use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use crate::{
    DLL_LOCK_COUNT, ProviderState,
    log::log,
    utils::{
        create_hbitmap_bgra_premul::create_hbitmap_bgra_premul, decode_blp_rgba::decode_blp_rgba,
        resize_fit_rgba_rect::resize_fit_rgba_rect, rgba_to_bgra_premul::rgba_to_bgra_premul,
    },
};

use windows::{
    Win32::{
        Foundation::{E_FAIL, E_INVALIDARG, HWND, LPARAM, RECT, S_FALSE, WPARAM},
        Graphics::Gdi::{DeleteObject, HBITMAP},
        System::{
            Com::{ISequentialStream, IStream, STREAM_SEEK_SET},
            LibraryLoader::GetModuleHandleW,
            Ole::IOleWindow_Impl,
        },
        UI::{
            Input::KeyboardAndMouse::SetFocus,
            Shell::{
                IInitializeWithItem_Impl, IPreviewHandler_Impl, IShellItem,
                PropertiesSystem::{IInitializeWithFile_Impl, IInitializeWithStream_Impl},
                SIGDN_FILESYSPATH,
            },
            WindowsAndMessaging::{
                CreateWindowExW, DestroyWindow, IMAGE_BITMAP, MSG, STM_SETIMAGE, SW_SHOWNORMAL,
                SWP_NOACTIVATE, SWP_NOOWNERZORDER, SWP_NOSENDCHANGING, SendMessageW, SetWindowPos,
                ShowWindow, WINDOW_EX_STYLE, WINDOW_STYLE, WS_CHILD, WS_CLIPCHILDREN,
                WS_CLIPSIBLINGS, WS_VISIBLE,
            },
        },
    },
    core::{BOOL, Error, Interface, PCWSTR, PWSTR, Result as WinResult, w},
};
use windows_implement::implement;

const SS_BITMAP: WINDOW_STYLE = WINDOW_STYLE(0x0000000E);

#[derive(Default)]
struct PreviewUi {
    parent: Option<HWND>,
    rect: RECT,
    window: Option<HWND>,
    hbitmap: Option<HBITMAP>,
    image: Option<(u32, u32, Arc<[u8]>)>,
}

#[implement(
    windows::Win32::UI::Shell::IPreviewHandler,
    windows::Win32::UI::Shell::IInitializeWithItem,
    windows::Win32::UI::Shell::PropertiesSystem::IInitializeWithStream,
    windows::Win32::UI::Shell::PropertiesSystem::IInitializeWithFile,
    windows::Win32::System::Ole::IOleWindow
)]
pub struct BlpPreviewHandler {
    state: Mutex<ProviderState>,
    ui: Mutex<PreviewUi>,
}

impl BlpPreviewHandler {
    pub fn new() -> Self {
        DLL_LOCK_COUNT.fetch_add(1, Ordering::SeqCst);
        log("Method BlpPreviewHandler::new called");
        Self {
            state: Mutex::new(ProviderState::default()),
            ui: Mutex::new(PreviewUi::default()),
        }
    }

    /* ---------- helpers that DO NOT hold the lock during Win32 calls ---------- */

    fn destroy_child_handles(hwnd: Option<HWND>, hbmp: Option<HBITMAP>) {
        if let Some(h) = hbmp {
            unsafe {
                let _ = DeleteObject(h.into());
            }
        }
        if let Some(w) = hwnd {
            // Сбрасываем картинку, чтобы не протекла
            let prev = unsafe {
                SendMessageW(
                    w,
                    STM_SETIMAGE,
                    Some(WPARAM(IMAGE_BITMAP.0 as usize)),
                    Some(LPARAM(0)),
                )
            };
            if prev.0 != 0 {
                unsafe {
                    let _ = DeleteObject(HBITMAP(prev.0 as *mut _).into());
                }
            }
            unsafe {
                let _ = DestroyWindow(w);
            }
        }
    }

    fn ensure_window_created(
        &self,
        parent: HWND,
        rect: RECT,
        existing: Option<HWND>,
    ) -> WinResult<HWND> {
        if let Some(h) = existing {
            return Ok(h);
        }
        let width = (rect.right - rect.left).max(1);
        let height = (rect.bottom - rect.top).max(1);
        let instance = unsafe { GetModuleHandleW(None) }?;
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("STATIC"),
                PCWSTR::null(),
                WINDOW_STYLE(WS_CHILD.0 | WS_VISIBLE.0 | WS_CLIPCHILDREN.0 | WS_CLIPSIBLINGS.0)
                    | SS_BITMAP,
                rect.left,
                rect.top,
                width,
                height,
                Some(parent),
                None,
                Some(instance.into()),
                None,
            )?
        };
        unsafe {
            let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
        }
        Ok(hwnd)
    }

    fn render_current_unlocked(
        &self,
        parent: HWND,
        rect: RECT,
        image: (u32, u32, Arc<[u8]>),
        current_hwnd: Option<HWND>,
        current_hbmp: Option<HBITMAP>,
    ) -> WinResult<(HWND, HBITMAP)> {
        let (iw, ih, data) = image;

        let hwnd = self.ensure_window_created(parent, rect, current_hwnd)?;

        // Цели
        let target_w = (rect.right - rect.left).max(1) as u32;
        let target_h = (rect.bottom - rect.top).max(1) as u32;

        // Подгоняем, конвертим, создаём HBITMAP
        let (tw, th, rgba_fit) = resize_fit_rgba_rect(&data, iw, ih, target_w, target_h);
        let bgra = rgba_to_bgra_premul(&rgba_fit);
        let hbmp = unsafe { create_hbitmap_bgra_premul(tw as i32, th as i32, &bgra)? };

        // Центруем
        let offset_x = rect.left + ((target_w as i32 - tw as i32) / 2);
        let offset_y = rect.top + ((target_h as i32 - th as i32) / 2);
        unsafe {
            SetWindowPos(
                hwnd,
                None,
                offset_x,
                offset_y,
                tw as i32,
                th as i32,
                SWP_NOACTIVATE | SWP_NOOWNERZORDER | SWP_NOSENDCHANGING,
            )?;
        }

        // Вставляем bitmap в STATIC, забираем предыдущий
        let previous = unsafe {
            SendMessageW(
                hwnd,
                STM_SETIMAGE,
                Some(WPARAM(IMAGE_BITMAP.0 as usize)),
                Some(LPARAM(hbmp.0 as isize)),
            )
        };

        // Чистим предыдущие (если были)
        if let Some(old) = current_hbmp {
            unsafe {
                let _ = DeleteObject(old.into());
            }
        }
        if previous.0 != 0 {
            unsafe {
                let _ = DeleteObject(HBITMAP(previous.0 as *mut _).into());
            }
        }

        log(&format!(
            "BlpPreviewHandler::render_current drew {}x{} (src {}x{}, target {}x{}, hwnd={:?})",
            tw, th, iw, ih, target_w, target_h, hwnd
        ));

        Ok((hwnd, hbmp))
    }

    fn acquire_source(&self) -> WinResult<(Arc<[u8]>, bool)> {
        log("Method BlpPreviewHandler::acquire_source called");

        let (data_arc, path_opt) = {
            let st = self.state.lock().unwrap();
            (st.stream_data.clone(), st.path_utf8.clone())
        };

        if let Some(buf) = data_arc {
            log(&format!(
                "acquire_source -> stream buffer ({} bytes)",
                buf.len()
            ));
            return Ok((buf, true));
        }

        let path = match path_opt {
            Some(p) => p,
            None => {
                let err = Error::from(E_FAIL);
                log(&format!("acquire_source -> Err({err:?}) no path"));
                return Err(err);
            }
        };

        log(&format!("acquire_source reading file '{path}'"));
        let raw = std::fs::read(&path).map_err(|e| {
            log(&format!("acquire_source read failed: {e}"));
            Error::from(E_FAIL)
        })?;

        let out: Arc<[u8]> = Arc::from(raw);
        log(&format!(
            "acquire_source -> file buffer ({} bytes)",
            out.len()
        ));
        Ok((out, false))
    }

    fn destroy_child(&self) {
        // Забираем хэндлы и освобождаем мьютекс
        let (hwnd, hbmp) = {
            let mut ui = self.ui.lock().unwrap();
            (ui.window.take(), ui.hbitmap.take())
        };
        // Уничтожаем хэндлы вне блокировки
        Self::destroy_child_handles(hwnd, hbmp);
        log("destroy_child: done");
    }

    fn render_current(&self) -> WinResult<()> {
        // Читаем снимок состояния
        let (parent, rect, image, current_hwnd, current_hbmp) = {
            let ui = self.ui.lock().unwrap();
            match (ui.parent, ui.image.as_ref()) {
                (Some(p), Some(img)) => (p, ui.rect, img.clone(), ui.window, ui.hbitmap),
                _ => {
                    log("render_current: nothing to draw");
                    return Ok(());
                }
            }
        };

        // Тяжёлую работу делаем без мьютекса
        let (hwnd, hbmp) =
            self.render_current_unlocked(parent, rect, image, current_hwnd, current_hbmp)?;

        // Фиксируем новые поля
        let mut ui = self.ui.lock().unwrap();
        ui.window = Some(hwnd);
        ui.hbitmap = Some(hbmp);
        Ok(())
    }
}

impl Drop for BlpPreviewHandler {
    fn drop(&mut self) {
        DLL_LOCK_COUNT.fetch_sub(1, Ordering::SeqCst);
        log("Method BlpPreviewHandler::drop called");
        self.destroy_child();
        let mut ui = self.ui.lock().unwrap();
        ui.image = None;
        log("Method BlpPreviewHandler::drop returning: Ok");
    }
}

/* ------------------------- Initializers ------------------------- */

impl IInitializeWithItem_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn Initialize(&self, psi: windows::core::Ref<'_, IShellItem>, grf_mode: u32) -> WinResult<()> {
        log(&format!(
            "IInitializeWithItem::Initialize grf_mode=0x{grf_mode:08X}"
        ));
        unsafe {
            let item: &IShellItem = psi.ok()?;
            let pw: PWSTR = item.GetDisplayName(SIGDN_FILESYSPATH)?;
            if pw.is_null() {
                let err = Error::from(E_FAIL);
                log(&format!(
                    "IInitializeWithItem::Initialize -> Err({err:?}) null path"
                ));
                return Err(err);
            }
            let s16 = widestring::U16CStr::from_ptr_str(pw.0);
            let path = s16.to_string_lossy();
            let mut st = self.state.lock().unwrap();
            st.path_utf8 = Some(path.clone());
            st.stream_data = None;
            log(&format!("IInitializeWithItem::Initialize path='{path}'"));
        }
        Ok(())
    }
}

impl IInitializeWithFile_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn Initialize(&self, psz_file_path: &PCWSTR, grf_mode: u32) -> WinResult<()> {
        log(&format!(
            "IInitializeWithFile::Initialize grf_mode=0x{grf_mode:08X}"
        ));
        if psz_file_path.is_null() || psz_file_path.0.is_null() {
            let err = Error::from(E_FAIL);
            log(&format!(
                "IInitializeWithFile::Initialize -> Err({err:?}) null path"
            ));
            return Err(err);
        }
        let path = unsafe { widestring::U16CStr::from_ptr_str(psz_file_path.0).to_string_lossy() };
        let mut st = self.state.lock().unwrap();
        st.path_utf8 = Some(path.clone());
        st.stream_data = None;
        log(&format!("IInitializeWithFile::Initialize path='{path}'"));
        Ok(())
    }
}

impl IInitializeWithStream_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn Initialize(&self, pstream: windows::core::Ref<'_, IStream>, grf_mode: u32) -> WinResult<()> {
        log(&format!(
            "IInitializeWithStream::Initialize grf_mode=0x{grf_mode:08X}"
        ));
        let stream: &IStream = pstream.ok()?;
        unsafe {
            stream.Seek(0, STREAM_SEEK_SET, None)?;
        }

        let seq: ISequentialStream = stream.cast()?;
        let mut buf = [0u8; 8192];
        let mut data = Vec::new();

        loop {
            let mut read = 0u32;
            let hr = unsafe {
                seq.Read(
                    buf.as_mut_ptr() as *mut _,
                    buf.len() as u32,
                    Some(&mut read),
                )
            };
            if hr.is_err() && hr != windows::core::HRESULT::from(S_FALSE) {
                let err = Error::from(hr);
                log(&format!(
                    "IInitializeWithStream::Initialize(Read) -> Err({err:?})"
                ));
                return Err(err);
            }
            if read > 0 {
                data.extend_from_slice(&buf[..read as usize]);
            }
            if hr == windows::core::HRESULT::from(S_FALSE) || read == 0 {
                break;
            }
        }

        let total = data.len();
        if total == 0 {
            let err = Error::from(E_FAIL);
            log(&format!(
                "IInitializeWithStream::Initialize -> Err({err:?}) empty stream"
            ));
            return Err(err);
        }

        let mut st = self.state.lock().unwrap();
        st.path_utf8 = None;
        st.stream_data = Some(Arc::from(data));
        log(&format!(
            "IInitializeWithStream::Initialize cached {total} bytes"
        ));
        Ok(())
    }
}

/* ------------------------- IPreviewHandler ------------------------- */

impl IPreviewHandler_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn SetWindow(&self, hwnd: HWND, prc: *const RECT) -> WinResult<()> {
        if prc.is_null() {
            let err = Error::from(E_INVALIDARG);
            log(&format!(
                "IPreviewHandler::SetWindow -> Err({err:?}) prc=NULL"
            ));
            return Err(err);
        }
        if hwnd.0.is_null() {
            let err = Error::from(E_INVALIDARG);
            log(&format!(
                "IPreviewHandler::SetWindow -> Err({err:?}) hwnd=NULL"
            ));
            return Err(err);
        }
        let rect = unsafe { *prc };
        log(&format!(
            "IPreviewHandler::SetWindow hwnd={:?} rect=({}, {}, {}, {})",
            hwnd, rect.left, rect.top, rect.right, rect.bottom
        ));

        // Читаем/обновляем состояние, но не трогаем Win32 внутри замка
        let (need_destroy, need_render, old_hwnd, old_hbmp) = {
            let mut ui = self.ui.lock().unwrap();
            let need_destroy = ui.parent != Some(hwnd);
            let old_hwnd = if need_destroy { ui.window.take() } else { None };
            let old_hbmp = if need_destroy {
                ui.hbitmap.take()
            } else {
                None
            };
            ui.parent = Some(hwnd);
            ui.rect = rect;
            let need_render = ui.image.is_some();
            (need_destroy, need_render, old_hwnd, old_hbmp)
        };

        if need_destroy {
            BlpPreviewHandler::destroy_child_handles(old_hwnd, old_hbmp);
        }
        if need_render {
            self.render_current()?;
        }
        Ok(())
    }

    #[allow(non_snake_case)]
    fn SetRect(&self, prc: *const RECT) -> WinResult<()> {
        if prc.is_null() {
            let err = Error::from(E_INVALIDARG);
            log(&format!(
                "IPreviewHandler::SetRect -> Err({err:?}) prc=NULL"
            ));
            return Err(err);
        }
        let rect = unsafe { *prc };
        log(&format!(
            "IPreviewHandler::SetRect rect=({}, {}, {}, {})",
            rect.left, rect.top, rect.right, rect.bottom
        ));

        let need_render = {
            let mut ui = self.ui.lock().unwrap();
            ui.rect = rect;
            ui.image.is_some()
        };
        if need_render {
            self.render_current()?;
        }
        Ok(())
    }

    #[allow(non_snake_case)]
    fn DoPreview(&self) -> WinResult<()> {
        log("IPreviewHandler::DoPreview called");
        let (data, from_stream) = self.acquire_source()?;
        let (w, h, rgba) = decode_blp_rgba(&data).map_err(|_| {
            let err = Error::from(E_FAIL);
            log(&format!(
                "IPreviewHandler::DoPreview -> Err({err:?}) decode failed"
            ));
            err
        })?;

        {
            let mut ui = self.ui.lock().unwrap();
            ui.image = Some((w, h, Arc::from(rgba)));
        }

        self.render_current()?;
        log(&format!(
            "IPreviewHandler::DoPreview decoded {}x{} from {}",
            w,
            h,
            if from_stream { "stream" } else { "file" }
        ));
        Ok(())
    }

    #[allow(non_snake_case)]
    fn Unload(&self) -> WinResult<()> {
        log("IPreviewHandler::Unload called");
        self.destroy_child();
        let mut ui = self.ui.lock().unwrap();
        ui.image = None;
        Ok(())
    }

    #[allow(non_snake_case)]
    fn SetFocus(&self) -> WinResult<()> {
        log("IPreviewHandler::SetFocus called");
        let hwnd = {
            let ui = self.ui.lock().unwrap();
            ui.window.or(ui.parent)
        };
        if let Some(hwnd) = hwnd {
            unsafe {
                let _ = SetFocus(Some(hwnd));
            }
            Ok(())
        } else {
            let err = Error::from(E_FAIL);
            log(&format!("IPreviewHandler::SetFocus -> Err({err:?})"));
            Err(err)
        }
    }

    #[allow(non_snake_case)]
    fn QueryFocus(&self) -> WinResult<HWND> {
        log("IPreviewHandler::QueryFocus called");
        let hwnd = {
            let ui = self.ui.lock().unwrap();
            ui.window.or(ui.parent)
        };
        hwnd.ok_or_else(|| {
            let err = Error::from(E_FAIL);
            log(&format!("IPreviewHandler::QueryFocus -> Err({err:?})"));
            err
        })
    }

    #[allow(non_snake_case)]
    fn TranslateAccelerator(&self, pmsg: *const MSG) -> WinResult<()> {
        if pmsg.is_null() {
            log("IPreviewHandler::TranslateAccelerator pmsg=NULL");
        } else {
            unsafe {
                log(&format!(
                    "IPreviewHandler::TranslateAccelerator msg=0x{:04X} wParam=0x{:X} lParam=0x{:X} hwnd={:?}",
                    (*pmsg).message,
                    (*pmsg).wParam.0,
                    (*pmsg).lParam.0,
                    (*pmsg).hwnd
                ));
            }
        }
        let err = Error::from(S_FALSE);
        Err(err)
    }
}

/* ------------------------- IOleWindow ------------------------- */

impl IOleWindow_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn GetWindow(&self) -> WinResult<HWND> {
        let hwnd = {
            let ui = self.ui.lock().unwrap();
            ui.window.or(ui.parent)
        };
        hwnd.ok_or_else(|| {
            let err = Error::from(E_FAIL);
            log(&format!("IOleWindow::GetWindow -> Err({err:?})"));
            err
        })
    }

    #[allow(non_snake_case)]
    fn ContextSensitiveHelp(&self, fenter_mode: BOOL) -> WinResult<()> {
        log(&format!(
            "IOleWindow::ContextSensitiveHelp fEnterMode={}",
            fenter_mode.as_bool()
        ));
        let err = Error::from(S_FALSE);
        Err(err)
    }
}

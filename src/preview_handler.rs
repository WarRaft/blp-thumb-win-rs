use crate::{DLL_LOCK_COUNT, ProviderState, log_desktop};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use crate::utils::create_hbitmap_bgra_premul::create_hbitmap_bgra_premul;
use crate::utils::decode_blp_rgba::decode_blp_rgba;
use crate::utils::resize_fit_rgba_rect::resize_fit_rgba_rect;
use crate::utils::rgba_to_bgra_premul::rgba_to_bgra_premul;
use windows::Win32::Foundation::{E_FAIL, E_INVALIDARG, HWND, LPARAM, RECT, S_FALSE, WPARAM};
use windows::Win32::Graphics::Gdi::{DeleteObject, HBITMAP};
use windows::Win32::System::Com::{ISequentialStream, IStream, STREAM_SEEK_SET};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Ole::IOleWindow_Impl;
use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows::Win32::UI::Shell::PropertiesSystem::{
    IInitializeWithFile_Impl, IInitializeWithStream_Impl,
};
use windows::Win32::UI::Shell::{
    IInitializeWithItem_Impl, IPreviewHandler_Impl, IShellItem, SIGDN_FILESYSPATH,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, IMAGE_BITMAP, MSG, STM_SETIMAGE, SW_SHOWNORMAL, SWP_NOACTIVATE,
    SWP_NOOWNERZORDER, SWP_NOSENDCHANGING, SendMessageW, SetWindowPos, ShowWindow, WINDOW_EX_STYLE,
    WINDOW_STYLE, WS_CHILD, WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_VISIBLE,
};
use windows::core::{Error, Interface, Result as WinResult, w};
use windows_core::{BOOL, PCWSTR, PWSTR};
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
        let _ = log_desktop("Method BlpPreviewHandler::new called");
        Self {
            state: Mutex::new(ProviderState::default()),
            ui: Mutex::new(PreviewUi::default()),
        }
    }

    fn acquire_source(&self) -> WinResult<(Arc<[u8]>, bool)> {
        let _ = log_desktop("Method BlpPreviewHandler::acquire_source called");

        let (data_arc, path_opt) = {
            let st = self.state.lock().unwrap();
            (st.stream_data.clone(), st.path_utf8.clone())
        };

        if let Some(buf) = data_arc {
            let _ = log_desktop(format!(
                "BlpPreviewHandler::acquire_source returning stream buffer ({} bytes)",
                buf.len()
            ));
            return Ok((buf, true));
        }

        let path = match path_opt {
            Some(p) => p,
            None => {
                let err = Error::from(E_FAIL);
                let _ = log_desktop(format!(
                    "Method BlpPreviewHandler::acquire_source returning: Err({err:?}) (no path)"
                ));
                return Err(err);
            }
        };

        let _ = log_desktop(format!(
            "BlpPreviewHandler::acquire_source reading file '{}'",
            path
        ));
        let raw = std::fs::read(&path).map_err(|e| {
            let _ = log_desktop(format!(
                "BlpPreviewHandler::acquire_source read failed: {}",
                e
            ));
            Error::from(E_FAIL)
        })?;

        // ВАЖНО: явный тип, чтобы не было E0282
        let out: Arc<[u8]> = Arc::from(raw);
        let _ = log_desktop(format!(
            "Method BlpPreviewHandler::acquire_source returning file buffer ({} bytes)",
            out.len()
        ));
        Ok((out, false))
    }

    fn destroy_child(ui: &mut PreviewUi) {
        let _ = log_desktop("Method BlpPreviewHandler::destroy_child called");
        if let Some(hwnd) = ui.window.take() {
            unsafe {
                let old = SendMessageW(
                    hwnd,
                    STM_SETIMAGE,
                    Some(WPARAM(IMAGE_BITMAP.0 as usize)),
                    Some(LPARAM(0)),
                );
                if old.0 != 0 {
                    let _ = DeleteObject(HBITMAP(old.0 as *mut _).into());
                }
                let _ = DestroyWindow(hwnd);
            }
        }
        if let Some(old) = ui.hbitmap.take() {
            unsafe {
                let _ = DeleteObject(old.into());
            }
        }
        let _ = log_desktop("Method BlpPreviewHandler::destroy_child returning: Ok");
    }

    fn ensure_window(ui: &mut PreviewUi) -> WinResult<HWND> {
        let _ = log_desktop(format!(
            "Method BlpPreviewHandler::ensure_window called with parent={:?} existing={:?} rect=({}, {}, {}, {})",
            ui.parent, ui.window, ui.rect.left, ui.rect.top, ui.rect.right, ui.rect.bottom
        ));

        if let Some(hwnd) = ui.window {
            let _ = log_desktop(
                "Method BlpPreviewHandler::ensure_window returning: Ok (reusing child)",
            );
            return Ok(hwnd);
        }

        let parent = ui.parent.ok_or_else(|| {
            let err = Error::from(E_FAIL);
            let _ = log_desktop(format!(
                "Method BlpPreviewHandler::ensure_window returning: Err({err:?}) (no parent)"
            ));
            err
        })?;

        let rect = ui.rect;
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

        ui.window = Some(hwnd);
        let _ =
            log_desktop("Method BlpPreviewHandler::ensure_window returning: Ok (created child)");
        Ok(hwnd)
    }

    fn render_current(ui: &mut PreviewUi) -> WinResult<()> {
        let _ = log_desktop("Method BlpPreviewHandler::render_current called");
        let (iw, ih, data) = match &ui.image {
            Some(t) => t.clone(),
            None => {
                let _ = log_desktop("BlpPreviewHandler::render_current: no image, nothing to draw");
                return Ok(());
            }
        };

        let hwnd = Self::ensure_window(ui)?;
        let target_w = (ui.rect.right - ui.rect.left).max(1) as u32;
        let target_h = (ui.rect.bottom - ui.rect.top).max(1) as u32;

        let (tw, th, rgba_fit) = resize_fit_rgba_rect(&data, iw, ih, target_w, target_h);
        let bgra = rgba_to_bgra_premul(&rgba_fit);
        let hbmp = unsafe { create_hbitmap_bgra_premul(tw as i32, th as i32, &bgra)? };

        let offset_x = ui.rect.left + ((target_w as i32 - tw as i32) / 2);
        let offset_y = ui.rect.top + ((target_h as i32 - th as i32) / 2);

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

        let previous = unsafe {
            SendMessageW(
                hwnd,
                STM_SETIMAGE,
                Some(WPARAM(IMAGE_BITMAP.0 as usize)),
                Some(LPARAM(hbmp.0 as isize)),
            )
        };

        if let Some(old) = ui.hbitmap.replace(hbmp) {
            unsafe {
                let _ = DeleteObject(old.into());
            }
        }
        if previous.0 != 0 {
            unsafe {
                let _ = DeleteObject(HBITMAP(previous.0 as *mut _).into());
            }
        }

        let _ = log_desktop(format!(
            "BlpPreviewHandler::render_current drew {}x{} (src {}x{}, target {}x{}, hwnd={:?})",
            tw, th, iw, ih, target_w, target_h, hwnd
        ));
        let _ = log_desktop("Method BlpPreviewHandler::render_current returning: Ok");
        Ok(())
    }
}

impl Drop for BlpPreviewHandler {
    fn drop(&mut self) {
        DLL_LOCK_COUNT.fetch_sub(1, Ordering::SeqCst);
        let _ = log_desktop("Method BlpPreviewHandler::drop called");
        let mut ui = self.ui.lock().unwrap();
        Self::destroy_child(&mut ui);
        ui.image = None;
        let _ = log_desktop("Method BlpPreviewHandler::drop returning: Ok");
    }
}

/* ------------------------- Initializers ------------------------- */

impl IInitializeWithItem_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn Initialize(&self, psi: windows::core::Ref<'_, IShellItem>, grf_mode: u32) -> WinResult<()> {
        // Не логируем `psi` через {:?} — у него нет Debug
        let _ = log_desktop(format!(
            "Method IInitializeWithItem::Initialize called with grf_mode=0x{:08X}",
            grf_mode
        ));
        unsafe {
            let item: &IShellItem = psi.ok()?;
            let pw: PWSTR = item.GetDisplayName(SIGDN_FILESYSPATH)?;
            if pw.is_null() {
                let err = Error::from(E_FAIL);
                let _ = log_desktop(format!(
                    "Method IInitializeWithItem::Initialize returning: Err({err:?}) (null path)"
                ));
                return Err(err);
            }
            let s16 = widestring::U16CStr::from_ptr_str(pw.0);
            let path = s16.to_string_lossy();
            let mut st = self.state.lock().unwrap();
            st.path_utf8 = Some(path.clone());
            st.stream_data = None;
            drop(st);
            let _ = log_desktop(format!(
                "IInitializeWithItem::Initialize resolved path='{}'",
                path
            ));
        }
        let _ = log_desktop("Method IInitializeWithItem::Initialize returning: Ok");
        Ok(())
    }
}

impl IInitializeWithFile_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn Initialize(&self, psz_file_path: &PCWSTR, grf_mode: u32) -> WinResult<()> {
        let _ = log_desktop(format!(
            "Method IInitializeWithFile::Initialize called with grf_mode=0x{:08X}",
            grf_mode
        ));
        if psz_file_path.is_null() || psz_file_path.0.is_null() {
            let err = Error::from(E_FAIL);
            let _ = log_desktop(format!(
                "Method IInitializeWithFile::Initialize returning: Err({err:?}) (null path)"
            ));
            return Err(err);
        }
        let path = unsafe { widestring::U16CStr::from_ptr_str(psz_file_path.0).to_string_lossy() };
        let mut st = self.state.lock().unwrap();
        st.path_utf8 = Some(path.clone());
        st.stream_data = None;
        drop(st);
        let _ = log_desktop(format!("IInitializeWithFile::Initialize path='{}'", path));
        let _ = log_desktop("Method IInitializeWithFile::Initialize returning: Ok");
        Ok(())
    }
}

impl IInitializeWithStream_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn Initialize(&self, pstream: windows::core::Ref<'_, IStream>, grf_mode: u32) -> WinResult<()> {
        // Не логируем pstream через {:?}
        let _ = log_desktop(format!(
            "Method IInitializeWithStream::Initialize called with grf_mode=0x{:08X}",
            grf_mode
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
                    Some(&mut read as *mut u32),
                )
            };
            if hr.is_err() && hr != windows::core::HRESULT::from(S_FALSE) {
                let err = Error::from(hr);
                let _ = log_desktop(format!(
                    "Method IInitializeWithStream::Initialize(Read) returning: Err({err:?})"
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
            let _ = log_desktop(format!(
                "Method IInitializeWithStream::Initialize returning: Err({err:?}) (empty stream)"
            ));
            return Err(err);
        }

        let mut st = self.state.lock().unwrap();
        st.path_utf8 = None;
        // здесь вывод типа обычно срабатывает сам, но можно и явно:
        st.stream_data = Some(Arc::from(data)); // Arc<[u8]>
        drop(st);

        let _ = log_desktop(format!(
            "IInitializeWithStream::Initialize cached {} bytes",
            total
        ));
        let _ = log_desktop("Method IInitializeWithStream::Initialize returning: Ok");
        Ok(())
    }
}

/* ------------------------- IPreviewHandler ------------------------- */

impl IPreviewHandler_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn SetWindow(&self, hwnd: HWND, prc: *const RECT) -> WinResult<()> {
        if prc.is_null() {
            let err = Error::from(E_INVALIDARG);
            let _ = log_desktop(format!(
                "Method IPreviewHandler::SetWindow returning: Err({err:?}) (prc=NULL)"
            ));
            return Err(err);
        }
        let rect = unsafe { *prc };
        let _ = log_desktop(format!(
            "Method IPreviewHandler::SetWindow called with hwnd={:?} rect=({}, {}, {}, {})",
            hwnd, rect.left, rect.top, rect.right, rect.bottom
        ));
        if hwnd.0.is_null() {
            let err = Error::from(E_INVALIDARG);
            let _ = log_desktop(format!(
                "Method IPreviewHandler::SetWindow returning: Err({err:?}) (hwnd=NULL)"
            ));
            return Err(err);
        }

        let mut ui = self.ui.lock().unwrap();
        if ui.parent != Some(hwnd) {
            BlpPreviewHandler::destroy_child(&mut ui);
        }
        ui.parent = Some(hwnd);
        ui.rect = rect;
        if ui.image.is_some() {
            BlpPreviewHandler::render_current(&mut ui)?;
        }
        let _ = log_desktop("Method IPreviewHandler::SetWindow returning: Ok");
        Ok(())
    }

    #[allow(non_snake_case)]
    fn SetRect(&self, prc: *const RECT) -> WinResult<()> {
        if prc.is_null() {
            let err = Error::from(E_INVALIDARG);
            let _ = log_desktop(format!(
                "Method IPreviewHandler::SetRect returning: Err({err:?}) (prc=NULL)"
            ));
            return Err(err);
        }
        let rect = unsafe { *prc };
        let _ = log_desktop(format!(
            "Method IPreviewHandler::SetRect called with rect=({}, {}, {}, {})",
            rect.left, rect.top, rect.right, rect.bottom
        ));

        let mut ui = self.ui.lock().unwrap();
        ui.rect = rect;
        if ui.image.is_some() {
            BlpPreviewHandler::render_current(&mut ui)?;
        }
        let _ = log_desktop("Method IPreviewHandler::SetRect returning: Ok");
        Ok(())
    }

    #[allow(non_snake_case)]
    fn DoPreview(&self) -> WinResult<()> {
        let _ = log_desktop("Method IPreviewHandler::DoPreview called");
        let (data, from_stream) = self.acquire_source()?;
        let (w, h, rgba) = decode_blp_rgba(&data).map_err(|_| {
            let err = Error::from(E_FAIL);
            let _ = log_desktop(format!(
                "Method IPreviewHandler::DoPreview returning: Err({err:?}) (decode failed)"
            ));
            err
        })?;

        let mut ui = self.ui.lock().unwrap();
        ui.image = Some((w, h, Arc::from(rgba)));
        BlpPreviewHandler::render_current(&mut ui)?;
        let _ = log_desktop(format!(
            "IPreviewHandler::DoPreview decoded {}x{} from {}",
            w,
            h,
            if from_stream { "stream" } else { "file" }
        ));
        let _ = log_desktop("Method IPreviewHandler::DoPreview returning: Ok");
        Ok(())
    }

    #[allow(non_snake_case)]
    fn Unload(&self) -> WinResult<()> {
        let _ = log_desktop("Method IPreviewHandler::Unload called");
        let mut ui = self.ui.lock().unwrap();
        BlpPreviewHandler::destroy_child(&mut ui);
        ui.image = None;
        let _ = log_desktop("Method IPreviewHandler::Unload returning: Ok");
        Ok(())
    }

    #[allow(non_snake_case)]
    fn SetFocus(&self) -> WinResult<()> {
        let _ = log_desktop("Method IPreviewHandler::SetFocus called");
        let ui = self.ui.lock().unwrap();
        if let Some(hwnd) = ui.window.or(ui.parent) {
            unsafe {
                let _ = SetFocus(Some(hwnd));
            }
            let _ = log_desktop(format!("IPreviewHandler::SetFocus hwnd={:?}", hwnd));
            let _ = log_desktop("Method IPreviewHandler::SetFocus returning: Ok");
            Ok(())
        } else {
            let err = Error::from(E_FAIL);
            let _ = log_desktop(format!(
                "Method IPreviewHandler::SetFocus returning: Err({err:?})"
            ));
            Err(err)
        }
    }

    #[allow(non_snake_case)]
    fn QueryFocus(&self) -> WinResult<HWND> {
        let _ = log_desktop("Method IPreviewHandler::QueryFocus called");
        let ui = self.ui.lock().unwrap();
        match ui.window.or(ui.parent) {
            Some(hwnd) => {
                let _ = log_desktop(format!("IPreviewHandler::QueryFocus hwnd={:?}", hwnd));
                let _ = log_desktop("Method IPreviewHandler::QueryFocus returning: Ok");
                Ok(hwnd)
            }
            None => {
                let err = Error::from(E_FAIL);
                let _ = log_desktop(format!(
                    "Method IPreviewHandler::QueryFocus returning: Err({err:?})"
                ));
                Err(err)
            }
        }
    }

    #[allow(non_snake_case)]
    fn TranslateAccelerator(&self, pmsg: *const MSG) -> WinResult<()> {
        if pmsg.is_null() {
            let _ =
                log_desktop("Method IPreviewHandler::TranslateAccelerator called with pmsg=NULL");
        } else {
            unsafe {
                let _ = log_desktop(format!(
                    "Method IPreviewHandler::TranslateAccelerator called with msg=0x{:04X} wParam=0x{:X} lParam=0x{:X} hwnd={:?}",
                    (*pmsg).message,
                    (*pmsg).wParam.0,
                    (*pmsg).lParam.0,
                    (*pmsg).hwnd
                ));
            }
        }
        // Not handled → S_FALSE
        let err = Error::from(S_FALSE);
        let _ = log_desktop(format!(
            "Method IPreviewHandler::TranslateAccelerator returning: Err({err:?})"
        ));
        Err(err)
    }
}

/* ------------------------- IOleWindow ------------------------- */

impl IOleWindow_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn GetWindow(&self) -> WinResult<HWND> {
        let _ = log_desktop("Method IOleWindow::GetWindow called");
        let ui = self.ui.lock().unwrap();
        match ui.window.or(ui.parent) {
            Some(hwnd) => {
                let _ = log_desktop(format!("IOleWindow::GetWindow hwnd={:?}", hwnd));
                let _ = log_desktop("Method IOleWindow::GetWindow returning: Ok");
                Ok(hwnd)
            }
            None => {
                let err = Error::from(E_FAIL);
                let _ = log_desktop(format!(
                    "Method IOleWindow::GetWindow returning: Err({err:?})"
                ));
                Err(err)
            }
        }
    }

    #[allow(non_snake_case)]
    fn ContextSensitiveHelp(&self, fenter_mode: BOOL) -> WinResult<()> {
        let _ = log_desktop(format!(
            "Method IOleWindow::ContextSensitiveHelp called with fEnterMode={}",
            fenter_mode.as_bool()
        ));
        // Not supported
        let err = Error::from(S_FALSE);
        let _ = log_desktop(format!(
            "Method IOleWindow::ContextSensitiveHelp returning: Err({err:?})"
        ));
        Err(err)
    }
}

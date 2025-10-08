use crate::{DLL_LOCK_COUNT, ProviderState};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use crate::log::log;
use crate::utils::create_hbitmap_bgra_premul::create_hbitmap_bgra_premul;
use crate::utils::decode_blp_rgba::decode_blp_rgba;
use crate::utils::resize_fit_rgba::resize_fit_rgba;
use crate::utils::rgba_to_bgra_premul::rgba_to_bgra_premul;
use windows::Win32::Foundation::{
    E_FAIL, E_NOTIMPL, E_POINTER, HWND, LPARAM, RECT, S_FALSE, WPARAM,
};
use windows::Win32::Graphics::Gdi::{DeleteObject, HBITMAP};
use windows::Win32::System::Com::{ISequentialStream, IStream, STREAM_SEEK_SET};
use windows::Win32::System::Ole::IOleWindow_Impl;
use windows::Win32::UI::Shell::PropertiesSystem::{
    IInitializeWithFile_Impl, IInitializeWithStream_Impl,
};
use windows::Win32::UI::Shell::{
    IInitializeWithItem_Impl, IPreviewHandler_Impl, IShellItem, SIGDN_FILESYSPATH,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, GetClientRect, IMAGE_BITMAP, STM_SETIMAGE, SWP_NOACTIVATE,
    SWP_NOMOVE, SWP_NOZORDER, SendMessageW, SetParent, SetWindowPos, WINDOW_EX_STYLE, WINDOW_STYLE,
    WS_CHILD, WS_VISIBLE,
};
use windows::core::{Error, HRESULT, Interface, Result as WinResult};
use windows_core::BOOL;
use windows_core::{PCWSTR, PWSTR};
use windows_implement::implement;

const SS_BITMAP: WINDOW_STYLE = WINDOW_STYLE(0x0000_000E);
const SS_CENTERIMAGE: WINDOW_STYLE = WINDOW_STYLE(0x0000_0200);

#[implement(
    windows::Win32::UI::Shell::IPreviewHandler,
    windows::Win32::UI::Shell::IInitializeWithItem,
    windows::Win32::UI::Shell::PropertiesSystem::IInitializeWithStream,
    windows::Win32::UI::Shell::PropertiesSystem::IInitializeWithFile
)]
pub struct BlpPreviewHandler {
    state: Mutex<ProviderState>,
    hwnd_parent: Mutex<Option<HWND>>,
    hwnd_preview: Mutex<Option<HWND>>,
    rect_parent: Mutex<RECT>,
    bitmap: Mutex<Option<HBITMAP>>,
}

impl BlpPreviewHandler {
    pub fn new() -> Self {
        DLL_LOCK_COUNT.fetch_add(1, Ordering::SeqCst);
        log("BlpPreviewHandler::new");
        Self {
            state: Mutex::new(ProviderState::default()),
            hwnd_parent: Mutex::new(None),
            hwnd_preview: Mutex::new(None),
            rect_parent: Mutex::new(RECT {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            }),
            bitmap: Mutex::new(None),
        }
    }

    fn create_preview_window(&self) -> WinResult<()> {
        let hwnd_parent = self.hwnd_parent.lock().unwrap();
        let rect = self.rect_parent.lock().unwrap();

        if hwnd_parent.is_none() {
            return Err(Error::from(E_FAIL));
        }

        let parent = hwnd_parent.unwrap();
        let rect = *rect;
        let style = WINDOW_STYLE(WS_CHILD.0 | WS_VISIBLE.0 | SS_BITMAP.0 | SS_CENTERIMAGE.0);

        // Create a static window to display our content
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                windows::core::w!("STATIC"),
                windows::core::w!(""),
                style,
                rect.left,
                rect.top,
                rect.right - rect.left,
                rect.bottom - rect.top,
                Some(parent),
                None,
                None,
                None,
            )?
        };

        // Store the window handle
        let mut hwnd_preview = self.hwnd_preview.lock().unwrap();
        *hwnd_preview = Some(hwnd);

        // Get the image data and render it
        self.render_preview_content(hwnd)?;

        Ok(())
    }

    fn render_preview_content(&self, hwnd: HWND) -> WinResult<()> {
        // Get the image data from state
        let (data_arc, path_opt) = {
            let st = self.state.lock().unwrap();
            (st.stream_data.clone(), st.path_utf8.clone())
        };

        let data_arc: Arc<[u8]> = if let Some(buf) = data_arc {
            buf
        } else if let Some(path) = path_opt {
            let raw = std::fs::read(&path).map_err(|_| Error::from(E_FAIL))?;
            Arc::from(raw)
        } else {
            return Err(Error::from(E_FAIL));
        };

        // Decode BLP image
        let (w, h, rgba) = decode_blp_rgba(&data_arc).map_err(|_| Error::from(E_FAIL))?;

        // Get window dimensions
        let mut rect = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        unsafe {
            let _ = GetClientRect(hwnd, &mut rect);
        }

        let target_width = (rect.right - rect.left).max(0) as u32;
        let target_height = (rect.bottom - rect.top).max(0) as u32;
        if target_width == 0 || target_height == 0 {
            return Err(Error::from(E_FAIL));
        }

        // Resize image to fit window (use the smaller dimension as the target size)
        let target_size = target_width.min(target_height);
        let (tw, th, rgba_fit) = resize_fit_rgba(&rgba, w, h, target_size);

        // Convert to BGRA premultiplied
        let bgra_pm = rgba_to_bgra_premul(&rgba_fit);

        // Create final bitmap for the static control
        let hbmp = unsafe { create_hbitmap_bgra_premul(tw as i32, th as i32, &bgra_pm)? };

        unsafe {
            SendMessageW(
                hwnd,
                STM_SETIMAGE,
                Some(WPARAM(IMAGE_BITMAP.0 as usize)),
                Some(LPARAM(hbmp.0 as isize)),
            );
        }

        let mut bitmap_guard = self.bitmap.lock().unwrap();
        if let Some(old) = bitmap_guard.replace(hbmp) {
            unsafe {
                let _ = DeleteObject(old.into());
            }
        }
        Ok(())
    }
}

impl IOleWindow_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn GetWindow(&self) -> windows::core::Result<HWND> {
        let hwnd_preview = self.hwnd_preview.lock().unwrap();
        if let Some(hwnd) = *hwnd_preview {
            return Ok(hwnd);
        }
        drop(hwnd_preview);

        let hwnd_parent = self.hwnd_parent.lock().unwrap();
        if let Some(hwnd) = *hwnd_parent {
            Ok(hwnd)
        } else {
            Err(Error::from(E_FAIL))
        }
    }
    #[allow(non_snake_case)]
    fn ContextSensitiveHelp(&self, _f_enter_mode: BOOL) -> windows::core::Result<()> {
        Err(Error::from(E_NOTIMPL))
    }
}

impl Drop for BlpPreviewHandler {
    fn drop(&mut self) {
        DLL_LOCK_COUNT.fetch_sub(1, Ordering::SeqCst);
        log("BlpPreviewHandler::drop");

        // Clean up preview window and bitmap if still allocated
        let mut hwnd_preview = self.hwnd_preview.lock().unwrap();
        if let Some(hwnd) = hwnd_preview.take() {
            unsafe {
                SendMessageW(
                    hwnd,
                    STM_SETIMAGE,
                    Some(WPARAM(IMAGE_BITMAP.0 as usize)),
                    Some(LPARAM(0)),
                );
                let _ = DestroyWindow(hwnd);
            }
        }
        drop(hwnd_preview);

        let mut bitmap_guard = self.bitmap.lock().unwrap();
        if let Some(old) = bitmap_guard.take() {
            unsafe {
                let _ = DeleteObject(old.into());
            }
        }
    }
}

// IInitializeWithItem implementation
impl IInitializeWithItem_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn Initialize(
        &self,
        psi: windows::core::Ref<'_, IShellItem>,
        _grf_mode: u32,
    ) -> windows::core::Result<()> {
        unsafe {
            let item: &IShellItem = psi.ok()?;
            let pw: PWSTR = item.GetDisplayName(SIGDN_FILESYSPATH)?;
            if pw.is_null() {
                return Err(Error::from(E_FAIL));
            }
            let s16 = widestring::U16CStr::from_ptr_str(pw.0);
            let path = s16.to_string_lossy();
            let mut st = self.state.lock().unwrap();
            st.path_utf8 = Some(path.clone());
            st.stream_data = None;
            drop(st);
            log(format!("IInitializeWithItem: path={}", path));
        }
        Ok(())
    }
}

// IInitializeWithFile implementation
impl IInitializeWithFile_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn Initialize(&self, psz_file_path: &PCWSTR, _grf_mode: u32) -> windows::core::Result<()> {
        if psz_file_path.is_null() || psz_file_path.0.is_null() {
            return Err(Error::from(E_FAIL));
        }

        let path = unsafe { widestring::U16CStr::from_ptr_str(psz_file_path.0).to_string_lossy() };

        let mut st = self.state.lock().unwrap();
        st.path_utf8 = Some(path.clone());
        st.stream_data = None;
        drop(st);
        log(format!("IInitializeWithFile: path={}", path));
        Ok(())
    }
}

// IInitializeWithStream implementation
impl IInitializeWithStream_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn Initialize(
        &self,
        pstream: windows::core::Ref<'_, IStream>,
        _grf_mode: u32,
    ) -> windows::core::Result<()> {
        log("IInitializeWithStream: begin");

        let stream: &IStream = pstream.ok()?;

        unsafe {
            stream.Seek(0, STREAM_SEEK_SET, None)?;
        }

        let mut data = Vec::<u8>::new();
        let seq: ISequentialStream = stream.cast()?;
        let mut buf = [0u8; 8192];

        loop {
            let mut read = 0u32;
            let hr = unsafe {
                seq.Read(
                    buf.as_mut_ptr() as *mut _,
                    buf.len() as u32,
                    Some(&mut read as *mut u32),
                )
            };

            if hr.is_err() {
                log(format!(
                    "IInitializeWithStream: Read failed hr=0x{:08X}",
                    hr.0 as u32
                ));
                return Err(Error::from(hr));
            }

            if read > 0 {
                data.extend_from_slice(&buf[..read as usize]);
            }

            if hr == HRESULT::from(S_FALSE) || read == 0 {
                break;
            }
        }

        let data_len = data.len();
        if data_len == 0 {
            log("IInitializeWithStream: stream empty");
            return Err(Error::from(E_FAIL));
        }

        let mut st = self.state.lock().unwrap();
        st.path_utf8 = None;
        st.stream_data = Some(Arc::from(data));
        drop(st);
        log(format!("IInitializeWithStream: cached {} bytes", data_len));
        Ok(())
    }
}

// IPreviewHandler implementation
impl IPreviewHandler_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn SetWindow(&self, hwnd: HWND, prc: *const RECT) -> windows::core::Result<()> {
        if hwnd.0 != std::ptr::null_mut() && !prc.is_null() {
            let mut hwnd_parent = self.hwnd_parent.lock().unwrap();
            *hwnd_parent = Some(hwnd);
            drop(hwnd_parent);

            let rect = unsafe { *prc };
            let mut rect_parent = self.rect_parent.lock().unwrap();
            *rect_parent = rect;
            drop(rect_parent);

            // Update existing preview window if it exists
            let hwnd_preview = self.hwnd_preview.lock().unwrap();
            if let Some(preview_hwnd) = *hwnd_preview {
                unsafe {
                    let _ = SetParent(preview_hwnd, Some(hwnd));
                    let _ = SetWindowPos(
                        preview_hwnd,
                        None,
                        rect.left,
                        rect.top,
                        rect.right - rect.left,
                        rect.bottom - rect.top,
                        SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
                    );
                }
            }
        }
        Ok(())
    }
    #[allow(non_snake_case)]
    fn SetRect(&self, prc: *const RECT) -> windows::core::Result<()> {
        if prc.is_null() {
            return Err(Error::from(E_POINTER));
        }

        let rect = unsafe { *prc };
        let mut rect_parent = self.rect_parent.lock().unwrap();
        *rect_parent = rect;
        drop(rect_parent);

        let hwnd_preview = self.hwnd_preview.lock().unwrap();
        if let Some(hwnd) = *hwnd_preview {
            unsafe {
                let _ = SetWindowPos(
                    hwnd,
                    None,
                    rect.left,
                    rect.top,
                    rect.right - rect.left,
                    rect.bottom - rect.top,
                    SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
                );
            }
        }
        Ok(())
    }

    #[allow(non_snake_case)]
    fn DoPreview(&self) -> windows::core::Result<()> {
        let hwnd_preview = self.hwnd_preview.lock().unwrap();
        if hwnd_preview.is_none() {
            drop(hwnd_preview);
            self.create_preview_window()?;
        }
        Ok(())
    }

    #[allow(non_snake_case)]
    fn Unload(&self) -> windows::core::Result<()> {
        // Clear stream data
        let mut st = self.state.lock().unwrap();
        st.stream_data = None;
        drop(st);

        // Destroy preview window and release bitmap resources
        let mut hwnd_preview = self.hwnd_preview.lock().unwrap();
        if let Some(hwnd) = *hwnd_preview {
            unsafe {
                SendMessageW(
                    hwnd,
                    STM_SETIMAGE,
                    Some(WPARAM(IMAGE_BITMAP.0 as usize)),
                    Some(LPARAM(0)),
                );
                let _ = DestroyWindow(hwnd);
            }
            *hwnd_preview = None;
        }
        drop(hwnd_preview);

        let mut bitmap_guard = self.bitmap.lock().unwrap();
        if let Some(old) = bitmap_guard.take() {
            unsafe {
                let _ = DeleteObject(old.into());
            }
        }
        Ok(())
    }

    #[allow(non_snake_case)]
    fn SetFocus(&self) -> windows::core::Result<()> {
        let hwnd_preview = self.hwnd_preview.lock().unwrap();
        if let Some(_hwnd) = *hwnd_preview {
            // Focus is handled by the host
            Ok(())
        } else {
            Err(Error::from(S_FALSE))
        }
    }

    #[allow(non_snake_case)]
    fn QueryFocus(&self) -> windows::core::Result<HWND> {
        // Return the preview window if it exists, otherwise fail
        let hwnd_preview = self.hwnd_preview.lock().unwrap();
        if let Some(hwnd) = *hwnd_preview {
            Ok(hwnd)
        } else {
            Err(Error::from(E_FAIL))
        }
    }

    #[allow(non_snake_case)]
    fn TranslateAccelerator(
        &self,
        _pmsg: *const windows::Win32::UI::WindowsAndMessaging::MSG,
    ) -> windows::core::Result<()> {
        // For now, just return S_FALSE to let the host handle it
        Err(Error::from(S_FALSE))
    }
}

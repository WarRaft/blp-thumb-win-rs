use crate::{
    DLL_LOCK_COUNT, ProviderState, create_hbitmap_bgra_premul, decode_blp_rgba, log_desktop,
    rgba_to_bgra_premul,
};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use windows::Win32::Foundation::{E_FAIL, E_INVALIDARG, HWND, RECT, S_FALSE};
use windows::Win32::Graphics::Gdi::{
    AC_SRC_ALPHA, AC_SRC_OVER, AlphaBlend, BLENDFUNCTION, CreateCompatibleDC, DeleteDC,
    DeleteObject, GetDC, ReleaseDC, SelectObject,
};
use windows::Win32::System::Com::{ISequentialStream, IStream, STREAM_SEEK_SET};
use windows::Win32::UI::Shell::PropertiesSystem::{
    IInitializeWithFile_Impl, IInitializeWithStream_Impl,
};
use windows::Win32::UI::Shell::{
    IInitializeWithItem_Impl, IPreviewHandler_Impl, IShellItem, SIGDN_FILESYSPATH,
};
use windows::Win32::UI::WindowsAndMessaging::MSG;
use windows::core::{Error, Interface, Result as WinResult};
use windows_core::{BOOL, PCWSTR, PWSTR};
use windows_implement::implement;

#[derive(Clone)]
struct StoredImage {
    width: u32,
    height: u32,
    rgba: Arc<[u8]>,
}

#[derive(Default)]
struct PreviewUi {
    parent: Option<HWND>,
    rect: RECT,
    image: Option<StoredImage>,
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
        let _ = log_desktop("BlpPreviewHandler::new");
        Self {
            state: Mutex::new(ProviderState::default()),
            ui: Mutex::new(PreviewUi::default()),
        }
    }

    fn acquire_source(&self) -> WinResult<(Arc<[u8]>, bool)> {
        let (data_arc, path_opt) = {
            let st = self.state.lock().unwrap();
            (st.stream_data.clone(), st.path_utf8.clone())
        };

        if let Some(buf) = data_arc {
            let _ = log_desktop(format!(
                "BlpPreviewHandler::acquire_source stream ({} bytes)",
                buf.len()
            ));
            return Ok((buf, true));
        }

        let path = path_opt.ok_or_else(|| {
            let _ = log_desktop("BlpPreviewHandler::acquire_source missing path");
            Error::from(E_FAIL)
        })?;
        let _ = log_desktop(format!("BlpPreviewHandler::acquire_source file {}", path));
        let raw = std::fs::read(&path).map_err(|err| {
            let _ = log_desktop(format!(
                "BlpPreviewHandler::acquire_source read failed: {}",
                err
            ));
            Error::from(E_FAIL)
        })?;
        Ok((Arc::from(raw), false))
    }

    fn repaint_locked(ui: &PreviewUi) -> WinResult<()> {
        let hwnd = ui.parent.ok_or_else(|| Error::from(E_FAIL))?;
        let rect = ui.rect;
        let image = match &ui.image {
            Some(img) => img.clone(),
            None => return Ok(()),
        };

        let width = (rect.right - rect.left).max(1) as u32;
        let height = (rect.bottom - rect.top).max(1) as u32;
        let (dest_w, dest_h, rgba_fit) =
            resize_fit_rgba_rect(&image.rgba[..], image.width, image.height, width, height);
        let bgra = rgba_to_bgra_premul(&rgba_fit);
        let hbmp = unsafe { create_hbitmap_bgra_premul(dest_w as i32, dest_h as i32, &bgra)? };

        unsafe {
            let hdc = GetDC(Some(hwnd));
            if hdc.0.is_null() {
                let _ = DeleteObject(hbmp.into());
                return Err(Error::from(E_FAIL));
            }
            let mem_dc = CreateCompatibleDC(Some(hdc));
            if mem_dc.0.is_null() {
                let _ = ReleaseDC(Some(hwnd), hdc);
                let _ = DeleteObject(hbmp.into());
                return Err(Error::from(E_FAIL));
            }

            let old = SelectObject(mem_dc, hbmp.into());

            let available_w = width as i32;
            let available_h = height as i32;
            let offset_x = rect.left + ((available_w - dest_w as i32) / 2);
            let offset_y = rect.top + ((available_h - dest_h as i32) / 2);

            let blend = BLENDFUNCTION {
                BlendOp: AC_SRC_OVER as u8,
                BlendFlags: 0,
                SourceConstantAlpha: 255,
                AlphaFormat: AC_SRC_ALPHA as u8,
            };

            let success = AlphaBlend(
                hdc,
                offset_x,
                offset_y,
                dest_w as i32,
                dest_h as i32,
                mem_dc,
                0,
                0,
                dest_w as i32,
                dest_h as i32,
                blend,
            )
            .as_bool();

            if !old.0.is_null() {
                let _ = SelectObject(mem_dc, old);
            }
            let _ = DeleteDC(mem_dc);
            let _ = ReleaseDC(Some(hwnd), hdc);
            let _ = DeleteObject(hbmp.into());

            if !success {
                return Err(Error::from(E_FAIL));
            }
        }

        Ok(())
    }
}

impl Drop for BlpPreviewHandler {
    fn drop(&mut self) {
        DLL_LOCK_COUNT.fetch_sub(1, Ordering::SeqCst);
        let _ = log_desktop("BlpPreviewHandler::drop");
        let mut ui = self.ui.lock().unwrap();
        ui.image = None;
    }
}

impl IInitializeWithItem_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn Initialize(&self, psi: windows::core::Ref<'_, IShellItem>, _grf_mode: u32) -> WinResult<()> {
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
            let _ = log_desktop(format!("BlpPreviewHandler::Initialize item path={}", path));
        }
        Ok(())
    }
}

impl IInitializeWithFile_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn Initialize(&self, psz_file_path: &PCWSTR, _grf_mode: u32) -> WinResult<()> {
        if psz_file_path.is_null() || psz_file_path.0.is_null() {
            return Err(Error::from(E_FAIL));
        }
        let path = unsafe { widestring::U16CStr::from_ptr_str(psz_file_path.0).to_string_lossy() };
        let mut st = self.state.lock().unwrap();
        st.path_utf8 = Some(path.clone());
        st.stream_data = None;
        drop(st);
        let _ = log_desktop(format!("BlpPreviewHandler::Initialize file path={}", path));
        Ok(())
    }
}

impl IInitializeWithStream_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn Initialize(
        &self,
        pstream: windows::core::Ref<'_, IStream>,
        _grf_mode: u32,
    ) -> WinResult<()> {
        let _ = log_desktop("BlpPreviewHandler::Initialize stream begin");
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

            if hr.is_err() {
                return Err(Error::from(hr));
            }

            if read > 0 {
                data.extend_from_slice(&buf[..read as usize]);
            }

            if hr == windows::core::HRESULT::from(S_FALSE) || read == 0 {
                break;
            }
        }

        if data.is_empty() {
            let _ = log_desktop("BlpPreviewHandler::Initialize stream empty");
            return Err(Error::from(E_FAIL));
        }

        let mut st = self.state.lock().unwrap();
        st.path_utf8 = None;
        st.stream_data = Some(Arc::<[u8]>::from(data));
        drop(st);
        let _ = log_desktop("BlpPreviewHandler::Initialize stream cached");
        Ok(())
    }
}

impl IPreviewHandler_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn SetWindow(&self, hwnd: HWND, prc: *const RECT) -> WinResult<()> {
        if hwnd.0.is_null() || prc.is_null() {
            return Err(Error::from(E_INVALIDARG));
        }
        let rect = unsafe { *prc };
        let mut ui = self.ui.lock().unwrap();
        ui.parent = Some(hwnd);
        ui.rect = rect;
        let _ = log_desktop(format!(
            "BlpPreviewHandler::SetWindow hwnd={:?} rect=({}, {}, {}, {})",
            hwnd, rect.left, rect.top, rect.right, rect.bottom
        ));
        if ui.image.is_some() {
            BlpPreviewHandler::repaint_locked(&ui)?;
        }
        Ok(())
    }

    #[allow(non_snake_case)]
    fn SetRect(&self, prc: *const RECT) -> WinResult<()> {
        if prc.is_null() {
            return Err(Error::from(E_INVALIDARG));
        }
        let rect = unsafe { *prc };
        let mut ui = self.ui.lock().unwrap();
        ui.rect = rect;
        if ui.image.is_some() {
            BlpPreviewHandler::repaint_locked(&ui)?;
        }
        Ok(())
    }

    #[allow(non_snake_case)]
    fn DoPreview(&self) -> WinResult<()> {
        let _ = log_desktop("BlpPreviewHandler::DoPreview start");
        let (data, from_stream) = self.acquire_source()?;
        let (w, h, rgba) = decode_blp_rgba(&data).map_err(|_| Error::from(E_FAIL))?;

        let mut ui = self.ui.lock().unwrap();
        ui.image = Some(StoredImage {
            width: w,
            height: h,
            rgba: Arc::<[u8]>::from(rgba),
        });
        if ui.parent.is_some() {
            BlpPreviewHandler::repaint_locked(&ui)?;
        }

        let _ = log_desktop(format!(
            "BlpPreviewHandler::DoPreview decoded source {}x{} (stream={})",
            w, h, from_stream
        ));
        Ok(())
    }

    #[allow(non_snake_case)]
    fn Unload(&self) -> WinResult<()> {
        let _ = log_desktop("BlpPreviewHandler::Unload");
        let mut ui = self.ui.lock().unwrap();
        ui.image = None;
        Ok(())
    }

    #[allow(non_snake_case)]
    fn SetFocus(&self) -> WinResult<()> {
        Ok(())
    }

    #[allow(non_snake_case)]
    fn QueryFocus(&self) -> WinResult<HWND> {
        let ui = self.ui.lock().unwrap();
        ui.parent.ok_or_else(|| Error::from(E_FAIL))
    }

    #[allow(non_snake_case)]
    fn TranslateAccelerator(&self, _pmsg: *const MSG) -> WinResult<()> {
        Err(Error::from(S_FALSE))
    }
}

impl windows::Win32::System::Ole::IOleWindow_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn GetWindow(&self) -> WinResult<HWND> {
        let ui = self.ui.lock().unwrap();
        ui.parent.ok_or_else(|| Error::from(E_FAIL))
    }

    #[allow(non_snake_case)]
    fn ContextSensitiveHelp(&self, _fentermode: BOOL) -> WinResult<()> {
        Err(Error::from(S_FALSE))
    }
}

fn resize_fit_rgba_rect(
    src: &[u8],
    sw: u32,
    sh: u32,
    max_w: u32,
    max_h: u32,
) -> (u32, u32, Vec<u8>) {
    let max_w = max_w.max(1);
    let max_h = max_h.max(1);
    let scale = (max_w as f64 / sw as f64)
        .min(max_h as f64 / sh as f64)
        .min(1.0);

    let tw = (sw as f64 * scale).max(1.0).round() as u32;
    let th = (sh as f64 * scale).max(1.0).round() as u32;

    if tw == sw && th == sh {
        return (sw, sh, src.to_vec());
    }

    let mut out = vec![0u8; (tw * th * 4) as usize];
    for y in 0..th {
        let sy = (y as u64 * sh as u64 / th as u64) as u32;
        for x in 0..tw {
            let sx = (x as u64 * sw as u64 / tw as u64) as u32;
            let si = ((sy * sw + sx) * 4) as usize;
            let di = ((y * tw + x) * 4) as usize;
            out[di..di + 4].copy_from_slice(&src[si..si + 4]);
        }
    }
    (tw, th, out)
}

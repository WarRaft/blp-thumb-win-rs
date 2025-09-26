use crate::{
    DLL_LOCK_COUNT, ProviderState, create_hbitmap_bgra_premul, decode_blp_rgba, resize_fit_rgba,
    rgba_to_bgra_premul,
};
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use windows_implement::implement;

use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::UI::Shell::{IShellItem, SIGDN_FILESYSPATH, WTS_ALPHATYPE, WTSAT_ARGB};
use windows::core::Result as WinResult;
use windows_core::PWSTR;

#[implement(
    windows::Win32::UI::Shell::IThumbnailProvider,
    windows::Win32::UI::Shell::IInitializeWithItem
)]
pub struct BlpThumbProvider {
    state: Mutex<ProviderState>,
}

impl BlpThumbProvider {
    pub fn new() -> Self {
        DLL_LOCK_COUNT.fetch_add(1, Ordering::SeqCst);
        Self {
            state: Mutex::new(ProviderState::default()),
        }
    }
}

impl Drop for BlpThumbProvider {
    fn drop(&mut self) {
        DLL_LOCK_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
}

// ============================
// ВАЖНО: реализации на *_Impl
// ============================

impl windows::Win32::UI::Shell::IInitializeWithItem_Impl for BlpThumbProvider_Impl {
    #[allow(non_snake_case)]
    fn Initialize(
        &self,
        psi: windows::core::Ref<'_, IShellItem>,
        _grf_mode: u32,
    ) -> windows::core::Result<()> {
        unsafe {
            // Ref<IShellItem> -> &IShellItem
            let item: &IShellItem = psi.ok()?;
            let pw: PWSTR = item.GetDisplayName(SIGDN_FILESYSPATH)?;
            if pw.is_null() {
                return Err(windows::core::Error::from(
                    windows::Win32::Foundation::E_FAIL,
                ));
            }
            let s16 = widestring::U16CStr::from_ptr_str(pw.0);
            let mut st = self.state.lock().unwrap();
            st.path_utf8 = Some(s16.to_string_lossy());
            // при желании: windows::Win32::System::Memory::CoTaskMemFree(Some(pw.0 as _));
        }
        Ok(())
    }
}

impl windows::Win32::UI::Shell::IThumbnailProvider_Impl for BlpThumbProvider_Impl {
    #[allow(non_snake_case)]
    fn GetThumbnail(
        &self,
        cx: u32,
        phbmp: *mut HBITMAP,
        pdwalpha: *mut WTS_ALPHATYPE,
    ) -> WinResult<()> {
        use windows::Win32::Foundation::{E_FAIL, E_POINTER};
        use windows::core::Error;

        if phbmp.is_null() || pdwalpha.is_null() {
            return Err(Error::from(E_POINTER));
        }

        // путь из state
        let path = {
            let st = self.state.lock().unwrap();
            st.path_utf8.clone().ok_or_else(|| Error::from(E_FAIL))?
        };

        // читаем и декодим BLP → RGBA (mip0)
        let data = std::fs::read(path).map_err(|_| Error::from(E_FAIL))?;
        let (w, h, rgba) = decode_blp_rgba(&data).map_err(|_| Error::from(E_FAIL))?;
        let (tw, th, rgba_fit) = if cx > 0 && w.max(h) > cx {
            resize_fit_rgba(&rgba, w, h, cx)
        } else {
            (w, h, rgba)
        };

        // RGBA → BGRA premultiplied
        let bgra_pm = rgba_to_bgra_premul(&rgba_fit);

        // создаём HBITMAP
        let hbmp = unsafe { create_hbitmap_bgra_premul(tw as i32, th as i32, &bgra_pm)? };

        unsafe {
            *phbmp = hbmp;
            *pdwalpha = WTSAT_ARGB;
        }
        Ok(())
    }
}

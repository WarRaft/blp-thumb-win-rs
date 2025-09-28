use crate::{
    create_hbitmap_bgra_premul, decode_blp_rgba, resize_fit_rgba, rgba_to_bgra_premul, DLL_LOCK_COUNT,
    ProviderState,
};
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use windows_implement::implement;

use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::System::Com::{ISequentialStream, IStream, STREAM_SEEK_SET};
use windows::Win32::UI::Shell::{
    IInitializeWithFile, IInitializeWithItem, IInitializeWithStream, IShellItem, SIGDN_FILESYSPATH,
    WTS_ALPHATYPE, WTSAT_ARGB,
};
use windows::core::{Interface, Result as WinResult};
use windows_core::{PCWSTR, PWSTR};

#[implement(
    windows::Win32::UI::Shell::IThumbnailProvider,
    windows::Win32::UI::Shell::IInitializeWithItem,
    windows::Win32::UI::Shell::IInitializeWithStream,
    windows::Win32::UI::Shell::IInitializeWithFile
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
            st.stream_data = None;
            // при желании: windows::Win32::System::Memory::CoTaskMemFree(Some(pw.0 as _));
        }
        Ok(())
    }
}

impl windows::Win32::UI::Shell::IInitializeWithFile_Impl for BlpThumbProvider_Impl {
    #[allow(non_snake_case)]
    fn Initialize(
        &self,
        psz_file_path: &PCWSTR,
        _grf_mode: u32,
    ) -> windows::core::Result<()> {
        use windows::Win32::Foundation::E_FAIL;

        if psz_file_path.is_null() || psz_file_path.0.is_null() {
            return Err(windows::core::Error::from(E_FAIL));
        }

        let path = unsafe {
            widestring::U16CStr::from_ptr_str(psz_file_path.0)
                .to_string_lossy()
        };

        let mut st = self.state.lock().unwrap();
        st.path_utf8 = Some(path);
        st.stream_data = None;
        Ok(())
    }
}

impl windows::Win32::UI::Shell::IInitializeWithStream_Impl for BlpThumbProvider_Impl {
    #[allow(non_snake_case)]
    fn Initialize(
        &self,
        pstream: windows::core::Ref<'_, IStream>,
        _grf_mode: u32,
    ) -> windows::core::Result<()> {
        use windows::Win32::Foundation::{E_FAIL, S_FALSE};
        use windows::core::Error;

        let stream: &IStream = pstream.ok()?;

        // Always try to rewind to the beginning.
        unsafe {
            stream.Seek(0, STREAM_SEEK_SET, None)?;
        }

        let mut data = Vec::<u8>::new();
        let seq: ISequentialStream = stream.cast()?;
        let mut buf = [0u8; 8192];

        loop {
            let mut read = 0u32;
            let hr = unsafe {
                seq.Read(buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut read)
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
            return Err(Error::from(E_FAIL));
        }

        let mut st = self.state.lock().unwrap();
        st.path_utf8 = None;
        st.stream_data = Some(Arc::from(data));
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

        // ---- GREEN SQUARE SHORT-CIRCUIT ----
        if option_env!("NEVER").is_none() {
            let side = if cx > 0 { cx } else { 256 };
            let mut bgra = vec![0u8; (side as usize) * (side as usize) * 4];
            for px in bgra.chunks_exact_mut(4) {
                // BGRA (premultiplied), opaque green
                px[0] = 0; // B
                px[1] = 255; // G
                px[2] = 0; // R
                px[3] = 255; // A (opaque)
            }
            let hbmp = unsafe { create_hbitmap_bgra_premul(side as i32, side as i32, &bgra)? };
            unsafe {
                *phbmp = hbmp;
                *pdwalpha = WTSAT_ARGB;
            }
            return Ok(());
        }
        // ------------------------------------

        // источник: либо кэшированные данные из потока, либо путь на диске
        let (data_arc, path_opt) = {
            let st = self.state.lock().unwrap();
            (st.stream_data.clone(), st.path_utf8.clone())
        };

        let data_arc: Arc<[u8]> = if let Some(buf) = data_arc {
            buf
        } else {
            let path = path_opt.ok_or_else(|| Error::from(E_FAIL))?;
            let raw = std::fs::read(path).map_err(|_| Error::from(E_FAIL))?;
            Arc::from(raw)
        };

        // читаем и декодим BLP → RGBA (mip0)
        let (w, h, rgba) = decode_blp_rgba(&data_arc).map_err(|_| Error::from(E_FAIL))?;
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

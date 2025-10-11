use crate::{DLL_LOCK_COUNT, ProviderState};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use windows_implement::implement;

use crate::log::log;
use crate::utils::create_hbitmap_bgra_premul::create_hbitmap_bgra_premul;
use crate::utils::decode_blp_rgba::decode_blp_rgba;
use crate::utils::resize_fit_rgba::resize_fit_rgba;
use crate::utils::rgba_to_bgra_premul::rgba_to_bgra_premul;
use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::System::Com::{ISequentialStream, IStream, STREAM_SEEK_SET};
use windows::Win32::UI::Shell::PropertiesSystem::{IInitializeWithFile_Impl, IInitializeWithStream_Impl};
use windows::Win32::UI::Shell::{IInitializeWithItem_Impl, IShellItem, SIGDN_FILESYSPATH, WTS_ALPHATYPE, WTSAT_ARGB};
use windows::core::{Interface, Result as WinResult};
use windows_core::{PCWSTR, PWSTR};

#[implement(windows::Win32::UI::Shell::IThumbnailProvider, windows::Win32::UI::Shell::IInitializeWithItem, windows::Win32::UI::Shell::PropertiesSystem::IInitializeWithStream, windows::Win32::UI::Shell::PropertiesSystem::IInitializeWithFile)]
pub struct BlpThumbProvider {
    state: Mutex<ProviderState>,
}

impl BlpThumbProvider {
    pub fn new() -> Self {
        DLL_LOCK_COUNT.fetch_add(1, Ordering::SeqCst);
        log("BlpThumbProvider::new");
        Self { state: Mutex::new(ProviderState::default()) }
    }
}

impl Drop for BlpThumbProvider {
    fn drop(&mut self) {
        DLL_LOCK_COUNT.fetch_sub(1, Ordering::SeqCst);
        log("BlpThumbProvider::drop");
    }
}

// ============================
// ВАЖНО: реализации на *_Impl
// ============================

impl IInitializeWithItem_Impl for BlpThumbProvider_Impl {
    #[allow(non_snake_case)]
    fn Initialize(&self, psi: windows::core::Ref<'_, IShellItem>, _grf_mode: u32) -> windows::core::Result<()> {
        unsafe {
            // Ref<IShellItem> -> &IShellItem
            let item: &IShellItem = psi.ok()?;
            let pw: PWSTR = item.GetDisplayName(SIGDN_FILESYSPATH)?;
            if pw.is_null() {
                return Err(windows::core::Error::from(windows::Win32::Foundation::E_FAIL));
            }
            let s16 = widestring::U16CStr::from_ptr_str(pw.0);
            let path = s16.to_string_lossy();
            let mut st = self.state.lock().unwrap();
            st.path_utf8 = Some(path.clone());
            st.stream_data = None;
            drop(st);
            log(format!("IInitializeWithItem: path={}", path));
            // при желании: windows::Win32::System::Memory::CoTaskMemFree(Some(pw.0 as _));
        }
        Ok(())
    }
}

impl IInitializeWithFile_Impl for BlpThumbProvider_Impl {
    #[allow(non_snake_case)]
    fn Initialize(&self, psz_file_path: &PCWSTR, _grf_mode: u32) -> windows::core::Result<()> {
        use windows::Win32::Foundation::E_FAIL;

        if psz_file_path.is_null() || psz_file_path.0.is_null() {
            return Err(windows::core::Error::from(E_FAIL));
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

impl IInitializeWithStream_Impl for BlpThumbProvider_Impl {
    #[allow(non_snake_case)]
    fn Initialize(&self, pstream: windows::core::Ref<'_, IStream>, _grf_mode: u32) -> windows::core::Result<()> {
        use windows::Win32::Foundation::{E_FAIL, S_FALSE};
        use windows::core::Error;

        log("IInitializeWithStream: begin");

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
            let hr = unsafe { seq.Read(buf.as_mut_ptr() as *mut _, buf.len() as u32, Some(&mut read as *mut u32)) };

            if hr.is_err() {
                log(format!("IInitializeWithStream: Read failed hr=0x{:08X}", hr.0 as u32));
                return Err(Error::from(hr));
            }

            if read > 0 {
                data.extend_from_slice(&buf[..read as usize]);
            }

            if hr == windows::core::HRESULT::from(S_FALSE) || read == 0 {
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

impl windows::Win32::UI::Shell::IThumbnailProvider_Impl for BlpThumbProvider_Impl {
    #[allow(non_snake_case)]
    fn GetThumbnail(&self, cx: u32, phbmp: *mut HBITMAP, pdwalpha: *mut WTS_ALPHATYPE) -> WinResult<()> {
        use windows::Win32::Foundation::{E_FAIL, E_POINTER};
        use windows::core::Error;

        if phbmp.is_null() || pdwalpha.is_null() {
            return Err(Error::from(E_POINTER));
        }

        log(format!("GetThumbnail: start (cx={})", cx));

        // источник: либо кэшированные данные из потока, либо путь на диске
        let (data_arc, path_opt) = {
            let st = self.state.lock().unwrap();
            (st.stream_data.clone(), st.path_utf8.clone())
        };

        let using_stream = data_arc.is_some();
        let data_arc: Arc<[u8]> = if let Some(buf) = data_arc {
            log(format!("GetThumbnail: using cached stream buffer ({} bytes)", buf.len()));
            buf
        } else {
            let path = path_opt.ok_or_else(|| {
                log("GetThumbnail: no stream and no path available");
                Error::from(E_FAIL)
            })?;
            log(format!("GetThumbnail: reading from file {}", path));
            let raw = std::fs::read(&path).map_err(|err| {
                log(format!("GetThumbnail: read failed for {} ({})", path, err));
                Error::from(E_FAIL)
            })?;
            Arc::from(raw)
        };

        let data_len = data_arc.len();

        // читаем и декодим BLP → RGBA (mip0)
        let (w, h, rgba) = decode_blp_rgba(&data_arc).map_err(|_| {
            log(format!("GetThumbnail: decode failed (source={}, bytes={})", if using_stream { "stream" } else { "file" }, data_len));
            Error::from(E_FAIL)
        })?;
        let (tw, th, rgba_fit) = if cx > 0 && w.max(h) > cx { resize_fit_rgba(&rgba, w, h, cx) } else { (w, h, rgba) };

        log(format!("GetThumbnail: decoded {}x{} -> {}x{} (stream={}, bytes={})", w, h, tw, th, using_stream, data_len));

        // RGBA → BGRA premultiplied
        let bgra_pm = rgba_to_bgra_premul(&rgba_fit);

        // создаём HBITMAP
        let hbmp = unsafe { create_hbitmap_bgra_premul(tw as i32, th as i32, &bgra_pm)? };

        unsafe {
            *phbmp = hbmp;
            *pdwalpha = WTSAT_ARGB;
        }
        log(format!("GetThumbnail: success ({}x{}, stream={})", tw, th, using_stream));
        Ok(())
    }
}

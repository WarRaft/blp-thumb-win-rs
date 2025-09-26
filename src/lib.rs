#![cfg(target_os = "windows")]

mod keys;

use blp::core::image::ImageBlp;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{copy_nonoverlapping, null, null_mut};
use std::sync::atomic::{AtomicU32, Ordering};
use widestring::U16CStr;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::Com::*;
use windows::Win32::UI::Shell::*;
use windows::core::*;

// ========== CONFIG ==========
const FRIENDLY_NAME: &str = "BLP Thumbnail Provider";

// ========== DLL lock count for DllCanUnloadNow ==========
static DLL_LOCK_COUNT: AtomicU32 = AtomicU32::new(0);

// ========== Provider state ==========
#[derive(Default)]
struct ProviderState {
    path_utf8: Option<String>, // set by IInitializeWithFile
}

// ========== COM: IThumbnailProvider + IInitializeWithFile ==========
#[implement(IThumbnailProvider, IInitializeWithFile)]
struct BlpThumbProvider {
    state: ProviderState,
}

impl BlpThumbProvider {
    fn new() -> Self {
        DLL_LOCK_COUNT.fetch_add(1, Ordering::SeqCst);
        Self {
            state: ProviderState::default(),
        }
    }
}

impl Drop for BlpThumbProvider {
    fn drop(&mut self) {
        DLL_LOCK_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
}

// IInitializeWithFile
#[allow(non_snake_case)]
impl BlpThumbProvider {
    fn Initialize(&mut self, psz_file_path: PCWSTR, _grf_mode: u32) -> Result<()> {
        if psz_file_path.is_null() {
            return Err(Error::from(E_INVALIDARG));
        }
        // Convert PWSTR → UTF-8
        unsafe {
            let s16 = U16CStr::from_ptr_str(psz_file_path.0);
            self.state.path_utf8 = Some(s16.to_string_lossy());
        }
        Ok(())
    }
}
use std::{fs, path::Path};

#[allow(non_snake_case)]
impl BlpThumbProvider {
    fn GetThumbnail(
        &self,
        cx: u32,
        phbmp: *mut HBITMAP,
        pdwalpha: *mut WTS_ALPHATYPE,
    ) -> Result<()> {
        if phbmp.is_null() || pdwalpha.is_null() {
            return Err(Error::from(E_POINTER));
        }

        // 0) Путь из состояния → читаем файл в память
        let path = self
            .state
            .path_utf8
            .as_ref()
            .ok_or_else(|| Error::from(E_FAIL))?;
        let data = fs::read(Path::new(path)).map_err(|_| Error::from(E_FAIL))?;

        // 1) Декод BLP из буфера (генерим только mip0)
        let mut img = ImageBlp::from_buf_blp(&data).map_err(|_| Error::from(E_FAIL))?;
        let mut vis = [false; MAX_MIPS];
        vis[0] = true;
        img.decode(&data, &vis).map_err(|_| Error::from(E_FAIL))?;

        // Берём mip0 как RGBA
        let mip0 = img.mipmaps[0]
            .image
            .as_ref()
            .ok_or_else(|| Error::from(E_FAIL))?;
        let (mut w, mut h) = (mip0.width(), mip0.height());

        // 1.1 fit-даунскейл до cx при необходимости
        let rgba_fit: Vec<u8> = if w.max(h) > cx && cx > 0 {
            let (tw, th, out) = resize_fit_rgba(mip0.as_raw(), w, h, cx);
            w = tw;
            h = th;
            out
        } else {
            mip0.as_raw().clone()
        };

        // 2) RGBA → BGRA premultiplied
        let mut bgra_pm = vec![0u8; rgba_fit.len()];
        let pixels = (w as usize) * (h as usize);
        for p in 0..pixels {
            let r = rgba_fit[p * 4 + 0] as u32;
            let g = rgba_fit[p * 4 + 1] as u32;
            let b = rgba_fit[p * 4 + 2] as u32;
            let a = rgba_fit[p * 4 + 3] as u32;
            bgra_pm[p * 4 + 0] = ((b * a + 127) / 255) as u8; // B
            bgra_pm[p * 4 + 1] = ((g * a + 127) / 255) as u8; // G
            bgra_pm[p * 4 + 2] = ((r * a + 127) / 255) as u8; // R
            bgra_pm[p * 4 + 3] = a as u8; // A
        }

        // 3) HBITMAP
        unsafe {
            let hbmp = create_hbitmap_bgra_premul(w as i32, h as i32, &bgra_pm)?;
            *phbmp = hbmp;
            *pdwalpha = WTS_ALPHATYPE::WTSAT_ARGB;
        }
        Ok(())
    }
}

/// Наивный nearest-neighbor FIT до квадрата `cx` (с сохранением пропорций).
#[inline]
fn resize_fit_rgba(src: &[u8], sw: u32, sh: u32, cx: u32) -> (u32, u32, Vec<u8>) {
    let (tw, th) = if sw >= sh {
        let tw = cx.max(1);
        let th = ((sh as u64 * tw as u64) / sw as u64).max(1) as u32;
        (tw, th)
    } else {
        let th = cx.max(1);
        let tw = ((sw as u64 * th as u64) / sh as u64).max(1) as u32;
        (tw, th)
    };

    let mut out = vec![0u8; (tw * th * 4) as usize];

    // nearest-neighbor
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

// ========== GDI helper: CreateDIBSection for 32bpp BGRA premul ==========
unsafe fn create_hbitmap_bgra_premul(
    width: i32,
    height: i32,
    pixels_bgra: &[u8],
) -> Result<HBITMAP> {
    // BITMAPV5HEADER for alpha-friendly DIB
    let mut bi: BITMAPV5HEADER = zeroed();
    bi.bV5Size = size_of::<BITMAPV5HEADER>() as u32;
    bi.bV5Width = width;
    bi.bV5Height = -height; // negative = top-down
    bi.bV5Planes = 1;
    bi.bV5BitCount = 32;
    bi.bV5Compression = BI_BITFIELDS;
    bi.bV5RedMask = 0x00FF0000;
    bi.bV5GreenMask = 0x0000FF00;
    bi.bV5BlueMask = 0x000000FF;
    bi.bV5AlphaMask = 0xFF000000;
    bi.bV5CSType = LCS_sRGB;

    let hdc = HDC(0);
    let mut bits: *mut c_void = null_mut();

    let hbmp = CreateDIBSection(
        hdc,
        &*(&bi as *const BITMAPV5HEADER as *const BITMAPINFO),
        DIB_RGB_COLORS,
        &mut bits,
        None,
        0,
    );
    if hbmp.is_invalid() || bits.is_null() {
        return Err(Error::from(E_FAIL));
    }

    let expected = (width as usize) * (height as usize) * 4;
    if pixels_bgra.len() != expected {
        DeleteObject(hbmp);
        return Err(Error::from(E_INVALIDARG));
    }

    copy_nonoverlapping(pixels_bgra.as_ptr(), bits as *mut u8, expected);
    Ok(hbmp)
}

// ========== Class Factory (IClassFactory) ==========

#[implement(IClassFactory)]
struct BlpClassFactory;

#[allow(non_snake_case)]
impl BlpClassFactory {
    fn CreateInstance(
        &self,
        _outer: Option<&IUnknown>,
        iid: *const GUID,
        out: *mut *mut c_void,
    ) -> HRESULT {
        unsafe {
            if out.is_null() {
                return E_POINTER;
            }
            *out = null_mut();

            // Create the COM object
            let obj = BlpThumbProvider::new();
            let ccw = ComInterface::into_raw(obj.into());

            // Query for requested interface
            let hr = (*(ccw as *mut IUnknown)).QueryInterface(iid, out);
            (*(ccw as *mut IUnknown)).Release();

            hr
        }
    }

    fn LockServer(&self, f_lock: BOOL) -> HRESULT {
        if f_lock.as_bool() {
            DLL_LOCK_COUNT.fetch_add(1, Ordering::SeqCst);
        } else {
            DLL_LOCK_COUNT.fetch_sub(1, Ordering::SeqCst);
        }
        S_OK
    }
}

// Helper trait to wrap our struct into COM IUnknown via windows-rs
trait ComInterface: Sized {
    fn into_raw(self) -> *mut c_void;
}
impl ComInterface for BlpThumbProvider {
    fn into_raw(self) -> *mut c_void {
        // `implement` macro makes `BlpThumbProvider` convertible to IUnknown
        let unknown: IUnknown = self.into();
        unknown.into_raw() as *mut c_void
    }
}

// ========== DLL exports ==========

#[no_mangle]
pub extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    unsafe {
        if ppv.is_null() {
            return E_POINTER;
        }
        *ppv = null_mut();

        if rclsid.is_null() || *rclsid != CLSID_BLP_THUMB {
            return CLASS_E_CLASSNOTAVAILABLE;
        }

        // Return IClassFactory for our CLSID
        let factory = BlpClassFactory;
        let unk: IUnknown = factory.into();
        let hr = unk.query(riid, ppv);
        hr
    }
}

#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    if DLL_LOCK_COUNT.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}

// (Optional) friendly registry script body if you decide to self-register from code:
// But for Rust cdylib we use the external installer you already have.

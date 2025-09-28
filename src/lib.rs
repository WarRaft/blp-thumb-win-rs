mod class_factory;
pub mod keys;
mod thumbnail_provider;

#[cfg(not(target_pointer_width = "64"))]
compile_error!("blp-thumb-win must be built for 64-bit targets");

use std::env;
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::keys::CLSID_BLP_THUMB;
use blp::core::image::{ImageBlp, MAX_MIPS};

use once_cell::sync::Lazy;
use windows::Win32::Graphics::Gdi::{BI_BITFIELDS, HBITMAP};

use windows::Win32::Foundation::{E_FAIL, E_INVALIDARG, E_NOINTERFACE, E_POINTER, S_FALSE, S_OK};
use windows::Win32::Graphics::Gdi::{
    BITMAPINFO, BITMAPV5HEADER, CreateDIBSection, DIB_RGB_COLORS, DeleteObject,
};
use windows::Win32::System::Com::IClassFactory;

use crate::class_factory::BlpClassFactory;
use windows::core::{GUID, HRESULT, IUnknown, Interface};

const CLASS_E_CLASSNOTAVAILABLE: HRESULT = HRESULT(0x80040111u32 as i32);

static DLL_LOCK_COUNT: AtomicU32 = AtomicU32::new(0);
static DESKTOP_LOG_PATH: Lazy<Result<PathBuf, String>> = Lazy::new(desktop_log_path);

#[derive(Default)]
struct ProviderState {
    path_utf8: Option<String>,
    stream_data: Option<Arc<[u8]>>,
}

pub fn log_desktop(message: impl AsRef<str>) -> Result<(), String> {
    use chrono::Local;

    let path = DESKTOP_LOG_PATH
        .as_ref()
        .map_err(|err| err.clone())?
        .clone();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {}", parent.display(), e))?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("failed to open {}: {}", path.display(), e))?;

    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
    writeln!(file, "[{}] {}", timestamp, message.as_ref())
        .map_err(|e| format!("failed to write to {}: {}", path.display(), e))?;

    Ok(())
}

fn desktop_log_path() -> Result<PathBuf, String> {
    let mut candidates = Vec::new();

    if let Some(profile) = env::var_os("USERPROFILE") {
        candidates.push(PathBuf::from(profile));
    }
    if let (Some(drive), Some(path)) = (env::var_os("HOMEDRIVE"), env::var_os("HOMEPATH")) {
        let mut p = PathBuf::from(drive);
        p.push(PathBuf::from(path));
        candidates.push(p);
    }
    if let Some(home) = env::var_os("HOME") {
        candidates.push(PathBuf::from(home));
    }

    for mut base in candidates {
        base.push("Desktop");
        base.push("blp-thumb-win.log");
        return Ok(base);
    }

    Err("unable to locate Desktop path via USERPROFILE/HOMEPATH/HOME".to_string())
}

// ---- helpers: decode/resize/convert ----
fn decode_blp_rgba(data: &[u8]) -> Result<(u32, u32, Vec<u8>), ()> {
    let mut img = ImageBlp::from_buf(data).map_err(|_| ())?;

    let mut vis = [false; MAX_MIPS];
    vis[0] = true;
    img.decode(data, &vis).map_err(|_| ())?;

    let mip0 = img.mipmaps[0].image.as_ref().ok_or(())?;
    let (w, h) = (mip0.width(), mip0.height());
    Ok((w, h, mip0.as_raw().clone()))
}

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

#[inline]
fn rgba_to_bgra_premul(rgba: &[u8]) -> Vec<u8> {
    let pixels = rgba.len() / 4;
    let mut out = vec![0u8; rgba.len()];
    for p in 0..pixels {
        let r = rgba[p * 4 + 0] as u32;
        let g = rgba[p * 4 + 1] as u32;
        let b = rgba[p * 4 + 2] as u32;
        let a = rgba[p * 4 + 3] as u32;
        out[p * 4 + 0] = ((b * a + 127) / 255) as u8;
        out[p * 4 + 1] = ((g * a + 127) / 255) as u8;
        out[p * 4 + 2] = ((r * a + 127) / 255) as u8;
        out[p * 4 + 3] = a as u8;
    }
    out
}

// ---- GDI ----
unsafe fn create_hbitmap_bgra_premul(
    width: i32,
    height: i32,
    pixels_bgra: &[u8],
) -> windows::core::Result<HBITMAP> {
    pub const LCS_SRGB_U32: u32 = 0x7352_4742; // 'sRGB' в little-endian

    use core::ffi::c_void;
    use core::mem::{size_of, zeroed};
    use core::ptr::copy_nonoverlapping;

    // BITMAPV5HEADER под топ-даун 32bpp BGRA с альфой
    let mut v5: BITMAPV5HEADER = unsafe { zeroed() };
    v5.bV5Size = size_of::<BITMAPV5HEADER>() as u32;
    v5.bV5Width = width;
    v5.bV5Height = -height; // отрицательная высота = top-down
    v5.bV5Planes = 1;
    v5.bV5BitCount = 32;
    v5.bV5Compression = BI_BITFIELDS;
    v5.bV5RedMask = 0x00FF_0000;
    v5.bV5GreenMask = 0x0000_FF00;
    v5.bV5BlueMask = 0x0000_00FF;
    v5.bV5AlphaMask = 0xFF00_0000;
    v5.bV5CSType = LCS_SRGB_U32; // 'sRGB'

    let mut bits: *mut c_void = null_mut();

    // Создаём DIB-секцию
    let hbmp: HBITMAP = unsafe {
        CreateDIBSection(
            None, // Option<HDC>
            &*(&v5 as *const BITMAPV5HEADER as *const BITMAPINFO),
            DIB_RGB_COLORS,
            &mut bits,
            None, // hSection
            0,    // offset
        )?
    };

    // Проверяем, что нам отдали указатель на пиксели
    if bits.is_null() {
        unsafe {
            let _ = DeleteObject(hbmp.into());
        }
        return Err(windows::core::Error::from(E_FAIL));
    }

    // Размер входного буфера должен совпасть
    let expected = (width as usize) * (height as usize) * 4;
    if pixels_bgra.len() != expected {
        unsafe {
            let _ = DeleteObject(hbmp.into());
        }
        return Err(windows::core::Error::from(E_INVALIDARG));
    }

    // Копируем BGRA pre-multiplied в DIB
    unsafe { copy_nonoverlapping(pixels_bgra.as_ptr(), bits as *mut u8, expected) };

    Ok(hbmp)
}

// ---- DLL exports ----
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
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

        let cf: IClassFactory = BlpClassFactory.into();

        if riid.is_null() {
            return E_POINTER;
        }
        if *riid == IClassFactory::IID || *riid == IUnknown::IID {
            *ppv = cf.into_raw();
            S_OK
        } else {
            E_NOINTERFACE
        }
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    if DLL_LOCK_COUNT.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}

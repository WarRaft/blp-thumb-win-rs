use std::ptr::null_mut;
use windows::Win32::Foundation::{E_FAIL, E_INVALIDARG};
use windows::Win32::Graphics::Gdi::{BI_BITFIELDS, BITMAPINFO, BITMAPV5HEADER, CreateDIBSection, DIB_RGB_COLORS, DeleteObject, HBITMAP};

pub unsafe fn create_hbitmap_bgra_premul(width: i32, height: i32, pixels_bgra: &[u8]) -> windows::core::Result<HBITMAP> {
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

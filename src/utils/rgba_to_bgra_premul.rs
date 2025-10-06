#[inline]
pub fn rgba_to_bgra_premul(rgba: &[u8]) -> Vec<u8> {
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

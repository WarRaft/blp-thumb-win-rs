pub fn rgba_to_bgra_with_bg(rgba: &[u8], bg: (u8, u8, u8)) -> Vec<u8> {
    let (bg_r, bg_g, bg_b) = bg;
    let mut out = Vec::with_capacity(rgba.len());
    for px in rgba.chunks_exact(4) {
        let r = px[0];
        let g = px[1];
        let b = px[2];
        let a = px[3] as u32;
        let inv_a = 255 - a;
        let out_r = ((r as u32 * a + bg_r as u32 * inv_a) / 255) as u8;
        let out_g = ((g as u32 * a + bg_g as u32 * inv_a) / 255) as u8;
        let out_b = ((b as u32 * a + bg_b as u32 * inv_a) / 255) as u8;
        out.extend_from_slice(&[out_b, out_g, out_r, 0xFF]);
    }
    out
}

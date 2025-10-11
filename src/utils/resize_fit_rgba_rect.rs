pub fn resize_fit_rgba_rect(src: &[u8], sw: u32, sh: u32, max_w: u32, max_h: u32) -> (u32, u32, Vec<u8>) {
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

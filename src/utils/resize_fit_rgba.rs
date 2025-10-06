#[inline]
pub fn resize_fit_rgba(src: &[u8], sw: u32, sh: u32, cx: u32) -> (u32, u32, Vec<u8>) {
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

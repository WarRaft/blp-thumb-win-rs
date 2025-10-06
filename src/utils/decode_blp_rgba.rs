use blp::core::image::{ImageBlp, MAX_MIPS};

pub fn decode_blp_rgba(data: &[u8]) -> Result<(u32, u32, Vec<u8>), ()> {
    let mut img = ImageBlp::from_buf(data).map_err(|_| ())?;

    let mut vis = [false; MAX_MIPS];
    vis[0] = true;
    img.decode(data, &vis).map_err(|_| ())?;

    let mip0 = img.mipmaps[0].image.as_ref().ok_or(())?;
    let (w, h) = (mip0.width(), mip0.height());
    Ok((w, h, mip0.as_raw().clone()))
}

use std::io;
pub fn toggle_logging() -> io::Result<()> {
    blp_thumb_win::log::toggle_logging();
    Ok(())
}

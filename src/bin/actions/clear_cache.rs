use blp_thumb_win::log::log_cli;
use std::path::PathBuf;
use std::{env, fs, io};

pub fn clear_cache() -> io::Result<()> {
    log_cli("Clear cache: start");
    let Some(local) = env::var_os("LOCALAPPDATA") else {
        println!("LOCALAPPDATA is not set.");
        log_cli("Clear cache: LOCALAPPDATA not set");
        return Ok(());
    };
    let dir = PathBuf::from(local).join(r"Microsoft\Windows\Explorer");
    if !dir.is_dir() {
        println!("No thumbnail cache dir: {}", dir.display());
        log_cli(format!(
            "Clear cache: directory {} not found",
            dir.display()
        ));
        return Ok(());
    }
    let mut removed = 0usize;
    for e in fs::read_dir(&dir)? {
        let p = e?.path();
        if p.is_file() {
            if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                if name.starts_with("thumbcache_") {
                    let _ = fs::remove_file(&p);
                    removed += 1;
                }
            }
        }
    }
    println!("Removed {} files in {}", removed, dir.display());
    log_cli(format!(
        "Clear cache: removed {} files from {}",
        removed,
        dir.display()
    ));
    Ok(())
}

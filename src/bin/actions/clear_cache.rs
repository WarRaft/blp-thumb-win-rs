use std::path::PathBuf;
use std::{env, fs, io};

use blp_thumb_win::log::log_ui;

use blp_thumb_win::utils::guid::GuidExt;
use blp_thumb_win::{CLSID_BLP_PREVIEW, CLSID_BLP_THUMB};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};

/// Thin wrapper: run `clear_cache_inner()` and log any error instead of bubbling it to the UI.
/// This mirrors the install/install_inner pattern.
pub fn clear_cache() -> io::Result<()> {
    if let Err(err) = clear_cache_inner() {
        log_ui(format!("Clear cache failed: {}", err));
    }
    Ok(())
}

/// Clears per-user shell extension caches for our handlers:
/// 1) HKCU Shell Extensions cached values containing our CLSIDs
/// 2) On-disk Explorer thumbnail cache files under %LOCALAPPDATA%\Microsoft\Windows\Explorer
fn clear_cache_inner() -> io::Result<()> {
    log_ui("Clear cache: start");

    // -------------------------------------------------------------------------
    // 1) Registry cache: HKCU\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached
    //
    // We remove any value whose name contains our CLSID (with or without braces).
    // This forces Explorer to forget stale COM activation caches for our handlers.
    // -------------------------------------------------------------------------
    {
        let root = RegKey::predef(HKEY_CURRENT_USER);
        let path = r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached";
        match root.open_subkey_with_flags(path, KEY_READ | KEY_SET_VALUE) {
            Ok(key) => {
                let clsids = [CLSID_BLP_THUMB.to_braced_upper(), CLSID_BLP_PREVIEW.to_braced_upper()];
                let mut total_removed = 0usize;

                for clsid in clsids {
                    let clsid_upper = clsid.to_ascii_uppercase();
                    let clsid_nobrace = clsid_upper.trim_matches('{').trim_matches('}').to_string();

                    // Collect matching value names first (don't mutate while iterating).
                    let mut to_delete = Vec::new();
                    for value in key.enum_values() {
                        if let Ok((name, _)) = value {
                            let upper = name.to_ascii_uppercase();
                            if upper.contains(&clsid_upper) || upper.contains(&clsid_nobrace) {
                                to_delete.push(name);
                            }
                        }
                    }

                    // Delete collected values.
                    let mut removed = 0usize;
                    for name in to_delete {
                        if key.delete_value(&name).is_ok() {
                            removed += 1;
                        }
                    }
                    total_removed += removed;

                    log_ui(format!(
                        "HKCU: removed {} cached entries for {}",
                        removed, clsid
                    ));
                }

                if total_removed == 0 {
                    log_ui("HKCU: Shell Extensions\\Cached had no matching entries");
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                // Cache key may not exist on a fresh profile — that's fine.
                log_ui("HKCU: shell extension cache key missing");
            }
            Err(err) => {
                // Surface the error to the caller so the wrapper can log and proceed.
                return Err(err);
            }
        }
    }

    // -------------------------------------------------------------------------
    // 2) On-disk thumbnail cache: %LOCALAPPDATA%\Microsoft\Windows\Explorer
    //
    // We delete files that start with "thumbcache_". Explorer rebuilds them on demand.
    // This does NOT affect system-wide caches, only the current user.
    // -------------------------------------------------------------------------
    {
        let Some(local) = env::var_os("LOCALAPPDATA") else {
            log_ui("Clear cache: LOCALAPPDATA is not set");
            // Not an error for our purposes — nothing to clear on disk.
            return Ok(());
        };

        let dir = PathBuf::from(local).join(r"Microsoft\Windows\Explorer");
        if !dir.is_dir() {
            log_ui(format!(
                "Clear cache: directory {} not found",
                dir.display()
            ));
        } else {
            let mut removed = 0usize;
            for entry in fs::read_dir(&dir)? {
                let path = entry?.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                        if name.starts_with("thumbcache_") {
                            // Best-effort: ignore individual file errors, keep going.
                            let _ = fs::remove_file(&path);
                            removed += 1;
                        }
                    }
                }
            }
            log_ui(format!(
                "Clear cache: removed {} files from {}",
                removed,
                dir.display()
            ));
        }
    }

    log_ui("Clear cache: done");
    Ok(())
}

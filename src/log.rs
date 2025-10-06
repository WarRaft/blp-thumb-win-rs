use once_cell::sync::Lazy;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

/// Registry subkey storing misc settings shared between DLL and installer.
pub const LOG_SETTINGS_SUBKEY: &str = r"Software\blp-thumb-win";

/// Value under [`LOG_SETTINGS_SUBKEY`] toggling verbose logging (REG_DWORD 0/1).
pub const LOGGING_VALUE_NAME: &str = "LoggingEnabled";

static DESKTOP_LOG_PATH: Lazy<Result<PathBuf, String>> = Lazy::new(desktop_log_path);

pub fn log_file_path() -> Option<PathBuf> {
    DESKTOP_LOG_PATH.as_ref().ok().map(|p| p.clone())
}

pub fn desktop_log_path() -> Result<PathBuf, String> {
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

pub fn log_cli(message: impl Into<String>) {
    let text = message.into();
    if let Err(err) = log_desktop(&text) {
        eprintln!("[log] cannot write '{}': {}", text, err);
    }
}

pub fn log_ui(message: impl AsRef<str>) {
    let msg = message.as_ref();
    log_cli(msg);
    println!("{msg}");
}

pub fn log_desktop(message: impl AsRef<str>) -> Result<(), String> {
    if !log_endabled() {
        return Ok(());
    }
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

pub fn log_endabled() -> bool {
    fn read_from(hive: RegKey) -> Option<bool> {
        let key = hive.open_subkey(LOG_SETTINGS_SUBKEY).ok()?;
        let value = key.get_value::<u32, _>(LOGGING_VALUE_NAME).ok()?;
        Some(value != 0)
    }

    read_from(RegKey::predef(HKEY_CURRENT_USER))
        .or_else(|| read_from(RegKey::predef(HKEY_LOCAL_MACHINE)))
        .unwrap_or(false)
}

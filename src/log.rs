use crate::{DESKTOP_LOG_PATH, keys};
use std::fs::OpenOptions;
use std::io::Write;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

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
        let key = hive.open_subkey(keys::LOG_SETTINGS_SUBKEY).ok()?;
        let value = key.get_value::<u32, _>(keys::LOGGING_VALUE_NAME).ok()?;
        Some(value != 0)
    }

    read_from(RegKey::predef(HKEY_CURRENT_USER))
        .or_else(|| read_from(RegKey::predef(HKEY_LOCAL_MACHINE)))
        .unwrap_or(false)
}

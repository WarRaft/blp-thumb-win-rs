use blp_thumb_win::keys::{LOG_SETTINGS_SUBKEY, LOGGING_VALUE_NAME};
use blp_thumb_win::log::{log_endabled, log_ui};
use std::{fs, io};
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

/* ============================================================================
Toggle runtime logging (per-user, HKCU).

This function flips the per-user logging switch and persists it under:
  HKCU\{LOG_SETTINGS_SUBKEY}\{LOGGING_VALUE_NAME}  (DWORD: 1 = enabled, 0 = disabled)

Behavior:
- When enabling, we only store the flag (no file ops).
- When disabling, we also best-effort remove the current log file (if it exists).
- We do NOT modify any other settings or machine-wide keys.

Notes:
- Uses HKCU only; elevation should not be required. If access is denied due to policy,
  we log a clear message and return the error to the caller.
- This inlines the old `set_logging_enabled` logic so all work happens here.
============================================================================ */
pub fn toggle_logging() -> io::Result<()> {
    // Determine target state by flipping the current one.
    let current = log_endabled();
    let target = !current;

    log_ui(format!(
        "Logging toggle: current = {}, target = {}",
        if current { "enabled" } else { "disabled" },
        if target { "enabled" } else { "disabled" }
    ));

    // Persist the flag under HKCU\{LOG_SETTINGS_SUBKEY}\{LOGGING_VALUE_NAME}.
    let root = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = root.create_subkey(LOG_SETTINGS_SUBKEY)?;
    let value: u32 = if target { 1 } else { 0 };

    log_ui(format!(
        r"Writing HKCU\{} \ {} = {}",
        LOG_SETTINGS_SUBKEY, LOGGING_VALUE_NAME, value
    ));

    if let Err(err) = key.set_value(LOGGING_VALUE_NAME, &value) {
        if err.raw_os_error() == Some(5) {
            // Access denied (policy or restricted HKCU hive)
            log_ui(
                "Access denied when writing the HKCU logging flag. Try elevated context or review policy.",
            );
        }
        return Err(err);
    }

    // If we just disabled logging, best-effort remove the current log file (if any).
    if !target {
        if let Some(path) = blp_thumb_win::log_file_path() {
            if path.exists() {
                log_ui(format!("Removing log file: {}", path.display()));
                match fs::remove_file(&path) {
                    Ok(()) => log_ui("Log file removed."),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        log_ui("Log file already absent.");
                    }
                    Err(e) => {
                        log_ui(format!("Failed to remove log file: {}", e));
                    }
                }
            } else {
                log_ui("No log file to remove.");
            }
        } else {
            log_ui("Log file path is not configured.");
        }
    }

    log_ui(format!(
        "Logging is now {} (flag stored in HKCU\\{}).",
        if target { "ENABLED" } else { "DISABLED" },
        LOG_SETTINGS_SUBKEY
    ));
    Ok(())
}

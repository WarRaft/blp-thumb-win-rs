use std::io;
use std::ffi::OsStr;
use winreg::RegKey;
use winreg::types::ToRegValue;
use blp_thumb_win::log::log_cli;

/// Convenience helper: create (or open) a subkey under `root` and set a value,
/// logging the exact registry path and value written.
///
/// - `root`: a `RegKey` returned from `RegKey::predef(HKEY_...)` (HKLM/HKCU)
/// - `subkey_path`: path under `root` (e.g. "Software\\Classes\\CLSID\\{...}")
/// - `value_name`: name of the value (use "" for default)
/// - `value`: any type implementing `ToRegValue` (String, u32, etc.)
pub fn set_reg_value<N: AsRef<OsStr>, T: ToRegValue>(
    root: &RegKey,
    subkey_path: &str,
    value_name: N,
    value: &T,
) -> io::Result<()> {
    log_cli(format!("Creating/opening registry key: {}", subkey_path));
    let (subkey, _) = root.create_subkey(subkey_path)?;
    // Log the value being set. For the default value name write `(Default)`.
    let name_display = if value_name.as_ref().is_empty() { "(Default)" } else { "value" };
    log_cli(format!(
        "Setting value: {} \\\\ {} = <written>",
        subkey_path, name_display
    ));
    subkey.set_value(value_name, value)?;
    Ok(())
}

#![cfg(windows)]

use std::{env, fs, io, io::Write};

use windows::Win32::UI::Shell::{SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify};
use winreg::{RegKey, enums::*};

// Embedded DLL that you copy into ./bin/ at build time.
// The EXE will re-materialize it under %LOCALAPPDATA%\blp-thumb-win\
static DLL_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/bin/blp_thumb_win.dll"
));

// Single source of truth from the library (your keys module)
use crate::actiions::dialog::{Action, action_choose, action_execute};
use blp_thumb_win::keys::{LOG_SETTINGS_SUBKEY, LOGGING_VALUE_NAME};
use blp_thumb_win::log::{log_cli, log_endabled};

#[path = "actions/mod.rs"]
mod actiions;

#[path = "utils/mod.rs"]
mod utils;

fn main() -> io::Result<()> {
    log_cli("Installer started");
    loop {
        let (action, label) = action_choose()?;
        log_cli(format!("Menu selection: {}", label));

        if action == Action::Exit {
            log_cli("Installer exiting");
            break;
        }

        match action_execute(action) {
            Ok(()) => log_cli(format!("Action '{}' completed successfully", label)),
            Err(err) => {
                log_cli(format!("Action '{}' failed: {}", label, err));
                return Err(err);
            }
        }

        pause("\nPress Enter to return to the menu...");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegistryScope {
    CurrentUser,
    LocalMachine,
}

impl RegistryScope {
    fn name(self) -> &'static str {
        match self {
            RegistryScope::CurrentUser => "HKCU",
            RegistryScope::LocalMachine => "HKLM",
        }
    }

    fn root(self) -> RegKey {
        match self {
            RegistryScope::CurrentUser => RegKey::predef(HKEY_CURRENT_USER),
            RegistryScope::LocalMachine => RegKey::predef(HKEY_LOCAL_MACHINE),
        }
    }

    fn is_user(self) -> bool {
        matches!(self, RegistryScope::CurrentUser)
    }
}

fn clear_shell_ext_cache_scope(scope: RegistryScope, clsid: &str) -> io::Result<usize> {
    let root = scope.root();
    let path = r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached";
    let key = match root.open_subkey_with_flags(path, KEY_READ | KEY_SET_VALUE) {
        Ok(k) => k,
        Err(err) => {
            if err.kind() == io::ErrorKind::NotFound {
                log_cli(format!(
                    "{}: shell extension cache key missing",
                    scope.name()
                ));
                return Ok(0);
            }
            return Err(err);
        }
    };

    let clsid_upper = clsid.to_ascii_uppercase();
    let clsid_nobrace = clsid_upper.trim_matches('{').trim_matches('}').to_string();
    let mut to_delete = Vec::new();
    for value in key.enum_values() {
        if let Ok((name, _)) = value {
            let upper = name.to_ascii_uppercase();
            if upper.contains(&clsid_upper) || upper.contains(&clsid_nobrace) {
                to_delete.push(name);
            }
        }
    }

    let mut removed = 0usize;
    for name in to_delete {
        if key.delete_value(&name).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        log_cli(format!(
            r"{}: cleared {} entries from Shell Extensions\Cached",
            scope.name(),
            removed
        ));
    } else {
        log_cli(format!(
            "{}: no cached Shell Extensions entries to clear",
            scope.name()
        ));
    }
    Ok(removed)
}

fn enforce_thumbnail_settings_scope(scope: RegistryScope) -> io::Result<()> {
    log_cli(format!(
        "{}: enforcing Explorer thumbnail settings",
        scope.name()
    ));
    let root = scope.root();

    let (advanced, _) =
        root.create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")?;
    advanced.set_value("IconsOnly", &0u32)?;
    advanced.set_value("DisableThumbnails", &0u32)?;
    advanced.set_value("DisableThumbnailCache", &0u32)?;
    advanced.set_value("DisableThumbnailsOnNetworkFolders", &0u32)?;

    const POLICY_PATHS: [&str; 2] = [
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        r"Software\Policies\Microsoft\Windows\Explorer",
    ];
    const POLICY_VALUES: [&str; 3] = [
        "DisableThumbnails",
        "DisableThumbnailCache",
        "DisableThumbnailsOnNetworkFolders",
    ];

    for path in POLICY_PATHS {
        if let Ok((key, _)) = root.create_subkey(path) {
            for name in POLICY_VALUES {
                key.set_value(name, &0u32)?;
            }
        }
    }

    Ok(())
}

fn toggle_logging() -> io::Result<()> {
    let currently_enabled = log_endabled();
    let target = !currently_enabled;

    set_logging_enabled(RegistryScope::CurrentUser, target)?;
    if let Err(err) = set_logging_enabled(RegistryScope::LocalMachine, target) {
        log_cli(format!("Logging toggle: HKLM update failed: {}", err));
    }

    if !target {
        if let Some(path) = blp_thumb_win::log_file_path() {
            if path.exists() {
                match fs::remove_file(&path) {
                    Ok(()) => log_cli(format!("Removed log file {}", path.display())),
                    Err(err) => log_cli(format!(
                        "Failed to remove log file {}: {}",
                        path.display(),
                        err
                    )),
                }
            }
        }
    }

    log_cli(format!(
        "Logging {}",
        if target { "enabled" } else { "disabled" }
    ));
    println!("Logging {}.", if target { "enabled" } else { "disabled" });
    Ok(())
}

fn normalize_ext(raw: &str) -> String {
    let s = raw.trim();
    if s.starts_with('.') {
        s.to_string()
    } else {
        format!(".{}", s)
    }
}

fn current_progid_of_ext(ext: &str) -> Option<String> {
    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
    hkcr.open_subkey(ext)
        .ok()
        .and_then(|k| k.get_value::<String, _>("").ok())
        .filter(|s| !s.trim().is_empty())
}

fn pause(msg: &str) {
    print!("{msg}");
    let _ = io::stdout().flush();
    // Use read_line to avoid printing localized messages from external tools
    let mut _buf = String::new();
    let _ = io::stdin().read_line(&mut _buf);
}

fn set_logging_enabled(scope: RegistryScope, enabled: bool) -> io::Result<()> {
    let root = scope.root();
    let (key, _) = root.create_subkey(LOG_SETTINGS_SUBKEY)?;
    let value: u32 = if enabled { 1 } else { 0 };

    if let Err(err) = key.set_value(LOGGING_VALUE_NAME, &value) {
        if let Some(5) = err.raw_os_error() {
            println!(
                "Error: Access denied. Please run the program with administrative privileges."
            );
            log_cli("Error: Access denied while modifying HKLM.");
        }
        return Err(err);
    }

    Ok(())
}

fn open_with_list_entries(hkcu: &RegKey, ext: &str) -> Vec<String> {
    let path = format!(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{}\OpenWithList",
        ext
    );
    let mut entries = Vec::new();
    if let Ok(key) = hkcu.open_subkey(path) {
        for item in key.enum_values() {
            if let Ok((name, value)) = item {
                if name.len() == 1 {
                    let entry = value.to_string();
                    let entry = entry.trim_matches(char::from(0)).trim().to_string();
                    if !entry.is_empty() {
                        entries.push(entry);
                    }
                }
            }
        }
    }
    entries
}

fn open_with_progids_entries(hkcu: &RegKey, ext: &str) -> Vec<String> {
    let path = format!(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{}\OpenWithProgids",
        ext
    );
    let mut entries = Vec::new();
    if let Ok(key) = hkcu.open_subkey(path) {
        for item in key.enum_values() {
            if let Ok((name, _)) = item {
                let entry = name.trim_matches(char::from(0)).trim().to_string();
                if !entry.is_empty() {
                    entries.push(entry);
                }
            }
        }
    }
    entries
}

fn user_choice_prog_id(hkcu: &RegKey, ext: &str) -> Option<String> {
    let path = format!(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{}\UserChoice",
        ext
    );
    hkcu.open_subkey(path)
        .ok()
        .and_then(|key| key.get_value::<String, _>("ProgId").ok())
        .map(|s| s.trim_matches(char::from(0)).to_string())
        .filter(|s| !s.is_empty())
}

fn bind_application(hkcu: &RegKey, entry: &str, catid: &str, clsid: &str) -> io::Result<()> {
    let entry = entry.trim();
    if entry.is_empty() {
        return Ok(());
    }

    // If entry is already a ProgID, reuse helper
    if !entry.ends_with(".exe") {
        return bind_prog_id_application(hkcu, entry, catid, clsid);
    }

    let key_path = format!(r"Software\Classes\Applications\{}\ShellEx", entry);
    log_cli(format!(
        "Register COM: binding under application {} (ShellEx)",
        entry
    ));
    let (app_shellex, _) = hkcu.create_subkey(key_path)?;
    let (app_thumb, _) = app_shellex.create_subkey(catid)?;
    app_thumb.set_value("", &clsid)?;
    Ok(())
}

fn bind_prog_id_application(
    hkcu: &RegKey,
    progid: &str,
    catid: &str,
    clsid: &str,
) -> io::Result<()> {
    let progid = progid.trim();
    if progid.is_empty() {
        return Ok(());
    }

    if let Some(app) = progid.strip_prefix(r"Applications\") {
        return bind_application(hkcu, app, catid, clsid);
    }

    log_cli(format!(
        "Register COM: binding under ProgID application {}",
        progid
    ));
    let (app_shellex, _) = hkcu.create_subkey(format!(r"Software\Classes\{}\ShellEx", progid))?;
    let (app_thumb, _) = app_shellex.create_subkey(catid)?;
    app_thumb.set_value("", &clsid)?;
    Ok(())
}

fn remove_application_binding(hkcu: &RegKey, entry: &str, catid: &str) {
    let entry = entry.trim();
    if entry.is_empty() {
        return;
    }

    if !entry.ends_with(".exe") {
        remove_prog_id_application(hkcu, entry, catid);
        return;
    }

    let path = format!(r"Software\Classes\Applications\{}\ShellEx\{}", entry, catid);
    log_cli(format!(
        "Unregister COM: removing application binding {}",
        entry
    ));
    let _ = hkcu.delete_subkey_all(path);
}

fn remove_prog_id_application(hkcu: &RegKey, progid: &str, catid: &str) {
    let progid = progid.trim();
    if progid.is_empty() {
        return;
    }

    if let Some(app) = progid.strip_prefix(r"Applications\") {
        remove_application_binding(hkcu, app, catid);
        return;
    }

    let path = format!(r"Software\Classes\{}\ShellEx\{}", progid, catid);
    log_cli(format!(
        "Unregister COM: removing ProgID application binding {}",
        progid
    ));
    let _ = hkcu.delete_subkey_all(path);
}

fn notify_shell_assoc(reason: &str) {
    log_cli(format!(
        "Shell notify ({reason}): calling SHChangeNotify(SHCNE_ASSOCCHANGED)"
    ));
    unsafe {
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None);
    }
    log_cli("Shell notify: done");
}

use crate::{
    RegistryScope, clear_shell_ext_cache_scope, enforce_thumbnail_settings_scope,
    materialize_embedded_dll_machine, normalize_ext, notify_shell_assoc, probe_status,
    register_com_scope,
};
use blp_thumb_win::keys::{clsid_str, preview_clsid_str, shell_preview_handler_catid_str};
use blp_thumb_win::log::log_cli;
use std::io;
use std::path::Path;

const DEFAULT_EXT: &str = "blp";
const DEFAULT_PROGID: &str = "BlpThumbnailHandler";
const PREVIEW_FRIENDLY_NAME: &str = "BLP Thumbnail Preview Handler";

/// Ensure the preview handler CLSID is properly registered under HKCU and HKLM.
/// This includes binding it to the .blp extension and ProgID.
fn register_preview_handler(scope: RegistryScope, dll_path: &Path) -> io::Result<()> {
    let scope_name = scope.name();
    log_cli(format!(
        "Register Preview Handler [{}]: start (dll={})",
        scope_name,
        dll_path.display()
    ));

    let root = scope.root();
    let preview_clsid = preview_clsid_str();
    let preview_catid = shell_preview_handler_catid_str();
    let ext = normalize_ext(DEFAULT_EXT);

    // Register CLSID for the preview handler
    let (key_clsid, _) =
        root.create_subkey(format!(r"Software\Classes\CLSID\{}", preview_clsid))?;
    key_clsid.set_value("", &PREVIEW_FRIENDLY_NAME)?;
    key_clsid.set_value("DisableProcessIsolation", &1u32)?;

    let (key_inproc, _) = root.create_subkey(format!(
        r"Software\Classes\CLSID\{}\InprocServer32",
        preview_clsid
    ))?;
    key_inproc.set_value("", &dll_path.as_os_str())?;
    key_inproc.set_value("ThreadingModel", &"Apartment")?;

    // Bind CLSID to the .blp extension
    let (key_ext_shellex, _) = root.create_subkey(format!(r"Software\Classes\{}\ShellEx", ext))?;
    let (key_ext_entry, _) = key_ext_shellex.create_subkey(&preview_catid)?;
    key_ext_entry.set_value("", &preview_clsid)?;

    // Bind CLSID to the ProgID
    let (progid_key, _) = root.create_subkey(format!(r"Software\Classes\{}", DEFAULT_PROGID))?;
    let (pid_shellex, _) = progid_key.create_subkey("ShellEx")?;
    let (pid_entry, _) = pid_shellex.create_subkey(&preview_catid)?;
    pid_entry.set_value("", &preview_clsid)?;

    log_cli(format!(
        "Register Preview Handler [{}]: completed",
        scope_name
    ));
    Ok(())
}

pub fn install() -> io::Result<()> {
    log_cli("Install (all users): start");
    let dll_path = materialize_embedded_dll_machine()?;
    log_cli(format!(
        "Install (all users): DLL materialized to {}",
        dll_path.display()
    ));
    let mut warnings = Vec::new();
    if let Err(err) = register_com_scope(RegistryScope::LocalMachine, &dll_path) {
        warnings.push(format!("HKLM registration failed: {}", err));
    }
    if let Err(err) = register_com_scope(RegistryScope::CurrentUser, &dll_path) {
        warnings.push(format!("HKCU registration failed: {}", err));
    }

    // Register the preview handler explicitly
    if let Err(err) = register_preview_handler(RegistryScope::LocalMachine, &dll_path) {
        warnings.push(format!("HKLM preview handler registration failed: {}", err));
    }
    if let Err(err) = register_preview_handler(RegistryScope::CurrentUser, &dll_path) {
        warnings.push(format!("HKCU preview handler registration failed: {}", err));
    }

    if warnings.is_empty() {
        log_cli("Install (all users): registry entries written");
    } else {
        for warn in &warnings {
            log_cli(format!("Install warning: {}", warn));
        }
    }

    let thumb_clsid = clsid_str();
    let preview_clsid = preview_clsid_str();
    for scope in [RegistryScope::LocalMachine, RegistryScope::CurrentUser] {
        for clsid in [&thumb_clsid, &preview_clsid] {
            if let Err(err) = clear_shell_ext_cache_scope(scope, clsid) {
                warnings.push(format!("{} cache clear failed: {}", scope.name(), err));
            }
        }
        if let Err(err) = enforce_thumbnail_settings_scope(scope) {
            warnings.push(format!(
                "{} thumbnail settings failed: {}",
                scope.name(),
                err
            ));
        }
    }

    notify_shell_assoc("install-all");

    match probe_status() {
        Ok(report) => {
            if !report.is_ready() {
                for alert in &report.alerts {
                    log_cli(format!("Install verify alert: {}", alert));
                }
                warnings.push("Verification reported issues; see Status".to_string());
            }
        }
        Err(err) => {
            warnings.push(format!("Verification failed: {}", err));
            log_cli(format!("Install: probe_status failed: {}", err));
        }
    }

    if warnings.is_empty() {
        println!("Installed in HKLM and HKCU. Use 'Restart Explorer' to refresh thumbnails.");
    } else {
        println!("Install completed with warnings:");
        for warn in warnings {
            println!("  - {}", warn);
        }
    }
    Ok(())
}

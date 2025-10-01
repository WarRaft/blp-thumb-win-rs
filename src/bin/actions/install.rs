use crate::{
    RegistryScope, clear_shell_ext_cache_scope, enforce_thumbnail_settings_scope,
    materialize_embedded_dll_machine, notify_shell_assoc, probe_status, register_com_scope,
};
use blp_thumb_win::keys::{clsid_str, preview_clsid_str};
use blp_thumb_win::log::log_cli;
use std::io;

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

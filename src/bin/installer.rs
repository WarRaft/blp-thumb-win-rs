#![cfg(windows)]

use std::{
    env, fs, io,
    io::Write,
    path::{Path, PathBuf},
};

use dialoguer::console::style;
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Select, console::Term};
use windows::Win32::UI::Shell::{SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify};
use winreg::{RegKey, RegValue, enums::*};

// Embedded DLL that you copy into ./bin/ at build time.
// The EXE will re-materialize it under %LOCALAPPDATA%\blp-thumb-win\
static DLL_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/bin/blp_thumb_win.dll"
));

// Single source of truth from the library (your keys module)
use crate::restart_explorer::restart_explorer;
use blp_thumb_win::keys::{
    CLSID_BLP_THUMB, DEFAULT_EXT, DEFAULT_PROGID, FRIENDLY_NAME, clsid_str,
    shell_thumb_handler_catid_str,
};
use windows::Win32::Foundation::{S_FALSE, S_OK};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoUninitialize,
};
use windows::core::IUnknown;

#[path = "installer/restart_explorer.rs"]
mod restart_explorer;

pub(crate) fn log_cli(message: impl Into<String>) {
    let text = message.into();
    if let Err(err) = blp_thumb_win::log_desktop(&text) {
        eprintln!("[log] cannot write '{}': {}", text, err);
    }
}

fn main() -> io::Result<()> {
    log_cli("Installer started");
    loop {
        let action = choose_action()?;
        log_cli(format!("Menu selection: {}", action.title()));

        if action == Action::Exit {
            log_cli("Installer exiting");
            break;
        }

        match execute_action(action) {
            Ok(()) => log_cli(format!(
                "Action '{}' completed successfully",
                action.title()
            )),
            Err(err) => {
                log_cli(format!("Action '{}' failed: {}", action.title(), err));
                return Err(err);
            }
        }

        pause("\nPress Enter to return to the menu...");
    }
    Ok(())
}

/* ---------- Menu ---------- */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Install,
    Uninstall,
    Status,
    FixExplorer,
    InstallAllUsers,
    UninstallAllUsers,
    RestartExplorer,
    ClearThumbCache,
    ClearAssociations,
    Exit,
}

fn menu_theme() -> ColorfulTheme {
    // Force ASCII arrow; allow override via env MENU_ARROW if you ever need it.
    let mut t = ColorfulTheme::default();
    t.active_item_prefix = style(">".to_string());
    t.inactive_item_prefix = style(" ".to_string());
    t.picked_item_prefix = style(">".to_string());
    t.unpicked_item_prefix = style(" ".to_string());

    t.prompt_prefix = style("$".to_string());

    t.success_prefix = style(">".to_string());
    t.error_prefix = style("!".to_string());
    t
}

fn choose_action() -> io::Result<Action> {
    let items = [
        "Install (current user)",
        "Uninstall (current user)",
        "Status",
        "Fix Explorer settings",
        "Install (all users)",
        "Uninstall (all users)",
        "Restart Explorer",
        "Clear thumbnail cache",
        "Clear associations",
        "Exit",
    ];

    let idx = Select::with_theme(&menu_theme())
        .with_prompt("BLP Thumbnail Provider installer")
        .items(&items)
        .default(0)
        .interact_on(&Term::stdout())?;

    Ok(match idx {
        0 => Action::Install,
        1 => Action::Uninstall,
        2 => Action::Status,
        3 => Action::FixExplorer,
        4 => Action::InstallAllUsers,
        5 => Action::UninstallAllUsers,
        6 => Action::RestartExplorer,
        7 => Action::ClearThumbCache,
        8 => Action::ClearAssociations,
        _ => Action::Exit,
    })
}

impl Action {
    fn title(self) -> &'static str {
        match self {
            Action::Install => "Install (current user)",
            Action::Uninstall => "Uninstall (current user)",
            Action::Status => "Status",
            Action::FixExplorer => "Fix Explorer settings",
            Action::InstallAllUsers => "Install (all users)",
            Action::UninstallAllUsers => "Uninstall (all users)",
            Action::RestartExplorer => "Restart Explorer",
            Action::ClearThumbCache => "Clear thumbnail cache",
            Action::ClearAssociations => "Clear associations",
            Action::Exit => "Exit",
        }
    }
}

fn execute_action(action: Action) -> io::Result<()> {
    match action {
        Action::Install => install(),
        Action::Uninstall => uninstall(),
        Action::Status => status(),
        Action::FixExplorer => fix_explorer(),
        Action::InstallAllUsers => install_all_users(),
        Action::UninstallAllUsers => uninstall_all_users(),
        Action::RestartExplorer => restart_explorer(),
        Action::ClearThumbCache => clear_thumb_cache(),
        Action::ClearAssociations => clear_associations(),
        Action::Exit => Ok(()),
    }
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

/* ---------- Actions ---------- */

fn install() -> io::Result<()> {
    log_cli("Install: start");
    let dll_path = materialize_embedded_dll()?;
    log_cli(format!(
        "Install: DLL materialized to {}",
        dll_path.display()
    ));
    register_com_scope(RegistryScope::CurrentUser, &dll_path)?;
    log_cli("Install: registry entries written");
    let clsid = clsid_str();
    clear_shell_ext_cache_scope(RegistryScope::CurrentUser, &clsid)?;
    enforce_thumbnail_settings_scope(RegistryScope::CurrentUser)?;
    notify_shell_assoc("install");
    let report = probe_status()?;
    if !report.is_ready() {
        for alert in &report.alerts {
            log_cli(format!("Install verify alert: {}", alert));
        }
        println!("Post-install verification failed. Run 'Status' for detailed report.");
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "post-install verification failed",
        ));
    }
    println!("Installed in HKCU. Use 'Restart Explorer' to refresh thumbnails.");
    Ok(())
}

fn uninstall() -> io::Result<()> {
    log_cli("Uninstall: start");
    unregister_com_scope(RegistryScope::CurrentUser)?;
    log_cli("Uninstall: registry entries removed");
    notify_shell_assoc("uninstall");
    println!("Uninstalled from HKCU.");
    Ok(())
}

fn install_all_users() -> io::Result<()> {
    log_cli("InstallAllUsers: start");
    let dll_path = materialize_embedded_dll_machine()?;
    log_cli(format!(
        "InstallAllUsers: DLL materialized to {}",
        dll_path.display()
    ));
    register_com_scope(RegistryScope::LocalMachine, &dll_path)?;
    register_com_scope(RegistryScope::CurrentUser, &dll_path)?;
    log_cli("InstallAllUsers: registry entries written");
    let clsid = clsid_str();
    clear_shell_ext_cache_scope(RegistryScope::LocalMachine, &clsid)?;
    clear_shell_ext_cache_scope(RegistryScope::CurrentUser, &clsid)?;
    enforce_thumbnail_settings_scope(RegistryScope::LocalMachine)?;
    enforce_thumbnail_settings_scope(RegistryScope::CurrentUser)?;
    notify_shell_assoc("install-all");
    let report = probe_status()?;
    if !report.is_ready() {
        for alert in &report.alerts {
            log_cli(format!("InstallAllUsers verify alert: {}", alert));
        }
        println!("Post-install verification failed. Run 'Status' for detailed report.");
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "post-install verification failed",
        ));
    }
    println!("Installed in HKLM and HKCU. Use 'Restart Explorer' to refresh thumbnails.");
    Ok(())
}

fn uninstall_all_users() -> io::Result<()> {
    log_cli("UninstallAllUsers: start");
    unregister_com_scope(RegistryScope::LocalMachine)?;
    unregister_com_scope(RegistryScope::CurrentUser)?;
    notify_shell_assoc("uninstall-all");
    println!("Uninstalled from HKLM and HKCU.");
    Ok(())
}

fn status() -> io::Result<()> {
    log_cli("Status: probing");
    let report = probe_status()?;

    println!("Status (details below):");
    println!("  CLSID key:                   {}", mark(report.ok_clsid));
    println!("  InprocServer32 value:        {}", mark(report.ok_inproc));
    println!(
        "  DisableProcessIsolation:      {}",
        mark(report.disable_process_isolation)
    );
    println!(
        "  InprocServer32 path:         {}",
        report.inproc_server_path.as_deref().unwrap_or("<missing>")
    );
    println!(
        "  InprocServer32 file:         {}",
        mark(report.inproc_path_exists)
    );
    println!(
        "  ShellEx bind (ProgID):       {}",
        mark(report.ok_bind_prog)
    );
    println!(
        "  ShellEx bind (Ext):          {}",
        mark(report.ok_bind_ext)
    );
    println!(
        "  ShellEx bind (SysAssoc):     {}",
        mark(report.ok_bind_sys)
    );
    println!(
        "  Extension default ProgID:    {}",
        report.ext_default_value.as_deref().unwrap_or("<missing>")
    );
    println!(
        "  Extension default matches:   {}",
        mark(report.ext_default_matches)
    );
    println!(
        "  HKLM CLSID key:              {}",
        mark(report.machine_ok_clsid)
    );
    println!(
        "  HKLM InprocServer32 value:   {}",
        mark(report.machine_ok_inproc)
    );
    println!(
        "  HKLM DisableProcessIsolation:{}",
        mark(report.machine_disable_process_isolation)
    );
    println!(
        "  HKLM InprocServer32 path:    {}",
        report
            .machine_inproc_server_path
            .as_deref()
            .unwrap_or("<missing>")
    );
    println!(
        "  HKLM InprocServer32 file:    {}",
        mark(report.machine_inproc_path_exists)
    );
    println!(
        "  HKLM extension default:      {}",
        report
            .machine_ext_default_value
            .as_deref()
            .unwrap_or("<missing>")
    );
    println!(
        "  HKLM extension matches:      {}",
        mark(report.machine_ext_default_matches)
    );
    println!(
        "  HKLM ShellEx bind (ProgID):  {}",
        mark(report.machine_ok_bind_prog)
    );
    println!(
        "  HKLM ShellEx bind (Ext):     {}",
        mark(report.machine_ok_bind_ext)
    );
    println!(
        "  HKLM ShellEx bind (SysAssoc):{}",
        mark(report.machine_ok_bind_sys)
    );
    println!(
        "  HKLM Explorer ThumbnailHandlers: {}",
        mark(report.machine_ok_thumb_handler)
    );
    println!(
        "  HKCR effective binding:      {}",
        report.hkcr_binding.as_deref().unwrap_or("<missing>")
    );
    println!(
        "  HKCR binding matches:        {}",
        mark(report.hkcr_binding_matches)
    );
    println!(
        "  HKLM binding (ProgID/Ext):   {}/{}",
        presence(report.hklm_bind_prog),
        presence(report.hklm_bind_ext)
    );
    println!(
        "  Explorer IconsOnly:          {} (value={})",
        mark(report.icons_only_ok),
        format_u32_opt(report.icons_only_value)
    );
    println!(
        "  Explorer DisableThumbnails:  {} (value={})",
        mark(report.disable_thumbnails_ok),
        format_u32_opt(report.disable_thumbnails_value)
    );
    println!(
        "  Explorer DisableThumbCache:  {} (value={})",
        mark(report.disable_thumbnail_cache_ok),
        format_u32_opt(report.disable_thumbnail_cache_value)
    );
    println!(
        "  Explorer DisableNetworkThumbs:{} (value={})",
        mark(report.disable_network_ok),
        format_u32_opt(report.disable_network_value)
    );
    println!("  Explorer policies allow:     {}", mark(report.policy_ok));
    println!(
        "  Applications OpenWithList:   {}/{}",
        report.ok_apps_list_matched, report.apps_list_total
    );
    println!(
        "  Applications OpenWithProgids:{}/{}",
        report.ok_apps_progids_matched, report.apps_progids_total
    );
    println!("  UserChoice target:           {}", report.ok_user_choice);
    println!(
        "  Explorer ThumbnailHandlers:  {}",
        mark(report.ok_thumb_handler)
    );
    println!(
        "  CoCreateInstance test:       {} (installer self-check)",
        report.com_create_status
    );
    println!("  Overall ready:               {}", mark(report.is_ready()));
    if !report.alerts.is_empty() {
        for alert in &report.alerts {
            println!("  ALERT: {}", alert);
        }
    }

    if report.apps_list_total > 0 {
        println!("\n  OpenWithList entries:");
        for (entry, bound) in &report.apps_list_details {
            println!("    {:<30} {}", entry, mark(*bound));
        }
    }

    if report.apps_progids_total > 0 {
        println!("\n  OpenWithProgids entries:");
        for (entry, bound) in &report.apps_progids_details {
            println!("    {:<30} {}", entry, mark(*bound));
        }
    }

    if !report.cached_entries.is_empty() {
        println!("\n  Shell Extensions Cached:");
        for (name, state) in &report.cached_entries {
            match state {
                Some(val) => println!("    {:<60} state=0x{:08X}", name, val),
                None => println!("    {:<60} state=<unknown>", name),
            }
        }
    }

    if !report.policy_values.is_empty() {
        println!("\n  Explorer policy overrides:");
        for (path, value) in &report.policy_values {
            println!("    {:<80} value={}", path, value);
        }
    }

    if let Some((prog_id, bound)) = report.user_choice_detail.as_ref() {
        println!("\n  UserChoice:");
        println!("    {:<30} {}", prog_id, mark(*bound));
    }

    let ready = report.is_ready();
    log_cli(format!(
        "Status summary -> CLSID: {}, Inproc: {}, DPI: {}, InprocFile: {}, HKCR: {}, HKLM(prog/ext): {}/{}, Explorer handlers: {}, AppsList OK: {}/{}, Thumb settings: {}, CoCreate: {}, Ready: {}",
        mark(report.ok_clsid),
        mark(report.ok_inproc),
        mark(report.disable_process_isolation),
        mark(report.inproc_path_exists),
        mark(report.hkcr_binding_matches),
        presence(report.hklm_bind_prog),
        presence(report.hklm_bind_ext),
        mark(report.ok_thumb_handler),
        report.ok_apps_list_matched,
        report.apps_list_total,
        mark(report.thumbnail_settings_ok),
        report.com_create_status,
        mark(ready)
    ));
    Ok(())
}

fn fix_explorer() -> io::Result<()> {
    log_cli("FixExplorer: start");
    let clsid = clsid_str();
    enforce_thumbnail_settings_scope(RegistryScope::CurrentUser)?;
    if let Err(err) = enforce_thumbnail_settings_scope(RegistryScope::LocalMachine) {
        log_cli(format!(
            "FixExplorer: HKLM thumbnail settings not updated ({})",
            err
        ));
    }
    clear_shell_ext_cache_scope(RegistryScope::CurrentUser, &clsid)?;
    if let Err(err) = clear_shell_ext_cache_scope(RegistryScope::LocalMachine, &clsid) {
        log_cli(format!("FixExplorer: HKLM cache not cleared ({})", err));
    }
    notify_shell_assoc("fix-explorer");
    println!("Explorer settings reset. Use 'Restart Explorer' to apply.");
    Ok(())
}

fn clear_thumb_cache() -> io::Result<()> {
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
            "{}: cleared {} entries from Shell Extensions\\Cached",
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

fn clear_associations() -> io::Result<()> {
    log_cli("Clear associations: start");
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let clsid = clsid_str();
    let catid = shell_thumb_handler_catid_str();
    let ext = normalize_ext(DEFAULT_EXT);

    for entry in open_with_list_entries(&hkcu, &ext) {
        remove_application_binding(&hkcu, &entry, &catid);
    }
    for progid in open_with_progids_entries(&hkcu, &ext) {
        remove_prog_id_application(&hkcu, &progid, &catid);
    }
    if let Some(prog_id) = user_choice_prog_id(&hkcu, &ext) {
        if let Some(app) = prog_id.strip_prefix("Applications\\") {
            remove_application_binding(&hkcu, app, &catid);
        } else {
            remove_prog_id_application(&hkcu, &prog_id, &catid);
        }
        let _ = hkcu.delete_subkey_all(format!(
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{}\UserChoice",
            ext
        ));
    }

    let _ = hkcu.delete_subkey_all(format!(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{}",
        ext
    ));
    let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\{}", ext));
    let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\SystemFileAssociations\{}", ext));
    if let Ok(thumb_handlers) = hkcu.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers",
        KEY_SET_VALUE,
    ) {
        let _ = thumb_handlers.delete_value(&ext);
    }
    let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\WarRaft.BLP"));
    let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\CLSID\{}", clsid));
    let _ = hkcu
        .open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
            KEY_SET_VALUE,
        )
        .and_then(|k| k.delete_value(clsid));

    log_cli("Clear associations: completed");
    notify_shell_assoc("clear-assoc");
    Ok(())
}

/* ---------- Registry / files ---------- */

fn materialize_embedded_dll() -> io::Result<PathBuf> {
    // %LOCALAPPDATA%\blp-thumb-win\blp_thumb_win.dll (fallback: next to exe)
    let base = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut p = env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
            p.pop();
            p
        });
    materialize_embedded_dll_at(base)
}

fn materialize_embedded_dll_machine() -> io::Result<PathBuf> {
    let base = env::var_os("PROGRAMFILES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\\Program Files"));
    materialize_embedded_dll_at(base)
}

fn materialize_embedded_dll_at(base: PathBuf) -> io::Result<PathBuf> {
    log_cli(format!(
        "Materialize DLL: base directory {}",
        base.display()
    ));
    let dir = base.join("blp-thumb-win");
    log_cli(format!(
        "Materialize DLL: ensuring directory {}",
        dir.display()
    ));
    fs::create_dir_all(&dir)?;
    let path = dir.join("blp_thumb_win.dll");
    log_cli(format!(
        "Materialize DLL: writing {} ({} bytes)",
        path.display(),
        DLL_BYTES.len()
    ));
    fs::write(&path, DLL_BYTES)?;
    log_cli("Materialize DLL: completed");
    Ok(path)
}

fn normalize_ext(raw: &str) -> String {
    let s = raw.trim();
    if s.starts_with('.') {
        s.to_string()
    } else {
        format!(".{}", s)
    }
}

/// Register CLSID + Inproc + ShellEx mapping under HKCU.
/// We do not change icons or file type ownership.
/// We bind under ProgID (if present) and under the extension itself.
fn register_com_scope(scope: RegistryScope, dll_path: &Path) -> io::Result<()> {
    let scope_name = scope.name();
    log_cli(format!(
        "Register COM [{}]: start (dll={})",
        scope_name,
        dll_path.display()
    ));

    let root = scope.root();
    let clsid = clsid_str();
    let catid = shell_thumb_handler_catid_str();
    let ext = normalize_ext(DEFAULT_EXT);

    log_cli(format!("Register COM [{}]: creating CLSID key", scope_name));
    let (key_clsid, _) = root.create_subkey(format!(r"Software\Classes\CLSID\{}", clsid))?;
    key_clsid.set_value("", &FRIENDLY_NAME)?;
    log_cli(format!(
        "Register COM [{}]: setting DisableProcessIsolation=1",
        scope_name
    ));
    key_clsid.set_value("DisableProcessIsolation", &1u32)?;

    log_cli(format!(
        "Register COM [{}]: writing InprocServer32",
        scope_name
    ));
    let (key_inproc, _) =
        root.create_subkey(format!(r"Software\Classes\CLSID\{}\InprocServer32", clsid))?;
    key_inproc.set_value("", &dll_path.as_os_str())?;
    key_inproc.set_value("ThreadingModel", &"Apartment")?;

    log_cli(format!(
        "Register COM [{}]: marking extension as approved",
        scope_name
    ));
    let (approved, _) =
        root.create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved")?;
    approved.set_value(&clsid, &FRIENDLY_NAME)?;

    log_cli(format!(
        "Register COM [{}]: setting Implemented Categories",
        scope_name
    ));
    let _ = root.create_subkey(format!(
        r"Software\Classes\CLSID\{}\Implemented Categories\{}",
        clsid, catid
    ))?;

    log_cli(format!(
        "Register COM [{}]: ensuring extension metadata",
        scope_name
    ));
    let (ext_key, _) = root.create_subkey(format!(r"Software\Classes\{}", ext))?;
    match ext_key.get_value::<String, _>("Content Type") {
        Ok(existing)
            if !existing.trim_matches(char::from(0)).is_empty() && existing != "image/x-blp" =>
        {
            log_cli(format!(
                "Register COM [{}]: skipping Content Type override (current={})",
                scope_name, existing
            ));
        }
        _ => {
            ext_key.set_value("Content Type", &"image/x-blp")?;
        }
    }
    ext_key.set_value("PerceivedType", &"image")?;

    match ext_key.get_value::<String, _>("") {
        Ok(existing) if !existing.trim_matches(char::from(0)).is_empty() => {
            log_cli(format!(
                "Register COM [{}]: extension default already set to {}",
                scope_name, existing
            ));
        }
        _ => {
            log_cli(format!(
                "Register COM [{}]: setting extension default to WarRaft.BLP",
                scope_name
            ));
            ext_key.set_value("", &DEFAULT_PROGID)?;
        }
    }

    log_cli(format!(
        "Register COM [{}]: ensuring ProgID key {}",
        scope_name, DEFAULT_PROGID
    ));
    let (progid_key, _) = root.create_subkey(format!(r"Software\Classes\{}", DEFAULT_PROGID))?;
    if progid_key
        .get_value::<String, _>("")
        .map(|s| s.trim_matches(char::from(0)).is_empty())
        .unwrap_or(true)
    {
        progid_key.set_value("", &FRIENDLY_NAME)?;
    }
    let (pid_shellex, _) = progid_key.create_subkey("ShellEx")?;
    let (pid_thumb, _) = pid_shellex.create_subkey(&catid)?;
    pid_thumb.set_value("", &clsid)?;

    log_cli(format!(
        "Register COM [{}]: binding under extension {}",
        scope_name, ext
    ));
    let (key_ext_shellex, _) = root.create_subkey(format!(r"Software\Classes\{}\ShellEx", ext))?;
    let (key_ext_thumb, _) = key_ext_shellex.create_subkey(&catid)?;
    key_ext_thumb.set_value("", &clsid)?;

    log_cli(format!(
        "Register COM [{}]: binding under SystemFileAssociations {}",
        scope_name, ext
    ));
    let (key_sys_shellex, _) = root.create_subkey(format!(
        r"Software\Classes\SystemFileAssociations\{}\ShellEx",
        ext
    ))?;
    let (key_sys_thumb, _) = key_sys_shellex.create_subkey(&catid)?;
    key_sys_thumb.set_value("", &clsid)?;

    log_cli(format!(
        "Register COM [{}]: binding under Explorer\\ThumbnailHandlers",
        scope_name
    ));
    let (thumb_handlers, _) = root
        .create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers")?;
    thumb_handlers.set_value(&ext, &clsid)?;

    if scope.is_user() {
        for entry in open_with_list_entries(&root, &ext) {
            bind_application(&root, &entry, &catid, &clsid)?;
        }

        for progid in open_with_progids_entries(&root, &ext) {
            bind_prog_id_application(&root, &progid, &catid, &clsid)?;
        }

        if let Some(prog_id) = user_choice_prog_id(&root, &ext) {
            if let Some(app) = prog_id.strip_prefix("Applications\\") {
                bind_application(&root, app, &catid, &clsid)?;
            } else {
                bind_prog_id_application(&root, &prog_id, &catid, &clsid)?;
            }
        }
    }

    log_cli(format!("Register COM [{}]: completed", scope_name));

    Ok(())
}

fn unregister_com_scope(scope: RegistryScope) -> io::Result<()> {
    let scope_name = scope.name();
    log_cli(format!("Unregister COM [{}]: start", scope_name));
    let root = scope.root();
    let clsid = clsid_str();
    let catid = shell_thumb_handler_catid_str();
    let ext = normalize_ext(DEFAULT_EXT);

    if scope.is_user() {
        if let Some(pid) = current_progid_of_ext(&ext) {
            log_cli(format!(
                "Unregister COM [{}]: removing ProgID binding {}",
                scope_name, pid
            ));
            let _ = root.delete_subkey_all(format!(r"Software\Classes\{}\ShellEx\{}", pid, catid));
        }
    } else {
        let _ = root.delete_subkey_all(format!(
            r"Software\Classes\{}\ShellEx\{}",
            DEFAULT_PROGID, catid
        ));
    }

    log_cli(format!(
        "Unregister COM [{}]: removing extension binding {}",
        scope_name, ext
    ));
    let _ = root.delete_subkey_all(format!(r"Software\Classes\{}\ShellEx\{}", ext, catid));
    log_cli(format!(
        "Unregister COM [{}]: removing SystemFileAssociations binding {}",
        scope_name, ext
    ));
    let _ = root.delete_subkey_all(format!(
        r"Software\Classes\SystemFileAssociations\{}\ShellEx\{}",
        ext, catid
    ));

    if let Ok(thumb_handlers) = root.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers",
        KEY_SET_VALUE,
    ) {
        let _ = thumb_handlers.delete_value(&ext);
    }

    if let Ok(ext_key) =
        root.open_subkey_with_flags(format!(r"Software\Classes\{}", ext), KEY_SET_VALUE)
    {
        let _ = ext_key.delete_value("Content Type");
        let _ = ext_key.delete_value("PerceivedType");
    }

    if scope.is_user() {
        for entry in open_with_list_entries(&root, &ext) {
            remove_application_binding(&root, &entry, &catid);
        }

        for progid in open_with_progids_entries(&root, &ext) {
            remove_prog_id_application(&root, &progid, &catid);
        }

        if let Some(prog_id) = user_choice_prog_id(&root, &ext) {
            if let Some(app) = prog_id.strip_prefix("Applications\\") {
                remove_application_binding(&root, app, &catid);
            } else {
                remove_prog_id_application(&root, &prog_id, &catid);
            }
        }
    }

    log_cli(format!(
        "Unregister COM [{}]: removing CLSID keys",
        scope_name
    ));
    let _ = root.delete_subkey_all(format!(r"Software\Classes\CLSID\{}", clsid));
    let _ = root.delete_subkey_all(format!(r"Software\Classes\{}", DEFAULT_PROGID));
    let _ = root
        .open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
            KEY_SET_VALUE,
        )
        .and_then(|k| k.delete_value(clsid));
    log_cli(format!("Unregister COM [{}]: completed", scope_name));
    Ok(())
}

struct StatusReport {
    ok_clsid: bool,
    ok_inproc: bool,
    ok_bind_prog: bool,
    ok_bind_ext: bool,
    ok_bind_sys: bool,
    ok_thumb_handler: bool,
    disable_process_isolation: bool,
    inproc_server_path: Option<String>,
    inproc_path_exists: bool,
    ext_default_value: Option<String>,
    ext_default_matches: bool,
    machine_ok_clsid: bool,
    machine_ok_inproc: bool,
    machine_disable_process_isolation: bool,
    machine_inproc_server_path: Option<String>,
    machine_inproc_path_exists: bool,
    machine_ext_default_value: Option<String>,
    machine_ext_default_matches: bool,
    machine_ok_bind_prog: bool,
    machine_ok_bind_ext: bool,
    machine_ok_bind_sys: bool,
    machine_ok_thumb_handler: bool,
    hkcr_binding: Option<String>,
    hkcr_binding_matches: bool,
    hklm_bind_prog: bool,
    hklm_bind_ext: bool,
    cached_entries: Vec<(String, Option<u32>)>,
    icons_only_value: Option<u32>,
    icons_only_ok: bool,
    disable_thumbnails_value: Option<u32>,
    disable_thumbnails_ok: bool,
    disable_thumbnail_cache_value: Option<u32>,
    disable_thumbnail_cache_ok: bool,
    disable_network_value: Option<u32>,
    disable_network_ok: bool,
    policy_values: Vec<(String, u32)>,
    policy_ok: bool,
    thumbnail_settings_ok: bool,
    ok_apps_list_matched: usize,
    apps_list_total: usize,
    ok_apps_progids_matched: usize,
    apps_progids_total: usize,
    ok_user_choice: &'static str,
    apps_list_details: Vec<(String, bool)>,
    apps_progids_details: Vec<(String, bool)>,
    user_choice_detail: Option<(String, bool)>,
    com_create_status: &'static str,
    alerts: Vec<String>,
}

impl StatusReport {
    fn is_ready(&self) -> bool {
        self.alerts.is_empty() && self.com_create_status == "OK" && self.thumbnail_settings_ok
    }
}

fn probe_status() -> io::Result<StatusReport> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let clsid = clsid_str();
    let catid = shell_thumb_handler_catid_str();
    let ext = normalize_ext(DEFAULT_EXT);
    let progid_opt = current_progid_of_ext(&ext);

    let (ok_clsid, disable_process_isolation) =
        match hkcu.open_subkey(format!(r"Software\Classes\CLSID\{}", clsid)) {
            Ok(key) => {
                let dpi = key
                    .get_value::<u32, _>("DisableProcessIsolation")
                    .unwrap_or(0)
                    == 1;
                (true, dpi)
            }
            Err(_) => (false, false),
        };
    let (ok_inproc, inproc_server_path, inproc_path_exists) =
        match hkcu.open_subkey(format!(r"Software\Classes\CLSID\{}\InprocServer32", clsid)) {
            Ok(key) => {
                let path = key
                    .get_value::<String, _>("")
                    .ok()
                    .map(|s| s.trim_matches(char::from(0)).to_string())
                    .filter(|s| !s.is_empty());
                let exists = path
                    .as_ref()
                    .map(|p| Path::new(p).exists())
                    .unwrap_or(false);
                (true, path, exists)
            }
            Err(_) => (false, None, false),
        };

    let (ext_default_value, ext_default_matches) =
        match hkcu.open_subkey(format!(r"Software\Classes\{}", ext)) {
            Ok(key) => {
                let val = key
                    .get_value::<String, _>("")
                    .ok()
                    .map(|s| s.trim_matches(char::from(0)).to_string())
                    .filter(|s| !s.is_empty());
                let matches = val
                    .as_ref()
                    .map(|s| s.eq_ignore_ascii_case(DEFAULT_PROGID))
                    .unwrap_or(false);
                (val, matches)
            }
            Err(_) => (None, false),
        };

    let advanced_key = hkcu
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")
        .ok();
    let icons_only_value = advanced_key
        .as_ref()
        .and_then(|key| key.get_value::<u32, _>("IconsOnly").ok());
    let icons_only_ok = icons_only_value.map(|v| v == 0).unwrap_or(true);
    let disable_thumbnails_value = advanced_key
        .as_ref()
        .and_then(|key| key.get_value::<u32, _>("DisableThumbnails").ok());
    let disable_thumbnails_ok = disable_thumbnails_value.map(|v| v == 0).unwrap_or(true);
    let disable_thumbnail_cache_value = advanced_key
        .as_ref()
        .and_then(|key| key.get_value::<u32, _>("DisableThumbnailCache").ok());
    let disable_thumbnail_cache_ok = disable_thumbnail_cache_value
        .map(|v| v == 0)
        .unwrap_or(true);
    let disable_network_value = advanced_key.as_ref().and_then(|key| {
        key.get_value::<u32, _>("DisableThumbnailsOnNetworkFolders")
            .ok()
    });
    let disable_network_ok = disable_network_value.map(|v| v == 0).unwrap_or(true);

    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
    let (hkcr_binding, hkcr_binding_matches) =
        match hkcr.open_subkey(format!(r"{}\ShellEx\{}", ext, catid)) {
            Ok(key) => {
                let val = key
                    .get_value::<String, _>("")
                    .ok()
                    .map(|s| s.trim_matches(char::from(0)).to_string())
                    .filter(|s| !s.is_empty());
                let matches = val
                    .as_ref()
                    .map(|s| s.eq_ignore_ascii_case(&clsid))
                    .unwrap_or(false);
                (val, matches)
            }
            Err(_) => (None, false),
        };

    let mut cached_entries = Vec::new();
    if let Ok(cache_key) =
        hkcu.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached")
    {
        let clsid_upper = clsid.to_ascii_uppercase();
        let clsid_nobrace = clsid_upper.trim_matches('{').trim_matches('}').to_string();
        for value in cache_key.enum_values().flatten() {
            let name_upper = value.0.to_ascii_uppercase();
            if name_upper.contains(&clsid_upper) || name_upper.contains(&clsid_nobrace) {
                let state = match value.1 {
                    RegValue {
                        vtype: RegType::REG_BINARY,
                        ref bytes,
                    } if bytes.len() >= 4 => {
                        let mut arr = [0u8; 4];
                        arr.copy_from_slice(&bytes[..4]);
                        Some(u32::from_le_bytes(arr))
                    }
                    RegValue {
                        vtype: RegType::REG_DWORD,
                        ref bytes,
                    } if bytes.len() >= 4 => {
                        let mut arr = [0u8; 4];
                        arr.copy_from_slice(&bytes[..4]);
                        Some(u32::from_le_bytes(arr))
                    }
                    _ => None,
                };
                cached_entries.push((value.0, state));
            }
        }
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let machine_ok_clsid = hklm
        .open_subkey(format!(r"Software\Classes\CLSID\{}", clsid))
        .is_ok();
    let (machine_ok_inproc, machine_inproc_server_path, machine_inproc_path_exists) =
        match hklm.open_subkey(format!(r"Software\Classes\CLSID\{}\InprocServer32", clsid)) {
            Ok(key) => {
                let path = key
                    .get_value::<String, _>("")
                    .ok()
                    .map(|s| s.trim_matches(char::from(0)).to_string())
                    .filter(|s| !s.is_empty());
                let exists = path
                    .as_ref()
                    .map(|p| Path::new(p).exists())
                    .unwrap_or(false);
                (true, path, exists)
            }
            Err(_) => (false, None, false),
        };
    let machine_disable_process_isolation = hklm
        .open_subkey(format!(r"Software\Classes\CLSID\{}", clsid))
        .ok()
        .and_then(|key| key.get_value::<u32, _>("DisableProcessIsolation").ok())
        .map(|v| v == 1)
        .unwrap_or(false);

    let machine_ext_default_value = hklm
        .open_subkey(format!(r"Software\Classes\{}", ext))
        .ok()
        .and_then(|key| key.get_value::<String, _>("").ok())
        .map(|s| s.trim_matches(char::from(0)).to_string())
        .filter(|s| !s.is_empty());
    let machine_ext_default_matches = machine_ext_default_value
        .as_ref()
        .map(|s| s.eq_ignore_ascii_case(DEFAULT_PROGID))
        .unwrap_or(false);

    let machine_ok_bind_prog = hklm
        .open_subkey(format!(
            r"Software\Classes\{}\ShellEx\{}",
            DEFAULT_PROGID, catid
        ))
        .is_ok();
    let machine_ok_bind_ext = hklm
        .open_subkey(format!(r"Software\Classes\{}\ShellEx\{}", ext, catid))
        .is_ok();
    let machine_ok_bind_sys = hklm
        .open_subkey(format!(
            r"Software\Classes\SystemFileAssociations\{}\ShellEx\{}",
            ext, catid
        ))
        .is_ok();
    let machine_ok_thumb_handler = hklm
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers")
        .ok()
        .and_then(|key| key.get_value::<String, _>(&ext).ok())
        .map(|val| val.trim_matches(char::from(0)) == clsid)
        .unwrap_or(false);
    let hklm_bind_prog = machine_ok_bind_prog;
    let hklm_bind_ext = machine_ok_bind_ext;

    let mut policy_values = Vec::new();
    let mut policy_ok = true;
    const POLICY_PATHS: [&str; 2] = [
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        r"Software\Policies\Microsoft\Windows\Explorer",
    ];
    const POLICY_NAMES: [&str; 3] = [
        "DisableThumbnails",
        "DisableThumbnailCache",
        "DisableThumbnailsOnNetworkFolders",
    ];
    for (root, prefix) in [(&hkcu, "HKCU"), (&hklm, "HKLM")] {
        for path in POLICY_PATHS {
            if let Ok(key) = root.open_subkey(path) {
                for name in POLICY_NAMES {
                    if let Ok(value) = key.get_value::<u32, _>(name) {
                        if value != 0 {
                            policy_ok = false;
                            policy_values.push((format!(r"{}\\{}\\{}", prefix, path, name), value));
                        }
                    }
                }
            }
        }
    }

    let ok_prog = if let Some(pid) = &progid_opt {
        hkcu.open_subkey(format!(r"Software\Classes\{}\ShellEx\{}", pid, catid))
            .is_ok()
    } else {
        false
    };

    let ok_ext = hkcu
        .open_subkey(format!(r"Software\Classes\{}\ShellEx\{}", ext, catid))
        .is_ok();

    let ok_sys = hkcu
        .open_subkey(format!(
            r"Software\Classes\SystemFileAssociations\{}\ShellEx\{}",
            ext, catid
        ))
        .is_ok();

    let list_entries = open_with_list_entries(&hkcu, &ext);
    let mut apps_list_details = Vec::new();
    let mut ok_apps_list_matched = 0;
    for entry in list_entries {
        let bound = check_application_binding(&hkcu, &entry, &catid);
        if bound {
            ok_apps_list_matched += 1;
        }
        apps_list_details.push((entry, bound));
    }

    let progid_entries = open_with_progids_entries(&hkcu, &ext);
    let mut apps_progids_details = Vec::new();
    let mut ok_apps_progids_matched = 0;
    for entry in progid_entries {
        let bound = check_prog_id_application(&hkcu, &entry, &catid);
        if bound {
            ok_apps_progids_matched += 1;
        }
        apps_progids_details.push((entry, bound));
    }

    let user_choice_detail = user_choice_prog_id(&hkcu, &ext).map(|prog_id| {
        if let Some(app) = prog_id.strip_prefix("Applications\\") {
            let bound = check_application_binding(&hkcu, app, &catid);
            (prog_id, bound)
        } else {
            let bound = check_prog_id_application(&hkcu, &prog_id, &catid);
            (prog_id, bound)
        }
    });

    let ok_user_choice = user_choice_detail
        .as_ref()
        .map(|(_, ok)| if *ok { "OK" } else { "NO" })
        .unwrap_or("N/A");

    let mut alerts = Vec::new();
    if !ok_clsid {
        alerts.push("CLSID key missing".to_string());
    }
    if !ok_inproc {
        alerts.push("InprocServer32 missing".to_string());
    }
    if !ok_prog {
        alerts.push("ProgID ShellEx binding missing".to_string());
    }
    if !ok_ext {
        alerts.push("Extension ShellEx binding missing".to_string());
    }
    if !ok_sys {
        alerts.push("SystemFileAssociations ShellEx binding missing".to_string());
    }
    if !disable_process_isolation {
        alerts.push("DisableProcessIsolation not set to 1".to_string());
    }
    if !ext_default_matches {
        alerts.push(match &ext_default_value {
            Some(val) => format!("Extension default ProgID mismatch (current={})", val),
            None => "Extension default ProgID missing".to_string(),
        });
    }
    if ok_inproc && !inproc_path_exists {
        if let Some(path) = &inproc_server_path {
            alerts.push(format!("InprocServer32 target DLL not found: {}", path));
        } else {
            alerts.push("InprocServer32 target DLL not found".to_string());
        }
    }

    let ok_thumb_handler = hkcu
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers")
        .ok()
        .and_then(|key| key.get_value::<String, _>(&ext).ok())
        .map(|val| val.trim_matches(char::from(0)) == clsid)
        .unwrap_or(false);
    if !ok_thumb_handler {
        alerts.push("Explorer ThumbnailHandlers mapping missing".to_string());
    }
    if !hkcr_binding_matches {
        alerts.push(match &hkcr_binding {
            Some(val) => format!("HKCR binding points to {}", val),
            None => "HKCR binding missing".to_string(),
        });
    }
    if !cached_entries.is_empty() {
        alerts.push("Cached shell extension entry exists (clear may be required)".to_string());
    }
    if !icons_only_ok {
        alerts.push(format!(
            "Explorer setting IconsOnly disables thumbnails (value={})",
            format_u32_opt(icons_only_value)
        ));
    }
    if !disable_thumbnails_ok {
        alerts.push(format!(
            "Explorer setting DisableThumbnails is non-zero (value={})",
            format_u32_opt(disable_thumbnails_value)
        ));
    }
    if !disable_thumbnail_cache_ok {
        alerts.push(format!(
            "Explorer setting DisableThumbnailCache is non-zero (value={})",
            format_u32_opt(disable_thumbnail_cache_value)
        ));
    }
    if !disable_network_ok {
        alerts.push(format!(
            "Explorer setting DisableThumbnailsOnNetworkFolders is non-zero (value={})",
            format_u32_opt(disable_network_value)
        ));
    }
    if !machine_ok_clsid {
        alerts.push("HKLM CLSID key missing".to_string());
    }
    if !machine_ok_inproc {
        alerts.push("HKLM InprocServer32 missing".to_string());
    }
    if !machine_disable_process_isolation {
        alerts.push("HKLM DisableProcessIsolation not set to 1".to_string());
    }
    if !machine_ext_default_matches {
        alerts.push(match &machine_ext_default_value {
            Some(val) => format!("HKLM extension default ProgID mismatch (current={})", val),
            None => "HKLM extension default ProgID missing".to_string(),
        });
    }
    if machine_ok_inproc && !machine_inproc_path_exists {
        if let Some(path) = &machine_inproc_server_path {
            alerts.push(format!(
                "HKLM InprocServer32 target DLL not found: {}",
                path
            ));
        } else {
            alerts.push("HKLM InprocServer32 target DLL not found".to_string());
        }
    }
    if !machine_ok_bind_prog {
        alerts.push("HKLM ProgID ShellEx binding missing".to_string());
    }
    if !machine_ok_bind_ext {
        alerts.push("HKLM extension ShellEx binding missing".to_string());
    }
    if !machine_ok_bind_sys {
        alerts.push("HKLM SystemFileAssociations ShellEx binding missing".to_string());
    }
    if !machine_ok_thumb_handler {
        alerts.push("HKLM Explorer ThumbnailHandlers mapping missing".to_string());
    }
    if !policy_ok {
        alerts.push("Explorer policies disable thumbnails".to_string());
    }

    let mut com_create_status = "FAIL";
    let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    if hr == S_OK || hr == S_FALSE {
        unsafe {
            match CoCreateInstance::<Option<&IUnknown>, IUnknown>(
                &CLSID_BLP_THUMB,
                None,
                CLSCTX_INPROC_SERVER,
            ) {
                Ok(_) => {
                    com_create_status = "OK";
                }
                Err(err) => {
                    alerts.push(format!("CoCreateInstance failed: {err:?}"));
                    log_cli(format!("Status: CoCreateInstance failed: {err:?}"));
                }
            }
            CoUninitialize();
        }
    } else {
        alerts.push(format!("CoInitializeEx failed: {hr:?}"));
        log_cli(format!("Status: CoInitializeEx failed: {:?}", hr));
    }

    let thumbnail_settings_ok = icons_only_ok
        && disable_thumbnails_ok
        && disable_thumbnail_cache_ok
        && disable_network_ok
        && policy_ok;

    Ok(StatusReport {
        ok_clsid,
        ok_inproc,
        ok_bind_prog: ok_prog,
        ok_bind_ext: ok_ext,
        ok_bind_sys: ok_sys,
        ok_thumb_handler,
        disable_process_isolation,
        inproc_server_path,
        inproc_path_exists,
        ext_default_value,
        ext_default_matches,
        machine_ok_clsid,
        machine_ok_inproc,
        machine_disable_process_isolation,
        machine_inproc_server_path,
        machine_inproc_path_exists,
        machine_ext_default_value,
        machine_ext_default_matches,
        machine_ok_bind_prog,
        machine_ok_bind_ext,
        machine_ok_bind_sys,
        machine_ok_thumb_handler,
        hkcr_binding,
        hkcr_binding_matches,
        hklm_bind_prog,
        hklm_bind_ext,
        cached_entries,
        icons_only_value,
        icons_only_ok,
        disable_thumbnails_value,
        disable_thumbnails_ok,
        disable_thumbnail_cache_value,
        disable_thumbnail_cache_ok,
        disable_network_value,
        disable_network_ok,
        policy_values,
        policy_ok,
        thumbnail_settings_ok,
        ok_apps_list_matched,
        apps_list_total: apps_list_details.len(),
        ok_apps_progids_matched,
        apps_progids_total: apps_progids_details.len(),
        ok_user_choice,
        apps_list_details,
        apps_progids_details,
        user_choice_detail,
        com_create_status,
        alerts,
    })
}

/* ---------- Utils ---------- */

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

fn mark(b: bool) -> &'static str {
    if b { "OK" } else { "NO" }
}

fn presence(b: bool) -> &'static str {
    if b { "present" } else { "absent" }
}

fn format_u32_opt(value: Option<u32>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "<missing>".to_string())
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

fn check_application_binding(hkcu: &RegKey, entry: &str, catid: &str) -> bool {
    if entry.is_empty() {
        return false;
    }

    if !entry.ends_with(".exe") {
        return check_prog_id_application(hkcu, entry, catid);
    }

    hkcu.open_subkey(format!(
        r"Software\Classes\Applications\{}\ShellEx\{}",
        entry, catid
    ))
    .is_ok()
}

fn check_prog_id_application(hkcu: &RegKey, progid: &str, catid: &str) -> bool {
    if progid.is_empty() {
        return false;
    }

    if let Some(app) = progid.strip_prefix("Applications\\") {
        return check_application_binding(hkcu, app, catid);
    }

    hkcu.open_subkey(format!(r"Software\Classes\{}\ShellEx\{}", progid, catid))
        .is_ok()
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

    if let Some(app) = progid.strip_prefix("Applications\\") {
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

    if let Some(app) = progid.strip_prefix("Applications\\") {
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

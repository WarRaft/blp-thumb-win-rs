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
use winreg::{RegKey, enums::*};

// Embedded DLL that you copy into ./bin/ at build time.
// The EXE will re-materialize it under %LOCALAPPDATA%\blp-thumb-win\
static DLL_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/bin/blp_thumb_win.dll"
));

// Single source of truth from the library (your keys module)
use crate::restart_explorer::restart_explorer;
use blp_thumb_win::keys::{
    DEFAULT_EXT, DEFAULT_PROGID, FRIENDLY_NAME, clsid_str, shell_thumb_handler_catid_str,
};

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
        3 => Action::RestartExplorer,
        4 => Action::ClearThumbCache,
        5 => Action::ClearAssociations,
        _ => Action::Exit,
    })
}

impl Action {
    fn title(self) -> &'static str {
        match self {
            Action::Install => "Install (current user)",
            Action::Uninstall => "Uninstall (current user)",
            Action::Status => "Status",
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
        Action::RestartExplorer => restart_explorer(),
        Action::ClearThumbCache => clear_thumb_cache(),
        Action::ClearAssociations => clear_associations(),
        Action::Exit => Ok(()),
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
    register_com(&dll_path)?;
    log_cli("Install: registry entries written");
    notify_shell_assoc("install");
    println!("Installed in HKCU. Use 'Restart Explorer' to refresh thumbnails.");
    Ok(())
}

fn uninstall() -> io::Result<()> {
    log_cli("Uninstall: start");
    unregister_com()?;
    log_cli("Uninstall: registry entries removed");
    notify_shell_assoc("uninstall");
    println!("Uninstalled from HKCU.");
    Ok(())
}

fn status() -> io::Result<()> {
    log_cli("Status: probing");
    let report = probe_status()?;

    println!("Status (details below):");
    println!("  CLSID key:                   {}", mark(report.ok_clsid));
    println!("  InprocServer32 value:        {}", mark(report.ok_inproc));
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
        "  Applications OpenWithList:   {}/{}",
        report.ok_apps_list_matched, report.apps_list_total
    );
    println!(
        "  Applications OpenWithProgids:{}/{}",
        report.ok_apps_progids_matched, report.apps_progids_total
    );
    println!("  UserChoice target:           {}", report.ok_user_choice);

    if report.apps_list_total > 0 {
        println!("\n  OpenWithList entries:");
        for (entry, bound) in report.apps_list_details {
            println!("    {:<30} {}", entry, mark(bound));
        }
    }

    if report.apps_progids_total > 0 {
        println!("\n  OpenWithProgids entries:");
        for (entry, bound) in report.apps_progids_details {
            println!("    {:<30} {}", entry, mark(bound));
        }
    }

    if let Some(choice) = report.user_choice_detail {
        println!("\n  UserChoice:");
        println!("    {:<30} {}", choice.0, mark(choice.1));
    }

    log_cli(format!(
        "Status summary -> CLSID: {}, Inproc: {}, ProgID bind: {}, Ext bind: {}, SysAssoc bind: {}, AppsList OK: {}/{}",
        mark(report.ok_clsid),
        mark(report.ok_inproc),
        mark(report.ok_bind_prog),
        mark(report.ok_bind_ext),
        mark(report.ok_bind_sys),
        report.ok_apps_list_matched,
        report.apps_list_total
    ));
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
    let _ = hkcu.delete_subkey_all(format!(
        r"Software\Classes\SystemFileAssociations\{}",
        ext
    ));
    let _ = hkcu.delete_subkey_all(format!(
        r"Software\Classes\SystemFileAssociations\image\ShellEx\{}",
        catid
    ));
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
fn register_com(dll_path: &Path) -> io::Result<()> {
    log_cli(format!("Register COM: start (dll={})", dll_path.display()));
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    let clsid = clsid_str(); // "{...}"
    let catid = shell_thumb_handler_catid_str(); // "{e357...}"

    // HKCU\Software\Classes\CLSID\{CLSID}
    log_cli("Register COM: creating CLSID key");
    let (key_clsid, _) = hkcu.create_subkey(format!(r"Software\Classes\CLSID\{}", clsid))?;
    key_clsid.set_value("", &FRIENDLY_NAME)?;
    //log_cli("Register COM: setting DisableProcessIsolation=1");
    //key_clsid.set_value("DisableProcessIsolation", &1u32)?;

    // HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32
    log_cli("Register COM: writing InprocServer32");
    let (key_inproc, _) =
        hkcu.create_subkey(format!(r"Software\Classes\CLSID\{}\InprocServer32", clsid))?;
    key_inproc.set_value("", &dll_path.as_os_str())?;
    // Thumbnail providers are typically Apartment threaded.
    key_inproc.set_value("ThreadingModel", &"Apartment")?;

    // Optional: mark as Approved (per-user)
    log_cli("Register COM: marking extension as approved");
    let (approved, _) =
        hkcu.create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved")?;
    approved.set_value(&clsid, &FRIENDLY_NAME)?;

    // Implemented Categories (Thumbnail Provider)
    log_cli("Register COM: setting Implemented Categories");
    let _ = hkcu.create_subkey(format!(
        r"Software\Classes\CLSID\{}\Implemented Categories\{}",
        clsid, catid
    ))?;

    let ext = normalize_ext(DEFAULT_EXT);

    // Extension metadata
    log_cli("Register COM: ensuring extension metadata (content type/perceived type)");
    let (ext_key, _) = hkcu.create_subkey(format!(r"Software\Classes\{}", ext))?;
    // Don't clobber an existing Content Type if it differs; log instead
    match ext_key.get_value::<String, _>("Content Type") {
        Ok(existing)
            if !existing.trim_matches(char::from(0)).is_empty() && existing != "image/x-blp" =>
        {
            log_cli(format!(
                "Register COM: skipping Content Type override (current={})",
                existing
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
                "Register COM: extension default already set to {}",
                existing
            ));
        }
        _ => {
            log_cli("Register COM: setting extension default to WarRaft.BLP");
            ext_key.set_value("", &DEFAULT_PROGID)?;
        }
    }

    log_cli("Register COM: ensuring ProgID key WarRaft.BLP");
    let (progid_key, _) = hkcu.create_subkey(format!(r"Software\Classes\{}", DEFAULT_PROGID))?;
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

    // Bind under the extension itself.
    log_cli(format!("Register COM: binding under extension {}", ext));
    let (key_ext_shellex, _) = hkcu.create_subkey(format!(r"Software\Classes\{}\ShellEx", ext))?;
    let (key_ext_thumb, _) = key_ext_shellex.create_subkey(&catid)?;
    key_ext_thumb.set_value("", &clsid)?;

    // Bind under SystemFileAssociations too (Explorer often checks here).
    log_cli(format!(
        "Register COM: binding under SystemFileAssociations {}",
        ext
    ));
    let (key_sys_shellex, _) = hkcu
        .create_subkey(format!(r"Software\Classes\SystemFileAssociations\{}\ShellEx", ext))?;
    let (key_sys_thumb, _) = key_sys_shellex.create_subkey(&catid)?;
    key_sys_thumb.set_value("", &clsid)?;

    log_cli("Register COM: binding under SystemFileAssociations image");
    let (key_img_shellex, _) = hkcu
        .create_subkey(r"Software\Classes\SystemFileAssociations\image\ShellEx")?;
    let (key_img_thumb, _) = key_img_shellex.create_subkey(&catid)?;
    key_img_thumb.set_value("", &clsid)?;

    // Bind under Applications referenced in OpenWithList
    for entry in open_with_list_entries(&hkcu, &ext) {
        bind_application(&hkcu, &entry, &catid, &clsid)?;
    }

    for progid in open_with_progids_entries(&hkcu, &ext) {
        bind_prog_id_application(&hkcu, &progid, &catid, &clsid)?;
    }

    if let Some(prog_id) = user_choice_prog_id(&hkcu, &ext) {
        if let Some(app) = prog_id.strip_prefix("Applications\\") {
            bind_application(&hkcu, app, &catid, &clsid)?;
        } else {
            bind_prog_id_application(&hkcu, &prog_id, &catid, &clsid)?;
        }
    }

    log_cli("Register COM: completed");

    Ok(())
}

fn unregister_com() -> io::Result<()> {
    log_cli("Unregister COM: start");
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let clsid = clsid_str();
    let catid = shell_thumb_handler_catid_str();
    let ext = normalize_ext(DEFAULT_EXT);
    let progid_opt = current_progid_of_ext(&ext);

    if let Some(pid) = &progid_opt {
        log_cli(format!("Unregister COM: removing ProgID binding {}", pid));
        let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\{}\ShellEx\{}", pid, catid));
    }
    log_cli(format!(
        "Unregister COM: removing extension binding {}",
        ext
    ));
    let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\{}\ShellEx\{}", ext, catid));
    log_cli(format!(
        "Unregister COM: removing SystemFileAssociations binding {}",
        ext
    ));
    let _ = hkcu.delete_subkey_all(format!(
        r"Software\Classes\SystemFileAssociations\{}\ShellEx\{}",
        ext, catid
    ));

    log_cli("Unregister COM: removing SystemFileAssociations image binding");
    let _ = hkcu.delete_subkey_all(format!(
        r"Software\Classes\SystemFileAssociations\image\ShellEx\{}",
        catid
    ));

    if let Ok(ext_key) =
        hkcu.open_subkey_with_flags(format!(r"Software\Classes\{}", ext), KEY_SET_VALUE)
    {
        let _ = ext_key.delete_value("Content Type");
        let _ = ext_key.delete_value("PerceivedType");
    }

    // Remove bindings under Applications
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
    }
    log_cli("Unregister COM: removing CLSID keys");
    let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\CLSID\{}", clsid));
    let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\{}", DEFAULT_PROGID));
    let _ = hkcu
        .open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
            KEY_SET_VALUE,
        )
        .and_then(|k| k.delete_value(clsid));
    log_cli("Unregister COM: completed");
    Ok(())
}

struct StatusReport {
    ok_clsid: bool,
    ok_inproc: bool,
    ok_bind_prog: bool,
    ok_bind_ext: bool,
    ok_bind_sys: bool,
    ok_apps_list_matched: usize,
    apps_list_total: usize,
    ok_apps_progids_matched: usize,
    apps_progids_total: usize,
    ok_user_choice: &'static str,
    apps_list_details: Vec<(String, bool)>,
    apps_progids_details: Vec<(String, bool)>,
    user_choice_detail: Option<(String, bool)>,
}

fn probe_status() -> io::Result<StatusReport> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let clsid = clsid_str();
    let catid = shell_thumb_handler_catid_str();
    let ext = normalize_ext(DEFAULT_EXT);
    let progid_opt = current_progid_of_ext(&ext);

    let ok_clsid = hkcu
        .open_subkey(format!(r"Software\Classes\CLSID\{}", clsid))
        .is_ok();
    let ok_inproc = hkcu
        .open_subkey(format!(r"Software\Classes\CLSID\{}\InprocServer32", clsid))
        .is_ok();

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

    Ok(StatusReport {
        ok_clsid,
        ok_inproc,
        ok_bind_prog: ok_prog,
        ok_bind_ext: ok_ext,
        ok_bind_sys: ok_sys,
        ok_apps_list_matched,
        apps_list_total: apps_list_details.len(),
        ok_apps_progids_matched,
        apps_progids_total: apps_progids_details.len(),
        ok_user_choice,
        apps_list_details,
        apps_progids_details,
        user_choice_detail,
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

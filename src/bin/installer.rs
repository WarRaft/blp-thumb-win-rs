#![cfg(target_os = "windows")]

// Arrow-key interactive installer for the BLP Thumbnail Provider (COM DLL).
// Menu: Install (HKCU/HKLM), Uninstall (HKCU/HKLM), Status (HKCU/HKLM), Restart Explorer, Quit.
//
// Assumes DLL is next to the EXE as "blp_thumb.dll".
// Make sure CLSID_BLP_THUMB matches the CLSID implemented by your COM DLL.

use dialoguer::{theme::ColorfulTheme, Select};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use winreg::enums::*;
use winreg::RegKey;

// ---------- Constants you must keep in sync with the DLL ----------
const SHELL_THUMB_HANDLER_CATID: &str = "{e357fccd-a995-4576-b01f-234630154e96}";
// TODO: replace with your real CLSID (must match DLL)
const CLSID_BLP_THUMB: &str = "{12345678-1234-1234-1234-1234567890ab}";

const DEFAULT_PROGID: &str = "WarRaft.BLP";
const DEFAULT_EXT: &str = ".blp";
const FRIENDLY_NAME: &str = "BLP Thumbnail Provider";

// Scope for registry root
#[derive(Copy, Clone, Debug)]
enum Hive { User, Machine }

// ==============================
//            main()
// ==============================
fn main() {
    let theme = ColorfulTheme::default();

    loop {
        let items = vec![
            "Install…",
            "Uninstall…",
            "Status…",
            "Restart Explorer",
            "Quit",
        ];
        let Ok(sel) = Select::with_theme(&theme)
            .with_prompt("BLP Thumbnail Provider — choose an action")
            .items(&items)
            .default(0)
            .interact() else { return; };

        match sel {
            0 => submenu_install(&theme),
            1 => submenu_uninstall(&theme),
            2 => submenu_status(&theme),
            3 => {
                if let Err(e) = cmd_restart_explorer() { show_err(&e); }
                else { println!("✔ Explorer restarted"); }
            }
            _ => return,
        }
    }
}

// ---------- Submenus ----------
fn submenu_install(theme: &ColorfulTheme) {
    let items = vec!["Per-User (HKCU)", "Per-Machine (HKLM)", "Back"];
    let Ok(i) = Select::with_theme(theme)
        .with_prompt("Install scope")
        .items(&items)
        .default(0)
        .interact() else { return; };

    match i {
        0 => do_install(Hive::User),
        1 => do_install(Hive::Machine),
        _ => {}
    }
}

fn submenu_uninstall(theme: &ColorfulTheme) {
    let items = vec!["Per-User (HKCU)", "Per-Machine (HKLM)", "Back"];
    let Ok(i) = Select::with_theme(theme)
        .with_prompt("Uninstall scope")
        .items(&items)
        .default(0)
        .interact() else { return; };

    match i {
        0 => do_uninstall(Hive::User),
        1 => do_uninstall(Hive::Machine),
        _ => {}
    }
}

fn submenu_status(theme: &ColorfulTheme) {
    let items = vec!["Per-User (HKCU)", "Per-Machine (HKLM)", "Back"];
    let Ok(i) = Select::with_theme(theme)
        .with_prompt("Status scope")
        .items(&items)
        .default(0)
        .interact() else { return; };

    match i {
        0 => do_status(Hive::User),
        1 => do_status(Hive::Machine),
        _ => {}
    }
}

// ---------- High-level actions ----------
fn do_install(hive: Hive) {
    let dll = match resolve_dll(None) {
        Ok(p) => p,
        Err(e) => { show_err(&e); return; }
    };
    if !dll.exists() { show_err(&format!("DLL not found: {}", dll.display())); return; }

    println!(
        "→ Installing [{}]\n   DLL : {}\n   CLSID: {}",
        scope_name(hive), dll.display(), CLSID_BLP_THUMB
    );

    match open_classes_root(hive) {
        Ok(root) => {
            if let Err(e) = register_clsid(&root, &dll) { show_err(&e); return; }
            if let Err(e) = bind_extension(&root, DEFAULT_EXT, DEFAULT_PROGID) { show_err(&e); return; }
            if let Err(e) = wire_progid_shellex(&root, DEFAULT_PROGID) { show_err(&e); return; }
            println!("✔ Installed ({}). You may run “Restart Explorer”.", scope_name(hive));
        }
        Err(e) => show_err(&e),
    }
}

fn do_uninstall(hive: Hive) {
    println!("→ Uninstalling [{}]\n   CLSID: {}", scope_name(hive), CLSID_BLP_THUMB);

    match open_classes_root(hive) {
        Ok(root) => {
            if let Err(e) = unwire_progid_shellex_if_matches(&root, DEFAULT_PROGID) { show_err(&e); return; }
            if let Err(e) = unbind_extension_if_matches(&root, DEFAULT_EXT, DEFAULT_PROGID) { show_err(&e); return; }
            if let Err(e) = unregister_clsid(&root) { show_err(&e); return; }
            println!("✔ Uninstalled ({}). You may run “Restart Explorer”.", scope_name(hive));
        }
        Err(e) => show_err(&e),
    }
}

fn do_status(hive: Hive) {
    println!("→ Status [{}]", scope_name(hive));
    match open_classes_root(hive) {
        Ok(root) => {
            let clsid_ok = read_string(&root, &format!(r"CLSID\{}\InprocServer32\", CLSID_BLP_THUMB))
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            println!("  • CLSID registered       : {}", yesno(clsid_ok));

            let ext_target =
                read_string(&root, &format!(r"{}\", normalize_ext(DEFAULT_EXT))).unwrap_or_default();
            println!(
                "  • {} → {}",
                normalize_ext(DEFAULT_EXT),
                if ext_target.is_empty() { "<not set>".into() } else { ext_target }
            );

            let shellex_key = format!(r"{}\ShellEx\{}\",
                DEFAULT_PROGID, SHELL_THUMB_HANDLER_CATID);
            let shellex_val = read_string(&root, &shellex_key).unwrap_or_default();
            println!(
                "  • {} ShellEx handler     : {}",
                DEFAULT_PROGID,
                if shellex_val.is_empty() { "<not set>".into() } else { shellex_val }
            );
        }
        Err(e) => show_err(&e),
    }
}

// ---------- Explorer ----------
fn cmd_restart_explorer() -> Result<(), String> {
    run("taskkill", &["/IM", "explorer.exe", "/F"])?;
    run("explorer.exe", &[])?;
    Ok(())
}

// ---------- Registry helpers ----------
fn open_classes_root(hive: Hive) -> Result<RegKey, String> {
    match hive {
        Hive::Machine => RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags("Software\\Classes", KEY_READ | KEY_WRITE)
            .map_err(|e| format!("HKLM\\Software\\Classes: {}", e)),
        Hive::User => RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey("Software\\Classes")
            .map_err(|e| format!("HKCU\\Software\\Classes: {}", e))
            .map(|(k, _)| k),
    }
}

fn register_clsid(root: &RegKey, dll_path: &Path) -> Result<(), String> {
    let clsid_path  = format!(r"CLSID\{}\", CLSID_BLP_THUMB);
    let inproc_path = format!(r"CLSID\{}\InprocServer32\", CLSID_BLP_THUMB);

    create_and_set_default(root, &clsid_path, FRIENDLY_NAME)?;
    create_and_set_default(root, &inproc_path, &dll_path.display().to_string())?;

    let inproc = root
        .open_subkey_with_flags(&inproc_path, KEY_READ | KEY_WRITE)
        .map_err(|e| format!("open {}: {}", inproc_path, e))?;
    inproc
        .set_value("ThreadingModel", &"Apartment")
        .map_err(|e| format!("set ThreadingModel: {}", e))?;
    Ok(())
}

fn unregister_clsid(root: &RegKey) -> Result<(), String> {
    let inproc_path = format!(r"CLSID\{}\InprocServer32\", CLSID_BLP_THUMB);
    let clsid_path  = format!(r"CLSID\{}\", CLSID_BLP_THUMB);
    let _ = root.delete_subkey(&inproc_path);
    let _ = root.delete_subkey(&clsid_path);
    Ok(())
}

fn bind_extension(root: &RegKey, ext: &str, progid: &str) -> Result<(), String> {
    let ext_norm = normalize_ext(ext);

    let key = create(root, &format!(r"{}\", ext_norm))?;
    key.set_value("", &progid)
        .map_err(|e| format!("set {} default: {}", ext_norm, e))?;

    let pid_key = create(root, &format!(r"{}\", progid))?;
    pid_key
        .set_value("", &"BLP File")
        .map_err(|e| format!("set {} default: {}", progid, e))?;
    Ok(())
}

fn unbind_extension_if_matches(root: &RegKey, ext: &str, progid: &str) -> Result<(), String> {
    let ext_norm = normalize_ext(ext);
    let path = format!(r"{}\", ext_norm);
    let current = read_string(root, &path).unwrap_or_default();
    if current == progid {
        let key = root
            .open_subkey_with_flags(&path, KEY_READ | KEY_WRITE)
            .map_err(|e| format!("open {}: {}", path, e))?;
        key.set_value::<&str, &str>("", "")
            .map_err(|e| format!("clear {} default: {}", path, e))?;
    }
    Ok(())
}

fn wire_progid_shellex(root: &RegKey, progid: &str) -> Result<(), String> {
    let key_path = format!(r"{}\ShellEx\{}\",
        progid, SHELL_THUMB_HANDLER_CATID);
    let key = create(root, &key_path)?;
    key.set_value("", &CLSID_BLP_THUMB)
        .map_err(|e| format!("set {} default: {}", key_path, e))?;
    Ok(())
}

fn unwire_progid_shellex_if_matches(root: &RegKey, progid: &str) -> Result<(), String> {
    let key_path = format!(r"{}\ShellEx\{}\",
        progid, SHELL_THUMB_HANDLER_CATID);
    let current = read_string(root, &key_path).unwrap_or_default();
    if current.eq_ignore_ascii_case(CLSID_BLP_THUMB) {
        if let Ok(key) = root.open_subkey_with_flags(&key_path, KEY_READ | KEY_WRITE) {
            let _ = key.set_value::<&str, &str>("", "");
        }
    }
    Ok(())
}

// ---------- Small utils ----------
fn scope_name(h: Hive) -> &'static str {
    match h {
        Hive::User => "HKCU",
        Hive::Machine => "HKLM",
    }
}

fn yesno(b: bool) -> &'static str { if b { "yes" } else { "no" } }

fn resolve_dll(cli_dll: Option<&PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = cli_dll { return Ok(p.clone()); }
    let exe = env::current_exe().map_err(|e| format!("current_exe: {}", e))?;
    let dir = exe.parent().ok_or_else(|| "cannot get exe directory".to_string())?;
    Ok(dir.join("blp_thumb.dll"))
}

fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(cmd).args(args).output()
        .map_err(|e| format!("spawn {}: {}", cmd, e))?;
    if !out.status.success() {
        return Err(format!(
            "{} failed (code {:?})\nstdout: {}\nstderr: {}",
            cmd,
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn read_string(root: &RegKey, rel_path: &str) -> Result<String, String> {
    let key = root.open_subkey_with_flags(rel_path, KEY_READ)
        .map_err(|e| format!("open {}: {}", rel_path, e))?;
    key.get_value::<String, _>("")
        .map_err(|e| format!("read {} default: {}", rel_path, e))
}

fn create(root: &RegKey, rel_path: &str) -> Result<RegKey, String> {
    root.create_subkey(rel_path)
        .map_err(|e| format!("create {}: {}", rel_path, e))
        .map(|(k, _)| k)
}

fn create_and_set_default(root: &RegKey, rel_path: &str, val: &str) -> Result<(), String> {
    let k = create(root, rel_path)?;
    k.set_value("", &val)
        .map_err(|e| format!("set {} default: {}", rel_path, e))
}

fn show_err(msg: &str) { eprintln!("✖ {}", msg); }

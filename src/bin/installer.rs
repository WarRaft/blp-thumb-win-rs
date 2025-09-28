#![cfg(windows)]

use std::{
    env, fs, io,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread::sleep,
    time::Duration,
};

use dialoguer::console::style;
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Select, console::Term};
use winreg::{RegKey, enums::*};

// Embedded DLL that you copy into ./bin/ at build time.
// The EXE will re-materialize it under %LOCALAPPDATA%\blp-thumb-win\
static DLL_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/bin/blp_thumb_win.dll"
));

// Single source of truth from the library (your keys module)
use blp_thumb_win::keys::{DEFAULT_EXT, FRIENDLY_NAME, clsid_str, shell_thumb_handler_catid_str};

fn log_cli(message: impl Into<String>) {
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
    println!("Installed in HKCU. Use 'Restart Explorer' to refresh thumbnails.");
    Ok(())
}

fn uninstall() -> io::Result<()> {
    log_cli("Uninstall: start");
    unregister_com()?;
    log_cli("Uninstall: registry entries removed");
    println!("Uninstalled from HKCU.");
    Ok(())
}

fn status() -> io::Result<()> {
    log_cli("Status: probing");
    let (ok_clsid, ok_inproc, ok_bind_prog, ok_bind_ext) = probe_status()?;
    log_cli(format!(
        "Status results -> CLSID: {}, Inproc: {}, ProgID bind: {}, Ext bind: {}",
        mark(ok_clsid),
        mark(ok_inproc),
        mark(ok_bind_prog),
        mark(ok_bind_ext)
    ));
    println!("Status:");
    println!("  CLSID key:             {}", mark(ok_clsid));
    println!("  InprocServer32 value:  {}", mark(ok_inproc));
    println!("  ShellEx bind (ProgID): {}", mark(ok_bind_prog));
    println!("  ShellEx bind (Ext):    {}", mark(ok_bind_ext));
    Ok(())
}

fn restart_explorer() -> io::Result<()> {
    log_cli("Restart Explorer: terminating explorer.exe");
    // Kill silently (no localized output); ignore errors if it's not running.
    let _ = Command::new("taskkill")
        .args(["/F", "/IM", "explorer.exe"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    // Give the shell a moment to tear down.
    sleep(Duration::from_millis(400));

    log_cli("Restart Explorer: launching explorer.exe");
    let _ = Command::new("explorer.exe")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    println!("Explorer restarted.");
    log_cli("Restart Explorer: completed");
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
    log_cli("Register COM: setting DisableProcessIsolation=1");
    key_clsid.set_value("DisableProcessIsolation", &1u32)?;

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

    // Bind under ProgID if present, otherwise under extension key.
    let ext = normalize_ext(DEFAULT_EXT);
    let progid_opt = current_progid_of_ext(&ext);

    if let Some(pid) = &progid_opt {
        log_cli(format!("Register COM: binding under ProgID {}", pid));
        let (key_shellex, _) = hkcu.create_subkey(format!(r"Software\Classes\{}\ShellEx", pid))?;
        let (key_thumb, _) = key_shellex.create_subkey(&catid)?;
        key_thumb.set_value("", &clsid)?;
    }

    // Always also bind under the extension itself (defensive).
    log_cli(format!("Register COM: binding under extension {}", ext));
    let (key_ext_shellex, _) = hkcu.create_subkey(format!(r"Software\Classes\{}\ShellEx", ext))?;
    let (key_ext_thumb, _) = key_ext_shellex.create_subkey(&catid)?;
    key_ext_thumb.set_value("", &clsid)?;

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
    log_cli("Unregister COM: removing CLSID keys");
    let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\CLSID\{}", clsid));
    let _ = hkcu
        .open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
            KEY_SET_VALUE,
        )
        .and_then(|k| k.delete_value(clsid));
    log_cli("Unregister COM: completed");
    Ok(())
}

fn probe_status() -> io::Result<(bool, bool, bool, bool)> {
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

    Ok((ok_clsid, ok_inproc, ok_prog, ok_ext))
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

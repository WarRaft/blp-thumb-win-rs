#![cfg(windows)]

use std::{
    env, fs, io,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    thread::sleep,
    time::Duration,
};

use dialoguer::{Select, console::Term, theme::ColorfulTheme};
use winreg::{RegKey, enums::*};

// The embedded DLL (you copy it to ./bin/ at build time)
static DLL_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/bin/blp_thumb_win.dll"
));

// Single source of truth (your lib exposes these):
use blp_thumb_win::keys::{DEFAULT_EXT, FRIENDLY_NAME, clsid_str, shell_thumb_handler_catid_str};

fn main() -> io::Result<()> {
    loop {
        match choose_action()? {
            Action::Install => {
                install()?;
            }
            Action::Uninstall => {
                uninstall()?;
            }
            Action::Status => {
                status()?;
            }
            Action::RestartExplorer => {
                restart_explorer()?;
            }
            Action::ClearThumbCache => {
                clear_thumb_cache()?;
            }
            Action::Exit => break,
        }
        pause("\nPress Enter to return to menu...");
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Action {
    Install,
    Uninstall,
    Status,
    RestartExplorer,
    ClearThumbCache,
    Exit,
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

    let idx = Select::with_theme(&ColorfulTheme::default())
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

/* ---------- Actions ---------- */

fn install() -> io::Result<()> {
    let dll_path = materialize_embedded_dll()?;
    register_com(&dll_path)?;
    println!("Installed (HKCU). Use 'Restart Explorer' to refresh thumbnails.");
    Ok(())
}

fn uninstall() -> io::Result<()> {
    unregister_com()?;
    println!("Uninstalled (HKCU).");
    Ok(())
}

fn status() -> io::Result<()> {
    let (ok_clsid, ok_inproc, ok_bind_prog, ok_bind_ext) = probe_status()?;
    println!("Status:");
    println!("  CLSID key:             {}", mark(ok_clsid));
    println!("  InprocServer32 value:  {}", mark(ok_inproc));
    println!("  ShellEx bind (ProgID): {}", mark(ok_bind_prog));
    println!("  ShellEx bind (Ext):    {}", mark(ok_bind_ext));
    Ok(())
}

fn restart_explorer() -> io::Result<()> {
    let _ = Command::new("taskkill")
        .args(["/f", "/im", "explorer.exe"])
        .status();
    sleep(Duration::from_millis(400));
    let _ = Command::new("explorer.exe").status();
    println!("Explorer restarted.");
    Ok(())
}

fn clear_thumb_cache() -> io::Result<()> {
    let Some(local) = env::var_os("LOCALAPPDATA") else {
        println!("LOCALAPPDATA is not set.");
        return Ok(());
    };
    let dir = PathBuf::from(local).join(r"Microsoft\Windows\Explorer");
    if !dir.is_dir() {
        println!("No thumbnail cache dir: {}", dir.display());
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
    Ok(())
}

/* ---------- Registry / files ---------- */

fn materialize_embedded_dll() -> io::Result<PathBuf> {
    // %LOCALAPPDATA%\blp-thumb-win\blp_thumb_win.dll (fallback — next to exe)
    let base = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut p = env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
            p.pop();
            p
        });
    let dir = base.join("blp-thumb-win");
    fs::create_dir_all(&dir)?;
    let path = dir.join("blp_thumb_win.dll");
    fs::write(&path, DLL_BYTES)?;
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
/// We do *not* change icons/ownership of the file type.
/// We bind both under ProgID (if ext has one) and directly under the extension.
fn register_com(dll_path: &Path) -> io::Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    let clsid = clsid_str();
    let catid = shell_thumb_handler_catid_str();

    // HKCU\Software\Classes\CLSID\{CLSID}
    let (key_clsid, _) = hkcu.create_subkey(format!(r"Software\Classes\CLSID\{}", clsid))?;
    key_clsid.set_value("", &FRIENDLY_NAME)?;

    // HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32
    let (key_inproc, _) =
        hkcu.create_subkey(format!(r"Software\Classes\CLSID\{}\InprocServer32", clsid))?;
    key_inproc.set_value("", &dll_path.as_os_str())?;
    // Thumbnail providers are typically Apartment threaded
    key_inproc.set_value("ThreadingModel", &"Apartment")?;

    // Optional but harmless: mark as Approved (per-user)
    let (approved, _) =
        hkcu.create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved")?;
    approved.set_value(&clsid, &FRIENDLY_NAME)?;

    // Implemented Categories (Thumbnail Provider)
    let _ = hkcu.create_subkey(format!(
        r"Software\Classes\CLSID\{}\Implemented Categories\{}",
        clsid, catid
    ))?;

    // Bind under ProgID if present, otherwise under extension key.
    let ext = normalize_ext(DEFAULT_EXT);
    let progid_opt = current_progid_of_ext(&ext);

    if let Some(pid) = &progid_opt {
        let (key_shellex, _) = hkcu.create_subkey(format!(r"Software\Classes\{}\ShellEx", pid))?;
        let (key_thumb, _) = key_shellex.create_subkey(&catid)?;
        key_thumb.set_value("", &clsid)?;
    }

    // Always also bind under the extension itself (defensive)
    let (key_ext_shellex, _) = hkcu.create_subkey(format!(r"Software\Classes\{}\ShellEx", ext))?;
    let (key_ext_thumb, _) = key_ext_shellex.create_subkey(&catid)?;
    key_ext_thumb.set_value("", &clsid)?;

    Ok(())
}

fn unregister_com() -> io::Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let clsid = clsid_str();
    let catid = shell_thumb_handler_catid_str();
    let ext = normalize_ext(DEFAULT_EXT);
    let progid_opt = current_progid_of_ext(&ext);

    if let Some(pid) = &progid_opt {
        let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\{}\ShellEx\{}", pid, catid));
    }
    let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\{}\ShellEx\{}", ext, catid));
    let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\CLSID\{}", clsid));
    let _ = hkcu
        .open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
            KEY_SET_VALUE,
        )
        .and_then(|k| k.delete_value(clsid));
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

fn current_progid_of_ext(ext: &str) -> Option<String> {
    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
    hkcr.open_subkey(ext)
        .ok()
        .and_then(|k| k.get_value::<String, _>("").ok())
        .filter(|s| !s.trim().is_empty())
}

/* ---------- utils ---------- */

fn pause(msg: &str) {
    print!("{msg}");
    let _ = io::stdout().flush();
    let _ = io::stdin().read(&mut [0u8]).ok();
}

fn mark(b: bool) -> &'static str {
    if b { "OK" } else { "NO" }
}

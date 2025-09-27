use dialoguer::{Select, console::Term};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
    thread::sleep,
    time::Duration,
};
use winreg::{RegKey, enums::*};

// Вшитая DLL, ожидается в ./bin/blp_thumb_win.dll на момент компиляции инсталлера
static DLL_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/bin/blp_thumb_win.dll"
));

// Один источник правды из библиотеки
use blp_thumb_win::keys::{
    DEFAULT_EXT, DEFAULT_PROGID, FRIENDLY_NAME, clsid_str, shell_thumb_handler_catid_str,
};

fn main() -> io::Result<()> {
    loop {
        let items = &[
            "Install (HKCU)",
            "Uninstall (HKCU)",
            "Status",
            "Restart Explorer",
            "Clear thumbnail cache",
            "Exit",
        ];
        let sel = Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("BLP Thumbnail Provider installer")
            .items(items)
            .default(0)
            .interact_on_opt(&Term::stderr())
            .unwrap_or(None);

        match sel {
            Some(0) => action_install()?,
            Some(1) => action_uninstall()?,
            Some(2) => action_status()?,
            Some(3) => action_restart_explorer()?,
            Some(4) => action_clear_thumb_cache()?,
            _ => break,
        }

        pause("Press Enter to return to menu…");
    }
    Ok(())
}

fn action_install() -> io::Result<()> {
    let dll_path = materialize_embedded_dll()?;
    register_com(&dll_path)?;
    println!("✅ Installed under HKCU.\nTip: use 'Restart Explorer' to refresh thumbnails.");
    Ok(())
}

fn action_uninstall() -> io::Result<()> {
    unregister_com()?;
    println!("✅ Uninstalled from HKCU.");
    Ok(())
}

fn action_status() -> io::Result<()> {
    let (ok_clsid, ok_inproc, ok_bind) = probe_status()?;
    println!("Status:");
    println!("  CLSID present:      {}", mark(ok_clsid));
    println!("  InprocServer32:     {}", mark(ok_inproc));
    println!("  ShellEx Thumbnail:  {}", mark(ok_bind));
    Ok(())
}

fn action_restart_explorer() -> io::Result<()> {
    // Закрыть explorer
    let _ = Command::new("taskkill")
        .args(["/f", "/im", "explorer.exe"])
        .status();
    // Небольшая пауза — пусть освободит файлы/кеш
    sleep(Duration::from_millis(400));
    // Запустить explorer
    let _ = Command::new("explorer.exe").status();
    println!("🔄 Explorer restarted.");
    Ok(())
}

fn action_clear_thumb_cache() -> io::Result<()> {
    // Лучше делать на остановленном explorer (можно через пункт меню выше)
    let local = match env::var_os("LOCALAPPDATA") {
        Some(v) => PathBuf::from(v),
        None => {
            println!("⚠️ LOCALAPPDATA not set, skipping.");
            return Ok(());
        }
    };
    let dir = local.join(r"Microsoft\Windows\Explorer");
    if !dir.is_dir() {
        println!("ℹ️  No thumbnail cache dir: {}", dir.display());
        return Ok(());
    }

    let mut removed = 0usize;
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            // thumbcache_* (обычно *.db)
            if name.starts_with("thumbcache_") {
                let _ = fs::remove_file(&p);
                removed += 1;
            }
        }
    }
    println!("🧹 Removed {} cache files in {}", removed, dir.display());
    Ok(())
}

/// Сохраняем DLL рядом с профилем %LOCALAPPDATA%\blp-thumb-win\blp_thumb_win.dll
fn materialize_embedded_dll() -> io::Result<PathBuf> {
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

/// Регистрация: CLSID + Implemented Categories + ShellEx на ProgID (или .ext fallback)
fn register_com(dll_path: &Path) -> io::Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    let clsid = clsid_str(); // "{...}"
    let catid = shell_thumb_handler_catid_str(); // "{e357...}"

    // HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32
    let inproc_key = format!(r"Software\Classes\CLSID\{}\InprocServer32", clsid);
    let (key_inproc, _) = hkcu.create_subkey(inproc_key)?;
    key_inproc.set_value("", &dll_path.as_os_str())?;
    key_inproc.set_value("ThreadingModel", &"Both")?;

    // Friendly name
    let clsid_key = format!(r"Software\Classes\CLSID\{}", clsid);
    let (key_cls, _) = hkcu.create_subkey(clsid_key)?;
    key_cls.set_value("", &FRIENDLY_NAME)?;

    // Implemented Categories
    let implcat = format!(
        r"Software\Classes\CLSID\{}\Implemented Categories\{}",
        clsid, catid
    );
    let _ = hkcu.create_subkey(implcat)?;

    // Привязка только ThumbnailProvider, не трогая иконку/ассоциацию
    // Сначала пробуем повеситься на ProgID, иначе — на расширение
    let ext = normalize_ext(DEFAULT_EXT);
    let progid = current_progid_of_ext(&ext).unwrap_or_else(|| DEFAULT_PROGID.to_string());

    // HKCU\Software\Classes\<ProgID>\ShellEx\{catid} = {CLSID}
    let (key_shellex, _) = hkcu.create_subkey(format!(r"Software\Classes\{}\ShellEx", progid))?;
    let (key_thumb, _) = key_shellex.create_subkey(&catid)?;
    key_thumb.set_value("", &clsid)?;

    Ok(())
}

/// Дерегистрация: удаляем то, что создавали
fn unregister_com() -> io::Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    let clsid = clsid_str();
    let catid = shell_thumb_handler_catid_str();
    let ext = normalize_ext(DEFAULT_EXT);
    let progid_guess = current_progid_of_ext(&ext);

    // Удаляем привязку ShellEx либо с ProgID, либо с .ext
    if let Some(pid) = progid_guess {
        let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\{}\ShellEx\{}", pid, catid));
    } else {
        let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\{}\ShellEx\{}", ext, catid));
    }

    // Удаляем CLSID ветку
    let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\CLSID\{}", clsid));

    Ok(())
}

/// Проверка наличия ключей
fn probe_status() -> io::Result<(bool, bool, bool)> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    let clsid = clsid_str();
    let catid = shell_thumb_handler_catid_str();
    let ext = normalize_ext(DEFAULT_EXT);
    let progid_guess = current_progid_of_ext(&ext);

    // CLSID
    let ok_clsid = hkcu
        .open_subkey(format!(r"Software\Classes\CLSID\{}", clsid))
        .is_ok();
    // Inproc
    let ok_inproc = hkcu
        .open_subkey(format!(r"Software\Classes\CLSID\{}\InprocServer32", clsid))
        .is_ok();

    // ShellEx bind present?
    let ok_bind = if let Some(pid) = progid_guess {
        hkcu.open_subkey(format!(r"Software\Classes\{}\ShellEx\{}", pid, catid))
            .is_ok()
    } else {
        hkcu.open_subkey(format!(r"Software\Classes\{}\ShellEx\{}", ext, catid))
            .is_ok()
    };

    Ok((ok_clsid, ok_inproc, ok_bind))
}

/// Пытаемся прочитать текущий ProgID у расширения из HKCR
fn current_progid_of_ext(ext: &str) -> Option<String> {
    // читать из HKCR безопасно
    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
    hkcr.open_subkey(ext)
        .ok()
        .and_then(|k| k.get_value::<String, _>("").ok())
        .filter(|s| !s.trim().is_empty())
}

fn mark(b: bool) -> &'static str {
    if b { "✔" } else { "—" }
}

fn pause(msg: &str) {
    use std::io::Write;
    print!("{msg}");
    let _ = io::stdout().flush();
    let _ = io::stdin().read_line(&mut String::new());
}

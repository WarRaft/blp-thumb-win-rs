use std::{env, fs, io, path::PathBuf};
use winreg::{RegKey, enums::*};

// Та самая вшитая DLL:
static DLL_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/bin/blp_thumb_win.dll"
));

// Тянем «один источник правды» из либы
use blp_thumb_win::keys::{
    DEFAULT_EXT, DEFAULT_PROGID, FRIENDLY_NAME, clsid_str, shell_thumb_handler_catid_str,
};

fn main() -> io::Result<()> {
    // 1) Материализуем DLL из ресурсов EXE
    let dll_path = materialize_embedded_dll()?;

    // 2) Регистрируем в HKCU
    register_com(&dll_path)?;

    println!("OK. Registered under HKCU. Restart Explorer.exe to pick up thumbnails.");
    Ok(())
}

fn materialize_embedded_dll() -> io::Result<PathBuf> {
    // По-умолчанию кладём в %LOCALAPPDATA%\blp-thumb-win\
    let base = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // fallback: рядом с exe
            let mut p = env::current_exe().unwrap();
            p.pop();
            p
        });
    let dir = base.join("blp-thumb-win");
    fs::create_dir_all(&dir)?;
    let path = dir.join("blp_thumb_win.dll");
    fs::write(&path, DLL_BYTES)?;
    Ok(path)
}

fn register_com(dll_path: &PathBuf) -> io::Result<()> {
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

    // .blp -> ProgID
    let (key_ext, _) = hkcu.create_subkey(format!(r"Software\Classes\{}", DEFAULT_EXT))?;
    key_ext.set_value("", &DEFAULT_PROGID)?;

    // ProgID root
    let (key_progid, _) = hkcu.create_subkey(format!(r"Software\Classes\{}", DEFAULT_PROGID))?;
    key_progid.set_value("", &"BLP File")?;

    // ProgID\ShellEx\{ThumbnailProvider} = {CLSID}
    let (key_shellex, _) =
        hkcu.create_subkey(format!(r"Software\Classes\{}\ShellEx", DEFAULT_PROGID))?;
    let (key_thumb, _) = key_shellex.create_subkey(catid)?;
    key_thumb.set_value("", &clsid)?;

    Ok(())
}

use blp_thumb_win::keys::{
    DEFAULT_EXT, DEFAULT_PROGID, FRIENDLY_NAME, clsid_str, shell_thumb_handler_catid_str,
};
use std::env;
use std::path::PathBuf;
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

fn normalize_ext(ext: &str) -> String {
    let mut e = ext.trim().to_ascii_lowercase();
    if !e.starts_with('.') {
        e.insert(0, '.');
    }
    e
}
#[cfg(windows)]
fn main() -> std::io::Result<()> {
    // usage: blp-thumb-installer <path-to-dll>
    let dll_path: PathBuf = env::args()
        .nth(1)
        .map(PathBuf::from)
        .expect("Usage: blp-thumb-installer <path-to-dll>");

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    // ---- CLSID registration ----
    let clsid = clsid_str(); // "{...}"
    let inproc_key_path = format!(r"Software\Classes\CLSID\{}\InprocServer32", clsid);
    let (key_inproc, _) = hkcu.create_subkey(inproc_key_path)?;
    // (Default) = <dll_path>
    key_inproc.set_value("", &dll_path.as_os_str())?;
    // ThreadingModel = "Both"
    key_inproc.set_value("ThreadingModel", &"Both")?;

    // Friendly name under CLSID (ставим в (Default))
    let clsid_key_path = format!(r"Software\Classes\CLSID\{}", clsid);
    let (key_cls, _) = hkcu.create_subkey(clsid_key_path)?;
    key_cls.set_value("", &FRIENDLY_NAME)?;

    // Implemented Categories -> {ThumbnailProvider CatId}
    let catid = shell_thumb_handler_catid_str(); // "{e357fccd-...}"
    let implcat_key_path = format!(
        r"Software\Classes\CLSID\{}\Implemented Categories\{}",
        clsid, catid
    );
    let _ = hkcu.create_subkey(implcat_key_path)?;

    // ---- Extension & ProgID binding ----
    // .blp -> WarRaft.BLP
    let (key_ext, _) = hkcu.create_subkey(format!(r"Software\Classes\{}", DEFAULT_EXT))?;
    key_ext.set_value("", &DEFAULT_PROGID)?;

    // ProgID root (описание)
    let (key_progid, _) = hkcu.create_subkey(format!(r"Software\Classes\{}", DEFAULT_PROGID))?;
    key_progid.set_value("", &"BLP File")?;

    // ProgID\ShellEx\{ThumbnailProvider} = {CLSID}
    let (key_shellex, _) =
        hkcu.create_subkey(format!(r"Software\Classes\{}\ShellEx", DEFAULT_PROGID))?;
    let (key_thumb, _) = key_shellex.create_subkey(catid)?;
    key_thumb.set_value("", &clsid)?;

    println!("Registered under HKCU. Restart Explorer.exe to pick up thumbnails.");
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("⚠️ The installer can only be built and run on Windows 🪟");
}

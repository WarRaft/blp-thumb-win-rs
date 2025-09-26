use blp_thumb_win::keys::{CLSID_BLP_THUMB, THUMB_SHELLEX_CLSID};
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
    let dll_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .expect("Usage: blp-thumb-installer <path-to-dll>");

    // 1) HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let clsid_str = format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        CLSID_BLP_THUMB.data1,
        CLSID_BLP_THUMB.data2,
        CLSID_BLP_THUMB.data3,
        CLSID_BLP_THUMB.data4[0],
        CLSID_BLP_THUMB.data4[1],
        CLSID_BLP_THUMB.data4[2],
        CLSID_BLP_THUMB.data4[3],
        CLSID_BLP_THUMB.data4[4],
        CLSID_BLP_THUMB.data4[5],
        CLSID_BLP_THUMB.data4[6],
        CLSID_BLP_THUMB.data4[7]
    );

    let (key_inproc, _) = hkcu.create_subkey(format!(
        r"Software\Classes\CLSID\{}\InprocServer32",
        clsid_str
    ))?;
    key_inproc.set_value("", &dll_path.as_os_str())?;
    key_inproc.set_value("ThreadingModel", &"Both")?;

    // Friendly name (optional)
    let (key_cls, _) = hkcu.create_subkey(format!(r"Software\Classes\CLSID\{}", clsid_str))?;
    key_cls.set_value("FriendlyName", &"BLP Thumbnail Provider")?;

    // 2) Ассоциация расширения и слот ShellEx ThumbnailProvider
    let ext = normalize_ext("blp");
    let (key_ext, _) = hkcu.create_subkey(format!(r"Software\Classes\{}", ext))?;
    key_ext.set_value("", &"BLPFile")?;

    let (key_progid, _) = hkcu.create_subkey(r"Software\Classes\BLPFile")?;
    key_progid.set_value("", &"BLP File")?;

    let (key_shellex, _) = hkcu.create_subkey(r"Software\Classes\BLPFile\ShellEx")?;
    let (key_thumb, _) = key_shellex.create_subkey(THUMB_SHELLEX_CLSID)?;
    key_thumb.set_value("", &clsid_str)?;

    println!("Registered under HKCU. Restart Explorer.exe to pick up thumbnails.");
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("⚠️ The installer can only be built and run on Windows 🪟");
}

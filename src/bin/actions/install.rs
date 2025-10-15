use crate::DLL_BYTES;
use crate::utils::notify_shell_assoc::notify_shell_assoc;
use crate::utils::regedit::Rk;
use blp_thumb_win::log::log;
use blp_thumb_win::utils::guid::GuidExt;
use blp_thumb_win::{
    CLSID_BLP_THUMB, DEFAULT_EXT, DEFAULT_PROGID, FRIENDLY_NAME, SHELL_PREVIEW_HANDLER_CATID,
    SHELL_THUMB_HANDLER_CATID,
};
use std::path::PathBuf;
use std::{env, fs, io};
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
use winreg::RegKey;

const LEGACY_PREVIEW_CLSID: &str = "{8FC2C3AB-5B0B-4DB0-BC2E-9D6DBFBB8EAA}";

pub fn install() -> io::Result<()> {
    if let Err(err) = install_inner() {
        log(format!("Install failed: {err}"));
    }
    Ok(())
}

fn install_inner() -> io::Result<()> {
    log("Install (current user, thumbnail-only preview): start");

    // материализуем DLL
    let dll_path: PathBuf = {
        let base = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Users\Default\AppData\Local"));
        let dir = base.join("blp-thumb-win");
        fs::create_dir_all(&dir).map_err(|e| {
            log(format!("Failed to create dir {}: {e}", dir.display()));
            e
        })?;
        let path = dir.join("blp_thumb_win.dll");
        log(format!("Writing DLL {} ({} bytes)", path.display(), DLL_BYTES.len()));
        fs::write(&path, DLL_BYTES).map_err(|e| {
            log(format!("Failed to write DLL {}: {e}", path.display()));
            e
        })?;
        log("DLL materialized");
        path
    };

    let root = RegKey::predef(HKEY_CURRENT_USER);
    let ext = DEFAULT_EXT;
    let progid = DEFAULT_PROGID;

    let thumb_clsid = CLSID_BLP_THUMB.to_braced_upper();
    let thumb_catid = SHELL_THUMB_HANDLER_CATID.to_braced_upper();
    let preview_catid = SHELL_PREVIEW_HANDLER_CATID.to_braced_upper();

    log(format!(
        "Using CLSID THUMB={} CATs: THUMB={} PREVIEW={}",
        thumb_clsid, thumb_catid, preview_catid
    ));

    let del_tree = |path: &str| -> io::Result<()> {
        match root.delete_subkey_all(path) {
            Ok(()) => log(format!("Pre-clean: removed {}", path)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log(format!("Pre-clean: missing {}", path));
            }
            Err(e) => return Err(e),
        }
        Ok(())
    };
    let del_value = |key_path: &str, value_name: &str| -> io::Result<()> {
        match root.open_subkey_with_flags(key_path, KEY_READ | KEY_SET_VALUE) {
            Ok(key) => match key.delete_value(value_name) {
                Ok(()) => log(format!("Pre-clean: removed value {}\\{}", key_path, value_name)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    log(format!("Pre-clean: value missing {}\\{}", key_path, value_name));
                }
                Err(e) => return Err(e),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log(format!("Pre-clean: missing {}", key_path));
            }
            Err(e) => return Err(e),
        }
        Ok(())
    };

    log("Pre-clean: start");

    for path in [
        format!(r"Software\Classes\CLSID\{}", thumb_clsid),
        format!(r"Software\Classes\CLSID\{}", LEGACY_PREVIEW_CLSID),
        format!(
            r"Software\Classes\CLSID\{}\PersistentAddinsRegistered",
            LEGACY_PREVIEW_CLSID
        ),
        format!(r"Software\Classes\AppID\{}", LEGACY_PREVIEW_CLSID),
        "Software\\Classes\\AppID\\prevhost.exe".to_string(),
        format!(r"Software\Classes\{}\ShellEx\{}", ext, thumb_catid),
        format!(r"Software\Classes\{}\ShellEx\{}", ext, preview_catid),
        format!(r"Software\Classes\{}\ShellEx\{}", progid, thumb_catid),
        format!(r"Software\Classes\{}\ShellEx\{}", progid, preview_catid),
        format!(
            r"Software\Classes\SystemFileAssociations\{}\ShellEx\{}",
            ext, thumb_catid
        ),
        format!(
            r"Software\Classes\SystemFileAssociations\{}\ShellEx\{}",
            ext, preview_catid
        ),
        format!(r"Software\Classes\{}\PersistentHandler", ext),
    ] {
        let _ = del_tree(&path);
    }

    del_value(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers",
        ext,
    )?;
    del_value(
        r"Software\Microsoft\Windows\CurrentVersion\PreviewHandlers",
        LEGACY_PREVIEW_CLSID,
    )?;
    del_value(
        r"Software\Microsoft\Windows\CurrentVersion\PreviewHandlers",
        thumb_clsid.as_str(),
    )?;
    del_value(
        r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        thumb_clsid.as_str(),
    )?;
    del_value(
        r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        LEGACY_PREVIEW_CLSID,
    )?;

    log("Pre-clean: done");

    {
        log("Approving thumbnail handler");
        let approved =
            Rk::open(&root, r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved")?;
        approved.set(&thumb_clsid, FRIENDLY_NAME)?;
    }

    {
        log("Registering Thumbnail CLSID tree");
        let cls = Rk::open(&root, format!(r"Software\Classes\CLSID\{}", &thumb_clsid))?;
        cls.set_default(FRIENDLY_NAME)?;
        cls.set("DisableProcessIsolation", 1u32)?;
        let inproc = cls.sub("InprocServer32")?;
        inproc.set_default(dll_path.as_os_str())?;
        inproc.set("ThreadingModel", "Apartment")?;
        let _ = cls.sub(&format!(r"Implemented Categories\{}", thumb_catid))?;
    }

    {
        log("Writing .blp file-type metadata");
        let extk = Rk::open(&root, format!(r"Software\Classes\{}", ext))?;
        match extk.get::<String>("Content Type") {
            Ok(s) if !s.trim_matches(char::from(0)).is_empty() && s != "image/x-blp" => {
                log(format!("Skip Content Type override (current={s})"));
            }
            _ => {
                extk.set("Content Type", "image/x-blp")?;
            }
        }
        extk.set("PerceivedType", "image")?;
        extk.set_default(progid)?;
        let _ = root.delete_subkey_all(&format!(r"Software\Classes\{}\PersistentHandler", ext));
    }

    {
        log("Binding ProgID ShellEx handlers");
        let pid = Rk::open(&root, format!(r"Software\Classes\{}", progid))?;
        if pid
            .get::<String>("")
            .map(|s| s.trim_matches(char::from(0)).is_empty())
            .unwrap_or(true)
        {
            pid.set_default(FRIENDLY_NAME)?;
        }
        let shellex = pid.sub("ShellEx")?;
        shellex
            .sub(&thumb_catid)?
            .set_default(thumb_clsid.as_str())?;
        shellex
            .sub(&preview_catid)?
            .set_default(thumb_clsid.as_str())?;
    }

    {
        log("Binding ShellEx under .blp and SystemFileAssociations");
        let ext_sx = Rk::open(&root, format!(r"Software\Classes\{}\ShellEx", ext))?;
        ext_sx
            .sub(&thumb_catid)?
            .set_default(thumb_clsid.as_str())?;
        ext_sx
            .sub(&preview_catid)?
            .set_default(thumb_clsid.as_str())?;

        let sfa_sx =
            Rk::open(&root, format!(r"Software\Classes\SystemFileAssociations\{}\ShellEx", ext))?;
        sfa_sx
            .sub(&thumb_catid)?
            .set_default(thumb_clsid.as_str())?;
        sfa_sx
            .sub(&preview_catid)?
            .set_default(thumb_clsid.as_str())?;
    }

    {
        log("Updating Explorer handler lists");
        Rk::open(
            &root,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers",
        )?
        .set(ext, thumb_clsid.as_str())?;
        // Не регистрируем PreviewHandlers --- пусть Explorer использует миниатюру.
    }

    if let Ok((adv, _)) =
        root.create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")
    {
        log("Setting Explorer Advanced toggles for previews/thumbnails");
        let _ = adv.set_value("ShowPreviewHandlers", &1u32);
        let _ = adv.set_value("IconsOnly", &0u32);
        let _ = adv.set_value("DisableThumbnails", &0u32);
        let _ = adv.set_value("DisableThumbnailCache", &0u32);
        let _ = adv.set_value("DisableThumbnailsOnNetworkFolders", &0u32);
    }

    notify_shell_assoc("install");
    log("Installed in HKCU (thumbnail provider with preview redirect). Restart Explorer to refresh.");
    Ok(())
}

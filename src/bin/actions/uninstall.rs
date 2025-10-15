use crate::utils::notify_shell_assoc::notify_shell_assoc;

use blp_thumb_win::log::log;
use blp_thumb_win::utils::guid::GuidExt;
use blp_thumb_win::{
    CLSID_BLP_THUMB, DEFAULT_EXT, DEFAULT_PROGID, SHELL_PREVIEW_HANDLER_CATID, SHELL_THUMB_HANDLER_CATID,
};
use std::io;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
use winreg::RegKey;

const LEGACY_PREVIEW_CLSID: &str = "{8FC2C3AB-5B0B-4DB0-BC2E-9D6DBFBB8EAA}";

pub fn uninstall() -> io::Result<()> {
    if let Err(err) = uninstall_inner() {
        log(format!("Uninstall failed: {}", err));
    }
    Ok(())
}

fn uninstall_inner() -> io::Result<()> {
    log("Uninstall (current user): start — removing shell bindings.");

    let root = RegKey::predef(HKEY_CURRENT_USER);
    let ext = DEFAULT_EXT;
    let progid = DEFAULT_PROGID;

    let thumb_clsid = CLSID_BLP_THUMB.to_braced_upper();
    let thumb_catid = SHELL_THUMB_HANDLER_CATID.to_braced_upper();
    let preview_catid = SHELL_PREVIEW_HANDLER_CATID.to_braced_upper();

    let del_tree = |path: &str| -> io::Result<()> {
        match root.delete_subkey_all(path) {
            Ok(()) => log(format!("Removed key tree: {}", path)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log(format!("Key missing (skip): {}", path));
            }
            Err(e) => return Err(e),
        }
        Ok(())
    };

    let del_value = |key_path: &str, value_name: &str| -> io::Result<()> {
        match root.open_subkey_with_flags(key_path, KEY_READ | KEY_SET_VALUE) {
            Ok(key) => match key.delete_value(value_name) {
                Ok(()) => log(format!("Removed value: {} \\ {}", key_path, value_name)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    log(format!("Value missing (skip): {} \\ {}", key_path, value_name));
                }
                Err(e) => return Err(e),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log(format!("Key missing (skip): {}", key_path));
            }
            Err(e) => return Err(e),
        }
        Ok(())
    };

    let remove_shellex = |root_path: &str, cat: &str| -> io::Result<()> {
        let target = format!(r"{}\ShellEx\{}", root_path, cat);
        del_tree(&target)
    };

    // Shell Extensions Approved entries
    let approved_path = r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved";
    del_value(approved_path, thumb_clsid.as_str())?;
    del_value(approved_path, LEGACY_PREVIEW_CLSID)?;

    // ShellEx bindings (.blp / ProgID / SFA)
    remove_shellex(&format!(r"Software\Classes\{}", ext), &thumb_catid)?;
    remove_shellex(&format!(r"Software\Classes\{}", ext), &preview_catid)?;
    remove_shellex(&format!(r"Software\Classes\{}", progid), &thumb_catid)?;
    remove_shellex(&format!(r"Software\Classes\{}", progid), &preview_catid)?;
    remove_shellex(
        &format!(r"Software\Classes\SystemFileAssociations\{}", ext),
        &thumb_catid,
    )?;
    remove_shellex(
        &format!(r"Software\Classes\SystemFileAssociations\{}", ext),
        &preview_catid,
    )?;

    // Explorer handler lists
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

    // CLSID trees (.thumb and legacy preview)
    del_tree(&format!(r"Software\Classes\CLSID\{}", thumb_clsid))?;
    del_tree(&format!(r"Software\Classes\CLSID\{}", LEGACY_PREVIEW_CLSID))?;

    // Legacy AppID remnants
    del_tree(&format!(r"Software\Classes\AppID\{}", LEGACY_PREVIEW_CLSID))?;
    del_tree(r"Software\Classes\AppID\prevhost.exe")?;

    // File-type persistent handler glue
    del_tree(&format!(r"Software\Classes\{}\PersistentHandler", ext))?;

    notify_shell_assoc("uninstall");
    log("Uninstall completed (HKCU). Thumbnail preview bindings removed.");
    Ok(())
}

use crate::utils::notify_shell_assoc::notify_shell_assoc;

use blp_thumb_win::log::log_ui;
use blp_thumb_win::utils::guid::GuidExt;
use blp_thumb_win::{
    CLSID_BLP_PREVIEW, CLSID_BLP_THUMB, DEFAULT_EXT, DEFAULT_PROGID, SHELL_PREVIEW_HANDLER_CATID,
    SHELL_THUMB_HANDLER_CATID,
};
use std::io;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};

/** ============================================================================
Per-user uninstall of BLP thumbnail/preview handlers (HKCU only).

Removes only activation/registration points that can load our DLL:

1) CLSID registrations:
   - HKCU\Software\Classes\CLSID\{CLSID_BLP_THUMB}
   - HKCU\Software\Classes\CLSID\{CLSID_BLP_PREVIEW}

2) Explorer “Approved” list values for our CLSIDs.

3) ShellEx bindings (only if they point to our CLSIDs):
   - HKCU\Software\Classes\.blp\ShellEx\{ThumbCat} / {PreviewCat}
   - HKCU\Software\Classes\SystemFileAssociations\.blp\ShellEx\{...}
   - HKCU\Software\Classes\WarRaft.BLP\ShellEx\{...}

4) Explorer handler lists:
   - HKCU\...\Explorer\ThumbnailHandlers → delete value ".blp" if it equals our CLSID
   - HKCU\...\Explorer\PreviewHandlers   → delete value named {CLSID_BLP_PREVIEW}

5) Persistent handler glue we added to force preview through us:
   - HKCU\Software\Classes\.blp\PersistentHandler  (only if Default == {CLSID_BLP_PREVIEW})
   - HKCU\Software\Classes\CLSID\{CLSID_BLP_PREVIEW}\PersistentAddinsRegistered\{PreviewCat}

Intentionally left intact (to avoid breaking associations):
- HKCU\Software\Classes\.blp (Default/Content Type/PerceivedType)
- HKCU\Software\Classes\WarRaft.BLP (root, except ShellEx bindings)
- OpenWith* /UserChoice/Applications

Missing keys are treated as already-clean; all ops are per-user (HKCU).
============================================================================ */

pub fn uninstall() -> io::Result<()> {
    if let Err(err) = uninstall_inner() {
        log_ui(format!("Uninstall failed: {}", err));
    }
    Ok(())
}

fn uninstall_inner() -> io::Result<()> {
    log_ui("Uninstall (current user): start — removing activation points.");

    let root = RegKey::predef(HKEY_CURRENT_USER);

    let ext = DEFAULT_EXT; // ".blp"
    let progid = DEFAULT_PROGID;

    let thumb_clsid = CLSID_BLP_THUMB.to_braced_upper();
    let preview_clsid = CLSID_BLP_PREVIEW.to_braced_upper();
    let thumb_catid = SHELL_THUMB_HANDLER_CATID.to_braced_upper();
    let preview_catid = SHELL_PREVIEW_HANDLER_CATID.to_braced_upper();

    // Helpers
    let del_tree = |path: &str| -> io::Result<()> {
        match root.delete_subkey_all(path) {
            Ok(()) => log_ui(format!("Removed key tree: {}", path)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log_ui(format!("Key missing (skip): {}", path))
            }
            Err(e) => return Err(e),
        }
        Ok(())
    };

    let del_value = |key_path: &str, value_name: &str| -> io::Result<()> {
        match root.open_subkey_with_flags(key_path, KEY_READ | KEY_SET_VALUE) {
            Ok(key) => match key.delete_value(value_name) {
                Ok(()) => log_ui(format!("Removed value: {} \\ {}", key_path, value_name)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => log_ui(format!(
                    "Value missing (skip): {} \\ {}",
                    key_path, value_name
                )),
                Err(e) => return Err(e),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log_ui(format!("Key missing (skip): {}", key_path))
            }
            Err(e) => return Err(e),
        }
        Ok(())
    };

    let del_sub_if_default_eq = |subkey_path: &str, expect: &str| -> io::Result<()> {
        match root.open_subkey(subkey_path) {
            Ok(k) => {
                let cur: Result<String, _> = k.get_value("");
                if let Ok(mut v) = cur {
                    v = v.trim_matches(char::from(0)).trim().to_string();
                    if v.eq_ignore_ascii_case(expect) {
                        del_tree(subkey_path)?;
                    } else {
                        log_ui(format!(
                            "Preserving {} (Default != ours): '{}'",
                            subkey_path, v
                        ));
                    }
                } else {
                    // no default → safe to remove empty node
                    del_tree(subkey_path)?;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log_ui(format!("Missing (skip): {}", subkey_path))
            }
            Err(e) => return Err(e),
        }
        Ok(())
    };

    let del_shellex_if_matches = |base: &str, catid: &str, clsid: &str| -> io::Result<()> {
        let cat_path = format!(r"{}\ShellEx\{}", base, catid);
        del_sub_if_default_eq(&cat_path, clsid)
    };

    // 1) Explorer “Approved”
    {
        let approved = r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved";
        del_value(approved, thumb_clsid.as_str())?;
        del_value(approved, preview_clsid.as_str())?;
    }

    // 2) ShellEx bindings (.blp / SFA\.blp / ProgID)
    del_shellex_if_matches(
        &format!(r"Software\Classes\{}", ext),
        &thumb_catid,
        &thumb_clsid,
    )?;
    del_shellex_if_matches(
        &format!(r"Software\Classes\{}", ext),
        &preview_catid,
        &preview_clsid,
    )?;

    del_shellex_if_matches(
        &format!(r"Software\Classes\SystemFileAssociations\{}", ext),
        &thumb_catid,
        &thumb_clsid,
    )?;
    del_shellex_if_matches(
        &format!(r"Software\Classes\SystemFileAssociations\{}", ext),
        &preview_catid,
        &preview_clsid,
    )?;

    del_shellex_if_matches(
        &format!(r"Software\Classes\{}", progid),
        &thumb_catid,
        &thumb_clsid,
    )?;
    del_shellex_if_matches(
        &format!(r"Software\Classes\{}", progid),
        &preview_catid,
        &preview_clsid,
    )?;

    // 3) Explorer handler lists
    {
        // ThumbnailHandlers: remove ".blp" mapping if equals ours
        let th_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers";
        match root.open_subkey_with_flags(th_path, KEY_READ | KEY_SET_VALUE) {
            Ok(key) => match key.get_value::<String, _>(ext) {
                Ok(mut cur) => {
                    cur = cur.trim_matches(char::from(0)).trim().to_string();
                    if cur.eq_ignore_ascii_case(thumb_clsid.as_str()) {
                        key.delete_value(ext)?;
                        log_ui(format!(
                            "Removed ThumbnailHandlers mapping: {} -> {}",
                            ext, thumb_clsid
                        ));
                    } else {
                        log_ui(format!(
                            "Preserving ThumbnailHandlers mapping ({} -> {}), not ours",
                            ext, cur
                        ));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    log_ui("ThumbnailHandlers mapping missing (skip)")
                }
                Err(e) => return Err(e),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log_ui("ThumbnailHandlers key missing (skip)")
            }
            Err(e) => return Err(e),
        }

        // PreviewHandlers: delete value named with our preview CLSID
        let ph_path = r"Software\Microsoft\Windows\CurrentVersion\PreviewHandlers";
        del_value(ph_path, preview_clsid.as_str())?;
    }

    // 4) Persistent handler glue
    {
        // .blp\PersistentHandler (only if Default matches our preview CLSID)
        let ph_ext_path = format!(r"Software\Classes{}\PersistentHandler", ext);
        // careful: ensure backslash between Classes and ext
        let ph_ext_path = ph_ext_path.replace("Classes.", "Classes\\.");
        del_sub_if_default_eq(&ph_ext_path, preview_clsid.as_str())?;

        // CLSID\{PREVIEW}\PersistentAddinsRegistered\{PreviewCat}
        let par_cat = format!(
            r"Software\Classes\CLSID\{}\PersistentAddinsRegistered\{}",
            preview_clsid, preview_catid
        );
        del_tree(&par_cat)?;
        // If PersistentAddinsRegistered is now empty, remove the parent as well (best-effort).
        let par_root = format!(
            r"Software\Classes\CLSID\{}\PersistentAddinsRegistered",
            preview_clsid
        );
        let _ = del_tree(&par_root);
    }

    // 5) CLSID trees
    del_tree(&format!(r"Software\Classes\CLSID\{}", thumb_clsid))?;
    del_tree(&format!(r"Software\Classes\CLSID\{}", preview_clsid))?;

    // 6) Notify shell
    notify_shell_assoc("uninstall");

    log_ui("Uninstall completed (HKCU). DLL activation points removed; associations left intact.");
    Ok(())
}

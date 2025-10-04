use crate::utils::notify_shell_assoc::notify_shell_assoc;
use crate::{
    open_with_list_entries, open_with_progids_entries, remove_application_binding,
    remove_prog_id_application, user_choice_prog_id,
};
use blp_thumb_win::keys::{
    DEFAULT_EXT, DEFAULT_PROGID, clsid_str, preview_clsid_str, shell_preview_handler_catid_str,
    shell_thumb_handler_catid_str,
};
use blp_thumb_win::log::log_cli;
use std::io;
use winreg::RegKey;
use winreg::enums::{HKEY_CLASSES_ROOT, KEY_SET_VALUE};

pub fn uninstall() -> io::Result<()> {
    log_cli("Uninstall (all users): start");
    unregister_com_scope()?;
    notify_shell_assoc("uninstall-all");
    println!("Uninstalled from HKLM and HKCU.");
    Ok(())
}

fn unregister_com_scope() -> io::Result<()> {
    log_cli("Unregister start");
    let root = RegKey::predef(HKEY_CLASSES_ROOT);
    let thumb_clsid = clsid_str();
    let thumb_catid = shell_thumb_handler_catid_str();
    let preview_clsid = preview_clsid_str();
    let preview_catid = shell_preview_handler_catid_str();
    let ext = DEFAULT_EXT;

    let classes = [
        (&thumb_clsid, &thumb_catid),
        (&preview_clsid, &preview_catid),
    ];

    if let Some(pid) = current_progid_of_ext(&ext) {
        log_cli(format!("Unregister COM: removing ProgID binding {}", pid));
        for (_, catid) in &classes {
            let _ = root.delete_subkey_all(format!(r"Software\Classes\{}\ShellEx\{}", pid, catid));
        }
    }

    log_cli(format!(
        "Unregister COM: removing extension binding {}",
        ext
    ));
    for (_, catid) in &classes {
        let _ = root.delete_subkey_all(format!(r"Software\Classes\{}\ShellEx\{}", ext, catid));
    }
    log_cli(format!(
        "Unregister COM: removing SystemFileAssociations binding {}",
        ext
    ));
    for (_, catid) in &classes {
        let _ = root.delete_subkey_all(format!(
            r"Software\Classes\SystemFileAssociations\{}\ShellEx\{}",
            ext, catid
        ));
    }

    if let Ok(thumb_handlers) = root.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers",
        KEY_SET_VALUE,
    ) {
        let _ = thumb_handlers.delete_value(&ext);
    }
    if let Ok(preview_handlers) = root.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\PreviewHandlers",
        KEY_SET_VALUE,
    ) {
        let _ = preview_handlers.delete_value(&preview_clsid);
    }

    if let Ok(ext_key) =
        root.open_subkey_with_flags(format!(r"Software\Classes\{}", ext), KEY_SET_VALUE)
    {
        let _ = ext_key.delete_value("Content Type");
        let _ = ext_key.delete_value("PerceivedType");
    }

    for entry in open_with_list_entries(&root, &ext) {
        for (_, catid) in &classes {
            remove_application_binding(&root, &entry, catid);
        }
    }

    for progid in open_with_progids_entries(&root, &ext) {
        for (_, catid) in &classes {
            remove_prog_id_application(&root, &progid, catid);
        }
    }

    if let Some(prog_id) = user_choice_prog_id(&root, &ext) {
        if let Some(app) = prog_id.strip_prefix(r"Applications\") {
            for (_, catid) in &classes {
                remove_application_binding(&root, app, catid);
            }
        } else {
            for (_, catid) in &classes {
                remove_prog_id_application(&root, &prog_id, catid);
            }
        }
    }
    log_cli("Unregister COM: removing CLSID keys".to_string());
    for (clsid, _) in &classes {
        let _ = root.delete_subkey_all(format!(r"Software\Classes\CLSID\{}", clsid));
    }

    log_cli("Unregister COM: removing extension and ProgID keys".to_string());
    let _ = root.delete_subkey_all(format!(r"Software\Classes\{}", DEFAULT_PROGID));
    let _ = root.delete_subkey_all(format!(r"Software\Classes\{}", ext));

    log_cli(r"Unregister COM: removing Shell Extensions\Approved entries".to_string());
    let _ = root
        .open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
            KEY_SET_VALUE,
        )
        .and_then(|k| {
            for (clsid, _) in &classes {
                let _ = k.delete_value(clsid);
            }
            Ok(k)
        });
    log_cli("Unregister COM: completed".to_string());
    Ok(())
}

fn current_progid_of_ext(ext: &str) -> Option<String> {
    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
    hkcr.open_subkey(ext)
        .ok()
        .and_then(|k| k.get_value::<String, _>("").ok())
        .filter(|s| !s.trim().is_empty())
}

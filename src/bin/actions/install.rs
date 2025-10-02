use crate::{
    DLL_BYTES, RegistryScope, bind_application, bind_prog_id_application,
    clear_shell_ext_cache_scope, enforce_thumbnail_settings_scope, normalize_ext,
    notify_shell_assoc, open_with_list_entries, open_with_progids_entries, user_choice_prog_id,
};
use blp_thumb_win::keys::{
    FRIENDLY_NAME, clsid_str, preview_clsid_str, shell_preview_handler_catid_str,
    shell_thumb_handler_catid_str,
};
use blp_thumb_win::log::log_cli;
use std::path::{Path, PathBuf};
use std::{env, fs, io};

const DEFAULT_EXT: &str = "blp";
const DEFAULT_PROGID: &str = "BlpThumbnailHandler";
const PREVIEW_FRIENDLY_NAME: &str = "BLP Thumbnail Preview Handler";

pub fn install() -> io::Result<()> {
    log_cli("Install (all users): start");
    let dll_path = materialize_embedded_dll()?;
    log_cli(format!(
        "Install (all users): DLL materialized to {}",
        dll_path.display()
    ));
    let mut warnings = Vec::new();
    if let Err(err) = register_com_scope(RegistryScope::LocalMachine, &dll_path) {
        warnings.push(format!("HKLM registration failed: {}", err));
    }
    if let Err(err) = register_com_scope(RegistryScope::CurrentUser, &dll_path) {
        warnings.push(format!("HKCU registration failed: {}", err));
    }

    // Register the preview handler explicitly
    if let Err(err) = register_preview_handler(RegistryScope::LocalMachine, &dll_path) {
        warnings.push(format!("HKLM preview handler registration failed: {}", err));
    }
    if let Err(err) = register_preview_handler(RegistryScope::CurrentUser, &dll_path) {
        warnings.push(format!("HKCU preview handler registration failed: {}", err));
    }

    if warnings.is_empty() {
        log_cli("Install (all users): registry entries written");
    } else {
        for warn in &warnings {
            log_cli(format!("Install warning: {}", warn));
        }
    }

    let thumb_clsid = clsid_str();
    let preview_clsid = preview_clsid_str();
    for scope in [RegistryScope::LocalMachine, RegistryScope::CurrentUser] {
        for clsid in [&thumb_clsid, &preview_clsid] {
            if let Err(err) = clear_shell_ext_cache_scope(scope, clsid) {
                warnings.push(format!("{} cache clear failed: {}", scope.name(), err));
            }
        }
        if let Err(err) = enforce_thumbnail_settings_scope(scope) {
            warnings.push(format!(
                "{} thumbnail settings failed: {}",
                scope.name(),
                err
            ));
        }
    }

    notify_shell_assoc("install-all");

    if warnings.is_empty() {
        println!("Installed in HKLM and HKCU. Use 'Restart Explorer' to refresh thumbnails.");
    } else {
        println!("Install completed with warnings:");
        for warn in warnings {
            println!("  - {}", warn);
        }
    }
    Ok(())
}

fn materialize_embedded_dll() -> io::Result<PathBuf> {
    let base = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\\Users\\Default\\AppData\\Local"));

    log_cli(format!(
        "Materialize DLL: base directory {}",
        base.display()
    ));

    let dir = base.join("blp-thumb-win");
    log_cli(format!(
        "Materialize DLL: ensuring directory {}",
        dir.display()
    ));

    fs::create_dir_all(&dir).map_err(|e| {
        log_cli(format!("❌ Failed to create dir {}: {}", dir.display(), e));
        e
    })?;

    let path = dir.join("blp_thumb_win.dll");
    log_cli(format!(
        "Materialize DLL: writing {} ({} bytes)",
        path.display(),
        DLL_BYTES.len()
    ));

    fs::write(&path, DLL_BYTES).map_err(|e| {
        log_cli(format!("❌ Failed to write DLL {}: {}", path.display(), e));
        e
    })?;

    log_cli("Materialize DLL: completed");
    Ok(path)
}

/// Ensure the preview handler CLSID is properly registered under HKCU and HKLM.
/// This includes binding it to the .blp extension and ProgID.
fn register_preview_handler(scope: RegistryScope, dll_path: &Path) -> io::Result<()> {
    let scope_name = scope.name();
    log_cli(format!(
        "Register Preview Handler [{}]: start (dll={})",
        scope_name,
        dll_path.display()
    ));

    let root = scope.root();
    let preview_clsid = preview_clsid_str();
    let preview_catid = shell_preview_handler_catid_str();
    let ext = normalize_ext(DEFAULT_EXT);

    // Register CLSID for the preview handler
    let (key_clsid, _) =
        root.create_subkey(format!(r"Software\Classes\CLSID\{}", preview_clsid))?;
    key_clsid.set_value("", &PREVIEW_FRIENDLY_NAME)?;
    key_clsid.set_value("DisableProcessIsolation", &1u32)?;

    let (key_inproc, _) = root.create_subkey(format!(
        r"Software\Classes\CLSID\{}\InprocServer32",
        preview_clsid
    ))?;
    key_inproc.set_value("", &dll_path.as_os_str())?;
    key_inproc.set_value("ThreadingModel", &"Apartment")?;

    // Bind CLSID to the .blp extension
    let (key_ext_shellex, _) = root.create_subkey(format!(r"Software\Classes\{}\ShellEx", ext))?;
    let (key_ext_entry, _) = key_ext_shellex.create_subkey(&preview_catid)?;
    key_ext_entry.set_value("", &preview_clsid)?;

    // Bind CLSID to the ProgID
    let (progid_key, _) = root.create_subkey(format!(r"Software\Classes\{}", DEFAULT_PROGID))?;
    let (pid_shellex, _) = progid_key.create_subkey("ShellEx")?;
    let (pid_entry, _) = pid_shellex.create_subkey(&preview_catid)?;
    pid_entry.set_value("", &preview_clsid)?;

    log_cli(format!(
        "Register Preview Handler [{}]: completed",
        scope_name
    ));
    Ok(())
}

/// Register CLSID + Inproc + ShellEx mapping under HKCU.
/// We do not change icons or file type ownership.
/// We bind under ProgID (if present) and under the extension itself.
fn register_com_scope(scope: RegistryScope, dll_path: &Path) -> io::Result<()> {
    let scope_name = scope.name();
    log_cli(format!(
        "Register COM [{}]: start (dll={})",
        scope_name,
        dll_path.display()
    ));

    let root = scope.root();
    let thumb_clsid = clsid_str();
    let thumb_catid = shell_thumb_handler_catid_str();
    let preview_clsid = preview_clsid_str();
    let preview_catid = shell_preview_handler_catid_str();
    let ext = normalize_ext(blp_thumb_win::keys::DEFAULT_EXT);

    let classes = [
        (FRIENDLY_NAME, &thumb_clsid, &thumb_catid),
        (
            blp_thumb_win::keys::PREVIEW_FRIENDLY_NAME,
            &preview_clsid,
            &preview_catid,
        ),
    ];

    let (approved, _) =
        root.create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved")?;

    for (friendly, clsid, catid) in &classes {
        log_cli(format!(
            "Register COM [{}]: configuring CLSID {}",
            scope_name, clsid
        ));
        let (key_clsid, _) = root.create_subkey(format!(r"Software\Classes\CLSID\{}", clsid))?;
        key_clsid.set_value("", friendly)?;
        key_clsid.set_value("DisableProcessIsolation", &1u32)?;

        let (key_inproc, _) =
            root.create_subkey(format!(r"Software\Classes\CLSID\{}\InprocServer32", clsid))?;
        key_inproc.set_value("", &dll_path.as_os_str())?;
        key_inproc.set_value("ThreadingModel", &"Apartment")?;

        approved.set_value(clsid, friendly)?;

        let _ = root.create_subkey(format!(
            r"Software\Classes\CLSID\{}\Implemented Categories\{}",
            clsid, catid
        ))?;
    }

    log_cli(format!(
        "Register COM [{}]: ensuring extension metadata",
        scope_name
    ));
    let (ext_key, _) = root.create_subkey(format!(r"Software\Classes\{}", ext))?;
    match ext_key.get_value::<String, _>("Content Type") {
        Ok(existing)
            if !existing.trim_matches(char::from(0)).is_empty() && existing != "image/x-blp" =>
        {
            log_cli(format!(
                "Register COM [{}]: skipping Content Type override (current={})",
                scope_name, existing
            ));
        }
        _ => {
            ext_key.set_value("Content Type", &"image/x-blp")?;
        }
    }
    ext_key.set_value("PerceivedType", &"image")?;

    match ext_key.get_value::<String, _>("") {
        Ok(existing) if !existing.trim_matches(char::from(0)).is_empty() => {
            log_cli(format!(
                "Register COM [{}]: extension default already set to {}",
                scope_name, existing
            ));
        }
        _ => {
            log_cli(format!(
                "Register COM [{}]: setting extension default to WarRaft.BLP",
                scope_name
            ));
            ext_key.set_value("", &blp_thumb_win::keys::DEFAULT_PROGID)?;
        }
    }

    log_cli(format!(
        "Register COM [{}]: ensuring ProgID key {}",
        scope_name,
        blp_thumb_win::keys::DEFAULT_PROGID
    ));
    let (progid_key, _) = root.create_subkey(format!(
        r"Software\Classes\{}",
        blp_thumb_win::keys::DEFAULT_PROGID
    ))?;
    if progid_key
        .get_value::<String, _>("")
        .map(|s| s.trim_matches(char::from(0)).is_empty())
        .unwrap_or(true)
    {
        progid_key.set_value("", &FRIENDLY_NAME)?;
    }
    let (pid_shellex, _) = progid_key.create_subkey("ShellEx")?;
    for (_, clsid, catid) in &classes {
        let (pid_entry, _) = pid_shellex.create_subkey(catid)?;
        pid_entry.set_value("", &clsid.as_str())?;
    }

    log_cli(format!(
        "Register COM [{}]: binding under extension {}",
        scope_name, ext
    ));
    let (key_ext_shellex, _) = root.create_subkey(format!(r"Software\Classes\{}\ShellEx", ext))?;
    for (_, clsid, catid) in &classes {
        let (key_ext_entry, _) = key_ext_shellex.create_subkey(catid)?;
        key_ext_entry.set_value("", &clsid.as_str())?;
    }

    log_cli(format!(
        "Register COM [{}]: binding under SystemFileAssociations {}",
        scope_name, ext
    ));
    let (key_sys_shellex, _) = root.create_subkey(format!(
        r"Software\Classes\SystemFileAssociations\{}\ShellEx",
        ext
    ))?;
    for (_, clsid, catid) in &classes {
        let (key_sys_entry, _) = key_sys_shellex.create_subkey(catid)?;
        key_sys_entry.set_value("", &clsid.as_str())?;
    }

    log_cli(format!(
        "Register COM [{}]: binding Explorer handlers",
        scope_name
    ));
    let (thumb_handlers, _) = root
        .create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers")?;
    thumb_handlers.set_value(&ext, &thumb_clsid)?;
    let (preview_handlers, _) =
        root.create_subkey(r"Software\Microsoft\Windows\CurrentVersion\PreviewHandlers")?;
    preview_handlers.set_value(&preview_clsid, &blp_thumb_win::keys::PREVIEW_FRIENDLY_NAME)?;

    if scope.is_user() {
        for entry in open_with_list_entries(&root, &ext) {
            for (_, clsid, catid) in &classes {
                bind_application(&root, &entry, catid, clsid)?;
            }
        }

        for progid in open_with_progids_entries(&root, &ext) {
            for (_, clsid, catid) in &classes {
                bind_prog_id_application(&root, &progid, catid, clsid)?;
            }
        }

        if let Some(prog_id) = user_choice_prog_id(&root, &ext) {
            if let Some(app) = prog_id.strip_prefix(r"Applications\") {
                for (_, clsid, catid) in &classes {
                    bind_application(&root, app, catid, clsid)?;
                }
            } else {
                for (_, clsid, catid) in &classes {
                    bind_prog_id_application(&root, &prog_id, catid, clsid)?;
                }
            }
        }
    }

    log_cli(format!("Register COM [{}]: completed", scope_name));

    Ok(())
}

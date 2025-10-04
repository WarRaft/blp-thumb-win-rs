use crate::utils::notify_shell_assoc::notify_shell_assoc;
use crate::{
    DLL_BYTES, RegistryScope, open_with_list_entries, open_with_progids_entries,
    user_choice_prog_id,
};
use blp_thumb_win::keys::{
    DEFAULT_EXT, FRIENDLY_NAME, clsid_str, preview_clsid_str, shell_preview_handler_catid_str,
    shell_thumb_handler_catid_str,
};
use blp_thumb_win::log::{log_cli, log_ui};
use std::path::{Path, PathBuf};
use std::{env, fs, io};
use winreg::RegKey;
use winreg::enums::{KEY_READ, KEY_SET_VALUE};
// Use registry helper from utils
use crate::utils::regedit::{create_subkey, set_reg_value};

pub fn install() -> io::Result<()> {
    if let Err(err) = install_inner() {
        log_ui(format!("Install failed: {}", err));
    }
    Ok(())
}

fn install_inner() -> io::Result<()> {
    use std::path::PathBuf;
    use std::{env, fs};

    log_cli("Install (all users): start");

    // === inlined materialize_embedded_dll ===================================
    let dll_path: PathBuf = {
        let base = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Users\Default\AppData\Local"));

        let dir = base.join("blp-thumb-win");
        fs::create_dir_all(&dir).map_err(|e| {
            log_ui(format!("Failed to create dir {}: {}", dir.display(), e));
            e
        })?;

        let path = dir.join("blp_thumb_win.dll");
        log_ui(format!(
            "Writing DLL {} ({} bytes)",
            path.display(),
            DLL_BYTES.len()
        ));

        fs::write(&path, DLL_BYTES).map_err(|e| {
            log_ui(format!("Failed to write DLL {}: {}", path.display(), e));
            e
        })?;

        log_ui("DLL materialized");
        path
    };

    // ========================================================================

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

/// Register COM classes and shell bindings for this provider.
///
/// This function performs all registry writes needed for both the thumbnail
/// handler and the preview handler. It follows the steps from the Microsoft
/// documentation (links below) and intentionally writes to either HKLM or HKCU
/// depending on `scope`.
///
/// Docs:
/// - Thumbnail handlers: https://learn.microsoft.com/en-us/windows/win32/shell/thumbnail-providers
/// - Preview handlers: https://learn.microsoft.com/ru-ru/windows/win32/shell/preview-handlers
///
/// Registry layout (ASCII tree):
///
/// HKLM / HKCU
/// └─ Software
///    └─ Classes
///       ├─ .blp
///       │  (Default) = WarRaft.BLP                ; file extension -> ProgID
///       │  Content Type = image/x-blp
///       │  PerceivedType = image
///       ├─ WarRaft.BLP                            ; ProgID
///       │  (Default) = BLP Thumbnail Provider
///       │  ShellEx
///       │  └─ {8895B1C6-B41F-4C1C-A562-0D564250836F} = {CLSID_BLP_PREVIEW}
///       │  ThumbnailCutoff, TypeOverlay, etc. (optional)
///       └─ CLSID
///          ├─ {CLSID_BLP_THUMB}
///          │  (Default) = BLP Thumbnail Provider
///          │  DisableProcessIsolation = 1
///          │  InprocServer32
///          │  └─ (Default) = %LOCALAPPDATA%\blp-thumb-win\blp_thumb_win.dll
///          │     ThreadingModel = Apartment
///          │     ProgID = WarRaft.BLP
///          │  Implemented Categories
///          │  └─ {E357FCCD-A995-4576-B01F-234630154E96}
///          └─ {CLSID_BLP_PREVIEW}
///             (Default) = BLP Preview Handler
///             DisplayName = @blp_thumb_win.dll,-101    ; optional but helpful
///             AppID = {534A1E02-D58F-44f0-B58B-36CBED287C7C} ; enables prevhost usage
///             DisableProcessIsolation = 1
///             InprocServer32
///             └─ (Default) = %LOCALAPPDATA%\blp-thumb-win\blp_thumb_win.dll
///                ThreadingModel = Apartment
///                ProgID = WarRaft.BLP
///             Implemented Categories
///             └─ {8895B1C6-B41F-4C1C-A562-0D564250836F}
///
/// And finally, the system lists used by Explorer:
///
/// HKLM / HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers
///    (Default) entries mapping extension -> thumbnail CLSID
///
/// HKLM / HKCU\Software\Microsoft\Windows\CurrentVersion\PreviewHandlers
///    {CLSID_BLP_PREVIEW} = "BLP Preview Handler"
///
/// Notes:
/// - We prefer writing ProgID/Preview/Thumbnail registration in a single
///   function to avoid duplication and keep the installer deterministic.
/// - `AppID` is optional; it helps Windows host preview handlers in Prevhost
///   when appropriate (useful for cross-bitness isolation).
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
    let ext = DEFAULT_EXT;

    let classes = [
        (FRIENDLY_NAME, &thumb_clsid, &thumb_catid),
        (
            blp_thumb_win::keys::PREVIEW_FRIENDLY_NAME,
            &preview_clsid,
            &preview_catid,
        ),
    ];

    create_subkey(
        &root,
        r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
    )?;

    for (friendly, clsid, catid) in &classes {
        log_cli(format!(
            "Register COM [{}]: configuring CLSID {}",
            scope_name, clsid
        ));
        let path_clsid = format!(r"Software\Classes\CLSID\{}", clsid);
        set_reg_value(&root, &path_clsid, "", friendly)?;
        set_reg_value(&root, &path_clsid, "DisableProcessIsolation", &1u32)?;
        // Per MS docs: set DisplayName and AppID to help preview host and debugging
        if *catid == &preview_catid {
            set_reg_value(
                &root,
                &path_clsid,
                "DisplayName",
                &format!("@{}", dll_path.display()),
            )?;
            set_reg_value(
                &root,
                &path_clsid,
                "AppID",
                &blp_thumb_win::keys::APP_ID.to_string(),
            )?;
        }
        let key_clsid = create_subkey(&root, &path_clsid)?;
        key_clsid.set_value("DisableProcessIsolation", &1u32)?;

        let inproc_path = format!(r"Software\Classes\CLSID\{}\InprocServer32", clsid);
        create_subkey(&root, &inproc_path)?;
        set_reg_value(&root, &inproc_path, "", &dll_path.as_os_str())?;
        // Suggest associating ProgID inside InprocServer32 per docs (helps some hosts)
        if *catid == &preview_catid {
            set_reg_value(
                &root,
                &inproc_path,
                "ProgID",
                &blp_thumb_win::keys::DEFAULT_PROGID.to_string(),
            )?;
            set_reg_value(
                &root,
                &inproc_path,
                "VersionIndependentProgID",
                &blp_thumb_win::keys::DEFAULT_PROGID.to_string(),
            )?;
        }
        set_reg_value(&root, &inproc_path, "ThreadingModel", &"Apartment")?;

        set_reg_value(
            &root,
            r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
            clsid,
            friendly,
        )?;

        let impl_cat_path = format!(
            r"Software\Classes\CLSID\{}\Implemented Categories\{}",
            clsid, catid
        );
        let _ = create_subkey(&root, &impl_cat_path)?;
    }

    log_cli(format!(
        "Register COM [{}]: ensuring extension metadata",
        scope_name
    ));
    let ext_path = format!(r"Software\Classes\{}", ext);
    let ext_key = create_subkey(&root, &ext_path)?;
    log_cli(format!("Ensuring extension key: {}", ext_path));
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
            set_reg_value(&root, &ext_path, "Content Type", &"image/x-blp")?;
        }
    }
    log_cli(format!(
        r"Setting value: {}\PerceivedType = image",
        ext_path
    ));
    set_reg_value(&root, &ext_path, "PerceivedType", &"image")?;

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
            set_reg_value(&root, &ext_path, "", &blp_thumb_win::keys::DEFAULT_PROGID)?;
        }
    }

    log_cli(format!(
        "Register COM [{}]: ensuring ProgID key {}",
        scope_name,
        blp_thumb_win::keys::DEFAULT_PROGID
    ));
    let progid_path = format!(r"Software\Classes\{}", blp_thumb_win::keys::DEFAULT_PROGID);
    log_cli(format!("Creating ProgID key: {}", progid_path));
    let progid_key = create_subkey(&root, &progid_path)?;
    if progid_key
        .get_value::<String, _>("")
        .map(|s| s.trim_matches(char::from(0)).is_empty())
        .unwrap_or(true)
    {
        set_reg_value(&root, &progid_path, "", &FRIENDLY_NAME)?;
    }
    create_subkey(&root, &format!(r"{}\ShellEx", progid_path))?;
    for (_, clsid, catid) in &classes {
        let pid_entry_path = format!(r"{}\ShellEx\{}", blp_thumb_win::keys::DEFAULT_PROGID, catid);
        create_subkey(&root, &pid_entry_path)?;
        set_reg_value(&root, &pid_entry_path, "", &clsid.as_str())?;
    }

    log_cli(format!(
        "Register COM [{}]: binding under extension {}",
        scope_name, ext
    ));
    let key_ext_shellex_path = format!(r"Software\Classes\{}\ShellEx", ext);
    log_cli(format!(
        "Creating extension ShellEx key: {}",
        key_ext_shellex_path
    ));
    create_subkey(&root, &key_ext_shellex_path)?;
    for (_, clsid, catid) in &classes {
        let entry_path = format!(r"Software\Classes\{}\ShellEx\{}", ext, catid);
        create_subkey(&root, &entry_path)?;
        set_reg_value(&root, &entry_path, "", &clsid.as_str())?;
    }

    log_cli(format!(
        "Register COM [{}]: binding under SystemFileAssociations {}",
        scope_name, ext
    ));
    let key_sys_shellex_path = format!(r"Software\Classes\SystemFileAssociations\{}\ShellEx", ext);
    log_cli(format!(
        "Creating SystemFileAssociations ShellEx key: {}",
        key_sys_shellex_path
    ));
    create_subkey(&root, &key_sys_shellex_path)?;
    for (_, clsid, catid) in &classes {
        let entry_path = format!(
            r"Software\Classes\SystemFileAssociations\{}\ShellEx\{}",
            ext, catid
        );
        create_subkey(&root, &entry_path)?;
        set_reg_value(&root, &entry_path, "", &clsid.as_str())?;
    }

    log_cli(format!(
        "Register COM [{}]: binding Explorer handlers",
        scope_name
    ));
    let thumb_handlers_path =
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers";
    log_cli(format!(
        "Creating ThumbnailHandlers key: {}",
        thumb_handlers_path
    ));
    create_subkey(&root, thumb_handlers_path)?;
    set_reg_value(&root, thumb_handlers_path, &ext, &thumb_clsid)?;
    let preview_handlers_path = r"Software\Microsoft\Windows\CurrentVersion\PreviewHandlers";
    log_cli(format!(
        "Creating PreviewHandlers key: {}",
        preview_handlers_path
    ));
    create_subkey(&root, preview_handlers_path)?;
    set_reg_value(
        &root,
        preview_handlers_path,
        &preview_clsid,
        &blp_thumb_win::keys::PREVIEW_FRIENDLY_NAME,
    )?;

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

fn bind_application(hkcu: &RegKey, entry: &str, catid: &str, clsid: &str) -> io::Result<()> {
    let entry = entry.trim();
    if entry.is_empty() {
        return Ok(());
    }

    // If entry is already a ProgID, reuse helper
    if !entry.ends_with(".exe") {
        return bind_prog_id_application(hkcu, entry, catid, clsid);
    }

    let key_path = format!(r"Software\Classes\Applications\{}\ShellEx", entry);
    log_cli(format!(
        "Register COM: binding under application {} (ShellEx)",
        entry
    ));
    let (app_shellex, _) = hkcu.create_subkey(key_path)?;
    let (app_thumb, _) = app_shellex.create_subkey(catid)?;
    app_thumb.set_value("", &clsid)?;
    Ok(())
}

fn bind_prog_id_application(
    hkcu: &RegKey,
    progid: &str,
    catid: &str,
    clsid: &str,
) -> io::Result<()> {
    let progid = progid.trim();
    if progid.is_empty() {
        return Ok(());
    }

    if let Some(app) = progid.strip_prefix(r"Applications\") {
        return bind_application(hkcu, app, catid, clsid);
    }

    log_cli(format!(
        "Register COM: binding under ProgID application {}",
        progid
    ));
    let (app_shellex, _) = hkcu.create_subkey(format!(r"Software\Classes\{}\ShellEx", progid))?;
    let (app_thumb, _) = app_shellex.create_subkey(catid)?;
    app_thumb.set_value("", &clsid)?;
    Ok(())
}

fn clear_shell_ext_cache_scope(scope: RegistryScope, clsid: &str) -> io::Result<usize> {
    let root = scope.root();
    let path = r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached";
    let key = match root.open_subkey_with_flags(path, KEY_READ | KEY_SET_VALUE) {
        Ok(k) => k,
        Err(err) => {
            if err.kind() == io::ErrorKind::NotFound {
                log_cli(format!(
                    "{}: shell extension cache key missing",
                    scope.name()
                ));
                return Ok(0);
            }
            return Err(err);
        }
    };

    let clsid_upper = clsid.to_ascii_uppercase();
    let clsid_nobrace = clsid_upper.trim_matches('{').trim_matches('}').to_string();
    let mut to_delete = Vec::new();
    for value in key.enum_values() {
        if let Ok((name, _)) = value {
            let upper = name.to_ascii_uppercase();
            if upper.contains(&clsid_upper) || upper.contains(&clsid_nobrace) {
                to_delete.push(name);
            }
        }
    }

    let mut removed = 0usize;
    for name in to_delete {
        if key.delete_value(&name).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        log_cli(format!(
            r"{}: cleared {} entries from Shell Extensions\Cached",
            scope.name(),
            removed
        ));
    } else {
        log_cli(format!(
            "{}: no cached Shell Extensions entries to clear",
            scope.name()
        ));
    }
    Ok(removed)
}

fn enforce_thumbnail_settings_scope(scope: RegistryScope) -> io::Result<()> {
    log_cli(format!(
        "{}: enforcing Explorer thumbnail settings",
        scope.name()
    ));
    let root = scope.root();

    let (advanced, _) =
        root.create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")?;
    advanced.set_value("IconsOnly", &0u32)?;
    advanced.set_value("DisableThumbnails", &0u32)?;
    advanced.set_value("DisableThumbnailCache", &0u32)?;
    advanced.set_value("DisableThumbnailsOnNetworkFolders", &0u32)?;

    const POLICY_PATHS: [&str; 2] = [
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        r"Software\Policies\Microsoft\Windows\Explorer",
    ];
    const POLICY_VALUES: [&str; 3] = [
        "DisableThumbnails",
        "DisableThumbnailCache",
        "DisableThumbnailsOnNetworkFolders",
    ];

    for path in POLICY_PATHS {
        if let Ok((key, _)) = root.create_subkey(path) {
            for name in POLICY_VALUES {
                key.set_value(name, &0u32)?;
            }
        }
    }

    Ok(())
}

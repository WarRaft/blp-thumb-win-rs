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

// Use registry helper from utils

pub fn install() -> io::Result<()> {
    // Call the real installer which uses `?` for errors, and log any error here.
    if let Err(err) = install_inner() {
        log_cli(format!("Install failed: {}", err));
        return Err(err);
    }
    Ok(())
}

// Private implementation that contains the actual installation logic and returns
// errors via `?` so the public wrapper can handle/log them.
fn install_inner() -> io::Result<()> {
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
        let path_clsid = format!(r"Software\\Classes\\CLSID\\{}", clsid);
        log_cli(format!("Creating registry key: {}", path_clsid));
        let (key_clsid, _) = root.create_subkey(path_clsid)?;
        log_cli(format!(
            "Setting value: {}\\(Default) = {}",
            clsid, friendly
        ));
        key_clsid.set_value("", friendly)?;
        log_cli(format!(
            "Setting value: {}\\DisableProcessIsolation = {}",
            clsid, 1
        ));
        // Per MS docs: set DisplayName and AppID to help preview host and debugging
        if *catid == &preview_catid {
            log_cli(format!(
                "Setting value: {}\\DisplayName = @{}",
                clsid,
                dll_path.display()
            ));
            key_clsid.set_value("DisplayName", &format!("@{}", dll_path.display()))?;
            log_cli(format!(
                "Setting value: {}\\AppID = {}",
                clsid,
                blp_thumb_win::keys::APP_ID
            ));
            key_clsid.set_value("AppID", &blp_thumb_win::keys::APP_ID.to_string())?;
        }
        key_clsid.set_value("DisableProcessIsolation", &1u32)?;

        let (key_inproc, _) = root.create_subkey(format!(
            r"Software\\Classes\\CLSID\\{}\\InprocServer32",
            clsid
        ))?;
        log_cli(format!(
            "Creating registry key: Software\\Classes\\CLSID\\{}\\InprocServer32",
            clsid
        ));
        log_cli(format!(
            "Setting value: {}\\InprocServer32\\(Default) = {}",
            clsid,
            dll_path.display()
        ));
        key_inproc.set_value("", &dll_path.as_os_str())?;
        // Suggest associating ProgID inside InprocServer32 per docs (helps some hosts)
        if *catid == &preview_catid {
            log_cli(format!(
                "Setting value: {}\\InprocServer32\\ProgID = {}",
                clsid,
                blp_thumb_win::keys::DEFAULT_PROGID
            ));
            key_inproc.set_value("ProgID", &blp_thumb_win::keys::DEFAULT_PROGID.to_string())?;
            log_cli(format!(
                "Setting value: {}\\InprocServer32\\VersionIndependentProgID = {}",
                clsid,
                blp_thumb_win::keys::DEFAULT_PROGID
            ));
            key_inproc.set_value(
                "VersionIndependentProgID",
                &blp_thumb_win::keys::DEFAULT_PROGID.to_string(),
            )?;
        }
        key_inproc.set_value("ThreadingModel", &"Apartment")?;

        log_cli(format!("Approved list: setting {} = {}", clsid, friendly));
        approved.set_value(clsid, friendly)?;

        let impl_cat_path = format!(
            "Software\\Classes\\CLSID\\{}\\Implemented Categories\\{}",
            clsid, catid
        );
        log_cli(format!("Creating registry key: {}", impl_cat_path));
        let _ = root.create_subkey(impl_cat_path)?;
    }

    log_cli(format!(
        "Register COM [{}]: ensuring extension metadata",
        scope_name
    ));
    let (ext_key, _) = root.create_subkey(format!(r"Software\\Classes\\{}", ext))?;
    log_cli(format!(
        "Ensuring extension key: Software\\Classes\\{}",
        ext
    ));
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
            log_cli(format!(
                "Setting value: Software\\Classes\\{}\\Content Type = image/x-blp",
                ext
            ));
            ext_key.set_value("Content Type", &"image/x-blp")?;
        }
    }
    log_cli(format!(
        "Setting value: Software\\Classes\\{}\\PerceivedType = image",
        ext
    ));
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
            log_cli(format!(
                "Setting default ProgID: Software\\Classes\\{}\\(Default) = {}",
                ext,
                blp_thumb_win::keys::DEFAULT_PROGID
            ));
            ext_key.set_value("", &blp_thumb_win::keys::DEFAULT_PROGID)?;
        }
    }

    log_cli(format!(
        "Register COM [{}]: ensuring ProgID key {}",
        scope_name,
        blp_thumb_win::keys::DEFAULT_PROGID
    ));
    let progid_path = format!(
        r"Software\\Classes\\{}",
        blp_thumb_win::keys::DEFAULT_PROGID
    );
    log_cli(format!("Creating ProgID key: {}", progid_path));
    let (progid_key, _) = root.create_subkey(progid_path)?;
    if progid_key
        .get_value::<String, _>("")
        .map(|s| s.trim_matches(char::from(0)).is_empty())
        .unwrap_or(true)
    {
        log_cli(format!(
            "Setting value: {}\\(Default) = {}",
            blp_thumb_win::keys::DEFAULT_PROGID,
            FRIENDLY_NAME
        ));
        progid_key.set_value("", &FRIENDLY_NAME)?;
    }
    let (pid_shellex, _) = progid_key.create_subkey("ShellEx")?;
    for (_, clsid, catid) in &classes {
        let pid_entry_path = format!(
            r"{}\\ShellEx\\{}",
            blp_thumb_win::keys::DEFAULT_PROGID,
            catid
        );
        log_cli(format!("Creating ProgID ShellEx entry: {}", pid_entry_path));
        let (pid_entry, _) = pid_shellex.create_subkey(catid)?;
        log_cli(format!(
            "Setting value: {}\\(Default) = {}",
            pid_entry_path, clsid
        ));
        pid_entry.set_value("", &clsid.as_str())?;
    }

    log_cli(format!(
        "Register COM [{}]: binding under extension {}",
        scope_name, ext
    ));
    let key_ext_shellex_path = format!(r"Software\\Classes\\{}\\ShellEx", ext);
    log_cli(format!(
        "Creating extension ShellEx key: {}",
        key_ext_shellex_path
    ));
    let (key_ext_shellex, _) = root.create_subkey(key_ext_shellex_path)?;
    for (_, clsid, catid) in &classes {
        let entry_path = format!(r"Software\\Classes\\{}\\ShellEx\\{}", ext, catid);
        log_cli(format!("Creating extension ShellEx entry: {}", entry_path));
        let (key_ext_entry, _) = key_ext_shellex.create_subkey(catid)?;
        log_cli(format!(
            "Setting value: {}\\(Default) = {}",
            entry_path, clsid
        ));
        key_ext_entry.set_value("", &clsid.as_str())?;
    }

    log_cli(format!(
        "Register COM [{}]: binding under SystemFileAssociations {}",
        scope_name, ext
    ));
    let key_sys_shellex_path = format!(
        r"Software\\Classes\\SystemFileAssociations\\{}\\ShellEx",
        ext
    );
    log_cli(format!(
        "Creating SystemFileAssociations ShellEx key: {}",
        key_sys_shellex_path
    ));
    let (key_sys_shellex, _) = root.create_subkey(key_sys_shellex_path)?;
    for (_, clsid, catid) in &classes {
        let entry_path = format!(
            r"Software\\Classes\\SystemFileAssociations\\{}\\ShellEx\\{}",
            ext, catid
        );
        log_cli(format!(
            "Creating SystemFileAssociations ShellEx entry: {}",
            entry_path
        ));
        let (key_sys_entry, _) = key_sys_shellex.create_subkey(catid)?;
        log_cli(format!(
            "Setting value: {}\\(Default) = {}",
            entry_path, clsid
        ));
        key_sys_entry.set_value("", &clsid.as_str())?;
    }

    log_cli(format!(
        "Register COM [{}]: binding Explorer handlers",
        scope_name
    ));
    let thumb_handlers_path =
        r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ThumbnailHandlers";
    log_cli(format!(
        "Creating ThumbnailHandlers key: {}",
        thumb_handlers_path
    ));
    let (thumb_handlers, _) = root.create_subkey(thumb_handlers_path)?;
    log_cli(format!(
        "Setting ThumbnailHandlers entry: {} = {}",
        ext, thumb_clsid
    ));
    thumb_handlers.set_value(&ext, &thumb_clsid)?;
    let preview_handlers_path = r"Software\\Microsoft\\Windows\\CurrentVersion\\PreviewHandlers";
    log_cli(format!(
        "Creating PreviewHandlers key: {}",
        preview_handlers_path
    ));
    let (preview_handlers, _) = root.create_subkey(preview_handlers_path)?;
    log_cli(format!(
        "Setting PreviewHandlers entry: {} = {}",
        preview_clsid,
        blp_thumb_win::keys::PREVIEW_FRIENDLY_NAME
    ));
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

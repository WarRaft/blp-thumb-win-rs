use crate::DLL_BYTES;
use crate::utils::notify_shell_assoc::notify_shell_assoc;
use blp_thumb_win::keys::{
    DEFAULT_EXT, FRIENDLY_NAME, clsid_str, preview_clsid_str, shell_preview_handler_catid_str,
    shell_thumb_handler_catid_str,
};
use blp_thumb_win::log::{log_cli, log_ui};
use std::io;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};

/** =========================================================================
Register COM classes and shell bindings for this provider (HKCU only).

This inlined block performs all registry writes needed for both the
thumbnail handler and the preview handler. It follows the steps from the
Microsoft documentation.

Docs:
- Thumbnail handlers: https://learn.microsoft.com/en-us/windows/win32/shell/thumbnail-providers
- Preview handlers:   https://learn.microsoft.com/ru-ru/windows/win32/shell/preview-handlers

Registry layout (ASCII tree):

HKCU
└─ Software
   └─ Classes
      ├─ .blp
      │  (Default) = WarRaft.BLP                ; file extension -> ProgID
      │  Content Type = image/x-blp
      │  PerceivedType = image
      ├─ WarRaft.BLP                            ; ProgID
      │  (Default) = BLP Thumbnail/Preview Provider
      │  ShellEx
      │  └─ {8895B1C6-B41F-4C1C-A562-0D564250836F} = {CLSID_BLP_PREVIEW}
      │  ThumbnailCutoff, TypeOverlay, etc. (optional)
      └─ CLSID
         ├─ {CLSID_BLP_THUMB}
         │  (Default) = BLP Thumbnail Provider
         │  DisableProcessIsolation = 1
         │  InprocServer32
         │  └─ (Default) = %LOCALAPPDATA%\blp-thumb-win\blp_thumb_win.dll
         │     ThreadingModel = Apartment
         │     ProgID = WarRaft.BLP
         │  Implemented Categories
         │  └─ {E357FCCD-A995-4576-B01F-234630154E96}
         └─ {CLSID_BLP_PREVIEW}
            (Default) = BLP Preview Handler
            DisplayName = @blp_thumb_win.dll,-101    ; optional but helpful
            AppID = {534A1E02-D58F-44f0-B58B-36CBED287C7C} ; enables prevhost usage
            DisableProcessIsolation = 1
            InprocServer32
            └─ (Default) = %LOCALAPPDATA%\blp-thumb-win\blp_thumb_win.dll
               ThreadingModel = Apartment
               ProgID = WarRaft.BLP
            Implemented Categories
            └─ {8895B1C6-B41F-4C1C-A562-0D564250836F}

Explorer lists used by Explorer:
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers
   ".blp" = {CLSID_BLP_THUMB}
HKCU\Software\Microsoft\Windows\CurrentVersion\PreviewHandlers
   {CLSID_BLP_PREVIEW} = "BLP Preview Handler"

Notes:
- We target per-user install only (HKCU). No HKLM writes here.
- AppID is optional; helps Windows host preview handlers in Prevhost.
=========================================================================
*/
pub fn install() -> io::Result<()> {
    if let Err(err) = install_inner() {
        log_ui(format!("Install failed: {}", err));
    }
    Ok(())
}

fn install_inner() -> io::Result<()> {
    use std::path::PathBuf;
    use std::{env, fs};

    log_cli("Install (current user): start");

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
        "Install (current user): DLL materialized to {}",
        dll_path.display()
    ));

    let mut warnings = Vec::new();

    {
        use crate::utils::regedit::Rk;

        let root = RegKey::predef(HKEY_CURRENT_USER);
        let thumb_clsid = clsid_str(); // CLSID for Thumbnail
        let thumb_catid = shell_thumb_handler_catid_str(); // {E357FCCD-A995-4576-B01F-234630154E96}
        let preview_clsid = preview_clsid_str(); // CLSID for Preview
        let preview_catid = shell_preview_handler_catid_str(); // {8895B1C6-B41F-4C1C-A562-0D564250836F}
        let ext = DEFAULT_EXT; // ".blp"

        // (friendly, clsid, catid, is_preview)
        let classes = [
            (FRIENDLY_NAME, &thumb_clsid, &thumb_catid, false),
            (
                blp_thumb_win::keys::PREVIEW_FRIENDLY_NAME,
                &preview_clsid,
                &preview_catid,
                true,
            ),
        ];

        // Ensure Explorer "Approved" exists
        let approved = Rk::open(
            &root,
            r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        )?;

        // --- CLSID registration (both handlers) --------------------------------
        for (friendly, clsid, catid, is_preview) in &classes {
            log_cli(format!("Register COM [HKCU]: configuring CLSID {}", clsid));

            // HKCU\Software\Classes\CLSID\{CLSID}
            let clsid_key = Rk::open(&root, format!(r"Software\Classes\CLSID\{}", clsid))?;
            clsid_key.set_default(*friendly)?; // REG_SZ
            clsid_key.set("DisableProcessIsolation", 1u32)?; // REG_DWORD

            if *is_preview {
                clsid_key.set("DisplayName", format!("@{}", dll_path.display()))?;
                clsid_key.set("AppID", blp_thumb_win::keys::APP_ID.to_string())?;
            }

            // HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32
            let inproc = clsid_key.sub(r"InprocServer32")?;
            inproc.set_default(dll_path.as_os_str())?; // REG_SZ
            inproc.set("ThreadingModel", "Apartment")?; // REG_SZ
            if *is_preview {
                inproc.set("ProgID", blp_thumb_win::keys::DEFAULT_PROGID.to_string())?;
                inproc.set(
                    "VersionIndependentProgID",
                    blp_thumb_win::keys::DEFAULT_PROGID.to_string(),
                )?;
            }

            // HKCU\Software\Classes\CLSID\{CLSID}\Implemented Categories\{CATID}
            let _impl_cat = clsid_key.sub(&format!(r"Implemented Categories\{}", catid))?;

            // Explorer "Approved"
            approved.set(clsid.as_str(), *friendly)?;
        }
        // -----------------------------------------------------------------------

        // --- File extension metadata (.blp) ------------------------------------
        // HKCU\Software\Classes\.blp
        let ext_key = Rk::open(&root, format!(r"Software\Classes\{}", ext))?;
        match ext_key.get::<String>("Content Type") {
            Ok(existing)
                if !existing.trim_matches(char::from(0)).is_empty()
                    && existing != "image/x-blp" =>
            {
                log_cli(format!(
                    "Register COM [HKCU]: skipping Content Type override (current={})",
                    existing
                ));
            }
            _ => {
                ext_key.set("Content Type", "image/x-blp")?;
            }
        }
        log_cli(format!(r"Setting value: {}\PerceivedType = image", ext));
        ext_key.set("PerceivedType", "image")?;

        match ext_key.get::<String>("") {
            Ok(existing) if !existing.trim_matches(char::from(0)).is_empty() => {
                log_cli(format!(
                    "Register COM [HKCU]: extension default already set to {}",
                    existing
                ));
            }
            _ => {
                log_cli("Register COM [HKCU]: setting extension default to WarRaft.BLP");
                ext_key.set_default(blp_thumb_win::keys::DEFAULT_PROGID)?;
            }
        }
        // -----------------------------------------------------------------------

        // --- ProgID registration ------------------------------------------------
        // HKCU\Software\Classes\WarRaft.BLP
        let progid_key = Rk::open(
            &root,
            format!(r"Software\Classes\{}", blp_thumb_win::keys::DEFAULT_PROGID),
        )?;
        if progid_key
            .get::<String>("")
            .map(|s| s.trim_matches(char::from(0)).is_empty())
            .unwrap_or(true)
        {
            progid_key.set_default(FRIENDLY_NAME)?;
        }

        // HKCU\Software\Classes\WarRaft.BLP\ShellEx\{CATID} = {CLSID}
        let progid_shellex = progid_key.sub(r"ShellEx")?;
        for (_, clsid, catid, _) in &classes {
            let pid_entry = progid_shellex.sub(catid)?;
            pid_entry.set_default(clsid.as_str())?;
        }
        // -----------------------------------------------------------------------

        // --- Bind under extension and SFA --------------------------------------
        // HKCU\Software\Classes\.blp\ShellEx\{CATID} = {CLSID}
        let ext_shellex = Rk::open(&root, format!(r"Software\Classes\{}\ShellEx", ext))?;
        for (_, clsid, catid, _) in &classes {
            let entry = ext_shellex.sub(catid)?;
            entry.set_default(clsid.as_str())?;
        }

        // HKCU\Software\Classes\SystemFileAssociations\.blp\ShellEx\{CATID} = {CLSID}
        let sfa_shellex = Rk::open(
            &root,
            format!(r"Software\Classes\SystemFileAssociations\{}\ShellEx", ext),
        )?;
        for (_, clsid, catid, _) in &classes {
            let entry = sfa_shellex.sub(catid)?;
            entry.set_default(clsid.as_str())?;
        }
        // -----------------------------------------------------------------------

        // --- Explorer handler lists --------------------------------------------
        // HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers
        //   ".blp" = {CLSID_BLP_THUMB}
        let thumb_handlers = Rk::open(
            &root,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers",
        )?;
        thumb_handlers.set(ext, thumb_clsid.as_str())?;

        // HKCU\Software\Microsoft\Windows\CurrentVersion\PreviewHandlers
        //   {CLSID_BLP_PREVIEW} = "BLP Preview Handler"
        let preview_handlers = Rk::open(
            &root,
            r"Software\Microsoft\Windows\CurrentVersion\PreviewHandlers",
        )?;
        preview_handlers.set(
            preview_clsid.as_str(),
            blp_thumb_win::keys::PREVIEW_FRIENDLY_NAME,
        )?;
        // -----------------------------------------------------------------------

        // --- OpenWith bindings (HKCU only) -------------------------------------
        // FileExts\<.blp>\OpenWithList
        let mut ow_apps: Vec<String> = {
            let path = format!(
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{}\OpenWithList",
                ext
            );
            let mut v = Vec::new();
            if let Ok(key) = root.open_subkey(&path) {
                for item in key.enum_values() {
                    if let Ok((name, value)) = item {
                        if name.len() == 1 {
                            let s = value.to_string();
                            let s = s.trim_matches(char::from(0)).trim().to_string();
                            if !s.is_empty() {
                                v.push(s);
                            }
                        }
                    }
                }
            }
            v
        };

        // FileExts\<.blp>\OpenWithProgids
        let mut ow_progids: Vec<String> = {
            let path = format!(
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{}\OpenWithProgids",
                ext
            );
            let mut v = Vec::new();
            if let Ok(key) = root.open_subkey(&path) {
                for item in key.enum_values() {
                    if let Ok((name, _)) = item {
                        let s = name.trim_matches(char::from(0)).trim().to_string();
                        if !s.is_empty() {
                            v.push(s);
                        }
                    }
                }
            }
            v
        };

        // FileExts\<.blp>\UserChoice → ProgId (может быть "Applications\*.exe" или ProgID)
        let user_choice: Option<String> = {
            let path = format!(
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{}\UserChoice",
                ext
            );
            root.open_subkey(path)
                .ok()
                .and_then(|key| key.get_value::<String, _>("ProgId").ok())
                .map(|s| s.trim_matches(char::from(0)).to_string())
                .filter(|s| !s.is_empty())
        };

        // Bind helpers (inline)
        let bind_application = |app: &str, catid: &str, clsid: &str| -> io::Result<()> {
            let app_shellex = Rk::open(
                &root,
                format!(r"Software\Classes\Applications\{}\ShellEx", app),
            )?;
            let app_cat = app_shellex.sub(catid)?;
            app_cat.set_default(clsid)?;
            Ok(())
        };
        let bind_prog_id_application = |progid: &str, catid: &str, clsid: &str| -> io::Result<()> {
            if let Some(app) = progid.strip_prefix(r"Applications\") {
                return bind_application(app, catid, clsid);
            }
            let app_shellex = Rk::open(&root, format!(r"Software\Classes\{}\ShellEx", progid))?;
            let app_cat = app_shellex.sub(catid)?;
            app_cat.set_default(clsid)?;
            Ok(())
        };

        // Apply bindings for OpenWithList (apps) and OpenWithProgids
        for app in ow_apps.drain(..) {
            if !app.trim().is_empty() {
                for (_, clsid, catid, _) in &classes {
                    if app.ends_with(".exe") {
                        let _ = bind_application(&app, catid, clsid);
                    } else {
                        let _ = bind_prog_id_application(&app, catid, clsid);
                    }
                }
            }
        }
        for progid in ow_progids.drain(..) {
            if !progid.trim().is_empty() {
                for (_, clsid, catid, _) in &classes {
                    let _ = bind_prog_id_application(&progid, catid, clsid);
                }
            }
        }

        // Apply binding for UserChoice (if present)
        if let Some(prog_id) = user_choice {
            if let Some(app) = prog_id.strip_prefix(r"Applications\") {
                for (_, clsid, catid, _) in &classes {
                    let _ = bind_application(app, catid, clsid);
                }
            } else {
                for (_, clsid, catid, _) in &classes {
                    let _ = bind_prog_id_application(&prog_id, catid, clsid);
                }
            }
        }

        log_cli("Register COM [HKCU]: completed");
    }
    // ========================= end of inlined COM registration ================

    // === Clear Shell Extensions cache (HKCU) ==================================
    {
        let root = RegKey::predef(HKEY_CURRENT_USER);
        let path = r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached";
        match root.open_subkey_with_flags(path, KEY_READ | KEY_SET_VALUE) {
            Ok(key) => {
                let clsids = [clsid_str(), preview_clsid_str()];
                for clsid in clsids {
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
                            "HKCU: cleared {} entries from Shell Extensions\\Cached",
                            removed
                        ));
                    } else {
                        log_cli("HKCU: no cached Shell Extensions entries to clear");
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                log_cli("HKCU: shell extension cache key missing");
            }
            Err(err) => warnings.push(format!("HKCU cache clear failed: {}", err)),
        }
    }
    // ========================================================================

    // === Enforce Explorer thumbnail settings (HKCU) ==========================
    {
        let root = RegKey::predef(HKEY_CURRENT_USER);

        if let Ok((advanced, _)) =
            root.create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")
        {
            let _ = advanced.set_value("IconsOnly", &0u32);
            let _ = advanced.set_value("DisableThumbnails", &0u32);
            let _ = advanced.set_value("DisableThumbnailCache", &0u32);
            let _ = advanced.set_value("DisableThumbnailsOnNetworkFolders", &0u32);
        }

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
                    let _ = key.set_value(name, &0u32);
                }
            }
        }
    }
    // ========================================================================

    notify_shell_assoc("install-user");

    if warnings.is_empty() {
        println!("Installed in HKCU. Use 'Restart Explorer' to refresh thumbnails.");
    } else {
        println!("Install completed with warnings:");
        for warn in warnings {
            println!("  - {}", warn);
        }
    }
    Ok(())
}

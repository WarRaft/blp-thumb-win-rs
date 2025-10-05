use crate::DLL_BYTES;
use crate::utils::notify_shell_assoc::notify_shell_assoc;
use blp_thumb_win::keys::{
    DEFAULT_EXT, FRIENDLY_NAME, clsid_str, preview_clsid_str, shell_preview_handler_catid_str,
    shell_thumb_handler_catid_str,
};
use blp_thumb_win::log::log_ui;
use std::io;
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

/** ============================================================================
Per-user (HKCU) registration of COM thumbnail & preview handlers for the BLP format.

This routine performs all *per-user* (HKCU) registry writes required for:
- the thumbnail provider (Shell Thumbnail Provider);
- the preview handler (Shell Preview Handler).

It deliberately avoids modifying application associations:
- No writes under `...Explorer\FileExts\...\OpenWithList`;
- No writes under `...Explorer\FileExts\...\OpenWithProgids`;
- No writes under `...Explorer\FileExts\...\UserChoice`;
- No writes under `Software\Classes\Applications\...`.

Only our own ProgID / extension / CLSIDs and Explorer handler lists are touched.

References:
- Thumbnail providers: https://learn.microsoft.com/windows/win32/shell/thumbnail-providers
- Preview handlers:   https://learn.microsoft.com/windows/win32/shell/preview-handlers
- Registration:       https://learn.microsoft.com/windows/win32/shell/how-to-register-a-preview-handler

Registry layout (ASCII):

HKCU
└─ Software
   ├─ Classes
   │  ├─ .blp
   │  │  (Default)        = WarRaft.BLP               ; only if *currently empty*
   │  │  Content Type     = image/x-blp
   │  │  PerceivedType    = image
   │  ├─ WarRaft.BLP                                   ; our ProgID
   │  │  (Default)        = BLP Thumbnail/Preview Provider
   │  │  └─ ShellEx
   │  │     ├─ {E357FCCD-A995-4576-B01F-234630154E96}  = {CLSID_BLP_THUMB}
   │  │     └─ {8895B1C6-B41F-4C1C-A562-0D564250836F}  = {CLSID_BLP_PREVIEW}
   │  └─ CLSID
   │     ├─ {CLSID_BLP_THUMB}
   │     │  (Default)     = BLP Thumbnail Provider
   │     │  DisableProcessIsolation = 1 (DWORD)        ; thumbnail only
   │     │  └─ InprocServer32
   │     │     (Default)  = %LOCALAPPDATA%\blp-thumb-win\blp_thumb_win.dll
   │     │     ThreadingModel = Apartment
   │     │  └─ Implemented Categories
   │     │     └─ {E357FCCD-A995-4576-B01F-234630154E96}
   │     └─ {CLSID_BLP_PREVIEW}
   │        (Default)     = BLP Preview Handler
   │        DisplayName   = @<dll_path>                ; optional, helps diagnostics
   │        └─ InprocServer32
   │           (Default)  = %LOCALAPPDATA%\blp-thumb-win\blp_thumb_win.dll
   │           ThreadingModel = Apartment
   │           ProgID     = WarRaft.BLP                ; optional but helpful
   │           VersionIndependentProgID = WarRaft.BLP  ; optional but helpful
   │        └─ Implemented Categories
   │           └─ {8895B1C6-B41F-4C1C-A562-0D564250836F}
   └─ Microsoft\Windows\CurrentVersion
      ├─ Explorer\ThumbnailHandlers
      │  ".blp" = {CLSID_BLP_THUMB}
      └─ PreviewHandlers
         {CLSID_BLP_PREVIEW} = "BLP Preview Handler"

Notes:
- We target per-user install only (HKCU). No HKLM writes are performed.
- For Preview Handlers we DO NOT set DisableProcessIsolation or AppID.
  The shell hosts them out-of-process in prevhost.exe automatically.
============================================================================ */
pub fn install() -> io::Result<()> {
    if let Err(err) = install_inner() {
        log_ui(format!("Install failed: {}", err));
    }
    Ok(())
}

fn install_inner() -> io::Result<()> {
    use crate::utils::regedit::Rk;
    use std::path::PathBuf;
    use std::{env, fs};

    log_ui("Install (current user): start");

    // 1) Materialize the embedded DLL into %LOCALAPPDATA%\blp-thumb-win
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

    log_ui(format!(
        "Install (current user): DLL materialized to {}",
        dll_path.display()
    ));

    // 2) COM registration under HKCU (no application association changes)
    {
        let root = RegKey::predef(HKEY_CURRENT_USER);

        let thumb_clsid = clsid_str(); // CLSID (thumbnail)
        let thumb_catid = shell_thumb_handler_catid_str(); // {E357FCCD-A995-4576-B01F-234630154E96}
        let preview_clsid = preview_clsid_str(); // CLSID (preview)
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

        // Ensure Explorer "Approved" exists; we will register each CLSID there.
        let approved = Rk::open(
            &root,
            r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        )?;

        // 2.1) CLSID registration (for both handlers)
        for (friendly, clsid, catid, is_preview) in &classes {
            log_ui(format!("Register COM [HKCU]: configuring CLSID {}", clsid));

            // HKCU\Software\Classes\CLSID\{CLSID}
            let clsid_key = Rk::open(&root, format!(r"Software\Classes\CLSID\{}", clsid))?;
            clsid_key.set_default(*friendly)?;

            // Thumbnail: keep DisableProcessIsolation = 1
            // Preview  : DO NOT set it (and remove if left from older installs)
            if *is_preview {
                let _ = clsid_key.get::<u32>("DisableProcessIsolation").ok();
                let _ = clsid_key
                    .sub("") // no-op to use same helper
                    .and(Ok(()));
                let _ = clsid_key.key.delete_value("DisableProcessIsolation");
            } else {
                clsid_key.set("DisableProcessIsolation", 1u32)?;
            }

            // For preview: don't set AppID. If it exists from an older version, remove it.
            if *is_preview {
                let _ = clsid_key.key.delete_value("AppID");
                clsid_key.set("DisplayName", format!("@{}", dll_path.display()))?;
            }

            // HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32
            let inproc = clsid_key.sub(r"InprocServer32")?;
            inproc.set_default(dll_path.as_os_str())?;
            inproc.set("ThreadingModel", "Apartment")?;
            if *is_preview {
                // Optional, helps some hosts; does NOT hijack user's OpenWith choice.
                inproc.set("ProgID", blp_thumb_win::keys::DEFAULT_PROGID.to_string())?;
                inproc.set(
                    "VersionIndependentProgID",
                    blp_thumb_win::keys::DEFAULT_PROGID.to_string(),
                )?;
            }

            // HKCU\Software\Classes\CLSID\{CLSID}\Implemented Categories\{CATID}
            let _impl_cat = clsid_key.sub(&format!(r"Implemented Categories\{}", catid))?;

            // Add CLSID to Explorer-approved list
            approved.set(clsid.as_str(), *friendly)?;
        }

        // 2.2) File extension metadata for ".blp" (Default only if currently empty)
        let ext_key = Rk::open(&root, format!(r"Software\Classes\{}", ext))?;
        match ext_key.get::<String>("Content Type") {
            Ok(existing)
                if !existing.trim_matches(char::from(0)).is_empty()
                    && existing != "image/x-blp" =>
            {
                log_ui(format!(
                    "Register COM [HKCU]: skipping Content Type override (current={})",
                    existing
                ));
            }
            _ => {
                ext_key.set("Content Type", "image/x-blp")?;
            }
        }
        log_ui(format!(r"Setting value: {}\PerceivedType = image", ext));
        ext_key.set("PerceivedType", "image")?;

        match ext_key.get::<String>("") {
            Ok(existing) if !existing.trim_matches(char::from(0)).is_empty() => {
                log_ui(format!(
                    "Register COM [HKCU]: extension default already set to {}",
                    existing
                ));
            }
            _ => {
                log_ui("Register COM [HKCU]: setting extension default to WarRaft.BLP");
                ext_key.set_default(blp_thumb_win::keys::DEFAULT_PROGID)?;
            }
        }

        // 2.3) Our ProgID and its ShellEx bindings
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

        let progid_shellex = progid_key.sub(r"ShellEx")?;
        for (_, clsid, catid, _) in &classes {
            let pid_entry = progid_shellex.sub(catid)?;
            pid_entry.set_default(clsid.as_str())?;
        }

        // 2.4) Bind under extension and SystemFileAssociations
        let ext_shellex = Rk::open(&root, format!(r"Software\Classes\{}\ShellEx", ext))?;
        for (_, clsid, catid, _) in &classes {
            let entry = ext_shellex.sub(catid)?;
            entry.set_default(clsid.as_str())?;
        }

        let sfa_shellex = Rk::open(
            &root,
            format!(r"Software\Classes\SystemFileAssociations\{}\ShellEx", ext),
        )?;
        for (_, clsid, catid, _) in &classes {
            let entry = sfa_shellex.sub(catid)?;
            entry.set_default(clsid.as_str())?;
        }

        // 2.5) Explorer handler lists
        let thumb_handlers = Rk::open(
            &root,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers",
        )?;
        thumb_handlers.set(ext, thumb_clsid.as_str())?;

        let preview_handlers = Rk::open(
            &root,
            r"Software\Microsoft\Windows\CurrentVersion\PreviewHandlers",
        )?;
        preview_handlers.set(
            preview_clsid.as_str(),
            blp_thumb_win::keys::PREVIEW_FRIENDLY_NAME,
        )?;
    }

    // 3) Explorer thumbnail settings (best-effort; safe defaults for previews/thumbnails)
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

    // 4) Nudge the shell about association changes (safe to call per-user)
    notify_shell_assoc("install");

    log_ui("Installed in HKCU. Use 'Restart Explorer' to refresh thumbnails.");
    Ok(())
}

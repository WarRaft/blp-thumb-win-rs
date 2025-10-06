use crate::DLL_BYTES;
use crate::utils::notify_shell_assoc::notify_shell_assoc;
use crate::utils::regedit::Rk;
use blp_thumb_win::log::log_ui;
use blp_thumb_win::utils::guid::GuidExt;
use blp_thumb_win::{
    CLSID_BLP_PREVIEW, CLSID_BLP_THUMB, DEFAULT_EXT, DEFAULT_PROGID, FRIENDLY_NAME,
    PREVHOST_APPID_X64, PREVIEW_FRIENDLY_NAME, SHELL_PREVIEW_HANDLER_CATID,
    SHELL_THUMB_HANDLER_CATID,
};
use std::path::PathBuf;
use std::{env, fs, io};
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

/* ============================================================================
Per-user (HKCU) registration of COM thumbnail & preview handlers for the BLP format.

No regsvr32, no System32 — we write only HKCU keys needed for Explorer to load:
- Thumbnail provider (IThumbnailProvider) is in-proc.
- Preview handler (IPreviewHandler) is hosted out-of-proc via prevhost (AppID).

Docs:
  - Thumbnail providers: https://learn.microsoft.com/windows/win32/shell/thumbnail-providers
  - Preview handlers:   https://learn.microsoft.com/windows/win32/shell/preview-handlers

Registry layout (effective, under HKCU):

Software
└─ Classes
   ├─ .blp
   │  (Default)        = WarRaft.BLP               ; only if empty
   │  Content Type     = image/x-blp
    │ PerceivedType    = image
   ├─ WarRaft.BLP                                   ; our ProgID
   │  (Default)        = BLP Thumbnail/Preview Provider
   │  └─ ShellEx
   │     ├─ {E357FCCD-A995-4576-B01F-234630154E96}  = {CLSID_BLP_THUMB}
   │     └─ {8895B1C6-B41F-4C1C-A562-0D564250836F}  = {CLSID_BLP_PREVIEW}
   └─ CLSID
      ├─ {CLSID_BLP_THUMB}
      │  (Default)     = BLP Thumbnail Provider
      │  DisableProcessIsolation = 1 (DWORD)
      │  └─ InprocServer32 → @=<dll>, ThreadingModel="Apartment"
      │  └─ Implemented Categories\{E357FCCD-...}
      └─ {CLSID_BLP_PREVIEW}
         (Default)     = BLP Preview Handler
         DisplayName   = @<dll>
         AppID         = {6D2B5079-2F0B-48DD-AB7F-97CEC514D30B}   ; x64 prevhost
         DisableProcessIsolation = 1 (DWORD)
         └─ InprocServer32 → @=<dll>, ThreadingModel="Apartment"
         └─ Implemented Categories\{8895B1C6-...}

Software\Microsoft\Windows\CurrentVersion
├─ Explorer\ThumbnailHandlers          → ".blp" = {CLSID_BLP_THUMB}
├─ PreviewHandlers                     → {CLSID_BLP_PREVIEW} = "BLP Preview Handler"
└─ Explorer\Advanced
   ShowPreviewHandlers = 1 (DWORD)
============================================================================ */

pub fn install() -> io::Result<()> {
    if let Err(err) = install_inner() {
        log_ui(format!("Install failed: {err}"));
    }
    Ok(())
}

fn install_inner() -> io::Result<()> {
    log_ui("Install (current user): start");

    // 1) Materialize embedded DLL into %LOCALAPPDATA%\blp-thumb-win
    let dll_path: PathBuf = {
        let base = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Users\Default\AppData\Local"));
        let dir = base.join("blp-thumb-win");
        fs::create_dir_all(&dir).map_err(|e| {
            log_ui(format!("Failed to create dir {}: {e}", dir.display()));
            e
        })?;
        let path = dir.join("blp_thumb_win.dll");
        log_ui(format!(
            "Writing DLL {} ({} bytes)",
            path.display(),
            DLL_BYTES.len()
        ));
        fs::write(&path, DLL_BYTES).map_err(|e| {
            log_ui(format!("Failed to write DLL {}: {e}", path.display()));
            e
        })?;
        log_ui("DLL materialized");
        path
    };

    log_ui(format!(
        "Install (current user): DLL materialized to {}",
        dll_path.display()
    ));

    // 2) COM registration under HKCU
    let root = RegKey::predef(HKEY_CURRENT_USER);

    let ext = DEFAULT_EXT; // ".blp"
    let thumb_clsid = CLSID_BLP_THUMB.to_braced_upper();
    let thumb_catid = SHELL_THUMB_HANDLER_CATID.to_braced_upper();
    let preview_clsid = CLSID_BLP_PREVIEW.to_braced_upper();
    let preview_catid = SHELL_PREVIEW_HANDLER_CATID.to_braced_upper();

    log_ui(format!(
        "Using CLSIDs: THUMB={} PREVIEW={}, CATs: THUMB={} PREVIEW={}",
        thumb_clsid, preview_clsid, thumb_catid, preview_catid
    ));

    // --- Shell Extensions\Approved (opt-in both CLSIDs)
    {
        let approved = Rk::open(
            &root,
            r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        )?;
        approved.set(&thumb_clsid, FRIENDLY_NAME)?;
        approved.set(&preview_clsid, PREVIEW_FRIENDLY_NAME)?;
    }

    // --- Thumbnail CLSID node
    {
        let cls = Rk::open(&root, format!(r"Software\Classes\CLSID\{}", &thumb_clsid))?;
        cls.set_default(FRIENDLY_NAME)?;
        cls.set("DisableProcessIsolation", 1u32)?;
        let inproc = cls.sub("InprocServer32")?;
        inproc.set_default(dll_path.as_os_str())?;
        inproc.set("ThreadingModel", "Apartment")?;
        let _ = cls.sub(&format!(r"Implemented Categories\{}", thumb_catid))?;
    }

    // --- Preview CLSID node (out-of-proc via prevhost)
    {
        let cls = Rk::open(&root, format!(r"Software\Classes\CLSID\{}", &preview_clsid))?;
        cls.set_default(PREVIEW_FRIENDLY_NAME)?;
        cls.set("DisplayName", format!("@{}", dll_path.display()))?;
        cls.set("AppID", PREVHOST_APPID_X64.to_braced_upper())?;
        cls.set("DisableProcessIsolation", 1u32)?;
        let inproc = cls.sub("InprocServer32")?;
        inproc.set_default(dll_path.as_os_str())?;
        inproc.set("ThreadingModel", "Apartment")?;
        let _ = cls.sub(&format!(r"Implemented Categories\{}", preview_catid))?;
    }

    // --- .blp file type metadata
    {
        let extk = Rk::open(&root, format!(r"Software\Classes\{}", ext))?;
        match extk.get::<String>("Content Type") {
            Ok(s) if !s.trim_matches(char::from(0)).is_empty() && s != "image/x-blp" => {
                log_ui(format!("Skip Content Type override (current={s})"));
            }
            _ => {
                extk.set("Content Type", "image/x-blp")?;
            }
        }
        log_ui(format!(r"Setting value: {}\PerceivedType = image", ext));
        extk.set("PerceivedType", "image")?;
        match extk.get::<String>("") {
            Ok(s) if !s.trim_matches(char::from(0)).is_empty() => {
                log_ui(format!("Extension default already set to {s}"));
            }
            _ => {
                extk.set_default(DEFAULT_PROGID)?;
            }
        }
    }

    // --- ProgID + ShellEx bindings (primary binding point)
    {
        let pid = Rk::open(&root, format!(r"Software\Classes\{}", DEFAULT_PROGID))?;
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
            .set_default(preview_clsid.as_str())?;
    }

    // --- Bind also under .blp and SystemFileAssociations\.blp (secondary binding points)
    {
        let ext_sx = Rk::open(&root, format!(r"Software\Classes\{}\ShellEx", ext))?;
        ext_sx
            .sub(&thumb_catid)?
            .set_default(thumb_clsid.as_str())?;
        ext_sx
            .sub(&preview_catid)?
            .set_default(preview_clsid.as_str())?;

        let sfa_sx = Rk::open(
            &root,
            format!(r"Software\Classes\SystemFileAssociations\{}\ShellEx", ext),
        )?;
        sfa_sx
            .sub(&thumb_catid)?
            .set_default(thumb_clsid.as_str())?;
        sfa_sx
            .sub(&preview_catid)?
            .set_default(preview_clsid.as_str())?;
    }

    // --- Explorer handler lists
    Rk::open(
        &root,
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers",
    )?
    .set(ext, thumb_clsid.as_str())?;
    Rk::open(
        &root,
        r"Software\Microsoft\Windows\CurrentVersion\PreviewHandlers",
    )?
    .set(preview_clsid.as_str(), PREVIEW_FRIENDLY_NAME)?;

    // --- Enable Preview Pane handlers globally for this user (quality-of-life toggles)
    if let Ok((adv, _)) =
        root.create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")
    {
        let _ = adv.set_value("ShowPreviewHandlers", &1u32);
        let _ = adv.set_value("IconsOnly", &0u32);
        let _ = adv.set_value("DisableThumbnails", &0u32);
        let _ = adv.set_value("DisableThumbnailCache", &0u32);
        let _ = adv.set_value("DisableThumbnailsOnNetworkFolders", &0u32);
    }

    // 3) Notify Explorer that associations changed (refresh caches)
    notify_shell_assoc("install");
    log_ui("Installed in HKCU. Use 'Restart Explorer' to refresh thumbnails.");
    Ok(())
}

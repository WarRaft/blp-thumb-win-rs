use crate::DLL_BYTES;
use crate::utils::notify_shell_assoc::notify_shell_assoc;
use crate::utils::regedit::Rk;
use blp_thumb_win::log::log;
use blp_thumb_win::utils::guid::GuidExt;
use blp_thumb_win::{
    CLSID_BLP_PREVIEW, CLSID_BLP_THUMB, DEFAULT_EXT, DEFAULT_PROGID, FRIENDLY_NAME,
    PREVIEW_FRIENDLY_NAME, SHELL_PREVIEW_HANDLER_CATID, SHELL_THUMB_HANDLER_CATID,
};
use std::path::PathBuf;
use std::{env, fs, io};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};

/// Детерминированная установка в HKCU (x64), строго OUT-OF-PROC превью (prevhost.exe).
/// - Preview CLSID: AppID = {тот же GUID}, InprocServer32 = dll, ThreadingModel="Both"
/// - AppID\{GUID}\DllSurrogate = "prevhost.exe" (REG_SZ)
/// - Никаких AppID\prevhost.exe, никаких DisableProcessIsolation для превью
/// - Thumbnail: DisableProcessIsolation=1, ThreadingModel="Apartment"
/// - Полный pre-clean всех наших ключей перед записью
pub fn install() -> io::Result<()> {
    if let Err(err) = install_inner() {
        log(format!("Install failed: {err}"));
    }
    Ok(())
}

fn install_inner() -> io::Result<()> {
    log("Install (current user, x64, out-of-proc preview): start");

    // 0) Материализуем DLL в %LOCALAPPDATA%\blp-thumb-win\blp_thumb_win.dll
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
        log(format!(
            "Writing DLL {} ({} bytes)",
            path.display(),
            DLL_BYTES.len()
        ));
        fs::write(&path, DLL_BYTES).map_err(|e| {
            log(format!("Failed to write DLL {}: {e}", path.display()));
            e
        })?;
        log("DLL materialized");
        path
    };

    let root = RegKey::predef(HKEY_CURRENT_USER);
    let ext = DEFAULT_EXT; // ".blp"
    let progid = DEFAULT_PROGID; // ProgID для .blp

    let thumb_clsid = CLSID_BLP_THUMB.to_braced_upper();
    let thumb_catid = SHELL_THUMB_HANDLER_CATID.to_braced_upper();
    let preview_clsid = CLSID_BLP_PREVIEW.to_braced_upper();
    let preview_catid = SHELL_PREVIEW_HANDLER_CATID.to_braced_upper();

    // Используем сам GUID превью как AppID (это нормальная схема)
    let appid = preview_clsid.clone();

    log(format!(
        "Using CLSIDs: THUMB={} PREVIEW={}, CATs: THUMB={} PREVIEW={}, AppID={}",
        thumb_clsid, preview_clsid, thumb_catid, preview_catid, appid
    ));

    // Утилиты удаления
    let del_tree = |path: &str| -> io::Result<()> {
        match root.delete_subkey_all(path) {
            Ok(()) => log(format!("Pre-clean: removed {}", path)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log(format!("Pre-clean: missing {}", path))
            }
            Err(e) => return Err(e),
        }
        Ok(())
    };
    let del_value = |key_path: &str, value_name: &str| -> io::Result<()> {
        match root.open_subkey_with_flags(key_path, KEY_READ | KEY_SET_VALUE) {
            Ok(key) => match key.delete_value(value_name) {
                Ok(()) => log(format!(
                    "Pre-clean: removed value {}\\{}",
                    key_path, value_name
                )),
                Err(e) if e.kind() == io::ErrorKind::NotFound => log(format!(
                    "Pre-clean: value missing {}\\{}",
                    key_path, value_name
                )),
                Err(e) => return Err(e),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log(format!("Pre-clean: missing {}", key_path))
            }
            Err(e) => return Err(e),
        }
        Ok(())
    };

    // 1) ПОЛНАЯ зачистка перед записью
    log("Pre-clean: start");

    // CLSID ветки
    del_tree(&format!(r"Software\Classes\CLSID\{}", thumb_clsid))?;
    del_tree(&format!(r"Software\Classes\CLSID\{}", preview_clsid))?;

    // AppID ветки (наш AppID и лишний prevhost.exe)
    del_tree(&format!(r"Software\Classes\AppID\{}", appid))?;
    del_tree(r"Software\Classes\AppID\prevhost.exe")?;

    // ShellEx привязки: под расширением, ProgID и SFA\.blp
    del_tree(&format!(
        r"Software\Classes\{}\ShellEx\{}",
        ext, thumb_catid
    ))?;
    del_tree(&format!(
        r"Software\Classes\{}\ShellEx\{}",
        ext, preview_catid
    ))?;
    del_tree(&format!(
        r"Software\Classes\{}\ShellEx\{}",
        progid, thumb_catid
    ))?;
    del_tree(&format!(
        r"Software\Classes\{}\ShellEx\{}",
        progid, preview_catid
    ))?;
    del_tree(&format!(
        r"Software\Classes\SystemFileAssociations\{}\ShellEx\{}",
        ext, thumb_catid
    ))?;
    del_tree(&format!(
        r"Software\Classes\SystemFileAssociations\{}\ShellEx\{}",
        ext, preview_catid
    ))?;

    // .blp\PersistentHandler — удалить, чтобы не перехватывал обработку
    del_tree(&format!(r"Software\Classes\{}\PersistentHandler", ext))?;

    // CLSID\Preview\PersistentAddinsRegistered — выпиливаем (не нужно)
    del_tree(&format!(
        r"Software\Classes\CLSID\{}\PersistentAddinsRegistered",
        preview_clsid
    ))?;

    // Списки Explorer (удаляем записи и запишем заново)
    del_value(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailHandlers",
        ext,
    )?;
    del_value(
        r"Software\Microsoft\Windows\CurrentVersion\PreviewHandlers",
        preview_clsid.as_str(),
    )?;

    // Shell Extensions Approved (удаляем наши строки)
    del_value(
        r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        thumb_clsid.as_str(),
    )?;
    del_value(
        r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        preview_clsid.as_str(),
    )?;

    log("Pre-clean: done");

    // 2) Одобряем расширения (HKCU)
    {
        log("Approving shell extensions");
        let approved = Rk::open(
            &root,
            r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        )?;
        approved.set(&thumb_clsid, FRIENDLY_NAME)?;
        approved.set(&preview_clsid, PREVIEW_FRIENDLY_NAME)?;
    }

    // 3) Thumbnail CLSID (IN-PROC thumbnails: OK для Explorer)
    {
        log("Registering Thumbnail CLSID tree");
        let cls = Rk::open(&root, format!(r"Software\Classes\CLSID\{}", &thumb_clsid))?;
        cls.set_default(FRIENDLY_NAME)?;
        cls.set("DisableProcessIsolation", 1u32)?; // thumbs — в процессе explorer
        let inproc = cls.sub("InprocServer32")?;
        inproc.set_default(dll_path.as_os_str())?;
        inproc.set("ThreadingModel", "Apartment")?;
        let _ = cls.sub(&format!(r"Implemented Categories\{}", thumb_catid))?;
    }

    // 4) Preview CLSID (STRICT OUT-OF-PROC)
    {
        log("Registering Preview CLSID tree (OUT-OF-PROC via prevhost.exe)");
        let cls = Rk::open(&root, format!(r"Software\Classes\CLSID\{}", &preview_clsid))?;
        cls.set_default(PREVIEW_FRIENDLY_NAME)?;
        cls.set("DisplayName", format!("@{}", dll_path.display()))?;

        // Обязательно InprocServer32 (хоть он и грузится в суррогате), ThreadingModel="Both"
        let inproc = cls.sub("InprocServer32")?;
        inproc.set_default(dll_path.as_os_str())?;
        inproc.set("ThreadingModel", "Both")?;

        // Категория превью
        let _ = cls.sub(&format!(r"Implemented Categories\{}", preview_catid))?;

        // НИКАКОГО DisableProcessIsolation у превью
        let _ = cls.delete_value("DisableProcessIsolation");

        // Ставим AppID = тот же GUID, что и CLSID превью
        cls.set("AppID", appid.as_str())?;
    }

    // 5) AppID → prevhost.exe (REG_SZ, БЕЗ AppID\prevhost.exe)
    {
        log("Configuring AppID -> prevhost.exe (REG_SZ)");
        let appid_path = format!(r"Software\Classes\AppID\{}", appid);
        // Полностью пересоздадим ветку, чтобы гарантированно сбросить типы значений
        let _ = del_tree(&appid_path);
        let appid_key = Rk::open(&root, &appid_path)?;
        appid_key.set_default("Preview Handler Surrogate Host")?;
        // Критично: REG_SZ и именно "prevhost.exe"
        appid_key.set("DllSurrogate", "prevhost.exe")?;

        // На всякий — выпилим возможные хвосты
        let _ = del_tree(r"Software\Classes\AppID\prevhost.exe");
    }

    // 6) .blp метаданные (без PersistentHandler)
    {
        log("Writing .blp file-type metadata (no PersistentHandler)");
        let extk = Rk::open(&root, format!(r"Software\Classes\{}", ext))?;
        // Content Type
        match extk.get::<String>("Content Type") {
            Ok(s) if !s.trim_matches(char::from(0)).is_empty() && s != "image/x-blp" => {
                // если уже что-то стоит и не наше — не трогаем
                log(format!("Skip Content Type override (current={s})"));
            }
            _ => {
                extk.set("Content Type", "image/x-blp")?;
            }
        }
        extk.set("PerceivedType", "image")?;
        // Default ProgID
        extk.set_default(progid)?;
        // Гарантированно удалим PersistentHandler ещё раз
        let _ = root.delete_subkey_all(&format!(r"Software\Classes\{}\PersistentHandler", ext));
    }

    // 7) ProgID + ShellEx привязки
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
            .set_default(preview_clsid.as_str())?;
    }

    // 8) Дублируем привязки под .blp и SFA\.blp (Explorer смотрит в оба места)
    {
        log("Binding ShellEx under .blp and SystemFileAssociations");
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

    // 9) Списки хендлеров в Explorer
    {
        log("Updating Explorer handler lists");
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
    }

    // 10) Удобные флаги Explorer (не критично, но помогает)
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

    // 11) Уведомляем Explorer
    notify_shell_assoc("install");
    log("Installed in HKCU (x64, out-of-proc). Restart Explorer to refresh.");
    Ok(())
}

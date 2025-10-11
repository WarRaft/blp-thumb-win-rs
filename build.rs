// Windows resource pipeline for the *installer phase only*.
//
// What this does:
// 1) Runs only on Windows targets AND only when env BLP_INSTALLER=1 is set.
// 2) Re-run trigger is a single text file (log). Your outer script appends a timestamp to it.
// 3) If assets/generated/app.ico exists -> reuse it;
//    else if assets/icon.png exists -> generate a multi-size ICO once.
// 4) Always attempt to embed VERSIONINFO (from Cargo package env) and ICON (if present).
// 5) No cargo warnings: all messages go to the log file (BLP_BUILD_REPORT or assets/build-report.txt).
// 6) We do NOT probe or set resource compilers here. winresource crate uses RC/windres/llvm-rc
//    as configured by your toolchain/.cargo config. If it's missing, we log the error and continue.
//
// build-dependencies in Cargo.toml:
//   image       = "0.24"
//   ico         = "0.3"
//   winresource = "0.1"

use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn log_line(path: &Path, line: impl AsRef<str>) {
    let _ = fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")));
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let _ = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| writeln!(f, "[{}] {}", ts, line.as_ref()));
}

fn normalize_ver(v: &str) -> String {
    // Convert Cargo semver into "a.b.c.d" for VERSIONINFO.
    let mut parts = [0u16; 4];
    for (i, seg) in v.split('.').take(4).enumerate() {
        parts[i] = seg
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse::<u16>()
            .unwrap_or(0);
    }
    format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], parts[3])
}

fn generate_ico(src_png: &Path, out_ico: &Path) -> io::Result<()> {
    use ico::{IconDir, IconDirEntry, IconImage, ResourceType};
    use image::imageops::FilterType;

    if let Some(parent) = out_ico.parent() {
        fs::create_dir_all(parent)?;
    }

    let data = fs::read(src_png)?;
    let img = image::load_from_memory(&data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("decode {}: {e}", src_png.display())))?
        .to_rgba8();

    let (w, h) = (img.width(), img.height());
    if w != h {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("assets/icon.png must be square, got {w}x{h}")));
    }

    let sizes: &[u32] = &[16, 24, 32, 48, 64, 128, 256];
    let mut dir = IconDir::new(ResourceType::Icon);

    for &s in sizes {
        let resized = image::imageops::resize(&img, s, s, FilterType::Lanczos3);
        let ii = IconImage::from_rgba_data(s, s, resized.into_raw());
        let entry = IconDirEntry::encode(&ii).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("encode ico {s}px: {e}")))?;
        dir.add_entry(entry);
    }

    let mut f = fs::File::create(out_ico).map_err(|e| io::Error::new(e.kind(), format!("create {}: {e}", out_ico.display())))?;
    dir.write(&mut f)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("write {}: {e}", out_ico.display())))?;
    Ok(())
}

fn main() {
    // Resolve repo root and the log path (allow overriding via env).
    let repo = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let report_path = env::var_os("BLP_BUILD_REPORT")
        .map(PathBuf::from)
        .map(|p| if p.is_absolute() { p } else { repo.join(p) })
        .unwrap_or_else(|| repo.join("assets/build-report.txt"));

    // We always watch the log file to ensure build.rs runs when your script appends a timestamp.
    println!("cargo:rerun-if-changed={}", report_path.display());

    // Only care about Windows target and only in the installer phase.
    let is_windows_target = env::var("CARGO_CFG_TARGET_OS").ok().as_deref() == Some("windows");
    let is_installer = env::var_os("BLP_INSTALLER").is_some();
    if !is_windows_target || !is_installer {
        // No logging here to keep the file quiet when building the lib phase.
        return;
    }

    log_line(&report_path, "=== build.rs start (installer: Windows resources) ===");

    // Absolute asset paths (stable in workspaces).
    let src_png = repo.join("assets/icon.png");
    let out_ico = repo.join("assets/generated/app.ico");

    // ICO generate/reuse exactly like in the minimal working example.
    if out_ico.exists() {
        log_line(&report_path, format!("Reusing ICO: {}", out_ico.display()));
    } else if src_png.exists() {
        match generate_ico(&src_png, &out_ico) {
            Ok(_) => log_line(&report_path, format!("Generated ICO: {}", out_ico.display())),
            Err(e) => {
                log_line(&report_path, format!("ICO generation failed: kind={:?} raw={:?} msg={}", e.kind(), e.raw_os_error(), e));
                // Continue without icon.
            }
        }
    } else {
        log_line(&report_path, "No assets/icon.png found — icon embedding will be skipped.");
    }

    // VERSIONINFO + ICON from Cargo env (always attempt).
    let pkg_name = env::var("CARGO_PKG_NAME").unwrap_or_else(|_| "app".into());
    let pkg_desc = env::var("CARGO_PKG_DESCRIPTION").unwrap_or_else(|_| pkg_name.clone());
    let pkg_ver = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let ver4 = normalize_ver(&pkg_ver);
    let bin_name = env::var("CARGO_BIN_NAME").unwrap_or_else(|_| pkg_name.clone());
    let authors = env::var("CARGO_PKG_AUTHORS").unwrap_or_default();
    let company = authors
        .split(':')
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("Unknown Company")
        .to_string();
    let legal = if authors.is_empty() { format!("© {}", company) } else { format!("© {}", authors) };

    let mut res = winresource::WindowsResource::new();
    if out_ico.exists() {
        if let Some(p) = out_ico.to_str() {
            res.set_icon(p);
            log_line(&report_path, format!("ICON set = {}", p));
        }
    } else {
        log_line(&report_path, "ICON set = <none>");
    }
    res.set("FileDescription", &pkg_desc);
    res.set("ProductName", &pkg_name);
    res.set("CompanyName", &company);
    res.set("InternalName", &bin_name);
    res.set("OriginalFilename", &format!("{}.exe", bin_name));
    res.set("FileVersion", &ver4);
    res.set("ProductVersion", &ver4);
    res.set("LegalCopyright", &legal);
    res.set_language(0x0409); // en-US

    // Do not second-guess toolchain (RC/windres). If it's missing, we just log the error.
    match res.compile() {
        Ok(_) => log_line(&report_path, "Resource embedding OK (VERSIONINFO + optional ICON)."),
        Err(e) => log_line(&report_path, format!("Resource embedding error: kind={:?} raw={:?} msg={}", e.kind(), e.raw_os_error(), e)),
    }

    log_line(&report_path, "=== build.rs done ===");
}

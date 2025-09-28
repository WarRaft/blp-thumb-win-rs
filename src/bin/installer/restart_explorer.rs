use std::io;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::log_cli;

fn count_explorer_processes() -> io::Result<usize> {
    // Лёгкий способ без WMI: tasklist с фильтром по имени
    // CSV/без заголовка упрощает парсинг.
    let out = Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq explorer.exe", "/FO", "CSV", "/NH"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()?;

    if !out.status.success() {
        // Если tasklist неуспешен (редко), считаем "не знаем".
        return Ok(0);
    }

    let s = String::from_utf8_lossy(&out.stdout);
    // Каждая непустая строка CSV — это процесс explorer.exe
    let cnt = s.lines().filter(|ln| !ln.trim().is_empty()).count();

    Ok(cnt)
}

pub fn restart_explorer() -> io::Result<()> {
    log_cli("Restart Explorer: detecting running explorer.exe...");
    let before = count_explorer_processes().unwrap_or(0);
    log_cli(&format!("Restart Explorer: explorer.exe running: {before}"));

    // 1) Пытаемся завершить все экземпляры explorer.exe
    log_cli("Restart Explorer: terminating explorer.exe with taskkill /F /IM explorer.exe");
    let kill_status = Command::new("taskkill")
        .args(["/F", "/IM", "explorer.exe"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match kill_status {
        Ok(status) => {
            if status.success() {
                log_cli("Restart Explorer: taskkill exited successfully.");
            } else {
                log_cli(&format!(
                    "Restart Explorer: taskkill finished with code {:?} (may be already stopped).",
                    status.code()
                ));
            }
        }
        Err(e) => {
            log_cli(&format!(
                "Restart Explorer: taskkill failed: {e} (continuing anyway)."
            ));
        }
    }

    // 2) Ждём, пока процессы исчезнут (до 5 секунд)
    let wait_gone_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let cnt = count_explorer_processes().unwrap_or(0);
        if cnt == 0 {
            log_cli("Restart Explorer: explorer.exe is gone.");
            break;
        }
        if Instant::now() >= wait_gone_deadline {
            log_cli(&format!(
                "Restart Explorer: timeout waiting explorer.exe to exit (still {cnt}). Proceeding to start anyway."
            ));
            break;
        }
        sleep(Duration::from_millis(200));
    }

    // Небольшая пауза, чтобы проводник выгрузил shell extensions/иконки
    sleep(Duration::from_millis(300));

    // 3) Пытаемся запустить Explorer
    log_cli("Restart Explorer: launching explorer.exe (direct).");
    #[cfg(windows)]
    let creation_flags = 0x00000008 /* CREATE_NEW_PROCESS_GROUP */ | 0x00000008 /* дублируется безболезненно */;

    let started_direct = {
        let mut cmd = Command::new("explorer.exe");
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(creation_flags);
        }
        match cmd.status() {
            Ok(status) if status.success() => {
                log_cli("Restart Explorer: explorer.exe launched (direct).");
                true
            }
            Ok(status) => {
                log_cli(&format!(
                    "Restart Explorer: direct launch returned code {:?}. Will try via cmd /C start.",
                    status.code()
                ));
                false
            }
            Err(e) => {
                log_cli(&format!(
                    "Restart Explorer: direct launch failed: {e}. Will try via cmd /C start."
                ));
                false
            }
        }
    };

    if !started_direct {
        log_cli("Restart Explorer: launching via `cmd /C start \"\" explorer.exe`...");
        let via_cmd = Command::new("cmd")
            .args(["/C", "start", "", "explorer.exe"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match via_cmd {
            Ok(status) if status.success() => {
                log_cli("Restart Explorer: explorer.exe launched via cmd.");
            }
            Ok(status) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "Failed to start explorer via cmd. Exit code: {:?}",
                        status.code()
                    ),
                ));
            }
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to start explorer via cmd: {e}"),
                ));
            }
        }
    }

    // 4) Ждём, пока проводник поднимется (до 7 секунд)
    let wait_up_deadline = Instant::now() + Duration::from_secs(7);
    loop {
        let cnt = count_explorer_processes().unwrap_or(0);
        if cnt > 0 {
            log_cli(&format!(
                "Restart Explorer: explorer.exe is up (count={cnt})."
            ));
            break;
        }
        if Instant::now() >= wait_up_deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Explorer failed to start within timeout",
            ));
        }
        sleep(Duration::from_millis(250));
    }

    println!("Explorer restarted.");
    log_cli("Restart Explorer: completed successfully.");
    Ok(())
}

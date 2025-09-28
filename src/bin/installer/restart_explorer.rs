use std::io;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::log_cli;

const WAIT_EXPLORER_EXIT_MS: u64 = 5_000;
const WAIT_EXPLORER_START_MS: u64 = 5_000;
const POLL_INTERVAL_EXIT_MS: u64 = 200;
const POLL_INTERVAL_START_MS: u64 = 250;

fn count_explorer_processes() -> io::Result<usize> {
    let output = Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq explorer.exe", "/FO", "CSV", "/NH"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()?;

    if !output.status.success() {
        log_cli("Restart Explorer: tasklist finished with non-zero status; assuming 0 processes");
        return Ok(0);
    }

    let count = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();

    Ok(count)
}

pub fn restart_explorer() -> io::Result<()> {
    log_cli("Restart Explorer: begin");

    let running_before = count_explorer_processes().unwrap_or(0);
    log_cli(format!(
        "Restart Explorer: explorer.exe running before kill: {running_before}"
    ));

    log_cli("Restart Explorer: issuing taskkill /F /IM explorer.exe");
    let kill_status = Command::new("taskkill")
        .args(["/F", "/IM", "explorer.exe"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match kill_status {
        Ok(status) if status.success() => {
            log_cli("Restart Explorer: taskkill completed successfully");
        }
        Ok(status) => {
            log_cli(format!(
                "Restart Explorer: taskkill exit code {:?} (Explorer may already be stopped)",
                status.code()
            ));
        }
        Err(err) => {
            log_cli(format!(
                "Restart Explorer: taskkill failed: {err}. Continuing regardless"
            ));
        }
    }

    let exit_deadline = Instant::now() + Duration::from_millis(WAIT_EXPLORER_EXIT_MS);
    loop {
        let remaining = count_explorer_processes().unwrap_or(0);
        if remaining == 0 {
            log_cli("Restart Explorer: explorer.exe has exited");
            break;
        }
        if Instant::now() >= exit_deadline {
            log_cli(format!(
                "Restart Explorer: explorer.exe still running after timeout (count={remaining}), proceeding"
            ));
            break;
        }
        sleep(Duration::from_millis(POLL_INTERVAL_EXIT_MS));
    }

    sleep(Duration::from_millis(300));

    log_cli("Restart Explorer: launching explorer.exe (direct spawn)");
    let mut launched = false;
    match Command::new("explorer.exe")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => {
            log_cli("Restart Explorer: explorer.exe spawned successfully");
            launched = true;
            drop(child); // detach child handle
        }
        Err(err) => {
            log_cli(format!(
                "Restart Explorer: direct spawn failed: {err}. Falling back to cmd /C start"
            ));
        }
    }

    if !launched {
        log_cli("Restart Explorer: launching via cmd /C start \"\" explorer.exe");
        match Command::new("cmd")
            .args(["/C", "start", "", "explorer.exe"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => {
                log_cli("Restart Explorer: explorer.exe launched via cmd");
                drop(child);
                launched = true;
            }
            Err(err) => {
                let msg = format!("Failed to launch explorer.exe via cmd: {err}");
                log_cli(&msg);
                return Err(io::Error::new(io::ErrorKind::Other, msg));
            }
        }
    }

    if launched {
        let start_deadline = Instant::now() + Duration::from_millis(WAIT_EXPLORER_START_MS);
        loop {
            let count = count_explorer_processes().unwrap_or(0);
            if count > 0 {
                log_cli(format!(
                    "Restart Explorer: explorer.exe is running again (count={count})"
                ));
                break;
            }
            if Instant::now() >= start_deadline {
                log_cli("Restart Explorer: explorer.exe did not appear within timeout");
                break;
            }
            sleep(Duration::from_millis(POLL_INTERVAL_START_MS));
        }
    }

    println!("Explorer restarted.");
    log_cli("Restart Explorer: completed");
    Ok(())
}

use blp_thumb_win::log::log;
use std::io;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

fn count_explorer_processes() -> io::Result<usize> {
    let output = Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq explorer.exe", "/FO", "CSV", "/NH"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()?;

    if !output.status.success() {
        log("Restart Explorer: tasklist returned non-zero status; assuming 0 processes");
        return Ok(0);
    }

    let count = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();

    Ok(count)
}

pub fn restart_explorer() -> io::Result<()> {
    log("Restart Explorer: begin");

    let before = count_explorer_processes().unwrap_or(0);
    log(format!("Restart Explorer: explorer.exe running before kill: {before}"));

    let kill_status = Command::new("taskkill")
        .args(["/F", "/IM", "explorer.exe"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match kill_status {
        Ok(status) if status.success() => log("Restart Explorer: taskkill exited successfully"),
        Ok(status) => log(format!("Restart Explorer: taskkill exit code {:?} (Explorer may already be stopped)", status.code())),
        Err(err) => log(format!("Restart Explorer: taskkill failed ({err}); proceeding to launch")),
    }

    sleep(Duration::from_millis(400));

    let after_kill = count_explorer_processes().unwrap_or(0);
    log(format!("Restart Explorer: explorer.exe count after kill wait: {after_kill}"));

    log("Restart Explorer: launching explorer.exe (spawn)");
    match Command::new("explorer.exe")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => {
            log("Restart Explorer: explorer.exe spawned successfully");
            drop(child);
        }
        Err(err) => {
            log(format!("Restart Explorer: direct spawn failed ({err}); attempting via cmd /C start"));

            Command::new("cmd")
                .args(["/C", "start", "", "explorer.exe"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|start_err| {
                    log(format!("Restart Explorer: fallback start failed: {start_err}"));
                    start_err
                })?;
            log("Restart Explorer: explorer.exe launched via cmd");
        }
    }

    sleep(Duration::from_millis(250));
    let after_launch = count_explorer_processes().unwrap_or(0);
    log(format!("Restart Explorer: explorer.exe count after launch: {after_launch}"));

    log("Restart Explorer: completed");
    Ok(())
}

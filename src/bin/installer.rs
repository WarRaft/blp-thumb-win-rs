#![cfg(windows)]

use std::{env, io, io::Write};

// Embedded DLL that you copy into ./bin/ at build time.
// The EXE will re-materialize it under %LOCALAPPDATA%\blp-thumb-win\
static DLL_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/bin/blp_thumb_win.dll"
));

// Single source of truth from the library (your keys module)
use crate::actiions::dialog::{action_choose, action_execute, Action};
use blp_thumb_win::log::log_cli;

#[path = "actions/mod.rs"]
mod actiions;

#[path = "utils/mod.rs"]
mod utils;

fn main() -> io::Result<()> {
    log_cli("Installer started");
    loop {
        let (action, label) = action_choose()?;
        log_cli(format!("Menu selection: {}", label));

        if action == Action::Exit {
            log_cli("Installer exiting");
            break;
        }

        match action_execute(action) {
            Ok(()) => log_cli(format!("Action '{}' completed successfully", label)),
            Err(err) => {
                log_cli(format!("Action '{}' failed: {}", label, err));
                return Err(err);
            }
        }

        pause("\nPress Enter to return to the menu...");
    }
    Ok(())
}


fn pause(msg: &str) {
    print!("{msg}");
    let _ = io::stdout().flush();
    // Use read_line to avoid printing localized messages from external tools
    let mut _buf = String::new();
    let _ = io::stdin().read_line(&mut _buf);
}
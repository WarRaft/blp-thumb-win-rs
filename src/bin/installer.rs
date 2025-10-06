#![cfg(windows)]

use blp_thumb_win::log::log;
use std::{env, io, io::Write};

// Embedded DLL that you copy into ./bin/ at build time.
// The EXE will re-materialize it under %LOCALAPPDATA%\blp-thumb-win\
static DLL_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/bin/blp_thumb_win.dll"
));

// Single source of truth from the library (your keys module)
use crate::actiions::dialog::{Action, action_choose, action_execute};

#[path = "actions/mod.rs"]
mod actiions;

#[path = "utils/mod.rs"]
mod utils;

fn main() -> io::Result<()> {
    log("Installer started");
    loop {
        let (action, label) = action_choose()?;
        log(format!("Menu selection: {}", label));

        if action == Action::Exit {
            log("Installer exiting");
            break;
        }

        match action_execute(action) {
            Ok(()) => log(format!("Action '{}' completed successfully", label)),
            Err(err) => {
                log(format!("Action '{}' failed: {}", label, err));
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

// src/logging.rs
//! Minimal logging for shell extensions via OutputDebugStringW.
//! - OFF by default.
//! - One-time init from HKCU\Software\blp-thumb-win\LogEnabled (DWORD 0/1).
//! - State then lives in-process (no further registry reads).
//! - toggle_logging()/log_toggle() flips the state AND persists it to registry.
//! - Public API: log_enabled(), toggle_logging(), log_toggle(), log(...), logf!().

use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, Ordering};
use std::{io, io::Write, sync::Once};

use windows::{
    Win32::System::Console::GetConsoleWindow,
    Win32::System::Diagnostics::Debug::OutputDebugStringW,
    Win32::System::Threading::GetCurrentThreadId, core::PCWSTR,
};
// <— добавили

use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

// Registry location (per-user)
const REG_SUBKEY: &str = r"Software\blp-thumb-win";
const REG_VALUE: &str = "LogEnabled";

// Process-local on/off flag
static LOG_ON: AtomicBool = AtomicBool::new(false);

// One-time init guard
static INIT_ONCE: Once = Once::new();

/// Returns current logging state (initializes once from registry on first call).
#[inline]
pub fn log_enabled() -> bool {
    ensure_init();
    LOG_ON.load(Ordering::Relaxed)
}

/// Flips logging state AND persists it to HKCU (no args).
#[inline]
pub fn toggle_logging() {
    ensure_init();
    let new = !LOG_ON.load(Ordering::Relaxed);
    LOG_ON.store(new, Ordering::Relaxed);
    // Persist to registry (best-effort)
    let _ = write_registry_flag(new);
    ods_immediate(if new {
        "[blp-thumb] logging: ON"
    } else {
        "[blp-thumb] logging: OFF"
    });

    if new {
        println!(
            "[blp-thumb] Logging enabled.\n\
             To view debug output, use Sysinternals DebugView:\n\
             https://learn.microsoft.com/en-us/sysinternals/downloads/debugview"
        );
    }
}

#[inline]
fn console_attached() -> bool {
    let hwnd = unsafe { GetConsoleWindow() };
    !hwnd.0.is_null()
}

/// Logs a message to STDOUT (if a console is attached) and to DebugView (if enabled).
#[inline]
pub fn log(message: impl AsRef<str>) {
    let msg = message.as_ref();

    if console_attached() {
        let _ = std::io::Write::write_all(&mut io::stdout(), msg.as_bytes());
        let _ = std::io::Write::write_all(&mut io::stdout(), b"\n");
        let _ = io::stdout().flush();
    }

    // 2) Фильтр по флагу для OutputDebugStringW
    if !log_enabled() {
        return;
    }

    let pid = std::process::id();
    let tid = unsafe { GetCurrentThreadId() };

    // Префикс для DebugView
    let mut line = String::with_capacity(32 + msg.len());
    let _ = write!(line, "[{}:{}] [blp-thumb] {}", pid, tid, msg);
    ods_immediate(&line);
}

/// Internal: formatting sink used by logf! macro.
#[doc(hidden)]
#[inline]
pub fn __log_format(args: core::fmt::Arguments<'_>) {
    if !log_enabled() {
        return;
    }
    let pid = std::process::id();
    let tid = unsafe { GetCurrentThreadId() };

    let mut line = String::with_capacity(64);
    let _ = write!(line, "[{}:{}] [blp-thumb] ", pid, tid);
    let _ = line.write_fmt(args);
    ods_immediate(&line);
}

/// Internal: ensure one-time init from registry.
#[inline]
fn ensure_init() {
    INIT_ONCE.call_once(|| {
        let enabled = read_registry_flag_once().unwrap_or(false);
        LOG_ON.store(enabled, Ordering::Relaxed);
        // Announce init state (always visible in DebugView)
        ods_immediate(if enabled {
            "[blp-thumb] logging init: HKCU\\Software\\blp-thumb-win\\LogEnabled = 1"
        } else {
            "[blp-thumb] logging init: HKCU\\Software\\blp-thumb-win\\LogEnabled = 0 (or missing)"
        });
    });
}

/// Internal: read HKCU\Software\blp-thumb-win\LogEnabled (DWORD 0/1).
/// Returns Ok(bool) if successfully read, Err otherwise (treat as OFF).
fn read_registry_flag_once() -> Result<bool, ()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = match hkcu.open_subkey(REG_SUBKEY) {
        Ok(k) => k,
        Err(_) => return Err(()),
    };
    match key.get_value::<u32, _>(REG_VALUE) {
        Ok(v) => Ok(v != 0),
        Err(_) => Err(()),
    }
}

/// Internal: write HKCU\Software\blp-thumb-win\LogEnabled (DWORD 0/1).
/// Creates the subkey if missing. Best-effort: returns Err on failure.
fn write_registry_flag(on: bool) -> Result<(), ()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _disp) = hkcu.create_subkey(REG_SUBKEY).map_err(|_| ())?;
    key.set_value(REG_VALUE, &(if on { 1u32 } else { 0u32 }))
        .map_err(|_| ())
}

/// Internal: emit a NUL-terminated UTF-16 string to OutputDebugStringW.
#[inline]
fn ods_immediate(s: &str) {
    let mut wide = Vec::with_capacity(s.len() + 1);
    wide.extend(s.encode_utf16());
    wide.push(0);
    unsafe {
        OutputDebugStringW(PCWSTR(wide.as_ptr()));
    }
}

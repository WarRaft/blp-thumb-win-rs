use blp_thumb_win::log::log_cli;
use windows::Win32::UI::Shell::{SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify};

pub fn notify_shell_assoc(reason: &str) {
    log_cli(format!(
        "Shell notify ({reason}): calling SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST)"
    ));
    unsafe {
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None);
    }
    log_cli("Shell notify: done");
}

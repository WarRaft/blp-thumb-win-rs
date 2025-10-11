use blp_thumb_win::log::log;
use windows::Win32::UI::Shell::{SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify};

pub fn notify_shell_assoc(reason: &str) {
    log(format!("Shell notify ({reason}): calling SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST)"));
    unsafe {
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None);
    }
    log("Shell notify: done");
}

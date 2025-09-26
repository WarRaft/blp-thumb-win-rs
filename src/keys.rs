//! Common constants for BLP Thumbnail Provider registration.
//! Shared between the COM DLL and the installer. No duplicated string CLSIDs.

use windows::core::GUID;

/// Shell Thumbnail Provider category (Implemented Categories + ShellEx binding).
/// - HKCR\CLSID\{CLSID}\Implemented Categories\{SHELL_THUMB_HANDLER_CATID}
/// - HKCR\<.ext | ProgID>\ShellEx\{SHELL_THUMB_HANDLER_CATID} = {CLSID}
pub const SHELL_THUMB_HANDLER_CATID: GUID = GUID::from_u128(0xE357FCCD_A995_4576_B01F_234630154E96);

/// CLSID of this provider. Must match DLL exports and registry bindings.
pub const CLSID_BLP_THUMB: GUID = GUID::from_u128(0xB2E9A1F3_7C5D_4E2B_96A1_2C3D4E5F6A7B);

/// ProgID bound to `.blp` (HKCR\WarRaft.BLP; HKCR\.blp -> WarRaft.BLP).
pub const DEFAULT_PROGID: &str = "WarRaft.BLP";

/// File extension this provider supports.
pub const DEFAULT_EXT: &str = ".blp";

/// Human-friendly provider name (HKCR\CLSID\{CLSID}\(Default)).
pub const FRIENDLY_NAME: &str = "BLP Thumbnail Provider";

/// ----- Helpers (format GUIDs for registry values) -----

/// Returns `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` (uppercase, with braces).
#[inline]
pub fn guid_braced_upper(g: &GUID) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7]
    )
}

/// `{CLSID_BLP_THUMB}` as a braced uppercase string (for registry writes).
#[inline]
pub fn clsid_str() -> String {
    guid_braced_upper(&CLSID_BLP_THUMB)
}

/// `{SHELL_THUMB_HANDLER_CATID}` as a braced uppercase string.
#[inline]
pub fn shell_thumb_handler_catid_str() -> String {
    guid_braced_upper(&SHELL_THUMB_HANDLER_CATID)
}

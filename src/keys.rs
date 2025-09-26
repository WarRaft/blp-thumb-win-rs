//! Common constants for BLP Thumbnail Provider registration.
//! Shared between COM DLL (lib.rs) and installer (bin/installer.rs).

use windows::core::GUID;

/// Fixed Windows Shell Thumbnail Provider handler category
pub const SHELL_THUMB_HANDLER_CATID: &str = "{e357fccd-a995-4576-b01f-234630154e96}";

/// !!! Replace with your real CLSID (must match in DLL + registry) !!!
pub const CLSID_BLP_THUMB_STR: &str = "{12345678-1234-1234-1234-1234567890ab}";

/// Same CLSID as GUID type (for DLL implementation)
pub const CLSID_BLP_THUMB: GUID = GUID::from_u128(0x12345678_1234_1234_1234_1234567890ab);

/// ProgID that .blp extension is bound to
pub const DEFAULT_PROGID: &str = "WarRaft.BLP";

/// File extension we support
pub const DEFAULT_EXT: &str = ".blp";

/// Friendly name shown in registry under CLSID
pub const FRIENDLY_NAME: &str = "BLP Thumbnail Provider";

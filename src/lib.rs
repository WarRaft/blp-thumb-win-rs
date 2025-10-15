mod class_factory;
mod dll_export;
pub mod log;
mod thumbnail_provider;
pub mod utils;

#[cfg(not(target_pointer_width = "64"))]
compile_error!("blp-thumb-win must be built for 64-bit targets");

use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use windows::core::HRESULT;

const CLASS_E_CLASSNOTAVAILABLE: HRESULT = HRESULT(0x80040111u32 as i32);

static DLL_LOCK_COUNT: AtomicU32 = AtomicU32::new(0);

#[derive(Default)]
struct ProviderState {
    path_utf8: Option<String>,
    stream_data: Option<Arc<[u8]>>,
}

/// Common constants for BLP Thumbnail Provider registration.
/// Shared between the COM DLL and the installer. No duplicated string CLSIDs.
use windows::core::GUID;

/// Shell Thumbnail Provider category (Implemented Categories + ShellEx binding).
/// - HKCR\CLSID\{CLSID}\Implemented Categories\{SHELL_THUMB_HANDLER_CATID}
/// - HKCR\<.ext | ProgID>\ShellEx\{SHELL_THUMB_HANDLER_CATID} = {CLSID}
pub const SHELL_THUMB_HANDLER_CATID: GUID = GUID::from_u128(0xE357FCCD_A995_4576_B01F_234630154E96);

/// Shell Preview Handler category.
/// - HKCR\\CLSID\\{CLSID}\\Implemented Categories\\{SHELL_PREVIEW_HANDLER_CATID}
/// - HKCR\\<.ext | ProgID>\\ShellEx\\{SHELL_PREVIEW_HANDLER_CATID} = {CLSID}
pub const SHELL_PREVIEW_HANDLER_CATID: GUID = GUID::from_u128(0x8895B1C6_B41F_4C1C_A562_0D564250836F);

/// CLSID of this provider. Must match DLL exports and registry bindings.
pub const CLSID_BLP_THUMB: GUID = GUID::from_u128(0xB2E9A1F3_7C5D_4E2B_96A1_2C3D4E5F6A7B);

/// ProgID bound to `.blp` (HKCR\WarRaft.BLP; HKCR\.blp -> WarRaft.BLP).
pub const DEFAULT_PROGID: &str = "WarRaft.BLP";

/// File extension this provider supports.
pub const DEFAULT_EXT: &str = ".blp";

/// Human-friendly provider name (HKCR\CLSID\{CLSID}\(Default)).
pub const FRIENDLY_NAME: &str = "BLP Thumbnail Provider";

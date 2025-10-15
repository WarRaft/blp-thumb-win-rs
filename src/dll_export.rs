use crate::class_factory::BlpClassFactory;
use crate::utils::guid::GuidExt;
use crate::{CLASS_E_CLASSNOTAVAILABLE, CLSID_BLP_THUMB, DLL_LOCK_COUNT};
// .to_braced_upper() for &GUID

use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::Ordering;

use crate::log::log;
use windows::Win32::Foundation::{E_NOINTERFACE, E_POINTER, S_FALSE, S_OK};
use windows::Win32::System::Com::{APTTYPE, APTTYPEQUALIFIER, CoGetApartmentType, IClassFactory};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, IsWow64Process};
use windows_core::{BOOL, GUID, HRESULT, IUnknown, Interface};

fn log_host_environment() {
    // PID/TID
    let pid = unsafe { GetCurrentProcessId() };
    let tid = unsafe { GetCurrentThreadId() };

    // Путь до host EXE
    let mut buf = [0u16; 260]; // можно больше (например 32768) если хочешь
    let n = unsafe { GetModuleFileNameW(None, &mut buf) } as usize; // <-- ключевая правка
    let exe = if n > 0 { String::from_utf16_lossy(&buf[..n]) } else { "<unknown>".to_string() };

    // WOW64 vs native
    let mut wow = BOOL(0);
    let arch = unsafe {
        match IsWow64Process(GetCurrentProcess(), &mut wow) {
            Ok(()) => {
                if wow.as_bool() {
                    "WOW64 (32-bit host on 64-bit OS)"
                } else {
                    "native"
                }
            }
            Err(e) => {
                let _ = log(format!("IsWow64Process failed: {:?}", e));
                "unknown"
            }
        }
    };

    // COM apartment
    let (mut apt, mut qual) = (APTTYPE(0), APTTYPEQUALIFIER(0));
    let (apt_s, qual_s) = unsafe {
        match CoGetApartmentType(&mut apt, &mut qual) {
            Ok(_) => (format!("{:?}", apt), format!("{:?}", qual)),
            Err(_) => ("unknown".into(), "unknown".into()),
        }
    };

    let _ = log(format!("Host: exe='{}' pid={} tid={} arch={} apartment={} qual={}", exe, pid, tid, arch, apt_s, qual_s));
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllGetClassObject(rclsid: *const GUID, riid: *const GUID, ppv: *mut *mut c_void) -> HRESULT {
    log("DllGetClassObject called");
    log_host_environment();

    let _ = log(format!("DllGetClassObject args: rclsid_ptr={:?} riid_ptr={:?} ppv_ptr={:?}", rclsid, riid, ppv));

    // Pretty-print CLSID/IID
    if let Some(g) = unsafe { rclsid.as_ref() } {
        let name = if *g == CLSID_BLP_THUMB {
            "CLSID_BLP_THUMB"
        } else {
            "CLSID(unknown)"
        };
        let _ = log(format!("DllGetClassObject rclsid={} {}", name, g.to_braced_upper()));
    } else {
        let _ = log("DllGetClassObject rclsid=NULL");
    }
    if let Some(g) = unsafe { riid.as_ref() } {
        let name = if *g == IClassFactory::IID {
            "IClassFactory"
        } else if *g == IUnknown::IID {
            "IUnknown"
        } else {
            "IID(unknown)"
        };
        let _ = log(format!("DllGetClassObject riid={} {}", name, g.to_braced_upper()));
    } else {
        let _ = log("DllGetClassObject riid=NULL");
    }

    // Validate ppv
    if ppv.is_null() {
        let _ = log("DllGetClassObject: ppv=NULL -> E_POINTER");
        return E_POINTER;
    }
    unsafe {
        *ppv = null_mut();
    }

    // Validate rclsid and pick factory
    let r = match unsafe { rclsid.as_ref() } {
        Some(r) => *r,
        None => {
            let _ = log("DllGetClassObject: rclsid=NULL -> E_POINTER");
            return E_POINTER;
        }
    };

    let factory = if r == CLSID_BLP_THUMB {
        let _ = log("DllGetClassObject: class match -> Thumbnail provider");
        BlpClassFactory::new()
    } else {
        let _ = log("DllGetClassObject: CLASS_E_CLASSNOTAVAILABLE");
        return CLASS_E_CLASSNOTAVAILABLE;
    };

    // Validate riid
    let requested_iid = match unsafe { riid.as_ref() } {
        Some(i) => *i,
        None => {
            let _ = log("DllGetClassObject: riid=NULL -> E_POINTER");
            return E_POINTER;
        }
    };

    // Only IClassFactory/IUnknown are supported here
    let cf: IClassFactory = factory.into();
    if requested_iid == IClassFactory::IID || requested_iid == IUnknown::IID {
        unsafe {
            *ppv = cf.into_raw();
        }
        let _ = log(format!("DllGetClassObject: returning IClassFactory -> S_OK, out ppv={:?}", unsafe { *ppv }));
        S_OK
    } else {
        let _ = log(format!("DllGetClassObject: unsupported riid {} -> E_NOINTERFACE", requested_iid.to_braced_upper()));
        E_NOINTERFACE
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    log("DllCanUnloadNow called");
    let locks = DLL_LOCK_COUNT.load(Ordering::SeqCst);
    let hr = if locks == 0 { S_OK } else { S_FALSE };
    log(format!("DllCanUnloadNow: DLL_LOCK_COUNT={} -> {}", locks, if locks == 0 { "S_OK" } else { "S_FALSE" }));
    hr
}

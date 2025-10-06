use crate::class_factory::{BlpClassFactory, ProviderKind};
use crate::{
    CLASS_E_CLASSNOTAVAILABLE, CLSID_BLP_PREVIEW, CLSID_BLP_THUMB, DLL_LOCK_COUNT, log_desktop,
};
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::Ordering;
use windows::Win32::Foundation::{E_NOINTERFACE, E_POINTER, S_FALSE, S_OK};
use windows::Win32::System::Com::IClassFactory;
use windows_core::{GUID, HRESULT, IUnknown, Interface};

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    if let Err(err) = log_desktop("DllGetClassObject called") {
        eprintln!("[dll log] {err}");
    }
    unsafe {
        if ppv.is_null() {
            return E_POINTER;
        }
        *ppv = null_mut();

        if rclsid.is_null() {
            return E_POINTER;
        }

        let factory = if *rclsid == CLSID_BLP_THUMB {
            BlpClassFactory::new(ProviderKind::Thumbnail)
        } else if *rclsid == CLSID_BLP_PREVIEW {
            BlpClassFactory::new(ProviderKind::Preview)
        } else {
            return CLASS_E_CLASSNOTAVAILABLE;
        };

        let cf: IClassFactory = factory.into();

        if riid.is_null() {
            return E_POINTER;
        }
        if *riid == IClassFactory::IID || *riid == IUnknown::IID {
            *ppv = cf.into_raw();
            S_OK
        } else {
            E_NOINTERFACE
        }
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    if let Err(err) = log_desktop("DllCanUnloadNow called") {
        eprintln!("[dll log] {err}");
    }
    if DLL_LOCK_COUNT.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}

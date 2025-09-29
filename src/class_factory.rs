use crate::DLL_LOCK_COUNT;
use crate::log_desktop;
use crate::thumbnail_provider::BlpThumbProvider;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::Ordering;
use windows::Win32::System::Com::IClassFactory_Impl;
use windows_core::{BOOL, GUID, IUnknown};
use windows_implement::implement;

#[implement(windows::Win32::System::Com::IClassFactory)]
pub struct BlpClassFactory;

impl IClassFactory_Impl for BlpClassFactory_Impl {
    #[allow(non_snake_case)]
    fn CreateInstance(
        &self,
        _outer: windows::core::Ref<'_, IUnknown>, // <-- ВАЖНО: Ref<'_, IUnknown>
        riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> windows::core::Result<()> {
        use windows::Win32::Foundation::{E_NOINTERFACE, E_POINTER};
        use windows::Win32::UI::Shell::PropertiesSystem::{
            IInitializeWithFile, IInitializeWithStream,
        };
        use windows::Win32::UI::Shell::{IInitializeWithItem, IThumbnailProvider};
        use windows::core::{Error, IUnknown, Interface};

        if ppv.is_null() || riid.is_null() {
            return Err(Error::from(E_POINTER));
        }
        unsafe {
            *ppv = null_mut();
        }

        if let Err(err) = log_desktop("BlpClassFactory::CreateInstance called") {
            eprintln!("[dll log] {err}");
        }

        let unk: IUnknown = BlpThumbProvider::new().into();

        unsafe {
            if *riid == <IThumbnailProvider as Interface>::IID {
                *ppv = unk.cast::<IThumbnailProvider>()?.into_raw();
                return Ok(());
            }
            if *riid == <IInitializeWithItem as Interface>::IID {
                *ppv = unk.cast::<IInitializeWithItem>()?.into_raw();
                return Ok(());
            }
            if *riid == <IInitializeWithStream as Interface>::IID {
                *ppv = unk.cast::<IInitializeWithStream>()?.into_raw();
                return Ok(());
            }
            if *riid == <IInitializeWithFile as Interface>::IID {
                *ppv = unk.cast::<IInitializeWithFile>()?.into_raw();
                return Ok(());
            }
            if *riid == <IUnknown as Interface>::IID {
                *ppv = unk.into_raw();
                return Ok(());
            }
        }

        Err(Error::from(E_NOINTERFACE))
    }

    #[allow(non_snake_case)]
    fn LockServer(&self, f_lock: BOOL) -> windows::core::Result<()> {
        if f_lock.as_bool() {
            DLL_LOCK_COUNT.fetch_add(1, Ordering::SeqCst);
            let _ = log_desktop("BlpClassFactory::LockServer lock");
        } else {
            DLL_LOCK_COUNT.fetch_sub(1, Ordering::SeqCst);
            let _ = log_desktop("BlpClassFactory::LockServer unlock");
        }
        Ok(())
    }
}

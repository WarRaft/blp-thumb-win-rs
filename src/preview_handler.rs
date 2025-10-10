// lib.rs (или отдельный модуль в вашем DLL-проекте)
// Cargo.toml должен подтянуть:
// windows = { version = "0.58", features = [
//   "implement",
//   "Win32_Foundation",
//   "Win32_System_Com",
//   "Win32_UI_Shell",
//   "Win32_UI_WindowsAndMessaging",
// ] }

use crate::log::log;
use std::{
    cell::{Cell, RefCell},
    ffi::c_void,
};
use windows::{
    Win32::{
        Foundation::{E_INVALIDARG, E_NOINTERFACE, E_NOTIMPL, E_POINTER},
        Foundation::{GetLastError, HWND, RECT, SYSTEMTIME},
        System::Ole::{IObjectWithSite_Impl, IOleWindow_Impl},
        System::{
            Com::IStream,
            Ole::{IObjectWithSite, IOleWindow},
            SystemInformation::GetLocalTime,
        },
        UI::{
            Input::KeyboardAndMouse::{GetFocus, SetFocus},
            Shell::{
                IPreviewHandler, //
                IPreviewHandler_Impl,
                IPreviewHandlerFrame,
                PropertiesSystem::{IInitializeWithStream, IInitializeWithStream_Impl},
            },
            WindowsAndMessaging::{
                CreateWindowExW, //
                DestroyWindow,
                MSG,
                SW_SHOW,
                SWP_NOACTIVATE,
                SWP_NOMOVE,
                SWP_NOZORDER,
                SetParent,
                SetWindowPos,
                SetWindowTextW,
                ShowWindow,
                WINDOW_EX_STYLE,
                WINDOW_STYLE,
                WS_CHILD,
                WS_VISIBLE,
            },
        },
    },
    core::{
        BOOL,
        HRESULT,
        IUnknown,
        Interface,
        PCWSTR,
        Result,
        implement, //
        w,
    },
};
use windows_core::{GUID, Ref};

const STATIC_CLASSW: PCWSTR = w!("Static");

#[implement(IObjectWithSite, IPreviewHandler, IOleWindow, IInitializeWithStream)]
pub struct BlpPreviewHandler {
    hwnd_parent: Cell<HWND>,
    hwnd_preview: Cell<HWND>,
    rc_parent: Cell<RECT>,
    site: RefCell<Option<IUnknown>>,
    stream: RefCell<Option<IStream>>,
}

#[inline]
fn rw(rc: &RECT) -> i32 {
    rc.right - rc.left
}
#[inline]
fn rh(rc: &RECT) -> i32 {
    rc.bottom - rc.top
}

#[allow(non_snake_case)]
impl BlpPreviewHandler {
    pub fn new() -> Self {
        log("🔥BlpPreviewHandler::new");
        Self {
            hwnd_parent: Cell::new(HWND::default()), //
            hwnd_preview: Cell::new(HWND::default()),
            rc_parent: Cell::new(RECT { left: 0, top: 0, right: 0, bottom: 0 }),
            site: RefCell::new(None),
            stream: RefCell::new(None),
        }
    }

    fn update_bounds(&self) {
        let hwnd_preview = self.hwnd_preview.get();
        if hwnd_preview.is_invalid() {
            return;
        }
        unsafe {
            let rc = self.rc_parent.get();
            let _ = SetWindowPos(
                self.hwnd_preview.get(),
                None, // ← NULL в C++
                rc.left,
                rc.top,
                rw(&rc),
                rh(&rc),
                SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
    }

    fn format_local_timestamp() -> Vec<u16> {
        // GetLocalTime() у тебя — нуль-аргументный враппер
        let st: SYSTEMTIME = unsafe { GetLocalTime() };
        let s = format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn create_preview_window(&self) -> Result<()> {
        let parent = self.hwnd_parent.get();
        if parent.is_invalid() {
            return Err(E_INVALIDARG.into());
        }

        let rc = self.rc_parent.get();
        unsafe {
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0), //
                STATIC_CLASSW,
                PCWSTR::null(),
                WINDOW_STYLE::default() | WS_CHILD | WS_VISIBLE,
                rc.left,
                rc.top,
                rw(&rc),
                rh(&rc),
                Some(parent),
                None,
                None,
                None,
            )?;

            self.hwnd_preview.set(hwnd);

            let wts = Self::format_local_timestamp();
            SetWindowTextW(hwnd, PCWSTR(wts.as_ptr()))?;

            let _ = ShowWindow(hwnd, SW_SHOW);
        }
        Ok(())
    }
}

#[allow(non_snake_case)]
impl IObjectWithSite_Impl for BlpPreviewHandler_Impl {
    fn SetSite(&self, p_unknown_site: Ref<'_, IUnknown>) -> Result<()> {
        *self.site.borrow_mut() = p_unknown_site.clone();
        Ok(())
    }

    fn GetSite(&self, riid: *const GUID, ppv: *mut *mut c_void) -> Result<()> {
        unsafe {
            if ppv.is_null() {
                return Err(E_POINTER.into());
            }
            *ppv = std::ptr::null_mut();
        }

        // берём копию без блокировки borrow
        let owned = self.site.borrow().clone();
        let Some(current) = owned else {
            return Err(E_NOINTERFACE.into());
        };

        unsafe {
            current.query(riid, ppv).ok()?;
        }
        Ok(())
    }
}

#[allow(non_snake_case)]
impl IPreviewHandler_Impl for BlpPreviewHandler_Impl {
    fn SetWindow(&self, hwnd: HWND, prc: *const RECT) -> Result<()> {
        if hwnd.is_invalid() || prc.is_null() {
            return Err(E_INVALIDARG.into());
        }
        self.hwnd_parent.set(hwnd);
        unsafe {
            self.rc_parent.set(*prc);
        }

        // если превью уже создано — перепривяжем и обновим размеры
        let preview = self.hwnd_preview.get();
        if !preview.is_invalid() {
            unsafe {
                let _ = SetParent(preview, Some(hwnd));
            }
            self.update_bounds();
        }
        Ok(())
    }

    fn SetRect(&self, prc: *const RECT) -> Result<()> {
        if prc.is_null() {
            return Err(E_INVALIDARG.into());
        }
        unsafe {
            self.rc_parent.set(*prc);
        }
        self.update_bounds();
        Ok(())
    }

    fn DoPreview(&self) -> Result<()> {
        // создаём окно один раз, только если есть stream
        if self.hwnd_preview.get().is_invalid() && self.stream.borrow().is_some() {
            self.create_preview_window()?;
        }
        Ok(())
    }

    fn Unload(&self) -> Result<()> {
        *self.stream.borrow_mut() = None;

        let hwnd = self.hwnd_preview.get();
        if !hwnd.is_invalid() {
            unsafe {
                DestroyWindow(hwnd)?;
            }
            self.hwnd_preview.set(HWND::default());
        }

        Ok(())
    }

    fn SetFocus(&self) -> Result<()> {
        let hwnd = self.hwnd_preview.get();
        if !hwnd.is_invalid() {
            unsafe {
                let _ = SetFocus(Some(hwnd));
            }
        }
        Ok(())
    }

    fn QueryFocus(&self) -> Result<HWND> {
        unsafe {
            let h = GetFocus();
            if !h.is_invalid() {
                Ok(h)
            } else {
                let code = GetLastError();
                let hr = HRESULT::from_win32(code.0);
                Err(windows::core::Error::new(hr, "GetFocus failed"))
            }
        }
    }

    fn TranslateAccelerator(&self, pmsg: *const MSG) -> Result<()> {
        // достаём владёжную копию site (AddRef) и отпускаем borrow
        if let Some(site) = self.site.borrow().as_ref().cloned() {
            unsafe {
                if let Ok(frame) = site.cast::<IPreviewHandlerFrame>() {
                    let _ = frame.TranslateAccelerator(pmsg);
                }
            }
        }
        Ok(())
    }
}

#[allow(non_snake_case)]
impl IOleWindow_Impl for BlpPreviewHandler_Impl {
    fn GetWindow(&self) -> Result<HWND> {
        Ok(self.hwnd_parent.get())
    }

    #[allow(non_snake_case)]
    fn ContextSensitiveHelp(&self, _fEnterMode: BOOL) -> Result<()> {
        Err(E_NOTIMPL.into())
    }
}

impl IInitializeWithStream_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn Initialize(&self, pStream: Ref<'_, IStream>, _grfMode: u32) -> Result<()> {
        // Initialize может вызываться повторно — просто перезаписываем
        *self.stream.borrow_mut() = pStream.cloned();
        Ok(())
    }
}

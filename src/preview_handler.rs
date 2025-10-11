use crate::log::log;
use std::{
    cell::{Cell, RefCell},
    ffi::c_void,
    ptr,
};
use windows::{
    Win32::{
        Foundation::{E_NOTIMPL, HWND, RECT},
        System::{
            Com::IStream,
            Ole::{IObjectWithSite, IObjectWithSite_Impl, IOleWindow, IOleWindow_Impl},
        },
        UI::{
            Input::KeyboardAndMouse::GetFocus,
            Shell::{
                IPreviewHandler, IPreviewHandler_Impl,
                PropertiesSystem::{IInitializeWithStream, IInitializeWithStream_Impl},
            },
            WindowsAndMessaging::MSG,
        },
    },
    core::{BOOL, GUID, IUnknown, Interface, Ref, Result, implement},
};

#[implement(IObjectWithSite, IPreviewHandler, IOleWindow, IInitializeWithStream)]
pub struct BlpPreviewHandler {
    // Сохраняем только данные, приходящие из аргументов методов:
    hwnd_parent: Cell<HWND>,          // из SetWindow(parent, ...)
    rc_parent: Cell<RECT>,            // из SetWindow/SetRect
    site: RefCell<Option<IUnknown>>,  // из SetSite
    stream: RefCell<Option<IStream>>, // из Initialize
}
#[allow(non_snake_case)]
impl BlpPreviewHandler {
    pub fn new() -> Self {
        log("BlpPreviewHandler::new");
        Self {
            hwnd_parent: Cell::new(HWND::default()), //
            rc_parent: Cell::new(RECT { left: 0, top: 0, right: 0, bottom: 0 }),
            site: RefCell::new(None),
            stream: RefCell::new(None),
        }
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/api/propsys/nn-propsys-iinitializewithstream
#[allow(non_snake_case)]
impl IInitializeWithStream_Impl for BlpPreviewHandler_Impl {
    fn Initialize(&self, pStream: Ref<'_, IStream>, grfMode: u32) -> Result<()> {
        // .cloned() → Option<IStream>
        let opt = pStream.cloned();

        if let Some(stream) = opt {
            let raw = stream.as_raw();
            log(&format!("BlpPreviewHandler::Initialize (pStream=0x{:X}, grfMode=0x{:X})", raw as usize, grfMode));
            *self.stream.borrow_mut() = Some(stream);
        } else {
            log("BlpPreviewHandler::Initialize (pStream=None)");
            *self.stream.borrow_mut() = None;
        }

        Ok(())
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-ipreviewhandler
#[allow(non_snake_case)]
impl IPreviewHandler_Impl for BlpPreviewHandler_Impl {
    fn SetWindow(&self, parent: HWND, prc: *const RECT) -> Result<()> {
        self.hwnd_parent.set(parent);

        if prc.is_null() {
            log(&format!("BlpPreviewHandler::SetWindow (parent=0x{:X}, prc=NULL → rc: unchanged)", parent.0 as usize));
        } else {
            let rc = unsafe { *prc };
            log(&format!("BlpPreviewHandler::SetWindow (parent=0x{:X}, rc=({}, {}, {}, {}))", parent.0 as usize, rc.left, rc.top, rc.right, rc.bottom));
            self.rc_parent.set(rc);
        }

        Ok(())
    }

    fn SetRect(&self, prc: *const RECT) -> Result<()> {
        if prc.is_null() {
            log("BlpPreviewHandler::SetRect (prc=NULL → rc: unchanged)");
        } else {
            let rc = unsafe { *prc };
            log(&format!("BlpPreviewHandler::SetRect (rc=({}, {}, {}, {}))", rc.left, rc.top, rc.right, rc.bottom));
            self.rc_parent.set(rc);
        }
        Ok(())
    }

    fn DoPreview(&self) -> Result<()> {
        let parent = self.hwnd_parent.get();
        let rc = self.rc_parent.get();
        log(&format!("BlpPreviewHandler::DoPreview (parent=0x{:X}, rc=({}, {}, {}, {}), has_stream={})", parent.0 as usize, rc.left, rc.top, rc.right, rc.bottom, self.stream.borrow().is_some()));
        Ok(())
    }

    fn Unload(&self) -> Result<()> {
        log("BlpPreviewHandler::Unload");

        if self.stream.borrow().is_some() {
            log("  releasing IStream");
            self.stream.borrow_mut().take();
        } else {
            log("  no IStream to release");
        }

        Ok(())
    }

    fn SetFocus(&self) -> Result<()> {
        log("BlpPreviewHandler::SetFocus");
        Ok(())
    }

    fn QueryFocus(&self) -> Result<HWND> {
        let hwnd = unsafe { GetFocus() };
        log(&format!("BlpPreviewHandler::QueryFocus → 0x{:X}", hwnd.0 as usize));
        Ok(hwnd)
    }

    fn TranslateAccelerator(&self, pmsg: *const MSG) -> Result<()> {
        let addr = pmsg as usize;
        // Если pmsg не null — вытащим пару полей для логов
        let (message, wparam, lparam) = unsafe {
            if pmsg.is_null() {
                (0u32, 0usize, 0isize)
            } else {
                let m = ptr::read(pmsg);
                (m.message, m.wParam.0, m.lParam.0)
            }
        };
        log(&format!("BlpPreviewHandler::TranslateAccelerator (pmsg=0x{addr:X}, msg=0x{:X}, wParam=0x{:X}, lParam=0x{:X})", message, wparam, lparam));
        Ok(())
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/api/ocidl/nn-ocidl-iobjectwithsite
#[allow(non_snake_case)]
impl IObjectWithSite_Impl for BlpPreviewHandler_Impl {
    fn SetSite(&self, site: Ref<'_, IUnknown>) -> Result<()> {
        let mut slot = self.site.borrow_mut();

        match site.cloned() {
            Some(u) => {
                let raw = u.as_raw();

                if slot.is_some() {
                    log(&format!("BlpPreviewHandler::SetSite (site=0x{:X}) — replacing previous site", raw as usize));
                } else {
                    log(&format!("BlpPreviewHandler::SetSite (site=0x{:X}) — new site assigned", raw as usize));
                }

                *slot = Some(u);
            }

            None => {
                if slot.is_some() {
                    log("BlpPreviewHandler::SetSite (site=None) — releasing previous site");
                    slot.take();
                } else {
                    log("BlpPreviewHandler::SetSite (site=None) — no previous site to release");
                }
            }
        }

        Ok(())
    }

    fn GetSite(&self, riid: *const GUID, ppv: *mut *mut c_void) -> Result<()> {
        // Просто логируем входные аргументы; реализация — заглушка.
        let riid_val = unsafe { riid.as_ref().cloned() };
        log(&format!("BlpPreviewHandler::GetSite (riid={:?}, ppv={:?})", riid_val, ppv));
        Err(E_NOTIMPL.into())
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/api/oleidl/nn-oleidl-iolewindow
#[allow(non_snake_case)]
impl IOleWindow_Impl for BlpPreviewHandler_Impl {
    fn GetWindow(&self) -> Result<HWND> {
        // Отдаём parent (превью-окна пока нет) — это именно «коробка» с логами
        let hwnd = self.hwnd_parent.get();
        log(&format!("BlpPreviewHandler::GetWindow → HWND(0x{:X})", hwnd.0 as usize));
        Ok(hwnd)
    }

    fn ContextSensitiveHelp(&self, fEnterMode: BOOL) -> Result<()> {
        log(&format!("BlpPreviewHandler::ContextSensitiveHelp (fEnterMode={})", fEnterMode.0));
        Err(E_NOTIMPL.into())
    }
}

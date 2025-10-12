use crate::log::log;
use std::sync::OnceLock;
use std::{
    cell::{Cell, RefCell},
    ffi::c_void,
    ptr,
};
use windows::Win32::Graphics::Gdi::UpdateWindow;
use windows::{
    Win32::{
        Foundation::{
            COLORREF,
            ERROR_CLASS_ALREADY_EXISTS,
            GetLastError, //
            LPARAM,
            LRESULT,
            WPARAM,
        },
        Foundation::{E_NOTIMPL, HWND, RECT},
        Graphics::Gdi::{
            BeginPaint, //
            COLOR_WINDOW,
            CreateSolidBrush,
            DeleteObject,
            EndPaint,
            FillRect,
            GetSysColorBrush,
            HBRUSH,
            HGDIOBJ,
            InvalidateRect,
            PAINTSTRUCT,
        },
        System::{
            Com::IStream,
            LibraryLoader::GetModuleHandleW,
            Ole::{IObjectWithSite, IObjectWithSite_Impl, IOleWindow, IOleWindow_Impl},
            SystemInformation::GetTickCount,
        },
        UI::{
            Input::KeyboardAndMouse::GetFocus,
            Shell::{
                IPreviewHandler, IPreviewHandler_Impl,
                PropertiesSystem::{IInitializeWithStream, IInitializeWithStream_Impl},
            },
            WindowsAndMessaging::{
                CS_HREDRAW,
                CS_VREDRAW,
                CreateWindowExW, //
                DefWindowProcW,
                DestroyWindow,
                GetClientRect,
                IDC_ARROW,
                LoadCursorW,
                MSG,
                RegisterClassExW,
                SWP_NOACTIVATE,
                SWP_NOZORDER,
                SetParent,
                SetWindowPos,
                WINDOW_EX_STYLE,
                WM_CREATE,
                WM_DESTROY,
                WM_ERASEBKGND,
                WM_MOVE,
                WM_NCCALCSIZE,
                WM_NCCREATE,
                WM_NCDESTROY,
                WM_NCPAINT,
                WM_PAINT,
                WM_SHOWWINDOW,
                WM_SIZE,
                WM_WINDOWPOSCHANGED,
                WM_WINDOWPOSCHANGING,
                WNDCLASSEXW,
                WS_CHILD,
                WS_VISIBLE,
            },
        },
    },
    core::w,
    core::{BOOL, GUID, IUnknown, Interface, Ref, Result, implement},
};
use windows_result::HRESULT;

static CLASS_REG: OnceLock<Result<()>> = OnceLock::new();

pub fn register_class_once() -> Result<()> {
    CLASS_REG
        .get_or_init(|| unsafe {
            let wc = WNDCLASSEXW {
                cbSize: size_of::<WNDCLASSEXW>() as u32, //
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(wndproc),
                hInstance: GetModuleHandleW(None).ok().unwrap().into(),
                hCursor: LoadCursorW(None, IDC_ARROW).unwrap(),
                hbrBackground: HBRUSH::default(),
                lpszClassName: w!("BLP_PREVIEW_SQUARE"),
                ..Default::default()
            };

            let atom = RegisterClassExW(&wc);
            if atom == 0 {
                let err = GetLastError();
                if err == ERROR_CLASS_ALREADY_EXISTS {
                    Ok(())
                } else {
                    Err(windows::core::Error::new(HRESULT(1), "RegisterClassExW failed"))
                }
            } else {
                Ok(())
            }
        })
        .clone()
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    log(&format!(
        "wndproc: hwnd=0x{:X} msg=0x{:X}({}) wParam=0x{:X} lParam=0x{:X}",
        hwnd.0 as usize,
        msg,
        match msg {
            WM_ERASEBKGND => "WM_ERASEBKGND",
            WM_WINDOWPOSCHANGING => "WM_WINDOWPOSCHANGING",
            WM_WINDOWPOSCHANGED => "WM_WINDOWPOSCHANGED",
            WM_MOVE => "WM_MOVE",
            WM_SHOWWINDOW => "WM_SHOWWINDOW",

            WM_NCCALCSIZE => "WM_NCCALCSIZE",
            WM_SIZE => "WM_SIZE",

            WM_NCCREATE => "WM_NCCREATE",
            WM_CREATE => "WM_CREATE",

            WM_NCPAINT => "WM_NCPAINT",
            WM_PAINT => "WM_PAINT",

            WM_NCDESTROY => "WM_NCDESTROY",
            WM_DESTROY => "WM_DESTROY",
            _ => "UNKNOWN",
        },
        w.0,
        l.0
    ));

    unsafe {
        match msg {
            WM_ERASEBKGND => LRESULT(0),

            WM_WINDOWPOSCHANGED => {
                let _ = InvalidateRect(Some(hwnd), None, false);
                LRESULT(0)
            }

            WM_SHOWWINDOW => {
                if w.0 != 0 {
                    let _ = InvalidateRect(Some(hwnd), None, false);
                    let _ = UpdateWindow(hwnd);
                }
                LRESULT(0)
            }

            WM_NCPAINT => LRESULT(0),
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut ps);

                // client rect
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                let cw = rc.right - rc.left;
                let ch = rc.bottom - rc.top;

                // log sizes every time
                log(&format!("WM_PAINT: client {}x{} (l={}, t={}, r={}, b={})", cw, ch, rc.left, rc.top, rc.right, rc.bottom));

                // skip drawing when size is zero (but still EndPaint!)
                if cw <= 0 || ch <= 0 {
                    let _ = EndPaint(hwnd, &ps);
                    return LRESULT(0);
                }

                // background
                let _ = FillRect(hdc, &rc, GetSysColorBrush(COLOR_WINDOW));

                // square geometry
                let side = (cw.min(ch) * 3) / 5;
                let dx = rc.left + (cw - side) / 2;
                let dy = rc.top + (ch - side) / 2;
                let sq = RECT { left: dx, top: dy, right: dx + side, bottom: dy + side };

                // pseudo-random not-white color (time-based)
                let t = GetTickCount();
                let mut r = (t & 0xFF) as u8;
                let mut g = ((t >> 8) & 0xFF) as u8;
                let mut b = ((t >> 16) & 0xFF) as u8;
                if r > 230 && g > 230 && b > 230 {
                    r = r.saturating_sub(80);
                    g = g.saturating_sub(60);
                    b = b.saturating_sub(40);
                }
                if r > 200 {
                    r = 200;
                }

                let brush = CreateSolidBrush(COLORREF((r as u32) | ((g as u32) << 8) | ((b as u32) << 16)));
                if !brush.is_invalid() {
                    let _ = FillRect(hdc, &sq, brush);
                    let _ = DeleteObject(HGDIOBJ(brush.0));
                }

                let _ = EndPaint(hwnd, &ps);
                LRESULT(0)
            }

            WM_NCCALCSIZE => LRESULT(0),
            WM_SIZE => {
                let _ = InvalidateRect(Some(hwnd), None, false);
                LRESULT(0)
            }

            _ => DefWindowProcW(hwnd, msg, w, l),
        }
    }
}

#[implement(IObjectWithSite, IPreviewHandler, IOleWindow, IInitializeWithStream)]
pub struct BlpPreviewHandler {
    // Сохраняем только данные, приходящие из аргументов методов:
    hwnd_parent: Cell<HWND>, // из SetWindow(parent, ...)
    hwnd_preview: Cell<HWND>,
    rc_parent: Cell<RECT>,            // из SetWindow/SetRect
    site: RefCell<Option<IUnknown>>,  // из SetSite
    stream: RefCell<Option<IStream>>, // из Initialize
}
#[allow(non_snake_case)]
impl BlpPreviewHandler {
    pub fn new() -> Self {
        log("BlpPreviewHandler::new");
        let _ = register_class_once();
        Self {
            hwnd_parent: Cell::new(HWND::default()), //
            hwnd_preview: Cell::new(HWND::default()),
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
            log(&format!("BlpPreviewHandler::SetWindow (parent=0x{:X}, prc=NULL)", parent.0 as usize));
        } else {
            let rc = unsafe { *prc };
            log(&format!("BlpPreviewHandler::SetWindow (parent=0x{:X}, rc=({}, {}, {}, {}))", parent.0 as usize, rc.left, rc.top, rc.right, rc.bottom));
            self.rc_parent.set(rc);
        }

        let preview = self.hwnd_preview.get();
        if !preview.is_invalid() && !parent.is_invalid() {
            unsafe {
                let _ = SetParent(preview, Some(parent));
            }
            let rc = self.rc_parent.get();
            unsafe {
                let _ = SetWindowPos(
                    preview,
                    None, //
                    rc.left,
                    rc.top,
                    rc.right - rc.left,
                    rc.bottom - rc.top,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                );
            }
        }
        Ok(())
    }

    fn SetRect(&self, prc: *const RECT) -> Result<()> {
        if prc.is_null() {
            log("BlpPreviewHandler::SetRect (prc=NULL)");
            return Ok(());
        }
        let rc = unsafe { *prc };
        log(&format!("BlpPreviewHandler::SetRect (rc=({}, {}, {}, {}))", rc.left, rc.top, rc.right, rc.bottom));
        self.rc_parent.set(rc);
        Ok(())
    }

    fn DoPreview(&self) -> Result<()> {
        let parent = self.hwnd_parent.get();
        let rc = self.rc_parent.get();
        log(&format!(
            "BlpPreviewHandler::DoPreview (parent=0x{:X}, rc=({}, {}, {}, {}), has_stream={})",
            parent.0 as usize, //
            rc.left,
            rc.top,
            rc.right,
            rc.bottom,
            self.stream.borrow().is_some()
        ));
        let preview = self.hwnd_preview.get();

        unsafe {
            if preview.is_invalid() {
                let parent = self.hwnd_parent.get();
                let hwnd = CreateWindowExW(
                    WINDOW_EX_STYLE(0),       // dwExStyle: extended window styles (0 = none)
                    w!("BLP_PREVIEW_SQUARE"), // lpClassName: registered window class name to instantiate
                    None,                     // lpWindowName: window title/caption (None for child/untitled)
                    WS_CHILD | WS_VISIBLE,    // dwStyle: standard styles (child window + initially visible)
                    rc.left,                  // X: initial position (left) relative to parent client area
                    rc.top,                   // Y: initial position (top)  relative to parent client area
                    rc.right - rc.left,       // nWidth: initial width  in device units (pixels)
                    rc.bottom - rc.top,       // nHeight: initial height in device units (pixels)
                    Some(parent),             // hWndParent: parent window handle (required for WS_CHILD)
                    None,                     // hMenu / hWndChildID: menu or child control ID (None = no menu / default ID)
                    None,                     // hInstance: module handle owning the window class/resources
                    None,                     // lpParam: pointer to CREATESTRUCT/any user data passed to WM_CREATE (None = no extra)
                )?;

                self.hwnd_preview.set(hwnd);
            } else {
                let _ = SetWindowPos(
                    preview,                       // hWnd: handle of the window to move/resize (our child/canvas)
                    None,                          // hWndInsertAfter: Z-order target (None/NULL → ignored with SWP_NOZORDER)
                    rc.left,                       // X: new left position (ignored if SWP_NOMOVE is set)
                    rc.top,                        // Y: new top position  (ignored if SWP_NOMOVE is set)
                    rc.right - rc.left,            // cx: new width in pixels
                    rc.bottom - rc.top,            // cy: new height in pixels
                    SWP_NOZORDER | SWP_NOACTIVATE, // uFlags: don't move, don't change Z-order, don't activate
                );
            }
        }

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

        let child = self.hwnd_preview.get();
        if !child.is_invalid() {
            unsafe {
                let _ = DestroyWindow(child);
            }
            self.hwnd_preview.set(HWND::default());
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

use crate::log::log;
use std::sync::OnceLock;
use std::{
    cell::{Cell, RefCell},
    ffi::c_void,
    ptr,
};
use windows::Win32::Graphics::Gdi::{RDW_INTERNALPAINT, RDW_INVALIDATE, RedrawWindow};
use windows::Win32::UI::WindowsAndMessaging::GetParent;
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
            HGDIOBJ,
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
                IsWindow,
                LoadCursorW,
                MSG,
                RegisterClassExW,
                SW_SHOW,
                SWP_NOACTIVATE,
                SWP_NOMOVE,
                SWP_NOZORDER,
                SetParent,
                SetWindowPos,
                ShowWindow,
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
                WNDCLASS_STYLES,
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

fn register_class_once() -> Result<()> {
    CLASS_REG
        .get_or_init(|| unsafe {
            let wc = WNDCLASSEXW {
                cbSize: size_of::<WNDCLASSEXW>() as u32, //
                style: WNDCLASS_STYLES(CS_HREDRAW.0 | CS_VREDRAW.0),
                lpfnWndProc: Some(wndproc),
                hInstance: GetModuleHandleW(None).ok().unwrap().into(),
                hCursor: LoadCursorW(None, IDC_ARROW).unwrap(),
                hbrBackground: GetSysColorBrush(COLOR_WINDOW),
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
    let parent = unsafe { GetParent(hwnd) }.unwrap_or_default();

    log(&format!(
        "[wndproc] 0x{:X}:0x{:X} msg=0x{:X}({}) wParam=0x{:X} lParam=0x{:X}",
        parent.0 as usize,
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

    match msg {
        WM_ERASEBKGND => LRESULT(0),
        WM_SHOWWINDOW => LRESULT(0),
        WM_NCPAINT => LRESULT(1),
        WM_PAINT => {
            let mut ps = PAINTSTRUCT::default();
            let hdc = unsafe { BeginPaint(hwnd, &mut ps) };

            // client rect
            let mut rc = RECT::default();
            let _ = unsafe { GetClientRect(hwnd, &mut rc) };
            let cw = rc.right - rc.left;
            let ch = rc.bottom - rc.top;

            // log sizes every time
            log(&format!("WM_PAINT: client {}x{} (l={}, t={}, r={}, b={})", cw, ch, rc.left, rc.top, rc.right, rc.bottom));

            // skip drawing when size is zero (but still EndPaint!)
            if cw <= 0 || ch <= 0 {
                let _ = unsafe { EndPaint(hwnd, &ps) };
                return LRESULT(0);
            }

            // background
            let _ = unsafe { FillRect(hdc, &rc, GetSysColorBrush(COLOR_WINDOW)) };

            // square geometry
            let side = (cw.min(ch) * 3) / 5;
            let dx = rc.left + (cw - side) / 2;
            let dy = rc.top + (ch - side) / 2;
            let sq = RECT { left: dx, top: dy, right: dx + side, bottom: dy + side };

            // pseudo-random not-white color (time-based)
            let t = unsafe { GetTickCount() };
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

            let brush = unsafe { CreateSolidBrush(COLORREF((r as u32) | ((g as u32) << 8) | ((b as u32) << 16))) };
            if !brush.is_invalid() {
                let _ = unsafe { FillRect(hdc, &sq, brush) };
                let _ = unsafe { DeleteObject(HGDIOBJ(brush.0)) };
            }

            let _ = unsafe { EndPaint(hwnd, &ps) };
            LRESULT(0)
        }

        WM_NCCALCSIZE => LRESULT(0),
        WM_SIZE => {
            let wpx = (l.0 & 0xFFFF) as i32; // LOWORD(lParam) = width
            let hpx = ((l.0 >> 16) & 0xFFFF) as i32; // HIWORD(lParam) = height
            log(&format!("WM_SIZE: {}x{}", wpx, hpx));

            LRESULT(0)
        }

        _ => unsafe { DefWindowProcW(hwnd, msg, w, l) },
    }
}

#[implement(IObjectWithSite, IPreviewHandler, IOleWindow, IInitializeWithStream)]
pub struct BlpPreviewHandler {
    hwnd_parent: Cell<HWND>, // из SetWindow(parent, ...)
    hwnd_preview: Cell<HWND>,
    rc: Cell<RECT>,                   // из SetWindow/SetRect
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
            rc: Cell::new(RECT { left: 0, top: 0, right: 0, bottom: 0 }),
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
            log(&format!("Initialize (pStream=0x{:X}, grfMode=0x{:X})", raw as usize, grfMode));
            *self.stream.borrow_mut() = Some(stream);
        } else {
            log("Initialize (pStream=None)");
            *self.stream.borrow_mut() = None;
        }

        Ok(())
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-ipreviewhandler
#[allow(non_snake_case)]
impl IPreviewHandler_Impl for BlpPreviewHandler_Impl {
    fn SetWindow(&self, parent: HWND, prc: *const RECT) -> Result<()> {
        if parent.is_invalid() || prc.is_null() {
            log(&format!("SetWindow (parent=0x{:X}, prc=NULL)", parent.0 as usize));
            return Ok(());
        }
        self.hwnd_parent.set(parent);

        let rc = unsafe { *prc };
        log(&format!("SetWindow (parent=0x{:X}, rc=({}, {}, {}, {}))", parent.0 as usize, rc.left, rc.top, rc.right, rc.bottom));
        self.rc.set(rc);

        let preview = self.hwnd_preview.get();
        if !preview.is_invalid() {
            match unsafe { SetParent(preview, Some(parent)) } {
                Ok(_) => log("  SetWindow => SetParent => OK"),
                Err(e) => log(&format!("  SetParent => ERR: {:?}", e)),
            };

            match unsafe {
                SetWindowPos(
                    preview, //
                    None,
                    rc.left,
                    rc.top,
                    rc.right - rc.left,
                    rc.bottom - rc.top,
                    SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
                )
            } {
                Ok(_) => log("  SetWindow => SetWindowPos => OK"),
                Err(e) => log(&format!("  SetWindowPos => ERR: {:?}", e)),
            };
        } else {
            log("  SetWindow => hwnd_preview is invalid, skipping SetParent/SetWindowPos");
        }

        Ok(())
    }

    fn SetRect(&self, prc: *const RECT) -> Result<()> {
        if prc.is_null() {
            log("SetRect (prc=NULL)");
            return Ok(());
        }
        let rc = unsafe { *prc };
        self.rc.set(rc);

        let parent = self.hwnd_parent.get();
        let preview = self.hwnd_preview.get();

        log(&format!(
            "SetRect 0x{:X}:0x{:X} (rc=({}, {}, {}, {}))",
            parent.0 as usize, //
            preview.0 as usize,
            rc.left,
            rc.top,
            rc.right,
            rc.bottom
        ));

        if !preview.is_invalid() {
            match unsafe {
                SetWindowPos(
                    preview,
                    None, //
                    rc.left,
                    rc.top,
                    rc.right - rc.left,
                    rc.bottom - rc.top,
                    SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
                )
            } {
                Ok(_) => log("  SetRect => SetWindowPos => OK"),
                Err(e) => log(&format!("  SetRect => SetWindowPos => ERR: {:?}", e)),
            };
        }
        Ok(())
    }

    fn DoPreview(&self) -> Result<()> {
        let parent = self.hwnd_parent.get();
        let rc = self.rc.get();
        let preview = self.hwnd_preview.get();

        log(&format!(
            "DoPreview 0x{:X}:0x{:X} (rc=({}, {}, {}, {}), has_stream={})",
            parent.0 as usize, //
            preview.0 as usize,
            rc.left,
            rc.top,
            rc.right,
            rc.bottom,
            self.stream.borrow().is_some()
        ));

        if preview.is_invalid() {
            let parent = self.hwnd_parent.get();
            let hwnd = match unsafe {
                CreateWindowExW(
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
                )
            } {
                Ok(r) => {
                    log(&format!("  DoPreview => CreateWindowExW (0x{:X})", r.0 as usize));
                    r
                }
                Err(e) => {
                    log(&format!("  DoPreview => CreateWindowExW => ERR: {:?}", e));
                    return Err(e);
                }
            };
            self.hwnd_preview.set(hwnd);
            log(&format!("  DoPreview => ShowWindow({})", unsafe { ShowWindow(hwnd, SW_SHOW) }.as_bool()));
        } else {
            match unsafe {
                SetWindowPos(
                    preview,                                    // hWnd: handle of the window to move/resize (our child/canvas)
                    None,                                       // hWndInsertAfter: Z-order target (None/NULL → ignored with SWP_NOZORDER)
                    rc.left,                                    // X: new left position (ignored if SWP_NOMOVE is set)
                    rc.top,                                     // Y: new top position  (ignored if SWP_NOMOVE is set)
                    rc.right - rc.left,                         // cx: new width in pixels
                    rc.bottom - rc.top,                         // cy: new height in pixels
                    SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE, // uFlags: don't move, don't change Z-order, don't activate
                )
            } {
                Ok(_) => log("  DoPreview => SetWindowPos => OK"),
                Err(e) => log(&format!("  DoPreview => SetWindowPos => ERR: {:?}", e)),
            };
        }

        let preview = self.hwnd_preview.get();

        log(format!(
            "  DoPreview 0x{:X}:0x{:X} => RedrawWindow => {}", //
            parent.0 as usize,
            preview.0 as usize,
            unsafe { RedrawWindow(Some(preview), None, None, RDW_INVALIDATE | RDW_INTERNALPAINT) }.as_bool()
        ));

        Ok(())
    }

    #[allow(non_snake_case)]
    fn Unload(&self) -> Result<()> {
        log("Unload");

        // Release IStream (if any)
        if self.stream.borrow().is_some() {
            log("  releasing IStream");
            self.stream.borrow_mut().take();
        } else {
            log("  no IStream to release");
        }

        // Destroy preview window (same thread)
        let preview = self.hwnd_preview.get();
        if preview.is_invalid() {
            log("  hwnd_preview is invalid (nothing to destroy)");
            return Ok(());
        }

        let alive = unsafe { IsWindow(Some(preview)).as_bool() };
        log(&format!("  IsWindow(hwnd_preview) => {}", alive));
        if alive {
            match unsafe { DestroyWindow(preview) } {
                Ok(_) => log("  DestroyWindow => OK"),
                Err(e) => log(&format!("  DestroyWindow => ERR: {:?}", e)),
            }
        } else {
            log("  window already destroyed by host");
        }

        // Always clear our handle to avoid double-destroy later
        self.hwnd_preview.set(HWND::default());
        Ok(())
    }

    fn SetFocus(&self) -> Result<()> {
        log("SetFocus");
        Ok(())
    }

    fn QueryFocus(&self) -> Result<HWND> {
        let hwnd = unsafe { GetFocus() };
        log(&format!("QueryFocus → 0x{:X}", hwnd.0 as usize));
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
        log(&format!("TranslateAccelerator (pmsg=0x{addr:X}, msg=0x{:X}, wParam=0x{:X}, lParam=0x{:X})", message, wparam, lparam));
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
                    log(&format!("SetSite (site=0x{:X}) — replacing previous site", raw as usize));
                } else {
                    log(&format!("SetSite (site=0x{:X}) — new site assigned", raw as usize));
                }

                *slot = Some(u);
            }

            None => {
                if slot.is_some() {
                    log("SetSite (site=None) — releasing previous site");
                    slot.take();
                } else {
                    log("SetSite (site=None) — no previous site to release");
                }
            }
        }

        Ok(())
    }

    fn GetSite(&self, riid: *const GUID, ppv: *mut *mut c_void) -> Result<()> {
        // Просто логируем входные аргументы; реализация — заглушка.
        let riid_val = unsafe { riid.as_ref().cloned() };
        log(&format!("GetSite (riid={:?}, ppv={:?})", riid_val, ppv));
        Err(E_NOTIMPL.into())
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/api/oleidl/nn-oleidl-iolewindow
#[allow(non_snake_case)]
impl IOleWindow_Impl for BlpPreviewHandler_Impl {
    fn GetWindow(&self) -> Result<HWND> {
        let hwnd = self.hwnd_parent.get();
        log(&format!("GetWindow → HWND(0x{:X})", hwnd.0 as usize));
        Ok(hwnd)
    }

    fn ContextSensitiveHelp(&self, fEnterMode: BOOL) -> Result<()> {
        log(&format!("ContextSensitiveHelp (fEnterMode={})", fEnterMode.as_bool()));
        Err(E_NOTIMPL.into())
    }
}

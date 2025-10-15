use crate::log::log;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::{
    cell::{Cell, RefCell},
    ffi::c_void,
    ptr,
};
use windows::Win32::UI::WindowsAndMessaging::GetParent;
use windows::{
    Win32::{
        Foundation::{
            COLORREF,
            ERROR_CLASS_ALREADY_EXISTS,
            GetLastError, //
            LPARAM,
            LRESULT,
            S_FALSE,
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
            InvalidateRect,
            LOGFONTW,
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
                IPreviewHandler,
                IPreviewHandlerVisuals,
                IPreviewHandlerVisuals_Impl,
                IPreviewHandlerFrame,
                IPreviewHandler_Impl,
                PropertiesSystem::{IInitializeWithStream, IInitializeWithStream_Impl},
            },
            WindowsAndMessaging::{
                CS_DBLCLKS,
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
                SWP_NOZORDER,
                SetParent,
                SetWindowPos,
                ShowWindow,
                WINDOW_EX_STYLE,
                WM_CREATE,
                WM_DESTROY,
                WM_ERASEBKGND,
                WM_LBUTTONDBLCLK,
                WM_MOVE,
                WM_NCCALCSIZE,
                WM_NCCREATE,
                WM_NCDESTROY,
                WM_NCPAINT,
                WM_PAINT,
                WM_SETCURSOR,
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

#[derive(Clone, Copy)]
struct PreviewVisual {
    color: COLORREF,
    image_size: (i32, i32),
}

impl PreviewVisual {
    fn describe(&self) -> String {
        format!(
            "color=0x{:06X} image_size={}x{}", // COLORREF is 0x00bbggrr
            self.color.0 & 0x00FF_FFFF,
            self.image_size.0,
            self.image_size.1
        )
    }
}

#[derive(Clone, Copy, Default)]
struct WindowVisualState {
    preview: Option<PreviewVisual>,
    background: Option<COLORREF>,
    text: Option<COLORREF>,
}

fn visuals_store() -> &'static Mutex<HashMap<isize, WindowVisualState>> {
    static STORE: OnceLock<Mutex<HashMap<isize, WindowVisualState>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn hwnd_key(hwnd: HWND) -> isize {
    hwnd.0 as isize
}

fn update_window_visual_state<F>(hwnd: HWND, updater: F)
where
    F: FnOnce(&mut WindowVisualState),
{
    if hwnd.is_invalid() {
        return;
    }
    let mut map = visuals_store().lock().expect("visuals_store lock poisoned");
    let entry = map.entry(hwnd_key(hwnd)).or_default();
    updater(entry);
}

fn get_window_visual_state(hwnd: HWND) -> Option<WindowVisualState> {
    if hwnd.is_invalid() {
        return None;
    }
    visuals_store()
        .lock()
        .ok()
        .and_then(|map| map.get(&hwnd_key(hwnd)).copied())
}

fn clear_window_visual_state(hwnd: HWND) {
    if hwnd.is_invalid() {
        return;
    }
    if let Ok(mut map) = visuals_store().lock() {
        map.remove(&hwnd_key(hwnd));
    }
}

fn register_class_once() -> Result<()> {
    CLASS_REG
        .get_or_init(|| unsafe {
            let wc = WNDCLASSEXW {
                cbSize: size_of::<WNDCLASSEXW>() as u32, //
                style: WNDCLASS_STYLES(CS_HREDRAW.0 | CS_VREDRAW.0 | CS_DBLCLKS.0),
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
            0x0090 => "WM_UAHDESTROYWINDOW",
            WM_SETCURSOR => "WM_SETCURSOR",
            WM_LBUTTONDBLCLK => "WM_LBUTTONDBLCLK",

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
        WM_ERASEBKGND => unsafe { DefWindowProcW(hwnd, msg, w, l) },
        WM_SHOWWINDOW => {
            if w.0 != 0 {
                let _ = unsafe { InvalidateRect(Some(hwnd), None, false) };
                log("WM_SHOWWINDOW -> InvalidateRect(false)");
            }
            unsafe { DefWindowProcW(hwnd, msg, w, l) }
        }
        WM_WINDOWPOSCHANGED => {
            let _ = unsafe { InvalidateRect(Some(hwnd), None, false) };
            unsafe { DefWindowProcW(hwnd, msg, w, l) }
        }
        WM_PAINT => {
            let mut ps = PAINTSTRUCT::default();
            let hdc = unsafe { BeginPaint(hwnd, &mut ps) };

            let mut rc = RECT::default();
            let _ = unsafe { GetClientRect(hwnd, &mut rc) };
            let cw = rc.right - rc.left;
            let ch = rc.bottom - rc.top;

            if cw <= 0 || ch <= 0 {
                log(&format!("WM_PAINT: client {}x{} (empty); skipping", cw, ch));
                let _ = unsafe { EndPaint(hwnd, &ps) };
                return LRESULT(0);
            }

            let stored_state = get_window_visual_state(hwnd).unwrap_or_default();
            let bg_color = stored_state.background;
            let visual = stored_state.preview;
            let text_color = stored_state.text;

            // Fill background either with requested color or system window color
            match bg_color {
                Some(color) => {
                    let brush = unsafe { CreateSolidBrush(color) };
                    if !brush.is_invalid() {
                        let _ = unsafe { FillRect(hdc, &rc, brush) };
                        let _ = unsafe { DeleteObject(HGDIOBJ(brush.0)) };
                    } else {
                        let _ = unsafe { FillRect(hdc, &rc, GetSysColorBrush(COLOR_WINDOW)) };
                    }
                }
                None => {
                    let _ = unsafe { FillRect(hdc, &rc, GetSysColorBrush(COLOR_WINDOW)) };
                }
            }

            if let Some(state) = visual {
                let img_w = state.image_size.0.max(1);
                let img_h = state.image_size.1.max(1);
                let scale = f32::min(cw as f32 / img_w as f32, ch as f32 / img_h as f32);
                let draw_w = (img_w as f32 * scale).round() as i32;
                let draw_h = (img_h as f32 * scale).round() as i32;
                let dx = rc.left + (cw - draw_w) / 2;
                let dy = rc.top + (ch - draw_h) / 2;
                let draw_rect = RECT { left: dx, top: dy, right: dx + draw_w, bottom: dy + draw_h };

                let brush = unsafe { CreateSolidBrush(state.color) };
                if !brush.is_invalid() {
                    let _ = unsafe { FillRect(hdc, &draw_rect, brush) };
                    let _ = unsafe { DeleteObject(HGDIOBJ(brush.0)) };
                }

                log(&format!(
                    "WM_PAINT: client {}x{} using {} scaled→{}x{} at ({}, {}), text_color={}",
                    cw,
                    ch,
                    state.describe(),
                    draw_w,
                    draw_h,
                    dx,
                    dy,
                    match text_color {
                        Some(c) => format!("0x{:06X}", c.0 & 0x00FF_FFFF),
                        None => "<default>".into(),
                    }
                ));
            } else {
                log(&format!(
                    "WM_PAINT: client {}x{} but no preview_visual yet",
                    cw,
                    ch
                ));
            }

            let _ = unsafe { EndPaint(hwnd, &ps) };
            LRESULT(0)
        }
        WM_NCDESTROY => {
            clear_window_visual_state(hwnd);
            unsafe { DefWindowProcW(hwnd, msg, w, l) }
        }

        WM_SIZE => {
            let lp = l.0 as u32;
            let width = (lp & 0xFFFF) as i32;
            let height = ((lp >> 16) & 0xFFFF) as i32;
            log(&format!("WM_SIZE lParam=0x{:X} => {}x{}", lp, width, height));
            let _ = unsafe { InvalidateRect(Some(hwnd), None, false) };
            unsafe { DefWindowProcW(hwnd, msg, w, l) }
        }

        _ => unsafe { DefWindowProcW(hwnd, msg, w, l) },
    }
}

#[implement(IObjectWithSite, IPreviewHandler, IOleWindow, IInitializeWithStream, IPreviewHandlerVisuals)]
pub struct BlpPreviewHandler {
    hwnd_parent: Cell<HWND>, // из SetWindow(parent, ...)
    hwnd_preview: Cell<HWND>,
    rc: Cell<RECT>,                         // из SetWindow/SetRect
    site: RefCell<Option<IUnknown>>,        // из SetSite
    stream: RefCell<Option<IStream>>,       // из Initialize
    preview_visual: RefCell<Option<PreviewVisual>>,
    background_color: RefCell<Option<COLORREF>>,
    text_color: RefCell<Option<COLORREF>>,
    font: RefCell<Option<LOGFONTW>>,
    frame: RefCell<Option<IPreviewHandlerFrame>>,
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
            preview_visual: RefCell::new(None),
            background_color: RefCell::new(None),
            text_color: RefCell::new(None),
            font: RefCell::new(None),
            frame: RefCell::new(None),
        }
    }

    fn refresh_preview_visual(&self, reason: &str) {
        let rc = self.rc.get();
        let width = rc.right - rc.left;
        let height = rc.bottom - rc.top;

        if width <= 0 || height <= 0 {
            log(&format!("{} → preview size {}x{} (skip)", reason, width, height));
            self.sync_visual_state_to_window(self.hwnd_preview.get());
            return;
        }

        let visual = self.generate_preview_visual(width, height);
        log(&format!("{} → {}", reason, visual.describe()));
        *self.preview_visual.borrow_mut() = Some(visual);
        self.sync_visual_state_to_window(self.hwnd_preview.get());
    }

    fn generate_preview_visual(&self, width: i32, height: i32) -> PreviewVisual {
        let mut seed = unsafe { GetTickCount() };
        if let Some(stream) = self.stream.borrow().as_ref() {
            seed ^= (stream.as_raw() as u64) as u32;
        }
        seed ^= width as u32;
        seed = seed.rotate_left(13) ^ (height as u32);

        let mut r = (seed & 0xFF) as u8;
        let mut g = ((seed >> 8) & 0xFF) as u8;
        let mut b = ((seed >> 16) & 0xFF) as u8;

        if r > 220 && g > 220 && b > 220 {
            r = r.saturating_sub(70);
            g = g.saturating_sub(90);
            b = b.saturating_sub(110);
        }

        PreviewVisual {
            color: COLORREF((r as u32) | ((g as u32) << 8) | ((b as u32) << 16)),
            image_size: (width.max(1), height.max(1)),
        }
    }

    fn sync_visual_state_to_window(&self, hwnd: HWND) {
        if hwnd.is_invalid() {
            return;
        }

        let preview = *self.preview_visual.borrow();
        let background = *self.background_color.borrow();
        let text = *self.text_color.borrow();

        update_window_visual_state(hwnd, |state| {
            state.preview = preview;
            state.background = background;
            state.text = text;
        });
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
                    SWP_NOZORDER | SWP_NOACTIVATE,
                )
            } {
                Ok(_) => log("  SetWindow => SetWindowPos => OK"),
                Err(e) => log(&format!("  SetWindowPos => ERR: {:?}", e)),
            };
            let _ = unsafe { InvalidateRect(Some(preview), None, false) };
            log("  SetWindow => InvalidateRect(false)");
            self.sync_visual_state_to_window(preview);
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
                    SWP_NOZORDER | SWP_NOACTIVATE,
                )
            } {
                Ok(_) => log("  SetRect => SetWindowPos => OK"),
                Err(e) => log(&format!("  SetRect => SetWindowPos => ERR: {:?}", e)),
            };
            let _ = unsafe { InvalidateRect(Some(preview), None, false) };
            log("  SetRect => InvalidateRect(false)");
            self.refresh_preview_visual("SetRect");
        }
        Ok(())
    }

    fn DoPreview(&self) -> Result<()> {
        let parent = self.hwnd_parent.get();
        let rc = self.rc.get();
        let preview = self.hwnd_preview.get();

        if let Some(stream) = self.stream.borrow_mut().take() {
            log("DoPreview: stream present – reading signature");
            unsafe {
                stream.Seek(0, windows::Win32::System::Com::STREAM_SEEK_SET, None)?;
            }
            let mut magic = [0u8; 4];
            let mut read = 0u32;
            let hr = unsafe { stream.Read(magic.as_mut_ptr() as *mut _, magic.len() as u32, Some(&mut read)) };
            match hr.ok() {
                Ok(()) => {}
                Err(e) if e.code() == S_FALSE => {
                    log(&format!("DoPreview: stream.Read returned S_FALSE after {} bytes", read));
                }
                Err(e) => {
                    log(&format!("DoPreview: stream.Read failed hr=0x{:08X}", e.code().0));
                    return Err(e);
                }
            }
            log(&format!(
                "DoPreview: stream magic bytes = {:02X} {:02X} {:02X} {:02X}",
                magic[0], magic[1], magic[2], magic[3]
            ));
        } else {
            log("DoPreview: stream absent (already consumed or not provided)");
        }

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
            let _ = unsafe { InvalidateRect(Some(hwnd), None, false) };
            log("  DoPreview => InvalidateRect(false) for new window");
            self.sync_visual_state_to_window(hwnd);
        } else {
            match unsafe {
                SetWindowPos(
                    preview,                                    // hWnd: handle of the window to move/resize (our child/canvas)
                    None,                                       // hWndInsertAfter: Z-order target (None/NULL → ignored with SWP_NOZORDER)
                    rc.left,                                    // X: new left position (ignored if SWP_NOMOVE is set)
                    rc.top,                                     // Y: new top position  (ignored if SWP_NOMOVE is set)
                    rc.right - rc.left,                         // cx: new width in pixels
                    rc.bottom - rc.top,                         // cy: new height in pixels
                    SWP_NOZORDER | SWP_NOACTIVATE,              // uFlags: don't change Z-order, don't activate
                )
            } {
                Ok(_) => log("  DoPreview => SetWindowPos => OK"),
                Err(e) => log(&format!("  DoPreview => SetWindowPos => ERR: {:?}", e)),
            };
            let _ = unsafe { InvalidateRect(Some(preview), None, false) };
            log("  DoPreview => InvalidateRect(false) after SetWindowPos");
            self.sync_visual_state_to_window(preview);

        }

        self.refresh_preview_visual("DoPreview");

        let preview = self.hwnd_preview.get();

        log(format!(
            "  DoPreview 0x{:X}:0x{:X} complete",
            parent.0 as usize,
            preview.0 as usize
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

        clear_window_visual_state(preview);

        // Always clear our handle to avoid double-destroy later
        self.hwnd_preview.set(HWND::default());
        self.preview_visual.borrow_mut().take();
        self.background_color.borrow_mut().take();
        self.text_color.borrow_mut().take();
        self.font.borrow_mut().take();
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

        if let Some(frame) = self.frame.borrow().as_ref() {
            let hr = unsafe { frame.TranslateAccelerator(pmsg) };
            match hr {
                Ok(()) => {
                    log("  TranslateAccelerator → forwarded to IPreviewHandlerFrame (S_OK)");
                    return Ok(());
                }
                Err(e) if e.code() == S_FALSE => {
                    log("  TranslateAccelerator → frame returned S_FALSE (not handled)");
                    return Ok(());
                }
                Err(e) => {
                    log(&format!("  TranslateAccelerator → frame returned error 0x{:08X}", e.code().0));
                    return Err(e);
                }
            }
        } else {
            log("  TranslateAccelerator → no IPreviewHandlerFrame cached");
        }
        Ok(())
    }
}

/// Host-provided visual customization (background/text colors, fonts).
#[allow(non_snake_case)]
impl IPreviewHandlerVisuals_Impl for BlpPreviewHandler_Impl {
    fn SetBackgroundColor(&self, color: COLORREF) -> Result<()> {
        log(&format!("SetBackgroundColor 0x{:06X}", color.0 & 0x00FF_FFFF));
        *self.background_color.borrow_mut() = Some(color);
        self.sync_visual_state_to_window(self.hwnd_preview.get());
        Ok(())
    }

    fn SetFont(&self, plf: *const LOGFONTW) -> Result<()> {
        if plf.is_null() {
            log("SetFont(NULL) – clearing stored font");
            self.font.borrow_mut().take();
            return Ok(());
        }

        let lf = unsafe { *plf };
        let face_len = lf.lfFaceName.iter().position(|&c| c == 0).unwrap_or(lf.lfFaceName.len());
        let face = String::from_utf16_lossy(&lf.lfFaceName[..face_len]);
        log(&format!(
            "SetFont height={} weight={} charset={} face='{}'",
            lf.lfHeight,
            lf.lfWeight,
            lf.lfCharSet.0,
            face
        ));
        *self.font.borrow_mut() = Some(lf);
        self.sync_visual_state_to_window(self.hwnd_preview.get());
        Ok(())
    }

    fn SetTextColor(&self, color: COLORREF) -> Result<()> {
        log(&format!("SetTextColor 0x{:06X}", color.0 & 0x00FF_FFFF));
        *self.text_color.borrow_mut() = Some(color);
        self.sync_visual_state_to_window(self.hwnd_preview.get());
        Ok(())
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/api/ocidl/nn-ocidl-iobjectwithsite
#[allow(non_snake_case)]
impl IObjectWithSite_Impl for BlpPreviewHandler_Impl {
    fn SetSite(&self, site: Ref<'_, IUnknown>) -> Result<()> {
        let mut slot = self.site.borrow_mut();
        let mut frame_slot = self.frame.borrow_mut();

        match site.cloned() {
            Some(u) => {
                let raw = u.as_raw();

                if slot.is_some() {
                    log(&format!("SetSite (site=0x{:X}) — replacing previous site", raw as usize));
                } else {
                    log(&format!("SetSite (site=0x{:X}) — new site assigned", raw as usize));
                }

                match u.cast::<IPreviewHandlerFrame>() {
                    Ok(frame) => {
                        log("  SetSite => cached IPreviewHandlerFrame");
                        *frame_slot = Some(frame);
                    }
                    Err(err) => {
                        log(&format!("  SetSite => IPreviewHandlerFrame unavailable (hr=0x{:08X})", err.code().0));
                        frame_slot.take();
                    }
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
                frame_slot.take();
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
        let preview = self.hwnd_preview.get();
        if !preview.is_invalid() {
            log(&format!("GetWindow → preview HWND(0x{:X})", preview.0 as usize));
            return Ok(preview);
        }

        let parent = self.hwnd_parent.get();
        log(&format!("GetWindow → fallback parent HWND(0x{:X})", parent.0 as usize));
        Ok(parent)
    }

    fn ContextSensitiveHelp(&self, fEnterMode: BOOL) -> Result<()> {
        log(&format!("ContextSensitiveHelp (fEnterMode={})", fEnterMode.as_bool()));
        Err(E_NOTIMPL.into())
    }
}

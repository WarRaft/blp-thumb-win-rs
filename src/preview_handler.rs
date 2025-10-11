// lib.rs (или отдельный модуль в вашем DLL-проекте)
// Cargo.toml должен подтянуть:
// windows = { version = "0.58", features = [
//   "implement",
//   "Win32_Foundation",
//   "Win32_System_Com",
//   "Win32_UI_Shell",
//   "Win32_UI_WindowsAndMessaging",
// ] }

use crate::{
    log::log,
    utils::{
        create_hbitmap_bgra_premul::create_hbitmap_bgra_premul, //
        decode_blp_rgba::decode_blp_rgba,
        rgba_to_bgra_premul::rgba_to_bgra_premul,
    },
};
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    ffi::c_void,
    sync::{Mutex, OnceLock},
    time::Instant,
};
use windows::Win32::UI::WindowsAndMessaging::{CREATESTRUCTW, WINDOWPOS, WM_CREATE, WM_MOVE, WM_NCCALCSIZE, WM_NCCREATE, WM_NCPAINT, WM_SHOWWINDOW, WM_WINDOWPOSCHANGED, WM_WINDOWPOSCHANGING};
use windows::{
    Win32::{
        Foundation::{COLORREF, E_FAIL, HINSTANCE, LPARAM, LRESULT, S_FALSE, WPARAM},
        Foundation::{
            E_INVALIDARG,
            E_NOINTERFACE,
            E_NOTIMPL,
            E_POINTER,
            GetLastError, //
            HWND,
            RECT,
        },
        Graphics::Gdi::{
            BeginPaint, //
            CreateCompatibleDC,
            DRAW_TEXT_FORMAT,
            DT_CENTER,
            DT_SINGLELINE,
            DT_VCENTER,
            DeleteDC,
            DeleteObject,
            DrawTextW,
            EndPaint,
            FillRect,
            GetStockObject,
            HALFTONE,
            HBITMAP,
            HBRUSH,
            HDC,
            InvalidateRect,
            PAINTSTRUCT,
            SRCCOPY,
            SelectObject,
            SetBkMode,
            SetStretchBltMode,
            SetTextColor,
            StretchBlt,
            TRANSPARENT,
            UpdateWindow,
            WHITE_BRUSH,
        },
        System::{
            Com::{
                CoTaskMemFree, //
                ISequentialStream,
                IStream,
                STATFLAG_DEFAULT,
                STATSTG,
                STREAM_SEEK_SET,
            },
            LibraryLoader::GetModuleHandleW,
            Ole::{
                IObjectWithSite, //
                IObjectWithSite_Impl,
                IOleWindow,
                IOleWindow_Impl,
            },
        },
        UI::{
            Input::KeyboardAndMouse::{GetFocus, SetFocus},
            Shell::{
                IPreviewHandler, //
                IPreviewHandler_Impl,
                IPreviewHandlerFrame,
                IShellItem,
                PropertiesSystem::{
                    IInitializeWithStream, //
                    IInitializeWithStream_Impl,
                },
                SIGDN_FILESYSPATH,
                ShellExecuteW,
            },
            WindowsAndMessaging::{CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW, DestroyWindow, GetClientRect, HCURSOR, HICON, IDC_ARROW, LoadCursorW, MSG, RegisterClassW, SW_SHOWNORMAL, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOZORDER, SetCursor, SetParent, SetWindowPos, WINDOW_EX_STYLE, WINDOW_STYLE, WM_DESTROY, WM_ERASEBKGND, WM_LBUTTONUP, WM_PAINT, WM_PRINTCLIENT, WM_SETCURSOR, WM_SIZE, WNDCLASSW, WS_CHILD, WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_VISIBLE},
        },
    },
    core::{
        BOOL,
        GUID,
        HRESULT, //
        IUnknown,
        Interface,
        PCWSTR,
        Ref,
        Result,
        implement,
        w,
    },
};

static WNDCLASS_ATOM: OnceLock<u16> = OnceLock::new();
const CLASS_NAME: PCWSTR = w!("BlpPreviewWnd");
static PREVIEW_BITMAPS: OnceLock<Mutex<HashMap<isize, PreviewBitmap>>> = OnceLock::new();
static PREVIEW_PATHS: OnceLock<Mutex<HashMap<isize, Vec<u16>>>> = OnceLock::new();

#[derive(Clone, Copy)]
struct PreviewBitmap {
    hbmp: HBITMAP,
    width: i32,
    height: i32,
}

// Safe: GDI HBITMAP handles are process-wide; we guard all access via the UI thread and explicit destruction.
unsafe impl Send for PreviewBitmap {}

fn preview_store() -> &'static Mutex<HashMap<isize, PreviewBitmap>> {
    PREVIEW_BITMAPS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn preview_store_set(hwnd: HWND, bitmap: PreviewBitmap) {
    let mut store = preview_store().lock().unwrap();
    if let Some(old) = store.insert(hwnd.0 as isize, bitmap) {
        unsafe {
            let _ = DeleteObject(old.hbmp.into());
        }
    }
}

fn preview_store_get(hwnd: HWND) -> Option<PreviewBitmap> {
    preview_store()
        .lock()
        .unwrap()
        .get(&(hwnd.0 as isize))
        .copied()
}

fn preview_store_remove(hwnd: HWND) {
    let mut store = preview_store().lock().unwrap();
    if let Some(old) = store.remove(&(hwnd.0 as isize)) {
        unsafe {
            let _ = DeleteObject(old.hbmp.into());
        }
        log(&format!("preview_store_remove: hwnd=0x{:X} bitmap freed", hwnd.0 as usize));
    } else {
        log(&format!("preview_store_remove: hwnd=0x{:X} nothing to remove", hwnd.0 as usize));
    }
    preview_path_remove(hwnd);
}

fn preview_path_store() -> &'static Mutex<HashMap<isize, Vec<u16>>> {
    PREVIEW_PATHS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn preview_path_set(hwnd: HWND, path: Option<Vec<u16>>) {
    let mut map = preview_path_store().lock().unwrap();
    let key = hwnd.0 as isize;
    if let Some(mut path) = path {
        if !path.ends_with(&[0]) {
            path.push(0);
        }
        let _ = map.insert(key, path);
        log(&format!("preview_path_set: hwnd=0x{:X} -> stored path", hwnd.0 as usize));
    } else if map.remove(&key).is_some() {
        log(&format!("preview_path_set: hwnd=0x{:X} removed path", hwnd.0 as usize));
    }
}

fn preview_path_get(hwnd: HWND) -> Option<Vec<u16>> {
    preview_path_store()
        .lock()
        .unwrap()
        .get(&(hwnd.0 as isize))
        .cloned()
}

fn preview_path_remove(hwnd: HWND) {
    preview_path_set(hwnd, None);
}

fn request_redraw(hwnd: HWND, reason: &str) {
    unsafe {
        let res = InvalidateRect(Some(hwnd), None, true);
        if res.as_bool() {
            log(&format!("  request_redraw(\"{}\"): InvalidateRect => OK", reason));
        } else {
            let err = GetLastError();
            log(&format!("  request_redraw(\"{}\"): InvalidateRect failed err=0x{:08X}", reason, err.0));
        }

        let res = UpdateWindow(hwnd);
        if res.as_bool() {
            log(&format!("  request_redraw(\"{}\"): UpdateWindow => OK", reason));
        } else {
            let err = GetLastError();
            log(&format!("  request_redraw(\"{}\"): UpdateWindow failed err=0x{:08X}", reason, err.0));
        }
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            log(&format!("wndproc(HWND=0x{:X}) WM_PAINT begin", hwnd.0 as usize));
            let mut ps = PAINTSTRUCT::default();
            let hdc: HDC = unsafe { BeginPaint(hwnd, &mut ps) };

            let mut rc = RECT::default();
            unsafe {
                let _ = GetClientRect(hwnd, &mut rc);
            }
            log(&format!("  WM_PAINT client rect=({}, {}, {}, {})", rc.left, rc.top, rc.right, rc.bottom));

            unsafe {
                draw_preview_contents(hwnd, hdc, &rc);
            }

            unsafe {
                let _ = EndPaint(hwnd, &ps);
            }
            log(&format!("wndproc(HWND=0x{:X}) WM_PAINT end", hwnd.0 as usize));
            return LRESULT(0);
        }

        WM_PRINTCLIENT => {
            log(&format!("wndproc(HWND=0x{:X}) WM_PRINTCLIENT hdc=0x{:X} flags=0x{:X}", hwnd.0 as usize, w.0, l.0));
            let mut rc = RECT::default();
            unsafe {
                let _ = GetClientRect(hwnd, &mut rc);
                draw_preview_contents(hwnd, HDC(w.0 as *mut c_void), &rc);
            }
            return LRESULT(0);
        }
        WM_LBUTTONUP => {
            log(&format!("wndproc(HWND=0x{:X}) WM_LBUTTONUP", hwnd.0 as usize));
            if let Some(path) = preview_path_get(hwnd) {
                let file = PCWSTR(path.as_ptr());
                let result = unsafe { ShellExecuteW(Some(hwnd), PCWSTR::null(), file, PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL) };
                if (result.0 as isize) <= 32 {
                    log(&format!("  ShellExecuteW failed (code={})", result.0 as isize));
                } else {
                    log("  ShellExecuteW => OK");
                }
            } else {
                log("  WM_LBUTTONUP: no cached path to open");
            }
            return LRESULT(0);
        }
        WM_SETCURSOR => {
            log(&format!("wndproc(HWND=0x{:X}) WM_SETCURSOR hit=0x{:X} msg=0x{:X}", hwnd.0 as usize, w.0, l.0));
            if w.0 == hwnd.0 as usize {
                unsafe {
                    match LoadCursorW(None, IDC_ARROW) {
                        Ok(cur) => {
                            let _ = SetCursor(Some(cur));
                            return LRESULT(1);
                        }
                        Err(err) => {
                            log(&format!("  WM_SETCURSOR: LoadCursorW failed hr=0x{:08X}", err.code().0 as u32));
                        }
                    }
                }
            }
            return unsafe { DefWindowProcW(hwnd, msg, w, l) };
        }
        WM_ERASEBKGND => {
            log(&format!("wndproc(HWND=0x{:X}) WM_ERASEBKGND", hwnd.0 as usize));
            return LRESULT(1);
        }
        WM_SIZE => {
            log(&format!("wndproc(HWND=0x{:X}) WM_SIZE wParam=0x{:X} lParam=0x{:X}", hwnd.0 as usize, w.0, l.0));
            let width = (l.0 & 0xFFFF) as u16 as i32;
            let height = ((l.0 >> 16) & 0xFFFF) as u16 as i32;
            log(&format!("  WM_SIZE new client size {}x{}", width, height));
            unsafe {
                let _ = InvalidateRect(Some(hwnd), None, true);
            }
            return LRESULT(0);
        }
        WM_DESTROY => {
            log(&format!("wndproc(HWND=0x{:X}) WM_DESTROY", hwnd.0 as usize));
            preview_store_remove(hwnd);
        }

        WM_CREATE => {
            // lParam → *const CREATESTRUCTW
            log(&format!("wndproc(HWND=0x{:X}) WM_CREATE lp=0x{:X}", hwnd.0 as usize, l.0 as usize));
        }

        WM_MOVE => {
            #[inline]
            fn lo16(v: isize) -> i32 {
                (v as u32 & 0xFFFF) as u16 as i16 as i32
            }
            #[inline]
            fn hi16(v: isize) -> i32 {
                ((v as u32 >> 16) & 0xFFFF) as u16 as i16 as i32
            }

            // lParam: LOWORD = x, HIWORD = y (клиентская позиция)
            let x = lo16(l.0);
            let y = hi16(l.0);
            log(&format!("wndproc(HWND=0x{:X}) WM_MOVE x={} y={}", hwnd.0 as usize, x, y));
        }

        WM_SHOWWINDOW => {
            // wParam: TRUE/FALSE; lParam: причина (например, SW_PARENTOPENING и т.п.)
            log(&format!("wndproc(HWND=0x{:X}) WM_SHOWWINDOW shown={} reason=0x{:X}", hwnd.0 as usize, w.0 != 0, l.0 as usize));
        }

        WM_WINDOWPOSCHANGING => {
            // lParam → *mut WINDOWPOS
            log(&format!("wndproc(HWND=0x{:X}) WM_WINDOWPOSCHANGING lp=0x{:X}", hwnd.0 as usize, l.0 as usize));
            if l.0 != 0 {
                let wp = l.0 as *const WINDOWPOS;
                unsafe {
                    let wp = &*wp;
                    log(&format!(
                        "  WINDOWPOS hwnd=0x{:X} insertAfter=0x{:X} x={} y={} cx={} cy={} flags=0x{:08X}",
                        wp.hwnd.0 as usize,
                        wp.hwndInsertAfter.0 as usize,
                        wp.x,
                        wp.y,
                        wp.cx,
                        wp.cy,
                        wp.flags.0, // или u32::from(wp.flags)
                    ));
                }
            }
        }

        WM_WINDOWPOSCHANGED => {
            // lParam → *const WINDOWPOS
            log(&format!("wndproc(HWND=0x{:X}) WM_WINDOWPOSCHANGED lp=0x{:X}", hwnd.0 as usize, l.0 as usize));
            if l.0 != 0 {
                let wp = l.0 as *const WINDOWPOS;
                unsafe {
                    let wp = &*wp;
                    log(&format!(
                        "  WINDOWPOS hwnd=0x{:X} insertAfter=0x{:X} x={} y={} cx={} cy={} flags=0x{:08X}",
                        wp.hwnd.0 as usize, //
                        wp.hwndInsertAfter.0 as usize,
                        wp.x,
                        wp.y,
                        wp.cx,
                        wp.cy,
                        wp.flags.0
                    ));
                }
            }
        }

        // === Non Client
        WM_NCCREATE => {
            // lParam → *const CREATESTRUCTW
            log(&format!("wndproc(HWND=0x{:X}) WM_NCCREATE lp=0x{:X}", hwnd.0 as usize, l.0 as usize));
            if l.0 != 0 {
                // просто для трассировки, без разыменования полей
                let cs = l.0 as *const CREATESTRUCTW;
                log(&format!("  CREATESTRUCTW*={:p}", cs));
            }
        }

        WM_NCCALCSIZE => {
            // wParam: 1 => lParam указывает на NCCALCSIZE_PARAMS; 0 => RECT*
            log(&format!("wndproc(HWND=0x{:X}) WM_NCCALCSIZE wParam=0x{:X} lParam=0x{:X}", hwnd.0 as usize, w.0, l.0 as usize));
        }

        WM_NCPAINT => {
            // wParam: HRGN (region) или 1 (перерисовать всё); lParam обычно 0
            let rg = w.0; // 0 | 1 | HRGN
            log(&format!("wndproc(HWND=0x{:X}) WM_NCPAINT hrgn={}{}", hwnd.0 as usize, if rg == 1 { "ALL" } else { "0x" }, if rg == 1 { String::new() } else { format!("{:X}", rg) }));
            // Ничего кастомного не рисуем → пусть система/ DWM сделают своё
            // Верни 0 и дай базовой процедуре дорисовать:
            return DefWindowProcW(hwnd, msg, w, l).into();
        }

        // === Uncatched
        _ => {
            log(&format!("wndproc(HWND=0x{:X}) unhandled msg=0x{:X}", hwnd.0 as usize, msg));
        }
    }
    unsafe { DefWindowProcW(hwnd, msg, w, l) }
}

unsafe fn paint_preview_bitmap(hdc: HDC, rc: &RECT, bmp: PreviewBitmap) -> bool {
    if bmp.hbmp.is_invalid() || bmp.width <= 0 || bmp.height <= 0 {
        log("  paint_preview_bitmap: invalid bitmap metadata");
        return false;
    }

    let avail_w = rc.right - rc.left;
    let avail_h = rc.bottom - rc.top;
    if avail_w <= 0 || avail_h <= 0 {
        log("  paint_preview_bitmap: zero-sized client rect");
        return false;
    }

    let scale = (avail_w as f64 / bmp.width as f64)
        .min(avail_h as f64 / bmp.height as f64)
        .max(0.0);
    let draw_w = (bmp.width as f64 * scale).max(1.0).round() as i32;
    let draw_h = (bmp.height as f64 * scale).max(1.0).round() as i32;
    let draw_x = rc.left + (avail_w - draw_w) / 2;
    let draw_y = rc.top + (avail_h - draw_h) / 2;

    let mem_dc = unsafe { CreateCompatibleDC(Some(hdc)) };
    if mem_dc.is_invalid() {
        log("  paint_preview_bitmap: CreateCompatibleDC failed");
        return false;
    }

    let old = unsafe { SelectObject(mem_dc, bmp.hbmp.into()) };
    if old.is_invalid() {
        log("  paint_preview_bitmap: SelectObject returned NULL");
    }

    let mode = unsafe { SetStretchBltMode(hdc, HALFTONE) };
    if mode == 0 {
        log("  paint_preview_bitmap: SetStretchBltMode failed");
    }

    let blt = unsafe { StretchBlt(hdc, draw_x, draw_y, draw_w, draw_h, Some(mem_dc), 0, 0, bmp.width, bmp.height, SRCCOPY) };
    if !blt.as_bool() {
        let err = unsafe { GetLastError() };
        log(&format!("  paint_preview_bitmap: StretchBlt failed err=0x{:08X}", err.0));
    }

    if !old.is_invalid() {
        let _ = unsafe { SelectObject(mem_dc, old) };
    }
    let _ = unsafe { DeleteDC(mem_dc) };

    blt.as_bool()
}

unsafe fn draw_preview_contents(hwnd: HWND, hdc: HDC, rc: &RECT) {
    // фон
    unsafe {
        FillRect(hdc, rc, HBRUSH(GetStockObject(WHITE_BRUSH).0));
    }

    let mut painted_bitmap = false;
    if let Some(bmp) = preview_store_get(hwnd) {
        painted_bitmap = unsafe { paint_preview_bitmap(hdc, rc, bmp) };
        if painted_bitmap {
            log(&format!("  draw_preview_contents: rendered bitmap {}x{}", bmp.width, bmp.height));
        } else {
            log("  draw_preview_contents: bitmap draw failed -> fallback text");
        }
    } else {
        log("  draw_preview_contents: no cached bitmap -> fallback text");
    }

    if !painted_bitmap {
        unsafe {
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, COLORREF(0)); // RGB(0,0,0)
        }

        let mut wtxt: Vec<u16> = "BLP preview unavailable".encode_utf16().collect();
        wtxt.push(0);
        let fmt = DRAW_TEXT_FORMAT(DT_CENTER.0 | DT_VCENTER.0 | DT_SINGLELINE.0);
        let mut text_rc = *rc;
        let painted = unsafe { DrawTextW(hdc, &mut wtxt, &mut text_rc, fmt) };
        log(&format!("  draw_preview_contents: DrawTextW => {}", painted));
    }
}

fn ensure_class_registered() -> Result<()> {
    if WNDCLASS_ATOM.get().is_some() {
        return Ok(());
    }

    unsafe {
        // HINSTANCE через GetModuleHandleW(None)
        let hinst = HINSTANCE(GetModuleHandleW(None).ok().map(|h| h.0).unwrap_or_default());

        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            hInstance: hinst,
            hIcon: HICON::default(),
            hCursor: {
                let cur: HCURSOR = LoadCursorW(None, IDC_ARROW)?;
                cur
            },
            hbrBackground: HBRUSH(GetStockObject(WHITE_BRUSH).0),
            lpszClassName: CLASS_NAME,
            ..Default::default()
        };

        let atom: u16 = RegisterClassW(&wc);
        if atom == 0 {
            return Err(windows::core::Error::from(E_FAIL));
        }
        // OnceLock без try_init на стабильном Rust
        let _ = WNDCLASS_ATOM.set(atom);
    }

    Ok(())
}

#[implement(IObjectWithSite, IPreviewHandler, IOleWindow, IInitializeWithStream)]
pub struct BlpPreviewHandler {
    hwnd_parent: Cell<HWND>,
    hwnd_preview: Cell<HWND>,
    rc_parent: Cell<RECT>,
    site: RefCell<Option<IUnknown>>,
    stream: RefCell<Option<IStream>>,
    frame: RefCell<Option<IPreviewHandlerFrame>>,
    file_path: RefCell<Option<Vec<u16>>>,
}

#[allow(non_snake_case)]
impl BlpPreviewHandler {
    pub fn new() -> Self {
        log("BlpPreviewHandler::new");
        Self {
            hwnd_parent: Cell::new(HWND::default()), //
            hwnd_preview: Cell::new(HWND::default()),
            rc_parent: Cell::new(RECT { left: 0, top: 0, right: 0, bottom: 0 }),
            site: RefCell::new(None),
            stream: RefCell::new(None),
            frame: RefCell::new(None),
            file_path: RefCell::new(None),
        }
    }
}

impl BlpPreviewHandler_Impl {
    fn set_file_path(&self, path: Option<String>, source: &str) {
        let mut slot = self.file_path.borrow_mut();
        if let Some(path) = path {
            let mut wide: Vec<u16> = path.encode_utf16().collect();
            if !wide.ends_with(&[0]) {
                wide.push(0);
            }
            log(&format!("  cached file path from {}: {}", source, path));
            *slot = Some(wide);
        } else {
            log(&format!("  cached file path from {}: <none>", source));
            slot.take();
        }
    }

    fn update_path_from_shell_item(&self, site: &IUnknown) {
        match site.cast::<IShellItem>() {
            Ok(item) => match unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) } {
                Ok(pwstr) => {
                    if pwstr.is_null() {
                        log("  IShellItem::GetDisplayName returned NULL");
                        self.set_file_path(None, "site");
                    } else {
                        let path = unsafe { pwstr.to_string().unwrap_or_default() };
                        unsafe {
                            CoTaskMemFree(Some(pwstr.0 as _));
                        }
                        if path.is_empty() {
                            log("  IShellItem::GetDisplayName returned empty string");
                            self.set_file_path(None, "site");
                        } else {
                            self.set_file_path(Some(path), "site");
                        }
                    }
                }
                Err(err) => {
                    log(&format!("  IShellItem::GetDisplayName failed hr=0x{:08X}", err.code().0 as u32));
                }
            },
            Err(err) => {
                log(&format!("  site cast to IShellItem failed hr=0x{:08X}", err.code().0 as u32));
            }
        }
    }

    fn update_path_from_stream(&self) {
        let path = self.stream.borrow().as_ref().and_then(|stream| {
            let mut stat = STATSTG::default();
            match unsafe { stream.Stat(&mut stat, STATFLAG_DEFAULT) } {
                Ok(()) => {
                    if stat.pwcsName.is_null() {
                        log("  IStream::Stat returned NULL pwcsName");
                        None
                    } else {
                        let name = unsafe { stat.pwcsName.to_string().unwrap_or_default() };
                        unsafe {
                            CoTaskMemFree(Some(stat.pwcsName.0 as _));
                        }
                        if name.is_empty() {
                            log("  IStream::Stat pwcsName empty");
                            None
                        } else {
                            Some(name)
                        }
                    }
                }
                Err(err) => {
                    log(&format!("  IStream::Stat failed hr=0x{:08X}", err.code().0 as u32));
                    None
                }
            }
        });
        if let Some(path) = path {
            self.set_file_path(Some(path), "stream");
        }
    }

    fn update_frame_from_site(&self, site: &IUnknown) {
        match site.cast::<IPreviewHandlerFrame>() {
            Ok(frame) => {
                log("  site cast to IPreviewHandlerFrame => OK");
                *self.frame.borrow_mut() = Some(frame.clone());
                match unsafe { frame.GetWindowContext() } {
                    Ok(info) => {
                        log(&format!("  IPreviewHandlerFrame::GetWindowContext => OK (cAccelEntries={})", info.cAccelEntries));
                        if info.haccel.0.is_null() {
                            log("  frame context haccel=NULL");
                        }
                    }
                    Err(err) => {
                        log(&format!("  IPreviewHandlerFrame::GetWindowContext => ERR hr=0x{:08X}", err.code().0 as u32));
                    }
                }
            }
            Err(err) => {
                log(&format!("  site cast to IPreviewHandlerFrame failed hr=0x{:08X}", err.code().0 as u32));
                self.frame.borrow_mut().take();
            }
        }
    }

    fn load_bitmap_for_hwnd(&self, hwnd: HWND) -> Result<()> {
        log(&format!("  load_bitmap_for_hwnd(HWND=0x{:X}) begin", hwnd.0 as usize));
        let total_start = Instant::now();

        let read_start = Instant::now();
        let data = match self.read_stream_bytes() {
            Ok(buf) => buf,
            Err(err) => {
                log(&format!("  load_bitmap_for_hwnd: stream read failed hr=0x{:08X}", err.code().0 as u32));
                preview_store_remove(hwnd);
                return Err(err);
            }
        };
        log(&format!("  load_bitmap_for_hwnd: read {} bytes ({} ms)", data.len(), read_start.elapsed().as_millis()));

        let decode_start = Instant::now();
        let (w, h, rgba) = decode_blp_rgba(&data).map_err(|_| {
            log("  load_bitmap_for_hwnd: decode_blp_rgba failed");
            windows::core::Error::from(E_FAIL)
        })?;
        log(&format!("  load_bitmap_for_hwnd: decoded image {}x{} ({} ms)", w, h, decode_start.elapsed().as_millis()));

        let convert_start = Instant::now();
        let bgra = rgba_to_bgra_premul(&rgba);
        let hbmp = unsafe { create_hbitmap_bgra_premul(w as i32, h as i32, &bgra)? };
        log(&format!("  load_bitmap_for_hwnd: converted to HBITMAP ({} ms)", convert_start.elapsed().as_millis()));

        preview_store_set(hwnd, PreviewBitmap { hbmp, width: w as i32, height: h as i32 });
        log(&format!("  load_bitmap_for_hwnd: bitmap cached {}x{}", w, h));
        let path_clone = self.file_path.borrow().as_ref().cloned();
        preview_path_set(hwnd, path_clone);

        request_redraw(hwnd, "load_bitmap_for_hwnd");
        log(&format!("  load_bitmap_for_hwnd: total {} ms", total_start.elapsed().as_millis()));
        Ok(())
    }

    fn read_stream_bytes(&self) -> Result<Vec<u8>> {
        let stream = {
            let borrowed = self.stream.borrow();
            borrowed.as_ref().cloned().ok_or_else(|| {
                log("  read_stream_bytes: stream not initialized");
                windows::core::Error::from(E_POINTER)
            })?
        };
        Self::read_stream_to_vec(&stream)
    }

    fn read_stream_to_vec(stream: &IStream) -> Result<Vec<u8>> {
        unsafe {
            stream.Seek(0, STREAM_SEEK_SET, None)?;
        }
        let seq: ISequentialStream = stream.cast()?;
        let mut data = Vec::new();
        let mut buf = [0u8; 8192];

        loop {
            let mut read = 0u32;
            let hr = unsafe { seq.Read(buf.as_mut_ptr() as *mut _, buf.len() as u32, Some(&mut read as *mut u32)) };

            if hr.is_err() {
                log(&format!("  read_stream_to_vec: Read failed hr=0x{:08X}", hr.0 as u32));
                return Err(windows::core::Error::from(hr));
            }

            if read > 0 {
                data.extend_from_slice(&buf[..read as usize]);
            }

            if hr == S_FALSE || read == 0 {
                break;
            }
        }

        if data.is_empty() {
            log("  read_stream_to_vec: stream empty");
        }
        Ok(data)
    }
}

#[allow(non_snake_case)]
impl IObjectWithSite_Impl for BlpPreviewHandler_Impl {
    fn SetSite(&self, p_unknown_site: Ref<'_, IUnknown>) -> Result<()> {
        log("BlpPreviewHandler::SetSite");
        let mut slot = self.site.borrow_mut();
        if let Some(site) = p_unknown_site.as_ref() {
            log(&format!("  site ptr={:?}", site.as_raw()));
            if slot.is_some() {
                log("  replacing cached site");
            }
            *slot = Some(site.clone());
            log("  site cached (AddRef held)");
            drop(slot);
            self.update_frame_from_site(site);
            self.update_path_from_shell_item(site);
            self.update_path_from_stream();
        } else {
            log("  site ptr=NULL -> clearing cached site");
            let had_site = slot.take().is_some();
            if had_site {
                log("  previous site released");
            } else {
                log("  no cached site to clear");
            }
            drop(slot);
            if self.frame.borrow_mut().take().is_some() {
                log("  cached frame released");
            }
            if self.file_path.borrow_mut().take().is_some() {
                log("  cached file path cleared");
            }
        }
        Ok(())
    }

    fn GetSite(&self, riid: *const GUID, ppv: *mut *mut c_void) -> Result<()> {
        log("BlpPreviewHandler::GetSite");
        unsafe {
            if ppv.is_null() {
                return Err(E_POINTER.into());
            }
            *ppv = std::ptr::null_mut();
        }

        // берём копию без блокировки borrow
        let owned = self.site.borrow().clone();
        let Some(current) = owned else {
            log("  no cached site -> E_NOINTERFACE");
            return Err(E_NOINTERFACE.into());
        };

        let hr = unsafe { current.query(riid, ppv) };
        if hr.is_ok() {
            unsafe {
                log(&format!("  QueryInterface => OK, out_ptr={:?}", *ppv));
            }
            Ok(())
        } else {
            log(&format!("  QueryInterface => ERR hr=0x{:08X}", hr.0 as u32));
            Err(hr.into())
        }
    }
}

#[allow(non_snake_case)]
impl IPreviewHandler_Impl for BlpPreviewHandler_Impl {
    fn SetWindow(&self, hwnd: HWND, prc: *const RECT) -> Result<()> {
        log("BlpPreviewHandler::SetWindow (enter)");

        // --- проверка входных параметров ---
        log(&format!("  hwnd=0x{:X}, prc={:?}", hwnd.0 as usize, prc));
        if hwnd.is_invalid() {
            log("  hwnd invalid -> tearing down preview window");
            self.hwnd_parent.set(HWND::default());
            self.rc_parent
                .set(RECT { left: 0, top: 0, right: 0, bottom: 0 });

            let preview = self.hwnd_preview.get();
            if preview.is_invalid() {
                log("  preview already cleared");
            } else {
                unsafe {
                    match DestroyWindow(preview) {
                        Ok(_) => log(&format!("  DestroyWindow(HWND=0x{:X}) => OK", preview.0 as usize)),
                        Err(e) => log(&format!("  DestroyWindow(HWND=0x{:X}) => ERR hr=0x{:08X}", preview.0 as usize, e.code().0 as u32)),
                    }
                }
                preview_store_remove(preview);
                self.hwnd_preview.set(HWND::default());
            }
            log("  reset cached RECT and HWND");
            log("  BlpPreviewHandler::SetWindow (exit, teardown, return S_OK)");
            return Ok(());
        }
        if prc.is_null() {
            log("  prc null -> return E_INVALIDARG");
            return Err(E_INVALIDARG.into());
        }

        // --- кешируем родителя и прямоугольник ---
        let rc = unsafe { *prc };
        log(&format!("  cache parent HWND(0x{:X}) rc=({}, {}, {}, {})", hwnd.0 as usize, rc.left, rc.top, rc.right, rc.bottom));
        self.hwnd_parent.set(hwnd);
        self.rc_parent.set(rc);

        // --- если превью уже есть, перепривяжем и обновим размер ---
        let preview = self.hwnd_preview.get();
        if !preview.is_invalid() {
            unsafe {
                log(&format!("  preview exists -> HWND(0x{:X}) -> SetParent(...)", preview.0 as usize));
                match SetParent(preview, Some(hwnd)) {
                    Ok(new_parent) => {
                        log(&format!("  SetParent => OK, new parent HWND(0x{:X})", new_parent.0 as usize));
                    }
                    Err(e) => {
                        log(&format!("  SetParent => ERR hr=0x{:08X}", e.code().0 as u32));
                    }
                }

                let width = rc.right - rc.left;
                let height = rc.bottom - rc.top;
                log(&format!("  SetWindowPos: left={}, top={}, width={}, height={}", rc.left, rc.top, width, height));

                match SetWindowPos(
                    preview,
                    Some(HWND::default()), //
                    rc.left,
                    rc.top,
                    width,
                    height,
                    SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOMOVE,
                ) {
                    Ok(_) => log("  SetWindowPos => OK"),
                    Err(e) => log(&format!("  SetWindowPos => ERR hr=0x{:08X}", e.code().0 as u32)),
                };
            }
        } else {
            log("  preview HWND invalid (none created yet)");
        }

        log("  BlpPreviewHandler::SetWindow (exit, return S_OK)");
        Ok(())
    }

    fn SetRect(&self, prc: *const RECT) -> Result<()> {
        log("BlpPreviewHandler::SetRect (enter)");

        // --- проверка входного указателя ---
        if prc.is_null() {
            log("  prc is NULL -> E_INVALIDARG");
            return Err(E_INVALIDARG.into());
        }

        // --- кешируем прямоугольник ---
        let rc = unsafe { *prc };
        self.rc_parent.set(rc);
        let width = rc.right - rc.left;
        let height = rc.bottom - rc.top;
        log(&format!(
            "  cached rc=({}, {}, {}, {}), size={}x{}",
            rc.left, //
            rc.top,
            rc.right,
            rc.bottom,
            width,
            height
        ));

        // --- если превью уже создано, обновляем его размер ---
        let preview = self.hwnd_preview.get();
        log(&format!("  preview HWND = 0x{:X} (invalid={})", preview.0 as usize, preview.is_invalid()));

        if !preview.is_invalid() {
            log(&format!("  preview HWND(0x{:X}) exists -> SetWindowPos({}, {}, {}, {})", preview.0 as usize, rc.left, rc.top, width, height));

            unsafe {
                match SetWindowPos(
                    preview,
                    Some(HWND::default()),
                    rc.left, // SWP_NOMOVE — позиция игнорируется, но логируем для полноты
                    rc.top,
                    width,
                    height,
                    SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
                ) {
                    Ok(_) => log("  SetWindowPos => OK"),
                    Err(e) => log(&format!("  SetWindowPos => ERR hr=0x{:08X}", e.code().0 as u32)),
                }
            }
            request_redraw(preview, "SetRect");
        } else {
            log("  preview HWND invalid (no window yet)");
        }

        log("  BlpPreviewHandler::SetRect (exit, return S_OK)");
        Ok(())
    }

    fn DoPreview(&self) -> Result<()> {
        log("BlpPreviewHandler::DoPreview (custom hwnd)");

        let current_preview = self.hwnd_preview.get();
        if !current_preview.is_invalid() {
            log(&format!("  existing preview HWND detected=0x{:X} -> will destroy and recreate", current_preview.0 as usize));
            unsafe {
                match DestroyWindow(current_preview) {
                    Ok(_) => log("  DestroyWindow(existing preview) => OK"),
                    Err(e) => log(&format!("  DestroyWindow(existing preview) => ERR hr=0x{:08X}", e.code().0 as u32)),
                }
            }
            preview_store_remove(current_preview);
            self.hwnd_preview.set(HWND::default());
        } else {
            log("  no existing preview HWND cached");
        }

        let parent = self.hwnd_parent.get();
        if parent.is_invalid() {
            log("  parent invalid -> E_INVALIDARG");
            return Err(E_INVALIDARG.into());
        }

        ensure_class_registered()?;

        // Берём кэшированный rc, но даже если там 0×0 — СОЗДАЁМ окно!
        let rc = self.rc_parent.get();
        let mut w = rc.right - rc.left;
        let mut h = rc.bottom - rc.top;
        if w <= 0 || h <= 0 {
            // На этом этапе Explorer обычно ещё не успел вызвать SetRect —
            // создаём маленькое окно, чтобы хост увидел "готово".
            w = 1;
            h = 1;
            log("  rc is empty at DoPreview -> creating 1x1 placeholder (will be resized in SetRect)");
        } else {
            log(&format!("  rc at DoPreview: {}x{}", w, h));
        }

        let stream_ptr = self
            .stream
            .borrow()
            .as_ref()
            .map(|s| format!("{:?}", s.as_raw()))
            .unwrap_or_else(|| "None".to_string());
        log(&format!("  cached IStream={}", stream_ptr));

        let hwnd = unsafe {
            log(&format!("  CreateWindowExW(parent=0x{:X}, size={}x{})", parent.0 as usize, w, h));
            CreateWindowExW(
                WINDOW_EX_STYLE(0), //
                CLASS_NAME,
                PCWSTR::null(),
                WINDOW_STYLE((WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN).0),
                0,
                0,
                w,
                h,
                Some(parent),
                None,
                None,
                None,
            )?
        };

        log(&format!("  created preview HWND=0x{:X} ({}x{})", hwnd.0 as usize, w, h));
        self.hwnd_preview.set(hwnd);

        match self.load_bitmap_for_hwnd(hwnd) {
            Ok(_) => log("  load_bitmap_for_hwnd => OK"),
            Err(err) => {
                log(&format!("  load_bitmap_for_hwnd => ERR hr=0x{:08X}", err.code().0 as u32));
            }
        }

        unsafe {
            let res = UpdateWindow(hwnd);
            if res.as_bool() {
                log("  UpdateWindow => OK");
            } else {
                let err = GetLastError();
                log(&format!("  UpdateWindow => ERR GetLastError=0x{:08X}", err.0));
            }
        }

        if let Err(err) = self.SetFocus() {
            log(&format!("  SetFocus (auto) failed hr=0x{:08X}", err.code().0 as u32));
        }

        log("  DoPreview => S_OK");
        Ok(())
    }

    fn Unload(&self) -> Result<()> {
        log("BlpPreviewHandler::Unload");
        if self.stream.borrow().is_some() {
            log("  clearing cached stream");
        } else {
            log("  no cached stream to clear");
        }
        *self.stream.borrow_mut() = None;
        if self.file_path.borrow_mut().take().is_some() {
            log("  cleared cached file path");
        }

        let hwnd = self.hwnd_preview.get();
        if !hwnd.is_invalid() {
            unsafe {
                match DestroyWindow(hwnd) {
                    Ok(_) => log(&format!("  DestroyWindow(HWND=0x{:X}) => OK", hwnd.0 as usize)),
                    Err(e) => {
                        log(&format!("  DestroyWindow(HWND=0x{:X}) => ERR hr=0x{:08X}", hwnd.0 as usize, e.code().0 as u32));
                        return Err(e);
                    }
                }
            }
            preview_store_remove(hwnd);
            self.hwnd_preview.set(HWND::default());
        } else {
            log("  hwnd_preview already invalid");
        }

        Ok(())
    }

    fn SetFocus(&self) -> Result<()> {
        log("BlpPreviewHandler::SetFocus");
        let hwnd = self.hwnd_preview.get();
        if !hwnd.is_invalid() {
            unsafe {
                let prev = SetFocus(Some(hwnd));
                log(&format!("  SetFocus(HWND=0x{:X}) previous focus=0x{:X}", hwnd.0 as usize, prev.map(|h| h.0 as usize).unwrap_or(0)));
            }
            if let Some(frame) = self.frame.borrow().as_ref() {
                match unsafe { frame.GetWindowContext() } {
                    Ok(info) => log(&format!("  frame context after SetFocus: cAccelEntries={}", info.cAccelEntries)),
                    Err(err) => log(&format!("  frame GetWindowContext failed hr=0x{:08X}", err.code().0 as u32)),
                }
            } else {
                log("  SetFocus: frame not available");
            }
        } else {
            log("  hwnd_preview invalid -> nothing to focus");
        }
        Ok(())
    }

    fn QueryFocus(&self) -> Result<HWND> {
        log("BlpPreviewHandler::QueryFocus");
        unsafe {
            let h = GetFocus();
            if !h.is_invalid() {
                log(&format!("  QueryFocus => HWND=0x{:X}", h.0 as usize));
                Ok(h)
            } else {
                let code = GetLastError();
                let hr = HRESULT::from_win32(code.0);
                log(&format!("  QueryFocus => ERROR hr=0x{:08X}", hr.0 as u32));
                Err(windows::core::Error::new(hr, "GetFocus failed"))
            }
        }
    }

    fn TranslateAccelerator(&self, pmsg: *const MSG) -> Result<()> {
        log("BlpPreviewHandler::TranslateAccelerator");
        log(&format!("  MSG ptr={:?}", pmsg));
        if let Some(frame) = self.frame.borrow().as_ref() {
            unsafe {
                if let Err(err) = frame.TranslateAccelerator(pmsg) {
                    log(&format!("  IPreviewHandlerFrame::TranslateAccelerator => ERR hr=0x{:08X}", err.code().0 as u32));
                } else {
                    log("  IPreviewHandlerFrame::TranslateAccelerator invoked");
                }
            }
        } else {
            log("  frame not set -> S_OK without forwarding");
        }
        Ok(())
    }
}

#[allow(non_snake_case)]
impl IOleWindow_Impl for BlpPreviewHandler_Impl {
    fn GetWindow(&self) -> Result<HWND> {
        log("BlpPreviewHandler::GetWindow");
        let hwnd = self.hwnd_preview.get();
        if hwnd.is_invalid() {
            log("  hwnd_preview invalid -> E_FAIL");
            Err(E_FAIL.into())
        } else {
            log(&format!("  returning HWND=0x{:X}", hwnd.0 as usize));
            Ok(hwnd)
        }
    }

    #[allow(non_snake_case)]
    fn ContextSensitiveHelp(&self, _fEnterMode: BOOL) -> Result<()> {
        log("BlpPreviewHandler::ContextSensitiveHelp");
        Err(E_NOTIMPL.into())
    }
}

impl IInitializeWithStream_Impl for BlpPreviewHandler_Impl {
    #[allow(non_snake_case)]
    fn Initialize(&self, pStream: Ref<'_, IStream>, _grfMode: u32) -> Result<()> {
        log("BlpPreviewHandler::Initialize");
        // Initialize может вызываться повторно — просто перезаписываем
        *self.stream.borrow_mut() = pStream.cloned();
        self.update_path_from_stream();
        Ok(())
    }
}

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
use windows::{
    Win32::{
        Foundation::{
            COLORREF,
            E_FAIL,
            E_INVALIDARG,
            E_NOINTERFACE,
            E_NOTIMPL,
            E_POINTER,
            GetLastError, //
            HINSTANCE,
            HWND,
            LPARAM,
            LRESULT,
            RECT,
            S_FALSE,
            WPARAM,
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
                PropertiesSystem::{
                    IInitializeWithStream, //
                    IInitializeWithStream_Impl,
                },
                ShellExecuteW,
            },
            WindowsAndMessaging::{
                CREATESTRUCTW, //
                CS_HREDRAW,
                CS_VREDRAW,
                CreateWindowExW,
                DefWindowProcW,
                DestroyWindow,
                GetClassInfoExW,
                GetClientRect,
                HCURSOR,
                HICON,
                IDC_ARROW,
                LoadCursorW,
                MSG,
                RegisterClassW,
                SET_WINDOW_POS_FLAGS,
                SW_SHOWNORMAL,
                SWP_NOACTIVATE,
                SWP_NOMOVE,
                SWP_NOZORDER,
                SetCursor,
                SetParent,
                SetWindowPos,
                WINDOW_EX_STYLE,
                WINDOW_STYLE,
                WINDOWPOS,
                WM_CREATE,
                WM_DESTROY,
                WM_ERASEBKGND,
                WM_LBUTTONUP,
                WM_MOVE,
                WM_NCCALCSIZE,
                WM_NCCREATE,
                WM_NCPAINT,
                WM_PAINT,
                WM_PRINTCLIENT,
                WM_SETCURSOR,
                WM_SHOWWINDOW,
                WM_SIZE,
                WM_WINDOWPOSCHANGED,
                WM_WINDOWPOSCHANGING,
                WNDCLASSEXW,
                WNDCLASSW,
                WS_CHILD,
                WS_CLIPCHILDREN,
                WS_CLIPSIBLINGS,
                WS_VISIBLE,
            },
        },
    },
    core::{
        BOOL,
        GUID,
        HRESULT,
        IUnknown,
        Interface, //
        PCWSTR,
        Ref,
        Result,
        implement,
        w,
    },
};

const CLASS_NAME: PCWSTR = w!("BlpPreviewWnd");
static PREVIEW_BITMAPS: OnceLock<Mutex<HashMap<isize, PreviewBitmap>>> = OnceLock::new();
static PREVIEW_PATHS: OnceLock<Mutex<HashMap<isize, Vec<u16>>>> = OnceLock::new();
static CLASS_ATOM: OnceLock<u16> = OnceLock::new();

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
            use std::time::Instant;

            let t0 = Instant::now();
            let mut ps = PAINTSTRUCT::default();

            unsafe { BeginPaint(hwnd, &mut ps) };
            log(&format!("wndproc(HWND=0x{:X}) WM_PAINT begin (rcPaint=({}, {}, {}, {}))", hwnd.0 as usize, ps.rcPaint.left, ps.rcPaint.top, ps.rcPaint.right, ps.rcPaint.bottom));

            let t_draw = Instant::now();
            unsafe {
                draw_preview_contents(hwnd, ps.hdc, &ps.rcPaint);
            }
            let draw_ms = t_draw.elapsed().as_millis();
            log(&format!("  draw_preview_contents: {} ms", draw_ms));

            let ok = unsafe { EndPaint(hwnd, &ps).as_bool() };
            if ok {
                log(&format!("wndproc(HWND=0x{:X}) WM_PAINT EndPaint => OK", hwnd.0 as usize));
            } else {
                let gle = unsafe { GetLastError().0 };
                log(&format!("wndproc(HWND=0x{:X}) WM_PAINT EndPaint => FAIL GetLastError=0x{:08X}", hwnd.0 as usize, gle));
            }

            let total_ms = t0.elapsed().as_millis();
            log(&format!("wndproc(HWND=0x{:X}) WM_PAINT end (total={} ms)", hwnd.0 as usize, total_ms));
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

        // === Non-Client section ===
        // The "non-client area" refers to parts of a window drawn and managed by the system,
        // not by your application: borders, title bar, scroll bars, system buttons, etc.
        // A preview handler window (WS_CHILD) normally has no non-client area,
        // so we suppress these messages to avoid redundant painting or flicker.
        WM_NCCREATE => {
            // Sent before WM_CREATE to initialize the window's non-client area.
            // lParam points to a CREATESTRUCTW with creation parameters.
            log(&format!("wndproc(HWND=0x{:X}) WM_NCCREATE lp=0x{:X}", hwnd.0 as usize, l.0 as usize));
            if l.0 != 0 {
                let cs = l.0 as *const CREATESTRUCTW;
                log(&format!("  CREATESTRUCTW* = {:p}", cs));
            }
        }

        WM_NCCALCSIZE => {
            // Sent when the size and position of the client area must be calculated.
            // For child windows (like preview handlers) there is no frame, so we just ignore it.
            log(&format!("wndproc(HWND=0x{:X}) WM_NCCALCSIZE (ignored)", hwnd.0 as usize));
            return LRESULT(0);
        }

        WM_NCPAINT => {
            // Sent when the system needs to paint the non-client area
            // (e.g., borders, caption, scroll bars). For a borderless child window,
            // there is nothing to paint, so we intercept and return 0.
            log(&format!("wndproc(HWND=0x{:X}) WM_NCPAINT (ignored)", hwnd.0 as usize));
            return LRESULT(0);
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
    /// Connects this preview handler to the host **site** (`IObjectWithSite::SetSite` non-null overload).
    ///
    /// Purpose:
    /// - Cache the site interface for later use while the preview is active.
    /// - Optionally obtain `IPreviewHandlerFrame` for focus/accelerator routing (not required to render).
    ///
    /// Must be lightweight:
    /// - No I/O, no window creation, no painting, no blocking calls.
    /// - Just (re)cache interfaces and return.
    ///
    /// Parameters:
    /// - `site`: non-null site object provided by the host; cloning the `Ref` increments COM refcount.
    ///
    /// Call order (typical):
    /// `Initialize` → **`SetSite`** → `SetWindow` → `DoPreview` → `SetRect` (0+) → `Unload`.
    #[allow(non_snake_case)]
    fn SetSite(&self, site: Ref<'_, IUnknown>) -> Result<()> {
        log("BlpPreviewHandler::SetSite (enter, non-null)");

        if self.frame.borrow().is_some() {
            log("  releasing previous IPreviewHandlerFrame");
            *self.frame.borrow_mut() = None;
        }
        if self.site.borrow().is_some() {
            log("  releasing previous site");
            *self.site.borrow_mut() = None;
        }

        *self.site.borrow_mut() = site.clone();

        log("BlpPreviewHandler::SetSite (exit, return S_OK)");
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
#[allow(non_snake_case)]
impl IPreviewHandler_Impl for BlpPreviewHandler_Impl {
    /// Sets the host window for the preview handler (IPreviewHandler::SetWindow).
    ///
    /// # Contract (from MS Docs)
    /// - **Purpose:** The host (Explorer/prevhost) passes a **parent HWND** and the initial **display RECT**
    ///   for the preview content. This method is the *staging step* — no heavy work or rendering here.
    /// - **Call order:** `Initialize` → `SetSite` → **`SetWindow`** → `DoPreview` → `SetRect` (0+ times) → `Unload`.
    /// - **What you SHOULD do here:**
    ///   - Validate parameters.
    ///   - Cache the parent `HWND` and the `RECT` into your handler state.
    ///   - If your child window already exists, optionally **reparent** it to the new parent.
    ///     Geometry changes are expected to be applied later by **`SetRect`**.
    /// - **What you SHOULD NOT do here:**
    ///   - Do not create the child window (create it in **`DoPreview`**).
    ///   - Do not perform I/O/decoding or trigger synchronous paints (`UpdateWindow`).
    /// - **Special case:** If `parent` is invalid (null), treat it as a **teardown signal**: destroy your
    ///   child window and clear cached state. The handler object may remain alive.
    ///
    /// This implementation logs every step to help diagnose ordering and re-entrancy issues.
    /// It only records the parent/rect and (if present) reparents the existing child window.
    /// Any move/resize will be handled by **SetRect** that follows.
    ///
    /// Returns `S_OK` on success, `E_INVALIDARG` if `prc` is null when `parent` is valid.
    fn SetWindow(&self, parent: HWND, prc: *const RECT) -> Result<()> {
        log("BlpPreviewHandler::SetWindow (enter)");
        log(&format!("  in: parent=0x{:X}, prc={:p}", parent.0 as usize, prc));

        // Teardown path: host signals no parent → destroy child & clear state
        if parent.is_invalid() {
            log("  parent HWND is invalid → teardown");
            // Clear cached parent/rect
            self.hwnd_parent.set(HWND::default());
            self.rc_parent
                .set(RECT { left: 0, top: 0, right: 0, bottom: 0 });

            // Destroy existing child window if any
            let child = self.hwnd_preview.get();
            if child.is_invalid() {
                log("  preview HWND already cleared");
            } else {
                unsafe {
                    match DestroyWindow(child) {
                        Ok(_) => log(&format!("  DestroyWindow(HWND=0x{:X}) => OK", child.0 as usize)),
                        Err(e) => log(&format!("  DestroyWindow(HWND=0x{:X}) => ERR hr=0x{:08X}", child.0 as usize, e.code().0 as u32)),
                    }
                }
                preview_store_remove(child);
                self.hwnd_preview.set(HWND::default());
            }

            log("  BlpPreviewHandler::SetWindow (exit, teardown, return S_OK)");
            return Ok(());
        }

        // For a valid parent, prc must be non-null
        if prc.is_null() {
            log("  prc is NULL while parent is valid → E_INVALIDARG");
            return Err(E_INVALIDARG.into());
        }

        // Cache parent + rect (no creation, no painting here)
        let rc = unsafe { *prc };
        log(&format!("  cache: parent=0x{:X}, rc=({}, {}, {}, {}) (w={} h={})", parent.0 as usize, rc.left, rc.top, rc.right, rc.bottom, rc.right - rc.left, rc.bottom - rc.top));
        self.hwnd_parent.set(parent);
        self.rc_parent.set(rc);

        // If the child already exists, just reparent it; geometry is handled by SetRect
        let child = self.hwnd_preview.get();
        log(&format!("  cached preview HWND = 0x{:X} (invalid={})", child.0 as usize, child.is_invalid()));
        if !child.is_invalid() {
            unsafe {
                match SetParent(child, Some(parent)) {
                    Ok(new_parent) => {
                        log(&format!("  SetParent => OK, new parent=0x{:X}", new_parent.0 as usize));
                    }
                    Err(e) => {
                        log(&format!("  SetParent => ERR hr=0x{:08X}", e.code().0 as u32));
                    }
                }

                // Keep geometry unchanged here; SetRect will supply the authoritative position/size.
                // SWP_NOMOVE ensures we don't override left/top before SetRect arrives.
                match SetWindowPos(
                    child,
                    Some(HWND::default()),
                    0,
                    0,                  // ignored due to NOMOVE
                    rc.right - rc.left, // width (ignored if you prefer defer size to SetRect as well)
                    rc.bottom - rc.top, // height
                    SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOMOVE,
                ) {
                    Ok(_) => log("  SetWindowPos (reparent keep-pos) => OK"),
                    Err(e) => log(&format!("  SetWindowPos (reparent keep-pos) => ERR hr=0x{:08X}", e.code().0 as u32)),
                }
            }
        } else {
            log("  preview HWND not created yet (will be created in DoPreview)");
        }

        log("  BlpPreviewHandler::SetWindow (exit, return S_OK)");
        Ok(())
    }

    /// Applies the host-provided display rectangle (IPreviewHandler::SetRect).
    ///
    /// ## Contract (per Microsoft Docs)
    /// - The host calls `SetRect` to supply/adjust the **authoritative** position & size
    ///   for your preview child window.
    /// - You **must** resize/reposition your child window to this rect (no heuristics),
    ///   and paint **only inside** this area.
    /// - `SetRect` may arrive **before or after** `DoPreview`. If your child window does
    ///   not exist yet, just **cache** the rect and apply it when the window is created.
    /// - Return `E_INVALIDARG` if `prc == NULL`.
    ///
    /// ## Behavior here
    /// 1) Validate `prc`, cache the rect in `self.rc_parent`.
    /// 2) If a child window exists, call `SetWindowPos(child, …, left, top, w, h, SWP_NOZORDER|SWP_NOACTIVATE)`.
    ///    **Do not** use `SWP_NOMOVE`.
    /// 3) Request a repaint with `InvalidateRect(child, None, false)` (no `UpdateWindow`).
    ///
    /// All Win32 calls that return `Result<()>` are logged with OK/ERR branches.
    #[allow(non_snake_case)]
    fn SetRect(&self, prc: *const RECT) -> Result<()> {
        log("BlpPreviewHandler::SetRect (enter)");

        // --- 1) Validate pointer ---
        if prc.is_null() {
            log("  prc is NULL → E_INVALIDARG");
            return Err(windows::core::Error::new(HRESULT(1i32), "SetRect: prc is NULL")); // E_INVALIDARG
        }

        // --- 2) Cache the rect ---
        let rc = unsafe { *prc };
        let mut w = rc.right - rc.left;
        let mut h = rc.bottom - rc.top;
        if w < 0 {
            w = 0;
        }
        if h < 0 {
            h = 0;
        }

        self.rc_parent.set(rc);
        log(&format!("  cached rc=({}, {}, {}, {}) size={}×{}", rc.left, rc.top, rc.right, rc.bottom, w, h));

        // --- 3) Apply to the existing child (if any) ---
        let child: HWND = self.hwnd_preview.get();
        if child.is_invalid() {
            log("  child HWND not created yet → will apply when DoPreview creates it");
            log("BlpPreviewHandler::SetRect (exit, return S_OK)");
            return Ok(());
        }

        // SetWindowPos with move + size (authoritative), no z-order/no activate
        let flags: SET_WINDOW_POS_FLAGS = SWP_NOZORDER | SWP_NOACTIVATE;
        log(&format!(
            "  SetWindowPos(hwnd=0x{:X}, x={}, y={}, cx={}, cy={}, flags={:?})",
            child.0 as usize, //
            rc.left,
            rc.top,
            w,
            h,
            flags
        ));

        unsafe {
            match SetWindowPos(child, Some(HWND::default()), rc.left, rc.top, w, h, flags) {
                Ok(()) => log("  SetWindowPos => OK"),
                Err(e) => log(&format!("  SetWindowPos => ERR hr=0x{:08X}", e.code().0 as u32)),
            }
        }

        // --- 4) Request repaint (no UpdateWindow) ---
        unsafe {
            log(format!(
                "  InvalidateRect(hwnd=0x{:X}) => {}",
                child.0 as usize, //
                InvalidateRect(Some(child), None, false).as_bool()
            ));
        }

        log("BlpPreviewHandler::SetRect (exit, return S_OK)");
        Ok(())
    }

    /// Starts the preview UI (IPreviewHandler::DoPreview).
    ///
    /// ## Contract (per Microsoft Docs)
    /// - `SetWindow` precedes this and supplies the parent `HWND` and an initial RECT.
    /// - If the preview child window does not exist yet, create it **after this call**.
    /// - **Paint only** inside the area provided by `SetWindow`/`SetRect`.
    /// - Hosts often call `SetRect` *after* `DoPreview`; if the cached rect is empty,
    ///   create the child at **(0,0)** with size **0×0** and let `SetRect` resize it.
    /// - Do **not** block the host’s message loop; **do not** call `UpdateWindow`.
    /// - Keep UI minimal; no modal dialogs/toolbars. Unhandled messages → `DefWindowProcW`.
    ///
    /// ## Logging
    /// - Every Win32 call that returns `Result<()>` is logged for OK/ERR with the HRESULT.
    /// - Synchronous errors that use `GetLastError` are converted via `HRESULT::from_win32`.
    #[allow(non_snake_case)]
    fn DoPreview(&self) -> Result<()> {
        log("BlpPreviewHandler::DoPreview (enter)");

        // 0) Destroy previous child, if present
        let prev = self.hwnd_preview.get();
        if !prev.is_invalid() {
            log(&format!("  existing child HWND=0x{:X} → DestroyWindow", prev.0 as usize));
            unsafe {
                match DestroyWindow(prev) {
                    Ok(()) => log("  DestroyWindow => OK"),
                    Err(e) => log(&format!("  DestroyWindow => ERR hr=0x{:08X}", e.code().0 as u32)),
                }
            }
            preview_store_remove(prev);
            self.hwnd_preview.set(HWND::default());
        }

        // 1) Validate parent from SetWindow
        let parent = self.hwnd_parent.get();
        if parent.is_invalid() {
            log("  parent HWND invalid → E_INVALIDARG");
            return Err(windows::core::Error::new(HRESULT(1i32), "parent HWND invalid"));
        }

        // 2) Ensure the preview window class is registered (inline, one-time). No cursor tweaks.
        if CLASS_ATOM.get().is_none() {
            log("  [class] ensuring preview window class");
            unsafe {
                let hinst = HINSTANCE(GetModuleHandleW(None).ok().map(|h| h.0).unwrap_or_default());
                log(&format!("  [class] hInstance=0x{:X}", hinst.0 as usize));

                // Already registered in this process?
                let mut info = WNDCLASSEXW::default();
                info.cbSize = size_of::<WNDCLASSEXW>() as u32;
                if GetClassInfoExW(Some(hinst), CLASS_NAME, &mut info as *mut _).is_ok() {
                    log("  [class] already registered (GetClassInfoExW => OK)");
                    let _ = CLASS_ATOM.set(1); // any non-zero marker
                } else {
                    // Register fresh class: no non-client, no cursor meddling
                    let wc = WNDCLASSW {
                        style: CS_HREDRAW | CS_VREDRAW,
                        lpfnWndProc: Some(wndproc),
                        hInstance: hinst,
                        hIcon: HICON::default(),
                        hCursor: HCURSOR::default(), // do NOT touch cursor
                        hbrBackground: HBRUSH(GetStockObject(WHITE_BRUSH).0),
                        lpszClassName: CLASS_NAME,
                        ..Default::default()
                    };

                    let atom = RegisterClassW(&wc);
                    if atom == 0 {
                        let gle = GetLastError().0;
                        let hr = HRESULT::from_win32(gle);
                        log(&format!("  [class] RegisterClassW => FAIL GLE=0x{:08X} hr=0x{:08X}", gle, hr.0 as u32));
                        return Err(windows::core::Error::new(hr, "RegisterClassW failed"));
                    }
                    log(&format!("  [class] RegisterClassW => OK atom=0x{:X}", atom as u32));
                    let _ = CLASS_ATOM.set(atom);
                }
            }
        } else {
            log("  [class] preview class already initialized");
        }

        // 3) Pick initial geometry: 0×0 until SetRect arrives
        let rc: RECT = self.rc_parent.get();
        let (x, y, w, h) = if rc.right <= rc.left || rc.bottom <= rc.top {
            log("  cached rect empty → create child at (0,0) size 0×0; SetRect will resize");
            (0, 0, 0, 0)
        } else {
            let ww = rc.right - rc.left;
            let hh = rc.bottom - rc.top;
            log(&format!("  using cached rect: pos=({}, {}), size={}×{}", rc.left, rc.top, ww, hh));
            (rc.left, rc.top, ww, hh)
        };

        // 4) Create the child window (client-only; no borders)
        let hwnd = unsafe {
            log(&format!("  CreateWindowExW(parent=0x{:X}, pos=({}, {}), size={}×{})", parent.0 as usize, x, y, w, h));
            match CreateWindowExW(WINDOW_EX_STYLE(0), CLASS_NAME, PCWSTR::null(), WINDOW_STYLE((WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN).0), x, y, w, h, Some(parent), None, None, None) {
                Ok(h) => h,
                Err(e) => {
                    log(&format!("  CreateWindowExW => ERR hr=0x{:08X}", e.code().0 as u32));
                    return Err(e);
                }
            }
        };
        log(&format!("  created child HWND=0x{:X}", hwnd.0 as usize));
        self.hwnd_preview.set(hwnd);

        // 5) Load/decode preview resources (fast sync is fine; heavy → offload and PostMessage)
        match self.load_bitmap_for_hwnd(hwnd) {
            Ok(()) => log("  load_bitmap_for_hwnd => OK"),
            Err(e) => log(&format!("  load_bitmap_for_hwnd => ERR hr=0x{:08X}", e.code().0 as u32)),
        }

        // 6) Request repaint (no UpdateWindow). InvalidateRect returns Result<()>, log both branches.
        unsafe {
            log(format!(
                " InvalidateRect(hwnd=0x{:X}) => {}",
                hwnd.0 as usize, //
                InvalidateRect(Some(hwnd), None, false).as_bool()
            ));
        }

        // 7) Optional: set focus; SetFocus returns previous HWND
        unsafe {
            let prev = SetFocus(Some(hwnd))?;
            log(&format!("  SetFocus(HWND=0x{:X}) previous=0x{:X}", hwnd.0 as usize, prev.0 as usize));
        }

        log("BlpPreviewHandler::DoPreview (exit, return S_OK)");
        Ok(())
    }

    fn Unload(&self) -> Result<()> {
        log("BlpPreviewHandler::Unload");
        if self.stream.borrow().is_some() {
            log("  clearing cached stream");
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

    /// Minimal forwarding; not required for just drawing a bitmap.
    /// We simply best-effort forward to the host frame if present.
    #[allow(non_snake_case)]
    fn TranslateAccelerator(&self, pmsg: *const MSG) -> Result<()> {
        log("BlpPreviewHandler::TranslateAccelerator (enter)");
        log(&format!("  MSG ptr={:?}", pmsg));

        if let Some(frame) = self.frame.borrow().as_ref() {
            unsafe {
                match frame.TranslateAccelerator(pmsg) {
                    Ok(_) => log("  frame.TranslateAccelerator forwarded"),
                    Err(e) => log(&format!("  frame.TranslateAccelerator => ERR hr=0x{:08X}", e.code().0 as u32)),
                }
            }
        } else {
            log("  no IPreviewHandlerFrame cached → nothing to forward (OK for image preview)");
        }

        log("BlpPreviewHandler::TranslateAccelerator (exit, return S_OK)");
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

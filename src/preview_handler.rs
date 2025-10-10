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
use std::sync::OnceLock;
use std::{
    cell::{Cell, RefCell},
    ffi::c_void,
};
use windows::Win32::Foundation::{COLORREF, E_FAIL, HINSTANCE, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{BeginPaint, DRAW_TEXT_FORMAT, DT_CENTER, DT_SINGLELINE, DT_VCENTER, DrawTextW, EndPaint, FillRect, GetStockObject, HBRUSH, HDC, InvalidateRect, PAINTSTRUCT, SetBkMode, SetTextColor, TRANSPARENT, UpdateWindow, WHITE_BRUSH};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{CS_HREDRAW, CS_VREDRAW, DefWindowProcW, GetClientRect, HCURSOR, HICON, IDC_ARROW, LoadCursorW, RegisterClassW, WM_ERASEBKGND, WM_PAINT, WM_SIZE, WNDCLASSW, WS_CLIPCHILDREN, WS_CLIPSIBLINGS};
use windows::{
    Win32::{
        Foundation::{
            E_INVALIDARG,
            E_NOINTERFACE,
            E_NOTIMPL,
            E_POINTER,
            GetLastError, //
            HWND,
            RECT,
        },
        System::{
            Com::IStream,
            Ole::{IObjectWithSite, IObjectWithSite_Impl, IOleWindow, IOleWindow_Impl},
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
            },
            WindowsAndMessaging::{
                CreateWindowExW, //
                DestroyWindow,
                MSG,
                SWP_NOACTIVATE,
                SWP_NOMOVE,
                SWP_NOZORDER,
                SetParent,
                SetWindowPos,
                WINDOW_EX_STYLE,
                WINDOW_STYLE,
                WS_CHILD,
                WS_VISIBLE,
            },
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

const STATIC_CLASSW: PCWSTR = w!("Static");
static WNDCLASS_ATOM: OnceLock<u16> = OnceLock::new();
const CLASS_NAME: PCWSTR = w!("BlpPreviewWnd");

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            let mut ps = PAINTSTRUCT::default();
            let hdc: HDC = BeginPaint(hwnd, &mut ps);

            let mut rc = RECT::default();
            GetClientRect(hwnd, &mut rc);

            // фон
            FillRect(hdc, &rc, HBRUSH(GetStockObject(WHITE_BRUSH).0));

            // текст
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, COLORREF(0)); // RGB(0,0,0)

            let mut wtxt: Vec<u16> = "BLP demo preview (custom Win32)".encode_utf16().collect();
            // DrawTextW в windows 0.62 берёт &mut [u16], БЕЗ отдельного length и БЕЗ PCWSTR
            let fmt = DRAW_TEXT_FORMAT(DT_CENTER.0 | DT_VCENTER.0 | DT_SINGLELINE.0);
            DrawTextW(hdc, &mut wtxt, &mut rc, fmt);

            EndPaint(hwnd, &ps);
            return LRESULT(0);
        }
        WM_ERASEBKGND => {
            // скажем системе, что фон мы уже закрасили — меньше мерцаний
            return LRESULT(1);
        }
        WM_SIZE => {
            // сигнатура: InvalidateRect(Some(hwnd), None, bool)
            InvalidateRect(Some(hwnd), None, true);
            return LRESULT(0);
        }
        _ => {}
    }
    DefWindowProcW(hwnd, msg, w, l)
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
        }
    }
}

#[allow(non_snake_case)]
impl IObjectWithSite_Impl for BlpPreviewHandler_Impl {
    fn SetSite(&self, p_unknown_site: Ref<'_, IUnknown>) -> Result<()> {
        log("BlpPreviewHandler::SetSite");
        *self.site.borrow_mut() = p_unknown_site.clone();
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
        log("BlpPreviewHandler::SetWindow (enter)");

        // --- проверка входных параметров ---
        log(&format!("  hwnd=0x{:X}, prc={:?}", hwnd.0 as usize, prc));
        if hwnd.is_invalid() {
            log("  hwnd invalid -> return S_OK");
            return Ok(());
        }
        if prc.is_null() {
            log("  prc null -> return S_OK");
            return Ok(());
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
        log(&format!("  cached rc=({}, {}, {}, {}), size={}x{}", rc.left, rc.top, rc.right, rc.bottom, rc.right - rc.left, rc.bottom - rc.top));

        // --- если превью уже создано, обновляем его размер ---
        let preview = self.hwnd_preview.get();
        if !preview.is_invalid() {
            let width = rc.right - rc.left;
            let height = rc.bottom - rc.top;
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
        } else {
            log("  preview HWND invalid (no window yet)");
        }

        log("  BlpPreviewHandler::SetRect (exit, return S_OK)");
        Ok(())
    }

    fn DoPreview(&self) -> Result<()> {
        log("BlpPreviewHandler::DoPreview (custom hwnd)");

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

        let hwnd = unsafe {
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

        unsafe {
            UpdateWindow(hwnd);
        }

        log("  DoPreview => S_OK");
        Ok(())
    }

    fn Unload(&self) -> Result<()> {
        log("BlpPreviewHandler::Unload");
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
        log("BlpPreviewHandler::SetFocus");
        let hwnd = self.hwnd_preview.get();
        if !hwnd.is_invalid() {
            unsafe {
                let _ = SetFocus(Some(hwnd));
            }
        }
        Ok(())
    }

    fn QueryFocus(&self) -> Result<HWND> {
        log("BlpPreviewHandler::QueryFocus");
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
        log("BlpPreviewHandler::TranslateAccelerator");
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
        log("BlpPreviewHandler::GetWindow");
        Ok(self.hwnd_parent.get())
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
        Ok(())
    }
}

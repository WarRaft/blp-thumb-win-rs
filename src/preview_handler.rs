// lib.rs (или отдельный модуль в вашем DLL-проекте)
// Cargo.toml должен подтянуть:
// windows = { version = "0.58", features = [
//   "implement",
//   "Win32_Foundation",
//   "Win32_System_Com",
//   "Win32_UI_Shell",
//   "Win32_UI_WindowsAndMessaging",
// ] }

use windows::{
    Win32::{
        Foundation::{GetLastError, HWND, RECT, SYSTEMTIME},
        System::{
            Com::IStream,
            Ole::{IObjectWithSite, IOleWindow},
            SystemInformation::GetLocalTime,
        },
        UI::{
            Input::KeyboardAndMouse::{GetFocus, SetFocus},
            Shell::{IPreviewHandler, IPreviewHandlerFrame, PropertiesSystem::IInitializeWithStream},
            WindowsAndMessaging::{
                CreateWindowExW, //
                DestroyWindow,
                HMENU,
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
        BOOL, //
        HRESULT,
        IUnknown,
        Interface,
        PCWSTR,
        Result,
        implement,
        w,
    },
};

const STATIC_CLASSW: PCWSTR = w!("Static");

#[inline]
fn rect_width(rc: &RECT) -> i32 {
    rc.right - rc.left
}
#[inline]
fn rect_height(rc: &RECT) -> i32 {
    rc.bottom - rc.top
}

/// BLP Preview Handler (тестовый): рисует таймстамп.
#[implement(IObjectWithSite, IPreviewHandler, IOleWindow, IInitializeWithStream)]
pub struct BlpPreviewHandler {
    // счётчик ссылок берёт на себя #[implement]
    hwnd_parent: HWND,
    hwnd_preview: HWND,
    rc_parent: RECT,
    site: Option<IUnknown>,
    stream: Option<IStream>,
}

#[allow(non_snake_case)]
impl BlpPreviewHandler {
    pub fn new() -> Self {
        Self { hwnd_parent: HWND::default(), hwnd_preview: HWND::default(), rc_parent: RECT { left: 0, top: 0, right: 0, bottom: 0 }, site: None, stream: None }
    }

    /// Создаёт дочернее окно и выводит строку с таймстампом.
    fn create_preview_window(&mut self) -> Result<()> {
        unsafe {
            // создаём простейший STATIC control
            let style: WINDOW_STYLE = (WS_CHILD | WS_VISIBLE).into();
            let ex: WINDOW_EX_STYLE = WINDOW_EX_STYLE(0);

            let hwnd = CreateWindowExW(
                ex,
                STATIC_CLASSW,
                PCWSTR::null(), // текст зададим позже
                style,
                self.rc_parent.left,
                self.rc_parent.top,
                rect_width(&self.rc_parent),
                rect_height(&self.rc_parent),
                Some(self.hwnd_parent),
                Some(HMENU::default()),
                None,
                None,
            )?;

            if hwnd.is_invalid() {
                return Err(HRESULT::from_win32(GetLastError().0).into());
            }

            self.hwnd_preview = hwnd;

            // формируем строку времени
            let ts = format_local_timestamp();
            let widestr: Vec<u16> = ts.encode_utf16().chain(std::iter::once(0)).collect();
            SetWindowTextW(self.hwnd_preview, PCWSTR(widestr.as_ptr()))?;

            let _ = ShowWindow(self.hwnd_preview, SW_SHOW);
        }
        Ok(())
    }

    /// Обновить позицию/размер дочернего окна при ресайзе панели.
    fn update_preview_bounds(&self) {
        if !self.hwnd_preview.is_invalid() {
            unsafe {
                let _ = SetWindowPos(
                    self.hwnd_preview, //
                    Some(HWND::default()),
                    self.rc_parent.left,
                    self.rc_parent.top,
                    rect_width(&self.rc_parent),
                    rect_height(&self.rc_parent),
                    SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
                );
            }
        }
    }

    // ===== IObjectWithSite =====
    fn SetSite(&mut self, punk_site: Option<&IUnknown>) -> Result<()> {
        self.site = punk_site.cloned();
        Ok(())
    }

    fn GetSite(&self, riid: *const windows::core::GUID, ppv: *mut *mut core::ffi::c_void) -> HRESULT {
        unsafe { if let Some(site) = &self.site { site.query(riid, ppv) } else { windows::Win32::Foundation::E_FAIL } }
    }

    // ===== IOleWindow =====
    fn GetWindow(&self) -> Result<HWND> {
        Ok(self.hwnd_parent)
    }

    fn ContextSensitiveHelp(&self, _f_enter_mode: BOOL) -> Result<()> {
        // не требуется
        Err(windows::Win32::Foundation::E_NOTIMPL.into())
    }

    // ===== IInitializeWithStream =====
    fn Initialize(&mut self, p_stream: &IStream, _grf_mode: u32) -> Result<()> {
        // Может вызываться повторно — перезаписываем
        self.stream = Some(p_stream.clone());
        Ok(())
    }

    // ===== IPreviewHandler =====
    fn SetWindow(&mut self, hwnd: HWND, prc: *const RECT) -> Result<()> {
        unsafe {
            if !hwnd.is_invalid() && !prc.is_null() {
                self.hwnd_parent = hwnd;
                self.rc_parent = *prc;

                if !self.hwnd_preview.is_invalid() {
                    // если уже создан — обновим parent и размер
                    SetParent(self.hwnd_preview, Some(self.hwnd_parent))?;
                    self.update_preview_bounds();
                }
            }
        }
        Ok(())
    }

    fn SetRect(&mut self, prc: *const RECT) -> Result<()> {
        unsafe {
            if prc.is_null() {
                return Err(windows::Win32::Foundation::E_INVALIDARG.into());
            }
            self.rc_parent = *prc;
        }
        self.update_preview_bounds();
        Ok(())
    }

    fn SetFocus(&self) -> Result<()> {
        unsafe {
            if !self.hwnd_preview.is_invalid() {
                SetFocus(Some(self.hwnd_preview)).expect("TODO: panic message");
                Ok(())
            } else {
                // как в примере: S_FALSE, но в windows-rs Result проще вернуть Ok(()).
                Ok(())
            }
        }
    }

    fn QueryFocus(&self) -> Result<HWND> {
        unsafe {
            let h = GetFocus();
            if !h.is_invalid() { Ok(h) } else { Err(HRESULT::from_win32(GetLastError().0).into()) }
        }
    }

    fn TranslateAccelerator(&self, pmsg: *const windows::Win32::UI::WindowsAndMessaging::MSG) -> Result<()> {
        // Пробрасываем хосту (как в C++-образце)
        if let Some(site) = &self.site {
            unsafe {
                if let Ok(frame) = site.cast::<IPreviewHandlerFrame>() {
                    // Возвращаем S_FALSE, если не обработано — но windows-rs Result не несёт S_FALSE.
                    // Поэтому аккуратно вызываем и возвращаем Ok(()) независимо от результата: хост разберётся.
                    let _ = frame.TranslateAccelerator(pmsg);
                }
            }
        }
        Ok(())
    }

    fn DoPreview(&mut self) -> Result<()> {
        // В реальности вы бы парсили BLP из self.stream и рисовали.
        // Для тестов: создаём окно и печатаем текущий таймстамп.
        if !self.hwnd_preview.is_invalid() && self.stream.is_some() {
            self.create_preview_window()?;
        }
        Ok(())
    }

    fn Unload(&mut self) -> Result<()> {
        self.stream = None;
        if !self.hwnd_preview.is_invalid() {
            unsafe {
                DestroyWindow(self.hwnd_preview)?;
            }
            self.hwnd_preview = HWND::default();
        }
        Ok(())
    }
}

// ---------- Вспомогательное форматирование времени ----------
fn format_local_timestamp() -> String {
    unsafe {
        let mut st = SYSTEMTIME::default();
        GetLocalTime();
        // Пример: 2025-10-09 23:15:42.123
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}", //
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds
        )
    }
}

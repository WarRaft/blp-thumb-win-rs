use blp_thumb_win::log::log;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::Path;
use winreg::enums::RegType;
use winreg::types::FromRegValue;
use winreg::{RegKey, RegValue};

pub struct Rk<'a> {
    path: String,
    pub key: RegKey,
    _root: &'a RegKey,
}

// Полностью owned представление
pub enum RegVal {
    Sz(OsString), // REG_SZ
    Dword(u32),   // REG_DWORD
    Qword(u64),   // REG_QWORD
    Bin(Vec<u8>), // REG_BINARY
}

// Локальный трейт без lifetimes
pub trait IntoRegVal {
    fn into_reg_val(self) -> RegVal;
}

// --- реализации ---
impl<'a> IntoRegVal for &'a str {
    #[inline]
    fn into_reg_val(self) -> RegVal {
        RegVal::Sz(self.into())
    }
}
impl<'a> IntoRegVal for &'a OsStr {
    #[inline]
    fn into_reg_val(self) -> RegVal {
        RegVal::Sz(self.to_os_string())
    }
}
impl<'a> IntoRegVal for &'a Path {
    #[inline]
    fn into_reg_val(self) -> RegVal {
        RegVal::Sz(self.as_os_str().to_os_string())
    }
}
impl IntoRegVal for String {
    #[inline]
    fn into_reg_val(self) -> RegVal {
        RegVal::Sz(self.into())
    }
}
impl IntoRegVal for OsString {
    #[inline]
    fn into_reg_val(self) -> RegVal {
        RegVal::Sz(self)
    }
}
impl IntoRegVal for u32 {
    #[inline]
    fn into_reg_val(self) -> RegVal {
        RegVal::Dword(self)
    }
}
impl IntoRegVal for u64 {
    #[inline]
    fn into_reg_val(self) -> RegVal {
        RegVal::Qword(self)
    }
}
impl IntoRegVal for bool {
    #[inline]
    fn into_reg_val(self) -> RegVal {
        RegVal::Dword(if self { 1 } else { 0 })
    }
}
impl<'a> IntoRegVal for &'a [u8] {
    #[inline]
    fn into_reg_val(self) -> RegVal {
        RegVal::Bin(self.to_vec())
    }
}
impl IntoRegVal for Vec<u8> {
    #[inline]
    fn into_reg_val(self) -> RegVal {
        RegVal::Bin(self)
    }
}

impl<'a> Rk<'a> {
    #[inline]
    pub fn open(root: &'a RegKey, path: impl Into<String>) -> io::Result<Self> {
        let path = path.into();
        log(format!("Creating/opening registry key: {}", &path));
        let (key, _) = root.create_subkey(&path)?;
        Ok(Self { path, key, _root: root })
    }

    #[inline]
    pub fn sub(&self, suffix: &str) -> io::Result<Rk<'a>> {
        let full = if suffix.is_empty() { self.path.clone() } else { format!(r"{}\{}", self.path, suffix) };
        log(format!("Creating/opening registry key: {}", &full));
        let (k, _) = self.key.create_subkey(suffix)?;
        Ok(Rk { path: full, key: k, _root: self._root })
    }

    // НИКАКИХ HRTB: V: IntoRegVal
    #[inline]
    pub fn set<V: IntoRegVal>(&self, name: &str, value: V) -> io::Result<()> {
        let name_disp = if name.is_empty() { "(Default)" } else { name };
        match value.into_reg_val() {
            RegVal::Sz(os) => {
                log(format!("Setting value: {} \\ {} = REG_SZ", self.path, name_disp));
                self.key.set_value(name, &os)
            }
            RegVal::Dword(d) => {
                log(format!("Setting value: {} \\ {} = REG_DWORD", self.path, name_disp));
                self.key.set_value(name, &d)
            }
            RegVal::Qword(q) => {
                log(format!("Setting value: {} \\ {} = REG_QWORD", self.path, name_disp));
                self.key.set_value(name, &q)
            }
            RegVal::Bin(bytes) => {
                log(format!("Setting value: {} \\ {} = REG_BINARY ({} bytes)", self.path, name_disp, bytes.len()));
                let rv = RegValue { vtype: RegType::REG_BINARY, bytes };
                self.key.set_raw_value(name, &rv)
            }
        }
    }

    #[inline]
    pub fn set_default<V: IntoRegVal>(&self, value: V) -> io::Result<()> {
        self.set("", value)
    }

    #[inline]
    pub fn get<T: FromRegValue>(&self, name: &str) -> io::Result<T> {
        self.key.get_value(name)
    }

    #[allow(dead_code)]
    pub fn delete_value(&self, name: &str) -> io::Result<()> {
        match self.key.delete_value(name) {
            Ok(()) => {
                log(format!("Deleted value: {} \\ {}", self.path, name));
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log(format!("Value missing (skip): {} \\ {}", self.path, name));
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

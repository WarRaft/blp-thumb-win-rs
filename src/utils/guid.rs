use windows_core::GUID;

/// Public extension trait for nice GUID formatting + optional hints.
pub trait GuidExt {
    /// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` upper-case with braces.
    fn to_braced_upper(&self) -> String;
}

impl GuidExt for GUID {
    fn to_braced_upper(&self) -> String {
        format!("{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}", self.data1, self.data2, self.data3, self.data4[0], self.data4[1], self.data4[2], self.data4[3], self.data4[4], self.data4[5], self.data4[6], self.data4[7])
    }
}

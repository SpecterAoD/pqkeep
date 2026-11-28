//! DE: Metadaten-Fallback bei Sharing-/Zugriffsfehlern ohne gewöhnlichen Find-Record.
//! EN: Sharing/access-error metadata fallback without an ordinary find record.
use super::{SourceMetadata, io};
use std::ptr;
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FindClose, FindExInfoBasic,
        FindExSearchNameMatch, FindFirstFileExW,
    },
};

impl SourceMetadata {
    /// DE: Nur explizite Testfixture; echten Find-Aufruf auf Caller-Ziel prüfen.
    /// EN: Explicit fixture only; test the actual find call on caller-owned storage.
    /// # Errors
    /// DE/EN: Ungültiger Pfad oder nativer Find-Fehler / invalid path or native find failure.
    #[cfg(feature = "native-metadata-fixture")]
    pub fn capture_find_fixture(&mut self, path: &[u16]) -> io::Result<()> {
        use zeroize::Zeroize;
        self.zeroize();
        crate::path_windows::validate(path)?;
        self.capture_find(path, io::ErrorKind::PermissionDenied.into())
    }

    pub(super) fn capture_find(&mut self, path: &[u16], original: io::Error) -> io::Result<()> {
        // DE: Keine Wildcard-Abfrage durch den Fallback; Verbatim-Präfix ist kein Dateiname.
        // EN: Never turn the fallback into a wildcard query; verbatim prefix is not a name.
        let tail = if path.starts_with(&[92, 92, 63, 92]) {
            &path[4..]
        } else {
            path
        };
        if tail.iter().any(|&unit| unit == 42 || unit == 63) {
            return Err(original);
        }
        // DE: capture hat NUL-Geometrie über open validiert; tatsächliches SDK-Ziel bleibt exklusiv.
        // SAFETY: Called only after validated open failed; path is terminated and
        // live. The actual WIN32_FIND_DATAW target is aligned, exclusive and complete.
        let handle = unsafe {
            FindFirstFileExW(
                path.as_ptr(),
                FindExInfoBasic,
                std::ptr::from_mut(&mut self.find).cast(),
                FindExSearchNameMatch,
                ptr::null(),
                0,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(original);
        }
        // DE: Sofort schließen, keine fallible Arbeit oder Unwindstelle dazwischen.
        // SAFETY: Successful FindFirstFileExW returned this fresh owned search
        // handle; close exactly once before decoding the retained protected record.
        if unsafe { FindClose(handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // DE/EN: Caller-Record nach FindClose ausschließlich leihen / borrow caller record after close.
        let native = &self.find;
        self.symlink = native.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            && native.dwReserved0 & 0x2000_0000 != 0;
        self.directory = !self.symlink && native.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        self.file = !self.symlink && !self.directory;
        self.bytes = (u64::from(native.nFileSizeHigh) << 32) | u64::from(native.nFileSizeLow);
        Ok(())
    }
}

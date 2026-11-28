//! DE: fstatat ohne Linkverfolgung in ein exklusives stabiles Ziel.
//! EN: fstatat without symlink following into exclusive stable storage.
use super::{SourceMetadata, Zeroize, io};
use std::ffi::CStr;

impl SourceMetadata {
    /// DE: Metadaten ohne Linkverfolgung direkt erfassen; Caller schützt seinen Record.
    /// EN: Capture metadata without following links; caller protects the record.
    /// # Errors
    /// DE/EN: Native Verweigerung oder negative Länge / native refusal or negative size.
    pub fn capture(&mut self, path: &CStr) -> io::Result<()> {
        self.zeroize();
        // DE: SDK-Typ statt Layoutnachbau; lebender NUL-Pfad und exklusives Ziel.
        // SAFETY: CStr is terminated and live through this synchronous call. The
        // actual libc::stat destination is aligned, exclusive and writable in full.
        let result = unsafe {
            libc::fstatat(
                libc::AT_FDCWD,
                path.as_ptr(),
                self.native.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // DE: Nur nach erfolgreicher vollständiger Initialisierung ausleihen.
        // SAFETY: Successful fstatat initialized this actual stat object; no
        // whole private record is copied, and this borrow cannot outlive self.
        let native = unsafe { self.native.assume_init_ref() };
        self.bytes = u64::try_from(native.st_size).map_err(|_| io::ErrorKind::InvalidData)?;
        self.file = native.st_mode & libc::S_IFMT == libc::S_IFREG;
        self.directory = native.st_mode & libc::S_IFMT == libc::S_IFDIR;
        self.symlink = native.st_mode & libc::S_IFMT == libc::S_IFLNK;
        Ok(())
    }
}

//! DE: Native Metadaten direkt im vorab geschützten Caller-Record erfassen.
//! EN: Capture native metadata directly in the caller's preprotected record.
use std::io;
#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(target_os = "linux")]
type Native = libc::stat;
#[cfg(windows)]
type Native = windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_TAG_INFO, WIN32_FIND_DATAW};

/// DE: Öffentlich leer erzeugen; vor capture stabil sperren. Keine Clone/Debug-Kopie.
/// EN: Construct public-empty; stably lock before capture. No Clone/Debug copy.
pub struct SourceMetadata {
    #[cfg(target_os = "linux")]
    native: MaybeUninit<Native>,
    #[cfg(windows)]
    native: Native,
    #[cfg(windows)]
    tag: FILE_ATTRIBUTE_TAG_INFO,
    #[cfg(windows)]
    find: WIN32_FIND_DATAW,
    file: bool,
    directory: bool,
    symlink: bool,
    bytes: u64,
}

impl SourceMetadata {
    /// DE/EN: Nur öffentliche Anfangswerte / public initial values only.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            native: MaybeUninit::zeroed(),
            #[cfg(windows)]
            native: Native::default(),
            #[cfg(windows)]
            tag: FILE_ATTRIBUTE_TAG_INFO::default(),
            #[cfg(windows)]
            find: WIN32_FIND_DATAW::default(),
            file: false,
            directory: false,
            symlink: false,
            bytes: 0,
        }
    }

    /// DE/EN: Reguläre Datei / regular file.
    #[must_use]
    pub const fn is_file(&self) -> bool {
        self.file
    }
    /// DE/EN: Verzeichnis / directory.
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        self.directory
    }
    /// DE/EN: Symbolischer Verweis, ohne Verfolgung / symlink without following.
    #[must_use]
    pub const fn is_symlink(&self) -> bool {
        self.symlink
    }
    /// DE/EN: Dateigröße / file length.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Zeroize for SourceMetadata {
    fn zeroize(&mut self) {
        #[cfg(target_os = "linux")]
        self.native.zeroize();
        #[cfg(windows)]
        self.wipe_windows();
        self.file.zeroize();
        self.directory.zeroize();
        self.symlink.zeroize();
        self.bytes.zeroize();
    }
}
impl Drop for SourceMetadata {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for SourceMetadata {}

#[cfg(target_os = "linux")]
#[path = "source_metadata_linux.rs"]
mod linux;
#[cfg(windows)]
#[path = "source_metadata_windows.rs"]
mod windows;
#[cfg(windows)]
#[path = "source_metadata_windows_find.rs"]
mod windows_find;

#[cfg(windows)]
#[path = "source_metadata_windows_clear.rs"]
mod windows_clear;

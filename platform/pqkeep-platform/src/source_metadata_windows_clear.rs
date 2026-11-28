//! DE: SDK-Felder ohne private Record-Kopie und ohne eigene Raw-Wipe-FFI löschen.
//! EN: Wipe SDK fields without private record copies or our own raw-wipe FFI.
use super::SourceMetadata;
use windows_sys::Win32::{
    Foundation::FILETIME,
    Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_TAG_INFO, WIN32_FIND_DATAW},
};
use zeroize::Zeroize;

// DE: Vollständige Feldgeometrie ohne Padding; SDK-Änderungen sichtbar verweigern.
// EN: Complete field geometry without padding; visibly reject SDK layout changes.
const _: () = assert!(size_of::<BY_HANDLE_FILE_INFORMATION>() == 52);
const _: () = assert!(size_of::<FILE_ATTRIBUTE_TAG_INFO>() == 8);
const _: () = assert!(size_of::<WIN32_FIND_DATAW>() == 592);

fn time(value: &mut FILETIME) {
    value.dwLowDateTime.zeroize();
    value.dwHighDateTime.zeroize();
}

impl SourceMetadata {
    pub(super) fn wipe_windows(&mut self) {
        self.native.dwFileAttributes.zeroize();
        time(&mut self.native.ftCreationTime);
        time(&mut self.native.ftLastAccessTime);
        time(&mut self.native.ftLastWriteTime);
        self.native.dwVolumeSerialNumber.zeroize();
        self.native.nFileSizeHigh.zeroize();
        self.native.nFileSizeLow.zeroize();
        self.native.nNumberOfLinks.zeroize();
        self.native.nFileIndexHigh.zeroize();
        self.native.nFileIndexLow.zeroize();
        self.tag.FileAttributes.zeroize();
        self.tag.ReparseTag.zeroize();
        self.find.dwFileAttributes.zeroize();
        time(&mut self.find.ftCreationTime);
        time(&mut self.find.ftLastAccessTime);
        time(&mut self.find.ftLastWriteTime);
        self.find.nFileSizeHigh.zeroize();
        self.find.nFileSizeLow.zeroize();
        self.find.dwReserved0.zeroize();
        self.find.dwReserved1.zeroize();
        self.find.cFileName.zeroize();
        self.find.cAlternateFileName.zeroize();
    }
}

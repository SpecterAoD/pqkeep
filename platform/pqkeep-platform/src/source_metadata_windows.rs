//! DE: Reparse-Punkte nicht verfolgen; SDK-Records im geschützten Caller befüllen.
//! EN: Do not follow reparse points; fill SDK records in the protected caller.
use super::{SourceMetadata, Zeroize, io};
use std::{
    fs::File,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileAttributeTagInfo,
        GetFileInformationByHandle, GetFileInformationByHandleEx, OPEN_EXISTING,
    },
};

fn open(path: &[u16]) -> io::Result<File> {
    if path.last() != Some(&0) || path[..path.len() - 1].contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // DE: Lebender NUL-Pfad; nur Attribute lesen, keine Vererbung/Security-Mutation.
    // SAFETY: Terminated live path; documented flags open the reparse point itself.
    // Null security/template pointers are permitted; this creates one owned handle.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // DE: Eigentum genau einmal übertragen, auch Fehlerpfade schließen den Handle.
    // SAFETY: Successful CreateFileW returned a fresh owned handle transferred once.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

impl SourceMetadata {
    /// DE: Native Records direkt erfassen; vor Aufruf stabil im Caller sperren.
    /// EN: Capture native records directly; stably protect them before calling.
    /// # Errors
    /// DE/EN: Ungültiger Pfad oder native Verweigerung / invalid path or native refusal.
    pub fn capture(&mut self, path: &[u16]) -> io::Result<()> {
        self.zeroize();
        let file = match open(path) {
            Ok(file) => file,
            Err(error)
                if [
                    i32::try_from(ERROR_ACCESS_DENIED).ok(),
                    i32::try_from(ERROR_SHARING_VIOLATION).ok(),
                ]
                .contains(&error.raw_os_error()) =>
            {
                return self.capture_find(path, error);
            }
            Err(error) => return Err(error),
        };
        // DE: Echtes SDK-Ziel ist ausgerichtet und exklusiv; API behält keinen Pointer.
        // SAFETY: File owns a valid handle through this synchronous call; native
        // is aligned and writable for the actual BY_HANDLE_FILE_INFORMATION type.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut self.native) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // DE/EN: Initialisiertes SDK-Ziel ausschließlich leihen / borrow the initialized SDK target.
        let native = &self.native;
        if native.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            self.symlink = capture_tag(&file, &mut self.tag)?;
        }
        self.file = !self.symlink && native.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0;
        self.directory = !self.symlink && native.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        self.bytes = (u64::from(native.nFileSizeHigh) << 32) | u64::from(native.nFileSizeLow);
        Ok(())
    }
}

fn capture_tag(file: &File, tag: &mut FILE_ATTRIBUTE_TAG_INFO) -> io::Result<bool> {
    // DE: Nur bei Reparse-Attribut abfragen; normale FAT-Dateien benötigen diese Klasse nicht.
    // SAFETY: Owned live handle; exclusive aligned actual SDK tag record of
    // the specified complete size. The API does not retain its output pointer.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            std::ptr::from_mut(tag).cast(),
            u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>())
                .map_err(|_| io::ErrorKind::InvalidInput)?,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // DE/EN: Namensumleitende Tags wie std behandeln / match std name-surrogate tags.
    Ok(tag.ReparseTag & 0x2000_0000 != 0)
}

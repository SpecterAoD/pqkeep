//! DE: Native Dateipfade nur aus geliehenen, vom Caller geschützten UTF16-Zielen.
//! EN: Native file paths use borrowed caller-protected UTF16 storage only.

use std::{fs::File, io, os::windows::io::FromRawHandle, ptr};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFullPathNameW, OPEN_EXISTING,
    },
};

fn validate(path: &[u16]) -> io::Result<()> {
    if path.last() != Some(&0) || path[..path.len() - 1].contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(())
}

/// DE: Absolute Pfadform direkt in einen lebenden Caller-Puffer schreiben.
/// EN: Write the absolute path directly into live caller-owned storage.
/// # Errors
/// DE/EN: Ungültige UTF16-Geometrie oder native Verweigerung / invalid UTF16 geometry or native refusal.
pub fn absolute_path_into(input: &[u16], output: &mut [u16]) -> io::Result<usize> {
    validate(input)?;
    let len = u32::try_from(output.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    if len == 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // DE: Getrennte lebende Slices, NUL-geprüfte Eingabe, exklusives vollständiges Ziel.
    // SAFETY: Input terminates within its live borrow; output is exclusive and
    // writable for len units. The API retains no pointer; no file-part output requested.
    let count =
        unsafe { GetFullPathNameW(input.as_ptr(), len, output.as_mut_ptr(), ptr::null_mut()) };
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(count as usize)
}

/// DE: Bestehende Datei wie `std::File::open` aus bereits nativ kodiertem Pfad öffnen.
/// EN: Open an existing file with `std::File::open` sharing semantics from native storage.
/// # Errors
/// DE/EN: Ungültige Pfadgeometrie oder nativer Öffnungsfehler / invalid path geometry or native open failure.
pub fn open_file_read(path: &[u16]) -> io::Result<File> {
    validate(path)?;
    // DE: NUL-geprüfte lebende Eingabe; kein vererbbarer Handle, keine Security-Mutation.
    // SAFETY: The immutable input is terminated in bounds and stays live through
    // this synchronous call. Null security/template pointers are permitted; no inheritance.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // DE: Genau ein neuer besessener Handle; File übernimmt ausschließlich dieses Eigentum.
    // SAFETY: Successful CreateFileW returns a fresh owned file handle; transfer
    // it exactly once, with no other owner that could close it.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

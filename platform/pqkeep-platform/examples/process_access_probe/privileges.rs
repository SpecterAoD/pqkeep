//! DE: Ausschließlich lesende Diagnose des eigenen öffentlichen CI-Testtokens.
//! EN: Read-only diagnosis of the own public CI test token.

use std::{
    io,
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use windows_sys::Win32::{
    Foundation::LUID,
    Security::{
        GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_DEBUG_NAME,
        SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenPrivileges,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

fn own_token() -> io::Result<OwnedHandle> {
    let mut handle = std::ptr::null_mut();
    // SAFETY: Current-process pseudo handle is borrowed only. The initialized
    // output gets one new real TOKEN_QUERY handle; no adjustment right requested.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if handle.is_null() {
        return Err(io::Error::other("missing own query token"));
    }
    // SAFETY: Successful API returned a uniquely owned real handle, closed once.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

pub(super) fn debug_enabled() -> io::Result<bool> {
    let token = own_token()?;
    let (mut buffer, mut needed) = ([0u32; 512], 0);
    // SAFETY: Live own TOKEN_QUERY handle; initialized aligned2048byte buffer;
    // exact capacity passed and exclusive output count. No token writes.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenPrivileges,
            buffer.as_mut_ptr().cast(),
            2048,
            &raw mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let needed = usize::try_from(needed).map_err(|_| io::Error::other("invalid token length"))?;
    let offset = offset_of!(TOKEN_PRIVILEGES, Privileges);
    if offset % size_of::<u32>() != 0 || !(offset..=size_of_val(&buffer)).contains(&needed) {
        return Err(io::Error::other("invalid token result length"));
    }
    let count = usize::try_from(buffer[0]).map_err(|_| io::Error::other("invalid token count"))?;
    if count > (needed - offset) / size_of::<LUID_AND_ATTRIBUTES>() {
        return Err(io::Error::other("invalid token records"));
    }
    // SAFETY: DWORD-aligned record offset in a DWORD-aligned initialized buffer;
    // complete count validated against actual returned bytes. All fields integer.
    let values = unsafe {
        std::slice::from_raw_parts(
            buffer
                .as_ptr()
                .add(offset / size_of::<u32>())
                .cast::<LUID_AND_ATTRIBUTES>(),
            count,
        )
    };
    enabled(values)
}

fn enabled(values: &[LUID_AND_ATTRIBUTES]) -> io::Result<bool> {
    let mut debug = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: Null means local system lookup; static NUL-terminated privilege
    // name, exclusive initialized scalar output; no token or account mutation.
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), SE_DEBUG_NAME, &raw mut debug) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(values.iter().any(|value| {
        value.Luid.LowPart == debug.LowPart
            && value.Luid.HighPart == debug.HighPart
            && value.Attributes & SE_PRIVILEGE_ENABLED != 0
    }))
}

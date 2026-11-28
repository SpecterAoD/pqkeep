//! DE: Ausdrücklich freigegebene eigene CI-Threadprobe, kein Produktionspfad.
//! Primärtoken nur lesen/duplizieren, Privilegien ausschließlich im Duplikat senken.
//! EN: Explicitly approved own CI thread experiment, not a production path.
//! Read/duplicate primary token only; lower privileges exclusively on the duplicate.

use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use windows_sys::Win32::{
    Security::{
        AdjustTokenPrivileges, DuplicateTokenEx, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY, TokenImpersonation,
    },
    System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken, SetThreadToken,
    },
};

fn duplicate_primary() -> io::Result<OwnedHandle> {
    let mut original = std::ptr::null_mut();
    // SAFETY: Borrow current-process pseudo handle, request only query/duplicate;
    // initialized exclusive output. No adjustment access on the original token.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &raw mut original,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if original.is_null() {
        return Err(io::Error::other("missing own source token"));
    }
    // SAFETY: New uniquely owned real handle from successful OpenProcessToken.
    let original = unsafe { OwnedHandle::from_raw_handle(original) };
    let mut copy = std::ptr::null_mut();
    let rights = TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE;
    // SAFETY: Live query/duplicate handle; null attributes prohibit inheritance.
    // Creates a distinct owned impersonation token, never adjusts the original.
    if unsafe {
        DuplicateTokenEx(
            original.as_raw_handle(),
            rights,
            std::ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut copy,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if copy.is_null() {
        return Err(io::Error::other("missing own duplicate token"));
    }
    // SAFETY: Successful duplication returned one new real handle, owned once.
    Ok(unsafe { OwnedHandle::from_raw_handle(copy) })
}

fn thread_token() -> io::Result<Option<OwnedHandle>> {
    let mut token = std::ptr::null_mut();
    // SAFETY: Current-thread pseudo handle, query only, initialized exclusive
    // output; OpenAsSelf checks access, it does not change the token or identity.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) } == 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(1008) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    if token.is_null() {
        return Err(io::Error::other("missing own thread query token"));
    }
    // SAFETY: Successful open returned a new uniquely owned real query handle.
    Ok(Some(unsafe { OwnedHandle::from_raw_handle(token) }))
}

pub(super) fn own_thread() -> io::Result<OwnedHandle> {
    if thread_token()?.is_some() {
        return Err(io::Error::other(
            "unexpected preexisting thread impersonation",
        ));
    }
    let token = duplicate_primary()?;
    // SAFETY: Live uniquely owned DUPLICATE token with adjustment access;
    // TRUE disables every privilege, other parameters are documented ignored/null.
    // Neither original primary token nor account privileges are adjusted.
    if unsafe {
        AdjustTokenPrivileges(
            token.as_raw_handle(),
            1,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if super::privileges::any_enabled(&token)? {
        return Err(io::Error::other("duplicate privileges remain enabled"));
    }
    // SAFETY: NULL selects only the calling test thread. Live duplicate is an
    // impersonation token at SecurityImpersonation level with TOKEN_IMPERSONATE.
    // Never restore/enable privileges; this owned ephemeral thread exits afterward.
    if unsafe { SetThreadToken(std::ptr::null(), token.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let actual = thread_token()?.ok_or_else(|| io::Error::other("missing applied thread token"))?;
    if super::privileges::any_enabled(&actual)? {
        return Err(io::Error::other(
            "effective thread privileges remain enabled",
        ));
    }
    Ok(token)
}

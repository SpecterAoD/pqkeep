//! DE: Rust-1.88-Pfadsemantik mit gesperrten Zielen statt gewöhnlicher UTF16-Vecs.
//! EN: Rust1.88 path semantics using locked destinations instead of ordinary UTF16 Vecs.
//! DE/EN: Adapted branch logic: rust-lang/rust1.88 library/std/src/sys/path/windows.rs,
//! `get_long_path(prefer_verbatim=true)`, MIT OR Apache-2.0; no cryptographic changes.

use super::{Error, NativePath, Result};

const SEP: u16 = 92;
const ALT: u16 = 47;
const COLON: u16 = 58;
const QUERY: u16 = 63;
const VERBATIM: &[u16] = &[SEP, SEP, QUERY, SEP];
const NT: &[u16] = &[SEP, QUERY, QUERY, SEP];
const UNC: &[u16] = &[SEP, SEP, QUERY, SEP, 85, 78, 67, SEP];
const MAX_NATIVE: usize = 32768;
const LEGACY_MAX_PATH: usize = 248;

fn unchanged(path: &[u16]) -> bool {
    if path.starts_with(VERBATIM) || path.starts_with(NT) || path == [0] {
        return true;
    }
    if path.len() >= LEGACY_MAX_PATH {
        return false;
    }
    match path {
        [drive, COLON, 0] | [drive, COLON, SEP | ALT, ..] if *drive != SEP && *drive != ALT => true,
        [SEP | ALT, SEP | ALT, ..] => true,
        _ => false,
    }
}

#[cfg(test)]
#[path = "native_path_windows_tests.rs"]
mod tests;

pub(super) fn for_open(input: &NativePath) -> Result<Option<NativePath>> {
    let path = input.encoded()?;
    if unchanged(path) {
        return Ok(None);
    }
    let mut absolute = NativePath::prepare()?;
    absolute.allocate(259)?;
    for _ in 0..4 {
        let count = pqkeep_platform::absolute_path_into(path, absolute.0.get_mut().0.expose_mut())?;
        if count < absolute.0.get().0.expose().len() {
            absolute.0.get_mut().0.truncate(count + 1);
            return with_prefix(&absolute).map(Some);
        }
        if count >= MAX_NATIVE {
            return Err(Error::InvalidInput { field: "path" });
        }
        absolute.allocate(count)?;
    }
    Err(Error::Io(std::io::ErrorKind::InvalidInput))
}

fn with_prefix(absolute: &NativePath) -> Result<NativePath> {
    let units = absolute.encoded()?;
    let raw = &units[..units.len() - 1];
    let (prefix, skip) = match raw {
        [_, COLON, SEP, ..] => (VERBATIM, 0),
        [SEP, SEP, 46, SEP, ..] => (VERBATIM, 4),
        [SEP, SEP | QUERY, QUERY, SEP, ..] => (&[][..], 0),
        [SEP, SEP, ..] => (UNC, 2),
        _ => (&[][..], 0),
    };
    let tail = &raw[skip..];
    let len = prefix
        .len()
        .checked_add(tail.len())
        .ok_or(Error::MemoryLock)?;
    let mut out = NativePath::prepare()?;
    out.allocate(len)?;
    let target = out.0.get_mut().0.expose_mut();
    target[..prefix.len()].copy_from_slice(prefix);
    target[prefix.len()..len].copy_from_slice(tail);
    Ok(out)
}

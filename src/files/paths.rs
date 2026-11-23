//! DE: Prüfung relativer Archivpfade – beim Verschlüsseln (nur portable Namen
//! aufnehmen) und beim Entpacken (bösartige Archive abweisen). Pfade sind UTF-8,
//! getrennt durch „/“. Verboten: leere Teile, „.“, „..“, „\“, „:“, Steuerzeichen,
//! Windows-reservierte Namen, Leerzeichen/Punkt am Ende, zu lange Teile/Pfade,
//! zu tiefe Verschachtelung. Doppelte Pfade werden auch bei anderer Groß-/Klein-
//! schreibung erkannt (unter Windows/macOS wären sie dieselbe Datei).
//!
//! EN: Validation of relative archive paths – when encrypting (only include
//! portable names) and when extracting (reject malicious archives). Paths are
//! UTF-8, separated by "/". Forbidden: empty parts, ".", "..", "\", ":", control
//! characters, Windows reserved names, trailing space/dot, overlong parts/paths,
//! excessive nesting. Duplicates are detected case-insensitively too (on
//! Windows/macOS they would be the same file).

use super::ConfidentialText;
use crate::crypto::SecretBytes;
use std::collections::BTreeSet;
use std::ops::Bound;

use crate::{Error, Result};

#[cfg(test)]
#[path = "paths_tests.rs"]
mod paths_tests;

/// DE: Höchstlänge eines Pfadteils in Bytes. EN: Maximum length of a path part in bytes.
pub const MAX_COMPONENT_BYTES: usize = 255;
/// DE: Höchstlänge des ganzen Pfads in Bytes. EN: Maximum length of the whole path in bytes.
pub const MAX_PATH_BYTES: usize = 4096;
/// DE: Höchste Verschachtelungstiefe. EN: Maximum nesting depth.
pub const MAX_DEPTH: usize = 64;
/// DE: Höchstzahl an Einträgen. EN: Maximum number of entries.
pub const MAX_ENTRIES: u64 = 1_000_000;

const RESERVED: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];

fn invalid() -> Error {
    Error::InvalidInput { field: "path" }
}

/// DE: Windows-reservierter Name (auch mit Endung, z. B. „nul.txt“, „COM1.log“)?
/// EN: Windows reserved name (also with extension, e.g. "nul.txt", "COM1.log")?
fn is_reserved(part: &str) -> bool {
    let stem = part.split('.').next().unwrap_or(part);
    if RESERVED.iter().any(|name| stem.eq_ignore_ascii_case(name)) {
        return true;
    }
    let numbered = |prefix: &str| {
        stem.get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
            && stem.get(prefix.len()..).is_some_and(|rest| {
                matches!(
                    rest,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
    };
    numbered("COM") || numbered("LPT")
}

fn component_ok(part: &str) -> bool {
    !part.is_empty()
        && part != "."
        && part != ".."
        && part.len() <= MAX_COMPONENT_BYTES
        && !part.ends_with(' ')
        && !part.ends_with('.')
        && !part
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
        && !is_reserved(part)
}

/// DE: Prüft einen relativen Pfad und liefert seine Teile.
/// EN: Validates a relative path and returns its parts.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] mit Feld `path` / with field `path`.
pub fn validate(path: &str) -> Result<Vec<&str>> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || path.starts_with('/') {
        return Err(invalid());
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > MAX_DEPTH || !parts.iter().all(|p| component_ok(p)) {
        return Err(invalid());
    }
    Ok(parts)
}

/// DE: Merkt sich Pfade (ohne Groß-/Kleinschreibung) und erkennt Doppelte sowie
/// Datei/Ordner-Konflikte („a“ als Datei und „a/b“).
/// EN: Remembers paths (case-insensitively) and detects duplicates as well as
/// file/directory conflicts ("a" as a file and "a/b").
#[derive(Default)]
pub struct PathSet {
    entries: BTreeSet<ConfidentialText>,
    files: BTreeSet<ConfidentialText>,
}

fn lower_chars(part: &str) -> impl Iterator<Item = char> + '_ {
    // DE: Sigma-Aliase konservativ zusammenfassen; Originalnamen nicht ändern.
    // EN: Conservatively merge sigma aliases; never alter original names.
    part.chars()
        .flat_map(char::to_lowercase)
        .map(|c| if c == 'ς' { 'σ' } else { c })
}

fn folded_key(parts: &[&str]) -> Result<ConfidentialText> {
    if parts.is_empty() || parts.len() > MAX_DEPTH || !parts.iter().all(|p| component_ok(p)) {
        return Err(invalid());
    }
    let raw_len: usize = parts.iter().map(|p| p.len()).sum::<usize>() + parts.len() - 1;
    if raw_len > MAX_PATH_BYTES {
        return Err(invalid());
    }
    let len = parts
        .iter()
        .map(|p| lower_chars(p).map(char::len_utf8).sum::<usize>())
        .sum::<usize>()
        + parts.len()
        - 1;
    let mut out = SecretBytes::zeroed(len)?;
    let mut offset = 0;
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            out.expose_mut()[offset] = b'/';
            offset += 1;
        }
        for c in lower_chars(part) {
            let len = c.len_utf8();
            c.encode_utf8(&mut out.expose_mut()[offset..offset + len]);
            offset += len;
        }
    }
    ConfidentialText::from_locked(out)
}

impl PathSet {
    /// DE: Fügt einen Pfad hinzu; keine ungesperrte normalisierte Kopie.
    /// EN: Insert a path without an unlocked normalized copy.
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (path), [`Error::MemoryLock`].
    pub fn insert(&mut self, parts: &[&str], is_file: bool) -> Result<()> {
        let key = folded_key(parts)?;
        for (index, byte) in key.bytes().iter().enumerate() {
            if *byte == b'/' && self.files.contains(&key.bytes()[..index]) {
                return Err(invalid());
            }
        }
        if self.entries.contains(key.bytes()) {
            return Err(invalid());
        }
        if is_file {
            let mut prefix = SecretBytes::zeroed(key.bytes().len() + 1)?;
            prefix.expose_mut()[..key.bytes().len()].copy_from_slice(key.bytes());
            prefix.expose_mut()[key.bytes().len()] = b'/';
            if self
                .entries
                .range::<[u8], _>((Bound::Included(prefix.expose()), Bound::Unbounded))
                .next()
                .is_some_and(|p| p.bytes().starts_with(prefix.expose()))
            {
                return Err(invalid());
            }
        }
        let file_key = if is_file {
            Some(key.try_duplicate()?)
        } else {
            None
        };
        self.entries.insert(key);
        if let Some(key) = file_key {
            self.files.insert(key);
        }
        Ok(())
    }
}

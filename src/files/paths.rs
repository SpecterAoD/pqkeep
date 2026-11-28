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

use crate::{Error, Result};

#[cfg(test)]
#[path = "paths_tests.rs"]
mod paths_tests;

#[cfg(test)]
#[path = "path_components_tests.rs"]
mod component_tests;

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
    Ok(components(path)?.collect())
}

// DE: Vollständig prüfen, bevor ein geliehener Iterator zum Verbraucher gelangt.
// EN: Validate fully before returning a borrowed iterator to any consumer.
pub(super) fn components(path: &str) -> Result<impl Iterator<Item = &str> + Clone> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || path.starts_with('/') {
        return Err(invalid());
    }
    if !path
        .split('/')
        .enumerate()
        .all(|(index, part)| index < MAX_DEPTH && component_ok(part))
    {
        return Err(invalid());
    }
    Ok(path.split('/'))
}

pub(super) fn validate_only(path: &str) -> Result<()> {
    let _ = components(path)?;
    Ok(())
}

/// DE: Merkt sich Pfade (ohne Groß-/Kleinschreibung) und erkennt Doppelte sowie
/// Datei/Ordner-Konflikte („a“ als Datei und „a/b“).
/// EN: Remembers paths (case-insensitively) and detects duplicates as well as
/// file/directory conflicts ("a" as a file and "a/b").
#[derive(Default)]
pub struct PathSet {
    entries: super::confidential_path_index::Index,
}

fn folded_size<'a>(parts: impl Iterator<Item = &'a str>) -> Result<usize> {
    let (mut count, mut raw_len, mut len) = (0, 0, 0);
    for part in parts {
        if count == MAX_DEPTH || !component_ok(part) {
            return Err(invalid());
        }
        let separator = usize::from(count > 0);
        raw_len += part.len() + separator;
        if raw_len > MAX_PATH_BYTES {
            return Err(invalid());
        }
        len += part.chars().map(super::unicode_fold::size).sum::<usize>() + separator;
        count += 1;
    }
    if count == 0 {
        return Err(invalid());
    }
    Ok(len)
}

fn folded_key<'a>(parts: impl Iterator<Item = &'a str> + Clone) -> Result<ConfidentialText> {
    let mut out = SecretBytes::zeroed(folded_size(parts.clone())?)?;
    let mut offset = 0;
    for (index, part) in parts.enumerate() {
        if index > 0 {
            out.expose_mut()[offset] = b'/';
            offset += 1;
        }
        for c in part.chars() {
            offset += super::unicode_fold::write(c, &mut out.expose_mut()[offset..]);
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
        self.insert_components(parts.iter().copied(), is_file)
    }

    pub(super) fn insert_components<'a>(
        &mut self,
        parts: impl Iterator<Item = &'a str> + Clone,
        is_file: bool,
    ) -> Result<()> {
        let key = folded_key(parts)?;
        for (index, byte) in key.bytes().iter().enumerate() {
            if *byte == b'/' && self.entries.get(&key.bytes()[..index]) == Some(true) {
                return Err(invalid());
            }
        }
        if self.entries.get(key.bytes()).is_some() {
            return Err(invalid());
        }
        if is_file {
            let mut prefix = SecretBytes::zeroed(key.bytes().len() + 1)?;
            prefix.expose_mut()[..key.bytes().len()].copy_from_slice(key.bytes());
            prefix.expose_mut()[key.bytes().len()] = b'/';
            if self.entries.has_prefix(prefix.expose()) {
                return Err(invalid());
            }
        }
        self.entries.insert(key, is_file)
    }
}

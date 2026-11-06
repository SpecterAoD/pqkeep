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

use std::collections::HashSet;

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
    let stem = part.split('.').next().unwrap_or(part).to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        return true;
    }
    let numbered = |prefix: &str| {
        stem.strip_prefix(prefix).is_some_and(|rest| {
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
    entries: HashSet<String>,
    files: HashSet<String>,
}

impl PathSet {
    /// DE: Fügt einen Pfad hinzu. EN: Adds a path.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (Feld `path`) bei Doppelten/Konflikten / on duplicates/conflicts.
    pub fn insert(&mut self, parts: &[&str], is_file: bool) -> Result<()> {
        let folded: Vec<String> = parts.iter().map(|p| p.to_lowercase()).collect();
        for depth in 1..folded.len() {
            if self.files.contains(&folded[..depth].join("/")) {
                return Err(invalid());
            }
        }
        let key = folded.join("/");
        if !self.entries.insert(key.clone()) {
            return Err(invalid());
        }
        if is_file {
            self.files.insert(key);
        }
        Ok(())
    }
}

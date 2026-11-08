//! DE: Registry-Zugriff für `integrate` unter Windows: Wurzel (in Debug-Builds für Tests
//! umlenkbar), Einträge lesen, Zustand gegen das Manifest, schreiben, leere Eltern entfernen.
//! EN: Registry access for `integrate` on Windows: root (redirectable for tests in debug builds),
//! reading entries, state against the manifest, writing, removing empty parents.

use std::path::Path;

use windows_registry::{CURRENT_USER, Key, Type};

use super::manifest::{FileState, Manifest, digest};
use super::winplan::{COMMAND_KEY, SZ, Snapshot, Verb};

/// DE: Klassen-Wurzel unter HKCU. EN: Classes root below HKCU.
const CLASSES: &str = r"Software\Classes";
/// DE: Win32-Fehler 2 (nicht gefunden) als HRESULT. EN: Win32 error 2 (not found) as HRESULT.
const NOT_FOUND: u32 = 0x8007_0002;

pub(super) type RegResult<T> = windows_registry::Result<T>;

/// DE: Test-Wurzel `Software\PQKeepTest…`, nur in Debug-Builds per Umgebungsvariable.
/// EN: Test root `Software\PQKeepTest…`, only in debug builds via environment variable.
#[cfg(debug_assertions)]
fn test_root() -> Option<String> {
    std::env::var("PQKEEP_TEST_REG_ROOT")
        .ok()
        .filter(|r| r.starts_with(r"Software\PQKeepTest"))
}

#[cfg(not(debug_assertions))]
fn test_root() -> Option<String> {
    None
}

/// DE: Klassen-Wurzel (oder Test-Wurzel). EN: Classes root (or test root).
pub(super) fn root() -> String {
    test_root().unwrap_or_else(|| CLASSES.to_owned())
}

/// DE: Öffnet lesend; `None`, wenn der Schlüssel fehlt. EN: Opens for reading; `None` if missing.
pub(super) fn open(path: &str) -> RegResult<Option<Key>> {
    match CURRENT_USER.open(path) {
        Ok(k) => Ok(Some(k)),
        Err(e) if e.code().0.cast_unsigned() == NOT_FOUND => Ok(None),
        Err(e) => Err(e),
    }
}

/// DE: Alle Werte; Nicht-Text-Werte nur mit Typ (weichen ohnehin vom Plan ab).
/// EN: All values; non-text values only with their type (they differ from the plan anyway).
fn values(key: &Key) -> RegResult<Vec<(String, String, String)>> {
    let mut out = Vec::new();
    for (name, value) in key.values()? {
        let entry = match value.ty() {
            Type::String => (name, SZ.to_owned(), String::try_from(value)?),
            other => (name, format!("{other:?}"), String::new()),
        };
        out.push(entry);
    }
    Ok(out)
}

/// DE: Liest den Zustand eines Eintrags (Verb + `command`). EN: Reads the state of an entry.
fn snapshot(full: &str) -> RegResult<Option<Snapshot>> {
    let Some(key) = open(full)? else {
        return Ok(None);
    };
    let mut snap = Snapshot {
        values: values(&key)?,
        subkeys: key.keys()?.collect(),
        ..Snapshot::default()
    };
    let has_command = snap
        .subkeys
        .iter()
        .any(|k| k.eq_ignore_ascii_case(COMMAND_KEY));
    let cmd = if has_command {
        open(&format!(r"{full}\{COMMAND_KEY}"))?
    } else {
        None
    };
    if let Some(cmd) = cmd {
        snap.command_values = values(&cmd)?;
        snap.command_subkeys = cmd.keys()?.collect();
    }
    Ok(Some(snap))
}

pub(super) fn state(manifest: &Manifest, full: &str) -> RegResult<(FileState, Option<String>)> {
    let current = snapshot(full)?.map(|s| digest(s.canonical().as_bytes()));
    let st = match &current {
        None => FileState::Missing,
        Some(d) if manifest.recorded(Path::new(full)) == Some(d.as_str()) => FileState::Ours,
        Some(_) => FileState::Foreign,
    };
    Ok((st, current))
}

pub(super) fn write(full: &str, verb: &Verb) -> RegResult<()> {
    let key = CURRENT_USER.create(full)?;
    for (name, data) in &verb.values {
        key.set_string(name, data)?;
    }
    key.create(COMMAND_KEY)?.set_string("", &verb.command)
}

/// DE: Entfernt leere Elternschlüssel bis unterhalb der Wurzel. EN: Removes empty parents below the root.
pub(super) fn prune_empty(root: &str, full: &str) {
    let mut path = full;
    while let Some((parent, _)) = path.rsplit_once('\\') {
        if parent.len() <= root.len() {
            break;
        }
        let empty = matches!(open(parent), Ok(Some(k))
            if k.keys().is_ok_and(|mut i| i.next().is_none())
                && k.values().is_ok_and(|mut i| i.next().is_none()));
        if !empty || CURRENT_USER.remove_tree(parent).is_err() {
            break;
        }
        path = parent;
    }
}

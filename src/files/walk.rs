//! DE: Einlesen der Quelle: Einzeldatei oder Ordner (rekursiv, sortiert und damit
//! reproduzierbar). Symlinks werden nie verfolgt. Symlinks, Geräte/Pipes, Namen
//! ohne gültiges UTF-8 und nicht portable Namen werden übersprungen und gemeldet.
//!
//! EN: Reading the source: single file or directory (recursive, sorted and thus
//! reproducible). Symlinks are never followed. Symlinks, devices/pipes, names
//! without valid UTF-8 and non-portable names are skipped and reported.

use std::fs;
use std::path::{Path, PathBuf};

use super::paths::{self, MAX_ENTRIES};
use crate::{Error, Result};

/// DE: Grund für das Überspringen. EN: Reason for skipping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipReason {
    /// DE: Symbolischer Link. EN: Symbolic link.
    Symlink,
    /// DE: Gerät, Pipe, Socket. EN: Device, pipe, socket.
    Special,
    /// DE: Name ist kein gültiges UTF-8. EN: Name is not valid UTF-8.
    NonUtf8Name,
    /// DE: Name nicht portabel (z. B. „CON“, „a:b“, zu lang/tief).
    /// EN: Name not portable (e.g. "CON", "a:b", too long/deep).
    InvalidName,
}

/// DE: Übersprungener Eintrag. EN: Skipped entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// DE: Relativer Pfad (verlustbehaftet dargestellt). EN: Relative path (lossy).
    pub path: String,
    /// DE: Grund. EN: Reason.
    pub reason: SkipReason,
}

/// DE: Art eines Quelleintrags. EN: Kind of source entry.
pub(crate) enum SourceKind {
    Dir,
    File(u64),
}

/// DE: Quelleintrag mit relativem Archivpfad. EN: Source entry with relative archive path.
pub(crate) struct SourceEntry {
    pub rel: String,
    pub abs: PathBuf,
    pub kind: SourceKind,
}

/// DE: Einzeldatei als einziger Eintrag (Name muss portabel sein).
/// EN: Single file as the only entry (name must be portable).
pub(crate) fn collect_file(path: &Path) -> Result<SourceEntry> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        return Err(Error::InvalidInput { field: "source" });
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(Error::InvalidInput { field: "path" })?;
    paths::validate(name)?;
    Ok(SourceEntry {
        rel: name.to_owned(),
        abs: path.to_path_buf(),
        kind: SourceKind::File(meta.len()),
    })
}

/// DE: Ordner rekursiv; der Ordner selbst ist nicht Teil des Archivs.
/// EN: Directory recursively; the directory itself is not part of the archive.
pub(crate) fn collect_dir(root: &Path) -> Result<(Vec<SourceEntry>, Vec<Skipped>)> {
    if !fs::symlink_metadata(root)?.file_type().is_dir() {
        return Err(Error::InvalidInput { field: "source" });
    }
    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let mut children: Vec<_> = fs::read_dir(&dir)?.collect::<std::io::Result<_>>()?;
        children.sort_by_key(fs::DirEntry::file_name);
        // DE: Umgekehrt auf den Stapel, damit die Reihenfolge alphabetisch bleibt.
        // EN: Pushed in reverse so that the order stays alphabetical.
        let mut subdirs = Vec::new();
        for child in children {
            visit(&child, &prefix, &mut entries, &mut skipped, &mut subdirs)?;
            if entries.len() as u64 > MAX_ENTRIES {
                return Err(Error::InvalidInput { field: "entries" });
            }
        }
        stack.extend(subdirs.into_iter().rev());
    }
    entries.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok((entries, skipped))
}

fn visit(
    child: &fs::DirEntry,
    prefix: &str,
    entries: &mut Vec<SourceEntry>,
    skipped: &mut Vec<Skipped>,
    subdirs: &mut Vec<(PathBuf, String)>,
) -> Result<()> {
    let name = child.file_name();
    let lossy = format!("{prefix}{}", name.to_string_lossy());
    let mut skip = |reason| {
        skipped.push(Skipped {
            path: lossy.clone(),
            reason,
        });
        Ok(())
    };
    let Some(name) = name.to_str() else {
        return skip(SkipReason::NonUtf8Name);
    };
    let rel = format!("{prefix}{name}");
    if paths::validate(&rel).is_err() {
        return skip(SkipReason::InvalidName);
    }
    let file_type = child.file_type()?;
    if file_type.is_symlink() {
        return skip(SkipReason::Symlink);
    }
    let abs = child.path();
    if file_type.is_dir() {
        subdirs.push((abs.clone(), format!("{rel}/")));
        entries.push(SourceEntry {
            rel,
            abs,
            kind: SourceKind::Dir,
        });
    } else if file_type.is_file() {
        let size = fs::symlink_metadata(&abs)?.len();
        entries.push(SourceEntry {
            rel,
            abs,
            kind: SourceKind::File(size),
        });
    } else {
        return skip(SkipReason::Special);
    }
    Ok(())
}

//! DE: Identität der eigenen Ausgabe (#338): Nach dem Anlegen einer Temporärausgabe darf ein
//! Angreifer mit Schreibrecht im Zielordner ihren **Namen** austauschen. Deshalb merkt sich PQKeep
//! Gerät und Inode des offenen Objekts, veröffentlicht Dateien unter Linux über den offenen
//! Deskriptor (`/proc/self/fd/N`) statt über den Namen und prüft nach jedem Veröffentlichen, dass
//! unter dem Zielnamen wirklich das eigene Objekt liegt – sonst Fehler statt Erfolg.
//! Windows: Prüfung folgt in einem eigenen Schritt (Datei-ID über Handles); bis dahin gilt dort die
//! dokumentierte Grenze „nur vertrauenswürdige Zielordner“.
//! EN: Identity of our own output (#338): after a temporary output is created, an attacker with
//! write access to the target directory may swap its **name**. PQKeep therefore remembers device
//! and inode of the open object, publishes files on Linux via the open descriptor
//! (`/proc/self/fd/N`) instead of the name and checks after every publication that the target name
//! really holds our object – otherwise an error instead of success. Windows: the check follows in a
//! separate step (file ID via handles); until then the documented limit "trusted target
//! directories only" applies there.

use std::fs::{self, File};
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

/// DE: Gerät und Inode (Unix); unter Windows noch ohne Inhalt. EN: Device and inode (Unix).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl Identity {
    /// DE: Identität eines offenen Objekts (`fstat`). EN: Identity of an open object (`fstat`).
    pub(crate) fn of(file: &File) -> io::Result<Self> {
        Ok(from(&file.metadata()?))
    }

    /// DE: Identität unter einem Namen, ohne Symlinks zu folgen. EN: Identity under a name, no follow.
    pub(crate) fn at(path: &Path) -> io::Result<Self> {
        Ok(from(&fs::symlink_metadata(path)?))
    }
}

#[cfg(unix)]
fn from(meta: &fs::Metadata) -> Identity {
    use std::os::unix::fs::MetadataExt;
    Identity {
        dev: meta.dev(),
        ino: meta.ino(),
    }
}

#[cfg(not(unix))]
fn from(_meta: &fs::Metadata) -> Identity {
    Identity {}
}

/// DE: Fehler „Ausgabe wurde ausgetauscht“. EN: Error "output was replaced".
pub(crate) fn replaced() -> io::Error {
    io::Error::new(ErrorKind::InvalidData, "output replaced")
}

/// DE: Liegt unter `path` (ohne Symlink-Folgen) das Objekt `id`? EN: Does `path` hold object `id`?
pub(crate) fn is_own(path: &Path, id: Identity) -> bool {
    Identity::at(path).is_ok_and(|found| found == id)
}

/// DE: Nach dem Veröffentlichen: Ziel muss das eigene Objekt sein. EN: After publishing: own object.
pub(crate) fn verify(path: &Path, id: Identity) -> io::Result<()> {
    if is_own(path, id) {
        Ok(())
    } else {
        Err(replaced())
    }
}

/// DE: Pfad, über den das offene Objekt unabhängig von seinem Namen erreichbar ist (Linux:
/// `/proc/self/fd/N`, nur wenn er wirklich auf dieses Objekt zeigt). EN: Path reaching the open
/// object independent of its name (Linux: `/proc/self/fd/N`, only if it really points to it).
#[cfg(target_os = "linux")]
pub(crate) fn handle_path(file: &File) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    let path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    let id = Identity::of(file).ok()?;
    fs::metadata(&path)
        .is_ok_and(|meta| from(&meta) == id)
        .then_some(path)
}

/// DE: Ohne `/proc` kein Handle-Pfad. EN: Without `/proc` no handle path.
#[cfg(not(target_os = "linux"))]
pub(crate) fn handle_path(_file: &File) -> Option<PathBuf> {
    None
}

/// DE: Verlinkt das offene Objekt als `target` (scheitert, wenn `target` existiert). `Ok(false)`:
/// über den Deskriptor nicht möglich (kein `/proc`, Sandbox) – der Aufrufer nimmt den Namen und
/// prüft danach. EN: Links the open object as `target` (fails if it exists). `Ok(false)`: not
/// possible via the descriptor (no `/proc`, sandbox) – the caller uses the name and verifies.
#[cfg(target_os = "linux")]
pub(crate) fn link_handle(file: &File, target: &Path) -> io::Result<bool> {
    use rustix::fs::{AtFlags, CWD, linkat};
    let Some(source) = handle_path(file) else {
        return Ok(false);
    };
    match linkat(CWD, &source, CWD, target, AtFlags::SYMLINK_FOLLOW) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::EXIST) => Err(ErrorKind::AlreadyExists.into()),
        Err(_) => Ok(false),
    }
}

/// DE: Außer Linux: immer über den Namen. EN: Outside Linux: always via the name.
#[cfg(not(target_os = "linux"))]
pub(crate) fn link_handle(_file: &File, _target: &Path) -> io::Result<bool> {
    Ok(false)
}

/// DE: Umbenennen ohne Ersetzen (Linux `renameat2(RENAME_NOREPLACE)`); wo das Dateisystem es nicht
/// kann: prüfen und umbenennen. EN: Rename without replacing (Linux `renameat2(RENAME_NOREPLACE)`);
/// where the file system cannot: check and rename.
pub(crate) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{CWD, RenameFlags, renameat_with};
        match renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE) {
            Ok(()) => return Ok(()),
            Err(rustix::io::Errno::EXIST) => return Err(ErrorKind::AlreadyExists.into()),
            Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOSYS) => {}
            Err(e) => return Err(e.into()),
        }
    }
    if fs::symlink_metadata(to).is_ok() {
        return Err(ErrorKind::AlreadyExists.into());
    }
    fs::rename(from, to)
}

/// DE: Leert einen Ordner über einen Pfad (z. B. den Handle-Pfad), ohne Symlinks zu folgen.
/// EN: Empties a directory via a path (e.g. the handle path) without following symlinks.
pub(crate) fn clear_dir(path: &Path) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
        let _ = if is_dir {
            fs::remove_dir_all(&child)
        } else {
            fs::remove_file(&child)
        };
    }
}

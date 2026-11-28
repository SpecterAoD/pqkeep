//! DE: Schutz der Temporärausgabe gegen Austausch (#338): Dateien behalten ein zweites Handle
//! (Veröffentlichen und Prüfen über den Deskriptor); Ordner werden ohne Symlink-Folgen geöffnet,
//! Eigentümer und Rechte (0700) geprüft und unter Linux über `/proc/self/fd/N` beschrieben – ein
//! umbenannter oder ersetzter Temporärname lenkt keine Schreibvorgänge mehr um.
//! EN: Protection of the temporary output against replacement (#338): files keep a second handle
//! (publish and verify via the descriptor); directories are opened without following symlinks,
//! owner and mode (0700) are checked and on Linux they are written via `/proc/self/fd/N` – a
//! renamed or replaced temporary name no longer redirects writes.

use std::fs::File;
use std::path::{Path, PathBuf};

use crate::Result;
use crate::fs_identity::{Identity, clear_dir, is_own};
use crate::fsutil::{OutputFile, handle_of};

/// DE: Offenes eigenes Objekt. EN: Open own object.
pub(super) struct Guard {
    pub handle: File,
    pub id: Identity,
    /// DE: Pfad über das Handle (Linux, Ordner). EN: Path via the handle (Linux, directories).
    pub via: Option<PathBuf>,
}

impl Guard {
    /// DE: Für eine Temporärdatei. EN: For a temporary file.
    pub(super) fn file(file: &OutputFile) -> Result<Self> {
        let handle = handle_of(file)?;
        let id = Identity::of(&handle)?;
        Ok(Self {
            handle,
            id,
            via: None,
        })
    }

    /// DE: Für einen gerade angelegten Temporärordner (Linux). EN: For a just created temp dir.
    #[cfg(target_os = "linux")]
    pub(super) fn dir(temp: &Path) -> Result<Option<Self>> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(temp)?;
        let meta = handle.metadata()?;
        // DE: Gruppe und andere ohne Rechte (untere 6 Bit null). EN: No group/other bits.
        let private = meta.mode().trailing_zeros() >= 6;
        let own = meta.uid() == rustix::process::geteuid().as_raw() && private;
        if !own {
            return Err(crate::fs_identity::replaced().into());
        }
        let id = Identity::of(&handle)?;
        let via = crate::fs_identity::handle_path(&handle);
        Ok(Some(Self { handle, id, via }))
    }

    /// DE: Außer Linux: kein Ordner-Handle (Windows folgt eigens). EN: Outside Linux: none yet.
    #[cfg(not(target_os = "linux"))]
    pub(super) fn dir(_temp: &Path) -> Result<Option<Self>> {
        Ok(None)
    }
}

/// DE: Aufräumen nach Fehler: nur das eigene Objekt. Liegt es weder unter dem Temporär- noch unter
/// dem Zielnamen, wurde der Name ausgetauscht: dann wird der Inhalt über das Handle geleert, der
/// fremde Name bleibt unberührt. Liegt es schon unter dem Zielnamen (Fehler nach dem
/// Veröffentlichen), bleibt alles, wie es ist.
/// EN: Cleanup after failure: only our own object. If it is neither under the temporary nor under
/// the target name, the name was swapped: the content is emptied via the handle and the foreign
/// name stays untouched. If it is already under the target name (failure after publishing),
/// everything stays as it is.
pub(super) fn cleanup(temp: &Path, target: &Path, is_dir: bool, guard: Option<&Guard>) {
    if let Some(g) = guard.filter(|g| is_own(target, g.id)) {
        // DE: Datei per Hardlink veröffentlicht: nur den eigenen Temporärnamen entfernen.
        // EN: File published via hard link: only remove our own temporary name.
        if !is_dir && is_own(temp, g.id) {
            let _ = std::fs::remove_file(temp);
        }
        return;
    }
    let swapped = guard.filter(|g| !is_own(temp, g.id));
    match (swapped, is_dir) {
        (Some(g), true) => {
            if let Some(via) = &g.via {
                clear_dir(via);
            }
        }
        (Some(g), false) => {
            let _ = g.handle.set_len(0);
        }
        (None, true) => {
            let _ = std::fs::remove_dir_all(temp);
        }
        (None, false) => {
            let _ = std::fs::remove_file(temp);
        }
    }
}

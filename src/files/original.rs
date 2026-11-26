//! DE: Entschlüsseln unter dem Originalnamen aus dem Archiv (#315, zufällige äußere Namen).
//! Datei-Archiv: der eine Eintrag muss ein einzelner, portabler Name sein. Ordner-Archiv: alle
//! Einträge müssen unter **einem** obersten Ordner liegen (so schreibt `encrypt` mit zufälligem
//! Namen). Die Pfadregeln des Archivs gelten weiter; nichts wird überschrieben; veröffentlicht wird
//! erst nach vollständiger Prüfung.
//! EN: Decrypting under the original name from the archive (#315, random outer names). File
//! archive: the one entry must be a single portable name. Directory archive: all entries must lie
//! below **one** top-level directory (this is how `encrypt` writes with a random name). The archive
//! path rules still apply; nothing is overwritten; publishing happens only after full
//! verification.

use std::path::{Path, PathBuf};

use super::decrypt::{fill_dir, first_file, open, write_file};
use super::format::Content;
use super::output::TempOutput;
use super::{Report, Unlock, paths};
use crate::envelope::PublicKeyFile;
use crate::{Error, Result};

/// DE: Wählt aus dem vorgeschlagenen Ziel das tatsächliche (z. B. freien Namen); `None` = keins.
/// EN: Picks the actual target from the proposed one (e.g. a free name); `None` = none.
pub type ChooseTarget<'a> = &'a dyn Fn(&Path) -> Option<PathBuf>;

fn not_restorable() -> Error {
    Error::InvalidInput {
        field: "original_name",
    }
}

/// DE: Entschlüsselt `source` in den Ordner `dir` unter dem im Archiv gespeicherten Namen.
/// `choose` bestimmt das endgültige Ziel (z. B. nummeriert bei `--rename`). Liefert Ziel und
/// Bericht. Signaturprüfung wie [`super::decrypt_with`].
/// EN: Decrypts `source` into the directory `dir` under the name stored in the archive. `choose`
/// determines the final target (e.g. numbered with `--rename`). Returns target and report.
/// Signature check as [`super::decrypt_with`].
///
/// # Errors
/// DE/EN: wie [`super::decrypt_with`] / as [`super::decrypt_with`]; [`Error::InvalidInput`]
/// `original_name` (kein einzelner Originalname im Archiv / no single original name in the
/// archive); [`Error::Io`] `AlreadyExists` (kein freies Ziel / no free target).
pub fn decrypt_original(
    source: &Path,
    dir: &Path,
    unlock: &Unlock<'_>,
    signer: Option<&PublicKeyFile>,
    choose: ChooseTarget<'_>,
) -> Result<(PathBuf, Report)> {
    let (mut archive, content, check) = open(source, unlock, signer)?;
    // DE: Temporärausgaben heißen nach der Quelle. EN: Temporary output is named after the source.
    let base = dir.join(
        source
            .file_name()
            .ok_or(Error::InvalidInput { field: "path" })?,
    );
    let pick =
        |name: &str| choose(&dir.join(name)).ok_or(Error::Io(std::io::ErrorKind::AlreadyExists));
    match content {
        Content::File => {
            let entry = first_file(&mut archive)?;
            let name = entry.path()?.expose()?;
            if paths::validate(name)?.len() != 1 {
                return Err(not_restorable());
            }
            let target = pick(name)?;
            let output = TempOutput::file_near(&base, &target)?;
            let report = write_file(&entry, archive, output, check)?;
            Ok((target, report))
        }
        Content::Directory => {
            let temp = TempOutput::scratch_dir(&base)?;
            let mut root: Option<String> = None;
            let report = fill_dir(archive, temp.path(), check, |path, is_file| {
                single_root(&mut root, path, is_file)
            })?;
            let root = root.ok_or_else(not_restorable)?;
            let target = pick(&root)?;
            temp.publish_child(&root, &target)?;
            Ok((target, report))
        }
    }
}

/// DE: Erster Eintrag = oberster Ordner; alle weiteren müssen darunter liegen.
/// EN: First entry = top-level directory; all others must lie below it.
fn single_root(root: &mut Option<String>, path: &str, is_file: bool) -> Result<()> {
    match root {
        None if !is_file && !path.contains('/') => {
            *root = Some(path.to_owned());
            Ok(())
        }
        Some(r)
            if path
                .strip_prefix(r.as_str())
                .is_some_and(|rest| rest.starts_with('/')) =>
        {
            Ok(())
        }
        _ => Err(not_restorable()),
    }
}

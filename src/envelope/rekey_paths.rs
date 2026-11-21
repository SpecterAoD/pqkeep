//! DE: Enge Pfad-/Handleprüfungen für Rekey, keine Zusage gegen fremde Verzeichnisschreiber.
//! EN: Narrow rekey path/handle checks; no guarantee against hostile directory writers.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use super::{FileWarning, MAX_FILE_BYTES, Overwrite, RekeyOptions, io};
use crate::{Error, Result};

const INVALID: Error = Error::InvalidInput {
    field: "rekey_file",
};

pub(super) struct Targets {
    pub output: PathBuf,
    pub backup: Option<PathBuf>,
    pub in_place: bool,
}

pub(super) fn resolve(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().ok_or(INVALID)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let resolved = fs::canonicalize(parent)?.join(name);
    match fs::symlink_metadata(&resolved) {
        Ok(meta) if !meta.file_type().is_file() => Err(INVALID),
        // DE: Windows-Dateinamen sind nicht case-sensitiv. EN: Windows names are case insensitive.
        #[cfg(windows)]
        Ok(_) => Ok(fs::canonicalize(resolved)?),
        #[cfg(not(windows))]
        Ok(_) => Ok(resolved),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(resolved),
        Err(e) => Err(e.into()),
    }
}

pub(super) fn read(path: &Path) -> Result<(String, Vec<FileWarning>)> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(INVALID);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(INVALID);
    }
    let warnings = io::permission_warnings(&file)?;
    let mut text = String::new();
    file.take((MAX_FILE_BYTES + 1) as u64)
        .read_to_string(&mut text)
        .map_err(|_| INVALID)?;
    if text.len() > MAX_FILE_BYTES {
        return Err(INVALID);
    }
    Ok((text, warnings))
}

pub(super) fn targets(source: &Path, options: &RekeyOptions<'_>) -> Result<Targets> {
    let output = resolve(options.output)?;
    let in_place = source == output;
    if in_place {
        if options.overwrite != Overwrite::Yes {
            return Err(Error::Io(ErrorKind::AlreadyExists));
        }
        if options.backup.is_none() {
            return Err(Error::InvalidInput {
                field: "rekey_backup",
            });
        }
        check_links(source)?;
    } else if fs::symlink_metadata(&output).is_ok() {
        return Err(Error::Io(ErrorKind::AlreadyExists));
    }
    let backup = options.backup.map(resolve).transpose()?;
    if let Some(path) = &backup {
        if path == source || path == &output {
            return Err(Error::InvalidInput {
                field: "rekey_backup",
            });
        }
        if fs::symlink_metadata(path).is_ok() {
            return Err(Error::Io(ErrorKind::AlreadyExists));
        }
    }
    Ok(Targets {
        output,
        backup,
        in_place,
    })
}

#[cfg(unix)]
fn check_links(source: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if fs::symlink_metadata(source)?.nlink() != 1 {
        return Err(INVALID);
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn check_links(_source: &Path) -> Result<()> {
    Ok(())
}

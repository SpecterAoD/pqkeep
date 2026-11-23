//! DE: Gemeinsame vollständige Prüfung für check/list; Besucher bleiben privat und vorläufig.
//! EN: Shared complete check/list validation; visitors are private and provisional.

use std::io::{Read, sink};
use std::path::Path;

use super::archive::{ArchiveReader, Entry};
use super::format::Content;
use super::paths::{self, PathSet};
use super::{Report, Unlock, decrypt};
use crate::envelope::PublicKeyFile;
use crate::{Error, Result};

pub(super) fn read(
    source: &Path,
    unlock: &Unlock<'_>,
    signer: Option<&PublicKeyFile>,
    mut visit: impl FnMut(&Entry) -> Result<()>,
) -> Result<Report> {
    let (archive, content, check) = decrypt::open(source, unlock, signer)?;
    let mut report = match content {
        Content::File => file(archive, &mut visit)?,
        Content::Directory => directory(archive, &mut visit)?,
    };
    decrypt::verify(check, &mut report)?;
    Ok(report)
}

fn file<R: Read>(
    mut archive: ArchiveReader<R>,
    visit: &mut impl FnMut(&Entry) -> Result<()>,
) -> Result<Report> {
    let entry = archive
        .next_entry()?
        .ok_or(Error::InvalidInput { field: "archive" })?;
    if !entry.is_file() {
        return Err(Error::InvalidInput { field: "archive" });
    }
    let size = entry.size();
    visit(&entry)?;
    paths::validate(entry.path()?.expose()?)?;
    archive.copy_file(size, &mut sink())?;
    if archive.next_entry()?.is_some() {
        return Err(Error::InvalidInput { field: "archive" });
    }
    archive.finish()?;
    Ok(Report {
        files: 1,
        bytes: size,
        ..Report::default()
    })
}

fn directory<R: Read>(
    mut archive: ArchiveReader<R>,
    visit: &mut impl FnMut(&Entry) -> Result<()>,
) -> Result<Report> {
    let mut seen = PathSet::default();
    let mut report = Report::default();
    while let Some(entry) = archive.next_entry()? {
        // DE: List-Budget vor PathSet/Kopien prüfen; kein öffentlicher Callback.
        // EN: Check listing budget before PathSet/copies; no public callback.
        visit(&entry)?;
        seen.insert(&paths::validate(entry.path()?.expose()?)?, entry.is_file())?;
        if entry.is_file() {
            archive.copy_file(entry.size(), &mut sink())?;
            report.files += 1;
            report.bytes = report
                .bytes
                .checked_add(entry.size())
                .ok_or(Error::InvalidInput { field: "archive" })?;
        } else {
            report.directories += 1;
        }
    }
    archive.finish()?;
    Ok(report)
}

//! DE: Vor dem Sammeln gesperrte Listen-Datensätze ohne Reallokation.
//! EN: Listing records locked before collection without reallocation.

use super::{ConfidentialText, EntryKind, ListEntry, MAX_LIST_ENTRIES, archive::Entry};
use crate::{Error, Result, crypto::secret_buffer::SecretBuffer};
use std::{fmt, ops::Deref, slice};

/// DE: Vertrauliche Listeneinträge; Ausleihen ist eine bewusste Ausgabegrenze.
/// EN: Confidential listing records; borrowing is an explicit disclosure boundary.
#[derive(Default)]
pub struct ConfidentialEntries(Option<SecretBuffer<ListEntry>>);

impl ConfidentialEntries {
    pub(crate) fn prepare(&mut self) -> Result<()> {
        if self.0.is_none() {
            let mut empty = Vec::new();
            empty
                .try_reserve_exact(MAX_LIST_ENTRIES)
                .map_err(|_| Error::MemoryLock)?;
            self.0 = Some(SecretBuffer::new(empty)?);
        }
        Ok(())
    }

    pub(crate) fn push(&mut self, entry: &Entry) -> Result<()> {
        let path = entry.path()?;
        let arena = self.0.as_mut().ok_or(Error::MemoryLock)?;
        let original = arena.expose().len();
        // DE: Nur öffentliche Leerwerte bewegen; private Felder im gesperrten Slot setzen.
        // EN: Move only public empty values; fill private fields in the locked slot.
        arena.push_preallocated(ListEntry {
            path: ConfidentialText::prepare()?,
            kind: EntryKind::Directory,
            bytes: None,
        })?;
        let slot = &mut arena.expose_mut()[original];
        if let Err(error) = slot.path.copy_from(path) {
            arena.truncate(original);
            return Err(error);
        }
        if entry.is_file() {
            slot.kind = EntryKind::File;
            slot.bytes = Some(entry.size());
        }
        Ok(())
    }
}

impl TryFrom<Vec<ListEntry>> for ConfidentialEntries {
    type Error = Error;

    /// DE: Caller verantwortet seine Quellallokation; ab Übergabe zwingend sperren.
    /// EN: Caller owns source allocation responsibility; locking is mandatory on transfer.
    fn try_from(entries: Vec<ListEntry>) -> Result<Self> {
        if entries.len() > MAX_LIST_ENTRIES {
            return Err(Error::InvalidInput {
                field: "list_limit",
            });
        }
        Ok(Self(Some(SecretBuffer::new(entries)?)))
    }
}

impl Deref for ConfidentialEntries {
    type Target = [ListEntry];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().map_or(&[], SecretBuffer::expose)
    }
}

impl<'a> IntoIterator for &'a ConfidentialEntries {
    type Item = &'a ListEntry;
    type IntoIter = slice::Iter<'a, ListEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl PartialEq for ConfidentialEntries {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}
impl Eq for ConfidentialEntries {}

impl fmt::Debug for ConfidentialEntries {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfidentialEntries([REDACTED])")
    }
}

#[cfg(test)]
#[path = "confidential_entries_tests.rs"]
mod tests;

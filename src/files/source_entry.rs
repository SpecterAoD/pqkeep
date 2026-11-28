//! DE: Retinierte Quelldatensätze vor privaten Feldern stabil sperren.
//! EN: Stably lock retained source records before filling private fields.

use super::{ConfidentialText, native_path::NativePath, paths};
use crate::{Error, Result, crypto::SecretBytes};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Default)]
pub(crate) struct SourceEntry {
    pub(super) rel: Option<ConfidentialText>,
    pub(super) abs: Option<NativePath>,
    directory: bool,
    bytes: u64,
}

impl Zeroize for SourceEntry {
    fn zeroize(&mut self) {
        self.rel = None;
        self.abs = None;
        self.directory.zeroize();
        self.bytes.zeroize();
    }
}
impl Drop for SourceEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for SourceEntry {}

impl SourceEntry {
    // DE: Nur bereits gesperrte Arenaslots befüllen; keine privaten Record-Rückgaben.
    // EN: Populate only prelocked arena slots; no private record return values.
    pub(super) fn fill(
        &mut self,
        rel: &str,
        abs: &Path,
        directory: bool,
        bytes: u64,
    ) -> Result<()> {
        if self.rel.is_some() || self.abs.is_some() {
            return Err(Error::Crypto);
        }
        self.rel = Some(ConfidentialText::from_text(rel)?);
        self.abs = Some(NativePath::from_path(abs)?);
        self.directory = directory;
        self.bytes = bytes;
        Ok(())
    }

    pub(super) fn copy_from(&mut self, source: &Self) -> Result<()> {
        if self.rel.is_some() || self.abs.is_some() {
            return Err(Error::Crypto);
        }
        self.rel = Some(source.rel.as_ref().ok_or(Error::Crypto)?.try_duplicate()?);
        self.abs = Some(source.abs.as_ref().ok_or(Error::Crypto)?.try_duplicate()?);
        self.directory = source.directory;
        self.bytes = source.bytes;
        Ok(())
    }

    pub(super) fn path(&self) -> Result<&str> {
        self.rel.as_ref().ok_or(Error::Crypto)?.expose()
    }
    pub(super) fn path_bytes(&self) -> &[u8] {
        self.rel.as_ref().map_or(&[], ConfidentialText::bytes)
    }
    pub(super) fn is_directory(&self) -> bool {
        self.directory
    }
    pub(super) fn size(&self) -> u64 {
        self.bytes
    }

    pub(super) fn open(&self) -> Result<std::fs::File> {
        super::native_path::open_native(self.abs.as_ref().ok_or(Error::Crypto)?)
    }

    /// DE: Präfix direkt gesperrt zusammensetzen; bisherigen Zustand bei Fehler erhalten.
    /// EN: Assemble the prefix directly in locked storage; preserve old state on error.
    pub(super) fn prepend(&mut self, root: &str) -> Result<()> {
        let original = self.path_bytes();
        let head = root.len().checked_add(1).ok_or(Error::MemoryLock)?;
        let len = head.checked_add(original.len()).ok_or(Error::MemoryLock)?;
        let mut bytes = SecretBytes::zeroed(len)?;
        bytes.expose_mut()[..root.len()].copy_from_slice(root.as_bytes());
        bytes.expose_mut()[root.len()] = b'/';
        bytes.expose_mut()[head..].copy_from_slice(original);
        let rel = ConfidentialText::from_locked(bytes)?;
        paths::validate_only(rel.expose()?)?;
        self.rel = Some(rel);
        Ok(())
    }
}

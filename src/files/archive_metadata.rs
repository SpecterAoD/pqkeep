//! DE: Archiv-Framing und Datensätze vor privater Befüllung sperren.
//! EN: Lock archive framing and records before private population.

use super::{ConfidentialText, bad};
use crate::{Result, crypto::secret_buffer::SecretBuffer};
use std::io::{Read, Write};
use zeroize::Zeroize;

#[derive(Default)]
struct FrameState {
    bytes: [u8; 8],
    count: u64,
}

impl Zeroize for FrameState {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
        self.count.zeroize();
    }
}

pub(super) struct Framing(SecretBuffer<FrameState>);

impl Framing {
    pub(super) fn new() -> Result<Self> {
        Ok(Self(SecretBuffer::new(vec![FrameState::default()])?))
    }

    pub(super) fn read<R: Read>(
        &mut self,
        input: &mut crate::crypto::stream::DecryptReader<R>,
        width: usize,
    ) -> Result<u64> {
        let state = &mut self.0.expose_mut()[0];
        state.bytes.zeroize();
        let bytes = state.bytes.get_mut(..width).ok_or_else(bad)?;
        input.read_exact(bytes)?;
        Ok(bytes
            .iter()
            .enumerate()
            .fold(0, |value, (i, byte)| value | (u64::from(*byte) << (i * 8))))
    }

    pub(super) fn write<W: Write>(
        &mut self,
        output: &mut crate::crypto::stream::EncryptWriter<W>,
        value: u64,
        width: usize,
    ) -> Result<()> {
        let state = &mut self.0.expose_mut()[0];
        state.bytes.zeroize();
        let bytes = state.bytes.get_mut(..width).ok_or_else(bad)?;
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from((value >> (i * 8)) & 0xff).map_err(|_| bad())?;
        }
        output.push(bytes)
    }

    pub(super) fn count(&self) -> u64 {
        self.0.expose()[0].count
    }

    pub(super) fn advance(&mut self, limit: u64) -> Result<()> {
        let count = &mut self.0.expose_mut()[0].count;
        *count = count
            .checked_add(1)
            .filter(|n| *n <= limit)
            .ok_or_else(bad)?;
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct EntryRecord {
    pub(super) kind: u8,
    pub(super) path: Option<ConfidentialText>,
    pub(super) size: u64,
}

impl Zeroize for EntryRecord {
    fn zeroize(&mut self) {
        self.path.take();
        self.kind.zeroize();
        self.size.zeroize();
    }
}

/// DE: Nur der Guard bewegt sich; der private Datensatz bleibt gesperrt.
/// EN: Only the guard moves; the private record stays locked in place.
pub(crate) struct Entry(SecretBuffer<EntryRecord>);

impl Entry {
    pub(super) fn prepare() -> Result<Self> {
        Ok(Self(SecretBuffer::new(vec![EntryRecord::default()])?))
    }

    pub(super) fn record_mut(&mut self) -> &mut EntryRecord {
        &mut self.0.expose_mut()[0]
    }

    pub(crate) fn path(&self) -> Result<&ConfidentialText> {
        self.0.expose()[0].path.as_ref().ok_or_else(bad)
    }

    pub(crate) fn is_file(&self) -> bool {
        self.0.expose()[0].kind == super::TAG_FILE
    }

    pub(crate) fn size(&self) -> u64 {
        self.0.expose()[0].size
    }

    #[cfg(test)]
    pub(crate) fn fixture(path: ConfidentialText, size: Option<u64>) -> Result<Self> {
        let mut entry = Self::prepare()?;
        let record = entry.record_mut();
        record.kind = if size.is_some() {
            super::TAG_FILE
        } else {
            super::TAG_DIR
        };
        record.path = Some(path);
        record.size = size.unwrap_or_default();
        Ok(entry)
    }
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Entry([REDACTED])")
    }
}

#[cfg(test)]
#[path = "archive_metadata_tests.rs"]
mod tests;

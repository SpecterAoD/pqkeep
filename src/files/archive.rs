//! DE: Minimales Archivformat im verschlüsselten Strom. Einträge (Little Endian):
//! Ordner = 1 | Pfadlänge u16 | Pfad;  Datei = 2 | Pfadlänge u16 | Pfad | Größe u64 |
//! Inhalt | SHA3-256(Inhalt);  Ende = 0 | Anzahl Einträge u64.
//! Der Leser prüft Pfadlänge, UTF-8, Anzahl, Prüfsumme und dass nach dem Ende
//! nichts mehr folgt. Pfadregeln selbst prüft `paths`.
//!
//! EN: Minimal archive format inside the encrypted stream (layout above). The
//! reader checks path length, UTF-8, count, checksum and that nothing follows the
//! end marker. Path rules themselves are checked by `paths`.

use std::io::{Read, Write};

use crate::crypto::{SecretBytes, locked_hash::LockedHash};
use sha3::Sha3_256;

use super::ConfidentialText;
use super::paths::{MAX_ENTRIES, MAX_PATH_BYTES};
use crate::crypto::stream::{CHUNK_SIZE, DecryptReader, EncryptWriter};
use crate::{Error, Result};

const TAG_END: u8 = 0;
const TAG_DIR: u8 = 1;
const TAG_FILE: u8 = 2;

#[cfg(test)]
#[path = "archive_locked_tests.rs"]
mod tests;

fn bad() -> Error {
    Error::InvalidInput { field: "archive" }
}

/// DE: Schreibt Einträge verschlüsselt. EN: Writes entries encrypted.
pub(crate) struct ArchiveWriter<W: Write> {
    enc: EncryptWriter<W>,
    count: u64,
}

impl<W: Write> ArchiveWriter<W> {
    pub fn new(enc: EncryptWriter<W>) -> Self {
        Self { enc, count: 0 }
    }

    fn entry_head(&mut self, tag: u8, path: &str) -> Result<()> {
        let len = u16::try_from(path.len()).map_err(|_| Error::InvalidInput { field: "path" })?;
        self.enc.push(&[tag])?;
        self.enc.push(&len.to_le_bytes())?;
        self.enc.push(path.as_bytes())?;
        self.count += 1;
        Ok(())
    }

    pub fn dir(&mut self, path: &str) -> Result<()> {
        self.entry_head(TAG_DIR, path)
    }

    /// DE: Schreibt genau `size` Bytes aus `reader`; ändert sich die Quelle während
    /// des Lesens, wird abgebrochen. EN: Writes exactly `size` bytes from `reader`;
    /// aborts if the source changes while being read.
    pub fn file(&mut self, path: &str, reader: &mut impl Read, size: u64) -> Result<()> {
        self.entry_head(TAG_FILE, path)?;
        self.enc.push(&size.to_le_bytes())?;
        let mut hasher = LockedHash::<Sha3_256>::new()?;
        let mut buf = SecretBytes::zeroed(CHUNK_SIZE)?;
        let mut left = size;
        while left > 0 {
            let want = usize::try_from(left.min(CHUNK_SIZE as u64)).unwrap_or(CHUNK_SIZE);
            let n = reader.read(&mut buf.expose_mut()[..want])?;
            if n == 0 {
                return Err(Error::InvalidInput {
                    field: "source_changed",
                });
            }
            hasher.update(&buf.expose()[..n]);
            self.enc.push(&buf.expose()[..n])?;
            left -= n as u64;
        }
        if reader.read(&mut buf.expose_mut()[..1])? != 0 {
            return Err(Error::InvalidInput {
                field: "source_changed",
            });
        }
        self.enc.push(hasher.finalize()?.expose())?;
        Ok(())
    }

    pub fn finish(mut self) -> Result<W> {
        self.enc.push(&[TAG_END])?;
        self.enc.push(&self.count.to_le_bytes())?;
        Ok(self.enc.finish()?.0)
    }
}

/// DE: Eintrag im Archiv. EN: Archive entry.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    Dir(ConfidentialText),
    File(ConfidentialText, u64),
}

/// DE: Liest Einträge und prüft Inhalte. EN: Reads entries and verifies contents.
pub(crate) struct ArchiveReader<R: Read> {
    dec: DecryptReader<R>,
    count: u64,
}

impl<R: Read> ArchiveReader<R> {
    pub fn new(dec: DecryptReader<R>) -> Self {
        Self { dec, count: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        self.dec.read_exact(&mut out)?;
        Ok(out)
    }

    /// DE: Nächster Eintrag; `None` nach geprüftem Ende. EN: Next entry; `None` after a verified end.
    pub fn next_entry(&mut self) -> Result<Option<Entry>> {
        let [tag] = self.array::<1>()?;
        if tag == TAG_END {
            if u64::from_le_bytes(self.array()?) != self.count {
                return Err(bad());
            }
            return Ok(None);
        }
        if tag != TAG_DIR && tag != TAG_FILE {
            return Err(bad());
        }
        self.count += 1;
        if self.count > MAX_ENTRIES {
            return Err(bad());
        }
        let len = usize::from(u16::from_le_bytes(self.array()?));
        if len == 0 || len > MAX_PATH_BYTES {
            return Err(bad());
        }
        let mut raw = SecretBytes::zeroed(len)?;
        self.dec.read_exact(raw.expose_mut())?;
        let path = ConfidentialText::from_locked(raw)?;
        Ok(Some(if tag == TAG_DIR {
            Entry::Dir(path)
        } else {
            Entry::File(path, u64::from_le_bytes(self.array()?))
        }))
    }

    /// DE: Kopiert den Inhalt der aktuellen Datei und prüft die Prüfsumme.
    /// EN: Copies the current file's content and verifies the checksum.
    pub fn copy_file(&mut self, size: u64, out: &mut impl Write) -> Result<()> {
        let mut hasher = LockedHash::<Sha3_256>::new()?;
        let mut buf = SecretBytes::zeroed(CHUNK_SIZE)?;
        let mut left = size;
        while left > 0 {
            let want = usize::try_from(left.min(CHUNK_SIZE as u64)).unwrap_or(CHUNK_SIZE);
            self.dec.read_exact(&mut buf.expose_mut()[..want])?;
            hasher.update(&buf.expose()[..want]);
            out.write_all(&buf.expose()[..want])?;
            left -= want as u64;
        }
        let mut expected = SecretBytes::zeroed(32)?;
        self.dec.read_exact(expected.expose_mut())?;
        if hasher.finalize()?.expose() == expected.expose() {
            Ok(())
        } else {
            Err(Error::InvalidInput { field: "checksum" })
        }
    }

    /// DE: Bestätigt das Stromende (nichts mehr nach dem Ende-Eintrag).
    /// EN: Confirms the end of the stream (nothing after the end entry).
    pub fn finish(self) -> Result<()> {
        self.dec.finish()
    }
}

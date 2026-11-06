//! DE: Schreib-/Leseschnittstelle für den STREAM-Modus (siehe `stream`): ein
//! verschlüsselnder Schreiber und ein entschlüsselnder Leser, die nur geprüften
//! Klartext herausgeben. Eigene Fehlertypen statt `std::io`, damit
//! [`Error::Decrypt`] erhalten bleibt.
//!
//! EN: Write/read interface for STREAM mode (see `stream`): an encrypting writer
//! and a decrypting reader that only releases verified plaintext. Own error
//! types instead of `std::io` so that [`Error::Decrypt`] is preserved.

use std::io::{Read, Write};

use zeroize::Zeroizing;

use crate::crypto::aead::TAG_LEN;
use crate::crypto::stream::{CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE, PREFIX_LEN, Stream, read_full};
use crate::{Error, Result};

/// DE: Verschlüsselnder Schreiber: puffert bis zu einem Block; ein voller Block
/// wird erst versiegelt, wenn weitere Daten folgen. `finish` versiegelt den Rest
/// als letzten Block (auch leer).
/// EN: Encrypting writer: buffers up to one chunk; a full chunk is sealed only once
/// more data follows. `finish` seals the remainder as the last chunk (even empty).
pub struct EncryptWriter<W: Write> {
    stream: Stream,
    inner: W,
    buf: Zeroizing<Vec<u8>>,
    total: u64,
}

impl<W: Write> EncryptWriter<W> {
    /// DE: Neuer Schreiber. EN: New writer.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (Schlüssel / key).
    pub fn new(key: &[u8], prefix: [u8; PREFIX_LEN], aad: &[u8], inner: W) -> Result<Self> {
        Ok(Self {
            stream: Stream::new(key, prefix, aad)?,
            inner,
            buf: Zeroizing::new(Vec::with_capacity(CHUNK_SIZE)),
            total: 0,
        })
    }

    /// DE: Nimmt Klartext auf. EN: Accepts plaintext.
    ///
    /// # Errors
    /// DE/EN: [`Error::Io`], [`Error::Crypto`].
    pub fn push(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            if self.buf.len() == CHUNK_SIZE {
                let sealed = self.stream.seal(&self.buf, false)?;
                self.inner.write_all(&sealed)?;
                self.buf.clear();
            }
            let take = (CHUNK_SIZE - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            self.total += take as u64;
            data = &data[take..];
        }
        Ok(())
    }

    /// DE: Schließt ab; liefert den inneren Schreiber und die Klartextlänge.
    /// EN: Finishes; returns the inner writer and the plaintext length.
    ///
    /// # Errors
    /// DE/EN: [`Error::Io`], [`Error::Crypto`].
    pub fn finish(mut self) -> Result<(W, u64)> {
        let sealed = self.stream.seal(&self.buf, true)?;
        self.inner.write_all(&sealed)?;
        self.inner.flush()?;
        Ok((self.inner, self.total))
    }
}

/// DE: Entschlüsselnder Leser: gibt nur Klartext aus vollständig geprüften Blöcken
/// heraus. Erst `finish` bestätigt, dass der Strom korrekt endete.
/// EN: Decrypting reader: only releases plaintext from fully verified chunks.
/// Only `finish` confirms that the stream ended correctly.
pub struct DecryptReader<R: Read> {
    stream: Stream,
    inner: R,
    plain: Zeroizing<Vec<u8>>,
    pos: usize,
    pending: Vec<u8>,
    pending_len: usize,
    done: bool,
}

impl<R: Read> DecryptReader<R> {
    /// DE: Neuer Leser; liest den ersten Block vor. EN: New reader; pre-reads the first chunk.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (Schlüssel / key), [`Error::Io`].
    pub fn new(key: &[u8], prefix: [u8; PREFIX_LEN], aad: &[u8], mut inner: R) -> Result<Self> {
        let mut pending = vec![0u8; ENCRYPTED_CHUNK_SIZE];
        let pending_len = read_full(&mut inner, &mut pending)?;
        Ok(Self {
            stream: Stream::new(key, prefix, aad)?,
            inner,
            plain: Zeroizing::new(Vec::new()),
            pos: 0,
            pending,
            pending_len,
            done: false,
        })
    }

    fn refill(&mut self) -> Result<()> {
        if self.pending_len < TAG_LEN {
            return Err(Error::Decrypt);
        }
        let mut next = vec![0u8; ENCRYPTED_CHUNK_SIZE];
        let next_len = if self.pending_len == ENCRYPTED_CHUNK_SIZE {
            read_full(&mut self.inner, &mut next)?
        } else {
            0
        };
        let last = next_len == 0;
        self.plain = self.stream.open(&self.pending[..self.pending_len], last)?;
        self.pos = 0;
        self.pending = next;
        self.pending_len = next_len;
        self.done = last;
        Ok(())
    }

    /// DE: Liest bis zu `buf.len()` Bytes; 0 = Ende des Klartexts.
    /// EN: Reads up to `buf.len()` bytes; 0 = end of plaintext.
    ///
    /// # Errors
    /// DE/EN: [`Error::Decrypt`], [`Error::Io`].
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        while self.pos == self.plain.len() {
            if self.done {
                return Ok(0);
            }
            self.refill()?;
        }
        let n = buf.len().min(self.plain.len() - self.pos);
        buf[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }

    /// DE: Liest genau `buf.len()` Bytes. EN: Reads exactly `buf.len()` bytes.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (`archive`, zu früh zu Ende / ended early),
    /// [`Error::Decrypt`], [`Error::Io`].
    pub fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            let n = self.read(buf)?;
            if n == 0 {
                return Err(Error::InvalidInput { field: "archive" });
            }
            buf = &mut buf[n..];
        }
        Ok(())
    }

    /// DE: Bestätigt, dass kein Klartext übrig ist und der letzte Block gelesen wurde.
    /// EN: Confirms no plaintext is left and the last chunk has been read.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (Restdaten / trailing data), [`Error::Decrypt`].
    pub fn finish(mut self) -> Result<()> {
        let mut probe = [0u8; 1];
        if self.read(&mut probe)? == 0 {
            Ok(())
        } else {
            Err(Error::InvalidInput { field: "archive" })
        }
    }
}

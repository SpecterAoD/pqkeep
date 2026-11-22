//! DE: Streaming-AEAD nach der STREAM-Konstruktion (Hoang, Reyhanitabar, Rogaway,
//! Vizár; wie in age/Tink) mit AES-256-GCM. Blöcke à 64 KiB; Nonce = 7 Byte
//! Zufallspräfix ‖ 4 Byte Blockzähler (Big Endian) ‖ 1 Byte Endmarke. Jeder Block
//! trägt dieselbe AAD (z. B. Hash des Headers). Erkennt Kippen, Vertauschen,
//! Entfernen, Abschneiden und Anhängen von Blöcken; Speicherbedarf konstant.
//! Der Schlüssel muss pro Datei neu und zufällig sein.
//!
//! EN: Streaming AEAD following the STREAM construction (Hoang, Reyhanitabar,
//! Rogaway, Vizár; as in age/Tink) with AES-256-GCM. 64 KiB chunks; nonce =
//! 7-byte random prefix ‖ 4-byte chunk counter (big endian) ‖ 1-byte last flag.
//! Every chunk carries the same AAD (e.g. header hash). Detects flipped, swapped,
//! removed, truncated and appended chunks; constant memory. The key must be fresh
//! and random per file.

use std::io::{Read, Write};

use super::{SecretBytes, secret_state::SecretState};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, AeadInOut, Nonce, Payload};

use crate::crypto::aead::TAG_LEN;
pub use crate::crypto::stream_io::{DecryptReader, EncryptWriter};
use crate::{Error, Result};

/// DE: Klartext-Blockgröße. EN: Plaintext chunk size.
pub const CHUNK_SIZE: usize = 64 * 1024;
/// DE: Länge des Nonce-Präfixes. EN: Length of the nonce prefix.
pub const PREFIX_LEN: usize = 7;
/// DE: Größe eines vollen verschlüsselten Blocks. EN: Size of a full encrypted chunk.
pub const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_LEN;

/// DE: Gemeinsamer Zustand für Ver- und Entschlüsseln. EN: Shared state for both directions.
pub(crate) struct Stream {
    cipher: SecretState<Aes256Gcm>,
    prefix: [u8; PREFIX_LEN],
    counter: u32,
    aad: Vec<u8>,
}

impl Stream {
    pub(crate) fn new(key: &[u8], prefix: [u8; PREFIX_LEN], aad: &[u8]) -> Result<Self> {
        let cipher = super::aead::cipher(key)?;
        Ok(Self {
            cipher,
            prefix,
            counter: 0,
            aad: aad.to_vec(),
        })
    }

    fn nonce(&self, last: bool) -> Nonce<Aes256Gcm> {
        let mut n = [0u8; 12];
        n[..PREFIX_LEN].copy_from_slice(&self.prefix);
        n[PREFIX_LEN..11].copy_from_slice(&self.counter.to_be_bytes());
        n[11] = u8::from(last);
        Nonce::<Aes256Gcm>::from(n)
    }

    fn advance(&mut self) -> Result<()> {
        // DE: 2^32 Blöcke (256 TiB) sind die Obergrenze. EN: 2^32 chunks (256 TiB) are the limit.
        self.counter = self.counter.checked_add(1).ok_or(Error::Crypto)?;
        Ok(())
    }

    pub(crate) fn seal(&mut self, chunk: &[u8], last: bool) -> Result<Vec<u8>> {
        let payload = Payload {
            msg: chunk,
            aad: &self.aad,
        };
        let out = self
            .cipher
            .get()
            .encrypt(&self.nonce(last), payload)
            .map_err(|_| Error::Crypto)?;
        self.advance()?;
        Ok(out)
    }

    pub(crate) fn open(&mut self, chunk: &[u8], last: bool) -> Result<SecretBytes> {
        let n = chunk.len().checked_sub(TAG_LEN).ok_or(Error::Decrypt)?;
        let mut out = SecretBytes::from_slice(&chunk[..n])?;
        let tag = <[u8; TAG_LEN]>::try_from(&chunk[n..]).map_err(|_| Error::Decrypt)?;
        self.cipher
            .get()
            .decrypt_inout_detached(
                &self.nonce(last),
                &self.aad,
                out.expose_mut().into(),
                &tag.into(),
            )
            .map_err(|_| Error::Decrypt)?;
        self.advance()?;
        Ok(out)
    }
}

/// DE: Liest so viel wie möglich bis `buf` voll ist; liefert die gelesene Länge.
/// EN: Reads as much as possible until `buf` is full; returns the length read.
pub(crate) fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(filled)
}

/// DE: Verschlüsselt `reader` vollständig nach `writer`; liefert die Klartextlänge.
/// Ein leerer Eingang ergibt genau einen (leeren) Endblock.
/// EN: Encrypts `reader` completely into `writer`; returns the plaintext length.
/// Empty input yields exactly one (empty) final chunk.
///
/// # Errors
/// DE/EN: [`Error::Io`], [`Error::InvalidInput`] (Schlüssel / key), [`Error::Crypto`].
pub fn encrypt(
    key: &[u8],
    prefix: [u8; PREFIX_LEN],
    aad: &[u8],
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<u64> {
    let mut enc = EncryptWriter::new(key, prefix, aad, writer)?;
    let mut buf = SecretBytes::zeroed(CHUNK_SIZE)?;
    loop {
        let n = read_full(reader, buf.expose_mut())?;
        if n == 0 {
            break;
        }
        enc.push(&buf.expose()[..n])?;
    }
    Ok(enc.finish()?.1)
}

/// DE: Entschlüsselt `reader` nach `writer`; liefert die Klartextlänge. Bei einem
/// Fehler kann bereits Klartext geschrieben sein – der Aufrufer schreibt deshalb
/// in eine Temporärdatei und veröffentlicht erst nach Erfolg.
/// EN: Decrypts `reader` into `writer`; returns the plaintext length. On error some
/// plaintext may already have been written – the caller therefore writes to a
/// temporary file and publishes only on success.
///
/// # Errors
/// DE/EN: [`Error::Decrypt`] bei jeder Manipulation / on any tampering, [`Error::Io`].
pub fn decrypt(
    key: &[u8],
    prefix: [u8; PREFIX_LEN],
    aad: &[u8],
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<u64> {
    let mut dec = DecryptReader::new(key, prefix, aad, reader)?;
    let mut buf = SecretBytes::zeroed(CHUNK_SIZE)?;
    let mut total = 0u64;
    loop {
        let n = dec.read(buf.expose_mut())?;
        if n == 0 {
            return Ok(total);
        }
        writer.write_all(&buf.expose()[..n])?;
        total += n as u64;
    }
}

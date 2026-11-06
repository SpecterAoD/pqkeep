//! DE: Binärer Header verschlüsselter Dateien (`.pqkf`). Aufbau (Little Endian):
//! Magic „PQKFENC\0“ | Version u16 | Inhalt u8 (1 Datei, 2 Ordner) | Modus u8
//! (1 Passphrase, 2 Empfänger) | Blockgröße u32 | Nonce-Präfix 7 B | Modusdaten |
//! Wrap-Nonce 12 B | eingepackter Schlüssel 48 B.
//! Modusdaten: Passphrase = m u32, t u32, p u32, Salt-Länge u8, Salt;
//! Empfänger = KEM-Algorithmus u8, Empfänger-ID 32 B, KEM-Chiffrat-Länge u16, Chiffrat.
//! Strenger Parser: feste Werte, exakte Längen, KDF-Grenzen.
//!
//! EN: Binary header of encrypted files (`.pqkf`), layout (little endian) as
//! above. Strict parser: fixed values, exact lengths, KDF bounds.

use std::io::Read;

use sha3::{Digest, Sha3_256};

use crate::crypto::KemAlgorithm;
use crate::crypto::aead::NONCE_LEN;
use crate::crypto::kdf::{KdfParams, MAX_SALT_LEN, MIN_SALT_LEN};
use crate::crypto::stream::{CHUNK_SIZE, PREFIX_LEN};
use crate::crypto::wrap::{RecipientWrap, WRAPPED_LEN, Wrapped};
use crate::envelope::KEY_ID_LEN;
use crate::{Error, Result};

/// DE: Kennung. EN: Magic.
pub const MAGIC: &[u8; 8] = b"PQKFENC\0";
/// DE: Formatversion. EN: Format version.
pub const VERSION: u16 = 1;

/// DE: Inhaltstyp. EN: Content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content {
    /// DE: Einzeldatei. EN: Single file.
    File,
    /// DE: Ordner. EN: Directory.
    Directory,
}

/// DE: Schutzart mit ihren öffentlichen Parametern. EN: Protection with its public parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderMode {
    /// DE: Passphrase (Argon2id). EN: Passphrase (Argon2id).
    Passphrase {
        /// DE: KDF-Parameter. EN: KDF parameters.
        params: KdfParams,
        /// DE: Salt. EN: Salt.
        salt: Vec<u8>,
    },
    /// DE: ML-KEM-Empfänger. EN: ML-KEM recipient.
    Recipient {
        /// DE: Parametersatz. EN: Parameter set.
        algorithm: KemAlgorithm,
        /// DE: Schlüssel-ID des Empfängers. EN: Recipient key ID.
        recipient_id: [u8; KEY_ID_LEN],
        /// DE: KEM-Chiffrat. EN: KEM ciphertext.
        kem_ciphertext: Vec<u8>,
    },
}

/// DE: Vollständiger Header. EN: Complete header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    /// DE: Inhalt. EN: Content.
    pub content: Content,
    /// DE: Nonce-Präfix des Stroms. EN: Stream nonce prefix.
    pub prefix: [u8; PREFIX_LEN],
    /// DE: Schutzart. EN: Protection.
    pub mode: HeaderMode,
    /// DE: Eingepackter Dateischlüssel. EN: Wrapped file key.
    pub wrapped: Wrapped,
}

fn kem_code(a: KemAlgorithm) -> u8 {
    match a {
        KemAlgorithm::MlKem512 => 1,
        KemAlgorithm::MlKem768 => 2,
        KemAlgorithm::MlKem1024 => 3,
    }
}

fn kem_from_code(code: u8) -> Result<(KemAlgorithm, usize)> {
    match code {
        1 => Ok((KemAlgorithm::MlKem512, 768)),
        2 => Ok((KemAlgorithm::MlKem768, 1088)),
        3 => Ok((KemAlgorithm::MlKem1024, 1568)),
        _ => Err(Error::Unsupported),
    }
}

impl FileHeader {
    /// DE: Bytes vor Wrap-Daten und KEM-Chiffrat = AAD des eingepackten Schlüssels.
    /// EN: Bytes before wrap data and KEM ciphertext = AAD of the wrapped key.
    #[must_use]
    pub fn wrap_aad(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.push(match self.content {
            Content::File => 1,
            Content::Directory => 2,
        });
        match &self.mode {
            HeaderMode::Passphrase { .. } => out.push(1),
            HeaderMode::Recipient { .. } => out.push(2),
        }
        out.extend_from_slice(&u32::try_from(CHUNK_SIZE).unwrap_or(u32::MAX).to_le_bytes());
        out.extend_from_slice(&self.prefix);
        match &self.mode {
            HeaderMode::Passphrase { params, salt } => {
                for v in [params.memory_kib, params.iterations, params.parallelism] {
                    out.extend_from_slice(&v.to_le_bytes());
                }
                out.push(u8::try_from(salt.len()).unwrap_or(u8::MAX));
                out.extend_from_slice(salt);
            }
            HeaderMode::Recipient {
                algorithm,
                recipient_id,
                ..
            } => {
                out.push(kem_code(*algorithm));
                out.extend_from_slice(recipient_id);
            }
        }
        out
    }

    /// DE: Vollständige Kodierung. EN: Complete encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.wrap_aad();
        if let HeaderMode::Recipient { kem_ciphertext, .. } = &self.mode {
            out.extend_from_slice(
                &u16::try_from(kem_ciphertext.len())
                    .unwrap_or(0)
                    .to_le_bytes(),
            );
            out.extend_from_slice(kem_ciphertext);
        }
        out.extend_from_slice(&self.wrapped.nonce);
        out.extend_from_slice(&self.wrapped.ciphertext);
        out
    }

    /// DE: AAD aller Stromblöcke = SHA3-256 des gesamten Headers.
    /// EN: AAD of all stream chunks = SHA3-256 of the complete header.
    #[must_use]
    pub fn stream_aad(&self) -> Vec<u8> {
        Sha3_256::digest(self.encode()).to_vec()
    }

    /// DE: Empfänger-Daten für `wrap::unwrap_for_recipient`. EN: Recipient data for unwrapping.
    #[must_use]
    pub fn recipient_wrap(&self) -> Option<RecipientWrap> {
        match &self.mode {
            HeaderMode::Recipient { kem_ciphertext, .. } => Some(RecipientWrap {
                kem_ciphertext: kem_ciphertext.clone(),
                wrapped: self.wrapped.clone(),
            }),
            HeaderMode::Passphrase { .. } => None,
        }
    }

    /// DE: Liest und prüft den Header streng. EN: Reads and validates the header strictly.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (Feld `header`), [`Error::Unsupported`],
    /// [`Error::KdfParams`], [`Error::Io`].
    pub fn read(reader: &mut impl Read) -> Result<Self> {
        let mut r = Reader { inner: reader };
        if &r.array::<8>()? != MAGIC {
            return Err(bad());
        }
        if u16::from_le_bytes(r.array()?) != VERSION {
            return Err(Error::Unsupported);
        }
        let content = match r.byte()? {
            1 => Content::File,
            2 => Content::Directory,
            _ => return Err(bad()),
        };
        let mode_code = r.byte()?;
        if u32::from_le_bytes(r.array()?) != u32::try_from(CHUNK_SIZE).unwrap_or(0) {
            return Err(bad());
        }
        let prefix = r.array::<PREFIX_LEN>()?;
        let mode = match mode_code {
            1 => read_passphrase_mode(&mut r)?,
            2 => read_recipient_mode(&mut r)?,
            _ => return Err(bad()),
        };
        let nonce = r.array::<NONCE_LEN>()?;
        let ciphertext = r.bytes(WRAPPED_LEN)?;
        Ok(Self {
            content,
            prefix,
            mode,
            wrapped: Wrapped { nonce, ciphertext },
        })
    }
}

fn bad() -> Error {
    Error::InvalidInput { field: "header" }
}

fn read_passphrase_mode(r: &mut Reader<'_, impl Read>) -> Result<HeaderMode> {
    let params = KdfParams {
        memory_kib: u32::from_le_bytes(r.array()?),
        iterations: u32::from_le_bytes(r.array()?),
        parallelism: u32::from_le_bytes(r.array()?),
    };
    params.validate()?;
    let salt_len = usize::from(r.byte()?);
    if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt_len) {
        return Err(bad());
    }
    Ok(HeaderMode::Passphrase {
        params,
        salt: r.bytes(salt_len)?,
    })
}

fn read_recipient_mode(r: &mut Reader<'_, impl Read>) -> Result<HeaderMode> {
    let (algorithm, ct_len) = kem_from_code(r.byte()?)?;
    let recipient_id = r.array::<KEY_ID_LEN>()?;
    if usize::from(u16::from_le_bytes(r.array()?)) != ct_len {
        return Err(bad());
    }
    Ok(HeaderMode::Recipient {
        algorithm,
        recipient_id,
        kem_ciphertext: r.bytes(ct_len)?,
    })
}

struct Reader<'a, R: Read> {
    inner: &'a mut R,
}

impl<R: Read> Reader<'_, R> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        self.inner.read_exact(&mut out).map_err(|_| bad())?;
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; len];
        self.inner.read_exact(&mut out).map_err(|_| bad())?;
        Ok(out)
    }
}

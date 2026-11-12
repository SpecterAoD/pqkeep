//! DE: Binärer Header des Dateiformats v2 (`docs/V2_DRAFT.md`): mehrere Zugänge zu einem
//! Dateischlüssel. Bytegenau wie die Referenz `scripts/v2_reference.py` (Little Endian):
//!
//! ```text
//! M  = "PQKFENC\0" ‖ U16(2) ‖ U8(inhalt 1/2) ‖ U32(65536) ‖ nonce_prefix[7] ‖ U8(n) ‖ zugang_1..n
//! Passphrase-Zugang = U8(1) ‖ U8(faktor 0/1) ‖ U32(m) U32(t) U32(p) ‖ U8(len S) ‖ S ‖ nonce[12]
//! Empfänger-Zugang  = U8(2) ‖ U8(kem 1/2/3) ‖ ID[32] ‖ KEM-Chiffrat (768/1088/1568) ‖ nonce[12]
//! H  = M ‖ hülle_1..n (je 48 Byte)
//! WrapAAD(i) = D ‖ "aad/wrap\0" ‖ U32(len M) ‖ M ‖ U8(i)        Strom-AAD = SHA3-256(H)
//! ```
//!
//! Regeln: 1–65 Zugänge; höchstens ein Passphrase-Zugang, nur an erster Stelle; höchstens 64
//! Empfänger mit streng aufsteigender ID; Typ 3/4 (TPM/FIDO2, reserviert) und unbekannte Typen
//! sind „nicht unterstützt“. Strenger Parser: feste Werte, exakte Längen, KDF-Grenzen, nur
//! Puffer fester Größe. Dieses Modul kodiert und prüft nur; es ver- und entschlüsselt nichts.
//!
//! EN: Binary header of file format v2 (`docs/V2_DRAFT.md`): several access slots for one file
//! key. Byte-exact like the reference `scripts/v2_reference.py` (little endian), layout above.
//! Rules: 1–65 slots; at most one passphrase slot, first only; at most 64 recipients with
//! strictly ascending IDs; types 3/4 (TPM/FIDO2, reserved) and unknown types are "unsupported".
//! Strict parser: fixed values, exact lengths, KDF bounds, fixed-size buffers only. This module
//! only encodes and validates; it does not encrypt or decrypt anything.

use std::io::Read;

use sha3::{Digest, Sha3_256};

use super::format::{Content, MAGIC, Reader, bad};
pub use super::slot_v2::{MAX_RECIPIENTS, MAX_SLOTS, Slot, check_slots};
use crate::crypto::aead::NONCE_LEN;
use crate::crypto::kdf::MAX_SALT_LEN;
use crate::crypto::stream::{CHUNK_SIZE, PREFIX_LEN};
use crate::crypto::v2::{Domain, RECIPIENT_ID_LEN};
use crate::crypto::wrap::WRAPPED_LEN;
use crate::{Error, Result};

/// DE: Formatversion. EN: Format version.
pub const VERSION: u16 = 2;
/// DE: Obergrenze des gesamten Headers in Bytes (256 KiB). EN: Upper bound of the whole header.
pub const HEADER_LIMIT: usize = 262_144;

/// DE: Länge von M vor den Zugängen. EN: Length of M before the slots.
const FIXED_LEN: usize = MAGIC.len() + 2 + 1 + 4 + PREFIX_LEN + 1;

/// DE: Größter Header, den die Regeln zulassen (ein Passphrase-Zugang mit längstem Salt, 64 ×
/// ML-KEM-1024, 65 Hüllen). Liegt weit unter [`HEADER_LIMIT`]; der Parser kann die Grenze daher
/// nicht überschreiten und braucht keine Längenfelder aus der Datei.
/// EN: Largest header the rules allow (one passphrase slot with the longest salt, 64 ×
/// ML-KEM-1024, 65 wraps). Far below [`HEADER_LIMIT`]; the parser therefore cannot exceed the
/// limit and needs no length fields from the file.
pub const MAX_ENCODED_LEN: usize = FIXED_LEN
    + (2 + 12 + 1 + MAX_SALT_LEN + NONCE_LEN)
    + MAX_RECIPIENTS * (2 + RECIPIENT_ID_LEN + 1568 + NONCE_LEN)
    + MAX_SLOTS * WRAPPED_LEN;
const _: () = assert!(MAX_ENCODED_LEN <= HEADER_LIMIT);

/// DE: AAD der Hülle `index` (ab 0): Domäne, ganzes `M`, Index. Vertauschen oder Entfernen
/// eines Zugangs ändert die AAD jeder Hülle.
/// EN: AAD of wrap `index` (from 0): domain, complete `M`, index. Swapping or removing a slot
/// changes the AAD of every wrap.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] (Feld `header`) bei Index > 64 oder zu großem `M`.
pub fn wrap_aad(domain: Domain, metadata: &[u8], index: usize) -> Result<Vec<u8>> {
    if index > MAX_RECIPIENTS || metadata.len() > HEADER_LIMIT {
        return Err(bad());
    }
    let len = u32::try_from(metadata.len()).map_err(|_| bad())?;
    let mut out = [domain.tag(), b"aad/wrap\0", &len.to_le_bytes(), metadata].concat();
    out.push(u8::try_from(index).map_err(|_| bad())?);
    Ok(out)
}

/// DE: Vollständiger Header v2. EN: Complete v2 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderV2 {
    /// DE: Inhalt. EN: Content.
    pub content: Content,
    /// DE: Nonce-Präfix des Stroms. EN: Stream nonce prefix.
    pub prefix: [u8; PREFIX_LEN],
    /// DE: Zugänge in Dateireihenfolge. EN: Slots in file order.
    pub slots: Vec<Slot>,
    /// DE: Je Zugang der eingepackte Dateischlüssel (Chiffrat + Tag).
    /// EN: Per slot the wrapped file key (ciphertext + tag).
    pub wraps: Vec<[u8; WRAPPED_LEN]>,
}

impl HeaderV2 {
    /// DE: `M` = Header ohne Hüllen; prüft alle Regeln. EN: `M` = header without wraps; checks all rules.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (Feld `header`), [`Error::KdfParams`], [`Error::Unsupported`].
    pub fn metadata(&self) -> Result<Vec<u8>> {
        check_slots(&self.slots)?;
        let mut out = Vec::with_capacity(FIXED_LEN);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.push(match self.content {
            Content::File => 1,
            Content::Directory => 2,
        });
        out.extend_from_slice(&u32::try_from(CHUNK_SIZE).unwrap_or(u32::MAX).to_le_bytes());
        out.extend_from_slice(&self.prefix);
        out.push(u8::try_from(self.slots.len()).map_err(|_| bad())?);
        for slot in &self.slots {
            out.extend_from_slice(&slot.encode()?);
        }
        Ok(out)
    }

    /// DE: `H` = `M` und alle Hüllen; es muss genau eine Hülle je Zugang geben.
    /// EN: `H` = `M` and all wraps; there must be exactly one wrap per slot.
    ///
    /// # Errors
    /// DE/EN: wie [`Self::metadata`] / as [`Self::metadata`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.wraps.len() != self.slots.len() {
            return Err(bad());
        }
        let mut out = self.metadata()?;
        for wrap in &self.wraps {
            out.extend_from_slice(wrap);
        }
        Ok(out)
    }

    /// DE: AAD der Hülle `index` für Dateien. EN: AAD of wrap `index` for files.
    ///
    /// # Errors
    /// DE/EN: wie [`Self::metadata`]; Index ohne Zugang / index without slot.
    pub fn wrap_aad(&self, index: usize) -> Result<Vec<u8>> {
        if index >= self.slots.len() {
            return Err(bad());
        }
        wrap_aad(Domain::File, &self.metadata()?, index)
    }

    /// DE: AAD aller Stromblöcke = SHA3-256 des ganzen Headers samt aller Hüllen.
    /// EN: AAD of all stream chunks = SHA3-256 of the complete header including all wraps.
    ///
    /// # Errors
    /// DE/EN: wie [`Self::encode`] / as [`Self::encode`].
    pub fn stream_aad(&self) -> Result<Vec<u8>> {
        Ok(Sha3_256::digest(self.encode()?).to_vec())
    }

    /// DE: Liest und prüft den Header streng; liest nie mehr als [`MAX_ENCODED_LEN`] Bytes.
    /// EN: Reads and validates the header strictly; never reads more than [`MAX_ENCODED_LEN`] bytes.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] (Feld `header`), [`Error::Unsupported`] (Version,
    /// Zugangstyp, KEM), [`Error::KdfParams`].
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
        if u32::from_le_bytes(r.array()?) != u32::try_from(CHUNK_SIZE).unwrap_or(0) {
            return Err(bad());
        }
        let prefix = r.array::<PREFIX_LEN>()?;
        let count = usize::from(r.byte()?);
        if count == 0 || count > MAX_SLOTS {
            return Err(bad());
        }
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            slots.push(Slot::read(&mut r)?);
            check_slots(&slots)?;
        }
        let mut wraps = Vec::with_capacity(count);
        for _ in 0..count {
            wraps.push(r.array::<WRAPPED_LEN>()?);
        }
        Ok(Self {
            content,
            prefix,
            slots,
            wraps,
        })
    }
}

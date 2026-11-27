//! DE: Lesen und Schreiben der Absender-Signatur (Format v3, `docs/V3_SIGNED.md`, #44). Beim
//! Verschlüsseln hasht [`HashingWriter`] das Chiffrat `C`, danach wird `Σ` angehängt. Beim Lesen
//! liefert [`SignedBody`] genau `C` (Länge aus der Dateigröße), hasht es und liest am Ende `Σ`
//! samt Prüfung auf Dateiende; [`SignatureCheck::verify`] prüft die Signatur, **bevor** eine
//! Ausgabe veröffentlicht wird.
//!
//! EN: Reading and writing the sender signature (format v3, `docs/V3_SIGNED.md`, #44). When
//! encrypting, [`HashingWriter`] hashes the ciphertext `C`, then `Σ` is appended. When reading,
//! [`SignedBody`] yields exactly `C` (length from the file size), hashes it and reads `Σ` at the end
//! including an end-of-file check; [`SignatureCheck::verify`] checks the signature **before** any
//! output is published.

use std::cell::RefCell;
use std::io::{self, Read, Take, Write};
use std::rc::Rc;

use sha3::{Digest, Sha3_512};

use super::signer_v3::{FILE_SIG_CONTEXT, FILE_SIGNATURE_LEN, SIGNER_DSA, Signer, message};
use crate::crypto::{KeyAlgorithm, dsa};
use crate::envelope::{PublicKeyFile, UnlockedKey};
use crate::{Error, Result};

/// DE: Geprüfter Absender einer Datei. EN: Verified sender of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBy {
    /// DE: Schlüssel-ID (SHA3-256 des öffentlichen Schlüssels). EN: Key ID (SHA3-256 of the public key).
    pub key_id: Vec<u8>,
}

/// DE: Prüft, dass `key` ein ML-DSA-87-Schlüssel ist (vor jeder Arbeit).
/// EN: Checks that `key` is an ML-DSA-87 key (before any work).
///
/// # Errors
/// DE/EN: [`Error::Unsupported`].
pub fn check_signing_key(key: &UnlockedKey) -> Result<()> {
    if key.algorithm == KeyAlgorithm::Dsa(SIGNER_DSA) {
        Ok(())
    } else {
        Err(Error::Unsupported)
    }
}

/// DE: Schreiber, der alles Durchgeschriebene hasht und zählt. EN: Writer hashing and counting all data.
pub(super) struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha3_512,
    len: u64,
}

impl<W: Write> HashingWriter<W> {
    pub(super) fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha3_512::new(),
            len: 0,
        }
    }

    /// DE: Innerer Schreiber ohne Signatur. EN: Inner writer without signature.
    pub(super) fn into_inner(self) -> W {
        self.inner
    }

    /// DE: Signiert `H ‖ C`, prüft gegen und hängt `Σ` an; liefert den inneren Schreiber.
    /// EN: Signs `H ‖ C`, cross-checks and appends `Σ`; returns the inner writer.
    pub(super) fn append_signature(mut self, key: &UnlockedKey, header: &[u8]) -> Result<W> {
        check_signing_key(key)?;
        let msg = message(header, &self.hasher.finalize_reset(), self.len);
        let sig = dsa::sign(SIGNER_DSA, key.secret().expose(), &msg, FILE_SIG_CONTEXT)?;
        // DE: Gegenprobe gegen Rechen-/Speicherfehler. EN: Cross-check against compute/memory faults.
        if sig.len() != FILE_SIGNATURE_LEN
            || !dsa::verify(SIGNER_DSA, &key.public_key, &msg, FILE_SIG_CONTEXT, &sig)
        {
            return Err(Error::Crypto);
        }
        self.inner.write_all(&sig)?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.len += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// DE: Gemeinsamer Zustand zwischen Leser und Prüfung. EN: State shared by reader and check.
#[derive(Default)]
struct Tail {
    hasher: Sha3_512,
    len: u64,
    signature: Option<Vec<u8>>,
}

/// DE: Liest genau `C`; am Ende `Σ` und Dateiende. EN: Reads exactly `C`; at the end `Σ` and EOF.
pub(super) struct SignedBody<R: Read> {
    inner: Take<R>,
    tail: Rc<RefCell<Tail>>,
}

impl<R: Read> SignedBody<R> {
    /// DE: `body_len` = Länge von `C`. EN: `body_len` = length of `C`.
    pub(super) fn new(inner: R, body_len: u64, check: &SignatureCheck) -> Self {
        Self {
            inner: inner.take(body_len),
            tail: Rc::clone(&check.tail),
        }
    }

    fn read_signature(&mut self) {
        let rest = self.inner.get_mut();
        let mut sig = vec![0u8; FILE_SIGNATURE_LEN];
        let mut probe = [0u8; 1];
        // DE: Fehlt etwas oder folgt noch etwas, bleibt `signature` leer → Prüfung schlägt fehl.
        // EN: If something is missing or follows, `signature` stays empty → the check fails.
        if rest.read_exact(&mut sig).is_ok() && matches!(rest.read(&mut probe), Ok(0)) {
            self.tail.borrow_mut().signature = Some(sig);
        }
    }
}

impl<R: Read> Read for SignedBody<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            let mut tail = self.tail.borrow_mut();
            tail.hasher.update(&buf[..n]);
            tail.len += n as u64;
        } else if !buf.is_empty() && self.inner.limit() == 0 {
            self.read_signature();
        }
        Ok(n)
    }
}

/// DE: Chiffrat einer Datei: unsigniert unverändert, signiert begrenzt und gehasht.
/// EN: Ciphertext of a file: unsigned unchanged, signed bounded and hashed.
pub(super) enum Body<R: Read> {
    /// DE: v1/v2. EN: v1/v2.
    Plain(R),
    /// DE: v3. EN: v3.
    Signed(SignedBody<R>),
}

impl<R: Read> Read for Body<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(r) => r.read(buf),
            Self::Signed(r) => r.read(buf),
        }
    }
}

/// DE: Ergebnis eines verborgenen Absenders (füllt der Trailer-Leser). EN: Result of a hidden sender.
pub(crate) type HiddenResult = Rc<RefCell<Option<SignedBy>>>;

/// DE: Signaturprüfung: v3/v4-SIGNED (Σ am Dateiende) oder verborgener Absender (Trailer, #316).
/// EN: Signature check: v3/v4-SIGNED (Σ at the end) or hidden sender (trailer, #316).
pub(crate) struct SignatureCheck {
    tail: Rc<RefCell<Tail>>,
    header: Vec<u8>,
    signer: Option<Signer>,
    /// DE: Verborgener Absender: Ergebnis und verlangte Schlüssel-ID (`--signer`).
    /// EN: Hidden sender: result and required key ID (`--signer`).
    hidden: Option<(HiddenResult, Option<Vec<u8>>)>,
}

impl SignatureCheck {
    pub(super) fn new(header: Vec<u8>, signer: Signer) -> Self {
        Self {
            tail: Rc::new(RefCell::new(Tail::default())),
            header,
            signer: Some(signer),
            hidden: None,
        }
    }

    /// DE: Prüfung für einen verborgenen Absender; der Trailer-Leser trägt das Ergebnis ein.
    /// EN: Check for a hidden sender; the trailer reader fills in the result.
    pub(super) fn hidden(expected: Option<&PublicKeyFile>) -> (Self, HiddenResult) {
        let result: HiddenResult = Rc::new(RefCell::new(None));
        let check = Self {
            tail: Rc::new(RefCell::new(Tail::default())),
            header: Vec::new(),
            signer: None,
            hidden: Some((
                Rc::clone(&result),
                expected.map(PublicKeyFile::key_id).map(<[u8]>::to_vec),
            )),
        };
        (check, result)
    }

    /// DE: Prüft nach vollständig gelesenem `C`. EN: Verifies after `C` has been read completely.
    ///
    /// # Errors
    /// DE/EN: [`Error::Decrypt`] (Signatur fehlt, Datei zu lang oder abgeschnitten / signature
    /// missing, file too long or truncated), [`Error::InvalidSignature`].
    pub(super) fn verify(self) -> Result<SignedBy> {
        if let Some((result, expected)) = self.hidden {
            let signed = result.borrow_mut().take().ok_or(Error::Decrypt)?;
            if expected.is_some_and(|id| id != signed.key_id) {
                return Err(Error::InvalidSignature);
            }
            return Ok(signed);
        }
        let signer = self.signer.as_ref().ok_or(Error::Decrypt)?;
        let mut tail = self.tail.borrow_mut();
        let signature = tail.signature.take().ok_or(Error::Decrypt)?;
        let digest = tail.hasher.finalize_reset();
        let msg = message(&self.header, &digest, tail.len);
        let key = &signer.public_key;
        if !dsa::verify(SIGNER_DSA, key, &msg, FILE_SIG_CONTEXT, &signature) {
            return Err(Error::InvalidSignature);
        }
        Ok(SignedBy {
            key_id: signer.key_id(),
        })
    }
}

/// DE: Verlangter Absender bei verborgenem Absender: vorab nur die Art prüfen (ML-DSA-87); die
/// Identität prüft [`SignatureCheck::verify`] nach dem Entschlüsseln.
/// EN: Required sender with a hidden sender: only check the kind up front (ML-DSA-87); identity
/// is checked by [`SignatureCheck::verify`] after decrypting.
///
/// # Errors
/// DE/EN: [`Error::Unsupported`].
pub(super) fn require_kind(expected: Option<&PublicKeyFile>) -> Result<()> {
    match expected {
        Some(e) if e.algorithm() != KeyAlgorithm::Dsa(SIGNER_DSA) => Err(Error::Unsupported),
        _ => Ok(()),
    }
}

/// DE: Verlangt, dass `signer` der Absender ist (vor jeder Ableitung). Unsignierte Dateien und
/// andere Absender ergeben [`Error::InvalidSignature`].
/// EN: Requires `signer` to be the sender (before any derivation). Unsigned files and other
/// senders yield [`Error::InvalidSignature`].
///
/// # Errors
/// DE/EN: [`Error::Unsupported`] (kein ML-DSA-87-Schlüssel / not an ML-DSA-87 key),
/// [`Error::InvalidSignature`].
pub(super) fn require(expected: Option<&PublicKeyFile>, signer: Option<&Signer>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if expected.algorithm() != KeyAlgorithm::Dsa(SIGNER_DSA) {
        return Err(Error::Unsupported);
    }
    match signer {
        Some(s) if s.key_id() == expected.key_id() => Ok(()),
        _ => Err(Error::InvalidSignature),
    }
}

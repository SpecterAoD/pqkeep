//! DE: Schlüsselableitung für Format v2 (`docs/V2_DRAFT.md`). Jede Ableitung trägt eine Domäne
//! (`PQKeep/file/v2\0` bzw. `PQKeep/key/v2\0`), damit Schlüssel aus Dateiverschlüsselung und
//! Schlüsseldatei nie zusammenfallen.
//!
//! ```text
//! B     = Argon2id(P, salt = S, secret = F, ad = D ‖ "argon2\0", m, t, p, 32)
//! Wpass = HKDF-SHA3-256(salt = S,  IKM = B,  info = D ‖ "wrap/passphrase\0" ‖ U8(faktor))
//! Wrec  = HKDF-SHA3-256(salt = ct, IKM = ss, info = D_file ‖ "wrap/recipient\0" ‖ ID[32])
//! ```
//!
//! `F` ist der Inhalt der Faktordatei oder leer. Ohne Faktordatei ist das Ergebnis trotzdem
//! ein anderes als in v1 (Domäne und HKDF-Schritt).
//!
//! EN: Key derivation for format v2 (`docs/V2_DRAFT.md`). Every derivation carries a domain
//! (`PQKeep/file/v2\0` or `PQKeep/key/v2\0`) so that keys from file encryption and key files
//! never coincide. `F` is the content of the factor file or empty. Without a factor file the
//! result still differs from v1 (domain and HKDF step). Formulas: see above.

use hkdf::SimpleHkdf;
use sha3::Sha3_256;

use crate::crypto::factor::Factor;
use crate::crypto::kdf::{self, KdfParams};
use crate::crypto::{SecretBytes, aead};
use crate::security::Passphrase;
use crate::{Error, Result};

#[cfg(test)]
#[path = "v2_tests.rs"]
mod v2_tests;

/// DE: Länge der Empfänger-ID. EN: Length of the recipient ID.
pub const RECIPIENT_ID_LEN: usize = 32;

/// DE: Verwendungszweck einer Ableitung. EN: Purpose of a derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// DE: Dateiverschlüsselung (`*.pqenc`). EN: File encryption (`*.pqenc`).
    File,
    /// DE: Schlüsseldatei (`*.key.json`). EN: Key file (`*.key.json`).
    Key,
}

impl Domain {
    /// DE: Domänen-Tag (wird mitauthentifiziert, nie ändern).
    /// EN: Domain tag (authenticated, never change).
    #[must_use]
    pub fn tag(self) -> &'static [u8] {
        match self {
            Self::File => b"PQKeep/file/v2\0",
            Self::Key => b"PQKeep/key/v2\0",
        }
    }
}

fn info(domain: Domain, label: &[u8], tail: &[u8]) -> Vec<u8> {
    [domain.tag(), label, tail].concat()
}

/// DE: HKDF-SHA3-256 mit 32 Byte Ausgabe. `SimpleHkdf`, da SHA3 (Sponge) keine
/// Block-Kern-Schnittstelle für `Hmac` bietet.
/// EN: HKDF-SHA3-256 with 32 bytes of output. `SimpleHkdf` because SHA3 (sponge) offers no
/// block-core interface for `Hmac`.
fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<SecretBytes> {
    let mut key = SecretBytes::new(vec![0u8; aead::KEY_LEN]);
    SimpleHkdf::<Sha3_256>::new(Some(salt), ikm)
        .expand(info, key.expose_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}

/// DE: Zweiter Schritt des Passphrase-Zugangs: aus dem Argon2id-Ergebnis `B` wird `Wpass`.
/// EN: Second step of the passphrase slot: turns the Argon2id result `B` into `Wpass`.
fn expand_passphrase(domain: Domain, b: &[u8], salt: &[u8], factor: bool) -> Result<SecretBytes> {
    hkdf(
        salt,
        b,
        &info(domain, b"wrap/passphrase\0", &[u8::from(factor)]),
    )
}

/// DE: Packschlüssel `Wpass` aus Passphrase und optionaler Faktordatei. Die Grenzen für
/// Parameter und Salt sind dieselben wie in [`kdf::derive`].
/// EN: Wrapping key `Wpass` from passphrase and optional factor file. Bounds for parameters
/// and salt are the same as in [`kdf::derive`].
///
/// # Errors
/// DE/EN: [`Error::KdfParams`], [`Error::InvalidInput`] (Salt), [`Error::Crypto`].
pub fn passphrase_kek(
    domain: Domain,
    passphrase: &Passphrase,
    factor: Option<&Factor>,
    salt: &[u8],
    params: &KdfParams,
) -> Result<SecretBytes> {
    params.validate()?;
    if !(kdf::MIN_SALT_LEN..=kdf::MAX_SALT_LEN).contains(&salt.len()) {
        return Err(Error::InvalidInput { field: "salt" });
    }
    let secret = factor.map_or(&[][..], Factor::expose);
    let ad = info(domain, b"argon2\0", &[]);
    let mut b = SecretBytes::new(vec![0u8; kdf::OUTPUT_LEN]);
    kdf::argon2id(
        passphrase.expose(),
        salt,
        params,
        secret,
        &ad,
        b.expose_mut(),
    )?;
    expand_passphrase(domain, b.expose(), salt, factor.is_some())
}

/// DE: Packschlüssel `Wrec` eines Empfänger-Zugangs aus dem ML-KEM-Geheimnis. Salt ist das
/// KEM-Chiffrat, die Empfänger-ID geht in die Info ein. Nur für Dateien (Domäne `file`).
/// EN: Wrapping key `Wrec` of a recipient slot from the ML-KEM secret. The salt is the KEM
/// ciphertext, the recipient ID goes into the info. Files only (domain `file`).
///
/// # Errors
/// DE/EN: [`Error::Crypto`].
pub fn recipient_kek(
    shared: &[u8],
    kem_ciphertext: &[u8],
    recipient_id: &[u8; RECIPIENT_ID_LEN],
) -> Result<SecretBytes> {
    hkdf(
        kem_ciphertext,
        shared,
        &info(Domain::File, b"wrap/recipient\0", recipient_id),
    )
}

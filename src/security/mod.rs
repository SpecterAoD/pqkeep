//! DE: Passphrase-Sicherheit: Unicode-Normalisierung (NFKC), Stärkeprüfung mit
//! Begründung, Entropieschätzung und Generator. Ein neuer Schlüssel kann nur mit
//! einer [`StrongPassphrase`] geschützt werden; zum Öffnen genügt eine [`Passphrase`].
//!
//! EN: Passphrase security: Unicode normalisation (NFKC), strength check with
//! reasons, entropy estimate and generator. A new key can only be protected with
//! a [`StrongPassphrase`]; opening only needs a [`Passphrase`].

mod blocklist;
mod entropy;
pub mod generator;
mod patterns;
mod policy;

pub use entropy::formula_bits;
pub use policy::{MAX_CHARS, MIN_CHARS, MIN_ENTROPY_BITS, Reason, Rejection};

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

use crate::crypto::SecretBytes;
use crate::{Error, Result};

/// DE: Harte Obergrenze beim Einlesen (Schutz vor sehr großen Eingaben). Die
/// Stärkeprüfung lehnt bereits ab [`MAX_CHARS`] mit Begründung ab.
/// EN: Hard limit on input (protection against very large inputs). The strength
/// check already rejects above [`MAX_CHARS`] with a reason.
pub const INPUT_LIMIT_CHARS: usize = 4 * MAX_CHARS;

/// DE: Sprache für Meldungen. EN: Language for messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    /// Deutsch
    #[default]
    De,
    /// English
    En,
}

/// DE: NFKC-normalisierte Passphrase (UTF-8), wird beim Drop genullt.
/// Kein `Debug`, `Clone` oder `Display`.
/// EN: NFKC-normalised passphrase (UTF-8), zeroed on drop.
/// No `Debug`, `Clone` or `Display`.
pub struct Passphrase {
    bytes: SecretBytes,
    chars: usize,
}

impl Passphrase {
    /// DE: Normalisiert (NFKC) und übernimmt die Eingabe. Gleiche Passphrasen
    /// ergeben so unter Windows und Linux dieselben Bytes.
    /// EN: Normalises (NFKC) and takes the input. Equal passphrases thus give the
    /// same bytes on Windows and Linux.
    ///
    /// # Errors
    /// DE/EN: [`Error::InvalidInput`] bei leerer oder zu langer Eingabe / if empty or too long.
    pub fn new(input: &str) -> Result<Self> {
        // DE: Vorab reservieren, damit beim Wachsen möglichst keine Kopien entstehen.
        // EN: Reserve up front so that growing leaves as few copies as possible.
        let mut normalized = String::with_capacity(input.len().saturating_mul(3));
        normalized.extend(input.nfkc());
        let chars = normalized.chars().count();
        if chars == 0 || chars > INPUT_LIMIT_CHARS {
            normalized.zeroize();
            return Err(Error::InvalidInput {
                field: "passphrase",
            });
        }
        Ok(Self {
            bytes: SecretBytes::new(normalized.into_bytes()),
            chars,
        })
    }

    /// DE: Wie [`Passphrase::new`], nullt danach die übergebene Eingabe.
    /// EN: Like [`Passphrase::new`], then zeroes the given input.
    ///
    /// # Errors
    /// DE/EN: siehe / see [`Passphrase::new`].
    pub fn from_string(mut input: String) -> Result<Self> {
        let result = Self::new(&input);
        input.zeroize();
        result
    }

    /// DE: Normalisierte UTF-8-Bytes (für die Schlüsselableitung). Nicht loggen!
    /// EN: Normalised UTF-8 bytes (for key derivation). Do not log!
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.bytes.expose()
    }

    /// DE: Anzahl Unicode-Zeichen nach NFKC. EN: Number of Unicode characters after NFKC.
    #[must_use]
    pub fn char_count(&self) -> usize {
        self.chars
    }

    /// DE: Normalisierter Text, z. B. zur Anzeige einer erzeugten Passphrase auf
    /// ausdrücklichen Wunsch. Nicht loggen!
    /// EN: Normalised text, e.g. to display a generated passphrase on explicit
    /// request. Do not log!
    #[must_use]
    pub fn expose_str(&self) -> &str {
        // DE: Stammt immer aus einem `String`, ist also gültiges UTF-8.
        // EN: Always originates from a `String`, hence valid UTF-8.
        std::str::from_utf8(self.bytes.expose()).unwrap_or_default()
    }

    /// DE: Bewertet die Passphrase (alle Gründe, geschätzte Entropie).
    /// EN: Assesses the passphrase (all reasons, estimated entropy).
    #[must_use]
    pub fn assess(&self) -> Assessment {
        let (reasons, entropy_bits) = policy::assess(self.expose_str());
        Assessment {
            reasons,
            entropy_bits,
        }
    }
}

/// DE: Ergebnis der Bewertung (enthält keine Geheimnisse).
/// EN: Result of the assessment (contains no secrets).
#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    /// DE: Ablehnungsgründe; leer = stark genug. EN: Rejection reasons; empty = strong enough.
    pub reasons: Vec<Reason>,
    /// DE: Geschätzte Entropie in Bit. EN: Estimated entropy in bits.
    pub entropy_bits: f64,
}

impl Assessment {
    /// DE: `true`, wenn keine Gründe vorliegen. EN: `true` if there are no reasons.
    #[must_use]
    pub fn is_strong(&self) -> bool {
        self.reasons.is_empty()
    }
}

/// DE: Passphrase, die alle Regeln erfüllt. Nur über `TryFrom<Passphrase>` erzeugbar;
/// eine ungeprüfte [`Passphrase`] passt nicht (folgendes Beispiel kompiliert nicht).
/// EN: Passphrase that meets all rules. Only constructible via `TryFrom<Passphrase>`;
/// an unchecked [`Passphrase`] does not fit (the following example does not compile).
///
/// ```compile_fail
/// use pqc_keyforge::security::{Passphrase, StrongPassphrase};
/// let p: StrongPassphrase = Passphrase::new("weak").unwrap();
/// ```
pub struct StrongPassphrase {
    inner: Passphrase,
    entropy_bits: f64,
}

impl StrongPassphrase {
    /// DE: Geschätzte Entropie in Bit. EN: Estimated entropy in bits.
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        self.entropy_bits
    }
}

impl AsRef<Passphrase> for StrongPassphrase {
    fn as_ref(&self) -> &Passphrase {
        &self.inner
    }
}

impl From<Rejection> for Error {
    fn from(_: Rejection) -> Self {
        Self::WeakPassphrase
    }
}

impl TryFrom<Passphrase> for StrongPassphrase {
    type Error = Rejection;

    fn try_from(passphrase: Passphrase) -> std::result::Result<Self, Rejection> {
        let assessment = passphrase.assess();
        if assessment.is_strong() {
            Ok(Self {
                inner: passphrase,
                entropy_bits: assessment.entropy_bits,
            })
        } else {
            Err(Rejection {
                reasons: assessment.reasons,
                entropy_bits: assessment.entropy_bits,
            })
        }
    }
}

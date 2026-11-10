//! DE: Passphrase-Generator: OS-CSPRNG, Rejection Sampling ohne Modulo-Bias,
//! druckbares ASCII. Ein Kandidat, der nicht alle Zeichenklassen enthält oder die
//! Prüfung nicht besteht, wird vollständig verworfen und neu gezogen; so bleibt
//! die Verteilung über alle gültigen Passphrasen gleichmäßig.
//!
//! EN: Passphrase generator: OS CSPRNG, rejection sampling without modulo bias,
//! printable ASCII. A candidate that lacks a character class or fails the check
//! is discarded entirely and redrawn, keeping the distribution uniform over all
//! valid passphrases.

use zeroize::Zeroizing;

use super::entropy::formula_bits;
use super::{MIN_BITS, Passphrase, StrongPassphrase};
use crate::crypto::rng;
use crate::{Error, Result};

#[cfg(test)]
#[path = "generator_tests.rs"]
mod generator_tests;

/// DE: Standardlänge (≈ 210 Bit). EN: Default length (≈ 210 bits).
pub const DEFAULT_LEN: usize = 32;
/// DE: Kleinste Länge: auch ohne verwechselbare Zeichen (85 Zeichen) ≈ 154 Bit ≥ 128 Bit.
/// EN: Minimum length: even without ambiguous characters (85 characters) ≈ 154 bits ≥ 128 bits.
pub const MIN_LEN: usize = 24;
/// DE: Größte Länge. EN: Maximum length.
pub const MAX_LEN: usize = 256;
/// DE: Verwechselbare Zeichen. EN: Ambiguous characters.
pub const AMBIGUOUS: &str = "0O1lI|`'\"";
/// DE: Höchstzahl an Versuchen (praktisch nie erreicht).
/// EN: Maximum number of attempts (practically never reached).
const MAX_ATTEMPTS: usize = 1000;

/// DE: Optionen des Generators. EN: Generator options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// DE: Länge in Zeichen (24–256). EN: Length in characters (24–256).
    pub length: usize,
    /// DE: Verwechselbare Zeichen auslassen. EN: Omit ambiguous characters.
    pub exclude_ambiguous: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            length: DEFAULT_LEN,
            exclude_ambiguous: false,
        }
    }
}

impl Options {
    /// DE: Verwendetes Alphabet. EN: Alphabet in use.
    #[must_use]
    pub fn alphabet(&self) -> Vec<char> {
        ('!'..='~')
            .filter(|c| !(self.exclude_ambiguous && AMBIGUOUS.contains(*c)))
            .collect()
    }

    /// DE: Entropie nach Formel log2(Alphabet) × Länge (Anzeigewert).
    /// EN: Entropy per formula log2(alphabet) × length (display value).
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        formula_bits(self.alphabet().len(), self.length)
    }
}

/// DE: Bildet ein Zufallsbyte gleichverteilt auf `0..n` ab oder verwirft es.
/// EN: Maps a random byte uniformly onto `0..n` or rejects it.
pub(crate) fn uniform_index(byte: u8, n: usize) -> Option<usize> {
    if n == 0 || n > 256 {
        return None;
    }
    let limit = 256 - 256 % n;
    let b = usize::from(byte);
    (b < limit).then_some(b % n)
}

/// DE: Kleinste Länge, mit der die Prüfung `min_bits` verlässlich erreicht (128 → 24, 192 → 36,
/// 256 → 48). Die Prüfung schätzt vorsichtiger als die Formel (zufällige Buchstabenfolgen zählen
/// als Wörter), daher 16 Bit je 3 Zeichen.
/// EN: Smallest length that reliably reaches `min_bits` in the check (128 → 24, 192 → 36,
/// 256 → 48). The check estimates more conservatively than the formula (random letter runs count
/// as words), hence 16 bits per 3 characters.
#[must_use]
pub fn min_len(min_bits: u32) -> usize {
    let needed = usize::try_from(min_bits)
        .unwrap_or(usize::MAX)
        .saturating_mul(3)
        / 16;
    needed.max(MIN_LEN)
}

/// DE: Erzeugt eine starke Passphrase (mindestens 128 Bit).
/// EN: Generates a strong passphrase (at least 128 bits).
///
/// # Errors
/// DE/EN: wie / as [`generate_with`].
pub fn generate(options: &Options) -> Result<StrongPassphrase> {
    generate_with(options, MIN_BITS)
}

/// DE: Erzeugt eine Passphrase, die die Prüfung mit `min_bits` besteht.
/// EN: Generates a passphrase that passes the check with `min_bits`.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] (Länge außerhalb [`min_len`]..=256 / length outside),
/// [`Error::Rng`], [`Error::Crypto`] (keine gültige Passphrase nach vielen Versuchen / none valid
/// after many attempts).
pub fn generate_with(options: &Options, min_bits: u32) -> Result<StrongPassphrase> {
    if !(min_len(min_bits)..=MAX_LEN).contains(&options.length) {
        return Err(Error::InvalidInput { field: "length" });
    }
    let alphabet = options.alphabet();
    for _ in 0..MAX_ATTEMPTS {
        let candidate = draw(&alphabet, options.length)?;
        let passphrase = Passphrase::new(&candidate)?;
        if let Ok(strong) = StrongPassphrase::with_min_bits(passphrase, min_bits) {
            return Ok(strong);
        }
    }
    Err(Error::Crypto)
}

/// DE: Zieht `length` Zeichen gleichverteilt aus `alphabet`.
/// EN: Draws `length` characters uniformly from `alphabet`.
fn draw(alphabet: &[char], length: usize) -> Result<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(length));
    let mut pool = Zeroizing::new([0u8; 64]);
    while out.len() < length {
        rng::fill(pool.as_mut())?;
        for &byte in pool.iter() {
            if out.len() == length {
                break;
            }
            if let Some(i) = uniform_index(byte, alphabet.len()) {
                out.push(alphabet[i]);
            }
        }
    }
    Ok(out)
}

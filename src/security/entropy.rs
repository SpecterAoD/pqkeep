//! DE: Entropieschätzung. Formel laut Spezifikation: log2(Zeichenvorrat) × Länge.
//! Zeichenvorrat = Summe der vorkommenden Klassen; Zeichen, die zu erkannten
//! Mustern gehören, zählen nicht zur Länge. Eine Heuristik – sie misst die Form,
//! nicht wie zufällig die Passphrase tatsächlich gewählt wurde.
//!
//! EN: Entropy estimate. Formula per specification: log2(pool size) × length.
//! Pool = sum of the classes present; characters belonging to detected patterns
//! do not count towards the length. A heuristic – it measures the shape, not how
//! randomly the passphrase was actually chosen.

use super::policy::{CharPred, is_special};

/// DE: Größe der Klasse Kleinbuchstaben (ASCII). EN: Size of lowercase class (ASCII).
pub(super) const POOL_LOWER: u32 = 26;
/// DE: Großbuchstaben (ASCII). EN: Uppercase (ASCII).
pub(super) const POOL_UPPER: u32 = 26;
/// DE: Ziffern. EN: Digits.
pub(super) const POOL_DIGIT: u32 = 10;
/// DE: Druckbare ASCII-Sonderzeichen inkl. Leerzeichen. EN: Printable ASCII specials incl. space.
pub(super) const POOL_SPECIAL: u32 = 33;
/// DE: Pauschale für Nicht-ASCII-Zeichen (Umlaute, andere Schriften).
/// EN: Flat rate for non-ASCII characters (umlauts, other scripts).
pub(super) const POOL_NON_ASCII: u32 = 100;

/// DE: Bits nach der Generator-Formel: log2(Alphabet) × Länge.
/// EN: Bits per generator formula: log2(alphabet) × length.
#[must_use]
pub fn formula_bits(alphabet: usize, length: usize) -> f64 {
    let a = f64::from(u32::try_from(alphabet).unwrap_or(u32::MAX));
    let l = f64::from(u32::try_from(length).unwrap_or(u32::MAX));
    if a <= 1.0 { 0.0 } else { a.log2() * l }
}

/// DE: Zeichenvorrat aus den vorkommenden Klassen. EN: Pool from the classes present.
pub(super) fn pool_size(chars: &[char]) -> u32 {
    let classes: [(CharPred, u32); 5] = [
        (|c| c.is_ascii_lowercase(), POOL_LOWER),
        (|c| c.is_ascii_uppercase(), POOL_UPPER),
        (|c| c.is_ascii_digit(), POOL_DIGIT),
        (|c| c.is_ascii() && is_special(c), POOL_SPECIAL),
        (|c| !c.is_ascii() && !c.is_control(), POOL_NON_ASCII),
    ];
    classes
        .iter()
        .filter(|(pred, _)| chars.iter().any(|&c| pred(c)))
        .map(|(_, size)| size)
        .sum()
}

/// DE: Geschätzte Bits; markierte Zeichen (Muster) zählen nicht.
/// EN: Estimated bits; marked characters (patterns) do not count.
pub(super) fn estimate(chars: &[char], marked: &[bool]) -> f64 {
    let effective = marked.iter().filter(|m| !**m).count();
    formula_bits(pool_size(chars) as usize, effective)
}

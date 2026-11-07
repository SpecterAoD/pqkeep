//! DE: Entropieschätzung. Formel laut Spezifikation: log2(Zeichenvorrat) × Länge.
//! Zeichenvorrat = Summe der vorkommenden Klassen; Zeichen, die zu erkannten
//! Mustern gehören, zählen nicht zur Länge. Eine Heuristik – sie misst die Form,
//! nicht wie zufällig die Passphrase tatsächlich gewählt wurde.
//!
//! Wort-Modell: Eine Buchstabenfolge zählt höchstens wie Wörter – ein Wort aus den
//! eingebundenen Listen ≈ log2(7776) ≈ 12,9 Bit (+1 bei Großbuchstaben), ein
//! unbekanntes Wort 18 Bit je angefangene 10 Buchstaben. Ziffern zählen log2(10)
//! (Jahreszahlen, PINs), ein wiederholtes Sonder-/Trennzeichen 1 Bit. Angreifer raten
//! Wörter und Muster, nicht einzelne Buchstaben.
//!
//! EN: Entropy estimate. Formula per specification: log2(pool size) × length.
//! Pool = sum of the classes present; characters belonging to detected patterns
//! do not count towards the length. A heuristic – it measures the shape, not how
//! randomly the passphrase was actually chosen.
//!
//! Word model: a run of letters counts at most like words – a word from the bundled
//! lists ≈ log2(7776) ≈ 12.9 bits (+1 for capitals), an unknown word 18 bits per
//! started 10 letters. Digits count log2(10) (years, PINs), a repeated special/
//! separator character 1 bit. Attackers guess words and patterns, not single letters.

use std::ops::Range;

use super::dictionary;
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

/// DE: Bits für ein Wort aus den Listen (log2 7776). EN: Bits for a listed word (log2 7776).
pub const LIST_WORD_BITS: f64 = 12.925;
/// DE: Bits für ein unbekanntes Wort. EN: Bits for an unknown word.
pub const GENERIC_WORD_BITS: f64 = 18.0;
/// DE: Angenommene Höchstlänge eines Worts. EN: Assumed maximum word length.
const GENERIC_WORD_CHARS: usize = 10;
/// DE: Bits für ein bereits verwendetes Sonder-/Trennzeichen. EN: Bits for an already used special/separator.
const REPEAT_BITS: f64 = 1.0;

/// DE: Ergebnis der Schätzung. EN: Result of the estimate.
pub(super) struct Estimate {
    pub bits: f64,
    /// DE: Das Wort-Modell hat die Schätzung gesenkt. EN: The word model lowered the estimate.
    pub word_model: bool,
}

fn per_char(chars: &[char]) -> f64 {
    let pool = f64::from(pool_size(chars));
    if pool <= 1.0 { 0.0 } else { pool.log2() }
}

fn count(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

fn generic(n: usize, per: f64) -> f64 {
    (count(n) * per).min(count(n.div_ceil(GENERIC_WORD_CHARS)) * GENERIC_WORD_BITS)
}

/// DE: Kosten einer Buchstabenfolge: Minimum aus Einzelzeichen, unbekanntem Wort und
/// Zerlegung in Listenwörter. EN: Cost of a letter run: minimum of single characters,
/// unknown word and decomposition into listed words.
fn letter_run(chars: &[char], run: Range<usize>, words: &[Range<usize>], per: f64) -> (f64, bool) {
    let plain = count(run.len()) * per;
    let (mut dict, mut left, mut any) = (0.0, 0usize, false);
    let mut k = run.start;
    while k < run.end {
        if let Some(w) = words.iter().find(|w| w.start == k && w.end <= run.end) {
            dict += generic(left, per) + LIST_WORD_BITS;
            if chars[w.clone()].iter().any(|c| c.is_uppercase()) {
                dict += 1.0;
            }
            left = 0;
            any = true;
            k = w.end;
        } else {
            left += 1;
            k += 1;
        }
    }
    dict += generic(left, per);
    let mut best = plain.min(generic(run.len(), per));
    if any {
        best = best.min(dict);
    }
    (best, best < plain)
}

fn class(c: char) -> u8 {
    if c.is_alphabetic() {
        0
    } else if c.is_numeric() {
        1
    } else {
        2
    }
}

/// DE: Geschätzte Bits; markierte Zeichen (Muster) zählen nicht, Buchstaben- und
/// Ziffernfolgen nach dem Wort-Modell. `low` = Kleinbuchstaben-Kopie von `chars`.
/// EN: Estimated bits; marked characters (patterns) do not count, letter and digit
/// runs follow the word model. `low` = lowercase copy of `chars`.
pub(super) fn estimate(chars: &[char], low: &[char], marked: &[bool]) -> Estimate {
    let per = per_char(chars);
    let words = dictionary::find(low, marked);
    let (mut bits, mut word_model, mut i) = (0.0, false, 0);
    let mut seen: Vec<char> = Vec::new();
    while i < chars.len() {
        if marked[i] {
            i += 1;
            continue;
        }
        let kind = class(chars[i]);
        let mut j = i + 1;
        while j < chars.len() && !marked[j] && class(chars[j]) == kind {
            j += 1;
        }
        bits += match kind {
            0 => {
                let (cost, used) = letter_run(chars, i..j, &words, per);
                word_model |= used;
                cost
            }
            1 => count(j - i) * 10f64.log2().min(per),
            _ => chars[i..j]
                .iter()
                .map(|c| {
                    if seen.contains(c) {
                        REPEAT_BITS.min(per)
                    } else {
                        seen.push(*c);
                        per
                    }
                })
                .sum(),
        };
        i = j;
    }
    Estimate { bits, word_model }
}

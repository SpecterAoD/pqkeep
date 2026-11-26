//! DE: Zufällige äußere Dateinamen (#315): 128 Bit aus dem CSPRNG als 26 Zeichen Base32
//! (Kleinbuchstaben, ohne Auffüllung) plus `.pqkf`. Der Originalname steht ohnehin verschlüsselt im
//! Archiv; kein Formatwechsel.
//! EN: Random outer file names (#315): 128 bits from the CSPRNG as 26 base32 characters (lower
//! case, no padding) plus `.pqkf`. The original name is stored encrypted in the archive anyway;
//! no format change.

use std::path::{Path, PathBuf};

use super::EXTENSION;
use crate::crypto::rng;
use crate::{Error, Result};

/// DE: Länge des zufälligen Teils. EN: Length of the random part.
pub const RANDOM_NAME_LEN: usize = 26;

/// DE: Base32-Alphabet nach RFC 4648, kleingeschrieben. EN: RFC 4648 base32 alphabet, lower case.
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// DE: Versuche, bis ein freier Name gefunden ist (Kollision praktisch ausgeschlossen).
/// EN: Attempts until a free name is found (a collision is practically impossible).
const ATTEMPTS: usize = 8;

fn base32(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(RANDOM_NAME_LEN);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((acc << (5 - bits)) & 31) as usize]));
    }
    out
}

/// DE: Neuer zufälliger Name `<26 Zeichen>.pqkf`. EN: New random name `<26 chars>.pqkf`.
///
/// # Errors
/// DE/EN: [`Error::Rng`].
pub fn random_name() -> Result<String> {
    Ok(format!("{}.{EXTENSION}", base32(&rng::array::<16>()?)))
}

/// DE: Hat `name` die Form eines zufälligen Namens? Dann stellt `decrypt` den Originalnamen
/// aus dem Archiv her (ohne `--out`).
/// EN: Does `name` look like a random name? Then `decrypt` restores the original name from the
/// archive (without `--out`).
#[must_use]
pub fn is_random_name(name: &str) -> bool {
    name.strip_suffix(EXTENSION)
        .and_then(|s| s.strip_suffix('.'))
        .is_some_and(|stem| {
            stem.len() == RANDOM_NAME_LEN && stem.bytes().all(|b| ALPHABET.contains(&b))
        })
}

/// DE: Freier zufälliger Zielpfad in `dir` (`dir` leer = aktueller Ordner).
/// EN: Free random target path in `dir` (empty `dir` = current directory).
///
/// # Errors
/// DE/EN: [`Error::Rng`]; [`Error::Io`] `AlreadyExists`, wenn kein freier Name gefunden wurde /
/// if no free name was found.
pub fn random_target(dir: &Path) -> Result<PathBuf> {
    for _ in 0..ATTEMPTS {
        let path = dir.join(random_name()?);
        if std::fs::symlink_metadata(&path).is_err() {
            return Ok(path);
        }
    }
    Err(Error::Io(std::io::ErrorKind::AlreadyExists))
}

#[cfg(test)]
#[path = "random_name_tests.rs"]
mod tests;

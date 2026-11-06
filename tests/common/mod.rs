//! DE: Gemeinsame Test-Hilfen. Passphrasen werden zur Laufzeit erzeugt (keine Secrets im Repo).
//! EN: Shared test helpers. Passphrases are generated at runtime (no secrets in the repo).

// DE: Hilfsfunktionen sind keine #[test]-Funktionen, unwrap hier bewusst erlaubt.
// EN: Helpers are not #[test] functions; unwrap deliberately allowed here.
#![allow(dead_code, clippy::unwrap_used)]

use pqc_keyforge::crypto::kdf::{self, KdfParams};
use pqc_keyforge::crypto::rng;

/// DE: Kleinste zulässige Parameter (schnellster gültiger Fall).
/// EN: Smallest permitted parameters (fastest valid case).
pub fn min_params() -> KdfParams {
    KdfParams {
        memory_kib: kdf::MIN_MEMORY_KIB,
        iterations: kdf::MIN_ITERATIONS,
        parallelism: kdf::auto_parallelism(),
    }
}

/// DE: Zufällige Test-Passphrase (48 Hex-Zeichen). EN: Random test passphrase (48 hex chars).
pub fn random_passphrase() -> Vec<u8> {
    let raw = rng::array::<24>().unwrap();
    hex::encode(raw).into_bytes()
}

/// DE: Kopie mit einem gekippten Bit an Position `i`. EN: Copy with one flipped bit at `i`.
pub fn flip(data: &[u8], i: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    out[i] ^= 0x01;
    out
}

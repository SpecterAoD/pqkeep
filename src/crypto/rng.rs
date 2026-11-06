//! DE: Zufall ausschließlich aus dem Betriebssystem (CSPRNG über `getrandom`).
//! Keine eigenen Generatoren, kein `thread_rng`.
//!
//! EN: Randomness exclusively from the operating system (CSPRNG via `getrandom`).
//! No custom generators, no `thread_rng`.

use crate::crypto::SecretBytes;
use crate::{Error, Result};

/// DE: Füllt den Puffer mit Zufallsbytes des Betriebssystems.
/// EN: Fills the buffer with random bytes from the operating system.
///
/// # Errors
/// DE: [`Error::Rng`], wenn das Betriebssystem keinen Zufall liefert.
/// EN: [`Error::Rng`] if the operating system cannot provide randomness.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Rng)
}

/// DE: Liefert ein Array mit `N` Zufallsbytes (für öffentliche Werte wie Salt/Nonce).
/// EN: Returns an array of `N` random bytes (for public values such as salt/nonce).
///
/// # Errors
/// DE/EN: [`Error::Rng`].
pub fn array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// DE: Liefert `len` geheime Zufallsbytes (für Seeds und Schlüssel).
/// EN: Returns `len` secret random bytes (for seeds and keys).
///
/// # Errors
/// DE/EN: [`Error::Rng`].
pub fn secret(len: usize) -> Result<SecretBytes> {
    let mut out = SecretBytes::new(vec![0u8; len]);
    fill(out.expose_mut())?;
    Ok(out)
}

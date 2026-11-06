//! DE: Strikte Kodierungen: Base64 (Standard-Alphabet mit Padding) über `base64ct`
//! (konstante Laufzeit, lehnt nicht-kanonische Kodierungen ab) und Hex in
//! Kleinbuchstaben für die Schlüssel-ID. Jeweils mit Längengrenze.
//! EN: Strict encodings: Base64 (standard alphabet with padding) via `base64ct`
//! (constant time, rejects non-canonical encodings) and lowercase hex for the
//! key ID. Each with a length limit.

use base64ct::{Base64, Encoding};

use crate::{Error, Result};

/// DE: Kodiert Bytes als Base64. EN: Encodes bytes as Base64.
#[must_use]
pub fn b64_encode(data: &[u8]) -> String {
    Base64::encode_string(data)
}

/// DE: Dekodiert streng; `max` begrenzt die Länge der dekodierten Daten.
/// EN: Decodes strictly; `max` limits the length of the decoded data.
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] mit dem Feldnamen / with the field name.
pub fn b64_decode(text: &str, max: usize, field: &'static str) -> Result<Vec<u8>> {
    // DE: Vor dem Dekodieren prüfen (4 Zeichen → 3 Bytes). EN: Check before decoding.
    if text.len() > max.div_ceil(3) * 4 {
        return Err(Error::InvalidInput { field });
    }
    let out = Base64::decode_vec(text).map_err(|_| Error::InvalidInput { field })?;
    if out.len() > max {
        return Err(Error::InvalidInput { field });
    }
    Ok(out)
}

/// DE: Kodiert Bytes als Hex (Kleinbuchstaben). EN: Encodes bytes as lowercase hex.
#[must_use]
pub fn hex_encode(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    data.iter()
        .flat_map(|b| [DIGITS[usize::from(b >> 4)], DIGITS[usize::from(b & 0x0f)]])
        .map(char::from)
        .collect()
}

/// DE: Dekodiert Hex mit genau `len` Bytes; nur Kleinbuchstaben (eine Schreibweise).
/// EN: Decodes hex of exactly `len` bytes; lowercase only (one canonical form).
///
/// # Errors
/// DE/EN: [`Error::InvalidInput`] mit dem Feldnamen / with the field name.
pub fn hex_decode(text: &str, len: usize, field: &'static str) -> Result<Vec<u8>> {
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let bytes = text.as_bytes();
    if bytes.len() != len * 2 {
        return Err(Error::InvalidInput { field });
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| Some(nibble(p[0])? << 4 | nibble(p[1])?))
        .collect::<Option<Vec<u8>>>()
        .ok_or(Error::InvalidInput { field })
}

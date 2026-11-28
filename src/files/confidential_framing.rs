//! DE: Private Framingbytes direkt in vorab gesperrte Ziele schreiben.
//! EN: Write private framing bytes directly into prelocked destinations.

use super::format_v4::{DOMAIN_V4, TRAILER_LEN, TRAILER_MAGIC};
use crate::{
    Error, Result,
    crypto::{SecretBytes, locked_hash::LockedHash},
};
use sha3::Sha3_512;

pub(super) fn message(
    header: &[u8],
    plain_hash: &[u8],
    payload: u64,
    pad: u64,
) -> Result<SecretBytes> {
    const TAG: &[u8] = b"sig/hidden\0";
    if plain_hash.len() != 64 {
        return Err(Error::Crypto);
    }
    let mut header_hash = LockedHash::<Sha3_512>::new()?;
    header_hash.update(header);
    let header_hash = header_hash.finalize()?;
    let prefix = DOMAIN_V4.len() + TAG.len();
    let mut out = SecretBytes::zeroed(prefix + 128 + 16)?;
    let bytes = out.expose_mut();
    bytes[..DOMAIN_V4.len()].copy_from_slice(DOMAIN_V4);
    bytes[DOMAIN_V4.len()..prefix].copy_from_slice(TAG);
    bytes[prefix..prefix + 64].copy_from_slice(header_hash.expose());
    bytes[prefix + 64..prefix + 128].copy_from_slice(plain_hash);
    write_word(&mut bytes[prefix + 128..prefix + 136], payload)?;
    write_word(&mut bytes[prefix + 136..], pad)?;
    Ok(out)
}

pub(super) fn trailer(payload: u64, pad: u64) -> Result<SecretBytes> {
    let mut out = SecretBytes::zeroed(TRAILER_LEN)?;
    write_word(&mut out.expose_mut()[..8], payload)?;
    write_word(&mut out.expose_mut()[8..16], pad)?;
    out.expose_mut()[16..].copy_from_slice(TRAILER_MAGIC);
    Ok(out)
}

fn write_word(out: &mut [u8], mut value: u64) -> Result<()> {
    if out.len() != 8 {
        return Err(Error::Crypto);
    }
    // DE: Kein privates to_le_bytes-Rückgabearray; skalare Bytes direkt ins Ziel.
    // EN: No private to_le_bytes return array; write scalar bytes directly to target.
    for byte in out {
        *byte = u8::try_from(value & 255).map_err(|_| Error::Crypto)?;
        value >>= 8;
    }
    Ok(())
}

pub(super) fn read_word(bytes: &[u8]) -> Result<u64> {
    if bytes.len() != 8 {
        return Err(Error::Crypto);
    }
    Ok(bytes.iter().enumerate().fold(0, |value, (index, byte)| {
        value | (u64::from(*byte) << (8 * index))
    }))
}

#[cfg(test)]
#[path = "confidential_framing_tests.rs"]
mod tests;

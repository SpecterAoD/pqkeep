use crate::utils::{IPAD, OPAD, get_der_key};
use core::fmt;
use digest::{
    Digest, FixedOutput, KeyInit, MacMarker, Output, OutputSizeUser, Update,
    common::{Block, BlockSizeUser, InvalidLength, Key, KeySizeUser},
};

/// Simplified HMAC instance able to operate over hash functions
/// which do not expose block-level API and hash functions which
/// process blocks lazily (e.g. BLAKE2).
#[derive(Clone)]
pub struct SimpleHmac<D: Digest + BlockSizeUser> {
    digest: D,
    opad_key: Block<D>,
}

impl<D: Digest + BlockSizeUser> KeySizeUser for SimpleHmac<D> {
    type KeySize = D::BlockSize;
}

impl<D: Digest + BlockSizeUser> MacMarker for SimpleHmac<D> {}

impl<D: Digest + BlockSizeUser> KeyInit for SimpleHmac<D> {
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key.as_slice()).expect("HMAC accepts keys of any length")
    }

    #[inline]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        let mut buf = get_der_key::<D>(key);
        buf.iter_mut().for_each(|b: &mut u8| *b ^= IPAD);

        let mut digest = D::new();
        digest.update(&buf);

        buf.iter_mut().for_each(|b: &mut u8| *b ^= OPAD ^ IPAD);

        Ok(Self {
            digest,
            opad_key: buf,
        })
    }
}

impl<D: Digest + BlockSizeUser> Update for SimpleHmac<D> {
    #[inline(always)]
    fn update(&mut self, data: &[u8]) {
        self.digest.update(data);
    }
}

impl<D: Digest + BlockSizeUser> OutputSizeUser for SimpleHmac<D> {
    type OutputSize = D::OutputSize;
}

impl<D: Digest + BlockSizeUser> FixedOutput for SimpleHmac<D> {
    fn finalize_into(mut self, out: &mut Output<Self>) {
        let mut h = D::new();
        h.update(&self.opad_key);
        h.update(core::mem::replace(&mut self.digest, D::new()).finalize());
        h.finalize_into(out);
    }
}

impl<D: Digest + BlockSizeUser + fmt::Debug> fmt::Debug for SimpleHmac<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SimpleHmac { ... }")
    }
}

// DE: PQKeep-Ergänzung: Zustände bleiben in caller-owned, gesperrtem Speicher.
// EN: PQKeep addition: state stays in caller-owned locked storage.
impl<D> SimpleHmac<D>
where
    D: Digest + BlockSizeUser + digest::FixedOutputReset,
{
    /// Rekey in place; scratch must be caller-owned protected memory.
    pub fn rekey_in_place(&mut self, key: &[u8], scratch: &mut Output<D>) {
        use digest::typenum::Unsigned;
        self.digest = D::new();
        self.opad_key.fill(0);
        let key = if key.len() > D::BlockSize::USIZE {
            Digest::update(&mut self.digest, key);
            digest::FixedOutputReset::finalize_into_reset(&mut self.digest, scratch);
            scratch.as_slice()
        } else { key };
        self.opad_key[..key.len()].copy_from_slice(key);
        self.opad_key.iter_mut().for_each(|b| *b ^= IPAD);
        Digest::update(&mut self.digest, &self.opad_key);
        self.opad_key.iter_mut().for_each(|b| *b ^= OPAD ^ IPAD);
    }

    /// Finalize without moving keyed state; scratch/out must be protected.
    pub fn finalize_in_place(&mut self, scratch: &mut Output<D>, out: &mut Output<D>) {
        digest::FixedOutputReset::finalize_into_reset(&mut self.digest, scratch);
        Digest::update(&mut self.digest, &self.opad_key);
        Digest::update(&mut self.digest, &*scratch);
        digest::FixedOutputReset::finalize_into_reset(&mut self.digest, out);
    }
}

#[cfg(feature = "zeroize")]
impl<D: Digest + BlockSizeUser> Drop for SimpleHmac<D> {
    fn drop(&mut self) {
        use digest::zeroize::Zeroize;
        self.opad_key.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<D: Digest + BlockSizeUser + digest::zeroize::ZeroizeOnDrop> digest::zeroize::Zeroize for SimpleHmac<D> {
    fn zeroize(&mut self) {
        self.digest = D::new();
        self.opad_key.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<D: Digest + BlockSizeUser + digest::zeroize::ZeroizeOnDrop> digest::zeroize::ZeroizeOnDrop for SimpleHmac<D> {}

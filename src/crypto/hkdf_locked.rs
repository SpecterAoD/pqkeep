//! DE: RustCrypto-HKDF mit gesperrten, festen Zustands-/Zwischenpuffern.
//! EN: RustCrypto HKDF with locked fixed state/intermediate buffers.

use hkdf::InPlaceHmac;
use hmac::SimpleHmac;
use sha3::Sha3_256;
use sha3::digest::{Output, OutputSizeUser, Update, consts::U32};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::SecretBytes;
use super::secret_buffer::SecretBuffer;
use super::{locked_hash::output_view, secret_workspace::SecretWorkspace};
use crate::Result;

struct LockedHmac {
    state: SecretWorkspace<SimpleHmac<Sha3_256>>,
    scratch: SecretWorkspace<Output<Sha3_256>>,
}

// DE: Nur diese geprüften Typen: HMAC-Drop löscht Zustand, Buffer-Drop volle Kapazität.
// EN: Only these reviewed types: HMAC drop wipes state; buffer drop wipes full capacity.
impl ZeroizeOnDrop for SecretBuffer<SimpleHmac<Sha3_256>> {}
impl ZeroizeOnDrop for SecretBuffer<Output<Sha3_256>> {}

impl LockedHmac {
    fn new() -> Result<Self> {
        use hmac::KeyInit;
        // DE: Descriptor und Kapazität vor öffentlicher Initialisierung/privatem Rekey sperren.
        // EN: Lock descriptor/capacity before public initialization or private rekey.
        let mut state = SecretWorkspace::with_capacity(1)?;
        state.push_preallocated(
            SimpleHmac::<Sha3_256>::new_from_slice(&[]).map_err(|_| crate::Error::Crypto)?,
        )?;
        Ok(Self {
            state,
            scratch: SecretWorkspace::zeroed(1)?,
        })
    }
}

impl OutputSizeUser for LockedHmac {
    type OutputSize = U32;
}

impl InPlaceHmac for LockedHmac {
    fn rekey(&mut self, key: &[u8]) {
        self.state.expose_mut()[0].rekey_in_place(key, &mut self.scratch.expose_mut()[0]);
        self.scratch.expose_mut()[0].zeroize();
    }

    fn update(&mut self, data: &[u8]) {
        self.state.expose_mut()[0].update(data);
    }

    fn finalize_into(&mut self, out: &mut Output<Self>) {
        self.state.expose_mut()[0].finalize_in_place(&mut self.scratch.expose_mut()[0], out);
        self.scratch.expose_mut()[0].zeroize();
    }
}

pub(super) fn derive(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<SecretBytes> {
    let mut mac = LockedHmac::new()?;
    let mut prk = SecretBytes::zeroed(size_of::<Output<Sha3_256>>())?;
    let mut out = SecretBytes::zeroed(size_of::<Output<Sha3_256>>())?;
    hkdf::derive_first_block_in_place(
        &mut mac,
        salt,
        ikm,
        info,
        output_view::<Sha3_256>(&mut prk)?,
        output_view::<Sha3_256>(&mut out)?,
    );
    Ok(out)
}

#[cfg(test)]
#[path = "hkdf_workspace_tests.rs"]
mod tests;

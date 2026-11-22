//! DE: RustCrypto-HKDF mit gesperrten, festen Zustands-/Zwischenpuffern.
//! EN: RustCrypto HKDF with locked fixed state/intermediate buffers.

use hkdf::InPlaceHmac;
use hmac::SimpleHmac;
use sha3::Sha3_256;
use sha3::digest::{Output, OutputSizeUser, Update, consts::U32};
use zeroize::Zeroize;

use super::SecretBytes;
use super::secret_buffer::SecretBuffer;
use crate::Result;

struct LockedHmac {
    state: SecretBuffer<SimpleHmac<Sha3_256>>,
    scratch: SecretBuffer<Output<Sha3_256>>,
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
    use hmac::KeyInit;
    // DE: Nur ein öffentlicher leerer Schlüssel vor dem Sperren; Secret-Rekey erst danach.
    // EN: Only a public empty key before locking; secret rekey happens afterwards.
    let state = SimpleHmac::<Sha3_256>::new_from_slice(&[]).map_err(|_| crate::Error::Crypto)?;
    let mut mac = LockedHmac {
        state: SecretBuffer::new(vec![state])?,
        scratch: SecretBuffer::new(vec![Output::<Sha3_256>::default()])?,
    };
    let mut prk = SecretBuffer::new(vec![Output::<Sha3_256>::default()])?;
    let mut out = SecretBuffer::new(vec![Output::<Sha3_256>::default()])?;
    hkdf::derive_first_block_in_place(
        &mut mac,
        salt,
        ikm,
        info,
        &mut prk.expose_mut()[0],
        &mut out.expose_mut()[0],
    );
    SecretBytes::from_slice(&out.expose()[0])
}

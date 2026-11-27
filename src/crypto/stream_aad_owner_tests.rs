//! DE: Auch vertrauliche Bibliotheks-AAD bleibt im tatsächlichen Stream-Owner gesperrt.
//! EN: Confidential library AAD remains locked in the actual stream owner.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::locked_owner_test_support::locked;

#[test]
fn streaming_types_preserve_send_sync_and_unwind_traits() {
    fn traits<T: Send + Sync + std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
    traits::<Aes256Gcm>();
    traits::<EncryptWriter<Vec<u8>>>();
    traits::<DecryptReader<std::io::Cursor<Vec<u8>>>>();
}

#[test]
fn stream_retains_aad_in_locked_owner_through_private_operations() {
    let key = crate::crypto::rng::secret(32).unwrap();
    let message = crate::crypto::rng::secret(129).unwrap();
    for length in [0, 1, 4095, 4096, 4097, 8193] {
        let aad = crate::crypto::rng::secret(length).unwrap();
        let prefix = crate::crypto::rng::array::<PREFIX_LEN>().unwrap();
        let mut encrypt = Stream::new(key.expose(), prefix, aad.expose()).unwrap();
        locked(encrypt.aad.expose());
        locked(encrypt.cipher.get());
        let address = encrypt.aad.expose().as_ptr().addr();
        let ciphertext = encrypt.seal(message.expose(), true).unwrap();
        let mut decrypt = Stream::new(key.expose(), prefix, aad.expose()).unwrap();
        locked(decrypt.aad.expose());
        let plaintext = decrypt.open(&ciphertext, true).unwrap();
        let matches = plaintext.expose() == message.expose();
        assert!(matches);
        let stable = encrypt.aad.expose().as_ptr().addr() == address;
        assert!(stable);
        locked(encrypt.aad.expose());
        locked(decrypt.aad.expose());
    }
}

//! DE: Echte AEAD-Adaptergrenze vor der Backend-Verarbeitung prüfen.
//! EN: Inspect the real AEAD adapter boundary before backend processing.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::aead::{AeadCore, AeadInOut, Error, Nonce, Tag, TagPosition, consts};

struct Backend(bool);
impl AeadCore for Backend {
    type NonceSize = consts::U12;
    type TagSize = consts::U16;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl AeadInOut for Backend {
    fn encrypt_inout_detached(
        &self,
        _nonce: &Nonce<Self>,
        _aad: &[u8],
        mut work: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>, Error> {
        if !work.is_empty() {
            assert!(crate::hardening::memlock::is_locked(
                work.get_in().as_ptr().addr()
            ));
        }
        assert!(work.get_in().iter().all(|b| *b == 0x5a));
        if self.0 {
            return Err(Error);
        }
        // DE: Nur synthetischer Messadapter, keine eigene Kryptografie.
        // EN: Synthetic measuring backend only, not a cryptographic algorithm.
        work.get_out().fill(0x81);
        Ok(Tag::<Self>::default())
    }

    fn decrypt_inout_detached(
        &self,
        _nonce: &Nonce<Self>,
        _aad: &[u8],
        _work: InOutBuf<'_, '_, u8>,
        _tag: &Tag<Self>,
    ) -> Result<(), Error> {
        Err(Error)
    }
}

#[test]
fn adapter_locks_before_backend_and_copies_only_transformed_bytes() {
    for len in [0, 1, 32, 8191, 8192, 8193, 65535, 65536, 65537] {
        let input = vec![0x5a; len];
        let out = super::seal_locked(&Backend(false), [0; 12], &input, b"aad").unwrap();
        assert_eq!(out.len(), len + 16);
        assert!(out[..len].iter().all(|b| *b == 0x81));
        assert!(out[len..].iter().all(|b| *b == 0));
        assert!(input.iter().all(|b| *b == 0x5a));
    }
}

#[test]
fn backend_failure_never_returns_private_output() {
    assert!(matches!(
        super::seal_locked(&Backend(true), [0; 12], &[0x5a; 32], b""),
        Err(crate::Error::Crypto)
    ));
}

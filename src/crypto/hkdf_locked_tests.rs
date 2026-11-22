//! DE: Bytegleiche Ableitung zur unveränderten RustCrypto-API.
//! EN: Byte-identical derivation against the unchanged RustCrypto API.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{SecretBytes, rng};
use sha3::Sha3_256;

#[test]
fn locked_hkdf_matches_upstream_at_hmac_boundaries() {
    for n in [0, 1, 32, 135, 136, 137, 1568] {
        let salt = rng::secret(n).unwrap();
        let ikm = rng::secret(32).unwrap();
        let info = rng::secret(17).unwrap();
        let mut expected = SecretBytes::zeroed(32).unwrap();
        hkdf::SimpleHkdf::<Sha3_256>::new(Some(salt.expose()), ikm.expose())
            .expand(info.expose(), expected.expose_mut())
            .unwrap();
        let actual =
            super::hkdf_locked::derive(salt.expose(), ikm.expose(), info.expose()).unwrap();
        assert!(actual.is_locked() && actual.expose() == expected.expose());
    }
}

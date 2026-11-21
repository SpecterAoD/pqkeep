//! DE: RKEY-001–003: Identität, Authentifizierung und KDF bei v1/v2.
//! EN: RKEY-001–003: identity, authentication and KDF for v1/v2.
// DE: Boolean-Vergleiche verhindern Secret-/Container-Dumps bei Fehlern.
// EN: Boolean comparisons avoid secret/container dumps on assertion failures.
#![allow(clippy::unwrap_used, clippy::manual_assert_eq)]

mod common;

use common::rekey::Fixture;
use pqkeep::crypto::{DsaAlgorithm, KemAlgorithm, KeyAlgorithm};
use pqkeep::{Error, envelope::KeyFile};

fn algorithms() -> [KeyAlgorithm; 7] {
    [
        KeyAlgorithm::Kem(KemAlgorithm::MlKem512),
        KeyAlgorithm::Kem(KemAlgorithm::MlKem768),
        KeyAlgorithm::Kem(KemAlgorithm::MlKem1024),
        KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa44),
        KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa65),
        KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87),
        KeyAlgorithm::Aes256,
    ]
}

#[test]
fn rkey001_002_all_algorithms_and_formats_preserve_identity() {
    for v2 in [false, true] {
        for algorithm in algorithms() {
            let f = Fixture::new(v2, algorithm);
            let before = f.key.to_json().unwrap();
            let changed = f
                .key
                .rekey(f.old.as_ref(), &f.new, f.factor.as_ref(), None)
                .unwrap();
            f.assert_identity(&changed);
            assert_eq!(changed.kdf_params(), f.key.kdf_params());
            let old: serde_json::Value = serde_json::from_str(&before).unwrap();
            let new: serde_json::Value = serde_json::from_str(&changed.to_json().unwrap()).unwrap();
            assert!(old["kdf"]["salt"] != new["kdf"]["salt"]);
            assert!(old["cipher"]["nonce"] != new["cipher"]["nonce"]);
            assert!(f.key.to_json().unwrap() == before);
            f.assert_identity(&KeyFile::from_json(&changed.to_json().unwrap()).unwrap());
        }
    }
}

#[test]
fn rkey002_003_wrong_credentials_tamper_and_factor_mismatch_fail() {
    for v2 in [false, true] {
        let f = Fixture::new(v2, KeyAlgorithm::Aes256);
        assert!(matches!(
            f.key.rekey(f.new.as_ref(), &f.new, f.factor.as_ref(), None),
            Err(Error::Decrypt)
        ));
        let other = pqkeep::crypto::factor::Factor::from_bytes(
            &pqkeep::crypto::rng::array::<32>().unwrap(),
        )
        .unwrap();
        if v2 {
            assert!(matches!(
                f.key.rekey(f.old.as_ref(), &f.new, None, None),
                Err(Error::InvalidInput {
                    field: "factor_required"
                })
            ));
            assert!(matches!(
                f.key.rekey(f.old.as_ref(), &f.new, Some(&other), None),
                Err(Error::Decrypt)
            ));
        } else {
            assert!(matches!(
                f.key.rekey(f.old.as_ref(), &f.new, Some(&other), None),
                Err(Error::InvalidInput {
                    field: "factor_unused"
                })
            ));
        }
        let mut json: serde_json::Value = serde_json::from_str(&f.key.to_json().unwrap()).unwrap();
        json["metadata"]["name"] = "Tampered".into();
        let damaged = KeyFile::from_json(&json.to_string()).unwrap();
        assert!(matches!(
            damaged.rekey(f.old.as_ref(), &f.new, f.factor.as_ref(), None),
            Err(Error::Decrypt)
        ));
    }
}

#[test]
fn rkey003_kdf_reductions_and_invalid_bounds_fail_but_upgrade_works() {
    let f = Fixture::new(false, KeyAlgorithm::Aes256);
    let mut params = f.key.kdf_params();
    params.memory_kib = 0;
    assert!(matches!(
        f.key.rekey(f.old.as_ref(), &f.new, None, Some(&params)),
        Err(Error::KdfParams)
    ));
    params = f.key.kdf_params();
    params.iterations += 1;
    let stronger = f
        .key
        .rekey(f.old.as_ref(), &f.old, None, Some(&params))
        .unwrap();
    assert_eq!(stronger.kdf_params(), params);
    assert!(matches!(
        stronger.rekey(f.old.as_ref(), &f.new, None, Some(&f.key.kdf_params())),
        Err(Error::InvalidInput {
            field: "kdf_downgrade"
        })
    ));
    let changed = stronger.rekey(f.old.as_ref(), &f.new, None, None).unwrap();
    f.assert_identity(&changed);
}

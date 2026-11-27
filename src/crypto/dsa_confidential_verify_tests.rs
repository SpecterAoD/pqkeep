//! DE: Echte verborgene Verifikationspfade gegen ursprüngliche öffentliche Arithmetik.
//! EN: Compare actual hidden verification paths with original public arithmetic.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{
    crypto::{SecretBytes, rng},
    locked_owner_test_support::locked,
};

fn check_storage<P: MlDsaParams>(state: &State<P>) -> Vec<(usize, usize)> {
    locked(state.work.get());
    let mut rows = Vec::new();
    assert!(state.work.get().visit_private_storage(|address, len| {
        assert!(crate::hardening::memlock::is_locked(address));
        assert!(crate::hardening::memlock::is_locked(address + len - 1));
        #[cfg(target_os = "linux")]
        assert!(crate::locked_owner_test_support::own_mapping_locked(
            address
        ));
        rows.push((address, len));
        true
    }));
    assert_eq!(rows.len(), state.work.get().private_storage_count());
    rows
}

fn compare<P: MlDsaParams>(algorithm: DsaAlgorithm) {
    let key = super::super::generate(algorithm).unwrap();
    let public = SecretBytes::from_slice(&key.public_key).unwrap();
    let mut state = State::<P>::new().unwrap();
    let rows = check_storage(&state);
    for (message_len, context_len) in [(0, 0), (193, 255), (65_537, 17)] {
        let message = rng::secret(message_len).unwrap();
        let context = rng::secret(context_len).unwrap();
        let signature = super::super::sign_confidential(
            algorithm,
            key.seed().expose(),
            message.expose(),
            context.expose(),
        )
        .unwrap();
        let pk: &EncodedVerifyingKey<P> = public.expose().try_into().unwrap();
        let sig: &EncodedSignature<P> = signature.expose().try_into().unwrap();
        let valid =
            state
                .work
                .get_mut()
                .verify_encoded(pk, message.expose(), context.expose(), sig);
        assert!(valid);
        let actual = verify(
            algorithm,
            public.expose(),
            message.expose(),
            context.expose(),
            signature.expose(),
        )
        .unwrap();
        assert!(actual);
        let owners_unchanged = check_storage(&state) == rows;
        assert!(owners_unchanged);
        compare_tampering(algorithm, &public, &message, &context, &signature);
        state.work.get_mut().zeroize();
        let owners_unchanged = check_storage(&state) == rows;
        assert!(owners_unchanged);
        let valid =
            state
                .work
                .get_mut()
                .verify_encoded(pk, message.expose(), context.expose(), sig);
        assert!(valid);
    }
    assert_eq!(
        format!("{:?}", state.work.get()),
        "ConfidentialVerificationWorkspace { .. }"
    );
}

fn compare_tampering(
    algorithm: DsaAlgorithm,
    key: &SecretBytes,
    message: &SecretBytes,
    context: &SecretBytes,
    signature: &SecretBytes,
) {
    // DE: Öffentliche Referenz ausschließlich für diese Test-Gegenprobe.
    // EN: Public reference used only for this test comparison.
    assert!(super::super::verify(
        algorithm,
        key.expose(),
        message.expose(),
        context.expose(),
        signature.expose()
    ));
    let mut changed = SecretBytes::from_slice(signature.expose()).unwrap();
    for index in [0, 1, 32, changed.len() / 2, changed.len() - 1] {
        changed.expose_mut()[index] ^= 1;
        let expected = super::super::verify(
            algorithm,
            key.expose(),
            message.expose(),
            context.expose(),
            changed.expose(),
        );
        let actual = verify(
            algorithm,
            key.expose(),
            message.expose(),
            context.expose(),
            changed.expose(),
        )
        .unwrap();
        assert!(!expected);
        assert_eq!(actual, expected);
        changed.expose_mut()[index] ^= 1;
    }
    malformed_inputs(algorithm, key, message, context, signature, &mut changed);
}

fn malformed_inputs(
    algorithm: DsaAlgorithm,
    key: &SecretBytes,
    message: &SecretBytes,
    context: &SecretBytes,
    signature: &SecretBytes,
    changed: &mut SecretBytes,
) {
    let last = changed.len() - 1;
    changed.expose_mut()[last] = 255;
    assert!(
        !verify(
            algorithm,
            key.expose(),
            message.expose(),
            context.expose(),
            changed.expose()
        )
        .unwrap()
    );
    assert!(
        !verify(
            algorithm,
            &key.expose()[..key.len() - 1],
            message.expose(),
            context.expose(),
            signature.expose()
        )
        .unwrap()
    );
    assert!(
        !verify(
            algorithm,
            key.expose(),
            message.expose(),
            context.expose(),
            &signature.expose()[..signature.len() - 1]
        )
        .unwrap()
    );
    assert!(
        !verify(
            algorithm,
            key.expose(),
            message.expose(),
            &[0; 256],
            signature.expose()
        )
        .unwrap()
    );
}

#[test]
fn hidden_verification_matches_original_for_all_parameter_sets_and_tampering() {
    compare::<MlDsa44>(DsaAlgorithm::MlDsa44);
    compare::<MlDsa65>(DsaAlgorithm::MlDsa65);
    compare::<MlDsa87>(DsaAlgorithm::MlDsa87);
}

//! DE: Interner Test des Argon2id-Kerns mit dem offiziellen Testvektor aus
//! RFC 9106, Abschnitt 5.3 (32 KiB – unterhalb der öffentlichen Mindestgrenze,
//! daher nur intern über `argon2id` prüfbar). Sichert die Verdrahtung ab:
//! Variante Argon2id, Version 0x13, Parameterreihenfolge, Secret und AD.
//!
//! EN: Internal test of the Argon2id core with the official test vector from
//! RFC 9106, section 5.3 (32 KiB – below the public minimum, so only testable
//! internally via `argon2id`). Guards the wiring: variant Argon2id, version
//! 0x13, parameter order, secret and AD.

use super::{KdfParams, argon2id};

/// DE: Erwarteter Tag laut RFC 9106. EN: Expected tag per RFC 9106.
const RFC9106_TAG: [u8; 32] = [
    0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
    0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
];

fn rfc_params() -> KdfParams {
    KdfParams {
        memory_kib: 32,
        iterations: 3,
        parallelism: 4,
    }
}

#[test]
fn rfc9106_argon2id_vector() {
    let mut out = [0u8; 32];
    argon2id(
        &[0x01; 32],
        &[0x02; 16],
        &rfc_params(),
        &[0x03; 8],
        &[0x04; 12],
        &mut out,
    )
    .unwrap();
    assert_eq!(out, RFC9106_TAG);
}

#[test]
fn rfc9106_vector_detects_changed_inputs() {
    // DE: Ohne Secret bzw. AD muss ein anderer Tag entstehen.
    // EN: Without secret or AD a different tag must result.
    let mut no_secret = [0u8; 32];
    argon2id(
        &[0x01; 32],
        &[0x02; 16],
        &rfc_params(),
        &[],
        &[0x04; 12],
        &mut no_secret,
    )
    .unwrap();
    let mut no_ad = [0u8; 32];
    argon2id(
        &[0x01; 32],
        &[0x02; 16],
        &rfc_params(),
        &[0x03; 8],
        &[],
        &mut no_ad,
    )
    .unwrap();
    assert_ne!(no_secret, RFC9106_TAG);
    assert_ne!(no_ad, RFC9106_TAG);
    assert_ne!(no_secret, no_ad);
}

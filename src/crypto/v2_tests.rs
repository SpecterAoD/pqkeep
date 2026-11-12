//! DE: Interner Test der HKDF-Schritte von Format v2 gegen die Sollwerte V07 aus
//! `scripts/test_v2_vectors.py` (unabhängig mit Python `cryptography` berechnet). Sichert die
//! Verdrahtung: Hashfunktion, Rollen von Salt/IKM/Info, Domänen, Faktorbyte, Empfänger-ID.
//! Die vollständige Kette mit Argon2id prüft `tests/crypto_v2_kat.rs`.
//!
//! EN: Internal test of the HKDF steps of format v2 against the expected values V07 from
//! `scripts/test_v2_vectors.py` (computed independently with Python `cryptography`). Guards
//! the wiring: hash function, roles of salt/IKM/info, domains, factor byte, recipient ID.
//! The full chain with Argon2id is checked by `tests/crypto_v2_kat.rs`.

use super::{Domain, expand_passphrase, recipient_kek};

const PASSPHRASE: [(Domain, bool, &str); 4] = [
    (
        Domain::File,
        false,
        "4f41ede1889d37fa2f68f1031731f3ea4cc88ab7454660cb7f2821f282f3cedc",
    ),
    (
        Domain::File,
        true,
        "c40e01558262cea41d40fba3465a8b2c32ce672d2a10a53b45957298a37a8fc0",
    ),
    (
        Domain::Key,
        false,
        "8cb9342828047ad1138230e9b69f1b3acbc5dd74cd1d2c6b3c043aad423d715b",
    ),
    (
        Domain::Key,
        true,
        "3d9c5c935d84946e6cbdcab4922bd2a617fd926c36d0909dd9d85fc012dd95ba",
    ),
];
const RECIPIENT: &str = "f9b1412d2ef25deb302da555f52f68e8b6dd4650f6f12f2cbcac0e8676524cf1";

/// DE: Bytes `from`, `from + 1`, … (wie `bytes(range(...))`). EN: Counting bytes.
fn counting<const N: usize>(from: u8) -> [u8; N] {
    let mut out = [0u8; N];
    let mut value = from;
    for byte in &mut out {
        *byte = value;
        value = value.wrapping_add(1);
    }
    out
}

#[test]
fn v07_passphrase_slot_vectors() {
    let (b, salt) = (counting::<32>(0), counting::<32>(32));
    for (domain, factor, expected) in PASSPHRASE {
        let key = expand_passphrase(domain, &b, &salt, factor).unwrap();
        assert_eq!(hex::encode(key.expose()), expected, "{domain:?} {factor}");
    }
}

#[test]
fn v07_recipient_slot_vector() {
    let (shared, id) = (counting::<32>(64), counting::<32>(96));
    let ciphertext = counting::<1568>(0);
    let key = recipient_kek(&shared, &ciphertext, &id).unwrap();
    assert_eq!(hex::encode(key.expose()), RECIPIENT);
}

#[test]
fn recipient_inputs_all_matter() {
    let (shared, id) = (counting::<32>(64), counting::<32>(96));
    let ciphertext = counting::<1088>(0);
    let base = recipient_kek(&shared, &ciphertext, &id).unwrap();
    let variants = [
        recipient_kek(&counting::<32>(65), &ciphertext, &id).unwrap(),
        recipient_kek(&shared, &counting::<1088>(1), &id).unwrap(),
        recipient_kek(&shared, &ciphertext, &counting::<32>(97)).unwrap(),
        // DE: Vertauschte Rollen von Salt und IKM. EN: Swapped roles of salt and IKM.
        recipient_kek(&ciphertext, &shared, &id).unwrap(),
    ];
    for variant in &variants {
        assert_ne!(variant.expose(), base.expose());
    }
}

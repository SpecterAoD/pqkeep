//! DE: Schlüsseldatei v2 mit Faktordatei (C07, Schlüsseldatei-Teil von C06 aus
//! `docs/V2_TESTS.md`): Rundlauf aller Algorithmen mit unverändertem Seed, Version 1 bleibt wie
//! sie ist, die Faktordatei wird nie stillschweigend ignoriert, falscher Faktor und jede
//! Manipulation scheitern, Versionen lassen sich nicht ineinander umschreiben.
//!
//! EN: Key file v2 with factor file (C07, key file part of C06 in `docs/V2_TESTS.md`): round
//! trip of all algorithms with unchanged seed, version 1 stays as it is, the factor file is
//! never silently ignored, a wrong factor and any tampering fail, versions cannot be rewritten
//! into each other.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqkeep::Error;
use pqkeep::crypto::factor::Factor;
use pqkeep::crypto::{ALL_ALGORITHMS, KeyAlgorithm, SecretBytes, aead, dsa, kem};
use pqkeep::envelope::{FORMAT_VERSION, FORMAT_VERSION_V2, KeyFile, Metadata};
use pqkeep::security::StrongPassphrase;
use serde_json::{Value, json};

const BAD_FACTOR: Error = Error::InvalidInput {
    field: "kdf_factor",
};
const REQUIRED: Error = Error::InvalidInput {
    field: "factor_required",
};
const UNUSED: Error = Error::InvalidInput {
    field: "factor_unused",
};

/// DE: Neues Material: (Seed bzw. AES-Schlüssel, öffentlicher Schlüssel).
/// EN: Fresh material: (seed or AES key, public key).
fn material(algorithm: KeyAlgorithm) -> (SecretBytes, Vec<u8>) {
    match algorithm {
        KeyAlgorithm::Kem(a) => {
            let pair = kem::generate(a).unwrap();
            (
                SecretBytes::from_slice(pair.seed().expose()),
                pair.public_key,
            )
        }
        KeyAlgorithm::Dsa(a) => {
            let pair = dsa::generate(a).unwrap();
            (
                SecretBytes::from_slice(pair.seed().expose()),
                pair.public_key,
            )
        }
        KeyAlgorithm::Aes256 => (aead::generate_key().unwrap(), Vec::new()),
    }
}

struct Fixture {
    file: KeyFile,
    pass: StrongPassphrase,
    factor: Factor,
}

fn fixture(algorithm: KeyAlgorithm) -> Fixture {
    let pass = common::random_passphrase();
    let factor = common::v2_files::factor();
    let meta = Metadata {
        organization: Some("Example Org".to_owned()),
        ..Metadata::with_name("Test User")
    };
    let params = common::min_params();
    let file = KeyFile::generate_with_factor(&pass, &factor, algorithm, &meta, &params).unwrap();
    Fixture { file, pass, factor }
}

/// DE: JSON der Datei mit einer Änderung. EN: The file's JSON with one change.
fn changed(file: &KeyFile, change: impl FnOnce(&mut Value)) -> String {
    let mut doc: Value = serde_json::from_str(&file.to_json().unwrap()).unwrap();
    change(&mut doc);
    serde_json::to_string(&doc).unwrap()
}

#[test]
fn c07_all_algorithms_roundtrip_with_unchanged_seed() {
    let pass = common::random_passphrase();
    let factor = common::v2_files::factor();
    let meta = Metadata::with_name("Test User");
    let params = common::min_params();
    for alg in ALL_ALGORITHMS {
        let (seed, public) = material(alg);
        let file = KeyFile::create_with_factor(
            &pass,
            &factor,
            alg,
            seed.expose(),
            &public,
            &meta,
            &params,
        )
        .unwrap();
        assert_eq!(file.format_version(), FORMAT_VERSION_V2);
        let json = file.to_json().unwrap();
        assert!(json.contains("\"format_version\": 2"), "{alg:?}");
        assert!(json.contains("\"factor\": \"file-32\""), "{alg:?}");
        let parsed = KeyFile::from_json(&json).unwrap();
        assert_eq!(parsed, file, "{alg:?}");
        assert_eq!(parsed.to_json().unwrap(), json, "stabil / stable");
        let unlocked = parsed.unlock_with_factor(pass.as_ref(), &factor).unwrap();
        assert_eq!(unlocked.algorithm, alg);
        assert_eq!(unlocked.secret().expose(), seed.expose(), "{alg:?}");
        assert_eq!(unlocked.public_key, public);
    }
}

#[test]
fn c07_public_part_and_key_id_do_not_depend_on_the_version() {
    let alg = KeyAlgorithm::Kem(pqkeep::crypto::KemAlgorithm::default());
    let (seed, public) = material(alg);
    let pass = common::random_passphrase();
    let factor = common::v2_files::factor();
    let meta = Metadata::with_name("Test User");
    let params = common::min_params();
    let v1 = KeyFile::create(&pass, alg, seed.expose(), &public, &meta, &params).unwrap();
    let v2 =
        KeyFile::create_with_factor(&pass, &factor, alg, seed.expose(), &public, &meta, &params)
            .unwrap();
    assert_eq!(v1.key_id(), v2.key_id());
    assert_eq!(
        v1.public_part().unwrap().public_key(),
        v2.public_part().unwrap().public_key()
    );
}

#[test]
fn c06_version_1_is_unchanged_and_factor_is_never_ignored() {
    let (v1, v1_pass) = common::key_file(KeyAlgorithm::Aes256);
    let json = v1.to_json().unwrap();
    assert_eq!(v1.format_version(), FORMAT_VERSION);
    assert!(!v1.needs_factor());
    assert!(json.contains("\"format_version\": 1"));
    assert!(!json.contains("factor"));
    let factor = common::v2_files::factor();
    let with_factor = v1.unlock_with_factor(v1_pass.as_ref(), &factor);
    assert_eq!(with_factor.err(), Some(UNUSED));
    assert!(v1.unlock(v1_pass.as_ref()).is_ok());

    // DE: Version 2 ohne Faktor: klare Meldung, auch bei falscher Passphrase (vor Argon2id).
    // EN: Version 2 without factor: clear message, also for a wrong passphrase (before Argon2id).
    let v2 = fixture(KeyAlgorithm::Aes256);
    assert!(v2.file.needs_factor());
    assert_eq!(v2.file.unlock(v2.pass.as_ref()).err(), Some(REQUIRED));
    let wrong = common::passphrase("falsch / wrong");
    assert_eq!(v2.file.unlock(&wrong).err(), Some(REQUIRED));
}

#[test]
fn c07_wrong_factor_or_passphrase_fail_alike() {
    let f = fixture(KeyAlgorithm::Dsa(pqkeep::crypto::DsaAlgorithm::default()));
    let other = common::v2_files::factor();
    let wrong = common::passphrase("falsch / wrong");
    let wrong_factor = f.file.unlock_with_factor(f.pass.as_ref(), &other);
    assert_eq!(wrong_factor.err(), Some(Error::Decrypt));
    let wrong_passphrase = f.file.unlock_with_factor(&wrong, &f.factor);
    assert_eq!(wrong_passphrase.err(), Some(Error::Decrypt));
    assert!(
        f.file
            .unlock_with_factor(f.pass.as_ref(), &f.factor)
            .is_ok()
    );
}

#[test]
fn c07_version_and_factor_field_are_checked_strictly() {
    let v2 = fixture(KeyAlgorithm::Aes256).file;
    let (v1, _) = common::key_file(KeyAlgorithm::Aes256);
    let parse = |text: String| KeyFile::from_json(&text).err();
    let drop_factor = |doc: &mut Value| {
        doc["kdf"].as_object_mut().unwrap().remove("factor");
    };
    assert_eq!(parse(changed(&v2, drop_factor)), Some(BAD_FACTOR));
    assert_eq!(
        parse(changed(&v2, |d| d["format_version"] = json!(1))),
        Some(BAD_FACTOR)
    );
    assert_eq!(
        parse(changed(&v1, |d| d["format_version"] = json!(2))),
        Some(BAD_FACTOR)
    );
    assert_eq!(
        parse(changed(&v1, |d| d["kdf"]["factor"] = json!("file-32"))),
        Some(BAD_FACTOR)
    );
    for other in [json!("file-64"), json!(""), json!("FILE-32")] {
        let text = changed(&v2, |d| d["kdf"]["factor"] = other);
        assert_eq!(parse(text), Some(BAD_FACTOR));
    }
    for other in [json!(null), json!(1), json!(true)] {
        let text = changed(&v2, |d| d["kdf"]["factor"] = other);
        assert_eq!(parse(text), Some(Error::InvalidInput { field: "json" }));
    }
    for version in [0, 3, 4, u32::MAX] {
        let text = changed(&v2, |d| d["format_version"] = json!(version));
        assert_eq!(parse(text), Some(Error::Unsupported), "{version}");
    }
    let text = changed(&v2, |d| d["kdf"]["faktor"] = json!("file-32"));
    assert_eq!(parse(text), Some(Error::InvalidInput { field: "json" }));
}

#[test]
fn c07_versions_cannot_be_rewritten_into_each_other() {
    // DE: v2 → v1 umgeschrieben: liest sich als v1, öffnet aber nicht (andere Ableitung, AAD).
    // EN: v2 rewritten to v1: parses as v1 but does not open (different derivation, AAD).
    let f = fixture(KeyAlgorithm::Aes256);
    let text = changed(&f.file, |d| {
        d["format_version"] = json!(1);
        d["kdf"].as_object_mut().unwrap().remove("factor");
    });
    let downgraded = KeyFile::from_json(&text).unwrap();
    assert_eq!(
        downgraded.unlock(f.pass.as_ref()).err(),
        Some(Error::Decrypt)
    );

    // DE: v1 → v2 umgeschrieben: öffnet mit keiner Faktordatei.
    // EN: v1 rewritten to v2: opens with no factor file at all.
    let (v1, pass) = common::key_file(KeyAlgorithm::Aes256);
    let text = changed(&v1, |d| {
        d["format_version"] = json!(2);
        d["kdf"]["factor"] = json!("file-32");
    });
    let upgraded = KeyFile::from_json(&text).unwrap();
    let opened = upgraded.unlock_with_factor(pass.as_ref(), &f.factor);
    assert_eq!(opened.err(), Some(Error::Decrypt));
    assert_eq!(upgraded.unlock(pass.as_ref()).err(), Some(REQUIRED));
}

/// DE: Tauscht das erste Zeichen eines Base64-Texts, Länge bleibt.
/// EN: Swaps the first character of a Base64 text, length stays.
fn flipped(value: &Value) -> Value {
    let text = value.as_str().unwrap();
    let first = if text.starts_with('A') { "B" } else { "A" };
    json!(format!("{first}{}", &text[1..]))
}

/// DE: Gebundene Felder (Gruppe, Feld, neuer Wert; ohne Wert: erstes Base64-Zeichen tauschen).
/// EN: Bound fields (group, field, new value; without value: swap the first Base64 character).
const CHANGES: [(&str, &str, Option<&str>); 9] = [
    ("metadata", "name", Some("Anderer")),
    ("metadata", "organization", Some("Neu")),
    ("metadata", "company", Some("Neu")),
    ("metadata", "department", Some("Neu")),
    ("metadata", "account_type", Some("Neu")),
    ("kdf", "salt", None),
    ("cipher", "nonce", None),
    ("cipher", "ciphertext", None),
    ("", "created_utc", Some("2020-01-01T00:00:00Z")),
];

#[test]
fn c07_every_authenticated_field_is_bound() {
    let f = fixture(KeyAlgorithm::Aes256);
    let fails = |text: String, name: &str| {
        let tampered = KeyFile::from_json(&text).expect(name);
        let opened = tampered.unlock_with_factor(f.pass.as_ref(), &f.factor);
        assert_eq!(opened.err(), Some(Error::Decrypt), "{name}");
    };
    for (group, field, value) in CHANGES {
        let text = changed(&f.file, |doc| {
            let parent = if group.is_empty() {
                doc
            } else {
                &mut doc[group]
            };
            parent[field] = value.map_or_else(|| flipped(&parent[field]), |v| json!(v));
        });
        fails(text, field);
    }
    let id = "00".repeat(32);
    fails(changed(&f.file, |d| d["key_id"] = json!(id)), "key_id");
    let more = common::min_params().iterations + 1;
    let text = changed(&f.file, |d| d["kdf"]["iterations"] = json!(more));
    fails(text, "iterations");

    // DE: Öffentlicher Schlüssel: die Kennung passt nicht mehr, das fällt schon beim Lesen auf.
    // EN: Public key: the ID no longer matches, which already shows on reading.
    let kem = fixture(KeyAlgorithm::Kem(pqkeep::crypto::KemAlgorithm::default()));
    let text = changed(&kem.file, |d| d["public_key"] = flipped(&d["public_key"]));
    assert!(KeyFile::from_json(&text).is_err());
}

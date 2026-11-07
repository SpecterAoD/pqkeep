//! DE: Roundtrip Datei/Ordner in beiden Modi (Passphrase, ML-KEM-Empfänger),
//! Blockgrenzen, Bericht und `inspect`.
//! EN: Round trip file/directory in both modes (passphrase, ML-KEM recipient),
//! chunk boundaries, report and `inspect`.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqc_keyforge::crypto::{KemAlgorithm, KeyAlgorithm};
use pqc_keyforge::files::{self, Content, HeaderMode, Protection, Unlock};

#[test]
fn single_file_sizes_with_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let pass = common::random_passphrase();
    let protection = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    for size in [0usize, 1, 65_535, 65_536, 65_537, 3 * 1024 * 1024 + 7] {
        let data: Vec<u8> = (0..size).map(|i| u8::try_from(i % 249).unwrap()).collect();
        let src = dir.path().join(format!("in-{size}.bin"));
        let enc = dir.path().join(format!("in-{size}.pqkf"));
        let out = dir.path().join(format!("out-{size}.bin"));
        std::fs::write(&src, &data).unwrap();
        let report = files::encrypt(&src, &enc, &protection).unwrap();
        assert_eq!((report.files, report.bytes), (1, size as u64));
        let report = files::decrypt(&enc, &out, &Unlock::Passphrase(pass.as_ref())).unwrap();
        assert_eq!(report.bytes, size as u64);
        assert_eq!(std::fs::read(&out).unwrap(), data, "size {size}");
    }
}

#[test]
fn directory_with_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("quelle");
    std::fs::create_dir(&src).unwrap();
    common::write_sample_tree(&src);
    let pass = common::random_passphrase();
    let protection = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    let enc = dir.path().join("quelle.pqkf");
    let report = files::encrypt(&src, &enc, &protection).unwrap();
    assert_eq!((report.files, report.directories), (5, 4));
    assert_eq!(report.skipped, vec![]);

    let out = dir.path().join("ziel");
    let back = files::decrypt(&enc, &out, &Unlock::Passphrase(pass.as_ref())).unwrap();
    assert_eq!(
        (back.files, back.directories, back.bytes),
        (5, 4, report.bytes)
    );
    assert_eq!(common::read_tree(&out), common::read_tree(&src));
}

#[test]
fn recipient_mode_all_kem_sets() {
    for alg in [
        KemAlgorithm::MlKem512,
        KemAlgorithm::MlKem768,
        KemAlgorithm::MlKem1024,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (key_file, key_pass) = common::key_file(KeyAlgorithm::Kem(alg));
        let unlocked = key_file.unlock(key_pass.as_ref()).unwrap();
        let src = dir.path().join("baum");
        std::fs::create_dir(&src).unwrap();
        common::write_sample_tree(&src);
        let enc = dir.path().join("baum.pqkf");
        files::encrypt(
            &src,
            &enc,
            &Protection::Recipient(&key_file.public_part().unwrap()),
        )
        .unwrap();
        let out = dir.path().join("zurück");
        files::decrypt(&enc, &out, &Unlock::Key(&unlocked)).unwrap();
        assert_eq!(common::read_tree(&out), common::read_tree(&src), "{alg:?}");
    }
}

#[test]
fn inspect_shows_mode_without_key() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("a.txt");
    std::fs::write(&src, b"x").unwrap();
    let (key_file, _) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let enc = dir.path().join("a.pqkf");
    files::encrypt(
        &src,
        &enc,
        &Protection::Recipient(&key_file.public_part().unwrap()),
    )
    .unwrap();
    let header = files::inspect(&enc).unwrap();
    assert_eq!(header.content, Content::File);
    let HeaderMode::Recipient {
        algorithm,
        recipient_id,
        ..
    } = header.mode
    else {
        unreachable!("falscher Modus / wrong mode");
    };
    assert_eq!(algorithm, KemAlgorithm::MlKem768);
    assert_eq!(recipient_id.as_slice(), key_file.key_id());
}

#[test]
fn empty_directory_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("leer");
    std::fs::create_dir(&src).unwrap();
    let pass = common::random_passphrase();
    let protection = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    let enc = dir.path().join("leer.pqkf");
    files::encrypt(&src, &enc, &protection).unwrap();
    let out = dir.path().join("leer-zurück");
    let report = files::decrypt(&enc, &out, &Unlock::Passphrase(pass.as_ref())).unwrap();
    assert_eq!((report.files, report.directories), (0, 0));
    assert!(out.is_dir());
    assert_eq!(common::read_tree(&out).len(), 0);
}

#[test]
fn same_input_encrypts_differently() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("a.txt");
    std::fs::write(&src, b"gleich / same").unwrap();
    let (key_file, _) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem512));
    let a = dir.path().join("a1.pqkf");
    let b = dir.path().join("a2.pqkf");
    files::encrypt(
        &src,
        &a,
        &Protection::Recipient(&key_file.public_part().unwrap()),
    )
    .unwrap();
    files::encrypt(
        &src,
        &b,
        &Protection::Recipient(&key_file.public_part().unwrap()),
    )
    .unwrap();
    assert_ne!(std::fs::read(a).unwrap(), std::fs::read(b).unwrap());
}

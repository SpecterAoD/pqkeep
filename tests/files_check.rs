//! DE: `files::check` (#86): prüft v1 und v2, Datei und Ordner vollständig, ohne etwas zu
//! schreiben; jede Manipulation, Kürzung und falsche Passphrase/Faktordatei/Schlüssel wird
//! erkannt. Bösartige Archive: `tests/files_malicious.rs` (dort für `decrypt` und `check`).
//! EN: `files::check` (#86): checks v1 and v2, file and directory completely without writing
//! anything; every tampering, truncation and wrong passphrase/factor file/key is detected.
//! Malicious archives: `tests/files_malicious.rs` (there for both `decrypt` and `check`).

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use common::v2_files::{CONTENT, factor, kem_key, workspace};
use pqkeep::Error;
use pqkeep::crypto::KemAlgorithm;
use pqkeep::files::{self, PassphraseAccess, Protection, Unlock};

/// DE: Ordnerinhalt (Namen), um „nichts geschrieben“ zu prüfen. EN: Directory listing.
fn listing(dir: &Path) -> Vec<String> {
    common::dir_names(dir)
}

#[test]
fn v1_file_and_directory_pass_and_nothing_is_written() {
    let w = workspace();
    let pass = common::random_passphrase();
    let protection = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    let enc = w.work.join("a.pqkf");
    files::encrypt(&w.source, &enc, &protection).unwrap();
    let tree = w.dir.path().join("baum");
    common::write_sample_tree(&tree);
    let enc_dir = w.work.join("baum.pqkf");
    files::encrypt(&tree, &enc_dir, &protection).unwrap();

    let before = listing(&w.work);
    let unlock = Unlock::Passphrase(pass.as_ref());
    let report = files::check(&enc, &unlock).unwrap();
    assert_eq!((report.files, report.bytes), (1, CONTENT.len() as u64));
    let decrypted = files::decrypt(&enc_dir, &w.dir.path().join("zurueck"), &unlock).unwrap();
    let checked = files::check(&enc_dir, &unlock).unwrap();
    assert_eq!(checked, decrypted);
    assert_eq!(
        listing(&w.work),
        before,
        "check schreibt nichts / writes nothing"
    );

    let wrong = common::passphrase("eine ganz andere Passphrase 2026!");
    let err = files::check(&enc, &Unlock::Passphrase(&wrong)).unwrap_err();
    assert_eq!(err, Error::Decrypt);
}

#[test]
fn v2_factor_and_several_recipients() {
    let w = workspace();
    let pass = common::random_passphrase();
    let f = factor();
    let (anna, anna_key) = kem_key(KemAlgorithm::MlKem768);
    let (ben, ben_key) = kem_key(KemAlgorithm::MlKem1024);
    let (_, fremd_key) = kem_key(KemAlgorithm::MlKem512);
    let protection = Protection::Slots {
        passphrase: Some(PassphraseAccess {
            passphrase: &pass,
            params: common::min_params(),
            factor: Some(&f),
        }),
        recipients: &[&anna, &ben],
    };
    let enc = w.work.join("v2.pqkf");
    files::encrypt(&w.source, &enc, &protection).unwrap();
    let with_factor = Unlock::PassphraseWithFactor {
        passphrase: pass.as_ref(),
        factor: &f,
    };
    for unlock in [with_factor, Unlock::Key(&anna_key), Unlock::Key(&ben_key)] {
        assert_eq!(files::check(&enc, &unlock).unwrap().files, 1);
    }
    let without = files::check(&enc, &Unlock::Passphrase(pass.as_ref())).unwrap_err();
    assert_eq!(
        without,
        Error::InvalidInput {
            field: "factor_required"
        }
    );
    let foreign = files::check(&enc, &Unlock::Key(&fremd_key)).unwrap_err();
    assert_eq!(foreign, Error::InvalidInput { field: "recipient" });
    assert_eq!(listing(&w.work), ["v2.pqkf"]);
}

#[test]
fn every_tampered_or_truncated_file_fails() {
    let w = workspace();
    let (anna, anna_key) = kem_key(KemAlgorithm::MlKem768);
    let enc = w.work.join("a.pqkf");
    files::encrypt(&w.source, &enc, &Protection::Recipient(&anna)).unwrap();
    let bytes = std::fs::read(&enc).unwrap();
    let unlock = Unlock::Key(&anna_key);
    let probe = w.work.join("probe.pqkf");
    // DE: Jedes Byte einzeln kippen (Datei ist klein). EN: Flip every byte (the file is small).
    for i in 0..bytes.len() {
        std::fs::write(&probe, common::flip(&bytes, i)).unwrap();
        assert!(files::check(&probe, &unlock).is_err(), "Byte {i}");
    }
    for len in [0, 9, 10, bytes.len() / 2, bytes.len() - 1] {
        std::fs::write(&probe, &bytes[..len]).unwrap();
        assert!(files::check(&probe, &unlock).is_err(), "Länge {len}");
    }
    std::fs::remove_file(&probe).unwrap();
    assert_eq!(listing(&w.work), ["a.pqkf"]);
}

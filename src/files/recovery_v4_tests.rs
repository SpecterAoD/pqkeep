//! DE: REC-008 für Format v4 (#335, Lücke G5): Fehler beim Öffnen, Schreiben (auch teilweise),
//! Synchronisieren und Veröffentlichen während `decrypt` von Strom (mit Füllung bzw. verborgenem
//! Absender) und Archiv (Datei mit Füllung und verborgenem Absender, Ordner mit Füllung) – das Ziel
//! erscheint nie, die Quelle bleibt unverändert, keine Temporärreste.
//! EN: REC-008 for format v4 (#335, gap G5): failures while opening, writing (also partially),
//! syncing and publishing during `decrypt` of streams (with padding or hidden sender) and archives
//! (file with padding and hidden sender, directory with padding) – the target never appears, the
//! source stays unchanged, no temporary leftovers.
#![allow(clippy::unwrap_used)]

use std::io::ErrorKind;
use std::path::Path;

use crate::crypto::{DsaAlgorithm, KeyAlgorithm, kdf};
use crate::envelope::{KeyFile, Metadata, UnlockedKey};
use crate::fault_fixture_tests::{assert_no_temps, plan};
use crate::fault_io_tests::{Action, Failure, Point, Scope};
use crate::files::{self, EncryptOptions, Protection, Unlock};
use crate::security::{StrongPassphrase, generator};
use crate::{Error, Result};

fn params() -> kdf::KdfParams {
    kdf::KdfParams {
        memory_kib: kdf::MIN_MEMORY_KIB,
        iterations: kdf::MIN_ITERATIONS,
        parallelism: 1,
    }
}

fn signer(pass: &StrongPassphrase) -> UnlockedKey {
    let meta = Metadata {
        name: "synthetic".to_owned(),
        organization: None,
        company: None,
        department: None,
        account_type: None,
    };
    let algorithm = KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87);
    let file = KeyFile::generate(pass, algorithm, &meta, &params()).unwrap();
    file.unlock(pass.as_ref()).unwrap()
}

/// DE: Ein Fall: Quelle, Verschlüsselungsweg und Optionen. EN: One case: source, way and options.
struct Case {
    stream: bool,
    tree: bool,
    options: EncryptOptions,
    signed: bool,
}

const CASES: [Case; 4] = [
    Case {
        stream: true,
        tree: false,
        options: opts(true, false),
        signed: false,
    },
    Case {
        stream: true,
        tree: false,
        options: opts(false, true),
        signed: true,
    },
    Case {
        stream: false,
        tree: false,
        options: opts(true, true),
        signed: true,
    },
    Case {
        stream: false,
        tree: true,
        options: opts(true, false),
        signed: false,
    },
];

const fn opts(pad: bool, hide_sender: bool) -> EncryptOptions {
    EncryptOptions {
        pad,
        anonymous: false,
        hide_sender,
    }
}

fn encrypt(case: &Case, root: &Path, pass: &StrongPassphrase, key: &UnlockedKey) -> Result<()> {
    let source = root.join("source");
    let payload = vec![0x5a; 65_537];
    if case.tree {
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::write(source.join("a"), &payload).unwrap();
        std::fs::write(source.join("nested/b"), b"synthetic").unwrap();
    } else {
        std::fs::write(&source, &payload).unwrap();
    }
    let p = Protection::Passphrase {
        passphrase: pass,
        params: params(),
    };
    let signer = case.signed.then_some(key);
    let archive = root.join("archive.pqkf");
    if case.stream {
        files::encrypt_stream_to(&mut &payload[..], &archive, &p, signer, case.options)?;
    } else {
        files::encrypt_with_options(&source, &archive, &p, signer, case.options)?;
    }
    Ok(())
}

#[test]
fn rec008_v4_decrypt_failures_never_publish() {
    let pass = generator::generate(&generator::Options::default()).unwrap();
    let key = signer(&pass);
    let fail = Failure::Kind(ErrorKind::StorageFull);
    for case in &CASES {
        let root = tempfile::tempdir().unwrap();
        encrypt(case, root.path(), &pass, &key).unwrap();
        let archive = root.path().join("archive.pqkf");
        let before = std::fs::read(&archive).unwrap();
        let unlock = Unlock::Passphrase(pass.as_ref());
        let mut faults: Vec<_> = [
            Point::BeforeOpen,
            Point::AfterTempCreate,
            Point::BeforeFileSync,
            Point::BeforePublish,
        ]
        .map(|p| plan(p, Action::Fail(fail)))
        .into();
        faults.extend([0, 1, 65_536].map(|after| {
            plan(
                Point::Write,
                Action::Partial {
                    after,
                    failure: fail,
                },
            )
        }));
        for fault in faults {
            let target = root.path().join("out");
            let scope = Scope::new(root.path(), fault);
            let result = files::decrypt(&archive, &target, &unlock);
            let trace = scope.finish();
            assert_eq!(result, Err(Error::Io(ErrorKind::StorageFull)));
            assert!(!trace.contains(&Point::AfterPublish));
            assert!(!target.exists());
            assert!(
                std::fs::read(&archive).unwrap() == before,
                "Archiv verändert / changed"
            );
            assert_no_temps(root.path());
        }
        let valid = root.path().join("valid");
        files::decrypt(&archive, &valid, &unlock).unwrap();
        assert!(valid.exists());
    }
}

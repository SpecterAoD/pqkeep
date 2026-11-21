//! DE: REC-010–013: echte Core-Operationen, bestätigter Prozessabbruch und frischer Prozess.
//! EN: REC-010–013: real core operations, acknowledged termination and a fresh process.
#![allow(clippy::unwrap_used)]

use crate::crash_driver_tests::{self as driver, Captured, Operation, Request};
use crate::crypto::{factor::Factor, kdf};
use crate::fault_fixture_tests::{ArchiveCase, Keys, tree_bytes};
use crate::fault_io_tests::{Point, checkpoint};
use crate::security::StrongPassphrase;
use crate::{Result, envelope, files};
use std::path::Path;

pub(crate) fn execute(
    request: &Request,
    pass: Option<&StrongPassphrase>,
    factor: Option<&Factor>,
) -> Result<()> {
    let root = &request.root;
    match request.operation {
        Operation::Key => save_next(root, "key.json"),
        Operation::Rekey | Operation::RekeyBackup => rekey(root, pass.unwrap(), factor),
        Operation::Factor => Factor::create(&root.join("factor")),
        Operation::Encrypt => encrypt(root, pass.unwrap(), factor),
        Operation::Decrypt => files::decrypt(
            &root.join("archive.pqkf"),
            &root.join("out"),
            &unlock(pass.unwrap(), factor),
        )
        .map(|_| ()),
        Operation::Many => {
            for (i, name) in ["first.json", "second.json", "third.json"]
                .iter()
                .enumerate()
            {
                save_next(root, name)?;
                if i == 0 {
                    checkpoint(&root.join(name), Point::AfterFirstOperation)?;
                }
            }
            Ok(())
        }
        Operation::VerifyMany => verify_many(root, pass.unwrap(), factor),
        Operation::VerifyKey => verify_key(&root.join("key.json"), pass.unwrap(), factor),
        Operation::VerifyFactor => Factor::read(&root.join("factor")).map(|_| ()),
        Operation::VerifyArchive => {
            files::check(&root.join("archive.pqkf"), &unlock(pass.unwrap(), factor)).map(|_| ())
        }
        Operation::VerifyOutput => {
            files::check(&root.join("archive.pqkf"), &unlock(pass.unwrap(), factor))?;
            assert!(
                tree_bytes(&root.join("source")) == tree_bytes(&root.join("out")),
                "Output changed / Ausgabe verändert"
            );
            Ok(())
        }
    }
}

fn rekey(root: &Path, pass: &StrongPassphrase, factor: Option<&Factor>) -> Result<()> {
    let source = root.join("keys/key.json");
    let backup = root.join("backups/key.json");
    let loaded = envelope::RekeyFile::open(&source)?;
    let mut options = envelope::RekeyOptions::new(&source);
    options.overwrite = envelope::Overwrite::Yes;
    options.backup = Some(&backup);
    // DE: Gleiche erzeugte Passphrase isoliert den Speicher-Commit; getrennte Tests wechseln sie.
    // EN: Same generated passphrase isolates storage commit; separate tests change it.
    loaded.write(&options, pass.as_ref(), pass, factor)
}

fn save_next(root: &Path, name: &str) -> Result<()> {
    let key = envelope::load(&root.join("next.json"))?.0;
    envelope::save(&key, &root.join(name), envelope::Overwrite::Yes)
}

fn verify_key(path: &Path, pass: &StrongPassphrase, factor: Option<&Factor>) -> Result<()> {
    let key = envelope::load(path)?.0;
    match factor {
        Some(f) => key.unlock_with_factor(pass.as_ref(), f).map(|_| ()),
        None => key.unlock(pass.as_ref()).map(|_| ()),
    }
}

fn verify_many(root: &Path, pass: &StrongPassphrase, factor: Option<&Factor>) -> Result<()> {
    verify_key(&root.join("first.json"), pass, factor)?;
    assert!(!root.join("second.json").exists() && !root.join("third.json").exists());
    Ok(())
}

fn encrypt(root: &Path, pass: &StrongPassphrase, factor: Option<&Factor>) -> Result<()> {
    let params = kdf::KdfParams {
        memory_kib: kdf::MIN_MEMORY_KIB,
        iterations: kdf::MIN_ITERATIONS,
        parallelism: 1,
    };
    let protection = files::Protection::Slots {
        passphrase: Some(files::PassphraseAccess {
            passphrase: pass,
            params,
            factor,
        }),
        recipients: &[],
    };
    files::encrypt(
        &root.join("source"),
        &root.join("archive.pqkf"),
        &protection,
    )
    .map(|_| ())
}

fn unlock<'a>(pass: &'a StrongPassphrase, factor: Option<&'a Factor>) -> files::Unlock<'a> {
    match factor {
        Some(factor) => files::Unlock::PassphraseWithFactor {
            passphrase: pass.as_ref(),
            factor,
        },
        None => files::Unlock::Passphrase(pass.as_ref()),
    }
}

fn pauses() -> Vec<(Point, Option<usize>)> {
    vec![
        (Point::BeforeOpen, None),
        (Point::AfterTempCreate, None),
        (Point::Write, Some(1)),
        (Point::BeforePublish, None),
        (Point::AfterPublish, None),
    ]
}

fn quiet(captured: &Captured) {
    assert!(captured.err.is_empty(), "Child stderr / Kind-stderr");
}

type Snapshot = Vec<(std::path::PathBuf, Vec<(std::path::PathBuf, Vec<u8>)>)>;

fn unchanged_stale(root: &Path, tag: &str) -> Snapshot {
    let mut paths: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .contains(&format!(".tmp-{tag}"))
        })
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            let data = tree_bytes(&p);
            (p, data)
        })
        .collect()
}

#[test]
fn rec010_011_key_replace_crashes_preserve_valid_v1_v2_state() {
    for v2 in [false, true] {
        let keys = Keys::new(v2);
        for (point, after) in pauses() {
            let root = tempfile::tempdir().unwrap();
            let target = root.path().join("key.json");
            envelope::save(&keys.old, &target, envelope::Overwrite::No).unwrap();
            envelope::save(
                &keys.new,
                &root.path().join("next.json"),
                envelope::Overwrite::No,
            )
            .unwrap();
            let before = std::fs::read(&target).unwrap();
            let mut request = Request::new(root.path(), Operation::Key, Some(point));
            request.after = after;
            let captured = driver::run(&request, Some(keys.credentials()), true);
            quiet(&captured);
            keys.assert_no_secrets(&String::from_utf8_lossy(&captured.out));
            keys.assert_no_secrets(&String::from_utf8_lossy(&captured.err));
            let expected = if point == Point::AfterPublish {
                &keys.new
            } else {
                &keys.old
            };
            keys.assert_valid(&target, expected);
            if point != Point::AfterPublish {
                assert!(
                    std::fs::read(&target).unwrap() == before,
                    "Old key changed / Altschlüssel verändert"
                );
            }
            let stale = unchanged_stale(root.path(), &request.tag);
            if point == Point::BeforeOpen || point == Point::AfterPublish {
                assert_eq!(stale.len(), 0);
            } else {
                assert_eq!(stale.len(), 1);
            }
            let restart = Request::new(root.path(), Operation::VerifyKey, None);
            quiet(&driver::run(&restart, Some(keys.credentials()), false));
            keys.assert_valid(&target, expected);
            assert!(
                unchanged_stale(root.path(), &request.tag) == stale,
                "Stale changed / Rest verändert"
            );
        }
    }
}

#[test]
fn rec010_011_factor_crashes_leave_absent_or_valid_target() {
    for (point, after) in pauses() {
        let root = tempfile::tempdir().unwrap();
        let mut request = Request::new(root.path(), Operation::Factor, Some(point));
        request.after = after;
        quiet(&driver::run(&request, None, true));
        let target = root.path().join("factor");
        if point == Point::AfterPublish {
            assert!(Factor::read(&target).is_ok());
        } else {
            assert!(!target.exists());
        }
        let stale_names: Vec<_> = std::fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().contains(".tmp-"))
            .collect();
        assert_eq!(stale_names.len(), usize::from(point != Point::BeforeOpen));
        if point == Point::Write {
            assert_eq!(std::fs::metadata(&stale_names[0]).unwrap().len(), 1);
        }
        let snapshots: Vec<_> = stale_names
            .iter()
            .map(|p| zeroize::Zeroizing::new(std::fs::read(p).unwrap()))
            .collect();
        let operation = if point == Point::AfterPublish {
            Operation::VerifyFactor
        } else {
            Operation::Factor
        };
        quiet(&driver::run(
            &Request::new(root.path(), operation, None),
            None,
            false,
        ));
        assert!(Factor::read(&target).is_ok());
        for (path, bytes) in stale_names.iter().zip(&snapshots) {
            let actual = zeroize::Zeroizing::new(std::fs::read(path).unwrap());
            assert!(
                actual.as_slice() == bytes.as_slice(),
                "Factor temp changed / Faktorrest verändert"
            );
        }
    }
}

#[test]
fn rec010_011_archive_crashes_preserve_sources_and_restart_safely() {
    for v2 in [false, true] {
        for (point, after) in pauses() {
            let case = ArchiveCase::new(v2, v2, 65_537);
            let source = tree_bytes(&case.source);
            let mut request = Request::new(case.root.path(), Operation::Encrypt, Some(point));
            request.after = after;
            let captured = driver::run(&request, Some(case.credentials()), true);
            quiet(&captured);
            case.assert_no_secrets(&String::from_utf8_lossy(&captured.out));
            assert!(
                tree_bytes(&case.source) == source,
                "Source changed / Quelle verändert"
            );
            assert_eq!(case.archive.exists(), point == Point::AfterPublish);
            let stale = unchanged_stale(case.root.path(), &request.tag);
            let op = if point == Point::AfterPublish {
                Operation::VerifyArchive
            } else {
                Operation::Encrypt
            };
            quiet(&driver::run(
                &Request::new(case.root.path(), op, None),
                Some(case.credentials()),
                false,
            ));
            case.assert_valid(&case.root.path().join("valid"));
            assert!(
                unchanged_stale(case.root.path(), &request.tag) == stale,
                "Stale changed / Rest verändert"
            );
        }
    }
}

#[test]
fn rec010_011_decrypt_crashes_never_publish_partial_plaintext() {
    for v2 in [false, true] {
        for tree in [false, true] {
            for (point, after) in pauses() {
                let case = ArchiveCase::new(v2, tree, 65_537);
                case.encrypt().unwrap();
                let before = std::fs::read(&case.archive).unwrap();
                let mut request = Request::new(case.root.path(), Operation::Decrypt, Some(point));
                request.after = after;
                quiet(&driver::run(&request, Some(case.credentials()), true));
                let target = case.root.path().join("out");
                assert_eq!(target.exists(), point == Point::AfterPublish);
                let stale = unchanged_stale(case.root.path(), &request.tag);
                let op = if point == Point::AfterPublish {
                    Operation::VerifyOutput
                } else {
                    Operation::Decrypt
                };
                quiet(&driver::run(
                    &Request::new(case.root.path(), op, None),
                    Some(case.credentials()),
                    false,
                ));
                assert!(
                    tree_bytes(&target) == tree_bytes(&case.source),
                    "Output changed / Ausgabe verändert"
                );
                assert!(
                    std::fs::read(&case.archive).unwrap() == before,
                    "Archive changed / Archiv verändert"
                );
                assert!(
                    unchanged_stale(case.root.path(), &request.tag) == stale,
                    "Stale changed / Rest verändert"
                );
            }
        }
    }
}

#[test]
fn rec013_multistage_kill_distinguishes_committed_pending_and_unstarted() {
    let keys = Keys::new(false);
    for point in [Point::AfterFirstOperation, Point::BeforePublish] {
        let root = tempfile::tempdir().unwrap();
        envelope::save(
            &keys.new,
            &root.path().join("next.json"),
            envelope::Overwrite::No,
        )
        .unwrap();
        let mut request = Request::new(root.path(), Operation::Many, Some(point));
        if point == Point::BeforePublish {
            request.occurrence = 2;
        }
        quiet(&driver::run(&request, Some(keys.credentials()), true));
        keys.assert_valid(&root.path().join("first.json"), &keys.new);
        assert!(!root.path().join("second.json").exists());
        assert!(!root.path().join("third.json").exists());
        assert_eq!(
            unchanged_stale(root.path(), &request.tag).len(),
            usize::from(point == Point::BeforePublish)
        );
        let stale = unchanged_stale(root.path(), &request.tag);
        quiet(&driver::run(
            &Request::new(root.path(), Operation::VerifyMany, None),
            Some(keys.credentials()),
            false,
        ));
        assert!(
            unchanged_stale(root.path(), &request.tag) == stale,
            "Stale changed / Rest verändert"
        );
    }
}

#[test]
fn rec010_control_releases_checkpoint_and_reports_success() {
    let root = tempfile::tempdir().unwrap();
    let request = Request::new(root.path(), Operation::Factor, Some(Point::BeforePublish));
    quiet(&driver::run(&request, None, false));
    assert!(Factor::read(&root.path().join("factor")).is_ok());
}

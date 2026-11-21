//! DE: RKEY-008/009: echte Rekey-I/O, getrennte Scoped-Sicherungs-/Ziel-Fehlerpunkte.
//! EN: RKEY-008/009: real rekey I/O, separately scoped backup/target fault points.
// DE: Boolean-Vergleiche verhindern Secret-/Container-Dumps bei Fehlern.
// EN: Boolean comparisons avoid secret/container dumps on assertion failures.
#![allow(clippy::unwrap_used, clippy::manual_assert_eq)]

use std::fs;
use std::io::ErrorKind;

use crate::Error;
use crate::crypto::factor::Factor;
use crate::envelope::{self, Overwrite, RekeyFile, RekeyOptions};
use crate::fault_fixture_tests::{Keys, assert_no_temps, plan};
use crate::fault_io_tests::{Action, Failure, Point, Scope};
use crate::security::{Passphrase, StrongPassphrase, generator};

fn credentials(keys: &Keys) -> (StrongPassphrase, Option<Factor>) {
    let (pass, factor) = keys.credentials();
    let pass =
        StrongPassphrase::try_from(Passphrase::new(std::str::from_utf8(pass).unwrap()).unwrap())
            .unwrap();
    let factor = (!factor.is_empty()).then(|| Factor::from_bytes(factor).unwrap());
    (pass, factor)
}

struct Files {
    _root: tempfile::TempDir,
    dir: std::path::PathBuf,
    backups: std::path::PathBuf,
    source: std::path::PathBuf,
    backup: std::path::PathBuf,
    before: Vec<u8>,
}

impl Files {
    fn new(keys: &Keys) -> Self {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("keys");
        let backups = root.path().join("backups");
        fs::create_dir(&dir).unwrap();
        fs::create_dir(&backups).unwrap();
        let source = dir.join("key.json");
        let backup = backups.join("key.old.json");
        envelope::save(&keys.old, &source, Overwrite::No).unwrap();
        let before = fs::read(&source).unwrap();
        Self {
            _root: root,
            dir,
            backups,
            source,
            backup,
            before,
        }
    }

    fn options(&self) -> RekeyOptions<'_> {
        let mut options = RekeyOptions::new(&self.source);
        options.overwrite = Overwrite::Yes;
        options.backup = Some(&self.backup);
        options
    }

    fn assert_state(
        &self,
        keys: &Keys,
        old: &StrongPassphrase,
        new: &StrongPassphrase,
        factor: Option<&Factor>,
        published: bool,
    ) {
        if published {
            let changed = envelope::load(&self.source).unwrap().0;
            assert_eq!(changed.key_id(), keys.old.key_id());
            let unlock = |key: &envelope::KeyFile, pass: &Passphrase| {
                match factor {
                    Some(f) => key.unlock_with_factor(pass, f),
                    None => key.unlock(pass),
                }
                .unwrap()
            };
            assert!(
                unlock(&changed, new.as_ref()).secret().expose()
                    == unlock(&keys.old, old.as_ref()).secret().expose(),
                "Secret changed / Geheimnis verändert"
            );
        } else {
            assert!(
                fs::read(&self.source).unwrap() == self.before,
                "Source changed / Quelle verändert"
            );
            keys.assert_valid(&self.source, &keys.old);
        }
        if self.backup.exists() {
            assert!(
                fs::read(&self.backup).unwrap() == self.before,
                "Backup changed / Sicherung verändert"
            );
        }
    }
}

#[test]
fn rkey008_backup_and_target_faults_preserve_old_or_complete_new_key() {
    for v2 in [false, true] {
        let keys = Keys::new(v2);
        let (old, factor) = credentials(&keys);
        let new = generator::generate(&generator::Options::default()).unwrap();
        for backup_fault in [false, true] {
            let points = [
                Point::BeforeOpen,
                Point::AfterTempCreate,
                Point::BeforeFileSync,
                Point::BeforePublish,
                Point::AfterPublish,
                Point::BeforeRemoveFile,
            ];
            for point in points {
                // DE: Rename gibt es nur am Ziel, Remove nur an der Sicherung.
                // EN: Rename belongs to target, remove to backup.
                if !backup_fault && point == Point::BeforeRemoveFile {
                    continue;
                }
                let files = Files::new(&keys);
                let (dir, backups, source) = (&files.dir, &files.backups, &files.source);
                let loaded = RekeyFile::open(source).unwrap();
                let options = files.options();
                let scope = Scope::new(
                    if backup_fault { backups } else { dir },
                    plan(point, Action::Fail(Failure::Kind(ErrorKind::StorageFull))),
                );
                let result = loaded.write(&options, old.as_ref(), &new, factor.as_ref());
                scope.finish();
                assert!(matches!(result, Err(Error::Io(ErrorKind::StorageFull))));
                files.assert_state(
                    &keys,
                    &old,
                    &new,
                    factor.as_ref(),
                    !backup_fault && point == Point::AfterPublish,
                );
                assert_no_temps(dir);
                assert_no_temps(backups);
            }
        }
    }
}

#[test]
fn rkey008_partial_writes_rename_and_cleanup_failures_stay_explicit() {
    let keys = Keys::new(false);
    let (old, _) = credentials(&keys);
    let new = generator::generate(&generator::Options::default()).unwrap();
    for point in [Point::Write, Point::BeforeRename] {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("keys");
        fs::create_dir(&dir).unwrap();
        let source = dir.join("key.json");
        let backup = root.path().join("backup.json");
        envelope::save(&keys.old, &source, Overwrite::No).unwrap();
        let before = fs::read(&source).unwrap();
        let loaded = RekeyFile::open(&source).unwrap();
        let mut options = RekeyOptions::new(&source);
        options.overwrite = Overwrite::Yes;
        options.backup = Some(&backup);
        let failure = Failure::Kind(ErrorKind::PermissionDenied);
        let scope = Scope::new(
            &dir,
            plan(
                point,
                if point == Point::Write {
                    Action::Partial { after: 1, failure }
                } else {
                    Action::Fail(failure)
                },
            ),
        );
        assert!(matches!(
            loaded.write(&options, old.as_ref(), &new, None),
            Err(Error::Io(ErrorKind::PermissionDenied))
        ));
        scope.finish();
        assert!(fs::read(&source).unwrap() == before && fs::read(&backup).unwrap() == before);
        assert_no_temps(&dir);
    }
}

#[test]
fn rkey008_cleanup_failure_retains_primary_error() {
    let keys = Keys::new(false);
    let (old, _) = credentials(&keys);
    let new = generator::generate(&generator::Options::default()).unwrap();
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("key.json");
    let output = root.path().join("new.json");
    envelope::save(&keys.old, &source, Overwrite::No).unwrap();
    let loaded = RekeyFile::open(&source).unwrap();
    let options = RekeyOptions::new(&output);
    let scope = Scope::sequence(
        root.path(),
        vec![
            plan(
                Point::Write,
                Action::Partial {
                    after: 1,
                    failure: Failure::Kind(ErrorKind::StorageFull),
                },
            ),
            plan(
                Point::BeforeRemoveFile,
                Action::Fail(Failure::Kind(ErrorKind::PermissionDenied)),
            ),
        ],
    );
    assert!(matches!(
        loaded.write(&options, old.as_ref(), &new, None),
        Err(Error::Io(ErrorKind::StorageFull))
    ));
    scope.finish();
    assert!(!output.exists());
    keys.assert_valid(&source, &keys.old);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
}

#[test]
fn rkey008_backup_and_target_partial_write_boundaries() {
    for v2 in [false, true] {
        let keys = Keys::new(v2);
        let (old, factor) = credentials(&keys);
        let new = generator::generate(&generator::Options::default()).unwrap();
        for backup_phase in [false, true] {
            for after in [0, 1, keys.old.to_json().unwrap().len() - 1] {
                let files = Files::new(&keys);
                let scope = Scope::new(
                    if backup_phase {
                        &files.backups
                    } else {
                        &files.dir
                    },
                    plan(
                        Point::Write,
                        Action::Partial {
                            after,
                            failure: Failure::Kind(ErrorKind::StorageFull),
                        },
                    ),
                );
                let result = RekeyFile::open(&files.source).unwrap().write(
                    &files.options(),
                    old.as_ref(),
                    &new,
                    factor.as_ref(),
                );
                scope.finish();
                assert!(matches!(result, Err(Error::Io(ErrorKind::StorageFull))));
                files.assert_state(&keys, &old, &new, factor.as_ref(), false);
                assert_eq!(files.backup.exists(), !backup_phase);
                assert_no_temps(&files.dir);
                assert_no_temps(&files.backups);
            }
        }
    }
}

#[test]
fn rkey009_unsupported_hardlinks_never_enable_rekey_fallback() {
    let keys = Keys::new(false);
    let (old, _) = credentials(&keys);
    for with_backup in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("key.json");
        let output = root.path().join("new.json");
        let backup = root.path().join("backup.json");
        envelope::save(&keys.old, &source, Overwrite::No).unwrap();
        let loaded = RekeyFile::open(&source).unwrap();
        let mut options = RekeyOptions::new(&output);
        options.backup = with_backup.then_some(backup.as_path());
        let scope = Scope::new(
            root.path(),
            plan(
                Point::BeforeHardLink,
                Action::Fail(Failure::Kind(ErrorKind::Unsupported)),
            ),
        );
        assert!(matches!(
            loaded.write(&options, old.as_ref(), &old, None),
            Err(Error::Io(ErrorKind::Unsupported))
        ));
        let trace = scope.finish();
        assert!(!trace.contains(&Point::BeforeRename));
        assert!(!output.exists() && !backup.exists());
        keys.assert_valid(&source, &keys.old);
        assert_no_temps(root.path());
    }
}

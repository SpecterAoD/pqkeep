//! DE: RKEY-010: bestätigter Abbruch an Sicherung/Ziel, unveränderter Wiederanlauf.
//! EN: RKEY-010: acknowledged backup/target termination, unchanged restart state.
#![allow(clippy::unwrap_used)]
use crate::crash_driver_tests::{self as driver, Operation, Request};
use crate::crypto::factor::Factor;
use crate::envelope::{self, Overwrite, RekeyFile, RekeyOptions};
use crate::fault_fixture_tests::{Keys, tree_bytes};
use crate::fault_io_tests::Point;
use crate::security::Passphrase;
use std::fs;
use std::path::Path;

fn assert_identity(keys: &Keys, path: &Path) {
    let changed = envelope::load(path).unwrap().0;
    assert_eq!(changed.key_id(), keys.old.key_id());
    assert_eq!(changed.format_version(), keys.old.format_version());
    let (pass, factor) = keys.credentials();
    let pass = Passphrase::new(std::str::from_utf8(pass).unwrap()).unwrap();
    let factor = (!factor.is_empty()).then(|| Factor::from_bytes(factor).unwrap());
    let unlock = |key: &envelope::KeyFile| {
        match &factor {
            Some(f) => key.unlock_with_factor(&pass, f),
            None => key.unlock(&pass),
        }
        .unwrap()
    };
    assert!(
        unlock(&changed).secret().expose() == unlock(&keys.old).secret().expose(),
        "Identity changed / Identität verändert"
    );
}

fn crash_case(keys: &Keys, backup_phase: bool, point: Point) {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("keys");
    let backups = root.path().join("backups");
    fs::create_dir(&dir).unwrap();
    fs::create_dir(&backups).unwrap();
    let target = dir.join("key.json");
    let backup = backups.join("key.json");
    envelope::save(&keys.old, &target, Overwrite::No).unwrap();
    let before = fs::read(&target).unwrap();
    let operation = if backup_phase {
        Operation::RekeyBackup
    } else {
        Operation::Rekey
    };
    let mut request = Request::new(root.path(), operation, Some(point));
    request.after = (point == Point::Write).then_some(1);
    let captured = driver::run(&request, Some(keys.credentials()), true);
    assert!(captured.err.is_empty());
    keys.assert_no_secrets(&String::from_utf8_lossy(&captured.out));
    keys.assert_no_secrets(&String::from_utf8_lossy(&captured.err));
    let published = !backup_phase && point == Point::AfterPublish;
    if !published {
        assert!(
            fs::read(&target).unwrap() == before,
            "Old key lost / Altschlüssel verloren"
        );
    }
    assert_identity(keys, &target);
    assert_eq!(
        backup.exists(),
        !backup_phase || point == Point::AfterPublish
    );
    if backup.exists() {
        assert!(
            fs::read(&backup).unwrap() == before,
            "Backup changed / Sicherung verändert"
        );
        keys.assert_valid(&backup, &keys.old);
    }
    restart(keys, &dir, root.path());
}

fn restart(keys: &Keys, dir: &Path, root: &Path) {
    let snapshot = tree_bytes(root);
    let captured = driver::run(
        &Request::new(dir, Operation::VerifyKey, None),
        Some(keys.credentials()),
        false,
    );
    assert!(captured.err.is_empty());
    keys.assert_no_secrets(&String::from_utf8_lossy(&captured.out));
    assert!(
        tree_bytes(root) == snapshot,
        "Restart adopted stale files / Neustart übernimmt Reste"
    );
    assert_identity(keys, &dir.join("key.json"));
}

#[test]
fn rkey010_backup_and_target_kills_preserve_identity_and_restart_state() {
    for v2 in [false, true] {
        let keys = Keys::new(v2);
        for backup in [false, true] {
            for point in [
                Point::BeforeOpen,
                Point::AfterTempCreate,
                Point::Write,
                Point::BeforePublish,
                Point::AfterPublish,
            ] {
                crash_case(&keys, backup, point);
            }
        }
    }
}

#[test]
fn rkey010_control_completes_and_repeated_backup_is_never_overwritten() {
    let root = tempfile::tempdir().unwrap();
    let keys = Keys::new(false);
    for dir in ["keys", "backups"] {
        fs::create_dir(root.path().join(dir)).unwrap();
    }
    let target = root.path().join("keys/key.json");
    let backup = root.path().join("backups/key.json");
    envelope::save(&keys.old, &target, Overwrite::No).unwrap();
    let request = Request::new(root.path(), Operation::Rekey, Some(Point::BeforeRename));
    let captured = driver::run(&request, Some(keys.credentials()), false);
    assert!(captured.err.is_empty());
    assert_identity(&keys, &target);
    keys.assert_valid(&backup, &keys.old);
    let mut options = RekeyOptions::new(&target);
    options.overwrite = Overwrite::Yes;
    options.backup = Some(&backup);
    assert!(RekeyFile::open(&target).unwrap().check(&options).is_err());
    keys.assert_valid(&backup, &keys.old);
}

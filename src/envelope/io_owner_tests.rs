//! DE: RKEY-007/008: Cleanup darf niemals fremde Dateien am Temp-Pfad löschen.
//! EN: RKEY-007/008: cleanup must never delete another file at the temporary path.
#![allow(clippy::unwrap_used)]
use super::{Overwrite, save, write_temp};
use crate::Error;
use crate::fault_fixture_tests::{Keys, plan};
use crate::fault_io_tests::{Action, Failure, Point, Scope};
use std::fs;
use std::io::ErrorKind;

#[test]
fn rkey007_existing_valid_temp_collision_is_preserved() {
    for v2 in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let keys = Keys::new(v2);
        let temp = root.path().join("existing.json");
        let output = root.path().join("new.json");
        save(&keys.old, &temp, Overwrite::No).unwrap();
        let before = fs::read(&temp).unwrap();
        let result = write_temp(
            &temp,
            &output,
            keys.new.to_json().unwrap().as_bytes(),
            Overwrite::No,
            true,
        );
        assert!(matches!(result, Err(Error::Io(ErrorKind::AlreadyExists))));
        assert!(
            temp.exists(),
            "Foreign temp deleted / Fremder Temp gelöscht"
        );
        assert!(
            fs::read(&temp).unwrap() == before,
            "Foreign temp changed / Fremder Temp verändert"
        );
        assert!(!output.exists());
        keys.assert_valid(&temp, &keys.old);
    }
}

#[test]
fn rkey008_preopen_failure_does_not_cleanup_an_unowned_path() {
    let root = tempfile::tempdir().unwrap();
    let keys = Keys::new(false);
    let temp = root.path().join("existing.json");
    let output = root.path().join("new.json");
    save(&keys.old, &temp, Overwrite::No).unwrap();
    let scope = Scope::new(
        root.path(),
        plan(
            Point::BeforeOpen,
            Action::Fail(Failure::Kind(ErrorKind::PermissionDenied)),
        ),
    );
    let result = write_temp(
        &temp,
        &output,
        keys.new.to_json().unwrap().as_bytes(),
        Overwrite::Yes,
        false,
    );
    let trace = scope.finish();
    assert!(matches!(
        result,
        Err(Error::Io(ErrorKind::PermissionDenied))
    ));
    assert!(
        !trace.contains(&Point::BeforeRemoveFile),
        "Unowned cleanup attempted / Fremdes Cleanup versucht"
    );
    assert!(!output.exists());
    keys.assert_valid(&temp, &keys.old);
}

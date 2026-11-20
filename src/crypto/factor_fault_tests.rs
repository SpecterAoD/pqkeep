//! DE: REC-006/009: Faktor-Commitgrenzen und primäre plus sekundäre Fehler.
//! EN: REC-006/009: factor commit boundaries and primary plus secondary errors.
#![allow(clippy::unwrap_used)]

use std::io::ErrorKind;
use zeroize::Zeroizing;

use crate::Error;
use crate::crypto::factor::{FACTOR_LEN, Factor};
use crate::fault_fixture_tests::{assert_no_temps, plan};
use crate::fault_io_tests::{Action, Failure, Point, Scope};

#[test]
fn rec006_precommit_factor_failures_never_publish() {
    let fail = Failure::Kind(ErrorKind::StorageFull);
    let mut faults: Vec<_> = [
        Point::BeforeOpen,
        Point::AfterTempCreate,
        Point::BeforeFileSync,
        Point::BeforePublish,
        Point::BeforeHardLink,
    ]
    .map(|point| plan(point, Action::Fail(fail)))
    .into();
    faults.extend([0, 1, 31].map(|after| {
        plan(
            Point::Write,
            Action::Partial {
                after,
                failure: fail,
            },
        )
    }));
    for fault in faults {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("factor");
        let scope = Scope::new(dir.path(), fault);
        assert_eq!(
            Factor::create(&target),
            Err(Error::Io(ErrorKind::StorageFull))
        );
        assert!(!scope.finish().contains(&Point::AfterPublish));
        assert!(!target.exists());
        assert_no_temps(dir.path());
    }
}

#[test]
fn rec006_existing_factor_and_completed_publications_stay_valid() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("factor");
    Factor::create(&target).unwrap();
    let old = Zeroizing::new(std::fs::read(&target).unwrap());
    assert_eq!(
        Factor::create(&target),
        Err(Error::Io(ErrorKind::AlreadyExists))
    );
    assert!(
        Zeroizing::new(std::fs::read(&target).unwrap()) == old,
        "Factor changed / Faktor verändert"
    );
    assert!(Factor::read(&target).is_ok());
    for point in [Point::AfterPublish, Point::BeforeRemoveFile] {
        let target = dir.path().join(format!("factor-{point:?}"));
        let scope = Scope::new(
            dir.path(),
            plan(point, Action::Fail(Failure::Kind(ErrorKind::Other))),
        );
        assert_eq!(Factor::create(&target), Err(Error::Io(ErrorKind::Other)));
        scope.finish();
        assert_eq!(std::fs::metadata(&target).unwrap().len(), FACTOR_LEN as u64);
        assert!(Factor::read(&target).is_ok());
        assert_no_temps(dir.path());
    }
}

#[test]
fn rec009_factor_cleanup_failure_preserves_primary_and_leaves_own_temp() {
    for after in [31, 32] {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("factor");
        let primary = if after == 31 {
            plan(
                Point::Write,
                Action::Partial {
                    after,
                    failure: Failure::Kind(ErrorKind::StorageFull),
                },
            )
        } else {
            plan(
                Point::BeforeFileSync,
                Action::Fail(Failure::Kind(ErrorKind::StorageFull)),
            )
        };
        let scope = Scope::sequence(
            dir.path(),
            vec![
                primary,
                plan(
                    Point::BeforeRemoveFile,
                    Action::Fail(Failure::Kind(ErrorKind::PermissionDenied)),
                ),
            ],
        );
        assert_eq!(
            Factor::create(&target),
            Err(Error::Io(ErrorKind::StorageFull))
        );
        scope.finish();
        assert!(!target.exists());
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
        let stale = entries[0].as_ref().unwrap().path();
        let bytes = Zeroizing::new(std::fs::read(&stale).unwrap());
        assert_eq!(bytes.len(), after);
        assert_eq!(Factor::read(&stale).is_ok(), after == 32);
        Factor::create(&target).unwrap();
        assert!(Factor::read(&target).is_ok());
        assert!(
            Zeroizing::new(std::fs::read(&stale).unwrap()) == bytes,
            "Stale changed / Rest verändert"
        );
        // DE: Nur der besitzende TempDir räumt Reste auf. EN: Only the owning TempDir cleans remnants.
    }
}

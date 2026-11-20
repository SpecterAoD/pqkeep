//! DE: QA1-REC-005: echte atomare Schreibpfade, gültige v1/v2-Schlüssel und Commitgrenzen.
//! EN: QA1-REC-005: real atomic write paths, valid v1/v2 keys and commit boundaries.
#![allow(clippy::unwrap_used)]

use std::io::ErrorKind;

use crate::Error;
use crate::envelope::{self, Overwrite};
use crate::fault_fixture_tests::{Keys, assert_no_temps, plan};
use crate::fault_io_tests::{Action, Failure, Point, Scope};

#[test]
fn rec005_precommit_failures_preserve_v1_v2_keys() {
    for v2 in [false, true] {
        let keys = Keys::new(v2);
        let length = keys.new.to_json().unwrap().len();
        let fail = Failure::Kind(ErrorKind::StorageFull);
        let mut plans: Vec<_> = [
            Point::BeforeOpen,
            Point::AfterTempCreate,
            Point::BeforeFileSync,
            Point::BeforePublish,
        ]
        .into_iter()
        .map(|p| plan(p, Action::Fail(fail)))
        .collect();
        plans.extend([0, 1, length - 1].map(|after| {
            plan(
                Point::Write,
                Action::Partial {
                    after,
                    failure: fail,
                },
            )
        }));
        for overwrite in [Overwrite::No, Overwrite::Yes] {
            for fault in &plans {
                let dir = tempfile::tempdir().unwrap();
                let target = dir.path().join("key.json");
                envelope::save(&keys.old, &target, Overwrite::No).unwrap();
                let before = std::fs::read(&target).unwrap();
                let scope = Scope::new(dir.path(), *fault);
                let result = envelope::save(&keys.new, &target, overwrite);
                let trace = scope.finish();
                assert_eq!(result, Err(Error::Io(ErrorKind::StorageFull)));
                assert!(!trace.contains(&Point::AfterPublish));
                assert!(
                    std::fs::read(&target).unwrap() == before,
                    "Bytes changed / Bytes verändert"
                );
                keys.assert_valid(&target, &keys.old);
                assert_no_temps(dir.path());
            }
        }
    }
}

#[test]
fn rec005_success_and_postcommit_states_are_valid() {
    for v2 in [false, true] {
        let keys = Keys::new(v2);
        for overwrite in [Overwrite::No, Overwrite::Yes] {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("key.json");
            if overwrite == Overwrite::Yes {
                envelope::save(&keys.old, &target, Overwrite::No).unwrap();
            }
            envelope::save(&keys.new, &target, overwrite).unwrap();
            keys.assert_valid(&target, &keys.new);
            let other = dir.path().join("other.json");
            if overwrite == Overwrite::Yes {
                envelope::save(&keys.old, &other, Overwrite::No).unwrap();
            }
            let scope = Scope::new(
                dir.path(),
                plan(
                    Point::AfterPublish,
                    Action::Fail(Failure::Kind(ErrorKind::Other)),
                ),
            );
            let result = envelope::save(&keys.new, &other, overwrite);
            assert_eq!(result, Err(Error::Io(ErrorKind::Other)));
            assert!(scope.finish().contains(&Point::AfterPublish));
            keys.assert_valid(&other, &keys.new);
            assert_no_temps(dir.path());
        }
    }
}

#[test]
fn rec005_short_interrupted_and_zero_writes() {
    let dir = tempfile::tempdir().unwrap();
    let data = crate::crypto::rng::array::<128>().unwrap();
    for (index, action) in [Action::Short(1), Action::Interrupt, Action::Zero]
        .into_iter()
        .enumerate()
    {
        let target = dir.path().join(format!("out-{index}"));
        let scope = Scope::new(dir.path(), plan(Point::Write, action));
        let result = envelope::write_atomic(&target, &data, Overwrite::No);
        scope.finish();
        if matches!(action, Action::Zero) {
            assert_eq!(result, Err(Error::Io(ErrorKind::WriteZero)));
            assert!(!target.exists());
        } else {
            assert!(result.is_ok());
            assert!(
                std::fs::read(&target).unwrap() == data,
                "Bytes changed / Bytes verändert"
            );
        }
        assert_no_temps(dir.path());
    }
}

#[cfg(any(target_os = "linux", windows))]
#[test]
fn rec005_os_errors_and_messages_expose_no_secrets() {
    #[cfg(target_os = "linux")]
    let codes = [libc::ENOSPC, libc::EACCES];
    #[cfg(windows)]
    let codes = [112, 5]; // DE/EN: ERROR_DISK_FULL, ERROR_ACCESS_DENIED.
    let keys = Keys::new(false);
    for code in codes {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("key.json");
        let scope = Scope::new(
            dir.path(),
            plan(Point::Write, Action::Fail(Failure::Os(code))),
        );
        let result = envelope::save(&keys.new, &target, Overwrite::No);
        scope.finish();
        let error = result.unwrap_err();
        assert_eq!(
            error,
            Error::Io(std::io::Error::from_raw_os_error(code).kind())
        );
        let message = error.to_string();
        keys.assert_no_secrets(&message);
        assert!(!message.contains(target.to_str().unwrap()));
        assert!(!target.exists());
        assert_no_temps(dir.path());
    }
}

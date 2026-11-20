//! DE: REC-007/014: echte Archiv-I/O-Fehler und Best-effort-Eltern-sync.
//! EN: REC-007/014: real archive I/O failures and best-effort parent sync.
#![allow(clippy::unwrap_used)]

use crate::Error;
use crate::fault_fixture_tests::{ArchiveCase, assert_no_temps, plan, tree_bytes};
use crate::fault_io_tests::{Action, Failure, Point, Scope};
use std::io::ErrorKind;

#[test]
fn rec007_encrypt_failures_preserve_sources_and_hide_partial_archive() {
    for v2 in [false, true] {
        for tree in [false, true] {
            let case = ArchiveCase::new(v2, tree, 65_537);
            let before = tree_bytes(&case.source);
            let fail = Failure::Kind(ErrorKind::StorageFull);
            let mut faults: Vec<_> = [
                Point::BeforeOpen,
                Point::AfterTempCreate,
                Point::BeforeFlush,
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
                let scope = Scope::new(case.root.path(), fault);
                let result = case.encrypt();
                let trace = scope.finish();
                assert_eq!(result, Err(Error::Io(ErrorKind::StorageFull)));
                assert!(!trace.contains(&Point::AfterPublish));
                assert!(!case.archive.exists());
                assert!(
                    tree_bytes(&case.source) == before,
                    "Source changed / Quelle verändert"
                );
                case.assert_no_secrets(&result.unwrap_err().to_string());
                assert_no_temps(case.root.path());
            }
            case.encrypt().unwrap();
            case.assert_valid(&case.root.path().join("valid"));
        }
    }
}

#[test]
fn rec007_publication_failures_leave_complete_valid_archive() {
    for v2 in [false, true] {
        for point in [Point::AfterPublish, Point::BeforeRemoveFile] {
            let case = ArchiveCase::new(v2, true, 65_537);
            let before = tree_bytes(&case.source);
            let scope = Scope::new(
                case.root.path(),
                plan(
                    point,
                    Action::Fail(Failure::Kind(ErrorKind::PermissionDenied)),
                ),
            );
            assert_eq!(case.encrypt(), Err(Error::Io(ErrorKind::PermissionDenied)));
            scope.finish();
            case.assert_valid(&case.root.path().join("valid"));
            assert!(
                tree_bytes(&case.source) == before,
                "Source changed / Quelle verändert"
            );
            assert_no_temps(case.root.path());
        }
    }
}

#[test]
fn rec007_hardlink_failure_and_rename_fallback_are_distinct() {
    let case = ArchiveCase::new(false, false, 1);
    let unsupported = plan(
        Point::BeforeHardLink,
        Action::Fail(Failure::Kind(ErrorKind::Unsupported)),
    );
    let scope = Scope::sequence(
        case.root.path(),
        vec![
            unsupported,
            plan(
                Point::BeforeRename,
                Action::Fail(Failure::Kind(ErrorKind::PermissionDenied)),
            ),
        ],
    );
    assert_eq!(case.encrypt(), Err(Error::Io(ErrorKind::PermissionDenied)));
    scope.finish();
    assert!(!case.archive.exists());
    assert_no_temps(case.root.path());
    let scope = Scope::new(case.root.path(), unsupported);
    case.encrypt().unwrap();
    assert!(scope.finish().contains(&Point::BeforeRename));
    case.assert_valid(&case.root.path().join("valid"));
}

#[test]
fn rec007_boundary_sizes_roundtrip_without_faults() {
    for v2 in [false, true] {
        for size in [0, 1, 65_535, 65_536, 65_537] {
            let case = ArchiveCase::new(v2, false, size);
            let report = case.encrypt().unwrap();
            assert_eq!(report.bytes, size as u64);
            case.assert_valid(&case.root.path().join("valid"));
            assert_no_temps(case.root.path());
        }
    }
}

#[cfg(unix)]
#[test]
fn rec014_parent_sync_failure_is_best_effort_after_publish() {
    for v2 in [false, true] {
        let case = ArchiveCase::new(v2, v2, 1);
        let fault = plan(
            Point::BeforeDirSync,
            Action::Fail(Failure::Kind(ErrorKind::PermissionDenied)),
        );
        let scope = Scope::new(case.root.path(), fault);
        case.encrypt().unwrap();
        let trace = scope.finish();
        assert!(
            trace
                .iter()
                .position(|p| *p == Point::AfterPublish)
                .unwrap()
                < trace
                    .iter()
                    .position(|p| *p == Point::BeforeDirSync)
                    .unwrap()
        );
        let target = case.root.path().join("out");
        let scope = Scope::new(case.root.path(), fault);
        crate::files::decrypt(&case.archive, &target, &case.unlock()).unwrap();
        scope.finish();
        assert!(
            tree_bytes(&target) == tree_bytes(&case.source),
            "Output changed / Ausgabe verändert"
        );
        assert_no_temps(case.root.path());
    }
}

//! DE: REC-008/009: Datei-/Baumausgabe, späte Manipulation und Cleanup-Grenzen.
//! EN: REC-008/009: file/tree output, late tampering and cleanup boundaries.
#![allow(clippy::unwrap_used)]

use crate::fault_fixture_tests::{ArchiveCase, assert_no_temps, plan, tree_bytes};
use crate::fault_io_tests::{Action, Failure, Point, Scope};
use crate::{Error, files};
use std::io::ErrorKind;

#[test]
fn rec008_decrypt_failures_never_publish_partial_file_or_tree() {
    for v2 in [false, true] {
        for tree in [false, true] {
            let case = ArchiveCase::new(v2, tree, 65_537);
            case.encrypt().unwrap();
            let archive_before = std::fs::read(&case.archive).unwrap();
            let source_before = tree_bytes(&case.source);
            let fail = Failure::Kind(ErrorKind::StorageFull);
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
                let target = case.root.path().join("out");
                let scope = Scope::new(case.root.path(), fault);
                let result = files::decrypt(&case.archive, &target, &case.unlock());
                let trace = scope.finish();
                assert_eq!(result, Err(Error::Io(ErrorKind::StorageFull)));
                assert!(!trace.contains(&Point::AfterPublish));
                assert!(!target.exists());
                assert!(
                    std::fs::read(&case.archive).unwrap() == archive_before,
                    "Archive changed / Archiv verändert"
                );
                assert!(
                    tree_bytes(&case.source) == source_before,
                    "Source changed / Quelle verändert"
                );
                case.assert_no_secrets(&result.unwrap_err().to_string());
                assert_no_temps(case.root.path());
            }
            case.assert_valid(&case.root.path().join("valid"));
        }
    }
}

#[test]
fn rec008_directory_rename_failure_and_postpublish_error() {
    for v2 in [false, true] {
        let case = ArchiveCase::new(v2, true, 1);
        case.encrypt().unwrap();
        for point in [Point::BeforeRename, Point::AfterPublish] {
            let target = case.root.path().join(format!("out-{point:?}"));
            let scope = Scope::new(
                case.root.path(),
                plan(
                    point,
                    Action::Fail(Failure::Kind(ErrorKind::PermissionDenied)),
                ),
            );
            assert_eq!(
                files::decrypt(&case.archive, &target, &case.unlock()),
                Err(Error::Io(ErrorKind::PermissionDenied))
            );
            scope.finish();
            if point == Point::AfterPublish {
                assert!(
                    tree_bytes(&target) == tree_bytes(&case.source),
                    "Output changed / Ausgabe verändert"
                );
            } else {
                assert!(!target.exists());
            }
            assert_no_temps(case.root.path());
        }
    }
}

#[test]
fn rec009_decrypt_primary_error_survives_cleanup_failure() {
    for tree in [false, true] {
        let case = ArchiveCase::new(true, tree, 65_537);
        case.encrypt().unwrap();
        let before = std::fs::read(&case.archive).unwrap();
        let foreign = case.root.path().join(".foreign.tmp-0000000000000000");
        std::fs::write(&foreign, b"foreign / fremd").unwrap();
        let target = case.root.path().join("out");
        let remove = if tree {
            Point::BeforeRemoveDirAll
        } else {
            Point::BeforeRemoveFile
        };
        let scope = Scope::sequence(
            case.root.path(),
            vec![
                plan(
                    Point::BeforeFileSync,
                    Action::Fail(Failure::Kind(ErrorKind::StorageFull)),
                ),
                plan(
                    remove,
                    Action::Fail(Failure::Kind(ErrorKind::PermissionDenied)),
                ),
            ],
        );
        assert_eq!(
            files::decrypt(&case.archive, &target, &case.unlock()),
            Err(Error::Io(ErrorKind::StorageFull))
        );
        scope.finish();
        assert!(!target.exists());
        let stale: Vec<_> = own_temps(case.root.path());
        assert_eq!(stale.len(), 1);
        let remnants = tree_bytes(&stale[0]);
        files::decrypt(&case.archive, &target, &case.unlock()).unwrap();
        assert!(
            tree_bytes(&stale[0]) == remnants,
            "Stale changed / Rest verändert"
        );
        assert!(
            tree_bytes(&target) == tree_bytes(&case.source),
            "Output changed / Ausgabe verändert"
        );
        assert!(
            std::fs::read(&case.archive).unwrap() == before,
            "Archive changed / Archiv verändert"
        );
        assert_eq!(std::fs::read(&foreign).unwrap(), b"foreign / fremd");
    }
}

#[test]
fn rec008_late_authentication_failure_never_reaches_publish() {
    for v2 in [false, true] {
        for tree in [false, true] {
            let case = ArchiveCase::new(v2, tree, 3 * 65_536 + 7);
            case.encrypt().unwrap();
            let original = std::fs::read(&case.archive).unwrap();
            let mut damaged = original.clone();
            *damaged.last_mut().unwrap() ^= 1;
            std::fs::write(&case.archive, &damaged).unwrap();
            let target = case.root.path().join("out");
            let remove = if tree {
                Point::BeforeRemoveDirAll
            } else {
                Point::BeforeRemoveFile
            };
            let scope = Scope::new(
                case.root.path(),
                plan(
                    remove,
                    Action::Fail(Failure::Kind(ErrorKind::PermissionDenied)),
                ),
            );
            assert_eq!(
                files::decrypt(&case.archive, &target, &case.unlock()),
                Err(Error::Decrypt)
            );
            let trace = scope.finish();
            assert!(trace.contains(&Point::Write));
            assert!(!trace.contains(&Point::BeforePublish));
            assert!(!target.exists());
            assert_eq!(own_temps(case.root.path()).len(), 1);
            std::fs::write(&case.archive, &original).unwrap();
            case.assert_valid(&case.root.path().join("valid"));
        }
    }
}

fn own_temps(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".out.tmp-")
        })
        .collect()
}

#[test]
fn rec009_encrypt_primary_error_survives_cleanup_failure() {
    let case = ArchiveCase::new(true, false, 65_537);
    let before = tree_bytes(&case.source);
    let scope = Scope::sequence(
        case.root.path(),
        vec![
            plan(
                Point::BeforeFileSync,
                Action::Fail(Failure::Kind(ErrorKind::StorageFull)),
            ),
            plan(
                Point::BeforeRemoveFile,
                Action::Fail(Failure::Kind(ErrorKind::PermissionDenied)),
            ),
        ],
    );
    assert_eq!(case.encrypt(), Err(Error::Io(ErrorKind::StorageFull)));
    scope.finish();
    assert!(!case.archive.exists());
    let stale: Vec<_> = std::fs::read_dir(case.root.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".archive.pqkf.tmp-")
        })
        .collect();
    assert_eq!(stale.len(), 1);
    let remnants = std::fs::read(&stale[0]).unwrap();
    case.encrypt().unwrap();
    case.assert_valid(&case.root.path().join("valid"));
    assert!(
        std::fs::read(&stale[0]).unwrap() == remnants,
        "Stale changed / Rest verändert"
    );
    assert!(
        tree_bytes(&case.source) == before,
        "Source changed / Quelle verändert"
    );
}

#[test]
fn rec008_empty_tree_failures_and_control_are_unambiguous() {
    for v2 in [false, true] {
        let case = ArchiveCase::new(v2, true, 0);
        std::fs::remove_file(case.source.join("a")).unwrap();
        std::fs::remove_dir_all(case.source.join("nested")).unwrap();
        case.encrypt().unwrap();
        let target = case.root.path().join("out");
        for point in [Point::AfterTempCreate, Point::BeforePublish] {
            let scope = Scope::new(
                case.root.path(),
                plan(
                    point,
                    Action::Fail(Failure::Kind(ErrorKind::PermissionDenied)),
                ),
            );
            assert_eq!(
                files::decrypt(&case.archive, &target, &case.unlock()),
                Err(Error::Io(ErrorKind::PermissionDenied))
            );
            scope.finish();
            assert!(!target.exists());
            assert_no_temps(case.root.path());
        }
        files::decrypt(&case.archive, &target, &case.unlock()).unwrap();
        assert!(target.is_dir());
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
        assert_no_temps(case.root.path());
    }
}

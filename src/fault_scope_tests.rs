//! DE: QA1-REC-015: Scope-Isolation, Wiederholbarkeit und echter Schreiber.
//! EN: QA1-REC-015: scope isolation, repeatability and real writer.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::{ErrorKind, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use crate::envelope::{self, Overwrite};
use crate::fault_fixture_tests::plan;
use crate::fault_io_tests::{Action, Failure, Point, Scope};
use crate::fsutil::open_new;

#[test]
fn rec015_repeated_fault_has_same_trace_and_state() {
    let mut traces = Vec::new();
    for _ in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out");
        let scope = Scope::new(
            dir.path(),
            plan(
                Point::Write,
                Action::Partial {
                    after: 3,
                    failure: Failure::Kind(ErrorKind::StorageFull),
                },
            ),
        );
        assert!(envelope::write_atomic(&target, b"synthetic", Overwrite::No).is_err());
        traces.push(scope.finish());
        assert!(!target.exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    assert!(traces.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn rec015_scopes_are_thread_and_root_isolated() {
    let (ready, observed) = mpsc::channel();
    let mut releases = Vec::new();
    let threads: Vec<_> = [ErrorKind::StorageFull, ErrorKind::PermissionDenied]
        .into_iter()
        .map(|kind| {
            let (release, proceed) = mpsc::channel();
            releases.push(release);
            let ready = ready.clone();
            std::thread::spawn(move || isolated_worker(kind, &ready, &proceed))
        })
        .collect();
    for _ in 0..2 {
        observed.recv_timeout(Duration::from_secs(30)).unwrap();
    }
    for release in releases {
        release.send(()).unwrap();
    }
    for thread in threads {
        thread.join().unwrap();
    }
}

fn isolated_worker(kind: ErrorKind, ready: &Sender<()>, proceed: &Receiver<()>) {
    let root = tempfile::tempdir().unwrap();
    let foreign = tempfile::tempdir().unwrap();
    let scope = Scope::new(
        root.path(),
        plan(Point::BeforeOpen, Action::Fail(Failure::Kind(kind))),
    );
    ready.send(()).unwrap();
    proceed.recv_timeout(Duration::from_secs(30)).unwrap();
    envelope::write_atomic(&foreign.path().join("safe"), b"foreign", Overwrite::No).unwrap();
    let result = envelope::write_atomic(&root.path().join("fail"), b"own", Overwrite::No);
    assert_eq!(result, Err(crate::Error::Io(kind)));
    scope.finish();
    assert_eq!(
        std::fs::read(foreign.path().join("safe")).unwrap(),
        b"foreign"
    );
}

#[test]
fn rec015_partial_write_hits_exact_byte_boundary() {
    for after in [0, 1, 7] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("out");
        let scope = Scope::new(
            root.path(),
            plan(
                Point::Write,
                Action::Partial {
                    after,
                    failure: Failure::Kind(ErrorKind::StorageFull),
                },
            ),
        );
        let mut file = open_new(&path).unwrap();
        assert_eq!(
            file.write_all(b"12345678").unwrap_err().kind(),
            ErrorKind::StorageFull
        );
        scope.finish();
        drop(file);
        assert_eq!(std::fs::read(&path).unwrap(), &b"12345678"[..after]);
    }
}

#[test]
fn rec015_occurrence_and_flush_are_observed() {
    let dir = tempfile::tempdir().unwrap();
    let mut fault = plan(
        Point::BeforeFlush,
        Action::Fail(Failure::Kind(ErrorKind::Other)),
    );
    fault.occurrence = 2;
    let scope = Scope::new(dir.path(), fault);
    let mut file = open_new(&dir.path().join("out")).unwrap();
    file.write_all(b"synthetic").unwrap();
    file.flush().unwrap();
    assert_eq!(file.flush().unwrap_err().kind(), ErrorKind::Other);
    file.flush().unwrap();
    let trace = scope.finish();
    assert_eq!(
        trace.iter().filter(|&&p| p == Point::BeforeFlush).count(),
        3
    );
}

#[test]
fn rec015_rejects_unreached_nested_and_zero_occurrence_plans() {
    let dir = tempfile::tempdir().unwrap();
    let fault = plan(
        Point::BeforeOpen,
        Action::Fail(Failure::Kind(ErrorKind::Other)),
    );
    assert!(catch_unwind(AssertUnwindSafe(|| Scope::new(dir.path(), fault).finish())).is_err());
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _unused = Scope::new(dir.path(), fault);
        }))
        .is_err()
    );
    let mut invalid = fault;
    invalid.occurrence = 0;
    assert!(catch_unwind(AssertUnwindSafe(|| Scope::new(dir.path(), invalid))).is_err());
    let scope = Scope::new(dir.path(), fault);
    assert!(catch_unwind(AssertUnwindSafe(|| Scope::new(dir.path(), fault))).is_err());
    assert!(open_new(&dir.path().join("out")).is_err());
    scope.finish();
}

#[cfg(unix)]
#[test]
fn rec015_parent_and_symlink_paths_cannot_escape_root() {
    let root = tempfile::tempdir().unwrap();
    let foreign = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(foreign.path(), root.path().join("link")).unwrap();
    let scope = Scope::new(
        root.path(),
        plan(
            Point::BeforeOpen,
            Action::Fail(Failure::Kind(ErrorKind::Other)),
        ),
    );
    assert!(crate::fault_io_tests::capture(&root.path().join("../outside")).is_none());
    assert!(crate::fault_io_tests::capture(&root.path().join("link/outside")).is_none());
    assert!(open_new(&root.path().join("own")).is_err());
    scope.finish();
    assert_eq!(std::fs::read_dir(foreign.path()).unwrap().count(), 0);
}

#[test]
fn rec015_unwinding_restores_scope_and_detaches_open_writer() {
    let dir = tempfile::tempdir().unwrap();
    let fault = plan(
        Point::BeforeFileSync,
        Action::Fail(Failure::Kind(ErrorKind::Other)),
    );
    let mut file = None;
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _scope = Scope::new(dir.path(), fault);
            file = Some(open_new(&dir.path().join("out")).unwrap());
            panic!("Synthetic unwind / Synthetisches Unwinding");
        }))
        .is_err()
    );
    let old = file.unwrap();
    let scope = Scope::new(dir.path(), fault);
    let next = open_new(&dir.path().join("next")).unwrap();
    old.sync_all().unwrap();
    assert_eq!(next.sync_all().unwrap_err().kind(), ErrorKind::Other);
    scope.finish();
}

#[test]
fn rec015_sequence_requires_every_fault_and_restores_after_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out");
    let first = plan(
        Point::BeforeOpen,
        Action::Fail(Failure::Kind(ErrorKind::StorageFull)),
    );
    let second = plan(
        Point::BeforeFileSync,
        Action::Fail(Failure::Kind(ErrorKind::PermissionDenied)),
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let scope = Scope::sequence(dir.path(), vec![first, second]);
            assert!(crate::fault_io_tests::checkpoint(&path, Point::BeforeOpen).is_err());
            scope.finish();
        }))
        .is_err()
    );
    let scope = Scope::sequence(dir.path(), vec![first, second]);
    assert_eq!(
        crate::fault_io_tests::checkpoint(&path, Point::BeforeOpen)
            .unwrap_err()
            .kind(),
        ErrorKind::StorageFull
    );
    assert_eq!(
        crate::fault_io_tests::checkpoint(&path, Point::BeforeFileSync)
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    scope.finish();
}

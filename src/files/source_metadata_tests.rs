//! DE: Tatsächliche native Records, No-Follow, Fehler und Sperrverweigerung.
//! EN: Actual native records, no-follow, errors and lock refusal.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::Error;
#[cfg(target_os = "linux")]
use crate::hardening::memlock;

fn locked(metadata: &Metadata) {
    let record = metadata.0.get();
    crate::locked_owner_test_support::locked(record);
    #[cfg(windows)]
    {
        let mut query =
            SecretState::new(pqkeep_platform::memory_fixture::MemoryLockQuery::empty()).unwrap();
        let start = std::ptr::from_ref(record).addr();
        assert!(query.get_mut().is_locked(start).unwrap());
        assert!(
            query
                .get_mut()
                .is_locked(start + size_of_val(record) - 1)
                .unwrap()
        );
    }
}

#[test]
fn actual_native_records_match_public_files_and_directory_reference() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("public-ä-日本語");
    std::fs::write(&file, b"public metadata fixture").unwrap();
    for path in [&file, &root.path().to_path_buf()] {
        let native = Metadata::read(path).unwrap();
        locked(&native);
        let reference = std::fs::symlink_metadata(path).unwrap();
        assert_eq!(native.is_file(), reference.is_file());
        assert_eq!(native.is_dir(), reference.is_dir());
        assert_eq!(native.is_symlink(), reference.file_type().is_symlink());
        assert_eq!(native.bytes(), reference.len());
        locked(&native);
    }
}

#[test]
fn missing_and_nul_paths_keep_native_io_error_classes() {
    let root = tempfile::tempdir().unwrap();
    assert!(matches!(
        Metadata::read(&root.path().join("missing")),
        Err(Error::Io(std::io::ErrorKind::NotFound))
    ));
    assert!(matches!(
        Metadata::read(Path::new("bad\0name")),
        Err(Error::Io(std::io::ErrorKind::InvalidInput))
    ));
}

#[cfg(unix)]
#[test]
fn dangling_symlink_is_not_followed_or_misclassified() {
    let root = tempfile::tempdir().unwrap();
    let link = root.path().join("link");
    std::os::unix::fs::symlink(root.path().join("missing-target"), &link).unwrap();
    let metadata = Metadata::read(&link).unwrap();
    locked(&metadata);
    assert!(metadata.is_symlink());
    assert!(!metadata.is_file());
    assert!(!metadata.is_dir());
    assert_eq!(
        metadata.bytes(),
        std::fs::symlink_metadata(&link).unwrap().len()
    );
}

#[cfg(windows)]
#[test]
fn native_metadata_matches_std_while_a_file_is_open_without_sharing() {
    use std::os::windows::fs::OpenOptionsExt;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("held-public-file");
    std::fs::write(&path, b"public sharing fixture").unwrap();
    let _held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    let metadata = Metadata::read(&path).unwrap();
    locked(&metadata);
    assert!(metadata.is_file());
    assert_eq!(
        metadata.bytes(),
        std::fs::symlink_metadata(&path).unwrap().len()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn actual_metadata_denial_and_unwind_leave_parent_limits_unchanged() {
    use rustix::process::{Resource, getrlimit};
    let baseline = getrlimit(Resource::Memlock);
    crate::locked_owner_test_support::isolated_test(
        "files::source_metadata::tests::metadata_denial_child",
        "PQKEEP_SOURCE_METADATA_CHILD",
    );
    assert_eq!(getrlimit(Resource::Memlock), baseline);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "DE/EN: Nur eigenes begrenztes Kind / bounded own child only"]
fn metadata_denial_child() {
    use rustix::process::{Resource, getrlimit, setrlimit};
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("public-file");
    std::fs::write(&file, b"public fixture").unwrap();
    let baseline = memlock::stats().locked_pages;
    let caught = std::panic::catch_unwind(|| {
        let metadata = Metadata::read(&file).unwrap();
        locked(&metadata);
        std::panic::resume_unwind(Box::new(()));
    });
    assert!(caught.is_err());
    assert_eq!(memlock::stats().locked_pages, baseline);
    let mut limit = getrlimit(Resource::Memlock);
    limit.current = Some(0);
    setrlimit(Resource::Memlock, limit).unwrap();
    assert!(matches!(Metadata::read(&file), Err(Error::MemoryLock)));
    assert_eq!(memlock::stats().locked_pages, baseline);
}

#[cfg(windows)]
#[test]
fn direct_find_fixture_writes_actual_sdk_record_into_prelocked_caller() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("public-find-ä");
    std::fs::write(&path, b"public find fixture").unwrap();
    let encoded = NativePath::from_path(&path).unwrap();
    let mut metadata =
        Metadata(SecretState::new(pqkeep_platform::SourceMetadata::empty()).unwrap());
    locked(&metadata);
    metadata
        .0
        .get_mut()
        .capture_find_fixture(encoded.encoded().unwrap())
        .unwrap();
    locked(&metadata);
    assert!(metadata.is_file());
    assert!(!metadata.is_symlink());
    assert_eq!(
        metadata.bytes(),
        std::fs::symlink_metadata(&path).unwrap().len()
    );
}

#[cfg(windows)]
#[test]
fn windows_file_directory_and_dangling_symlinks_keep_no_follow_semantics() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("target-file");
    let directory = root.path().join("target-directory");
    std::fs::write(&file, b"public symlink fixture").unwrap();
    std::fs::create_dir(&directory).unwrap();
    let file_link = root.path().join("file-link");
    let dir_link = root.path().join("directory-link");
    let dangling = root.path().join("dangling");
    std::os::windows::fs::symlink_file(&file, &file_link).unwrap();
    std::os::windows::fs::symlink_dir(&directory, &dir_link).unwrap();
    std::os::windows::fs::symlink_file(root.path().join("missing"), &dangling).unwrap();
    for path in [&file_link, &dir_link, &dangling] {
        let metadata = Metadata::read(path).unwrap();
        locked(&metadata);
        assert!(metadata.is_symlink());
        assert!(!metadata.is_file());
        assert!(!metadata.is_dir());
        assert_eq!(
            metadata.bytes(),
            std::fs::symlink_metadata(path).unwrap().len()
        );
    }
}

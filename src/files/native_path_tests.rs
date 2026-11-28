//! DE: Native Repräsentation und reale Owner-Sperren vor Caller-Portierung prüfen.
//! EN: Check native representation and actual owner locks before porting callers.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::locked_owner_test_support::locked;

fn assert_owner(path: &NativePath) {
    locked(path.0.get());
    locked(path.0.get().0.expose());
    #[cfg(unix)]
    path.0.get().0.assert_metadata_locked();
    #[cfg(windows)]
    {
        let mut query =
            SecretState::new(pqkeep_platform::memory_fixture::MemoryLockQuery::empty()).unwrap();
        let owner = std::ptr::from_ref(path.0.get()).addr();
        let units = path.0.get().0.expose();
        assert!(query.get_mut().is_locked(owner).unwrap());
        assert!(
            query
                .get_mut()
                .is_locked(owner + size_of_val(path.0.get()) - 1)
                .unwrap()
        );
        assert!(query.get_mut().is_locked(units.as_ptr().addr()).unwrap());
        assert!(
            query
                .get_mut()
                .is_locked(units.as_ptr().addr() + size_of_val(units) - 1)
                .unwrap()
        );
    }
}

#[test]
fn native_open_preserves_the_std_invalid_nul_error_class() {
    assert!(matches!(
        open_file(Path::new("public\0fixture")),
        Err(Error::Io(std::io::ErrorKind::InvalidInput))
    ));
}

#[test]
fn native_path_roundtrips_and_duplicates_in_distinct_locked_owners() {
    let input = Path::new("public directory/öffentlicher Name.txt");
    let original = NativePath::from_path(input).unwrap();
    let copy = original.try_duplicate().unwrap();
    assert_owner(&original);
    assert_owner(&copy);
    let equal = original.encoded().unwrap() == copy.encoded().unwrap();
    assert!(equal);
    let distinct = original.encoded().unwrap().as_ptr() != copy.encoded().unwrap().as_ptr();
    assert!(distinct);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let equal = original.c_str().unwrap().to_bytes() == input.as_os_str().as_bytes();
        assert!(equal);
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        assert!(
            original
                .encoded()
                .unwrap()
                .iter()
                .copied()
                .eq(input.as_os_str().encode_wide().chain(std::iter::once(0)))
        );
    }
    assert_eq!(format!("{original:?}"), "NativePath([REDACTED])");
}

#[test]
fn native_read_adapter_preserves_file_contents_and_missing_file_error() {
    use std::io::Read;
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("öffentlicher fixture.txt");
    let expected = b"public native file fixture";
    std::fs::write(&source, expected).unwrap();
    let mut file = open_file(&source).unwrap();
    let mut actual = crate::crypto::SecretBytes::zeroed(expected.len()).unwrap();
    file.read_exact(actual.expose_mut()).unwrap();
    let equal = actual.expose() == expected;
    assert!(equal);
    let mut eof = [0];
    assert_eq!(file.read(&mut eof).unwrap(), 0);
    assert!(matches!(
        open_file(&root.path().join("missing fixture")),
        Err(Error::Io(std::io::ErrorKind::NotFound))
    ));
}

#[cfg(unix)]
#[test]
fn non_utf8_native_bytes_survive_without_lossy_string_staging() {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
    let bytes = b"public/\xff\xfe fixture";
    let path = NativePath::from_path(Path::new(OsStr::from_bytes(bytes))).unwrap();
    let equal = path.c_str().unwrap().to_bytes() == bytes;
    assert!(equal);
    assert_owner(&path);
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join(OsStr::from_bytes(bytes));
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, b"public fixture").unwrap();
    assert!(open_file(&source).is_ok());
}

#[cfg(windows)]
#[test]
fn native_wide_surrogates_survive_without_a_lossy_utf8_roundtrip() {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    let units = [0x61, 0xd800, 0x62, 0xdc00, 0xd83d, 0xde00];
    let input = OsString::from_wide(&units);
    let path = NativePath::from_path(Path::new(&input)).unwrap();
    assert!(
        path.encoded()
            .unwrap()
            .iter()
            .copied()
            .eq(units.into_iter().chain(std::iter::once(0)))
    );
    assert_owner(&path);
}

#[test]
fn invalid_native_nul_preserves_previous_path_and_explicit_wiping_clears_units() {
    let mut path = NativePath::from_path(Path::new("public fixture")).unwrap();
    let before = path.try_duplicate().unwrap();
    assert!(matches!(
        path.copy_native(&[65, 0, 66]),
        Err(Error::InvalidInput { field: "path" })
    ));
    let equal = path.encoded().unwrap() == before.encoded().unwrap();
    assert!(equal);
    path.zeroize();
    assert!(path.0.get().0.expose().iter().all(|unit| *unit == 0));
}

#[cfg(target_os = "linux")]
#[test]
fn native_path_denial_child_preserves_parent_limit() {
    use rustix::process::{Resource, getrlimit};
    let before = getrlimit(Resource::Memlock);
    crate::locked_owner_test_support::isolated_test(
        "files::native_path::tests::native_path_denial_child",
        "PQKEEP_NATIVE_PATH_CHILD",
    );
    assert_eq!(getrlimit(Resource::Memlock), before);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "DE/EN: Nur eigenes begrenztes Kind / bounded owned child only"]
fn native_path_denial_child() {
    use crate::hardening::memlock;
    use rustix::process::{Resource, getrlimit, setrlimit};
    assert_eq!(std::env::var("PQKEEP_NATIVE_PATH_CHILD").unwrap(), "1");
    let baseline = memlock::stats().locked_pages;
    let unwind = std::panic::catch_unwind(|| {
        let path = NativePath::from_path(Path::new("public fixture")).unwrap();
        assert_owner(&path);
        std::panic::resume_unwind(Box::new(()));
    });
    assert!(unwind.is_err());
    assert_eq!(memlock::stats().locked_pages, baseline);
    let source = vec![b'x'; 2 * region::page::size()];
    let path = NativePath::from_native(&source).unwrap();
    let baseline = memlock::stats().locked_pages;
    let mut limit = getrlimit(Resource::Memlock);
    limit.current = Some(0);
    setrlimit(Resource::Memlock, limit).unwrap();
    assert_eq!(getrlimit(Resource::Memlock).current, Some(0));
    assert!(matches!(path.try_duplicate(), Err(Error::MemoryLock)));
    let unchanged = path.c_str().unwrap().to_bytes() == source;
    assert!(unchanged);
    assert_eq!(memlock::stats().locked_pages, baseline);
}

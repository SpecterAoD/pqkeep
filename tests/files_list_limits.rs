//! DE: LIST-005: echte Container an beiden List-Grenzen; check-Limits unverändert.
//! EN: LIST-005: real containers at both listing caps; check limits unchanged.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::archive::{build, dir_entry, end, key};
use pqkeep::Error;
use pqkeep::files::{self, Content, MAX_LIST_ENTRIES, MAX_LIST_PATH_BYTES, Unlock};

fn expect_limit(result: &Result<files::Listing, Error>) {
    assert_eq!(
        result,
        &Err(Error::InvalidInput {
            field: "list_limit"
        })
    );
}

#[test]
fn ten_thousand_entries_are_valid_but_the_next_is_listing_only_error() {
    let key = key();
    let dir = tempfile::tempdir().unwrap();
    let enc = dir.path().join("input.pqkf");
    let mut raw = Vec::new();
    for n in 0..MAX_LIST_ENTRIES {
        raw.extend(dir_entry(&format!("d{n}")));
    }
    let mut valid = raw.clone();
    valid.extend(end(MAX_LIST_ENTRIES as u64));
    build(&key, Content::Directory, &valid, &enc);
    let unlock = Unlock::Key(&key.unlocked);
    assert_eq!(
        files::list(&enc, &unlock).unwrap().entries.len(),
        MAX_LIST_ENTRIES
    );
    raw.extend(dir_entry("extra"));
    raw.extend(end(MAX_LIST_ENTRIES as u64 + 1));
    build(&key, Content::Directory, &raw, &enc);
    expect_limit(&files::list(&enc, &unlock));
    assert_eq!(files::check(&enc, &unlock).unwrap().directories, 10_001);
    assert_eq!(common::dir_names(dir.path()), ["input.pqkf"]);
}

#[test]
fn sixteen_mib_path_bytes_are_valid_but_one_more_byte_is_rejected() {
    let key = key();
    let dir = tempfile::tempdir().unwrap();
    let enc = dir.path().join("input.pqkf");
    let mut raw = Vec::new();
    let count = MAX_LIST_PATH_BYTES / files::paths::MAX_PATH_BYTES;
    for n in 0..count {
        let prefix = format!("{n:04}");
        let component = "a".repeat(250);
        let path = format!(
            "{prefix}/{}{}",
            format!("{component}/").repeat(16),
            "b".repeat(75)
        );
        assert_eq!(path.len(), files::paths::MAX_PATH_BYTES);
        raw.extend(dir_entry(&path));
    }
    let mut valid = raw.clone();
    valid.extend(end(count as u64));
    build(&key, Content::Directory, &valid, &enc);
    let unlock = Unlock::Key(&key.unlocked);
    assert_eq!(files::list(&enc, &unlock).unwrap().entries.len(), count);
    raw.extend(dir_entry("x"));
    raw.extend(end(count as u64 + 1));
    build(&key, Content::Directory, &raw, &enc);
    expect_limit(&files::list(&enc, &unlock));
    assert_eq!(
        files::check(&enc, &unlock).unwrap().directories,
        count as u64 + 1
    );
}

#[test]
fn empty_directory_is_a_valid_empty_listing() {
    let key = key();
    let dir = tempfile::tempdir().unwrap();
    let enc = dir.path().join("empty.pqkf");
    build(&key, Content::Directory, &end(0), &enc);
    let listing = files::list(&enc, &Unlock::Key(&key.unlocked)).unwrap();
    assert!(listing.entries.is_empty());
    assert_eq!(listing.report, files::Report::default());
}

//! DE: Bösartige, aber KORREKT für den Empfänger verschlüsselte Archive (jeder mit
//! dem öffentlichen Schlüssel kann solche bauen). Alles muss abgewiesen werden,
//! ohne Ziel, ohne Reste und ohne Dateien außerhalb des Ziels.
//! EN: Malicious but CORRECTLY encrypted archives for the recipient (anyone with
//! the public key can build them). Everything must be rejected – no target, no
//! leftovers and no files outside the target.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::archive::{Key, build, dir_entry, end, file_entry, key};
use pqkeep::files::{self, Content, Unlock};

fn assert_rejected(key: &Key, content: Content, plaintext: &[u8], what: &str) {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("arbeit");
    std::fs::create_dir(&work).unwrap();
    let enc = dir.path().join("evil.pqkf");
    build(key, content, plaintext, &enc);
    // DE: `check` (#86) muss dieselben Fälle abweisen. EN: `check` (#86) must reject the same cases.
    let checked = files::check(&enc, &Unlock::Key(&key.unlocked));
    assert!(
        checked.is_err(),
        "{what}: check angenommen / check accepted"
    );
    assert!(files::list(&enc, &Unlock::Key(&key.unlocked)).is_err());
    let target = work.join("ziel");
    let result = files::decrypt(&enc, &target, &Unlock::Key(&key.unlocked));
    assert!(result.is_err(), "{what}: angenommen / accepted");
    assert_eq!(
        common::dir_names(&work),
        Vec::<String>::new(),
        "{what}: Reste / leftovers"
    );
    assert_eq!(
        common::dir_names(dir.path()),
        vec!["arbeit", "evil.pqkf"],
        "{what}: außerhalb / outside"
    );
}

#[test]
fn control_case_is_accepted() {
    // DE: Gegenprobe: dasselbe Werkzeug baut gültige Archive.
    // EN: Cross-check: the same tool builds valid archives.
    let key = key();
    let dir = tempfile::tempdir().unwrap();
    let enc = dir.path().join("ok.pqkf");
    let plain = [dir_entry("a"), file_entry("a/b.txt", b"hi", true), end(2)].concat();
    build(&key, Content::Directory, &plain, &enc);
    let report = files::check(&enc, &Unlock::Key(&key.unlocked)).unwrap();
    assert_eq!((report.files, report.directories, report.bytes), (1, 1, 2));
    let listed = files::list(&enc, &Unlock::Key(&key.unlocked)).unwrap();
    assert_eq!(listed.report, report);
    assert_eq!(listed.entries.len(), 2);
    let out = dir.path().join("ok");
    files::decrypt(&enc, &out, &Unlock::Key(&key.unlocked)).unwrap();
    assert_eq!(std::fs::read(out.join("a").join("b.txt")).unwrap(), b"hi");
}

#[test]
fn path_traversal_and_absolute_paths() {
    let key = key();
    for evil in [
        "../evil.txt",
        "a/../../evil.txt",
        "/etc/evil",
        "C:\\evil.txt",
        "C:/evil.txt",
        "\\\\server\\share\\x",
        "a\\..\\evil",
        "CON",
        "aux.txt",
        "a/./b",
        "",
        "trailing.",
    ] {
        let plain = [file_entry(evil, b"x", true), end(1)].concat();
        assert_rejected(&key, Content::Directory, &plain, evil);
    }
}

#[test]
fn duplicates_and_conflicts() {
    let key = key();
    let cases = [
        (
            "dup",
            [
                file_entry("a.txt", b"1", true),
                file_entry("a.txt", b"2", true),
                end(2),
            ]
            .concat(),
        ),
        (
            "case",
            [
                file_entry("a.txt", b"1", true),
                file_entry("A.TXT", b"2", true),
                end(2),
            ]
            .concat(),
        ),
        (
            "below file",
            [
                file_entry("a", b"1", true),
                file_entry("a/b", b"2", true),
                end(2),
            ]
            .concat(),
        ),
        ("dir dup", [dir_entry("d"), dir_entry("D"), end(2)].concat()),
    ];
    for (what, plain) in cases {
        assert_rejected(&key, Content::Directory, &plain, what);
    }
}

#[test]
fn structural_errors() {
    let key = key();
    let mut bad_tag = file_entry("a.txt", b"x", true);
    bad_tag[0] = 9;
    let mut non_utf8 = file_entry("ab", b"x", true);
    non_utf8[3] = 0xFF;
    let cases = [
        (
            "checksum",
            [file_entry("a.txt", b"data", false), end(1)].concat(),
        ),
        ("count", [file_entry("a.txt", b"x", true), end(5)].concat()),
        ("no end", file_entry("a.txt", b"x", true)),
        (
            "trailing",
            [file_entry("a.txt", b"x", true), end(1), vec![0u8; 3]].concat(),
        ),
        ("unknown tag", [bad_tag, end(1)].concat()),
        ("non-utf8", [non_utf8, end(1)].concat()),
        ("size too big", {
            let mut v = file_entry("a.txt", b"x", true);
            v[8..16].copy_from_slice(&1_000u64.to_le_bytes());
            [v, end(1)].concat()
        }),
        ("empty", Vec::new()),
    ];
    for (what, plain) in cases {
        assert_rejected(&key, Content::Directory, &plain, what);
    }
}

#[test]
fn single_file_content_rules() {
    let key = key();
    let cases = [
        ("dir in file", [dir_entry("a"), end(1)].concat()),
        (
            "two files",
            [
                file_entry("a", b"1", true),
                file_entry("b", b"2", true),
                end(2),
            ]
            .concat(),
        ),
        (
            "bad name",
            [file_entry("../a", b"1", true), end(1)].concat(),
        ),
        (
            "bad checksum",
            [file_entry("a", b"1", false), end(1)].concat(),
        ),
    ];
    for (what, plain) in cases {
        assert_rejected(&key, Content::File, &plain, what);
    }
}

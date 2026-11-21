//! DE: Vollständige Tabelle erlaubter und verbotener Archivpfade.
//! EN: Complete table of allowed and forbidden archive paths.

use super::{MAX_COMPONENT_BYTES, MAX_DEPTH, MAX_PATH_BYTES, PathSet, validate};

#[test]
fn allowed_paths() {
    for ok in [
        "a",
        "a/b/c.txt",
        "Ordner mit Leerzeichen/Datei.pdf",
        "Größe/äöü ß.txt",
        ".hidden",
        "a/.config/x",
        "file.tar.gz",
        "CONSOLE.txt",
        "COM10",
        "nul_file",
        "日本語/ファイル",
    ] {
        assert!(validate(ok).is_ok(), "{ok}");
    }
}

#[test]
fn forbidden_paths() {
    for bad in [
        "",
        "/",
        "/etc/passwd",
        "../x",
        "a/../../x",
        "a/./b",
        ".",
        "..",
        "a//b",
        "a/",
        "C:\\Windows\\x",
        "C:/x",
        "\\\\server\\share",
        "a\\b",
        "a:b",
        "a\u{0}b",
        "a\nb",
        "trailing.",
        "trailing ",
        "CON",
        "con.txt",
        "Nul",
        "a/aux/b",
        "COM1",
        "lpt9.log",
        "COM¹",
        "what?",
        "a*b",
        "a|b",
        "<x>",
        "\"q\"",
    ] {
        assert!(validate(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn length_and_depth_limits() {
    assert!(validate(&"a".repeat(MAX_COMPONENT_BYTES)).is_ok());
    assert!(validate(&"a".repeat(MAX_COMPONENT_BYTES + 1)).is_err());
    let deep_ok = vec!["d"; MAX_DEPTH].join("/");
    assert!(validate(&deep_ok).is_ok());
    let too_deep = vec!["d"; MAX_DEPTH + 1].join("/");
    assert!(validate(&too_deep).is_err());
    let long = vec!["x".repeat(200); 21].join("/");
    assert!(long.len() > MAX_PATH_BYTES);
    assert!(validate(&long).is_err());
}

#[test]
fn duplicates_and_conflicts() {
    let mut set = PathSet::default();
    set.insert(&["a"], false).unwrap();
    set.insert(&["a", "x.txt"], true).unwrap();
    assert!(
        set.insert(&["a", "x.txt"], true).is_err(),
        "doppelt / duplicate"
    );
    assert!(
        set.insert(&["A", "X.TXT"], true).is_err(),
        "Groß/klein / case"
    );
    assert!(
        set.insert(&["A"], false).is_err(),
        "Ordner doppelt / dir duplicate"
    );
    assert!(
        set.insert(&["a", "x.txt", "y"], true).is_err(),
        "unter Datei / below file"
    );
    set.insert(&["a", "Ä"], true).unwrap();
    assert!(
        set.insert(&["a", "ä"], true).is_err(),
        "Unicode-Groß/klein / Unicode case"
    );
}

/// DE: LIST-004: Datei als späterer Vorfahr ist ebenfalls ein Konflikt; kein O(n²)-Scan.
/// EN: LIST-004: A later file ancestor also conflicts; avoid a quadratic scan.
#[test]
fn later_file_ancestors_conflict_independently_of_order_and_case() {
    for child_file in [false, true] {
        for (parent, child) in [("a", "a/b"), ("Ä", "ä/b")] {
            let mut set = PathSet::default();
            set.insert(&validate(child).unwrap(), child_file).unwrap();
            set.insert(&["a-"], false).unwrap();
            assert!(set.insert(&validate(parent).unwrap(), true).is_err());
            // DE: Der abgewiesene Vorfahr darf den Zustand nicht vergiften.
            // EN: The rejected ancestor must not poison the state.
            let sibling = format!("{parent}/c");
            set.insert(&validate(&sibling).unwrap(), true).unwrap();
        }
    }
}

#[test]
fn later_directory_parent_and_non_descendant_prefixes_remain_valid() {
    let mut set = PathSet::default();
    set.insert(&["a", "b"], true).unwrap();
    set.insert(&["a"], false).unwrap();
    set.insert(&["ab"], true).unwrap();
    let mut set = PathSet::default();
    set.insert(&["a-"], false).unwrap();
    set.insert(&["a"], true).unwrap();
}

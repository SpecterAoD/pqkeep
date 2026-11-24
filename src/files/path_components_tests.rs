//! DE: Private geliehene Pfadteile und erhaltene öffentliche Verträge.
//! EN: Private borrowed path components and preserved public contracts.
#![allow(clippy::unwrap_used)]

use super::{MAX_COMPONENT_BYTES, MAX_DEPTH, MAX_PATH_BYTES, PathSet, components, validate};

#[test]
fn borrowed_components_replay_without_copying_source_names() {
    let source = String::from("folder/Ä日本語.txt");
    let mut parts = components(&source).unwrap();
    let saved = parts.clone();
    let first = parts.next().unwrap();
    assert!(std::ptr::eq(first.as_ptr(), source.as_ptr()));
    assert_eq!(first.len(), 6);
    let second = parts.next().unwrap();
    assert!(std::ptr::eq(second.as_ptr(), source[7..].as_ptr()));
    assert!(parts.next().is_none());
    assert_eq!(saved.collect::<Vec<_>>(), validate(&source).unwrap());
}

fn accepts(path: &str, expected: bool) {
    assert_eq!(components(path).is_ok(), expected);
    assert_eq!(validate(path).is_ok(), expected);
    assert_eq!(super::validate_only(path).is_ok(), expected);
}

#[test]
fn public_and_borrowed_validation_preserve_exact_byte_depth_boundaries() {
    accepts(&"a".repeat(MAX_COMPONENT_BYTES), true);
    accepts(&"a".repeat(MAX_COMPONENT_BYTES + 1), false);
    accepts(&format!("{}a", "é".repeat(127)), true);
    accepts(&format!("{}ab", "é".repeat(127)), false);
    accepts(&vec!["d"; MAX_DEPTH].join("/"), true);
    accepts(&vec!["d"; MAX_DEPTH + 1].join("/"), false);
    let mut parts = vec!["x".repeat(MAX_COMPONENT_BYTES); 16];
    parts[0].pop();
    parts.push("a".to_owned());
    let mut exact = parts.join("/");
    assert_eq!(exact.len(), MAX_PATH_BYTES);
    accepts(&exact, true);
    exact.push('x');
    accepts(&exact, false);
}

#[test]
fn invalid_later_components_are_rejected_before_any_iterator_is_returned() {
    for path in [
        "good/../bad",
        "good/CON.txt",
        "good//bad",
        "good/trailing.",
        "good/a\u{0}b",
        "good/what?",
        "good/",
        "/good",
        "",
    ] {
        assert!(matches!(
            components(path),
            Err(crate::Error::InvalidInput { field: "path" })
        ));
        accepts(path, false);
    }
}

#[test]
fn borrowed_and_public_path_sets_preserve_unicode_and_prefix_conflicts() {
    let (mut public, mut private) = (PathSet::default(), PathSet::default());
    for (path, file, expected) in [
        ("Ä", false, true),
        ("ä/İΣ", true, true),
        ("Ä/i\u{307}ς", true, false),
        ("Ä/i\u{307}ς/sub", true, false),
        ("Ä", true, false),
        ("Ä/new", true, true),
        ("OTHER/deep/file", true, true),
        ("other", true, false),
        ("other", false, true),
        ("other/deep", false, true),
        ("other/deep", true, false),
        ("childless", true, true),
        ("CHILDLESS/x", true, false),
    ] {
        let before = (private.entries.len(), private.files.len());
        assert_eq!(
            public.insert(&validate(path).unwrap(), file).is_ok(),
            expected
        );
        assert_eq!(
            private
                .insert_components(components(path).unwrap(), file)
                .is_ok(),
            expected
        );
        if !expected {
            assert_eq!((private.entries.len(), private.files.len()), before);
        }
        assert_eq!(public.entries.len(), private.entries.len());
        assert_eq!(public.files.len(), private.files.len());
        for (left, right) in public.entries.iter().zip(&private.entries) {
            assert!(left.bytes().eq(right.bytes()));
            left.assert_owner_locked();
            right.assert_owner_locked();
        }
    }
}

#[test]
fn public_slice_rejections_and_existing_part_semantics_remain_unchanged() {
    let mut set = PathSet::default();
    assert!(set.insert(&[], true).is_err());
    assert!(set.insert(&["good", ".."], true).is_err());
    assert!(set.insert(&vec!["d"; MAX_DEPTH + 1], true).is_err());
    assert!(set.entries.is_empty() && set.files.is_empty());
    // DE: Kein neuer Teile-Slice-Vertrag; interne Rohpfade werden vollständig getrennt geprüft.
    // EN: No new part-slice contract; internal raw paths are fully split and validated.
    set.insert(&["one/two"], true).unwrap();
    assert!(
        set.insert_components(components("one/two").unwrap(), true)
            .is_err()
    );
    set.insert_components(components("valid/other").unwrap(), true)
        .unwrap();
    assert_eq!(set.entries.len(), 2);
}

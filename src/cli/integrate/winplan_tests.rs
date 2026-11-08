//! DE: Tests der Windows-Planung (laufen auf allen Systemen).
//! EN: Tests of the Windows planning (run on all systems).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::cli::integrate_text::integrate_texts;
use pqkeep::security::Lang;

const BIN: &str = r"C:\Program Files\PQKeep\pqkeep.exe";

#[test]
fn plans_three_single_selection_verbs() {
    let verbs = plan(integrate_texts(Lang::De), BIN);
    let paths: Vec<&str> = verbs.iter().map(|v| v.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            r"*\shell\PQKeep.Encrypt",
            r"Directory\shell\PQKeep.Encrypt",
            r"SystemFileAssociations\.pqkf\shell\PQKeep.Decrypt"
        ]
    );
    for v in &verbs {
        assert!(
            v.values
                .contains(&("MultiSelectModel".into(), "Single".into()))
        );
        assert!(v.values.contains(&("Icon".into(), format!("{BIN},0"))));
    }
}

#[test]
fn command_quotes_program_and_path_after_double_dash() {
    let verbs = plan(integrate_texts(Lang::En), BIN);
    assert_eq!(
        verbs[0].command,
        r#""C:\Program Files\PQKeep\pqkeep.exe" context encrypt -- "%1""#
    );
    assert_eq!(
        verbs[2].command,
        r#""C:\Program Files\PQKeep\pqkeep.exe" context decrypt -- "%1""#
    );
}

#[test]
fn labels_follow_the_language() {
    let de = plan(integrate_texts(Lang::De), BIN);
    let en = plan(integrate_texts(Lang::En), BIN);
    assert_ne!(de[0].values[0].1, en[0].values[0].1);
    assert_eq!(de[0].values[0].0, "MUIVerb");
}

#[test]
fn canonical_form_detects_every_change() {
    let v = &plan(integrate_texts(Lang::De), BIN)[0];
    let base = v.snapshot();
    let same = base.canonical();
    assert_eq!(v.snapshot().canonical(), same);
    let mut s = base.clone();
    s.command_values[0].2.push(' ');
    assert_ne!(s.canonical(), same);
    let mut s = base.clone();
    s.values.push(("Extended".into(), SZ.into(), String::new()));
    assert_ne!(s.canonical(), same);
    let mut s = base.clone();
    s.values[0].1 = "expand_sz".into();
    assert_ne!(s.canonical(), same);
    let mut s = base.clone();
    s.command_subkeys.push("x".into());
    assert_ne!(s.canonical(), same);
    assert_ne!(Snapshot::default().canonical(), same);
}

#[test]
fn canonical_form_ignores_order_and_name_case() {
    let v = &plan(integrate_texts(Lang::De), BIN)[0];
    let mut s = v.snapshot();
    s.values.reverse();
    s.values[0].0 = s.values[0].0.to_uppercase();
    assert_eq!(s.canonical(), v.snapshot().canonical());
}

#[test]
fn canonical_fields_cannot_be_shifted() {
    // DE: Längenpräfixe verhindern, dass Inhalt zwischen Feldern „wandert“.
    // EN: Length prefixes prevent content from "moving" between fields.
    let a = Snapshot {
        values: vec![("a;".into(), SZ.into(), "b".into())],
        ..Snapshot::default()
    };
    let b = Snapshot {
        values: vec![("a".into(), SZ.into(), ";b".into())],
        ..Snapshot::default()
    };
    assert_ne!(a.canonical(), b.canonical());
}

#[test]
fn windows_path_rules() {
    let temp = vec![r"C:\Users\anna\AppData\Local\Temp".to_owned()];
    assert!(safe_windows_path(BIN, &temp));
    assert!(safe_windows_path(r"D:\Tools\Größe ä\pqkeep.exe", &temp));
    for bad in [
        r"\\server\share\pqkeep.exe",
        r"\\?\C:\Tools\pqkeep.exe",
        r"C:\Tools\pq%PATH%keep.exe",
        "C:\\Tools\\pq\"keep.exe",
        "C:\\Tools\\pq\nkeep.exe",
        r"C:\Tools\pqkeep",
        r"Tools\pqkeep.exe",
        r"C:\Users\anna\AppData\Local\Temp\x\pqkeep.exe",
        r"c:\users\ANNA\appdata\local\temp\pqkeep.exe",
    ] {
        assert!(!safe_windows_path(bad, &temp), "{bad}");
    }
    // DE: Nur echte Unterordner zählen als „unter Temp“. EN: Only real subfolders count.
    assert!(safe_windows_path(
        r"C:\Users\anna\AppData\Local\Temporary\pqkeep.exe",
        &temp
    ));
    assert!(safe_windows_path(BIN, &[String::new()]));
}

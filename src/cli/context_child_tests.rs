#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{clean_temps, own_temp};

const HEX: &str = "0123456789abcdef";

#[test]
fn own_temp_matches_only_our_pattern() {
    assert!(own_temp(
        &format!(".bericht.pdf.pqkf.tmp-{HEX}"),
        "bericht.pdf.pqkf"
    ));
    assert!(own_temp(
        &format!(".bericht.pdf (3).pqkf.tmp-{HEX}"),
        "bericht.pdf.pqkf"
    ));
    assert!(own_temp(&format!(".Ordner (2).tmp-{HEX}"), "Ordner"));
    for other in [
        format!("bericht.pdf.pqkf.tmp-{HEX}"),
        format!(".bericht.pdf.pqkf.tmp-{}", &HEX[..15]),
        format!(".bericht.pdf.pqkf.tmp-{}", HEX.to_uppercase()),
        format!(".anders.pdf.pqkf.tmp-{HEX}"),
        format!(".bericht.pdf (100).pqkf.tmp-{HEX}"),
        ".bericht.pdf.pqkf".to_owned(),
    ] {
        assert!(!own_temp(&other, "bericht.pdf.pqkf"), "{other}");
    }
}

#[test]
fn clean_temps_removes_only_own_leftovers() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("a.txt.pqkf");
    let keep = [
        "a.txt.pqkf",
        "a.txt",
        ".a.txt.pqkf.tmp-fremd",
        ".b.txt.pqkf.tmp-0123456789abcdef",
    ];
    for name in keep {
        std::fs::write(dir.path().join(name), b"x").unwrap();
    }
    std::fs::write(dir.path().join(format!(".a.txt.pqkf.tmp-{HEX}")), b"x").unwrap();
    std::fs::write(dir.path().join(format!(".a.txt (2).pqkf.tmp-{HEX}")), b"x").unwrap();
    let temp_dir = dir.path().join(format!(".a.tmp-{HEX}"));
    std::fs::create_dir(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("inhalt"), b"x").unwrap();
    clean_temps(&[target, dir.path().join("a")]);
    let mut left: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort_unstable();
    let mut expected: Vec<String> = keep.iter().map(|s| (*s).to_owned()).collect();
    expected.sort_unstable();
    assert_eq!(left, expected);
}

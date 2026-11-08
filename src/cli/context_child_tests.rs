#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{clean_temps, own_temp, with_tag};

const TAG: &str = "00112233aabbccdd";
const RND: &str = "0123456789abcdef";

#[test]
fn own_temp_needs_our_tag_and_pattern() {
    let ours = |name: &str| own_temp(name, "bericht.pdf.pqkf", TAG);
    assert!(ours(&format!(".bericht.pdf.pqkf.tmp-{TAG}{RND}")));
    assert!(ours(&format!(".bericht.pdf (3).pqkf.tmp-{TAG}{RND}")));
    assert!(own_temp(
        &format!(".Ordner (2).tmp-{TAG}{RND}"),
        "Ordner",
        TAG
    ));
    for other in [
        format!(".bericht.pdf.pqkf.tmp-{RND}"),
        format!(".bericht.pdf.pqkf.tmp-ffffffffffffffff{RND}"),
        format!("bericht.pdf.pqkf.tmp-{TAG}{RND}"),
        format!(".bericht.pdf.pqkf.tmp-{TAG}{}", &RND[..15]),
        format!(".bericht.pdf.pqkf.tmp-{TAG}{}", RND.to_uppercase()),
        format!(".anders.pdf.pqkf.tmp-{TAG}{RND}"),
        format!(".bericht.pdf (100).pqkf.tmp-{TAG}{RND}"),
        ".bericht.pdf.pqkf".to_owned(),
    ] {
        assert!(!ours(&other), "{other}");
    }
    assert!(!own_temp(&format!(".x.tmp-{RND}"), "x", ""));
}

#[test]
fn clean_temps_removes_only_own_leftovers() {
    let dir = tempfile::tempdir().unwrap();
    let keep = [
        "a.txt.pqkf".to_owned(),
        "a.txt".to_owned(),
        ".a.txt.pqkf.tmp-fremd".to_owned(),
        format!(".a.txt.pqkf.tmp-ffffffffffffffff{RND}"),
        format!(".b.txt.pqkf.tmp-{TAG}{RND}"),
    ];
    for name in &keep {
        std::fs::write(dir.path().join(name), b"x").unwrap();
    }
    std::fs::write(dir.path().join(format!(".a.txt.pqkf.tmp-{TAG}{RND}")), b"x").unwrap();
    std::fs::write(
        dir.path().join(format!(".a.txt (2).pqkf.tmp-{TAG}{RND}")),
        b"x",
    )
    .unwrap();
    let temp_dir = dir.path().join(format!(".a.tmp-{TAG}{RND}"));
    std::fs::create_dir(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("inhalt"), b"x").unwrap();
    clean_temps(&[dir.path().join("a.txt.pqkf"), dir.path().join("a")], TAG);
    let mut left: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort_unstable();
    let mut expected = keep.to_vec();
    expected.sort_unstable();
    assert_eq!(left, expected);
}

#[test]
fn tag_goes_right_after_the_command() {
    assert_eq!(
        with_tag(&["encrypt", "--out", "x", "--", "a"], TAG),
        ["encrypt", "--temp-tag", TAG, "--out", "x", "--", "a"]
    );
}

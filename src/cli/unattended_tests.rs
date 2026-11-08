#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use pqkeep::security::Lang;

use super::read_checked;
use crate::cli::io::code;

fn write(dir: &Path, name: &str, data: &[u8], mode: u32) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, data).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = mode;
    path
}

fn message(path: &Path) -> String {
    let f = read_checked(path, Lang::En).err().unwrap();
    assert_eq!(f.code, code::USAGE);
    f.message
}

#[test]
fn one_line_file_is_read_and_line_end_removed() {
    let dir = tempfile::tempdir().unwrap();
    for (name, data) in [
        ("lf", &b"wort eins zwei\n"[..]),
        ("crlf", b"wort eins zwei\r\n"),
        ("none", b"wort eins zwei"),
    ] {
        let p = write(dir.path(), name, data, 0o600);
        assert_eq!(
            read_checked(&p, Lang::En).ok().unwrap().expose_str(),
            "wort eins zwei",
            "{name}"
        );
    }
}

#[test]
fn malformed_files_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let cases: [(&str, Vec<u8>); 4] = [
        ("two", b"a\nb\n".to_vec()),
        ("cr", b"a\rb".to_vec()),
        ("big", vec![b'a'; 4097]),
        ("utf8", vec![0xff, 0xfe, b'a']),
    ];
    for (name, data) in cases {
        let p = write(dir.path(), name, &data, 0o600);
        assert!(message(&p).contains("invalid"), "{name}");
    }
    assert!(
        message(dir.path()).contains("invalid"),
        "Ordner / directory"
    );
}

#[cfg(unix)]
#[test]
fn links_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let target = write(dir.path(), "echt", b"geheim\n", 0o600);
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(message(&link).contains("invalid"));
}

#[cfg(target_os = "linux")]
#[test]
fn open_permissions_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o640, 0o604, 0o644, 0o660] {
        let p = write(dir.path(), &format!("m{mode:o}"), b"geheim\n", mode);
        assert!(message(&p).contains("chmod 600"), "{mode:o}");
    }
    let p = write(dir.path(), "ok400", b"geheim\n", 0o400);
    assert!(read_checked(&p, Lang::En).is_ok(), "0400");
}

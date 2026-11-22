#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{clean_temps, own_temp, with_tag};

const TAG: &str = "00112233aabbccdd";
const RND: &str = "0123456789abcdef";

#[test]
fn own_temp_needs_our_tag_and_pattern() {
    let ours = |name: &str| own_temp(name, "bericht.pdf.pqkf", TAG);
    assert!(ours(&format!(".bericht.pdf.pqkf.tmp-{TAG}{RND}")));
    assert!(ours(&format!(".bericht (3).pdf.pqkf.tmp-{TAG}{RND}")));
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
        format!(".bericht (100).pdf.pqkf.tmp-{TAG}{RND}"),
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
        dir.path().join(format!(".a (2).txt.pqkf.tmp-{TAG}{RND}")),
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

// DE: Nur Testbinary: echte Kind-Reste für den vorhandenen Cleanup-Helfer.
// EN: Test binary only: real child remnants for the existing cleanup helper.
struct KilledFixture(std::process::Child);

impl Drop for KilledFixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn crashed_fixture(root: &std::path::Path) {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cli::context_child::context_child_tests::crash_cleanup_entry",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut guard = KilledFixture(child);
    let descriptor = serde_json::to_vec(root).unwrap();
    assert!(descriptor.len() < 1024);
    let mut input = guard.0.stdin.take().unwrap();
    input
        .write_all(&u32::try_from(descriptor.len()).unwrap().to_le_bytes())
        .unwrap();
    input.write_all(&descriptor).unwrap();
    let mut output = guard.0.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut ack = [0];
        let _ = tx.send(output.read_exact(&mut ack).map(|()| ack));
    });
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(60))
            .unwrap()
            .unwrap(),
        *b"R"
    );
    guard.0.kill().unwrap();
    assert!(!guard.0.wait().unwrap().success());
    reader.join().unwrap();
}

#[test]
#[ignore = "Private subprocess fixture; executed by the cleanup parent test"]
fn crash_cleanup_entry() {
    use std::io::{Read, Write};
    let report = pqkeep::hardening::harden_process();
    #[cfg(target_os = "linux")]
    assert!(report.complete());
    #[cfg(not(target_os = "linux"))]
    let _ = report;
    let mut input = std::io::stdin().lock();
    let mut size = [0; 4];
    input.read_exact(&mut size).unwrap();
    let size = usize::try_from(u32::from_le_bytes(size)).unwrap();
    assert!(size < 1024);
    let mut descriptor = vec![0; size];
    input.read_exact(&mut descriptor).unwrap();
    let root: std::path::PathBuf = serde_json::from_slice(&descriptor).unwrap();
    assert!(root.is_absolute() && root.symlink_metadata().unwrap().is_dir());
    pqkeep::envelope::write_atomic(
        &root.join("a.pqkf"),
        b"committed",
        pqkeep::envelope::Overwrite::No,
    )
    .unwrap();
    std::fs::write(root.join(format!(".a.pqkf.tmp-{TAG}{RND}")), b"partial").unwrap();
    let tree = root.join(format!(".tree.tmp-{TAG}{RND}"));
    std::fs::create_dir(&tree).unwrap();
    std::fs::write(tree.join("partial"), b"partial").unwrap();
    std::io::stderr().write_all(b"R").unwrap();
    std::io::stderr().flush().unwrap();
    let mut command = [0];
    input.read_exact(&mut command).unwrap();
}

#[test]
fn rec013_cleanup_after_actual_child_death_preserves_other_files() {
    let root = tempfile::tempdir().unwrap();
    let foreign = root
        .path()
        .join(format!(".a.pqkf.tmp-ffffffffffffffff{RND}"));
    std::fs::write(&foreign, b"foreign").unwrap();
    crashed_fixture(root.path());
    let own = root.path().join(format!(".a.pqkf.tmp-{TAG}{RND}"));
    let tree = root.path().join(format!(".tree.tmp-{TAG}{RND}"));
    assert_eq!(std::fs::read(&own).unwrap(), b"partial");
    assert!(tree.join("partial").is_file());
    clean_temps(&[root.path().join("a.pqkf"), root.path().join("tree")], TAG);
    assert!(!own.exists() && !tree.exists());
    assert_eq!(
        std::fs::read(root.path().join("a.pqkf")).unwrap(),
        b"committed"
    );
    assert_eq!(std::fs::read(&foreign).unwrap(), b"foreign");
}

#[cfg(windows)]
#[test]
fn fs009_cleanup_sharing_lock_leaves_temp_until_handle_release() {
    use std::os::windows::fs::OpenOptionsExt;
    let root = tempfile::tempdir().unwrap();
    crashed_fixture(root.path());
    let own = root.path().join(format!(".a.pqkf.tmp-{TAG}{RND}"));
    let locked = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&own)
        .unwrap();
    clean_temps(&[root.path().join("a.pqkf")], TAG);
    assert!(own.exists());
    drop(locked);
    clean_temps(&[root.path().join("a.pqkf")], TAG);
    assert!(!own.exists());
    assert_eq!(
        std::fs::read(root.path().join("a.pqkf")).unwrap(),
        b"committed"
    );
}

/// DE: `@@signer` nur mit genau 64 kleinen Hex-Zeichen (#287). EN: Only exactly 64 lowercase hex.
#[test]
fn signer_control_line_is_strict() {
    let ok = "0123456789abcdef".repeat(4);
    assert_eq!(super::signer_id(&ok), Some(ok.clone()));
    for bad in [
        ok[..63].to_owned(),
        format!("{ok}0"),
        ok.to_uppercase(),
        format!("{} x", &ok[..62]),
        String::new(),
    ] {
        assert_eq!(super::signer_id(&bad), None, "{bad}");
    }
}

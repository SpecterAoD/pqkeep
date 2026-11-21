//! DE: LIST-007–009: echte CLI, Schema, Ausgabe-Gating und bestehende Zugänge.
//! EN: LIST-007–009: real CLI, schema, output gating and existing access methods.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqkeep::crypto::factor::Factor;
use pqkeep::files::{self, PassphraseAccess, Protection};
use pqkeep::security::StrongPassphrase;
use serde_json::Value;
use zeroize::Zeroizing;

struct Fixture {
    root: tempfile::TempDir,
    pass: StrongPassphrase,
    payload: String,
    v2: bool,
}

impl Fixture {
    fn new(v2: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let pass = common::random_passphrase();
        let payload = String::from_utf8(common::random_secret()).unwrap();
        let tree = root.path().join("data");
        std::fs::create_dir_all(tree.join("leer")).unwrap();
        std::fs::write(tree.join("innen.txt"), &payload).unwrap();
        let factor = v2.then(|| {
            Factor::create(&root.path().join("factor")).unwrap();
            Factor::read(&root.path().join("factor")).unwrap()
        });
        let protection = factor.as_ref().map_or_else(
            || Protection::Passphrase {
                passphrase: &pass,
                params: common::min_params(),
            },
            |f| Protection::Slots {
                passphrase: Some(PassphraseAccess {
                    passphrase: &pass,
                    params: common::min_params(),
                    factor: Some(f),
                }),
                recipients: &[],
            },
        );
        files::encrypt(&tree, &root.path().join("input.pqkf"), &protection).unwrap();
        Self {
            root,
            pass,
            payload,
            v2,
        }
    }

    fn run(&self, json: bool, lang: &str) -> (i32, String, String) {
        let mut args = vec![
            "--lang",
            lang,
            "--verbose",
            "list",
            "input.pqkf",
            "--passphrase-stdin",
        ];
        if self.v2 {
            args.extend(["--factor-file", "factor"]);
        }
        if json {
            args.push("--json");
        }
        let stdin = Zeroizing::new(format!("{}\n", self.pass.as_ref().expose_str()));
        let result = common::pqkeep(&args, &stdin, self.root.path());
        self.no_secrets(&result.1, &result.2);
        result
    }

    fn no_secrets(&self, out: &str, err: &str) {
        // DE: Erst prüfen, bevor eine weitere Assertion Ausgaben zeigen könnte.
        // EN: Check before another assertion could display output.
        for s in [out, err] {
            assert!(!s.contains(self.pass.as_ref().expose_str()));
            assert!(!s.contains(&self.payload));
        }
    }
}

fn object(out: &str) -> Value {
    assert_eq!(out.lines().count(), 1);
    let v: Value = serde_json::from_str(out).unwrap();
    assert_eq!(v["schema"], "pqkeep-list/1");
    assert_eq!(v["command"], "list");
    v
}

#[test]
fn v1_v2_text_and_json_work_in_both_languages_with_sandbox_and_no_files() {
    for v2 in [false, true] {
        let f = Fixture::new(v2);
        let before = common::dir_names(f.root.path());
        for lang in ["de", "en"] {
            let (code, out, err) = f.run(false, lang);
            assert_eq!(code, 0);
            assert!(out.contains("innen.txt") && out.contains("leer"));
            if cfg!(target_os = "linux") {
                assert!(err.contains("landlock=") && err.contains("seccomp=full"));
            }
            let (code, out, _) = f.run(true, lang);
            assert_eq!(code, 0);
            let v = object(&out);
            assert_eq!(v["ok"], true);
            assert_eq!(v["authentication"], "container_integrity");
            assert_eq!(v["entries"].as_array().unwrap().len(), 2);
            assert_eq!(v["summary"]["files"], 1);
            assert_eq!(v["summary"]["directories"], 1);
            assert_eq!(v["summary"]["bytes"], f.payload.len());
        }
        assert_eq!(common::dir_names(f.root.path()), before);
    }
}

#[test]
fn late_authentication_failure_has_no_names_or_partial_list_in_text_or_json() {
    for v2 in [false, true] {
        let f = Fixture::new(v2);
        let input = f.root.path().join("input.pqkf");
        let original = std::fs::read(&input).unwrap();
        let mut bad = original.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let mut appended = original.clone();
        appended.push(0);
        for data in [bad, original[..last].to_vec(), appended] {
            std::fs::write(&input, data).unwrap();
            for json in [false, true] {
                let (code, out, err) = f.run(json, "en");
                assert_ne!(code, 0);
                assert!(!out.contains("innen.txt") && !out.contains("leer"));
                assert!(!err.contains("innen.txt"));
                if json {
                    let v = object(&out);
                    assert_eq!(v["ok"], false);
                    assert!(v.get("entries").is_none());
                } else {
                    assert_eq!(out, "");
                }
            }
        }
    }
}

#[test]
fn early_missing_header_and_credential_errors_use_the_listing_schema() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bad.pqkf"), b"bad").unwrap();
    for args in [
        vec!["--batch", "list", "missing.pqkf", "--json"],
        vec!["--batch", "list", "bad.pqkf", "--json"],
        vec![
            "--batch",
            "--passphrase-file",
            "missing-pass",
            "list",
            "bad.pqkf",
            "--json",
        ],
    ] {
        let (code, out, _) = common::pqkeep(&args, "", dir.path());
        assert_eq!(code, 1);
        let v = object(&out);
        assert_eq!(v["ok"], false);
        assert!(v.get("entries").is_none() && v.get("authentication").is_none());
        assert_eq!(v["error"]["code"], 1);
    }
}

#[test]
fn wrong_passphrase_and_required_input_do_not_list_metadata() {
    for v2 in [false, true] {
        let f = Fixture::new(v2);
        let mut args = vec!["list", "input.pqkf", "--passphrase-stdin", "--json"];
        if v2 {
            args.extend(["--factor-file", "factor"]);
        }
        let wrong = common::random_passphrase();
        let line = Zeroizing::new(format!("{}\n", wrong.as_ref().expose_str()));
        let (code, out, err) = common::pqkeep(&args, &line, f.root.path());
        assert!(
            !out.contains(wrong.as_ref().expose_str())
                && !err.contains(wrong.as_ref().expose_str())
        );
        f.no_secrets(&out, &err);
        assert_eq!(code, 3);
        let v = object(&out);
        assert!(v.get("entries").is_none());
        let (code, out, _) = common::pqkeep(
            &["--batch", "list", "input.pqkf", "--json"],
            "",
            f.root.path(),
        );
        assert_eq!(code, 2);
        assert!(object(&out).get("entries").is_none());
    }
}

#[test]
fn single_source_only_and_no_output_or_credential_argument() {
    let dir = tempfile::tempdir().unwrap();
    for extra in [
        vec!["second.pqkf"],
        vec!["--out", "target"],
        vec!["--passphrase", "value"],
    ] {
        let args = [vec!["list", "input.pqkf"], extra].concat();
        assert_eq!(common::pqkeep(&args, "", dir.path()).0, 2);
    }
}

#[test]
fn old_check_json_stays_metadata_free_and_keeps_its_schema() {
    let f = Fixture::new(false);
    let line = Zeroizing::new(format!("{}\n", f.pass.as_ref().expose_str()));
    let (code, out, err) = common::pqkeep(
        &["check", "input.pqkf", "--passphrase-stdin", "--json"],
        &line,
        f.root.path(),
    );
    f.no_secrets(&out, &err);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["schema"], "pqkeep-json/1");
    assert!(!out.contains("innen.txt") && v.get("entries").is_none());
}

#[test]
fn closed_stdout_is_an_io_failure_after_a_valid_listing() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let f = Fixture::new(false);
    for json in [false, true] {
        assert_eq!(f.run(json, "en").0, 0);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_pqkeep"));
        cmd.args(["--lang", "en", "list", "input.pqkf", "--passphrase-stdin"]);
        if json {
            cmd.arg("--json");
        }
        let mut child = cmd
            .current_dir(f.root.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        let line = Zeroizing::new(format!("{}\n", f.pass.as_ref().expose_str()));
        child
            .stdin
            .take()
            .unwrap()
            .write_all(line.as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        let err = String::from_utf8(result.stderr).unwrap();
        f.no_secrets("", &err);
        assert_eq!(result.status.code(), Some(1));
        assert!(!err.contains("panicked") && !err.contains("innen.txt"));
    }
}

#[cfg(windows)]
#[test]
fn native_windows_exclusive_source_lock_returns_only_an_error() {
    use std::os::windows::fs::OpenOptionsExt;
    let f = Fixture::new(false);
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(f.root.path().join("input.pqkf"))
        .unwrap();
    let (code, out, err) = f.run(true, "en");
    assert_eq!(code, 1);
    assert!(object(&out).get("entries").is_none());
    assert!(!err.contains("innen.txt"));
    drop(held);
    assert_eq!(f.run(true, "en").0, 0);
}

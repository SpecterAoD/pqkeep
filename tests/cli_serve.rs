//! DE: CLI `pqkeep serve`: Token anlegen, Bind-Prüfung, Hilfe, echter Start.
//! EN: CLI `pqkeep serve`: token creation, bind check, help, real start.
#![cfg(feature = "api")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};

#[test]
fn init_token_shows_token_once_and_stores_hash() {
    let dir = tempfile::tempdir().unwrap();
    let args = [
        "--lang",
        "en",
        "serve",
        "--init-token",
        "--token-file",
        "api.token",
    ];
    let (code, out, err) = common::pqkeep(&args, "", dir.path());
    assert_eq!(code, 0, "{err}");
    let token = out.trim();
    assert!(token.starts_with("pqk1_"));
    assert!(err.contains("shown only now"));
    let stored = std::fs::read_to_string(dir.path().join("api.token")).unwrap();
    assert!(!stored.contains(&token["pqk1_".len()..]));
    // DE: Zweites Anlegen ohne --force: Ziel existiert (Exit 5).
    // EN: Second creation without --force: target exists (exit 5).
    let (code, _, _) = common::pqkeep(&args, "", dir.path());
    assert_eq!(code, 5);
    let mut forced = args.to_vec();
    forced.push("--force");
    let (code, out2, _) = common::pqkeep(&forced, "", dir.path());
    assert_eq!(code, 0);
    assert_ne!(out2.trim(), token);
}

#[test]
fn remote_bind_needs_allow_remote() {
    let dir = tempfile::tempdir().unwrap();
    let init = ["serve", "--init-token", "--token-file", "t"];
    assert_eq!(common::pqkeep(&init, "", dir.path()).0, 0);
    let args = [
        "--lang",
        "de",
        "serve",
        "--token-file",
        "t",
        "--bind",
        "0.0.0.0:0",
    ];
    let (code, _, err) = common::pqkeep(&args, "", dir.path());
    assert_eq!(code, 2);
    assert!(err.contains("--allow-remote"), "{err}");
    let bad = ["serve", "--token-file", "t", "--bind", "localhost"];
    assert_eq!(common::pqkeep(&bad, "", dir.path()).0, 2);
    let missing = ["serve", "--token-file", "fehlt", "--bind", "127.0.0.1:0"];
    assert_eq!(common::pqkeep(&missing, "", dir.path()).0, 1);
    let force_alone = ["serve", "--token-file", "t", "--force"];
    assert_eq!(common::pqkeep(&force_alone, "", dir.path()).0, 2);
}

#[test]
fn serve_help_in_both_languages() {
    let dir = tempfile::tempdir().unwrap();
    let (_, de, _) = common::pqkeep(&["--lang", "de", "serve", "--help"], "", dir.path());
    assert!(de.contains("Reverse Proxy") && de.contains("--token-file"));
    let (_, en, _) = common::pqkeep(&["--lang", "en", "serve", "--help"], "", dir.path());
    assert!(en.contains("reverse proxy") && en.contains("Exit codes"));
}

#[test]
fn serve_answers_health_on_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let init = ["serve", "--init-token", "--token-file", "t"];
    assert_eq!(common::pqkeep(&init, "", dir.path()).0, 0);
    let mut child = Command::new(env!("CARGO_BIN_EXE_pqkeep"))
        .args([
            "--lang",
            "en",
            "serve",
            "--token-file",
            "t",
            "--bind",
            "127.0.0.1:0",
        ])
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    while !line.contains("http://") {
        line.clear();
        assert!(
            stderr.read_line(&mut line).unwrap() > 0,
            "kein Start / no start"
        );
    }
    let addr = line.trim().rsplit("http://").next().unwrap().to_owned();
    let mut s = TcpStream::connect(&addr).unwrap();
    s.write_all(b"GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    s.read_to_string(&mut response).unwrap();
    child.kill().unwrap();
    let _ = child.wait();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}

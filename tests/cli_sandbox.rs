//! DE: Sandbox über das echte Binary: `serve` erzeugt mit aktiver Sandbox Schlüssel
//! (Argon2-Threads), `--verbose` zeigt den Status, `--no-sandbox` warnt mit Risiken.
//! EN: Sandbox via the real binary: `serve` generates keys with the sandbox active
//! (Argon2 threads), `--verbose` shows the status, `--no-sandbox` warns with risks.
#![cfg(feature = "api")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};

/// DE: Startet `serve` auf einem freien Port; liefert Prozess, Adresse und Stderr-Zeilen.
/// EN: Starts `serve` on a free port; returns process, address and stderr lines.
// DE: Aufrufer beenden den Prozess (`kill` + `wait`). EN: Callers end the process (`kill` + `wait`).
#[allow(clippy::zombie_processes)]
fn start(dir: &Path, extra: &[&str]) -> (Child, String, Vec<String>) {
    let mut args = vec!["--lang", "en"];
    args.extend_from_slice(extra);
    args.extend(["serve", "--token-file", "t", "--bind", "127.0.0.1:0"]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_keyforge"))
        .args(&args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        assert!(stderr.read_line(&mut line).unwrap() > 0, "{lines:?}");
        lines.push(line.trim_end().to_owned());
        if let Some(addr) = line.trim().rsplit_once("http://") {
            return (child, addr.1.to_owned(), lines);
        }
    }
}

fn post(addr: &str, path: &str, token: &str, body: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    s.read_to_string(&mut response).unwrap();
    response
}

fn init_token(dir: &Path) -> String {
    let (code, out, _) = common::keyforge(&["serve", "--init-token", "--token-file", "t"], "", dir);
    assert_eq!(code, 0);
    out.trim().to_owned()
}

#[test]
fn sandboxed_serve_generates_keys() {
    let dir = tempfile::tempdir().unwrap();
    let token = init_token(dir.path());
    let (mut child, addr, lines) = start(dir.path(), &["--verbose"]);
    if cfg!(target_os = "linux") {
        assert!(
            lines
                .iter()
                .any(|l| l.contains("Sandbox: landlock=") && l.ends_with("seccomp=full")),
            "{lines:?}"
        );
    }
    let pass = common::random_passphrase();
    for alg in ["ml-kem-768", "ml-dsa-65", "aes-256"] {
        let body = serde_json::json!({
            "passphrase": pass.as_ref().expose_str(),
            "algorithm": alg,
            "metadata": { "name": "Sandbox Test" },
        })
        .to_string();
        let response = post(&addr, "/v1/generate", &token, &body);
        assert!(response.starts_with("HTTP/1.1 201"), "{alg}: {response}");
    }
    let response = post(&addr, "/v1/validate", &token, r#"{"passphrase":"kurz"}"#);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    child.kill().unwrap();
    let _ = child.wait();
}

#[test]
fn no_sandbox_warns_with_risks() {
    let dir = tempfile::tempdir().unwrap();
    let (code, out, err) = common::keyforge(
        &["--lang", "de", "--no-sandbox", "passphrase"],
        "",
        dir.path(),
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.lines().count(), 1);
    assert!(err.contains("WARNUNG: --no-sandbox"), "{err}");
    assert!(
        err.contains("Risiken") && err.contains("ALLE Ihre Dateien"),
        "{err}"
    );
    let (_, _, err) = common::keyforge(
        &["--lang", "en", "--no-sandbox", "passphrase"],
        "",
        dir.path(),
    );
    assert!(
        err.contains("Risks") && err.contains("ALL of your files"),
        "{err}"
    );
}

#[test]
fn no_sandbox_serve_reports_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let _ = init_token(dir.path());
    let (mut child, _addr, lines) = start(dir.path(), &["--verbose", "--no-sandbox"]);
    child.kill().unwrap();
    let _ = child.wait();
    let text = lines.join("\n");
    assert!(text.contains("WARNING: --no-sandbox"), "{text}");
    assert!(
        text.contains("Sandbox: landlock=disabled seccomp=disabled"),
        "{text}"
    );
}

#[test]
fn help_lists_no_sandbox_with_warning() {
    let dir = tempfile::tempdir().unwrap();
    let (_, out, _) = common::keyforge(&["--lang", "de", "--help"], "", dir.path());
    assert!(
        out.contains("--no-sandbox") && out.contains("NUR zur Fehlersuche"),
        "{out}"
    );
}

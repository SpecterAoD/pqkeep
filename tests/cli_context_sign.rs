//! DE: Absender-Signatur im Kontextmenü (#287) mit nachgebautem zenity: Passphrase-Schutz plus
//! Signatur (zwei Passwortfenster, eine Pipe) und Empfänger plus Signatur (ein Passwortfenster);
//! die Datei ist v3, vom richtigen Absender, und keine Passphrase steht in Fenster-Argumenten.
//! EN: Sender signature in the context menu (#287) with a fake zenity: passphrase protection plus
//! signature (two password windows, one pipe) and recipients plus signature (one password window);
//! the file is v3, from the right sender, and no passphrase appears in window arguments.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::Path;

use common::fake_dialog::Env;
use pqkeep::crypto::{DsaAlgorithm, KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{self, Overwrite};

/// DE: Schlüsselpaar `name.key.json`/`name.pub.json`; liefert die Passphrase.
/// EN: Key pair `name.key.json`/`name.pub.json`; returns the passphrase.
fn key(dir: &Path, name: &str, algorithm: KeyAlgorithm) -> String {
    let (file, pass) = common::key_file(algorithm);
    envelope::save(&file, &dir.join(format!("{name}.key.json")), Overwrite::No).unwrap();
    let public = file.public_part().unwrap();
    envelope::save_public(
        &public,
        &dir.join(format!("{name}.pub.json")),
        Overwrite::No,
    )
    .unwrap();
    pass.as_ref().expose_str().to_owned()
}

fn joined(e: &Env) -> String {
    e.calls()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n")
}

/// DE: Prüft Format 3 und Absender Anna (mit `--signer`). EN: Checks format 3 and sender Anna.
fn signed_by_anna(dir: &Path, file: &str, unlock: &[&str], stdin: &str) {
    let bytes = fs::read(dir.join(file)).unwrap();
    assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), 3);
    let mut args = vec!["--lang", "en", "check", file, "--signer", "anna.pub.json"];
    args.extend_from_slice(unlock);
    args.push("--passphrase-stdin");
    let (code, out, err) = common::pqkeep(&args, stdin, dir);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Signed by (verified)"), "{out}");
}

#[test]
fn passphrase_and_signature_use_two_windows_and_one_pipe() {
    let e = Env::new("zenity");
    let anna = key(e.work(), "anna", KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87));
    let file = e.work().join("brief.txt");
    fs::write(&file, b"Hallo").unwrap();
    let p = common::random_passphrase().as_ref().expose_str().to_owned();
    let key_path = format!("{}\n", e.work().join("anna.key.json").display());
    // DE: Modus, „Privatsphäre hoch“ nein, signieren ja, Schlüssel, neue Passphrase (zweimal), Signatur-Passphrase, Fertig.
    // EN: Mode, sign yes, key, new passphrase (twice), signing passphrase, done.
    e.answer(&[
        (0, "0\n"),
        (1, ""),
        (0, ""),
        (0, &key_path),
        (0, &format!("{p}\n{p}\n")),
        (0, &format!("{anna}\n")),
        (0, ""),
    ]);
    assert_eq!(e.context("encrypt", &file), 0, "{:?}", e.calls());
    let calls = e.calls();
    assert!(calls[5].contains(&"--hide-text".to_owned()), "{calls:?}");
    let all = joined(&e);
    assert!(
        !all.contains(&p) && !all.contains(&anna),
        "Passphrase in Argumenten"
    );
    signed_by_anna(e.work(), "brief.txt.pqkf", &[], &format!("{p}\n"));
}

#[test]
fn recipients_and_signature_need_only_the_signing_passphrase() {
    let e = Env::new("zenity");
    let anna = key(e.work(), "anna", KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87));
    let ben = key(e.work(), "ben", KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    let file = e.work().join("plan.txt");
    fs::write(&file, b"Plan").unwrap();
    let pick = |name: &str| format!("{}\n", e.work().join(name).display());
    // DE: Modus Empfänger, Ben, Fingerabdruck ja, kein weiterer, signieren ja, Schlüssel,
    //     Signatur-Passphrase, Fertig. EN: Recipient mode, Ben, fingerprint yes, no more, sign
    //     yes, key, signing passphrase, done.
    e.answer(&[
        (0, "1\n"),
        (1, ""),
        (0, &pick("ben.pub.json")),
        (0, ""),
        (1, ""),
        (0, ""),
        (0, &pick("anna.key.json")),
        (0, &format!("{anna}\n")),
        (0, ""),
    ]);
    assert_eq!(e.context("encrypt", &file), 0, "{:?}", e.calls());
    assert!(!joined(&e).contains(&anna), "Passphrase in Argumenten");
    signed_by_anna(
        e.work(),
        "plan.txt.pqkf",
        &["--key", "ben.key.json"],
        &format!("{ben}\n"),
    );
}

/// DE: Codex-Befund (#290): Ein Dateiname mit Zeilenumbruch und „Signed by (verified): …“ darf bei
/// einer unsignierten Datei keinen Absender vortäuschen. EN: Codex finding (#290): a file name with
/// a newline and "Signed by (verified): …" must not fake a sender for an unsigned file.
#[test]
fn file_names_cannot_fake_a_verified_sender() {
    let e = Env::new("zenity");
    let p = common::random_passphrase().as_ref().expose_str().to_owned();
    fs::write(e.work().join("a.txt"), b"x").unwrap();
    let enc = ["encrypt", "a.txt", "--passphrase-stdin"];
    let (code, _, err) = common::pqkeep(&enc, &format!("{p}\n"), e.work());
    assert_eq!(code, 0, "{err}");
    let fake = format!("z\nSigned by (verified): {}.txt.pqkf", "a".repeat(64));
    let forged = e.work().join(&fake);
    fs::rename(e.work().join("a.txt.pqkf"), &forged).unwrap();
    e.answer(&[(0, &format!("{p}\n")), (0, "")]);
    assert_eq!(e.context("decrypt", &forged), 0, "{:?}", e.calls());
    let calls = e.calls();
    let done = calls.last().unwrap().join("\n");
    assert!(done.contains("--info"), "{done}");
    // DE: Der Name steht maskiert in einer Zeile; keine Zeile beginnt mit der Absender-Beschriftung.
    // EN: The name stays escaped on one line; no line starts with the sender label.
    assert!(done.contains("z\\nSigned by"), "{done}");
    assert!(
        !done.lines().any(|l| l.starts_with("Signed by (verified)")),
        "{done}"
    );
}

/// DE: Codex-Befund (#290): Mehr Eingabe als ein Pipe-Puffer fasst blockiert nicht – der Kindprozess
/// liest von Anfang an mit und weist sie ab; keine Datei. EN: Codex finding (#290): more input than a
/// pipe buffer holds does not block – the child reads from the start and rejects it; no file.
#[test]
fn oversized_password_input_does_not_block() {
    let e = Env::new("zenity");
    key(e.work(), "anna", KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87));
    let file = e.work().join("gross.txt");
    fs::write(&file, b"x").unwrap();
    let key_path = format!("{}\n", e.work().join("anna.key.json").display());
    let huge = format!("{}\n", "x".repeat(200 * 1024));
    e.answer(&[
        (0, "0\n"),
        (1, ""),
        (0, ""),
        (0, &key_path),
        (0, &huge),
        (0, ""),
        (1, ""),
    ]);
    let started = std::time::Instant::now();
    assert_ne!(e.context("encrypt", &file), 0, "{:?}", e.calls());
    assert!(started.elapsed() < std::time::Duration::from_secs(60));
    assert!(!e.work().join("gross.txt.pqkf").exists());
}

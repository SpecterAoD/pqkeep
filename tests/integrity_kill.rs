//! DE: Integrität (#335, Lücke G6, QA1-REC-003): `pqkeep decrypt` wird mitten im Schreiben per
//! SIGKILL beendet – das Ziel erscheint nie. Bekannte Grenze (L1, Abhilfe in #338): Ein
//! Temporärrest mit verstecktem Namen und Rechten 0600 kann bleiben; er wird beim nächsten Lauf
//! nicht übernommen, das erneute Entschlüsseln gelingt und veröffentlicht nur geprüfte Daten.
//! EN: Integrity (#335, gap G6, QA1-REC-003): `pqkeep decrypt` is killed with SIGKILL while
//! writing – the target never appears. Known limit (L1, remedy in #338): a temporary leftover with
//! a hidden name and mode 0600 may remain; the next run does not adopt it, decrypting again
//! succeeds and publishes only verified data.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pqkeep::crypto::{KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{self, Overwrite};
use pqkeep::files::{self, EncryptOptions, Protection};

const SIZE: u64 = 256 * 1024 * 1024;

fn temps(dir: &Path) -> Vec<String> {
    common::dir_names(dir)
        .into_iter()
        .filter(|n| n.contains(".tmp-"))
        .collect()
}

const ARGS: [&str; 7] = [
    "decrypt",
    "gross.pqkf",
    "--key",
    "k.key.json",
    "-o",
    "gross.bin",
    "--passphrase-stdin",
];

/// DE: Schlüssel und großer Strom in `d`; liefert die Passphrase-Zeile für stdin.
/// EN: Key and large stream in `d`; returns the passphrase line for stdin.
fn fixture(d: &Path) -> String {
    let (file, pass) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    envelope::save(&file, &d.join("k.key.json"), Overwrite::No).unwrap();
    let public = file.public_part().unwrap();
    let p = Protection::Recipient(&public);
    let mut source = std::io::repeat(0x42).take(SIZE);
    let enc = d.join("gross.pqkf");
    files::encrypt_stream_to(&mut source, &enc, &p, None, EncryptOptions::default()).unwrap();
    format!("{}\n", pass.as_ref().expose_str())
}

/// DE: Startet `decrypt`, wartet, bis die Temporärdatei wächst, und beendet per SIGKILL; liefert
/// den Namen der Temporärdatei. EN: Starts `decrypt`, waits until the temporary file grows and
/// kills with SIGKILL; returns the temporary file's name.
fn start_and_kill(d: &Path, line: &str) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pqkeep"))
        .args(ARGS)
        .current_dir(d)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(line.as_bytes()).unwrap();
    drop(stdin);
    let start = Instant::now();
    let seen = loop {
        let grown = temps(d)
            .into_iter()
            .find(|t| std::fs::metadata(d.join(t)).is_ok_and(|m| m.len() > 0));
        if let Some(t) = grown {
            break t;
        }
        let running = child.try_wait().unwrap().is_none();
        assert!(running, "zu schnell fertig / finished too fast");
        let waited = start.elapsed() < Duration::from_secs(120);
        assert!(waited, "keine Temporärdatei / no temp");
        std::thread::sleep(Duration::from_millis(2));
    };
    child.kill().unwrap();
    child.wait().unwrap();
    seen
}

#[test]
fn killed_decrypt_never_publishes_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let line = fixture(d);
    let seen = start_and_kill(d, &line);
    assert!(
        !d.join("gross.bin").exists(),
        "Ziel nach Kill / target after kill"
    );
    // DE: Grenze L1: Rest kann bleiben – nur für den Eigentümer lesbar.
    // EN: Limit L1: a leftover may remain – readable by the owner only.
    if let Ok(meta) = std::fs::metadata(d.join(&seen)) {
        assert_eq!(meta.permissions().mode() & 0o077, 0, "Rechte / mode");
    }
    let (code, _, err) = common::pqkeep(&ARGS, &line, d);
    assert_eq!(code, 0, "{err}");
    assert_eq!(std::fs::metadata(d.join("gross.bin")).unwrap().len(), SIZE);
    // DE: Der alte Rest wurde nicht übernommen. EN: The old leftover was not adopted.
    assert!(temps(d).iter().all(|t| *t == seen), "{:?}", temps(d));
}

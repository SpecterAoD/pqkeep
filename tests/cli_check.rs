//! DE: `pqkeep check` (#86): Exit-Codes für Monitoring (0 / 3 / 1 / 2), eine Zeile je Datei und
//! eine Zusammenfassung, jede Datei wird geprüft, nichts wird geschrieben, Sandbox ohne
//! Schreibrecht, Hilfe DE/EN.
//! EN: `pqkeep check` (#86): exit codes for monitoring (0 / 3 / 1 / 2), one line per file and a
//! summary, every file is checked, nothing is written, sandbox without write access, help DE/EN.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use pqkeep::crypto::{KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{self, Overwrite};
use pqkeep::files::{self, Protection};

fn run(dir: &Path, args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut full = vec!["--lang", "de"];
    full.extend_from_slice(args);
    common::pqkeep(&full, stdin, dir)
}

/// DE: Zwei mit Passphrase verschlüsselte Dateien (Minimalparameter); liefert die Passphrase.
/// EN: Two passphrase-encrypted files (minimal parameters); returns the passphrase.
fn two_files(d: &Path) -> String {
    let pass = common::random_passphrase();
    let protection = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    for name in ["a", "b"] {
        let src = d.join(format!("{name}.txt"));
        std::fs::write(&src, name).unwrap();
        files::encrypt(&src, &d.join(format!("{name}.pqkf")), &protection).unwrap();
        std::fs::remove_file(&src).unwrap();
    }
    format!("{}\n", pass.as_ref().expose_str())
}

#[test]
fn all_fine_gives_exit_0_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let p = two_files(d);
    let before = common::dir_names(d);
    let (code, out, err) = run(d, &["check", "a.pqkf", "b.pqkf", "--passphrase-stdin"], &p);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.matches("OK: ").count(), 2, "{out}");
    assert!(
        out.contains("Geprüft: 2, in Ordnung: 2, fehlerhaft: 0"),
        "{out}"
    );
    assert_eq!(common::dir_names(d), before);
}

#[test]
fn every_file_is_checked_and_the_first_error_decides() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let p = two_files(d);
    // DE: a manipuliert (letztes Byte), b in Ordnung. EN: a tampered (last byte), b fine.
    let mut bytes = std::fs::read(d.join("a.pqkf")).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(d.join("a.pqkf"), &bytes).unwrap();
    std::fs::write(d.join("kaputt.pqkf"), b"kein pqkeep").unwrap();
    let args = [
        "check",
        "a.pqkf",
        "b.pqkf",
        "kaputt.pqkf",
        "--passphrase-stdin",
    ];
    let (code, out, err) = run(d, &args, &p);
    assert_eq!(code, 3, "{err}");
    assert!(
        err.contains("FEHLER: a.pqkf") && err.contains("FEHLER: kaputt.pqkf"),
        "{err}"
    );
    assert!(out.contains("OK: b.pqkf"), "{out}");
    assert!(
        out.contains("Geprüft: 3, in Ordnung: 1, fehlerhaft: 2"),
        "{out}"
    );
    // DE: Nur die kaputte Datei: sonstiger Fehler (1). EN: Only the broken file: other error (1).
    assert_eq!(run(d, &["check", "kaputt.pqkf"], "").0, 1);
    let (code, _, err) = run(d, &["check", "fehlt.pqkf"], "");
    assert_eq!(code, 1);
    assert!(err.contains("nicht gefunden"), "{err}");
    // DE: Falsche Passphrase: 3. EN: Wrong passphrase: 3.
    let wrong = format!("{}\n", common::random_passphrase().as_ref().expose_str());
    assert_eq!(
        run(d, &["check", "b.pqkf", "--passphrase-stdin"], &wrong).0,
        3
    );
}

#[test]
fn key_files_factor_and_mixed_selections() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let p = two_files(d);
    let (file, key_pass) = common::key_file(KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    envelope::save(&file, &d.join("k.key.json"), Overwrite::No).unwrap();
    std::fs::write(d.join("c.txt"), b"c").unwrap();
    let public = file.public_part().unwrap();
    files::encrypt(
        &d.join("c.txt"),
        &d.join("c.pqkf"),
        &Protection::Recipient(&public),
    )
    .unwrap();
    let kp = format!("{}\n", key_pass.as_ref().expose_str());
    let with_key = ["check", "c.pqkf", "-k", "k.key.json", "--passphrase-stdin"];
    let (code, out, err) = run(d, &with_key, &kp);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("OK: c.pqkf"), "{out}");
    // DE: Passphrase- und Empfängerdateien gemischt: Bedienfehler. EN: Mixed: usage error.
    let (code, _, err) = run(d, &["check", "a.pqkf", "c.pqkf", "--passphrase-stdin"], &p);
    assert_eq!(code, 2, "{err}");

    // DE: Faktordatei fehlt → Exit 2 vor der Passphrase. EN: Missing factor file → exit 2.
    assert_eq!(run(d, &["factor", "--out", "f.factor"], "").0, 0);
    let enc = [
        "encrypt",
        "c.txt",
        "-o",
        "f.pqkf",
        "--factor-file",
        "f.factor",
    ];
    let (code, _, err) = run(d, &[&enc[..], &["--passphrase-stdin"]].concat(), &p);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = run(d, &["check", "f.pqkf", "--passphrase-stdin"], &p);
    assert_eq!(code, 2);
    assert!(err.contains("--factor-file"), "{err}");
    let ok = [
        "check",
        "f.pqkf",
        "--passphrase-stdin",
        "--factor-file",
        "f.factor",
    ];
    assert_eq!(run(d, &ok, &p).0, 0);
}

#[test]
fn runs_sandboxed_and_help_in_both_languages() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let p = two_files(d);
    let (code, _, err) = run(
        d,
        &["--verbose", "check", "a.pqkf", "--passphrase-stdin"],
        &p,
    );
    assert_eq!(code, 0, "{err}");
    #[cfg(target_os = "linux")]
    assert!(
        err.contains("Sandbox: landlock=") && err.contains("seccomp=full"),
        "{err}"
    );
    for (lang, words) in [
        (
            "de",
            ["ohne etwas zu schreiben", "pqkeep inspect", "Exit-Code"],
        ),
        (
            "en",
            ["without writing anything", "pqkeep inspect", "Exit code"],
        ),
    ] {
        let (code, out, _) = common::pqkeep(&["--lang", lang, "check", "--help"], "", d);
        assert_eq!(code, 0);
        for word in words {
            assert!(out.contains(word), "{word}: {out}");
        }
        common::assert_no_secret_like_words(&out, "check --help");
        let (_, top, _) = common::pqkeep(&["--lang", lang, "--help"], "", d);
        assert!(top.contains("check"), "{top}");
    }
}

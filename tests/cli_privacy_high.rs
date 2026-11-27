//! DE: Stufe „Privatsphäre hoch“ vollständig (#316 Schritt 6): zufälliger Name, Füllung,
//! verborgener Absender beim Signieren und – bei ML-KEM-1024-Empfängern – anonyme Empfänger
//! (experimentell, Warnung); andere Schlüssel: Hinweis, IDs sichtbar; Abwahl mit
//! `--no-anonymous-recipients`, im Kontextmenü per Rückfrage (Ersatz-zenity).
//! EN: Level "privacy high" complete (#316 step 6): random name, padding, hidden sender when
//! signing and – for ML-KEM-1024 recipients – anonymous recipients (experimental, warning); other
//! keys: notice, IDs visible; deselect with `--no-anonymous-recipients`, in the context menu via a
//! question (fake zenity).

// DE: Tests dürfen unwrap/expect nutzen. EN: Tests may use unwrap/expect.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use pqkeep::crypto::{DsaAlgorithm, KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{self, Overwrite};
use pqkeep::files::format_v4::{OPT_ANON, OPT_HIDDEN_SENDER, OPT_PAD};
use pqkeep::files::is_random_name;

/// DE: Schlüsselpaar `name.key.json`/`name.pub.json`; liefert die Passphrase.
/// EN: Key pair `name.key.json`/`name.pub.json`; returns the passphrase.
fn key(dir: &Path, name: &str, algorithm: KeyAlgorithm) -> String {
    let (file, pass) = common::key_file(algorithm);
    envelope::save(&file, &dir.join(format!("{name}.key.json")), Overwrite::No).unwrap();
    let public = file.public_part().unwrap();
    let target = dir.join(format!("{name}.pub.json"));
    envelope::save_public(&public, &target, Overwrite::No).unwrap();
    pass.as_ref().expose_str().to_owned()
}

fn run(dir: &Path, args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut full = vec!["--lang", "en"];
    full.extend_from_slice(args);
    common::pqkeep(&full, stdin, dir)
}

/// DE: Die eine Datei mit zufälligem Namen (danach entfernt). EN: The one random-name file.
fn take_random(dir: &Path) -> (PathBuf, u16) {
    let found: Vec<PathBuf> = common::dir_names(dir)
        .into_iter()
        .filter(|n| is_random_name(n))
        .map(|n| dir.join(n))
        .collect();
    assert_eq!(found.len(), 1, "{:?}", common::dir_names(dir));
    let options = pqkeep::files::inspect_v2(&found[0])
        .unwrap()
        .v4
        .unwrap()
        .options;
    (found[0].clone(), options)
}

#[test]
fn level_high_hides_name_size_sender_and_recipients() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let anna = key(d, "anna", KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87));
    let ben = key(d, "ben", KeyAlgorithm::Kem(KemAlgorithm::MlKem1024));
    fs::write(d.join("brief.txt"), b"Hallo Ben").unwrap();
    let args = [
        "encrypt",
        "brief.txt",
        "--to",
        "ben.pub.json",
        "--sign-with",
        "anna.key.json",
        "--privacy",
        "high",
        "--passphrase-stdin",
    ];
    let (code, _, err) = run(d, &args, &format!("{anna}\n"));
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("EXPERIMENTAL"), "{err}");
    assert!(err.contains("--no-anonymous-recipients"), "{err}");
    let (enc, options) = take_random(d);
    let all = OPT_PAD | OPT_ANON | OPT_HIDDEN_SENDER;
    assert_eq!(options & all, all, "{options:#x}");
    let name = enc.file_name().unwrap().to_str().unwrap().to_owned();
    // DE: Entschlüsseln stellt den Originalnamen her. EN: Decrypting restores the original name.
    fs::remove_file(d.join("brief.txt")).unwrap();
    let dec = [
        "decrypt",
        &name,
        "--key",
        "ben.key.json",
        "--signer",
        "anna.pub.json",
        "--passphrase-stdin",
    ];
    let (code, out, err) = run(d, &dec, &format!("{ben}\n"));
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Signed by (verified)"), "{out}");
    assert_eq!(fs::read(d.join("brief.txt")).unwrap(), b"Hallo Ben");
}

#[test]
fn other_kem_is_skipped_and_deselect_switch_works() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    key(d, "ben", KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
    key(d, "cleo", KeyAlgorithm::Kem(KemAlgorithm::MlKem1024));
    fs::write(d.join("brief.txt"), b"x").unwrap();
    let base = ["encrypt", "brief.txt", "--privacy", "high", "--to"];
    let (code, _, err) = run(d, &[&base[..], &["ben.pub.json"]].concat(), "");
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("anonymous recipients skipped"), "{err}");
    let (enc, options) = take_random(d);
    assert_eq!(options & (OPT_PAD | OPT_ANON), OPT_PAD);
    fs::remove_file(enc).unwrap();
    let off = [&base[..], &["cleo.pub.json", "--no-anonymous-recipients"]].concat();
    let (code, _, err) = run(d, &off, "");
    assert_eq!(code, 0, "{err}");
    assert!(!err.contains("EXPERIMENTAL"), "{err}");
    assert_eq!(take_random(d).1 & OPT_ANON, 0);
    // DE: Beides zugleich ist ein Bedienfehler. EN: Both at once is a usage error.
    let both = [
        "encrypt",
        "brief.txt",
        "--to",
        "cleo.pub.json",
        "--anonymous-recipients",
        "--no-anonymous-recipients",
    ];
    assert_eq!(run(d, &both, "").0, 2);
}

#[cfg(target_os = "linux")]
#[test]
fn context_menu_asks_and_can_deselect_anonymous_recipients() {
    let e = common::fake_dialog::Env::new("zenity");
    key(e.work(), "cleo", KeyAlgorithm::Kem(KemAlgorithm::MlKem1024));
    let file = e.work().join("plan.txt");
    fs::write(&file, b"Plan").unwrap();
    let pick = format!("{}\n", e.work().join("cleo.pub.json").display());
    for (keep, want) in [(0, OPT_ANON), (1, 0)] {
        // DE: Modus Empfänger, „Privatsphäre hoch“ ja, Cleo, Fingerabdruck ja, kein weiterer,
        //     anonyme Empfänger behalten/abwählen, nicht signieren, Fertig.
        // EN: Recipient mode, "privacy high" yes, Cleo, fingerprint yes, no more, keep/deselect
        //     anonymous recipients, do not sign, done.
        e.answer(&[
            (0, "1\n"),
            (0, ""),
            (0, &pick),
            (0, ""),
            (1, ""),
            (keep, ""),
            (1, ""),
            (0, ""),
        ]);
        assert_eq!(e.context("encrypt", &file), 0, "{:?}", e.calls());
        let asked = e
            .calls()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("\n");
        assert!(asked.contains("EXPERIMENTAL"), "{asked}");
        let (enc, options) = take_random(e.work());
        assert_eq!(
            options & (OPT_PAD | OPT_ANON),
            OPT_PAD | want,
            "keep={keep}"
        );
        fs::remove_file(enc).unwrap();
    }
}

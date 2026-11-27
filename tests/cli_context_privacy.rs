//! DE: Kontextmenü mit Stufe „Privatsphäre hoch“ (#315, Linux, Ersatz-zenity): zufälliger Name
//! einzeln und mehrfach, Entschlüsseln stellt den Originalnamen her, Abbrechen hinterlässt keine
//! Reste.
//! EN: Context menu with level "privacy high" (#315, Linux, fake zenity): random name for one and
//! several files, decrypting restores the original name, cancelling leaves no leftovers.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::fake_dialog::Env;
use pqkeep::files::is_random_name;

fn pass() -> String {
    common::random_passphrase().as_ref().expose_str().to_owned()
}

/// DE: Stufe hoch bedeutet auch Füllung (Codex-Fund #339). EN: Level high also means padding.
fn assert_padded(enc: &Path) {
    let v4 = pqkeep::files::inspect_v2(enc).unwrap().v4.unwrap();
    assert_ne!(
        v4.options & pqkeep::files::format_v4::OPT_PAD,
        0,
        "{}",
        enc.display()
    );
}

fn random_files(dir: &Path) -> Vec<PathBuf> {
    common::dir_names(dir)
        .into_iter()
        .filter(|n| is_random_name(n))
        .map(|n| dir.join(n))
        .collect()
}

#[test]
fn single_file_gets_random_name_and_restores_original() {
    let e = Env::new("zenity");
    let file = e.work().join("steuer-2026.pdf");
    fs::write(&file, b"geheim").unwrap();
    let p = pass();
    // DE: Modus, „Privatsphäre hoch“ ja, nicht signieren, Passphrase, Fertig.
    // EN: Mode, "privacy high" yes, do not sign, passphrase, done.
    e.answer(&[
        (0, "0\n"),
        (0, ""),
        (1, ""),
        (0, &format!("{p}\n{p}\n")),
        (0, ""),
    ]);
    assert_eq!(e.context("encrypt", &file), 0, "{:?}", e.calls());
    let enc = random_files(e.work());
    assert_eq!(enc.len(), 1, "{:?}", common::dir_names(e.work()));
    assert_padded(&enc[0]);
    let done = e.calls().last().unwrap().join("\n");
    assert!(
        done.contains(enc[0].file_name().unwrap().to_str().unwrap()),
        "{done}"
    );
    fs::remove_file(&file).unwrap();
    e.answer(&[(0, &format!("{p}\n")), (0, "")]);
    assert_eq!(e.context("decrypt", &enc[0]), 0, "{:?}", e.calls());
    assert_eq!(fs::read(&file).unwrap(), b"geheim");
}

#[test]
fn several_files_each_and_cancel_leaves_nothing() {
    let e = Env::new("zenity");
    let src: Vec<PathBuf> = (0..3)
        .map(|i| {
            let f = e.work().join(format!("f{i}.txt"));
            fs::write(&f, b"x").unwrap();
            f
        })
        .collect();
    let refs: Vec<&Path> = src.iter().map(PathBuf::as_path).collect();
    let p = pass();
    let flow = [
        (0, "0\n"),
        (0, "0\n"),
        (0, ""),
        (1, ""),
        (0, format!("{p}\n{p}\n").leak() as &str),
        (0, ""),
    ];
    e.answer(&flow);
    assert_eq!(e.context_many("encrypt", &refs), 0, "{:?}", e.calls());
    assert_eq!(random_files(e.work()).len(), 3);
    for f in random_files(e.work()) {
        assert_padded(&f);
    }
    // DE: Abbrechen mitten drin: keine Temporärreste mit zufälligem Namen.
    // EN: Cancel midway: no temporary leftovers with random names.
    for f in random_files(e.work()) {
        fs::remove_file(f).unwrap();
    }
    e.cancel_after("0.5");
    e.answer(&flow);
    assert_eq!(e.context_many("encrypt", &refs), 2, "{:?}", e.calls());
    let left = common::dir_names(e.work());
    assert!(left.iter().all(|n| !n.contains(".tmp-")), "{left:?}");
}

//! DE: Integrität (#335, Lücke G2, QA1-FMT-003): Jedes Header-Byte einer kleinen Datei in jedem
//! Format (v1–v4: mehrere Empfänger, sichtbare Signatur, Füllung, verborgener Absender, anonyme
//! Empfänger, Strom) wird gekippt; `decrypt` scheitert für jedes Byte, zusätzlich je Byte reihum
//! `check`, `list` oder `decrypt --original-name` – nie eine Ausgabe, nie ein Temporärrest. Die
//! Pfade teilen sich das Öffnen des Headers; reihum hält die Laufzeit klein.
//! EN: Integrity (#335, gap G2, QA1-FMT-003): every header byte of a small file in every format
//! (v1–v4: several recipients, visible signature, padding, hidden sender, anonymous recipients,
//! stream) is flipped; `decrypt` fails for every byte, plus per byte in turn `check`, `list` or
//! `decrypt --original-name` – never any output, never a temporary leftover. The paths share
//! header opening; rotating keeps the run time small.

// DE: Tests dürfen unwrap/expect nutzen. EN: Tests may use unwrap/expect.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::integrity::{self, ALL, Kind, Path4, must_fail};

const OTHERS: [Path4; 3] = [Path4::Check, Path4::List, Path4::Original];

fn every_header_byte(kind: Kind) {
    let dir = tempfile::tempdir().unwrap();
    let keys = integrity::keys();
    let unlock = keys.unlock(kind);
    let good = integrity::seal(dir.path(), "gut", kind, &keys, b"Integritaet / integrity");
    let len = integrity::header_len(&good);
    assert!(len > 32, "{kind:?}: {len}");
    for i in 0..len {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        let what = format!("{kind:?} Byte {i}/{len}");
        must_fail(dir.path(), &bad, &unlock, Path4::Decrypt, &what);
        must_fail(dir.path(), &bad, &unlock, OTHERS[i % OTHERS.len()], &what);
    }
}

#[test]
fn v1_and_v2_headers() {
    every_header_byte(Kind::V1);
    every_header_byte(Kind::V2);
}

#[test]
fn v3_header_with_visible_sender() {
    every_header_byte(Kind::V3);
}

#[test]
fn v4_file_headers() {
    for kind in [Kind::V4Pad, Kind::V4Hidden, Kind::V4Anon] {
        every_header_byte(kind);
    }
}

#[test]
fn v4_stream_headers() {
    for kind in [Kind::V4Stream, Kind::V4StreamHidden] {
        every_header_byte(kind);
    }
}

#[test]
fn unchanged_files_open_on_every_path() {
    let dir = tempfile::tempdir().unwrap();
    let keys = integrity::keys();
    for kind in ALL {
        let bytes = integrity::seal(dir.path(), "gut", kind, &keys, b"ok");
        let input = dir.path().join("ok.pqkf");
        std::fs::write(&input, &bytes).unwrap();
        let out = dir.path().join("ok.out");
        pqkeep::files::decrypt(&input, &out, &keys.unlock(kind)).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"ok", "{kind:?}");
        std::fs::remove_file(&out).unwrap();
        assert_eq!(
            pqkeep::files::check(&input, &keys.unlock(kind))
                .unwrap()
                .bytes,
            2
        );
        std::fs::remove_file(&input).unwrap();
    }
}

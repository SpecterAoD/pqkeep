//! DE: Integrität (#335, Lücken G3/G4): Auf Dateiebene für jedes Format (v1–v4, Archiv und Strom,
//! mit Füllung, sichtbarer bzw. verborgener Signatur, anonymen Empfängern) Blöcke tauschen,
//! doppeln, entfernen, an jeder Blockgrenze und kurz vor dem Ende abschneiden, anhängen und Blöcke
//! einer zweiten Datei einsetzen – `decrypt` und `check` scheitern ohne Ausgabe. Frische: zweimal
//! dieselbe Quelle ergibt anderen Präfix, andere Schlüsselbindung (v4) und anderes Chiffrat.
//! EN: Integrity (#335, gaps G3/G4): at file level for every format (v1–v4, archive and stream,
//! with padding, visible or hidden signature, anonymous recipients) swap, duplicate and remove
//! chunks, cut at every chunk boundary and just before the end, append, and insert chunks of a
//! second file – `decrypt` and `check` fail without output. Freshness: the same source twice gives
//! a different prefix, key commitment (v4) and ciphertext.

// DE: Tests dürfen unwrap/expect nutzen. EN: Tests may use unwrap/expect.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::integrity::{self, ALL, ENC_CHUNK, Kind, Path4, must_fail};

/// DE: Drei Blöcke (zwei volle, ein kurzer letzter). EN: Three chunks (two full, a short last one).
fn plain() -> Vec<u8> {
    (0..2 * 64 * 1024 + 777usize)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect()
}

/// DE: Setzt Header, veränderten Strom und ggf. die sichtbare Signatur zusammen.
/// EN: Joins header, altered stream and the visible signature if any.
fn rebuild(kind: Kind, good: &[u8], body: &[u8]) -> Vec<u8> {
    let range = integrity::body(kind, good);
    [&good[..range.start], body, &good[range.end..]].concat()
}

fn chunks(body: &[u8]) -> Vec<&[u8]> {
    body.chunks(ENC_CHUNK).collect()
}

/// DE: Alle Strom-Varianten eines Falls. EN: All stream variants of a case.
fn variants(kind: Kind, good: &[u8], other: &[u8]) -> Vec<(String, Vec<u8>)> {
    let body = &good[integrity::body(kind, good)];
    let foreign = &other[integrity::body(kind, other)];
    let c = chunks(body);
    let f = chunks(foreign);
    assert!(c.len() >= 3, "{kind:?}: {} Blöcke / chunks", c.len());
    let mut out = vec![
        (
            "Tausch 0/1 / swap".into(),
            [c[1], c[0], &c[2..].concat()].concat(),
        ),
        (
            "Doppel 0 / duplicate".into(),
            [c[0], c[0], &c[1..].concat()].concat(),
        ),
        ("ohne 1 / without".into(), [c[0], &c[2..].concat()].concat()),
        (
            "fremd 1 / foreign".into(),
            [c[0], f[1], &c[2..].concat()].concat(),
        ),
        (
            "fremd letzter / foreign last".into(),
            [&c[..c.len() - 1].concat(), *f.last().unwrap()].concat(),
        ),
        ("angehängt / appended".into(), [body, f[0]].concat()),
        (
            "1 Byte mehr / one byte more".into(),
            [body, &[0u8][..]].concat(),
        ),
        (
            "1 Byte weniger / one byte less".into(),
            body[..body.len() - 1].to_vec(),
        ),
        (
            "16 Byte weniger / 16 bytes less".into(),
            body[..body.len() - 16].to_vec(),
        ),
    ];
    for k in 0..c.len() {
        out.push((format!("Schnitt nach Block {k} / cut"), c[..k].concat()));
    }
    out.into_iter()
        .map(|(what, b)| (what, rebuild(kind, good, &b)))
        .collect()
}

#[test]
fn chunk_manipulations_fail_on_every_format() {
    let dir = tempfile::tempdir().unwrap();
    let keys = integrity::keys();
    let data = plain();
    for kind in ALL {
        let good = integrity::seal(dir.path(), "a", kind, &keys, &data);
        let other = integrity::seal(dir.path(), "b", kind, &keys, &data);
        let unlock = keys.unlock(kind);
        for (what, bad) in variants(kind, &good, &other) {
            let what = format!("{kind:?}: {what}");
            must_fail(dir.path(), &bad, &unlock, Path4::Decrypt, &what);
            must_fail(dir.path(), &bad, &unlock, Path4::Check, &what);
        }
        // DE: Unverändert öffnet die Datei. EN: Unchanged, the file opens.
        let input = dir.path().join("gut.pqkf");
        std::fs::write(&input, &good).unwrap();
        let out = dir.path().join("gut.out");
        pqkeep::files::decrypt(&input, &out, &unlock).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), data, "{kind:?}");
        std::fs::remove_file(&out).unwrap();
        std::fs::remove_file(&input).unwrap();
    }
}

/// DE: Nonce-Präfix aus dem geparsten Header. EN: Nonce prefix from the parsed header.
fn prefix(bytes: &[u8]) -> [u8; 7] {
    if u16::from_le_bytes([bytes[8], bytes[9]]) == 1 {
        pqkeep::files::FileHeader::read(&mut &bytes[..])
            .unwrap()
            .prefix
    } else {
        pqkeep::files::HeaderV2::read(&mut &bytes[..])
            .unwrap()
            .prefix
    }
}

#[test]
fn same_source_twice_is_fresh_on_every_format() {
    let dir = tempfile::tempdir().unwrap();
    let keys = integrity::keys();
    for kind in ALL {
        let a = integrity::seal(dir.path(), "a", kind, &keys, b"gleich / same");
        let b = integrity::seal(dir.path(), "b", kind, &keys, b"gleich / same");
        assert_ne!(prefix(&a), prefix(&b), "{kind:?}: Präfix / prefix");
        let (ra, rb) = (integrity::body(kind, &a), integrity::body(kind, &b));
        assert_ne!(
            &a[ra.clone()][..16],
            &b[rb][..16],
            "{kind:?}: Chiffrat / ciphertext"
        );
        assert_ne!(&a[..ra.start], &b[..ra.start], "{kind:?}: Header");
        if u16::from_le_bytes([a[8], a[9]]) == 4 {
            let commit = |x: &[u8]| {
                let path = dir.path().join("c.pqkf");
                std::fs::write(&path, x).unwrap();
                pqkeep::files::inspect_v2(&path).unwrap().v4.unwrap().commit
            };
            assert_ne!(commit(&a), commit(&b), "{kind:?}: commit");
        }
    }
}

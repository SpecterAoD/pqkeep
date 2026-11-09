//! DE: Passphrase-Stärke (G1): Untergrenze 128 Bit, `--min-bits` (128–256), `pqkeep passphrase 40`
//! als Kurzform, Standardlänge 32, Mindestlänge 24, Einstufung in der Ausgabe.
//! EN: Passphrase strength (G1): minimum 128 bits, `--min-bits` (128–256), `pqkeep passphrase 40`
//! as short form, default length 32, minimum length 24, rating in the output.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqkeep::security::{Reason, StrongPassphrase};

/// DE: ≈ 152 Bit laut Schätzung. EN: ≈ 152 bits by estimate.
const PASS_152: &str = "Bm7#qLx2!Vp9$Kd4Rw8&Zt3?Hy6";

fn run(args: &[&str], stdin: &str) -> (i32, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut full = vec!["--lang", "en"];
    full.extend_from_slice(args);
    common::pqkeep(&full, stdin, dir.path())
}

#[test]
fn library_minimum_is_128_and_can_be_raised() {
    let weak = common::passphrase("Bm7#qLx2!Vp9$Kd4");
    let reasons = weak.assess().reasons;
    assert!(
        reasons
            .iter()
            .any(|r| matches!(r, Reason::LowEntropy { min: 128, .. })),
        "{reasons:?}"
    );
    assert!(StrongPassphrase::try_from(common::passphrase(PASS_152)).is_ok());
    let raised = StrongPassphrase::with_min_bits(common::passphrase(PASS_152), 200);
    let rejection = raised.err().unwrap();
    assert!(
        rejection
            .reasons
            .iter()
            .any(|r| matches!(r, Reason::LowEntropy { min: 200, .. }))
    );
    // DE: Werte unter 128 heben die Grenze nicht auf. EN: Values below 128 do not lower it.
    let lowered = StrongPassphrase::with_min_bits(common::passphrase("Bm7#qLx2!Vp9$Kd4"), 80);
    assert!(lowered.is_err());
}

#[test]
fn validate_shows_rating_and_honours_min_bits() {
    let input = format!("{PASS_152}\n");
    let (code, out, _) = run(&["validate", "--passphrase-stdin"], &input);
    assert_eq!(code, 0);
    assert!(out.contains("good (≥ 128 bits"), "{out}");
    let (code, _, err) = run(
        &["validate", "--passphrase-stdin", "--min-bits", "200"],
        &input,
    );
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("at least 200 bits"), "{err}");
    for bad in ["127", "257", "abc"] {
        let (code, _, _) = run(
            &["validate", "--passphrase-stdin", "--min-bits", bad],
            &input,
        );
        assert_eq!(code, 2, "{bad}");
    }
}

#[test]
fn passphrase_short_form_default_and_limits() {
    let (code, out, err) = run(&["passphrase"], "");
    assert_eq!(code, 0);
    assert_eq!(out.trim_end().chars().count(), 32);
    assert!(err.contains("very strong"), "{err}");
    let (code, out, _) = run(&["passphrase", "40"], "");
    assert_eq!(code, 0);
    assert_eq!(out.trim_end().chars().count(), 40);
    let (code, out, _) = run(&["passphrase", "--length", "24", "--no-ambiguous"], "");
    assert_eq!(code, 0);
    assert_eq!(out.trim_end().chars().count(), 24);
    assert_ne!(run(&["passphrase", "20"], "").0, 0, "unter 24 / below 24");
    assert_eq!(
        run(&["passphrase", "40", "-l", "30"], "").0,
        2,
        "beides / both"
    );
}

#[test]
fn encrypt_and_generate_respect_min_bits() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"x").unwrap();
    let input = format!("{PASS_152}\n");
    let args = [
        "--lang",
        "en",
        "encrypt",
        "--passphrase-stdin",
        "--min-bits",
        "200",
        "a.txt",
    ];
    assert_eq!(common::pqkeep(&args, &input, dir.path()).0, 4);
    assert!(!dir.path().join("a.txt.pqkf").exists());
    let args = ["--lang", "en", "encrypt", "--passphrase-stdin", "a.txt"];
    assert_eq!(common::pqkeep(&args, &input, dir.path()).0, 0);
    let gen_args = [
        "--lang",
        "en",
        "generate",
        "--name",
        "A",
        "--out",
        "k.json",
        "--passphrase-stdin",
        "--min-bits",
        "160",
    ];
    assert_eq!(common::pqkeep(&gen_args, &input, dir.path()).0, 4);
}

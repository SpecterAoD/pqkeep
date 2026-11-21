//! DE: RKEY-004–007/011: CLI, sichere Eingabe, Grenzen und frühzeitige Ablehnung.
//! EN: RKEY-004–007/011: CLI, safe input, boundaries and early rejection.
#![allow(clippy::unwrap_used)]
mod common;

use common::rekey::Fixture;
use pqkeep::crypto::KeyAlgorithm;
use pqkeep::envelope;
use zeroize::Zeroizing;

fn input(f: &Fixture) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "{}\n{}\n{}\n",
        f.old.as_ref().expose_str(),
        f.new.as_ref().expose_str(),
        f.new.as_ref().expose_str()
    ))
}

fn run(f: &Fixture, args: &[&str], input: &str) -> (i32, String, String) {
    let result = common::pqkeep(args, input, f.root.path());
    for text in [&result.1, &result.2] {
        for secret in [f.old.as_ref().expose_str(), f.new.as_ref().expose_str()] {
            assert!(!text.contains(secret), "Secret output / Secret-Ausgabe");
        }
    }
    result
}

#[test]
fn rkey004_005_011_cli_new_output_and_confirmed_replacement_v1_v2() {
    for v2 in [false, true] {
        for replace in [false, true] {
            let f = Fixture::new(v2, KeyAlgorithm::Aes256);
            let before = std::fs::read(&f.source).unwrap();
            let out = if replace { "key.json" } else { "new.json" };
            let mut args = vec![
                "--lang",
                "en",
                "--batch",
                "rekey",
                "key.json",
                "--out",
                out,
                "--passphrase-stdin",
            ];
            if replace {
                args.extend(["--backup", "backup.json", "--force", "--yes"]);
            }
            if v2 {
                args.extend(["--factor-file", "factor"]);
            }
            let (code, text, _) = run(&f, &args, &input(&f));
            assert_eq!(code, 0);
            assert!(text.contains("renewed"));
            f.assert_identity(&envelope::load(&f.root.path().join(out)).unwrap().0);
            let preserved = if replace { &f.backup } else { &f.source };
            assert!(
                std::fs::read(preserved).unwrap() == before,
                "Original changed / Original verändert"
            );
        }
    }
}

#[test]
fn rkey006_011_cli_input_rejects_mismatch_weak_short_and_oversized_frames() {
    let f = Fixture::new(false, KeyAlgorithm::Aes256);
    let args = [
        "rekey",
        "key.json",
        "--out",
        "new.json",
        "--passphrase-stdin",
    ];
    let old = f.old.as_ref().expose_str();
    let new = f.new.as_ref().expose_str();
    let weak = &old[..1];
    let cases = [
        (Zeroizing::new(String::new()), 2),
        (Zeroizing::new(format!("{old}\n{new}\n{old}\n")), 2),
        (Zeroizing::new(format!("{old}\n{weak}\n{weak}\n")), 4),
        (Zeroizing::new(format!("{new}\n{new}\n{new}\n")), 3),
        (Zeroizing::new(format!("{old}\n{new}\n{new}\nextra\n")), 2),
        (Zeroizing::new(format!("{}\n", old.repeat(200))), 2),
    ];
    for (data, expected) in cases {
        assert_eq!(run(&f, &args, &data).0, expected);
        assert!(!f.output.exists() && !f.backup.exists());
    }
    assert!(
        f.unlock(&envelope::load(&f.source).unwrap().0, f.old.as_ref())
            .is_ok()
    );
}

#[test]
fn rkey005_007_cli_refuses_foreign_output_and_unconfirmed_or_unbacked_replace() {
    let f = Fixture::new(false, KeyAlgorithm::Aes256);
    std::fs::write(&f.output, b"foreign / fremd").unwrap();
    for args in [
        vec!["rekey", "key.json", "-o", "new.json", "--force", "--yes"],
        vec!["rekey", "key.json", "-o", "key.json"],
    ] {
        assert_eq!(run(&f, &args, "").0, 5);
    }
    assert_eq!(
        run(
            &f,
            &["rekey", "key.json", "-o", "key.json", "--force", "--yes"],
            ""
        )
        .0,
        1
    );
    assert_eq!(
        run(
            &f,
            &[
                "--batch",
                "rekey",
                "key.json",
                "-o",
                "key.json",
                "--force",
                "--backup",
                "backup.json"
            ],
            ""
        )
        .0,
        2
    );
    assert!(!f.backup.exists());
    assert!(
        std::fs::read(&f.output).unwrap() == b"foreign / fremd",
        "Foreign output changed / Fremdziel verändert"
    );
    assert!(
        f.unlock(&envelope::load(&f.source).unwrap().0, f.old.as_ref())
            .is_ok()
    );
}

#[test]
fn rkey003_011_cli_rejects_global_file_factor_mismatch_batch_prompt_and_min_bits() {
    for v2 in [false, true] {
        let f = Fixture::new(v2, KeyAlgorithm::Aes256);
        assert_eq!(
            run(
                &f,
                &[
                    "--passphrase-file",
                    "absent",
                    "rekey",
                    "absent",
                    "-o",
                    "new.json"
                ],
                ""
            )
            .0,
            2
        );
        let mut args = vec!["--batch", "rekey", "key.json", "-o", "new.json"];
        if v2 {
            assert_eq!(run(&f, &args, "").0, 2);
            args.extend(["--factor-file", "factor"]);
        }
        assert_eq!(run(&f, &args, "").0, 2);
        args.extend(["--passphrase-stdin", "--min-bits", "256"]);
        assert_eq!(run(&f, &args, &input(&f)).0, 4);
        assert!(!f.output.exists());
    }
}

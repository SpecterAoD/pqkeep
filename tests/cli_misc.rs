//! DE: CLI: validate, passphrase, Sprache, Hilfe je Befehl in DE/EN mit Beispiel und
//! Exit-Codes, keine Passphrase per Argument möglich.
//! EN: CLI: validate, passphrase, language, help per command in DE/EN with example
//! and exit codes, no passphrase possible via argument.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqc_keyforge::security::{Passphrase, StrongPassphrase};

const COMMANDS: [&str; 5] = ["generate", "validate", "passphrase", "inspect", "export"];

fn tmp() -> std::path::PathBuf {
    std::env::temp_dir()
}

#[test]
fn passphrase_command_outputs_only_the_passphrase() {
    let (code, out, err) = common::keyforge(
        &["--lang", "de", "passphrase", "--length", "32"],
        "",
        &tmp(),
    );
    assert_eq!(code, 0);
    let line = out.trim_end_matches('\n');
    assert_eq!(out.lines().count(), 1);
    assert_eq!(line.chars().count(), 32);
    assert!(StrongPassphrase::try_from(Passphrase::new(line).unwrap()).is_ok());
    assert!(err.contains("Geschätzte Stärke"));
    let (code, out, _) = common::keyforge(&["passphrase", "--no-ambiguous"], "", &tmp());
    assert_eq!(code, 0);
    assert!(!out.trim_end().chars().any(|c| "0O1lI|`'\"".contains(c)));
    let (code, _, _) = common::keyforge(&["passphrase", "--length", "8"], "", &tmp());
    assert_eq!(code, 1);
}

#[test]
fn validate_reports_reasons_and_exit_codes() {
    let (code, _, err) = common::keyforge(
        &["--lang", "de", "validate", "--passphrase-stdin"],
        "aaaa\n",
        &tmp(),
    );
    assert_eq!(code, 4);
    for reason in ["zu kurz", "kein Großbuchstabe", "Wiederholungen"] {
        assert!(err.contains(reason), "{reason}: {err}");
    }
    let strong = common::random_passphrase().as_ref().expose_str().to_owned();
    let (code, out, _) = common::keyforge(
        &["--lang", "en", "validate", "--passphrase-stdin"],
        &format!("{strong}\r\n"),
        &tmp(),
    );
    assert_eq!(code, 0, "CRLF wird entfernt / CRLF is stripped");
    assert!(out.contains("meets all rules"));
}

#[test]
fn no_tty_without_stdin_flag_is_usage_error() {
    let (code, _, err) = common::keyforge(&["--lang", "en", "validate"], "", &tmp());
    assert_eq!(code, 2);
    assert!(err.contains("--passphrase-stdin"));
}

#[test]
fn passphrase_cannot_be_given_as_argument() {
    for attempt in [
        ["validate", "--passphrase", "x"],
        ["validate", "--password", "x"],
    ] {
        let (code, _, _) = common::keyforge(&attempt, "", &tmp());
        assert_eq!(code, 2, "{attempt:?}");
    }
}

#[test]
fn help_per_command_in_both_languages() {
    for (lang, example, exit) in [
        ("de", "Beispiel", "Exit-Codes"),
        ("en", "Example", "Exit codes"),
    ] {
        let (code, out, _) = common::keyforge(&["--lang", lang, "--help"], "", &tmp());
        assert_eq!(code, 0);
        assert!(out.contains(example) && out.contains(exit), "{lang}");
        for cmd in COMMANDS {
            let (code, out, _) = common::keyforge(&["--lang", lang, cmd, "--help"], "", &tmp());
            assert_eq!(code, 0, "{lang} {cmd}");
            assert!(out.contains(example), "{lang} {cmd}: Beispiel / example");
            assert!(out.contains(exit), "{lang} {cmd}: Exit-Codes");
            assert!(out.contains("keyforge"), "{lang} {cmd}");
        }
    }
    let (_, de, _) = common::keyforge(&["--lang", "de", "generate", "--help"], "", &tmp());
    let (_, en, _) = common::keyforge(&["--lang", "en", "generate", "--help"], "", &tmp());
    assert!(de.contains("Neuen Schlüssel erzeugen") && en.contains("Generate a new key"));
}

#[test]
fn help_contains_no_example_secrets() {
    // DE: Kein Wort in einem Hilfetext darf die Passphrase-Regeln erfüllen.
    // EN: No word in any help text may satisfy the passphrase rules.
    for lang in ["de", "en"] {
        let mut texts = vec![common::keyforge(&["--lang", lang, "--help"], "", &tmp()).1];
        for cmd in COMMANDS {
            texts.push(common::keyforge(&["--lang", lang, cmd, "--help"], "", &tmp()).1);
        }
        // DE: Satzzeichen/Klammern am Wortrand gehören zum Text, nicht zum Wort
        //     (sonst erfüllt z. B. „Argon2id-Profil:“ formal die Regeln).
        // EN: Punctuation/brackets at word edges belong to the text, not the word
        //     (otherwise e.g. "Argon2id-Profil:" formally meets the rules).
        let edge = |c: char| ".,:;!?()[]\"'„“<>".contains(c);
        for word in texts.iter().flat_map(|t| t.split_whitespace()) {
            let word = word.trim_matches(edge);
            if word.is_empty() {
                continue;
            }
            let strong = StrongPassphrase::try_from(Passphrase::new(word).unwrap());
            assert!(strong.is_err(), "{lang}: {word}");
        }
    }
}

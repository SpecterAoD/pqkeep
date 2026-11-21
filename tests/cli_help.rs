//! DE: Hilfe: alle Befehle und Themen in DE und EN (mit Beispiel), deutsche
//! Überschriften, keine Beispielgeheimnisse, Completions für alle Shells, Manpage.
//! EN: Help: all commands and topics in DE and EN (with example), German
//! headings, no example secrets, completions for all shells, man page.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

const COMMANDS: &[&str] = &[
    "generate",
    "validate",
    "passphrase",
    "inspect",
    "export",
    "rekey",
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "factor",
    "check",
    "list",
    "integrate",
    "context",
    #[cfg(feature = "api")]
    "serve",
    "help",
    "completions",
    "man",
];
const TOPICS: [&str; 6] = [
    "passphrase",
    "algorithms",
    "container",
    "files",
    "security",
    "verify",
];

fn run(args: &[&str]) -> (i32, String, String) {
    common::pqkeep(args, "", &std::env::temp_dir())
}

fn all_help_texts(lang: &str) -> Vec<String> {
    let mut texts = vec![
        run(&["--lang", lang, "--help"]).1,
        run(&["--lang", lang, "help"]).1,
    ];
    for cmd in COMMANDS {
        texts.push(run(&["--lang", lang, cmd, "--help"]).1);
    }
    for topic in TOPICS {
        texts.push(run(&["--lang", lang, "help", topic]).1);
    }
    texts
}

#[test]
fn every_command_has_localised_help_with_example() {
    for (lang, example, heading, exit) in [
        ("de", "Beispiel", "Verwendung:", "Exit-Codes"),
        ("en", "Example", "Usage:", "Exit codes"),
    ] {
        for cmd in COMMANDS {
            for flag in ["--help", "-h"] {
                let (code, out, _) = run(&["--lang", lang, cmd, flag]);
                assert_eq!(code, 0, "{lang} {cmd} {flag}");
                for needle in [example, heading, exit] {
                    assert!(out.contains(needle), "{lang} {cmd} {flag}: {needle}");
                }
                let codes = out.split_once(exit).unwrap().1;
                for value in 0..=7 {
                    assert!(
                        codes.contains(&format!("  {value}  ")),
                        "{lang} {cmd} {flag}: exit code {value}"
                    );
                }
            }
        }
    }
    let (_, de, _) = run(&["--lang", "de", "encrypt", "--help"]);
    assert!(de.contains("Argumente und Optionen") && de.contains("Hilfe anzeigen"));
    assert!(!de.contains("[default:") && !de.contains("Print help"));
}

#[test]
fn every_topic_in_both_languages() {
    for topic in TOPICS {
        let (code_de, de, _) = run(&["--lang", "de", "help", topic]);
        let (code_en, en, _) = run(&["--lang", "en", "help", topic]);
        assert_eq!((code_de, code_en), (0, 0), "{topic}");
        assert!(de.contains("Beispiel") && en.contains("Example"), "{topic}");
        assert_ne!(de, en, "{topic}");
    }
    for lang in ["de", "en"] {
        let (code, _, _) = run(&["--lang", lang, "help", "unbekannt"]);
        assert_eq!(code, 2, "{lang}");
    }
}

#[test]
fn command_list_matches_root_help() {
    for lang in ["de", "en"] {
        let (code, out, _) = run(&["--lang", lang, "--help"]);
        assert_eq!(code, 0, "{lang}");
        // DE: Clap nennt diesen Abschnitt in beiden Sprachen "Commands:". Nur Namen
        //     vergleichen, unabhängig von Beschreibungen, Reihenfolge und Spaltenbreite.
        // EN: Clap calls this section "Commands:" in both languages. Compare names
        //     only, independently of descriptions, order and column width.
        let mut lines = out.lines().skip_while(|line| *line != "Commands:");
        assert_eq!(lines.next(), Some("Commands:"), "{lang}");
        let mut actual: Vec<_> = lines
            .take_while(|line| !line.trim().is_empty())
            .filter_map(|line| line.split_whitespace().next())
            .collect();
        let mut expected = COMMANDS.to_vec();
        actual.sort_unstable();
        expected.sort_unstable();
        assert_eq!(actual, expected, "{lang}: command coverage");
    }
}

#[cfg(not(feature = "api"))]
#[test]
fn serve_is_unavailable_without_api() {
    for lang in ["de", "en"] {
        let (code, _, _) = run(&["--lang", lang, "serve", "--help"]);
        assert_eq!(code, 2, "{lang}");
    }
}

#[test]
fn container_topic_warns_about_plaintext_metadata() {
    assert!(
        run(&["--lang", "de", "help", "container"])
            .1
            .contains("NICHT verschlüsselt")
    );
    assert!(
        run(&["--lang", "en", "help", "container"])
            .1
            .contains("NOT encrypted")
    );
}

#[test]
fn no_example_secrets_anywhere() {
    for lang in ["de", "en"] {
        for text in all_help_texts(lang) {
            common::assert_no_secret_like_words(&text, lang);
        }
    }
}

#[test]
fn completions_and_man_page() {
    for (shell, marker) in [
        ("bash", "complete"),
        ("zsh", "#compdef pqkeep"),
        ("fish", "complete -c pqkeep"),
        ("powershell", "Register-ArgumentCompleter"),
    ] {
        let (code, out, _) = run(&["completions", shell]);
        assert_eq!(code, 0, "{shell}");
        assert!(out.contains(marker) && out.contains("encrypt"), "{shell}");
    }
    let (code, out, _) = run(&["--lang", "de", "man"]);
    assert_eq!(code, 0);
    assert!(out.contains(".TH pqkeep 1") && out.contains("verschlüsseln"));
}

#[test]
fn usage_error_has_localised_prefix() {
    for (lang, prefix) in [("de", "Bedienfehler"), ("en", "Usage error")] {
        let (code, _, err) = run(&["--lang", lang, "unbekannt"]);
        assert_eq!(code, 2, "{lang}");
        assert!(err.contains(prefix), "{lang}: {prefix}");
    }
}

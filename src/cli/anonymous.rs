//! DE: Anonyme Empfänger (experimentell, #316/#340) auf der Kommandozeile und in der Stufe
//! „Privatsphäre hoch“: `--anonymous-recipients` verlangt ML-KEM-1024 (sonst Bedienfehler); die
//! Stufe nimmt sie mit, wenn alle Empfänger ML-KEM-1024 sind (sonst Hinweis und sichtbare IDs).
//! Jede Nutzung warnt „experimentell“; abwählbar mit `--no-anonymous-recipients`, im Menü und im
//! Kontextmenü per Rückfrage (Vorauswahl: behalten).
//! EN: Anonymous recipients (experimental, #316/#340) on the command line and in the level "privacy
//! high": `--anonymous-recipients` requires ML-KEM-1024 (else a usage error); the level includes
//! them when all recipients are ML-KEM-1024 (else a notice and visible IDs). Every use warns
//! "experimental"; can be deselected with `--no-anonymous-recipients`, in the menu and the context
//! menu via a question (default: keep).

use std::path::Path;

use clap::{Arg, ArgMatches};
use pqkeep::crypto::{KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{self, PublicKeyFile};
use pqkeep::files::EncryptOptions;
use pqkeep::security::Lang;

use super::io::{CliResult, Failure, code, localize};

/// DE: Name des Abwahl-Schalters. EN: Name of the deselect switch.
pub const NO_ANONYMOUS: &str = "no-anonymous-recipients";

/// DE: Abwahl als Argument für Kindprozesse. EN: Deselection as an argument for child processes.
pub const NO_ANONYMOUS_FLAG: &str = "--no-anonymous-recipients";

/// DE: Argument für `encrypt`. EN: Argument for `encrypt`.
pub fn no_arg(lang: Lang) -> Arg {
    let help = match lang {
        Lang::De => {
            "Anonyme Empfänger (experimentell) aus der Stufe --privacy high abwählen – Empfänger-IDs bleiben sichtbar"
        }
        Lang::En => {
            "Deselect anonymous recipients (experimental) from the level --privacy high – recipient IDs stay visible"
        }
    };
    super::args::flag(NO_ANONYMOUS, help).conflicts_with(super::recipients::ANONYMOUS)
}

fn flag(m: &ArgMatches, name: &str) -> bool {
    m.try_get_one::<bool>(name).ok().flatten() == Some(&true)
}

fn all_1024(keys: &[PublicKeyFile]) -> bool {
    keys.iter()
        .all(|k| k.algorithm() == KeyAlgorithm::Kem(KemAlgorithm::MlKem1024))
}

fn note(text: &str, lang: Lang) {
    eprintln!("{}", localize(text, lang));
}

/// DE: Optionen samt Entscheidung über anonyme Empfänger (nach dem Laden der Empfänger).
/// EN: Options including the decision on anonymous recipients (after loading the recipients).
pub fn options(m: &ArgMatches, keys: &[PublicKeyFile], lang: Lang) -> CliResult<EncryptOptions> {
    let explicit = super::recipients::anonymous(m);
    let level = super::privacy::high(m) && !flag(m, NO_ANONYMOUS) && !keys.is_empty();
    let base = super::privacy::options(m);
    if !explicit && !level {
        return Ok(EncryptOptions {
            anonymous: false,
            ..base
        });
    }
    if !all_1024(keys) {
        if explicit {
            let text = super::recipients::message("anonymous_kem").unwrap_or_default();
            return Err(Failure::new(code::USAGE, localize(text, lang)));
        }
        note(
            "Hinweis: anonyme Empfänger übersprungen – nicht alle Empfänger haben ML-KEM-1024; die Empfänger-IDs bleiben sichtbar. / Note: anonymous recipients skipped – not all recipients use ML-KEM-1024; recipient IDs stay visible.",
            lang,
        );
        return Ok(EncryptOptions {
            anonymous: false,
            ..base
        });
    }
    note(
        "Warnung: anonyme Empfänger sind EXPERIMENTELL – die Anonymität von ML-KEM (FIPS 203) ist noch nicht formal belegt (#340). / Warning: anonymous recipients are EXPERIMENTAL – the anonymity of ML-KEM (FIPS 203) is not yet formally established (#340).",
        lang,
    );
    if !explicit {
        note(
            "Abwählen mit --no-anonymous-recipients. / Deselect with --no-anonymous-recipients.",
            lang,
        );
    }
    Ok(EncryptOptions {
        anonymous: true,
        ..base
    })
}

/// DE: Kämen anonyme Empfänger in Frage (alle Empfänger lesbar und ML-KEM-1024)? Ladefehler
/// meldet später der Kindprozess. EN: Would anonymous recipients apply (all recipients readable
/// and ML-KEM-1024)? Load errors are reported later by the child process.
pub fn possible(paths: &[String]) -> bool {
    let keys: Option<Vec<PublicKeyFile>> = paths
        .iter()
        .map(|p| envelope::load_public(Path::new(p)).ok())
        .collect();
    keys.is_some_and(|k| !k.is_empty() && all_1024(&k))
}

/// DE: Rückfrage in Menü und Kontextmenü (Ja = behalten). EN: Question in menu and context menu
/// (yes = keep).
pub fn keep_question(lang: Lang) -> &'static str {
    match lang {
        Lang::De => {
            "„Privatsphäre hoch“ verbirgt auch die Empfänger (anonyme Empfänger). Das ist EXPERIMENTELL: Die Anonymität von ML-KEM (FIPS 203) ist noch nicht formal belegt (#340). Anonyme Empfänger verwenden? (Nein = abwählen, Empfänger-IDs bleiben sichtbar)"
        }
        Lang::En => {
            "\"Privacy high\" also hides the recipients (anonymous recipients). This is EXPERIMENTAL: the anonymity of ML-KEM (FIPS 203) is not yet formally established (#340). Use anonymous recipients? (No = deselect, recipient IDs stay visible)"
        }
    }
}

/// DE: Rückfrage im Terminal (Menü, Terminal-Kontextmenü), Vorauswahl Ja = behalten.
/// EN: Question in the terminal (menu, terminal context menu), default yes = keep.
pub fn keep_terminal(lang: Lang) -> CliResult<bool> {
    dialoguer::Confirm::new()
        .with_prompt(keep_question(lang))
        .default(true)
        .interact()
        .map_err(|_| Failure::new(code::ERROR, ""))
}

/// DE: Zusatzargument nach der Rückfrage: nur bei Stufe hoch und passenden Empfängern; `keep`
/// stellt die Frage. EN: Extra argument after the question: only with level high and suitable
/// recipients; `keep` asks the question.
pub fn deselect_args(
    high: bool,
    paths: &[String],
    keep: impl FnOnce() -> CliResult<bool>,
) -> CliResult<Vec<String>> {
    if !high || !possible(paths) || keep()? {
        return Ok(Vec::new());
    }
    Ok(vec![NO_ANONYMOUS_FLAG.to_owned()])
}

/// DE: `--to`-Argumente samt Abwahl. EN: `--to` arguments including the deselection.
pub fn to_args(
    all: &[String],
    high: bool,
    keep: impl FnOnce() -> CliResult<bool>,
) -> CliResult<Vec<String>> {
    let deselect = deselect_args(high, all, keep)?;
    Ok([super::recipients_ui::to_args(all), deselect].concat())
}

#[cfg(test)]
#[path = "anonymous_tests.rs"]
mod anonymous_tests;

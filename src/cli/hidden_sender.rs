//! DE: Verborgener Absender (`encrypt --sign-with … --hide-sender`, Format v4, #316): Absender-
//! schlüssel und Signatur stehen nur im verschlüsselten Teil; Empfänger prüfen sie beim
//! Entschlüsseln. Die Stufe `--privacy high` verbirgt den Absender, wenn signiert wird.
//! EN: Hidden sender (`encrypt --sign-with … --hide-sender`, format v4, #316): sender key and
//! signature live only inside the encrypted part; recipients verify them when decrypting. The level
//! `--privacy high` hides the sender when signing.

use std::path::PathBuf;

use clap::{Arg, ArgMatches};
use pqkeep::security::Lang;

use super::io::{CliResult, Failure, code, localize};

/// DE: Name des Schalters. EN: Name of the switch.
pub const HIDE_SENDER: &str = "hide-sender";

/// DE: Argument für `encrypt`. EN: Argument for `encrypt`.
pub fn arg(lang: Lang) -> Arg {
    let help = match lang {
        Lang::De => {
            "Absender verbergen: Schlüssel und Signatur nur im verschlüsselten Teil (nur mit --sign-with; Format v4, lesbar ab beta.5)"
        }
        Lang::En => {
            "Hide the sender: key and signature only inside the encrypted part (only with --sign-with; format v4, readable from beta.5)"
        }
    };
    super::args::flag(HIDE_SENDER, help)
}

fn signing(m: &ArgMatches) -> bool {
    m.get_one::<PathBuf>(super::signing::SIGN_WITH).is_some()
}

/// DE: Absender verbergen? `--hide-sender` oder Stufe hoch beim Signieren.
/// EN: Hide the sender? `--hide-sender` or level high when signing.
pub fn wanted(m: &ArgMatches) -> bool {
    let flag = m.try_get_one::<bool>(HIDE_SENDER).ok().flatten() == Some(&true);
    let high = m
        .try_get_one::<String>("privacy")
        .ok()
        .flatten()
        .map(String::as_str)
        == Some("high");
    flag || (high && signing(m))
}

/// DE: `--hide-sender` ohne `--sign-with` ist ein Bedienfehler (vor jeder Eingabe).
/// EN: `--hide-sender` without `--sign-with` is a usage error (before any input).
pub fn check(m: &ArgMatches, lang: Lang) -> CliResult {
    let flag = m.try_get_one::<bool>(HIDE_SENDER).ok().flatten() == Some(&true);
    if flag && !signing(m) {
        return Err(Failure::new(
            code::USAGE,
            localize(message("hide_sender").unwrap_or_default(), lang),
        ));
    }
    Ok(())
}

/// DE: Meldungen zu Feldnamen der Bibliothek. EN: Messages for library field names.
pub fn message(field: &str) -> Option<&'static str> {
    (field == "hide_sender").then_some(
        "--hide-sender braucht --sign-with (ohne Signatur gibt es keinen Absender) / --hide-sender needs --sign-with (without a signature there is no sender)",
    )
}

/// DE: Zeile für `inspect`. EN: Line for `inspect`.
pub fn inspect_line(lang: Lang) -> String {
    localize(
        "Signiert: ja, Absender verborgen (wird beim Entschlüsseln geprüft) / signed: yes, sender hidden (verified when decrypting)",
        lang,
    )
}

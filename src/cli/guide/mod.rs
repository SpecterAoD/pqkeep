//! DE: Geführte Abläufe für Einsteiger (Plan G2): Schlüssel erstellen, Datei signieren, Signatur
//! prüfen. Start über das Menü (`pqkeep` ohne Argumente) oder wenn `generate`/`sign`/`verify` im
//! Terminal ohne die nötigen Angaben aufgerufen werden – nie ohne Terminal oder mit `--batch`.
//! Der Ablauf fragt nur ab und startet dann **dieselben Befehle** als Kindprozesse mit voller
//! Sandbox; er verarbeitet keine Geheimnisse. Am Ende zeigt er die entsprechenden Befehle an.
//! EN: Guided flows for beginners (plan G2): create a key, sign a file, verify a signature. Started
//! from the menu (`pqkeep` without arguments) or when `generate`/`sign`/`verify` are called in a
//! terminal without the required input – never without a terminal or with `--batch`. The flow only
//! asks and then runs **the same commands** as child processes with the full sandbox; it handles no
//! secrets. At the end it shows the corresponding commands.

mod factor;
mod keygen;
mod levels;
mod signing;
mod text;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use clap::ArgMatches;
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input, Select};
use pqkeep::security::Lang;

use super::io::{CliResult, Failure, code};

pub use keygen::run as keygen;
pub use signing::{sign, verify};

/// DE: Abbruch durch den Benutzer (Esc). EN: Cancelled by the user (Esc).
fn cancelled() -> Failure {
    Failure::new(code::USAGE, "")
}

/// DE: Auswahl; Esc bricht ab. EN: Selection; Esc cancels.
fn select<S: std::fmt::Display>(prompt: &str, items: &[S], default: usize) -> CliResult<usize> {
    Select::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .items(items)
        .default(default)
        .interact_opt()
        .ok()
        .flatten()
        .ok_or_else(cancelled)
}

/// DE: Texteingabe mit optionaler Vorgabe. EN: Text input with an optional default.
fn input(prompt: &str, default: Option<&str>, allow_empty: bool) -> CliResult<String> {
    let theme = ColorfulTheme::default();
    let mut field = Input::<String>::with_theme(&theme)
        .with_prompt(prompt)
        .allow_empty(allow_empty);
    if let Some(d) = default {
        field = field.default(d.to_owned());
    }
    field.interact_text().map_err(|_| cancelled())
}

/// DE: Ja/Nein. EN: Yes/no.
fn confirm(prompt: &str, default: bool) -> CliResult<bool> {
    Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .default(default)
        .interact_opt()
        .ok()
        .flatten()
        .ok_or_else(cancelled)
}

/// DE: Pfad abfragen (Anführungszeichen vom Hineinziehen entfernt); `must_exist` = so lange
/// fragen, bis es die Datei gibt. EN: Ask for a path (quotes from drag and drop removed).
fn path(
    prompt: &str,
    default: Option<&str>,
    must_exist: bool,
    not_found: &str,
) -> CliResult<String> {
    loop {
        let raw = input(prompt, default, false)?;
        let trimmed = raw.trim();
        let unquoted = trimmed
            .strip_prefix('\'')
            .and_then(|t| t.strip_suffix('\''))
            .or_else(|| trimmed.strip_prefix('"').and_then(|t| t.strip_suffix('"')))
            .unwrap_or(trimmed)
            .to_owned();
        if !must_exist || Path::new(&unquoted).is_file() {
            return Ok(unquoted);
        }
        eprintln!("{not_found}");
    }
}

/// DE: Startet `pqkeep --lang <x> <args…>` mit geerbtem Terminal; liefert den Exit-Code.
/// EN: Runs `pqkeep --lang <x> <args…>` with the inherited terminal; returns the exit code.
fn child(lang: Lang, args: &[String]) -> CliResult<i32> {
    let fail = |e: std::io::Error| Failure::from_error(&e.into(), lang);
    let exe = std::env::current_exe().map_err(fail)?;
    let code = if lang == Lang::De { "de" } else { "en" };
    let status = std::process::Command::new(exe)
        .args(["--lang", code])
        .args(args)
        .status()
        .map_err(fail)?;
    Ok(status.code().unwrap_or(1))
}

/// DE: Argument für die Anzeige als Shell-Befehl quoten. EN: Quote an argument for display.
fn quote(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/:=@%+-,".contains(c));
    if plain {
        arg.to_owned()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

/// DE: Befehlszeile zum Nachlesen. EN: Command line for reference.
fn command_line(args: &[String]) -> String {
    let quoted: Vec<String> = args.iter().map(|a| quote(a)).collect();
    format!("pqkeep {}", quoted.join(" "))
}

/// DE: Soll statt eines Fehlers der geführte Ablauf starten? Nur im Terminal, nie mit `--batch`,
/// und nur wenn Pflichtangaben fehlen.
/// EN: Should the guided flow start instead of an error? Only in a terminal, never with
/// `--batch`, and only when required input is missing.
pub fn wanted(name: &str, m: &ArgMatches) -> bool {
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    if !interactive || super::unattended::batch() {
        return false;
    }
    let missing = |id: &str| m.try_get_one::<String>(id).ok().flatten().is_none();
    let missing_path = |id: &str| m.try_get_one::<PathBuf>(id).ok().flatten().is_none();
    match name {
        "generate" => missing("name") || missing_path("out"),
        "sign" => missing_path("file") || missing_path("key"),
        "verify" => missing_path("file") || missing_path("pub"),
        _ => false,
    }
}

/// DE: Geführten Ablauf zu einem Befehl starten; ein schon angegebenes `--factor-file` wird beim
/// Erstellen eines Schlüssels übernommen.
/// EN: Start the guided flow for a command; a `--factor-file` already given is taken over when
/// creating a key.
pub fn run(name: &str, lang: Lang, m: &ArgMatches) -> CliResult {
    let given = super::factor_cmd::path(m).map(|p| p.to_string_lossy().into_owned());
    match name {
        "generate" => keygen(lang, None, given).map(|_| ()),
        "sign" => sign(lang),
        _ => verify(lang),
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod mod_tests;

//! DE: `pqkeep context encrypt|decrypt -- <pfad>`: vom Kontextmenü im Terminal gestartet. Fragt
//! nur Modus und Pfade ab; die eigentliche Arbeit (inkl. verdeckter Passphrase-Eingabe) läuft wie im
//! Menü als eigener Prozess mit voller Sandbox. Dieser Prozess verarbeitet keine Geheimnisse.
//! EN: `pqkeep context encrypt|decrypt -- <path>`: started by the context menu in a terminal. Only
//! asks for mode and paths; the actual work (incl. hidden passphrase input) runs, as in the menu, as
//! a separate process with the full sandbox. This process handles no secrets.

use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use dialoguer::{Confirm, Input, Select};
use pqkeep::files::{self, HeaderMode};
use pqkeep::security::Lang;

use super::files_cmd::{default_decrypted, default_encrypted, free_target};
use super::integrate_text::{IntegrateTexts, integrate_texts};
use super::io::{CliResult, Failure, code};
use super::text::Texts;

/// DE: Argumente von `context`. EN: Arguments of `context`.
pub fn command(base: Command, lang: Lang) -> Command {
    let s = integrate_texts(lang);
    base.arg(
        Arg::new("action")
            .help(s.ctx_arg_action)
            .required(true)
            .hide_possible_values(true)
            .value_parser(["encrypt", "decrypt", "auto"]),
    )
    .arg(
        Arg::new("path")
            .help(s.ctx_arg_path)
            .required(true)
            .num_args(1..=super::args::MAX_SOURCES)
            .value_parser(value_parser!(PathBuf)),
    )
    .arg(
        Arg::new("dialog")
            .long("dialog")
            .help(super::dialog_text::dialog_texts(lang).arg_dialog)
            .action(ArgAction::SetTrue),
    )
}

fn lang_code(lang: Lang) -> &'static str {
    if lang == Lang::De { "de" } else { "en" }
}

/// DE: Startet `pqkeep --lang <x> <args…>` als Kindprozess. EN: Runs pqkeep as a child process.
pub(super) fn child(lang: Lang, extra: &[&str]) -> CliResult {
    let mut argv = vec![
        "pqkeep".to_owned(),
        "--lang".to_owned(),
        lang_code(lang).to_owned(),
    ];
    argv.extend(extra.iter().map(|a| (*a).to_owned()));
    super::run_child(&argv, lang)
}

/// DE: Absoluter Pfad, damit kein weitergegebener Wert mit `-` beginnt und als Option gilt.
/// EN: Absolute path so that no passed value starts with `-` and counts as an option.
pub(super) fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// DE: Pfad abfragen; Anführungszeichen vom Hineinziehen ins Terminal werden entfernt.
/// EN: Ask for a path; quotes from drag and drop into the terminal are removed.
pub(super) fn ask_path(prompt: &str) -> CliResult<String> {
    let raw: String = Input::new()
        .with_prompt(prompt)
        .interact_text()
        .map_err(|_| Failure::new(code::ERROR, ""))?;
    let trimmed = raw.trim();
    let unquoted = trimmed
        .strip_prefix('\'')
        .and_then(|t| t.strip_suffix('\''))
        .or_else(|| trimmed.strip_prefix('"').and_then(|t| t.strip_suffix('"')))
        .unwrap_or(trimmed);
    Ok(absolute(Path::new(unquoted)).to_string_lossy().into_owned())
}

/// DE: `--out` mit freiem Namen. EN: `--out` with a free name.
pub(super) fn out_arg(target: Option<&Path>, lang: Lang) -> CliResult<String> {
    let free = target.and_then(free_target);
    let path = free.ok_or_else(|| {
        Failure::from_error(&pqkeep::Error::Io(std::io::ErrorKind::AlreadyExists), lang)
    })?;
    utf8(&path, lang)
}

pub(super) fn utf8(path: &Path, lang: Lang) -> CliResult<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Failure::from_error(&pqkeep::Error::InvalidInput { field: "path" }, lang))
}

fn encrypt(s: &IntegrateTexts, lang: Lang, path: &str) -> CliResult {
    let modes: Vec<&str> = s.ctx_modes.split('|').collect();
    let mode = Select::new()
        .with_prompt(s.ctx_mode)
        .items(&modes)
        .default(0)
        .interact()
        .map_err(|_| Failure::new(code::ERROR, ""))?;
    let out = out_arg(default_encrypted(Path::new(path)).as_deref(), lang)?;
    if mode == 0 {
        return child(lang, &["encrypt", "--out", &out, "--", path]);
    }
    let public = ask_path(s.ctx_prompt_pub)?;
    child(lang, &["inspect", "--", &public])?;
    let ok = Confirm::new()
        .with_prompt(s.ctx_confirm)
        .default(false)
        .interact()
        .map_err(|_| Failure::new(code::ERROR, ""))?;
    if !ok {
        return Err(Failure::new(code::USAGE, ""));
    }
    child(
        lang,
        &["encrypt", "--to", &public, "--out", &out, "--", path],
    )
}

fn decrypt(s: &IntegrateTexts, lang: Lang, source: &Path, path: &str) -> CliResult {
    if source.extension().and_then(|e| e.to_str()) != Some(files::EXTENSION) {
        return Err(Failure::new(code::USAGE, s.ctx_not_pqkf));
    }
    let header = files::inspect(source).map_err(|e| Failure::from_error(&e, lang))?;
    let out = out_arg(default_decrypted(source).as_deref(), lang)?;
    if let HeaderMode::Recipient { .. } = header.mode {
        let key = ask_path(s.ctx_prompt_key)?;
        return child(lang, &["decrypt", "--key", &key, "--out", &out, "--", path]);
    }
    child(lang, &["decrypt", "--out", &out, "--", path])
}

/// DE: `pqkeep context`. EN: `pqkeep context`.
pub fn run(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    let s = integrate_texts(lang);
    let sources: Vec<PathBuf> = m
        .get_many::<PathBuf>("path")
        .map(|v| v.map(|p| absolute(p)).collect())
        .unwrap_or_default();
    let action = m
        .get_one::<String>("action")
        .map_or("encrypt", String::as_str);
    if m.get_flag("dialog") {
        return super::context_dialog::run(lang, action, &sources);
    }
    if !std::io::stdin().is_terminal() {
        return Err(Failure::new(code::USAGE, t.msg_no_tty));
    }
    let action = super::context_many::resolve_action(action, &sources);
    let result = super::context_many::checked(&sources, lang).and_then(|paths| {
        if paths.len() > 1 {
            super::context_many::terminal(s, lang, action, &sources, &paths)
        } else if action == "decrypt" {
            decrypt(s, lang, &sources[0], &paths[0])
        } else {
            encrypt(s, lang, &paths[0])
        }
    });
    match &result {
        Ok(()) => println!("{}", s.ctx_done),
        Err(f) => {
            if !f.message.is_empty() {
                eprintln!("{}: {}", t.msg_error, f.message);
            }
            eprintln!("{}", s.ctx_failed);
        }
    }
    eprintln!("{}", s.ctx_enter);
    let _ = std::io::stdin().lock().read_line(&mut String::new());
    // DE: Meldung wurde schon ausgegeben; nur den Exit-Code weiterreichen.
    // EN: Message already printed; only pass on the exit code.
    result.map_err(|f| Failure::new(f.code, ""))
}

#[cfg(test)]
#[path = "context_tests.rs"]
mod context_tests;

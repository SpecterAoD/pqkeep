//! DE: Ein-/Ausgabe der CLI: Passphrase verdeckt oder aus Stdin (nie Argument/
//! Umgebungsvariable), Bestätigungen, Fehlercodes, lokalisierte Fehlermeldungen.
//! EN: CLI input/output: passphrase hidden or from stdin (never argument/
//! environment variable), confirmations, exit codes, localised error messages.

use std::io::{BufRead, IsTerminal};
use std::path::Path;
use std::process::ExitCode;

use dialoguer::{Confirm, Password};
use pqkeep::Error;
use pqkeep::security::{Lang, Passphrase};
use zeroize::Zeroize;

use super::text::Texts;

/// DE: Exit-Codes (siehe Hilfe). EN: Exit codes (see help).
pub mod code {
    /// DE/EN: Erfolg / success.
    pub const OK: u8 = 0;
    /// DE/EN: Fehler / error.
    pub const ERROR: u8 = 1;
    /// DE/EN: Bedienfehler / usage error.
    pub const USAGE: u8 = 2;
    /// DE/EN: Entschlüsselung fehlgeschlagen / decryption failed.
    pub const DECRYPT: u8 = 3;
    /// DE/EN: Passphrase zu schwach / passphrase too weak.
    pub const WEAK: u8 = 4;
    /// DE/EN: Ziel existiert / target exists.
    pub const EXISTS: u8 = 5;
    /// DE: Keine Fenster möglich (`context --dialog`; `pqkeepw.exe` öffnet dann eine Konsole).
    /// EN: No windows possible (`context --dialog`; `pqkeepw.exe` then opens a console).
    pub const NO_WINDOWS: u8 = 6;
    /// DE/EN: Signatur ungültig / signature invalid (`verify`).
    pub const INVALID: u8 = 7;
}

/// DE: Fehler der CLI mit Exit-Code. EN: CLI error with exit code.
pub struct Failure {
    pub code: u8,
    pub message: String,
}

impl Failure {
    pub fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// DE: Aus Bibliotheksfehler, Meldung in der gewählten Sprache.
    /// EN: From a library error, message in the chosen language.
    pub fn from_error(err: &Error, lang: Lang) -> Self {
        use std::io::ErrorKind;
        let code = match err {
            Error::Decrypt => code::DECRYPT,
            Error::WeakPassphrase => code::WEAK,
            Error::InvalidSignature => code::INVALID,
            Error::Io(ErrorKind::AlreadyExists) => code::EXISTS,
            // DE: Option fehlt oder ist überflüssig. EN: Option missing or superfluous.
            Error::InvalidInput {
                field: "factor_required" | "factor_unused",
            } => code::USAGE,
            _ => code::ERROR,
        };
        let text = match err {
            Error::Io(ErrorKind::AlreadyExists) => {
                "Ziel existiert bereits (--force zum Ersetzen) / target already exists (use --force to replace)"
                    .to_owned()
            }
            Error::Io(ErrorKind::NotFound) => {
                "Datei oder Ordner nicht gefunden / file or directory not found".to_owned()
            }
            Error::Io(ErrorKind::PermissionDenied) => {
                "Zugriff verweigert / permission denied".to_owned()
            }
            Error::Io(kind) => format!("Ein-/Ausgabefehler ({kind}) / I/O error ({kind})"),
            Error::InvalidInput { field } => super::factor_cmd::message(field)
                .map_or_else(|| err.to_string(), str::to_owned),
            other => other.to_string(),
        };
        Self::new(code, localize(&text, lang))
    }
}

/// DE: Wählt aus „Deutsch / English“ den passenden Teil. EN: Picks the matching part.
pub fn localize(text: &str, lang: Lang) -> String {
    match (text.split_once(" / "), lang) {
        (Some((de, _)), Lang::De) => de.to_owned(),
        (Some((_, en)), Lang::En) => en.to_owned(),
        (None, _) => text.to_owned(),
    }
}

pub type CliResult<T = ()> = Result<T, Failure>;

/// DE: Liest eine Passphrase (verdeckt oder Stdin); `confirm` fragt zweimal.
/// EN: Reads a passphrase (hidden or stdin); `confirm` asks twice.
pub fn read_passphrase(
    t: &Texts,
    lang: Lang,
    from_stdin: bool,
    confirm: bool,
) -> CliResult<Passphrase> {
    let prompt = if confirm {
        t.prompt_new_passphrase
    } else {
        t.prompt_passphrase
    };
    read_passphrase_as(t, lang, from_stdin, confirm, prompt)
}

/// DE: Wie [`read_passphrase`], mit eigenem Eingabetext. EN: Like [`read_passphrase`] with own prompt.
pub fn read_passphrase_as(
    t: &Texts,
    lang: Lang,
    from_stdin: bool,
    confirm: bool,
    prompt_text: &str,
) -> CliResult<Passphrase> {
    if let Some(result) = super::unattended::read_pass_file(lang, from_stdin) {
        return result;
    }
    let text = if from_stdin {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| Failure::from_error(&Error::from(e), lang))?;
        let trimmed_len = line.trim_end_matches(['\n', '\r']).len();
        line.truncate(trimmed_len);
        line
    } else {
        if super::unattended::batch() {
            return Err(super::unattended::batch_failure(lang));
        }
        if !std::io::stdin().is_terminal() {
            return Err(Failure::new(code::USAGE, t.msg_no_tty));
        }
        let mut prompt = Password::new().with_prompt(prompt_text);
        if confirm {
            prompt = prompt.with_confirmation(t.prompt_confirm, t.prompt_mismatch);
        }
        prompt
            .interact()
            .map_err(|_| Failure::new(code::ERROR, t.msg_aborted))?
    };
    Passphrase::from_string(text).map_err(|e| Failure::from_error(&e, lang))
}

/// DE: Liest eine neue Passphrase zweimal von stdin (je eine Zeile) und vergleicht im eigenen
/// (sandboxed) Prozess – für das Passwortfenster des Kontextmenüs.
/// EN: Reads a new passphrase twice from stdin (one line each) and compares in this own
/// (sandboxed) process – for the context menu's password window.
pub fn read_confirmed_stdin(t: &Texts, lang: Lang) -> CliResult<Passphrase> {
    let read = || -> CliResult<String> {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| Failure::from_error(&Error::from(e), lang))?;
        let len = line.trim_end_matches(['\n', '\r']).len();
        line.truncate(len);
        Ok(line)
    };
    let first = read()?;
    let mut second = read()?;
    let same = first == second;
    second.zeroize();
    if !same {
        let mut first = first;
        first.zeroize();
        return Err(Failure::new(code::USAGE, t.prompt_mismatch));
    }
    Passphrase::from_string(first).map_err(|e| Failure::from_error(&e, lang))
}

/// DE: Klärt, ob ein vorhandenes Ziel ersetzt werden darf. EN: Decides whether an existing target may be replaced.
pub fn allow_overwrite(
    t: &Texts,
    lang: Lang,
    path: &Path,
    force: bool,
    yes: bool,
) -> CliResult<bool> {
    if !path.exists() || !force {
        return Ok(false);
    }
    if yes {
        return Ok(true);
    }
    if super::unattended::batch() {
        return Err(super::unattended::batch_failure(lang));
    }
    if !std::io::stdin().is_terminal() {
        return Err(Failure::new(code::USAGE, t.msg_no_tty));
    }
    let ok = Confirm::new()
        .with_prompt(t.prompt_overwrite)
        .default(false)
        .interact()
        .map_err(|_| Failure::new(code::ERROR, t.msg_aborted))?;
    if ok {
        Ok(true)
    } else {
        Err(Failure::new(code::EXISTS, t.msg_aborted))
    }
}

/// DE: Fingerabdruck lesbar in Vierergruppen. EN: Fingerprint readable in groups of four.
pub fn fingerprint(hex: &str) -> String {
    let mut out = String::with_capacity(hex.len() + hex.len() / 4);
    for (i, c) in hex.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// DE: Beendet mit Code; Fehlermeldung auf Stderr. EN: Exits with code; error message on stderr.
pub fn finish(result: CliResult, t: &Texts) -> ExitCode {
    match result {
        Ok(()) => ExitCode::from(code::OK),
        Err(mut f) => {
            // DE: Leere Meldung = Details wurden bereits ausgegeben.
            // EN: Empty message = details have already been printed.
            if !f.message.is_empty() {
                eprintln!("{}: {}", t.msg_error, f.message);
            }
            f.message.zeroize();
            ExitCode::from(f.code)
        }
    }
}

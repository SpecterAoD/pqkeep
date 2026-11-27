//! DE: Verschlüsseln aus einer Pipe (#83, Format v4 Inhalt „Strom“): `encrypt --stdin` liest die
//! Daten von stdin und schreibt nach `--out` (atomar) oder mit `--stdout` direkt nach stdout (keine
//! Temporärdatei; Meldungen dann nur auf stderr). Weil stdin die Daten liefert, kommt die
//! Passphrase nur aus `--passphrase-file` (oder es gibt nur Empfänger); eine Signatur braucht
//! `--sign-passphrase-file`. Entschlüsselt wird wie jede `.pqkf` nur in eine Datei (S2b verworfen).
//! EN: Encrypting from a pipe (#83, format v4 content "stream"): `encrypt --stdin` reads the data
//! from stdin and writes to `--out` (atomically) or with `--stdout` directly to stdout (no temporary
//! file; messages then on stderr only). Since stdin carries the data, the passphrase only comes from
//! `--passphrase-file` (or there are only recipients); a signature needs `--sign-passphrase-file`.
//! Decryption, like any `.pqkf`, goes into a file only (S2b dropped).

use std::path::PathBuf;

use clap::{Arg, ArgMatches};
use pqkeep::files::{self, Report};
use pqkeep::security::Lang;

use super::args::flag;
use super::files_cmd::{OwnedProtection, print_report, read_protection};
use super::io::{CliResult, Failure, code, localize};
use super::text::Texts;

/// DE: Schalter „Daten von stdin“. EN: Switch "data from stdin".
pub const STDIN: &str = "stdin";
/// DE: Schalter „Ergebnis nach stdout“. EN: Switch "result to stdout".
pub const STDOUT: &str = "stdout";

/// DE: Argumente für `encrypt`. EN: Arguments for `encrypt`.
pub fn args(lang: Lang) -> [Arg; 2] {
    let (input, output) = match lang {
        Lang::De => (
            "Daten von stdin lesen (Pipe) und als Datenstrom verschlüsseln (Format v4); Ziel mit --out oder --stdout; Passphrase nur über --passphrase-file oder nur Empfänger (--to)",
            "Verschlüsseltes Ergebnis nach stdout schreiben (nur mit --stdin; Meldungen auf stderr)",
        ),
        Lang::En => (
            "Read the data from stdin (pipe) and encrypt it as a data stream (format v4); target via --out or --stdout; passphrase only via --passphrase-file or recipients only (--to)",
            "Write the encrypted result to stdout (only with --stdin; messages on stderr)",
        ),
    };
    [
        flag(STDIN, input).conflicts_with_all([
            "source",
            "each",
            "rename",
            "random-name",
            "privacy",
            "passphrase-stdin",
            "confirm-stdin",
        ]),
        flag(STDOUT, output)
            .requires(STDIN)
            .conflicts_with_all(["out", "json"]),
    ]
}

/// DE: `--stdin` gewählt? `--stdout` allein ist ein Bedienfehler (clap prüft `requires` bei
/// Schaltern nicht zuverlässig).
/// EN: `--stdin` chosen? `--stdout` alone is a usage error (clap does not reliably check `requires`
/// for switches).
pub fn wanted(m: &ArgMatches, lang: Lang) -> CliResult<bool> {
    if m.get_flag(STDOUT) && !m.get_flag(STDIN) {
        return Err(usage(
            "--stdout nur zusammen mit --stdin / --stdout only together with --stdin",
            lang,
        ));
    }
    Ok(m.get_flag(STDIN))
}

fn usage(text: &str, lang: Lang) -> Failure {
    Failure::new(code::USAGE, localize(text, lang))
}

/// DE: Bedienregeln vor jeder Eingabe. EN: Usage rules before any input.
pub fn check(m: &ArgMatches, lang: Lang) -> CliResult {
    if !m.get_flag(STDOUT) && m.get_one::<PathBuf>("out").is_none() {
        return Err(usage(
            "Mit --stdin bitte ein Ziel angeben: --out <datei> oder --stdout / with --stdin please give a target: --out <file> or --stdout",
            lang,
        ));
    }
    let recipients = !super::recipients::paths(m).is_empty();
    let own_passphrase = !recipients || m.get_flag(super::recipients::WITH_PASSPHRASE);
    if own_passphrase && super::unattended::pass_file().is_none() {
        return Err(usage(
            "stdin liefert bereits die Daten – Passphrase bitte mit --passphrase-file angeben oder nur Empfänger (--to) verwenden / stdin already carries the data – please give the passphrase with --passphrase-file or use recipients only (--to)",
            lang,
        ));
    }
    let signing = m.get_one::<PathBuf>(super::signing::SIGN_WITH).is_some();
    if signing
        && m.get_one::<PathBuf>(super::signing::SIGN_PASS_FILE)
            .is_none()
    {
        return Err(usage(
            "Mit --stdin braucht --sign-with die Passphrase aus --sign-passphrase-file / with --stdin, --sign-with needs the passphrase from --sign-passphrase-file",
            lang,
        ));
    }
    Ok(())
}

/// DE: Verschlüsselt stdin; liefert Ziel (`None` = stdout) und Bericht.
/// EN: Encrypts stdin; returns the target (`None` = stdout) and the report.
pub fn run(p: &OwnedProtection, m: &ArgMatches) -> pqkeep::Result<(Option<PathBuf>, Report)> {
    let mut input = std::io::stdin().lock();
    if m.get_flag(STDOUT) {
        let out = std::io::stdout().lock();
        let report = p.with(|prot| {
            files::encrypt_stream(&mut input, out, prot, p.signer.as_ref(), p.options)
        })?;
        return Ok((None, report));
    }
    let out = m
        .get_one::<PathBuf>("out")
        .cloned()
        .ok_or(pqkeep::Error::InvalidInput { field: "out" })?;
    let report = p.with(|prot| {
        files::encrypt_stream_to(&mut input, &out, prot, p.signer.as_ref(), p.options)
    })?;
    Ok((Some(out), report))
}

/// DE: Meldung bei `--stdout`: nur auf stderr, damit stdout rein bleibt.
/// EN: Message with `--stdout`: stderr only so stdout stays clean.
pub fn report_stderr(verb: &str, summary: &str, r: &Report) {
    eprintln!("{verb}: stdout");
    eprintln!("{summary}: {} / {} / {}", r.files, r.directories, r.bytes);
}

/// DE: `encrypt --stdin` (Text-Ausgabe). EN: `encrypt --stdin` (text output).
pub fn encrypt(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    check(m, lang)?;
    let protection = read_protection(t, lang, m)?;
    let (out, report) = run(&protection, m).map_err(|e| Failure::from_error(&e, lang))?;
    match out {
        Some(out) => print_report(t, lang, t.msg_encrypted, &out, &report),
        None => report_stderr(t.msg_encrypted, t.msg_summary, &report),
    }
    Ok(())
}

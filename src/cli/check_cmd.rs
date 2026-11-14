//! DE: `pqkeep check <datei.pqkf>…` (#86): prüft verschlüsselte Dateien vollständig – wie beim
//! Entschlüsseln, aber ohne etwas zu schreiben (für Backup-Kontrollen und Monitoring). Passphrase
//! bzw. Schlüssel nur einmal; jede Datei wird geprüft, auch wenn eine scheitert. Exit-Code: der
//! erste Fehler (3 = falscher Schlüssel oder Manipulation, 1 = sonstiger Fehler, 2 = Bedienfehler).
//! Kopfdaten ohne Geheimnis zeigt `inspect` – das ist keine Integritätsprüfung.
//! EN: `pqkeep check <file.pqkf>…` (#86): checks encrypted files completely – like decrypting, but
//! without writing anything (for backup checks and monitoring). Passphrase or key only once; every
//! file is checked even if one fails. Exit code: the first error (3 = wrong key or tampering,
//! 1 = other error, 2 = usage error). Header data without a secret is shown by `inspect` – that is
//! no integrity check.

use std::path::{Path, PathBuf};

use clap::{ArgMatches, Command, value_parser};
use pqkeep::files;
use pqkeep::security::Lang;

use super::args::{base, flag, opt, path};
use super::args_files::MAX_SOURCES;
use super::io::{CliResult, Failure, code};
use super::text::Texts;
use super::unlock::Access;

/// DE: Texte. EN: Texts.
struct CheckTexts {
    about: &'static str,
    after: &'static str,
    arg_sources: &'static str,
    ok: &'static str,
    failed: &'static str,
    summary: &'static str,
}

const DE: CheckTexts = CheckTexts {
    about: "Verschlüsselte Dateien vollständig prüfen, ohne etwas zu schreiben (Backup-Kontrolle)",
    after: "Beispiele:\n  pqkeep check backup.pqkf\n  pqkeep check --key backup.key.json /srv/backup/*.pqkf\n\nPrüft alle Blöcke, Prüfsummen und Archivpfade wie beim Entschlüsseln; geschrieben wird nichts. Exit-Code 0 = alles in Ordnung, 3 = falscher Schlüssel bzw. falsche Passphrase oder Manipulation, 1 = sonstiger Fehler. Nur die Kopfdaten ohne Passphrase zeigt pqkeep inspect (keine Integritätsprüfung).",
    arg_sources: "Verschlüsselte Datei(en) (.pqkf)",
    ok: "OK",
    failed: "FEHLER",
    summary: "Geprüft: {n}, in Ordnung: {ok}, fehlerhaft: {bad}",
};

const EN: CheckTexts = CheckTexts {
    about: "Check encrypted files completely without writing anything (backup check)",
    after: "Examples:\n  pqkeep check backup.pqkf\n  pqkeep check --key backup.key.json /srv/backup/*.pqkf\n\nChecks all chunks, checksums and archive paths as when decrypting; nothing is written. Exit code 0 = all fine, 3 = wrong key or passphrase or tampering, 1 = other error. Only the header data without a passphrase is shown by pqkeep inspect (no integrity check).",
    arg_sources: "Encrypted file(s) (.pqkf)",
    ok: "OK",
    failed: "ERROR",
    summary: "Checked: {n}, fine: {ok}, failed: {bad}",
};

fn check_texts(lang: Lang) -> &'static CheckTexts {
    match lang {
        Lang::De => &DE,
        Lang::En => &EN,
    }
}

/// DE: Argumente von `check`. EN: Arguments of `check`.
pub fn command(lang: Lang) -> Command {
    let t = super::text::texts(lang);
    let c = check_texts(lang);
    base("check", c.about, c.after, lang)
        .arg(path("source", c.arg_sources).num_args(1..=MAX_SOURCES))
        .arg(
            opt("key", t.arg_key)
                .short('k')
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(flag("passphrase-stdin", t.arg_passphrase_stdin))
        .arg(super::factor_cmd::arg(lang))
}

/// DE: Lesefreigaben für die Sandbox: vorhandene Quellen und der Schlüssel. Fehlende Quellen
/// (auch tote Links) meldet `run` je Datei, statt alles abzubrechen.
/// EN: Read permissions for the sandbox: existing sources and the key. Missing sources (also
/// dangling links) are reported per file by `run` instead of aborting everything.
pub fn read_paths(m: &ArgMatches) -> Vec<PathBuf> {
    let mut all: Vec<PathBuf> = super::files_cmd::sources(m)
        .into_iter()
        .filter(|p| p.exists())
        .collect();
    all.extend(m.get_one::<PathBuf>("key").cloned());
    all
}

/// DE: Zugang je Datei aus dem Header; nicht lesbare Header sind Fehler dieser Datei.
/// EN: Access per file from the header; unreadable headers are errors of that file.
fn accesses(sources: &[PathBuf], lang: Lang) -> Vec<Result<Access, Failure>> {
    sources
        .iter()
        .map(|s| Access::read(s).map_err(|e| Failure::from_error(&e, lang)))
        .collect()
}

/// DE: Alle lesbaren Dateien brauchen dieselbe Art (Schlüssel oder Passphrase).
/// EN: All readable files need the same kind (key or passphrase).
fn use_key(all: &[Result<Access, Failure>], key_given: bool, lang: Lang) -> CliResult<bool> {
    let mut kinds = all.iter().flatten().map(|a| a.use_key(key_given));
    let first = kinds.next().unwrap_or(key_given);
    if kinds.any(|k| k != first) {
        let s = super::many_text::many_texts(lang);
        return Err(Failure::new(code::USAGE, s.mixed));
    }
    Ok(first)
}

fn print_line(t: &Texts, c: &CheckTexts, src: &Path, result: &Result<files::Report, Failure>) {
    match result {
        Ok(r) => println!(
            "{}: {} ({}: {} / {} / {})",
            c.ok,
            src.display(),
            t.msg_summary,
            r.files,
            r.directories,
            r.bytes
        ),
        Err(f) => eprintln!("{}: {}: {}", c.failed, src.display(), f.message),
    }
}

/// DE: `pqkeep check`. EN: `pqkeep check`.
pub fn run(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    let c = check_texts(lang);
    let sources = super::files_cmd::sources(m);
    let found = accesses(&sources, lang);
    let key_given = m.get_one::<PathBuf>("key").is_some();
    // DE: Bei nur einer Datei passende Meldung zur Faktordatei vor der Passphrase-Abfrage.
    // EN: With a single file a matching factor-file message before the passphrase prompt.
    let factor_needed = match found.as_slice() {
        [Ok(access)] => access.passphrase,
        [Err(f)] => return Err(Failure::new(f.code, f.message.clone())),
        _ => None,
    };
    let key = use_key(&found, key_given, lang)?;
    // DE: Ist kein Header lesbar, nichts abfragen – nur die Fehler je Datei melden.
    // EN: If no header is readable, ask for nothing – just report the per-file errors.
    let opened = if found.iter().any(Result::is_ok) {
        Some(super::unlock::for_decrypt(t, lang, m, key, factor_needed)?)
    } else {
        None
    };
    let (mut ok, mut first_error) = (0, None);
    for (src, access) in sources.iter().zip(found) {
        let result = access.and_then(|_| {
            let unlock = opened
                .as_ref()
                .ok_or_else(|| Failure::new(code::ERROR, ""))?;
            files::check(src, &unlock.get()).map_err(|e| Failure::from_error(&e, lang))
        });
        print_line(t, c, src, &result);
        match result {
            Ok(_) => ok += 1,
            Err(f) => {
                first_error.get_or_insert(f.code);
            }
        }
    }
    drop(opened);
    let n = sources.len();
    let summary = c
        .summary
        .replace("{n}", &n.to_string())
        .replace("{ok}", &ok.to_string())
        .replace("{bad}", &(n - ok).to_string());
    println!("{summary}");
    first_error.map_or(Ok(()), |code| Err(Failure::new(code, "")))
}

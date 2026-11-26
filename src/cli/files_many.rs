//! DE: `encrypt`/`decrypt` mit mehreren Quellen (Mehrfachauswahl): Passphrase bzw. Schlüssel nur
//! einmal, alles in **einem** Prozess mit voller Sandbox. „Einzeln“: Fehler einer Datei halten die
//! übrigen nicht auf; am Ende eine Zeile je Datei und eine Zusammenfassung, Exit-Code ≠ 0 bei
//! einem Fehler. „Container“: alles oder nichts.
//! EN: `encrypt`/`decrypt` with several sources (multi-selection): passphrase or key only once,
//! everything in **one** process with the full sandbox. "Separately": a failing file does not stop
//! the others; at the end one line per file and a summary, exit code ≠ 0 on any error.
//! "Container": all or nothing.

use std::path::{Path, PathBuf};

use clap::ArgMatches;
use pqkeep::files::{self, Report};
use pqkeep::security::Lang;

use super::files_cmd::{
    default_decrypted, default_encrypted, default_for, print_report, read_protection,
};
use super::io::{CliResult, Failure, code};
use super::many_text::{ManyTexts, many_texts};
use super::text::Texts;

/// DE: Ergebnis eines Schritts mit Verb für die Ausgabe. EN: Result of one step with its verb.
type Step<'a> = pqkeep::Result<(&'a str, Report)>;

/// DE: Zählt Erfolge und merkt sich den ersten Fehlercode. EN: Counts successes, keeps the first error code.
struct Tally<'a> {
    s: &'a ManyTexts,
    ok: usize,
    total: usize,
    first_error: Option<u8>,
    /// DE: Anzahl Quellen; `Some` = Fortschrittszeilen fürs Kontextmenü (`--progress`).
    /// EN: Number of sources; `Some` = progress lines for the context menu (`--progress`).
    progress: Option<usize>,
}

impl<'a> Tally<'a> {
    fn new(s: &'a ManyTexts, m: &ArgMatches, count: usize) -> Self {
        Self {
            s,
            ok: 0,
            total: 0,
            first_error: None,
            progress: m.get_flag("progress").then_some(count),
        }
    }

    /// DE: Vor jeder Datei: `@@progress <nr> <anzahl>` (ohne Pfade). EN: Before each file.
    fn begin(&self) {
        use std::io::Write;
        if let Some(n) = self.progress {
            println!("@@progress {} {n}", self.total + 1);
            let _ = std::io::stdout().flush();
        }
    }

    fn record(&mut self, t: &Texts, lang: Lang, src: &Path, out: &Path, r: Step) {
        self.total += 1;
        match r {
            Ok((verb, report)) => {
                self.ok += 1;
                print_report(t, lang, verb, out, &report);
                if self.progress.is_some()
                    && let Some(name) = out.file_name()
                {
                    println!("@@done {}", super::files_cmd::shown(Path::new(name)));
                }
            }
            Err(e) => {
                let f = Failure::from_error(&e, lang);
                eprintln!("{}: {}: {}", self.s.failed, src.display(), f.message);
                self.first_error.get_or_insert(f.code);
            }
        }
    }

    fn missing_target(&mut self, src: &Path) {
        self.total += 1;
        eprintln!("{}: {}", self.s.failed, src.display());
        self.first_error.get_or_insert(code::EXISTS);
    }

    fn finish(self) -> CliResult {
        println!("{}: {} / {}", self.s.summary, self.ok, self.total);
        self.first_error
            .map_or(Ok(()), |c| Err(Failure::new(c, "")))
    }
}

/// DE: Mehrere Quellen verschlüsseln. EN: Encrypt several sources.
pub fn encrypt(t: &Texts, lang: Lang, m: &ArgMatches, sources: &[PathBuf]) -> CliResult {
    let s = many_texts(lang);
    if !m.get_flag("each") {
        let out = m
            .get_one::<PathBuf>("out")
            .ok_or_else(|| Failure::new(code::USAGE, s.need_out))?;
        let protection = read_protection(t, lang, m)?;
        let list: Vec<&Path> = sources.iter().map(PathBuf::as_path).collect();
        let fail = |e: pqkeep::Error| Failure::from_error(&e, lang);
        let (out, report) = if super::privacy::random(m) {
            super::privacy::encrypt_container(&protection, &list, out).map_err(fail)?
        } else {
            (
                out.clone(),
                protection.encrypt_many(&list, out).map_err(fail)?,
            )
        };
        print_report(t, lang, t.msg_encrypted, &out, &report);
        return Ok(());
    }
    super::privacy::check_out(m, false, lang)?;
    let protection = read_protection(t, lang, m)?;
    let mut tally = Tally::new(s, m, sources.len());
    for src in sources {
        tally.begin();
        if super::privacy::random(m) {
            let (out, r) = super::privacy::encrypt_random(&protection, src, None);
            let out = out.unwrap_or_else(|| src.clone());
            tally.record(t, lang, src, &out, r.map(|r| (t.msg_encrypted, r)));
            continue;
        }
        let Some(out) = default_for(m, default_encrypted(src)) else {
            tally.missing_target(src);
            continue;
        };
        let r = protection.encrypt(src, &out).map(|r| (t.msg_encrypted, r));
        tally.record(t, lang, src, &out, r);
    }
    tally.finish()
}

/// DE: Mehrere `.pqkf`: alle gleich geschützt? Dann Passphrase bzw. Schlüssel einmal einlesen.
/// EN: Several `.pqkf`: all protected alike? Then read the passphrase or key once.
pub(super) fn open_many(
    t: &Texts,
    lang: Lang,
    m: &ArgMatches,
    sources: &[PathBuf],
) -> CliResult<super::unlock::Opened> {
    let s = many_texts(lang);
    if m.get_one::<PathBuf>("out").is_some() {
        return Err(Failure::new(code::USAGE, s.no_out));
    }
    let key_given = m.get_one::<PathBuf>("key").is_some();
    let mut use_key = None;
    for src in sources {
        let wanted = super::unlock::Access::read(src)
            .map_err(|e| Failure::from_error(&e, lang))?
            .use_key(key_given);
        if *use_key.get_or_insert(wanted) != wanted {
            return Err(Failure::new(code::USAGE, s.mixed));
        }
    }
    super::unlock::for_decrypt(t, lang, m, use_key == Some(true), None)
}

/// DE: Wie [`open_many`], dazu der verlangte Absender (`--signer`, vor der Abfrage geladen).
/// EN: Like [`open_many`], plus the required sender (`--signer`, loaded before the prompt).
pub(super) fn open_many_signed(
    t: &Texts,
    lang: Lang,
    m: &ArgMatches,
    sources: &[PathBuf],
) -> CliResult<(
    super::unlock::Opened,
    Option<pqkeep::envelope::PublicKeyFile>,
)> {
    let expected = super::signing::load_expected(lang, m)?;
    Ok((open_many(t, lang, m, sources)?, expected))
}

/// DE: Mehrere `.pqkf` mit derselben Passphrase bzw. demselben Schlüssel entschlüsseln.
/// EN: Decrypt several `.pqkf` with the same passphrase or the same key.
pub fn decrypt(t: &Texts, lang: Lang, m: &ArgMatches, sources: &[PathBuf]) -> CliResult {
    let (opened, expected) = open_many_signed(t, lang, m, sources)?;
    let unlock = opened.get();
    let mut tally = Tally::new(many_texts(lang), m, sources.len());
    for src in sources {
        tally.begin();
        if super::privacy::restore(m, src) {
            let (out, r) = super::privacy::decrypt_original(m, src, &unlock, expected.as_ref());
            let out = out.unwrap_or_else(|| src.clone());
            tally.record(t, lang, src, &out, r.map(|r| (t.msg_decrypted, r)));
            continue;
        }
        let Some(out) = default_for(m, default_decrypted(src)) else {
            tally.missing_target(src);
            continue;
        };
        let r = files::decrypt_with(src, &out, &unlock, expected.as_ref())
            .map(|r| (t.msg_decrypted, r));
        tally.record(t, lang, src, &out, r);
    }
    tally.finish()
}

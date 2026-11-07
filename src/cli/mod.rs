//! DE: Kommandozeile `keyforge`. Nutzt ausschließlich die Core-API der Bibliothek.
//! Beim Start: Prozesshärtung, Warnung bei root, Sprache aus `--lang` bzw. System.
//! EN: Command line `keyforge`. Uses the library's core API only.
//! On start: process hardening, warning when root, language from `--lang` or system.

mod args;
mod io;
mod keys;
mod text;
mod text_de;
mod text_en;
mod validate;

use std::process::ExitCode;

use pqc_keyforge::hardening::{self, memlock};

use self::io::{Failure, code, finish};
use self::text::{Texts, texts};

/// DE: Einstiegspunkt der CLI. EN: CLI entry point.
pub fn run() -> ExitCode {
    let report = hardening::harden_process();
    let argv: Vec<String> = std::env::args().collect();
    let lang = args::detect_lang(&argv);
    let t = texts(lang);
    warn_if_root(t);
    let matches = match args::build(lang).try_get_matches_from(&argv) {
        Ok(m) => m,
        Err(e) => {
            let _ = e.print();
            return ExitCode::from(if e.use_stderr() {
                code::USAGE
            } else {
                code::OK
            });
        }
    };
    if matches.get_flag("verbose") {
        let lock = memlock::stats();
        eprintln!(
            "{}: core_dumps_disabled={} not_dumpable={} locked_pages={} failed_locks={}",
            t.msg_hardening,
            report.core_dumps_disabled,
            report.not_dumpable,
            lock.locked_pages,
            lock.failed_attempts
        );
    }
    let result = match matches.subcommand() {
        Some(("generate", m)) => keys::generate(t, lang, m),
        Some(("export", m)) => keys::export(t, lang, m),
        Some(("inspect", m)) => keys::inspect(t, lang, m),
        Some(("validate", m)) => validate::validate(t, lang, m),
        Some(("passphrase", m)) => validate::passphrase(t, lang, m),
        _ => Err(Failure::new(code::USAGE, "?")),
    };
    finish(result, t)
}

#[cfg(target_os = "linux")]
fn warn_if_root(t: &Texts) {
    if rustix::process::geteuid().is_root() {
        eprintln!("{}", t.msg_root_warning);
    }
}

#[cfg(not(target_os = "linux"))]
fn warn_if_root(t: &Texts) {
    // DE: Windows: Admin-Erkennung bräuchte eine unsafe-API; dokumentierte Lücke.
    // EN: Windows: admin detection would need an unsafe API; documented gap.
    let _ = t.msg_root_warning;
}

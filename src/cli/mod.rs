//! DE: Kommandozeile `keyforge`. Nutzt ausschließlich die Core-API der Bibliothek.
//! Beim Start: Prozesshärtung, Warnung bei root, Sprache aus `--lang` bzw. System.
//! Ohne Argumente im Terminal: interaktives Menü.
//! EN: Command line `keyforge`. Uses the library's core API only.
//! On start: process hardening, warning when root, language from `--lang` or system.
//! Without arguments in a terminal: interactive menu.

mod args;
mod files_cmd;
mod help;
mod io;
mod keys;
mod menu;
#[cfg(feature = "api")]
mod serve;
#[cfg(feature = "api")]
mod serve_text;
mod text;
mod text_de;
mod text_en;
mod topics_de;
mod topics_en;
mod validate;

use std::io::IsTerminal;
use std::process::ExitCode;

use pqc_keyforge::hardening::{self, HardeningReport, memlock};
use pqc_keyforge::security::Lang;

use self::io::{CliResult, Failure, code, finish};
use self::text::{Texts, texts};

/// DE: Einstiegspunkt der CLI. EN: CLI entry point.
pub fn run() -> ExitCode {
    let report = hardening::harden_process();
    let argv: Vec<String> = std::env::args().collect();
    let lang = args::detect_lang(&argv);
    let t = texts(lang);
    warn_if_root(t);
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let result = if argv.len() <= 1 && interactive {
        menu::run(t, lang, |a| execute(&a, lang, report))
    } else {
        execute(&argv, lang, report)
    };
    finish(result, t)
}

/// DE: Parst und führt einen Befehl aus. EN: Parses and runs a command.
fn execute(argv: &[String], lang: Lang, report: HardeningReport) -> CliResult {
    let t = texts(lang);
    let matches = match args::build(lang).try_get_matches_from(argv) {
        Ok(m) => m,
        Err(e) => {
            if e.use_stderr() {
                eprintln!("{}", t.msg_usage_error);
                let _ = e.print();
                return Err(Failure::new(code::USAGE, ""));
            }
            let _ = e.print();
            return Ok(());
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
    match matches.subcommand() {
        Some(("generate", m)) => keys::generate(t, lang, m),
        Some(("export", m)) => keys::export(t, lang, m),
        Some(("inspect", m)) => keys::inspect(t, lang, m),
        Some(("validate", m)) => validate::validate(t, lang, m),
        Some(("passphrase", m)) => validate::passphrase(t, lang, m),
        Some(("encrypt", m)) => files_cmd::encrypt(t, lang, m),
        Some(("decrypt", m)) => files_cmd::decrypt(t, lang, m),
        Some(("help", m)) => help::help(t, lang, m),
        Some(("completions", m)) => {
            help::completions(lang, m);
            Ok(())
        }
        Some(("man", _)) => help::man(lang),
        #[cfg(feature = "api")]
        Some(("serve", m)) => serve::serve(lang, m),
        _ => Err(Failure::new(code::USAGE, "")),
    }
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

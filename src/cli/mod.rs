//! DE: Kommandozeile `pqkeep`. Nutzt ausschließlich die Core-API der Bibliothek.
//! Beim Start: Prozesshärtung, Warnung bei root, Sprache aus `--lang` bzw. System.
//! Ohne Argumente im Terminal: interaktives Menü.
//! EN: Command line `pqkeep`. Uses the library's core API only.
//! On start: process hardening, warning when root, language from `--lang` or system.
//! Without arguments in a terminal: interactive menu.

mod access;
mod args;
mod context;
mod files_cmd;
mod help;
mod integrate;
mod integrate_text;
mod io;
mod keys;
mod menu;
mod sandbox;
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

use pqkeep::hardening::sandbox::Profile;
use pqkeep::hardening::{self, HardeningReport, memlock};
use pqkeep::security::Lang;

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
        menu::run(t, lang, |a| run_child(&a, lang))
    } else {
        execute(&argv, lang, report)
    };
    finish(result, t)
}

/// DE: Menüaktion als eigener Prozess mit voller Sandbox (Landlock lässt sich nicht
/// lockern; der Menü-Prozess selbst verarbeitet keine Passphrasen oder Schlüssel).
/// Fehlermeldungen gibt der Kindprozess selbst aus.
/// EN: Menu action as its own process with the full sandbox (Landlock cannot be
/// relaxed; the menu process itself handles no passphrases or keys). The child
/// prints its own error messages.
fn run_child(argv: &[String], lang: Lang) -> CliResult {
    let fail = |e: std::io::Error| Failure::from_error(&e.into(), lang);
    let exe = std::env::current_exe().map_err(fail)?;
    let status = std::process::Command::new(exe)
        .args(argv.iter().skip(1))
        .status()
        .map_err(fail)?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure::new(code::ERROR, ""))
    }
}

fn print_hardening(t: &Texts, report: HardeningReport) {
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
    let sandboxed = !matches.get_flag("no-sandbox");
    if !sandboxed {
        sandbox::confirm_disabled(lang)?;
    }
    let verbose = matches.get_flag("verbose");
    if verbose {
        print_hardening(t, report);
    }
    // DE: Sandbox nach dem Parsen, vor jeder Eingabe und jedem Dateizugriff.
    // EN: Sandbox after parsing, before any input and any file access.
    if let Some((name, m)) = matches.subcommand()
        && let Some(access) = access::for_command(name, m, lang)?
    {
        sandbox::enable(&Profile::Cli(access), sandboxed, verbose, lang)?;
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
        Some(("integrate", m)) => integrate::run(lang, m, sandboxed, verbose),
        Some(("context", m)) => context::run(t, lang, m),
        #[cfg(feature = "api")]
        Some(("serve", m)) => serve::serve(lang, m, sandboxed),
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

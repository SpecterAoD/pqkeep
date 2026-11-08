//! DE: `pqkeep integrate install|uninstall|status`: Kontextmenü im Dateimanager (Linux: Nemo,
//! Nautilus, Dolphin) nur für den aktuellen Benutzer. Fehlende Zielordner werden vorab angelegt,
//! danach läuft der Befehl in der Sandbox und darf nur in diese Ordner schreiben.
//! EN: `pqkeep integrate install|uninstall|status`: file manager context menu (Linux: Nemo,
//! Nautilus, Dolphin) for the current user only. Missing target folders are created up front, then
//! the command runs in the sandbox and may only write to those folders.

#[cfg(target_os = "linux")]
mod discover;
#[cfg(target_os = "linux")]
mod entries;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod manifest;
mod platform;

use clap::{Arg, ArgAction, ArgMatches, Command};
use pqkeep::security::Lang;

use super::integrate_text::integrate_texts;
use super::io::CliResult;

/// DE: Argumente von `integrate`. EN: Arguments of `integrate`.
pub fn command(base: Command, lang: Lang) -> Command {
    let s = integrate_texts(lang);
    base.arg(
        Arg::new("action")
            .help(s.arg_action)
            .required(true)
            .hide_possible_values(true)
            .value_parser(["install", "uninstall", "status"]),
    )
    .arg(
        Arg::new("all")
            .long("all")
            .help(s.arg_all)
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("dry-run")
            .long("dry-run")
            .help(s.arg_dry_run)
            .action(ArgAction::SetTrue),
    )
}

/// DE: Optionen eines Aufrufs. EN: Options of one call.
// DE: Vier unabhängige Schalter aus der Kommandozeile; eine Zustandsmaschine wäre hier künstlich.
// EN: Four independent command line switches; a state machine would be artificial here.
#[allow(clippy::struct_excessive_bools)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct Options {
    pub all: bool,
    pub dry_run: bool,
    pub sandboxed: bool,
    pub verbose: bool,
}

/// DE: `pqkeep integrate`. EN: `pqkeep integrate`.
pub fn run(lang: Lang, m: &ArgMatches, sandboxed: bool, verbose: bool) -> CliResult {
    let opts = Options {
        all: m.get_flag("all"),
        dry_run: m.get_flag("dry-run"),
        sandboxed,
        verbose,
    };
    let action = m
        .get_one::<String>("action")
        .map_or("status", String::as_str);
    platform::run(action, &opts, lang)
}

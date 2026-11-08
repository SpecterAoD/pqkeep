//! DE: Aufbau der Kommandozeile (clap-Builder), damit alle Hilfetexte zur Laufzeit
//! in der gewählten Sprache erscheinen – inklusive Überschriften (eigenes Template),
//! Hilfe-/Versionsoption und ohne englische „[default: …]“-Zusätze (Standardwerte
//! stehen im Hilfetext). Eine Passphrase ist nie ein Argument.
//!
//! EN: Command line definition (clap builder) so that all help texts appear in the
//! chosen language at runtime – including headings (own template), help/version
//! flags and without English "[default: …]" suffixes (defaults are in the help
//! text). A passphrase is never an argument.

use std::path::PathBuf;

use clap::{Arg, ArgAction, Command, value_parser};
use pqkeep::security::Lang;

use super::text::{exit_codes, texts};

/// DE: Algorithmus-Namen auf der Kommandozeile. EN: Algorithm names on the command line.
pub const ALGORITHMS: [&str; 7] = [
    "ml-kem-512",
    "ml-kem-768",
    "ml-kem-1024",
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    "aes-256",
];

/// DE: Hilfethemen. EN: Help topics.
pub const TOPICS: [&str; 6] = [
    "passphrase",
    "algorithms",
    "container",
    "files",
    "security",
    "verify",
];

/// DE: Shells für Completions. EN: Shells for completions.
pub const SHELLS: [&str; 4] = ["bash", "zsh", "fish", "powershell"];

fn after(lang: Lang, text: &str) -> String {
    format!("{text}\n\n{}", exit_codes(lang))
}

fn flag(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .help(help)
        .action(ArgAction::SetTrue)
}

fn opt(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .help(help)
        .hide_default_value(true)
        .hide_possible_values(true)
}

fn path(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .help(help)
        .required(true)
        .value_parser(value_parser!(PathBuf))
}

/// DE: Gemeinsame Grundlage jedes Befehls: Sprache der Überschriften, eigene Hilfeoption.
/// EN: Common base of every command: heading language, own help flag.
fn base(name: &'static str, about: &'static str, after_text: &str, lang: Lang) -> Command {
    let t = texts(lang);
    Command::new(name)
        .about(about)
        .after_help(after(lang, after_text))
        .help_template(format!(
            "{{about-with-newline}}\n{} {{usage}}\n\n{{all-args}}{{after-help}}",
            t.heading_usage
        ))
        .next_help_heading(t.heading_options)
        .disable_help_flag(true)
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .help(t.flag_help)
                .action(ArgAction::Help),
        )
}

/// DE: Optionales Ziel ohne Überschreiben (Dateiverschlüsselung überschreibt nie).
/// EN: Optional target without overwriting (file encryption never overwrites).
fn out_optional(lang: Lang) -> Arg {
    opt("out", texts(lang).arg_out_optional)
        .short('o')
        .value_parser(value_parser!(PathBuf))
}

fn out_args(lang: Lang, required: bool) -> [Arg; 3] {
    let t = texts(lang);
    [
        opt("out", t.arg_out)
            .short('o')
            .required(required)
            .value_parser(value_parser!(PathBuf)),
        flag("force", t.arg_force),
        flag("yes", t.arg_yes).requires("force"),
    ]
}

fn profile(lang: Lang) -> Arg {
    opt("profile", texts(lang).arg_profile)
        .default_value("standard")
        .value_parser(["standard", "hardened"])
}

fn generate(lang: Lang) -> Command {
    let t = texts(lang);
    base("generate", t.gen_about, t.gen_after, lang)
        .arg(
            opt("algorithm", t.arg_algorithm)
                .short('a')
                .default_value("ml-kem-768")
                .value_parser(ALGORITHMS),
        )
        .arg(opt("name", t.arg_name).short('n').required(true))
        .arg(opt("organization", t.arg_org))
        .arg(opt("company", t.arg_company))
        .arg(opt("department", t.arg_department))
        .arg(opt("account-type", t.arg_account_type))
        .arg(profile(lang))
        .args(out_args(lang, true))
        .arg(flag("passphrase-stdin", t.arg_passphrase_stdin))
}

/// DE: Höchstzahl an Quellen je Aufruf. EN: Maximum number of sources per call.
pub const MAX_SOURCES: usize = 1000;

fn file_commands(lang: Lang) -> [Command; 2] {
    let t = texts(lang);
    let m = super::many_text::many_texts(lang);
    [
        base("encrypt", t.enc_about, t.enc_after, lang)
            .arg(path("source", m.arg_sources).num_args(1..=MAX_SOURCES))
            .arg(flag("each", m.arg_each).conflicts_with("out"))
            .arg(flag("rename", m.arg_rename))
            .arg(opt("temp-tag", "").hide(true))
            .arg(flag("progress", "").hide(true))
            .arg(opt("to", t.arg_to).value_parser(value_parser!(PathBuf)))
            .arg(profile(lang))
            .arg(out_optional(lang))
            .arg(flag("passphrase-stdin", t.arg_passphrase_stdin))
            // DE: Intern fürs Kontextmenü: zwei Zeilen lesen und vergleichen.
            // EN: Internal for the context menu: read and compare two lines.
            .arg(
                flag("confirm-stdin", "")
                    .hide(true)
                    .requires("passphrase-stdin"),
            ),
        base("decrypt", t.dec_about, t.dec_after, lang)
            .arg(path("source", m.arg_encrypted).num_args(1..=MAX_SOURCES))
            .arg(flag("rename", m.arg_rename))
            .arg(opt("temp-tag", "").hide(true))
            .arg(flag("progress", "").hide(true))
            .arg(
                opt("key", t.arg_key)
                    .short('k')
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(out_optional(lang))
            .arg(flag("passphrase-stdin", t.arg_passphrase_stdin)),
    ]
}

fn help_commands(lang: Lang) -> [Command; 3] {
    let t = texts(lang);
    [
        base("help", t.help_about, t.help_after, lang).arg(
            Arg::new("topic")
                .help(t.arg_topic)
                .hide_possible_values(true)
                .value_parser(TOPICS),
        ),
        base("completions", t.compl_about, t.compl_after, lang).arg(
            Arg::new("shell")
                .help(t.arg_shell)
                .required(true)
                .hide_possible_values(true)
                .value_parser(SHELLS),
        ),
        base("man", t.man_about, t.man_after, lang),
    ]
}

/// DE: Vollständige Kommandozeile in der Sprache `lang`. EN: Full command line in language `lang`.
pub fn build(lang: Lang) -> Command {
    let t = texts(lang);
    let cmd = base("pqkeep", t.app_about, t.app_after, lang)
        .version(pqkeep::VERSION)
        .disable_version_flag(true)
        .disable_help_subcommand(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("version")
                .short('V')
                .long("version")
                .help(t.flag_version)
                .action(ArgAction::Version),
        )
        .arg(
            opt("lang", t.arg_lang)
                .global(true)
                .value_parser(["de", "en"]),
        )
        .args(global_args(lang))
        .subcommand(generate(lang))
        .subcommand(
            base("validate", t.validate_about, t.validate_after, lang)
                .arg(flag("passphrase-stdin", t.arg_passphrase_stdin)),
        )
        .subcommand(
            base("passphrase", t.pass_about, t.pass_after, lang)
                .arg(
                    opt("length", t.arg_length)
                        .short('l')
                        .default_value("24")
                        .value_parser(value_parser!(usize)),
                )
                .arg(flag("no-ambiguous", t.arg_no_ambiguous)),
        )
        .subcommand(
            base("inspect", t.inspect_about, t.inspect_after, lang).arg(path("file", t.arg_file)),
        )
        .subcommand(
            base("export", t.export_about, t.export_after, lang)
                .arg(path("file", t.arg_keyfile))
                .args(out_args(lang, true)),
        )
        .subcommands(file_commands(lang))
        .subcommands(help_commands(lang));
    with_integration(with_serve(cmd, lang), lang)
}

/// DE: Globale Schalter (gelten für alle Befehle). EN: Global switches (apply to all commands).
fn global_args(lang: Lang) -> [Arg; 4] {
    let t = texts(lang);
    [
        flag("verbose", t.arg_verbose).short('v').global(true),
        flag("no-sandbox", super::sandbox::arg_help(lang)).global(true),
        flag("batch", t.arg_batch).global(true),
        opt("passphrase-file", t.arg_passphrase_file)
            .global(true)
            .value_parser(value_parser!(PathBuf)),
    ]
}

/// DE: Kontextmenü-Befehle `integrate` und `context`. EN: Context menu commands.
fn with_integration(cmd: Command, lang: Lang) -> Command {
    let s = super::integrate_text::integrate_texts(lang);
    cmd.subcommand(super::integrate::command(
        base("integrate", s.about, s.after, lang),
        lang,
    ))
    .subcommand(super::context::command(
        base("context", s.ctx_about, s.ctx_after, lang),
        lang,
    ))
}

/// DE: Hängt `serve` an (nur mit Feature `api`). EN: Appends `serve` (feature `api` only).
#[cfg(feature = "api")]
fn with_serve(cmd: Command, lang: Lang) -> Command {
    let s = super::serve_text::serve_texts(lang);
    cmd.subcommand(super::serve::command(
        base("serve", s.about, s.after, lang),
        lang,
    ))
}

#[cfg(not(feature = "api"))]
fn with_serve(cmd: Command, _lang: Lang) -> Command {
    cmd
}

/// DE: Sprache aus `--lang` (vor dem eigentlichen Parsen) oder dem System.
/// EN: Language from `--lang` (before actual parsing) or the system.
pub fn detect_lang(args: &[String]) -> Lang {
    let explicit = args.iter().enumerate().find_map(|(i, a)| {
        a.strip_prefix("--lang=")
            .map(str::to_owned)
            .or_else(|| (a == "--lang").then(|| args.get(i + 1).cloned()).flatten())
    });
    let code = explicit.or_else(sys_locale::get_locale).unwrap_or_default();
    if code.to_ascii_lowercase().starts_with("de") {
        Lang::De
    } else {
        Lang::En
    }
}

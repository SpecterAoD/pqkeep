//! DE: Aufbau der Kommandozeile (clap-Builder), damit alle Hilfetexte zur Laufzeit
//! in der gewählten Sprache erscheinen. Eine Passphrase ist nie ein Argument.
//! EN: Command line definition (clap builder) so that all help texts appear in the
//! chosen language at runtime. A passphrase is never an argument.

use clap::{Arg, ArgAction, Command, value_parser};
use pqc_keyforge::security::Lang;

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
    Arg::new(name).long(name).help(help)
}

fn out_args(lang: Lang) -> [Arg; 3] {
    let t = texts(lang);
    [
        opt("out", t.arg_out)
            .short('o')
            .required(true)
            .value_parser(value_parser!(std::path::PathBuf)),
        flag("force", t.arg_force),
        flag("yes", t.arg_yes).requires("force"),
    ]
}

fn generate(lang: Lang) -> Command {
    let t = texts(lang);
    Command::new("generate")
        .about(t.gen_about)
        .after_help(after(lang, t.gen_after))
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
        .arg(
            opt("profile", t.arg_profile)
                .default_value("standard")
                .value_parser(["standard", "hardened"]),
        )
        .args(out_args(lang))
        .arg(flag("passphrase-stdin", t.arg_passphrase_stdin))
}

fn simple(name: &'static str, about: &'static str, after_text: &str, lang: Lang) -> Command {
    Command::new(name)
        .about(about)
        .after_help(after(lang, after_text))
}

/// DE: Vollständige Kommandozeile in der Sprache `lang`. EN: Full command line in language `lang`.
pub fn build(lang: Lang) -> Command {
    let t = texts(lang);
    let file = |help| {
        Arg::new("file")
            .help(help)
            .required(true)
            .value_parser(value_parser!(std::path::PathBuf))
    };
    Command::new("keyforge")
        .version(pqc_keyforge::VERSION)
        .about(t.app_about)
        .after_help(after(lang, t.app_after))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("lang")
                .long("lang")
                .global(true)
                .help(t.arg_lang)
                .value_parser(["de", "en"]),
        )
        .arg(flag("verbose", t.arg_verbose).short('v').global(true))
        .subcommand(generate(lang))
        .subcommand(
            simple("validate", t.validate_about, t.validate_after, lang)
                .arg(flag("passphrase-stdin", t.arg_passphrase_stdin)),
        )
        .subcommand(
            simple("passphrase", t.pass_about, t.pass_after, lang)
                .arg(
                    opt("length", t.arg_length)
                        .short('l')
                        .default_value("24")
                        .value_parser(value_parser!(usize)),
                )
                .arg(flag("no-ambiguous", t.arg_no_ambiguous)),
        )
        .subcommand(simple("inspect", t.inspect_about, t.inspect_after, lang).arg(file(t.arg_file)))
        .subcommand(
            simple("export", t.export_about, t.export_after, lang)
                .arg(file(t.arg_keyfile))
                .args(out_args(lang)),
        )
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

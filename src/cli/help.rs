//! DE: `pqkeep help [thema]`, `pqkeep completions <shell>`, `pqkeep man`.
//! Alles wird lokal erzeugt, ohne Netzwerkzugriff.
//! EN: `pqkeep help [topic]`, `pqkeep completions <shell>`, `pqkeep man`.
//! Everything is generated locally, without network access.

use clap::ArgMatches;
use clap_complete::Shell;
use pqkeep::security::Lang;

use super::args;
use super::io::{CliResult, Failure, code};
use super::text::Texts;

/// DE: Text eines Hilfethemas. EN: Text of a help topic.
pub fn topic(lang: Lang, name: &str) -> Option<&'static str> {
    let list = match lang {
        Lang::De => super::topics_de::TOPICS,
        Lang::En => super::topics_en::TOPICS,
    };
    list.iter().find(|(n, _)| *n == name).map(|(_, text)| *text)
}

/// DE: `pqkeep help`. EN: `pqkeep help`.
pub fn help(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    if let Some(name) = m.get_one::<String>("topic") {
        let text = topic(lang, name)
            .ok_or_else(|| Failure::new(code::USAGE, format!("{}: {name}", t.msg_unknown_topic)))?;
        println!("{text}");
    } else {
        let mut cmd = args::build(lang);
        cmd.print_long_help()
            .map_err(|e| Failure::new(code::ERROR, e.to_string()))?;
        println!();
    }
    Ok(())
}

/// DE: `pqkeep completions`. EN: `pqkeep completions`.
pub fn completions(lang: Lang, m: &ArgMatches) {
    let shell = match m.get_one::<String>("shell").map(String::as_str) {
        Some("zsh") => Shell::Zsh,
        Some("fish") => Shell::Fish,
        Some("powershell") => Shell::PowerShell,
        _ => Shell::Bash,
    };
    let mut cmd = args::build(lang);
    clap_complete::generate(shell, &mut cmd, "pqkeep", &mut std::io::stdout());
}

/// DE: `pqkeep man` (roff auf Stdout). EN: `pqkeep man` (roff on stdout).
pub fn man(lang: Lang) -> CliResult {
    clap_mangen::Man::new(args::build(lang))
        .render(&mut std::io::stdout())
        .map_err(|e| Failure::new(code::ERROR, e.to_string()))
}

//! DE: Opt-in-Rekey ohne Formatwechsel; Core prüft Sicherung und Veröffentlichung.
//! EN: Opt-in rekey without format change; core validates backup and publication.
use std::path::PathBuf;

use clap::{ArgMatches, Command, value_parser};
use pqkeep::envelope::{Overwrite, RekeyFile, RekeyOptions};
use pqkeep::security::Lang;

use super::args::{base, flag, min_bits, opt, path};
use super::io::{self, CliResult, Failure, code};
use super::{factor_cmd, rekey_input, rekey_text, text::Texts, unattended, unlock};

pub(super) fn command(lang: Lang) -> Command {
    let s = rekey_text::texts(lang);
    let t = super::text::texts(lang);
    base("rekey", s.about, s.after, lang)
        .arg(path("file", t.arg_keyfile))
        .arg(
            opt("out", s.out)
                .short('o')
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(opt("backup", s.backup).value_parser(value_parser!(PathBuf)))
        .arg(flag("force", t.arg_force))
        .arg(flag("yes", t.arg_yes).requires("force"))
        .arg(flag("passphrase-stdin", s.stdin))
        .arg(min_bits(lang))
        .arg(factor_cmd::arg(lang))
}

// DE: Vor Sandbox-Pfadzugriffen ablehnen, auch wenn die globale Datei fehlt.
// EN: Reject before sandbox path access, even if the global file does not exist.
pub(super) fn check_input(lang: Lang) -> CliResult {
    if unattended::pass_file().is_some() {
        return Err(Failure::new(code::USAGE, rekey_text::texts(lang).pass_file));
    }
    Ok(())
}

pub(super) fn run(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    check_input(lang)?;
    let fail = |e| Failure::from_error(&e, lang);
    let source = m.get_one::<PathBuf>("file").cloned().unwrap_or_default();
    let out = m.get_one::<PathBuf>("out").cloned().unwrap_or_default();
    let loaded = RekeyFile::open(&source).map_err(fail)?;
    let mut options = RekeyOptions::new(&out);
    options.backup = m.get_one::<PathBuf>("backup").map(PathBuf::as_path);
    if m.get_flag("force") {
        options.overwrite = Overwrite::Yes;
    }
    loaded.check(&options).map_err(fail)?;
    unlock::check_factor(
        loaded.key().needs_factor(),
        factor_cmd::path(m).is_some(),
        lang,
    )?;
    let factor = factor_cmd::load(m, lang)?;
    for warning in loaded.warnings() {
        eprintln!("{}", warning.message(lang));
    }
    if options.overwrite == Overwrite::Yes
        && out.exists()
        && !io::allow_overwrite(t, lang, &out, true, m.get_flag("yes"))?
    {
        return Err(Failure::new(code::EXISTS, t.msg_aborted));
    }
    let (old, new) = rekey_input::read(t, lang, m)?;
    loaded
        .write(&options, &old, &new, factor.as_ref())
        .map_err(fail)?;
    let s = rekey_text::texts(lang);
    println!("{}: {}", s.changed, out.display());
    eprintln!("{}", s.hint);
    Ok(())
}

pub(super) fn message(field: &str) -> Option<&'static str> {
    Some(match field {
        "rekey_backup" => {
            "Austausch erfordert eine neue separate Sicherung (--backup) / replacement requires a new separate backup (--backup)"
        }
        "rekey_file" => {
            "Rekey benötigt eine begrenzte reguläre Datei ohne Verknüpfung; Austausch ohne weitere Hardlinks / rekey requires a bounded regular file without links; replacement without additional hard links"
        }
        "rekey_changed" => {
            "Quelldatei hat sich geändert; keine weitere Veröffentlichung / source file changed; no further publication"
        }
        "kdf_downgrade" => {
            "KDF-Parameter dürfen nicht abgesenkt werden / KDF parameters must not be reduced"
        }
        _ => return None,
    })
}

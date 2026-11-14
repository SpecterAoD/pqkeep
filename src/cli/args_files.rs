//! DE: Argumente der Datei-Befehle `encrypt` und `decrypt` (eine oder mehrere Quellen).
//! EN: Arguments of the file commands `encrypt` and `decrypt` (one or more sources).

use clap::{ArgAction, Command, value_parser};
use pqkeep::security::Lang;
use std::path::PathBuf;

use super::args::{base, flag, opt, out_optional, path, profile};
use super::recipients;
use super::text::texts;

/// DE: Höchstzahl an Quellen je Aufruf. EN: Maximum number of sources per call.
pub const MAX_SOURCES: usize = 1000;

pub(super) fn file_commands(lang: Lang) -> [Command; 2] {
    let t = texts(lang);
    let m = super::many_text::many_texts(lang);
    [
        base("encrypt", t.enc_about, t.enc_after, lang)
            .arg(path("source", m.arg_sources).num_args(1..=MAX_SOURCES))
            .arg(flag("each", m.arg_each).conflicts_with("out"))
            .arg(flag("rename", m.arg_rename))
            .arg(opt("temp-tag", "").hide(true))
            .arg(flag("progress", "").hide(true))
            // DE: Mehrfach möglich (#47); Anzahl, Typ und Doppel prüft `recipients.rs`.
            // EN: May be repeated (#47); count, kind and duplicates are checked in `recipients.rs`.
            .arg(
                opt("to", t.arg_to)
                    .value_parser(value_parser!(PathBuf))
                    .action(ArgAction::Append),
            )
            .arg(flag(recipients::WITH_PASSPHRASE, recipients::help(lang)).requires("to"))
            .arg(profile(lang))
            .arg(out_optional(lang))
            .arg(super::args::min_bits(lang))
            .arg(flag("passphrase-stdin", t.arg_passphrase_stdin))
            // DE: Die Faktordatei ergänzt die Passphrase, nicht den Empfängerschlüssel; mit `--to`
            //     nur zusammen mit `--with-passphrase` (Prüfung vor der Passphrase-Abfrage).
            // EN: The factor file complements the passphrase, not the recipient key; with `--to`
            //     only together with `--with-passphrase` (checked before the passphrase prompt).
            .arg(super::factor_cmd::arg(lang))
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
            .arg(flag("passphrase-stdin", t.arg_passphrase_stdin))
            .arg(super::factor_cmd::arg(lang)),
    ]
}

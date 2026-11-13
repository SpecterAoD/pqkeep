//! DE: Argumente der Datei-Befehle `encrypt` und `decrypt` (eine oder mehrere Quellen).
//! EN: Arguments of the file commands `encrypt` and `decrypt` (one or more sources).

use clap::{Command, value_parser};
use pqkeep::security::Lang;
use std::path::PathBuf;

use super::args::{base, flag, opt, out_optional, path, profile};
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
            .arg(opt("to", t.arg_to).value_parser(value_parser!(PathBuf)))
            .arg(profile(lang))
            .arg(out_optional(lang))
            .arg(super::args::min_bits(lang))
            .arg(flag("passphrase-stdin", t.arg_passphrase_stdin))
            // DE: Die Faktordatei ergänzt die Passphrase, nicht den Empfängerschlüssel.
            // EN: The factor file complements the passphrase, not the recipient key.
            .arg(super::factor_cmd::arg(lang).conflicts_with("to"))
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

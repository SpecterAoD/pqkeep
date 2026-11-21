//! DE: Explizite Archivliste; Ausgabe erst nach vollständiger Core-Prüfung.
//! EN: Explicit archive listing; output only after complete core verification.

use std::io::Write;
use std::path::PathBuf;

use clap::{ArgMatches, Command, value_parser};
use pqkeep::files::{self, EntryKind, Listing};
use pqkeep::security::Lang;
use serde_json::{Map, Value, json};

use super::args::{base, flag, opt, path};
use super::io::{CliResult, Failure, code};
use super::list_text::texts;
use super::text::Texts;
use super::unlock::Access;

/// DE: Eigenes Schema, weil nur list bewusst Archivpfade zeigt.
/// EN: Separate schema because only list deliberately exposes archive paths.
pub const SCHEMA: &str = "pqkeep-list/1";

pub fn command(lang: Lang) -> Command {
    let t = super::text::texts(lang);
    let s = texts(lang);
    base("list", s.about, s.after, lang)
        .arg(path("source", s.source))
        .arg(
            opt("key", t.arg_key)
                .short('k')
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(flag("passphrase-stdin", t.arg_passphrase_stdin))
        .arg(super::factor_cmd::arg(lang))
        .arg(flag("json", s.json))
}

fn load(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult<Listing> {
    let source = super::files_cmd::source(m);
    let fail = |e| Failure::from_error(&e, lang);
    let access = Access::read(&source).map_err(fail)?;
    let opened = super::unlock::for_decrypt(
        t,
        lang,
        m,
        access.use_key(m.get_one::<PathBuf>("key").is_some()),
        access.passphrase,
    )?;
    files::list(&source, &opened.get()).map_err(fail)
}

/// DE: Textausgabe nach erfolgreicher Authentisierung; Schreibfehler bleiben Fehler.
/// EN: Text output after successful authentication; write failures remain errors.
pub fn run(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    let listing = load(t, lang, m)?;
    write_text(&mut std::io::stdout().lock(), &listing, lang)
        .map_err(|e| Failure::from_error(&e.into(), lang))
}

fn write_text(out: &mut impl Write, listing: &Listing, lang: Lang) -> std::io::Result<()> {
    let s = texts(lang);
    writeln!(out, "{}", s.verified)?;
    for entry in &listing.entries {
        let kind = match entry.kind {
            EntryKind::File => s.file,
            EntryKind::Directory => s.directory,
        };
        let size = entry.bytes.map_or_else(|| "-".into(), |v| v.to_string());
        // DE: Namen zitieren/escapen statt als Terminal-Steuerung interpretieren.
        // EN: Quote/escape names rather than interpreting them as terminal control.
        writeln!(out, "{kind}\t{size}\t{:?}", entry.path)?;
    }
    let r = &listing.report;
    writeln!(
        out,
        "{}: {} / {} / {}",
        super::text::texts(lang).msg_summary,
        r.files,
        r.directories,
        r.bytes
    )?;
    out.flush()
}

/// DE: Nur geprüfte Metadaten, keine Nutzdaten oder Absenderzusage.
/// EN: Verified metadata only, no payload or sender-identity claim.
pub fn json(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult<(Map<String, Value>, u8)> {
    let listing = load(t, lang, m)?;
    let entries = listing
        .entries
        .iter()
        .map(|entry| {
            let kind = match entry.kind {
                EntryKind::File => "file",
                EntryKind::Directory => "directory",
            };
            json!({"kind":kind,"path":entry.path,"bytes":entry.bytes})
        })
        .collect::<Vec<_>>();
    let mut body = Map::new();
    body.insert(
        "source".into(),
        super::files_cmd::source(m)
            .to_string_lossy()
            .into_owned()
            .into(),
    );
    body.insert("authentication".into(), "container_integrity".into());
    body.insert("entries".into(), entries.into());
    let r = listing.report;
    body.insert(
        "summary".into(),
        json!({"files":r.files,"directories":r.directories,"bytes":r.bytes}),
    );
    Ok((body, code::OK))
}

/// DE: Fallible Ausgabe auch für frühe JSON-Fehler. EN: Fallible output for early JSON errors too.
pub(super) fn emit_json(value: &Value) -> CliResult {
    write_json(&mut std::io::stdout().lock(), value)
        .map_err(|_| Failure::new(code::ERROR, "Ausgabe fehlgeschlagen / output failed"))
}

fn write_json(out: &mut impl Write, value: &Value) -> std::io::Result<()> {
    writeln!(out, "{value}")?;
    out.flush()
}

pub(super) fn message(field: &str) -> Option<&'static str> {
    (field == "list_limit").then_some("Archivliste überschreitet 10.000 Einträge oder 16 MiB Pfadbytes / archive listing exceeds 10,000 entries or 16 MiB of path bytes")
}

#[cfg(test)]
#[path = "list_cmd_tests.rs"]
mod tests;

//! DE: Fenster-Ablauf für mehrere Dateien: „jede einzeln“ oder „ein Container“ (Name vorgeschlagen,
//! frei änderbar), Passphrase bzw. Empfänger nur einmal, ein Kindprozess, Fortschritt mit
//! Abbrechen, Zusammenfassung am Ende. Wiederholen nur, wenn noch nichts geschrieben wurde
//! (zu schwache oder ungleiche Passphrase).
//! EN: Window flow for several files: "each separately" or "one container" (name suggested, freely
//! editable), passphrase or recipient only once, one child process, progress with cancel, summary
//! at the end. Retry only if nothing was written yet (too weak or mismatched passphrase).

use std::path::PathBuf;

use pqkeep::files::{self, HeaderMode};

use super::context::utf8;
use super::context_child::Outcome;
use super::context_dialog::{Ui, cancelled};
use super::context_many::{all_pqkf, container_default, container_target, selection_dir};
use super::files_cmd::{default_decrypted, default_encrypted};
use super::io::{CliResult, Failure, code};
use super::many_text::{ManyTexts, many_texts};

/// DE: Höchstzahl an Versuchen. EN: Maximum number of attempts.
const ATTEMPTS: usize = 3;

/// DE: Bis zu so vielen Dateien wird jede einzeln aufgeführt. EN: Up to this many files are listed.
const LIST_MAX: usize = 20;

/// DE: Zusammenfassung (letzte Zeile der Ausgabe) und – bei wenigen Dateien – je Datei „OK: name“;
/// Fehler je Datei stehen in den Meldungen des Kindprozesses.
/// EN: Summary (last output line) and – for few files – "OK: name" per file; per-file errors are in
/// the child's messages.
fn summary(out: &str, done: &[String]) -> String {
    let mut text = out.lines().last().unwrap_or_default().to_owned();
    if !done.is_empty() && done.len() <= LIST_MAX {
        text.push('\n');
        for name in done {
            text.push_str("\nOK: ");
            text.push_str(name);
        }
    }
    text
}

/// DE: Ergebnis anzeigen; `Some(..)` = fertig, `None` = erneut versuchen.
/// EN: Show the result; `Some(..)` = finished, `None` = try again.
fn show(ui: &Ui<'_>, m: &ManyTexts, outcome: Outcome) -> Option<CliResult> {
    let d = ui.d;
    match outcome {
        Outcome::Done { out, warn, done } if warn.is_empty() => {
            ui.dlg
                .info(&format!("{}\n{}", m.ctx_done, summary(&out, &done)));
            Some(Ok(()))
        }
        Outcome::Done { out, warn, done } => {
            let text = format!(
                "{}\n{}\n\n{}\n{warn}",
                m.ctx_done,
                summary(&out, &done),
                d.incomplete
            );
            ui.dlg.warning(&text);
            Some(Ok(()))
        }
        Outcome::Cancelled { started } => {
            if started {
                ui.dlg.info(m.ctx_cancelled);
            }
            Some(Err(cancelled()))
        }
        Outcome::Failed {
            code: c,
            msg,
            out,
            done,
        } => {
            let text = format!("{}\n\n{msg}\n\n{}", d.failed, summary(&out, &done));
            ui.dlg.error(&text);
            // DE: WEAK/USAGE entstehen vor der ersten Datei – Wiederholen erzeugt keine Doppel.
            // EN: WEAK/USAGE happen before the first file – retrying creates no duplicates.
            let retry = (c == code::WEAK || c == code::USAGE) && ui.dlg.question(d.retry);
            (!retry).then(|| Err(Failure::new(code::ERROR, "")))
        }
    }
}

fn repeat(ui: &Ui<'_>, m: &ManyTexts, mut step: impl FnMut() -> CliResult<Outcome>) -> CliResult {
    for _ in 0..ATTEMPTS {
        if let Some(result) = show(ui, m, step()?) {
            return result;
        }
    }
    Err(Failure::new(code::ERROR, ""))
}

fn encrypt(ui: &Ui<'_>, m: &ManyTexts, sources: &[PathBuf], refs: &[&str]) -> CliResult {
    let ways: Vec<&str> = m.ctx_ways.split('|').collect();
    let way = ui.dlg.choose(m.ctx_how, &ways).ok_or_else(cancelled)?;
    let mut cmd: Vec<String> = vec!["encrypt".into()];
    let each = way == 0;
    let targets: Vec<PathBuf> = if each {
        cmd.extend(["--each".into(), "--rename".into(), "--progress".into()]);
        sources
            .iter()
            .filter_map(|s| default_encrypted(s))
            .collect()
    } else {
        let name = ui
            .dlg
            .entry(m.ctx_name, &container_default(sources, m))
            .ok_or_else(cancelled)?;
        let target = container_target(&selection_dir(sources), &name)
            .ok_or_else(|| Failure::new(code::USAGE, m.ctx_bad_name))?;
        cmd.extend(["--out".into(), utf8(&target, ui.lang)?]);
        vec![target]
    };
    let modes: Vec<&str> = ui.s.ctx_modes.split('|').collect();
    if ui.dlg.choose(ui.s.ctx_mode, &modes).ok_or_else(cancelled)? == 1 {
        let public = ui.recipient(&sources[0])?;
        cmd.extend(["--to".into(), public, "--".into()]);
        cmd.extend(refs.iter().map(|r| (*r).to_owned()));
        let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
        return repeat(ui, m, || ui.plain(&args, &targets, each));
    }
    let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
    repeat(ui, m, || {
        ui.with_pass(ui.d.new_pass, true, &args, refs, &targets, each)
    })
}

fn decrypt(ui: &Ui<'_>, m: &ManyTexts, sources: &[PathBuf], refs: &[&str]) -> CliResult {
    if !all_pqkf(sources) {
        return Err(Failure::new(code::USAGE, ui.s.ctx_not_pqkf));
    }
    let header = files::inspect(&sources[0]).map_err(|e| Failure::from_error(&e, ui.lang))?;
    let targets: Vec<PathBuf> = sources
        .iter()
        .filter_map(|s| default_decrypted(s))
        .collect();
    let d = ui.d;
    if let HeaderMode::Recipient { .. } = header.mode {
        let key = ui.pick(d.pick_key, &sources[0], "*.json", d.filter_key)?;
        let cmd = ["decrypt", "--rename", "--progress", "--key", &key];
        return repeat(ui, m, || {
            ui.with_pass(d.key_pass, false, &cmd, refs, &targets, true)
        });
    }
    let cmd = ["decrypt", "--rename", "--progress"];
    repeat(ui, m, || {
        ui.with_pass(d.pass, false, &cmd, refs, &targets, true)
    })
}

/// DE: Einstieg für mehrere Quellen. EN: Entry point for several sources.
pub(super) fn run(ui: &Ui<'_>, action: &str, sources: &[PathBuf], paths: &[String]) -> CliResult {
    let m = many_texts(ui.lang);
    let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    if action == "decrypt" {
        decrypt(ui, m, sources, &refs)
    } else {
        encrypt(ui, m, sources, &refs)
    }
}

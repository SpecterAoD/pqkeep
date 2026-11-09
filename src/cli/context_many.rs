//! DE: Mehrfachauswahl im Kontextmenü: gemeinsame Hilfen (Aktion `auto`, Prüfen der Pfade,
//! Container-Name mit Vorschlag) und der Ablauf im Terminal. Die Arbeit macht ein einziger
//! Kindprozess mit voller Sandbox (`encrypt --each --rename`, `encrypt --out`, `decrypt --rename`).
//! EN: Multi-selection in the context menu: shared helpers (action `auto`, checking paths,
//! container name with suggestion) and the terminal flow. The work is done by a single child
//! process with the full sandbox (`encrypt --each --rename`, `encrypt --out`, `decrypt --rename`).

use std::path::{Path, PathBuf};

use dialoguer::{Confirm, Input, Select};
use pqkeep::files::{self, HeaderMode};
use pqkeep::security::Lang;

use super::context::{ask_path, child, utf8};
use super::files_cmd::free_target;
use super::integrate_text::IntegrateTexts;
use super::io::{CliResult, Failure, code};
use super::many_text::{ManyTexts, many_texts};

/// DE: Sind alle Quellen `.pqkf`? EN: Are all sources `.pqkf`?
pub(super) fn all_pqkf(sources: &[PathBuf]) -> bool {
    sources
        .iter()
        .all(|s| s.extension().and_then(|e| e.to_str()) == Some(files::EXTENSION))
}

/// DE: `auto` („Senden an“): Entschlüsseln, wenn alle `.pqkf` sind, sonst Verschlüsseln.
/// EN: `auto` ("Send to"): decrypt if all are `.pqkf`, else encrypt.
pub(super) fn resolve_action<'a>(action: &'a str, sources: &[PathBuf]) -> &'a str {
    match action {
        "auto" if all_pqkf(sources) => "decrypt",
        "auto" => "encrypt",
        other => other,
    }
}

/// DE: Höchstens `MAX_SOURCES` Einträge – sonst klare Meldung (statt stillem Abbruch beim Parsen).
/// EN: At most `MAX_SOURCES` entries – otherwise a clear message (instead of a silent parse error).
pub(super) fn limit(sources: &[PathBuf], lang: Lang) -> CliResult {
    let max = super::args_files::MAX_SOURCES;
    if sources.len() > max {
        let text = many_texts(lang).too_many.replace("{max}", &max.to_string());
        return Err(Failure::new(code::USAGE, text));
    }
    Ok(())
}

/// DE: Alle Quellen vorhanden und als UTF-8 darstellbar. EN: All sources exist and are valid UTF-8.
pub(super) fn checked(sources: &[PathBuf], lang: Lang) -> CliResult<Vec<String>> {
    sources
        .iter()
        .map(|s| {
            if !s.exists() {
                let e = pqkeep::Error::Io(std::io::ErrorKind::NotFound);
                return Err(Failure::from_error(&e, lang));
            }
            utf8(s, lang)
        })
        .collect()
}

/// DE: Ordner der Auswahl (der der ersten Quelle). EN: Folder of the selection (that of the first source).
pub(super) fn selection_dir(sources: &[PathBuf]) -> PathBuf {
    sources
        .first()
        .and_then(|s| s.parent())
        .unwrap_or(Path::new("/"))
        .to_path_buf()
}

/// DE: Vorschlag: `<Ordnername>.pqkf`, sonst `Auswahl (N Einträge).pqkf`; immer ein freier Name.
/// EN: Suggestion: `<folder name>.pqkf`, else `Selection (N entries).pqkf`; always a free name.
pub(super) fn container_default(sources: &[PathBuf], m: &ManyTexts) -> String {
    let dir = selection_dir(sources);
    let folder = dir
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty());
    let stem = folder.map_or_else(
        || m.ctx_selection.replace("{n}", &sources.len().to_string()),
        str::to_owned,
    );
    let name = format!("{stem}.{}", files::EXTENSION);
    free_target(&dir.join(&name))
        .and_then(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_owned))
        .unwrap_or(name)
}

/// DE: Ziel aus dem frei eingegebenen Namen: nur ein Dateiname, `.pqkf` wird ergänzt, freier Name.
/// EN: Target from the freely entered name: a plain file name only, `.pqkf` appended, free name.
pub(super) fn container_target(dir: &Path, input: &str) -> Option<PathBuf> {
    let name = input.trim();
    let bad = name.is_empty()
        || name == "."
        || name == ".."
        || name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control());
    if bad {
        return None;
    }
    let suffix = format!(".{}", files::EXTENSION);
    let name = if name.to_lowercase().ends_with(&suffix) {
        name.to_owned()
    } else {
        format!("{name}{suffix}")
    };
    free_target(&dir.join(name))
}

fn select(prompt: &str, items: &[&str]) -> CliResult<usize> {
    Select::new()
        .with_prompt(prompt)
        .items(items)
        .default(0)
        .interact()
        .map_err(|_| Failure::new(code::ERROR, ""))
}

fn recipient(s: &IntegrateTexts, lang: Lang) -> CliResult<String> {
    let public = ask_path(s.ctx_prompt_pub)?;
    child(lang, &["inspect", "--", &public])?;
    let ok = Confirm::new()
        .with_prompt(s.ctx_confirm)
        .default(false)
        .interact()
        .map_err(|_| Failure::new(code::ERROR, ""))?;
    if ok {
        Ok(public)
    } else {
        Err(Failure::new(code::USAGE, ""))
    }
}

/// DE: Ablauf im Terminal für mehrere Quellen. EN: Terminal flow for several sources.
pub(super) fn terminal(
    s: &IntegrateTexts,
    lang: Lang,
    action: &str,
    sources: &[PathBuf],
    paths: &[String],
) -> CliResult {
    let m = many_texts(lang);
    let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    if action == "decrypt" {
        if !all_pqkf(sources) {
            return Err(Failure::new(code::USAGE, s.ctx_not_pqkf));
        }
        let header = files::inspect(&sources[0]).map_err(|e| Failure::from_error(&e, lang))?;
        let key = match header.mode {
            HeaderMode::Recipient { .. } => Some(ask_path(s.ctx_prompt_key)?),
            HeaderMode::Passphrase { .. } => None,
        };
        let mut args = vec!["decrypt", "--rename"];
        if let Some(k) = &key {
            args.extend(["--key", k.as_str()]);
        }
        args.push("--");
        args.extend(&refs);
        return child(lang, &args);
    }
    let ways: Vec<&str> = m.ctx_ways.split('|').collect();
    let out: String;
    let mut args = vec!["encrypt"];
    if select(m.ctx_how, &ways)? == 0 {
        args.extend(["--each", "--rename"]);
    } else {
        let name: String = Input::new()
            .with_prompt(m.ctx_name)
            .with_initial_text(container_default(sources, m))
            .interact_text()
            .map_err(|_| Failure::new(code::ERROR, ""))?;
        let target = container_target(&selection_dir(sources), &name)
            .ok_or_else(|| Failure::new(code::USAGE, m.ctx_bad_name))?;
        out = utf8(&target, lang)?;
        args.extend(["--out", out.as_str()]);
    }
    let modes: Vec<&str> = s.ctx_modes.split('|').collect();
    let public = if select(s.ctx_mode, &modes)? == 1 {
        Some(recipient(s, lang)?)
    } else {
        None
    };
    if let Some(p) = &public {
        args.extend(["--to", p.as_str()]);
    }
    args.push("--");
    args.extend(&refs);
    child(lang, &args)
}

#[cfg(test)]
#[path = "context_many_tests.rs"]
mod context_many_tests;

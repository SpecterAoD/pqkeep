//! DE: Kindprozesse des Fenster-Ablaufs: starten (ohne Konsolenfenster), mit Fortschrittsfenster
//! warten, Abbrechen ermöglichen. Ausgaben werden in eigenen Threads gelesen (keine volle Pipe).
//! Nach einem Abbruch werden **nur eigene** Temporärdateien entfernt: Der Kindprozess bekommt eine
//! zufällige Kennung (`--temp-tag`), die die Bibliothek in jeden Temporärnamen schreibt
//! (`.<ziel>.tmp-<kennung><16 Hex>`, auch für freie Namen `ziel (n)`); fertige Ziele bleiben.
//! EN: Child processes of the window flow: start (without console window), wait with a progress
//! window, allow cancelling. Output is read in own threads (no full pipe). After cancelling, **only
//! own** temporary files are removed: the child gets a random tag (`--temp-tag`) that the library
//! writes into every temporary name (`.<target>.tmp-<tag><16 hex>`, also for free names
//! `target (n)`); finished targets stay.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

use pqkeep::security::Lang;

use super::dialog::Dialog;
use super::io::{CliResult, Failure, code};

/// DE: Ergebnis eines Kindprozesses. EN: Result of a child process.
pub(super) enum Outcome {
    /// DE: Erfolg mit Ausgabe und Warnungen (z. B. übersprungene Einträge).
    /// EN: Success with output and warnings (e.g. skipped entries).
    Done { out: String, warn: String },
    /// DE: Abgebrochen; `started` = Arbeit lief schon (Fortschrittsfenster).
    /// EN: Cancelled; `started` = work was already running (progress window).
    Cancelled { started: bool },
    /// DE: Fehler mit Exit-Code und Meldung. EN: Failure with exit code and message.
    Failed { code: u8, msg: String, out: String },
}

/// DE: Neue Kennung (16 Hex) für die Temporärnamen eines Kindprozesses.
/// EN: New tag (16 hex) for a child's temporary names.
pub(super) fn new_tag(lang: Lang) -> CliResult<String> {
    pqkeep::crypto::rng::array::<8>()
        .map(|b| pqkeep::envelope::hex_encode(&b))
        .map_err(|e| Failure::from_error(&e, lang))
}

/// DE: `args` mit `--temp-tag <tag>` direkt nach dem Befehl. EN: `args` with `--temp-tag <tag>` after the command.
pub(super) fn with_tag<'a>(args: &[&'a str], tag: &'a str) -> Vec<&'a str> {
    let mut out = Vec::with_capacity(args.len() + 2);
    out.extend(args.first());
    out.extend(["--temp-tag", tag]);
    out.extend(args.iter().skip(1));
    out
}

/// DE: Startet `pqkeep --lang <x> <args…>`. EN: Starts `pqkeep --lang <x> <args…>`.
pub(super) fn spawn(lang: Lang, args: &[&str], stdin: Stdio) -> CliResult<Child> {
    let fail = |e: std::io::Error| Failure::from_error(&e.into(), lang);
    let exe = std::env::current_exe().map_err(fail)?;
    let code = if lang == Lang::De { "de" } else { "en" };
    let mut cmd = Command::new(exe);
    super::dialog::no_console_window(&mut cmd);
    cmd.args(["--lang", code])
        .args(args)
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(fail)
}

fn drain(pipe: Option<impl Read + Send + 'static>) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = pipe {
            let _ = p.read_to_end(&mut buf);
        }
        String::from_utf8_lossy(&buf).trim().to_owned()
    })
}

fn outcome(status: ExitStatus, out: String, warn: String) -> Outcome {
    if status.success() {
        Outcome::Done { out, warn }
    } else {
        let code = status
            .code()
            .and_then(|c| u8::try_from(c).ok())
            .unwrap_or(code::ERROR);
        Outcome::Failed {
            code,
            msg: warn,
            out,
        }
    }
}

/// DE: Wartet mit abbrechbarem Fortschrittsfenster. EN: Waits with a cancelable progress window.
pub(super) fn finish(
    dlg: &Dialog,
    working: &str,
    lang: Lang,
    mut child: Child,
    targets: &[PathBuf],
    tag: Option<&str>,
) -> CliResult<Outcome> {
    let fail = |e: std::io::Error| Failure::from_error(&e.into(), lang);
    let out = drain(child.stdout.take());
    let err = drain(child.stderr.take());
    let mut progress = dlg.progress(working, true);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(fail)? {
            break status;
        }
        if progress.closed() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = (out.join(), err.join());
            if let Some(tag) = tag {
                clean_temps(targets, tag);
            }
            return Ok(Outcome::Cancelled { started: true });
        }
        thread::sleep(Duration::from_millis(100));
    };
    drop(progress);
    let (out, warn) = (
        out.join().unwrap_or_default(),
        err.join().unwrap_or_default(),
    );
    Ok(outcome(status, out, warn))
}

/// DE: Ist `name` eine Temporärausgabe mit Kennung `tag` für `base` oder einen freien Namen davon?
/// EN: Is `name` a temporary output with tag `tag` for `base` or a free name of it?
pub(super) fn own_temp(name: &str, base: &str, tag: &str) -> bool {
    let Some(rest) = name.strip_prefix('.') else {
        return false;
    };
    let Some((middle, hex)) = rest.rsplit_once(".tmp-") else {
        return false;
    };
    let random = hex.strip_prefix(tag).filter(|_| !tag.is_empty());
    let hex_ok = random.is_some_and(|r| {
        r.len() == 16
            && r.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    });
    if !hex_ok {
        return false;
    }
    if middle == base {
        return true;
    }
    let (stem, ext) = match base.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s, format!(".{e}")),
        _ => (base, String::new()),
    };
    (2..100).any(|n| middle == format!("{stem} ({n}){ext}"))
}

/// DE: Entfernt eigene Temporärausgaben neben den Zielen. EN: Removes own temporary output next to targets.
pub(super) fn clean_temps(targets: &[PathBuf], tag: &str) {
    for target in targets {
        let (Some(dir), Some(base)) =
            (target.parent(), target.file_name().and_then(|n| n.to_str()))
        else {
            continue;
        };
        let Ok(list) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in list.flatten() {
            let name = entry.file_name();
            if name.to_str().is_some_and(|n| own_temp(n, base, tag)) {
                remove(&entry.path());
            }
        }
    }
}

fn remove(path: &Path) {
    let is_dir = std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir());
    let _ = if is_dir {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
}

#[cfg(test)]
#[path = "context_child_tests.rs"]
mod context_child_tests;

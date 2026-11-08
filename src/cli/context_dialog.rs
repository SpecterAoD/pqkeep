//! DE: `pqkeep context --dialog`: derselbe Ablauf wie im Terminal, aber mit kleinen Fenstern.
//! Ver- und Entschlüsseln laufen als Kindprozess mit voller Sandbox. Die Passphrase fließt per
//! Pipe vom Passwortfenster direkt in dessen stdin – dieser Prozess sieht sie nie. Mehrere Dateien:
//! `context_dialog_many.rs`.
//! EN: `pqkeep context --dialog`: the same flow as in the terminal, but with small windows.
//! Encryption and decryption run as a child process with the full sandbox. The passphrase flows
//! through a pipe from the password window straight into its stdin – this process never sees it.
//! Several files: `context_dialog_many.rs`.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use pqkeep::files::{self, HeaderMode};
use pqkeep::security::Lang;

use super::context::{out_arg, utf8};
use super::context_child::{Outcome, finish, spawn};
use super::dialog::Dialog;
use super::dialog_text::{DialogTexts, dialog_texts};
use super::files_cmd::{default_decrypted, default_encrypted};
use super::integrate_text::{IntegrateTexts, integrate_texts};
use super::io::{CliResult, Failure, code};

/// DE: Höchstzahl an Versuchen (z. B. bei zu schwacher Passphrase). EN: Maximum number of attempts.
const ATTEMPTS: usize = 3;

pub(super) struct Ui<'a> {
    pub dlg: Dialog,
    pub d: &'a DialogTexts,
    pub s: &'a IntegrateTexts,
    pub lang: Lang,
}

pub(super) fn cancelled() -> Failure {
    Failure::new(code::USAGE, "")
}

impl Ui<'_> {
    /// DE: Kindprozess ohne Passphrase. EN: Child without passphrase.
    pub(super) fn plain(&self, args: &[&str], targets: &[PathBuf]) -> CliResult<Outcome> {
        let child = spawn(self.lang, args, Stdio::null())?;
        finish(&self.dlg, self.d.working, self.lang, child, targets)
    }

    /// DE: Passwortfenster → Pipe → Kindprozess (`--passphrase-stdin`, ggf. `--confirm-stdin`);
    /// `cmd` endet vor `--`, danach folgen `paths`.
    /// EN: Password window → pipe → child process (`--passphrase-stdin`, maybe `--confirm-stdin`);
    /// `cmd` ends before `--`, followed by `paths`.
    pub(super) fn with_pass(
        &self,
        prompt: &str,
        new: bool,
        cmd: &[&str],
        paths: &[&str],
        targets: &[PathBuf],
    ) -> CliResult<Outcome> {
        let confirm = new.then_some((self.d.first, self.d.second));
        let no_tool = || Failure::new(code::ERROR, self.d.no_tool);
        let (mut tool, two_lines) = self.dlg.password(prompt, confirm).ok_or_else(no_tool)?;
        let pipe = tool.stdout.take().ok_or_else(no_tool)?;
        let mut args = cmd.to_vec();
        args.push("--passphrase-stdin");
        if two_lines {
            args.push("--confirm-stdin");
        }
        args.push("--");
        args.extend_from_slice(paths);
        let mut child = spawn(self.lang, &args, Stdio::from(pipe))?;
        if !tool.wait().is_ok_and(|s| s.success()) {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(Outcome::Cancelled { started: false });
        }
        finish(&self.dlg, self.d.working, self.lang, child, targets)
    }

    /// DE: Wiederholt `step` nach Fehlern auf Wunsch. EN: Repeats `step` after errors on request.
    fn repeat(&self, out: &str, mut step: impl FnMut() -> CliResult<Outcome>) -> CliResult {
        for _ in 0..ATTEMPTS {
            match step()? {
                Outcome::Done { warn, .. } if warn.is_empty() => {
                    self.dlg.info(&format!("{}\n{out}", self.d.done));
                    return Ok(());
                }
                // DE: Ein unvollständiges Archiv darf nicht wie ein voller Erfolg aussehen.
                // EN: An incomplete archive must not look like a full success.
                Outcome::Done { warn, .. } => {
                    let d = self.d;
                    let text = format!("{}\n{out}\n\n{}\n{warn}", d.done, d.incomplete);
                    self.dlg.warning(&text);
                    return Ok(());
                }
                Outcome::Cancelled { .. } => return Err(cancelled()),
                Outcome::Failed { msg, .. } => {
                    self.dlg.error(&format!("{}\n\n{msg}", self.d.failed));
                    if !self.dlg.question(self.d.retry) {
                        break;
                    }
                }
            }
        }
        Err(Failure::new(code::ERROR, ""))
    }

    pub(super) fn pick(
        &self,
        prompt: &str,
        near: &Path,
        pattern: &str,
        label: &str,
    ) -> CliResult<String> {
        let start = near.parent().unwrap_or(Path::new("/"));
        let file = self.dlg.open_file(prompt, start, pattern, label);
        utf8(&file.ok_or_else(cancelled)?, self.lang)
    }

    /// DE: Empfänger wählen, Fingerabdruck zeigen und bestätigen lassen.
    /// EN: Pick a recipient, show the fingerprint and ask for confirmation.
    pub(super) fn recipient(&self, near: &Path) -> CliResult<String> {
        let d = self.d;
        let public = self.pick(d.pick_pub, near, "*.pub.json", d.filter_pub)?;
        let info = finish(
            &self.dlg,
            d.working,
            self.lang,
            spawn(self.lang, &["inspect", "--", &public], Stdio::null())?,
            &[],
        )?;
        let shown = match info {
            Outcome::Done { out, .. } => out,
            Outcome::Cancelled { .. } => return Err(cancelled()),
            Outcome::Failed { msg, .. } => {
                self.dlg.error(&format!("{}\n\n{msg}", d.failed));
                return Err(Failure::new(code::ERROR, ""));
            }
        };
        if !self
            .dlg
            .question(&format!("{shown}\n{}", self.s.ctx_confirm))
        {
            return Err(cancelled());
        }
        Ok(public)
    }

    fn encrypt(&self, path: &str) -> CliResult {
        let modes: Vec<&str> = self.s.ctx_modes.split('|').collect();
        let mode = self
            .dlg
            .choose(self.s.ctx_mode, &modes)
            .ok_or_else(cancelled)?;
        let out = out_arg(default_encrypted(Path::new(path)).as_deref(), self.lang)?;
        let targets = [PathBuf::from(&out)];
        if mode == 0 {
            let cmd = ["encrypt", "--out", &out];
            let new_pass = self.d.new_pass;
            return self.repeat(&out, || {
                self.with_pass(new_pass, true, &cmd, &[path], &targets)
            });
        }
        let public = self.recipient(Path::new(path))?;
        let cmd = ["encrypt", "--to", &public, "--out", &out, "--", path];
        self.repeat(&out, || self.plain(&cmd, &targets))
    }

    fn decrypt(&self, source: &Path, path: &str) -> CliResult {
        if source.extension().and_then(|e| e.to_str()) != Some(files::EXTENSION) {
            return Err(Failure::new(code::USAGE, self.s.ctx_not_pqkf));
        }
        let header = files::inspect(source).map_err(|e| Failure::from_error(&e, self.lang))?;
        let out = out_arg(default_decrypted(source).as_deref(), self.lang)?;
        let targets = [PathBuf::from(&out)];
        let d = self.d;
        if let HeaderMode::Recipient { .. } = header.mode {
            let key = self.pick(d.pick_key, source, "*.json", d.filter_key)?;
            let cmd = ["decrypt", "--key", &key, "--out", &out];
            return self.repeat(&out, || {
                self.with_pass(d.key_pass, false, &cmd, &[path], &targets)
            });
        }
        let cmd = ["decrypt", "--out", &out];
        self.repeat(&out, || {
            self.with_pass(d.pass, false, &cmd, &[path], &targets)
        })
    }
}

/// DE: Einstieg für `context --dialog` (eine oder mehrere Quellen; `auto` = Entschlüsseln, wenn
/// alle `.pqkf` sind).
/// EN: Entry point for `context --dialog` (one or more sources; `auto` = decrypt if all are `.pqkf`).
pub fn run(lang: Lang, action: &str, sources: &[PathBuf]) -> CliResult {
    let d = dialog_texts(lang);
    // DE: Ohne Fenster eigener Exit-Code; unter Windows öffnet `pqkeepw.exe` dann eine Konsole.
    //     Es hat selbst keine Standardkanäle, die neue Konsole bekommt daher eigene.
    // EN: Without windows a dedicated exit code; on Windows `pqkeepw.exe` then opens a console.
    //     It has no standard handles itself, so the new console gets its own.
    let Some(dlg) = Dialog::detect(d.title, d.cancel) else {
        return Err(Failure::new(code::NO_WINDOWS, d.no_tool));
    };
    let ui = Ui {
        dlg,
        d,
        s: integrate_texts(lang),
        lang,
    };
    let action = super::context_many::resolve_action(action, sources);
    let result = super::context_many::checked(sources, lang).and_then(|paths| {
        if paths.len() > 1 {
            super::context_dialog_many::run(&ui, action, sources, &paths)
        } else if action == "decrypt" {
            ui.decrypt(&sources[0], &paths[0])
        } else {
            ui.encrypt(&paths[0])
        }
    });
    if let Err(f) = &result
        && !f.message.is_empty()
    {
        ui.dlg.error(&f.message);
    }
    // DE: Meldung wurde im Fenster gezeigt; nur den Exit-Code weiterreichen.
    // EN: Message was shown in a window; only pass on the exit code.
    result.map_err(|f| Failure::new(f.code, ""))
}

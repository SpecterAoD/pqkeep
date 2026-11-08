//! DE: `pqkeep context --dialog`: derselbe Ablauf wie im Terminal, aber mit kleinen Fenstern.
//! Ver- und Entschlüsseln laufen als Kindprozess mit voller Sandbox. Die Passphrase fließt per
//! Pipe vom Passwortfenster direkt in dessen stdin – dieser Prozess sieht sie nie.
//! EN: `pqkeep context --dialog`: the same flow as in the terminal, but with small windows.
//! Encryption and decryption run as a child process with the full sandbox. The passphrase flows
//! through a pipe from the password window straight into its stdin – this process never sees it.

use std::path::Path;
use std::process::{Child, Command, Output, Stdio};

use pqkeep::files::{self, HeaderMode};
use pqkeep::security::Lang;

use super::context::{out_arg, utf8};
use super::dialog::Dialog;
use super::dialog_text::{DialogTexts, dialog_texts};
use super::files_cmd::{default_decrypted, default_encrypted};
use super::integrate_text::{IntegrateTexts, integrate_texts};
use super::io::{CliResult, Failure, code};

/// DE: Höchstzahl an Versuchen (z. B. bei zu schwacher Passphrase). EN: Maximum number of attempts.
const ATTEMPTS: usize = 3;

/// DE: Ergebnis eines Kindprozesses. EN: Result of a child process.
enum Outcome {
    /// DE: Erfolg; Inhalt = Warnungen (z. B. übersprungene Einträge). EN: Success; content = warnings.
    Done(String),
    Cancelled,
    Failed(String),
}

struct Ui<'a> {
    dlg: Dialog,
    d: &'a DialogTexts,
    s: &'a IntegrateTexts,
    lang: Lang,
}

fn cancelled() -> Failure {
    Failure::new(code::USAGE, "")
}

/// DE: Startet `pqkeep --lang <x> <args…>`. EN: Starts `pqkeep --lang <x> <args…>`.
fn spawn(lang: Lang, args: &[&str], stdin: Stdio) -> CliResult<Child> {
    let fail = |e: std::io::Error| Failure::from_error(&e.into(), lang);
    let exe = std::env::current_exe().map_err(fail)?;
    let code = if lang == Lang::De { "de" } else { "en" };
    Command::new(exe)
        .args(["--lang", code])
        .args(args)
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(fail)
}

fn wait(lang: Lang, child: Child) -> CliResult<Output> {
    child
        .wait_with_output()
        .map_err(|e| Failure::from_error(&e.into(), lang))
}

fn outcome(out: &Output) -> Outcome {
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    if out.status.success() {
        Outcome::Done(stderr)
    } else {
        Outcome::Failed(stderr)
    }
}

impl Ui<'_> {
    /// DE: Kindprozess ohne Passphrase, mit Fortschrittsfenster. EN: Child without passphrase.
    fn plain(&self, args: &[&str]) -> CliResult<Outcome> {
        let _progress = self.dlg.progress(self.d.working);
        let child = spawn(self.lang, args, Stdio::null())?;
        Ok(outcome(&wait(self.lang, child)?))
    }

    /// DE: Passwortfenster → Pipe → Kindprozess (`--passphrase-stdin`, ggf. `--confirm-stdin`).
    /// EN: Password window → pipe → child process (`--passphrase-stdin`, maybe `--confirm-stdin`).
    fn with_pass(&self, prompt: &str, new: bool, cmd: &[&str], path: &str) -> CliResult<Outcome> {
        let confirm = new.then_some((self.d.first, self.d.second));
        let no_tool = || Failure::new(code::ERROR, self.d.no_tool);
        let (mut tool, two_lines) = self.dlg.password(prompt, confirm).ok_or_else(no_tool)?;
        let pipe = tool.stdout.take().ok_or_else(no_tool)?;
        let mut args = cmd.to_vec();
        args.push("--passphrase-stdin");
        if two_lines {
            args.push("--confirm-stdin");
        }
        args.extend(["--", path]);
        let mut child = spawn(self.lang, &args, Stdio::from(pipe))?;
        if !tool.wait().is_ok_and(|s| s.success()) {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(Outcome::Cancelled);
        }
        let _progress = self.dlg.progress(self.d.working);
        Ok(outcome(&wait(self.lang, child)?))
    }

    /// DE: Wiederholt `step` nach Fehlern auf Wunsch. EN: Repeats `step` after errors on request.
    fn repeat(&self, out: &str, mut step: impl FnMut() -> CliResult<Outcome>) -> CliResult {
        for _ in 0..ATTEMPTS {
            match step()? {
                Outcome::Done(warnings) if warnings.is_empty() => {
                    self.dlg.info(&format!("{}\n{out}", self.d.done));
                    return Ok(());
                }
                // DE: Ein unvollständiges Archiv darf nicht wie ein voller Erfolg aussehen.
                // EN: An incomplete archive must not look like a full success.
                Outcome::Done(warnings) => {
                    let d = self.d;
                    self.dlg.warning(&format!(
                        "{}\n{out}\n\n{}\n{warnings}",
                        d.done, d.incomplete
                    ));
                    return Ok(());
                }
                Outcome::Cancelled => return Err(cancelled()),
                Outcome::Failed(msg) => {
                    self.dlg.error(&format!("{}\n\n{msg}", self.d.failed));
                    if !self.dlg.question(self.d.retry) {
                        break;
                    }
                }
            }
        }
        Err(Failure::new(code::ERROR, ""))
    }

    fn pick(&self, prompt: &str, near: &Path, pattern: &str, label: &str) -> CliResult<String> {
        let start = near.parent().unwrap_or(Path::new("/"));
        let file = self.dlg.open_file(prompt, start, pattern, label);
        utf8(&file.ok_or_else(cancelled)?, self.lang)
    }

    fn encrypt(&self, path: &str) -> CliResult {
        let modes: Vec<&str> = self.s.ctx_modes.split('|').collect();
        let mode = self
            .dlg
            .choose(self.s.ctx_mode, &modes)
            .ok_or_else(cancelled)?;
        let out = out_arg(default_encrypted(Path::new(path)).as_deref(), self.lang)?;
        if mode == 0 {
            let cmd = ["encrypt", "--out", &out];
            return self.repeat(&out, || self.with_pass(self.d.new_pass, true, &cmd, path));
        }
        let d = self.d;
        let public = self.pick(d.pick_pub, Path::new(path), "*.pub.json", d.filter_pub)?;
        let info = wait(
            self.lang,
            spawn(self.lang, &["inspect", "--", &public], Stdio::null())?,
        )?;
        if let Outcome::Failed(msg) = outcome(&info) {
            self.dlg.error(&format!("{}\n\n{msg}", d.failed));
            return Err(Failure::new(code::ERROR, ""));
        }
        let shown = String::from_utf8_lossy(&info.stdout);
        if !self
            .dlg
            .question(&format!("{}\n{}", shown.trim(), self.s.ctx_confirm))
        {
            return Err(cancelled());
        }
        let cmd = ["encrypt", "--to", &public, "--out", &out, "--", path];
        self.repeat(&out, || self.plain(&cmd))
    }

    fn decrypt(&self, source: &Path, path: &str) -> CliResult {
        if source.extension().and_then(|e| e.to_str()) != Some(files::EXTENSION) {
            return Err(Failure::new(code::USAGE, self.s.ctx_not_pqkf));
        }
        let header = files::inspect(source).map_err(|e| Failure::from_error(&e, self.lang))?;
        let out = out_arg(default_decrypted(source).as_deref(), self.lang)?;
        if let HeaderMode::Recipient { .. } = header.mode {
            let d = self.d;
            let key = self.pick(d.pick_key, source, "*.json", d.filter_key)?;
            let cmd = ["decrypt", "--key", &key, "--out", &out];
            return self.repeat(&out, || self.with_pass(d.key_pass, false, &cmd, path));
        }
        let cmd = ["decrypt", "--out", &out];
        self.repeat(&out, || self.with_pass(self.d.pass, false, &cmd, path))
    }
}

/// DE: Einstieg für `context --dialog`. EN: Entry point for `context --dialog`.
pub fn run(lang: Lang, action: &str, source: &Path) -> CliResult {
    let d = dialog_texts(lang);
    let Some(dlg) = Dialog::detect(d.title) else {
        return Err(Failure::new(code::ERROR, d.no_tool));
    };
    let ui = Ui {
        dlg,
        d,
        s: integrate_texts(lang),
        lang,
    };
    let result = utf8(source, lang).and_then(|path| {
        if !source.exists() {
            let e = pqkeep::Error::Io(std::io::ErrorKind::NotFound);
            return Err(Failure::from_error(&e, lang));
        }
        if action == "decrypt" {
            ui.decrypt(source, &path)
        } else {
            ui.encrypt(&path)
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

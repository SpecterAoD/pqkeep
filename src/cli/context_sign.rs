//! DE: Absender-Signatur im Kontextmenü (#287, Format v3 aus #44): Frage „Als Absender signieren?“,
//! Auswahl des eigenen ML-DSA-87-Schlüssels (und ggf. seiner Faktordatei). Mit Passphrase-Schutz
//! braucht es zwei Passphrasen: Beide Passwortfenster schreiben nacheinander in **dieselbe**
//! Betriebssystem-Pipe, deren Leseende der Kindprozess als stdin bekommt (`--passphrase-stdin`,
//! ggf. `--confirm-stdin`, dann `--sign-passphrase-next-line`). Dieser Prozess liest die Pipe nie –
//! er sieht keine Passphrase. Nach dem Entschlüsseln nennt das Fertig-Fenster den geprüften Absender.
//! EN: Sender signature in the context menu (#287, format v3 from #44): question "Sign as sender?",
//! choice of the own ML-DSA-87 key (and its factor file if needed). With passphrase protection two
//! passphrases are needed: both password windows write one after the other into the **same** OS
//! pipe whose read end becomes the child's stdin (`--passphrase-stdin`, maybe `--confirm-stdin`,
//! then `--sign-passphrase-next-line`). This process never reads the pipe – it sees no passphrase.
//! After decrypting, the final window names the verified sender.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use super::context_child::{Outcome, finish, new_tag, spawn, with_tag};
use super::context_dialog::Ui;
use super::factor_ui::Ask;
use super::io::{CliResult, Failure, code};
use super::signing::{SIGN_FACTOR, SIGN_PASS_NEXT, SIGN_WITH, texts};

/// DE: Gewählter Signaturschlüssel. EN: Chosen signing key.
pub(super) struct SignChoice {
    key: String,
    factor: Option<String>,
}

impl SignChoice {
    /// DE: Argumente für `encrypt`. EN: Arguments for `encrypt`.
    pub(super) fn args(&self) -> Vec<String> {
        let mut out = vec![format!("--{SIGN_WITH}"), self.key.clone()];
        if let Some(f) = &self.factor {
            out.extend([format!("--{SIGN_FACTOR}"), f.clone()]);
        }
        out
    }
}

/// DE: Fragt, ob signiert werden soll; dann Schlüssel und ggf. Faktordatei.
/// EN: Asks whether to sign; then key and factor file if needed.
pub(super) fn ask(ui: &Ui<'_>, near: &Path) -> CliResult<Option<SignChoice>> {
    let s = texts(ui.lang);
    if !ui.dlg.question(s.ctx_question) {
        return Ok(None);
    }
    let key = ui.pick(s.ctx_pick, near, "*.key.json", s.ctx_filter)?;
    let factor = super::factor_ui::key_needs(Path::new(&key))
        .then(|| ui.ask_for(near, Ask::Factor))
        .transpose()?;
    Ok(Some(SignChoice { key, factor }))
}

/// DE: Verschlüsseln für Empfänger, optional signiert: dann braucht es nur die Passphrase des
/// Signaturschlüssels (ein Passwortfenster), sonst keine.
/// EN: Encrypting for recipients, optionally signed: then only the signing key passphrase is
/// needed (one password window), otherwise none.
/// `out`: DE: Ziel und Zusatzargumente (#315). EN: target and extra arguments (#315).
pub(super) fn for_recipients(
    ui: &Ui<'_>,
    path: &str,
    (out, level): (&str, &[&str]),
    targets: &[PathBuf],
) -> CliResult {
    let all = super::context_dialog_many::recipients(ui, Path::new(path))?;
    let to = super::recipients_ui::to_args(&all);
    let sign = ask(ui, Path::new(path))?;
    let sign_args = sign.as_ref().map(SignChoice::args).unwrap_or_default();
    let mut cmd = vec!["encrypt"];
    cmd.extend(to.iter().map(String::as_str));
    cmd.extend(["--out", out]);
    cmd.extend(level);
    cmd.extend(sign_args.iter().map(String::as_str));
    if sign.is_some() {
        let prompt = texts(ui.lang).prompt;
        return ui.repeat(out, || {
            ui.with_pass(prompt, false, &cmd, &[path], targets, false)
        });
    }
    cmd.extend(["--", path]);
    ui.repeat(out, || ui.plain(&cmd, targets, false))
}

/// DE: Zwei Passwortfenster (neue Datei-Passphrase, dann Passphrase des Signaturschlüssels) → eine
/// Pipe → Kindprozess. `cmd` endet vor `--`, danach folgen `paths`.
/// EN: Two password windows (new file passphrase, then signing key passphrase) → one pipe → child.
/// `cmd` ends before `--`, followed by `paths`.
pub(super) fn two_passphrases(
    ui: &Ui<'_>,
    cmd: &[&str],
    paths: &[&str],
    targets: &[PathBuf],
    step: bool,
) -> CliResult<Outcome> {
    let no_tool = || Failure::new(code::ERROR, ui.d.no_tool);
    let io = |e: std::io::Error| Failure::from_error(&e.into(), ui.lang);
    let (reader, writer) = std::io::pipe().map_err(io)?;
    let confirm = Some((ui.d.first, ui.d.second));
    let first = writer.try_clone().map_err(io)?;
    let (mut tool, two_lines) = ui
        .dlg
        .password_into(ui.d.new_pass, confirm, first)
        .ok_or_else(no_tool)?;
    // DE: Der Kindprozess liest von Anfang an mit (Codex-Befund): Ein volles Pipe-Puffer kann so
    //     kein Passwortfenster blockieren. EN: The child reads from the start (Codex finding): a
    //     full pipe buffer can thus not block a password window.
    let tag = new_tag(ui.lang)?;
    let next = format!("--{SIGN_PASS_NEXT}");
    let mut args = with_tag(cmd, &tag);
    args.push("--passphrase-stdin");
    if two_lines {
        args.push("--confirm-stdin");
    }
    args.extend([next.as_str(), "--"]);
    args.extend_from_slice(paths);
    let mut child = spawn(ui.lang, &args, Stdio::from(reader))?;
    if !tool.wait().is_ok_and(|s| s.success()) {
        return Ok(stop(child));
    }
    // DE: Hat der Kindprozess schon aufgegeben (z. B. ungleiche Wiederholung), entfällt das zweite
    //     Fenster. `writer` wandert ins zweite Fenster; danach hält dieser Prozess kein Schreibende.
    // EN: If the child already gave up (e.g. mismatching repeat), the second window is skipped.
    //     `writer` moves into the second window; afterwards this process holds no write end.
    if matches!(child.try_wait(), Ok(None)) {
        let prompt = texts(ui.lang).prompt;
        let Some((mut tool, _)) = ui.dlg.password_into(prompt, None, writer) else {
            let _ = stop(child);
            return Err(no_tool());
        };
        if !tool.wait().is_ok_and(|s| s.success()) {
            return Ok(stop(child));
        }
    }
    finish(
        &ui.dlg,
        &ui.watch(step),
        ui.lang,
        child,
        targets,
        Some(&tag),
    )
}

/// DE: Bricht den Kindprozess vor jeder Arbeit ab (er wartete noch auf Passphrasen).
/// EN: Stops the child before any work (it was still waiting for passphrases).
fn stop(mut child: std::process::Child) -> Outcome {
    let _ = child.kill();
    let _ = child.wait();
    Outcome::Cancelled { started: false }
}

/// DE: Zeilen „Signiert von (geprüft): …“ für das Fertig-Fenster aus den `@@signer`-Steuerzeilen des
/// Kindprozesses (nie aus dem Ausgabetext), jeder Absender einmal; leer ohne signierte Dateien.
/// EN: Lines "Signed by (verified): …" for the final window from the child's `@@signer` control
/// lines (never from output text), each sender once; empty without signed files.
pub(super) fn signer_lines(lang: pqkeep::security::Lang, signers: &[String]) -> String {
    let label = super::signing::signed_by_label(lang);
    let mut seen: Vec<&str> = Vec::new();
    for id in signers {
        if !seen.contains(&id.as_str()) {
            seen.push(id);
        }
    }
    let lines: Vec<String> = seen
        .iter()
        .map(|id| format!("{label}: {}", super::io::fingerprint(id)))
        .collect();
    if lines.is_empty() {
        String::new()
    } else {
        format!("\n\n{}", lines.join("\n"))
    }
}

#[cfg(test)]
#[path = "context_sign_tests.rs"]
mod context_sign_tests;

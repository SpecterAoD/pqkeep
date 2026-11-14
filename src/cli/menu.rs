//! DE: Interaktives Menü (nur im Terminal, ohne Argumente). Jede Auswahl fragt die
//! nötigen Angaben ab und startet denselben Befehl wie die Kommandozeile als eigenen
//! Prozess mit voller Sandbox – es gibt keine zweite Logik. Schlüssel erstellen, Signieren
//! und Prüfen laufen geführt (`guide`). Kurzhinweise (Passphrase-Regeln, Metadaten im Klartext)
//! erscheinen an der passenden Stelle.
//! EN: Interactive menu (terminal only, without arguments). Each choice asks for
//! the required input and starts the same command as the command line as its own
//! process with the full sandbox – there is no second logic. Creating keys, signing and
//! verifying are guided (`guide`). Short hints (passphrase rules, plaintext metadata) appear where
//! relevant.

use std::path::Path;

use dialoguer::{Confirm, Input, Select};
use pqkeep::security::Lang;

use super::factor_ui::Ask;
use super::guide;
use super::io::{CliResult, Failure, code};
use super::text::Texts;

fn ask(prompt: &str, allow_empty: bool) -> CliResult<String> {
    Input::<String>::new()
        .with_prompt(prompt)
        .allow_empty(allow_empty)
        .interact_text()
        .map_err(|_| Failure::new(code::ERROR, ""))
}

/// DE: Ja/Nein, Standard Nein. EN: Yes/no, default no.
fn confirm(prompt: &str) -> CliResult<bool> {
    Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()
        .map_err(|_| Failure::new(code::ERROR, ""))
}

fn ask_default(prompt: &str, default: &str) -> CliResult<String> {
    Input::<String>::new()
        .with_prompt(prompt)
        .default(default.to_owned())
        .interact_text()
        .map_err(|_| Failure::new(code::ERROR, ""))
}

fn push_out(argv: &mut Vec<String>, t: &Texts) -> CliResult {
    let out = ask(t.menu_out, true)?;
    if !out.is_empty() {
        argv.extend(["--out".to_owned(), out]);
    }
    Ok(())
}

/// DE: Ver-/Entschlüsseln: Pfad, dann nur die Angaben, die nötig sind. Beim Entschlüsseln
/// entscheidet der Header der Datei (Schlüsseldatei, Faktordatei); ist er nicht lesbar, meldet
/// der Befehl selbst den Fehler.
/// EN: Encrypt/decrypt: path, then only the input that is needed. When decrypting, the file's
/// header decides (key file, factor file); if it cannot be read the command reports the error.
fn crypt_args(t: &Texts, lang: Lang, encrypt: bool, argv: &mut Vec<String>) -> CliResult {
    let f = super::factor_ui::ui_texts(lang);
    argv.push(if encrypt { "encrypt" } else { "decrypt" }.to_owned());
    let path = ask(t.menu_path, false)?;
    if encrypt {
        let to = ask(t.menu_recipient, true)?;
        // DE: Mit Empfängern: weitere sammeln, dann optional eigene Passphrase (#47).
        // EN: With recipients: collect more, then optionally an own passphrase (#47).
        let with_pass = !to.is_empty() && {
            let r = super::recipients_ui::texts(lang);
            let all = super::recipients_ui::collect(to.clone(), || {
                ask(r.menu_more, true).map(|p| (!p.is_empty()).then_some(p))
            })?;
            argv.extend(super::recipients_ui::to_args(&all));
            confirm(r.with_pass)?
        };
        if with_pass {
            argv.push(super::recipients::WITH_PASSPHRASE_FLAG.to_owned());
        }
        if to.is_empty() || with_pass {
            let factor = ask(f.menu_optional, true)?;
            if !factor.is_empty() {
                argv.extend([super::factor_cmd::FLAG.to_owned(), factor]);
            }
        }
    } else {
        let extra = super::factor_ui::for_decrypt(Path::new(&path), lang, |what| match what {
            Ask::Key => ask(t.menu_keyfile, false),
            Ask::Factor => ask(f.needed, false),
        });
        argv.extend(extra.map(|e| e.args).unwrap_or_default());
    }
    push_out(argv, t)?;
    // DE: Pfad zuletzt nach `--`, damit er nie als Option gilt. EN: Path last after `--`.
    argv.extend(["--".to_owned(), path]);
    Ok(())
}

/// DE: Baut die Argumente für eine Menüauswahl; `None` = Beenden.
/// EN: Builds the arguments for a menu choice; `None` = quit.
fn choice_args(t: &Texts, lang: Lang, choice: usize) -> CliResult<Option<Vec<String>>> {
    let mut argv: Vec<String> = Vec::new();
    match choice {
        1 => {
            eprintln!("{}", t.menu_hint_passphrase);
            let len = ask_default(t.menu_pass_len, "32")?;
            argv.extend(["passphrase".to_owned(), len.trim().to_owned()]);
        }
        2 => {
            eprintln!("{}", t.menu_hint_passphrase);
            argv.push("validate".to_owned());
        }
        3 | 4 => {
            argv.push(if choice == 3 { "inspect" } else { "export" }.to_owned());
            argv.push(ask(t.menu_path, false)?);
            if choice == 4 {
                argv.extend(["--out".to_owned(), ask(t.arg_out, false)?]);
            }
        }
        5 | 6 => crypt_args(t, lang, choice == 5, &mut argv)?,
        9 => {
            let out = ask(super::factor_ui::ui_texts(lang).menu_out, false)?;
            argv.extend(["factor".to_owned(), "--out".to_owned(), out]);
        }
        10 => argv.push("help".to_owned()),
        _ => return Ok(None),
    }
    Ok(Some(argv))
}

/// DE: Menüschleife; `execute` führt die erzeugten Argumente aus.
/// EN: Menu loop; `execute` runs the generated arguments.
pub fn run(t: &Texts, lang: Lang, execute: impl Fn(Vec<String>) -> CliResult) -> CliResult {
    let items: Vec<&str> = t.menu_items.split('|').collect();
    loop {
        let choice = Select::new()
            .with_prompt(t.menu_title)
            .items(&items)
            .default(0)
            .interact()
            .map_err(|_| Failure::new(code::OK, ""))?;
        // DE: Geführte Abläufe (Plan G2) starten ihre Befehle selbst als Kindprozesse.
        // EN: Guided flows (plan G2) start their commands themselves as child processes.
        let guided = match choice {
            0 => Some(guide::keygen(lang, None, None).map(|_| ())),
            7 => Some(guide::sign(lang)),
            8 => Some(guide::verify(lang)),
            _ => None,
        };
        if guided.is_some() {
            println!();
            continue;
        }
        let Some(choice_argv) = choice_args(t, lang, choice)? else {
            return Ok(());
        };
        let lang_code = if lang == Lang::De { "de" } else { "en" };
        let mut argv = vec![
            "pqkeep".to_owned(),
            "--lang".to_owned(),
            lang_code.to_owned(),
        ];
        argv.extend(choice_argv);
        if let Err(f) = execute(argv)
            && !f.message.is_empty()
        {
            eprintln!("{}: {}", t.msg_error, f.message);
        }
        println!();
    }
}

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

use dialoguer::{Input, Select};
use pqkeep::security::Lang;

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

/// DE: Baut die Argumente für eine Menüauswahl; `None` = Beenden.
/// EN: Builds the arguments for a menu choice; `None` = quit.
fn choice_args(t: &Texts, choice: usize) -> CliResult<Option<Vec<String>>> {
    let mut argv: Vec<String> = Vec::new();
    match choice {
        1 => {
            eprintln!("Passphrase hint: follow the passphrase rules.");
            let len = ask_default(t.menu_pass_len, "32")?;
            argv.extend(["passphrase".to_owned(), len.trim().to_owned()]);
        }
        2 => {
            eprintln!("Passphrase hint: follow the passphrase rules.");
            argv.push("validate".to_owned());
        }
        3 | 4 => {
            argv.push(if choice == 3 { "inspect" } else { "export" }.to_owned());
            argv.push(ask(t.menu_path, false)?);
            if choice == 4 {
                argv.extend(["--out".to_owned(), ask(t.arg_out, false)?]);
            }
        }
        5 | 6 => {
            argv.push(if choice == 5 { "encrypt" } else { "decrypt" }.to_owned());
            argv.push(ask(t.menu_path, false)?);
            let (flag, prompt) = if choice == 5 {
                ("--to", t.menu_recipient)
            } else {
                ("--key", t.menu_keyfile)
            };
            let extra = ask(prompt, true)?;
            if !extra.is_empty() {
                argv.extend([flag.to_owned(), extra]);
            }
            push_out(&mut argv, t)?;
        }
        9 => argv.push("help".to_owned()),
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
            0 => Some(guide::keygen(lang, None).map(|_| ())),
            7 => Some(guide::sign(lang)),
            8 => Some(guide::verify(lang)),
            _ => None,
        };
        if guided.is_some() {
            println!();
            continue;
        }
        let Some(choice_argv) = choice_args(t, choice)? else {
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

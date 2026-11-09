//! DE: Geführtes Signieren und Prüfen. Ein neuer Signaturschlüssel kann unterwegs erstellt werden.
//! EN: Guided signing and verifying. A new signing key can be created along the way.

use std::path::Path;

use pqkeep::security::Lang;

use super::keygen;
use super::levels::Purpose;
use super::text::guide_texts;
use super::{child, command_line, confirm, path, select};
use crate::cli::io::{CliResult, Failure, code};
use crate::cli::sign_cmd::default_sig;

/// DE: Befehl anzeigen, bestätigen lassen, ausführen. EN: Show, confirm and run a command.
fn run_shown(lang: Lang, args: &[String]) -> CliResult {
    let g = guide_texts(lang);
    eprintln!("\n{}\n  {}\n", g.equivalent, command_line(args));
    if !confirm(g.confirm, true)? {
        return Err(super::cancelled());
    }
    match child(lang, args)? {
        0 => Ok(()),
        c => Err(Failure::new(u8::try_from(c).unwrap_or(code::ERROR), "")),
    }
}

fn sig_default(file: &str) -> String {
    default_sig(Path::new(file))
        .and_then(|p| p.to_str().map(str::to_owned))
        .unwrap_or_default()
}

/// DE: Datei geführt signieren. EN: Sign a file, guided.
pub fn sign(lang: Lang) -> CliResult {
    let g = guide_texts(lang);
    eprintln!("\n{}\n", g.sign_title);
    let file = path(g.sign_file, None, true, g.not_found)?;
    let choices: Vec<&str> = g.key_choice.split('|').collect();
    let key = if select(g.key_path, &choices, 0)? == 1 {
        keygen::run(lang, Some(Purpose::Sign))?.out
    } else {
        path(g.key_path, None, true, g.not_found)?
    };
    let out = path(g.sig_out, Some(&sig_default(&file)), false, g.not_found)?;
    let args: Vec<String> = ["sign", "--key", &key, "--out", &out, "--", &file]
        .map(str::to_owned)
        .to_vec();
    run_shown(lang, &args)
}

/// DE: Signatur geführt prüfen. EN: Verify a signature, guided.
pub fn verify(lang: Lang) -> CliResult {
    let g = guide_texts(lang);
    eprintln!("\n{}\n", g.verify_title);
    let file = path(g.verify_file, None, true, g.not_found)?;
    let public = path(g.pub_path, None, true, g.not_found)?;
    let sig = path(g.sig_path, Some(&sig_default(&file)), true, g.not_found)?;
    let args: Vec<String> = ["verify", "--pub", &public, "--sig", &sig, "--", &file]
        .map(str::to_owned)
        .to_vec();
    run_shown(lang, &args)
}

//! DE: `pqkeep sign` und `pqkeep verify` (U1-2): abgesetzte ML-DSA-87-Signaturen über die
//! Bibliothek `pqkeep::sign`. Ausgabe beim Prüfen eindeutig `[VERIFIED]` bzw. `[INVALID]`
//! (Exit-Code 0 bzw. 7) mit Fingerabdruck des Signierers.
//! EN: `pqkeep sign` and `pqkeep verify` (U1-2): detached ML-DSA-87 signatures via the library
//! `pqkeep::sign`. Verification prints exactly `[VERIFIED]` or `[INVALID]` (exit code 0 or 7)
//! with the signer's fingerprint.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::{ArgMatches, Command, value_parser};
use pqkeep::envelope::{self, Overwrite, hex_encode};
use pqkeep::security::Lang;
use pqkeep::{Error, sign};

use super::args::{base, flag, opt, path};
use super::io::{CliResult, Failure, code, read_passphrase_as};
use super::sign_text::sign_texts;
use super::text::{Texts, texts};

/// DE: Befehle `sign` und `verify`. EN: Commands `sign` and `verify`.
pub fn commands(lang: Lang) -> [Command; 2] {
    let s = sign_texts(lang);
    let t = texts(lang);
    let file = |o: &'static str, h: &'static str| opt(o, h).value_parser(value_parser!(PathBuf));
    [
        base("sign", s.sign_about, s.sign_after, lang)
            .arg(path("file", s.arg_file).required(false))
            .arg(file("key", s.arg_key).short('k'))
            .arg(file("out", s.arg_out).short('o'))
            .arg(flag("passphrase-stdin", t.arg_passphrase_stdin)),
        base("verify", s.verify_about, s.verify_after, lang)
            .arg(path("file", s.arg_file).required(false))
            .arg(file("pub", s.arg_pub).short('p'))
            .arg(file("sig", s.arg_sig).short('s')),
    ]
}

/// DE: Standard-Signaturdatei `<datei>.pqsig`. EN: Default signature file `<file>.pqsig`.
pub fn default_sig(file: &Path) -> Option<PathBuf> {
    let mut name = OsString::from(file.file_name()?);
    name.push(".");
    name.push(sign::EXTENSION);
    Some(file.with_file_name(name))
}

fn arg_path(m: &ArgMatches, id: &str) -> Option<PathBuf> {
    m.get_one::<PathBuf>(id).cloned()
}

/// DE: Signaturdatei (`--out`/`--sig` oder Standard). EN: Signature file (option or default).
pub fn sig_path(m: &ArgMatches, id: &str) -> Option<PathBuf> {
    arg_path(m, id).or_else(|| arg_path(m, "file").and_then(|f| default_sig(&f)))
}

/// DE: `pqkeep sign`. EN: `pqkeep sign`.
pub fn sign(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    let s = sign_texts(lang);
    if arg_path(m, "file").is_none() || arg_path(m, "key").is_none() {
        return Err(Failure::new(code::USAGE, s.need_sign_args));
    }
    let fail = |e: Error| Failure::from_error(&e, lang);
    let file = arg_path(m, "file").unwrap_or_default();
    let out = sig_path(m, "out").ok_or_else(|| fail(Error::InvalidInput { field: "path" }))?;
    if out.exists() {
        return Err(fail(Error::Io(std::io::ErrorKind::AlreadyExists)));
    }
    let (key_file, warnings) =
        envelope::load(&arg_path(m, "key").unwrap_or_default()).map_err(fail)?;
    for w in warnings {
        eprintln!("{}: {}", t.msg_warning, w.message(lang));
    }
    // DE: Vor der Passphrase-Abfrage prüfen. EN: Check before asking for the passphrase.
    if key_file.algorithm() != sign::SIG_ALGORITHM {
        return Err(Failure::new(code::USAGE, s.need_ml_dsa_87));
    }
    let stdin = m.get_flag("passphrase-stdin");
    let pass = read_passphrase_as(t, lang, stdin, false, t.prompt_key_passphrase)?;
    let unlocked = key_file.unlock(&pass).map_err(fail)?;
    drop(pass);
    let signature = sign::sign_file(&unlocked, &file).map_err(fail)?;
    drop(unlocked);
    let json = signature.to_json().map_err(fail)?;
    envelope::write_atomic(&out, json.as_bytes(), Overwrite::No).map_err(fail)?;
    println!("{}: {}", s.signed, out.display());
    println!("{}: {}", s.fingerprint, signature.key_id_hex());
    Ok(())
}

/// DE: `pqkeep verify`. EN: `pqkeep verify`.
pub fn verify(lang: Lang, m: &ArgMatches) -> CliResult {
    let s = sign_texts(lang);
    if arg_path(m, "file").is_none() || arg_path(m, "pub").is_none() {
        return Err(Failure::new(code::USAGE, s.need_verify_args));
    }
    let fail = |e: Error| Failure::from_error(&e, lang);
    let file = arg_path(m, "file").unwrap_or_default();
    let public = envelope::load_public(&arg_path(m, "pub").unwrap_or_default()).map_err(fail)?;
    if public.algorithm() != sign::SIG_ALGORITHM {
        return Err(Failure::new(code::USAGE, s.need_ml_dsa_87));
    }
    let sig_file = sig_path(m, "sig").ok_or_else(|| fail(Error::InvalidInput { field: "path" }))?;
    let signature = sign::load(&sig_file).map_err(fail)?;
    match sign::verify_file(&public, &signature, &file) {
        Ok(ok) => {
            println!("[VERIFIED] {}", file.display());
            let name = &public.metadata().name;
            println!("  {}: {} ({name})", s.signer, hex_encode(&ok.key_id));
            println!("  {}: {}", s.time, ok.created_utc);
            println!("  {}", s.note);
            Ok(())
        }
        Err(Error::InvalidSignature) => {
            println!("[INVALID] {}", file.display());
            println!("  {}", s.invalid);
            if signature.key_id() != public.key_id() {
                println!("  {}: {}", s.other_key, signature.key_id_hex());
            }
            Err(Failure::new(code::INVALID, ""))
        }
        Err(e) => Err(fail(e)),
    }
}

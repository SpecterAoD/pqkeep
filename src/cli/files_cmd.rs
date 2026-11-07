//! DE: Befehle encrypt und decrypt (Datei oder Ordner). Ausgabe nie überschrieben.
//! EN: Commands encrypt and decrypt (file or directory). Output never overwritten.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::ArgMatches;
use pqkeep::crypto::kdf::KdfProfile;
use pqkeep::envelope;
use pqkeep::files::{self, HeaderMode, Protection, Report, SkipReason, Unlock};
use pqkeep::security::{Lang, StrongPassphrase};

use super::io::{CliResult, Failure, code, read_passphrase, read_passphrase_as};
use super::text::Texts;
use super::validate::print_rejection;

fn source(m: &ArgMatches) -> PathBuf {
    m.get_one::<PathBuf>("source").cloned().unwrap_or_default()
}

/// DE: Standardziel beim Verschlüsseln. EN: Default target when encrypting.
pub fn default_encrypted(src: &Path) -> Option<PathBuf> {
    let name = src.file_name()?;
    let mut out = OsString::from(name);
    out.push(".");
    out.push(files::EXTENSION);
    Some(src.with_file_name(out))
}

/// DE: Standardziel beim Entschlüsseln. EN: Default target when decrypting.
pub fn default_decrypted(src: &Path) -> Option<PathBuf> {
    let name = src.file_name()?.to_str()?;
    let suffix = format!(".{}", files::EXTENSION);
    let stem = name.strip_suffix(&suffix).filter(|s| !s.is_empty());
    let new = stem.map_or_else(|| format!("{name}.decrypted"), str::to_owned);
    Some(src.with_file_name(new))
}

fn target(t: &Texts, m: &ArgMatches, default: Option<PathBuf>) -> CliResult<PathBuf> {
    m.get_one::<PathBuf>("out")
        .cloned()
        .or(default)
        .ok_or_else(|| Failure::new(code::USAGE, t.arg_out_optional))
}

fn print_report(t: &Texts, lang: Lang, verb: &str, out: &Path, report: &Report) {
    println!("{verb}: {}", out.display());
    println!(
        "{}: {} / {} / {}",
        t.msg_summary, report.files, report.directories, report.bytes
    );
    for skipped in &report.skipped {
        let reason = match skipped.reason {
            SkipReason::Symlink => t.skip_symlink,
            SkipReason::Special => t.skip_special,
            SkipReason::NonUtf8Name => t.skip_non_utf8,
            _ => t.skip_invalid,
        };
        eprintln!("{}: {} ({reason})", t.msg_skipped, skipped.path);
    }
    let _ = lang;
}

/// DE: `pqkeep encrypt`. EN: `pqkeep encrypt`.
pub fn encrypt(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    let fail = |e: pqkeep::Error| Failure::from_error(&e, lang);
    let src = source(m);
    let out = target(t, m, default_encrypted(&src))?;
    let report = if let Some(to) = m.get_one::<PathBuf>("to") {
        let public = envelope::load_public(to).map_err(fail)?;
        files::encrypt(&src, &out, &Protection::Recipient(&public)).map_err(fail)?
    } else {
        let profile = if m.get_one::<String>("profile").map(String::as_str) == Some("hardened") {
            KdfProfile::Hardened
        } else {
            KdfProfile::Standard
        };
        let pass = read_passphrase(t, lang, m.get_flag("passphrase-stdin"), true)?;
        let strong = StrongPassphrase::try_from(pass).map_err(|rejection| {
            print_rejection(t, lang, &rejection);
            Failure::new(code::WEAK, "")
        })?;
        let protection = Protection::Passphrase {
            passphrase: &strong,
            params: profile.params(),
        };
        files::encrypt(&src, &out, &protection).map_err(fail)?
    };
    print_report(t, lang, t.msg_encrypted, &out, &report);
    Ok(())
}

/// DE: `pqkeep decrypt`. EN: `pqkeep decrypt`.
pub fn decrypt(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    let fail = |e: pqkeep::Error| Failure::from_error(&e, lang);
    let src = source(m);
    let header = files::inspect(&src).map_err(fail)?;
    let out = target(t, m, default_decrypted(&src))?;
    let stdin = m.get_flag("passphrase-stdin");
    let key = m.get_one::<PathBuf>("key");
    let report = match (&header.mode, key) {
        (HeaderMode::Recipient { .. }, None) => {
            return Err(Failure::new(code::USAGE, t.msg_need_key));
        }
        (HeaderMode::Recipient { .. }, Some(key_path)) => {
            let (key_file, warnings) = envelope::load(key_path).map_err(fail)?;
            for w in warnings {
                eprintln!("{}: {}", t.msg_warning, w.message(lang));
            }
            let pass = read_passphrase_as(t, lang, stdin, false, t.prompt_key_passphrase)?;
            let unlocked = key_file.unlock(&pass).map_err(fail)?;
            drop(pass);
            files::decrypt(&src, &out, &Unlock::Key(&unlocked)).map_err(fail)?
        }
        (HeaderMode::Passphrase { .. }, key) => {
            if key.is_some() {
                eprintln!("{}: {}", t.msg_warning, t.msg_no_key_needed);
            }
            let pass = read_passphrase(t, lang, stdin, false)?;
            files::decrypt(&src, &out, &Unlock::Passphrase(&pass)).map_err(fail)?
        }
    };
    print_report(t, lang, t.msg_decrypted, &out, &report);
    Ok(())
}

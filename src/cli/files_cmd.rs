//! DE: Befehle encrypt und decrypt (Datei oder Ordner). Ausgabe nie überschrieben.
//! EN: Commands encrypt and decrypt (file or directory). Output never overwritten.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::ArgMatches;
use pqkeep::crypto::factor::Factor;
use pqkeep::crypto::kdf::{KdfParams, KdfProfile};
use pqkeep::envelope;
use pqkeep::files::{self, PassphraseAccess, Protection, Report, SkipReason};
use pqkeep::security::{Lang, StrongPassphrase};

use super::io::{CliResult, Failure, code, read_confirmed_stdin, read_passphrase};
use super::text::Texts;
use super::validate::print_rejection;

/// DE: Alle Quellen (eine oder mehrere). EN: All sources (one or more).
pub(super) fn sources(m: &ArgMatches) -> Vec<PathBuf> {
    m.get_many::<PathBuf>("source")
        .map(|v| v.cloned().collect())
        .unwrap_or_default()
}

fn source(m: &ArgMatches) -> PathBuf {
    sources(m).into_iter().next().unwrap_or_default()
}

/// DE: Freier Name neben dem Ziel: `name.ext`, sonst `name (2).ext` … `name (99).ext`.
/// EN: Free name next to the target: `name.ext`, else `name (2).ext` … `name (99).ext`.
pub fn free_target(target: &Path) -> Option<PathBuf> {
    if !target.exists() {
        return Some(target.to_path_buf());
    }
    let stem = target.file_stem()?.to_str()?;
    let ext = target.extension().and_then(|e| e.to_str());
    (2..100)
        .map(|n| {
            let name = match ext {
                Some(e) => format!("{stem} ({n}).{e}"),
                None => format!("{stem} ({n})"),
            };
            target.with_file_name(name)
        })
        .find(|p| !p.exists())
}

/// DE: Standardziel; mit `--rename` ein freier Name. EN: Default target; with `--rename` a free name.
pub(super) fn default_for(m: &ArgMatches, default: Option<PathBuf>) -> Option<PathBuf> {
    if m.get_flag("rename") {
        default.as_deref().and_then(free_target)
    } else {
        default
    }
}

/// DE: Eingelesener Schutz: geprüfte Passphrase (optional mit Faktordatei) und/oder Empfänger.
/// EN: Read protection: checked passphrase (optional factor file) and/or recipients.
pub(super) struct OwnedProtection {
    passphrase: Option<(StrongPassphrase, KdfParams, Option<Factor>)>,
    recipients: Vec<envelope::PublicKeyFile>,
}

impl OwnedProtection {
    /// DE: Ruft `f` mit dem Schutz auf. Die Bibliothek schreibt v1, wenn ein einzelner Zugang
    /// ohne Faktordatei genügt (Byte für Byte wie bisher), sonst v2.
    /// EN: Calls `f` with the protection. The library writes v1 if a single slot without factor
    /// file suffices (byte for byte as before), else v2.
    pub(super) fn with<R>(&self, f: impl FnOnce(&Protection<'_>) -> R) -> R {
        let recipients: Vec<&envelope::PublicKeyFile> = self.recipients.iter().collect();
        let passphrase = self
            .passphrase
            .as_ref()
            .map(|(passphrase, params, factor)| PassphraseAccess {
                passphrase,
                params: *params,
                factor: factor.as_ref(),
            });
        f(&Protection::Slots {
            passphrase,
            recipients: &recipients,
        })
    }
}

/// DE: Empfänger laden und/oder neue Passphrase (zweimal) lesen und prüfen. Empfänger und
/// Faktordatei werden vor der Passphrase-Abfrage geprüft.
/// EN: Load the recipients and/or read and check a new passphrase (twice). Recipients and factor
/// file are checked before the passphrase prompt.
pub(super) fn read_protection(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult<OwnedProtection> {
    super::recipients::check_factor(m, lang)?;
    let recipients = super::recipients::load(m, lang)?;
    if !recipients.is_empty() && !m.get_flag(super::recipients::WITH_PASSPHRASE) {
        return Ok(OwnedProtection {
            passphrase: None,
            recipients,
        });
    }
    let profile = if m.get_one::<String>("profile").map(String::as_str) == Some("hardened") {
        KdfProfile::Hardened
    } else {
        KdfProfile::Standard
    };
    let factor = super::factor_cmd::load(m, lang)?;
    let pass = if m.get_flag("confirm-stdin") {
        read_confirmed_stdin(t, lang)?
    } else {
        read_passphrase(t, lang, m.get_flag("passphrase-stdin"), true)?
    };
    let strong = super::validate::strong(m, pass).map_err(|rejection| {
        print_rejection(t, lang, &rejection);
        Failure::new(code::WEAK, "")
    })?;
    Ok(OwnedProtection {
        passphrase: Some((strong, profile.params(), factor)),
        recipients,
    })
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

pub(super) fn print_report(t: &Texts, lang: Lang, verb: &str, out: &Path, report: &Report) {
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
/// DE: Verstecktes `--temp-tag` (vom Kontextmenü) an die Bibliothek geben.
/// EN: Pass the hidden `--temp-tag` (from the context menu) to the library.
fn apply_temp_tag(m: &ArgMatches, lang: Lang) -> CliResult {
    match m.get_one::<String>("temp-tag") {
        Some(tag) => files::set_temp_tag(tag).map_err(|e| Failure::from_error(&e, lang)),
        None => Ok(()),
    }
}

pub fn encrypt(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    apply_temp_tag(m, lang)?;
    let all = sources(m);
    if all.len() > 1 || m.get_flag("each") {
        return super::files_many::encrypt(t, lang, m, &all);
    }
    let src = source(m);
    let out = target(t, m, default_for(m, default_encrypted(&src)))?;
    let protection = read_protection(t, lang, m)?;
    let report = protection
        .with(|p| files::encrypt(&src, &out, p))
        .map_err(|e| Failure::from_error(&e, lang))?;
    print_report(t, lang, t.msg_encrypted, &out, &report);
    Ok(())
}

/// DE: `pqkeep decrypt`. EN: `pqkeep decrypt`.
pub fn decrypt(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    apply_temp_tag(m, lang)?;
    let all = sources(m);
    if all.len() > 1 {
        return super::files_many::decrypt(t, lang, m, &all);
    }
    let fail = |e: pqkeep::Error| Failure::from_error(&e, lang);
    let src = source(m);
    let access = super::unlock::Access::read(&src).map_err(fail)?;
    let out = target(t, m, default_for(m, default_decrypted(&src)))?;
    let use_key = access.use_key(m.get_one::<PathBuf>("key").is_some());
    let opened = super::unlock::for_decrypt(t, lang, m, use_key, access.passphrase)?;
    let report = files::decrypt(&src, &out, &opened.get()).map_err(fail)?;
    drop(opened);
    print_report(t, lang, t.msg_decrypted, &out, &report);
    Ok(())
}

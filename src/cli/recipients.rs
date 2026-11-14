//! DE: Mehrere Empfänger beim Verschlüsseln (`--to` mehrfach, bis 64; #47). Alle öffentlichen
//! Schlüssel werden vor der Passphrase-Abfrage geladen und geprüft: nur ML-KEM, keine Doppel,
//! höchstens 64. Ab zwei Empfängern (oder mit `--with-passphrase`) wird jeder mit Fingerabdruck
//! aufgelistet. Ein einzelner Empfänger ohne Zusätze bleibt Format v1 (D3).
//! EN: Several recipients when encrypting (repeated `--to`, up to 64; #47). All public keys are
//! loaded and checked before the passphrase prompt: ML-KEM only, no duplicates, at most 64. From
//! two recipients on (or with `--with-passphrase`) each is listed with its fingerprint. A single
//! recipient without extras stays format v1 (D3).

use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::ArgMatches;
use pqkeep::crypto::KeyAlgorithm;
use pqkeep::envelope::{self, PublicKeyFile};
use pqkeep::files::MAX_RECIPIENTS;
use pqkeep::security::Lang;

use super::io::{CliResult, Failure, code, fingerprint, localize};

/// DE: Name des Schalters „Empfänger und eigene Passphrase“. EN: Name of the combined switch.
pub const WITH_PASSPHRASE: &str = "with-passphrase";

/// DE: Hilfetext für `--with-passphrase`. EN: Help text for `--with-passphrase`.
pub fn help(lang: Lang) -> &'static str {
    match lang {
        Lang::De => {
            "Zusätzlich zu den Empfängern (--to) eine eigene Passphrase setzen (optional mit --factor-file); erzeugt Format v2"
        }
        Lang::En => {
            "Set an own passphrase in addition to the recipients (--to) (optionally with --factor-file); writes format v2"
        }
    }
}

/// DE: Meldungen zu Empfängern (Feldnamen der Bibliothek bzw. dieses Moduls).
/// EN: Messages about recipients (field names of the library or this module).
pub fn message(field: &str) -> Option<&'static str> {
    Some(match field {
        // DE: Beim Entschlüsseln: eigener Schlüssel nicht unter den Empfängern.
        // EN: When decrypting: own key not among the recipients.
        "recipient" => {
            "Dieser Schlüssel ist nicht unter den Empfängern der Datei (pqkeep inspect zeigt sie) / this key is not among the file's recipients (pqkeep inspect shows them)"
        }
        "recipient_kind" => {
            "Kein öffentlicher Schlüssel zum Verschlüsseln (ML-KEM, *.pub.json) / not a public encryption key (ML-KEM, *.pub.json)"
        }
        "recipient_count" => "Höchstens 64 Empfänger je Datei / at most 64 recipients per file",
        "recipient_duplicate" => {
            "Derselbe Empfänger ist mehrfach angegeben / the same recipient is given more than once"
        }
        "factor_needs_passphrase" => {
            "--factor-file gehört zur Passphrase – zusammen mit --to nur mit --with-passphrase / --factor-file belongs to the passphrase – with --to only together with --with-passphrase"
        }
        _ => return None,
    })
}

fn usage(field: &str, lang: Lang) -> Failure {
    Failure::new(code::USAGE, localize(message(field).unwrap_or(field), lang))
}

/// DE: Alle `--to`-Pfade in der angegebenen Reihenfolge. EN: All `--to` paths in the given order.
pub fn paths(m: &ArgMatches) -> Vec<PathBuf> {
    m.get_many::<PathBuf>("to")
        .map(|v| v.cloned().collect())
        .unwrap_or_default()
}

/// DE: Prüft eine Liste geladener Empfänger (Typ, Anzahl, Doppel) und liefert den Feldnamen des
/// ersten Fehlers. EN: Checks a list of loaded recipients (kind, count, duplicates) and returns
/// the field name of the first error.
pub fn check(keys: &[PublicKeyFile]) -> Result<(), &'static str> {
    if keys.len() > MAX_RECIPIENTS {
        return Err("recipient_count");
    }
    let mut seen = BTreeSet::new();
    for key in keys {
        if !matches!(key.algorithm(), KeyAlgorithm::Kem(_)) {
            return Err("recipient_kind");
        }
        if !seen.insert(key.key_id()) {
            return Err("recipient_duplicate");
        }
    }
    Ok(())
}

/// DE: Zeile „Empfänger i/n: Name (Fingerabdruck)“. EN: Line "Recipient i/n: name (fingerprint)".
pub fn line(lang: Lang, index: usize, total: usize, key: &PublicKeyFile) -> String {
    let label = match lang {
        Lang::De => "Empfänger",
        Lang::En => "Recipient",
    };
    let name = &key.metadata().name;
    let fp = fingerprint(&key.key_id_hex());
    format!("{label} {}/{total}: {name} ({fp})", index + 1)
}

/// DE: Lädt und prüft alle Empfänger; listet sie bei mehreren auf (stderr, vor der Passphrase).
/// EN: Loads and checks all recipients; lists them if several (stderr, before the passphrase).
pub fn load(m: &ArgMatches, lang: Lang) -> CliResult<Vec<PublicKeyFile>> {
    let all = paths(m);
    if all.len() > MAX_RECIPIENTS {
        return Err(usage("recipient_count", lang));
    }
    let mut keys = Vec::with_capacity(all.len());
    for path in &all {
        keys.push(envelope::load_public(path).map_err(|e| Failure::from_error(&e, lang))?);
    }
    check(&keys).map_err(|field| usage(field, lang))?;
    if keys.len() > 1 || m.get_flag(WITH_PASSPHRASE) {
        for (i, key) in keys.iter().enumerate() {
            eprintln!("{}", line(lang, i, keys.len(), key));
        }
    }
    Ok(keys)
}

/// DE: `--factor-file` mit `--to` nur zusammen mit `--with-passphrase`.
/// EN: `--factor-file` with `--to` only together with `--with-passphrase`.
pub fn check_factor(m: &ArgMatches, lang: Lang) -> CliResult {
    let factor = super::factor_cmd::path(m).is_some();
    if factor && m.contains_id("to") && !m.get_flag(WITH_PASSPHRASE) {
        return Err(usage("factor_needs_passphrase", lang));
    }
    Ok(())
}

#[cfg(test)]
#[path = "recipients_tests.rs"]
mod tests;

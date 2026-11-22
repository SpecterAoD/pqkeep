//! DE: `pqkeep inspect --json` (#85): dieselben Angaben wie die Textausgabe, als Objekt nach
//! `docs/JSON.md` – öffentliche Schlüssel, Schlüsseldateien (Metadaten, KDF, Faktordatei,
//! Warnungen) und verschlüsselte Dateien v1/v2 (Inhalt, Zugänge). Nur Kopfdaten, nichts Geheimes.
//! EN: `pqkeep inspect --json` (#85): the same data as the text output, as an object per
//! `docs/JSON.md` – public keys, key files (metadata, KDF, factor file, warnings) and encrypted
//! files v1/v2 (content, slots). Header data only, nothing secret.

use std::path::{Path, PathBuf};

use clap::ArgMatches;
use pqkeep::crypto::KeyAlgorithm;
use pqkeep::crypto::kdf::KdfParams;
use pqkeep::envelope::{self, Metadata};
use pqkeep::files::{self, Content, HeaderMode, Slot};
use pqkeep::security::Lang;
use serde_json::{Map, Value, json};

use super::io::{CliResult, Failure, code};

fn kdf(p: &KdfParams) -> Value {
    json!({ "memory_kib": p.memory_kib, "iterations": p.iterations,
        "parallelism": p.parallelism })
}

fn metadata(m: &Metadata) -> Value {
    json!({ "name": m.name, "organization": m.organization, "company": m.company,
        "department": m.department, "account_type": m.account_type })
}

fn content(c: Content) -> &'static str {
    match c {
        Content::File => "file",
        Content::Directory => "directory",
    }
}

fn recipient(algorithm: pqkeep::crypto::KemAlgorithm, id: &[u8]) -> Value {
    json!({ "kind": "recipient", "algorithm": KeyAlgorithm::Kem(algorithm).id(),
        "recipient_id": envelope::hex_encode(id) })
}

/// DE: Verschlüsselte Datei: Version, Inhalt, Zugänge. EN: Encrypted file: version, content, slots.
fn encrypted(path: &Path) -> pqkeep::Result<Map<String, Value>> {
    let (version, kind, slots, signer) = match files::inspect(path) {
        Err(pqkeep::Error::Unsupported) => {
            let header = files::inspect_v2(path)?;
            let slots = header.slots.iter().map(|slot| match slot {
                Slot::Passphrase { factor, params, .. } => json!({ "kind": "passphrase",
                    "kdf": kdf(params), "factor_required": factor }),
                Slot::Recipient {
                    algorithm,
                    recipient_id,
                    ..
                } => recipient(*algorithm, recipient_id),
            });
            // DE: Absender nur aus dem Header – ungeprüft (#44). EN: Sender from the header only – unverified.
            let signer = header.signer.as_ref().map_or(
                Value::Null,
                |s| json!({ "key_id": envelope::hex_encode(&s.key_id()), "verified": false }),
            );
            let slots = slots.collect::<Vec<_>>();
            (header.version(), header.content, slots, signer)
        }
        other => {
            let header = other?;
            let slot = match &header.mode {
                HeaderMode::Passphrase { params, .. } => json!({ "kind": "passphrase",
                    "kdf": kdf(params), "factor_required": false }),
                HeaderMode::Recipient {
                    algorithm,
                    recipient_id,
                    ..
                } => recipient(*algorithm, recipient_id),
            };
            (1, header.content, vec![slot], Value::Null)
        }
    };
    let mut body = Map::new();
    body.insert("type".into(), "encrypted_file".into());
    body.insert("format_version".into(), version.into());
    body.insert("content".into(), content(kind).into());
    body.insert("slots".into(), slots.into());
    body.insert("signer".into(), signer);
    Ok(body)
}

/// DE: Schlüsseldatei bzw. öffentlicher Schlüssel. EN: Key file or public key.
fn key(path: &Path, lang: Lang) -> pqkeep::Result<Map<String, Value>> {
    let text = envelope::read_limited(path)?;
    let mut body = Map::new();
    if let Ok(public) = envelope::PublicKeyFile::from_json(&text) {
        body.insert("type".into(), "public_key".into());
        body.insert("algorithm".into(), public.algorithm().id().into());
        body.insert("key_id".into(), public.key_id_hex().into());
        body.insert("created_utc".into(), public.created_utc().into());
        body.insert("metadata".into(), metadata(public.metadata()));
        return Ok(body);
    }
    let (key, warnings) = envelope::load(path)?;
    body.insert("type".into(), "key_file".into());
    body.insert("algorithm".into(), key.algorithm().id().into());
    body.insert("key_id".into(), key.key_id_hex().into());
    body.insert("created_utc".into(), key.created_utc().into());
    body.insert("metadata".into(), metadata(key.metadata()));
    body.insert("kdf".into(), kdf(&key.kdf_params()));
    body.insert("factor_required".into(), key.needs_factor().into());
    let warnings: Vec<String> = warnings.iter().map(|w| w.message(lang)).collect();
    body.insert("warnings".into(), warnings.into());
    Ok(body)
}

/// DE: `pqkeep inspect --json`. EN: `pqkeep inspect --json`.
pub fn run(lang: Lang, m: &ArgMatches) -> CliResult<(Map<String, Value>, u8)> {
    let path = m.get_one::<PathBuf>("file").cloned().unwrap_or_default();
    let body = if super::keys::is_encrypted_file(&path) {
        encrypted(&path)
    } else {
        key(&path, lang)
    };
    let mut body = body.map_err(|e| Failure::from_error(&e, lang))?;
    body.insert("file".into(), path.to_string_lossy().into());
    Ok((body, code::OK))
}

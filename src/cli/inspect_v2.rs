//! DE: `pqkeep inspect` für verschlüsselte Dateien im Format v2: Inhalt und alle Zugänge
//! (Passphrase mit/ohne Faktordatei, Empfänger mit Fingerabdruck) – ohne Passphrase/Schlüssel.
//! EN: `pqkeep inspect` for encrypted files in format v2: content and all access slots
//! (passphrase with/without factor file, recipients with fingerprint) – no passphrase/key needed.

use std::path::Path;

use pqkeep::crypto::KeyAlgorithm;
use pqkeep::envelope;
use pqkeep::files::{self, Content, Slot};
use pqkeep::security::Lang;

use super::io::{CliResult, Failure, fingerprint};
use super::text::Texts;

/// DE: Gibt Inhalt und Zugänge aus. EN: Prints content and slots.
pub fn print(t: &Texts, lang: Lang, path: &Path) -> CliResult {
    let header = files::inspect_v2(path).map_err(|e| Failure::from_error(&e, lang))?;
    println!("{}: {}", t.lbl_type, t.type_encrypted);
    let content = match header.content {
        Content::File => t.content_file,
        Content::Directory => t.content_dir,
    };
    println!("{}: {content}", t.lbl_content);
    for slot in header.slots {
        match slot {
            Slot::Passphrase { factor, params, .. } => {
                println!("{}: {}", t.lbl_mode, t.mode_passphrase);
                let (m, i, p) = (params.memory_kib, params.iterations, params.parallelism);
                println!("{}: m={m} KiB, t={i}, p={p}", t.lbl_kdf);
                if factor {
                    println!("{}", super::factor_cmd::needed(lang));
                }
            }
            Slot::Recipient {
                algorithm,
                recipient_id,
                ..
            } => {
                println!("{}: {}", t.lbl_mode, t.mode_recipient);
                println!("{}: {}", t.lbl_algorithm, KeyAlgorithm::Kem(algorithm).id());
                let hex = envelope::hex_encode(&recipient_id);
                println!("{}: {}", t.lbl_recipient, fingerprint(&hex));
            }
        }
    }
    Ok(())
}

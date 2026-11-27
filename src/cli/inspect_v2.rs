//! DE: `pqkeep inspect` für verschlüsselte Dateien im Format v2/v3: Inhalt und alle Zugänge
//! (Passphrase mit/ohne Faktordatei, Empfänger mit Fingerabdruck), bei v3 der Absender (ungeprüft)
//! – ohne Passphrase/Schlüssel.
//! EN: `pqkeep inspect` for encrypted files in format v2/v3: content and all access slots
//! (passphrase with/without factor file, recipients with fingerprint), for v3 the sender
//! (unverified) – no passphrase/key needed.

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
        Content::Stream => t.content_stream,
    };
    println!("{}: {content}", t.lbl_content);
    if padded(&header) {
        let text = "Größe verborgen (Füllung, Format v4) / size hidden (padding, format v4)";
        println!("{}", super::io::localize(text, lang));
    }
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
            Slot::Anonymous { .. } => {
                println!("{}: {}", t.lbl_mode, t.mode_recipient);
                let text = "anonym, ML-KEM-1024, experimentell (#340) / anonymous, ML-KEM-1024, experimental (#340)";
                println!("{}: {}", t.lbl_recipient, super::io::localize(text, lang));
            }
        }
    }
    super::signing::print_unverified(lang, header.signer.as_ref());
    Ok(())
}

/// DE: Füllung (Format v4, Bit PAD)? EN: Padding (format v4, bit PAD)?
pub(super) fn padded(header: &files::HeaderV2) -> bool {
    header
        .v4
        .as_ref()
        .is_some_and(|v4| v4.options & files::format_v4::OPT_PAD != 0)
}

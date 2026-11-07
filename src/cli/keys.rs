//! DE: Befehle rund um Schlüssel: generate, export, inspect.
//! EN: Key-related commands: generate, export, inspect.

use std::path::{Path, PathBuf};

use clap::ArgMatches;
use pqc_keyforge::crypto::kdf::KdfProfile;
use pqc_keyforge::crypto::{DsaAlgorithm, KemAlgorithm, KeyAlgorithm};
use pqc_keyforge::envelope::{self, KeyFile, Metadata, Overwrite, PUBLIC_MAGIC};
use pqc_keyforge::files::{self, Content, HeaderMode};
use pqc_keyforge::security::{Lang, StrongPassphrase};

use super::io::{CliResult, Failure, allow_overwrite, code, fingerprint, read_passphrase};
use super::text::Texts;
use super::validate::print_rejection;

fn algorithm(name: &str) -> KeyAlgorithm {
    match name {
        "ml-kem-512" => KeyAlgorithm::Kem(KemAlgorithm::MlKem512),
        "ml-kem-1024" => KeyAlgorithm::Kem(KemAlgorithm::MlKem1024),
        "ml-dsa-44" => KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa44),
        "ml-dsa-65" => KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa65),
        "ml-dsa-87" => KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87),
        "aes-256" => KeyAlgorithm::Aes256,
        _ => KeyAlgorithm::Kem(KemAlgorithm::MlKem768),
    }
}

fn s(m: &ArgMatches, id: &str) -> Option<String> {
    m.get_one::<String>(id).cloned()
}

fn target(t: &Texts, m: &ArgMatches) -> CliResult<(PathBuf, Overwrite)> {
    let out = m.get_one::<PathBuf>("out").cloned().unwrap_or_default();
    let replace = allow_overwrite(t, &out, m.get_flag("force"), m.get_flag("yes"))?;
    Ok((
        out,
        if replace {
            Overwrite::Yes
        } else {
            Overwrite::No
        },
    ))
}

/// DE: `keyforge generate`. EN: `keyforge generate`.
pub fn generate(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    let alg = algorithm(&s(m, "algorithm").unwrap_or_default());
    let meta = Metadata {
        name: s(m, "name").unwrap_or_default(),
        organization: s(m, "organization"),
        company: s(m, "company"),
        department: s(m, "department"),
        account_type: s(m, "account-type"),
    };
    let profile = if s(m, "profile").as_deref() == Some("hardened") {
        KdfProfile::Hardened
    } else {
        KdfProfile::Standard
    };
    let (out, overwrite) = target(t, m)?;
    let fail = |e: pqc_keyforge::Error| Failure::from_error(&e, lang);
    meta.normalized().map_err(fail)?;
    let pass = read_passphrase(t, lang, m.get_flag("passphrase-stdin"), true)?;
    let strong = match StrongPassphrase::try_from(pass) {
        Ok(p) => p,
        Err(rejection) => {
            print_rejection(t, lang, &rejection);
            return Err(Failure::new(code::WEAK, ""));
        }
    };
    let key = KeyFile::generate(&strong, alg, &meta, &profile.params()).map_err(fail)?;
    drop(strong);
    envelope::save(&key, &out, overwrite).map_err(fail)?;
    println!("{}: {}", t.msg_created, out.display());
    println!("{}: {}", t.lbl_algorithm, alg.id());
    println!("{}: {}", t.msg_fingerprint, fingerprint(&key.key_id_hex()));
    eprintln!("{}", t.msg_metadata_plaintext);
    Ok(())
}

/// DE: `keyforge export`. EN: `keyforge export`.
pub fn export(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    let fail = |e: pqc_keyforge::Error| Failure::from_error(&e, lang);
    let file = m.get_one::<PathBuf>("file").cloned().unwrap_or_default();
    let (key, _warnings) = envelope::load(&file).map_err(fail)?;
    let public = key.public_part().map_err(fail)?;
    let (out, overwrite) = target(t, m)?;
    envelope::save_public(&public, &out, overwrite).map_err(fail)?;
    println!("{}: {}", t.msg_exported, out.display());
    println!(
        "{}: {}",
        t.msg_fingerprint,
        fingerprint(&public.key_id_hex())
    );
    eprintln!("{}", t.msg_verify_fingerprint);
    Ok(())
}

fn print_meta(t: &Texts, meta: &Metadata) {
    println!("{}: {}", t.lbl_name, meta.name);
    let optional = [
        (t.lbl_organization, &meta.organization),
        (t.lbl_company, &meta.company),
        (t.lbl_department, &meta.department),
        (t.lbl_account_type, &meta.account_type),
    ];
    for (label, value) in optional {
        if let Some(v) = value {
            println!("{label}: {v}");
        }
    }
}

/// DE: `keyforge inspect`. EN: `keyforge inspect`.
pub fn inspect(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    let fail = |e: pqc_keyforge::Error| Failure::from_error(&e, lang);
    let file = m.get_one::<PathBuf>("file").cloned().unwrap_or_default();
    if is_encrypted_file(&file) {
        return inspect_encrypted(t, lang, &file);
    }
    let text = envelope::read_limited(&file).map_err(fail)?;
    if text.contains(PUBLIC_MAGIC) {
        let key = envelope::PublicKeyFile::from_json(&text).map_err(fail)?;
        println!("{}: {}", t.lbl_type, t.type_public);
        println!("{}: {}", t.lbl_algorithm, key.algorithm().id());
        println!("{}: {}", t.lbl_key_id, fingerprint(&key.key_id_hex()));
        println!("{}: {}", t.lbl_created, key.created_utc());
        print_meta(t, key.metadata());
        return Ok(());
    }
    let (key, warnings) = envelope::load(&file).map_err(fail)?;
    let k = key.kdf_params();
    println!("{}: {}", t.lbl_type, t.type_key);
    println!("{}: {}", t.lbl_algorithm, key.algorithm().id());
    println!("{}: {}", t.lbl_key_id, fingerprint(&key.key_id_hex()));
    println!("{}: {}", t.lbl_created, key.created_utc());
    print_meta(t, key.metadata());
    println!(
        "{}: m={} KiB, t={}, p={}",
        t.lbl_kdf, k.memory_kib, k.iterations, k.parallelism
    );
    for w in warnings {
        eprintln!("{}: {}", t.msg_warning, w.message(lang));
    }
    Ok(())
}

fn is_encrypted_file(path: &Path) -> bool {
    let mut magic = [0u8; 8];
    std::fs::File::open(path)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut magic))
        .is_ok()
        && &magic == files::format::MAGIC
}

fn inspect_encrypted(t: &Texts, lang: Lang, path: &Path) -> CliResult {
    let header = files::inspect(path).map_err(|e| Failure::from_error(&e, lang))?;
    println!("{}: {}", t.lbl_type, t.type_encrypted);
    let content = match header.content {
        Content::File => t.content_file,
        Content::Directory => t.content_dir,
    };
    println!("{}: {content}", t.lbl_content);
    match header.mode {
        HeaderMode::Passphrase { params, .. } => {
            println!("{}: {}", t.lbl_mode, t.mode_passphrase);
            let (m, i, p) = (params.memory_kib, params.iterations, params.parallelism);
            println!("{}: m={m} KiB, t={i}, p={p}", t.lbl_kdf);
        }
        HeaderMode::Recipient {
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
    Ok(())
}

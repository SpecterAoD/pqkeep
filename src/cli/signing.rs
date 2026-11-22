//! DE: Absender-Signatur in `.pqkf` auf der Kommandozeile (#44, `docs/V3_SIGNED.md`):
//! `--sign-with <schlüssel>` (+ `--sign-factor-file`) beim Verschlüsseln, `--signer <pub>` beim
//! Entschlüsseln und Prüfen. Algorithmus und Faktordatei werden vor jeder Passphrase-Abfrage
//! geprüft. Ohne Terminal gibt es nur **eine** Passphrase-Quelle; braucht die Datei selbst eine
//! Passphrase, ist `--sign-with` deshalb nur im Dialog möglich (sonst eindeutige Bedienfehler).
//! EN: Sender signature inside `.pqkf` on the command line (#44, `docs/V3_SIGNED.md`):
//! `--sign-with <key>` (+ `--sign-factor-file`) when encrypting, `--signer <pub>` when decrypting
//! and checking. Algorithm and factor file are checked before any passphrase prompt. Without a
//! terminal there is only **one** passphrase source; if the file itself needs a passphrase,
//! `--sign-with` is therefore only possible interactively (otherwise a clear usage error).

use std::path::PathBuf;

use clap::{Arg, ArgMatches, value_parser};
use pqkeep::crypto::factor::Factor;
use pqkeep::crypto::{DsaAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{self, PublicKeyFile, UnlockedKey};
use pqkeep::files::{SignedBy, Signer};
use pqkeep::security::Lang;
use pqkeep::{Error, Result};

use super::args::opt;
use super::io::{CliResult, Failure, code, fingerprint, read_passphrase_as};
use super::text::Texts;

/// DE: Optionsnamen. EN: Option names.
pub const SIGN_WITH: &str = "sign-with";
/// DE: Faktordatei des Signaturschlüssels. EN: Factor file of the signing key.
pub const SIGN_FACTOR: &str = "sign-factor-file";
/// DE: Verlangter Absender. EN: Required sender.
pub const SIGNER: &str = "signer";

const ML_DSA_87: KeyAlgorithm = KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87);

struct SignTexts {
    arg_sign_with: &'static str,
    arg_sign_factor: &'static str,
    arg_signer: &'static str,
    prompt: &'static str,
    signed_by: &'static str,
    unverified: &'static str,
    one_source: &'static str,
    need_dsa: &'static str,
}

const DE: SignTexts = SignTexts {
    arg_sign_with: "Datei zusätzlich mit diesem ML-DSA-87-Schlüssel signieren (Absender-Signatur, Format v3)",
    arg_sign_factor: "Faktordatei des Signaturschlüssels (nur wenn dieser eine verlangt)",
    arg_signer: "Datei muss von diesem Absender signiert sein (öffentlicher ML-DSA-87-Schlüssel); sonst Fehler, keine Ausgabe",
    prompt: "Passphrase des Signaturschlüssels",
    signed_by: "Signiert von (geprüft)",
    unverified: "Absender (ungeprüft, prüfen mit pqkeep check oder beim Entschlüsseln)",
    one_source: "--sign-with braucht eine eigene Passphrase; zusammen mit einer Datei-Passphrase nur im Dialog (ohne --passphrase-stdin/--passphrase-file/--batch)",
    need_dsa: "Für die Absender-Signatur wird ein ML-DSA-87-Schlüssel gebraucht (--sign-with: *.key.json, --signer: *.pub.json)",
};

const EN: SignTexts = SignTexts {
    arg_sign_with: "Additionally sign the file with this ML-DSA-87 key (sender signature, format v3)",
    arg_sign_factor: "Factor file of the signing key (only if it requires one)",
    arg_signer: "File must be signed by this sender (public ML-DSA-87 key); otherwise error, no output",
    prompt: "Passphrase of the signing key",
    signed_by: "Signed by (verified)",
    unverified: "Sender (unverified, verify with pqkeep check or when decrypting)",
    one_source: "--sign-with needs its own passphrase; together with a file passphrase only interactively (without --passphrase-stdin/--passphrase-file/--batch)",
    need_dsa: "The sender signature needs an ML-DSA-87 key (--sign-with: *.key.json, --signer: *.pub.json)",
};

fn texts(lang: Lang) -> &'static SignTexts {
    if lang == Lang::De { &DE } else { &EN }
}

fn path(m: &ArgMatches, id: &str) -> Option<PathBuf> {
    m.try_get_one::<PathBuf>(id).ok().flatten().cloned()
}

/// DE: Alle angegebenen Pfade (für die Sandbox, nur lesen). EN: All given paths (sandbox, read only).
pub fn paths(m: &ArgMatches) -> Vec<PathBuf> {
    [SIGN_WITH, SIGN_FACTOR, SIGNER]
        .iter()
        .filter_map(|id| path(m, id))
        .collect()
}

/// DE: Optionen für `encrypt`. EN: Options for `encrypt`.
pub fn encrypt_args(lang: Lang) -> [Arg; 2] {
    let s = texts(lang);
    [
        opt(SIGN_WITH, s.arg_sign_with).value_parser(value_parser!(PathBuf)),
        opt(SIGN_FACTOR, s.arg_sign_factor)
            .value_parser(value_parser!(PathBuf))
            .requires(SIGN_WITH),
    ]
}

/// DE: Option `--signer` für `decrypt` und `check`. EN: Option `--signer` for `decrypt` and `check`.
pub fn signer_arg(lang: Lang) -> Arg {
    opt(SIGNER, texts(lang).arg_signer).value_parser(value_parser!(PathBuf))
}

fn fail(lang: Lang) -> impl Fn(Error) -> Failure {
    move |e| Failure::from_error(&e, lang)
}

/// DE: Bedienregel ohne Terminal (vor jeder Abfrage). `file_passphrase` = die Datei bekommt
/// einen Passphrase-Zugang. EN: Rule without a terminal (before any prompt).
pub fn check_sources(lang: Lang, m: &ArgMatches, file_passphrase: bool) -> CliResult {
    let non_interactive = m.get_flag("passphrase-stdin")
        || super::unattended::pass_file().is_some()
        || super::unattended::batch();
    if path(m, SIGN_WITH).is_some() && file_passphrase && non_interactive {
        return Err(Failure::new(code::USAGE, texts(lang).one_source));
    }
    Ok(())
}

/// DE: Geladener, noch gesperrter Signaturschlüssel (Algorithmus und Faktordatei geprüft).
/// EN: Loaded, still locked signing key (algorithm and factor file checked).
pub struct PendingKey {
    key: envelope::KeyFile,
    factor: Option<Factor>,
}

impl PendingKey {
    /// DE: Fragt die Passphrase ab und entsperrt. EN: Asks for the passphrase and unlocks.
    pub fn unlock(self, t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult<UnlockedKey> {
        let stdin = m.get_flag("passphrase-stdin");
        let pass = read_passphrase_as(t, lang, stdin, false, texts(lang).prompt)?;
        let unlocked: Result<UnlockedKey> = match &self.factor {
            Some(f) => self.key.unlock_with_factor(&pass, f),
            None => self.key.unlock(&pass),
        };
        unlocked.map_err(fail(lang))
    }
}

/// DE: Lädt den Signaturschlüssel (`--sign-with`) und prüft Algorithmus und Faktordatei – vor
/// jeder Passphrase-Abfrage. EN: Loads the signing key and checks algorithm and factor file –
/// before any passphrase prompt.
pub fn prepare(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult<Option<PendingKey>> {
    let Some(key_path) = path(m, SIGN_WITH) else {
        return Ok(None);
    };
    let (key, warnings) = envelope::load(&key_path).map_err(fail(lang))?;
    for w in warnings {
        eprintln!("{}: {}", t.msg_warning, w.message(lang));
    }
    if key.algorithm() != ML_DSA_87 {
        return Err(Failure::new(code::USAGE, texts(lang).need_dsa));
    }
    let factor_path = path(m, SIGN_FACTOR);
    super::unlock::check_factor(key.needs_factor(), factor_path.is_some(), lang)?;
    let factor = factor_path
        .map(|p| Factor::read(&p))
        .transpose()
        .map_err(fail(lang))?;
    Ok(Some(PendingKey { key, factor }))
}

/// DE: Lädt den verlangten Absender (`--signer`), nur ML-DSA-87.
/// EN: Loads the required sender (`--signer`), ML-DSA-87 only.
pub fn load_expected(lang: Lang, m: &ArgMatches) -> CliResult<Option<PublicKeyFile>> {
    let Some(p) = path(m, SIGNER) else {
        return Ok(None);
    };
    let key = envelope::load_public(&p).map_err(fail(lang))?;
    if key.algorithm() != ML_DSA_87 {
        return Err(Failure::new(code::USAGE, texts(lang).need_dsa));
    }
    Ok(Some(key))
}

/// DE: Zeile „Signiert von …“ (nur bei signierten Dateien). EN: Line "Signed by …" (signed files only).
pub fn print(lang: Lang, signer: Option<&SignedBy>) {
    if let Some(s) = signer {
        println!(
            "{}: {}",
            texts(lang).signed_by,
            fingerprint(&envelope::hex_encode(&s.key_id))
        );
    }
}

/// DE: Absender aus dem Header (`inspect`), ausdrücklich ungeprüft. EN: Sender from the header
/// (`inspect`), explicitly unverified.
pub fn print_unverified(lang: Lang, signer: Option<&Signer>) {
    if let Some(s) = signer {
        println!(
            "{}: {}",
            texts(lang).unverified,
            fingerprint(&envelope::hex_encode(&s.key_id()))
        );
    }
}

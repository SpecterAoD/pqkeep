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

use std::path::{Path, PathBuf};

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
/// DE: Passphrase-Datei des Signaturschlüssels (#286). EN: Passphrase file of the signing key (#286).
pub const SIGN_PASS_FILE: &str = "sign-passphrase-file";
/// DE: Intern (Kontextmenü, #287): Passphrase des Signaturschlüssels = nächste stdin-Zeile nach der
/// Datei-Passphrase; beide kommen aus Passwortfenstern über dieselbe Pipe.
/// EN: Internal (context menu, #287): signing key passphrase = next stdin line after the file
/// passphrase; both come from password windows through the same pipe.
pub const SIGN_PASS_NEXT: &str = "sign-passphrase-next-line";

const ML_DSA_87: KeyAlgorithm = KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87);

pub(super) struct SignTexts {
    arg_sign_with: &'static str,
    arg_sign_factor: &'static str,
    arg_signer: &'static str,
    arg_sign_pass: &'static str,
    pub prompt: &'static str,
    signed_by: &'static str,
    unverified: &'static str,
    one_source: &'static str,
    need_dsa: &'static str,
    /// DE: Menü und Kontextmenü (#287). EN: Menu and context menu (#287).
    pub menu_key: &'static str,
    pub menu_factor: &'static str,
    pub ctx_question: &'static str,
    pub ctx_pick: &'static str,
    pub ctx_filter: &'static str,
}

const DE: SignTexts = SignTexts {
    arg_sign_with: "Datei zusätzlich mit diesem ML-DSA-87-Schlüssel signieren (Absender-Signatur, Format v3)",
    arg_sign_factor: "Faktordatei des Signaturschlüssels (nur wenn dieser eine verlangt)",
    arg_signer: "Datei muss von diesem Absender signiert sein (öffentlicher ML-DSA-87-Schlüssel); sonst Fehler, keine Ausgabe",
    arg_sign_pass: "Passphrase des Signaturschlüssels aus dieser Datei (Regeln wie --passphrase-file: eine Zeile, Linux 0600) – für den Betrieb ohne Terminal",
    prompt: "Passphrase des Signaturschlüssels",
    signed_by: "Signiert von (geprüft)",
    unverified: "Absender (ungeprüft, prüfen mit pqkeep check oder beim Entschlüsseln)",
    one_source: "--sign-with braucht eine eigene Passphrase; ohne Terminal zusammen mit einer Datei-Passphrase bitte --sign-passphrase-file angeben",
    need_dsa: "Für die Absender-Signatur wird ein ML-DSA-87-Schlüssel gebraucht (--sign-with: *.key.json, --signer: *.pub.json)",
    menu_key: "Als Absender signieren? Eigener ML-DSA-87-Schlüssel (.key.json, leer = nicht signieren)",
    menu_factor: "Faktordatei des Signaturschlüssels",
    ctx_question: "Zusätzlich als Absender signieren (eigener ML-DSA-87-Schlüssel)? Empfänger können dann prüfen, dass die Datei von Ihnen stammt.",
    ctx_pick: "Eigenen Signaturschlüssel wählen (ML-DSA-87)",
    ctx_filter: "Schlüsseldateien (*.key.json)",
};

const EN: SignTexts = SignTexts {
    arg_sign_with: "Additionally sign the file with this ML-DSA-87 key (sender signature, format v3)",
    arg_sign_factor: "Factor file of the signing key (only if it requires one)",
    arg_signer: "File must be signed by this sender (public ML-DSA-87 key); otherwise error, no output",
    arg_sign_pass: "Passphrase of the signing key from this file (rules as --passphrase-file: one line, Linux 0600) – for use without a terminal",
    prompt: "Passphrase of the signing key",
    signed_by: "Signed by (verified)",
    unverified: "Sender (unverified, verify with pqkeep check or when decrypting)",
    one_source: "--sign-with needs its own passphrase; without a terminal together with a file passphrase please pass --sign-passphrase-file",
    need_dsa: "The sender signature needs an ML-DSA-87 key (--sign-with: *.key.json, --signer: *.pub.json)",
    menu_key: "Sign as sender? Own ML-DSA-87 key (.key.json, empty = do not sign)",
    menu_factor: "Factor file of the signing key",
    ctx_question: "Additionally sign as sender (own ML-DSA-87 key)? Recipients can then verify that the file comes from you.",
    ctx_pick: "Choose your own signing key (ML-DSA-87)",
    ctx_filter: "Key files (*.key.json)",
};

pub(super) fn texts(lang: Lang) -> &'static SignTexts {
    if lang == Lang::De { &DE } else { &EN }
}

fn path(m: &ArgMatches, id: &str) -> Option<PathBuf> {
    m.try_get_one::<PathBuf>(id).ok().flatten().cloned()
}

/// DE: Alle angegebenen Pfade (für die Sandbox, nur lesen). EN: All given paths (sandbox, read only).
pub fn paths(m: &ArgMatches) -> Vec<PathBuf> {
    [SIGN_WITH, SIGN_FACTOR, SIGN_PASS_FILE, SIGNER]
        .iter()
        .filter_map(|id| path(m, id))
        .collect()
}

/// DE: Optionen für `encrypt`. EN: Options for `encrypt`.
pub fn encrypt_args(lang: Lang) -> [Arg; 4] {
    let s = texts(lang);
    [
        opt(SIGN_WITH, s.arg_sign_with).value_parser(value_parser!(PathBuf)),
        opt(SIGN_FACTOR, s.arg_sign_factor)
            .value_parser(value_parser!(PathBuf))
            .requires(SIGN_WITH),
        opt(SIGN_PASS_FILE, s.arg_sign_pass)
            .value_parser(value_parser!(PathBuf))
            .requires(SIGN_WITH),
        super::args::flag(SIGN_PASS_NEXT, "")
            .hide(true)
            .requires(SIGN_WITH)
            .requires("passphrase-stdin"),
    ]
}

fn next_line(m: &ArgMatches) -> bool {
    m.try_get_one::<bool>(SIGN_PASS_NEXT)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}

/// DE: Menü (#287): fragt nach dem eigenen Signaturschlüssel (leer = nicht signieren) und – falls
/// dieser sie verlangt – nach seiner Faktordatei; ergänzt `argv`.
/// EN: Menu (#287): asks for the own signing key (empty = do not sign) and – if it requires one –
/// its factor file; extends `argv`.
pub fn menu_args(
    lang: Lang,
    mut ask: impl FnMut(&str) -> CliResult<String>,
    argv: &mut Vec<String>,
) -> CliResult {
    let s = texts(lang);
    let key = ask(s.menu_key)?;
    if key.trim().is_empty() {
        return Ok(());
    }
    let needs_factor = super::factor_ui::key_needs(Path::new(&key));
    argv.extend([format!("--{SIGN_WITH}"), key]);
    if needs_factor {
        argv.extend([format!("--{SIGN_FACTOR}"), ask(s.menu_factor)?]);
    }
    Ok(())
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
    let own_source = path(m, SIGN_PASS_FILE).is_some() || next_line(m);
    if path(m, SIGN_WITH).is_some() && file_passphrase && non_interactive && !own_source {
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
    /// DE: Passphrase aus `--sign-passphrase-file` oder (sonst) wie gewohnt abfragen; entsperren.
    /// EN: Passphrase from `--sign-passphrase-file` or (otherwise) as usual; unlocks.
    pub fn unlock(self, t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult<UnlockedKey> {
        let pass = if let Some(p) = path(m, SIGN_PASS_FILE) {
            super::unattended::read_file(&p, lang)?
        } else {
            let stdin = m.get_flag("passphrase-stdin");
            read_passphrase_as(t, lang, stdin, false, texts(lang).prompt)?
        };
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

/// DE: Beschriftung der Absenderzeile (für das Fertig-Fenster des Kontextmenüs).
/// EN: Label of the sender line (for the context menu's final window).
pub fn signed_by_label(lang: Lang) -> &'static str {
    texts(lang).signed_by
}

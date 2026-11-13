//! DE: Gemeinsames Entsperren für `decrypt` und `sign`: welche Zugänge eine verschlüsselte Datei
//! hat (v1 und v2), Schlüsseldatei mit Passphrase – und bei Version 2 mit Faktordatei – öffnen.
//! Passt `--factor-file` nicht zur Datei, wird das vor der Passphrase-Abfrage gemeldet; die
//! Faktordatei wird nie stillschweigend ignoriert.
//! EN: Shared unlocking for `decrypt` and `sign`: which access slots an encrypted file has (v1
//! and v2), opening a key file with passphrase – and for version 2 with factor file. If
//! `--factor-file` does not match the file this is reported before the passphrase prompt; the
//! factor file is never silently ignored.

use std::path::{Path, PathBuf};

use clap::ArgMatches;
use pqkeep::crypto::factor::Factor;
use pqkeep::envelope::{self, KeyFile, UnlockedKey};
use pqkeep::files::{self, HeaderMode, Slot, Unlock};
use pqkeep::security::{Lang, Passphrase};
use pqkeep::{Error, Result};

use super::io::{CliResult, Failure, code, read_passphrase, read_passphrase_as};
use super::text::Texts;

/// DE: Zugänge einer verschlüsselten Datei. EN: Access slots of an encrypted file.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Access {
    /// DE: Passphrase-Zugang; `Some(true)` = mit Faktordatei.
    /// EN: Passphrase slot; `Some(true)` = with factor file.
    pub passphrase: Option<bool>,
    /// DE: Mindestens ein Empfänger. EN: At least one recipient.
    pub recipient: bool,
}

impl Access {
    /// DE: Liest nur den Header (v1, sonst v2). EN: Reads the header only (v1, else v2).
    pub fn read(source: &Path) -> Result<Self> {
        let mut access = Self {
            passphrase: None,
            recipient: false,
        };
        match files::inspect(source) {
            Ok(header) => match header.mode {
                HeaderMode::Passphrase { .. } => access.passphrase = Some(false),
                HeaderMode::Recipient { .. } => access.recipient = true,
            },
            Err(Error::Unsupported) => {
                for slot in files::inspect_v2(source)?.slots {
                    match slot {
                        Slot::Passphrase { factor, .. } => access.passphrase = Some(factor),
                        Slot::Recipient { .. } => access.recipient = true,
                    }
                }
            }
            Err(e) => return Err(e),
        }
        Ok(access)
    }

    /// DE: Mit Schlüsseldatei öffnen? Ja, wenn es Empfänger gibt und `--key` angegeben ist oder
    /// kein Passphrase-Zugang existiert. EN: Open with a key file? Yes if there are recipients
    /// and `--key` is given or no passphrase slot exists.
    pub fn use_key(self, key_given: bool) -> bool {
        self.recipient && (key_given || self.passphrase.is_none())
    }
}

/// DE: Fehler, wenn `--factor-file` nicht dazu passt, ob eine Faktordatei nötig ist.
/// EN: Error if `--factor-file` does not match whether a factor file is needed.
fn check_factor(needed: bool, given: bool, lang: Lang) -> CliResult {
    let field = match (needed, given) {
        (true, false) => "factor_required",
        (false, true) => "factor_unused",
        _ => return Ok(()),
    };
    Err(Failure::from_error(&Error::InvalidInput { field }, lang))
}

/// DE: Geladene Schlüsseldatei entsperren (Passphrase, bei Version 2 zusätzlich Faktordatei).
/// EN: Unlock a loaded key file (passphrase, for version 2 the factor file as well).
pub fn open_key(t: &Texts, lang: Lang, m: &ArgMatches, key: &KeyFile) -> CliResult<UnlockedKey> {
    let fail = |e: Error| Failure::from_error(&e, lang);
    check_factor(
        key.needs_factor(),
        super::factor_cmd::path(m).is_some(),
        lang,
    )?;
    let factor = super::factor_cmd::load(m, lang)?;
    let stdin = m.get_flag("passphrase-stdin");
    let pass = read_passphrase_as(t, lang, stdin, false, t.prompt_key_passphrase)?;
    match &factor {
        Some(factor) => key.unlock_with_factor(&pass, factor),
        None => key.unlock(&pass),
    }
    .map_err(fail)
}

/// DE: Schlüsseldatei laden (Warnungen ausgeben) und entsperren. EN: Load (print warnings) and unlock.
fn load_key(t: &Texts, lang: Lang, m: &ArgMatches, path: &Path) -> CliResult<UnlockedKey> {
    let (key, warnings) = envelope::load(path).map_err(|e| Failure::from_error(&e, lang))?;
    for w in warnings {
        eprintln!("{}: {}", t.msg_warning, w.message(lang));
    }
    open_key(t, lang, m, &key)
}

/// DE: Eingelesener Zugang zum Entschlüsseln. EN: Read access for decrypting.
pub enum Opened {
    /// DE: Entsperrter Empfängerschlüssel. EN: Unlocked recipient key.
    Key(UnlockedKey),
    /// DE: Passphrase, optional mit Faktordatei. EN: Passphrase, optional factor file.
    Passphrase(Passphrase, Option<Factor>),
}

impl Opened {
    /// DE: Sicht für die Bibliothek. EN: View for the library.
    pub fn get(&self) -> Unlock<'_> {
        match self {
            Self::Key(key) => Unlock::Key(key),
            Self::Passphrase(passphrase, None) => Unlock::Passphrase(passphrase),
            Self::Passphrase(passphrase, Some(factor)) => {
                Unlock::PassphraseWithFactor { passphrase, factor }
            }
        }
    }
}

/// DE: Zugang für `decrypt` einlesen. `passphrase_factor`: bei einer einzelnen Datei bekannt, ob
/// ihr Passphrase-Zugang eine Faktordatei braucht (wird dann vorab geprüft).
/// EN: Read the access for `decrypt`. `passphrase_factor`: for a single file it is known whether
/// its passphrase slot needs a factor file (then checked up front).
pub fn for_decrypt(
    t: &Texts,
    lang: Lang,
    m: &ArgMatches,
    use_key: bool,
    passphrase_factor: Option<bool>,
) -> CliResult<Opened> {
    let key = m.get_one::<PathBuf>("key");
    if use_key {
        let path = key.ok_or_else(|| Failure::new(code::USAGE, t.msg_need_key))?;
        return load_key(t, lang, m, path).map(Opened::Key);
    }
    if key.is_some() {
        eprintln!("{}: {}", t.msg_warning, t.msg_no_key_needed);
    }
    if let Some(needed) = passphrase_factor {
        check_factor(needed, super::factor_cmd::path(m).is_some(), lang)?;
    }
    let factor = super::factor_cmd::load(m, lang)?;
    let pass = read_passphrase(t, lang, m.get_flag("passphrase-stdin"), false)?;
    Ok(Opened::Passphrase(pass, factor))
}

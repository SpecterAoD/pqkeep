//! DE: Unbeaufsichtigter Betrieb (S3): `--passphrase-file <pfad>` und `--batch`. Die Passphrase-Datei
//! muss eine reguläre Datei sein (keine Verknüpfung), höchstens 4 KiB, eine Zeile; unter Linux nur für
//! den Eigentümer lesbar (keine Rechte für Gruppe/andere) und im Besitz des aufrufenden Benutzers oder
//! von root (systemd `LoadCredential=`). Windows: keine ACL-Prüfung ohne `unsafe` (dokumentierte Grenze).
//! `--batch` fragt nie nach, sondern bricht mit klarer Meldung ab. Keine Umgebungsvariablen.
//! EN: Unattended operation (S3): `--passphrase-file <path>` and `--batch`. The passphrase file must be a
//! regular file (no link), at most 4 KiB, one line; on Linux readable by the owner only (no group/other
//! permissions) and owned by the calling user or root (systemd `LoadCredential=`). Windows: no ACL check
//! without `unsafe` (documented limitation). `--batch` never prompts but aborts with a clear message.
//! No environment variables.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use clap::ArgMatches;
use pqkeep::security::{Lang, Passphrase};
use zeroize::Zeroizing;

use super::io::{CliResult, Failure, code};

/// DE: Höchstgröße der Passphrase-Datei. EN: Maximum size of the passphrase file.
const MAX_FILE: u64 = 4096;

static BATCH: AtomicBool = AtomicBool::new(false);
static PASS_FILE: OnceLock<PathBuf> = OnceLock::new();

/// DE: Texte. EN: Texts.
struct UnattendedTexts {
    invalid: &'static str,
    perms: &'static str,
    conflict: &'static str,
    batch: &'static str,
}

static DE: UnattendedTexts = UnattendedTexts {
    invalid: "Passphrase-Datei ungültig (keine reguläre Datei, Verknüpfung, größer als 4 KiB, mehr als eine Zeile oder kein UTF-8).",
    perms: "Passphrase-Datei hat zu offene Rechte oder einen fremden Eigentümer – bitte „chmod 600“ (nur der eigene Benutzer bzw. root).",
    conflict: "--passphrase-file und --passphrase-stdin schließen sich aus.",
    batch: "--batch: Eine Eingabe wäre nötig. Bitte --passphrase-file oder --passphrase-stdin bzw. --force --yes angeben.",
};

static EN: UnattendedTexts = UnattendedTexts {
    invalid: "Passphrase file invalid (not a regular file, a link, larger than 4 KiB, more than one line or not UTF-8).",
    perms: "Passphrase file has too open permissions or a foreign owner – please \"chmod 600\" (own user or root only).",
    conflict: "--passphrase-file and --passphrase-stdin are mutually exclusive.",
    batch: "--batch: input would be required. Please pass --passphrase-file or --passphrase-stdin, or --force --yes.",
};

fn texts(lang: Lang) -> &'static UnattendedTexts {
    if lang == Lang::De { &DE } else { &EN }
}

/// DE: Globale Optionen nach dem Parsen übernehmen. EN: Take over global options after parsing.
pub fn configure(m: &ArgMatches) {
    BATCH.store(m.get_flag("batch"), Ordering::Relaxed);
    if let Some(p) = m.get_one::<PathBuf>("passphrase-file") {
        let _ = PASS_FILE.set(p.clone());
    }
}

/// DE: Nie nachfragen? EN: Never prompt?
pub fn batch() -> bool {
    BATCH.load(Ordering::Relaxed)
}

/// DE: Fehler „Eingabe nötig“ im Batch-Modus. EN: "Input required" error in batch mode.
pub fn batch_failure(lang: Lang) -> Failure {
    Failure::new(code::USAGE, texts(lang).batch)
}

/// DE: Gesetzte Passphrase-Datei (für die Sandbox-Freigabe). EN: Configured passphrase file.
pub fn pass_file() -> Option<&'static Path> {
    PASS_FILE.get().map(PathBuf::as_path)
}

fn open(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// DE: Rechte und Eigentümer (Linux). EN: Permissions and owner (Linux).
#[cfg(target_os = "linux")]
// DE: Maske 0o077 (Gruppe/andere) ist lesbarer als `trailing_zeros`. EN: Mask is clearer.
#[allow(clippy::verbose_bit_mask)]
fn permissions_ok(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let euid = rustix::process::geteuid().as_raw();
    meta.mode() & 0o077 == 0 && (meta.uid() == euid || meta.uid() == 0)
}

#[cfg(not(target_os = "linux"))]
fn permissions_ok(_meta: &fs::Metadata) -> bool {
    true
}

/// DE: Liest die Passphrase aus der Datei, falls `--passphrase-file` gesetzt ist.
/// EN: Reads the passphrase from the file if `--passphrase-file` is set.
pub fn read_pass_file(lang: Lang, from_stdin: bool) -> Option<CliResult<Passphrase>> {
    let path = pass_file()?;
    let s = texts(lang);
    if from_stdin {
        return Some(Err(Failure::new(code::USAGE, s.conflict)));
    }
    Some(read_checked(path, lang))
}

fn read_checked(path: &Path, lang: Lang) -> CliResult<Passphrase> {
    let s = texts(lang);
    let invalid = || Failure::new(code::USAGE, s.invalid);
    let io = |e: std::io::Error| Failure::from_error(&e.into(), lang);
    if fs::symlink_metadata(path)
        .map_err(io)?
        .file_type()
        .is_symlink()
    {
        return Err(invalid());
    }
    let file = open(path).map_err(|_| invalid())?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() {
        return Err(invalid());
    }
    if !permissions_ok(&meta) {
        return Err(Failure::new(code::USAGE, s.perms));
    }
    let mut buf = Zeroizing::new(Vec::new());
    file.take(MAX_FILE + 1).read_to_end(&mut buf).map_err(io)?;
    let mut len = buf.len();
    if len as u64 > MAX_FILE {
        return Err(invalid());
    }
    if buf[..len].ends_with(b"\n") {
        len -= 1;
        if buf[..len].ends_with(b"\r") {
            len -= 1;
        }
    }
    let line = &buf[..len];
    if line.contains(&b'\n') || line.contains(&b'\r') {
        return Err(invalid());
    }
    let text = String::from_utf8(line.to_vec()).map_err(|e| {
        // DE: Auch fehlerhafte Bytes nullen. EN: Zero invalid bytes too.
        let mut bytes = e.into_bytes();
        zeroize::Zeroize::zeroize(&mut bytes);
        invalid()
    })?;
    Passphrase::from_string(text).map_err(|e| Failure::from_error(&e, lang))
}

#[cfg(test)]
#[path = "unattended_tests.rs"]
mod unattended_tests;

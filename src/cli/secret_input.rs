//! DE: Begrenzte Passphrase-Eingabe direkt in vorab gesperrten Speicher.
//! EN: Bounded password input directly into pre-locked storage.

use std::fs::File;
use std::io::Read;

use pqkeep::crypto::SecretBytes;
use pqkeep::security::{INPUT_LIMIT_CHARS, Lang, Passphrase};
use pqkeep::{Error, Result};

use super::io::{CliResult, Failure};

#[cfg(unix)]
pub(super) fn stdin_file() -> std::io::Result<File> {
    use std::os::fd::AsFd;
    Ok(File::from(std::io::stdin().as_fd().try_clone_to_owned()?))
}

#[cfg(windows)]
pub(super) fn stdin_file() -> std::io::Result<File> {
    use std::os::windows::io::AsHandle;
    Ok(File::from(
        std::io::stdin().as_handle().try_clone_to_owned()?,
    ))
}

// DE: Absichtliche Ausgabe direkt ans OS, ohne stdout-Zwischenpuffer.
// EN: Intentional disclosure directly to the OS, without stdout staging.
pub(super) fn stdout_file() -> std::io::Result<impl std::io::Write> {
    pqkeep::security::output::stdout()
}

pub(super) fn read_line(reader: &mut impl Read, limit: usize) -> Result<SecretBytes> {
    let mut out = SecretBytes::zeroed(limit + 1)?;
    let mut len = 0;
    loop {
        match reader.read(&mut out.expose_mut()[len..=len]) {
            Ok(0) => break,
            Ok(_) if out.expose()[len] == b'\n' => break,
            Ok(_) => {
                len += 1;
                if len > limit {
                    return Err(Error::InvalidInput {
                        field: "passphrase",
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    while len > 0 && out.expose()[len - 1] == b'\r' {
        len -= 1;
    }
    out.truncate(len);
    Ok(out)
}

pub(super) fn stdin_line(lang: Lang) -> CliResult<SecretBytes> {
    let result = stdin_file()
        .map_err(Error::from)
        .and_then(|mut file| read_line(&mut file, INPUT_LIMIT_CHARS * 4));
    result.map_err(|e| Failure::from_error(&e, lang))
}

pub(super) fn passphrase(bytes: &SecretBytes, lang: Lang) -> CliResult<Passphrase> {
    let text = std::str::from_utf8(bytes.expose()).map_err(|_| {
        Failure::from_error(
            &Error::InvalidInput {
                field: "passphrase",
            },
            lang,
        )
    })?;
    Passphrase::new(text).map_err(|e| Failure::from_error(&e, lang))
}

#[cfg(test)]
#[path = "secret_input_tests.rs"]
mod secret_input_tests;

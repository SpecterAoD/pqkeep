//! DE: Begrenzte, genullte Rekey-Eingabe, keine Passphrase-Argumente/Umgebung.
//! EN: Bounded, zeroized rekey input; no passphrase arguments/environment.
use std::io::Read;

use clap::ArgMatches;
use pqkeep::crypto::SecretBytes;
use pqkeep::security::{Lang, Passphrase, StrongPassphrase};

use super::io::{self, CliResult, Failure, code};
use super::{rekey_text, text::Texts, validate};

const MAX_LINE: usize = 4096;

pub(super) fn read(
    t: &Texts,
    lang: Lang,
    m: &ArgMatches,
) -> CliResult<(Passphrase, StrongPassphrase)> {
    let (old, new) = if m.get_flag("passphrase-stdin") {
        stdin(t, lang)?
    } else {
        (
            io::read_passphrase_as(t, lang, false, false, t.prompt_key_passphrase)?,
            io::read_passphrase(t, lang, false, true)?,
        )
    };
    let new = validate::strong(m, new).map_err(|r| {
        validate::print_rejection(t, lang, &r);
        Failure::new(code::WEAK, "")
    })?;
    Ok((old, new))
}

fn stdin(t: &Texts, lang: Lang) -> CliResult<(Passphrase, Passphrase)> {
    let mut reader =
        super::secret_input::stdin_file().map_err(|e| Failure::from_error(&e.into(), lang))?;
    let mut extra = SecretBytes::zeroed(1).map_err(|e| Failure::from_error(&e, lang))?;
    let old = line(&mut reader, lang)?;
    let new = line(&mut reader, lang)?;
    let confirm = line(&mut reader, lang)?;
    if new.expose() != confirm.expose() {
        return Err(Failure::new(code::USAGE, t.prompt_mismatch));
    }
    if reader
        .read(extra.expose_mut())
        .map_err(|e| Failure::from_error(&e.into(), lang))?
        != 0
    {
        return Err(invalid(lang));
    }
    let pass = |bytes: &[u8]| {
        let text = std::str::from_utf8(bytes).map_err(|_| invalid(lang))?;
        Passphrase::new(text).map_err(|e| Failure::from_error(&e, lang))
    };
    Ok((pass(old.expose())?, pass(new.expose())?))
}

fn invalid(lang: Lang) -> Failure {
    Failure::new(code::USAGE, rekey_text::texts(lang).input)
}

fn line(reader: &mut impl Read, lang: Lang) -> CliResult<SecretBytes> {
    // DE: Feste Sperre vor dem ersten Byte, kein Read-ahead oder Reallokation.
    // EN: Fixed lock before the first byte, no read-ahead or reallocation.
    let mut bytes = SecretBytes::zeroed(MAX_LINE + 1).map_err(|e| Failure::from_error(&e, lang))?;
    let mut len = 0;
    loop {
        match reader.read(&mut bytes.expose_mut()[len..=len]) {
            Ok(0) => return Err(invalid(lang)),
            Ok(_) => {
                len += 1;
                if len > MAX_LINE {
                    return Err(invalid(lang));
                }
                if bytes.expose()[len - 1] == b'\n' {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Failure::from_error(&e.into(), lang)),
        }
    }
    len -= 1;
    if len > 0 && bytes.expose()[len - 1] == b'\r' {
        len -= 1;
    }
    if bytes.expose()[..len].contains(&b'\r') {
        return Err(invalid(lang));
    }
    bytes.truncate(len);
    Ok(bytes)
}

#[cfg(test)]
#[path = "rekey_input_tests.rs"]
mod tests;

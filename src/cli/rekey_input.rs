//! DE: Begrenzte, genullte Rekey-Eingabe, keine Passphrase-Argumente/Umgebung.
//! EN: Bounded, zeroized rekey input; no passphrase arguments/environment.
use std::io::{BufRead, Read};

use clap::ArgMatches;
use pqkeep::security::{Lang, Passphrase, StrongPassphrase};
use zeroize::Zeroizing;

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
    let mut reader = std::io::stdin().lock();
    let old = line(&mut reader, lang)?;
    let new = line(&mut reader, lang)?;
    let confirm = line(&mut reader, lang)?;
    if new.as_slice() != confirm.as_slice() {
        return Err(Failure::new(code::USAGE, t.prompt_mismatch));
    }
    let mut extra = Zeroizing::new([0; 1]);
    if reader
        .read(&mut *extra)
        .map_err(|e| Failure::from_error(&e.into(), lang))?
        != 0
    {
        return Err(invalid(lang));
    }
    let pass = |bytes: &[u8]| {
        let text = std::str::from_utf8(bytes).map_err(|_| invalid(lang))?;
        Passphrase::new(text).map_err(|e| Failure::from_error(&e, lang))
    };
    Ok((pass(&old)?, pass(&new)?))
}

fn invalid(lang: Lang) -> Failure {
    Failure::new(code::USAGE, rekey_text::texts(lang).input)
}

fn line(reader: &mut impl BufRead, lang: Lang) -> CliResult<Zeroizing<Vec<u8>>> {
    // DE: Vorab reservieren: keine ungenullten alten Puffer durch Reallokation.
    // EN: Reserve up front: no unzeroized old buffers from reallocation.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_LINE + 1));
    reader
        .take((MAX_LINE + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|e| Failure::from_error(&e.into(), lang))?;
    if bytes.len() > MAX_LINE || !bytes.ends_with(b"\n") {
        return Err(invalid(lang));
    }
    bytes.pop();
    if bytes.ends_with(b"\r") {
        bytes.pop();
    }
    if bytes.contains(&b'\r') {
        return Err(invalid(lang));
    }
    Ok(bytes)
}

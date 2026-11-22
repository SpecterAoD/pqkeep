//! DE: Verdeckte Terminaleingabe direkt in einen begrenzten SecretBytes-Puffer.
//! EN: Hidden terminal input directly into a bounded `SecretBytes` buffer.

use dialoguer::console::{Key, Term};
use pqkeep::Error;
use pqkeep::crypto::SecretBytes;
use pqkeep::security::{INPUT_LIMIT_CHARS, Lang, Passphrase};

use super::io::{CliResult, Failure, code};
use super::text::Texts;

fn read(term: &Term, prompt: &str, lang: Lang) -> CliResult<SecretBytes> {
    #[cfg(target_os = "linux")]
    let mode =
        super::terminal_mode::Mode::new().map_err(|e| Failure::from_error(&e.into(), lang))?;
    let result = read_hidden(term, prompt, lang);
    #[cfg(target_os = "linux")]
    mode.restore()
        .map_err(|e| Failure::from_error(&e.into(), lang))?;
    result
}

fn read_hidden(term: &Term, prompt: &str, lang: Lang) -> CliResult<SecretBytes> {
    let fail = |e: std::io::Error| Failure::from_error(&e.into(), lang);
    let mut out =
        SecretBytes::zeroed(INPUT_LIMIT_CHARS * 4).map_err(|e| Failure::from_error(&e, lang))?;
    term.write_str(&format!("{prompt}: ")).map_err(fail)?;
    let mut len = 0;
    loop {
        match term.read_key_raw().map_err(fail)? {
            Key::Enter => break,
            Key::Escape | Key::CtrlC => return Err(Failure::new(code::ERROR, "")),
            Key::Backspace if len > 0 => {
                let end = len;
                len -= 1;
                while len > 0 && out.expose()[len] & 0xc0 == 0x80 {
                    len -= 1;
                }
                out.expose_mut()[len..end].fill(0);
            }
            Key::Char(ch) if !ch.is_control() => {
                let n = ch.len_utf8();
                if n > out.len() - len {
                    return Err(Failure::from_error(
                        &Error::InvalidInput {
                            field: "passphrase",
                        },
                        lang,
                    ));
                }
                ch.encode_utf8(&mut out.expose_mut()[len..len + n]);
                len += n;
            }
            _ => {}
        }
    }
    term.write_line("").map_err(fail)?;
    out.truncate(len);
    Ok(out)
}

pub(super) fn password(
    t: &Texts,
    lang: Lang,
    prompt: &str,
    confirm: bool,
) -> CliResult<Passphrase> {
    let term = Term::stderr();
    if !term.is_term() {
        return Err(Failure::new(code::USAGE, t.msg_no_tty));
    }
    loop {
        let first = read(&term, prompt, lang)?;
        if confirm {
            let second = read(&term, t.prompt_confirm, lang)?;
            if first.expose() != second.expose() {
                term.write_line(&super::io::confirmation_error(t))
                    .map_err(|e| Failure::from_error(&e.into(), lang))?;
                continue;
            }
        }
        return super::secret_input::passphrase(&first, lang);
    }
}

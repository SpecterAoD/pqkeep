//! DE: Verdeckte Terminaleingabe direkt in einen begrenzten SecretBytes-Puffer.
//! EN: Hidden terminal input directly into a bounded `SecretBytes` buffer.

use dialoguer::console::Term;
use pqkeep::Error;
use pqkeep::crypto::SecretBytes;
use pqkeep::security::{INPUT_LIMIT_CHARS, Lang, Passphrase};

use super::io::{CliResult, Failure, code};
use super::terminal_input::{Action, Input};
use super::text::Texts;
use zeroize::Zeroize;

struct Session {
    input: Input,
    first: SecretBytes,
    second: Option<SecretBytes>,
}

impl Session {
    fn new(confirm: bool) -> pqkeep::Result<Self> {
        Ok(Self {
            input: Input::new()?,
            first: SecretBytes::zeroed(INPUT_LIMIT_CHARS * 4)?,
            second: if confirm {
                Some(SecretBytes::zeroed(INPUT_LIMIT_CHARS * 4)?)
            } else {
                None
            },
        })
    }
}

fn read_hidden(
    term: &Term,
    prompt: &str,
    lang: Lang,
    input: &mut Input,
    out: &mut SecretBytes,
) -> CliResult<usize> {
    let fail = |e: std::io::Error| Failure::from_error(&e.into(), lang);
    out.expose_mut().zeroize();
    term.write_str(&format!("{prompt}: ")).map_err(fail)?;
    let mut len = 0;
    loop {
        match input.next().map_err(fail)? {
            Action::Finish => break,
            Action::Cancel => return Err(Failure::new(code::ERROR, "")),
            action => {
                edit(action, input, out, &mut len).map_err(|e| Failure::from_error(&e, lang))?;
            }
        }
    }
    term.write_line("").map_err(fail)?;
    Ok(len)
}

fn edit(
    action: Action,
    input: &Input,
    out: &mut SecretBytes,
    len: &mut usize,
) -> pqkeep::Result<()> {
    match action {
        Action::Backspace(repeat) => {
            for _ in 0..repeat {
                if *len == 0 {
                    break;
                }
                let end = *len;
                *len -= 1;
                while *len > 0 && out.expose()[*len] & 0xc0 == 0x80 {
                    *len -= 1;
                }
                out.expose_mut()[*len..end].zeroize();
            }
        }
        Action::Text { len: n, repeat } if (1..=4).contains(&n) && repeat > 0 => {
            let size = n
                .checked_mul(usize::from(repeat))
                .filter(|size| *size <= out.len() - *len)
                .ok_or(Error::InvalidInput {
                    field: "passphrase",
                })?;
            for destination in out.expose_mut()[*len..*len + size].chunks_exact_mut(n) {
                destination.copy_from_slice(input.text(n));
            }
            *len += size;
        }
        Action::Ignore => {}
        Action::Finish | Action::Cancel | Action::Text { .. } => {
            return Err(Error::InvalidInput {
                field: "passphrase",
            });
        }
    }
    Ok(())
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
    let mut session = Session::new(confirm).map_err(|e| Failure::from_error(&e, lang))?;
    #[cfg(target_os = "linux")]
    let mode =
        super::terminal_mode::Mode::new().map_err(|e| Failure::from_error(&e.into(), lang))?;
    #[cfg(windows)]
    let stdin = std::io::stdin();
    #[cfg(windows)]
    let mode = {
        use std::os::windows::io::AsHandle;
        pqkeep_platform::ConsoleInputMode::new(stdin.as_handle())
            .map_err(|e| Failure::from_error(&e.into(), lang))?
    };
    let result = read_password(&term, &mut session, t, lang, prompt);
    #[cfg(target_os = "linux")]
    mode.restore(result.is_err())
        .map_err(|e| Failure::from_error(&e.into(), lang))?;
    #[cfg(windows)]
    (if result.is_err() {
        mode.restore_after_error()
    } else {
        mode.restore()
    })
    .map_err(|e| Failure::from_error(&e.into(), lang))?;
    result
}

fn read_password(
    term: &Term,
    session: &mut Session,
    t: &Texts,
    lang: Lang,
    prompt: &str,
) -> CliResult<Passphrase> {
    loop {
        let len = read_hidden(term, prompt, lang, &mut session.input, &mut session.first)?;
        if let Some(second) = &mut session.second {
            let second_len = read_hidden(term, t.prompt_confirm, lang, &mut session.input, second)?;
            if session.first.expose()[..len] != second.expose()[..second_len] {
                term.write_line(&super::io::confirmation_error(t))
                    .map_err(|e| Failure::from_error(&e.into(), lang))?;
                continue;
            }
        }
        session.first.truncate(len);
        return super::secret_input::passphrase(&session.first, lang);
    }
}

#[cfg(test)]
#[path = "terminal_secret_tests.rs"]
mod tests;

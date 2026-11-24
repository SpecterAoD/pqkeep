//! DE: Ungepufferte Reads in gesperrte Bytes. EN: Unbuffered reads into locked bytes.

use super::terminal_input::Action;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use std::io;
use zeroize::Zeroize;

fn byte(scratch: &mut [u8]) -> io::Result<()> {
    if rustix::io::read(std::io::stdin(), scratch)? != 1 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

fn ready() -> io::Result<bool> {
    let input = std::io::stdin();
    let mut fds = [PollFd::new(&input, PollFlags::IN)];
    // DE: Begrenztes Escape-Fenster, keine privaten Bytes im Poll-Array.
    // EN: Bounded escape window; the poll array contains no private bytes.
    poll(
        &mut fds,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        }),
    )?;
    if fds[0]
        .revents()
        .intersects(PollFlags::ERR | PollFlags::NVAL)
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(fds[0].revents().intersects(PollFlags::IN | PollFlags::HUP))
}

fn escape(scratch: &mut [u8]) -> io::Result<Action> {
    if !ready()? {
        return Ok(Action::Cancel);
    }
    scratch.zeroize();
    byte(&mut scratch[..1])?;
    if !matches!(scratch[0], b'[' | b'O') {
        return Ok(Action::Ignore);
    }
    for _ in 0..32 {
        if !ready()? {
            return Ok(Action::Ignore);
        }
        scratch.zeroize();
        byte(&mut scratch[..1])?;
        match scratch[0] {
            0x40..=0x7e => return Ok(Action::Ignore),
            0x20..=0x3f => {}
            _ => return Err(io::ErrorKind::InvalidData.into()),
        }
    }
    Err(io::ErrorKind::InvalidData.into())
}

pub(super) fn next(scratch: &mut [u8]) -> io::Result<Action> {
    byte(&mut scratch[..1])?;
    match scratch[0] {
        b'\r' | b'\n' => return Ok(Action::Finish),
        3 => return Ok(Action::Cancel),
        8 | 127 => return Ok(Action::Backspace(1)),
        27 => return escape(scratch),
        0..=31 => return Ok(Action::Ignore),
        _ => {}
    }
    let len = match scratch[0] {
        0x20..=0x7e => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return Err(io::ErrorKind::InvalidData.into()),
    };
    for offset in 1..len {
        byte(&mut scratch[offset..=offset])?;
        if !(0x80..=0xbf).contains(&scratch[offset]) {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    let text = std::str::from_utf8(&scratch[..len]).map_err(|_| io::ErrorKind::InvalidData)?;
    Ok(if text.chars().any(char::is_control) {
        Action::Ignore
    } else {
        Action::Text { len, repeat: 1 }
    })
}

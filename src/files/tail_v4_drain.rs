//! DE: Auch Längen und Cursor des privaten Trailer-Rückhalts vor Eingang sperren.
//! EN: Prelock lengths and cursors of private trailer holdback before ingress.

use super::format_v4::TRAILER_LEN;
use crate::{
    Error, Result,
    crypto::{
        SecretBytes,
        secret_state::SecretState,
        stream::{CHUNK_SIZE, DecryptReader, PlainHash},
    },
};
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

struct State {
    buffer: Option<SecretBytes>,
    held: usize,
    written: u64,
    zeros: u64,
}

impl Zeroize for State {
    fn zeroize(&mut self) {
        self.buffer.take();
        self.held.zeroize();
        self.written.zeroize();
        self.zeros.zeroize();
    }
}
impl Drop for State {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for State {}

pub(super) struct Drained(SecretState<State>);

impl Drained {
    fn prepare(holdback: usize) -> Result<Self> {
        if holdback < TRAILER_LEN {
            return Err(Error::Crypto);
        }
        let mut out = Self(SecretState::new(State {
            buffer: None,
            held: 0,
            written: 0,
            zeros: 0,
        })?);
        out.0.get_mut().buffer = Some(SecretBytes::zeroed(
            CHUNK_SIZE.checked_add(holdback).ok_or(Error::Crypto)?,
        )?);
        Ok(out)
    }

    pub(super) fn written(&self) -> u64 {
        self.0.get().written
    }
    pub(super) fn zeros(&self) -> u64 {
        self.0.get().zeros
    }
    pub(super) fn bytes(&self) -> Result<&[u8]> {
        self.0
            .get()
            .buffer
            .as_ref()
            .map(SecretBytes::expose)
            .ok_or(Error::Crypto)
    }
}

pub(super) fn drain<R: Read>(
    dec: &mut DecryptReader<R>,
    writer: &mut impl Write,
    holdback: usize,
    mut hash: Option<&mut PlainHash>,
) -> Result<Drained> {
    let mut out = Drained::prepare(holdback)?;
    let state = out.0.get_mut();
    loop {
        let buffer = state.buffer.as_mut().ok_or(Error::Crypto)?;
        let n = dec.read(&mut buffer.expose_mut()[state.held..])?;
        if n == 0 {
            break;
        }
        state.held = state
            .held
            .checked_add(n)
            .filter(|held| *held <= buffer.len())
            .ok_or(Error::Crypto)?;
        if state.held > holdback {
            release_ready(state, writer, holdback, hash.as_deref_mut())?;
        }
    }
    if state.held != holdback {
        return Err(Error::InvalidInput { field: "trailer" });
    }
    state
        .buffer
        .as_mut()
        .ok_or(Error::Crypto)?
        .truncate(holdback);
    Ok(out)
}

fn release_ready(
    state: &mut State,
    writer: &mut impl Write,
    holdback: usize,
    hash: Option<&mut PlainHash>,
) -> Result<()> {
    let ready = state.held - holdback;
    let ready_u64 = u64::try_from(ready).map_err(|_| Error::Decrypt)?;
    let buffer = state.buffer.as_mut().ok_or(Error::Crypto)?;
    let part = &buffer.expose()[..ready];
    writer.write_all(part)?;
    if let Some(hash) = hash {
        hash.update(part);
    }
    state.zeros = match part.iter().rposition(|byte| *byte != 0) {
        Some(last) => u64::try_from(ready - last - 1).map_err(|_| Error::Decrypt)?,
        None => state.zeros.checked_add(ready_u64).ok_or(Error::Decrypt)?,
    };
    state.written = state.written.checked_add(ready_u64).ok_or(Error::Decrypt)?;
    buffer.expose_mut().copy_within(ready..state.held, 0);
    state.held = holdback;
    Ok(())
}

#[cfg(test)]
#[path = "tail_v4_drain_tests.rs"]
mod tests;

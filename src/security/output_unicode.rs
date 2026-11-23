//! DE: Keine privaten UTF-16-Kopien außerhalb des geliehenen gesperrten Ziels.
//! EN: No private UTF-16 copies outside the borrowed locked destination.

use std::io;
use zeroize::Zeroize;

fn flush(
    words: &mut [u16],
    len: usize,
    write: &mut impl FnMut(&[u16]) -> io::Result<usize>,
) -> io::Result<()> {
    let result = (|| {
        let mut offset = 0;
        while offset < len {
            let count = write(&words[offset..len])?;
            if count == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            if count > len - offset {
                return Err(io::ErrorKind::InvalidData.into());
            }
            offset += count;
        }
        Ok(())
    })();
    words.zeroize();
    result
}

pub(super) fn write_text(
    words: &mut [u16],
    text: &str,
    mut write: impl FnMut(&[u16]) -> io::Result<usize>,
) -> io::Result<()> {
    if words.len() < 2 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut filled = 0;
    for c in text.chars() {
        let len = c.len_utf16();
        if filled + len > words.len() {
            flush(words, filled, &mut write)?;
            filled = 0;
        }
        c.encode_utf16(&mut words[filled..filled + len]);
        filled += len;
    }
    flush(words, filled, &mut write)
}

#[cfg(test)]
#[path = "output_unicode_tests.rs"]
mod tests;

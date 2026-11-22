//! DE: Zeichenkopien erst nach vollständiger Seitensperre schreiben.
//! EN: Write character copies only after full page locking.
use crate::Result;
use crate::crypto::secret_buffer::SecretBuffer;

pub(super) fn chars(iter: impl Iterator<Item = char> + Clone) -> Result<SecretBuffer<char>> {
    let mut out = SecretBuffer::new(vec!['\0'; iter.clone().count()])?;
    for (slot, ch) in out.expose_mut().iter_mut().zip(iter) {
        *slot = ch;
    }
    Ok(out)
}

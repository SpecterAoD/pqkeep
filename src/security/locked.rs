//! DE: Zeichenkopien erst nach vollständiger Seitensperre schreiben.
//! EN: Write character copies only after full page locking.
use crate::Result;
use crate::crypto::secret_workspace::SecretWorkspace;

pub(super) fn chars(iter: impl Iterator<Item = char> + Clone) -> Result<SecretWorkspace<char>> {
    let mut out = SecretWorkspace::zeroed(iter.clone().count())?;
    for (slot, ch) in out.expose_mut().iter_mut().zip(iter) {
        *slot = ch;
    }
    Ok(out)
}

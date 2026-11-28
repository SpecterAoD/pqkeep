//! DE: Konkreten Iterator mit Quelle und laufender Position vor Nutzung sperren.
//! EN: Prelock the concrete iterator source and running position before use.
use super::{Result, SecretState, SourceEntries, SourceEntry};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(super) struct Cursor<'a> {
    source: Option<&'a SourceEntries>,
    position: usize,
}
impl Zeroize for Cursor<'_> {
    fn zeroize(&mut self) {
        self.source = None;
        self.position.zeroize();
    }
}
impl Drop for Cursor<'_> {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for Cursor<'_> {}

pub(crate) struct Iter<'a>(pub(super) SecretState<Cursor<'a>>);
impl SourceEntries {
    pub(crate) fn try_iter(&self) -> Result<Iter<'_>> {
        let mut out = Iter(SecretState::new(Cursor {
            source: None,
            position: 0,
        })?);
        out.0.get_mut().source = Some(self);
        Ok(out)
    }
}
impl<'a> Iterator for Iter<'a> {
    type Item = Result<&'a SourceEntry>;
    fn next(&mut self) -> Option<Self::Item> {
        let cursor = self.0.get_mut();
        let source = cursor.source?;
        if cursor.position >= source.len() {
            return None;
        }
        let entry = source.get(cursor.position);
        cursor.position += 1;
        Some(entry)
    }
}

//! DE: Tatsächliche native Metadaten vor Kernel-Ausgabe stabil sperren.
//! EN: Stably lock actual native metadata before kernel output.
use super::native_path::NativePath;
use crate::{Error, Result, crypto::secret_state::SecretState};
use std::path::Path;

pub(super) struct Metadata(SecretState<pqkeep_platform::SourceMetadata>);

impl Metadata {
    pub(super) fn read(path: &Path) -> Result<Self> {
        let mut output = Self(SecretState::new(pqkeep_platform::SourceMetadata::empty())?);
        let path = NativePath::from_path(path).map_err(|error| match error {
            Error::InvalidInput { field: "path" } => Error::Io(std::io::ErrorKind::InvalidInput),
            other => other,
        })?;
        path.metadata_into(output.0.get_mut())?;
        Ok(output)
    }
    pub(super) fn is_file(&self) -> bool {
        self.0.get().is_file()
    }
    pub(super) fn is_dir(&self) -> bool {
        self.0.get().is_dir()
    }
    pub(super) fn is_symlink(&self) -> bool {
        self.0.get().is_symlink()
    }
    pub(super) fn bytes(&self) -> u64 {
        self.0.get().bytes()
    }
}

#[cfg(test)]
#[path = "source_metadata_tests.rs"]
mod tests;

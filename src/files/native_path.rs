//! DE: Native Pfade vor Befüllung sperren; keine Klartext-PathBuf-/OsString-Kopie.
//! EN: Lock native paths before population; no plaintext PathBuf/OsString copy.

use crate::{Error, Result, crypto::secret_state::SecretState};
use std::{fmt, path::Path};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(unix)]
type Units = crate::crypto::SecretBytes;
#[cfg(windows)]
type Units = crate::crypto::secret_workspace::SecretWorkspace<u16>;
#[cfg(unix)]
type Unit = u8;
#[cfg(windows)]
type Unit = u16;

struct State(Units);

impl Zeroize for State {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for State {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for State {}

/// DE: Auch der konkrete native Pufferowner bleibt im gesperrten Zustand.
/// EN: The concrete native buffer owner also remains in protected state.
pub(super) struct NativePath(SecretState<State>);

#[cfg(test)]
#[path = "native_path_tests.rs"]
mod tests;

impl NativePath {
    pub(super) fn prepare() -> Result<Self> {
        Ok(Self(SecretState::new(State(Units::zeroed(0)?))?))
    }

    /// DE: Caller verantwortet seine Quelle; internes Ziel vor privater Kopie sperren.
    /// EN: Caller owns input responsibility; lock internal destination before copying.
    pub(super) fn from_path(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Self::from_native(path.as_os_str().as_bytes())
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let mut out = Self::prepare()?;
            let len = path.as_os_str().encode_wide().count();
            out.allocate(len)?;
            for (slot, unit) in out.0.get_mut().0.expose_mut()[..len]
                .iter_mut()
                .zip(path.as_os_str().encode_wide())
            {
                if unit == 0 {
                    return Err(Error::InvalidInput { field: "path" });
                }
                *slot = unit;
            }
            Ok(out)
        }
    }

    pub(super) fn from_native(source: &[Unit]) -> Result<Self> {
        let mut out = Self::prepare()?;
        out.copy_native(source)?;
        Ok(out)
    }

    pub(super) fn copy_native(&mut self, source: &[Unit]) -> Result<()> {
        if source.contains(&0) {
            return Err(Error::InvalidInput { field: "path" });
        }
        self.allocate(source.len())?;
        self.0.get_mut().0.expose_mut()[..source.len()].copy_from_slice(source);
        Ok(())
    }

    fn allocate(&mut self, len: usize) -> Result<()> {
        let len = len.checked_add(1).ok_or(Error::MemoryLock)?;
        // DE: Nur öffentlich leeren Owner bewegen; erst danach private Einheiten schreiben.
        // EN: Move only the public-empty owner, then write private native units in place.
        self.0.get_mut().0 = Units::zeroed(len)?;
        Ok(())
    }

    pub(super) fn encoded(&self) -> Result<&[Unit]> {
        let units = self.0.get().0.expose();
        if units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
            return Err(Error::Crypto);
        }
        Ok(units)
    }

    #[cfg(unix)]
    pub(super) fn c_str(&self) -> Result<&std::ffi::CStr> {
        std::ffi::CStr::from_bytes_with_nul(self.encoded()?).map_err(|_| Error::Crypto)
    }

    #[cfg(any(target_os = "linux", windows))]
    pub(super) fn metadata_into(&self, output: &mut pqkeep_platform::SourceMetadata) -> Result<()> {
        #[cfg(target_os = "linux")]
        output.capture(self.c_str()?)?;
        #[cfg(windows)]
        {
            let converted = windows::for_open(self)?;
            output.capture(converted.as_ref().unwrap_or(self).encoded()?)?;
        }
        Ok(())
    }

    pub(super) fn try_duplicate(&self) -> Result<Self> {
        let units = self.encoded()?;
        Self::from_native(&units[..units.len() - 1])
    }
}

impl Zeroize for NativePath {
    fn zeroize(&mut self) {
        self.0.get_mut().zeroize();
    }
}
impl fmt::Debug for NativePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativePath([REDACTED])")
    }
}

#[cfg(windows)]
#[path = "native_path_windows.rs"]
mod windows;

pub(super) fn open_file(path: &Path) -> Result<std::fs::File> {
    let path = NativePath::from_path(path).map_err(|error| match error {
        // DE: Bestehende File::open-Fehlerklasse für NUL-Pfade erhalten.
        // EN: Preserve the existing File::open error class for NUL paths.
        Error::InvalidInput { field: "path" } => Error::Io(std::io::ErrorKind::InvalidInput),
        other => other,
    })?;
    open_native(&path)
}

pub(super) fn open_native(path: &NativePath) -> Result<std::fs::File> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{CWD, Mode, OFlags, openat};
        // DE: Unveränderte Sandbox nutzt openat, nicht den älteren x86-open-Syscall.
        // EN: The unchanged sandbox permits openat, not legacy x86 open.
        openat(
            CWD,
            path.c_str()?,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(std::fs::File::from)
        .map_err(|error| std::io::Error::from(error).into())
    }
    #[cfg(windows)]
    {
        let normalized = windows::for_open(path)?;
        pqkeep_platform::open_file_read(normalized.as_ref().unwrap_or(path).encoded()?)
            .map_err(Into::into)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = path;
        Err(Error::Unsupported)
    }
}

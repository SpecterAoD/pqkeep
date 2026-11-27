//! DE: Private Hash-/Block-/Workerflächen vorab sperren; keine Ersatzparameter.
//! EN: Prelock private hash/block/worker storage; no substitute parameters.

use crate::{Argon2, Block, Error, Params};
use blake2::ProtectedBlake2b;
use std::sync::Mutex;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod fill;
mod hashing;
mod worker;

/// DE: Geliehene Eingaben; AD wird nicht in Params kopiert.
/// EN: Borrowed inputs; associated data is not copied into Params.
pub struct WorkspaceInputs<'a> {
    /// DE/EN: Geliehenes Passwort / borrowed password.
    pub password: &'a [u8],
    /// DE/EN: Geliehener Salt / borrowed salt.
    pub salt: &'a [u8],
    /// DE/EN: Geliehene assoziierte Daten / borrowed associated data.
    pub associated_data: &'a [u8],
}

/// DE/EN: Statische Fehler ohne private Inhalte / static errors without private data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceError {
    /// DE/EN: Bestehender Eingabevertrag / existing input contract.
    Argon(Error),
    /// DE/EN: Ungültige öffentliche Geometrie / invalid public geometry.
    Geometry,
    /// DE/EN: Belegter/vergifteter Worker / busy or poisoned worker.
    Unavailable,
    /// DE/EN: Ungültiger Hashzustand / invalid hash state.
    Hash,
}
impl From<Error> for WorkspaceError {
    fn from(error: Error) -> Self {
        Self::Argon(error)
    }
}
impl From<blake2::digest::InvalidOutputSize> for WorkspaceError {
    fn from(_: blake2::digest::InvalidOutputSize) -> Self {
        Self::Hash
    }
}
impl core::fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("protected Argon2 workspace unavailable or invalid")
    }
}
impl core::error::Error for WorkspaceError {}

struct HashWorkspace {
    core: ProtectedBlake2b,
    last_output: [u8; 64],
}

/// DE: Gesamten öffentlichen Anfangszustand vor privaten Eingaben sperren.
/// EN: Prelock the entire public initial state before private inputs.
pub struct OperationWorkspace {
    hash: HashWorkspace,
    initial_hash: [u8; 64],
    block_bytes: [u8; Block::SIZE],
    final_block: Block,
}
impl Default for OperationWorkspace {
    fn default() -> Self {
        Self {
            hash: Default::default(),
            initial_hash: [0; 64],
            block_bytes: [0; Block::SIZE],
            final_block: Block::new(),
        }
    }
}

#[derive(Default)]
struct WorkerState {
    address: Block,
    input: Block,
    zero: Block,
    r: Block,
    result: Block,
    completed_segments: usize,
}

/// DE: Eigener Inline-Worker je Lane; gesamte Fläche vor Passwortverarbeitung sperren.
/// EN: One inline worker per lane; prelock completely before password processing.
#[derive(Default)]
pub struct WorkerWorkspace {
    state: Mutex<WorkerState>,
}

impl Argon2<'_> {
    /// DE: Tatsächliche bisherige AVX2-Auswahl; keine privaten Zustände ausgeben.
    /// EN: Actual existing AVX2 dispatch selection; exposes no private state.
    #[must_use]
    pub fn protected_compression_uses_avx2(&self) -> bool {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            self.cpu_feat_avx2.get()
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            false
        }
    }

    /// DE: Alle drei Speicherbereiche vorher sperren; Params-AD muss leer sein.
    /// EN: Prelock all three storage regions; Params associated data must be empty.
    /// # Errors
    /// DE/EN: Eingaben/Geometrie ungültig oder Worker nicht verfügbar / invalid inputs,
    /// geometry or unavailable worker. Keine Finalausgabe bei Workerfehler / no final output
    /// on worker failure.
    pub fn hash_password_into_with_workspace(
        &self,
        inputs: WorkspaceInputs<'_>,
        out: &mut [u8],
        memory: &mut [Block],
        work: &mut OperationWorkspace,
        workers: &mut [WorkerWorkspace],
    ) -> Result<(), WorkspaceError> {
        self.validate_workspace_inputs(&inputs, out, memory, workers)?;
        work.initial_hash(self, &inputs, out.len())?;
        work.initialize_blocks(self, memory)?;
        self.fill_with_workers(memory, workers)?;
        work.finalize(self, memory, out)
    }

    fn validate_workspace_inputs(
        &self,
        inputs: &WorkspaceInputs<'_>,
        out: &[u8],
        memory: &[Block],
        workers: &mut [WorkerWorkspace],
    ) -> Result<(), WorkspaceError> {
        if out.len() < self.params.output_len().unwrap_or(Params::MIN_OUTPUT_LEN) {
            return Err(Error::OutputTooShort.into());
        }
        if out.len() > self.params.output_len().unwrap_or(Params::MAX_OUTPUT_LEN) {
            return Err(Error::OutputTooLong.into());
        }
        Self::verify_inputs(inputs.password, inputs.salt)?;
        if memory.len() < self.params.block_count()
            || workers.len() < self.params.lanes()
            || !self.params.data().is_empty()
            || inputs.associated_data.len() > Params::MAX_DATA_LEN
        {
            return Err(WorkspaceError::Geometry);
        }
        for worker in workers.iter_mut().take(self.params.lanes()) {
            worker
                .state
                .get_mut()
                .map_err(|_| WorkspaceError::Unavailable)?
                .zeroize();
        }
        Ok(())
    }
}

impl Default for HashWorkspace {
    fn default() -> Self {
        Self {
            core: Default::default(),
            last_output: [0; 64],
        }
    }
}

impl Zeroize for HashWorkspace {
    fn zeroize(&mut self) {
        self.core.zeroize();
        self.last_output.zeroize();
    }
}
impl Zeroize for OperationWorkspace {
    fn zeroize(&mut self) {
        self.hash.zeroize();
        self.initial_hash.zeroize();
        self.block_bytes.zeroize();
        self.final_block.zeroize();
    }
}
impl Drop for OperationWorkspace {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for OperationWorkspace {}

// DE/EN: Auch Debug darf keine privaten Eingaben/Zustände zeigen / redact Debug too.
macro_rules! redacted_debug {
    ($type:ty, $name:literal) => {
        impl core::fmt::Debug for $type {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct($name).finish_non_exhaustive()
            }
        }
    };
}
redacted_debug!(WorkspaceInputs<'_>, "WorkspaceInputs");
redacted_debug!(OperationWorkspace, "OperationWorkspace");
redacted_debug!(WorkerWorkspace, "WorkerWorkspace");

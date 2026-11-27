//! DE: Bestehende AES-256-Fixslicing-Kerne mit vollständig gesperrten Ziel-/Scratchflächen.
//! EN: Existing AES-256 fixslicing cores with completely prelocked outputs and scratch.

use super::{BatchBlocks, NativeWord, State, aes256};
use crate::Block;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// DE/EN: Öffentliche Blockgeometrie ungültig / invalid public block geometry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidBlockGeometry;

/// DE: Gesamtes Objekt vor Schlüssel/Blockeingabe sperren; portable konstante Berechnung.
/// EN: Prelock the entire object before key/block input; portable constant-time computation.
pub struct ProtectedAes256 {
    keys: aes256::RoundKeys<NativeWord>,
    state: State<NativeWord>,
    scratch: State<NativeWord>,
    input: BatchBlocks<NativeWord>,
    output: BatchBlocks<NativeWord>,
}

impl Default for ProtectedAes256 {
    fn default() -> Self {
        Self {
            keys: [NativeWord::default(); 120],
            state: Default::default(),
            scratch: Default::default(),
            input: Default::default(),
            output: Default::default(),
        }
    }
}

impl ProtectedAes256 {
    /// DE/EN: Ursprüngliche native Batchgröße / original native batch size.
    #[must_use]
    pub fn batch_size(&self) -> usize {
        self.input.len()
    }

    /// DE: Caller muss self vor privatem Schlüssel vollständig sperren.
    /// EN: Caller must prelock self completely before the private key.
    pub fn initialize(&mut self, key: &[u8; 32]) {
        aes256::key_schedule_into(key, &mut self.keys, &mut self.input, &mut self.scratch);
    }

    /// DE: Self und privates Ausgabeziel müssen vorher vollständig gesperrt sein.
    /// EN: Self and private output storage must already be completely locked.
    pub fn encrypt_block_into(&mut self, input: &Block, out: &mut Block) {
        self.input.fill(Block::default());
        self.input[0].copy_from_slice(input);
        aes256::encrypt_into(
            &self.keys,
            &self.input,
            &mut self.state,
            &mut self.output,
            &mut self.scratch,
        );
        out.copy_from_slice(&self.output[0]);
    }

    /// DE: Self und alle privaten Zielblöcke vorher sperren; native Batchgröße erhalten.
    /// EN: Prelock self and every private output block; preserve the native batch size.
    ///
    /// # Errors
    /// DE/EN: Ungleiche oder zu große Batchgeometrie / mismatched or excessive batch sizes.
    pub fn encrypt_blocks_into(
        &mut self,
        input: &[Block],
        out: &mut [Block],
    ) -> Result<(), InvalidBlockGeometry> {
        if input.len() != out.len() || input.len() > self.input.len() {
            return Err(InvalidBlockGeometry);
        }
        self.input.fill(Block::default());
        for (target, source) in self.input.iter_mut().zip(input) {
            target.copy_from_slice(source);
        }
        aes256::encrypt_into(
            &self.keys,
            &self.input,
            &mut self.state,
            &mut self.output,
            &mut self.scratch,
        );
        for (target, source) in out.iter_mut().zip(self.output.iter()) {
            target.copy_from_slice(source);
        }
        Ok(())
    }
}

impl Zeroize for ProtectedAes256 {
    fn zeroize(&mut self) {
        self.keys.zeroize();
        self.state.zeroize();
        self.scratch.zeroize();
        for block in self.input.iter_mut() {
            block.as_mut_slice().zeroize();
        }
        for block in self.output.iter_mut() {
            block.as_mut_slice().zeroize();
        }
    }
}
impl Drop for ProtectedAes256 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for ProtectedAes256 {}
impl core::fmt::Debug for ProtectedAes256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProtectedAes256").finish_non_exhaustive()
    }
}

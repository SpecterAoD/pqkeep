//! DE: BLAKE2b mit vollständig geliehenen privaten Arbeitsflächen.
//! EN: BLAKE2b with completely borrowed private workspace storage.

use crate::{Array, Blake2bVarCore, InvalidOutputSize, U64, U128, Zeroize, ZeroizeOnDrop};

/// DE: Gesamten öffentlichen Anfangszustand vor privaten Eingaben sperren.
/// EN: Prelock the entire public initial state before private inputs.
pub struct ProtectedBlake2b {
    core: Blake2bVarCore,
    pending: Array<u8, U128>,
    full_output: Array<u8, U64>,
    buffered: usize,
    output_length: usize,
    finalized: bool,
}

impl Default for ProtectedBlake2b {
    fn default() -> Self {
        Self {
            core: Blake2bVarCore::new_with_params(&[], &[], 0, 64),
            pending: Default::default(),
            full_output: Default::default(),
            buffered: 0,
            output_length: 64,
            finalized: false,
        }
    }
}

impl ProtectedBlake2b {
    /// DE: Öffentliche Digestgröße1..64; self vor privater Befüllung sperren.
    /// EN: Public digest size1..64; prelock self before private population.
    /// # Errors
    /// DE/EN: Ungültige Digestgröße / invalid digest size.
    pub fn initialize(&mut self, output_length: usize) -> Result<(), InvalidOutputSize> {
        if !(1..=64).contains(&output_length) {
            return Err(InvalidOutputSize);
        }
        self.zeroize();
        self.core = Blake2bVarCore::new_with_params(&[], &[], 0, output_length);
        self.output_length = output_length;
        self.finalized = false;
        Ok(())
    }

    /// DE: Ursprüngliche Lazy-Blocksemantik, keine private Buffer-Rückgabe.
    /// EN: Original lazy-block semantics, no returned private buffer.
    /// # Errors
    /// DE/EN: Gelöschter/finalisierter Zustand / wiped or finalized state.
    pub fn update(&mut self, mut input: &[u8]) -> Result<(), InvalidOutputSize> {
        self.require_active()?;
        while !input.is_empty() {
            self.flush_full();
            let count = input.len().min(128 - self.buffered);
            self.pending[self.buffered..self.buffered + count].copy_from_slice(&input[..count]);
            self.buffered += count;
            input = &input[count..];
        }
        Ok(())
    }

    /// DE: Längen-/Wortframing direkt im gesperrten Puffer, kein Konvertierungsarray.
    /// EN: Length/word framing directly in the locked buffer, no conversion array.
    /// # Errors
    /// DE/EN: Gelöschter/finalisierter Zustand / wiped or finalized state.
    pub fn update_u32_le(&mut self, value: u32) -> Result<(), InvalidOutputSize> {
        self.require_active()?;
        for index in 0..4 {
            self.flush_full();
            self.pending[self.buffered] = (value >> (index * 8)) as u8;
            self.buffered += 1;
        }
        Ok(())
    }

    fn flush_full(&mut self) {
        if self.buffered == 128 {
            self.core.t += 128;
            self.core.compress(&self.pending, 0, 0);
            self.buffered = 0;
        }
    }

    fn require_active(&self) -> Result<(), InvalidOutputSize> {
        if self.output_length == 0 || self.finalized {
            return Err(InvalidOutputSize);
        }
        Ok(())
    }

    /// DE: Privates Ausgabeziel vorab sperren; genau initialisierte Digestgröße.
    /// EN: Prelock private output; require the initialized digest size exactly.
    /// # Errors
    /// DE/EN: Geometrie/Zustand ungültig, vor Ausgabezugriff / invalid geometry or state before output.
    pub fn finalize_into(&mut self, out: &mut [u8]) -> Result<(), InvalidOutputSize> {
        self.require_active()?;
        if out.len() != self.output_length {
            return Err(InvalidOutputSize);
        }
        self.finalized = true;
        self.pending[self.buffered..].fill(0);
        self.core.t += self.buffered as u64;
        self.core
            .finalize_with_flag(&self.pending, 0, &mut self.full_output);
        out.copy_from_slice(&self.full_output[..self.output_length]);
        Ok(())
    }
}

impl Zeroize for ProtectedBlake2b {
    fn zeroize(&mut self) {
        self.core.zeroize();
        self.pending.as_mut_slice().zeroize();
        self.full_output.as_mut_slice().zeroize();
        self.buffered.zeroize();
        self.output_length.zeroize();
        self.finalized.zeroize();
    }
}
impl Drop for ProtectedBlake2b {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for ProtectedBlake2b {}
impl core::fmt::Debug for ProtectedBlake2b {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProtectedBlake2b").finish_non_exhaustive()
    }
}

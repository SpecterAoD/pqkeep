//! DE: Ursprüngliches Argon2-Framing und BLAKE2b-long ohne private Rückgabepuffer.
//! EN: Original Argon2 framing and BLAKE2b-long without returned private buffers.

use super::{
    Argon2, Block, Error, HashWorkspace, OperationWorkspace, WorkspaceError, WorkspaceInputs,
};
use zeroize::Zeroize;

impl HashWorkspace {
    pub(super) fn long_hash(
        &mut self,
        inputs: &[&[u8]],
        out: &mut [u8],
    ) -> Result<(), WorkspaceError> {
        if out.is_empty() {
            return Err(Error::OutputTooShort.into());
        }
        let length = u32::try_from(out.len()).map_err(|_| Error::OutputTooLong)?;
        self.core.initialize(out.len().min(64))?;
        self.core.update_u32_le(length)?;
        for input in inputs {
            self.core.update(input)?;
        }
        if out.len() <= 64 {
            self.core.finalize_into(out)?;
            return Ok(());
        }
        self.core.finalize_into(&mut self.last_output)?;
        let (first, mut rest) = out.split_at_mut(32);
        first.copy_from_slice(&self.last_output[..32]);
        while rest.len() > 64 {
            let (chunk, tail) = rest.split_at_mut(32);
            rest = tail;
            self.core.initialize(64)?;
            self.core.update(&self.last_output)?;
            self.core.finalize_into(&mut self.last_output)?;
            chunk.copy_from_slice(&self.last_output[..32]);
        }
        self.core.initialize(rest.len())?;
        self.core.update(&self.last_output)?;
        self.core.finalize_into(rest)?;
        Ok(())
    }
}

impl OperationWorkspace {
    pub(super) fn initial_hash(
        &mut self,
        argon: &Argon2<'_>,
        inputs: &WorkspaceInputs<'_>,
        output_length: usize,
    ) -> Result<(), WorkspaceError> {
        let hash = &mut self.hash.core;
        hash.initialize(64)?;
        argon.absorb_initial_hash(
            inputs.password,
            inputs.salt,
            inputs.associated_data,
            output_length,
            hash,
        )?;
        hash.finalize_into(&mut self.initial_hash)?;
        Ok(())
    }

    pub(super) fn initialize_blocks(
        &mut self,
        argon: &Argon2<'_>,
        memory: &mut [Block],
    ) -> Result<(), WorkspaceError> {
        let blocks = &mut memory[..argon.params.block_count()];
        for (lane, blocks) in blocks
            .chunks_exact_mut(argon.params.lane_length())
            .enumerate()
        {
            let lane = u32::try_from(lane).map_err(|_| WorkspaceError::Geometry)?;
            for (index, block) in blocks[..2].iter_mut().enumerate() {
                let index = u32::try_from(index).map_err(|_| WorkspaceError::Geometry)?;
                self.hash.long_hash(
                    &[
                        &self.initial_hash,
                        &index.to_le_bytes(),
                        &lane.to_le_bytes(),
                    ],
                    &mut self.block_bytes,
                )?;
                block.load(&self.block_bytes);
            }
        }
        self.initial_hash.zeroize();
        Ok(())
    }

    pub(super) fn finalize(
        &mut self,
        argon: &Argon2<'_>,
        memory: &[Block],
        out: &mut [u8],
    ) -> Result<(), WorkspaceError> {
        let lane_length = argon.params.lane_length();
        self.final_block
            .as_mut()
            .copy_from_slice(memory[lane_length - 1].as_ref());
        for lane in 1..argon.params.lanes() {
            self.final_block ^= &memory[lane * lane_length + lane_length - 1];
        }
        for (chunk, word) in self
            .block_bytes
            .chunks_exact_mut(8)
            .zip(self.final_block.iter())
        {
            for (index, byte) in chunk.iter_mut().enumerate() {
                *byte = u8::try_from((*word >> (index * 8)) & 0xff)
                    .map_err(|_| WorkspaceError::Geometry)?;
            }
        }
        self.hash.long_hash(&[&self.block_bytes], out)
    }
}

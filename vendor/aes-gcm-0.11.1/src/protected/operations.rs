//! DE: Ursprüngliches GCM-Framing/CTR32BE mit geliehenem privaten Scratch.
//! EN: Original GCM framing/CTR32BE with borrowed private scratch storage.

use super::{Counter, Ctr32BE, CtrFlavor, Error, InOutBuf, Nonce, ProtectedAes256Gcm, State, U16};
use zeroize::Zeroize;

impl State {
    pub(super) fn begin(&mut self, nonce: &Nonce<ProtectedAes256Gcm>) -> Counter {
        self.operations.zeroize();
        self.operations.nonce[..12].copy_from_slice(nonce);
        self.operations.nonce[15] = 1;
        let mut counter = <Ctr32BE as CtrFlavor<U16>>::from_nonce(&self.operations.nonce);
        // DE/EN: Ausschließlich öffentlicher Zählerblock / exclusively public counter block.
        let block = <Ctr32BE as CtrFlavor<U16>>::next_block(&mut counter);
        self.aes
            .encrypt_block_into(&block, &mut self.operations.mask);
        counter
    }

    pub(super) fn apply_keystream(
        &mut self,
        counter: &mut Counter,
        mut buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<(), Error> {
        while !buffer.is_empty() {
            let bytes = buffer.len().min(self.aes.batch_size() * 16);
            let blocks = bytes.div_ceil(16);
            for target in &mut self.operations.counters[..blocks] {
                *target = <Ctr32BE as CtrFlavor<U16>>::next_block(counter);
            }
            self.aes
                .encrypt_blocks_into(
                    &self.operations.counters[..blocks],
                    &mut self.operations.streams[..blocks],
                )
                .map_err(|_| Error)?;
            let (part, rest) = buffer.split_at(bytes);
            for (index, mut byte) in part.into_iter().enumerate() {
                let value = *byte.get_in() ^ self.operations.streams[index / 16][index % 16];
                *byte.get_out() = value;
            }
            buffer = rest;
        }
        Ok(())
    }

    pub(super) fn authenticate(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<(), Error> {
        self.hash.reset();
        self.authenticate_padded(aad);
        self.authenticate_padded(ciphertext);
        let aad_bits = u64::try_from(aad.len()).map_err(|_| Error)? * 8;
        let ciphertext_bits = u64::try_from(ciphertext.len()).map_err(|_| Error)? * 8;
        // DE/EN: Längen sind öffentlich; ursprünglicher Big-Endian-Längenblock.
        // Lengths are public; preserve the original big-endian length block.
        self.operations.padding[..8].copy_from_slice(&aad_bits.to_be_bytes());
        self.operations.padding[8..].copy_from_slice(&ciphertext_bits.to_be_bytes());
        self.hash.update_block(&self.operations.padding);
        self.hash.finalize_into(&mut self.operations.tag);
        for (target, mask) in self
            .operations
            .tag
            .iter_mut()
            .zip(self.operations.mask.iter())
        {
            *target ^= *mask;
        }
        Ok(())
    }

    fn authenticate_padded(&mut self, data: &[u8]) {
        for part in data.chunks(16) {
            self.operations.padding.as_mut_slice().zeroize();
            self.operations.padding[..part.len()].copy_from_slice(part);
            self.hash.update_block(&self.operations.padding);
        }
    }
}

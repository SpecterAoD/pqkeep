//! DE: Fester Root-Vertrag AES-256/GCM, Nonce96/Tag128; vor Schlüsselbefüllung sperren.
//! EN: Fixed Root AES-256/GCM contract, nonce96/tag128; prelock before key population.

use aead::{AeadCore, AeadInOut, Error, Nonce, Tag, TagPosition, inout::InOutBuf};
use aes::{Block, ProtectedAes256};
use cipher::consts::{U12, U16};
use ctr::flavors::{Ctr32BE, CtrFlavor};
use ctutils::CtEq;
use ghash::ProtectedGHash;
use std::sync::Mutex;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod operations;
type Counter = <Ctr32BE as CtrFlavor<U16>>::CtrNonce;

/// DE: Gesamtes Objekt vor privatem Schlüssel sperren; private Ausgaben ebenfalls vorab sperren.
/// EN: Prelock this entire object before a private key; prelock private output buffers too.
/// DE/EN: Portable konstante Berechnung, keine Hardwarebeschleunigungszusage / portable constant-time
/// computation, no hardware-acceleration promise.
#[derive(Default)]
pub struct ProtectedAes256Gcm {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    aes: ProtectedAes256,
    hash: ProtectedGHash,
    operations: Operations,
    initialized: bool,
}

#[derive(Default)]
struct Operations {
    hash_key: Block,
    nonce: Block,
    mask: Block,
    padding: Block,
    tag: Block,
    counters: [Block; 4],
    streams: [Block; 4],
}

impl ProtectedAes256Gcm {
    /// DE: Caller muss self vor privater Initialisierung vollständig sperren.
    /// EN: Caller must completely prelock self before private initialization.
    /// # Errors
    /// DE/EN: Vergifteter Zustand wird verweigert / poisoned state is refused.
    pub fn initialize(&mut self, key: &[u8; 32]) -> Result<(), Error> {
        let state = self.state.get_mut().map_err(|_| Error)?;
        state.zeroize();
        state.aes.initialize(key);
        state
            .aes
            .encrypt_block_into(&Block::default(), &mut state.operations.hash_key);
        state.hash.initialize(&state.operations.hash_key);
        state.operations.hash_key.as_mut_slice().zeroize();
        state.initialized = true;
        Ok(())
    }
}

impl AeadCore for ProtectedAes256Gcm {
    type NonceSize = U12;
    type TagSize = U16;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

fn validate_lengths(data: usize, aad: usize) -> Result<(), Error> {
    if u64::try_from(data).map_err(|_| Error)? > crate::P_MAX
        || u64::try_from(aad).map_err(|_| Error)? > crate::A_MAX
    {
        return Err(Error);
    }
    Ok(())
}

impl AeadInOut for ProtectedAes256Gcm {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>, Error> {
        validate_lengths(buffer.len(), aad.len())?;
        let mut state = self.state.try_lock().map_err(|_| Error)?;
        if !state.initialized {
            return Err(Error);
        }
        let mut counter = state.begin(nonce);
        state.apply_keystream(&mut counter, buffer.reborrow())?;
        state.authenticate(aad, buffer.get_out())?;
        // DE: Erst vollständiges Chiffrat plus beabsichtigter öffentlicher Tag freigeben.
        // EN: Release only complete ciphertext and its intended public tag.
        Ok(state.operations.tag.clone())
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        validate_lengths(buffer.len(), aad.len())?;
        let mut state = self.state.try_lock().map_err(|_| Error)?;
        if !state.initialized {
            return Err(Error);
        }
        let mut counter = state.begin(nonce);
        state.authenticate(aad, buffer.get_in())?;
        let valid: bool = state.operations.tag.ct_eq(tag).into();
        if !valid {
            return Err(Error);
        }
        state.apply_keystream(&mut counter, buffer)
    }
}

impl Zeroize for Operations {
    fn zeroize(&mut self) {
        self.hash_key.as_mut_slice().zeroize();
        self.nonce.as_mut_slice().zeroize();
        self.mask.as_mut_slice().zeroize();
        self.padding.as_mut_slice().zeroize();
        self.tag.as_mut_slice().zeroize();
        for block in &mut self.counters {
            block.as_mut_slice().zeroize();
        }
        for block in &mut self.streams {
            block.as_mut_slice().zeroize();
        }
    }
}
impl Zeroize for State {
    fn zeroize(&mut self) {
        self.aes.zeroize();
        self.hash.zeroize();
        self.operations.zeroize();
        self.initialized = false;
    }
}
impl Zeroize for ProtectedAes256Gcm {
    fn zeroize(&mut self) {
        // DE: Vergifteten Zustand nur löschen; Krypto verweigert ihn weiterhin.
        // EN: Access poisoned storage only for wiping; crypto continues to refuse it.
        let state = match self.state.get_mut() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.zeroize();
    }
}
impl Drop for ProtectedAes256Gcm {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for ProtectedAes256Gcm {}
impl core::fmt::Debug for ProtectedAes256Gcm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProtectedAes256Gcm").finish_non_exhaustive()
    }
}

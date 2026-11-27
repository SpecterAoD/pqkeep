#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]

#[cfg(feature = "hazmat")]
pub mod hazmat;

mod backend;
mod field_element;
#[cfg(feature = "protected-workspace")]
pub use field_element::protected::ProtectedPolyval;

pub use universal_hash;

use crate::backend::State;
use core::fmt::{self, Debug};
use universal_hash::{
    KeyInit, Reset, UhfBackend, UhfClosure, UniversalHash,
    common::{BlockSizeUser, KeySizeUser, ParBlocksSizeUser},
    consts::{U4, U16},
};

/// Size of a POLYVAL block in bytes
pub const BLOCK_SIZE: usize = 16;

/// Size of a POLYVAL key in bytes
pub const KEY_SIZE: usize = 16;

/// POLYVAL keys (16-bytes)
pub type Key = universal_hash::Key<Polyval>;

/// POLYVAL blocks (16-bytes)
pub type Block = universal_hash::Block<Polyval>;

/// POLYVAL parallel blocks (4 x 16-bytes)
pub type ParBlocks = universal_hash::ParBlocks<Polyval>;

/// POLYVAL tags (16-bytes)
pub type Tag = universal_hash::Block<Polyval>;

/// **POLYVAL**: GHASH-like universal hash over GF(2^128), but optimized for little-endian
/// architectures.
#[derive(Clone)]
pub struct Polyval {
    /// State of the internal hash being computed.
    state: State,
}

impl Polyval {
    /// Initialize POLYVAL with the given `H` field element (i.e. hash key).
    #[must_use]
    pub fn new(h: &Key) -> Self {
        Self {
            state: State::new(h),
        }
    }
}

impl KeyInit for Polyval {
    fn new(h: &Key) -> Self {
        Self::new(h)
    }
}

impl KeySizeUser for Polyval {
    type KeySize = U16;
}

impl BlockSizeUser for Polyval {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for Polyval {
    type ParBlocksSize = U4;
}

impl UniversalHash for Polyval {
    fn update_with_backend(&mut self, f: impl UhfClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }

    fn finalize(self) -> Tag {
        self.state.finalize()
    }
}

impl UhfBackend for Polyval {
    fn proc_block(&mut self, block: &Block) {
        self.state.proc_block(block);
    }

    fn proc_par_blocks(&mut self, blocks: &ParBlocks) {
        self.state.proc_par_blocks(blocks);
    }
}

impl Reset for Polyval {
    fn reset(&mut self) {
        self.state.reset();
    }
}

impl Debug for Polyval {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("Polyval").finish_non_exhaustive()
    }
}

impl Drop for Polyval {
    fn drop(&mut self) {
        // SAFETY: `Polyval` satisfies the safety conditions of `zeroize_flat_type`
        #[cfg(feature = "zeroize")]
        unsafe {
            zeroize::zeroize_flat_type(self);
        }
    }
}

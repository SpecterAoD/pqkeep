//! DE: Lebenden Hashzustand und Ausgabesperre neben unabhängigen Digests prüfen.
//! EN: Check live hash state/output locks alongside independent digests.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;
use sha3::{Sha3_256, Sha3_512};

fn check<D>()
where
    D: Digest + FixedOutputReset + ZeroizeOnDrop,
    Output<D>: Zeroize,
{
    for len in [0, 1, 135, 136, 137, 4095, 4096, 4097, 65535, 65536, 65537] {
        let fixture = vec![0x5a; len];
        let mut locked = LockedHash::<D>::new().unwrap();
        for part in fixture.chunks(17) {
            let address = std::ptr::from_ref(locked.state.get()).addr();
            assert!(memlock::is_locked(address));
            assert!(memlock::is_locked(address + size_of::<D>() - 1));
            locked.update(part);
        }
        let output = locked.finalize().unwrap();
        assert!(memlock::is_locked(output.expose().as_ptr().addr()));
        assert_eq!(output.expose(), D::digest(&fixture).as_slice());
    }
}

#[test]
fn sha3_256_state_and_output_are_locked_without_changing_digest() {
    check::<Sha3_256>();
}

#[test]
fn sha3_512_state_and_output_are_locked_without_changing_digest() {
    check::<Sha3_512>();
}

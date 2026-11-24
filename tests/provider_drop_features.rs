//! DE: Typvertrag für die tatsächlichen privaten Argon2-Hashprovider.
//! EN: Destruction contract for the actual private Argon2 hash providers.

fn requires_wiping_drop<T: zeroize::ZeroizeOnDrop>() {}

#[test]
fn blake2_fixed_wrapper_components_require_wiping_drop() {
    use blake2::digest::{
        block_api::CtOutWrapper,
        block_buffer::LazyBuffer,
        consts::{U64, U128},
    };
    requires_wiping_drop::<CtOutWrapper<blake2::Blake2bVarCore, U64>>();
    requires_wiping_drop::<LazyBuffer<U128>>();
}

#[test]
fn blake2_variable_core_requires_wiping_drop() {
    requires_wiping_drop::<blake2::Blake2bVarCore>();
}

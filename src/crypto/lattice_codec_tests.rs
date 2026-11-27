//! DE: Unabhängige Bitreferenz und tatsächlich gesperrte Codec-Ziele.
//! EN: Independent bit reference and actually locked codec destinations.
#![allow(clippy::unwrap_used)]

use super::secret_state::SecretState;
use crate::locked_owner_test_support::locked;
use ml_kem::array::typenum::{U1, U2, U3, U4, U5, U6, U10, U11, U12, U13, U18, U20};
use module_lattice::{
    DecodedValue, Elem, EncodedPolynomial, EncodingSize, Field, byte_decode, byte_decode_into,
    byte_encode, byte_encode_into,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

module_lattice::define_field!(KemField, u16, u32, u64, 3329);
module_lattice::define_field!(DsaField, u32, u64, u128, 8_380_417);

struct Guarded<F: Field, D: EncodingSize>
where
    F::Int: Zeroize,
{
    before: [u8; 7],
    values: DecodedValue<F>,
    encoded: EncodedPolynomial<D>,
    decoded: DecodedValue<F>,
    after: [u8; 9],
}

impl<F: Field, D: EncodingSize> ZeroizeOnDrop for Guarded<F, D> where F::Int: Zeroize {}

impl<F: Field, D: EncodingSize> Drop for Guarded<F, D>
where
    F::Int: Zeroize,
{
    fn drop(&mut self) {
        self.values.zeroize();
        self.encoded.zeroize();
        self.decoded.zeroize();
    }
}

fn exercise<F: Field, D: EncodingSize>(coefficient: impl Fn(usize) -> F::Int)
where
    F::Int: Zeroize,
{
    let mut owner = SecretState::new(Guarded::<F, D> {
        before: [0xa5; 7],
        values: DecodedValue::default(),
        encoded: EncodedPolynomial::<D>::default(),
        decoded: DecodedValue::default(),
        after: [0x5a; 9],
    })
    .unwrap();
    locked(owner.get());
    let address = std::ptr::from_ref(owner.get()).addr();
    let storage = owner.get_mut();
    for (i, value) in storage.values.iter_mut().enumerate() {
        *value = Elem::new(coefficient(i));
    }
    byte_encode_into::<F, D>(&storage.values, &mut storage.encoded);
    same(&storage.encoded, &byte_encode::<F, D>(&storage.values));
    check_bits::<F, D>(storage);
    byte_decode_into::<F, D>(&storage.encoded, &mut storage.decoded);
    same(&storage.decoded, &byte_decode::<F, D>(&storage.encoded));
    assert!(storage.before == [0xa5; 7] && storage.after == [0x5a; 9]);
    check_reduction::<F, D>(storage);
    storage.values.zeroize();
    storage.encoded.zeroize();
    storage.decoded.zeroize();
    assert!(storage.encoded.iter().all(|byte| *byte == 0));
    assert!(
        storage
            .decoded
            .iter()
            .all(|value| Into::<u128>::into(value.0) == 0)
    );
    same(&std::ptr::from_ref(owner.get()).addr(), &address);
    locked(owner.get());
}

fn check_bits<F: Field, D: EncodingSize>(storage: &Guarded<F, D>)
where
    F::Int: Zeroize,
{
    // DE: Einzelbits prüfen, unabhängig von den Provider-Packgruppen.
    // EN: Inspect individual bits independently of provider packing groups.
    for (i, value) in storage.values.iter().enumerate() {
        let coefficient: u128 = value.0.into();
        for bit in 0..D::USIZE {
            let index = i * D::USIZE + bit;
            let actual = (storage.encoded[index / 8] >> (index % 8)) & 1;
            same(&u128::from(actual), &((coefficient >> bit) & 1));
        }
    }
}

fn check_reduction<F: Field, D: EncodingSize>(storage: &Guarded<F, D>)
where
    F::Int: Zeroize,
{
    for (input, actual) in storage.values.iter().zip(storage.decoded.iter()) {
        let input: u128 = input.0.into();
        let expected = if D::USIZE == 12 {
            input % Into::<u128>::into(F::Q)
        } else {
            input
        };
        same(&Into::<u128>::into(actual.0), &expected);
    }
}

macro_rules! check_widths {
    ($field:ty, $int:ty, $($width:ty),+) => {$(
        exercise::<$field, $width>(|i| {
            let mask = (1 << <$width>::USIZE) - 1;
            // DE/EN: Null, Maximum, Einzelbits und Übertragsgrenzen / boundary patterns.
            let value = match i % 5 {
                0 => 0,
                1 => mask,
                2 => one_bit(i, <$width>::USIZE),
                3 => mask / 2,
                _ => i * 17,
            };
            <$int>::try_from(value & mask).unwrap()
        });
    )+};
}

#[test]
fn kem_codec_all_used_widths_into_locked_destinations() {
    use ml_kem::array::typenum::Unsigned;
    check_widths!(KemField, u16, U1, U4, U5, U6, U10, U11, U12);
}

#[test]
fn dsa_codec_all_used_widths_into_locked_destinations() {
    use ml_kem::array::typenum::Unsigned;
    check_widths!(DsaField, u32, U1, U2, U3, U4, U6, U10, U13, U18, U20);
}

// DE: Keine Koeffizienten/Adressen bei Fehlern ausgeben.
// EN: Never print coefficients/addresses on assertion failure.
fn same<T: PartialEq>(left: &T, right: &T) {
    let equal = left == right;
    assert!(equal);
}

fn one_bit(index: usize, width: usize) -> usize {
    1 << (index % width)
}

struct GuardedVector<D, K>
where
    K: module_lattice::ArraySize,
    D: module_lattice::VectorEncodingSize<K>,
{
    before: [u8; 5],
    values: module_lattice::Vector<KemField, K>,
    encoded: module_lattice::EncodedVector<D, K>,
    after: [u8; 7],
}

impl<D, K> ZeroizeOnDrop for GuardedVector<D, K>
where
    K: module_lattice::ArraySize,
    D: module_lattice::VectorEncodingSize<K>,
{
}

impl<D, K> Drop for GuardedVector<D, K>
where
    K: module_lattice::ArraySize,
    D: module_lattice::VectorEncodingSize<K>,
{
    fn drop(&mut self) {
        self.values.zeroize();
        self.encoded.zeroize();
    }
}

fn vector_output<D, K>()
where
    K: module_lattice::ArraySize,
    D: module_lattice::VectorEncodingSize<K>,
{
    let mut owner = SecretState::new(GuardedVector::<D, K> {
        before: [0xa5; 5],
        values: module_lattice::Vector::default(),
        encoded: module_lattice::EncodedVector::<D, K>::default(),
        after: [0x5a; 7],
    })
    .unwrap();
    locked(owner.get());
    let storage = owner.get_mut();
    for (i, polynomial) in storage.values.0.iter_mut().enumerate() {
        for (j, value) in polynomial.0.iter_mut().enumerate() {
            *value = Elem::new(u16::try_from((i * 257 + j * 17) & ((1 << D::USIZE) - 1)).unwrap());
        }
    }
    module_lattice::byte_encode_vector_into::<KemField, D, K>(
        &storage.values,
        &mut storage.encoded,
    )
    .unwrap();
    let mut legacy = module_lattice::Encode::<D>::encode(&storage.values);
    same(&storage.encoded, &legacy);
    legacy.zeroize();
    assert!(storage.before == [0xa5; 5] && storage.after == [0x5a; 7]);
    locked(owner.get());
}

#[test]
fn private_ciphertext_vector_encoding_borrows_locked_output_for_all_kem_variants() {
    vector_output::<U10, U2>();
    vector_output::<U10, U3>();
    vector_output::<U11, U4>();
}

#[test]
fn unsupported_vector_encoding_geometry_is_rejected_before_output_writes() {
    use ml_kem::array::typenum::U256;
    let mut owner = SecretState::new(GuardedVector::<U256, U1> {
        before: [0xa5; 5],
        values: module_lattice::Vector::default(),
        encoded: module_lattice::EncodedVector::<U256, U1>::default(),
        after: [0x5a; 7],
    })
    .unwrap();
    let storage = owner.get_mut();
    storage.encoded.fill(0xa5);
    assert!(
        module_lattice::byte_encode_vector_into::<KemField, U256, U1>(
            &storage.values,
            &mut storage.encoded,
        )
        .is_err()
    );
    assert!(storage.encoded.iter().all(|byte| *byte == 0xa5));
    locked(owner.get());
}

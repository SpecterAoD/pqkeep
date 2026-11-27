//! DE: Private Vektorkodierung direkt in geliehene vollständige Ausgabe.
//! EN: Encode private vectors directly into borrowed complete output storage.

use crate::{ArraySize, EncodedPolynomial, EncodedVector, Field, Vector, VectorEncodingSize};
use array::typenum::Unsigned;

/// DE: Ungültige öffentliche Ausgabegeometrie, vor dem Schreiben abgelehnt.
/// EN: Invalid public output geometry, rejected before writing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidEncodingGeometry;

/// DE: Kodiert ohne private Polynom-/Vektorrückgabe ins vorhandene Caller-Ziel.
/// EN: Encode into existing caller storage without private polynomial/vector returns.
///
/// # Errors
/// DE/EN: `InvalidEncodingGeometry` bei unvollständigen Zielteilen / incomplete output parts.
pub fn byte_encode_vector_into<F, D, K>(
    values: &Vector<F, K>,
    out: &mut EncodedVector<D, K>,
) -> Result<(), InvalidEncodingGeometry>
where
    F: Field,
    D: VectorEncodingSize<K>,
    K: ArraySize,
{
    let polynomial_bytes = D::EncodedPolynomialSize::USIZE;
    let byte_step = D::ByteStep::USIZE;
    let value_step = D::ValueStep::USIZE;
    if polynomial_bytes == 0
        || byte_step == 0
        || byte_step > 16
        || value_step == 0
        || polynomial_bytes % byte_step != 0
        || 256 % value_step != 0
        || polynomial_bytes / byte_step != 256 / value_step
        || D::USIZE.checked_mul(value_step) != Some(byte_step * 8)
    {
        return Err(InvalidEncodingGeometry);
    }
    let (chunks, tail) = EncodedPolynomial::<D>::slice_as_chunks_mut(out.as_mut_slice());
    if !tail.is_empty() || chunks.len() != values.0.len() {
        return Err(InvalidEncodingGeometry);
    }
    for (polynomial, target) in values.0.iter().zip(chunks) {
        crate::byte_encode_into::<F, D>(&polynomial.0, target);
    }
    Ok(())
}

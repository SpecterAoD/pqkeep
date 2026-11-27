use core::ops::Mul;
use ctutils::{CtEq, CtGt, CtLt, CtSelect};
use hybrid_array::{
    Array, ArraySize,
    typenum::{Shleft, U1, U13, Unsigned},
};
use module_lattice::{Field, MaybeBox, Truncate};

module_lattice::define_field!(BaseField, u32, u64, u128, 8_380_417);

pub(crate) type Int = <BaseField as Field>::Int;

pub(crate) type Elem = module_lattice::Elem<BaseField>;
pub(crate) type Polynomial = module_lattice::Polynomial<BaseField>;
pub(crate) type Vector<K> = module_lattice::Vector<BaseField, K>;
pub(crate) type NttPolynomial = module_lattice::NttPolynomial<BaseField>;
pub(crate) type NttVector<K> = module_lattice::NttVector<BaseField, K>;

/// Private matrix storage which offloads each row before constructing the next one.
/// Without `alloc`, `MaybeBox` keeps the rows inline.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct NttMatrix<K: ArraySize, L: ArraySize>(Array<MaybeBox<NttVector<L>>, K>);

impl<K: ArraySize, L: ArraySize> NttMatrix<K, L> {
    pub(crate) fn from_fn(mut f: impl FnMut(usize) -> NttVector<L>) -> Self {
        Self(Array::from_fn(|i| MaybeBox::new(f(i))))
    }

    #[cfg(feature = "protected-workspace")]
    pub(crate) fn multiply_into(
        &self,
        rhs: &NttVector<L>,
        out: &mut NttVector<K>,
        product: &mut NttPolynomial,
    ) {
        for (row, target) in self.0.iter().zip(out.0.iter_mut()) {
            target.0.fill(Elem::new(0));
            for (left, right) in row.0.iter().zip(rhs.0.iter()) {
                crate::ntt::multiply_ntt_into(left, right, product);
                for (sum, value) in target.0.iter_mut().zip(product.0.iter()) {
                    *sum = *sum + *value;
                }
            }
        }
    }
}

impl<K: ArraySize, L: ArraySize> Mul<&NttVector<L>> for &NttMatrix<K, L> {
    type Output = NttVector<K>;

    fn mul(self, rhs: &NttVector<L>) -> Self::Output {
        NttVector::new(self.0.iter().map(|row| &**row * rhs).collect())
    }
}

// We require modular reduction for three moduli: q, 2^d, and 2 * gamma2.  All three of these are
// greater than sqrt(q), which means that a number reduced mod q will always be less than M^2,
// which means that barrett reduction will work.
pub(crate) trait BarrettReduce: Unsigned {
    const SHIFT: usize;
    const MULTIPLIER: u64;

    fn reduce(x: u32) -> u32 {
        let m = Self::U64;
        let x: u64 = x.into();
        let quotient = (x * Self::MULTIPLIER) >> Self::SHIFT;
        let remainder = x - quotient * m;

        let r_small: u32 = Truncate::truncate(remainder);
        let r_large: u32 = Truncate::truncate(remainder.wrapping_sub(m));
        u32::ct_select(&r_large, &r_small, remainder.ct_lt(&m))
    }
}

impl<M> BarrettReduce for M
where
    M: Unsigned,
{
    #[allow(clippy::as_conversions)]
    const SHIFT: usize = 2 * (M::U64.ilog2() + 1) as usize;
    #[allow(clippy::integer_division_remainder_used, reason = "constant")]
    const MULTIPLIER: u64 = (1 << Self::SHIFT) / M::U64;
}

pub(crate) trait Decompose {
    fn decompose<TwoGamma2: Unsigned>(self) -> (Elem, Elem);
}

/// Constant-time division by a compile-time constant divisor.
///
/// This trait provides a constant-time alternative to the hardware division
/// instruction, which has variable timing based on operand values.
/// Uses Barrett reduction to compute `x / M` where M is a compile-time constant.
pub(crate) trait ConstantTimeDiv: Unsigned {
    /// Bit shift for Barrett reduction, chosen to provide sufficient precision
    const CT_DIV_SHIFT: usize;
    /// Precomputed multiplier: ceil(2^SHIFT / M)
    const CT_DIV_MULTIPLIER: u64;

    /// Perform constant-time division of x by `Self::U32`
    /// Requires: x < Q (the field modulus, ~2^23)
    #[allow(clippy::inline_always)] // Required for constant-time guarantees in crypto code
    #[inline(always)]
    fn ct_div(x: u32) -> u32 {
        // Barrett reduction: q = (x * MULTIPLIER) >> SHIFT
        // This gives us floor(x / M) for x < Q
        let x64 = u64::from(x);
        let quotient = (x64 * Self::CT_DIV_MULTIPLIER) >> Self::CT_DIV_SHIFT;
        // Quotient is guaranteed to fit in u32 because:
        // - x < Q (~2^23), so quotient = x / M < x < 2^23 < 2^32
        #[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
        let result = quotient as u32;
        result
    }
}

impl<M> ConstantTimeDiv for M
where
    M: Unsigned,
{
    // Use a shift that provides enough precision for the ML-DSA field (Q ~ 2^23)
    // We need SHIFT > log2(Q) + log2(M) to ensure accuracy
    // With Q < 2^24 and M < 2^20, SHIFT = 48 is sufficient
    const CT_DIV_SHIFT: usize = 48;

    // Precompute the multiplier at compile time
    // We add (M-1) before dividing to get ceiling division, ensuring we never underestimate
    #[allow(clippy::integer_division_remainder_used, reason = "constant")]
    const CT_DIV_MULTIPLIER: u64 = (1u64 << Self::CT_DIV_SHIFT).div_ceil(M::U64);
}

impl Decompose for Elem {
    // Algorithm 36 Decompose
    //
    // This implementation uses constant-time division to avoid timing side-channels.
    // The original algorithm used hardware division which has variable timing based
    // on operand values, potentially leaking secret information during signing.
    fn decompose<TwoGamma2: Unsigned>(self) -> (Elem, Elem) {
        let r_plus = self.clone();
        let r0 = r_plus.mod_plus_minus::<TwoGamma2>();

        let diff = r_plus - r0;
        let is_edge = diff.0.ct_eq(&(BaseField::Q - 1));

        // Compute both branches unconditionally
        let edge = (Elem::new(0), r0 - Elem::new(1));
        let r1 = Elem::new(TwoGamma2::ct_div(diff.0));
        let normal = (r1, r0);

        let r1_out = Elem::new(u32::ct_select(&normal.0.0, &edge.0.0, is_edge));
        let r0_out = Elem::new(u32::ct_select(&normal.1.0, &edge.1.0, is_edge));
        (r1_out, r0_out)
    }
}

#[allow(clippy::module_name_repetitions)] // I can't think of a better name
pub(crate) trait AlgebraExt: Sized {
    fn mod_plus_minus<M: Unsigned>(&self) -> Self;
    fn infinity_norm(&self) -> Int;
    fn power2round(&self) -> (Self, Self);
    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self;
    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self;
}

impl AlgebraExt for Elem {
    fn mod_plus_minus<M: Unsigned>(&self) -> Self {
        let raw_mod = Elem::new(M::reduce(self.0));
        let in_lower_half = !raw_mod.0.ct_gt(&(M::U32 >> 1));
        Elem::new(u32::ct_select(
            &(raw_mod - Elem::new(M::U32)).0,
            &raw_mod.0,
            in_lower_half,
        ))
    }

    // FIPS 204 defines the infinity norm differently for signed vs. unsigned integers:
    //
    // * For w in Z, |w|_\infinity = |w|, the absolute value of w
    // * For w in Z_q, |W|_infinity = |w mod^\pm q|
    //
    // Note that these two definitions are equivalent if |w| < q/2.  This property holds for all of
    // the signed integers used in this crate, so we can safely use the unsigned version.  However,
    // since mod_plus_minus is also unsigned, we need to unwrap the "negative" values.
    fn infinity_norm(&self) -> u32 {
        let in_lower_half = !self.0.ct_gt(&(BaseField::Q >> 1));
        u32::ct_select(&(BaseField::Q - self.0), &self.0, in_lower_half)
    }

    // Algorithm 35 Power2Round
    //
    // In the specification, this function maps to signed integers rather than modular integers.
    // To avoid the need for a whole separate type for signed integer polynomials, we represent
    // these values using integers mod Q.  This is safe because Q is much larger than 2^13, so
    // there's no risk of overlap between positive numbers (x) and negative numbers (Q-x).
    fn power2round(&self) -> (Self, Self) {
        type D = U13;
        type Pow2D = Shleft<U1, D>;

        let r_plus = self.clone();
        let r0 = r_plus.mod_plus_minus::<Pow2D>();
        let r1 = Elem::new((r_plus - r0).0 >> D::USIZE);

        (r1, r0)
    }

    // Algorithm 37 HighBits
    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self {
        self.decompose::<TwoGamma2>().0
    }

    // Algorithm 38 LowBits
    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self {
        self.decompose::<TwoGamma2>().1
    }
}

impl AlgebraExt for Polynomial {
    fn mod_plus_minus<M: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(AlgebraExt::mod_plus_minus::<M>).collect())
    }

    fn infinity_norm(&self) -> u32 {
        self.0
            .iter()
            .map(AlgebraExt::infinity_norm)
            .fold(0, |acc, x| u32::ct_select(&x, &acc, acc.ct_gt(&x)))
    }

    fn power2round(&self) -> (Self, Self) {
        let mut r1 = Self::default();
        let mut r0 = Self::default();

        for (i, x) in self.0.iter().enumerate() {
            (r1.0[i], r0.0[i]) = x.power2round();
        }

        (r1, r0)
    }

    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::high_bits::<TwoGamma2>)
                .collect(),
        )
    }

    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::low_bits::<TwoGamma2>)
                .collect(),
        )
    }
}

impl<K: ArraySize> AlgebraExt for Vector<K> {
    fn mod_plus_minus<M: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(AlgebraExt::mod_plus_minus::<M>).collect())
    }

    fn infinity_norm(&self) -> u32 {
        self.0
            .iter()
            .map(AlgebraExt::infinity_norm)
            .fold(0, |acc, x| u32::ct_select(&x, &acc, acc.ct_gt(&x)))
    }

    fn power2round(&self) -> (Self, Self) {
        let mut r1 = Self::default();
        let mut r0 = Self::default();

        for (i, x) in self.0.iter().enumerate() {
            (r1.0[i], r0.0[i]) = x.power2round();
        }

        (r1, r0)
    }

    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::high_bits::<TwoGamma2>)
                .collect(),
        )
    }

    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::low_bits::<TwoGamma2>)
                .collect(),
        )
    }
}

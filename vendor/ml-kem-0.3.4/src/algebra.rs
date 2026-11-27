use crate::{
    B32,
    crypto::{PRF, PrfOutput, XOF},
    param::CbdSamplingSize,
};
use array::{Array, ArraySize, typenum::U256};
use module_lattice::{Field, MultiplyNtt, Truncate};
use sha3::digest::XofReader;

module_lattice::define_field!(BaseField, u16, u32, u64, 3329);

pub(crate) type Int = <BaseField as Field>::Int;

/// An element of GF(q).
pub(crate) type Elem = module_lattice::Elem<BaseField>;

/// An element of the ring `R_q`, i.e., a polynomial over `Z_q` of degree 255
pub(crate) type Polynomial = module_lattice::Polynomial<BaseField>;

/// A vector of polynomials of length `K`.
pub(crate) type Vector<K> = module_lattice::Vector<BaseField, K>;

/// An element of the ring `T_q` i.e. a tuple of 128 elements of the direct sum components of `T_q`.
pub(crate) type NttPolynomial = module_lattice::NttPolynomial<BaseField>;

/// A vector of K NTT-domain polynomials.
pub(crate) type NttVector<K> = module_lattice::NttVector<BaseField, K>;

/// A K x K matrix of NTT-domain polynomials.  Each vector represents a row of the matrix, so that
/// multiplying on the right just requires iteration.
pub(crate) type NttMatrix<K> = module_lattice::NttMatrix<BaseField, K, K>;

/// SHAKE128 rate in bytes. It is a multiple of 3, so every block holds whole 3-byte groups.
const SHAKE128_BLOCK_SIZE: usize = 168;

/// Algorithm 7: `SampleNTT(B)`
///
/// The XOF output is consumed in whole SHAKE128 blocks: three blocks yield 256 accepted
/// coefficients except with small probability, after which blocks are squeezed one at a time.
/// The XOF input is the public seed `rho`, so the data-dependent loop does not leak secrets.
pub(crate) fn sample_ntt(B: &mut impl XofReader) -> NttPolynomial {
    let mut coeffs = [Elem::new(0); 256];

    let mut bytes = [0u8; 3 * SHAKE128_BLOCK_SIZE];
    B.read(&mut bytes);
    let mut n = rej_uniform(&mut coeffs, 0, &bytes);

    while n < coeffs.len() {
        let mut block = [0u8; SHAKE128_BLOCK_SIZE];
        B.read(&mut block);
        n = rej_uniform(&mut coeffs, n, &block);
    }

    NttPolynomial::new(coeffs.into())
}

/// Parse `bytes` into 12-bit candidates, append those below `q` to `coeffs[n..]`, and return the
/// new number of coefficients (Algorithm 7, steps 3-15).
fn rej_uniform(coeffs: &mut [Elem; 256], mut n: usize, bytes: &[u8]) -> usize {
    for b in bytes.chunks_exact(3) {
        if n == coeffs.len() {
            break;
        }

        let d1 = Int::from(b[0]) + ((Int::from(b[1]) & 0xf) << 8);
        let d2 = (Int::from(b[1]) >> 4) + (Int::from(b[2]) << 4);

        if d1 < BaseField::Q {
            coeffs[n] = Elem::new(d1);
            n += 1;
        }

        if d2 < BaseField::Q && n < coeffs.len() {
            coeffs[n] = Elem::new(d2);
            n += 1;
        }
    }

    n
}

pub(crate) fn matrix_sample_ntt<K: ArraySize>(rho: &B32, transpose: bool) -> NttMatrix<K> {
    NttMatrix::new(Array::from_fn(|i| {
        NttVector::new(Array::from_fn(|j| {
            let (i, j) = if transpose { (j, i) } else { (i, j) };
            let mut xof = XOF(rho, Truncate::truncate(j), Truncate::truncate(i));
            sample_ntt(&mut xof)
        }))
    }))
}

/// Algorithm 8: `SamplePolyCBD_eta(B)`
///
/// To avoid all the bitwise manipulation in the algorithm as written, we reuse the logic in
/// `ByteDecode`.  We decode the PRF output into integers with `2 * eta` bits, then use
/// `count_ones` to perform the summation described in the algorithm.
///
/// The PRF output is secret, so each coefficient is computed arithmetically: no memory access
/// or branch depends on the sampled bits (in particular, there is no lookup table).
pub(crate) fn sample_poly_cbd<Eta>(B: &PrfOutput<Eta>) -> Polynomial
where
    Eta: CbdSamplingSize,
{
    let mut out = Polynomial::default();
    sample_poly_cbd_into::<Eta>(B, &mut out);
    out
}

// DE: Dieselben CBD-Koeffizienten direkt im geliehenen Dekodierziel auswerten.
// EN: Evaluate the same CBD coefficients directly in the borrowed decoding target.
pub(crate) fn sample_poly_cbd_into<Eta>(B: &PrfOutput<Eta>, out: &mut Polynomial)
where
    Eta: CbdSamplingSize,
{
    module_lattice::byte_decode_into::<BaseField, Eta::SampleSize>(B, &mut out.0);
    for value in &mut out.0 {
        *value = cbd_coefficient::<Eta>(value.0);
    }
}

/// Map `2 * eta` sampled bits to a CBD coefficient: the number of ones in the low `eta` bits
/// minus the number of ones in the high `eta` bits, reduced mod `q`.
fn cbd_coefficient<Eta>(bits: Int) -> Elem
where
    Eta: CbdSamplingSize,
{
    let low_mask: Int = (1 << Eta::USIZE) - 1;
    let x = <Int as Truncate<u32>>::truncate((bits & low_mask).count_ones());
    let y = <Int as Truncate<u32>>::truncate((bits >> Eta::USIZE).count_ones());

    // x, y <= eta, so `x + Q - y` is in `[Q - eta, Q + eta]` and one conditional subtraction
    // fully reduces it.
    Elem::new(BaseField::small_reduce(x + BaseField::Q - y))
}

pub(crate) fn sample_poly_vec_cbd<Eta, K>(sigma: &B32, start_n: u8) -> Vector<K>
where
    Eta: CbdSamplingSize,
    K: ArraySize,
{
    Vector::new(Array::from_fn(|i| {
        let i: u8 = Truncate::truncate(i);
        let N = start_n + i;
        let prf_output = PRF::<Eta>(sigma, N);
        sample_poly_cbd::<Eta>(&prf_output)
    }))
}

/// The Number Theoretic Transform (NTT) is a variant of the Discrete Fourier Transform (DFT)
/// defined over a finite field that turns costly polynomial multiplications into simple
/// coefficient-wise multiplications modulo a fixed prime.
pub(crate) trait Ntt {
    type Output: Default;
    fn ntt(&self) -> Self::Output {
        let mut out = Self::Output::default();
        self.ntt_into(&mut out);
        out
    }

    // DE: Bestehende Transformation in die geliehene Fläche schreiben.
    // EN: Write the existing transform into borrowed storage.
    fn ntt_into(&self, out: &mut Self::Output);
}

/// One layer of the forward NTT butterfly.
///
/// `LEN` is the butterfly half-length and `ITERATIONS = 128 / LEN` is the number of
/// butterfly groups in the layer. Making both compile-time constants lets the compiler
/// eliminate the iterator length calculation (`256 / (2 * LEN)`) that `step_by` would
/// otherwise compute with a `UDIV` instruction.
#[inline(always)]
fn ntt_layer<const LEN: usize, const ITERATIONS: usize>(f: &mut Array<Elem, U256>, k: &mut usize) {
    for i in 0..ITERATIONS {
        let start = i * 2 * LEN;
        let zeta = ZETA_POW_BITREV[*k];
        *k += 1;

        for j in start..(start + LEN) {
            let t = zeta * f[j + LEN];
            f[j + LEN] = f[j] - t;
            f[j] = f[j] + t;
        }
    }
}

/// Algorithm 9: `NTT`
impl Ntt for Polynomial {
    type Output = NttPolynomial;

    fn ntt_into(&self, out: &mut NttPolynomial) {
        let mut k = 1;
        let f = &mut out.0;
        f.copy_from_slice(&self.0);

        ntt_layer::<128, 1>(f, &mut k);
        ntt_layer::<64, 2>(f, &mut k);
        ntt_layer::<32, 4>(f, &mut k);
        ntt_layer::<16, 8>(f, &mut k);
        ntt_layer::<8, 16>(f, &mut k);
        ntt_layer::<4, 32>(f, &mut k);
        ntt_layer::<2, 64>(f, &mut k);
    }
}

impl<K: ArraySize> Ntt for Vector<K> {
    type Output = NttVector<K>;

    fn ntt_into(&self, out: &mut NttVector<K>) {
        for (source, target) in self.0.iter().zip(out.0.iter_mut()) {
            source.ntt_into(target);
        }
    }
}

/// The inverse NTT is the reverse of the Number Theoretic Transform, converting coefficient-wise
/// products back into standard polynomial form while preserving correctness modulo the same prime.
#[allow(clippy::module_name_repetitions)]
pub(crate) trait NttInverse {
    type Output;
    fn ntt_inverse(&self) -> Self::Output;
}

/// One layer of the inverse NTT butterfly.
///
/// See [`ntt_layer`] for the rationale behind the const generics.
#[inline(always)]
fn ntt_inverse_layer<const LEN: usize, const ITERATIONS: usize>(
    f: &mut Array<Elem, U256>,
    k: &mut usize,
) {
    for i in 0..ITERATIONS {
        let start = i * 2 * LEN;
        let zeta = ZETA_POW_BITREV[*k];
        *k -= 1;

        for j in start..(start + LEN) {
            let t = f[j];
            f[j] = t + f[j + LEN];
            f[j + LEN] = zeta * (f[j + LEN] - t);
        }
    }
}

/// Algorithm 10: `NTT^{-1}`
impl NttInverse for NttPolynomial {
    type Output = Polynomial;

    fn ntt_inverse(&self) -> Polynomial {
        let mut f: Array<Elem, U256> = self.0.clone();
        let mut k = 127;

        ntt_inverse_layer::<2, 64>(&mut f, &mut k);
        ntt_inverse_layer::<4, 32>(&mut f, &mut k);
        ntt_inverse_layer::<8, 16>(&mut f, &mut k);
        ntt_inverse_layer::<16, 8>(&mut f, &mut k);
        ntt_inverse_layer::<32, 4>(&mut f, &mut k);
        ntt_inverse_layer::<64, 2>(&mut f, &mut k);
        ntt_inverse_layer::<128, 1>(&mut f, &mut k);

        Elem::new(3303) * &Polynomial::new(f)
    }
}

impl<K: ArraySize> NttInverse for NttVector<K> {
    type Output = Vector<K>;

    fn ntt_inverse(&self) -> Vector<K> {
        Vector::new(self.0.iter().map(NttInverse::ntt_inverse).collect())
    }
}

/// Algorithm 11: `MultiplyNTTs`
impl MultiplyNtt for BaseField {
    fn multiply_ntt(lhs: &NttPolynomial, rhs: &NttPolynomial) -> NttPolynomial {
        let mut out = NttPolynomial::new(Array::default());

        for i in 0..128 {
            let (c0, c1) = base_case_multiply(
                lhs.0[2 * i],
                lhs.0[2 * i + 1],
                rhs.0[2 * i],
                rhs.0[2 * i + 1],
                i,
            );

            out.0[2 * i] = c0;
            out.0[2 * i + 1] = c1;
        }

        out
    }
}

/// Algorithm 12: `BaseCaseMultiply`
///
/// This is a hot loop.  We promote to u64 so that we can do the absolute minimum number of
/// modular reductions, since these are the expensive operation.
#[inline]
fn base_case_multiply(a0: Elem, a1: Elem, b0: Elem, b1: Elem, i: usize) -> (Elem, Elem) {
    let a0 = u32::from(a0.0);
    let a1 = u32::from(a1.0);
    let b0 = u32::from(b0.0);
    let b1 = u32::from(b1.0);
    let g = u32::from(GAMMA[i].0);

    let b1g = u32::from(BaseField::barrett_reduce(b1 * g));

    let c0 = BaseField::barrett_reduce(a0 * b0 + a1 * b1g);
    let c1 = BaseField::barrett_reduce(a0 * b1 + a1 * b0);
    (Elem::new(c0), Elem::new(c1))
}

/// Since the powers of zeta used in the `NTT` and `MultiplyNTTs` are fixed, we use pre-computed
/// tables to avoid the need to compute the exponentiations at runtime.
///
/// * `ZETA_POW_BITREV[i] = zeta^{BitRev_7(i)}`
/// * `GAMMA[i] = zeta^{2 BitRev_7(i) + 1}`
///
/// Note that the const environment here imposes some annoying conditions.  Because operator
/// overloading can't be const, we have to do all the reductions here manually.  Because `for` loops
/// are forbidden in `const` functions, we do them manually with `while` loops.
///
/// The values computed here match those provided in Appendix A of FIPS 203.
/// `ZETA_POW_BITREV` corresponds to the first table, and `GAMMA` to the second table.
#[allow(clippy::integer_division_remainder_used, reason = "constant")]
const ZETA_POW_BITREV: [Elem; 128] = {
    const ZETA: u64 = 17;

    const fn bitrev7(x: usize) -> usize {
        ((x >> 6) % 2)
            | (((x >> 5) % 2) << 1)
            | (((x >> 4) % 2) << 2)
            | (((x >> 3) % 2) << 3)
            | (((x >> 2) % 2) << 4)
            | (((x >> 1) % 2) << 5)
            | ((x % 2) << 6)
    }

    // Compute the powers of zeta
    let mut pow = [Elem::new(0); 128];
    let mut i = 0;
    let mut curr = 1u64;

    while i < 128 {
        pow[i] = Elem::new((curr & 0xFFFF) as u16);
        i += 1;
        curr = (curr * ZETA) % BaseField::QLL;
    }

    // Reorder the powers according to bitrev7
    let mut pow_bitrev = [Elem::new(0); 128];
    let mut i = 0;
    while i < 128 {
        pow_bitrev[i] = pow[bitrev7(i)];
        i += 1;
    }
    pow_bitrev
};

#[allow(clippy::integer_division_remainder_used, reason = "constant")]
const GAMMA: [Elem; 128] = {
    const ZETA: u64 = 17;
    let mut gamma = [Elem::new(0); 128];
    let mut i = 0;
    while i < 128 {
        let zpr = ZETA_POW_BITREV[i].0 as u64;
        let g = (zpr * zpr * ZETA) % BaseField::QLL;
        gamma[i] = Elem::new((g & 0xFFFF) as u16);
        i += 1;
    }
    gamma
};

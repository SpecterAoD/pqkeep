use crate::algebra::{BaseField, Elem, Int, Polynomial, Vector};
use array::ArraySize;
use module_lattice::EncodingSize;
use module_lattice::{Field, Truncate};

// A convenience trait to allow us to associate some constants with a typenum
pub(crate) trait CompressionFactor: EncodingSize {
    const POW2_HALF: u32;
    const MASK: Int;
    const DIV_SHIFT: usize;
    const DIV_MUL: u64;
}

impl<T> CompressionFactor for T
where
    T: EncodingSize,
{
    const POW2_HALF: u32 = 1 << (T::USIZE - 1);
    const MASK: Int = (1 << T::USIZE) - 1;
    const DIV_SHIFT: usize = 34;
    #[allow(clippy::integer_division_remainder_used, reason = "constant")]
    const DIV_MUL: u64 = (1 << T::DIV_SHIFT) / BaseField::QLL;
}

// Traits for objects that allow compression / decompression
pub(crate) trait Compress {
    fn compress<D: CompressionFactor>(&mut self) -> &Self;
    fn decompress<D: CompressionFactor>(&mut self) -> &Self;
}

impl Compress for Elem {
    // Equation 4.5: Compress_d(x) = round((2^d / q) x)
    //
    // Here and in decompression, we leverage the following facts:
    //
    //   round(a / b) = floor((a + b/2) / b)
    //   a / q ~= (a * x) >> s where x >> s ~= 1/q
    fn compress<D: CompressionFactor>(&mut self) -> &Self {
        const Q_HALF: u64 = (BaseField::QLL + 1) >> 1;
        let x = u64::from(self.0);
        let y = (((x << D::USIZE) + Q_HALF) * D::DIV_MUL) >> D::DIV_SHIFT;
        let y: u16 = Truncate::truncate(y);
        self.0 = y & D::MASK;
        self
    }

    // Equation 4.6: Decompress_d(x) = round((q / 2^d) x)
    fn decompress<D: CompressionFactor>(&mut self) -> &Self {
        let x = u32::from(self.0);
        let y = ((x * BaseField::QL) + D::POW2_HALF) >> D::USIZE;
        self.0 = Truncate::truncate(y);
        self
    }
}
impl Compress for Polynomial {
    fn compress<D: CompressionFactor>(&mut self) -> &Self {
        for x in &mut self.0 {
            x.compress::<D>();
        }

        self
    }

    fn decompress<D: CompressionFactor>(&mut self) -> &Self {
        for x in &mut self.0 {
            x.decompress::<D>();
        }

        self
    }
}

impl<K: ArraySize> Compress for Vector<K> {
    fn compress<D: CompressionFactor>(&mut self) -> &Self {
        for x in &mut self.0 {
            x.compress::<D>();
        }

        self
    }

    fn decompress<D: CompressionFactor>(&mut self) -> &Self {
        for x in &mut self.0 {
            x.decompress::<D>();
        }

        self
    }
}

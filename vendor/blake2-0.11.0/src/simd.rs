use core::ops::{Add, BitXor, Shl, Shr};

#[cfg(feature = "zeroize")]
use digest::zeroize::Zeroize;

macro_rules! impl_vector4 {
    ($vec:ident, $word:ident) => {
        #[derive(Clone, Copy, Debug)]
        #[repr(C)]
        pub(crate) struct $vec(
            pub(crate) $word,
            pub(crate) $word,
            pub(crate) $word,
            pub(crate) $word,
        );

        impl $vec {
            #[inline(always)]
            pub(crate) fn new(e0: $word, e1: $word, e2: $word, e3: $word) -> Self {
                Self(e0, e1, e2, e3)
            }

            // DE: Direkt in vorab gesperrtes Ziel; kein privater Konvertierungsvektor.
            // EN: Directly into prelocked output; no private conversion vector.
            #[cfg(feature = "protected-workspace")]
            pub(crate) fn write_le_into(&self, out: &mut [u8]) {
                let width = core::mem::size_of::<$word>();
                for (index, byte) in out.iter_mut().enumerate() {
                    let value = match index / width {
                        0 => self.0,
                        1 => self.1,
                        2 => self.2,
                        _ => self.3,
                    };
                    *byte = (value >> ((index % width) * 8)) as u8;
                }
            }

            #[inline(always)]
            pub(crate) fn gather_into(
                &mut self,
                src: &[$word],
                i0: usize,
                i1: usize,
                i2: usize,
                i3: usize,
            ) {
                self.0 = src[i0];
                self.1 = src[i1];
                self.2 = src[i2];
                self.3 = src[i3];
            }

            #[inline(always)]
            pub(crate) fn copy_from(&mut self, source: &Self) {
                self.0 = source.0;
                self.1 = source.1;
                self.2 = source.2;
                self.3 = source.3;
            }

            #[cfg(target_endian = "little")]
            #[inline(always)]
            #[cfg(not(feature = "protected-workspace"))]
            pub(crate) fn to_le(self) -> Self {
                self
            }

            #[cfg(not(target_endian = "little"))]
            #[inline(always)]
            #[cfg(not(feature = "protected-workspace"))]
            pub(crate) fn to_le(self) -> Self {
                $vec::new(
                    self.0.to_le(),
                    self.1.to_le(),
                    self.2.to_le(),
                    self.3.to_le(),
                )
            }

            #[inline(always)]
            pub(crate) fn add_assign(&mut self, rhs: &Self) {
                self.0 = self.0.wrapping_add(rhs.0);
                self.1 = self.1.wrapping_add(rhs.1);
                self.2 = self.2.wrapping_add(rhs.2);
                self.3 = self.3.wrapping_add(rhs.3);
            }

            #[inline(always)]
            pub(crate) fn add_le_assign(&mut self, rhs: &Self) {
                self.0 = self.0.wrapping_add($word::from_le(rhs.0));
                self.1 = self.1.wrapping_add($word::from_le(rhs.1));
                self.2 = self.2.wrapping_add($word::from_le(rhs.2));
                self.3 = self.3.wrapping_add($word::from_le(rhs.3));
            }

            #[inline(always)]
            pub(crate) fn xor_assign(&mut self, rhs: &Self) {
                self.0 ^= rhs.0;
                self.1 ^= rhs.1;
                self.2 ^= rhs.2;
                self.3 ^= rhs.3;
            }

            #[inline(always)]
            pub(crate) fn xor_pair_assign(&mut self, a: &Self, b: &Self) {
                self.0 ^= a.0 ^ b.0;
                self.1 ^= a.1 ^ b.1;
                self.2 ^= a.2 ^ b.2;
                self.3 ^= a.3 ^ b.3;
            }

            #[inline(always)]
            pub(crate) fn xor_words(&mut self, a: $word, b: $word, c: $word, d: $word) {
                self.0 ^= a;
                self.1 ^= b;
                self.2 ^= c;
                self.3 ^= d;
            }

            #[inline(always)]
            pub(crate) fn rotate_right_assign(&mut self, n: u32) {
                self.0 = self.0.rotate_right(n);
                self.1 = self.1.rotate_right(n);
                self.2 = self.2.rotate_right(n);
                self.3 = self.3.rotate_right(n);
            }

            #[inline(always)]
            pub(crate) fn rotate_lanes_left(&mut self, distance: u8) {
                match distance {
                    1 => {
                        let first = self.0;
                        self.0 = self.1;
                        self.1 = self.2;
                        self.2 = self.3;
                        self.3 = first;
                    }
                    2 => {
                        core::mem::swap(&mut self.0, &mut self.2);
                        core::mem::swap(&mut self.1, &mut self.3);
                    }
                    _ => {
                        let last = self.3;
                        self.3 = self.2;
                        self.2 = self.1;
                        self.1 = self.0;
                        self.0 = last;
                    }
                }
            }

            #[inline(always)]
            #[cfg(not(feature = "protected-workspace"))]
            pub(crate) fn as_bytes(&self) -> &[u8] {
                let p = self as *const Self as *const u8;
                unsafe { core::slice::from_raw_parts(p, core::mem::size_of::<Self>()) }
            }
        }

        impl Add for $vec {
            type Output = Self;

            #[inline(always)]
            fn add(mut self, rhs: Self) -> Self::Output {
                self.add_assign(&rhs);
                self
            }
        }

        impl BitXor for $vec {
            type Output = Self;

            #[inline(always)]
            fn bitxor(mut self, rhs: Self) -> Self::Output {
                self.xor_assign(&rhs);
                self
            }
        }

        impl Shl<$vec> for $vec {
            type Output = Self;

            #[inline(always)]
            fn shl(self, rhs: Self) -> Self::Output {
                $vec::new(
                    self.0 << rhs.0,
                    self.1 << rhs.1,
                    self.2 << rhs.2,
                    self.3 << rhs.3,
                )
            }
        }

        impl Shr<$vec> for $vec {
            type Output = Self;

            #[inline(always)]
            fn shr(self, rhs: Self) -> Self::Output {
                $vec::new(
                    self.0 >> rhs.0,
                    self.1 >> rhs.1,
                    self.2 >> rhs.2,
                    self.3 >> rhs.3,
                )
            }
        }

        #[cfg(feature = "zeroize")]
        impl Zeroize for $vec {
            fn zeroize(&mut self) {
                self.0.zeroize();
                self.1.zeroize();
                self.2.zeroize();
                self.3.zeroize();
            }
        }
    };
}

impl_vector4!(u32x4, u32);
impl_vector4!(u64x4, u64);

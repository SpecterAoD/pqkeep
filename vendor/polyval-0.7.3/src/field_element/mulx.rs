//! The `mulX_POLYVAL()` function.

use super::FieldElement;

impl FieldElement {
    /// The `mulX_POLYVAL()` function as defined in [RFC 8452 Appendix A][1].
    ///
    /// Performs a doubling (a.k.a. "multiply by x") over GF(2^128).
    /// This is useful for implementing GHASH in terms of POLYVAL.
    ///
    /// [1]: https://tools.ietf.org/html/rfc8452#appendix-A
    #[must_use]
    pub fn mulx(self) -> Self {
        let mut v = u128::from(self);
        let v_hi = v >> 127;

        v <<= 1;
        v ^= v_hi ^ (v_hi << 127) ^ (v_hi << 126) ^ (v_hi << 121);
        v.to_le_bytes().into()
    }
}

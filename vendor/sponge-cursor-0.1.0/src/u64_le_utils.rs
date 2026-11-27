//! DE: Direkte Little-Endian-Bytezugriffe ohne private Konvertierungsarrays.
//! EN: Direct little-endian byte accesses without private conversion arrays.

#[inline(always)]
pub(crate) fn absorb_full<const N: usize, const RATE: usize>(
    state: &mut [u64; N],
    block: &[u8; RATE],
) {
    absorb_partial::<N, RATE>(state, 0, block);
}

#[inline(always)]
pub(crate) fn absorb_partial<const N: usize, const RATE: usize>(
    state: &mut [u64; N],
    offset: usize,
    data: &[u8],
) {
    const {
        assert!(size_of::<[u8; RATE]>() <= size_of::<[u64; N]>());
        assert!(RATE % size_of::<u64>() == 0);
    };
    assert!(offset <= RATE && data.len() <= RATE - offset);
    // DE: Direkt in Lanes schreiben, ohne Bytearray oder Pointer-Cast.
    // EN: Write directly into lanes, without a byte array or pointer cast.
    for (i, byte) in data.iter().enumerate() {
        let pos = offset + i;
        state[pos / 8] ^= u64::from(*byte) << (8 * (pos % 8));
    }
}

#[inline(always)]
pub(crate) fn squeeze_read_full<const N: usize, const RATE: usize>(
    state: &[u64; N],
    dst: &mut [u8; RATE],
) {
    squeeze_read_partial::<N, RATE>(state, 0, dst);
}

#[inline(always)]
pub(crate) fn squeeze_read_partial<const N: usize, const RATE: usize>(
    state: &[u64; N],
    offset: usize,
    dst: &mut [u8],
) {
    const {
        assert!(size_of::<[u8; RATE]>() <= size_of::<[u64; N]>());
        assert!(RATE % size_of::<u64>() == 0);
    };
    assert!(offset <= RATE && dst.len() <= RATE - offset);
    for (i, byte) in dst.iter_mut().enumerate() {
        *byte = lane_byte(state, offset + i);
    }
}

#[inline(always)]
pub(crate) fn squeeze_xor_full<const N: usize, const RATE: usize>(
    state: &[u64; N],
    dst: &mut [u8; RATE],
) {
    squeeze_xor_partial::<N, RATE>(state, 0, dst);
}

#[inline(always)]
pub(crate) fn squeeze_xor_partial<const N: usize, const RATE: usize>(
    state: &[u64; N],
    offset: usize,
    dst: &mut [u8],
) {
    const {
        assert!(size_of::<[u8; RATE]>() <= size_of::<[u64; N]>());
        assert!(RATE % size_of::<u64>() == 0);
    };
    assert!(offset <= RATE && dst.len() <= RATE - offset);
    for (i, byte) in dst.iter_mut().enumerate() {
        *byte ^= lane_byte(state, offset + i);
    }
}

// DE: Die Maske beweist, dass bei der Bytekonvertierung keine Bits verloren gehen.
// EN: The mask proves that byte conversion cannot lose significant bits.
#[allow(clippy::cast_possible_truncation, reason = "masked to one byte")]
#[inline(always)]
fn lane_byte<const N: usize>(state: &[u64; N], pos: usize) -> u8 {
    ((state[pos / 8] >> (8 * (pos % 8))) & 0xff) as u8
}

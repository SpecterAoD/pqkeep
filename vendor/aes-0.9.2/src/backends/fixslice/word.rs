use crate::Block;
use cipher::{
    Array,
    array::ArraySize,
    consts::{U2, U4},
};
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Shl, Shr};

/// Width-abstracted machine word holding one row of a bitsliced AES state.
pub(crate) trait Word:
    Sized
    + Copy
    + Default
    + 'static
    + BitAnd<Output = Self>
    + BitAndAssign
    + BitOr<Output = Self>
    + BitOrAssign
    + BitXor<Output = Self>
    + BitXorAssign
    + Not<Output = Self>
    + Shl<u32, Output = Self>
    + Shr<u32, Output = Self>
{
    /// Number of 128-bit blocks bitsliced together in one state.
    type Blocks: ArraySize;

    /// Width in bits of one row of the bitsliced state (8 for `u32`, 16 for `u64`).
    const ROW_BITS: u32 = (size_of::<Self>() * 2) as u32;

    /// Half of `ROW_BITS`.
    const HALF_ROW: u32 = Self::ROW_BITS / 2;
    /// Quarter of `ROW_BITS`.
    const QUARTER_ROW: u32 = Self::ROW_BITS / 4;

    /// Distance in bits to rotate a state row by `(rows, cols)` positions.
    #[inline(always)]
    fn ror_distance(rows: u32, cols: u32) -> u32 {
        rows * Self::ROW_BITS + cols * Self::QUARTER_ROW
    }

    /// Rotate right by `n` bits.
    fn ror(self, n: u32) -> Self;

    /// Pack the same byte across all 4 rows of the word.
    fn uniform_row(b: u8) -> Self;

    /// Place one byte at each of the 4 row positions of the word (row 0 = LSB).
    fn pack_rows(r0: u8, r1: u8, r2: u8, r3: u8) -> Self;

    /// Replicate byte `b` across every byte of the word.
    fn byte_repeat(b: u8) -> Self;

    /// Pack `Self::Blocks` input blocks into a bitsliced 8-row state slice.
    #[inline(always)]
    fn bitslice(output: &mut [Self], input: &Array<Block, Self::Blocks>) {
        Self::bitslice_with_scratch(output, input, &mut [Self::default(); 8]);
    }
    // DE/EN: Gesamten Scratch vor privater Befüllung sperren / prelock all scratch.
    fn bitslice_with_scratch(
        output: &mut [Self],
        input: &Array<Block, Self::Blocks>,
        scratch: &mut [Self; 8],
    );

    /// Unpack a bitsliced 8-row state slice into `Self::Blocks` output blocks.
    #[inline(always)]
    fn inv_bitslice(input: &[Self]) -> Array<Block, Self::Blocks> {
        let mut output = Array::default();
        Self::inv_bitslice_into(input, &mut output, &mut [Self::default(); 8]);
        output
    }
    // DE/EN: Ausgabe und Scratch vorab sperren / prelock output and scratch.
    fn inv_bitslice_into(
        input: &[Self],
        output: &mut Array<Block, Self::Blocks>,
        scratch: &mut [Self; 8],
    );
}

impl Word for u32 {
    type Blocks = U2;

    #[inline(always)]
    fn ror(self, n: u32) -> u32 {
        self.rotate_right(n)
    }

    #[inline(always)]
    fn uniform_row(b: u8) -> u32 {
        (b as u32) * 0x01010101
    }

    #[inline(always)]
    fn pack_rows(r0: u8, r1: u8, r2: u8, r3: u8) -> u32 {
        (r0 as u32) | ((r1 as u32) << 8) | ((r2 as u32) << 16) | ((r3 as u32) << 24)
    }

    #[inline(always)]
    fn byte_repeat(b: u8) -> u32 {
        (b as u32) * 0x01010101
    }

    /// Bitslice two 128-bit input blocks into a 256-bit internal state.
    fn bitslice_with_scratch(output: &mut [u32], input: &Array<Block, U2>, t: &mut [u32; 8]) {
        debug_assert_eq!(output.len(), 8);
        let input0 = input[0].as_slice();
        let input1 = input[1].as_slice();

        // Bitslicing is a bit index manipulation. 256 bits of data means each bit is positioned at
        // an 8-bit index. AES data is 2 blocks, each one a 4x4 column-major matrix of bytes, so the
        // index is initially ([b]lock, [c]olumn, [r]ow, [p]osition):
        //     b0 c1 c0 r1 r0 p2 p1 p0
        //
        // The desired bitsliced data groups first by bit position, then row, column, block:
        //     p2 p1 p0 r1 r0 c1 c0 b0

        // Interleave the columns on input (note the order of input)
        //     b0 c1 c0 __ __ __ __ __ => c1 c0 b0 __ __ __ __ __
        t[0] = read_word(&input0[0x00..0x04]);
        t[1] = read_word(&input1[0x00..0x04]);
        t[2] = read_word(&input0[0x04..0x08]);
        t[3] = read_word(&input1[0x04..0x08]);
        t[4] = read_word(&input0[0x08..0x0c]);
        t[5] = read_word(&input1[0x08..0x0c]);
        t[6] = read_word(&input0[0x0c..0x10]);
        t[7] = read_word(&input1[0x0c..0x10]);

        bitslice_swaps(t);

        // Final bitsliced bit index, as desired:
        //     p2 p1 p0 r1 r0 c1 c0 b0
        output[..8].copy_from_slice(t);
    }

    /// Un-bitslice a 256-bit internal state into two 128-bit blocks.
    fn inv_bitslice_into(input: &[u32], output: &mut Array<Block, U2>, t: &mut [u32; 8]) {
        debug_assert_eq!(input.len(), 8);

        // Unbitslicing is a bit index manipulation. 256 bits of data means each bit is positioned
        // at an 8-bit index. AES data is 2 blocks, each one a 4x4 column-major matrix of bytes, so
        // the desired index for the output is ([b]lock, [c]olumn, [r]ow, [p]osition):
        //     b0 c1 c0 r1 r0 p2 p1 p0
        //
        // The initially bitsliced data groups first by bit position, then row, column, block:
        //     p2 p1 p0 r1 r0 c1 c0 b0

        t.copy_from_slice(&input[..8]);

        bitslice_swaps(t);

        // De-interleave the columns on output (note the order of output)
        //     c1 c0 b0 __ __ __ __ __ => b0 c1 c0 __ __ __ __ __
        write_word(t[0], &mut output[0][0x00..0x04]);
        write_word(t[2], &mut output[0][0x04..0x08]);
        write_word(t[4], &mut output[0][0x08..0x0c]);
        write_word(t[6], &mut output[0][0x0c..0x10]);
        write_word(t[1], &mut output[1][0x00..0x04]);
        write_word(t[3], &mut output[1][0x04..0x08]);
        write_word(t[5], &mut output[1][0x08..0x0c]);
        write_word(t[7], &mut output[1][0x0c..0x10]);

        // Final AES bit index, as desired:
        //     b0 c1 c0 r1 r0 p2 p1 p0
    }
}

/// Expand an 8-bit row pattern to a 16-bit row pattern by doubling each bit:
/// input bit `i` becomes output bits `2i` and `2i+1`. Branchless SWAR so LLVM
/// folds it to a single 16-bit immediate when `b` is a constant.
#[inline(always)]
const fn double_bits(b: u8) -> u16 {
    let x = b as u16;
    // Spread the 8 bits of x to even positions 0,2,4,6,8,10,12,14.
    let x = (x | (x << 4)) & 0x0f0f;
    let x = (x | (x << 2)) & 0x3333;
    let x = (x | (x << 1)) & 0x5555;
    // Duplicate each spread bit to its adjacent odd position.
    x | (x << 1)
}

impl Word for u64 {
    type Blocks = U4;

    #[inline(always)]
    fn ror(self, n: u32) -> u64 {
        self.rotate_right(n)
    }

    #[inline(always)]
    fn uniform_row(b: u8) -> u64 {
        (double_bits(b) as u64) * 0x0001_0001_0001_0001
    }

    #[inline(always)]
    fn pack_rows(r0: u8, r1: u8, r2: u8, r3: u8) -> u64 {
        (double_bits(r0) as u64)
            | ((double_bits(r1) as u64) << 16)
            | ((double_bits(r2) as u64) << 32)
            | ((double_bits(r3) as u64) << 48)
    }

    #[inline(always)]
    fn byte_repeat(b: u8) -> u64 {
        (b as u64) * 0x0101010101010101
    }

    /// Bitslice four 128-bit input blocks into a 512-bit internal state.
    fn bitslice_with_scratch(output: &mut [u64], input: &Array<Block, U4>, t: &mut [u64; 8]) {
        debug_assert_eq!(output.len(), 8);

        // Bitslicing is a bit index manipulation. 512 bits of data means each bit is positioned at
        // a 9-bit index. AES data is 4 blocks, each one a 4x4 column-major matrix of bytes, so the
        // index is initially ([b]lock, [c]olumn, [r]ow, [p]osition):
        //     b1 b0 c1 c0 r1 r0 p2 p1 p0
        //
        // The desired bitsliced data groups first by bit position, then row, column, block:
        //     p2 p1 p0 r1 r0 c1 c0 b1 b0

        #[rustfmt::skip]
        fn read_reordered(input: &[u8]) -> u64 {
            (u64::from(input[0x0])        ) |
            (u64::from(input[0x1]) << 0x10) |
            (u64::from(input[0x2]) << 0x20) |
            (u64::from(input[0x3]) << 0x30) |
            (u64::from(input[0x8]) << 0x08) |
            (u64::from(input[0x9]) << 0x18) |
            (u64::from(input[0xa]) << 0x28) |
            (u64::from(input[0xb]) << 0x38)
        }

        // Reorder each block's bytes on input
        //     __ __ c1 c0 r1 r0 __ __ __ => __ __ c0 r1 r0 c1 __ __ __
        // Reorder by relabeling (note the order of input)
        //     b1 b0 c0 __ __ __ __ __ __ => c0 b1 b0 __ __ __ __ __ __
        t[0] = read_reordered(&input[0][0x00..0x0c]);
        t[1] = read_reordered(&input[1][0x00..0x0c]);
        t[2] = read_reordered(&input[2][0x00..0x0c]);
        t[3] = read_reordered(&input[3][0x00..0x0c]);
        t[4] = read_reordered(&input[0][0x04..0x10]);
        t[5] = read_reordered(&input[1][0x04..0x10]);
        t[6] = read_reordered(&input[2][0x04..0x10]);
        t[7] = read_reordered(&input[3][0x04..0x10]);

        bitslice_swaps(t);

        // Final bitsliced bit index, as desired:
        //     p2 p1 p0 r1 r0 c1 c0 b1 b0
        output[..8].copy_from_slice(t);
    }

    /// Un-bitslice a 512-bit internal state into four 128-bit blocks.
    fn inv_bitslice_into(input: &[u64], output: &mut Array<Block, U4>, t: &mut [u64; 8]) {
        debug_assert_eq!(input.len(), 8);

        // Unbitslicing is a bit index manipulation. 512 bits of data means each bit is positioned
        // at a 9-bit index. AES data is 4 blocks, each one a 4x4 column-major matrix of bytes, so
        // the desired index for the output is ([b]lock, [c]olumn, [r]ow, [p]osition):
        //     b1 b0 c1 c0 r1 r0 p2 p1 p0
        //
        // The initially bitsliced data groups first by bit position, then row, column, block:
        //     p2 p1 p0 r1 r0 c1 c0 b1 b0

        t.copy_from_slice(&input[..8]);

        bitslice_swaps(t);

        #[rustfmt::skip]
        fn write_reordered(columns: u64, output: &mut [u8]) {
            output[0x0] = (columns        ) as u8;
            output[0x1] = (columns >> 0x10) as u8;
            output[0x2] = (columns >> 0x20) as u8;
            output[0x3] = (columns >> 0x30) as u8;
            output[0x8] = (columns >> 0x08) as u8;
            output[0x9] = (columns >> 0x18) as u8;
            output[0xa] = (columns >> 0x28) as u8;
            output[0xb] = (columns >> 0x38) as u8;
        }

        // Reorder by relabeling (note the order of output)
        //     c0 b1 b0 __ __ __ __ __ __ => b1 b0 c0 __ __ __ __ __ __
        // Reorder each block's bytes on output
        //     __ __ c0 r1 r0 c1 __ __ __ => __ __ c1 c0 r1 r0 __ __ __
        write_reordered(t[0], &mut output[0][0x00..0x0c]);
        write_reordered(t[4], &mut output[0][0x04..0x10]);
        write_reordered(t[1], &mut output[1][0x00..0x0c]);
        write_reordered(t[5], &mut output[1][0x04..0x10]);
        write_reordered(t[2], &mut output[2][0x00..0x0c]);
        write_reordered(t[6], &mut output[2][0x04..0x10]);
        write_reordered(t[3], &mut output[3][0x00..0x0c]);
        write_reordered(t[7], &mut output[3][0x04..0x10]);

        // Final AES bit index, as desired:
        //     b1 b0 c1 c0 r1 r0 p2 p1 p0
    }
}

/// Width-generic delta-swap pipeline shared by `bitslice` and `inv_bitslice`
/// across every `Word` impl. The same three-pass sequence inverts itself, so
/// `bitslice` and `inv_bitslice` invoke it identically.
///
/// The diagrams below describe the `u32` case (8-bit rows); for `u64` each
/// bit position widens by one, but the swap structure is unchanged.
#[inline(always)]
fn bitslice_swaps<W: Word>(t: &mut [W; 8]) {
    use super::utils::delta_swap_2;
    let [t0, t1, t2, t3, t4, t5, t6, t7] = t;

    // Bit Index Swap 5 <-> 0:
    //     __ __ b0 __ __ __ __ p0 => __ __ p0 __ __ __ __ b0
    let m0 = W::byte_repeat(0x55);
    delta_swap_2(t1, t0, 1, m0);
    delta_swap_2(t3, t2, 1, m0);
    delta_swap_2(t5, t4, 1, m0);
    delta_swap_2(t7, t6, 1, m0);

    // Bit Index Swap 6 <-> 1:
    //     __ c0 __ __ __ __ p1 __ => __ p1 __ __ __ __ c0 __
    let m1 = W::byte_repeat(0x33);
    delta_swap_2(t2, t0, 2, m1);
    delta_swap_2(t3, t1, 2, m1);
    delta_swap_2(t6, t4, 2, m1);
    delta_swap_2(t7, t5, 2, m1);

    // Bit Index Swap 7 <-> 2:
    //     c1 __ __ __ __ p2 __ __ => p2 __ __ __ __ c1 __ __
    let m2 = W::byte_repeat(0x0f);
    delta_swap_2(t4, t0, 4, m2);
    delta_swap_2(t5, t1, 4, m2);
    delta_swap_2(t6, t2, 4, m2);
    delta_swap_2(t7, t3, 4, m2);
}

// DE: Skalarzugriff statt privater Konvertierungsarrays. EN: Scalar access avoids conversion arrays.
#[inline(always)]
fn read_word(input: &[u8]) -> u32 {
    u32::from(input[0])
        | (u32::from(input[1]) << 8)
        | (u32::from(input[2]) << 16)
        | (u32::from(input[3]) << 24)
}
#[inline(always)]
fn write_word(value: u32, output: &mut [u8]) {
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (value >> (index * 8)) as u8;
    }
}

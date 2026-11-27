use super::{BatchBlocks, State, Word, mix_columns::*, sbox::*, utils::*};

/// AES-256 round keys
pub(crate) type RoundKeys<W> = [W; 120];

/// Fully bitsliced AES-256 key schedule to match the fully-fixsliced representation.
pub(crate) fn key_schedule<W: Word>(key: &[u8; 32]) -> RoundKeys<W> {
    let mut rkeys = [W::default(); 120];
    key_schedule_into(
        key,
        &mut rkeys,
        &mut BatchBlocks::<W>::default(),
        &mut [W::default(); 8],
    );
    rkeys
}

// DE: Gesamte Schlüssel-/Scratchflächen vorab sperren. EN: Prelock keys and scratch.
pub(crate) fn key_schedule_into<W: Word>(
    key: &[u8; 32],
    rkeys: &mut RoundKeys<W>,
    batch: &mut BatchBlocks<W>,
    scratch: &mut State<W>,
) {
    for slot in batch.iter_mut() {
        slot.copy_from_slice(&key[..16]);
    }
    W::bitslice_with_scratch(&mut rkeys[..8], batch, scratch);
    for slot in batch.iter_mut() {
        slot.copy_from_slice(&key[16..]);
    }
    W::bitslice_with_scratch(&mut rkeys[8..16], batch, scratch);

    let mut rk_off = 8;

    let mut rcon = 0;
    loop {
        memshift32(rkeys, rk_off);
        rk_off += 8;

        sub_bytes(&mut rkeys[rk_off..(rk_off + 8)]);
        sub_bytes_nots(&mut rkeys[rk_off..(rk_off + 8)]);

        add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon);
        xor_columns(rkeys, rk_off, 16, W::ror_distance(1, 3));
        rcon += 1;

        if rcon == 7 {
            break;
        }

        memshift32(rkeys, rk_off);
        rk_off += 8;

        sub_bytes(&mut rkeys[rk_off..(rk_off + 8)]);
        sub_bytes_nots(&mut rkeys[rk_off..(rk_off + 8)]);

        xor_columns(rkeys, rk_off, 16, W::ror_distance(0, 3));
    }

    // Adjust to match fixslicing format
    #[cfg(aes_backend_soft = "compact")]
    {
        for i in (8..120).step_by(16) {
            inv_shift_rows_1(&mut rkeys[i..(i + 8)]);
        }
    }
    #[cfg(not(aes_backend_soft = "compact"))]
    {
        for i in (8..104).step_by(32) {
            inv_shift_rows_1(&mut rkeys[i..(i + 8)]);
            inv_shift_rows_2(&mut rkeys[(i + 8)..(i + 16)]);
            inv_shift_rows_3(&mut rkeys[(i + 16)..(i + 24)]);
        }
        inv_shift_rows_1(&mut rkeys[104..112]);
    }

    // Account for NOTs removed from sub_bytes
    for i in 1..15 {
        sub_bytes_nots(&mut rkeys[(i * 8)..(i * 8 + 8)]);
    }
}

/// Fully-fixsliced AES-256 encryption (the ShiftRows is completely omitted).
///
/// Encrypts four blocks in-place and in parallel.
pub(crate) fn encrypt<W: Word>(rkeys: &RoundKeys<W>, blocks: &BatchBlocks<W>) -> BatchBlocks<W> {
    let mut state = State::<W>::default();
    let mut output = BatchBlocks::<W>::default();
    encrypt_into(
        rkeys,
        blocks,
        &mut state,
        &mut output,
        &mut State::<W>::default(),
    );
    output
}

// DE: Gleiche Runden mit geliehenen privaten Flächen. EN: Same rounds, borrowed private storage.
pub(crate) fn encrypt_into<W: Word>(
    rkeys: &RoundKeys<W>,
    blocks: &BatchBlocks<W>,
    state: &mut State<W>,
    output: &mut BatchBlocks<W>,
    scratch: &mut State<W>,
) {
    W::bitslice_with_scratch(state, blocks, scratch);

    add_round_key(state, &rkeys[..8]);

    let mut rk_off = 8;
    loop {
        sub_bytes(state);
        mix_columns_1(state);
        add_round_key(state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;

        #[cfg(aes_backend_soft = "compact")]
        {
            shift_rows_2(state);
        }

        if rk_off == 112 {
            break;
        }

        #[cfg(not(aes_backend_soft = "compact"))]
        {
            sub_bytes(state);
            mix_columns_2(state);
            add_round_key(state, &rkeys[rk_off..(rk_off + 8)]);
            rk_off += 8;

            sub_bytes(state);
            mix_columns_3(state);
            add_round_key(state, &rkeys[rk_off..(rk_off + 8)]);
            rk_off += 8;
        }

        sub_bytes(state);
        mix_columns_0(state);
        add_round_key(state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;
    }

    #[cfg(not(aes_backend_soft = "compact"))]
    {
        shift_rows_2(state);
    }

    sub_bytes(state);
    add_round_key(state, &rkeys[112..]);

    W::inv_bitslice_into(state, output, scratch);
}

/// Fully-fixsliced AES-256 decryption (the InvShiftRows is completely omitted).
///
/// Decrypts four blocks in-place and in parallel.
pub(crate) fn decrypt<W: Word>(rkeys: &RoundKeys<W>, blocks: &BatchBlocks<W>) -> BatchBlocks<W> {
    let mut state = State::<W>::default();

    W::bitslice(&mut state, blocks);

    add_round_key(&mut state, &rkeys[112..]);
    inv_sub_bytes(&mut state);

    #[cfg(not(aes_backend_soft = "compact"))]
    {
        inv_shift_rows_2(&mut state);
    }

    let mut rk_off = 104;
    loop {
        #[cfg(aes_backend_soft = "compact")]
        {
            inv_shift_rows_2(&mut state);
        }

        add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        inv_mix_columns_1(&mut state);
        inv_sub_bytes(&mut state);
        rk_off -= 8;

        if rk_off == 0 {
            break;
        }

        add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        inv_mix_columns_0(&mut state);
        inv_sub_bytes(&mut state);
        rk_off -= 8;

        #[cfg(not(aes_backend_soft = "compact"))]
        {
            add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
            inv_mix_columns_3(&mut state);
            inv_sub_bytes(&mut state);
            rk_off -= 8;

            add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
            inv_mix_columns_2(&mut state);
            inv_sub_bytes(&mut state);
            rk_off -= 8;
        }
    }

    add_round_key(&mut state, &rkeys[..8]);

    W::inv_bitslice(&state)
}

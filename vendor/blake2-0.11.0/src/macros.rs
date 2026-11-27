macro_rules! blake2_impl {
    (
        $name:ident, $alg_name:expr, $word:ident, $vec:ident, $bytes:ident,
        $block_size:ident, $R1:expr, $R2:expr, $R3:expr, $R4:expr, $IV:expr,
        $vardoc:expr, $doc:expr,
    ) => {
        #[derive(Clone)]
        #[doc=$vardoc]
        pub struct $name {
            h: [$vec; 2],
            t: u64,
            #[cfg(feature = "protected-workspace")]
            scratch_m: [$word; 16],
            #[cfg(feature = "protected-workspace")]
            scratch_v: [$vec; 4],
            #[cfg(feature = "protected-workspace")]
            scratch_message: $vec,
            #[cfg(feature = "reset")]
            h0: [$vec; 2],
        }

        impl $name {
            #[inline(always)]
            fn iv0() -> $vec {
                $vec::new($IV[0], $IV[1], $IV[2], $IV[3])
            }
            #[inline(always)]
            fn iv1() -> $vec {
                $vec::new($IV[4], $IV[5], $IV[6], $IV[7])
            }

            /// Creates a new context with the full set of sequential-mode parameters.
            pub fn new_with_params(
                salt: &[u8],
                persona: &[u8],
                key_size: usize,
                output_size: usize,
            ) -> Self {
                assert!(key_size <= $bytes::to_usize());
                assert!(output_size <= $bytes::to_usize());

                // The number of bytes needed to express two words.
                let length = $bytes::to_usize() / 4;
                assert!(salt.len() <= length);
                assert!(persona.len() <= length);

                // Build a parameter block
                let mut p = [0 as $word; 8];
                p[0] = 0x0101_0000 ^ ((key_size as $word) << 8) ^ (output_size as $word);

                // salt is two words long
                if salt.len() < length {
                    let mut padded_salt = Array::<u8, <$bytes as Div<U4>>::Output>::default();
                    for i in 0..salt.len() {
                        padded_salt[i] = salt[i];
                    }
                    p[4] = $word::from_le_bytes(padded_salt[0..length / 2].try_into().unwrap());
                    p[5] = $word::from_le_bytes(
                        padded_salt[length / 2..padded_salt.len()]
                            .try_into()
                            .unwrap(),
                    );
                } else {
                    p[4] = $word::from_le_bytes(salt[0..salt.len() / 2].try_into().unwrap());
                    p[5] =
                        $word::from_le_bytes(salt[salt.len() / 2..salt.len()].try_into().unwrap());
                }

                // persona is also two words long
                if persona.len() < length {
                    let mut padded_persona = Array::<u8, <$bytes as Div<U4>>::Output>::default();
                    for i in 0..persona.len() {
                        padded_persona[i] = persona[i];
                    }
                    p[6] = $word::from_le_bytes(padded_persona[0..length / 2].try_into().unwrap());
                    p[7] = $word::from_le_bytes(
                        padded_persona[length / 2..padded_persona.len()]
                            .try_into()
                            .unwrap(),
                    );
                } else {
                    p[6] = $word::from_le_bytes(persona[0..length / 2].try_into().unwrap());
                    p[7] = $word::from_le_bytes(
                        persona[length / 2..persona.len()].try_into().unwrap(),
                    );
                }

                let h = [
                    Self::iv0() ^ $vec::new(p[0], p[1], p[2], p[3]),
                    Self::iv1() ^ $vec::new(p[4], p[5], p[6], p[7]),
                ];
                $name {
                    #[cfg(feature = "reset")]
                    h0: h.clone(),
                    h,
                    t: 0,
                    #[cfg(feature = "protected-workspace")]
                    scratch_m: [0; 16],
                    #[cfg(feature = "protected-workspace")]
                    scratch_v: [$vec::new(0, 0, 0, 0); 4],
                    #[cfg(feature = "protected-workspace")]
                    scratch_message: $vec::new(0, 0, 0, 0),
                }
            }

            fn finalize_with_flag(
                &mut self,
                final_block: &Array<u8, $block_size>,
                flag: $word,
                out: &mut Output<Self>,
            ) {
                self.compress(final_block, !0, flag);
                let n = size_of::<$vec>();
                #[cfg(feature = "protected-workspace")]
                {
                    self.h[0].write_le_into(&mut out[..n]);
                    self.h[1].write_le_into(&mut out[n..]);
                }
                #[cfg(not(feature = "protected-workspace"))]
                {
                    out[..n].copy_from_slice(self.h[0].to_le().as_bytes());
                    out[n..].copy_from_slice(self.h[1].to_le().as_bytes());
                }
            }

            fn compress(&mut self, block: &Block<Self>, f0: $word, f1: $word) {
                use $crate::consts::SIGMA;

                #[cfg_attr(not(feature = "size_opt"), inline(always))]
                fn quarter_round(v: &mut [$vec; 4], rd: u32, rb: u32, m: &$vec) {
                    let [v0, v1, v2, v3] = v;
                    v0.add_assign(v1);
                    v0.add_le_assign(m);
                    v3.xor_assign(v0);
                    v3.rotate_right_assign(rd);
                    v2.add_assign(v3);
                    v1.xor_assign(v2);
                    v1.rotate_right_assign(rb);
                }

                #[cfg_attr(not(feature = "size_opt"), inline(always))]
                fn shuffle(v: &mut [$vec; 4]) {
                    v[1].rotate_lanes_left(1);
                    v[2].rotate_lanes_left(2);
                    v[3].rotate_lanes_left(3);
                }

                #[cfg_attr(not(feature = "size_opt"), inline(always))]
                fn unshuffle(v: &mut [$vec; 4]) {
                    v[1].rotate_lanes_left(3);
                    v[2].rotate_lanes_left(2);
                    v[3].rotate_lanes_left(1);
                }

                #[cfg_attr(not(feature = "size_opt"), inline(always))]
                fn round(v: &mut [$vec; 4], m: &[$word; 16], s: &[usize; 16], scratch: &mut $vec) {
                    scratch.gather_into(m, s[0], s[2], s[4], s[6]);
                    quarter_round(v, $R1, $R2, scratch);
                    scratch.gather_into(m, s[1], s[3], s[5], s[7]);
                    quarter_round(v, $R3, $R4, scratch);
                    shuffle(v);
                    scratch.gather_into(m, s[8], s[10], s[12], s[14]);
                    quarter_round(v, $R1, $R2, scratch);
                    scratch.gather_into(m, s[9], s[11], s[13], s[15]);
                    quarter_round(v, $R3, $R4, scratch);
                    unshuffle(v);
                }

                #[cfg(not(feature = "protected-workspace"))]
                let mut m_storage: [$word; 16] = Default::default();
                #[cfg(not(feature = "protected-workspace"))]
                let m = &mut m_storage;
                #[cfg(feature = "protected-workspace")]
                let m = &mut self.scratch_m;
                let n = core::mem::size_of::<$word>();
                for (v, chunk) in m.iter_mut().zip(block.chunks_exact(n)) {
                    *v = 0;
                    for (index, byte) in chunk.iter().enumerate() {
                        let shift = if cfg!(target_endian = "little") {
                            index * 8
                        } else {
                            (n - index - 1) * 8
                        };
                        *v |= $word::from(*byte) << shift;
                    }
                }
                let h = &mut self.h;

                let t0 = self.t as $word;
                let t1 = match $bytes::to_u8() {
                    64 => 0,
                    32 => (self.t >> 32) as $word,
                    _ => unreachable!(),
                };

                #[cfg(not(feature = "protected-workspace"))]
                let mut v_storage = [$vec::new(0, 0, 0, 0); 4];
                #[cfg(not(feature = "protected-workspace"))]
                let v = &mut v_storage;
                #[cfg(feature = "protected-workspace")]
                let v = &mut self.scratch_v;
                v[0].copy_from(&h[0]);
                v[1].copy_from(&h[1]);
                v[2] = Self::iv0();
                v[3] = Self::iv1();
                v[3].xor_words(t0, t1, f0, f1);
                #[cfg(not(feature = "protected-workspace"))]
                let mut message_storage = $vec::new(0, 0, 0, 0);
                #[cfg(not(feature = "protected-workspace"))]
                let message = &mut message_storage;
                #[cfg(feature = "protected-workspace")]
                let message = &mut self.scratch_message;

                round(v, m, &SIGMA[0], message);
                round(v, m, &SIGMA[1], message);
                round(v, m, &SIGMA[2], message);
                round(v, m, &SIGMA[3], message);
                round(v, m, &SIGMA[4], message);
                round(v, m, &SIGMA[5], message);
                round(v, m, &SIGMA[6], message);
                round(v, m, &SIGMA[7], message);
                round(v, m, &SIGMA[8], message);
                round(v, m, &SIGMA[9], message);
                if $bytes::to_u8() == 64 {
                    round(v, m, &SIGMA[0], message);
                    round(v, m, &SIGMA[1], message);
                }

                h[0].xor_pair_assign(&v[0], &v[2]);
                h[1].xor_pair_assign(&v[1], &v[3]);
            }
        }

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = $block_size;
        }

        impl BufferKindUser for $name {
            type BufferKind = Lazy;
        }

        impl UpdateCore for $name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    self.t += block.len() as u64;
                    self.compress(block, 0, 0);
                }
            }
        }

        impl OutputSizeUser for $name {
            type OutputSize = $bytes;
        }

        impl VariableOutputCore for $name {
            const TRUNC_SIDE: TruncSide = TruncSide::Left;

            #[inline]
            fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
                if output_size > Self::OutputSize::USIZE {
                    return Err(InvalidOutputSize);
                }
                Ok(Self::new_with_params(&[], &[], 0, output_size))
            }

            #[inline]
            fn finalize_variable_core(
                &mut self,
                buffer: &mut Buffer<Self>,
                out: &mut Output<Self>,
            ) {
                self.t += buffer.get_pos() as u64;
                let block = buffer.pad_with_zeros();
                self.finalize_with_flag(&block, 0, out);
            }
        }

        #[cfg(feature = "reset")]
        impl Reset for $name {
            fn reset(&mut self) {
                self.h = self.h0;
                self.t = 0;
            }
        }

        impl AlgorithmName for $name {
            #[inline]
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($alg_name)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        #[cfg(feature = "zeroize")]
        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.h.zeroize();
                self.t.zeroize();
                #[cfg(feature = "reset")]
                self.h0.zeroize();
                #[cfg(feature = "protected-workspace")]
                {
                    self.scratch_m.zeroize();
                    self.scratch_v.zeroize();
                    self.scratch_message.zeroize();
                }
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                self.zeroize();
            }
        }

        impl VariableOutputCoreCustomized for $name {
            #[inline]
            fn new_customized(customization: &[u8], output_size: usize) -> Self {
                Self::new_with_params(&[], customization, 0, output_size)
            }
        }

        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $name {}
    };
}

macro_rules! blake2_mac_impl {
    (
        $name:ident, $hash:ty, $max_size:ty, $doc:expr
    ) => {
        #[derive(Clone)]
        #[doc=$doc]
        pub struct $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            core: $hash,
            buffer: LazyBuffer<<$hash as BlockSizeUser>::BlockSize>,
            #[cfg(feature = "reset")]
            key_block: Option<Key<Self>>,
            _out: PhantomData<OutSize>,
        }

        impl<OutSize> $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            /// Create new instance using provided key, salt, and persona.
            ///
            /// Setting key to `None` indicates unkeyed usage.
            ///
            /// # Errors
            ///
            /// If key is `Some`, then its length should not be zero or bigger
            /// than the block size. The salt and persona length should not be
            /// bigger than quarter of block size. If any of those conditions is
            /// false the method will return an error.
            #[inline]
            pub fn new_with_salt_and_personal(
                key: Option<&[u8]>,
                salt: &[u8],
                persona: &[u8],
            ) -> Result<Self, InvalidLength> {
                let kl = key.map_or(0, |k| k.len());
                let bs = <$hash as BlockSizeUser>::BlockSize::USIZE;
                let qbs = bs / 4;
                if key.is_some() && kl == 0 || kl > bs || salt.len() > qbs || persona.len() > qbs {
                    return Err(InvalidLength);
                }
                let buffer = if let Some(k) = key {
                    let mut padded_key = Block::<$hash>::default();
                    padded_key[..kl].copy_from_slice(k);
                    LazyBuffer::new(&padded_key)
                } else {
                    LazyBuffer::default()
                };
                Ok(Self {
                    core: <$hash>::new_with_params(salt, persona, kl, OutSize::USIZE),
                    buffer,
                    #[cfg(feature = "reset")]
                    key_block: key.map(|k| {
                        let mut t = Key::<Self>::default();
                        t[..kl].copy_from_slice(k);
                        t
                    }),
                    _out: PhantomData,
                })
            }
        }

        impl<OutSize> KeySizeUser for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            type KeySize = $max_size;
        }

        impl<OutSize> KeyInit for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            #[inline]
            fn new(key: &Key<Self>) -> Self {
                Self::new_from_slice(key).expect("Key has correct length")
            }

            #[inline]
            fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
                let kl = key.len();
                if kl > <Self as KeySizeUser>::KeySize::USIZE {
                    return Err(InvalidLength);
                }
                let mut padded_key = Block::<$hash>::default();
                padded_key[..kl].copy_from_slice(key);
                Ok(Self {
                    core: <$hash>::new_with_params(&[], &[], key.len(), OutSize::USIZE),
                    buffer: LazyBuffer::new(&padded_key),
                    #[cfg(feature = "reset")]
                    key_block: {
                        let mut t = Key::<Self>::default();
                        t[..kl].copy_from_slice(key);
                        Some(t)
                    },
                    _out: PhantomData,
                })
            }
        }

        impl<OutSize> Update for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            #[inline]
            fn update(&mut self, input: &[u8]) {
                let Self { core, buffer, .. } = self;
                buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
            }
        }

        impl<OutSize> OutputSizeUser for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            type OutputSize = OutSize;
        }

        impl<OutSize> FixedOutput for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            #[inline]
            fn finalize_into(mut self, out: &mut Output<Self>) {
                let Self { core, buffer, .. } = &mut self;
                let mut full_res = Default::default();
                core.finalize_variable_core(buffer, &mut full_res);
                out.copy_from_slice(&full_res[..OutSize::USIZE]);
            }
        }

        #[cfg(feature = "reset")]
        impl<OutSize> Reset for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            fn reset(&mut self) {
                self.core.reset();
                self.buffer = if let Some(k) = self.key_block {
                    let kl = k.len();
                    let mut padded_key = Block::<$hash>::default();
                    padded_key[..kl].copy_from_slice(&k);
                    LazyBuffer::new(&padded_key)
                } else {
                    LazyBuffer::default()
                }
            }
        }

        #[cfg(feature = "reset")]
        impl<OutSize> FixedOutputReset for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                let Self { core, buffer, .. } = self;
                let mut full_res = Default::default();
                core.finalize_variable_core(buffer, &mut full_res);
                out.copy_from_slice(&full_res[..OutSize::USIZE]);
                self.reset();
            }
        }

        impl<OutSize> MacMarker for $name<OutSize> where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>
        {
        }

        impl<OutSize> fmt::Debug for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{} {{ ... }}", stringify!($name), OutSize::USIZE)
            }
        }

        impl<OutSize> Drop for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                {
                    // `self.core` zeroized by its `Drop` impl
                    self.buffer.zeroize();
                    #[cfg(feature = "reset")]
                    if let Some(mut key_block) = self.key_block {
                        key_block.zeroize();
                    }
                }
            }
        }
        #[cfg(feature = "zeroize")]
        impl<OutSize> ZeroizeOnDrop for $name<OutSize> where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>
        {
        }
    };
}

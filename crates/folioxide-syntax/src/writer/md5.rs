//! MD5 (RFC 1321), for the file identifiers the writers generate (ISO 32000-2 §14.4).
//!
//! §14.4 suggests computing `/ID` with MD5 over information about the file. The core has no clock
//! and no RNG, so the writers digest the content they write. This is not a security use (the
//! identifiers are not secret and need no collision resistance), and a few dozen lines here keep
//! the syntax layer free of a hashing dependency; the security handler (M5) uses the `md-5`
//! crate for key derivation.

/// The per-round shift amounts (RFC 1321 §3.4).
const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// `floor(abs(sin(i + 1)) * 2^32)` (RFC 1321 §3.4).
const K: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

/// An incremental MD5 computation.
#[derive(Clone, Debug)]
pub(crate) struct Md5 {
    state: [u32; 4],
    /// The bytes digested so far.
    len: u64,
    /// The pending bytes of an incomplete block.
    pending: Vec<u8>,
}

impl Md5 {
    /// A new computation.
    pub(crate) fn new() -> Md5 {
        Md5 {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            len: 0,
            pending: Vec::with_capacity(64),
        }
    }

    /// Digests `data`.
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if !self.pending.is_empty() {
            let take = (64 - self.pending.len()).min(data.len());
            let (head, rest) = data.split_at(take);
            self.pending.extend_from_slice(head);
            data = rest;
            if self.pending.len() < 64 {
                return;
            }
            let block = std::mem::take(&mut self.pending);
            self.block(&block);
            self.pending = block;
            self.pending.clear();
        }
        let mut blocks = data.chunks_exact(64);
        for block in &mut blocks {
            self.block(block);
        }
        self.pending.extend_from_slice(blocks.remainder());
    }

    /// The digest of everything given to [`Md5::update`].
    pub(crate) fn finish(mut self) -> [u8; 16] {
        let bits = self.len.wrapping_mul(8);
        let mut tail = std::mem::take(&mut self.pending);
        tail.push(0x80);
        while tail.len() % 64 != 56 {
            tail.push(0);
        }
        tail.extend_from_slice(&bits.to_le_bytes());
        for block in tail.chunks_exact(64) {
            self.block(block);
        }
        let mut out = [0u8; 16];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Processes one 64-byte block (RFC 1321 §3.4).
    fn block(&mut self, block: &[u8]) {
        let mut m = [0u32; 16];
        for (word, bytes) in m.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes([
                bytes.first().copied().unwrap_or(0),
                bytes.get(1).copied().unwrap_or(0),
                bytes.get(2).copied().unwrap_or(0),
                bytes.get(3).copied().unwrap_or(0),
            ]);
        }
        let [mut a, mut b, mut c, mut d] = self.state;
        for (i, (&k, &s)) in K.iter().zip(S.iter()).enumerate() {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let word = m.get(g).copied().unwrap_or(0);
            let rotated = a
                .wrapping_add(f)
                .wrapping_add(k)
                .wrapping_add(word)
                .rotate_left(s);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }
        for (state, value) in self.state.iter_mut().zip([a, b, c, d]) {
            *state = state.wrapping_add(value);
        }
    }
}

/// The MD5 digest of `data`.
#[cfg(test)]
pub(crate) fn md5(data: &[u8]) -> [u8; 16] {
    let mut md5 = Md5::new();
    md5.update(data);
    md5.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(digest: [u8; 16]) -> String {
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn rfc_1321_test_suite() {
        // RFC 1321 Appendix A.5.
        let cases: [(&[u8], &str); 7] = [
            (b"", "d41d8cd98f00b204e9800998ecf8427e"),
            (b"a", "0cc175b9c0f1b6a831c399e269772661"),
            (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
            (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(hex(md5(input)), expected, "{:?}", input.escape_ascii());
        }
    }

    #[test]
    fn incremental_updates_match_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 251) as u8).collect();
        let whole = md5(&data);
        for split in [0, 1, 55, 56, 63, 64, 65, 127, 128, 999, 1000] {
            let mut md5 = Md5::new();
            let (a, b) = data.split_at(split);
            md5.update(a);
            md5.update(b);
            assert_eq!(md5.finish(), whole, "split at {split}");
        }
        let mut bytewise = Md5::new();
        for byte in &data {
            bytewise.update(std::slice::from_ref(byte));
        }
        assert_eq!(bytewise.finish(), whole);
    }
}

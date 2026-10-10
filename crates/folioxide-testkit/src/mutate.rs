//! Deterministic, seeded byte mutations for robustness tests.
//!
//! `no_panic_on_mutated_input` (ARCHITECTURE §A.9, layer 3) is a stable-toolchain stand-in for
//! fuzzing: it mutates valid fixtures and checks that the parser never panics. [`Mutator`]
//! produces those mutations from a seed, so a failure reproduces exactly: the same seed and
//! input always give the same outputs, on every platform.
//!
//! ```
//! use folioxide_testkit::mutate::{Mutator, mutations};
//!
//! let input = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n";
//! let a: Vec<Vec<u8>> = mutations(input, 42, 100).collect();
//! let b: Vec<Vec<u8>> = mutations(input, 42, 100).collect();
//! assert_eq!(a, b);
//! assert!(a.iter().any(|m| m.as_slice() != input));
//!
//! let mut m = Mutator::new(7);
//! let once = m.mutate(input);
//! assert!(once.len() <= input.len() + Mutator::MAX_GROWTH);
//! ```

/// One kind of mutation.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MutationKind {
    /// Flip one bit.
    BitFlip,
    /// Replace one byte with a random byte.
    ByteSet,
    /// Cut the input at a random position.
    Truncate,
    /// Insert 1–16 random bytes.
    Insert,
    /// Copy a chunk of up to 256 bytes to another position.
    DuplicateChunk,
    /// Remove a chunk of up to 256 bytes.
    DeleteChunk,
    /// Overwrite bytes with a PDF token that steers the parser into unusual paths (a keyword,
    /// a delimiter run or an extreme number).
    Token,
}

impl MutationKind {
    /// Every kind, in the order [`Mutator::mutate`] picks from.
    pub const ALL: [MutationKind; 7] = [
        MutationKind::BitFlip,
        MutationKind::ByteSet,
        MutationKind::Truncate,
        MutationKind::Insert,
        MutationKind::DuplicateChunk,
        MutationKind::DeleteChunk,
        MutationKind::Token,
    ];
}

/// Tokens for [`MutationKind::Token`].
const TOKENS: &[&[u8]] = &[
    b"obj",
    b"endobj",
    b"stream\n",
    b"endstream",
    b"xref\n",
    b"trailer",
    b"startxref",
    b"%%EOF",
    b"%PDF-",
    b" R ",
    b"<<",
    b">>",
    b"[[[[",
    b"((((",
    b"<</Length 9 0 R>>",
    b"/Length -1",
    b"/Prev 0",
    b"/Extends 1 0 R",
    b"/W [0 0 0]",
    b"/N 2147483647",
    b"/Filter /FlateDecode",
    b"/DecodeParms <</Predictor 15 /Columns 4000000000>>",
    b"9999999999",
    b"-2147483649",
    b"0 65535",
    b"18446744073709551616",
    b"1.0e5",
    b"#",
    b"\\",
    b"\r",
    b"\0",
];

/// A seeded generator of byte mutations (SplitMix64; no external RNG, no ambient state).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mutator {
    state: u64,
}

impl Mutator {
    /// The most bytes one call to [`Mutator::mutate`] can add (up to four operations, each
    /// adding at most 256 bytes).
    pub const MAX_GROWTH: usize = 4 * 256;

    /// A mutator whose output is fully determined by `seed`.
    pub const fn new(seed: u64) -> Self {
        Mutator { state: seed }
    }

    /// The next pseudo-random value (SplitMix64).
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A pseudo-random value in `0..n` (0 when `n` is 0).
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }

    /// Returns a copy of `input` with one to four random mutations applied.
    pub fn mutate(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = input.to_vec();
        let count = 1 + self.below(4);
        for _ in 0..count {
            let kind = MutationKind::ALL
                .get(self.below(MutationKind::ALL.len()))
                .copied()
                .unwrap_or(MutationKind::BitFlip);
            self.apply(&mut out, kind);
        }
        out
    }

    /// Applies one mutation of `kind` to `data` in place. Mutations that need bytes to work on
    /// leave empty input unchanged, except [`MutationKind::Insert`] and
    /// [`MutationKind::Token`], which insert into it.
    pub fn apply(&mut self, data: &mut Vec<u8>, kind: MutationKind) {
        let len = data.len();
        match kind {
            MutationKind::BitFlip => {
                let at = self.below(len);
                let bit = self.below(8);
                if let Some(byte) = data.get_mut(at) {
                    *byte ^= 1 << bit;
                }
            }
            MutationKind::ByteSet => {
                let at = self.below(len);
                let value = self.next_u64() as u8;
                if let Some(byte) = data.get_mut(at) {
                    *byte = value;
                }
            }
            MutationKind::Truncate => {
                let at = self.below(len);
                data.truncate(at);
            }
            MutationKind::Insert => {
                let at = self.below(len + 1);
                let n = 1 + self.below(16);
                let bytes: Vec<u8> = (0..n).map(|_| self.next_u64() as u8).collect();
                data.splice(at..at, bytes);
            }
            MutationKind::DuplicateChunk => {
                if len == 0 {
                    return;
                }
                let start = self.below(len);
                let n = 1 + self.below(256.min(len - start));
                let chunk = data.get(start..start + n).map(<[u8]>::to_vec);
                let at = self.below(len + 1);
                if let Some(chunk) = chunk {
                    data.splice(at..at, chunk);
                }
            }
            MutationKind::DeleteChunk => {
                if len == 0 {
                    return;
                }
                let start = self.below(len);
                let n = 1 + self.below(256.min(len - start));
                data.drain(start..start + n);
            }
            MutationKind::Token => {
                let token = TOKENS
                    .get(self.below(TOKENS.len()))
                    .copied()
                    .unwrap_or(b"obj");
                let at = self.below(len + 1);
                if self.below(2) == 0 {
                    // Overwrite (clamped to the end), keeping offsets after the token intact.
                    let end = (at + token.len()).min(len);
                    data.splice(at..end, token.iter().copied());
                } else {
                    data.splice(at..at, token.iter().copied());
                }
            }
        }
    }
}

/// `count` mutations of `input`, each made with [`Mutator::mutate`] by one mutator seeded with
/// `seed`.
pub fn mutations(input: &[u8], seed: u64, count: usize) -> impl Iterator<Item = Vec<u8>> + '_ {
    let mut mutator = Mutator::new(seed);
    (0..count).map(move |_| mutator.mutate(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix_reference_values() {
        // Reference output of SplitMix64 seeded with 0.
        let mut m = Mutator::new(0);
        assert_eq!(m.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(m.next_u64(), 0x6E78_9E6A_A1B9_65F4);
    }

    #[test]
    fn every_kind_works_on_every_length() {
        let mut m = Mutator::new(1);
        for kind in MutationKind::ALL {
            for len in [0usize, 1, 2, 300] {
                for _ in 0..50 {
                    let mut data = vec![b'x'; len];
                    m.apply(&mut data, kind);
                    assert!(data.len() <= len + 256, "{kind:?} {len}");
                }
            }
        }
    }

    #[test]
    fn mutations_change_the_input_and_are_reproducible() {
        let input = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
        let first: Vec<Vec<u8>> = mutations(input, 9, 200).collect();
        assert_eq!(first, mutations(input, 9, 200).collect::<Vec<_>>());
        assert_ne!(first, mutations(input, 10, 200).collect::<Vec<_>>());
        let changed = first.iter().filter(|m| m.as_slice() != input).count();
        assert!(changed > 190, "{changed}");
        assert!(
            first
                .iter()
                .all(|m| m.len() <= input.len() + Mutator::MAX_GROWTH)
        );
    }

    #[test]
    fn below_is_in_range() {
        let mut m = Mutator::new(3);
        assert_eq!(m.below(0), 0);
        for n in 1..50 {
            assert!(m.below(n) < n);
        }
    }
}

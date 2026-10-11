//! The digests of signed byte ranges, shared by the signatures of one verification and bounded
//! (R-18; QA finding: verification must not be quadratic in the file size).
//!
//! - Each distinct `(algorithm, ranges)` is hashed once: many signature dictionaries with the
//!   same byte range cost one digest.
//! - Sequential signatures sign prefixes of the same file (`[0, a)` grows with each signature):
//!   the hash state is kept at checkpoints every [`CHECKPOINT`] bytes and at the end of every
//!   first range hashed, so a first range continues from the nearest state before it instead of
//!   from byte 0. Signing `n` sequential signatures costs about the file once, not `n` times.
//! - The bytes hashed in total are bounded by [`Digests::budget_for`]: past it a digest is not
//!   computed (the signature is then not intact, with a warning), so a file with thousands of
//!   signature dictionaries that each sign most of the file cannot pin a worker.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};

use crate::algorithms::{DigestAlgorithm, Hasher};

/// The distance between two saved hash states of a first range.
pub(crate) const CHECKPOINT: usize = 64 * 1024;

/// The most hash states kept per algorithm.
const MAX_STATES: usize = 1 << 16;

/// The least hashing budget, whatever the file size.
pub(crate) const MIN_HASH_BUDGET: u64 = 64 * 1024 * 1024;

/// How many times the file size the hashing budget allows besides [`MIN_HASH_BUDGET`].
pub(crate) const HASH_BUDGET_FILES: u64 = 4;

/// A digest computation: the algorithm and the `(offset, length)` ranges.
type DigestKey = (DigestAlgorithm, Vec<(usize, usize)>);

/// The digests of byte ranges of one file.
pub(crate) struct Digests<'a> {
    source: &'a [u8],
    /// Bytes that may still be hashed.
    left: Cell<u64>,
    /// How many digests were refused for want of budget.
    refused: Cell<usize>,
    /// Every digest computed, by algorithm and ranges.
    results: RefCell<HashMap<DigestKey, Vec<u8>>>,
    /// Per algorithm: the hash state after `[0, position)`, by position.
    states: RefCell<HashMap<DigestAlgorithm, BTreeMap<usize, Hasher>>>,
}

impl<'a> Digests<'a> {
    /// The digests of ranges of `source`, with the budget [`Digests::budget_for`].
    pub(crate) fn new(source: &'a [u8]) -> Digests<'a> {
        Digests::with_budget(source, Digests::budget_for(source.len()))
    }

    /// The digests of ranges of `source`, hashing at most `budget` bytes in total.
    pub(crate) fn with_budget(source: &'a [u8], budget: u64) -> Digests<'a> {
        Digests {
            source,
            left: Cell::new(budget),
            refused: Cell::new(0),
            results: RefCell::new(HashMap::new()),
            states: RefCell::new(HashMap::new()),
        }
    }

    /// The hashing budget for a file of `len` bytes: [`MIN_HASH_BUDGET`] plus
    /// [`HASH_BUDGET_FILES`] times the file.
    pub(crate) fn budget_for(len: usize) -> u64 {
        MIN_HASH_BUDGET.saturating_add((len as u64).saturating_mul(HASH_BUDGET_FILES))
    }

    /// How many digests were refused because the budget was spent.
    pub(crate) fn refused(&self) -> usize {
        self.refused.get()
    }

    /// The digest with `algorithm` of the `(offset, length)` ranges of the file, concatenated;
    /// `None` when a range lies outside the file or the budget does not cover it.
    pub(crate) fn digest(
        &self,
        algorithm: DigestAlgorithm,
        ranges: &[(usize, usize)],
    ) -> Option<Vec<u8>> {
        let key = (algorithm, ranges.to_vec());
        if let Some(known) = self.results.borrow().get(&key) {
            return Some(known.clone());
        }
        for &(offset, length) in ranges {
            if offset.checked_add(length)? > self.source.len() {
                return None;
            }
        }
        let (mut hasher, rest) = match ranges.split_first() {
            Some((&(0, first), rest)) => (self.prefix(algorithm, first)?, rest),
            _ => (algorithm.hasher(), ranges),
        };
        for &(offset, length) in rest {
            self.spend(length)?;
            hasher.update(self.source.get(offset..offset.checked_add(length)?)?);
        }
        let digest = hasher.finalize();
        self.results.borrow_mut().insert(key, digest.clone());
        Some(digest)
    }

    /// The hash state after `[0, end)`, continued from the nearest saved state at or before
    /// `end`; saves states at the checkpoints passed and at `end`.
    fn prefix(&self, algorithm: DigestAlgorithm, end: usize) -> Option<Hasher> {
        let mut all = self.states.borrow_mut();
        let states = all.entry(algorithm).or_default();
        let (mut position, mut hasher) = states
            .range(..=end)
            .next_back()
            .map(|(&position, state)| (position, state.clone()))
            .unwrap_or_else(|| (0, algorithm.hasher()));
        self.spend(end - position)?;
        while position < end {
            let next = (position / CHECKPOINT)
                .saturating_add(1)
                .saturating_mul(CHECKPOINT)
                .min(end);
            hasher.update(self.source.get(position..next)?);
            position = next;
            if position % CHECKPOINT == 0 && states.len() < MAX_STATES {
                states.insert(position, hasher.clone());
            }
        }
        if states.len() < MAX_STATES {
            states.insert(end, hasher.clone());
        }
        Some(hasher)
    }

    /// Takes `bytes` from the budget; `None` (and one more refusal) when it does not cover them.
    fn spend(&self, bytes: usize) -> Option<()> {
        match self.left.get().checked_sub(bytes as u64) {
            Some(left) => {
                self.left.set(left);
                Some(())
            }
            None => {
                self.refused.set(self.refused.get().saturating_add(1));
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 % 251) as u8).collect()
    }

    fn direct(source: &[u8], algorithm: DigestAlgorithm, ranges: &[(usize, usize)]) -> Vec<u8> {
        let parts: Vec<&[u8]> = ranges.iter().map(|&(o, l)| &source[o..o + l]).collect();
        algorithm.digest(&parts)
    }

    #[test]
    fn digests_match_direct_hashing_in_any_order() {
        let source = data(5 * CHECKPOINT + 123);
        let digests = Digests::new(&source);
        let cases: Vec<Vec<(usize, usize)>> = vec![
            vec![(0, 3 * CHECKPOINT + 5), (3 * CHECKPOINT + 50, 1000)],
            vec![(0, 100), (200, 50)],
            vec![(0, 5 * CHECKPOINT + 123)],
            vec![(0, CHECKPOINT), (CHECKPOINT + 1, 7)],
            vec![(10, 20), (40, 2)],
            vec![(0, 0), (0, 0)],
            vec![(0, 2 * CHECKPOINT - 1), (2 * CHECKPOINT, 10)],
        ];
        for algorithm in [DigestAlgorithm::Sha256, DigestAlgorithm::Sha512] {
            // Longest first, then shorter prefixes: states before each end are reused.
            for ranges in cases.iter().rev().chain(cases.iter()) {
                assert_eq!(
                    digests.digest(algorithm, ranges),
                    Some(direct(&source, algorithm, ranges)),
                    "{algorithm:?} {ranges:?}"
                );
            }
        }
        assert_eq!(
            digests.digest(DigestAlgorithm::Sha256, &[(0, source.len() + 1)]),
            None
        );
        assert_eq!(digests.refused(), 0);
    }

    #[test]
    fn sequential_prefixes_cost_the_file_once() {
        let source = data(64 * CHECKPOINT);
        // A budget of twice the file: sixty-four signatures over growing prefixes still fit.
        let digests = Digests::with_budget(&source, 2 * source.len() as u64);
        for n in 1..=64 {
            let a = n * CHECKPOINT - 100;
            let ranges = [(0, a), (a + 50, 25)];
            assert!(
                digests.digest(DigestAlgorithm::Sha256, &ranges).is_some(),
                "{n}"
            );
        }
        assert_eq!(digests.refused(), 0);
    }

    #[test]
    fn the_budget_bounds_distinct_large_ranges() {
        let source = data(10 * CHECKPOINT);
        let digests = Digests::with_budget(&source, 3 * source.len() as u64);
        // Each range's second part is most of the file and differs: only a few fit.
        let mut computed = 0;
        for i in 0..20 {
            if digests
                .digest(
                    DigestAlgorithm::Sha256,
                    &[(0, 10), (20 + i, source.len() - 40)],
                )
                .is_some()
            {
                computed += 1;
            }
        }
        assert!((2..=4).contains(&computed), "{computed}");
        assert!(digests.refused() >= 16);
        // The same ranges again cost nothing: they are cached.
        assert!(
            digests
                .digest(DigestAlgorithm::Sha256, &[(0, 10), (20, source.len() - 40)])
                .is_some()
        );
    }
}

//! A growable output buffer with a hard size cap, shared by the decoders.

use super::FilterError;

/// Initial capacity cap: the buffer starts small and grows with real output, so an input that
/// merely *claims* a large size cannot make us reserve memory up front.
const MAX_INITIAL_CAPACITY: usize = 1 << 20;

/// Output of a decoder, never longer than `max` bytes.
///
/// Every write checks the cap first and fails with [`FilterError::LimitExceeded`] instead of
/// growing past it.
pub(super) struct LimitedOutput {
    data: Vec<u8>,
    max: usize,
}

impl LimitedOutput {
    /// An empty buffer capped at `max` bytes; `size_hint` only sizes the first allocation.
    pub(super) fn new(max: usize, size_hint: usize) -> LimitedOutput {
        LimitedOutput {
            data: Vec::with_capacity(size_hint.min(max).min(MAX_INITIAL_CAPACITY)),
            max,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.data.len()
    }

    pub(super) fn get(&self, index: usize) -> Option<u8> {
        self.data.get(index).copied()
    }

    /// Fails unless `additional` more bytes fit under the cap.
    fn reserve_checked(&self, additional: usize) -> Result<(), FilterError> {
        if additional > self.max.saturating_sub(self.data.len()) {
            Err(FilterError::LimitExceeded { limit: self.max })
        } else {
            Ok(())
        }
    }

    pub(super) fn push(&mut self, byte: u8) -> Result<(), FilterError> {
        self.reserve_checked(1)?;
        self.data.push(byte);
        Ok(())
    }

    pub(super) fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), FilterError> {
        self.reserve_checked(bytes.len())?;
        self.data.extend_from_slice(bytes);
        Ok(())
    }

    /// Appends `count` copies of `byte`.
    pub(super) fn extend_repeat(&mut self, byte: u8, count: usize) -> Result<(), FilterError> {
        self.reserve_checked(count)?;
        self.data.resize(self.data.len() + count, byte);
        Ok(())
    }

    /// Appends a copy of the `len` bytes already written at `start` (LZW table entries).
    /// Returns `false`, writing nothing, if that range is not inside the buffer.
    pub(super) fn extend_from_within(
        &mut self,
        start: usize,
        len: usize,
    ) -> Result<bool, FilterError> {
        let Some(end) = start.checked_add(len) else {
            return Ok(false);
        };
        if end > self.data.len() {
            return Ok(false);
        }
        self.reserve_checked(len)?;
        self.data.extend_from_within(start..end);
        Ok(true)
    }

    pub(super) fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

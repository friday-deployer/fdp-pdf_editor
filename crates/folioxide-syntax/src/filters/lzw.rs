//! `LZWDecode` (ISO 32000-2 §7.4.4.2).
//!
//! Codes are read most significant bit first, starting at 9 bits and growing to at most 12.
//! Code 256 clears the table, 257 ends the data, and new entries are numbered from 258. With
//! `/EarlyChange 1` (the default) the code width grows one code early: to 10 bits once the next
//! entry number reaches 511 rather than 512, and so on (§7.4.4.3, Table 7).
//!
//! The table stores each entry as a range of the output already written: an entry is always the
//! previous code's string plus the first byte of the current one, and those bytes sit next to each
//! other in the output. Decoding is therefore linear in the output size and needs no per-entry
//! allocation.
//!
//! Leniency: missing initial clear codes and a missing end-of-data code are fine. Once the table
//! is full, entries stop being added (the code width stays 12) until the next clear code. An
//! invalid code ends decoding; the output so far is kept and flagged truncated.

use super::output::LimitedOutput;
use super::{Decoded, Filter, FilterError};

const CLEAR_TABLE: u16 = 256;
const END_OF_DATA: u16 = 257;
const FIRST_ENTRY: u16 = 258;
/// Codes are at most 12 bits, so the table holds at most 4096 codes.
const MAX_CODES: usize = 4096;
const MIN_WIDTH: u32 = 9;
const MAX_WIDTH: u32 = 12;

/// Reads fixed-width codes, most significant bit first.
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u32,
    bits: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> BitReader<'a> {
        BitReader {
            data,
            pos: 0,
            acc: 0,
            bits: 0,
        }
    }

    /// The next `width`-bit code (`width` ≤ 16), or `None` when fewer than `width` bits remain.
    fn read(&mut self, width: u32) -> Option<u16> {
        while self.bits < width {
            let byte = *self.data.get(self.pos)?;
            self.pos += 1;
            self.acc = (self.acc << 8) | u32::from(byte);
            self.bits += 8;
        }
        self.bits -= width;
        let code = (self.acc >> self.bits) & ((1 << width) - 1);
        self.acc &= (1 << self.bits) - 1;
        u16::try_from(code).ok()
    }
}

/// The code width after the table has grown to `next_entry` entries (§7.4.4.3).
fn code_width(next_entry: usize, early_change: bool) -> u32 {
    let n = next_entry + usize::from(early_change);
    if n < 512 {
        MIN_WIDTH
    } else if n < 1024 {
        10
    } else if n < 2048 {
        11
    } else {
        MAX_WIDTH
    }
}

/// Decodes an `/LZWDecode` stream (without predictor) into at most `max` bytes.
pub(super) fn decode(data: &[u8], early_change: bool, max: usize) -> Result<Decoded, FilterError> {
    let mut out = LimitedOutput::new(max, data.len().saturating_mul(3));
    // Entries for codes 258.. as (start, len) ranges of `out`.
    let mut table: Vec<(usize, usize)> = Vec::with_capacity(MAX_CODES - usize::from(FIRST_ENTRY));
    let mut width = MIN_WIDTH;
    // The output range of the previous code, `None` right after a clear (or at the start).
    let mut previous: Option<(usize, usize)> = None;
    let mut reader = BitReader::new(data);

    while let Some(code) = reader.read(width) {
        if code == CLEAR_TABLE {
            table.clear();
            width = MIN_WIDTH;
            previous = None;
            continue;
        }
        if code == END_OF_DATA {
            break;
        }
        let start = out.len();
        let current = if code < CLEAR_TABLE {
            // `code < 256` here, so the cast is lossless.
            out.push(code as u8)?;
            (start, 1)
        } else {
            let index = usize::from(code - FIRST_ENTRY);
            match (table.get(index), previous) {
                (Some(&(entry_start, entry_len)), _) => {
                    if !out.extend_from_within(entry_start, entry_len)? {
                        return super::corrupt_or_truncated(
                            Filter::Lzw,
                            out.into_vec(),
                            "inconsistent LZW table",
                        );
                    }
                    (start, entry_len)
                }
                // The KwKwK case: the code being defined right now, i.e. the previous string plus
                // its own first byte.
                (None, Some((prev_start, prev_len))) if index == table.len() => {
                    let first = out.get(prev_start);
                    let copied = out.extend_from_within(prev_start, prev_len)?;
                    match (copied, first) {
                        (true, Some(first)) => out.push(first)?,
                        _ => {
                            return super::corrupt_or_truncated(
                                Filter::Lzw,
                                out.into_vec(),
                                "inconsistent LZW table",
                            );
                        }
                    }
                    (start, prev_len + 1)
                }
                _ => {
                    return super::corrupt_or_truncated(
                        Filter::Lzw,
                        out.into_vec(),
                        format!("LZW code {code} is not in the table"),
                    );
                }
            }
        };
        if let Some((prev_start, prev_len)) = previous {
            // New entry: the previous string plus the first byte of the current one. The current
            // string was written right after the previous one, so that is one contiguous range.
            if usize::from(FIRST_ENTRY) + table.len() < MAX_CODES {
                table.push((prev_start, prev_len + 1));
            }
            width = code_width(usize::from(FIRST_ENTRY) + table.len(), early_change);
        }
        previous = Some(current);
    }
    Ok(Decoded::complete(out.into_vec()))
}

/// A test-only LZW encoder matching the decoder's conventions (and Adobe's): clear code first,
/// clear again when the table is full, end-of-data code last. Cross-checked against qpdf through
/// the vectors in `test_vectors.rs`.
#[cfg(test)]
pub(super) fn encode_for_tests(data: &[u8], early_change: bool) -> Vec<u8> {
    use std::collections::HashMap;

    struct BitWriter {
        out: Vec<u8>,
        acc: u64,
        bits: u32,
    }
    impl BitWriter {
        fn write(&mut self, code: u16, width: u32) {
            self.acc = (self.acc << width) | u64::from(code);
            self.bits += width;
            while self.bits >= 8 {
                self.bits -= 8;
                self.out.push((self.acc >> self.bits) as u8);
            }
        }
        fn finish(mut self) -> Vec<u8> {
            if self.bits > 0 {
                self.out.push((self.acc << (8 - self.bits)) as u8);
            }
            self.out
        }
    }

    // The decoder lags one code behind the encoder: when it reads code number k (counting from 1
    // after a clear) it has k - 2 entries, so the encoder must use that width.
    let width_for = |emitted: usize| {
        code_width(
            usize::from(FIRST_ENTRY) + emitted.saturating_sub(1),
            early_change,
        )
    };
    let mut writer = BitWriter {
        out: Vec::new(),
        acc: 0,
        bits: 0,
    };
    let mut table: HashMap<Vec<u8>, u16> = HashMap::new();
    let mut emitted = 0usize;
    writer.write(CLEAR_TABLE, width_for(0));
    let mut word: Vec<u8> = Vec::new();
    let code_of = |table: &HashMap<Vec<u8>, u16>, word: &[u8]| -> u16 {
        if word.len() == 1 {
            u16::from(word[0])
        } else {
            table[word]
        }
    };
    for &byte in data {
        let mut extended = word.clone();
        extended.push(byte);
        if extended.len() == 1 || table.contains_key(&extended) {
            word = extended;
            continue;
        }
        writer.write(code_of(&table, &word), width_for(emitted));
        emitted += 1;
        let entry = usize::from(FIRST_ENTRY) + emitted - 1;
        table.insert(extended, entry as u16);
        if entry == MAX_CODES - 1 {
            writer.write(CLEAR_TABLE, width_for(emitted));
            table.clear();
            emitted = 0;
        }
        word = vec![byte];
    }
    if !word.is_empty() {
        writer.write(code_of(&table, &word), width_for(emitted));
        emitted += 1;
    }
    writer.write(END_OF_DATA, width_for(emitted));
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::test_vectors::{LZW_EC0, LZW_EC1, lzw_ec0_data, lzw_ec1_data};
    use crate::filters::tests::{hex, lcg_bytes};
    use crate::filters::{DecodeLimits, FilterParams, decode as decode_filter};

    fn lzw(data: &[u8], early_change: bool) -> Decoded {
        decode_filter(
            Filter::Lzw,
            data,
            &FilterParams::default().with_early_change(early_change),
            &DecodeLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn lzw_spec_example() {
        // ISO 32000-2 §7.4.4.2, Example 2: "-----A---B" encodes to these bytes (EarlyChange 1;
        // the example never reaches the width change, so both settings decode it).
        let encoded = [0x80, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01];
        for early_change in [true, false] {
            let decoded = lzw(&encoded, early_change);
            assert_eq!(decoded.data, b"-----A---B");
            assert!(!decoded.truncated);
        }
        assert_eq!(encode_for_tests(b"-----A---B", true), encoded);
    }

    #[test]
    fn lzw_early_change() {
        // Vectors from an independent encoder, verified by qpdf's decoder with the matching
        // /EarlyChange; they cross every code width and (EarlyChange 1) a full-table clear.
        let ec1 = hex(LZW_EC1);
        let decoded = lzw(&ec1, true);
        assert!(!decoded.truncated);
        assert_eq!(decoded.data, lzw_ec1_data());
        let ec0 = hex(LZW_EC0);
        let decoded = lzw(&ec0, false);
        assert!(!decoded.truncated);
        assert_eq!(decoded.data, lzw_ec0_data());

        // The wrong setting goes off the rails right at the first width change.
        let wrong = decode_filter(
            Filter::Lzw,
            &ec1,
            &FilterParams::default().with_early_change(false),
            &DecodeLimits::default(),
        );
        assert!(!wrong.is_ok_and(|d| d.data == lzw_ec1_data()));
        let wrong = decode_filter(
            Filter::Lzw,
            &ec0,
            &FilterParams::default().with_early_change(true),
            &DecodeLimits::default(),
        );
        assert!(!wrong.is_ok_and(|d| d.data == lzw_ec0_data()));

        // The test encoder reproduces both vectors bit for bit.
        assert_eq!(encode_for_tests(&lzw_ec1_data(), true), ec1);
        assert_eq!(encode_for_tests(&lzw_ec0_data(), false), ec0);
    }

    #[test]
    fn lzw_code_widths() {
        assert_eq!(code_width(510, true), 9);
        assert_eq!(code_width(511, true), 10);
        assert_eq!(code_width(511, false), 9);
        assert_eq!(code_width(512, false), 10);
        assert_eq!(code_width(1023, true), 11);
        assert_eq!(code_width(1024, false), 11);
        assert_eq!(code_width(2047, true), 12);
        assert_eq!(code_width(2048, false), 12);
        assert_eq!(code_width(4096, true), 12);
    }

    #[test]
    fn lzw_roundtrip_with_table_resets() {
        for (seed, len, alphabet) in [(1, 0, 256), (2, 1, 256), (3, 70_000, 256), (4, 100_000, 3)] {
            let data = lcg_bytes(seed, len, alphabet);
            for early_change in [true, false] {
                let encoded = encode_for_tests(&data, early_change);
                let decoded = lzw(&encoded, early_change);
                assert!(!decoded.truncated);
                assert_eq!(
                    decoded.data, data,
                    "seed {seed}, early change {early_change}"
                );
            }
        }
    }

    #[test]
    fn lzw_lenient_cases() {
        // No initial clear code, no end-of-data code: 'A' 'B' as 9-bit codes.
        let decoded = lzw(&[0x20, 0x90, 0x80], true);
        assert_eq!(decoded.data, b"AB");
        assert!(!decoded.truncated);
        // Data after the end-of-data code is ignored.
        let mut encoded = encode_for_tests(b"hello hello hello", true);
        encoded.extend_from_slice(b"\xFF\xFF\xFF");
        assert_eq!(lzw(&encoded, true).data, b"hello hello hello");
        // Empty input decodes to nothing.
        assert_eq!(lzw(b"", true), Decoded::complete(Vec::new()));
    }

    #[test]
    fn lzw_invalid_code() {
        // Clear, 'A', then code 300 (not yet defined): the 'A' survives, flagged truncated.
        let encoded = pack(&[(256, 9), (65, 9), (300, 9), (257, 9)]);
        let decoded = lzw(&encoded, true);
        assert_eq!(decoded.data, b"A");
        assert!(decoded.truncated);
        // An undefined code before any output is an error.
        let encoded = pack(&[(256, 9), (259, 9)]);
        let err = decode_filter(
            Filter::Lzw,
            &encoded,
            &FilterParams::default(),
            &DecodeLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            FilterError::Corrupt {
                filter: Filter::Lzw,
                ..
            }
        ));
    }

    #[test]
    fn lzw_bomb_limited() {
        let encoded = encode_for_tests(&vec![b'x'; 1 << 20], true);
        let err = decode_filter(
            Filter::Lzw,
            &encoded,
            &FilterParams::default(),
            &DecodeLimits::new(1000),
        )
        .unwrap_err();
        assert_eq!(err, FilterError::LimitExceeded { limit: 1000 });
    }

    #[test]
    fn lzw_survives_garbage() {
        for seed in 0..200 {
            let data = lcg_bytes(seed, 1 + (seed as usize * 37) % 2000, 256);
            for early_change in [true, false] {
                let _ = decode_filter(
                    Filter::Lzw,
                    &data,
                    &FilterParams::default().with_early_change(early_change),
                    &DecodeLimits::new(1 << 20),
                );
            }
        }
    }

    fn pack(codes: &[(u16, u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc = 0u64;
        let mut bits = 0u32;
        for &(code, width) in codes {
            acc = (acc << width) | u64::from(code);
            bits += width;
            while bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        if bits > 0 {
            out.push((acc << (8 - bits)) as u8);
        }
        out
    }
}

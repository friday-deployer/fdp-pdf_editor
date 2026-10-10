//! `FlateDecode` (ISO 32000-2 §7.4.4): a zlib stream (RFC 1950) around deflate data (RFC 1951).
//!
//! Decoding is lenient: a truncated or corrupt stream yields everything inflated before the
//! problem, flagged as truncated. The Adler-32 trailer is not checked (many writers get it wrong
//! or leave it out, and it carries no data). Input without a valid zlib header is tried as raw
//! deflate data, which some broken writers produce.

use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};

use super::{Decoded, Filter, FilterError};

/// The first output buffer is about this many times the input size (deflate rarely does worse
/// than 4:1 on PDF content), clamped between these bounds and the output cap.
const INITIAL_RATIO: usize = 4;
const MIN_INITIAL_LEN: usize = 4096;
const MAX_INITIAL_LEN: usize = 1 << 20;

/// Compresses `data` into a zlib stream suitable for `/FlateDecode`.
///
/// `level` is the usual zlib compression level: 0 stores, 1 is fastest, 9 compresses best (6 is
/// zlib's default). Values above 9 are treated as 9.
pub fn encode_flate(data: &[u8], level: u8) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(data, level.min(9))
}

/// How an inflate run ended.
enum Outcome {
    /// The final deflate block ended cleanly.
    Done,
    /// The input ended before the final block did.
    Truncated,
    /// Invalid deflate data.
    Corrupt,
}

/// Decodes a `/FlateDecode` stream (without predictor) into at most `max` bytes.
pub(super) fn decode(data: &[u8], max: usize) -> Result<Decoded, FilterError> {
    if data.len() < 2 {
        // Too short for even a zlib header. An empty Flate stream is common in the wild (empty
        // content streams); report it as truncated rather than as an error.
        return Ok(Decoded {
            data: Vec::new(),
            truncated: true,
        });
    }
    if let Some(body) = zlib_body(data) {
        let (out, outcome) = inflate(body, max)?;
        return match outcome {
            Outcome::Done => Ok(Decoded::complete(out)),
            Outcome::Truncated => Ok(Decoded {
                data: out,
                truncated: true,
            }),
            Outcome::Corrupt => {
                super::corrupt_or_truncated(Filter::Flate, out, "invalid deflate data")
            }
        };
    }
    // No zlib header: try raw deflate data before giving up.
    let (out, outcome) = inflate(data, max)?;
    match outcome {
        Outcome::Done => Ok(Decoded::complete(out)),
        Outcome::Truncated | Outcome::Corrupt => super::corrupt_or_truncated(
            Filter::Flate,
            out,
            "invalid zlib header and not raw deflate data",
        ),
    }
}

/// Returns the deflate data after a valid zlib header (RFC 1950 §2.2), or `None` if `data` does
/// not start with one.
fn zlib_body(data: &[u8]) -> Option<&[u8]> {
    let (&cmf, rest) = data.split_first()?;
    let (&flg, rest) = rest.split_first()?;
    let method_is_deflate = cmf & 0x0F == 8;
    let window_ok = cmf >> 4 <= 7;
    let check_ok = (u16::from(cmf) << 8 | u16::from(flg)) % 31 == 0;
    if !(method_is_deflate && window_ok && check_ok) {
        return None;
    }
    if flg & 0x20 != 0 {
        // FDICT: a preset dictionary id follows. PDF never uses one; skip the id and inflate what
        // does not depend on the dictionary.
        return rest.get(4..);
    }
    Some(rest)
}

/// Inflates raw deflate data into at most `max` bytes.
///
/// The whole output is one non-wrapping buffer (so back-references can reach any earlier byte),
/// grown by doubling up to `max + 1` bytes: a stream that still has output pending at that size is
/// over the limit.
fn inflate(mut input: &[u8], max: usize) -> Result<(Vec<u8>, Outcome), FilterError> {
    let cap = max.saturating_add(1);
    let initial = input
        .len()
        .saturating_mul(INITIAL_RATIO)
        .clamp(MIN_INITIAL_LEN, MAX_INITIAL_LEN)
        .min(cap);
    let mut out = vec![0u8; initial];
    let mut out_pos = 0usize;
    let mut decompressor = Box::<DecompressorOxide>::default();
    // No TINFL_FLAG_HAS_MORE_INPUT: the input is complete, so running out of it means truncation.
    let flags = inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    let outcome = loop {
        let (status, consumed, written) =
            decompress(&mut decompressor, input, &mut out, out_pos, flags);
        out_pos = out_pos.saturating_add(written).min(out.len());
        input = input.get(consumed..).unwrap_or_default();
        match status {
            TINFLStatus::Done => break Outcome::Done,
            TINFLStatus::HasMoreOutput => {
                if out.len() >= cap {
                    return Err(FilterError::LimitExceeded { limit: max });
                }
                let new_len = out.len().saturating_mul(2).min(cap);
                out.resize(new_len, 0);
            }
            TINFLStatus::NeedsMoreInput | TINFLStatus::FailedCannotMakeProgress => {
                break Outcome::Truncated;
            }
            _ => break Outcome::Corrupt,
        }
    };
    if out_pos > max {
        return Err(FilterError::LimitExceeded { limit: max });
    }
    out.truncate(out_pos);
    Ok((out, outcome))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::test_vectors::{
        FLATE_FLUSH_POINT, FLATE_FLUSHED_THEN_CORRUPT, FLATE_RAW_DEFLATE, FLATE_TEXT_TRUNCATED_AT,
        FLATE_TEXT_TRUNCATED_ZLIB_LEN, FLATE_TEXT_ZLIB, flate_text,
    };
    use crate::filters::tests::hex;
    use crate::filters::{DecodeLimits, FilterParams, decode as decode_filter};

    fn flate(data: &[u8], max: usize) -> Result<Decoded, FilterError> {
        decode_filter(
            Filter::Flate,
            data,
            &FilterParams::default(),
            &DecodeLimits::new(max),
        )
    }

    #[test]
    fn flate_decodes_zlib_vector() {
        let decoded = flate(&hex(FLATE_TEXT_ZLIB), usize::MAX).unwrap();
        assert!(!decoded.truncated);
        assert_eq!(decoded.data, flate_text());
    }

    #[test]
    fn flate_decodes_raw_deflate_without_header() {
        let decoded = flate(&hex(FLATE_RAW_DEFLATE), usize::MAX).unwrap();
        assert!(!decoded.truncated);
        assert_eq!(decoded.data, flate_text());
    }

    #[test]
    fn flate_truncated_partial() {
        let full = hex(FLATE_TEXT_ZLIB);
        let text = flate_text();
        let cut = full.get(..FLATE_TEXT_TRUNCATED_AT).unwrap();
        let decoded = flate(cut, usize::MAX).unwrap();
        assert!(decoded.truncated, "a truncated stream must be flagged");
        assert!(!decoded.data.is_empty());
        assert!(
            text.starts_with(&decoded.data),
            "partial output must be a prefix"
        );
        // zlib itself (Python `zlib.decompressobj`) recovers exactly as much from this prefix.
        assert_eq!(decoded.data.len(), FLATE_TEXT_TRUNCATED_ZLIB_LEN);

        // Every prefix that stops inside the deflate data decodes to a prefix of the text,
        // flagged truncated, and never errors.
        for len in 0..full.len() - 4 {
            let decoded = flate(full.get(..len).unwrap(), usize::MAX).unwrap();
            assert!(decoded.truncated, "prefix of {len} bytes not flagged");
            assert!(text.starts_with(&decoded.data));
        }

        // Stored (level 0) blocks are recovered byte by byte as well.
        let stored = encode_flate(&text, 0);
        for len in [3, 7, 8, 100, 5000, stored.len() - 5] {
            let decoded = flate(stored.get(..len).unwrap(), usize::MAX).unwrap();
            assert!(decoded.truncated);
            assert!(text.starts_with(&decoded.data));
            if len > 7 {
                assert!(
                    decoded.data.len() + 16 >= len,
                    "stored prefix of {len} bytes"
                );
            }
        }

        // Missing Adler-32 trailer only: the data is complete, nothing is flagged.
        let no_adler = full.get(..full.len() - 4).unwrap();
        let decoded = flate(no_adler, usize::MAX).unwrap();
        assert!(!decoded.truncated);
        assert_eq!(decoded.data, text);

        // Corruption after a full flush (zlib `Z_FULL_FLUSH`, then a reserved block type): the
        // bytes before the corruption survive, flagged truncated. zlib returns the same prefix.
        let decoded = flate(&hex(FLATE_FLUSHED_THEN_CORRUPT), usize::MAX).unwrap();
        assert!(decoded.truncated);
        assert_eq!(decoded.data, text.get(..FLATE_FLUSH_POINT).unwrap());
    }

    #[test]
    fn flate_bomb_limited() {
        // 64 MiB of zeros deflates to about 64 KiB; a 1 MiB cap must stop it early.
        let bomb = encode_flate(&vec![0u8; 64 << 20], 9);
        assert!(bomb.len() < 128 << 10);
        let err = flate(&bomb, 1 << 20).unwrap_err();
        assert_eq!(err, FilterError::LimitExceeded { limit: 1 << 20 });

        // The cap is inclusive: exactly `max` bytes is fine, one more is not.
        let exact = encode_flate(&vec![7u8; 100_000], 6);
        assert_eq!(flate(&exact, 100_000).unwrap().data.len(), 100_000);
        assert_eq!(
            flate(&exact, 99_999).unwrap_err(),
            FilterError::LimitExceeded { limit: 99_999 }
        );
        // A zero cap admits only empty output.
        assert_eq!(flate(&encode_flate(b"", 6), 0).unwrap().data, b"");
        assert!(flate(&encode_flate(b"x", 6), 0).is_err());
    }

    #[test]
    fn flate_corrupt_without_output_is_error() {
        // Valid zlib header, then an invalid block type (3).
        let err = flate(&[0x78, 0x9C, 0x07, 0x00], usize::MAX).unwrap_err();
        assert!(matches!(
            err,
            FilterError::Corrupt {
                filter: Filter::Flate,
                ..
            }
        ));
        // Plain text is neither zlib nor raw deflate.
        let err = flate(b"hello, world", usize::MAX).unwrap_err();
        assert!(matches!(
            err,
            FilterError::Corrupt {
                filter: Filter::Flate,
                ..
            }
        ));
    }

    #[test]
    fn flate_empty_input_is_truncated_empty() {
        let decoded = flate(b"", usize::MAX).unwrap();
        assert!(decoded.data.is_empty());
        assert!(decoded.truncated);
    }

    #[test]
    fn flate_ignores_trailing_garbage() {
        let mut data = encode_flate(b"content", 6);
        data.extend_from_slice(b"\r\nendstream garbage");
        let decoded = flate(&data, usize::MAX).unwrap();
        assert_eq!(decoded.data, b"content");
        assert!(!decoded.truncated);
    }

    #[test]
    fn flate_roundtrip_all_levels() {
        let text = flate_text();
        for level in 0..=12u8 {
            let encoded = encode_flate(&text, level);
            assert_eq!(
                flate(&encoded, usize::MAX).unwrap().data,
                text,
                "level {level}"
            );
        }
        let mut state = 0x1234_5678u32;
        for len in [0usize, 1, 2, 31, 32_768, 70_001] {
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    (state >> 16) as u8
                })
                .collect();
            let encoded = encode_flate(&data, 6);
            let decoded = flate(&encoded, usize::MAX).unwrap();
            assert_eq!(decoded.data, data);
            assert!(!decoded.truncated);
        }
    }

    #[test]
    fn flate_encoder_output_is_a_zlib_stream() {
        for level in [0, 1, 6, 9] {
            let encoded = encode_flate(b"abc", level);
            assert!(zlib_body(&encoded).is_some(), "level {level}");
        }
    }

    #[test]
    fn zlib_header_validation() {
        assert!(zlib_body(&[0x78, 0x9C]).is_some());
        assert!(zlib_body(&[0x78, 0x01]).is_some());
        assert!(zlib_body(&[0x78, 0xDA]).is_some());
        assert!(zlib_body(&[0x78, 0x9D]).is_none(), "bad FCHECK");
        assert!(zlib_body(&[0x79, 0x9C]).is_none(), "bad method");
        assert!(zlib_body(&[0x88, 0x98]).is_none(), "window too large");
        assert!(zlib_body(&[0x78]).is_none());
        assert!(zlib_body(&[]).is_none());
    }
}

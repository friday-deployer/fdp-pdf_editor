//! Fuzz target `fuzz_filters`: every stream filter decoder, the predictors, filter chains and
//! the encoders (ISO 32000-2 §7.4).
//!
//! The first six input bytes choose the decode parameters (predictor, colors, bits per
//! component, columns, early change) and a filter chain; the rest is the encoded data. On any
//! input:
//! - `decode` and `decode_chain` never panic, for every filter in `Filter::ALL`, and never
//!   return more than `max_output` bytes;
//! - the passthrough filters (DCT, JPX, JBIG2, CCITT) are refused by `decode` and returned as
//!   remaining by `decode_chain`;
//! - a one-filter chain gives exactly what `decode` gives;
//! - the Flate, ASCIIHex and ASCII85 encoders round-trip through their decoders.
//!
//! Run with `cargo +nightly fuzz run fuzz_filters` from the repository root.

#![no_main]

use folioxide_syntax::filters::{
    DecodeLimits, Filter, FilterError, FilterParams, decode, decode_chain, encode_ascii_hex,
    encode_ascii85, encode_flate,
};
use libfuzzer_sys::fuzz_target;

/// Small enough to keep each run fast; large enough for real bombs to hit it.
const MAX_OUTPUT: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    let Some((head, body)) = data.split_first_chunk::<6>() else {
        return;
    };
    let params = params(head);
    let limits = DecodeLimits::new(MAX_OUTPUT).with_max_chain_len(4);

    for filter in Filter::ALL {
        let single = decode(filter, body, &params, &limits);
        let chain = decode_chain(&[(filter, params)], body, &limits);
        if let Ok(decoded) = &single {
            assert!(decoded.data.len() <= MAX_OUTPUT, "{filter}");
        }
        if filter.is_passthrough() {
            assert_eq!(single, Err(FilterError::Unsupported { filter }));
            let out = chain.unwrap();
            assert_eq!(out.remaining, [filter]);
            assert_eq!(out.data, body);
            assert!(!out.truncated);
        } else {
            match (&single, &chain) {
                (Ok(one), Ok(out)) => {
                    assert_eq!(one.data, out.data, "{filter}");
                    assert_eq!(one.truncated, out.truncated, "{filter}");
                    assert!(out.remaining.is_empty());
                }
                (Err(a), Err(b)) => assert_eq!(a, b, "{filter}"),
                (a, b) => panic!("{filter}: decode {a:?} but decode_chain {b:?}"),
            }
        }
    }

    // A chain of up to five filters (one more than the limit allows) picked by the head bytes.
    let len = 1 + usize::from(head[0] >> 5) % 5;
    let chain: Vec<(Filter, FilterParams)> = head
        .iter()
        .take(len)
        .map(|&b| (Filter::ALL[usize::from(b) % Filter::ALL.len()], params))
        .collect();
    match decode_chain(&chain, body, &limits) {
        Ok(out) => {
            assert!(chain.len() <= 4);
            assert!(out.data.len() <= MAX_OUTPUT);
            let first_passthrough = chain.iter().position(|(f, _)| f.is_passthrough());
            let expected: Vec<Filter> = first_passthrough
                .map(|i| chain[i..].iter().map(|(f, _)| *f).collect())
                .unwrap_or_default();
            assert_eq!(out.remaining, expected);
        }
        Err(FilterError::LimitExceeded { limit }) if chain.len() > 4 => assert_eq!(limit, 4),
        Err(_) => {}
    }

    // Encoders round-trip.
    let plain = FilterParams::new();
    let roomy = DecodeLimits::new(body.len().max(1));
    let flate = encode_flate(body, head[1] % 10);
    let back = decode(Filter::Flate, &flate, &plain, &roomy).unwrap();
    assert!(!back.truncated);
    assert_eq!(back.data, body);
    let back = decode(Filter::AsciiHex, &encode_ascii_hex(body), &plain, &roomy).unwrap();
    assert_eq!(back.data, body);
    let back = decode(Filter::Ascii85, &encode_ascii85(body), &plain, &roomy).unwrap();
    assert_eq!(back.data, body);
});

/// Decode parameters from the head bytes, mostly valid, sometimes arbitrary.
fn params(head: &[u8; 6]) -> FilterParams {
    let predictor = match head[0] % 12 {
        0 => 1,
        1 => 2,
        n @ 2..=7 => 8 + n, // 10..=15
        8 => 0,
        _ => head[5], // anything, mostly invalid
    };
    let colors = if head[1] & 0x80 == 0 {
        1 + head[1] % 4
    } else {
        head[1]
    };
    let bits_per_component = if head[2] & 0x80 == 0 {
        [1, 2, 4, 8, 16][usize::from(head[2]) % 5]
    } else {
        head[2]
    };
    let columns = match head[3] >> 6 {
        0 => 1 + u32::from(head[4] % 16),
        1 => u32::from(u16::from_le_bytes([head[3] & 0x3F, head[4]])),
        2 => 0,
        _ => u32::from_le_bytes([head[4], head[3], 0xFF, 0x7F]),
    };
    FilterParams::new()
        .with_predictor(predictor)
        .with_colors(colors)
        .with_bits_per_component(bits_per_component)
        .with_columns(columns)
        .with_early_change(head[5] & 1 == 1)
}

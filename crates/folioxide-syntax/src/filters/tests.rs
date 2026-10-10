//! API-level tests for `filters`: names, defaults, `decode`, `decode_chain`, and a deterministic
//! no-panic sweep over garbage and mutated input. Per-filter tests live in each filter's module.

use super::*;

/// Decodes a hex string (test vectors); panics on bad input.
pub(super) fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(digits.len().is_multiple_of(2), "odd hex length");
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// Deterministic pseudo-random bytes below `alphabet` (≤ 256): the 32-bit LCG that
/// `gen_test_vectors.py` uses too.
pub(super) fn lcg_bytes(seed: u32, len: usize, alphabet: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            ((state >> 16) % alphabet) as u8
        })
        .collect()
}

fn plain() -> FilterParams {
    FilterParams::default()
}

fn unlimited() -> DecodeLimits {
    DecodeLimits::new(usize::MAX)
}

#[test]
fn filter_names() {
    let names: [(&[u8], Filter); 17] = [
        (b"FlateDecode", Filter::Flate),
        (b"Fl", Filter::Flate),
        (b"LZWDecode", Filter::Lzw),
        (b"LZW", Filter::Lzw),
        (b"ASCIIHexDecode", Filter::AsciiHex),
        (b"AHx", Filter::AsciiHex),
        (b"ASCII85Decode", Filter::Ascii85),
        (b"A85", Filter::Ascii85),
        (b"RunLengthDecode", Filter::RunLength),
        (b"RL", Filter::RunLength),
        (b"DCTDecode", Filter::Dct),
        (b"DCT", Filter::Dct),
        (b"JPXDecode", Filter::Jpx),
        (b"JBIG2Decode", Filter::Jbig2),
        (b"CCITTFaxDecode", Filter::CcittFax),
        (b"CCF", Filter::CcittFax),
        (b"Crypt", Filter::Crypt),
    ];
    for (name, filter) in names {
        assert_eq!(Filter::from_name(name), Some(filter), "{name:?}");
    }
    for filter in Filter::ALL {
        assert_eq!(Filter::from_name(filter.name().as_bytes()), Some(filter));
        assert_eq!(filter.to_string(), filter.name());
    }
    for unknown in [
        &b""[..],
        b"flatedecode",
        b"/FlateDecode",
        b"Flate",
        b"BrotliDecode",
        b"JPX",
    ] {
        assert_eq!(Filter::from_name(unknown), None, "{unknown:?}");
    }
}

#[test]
fn filter_classification() {
    let passthrough: Vec<Filter> = Filter::ALL
        .into_iter()
        .filter(|f| f.is_passthrough())
        .collect();
    assert_eq!(
        passthrough,
        [Filter::CcittFax, Filter::Jbig2, Filter::Dct, Filter::Jpx]
    );
    let predictors: Vec<Filter> = Filter::ALL
        .into_iter()
        .filter(|f| f.supports_predictor())
        .collect();
    assert_eq!(predictors, [Filter::Lzw, Filter::Flate]);
}

#[test]
fn defaults_follow_the_spec() {
    let p = FilterParams::default();
    assert_eq!(
        (
            p.predictor,
            p.colors,
            p.bits_per_component,
            p.columns,
            p.early_change
        ),
        (1, 1, 8, 1, true)
    );
    assert_eq!(FilterParams::new(), p);
    let p = p
        .with_predictor(12)
        .with_colors(3)
        .with_bits_per_component(16)
        .with_columns(640)
        .with_early_change(false);
    assert_eq!(
        (
            p.predictor,
            p.colors,
            p.bits_per_component,
            p.columns,
            p.early_change
        ),
        (12, 3, 16, 640, false)
    );
    let limits = DecodeLimits::default();
    assert_eq!(limits.max_output, 512 * 1024 * 1024);
    assert_eq!(limits.max_chain_len, 16);
    let limits = DecodeLimits::new(10)
        .with_max_chain_len(2)
        .with_max_output(20);
    assert_eq!((limits.max_output, limits.max_chain_len), (20, 2));
}

#[test]
fn passthrough_filters_are_unsupported_in_decode() {
    for filter in [Filter::Dct, Filter::Jpx, Filter::Jbig2, Filter::CcittFax] {
        assert_eq!(
            decode(filter, b"\xFF\xD8", &plain(), &unlimited()).unwrap_err(),
            FilterError::Unsupported { filter }
        );
    }
}

#[test]
fn crypt_is_identity() {
    let decoded = decode(Filter::Crypt, b"secret", &plain(), &unlimited()).unwrap();
    assert_eq!(decoded, Decoded::complete(b"secret".to_vec()));
    assert_eq!(
        decode(Filter::Crypt, b"secret", &plain(), &DecodeLimits::new(5)).unwrap_err(),
        FilterError::LimitExceeded { limit: 5 }
    );
}

#[test]
fn chain_applies_filters_in_order() {
    let text = b"BT /F1 12 Tf (Hello) Tj ET".repeat(20);
    // /Filter [/ASCII85Decode /FlateDecode]: the data was deflated, then ASCII85-encoded.
    let encoded = encode_ascii85(&encode_flate(&text, 6));
    let chain = [(Filter::Ascii85, plain()), (Filter::Flate, plain())];
    let out = decode_chain(&chain, &encoded, &unlimited()).unwrap();
    assert_eq!(out.data, text);
    assert!(out.remaining.is_empty());
    assert!(!out.truncated);

    // Three levels, with a Crypt entry first (identity here).
    let encoded = encode_ascii_hex(&encode_ascii85(&encode_flate(&text, 9)));
    let chain = [
        (Filter::Crypt, plain()),
        (Filter::AsciiHex, plain()),
        (Filter::Ascii85, plain()),
        (Filter::Flate, plain()),
    ];
    assert_eq!(
        decode_chain(&chain, &encoded, &unlimited()).unwrap().data,
        text
    );

    // No filters: the data as is.
    let out = decode_chain(&[], b"raw", &unlimited()).unwrap();
    assert_eq!(out.data, b"raw");
    assert!(out.remaining.is_empty() && !out.truncated);
}

#[test]
fn chain_stops_at_passthrough() {
    let jpeg = b"\xFF\xD8\xFF\xE0 not really a jpeg \xFF\xD9";
    let chain = [(Filter::Flate, plain()), (Filter::Dct, plain())];
    let out = decode_chain(&chain, &encode_flate(jpeg, 6), &unlimited()).unwrap();
    assert_eq!(out.data, jpeg);
    assert_eq!(out.remaining, [Filter::Dct]);

    // Everything from the first passthrough filter on is left, in order.
    let chain = [
        (Filter::AsciiHex, plain()),
        (Filter::Jbig2, plain()),
        (Filter::Flate, plain()),
        (Filter::CcittFax, plain()),
    ];
    let out = decode_chain(&chain, b"41 42>", &unlimited()).unwrap();
    assert_eq!(out.data, b"AB");
    assert_eq!(
        out.remaining,
        [Filter::Jbig2, Filter::Flate, Filter::CcittFax]
    );

    let chain = [(Filter::Jpx, plain())];
    let out = decode_chain(&chain, b"jp2", &unlimited()).unwrap();
    assert_eq!(out.data, b"jp2");
    assert_eq!(out.remaining, [Filter::Jpx]);
}

#[test]
fn chain_propagates_truncation_and_errors() {
    let text = b"0123456789".repeat(100);
    // ASCII85 stage damaged at the end (one stray character), Flate stage then truncated too.
    let mut encoded = encode_ascii85(&encode_flate(&text, 6));
    encoded.truncate(encoded.len() - 2); // drop "~>"
    let cut = encoded.len() / 2;
    encoded.truncate(cut - cut % 5 + 1); // leave a one-character final group
    let chain = [(Filter::Ascii85, plain()), (Filter::Flate, plain())];
    let out = decode_chain(&chain, &encoded, &unlimited()).unwrap();
    assert!(out.truncated);
    assert!(text.starts_with(&out.data));

    // A hard error in any step fails the chain.
    let chain = [(Filter::AsciiHex, plain()), (Filter::Flate, plain())];
    let err = decode_chain(&chain, b"zz", &unlimited()).unwrap_err();
    assert!(matches!(
        err,
        FilterError::Corrupt {
            filter: Filter::AsciiHex,
            ..
        }
    ));
    let bad_params = plain().with_predictor(99);
    let chain = [(Filter::AsciiHex, plain()), (Filter::Flate, bad_params)];
    let err = decode_chain(&chain, b"00>", &unlimited()).unwrap_err();
    assert!(matches!(err, FilterError::InvalidParams { .. }));
}

#[test]
fn chain_limits() {
    let long: Vec<(Filter, FilterParams)> = vec![(Filter::Crypt, plain()); 17];
    assert_eq!(
        decode_chain(&long, b"x", &DecodeLimits::default()).unwrap_err(),
        FilterError::LimitExceeded { limit: 16 }
    );
    let at_limit = long.get(..16).unwrap();
    assert_eq!(
        decode_chain(at_limit, b"x", &DecodeLimits::default())
            .unwrap()
            .data,
        b"x"
    );
    // The output cap applies per step...
    let chain = [(Filter::AsciiHex, plain())];
    assert_eq!(
        decode_chain(&chain, b"414243>", &DecodeLimits::new(2)).unwrap_err(),
        FilterError::LimitExceeded { limit: 2 }
    );
    // ...and to data that no step decoded.
    assert_eq!(
        decode_chain(&[], b"abc", &DecodeLimits::new(2)).unwrap_err(),
        FilterError::LimitExceeded { limit: 2 }
    );
    let chain = [(Filter::Dct, plain())];
    assert_eq!(
        decode_chain(&chain, b"abc", &DecodeLimits::new(2)).unwrap_err(),
        FilterError::LimitExceeded { limit: 2 }
    );
}

#[test]
fn errors_display() {
    let corrupt = FilterError::Corrupt {
        filter: Filter::Flate,
        detail: "invalid deflate data".into(),
    };
    assert_eq!(
        corrupt.to_string(),
        "corrupt FlateDecode data: invalid deflate data"
    );
    assert_eq!(
        FilterError::LimitExceeded { limit: 10 }.to_string(),
        "filter decoding limit exceeded (limit 10)"
    );
    assert_eq!(
        FilterError::Unsupported {
            filter: Filter::Dct
        }
        .to_string(),
        "DCTDecode is not decoded by the syntax layer"
    );
    assert_eq!(
        FilterError::InvalidParams { detail: "x".into() }.to_string(),
        "invalid filter parameters: x"
    );
    fn assert_error<E: std::error::Error + Send + Sync + 'static>() {}
    assert_error::<FilterError>();
}

/// Every decoder, with and without predictors, on garbage and on mutated valid data: never
/// panics, never exceeds the cap. (A stable-toolchain stand-in for `fuzz_filters`.)
#[test]
fn no_panic_on_garbage_and_mutations() {
    const CAP: usize = 1 << 16;
    let limits = DecodeLimits::new(CAP);
    let param_sets = [
        plain(),
        plain().with_predictor(2).with_colors(3).with_columns(5),
        plain()
            .with_predictor(2)
            .with_bits_per_component(1)
            .with_columns(9),
        plain()
            .with_predictor(2)
            .with_bits_per_component(16)
            .with_colors(2),
        plain().with_predictor(12).with_colors(3).with_columns(4),
        plain()
            .with_predictor(15)
            .with_bits_per_component(4)
            .with_columns(u32::MAX),
        plain().with_early_change(false),
    ];
    let text = b"q 1 0 0 1 72 720 cm BT /F1 12 Tf (abc) Tj ET Q\n".repeat(30);
    let valid: Vec<(Filter, Vec<u8>)> = vec![
        (Filter::Flate, encode_flate(&text, 6)),
        (Filter::Lzw, lzw::encode_for_tests(&text, true)),
        (Filter::AsciiHex, encode_ascii_hex(&text)),
        (Filter::Ascii85, encode_ascii85(&text)),
        (Filter::RunLength, b"\x05abcdef\xF0x\x00y\x80".to_vec()),
    ];
    let mut checked = 0usize;
    let mut check = |filter: Filter, data: &[u8], params: &FilterParams| {
        if let Ok(decoded) = decode(filter, data, params, &limits) {
            assert!(decoded.data.len() <= CAP);
        }
        checked += 1;
    };
    for seed in 0..300u32 {
        let len = (seed as usize * 7919) % 3000;
        let garbage = lcg_bytes(seed, len, 256);
        let ascii = lcg_bytes(seed, len, 128);
        for filter in Filter::ALL {
            for params in &param_sets {
                check(filter, &garbage, params);
                check(filter, &ascii, params);
            }
        }
        for (filter, data) in &valid {
            let mut mutated = data.clone();
            let flips = lcg_bytes(seed ^ 0x5555, 8, 256);
            for pair in flips.chunks(2) {
                let pos = (usize::from(pair[0]) * 131 + seed as usize) % mutated.len();
                mutated[pos] ^= pair[1] | 1;
            }
            let cut = (seed as usize * 31) % (mutated.len() + 1);
            for params in &param_sets {
                check(*filter, &mutated, params);
                check(*filter, &mutated[..cut], params);
            }
        }
    }
    assert!(checked > 30_000);
}

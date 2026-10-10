#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Property tests: every `Object` tree within the limits serializes and parses back equal
//! (ARCHITECTURE §A.9 layer 3, M1 acceptance criterion 4).
//!
//! - `proptest_object_roundtrip` (10,000 cases): `serialize_object` → `parse_object` in strict
//!   mode gives the same object, with reals compared after the serializer's rounding
//!   (`canonical_real`), and serializing the result again gives the same bytes.
//! - `proptest_indirect_roundtrip` and `proptest_stream_roundtrip`: the same through
//!   `serialize_indirect` → `parse_indirect_at`, for plain objects and for streams.
//!
//! The runs are deterministic: a fixed RNG seed, and no failure-persistence files. Set
//! `PROPTEST_CASES` or `PROPTEST_RNG_SEED` to run more cases or a different seed. The whole file
//! takes a few seconds in a debug build, so it runs in the normal `cargo test`.

use folioxide_syntax::serialize::canonical_real;
use folioxide_syntax::{
    Dict, ErrorCode, Limits, Name, Object, ObjectId, ParseCtx, PdfString, Stream, StreamData,
    Strictness, parse_indirect_at, parse_object, serialize_indirect, serialize_object,
};
use proptest::prelude::*;
use proptest::test_runner::RngSeed;

/// The number of cases of `proptest_object_roundtrip` (acceptance criterion: at least 10k).
const OBJECT_CASES: u32 = 10_000;

/// A fixed seed, so every run explores the same cases (tests are deterministic, CLAUDE.md).
const SEED: u64 = 0x00F0_110C_1DE5_EED5;

fn config(cases: u32) -> ProptestConfig {
    let default = ProptestConfig::default();
    ProptestConfig {
        // `ProptestConfig::default()` reads PROPTEST_CASES and PROPTEST_RNG_SEED.
        cases: if std::env::var_os("PROPTEST_CASES").is_some() {
            default.cases
        } else {
            cases
        },
        rng_seed: if std::env::var_os("PROPTEST_RNG_SEED").is_some() {
            default.rng_seed
        } else {
            RngSeed::Fixed(SEED)
        },
        failure_persistence: None,
        ..default
    }
}

fn strict() -> ParseCtx<'static> {
    ParseCtx::new(Limits::DEFAULT, Strictness::Strict)
}

// ---------------------------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------------------------

/// Name bytes: typical ASCII names, and any bytes except NUL (§7.3.5 forbids it), including
/// delimiters, `#`, white-space and non-ASCII bytes that the serializer must escape.
fn name_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        "[A-Za-z][A-Za-z0-9.+_-]{0,15}".prop_map(String::into_bytes),
        prop::collection::vec(1u8..=255, 0..16),
    ]
}

/// Reals of every magnitude, plus the values with special formatting rules.
fn real() -> impl Strategy<Value = f64> {
    prop_oneof![
        4 => any::<f64>(),
        4 => -1.0e6..1.0e6f64,
        2 => (-100_000i64..100_000, 0i32..8).prop_map(|(m, e)| m as f64 / 10f64.powi(e)),
        2 => (-1000i64..1000).prop_map(|n| n as f64),
        1 => prop::sample::select(vec![
            0.0,
            -0.0,
            1e-10,
            5e-11,
            -4.9e-11,
            f64::MIN_POSITIVE,
            f64::MAX,
            f64::MIN,
            f64::EPSILON,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
            123_456.789_012_345_67,
            0.1 + 0.2,
        ]),
    ]
}

fn string() -> impl Strategy<Value = PdfString> {
    (
        prop_oneof![
            prop::collection::vec(any::<u8>(), 0..48),
            // Parentheses, backslashes and EOLs, which literal strings must escape.
            prop::collection::vec(prop::sample::select(b"()\\\r\n \t\x00a".to_vec()), 0..24),
        ],
        any::<bool>(),
    )
        .prop_map(|(bytes, hex)| PdfString { bytes, hex })
}

fn leaf() -> impl Strategy<Value = Object> {
    prop_oneof![
        Just(Object::Null),
        any::<bool>().prop_map(Object::Bool),
        any::<i64>().prop_map(Object::Int),
        (-1000i64..1000).prop_map(Object::Int),
        real().prop_map(Object::Real),
        string().prop_map(Object::String),
        name_bytes().prop_map(|b| Object::Name(Name::from(b))),
        (any::<u32>(), any::<u16>()).prop_map(|(n, g)| Object::Ref(ObjectId::new(n, g))),
        (0u32..100, 0u16..3).prop_map(|(n, g)| Object::Ref(ObjectId::new(n, g))),
    ]
}

fn dict(value: impl Strategy<Value = Object>) -> impl Strategy<Value = Dict> {
    prop::collection::vec((name_bytes(), value), 0..8).prop_map(|entries| {
        entries
            .into_iter()
            .map(|(key, value)| (Name::from(key), value))
            .collect()
    })
}

/// Object trees up to 8 levels deep (stream objects excluded: they are only valid at the top
/// of an indirect object, see `proptest_stream_roundtrip`).
fn object() -> impl Strategy<Value = Object> {
    leaf().prop_recursive(8, 128, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Object::Array),
            dict(inner).prop_map(Object::Dict),
        ]
    })
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// What a reader gets back after `object` is written: reals rounded as the serializer rounds.
fn canonical(object: &Object) -> Object {
    match object {
        Object::Real(r) => Object::Real(canonical_real(*r)),
        Object::Array(items) => Object::Array(items.iter().map(canonical).collect()),
        Object::Dict(dict) => Object::Dict(
            dict.iter()
                .map(|(k, v)| (k.clone(), canonical(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn to_bytes(object: &Object) -> Vec<u8> {
    let mut out = Vec::new();
    serialize_object(object, &mut out);
    out
}

/// Bit-exact equality of reals, so `-0.0` vs `0.0` and NaN slips would be caught.
fn same_bits(a: &Object, b: &Object) -> bool {
    match (a, b) {
        (Object::Real(x), Object::Real(y)) => x.to_bits() == y.to_bits(),
        (Object::Array(x), Object::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same_bits(a, b))
        }
        (Object::Dict(x), Object::Dict(y)) => {
            x.len() == y.len()
                && x.iter()
                    .zip(y.iter())
                    .all(|((ka, va), (kb, vb))| ka == kb && same_bits(va, vb))
        }
        _ => a == b,
    }
}

// ---------------------------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(config(OBJECT_CASES))]

    #[test]
    fn proptest_object_roundtrip(object in object()) {
        let bytes = to_bytes(&object);
        let (parsed, end) = parse_object(&bytes, 0, &strict())
            .unwrap_or_else(|e| panic!("{e}: {}", bytes.escape_ascii()));
        prop_assert_eq!(end, bytes.len());
        let expected = canonical(&object);
        prop_assert!(same_bits(&parsed, &expected), "{parsed:?} != {expected:?}");
        // Writing what was read gives the same bytes: formatting is idempotent.
        prop_assert_eq!(to_bytes(&parsed), bytes);
    }
}

proptest! {
    #![proptest_config(config(2_000))]

    #[test]
    fn proptest_indirect_roundtrip(
        object in object(),
        num in 1u32..=u32::MAX,
        generation in any::<u16>(),
    ) {
        let id = ObjectId::new(num, generation);
        let mut bytes = b"%PDF-2.0\n".to_vec();
        let offset = bytes.len();
        serialize_indirect(id, &object, None, &mut bytes).unwrap();
        let parsed = parse_indirect_at(&bytes, offset, &strict(), &|_| None).unwrap();
        prop_assert_eq!(parsed.id, id);
        prop_assert_eq!(parsed.end + 1, bytes.len(), "endobj, then the final LF");
        prop_assert!(parsed.stream_data_range.is_none());
        prop_assert!(same_bits(&parsed.object, &canonical(&object)));
    }

    #[test]
    fn proptest_stream_roundtrip(
        mut entries in dict(leaf()),
        data in prop::collection::vec(any::<u8>(), 0..256),
        endstream_inside in any::<bool>(),
    ) {
        // Stream data may contain anything, even the `endstream` keyword: /Length decides.
        let mut data = data;
        if endstream_inside {
            data.extend_from_slice(b"\nendstream\nendobj\n");
        }
        entries.remove(b"Length");
        // A /Filter would make the dictionary claim an encoding the data does not have; the
        // writer keeps it for `Encoded` data, which is what this test round-trips.
        let stream = Stream::new(entries.clone(), StreamData::Encoded(data.clone()));
        let mut bytes = Vec::new();
        serialize_indirect(ObjectId::new(7, 0), &Object::Stream(Box::new(stream)), None, &mut bytes)
            .unwrap();
        let parsed = parse_indirect_at(&bytes, 0, &strict(), &|_| None).unwrap();
        let range = parsed.stream_data_range.clone().unwrap();
        prop_assert_eq!(&bytes[range.start as usize..range.end as usize], &data[..]);
        let Object::Stream(read) = &parsed.object else { panic!("not a stream") };
        prop_assert_eq!(read.data.clone(), StreamData::Source(range));
        let mut expected = match canonical(&Object::Dict(entries)) {
            Object::Dict(d) => d,
            _ => unreachable!(),
        };
        expected.insert("Length", data.len() as i64);
        prop_assert!(same_bits(&Object::Dict(read.dict.clone()), &Object::Dict(expected)));
        prop_assert_eq!(parsed.end + 1, bytes.len());
    }
}

// ---------------------------------------------------------------------------------------------
// Deterministic edge cases
// ---------------------------------------------------------------------------------------------

/// Nesting `depth` levels of alternating arrays and dictionaries around `inner`.
fn nested(depth: usize, inner: Object) -> Object {
    (0..depth).fold(inner, |acc, level| {
        if level % 2 == 0 {
            Object::Array(vec![acc])
        } else {
            let mut d = Dict::new();
            d.insert("K", acc);
            Object::Dict(d)
        }
    })
}

#[test]
fn nesting_up_to_the_limit_round_trips() {
    let max = usize::from(Limits::DEFAULT.max_nesting_depth);
    let object = nested(max, Object::Real(0.5));
    let bytes = to_bytes(&object);
    let (parsed, end) = parse_object(&bytes, 0, &strict()).unwrap();
    assert_eq!(end, bytes.len());
    assert_eq!(parsed, object);

    let too_deep = to_bytes(&nested(max + 1, Object::Null));
    let err = parse_object(&too_deep, 0, &strict()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);

    // A smaller limit is honoured exactly too.
    let ctx = ParseCtx::new(
        Limits::DEFAULT.with_max_nesting_depth(3),
        Strictness::Strict,
    );
    assert!(parse_object(&to_bytes(&nested(3, Object::Null)), 0, &ctx).is_ok());
    assert!(parse_object(&to_bytes(&nested(4, Object::Null)), 0, &ctx).is_err());
}

#[test]
fn extreme_values_round_trip() {
    let mut d = Dict::new();
    d.insert(Name::from(&b""[..]), Object::Int(i64::MIN));
    d.insert(Name::from(&b"#/()<>[]{}%"[..]), Object::Int(i64::MAX));
    d.insert(Name::from(vec![0xFF, 0x80, b' ']), Object::Real(f64::MAX));
    let object = Object::Array(vec![
        Object::Dict(d),
        Object::Real(f64::MIN_POSITIVE),
        Object::Real(-1e-11),
        Object::Ref(ObjectId::new(u32::MAX, u16::MAX)),
        Object::String(PdfString {
            bytes: b"\\)(\r\n\r".to_vec(),
            hex: false,
        }),
        Object::String(PdfString {
            bytes: Vec::new(),
            hex: true,
        }),
        Object::Name(Name::from(&b""[..])),
    ]);
    let bytes = to_bytes(&object);
    let (parsed, end) = parse_object(&bytes, 0, &strict()).unwrap();
    assert_eq!(end, bytes.len());
    assert!(same_bits(&parsed, &canonical(&object)), "{parsed:?}");
    assert_eq!(canonical_real(-1e-11).to_bits(), 0.0f64.to_bits());
}

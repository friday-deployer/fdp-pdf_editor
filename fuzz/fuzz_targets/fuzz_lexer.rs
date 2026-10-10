//! Fuzz target `fuzz_lexer`: the lexer and the object parser (ISO 32000-2 §7.2–7.3).
//!
//! The first input byte selects the policy (bit 0: strict, bit 1: tiny limits) and a start
//! offset; the rest is the PDF text. On any input:
//! - the lexer never panics, every token lies inside the input and after the previous one, an
//!   error always moves the position forward, and lexing terminates;
//! - `parse_object`, `parse_indirect_header` and `parse_indirect_at` never panic;
//! - whatever `parse_object` accepts serializes to text that parses back (with the same policy)
//!   to the same object, reals compared after the serializer's rounding, and serializing that
//!   again gives the same bytes.
//!
//! Run with `cargo +nightly fuzz run fuzz_lexer` from the repository root.

#![no_main]

use folioxide_syntax::serialize::canonical_real;
use folioxide_syntax::{
    DiagnosticLog, Lexer, Limits, Object, ObjectId, ParseCtx, Strictness, parse_indirect_at,
    parse_indirect_header, parse_object, serialize_object,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else {
        return;
    };
    let strictness = if selector & 1 == 0 {
        Strictness::Lenient
    } else {
        Strictness::Strict
    };
    let limits = if selector & 2 == 0 {
        Limits::DEFAULT
    } else {
        Limits::DEFAULT
            .with_max_nesting_depth(8)
            .with_max_string_len(64)
            .with_max_ref_chain(2)
    };
    let log = DiagnosticLog::new(32);
    let ctx = ParseCtx::new(limits, strictness).with_diagnostics(&log);
    let start = usize::from(selector >> 2) % (input.len() + 1);

    lex_everything(input, start, &ctx);

    // Parse a run of objects from `start`, as the object-stream and xref readers do.
    let mut pos = start;
    for _ in 0..64 {
        match parse_object(input, pos, &ctx) {
            Ok((object, end)) => {
                assert!(end > pos && end <= input.len(), "{pos} -> {end}");
                round_trip(&object, &ctx);
                pos = end;
            }
            Err(_) => break,
        }
    }

    let _ = parse_indirect_header(input, start, &ctx);
    let resolver = |id: ObjectId| -> Option<i64> {
        // A deterministic, sometimes-wrong length, so both the /Length path and the endstream
        // scan are exercised.
        (id.num % 3 != 0).then(|| i64::from(id.num % 4096))
    };
    if let Ok(indirect) = parse_indirect_at(input, start, &ctx, &resolver) {
        assert!(indirect.end <= input.len());
        if let Some(range) = &indirect.stream_data_range {
            assert!(range.start <= range.end && range.end <= input.len() as u64);
        }
    }
});

/// Lexes from `start` to the end, checking positions.
fn lex_everything(input: &[u8], start: usize, ctx: &ParseCtx<'_>) {
    let mut lexer = Lexer::with_ctx(input, start, ctx);
    // Every call consumes at least one byte or ends, so this many calls always suffice.
    for _ in 0..=input.len() + 1 {
        let before = lexer.position();
        match lexer.next_token() {
            Ok(Some(token)) => {
                assert!(before <= token.start, "{before} > {}", token.start);
                assert!(token.start < token.end && token.end <= input.len());
                assert_eq!(lexer.position(), token.end);
            }
            Ok(None) => {
                assert!(lexer.is_at_end());
                return;
            }
            Err(_) => {
                assert!(
                    lexer.position() > before || lexer.position() == input.len(),
                    "no progress after an error at {before}"
                );
                if lexer.position() == input.len() {
                    return;
                }
            }
        }
    }
    panic!("the lexer did not terminate");
}

/// Serializes `object`, parses it back with the same policy, and compares.
fn round_trip(object: &Object, ctx: &ParseCtx<'_>) {
    let mut bytes = Vec::new();
    serialize_object(object, &mut bytes);
    let (again, end) = parse_object(&bytes, 0, ctx).unwrap_or_else(|e| {
        panic!(
            "serializer output does not parse: {e}\n{}",
            bytes.escape_ascii()
        )
    });
    assert_eq!(end, bytes.len());
    assert!(
        same(&again, &canonical(object)),
        "{again:?} != {object:?}\n{}",
        bytes.escape_ascii()
    );
    let mut twice = Vec::new();
    serialize_object(&again, &mut twice);
    assert_eq!(twice, bytes, "serializing is not idempotent");
}

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

/// Equality with reals compared bit for bit.
fn same(a: &Object, b: &Object) -> bool {
    match (a, b) {
        (Object::Real(x), Object::Real(y)) => x.to_bits() == y.to_bits(),
        (Object::Array(x), Object::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same(a, b))
        }
        (Object::Dict(x), Object::Dict(y)) => {
            x.len() == y.len()
                && x.iter()
                    .zip(y.iter())
                    .all(|((ka, va), (kb, vb))| ka == kb && same(va, vb))
        }
        _ => a == b,
    }
}

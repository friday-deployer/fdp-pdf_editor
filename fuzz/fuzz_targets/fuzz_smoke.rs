//! Placeholder fuzz target (M0). It proves that the cargo-fuzz crate builds against
//! `folioxide-syntax`; the real targets (`fuzz_lexer`, `fuzz_filters`, `fuzz_parse_document`, ...)
//! arrive with M1. Run with `cargo +nightly fuzz run fuzz_smoke` from the repo root.

#![no_main]

use libfuzzer_sys::fuzz_target;

// Link the syntax crate so the build exercises the real dependency path.
use folioxide_syntax as _;

fuzz_target!(|data: &[u8]| {
    // Nothing to parse yet: just touch the input so the harness has a data dependency.
    std::hint::black_box(data);
});

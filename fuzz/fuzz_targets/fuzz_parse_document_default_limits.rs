//! Fuzz target `fuzz_parse_document_default_limits`: the read path of `fuzz_parse_document`
//! (ISO 32000-2 §7.5; open, resolve every object, follow every reference, decode every stream,
//! count the pages) with **`Limits::default()`** as shipped, and a per-input time budget.
//!
//! `fuzz_parse_document` lowers the decoding limits so that bombs do not stall it, which also
//! hides amplification that only the default limits allow (long `/Prev` chains of compressed
//! cross-reference streams, overlapping sections, reconstructions of files full of object
//! streams). This target keeps the defaults and judges each input by the work it justifies
//! instead (`folioxide_testkit::budget::WorkBudget::FUZZ`): 2 s, plus 300 ns per input byte,
//! 40 µs per object resolved or reference followed, and 20 ns per byte the store decoded. On any
//! input, in lenient and in strict mode:
//! - nothing panics or overflows the stack, and the store's documented guarantees hold
//!   (`folioxide_testkit::exercise`, `Report::violations`);
//! - opening and reading everything finishes within that allowance (an assertion: libFuzzer
//!   saves the input as a crash);
//! - an input still running after [`HANG`] aborts the process through
//!   `folioxide_testkit::budget::Watchdog`, which libFuzzer also saves as a crash. Its own
//!   `-timeout` (20 minutes by default) is a backstop.
//!
//! libFuzzer's default `-rss_limit_mb=2048` applies: an input that makes the store hold
//! gigabytes is reported as an out-of-memory crash, which is what this target is for.
//!
//! Run with `cargo +nightly fuzz run fuzz_parse_document_default_limits` from the repository
//! root; seed it with the `*.pdf` files under `fixtures/` like `fuzz_parse_document` (the
//! resource-exhaustion seeds in `fixtures/hostile/` matter most here).

#![no_main]

use std::time::{Duration, Instant};

use folioxide_syntax::{Limits, OpenOptions, Strictness};
use folioxide_testkit::budget::{Watchdog, WorkBudget};
use folioxide_testkit::exercise::exercise;
use libfuzzer_sys::fuzz_target;

/// The most one input may take (both modes) before the watchdog aborts. The most decoding the
/// default limits permit (4 GiB per mode, from eight 512 MiB bombs) takes about 40 s for both
/// modes in an AddressSanitizer build, and the work budget allows each mode about 90 s for it.
const HANG: Duration = Duration::from_secs(300);

fuzz_target!(|data: &[u8]| {
    let _armed = Watchdog::global(HANG).arm("fuzz_parse_document_default_limits input");
    for strictness in [Strictness::Lenient, Strictness::Strict] {
        let options = OpenOptions::default().with_strictness(strictness);
        debug_assert_eq!(options.limits, Limits::DEFAULT);
        let started = Instant::now();
        let report = exercise(data, &options);
        let elapsed = started.elapsed();
        assert!(
            report.violations.is_empty(),
            "{strictness:?}: {:#?}",
            report.violations
        );
        let decoded = report.total_decoded.max(report.decoded_bytes);
        let objects = report.objects + report.references;
        let allowed = WorkBudget::FUZZ.allowance(data.len(), objects, decoded);
        assert!(
            elapsed <= allowed,
            "{strictness:?}: took {elapsed:.2?} for {} input bytes, {objects} objects and {decoded} \
             decoded bytes (allowed {allowed:.2?}): super-linear work",
            data.len()
        );
    }
});

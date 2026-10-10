//! Fuzz target `fuzz_parse_document`: the whole read path of the lazy store (ISO 32000-2 §7.5,
//! ARCHITECTURE §A.9 layer 4): open, resolve every object, follow every reference, decode every
//! stream and count the pages.
//!
//! The input is the PDF file itself, unchanged, so the committed fixtures are a useful seed
//! corpus as they are. Each input is opened three times: lenient and strict with the default
//! limits except smaller decoding limits ([`FUZZ_LIMITS`]), and lenient with tiny limits (so
//! every limit check is reached). On any input:
//! - nothing panics, overflows the stack or hangs;
//! - the guarantees the store documents hold (checked by
//!   `folioxide_testkit::exercise`, listed on `Report::violations`): the error codes of
//!   lenient mode, cached objects, stream ranges inside the source, decoded sizes within the
//!   limits, the object cap, a catalog dictionary after every successful open;
//! - each open-and-read finishes within the work it justifies
//!   (`folioxide_testkit::budget::WorkBudget::FUZZ`), and a run that hangs is aborted by
//!   `folioxide_testkit::budget::Watchdog` (both are reported as crashes with the input).
//!
//! `fuzz_parse_document_default_limits` runs the same read path with the default limits as
//! shipped.
//!
//! Run with `cargo +nightly fuzz run fuzz_parse_document` from the repository root.

#![no_main]

use std::time::{Duration, Instant};

use folioxide_syntax::{Limits, OpenOptions, Strictness};
use folioxide_testkit::budget::{Watchdog, WorkBudget};
use folioxide_testkit::exercise::exercise;
use libfuzzer_sys::fuzz_target;

/// The most one input may take (all three opens) before the watchdog aborts.
const HANG: Duration = Duration::from_secs(60);

/// Tight limits, so short inputs reach the limit checks too.
const TINY_LIMITS: Limits = Limits::DEFAULT
    .with_max_objects(4096)
    .with_max_nesting_depth(12)
    .with_max_decoded_stream(4096)
    .with_max_total_decoded(16 * 1024)
    .with_max_xref_sections(3)
    .with_max_page_tree_depth(3)
    .with_max_string_len(1024)
    .with_max_ref_chain(2)
    .with_max_diagnostics(8);

/// The default limits, except that a stream decodes to at most 8 MiB and a document to at most
/// 32 MiB: a chain of Flate filters multiplies compression ratios, and with the defaults (512 MiB
/// and 4 GiB) one small bomb would take seconds and stall the fuzzer. The default values are
/// tested by the unit tests.
const FUZZ_LIMITS: Limits = Limits::DEFAULT
    .with_max_decoded_stream(8 * 1024 * 1024)
    .with_max_total_decoded(32 * 1024 * 1024);

fuzz_target!(|data: &[u8]| {
    let _armed = Watchdog::global(HANG).arm("fuzz_parse_document input");
    for options in [
        OpenOptions::default().with_limits(FUZZ_LIMITS),
        OpenOptions::default()
            .with_strictness(Strictness::Strict)
            .with_limits(FUZZ_LIMITS),
        OpenOptions::default().with_limits(TINY_LIMITS),
    ] {
        let started = Instant::now();
        let report = exercise(data, &options);
        let elapsed = started.elapsed();
        assert!(
            report.violations.is_empty(),
            "{:?}: {:#?}",
            options.strictness,
            report.violations
        );
        let decoded = report.total_decoded.max(report.decoded_bytes);
        let objects = report.objects + report.references;
        let allowed = WorkBudget::FUZZ.allowance(data.len(), objects, decoded);
        assert!(
            elapsed <= allowed,
            "{:?}: took {elapsed:.2?} for {} input bytes, {objects} objects and {decoded} \
             decoded bytes (allowed {allowed:.2?}): super-linear work",
            options.strictness,
            data.len()
        );
    }
});

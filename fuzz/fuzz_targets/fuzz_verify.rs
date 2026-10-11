//! Fuzz target `fuzz_verify`: PDF signature verification end to end (ISO 32000-2 §12.8; M3
//! brief §5 V0–V12, R-18): open the input leniently, then `folioxide_sign::verify_pdf::verify`
//! without trust anchors and with the test PKI root as anchor (discovery of signature fields and
//! orphan dictionaries, the `/ByteRange` and `/Contents` checks, the CMS, coverage, the revision
//! comparison and trust).
//!
//! The input is the PDF file itself, so the signed files under `fixtures/sign/pdf/` (and any
//! signed output of the test suite) are a useful seed corpus. On any input:
//! - nothing panics, overflows the stack or hangs (a run still going after [`HANG`] is aborted
//!   by `folioxide_testkit::budget::Watchdog`, which libFuzzer saves as a crash);
//! - every report keeps its documented invariants: `is_valid()` implies a sound byte range, an
//!   intact and valid signature, a field name and no problem; `pades_level` and
//!   `trusted == Some(true)` imply an intact, valid signature; `trusted` is `None` without
//!   anchors; a valid report's byte range lies inside the file, and `entireFile` ends at its
//!   end;
//! - verification finishes within the work it justifies: the read allowance of
//!   `folioxide_testkit::budget::WorkBudget::FUZZ` for the input, the objects and the decoded
//!   bytes, plus [`PER_SIGNATURE`] for each report (its digests, signatures and path).
//!
//! Run with `cargo +nightly fuzz run fuzz_verify` from the repository root.

#![no_main]

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use folioxide_model::{Document, PdfDate};
use folioxide_sign::report::{Coverage, SignatureReport};
use folioxide_sign::verify_pdf::{VerifyOptions, verify};
use folioxide_syntax::OpenOptions;
use folioxide_testkit::budget::{Watchdog, WorkBudget};
use libfuzzer_sys::fuzz_target;

/// The most one input may take before the watchdog aborts.
const HANG: Duration = Duration::from_secs(120);

/// The time allowed per report on top of the read allowance: hashing the signed ranges (linear
/// in the input, already allowed), a few RSA (up to 8192 bits) or ECDSA verifications for the
/// CMS and the certification path (at most 8 links over at most 64 candidates), and the
/// revision comparison of the revisions after the signed one.
const PER_SIGNATURE: Duration = Duration::from_secs(2);

/// The test PKI root (`fixtures/pki/root.pem`) as DER.
fn anchors() -> &'static [Vec<u8>] {
    static ANCHORS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    ANCHORS.get_or_init(|| {
        folioxide_sign::keys::certificates_from_pem(include_str!("../../fixtures/pki/root.pem"))
            .unwrap_or_default()
    })
}

/// The broken invariants of `report` on an input of `len` bytes.
fn check(report: &SignatureReport, len: usize, anchored: bool) {
    let sound = report.intact && report.signature_valid;
    if report.is_valid() {
        assert!(sound && report.byte_range_ok && report.problems.is_empty());
        assert!(report.field_name.is_some());
        let Some(&[o1, l1, o2, l2]) = report.byte_range.as_deref() else {
            panic!("valid without four byte range values: {report:?}");
        };
        assert!(o1 == 0 && l1 > 0 && o1 + l1 < o2, "{report:?}");
        let end = usize::try_from(o2 + l2).unwrap_or(usize::MAX);
        assert!(end <= len, "{report:?}");
        if report.coverage == Coverage::EntireFile {
            assert_eq!(end, len, "{report:?}");
        }
    }
    if report.pades_level.is_some() {
        assert!(sound && report.byte_range_ok, "{report:?}");
    }
    if report.trusted == Some(true) {
        assert!(sound, "{report:?}");
    }
    if !anchored {
        assert_eq!(report.trusted, None, "{report:?}");
    }
}

fuzz_target!(|data: &[u8]| {
    let _armed = Watchdog::global(HANG).arm("fuzz_verify input");
    let started = Instant::now();
    let Ok(doc) = Document::open(data.to_vec(), &OpenOptions::default()) else {
        return;
    };
    let at = PdfDate::parse(b"D:20261010120000Z");
    let mut reports = 0;
    for (anchored, options) in [
        (false, VerifyOptions::default()),
        (
            true,
            VerifyOptions::default()
                .with_trust_anchors_der(anchors().to_vec())
                .with_validation_time(at),
        ),
    ] {
        let Ok(found) = verify(&doc, &options) else {
            continue;
        };
        for report in &found {
            check(report, data.len(), anchored);
        }
        reports += found.len();
    }
    let elapsed = started.elapsed();
    let store = doc.store();
    let objects = store.object_ids().len();
    let read = WorkBudget::FUZZ.allowance(data.len(), objects, store.total_decoded());
    let allowed = read
        .saturating_mul(2)
        .saturating_add(PER_SIGNATURE.saturating_mul(u32::try_from(reports).unwrap_or(u32::MAX)));
    assert!(
        elapsed <= allowed,
        "took {elapsed:.2?} for {} input bytes, {objects} objects and {reports} reports \
         (allowed {allowed:.2?}): super-linear work",
        data.len()
    );
});

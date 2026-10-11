#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Interoperability with signatures made by other signers (M3 brief §0, §6.2
//! "interoperability"): every PDF of `fixtures/sign/pdf` (pyHanko 0.37 `sign_pdf`, `certify`
//! and `PdfTimeStamper`, and OpenSSL CMS over pyHanko placeholders; WP3.2B, `tools/fixtures/
//! sign.py`) is verified, and each report is compared field by field with **pyHanko's own
//! validation** of the same file.
//!
//! - [`PYHANKO`] is what `tools/oracles/validate_sig.py <file> --trust-root
//!   fixtures/pki/root.pem --json` (pyHanko 0.37.0, `validate_pdf_signature` /
//!   `validate_pdf_timestamp`, no fetching) printed for each fixture on 2026-10-10. The test PKI
//!   is valid from 2026 to 2075, so the date is not part of the verdict.
//! - [`DIFFERENCES`] lists where Folioxide deliberately reports something else, with the reason;
//!   nothing else may differ.
//! - The oracle suite `sign-interop` writes the same fixtures with expectations from our own
//!   reports (`sign_support::oracle`), so `cargo xtask oracle --suite sign-interop` re-checks
//!   the agreement against the live pyHanko, pdfsig and OpenSSL.

mod sign_support;

use folioxide_sign::ProblemCode;
use folioxide_sign::report::{Coverage, ModificationLevel, PadesLevel, SignatureKind};
use folioxide_testkit::{EMIT_ENABLED, ExpectJson, emit_case};
use sign_support::oracle::{TRUST_ROOT, signatures, startxref_count};
use sign_support::*;

/// pyHanko's verdict on one signature of a fixture.
struct PyHanko {
    file: &'static str,
    field: &'static str,
    intact: bool,
    valid: bool,
    trusted: bool,
    coverage: Coverage,
    modification: ModificationLevel,
    docmdp: Option<u8>,
}

/// One row of [`PYHANKO`].
const fn row(
    file: &'static str,
    field: &'static str,
    trusted: bool,
    coverage: Coverage,
    modification: ModificationLevel,
    docmdp: Option<u8>,
) -> PyHanko {
    PyHanko {
        file,
        field,
        intact: true,
        valid: true,
        trusted,
        coverage,
        modification,
        docmdp,
    }
}

/// pyHanko 0.37.0's validation of every signature of `fixtures/sign/pdf`, with
/// `fixtures/pki/root.pem` as the trust root (`pyhanko-empty-field.pdf` has no signature).
const PYHANKO: &[PyHanko] = {
    use Coverage::{EntireFile, EntireRevision};
    use ModificationLevel::{LtaUpdates, None};
    &[
        row(
            "openssl-p256-cades.pdf",
            "Signature1",
            true,
            EntireFile,
            None,
            Option::None,
        ),
        // SHA-1: intact and valid, never trusted (DEFAULT_WEAK_HASH_ALGORITHMS).
        row(
            "openssl-rsa2048-sha1.pdf",
            "Signature1",
            false,
            EntireFile,
            None,
            Option::None,
        ),
        row(
            "openssl-rsa2048.pdf",
            "Signature1",
            true,
            EntireFile,
            None,
            Option::None,
        ),
        row(
            "pyhanko-certified-p1.pdf",
            "Signature1",
            true,
            EntireFile,
            None,
            Some(1),
        ),
        row(
            "pyhanko-certified-p2.pdf",
            "Signature1",
            true,
            EntireFile,
            None,
            Some(2),
        ),
        row(
            "pyhanko-doc-timestamp.pdf",
            "Signature1",
            true,
            EntireRevision,
            LtaUpdates,
            Option::None,
        ),
        row(
            "pyhanko-doc-timestamp.pdf",
            "DocTimeStamp1",
            true,
            EntireFile,
            None,
            Option::None,
        ),
        row(
            "pyhanko-p256.pdf",
            "Signature1",
            true,
            EntireFile,
            None,
            Option::None,
        ),
        row(
            "pyhanko-pkcs7-rsa3072.pdf",
            "Signature1",
            true,
            EntireFile,
            None,
            Option::None,
        ),
        row(
            "pyhanko-rsa2048.pdf",
            "Signature1",
            true,
            EntireFile,
            None,
            Option::None,
        ),
        row(
            "pyhanko-two-signatures.pdf",
            "Signature1",
            true,
            EntireRevision,
            ModificationLevel::FormFilling,
            Option::None,
        ),
        row(
            "pyhanko-two-signatures.pdf",
            "Signature2",
            true,
            EntireFile,
            None,
            Option::None,
        ),
    ]
};

/// Where Folioxide deliberately differs from pyHanko on these fixtures: `(file, field, key,
/// ours, pyhanko, reason)`.
const DIFFERENCES: &[(&str, &str, &str, &str, &str, &str)] = &[
    (
        "pyhanko-doc-timestamp.pdf",
        "DocTimeStamp1",
        "valid",
        "false",
        "true",
        "M3 lists document timestamps without verifying the RFC 3161 token \
         (PendingTimestampVerification, brief §5 V1); M4 verifies them",
    ),
    (
        "pyhanko-doc-timestamp.pdf",
        "DocTimeStamp1",
        "trusted",
        "none",
        "true",
        "no trust verdict for an unverified document timestamp (M4)",
    ),
];

/// Our value of `key` for `(file, field)` when it deliberately differs from pyHanko's.
fn ours(file: &str, field: &str, key: &str) -> Option<&'static str> {
    DIFFERENCES
        .iter()
        .find(|(f, n, k, ..)| *f == file && *n == field && *k == key)
        .map(|(_, _, _, ours, _, _)| *ours)
}

#[test]
fn interop_fixtures_agree_with_pyhanko() {
    let fixtures = interop_fixtures();
    assert!(fixtures.len() >= 11, "{} fixtures", fixtures.len());
    let mut compared = 0;
    for (file, pdf) in &fixtures {
        let reports = verify(pdf);
        let expected: Vec<&PyHanko> = PYHANKO.iter().filter(|p| p.file == file).collect();
        let names: Vec<Option<&str>> = reports.iter().map(|r| r.field_name.as_deref()).collect();
        let want: Vec<Option<&str>> = expected.iter().map(|p| Some(p.field)).collect();
        assert_eq!(names, want, "{file}: the same signatures, in signing order");
        for (r, p) in reports.iter().zip(&expected) {
            let at = format!("{file} {}: {} {:?}", p.field, summary(r), r.warnings);
            assert_eq!(r.intact, p.intact, "{at}");
            let valid = ours(file, p.field, "valid").map_or(p.valid, |v| v == "true");
            assert_eq!(r.signature_valid, valid, "{at}");
            let trusted = match ours(file, p.field, "trusted") {
                Some("none") => Option::None,
                Some(v) => Some(v == "true"),
                Option::None => Some(p.trusted),
            };
            assert_eq!(r.trusted, trusted, "{at}");
            assert_eq!(r.coverage, p.coverage, "{at}");
            assert_eq!(r.modification, p.modification, "{at}");
            assert_eq!(r.docmdp, p.docmdp, "{at}");
            // Our own fields are never more optimistic than pyHanko (brief §0).
            assert!(r.byte_range_ok, "{at}");
            if r.is_valid() {
                assert!(p.intact && p.valid, "{at}");
            }
            compared += 1;
        }
    }
    assert_eq!(compared, PYHANKO.len(), "every pyHanko row was compared");
}

#[test]
fn interop_report_details() {
    let get = |file: &str| {
        let pdf = interop_fixtures()
            .into_iter()
            .find(|(name, _)| name == file)
            .unwrap()
            .1;
        verify(&pdf)
    };

    // pyHanko's B-B signatures are PAdES B-B for us too; adbe.pkcs7.detached ones are not.
    for file in [
        "pyhanko-rsa2048.pdf",
        "pyhanko-p256.pdf",
        "pyhanko-certified-p2.pdf",
    ] {
        let r = &get(file)[0];
        assert_eq!(r.pades_level, Some(PadesLevel::BB), "{file}");
        assert!(r.is_valid() && r.problems.is_empty(), "{file}");
        assert_eq!(r.sub_filter.as_deref(), Some("ETSI.CAdES.detached"));
    }
    let r = &get("pyhanko-pkcs7-rsa3072.pdf")[0];
    assert_eq!(r.sub_filter.as_deref(), Some("adbe.pkcs7.detached"));
    assert_eq!(r.pades_level, None);
    assert!(r.is_valid(), "{}", summary(r));

    // OpenSSL CMS: the -cades one has a signing-time attribute, so it is not B-B.
    let r = &get("openssl-p256-cades.pdf")[0];
    assert_eq!(r.pades_level, None);
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.digest_algorithm.as_deref(), Some("sha256"));

    // SHA-1: the signature verifies, but it is weak and never trusted.
    let r = &get("openssl-rsa2048-sha1.pdf")[0];
    assert!(r.intact && r.signature_valid);
    assert!(r.has_problem(ProblemCode::WeakAlgorithm), "{}", summary(r));
    assert!(!r.is_valid());
    assert_eq!(r.digest_algorithm.as_deref(), Some("sha1"));

    // A document timestamp is listed with its TSA, not verified.
    let reports = get("pyhanko-doc-timestamp.pdf");
    let ts = &reports[1];
    assert_eq!(ts.kind, SignatureKind::DocTimeStamp);
    assert_eq!(ts.sub_filter.as_deref(), Some("ETSI.RFC3161"));
    assert!(ts.intact && ts.byte_range_ok);
    assert!(ts.has_problem(ProblemCode::PendingTimestampVerification));
    assert!(ts.signer.is_some(), "the TSA certificate");

    // An unsigned field is not a signature.
    assert!(get("pyhanko-empty-field.pdf").is_empty());

    // Certification: P from /Reference (or /Perms), docmdpOk until M4 is None.
    for (file, p) in [
        ("pyhanko-certified-p1.pdf", 1),
        ("pyhanko-certified-p2.pdf", 2),
    ] {
        let r = &get(file)[0];
        assert_eq!(r.docmdp, Some(p), "{file}");
        assert_eq!(r.docmdp_ok, Option::None);
    }

    // pyHanko's second signature changes the catalog's /Version, /Extensions and adds an XMP
    // /Metadata stream: form filling for the first signature, as pyHanko says.
    let reports = get("pyhanko-two-signatures.pdf");
    assert_eq!(reports[0].modification, ModificationLevel::FormFilling);
    assert!(
        !reports[0]
            .warnings
            .iter()
            .any(|w| w.contains("modified after signing")),
        "{:?}",
        reports[0].warnings
    );
}

#[test]
fn interop_differences_name_real_rows() {
    for (file, field, key, ours, pyhanko, reason) in DIFFERENCES {
        assert!(
            PYHANKO.iter().any(|p| p.file == *file && p.field == *field),
            "{file} {field}"
        );
        assert!(["valid", "trusted"].contains(key), "{key}");
        assert_ne!(ours, pyhanko);
        assert!(!reason.is_empty());
    }
}

/// The `sign-interop` oracle suite: every fixture with a signature, expectations from our
/// report.
#[test]
fn oracle_sign_interop() {
    let mut written = 0;
    let mut cases = 0;
    for (file, pdf) in interop_fixtures() {
        let reports = verify(&pdf);
        if reports.is_empty() {
            continue; // pyhanko-empty-field.pdf: nothing to validate
        }
        let doc = open(&pdf);
        let expect = ExpectJson::new()
            .raw(
                "trustRoots",
                format!("[{}]", folioxide_testkit::emit::json_string(TRUST_ROOT)),
            )
            .int("pages", doc.page_count().unwrap() as i64)
            .int("revisions", startxref_count(&pdf))
            .raw("signatures", signatures(&reports, true));
        let name = file.trim_end_matches(".pdf");
        cases += 1;
        if emit_case("sign-interop", name, &pdf, &expect)
            .unwrap()
            .is_some()
        {
            written += 1;
        }
    }
    assert!(cases >= 10, "{cases} cases");
    assert_eq!(written, if EMIT_ENABLED { cases } else { 0 });
}

//! Interoperability of the crypto side with signed PDFs from other signers (M3 WP3.2B): the CMS
//! in every signature of `fixtures/sign/pdf/` (signed by pyHanko 0.37.0, or by `openssl cms
//! -sign` over byte ranges pyHanko prepared) parses, verifies over its `/ByteRange`, and its
//! signer chains to the test root with `build_trust`. `tools/fixtures/sign.py --check` asserts
//! that pyHanko, pdfsig and OpenSSL accept the same files.
//!
//! The ByteRange is read with a byte scan, not with the PDF verifier (that is the PDF side's
//! `verify_pyhanko_fixture_agrees`): this test isolates the CMS and trust code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod cms_support;

use cms_support::{cert_der, fixture};
use folioxide_model::PdfDate;
use folioxide_sign::ProblemCode;
use folioxide_sign::algorithms::{DigestAlgorithm, oid};
use folioxide_sign::cms::{self, CmsVerification};
use folioxide_sign::x509info::{self, UnixTime, build_trust};

/// One signature of a PDF: its ByteRange, the CMS from the gap (zero padding included) and the
/// signed bytes.
struct Embedded {
    byte_range: [usize; 4],
    contents: Vec<u8>,
    signed: Vec<u8>,
}

/// Every `/ByteRange [a b c d]` in the file, with its gap decoded from hex.
fn signatures(pdf: &[u8]) -> Vec<Embedded> {
    let mut out = Vec::new();
    let key = b"/ByteRange";
    let mut from = 0;
    while let Some(pos) = pdf[from..].windows(key.len()).position(|w| w == key) {
        let start = from + pos + key.len();
        from = start;
        let rest = &pdf[start..];
        let open = rest.iter().position(|&b| b == b'[').unwrap();
        let close = rest.iter().position(|&b| b == b']').unwrap();
        let numbers: Vec<usize> = std::str::from_utf8(&rest[open + 1..close])
            .unwrap()
            .split_ascii_whitespace()
            .map(|n| n.parse().unwrap())
            .collect();
        let [a, b, c, d] = numbers.as_slice() else {
            panic!("ByteRange {numbers:?}");
        };
        let gap = &pdf[a + b..*c];
        assert_eq!((gap[0], gap[gap.len() - 1]), (b'<', b'>'));
        let hex = &gap[1..gap.len() - 1];
        let contents = hex
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let mut signed = pdf[*a..a + b].to_vec();
        signed.extend_from_slice(&pdf[*c..c + d]);
        out.push(Embedded {
            byte_range: [*a, *b, *c, *d],
            contents,
            signed,
        });
    }
    out.sort_by_key(|s| s.byte_range[2] + s.byte_range[3]);
    out
}

/// Parses and verifies one embedded CMS over its signed bytes.
fn verify(sig: &Embedded) -> (cms::ParsedCms, CmsVerification) {
    let parsed = cms::parse(&sig.contents).unwrap();
    assert!(
        sig.contents[parsed.raw.end..].iter().all(|&b| b == 0),
        "non-zero padding"
    );
    let signed = sig.signed.clone();
    let verification = cms::verify_detached(&parsed, &|d| Some(d.digest(&[&signed])), &[]);
    (parsed, verification)
}

fn now() -> UnixTime {
    UnixTime::from_pdf_date(&PdfDate::parse(b"D:20261010120000Z").unwrap())
}

/// The expectations for one signature of a fixture.
struct Expected {
    digest: DigestAlgorithm,
    signature_algorithm: &'static str,
    /// Signed by pyHanko as PAdES: B-B attributes (ESS v2, no signing time).
    pades: bool,
    /// The SHA-1 legacy case.
    weak: bool,
}

const fn expected(
    digest: DigestAlgorithm,
    signature_algorithm: &'static str,
    pades: bool,
) -> Expected {
    Expected {
        digest,
        signature_algorithm,
        pades,
        weak: false,
    }
}

#[test]
fn cms_of_signed_pdfs_verifies_and_chains() {
    use DigestAlgorithm::{Sha1, Sha256, Sha384};
    let cases: [(&str, Vec<Expected>); 9] = [
        (
            "pyhanko-rsa2048.pdf",
            vec![expected(Sha256, "sha256WithRSAEncryption", true)],
        ),
        (
            "pyhanko-p256.pdf",
            vec![expected(Sha256, "ecdsa-with-SHA256", true)],
        ),
        (
            "pyhanko-two-signatures.pdf",
            vec![
                expected(Sha256, "sha256WithRSAEncryption", true),
                expected(Sha384, "ecdsa-with-SHA384", true),
            ],
        ),
        (
            "pyhanko-pkcs7-rsa3072.pdf",
            vec![expected(Sha256, "sha256WithRSAEncryption", false)],
        ),
        (
            "pyhanko-certified-p1.pdf",
            vec![expected(Sha256, "ecdsa-with-SHA256", true)],
        ),
        (
            "pyhanko-certified-p2.pdf",
            vec![expected(Sha256, "sha256WithRSAEncryption", true)],
        ),
        (
            "openssl-rsa2048.pdf",
            vec![expected(Sha256, "sha256WithRSAEncryption", false)],
        ),
        (
            "openssl-p256-cades.pdf",
            vec![expected(Sha256, "ecdsa-with-SHA256", false)],
        ),
        (
            "openssl-rsa2048-sha1.pdf",
            vec![Expected {
                weak: true,
                ..expected(Sha1, "sha1WithRSAEncryption", false)
            }],
        ),
    ];
    let root = cert_der("pki/root.pem");
    for (name, wanted) in cases {
        let pdf = fixture(&format!("sign/pdf/{name}"));
        let found = signatures(&pdf);
        assert_eq!(found.len(), wanted.len(), "{name}");
        for (index, (sig, want)) in found.iter().zip(&wanted).enumerate() {
            let label = format!("{name} #{index}");
            let (parsed, v) = verify(sig);
            assert!(v.intact, "{label}: {:?}", v.problems);
            assert!(v.signature_valid, "{label}: {:?}", v.problems);
            assert_eq!(v.digest, Some(want.digest), "{label}");
            assert_eq!(
                v.signature_algorithm.as_deref(),
                Some(want.signature_algorithm),
                "{label}"
            );
            let weak: Vec<_> = v
                .problems
                .iter()
                .filter(|p| p.code == ProblemCode::WeakAlgorithm)
                .collect();
            assert_eq!(
                weak.len(),
                usize::from(want.weak),
                "{label}: {:?}",
                v.problems
            );
            if !want.weak {
                assert!(v.problems.is_empty(), "{label}: {:?}", v.problems);
            }
            assert_eq!(v.pades_attrs.is_baseline_b(), want.pades, "{label}");
            assert_eq!(
                v.pades_attrs.content_type.as_deref(),
                Some(oid::ID_DATA),
                "{label}"
            );
            if want.pades {
                assert_eq!(v.pades_attrs.signing_certificate_v2, Some(true));
                assert!(v.pades_attrs.signing_time.is_none());
            }

            // The signer chains to the test root through the CMS certificates.
            let signer = v.signer_cert.clone().unwrap();
            let trust = build_trust(
                &signer,
                &parsed.certificates,
                std::slice::from_ref(&root),
                now(),
            );
            assert!(trust.trusted, "{label}: {:?}", trust.reasons);
            assert_eq!(trust.path.len(), 3, "{label}");
            let info = x509info::certificate_info(&signer).unwrap();
            assert!(
                info.subject.starts_with("CN=Folioxide Test Signer"),
                "{label}: {}",
                info.subject
            );
        }
    }
}

#[test]
fn doc_timestamp_token_is_not_a_detached_signature() {
    // pyhanko-doc-timestamp.pdf: Signature1 (P-256, PAdES) then DocTimeStamp1 (RFC 3161 token
    // from pki/tsa). The token is a SignedData over TSTInfo with eContent, so the detached
    // route reports it (the PDF side lists it as a DocTimeStamp, brief §5 V1).
    let pdf = fixture("sign/pdf/pyhanko-doc-timestamp.pdf");
    let found = signatures(&pdf);
    assert_eq!(found.len(), 2);
    let (_, signature) = verify(&found[0]);
    assert!(signature.intact && signature.signature_valid);
    // The signature covers its revision only; the timestamp covers the whole file.
    assert!(found[0].byte_range[2] + found[0].byte_range[3] < pdf.len());
    assert_eq!(found[1].byte_range[2] + found[1].byte_range[3], pdf.len());

    let (token, verification) = verify(&found[1]);
    assert_eq!(
        token.econtent_type.as_deref(),
        Some("1.2.840.113549.1.9.16.1.4")
    );
    assert!(token.econtent.is_some());
    assert!(!verification.signature_valid);
    assert!(
        verification
            .problems
            .iter()
            .any(|p| p.code == ProblemCode::EContentPresent),
        "{:?}",
        verification.problems
    );
    // The TSA certificate chains to the root.
    let tsa = verification.signer_cert.clone().unwrap();
    let trust = build_trust(
        &tsa,
        &token.certificates,
        &[cert_der("pki/root.pem")],
        now(),
    );
    assert!(trust.trusted, "{:?}", trust.reasons);
}

#[test]
fn signed_pdfs_extend_their_inputs() {
    // Every fixture is an incremental update of minimal.pdf (or of another fixture).
    let minimal = fixture("syntax/minimal.pdf");
    for name in [
        "pyhanko-rsa2048.pdf",
        "pyhanko-p256.pdf",
        "pyhanko-pkcs7-rsa3072.pdf",
        "pyhanko-certified-p1.pdf",
        "pyhanko-certified-p2.pdf",
        "pyhanko-empty-field.pdf",
        "openssl-rsa2048.pdf",
        "openssl-p256-cades.pdf",
        "openssl-rsa2048-sha1.pdf",
    ] {
        let pdf = fixture(&format!("sign/pdf/{name}"));
        assert!(pdf.starts_with(&minimal), "{name}");
    }
    let one = fixture("sign/pdf/pyhanko-rsa2048.pdf");
    assert!(fixture("sign/pdf/pyhanko-two-signatures.pdf").starts_with(&one));
    let p256 = fixture("sign/pdf/pyhanko-p256.pdf");
    assert!(fixture("sign/pdf/pyhanko-doc-timestamp.pdf").starts_with(&p256));
    assert!(signatures(&fixture("sign/pdf/pyhanko-empty-field.pdf")).is_empty());
}

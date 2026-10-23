#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Document timestamps (`/Type /DocTimeStamp`, `/SubFilter /ETSI.RFC3161`; ISO 32000-2 §12.8.5;
//! M4 brief §5 V7c): the token in `/Contents` is verified over the signed byte ranges, and its
//! problems are the report's. These replace M3's `verify_doc_timestamp_listed`.

mod bt_support;

use bt_support::*;
use folioxide_sign::ProblemCode;
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::report::{PadesLevel, SignatureKind, SignatureReport};
use folioxide_sign::tsp::{MessageImprint, TimeStampReq};
use folioxide_sign::verify_pdf::VerifyOptions;

/// The document timestamp report of a file.
fn doc_timestamp(reports: &[SignatureReport]) -> &SignatureReport {
    reports
        .iter()
        .find(|r| r.kind == SignatureKind::DocTimeStamp)
        .expect("a document timestamp")
}

#[test]
fn verify_doc_timestamp_pyhanko_fixture() {
    let pdf = pdf_fixture("pyhanko-doc-timestamp.pdf");
    let reports = verify(&pdf);
    assert_eq!(reports.len(), 2);
    let ts = doc_timestamp(&reports);
    assert_eq!(ts.field_name.as_deref(), Some("DocTimeStamp1"));
    assert_eq!(ts.sub_filter.as_deref(), Some("ETSI.RFC3161"));
    assert!(ts.intact && ts.signature_valid, "{}", summary(ts));
    assert!(ts.is_valid(), "{}", summary(ts));
    assert_eq!(ts.trusted, Some(true), "{}", summary(ts));
    assert!(ts.problems.is_empty(), "{}", summary(ts));
    assert!(!ts.has_problem(ProblemCode::PendingTimestampVerification));
    assert_eq!(ts.pades_level, None);
    // Manager ruling R-5 (QA finding 33): a document timestamp has no DocMDP of its own, so no
    // docmdp_ok (pyHanko's DocumentTimestampStatus leaves it None), and None never refuses it.
    assert_eq!(ts.docmdp, None);
    assert_eq!(ts.docmdp_ok, None);
    assert!(ts.is_acceptable(folioxide_sign::report::ModificationLevel::None));
    // Its own token: claimed_time = genTime (DummyTimeStamper: microsecond fractions).
    let info = ts.timestamp.as_ref().unwrap();
    assert_eq!(ts.timestamps, std::slice::from_ref(info));
    assert_eq!(ts.claimed_time.as_deref(), Some(info.gen_time.as_str()));
    assert!(info.gen_time.contains('.'), "{}", info.gen_time);
    assert!(info.intact && info.valid && info.trusted == Some(true));
    assert_eq!(
        ts.signer.as_ref().and_then(|c| c.common_name.as_deref()),
        Some("Folioxide Test TSA")
    );
    assert_eq!(ts.digest_algorithm.as_deref(), Some("sha256"));
    assert!(!ts.chain.is_empty(), "the token's certificates");
    // The signature before it is B-B: B-T through a later document timestamp is M11 (D-20).
    let signature = reports
        .iter()
        .find(|r| r.kind == SignatureKind::Signature)
        .unwrap();
    assert_eq!(signature.pades_level, Some(PadesLevel::BB));
    assert!(signature.timestamp.is_none() && signature.timestamps.is_empty());

    // Without anchors: valid, no trust verdict.
    let reports = verify_with(&pdf, &VerifyOptions::new());
    let ts = doc_timestamp(&reports);
    assert!(ts.is_valid() && ts.trusted.is_none(), "{}", summary(ts));

    // The P=1 certified document timestamped by pyHanko (fixture for the `certify` suite).
    let reports = verify(&pdf_fixture("pyhanko-certified-p1-dts.pdf"));
    let ts = doc_timestamp(&reports);
    assert!(ts.is_valid() && ts.trusted == Some(true), "{}", summary(ts));
    assert_eq!(ts.docmdp_ok, None, "R-5");
    // The certification before it keeps its verdict: the timestamp is allowed under P = 1.
    let certification = reports
        .iter()
        .find(|r| r.kind == SignatureKind::Signature)
        .unwrap();
    assert_eq!(certification.docmdp, Some(1));
    assert_eq!(
        certification.docmdp_ok,
        Some(true),
        "{}",
        summary(certification)
    );
}

/// `pdf` with `token` written over the document timestamp's `/Contents`, in place.
fn replace_doc_timestamp_token(pdf: &[u8], report: &SignatureReport, token: &[u8]) -> Vec<u8> {
    let br = report.byte_range.as_deref().unwrap();
    let gap = (br[0] + br[1]) as usize..br[2] as usize;
    let room = gap.end - gap.start - 2;
    let digits = hex(token).into_bytes();
    assert!(digits.len() <= room, "{} > {room}", digits.len());
    let mut out = pdf.to_vec();
    out[gap.start + 1..gap.end - 1]
        .copy_from_slice(&[digits.as_slice(), &vec![b'0'; room - digits.len()]].concat());
    out
}

#[test]
fn verify_doc_timestamp_imprint_mismatch() {
    let pdf = pdf_fixture("pyhanko-doc-timestamp.pdf");
    let reports = verify(&pdf);
    let report = doc_timestamp(&reports).clone();
    // A sound token of the mock TSA, but over other bytes than the byte ranges.
    let digest = DigestAlgorithm::Sha256;
    let request = TimeStampReq::new(
        MessageImprint::new(digest, digest.digest(&[b"other bytes"])),
        Some(NONCE),
        None,
    );
    let token = mock_tsa().token_for(&request.to_der()).unwrap();
    let forged = replace_doc_timestamp_token(&pdf, &report, &token);
    let reports = verify(&forged);
    let ts = doc_timestamp(&reports);
    assert!(!ts.intact, "{}", summary(ts));
    assert!(
        ts.signature_valid,
        "the token itself is sound: {}",
        summary(ts)
    );
    assert!(ts.has_problem(ProblemCode::TimestampImprintMismatch));
    assert!(!ts.is_valid());
    assert_eq!(
        ts.trusted,
        Some(false),
        "a changed document is never trusted"
    );
    let info = ts.timestamp.as_ref().unwrap();
    assert!(!info.intact && info.valid);

    // The same token over the right bytes is accepted: the forgery is only in the imprint.
    let ranges = report.byte_range.as_deref().unwrap();
    let signed = [
        &pdf[ranges[0] as usize..(ranges[0] + ranges[1]) as usize],
        &pdf[ranges[2] as usize..(ranges[2] + ranges[3]) as usize],
    ]
    .concat();
    let request = TimeStampReq::new(
        MessageImprint::new(digest, digest.digest(&[&signed])),
        Some(NONCE),
        None,
    );
    let token = mock_tsa().token_for(&request.to_der()).unwrap();
    let replaced = replace_doc_timestamp_token(&pdf, &report, &token);
    let reports = verify(&replaced);
    let ts = doc_timestamp(&reports);
    assert!(ts.is_valid() && ts.trusted == Some(true), "{}", summary(ts));
    assert_eq!(ts.claimed_time.as_deref(), Some("2026-10-10T12:00:30Z"));
}

#[test]
fn verify_doc_timestamp_with_unsuitable_tsa_or_sub_filter() {
    let pdf = pdf_fixture("pyhanko-doc-timestamp.pdf");
    let reports = verify(&pdf);
    let report = doc_timestamp(&reports).clone();
    let ranges = report.byte_range.as_deref().unwrap();
    let signed = [
        &pdf[ranges[0] as usize..(ranges[0] + ranges[1]) as usize],
        &pdf[ranges[2] as usize..(ranges[2] + ranges[3]) as usize],
    ]
    .concat();
    let digest = DigestAlgorithm::Sha256;
    let request = TimeStampReq::new(
        MessageImprint::new(digest, digest.digest(&[&signed])),
        Some(NONCE),
        None,
    );
    // A TSA certificate whose EKU is not critical: the token is not valid (D-4). The root is
    // left out of the token, so it fits pyHanko's placeholder.
    let key = tsa_key("tsa-eku-noncritical.pem");
    let token = folioxide_testkit::tsa::MockTsa::new(
        cert("tsa-eku-noncritical.pem"),
        Vec::new(),
        Box::new(move |attrs| {
            use folioxide_sign::signer::Signer;
            key.sign(DigestAlgorithm::Sha256, attrs).unwrap()
        }),
    )
    .token_for(&request.to_der())
    .unwrap();
    let reports = verify(&replace_doc_timestamp_token(&pdf, &report, &token));
    let ts = doc_timestamp(&reports);
    assert!(ts.intact && !ts.signature_valid, "{}", summary(ts));
    assert!(ts.has_problem(ProblemCode::TsaCertificateUnsuitable));
    assert_eq!(ts.trusted, Some(false));

    // A document timestamp with another /SubFilter (same length, so offsets stay): refused.
    let from = b"/ETSI.RFC3161";
    let at = pdf
        .windows(from.len())
        .rposition(|w| w == from)
        .expect("the SubFilter");
    let mut relabelled = pdf.clone();
    relabelled[at..at + from.len()].copy_from_slice(b"/ETSI.RFC3162");
    let reports = verify(&relabelled);
    let ts = doc_timestamp(&reports);
    assert!(
        ts.has_problem(ProblemCode::UnsupportedSubFilter),
        "{}",
        summary(ts)
    );
    assert!(!ts.signature_valid && !ts.is_valid());
}

#[test]
fn verify_doc_timestamp_ess_second_cert_id_decoy() {
    // QA round 2 finding 3 on a document timestamp: a later ESS identifier that names an
    // attacker root carrying the real root's name (in the token) is not on the chain, as
    // OpenSSL finds (`ess cert id not found`); pyHanko reads only the first identifier.
    use bt_support::decoys::decoys;
    use folioxide_sign::signer::Signer;
    use folioxide_testkit::tsa::{Ess, MockTsa, MockTsaOptions};

    let pdf = pdf_fixture("pyhanko-doc-timestamp.pdf");
    let reports = verify(&pdf);
    let report = doc_timestamp(&reports).clone();
    let ranges = report.byte_range.as_deref().unwrap();
    let signed = [
        &pdf[ranges[0] as usize..(ranges[0] + ranges[1]) as usize],
        &pdf[ranges[2] as usize..(ranges[2] + ranges[3]) as usize],
    ]
    .concat();
    let digest = DigestAlgorithm::Sha256;
    let request = TimeStampReq::new(
        MessageImprint::new(digest, digest.digest(&[&signed])),
        Some(NONCE),
        None,
    );
    let tsa = cert("tsa.pem");
    let token = |extra: Vec<Vec<u8>>, ids: Vec<Vec<u8>>| {
        let key = tsa_key("tsa.pem");
        MockTsa::new(
            tsa.clone(),
            extra,
            Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
        )
        .with_options(MockTsaOptions {
            ess: Ess::V2,
            ess_cert_ids: Some(ids),
            ..MockTsaOptions::default()
        })
        .token_for(&request.to_der())
        .unwrap()
    };
    let fake_root = decoys().fake_root.clone();
    let forged = token(vec![fake_root.clone()], vec![tsa.clone(), fake_root]);
    let reports = verify(&replace_doc_timestamp_token(&pdf, &report, &forged));
    let ts = doc_timestamp(&reports);
    assert!(ts.intact && !ts.signature_valid, "{}", summary(ts));
    assert!(ts.has_problem(ProblemCode::TimestampEssMismatch));
    assert_eq!(ts.trusted, Some(false));
    assert!(!ts.is_valid());

    // The control: the real root, which the trust anchors hold (the token does not carry it).
    let honest = token(Vec::new(), vec![tsa.clone(), cert("root.pem")]);
    let reports = verify(&replace_doc_timestamp_token(&pdf, &report, &honest));
    let ts = doc_timestamp(&reports);
    assert!(ts.is_valid() && ts.trusted == Some(true), "{}", summary(ts));
}

#[test]
fn verify_doc_timestamp_token_decoders() {
    // QA round 3 findings 2–4 and round 4 findings 1 and 2 on the document timestamp path
    // (variants r3-dts-*, r5-dts-*): the same whitelist as for signature timestamps, so a token
    // OpenSSL's decoders refuse is malformed.
    use bt_support::tokens;
    use folioxide_sign::signer::Signer;
    use folioxide_testkit::tsa::MockTsaOptions;
    let pdf = pdf_fixture("pyhanko-doc-timestamp.pdf");
    let reports = verify(&pdf);
    let report = doc_timestamp(&reports).clone();
    let ranges = report.byte_range.as_deref().unwrap();
    let signed = [
        &pdf[ranges[0] as usize..(ranges[0] + ranges[1]) as usize],
        &pdf[ranges[2] as usize..(ranges[2] + ranges[3]) as usize],
    ]
    .concat();
    let digest = DigestAlgorithm::Sha256;
    let request = TimeStampReq::new(
        MessageImprint::new(digest, digest.digest(&[&signed])),
        Some(NONCE),
        None,
    );
    let issuer = bt_support::decoys::issuer_of(&cert("tsa.pem"));
    let subject = bt_support::decoys::subject_of(&cert("tsa.pem"));
    for (name, tsa_cert, options, why) in [
        (
            "r3-dts-attr-unknown-two-values-unsorted",
            MockTsaOptions {
                extra_signed_attributes: vec![tokens::unsorted_attribute(
                    &tokens::test_oid(99),
                    &[tokens::octets(b"a"), tokens::octets(b"b")],
                )],
                ..MockTsaOptions::default()
            },
            "signed attributes are not DER",
        ),
        (
            "r3-dts-ess-policies-junk",
            MockTsaOptions {
                ess_policies: Some(tokens::seq(&[tokens::seq(&[tokens::int(1)])])),
                ..MockTsaOptions::default()
            },
            "a policies entry is not a PolicyInformation",
        ),
        (
            "r3-dts-ess-issuer-visiblestring",
            MockTsaOptions {
                ess_issuer_name: Some(bt_support::decoys::reencode_name(&issuer, 0x1A, false)),
                ..MockTsaOptions::default()
            },
            "does not decode as a name",
        ),
        (
            "r3-dts-tstinfo-extensions-junk",
            MockTsaOptions {
                tst_extensions: Some(tokens::tst_extensions(&[tokens::der(0xA4, &subject)])),
                ..MockTsaOptions::default()
            },
            "not an Extension",
        ),
        // QA round 4 findings 1 and 2 (variants r5-dts-crl-bmp-surrogate, r5-dts-gn-unknown-ctx9,
        // r5-dts-gn-universal-null; r5-dts-bmp-surrogate-subject is below).
        (
            "r5-dts-crl-bmp-surrogate",
            MockTsaOptions {
                crls: vec![bt_support::decoys::test_crl(
                    &bt_support::decoys::test_name(bt_support::decoys::bmp(&[0x54, 0xD800])),
                )],
                ..MockTsaOptions::default()
            },
            "BMPString with a UTF-16 surrogate",
        ),
        (
            "r5-dts-gn-unknown-ctx9",
            MockTsaOptions {
                tsa_general_name: Some(tokens::der(0x89, b"tsa")),
                ..MockTsaOptions::default()
            },
            "tsa is a GeneralName that does not decode",
        ),
        (
            "r5-dts-gn-universal-null",
            MockTsaOptions {
                tsa_general_name: Some(vec![0x05, 0x00]),
                ..MockTsaOptions::default()
            },
            "tsa is a GeneralName that does not decode",
        ),
    ]
    .into_iter()
    .map(|(name, options, why)| (name, cert("tsa.pem"), options, why))
    .chain([(
        "r5-dts-bmp-surrogate-subject",
        bt_support::decoys::tsa_cert_with(
            0x0A5E_0D75,
            &bt_support::decoys::test_name(bt_support::decoys::bmp(&[0x54, 0xD800])),
            &[],
        ),
        MockTsaOptions::default(),
        "BMPString with a UTF-16 surrogate",
    )]) {
        // The TSA certificate alone (the anchors hold the root), so the token fits the
        // fixture's /Contents.
        let key = tsa_key("tsa.pem");
        let token = folioxide_testkit::tsa::MockTsa::new(
            tsa_cert,
            Vec::new(),
            Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
        )
        .with_options(options)
        .token_for(&request.to_der())
        .unwrap();
        let reports = verify(&replace_doc_timestamp_token(&pdf, &report, &token));
        let ts = doc_timestamp(&reports);
        assert!(
            !ts.signature_valid && !ts.is_valid(),
            "{name}: {}",
            summary(ts)
        );
        assert_eq!(ts.trusted, Some(false), "{name}");
        let malformed = ts
            .problems
            .iter()
            .find(|p| p.code == ProblemCode::TimestampMalformed)
            .unwrap_or_else(|| panic!("{name}: {}", summary(ts)));
        assert!(malformed.message.contains(why), "{name}: {malformed:?}");
    }
    // The control: the same bare token, unbent, is a sound document timestamp.
    let key = tsa_key("tsa.pem");
    let honest = folioxide_testkit::tsa::MockTsa::new(
        cert("tsa.pem"),
        Vec::new(),
        Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
    )
    .token_for(&request.to_der())
    .unwrap();
    let reports = verify(&replace_doc_timestamp_token(&pdf, &report, &honest));
    let ts = doc_timestamp(&reports);
    assert!(ts.is_valid() && ts.trusted == Some(true), "{}", summary(ts));
}

#[test]
fn verify_doc_timestamp_r22_certificate_rules() {
    // Manager ruling R-22 on the document timestamp path (QA round 5 variants
    // r6-dts-akid-keyid-wrong, r7-dts-spki-pss-no-params, r7-dts-spki-pss-sha256-params, and
    // the TSA certificate extension defects): (a) an authorityKeyIdentifier that does not
    // describe the root leaves the token valid but untrusted; (b) a PKCS #1 v1.5 token by a key
    // restricted to RSASSA-PSS is not valid; (c) a duplicated extension makes the TSA
    // certificate unsuitable.
    use bt_support::decoys::{
        der, extension, issue, pss_spki, signer, ski_of, spki_of, subject_of, tsa_cert_with,
        tsa_extensions,
    };
    use folioxide_sign::signer::Signer as _;
    use folioxide_testkit::tsa::MockTsa;

    let pdf = pdf_fixture("pyhanko-doc-timestamp.pdf");
    let reports = verify(&pdf);
    let report = doc_timestamp(&reports).clone();
    let ranges = report.byte_range.as_deref().unwrap();
    let signed = [
        &pdf[ranges[0] as usize..(ranges[0] + ranges[1]) as usize],
        &pdf[ranges[2] as usize..(ranges[2] + ranges[3]) as usize],
    ]
    .concat();
    let digest = DigestAlgorithm::Sha256;
    let request = TimeStampReq::new(
        MessageImprint::new(digest, digest.digest(&[&signed])),
        Some(NONCE),
        None,
    );
    // The root is left out of the tokens, so they fit pyHanko's placeholder.
    let token_of = |tsa_cert: Vec<u8>| {
        let key = tsa_key("tsa.pem");
        MockTsa::new(
            tsa_cert,
            Vec::new(),
            Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
        )
        .token_for(&request.to_der())
        .unwrap()
    };
    let root = cert("root.pem");
    let tsa = cert("tsa.pem");
    let akid =
        |key_id: &[u8]| extension(&[0x55, 0x1D, 0x23], false, &der(0x30, &der(0x80, key_id)));

    // (a) The control names the root's key identifier; the variant another one.
    for (serial, key_id, trusted) in [
        (0x4A00, ski_of(&root).unwrap(), true),
        (0x4A01, vec![0xAA; 20], false),
    ] {
        let tsa_cert = tsa_cert_with(serial, &subject_of(&tsa), &[akid(&key_id)]);
        let reports = verify(&replace_doc_timestamp_token(
            &pdf,
            &report,
            &token_of(tsa_cert),
        ));
        let ts = doc_timestamp(&reports);
        assert!(ts.is_valid(), "{serial:x}: {}", summary(ts));
        assert_eq!(ts.trusted, Some(trusted), "{serial:x}: {}", summary(ts));
    }

    // (b) A PSS-only TSA key, with and without parameters, and a PKCS #1 v1.5 token.
    let pss_params = {
        let algorithm = rsassa_pss_sha256();
        bt_support::decoys::children(bt_support::decoys::content(&algorithm))[1].to_vec()
    };
    for (serial, parameters) in [(0x4A10, None), (0x4A11, Some(pss_params))] {
        let tsa_cert = issue(
            serial,
            &subject_of(&root),
            &subject_of(&tsa),
            &pss_spki(&spki_of(&tsa), parameters.as_deref()),
            &tsa_extensions(),
            &signer("root.key.pem", "root.pem"),
        );
        let reports = verify(&replace_doc_timestamp_token(
            &pdf,
            &report,
            &token_of(tsa_cert),
        ));
        let ts = doc_timestamp(&reports);
        assert!(
            ts.intact && !ts.signature_valid,
            "{serial:x}: {}",
            summary(ts)
        );
        assert!(
            ts.has_problem(ProblemCode::TimestampSignatureInvalid),
            "{serial:x}: {}",
            summary(ts)
        );
        assert_eq!(ts.trusted, Some(false));
    }

    // (c) Two subjectKeyIdentifier extensions; and an nsCertType that is a NULL (final fix
    // round 2, finding 1, variant r8-dts-ext-2_16_840_1_113730_1_1-junk-null: OpenSSL "invalid
    // certificate"), which OpenSSL decodes and Folioxide had not.
    let ski = extension(&[0x55, 0x1D, 0x0E], false, &der(0x04, &[1, 2, 3, 4]));
    let ns_cert_type = extension(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x01],
        false,
        &[0x05, 0x00],
    );
    // M4 closing round, findings 8 and 11: a critical subjectKeyIdentifier or
    // authorityKeyIdentifier, which OpenSSL does not handle (unhandled critical extension).
    let critical_ski = extension(&[0x55, 0x1D, 0x0E], true, &der(0x04, &[1, 2, 3, 4]));
    let critical_aki = extension(
        &[0x55, 0x1D, 0x23],
        true,
        &der(0x30, &der(0x80, &ski_of(&root).unwrap())),
    );
    for (serial, extensions) in [
        (0x4A20, vec![ski.clone(), ski]),
        (0x4A21, vec![ns_cert_type]),
        (0x4A22, vec![critical_ski]),
        (0x4A23, vec![critical_aki]),
    ] {
        let tsa_cert = tsa_cert_with(serial, &subject_of(&tsa), &extensions);
        let reports = verify(&replace_doc_timestamp_token(
            &pdf,
            &report,
            &token_of(tsa_cert),
        ));
        let ts = doc_timestamp(&reports);
        assert!(
            ts.intact && !ts.signature_valid,
            "{serial:x}: {}",
            summary(ts)
        );
        assert!(
            ts.has_problem(ProblemCode::TsaCertificateUnsuitable),
            "{serial:x}: {}",
            summary(ts)
        );
        assert_eq!(ts.trusted, Some(false));
    }
}

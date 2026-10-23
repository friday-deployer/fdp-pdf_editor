#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Verifying signature timestamps (M4 brief §5 V7b, V8, V9; §5.4 "Timestamps"; §6.2
//! "Verification"): the report's timestamp fields, every timestamp attack of the corpus, token
//! selection, and the signer's trust time.
//!
//! The attack files are made below Folioxide's own `finish` (which refuses every one of these
//! tokens): the CMS is assembled with [`cms::assemble_with_timestamp`] (or by hand for several
//! tokens) and written into the prepared `/Contents` unchecked.

mod bt_support;

use bt_support::*;
use folioxide_sign::ProblemCode;
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::bt::TimestampParams;
use folioxide_sign::cms;
use folioxide_sign::prepare::{PrepareRequest, PreparedSignature, SignatureOptions, prepare};
use folioxide_sign::report::{PadesLevel, SignatureReport, TimestampInfo};
use folioxide_sign::signer::{LocalSigner, Signer};
use folioxide_sign::tsp::{DEFAULT_TSA_RESERVE, MAX_TIMESTAMP_TOKENS};
use folioxide_sign::verify_pdf::VerifyOptions;
use folioxide_testkit::tsa::{Echo, Ess, MockTsa, MockTsaOptions};

/// What a B-T attack file is made of: the prepared signature, the signer's value and the
/// request the honest flow would send.
struct Parts {
    prepared: PreparedSignature,
    value: Vec<u8>,
    request: Vec<u8>,
}

fn parts(signer: &LocalSigner, time: folioxide_model::PdfDate) -> Parts {
    parts_with_reserve(signer, time, 2 * DEFAULT_TSA_RESERVE)
}

/// [`parts`] with `tsa_reserve` bytes of token budget.
fn parts_with_reserve(
    signer: &LocalSigner,
    time: folioxide_model::PdfDate,
    tsa_reserve: usize,
) -> Parts {
    let request = PrepareRequest::new(
        signer.certificate_chain().to_vec(),
        signer.algorithm(),
        time,
    )
    .with_options(SignatureOptions::new(time).with_tsa_reserve(Some(tsa_reserve)));
    let prepared = prepare(&open(&minimal()), &request).unwrap();
    let value = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let request = prepared
        .timestamp_request(&value, &TimestampParams::new().with_nonce(Some(NONCE)))
        .unwrap();
    Parts {
        prepared,
        value,
        request,
    }
}

/// The CMS of `parts` with `unsigned` (a whole `[1]` element) after the signature value.
fn cms_with_unsigned(parts: &Parts, signer: &LocalSigner, unsigned: Option<&[u8]>) -> Vec<u8> {
    let plain = cms::assemble(
        parts.prepared.to_be_signed(),
        &parts.value,
        signer.certificate_chain(),
        signer.algorithm(),
        signer.key_kind(),
        parts.prepared.digest_algorithm(),
    )
    .unwrap();
    match unsigned {
        Some(unsigned) => append_to_signer_info(&plain, unsigned),
        None => plain,
    }
}

/// A B-T file whose one token is `token` (unchecked).
fn with_token(parts: &Parts, signer: &LocalSigner, token: &[u8]) -> Vec<u8> {
    let cms = cms::assemble_with_timestamp(
        parts.prepared.to_be_signed(),
        &parts.value,
        signer.certificate_chain(),
        signer.algorithm(),
        signer.key_kind(),
        parts.prepared.digest_algorithm(),
        token,
    )
    .unwrap();
    embed_raw(&parts.prepared, &cms)
}

/// A B-T file by `signer` whose token `tsa` makes for the honest request.
fn attack(tsa: &MockTsa) -> Vec<u8> {
    let signer = rsa2048();
    let parts = parts(&signer, time());
    let token = tsa.token_for(&parts.request).unwrap();
    with_token(&parts, &signer, &token)
}

/// The one report of a one-signature file.
fn report(pdf: &[u8]) -> SignatureReport {
    let mut reports = verify(pdf);
    assert_eq!(reports.len(), 1);
    reports.remove(0)
}

fn token_codes(info: &TimestampInfo) -> Vec<ProblemCode> {
    info.problems.iter().map(|p| p.code).collect()
}

/// A file whose signature is sound but whose only timestamp has `codes`, `intact` and
/// `valid`: B-B, the problems in the timestamp only (D-6), never trusted.
fn assert_broken_timestamp(pdf: &[u8], intact: bool, valid: bool, codes: &[ProblemCode]) {
    let r = report(pdf);
    assert!(
        r.is_valid(),
        "the signature itself is sound: {}",
        summary(&r)
    );
    assert!(r.problems.is_empty(), "{}", summary(&r));
    assert_eq!(r.pades_level, Some(PadesLevel::BB), "{}", summary(&r));
    let ts = r.timestamp.as_ref().unwrap();
    assert_eq!((ts.intact, ts.valid), (intact, valid), "{ts:?}");
    assert_eq!(ts.trusted, Some(false), "{ts:?}");
    assert_eq!(token_codes(ts), codes, "{ts:?}");
    assert_eq!(r.timestamps.len(), 1);
}

/// The default mock with `options`.
fn mock(options: MockTsaOptions) -> MockTsa {
    mock_tsa_with("tsa.pem", options)
}

fn defaults() -> MockTsaOptions {
    MockTsaOptions::default()
}

// ---- DER surgery for the multi-token files ---------------------------------------------------

/// `(header length, content length)` of the definite-length DER element at the start of `d`.
fn header(d: &[u8]) -> (usize, usize) {
    if d[1] < 0x80 {
        (2, usize::from(d[1]))
    } else {
        let n = usize::from(d[1] & 0x7F);
        (
            2 + n,
            d[2..2 + n]
                .iter()
                .fold(0, |a, &b| (a << 8) | usize::from(b)),
        )
    }
}

fn content(d: &[u8]) -> &[u8] {
    let (h, l) = header(d);
    &d[h..h + l]
}

fn children(mut c: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while !c.is_empty() {
        let (h, l) = header(c);
        out.push(&c[..h + l]);
        c = &c[h + l..];
    }
    out
}

fn tlv(tag: u8, c: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match c.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(c);
    out
}

/// `cms` (our DER `ContentInfo`) with `extra` appended to its SignerInfo, every enclosing length
/// rewritten.
fn append_to_signer_info(cms: &[u8], extra: &[u8]) -> Vec<u8> {
    let ci = children(content(cms));
    let signed_data = children(content(ci[1]))[0];
    let fields = children(content(signed_data));
    let (last, rest) = fields.split_last().unwrap();
    let signer_info = children(content(last))[0];
    let new_si = tlv(0x30, &[content(signer_info), extra].concat());
    let new_sd = tlv(0x30, &[rest.concat(), tlv(0x31, &new_si)].concat());
    tlv(0x30, &[ci[0], &tlv(0xA0, &new_sd)].concat())
}

/// `unsignedAttrs [1]` with one `id-aa-signatureTimeStampToken` attribute holding `tokens`,
/// DER-sorted.
fn unsigned_tokens(tokens: &[Vec<u8>]) -> Vec<u8> {
    let oid = [
        0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
    ];
    let mut sorted: Vec<&Vec<u8>> = tokens.iter().collect();
    sorted.sort();
    let values: Vec<u8> = sorted.into_iter().flatten().copied().collect();
    tlv(
        0xA1,
        &tlv(0x30, &[oid.as_slice(), &tlv(0x31, &values)].concat()),
    )
}

// ---- report fields -------------------------------------------------------------------------

#[test]
fn verify_bt_reports_timestamp_fields() {
    let tsa = mock(MockTsaOptions {
        serial: 0x1234,
        tsa_name: true,
        signing_time_attr: true,
        accuracy_secs: Some(2),
        ..defaults()
    });
    let signed = sign_bt_with(
        &minimal(),
        &p256(),
        SignatureOptions::new(time()),
        &Tsa(tsa),
    )
    .unwrap();
    let r = report(&signed);
    assert!(r.is_valid() && r.trusted == Some(true), "{}", summary(&r));
    assert_eq!(r.pades_level, Some(PadesLevel::BT));
    let ts = r.timestamp.clone().unwrap();
    assert_eq!(r.timestamps, std::slice::from_ref(&ts));
    assert_eq!(ts.gen_time, "2026-10-10T12:00:30Z");
    assert_eq!(
        ts.tsa.as_ref().and_then(|c| c.common_name.as_deref()),
        Some("Folioxide Test TSA")
    );
    assert!(
        ts.tsa_name
            .as_deref()
            .is_some_and(|n| n.contains("CN=Folioxide Test TSA")),
        "{:?}",
        ts.tsa_name
    );
    assert_eq!(ts.policy.as_deref(), Some("1.2.3.4.1"));
    assert_eq!(ts.serial_hex.as_deref(), Some("1234"));
    assert_eq!(ts.accuracy_micros, Some(2_000_000));
    assert!(!ts.ordering);
    assert_eq!(ts.imprint_algorithm.as_deref(), Some("sha256"));
    assert_eq!(
        ts.signature_algorithm.as_deref(),
        Some("sha256WithRSAEncryption")
    );
    assert!(ts.intact && ts.valid && ts.trusted == Some(true));
    // Without a validation time the TSA was validated at its own genTime, which the report
    // says (QA round 1 finding F8), for the token and for the signer.
    assert!(ts.problems.is_empty(), "{ts:?}");
    assert_eq!(ts.warnings.len(), 1, "{ts:?}");
    assert!(
        ts.warnings[0].contains("validated at the token's own genTime"),
        "{ts:?}"
    );
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("genTime of the signature timestamp")),
        "{:?}",
        r.warnings
    );
    // With one, nothing to say.
    let now = folioxide_model::PdfDate::parse(b"D:20261010130000Z").unwrap();
    let at_now = &verify_with(
        &signed,
        &VerifyOptions::new()
            .with_trust_anchors_der(anchors())
            .with_validation_time(Some(now)),
    )[0];
    let ts_now = at_now.timestamp.as_ref().unwrap();
    assert!(
        ts_now.trusted == Some(true) && ts_now.warnings.is_empty(),
        "{ts_now:?}"
    );
    assert!(
        !at_now.warnings.iter().any(|w| w.contains("genTime")),
        "{:?}",
        at_now.warnings
    );

    // Without anchors: no trust verdict for the token nor the signer.
    let plain = &verify_with(&signed, &VerifyOptions::new())[0];
    assert_eq!(plain.trusted, None);
    let ts = plain.timestamp.as_ref().unwrap();
    assert_eq!(ts.trusted, None);
    assert!(ts.intact && ts.valid);
    assert_eq!(plain.pades_level, Some(PadesLevel::BT));

    // Separate timestamp anchors: the signer's root does not anchor the TSA any more.
    let other = VerifyOptions::new()
        .with_trust_anchors_der(anchors())
        .with_timestamp_trust_anchors_der(Some(vec![cert("signer-p256.pem")]));
    let r = &verify_with(&signed, &other)[0];
    assert_eq!(r.timestamp.as_ref().unwrap().trusted, Some(false));
    assert_eq!(r.pades_level, Some(PadesLevel::BT), "valid, not trusted");
    // An explicitly empty set: no verdict for the token.
    let none = VerifyOptions::new()
        .with_trust_anchors_der(anchors())
        .with_timestamp_trust_anchors_der(Some(Vec::new()));
    let r = &verify_with(&signed, &none)[0];
    assert_eq!(r.timestamp.as_ref().unwrap().trusted, None);
    assert_eq!(r.trusted, Some(true));

    #[cfg(feature = "serde")]
    {
        let json = serde_json::to_value(r.timestamp.as_ref().unwrap()).unwrap();
        for key in [
            "genTime",
            "tsa",
            "tsaName",
            "policy",
            "serialHex",
            "accuracyMicros",
            "ordering",
            "imprintAlgorithm",
            "signatureAlgorithm",
            "intact",
            "valid",
            "trusted",
            "problems",
            "warnings",
        ] {
            assert!(json.get(key).is_some(), "{key}: {json}");
        }
    }
}

// ---- §5.4 timestamp attacks ------------------------------------------------------------------

/// Hex-decodes the `/Contents` of the report's signature, and the gap's range.
fn contents(pdf: &[u8], r: &SignatureReport) -> (Vec<u8>, std::ops::Range<usize>) {
    let br = r.byte_range.as_deref().unwrap();
    let gap = (br[0] + br[1]) as usize..br[2] as usize;
    let digits = &pdf[gap.start + 1..gap.end - 1];
    let bytes = digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    (bytes, gap)
}

/// `pdf` with `cms` written over the report's `/Contents`, zero-padded, in place.
fn rewrite_contents(pdf: &[u8], r: &SignatureReport, cms: &[u8]) -> Vec<u8> {
    let (_, gap) = contents(pdf, r);
    let mut out = pdf.to_vec();
    let digits = hex(cms).into_bytes();
    let room = gap.end - gap.start - 2;
    assert!(digits.len() <= room);
    out[gap.start + 1..gap.end - 1]
        .copy_from_slice(&[digits.as_slice(), &vec![b'0'; room - digits.len()]].concat());
    out
}

#[test]
fn tst_substituted_from_other_signature() {
    let signer = rsa2048();
    let a = sign_bt(&minimal(), &signer);
    let b = sign_bt(&folioxide_testkit::fixtures::syntax::xref_stream(), &signer);
    let (ra, rb) = (report(&a), report(&b));
    let (cms_a, _) = contents(&a, &ra);
    let (cms_b, _) = contents(&b, &rb);
    let pa = cms::parse(&cms_a).unwrap();
    let pb = cms::parse(&cms_b).unwrap();
    let token_b = cms::signature_timestamp_tokens(&pb.signer_infos[0]).remove(0);
    // A's CMS, A's signature, B's (sound, trusted) token, written into A's /Contents in place.
    let mut attrs = pa.signer_infos[0].signed_attrs.clone().unwrap();
    attrs[0] = 0x31;
    let substituted = cms::assemble_with_timestamp(
        &attrs,
        &pa.signer_infos[0].signature,
        signer.certificate_chain(),
        signer.algorithm(),
        signer.key_kind(),
        DigestAlgorithm::Sha256,
        &token_b,
    )
    .unwrap();
    let forged = rewrite_contents(&a, &ra, &substituted);
    assert_eq!(forged.len(), a.len());
    assert_broken_timestamp(
        &forged,
        false,
        true,
        &[ProblemCode::TimestampImprintMismatch],
    );
}

#[test]
fn tst_imprint_over_der_octet_string() {
    // The classic bug: hashing the signature value's DER OCTET STRING (tag and length) instead
    // of its contents octets (pyHanko generic_cms.py:792; OpenSSL -data sigvalue.bin).
    let signer = rsa2048();
    let parts = parts(&signer, time());
    let mut octet_string = vec![0x04, 0x82, 0x01, 0x00];
    octet_string.extend_from_slice(&parts.value);
    let tsa = mock(MockTsaOptions {
        imprint: Echo::Replace(DigestAlgorithm::Sha256.digest(&[&octet_string])),
        ..defaults()
    });
    let token = tsa.token_for(&parts.request).unwrap();
    assert_broken_timestamp(
        &with_token(&parts, &signer, &token),
        false,
        true,
        &[ProblemCode::TimestampImprintMismatch],
    );
}

#[test]
fn tst_imprint_over_signed_attrs() {
    let signer = rsa2048();
    let parts = parts(&signer, time());
    let tsa = mock(MockTsaOptions {
        imprint: Echo::Replace(DigestAlgorithm::Sha256.digest(&[parts.prepared.to_be_signed()])),
        ..defaults()
    });
    let token = tsa.token_for(&parts.request).unwrap();
    assert_broken_timestamp(
        &with_token(&parts, &signer, &token),
        false,
        true,
        &[ProblemCode::TimestampImprintMismatch],
    );
}

#[test]
fn tst_econtent_id_data() {
    let pdf = attack(&mock(MockTsaOptions {
        econtent_type: "1.2.840.113549.1.7.1".into(),
        ..defaults()
    }));
    assert_broken_timestamp(&pdf, false, false, &[ProblemCode::TimestampMalformed]);
}

#[test]
fn tst_two_signer_infos() {
    let pdf = attack(&mock(MockTsaOptions {
        signer_infos: 2,
        ..defaults()
    }));
    assert_broken_timestamp(&pdf, false, false, &[ProblemCode::TimestampMalformed]);
}

#[test]
fn tst_version_2() {
    let pdf = attack(&mock(MockTsaOptions {
        tst_version: 2,
        ..defaults()
    }));
    assert_broken_timestamp(&pdf, false, false, &[ProblemCode::TimestampMalformed]);
}

#[test]
fn tst_ess_missing() {
    let pdf = attack(&mock(MockTsaOptions {
        ess: Ess::Missing,
        ..defaults()
    }));
    assert_broken_timestamp(&pdf, true, false, &[ProblemCode::TimestampEssMismatch]);
}

#[test]
fn tst_ess_wrong_cert() {
    let pdf = attack(&mock(MockTsaOptions {
        ess: Ess::WrongHash,
        ..defaults()
    }));
    assert_broken_timestamp(&pdf, true, false, &[ProblemCode::TimestampEssMismatch]);
}

#[test]
fn tst_signed_by_document_signer() {
    // A backdated self-timestamp: the document signer's own key and certificate (no
    // timestamping EKU) "timestamp" its signature at 2025-06-01.
    let signer = rsa2048();
    let key = rsa2048();
    let fake = MockTsa::new(
        cert("signer-rsa2048.pem"),
        vec![cert("intermediate.pem")],
        Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
    )
    .with_options(MockTsaOptions {
        gen_time: "20250601000000Z".into(),
        ..defaults()
    });
    let parts = parts(&signer, time());
    let token = fake.token_for(&parts.request).unwrap();
    let pdf = with_token(&parts, &signer, &token);
    assert_broken_timestamp(&pdf, true, false, &[ProblemCode::TsaCertificateUnsuitable]);
    let r = report(&pdf);
    assert!(
        r.timestamp.as_ref().unwrap().problems[0]
            .message
            .contains("no extended key usage")
    );
}

/// A file timestamped by the mock with the TSA certificate variant `cert_name`.
fn variant(cert_name: &str) -> Vec<u8> {
    attack(&mock_tsa_with(cert_name, defaults()))
}

#[test]
fn tst_tsa_eku_noncritical() {
    // Deliberately stricter than pyHanko (brief §0.1): pyHanko trusts it, OpenSSL refuses it.
    assert_broken_timestamp(
        &variant("tsa-eku-noncritical.pem"),
        true,
        false,
        &[ProblemCode::TsaCertificateUnsuitable],
    );
}

#[test]
fn tst_tsa_eku_extra_purpose() {
    assert_broken_timestamp(
        &variant("tsa-eku-extra.pem"),
        true,
        false,
        &[ProblemCode::TsaCertificateUnsuitable],
    );
}

#[test]
fn tst_tsa_ku_key_encipherment() {
    assert_broken_timestamp(
        &variant("tsa-ku-keyenc.pem"),
        true,
        false,
        &[ProblemCode::TsaCertificateUnsuitable],
    );
}

#[test]
fn tst_tsa_no_eku() {
    assert_broken_timestamp(
        &variant("tsa-no-eku.pem"),
        true,
        false,
        &[ProblemCode::TsaCertificateUnsuitable],
    );
}

#[test]
fn tst_tsa_cert_not_valid_at_gen_time() {
    // RFC 3161 §2.4.2: genTime is the TSA's time; a token outside its certificate's validity is
    // backdated. pyHanko validates at "now" and accepts it (brief §0.1).
    assert_broken_timestamp(
        &variant("tsa-not-yet-valid.pem"),
        true,
        false,
        &[ProblemCode::TsaCertificateNotValidAtGenTime],
    );
}

#[test]
fn tst_two_tokens_one_bad() {
    let signer = rsa2048();
    let parts = parts(&signer, time());
    let good = mock_tsa().token_for(&parts.request).unwrap();
    let bad = mock(MockTsaOptions {
        imprint: Echo::Replace(vec![0x42; 32]),
        gen_time: "20261010120010Z".into(),
        ..defaults()
    })
    .token_for(&parts.request)
    .unwrap();
    let cms = cms_with_unsigned(&parts, &signer, Some(&unsigned_tokens(&[good, bad])));
    let r = report(&embed_raw(&parts.prepared, &cms));
    assert!(r.is_valid(), "{}", summary(&r));
    assert_eq!(r.timestamps.len(), 2);
    // The sound one is selected although the broken one is earlier.
    let selected = r.timestamp.as_ref().unwrap();
    assert!(selected.intact && selected.valid && selected.trusted == Some(true));
    assert_eq!(selected.gen_time, "2026-10-10T12:00:30Z");
    assert_eq!(r.pades_level, Some(PadesLevel::BT));
    let broken: Vec<&TimestampInfo> = r.timestamps.iter().filter(|t| !t.intact).collect();
    assert_eq!(broken.len(), 1);
    assert_eq!(
        token_codes(broken[0]),
        [ProblemCode::TimestampImprintMismatch]
    );
}

#[test]
fn tst_two_tokens_both_good_earliest_selected() {
    let signer = rsa2048();
    let parts = parts(&signer, time());
    let later = mock_tsa().token_for(&parts.request).unwrap();
    let earlier = mock(MockTsaOptions {
        gen_time: "20261010120010.25Z".into(),
        serial: 2,
        ..defaults()
    })
    .token_for(&parts.request)
    .unwrap();
    let tokens = vec![later, earlier];
    let cms = cms_with_unsigned(&parts, &signer, Some(&unsigned_tokens(&tokens)));
    let r = report(&embed_raw(&parts.prepared, &cms));
    assert!(r.is_valid(), "{}", summary(&r));
    assert_eq!(r.timestamps.len(), 2);
    assert!(r.timestamps.iter().all(|t| t.intact && t.valid));
    assert_eq!(
        r.timestamp.as_ref().unwrap().gen_time,
        "2026-10-10T12:00:10.25Z"
    );
    assert_eq!(
        r.timestamp.as_ref().unwrap().serial_hex.as_deref(),
        Some("02")
    );
    assert_eq!(r.pades_level, Some(PadesLevel::BT));
    // Listed in attribute order (the tokens are DER-sorted in the SET).
    let mut sorted = tokens.clone();
    sorted.sort();
    let order: Vec<&str> = r.timestamps.iter().map(|t| t.gen_time.as_str()).collect();
    let expected: Vec<&str> = sorted
        .iter()
        .map(|t| {
            if *t == tokens[0] {
                "2026-10-10T12:00:30Z"
            } else {
                "2026-10-10T12:00:10.25Z"
            }
        })
        .collect();
    assert_eq!(order, expected);
}

#[test]
fn tst_token_ber() {
    let signer = rsa2048();
    let parts = parts(&signer, time());
    let token = mock_tsa().token_for(&parts.request).unwrap();
    // The outer ContentInfo with an indefinite length.
    let (h, _) = header(&token);
    let ber = [&[0x30, 0x80][..], &token[h..], &[0, 0]].concat();
    let pdf = with_token(&parts, &signer, &ber);
    let r = report(&pdf);
    assert!(r.is_valid(), "{}", summary(&r));
    // Embedded verbatim and opaque: the signer's CMS is still DER, so B-T.
    assert_eq!(r.pades_level, Some(PadesLevel::BT), "{}", summary(&r));
    let ts = r.timestamp.as_ref().unwrap();
    assert!(ts.intact && ts.valid && ts.trusted == Some(true), "{ts:?}");
    assert!(ts.warnings.iter().any(|w| w.contains("BER")), "{ts:?}");
}

#[test]
fn tst_more_tokens_than_verified_warn() {
    let signer = rsa2048();
    let parts = parts_with_reserve(&signer, time(), 40_000);
    let tokens: Vec<Vec<u8>> = (0..=MAX_TIMESTAMP_TOKENS as u64)
        .map(|serial| {
            mock(MockTsaOptions {
                serial: serial + 1,
                accuracy_secs: None,
                ..defaults()
            })
            .token_for(&parts.request)
            .unwrap()
        })
        .collect();
    let cms = cms_with_unsigned(&parts, &signer, Some(&unsigned_tokens(&tokens)));
    let r = report(&embed_raw(&parts.prepared, &cms));
    assert_eq!(r.timestamps.len(), MAX_TIMESTAMP_TOKENS);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("more than 8 signature timestamp tokens")),
        "{:?}",
        r.warnings
    );
    assert_eq!(r.pades_level, Some(PadesLevel::BT));
}

#[test]
fn tst_predating_the_claimed_time_warns() {
    let signer = rsa2048();
    let parts = parts(&signer, time());
    let early = mock(MockTsaOptions {
        gen_time: "20261010110000Z".into(),
        ..defaults()
    })
    .token_for(&parts.request)
    .unwrap();
    let r = report(&with_token(&parts, &signer, &early));
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("predates the claimed signing time")),
        "{:?}",
        r.warnings
    );
    assert_eq!(r.pades_level, Some(PadesLevel::BT));
}

// ---- V9 --------------------------------------------------------------------------------------

#[test]
fn verify_signer_trusted_at_trusted_gen_time_without_validation_time() {
    // expired.pem is valid in 2025 only. The claimed time /M is 2024-12-01 (before its
    // validity); a trusted token says 2025-06-01 (inside it).
    let signer = pem_signer("expired.key.pem", "expired.pem");
    let claimed = folioxide_model::PdfDate::parse(b"D:20241201000000Z").unwrap();
    let parts = parts(&signer, claimed);
    let tsa = mock(MockTsaOptions {
        gen_time: "20250601000000Z".into(),
        ..defaults()
    });
    let token = tsa.token_for(&parts.request).unwrap();
    let r = report(&with_token(&parts, &signer, &token));
    assert_eq!(r.timestamp.as_ref().unwrap().trusted, Some(true));
    assert_eq!(
        r.trusted,
        Some(true),
        "validated at genTime: {}",
        summary(&r)
    );
    assert!(
        !r.warnings.iter().any(|w| w.contains("(/M)")),
        "no claimed-time warning: {:?}",
        r.warnings
    );
    // But the genTime is the TSA's own claim (QA round 1 finding F8): the report says so.
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("genTime of the signature timestamp, the TSA's own claim")),
        "{:?}",
        r.warnings
    );

    // The same signature with an untrusted token falls back to /M, with M3's warning.
    let untrusted = mock_tsa_with(
        "tsa-eku-noncritical.pem",
        MockTsaOptions {
            gen_time: "20250601000000Z".into(),
            ..defaults()
        },
    );
    let token = untrusted.token_for(&parts.request).unwrap();
    let r = report(&with_token(&parts, &signer, &token));
    assert_eq!(r.timestamp.as_ref().unwrap().trusted, Some(false));
    assert_eq!(r.trusted, Some(false), "{}", summary(&r));
    assert!(
        r.warnings.iter().any(|w| w.contains("(/M)")),
        "{:?}",
        r.warnings
    );

    // An explicit validation time wins over genTime.
    let token = tsa.token_for(&parts.request).unwrap();
    let pdf = with_token(&parts, &signer, &token);
    let at = folioxide_model::PdfDate::parse(b"D:20261010120000Z").unwrap();
    let options = VerifyOptions::new()
        .with_trust_anchors_der(anchors())
        .with_validation_time(Some(at));
    let r = &verify_with(&pdf, &options)[0];
    assert_eq!(r.trusted, Some(false), "expired at the validation time");
}

#[test]
fn verify_pyhanko_bt_fixture() {
    let pdf = pdf_fixture("pyhanko-bt-rsa2048.pdf");
    let r = report(&pdf);
    assert!(r.is_valid() && r.trusted == Some(true), "{}", summary(&r));
    assert_eq!(r.pades_level, Some(PadesLevel::BT));
    let ts = r.timestamp.as_ref().unwrap();
    assert!(ts.intact && ts.valid && ts.trusted == Some(true), "{ts:?}");
    assert_eq!(ts.imprint_algorithm.as_deref(), Some("sha256"));
}

// ---- QA round 1: tokens OpenSSL refuses (findings F2–F6) and unsigned attributes (F10) ---------
//
// Each token below is signed by the real test TSA; OpenSSL `ts -verify` refuses all of them
// (`tsa name mismatch`, `ess cert id not found`, `message imprint mismatch`, `unable to find
// message digest`, ASN.1 decode errors), pyHanko accepts most (brief §0.1 rows `tst_*`).

/// The DER AlgorithmIdentifier `{ oid, parameters }` (raw parameter TLV, or none).
fn algorithm(oid: &[u8], parameters: Option<&[u8]>) -> Vec<u8> {
    let mut content = tlv(0x06, oid);
    if let Some(parameters) = parameters {
        content.extend_from_slice(parameters);
    }
    tlv(0x30, &content)
}

/// id-sha256, id-sha1 and an unknown OID, as content octets.
const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const SHA1_OID: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];

/// The test signer's subject `Name`, read from its certificate (issuer, validity, subject).
fn subject_of(cert_der: &[u8]) -> Vec<u8> {
    let tbs = children(content(cert_der))[0];
    let fields = children(content(tbs));
    let skip = usize::from(fields[0][0] == 0xA0);
    fields[skip + 4].to_vec()
}

#[test]
fn tst_tsa_name_mismatch() {
    // RFC 3161 §2.4.2: tsa "MUST correspond to one of the subject names included in the
    // certificate"; here it names the document signer (finding F2).
    let signer_name = subject_of(&cert("signer-rsa2048.pem"));
    let pdf = attack(&mock(MockTsaOptions {
        tsa_general_name: Some(tlv(0xA4, &signer_name)),
        ..defaults()
    }));
    assert_broken_timestamp(&pdf, true, false, &[ProblemCode::TsaNameMismatch]);
    let r = report(&pdf);
    let ts = r.timestamp.as_ref().unwrap();
    assert!(
        ts.problems[0]
            .message
            .contains("Folioxide Test Signer RSA-2048"),
        "{ts:?}"
    );
    // Another kind of name (a dNSName) the certificate has no subjectAltName for.
    let pdf = attack(&mock(MockTsaOptions {
        tsa_general_name: Some(tlv(0x82, b"tsa.example")),
        ..defaults()
    }));
    assert_broken_timestamp(&pdf, true, false, &[ProblemCode::TsaNameMismatch]);
    // The control: the TSA certificate's own subject.
    let pdf = attack(&mock(MockTsaOptions {
        tsa_general_name: Some(tlv(0xA4, &subject_of(&cert("tsa.pem")))),
        ..defaults()
    }));
    let ts = report(&pdf).timestamp.unwrap();
    assert!(ts.intact && ts.valid && ts.trusted == Some(true), "{ts:?}");
}

#[test]
fn tst_ess_v2_ok_v1_wrong() {
    // Finding F3 (a): every ESS attribute present is checked, as OpenSSL does; pyHanko reads
    // only v2 when present.
    let pdf = attack(&mock(MockTsaOptions {
        ess: Ess::V2AndWrongV1,
        ..defaults()
    }));
    assert_broken_timestamp(&pdf, true, false, &[ProblemCode::TimestampEssMismatch]);
    // Both correct: sound.
    let ts = report(&attack(&mock(MockTsaOptions {
        ess: Ess::V1AndV2,
        ..defaults()
    })))
    .timestamp
    .unwrap();
    assert!(ts.intact && ts.valid && ts.trusted == Some(true), "{ts:?}");
}

#[test]
fn tst_ess_second_cert_id() {
    // Finding F3 (b): every identifier after the first must name another certificate of the
    // TSA certificate's chain (OpenSSL `ess_find_cert`); pyHanko reads only the first.
    for (ess, more, why) in [
        (Ess::V2, b"junk".to_vec(), "v2, a hash of no certificate"),
        (Ess::V1, b"junk".to_vec(), "v1, a hash of no certificate"),
        (
            Ess::V2,
            cert("signer-rsa2048.pem"),
            "v2, a certificate the token does not carry",
        ),
        (Ess::V2, cert("tsa.pem"), "v2, the TSA certificate again"),
    ] {
        let pdf = attack(&mock(MockTsaOptions {
            ess,
            ess_more_cert_ids: vec![more],
            ..defaults()
        }));
        let r = report(&pdf);
        let ts = r.timestamp.as_ref().unwrap();
        assert!(ts.intact && !ts.valid, "{why}: {ts:?}");
        assert_eq!(
            token_codes(ts),
            [ProblemCode::TimestampEssMismatch],
            "{why}"
        );
        assert_eq!(r.pades_level, Some(PadesLevel::BB), "{why}");
    }
    // The control: the root, which the token carries and which issued the TSA certificate.
    for ess in [Ess::V2, Ess::V1, Ess::V1AndV2] {
        let pdf = attack(&mock(MockTsaOptions {
            ess,
            ess_more_cert_ids: vec![cert("root.pem")],
            ..defaults()
        }));
        let ts = report(&pdf).timestamp.unwrap();
        assert!(
            ts.intact && ts.valid && ts.trusted == Some(true),
            "{ess:?}: {ts:?}"
        );
    }
}

#[test]
fn tst_imprint_algorithm_parameters() {
    // Finding F4: SHA-256 with an OCTET STRING parameter is not the algorithm of the request
    // (RFC 5754 §2; OpenSSL ts_check_imprints: "message imprint mismatch").
    let pdf = attack(&mock(MockTsaOptions {
        imprint_algorithm: Some(algorithm(SHA256_OID, Some(&[0x04, 0x01, 0x00]))),
        ..defaults()
    }));
    assert_broken_timestamp(&pdf, false, true, &[ProblemCode::TimestampImprintMismatch]);
    // Absent parameters are NULL's equal (the control).
    let ts = report(&attack(&mock(MockTsaOptions {
        imprint_algorithm: Some(algorithm(SHA256_OID, None)),
        ..defaults()
    })))
    .timestamp
    .unwrap();
    assert!(ts.intact && ts.valid && ts.trusted == Some(true), "{ts:?}");
}

/// A token whose shape `options` breaks: malformed, neither intact nor valid, and `why` in the
/// problem.
fn assert_malformed_shape(options: MockTsaOptions, why: &str) {
    let pdf = attack(&mock(options));
    assert_broken_timestamp(&pdf, false, false, &[ProblemCode::TimestampMalformed]);
    let r = report(&pdf);
    let message = &r.timestamp.as_ref().unwrap().problems[0].message;
    assert!(message.contains(why), "{why}: {message}");
}

#[test]
fn tst_signed_data_version_1() {
    // Finding F5: RFC 5652 §5.1 requires version 3 for an eContentType other than id-data
    // (pyHanko cannot read such a token's TSTInfo; OpenSSL ignores the version).
    assert_malformed_shape(
        MockTsaOptions {
            signed_data_version: 1,
            ..defaults()
        },
        "SignedData version is 1, not 3",
    );
}

#[test]
fn tst_signer_info_version_not_its_sid() {
    // RFC 5652 §5.3: version 1 with an issuerAndSerialNumber (stricter than pyHanko and
    // OpenSSL, which both accept 3 here: brief §0.1).
    assert_malformed_shape(
        MockTsaOptions {
            signer_info_version: 3,
            ..defaults()
        },
        "SignerInfo version is 3, not 1",
    );
}

#[test]
fn tst_digest_algorithms() {
    // Finding F6: OpenSSL `PKCS7_dataInit` / `PKCS7_signatureVerify` ("unable to find message
    // digest") needs the SignerInfo's digest among them, and knows every member.
    for (members, why) in [
        (Vec::new(), "lists no digest algorithm"),
        (
            vec![algorithm(SHA1_OID, Some(&[0x05, 0x00]))],
            "does not list the SignerInfo's digest",
        ),
        (
            vec![
                algorithm(SHA256_OID, Some(&[0x05, 0x00])),
                algorithm(&[0x2A, 0x03, 0x04], None),
            ],
            "lists 1.2.3.4",
        ),
        (
            vec![algorithm(SHA256_OID, Some(&[0x04, 0x00]))],
            "lists 2.16.840.1.101.3.4.2.1",
        ),
    ] {
        assert_malformed_shape(
            MockTsaOptions {
                digest_algorithms: Some(members),
                ..defaults()
            },
            why,
        );
    }
    // SHA-1 listed besides SHA-256 is fine.
    let ts = report(&attack(&mock(MockTsaOptions {
        digest_algorithms: Some(vec![
            algorithm(SHA256_OID, Some(&[0x05, 0x00])),
            algorithm(SHA1_OID, None),
        ]),
        ..defaults()
    })))
    .timestamp
    .unwrap();
    assert!(ts.intact && ts.valid && ts.trusted == Some(true), "{ts:?}");
}

#[test]
fn tst_certificate_set_entries_decode() {
    // Finding F6: OpenSSL decodes every certificate of the set, used or not.
    let root = cert("root.pem");
    // The root with its organizationName as an INTEGER (same bytes, tag 0x02): it still
    // decodes as a certificate, but no X.509 name holds an INTEGER.
    let needle = b"\x0c\x12Folioxide Test PKI";
    let at = root
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    let mut integer_name = root.clone();
    integer_name[at] = 0x02;
    for (entry, why) in [
        (tlv(0x30, &[0x02, 0x01, 0x05]), "certificate does not parse"),
        (tlv(0x30, &[0x02, 0x02, 0x00, 0x05]), "non-minimal INTEGER"),
        (tlv(0xA1, &[0x05, 0x00]), "not an X.509 certificate"),
        (integer_name, "name value of a type a name may not hold"),
    ] {
        assert_malformed_shape(
            MockTsaOptions {
                extra_certificate_entries: vec![entry],
                ..defaults()
            },
            why,
        );
    }
}

#[test]
fn tst_signature_algorithm_parameters() {
    // sha256WithRSAEncryption takes NULL or nothing (RFC 4055 §5).
    let sha256_with_rsa = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
    assert_malformed_shape(
        MockTsaOptions {
            signature_algorithm: Some(algorithm(&sha256_with_rsa, Some(&[0x04, 0x00]))),
            ..defaults()
        },
        "signatureAlgorithm has parameters other than NULL",
    );
    let ts = report(&attack(&mock(MockTsaOptions {
        signature_algorithm: Some(algorithm(&sha256_with_rsa, None)),
        ..defaults()
    })))
    .timestamp
    .unwrap();
    assert!(ts.intact && ts.valid && ts.trusted == Some(true), "{ts:?}");
}

#[test]
fn tst_padded_integer_in_tst_info() {
    // A nonce with a redundant leading zero octet is no valid INTEGER (X.690 §8.3.2; OpenSSL
    // "illegal padding"), so the TSTInfo is malformed, whatever its value.
    let signer = rsa2048();
    let parts = parts(&signer, time());
    let token = mock(MockTsaOptions {
        nonce: Echo::Replace([&[0u8][..], &NONCE.to_be_bytes()].concat()),
        ..defaults()
    })
    .token_for(&parts.request)
    .unwrap();
    let pdf = with_token(&parts, &signer, &token);
    assert_broken_timestamp(&pdf, false, false, &[ProblemCode::TimestampMalformed]);
}

#[test]
fn unsigned_attributes_beyond_the_limit_are_not_read() {
    // Finding F10: unsigned attributes are not signed, so 100 of them before the token make
    // no invalid signature: the ones after the first 64 are not read, with a warning.
    let signer = rsa2048();
    let parts = parts_with_reserve(&signer, time(), 3 * DEFAULT_TSA_RESERVE);
    let token = mock_tsa().token_for(&parts.request).unwrap();
    let junk = tlv(
        0x30,
        &[
            &[0x06, 0x03, 0x2A, 0x03, 0x04][..],
            &tlv(0x31, &[0x05, 0x00]),
        ]
        .concat(),
    );
    let oid = [
        0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
    ];
    let token_attr = tlv(0x30, &[oid.as_slice(), &tlv(0x31, &token)].concat());
    for (count, seen) in [(100, false), (cms::MAX_ATTRIBUTES - 1, true)] {
        let mut attrs = junk.repeat(count);
        attrs.extend_from_slice(&token_attr);
        let unsigned = tlv(0xA1, &attrs);
        let cms = cms_with_unsigned(&parts, &signer, Some(&unsigned));
        let r = report(&embed_raw(&parts.prepared, &cms));
        assert!(
            r.is_valid() && r.problems.is_empty(),
            "{count}: {}",
            summary(&r)
        );
        let warned = r
            .warnings
            .iter()
            .any(|w| w.contains("more than 64 unsigned attributes"));
        assert_eq!(warned, !seen, "{count}: {:?}", r.warnings);
        assert_eq!(r.timestamps.len(), usize::from(seen), "{count}");
        let level = if seen { PadesLevel::BT } else { PadesLevel::BB };
        assert_eq!(r.pades_level, Some(level), "{count}");
    }
    // An unsignedAttrs under another tag ([2]) is no SignerInfo at all (RFC 5652 §5.3; OpenSSL
    // cannot decode it either): the CMS stays malformed.
    let cms = cms_with_unsigned(&parts, &signer, Some(&tlv(0xA2, &token_attr)));
    let r = report(&embed_raw(&parts.prepared, &cms));
    assert!(r.has_problem(ProblemCode::CmsMalformed), "{}", summary(&r));
}

// ---- QA round 2: ESS decoys (finding 3) and canonical names (finding 4) -----------------------
//
// OpenSSL looks for every later ESS identifier in the chain it verified (signer, issuers, trust
// anchor); a certificate that only carries an issuer's subject name is not in it. Folioxide
// links the TSA certificate to its issuers by name **and** verified signature, and with trust
// anchors requires the later identifiers on the validated path. pyHanko reads only the first
// identifier, so it accepts every token below (brief §0.1 row `tst_ess_second_cert_id_decoy`).

use bt_support::decoys::{decoys, issuer_of, reencode_name};
use folioxide_sign::verify_pdf::VerifyOptions as Options;

/// A mock TSA for `tsa_cert` (a certificate of `tsa.key.pem`) whose token carries `extra`,
/// with `options`.
fn mock_for(tsa_cert: &[u8], extra: &[&[u8]], options: MockTsaOptions) -> MockTsa {
    let key = tsa_key("tsa.pem");
    MockTsa::new(
        tsa_cert.to_vec(),
        extra.iter().map(|c| c.to_vec()).collect(),
        Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
    )
    .with_options(options)
}

/// `ess` naming `ids` (all of them, the first included) in every ESS attribute.
fn naming(ess: Ess, ids: &[&[u8]]) -> MockTsaOptions {
    MockTsaOptions {
        ess,
        ess_cert_ids: Some(ids.iter().map(|c| c.to_vec()).collect()),
        ..defaults()
    }
}

/// The single timestamp of `pdf` verified with `options`.
fn timestamp_with(pdf: &[u8], options: &Options) -> TimestampInfo {
    let mut reports = verify_with(pdf, options);
    assert_eq!(reports.len(), 1);
    reports.remove(0).timestamp.unwrap()
}

#[test]
fn tst_ess_second_cert_id_decoy() {
    let d = decoys();
    let (tsa, root, inter) = (cert("tsa.pem"), cert("root.pem"), cert("intermediate.pem"));
    let tsa_vi = &d.tsa_via_intermediate;
    let cases: [(&str, MockTsa); 8] = [
        (
            "v2 [TSA, attacker root with the root's name]",
            mock_for(
                &tsa,
                &[&root, &d.fake_root],
                naming(Ess::V2, &[&tsa, &d.fake_root]),
            ),
        ),
        (
            "v1 [TSA, attacker root]",
            mock_for(
                &tsa,
                &[&root, &d.fake_root],
                naming(Ess::V1, &[&tsa, &d.fake_root]),
            ),
        ),
        (
            "v1 and v2 [TSA, attacker root]",
            mock_for(
                &tsa,
                &[&d.fake_root, &root],
                naming(Ess::V1AndV2, &[&tsa, &d.fake_root]),
            ),
        ),
        (
            "v1 [TSA] correct, v2 [TSA, attacker root]",
            mock_for(
                &tsa,
                &[&root, &d.fake_root],
                MockTsaOptions {
                    ess_v1_cert_ids: Some(vec![tsa.clone()]),
                    ..naming(Ess::V1AndV2, &[&tsa, &d.fake_root])
                },
            ),
        ),
        (
            "v2 [TSA, root, attacker root]",
            mock_for(
                &tsa,
                &[&root, &d.fake_root],
                naming(Ess::V2, &[&tsa, &root, &d.fake_root]),
            ),
        ),
        (
            "TSA via the intermediate, v2 [TSA, attacker certificate with the intermediate's name]",
            mock_for(
                tsa_vi,
                &[&inter, &root, &d.fake_intermediate],
                naming(Ess::V2, &[tsa_vi, &d.fake_intermediate]),
            ),
        ),
        (
            "v2 [TSA, a twin of the TSA certificate]",
            mock_for(
                &tsa,
                &[&root, &d.tsa_twin],
                naming(Ess::V2, &[&tsa, &d.tsa_twin]),
            ),
        ),
        (
            "v2 [TSA, attacker root] without the attacker root in the token",
            mock_for(&tsa, &[&root], naming(Ess::V2, &[&tsa, &d.fake_root])),
        ),
    ];
    for (why, tsa) in &cases {
        let pdf = attack(tsa);
        let r = report(&pdf);
        assert!(r.is_valid(), "{why}: {}", summary(&r));
        assert_eq!(r.pades_level, Some(PadesLevel::BB), "{why}");
        let ts = r.timestamp.as_ref().unwrap();
        assert!(
            ts.intact && !ts.valid && ts.trusted == Some(false),
            "{why}: {ts:?}"
        );
        assert_eq!(
            token_codes(ts),
            [ProblemCode::TimestampEssMismatch],
            "{why}"
        );
        // Without anchors too: the decoy is linked by name only, never by signature.
        let ts = timestamp_with(&pdf, &Options::new());
        assert!(
            ts.intact && !ts.valid && ts.trusted.is_none(),
            "{why}: {ts:?}"
        );
    }
}

#[test]
fn tst_ess_second_cert_id_reissued_root() {
    // The root's name and key under another serial: it verifies the TSA certificate like the
    // root, but it is not the trust anchor, so OpenSSL does not find it in its chain.
    let d = decoys();
    let (tsa, root) = (cert("tsa.pem"), cert("root.pem"));
    let pdf = attack(&mock_for(
        &tsa,
        &[&root, &d.reissued_root],
        naming(Ess::V2, &[&tsa, &d.reissued_root]),
    ));
    let r = report(&pdf);
    assert!(r.is_valid(), "{}", summary(&r));
    assert_eq!(r.pades_level, Some(PadesLevel::BB));
    let ts = r.timestamp.as_ref().unwrap();
    assert!(
        ts.intact && !ts.valid && ts.trusted == Some(false),
        "{ts:?}"
    );
    assert_eq!(token_codes(ts), [ProblemCode::TimestampEssMismatch]);
    assert!(ts.problems[0].message.contains("validated path"), "{ts:?}");
    // Without anchors it cannot be told from the root: valid, no trust verdict.
    let ts = timestamp_with(&pdf, &Options::new());
    assert!(ts.intact && ts.valid && ts.trusted.is_none(), "{ts:?}");
    // With the re-issued root as the anchor, it is the chain's anchor (OpenSSL agrees).
    let ts = timestamp_with(
        &pdf,
        &Options::new().with_trust_anchors_der(vec![d.reissued_root.clone()]),
    );
    assert!(ts.intact && ts.valid && ts.trusted == Some(true), "{ts:?}");
}

#[test]
fn tst_ess_later_ids_on_the_chain() {
    // The controls: later identifiers that name the real chain, as OpenSSL accepts them.
    let d = decoys();
    let (tsa, root, inter) = (cert("tsa.pem"), cert("root.pem"), cert("intermediate.pem"));
    let tsa_vi = &d.tsa_via_intermediate;
    let cases: [(&str, MockTsa); 5] = [
        (
            "v1 and v2 [TSA, root]",
            mock_for(
                &tsa,
                &[&root, &d.fake_root],
                naming(Ess::V1AndV2, &[&tsa, &root]),
            ),
        ),
        (
            "TSA via the intermediate, v2 [TSA, intermediate, root]",
            mock_for(
                tsa_vi,
                &[&inter, &root, &d.fake_intermediate],
                naming(Ess::V2, &[tsa_vi, &inter, &root]),
            ),
        ),
        (
            "TSA via the intermediate, v1 [TSA, root] (skips the intermediate)",
            mock_for(tsa_vi, &[&inter, &root], naming(Ess::V1, &[tsa_vi, &root])),
        ),
        (
            "TSA via the intermediate, v2 [TSA, root, intermediate, root]",
            mock_for(
                tsa_vi,
                &[&inter, &root],
                naming(Ess::V2, &[tsa_vi, &root, &inter, &root]),
            ),
        ),
        (
            "v2 [TSA, root] with the root only among the trust anchors",
            mock_for(&tsa, &[], naming(Ess::V2, &[&tsa, &root])),
        ),
    ];
    for (why, tsa) in &cases {
        let pdf = attack(tsa);
        let r = report(&pdf);
        assert_eq!(
            r.pades_level,
            Some(PadesLevel::BT),
            "{why}: {}",
            summary(&r)
        );
        let ts = r.timestamp.as_ref().unwrap();
        assert!(
            ts.intact && ts.valid && ts.trusted == Some(true) && ts.problems.is_empty(),
            "{why}: {ts:?}"
        );
    }
    // Without anchors a root the token does not carry names nothing (no chain to look in).
    let pdf = attack(&cases[4].1);
    let ts = timestamp_with(&pdf, &Options::new());
    assert!(ts.intact && !ts.valid && ts.trusted.is_none(), "{ts:?}");
    assert_eq!(token_codes(&ts), [ProblemCode::TimestampEssMismatch]);
}

#[test]
fn tst_names_compare_as_x509_name_cmp() {
    // Finding 4: the TSTInfo tsa name and the ESS issuerSerial name are compared as RFC 5280
    // §7.1 and OpenSSL's X509_NAME_cmp compare names: another string type or ASCII case is
    // the same name (OpenSSL and pyHanko accept these tokens too).
    let (tsa, root) = (cert("tsa.pem"), cert("root.pem"));
    let subject = subject_of(&tsa);
    let issuer = issuer_of(&tsa);
    for (why, options) in [
        (
            "tsa = the subject as PrintableString",
            MockTsaOptions {
                tsa_general_name: Some(tlv(0xA4, &reencode_name(&subject, 0x13, false))),
                ..defaults()
            },
        ),
        (
            "tsa = the subject lowercased",
            MockTsaOptions {
                tsa_general_name: Some(tlv(0xA4, &reencode_name(&subject, 0x0C, true))),
                ..defaults()
            },
        ),
        (
            "ESS v2 issuer as PrintableString",
            MockTsaOptions {
                ess_issuer_name: Some(reencode_name(&issuer, 0x13, false)),
                ..defaults()
            },
        ),
        (
            "ESS v1 issuer lowercased, the root's too",
            MockTsaOptions {
                ess_issuer_name: Some(reencode_name(&issuer, 0x0C, true)),
                ..naming(Ess::V1, &[&tsa, &root])
            },
        ),
    ] {
        let ts = report(&attack(&mock(options))).timestamp.unwrap();
        assert!(
            ts.intact && ts.valid && ts.trusted == Some(true),
            "{why}: {ts:?}"
        );
    }
    // The RDNs in another order are another name.
    let mut rdns = children(content(&subject));
    rdns.reverse();
    let reversed = tlv(0x30, &rdns.concat());
    let pdf = attack(&mock(MockTsaOptions {
        tsa_general_name: Some(tlv(0xA4, &reversed)),
        ..defaults()
    }));
    assert_broken_timestamp(&pdf, true, false, &[ProblemCode::TsaNameMismatch]);
    let pdf = attack(&mock(MockTsaOptions {
        ess_issuer_name: Some(reversed),
        ..defaults()
    }));
    assert_broken_timestamp(&pdf, true, false, &[ProblemCode::TimestampEssMismatch]);
}

/// OpenSSL's rule for the ESS identifiers of one attribute (`OSSL_ESS_check_signing_certs`,
/// `find`): the first names the signer, chain index 0, and every later one a certificate of
/// the verified chain after it.
fn openssl_accepts(ids: &[&[u8]], chain: &[&[u8]]) -> bool {
    match ids.split_first() {
        Some((first, later)) => {
            *first == chain[0] && later.iter().all(|id| chain[1..].contains(id))
        }
        None => false,
    }
}

/// One token of [`tst_ess_identifiers_exhaustive`]: the TSA certificate, the other certificates
/// the token carries, the ESS attributes and their identifiers, and OpenSSL's verdict.
struct EssCase {
    tsa: Vec<u8>,
    extra: Vec<Vec<u8>>,
    ess: Ess,
    ids: Vec<Vec<u8>>,
    accepted: bool,
}

#[test]
fn tst_ess_identifiers_exhaustive() {
    // QA round 2 (finding 3): every sequence of 1 to 3 identifiers over the TSA certificate,
    // the root, the intermediate, the three decoys, a twin of the TSA certificate and the
    // document signer, in v2, v1 and both, for a TSA under the root and one under the
    // intermediate, the token carrying every candidate (QA's 816 tokens). Folioxide's
    // `valid` must be OpenSSL's verdict for each, both ways. Sequences of 3 start with the TSA.
    let d = decoys();
    let (root, inter) = (cert("root.pem"), cert("intermediate.pem"));
    let signer_cert = cert("signer-rsa2048.pem");
    let tsa_plain = cert("tsa.pem");
    let options = Options::new().with_timestamp_trust_anchors_der(Some(vec![root.clone()]));
    let signer = rsa2048();
    let parts = parts_with_reserve(&signer, time(), 32 * 1024);
    let mut cases: Vec<EssCase> = Vec::new();
    for tsa in [&tsa_plain, &d.tsa_via_intermediate] {
        let chain: Vec<&[u8]> = if *tsa == tsa_plain {
            vec![tsa, &root]
        } else {
            vec![tsa, &inter, &root]
        };
        let candidates: [&[u8]; 8] = [
            tsa,
            &root,
            &inter,
            &d.fake_root,
            &d.reissued_root,
            &d.fake_intermediate,
            &d.tsa_twin,
            &signer_cert,
        ];
        let extra: Vec<Vec<u8>> = candidates[1..].iter().map(|c| c.to_vec()).collect();
        let mut sequences: Vec<Vec<&[u8]>> = Vec::new();
        for a in candidates {
            sequences.push(vec![a]);
            for b in candidates {
                sequences.push(vec![a, b]);
                if a == *tsa {
                    for c in candidates {
                        sequences.push(vec![a, b, c]);
                    }
                }
            }
        }
        for ids in &sequences {
            let accepted = openssl_accepts(ids, &chain);
            for ess in [Ess::V2, Ess::V1, Ess::V1AndV2] {
                cases.push(EssCase {
                    tsa: tsa.to_vec(),
                    extra: extra.clone(),
                    ess,
                    ids: ids.iter().map(|c| c.to_vec()).collect(),
                    accepted,
                });
            }
        }
    }
    assert_eq!(cases.len(), 816);
    // Accepted: [TSA], [TSA, root], [TSA, root, root] under the root; [TSA] and [TSA, x] and
    // [TSA, x, y] with x, y in {intermediate, root} under the intermediate; three modes each.
    assert_eq!(cases.iter().filter(|c| c.accepted).count(), (3 + 7) * 3);
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
    let chunk = cases.len().div_ceil(threads);
    let mismatches: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = cases
            .chunks(chunk)
            .map(|chunk| {
                let (parts, signer, options) = (&parts, &signer, &options);
                scope.spawn(move || {
                    let mut out = Vec::new();
                    for EssCase {
                        tsa,
                        extra,
                        ess,
                        ids,
                        accepted,
                    } in chunk
                    {
                        let extra: Vec<&[u8]> = extra.iter().map(Vec::as_slice).collect();
                        let options_for_ids = MockTsaOptions {
                            ess: *ess,
                            ess_cert_ids: Some(ids.clone()),
                            ..defaults()
                        };
                        let token = mock_for(tsa, &extra, options_for_ids)
                            .token_for(&parts.request)
                            .unwrap();
                        let pdf = with_token(parts, signer, &token);
                        let ts = timestamp_with(&pdf, options);
                        let as_expected = ts.intact
                            && ts.valid == *accepted
                            && ts.trusted == Some(*accepted)
                            && (*accepted
                                || token_codes(&ts) == [ProblemCode::TimestampEssMismatch]);
                        if !as_expected {
                            out.push(format!(
                                "{ess:?} {} ids, OpenSSL {accepted}: {ts:?}",
                                ids.len()
                            ));
                        }
                    }
                    out
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    });
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

// ---- Constructs RFC 5652 allows that OpenSSL 3.0's `ts -verify` cannot read -------------------
//
// OpenSSL verifies timestamp tokens through its PKCS #7 layer, which knows neither RSASSA-PSS
// (`PKCS7_signatureVerify: signature failure`) nor a SignerInfo identified by its
// subjectKeyIdentifier (an ASN.1 decode error: PKCS #7 has only issuerAndSerialNumber). Both are
// valid CMS (RFC 4056, RFC 5652 §5.3) and pyHanko accepts them, as Folioxide does: the two known
// exceptions to brief §5.5 (iii), oracle cases `tst-rsa-pss-signed` and
// `tst-sid-subject-key-identifier` with an OpenSSL `knownFailures` row.

/// The subjectKeyIdentifier of `tsa.pem` (gen-pki.sh: `subjectKeyIdentifier = hash`).
fn tsa_subject_key_identifier() -> Vec<u8> {
    let tsa = cert("tsa.pem");
    let marker = [0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14];
    let at = tsa.windows(marker.len()).position(|w| w == marker).unwrap() + marker.len();
    tsa[at..at + 20].to_vec()
}

#[test]
fn tst_rsa_pss_signed() {
    let tsa = mock_tsa_pss(defaults());
    let r = report(&attack(&tsa));
    assert_eq!(r.pades_level, Some(PadesLevel::BT), "{}", summary(&r));
    let ts = r.timestamp.as_ref().unwrap();
    assert!(
        ts.intact && ts.valid && ts.trusted == Some(true) && ts.problems.is_empty(),
        "{ts:?}"
    );
    assert_eq!(ts.signature_algorithm.as_deref(), Some("rsassa-pss"));
    // The signing side embeds such a token too.
    let signed = sign_bt_with(
        &minimal(),
        &rsa2048(),
        folioxide_sign::prepare::SignatureOptions::new(time()),
        &Tsa(mock_tsa_pss(defaults())),
    )
    .unwrap();
    assert_eq!(report(&signed).pades_level, Some(PadesLevel::BT));
    // Parameters that do not describe the signature (another salt length) do not verify.
    let mut algorithm = rsassa_pss_sha256();
    let salt = algorithm.len() - 1;
    algorithm[salt] = 20;
    let pdf = attack(&mock_tsa_pss(MockTsaOptions {
        signature_algorithm: Some(algorithm),
        ..defaults()
    }));
    let ts = report(&pdf).timestamp.unwrap();
    assert!(ts.intact && !ts.valid, "{ts:?}");
    assert_eq!(token_codes(&ts), [ProblemCode::TimestampSignatureInvalid]);
}

#[test]
fn tst_sid_subject_key_identifier() {
    let pdf = attack(&mock(MockTsaOptions {
        signer_key_identifier: Some(tsa_subject_key_identifier()),
        signer_info_version: 3,
        ..defaults()
    }));
    let r = report(&pdf);
    assert_eq!(r.pades_level, Some(PadesLevel::BT), "{}", summary(&r));
    let ts = r.timestamp.as_ref().unwrap();
    assert!(
        ts.intact && ts.valid && ts.trusted == Some(true) && ts.problems.is_empty(),
        "{ts:?}"
    );
    // Version 1 does not go with a subjectKeyIdentifier (RFC 5652 §5.3).
    assert_malformed_shape(
        MockTsaOptions {
            signer_key_identifier: Some(tsa_subject_key_identifier()),
            ..defaults()
        },
        "SignerInfo version is 1, not 3",
    );
    // A subjectKeyIdentifier of no certificate of the token names no signer.
    let pdf = attack(&mock(MockTsaOptions {
        signer_key_identifier: Some(vec![7; 20]),
        signer_info_version: 3,
        ..defaults()
    }));
    let ts = report(&pdf).timestamp.unwrap();
    assert!(!ts.valid, "{ts:?}");
}

// ---- QA round 3: what OpenSSL's decoders read and Folioxide did not (findings 1–4, 7, 8) ------
//
// Each token below is signed by the test TSA over exactly the bytes it carries, so a verifier
// that hashes the signed attributes as found (pyHanko, Folioxide before) calls it intact and
// valid; `openssl ts -verify` refuses every refused one (QA's variants of the same names), so
// Folioxide does too: `TimestampMalformed`, the signature itself sound and B-B (brief §0.1).

use bt_support::tokens;

/// [`assert_malformed_shape`] for a list of `(QA variant, options, why)`.
fn assert_all_malformed(cases: Vec<(&str, MockTsaOptions, &str)>) {
    for (name, options, why) in cases {
        let pdf = attack(&mock(options));
        let r = report(&pdf);
        assert!(
            r.is_valid() && r.problems.is_empty(),
            "{name}: {}",
            summary(&r)
        );
        assert_eq!(
            r.pades_level,
            Some(PadesLevel::BB),
            "{name}: {}",
            summary(&r)
        );
        let ts = r.timestamp.as_ref().unwrap();
        assert!(
            !ts.intact && !ts.valid && ts.trusted == Some(false),
            "{name}: {ts:?}"
        );
        assert_eq!(token_codes(ts), [ProblemCode::TimestampMalformed], "{name}");
        assert!(ts.problems[0].message.contains(why), "{name}: {ts:?}");
    }
}

/// The token of the mock with `options` is intact, valid and trusted, and the signature B-T.
fn assert_sound_token(name: &str, options: MockTsaOptions) {
    let r = report(&attack(&mock(options)));
    assert_eq!(
        r.pades_level,
        Some(PadesLevel::BT),
        "{name}: {}",
        summary(&r)
    );
    let ts = r.timestamp.unwrap();
    assert!(
        ts.intact && ts.valid && ts.trusted == Some(true) && ts.problems.is_empty(),
        "{name}: {ts:?}"
    );
}

#[test]
fn tst_signed_attributes_not_der() {
    // Finding 2: OpenSSL verifies over a DER re-encoding of the signed attributes (each
    // attribute's values sorted, minimal definite lengths), BouncyCastle over the sorted set, so
    // a TSA that signed any other encoding of them made a token those verifiers refuse
    // (`bad signature`). RFC 5652 §5.4 signs the DER encoding.
    use tokens::*;
    const NOT_DER: &str = "signed attributes are not DER";
    let (t1, t2) = (utc_time("261010120030Z"), utc_time("261010120031Z"));
    let octet_values = [octets(b"a"), octets(b"b")];
    let int_values = [int(1), int(2), der(0x02, &[0x01, 0x2C])];
    let extra = |attribute: Vec<u8>| MockTsaOptions {
        extra_signed_attributes: vec![attribute],
        ..defaults()
    };
    let encoded = |encode: fn(&[u8]) -> Vec<u8>| MockTsaOptions {
        signed_attrs_encoding: Some(encode),
        ..defaults()
    };
    assert_all_malformed(vec![
        (
            "r3-attr-signing-time-unsorted-values",
            extra(unsorted_attribute(&SIGNING_TIME, &[t1.clone(), t2.clone()])),
            NOT_DER,
        ),
        (
            "r3-attr-unknown-oid-unsorted-values",
            extra(unsorted_attribute(&test_oid(99), &octet_values)),
            NOT_DER,
        ),
        (
            "r3-attr-unknown-three-ints-unsorted-values",
            extra(unsorted_attribute(&test_oid(98), &int_values)),
            NOT_DER,
        ),
        (
            "r3-ber-sattr-all-attrs-indefinite",
            encoded(attributes_indefinite),
            NOT_DER,
        ),
        (
            "r3-ber-sattr-ess-attr-indefinite",
            encoded(ess_attribute_indefinite),
            NOT_DER,
        ),
        (
            "r3-ber-sattr-first-attr-header-longform",
            encoded(first_attribute_long_form),
            NOT_DER,
        ),
        (
            "r3-ber-sattr-md-oid-longform",
            encoded(message_digest_type_long_form),
            NOT_DER,
        ),
        (
            "r3-ber-sattr-md-set-longform",
            encoded(message_digest_values_long_form),
            NOT_DER,
        ),
        (
            "r3-ber-sattr-ct-value-oid-longform",
            encoded(content_type_value_long_form),
            NOT_DER,
        ),
        (
            "r3-ber-sattr-set-header-longform-4",
            encoded(set_header_long_form_4),
            NOT_DER,
        ),
        // What OpenSSL's re-encoding of an attribute value changes too (X.690 §11.1, §11.2.1).
        (
            "a BOOLEAN value TRUE written 01",
            extra(attribute(&test_oid(93), &[der(0x01, &[0x01])])),
            NOT_DER,
        ),
        (
            "a BIT STRING value with its unused bits set",
            extra(attribute(&test_oid(92), &[der(0x03, &[0x04, 0xF8])])),
            NOT_DER,
        ),
        // Deliberately stricter than OpenSSL (which keeps the order it reads) and pyHanko:
        // attributes out of DER order are not the DER encoding the TSA must sign (§5.4), and
        // BouncyCastle (EU DSS) re-sorts them before it verifies (brief §0.1).
        (
            "the attributes out of DER order",
            encoded(attributes_reversed),
            NOT_DER,
        ),
    ]);
    // The controls: the same attributes in DER (QA's *-sorted-values; OpenSSL accepts them).
    for (name, attribute) in [
        (
            "r3-attr-signing-time-sorted-values",
            sorted_attribute(&SIGNING_TIME, &[t1, t2]),
        ),
        (
            "r3-attr-unknown-oid-sorted-values",
            sorted_attribute(&test_oid(99), &octet_values),
        ),
        (
            "r3-attr-unknown-three-ints-sorted-values",
            sorted_attribute(&test_oid(98), &int_values),
        ),
        (
            "a BOOLEAN value TRUE written FF",
            attribute(&test_oid(93), &[der(0x01, &[0xFF])]),
        ),
        (
            "a BIT STRING value with clear unused bits",
            attribute(&test_oid(92), &[der(0x03, &[0x04, 0xF0])]),
        ),
        ("r3-attr-unknown-empty-set", attribute(&test_oid(96), &[])),
    ] {
        assert_sound_token(name, extra(attribute));
    }
}

#[test]
fn tst_ess_attribute_decodes() {
    // Findings 3, 7 and 8: OpenSSL decodes every ESS signing-certificate attribute with its
    // ESS_SIGNING_CERT(_V2) template, `policies` (SEQUENCE OF PolicyInformation) and the
    // IssuerSerial names (X509_NAME_ENTRY value types) included, and refuses the whole token
    // when that fails; Folioxide looked only at the policies' tag and compared the names.
    use tokens::*;
    let tsa = cert("tsa.pem");
    let visible_issuer = reencode_name(&issuer_of(&tsa), 0x1A, false);
    for (ess, version) in [(Ess::V2, "v2"), (Ess::V1, "v1")] {
        let policies = |policies: Vec<u8>| MockTsaOptions {
            ess,
            ess_policies: Some(policies),
            ..defaults()
        };
        let named = |n: &str| format!("r3-ess-policies-{n}-{version}");
        assert_all_malformed(vec![
            (
                named("junk-integer").as_str(),
                policies(seq(&[seq(&[int(1)])])),
                "a policies entry is not a PolicyInformation",
            ),
            (
                named("junk-octets").as_str(),
                policies(seq(&[octets(b"abc")])),
                "a policies entry is not a PolicyInformation",
            ),
            (
                named("qualifier-junk").as_str(),
                policies(seq(&[seq(&[oid(&test_oid(1)), seq(&[int(9)])])])),
                "a policy qualifier is not a PolicyQualifierInfo",
            ),
            (
                named("wrong-tag").as_str(),
                policies(der(0x31, &seq(&[oid(&test_oid(1))]))),
                "policies is not a SEQUENCE",
            ),
            (
                "a CPS qualifier that is not an IA5String",
                policies(policies_with_qualifier(
                    &ID_QT_CPS,
                    der(0x0C, b"https://x.example/"),
                )),
                "a CPS qualifier is not an IA5String",
            ),
            (
                "a user notice qualifier that is not a UserNotice",
                policies(policies_with_qualifier(&ID_QT_UNOTICE, seq(&[int(1)]))),
                "not a UserNotice",
            ),
            (
                &format!("r3-name-essissuer-visible ({version})"),
                MockTsaOptions {
                    ess,
                    ess_issuer_name: Some(visible_issuer.clone()),
                    ..defaults()
                },
                "a value of a type a name may not hold",
            ),
        ]);
        // The controls, which OpenSSL accepts too.
        let notice = seq(&[
            seq(&[der(0x16, b"Folioxide"), seq(&[int(1), int(2)])]),
            der(0x1A, b"test only"),
        ]);
        for (name, value) in [
            (named("valid"), policies_valid()),
            (named("empty"), seq(&[])),
            (
                named("qualifier-valid"),
                policies_with_qualifier(&ID_QT_CPS, der(0x16, b"https://x.example/")),
            ),
            (
                format!("a user notice ({version})"),
                policies_with_qualifier(&ID_QT_UNOTICE, notice),
            ),
            (
                format!("a user notice with explicit text only ({version})"),
                policies_with_qualifier(&ID_QT_UNOTICE, seq(&[der(0x0C, b"text")])),
            ),
            (
                format!("an unknown qualifier: any value ({version})"),
                policies_with_qualifier(&test_oid(7), int(5)),
            ),
        ] {
            assert_sound_token(&name, policies(value));
        }
        // Other string types QA tried (PrintableString, IA5String: the same ASCII) are names.
        for tag in [0x13, 0x16] {
            assert_sound_token(
                &format!("issuer tag {tag:02X} ({version})"),
                MockTsaOptions {
                    ess,
                    ess_issuer_name: Some(reencode_name(&issuer_of(&tsa), tag, false)),
                    ..defaults()
                },
            );
        }
    }
}

#[test]
fn tst_tst_info_extensions_decode() {
    // Finding 4: OpenSSL decodes the TSTInfo `[1] extensions` as X509_EXTENSIONs and refuses
    // the token when they do not decode; Folioxide only looked for the tag.
    use tokens::*;
    let with = |element: Vec<u8>| MockTsaOptions {
        tst_extensions: Some(element),
        ..defaults()
    };
    let subject = subject_of(&cert("tsa.pem"));
    assert_all_malformed(vec![
        (
            "r3-tstinfo-extensions-junk-sequence",
            with(tst_extensions(&[seq(&[seq(&[int(1)])])])),
            "extnID has the wrong type",
        ),
        (
            "r3-tstinfo-extensions-octet-string",
            with(tst_extensions(&[octets(b"zz")])),
            "not an Extension",
        ),
        (
            "r3-tstinfo-extensions-gn-retagged-tsa",
            with(tst_extensions(&[der(0xA4, &subject)])),
            "not an Extension",
        ),
        (
            "r4-tstinfo-extension-extra-field",
            with(tst_extensions(&[seq(&[
                oid(&test_oid(5)),
                octets(&[0x05, 0x00]),
                der(0x05, &[]),
            ])])),
            "unexpected element after the last field",
        ),
        (
            "r4-tstinfo-extension-int-oid",
            with(tst_extensions(&[seq(&[int(5), octets(&[0x05, 0x00])])])),
            "extnID has the wrong type",
        ),
        (
            "r4-tstinfo-extension-value-not-octets",
            with(tst_extensions(&[seq(&[oid(&test_oid(5)), int(1)])])),
            "expected an OCTET STRING",
        ),
        // Deliberately stricter than OpenSSL: RFC 5280 §4.1 Extensions ::= SEQUENCE SIZE
        // (1..MAX) OF Extension.
        (
            "r3-tstinfo-extensions-empty",
            with(tst_extensions(&[])),
            "extensions is empty",
        ),
    ]);
    // The controls: Folioxide reads extensions but acts on none (RFC 3161 defines none).
    for (name, element) in [
        (
            "r3-tstinfo-extensions-valid-noncritical",
            tst_extensions(&[extension(5)]),
        ),
        (
            "r4-tstinfo-extension-two-valid",
            tst_extensions(&[extension(5), extension(6)]),
        ),
        (
            "r3-tstinfo-extensions-critical-unknown",
            tst_extensions(&[seq(&[
                oid(&test_oid(6)),
                der(0x01, &[0xFF]),
                octets(&[0x05, 0x00]),
            ])]),
        ),
        (
            "r3-tstinfo-extensions-bad-bool (BER, the TSTInfo is not DER-checked)",
            tst_extensions(&[seq(&[
                oid(&test_oid(7)),
                der(0x01, &[0x01]),
                octets(&[0x05, 0x00]),
            ])]),
        ),
    ] {
        assert_sound_token(name, with(element));
    }
}

#[test]
fn tst_unreadable_unsigned_attribute_warns() {
    // Finding 1: a token value that cannot be read at all (a huge declared length, truncated,
    // nested deeper than the limit) used to vanish without a word: no timestamp, no warning.
    // The report now says an unsigned attribute could not be read, and why the signature has no
    // PAdES level (the CMS around the damaged value is not DER).
    let signer = rsa2048();
    let parts = parts(&signer, time());
    let token = mock_tsa().token_for(&parts.request).unwrap();
    let oid = [
        0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
    ];
    let mut deep = Vec::new();
    for _ in 0..33 {
        deep.extend([0x30, 0x80]);
    }
    deep.extend(std::iter::repeat_n(0u8, 66));
    for (name, values, timestamps) in [
        (
            "huge_len_4",
            [&[0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF][..], &token[..16]].concat(),
            0,
        ),
        ("trunc10", token[..10].to_vec(), 0),
        ("deep_indef33", deep, 0),
        (
            "a sound token, then a truncated one",
            [token.as_slice(), &token[..10]].concat(),
            1,
        ),
    ] {
        let attribute = tlv(0x30, &[oid.as_slice(), &tlv(0x31, &values)].concat());
        let cms = cms_with_unsigned(&parts, &signer, Some(&tlv(0xA1, &attribute)));
        let r = report(&embed_raw(&parts.prepared, &cms));
        assert!(
            r.is_valid() && r.problems.is_empty(),
            "{name}: {}",
            summary(&r)
        );
        assert_eq!(r.timestamps.len(), timestamps, "{name}");
        assert_eq!(r.pades_level, None, "{name}");
        for warning in ["could not be read", "not DER-encoded"] {
            assert!(
                r.warnings.iter().any(|w| w.contains(warning)),
                "{name}: {warning}: {:?}",
                r.warnings
            );
        }
    }
    // A sound file has neither warning.
    let r = report(&attack(&mock_tsa()));
    assert!(
        !r.warnings
            .iter()
            .any(|w| w.contains("could not be read") || w.contains("not DER-encoded")),
        "{:?}",
        r.warnings
    );
}

// ---- QA round 4: names OpenSSL cannot convert, GeneralNames it cannot decode (findings 1–3, 6,
// 7) -----------------------------------------------------------------------------------------
//
// Every certificate below is issued at test time by the test root (bt_support::decoys), so the
// tokens are signed and chain as a real TSA's would; `openssl ts -verify` refuses each refused
// one with an ASN.1 decode error (QA's variants of the same names), so Folioxide calls the token
// malformed on both sides (brief §0.1).

use bt_support::decoys::{bmp, test_crl, test_name, tsa_cert_with, ucs4};

/// The single timestamp token of a file whose token `tsa` makes is `TimestampMalformed`, with
/// `why` in its message; the signature itself is sound and B-B.
#[track_caller]
fn assert_malformed_token(name: &str, tsa: &MockTsa, why: &str) {
    let r = report(&attack(tsa));
    assert!(
        r.is_valid() && r.problems.is_empty(),
        "{name}: {}",
        summary(&r)
    );
    assert_eq!(
        r.pades_level,
        Some(PadesLevel::BB),
        "{name}: {}",
        summary(&r)
    );
    let ts = r.timestamp.as_ref().unwrap();
    assert!(
        !ts.intact && !ts.valid && ts.trusted == Some(false),
        "{name}: {ts:?}"
    );
    assert_eq!(token_codes(ts), [ProblemCode::TimestampMalformed], "{name}");
    assert!(ts.problems[0].message.contains(why), "{name}: {ts:?}");
}

/// The token of `tsa` is intact, valid and trusted, and the signature B-T.
#[track_caller]
fn assert_sound_token_of(name: &str, tsa: &MockTsa) {
    let r = report(&attack(tsa));
    assert_eq!(
        r.pades_level,
        Some(PadesLevel::BT),
        "{name}: {}",
        summary(&r)
    );
    let ts = r.timestamp.unwrap();
    assert!(
        ts.intact && ts.valid && ts.trusted == Some(true) && ts.problems.is_empty(),
        "{name}: {ts:?}"
    );
}

/// The `O=Folioxide Test PKI, CN=…` name with a BMPString common name of `units`.
fn bmp_name(units: &[u16]) -> Vec<u8> {
    test_name(bmp(units))
}

#[test]
fn tst_name_strings_openssl_converts() {
    // Finding 1 (variants r5-tsa-subject-c-bmp-*, r5-unused-cert-bmp-*, r5-crl-issuer-bmp-*,
    // r5-tsa-san-dirname-*, fuzz8 n0003–n0006): OpenSSL converts every value of every name it
    // decodes to UTF-8 (x509_name_canon), one UCS-2 code unit per BMPString character, so a
    // surrogate (lone, paired or reversed) or a UniversalString value beyond Unicode is
    // "illegal characters" and the whole token does not decode there.
    const WHY: &str = "OpenSSL cannot convert";
    let root = cert("root.pem");
    let surrogates: [(&str, &[u16]); 7] = [
        ("lone-surrogate", &[0x54, 0xD800]),
        ("surrogate-pair", &[0x54, 0xD83D, 0xDE00]),
        ("low-surrogate-first", &[0xDC00, 0xD800]),
        ("d800", &[0xD800]),
        ("dbff", &[0xDBFF]),
        ("dc00", &[0xDC00]),
        ("dfff", &[0xDFFF]),
    ];
    for (serial, (label, units)) in (0x0A5E_0100..).zip(surrogates) {
        // The TSA certificate's own subject.
        let tsa_cert = tsa_cert_with(serial, &bmp_name(units), &[]);
        assert_malformed_token(
            &format!("r5-tsa-subject-c-bmp-{label}"),
            &mock_for(&tsa_cert, &[&root], defaults()),
            WHY,
        );
        // The same certificate, unused, in the token's set.
        assert_malformed_token(
            &format!("r5-unused-cert-bmp-{label}"),
            &mock(MockTsaOptions {
                extra_certificate_entries: vec![tsa_cert],
                ..defaults()
            }),
            WHY,
        );
        // A CRL's issuer, the ESS issuerSerial name and the TSTInfo tsa directoryName.
        assert_malformed_token(
            &format!("r5-crl-issuer-bmp-{label}"),
            &mock(MockTsaOptions {
                crls: vec![test_crl(&bmp_name(units))],
                ..defaults()
            }),
            WHY,
        );
        assert_malformed_token(
            &format!("ess-issuer-bmp-{label}"),
            &mock(MockTsaOptions {
                ess_issuer_name: Some(bmp_name(units)),
                ..defaults()
            }),
            WHY,
        );
        assert_malformed_token(
            &format!("r5-tsa-dirname-bmp-{label}"),
            &mock(MockTsaOptions {
                tsa_general_name: Some(tokens::der(0xA4, &bmp_name(units))),
                ..defaults()
            }),
            WHY,
        );
    }
    // UniversalString: a surrogate or a value above 10FFFF, in a subjectAltName directoryName
    // the TSTInfo tsa names (r5-tsa-san-dirname-universal-*).
    for (serial, (label, values)) in (0x0A5E_0200..).zip([
        ("universal-surrogate", &[0x54, 0xD800][..]),
        ("universal-above-10ffff", &[0x54, 0x11_0000]),
    ]) {
        let alias = tokens::der(0xA4, &test_name(ucs4(values)));
        let san = bt_support::decoys::extension(
            &[0x55, 0x1D, 0x11],
            false,
            &tokens::seq(std::slice::from_ref(&alias)),
        );
        let tsa_cert = tsa_cert_with(
            serial,
            &bt_support::decoys::subject_of(&cert("tsa.pem")),
            &[san],
        );
        assert_malformed_token(
            &format!("r5-tsa-san-dirname-{label}"),
            &mock_for(
                &tsa_cert,
                &[&root],
                MockTsaOptions {
                    tsa_general_name: Some(alias),
                    ..defaults()
                },
            ),
            WHY,
        );
    }
    // A BMPString surrogate pair in a subjectAltName directoryName the token does not name: the
    // extension does not decode, so it names nothing (TsaNameMismatch for a dNSName listed
    // before it), and the TSA certificate is unsuitable (OpenSSL marks a certificate with an
    // undecodable extension invalid: ruling R-22 (c), QA round 5 finding 37).
    let dns = tokens::der(0x82, b"tsa.example");
    let bad_alias = tokens::der(0xA4, &bmp_name(&[0xD83D, 0xDE00]));
    let san = bt_support::decoys::extension(
        &[0x55, 0x1D, 0x11],
        false,
        &tokens::seq(&[dns.clone(), bad_alias]),
    );
    let tsa_cert = tsa_cert_with(
        0x0A5E_0300,
        &bt_support::decoys::subject_of(&cert("tsa.pem")),
        &[san],
    );
    let ts = timestamp_with(
        &attack(&mock_for(
            &tsa_cert,
            &[&root],
            MockTsaOptions {
                tsa_general_name: Some(dns),
                ..defaults()
            },
        )),
        &VerifyOptions::new().with_trust_anchors_der(anchors()),
    );
    assert!(
        ts.intact && !ts.valid && ts.trusted == Some(false),
        "{ts:?}"
    );
    assert_eq!(
        token_codes(&ts),
        [
            ProblemCode::TsaNameMismatch,
            ProblemCode::TsaCertificateUnsuitable
        ],
        "{ts:?}"
    );

    // Controls OpenSSL converts: NUL, non-characters, the code points around the surrogates.
    for (serial, units) in (0x0A5E_0400..).zip([
        &[0x54, 0x0000][..],
        &[0x54, 0xFFFE],
        &[0x54, 0xFFFF],
        &[0x54, 0xD7FF, 0xE000],
    ]) {
        let tsa_cert = tsa_cert_with(serial, &bmp_name(units), &[]);
        assert_sound_token_of(
            &format!("bmp {units:04x?}"),
            &mock_for(&tsa_cert, &[&root], defaults()),
        );
    }
    assert_sound_token_of(
        "an unused certificate and a CRL with BMPString names that convert",
        &mock(MockTsaOptions {
            extra_certificate_entries: vec![tsa_cert_with(0x0A5E_0500, &bmp_name(&[0xFFFD]), &[])],
            crls: vec![test_crl(&bmp_name(&[0x54, 0xFFFE]))],
            ..defaults()
        }),
    );
}

#[test]
fn tst_universal_string_certificate_names_are_malformed() {
    // Finding 7 (variant r5-tsa-subject-universal-ok), recorded as stricter than both
    // references (brief §0.1): a certificate of the token whose name holds a UniversalString
    // that is valid UCS-4 is malformed to Folioxide, which decodes certificates with x509-cert
    // (its DER layer has no UniversalString tag); OpenSSL and pyHanko accept it. RFC 5280
    // §4.1.2.4 keeps UniversalString only for backward compatibility ("MUST NOT" be used in
    // new certificates for new names).
    let root = cert("root.pem");
    let tsa_cert = tsa_cert_with(0x0A5E_0600, &test_name(ucs4(&[0x54, 0x53, 0x41])), &[]);
    assert_malformed_token(
        "r5-tsa-subject-universal-ok",
        &mock_for(&tsa_cert, &[&root], defaults()),
        "does not parse",
    );
    // Outside a certificate (the TSTInfo tsa directoryName) a valid UniversalString is fine.
    assert_sound_token_of(
        "a tsa directoryName with a UniversalString, compared canonically",
        &mock(MockTsaOptions {
            tsa_general_name: Some(tokens::der(
                0xA4,
                &bt_support::decoys::name_of(&[
                    (
                        bt_support::decoys::O,
                        tokens::der(0x0C, b"Folioxide Test PKI"),
                    ),
                    (
                        &[0x55, 0x04, 0x0B],
                        ucs4(
                            &"TEST ONLY - DO NOT TRUST"
                                .chars()
                                .map(u32::from)
                                .collect::<Vec<_>>(),
                        ),
                    ),
                    (
                        bt_support::decoys::CN,
                        ucs4(
                            &"Folioxide Test TSA"
                                .chars()
                                .map(u32::from)
                                .collect::<Vec<_>>(),
                        ),
                    ),
                ]),
            )),
            ..defaults()
        }),
    );
}

#[test]
fn tst_tsa_general_name_decodes() {
    // Finding 2 (variants r5-tsa-gn-*): the TSTInfo tsa GeneralName is decoded as OpenSSL's
    // GENERAL_NAME template reads it, every choice; a name it cannot decode (no matching choice
    // type, wrong tag, explicit tag not constructed) makes `ts -verify` refuse the token.
    const WHY: &str = "tsa is a GeneralName that does not decode";
    let oid = tokens::oid(&tokens::test_oid(8));
    let utf8 = tokens::der(0x0C, b"Folioxide");
    let subject = bt_support::decoys::subject_of(&cert("tsa.pem"));
    for (name, general_name) in [
        ("r5-tsa-gn-edi-junk-int", tokens::der(0xA5, &tokens::int(1))),
        (
            "r5-tsa-gn-edi-no-partyname",
            tokens::der(0xA5, &tokens::der(0xA0, &utf8)),
        ),
        (
            "r5-tsa-gn-othername-junk-int",
            tokens::der(0xA0, &[tokens::int(1), tokens::der(0xA0, &utf8)].concat()),
        ),
        (
            "r5-tsa-gn-othername-no-explicit-value",
            tokens::der(0xA0, &oid),
        ),
        ("r5-tsa-gn-x400-primitive", tokens::der(0x83, b"x400")),
        ("r5-tsa-gn-rid-constructed", tokens::der(0xA8, &oid)),
        ("r5-tsa-gn-unknown-ctx9", tokens::der(0x89, b"tsa")),
        (
            "r5-tsa-gn-unknown-ctx10-constructed",
            tokens::der(0xAA, &utf8),
        ),
        ("r5-tsa-gn-universal-null", vec![0x05, 0x00]),
        ("r5-tsa-gn-universal-int", tokens::int(1)),
        ("r5-tsa-gn-universal-utf8", utf8.clone()),
        ("r5-tsa-gn-dirname-primitive", tokens::der(0x84, &subject)),
        (
            "r5-tsa-gn-dns-constructed",
            tokens::der(0xA2, &tokens::der(0x16, b"tsa.example")),
        ),
        (
            "r5-tsa-gn-ip-constructed",
            tokens::der(0xA7, &tokens::octets(&[127, 0, 0, 1])),
        ),
    ] {
        assert_malformed_token(
            name,
            &mock(MockTsaOptions {
                tsa_general_name: Some(general_name),
                ..defaults()
            }),
            WHY,
        );
    }

    // Controls OpenSSL accepts (r5-tsa-gn-othername-valid, -edi-valid, uri, ip, rfc822,
    // rid-valid): each choice, named by a subjectAltName entry of the TSA certificate with the
    // same bytes. (pyHanko's asn1crypto cannot parse some of these subjectAltName entries and
    // does not trust the TSA there; QA waived that.)
    let controls = [
        tokens::der(0xA0, &[oid.clone(), tokens::der(0xA0, &utf8)].concat()),
        tokens::der(
            0xA5,
            &[
                tokens::der(0xA0, &tokens::der(0x13, b"assigner")),
                tokens::der(0xA1, &utf8),
            ]
            .concat(),
        ),
        tokens::der(0x86, b"https://tsa.example/"),
        tokens::der(0x87, &[192, 0, 2, 1]),
        tokens::der(0x81, b"tsa@example.org"),
        tokens::der(0x88, &tokens::test_oid(9)),
        tokens::der(0x82, b"tsa.example"),
        tokens::der(0xA3, &tokens::seq(&[])),
    ];
    let san = bt_support::decoys::extension(&[0x55, 0x1D, 0x11], false, &tokens::seq(&controls));
    let tsa_cert = tsa_cert_with(0x0A5E_0700, &subject, &[san]);
    let root = cert("root.pem");
    for general_name in controls {
        assert_sound_token_of(
            &format!("{general_name:02x?}"),
            &mock_for(
                &tsa_cert,
                &[&root],
                MockTsaOptions {
                    tsa_general_name: Some(general_name),
                    ..defaults()
                },
            ),
        );
    }
    // A name the subjectAltName does not hold is still a mismatch.
    let ts = report(&attack(&mock_for(
        &tsa_cert,
        &[&root],
        MockTsaOptions {
            tsa_general_name: Some(tokens::der(0x82, b"other.example")),
            ..defaults()
        },
    )))
    .timestamp
    .unwrap();
    assert_eq!(token_codes(&ts), [ProblemCode::TsaNameMismatch], "{ts:?}");
}

#[test]
fn tst_damaged_timestamp_attribute_makes_the_cms_malformed() {
    // Finding 6: unsigned attributes are part of the SignerInfo's syntax (RFC 5652 §5.3), so an
    // id-aa-signatureTimeStampToken attribute that is not an Attribute (its values not a SET,
    // or no values at all) makes the whole CMS malformed, as for pyHanko, which cannot read
    // such a file either; only a token that is a well-formed attribute value stays in the
    // timestamp's own problems (D-6). The documentation says so (report.rs, README).
    let signer = rsa2048();
    let parts = parts(&signer, time());
    let token = mock_tsa().token_for(&parts.request).unwrap();
    let oid = [
        0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
    ];
    for (name, attribute) in [
        (
            "tok-attr-values-not-a-set",
            tlv(0x30, &[oid.as_slice(), &tlv(0x30, &token)].concat()),
        ),
        ("tok-attr-without-values", tlv(0x30, &oid)),
        (
            "r5-warn-attr-type-not-oid",
            tlv(
                0x30,
                &[&[0x02, 0x01, 0x01][..], &tlv(0x31, &token)].concat(),
            ),
        ),
    ] {
        let cms = cms_with_unsigned(&parts, &signer, Some(&tlv(0xA1, &attribute)));
        let r = report(&embed_raw(&parts.prepared, &cms));
        assert!(!r.intact && !r.signature_valid, "{name}: {}", summary(&r));
        assert!(
            r.problems
                .iter()
                .any(|p| p.code == ProblemCode::CmsMalformed),
            "{name}: {}",
            summary(&r)
        );
    }
}

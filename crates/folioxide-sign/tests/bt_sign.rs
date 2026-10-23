#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! PAdES B-T signing (M4 brief §3.1, §4.2–§4.5, §6.2 "B-T"): the one-step [`sign`] with a
//! timestamper, the two-phase `timestamp_request` / `finish_with_timestamp`, the retry on token
//! overflow, the committed OpenSSL reply through the external path, and `embed_cms` with
//! timestamp tokens.

mod bt_support;

use std::sync::atomic::{AtomicUsize, Ordering};

use bt_support::*;
use folioxide_sign::Error;
use folioxide_sign::algorithms::{DigestAlgorithm, KeyKind, SignatureAlgorithm};
use folioxide_sign::bt::TimestampParams;
use folioxide_sign::cms;
use folioxide_sign::field::SubFilter;
use folioxide_sign::prepare::{PrepareRequest, PreparedSignature, SignatureOptions, prepare};
use folioxide_sign::report::PadesLevel;
use folioxide_sign::sign::{SignRequest, sign};
use folioxide_sign::signer::{LocalSigner, Signer};
use folioxide_sign::tsp::{DEFAULT_TSA_RESERVE, TimeStampReq, Timestamper};
use folioxide_syntax::ErrorCode;
use folioxide_testkit::tsa::{Echo, MockTsaOptions};

/// Prepares `minimal.pdf` for `signer` with `options`.
fn prepared(signer: &LocalSigner, options: SignatureOptions) -> PreparedSignature {
    let request = PrepareRequest::new(
        signer.certificate_chain().to_vec(),
        signer.algorithm(),
        time(),
    )
    .with_options(options);
    prepare(&open(&minimal()), &request).unwrap()
}

/// The default B-T options: [`DEFAULT_TSA_RESERVE`] bytes of token budget.
fn bt_options() -> SignatureOptions {
    SignatureOptions::new(time()).with_tsa_reserve(Some(DEFAULT_TSA_RESERVE))
}

fn params() -> TimestampParams {
    TimestampParams::new().with_nonce(Some(NONCE))
}

#[test]
fn sign_bt_mock_tsa() {
    for (name, signer) in [("P-256", p256()), ("RSA-2048", rsa2048())] {
        let signed = sign_bt(&minimal(), &signer);
        let reports = verify(&signed);
        let [r] = reports.as_slice() else {
            panic!("{name}: one report")
        };
        assert!(r.is_valid(), "{name}: {}", summary(r));
        assert_eq!(r.trusted, Some(true), "{name}: {}", summary(r));
        assert_eq!(
            r.pades_level,
            Some(PadesLevel::BT),
            "{name}: {}",
            summary(r)
        );
        let ts = r.timestamp.as_ref().unwrap();
        assert!(ts.intact && ts.valid, "{name}: {ts:?}");
        assert_eq!(ts.trusted, Some(true), "{name}: {ts:?}");
        // The mock's genTime, 20261010120030Z.
        assert_eq!(ts.gen_time, "2026-10-10T12:00:30Z");
        assert_eq!(r.timestamps.len(), 1);
        assert!(ts.problems.is_empty(), "{ts:?}");
        // The signature carries exactly one token, over its value.
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.contains("claimed signing time (/M)")),
            "V9: the signer is validated at the trusted genTime: {:?}",
            r.warnings
        );
    }
}

#[test]
fn sign_bt_two_phase_matches_one_step() {
    for signer in [rsa2048(), p256()] {
        let one_step = sign_bt(&minimal(), &signer);

        let prepared = prepared(&signer, bt_options());
        let value = signer
            .sign(prepared.digest_algorithm(), prepared.to_be_signed())
            .unwrap();
        let request = prepared.timestamp_request(&value, &params()).unwrap();
        let response = mock_tsa().respond(&request);
        let two_phase = prepared
            .finish_with_timestamp(&value, &request, &response)
            .unwrap();
        assert_eq!(one_step, two_phase, "{:?}", signer.key_kind());
    }
}

/// The DER `ECDSA-Sig-Value` as IEEE P1363 `r || s` of `field` bytes each.
fn p1363(der: &[u8], field: usize) -> Vec<u8> {
    assert_eq!(der[0], 0x30);
    let mut pos = 2;
    let mut out = Vec::new();
    for _ in 0..2 {
        assert_eq!(der[pos], 0x02);
        let len = usize::from(der[pos + 1]);
        let int = &der[pos + 2..pos + 2 + len];
        let int = &int[int.len().saturating_sub(field)..];
        out.extend(std::iter::repeat_n(0, field - int.len()));
        out.extend_from_slice(int);
        pos += 2 + len;
    }
    out
}

#[test]
fn bt_request_imprint_over_normalized_ecdsa_value() {
    let signer = p256();
    let prepared = prepared(&signer, bt_options());
    let der = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let raw = p1363(&der, 32);
    assert_eq!(raw.len(), 64);
    let from_raw = prepared.timestamp_request(&raw, &params()).unwrap();
    let from_der = prepared.timestamp_request(&der, &params()).unwrap();
    assert_eq!(
        from_raw, from_der,
        "the imprint covers the normalized (DER) value"
    );
    let request = TimeStampReq::from_der(&from_raw).unwrap();
    assert_eq!(request.imprint.digest, DigestAlgorithm::Sha256);
    assert_eq!(
        request.imprint.hashed_message,
        DigestAlgorithm::Sha256.digest(&[&der])
    );
    assert_ne!(
        request.imprint.hashed_message,
        DigestAlgorithm::Sha256.digest(&[&raw])
    );
    assert!(request.cert_req);
    assert_eq!(request.nonce.as_deref(), Some(&NONCE.to_be_bytes()[..]));

    // finish_with_timestamp accepts the P1363 value too, and the token covers the DER value.
    let response = mock_tsa().respond(&from_raw);
    let signed = prepared
        .finish_with_timestamp(&raw, &from_raw, &response)
        .unwrap();
    let r = &verify(&signed)[0];
    assert_eq!(r.pades_level, Some(PadesLevel::BT), "{}", summary(r));
}

#[test]
fn bt_request_parameters() {
    let signer = rsa2048();
    let prepared = prepared(&signer, bt_options());
    let value = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    // The imprint digest defaults to the signature's and can be chosen.
    let sha512 = params().with_digest(Some(DigestAlgorithm::Sha512));
    let request =
        TimeStampReq::from_der(&prepared.timestamp_request(&value, &sha512).unwrap()).unwrap();
    assert_eq!(request.imprint.digest, DigestAlgorithm::Sha512);
    let policy = params().with_policy(Some("1.2.3.4.5".into()));
    let request =
        TimeStampReq::from_der(&prepared.timestamp_request(&value, &policy).unwrap()).unwrap();
    assert_eq!(request.policy.as_deref(), Some("1.2.3.4.5"));
    // Refused: SHA-1, a policy that is not an OID, a value by another key.
    let sha1 = params().with_digest(Some(DigestAlgorithm::Sha1));
    let err = prepared.timestamp_request(&value, &sha1).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    let bad_policy = params().with_policy(Some("policy".into()));
    let err = prepared.timestamp_request(&value, &bad_policy).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    let err = prepared
        .timestamp_request(&[1; 256], &params())
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::SignatureInvalid, "{err}");
    // The nonce is a positive INTEGER (brief §4.1; ruling R-24, QA round 5 finding 4): 0 is
    // refused, 1 and 2^64 - 1 are the bounds.
    let zero = TimestampParams::new().with_nonce(Some(0));
    let err = prepared.timestamp_request(&value, &zero).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    assert!(err.to_string().contains("positive"), "{err}");
    for nonce in [1, u64::MAX] {
        let request = TimeStampReq::from_der(
            &prepared
                .timestamp_request(&value, &TimestampParams::new().with_nonce(Some(nonce)))
                .unwrap(),
        )
        .unwrap();
        let expected = TimeStampReq::new(request.imprint.clone(), Some(nonce), None);
        assert_eq!(request.nonce, expected.nonce, "{nonce}");
    }
    // The one-shot sign refuses it too, before the TSA is asked.
    let asked = AtomicUsize::new(0);
    let counting = |request: &[u8]| -> folioxide_sign::Result<Vec<u8>> {
        asked.fetch_add(1, Ordering::SeqCst);
        Err(Error::InvalidArgument(format!("{} bytes", request.len())))
    };
    let err = sign(
        &open(&minimal()),
        &SignRequest::new(&signer, time())
            .with_options(bt_options())
            .with_timestamper(&counting, zero),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    assert!(err.to_string().contains("positive"), "{err}");
    assert_eq!(asked.load(Ordering::SeqCst), 0);
    // Without a nonce: a random one (sys-rng is a default feature), never 0.
    let a = prepared
        .timestamp_request(&value, &TimestampParams::new())
        .unwrap();
    let b = prepared
        .timestamp_request(&value, &TimestampParams::new())
        .unwrap();
    assert_ne!(a, b, "two random nonces");
    for request in [&a, &b] {
        let nonce = TimeStampReq::from_der(request).unwrap().nonce.unwrap();
        assert!(nonce.iter().any(|&b| b != 0), "{nonce:02x?}");
    }
}

#[test]
fn bt_default_tsa_reserve_8192() {
    let signer = rsa2048();
    let signed = sign_bt(&minimal(), &signer);
    let budgeted = prepared(&signer, bt_options());
    let unbudgeted = prepared(&signer, SignatureOptions::new(time()));
    assert!(budgeted.contents_capacity() > unbudgeted.contents_capacity());
    // The signed file has exactly the budgeted placeholder.
    let contents = |pdf: &[u8]| {
        let at = pdf.windows(10).rposition(|w| w == b"/Contents ").unwrap();
        let start = at + pdf[at..].iter().position(|&b| b == b'<').unwrap();
        let end = start + pdf[start..].iter().position(|&b| b == b'>').unwrap();
        (end - start - 1) / 2
    };
    assert_eq!(contents(&signed), budgeted.contents_capacity());
    assert_eq!(contents(budgeted.pdf()), budgeted.contents_capacity());
    // An explicit tsa_reserve is used as given.
    let small = SignatureOptions::new(time()).with_tsa_reserve(Some(4096));
    let signed = sign_bt_with(&minimal(), &signer, small.clone(), &Tsa(mock_tsa())).unwrap();
    assert_eq!(
        contents(&signed),
        prepared(&signer, small).contents_capacity()
    );
}

/// A signer that counts its calls.
struct Counting<'a>(&'a LocalSigner, AtomicUsize);

impl Signer for Counting<'_> {
    fn certificate_chain(&self) -> &[Vec<u8>] {
        self.0.certificate_chain()
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
    fn key_kind(&self) -> KeyKind {
        self.0.key_kind()
    }
    fn sign(&self, digest: DigestAlgorithm, data: &[u8]) -> folioxide_sign::Result<Vec<u8>> {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0.sign(digest, data)
    }
}

/// A timestamper that counts its calls.
struct CountingTsa(Tsa, AtomicUsize);

impl Timestamper for CountingTsa {
    fn timestamp(&self, request: &[u8]) -> folioxide_sign::Result<Vec<u8>> {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0.timestamp(request)
    }
}

/// A mock TSA whose tokens carry the root eight times over: about 12 KB, more than the default
/// budget.
fn big_tsa() -> Tsa {
    let key = tsa_key("tsa.pem");
    Tsa(folioxide_testkit::tsa::MockTsa::new(
        cert("tsa.pem"),
        vec![cert("root.pem"); 8],
        Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
    ))
}

#[test]
fn bt_token_overflow_reports_needed_and_sign_retries_once() {
    let signer = rsa2048();
    let prepared = prepared(&signer, bt_options());
    let reserved = prepared.contents_capacity();
    let value = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let request = prepared.timestamp_request(&value, &params()).unwrap();
    let response = big_tsa().0.respond(&request);
    let (err, back) = prepared
        .try_finish_with_timestamp(&value, &request, &response)
        .unwrap_err()
        .into_parts();
    let Error::PlaceholderTooSmall {
        needed,
        reserved: got,
    } = err
    else {
        panic!("{err}")
    };
    assert_eq!(got, reserved);
    assert!(needed > reserved, "{needed} > {reserved}");

    // Preparing again with exactly `needed` fits the same token.
    let again = self::prepared(&signer, bt_options().with_contents_reserve(Some(needed)));
    let value = signer
        .sign(again.digest_algorithm(), again.to_be_signed())
        .unwrap();
    let request = again.timestamp_request(&value, &params()).unwrap();
    let response = big_tsa().0.respond(&request);
    let signed = again
        .finish_with_timestamp(&value, &request, &response)
        .unwrap();
    assert_eq!(verify(&signed)[0].pades_level, Some(PadesLevel::BT));
    drop(back);

    // sign(): one retry, the signer and the TSA are each called twice.
    let counting = Counting(&signer, AtomicUsize::new(0));
    let tsa = CountingTsa(big_tsa(), AtomicUsize::new(0));
    let signed = sign(
        &open(&minimal()),
        &SignRequest::new(&counting, time()).with_timestamper(&tsa, params()),
    )
    .unwrap();
    assert_eq!(counting.1.load(Ordering::SeqCst), 2);
    assert_eq!(tsa.1.load(Ordering::SeqCst), 2);
    let r = &verify(&signed)[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.pades_level, Some(PadesLevel::BT), "{}", summary(r));
}

#[test]
fn bt_finish_rejects_response_for_other_request() {
    let signer = p256();
    let prepared = prepared(&signer, bt_options());
    let value = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let request = prepared.timestamp_request(&value, &params()).unwrap();
    let tsa = mock_tsa();
    // A response to a request with another nonce: refused at the nonce check.
    let other_nonce = prepared
        .timestamp_request(&value, &TimestampParams::new().with_nonce(Some(7)))
        .unwrap();
    let (err, prepared) = prepared
        .try_finish_with_timestamp(&value, &request, &tsa.respond(&other_nonce))
        .unwrap_err()
        .into_parts();
    assert_eq!(err.code(), ErrorCode::TimestampInvalid);
    assert!(err.to_string().contains("nonce"), "{err}");
    // A response over other data: refused at the imprint check.
    let other_data = TimeStampReq::new(
        folioxide_sign::tsp::MessageImprint::new(DigestAlgorithm::Sha256, vec![9; 32]),
        Some(NONCE),
        None,
    )
    .to_der();
    let (err, prepared) = prepared
        .try_finish_with_timestamp(&value, &request, &tsa.respond(&other_data))
        .unwrap_err()
        .into_parts();
    assert!(err.to_string().contains("messageImprint"), "{err}");
    // The prepared signature came back unchanged: the right response still finishes it.
    let signed = prepared
        .finish_with_timestamp(&value, &request, &tsa.respond(&request))
        .unwrap();
    assert_eq!(verify(&signed)[0].pades_level, Some(PadesLevel::BT));
}

#[test]
fn bt_finish_rejects_request_for_other_signature() {
    let signer = rsa2048();
    let first = prepared(&signer, bt_options());
    let other = prepared(&signer, bt_options().with_reason(Some("another".into())));
    let value = signer
        .sign(first.digest_algorithm(), first.to_be_signed())
        .unwrap();
    let other_value = signer
        .sign(other.digest_algorithm(), other.to_be_signed())
        .unwrap();
    let other_request = other.timestamp_request(&other_value, &params()).unwrap();
    let response = mock_tsa().respond(&other_request);
    // The response answers its request (steps 1–8), but the request is another signature's.
    let err = first
        .clone()
        .finish_with_timestamp(&value, &other_request, &response)
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::TimestampInvalid);
    assert!(
        err.to_string().contains("not this signature's request"),
        "{err}"
    );
    // A request without certReq.
    let mut no_cert =
        TimeStampReq::from_der(&first.timestamp_request(&value, &params()).unwrap()).unwrap();
    no_cert.cert_req = false;
    let no_cert = no_cert.to_der();
    let err = first
        .clone()
        .finish_with_timestamp(&value, &no_cert, &mock_tsa().respond(&no_cert))
        .unwrap_err();
    assert!(err.to_string().contains("certReq"), "{err}");
    // A request that does not parse.
    let err = first
        .finish_with_timestamp(&value, b"garbage", &response)
        .unwrap_err();
    assert!(err.to_string().contains("does not parse"), "{err}");
}

#[test]
fn bt_external_openssl_token_embedded() {
    // The deterministic RSA signature value of `minimal.pdf` (RSA PKCS#1 v1.5 is
    // deterministic, and so is prepare), timestamped by `openssl ts -reply` with
    // tools/tsa/openssl-tsa.cnf over the request below (nonce NONCE).
    let signer = rsa2048();
    let prepared = prepared(&signer, bt_options());
    let value = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let request = prepared.timestamp_request(&value, &params()).unwrap();
    if let Some(out) = std::env::var_os("FOLIOXIDE_TSA_REQUEST_OUT") {
        // tools/fixtures/sign.py --only tsa: write the request to answer.
        std::fs::write(out, &request).unwrap();
        return;
    }
    assert_eq!(
        request,
        tsa_fixture("openssl-reply.tsq"),
        "fixtures/sign/tsa/openssl-reply.tsq is stale (the signed bytes changed): regenerate \
         it with `.venv/bin/python -I tools/fixtures/sign.py --only tsa` (brief R-15)"
    );
    let response = tsa_fixture("openssl-reply.tsr");
    let signed = prepared
        .finish_with_timestamp(&value, &request, &response)
        .unwrap();
    let r = &verify(&signed)[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.pades_level, Some(PadesLevel::BT), "{}", summary(r));
    let ts = r.timestamp.as_ref().unwrap();
    assert!(ts.intact && ts.valid && ts.trusted == Some(true), "{ts:?}");
    assert_eq!(ts.policy.as_deref(), Some("1.2.3.4.1"));
    assert_eq!(ts.accuracy_micros, Some(1_000_000));
    assert!(
        ts.tsa_name
            .as_deref()
            .is_some_and(|n| n.contains("Folioxide Test TSA"))
    );
    assert_eq!(
        ts.tsa.as_ref().and_then(|c| c.common_name.as_deref()),
        Some("Folioxide Test TSA")
    );
    assert_eq!(
        ts.signature_algorithm.as_deref(),
        Some("sha256WithRSAEncryption")
    );
}

/// A complete B-T CMS for `prepared`, made outside Folioxide's finish: the value, a token from
/// `tsa` over it, assembled with the token.
fn external_cms(
    prepared: &PreparedSignature,
    signer: &LocalSigner,
    tsa: &folioxide_testkit::tsa::MockTsa,
) -> Vec<u8> {
    let value = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let request = prepared.timestamp_request(&value, &params()).unwrap();
    let token = tsa.token_for(&request).unwrap();
    cms::assemble_with_timestamp(
        prepared.to_be_signed(),
        &value,
        signer.certificate_chain(),
        signer.algorithm(),
        signer.key_kind(),
        prepared.digest_algorithm(),
        &token,
    )
    .unwrap()
}

#[test]
fn embed_cms_with_valid_token_accepted() {
    let signer = p256();
    let prepared = prepared(&signer, bt_options());
    let cms_der = external_cms(&prepared, &signer, &mock_tsa());
    let signed = prepared.embed_cms(&cms_der).unwrap();
    let r = &verify(&signed)[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.pades_level, Some(PadesLevel::BT), "{}", summary(r));
}

#[test]
fn embed_cms_with_invalid_token_rejected() {
    let signer = p256();
    let prepared = prepared(&signer, bt_options());
    let over_other_bytes = mock_tsa_with(
        "tsa.pem",
        MockTsaOptions {
            imprint: Echo::Replace(vec![0x42; 32]),
            ..MockTsaOptions::default()
        },
    );
    let cms_der = external_cms(&prepared, &signer, &over_other_bytes);
    let (err, prepared) = prepared.try_embed_cms(&cms_der).unwrap_err().into_parts();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.to_string()
            .contains("the CMS's signature timestamp is not valid"),
        "{err}"
    );
    assert!(err.to_string().contains("messageImprint"), "{err}");
    // A token by an unsuitable TSA certificate is refused the same way.
    let noncritical = mock_tsa_with("tsa-eku-noncritical.pem", MockTsaOptions::default());
    let cms_der = external_cms(&prepared, &signer, &noncritical);
    let err = prepared.embed_cms(&cms_der).unwrap_err();
    assert!(err.to_string().contains("not critical"), "{err}");
}

#[test]
fn bt_adbe_pkcs7_detached_timestamped() {
    let signer = rsa2048();
    let options = SignatureOptions::new(time()).with_sub_filter(SubFilter::AdbePkcs7Detached);
    let signed = sign_bt_with(&minimal(), &signer, options, &Tsa(mock_tsa())).unwrap();
    let r = &verify(&signed)[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.sub_filter.as_deref(), Some("adbe.pkcs7.detached"));
    assert_eq!(r.pades_level, None, "not PAdES");
    let ts = r.timestamp.as_ref().unwrap();
    assert!(ts.intact && ts.valid && ts.trusted == Some(true), "{ts:?}");
}

#[test]
fn bt_timestamper_failures_and_refusals_are_errors() {
    let signer = p256();
    // A transport failure, by the Timestamper convention.
    let failing = |_: &[u8]| -> folioxide_sign::Result<Vec<u8>> {
        Err(Error::TimestampInvalid(
            "TSA request failed: connection refused".into(),
        ))
    };
    let err =
        sign_bt_with(&minimal(), &signer, SignatureOptions::new(time()), &failing).unwrap_err();
    assert_eq!(err.code(), ErrorCode::TimestampInvalid);
    assert!(err.to_string().contains("TSA request failed"), "{err}");
    // A refusal names the status, its text and the failure bits.
    let refusing = Tsa(mock_tsa_with(
        "tsa.pem",
        MockTsaOptions {
            status: 2,
            status_string: Some("policy not accepted".into()),
            fail_info: Some(1 << 15),
            ..MockTsaOptions::default()
        },
    ));
    let err = sign_bt_with(
        &minimal(),
        &signer,
        SignatureOptions::new(time()),
        &refusing,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "timestamp invalid: TSA refused: status 2, \"policy not accepted\", failInfo \
         unacceptedPolicy"
    );
}

#[test]
fn bt_sign_refuses_tokens_openssl_cannot_decode() {
    // QA round 3 finding 5: `sign` (signPdf in Node) embedded tokens whose ESS policies, ESS
    // issuer name, TSTInfo extensions or signed-attribute encoding OpenSSL's `ts -verify` refuses.
    // The response check is the verifier's whitelist, so it refuses them now.
    use bt_support::tokens;
    let issuer = bt_support::decoys::issuer_of(&cert("tsa.pem"));
    for (name, options) in [
        (
            "ts-sign-ess-policies-junk",
            MockTsaOptions {
                ess_policies: Some(tokens::seq(&[tokens::seq(&[tokens::int(1)])])),
                ..MockTsaOptions::default()
            },
        ),
        (
            "ts-sign-ess-issuer-visible",
            MockTsaOptions {
                ess_issuer_name: Some(bt_support::decoys::reencode_name(&issuer, 0x1A, false)),
                ..MockTsaOptions::default()
            },
        ),
        (
            "ts-sign-tst-ext-junk",
            MockTsaOptions {
                tst_extensions: Some(tokens::tst_extensions(&[tokens::octets(b"zz")])),
                ..MockTsaOptions::default()
            },
        ),
        (
            "ts-sign-sattr-indef",
            MockTsaOptions {
                signed_attrs_encoding: Some(tokens::attributes_indefinite),
                ..MockTsaOptions::default()
            },
        ),
        (
            "ts-sign-sattr-unsorted",
            MockTsaOptions {
                extra_signed_attributes: vec![tokens::unsorted_attribute(
                    &tokens::SIGNING_TIME,
                    &[
                        tokens::utc_time("261010120030Z"),
                        tokens::utc_time("261010120031Z"),
                    ],
                )],
                ..MockTsaOptions::default()
            },
        ),
        // QA round 4 finding 4 (the signing side of findings 1 and 2).
        (
            "ts-sign-r5-crl-bmp-lone-surrogate",
            MockTsaOptions {
                crls: vec![bt_support::decoys::test_crl(
                    &bt_support::decoys::test_name(bt_support::decoys::bmp(&[0x54, 0xD800])),
                )],
                ..MockTsaOptions::default()
            },
        ),
        (
            "ts-sign-r5-tsa-gn-universal-null",
            MockTsaOptions {
                tsa_general_name: Some(vec![0x05, 0x00]),
                ..MockTsaOptions::default()
            },
        ),
        (
            "ts-sign-r5-tsa-gn-unknown-ctx9",
            MockTsaOptions {
                tsa_general_name: Some(tokens::der(0x89, b"tsa")),
                ..MockTsaOptions::default()
            },
        ),
    ] {
        let tsa = Tsa(mock_tsa_with("tsa.pem", options));
        let err =
            sign_bt_with(&minimal(), &p256(), SignatureOptions::new(time()), &tsa).unwrap_err();
        assert_eq!(err.code(), ErrorCode::TimestampInvalid, "{name}: {err}");
    }
    // ts-sign-r5-cert-subject-bmp-lone-surrogate: the TSA certificate's own subject.
    let surrogate_tsa = bt_support::decoys::tsa_cert_with(
        0x0A5E_0900,
        &bt_support::decoys::test_name(bt_support::decoys::bmp(&[0x54, 0xD800])),
        &[],
    );
    let key = tsa_key("tsa.pem");
    let tsa = Tsa(folioxide_testkit::tsa::MockTsa::new(
        surrogate_tsa.clone(),
        vec![cert("root.pem")],
        Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
    ));
    let err = sign_bt_with(&minimal(), &p256(), SignatureOptions::new(time()), &tsa).unwrap_err();
    assert_eq!(err.code(), ErrorCode::TimestampInvalid, "{err}");
    assert!(err.to_string().contains("surrogate"), "{err}");
}

#[test]
fn embed_cms_refuses_tokens_openssl_cannot_decode() {
    // QA round 4 finding 4 (ts-embed-r5-*): `embed_cms` (Node `PreparedSignature.embedCms`)
    // checks the token of the caller's CMS with the verifier's whitelist, so it refuses the
    // same tokens as `sign`.
    use bt_support::tokens;
    let signer = p256();
    let surrogate_name = bt_support::decoys::test_name(bt_support::decoys::bmp(&[0x54, 0xD800]));
    let surrogate_tsa = bt_support::decoys::tsa_cert_with(0x0A5E_0A00, &surrogate_name, &[]);
    let key = tsa_key("tsa.pem");
    let cases = [
        (
            "ts-embed-r5-cert-subject-bmp-lone-surrogate",
            folioxide_testkit::tsa::MockTsa::new(
                surrogate_tsa,
                vec![cert("root.pem")],
                Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
            ),
        ),
        (
            "ts-embed-r5-crl-bmp-lone-surrogate",
            mock_tsa_with(
                "tsa.pem",
                MockTsaOptions {
                    crls: vec![bt_support::decoys::test_crl(&surrogate_name)],
                    ..MockTsaOptions::default()
                },
            ),
        ),
        (
            "ts-embed-r5-tsa-gn-universal-null",
            mock_tsa_with(
                "tsa.pem",
                MockTsaOptions {
                    tsa_general_name: Some(vec![0x05, 0x00]),
                    ..MockTsaOptions::default()
                },
            ),
        ),
        (
            "ts-embed-r5-tsa-gn-unknown-ctx9",
            mock_tsa_with(
                "tsa.pem",
                MockTsaOptions {
                    tsa_general_name: Some(tokens::der(0x89, b"tsa")),
                    ..MockTsaOptions::default()
                },
            ),
        ),
    ];
    for (name, tsa) in cases {
        let prepared = prepared(&signer, bt_options());
        let cms_der = external_cms(&prepared, &signer, &tsa);
        let err = prepared.embed_cms(&cms_der).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{name}: {err}");
        assert!(
            err.to_string()
                .contains("the CMS's signature timestamp is not valid"),
            "{name}: {err}"
        );
    }
}

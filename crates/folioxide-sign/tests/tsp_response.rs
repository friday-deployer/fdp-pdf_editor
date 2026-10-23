#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! RFC 3161 responses and tokens (M4 brief §4.1, §4.2, §5 V7b; §6.2 "TSP"): response
//! validation on the signing side (`validate_response`, every ordered check), token
//! verification on the verification side (`verify_token`, its problem codes), the TSA
//! certificate rules (D-4), `genTime`, and the interoperability fixtures made by `openssl ts
//! -reply` and pyHanko's DummyTimeStamper.

mod bt_support;

use bt_support::tokens;
use bt_support::*;
use folioxide_sign::ProblemCode;
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::signer::Signer as _;
use folioxide_sign::tsp::{
    self, GenTime, MessageImprint, PkiStatus, TimeStampReq, TimeStampResp, TokenVerification,
    TstInfo, ValidatedToken,
};
use folioxide_sign::x509info::check_tsa_certificate;
use folioxide_syntax::ErrorCode;
use folioxide_testkit::tsa::{Echo, Ess, MockTsaOptions};

/// The timestamped data of these tests.
const DATA: &[u8] = b"the signature value";

/// The request over [`DATA`] with `digest` and nonce [`NONCE`].
fn request_with(digest: DigestAlgorithm, policy: Option<&str>) -> TimeStampReq {
    let imprint = MessageImprint::new(digest, digest.digest(&[DATA]));
    TimeStampReq::new(imprint, Some(NONCE), policy.map(str::to_owned))
}

fn request() -> TimeStampReq {
    request_with(DigestAlgorithm::Sha256, None)
}

/// The mock's response to [`request`] with `options` and the TSA certificate `cert`.
fn respond(cert: &str, options: MockTsaOptions) -> Vec<u8> {
    mock_tsa_with(cert, options).respond(&request().to_der())
}

fn validate(response: &[u8]) -> folioxide_sign::Result<ValidatedToken> {
    tsp::validate_response(&request(), response)
}

/// The error message of a refused response, asserting its code.
fn refused(response: &[u8]) -> String {
    let err = validate(response).unwrap_err();
    assert_eq!(err.code(), ErrorCode::TimestampInvalid, "{err}");
    err.to_string()
}

/// The token of a response.
fn token_of(response: &[u8]) -> Vec<u8> {
    TimeStampResp::from_der(response).unwrap().token.unwrap()
}

/// `verify_token` over [`DATA`].
fn verify_token(token: &[u8]) -> TokenVerification {
    tsp::verify_token(token, &|d| Some(d.digest(&[DATA])), &[])
}

fn codes(v: &TokenVerification) -> Vec<ProblemCode> {
    v.problems.iter().map(|p| p.code).collect()
}

fn options() -> MockTsaOptions {
    MockTsaOptions::default()
}

#[test]
fn mock_tsa_response_validates() {
    let response = respond("tsa.pem", options());
    let validated = validate(&response).unwrap();
    assert!(validated.warnings.is_empty(), "{:?}", validated.warnings);
    assert_eq!(validated.tsa_cert_der, cert("tsa.pem"));
    assert_eq!(validated.token_der, token_of(&response));
    let tst = &validated.tst_info;
    assert_eq!(tst.version, 1);
    assert_eq!(tst.policy, "1.2.3.4.1");
    assert_eq!(tst.serial, [1]);
    assert_eq!(tst.gen_time.to_rfc3339(), "2026-10-10T12:00:30Z");
    assert_eq!(tst.accuracy.as_ref().unwrap().seconds, Some(1));
    assert_eq!(tst.nonce.as_deref(), Some(&NONCE.to_be_bytes()[..]));
    assert_eq!(tst.imprint, request().imprint);
    assert!(!tst.ordering && !tst.has_extensions);
    assert_eq!(tst.tsa_name, None);
    // TstInfo::from_der on the token's eContent agrees.
    let parsed = folioxide_sign::cms::parse(&validated.token_der).unwrap();
    assert_eq!(
        TstInfo::from_der(parsed.econtent.as_deref().unwrap()).unwrap(),
        *tst
    );
    // The verification side agrees too.
    let v = verify_token(&validated.token_der);
    assert!(v.intact && v.valid, "{:?}", v.problems);
    assert!(v.problems.is_empty() && v.warnings.is_empty(), "{v:?}");
    assert_eq!(v.tsa_cert.as_deref(), Some(cert("tsa.pem").as_slice()));
    assert_eq!(v.certificates.len(), 2, "the TSA certificate and the root");
    assert_eq!(
        v.signature_algorithm.as_deref(),
        Some("sha256WithRSAEncryption")
    );
    // With the TSA name and a signing-time attribute, as OpenSSL writes them.
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            tsa_name: true,
            signing_time_attr: true,
            ..options()
        },
    );
    let validated = validate(&response).unwrap();
    let name = validated.tst_info.tsa_name.unwrap();
    assert!(name.contains("CN=Folioxide Test TSA"), "{name}");
}

#[test]
fn tst_response_rejection_reports_status_and_fail_info() {
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            status: 2,
            status_string: Some("unsupported algorithm".into()),
            fail_info: Some(1 | 1 << 5),
            ..options()
        },
    );
    let parsed = TimeStampResp::from_der(&response).unwrap();
    assert_eq!(parsed.status.status, PkiStatus::Rejection);
    assert_eq!(parsed.status.status_string, ["unsupported algorithm"]);
    assert_eq!(parsed.status.fail_info, Some(0b10_0001));
    assert_eq!(parsed.token, None);
    assert_eq!(
        refused(&response),
        "timestamp invalid: TSA refused: status 2, \"unsupported algorithm\", failInfo badAlg, \
         badDataFormat"
    );
    // Every status but granted and grantedWithMods is a refusal.
    for (status, expected) in [
        (3, PkiStatus::Waiting),
        (4, PkiStatus::RevocationWarning),
        (5, PkiStatus::RevocationNotification),
        (6, PkiStatus::Unknown(6)),
    ] {
        let response = respond(
            "tsa.pem",
            MockTsaOptions {
                status,
                ..options()
            },
        );
        assert_eq!(
            TimeStampResp::from_der(&response).unwrap().status.status,
            expected
        );
        let message = refused(&response);
        assert!(
            message.contains(&format!(
                "TSA refused: status {status}, \"\", failInfo none"
            )),
            "{message}"
        );
    }
}

#[test]
fn tst_response_granted_with_mods_accepted() {
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            status: 1,
            ..options()
        },
    );
    assert_eq!(
        TimeStampResp::from_der(&response).unwrap().status.status,
        PkiStatus::GrantedWithMods
    );
    validate(&response).unwrap();
}

#[test]
fn tst_response_without_token_rejected() {
    // The mock's granted response with its token cut off: SEQUENCE { status }.
    let response = respond("tsa.pem", options());
    let status = [0x30, 0x03, 0x02, 0x01, 0x00];
    assert!(response[4..].starts_with(&status));
    let bare = [&[0x30, 0x05][..], &status].concat();
    assert_eq!(TimeStampResp::from_der(&bare).unwrap().token, None);
    assert!(refused(&bare).contains("holds no timestamp token"));
    // Garbage is no response at all.
    assert!(refused(b"garbage").contains("does not parse"));
}

#[test]
fn tst_nonce_mismatch_rejected() {
    let other = respond(
        "tsa.pem",
        MockTsaOptions {
            nonce: Echo::Replace(vec![0x01, 0x02]),
            ..options()
        },
    );
    assert!(refused(&other).contains("nonce differs"));
    // The same value with a redundant leading zero octet is not a valid INTEGER at all (X.690
    // §8.3.2, in BER too): OpenSSL cannot decode such a token, so it is refused before the
    // nonces are compared as values (D-10; QA round 1 finding F6).
    let padded = respond(
        "tsa.pem",
        MockTsaOptions {
            nonce: Echo::Replace([&[0u8][..], &NONCE.to_be_bytes()].concat()),
            ..options()
        },
    );
    assert!(refused(&padded).contains("non-minimal INTEGER"));
    // A high-bit nonce needs its sign octet: that one is minimal, and equal to the request's.
    let high = TimeStampReq::new(request().imprint, Some(0x8000_0000_0000_0000), None);
    let response = mock_tsa_with("tsa.pem", options()).respond(&high.to_der());
    tsp::validate_response(&high, &response).unwrap();
    // A token with a nonce for a request without one.
    let no_nonce = TimeStampReq::new(request().imprint, None, None);
    let response = mock_tsa_with(
        "tsa.pem",
        MockTsaOptions {
            nonce: Echo::Replace(vec![7]),
            ..options()
        },
    )
    .respond(&no_nonce.to_der());
    let err = tsp::validate_response(&no_nonce, &response).unwrap_err();
    assert!(err.to_string().contains("had no nonce"), "{err}");
}

#[test]
fn tst_nonce_missing_in_token_rejected() {
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            nonce: Echo::Omit,
            ..options()
        },
    );
    assert!(refused(&response).contains("has none"));
}

#[test]
fn tst_imprint_mismatch_rejected() {
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            imprint: Echo::Replace(vec![0x42; 32]),
            ..options()
        },
    );
    assert!(refused(&response).contains("messageImprint differs"));
    // The verification side: not intact, but the TSA's signature is still valid.
    let v = verify_token(&token_of(&response));
    assert!(!v.intact && v.valid, "{v:?}");
    assert_eq!(codes(&v), [ProblemCode::TimestampImprintMismatch]);
}

#[test]
fn tst_imprint_algorithm_mismatch_rejected() {
    // A response to the same data hashed with SHA-384, for a SHA-256 request.
    let sha384 = request_with(DigestAlgorithm::Sha384, None);
    let response = mock_tsa().respond(&sha384.to_der());
    let message = refused(&response);
    assert!(
        message.contains("uses 2.16.840.1.101.3.4.2.2, but the request used sha256"),
        "{message}"
    );
    // On its own request it validates, and it verifies over the SHA-384 digest.
    tsp::validate_response(&sha384, &response).unwrap();
    let v = verify_token(&token_of(&response));
    assert!(v.intact && v.valid, "{v:?}");
    assert_eq!(v.tst_info.unwrap().imprint.digest, DigestAlgorithm::Sha384);
}

/// The DER of `request` with the hash algorithm's NULL parameters removed.
fn without_null(request: &TimeStampReq) -> Vec<u8> {
    let der = request.to_der();
    let null = [0x05, 0x00];
    let at = der.windows(2).position(|w| w == null).unwrap();
    let mut out = [&der[..at], &der[at + 2..]].concat();
    // Shrink the three enclosing lengths (all short form here).
    out[1] -= 2; // TimeStampReq
    out[6] -= 2; // MessageImprint
    out[8] -= 2; // AlgorithmIdentifier
    out
}

#[test]
fn tst_imprint_null_and_absent_params_equal() {
    let ours = request();
    let absent = without_null(&ours);
    assert_eq!(TimeStampReq::from_der(&absent).unwrap(), ours);
    // A TSA that echoes absent parameters answers our NULL request: accepted.
    let response = mock_tsa().respond(&absent);
    let token = token_of(&response);
    let tst = folioxide_sign::cms::parse(&token)
        .unwrap()
        .econtent
        .unwrap();
    assert!(
        !tst.windows(13).any(|w| w
            == [
                0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
            ]),
        "the token's imprint has no NULL"
    );
    validate(&response).unwrap();
    // And the other way round.
    let response = mock_tsa().respond(&ours.to_der());
    tsp::validate_response(&TimeStampReq::from_der(&absent).unwrap(), &response).unwrap();
}

#[test]
fn tst_policy_mismatch_rejected() {
    let asked = request_with(DigestAlgorithm::Sha256, Some("1.2.3.4.5"));
    let response = mock_tsa().respond(&asked.to_der());
    let err = tsp::validate_response(&asked, &response).unwrap_err();
    assert!(
        err.to_string()
            .contains("policy is 1.2.3.4.1, but the request asked for 1.2.3.4.5"),
        "{err}"
    );
    // The policy the TSA chose is fine when the request named none.
    validate(&respond("tsa.pem", options())).unwrap();
    // And the requested one is accepted.
    let response = mock_tsa_with(
        "tsa.pem",
        MockTsaOptions {
            policy: "1.2.3.4.5".into(),
            ..options()
        },
    )
    .respond(&asked.to_der());
    tsp::validate_response(&asked, &response).unwrap();
}

#[test]
fn tst_econtent_not_tstinfo_rejected() {
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            econtent_type: "1.2.840.113549.1.7.1".into(),
            ..options()
        },
    );
    assert!(refused(&response).contains("not id-ct-TSTInfo"));
    let v = verify_token(&token_of(&response));
    assert_eq!(codes(&v), [ProblemCode::TimestampMalformed]);
    assert!(!v.intact && !v.valid);
}

#[test]
fn tst_two_signer_infos_rejected() {
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            signer_infos: 2,
            ..options()
        },
    );
    assert!(refused(&response).contains("2 SignerInfos"));
    let v = verify_token(&token_of(&response));
    assert_eq!(codes(&v), [ProblemCode::TimestampMalformed]);
}

#[test]
fn tst_version_not_1_rejected() {
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            tst_version: 2,
            ..options()
        },
    );
    assert!(refused(&response).contains("TSTInfo version is 2"));
    let v = verify_token(&token_of(&response));
    assert_eq!(codes(&v), [ProblemCode::TimestampMalformed]);
    // TstInfo::from_der returns any version; the verifiers require 1.
    let parsed = folioxide_sign::cms::parse(&token_of(&response)).unwrap();
    assert_eq!(
        TstInfo::from_der(parsed.econtent.as_deref().unwrap())
            .unwrap()
            .version,
        2
    );
}

#[test]
fn tst_cert_missing_with_cert_req_rejected() {
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            include_certs: false,
            ..options()
        },
    );
    assert!(refused(&response).contains("does not carry the TSA certificate"));
    // The verification side finds it among the extra certificates.
    let token = token_of(&response);
    let v = verify_token(&token);
    assert!(!v.valid);
    assert_eq!(codes(&v), [ProblemCode::TimestampSignatureInvalid]);
    let v = tsp::verify_token(&token, &|d| Some(d.digest(&[DATA])), &[cert("tsa.pem")]);
    assert!(v.intact && v.valid, "{v:?}");
}

#[test]
fn tst_ess_missing_rejected() {
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            ess: Ess::Missing,
            ..options()
        },
    );
    assert!(refused(&response).contains("ESS signing-certificate"));
    let v = verify_token(&token_of(&response));
    assert!(v.intact && !v.valid);
    assert_eq!(codes(&v), [ProblemCode::TimestampEssMismatch]);
}

#[test]
fn tst_ess_mismatch_rejected() {
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            ess: Ess::WrongHash,
            ..options()
        },
    );
    assert!(refused(&response).contains("ESS signing-certificate"));
    let v = verify_token(&token_of(&response));
    assert!(v.intact && !v.valid);
    assert_eq!(codes(&v), [ProblemCode::TimestampEssMismatch]);
}

#[test]
fn tst_ess_v1_accepted() {
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            ess: Ess::V1,
            ..options()
        },
    );
    let validated = validate(&response).unwrap();
    // SHA-1 in ESS v1 is not a weak-algorithm problem (brief §4.2 step 6).
    let v = verify_token(&validated.token_der);
    assert!(v.intact && v.valid, "{v:?}");
    assert!(v.problems.is_empty(), "{:?}", v.problems);
}

#[test]
fn tst_ess_v2_accepted() {
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            ess: Ess::V2,
            ..options()
        },
    );
    validate(&response).unwrap();
    let v = verify_token(&token_of(&response));
    assert!(v.intact && v.valid && v.problems.is_empty(), "{v:?}");
}

/// A TSA certificate variant: `check_tsa_certificate` refuses it with `reason`, the signing
/// side refuses the mock's response, and the verification side reports `code`.
fn unsuitable(cert_name: &str, reason: &str) {
    let err = check_tsa_certificate(&cert(cert_name)).unwrap_err();
    assert!(err.contains(reason), "{cert_name}: {err}");
    let response = respond(cert_name, options());
    let message = refused(&response);
    assert!(
        message.contains("not suitable for timestamping") && message.contains(reason),
        "{cert_name}: {message}"
    );
    let v = verify_token(&token_of(&response));
    assert!(v.intact && !v.valid, "{cert_name}: {v:?}");
    assert_eq!(
        codes(&v),
        [ProblemCode::TsaCertificateUnsuitable],
        "{cert_name}"
    );
}

#[test]
fn tsa_eku_missing_rejected() {
    unsuitable("tsa-no-eku.pem", "no extended key usage");
}

#[test]
fn tsa_eku_not_critical_rejected() {
    unsuitable("tsa-eku-noncritical.pem", "not critical");
}

#[test]
fn tsa_eku_extra_purpose_rejected() {
    unsuitable("tsa-eku-extra.pem", "not exactly {id-kp-timeStamping}");
}

#[test]
fn tsa_ku_key_encipherment_rejected() {
    unsuitable(
        "tsa-ku-keyenc.pem",
        "allows more than digitalSignature and nonRepudiation",
    );
}

#[test]
fn tsa_cert_not_valid_at_gen_time_rejected() {
    // The certificate is suitable, but valid only from 2070 on; the token says 2026.
    check_tsa_certificate(&cert("tsa-not-yet-valid.pem")).unwrap();
    let response = respond("tsa-not-yet-valid.pem", options());
    assert!(refused(&response).contains("outside the TSA certificate's validity"));
    let v = verify_token(&token_of(&response));
    assert!(v.intact && !v.valid);
    assert_eq!(codes(&v), [ProblemCode::TsaCertificateNotValidAtGenTime]);
    // A genTime inside the validity is fine.
    let response = respond(
        "tsa-not-yet-valid.pem",
        MockTsaOptions {
            gen_time: "20710101000000Z".into(),
            ..options()
        },
    );
    validate(&response).unwrap();
}

#[test]
fn tsa_certificate_checks_on_the_pki() {
    check_tsa_certificate(&cert("tsa.pem")).unwrap();
    // A document signer has no timestamping EKU; a CA neither.
    assert!(check_tsa_certificate(&cert("signer-p256.pem")).is_err());
    assert!(check_tsa_certificate(&cert("root.pem")).is_err());
    assert!(check_tsa_certificate(b"garbage").is_err());
}

#[test]
fn gen_time_fraction_parsed() {
    let time = GenTime::parse(b"20261011035141.825589Z").unwrap();
    assert_eq!(time.unix_seconds, 1_791_690_701);
    assert_eq!(time.nanos, 825_589_000);
    assert_eq!(time.fraction_digits, 6);
    assert_eq!(time.to_rfc3339(), "2026-10-11T03:51:41.825589Z");
    assert!(!time.has_trailing_zeros());
    for (text, nanos, digits, rfc3339) in [
        ("20261011035141Z", 0, 0, "2026-10-11T03:51:41Z"),
        (
            "20261011035141.5Z",
            500_000_000,
            1,
            "2026-10-11T03:51:41.5Z",
        ),
        (
            "20261011035141.123456789Z",
            123_456_789,
            9,
            "2026-10-11T03:51:41.123456789Z",
        ),
        (
            "20000229235959.001Z",
            1_000_000,
            3,
            "2000-02-29T23:59:59.001Z",
        ),
    ] {
        let time = GenTime::parse(text.as_bytes()).unwrap();
        assert_eq!(
            (time.nanos, time.fraction_digits),
            (nanos, digits),
            "{text}"
        );
        assert_eq!(time.to_rfc3339(), rfc3339);
    }
    // Ordered by instant.
    let a = GenTime::parse(b"20261011035141.5Z").unwrap();
    let b = GenTime::parse(b"20261011035141.6Z").unwrap();
    let c = GenTime::parse(b"20261011035142Z").unwrap();
    assert!(a < b && b < c);
}

#[test]
fn gen_time_rejects_offsets_and_missing_z() {
    for text in [
        "20261011035141+0200",
        "20261011035141-0500",
        "20261011035141",
        "20261011035141z",
        "20261011035141.Z",
        "20261011035141.5",
        "20261011035141,5Z",
        "20261011035141.1234567890Z",
        "20261011035160Z",
        "20261011036041Z",
        "20261011245141Z",
        "20261311035141Z",
        "20260001035141Z",
        "20260230035141Z",
        "20250229035141Z",
        "2026101103514Z",
        " 20261011035141Z",
        "20261011035141Z ",
        "2026101103514aZ",
        "",
    ] {
        let err = GenTime::parse(text.as_bytes()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::TimestampInvalid, "{text:?}");
    }
    GenTime::parse(b"20240229035141Z").unwrap();
}

#[test]
fn gen_time_trailing_zero_fraction_warns() {
    let time = GenTime::parse(b"20261010120030.50Z").unwrap();
    assert!(time.has_trailing_zeros());
    assert_eq!(time.to_rfc3339(), "2026-10-10T12:00:30.50Z");
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            gen_time: "20261010120030.50Z".into(),
            ..options()
        },
    );
    let validated = validate(&response).unwrap();
    assert!(
        validated
            .warnings
            .iter()
            .any(|w| w.contains("trailing zeros")),
        "{:?}",
        validated.warnings
    );
    let v = verify_token(&validated.token_der);
    assert!(v.intact && v.valid);
    assert!(v.warnings.iter().any(|w| w.contains("trailing zeros")));
}

/// A committed request/response pair of `fixtures/sign/tsa`, validated as the signing side
/// does, then verified as the verification side does over the request's imprint.
fn committed(stem: &str) -> (ValidatedToken, TokenVerification) {
    let request = TimeStampReq::from_der(&tsa_fixture(&format!("{stem}.tsq"))).unwrap();
    assert!(request.cert_req);
    assert_eq!(request.nonce.as_deref(), Some(&NONCE.to_be_bytes()[..]));
    let validated = tsp::validate_response(&request, &tsa_fixture(&format!("{stem}.tsr"))).unwrap();
    let hashed = request.imprint.hashed_message.clone();
    let digest = request.imprint.digest;
    let v = tsp::verify_token(
        &validated.token_der,
        &|d| (d == digest).then(|| hashed.clone()),
        &[],
    );
    assert!(v.intact && v.valid, "{stem}: {v:?}");
    (validated, v)
}

#[test]
fn openssl_reply_token_validates() {
    let (validated, v) = committed("openssl-reply");
    assert!(validated.warnings.is_empty(), "{:?}", validated.warnings);
    let tst = &validated.tst_info;
    assert_eq!(tst.policy, "1.2.3.4.1");
    assert_eq!(tst.accuracy.as_ref().unwrap().seconds, Some(1));
    assert!(
        tst.tsa_name
            .as_deref()
            .is_some_and(|n| n.contains("CN=Folioxide Test TSA")),
        "{:?}",
        tst.tsa_name
    );
    // OpenSSL: whole seconds (clock_precision_digits = 0), two certificates.
    assert_eq!(tst.gen_time.fraction_digits, 0);
    assert_eq!(v.certificates.len(), 2);
    assert_eq!(validated.tsa_cert_der, cert("tsa.pem"));
    // The OpenSSL token shape of brief §0: SignedData v3, sha256 with NULL.
    let token = &validated.token_der;
    assert!(token.windows(3).any(|w| w == [0x02, 0x01, 0x03]));
}

#[test]
fn pyhanko_dummy_token_validates() {
    let (validated, _) = committed("pyhanko-dummy");
    // DummyTimeStamper: microsecond genTime fractions, ESS v1 (brief §0).
    let tst = &validated.tst_info;
    assert_eq!(
        tst.gen_time.fraction_digits,
        6,
        "{}",
        tst.gen_time.to_rfc3339()
    );
    assert_eq!(validated.tsa_cert_der, cert("tsa.pem"));
}

#[test]
fn tst_unknown_imprint_algorithm_is_unsupported() {
    // The mock echoes the request's algorithm: SHA3-256 (not implemented by Folioxide).
    let sha3 = [
        0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00,
    ];
    let imprint = [&[0x30, 0x31][..], &sha3, &[0x04, 0x20], &[0x11; 32]].concat();
    let request = [
        &[0x30, 0x39, 0x02, 0x01, 0x01][..],
        &imprint,
        &[0x01, 0x01, 0xFF],
    ]
    .concat();
    assert!(TimeStampReq::from_der(&request).is_err());
    let token = mock_tsa().token_for(&request).unwrap();
    let v = verify_token(&token);
    assert!(!v.intact && v.valid, "{v:?}");
    assert_eq!(codes(&v), [ProblemCode::UnsupportedAlgorithm]);
    assert!(v.tst_info.is_none());
    let parsed = folioxide_sign::cms::parse(&token).unwrap();
    assert!(TstInfo::from_der(parsed.econtent.as_deref().unwrap()).is_err());
}

// ---- QA round 1: the token whitelist on the signing side (findings F2–F6) ---------------------

/// A DER AlgorithmIdentifier `{ oid, parameters }`.
fn algorithm_id(oid: &[u8], parameters: &[u8]) -> Vec<u8> {
    let mut content = vec![0x06, oid.len() as u8];
    content.extend_from_slice(oid);
    content.extend_from_slice(parameters);
    [vec![0x30, content.len() as u8], content].concat()
}

#[test]
fn tst_response_token_whitelist_rejected() {
    // Each of these tokens is signed by the test TSA and OpenSSL refuses it, or (SignedData and
    // SignerInfo versions) RFC 5652 forbids it; Folioxide never embeds such a token, and its
    // verifier reports the same code as the signing side refuses it for.
    let sha256 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    let dns_name = [&[0x82, 0x0B][..], b"tsa.example"].concat();
    let cases: Vec<(MockTsaOptions, &str, ProblemCode)> = vec![
        (
            MockTsaOptions {
                tsa_general_name: Some(dns_name),
                ..options()
            },
            "not a subject name of the TSA certificate",
            ProblemCode::TsaNameMismatch,
        ),
        (
            MockTsaOptions {
                ess: Ess::V2AndWrongV1,
                ..options()
            },
            "first identifier of the signing-certificate attribute",
            ProblemCode::TimestampEssMismatch,
        ),
        (
            MockTsaOptions {
                ess_more_cert_ids: vec![b"junk".to_vec()],
                ..options()
            },
            "a later identifier of the signing-certificate-v2 attribute",
            ProblemCode::TimestampEssMismatch,
        ),
        (
            MockTsaOptions {
                signed_data_version: 1,
                ..options()
            },
            "SignedData version is 1, not 3",
            ProblemCode::TimestampMalformed,
        ),
        (
            MockTsaOptions {
                signer_info_version: 3,
                ..options()
            },
            "SignerInfo version is 3, not 1",
            ProblemCode::TimestampMalformed,
        ),
        (
            MockTsaOptions {
                digest_algorithms: Some(Vec::new()),
                ..options()
            },
            "lists no digest algorithm",
            ProblemCode::TimestampMalformed,
        ),
        (
            MockTsaOptions {
                extra_certificate_entries: vec![vec![0x30, 0x03, 0x02, 0x01, 0x05]],
                ..options()
            },
            "certificate does not parse",
            ProblemCode::TimestampMalformed,
        ),
        (
            MockTsaOptions {
                signature_algorithm: Some(algorithm_id(
                    &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
                    &[0x04, 0x00],
                )),
                ..options()
            },
            "signatureAlgorithm has parameters other than NULL",
            ProblemCode::TimestampMalformed,
        ),
        // QA round 3 finding 5 (sign_side.mjs `ts-sign-*`, findings 2–4 on the signing side):
        // the shared whitelist refuses what OpenSSL's decoders refuse.
        (
            // ts-sign-ess-policies-junk
            MockTsaOptions {
                ess_policies: Some(tokens::seq(&[tokens::seq(&[tokens::int(1)])])),
                ..options()
            },
            "a policies entry is not a PolicyInformation",
            ProblemCode::TimestampMalformed,
        ),
        (
            // ts-sign-ess-issuer-visible
            MockTsaOptions {
                ess_issuer_name: Some(bt_support::decoys::reencode_name(
                    &bt_support::decoys::issuer_of(&cert("tsa.pem")),
                    0x1A,
                    false,
                )),
                ..options()
            },
            "does not decode as a name",
            ProblemCode::TimestampMalformed,
        ),
        (
            // ts-sign-tst-ext-junk
            MockTsaOptions {
                tst_extensions: Some(tokens::tst_extensions(&[tokens::octets(b"zz")])),
                ..options()
            },
            "not an Extension",
            ProblemCode::TimestampMalformed,
        ),
        (
            // ts-sign-sattr-indef
            MockTsaOptions {
                signed_attrs_encoding: Some(tokens::attributes_indefinite),
                ..options()
            },
            "signed attributes are not DER",
            ProblemCode::TimestampMalformed,
        ),
        (
            // ts-sign-sattr-unsorted
            MockTsaOptions {
                extra_signed_attributes: vec![tokens::unsorted_attribute(
                    &tokens::test_oid(99),
                    &[tokens::octets(b"a"), tokens::octets(b"b")],
                )],
                ..options()
            },
            "signed attributes are not DER",
            ProblemCode::TimestampMalformed,
        ),
        // QA round 4 findings 1–3 (ts-sign-r5-crl-bmp-lone-surrogate,
        // ts-sign-r5-tsa-gn-universal-null, ts-sign-r5-tsa-gn-unknown-ctx9 and their ts-embed-*
        // twins): a name OpenSSL cannot convert, a tsa GeneralName it cannot decode.
        (
            MockTsaOptions {
                crls: vec![bt_support::decoys::test_crl(
                    &bt_support::decoys::test_name(bt_support::decoys::bmp(&[0x54, 0xD800])),
                )],
                ..options()
            },
            "BMPString with a UTF-16 surrogate",
            ProblemCode::TimestampMalformed,
        ),
        (
            MockTsaOptions {
                tsa_general_name: Some(vec![0x05, 0x00]),
                ..options()
            },
            "tsa is a GeneralName that does not decode",
            ProblemCode::TimestampMalformed,
        ),
        (
            MockTsaOptions {
                tsa_general_name: Some(tokens::der(0x89, b"tsa")),
                ..options()
            },
            "tsa is a GeneralName that does not decode",
            ProblemCode::TimestampMalformed,
        ),
    ];
    for (options, why, code) in cases {
        let response = respond("tsa.pem", options);
        let message = refused(&response);
        assert!(message.contains(why), "{why}: {message}");
        let v = verify_token(&token_of(&response));
        assert!(!v.valid, "{why}: {v:?}");
        assert_eq!(codes(&v), [code], "{why}: {v:?}");
    }
    // ts-sign-r5-cert-subject-bmp-lone-surrogate: the TSA certificate's own subject.
    let surrogate_tsa = bt_support::decoys::tsa_cert_with(
        0x0A5E_0800,
        &bt_support::decoys::test_name(bt_support::decoys::bmp(&[0x54, 0xD800])),
        &[],
    );
    let key = tsa_key("tsa.pem");
    let response = folioxide_testkit::tsa::MockTsa::new(
        surrogate_tsa,
        vec![cert("root.pem")],
        Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
    )
    .respond(&request().to_der());
    let message = refused(&response);
    assert!(
        message.contains("BMPString with a UTF-16 surrogate"),
        "{message}"
    );
    let v = verify_token(&token_of(&response));
    assert_eq!(codes(&v), [ProblemCode::TimestampMalformed], "{v:?}");
    // The imprint algorithm with parameters other than NULL is not the request's algorithm.
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            imprint_algorithm: Some(algorithm_id(&sha256, &[0x04, 0x01, 0x00])),
            ..options()
        },
    );
    assert!(refused(&response).contains("messageImprint uses"));
    let v = verify_token(&token_of(&response));
    assert!(!v.intact && v.valid, "{v:?}");
    assert_eq!(codes(&v), [ProblemCode::TimestampImprintMismatch]);
}

#[test]
fn tst_ess_later_cert_id_names_the_chain() {
    // A later ESS identifier naming the root the token carries is what OpenSSL accepts.
    let response = respond(
        "tsa.pem",
        MockTsaOptions {
            ess: Ess::V1AndV2,
            ess_more_cert_ids: vec![cert("root.pem")],
            ..options()
        },
    );
    validate(&response).unwrap();
    let v = verify_token(&token_of(&response));
    assert!(v.intact && v.valid && v.problems.is_empty(), "{v:?}");
    // Without the root in the token, but given as an extra certificate, it is still found.
    let key = tsa_key("tsa.pem");
    let bare = folioxide_testkit::tsa::MockTsa::new(
        cert("tsa.pem"),
        Vec::new(),
        Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
    )
    .with_options(MockTsaOptions {
        ess_more_cert_ids: vec![cert("root.pem")],
        ..options()
    });
    let token = bare.token_for(&request().to_der()).unwrap();
    let imprint = |d: DigestAlgorithm| Some(d.digest(&[DATA]));
    let alone = tsp::verify_token(&token, &imprint, &[]);
    assert_eq!(
        codes(&alone),
        [ProblemCode::TimestampEssMismatch],
        "{alone:?}"
    );
    let with_root = tsp::verify_token(&token, &imprint, &[cert("root.pem")]);
    assert!(with_root.intact && with_root.valid, "{with_root:?}");
}

#[test]
fn tst_ess_later_cert_id_decoy_refused_on_the_signing_side() {
    // QA round 2 finding 3: the signing side resolves later identifiers the same way, by name
    // and verified signature, so it never embeds a token naming a certificate that only carries
    // an issuer's name (OpenSSL: ess cert id not found).
    let d = bt_support::decoys::decoys();
    let (tsa, root) = (cert("tsa.pem"), cert("root.pem"));
    let response_with = |extra: Vec<Vec<u8>>, ids: Vec<Vec<u8>>| {
        let key = tsa_key("tsa.pem");
        folioxide_testkit::tsa::MockTsa::new(
            tsa.clone(),
            extra,
            Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
        )
        .with_options(MockTsaOptions {
            ess: Ess::V1AndV2,
            ess_cert_ids: Some(ids),
            ..options()
        })
        .respond(&request().to_der())
    };
    let decoy = response_with(
        vec![root.clone(), d.fake_root.clone()],
        vec![tsa.clone(), d.fake_root.clone()],
    );
    let message = refused(&decoy);
    assert!(
        message.contains("checked by name and signature"),
        "{message}"
    );
    let v = verify_token(&token_of(&decoy));
    assert!(v.intact && !v.valid, "{v:?}");
    assert_eq!(codes(&v), [ProblemCode::TimestampEssMismatch]);
    // A first identifier that names the root instead of the TSA certificate.
    let wrong_first = response_with(vec![root.clone()], vec![root.clone()]);
    assert!(refused(&wrong_first).contains("first identifier"));
    // The control: the root itself.
    validate(&response_with(vec![root.clone()], vec![tsa.clone(), root])).unwrap();
}

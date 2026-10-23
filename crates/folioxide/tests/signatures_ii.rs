//! The facade's signatures-II API (M4 brief §3; WP4.3B): PAdES B-T in one step and in two
//! phases, certification, verification of document timestamps, and the M4 error codes, used the
//! way an application would, with the committed test PKI and the testkit's mock TSA.
#![cfg(feature = "signatures")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;

use folioxide::sign::tsp::TstInfo;
use folioxide::{
    DigestAlgorithm, DocMdpPermissions, Document, Error, ErrorCode, LocalSigner, OpenOptions,
    PadesLevel, PdfDate, PrepareRequest, PreparedSignature, SignRequest, SignatureKind,
    SignatureOptions, Signer, TimeStampReq, TimeStampResp, TimestampParams, VerifyOptions,
    certificates_from_pem, prepare, sign, verify_bytes,
};
use folioxide_testkit::tsa::{MockTsa, MockTsaOptions};

fn fixture(path: &str) -> Vec<u8> {
    let full = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(path);
    std::fs::read(&full).unwrap_or_else(|e| panic!("reading {}: {e}", full.display()))
}

fn pem(name: &str) -> String {
    String::from_utf8(fixture(&format!("pki/{name}"))).unwrap()
}

fn time() -> PdfDate {
    PdfDate::parse(b"D:20261010120000Z").unwrap()
}

fn open(pdf: Vec<u8>) -> Document {
    Document::open(pdf, &OpenOptions::default()).unwrap()
}

fn signer() -> LocalSigner {
    LocalSigner::from_pem(
        &pem("signer-p256.key.pem"),
        &(pem("signer-p256.pem") + &pem("intermediate.pem")),
        None,
    )
    .unwrap()
}

fn root() -> Vec<Vec<u8>> {
    certificates_from_pem(&pem("root.pem")).unwrap()
}

/// The mock TSA of the test PKI, with `options`.
fn mock(options: MockTsaOptions) -> MockTsa {
    let key = LocalSigner::from_pem(&pem("tsa.key.pem"), &pem("tsa.pem"), None).unwrap();
    let first = |name: &str| certificates_from_pem(&pem(name)).unwrap().remove(0);
    MockTsa::new(
        first("tsa.pem"),
        vec![first("root.pem")],
        Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
    )
    .with_options(options)
}

/// One step with a timestamper and two phases with the same nonce give the same file, and its
/// signature verifies B-T with a trusted timestamp at the mock's `genTime`.
#[test]
fn bt_two_phases_match_one_step() {
    let signer = signer();
    let tsa = mock(MockTsaOptions::default());
    let timestamper =
        |request: &[u8]| -> folioxide::sign::Result<Vec<u8>> { Ok(tsa.respond(request)) };
    let params = TimestampParams::new().with_nonce(Some(7));
    let request = SignRequest::new(&signer, time()).with_timestamper(&timestamper, params.clone());
    let one_step = sign(&open(fixture("syntax/minimal.pdf")), &request).unwrap();

    let options =
        SignatureOptions::new(time()).with_tsa_reserve(Some(folioxide::DEFAULT_TSA_RESERVE));
    let prepared = prepare(
        &open(fixture("syntax/minimal.pdf")),
        &PrepareRequest::new(
            signer.certificate_chain().to_vec(),
            signer.algorithm(),
            time(),
        )
        .with_options(options),
    )
    .unwrap();
    let value = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let request_der = prepared.timestamp_request(&value, &params).unwrap();
    let parsed = TimeStampReq::from_der(&request_der).unwrap();
    assert!(parsed.cert_req);
    assert_eq!(parsed.nonce.as_deref(), Some(&[7][..]));
    let response_der = tsa.respond(&request_der);
    let response = TimeStampResp::from_der(&response_der).unwrap();
    assert!(response.token.is_some());
    let two_phases = prepared
        .finish_with_timestamp(&value, &request_der, &response_der)
        .unwrap();
    assert_eq!(one_step, two_phases);

    let options = VerifyOptions::new().with_trust_anchors_der(root());
    let report = verify_bytes(two_phases, &options).unwrap().remove(0);
    assert_eq!(report.pades_level, Some(PadesLevel::BT));
    let timestamp = report.timestamp.as_ref().unwrap();
    assert!(timestamp.intact && timestamp.valid);
    assert_eq!(timestamp.trusted, Some(true));
    assert_eq!(timestamp.gen_time, "2026-10-10T12:00:30Z");
    assert!(report.is_acceptable(folioxide::ModificationLevel::None));
}

/// A refused response gives the prepared signature back (`FinishError`), and the right one
/// finishes it; the refusal is `E_TIMESTAMP_INVALID` through the facade's error.
#[test]
fn a_refused_response_gives_the_prepared_signature_back() {
    let signer = signer();
    let prepared: PreparedSignature = prepare(
        &open(fixture("syntax/minimal.pdf")),
        &PrepareRequest::new(
            signer.certificate_chain().to_vec(),
            signer.algorithm(),
            time(),
        )
        .with_options(SignatureOptions::new(time()).with_tsa_reserve(Some(8192))),
    )
    .unwrap();
    let value = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let params = TimestampParams::new().with_nonce(Some(1));
    let request_der = prepared.timestamp_request(&value, &params).unwrap();
    let refusing = mock(MockTsaOptions {
        status: 2,
        status_string: Some("no".to_owned()),
        ..MockTsaOptions::default()
    });
    let refused = prepared
        .try_finish_with_timestamp(&value, &request_der, &refusing.respond(&request_der))
        .unwrap_err();
    let (error, prepared) = refused.into_parts();
    let error = Error::from(error);
    assert_eq!(error.code(), ErrorCode::TimestampInvalid);
    assert!(error.to_string().contains("status 2"), "{error}");

    let tsa = mock(MockTsaOptions::default());
    let response_der = tsa.respond(&request_der);
    let signed = prepared
        .finish_with_timestamp(&value, &request_der, &response_der)
        .unwrap();
    let report = verify_bytes(signed, &VerifyOptions::new())
        .unwrap()
        .remove(0);
    assert_eq!(report.pades_level, Some(PadesLevel::BT));
    // The token's TSTInfo is the one the TSA wrote.
    let token = tsa.token_for(&request_der).unwrap();
    let parsed = folioxide::sign::cms::parse(&token).unwrap();
    assert!(!parsed.signer_infos.is_empty());
    let info = report.timestamp.as_ref().unwrap();
    assert_eq!(info.serial_hex.as_deref(), Some("01"));
    let _: fn(&[u8]) -> folioxide::sign::Result<TstInfo> = TstInfo::from_der;
}

/// Certification levels and the refusals that keep a certified document valid.
#[test]
fn certification_through_the_facade() {
    let signer = signer();
    let certify = |p: DocMdpPermissions| {
        let request = SignRequest::new(&signer, time());
        let options = request.options.clone().with_certification(Some(p));
        sign(
            &open(fixture("syntax/minimal.pdf")),
            &request.with_options(options),
        )
        .unwrap()
    };
    for p in [
        DocMdpPermissions::NoChanges,
        DocMdpPermissions::FormFilling,
        DocMdpPermissions::FormFillingAndAnnotations,
    ] {
        let certified = certify(p);
        let report = verify_bytes(certified.clone(), &VerifyOptions::new())
            .unwrap()
            .remove(0);
        assert_eq!(report.docmdp, Some(p.p()));
        assert_eq!(report.docmdp_ok, Some(true));

        // A second signature: refused under P = 1, an approval under P = 2 and 3.
        let approval = sign(&open(certified), &SignRequest::new(&signer, time()));
        match p {
            DocMdpPermissions::NoChanges => {
                let err = Error::from(approval.unwrap_err());
                assert_eq!(err.code(), ErrorCode::DocMdpForbids, "{err}");
            }
            _ => {
                let reports = verify_bytes(approval.unwrap(), &VerifyOptions::new()).unwrap();
                assert_eq!(reports[0].docmdp_ok, Some(true));
                assert_eq!(
                    reports[0].modification,
                    folioxide::ModificationLevel::FormFilling
                );
            }
        }
    }
}

/// A document timestamp made by pyHanko is verified through the facade: its own token is the
/// report's timestamp, trusted with the test root.
#[test]
fn document_timestamps_are_verified() {
    let options = VerifyOptions::new().with_trust_anchors_der(root());
    let reports = verify_bytes(fixture("sign/pdf/pyhanko-doc-timestamp.pdf"), &options).unwrap();
    let doc_timestamp = reports
        .iter()
        .find(|r| r.kind == SignatureKind::DocTimeStamp)
        .expect("a document timestamp");
    assert!(doc_timestamp.intact && doc_timestamp.signature_valid);
    let token = doc_timestamp.timestamp.as_ref().expect("its token");
    assert!(token.intact && token.valid);
    assert_eq!(token.trusted, Some(true));
    assert_eq!(
        doc_timestamp.claimed_time.as_deref(),
        Some(token.gen_time.as_str())
    );
}

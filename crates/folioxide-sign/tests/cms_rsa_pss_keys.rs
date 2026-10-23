#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! RSA keys whose SubjectPublicKeyInfo algorithm is `id-RSASSA-PSS` (manager ruling R-22 (b);
//! M4 QA round 5 findings 36 and 48; RFC 4055 §1.2, §3.1).
//!
//! Such a key "MUST only be used with the RSASSA-PSS signature scheme", and its parameters,
//! when present, fix the scheme's. pyhanko-certvalidator refuses a PKCS #1 v1.5 signature with
//! it (an assertion) and a PSS signature with other parameters (`PSSParameterMismatch`);
//! OpenSSL refuses the first (`illegal or unsupported padding mode`, `last octet invalid`). So
//! does Folioxide, for timestamp tokens (signature and document timestamps, signing and
//! verifying side), document signatures and certificate signatures on a path, and it never
//! signs with such a certificate. The certificates are issued at test time from the committed
//! keys of `fixtures/pki`.

mod bt_support;

use bt_support::decoys::{self, children, content, issue, pss_spki, signer, spki_of, subject_of};
use bt_support::*;
use folioxide_model::PdfDate;
use folioxide_sign::algorithms::{DigestAlgorithm, KeyKind, SignatureAlgorithm};
use folioxide_sign::bt::TimestampParams;
use folioxide_sign::cms::{self, SignedAttrsInput};
use folioxide_sign::prepare::{PrepareRequest, SignatureOptions, prepare};
use folioxide_sign::report::{PadesLevel, SignatureReport};
use folioxide_sign::signer::Signer as _;
use folioxide_sign::tsp::DEFAULT_TSA_RESERVE;
use folioxide_sign::verify_pdf::VerifyOptions;
use folioxide_sign::x509info::{self, UnixTime, build_trust};
use folioxide_sign::{Error, ProblemCode};
use folioxide_syntax::ErrorCode;
use folioxide_testkit::tsa::{MockTsa, MockTsaOptions};

/// The `RSASSA-PSS-params` element of [`rsassa_pss_sha256_salt`] (SHA-256, MGF1-SHA-256,
/// `salt`-byte salt).
fn pss_params(salt: u8) -> Vec<u8> {
    let algorithm = rsassa_pss_sha256_salt(salt);
    children(content(&algorithm))[1].to_vec()
}

/// `tsa.pem`'s subject and key, issued by the root, with the TSA's key restricted to
/// RSASSA-PSS by an `id-RSASSA-PSS` SubjectPublicKeyInfo with `parameters`.
fn pss_tsa_cert(serial: u32, parameters: Option<&[u8]>) -> Vec<u8> {
    let tsa = cert("tsa.pem");
    issue(
        serial,
        &subject_of(&cert("root.pem")),
        &subject_of(&tsa),
        &pss_spki(&spki_of(&tsa), parameters),
        &decoys::tsa_extensions(),
        &signer("root.key.pem", "root.pem"),
    )
}

/// A mock TSA for `tsa_cert` signing PKCS #1 v1.5 (sha256WithRSAEncryption).
fn pkcs1_tsa(tsa_cert: Vec<u8>) -> MockTsa {
    let key = tsa_key("tsa.pem");
    MockTsa::new(
        tsa_cert,
        vec![cert("root.pem")],
        Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
    )
}

/// A B-T file of `minimal.pdf` by RSA-2048 whose token `tsa` makes, written below Folioxide's
/// own `finish` (which refuses the deliberate tokens).
fn attack(tsa: &MockTsa) -> Vec<u8> {
    let signer = rsa2048();
    let request = PrepareRequest::new(
        signer.certificate_chain().to_vec(),
        signer.algorithm(),
        time(),
    )
    .with_options(SignatureOptions::new(time()).with_tsa_reserve(Some(DEFAULT_TSA_RESERVE)));
    let prepared = prepare(&open(&minimal()), &request).unwrap();
    let value = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let request = prepared
        .timestamp_request(&value, &TimestampParams::new().with_nonce(Some(NONCE)))
        .unwrap();
    let token = tsa.token_for(&request).unwrap();
    let cms = cms::assemble_with_timestamp(
        prepared.to_be_signed(),
        &value,
        signer.certificate_chain(),
        signer.algorithm(),
        signer.key_kind(),
        prepared.digest_algorithm(),
        &token,
    )
    .unwrap();
    embed_raw(&prepared, &cms)
}

/// The one report of a one-signature file.
fn report(pdf: &[u8]) -> SignatureReport {
    let mut reports = verify(pdf);
    assert_eq!(reports.len(), 1);
    reports.remove(0)
}

/// Signs `minimal.pdf` B-T with `tsa`.
fn sign_with(tsa: MockTsa) -> folioxide_sign::Result<Vec<u8>> {
    sign_bt_with(
        &minimal(),
        &rsa2048(),
        SignatureOptions::new(time()),
        &Tsa(tsa),
    )
}

#[test]
fn pkcs1_tokens_of_a_pss_only_tsa_key_are_invalid() {
    // r7-spki-pss-no-params, r7-spki-pss-sha256-params, r7-spki-pss-sha1-params,
    // r7-struct-spki-id-rsassa-pss, r7-v8-spki-pss-bt and the signPdf callback
    // ts-sign-r7-resp-tok-spki-pss(-sha256): a token signed with PKCS #1 v1.5 by a TSA whose
    // certificate restricts its key to RSASSA-PSS.
    let sha1_params = {
        // RSASSA-PSS-params with the defaults written out as SHA-1 (an empty SEQUENCE).
        tokens::seq(&[])
    };
    for (serial, name, parameters) in [
        (0x3A00, "no-params", None),
        (0x3A01, "sha256-params", Some(pss_params(32))),
        (0x3A02, "sha1-params", Some(sha1_params)),
    ] {
        let tsa_cert = pss_tsa_cert(serial, parameters.as_deref());
        // The verifying side: intact (the imprint is right), not valid, never trusted; B-B.
        let r = report(&attack(&pkcs1_tsa(tsa_cert.clone())));
        assert!(r.is_valid(), "{name}: {}", summary(&r));
        assert_eq!(
            r.pades_level,
            Some(PadesLevel::BB),
            "{name}: {}",
            summary(&r)
        );
        let ts = r.timestamp.as_ref().unwrap();
        assert!(
            ts.intact && !ts.valid && ts.trusted == Some(false),
            "{name}: {ts:?}"
        );
        let problem = ts
            .problems
            .iter()
            .find(|p| p.code == ProblemCode::TimestampSignatureInvalid)
            .unwrap_or_else(|| panic!("{name}: {ts:?}"));
        assert!(
            problem.message.contains("id-RSASSA-PSS"),
            "{name}: {problem:?}"
        );
        // The signing side refuses the response.
        let err = sign_with(pkcs1_tsa(tsa_cert)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::TimestampInvalid, "{name}: {err}");
        assert!(err.to_string().contains("id-RSASSA-PSS"), "{name}: {err}");
    }
}

#[test]
fn pss_tokens_must_match_the_key_parameters() {
    // RFC 4055 §3.1, as pyHanko compares them (PSSParameterMismatch): a key with parameters
    // verifies only signatures with exactly those parameters; a key without parameters
    // verifies any RSASSA-PSS signature.
    for (serial, name, key_parameters, salt, sound) in [
        (0x3B00, "no params, salt 32", None, 32, true),
        (0x3B01, "no params, salt 20", None, 20, true),
        (0x3B02, "salt 32, salt 32", Some(pss_params(32)), 32, true),
        (0x3B03, "salt 32, salt 20", Some(pss_params(32)), 20, false),
        (0x3B04, "salt 20, salt 32", Some(pss_params(20)), 32, false),
    ] {
        let tsa_cert = pss_tsa_cert(serial, key_parameters.as_deref());
        let tsa = || mock_tsa_pss_for(tsa_cert.clone(), salt, MockTsaOptions::default());
        let r = report(&attack(&tsa()));
        let ts = r.timestamp.as_ref().unwrap();
        if sound {
            assert!(
                ts.intact && ts.valid && ts.trusted == Some(true),
                "{name}: {ts:?}"
            );
            assert_eq!(r.pades_level, Some(PadesLevel::BT), "{name}");
            let signed = sign_with(tsa()).unwrap();
            assert_eq!(report(&signed).pades_level, Some(PadesLevel::BT), "{name}");
        } else {
            assert!(ts.intact && !ts.valid, "{name}: {ts:?}");
            assert!(
                ts.problems
                    .iter()
                    .any(|p| p.code == ProblemCode::TimestampSignatureInvalid
                        && p.message
                            .contains("differ from the ones its id-RSASSA-PSS key allows")),
                "{name}: {ts:?}"
            );
            assert!(sign_with(tsa()).is_err(), "{name}");
        }
    }
    // A NULL is no RSASSA-PSS-params (RFC 4055 §3.1): the key is unusable, the token invalid.
    let tsa_cert = pss_tsa_cert(0x3B10, Some(&[0x05, 0x00]));
    let ts = report(&attack(&mock_tsa_pss_for(
        tsa_cert,
        32,
        MockTsaOptions::default(),
    )))
    .timestamp
    .unwrap();
    assert!(ts.intact && !ts.valid, "{ts:?}");
}

#[test]
fn document_signer_with_a_pss_only_key() {
    // doc7-spki-pss, doc7-spki-pss-sha256: the RSA-2048 signer's certificate re-issued by the
    // intermediate with an id-RSASSA-PSS SubjectPublicKeyInfo. Folioxide signs RSA with
    // PKCS #1 v1.5 only, which no verifier accepts with such a key.
    let signer_cert = cert("signer-rsa2048.pem");
    let intermediate = cert("intermediate.pem");
    for (serial, parameters) in [(0x3C00, None), (0x3C01, Some(pss_params(32)))] {
        let pss_cert = issue(
            serial,
            &subject_of(&intermediate),
            &subject_of(&signer_cert),
            &pss_spki(&spki_of(&signer_cert), parameters.as_deref()),
            &[decoys::extension(
                &[0x55, 0x1D, 0x0F],
                true,
                &decoys::der(0x03, &[0x06, 0xC0]),
            )],
            &signer("intermediate.key.pem", "intermediate.pem"),
        );
        // The signing side: the certificate cannot sign, so prepare refuses it.
        let err = x509info::certificate_key_kind(&pss_cert).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
        let request = PrepareRequest::new(
            vec![pss_cert.clone(), intermediate.clone()],
            SignatureAlgorithm::RsaPkcs1v15,
            time(),
        );
        let err = prepare(&open(&minimal()), &request).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
        assert!(err.to_string().contains("id-RSASSA-PSS"), "{err}");

        // The verifying side, on a file made below the signing API: a PKCS #1 v1.5 signature
        // over signed attributes that name the PSS certificate.
        let rsa = rsa2048();
        let prepared = prepare(
            &open(&minimal()),
            &PrepareRequest::new(rsa.certificate_chain().to_vec(), rsa.algorithm(), time()),
        )
        .unwrap();
        let attrs = cms::build_signed_attrs(&SignedAttrsInput {
            digest: DigestAlgorithm::Sha256,
            document_digest: prepared.document_digest(),
            signer_cert_der: &pss_cert,
        })
        .unwrap();
        let value = rsa.sign(DigestAlgorithm::Sha256, &attrs).unwrap();
        // The raw verification refuses the value…
        let err = cms::verify_raw(
            &pss_cert,
            SignatureAlgorithm::RsaPkcs1v15,
            DigestAlgorithm::Sha256,
            &attrs,
            &value,
        )
        .unwrap_err();
        assert!(err.to_string().contains("id-RSASSA-PSS"), "{err}");
        let chain = vec![pss_cert.clone(), intermediate.clone()];
        let cms_der = cms::assemble(
            &attrs,
            &value,
            &chain,
            SignatureAlgorithm::RsaPkcs1v15,
            KeyKind::Rsa { bits: 2048 },
            DigestAlgorithm::Sha256,
        )
        .unwrap();
        // …embed_cms refuses the CMS…
        let err = prepared.clone().embed_cms(&cms_der).unwrap_err();
        assert!(err.to_string().contains("id-RSASSA-PSS"), "{err}");
        // …and the verifier calls it invalid and untrusted (pyHanko raises, OpenSSL: illegal or
        // unsupported padding mode).
        let r = report(&embed_raw(&prepared, &cms_der));
        assert!(r.intact && !r.signature_valid, "{}", summary(&r));
        assert_eq!(r.trusted, Some(false), "{}", summary(&r));
        let problem = r
            .problems
            .iter()
            .find(|p| p.code == ProblemCode::SignatureInvalid)
            .unwrap_or_else(|| panic!("{}", summary(&r)));
        assert!(problem.message.contains("id-RSASSA-PSS"), "{problem:?}");
    }
}

#[test]
fn certificate_signatures_by_a_pss_only_issuer_key() {
    // A path edge: the root as an anchor whose key is restricted to RSASSA-PSS cannot have made
    // the intermediate's sha256WithRSAEncryption signature.
    let root = cert("root.pem");
    let now = UnixTime::from_pdf_date(&PdfDate::parse(b"D:20261010120000Z").unwrap());
    let signer_cert = cert("signer-rsa2048.pem");
    let intermediate = cert("intermediate.pem");
    assert!(
        build_trust(
            &signer_cert,
            std::slice::from_ref(&intermediate),
            std::slice::from_ref(&root),
            now
        )
        .trusted
    );
    let pss_root = issue(
        0x3D00,
        &subject_of(&root),
        &subject_of(&root),
        &pss_spki(&spki_of(&root), None),
        &decoys::ca_extensions(),
        &signer("root.key.pem", "root.pem"),
    );
    let result = build_trust(&signer_cert, &[intermediate], &[pss_root], now);
    assert!(!result.trusted);
    assert!(
        result.reasons.iter().any(|r| r.contains("id-RSASSA-PSS")),
        "{:?}",
        result.reasons
    );
}

/// `AlgorithmIdentifier { OID, NULL }` of a SHA-2 hash (2.16.840.1.101.3.4.2.`last`).
fn sha2(last: u8) -> Vec<u8> {
    use decoys::der;
    der(
        0x30,
        &[
            der(
                0x06,
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last],
            ),
            vec![0x05, 0x00],
        ]
        .concat(),
    )
}

/// The `RSASSA-PSS-params` fields: `[0]` hash, `[1]` MGF1 with hash, `[2]` salt length.
fn pss_hash(hash: &[u8]) -> Vec<u8> {
    decoys::der(0xA0, hash)
}
fn pss_mgf1(hash: &[u8]) -> Vec<u8> {
    use decoys::der;
    der(
        0xA1,
        &der(
            0x30,
            &[
                der(
                    0x06,
                    &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08],
                ),
                hash.to_vec(),
            ]
            .concat(),
        ),
    )
}
fn pss_salt(salt: u8) -> Vec<u8> {
    decoys::der(0xA2, &decoys::der(0x02, &[salt]))
}

/// `RSASSA-PSS-params` written with `fields` as they are, and the `id-RSASSA-PSS`
/// AlgorithmIdentifier holding them.
fn pss_params_raw(fields: &[Vec<u8>]) -> Vec<u8> {
    decoys::der(0x30, &fields.concat())
}
fn pss_algorithm_raw(fields: &[Vec<u8>]) -> Vec<u8> {
    use decoys::der;
    der(
        0x30,
        &[
            der(
                0x06,
                &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A],
            ),
            pss_params_raw(fields),
        ]
        .concat(),
    )
}

/// The `RSASSA-PSS-params` variants of M4 final fix round 2, finding 2, each of which a
/// last-wins reader takes for SHA-256 with a 32-byte salt (what the TSA signs with): a
/// repeated hash, a repeated salt length, and the fields out of order. asn1crypto refuses
/// them ("Unknown element") or reads the first salt length, OpenSSL cannot decode them.
fn non_der_pss_params() -> [(&'static str, Vec<Vec<u8>>); 3] {
    let sha256 = sha2(0x01);
    let sha512 = sha2(0x03);
    [
        (
            "dup-hash",
            vec![
                pss_hash(&sha512),
                pss_hash(&sha256),
                pss_mgf1(&sha256),
                pss_salt(32),
            ],
        ),
        (
            "dup-salt",
            vec![
                pss_hash(&sha256),
                pss_mgf1(&sha256),
                pss_salt(64),
                pss_salt(32),
            ],
        ),
        (
            "out-of-order",
            vec![pss_mgf1(&sha256), pss_hash(&sha256), pss_salt(32)],
        ),
    ]
}

#[test]
fn pss_parameters_must_be_der_on_the_key_and_the_token() {
    // M4 final fix round 2, finding 2 (variants r8-pss-spkiq-dup-hash-last-sha1-tok-pss-sha1-20,
    // r8-pss-spkiq-dup-salt-last-20-tok-pss-sha1-20, r8-pss-spkiq-out-of-order-tok-pss-sha1-20,
    // r8-pss-tokparams-dup-hash-last-sha1, r8-pss-tokparams-dup-salt-last-20; pyHanko errors
    // or calls them invalid, OpenSSL cannot decode the key): the parameters were read in any
    // order, the last of a repeated field winning, so the token verified.
    let sha256 = sha2(0x01);
    // The control: the same parameters, once each and in order.
    let control = vec![pss_hash(&sha256), pss_mgf1(&sha256), pss_salt(32)];
    let tsa_cert = pss_tsa_cert(0x3E00, Some(&pss_params_raw(&control)));
    let r = report(&attack(&mock_tsa_pss_for(
        tsa_cert,
        32,
        MockTsaOptions::default(),
    )));
    let ts = r.timestamp.as_ref().unwrap();
    assert!(
        ts.intact && ts.valid && ts.trusted == Some(true),
        "control: {ts:?}"
    );

    for (serial, (name, fields)) in (0x3E10..).zip(non_der_pss_params()) {
        // On the TSA certificate's id-RSASSA-PSS key.
        let tsa_cert = pss_tsa_cert(serial, Some(&pss_params_raw(&fields)));
        let tsa = || mock_tsa_pss_for(tsa_cert.clone(), 32, MockTsaOptions::default());
        let r = report(&attack(&tsa()));
        let ts = r.timestamp.as_ref().unwrap();
        assert!(
            ts.intact && !ts.valid && ts.trusted == Some(false),
            "key {name}: {ts:?}"
        );
        assert_eq!(r.pades_level, Some(PadesLevel::BB), "key {name}");
        assert!(sign_with(tsa()).is_err(), "key {name}");

        // In the token's SignerInfo signatureAlgorithm (a plain RSA TSA certificate).
        let options = MockTsaOptions {
            signature_algorithm: Some(pss_algorithm_raw(&fields)),
            ..MockTsaOptions::default()
        };
        let tsa = || mock_tsa_pss_for(cert("tsa.pem"), 32, options.clone());
        let r = report(&attack(&tsa()));
        let ts = r.timestamp.as_ref().unwrap();
        assert!(ts.intact && !ts.valid, "token {name}: {ts:?}");
        assert_eq!(r.pades_level, Some(PadesLevel::BB), "token {name}");
        assert!(
            ts.problems.iter().any(|p| p.message.contains("RSASSA-PSS")),
            "token {name}: {ts:?}"
        );
        assert!(sign_with(tsa()).is_err(), "token {name}");
    }
}

/// `AlgorithmIdentifier { id-sha256, parameters… }` with the whole `parameters` elements as
/// given (none: absent).
fn sha256_with(parameters: &[Vec<u8>]) -> Vec<u8> {
    use decoys::der;
    let mut parts = vec![der(
        0x06,
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
    )];
    parts.extend(parameters.iter().cloned());
    der(0x30, &parts.concat())
}

#[test]
fn pss_hash_parameters_must_be_absent_or_null() {
    // M4 closing round, finding 7 (variants r9-pssanchor-int-hash-only, -int-mgf-only,
    // -int-both, -octets-both, -seq-both, r9-pss256-anchor-hash-alg-int-params; controls
    // r9-pssanchor-null-both-control, r9-pss256-anchor-hash-null-absent; pyHanko: untrusted,
    // as it compares the parameters structurally): RFC 4055 §2.1 allows only absent or NULL
    // parameters on the hash AlgorithmIdentifiers of RSASSA-PSS-params, the hash and the MGF1
    // hash. A trust anchor whose id-RSASSA-PSS key had an INTEGER there verified its
    // certificates' PSS signatures, so the TSA was trusted. Now such parameters make the key
    // unusable wherever they appear: on an anchor, on an intermediate, on the TSA certificate,
    // and in the token's signatureAlgorithm.
    let root = cert("root.pem");
    let tsa = cert("tsa.pem");
    let now = UnixTime::from_pdf_date(&time());
    let null = vec![0x05, 0x00];
    let integer = decoys::der(0x02, &[0x01]);
    let octets = decoys::der(0x04, &[]);
    let sequence = decoys::der(0x30, &[]);
    let variants: [(&str, Vec<u8>, Vec<u8>, bool); 8] = [
        (
            "null-both",
            sha256_with(std::slice::from_ref(&null)),
            sha256_with(std::slice::from_ref(&null)),
            true,
        ),
        ("absent-both", sha256_with(&[]), sha256_with(&[]), true),
        (
            "int-hash-only",
            sha256_with(std::slice::from_ref(&integer)),
            sha256_with(std::slice::from_ref(&null)),
            false,
        ),
        (
            "int-mgf-only",
            sha256_with(std::slice::from_ref(&null)),
            sha256_with(std::slice::from_ref(&integer)),
            false,
        ),
        (
            "int-both",
            sha256_with(std::slice::from_ref(&integer)),
            sha256_with(std::slice::from_ref(&integer)),
            false,
        ),
        (
            "octets-both",
            sha256_with(std::slice::from_ref(&octets)),
            sha256_with(std::slice::from_ref(&octets)),
            false,
        ),
        (
            "seq-both",
            sha256_with(std::slice::from_ref(&sequence)),
            sha256_with(std::slice::from_ref(&sequence)),
            false,
        ),
        (
            "two-params-hash",
            sha256_with(&[null.clone(), null.clone()]),
            sha256_with(std::slice::from_ref(&null)),
            false,
        ),
    ];
    let intermediate_name =
        decoys::test_name(decoys::der(0x0C, b"Folioxide Test PSS-only Intermediate"));
    for (serial, (name, hash, mgf_hash, accepted)) in (0x3F00u32..).step_by(8).zip(variants) {
        let fields = [pss_hash(&hash), pss_mgf1(&mgf_hash), pss_salt(32)];
        let params = pss_params_raw(&fields);

        // 1. The anchor: the root's name and key, the key restricted by these parameters. The
        //    TSA certificate is signed by the root key with RSASSA-PSS SHA-256 / 32.
        let anchor = issue(
            serial,
            &subject_of(&root),
            &subject_of(&root),
            &pss_spki(&spki_of(&root), Some(&params)),
            &decoys::ca_extensions(),
            &signer("root.key.pem", "root.pem"),
        );
        let tsa_cert = decoys::issue_pss(
            serial + 1,
            &subject_of(&root),
            &subject_of(&tsa),
            &spki_of(&tsa),
            &decoys::tsa_extensions(),
            "root.key.pem",
        );
        let result = x509info::build_trust_for(
            x509info::TrustPurpose::TimeStamping,
            &tsa_cert,
            &[],
            std::slice::from_ref(&anchor),
            now,
        );
        assert_eq!(
            result.trusted, accepted,
            "anchor {name}: {:?}",
            result.reasons
        );
        if !accepted {
            assert!(
                result
                    .reasons
                    .iter()
                    .any(|r| r.contains("RSASSA-PSS parameters")),
                "anchor {name}: {:?}",
                result.reasons
            );
        }
        // The same through verify_pdf, with the anchor as the only timestamp trust anchor.
        let options = VerifyOptions::new()
            .with_trust_anchors_der(anchors())
            .with_timestamp_trust_anchors_der(Some(vec![anchor.clone()]));
        let reports = verify_with(&attack(&pkcs1_tsa(tsa_cert)), &options);
        let ts = reports[0].timestamp.as_ref().unwrap();
        assert!(
            ts.intact && ts.valid && ts.trusted == Some(accepted),
            "anchor {name}: {ts:?}"
        );

        // 2. An intermediate under the root whose key (the RSA-3072 signer's) the parameters
        //    restrict, signing the TSA certificate with RSASSA-PSS SHA-256 / 32.
        let intermediate = issue(
            serial + 2,
            &subject_of(&root),
            &intermediate_name,
            &pss_spki(&spki_of(&cert("signer-rsa3072.pem")), Some(&params)),
            &decoys::ca_extensions(),
            &signer("root.key.pem", "root.pem"),
        );
        let tsa_cert = decoys::issue_pss(
            serial + 3,
            &intermediate_name,
            &subject_of(&tsa),
            &spki_of(&tsa),
            &decoys::tsa_extensions(),
            "signer-rsa3072.key.pem",
        );
        let result = x509info::build_trust_for(
            x509info::TrustPurpose::TimeStamping,
            &tsa_cert,
            &[intermediate],
            std::slice::from_ref(&root),
            now,
        );
        assert_eq!(
            result.trusted, accepted,
            "intermediate {name}: {:?}",
            result.reasons
        );

        // 3. The TSA certificate's own key restricted by them: the token is not valid, and
        //    Folioxide's signer refuses it.
        let tsa_cert = pss_tsa_cert(serial + 4, Some(&params));
        let tsa = || mock_tsa_pss_for(tsa_cert.clone(), 32, MockTsaOptions::default());
        let r = report(&attack(&tsa()));
        let ts = r.timestamp.as_ref().unwrap();
        assert_eq!(ts.valid, accepted, "key {name}: {ts:?}");
        assert_eq!(ts.trusted, Some(accepted), "key {name}: {ts:?}");
        assert_eq!(sign_with(tsa()).is_ok(), accepted, "key {name}");

        // 4. The token's SignerInfo signatureAlgorithm with them (a plain RSA TSA key).
        let options = MockTsaOptions {
            signature_algorithm: Some(pss_algorithm_raw(&fields)),
            ..MockTsaOptions::default()
        };
        let tsa = || mock_tsa_pss_for(cert("tsa.pem"), 32, options.clone());
        let r = report(&attack(&tsa()));
        let ts = r.timestamp.as_ref().unwrap();
        assert!(ts.intact && ts.valid == accepted, "token {name}: {ts:?}");
        assert_eq!(
            r.pades_level,
            Some(if accepted {
                PadesLevel::BT
            } else {
                PadesLevel::BB
            }),
            "token {name}"
        );
        assert_eq!(sign_with(tsa()).is_ok(), accepted, "token {name}");
    }
}

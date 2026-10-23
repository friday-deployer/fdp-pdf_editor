#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The parameters of a certificate's signature algorithm on every path edge (manager ruling
//! R-30 (b); M4 adversarial round 10, variants `r10-samealg-*`).
//!
//! The RSASSA-PKCS1-v1_5 algorithms take absent or NULL parameters (RFC 4055 §5), the ECDSA
//! algorithms none (RFC 5758 §3.2), in the outer `signatureAlgorithm` and in
//! `tbsCertificate.signature` alike. pyhanko-certvalidator does not trust a path through a
//! certificate with other parameters there (`r10-samealg-int-int`: timestamp trusted False),
//! where Folioxide had verified the signature and trusted the path. Every such edge is now
//! untrusted; NULL and absent parameters stay trusted. The certificates are issued at test time
//! from the committed keys of `fixtures/pki` (`bt_support::decoys`).

mod bt_support;

use bt_support::decoys::{
    self, children, content, der, issue_with, signer, spki_of, subject_of, tsa_extensions,
};
use bt_support::*;
use folioxide_model::PdfDate;
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::prepare::SignatureOptions;
use folioxide_sign::report::PadesLevel;
use folioxide_sign::signer::{LocalSigner, Signer as _};
use folioxide_sign::x509info::{TrustPurpose, TrustResult, UnixTime, build_trust, build_trust_for};
use folioxide_testkit::tsa::{MockTsa, MockTsaOptions};

/// `sha256WithRSAEncryption` (1.2.840.113549.1.1.11), content octets.
const SHA256_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
/// `ecdsa-with-SHA384` (1.2.840.10045.4.3.3), content octets.
const ECDSA_WITH_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];

/// The reason fragment of RSASSA-PKCS1-v1_5 parameters that are neither absent nor NULL.
const NOT_NULL: &str = "has parameters that are neither absent nor NULL (RFC 4055 §5)";
/// The reason fragment of ECDSA parameters that are present.
const NOT_ABSENT: &str = "has parameters, which must be absent (RFC 5758 §3.2)";

/// The validation time of the test PKI's checks.
fn now() -> UnixTime {
    UnixTime::from_pdf_date(&PdfDate::parse(b"D:20261010120000Z").unwrap())
}

/// The parameter cases: a name and the whole parameters element (`None`: absent).
fn parameters() -> Vec<(&'static str, Option<Vec<u8>>)> {
    vec![
        ("absent", None),
        ("null", Some(vec![0x05, 0x00])),
        ("integer", Some(der(0x02, &[0x01]))),
        ("octet-string", Some(der(0x04, &[]))),
        ("sequence", Some(der(0x30, &[]))),
    ]
}

/// The AlgorithmIdentifier of the OID content octets `oid` with `parameters`.
fn algorithm(oid: &[u8], parameters: Option<&[u8]>) -> Vec<u8> {
    der(
        0x30,
        &[der(0x06, oid), parameters.unwrap_or_default().to_vec()].concat(),
    )
}

/// `cert_der` with its outer `signatureAlgorithm` replaced by `outer`: the signature still
/// covers the unchanged `tbsCertificate`.
fn with_outer(cert_der: &[u8], outer: &[u8]) -> Vec<u8> {
    let parts = children(content(cert_der));
    der(0x30, &[parts[0], outer, parts[2]].concat())
}

#[track_caller]
fn assert_trusted(name: &str, result: &TrustResult) {
    assert!(result.trusted, "{name}: untrusted: {:?}", result.reasons);
}

#[track_caller]
fn assert_untrusted(name: &str, result: &TrustResult, fragments: &[&str]) {
    assert!(!result.trusted, "{name}: trusted, expected {fragments:?}");
    assert!(
        result
            .reasons
            .iter()
            .any(|r| fragments.iter().all(|f| r.contains(f))),
        "{name}: no reason contains {fragments:?}: {:?}",
        result.reasons
    );
}

/// The TSA certificate (`tsa.pem`'s name and key) issued by the root with
/// sha256WithRSAEncryption whose parameters are `inner` in `tbsCertificate` and `outer`
/// outside, as the round-10 variants `r10-samealg-<inner>-<outer>` build it.
fn tsa_cert(serial: u32, inner: Option<&[u8]>, outer: Option<&[u8]>) -> Vec<u8> {
    let root = cert("root.pem");
    let tsa = cert("tsa.pem");
    let root_key = signer("root.key.pem", "root.pem");
    let issued = issue_with(
        serial,
        &subject_of(&root),
        &subject_of(&tsa),
        &spki_of(&tsa),
        &tsa_extensions(),
        &algorithm(SHA256_WITH_RSA, inner),
        &|tbs| root_key.sign(DigestAlgorithm::Sha256, tbs).unwrap(),
    );
    with_outer(&issued, &algorithm(SHA256_WITH_RSA, outer))
}

/// The trust in `tsa_cert` for timestamping, under the test root.
fn tsa_trust(tsa_cert: &[u8]) -> TrustResult {
    build_trust_for(
        TrustPurpose::TimeStamping,
        tsa_cert,
        &[],
        &[cert("root.pem")],
        now(),
    )
}

#[test]
fn chain_rsa_signature_parameters_on_the_tsa_edge() {
    // r10-samealg-*: the same parameters inside and outside. NULL and absent are trusted (as
    // by pyHanko and OpenSSL); an INTEGER (pyHanko: trusted False), an OCTET STRING or a
    // SEQUENCE is an untrusted edge.
    for (index, (name, params)) in parameters().into_iter().enumerate() {
        let tsa = tsa_cert(0x3000 + index as u32, params.as_deref(), params.as_deref());
        let result = tsa_trust(&tsa);
        if matches!(name, "absent" | "null") {
            assert_trusted(name, &result);
        } else {
            assert_untrusted(
                name,
                &result,
                &["its signatureAlgorithm sha256WithRSAEncryption", NOT_NULL],
            );
        }
    }
}

#[test]
fn chain_rsa_signature_parameters_inside_and_outside_differ() {
    // r10-samealg-null-int and its mirror: each AlgorithmIdentifier is checked on its own, so
    // the edge fails whichever of the two carries the INTEGER.
    let integer = der(0x02, &[0x01]);
    let null = [0x05, 0x00];
    let result = tsa_trust(&tsa_cert(0x3010, Some(&null), Some(&integer)));
    assert_untrusted("null-int", &result, &["its signatureAlgorithm", NOT_NULL]);
    let result = tsa_trust(&tsa_cert(0x3011, Some(&integer), Some(&null)));
    assert_untrusted(
        "int-null",
        &result,
        &["its tbsCertificate signature", NOT_NULL],
    );
    // NULL inside, absent outside (r10-samealg-null-absent): the parameters suit the
    // algorithm, but the two AlgorithmIdentifiers differ (RFC 5280 §4.1.1.2), which path
    // validation refuses on its own (stricter than pyHanko, as before).
    let result = tsa_trust(&tsa_cert(0x3012, Some(&null), None));
    assert_untrusted(
        "null-absent",
        &result,
        &["the signature algorithm differs from the one in tbsCertificate"],
    );
}

#[test]
fn chain_rsa_signature_parameters_on_the_intermediate_edge() {
    // The intermediate CA (its name and key) re-issued by the root with sha256WithRSAEncryption
    // whose parameters are each case, inside and outside, over the RSA-2048 document signer.
    let root = cert("root.pem");
    let intermediate = cert("intermediate.pem");
    let root_key = signer("root.key.pem", "root.pem");
    let signer_cert = cert("signer-rsa2048.pem");
    for (index, (name, params)) in parameters().into_iter().enumerate() {
        let alg = algorithm(SHA256_WITH_RSA, params.as_deref());
        let reissued = issue_with(
            0x3100 + index as u32,
            &subject_of(&root),
            &subject_of(&intermediate),
            &spki_of(&intermediate),
            &decoys::ca_extensions(),
            &alg,
            &|tbs| root_key.sign(DigestAlgorithm::Sha256, tbs).unwrap(),
        );
        let result = build_trust(
            &signer_cert,
            &[reissued],
            std::slice::from_ref(&root),
            now(),
        );
        if matches!(name, "absent" | "null") {
            assert_trusted(name, &result);
        } else {
            assert_untrusted(name, &result, &[NOT_NULL]);
        }
    }
}

/// The RSA-2048 signer's certificate (its name and key) re-issued by the P-384 intermediate
/// with ecdsa-with-SHA384 whose parameters are `params`, inside and outside, and keyUsage
/// digitalSignature and nonRepudiation.
fn ecdsa_signer_cert(serial: u32, params: Option<&[u8]>) -> Vec<u8> {
    let intermediate = cert("intermediate.pem");
    let intermediate_key = signer("intermediate.key.pem", "intermediate.pem");
    let signer_cert = cert("signer-rsa2048.pem");
    issue_with(
        serial,
        &subject_of(&intermediate),
        &subject_of(&signer_cert),
        &spki_of(&signer_cert),
        &[decoys::extension(
            &[0x55, 0x1D, 0x0F],
            true,
            &der(0x03, &[0x06, 0xC0]),
        )],
        &algorithm(ECDSA_WITH_SHA384, params),
        &|tbs| intermediate_key.sign(DigestAlgorithm::Sha384, tbs).unwrap(),
    )
}

#[test]
fn chain_ecdsa_signature_parameters_on_the_signer_edge() {
    // ECDSA takes no parameters at all (RFC 5758 §3.2): only the absent case is trusted; NULL
    // too is an untrusted edge.
    let root = cert("root.pem");
    let intermediate = cert("intermediate.pem");
    for (index, (name, params)) in parameters().into_iter().enumerate() {
        let leaf = ecdsa_signer_cert(0x3200 + index as u32, params.as_deref());
        let result = build_trust(
            &leaf,
            std::slice::from_ref(&intermediate),
            std::slice::from_ref(&root),
            now(),
        );
        if name == "absent" {
            assert_trusted(name, &result);
        } else {
            assert_untrusted(
                name,
                &result,
                &["its signatureAlgorithm ecdsa-with-SHA384", NOT_ABSENT],
            );
        }
    }
}

/// A mock TSA for `tsa_cert` (a certificate of `tsa.key.pem`) carrying the root.
fn mock_with(tsa_cert: Vec<u8>) -> MockTsa {
    let key = tsa_key("tsa.pem");
    MockTsa::new(
        tsa_cert,
        vec![cert("root.pem")],
        Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
    )
    .with_options(MockTsaOptions::default())
}

#[test]
fn signature_timestamp_with_bad_certificate_signature_parameters_is_untrusted() {
    // r10-samealg-int-int end to end: the token stays intact and valid, the signature B-T, but
    // the token is not trusted (pyHanko: intact, valid, trusted False); the NULL control
    // (r10-samealg-null-null-control) stays trusted.
    for (index, (name, params)) in parameters().into_iter().enumerate() {
        let tsa_cert = tsa_cert(0x3300 + index as u32, params.as_deref(), params.as_deref());
        let tsa = Tsa(mock_with(tsa_cert));
        let signed =
            sign_bt_with(&minimal(), &rsa2048(), SignatureOptions::new(time()), &tsa).unwrap();
        let report = &verify(&signed)[0];
        assert!(report.is_valid(), "{name}: {}", summary(report));
        assert_eq!(report.pades_level, Some(PadesLevel::BT), "{name}");
        let ts = report.timestamp.as_ref().unwrap();
        assert!(ts.intact && ts.valid, "{name}: {ts:?}");
        let trusted = matches!(name, "absent" | "null");
        assert_eq!(ts.trusted, Some(trusted), "{name}: {ts:?}");
    }
}

#[test]
fn document_signature_with_bad_certificate_signature_parameters_is_untrusted() {
    // The document signer's certificate signed by the intermediate with ecdsa-with-SHA384:
    // absent parameters are trusted, an INTEGER is not; the signature itself stays valid.
    let intermediate = cert("intermediate.pem");
    for (serial, params, trusted) in [
        (0x3400, None, true),
        (0x3401, Some(der(0x02, &[0x01])), false),
    ] {
        let leaf = ecdsa_signer_cert(serial, params.as_deref());
        let signer = LocalSigner::from_pem(
            &pki_text("signer-rsa2048.key.pem"),
            &pem(&[leaf, intermediate.clone()]),
            None,
        )
        .unwrap();
        let signed = sign_bt(&minimal(), &signer);
        let report = &verify(&signed)[0];
        assert!(report.is_valid(), "{serial:x}: {}", summary(report));
        assert_eq!(
            report.trusted,
            Some(trusted),
            "{serial:x}: {}",
            summary(report)
        );
    }
}

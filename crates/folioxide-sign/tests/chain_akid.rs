#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The authorityKeyIdentifier on every path edge (manager ruling R-22 (a); M4 QA round 5
//! findings 32 and 40–47; RFC 5280 §4.2.1.1).
//!
//! pyhanko-certvalidator skips a candidate issuer whose subjectKeyIdentifier differs from the
//! certificate's authority keyIdentifier, or whose own issuer and serial differ from the
//! authorityCertIssuer and authorityCertSerialNumber (`find_potential_issuers`,
//! `is_potential_issuer_of`); OpenSSL's `X509_check_akid` refuses the same edges and also a
//! serial number given alone. Folioxide refuses the union, for document signers, signature
//! timestamps and document timestamps alike. The certificates are issued at test time from the
//! committed keys of `fixtures/pki` (`bt_support::decoys`).

mod bt_support;

use bt_support::decoys::{
    self, der, extension, intermediate_with, issuer_of, reencode_name, serial_of, signer_cert_with,
    ski_of, subject_of, tsa_cert_with,
};
use bt_support::*;
use folioxide_model::PdfDate;
use folioxide_sign::ProblemCode;
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::prepare::SignatureOptions;
use folioxide_sign::report::PadesLevel;
use folioxide_sign::signer::{LocalSigner, Signer as _};
use folioxide_sign::x509info::{TrustPurpose, TrustResult, UnixTime, build_trust, build_trust_for};
use folioxide_testkit::tsa::{Ess, MockTsa, MockTsaOptions};

/// The validation time of the test PKI's checks.
fn now() -> UnixTime {
    UnixTime::from_pdf_date(&PdfDate::parse(b"D:20261010120000Z").unwrap())
}

#[track_caller]
fn assert_trusted(name: &str, result: &TrustResult) {
    assert!(result.trusted, "{name}: untrusted: {:?}", result.reasons);
}

#[track_caller]
fn assert_untrusted(name: &str, result: &TrustResult, fragment: &str) {
    assert!(!result.trusted, "{name}: trusted, expected {fragment:?}");
    assert!(
        result.reasons.iter().any(|r| r.contains(fragment)),
        "{name}: no reason contains {fragment:?}: {:?}",
        result.reasons
    );
}

/// `AuthorityKeyIdentifier { keyIdentifier [0], authorityCertIssuer [1], serial [2] }` as a
/// non-critical extension; `issuer` is the content of `[1]` (one or more GeneralNames).
fn akid(key_id: Option<&[u8]>, issuer: Option<Vec<u8>>, serial: Option<&[u8]>) -> Vec<u8> {
    let mut parts = Vec::new();
    if let Some(key_id) = key_id {
        parts.push(der(0x80, key_id));
    }
    if let Some(issuer) = issuer {
        parts.push(der(0xA1, &issuer));
    }
    if let Some(serial) = serial {
        parts.push(der(0x82, serial));
    }
    extension(&[0x55, 0x1D, 0x23], false, &der(0x30, &parts.concat()))
}

/// A `directoryName` GeneralName.
fn dir(name: &[u8]) -> Vec<u8> {
    der(0xA4, name)
}

/// A wrong key identifier.
const WRONG_KEY_ID: [u8; 20] = [0xAA; 20];
/// A wrong serial number (INTEGER content).
const WRONG_SERIAL: [u8; 2] = [0x01, 0x02];

/// The AKI cases of the round-5 variants for a certificate whose issuer has the key
/// identifier `key_id`, the issuer name `issuer_issuer` (the issuer's own issuer) and the serial
/// `serial`; `other` is a name that is not `issuer_issuer`. Each is `(name, extension, trusted,
/// reason fragment)`.
fn cases(
    key_id: &[u8],
    issuer_issuer: &[u8],
    serial: &[u8],
    other: &[u8],
) -> Vec<(&'static str, Vec<u8>, bool, &'static str)> {
    const KEY_ID: &str = "its keyIdentifier is not the issuer's subjectKeyIdentifier";
    const SERIAL: &str = "its authorityCertSerialNumber is not the issuer's serial number";
    const ISSUER: &str = "its authorityCertIssuer does not name the issuer's own issuer";
    const NO_SERIAL: &str = "its authorityCertIssuer comes without authorityCertSerialNumber";
    vec![
        // pyHanko and OpenSSL refuse these (variants r6-akid-*).
        (
            "keyid-wrong",
            akid(Some(&WRONG_KEY_ID), None, None),
            false,
            KEY_ID,
        ),
        (
            "keyid-wrong-with-correct-issuer-serial",
            akid(Some(&WRONG_KEY_ID), Some(dir(issuer_issuer)), Some(serial)),
            false,
            KEY_ID,
        ),
        (
            "serial-wrong",
            akid(Some(key_id), Some(dir(issuer_issuer)), Some(&WRONG_SERIAL)),
            false,
            SERIAL,
        ),
        (
            "issuer-wrong",
            akid(Some(key_id), Some(dir(other)), Some(serial)),
            false,
            ISSUER,
        ),
        (
            "issuer-only-wrong",
            akid(None, Some(dir(other)), None),
            false,
            NO_SERIAL,
        ),
        // OpenSSL refuses a wrong serial given alone; pyHanko ignores it (stricter than pyHanko).
        (
            "serial-only-wrong",
            akid(None, None, Some(&WRONG_SERIAL)),
            false,
            SERIAL,
        ),
        // pyHanko compares the issuer and serial as a pair: an issuer without a serial never
        // matches, even the right one.
        (
            "issuer-correct-without-serial",
            akid(Some(key_id), Some(dir(issuer_issuer)), None),
            false,
            NO_SERIAL,
        ),
        // pyHanko reads the first GeneralName: a dNSName before the right directoryName.
        (
            "issuer-dns-first",
            akid(
                Some(key_id),
                Some([der(0x82, b"ca.example"), dir(issuer_issuer)].concat()),
                Some(serial),
            ),
            false,
            ISSUER,
        ),
        // pyHanko hashes the name's bytes: another encoding of the same name does not match.
        (
            "issuer-reencoded",
            akid(
                None,
                Some(dir(&reencode_name(issuer_issuer, 0x13, false))),
                Some(serial),
            ),
            false,
            ISSUER,
        ),
        // Controls: what describes the issuer is trusted.
        (
            "all-correct",
            akid(Some(key_id), Some(dir(issuer_issuer)), Some(serial)),
            true,
            "",
        ),
        (
            "keyid-correct-only",
            akid(Some(key_id), None, None),
            true,
            "",
        ),
        (
            "issuer-serial-correct",
            akid(None, Some(dir(issuer_issuer)), Some(serial)),
            true,
            "",
        ),
        ("empty", akid(None, None, None), true, ""),
    ]
}

#[track_caller]
fn check(name: &str, result: &TrustResult, trusted: bool, fragment: &str) {
    if trusted {
        assert_trusted(name, result);
    } else {
        assert_untrusted(name, result, fragment);
        assert_untrusted(name, result, "(RFC 5280 §4.2.1.1)");
    }
}

#[test]
fn chain_akid_on_the_signer_edge() {
    // The document signer (variants doc6-akid-leaf-*): the RSA-2048 signer re-issued by the
    // intermediate with an authorityKeyIdentifier that does (not) describe the intermediate.
    let root = cert("root.pem");
    let intermediate = cert("intermediate.pem");
    let key_id = ski_of(&intermediate).unwrap();
    let serial = serial_of(&intermediate);
    let issuer_issuer = issuer_of(&intermediate);
    assert_eq!(issuer_issuer, subject_of(&root));
    for (index, (name, ext, trusted, fragment)) in
        cases(&key_id, &issuer_issuer, &serial, &subject_of(&intermediate))
            .into_iter()
            .enumerate()
    {
        let leaf = signer_cert_with(0x2A00 + index as u32, &[ext]);
        let result = build_trust(
            &leaf,
            std::slice::from_ref(&intermediate),
            std::slice::from_ref(&root),
            now(),
        );
        check(&format!("leaf {name}"), &result, trusted, fragment);
    }
    // doc6-akid-leaf-keyid-correct-only: an AKI that describes the ROOT, not the actual issuer.
    let leaf = signer_cert_with(0x2A40, &[akid(Some(&ski_of(&root).unwrap()), None, None)]);
    assert_untrusted(
        "leaf AKI names the root",
        &build_trust(
            &leaf,
            std::slice::from_ref(&intermediate),
            std::slice::from_ref(&root),
            now(),
        ),
        "its keyIdentifier is not the issuer's subjectKeyIdentifier",
    );
    // The signer that is itself the anchor has no issuer edge: its AKI is not compared.
    let leaf = signer_cert_with(0x2A41, &[akid(Some(&WRONG_KEY_ID), None, None)]);
    assert_trusted(
        "signer as anchor",
        &build_trust(&leaf, &[], std::slice::from_ref(&leaf), now()),
    );
}

#[test]
fn chain_akid_on_the_intermediate_edge() {
    // The intermediate CA (variants doc6-akid-inter-*, r6-akid-inter-*): re-issued by the root
    // with an authorityKeyIdentifier that does (not) describe the root, the trust anchor.
    let root = cert("root.pem");
    let signer = cert("signer-rsa2048.pem");
    let key_id = ski_of(&root).unwrap();
    let serial = serial_of(&root);
    let issuer_issuer = issuer_of(&root);
    let other = subject_of(&cert("intermediate.pem"));
    for (index, (name, ext, trusted, fragment)) in cases(&key_id, &issuer_issuer, &serial, &other)
        .into_iter()
        .enumerate()
    {
        let intermediate = intermediate_with(0x2B00 + index as u32, &[ext]);
        let result = build_trust(&signer, &[intermediate], std::slice::from_ref(&root), now());
        check(&format!("intermediate {name}"), &result, trusted, fragment);
    }
}

#[test]
fn chain_akid_on_the_tsa_edge() {
    // The TSA certificate (variants r6-akid-leaf-*, r6-tsacert-akid-issuer-plain), for the
    // timestamping purpose: the TSA re-issued by the root with an AKI that does (not) describe
    // the root.
    let root = cert("root.pem");
    let tsa_subject = subject_of(&cert("tsa.pem"));
    let key_id = ski_of(&root).unwrap();
    let serial = serial_of(&root);
    let issuer_issuer = issuer_of(&root);
    for (index, (name, ext, trusted, fragment)) in
        cases(&key_id, &issuer_issuer, &serial, &tsa_subject)
            .into_iter()
            .enumerate()
    {
        let tsa = tsa_cert_with(0x2C00 + index as u32, &tsa_subject, &[ext]);
        let result = build_trust_for(
            TrustPurpose::TimeStamping,
            &tsa,
            &[],
            std::slice::from_ref(&root),
            now(),
        );
        check(&format!("tsa {name}"), &result, trusted, fragment);
    }
}

/// A mock TSA for `tsa_cert` (a certificate of `tsa.key.pem`) carrying `extra`.
fn mock_with(tsa_cert: Vec<u8>, extra: Vec<Vec<u8>>, options: MockTsaOptions) -> MockTsa {
    let key = tsa_key("tsa.pem");
    MockTsa::new(
        tsa_cert,
        extra,
        Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
    )
    .with_options(options)
}

#[test]
fn signature_timestamp_with_akid_mismatch_is_untrusted() {
    // r6-akid-leaf-keyid-wrong, r6-v8-akid-mismatch-token-b-t, r6-v9-null-akid-mismatch-*: the
    // token stays intact and valid (OpenSSL's ts -verify fails on the chain only), the signature
    // B-T, but the token is not trusted, so it never moves the signer's trust time (V9).
    let root = cert("root.pem");
    let tsa_subject = subject_of(&cert("tsa.pem"));
    let bad = tsa_cert_with(
        0x2D00,
        &tsa_subject,
        &[akid(Some(&WRONG_KEY_ID), None, None)],
    );
    let good = tsa_cert_with(
        0x2D01,
        &tsa_subject,
        &[akid(Some(&ski_of(&root).unwrap()), None, None)],
    );
    for (name, tsa_cert, trusted) in [("keyid-wrong", bad, false), ("keyid-correct", good, true)] {
        let tsa = Tsa(mock_with(
            tsa_cert,
            vec![root.clone()],
            MockTsaOptions::default(),
        ));
        let signed =
            sign_bt_with(&minimal(), &rsa2048(), SignatureOptions::new(time()), &tsa).unwrap();
        let report = &verify(&signed)[0];
        assert!(report.is_valid(), "{name}: {}", summary(report));
        assert_eq!(report.pades_level, Some(PadesLevel::BT), "{name}");
        let ts = report.timestamp.as_ref().unwrap();
        assert!(ts.intact && ts.valid, "{name}: {ts:?}");
        assert_eq!(ts.trusted, Some(trusted), "{name}: {ts:?}");
    }

    // r6-akid-inter-keyid-wrong: the TSA under an intermediate whose AKI does not describe the
    // root.
    let d = decoys::decoys();
    for (serial, ext, trusted) in [
        (0x2D10, akid(Some(&WRONG_KEY_ID), None, None), false),
        (
            0x2D11,
            akid(Some(&ski_of(&root).unwrap()), None, None),
            true,
        ),
    ] {
        let intermediate = intermediate_with(serial, &[ext]);
        let tsa = Tsa(mock_with(
            d.tsa_via_intermediate.clone(),
            vec![intermediate, root.clone()],
            MockTsaOptions::default(),
        ));
        let signed =
            sign_bt_with(&minimal(), &rsa2048(), SignatureOptions::new(time()), &tsa).unwrap();
        let ts = verify(&signed)[0].timestamp.clone().unwrap();
        assert!(ts.intact && ts.valid, "{serial:x}: {ts:?}");
        assert_eq!(ts.trusted, Some(trusted), "{serial:x}: {ts:?}");
    }
}

#[test]
fn later_ess_identifiers_need_an_akid_consistent_link() {
    // The ESS later identifiers are resolved against certificates linked by name, signature
    // and authority key identifier (linked_issuers): a TSA certificate whose AKI does not
    // describe the root does not link to it, so an identifier that names the root is not found,
    // as in OpenSSL's verified chain (stricter than pyHanko, which reads the first identifier).
    let root = cert("root.pem");
    let tsa_subject = subject_of(&cert("tsa.pem"));
    for (serial, key_id, valid) in [
        (0x2E00, WRONG_KEY_ID.to_vec(), false),
        (0x2E01, ski_of(&root).unwrap(), true),
    ] {
        let tsa_cert = tsa_cert_with(serial, &tsa_subject, &[akid(Some(&key_id), None, None)]);
        let options = MockTsaOptions {
            ess: Ess::V2,
            ess_cert_ids: Some(vec![tsa_cert.clone(), root.clone()]),
            ..MockTsaOptions::default()
        };
        let tsa = Tsa(mock_with(tsa_cert, vec![root.clone()], options));
        let result = sign_bt_with(&minimal(), &rsa2048(), SignatureOptions::new(time()), &tsa);
        if valid {
            let ts = verify(&result.unwrap())[0].timestamp.clone().unwrap();
            assert!(ts.intact && ts.valid && ts.trusted == Some(true), "{ts:?}");
        } else {
            // The signing side refuses the token; so does the verifier, below finish.
            let err = result.unwrap_err();
            assert!(err.to_string().contains("ESS"), "{err}");
        }
    }
}

#[test]
fn document_signature_with_akid_mismatch_is_untrusted() {
    // doc6-akid-leaf-keyid-wrong (variants nc_doc6/akid-*): a document signature whose signer
    // certificate's AKI does not describe the intermediate. pyHanko: valid, trusted False.
    let intermediate = cert("intermediate.pem");
    for (serial, ext, trusted) in [
        (0x2F00, akid(Some(&WRONG_KEY_ID), None, None), false),
        (
            0x2F01,
            akid(Some(&ski_of(&intermediate).unwrap()), None, None),
            true,
        ),
    ] {
        let leaf = signer_cert_with(serial, &[ext]);
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
        if !trusted {
            assert!(
                report
                    .warnings
                    .iter()
                    .chain(report.problems.iter().map(|p| &p.message))
                    .any(|w| w.contains("authorityKeyIdentifier")),
                "{}",
                summary(report)
            );
            assert!(!report.has_problem(ProblemCode::SignatureInvalid));
        }
    }
}

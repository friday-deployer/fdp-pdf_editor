#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Path validation and certificate extensions (M4 QA round 4 findings 5 and 9;
//! `x509info::build_trust`, RFC 5280 §4.2, §6.1).
//!
//! The certificates are issued at test time from the committed keys of `fixtures/pki`
//! (`bt_support::decoys`): the intermediate CA re-issued by the root with extra extensions (so
//! every certificate the real intermediate issued chains to it as well), the RSA-2048 signer and
//! the TSA re-issued with extra extensions. pyhanko-certvalidator processes name and policy
//! constraints and refuses an extension it cannot parse; OpenSSL refuses a known extension that
//! does not decode (`EXFLAG_INVALID`) and applies name constraints. Folioxide processes neither
//! constraint, so a path with one on an issuer is untrusted whether it is critical or not, and
//! every known extension must decode.

mod bt_support;

use bt_support::decoys::{
    der, extension, intermediate_with, signer_cert_with, spki_of, subject_of, tsa_cert_with,
};
use bt_support::*;
use folioxide_model::PdfDate;
use folioxide_sign::report::PadesLevel;
use folioxide_sign::signer::{LocalSigner, Signer as _};
use folioxide_sign::x509info::{TrustResult, UnixTime, build_trust};
use folioxide_testkit::tsa::{MockTsa, MockTsaOptions};

/// The validation time of the test PKI's checks.
fn now() -> UnixTime {
    UnixTime::from_pdf_date(&PdfDate::parse(b"D:20261010120000Z").unwrap())
}

/// `build_trust` with the root as the only anchor.
fn under_root(leaf: &[u8], pool: &[Vec<u8>]) -> TrustResult {
    build_trust(leaf, pool, &[cert("root.pem")], now())
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

/// The extension OIDs (content octets).
const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x1E];
const POLICY_MAPPINGS: &[u8] = &[0x55, 0x1D, 0x21];
const POLICY_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x24];
const INHIBIT_ANY_POLICY: &[u8] = &[0x55, 0x1D, 0x36];
const AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1D, 0x23];
const SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1D, 0x0E];
const CRL_DISTRIBUTION_POINTS: &[u8] = &[0x55, 0x1D, 0x1F];
const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11];
const ISSUER_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x12];
const CERTIFICATE_POLICIES: &[u8] = &[0x55, 0x1D, 0x20];
const AUTHORITY_INFO_ACCESS: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];

/// `SEQUENCE { e… }`.
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &parts.concat())
}

/// `NameConstraints` with one subtree whose base is `base`, permitted (`[0]`) or excluded
/// (`[1]`).
fn name_constraints(excluded: bool, base: Vec<u8>) -> Vec<u8> {
    seq(&[der(if excluded { 0xA1 } else { 0xA0 }, &seq(&[base]))])
}

/// A non-critical extension.
fn plain(oid: &[u8], value: &[u8]) -> Vec<u8> {
    extension(oid, false, value)
}

/// `anyPolicy` (2.5.29.32.0).
fn any_policy() -> Vec<u8> {
    der(0x06, &[0x55, 0x1D, 0x20, 0x00])
}

/// A test policy OID (1.2.3.4.`last`).
fn test_policy(last: u8) -> Vec<u8> {
    der(0x06, &[0x2A, 0x03, 0x04, last])
}

#[test]
fn chain_constraints_folioxide_does_not_process_make_the_path_untrusted() {
    // Finding 5 (variants r5-trust-ca-nc-*-noncritical, r5-trust-nc-dns-*-noncritical,
    // r5-trust-ca-policy-require-explicit-0-noncritical) and finding 9 (nc_doc): a NON-critical
    // nameConstraints, policyConstraints or policyMappings on the intermediate was ignored, so
    // Folioxide trusted paths pyHanko and OpenSSL reject (excluded or permitted subtree
    // violation, explicit policy required).
    let signer = cert("signer-rsa2048.pem");
    let signer_dn = der(0xA4, &subject_of(&signer));
    let other_dn = der(0xA4, &subject_of(&cert("root.pem")));
    let dns = der(0x82, b"example.org");

    // The control: the same intermediate, re-issued without constraints.
    assert_trusted(
        "control",
        &under_root(&signer, &[intermediate_with(0x1C00, &[])]),
    );

    for (serial, (name, ext)) in (0x1C10..).zip([
        (
            "r5-trust-ca-nc-exclude-own-dn-noncritical (nc_doc)",
            plain(NAME_CONSTRAINTS, &name_constraints(true, signer_dn.clone())),
        ),
        (
            "r5-trust-ca-nc-permit-other-dn-noncritical",
            plain(NAME_CONSTRAINTS, &name_constraints(false, other_dn)),
        ),
        (
            "r5-trust-nc-dns-permit-other-dns-noncritical",
            plain(NAME_CONSTRAINTS, &name_constraints(false, dns.clone())),
        ),
        // Satisfied constraints are refused too: stricter than pyHanko and OpenSSL, which
        // trust these paths (brief §0.1, the sign-bt row tst-tsa-ca-name-constraints-satisfied).
        (
            "a nameConstraints the path satisfies",
            plain(NAME_CONSTRAINTS, &name_constraints(true, dns.clone())),
        ),
        (
            "r5-trust-ca-policy-require-explicit-0-noncritical",
            plain(POLICY_CONSTRAINTS, &seq(&[der(0x80, &[0])])),
        ),
        (
            "policyMappings",
            plain(
                POLICY_MAPPINGS,
                &seq(&[seq(&[test_policy(1), test_policy(2)])]),
            ),
        ),
        (
            "a critical nameConstraints",
            extension(
                NAME_CONSTRAINTS,
                true,
                &name_constraints(true, signer_dn.clone()),
            ),
        ),
    ]) {
        let intermediate = intermediate_with(serial, &[ext]);
        assert_untrusted(
            name,
            &under_root(&signer, &[intermediate]),
            "which Folioxide does not process",
        );
    }

    // policyConstraints on the signer itself (its requireExplicitPolicy takes effect at the end
    // of the path, RFC 5280 §6.1.5 (b)).
    let leaf = signer_cert_with(
        0x1C30,
        &[plain(POLICY_CONSTRAINTS, &seq(&[der(0x80, &[0])]))],
    );
    assert_untrusted(
        "policyConstraints on the signer",
        &under_root(&leaf, &[cert("intermediate.pem")]),
        "policyConstraints",
    );

    // Controls: a non-critical inhibitAnyPolicy cannot fail a path without policy constraints,
    // and name constraints on the signer constrain nothing (RFC 5280 §6.1.4 (g) prepares the
    // next certificate).
    let inhibit = intermediate_with(0x1C40, &[plain(INHIBIT_ANY_POLICY, &der(0x02, &[0]))]);
    assert_trusted(
        "r5-trust-ca-inhibit-any-policy-0-noncritical",
        &under_root(&signer, &[inhibit]),
    );
    let leaf = signer_cert_with(
        0x1C41,
        &[plain(NAME_CONSTRAINTS, &name_constraints(true, dns))],
    );
    assert_trusted(
        "nameConstraints on the signer",
        &under_root(&leaf, &[cert("intermediate.pem")]),
    );
}

#[test]
fn chain_known_extensions_must_decode() {
    // Finding 5 (variants r5-ext-junk-ca-{akid,ski,crldp,nc,eku,san},
    // r5-ext-junk-leaf-{san,crldp,nc}, and the waived ones pyHanko refuses: certpol, polmap,
    // polcons, inhibit, ian, aia, freshcrl): a known extension whose value does not decode makes
    // the certificate unusable for pyHanko and OpenSSL, critical or not.
    let signer = cert("signer-rsa2048.pem");
    // A NULL: no known extension's value (QA used an INTEGER, which is a valid inhibitAnyPolicy).
    let junk = vec![0x05, 0x00];
    let ca_cases: [(&str, &[u8]); 9] = [
        ("r5-ext-junk-ca-akid", AUTHORITY_KEY_ID),
        ("r5-ext-junk-ca-ski", SUBJECT_KEY_ID),
        ("r5-ext-junk-ca-crldp", CRL_DISTRIBUTION_POINTS),
        ("r5-ext-junk-ca-nc", NAME_CONSTRAINTS),
        ("r5-ext-junk-ca-eku", EXT_KEY_USAGE),
        ("r5-ext-junk-ca-san", SUBJECT_ALT_NAME),
        ("r5-ext-junk-ca-certpol", CERTIFICATE_POLICIES),
        ("r5-ext-junk-ca-ian", ISSUER_ALT_NAME),
        ("r5-ext-junk-ca-aia", AUTHORITY_INFO_ACCESS),
    ];
    for (serial, (name, oid)) in (0x1D00..).zip(ca_cases) {
        let intermediate = intermediate_with(serial, &[plain(oid, &junk)]);
        // The signer's authorityKeyIdentifier names the intermediate's key identifier, so an
        // intermediate whose subjectKeyIdentifier does not decode is no issuer of it at all
        // (manager ruling R-22 (a)).
        let fragment = if oid == SUBJECT_KEY_ID {
            "subjectKeyIdentifier, which its keyIdentifier must equal, does not decode"
        } else {
            "extension that does not decode"
        };
        assert_untrusted(name, &under_root(&signer, &[intermediate]), fragment);
    }
    let leaf_cases: [(&str, &[u8]); 7] = [
        ("r5-ext-junk-leaf-san", SUBJECT_ALT_NAME),
        ("r5-ext-junk-leaf-crldp", CRL_DISTRIBUTION_POINTS),
        ("r5-ext-junk-leaf-nc", NAME_CONSTRAINTS),
        ("r5-ext-junk-leaf-polcons", POLICY_CONSTRAINTS),
        ("r5-ext-junk-leaf-inhibit", INHIBIT_ANY_POLICY),
        ("r5-ext-junk-leaf-polmap", POLICY_MAPPINGS),
        ("r5-ext-junk-leaf-akid", AUTHORITY_KEY_ID),
    ];
    for (serial, (name, oid)) in (0x1D20..).zip(leaf_cases) {
        let leaf = signer_cert_with(serial, &[plain(oid, &junk)]);
        assert_untrusted(
            name,
            &under_root(&leaf, &[cert("intermediate.pem")]),
            "extension that does not decode",
        );
    }
    // A subjectAltName whose directoryName OpenSSL cannot convert (finding 1) does not decode.
    let surrogate = der(
        0xA4,
        &bt_support::decoys::test_name(bt_support::decoys::bmp(&[0xD83D, 0xDE00])),
    );
    let leaf = signer_cert_with(0x1D40, &[plain(SUBJECT_ALT_NAME, &seq(&[surrogate]))]);
    assert_untrusted(
        "a subjectAltName with a BMPString surrogate pair",
        &under_root(&leaf, &[cert("intermediate.pem")]),
        "extension that does not decode",
    );

    // Finding 1 on the path: a signer whose subject holds a BMPString surrogate (OpenSSL cannot
    // decode the certificate, asn1crypto fails on it) is not trusted; NUL and U+FFFE are fine.
    let issue_leaf = |serial: u32, units: &[u16]| {
        bt_support::decoys::issue(
            serial,
            &subject_of(&cert("intermediate.pem")),
            &bt_support::decoys::test_name(bt_support::decoys::bmp(units)),
            &spki_of(&signer),
            &[extension(
                &[0x55, 0x1D, 0x0F],
                true,
                &der(0x03, &[0x06, 0xC0]),
            )],
            &bt_support::decoys::signer("intermediate.key.pem", "intermediate.pem"),
        )
    };
    assert_untrusted(
        "a signer subject with a lone surrogate",
        &under_root(
            &issue_leaf(0x1D45, &[0x54, 0xD800]),
            &[cert("intermediate.pem")],
        ),
        "cannot convert to UTF-8",
    );
    assert_trusted(
        "a signer subject with NUL and U+FFFE",
        &under_root(
            &issue_leaf(0x1D46, &[0x54, 0x0000, 0xFFFE]),
            &[cert("intermediate.pem")],
        ),
    );

    // Controls: the same extensions, well formed, on the intermediate and on the signer, with
    // authority key identifiers that name each issuer's subject key identifier (R-22 (a)).
    let uri = der(0x86, b"http://example.org/ca.crl");
    let root_ski = bt_support::decoys::ski_of(&cert("root.pem")).unwrap();
    let key_ids = |authority: &[u8], subject: &[u8]| {
        [
            plain(AUTHORITY_KEY_ID, &seq(&[der(0x80, authority)])),
            plain(SUBJECT_KEY_ID, &der(0x04, subject)),
        ]
    };
    let good = [
        plain(
            CRL_DISTRIBUTION_POINTS,
            &seq(&[seq(&[der(0xA0, &der(0xA0, &uri))])]),
        ),
        plain(
            CERTIFICATE_POLICIES,
            &seq(&[seq(&[any_policy()]), seq(&[test_policy(1)])]),
        ),
        plain(ISSUER_ALT_NAME, &seq(std::slice::from_ref(&uri))),
        plain(
            AUTHORITY_INFO_ACCESS,
            &seq(&[seq(&[
                der(0x06, &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]),
                uri.clone(),
            ])]),
        ),
    ];
    let intermediate = intermediate_with(
        0x1D50,
        &[&key_ids(&root_ski, &[1, 2, 3, 4])[..], &good].concat(),
    );
    let mut leaf_extensions = [&key_ids(&[1, 2, 3, 4], &[5, 6, 7, 8])[..], &good].concat();
    leaf_extensions.push(plain(
        EXT_KEY_USAGE,
        &seq(&[der(0x06, &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04])]),
    ));
    leaf_extensions.push(plain(
        SUBJECT_ALT_NAME,
        &seq(&[der(0x81, b"signer@example.org"), der(0x82, b"example.org")]),
    ));
    let leaf = signer_cert_with(0x1D51, &leaf_extensions);
    assert_trusted(
        "well-formed extensions",
        &under_root(&leaf, &[intermediate]),
    );
}

#[test]
fn chain_name_constraints_document_signature_untrusted() {
    // Finding 9 (/tmp nc_doc/nc-exclude-noncritical.pdf): a document signature whose chain runs
    // through an intermediate with a NON-critical nameConstraints excluding the signer's name.
    // pyHanko: trusted False; Folioxide trusted it. The signature itself stays valid.
    let signer_cert = cert("signer-rsa2048.pem");
    let constraint = plain(
        NAME_CONSTRAINTS,
        &name_constraints(true, der(0xA4, &subject_of(&signer_cert))),
    );
    for (name, intermediate, trusted) in [
        ("plain", intermediate_with(0x1E00, &[]), true),
        (
            "nc-exclude-noncritical",
            intermediate_with(0x1E01, &[constraint]),
            false,
        ),
    ] {
        let signer = LocalSigner::from_pem(
            &pki_text("signer-rsa2048.key.pem"),
            &pem(&[signer_cert.clone(), intermediate]),
            None,
        )
        .unwrap();
        let signed = sign_bt(&minimal(), &signer);
        let report = &verify(&signed)[0];
        assert!(report.is_valid(), "{name}: {}", summary(report));
        assert_eq!(report.trusted, Some(trusted), "{name}: {}", summary(report));
        if !trusted {
            assert!(
                report
                    .warnings
                    .iter()
                    .any(|w| w.contains("nameConstraints")),
                "{name}: {:?}",
                report.warnings
            );
        }
    }
}

#[test]
fn tsa_path_name_constraints_untrusted() {
    // Finding 5 on the timestamp path: the TSA certificate issued by an intermediate whose
    // non-critical nameConstraints excludes the TSA's name (pyHanko: trusted False; OpenSSL:
    // excluded subtree violation). The token stays intact and valid; only its trust goes.
    let d = bt_support::decoys::decoys();
    let tsa_cert = d.tsa_via_intermediate.clone();
    let excluded = plain(
        NAME_CONSTRAINTS,
        &name_constraints(true, der(0xA4, &subject_of(&tsa_cert))),
    );
    for (name, intermediate, trusted) in [
        ("plain", intermediate_with(0x1F00, &[]), true),
        ("excluded", intermediate_with(0x1F01, &[excluded]), false),
    ] {
        let key = tsa_key("tsa.pem");
        let tsa = Tsa(MockTsa::new(
            tsa_cert.clone(),
            vec![intermediate, cert("root.pem")],
            Box::new(move |attrs| {
                key.sign(folioxide_sign::algorithms::DigestAlgorithm::Sha256, attrs)
                    .unwrap()
            }),
        )
        .with_options(MockTsaOptions::default()));
        let signed = sign_bt_with(
            &minimal(),
            &rsa2048(),
            folioxide_sign::prepare::SignatureOptions::new(time()),
            &tsa,
        )
        .unwrap();
        let report = &verify(&signed)[0];
        assert_eq!(report.pades_level, Some(PadesLevel::BT), "{name}");
        let ts = report.timestamp.as_ref().unwrap();
        assert!(ts.intact && ts.valid, "{name}: {ts:?}");
        assert_eq!(ts.trusted, Some(trusted), "{name}: {ts:?}");
    }
    // A subjectAltName on the TSA certificate that does not decode makes the token invalid,
    // not merely untrusted: OpenSSL marks such a certificate invalid (ruling R-22 (c), QA round 5
    // finding 37), so the signing side refuses the response (verify_bt.rs has the verifying
    // side).
    let junk_san = tsa_cert_with(
        0x1F10,
        &subject_of(&cert("tsa.pem")),
        &[plain(SUBJECT_ALT_NAME, &der(0x02, &[5]))],
    );
    assert_eq!(spki_of(&junk_san), spki_of(&cert("tsa.pem")));
    let key = tsa_key("tsa.pem");
    let tsa = Tsa(MockTsa::new(
        junk_san,
        vec![cert("root.pem")],
        Box::new(move |attrs| {
            key.sign(folioxide_sign::algorithms::DigestAlgorithm::Sha256, attrs)
                .unwrap()
        }),
    ));
    let err = sign_bt_with(
        &minimal(),
        &rsa2048(),
        folioxide_sign::prepare::SignatureOptions::new(time()),
        &tsa,
    )
    .unwrap_err();
    assert_eq!(err.code(), folioxide_syntax::ErrorCode::TimestampInvalid);
    let text = err.to_string();
    assert!(
        text.contains("not suitable for timestamping")
            && text.contains("subjectAltName extension that does not decode"),
        "{text}"
    );
}

/// A mock TSA for `tsa_cert` (a certificate of `tsa.key.pem`) under the root, signing with
/// PKCS #1 v1.5.
fn pkcs1_tsa(tsa_cert: Vec<u8>) -> Tsa {
    let key = tsa_key("tsa.pem");
    Tsa(MockTsa::new(
        tsa_cert,
        vec![cert("root.pem")],
        Box::new(move |attrs| {
            key.sign(folioxide_sign::algorithms::DigestAlgorithm::Sha256, attrs)
                .unwrap()
        }),
    ))
}

/// The report of `minimal.pdf` signed B-T by RSA-2048 with the token of `tsa`, embedded below
/// Folioxide's own `finish` (which refuses the tokens of unsuitable TSA certificates).
fn embedded_token_report(tsa: &Tsa) -> folioxide_sign::report::SignatureReport {
    let prepared = {
        let signer = rsa2048();
        let request = folioxide_sign::prepare::PrepareRequest::new(
            signer.certificate_chain().to_vec(),
            signer.algorithm(),
            time(),
        )
        .with_options(
            folioxide_sign::prepare::SignatureOptions::new(time())
                .with_tsa_reserve(Some(folioxide_sign::tsp::DEFAULT_TSA_RESERVE)),
        );
        folioxide_sign::prepare::prepare(&open(&minimal()), &request).unwrap()
    };
    let signer = rsa2048();
    let value = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let request = prepared
        .timestamp_request(
            &value,
            &folioxide_sign::bt::TimestampParams::new().with_nonce(Some(NONCE)),
        )
        .unwrap();
    let token = tsa.0.token_for(&request).unwrap();
    let cms = folioxide_sign::cms::assemble_with_timestamp(
        prepared.to_be_signed(),
        &value,
        signer.certificate_chain(),
        signer.algorithm(),
        signer.key_kind(),
        prepared.digest_algorithm(),
        &token,
    )
    .unwrap();
    verify(&embed_raw(&prepared, &cms)).remove(0)
}

#[test]
fn tsa_certificate_extension_defects_make_the_token_invalid() {
    // Manager ruling R-22 (c), QA round 5 finding 37 (variants r7-extlist-dup-{ski,bc,akid},
    // r5-ext-junk-leaf-{bc,san,akid,crldp,nc}, r6-tsacert-*-surrogate): OpenSSL's
    // ossl_x509v3_cache_extensions marks a TSA certificate with a duplicated or undecodable
    // known extension invalid, so `openssl ts -verify` refuses the token whatever the anchors.
    // The token is therefore not valid (TsaCertificateUnsuitable), the signature B-B, and the
    // signing side refuses the response.
    use folioxide_sign::ProblemCode;
    use folioxide_sign::algorithms::DigestAlgorithm;
    use folioxide_sign::x509info::check_tsa_certificate;

    let tsa_subject = subject_of(&cert("tsa.pem"));
    let ski = plain(SUBJECT_KEY_ID, &der(0x04, &[1, 2, 3, 4]));
    let bc = plain(&[0x55, 0x1D, 0x13], &seq(&[]));
    let root_ski = bt_support::decoys::ski_of(&cert("root.pem")).unwrap();
    let aki = plain(AUTHORITY_KEY_ID, &seq(&[der(0x80, &root_ski)]));
    let junk = vec![0x05, 0x00];
    let cases: Vec<(&str, Vec<Vec<u8>>, &str)> = vec![
        (
            "r7-extlist-dup-ski",
            vec![ski.clone(), ski],
            "more than once",
        ),
        ("r7-extlist-dup-bc", vec![bc.clone(), bc], "more than once"),
        (
            "r7-extlist-dup-akid",
            vec![aki.clone(), aki],
            "more than once",
        ),
        (
            "r5-ext-junk-leaf-crldp",
            vec![plain(CRL_DISTRIBUTION_POINTS, &junk)],
            "cRLDistributionPoints extension that does not decode",
        ),
        (
            "r5-ext-junk-leaf-bc",
            vec![plain(&[0x55, 0x1D, 0x13], &junk)],
            "basicConstraints extension that does not decode",
        ),
        (
            "r5-ext-junk-leaf-nc",
            vec![plain(NAME_CONSTRAINTS, &junk)],
            "nameConstraints extension that does not decode",
        ),
    ];
    for (serial, (name, extensions, fragment)) in (0x1F20..).zip(cases) {
        let tsa_cert = tsa_cert_with(serial, &tsa_subject, &extensions);
        let reason = check_tsa_certificate(&tsa_cert).unwrap_err();
        assert!(reason.contains(fragment), "{name}: {reason}");
        let key = tsa_key("tsa.pem");
        let mock = MockTsa::new(
            tsa_cert,
            vec![cert("root.pem")],
            Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
        );
        // The signing side refuses the response.
        let tsa = Tsa(mock);
        let err = sign_bt_with(
            &minimal(),
            &rsa2048(),
            folioxide_sign::prepare::SignatureOptions::new(time()),
            &tsa,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not suitable for timestamping")
                && err.to_string().contains(fragment),
            "{name}: {err}"
        );
        // The verifying side, on the token embedded below finish.
        let report = &embedded_token_report(&tsa);
        assert!(report.is_valid(), "{name}: {}", summary(report));
        assert_eq!(report.pades_level, Some(PadesLevel::BB), "{name}");
        let ts = report.timestamp.as_ref().unwrap();
        assert!(
            ts.intact && !ts.valid && ts.trusted == Some(false),
            "{name}: {ts:?}"
        );
        assert!(
            ts.problems
                .iter()
                .any(|p| p.code == ProblemCode::TsaCertificateUnsuitable
                    && p.message.contains(fragment)),
            "{name}: {ts:?}"
        );
    }
    // The control: one instance of each, well formed.
    let good = tsa_cert_with(
        0x1F30,
        &tsa_subject,
        &[
            plain(SUBJECT_KEY_ID, &der(0x04, &[1, 2, 3, 4])),
            plain(AUTHORITY_KEY_ID, &seq(&[der(0x80, &root_ski)])),
        ],
    );
    assert_eq!(check_tsa_certificate(&good), Ok(()));
}

#[test]
fn document_signer_extension_defects_make_the_path_untrusted() {
    // The same defects on a document signer's certificate are a trust problem (ruling R-22
    // (c)): the signature stays valid, the path untrusted.
    let ski = plain(SUBJECT_KEY_ID, &der(0x04, &[1, 2, 3, 4]));
    for (serial, name, extensions) in [
        (
            0x1F40,
            "duplicate subjectKeyIdentifier",
            vec![ski.clone(), ski],
        ),
        (
            0x1F41,
            "junk cRLDistributionPoints",
            vec![plain(CRL_DISTRIBUTION_POINTS, &[0x05, 0x00])],
        ),
    ] {
        let leaf = signer_cert_with(serial, &extensions);
        let result = under_root(&leaf, &[cert("intermediate.pem")]);
        assert!(!result.trusted, "{name}");
        let signer = LocalSigner::from_pem(
            &pki_text("signer-rsa2048.key.pem"),
            &pem(&[leaf, cert("intermediate.pem")]),
            None,
        )
        .unwrap();
        let report = &verify(&sign_bt(&minimal(), &signer))[0];
        assert!(report.is_valid(), "{name}: {}", summary(report));
        assert_eq!(report.trusted, Some(false), "{name}: {}", summary(report));
    }
}

/// The extension types of M4 final fix round 2, finding 1 (content octets of the OIDs): the
/// ones asn1crypto (pyHanko) or OpenSSL decode beyond RFC 5280's, with a well-formed value
/// each.
const SUBJECT_DIRECTORY_ATTRIBUTES: &[u8] = &[0x55, 0x1D, 0x09];
const PRIVATE_KEY_USAGE_PERIOD: &[u8] = &[0x55, 0x1D, 0x10];
const TLS_FEATURE: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18];
const NS_CERT_TYPE: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x01];
const IP_ADDR_BLOCKS: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x07];
const AS_IDENTIFIERS: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x08];
const PROXY_CERT_INFO: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0E];

/// `(name, OID, a well-formed value)` for each type of finding 1, the decoded name first.
fn finding_1_types() -> Vec<(&'static str, &'static [u8], Vec<u8>)> {
    let oid = der(0x06, &[0x2A, 0x03, 0x04]);
    vec![
        (
            "subjectDirectoryAttributes",
            SUBJECT_DIRECTORY_ATTRIBUTES,
            // dateOfBirth (1.3.6.1.5.5.7.9.1) as a qualified certificate writes it.
            seq(&[seq(&[
                der(0x06, &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x01]),
                der(0x31, &der(0x18, b"19700101120000Z")),
            ])]),
        ),
        (
            "privateKeyUsagePeriod",
            PRIVATE_KEY_USAGE_PERIOD,
            seq(&[der(0x80, b"20250101000000Z"), der(0x81, b"20300101000000Z")]),
        ),
        ("tlsFeature", TLS_FEATURE, seq(&[der(0x02, &[5])])),
        ("nsCertType", NS_CERT_TYPE, der(0x03, &[0x07, 0x80])),
        (
            "ipAddrBlocks",
            IP_ADDR_BLOCKS,
            seq(&[seq(&[der(0x04, &[0x00, 0x01]), vec![0x05, 0x00]])]),
        ),
        (
            "autonomousSysIds",
            AS_IDENTIFIERS,
            seq(&[der(0xA0, &seq(&[der(0x02, &[0x40])]))]),
        ),
        ("proxyCertInfo", PROXY_CERT_INFO, seq(&[seq(&[oid])])),
    ]
}

/// QA's junk values (r8-ext-*-{junk-null,empty,junk-oid}).
fn finding_1_junk() -> [(&'static str, Vec<u8>); 3] {
    [
        ("junk-null", vec![0x05, 0x00]),
        ("empty", Vec::new()),
        ("junk-oid", der(0x06, &[0x2A, 0x03, 0x04])),
    ]
}

#[test]
fn tsa_certificate_extensions_asn1crypto_or_openssl_decode_must_decode() {
    // M4 final fix round 2, finding 1 (variants r8-ext-2_16_840_1_113730_1_1-*,
    // r8-ext-1_3_6_1_5_5_7_1_{7,8,14}-*, r8-dts-ext-2_16_840_1_113730_1_1-junk-null and the
    // signing-side ts-sign8-r8-tok-junk-{nscerttype,proxycertinfo}: OpenSSL "invalid
    // certificate"; r8-ext-2_5_29_{9,16}-*, r8-ext-1_3_6_1_5_5_7_1_24-*: pyHanko untrusted):
    // a TSA certificate whose extension of one of these types does not decode makes the token
    // invalid (TsaCertificateUnsuitable), and the signing side refuses the response.
    use folioxide_sign::ProblemCode;
    use folioxide_sign::x509info::check_tsa_certificate;

    let tsa_subject = subject_of(&cert("tsa.pem"));
    let mut serial = 0x2A00;
    for (name, oid, _) in finding_1_types() {
        for (junk_name, junk) in finding_1_junk() {
            serial += 1;
            let label = format!("{name} {junk_name}");
            let tsa_cert = tsa_cert_with(serial, &tsa_subject, &[plain(oid, &junk)]);
            let fragment = format!("a {name} extension that does not decode");
            let reason = check_tsa_certificate(&tsa_cert).unwrap_err();
            assert!(reason.contains(&fragment), "{label}: {reason}");
            if junk_name != "junk-null" {
                continue;
            }
            // The signing side refuses the response, the verifying side the embedded token.
            let err = sign_bt_with(
                &minimal(),
                &rsa2048(),
                folioxide_sign::prepare::SignatureOptions::new(time()),
                &pkcs1_tsa(tsa_cert.clone()),
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("not suitable for timestamping")
                    && err.to_string().contains(&fragment),
                "{label}: {err}"
            );
            let report = embedded_token_report(&pkcs1_tsa(tsa_cert));
            assert!(report.is_valid(), "{label}: {}", summary(&report));
            assert_eq!(report.pades_level, Some(PadesLevel::BB), "{label}");
            let ts = report.timestamp.as_ref().unwrap();
            assert!(
                ts.intact && !ts.valid && ts.trusted == Some(false),
                "{label}: {ts:?}"
            );
            assert!(
                ts.problems
                    .iter()
                    .any(|p| p.code == ProblemCode::TsaCertificateUnsuitable
                        && p.message.contains(&fragment)),
                "{label}: {ts:?}"
            );
        }
    }

    // A proxy certificate that is a CA or carries an alternative name: OpenSSL marks it invalid.
    let proxy = plain(PROXY_CERT_INFO, &seq(&[seq(&[der(0x06, &[0x2A, 0x03])])]));
    for (name, more) in [
        (
            "with a subjectAltName",
            plain(SUBJECT_ALT_NAME, &seq(&[der(0x82, b"tsa.example.org")])),
        ),
        (
            "with an issuerAltName",
            plain(ISSUER_ALT_NAME, &seq(&[der(0x82, b"ca.example.org")])),
        ),
        (
            "with cA TRUE",
            plain(&[0x55, 0x1D, 0x13], &seq(&[vec![0x01, 0x01, 0xFF]])),
        ),
    ] {
        serial += 1;
        let tsa_cert = tsa_cert_with(serial, &tsa_subject, &[proxy.clone(), more]);
        let reason = check_tsa_certificate(&tsa_cert).unwrap_err();
        assert!(
            reason.contains("proxyCertInfo extension although it is a certificate authority"),
            "{name}: {reason}"
        );
    }

    // Controls. The four types pyHanko and OpenSSL accept anywhere, well formed: the token is
    // valid and trusted. The RFC 3779 blocks and a proxy certificate, well formed: the token
    // is valid (the certificate is suitable) but not trusted, since OpenSSL refuses such a
    // chain and Folioxide does not process them (stricter than pyHanko, which trusts it).
    for (name, oid, value) in finding_1_types() {
        serial += 1;
        let tsa_cert = tsa_cert_with(serial, &tsa_subject, &[plain(oid, &value)]);
        assert_eq!(check_tsa_certificate(&tsa_cert), Ok(()), "{name}");
        let unprocessed = [IP_ADDR_BLOCKS, AS_IDENTIFIERS, PROXY_CERT_INFO].contains(&oid);
        let report = &verify(
            &sign_bt_with(
                &minimal(),
                &rsa2048(),
                folioxide_sign::prepare::SignatureOptions::new(time()),
                &pkcs1_tsa(tsa_cert),
            )
            .unwrap(),
        )[0];
        let ts = report.timestamp.as_ref().unwrap();
        assert!(ts.intact && ts.valid, "{name}: {ts:?}");
        assert_eq!(report.pades_level, Some(PadesLevel::BT), "{name}");
        assert_eq!(ts.trusted, Some(!unprocessed), "{name}: {ts:?}");
        if unprocessed {
            assert!(
                ts.warnings
                    .iter()
                    .chain(report.warnings.iter())
                    .any(|w| w.contains("whose path processing Folioxide does not implement")),
                "{name}: {ts:?} {:?}",
                report.warnings
            );
        }
    }
}

#[test]
fn document_signer_extensions_asn1crypto_or_openssl_decode_must_decode() {
    // M4 final fix round 2, finding 1 (nc_doc8/{leafjunk,cajunk}-{subjdirattrs,pkup,
    // tlsfeature}.pdf: ours trusted, pyHanko trusted False): the same junk on the signer or on
    // its intermediate makes the path untrusted; the signature stays valid.
    let signer = cert("signer-rsa2048.pem");
    let mut serial = 0x2B00;
    for (name, oid, _) in finding_1_types() {
        for (junk_name, junk) in finding_1_junk() {
            serial += 2;
            let label = format!("{name} {junk_name}");
            let fragment = format!("a {name} extension that does not decode");
            let leaf = signer_cert_with(serial, &[plain(oid, &junk)]);
            assert_untrusted(
                &format!("leaf {label}"),
                &under_root(&leaf, &[cert("intermediate.pem")]),
                &fragment,
            );
            let intermediate = intermediate_with(serial + 1, &[plain(oid, &junk)]);
            assert_untrusted(
                &format!("intermediate {label}"),
                &under_root(&signer, &[intermediate]),
                &fragment,
            );
        }
    }
    // One of them through the whole verifier (nc_doc8/leafjunk-pkup).
    let leaf = signer_cert_with(0x2BF0, &[plain(PRIVATE_KEY_USAGE_PERIOD, &[0x05, 0x00])]);
    let local = LocalSigner::from_pem(
        &pki_text("signer-rsa2048.key.pem"),
        &pem(&[leaf, cert("intermediate.pem")]),
        None,
    )
    .unwrap();
    let report = &verify(&sign_bt(&minimal(), &local))[0];
    assert!(report.is_valid(), "{}", summary(report));
    assert_eq!(report.trusted, Some(false), "{}", summary(report));

    // Controls: well formed, the first four are trusted on the signer and on the intermediate;
    // the RFC 3779 blocks and proxyCertInfo are not, on any certificate of the path.
    for (name, oid, value) in finding_1_types() {
        serial += 2;
        let unprocessed = [IP_ADDR_BLOCKS, AS_IDENTIFIERS, PROXY_CERT_INFO].contains(&oid);
        let leaf = signer_cert_with(serial, &[plain(oid, &value)]);
        let intermediate = intermediate_with(serial + 1, &[plain(oid, &value)]);
        for (place, result) in [
            ("leaf", under_root(&leaf, &[cert("intermediate.pem")])),
            ("intermediate", under_root(&signer, &[intermediate])),
        ] {
            let label = format!("{place} {name}");
            if unprocessed {
                assert_untrusted(
                    &label,
                    &result,
                    "whose path processing Folioxide does not implement",
                );
            } else {
                assert_trusted(&label, &result);
            }
        }
    }
}

/// Well-formed values of the extension types that OpenSSL's `X509_supported_extension` does not
/// list, for a critical extension `(name, OID content octets, value)`: OpenSSL refuses every
/// chain with one ("unhandled critical extension"; M4 closing round, findings 8 and 11).
fn unhandled_critical_extensions() -> Vec<(&'static str, Vec<u8>)> {
    let uri = der(0x86, b"http://example.org/ca");
    let root_ski = bt_support::decoys::ski_of(&cert("root.pem")).unwrap();
    let access = |method_last: u8| {
        seq(&[seq(&[
            der(
                0x06,
                &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, method_last],
            ),
            uri.clone(),
        ])])
    };
    vec![
        (
            "subjectKeyIdentifier (r9-crit-ski)",
            extension(SUBJECT_KEY_ID, true, &der(0x04, &[1, 2, 3, 4])),
        ),
        (
            "authorityKeyIdentifier (r9-crit-aki)",
            extension(AUTHORITY_KEY_ID, true, &seq(&[der(0x80, &root_ski)])),
        ),
        (
            "authorityInfoAccess (r9-crit-aia)",
            extension(AUTHORITY_INFO_ACCESS, true, &access(0x02)),
        ),
        (
            "freshestCRL (r9-crit-freshestcrl)",
            extension(
                &[0x55, 0x1D, 0x2E],
                true,
                &seq(&[seq(&[der(0xA0, &der(0xA0, &uri))])]),
            ),
        ),
        (
            "qcStatements (r9-crit-qcstatements)",
            extension(
                &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x03],
                true,
                // QcCompliance (0.4.0.1862.1.1, ETSI EN 319 412-5).
                &seq(&[seq(&[der(0x06, &[0x04, 0x00, 0x8E, 0x46, 0x01, 0x01])])]),
            ),
        ),
        (
            "issuerAltName",
            extension(ISSUER_ALT_NAME, true, &seq(std::slice::from_ref(&uri))),
        ),
        (
            "subjectInfoAccess (r9-crit-sia)",
            extension(
                &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0B],
                true,
                &access(0x05),
            ),
        ),
        (
            "privateKeyUsagePeriod (r9-crit-pkup)",
            extension(
                PRIVATE_KEY_USAGE_PERIOD,
                true,
                &seq(&[der(0x80, b"20250101000000Z")]),
            ),
        ),
        (
            "a private extension",
            extension(
                &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xFD, 0x59, 0x01],
                true,
                &[0x05, 0x00],
            ),
        ),
    ]
}

/// The controls of [`unhandled_critical_extensions`]: critical extensions that OpenSSL handles
/// and Folioxide processes or needs not process (r9-crit-{crldp,certpolicies,san,ocspnocheck}).
fn handled_critical_extensions() -> Vec<(&'static str, Vec<u8>)> {
    let uri = der(0x86, b"http://example.org/ca.crl");
    vec![
        (
            "cRLDistributionPoints",
            extension(
                CRL_DISTRIBUTION_POINTS,
                true,
                &seq(&[seq(&[der(0xA0, &der(0xA0, &uri))])]),
            ),
        ),
        (
            "certificatePolicies",
            extension(CERTIFICATE_POLICIES, true, &seq(&[seq(&[any_policy()])])),
        ),
        (
            "subjectAltName",
            extension(
                SUBJECT_ALT_NAME,
                true,
                &seq(&[der(0x82, b"tsa.example.org")]),
            ),
        ),
        (
            "ocspNoCheck",
            extension(
                &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05],
                true,
                &[0x05, 0x00],
            ),
        ),
    ]
}

#[test]
fn tsa_certificate_critical_extensions_openssl_does_not_handle_make_the_token_invalid() {
    // M4 closing round, findings 8 and 11, manager ruling R-26 (variants r9-crit-ski, -aki,
    // -aia, -freshestcrl, -qcstatements; expert crit/tsa-{aki,ski,aia}): a TSA certificate with
    // a critical extension OpenSSL does not handle was valid and trusted, B-T, and Folioxide's
    // signer embedded its token, where `openssl ts -verify` refuses it ("unhandled critical
    // extension"). RFC 5280 §4.2.1.1, §4.2.1.2 and §4.2.2.1 say the key identifiers and the
    // authority information access MUST be non-critical. Now the certificate is unsuitable: the
    // token is not valid (TsaCertificateUnsuitable), the signature B-B, and the signing side
    // refuses the response. pyHanko trusts these tokens (stricter than pyHanko, equal to OpenSSL).
    use folioxide_sign::ProblemCode;
    use folioxide_sign::x509info::check_tsa_certificate;

    let tsa_subject = subject_of(&cert("tsa.pem"));
    for (serial, (name, critical)) in (0x2A00..).zip(unhandled_critical_extensions()) {
        let tsa_cert = tsa_cert_with(serial, &tsa_subject, std::slice::from_ref(&critical));
        let reason = check_tsa_certificate(&tsa_cert).unwrap_err();
        assert!(reason.contains("critical"), "{name}: {reason}");
        // The TSA's path is untrusted too.
        let path = folioxide_sign::x509info::build_trust_for(
            folioxide_sign::x509info::TrustPurpose::TimeStamping,
            &tsa_cert,
            &[],
            &[cert("root.pem")],
            now(),
        );
        assert!(!path.trusted, "{name}: {:?}", path.reasons);
        let tsa = pkcs1_tsa(tsa_cert);
        let err = sign_bt_with(
            &minimal(),
            &rsa2048(),
            folioxide_sign::prepare::SignatureOptions::new(time()),
            &tsa,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not suitable for timestamping")
                && err.to_string().contains("critical"),
            "{name}: {err}"
        );
        let report = &embedded_token_report(&tsa);
        assert!(
            report.is_valid() && report.trusted == Some(true),
            "{name}: {}",
            summary(report)
        );
        assert_eq!(report.pades_level, Some(PadesLevel::BB), "{name}");
        let ts = report.timestamp.as_ref().unwrap();
        assert!(
            ts.intact && !ts.valid && ts.trusted == Some(false),
            "{name}: {ts:?}"
        );
        assert!(
            ts.problems
                .iter()
                .any(|p| p.code == ProblemCode::TsaCertificateUnsuitable
                    && p.message.contains("critical")),
            "{name}: {ts:?}"
        );
    }
    // A critical key identifier is named as RFC 5280 forbids it.
    let ski = &unhandled_critical_extensions()[0].1;
    let reason = check_tsa_certificate(&tsa_cert_with(
        0x2A20,
        &tsa_subject,
        std::slice::from_ref(ski),
    ))
    .unwrap_err();
    assert!(
        reason.contains("critical subjectKeyIdentifier extension, which OpenSSL does not handle")
            && reason.contains("RFC 5280 §4.2.1.2 says it MUST be non-critical"),
        "{reason}"
    );

    // Controls: critical extensions OpenSSL handles; the token is valid and trusted, B-T, and
    // signing succeeds (OpenSSL: Verification: OK for the same certificates).
    for (serial, (name, critical)) in (0x2A30..).zip(handled_critical_extensions()) {
        let tsa_cert = tsa_cert_with(serial, &tsa_subject, std::slice::from_ref(&critical));
        assert_eq!(check_tsa_certificate(&tsa_cert), Ok(()), "{name}");
        let tsa = pkcs1_tsa(tsa_cert);
        let signed = sign_bt_with(
            &minimal(),
            &rsa2048(),
            folioxide_sign::prepare::SignatureOptions::new(time()),
            &tsa,
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        let report = &verify(&signed)[0];
        assert_eq!(report.pades_level, Some(PadesLevel::BT), "{name}");
        let ts = report.timestamp.as_ref().unwrap();
        assert!(
            ts.intact && ts.valid && ts.trusted == Some(true),
            "{name}: {ts:?}"
        );
    }
}

#[test]
fn critical_extensions_openssl_does_not_handle_make_a_path_untrusted() {
    // The same rule on a document signer's path (R-26: "a signer path untrusted"): on the
    // signer, on the intermediate, and on the TSA's intermediate. The signature stays valid.
    let root_ski = bt_support::decoys::ski_of(&cert("root.pem")).unwrap();
    for (serial, (name, critical)) in (0x2A40..).step_by(2).zip(unhandled_critical_extensions()) {
        // On the signer: its authorityKeyIdentifier would name the intermediate, so the AKI row
        // is the intermediate's own below.
        if !name.starts_with("authorityKeyIdentifier") {
            let leaf = signer_cert_with(serial, std::slice::from_ref(&critical));
            assert_untrusted(
                name,
                &under_root(&leaf, &[cert("intermediate.pem")]),
                "critical",
            );
        }
        // On the intermediate: a subjectKeyIdentifier must stay the one the signer's
        // authorityKeyIdentifier names (R-22 (a)).
        let critical = if name.starts_with("subjectKeyIdentifier") {
            let own = bt_support::decoys::ski_of(&cert("intermediate.pem")).unwrap();
            extension(SUBJECT_KEY_ID, true, &der(0x04, &own))
        } else {
            critical
        };
        let intermediate = intermediate_with(serial + 1, std::slice::from_ref(&critical));
        assert_untrusted(
            name,
            &under_root(&cert("signer-rsa2048.pem"), &[intermediate]),
            "critical",
        );
    }
    // The intermediate's critical authorityKeyIdentifier naming the root.
    let intermediate = intermediate_with(
        0x2A60,
        &[extension(
            AUTHORITY_KEY_ID,
            true,
            &seq(&[der(0x80, &root_ski)]),
        )],
    );
    assert_untrusted(
        "critical authorityKeyIdentifier on the intermediate",
        &under_root(
            &cert("signer-rsa2048.pem"),
            std::slice::from_ref(&intermediate),
        ),
        "critical authorityKeyIdentifier extension, which OpenSSL does not handle",
    );
    // A document signature by a signer with a critical subjectKeyIdentifier: valid, untrusted.
    let leaf = signer_cert_with(
        0x2A61,
        &[extension(SUBJECT_KEY_ID, true, &der(0x04, &[1, 2, 3, 4]))],
    );
    let signer = LocalSigner::from_pem(
        &pki_text("signer-rsa2048.key.pem"),
        &pem(&[leaf, cert("intermediate.pem")]),
        None,
    )
    .unwrap();
    let report = &verify(&sign_bt(&minimal(), &signer))[0];
    assert!(report.is_valid(), "{}", summary(report));
    assert_eq!(report.trusted, Some(false), "{}", summary(report));
    assert_eq!(
        report.pades_level,
        Some(PadesLevel::BT),
        "{}",
        summary(report)
    );

    // Controls: the critical extensions OpenSSL handles keep the paths trusted.
    for (serial, (name, critical)) in (0x2A70..).step_by(2).zip(handled_critical_extensions()) {
        let leaf = signer_cert_with(serial, std::slice::from_ref(&critical));
        assert_trusted(name, &under_root(&leaf, &[cert("intermediate.pem")]));
        let intermediate = intermediate_with(serial + 1, std::slice::from_ref(&critical));
        assert_trusted(
            name,
            &under_root(&cert("signer-rsa2048.pem"), &[intermediate]),
        );
    }
    // A critical extension OpenSSL handles but Folioxide does not process stays untrusted
    // (stricter than OpenSSL): nsCertType.
    let leaf = signer_cert_with(
        0x2A80,
        &[extension(NS_CERT_TYPE, true, &der(0x03, &[0x07, 0x80]))],
    );
    assert_untrusted(
        "critical nsCertType",
        &under_root(&leaf, &[cert("intermediate.pem")]),
        "critical nsCertType extension, which Folioxide does not process",
    );
}

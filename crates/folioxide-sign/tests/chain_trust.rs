//! Trust path building and validation (M3 brief §5 V9, §6.2 "certificates and trust"; decisions
//! D-10, D-12, D-16): `x509info::build_trust` over the test PKI and the chain fixtures of
//! `fixtures/sign/chain/` (`tools/fixtures/sign.py`, whose `--check` asserts that
//! pyhanko-certvalidator reaches the same verdicts, except for the deliberate difference D-10).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod cms_support;

use std::time::{Duration, Instant};

use cms_support::{SIGNERS, cert_der};
use folioxide_model::PdfDate;
use folioxide_sign::ProblemCode;
use folioxide_sign::x509info::{
    self, MAX_CANDIDATES, MAX_PATH_CERTIFICATES, MIN_RSA_TRUST_BITS, TrustResult, UnixTime,
    build_trust,
};

/// The validation time of the chain fixtures' pyHanko check (`CHAIN_MOMENT` in sign.py).
fn now() -> UnixTime {
    at("D:20261010120000Z")
}

fn at(date: &str) -> UnixTime {
    UnixTime::from_pdf_date(&PdfDate::parse(date.as_bytes()).unwrap())
}

fn pki(name: &str) -> Vec<u8> {
    cert_der(&format!("pki/{name}.pem"))
}

fn chain(name: &str) -> Vec<u8> {
    cert_der(&format!("sign/chain/{name}.pem"))
}

fn root() -> Vec<u8> {
    pki("root")
}

fn intermediate() -> Vec<u8> {
    pki("intermediate")
}

/// `build_trust` with the root as the only anchor.
fn under_root(signer: &[u8], pool: &[Vec<u8>]) -> TrustResult {
    build_trust(signer, pool, &[root()], now())
}

#[track_caller]
fn assert_trusted(result: &TrustResult) {
    assert!(result.trusted, "untrusted: {:?}", result.reasons);
    assert!(result.reasons.is_empty());
    assert!(result.problems.is_empty(), "{:?}", result.problems);
    assert!(!result.path.is_empty());
}

#[track_caller]
fn assert_untrusted(result: &TrustResult, fragment: &str) {
    assert!(!result.trusted, "trusted, expected: {fragment}");
    assert!(
        result.reasons.iter().any(|r| r.contains(fragment)),
        "no reason contains {fragment:?}: {:?}",
        result.reasons
    );
}

#[test]
fn chain_rsa_root_ecdsa_intermediate_trusted() {
    // RSA-3072 root (sha256WithRSAEncryption) -> P-384 intermediate (ecdsa-with-SHA384) ->
    // RSA and ECDSA signers: both certificate signature families on one path.
    for name in SIGNERS {
        let signer = pki(&format!("signer-{name}"));
        let result = under_root(&signer, &[intermediate()]);
        assert_trusted(&result);
        assert_eq!(
            result.path,
            [signer.clone(), intermediate(), root()],
            "{name}"
        );
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);

        // The pool as a CMS carries it: the signer, the intermediate and the root, in any
        // order and with repeats.
        let pool = [root(), signer.clone(), intermediate(), intermediate()];
        let result = under_root(&signer, &pool);
        assert_trusted(&result);
        assert_eq!(result.path, [signer.clone(), intermediate(), root()]);
    }
    // Unrelated certificates in the pool and among the anchors change nothing.
    let signer = pki("signer-p256");
    let pool = [
        pki("tsa"),
        chain("impostor-root"),
        chain("sub-ca"),
        intermediate(),
    ];
    let anchors = [chain("self-signed"), chain("impostor-root"), root()];
    let result = build_trust(&signer, &pool, &anchors, now());
    assert_trusted(&result);
    assert_eq!(result.path.last(), Some(&root()));
}

#[test]
fn chain_validity_window_is_inclusive() {
    let signer = pki("signer-rsa2048");
    let pool = [intermediate()];
    for date in ["D:20250101000000Z", "D:20751231235959Z"] {
        assert_trusted(&build_trust(&signer, &pool, &[root()], at(date)));
    }
    let early = build_trust(&signer, &pool, &[root()], at("D:20241231235959Z"));
    assert_untrusted(&early, "is not valid before 2025-01-01T00:00:00Z");
    let late = build_trust(&signer, &pool, &[root()], at("D:20760101000000Z"));
    assert_untrusted(&late, "expired on 2075-12-31T23:59:59Z");
    // The path is still reported when validation fails.
    assert_eq!(late.path.len(), 3);
}

#[test]
fn chain_expired_untrusted() {
    let expired = pki("expired");
    let result = under_root(&expired, &[intermediate()]);
    assert_untrusted(&result, "expired on 2025-12-31T23:59:59Z");
    assert!(result.reasons[0].contains("Folioxide Test Signer (expired)"));
    assert_eq!(result.path, [expired.clone(), intermediate(), root()]);
    // In 2025 the same certificate was valid.
    assert_trusted(&build_trust(
        &expired,
        &[intermediate()],
        &[root()],
        at("D:20250601000000Z"),
    ));
}

#[test]
fn chain_wrong_ku_untrusted() {
    let result = under_root(&pki("wrong-ku"), &[intermediate()]);
    assert_untrusted(
        &result,
        "allows neither digitalSignature nor nonRepudiation",
    );
    assert_eq!(result.reasons.len(), 1, "{:?}", result.reasons);
}

#[test]
fn chain_ku_digital_signature_or_non_repudiation() {
    // D-10: either bit is enough. pyHanko accepts only the nonRepudiation signer (sign.py
    // --check asserts that): a deliberate difference that the fixture PKI never exercises.
    for name in ["ku-digital-signature", "ku-non-repudiation"] {
        let result = under_root(&chain(name), &[intermediate()]);
        assert_trusted(&result);
        let info = x509info::certificate_info(&chain(name)).unwrap();
        assert_eq!(info.key_usage.len(), 1, "{name}: {:?}", info.key_usage);
    }
}

#[test]
fn chain_missing_intermediate_untrusted() {
    let result = under_root(&pki("signer-p384"), &[]);
    assert_untrusted(&result, "no certification path");
    assert_untrusted(&result, "Folioxide Test Intermediate CA");
    assert!(result.path.is_empty());
    // Extra certificates complete the path (VerifyOptions::extra_certs_der).
    assert_trusted(&under_root(&pki("signer-p384"), &[intermediate()]));
}

#[test]
fn chain_wrong_anchor_untrusted() {
    let signer = pki("signer-rsa3072");
    // An unrelated anchor.
    let result = build_trust(&signer, &[intermediate()], &[chain("self-signed")], now());
    assert_untrusted(&result, "no certification path");
    // An anchor with the root's name but another key: the intermediate's signature fails.
    let impostor = chain("impostor-root");
    let result = build_trust(
        &signer,
        &[intermediate()],
        std::slice::from_ref(&impostor),
        now(),
    );
    assert_untrusted(&result, "does not verify");
    assert!(result.path.is_empty());
    // The real root in the pool is not an anchor.
    let result = build_trust(&signer, &[intermediate(), root()], &[impostor], now());
    assert_untrusted(&result, "no certification path");
}

#[test]
fn chain_intermediate_as_anchor() {
    // Any certificate can be an anchor; the path then ends there.
    let signer = pki("signer-p256");
    let result = build_trust(&signer, &[], &[intermediate()], now());
    assert_trusted(&result);
    assert_eq!(result.path, [signer, intermediate()]);
}

#[test]
fn chain_self_signed_signer() {
    let signer = chain("self-signed");
    // Self-signed and not an anchor: no path (its only issuer candidate is itself).
    let result = under_root(&signer, std::slice::from_ref(&signer));
    assert_untrusted(&result, "no certification path");
    // Its own anchor: trusted, and the path is the signer alone.
    let result = build_trust(&signer, &[], std::slice::from_ref(&signer), now());
    assert_trusted(&result);
    assert_eq!(result.path, std::slice::from_ref(&signer));
    // The signer's own checks still apply when it is the anchor.
    let result = build_trust(
        &signer,
        &[],
        std::slice::from_ref(&signer),
        at("D:20800101000000Z"),
    );
    assert_untrusted(&result, "expired");
    let wrong_ku = pki("wrong-ku");
    let result = build_trust(&wrong_ku, &[], std::slice::from_ref(&wrong_ku), now());
    assert_untrusted(&result, "neither digitalSignature nor nonRepudiation");
}

#[test]
fn chain_path_length_violation_untrusted() {
    // root -> intermediate (pathlen:0) -> sub-CA -> signer.
    let signer = chain("sub-ca-signer");
    let pool = [chain("sub-ca"), intermediate()];
    let result = under_root(&signer, &pool);
    assert_untrusted(&result, "pathLenConstraint");
    assert_eq!(result.path.len(), 4);
    // With the intermediate as the anchor its own constraint does not apply (RFC 5280
    // §6.1.1 (d); pyHanko agrees, see sign.py --check).
    assert_trusted(&build_trust(&signer, &pool, &[intermediate()], now()));
}

#[test]
fn chain_unknown_critical_extension_untrusted() {
    let result = under_root(&chain("unknown-critical"), &[intermediate()]);
    assert_untrusted(&result, "unknown critical extension 1.3.6.1.4.1.32473.1");
    assert_eq!(result.reasons.len(), 1, "{:?}", result.reasons);
    // Known critical extensions (basicConstraints, keyUsage, the TSA's extKeyUsage) are fine.
    assert_trusted(&under_root(&pki("tsa"), &[]));
}

#[test]
fn chain_issuer_not_ca_untrusted() {
    // signer-p256 (CA:FALSE) issued this certificate.
    let result = under_root(
        &chain("issued-by-ee"),
        &[pki("signer-p256"), intermediate()],
    );
    assert_untrusted(&result, "is not a CA");
}

#[test]
fn chain_issuer_without_key_cert_sign_untrusted() {
    let result = under_root(&chain("no-certsign-signer"), &[chain("no-certsign-ca")]);
    assert_untrusted(&result, "lacks keyCertSign");
}

#[test]
fn chain_sha1_certificate_signature_weak() {
    let result = under_root(&chain("sha1-signer"), &[intermediate()]);
    assert_untrusted(&result, "ecdsa-with-SHA1, a weak algorithm");
    assert_eq!(result.problems.len(), 1);
    assert_eq!(result.problems[0].code, ProblemCode::WeakAlgorithm);
}

#[test]
fn chain_rsa_below_2048_untrusted() {
    // D-12: RSA-1024 still verifies, but a path with an RSA key below MIN_RSA_TRUST_BITS is not
    // trusted (pyhanko-certvalidator's DisallowWeakAlgorithmsPolicy; pyHanko's CMS validation
    // for the signer's own key).
    assert_eq!(MIN_RSA_TRUST_BITS, 2048);
    // An issuer with an RSA-1024 key: its signature on the signer verifies, but is weak.
    let result = under_root(&chain("rsa1024-ca-signer"), &[chain("rsa1024-ca")]);
    assert_untrusted(&result, "RSA key of only 1024 bits");
    assert_eq!(
        result.path.len(),
        3,
        "the path verifies: {:?}",
        result.reasons
    );
    assert_eq!(result.problems.len(), 1);
    assert_eq!(result.problems[0].code, ProblemCode::WeakAlgorithm);
    // The signer's own RSA-1024 key.
    let result = under_root(&chain("rsa1024-signer"), &[intermediate()]);
    assert_untrusted(&result, "the signer");
    assert_untrusted(&result, "RSA key of only 1024 bits");
    assert_eq!(result.problems[0].code, ProblemCode::WeakAlgorithm);
    let info = x509info::certificate_info(&chain("rsa1024-signer")).unwrap();
    assert_eq!(info.key.bits, 1024);
}

#[test]
fn chain_rsa_pss_certificate_signature_trusted() {
    // The root signed this CA with RSASSA-PSS (SHA-256, MGF1-SHA-256, salt 32).
    let result = under_root(&chain("pss-ca-signer"), &[chain("pss-ca")]);
    assert_trusted(&result);
    assert_eq!(result.path.len(), 3);
}

#[test]
fn chain_inputs_that_do_not_parse() {
    let signer = pki("signer-p256");
    // Garbage in the pool and among the anchors is ignored with a warning.
    let garbage = b"not a certificate".to_vec();
    let result = build_trust(
        &signer,
        &[garbage.clone(), intermediate()],
        &[garbage.clone(), root()],
        now(),
    );
    assert_trusted(&result);
    assert_eq!(result.warnings.len(), 2, "{:?}", result.warnings);
    // A signer that does not parse, no anchors, or only unusable anchors: untrusted.
    assert_untrusted(
        &build_trust(&garbage, &[], &[root()], now()),
        "signer certificate is unusable",
    );
    assert_untrusted(
        &build_trust(&signer, &[intermediate()], &[], now()),
        "no trust anchors",
    );
    assert_untrusted(
        &build_trust(&signer, &[intermediate()], &[garbage], now()),
        "none of the trust anchors",
    );
}

#[test]
fn chain_candidate_limit() {
    // Copies of the intermediate with a corrupted signature: each still names (and its key
    // still verifies) the signer, but none chains to the root.
    let real = intermediate();
    let corrupted: Vec<Vec<u8>> = (0..70u8)
        .map(|i| {
            let mut copy = real.clone();
            let last = copy.len() - 1 - usize::from(i % 8);
            copy[last] ^= 1 + (i / 8);
            copy
        })
        .collect();
    let signer = pki("signer-p384");

    // The real intermediate after more than MAX_CANDIDATES others is never considered.
    let mut pool = corrupted.clone();
    pool.push(real.clone());
    assert!(pool.len() > MAX_CANDIDATES);
    let started = Instant::now();
    let result = under_root(&signer, &pool);
    assert_untrusted(&result, "no certification path");
    assert!(
        result
            .warnings
            .iter()
            .any(|w| w.contains("only the first 64")),
        "{:?}",
        result.warnings
    );
    assert!(started.elapsed() < Duration::from_secs(60));

    // First, it is found.
    let mut pool = vec![real];
    pool.extend(corrupted);
    assert_trusted(&under_root(&signer, &pool));
}

#[test]
fn chain_length_is_bounded() {
    assert_eq!(MAX_PATH_CERTIFICATES, 8);
    // A self-issued loop of one certificate, offered many times, never recurses: duplicates
    // are dropped and a path never repeats a certificate.
    let signer = chain("self-signed");
    let pool = vec![signer.clone(); 100];
    assert_untrusted(&under_root(&signer, &pool), "no certification path");
}

#[test]
fn chain_mutated_certificates_never_panic() {
    // Deterministic byte mutations of the signer and the intermediate: build_trust must
    // return (trusted only when the mutation is harmless) and never panic.
    let signer = pki("signer-p256");
    let inter = intermediate();
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..300 {
        let mut s = signer.clone();
        let mut i = inter.clone();
        let target = if round % 2 == 0 { &mut s } else { &mut i };
        let pos = usize::try_from(next() % target.len() as u64).unwrap();
        match next() % 3 {
            0 => target[pos] ^= 1 << (next() % 8),
            1 => target.truncate(pos),
            _ => target.insert(pos, (next() & 0xFF) as u8),
        }
        let result = under_root(&s, &[i]);
        if result.trusted {
            assert_eq!(result.path.len(), 3);
        }
    }
}

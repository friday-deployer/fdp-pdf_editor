//! Golden cross-check with OpenSSL (WP3.1B): a SignedData over the fixed vector content, built
//! with every fixture signer and every signing digest, must pass
//! `openssl cms -verify -binary -inform DER -content <data> -CAfile fixtures/pki/root.pem
//! -purpose any`.
//!
//! The check runs when the `openssl` tool is installed and is skipped (with a notice) otherwise;
//! `FOLIOXIDE_REQUIRE_OPENSSL=1` turns a missing OpenSSL into a failure. The same CMS must also
//! verify with Folioxide's own verifier, so both sides agree on every vector.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod cms_support;

use cms_support::{
    PASSWORD, fixture, openssl_available, openssl_cms_verify, pem_signer, scratch_dir, sign_cms,
    vector_data, verify_over,
};
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::signer::{LocalSigner, Signer};

const DIGESTS: [DigestAlgorithm; 3] = [
    DigestAlgorithm::Sha256,
    DigestAlgorithm::Sha384,
    DigestAlgorithm::Sha512,
];

/// Every signer of the test PKI, through every loader.
fn signers() -> Vec<(String, LocalSigner)> {
    let mut out: Vec<(String, LocalSigner)> = cms_support::SIGNERS
        .iter()
        .map(|name| (format!("pem-{name}"), pem_signer(name)))
        .collect();
    for p12 in [
        "signer-rsa2048-modern",
        "signer-rsa2048-3des",
        "signer-rsa2048-rc2-40",
        "signer-p256-modern",
    ] {
        out.push((
            p12.to_owned(),
            LocalSigner::from_pkcs12(&fixture(&format!("pki/{p12}.p12")), PASSWORD).unwrap(),
        ));
    }
    out
}

#[test]
fn signed_data_verifies_with_openssl() {
    let data = vector_data();
    let openssl = openssl_available();
    let dir = scratch_dir("signed_data_verifies_with_openssl");
    let mut checked = 0;
    for (name, signer) in signers() {
        for digest in DIGESTS {
            let der = sign_cms(&signer, digest, &data);
            let v = verify_over(&der, &data);
            assert!(
                v.intact && v.signature_valid && v.problems.is_empty(),
                "{name} {digest}: {v:?}"
            );
            if openssl {
                let (ok, stderr) =
                    openssl_cms_verify(&dir, &format!("{name}-{digest}"), &der, &data);
                assert!(ok, "openssl cms -verify {name} {digest}: {stderr}");
                // And a flipped content byte fails in OpenSSL too.
                let mut tampered = data.clone();
                tampered[0] ^= 1;
                let (ok, _) =
                    openssl_cms_verify(&dir, &format!("{name}-{digest}-bad"), &der, &tampered);
                assert!(!ok, "openssl accepted tampered content for {name} {digest}");
                checked += 1;
            }
        }
        let _ = signer.certificate_chain();
    }
    if openssl {
        assert_eq!(checked, 8 * 3);
        eprintln!("openssl cms -verify: {checked} SignedData vectors verified");
    }
}

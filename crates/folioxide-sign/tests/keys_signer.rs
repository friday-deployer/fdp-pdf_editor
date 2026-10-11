//! `LocalSigner` signing (M3 brief §3.1, R-9, §6.2 "signers and ECDSA"): RSA PKCS#1 v1.5
//! against OpenSSL golden vectors, the blinded RSA path, and deterministic ECDSA.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod cms_support;

use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use cms_support::{
    fixture, fixture_str, fixtures_dir, openssl_available, pem_signer, scratch_dir, vector_data,
};
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::cms;
use folioxide_sign::signer::{LocalSigner, Signer};

/// A deterministic test RNG that counts how many times it is asked for randomness.
struct CountingRng {
    state: u64,
    calls: Arc<AtomicUsize>,
}

impl CountingRng {
    fn next(&mut self) -> u64 {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // splitmix64
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl rand_core::TryRng for CountingRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for CountingRng {}

#[test]
fn local_signer_rsa_matches_openssl_golden() {
    let data = vector_data();
    // PKCS#1 v1.5 is deterministic: Folioxide must produce OpenSSL's exact bytes
    // (`openssl dgst -sign`, committed by tools/fixtures/sign.py).
    for (name, digest, golden) in [
        (
            "rsa2048",
            DigestAlgorithm::Sha256,
            "sign/golden-rsa2048-sha256.sig",
        ),
        (
            "rsa3072",
            DigestAlgorithm::Sha512,
            "sign/golden-rsa3072-sha512.sig",
        ),
    ] {
        let signer = pem_signer(name);
        let signature = signer.sign(digest, &data).unwrap();
        assert_eq!(signature, fixture(golden), "{name} {digest}");
        assert_eq!(signature.len(), signer.key_kind().max_signature_len());
        // The same through the PKCS#1 and PKCS#12 loaders.
        let pkcs1 = LocalSigner::from_pem(
            &fixture_str(&format!("pki/signer-{name}.key.pkcs1.pem")),
            &fixture_str(&format!("pki/signer-{name}.pem")),
            None,
        )
        .unwrap();
        assert_eq!(pkcs1.sign(digest, &data).unwrap(), fixture(golden));
    }
    let p12 =
        LocalSigner::from_pkcs12(&fixture("pki/signer-rsa2048-3des.p12"), "folioxide").unwrap();
    assert_eq!(
        p12.sign(DigestAlgorithm::Sha256, &data).unwrap(),
        fixture("sign/golden-rsa2048-sha256.sig")
    );

    // Live cross-check with OpenSSL for the other digests, when it is installed.
    if openssl_available() {
        let dir = scratch_dir("local_signer_rsa_matches_openssl_golden");
        let tbs = dir.join("tbs.bin");
        std::fs::write(&tbs, b"another message to sign").unwrap();
        for (name, digest) in [
            ("rsa2048", DigestAlgorithm::Sha384),
            ("rsa2048", DigestAlgorithm::Sha512),
            ("rsa3072", DigestAlgorithm::Sha256),
        ] {
            let output = Command::new("openssl")
                .args(["dgst", &format!("-{digest}"), "-sign"])
                .arg(fixtures_dir().join(format!("pki/signer-{name}.key.pem")))
                .arg(&tbs)
                .output()
                .unwrap();
            assert!(output.status.success());
            let ours = pem_signer(name)
                .sign(digest, b"another message to sign")
                .unwrap();
            assert_eq!(ours, output.stdout, "{name} {digest}");
        }
    }
}

#[test]
fn local_signer_rsa_uses_blinding_path() {
    let calls = Arc::new(AtomicUsize::new(0));
    let rng = CountingRng {
        state: 42,
        calls: Arc::clone(&calls),
    };
    let signer = pem_signer("rsa2048").with_rng(Box::new(rng));
    let data = vector_data();
    let signature = signer.sign(DigestAlgorithm::Sha256, &data).unwrap();
    // RandomizedSigner::try_sign_with_rng blinds with the RNG; the plain Signer path would not
    // touch it (brief R-9).
    let used = calls.load(Ordering::SeqCst);
    assert!(used > 0, "the RSA signature did not use the RNG");
    // Blinding never changes a PKCS#1 v1.5 signature.
    assert_eq!(signature, fixture("sign/golden-rsa2048-sha256.sig"));
    // A second signature asks for fresh randomness.
    signer.sign(DigestAlgorithm::Sha256, &data).unwrap();
    assert!(calls.load(Ordering::SeqCst) > used);

    // ECDSA (RFC 6979) never uses it.
    let calls = Arc::new(AtomicUsize::new(0));
    let rng = CountingRng {
        state: 7,
        calls: Arc::clone(&calls),
    };
    let ecdsa = pem_signer("p256").with_rng(Box::new(rng));
    ecdsa.sign(DigestAlgorithm::Sha256, &data).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn ecdsa_signatures_are_deterministic_der_and_verify() {
    let data = vector_data();
    for (name, field) in [("p256", 32usize), ("p384", 48)] {
        let signer = pem_signer(name);
        for digest in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let first = signer.sign(digest, &data).unwrap();
            let second = signer.sign(digest, &data).unwrap();
            assert_eq!(first, second, "{name} {digest}: RFC 6979 is deterministic");
            assert_eq!(first[0], 0x30, "DER ECDSA-Sig-Value");
            assert!(first.len() <= 2 * field + 8);
            cms::verify_raw(
                &signer.certificate_chain()[0],
                signer.algorithm(),
                digest,
                &data,
                &first,
            )
            .unwrap();
            // The other digest does not verify.
            let other = if digest == DigestAlgorithm::Sha256 {
                DigestAlgorithm::Sha512
            } else {
                DigestAlgorithm::Sha256
            };
            assert!(
                cms::verify_raw(
                    &signer.certificate_chain()[0],
                    signer.algorithm(),
                    other,
                    &data,
                    &first
                )
                .is_err()
            );
        }
    }
}

#[test]
fn ecdsa_signatures_verify_with_openssl() {
    if !openssl_available() {
        return;
    }
    let dir = scratch_dir("ecdsa_signatures_verify_with_openssl");
    let data_path = dir.join("data.bin");
    std::fs::write(&data_path, vector_data()).unwrap();
    for name in ["p256", "p384"] {
        let signer = pem_signer(name);
        for digest in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let sig_path = dir.join(format!("{name}-{digest}.sig"));
            std::fs::write(&sig_path, signer.sign(digest, &vector_data()).unwrap()).unwrap();
            let output = Command::new("openssl")
                .args(["dgst", &format!("-{digest}"), "-prverify"])
                .arg(fixtures_dir().join(format!("pki/signer-{name}.key.pem")))
                .arg("-signature")
                .arg(&sig_path)
                .arg(&data_path)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("Verified OK"), "{name} {digest}: {stdout}");
        }
    }
}

#[test]
fn signers_are_shareable_across_threads() {
    let signer: Arc<dyn Signer> = Arc::new(pem_signer("rsa2048"));
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let signer = Arc::clone(&signer);
            std::thread::spawn(move || {
                signer
                    .sign(DigestAlgorithm::Sha256, format!("message {i}").as_bytes())
                    .unwrap()
            })
        })
        .collect();
    for (i, handle) in handles.into_iter().enumerate() {
        let signature = handle.join().unwrap();
        cms::verify_raw(
            &signer.certificate_chain()[0],
            signer.algorithm(),
            DigestAlgorithm::Sha256,
            format!("message {i}").as_bytes(),
            &signature,
        )
        .unwrap();
    }
}

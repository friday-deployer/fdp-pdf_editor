//! ECDSA signature values (M3 brief §4.3 "ECDSA value", R-10, §6.2 "signers and ECDSA"): DER and
//! IEEE P1363 inputs, minimal re-encoding, high-S values and bad lengths.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod cms_support;

use cms_support::{der_children, der_split, pem_signer, tlv, vector_data, verify_over};
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::cms::{self, SignedAttrsInput};
use folioxide_sign::signer::{LocalSigner, Signer};
use folioxide_syntax::ErrorCode;

/// Signed attributes over the vector data and `signer`'s DER signature of them.
fn signed(signer: &LocalSigner, digest: DigestAlgorithm) -> (Vec<u8>, Vec<u8>) {
    let attrs = cms::build_signed_attrs(&SignedAttrsInput {
        digest,
        document_digest: &digest.digest(&[&vector_data()]),
        signer_cert_der: &signer.certificate_chain()[0],
    })
    .unwrap();
    let signature = signer.sign(digest, &attrs).unwrap();
    (attrs, signature)
}

/// `r || s` of a DER ECDSA-Sig-Value, each left-padded to `field` bytes.
fn to_p1363(der: &[u8], field: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for (_, int) in der_children(der) {
        let (_, content) = der_split(&int);
        let magnitude: Vec<u8> = content.iter().copied().skip_while(|&b| b == 0).collect();
        out.extend(vec![0u8; field - magnitude.len()]);
        out.extend(magnitude);
    }
    out
}

/// A DER ECDSA-Sig-Value from `r || s` with `pad` redundant zero octets before each INTEGER
/// value and a long-form SEQUENCE length.
fn lax_der(p1363: &[u8], pad: usize) -> Vec<u8> {
    let (r, s) = p1363.split_at(p1363.len() / 2);
    let mut body = Vec::new();
    for half in [r, s] {
        let mut content = vec![0u8; pad + 1];
        content.extend_from_slice(half);
        body.extend(tlv(0x02, &content));
    }
    let mut out = vec![0x30, 0x81, body.len() as u8];
    out.extend(body);
    out
}

/// Assembles a CMS with `signature` and returns the embedded signature value.
fn embedded(
    signer: &LocalSigner,
    digest: DigestAlgorithm,
    attrs: &[u8],
    signature: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let der = cms::assemble(
        attrs,
        signature,
        signer.certificate_chain(),
        signer.algorithm(),
        signer.key_kind(),
        digest,
    )
    .unwrap();
    let value = cms::parse(&der).unwrap().signer_infos[0].signature.clone();
    (der, value)
}

fn cases() -> [(LocalSigner, DigestAlgorithm, usize); 3] {
    [
        (pem_signer("p256"), DigestAlgorithm::Sha256, 32),
        (pem_signer("p384"), DigestAlgorithm::Sha384, 48),
        (pem_signer("p256"), DigestAlgorithm::Sha512, 32),
    ]
}

#[test]
fn ecdsa_der_accepted() {
    for (signer, digest, _) in cases() {
        let (attrs, der_sig) = signed(&signer, digest);
        let (cms_der, value) = embedded(&signer, digest, &attrs, &der_sig);
        assert_eq!(value, der_sig, "minimal DER is embedded unchanged");
        let v = verify_over(&cms_der, &vector_data());
        assert!(v.intact && v.signature_valid, "{v:?}");
        let cert = &signer.certificate_chain()[0];
        assert_eq!(
            cms::verify_and_normalize(cert, signer.algorithm(), digest, &attrs, &der_sig).unwrap(),
            der_sig
        );
    }
}

#[test]
fn ecdsa_p1363_accepted() {
    for (signer, digest, field) in cases() {
        let (attrs, der_sig) = signed(&signer, digest);
        let p1363 = to_p1363(&der_sig, field);
        assert_eq!(p1363.len(), 2 * field);
        // assemble converts r || s to the minimal DER the signer itself produced.
        let (cms_der, value) = embedded(&signer, digest, &attrs, &p1363);
        assert_eq!(value, der_sig);
        let v = verify_over(&cms_der, &vector_data());
        assert!(v.intact && v.signature_valid, "{v:?}");
        let cert = &signer.certificate_chain()[0];
        cms::verify_raw(cert, signer.algorithm(), digest, &attrs, &p1363).unwrap();
        assert_eq!(
            cms::verify_and_normalize(cert, signer.algorithm(), digest, &attrs, &p1363).unwrap(),
            der_sig
        );
    }
}

#[test]
fn ecdsa_non_minimal_der_normalized() {
    for (signer, digest, field) in cases() {
        let (attrs, der_sig) = signed(&signer, digest);
        for pad in [1, 3] {
            let lax = lax_der(&to_p1363(&der_sig, field), pad);
            assert_ne!(lax, der_sig);
            let (cms_der, value) = embedded(&signer, digest, &attrs, &lax);
            assert_eq!(value, der_sig, "re-encoded with minimal INTEGERs");
            let v = verify_over(&cms_der, &vector_data());
            assert!(v.intact && v.signature_valid, "{v:?}");
            let cert = &signer.certificate_chain()[0];
            assert_eq!(
                cms::verify_and_normalize(cert, signer.algorithm(), digest, &attrs, &lax).unwrap(),
                der_sig
            );
        }
    }
}

#[test]
fn ecdsa_high_s_verifies() {
    // Low-S is not required (P-256/P-384 have NORMALIZE_S = false): n - s verifies too.
    let signer = pem_signer("p256");
    let digest = DigestAlgorithm::Sha256;
    let (attrs, der_sig) = signed(&signer, digest);
    let sig = p256::ecdsa::Signature::from_der(&der_sig).unwrap();
    let (r, s) = sig.split_scalars();
    let flipped = p256::ecdsa::Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
    let flipped_der = flipped.to_der().as_bytes().to_vec();
    assert_ne!(flipped_der, der_sig);
    let cert = &signer.certificate_chain()[0];
    cms::verify_raw(cert, signer.algorithm(), digest, &attrs, &flipped_der).unwrap();
    let (cms_der, value) = embedded(&signer, digest, &attrs, &flipped_der);
    assert_eq!(
        value, flipped_der,
        "the value is kept, not normalized to low-S"
    );
    let v = verify_over(&cms_der, &vector_data());
    assert!(v.intact && v.signature_valid, "{v:?}");

    let signer = pem_signer("p384");
    let digest = DigestAlgorithm::Sha384;
    let (attrs, der_sig) = signed(&signer, digest);
    let sig = p384::ecdsa::Signature::from_der(&der_sig).unwrap();
    let (r, s) = sig.split_scalars();
    let flipped = p384::ecdsa::Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
    let flipped_der = flipped.to_der().as_bytes().to_vec();
    cms::verify_raw(
        &signer.certificate_chain()[0],
        signer.algorithm(),
        digest,
        &attrs,
        &flipped_der,
    )
    .unwrap();
}

#[test]
fn ecdsa_wrong_length_rejected() {
    for (signer, digest, field) in cases() {
        let (attrs, der_sig) = signed(&signer, digest);
        let p1363 = to_p1363(&der_sig, field);
        let cert = &signer.certificate_chain()[0];
        for bad in [
            p1363[..2 * field - 1].to_vec(),
            [p1363.clone(), vec![0]].concat(),
            Vec::new(),
            der_sig[..der_sig.len() - 1].to_vec(),
            [der_sig.clone(), vec![0]].concat(),
        ] {
            let err = cms::assemble(
                &attrs,
                &bad,
                signer.certificate_chain(),
                signer.algorithm(),
                signer.key_kind(),
                digest,
            )
            .unwrap_err();
            assert_eq!(
                err.code(),
                ErrorCode::SignatureInvalid,
                "{} bytes",
                bad.len()
            );
            let err = cms::verify_raw(cert, signer.algorithm(), digest, &attrs, &bad).unwrap_err();
            assert_eq!(err.code(), ErrorCode::SignatureInvalid);
        }
        // Right length, wrong value: assemble does not verify, verify_raw rejects it.
        let mut wrong = p1363.clone();
        wrong[5] ^= 1;
        let err = cms::verify_raw(cert, signer.algorithm(), digest, &attrs, &wrong).unwrap_err();
        assert_eq!(err.code(), ErrorCode::SignatureInvalid);
    }
}

#[test]
fn ecdsa_p1363_of_many_signatures_normalizes_to_the_signers_der() {
    // Over many messages some r or s values are shorter than the field (a leading zero octet in
    // P1363, a shorter INTEGER in DER); every P1363 value must normalize to the signer's DER.
    let signer = pem_signer("p256");
    let digest = DigestAlgorithm::Sha256;
    let cert = &signer.certificate_chain()[0];
    let mut short = 0;
    for i in 0..=255u8 {
        let tbs = [b"ambiguity probe ".as_slice(), &[i]].concat();
        let der_sig = signer.sign(digest, &tbs).unwrap();
        let p1363 = to_p1363(&der_sig, 32);
        if p1363[0] == 0 || p1363[32] == 0 {
            short += 1;
        }
        cms::verify_raw(cert, signer.algorithm(), digest, &tbs, &p1363).unwrap();
        assert_eq!(
            cms::verify_and_normalize(cert, signer.algorithm(), digest, &tbs, &p1363).unwrap(),
            der_sig
        );
    }
    assert!(short > 0, "no signature with a short r or s among 256");
}

#[test]
fn verify_raw_rejects_algorithm_key_mismatch() {
    let signer = pem_signer("p256");
    let err = cms::verify_raw(
        &signer.certificate_chain()[0],
        folioxide_sign::algorithms::SignatureAlgorithm::RsaPkcs1v15,
        DigestAlgorithm::Sha256,
        b"x",
        &[0; 64],
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    let err = cms::verify_raw(
        b"not a cert",
        signer.algorithm(),
        DigestAlgorithm::Sha256,
        b"x",
        &[0; 64],
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Certificate);
    // A signature by another key.
    let other = pem_signer("p256")
        .sign(DigestAlgorithm::Sha256, b"x")
        .unwrap();
    let p384 = pem_signer("p384");
    let err = cms::verify_raw(
        &p384.certificate_chain()[0],
        p384.algorithm(),
        DigestAlgorithm::Sha256,
        b"x",
        &other,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::SignatureInvalid);
}

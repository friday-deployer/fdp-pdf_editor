//! ECDSA signature values (M3 brief §4.3 "ECDSA value", R-10, §6.2 "signers and ECDSA"): DER and
//! IEEE P1363 inputs, minimal re-encoding, high-S values and bad lengths. A value a signer hands
//! to `finish` may be P1363 or non-minimal DER (it is normalised); an **embedded** value, in a
//! document signature or a timestamp token, must be minimal DER, as OpenSSL and pyHanko verify
//! it (M4 QA finding F1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod cms_support;

use cms_support::{
    alg_id, der_children, der_split, edit_signer_info, octets, pem_signer, tlv, vector_data,
    verify_over,
};
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::cms::{self, SignedAttrsInput};
use folioxide_sign::signer::{LocalSigner, Signer};
use folioxide_sign::tsp::{MessageImprint, OID_CT_TST_INFO, TimeStampReq};
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

/// The CMS of `signer` over the vector data with its signature value replaced by `value` (the
/// SignerInfo's `signature` OCTET STRING, every enclosing length rebuilt).
fn cms_with_value(signer: &LocalSigner, digest: DigestAlgorithm, value: &[u8]) -> Vec<u8> {
    let (attrs, der_sig) = signed(signer, digest);
    let (cms_der, _) = embedded(signer, digest, &attrs, &der_sig);
    edit_signer_info(&cms_der, |children| {
        assert_eq!(children[5].0, 0x04, "the signature value");
        children[5].1 = octets(value);
    })
}

#[test]
fn ecdsa_p1363_value_in_cms_rejected() {
    // M4 QA finding F1b: the document signature's embedded value must be DER (OpenSSL `cms
    // -verify` and pyHanko reject r || s); finish still normalises a P1363 value it is given.
    for (signer, digest, field) in cases() {
        let (attrs, der_sig) = signed(&signer, digest);
        let p1363 = to_p1363(&der_sig, field);
        let v = verify_over(&cms_with_value(&signer, digest, &p1363), &vector_data());
        assert!(v.intact && !v.signature_valid, "{v:?}");
        assert!(
            v.problems
                .iter()
                .any(|p| p.message.contains("not the DER encoding")),
            "{:?}",
            v.problems
        );
        // The control: the same CMS with the DER value verifies.
        let v = verify_over(&cms_with_value(&signer, digest, &der_sig), &vector_data());
        assert!(v.intact && v.signature_valid, "{v:?}");
        let cert = &signer.certificate_chain()[0];
        assert_eq!(
            cms::verify_and_normalize(cert, signer.algorithm(), digest, &attrs, &p1363).unwrap(),
            der_sig
        );
    }
}

#[test]
fn ecdsa_non_minimal_der_value_in_cms_rejected() {
    for (signer, digest, field) in cases() {
        let (_, der_sig) = signed(&signer, digest);
        for pad in [1, 3] {
            let lax = lax_der(&to_p1363(&der_sig, field), pad);
            let v = verify_over(&cms_with_value(&signer, digest, &lax), &vector_data());
            assert!(v.intact && !v.signature_valid, "pad {pad}: {v:?}");
        }
    }
}

/// A timestamp token over `b"value"` signed by the test P-256 key with ECDSA (the CMS layer
/// does not check the TSA purpose), its signature value replaced by `value(der)`.
fn ecdsa_token(value: impl FnOnce(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let signer = pem_signer("p256");
    let cert = signer.certificate_chain()[0].clone();
    let sign = move |attrs: &[u8]| signer.sign(DigestAlgorithm::Sha256, attrs).unwrap();
    let tsa = folioxide_testkit::tsa::MockTsa::new(cert, Vec::new(), Box::new(sign));
    let digest = DigestAlgorithm::Sha256;
    let request = TimeStampReq::new(
        MessageImprint::new(digest, digest.digest(&[b"value"])),
        Some(0x0102_0304_0506_0708),
        None,
    );
    let token = tsa.token_for(&request.to_der()).unwrap();
    // The mock writes sha256WithRSAEncryption: ecdsa-with-SHA256, and the chosen value.
    edit_signer_info(&token, |children| {
        children[4].1 = alg_id("1.2.840.10045.4.3.2");
        let (_, der) = der_split(&children[5].1);
        let der = der.to_vec();
        children[5].1 = octets(&value(&der));
    })
}

#[test]
fn tst_ecdsa_der_control_verifies() {
    let token = ecdsa_token(<[u8]>::to_vec);
    let v = cms::verify_encapsulated(&cms::parse(&token).unwrap(), OID_CT_TST_INFO, &[]);
    assert!(v.intact && v.signature_valid, "{v:?}");
}

#[test]
fn tst_ecdsa_p1363_rejected() {
    // M4 QA finding F1a: `openssl ts -verify` and pyHanko reject a TSA's r || s value.
    let token = ecdsa_token(|der| to_p1363(der, 32));
    let v = cms::verify_encapsulated(&cms::parse(&token).unwrap(), OID_CT_TST_INFO, &[]);
    assert!(v.intact && !v.signature_valid, "{v:?}");
}

#[test]
fn tst_ecdsa_nonminimal_der_rejected() {
    let token = ecdsa_token(|der| lax_der(&to_p1363(der, 32), 1));
    let v = cms::verify_encapsulated(&cms::parse(&token).unwrap(), OID_CT_TST_INFO, &[]);
    assert!(v.intact && !v.signature_valid, "{v:?}");
}

//! CMS building (M3 brief §4.3, §6.2 "CMS building"): the PAdES signed attributes, their DER
//! order and the `0x31` rule, ESSCertIDv2, the SignedData layout, algorithm parameters,
//! certificates and the size bound.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod cms_support;

use cms_support::{SIGNERS, der_children, der_split, oid_der, pem_signer, sign_cms, vector_data};
use folioxide_sign::algorithms::{DigestAlgorithm, KeyKind, SignatureAlgorithm, oid};
use folioxide_sign::cms::{self, SignedAttrsInput};
use folioxide_sign::signer::Signer;
use folioxide_syntax::ErrorCode;

const DIGESTS: [DigestAlgorithm; 3] = [
    DigestAlgorithm::Sha256,
    DigestAlgorithm::Sha384,
    DigestAlgorithm::Sha512,
];

fn signed_attrs(signer: &dyn Signer, digest: DigestAlgorithm, content: &[u8]) -> Vec<u8> {
    cms::build_signed_attrs(&SignedAttrsInput {
        digest,
        document_digest: &digest.digest(&[content]),
        signer_cert_der: &signer.certificate_chain()[0],
    })
    .unwrap()
}

/// `(type OID content, value TLVs)` of every attribute in a 0x31 attribute SET.
fn attributes(attrs: &[u8]) -> Vec<(Vec<u8>, Vec<Vec<u8>>)> {
    der_children(attrs)
        .into_iter()
        .map(|(_, attribute)| {
            let fields = der_children(&attribute);
            let (_, oid_content) = der_split(&fields[0].1);
            let values = der_children(&fields[1].1)
                .into_iter()
                .map(|(_, v)| v)
                .collect();
            (oid_content.to_vec(), values)
        })
        .collect()
}

fn oid_content(dotted: &str) -> Vec<u8> {
    der_split(&oid_der(dotted)).1.to_vec()
}

/// The raw issuer Name and serial INTEGER of a certificate (RFC 5280 §4.1).
fn issuer_and_serial(cert: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let tbs = der_children(cert)[0].1.clone();
    let fields = der_children(&tbs);
    let offset = usize::from(fields[0].0 == 0xA0);
    (fields[offset + 2].1.clone(), fields[offset].1.clone())
}

/// The ESSCertIDv2 of signed attributes.
fn ess_cert_id(attrs: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let ess = attributes(attrs)
        .into_iter()
        .find(|(t, _)| *t == oid_content(oid::SIGNING_CERTIFICATE_V2))
        .unwrap();
    assert_eq!(ess.1.len(), 1);
    let signing_certificate = der_children(&ess.1[0]);
    assert_eq!(signing_certificate.len(), 1, "no policies");
    let certs = der_children(&signing_certificate[0].1);
    assert_eq!(certs.len(), 1, "exactly one ESSCertIDv2");
    der_children(&certs[0].1)
}

#[test]
fn cms_signed_attrs_retagged_0x31() {
    let data = vector_data();
    for name in SIGNERS {
        let signer = pem_signer(name);
        let digest = folioxide_sign::algorithms::default_digest(signer.key_kind());
        let tbs = signed_attrs(&signer, digest, &data);
        assert_eq!(tbs[0], 0x31);
        let der = sign_cms(&signer, digest, &data);
        let parsed = cms::parse(&der).unwrap();
        let si_attrs = parsed.signer_infos[0].signed_attrs.clone().unwrap();
        // Same length and content octets; only the tag differs (RFC 5652 §5.4).
        let fresh = signed_attrs(&signer, digest, &data);
        assert_eq!(si_attrs[0], 0xA0);
        assert_eq!(si_attrs[1..], fresh[1..]);
        // And the signature covers the 0x31 form.
        cms::verify_raw(
            &signer.certificate_chain()[0],
            signer.algorithm(),
            digest,
            &fresh,
            &parsed.signer_infos[0].signature,
        )
        .unwrap();
    }
}

#[test]
fn cms_signed_attrs_der_sorted() {
    let data = vector_data();
    for name in SIGNERS {
        let signer = pem_signer(name);
        for digest in DIGESTS {
            let attrs = signed_attrs(&signer, digest, &data);
            let encodings: Vec<Vec<u8>> =
                der_children(&attrs).into_iter().map(|(_, a)| a).collect();
            assert_eq!(encodings.len(), 3);
            let mut sorted = encodings.clone();
            sorted.sort();
            assert_eq!(encodings, sorted, "{name} {digest}: X.690 §11.6 order");
            // The order depends on the lengths, not on the attribute types: content-type is
            // always the shortest, the others follow by length.
            let types: Vec<Vec<u8>> = attributes(&attrs).into_iter().map(|(t, _)| t).collect();
            assert_eq!(types[0], oid_content(oid::CONTENT_TYPE));
            let by_length = |t: &str| {
                encodings
                    .iter()
                    .zip(&types)
                    .find(|(_, ty)| **ty == oid_content(t))
                    .map(|(e, _)| e.len())
                    .unwrap()
            };
            assert_eq!(
                types[1] == oid_content(oid::MESSAGE_DIGEST),
                by_length(oid::MESSAGE_DIGEST) <= by_length(oid::SIGNING_CERTIFICATE_V2),
                "{name} {digest}"
            );
        }
    }
}

#[test]
fn ess_cert_id_v2_omits_default_sha256() {
    let signer = pem_signer("p256");
    let attrs = signed_attrs(&signer, DigestAlgorithm::Sha256, &vector_data());
    let fields = ess_cert_id(&attrs);
    // No hashAlgorithm at all: {id-sha256} is the DEFAULT and DER omits it (X.690 §11.5). The
    // encoding of {id-sha256, NULL} (30 0d 06 09 ... 05 00) must not appear either.
    assert_eq!(fields.len(), 2, "certHash and issuerSerial only");
    assert_eq!(fields[0].0, 0x04, "the first field is certHash");
    let sha256_null = [
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    ];
    let sha256_absent = &sha256_null[..13];
    let mut sha256_absent_seq = vec![0x30, 0x0b];
    sha256_absent_seq.extend_from_slice(&sha256_absent[2..]);
    let ess_value = &attributes(&attrs)
        .into_iter()
        .find(|(t, _)| *t == oid_content(oid::SIGNING_CERTIFICATE_V2))
        .unwrap()
        .1[0];
    assert!(!contains(ess_value, &sha256_null));
    assert!(!contains(ess_value, &sha256_absent_seq));
    assert_eq!(
        fields[0].1[2..],
        DigestAlgorithm::Sha256.digest(&[&signer.certificate_chain()[0]])[..]
    );
}

#[test]
fn ess_cert_id_v2_sha384_explicit() {
    for (digest, oid_last) in [
        (DigestAlgorithm::Sha384, 0x02),
        (DigestAlgorithm::Sha512, 0x03),
    ] {
        let signer = pem_signer("p384");
        let attrs = signed_attrs(&signer, digest, &vector_data());
        let fields = ess_cert_id(&attrs);
        assert_eq!(fields.len(), 3);
        // {oid, parameters ABSENT}: 30 0b 06 09 60 86 48 01 65 03 04 02 0x
        assert_eq!(
            fields[0].1,
            [
                0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, oid_last
            ]
        );
        let (_, cert_hash) = der_split(&fields[1].1);
        assert_eq!(
            cert_hash,
            digest.digest(&[&signer.certificate_chain()[0]]).as_slice()
        );
    }
}

#[test]
fn ess_cert_id_v2_has_issuer_serial() {
    for name in SIGNERS {
        let signer = pem_signer(name);
        let attrs = signed_attrs(&signer, DigestAlgorithm::Sha256, &vector_data());
        let fields = ess_cert_id(&attrs);
        let issuer_serial = der_children(&fields[1].1);
        assert_eq!(issuer_serial.len(), 2);
        let general_names = der_children(&issuer_serial[0].1);
        assert_eq!(general_names.len(), 1);
        // directoryName [4] EXPLICIT Name.
        assert_eq!(general_names[0].0, 0xA4);
        let (issuer, serial) = issuer_and_serial(&signer.certificate_chain()[0]);
        assert_eq!(der_split(&general_names[0].1).1, issuer.as_slice());
        assert_eq!(issuer_serial[1].1, serial);
    }
}

#[test]
fn no_signing_time_attr() {
    let data = vector_data();
    for name in SIGNERS {
        let signer = pem_signer(name);
        for digest in DIGESTS {
            let mut types: Vec<Vec<u8>> = attributes(&signed_attrs(&signer, digest, &data))
                .into_iter()
                .map(|(t, values)| {
                    assert_eq!(values.len(), 1);
                    t
                })
                .collect();
            types.sort();
            let mut expected = vec![
                oid_content(oid::CONTENT_TYPE),
                oid_content(oid::MESSAGE_DIGEST),
                oid_content(oid::SIGNING_CERTIFICATE_V2),
            ];
            expected.sort();
            assert_eq!(types, expected, "exactly the three PAdES B-B attributes");
            assert!(!types.contains(&oid_content(oid::SIGNING_TIME)));
            assert!(!types.contains(&oid_content(oid::SIGNING_CERTIFICATE)));
            assert!(!types.contains(&oid_content(oid::CMS_ALGORITHM_PROTECTION)));
        }
    }
}

#[test]
fn signed_attrs_values() {
    let data = vector_data();
    let signer = pem_signer("rsa2048");
    let attrs = signed_attrs(&signer, DigestAlgorithm::Sha512, &data);
    for (attr_type, values) in attributes(&attrs) {
        if attr_type == oid_content(oid::CONTENT_TYPE) {
            assert_eq!(values[0], oid_der(oid::ID_DATA));
        } else if attr_type == oid_content(oid::MESSAGE_DIGEST) {
            assert_eq!(
                der_split(&values[0]).1,
                DigestAlgorithm::Sha512.digest(&[&data]).as_slice()
            );
        }
    }
    // The length does not depend on the digest value (placeholder sizing, brief §4.2).
    let zero = cms::build_signed_attrs(&SignedAttrsInput {
        digest: DigestAlgorithm::Sha512,
        document_digest: &[0; 64],
        signer_cert_der: &signer.certificate_chain()[0],
    })
    .unwrap();
    assert_eq!(zero.len(), attrs.len());
}

#[test]
fn build_signed_attrs_rejects_bad_input() {
    let signer = pem_signer("p256");
    let cert = &signer.certificate_chain()[0];
    for (digest, document_digest, cert, code) in [
        (
            DigestAlgorithm::Sha256,
            vec![0u8; 31],
            cert.clone(),
            ErrorCode::InvalidArgument,
        ),
        (
            DigestAlgorithm::Sha384,
            vec![0u8; 32],
            cert.clone(),
            ErrorCode::InvalidArgument,
        ),
        (
            DigestAlgorithm::Sha1,
            vec![0u8; 20],
            cert.clone(),
            ErrorCode::InvalidArgument,
        ),
        (
            DigestAlgorithm::Sha256,
            vec![0u8; 32],
            vec![0x30, 0x00],
            ErrorCode::Certificate,
        ),
    ] {
        let err = cms::build_signed_attrs(&SignedAttrsInput {
            digest,
            document_digest: &document_digest,
            signer_cert_der: &cert,
        })
        .unwrap_err();
        assert_eq!(err.code(), code, "{digest}: {err}");
    }
}

#[test]
fn cms_detached_no_econtent() {
    let der = sign_cms(&pem_signer("p384"), DigestAlgorithm::Sha384, &vector_data());
    let parsed = cms::parse(&der).unwrap();
    assert_eq!(parsed.content_type, oid::ID_SIGNED_DATA);
    assert_eq!(parsed.econtent_type.as_deref(), Some(oid::ID_DATA));
    assert_eq!(parsed.econtent, None);
    assert_eq!(parsed.raw, 0..der.len());
    // The encapContentInfo is exactly SEQUENCE { id-data }.
    let signed_data = der_children(&der_children(&der)[1].1)[0].1.clone();
    let fields = der_children(&signed_data);
    assert_eq!(fields[0].1, [0x02, 0x01, 0x01], "SignedData version 1");
    assert_eq!(fields[2].1, cms_support::seq(&[&oid_der(oid::ID_DATA)]));
    assert_eq!(
        fields.len(),
        5,
        "version, digestAlgorithms, encapContentInfo, certificates, signerInfos"
    );
    assert_eq!(fields[3].0, 0xA0);
    // SignerInfo: version 1, IssuerAndSerialNumber with the raw issuer and serial, no unsigned
    // attributes.
    let signer_infos = der_children(&fields[4].1);
    assert_eq!(signer_infos.len(), 1);
    let si = der_children(&signer_infos[0].1);
    assert_eq!(si.len(), 6);
    assert_eq!(si[0].1, [0x02, 0x01, 0x01]);
    let (issuer, serial) = issuer_and_serial(&cms_support::cert_der("pki/signer-p384.pem"));
    assert_eq!(si[1].1, cms_support::seq(&[&issuer, &serial]));
    let info = &parsed.signer_infos[0];
    assert_eq!(info.version, 1);
    assert_eq!(
        info.sid,
        cms::SignerIdentifier::IssuerAndSerialNumber { issuer, serial }
    );
    assert!(info.unsigned_attrs.is_none());
}

#[test]
fn cms_certificates_byte_identical() {
    let signer = pem_signer("rsa3072");
    let chain = vec![
        signer.certificate_chain()[0].clone(),
        cms_support::cert_der("pki/intermediate.pem"),
        cms_support::cert_der("pki/root.pem"),
    ];
    let digest = DigestAlgorithm::Sha256;
    let attrs = signed_attrs(&signer, digest, &vector_data());
    let signature = signer.sign(digest, &attrs).unwrap();
    let der = cms::assemble(
        &attrs,
        &signature,
        &chain,
        signer.algorithm(),
        signer.key_kind(),
        digest,
    )
    .unwrap();
    let parsed = cms::parse(&der).unwrap();
    // Every input certificate, byte for byte, in DER SET OF order (X.690 §11.6).
    let mut expected = chain.clone();
    expected.sort();
    assert_eq!(parsed.certificates, expected);
    for cert in &chain {
        assert!(contains(&der, cert));
    }
    let v = cms_support::verify_over(&der, &vector_data());
    assert!(v.intact && v.signature_valid, "{v:?}");
}

#[test]
fn cms_alg_id_params() {
    let data = vector_data();
    for name in SIGNERS {
        let signer = pem_signer(name);
        for digest in DIGESTS {
            let der = sign_cms(&signer, digest, &data);
            let parsed = cms::parse(&der).unwrap();
            let info = &parsed.signer_infos[0];
            // Digests: parameters absent (RFC 5754 §2).
            assert_eq!(info.digest_algorithm.oid, digest.oid());
            assert_eq!(info.digest_algorithm.parameters, None);
            let signed_data = der_children(&der_children(&der)[1].1)[0].1.clone();
            let digest_algorithms = der_children(&der_children(&signed_data)[1].1);
            assert_eq!(digest_algorithms.len(), 1);
            assert_eq!(digest_algorithms[0].1, cms_support::alg_id(digest.oid()));
            // RSA: NULL (RFC 4055 §5); ECDSA: absent (RFC 5758 §3.2).
            assert_eq!(
                info.signature_algorithm.oid,
                signer.algorithm().signature_oid(digest)
            );
            let expected_params = match signer.algorithm() {
                SignatureAlgorithm::RsaPkcs1v15 => Some(vec![0x05, 0x00]),
                _ => None,
            };
            assert_eq!(
                info.signature_algorithm.parameters, expected_params,
                "{name} {digest}"
            );
        }
    }
}

#[test]
fn cms_len_upper_bound_is_tight() {
    for name in SIGNERS {
        let signer = pem_signer(name);
        for digest in DIGESTS {
            for document in 0..4u8 {
                let content = [document; 7];
                let attrs = signed_attrs(&signer, digest, &content);
                let bound = cms::cms_len_upper_bound(
                    &attrs,
                    signer.certificate_chain(),
                    signer.algorithm(),
                    signer.key_kind(),
                    digest,
                )
                .unwrap();
                let signature = signer.sign(digest, &attrs).unwrap();
                let der = cms::assemble(
                    &attrs,
                    &signature,
                    signer.certificate_chain(),
                    signer.algorithm(),
                    signer.key_kind(),
                    digest,
                )
                .unwrap();
                match signer.key_kind() {
                    KeyKind::Rsa { .. } => assert_eq!(bound, der.len(), "{name} {digest}"),
                    _ => {
                        assert!(bound >= der.len(), "{name} {digest}");
                        // A maximal DER ECDSA value is 72/104 bytes; a real one is at most a few
                        // bytes shorter (two sign octets, rarely a shorter INTEGER).
                        assert!(
                            bound - der.len() <= 3,
                            "{name} {digest}: bound {bound}, actual {}",
                            der.len()
                        );
                        assert_eq!(
                            bound - der.len(),
                            signer.key_kind().max_signature_len() - signature.len()
                        );
                    }
                }
            }
        }
    }
}

/// The inputs of one `assemble` call and the error code it must give.
type Case = (
    Vec<u8>,
    Vec<u8>,
    Vec<Vec<u8>>,
    SignatureAlgorithm,
    KeyKind,
    DigestAlgorithm,
    ErrorCode,
);

#[test]
fn assemble_rejects_bad_input() {
    let signer = pem_signer("rsa2048");
    let digest = DigestAlgorithm::Sha256;
    let attrs = signed_attrs(&signer, digest, b"x");
    let signature = signer.sign(digest, &attrs).unwrap();
    let chain = signer.certificate_chain();
    let kind = signer.key_kind();
    let rsa = SignatureAlgorithm::RsaPkcs1v15;
    let mut retagged = attrs.clone();
    retagged[0] = 0xA0;
    let mut long = vec![1u8];
    long.extend_from_slice(&signature);
    let cases: Vec<Case> = vec![
        (
            attrs.clone(),
            signature.clone(),
            vec![],
            rsa,
            kind,
            digest,
            ErrorCode::InvalidArgument,
        ),
        (
            attrs.clone(),
            signature.clone(),
            chain.to_vec(),
            SignatureAlgorithm::Ecdsa,
            kind,
            digest,
            ErrorCode::InvalidArgument,
        ),
        (
            attrs.clone(),
            signature.clone(),
            chain.to_vec(),
            rsa,
            kind,
            DigestAlgorithm::Sha1,
            ErrorCode::InvalidArgument,
        ),
        (
            attrs.clone(),
            signature.clone(),
            chain.to_vec(),
            rsa,
            KeyKind::Rsa { bits: 1024 },
            digest,
            ErrorCode::InvalidArgument,
        ),
        (
            retagged,
            signature.clone(),
            chain.to_vec(),
            rsa,
            kind,
            digest,
            ErrorCode::InvalidArgument,
        ),
        (
            attrs[..attrs.len() - 1].to_vec(),
            signature.clone(),
            chain.to_vec(),
            rsa,
            kind,
            digest,
            ErrorCode::InvalidArgument,
        ),
        (
            attrs.clone(),
            long,
            chain.to_vec(),
            rsa,
            kind,
            digest,
            ErrorCode::SignatureInvalid,
        ),
        (
            attrs.clone(),
            signature.clone(),
            vec![b"junk".to_vec()],
            rsa,
            kind,
            digest,
            ErrorCode::Certificate,
        ),
        (
            attrs.clone(),
            signature.clone(),
            vec![chain[0].clone(), b"junk".to_vec()],
            rsa,
            kind,
            digest,
            ErrorCode::Certificate,
        ),
    ];
    for (i, (attrs, signature, chain, alg, kind, digest, code)) in cases.into_iter().enumerate() {
        let err = cms::assemble(&attrs, &signature, &chain, alg, kind, digest).unwrap_err();
        assert_eq!(err.code(), code, "case {i}: {err}");
        if code != ErrorCode::SignatureInvalid {
            let err = cms::cms_len_upper_bound(&attrs, &chain, alg, kind, digest).unwrap_err();
            assert_eq!(err.code(), code, "bound case {i}: {err}");
        }
    }
    // A short RSA signature is left-padded to the modulus length.
    let stripped: Vec<u8> = signature.iter().copied().skip_while(|&b| b == 0).collect();
    if stripped.len() < signature.len() {
        let der = cms::assemble(&attrs, &stripped, chain, rsa, kind, digest).unwrap();
        assert_eq!(
            cms::parse(&der).unwrap().signer_infos[0].signature,
            signature
        );
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

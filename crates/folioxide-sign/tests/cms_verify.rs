//! CMS verification (M3 brief §5 V6–V8, §6.2 "CMS verification"): OpenSSL and pyHanko vectors,
//! RSA-PSS, short RSA signatures, SHA-1, algorithm consistency and protection, ESS
//! signing-certificate checks, and every structural problem code of `verify_detached`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod cms_support;

use cms_support::{
    alg_id, attribute, basic_attributes, cert_der, cms_with_attributes, der_children, der_split,
    edit_signed_data, edit_signer_info, fixture, octets, oid_der, pem_signer, seq, sign_cms, tlv,
    vector_data, verify_over,
};
use folioxide_sign::ProblemCode;
use folioxide_sign::algorithms::{DigestAlgorithm, oid};
use folioxide_sign::cms::{self, CmsVerification, SignedAttrsInput};
use folioxide_sign::signer::Signer;

fn codes(v: &CmsVerification) -> Vec<ProblemCode> {
    v.problems.iter().map(|p| p.code).collect()
}

fn assert_valid(v: &CmsVerification, what: &str) {
    assert!(v.intact && v.signature_valid, "{what}: {v:?}");
    assert!(v.problems.is_empty(), "{what}: {:?}", v.problems);
}

/// The raw issuer Name and serial INTEGER of a certificate (RFC 5280 §4.1).
fn issuer_and_serial(cert: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let tbs = der_children(cert)[0].1.clone();
    let fields = der_children(&tbs);
    let offset = usize::from(fields[0].0 == 0xA0);
    (fields[offset + 2].1.clone(), fields[offset].1.clone())
}

/// `IssuerSerial { GeneralNames { [4] issuer }, serial }`.
fn issuer_serial(issuer: &[u8], serial: &[u8]) -> Vec<u8> {
    seq(&[&seq(&[&tlv(0xA4, issuer)]), serial])
}

/// A signing-certificate-v2 attribute with one ESSCertIDv2 made of `fields`.
fn ess_v2(fields: &[&[u8]]) -> Vec<u8> {
    attribute(
        oid::SIGNING_CERTIFICATE_V2,
        &[&seq(&[&seq(&[&seq(fields)])])],
    )
}

/// Hand-made signed attributes, DER-sorted.
fn sorted_cms(signer: &dyn Signer, digest: DigestAlgorithm, attrs: Vec<Vec<u8>>) -> Vec<u8> {
    let mut attrs = attrs;
    attrs.sort();
    let refs: Vec<&[u8]> = attrs.iter().map(Vec::as_slice).collect();
    cms_with_attributes(signer, digest, &refs)
}

#[test]
fn verify_own_cms_for_every_signer_and_digest() {
    let data = vector_data();
    for name in cms_support::SIGNERS {
        let signer = pem_signer(name);
        for digest in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let der = sign_cms(&signer, digest, &data);
            let v = verify_over(&der, &data);
            assert_valid(&v, &format!("{name} {digest}"));
            assert_eq!(v.digest, Some(digest));
            assert_eq!(
                v.signature_algorithm.as_deref(),
                Some(signer.algorithm().signature_name(digest))
            );
            assert_eq!(
                v.signer_cert.as_deref(),
                Some(signer.certificate_chain()[0].as_slice())
            );
            assert!(v.pades_attrs.is_baseline_b(), "{v:?}");
            assert_eq!(v.pades_attrs.content_type.as_deref(), Some(oid::ID_DATA));
            assert_eq!(v.pades_attrs.message_digest, Some(digest.digest(&[&data])));
            assert_eq!(v.pades_attrs.signing_certificate_v2, Some(true));
            assert!(v.warnings.is_empty());
        }
    }
}

#[test]
fn verify_openssl_vectors() {
    let data = vector_data();
    for (name, digest, sig_alg, ess_v2) in [
        (
            "openssl-rsa2048-sha256.p7s",
            DigestAlgorithm::Sha256,
            "sha256WithRSAEncryption",
            None,
        ),
        (
            "openssl-p256-cades.p7s",
            DigestAlgorithm::Sha256,
            "ecdsa-with-SHA256",
            Some(true),
        ),
        (
            "openssl-p384-sha384.p7s",
            DigestAlgorithm::Sha384,
            "ecdsa-with-SHA384",
            None,
        ),
        (
            "openssl-long-serial.p7s",
            DigestAlgorithm::Sha256,
            "ecdsa-with-SHA256",
            None,
        ),
        (
            "ber-indefinite-p256.p7s",
            DigestAlgorithm::Sha256,
            "ecdsa-with-SHA256",
            Some(true),
        ),
    ] {
        let v = verify_over(&fixture(&format!("sign/{name}")), &data);
        assert_valid(&v, name);
        assert_eq!(v.digest, Some(digest), "{name}");
        assert_eq!(v.signature_algorithm.as_deref(), Some(sig_alg), "{name}");
        assert_eq!(v.pades_attrs.signing_certificate_v2, ess_v2, "{name}");
        // OpenSSL writes a signing-time, which PAdES B-B forbids.
        let time = v.pades_attrs.signing_time.clone().unwrap();
        assert!(
            time.starts_with("20") && time.ends_with('Z') && time.len() == 20,
            "{time}"
        );
        assert!(!v.pades_attrs.is_baseline_b());
    }
}

#[test]
fn verify_pyhanko_fixture_vectors() {
    let data = vector_data();
    for (name, digest, sig_alg) in [
        (
            "pyhanko-rsa2048.p7s",
            DigestAlgorithm::Sha256,
            "sha256WithRSAEncryption",
        ),
        (
            "pyhanko-p256.p7s",
            DigestAlgorithm::Sha256,
            "ecdsa-with-SHA256",
        ),
        (
            "pyhanko-p384-sha384.p7s",
            DigestAlgorithm::Sha384,
            "ecdsa-with-SHA384",
        ),
        (
            "pyhanko-rsa3072-pss.p7s",
            DigestAlgorithm::Sha256,
            "rsassa-pss",
        ),
    ] {
        let v = verify_over(&fixture(&format!("sign/{name}")), &data);
        assert_valid(&v, name);
        assert_eq!(v.digest, Some(digest), "{name}");
        assert_eq!(v.signature_algorithm.as_deref(), Some(sig_alg), "{name}");
        // pyHanko with use_pades=True: the PAdES B-B attribute profile.
        assert!(v.pades_attrs.is_baseline_b(), "{name}: {:?}", v.pades_attrs);
        let wrong = verify_over(&fixture(&format!("sign/{name}")), b"other bytes");
        assert!(!wrong.intact && wrong.signature_valid, "{name}");
        assert_eq!(codes(&wrong), [ProblemCode::DigestMismatch]);
    }
}

#[test]
fn verify_rsa_pss_openssl_fixture() {
    let data = vector_data();
    let der = fixture("sign/openssl-rsa2048-pss.p7s");
    let v = verify_over(&der, &data);
    assert_valid(&v, "openssl PSS");
    assert_eq!(v.signature_algorithm.as_deref(), Some("rsassa-pss"));

    // The parameters OpenSSL wrote: hash, MGF1 and the salt length.
    let parsed = cms::parse(&der).unwrap();
    let alg = &parsed.signer_infos[0].signature_algorithm;
    assert_eq!(alg.oid, oid::RSASSA_PSS);
    let params = alg.parameters.clone().unwrap();
    let salt_field = der_children(&params)
        .into_iter()
        .find(|(tag, _)| *tag == 0xA2)
        .unwrap()
        .1;
    let salt_int = der_split(&salt_field).1.to_vec();
    let salt = der_split(&salt_int)
        .1
        .iter()
        .fold(0usize, |a, &b| (a << 8) | usize::from(b));
    assert!(salt > 0);

    // OpenSSL uses the maximal salt (222 bytes for RSA-2048 and SHA-256): a two-octet INTEGER.
    let unsigned = |value: usize| {
        let bytes = value.to_be_bytes();
        let mut content: Vec<u8> = bytes.iter().copied().skip_while(|&b| b == 0).collect();
        if content.first().is_none_or(|&b| b & 0x80 != 0) {
            content.insert(0, 0);
        }
        content
    };
    let pss_params = |hash: &str, mgf_hash: &str, salt: usize| {
        seq(&[
            &tlv(0xA0, &alg_id(hash)),
            &tlv(0xA1, &seq(&[&oid_der(oid::MGF1), &alg_id(mgf_hash)])),
            &tlv(0xA2, &tlv(0x02, &unsigned(salt))),
        ])
    };
    let with_params = |params: Vec<u8>| {
        edit_signer_info(&der, |si| {
            si[4] = (0x30, seq(&[&oid_der(oid::RSASSA_PSS), &params]))
        })
    };
    // Re-encoding the same parameters keeps the signature valid.
    let v = verify_over(
        &with_params(pss_params(oid::SHA256, oid::SHA256, salt)),
        &data,
    );
    assert_valid(&v, "re-encoded PSS parameters");
    // A different salt length does not verify.
    let v = verify_over(
        &with_params(pss_params(oid::SHA256, oid::SHA256, salt + 1)),
        &data,
    );
    assert!(!v.signature_valid && v.intact);
    assert_eq!(codes(&v), [ProblemCode::SignatureInvalid]);
    // MGF1 on another hash is not supported.
    let v = verify_over(
        &with_params(pss_params(oid::SHA256, oid::SHA1, salt)),
        &data,
    );
    assert!(!v.signature_valid);
    assert_eq!(codes(&v), [ProblemCode::UnsupportedAlgorithm]);
    // A PSS hash that differs from the digest algorithm.
    let v = verify_over(
        &with_params(pss_params(oid::SHA384, oid::SHA384, salt)),
        &data,
    );
    assert!(!v.signature_valid);
    assert_eq!(codes(&v), [ProblemCode::DigestSignatureAlgorithmMismatch]);
    // pyHanko's PSS (RSA-3072) verifies too.
    assert_valid(
        &verify_over(&fixture("sign/pyhanko-rsa3072-pss.p7s"), &data),
        "pyHanko PSS",
    );
}

#[test]
fn verify_rsa_short_signature_left_padded() {
    // Find a content whose PKCS#1 v1.5 signature starts with a zero octet (about 1 in 256;
    // the search starts at the first hit for the committed test key).
    let signer = pem_signer("rsa2048");
    let digest = DigestAlgorithm::Sha256;
    let (content, attrs, signature) = (247u32..247 + 4096)
        .find_map(|i| {
            let content = format!("short signature probe {i}").into_bytes();
            let attrs = cms::build_signed_attrs(&SignedAttrsInput {
                digest,
                document_digest: &digest.digest(&[&content]),
                signer_cert_der: &signer.certificate_chain()[0],
            })
            .unwrap();
            let signature = signer.sign(digest, &attrs).unwrap();
            (signature[0] == 0).then_some((content, attrs, signature))
        })
        .unwrap();
    assert_eq!(signature.len(), 256);
    let short = &signature[1..];
    cms::verify_raw(
        &signer.certificate_chain()[0],
        signer.algorithm(),
        digest,
        &attrs,
        short,
    )
    .unwrap();
    let full = cms::assemble(
        &attrs,
        &signature,
        signer.certificate_chain(),
        signer.algorithm(),
        signer.key_kind(),
        digest,
    )
    .unwrap();
    // A CMS that carries the 255-byte value, as some signers write it.
    let der = edit_signer_info(&full, |si| si[5] = (0x04, octets(short)));
    assert_eq!(
        cms::parse(&der).unwrap().signer_infos[0].signature.len(),
        255
    );
    assert_valid(&verify_over(&der, &content), "short RSA signature");
    // Longer than the modulus is invalid.
    let long = [&[0x01][..], &signature].concat();
    let der = edit_signer_info(&full, |si| si[5] = (0x04, octets(&long)));
    let v = verify_over(&der, &content);
    assert!(!v.signature_valid);
    assert_eq!(codes(&v), [ProblemCode::SignatureInvalid]);
}

#[test]
fn verify_sha1_legacy_weak() {
    let v = verify_over(&fixture("sign/openssl-rsa2048-sha1.p7s"), &vector_data());
    // The cryptography holds; the weakness is a problem (never trusted, never `is_valid`).
    assert!(v.intact && v.signature_valid, "{v:?}");
    assert_eq!(codes(&v), [ProblemCode::WeakAlgorithm]);
    assert_eq!(v.digest, Some(DigestAlgorithm::Sha1));
    assert_eq!(
        v.signature_algorithm.as_deref(),
        Some("sha1WithRSAEncryption")
    );
}

#[test]
fn verify_digest_sigalg_mismatch_invalid() {
    let data = vector_data();
    let der = sign_cms(&pem_signer("rsa2048"), DigestAlgorithm::Sha256, &data);
    let mismatched = edit_signer_info(&der, |si| {
        si[4] = (0x30, seq(&[&oid_der(oid::SHA384_WITH_RSA), &[0x05, 0x00]]))
    });
    let v = verify_over(&mismatched, &data);
    assert!(v.intact && !v.signature_valid, "{v:?}");
    assert_eq!(codes(&v), [ProblemCode::DigestSignatureAlgorithmMismatch]);

    // The same for ECDSA.
    let der = sign_cms(&pem_signer("p384"), DigestAlgorithm::Sha384, &data);
    let mismatched = edit_signer_info(&der, |si| si[4] = (0x30, alg_id(oid::ECDSA_WITH_SHA512)));
    let v = verify_over(&mismatched, &data);
    assert!(!v.signature_valid);
    assert_eq!(codes(&v), [ProblemCode::DigestSignatureAlgorithmMismatch]);

    // rsaEncryption / id-ecPublicKey take the digest algorithm and stay valid (RFC 3370 §3.2).
    let der = sign_cms(&pem_signer("rsa2048"), DigestAlgorithm::Sha256, &data);
    let generic = edit_signer_info(&der, |si| {
        si[4] = (0x30, seq(&[&oid_der(oid::RSA_ENCRYPTION), &[0x05, 0x00]]))
    });
    assert_valid(&verify_over(&generic, &data), "rsaEncryption");
    let der = sign_cms(&pem_signer("p256"), DigestAlgorithm::Sha512, &data);
    let generic = edit_signer_info(&der, |si| si[4] = (0x30, alg_id(oid::EC_PUBLIC_KEY)));
    assert_valid(&verify_over(&generic, &data), "id-ecPublicKey");
}

#[test]
fn verify_algorithm_protection_mismatch() {
    let signer = pem_signer("rsa2048");
    let digest = DigestAlgorithm::Sha256;
    let data = vector_data();
    let (content_type, message_digest) = basic_attributes(digest, &data);
    let rsa_sha256 = [oid_der(oid::SHA256_WITH_RSA), vec![0x05, 0x00]].concat();
    let protection = |digest_alg: &[u8], signature_alg: Option<&[u8]>| {
        let mut fields = vec![digest_alg.to_vec()];
        if let Some(sig) = signature_alg {
            // [1] IMPLICIT AlgorithmIdentifier (RFC 6211 uses IMPLICIT tags).
            fields.push(tlv(0xA1, sig));
        }
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        attribute(oid::CMS_ALGORITHM_PROTECTION, &[&seq(&refs)])
    };
    let cms_with = |attr: Vec<u8>| {
        sorted_cms(
            &signer,
            digest,
            vec![content_type.clone(), message_digest.clone(), attr],
        )
    };
    // Matching: valid (NULL digest parameters equal absent ones).
    for digest_alg in [
        alg_id(oid::SHA256),
        seq(&[&oid_der(oid::SHA256), &[0x05, 0x00]]),
    ] {
        let v = verify_over(&cms_with(protection(&digest_alg, Some(&rsa_sha256))), &data);
        assert_valid(&v, "matching protection");
    }
    // Wrong digest, wrong signature algorithm, or no signature algorithm: mismatch.
    let ecdsa = oid_der(oid::ECDSA_WITH_SHA256);
    for attr in [
        protection(&alg_id(oid::SHA512), Some(&rsa_sha256)),
        protection(&alg_id(oid::SHA256), Some(&ecdsa)),
        protection(&alg_id(oid::SHA256), None),
    ] {
        let v = verify_over(&cms_with(attr), &data);
        assert!(v.intact && !v.signature_valid, "{v:?}");
        assert_eq!(codes(&v), [ProblemCode::AlgorithmProtectionMismatch]);
    }
}

#[test]
fn verify_signing_cert_v2_mismatch() {
    let signer = pem_signer("p256");
    let digest = DigestAlgorithm::Sha256;
    let data = vector_data();
    let cert = signer.certificate_chain()[0].clone();
    let (content_type, message_digest) = basic_attributes(digest, &data);
    let (issuer, serial) = issuer_and_serial(&cert);
    let (_, other_serial) = issuer_and_serial(&cert_der("pki/signer-p384.pem"));
    let right_hash = octets(&DigestAlgorithm::Sha256.digest(&[&cert]));
    let wrong_hash = octets(&DigestAlgorithm::Sha256.digest(&[&cert_der("pki/intermediate.pem")]));
    let cms_with = |attrs: Vec<Vec<u8>>| {
        let mut all = vec![content_type.clone(), message_digest.clone()];
        all.extend(attrs);
        sorted_cms(&signer, digest, all)
    };

    // Matching: certHash alone, or with issuerSerial; SHA-384 certHash with its AlgId.
    for attrs in [
        vec![ess_v2(&[&right_hash])],
        vec![ess_v2(&[&right_hash, &issuer_serial(&issuer, &serial)])],
        vec![ess_v2(&[
            &alg_id(oid::SHA384),
            &octets(&DigestAlgorithm::Sha384.digest(&[&cert])),
        ])],
        // {id-sha256, NULL} is not the DER DEFAULT, but it names the same hash.
        vec![ess_v2(&[
            &seq(&[&oid_der(oid::SHA256), &[0x05, 0x00]]),
            &right_hash,
        ])],
    ] {
        let v = verify_over(&cms_with(attrs), &data);
        assert_valid(&v, "matching ESS");
        assert_eq!(v.pades_attrs.signing_certificate_v2, Some(true));
    }

    // Mismatches.
    let two_names = seq(&[&seq(&[&tlv(0xA4, &issuer), &tlv(0xA4, &issuer)]), &serial]);
    for attrs in [
        vec![ess_v2(&[&wrong_hash])],
        vec![ess_v2(&[
            &right_hash,
            &issuer_serial(&issuer, &other_serial),
        ])],
        vec![ess_v2(&[&right_hash, &two_names])],
        // A hash algorithm Folioxide does not implement (MD5).
        vec![ess_v2(&[&alg_id("1.2.840.113549.2.5"), &right_hash])],
        // Two signing-certificate-v2 attributes.
        vec![
            ess_v2(&[&right_hash]),
            ess_v2(&[&right_hash, &issuer_serial(&issuer, &serial)]),
        ],
    ] {
        let v = verify_over(&cms_with(attrs), &data);
        assert!(v.intact && !v.signature_valid, "{v:?}");
        assert_eq!(codes(&v), [ProblemCode::SigningCertificateMismatch]);
        assert_eq!(v.pades_attrs.signing_certificate_v2, Some(false));
    }

    // ESS v1 (SHA-1 certHash) is checked when there is no v2 (as pyHanko).
    let v1 = |hash: &[u8]| {
        attribute(
            oid::SIGNING_CERTIFICATE,
            &[&seq(&[&seq(&[&seq(&[&octets(hash)])])])],
        )
    };
    let v = verify_over(
        &cms_with(vec![v1(&DigestAlgorithm::Sha1.digest(&[&cert]))]),
        &data,
    );
    assert_valid(&v, "ESS v1");
    assert_eq!(v.pades_attrs.signing_certificate_v1, Some(true));
    assert!(!v.pades_attrs.is_baseline_b(), "v1 is not B-B");
    let v = verify_over(&cms_with(vec![v1(&[0u8; 20])]), &data);
    assert_eq!(codes(&v), [ProblemCode::SigningCertificateMismatch]);
}

#[test]
fn verify_content_type_and_message_digest_attributes() {
    let signer = pem_signer("rsa2048");
    let digest = DigestAlgorithm::Sha256;
    let data = vector_data();
    let (content_type, message_digest) = basic_attributes(digest, &data);
    let wrong_type = attribute(oid::CONTENT_TYPE, &[&oid_der(oid::ID_SIGNED_DATA)]);
    let two_values = attribute(
        oid::CONTENT_TYPE,
        &[&oid_der(oid::ID_DATA), &oid_der(oid::ID_DATA)],
    );
    let not_octets = attribute(oid::MESSAGE_DIGEST, &[&oid_der(oid::ID_DATA)]);
    for (attrs, code) in [
        (
            vec![message_digest.clone()],
            ProblemCode::ContentTypeMismatch,
        ),
        (
            vec![wrong_type, message_digest.clone()],
            ProblemCode::ContentTypeMismatch,
        ),
        (
            vec![two_values, message_digest.clone()],
            ProblemCode::ContentTypeMismatch,
        ),
        (
            vec![content_type.clone()],
            ProblemCode::MessageDigestMissing,
        ),
        (
            vec![content_type.clone(), not_octets],
            ProblemCode::MessageDigestMissing,
        ),
        (
            vec![
                content_type.clone(),
                message_digest.clone(),
                message_digest.clone(),
            ],
            ProblemCode::MessageDigestMissing,
        ),
    ] {
        let v = verify_over(&sorted_cms(&signer, digest, attrs), &data);
        assert!(!v.signature_valid, "{code:?}: {v:?}");
        assert!(codes(&v).contains(&code), "{code:?}: {v:?}");
    }
    // A signing-time attribute is reported (PAdES forbids it) but does not invalidate.
    let time = attribute(oid::SIGNING_TIME, &[&tlv(0x17, b"261010120000Z")]);
    let v = verify_over(
        &sorted_cms(&signer, digest, vec![content_type, message_digest, time]),
        &data,
    );
    assert_valid(&v, "signing-time");
    assert_eq!(
        v.pades_attrs.signing_time.as_deref(),
        Some("2026-10-10T12:00:00Z")
    );
}

#[test]
fn verify_structure_problems() {
    let data = vector_data();
    let signer = pem_signer("p256");
    let der = sign_cms(&signer, DigestAlgorithm::Sha256, &data);

    // Two SignerInfos, and none.
    let two = edit_signed_data(&der, |sd| {
        let last = sd.len() - 1;
        let si = der_split(&sd[last].1).1.to_vec();
        sd[last].1 = tlv(0x31, &[si.clone(), si].concat());
    });
    assert_eq!(
        codes(&verify_over(&two, &data)),
        [ProblemCode::SignerInfoCount]
    );
    let none = edit_signed_data(&der, |sd| {
        let last = sd.len() - 1;
        sd[last].1 = tlv(0x31, &[]);
    });
    assert_eq!(
        codes(&verify_over(&none, &data)),
        [ProblemCode::SignerInfoCount]
    );

    // Encapsulated content on a detached signature, and an eContentType other than id-data.
    let attached = edit_signed_data(&der, |sd| {
        sd[2].1 = seq(&[&oid_der(oid::ID_DATA), &tlv(0xA0, &octets(&data))]);
    });
    let v = verify_over(&attached, &data);
    assert!(!v.signature_valid);
    assert_eq!(codes(&v), [ProblemCode::EContentPresent]);
    let other_type = edit_signed_data(&der, |sd| {
        sd[2].1 = seq(&[&oid_der("1.2.840.113549.1.9.16.1.4")])
    });
    let v = verify_over(&other_type, &data);
    assert!(
        codes(&v).contains(&ProblemCode::ContentTypeMismatch),
        "{v:?}"
    );

    // No certificates: the signer is not found, unless it is passed in.
    let no_certs = edit_signed_data(&der, |sd| {
        sd.remove(3);
    });
    let parsed = cms::parse(&no_certs).unwrap();
    let digest_of = |d: DigestAlgorithm| Some(d.digest(&[&data]));
    let v = cms::verify_detached(&parsed, &digest_of, &[]);
    assert!(v.intact && !v.signature_valid);
    assert_eq!(codes(&v), [ProblemCode::SignerCertNotFound]);
    let v = cms::verify_detached(
        &parsed,
        &digest_of,
        &[
            cert_der("pki/root.pem"),
            signer.certificate_chain()[0].clone(),
        ],
    );
    assert_valid(&v, "signer from extra_certs");

    // A signature that does not verify.
    let tampered = edit_signer_info(&der, |si| {
        let (_, value) = der_split(&si[5].1);
        let mut value = value.to_vec();
        let at = value.len() - 3;
        value[at] ^= 1;
        si[5].1 = octets(&value);
    });
    let v = verify_over(&tampered, &data);
    assert!(v.intact && !v.signature_valid);
    assert_eq!(codes(&v), [ProblemCode::SignatureInvalid]);

    // Algorithms Folioxide does not implement.
    let ed25519 = edit_signer_info(&der, |si| si[4].1 = alg_id("1.3.101.112"));
    assert_eq!(
        codes(&verify_over(&ed25519, &data)),
        [ProblemCode::UnsupportedAlgorithm]
    );
    let md5 = edit_signer_info(&der, |si| si[2].1 = alg_id("1.2.840.113549.2.5"));
    let v = verify_over(&md5, &data);
    assert!(!v.intact && !v.signature_valid);
    assert!(
        codes(&v).contains(&ProblemCode::UnsupportedAlgorithm),
        "{v:?}"
    );

    // A signature algorithm of the wrong family for the key.
    let rsa_on_ec = edit_signer_info(&der, |si| {
        si[4].1 = seq(&[&oid_der(oid::SHA256_WITH_RSA), &[0x05, 0x00]])
    });
    let v = verify_over(&rsa_on_ec, &data);
    assert_eq!(codes(&v), [ProblemCode::SignatureInvalid]);

    // The digest of the content is not available: not intact, no problem of its own.
    let parsed = cms::parse(&der).unwrap();
    let v = cms::verify_detached(&parsed, &|_| None, &[]);
    assert!(!v.intact && v.signature_valid);
}

#[test]
fn verify_subject_key_identifier_sid() {
    let data = vector_data();
    let signer = pem_signer("p256");
    let der = sign_cms(&signer, DigestAlgorithm::Sha256, &data);
    // The signer certificate's subjectKeyIdentifier (gen-pki.sh: `subjectKeyIdentifier = hash`).
    let ski = {
        let cert = &signer.certificate_chain()[0];
        let marker = [0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14];
        let at = cert
            .windows(marker.len())
            .position(|w| w == marker)
            .unwrap()
            + marker.len();
        cert[at..at + 20].to_vec()
    };
    let with_ski = edit_signer_info(&der, |si| {
        si[0].1 = vec![0x02, 0x01, 0x03];
        si[1] = (0x80, tlv(0x80, &ski));
    });
    let parsed = cms::parse(&with_ski).unwrap();
    assert_eq!(parsed.signer_infos[0].version, 3);
    assert_eq!(
        parsed.signer_infos[0].sid,
        cms::SignerIdentifier::SubjectKeyIdentifier(ski.clone())
    );
    assert_valid(&verify_over(&with_ski, &data), "SKI sid");
    let unknown = edit_signer_info(&der, |si| si[1] = (0x80, tlv(0x80, &[0xAB; 20])));
    assert_eq!(
        codes(&verify_over(&unknown, &data)),
        [ProblemCode::SignerCertNotFound]
    );
}

#[test]
fn verify_without_signed_attributes() {
    let der = fixture("sign/openssl-rsa2048-noattr.p7s");
    let v = verify_over(&der, &vector_data());
    // pyHanko: with no signed attributes, intact = valid.
    assert_valid(&v, "no signed attributes");
    assert_eq!(v.pades_attrs, Default::default());
    let v = verify_over(&der, b"other content");
    assert!(!v.intact && !v.signature_valid);
    assert_eq!(codes(&v), [ProblemCode::SignatureInvalid]);
}

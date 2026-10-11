//! CMS parsing (M3 brief §4.3 "Parsing for verification", R-13, R-18, §6.2 "CMS parsing" and
//! "robustness"): BER, raw signed attributes, long serial numbers, limits, and no panics.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod cms_support;

use cms_support::{
    attribute, basic_attributes, cert_der, cms_with_attributes, fixture, octets, oid_der,
    pem_signer, seq, set, tlv, vector_data, verify_over,
};
use folioxide_sign::ProblemCode;
use folioxide_sign::algorithms::{DigestAlgorithm, oid};
use folioxide_sign::cms::{self, MAX_ATTRIBUTES, MAX_CERTIFICATES, SignerIdentifier};
use folioxide_sign::x509info;
use folioxide_syntax::ErrorCode;
use proptest::prelude::*;

#[test]
fn cms_parse_ber_indefinite() {
    // Detached, with indefinite lengths on every outer structure (tools/fixtures/sign.py).
    let ber = fixture("sign/ber-indefinite-p256.p7s");
    assert_eq!(ber[..2], [0x30, 0x80]);
    let parsed = cms::parse(&ber).unwrap();
    assert_eq!(parsed.raw, 0..ber.len());
    assert_eq!(parsed.econtent, None);
    assert_eq!(parsed.certificates.len(), 2);
    assert_eq!(parsed.signer_infos.len(), 1);
    let v = verify_over(&ber, &vector_data());
    assert!(v.intact && v.signature_valid, "{v:?}");
    // Same signer info as its DER source.
    let der = cms::parse(&fixture("sign/openssl-p256-cades.p7s")).unwrap();
    assert_eq!(
        der.signer_infos[0].signed_attrs,
        parsed.signer_infos[0].signed_attrs
    );
    assert_eq!(
        der.signer_infos[0].signature,
        parsed.signer_infos[0].signature
    );
    assert_eq!(der.certificates, parsed.certificates);

    // OpenSSL -stream: indefinite lengths and the content embedded as a constructed OCTET STRING.
    let attached = fixture("sign/openssl-p256-ber-attached.p7s");
    let parsed = cms::parse(&attached).unwrap();
    assert_eq!(parsed.econtent.as_deref(), Some(vector_data().as_slice()));
    let v = cms::verify_detached(&parsed, &|d| Some(d.digest(&[&vector_data()])), &[]);
    assert!(!v.signature_valid);
    assert!(
        v.problems
            .iter()
            .any(|p| p.code == ProblemCode::EContentPresent),
        "{v:?}"
    );
    // Trailing padding is not parsed.
    let mut padded = ber.clone();
    padded.extend([0u8; 100]);
    assert_eq!(cms::parse(&padded).unwrap().raw, 0..ber.len());
}

#[test]
fn cms_parse_keeps_unsorted_signed_attrs() {
    let signer = pem_signer("rsa2048");
    let digest = DigestAlgorithm::Sha256;
    let data = vector_data();
    let (content_type, message_digest) = basic_attributes(digest, &data);
    // message-digest (30 2f ...) sorts after content-type (30 18 ...); put it first.
    assert!(message_digest > content_type);
    let attrs = set(&[&message_digest, &content_type]);
    let der = cms_with_attributes(&signer, digest, &[&message_digest, &content_type]);
    let parsed = cms::parse(&der).unwrap();
    let raw = parsed.signer_infos[0].signed_attrs.clone().unwrap();
    // Byte for byte as found: re-encoding would re-sort the SET OF and break the signature.
    assert_eq!(raw[0], 0xA0);
    assert_eq!(raw[1..], attrs[1..]);
    let v = verify_over(&der, &data);
    assert!(v.intact && v.signature_valid, "{v:?}");
    assert!(
        v.warnings.iter().any(|w| w.contains("signedAttrs not DER")),
        "{:?}",
        v.warnings
    );
    // The sorted twin has no warning.
    let sorted = cms_with_attributes(&signer, digest, &[&content_type, &message_digest]);
    let v = verify_over(&sorted, &data);
    assert!(v.signature_valid && v.warnings.is_empty(), "{v:?}");
}

#[test]
fn cms_parse_serial_over_20_bytes() {
    let der = fixture("sign/openssl-long-serial.p7s");
    let parsed = cms::parse(&der).unwrap();
    let cert = cert_der("sign/long-serial.pem");
    assert_eq!(parsed.certificates, std::slice::from_ref(&cert));
    let SignerIdentifier::IssuerAndSerialNumber { serial, .. } = &parsed.signer_infos[0].sid else {
        panic!("expected IssuerAndSerialNumber");
    };
    // An INTEGER of 24 content octets (RFC 5280 §4.1.2.2 allows at most 20).
    assert_eq!(serial[..2], [0x02, 24]);
    let info = x509info::certificate_info(&cert).unwrap();
    assert_eq!(
        info.serial_hex,
        "0102030405060708090A0B0C0D0E0F101112131415161718"
    );
    let v = verify_over(&der, &vector_data());
    assert!(v.intact && v.signature_valid, "{v:?}");
    assert_eq!(v.signer_cert.as_deref(), Some(cert.as_slice()));
}

#[test]
fn cms_parse_depth_limited() {
    // 40 nested indefinite SEQUENCEs.
    let mut deep = Vec::new();
    for _ in 0..40 {
        deep.extend([0x30, 0x80]);
    }
    deep.extend([0u8; 80]);
    assert_eq!(
        cms::parse(&deep).unwrap_err().code(),
        ErrorCode::LimitExceeded
    );

    // Deep indefinite-length nesting inside an otherwise valid CMS (an extra entry of the
    // certificates SET): finding its end means walking it, which the depth limit bounds.
    // (Definite-length elements are skipped by their length and never walked.)
    let signer = pem_signer("p256");
    let der = cms_support::sign_cms(&signer, DigestAlgorithm::Sha256, &vector_data());
    let indefinite = |levels: usize| {
        let mut value = Vec::new();
        for _ in 0..levels {
            value.extend([0x30, 0x80]);
        }
        value.extend([0x05, 0x00]);
        value.extend(vec![0u8; 2 * levels]);
        value
    };
    let with_extra_certificate = |extra: Vec<u8>| {
        cms_support::edit_signed_data(&der, |sd| {
            let certs = cms_support::der_split(&sd[3].1).1.to_vec();
            sd[3] = (0xA0, tlv(0xA0, &[certs, extra].concat()));
        })
    };
    let deep_cms = with_extra_certificate(indefinite(40));
    assert_eq!(
        cms::parse(&deep_cms).unwrap_err().code(),
        ErrorCode::LimitExceeded
    );

    // Shallow enough: the same with 20 levels parses (and the odd entry is kept as given).
    let ok = with_extra_certificate(indefinite(20));
    let parsed = cms::parse(&ok).unwrap();
    assert_eq!(parsed.certificates.len(), 3);
}

#[test]
fn cms_parse_count_limits() {
    let signer = pem_signer("p256");
    let digest = DigestAlgorithm::Sha256;
    let data = vector_data();
    let der = cms_support::sign_cms(&signer, digest, &data);
    let cert = cert_der("pki/intermediate.pem");

    // Certificates: 64 parse, 65 do not.
    for (count, ok) in [(MAX_CERTIFICATES, true), (MAX_CERTIFICATES + 1, false)] {
        let certs: Vec<u8> = std::iter::repeat_n(cert.clone(), count).flatten().collect();
        let edited = cms_support::edit_signed_data(&der, |sd| sd[3] = (0xA0, tlv(0xA0, &certs)));
        let result = cms::parse(&edited);
        assert_eq!(result.is_ok(), ok, "{count} certificates");
        if !ok {
            assert_eq!(result.unwrap_err().code(), ErrorCode::LimitExceeded);
        }
    }

    // Attributes: 64 parse, 65 do not.
    let (content_type, message_digest) = basic_attributes(digest, &data);
    for (count, ok) in [(MAX_ATTRIBUTES, true), (MAX_ATTRIBUTES + 1, false)] {
        let filler = attribute("1.2.3.4", &[&[0x05, 0x00]]);
        let mut attrs: Vec<&[u8]> = vec![&content_type, &message_digest];
        for _ in 2..count {
            attrs.push(&filler);
        }
        let edited = cms_with_attributes(&signer, digest, &attrs);
        let result = cms::parse(&edited);
        assert_eq!(result.is_ok(), ok, "{count} attributes");
        if !ok {
            assert_eq!(result.unwrap_err().code(), ErrorCode::LimitExceeded);
        }
    }
}

#[test]
fn cms_parse_rejects_malformed_structures() {
    let signer = pem_signer("p256");
    let der = cms_support::sign_cms(&signer, DigestAlgorithm::Sha256, &vector_data());
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"garbage".to_vec(),
        der[..der.len() / 2].to_vec(),
        // ContentInfo without content.
        seq(&[&oid_der(oid::ID_SIGNED_DATA)]),
        // SignedData without signerInfos.
        cms_support::edit_signed_data(&der, |sd| {
            sd.pop();
        }),
        // A SignerInfo field of the wrong type.
        cms_support::edit_signer_info(&der, |si| si[0] = (0x04, octets(&[1]))),
        // An attribute that is not SEQUENCE { OID, SET }.
        cms_support::edit_signer_info(&der, |si| si[3] = (0xA0, tlv(0xA0, &octets(b"x")))),
        // An extra element after the signature.
        cms_support::edit_signer_info(&der, |si| si.push((0x05, vec![0x05, 0x00]))),
    ];
    for (i, bytes) in cases.iter().enumerate() {
        let err = cms::parse(bytes).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Syntax, "case {i}: {err}");
    }
}

#[test]
fn cms_parse_foreign_vectors() {
    for (name, signers, certs) in [
        ("openssl-rsa2048-sha256.p7s", 1, 2),
        ("openssl-p384-sha384.p7s", 1, 2),
        ("openssl-rsa2048-pss.p7s", 1, 2),
        ("openssl-rsa2048-noattr.p7s", 1, 2),
        ("pyhanko-rsa2048.p7s", 1, 2),
        ("pyhanko-p256.p7s", 1, 2),
        ("pyhanko-p384-sha384.p7s", 1, 2),
        ("pyhanko-rsa3072-pss.p7s", 1, 2),
    ] {
        let der = fixture(&format!("sign/{name}"));
        let parsed = cms::parse(&der).unwrap();
        assert_eq!(parsed.content_type, oid::ID_SIGNED_DATA, "{name}");
        assert_eq!(
            parsed.econtent_type.as_deref(),
            Some(oid::ID_DATA),
            "{name}"
        );
        assert_eq!(parsed.signer_infos.len(), signers, "{name}");
        assert_eq!(parsed.certificates.len(), certs, "{name}");
        assert_eq!(parsed.raw, 0..der.len());
        let info = &parsed.signer_infos[0];
        assert!(info.raw.end <= der.len() && info.raw.start < info.raw.end);
        assert_eq!(
            info.signed_attrs.is_none(),
            name.contains("noattr"),
            "{name}"
        );
    }
}

/// A few valid CMS blobs for the mutation strategy.
fn seeds() -> Vec<Vec<u8>> {
    vec![
        cms_support::sign_cms(&pem_signer("p256"), DigestAlgorithm::Sha256, b"seed"),
        fixture("sign/ber-indefinite-p256.p7s"),
        fixture("sign/openssl-rsa2048-pss.p7s"),
        fixture("sign/openssl-p256-ber-attached.p7s"),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, failure_persistence: None, ..ProptestConfig::default() })]

    /// Mutated and random inputs never panic `parse`, and whatever parses never panics
    /// `verify_detached` (brief §6.2 robustness, R-18).
    #[test]
    fn cms_parse_never_panics(
        seed in 0usize..5,
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>(), 0u8..4), 1..8),
        random in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let seeds = SEEDS.with(Clone::clone);
        let mut bytes = if seed < seeds.len() { seeds[seed].clone() } else { random };
        for (index, value, kind) in edits {
            if bytes.is_empty() {
                bytes.push(value);
                continue;
            }
            let at = index.index(bytes.len());
            match kind {
                0 => bytes[at] = value,
                1 => bytes[at] ^= 0x80,
                2 => { bytes.truncate(at); }
                _ => { bytes.insert(at, value); }
            }
        }
        if let Ok(parsed) = cms::parse(&bytes) {
            let _ = cms::verify_detached(&parsed, &|d| Some(d.digest(&[b"seed"])), &[]);
        }
    }
}

thread_local! {
    static SEEDS: Vec<Vec<u8>> = seeds();
}

#[test]
fn not_signed_data_parses_without_signers() {
    let ci = seq(&[&oid_der(oid::ID_DATA), &tlv(0xA0, &octets(b"x"))]);
    let parsed = cms::parse(&ci).unwrap();
    assert_eq!(parsed.content_type, oid::ID_DATA);
    assert!(parsed.signer_infos.is_empty());
    let v = cms::verify_detached(&parsed, &|_| None, &[]);
    assert_eq!(v.problems[0].code, ProblemCode::NotSignedData);
}

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The CMS additions of M4 (brief §3.1, §4.3, §4.4; §6.2 "CMS"): the signature timestamp
//! unsigned attribute, its sizing, BER tokens, and encapsulated-content verification of
//! timestamp tokens.

mod bt_support;

use bt_support::*;
use folioxide_sign::ProblemCode;
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::cms::{self, SignedAttrsInput};
use folioxide_sign::prepare::SignatureOptions;
use folioxide_sign::report::PadesLevel;
use folioxide_sign::signer::{LocalSigner, Signer};
use folioxide_sign::tsp::{self, MessageImprint, OID_CT_TST_INFO, TimeStampReq, Timestamper};
use folioxide_testkit::tsa::{Ess, MockTsaOptions};

/// The signed attributes for a document digest of `fill` bytes, and `signer`'s value over them.
fn signed(signer: &LocalSigner) -> (Vec<u8>, Vec<u8>) {
    let digest = DigestAlgorithm::Sha256;
    let attrs = cms::build_signed_attrs(&SignedAttrsInput {
        digest,
        document_digest: &[7; 32],
        signer_cert_der: &signer.certificate_chain()[0],
    })
    .unwrap();
    let value = signer.sign(digest, &attrs).unwrap();
    (attrs, value)
}

/// A mock token over `value` (SHA-256 imprint, nonce [`NONCE`]).
fn token_over(value: &[u8]) -> Vec<u8> {
    let digest = DigestAlgorithm::Sha256;
    let request = TimeStampReq::new(
        MessageImprint::new(digest, digest.digest(&[value])),
        Some(NONCE),
        None,
    );
    mock_tsa().token_for(&request.to_der()).unwrap()
}

/// `token` with its outer ContentInfo re-encoded with an indefinite length (BER).
fn ber(token: &[u8]) -> Vec<u8> {
    let element = cms::parse(token).unwrap();
    assert_eq!(element.raw, 0..token.len());
    // The content after the outer header: a short or long definite length.
    let header = if token[1] < 0x80 {
        2
    } else {
        2 + usize::from(token[1] & 0x7F)
    };
    [&[0x30, 0x80][..], &token[header..], &[0x00, 0x00]].concat()
}

#[test]
fn cms_assemble_with_timestamp_keeps_signed_attrs_and_signature() {
    for signer in [rsa2048(), p256()] {
        let (attrs, value) = signed(&signer);
        let (alg, kind, digest) = (
            signer.algorithm(),
            signer.key_kind(),
            DigestAlgorithm::Sha256,
        );
        let chain = signer.certificate_chain();
        let plain = cms::assemble(&attrs, &value, chain, alg, kind, digest).unwrap();
        let token = token_over(&value);
        let stamped =
            cms::assemble_with_timestamp(&attrs, &value, chain, alg, kind, digest, &token).unwrap();
        let (a, b) = (cms::parse(&plain).unwrap(), cms::parse(&stamped).unwrap());
        let (sa, sb) = (&a.signer_infos[0], &b.signer_infos[0]);
        assert_eq!(sa.signed_attrs, sb.signed_attrs);
        assert_eq!(sa.signature, sb.signature);
        assert_eq!(sa.sid, sb.sid);
        assert_eq!(a.certificates, b.certificates);
        assert_eq!(sa.unsigned_attrs, None);
        // A1 L { 30 L { 06 0B <id-aa-signatureTimeStampToken>, 31 L { token } } }
        let unsigned = sb.unsigned_attrs.as_deref().unwrap();
        assert_eq!(unsigned[0], 0xA1);
        let oid = [
            0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
        ];
        assert!(unsigned.windows(oid.len()).any(|w| w == oid));
        assert!(unsigned.ends_with(&token), "the token, byte for byte, last");
        assert_eq!(
            cms::signature_timestamp_tokens(sb),
            std::slice::from_ref(&token)
        );
        // The attribute was added; only the five enclosing lengths grew (SignerInfo,
        // signerInfos, SignedData, [0], ContentInfo: at most 2 octets each here).
        let grown = stamped.len() - plain.len();
        assert!(
            grown >= unsigned.len() && grown <= unsigned.len() + 10,
            "{grown} for {}",
            unsigned.len()
        );
        // Both verify, with the signature unchanged; the token verifies over the value.
        for parsed in [&a, &b] {
            let v = cms::verify_detached(parsed, &|_| Some(vec![7; 32]), &[]);
            assert!(v.intact && v.signature_valid, "{:?}", v.problems);
            assert!(v.pades_attrs.is_baseline_b());
        }
        let v = tsp::verify_token(&token, &|d| Some(d.digest(&[&sb.signature])), &[]);
        assert!(v.intact && v.valid, "{v:?}");
        // A token that is not one SEQUENCE is refused.
        for bad in [&b""[..], b"\x04\x01\x00", &token[..token.len() - 1]] {
            let err = cms::assemble_with_timestamp(&attrs, &value, chain, alg, kind, digest, bad)
                .unwrap_err();
            assert_eq!(
                err.code(),
                folioxide_syntax::ErrorCode::InvalidArgument,
                "{err}"
            );
        }
    }
}

#[test]
fn cms_len_upper_bound_with_timestamp_is_tight() {
    for signer in [rsa2048(), p256(), p384()] {
        let digest = if signer.key_kind() == folioxide_sign::algorithms::KeyKind::EcP384 {
            DigestAlgorithm::Sha384
        } else {
            DigestAlgorithm::Sha256
        };
        let attrs = cms::build_signed_attrs(&SignedAttrsInput {
            digest,
            document_digest: &vec![7; digest.output_len()],
            signer_cert_der: &signer.certificate_chain()[0],
        })
        .unwrap();
        let value = signer.sign(digest, &attrs).unwrap();
        let (alg, kind, chain) = (
            signer.algorithm(),
            signer.key_kind(),
            signer.certificate_chain(),
        );
        assert_eq!(
            cms::cms_len_upper_bound_with_timestamp(&attrs, chain, alg, kind, digest, 0).unwrap(),
            cms::cms_len_upper_bound(&attrs, chain, alg, kind, digest).unwrap()
        );
        for token_len in [
            2usize, 100, 127, 128, 200, 255, 256, 3131, 8192, 65_535, 70_000,
        ] {
            // A "token" of exactly token_len bytes: one SEQUENCE.
            let header = if token_len - 2 < 0x80 {
                2
            } else if token_len - 3 < 0x100 {
                3
            } else if token_len - 4 < 0x1_0000 {
                4
            } else {
                5
            };
            let content = token_len - header;
            let mut token = vec![0x30];
            match header {
                2 => token.push(content as u8),
                3 => token.extend([0x81, content as u8]),
                4 => token.extend([0x82, (content >> 8) as u8, content as u8]),
                _ => token.extend([
                    0x83,
                    (content >> 16) as u8,
                    (content >> 8) as u8,
                    content as u8,
                ]),
            }
            token.resize(token_len, 0);
            let bound = cms::cms_len_upper_bound_with_timestamp(
                &attrs, chain, alg, kind, digest, token_len,
            )
            .unwrap();
            let real =
                cms::assemble_with_timestamp(&attrs, &value, chain, alg, kind, digest, &token)
                    .unwrap()
                    .len();
            if kind.p1363_len().is_none() {
                assert_eq!(bound, real, "RSA exact, token {token_len}");
            } else {
                assert!(
                    bound >= real && bound <= real + 3,
                    "{kind:?} token {token_len}: bound {bound}, real {real}"
                );
            }
        }
    }
}

/// A timestamper whose tokens are BER (the mock's, re-encoded with an indefinite outer length).
struct BerTsa;

impl Timestamper for BerTsa {
    fn timestamp(&self, request: &[u8]) -> folioxide_sign::Result<Vec<u8>> {
        let token = ber(&mock_tsa().token_for(request).unwrap());
        let status = [0x30, 0x03, 0x02, 0x01, 0x00];
        let len = status.len() + token.len();
        let mut response = vec![0x30, 0x82, (len >> 8) as u8, len as u8];
        response.extend(status);
        response.extend(token);
        Ok(response)
    }
}

#[test]
fn cms_ber_token_embedded_verbatim_with_warning() {
    let digest = DigestAlgorithm::Sha256;
    let request = TimeStampReq::new(
        MessageImprint::new(digest, digest.digest(&[b"value"])),
        Some(NONCE),
        None,
    );
    let response = BerTsa.timestamp(&request.to_der()).unwrap();
    let validated = tsp::validate_response(&request, &response).unwrap();
    assert_eq!(&validated.token_der[..2], [0x30, 0x80]);
    assert!(
        validated.warnings.iter().any(|w| w.contains("BER")),
        "{:?}",
        validated.warnings
    );
    let v = tsp::verify_token(&validated.token_der, &|d| Some(d.digest(&[b"value"])), &[]);
    assert!(v.intact && v.valid, "{v:?}");
    assert!(
        v.warnings.iter().any(|w| w.contains("BER")),
        "{:?}",
        v.warnings
    );

    // Signed B-T with it: embedded verbatim, and the CMS around it still counts as DER for
    // PAdES (the token is opaque, D-12).
    let signer = p256();
    let signed = sign_bt_with(&minimal(), &signer, SignatureOptions::new(time()), &BerTsa).unwrap();
    let r = &verify(&signed)[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.pades_level, Some(PadesLevel::BT), "{}", summary(r));
    let ts = r.timestamp.as_ref().unwrap();
    assert!(ts.intact && ts.valid && ts.trusted == Some(true), "{ts:?}");
    assert!(ts.warnings.iter().any(|w| w.contains("BER")), "{ts:?}");
    let hex_token = hex(&ber(&mock_tsa().token_for(&request.to_der()).unwrap())[..2]);
    assert_eq!(hex_token, "3080");
    assert!(
        String::from_utf8_lossy(&signed).contains("A1"),
        "the unsigned attribute"
    );
}

#[test]
fn verify_encapsulated_tst_info() {
    let token = token_over(b"value");
    let parsed = cms::parse(&token).unwrap();
    let v = cms::verify_encapsulated(&parsed, OID_CT_TST_INFO, &[]);
    assert!(v.intact && v.signature_valid, "{:?}", v.problems);
    assert_eq!(v.signer_cert.as_deref(), Some(cert("tsa.pem").as_slice()));
    assert_eq!(v.pades_attrs.signing_certificate_v2, Some(true));
    assert_eq!(v.pades_attrs.content_type.as_deref(), Some(OID_CT_TST_INFO));
    assert_eq!(v.digest, Some(DigestAlgorithm::Sha256));
    assert_eq!(
        v.signature_algorithm.as_deref(),
        Some("sha256WithRSAEncryption")
    );
    assert!(v.problems.is_empty());

    // Another expected eContentType.
    let v = cms::verify_encapsulated(&parsed, "1.2.840.113549.1.7.1", &[]);
    assert!(!v.signature_valid);
    assert!(
        v.problems
            .iter()
            .any(|p| p.code == ProblemCode::ContentTypeMismatch)
    );

    // A changed TSTInfo: the message digest no longer matches (not intact).
    let mut changed = parsed.clone();
    let mut econtent = changed.econtent.take().unwrap();
    let last = econtent.len() - 1;
    econtent[last] ^= 1;
    changed.econtent = Some(econtent);
    let v = cms::verify_encapsulated(&changed, OID_CT_TST_INFO, &[]);
    assert!(!v.intact, "{v:?}");
    // No eContent.
    let mut detached = parsed.clone();
    detached.econtent = None;
    let v = cms::verify_encapsulated(&detached, OID_CT_TST_INFO, &[]);
    assert!(!v.intact && !v.signature_valid);
    assert!(
        v.problems
            .iter()
            .any(|p| p.code == ProblemCode::CmsMalformed)
    );

    // A wrong ESS certHash is reported, not a signature failure (the caller decides).
    let wrong = mock_tsa_with(
        "tsa.pem",
        MockTsaOptions {
            ess: Ess::WrongHash,
            ..MockTsaOptions::default()
        },
    );
    let digest = DigestAlgorithm::Sha256;
    let request = TimeStampReq::new(
        MessageImprint::new(digest, digest.digest(&[b"value"])),
        Some(NONCE),
        None,
    );
    let token = wrong.token_for(&request.to_der()).unwrap();
    let v = cms::verify_encapsulated(&cms::parse(&token).unwrap(), OID_CT_TST_INFO, &[]);
    assert!(v.intact && v.signature_valid);
    assert_eq!(v.pades_attrs.signing_certificate_v2, Some(false));
    // ESS v1 is reported in its own field.
    let v1 = mock_tsa_with(
        "tsa.pem",
        MockTsaOptions {
            ess: Ess::V1,
            ..MockTsaOptions::default()
        },
    );
    let token = v1.token_for(&request.to_der()).unwrap();
    let v = cms::verify_encapsulated(&cms::parse(&token).unwrap(), OID_CT_TST_INFO, &[]);
    assert!(v.intact && v.signature_valid);
    assert_eq!(
        (
            v.pades_attrs.signing_certificate_v1,
            v.pades_attrs.signing_certificate_v2
        ),
        (Some(true), None)
    );

    // Without certificates in the token, the signer comes from the extra certificates.
    let bare = mock_tsa_with(
        "tsa.pem",
        MockTsaOptions {
            include_certs: false,
            ..MockTsaOptions::default()
        },
    );
    let token = bare.token_for(&request.to_der()).unwrap();
    let parsed = cms::parse(&token).unwrap();
    assert!(!cms::verify_encapsulated(&parsed, OID_CT_TST_INFO, &[]).signature_valid);
    let v = cms::verify_encapsulated(&parsed, OID_CT_TST_INFO, &[cert("tsa.pem")]);
    assert!(v.intact && v.signature_valid, "{:?}", v.problems);

    // A token is not a detached signature.
    let v = cms::verify_detached(&parsed, &|_| None, &[cert("tsa.pem")]);
    assert!(!v.signature_valid);
    assert!(
        v.problems
            .iter()
            .any(|p| p.code == ProblemCode::EContentPresent)
    );
}

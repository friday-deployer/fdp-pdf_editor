//! Building the PAdES signed attributes and assembling `ContentInfo(SignedData)` (M3 brief §4.3).
//!
//! The signed attributes are encoded with `der` 0.8 types, so the `SET OF` is DER-sorted by
//! `SetOfVec` and the ESSCertIDv2 `hashAlgorithm` DEFAULT is omitted by `der_derive`. The outer
//! `SignedData` is written by hand with [`tlv`] because the certificates and the `sid` must be
//! the input bytes, never re-encoded.

use const_oid::ObjectIdentifier;
use der::asn1::{Any, OctetString, SetOfVec};
use der::{Decode as _, Encode as _, Sequence};
use spki::AlgorithmIdentifierRef;
use x509_cert::attr::Attribute;

use super::SignedAttrsInput;
use super::tlv::{
    self, TAG_CONTEXT_0, TAG_CONTEXT_4, TAG_INTEGER, TAG_NULL, TAG_OCTET_STRING, TAG_OID,
    TAG_SEQUENCE, TAG_SET,
};
use crate::algorithms::{
    DigestAlgorithm, KeyKind, SignatureAlgorithm, check_signing_combination, oid,
};
use crate::error::{Error, Result};
use crate::keys::public::{ecdsa_der_from_fixed, ecdsa_der_to_fixed, rsa_left_pad};
use crate::x509info::cert::CertParts;

/// `ESSCertIDv2` (RFC 5035 §4):
///
/// ```text
/// ESSCertIDv2 ::= SEQUENCE {
///     hashAlgorithm  AlgorithmIdentifier DEFAULT {algorithm id-sha256},
///     certHash       Hash,
///     issuerSerial   IssuerSerial OPTIONAL }
/// ```
///
/// The DEFAULT is `{id-sha256}` with **absent** parameters: `der_derive` omits a field equal to
/// its default (X.690 §11.5), while `{id-sha256, NULL}` is a different value and is encoded.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub(crate) struct EssCertIdV2<'a> {
    #[asn1(default = "sha256_algorithm_identifier")]
    pub hash_algorithm: AlgorithmIdentifierRef<'a>,
    pub cert_hash: OctetString,
    /// The DER of `IssuerSerial`, written by hand from the certificate's raw issuer and serial.
    pub issuer_serial: Option<Any>,
}

/// `SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, policies ... OPTIONAL }`
/// (RFC 5035 §3); Folioxide writes no policies.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub(crate) struct SigningCertificateV2<'a> {
    pub certs: Vec<EssCertIdV2<'a>>,
}

/// The DEFAULT `hashAlgorithm` of ESSCertIDv2: `{id-sha256}`, parameters absent.
pub(crate) fn sha256_algorithm_identifier<'a>() -> AlgorithmIdentifierRef<'a> {
    AlgorithmIdentifierRef {
        oid: OID_SHA256,
        parameters: None,
    }
}

const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::SHA1);
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::SHA256);
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::SHA384);
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::SHA512);
const OID_ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::ID_DATA);
const OID_ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::ID_SIGNED_DATA);
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::CONTENT_TYPE);
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::MESSAGE_DIGEST);
const OID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap(oid::SIGNING_CERTIFICATE_V2);
const OID_SHA1_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::SHA1_WITH_RSA);
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::SHA256_WITH_RSA);
const OID_SHA384_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::SHA384_WITH_RSA);
const OID_SHA512_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::SHA512_WITH_RSA);
const OID_ECDSA_WITH_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::ECDSA_WITH_SHA1);
const OID_ECDSA_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap(oid::ECDSA_WITH_SHA256);
const OID_ECDSA_WITH_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap(oid::ECDSA_WITH_SHA384);
const OID_ECDSA_WITH_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap(oid::ECDSA_WITH_SHA512);

/// The `ObjectIdentifier` of a CMS signatureAlgorithm (RFC 4055 §5, RFC 5758 §3.2).
fn signature_oid(alg: SignatureAlgorithm, digest: DigestAlgorithm) -> ObjectIdentifier {
    match (alg, digest) {
        (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha256) => OID_SHA256_WITH_RSA,
        (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha384) => OID_SHA384_WITH_RSA,
        (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha512) => OID_SHA512_WITH_RSA,
        (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha1) => OID_SHA1_WITH_RSA,
        (SignatureAlgorithm::Ecdsa, DigestAlgorithm::Sha256) => OID_ECDSA_WITH_SHA256,
        (SignatureAlgorithm::Ecdsa, DigestAlgorithm::Sha384) => OID_ECDSA_WITH_SHA384,
        (SignatureAlgorithm::Ecdsa, DigestAlgorithm::Sha512) => OID_ECDSA_WITH_SHA512,
        (SignatureAlgorithm::Ecdsa, DigestAlgorithm::Sha1) => OID_ECDSA_WITH_SHA1,
    }
}

/// The `ObjectIdentifier` of a digest.
pub(crate) fn digest_oid(digest: DigestAlgorithm) -> ObjectIdentifier {
    match digest {
        DigestAlgorithm::Sha256 => OID_SHA256,
        DigestAlgorithm::Sha384 => OID_SHA384,
        DigestAlgorithm::Sha512 => OID_SHA512,
        DigestAlgorithm::Sha1 => OID_SHA1,
    }
}

/// See [`super::build_signed_attrs`].
pub(crate) fn build_signed_attrs(input: &SignedAttrsInput<'_>) -> Result<Vec<u8>> {
    let digest = input.digest;
    if digest.is_weak() {
        return Err(Error::InvalidArgument(format!(
            "{digest} is not allowed for signing; use sha256, sha384 or sha512"
        )));
    }
    if input.document_digest.len() != digest.output_len() {
        return Err(Error::InvalidArgument(format!(
            "the document digest has {} bytes; {digest} digests have {}",
            input.document_digest.len(),
            digest.output_len()
        )));
    }
    let signer = CertParts::parse(input.signer_cert_der)?;

    // IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber CertificateSerialNumber }
    // (RFC 5035 §4), GeneralNames = SEQUENCE OF GeneralName, directoryName [4] Name: EXPLICIT,
    // because Name is a CHOICE (X.680 §31.2.7; RFC 5280 §4.2.1.6).
    let directory_name = tlv::tlv(TAG_CONTEXT_4, signer.issuer);
    let general_names = tlv::tlv(TAG_SEQUENCE, &directory_name);
    let issuer_serial = tlv::tlv_parts(TAG_SEQUENCE, &[&general_names, signer.serial]);

    let cert_id = EssCertIdV2 {
        hash_algorithm: AlgorithmIdentifierRef {
            oid: digest_oid(digest),
            parameters: None,
        },
        cert_hash: octet_string(digest.digest(&[input.signer_cert_der]))?,
        issuer_serial: Some(any(&issuer_serial)?),
    };
    let signing_certificate = SigningCertificateV2 {
        certs: vec![cert_id],
    }
    .to_der()
    .map_err(encoding_error)?;

    let attributes = vec![
        attribute(
            OID_CONTENT_TYPE,
            &OID_ID_DATA.to_der().map_err(encoding_error)?,
        )?,
        attribute(
            OID_MESSAGE_DIGEST,
            &octet_string(input.document_digest.to_vec())?
                .to_der()
                .map_err(encoding_error)?,
        )?,
        attribute(OID_SIGNING_CERTIFICATE_V2, &signing_certificate)?,
    ];
    // `SetOfVec::try_from` sorts the encodings (X.690 §11.6; der 0.8.2 `der_sort`). Never sort
    // by hand: the order depends on the lengths (brief §4.3).
    SetOfVec::try_from(attributes)
        .and_then(|set| set.to_der())
        .map_err(encoding_error)
}

fn attribute(oid: ObjectIdentifier, value_der: &[u8]) -> Result<Attribute> {
    let values = SetOfVec::try_from(vec![any(value_der)?]).map_err(encoding_error)?;
    Ok(Attribute { oid, values })
}

fn any(der: &[u8]) -> Result<Any> {
    Any::from_der(der).map_err(encoding_error)
}

fn octet_string(bytes: Vec<u8>) -> Result<OctetString> {
    OctetString::new(bytes).map_err(encoding_error)
}

fn encoding_error(err: der::Error) -> Error {
    Error::Crypto(format!("DER encoding failed: {err}"))
}

/// The checked inputs of [`assemble`] and [`cms_len_upper_bound`].
struct Inputs<'a> {
    signer: CertParts<'a>,
}

fn check_inputs<'a>(
    signed_attrs: &[u8],
    chain_der: &'a [Vec<u8>],
    alg: SignatureAlgorithm,
    kind: KeyKind,
    digest: DigestAlgorithm,
) -> Result<Inputs<'a>> {
    if kind.algorithm() != alg {
        return Err(Error::InvalidArgument(format!(
            "a {kind:?} key cannot make {alg} signatures"
        )));
    }
    check_signing_combination(kind, digest)?;
    let attrs = tlv::read_exact(signed_attrs, super::MAX_DEPTH).map_err(|e| {
        Error::InvalidArgument(format!(
            "the signed attributes are not one DER element: {e}"
        ))
    })?;
    if attrs.tag != TAG_SET || attrs.indefinite {
        return Err(Error::InvalidArgument(
            "the signed attributes must be a DER SET (first byte 0x31)".into(),
        ));
    }
    let leaf = chain_der
        .first()
        .ok_or_else(|| Error::InvalidArgument("the certificate chain is empty".into()))?;
    let signer = CertParts::parse(leaf)?;
    for (index, cert) in chain_der.iter().enumerate().skip(1) {
        match tlv::read_exact(cert, super::MAX_DEPTH) {
            Ok(element) if element.tag == TAG_SEQUENCE => {}
            _ => {
                return Err(Error::Certificate(format!(
                    "certificate {index} of the chain is not one DER SEQUENCE"
                )));
            }
        }
    }
    Ok(Inputs { signer })
}

/// See [`super::cms_len_upper_bound`].
pub(crate) fn cms_len_upper_bound(
    signed_attrs: &[u8],
    chain_der: &[Vec<u8>],
    alg: SignatureAlgorithm,
    kind: KeyKind,
    digest: DigestAlgorithm,
) -> Result<usize> {
    let inputs = check_inputs(signed_attrs, chain_der, alg, kind, digest)?;
    let longest = vec![0u8; kind.max_signature_len()];
    Ok(encode(
        signed_attrs,
        &longest,
        chain_der,
        alg,
        digest,
        &inputs.signer,
    )
    .len())
}

/// See [`super::assemble`].
pub(crate) fn assemble(
    signed_attrs: &[u8],
    signature: &[u8],
    chain_der: &[Vec<u8>],
    alg: SignatureAlgorithm,
    kind: KeyKind,
    digest: DigestAlgorithm,
) -> Result<Vec<u8>> {
    let inputs = check_inputs(signed_attrs, chain_der, alg, kind, digest)?;
    let value = normalize_signature(signature, kind)?;
    Ok(encode(
        signed_attrs,
        &value,
        chain_der,
        alg,
        digest,
        &inputs.signer,
    ))
}

/// The signature value to embed (brief §4.3 "Normalisation"):
///
/// - RSA: left-padded with zeros to the modulus length; longer is invalid.
/// - ECDSA: a DER `ECDSA-Sig-Value` consuming every byte, re-encoded minimally; else IEEE P1363
///   `r || s` of exactly twice the field size; else invalid.
pub(crate) fn normalize_signature(signature: &[u8], kind: KeyKind) -> Result<Vec<u8>> {
    match kind.p1363_len() {
        None => rsa_left_pad(signature, kind.max_signature_len()).ok_or_else(|| {
            Error::SignatureInvalid(format!(
                "the RSA signature has {} bytes; the modulus has {}",
                signature.len(),
                kind.max_signature_len()
            ))
        }),
        Some(p1363) => {
            let field = p1363 / 2;
            if let Some(fixed) = ecdsa_der_to_fixed(signature, field) {
                Ok(ecdsa_der_from_fixed(&fixed, field))
            } else if signature.len() == p1363 {
                Ok(ecdsa_der_from_fixed(signature, field))
            } else {
                Err(Error::SignatureInvalid(format!(
                    "the ECDSA signature ({} bytes) is neither DER nor IEEE P1363 ({p1363} bytes)",
                    signature.len()
                )))
            }
        }
    }
}

/// Writes `ContentInfo(SignedData)` (RFC 5652 §3, §5.1, §5.3; brief §4.3):
///
/// ```text
/// ContentInfo ::= SEQUENCE { id-signedData, [0] EXPLICIT SignedData }
/// SignedData  ::= SEQUENCE { version 1, digestAlgorithms SET { digestAlgorithm },
///                            encapContentInfo { id-data }, certificates [0] IMPLICIT, signerInfos SET }
/// SignerInfo  ::= SEQUENCE { version 1, sid IssuerAndSerialNumber, digestAlgorithm,
///                            signedAttrs [0] IMPLICIT, signatureAlgorithm, signature OCTET STRING }
/// ```
fn encode(
    signed_attrs: &[u8],
    signature: &[u8],
    chain_der: &[Vec<u8>],
    alg: SignatureAlgorithm,
    digest: DigestAlgorithm,
    signer: &CertParts<'_>,
) -> Vec<u8> {
    let version_1 = [TAG_INTEGER, 0x01, 0x01];
    // RFC 5754 §2: SHA-2 AlgorithmIdentifiers omit the parameters.
    let digest_algorithm = tlv::tlv(
        TAG_SEQUENCE,
        &tlv::tlv(TAG_OID, digest_oid(digest).as_bytes()),
    );
    let signature_oid = signature_oid(alg, digest);
    let signature_algorithm = match alg {
        // RFC 4055 §5: sha*WithRSAEncryption carries NULL parameters.
        SignatureAlgorithm::RsaPkcs1v15 => tlv::tlv_parts(
            TAG_SEQUENCE,
            &[
                &tlv::tlv(TAG_OID, signature_oid.as_bytes()),
                &[TAG_NULL, 0x00],
            ],
        ),
        // RFC 5758 §3.2: ecdsa-with-SHA* omits the parameters.
        SignatureAlgorithm::Ecdsa => {
            tlv::tlv(TAG_SEQUENCE, &tlv::tlv(TAG_OID, signature_oid.as_bytes()))
        }
    };
    // IssuerAndSerialNumber with the certificate's raw issuer and serial (never re-encoded),
    // and SignerInfo version 1 (RFC 5652 §5.3).
    let sid = tlv::tlv_parts(TAG_SEQUENCE, &[signer.issuer, signer.serial]);
    // RFC 5652 §5.4: inside SignerInfo the attributes carry the [0] IMPLICIT tag; the length
    // and content octets are those of the 0x31-tagged bytes that were signed.
    let mut implicit_attrs = signed_attrs.to_vec();
    if let Some(first) = implicit_attrs.first_mut() {
        *first = TAG_CONTEXT_0;
    }
    let signer_info = tlv::tlv_parts(
        TAG_SEQUENCE,
        &[
            &version_1,
            &sid,
            &digest_algorithm,
            &implicit_attrs,
            &signature_algorithm,
            &tlv::tlv(TAG_OCTET_STRING, signature),
        ],
    );

    // certificates [0] IMPLICIT SET OF: the input bytes, DER-sorted (X.690 §11.6).
    let mut certificates: Vec<&[u8]> = chain_der.iter().map(Vec::as_slice).collect();
    certificates.sort_by(|a, b| tlv::der_set_order(a, b));
    let encap_content_info = tlv::tlv(TAG_SEQUENCE, &tlv::tlv(TAG_OID, OID_ID_DATA.as_bytes()));
    let signed_data = tlv::tlv_parts(
        TAG_SEQUENCE,
        &[
            &version_1,
            &tlv::tlv(TAG_SET, &digest_algorithm),
            &encap_content_info,
            &tlv::tlv_parts(TAG_CONTEXT_0, &certificates),
            &tlv::tlv(TAG_SET, &signer_info),
        ],
    );
    tlv::tlv_parts(
        TAG_SEQUENCE,
        &[
            &tlv::tlv(TAG_OID, OID_ID_SIGNED_DATA.as_bytes()),
            &tlv::tlv(TAG_CONTEXT_0, &signed_data),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_id(hash_algorithm: AlgorithmIdentifierRef<'static>) -> Vec<u8> {
        EssCertIdV2 {
            hash_algorithm,
            cert_hash: OctetString::new(vec![0xAB; 32]).unwrap(),
            issuer_serial: None,
        }
        .to_der()
        .unwrap()
    }

    /// RFC 5035 §4 / X.690 §11.5: `{id-sha256}` (parameters absent) is the DEFAULT and is
    /// omitted; `{id-sha256, NULL}` is a different value and must be encoded.
    #[test]
    fn ess_cert_id_default_is_sha256_without_parameters() {
        let omitted = cert_id(sha256_algorithm_identifier());
        assert_eq!(omitted[..4], [0x30, 0x22, 0x04, 0x20]);

        let null = der::asn1::AnyRef::from(der::asn1::Null);
        let with_null = cert_id(AlgorithmIdentifierRef {
            oid: OID_SHA256,
            parameters: Some(null),
        });
        assert_eq!(
            with_null[2..17],
            [
                0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00
            ]
        );

        let sha384 = cert_id(AlgorithmIdentifierRef {
            oid: OID_SHA384,
            parameters: None,
        });
        assert_eq!(sha384[2..4], [0x30, 0x0b]);
        // The decoder fills the DEFAULT back in.
        let decoded = EssCertIdV2::from_der(&omitted).unwrap();
        assert_eq!(decoded.hash_algorithm, sha256_algorithm_identifier());
    }

    #[test]
    fn normalize_signature_forms() {
        let rsa = KeyKind::Rsa { bits: 2048 };
        assert_eq!(normalize_signature(&[1, 2, 3], rsa).unwrap().len(), 256);
        assert!(normalize_signature(&[1; 257], rsa).is_err());
        let p256 = KeyKind::EcP256;
        let p1363 = [[0u8; 31].as_slice(), &[5], &[0x80; 32]].concat();
        let der = normalize_signature(&p1363, p256).unwrap();
        assert_eq!(der[..5], [0x30, 0x26, 0x02, 0x01, 0x05]);
        assert_eq!(normalize_signature(&der, p256).unwrap(), der);
        assert!(normalize_signature(&[0; 63], p256).is_err());
    }
}

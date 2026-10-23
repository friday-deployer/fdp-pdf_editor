//! The shape of a timestamp token, checked as a whitelist on both sides (M4 brief §4.2 step 3,
//! §5 V7b step 1; QA round 1 findings F5 and F6).
//!
//! A token passes only when everything it carries is what RFC 3161 and RFC 5652 allow and an
//! ASN.1 decoder such as OpenSSL's can read, the parts no check of Folioxide uses included:
//!
//! - a ContentInfo `signedData` with exactly one SignerInfo, eContentType `id-ct-TSTInfo` and
//!   eContent (RFC 3161 §2.4.2);
//! - `SignedData.version` 3, as RFC 5652 §5.1 requires when the eContentType is not `id-data`
//!   and the certificates are all X.509 certificates (pyHanko cannot read the TSTInfo of a
//!   version-1 token, OpenSSL ignores the version);
//! - `digestAlgorithms` non-empty, every member a digest Folioxide implements with absent or
//!   NULL parameters (RFC 5754 §2), the SignerInfo's among them (OpenSSL `PKCS7_dataInit` and
//!   `PKCS7_signatureVerify` refuse an unknown member or a missing one);
//! - every `certificates` entry a `certificate` choice that decodes as an X.509 certificate,
//!   used or not, and every `crls` entry a CRL that decodes (OpenSSL decodes them all), their
//!   issuer and subject names as OpenSSL's `X509_NAME` reads them
//!   ([`names::name_decodes`](crate::x509info::names::name_decodes));
//! - the SignerInfo version 1 with an issuerAndSerialNumber and 3 with a subjectKeyIdentifier
//!   (RFC 5652 §5.3), its digestAlgorithm with absent or NULL parameters, and its
//!   signatureAlgorithm with absent or NULL parameters for PKCS #1 v1.5 (RFC 4055 §5) and ECDSA
//!   (RFC 5758 §3.2, which also allows no NULL; Folioxide accepts it); RSASSA-PSS parameters are
//!   checked when the signature is ([`verify_encapsulated`](crate::cms::verify_encapsulated));
//! - every primitive inside the token and inside its TSTInfo a valid encoding of its universal
//!   type: no empty or padded INTEGER, no invalid OBJECT IDENTIFIER, no BMPString with a UTF-16
//!   surrogate or UniversalString beyond Unicode (which OpenSSL cannot convert in a name, QA
//!   round 4 finding 1), and so on ([`tlv::check_primitives`]);
//! - the SignerInfo's signed attributes present (RFC 5652 §5.3) and **DER** (QA round 3 finding
//!   2): the TSA signs their DER encoding (§5.4), and OpenSSL and BouncyCastle (EU DSS) verify
//!   over a DER re-encoding, so a token signed over a BER or unsorted encoding fails there,
//!   whereas a verifier that hashes the bytes as found accepts it;
//! - every value of an ESS signing-certificate attribute (v1 or v2) a `SigningCertificate(V2)`
//!   that decodes as OpenSSL's `ESS_SIGNING_CERT(_V2)` templates decode it (QA round 3 finding
//!   3): the optional `policies` as `SEQUENCE OF PolicyInformation` (RFC 5280 §4.2.1.4), each
//!   `IssuerSerial` one directoryName whose `Name` decodes.
//!
//! The TSTInfo's own fields are checked where it is decoded
//! ([`parse::tst_info`](super::parse::tst_info): its `extensions` too, QA round 3 finding 4).
//!
//! The check is one pass over the token, plus one certificate decode per certificate (at most
//! [`MAX_CERTIFICATES`](crate::cms::MAX_CERTIFICATES)).

use der::Decode as _;

use super::OID_CT_TST_INFO;
use crate::algorithms::oid;
use crate::cms::decode::{algorithm_id, attributes, signed_data_layout};
use crate::cms::{AlgorithmId, MAX_DEPTH, ParsedCms, SignerIdentifier, oid_to_string, tlv, verify};
use crate::x509info::cert;
use crate::x509info::names::name_decodes;

/// Whether AlgorithmIdentifier parameters are absent or `NULL`.
fn null_or_absent(algorithm: &AlgorithmId) -> bool {
    super::parse::null_or_absent(algorithm.parameters.as_deref())
}

/// `id-qt-cps` (1.3.6.1.5.5.7.2.1, RFC 5280 §4.2.1.4) as content octets.
const ID_QT_CPS: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01];
/// `id-qt-unotice` (1.3.6.1.5.5.7.2.2) as content octets.
const ID_QT_UNOTICE: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02];
/// `IA5String`, primitive.
const TAG_IA5_STRING: u8 = 0x16;

/// Whether `tag` is a `DisplayText` (RFC 5280 §4.2.1.4: IA5String, VisibleString, BMPString or
/// UTF8String; OpenSSL's `B_ASN1_DISPLAYTEXT`).
fn display_text(tag: u8) -> bool {
    matches!(tag, TAG_IA5_STRING | 0x1A | 0x1E | 0x0C)
}

/// The children of `element` (read at `depth`), at most `max`, or `what` as the error.
fn fields(
    input: &[u8],
    element: &tlv::Element,
    depth: usize,
    max: usize,
    what: &'static str,
) -> Result<Vec<tlv::Element>, &'static str> {
    tlv::children_vec(input, element, depth, MAX_DEPTH, max).map_err(|_| what)
}

/// `policies SEQUENCE OF PolicyInformation` of an ESS `SigningCertificate(V2)` (RFC 2634
/// §5.4.1, RFC 5035 §3), as OpenSSL's `POLICYINFO` template decodes it (RFC 5280 §4.2.1.4):
///
/// ```text
/// PolicyInformation ::= SEQUENCE { policyIdentifier OID,
///     policyQualifiers SEQUENCE OF PolicyQualifierInfo OPTIONAL }
/// PolicyQualifierInfo ::= SEQUENCE { policyQualifierId OID, qualifier ANY DEFINED BY it }
/// ```
///
/// The qualifier of `id-qt-cps` is an IA5String, that of `id-qt-unotice` a `UserNotice`, any
/// other one a single element (QA round 3 finding 3: Folioxide read only the outer tag, and
/// OpenSSL refuses the whole token when this does not decode). A certificate's
/// `certificatePolicies` extension has the same syntax and is read with this too (QA round 4
/// finding 5).
pub(crate) fn policies(
    input: &[u8],
    element: &tlv::Element,
    depth: usize,
) -> Result<(), &'static str> {
    if element.tag != tlv::TAG_SEQUENCE {
        return Err("policies is not a SEQUENCE");
    }
    const NOT_INFO: &str = "a policies entry is not a PolicyInformation";
    const NOT_QUALIFIER: &str = "a policy qualifier is not a PolicyQualifierInfo";
    for info in tlv::children(input, element, depth, MAX_DEPTH) {
        let info = info.map_err(|_| NOT_INFO)?;
        if info.tag != tlv::TAG_SEQUENCE {
            return Err(NOT_INFO);
        }
        let parts = fields(input, &info, depth + 1, 2, NOT_INFO)?;
        let (identifier, qualifiers) = match parts.as_slice() {
            [identifier] => (identifier, None),
            [identifier, qualifiers] => (identifier, Some(qualifiers)),
            _ => return Err(NOT_INFO),
        };
        if identifier.tag != tlv::TAG_OID {
            return Err(NOT_INFO);
        }
        let Some(qualifiers) = qualifiers else {
            continue;
        };
        if qualifiers.tag != tlv::TAG_SEQUENCE {
            return Err("policyQualifiers is not a SEQUENCE");
        }
        for qualifier in tlv::children(input, qualifiers, depth + 2, MAX_DEPTH) {
            let qualifier = qualifier.map_err(|_| NOT_QUALIFIER)?;
            if qualifier.tag != tlv::TAG_SEQUENCE {
                return Err(NOT_QUALIFIER);
            }
            let parts = fields(input, &qualifier, depth + 3, 2, NOT_QUALIFIER)?;
            let [id, value] = parts.as_slice() else {
                return Err(NOT_QUALIFIER);
            };
            if id.tag != tlv::TAG_OID {
                return Err(NOT_QUALIFIER);
            }
            let id = id.content(input);
            if id == ID_QT_CPS && value.tag != TAG_IA5_STRING {
                return Err("a CPS qualifier is not an IA5String");
            }
            if id == ID_QT_UNOTICE {
                user_notice(input, value, depth + 4)?;
            }
        }
    }
    Ok(())
}

/// `UserNotice ::= SEQUENCE { noticeRef NoticeReference OPTIONAL, explicitText DisplayText
/// OPTIONAL }` with `NoticeReference ::= SEQUENCE { organization DisplayText, noticeNumbers
/// SEQUENCE OF INTEGER }` (RFC 5280 §4.2.1.4; OpenSSL `USERNOTICE`, `NOTICEREF`).
fn user_notice(input: &[u8], element: &tlv::Element, depth: usize) -> Result<(), &'static str> {
    const BAD: &str = "a user notice qualifier is not a UserNotice";
    if element.tag != tlv::TAG_SEQUENCE {
        return Err(BAD);
    }
    let parts = fields(input, element, depth, 2, BAD)?;
    let mut parts = parts.iter().peekable();
    if let Some(reference) = parts.next_if(|p| p.tag == tlv::TAG_SEQUENCE) {
        let inner = fields(input, reference, depth + 1, 2, BAD)?;
        let [organization, numbers] = inner.as_slice() else {
            return Err(BAD);
        };
        if !display_text(organization.tag) || numbers.tag != tlv::TAG_SEQUENCE {
            return Err(BAD);
        }
        for number in tlv::children(input, numbers, depth + 2, MAX_DEPTH) {
            if !number.is_ok_and(|n| n.tag == tlv::TAG_INTEGER) {
                return Err(BAD);
            }
        }
    }
    let _explicit_text = parts.next_if(|p| display_text(p.tag));
    match parts.next() {
        None => Ok(()),
        Some(_) => Err(BAD),
    }
}

/// `IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber CertificateSerialNumber }`
/// (RFC 5035 §4; OpenSSL's `ESS_ISSUER_SERIAL` has no `issuerUID`), whose `issuer` is exactly
/// one `directoryName` with a `Name` that decodes ([`name_decodes`]): OpenSSL refuses the token
/// when a name value does not decode (QA round 3 finding 3, a VisibleString; round 4 finding 1,
/// a BMPString surrogate), and only one directoryName can name a certificate's issuer there
/// (`ess_issuer_serial_cmp`).
fn issuer_serial(input: &[u8], element: &tlv::Element, depth: usize) -> Result<(), &'static str> {
    const BAD: &str = "an IssuerSerial is not one directoryName and a serial number";
    let parts = fields(input, element, depth, 2, BAD)?;
    let [names, serial] = parts.as_slice() else {
        return Err(BAD);
    };
    if element.tag != tlv::TAG_SEQUENCE
        || names.tag != tlv::TAG_SEQUENCE
        || serial.tag != tlv::TAG_INTEGER
    {
        return Err(BAD);
    }
    let names = fields(input, names, depth + 1, 1, BAD)?;
    let [directory_name] = names.as_slice() else {
        return Err(BAD);
    };
    if directory_name.tag != tlv::TAG_CONTEXT_4 {
        return Err(BAD);
    }
    let name = fields(input, directory_name, depth + 2, 1, BAD)?;
    let [name] = name.as_slice() else {
        return Err(BAD);
    };
    if !name_decodes(name.raw(input)) {
        return Err(
            "the issuer name of an IssuerSerial does not decode as a name (a value of a type a \
             name may not hold, or a string OpenSSL cannot convert to UTF-8)",
        );
    }
    Ok(())
}

/// One `ESSCertID ::= SEQUENCE { certHash OCTET STRING, issuerSerial IssuerSerial OPTIONAL }`
/// (RFC 2634 §5.4.1) or `ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier DEFAULT
/// sha256, certHash OCTET STRING, issuerSerial IssuerSerial OPTIONAL }` (RFC 5035 §4).
fn cert_id(input: &[u8], id: &tlv::Element, depth: usize, v2: bool) -> Result<(), &'static str> {
    const BAD: &str =
        "an identifier is not a hash algorithm (v2), a certHash and an optional IssuerSerial";
    let parts = fields(input, id, depth, 3, BAD)?;
    if id.tag != tlv::TAG_SEQUENCE {
        return Err(BAD);
    }
    let mut parts = parts.iter().peekable();
    if v2
        && let Some(algorithm) = parts.next_if(|p| p.tag == tlv::TAG_SEQUENCE)
        && algorithm_id(input, algorithm, depth + 1).is_err()
    {
        return Err("an identifier's hashAlgorithm is not an AlgorithmIdentifier");
    }
    if !parts.next().is_some_and(|p| p.tag == tlv::TAG_OCTET_STRING) {
        return Err(BAD);
    }
    if let Some(serial) = parts.next() {
        issuer_serial(input, serial, depth + 1)?;
    }
    if parts.next().is_some() {
        return Err(BAD);
    }
    Ok(())
}

/// `SigningCertificate ::= SEQUENCE { certs SEQUENCE OF ESSCertID, policies SEQUENCE OF
/// PolicyInformation OPTIONAL }` (RFC 2634 §5.4) or `SigningCertificateV2` with `ESSCertIDv2`
/// (RFC 5035 §3), decoded as OpenSSL's `ESS_SIGNING_CERT(_V2)` templates decode them, the
/// optional fields included. Whether the identifiers name the TSA certificate is the binding
/// check's ([`check_signing_certificates`](crate::cms::verify::check_signing_certificates)).
fn signing_certificate(value: &[u8], v2: bool) -> Result<(), &'static str> {
    const BAD: &str = "it is not a SEQUENCE of certs and optional policies";
    let outer = tlv::read_exact(value, MAX_DEPTH).map_err(|_| BAD)?;
    let parts = fields(value, &outer, 0, 2, BAD)?;
    let (certs, policy_list) = match parts.as_slice() {
        [certs] => (certs, None),
        [certs, policy_list] => (certs, Some(policy_list)),
        _ => return Err(BAD),
    };
    if outer.tag != tlv::TAG_SEQUENCE || certs.tag != tlv::TAG_SEQUENCE {
        return Err(BAD);
    }
    for id in tlv::children(value, certs, 1, MAX_DEPTH) {
        let id = id.map_err(|_| "an identifier does not parse")?;
        cert_id(value, &id, 2, v2)?;
    }
    if let Some(policy_list) = policy_list {
        policies(value, policy_list, 1)?;
    }
    Ok(())
}

/// The signed attributes of the token's SignerInfo (QA round 3 findings 2 and 3): present (RFC
/// 5652 §5.3 requires them when the eContentType is not id-data), DER
/// ([`signed_attributes_are_der`](crate::cms::verify::signed_attributes_are_der): the signature
/// is over their DER encoding, §5.4, and OpenSSL and BouncyCastle verify over a DER
/// re-encoding), and every value of every ESS signing-certificate attribute decodes
/// ([`signing_certificate`]).
fn signed_attributes(signed_attrs: Option<&[u8]>) -> Result<(), String> {
    let signed_attrs = signed_attrs.ok_or_else(|| {
        "the token's SignerInfo has no signed attributes, which RFC 5652 §5.3 requires when the \
         eContentType is not id-data"
            .to_owned()
    })?;
    if !verify::signed_attributes_are_der(signed_attrs) {
        return Err(
            "the token's signed attributes are not DER: RFC 5652 §5.4 signs their DER encoding, \
             and OpenSSL and BouncyCastle verify the signature over a DER re-encoding (sorted \
             values, minimal definite lengths), which a TSA that signed other bytes fails"
                .to_owned(),
        );
    }
    for (attr_type, values) in attributes(signed_attrs) {
        let (v2, name) = match oid_to_string(&attr_type).as_deref() {
            Some(oid::SIGNING_CERTIFICATE_V2) => (true, "signing-certificate-v2"),
            Some(oid::SIGNING_CERTIFICATE) => (false, "signing-certificate"),
            _ => continue,
        };
        for value in &values {
            signing_certificate(value, v2).map_err(|why| {
                format!("the token's {name} attribute does not decode (RFC 2634, RFC 5035): {why}")
            })?;
        }
    }
    Ok(())
}

/// The `issuer` `Name` (the whole TLV) of the DER CRL `crl`: `CertificateList ::= SEQUENCE {
/// tbsCertList SEQUENCE { version INTEGER OPTIONAL, signature AlgorithmIdentifier, issuer Name,
/// … }, … }` (RFC 5280 §5.1).
fn crl_issuer(crl: &[u8]) -> Option<&[u8]> {
    let outer = tlv::read_exact(crl, MAX_DEPTH).ok()?;
    let tbs = tlv::children(crl, &outer, 0, MAX_DEPTH).next()?.ok()?;
    let mut fields = tlv::children(crl, &tbs, 1, MAX_DEPTH);
    let mut field = fields.next()?.ok()?;
    if field.tag == tlv::TAG_INTEGER {
        field = fields.next()?.ok()?;
    }
    // `field` is the signature AlgorithmIdentifier; the issuer follows.
    (field.tag == tlv::TAG_SEQUENCE).then_some(())?;
    let issuer = fields.next()?.ok()?;
    Some(issuer.raw(crl))
}

/// The value of a small INTEGER's content octets for a message, else their hexadecimal.
fn integer_text(content: &[u8]) -> String {
    match content {
        [value] if *value < 0x80 => value.to_string(),
        _ => content.iter().map(|b| format!("{b:02X}")).collect(),
    }
}

/// Checks the shape of `token`, which parsed as `parsed`, and returns the eContent (the DER
/// TSTInfo). See the module documentation for what is checked.
///
/// # Errors
/// What is wrong, as one sentence (the verifier reports it as `TimestampMalformed`, the signing
/// side refuses the response with it).
pub(super) fn token_shape<'a>(token: &[u8], parsed: &'a ParsedCms) -> Result<&'a [u8], String> {
    if parsed.content_type != oid::ID_SIGNED_DATA {
        return Err(format!(
            "the token's ContentInfo is {}, not signedData",
            parsed.content_type
        ));
    }
    let [signer_info] = parsed.signer_infos.as_slice() else {
        return Err(format!(
            "the token has {} SignerInfos; exactly one is required",
            parsed.signer_infos.len()
        ));
    };
    let econtent_type = parsed.econtent_type.as_deref().unwrap_or_default();
    if econtent_type != OID_CT_TST_INFO {
        return Err(format!(
            "the token's eContentType is {econtent_type}, not id-ct-TSTInfo"
        ));
    }
    let econtent = parsed
        .econtent
        .as_deref()
        .ok_or_else(|| "the token has no encapsulated TSTInfo".to_owned())?;

    // Every primitive of the token and of its TSTInfo.
    let content_info = token.get(parsed.raw.clone()).unwrap_or_default();
    for (bytes, what) in [(content_info, "the token"), (econtent, "the TSTInfo")] {
        let element = tlv::read_exact(bytes, MAX_DEPTH)
            .map_err(|err| format!("{what} does not decode: {err}"))?;
        tlv::check_primitives(bytes, &element, 0, MAX_DEPTH)
            .map_err(|why| format!("{what} holds {why}"))?;
    }

    let layout = signed_data_layout(content_info)
        .map_err(|err| format!("the token's SignedData does not decode: {err}"))?;
    // RFC 5652 §5.1: version 3 for an eContentType other than id-data (4 and 5 need attribute
    // or other certificates, which a token may not carry, below).
    if layout.version != [3] {
        return Err(format!(
            "the token's SignedData version is {}, not 3 (RFC 5652 §5.1)",
            integer_text(&layout.version)
        ));
    }

    // digestAlgorithms.
    if layout.digest_algorithms.is_empty() {
        return Err("the token's SignedData lists no digest algorithm".to_owned());
    }
    let mut listed = Vec::with_capacity(layout.digest_algorithms.len());
    for range in &layout.digest_algorithms {
        let bytes = content_info.get(range.clone()).unwrap_or_default();
        let algorithm = tlv::read_exact(bytes, MAX_DEPTH)
            .ok()
            .filter(|element| element.tag == tlv::TAG_SEQUENCE)
            .and_then(|element| algorithm_id(bytes, &element, 0).ok())
            .ok_or_else(|| {
                "a digestAlgorithms member of the token is not an AlgorithmIdentifier".to_owned()
            })?;
        match algorithm.digest() {
            Some(digest) if null_or_absent(&algorithm) => listed.push(digest),
            _ => {
                return Err(format!(
                    "the token's digestAlgorithms lists {}, which is not a supported digest with \
                     absent or NULL parameters",
                    algorithm.oid
                ));
            }
        }
    }
    let signer_digest = signer_info.digest_algorithm.digest();
    if !signer_digest.is_some_and(|digest| listed.contains(&digest)) {
        return Err(format!(
            "the token's digestAlgorithms does not list the SignerInfo's digest algorithm {}",
            signer_info.digest_algorithm.oid
        ));
    }

    // certificates and crls: X.509 certificates and CRLs only, each of which decodes.
    for (tag, range) in &layout.certificate_choices {
        if *tag != tlv::TAG_SEQUENCE {
            return Err(
                "the token's certificates hold an entry that is not an X.509 certificate"
                    .to_owned(),
            );
        }
        let bytes = content_info.get(range.clone()).unwrap_or_default();
        cert::decode(bytes).map_err(|err| format!("a certificate of the token: {err}"))?;
        let names_ok = cert::CertParts::parse(bytes)
            .is_ok_and(|parts| name_decodes(parts.issuer) && name_decodes(parts.subject));
        if !names_ok {
            return Err(
                "a certificate of the token has a name value of a type a name may not hold"
                    .to_owned(),
            );
        }
    }
    for (tag, range) in &layout.crls {
        let bytes = content_info.get(range.clone()).unwrap_or_default();
        let decodes = *tag == tlv::TAG_SEQUENCE
            && x509_cert::crl::CertificateList::<x509_cert::certificate::Raw>::from_der(bytes)
                .is_ok()
            && crl_issuer(bytes).is_some_and(name_decodes);
        if !decodes {
            return Err("the token's crls hold an entry that is not a CRL that decodes".to_owned());
        }
    }

    // The SignerInfo (RFC 5652 §5.3).
    let expected_version = match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber { issuer, .. } => {
            if !name_decodes(issuer) {
                return Err(
                    "the token's signer identifier has an issuer name value of a type a name may \
                     not hold"
                        .to_owned(),
                );
            }
            1
        }
        SignerIdentifier::SubjectKeyIdentifier(_) => 3,
    };
    if signer_info.version != expected_version {
        return Err(format!(
            "the token's SignerInfo version is {}, not {expected_version} for its signer \
             identifier (RFC 5652 §5.3)",
            signer_info.version
        ));
    }
    if !null_or_absent(&signer_info.digest_algorithm) {
        return Err(
            "the token's SignerInfo digestAlgorithm has parameters other than NULL".to_owned(),
        );
    }
    let signature_algorithm = &signer_info.signature_algorithm;
    let parameterless = matches!(
        signature_algorithm.oid.as_str(),
        oid::RSA_ENCRYPTION
            | oid::SHA1_WITH_RSA
            | oid::SHA256_WITH_RSA
            | oid::SHA384_WITH_RSA
            | oid::SHA512_WITH_RSA
            | oid::EC_PUBLIC_KEY
            | oid::ECDSA_WITH_SHA1
            | oid::ECDSA_WITH_SHA256
            | oid::ECDSA_WITH_SHA384
            | oid::ECDSA_WITH_SHA512
    );
    if parameterless && !null_or_absent(signature_algorithm) {
        return Err(
            "the token's SignerInfo signatureAlgorithm has parameters other than NULL".to_owned(),
        );
    }
    signed_attributes(signer_info.signed_attrs.as_deref())?;
    Ok(econtent)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SEQUENCE { e… }`.
    fn seq(elements: &[Vec<u8>]) -> Vec<u8> {
        tlv::tlv(tlv::TAG_SEQUENCE, &elements.concat())
    }

    #[test]
    fn signing_certificates_decode_as_openssl_reads_them() {
        let hash = tlv::tlv(tlv::TAG_OCTET_STRING, &[0xAB; 32]);
        let oid = |c: &[u8]| tlv::tlv(tlv::TAG_OID, c);
        let name = seq(&[tlv::tlv(
            tlv::TAG_SET,
            &seq(&[oid(&[0x55, 0x04, 0x03]), vec![0x0C, 0x01, b'a']]),
        )]);
        let visible = seq(&[tlv::tlv(
            tlv::TAG_SET,
            &seq(&[oid(&[0x55, 0x04, 0x03]), vec![0x1A, 0x01, b'a']]),
        )]);
        let issuer_serial = |name: &[u8]| {
            seq(&[
                seq(&[tlv::tlv(tlv::TAG_CONTEXT_4, name)]),
                tlv::tlv(tlv::TAG_INTEGER, &[1]),
            ])
        };
        let sha256 = seq(&[oid(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])]);
        let decode = |value: Vec<u8>, v2: bool| signing_certificate(&value, v2);
        let with = |ids: Vec<Vec<u8>>, policies: Option<Vec<u8>>| {
            let mut parts = vec![seq(&ids)];
            parts.extend(policies);
            seq(&parts)
        };

        // Accepted: v1 and v2 identifiers, with and without issuerSerial and hash algorithm.
        let v1_id = seq(&[hash.clone(), issuer_serial(&name)]);
        let v2_id = seq(&[sha256.clone(), hash.clone(), issuer_serial(&name)]);
        assert_eq!(decode(with(vec![v1_id.clone()], None), false), Ok(()));
        assert_eq!(decode(with(vec![v2_id.clone()], None), true), Ok(()));
        assert_eq!(
            decode(with(vec![seq(std::slice::from_ref(&hash))], None), true),
            Ok(())
        );
        // An empty list decodes (the binding check refuses it).
        assert_eq!(decode(with(Vec::new(), None), true), Ok(()));
        // Policies: a PolicyInformation, with qualifiers of each kind; or none at all.
        let info = |qualifiers: Option<Vec<u8>>| {
            let mut parts = vec![oid(&[0x2A, 0x03])];
            parts.extend(qualifiers);
            seq(&parts)
        };
        let qualifier = |id: &[u8], value: Vec<u8>| seq(&[oid(id), value]);
        let notice = seq(&[
            seq(&[
                vec![0x16, 0x01, b'o'],
                seq(&[tlv::tlv(tlv::TAG_INTEGER, &[1])]),
            ]),
            vec![0x1E, 0x02, 0x00, b't'],
        ]);
        for policies in [
            seq(&[]),
            seq(&[info(None)]),
            seq(&[info(Some(seq(&[qualifier(
                &ID_QT_CPS,
                vec![0x16, 0x01, b'u'],
            )])))]),
            seq(&[info(Some(seq(&[qualifier(
                &ID_QT_UNOTICE,
                notice.clone(),
            )])))]),
            seq(&[info(Some(seq(&[qualifier(&ID_QT_UNOTICE, seq(&[]))])))]),
            seq(&[info(Some(seq(&[qualifier(
                &[0x2A, 0x04],
                vec![0x05, 0x00],
            )])))]),
        ] {
            assert_eq!(
                decode(with(vec![v2_id.clone()], Some(policies.clone())), true),
                Ok(()),
                "{policies:02x?}"
            );
        }

        // Refused, each with its reason.
        let refused = |value: Vec<u8>, v2: bool, why: &str| {
            let err = decode(value, v2).unwrap_err();
            assert!(err.contains(why), "{why}: {err}");
        };
        let policies = |p: Vec<u8>| with(vec![v2_id.clone()], Some(p));
        refused(
            policies(seq(&[seq(&[tlv::tlv(tlv::TAG_INTEGER, &[1])])])),
            true,
            "PolicyInformation",
        );
        refused(
            policies(seq(&[tlv::tlv(tlv::TAG_OCTET_STRING, b"abc")])),
            true,
            "PolicyInformation",
        );
        refused(policies(seq(&[seq(&[])])), true, "PolicyInformation");
        refused(
            policies(seq(&[seq(&[oid(&[0x2A, 0x03]), seq(&[]), seq(&[])])])),
            true,
            "PolicyInformation",
        );
        refused(
            policies(tlv::tlv(tlv::TAG_SET, &info(None))),
            true,
            "policies is not a SEQUENCE",
        );
        refused(
            policies(seq(&[info(Some(tlv::tlv(tlv::TAG_SET, &[])))])),
            true,
            "policyQualifiers is not a SEQUENCE",
        );
        refused(
            policies(seq(&[info(Some(seq(&[seq(&[tlv::tlv(
                tlv::TAG_INTEGER,
                &[9],
            )])])))])),
            true,
            "PolicyQualifierInfo",
        );
        refused(
            policies(seq(&[info(Some(seq(&[qualifier(
                &ID_QT_CPS,
                vec![0x0C, 0x01, b'u'],
            )])))])),
            true,
            "not an IA5String",
        );
        for bad_notice in [
            seq(&[tlv::tlv(tlv::TAG_INTEGER, &[1])]),
            seq(&[vec![0x16, 0x01, b't'], vec![0x16, 0x01, b't']]),
            seq(&[seq(&[vec![0x16, 0x01, b'o']])]),
            seq(&[seq(&[vec![0x04, 0x01, b'o'], seq(&[])])]),
            seq(&[seq(&[vec![0x16, 0x01, b'o'], seq(&[vec![0x04, 0x00]])])]),
            tlv::tlv(tlv::TAG_OCTET_STRING, b"n"),
        ] {
            refused(
                policies(seq(&[info(Some(seq(&[qualifier(
                    &ID_QT_UNOTICE,
                    bad_notice,
                )])))])),
                true,
                "not a UserNotice",
            );
        }
        // The IssuerSerial: one directoryName with a Name that decodes, and a serial.
        let id_with = |serial: Vec<u8>| with(vec![seq(&[hash.clone(), serial])], None);
        refused(
            id_with(issuer_serial(&visible)),
            false,
            "does not decode as a name",
        );
        // QA round 4 finding 1: a BMPString surrogate in the issuer name.
        let surrogate = seq(&[tlv::tlv(
            tlv::TAG_SET,
            &seq(&[oid(&[0x55, 0x04, 0x03]), vec![0x1E, 0x02, 0xD8, 0x00]]),
        )]);
        refused(
            id_with(issuer_serial(&surrogate)),
            false,
            "does not decode as a name",
        );
        refused(
            id_with(seq(&[seq(&[tlv::tlv(tlv::TAG_CONTEXT_4, &name)])])),
            false,
            "IssuerSerial",
        );
        refused(
            id_with(seq(&[
                seq(&[tlv::tlv(tlv::TAG_CONTEXT_4, &name), vec![0x82, 0x01, b'x']]),
                tlv::tlv(tlv::TAG_INTEGER, &[1]),
            ])),
            false,
            "IssuerSerial",
        );
        refused(
            id_with(seq(&[
                seq(&[vec![0x82, 0x01, b'x']]),
                tlv::tlv(tlv::TAG_INTEGER, &[1]),
            ])),
            false,
            "IssuerSerial",
        );
        refused(
            id_with(seq(&[
                seq(&[tlv::tlv(tlv::TAG_CONTEXT_4, &name)]),
                tlv::tlv(tlv::TAG_INTEGER, &[1]),
                tlv::tlv(tlv::TAG_INTEGER, &[2]),
            ])),
            false,
            "IssuerSerial",
        );
        // The identifiers: a v1 one with a hash algorithm, a missing certHash, extra fields, a
        // hash algorithm that is no AlgorithmIdentifier.
        refused(
            with(vec![seq(&[sha256.clone(), hash.clone()])], None),
            false,
            "identifier",
        );
        refused(
            with(vec![seq(&[issuer_serial(&name)])], None),
            true,
            "identifier",
        );
        refused(
            with(
                vec![seq(&[hash.clone(), issuer_serial(&name), vec![0x05, 0x00]])],
                None,
            ),
            false,
            "identifier",
        );
        refused(
            with(vec![seq(&[seq(&[vec![0x05, 0x00]]), hash.clone()])], None),
            true,
            "hashAlgorithm",
        );
        refused(
            with(vec![tlv::tlv(tlv::TAG_OCTET_STRING, &[1])], None),
            true,
            "identifier",
        );
        // The outer structure.
        refused(seq(&[]), true, "certs");
        refused(
            tlv::tlv(tlv::TAG_SET, &seq(std::slice::from_ref(&v2_id))),
            true,
            "certs",
        );
        refused(
            seq(&[seq(std::slice::from_ref(&v2_id)), seq(&[]), seq(&[])]),
            true,
            "certs",
        );
        refused(vec![0x30, 0x84, 0xFF], true, "certs");
    }

    #[test]
    fn signed_attributes_must_be_present_and_der() {
        assert!(
            signed_attributes(None)
                .unwrap_err()
                .contains("no signed attributes")
        );
        let attribute = |values: &[u8]| {
            seq(&[
                tlv::tlv(tlv::TAG_OID, &[0x2A, 0x03]),
                tlv::tlv(tlv::TAG_SET, values),
            ])
        };
        let signed = |attributes: &[Vec<u8>]| tlv::tlv(tlv::TAG_CONTEXT_0, &attributes.concat());
        assert_eq!(
            signed_attributes(Some(&signed(&[attribute(&[0x05, 0x00])]))),
            Ok(())
        );
        for not_der in [
            // Values out of order, a BOOLEAN TRUE as 01, an indefinite length, a long form.
            signed(&[attribute(&[0x04, 0x01, b'b', 0x04, 0x01, b'a'])]),
            signed(&[attribute(&[0x01, 0x01, 0x01])]),
            [&[0xA0, 0x80][..], &attribute(&[0x05, 0x00]), &[0, 0]].concat(),
            [&[0xA0, 0x81, 0x09][..], &attribute(&[0x05, 0x00])].concat(),
        ] {
            assert!(
                signed_attributes(Some(&not_der))
                    .unwrap_err()
                    .contains("not DER"),
                "{not_der:02x?}"
            );
        }
        // An ESS attribute that does not decode names itself.
        let ess = seq(&[
            tlv::tlv(
                tlv::TAG_OID,
                &[
                    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
                ],
            ),
            tlv::tlv(tlv::TAG_SET, &[0x05, 0x00]),
        ]);
        assert!(
            signed_attributes(Some(&signed(&[ess])))
                .unwrap_err()
                .contains("signing-certificate-v2 attribute does not decode")
        );
    }

    #[test]
    fn integer_text_is_short() {
        assert_eq!(integer_text(&[3]), "3");
        assert_eq!(integer_text(&[0x00, 0x03]), "0003");
        assert_eq!(integer_text(&[]), "");
    }

    #[test]
    fn not_signed_data_is_refused_first() {
        let id_data = [
            0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
        ];
        let parsed = crate::cms::parse(&id_data).unwrap();
        assert!(
            token_shape(&id_data, &parsed)
                .unwrap_err()
                .contains("not signedData")
        );
    }
}

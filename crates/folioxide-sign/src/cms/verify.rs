//! Verifying detached CMS signatures (M3 brief §5 V6–V8) and raw signature values.
//!
//! Everything here works on the bytes [`parse`](super::parse()) kept: the signature is checked over
//! the **original** signed attributes with the first octet replaced by `0x31` (RFC 5652 §5.4),
//! never over a re-encoding. Every defect becomes a [`Problem`]; nothing panics.

use der::Decode as _;

use super::decode::{algorithm_id, attributes, oid_to_string};
use super::tlv::{
    self, Element, TAG_CONTEXT_0, TAG_CONTEXT_1, TAG_CONTEXT_2, TAG_CONTEXT_3, TAG_CONTEXT_4,
    TAG_GENERALIZED_TIME, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET,
    TAG_UTC_TIME,
};
use super::{
    AlgorithmId, CmsVerification, MAX_DEPTH, PadesAttrs, ParsedCms, ParsedSignerInfo,
    SignerIdentifier,
};
use crate::algorithms::{DigestAlgorithm, KeyKind, SignatureAlgorithm, oid};
use crate::error::{Error, Result};
use crate::keys::public::{PublicKey, VerifyFailure};
use crate::problem::{Problem, ProblemCode};
use crate::x509info::cert::{self, CertParts};

/// How a `signatureAlgorithm` asks for the value to be checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scheme {
    /// RSASSA-PKCS1-v1_5.
    RsaPkcs1v15,
    /// RSASSA-PSS with this salt length (MGF1 on the same hash).
    RsaPss { salt_len: usize },
    /// ECDSA.
    Ecdsa,
}

/// A classified `signatureAlgorithm`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignatureScheme {
    pub(crate) scheme: Scheme,
    /// The hash the OID implies; `None` for `rsaEncryption` and `id-ecPublicKey`, which take
    /// the SignerInfo's digestAlgorithm.
    pub(crate) implied_hash: Option<DigestAlgorithm>,
}

/// Classifies a CMS `signatureAlgorithm` (brief §4.3 "Algorithm OIDs and parameters"); also
/// used for certificate signatures, which use the same OIDs (RFC 4055, RFC 5758).
pub(crate) fn classify(alg: &AlgorithmId) -> std::result::Result<SignatureScheme, String> {
    let pkcs1 = |hash| {
        Ok(SignatureScheme {
            scheme: Scheme::RsaPkcs1v15,
            implied_hash: hash,
        })
    };
    let ecdsa = |hash| {
        Ok(SignatureScheme {
            scheme: Scheme::Ecdsa,
            implied_hash: hash,
        })
    };
    match alg.oid.as_str() {
        oid::RSA_ENCRYPTION => pkcs1(None),
        oid::SHA1_WITH_RSA => pkcs1(Some(DigestAlgorithm::Sha1)),
        oid::SHA256_WITH_RSA => pkcs1(Some(DigestAlgorithm::Sha256)),
        oid::SHA384_WITH_RSA => pkcs1(Some(DigestAlgorithm::Sha384)),
        oid::SHA512_WITH_RSA => pkcs1(Some(DigestAlgorithm::Sha512)),
        oid::EC_PUBLIC_KEY => ecdsa(None),
        oid::ECDSA_WITH_SHA1 => ecdsa(Some(DigestAlgorithm::Sha1)),
        oid::ECDSA_WITH_SHA256 => ecdsa(Some(DigestAlgorithm::Sha256)),
        oid::ECDSA_WITH_SHA384 => ecdsa(Some(DigestAlgorithm::Sha384)),
        oid::ECDSA_WITH_SHA512 => ecdsa(Some(DigestAlgorithm::Sha512)),
        oid::RSASSA_PSS => {
            let (hash, salt_len) = pss_parameters(alg.parameters.as_deref())?;
            Ok(SignatureScheme {
                scheme: Scheme::RsaPss { salt_len },
                implied_hash: Some(hash),
            })
        }
        other => Err(format!(
            "signature algorithm {} is not supported",
            algorithm_name(other)
        )),
    }
}

/// A readable name for a signature algorithm OID.
pub(crate) fn algorithm_name(dotted: &str) -> String {
    match dotted {
        "1.3.101.112" => "Ed25519".to_owned(),
        "1.3.101.113" => "Ed448".to_owned(),
        "1.2.840.10040.4.3" => "dsa-with-sha1".to_owned(),
        "2.16.840.1.101.3.4.3.2" => "dsa-with-sha256".to_owned(),
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption".to_owned(),
        other => other.to_owned(),
    }
}

/// `RSASSA-PSS-params` (RFC 4055 §3.1, RFC 8017 Appendix A.2.3; EXPLICIT tags):
///
/// ```text
/// SEQUENCE { hashAlgorithm [0] DEFAULT sha1, maskGenAlgorithm [1] DEFAULT mgf1SHA1,
///            saltLength [2] INTEGER DEFAULT 20, trailerField [3] INTEGER DEFAULT 1 }
/// ```
///
/// Returns the hash and the salt length. MGF1 must use the same hash, and the trailer must be 1.
fn pss_parameters(params: Option<&[u8]>) -> std::result::Result<(DigestAlgorithm, usize), String> {
    let mut hash = DigestAlgorithm::Sha1;
    let mut mgf_hash = DigestAlgorithm::Sha1;
    let mut salt_len = 20usize;
    let bad = |what: &str| format!("RSASSA-PSS parameters: {what}");
    let Some(params) = params else {
        return Ok((hash, salt_len));
    };
    let seq = tlv::read_exact(params, 8).map_err(|_| bad("malformed"))?;
    if seq.tag != TAG_SEQUENCE {
        return Err(bad("not a SEQUENCE"));
    }
    for field in tlv::children(params, &seq, 0, 8) {
        let field = field.map_err(|_| bad("malformed"))?;
        let inner = tlv::children(params, &field, 1, 8)
            .next()
            .and_then(std::result::Result::ok)
            .ok_or_else(|| bad("empty field"))?;
        match field.tag {
            TAG_CONTEXT_0 => {
                let alg = algorithm_id(params, &inner, 2).map_err(|_| bad("hashAlgorithm"))?;
                hash = alg
                    .digest()
                    .ok_or_else(|| bad(&format!("hash {} is not supported", alg.oid)))?;
            }
            TAG_CONTEXT_1 => {
                let mgf = algorithm_id(params, &inner, 2).map_err(|_| bad("maskGenAlgorithm"))?;
                if mgf.oid != oid::MGF1 {
                    return Err(bad(&format!(
                        "mask generation function {} is not MGF1",
                        mgf.oid
                    )));
                }
                let mgf_params = mgf.parameters.unwrap_or_default();
                let mgf_alg = tlv::read_exact(&mgf_params, 4)
                    .ok()
                    .and_then(|el| algorithm_id(&mgf_params, &el, 0).ok())
                    .ok_or_else(|| bad("MGF1 hash"))?;
                mgf_hash = mgf_alg
                    .digest()
                    .ok_or_else(|| bad(&format!("MGF1 hash {} is not supported", mgf_alg.oid)))?;
            }
            TAG_CONTEXT_2 => {
                salt_len = small_unsigned(inner.content(params), inner.tag)
                    .filter(|&s| s <= 1024)
                    .ok_or_else(|| bad("saltLength"))?;
            }
            TAG_CONTEXT_3 => {
                if small_unsigned(inner.content(params), inner.tag) != Some(1) {
                    return Err(bad("trailerField is not 1"));
                }
            }
            _ => return Err(bad("unknown field")),
        }
    }
    if mgf_hash != hash {
        return Err(bad("MGF1 uses a different hash than the signature"));
    }
    Ok((hash, salt_len))
}

fn small_unsigned(content: &[u8], tag: u8) -> Option<usize> {
    if tag != TAG_INTEGER {
        return None;
    }
    let value = tlv::integer_canonical(content);
    if value.is_empty() || value.len() > 4 || value.first().is_some_and(|&b| b & 0x80 != 0) {
        return None;
    }
    Some(
        value
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b)),
    )
}

/// The DER content octets of a known OID constant (for comparing attribute types).
fn oid_bytes(dotted: &'static str) -> Vec<u8> {
    const_oid::ObjectIdentifier::new(dotted)
        .map(|o| o.as_bytes().to_vec())
        .unwrap_or_default()
}

/// Whether two AlgorithmIdentifiers are the same algorithm: equal OIDs, and parameters that are
/// equal or both "absent or NULL" (RFC 5754 §2 allows either for SHA-2).
pub(crate) fn same_algorithm(a: &AlgorithmId, b: &AlgorithmId) -> bool {
    let null_or_absent = |p: &Option<Vec<u8>>| p.as_deref().is_none_or(|p| p == [0x05, 0x00]);
    a.oid == b.oid
        && (a.parameters == b.parameters
            || (null_or_absent(&a.parameters) && null_or_absent(&b.parameters)))
}

/// Collects problems and whether any of them invalidates the signature.
struct Findings {
    problems: Vec<Problem>,
    warnings: Vec<String>,
    /// A problem that makes `signature_valid` false was recorded.
    invalid: bool,
}

impl Findings {
    fn fail(&mut self, code: ProblemCode, message: impl Into<String>) {
        self.problems.push(Problem::new(code, message));
        self.invalid = true;
    }

    /// A problem that does not by itself make the signature invalid (a digest mismatch only
    /// breaks `intact`; a weak algorithm only breaks trust).
    fn note(&mut self, code: ProblemCode, message: impl Into<String>) {
        if !self.problems.iter().any(|p| p.code == code) {
            self.problems.push(Problem::new(code, message));
        }
    }
}

/// See [`super::verify_detached`].
pub(crate) fn verify_detached(
    parsed: &ParsedCms,
    document_digest_for: &dyn Fn(DigestAlgorithm) -> Option<Vec<u8>>,
    extra_certs: &[Vec<u8>],
) -> CmsVerification {
    if parsed.content_type != oid::ID_SIGNED_DATA {
        return CmsVerification::failed(Problem::new(
            ProblemCode::NotSignedData,
            format!("the ContentInfo is {}, not signedData", parsed.content_type),
        ));
    }
    let [signer_info] = parsed.signer_infos.as_slice() else {
        return CmsVerification::failed(Problem::new(
            ProblemCode::SignerInfoCount,
            format!(
                "the SignedData has {} SignerInfos; exactly one is required",
                parsed.signer_infos.len()
            ),
        ));
    };
    let mut findings = Findings {
        problems: Vec::new(),
        warnings: Vec::new(),
        invalid: false,
    };
    let econtent_type = parsed.econtent_type.as_deref().unwrap_or_default();
    if econtent_type != oid::ID_DATA {
        findings.fail(
            ProblemCode::ContentTypeMismatch,
            format!("the eContentType is {econtent_type}, not id-data"),
        );
    }
    if parsed.econtent.is_some() {
        findings.fail(
            ProblemCode::EContentPresent,
            "a detached signature carries encapsulated content",
        );
    }

    let digest = signer_info.digest_algorithm.digest();
    if digest.is_none() {
        findings.fail(
            ProblemCode::UnsupportedAlgorithm,
            format!(
                "digest algorithm {} is not supported",
                algorithm_name(&signer_info.digest_algorithm.oid)
            ),
        );
    }
    let scheme = match classify(&signer_info.signature_algorithm) {
        Ok(scheme) => Some(scheme),
        Err(message) => {
            findings.fail(ProblemCode::UnsupportedAlgorithm, message);
            None
        }
    };
    if let (Some(scheme), Some(digest)) = (&scheme, digest)
        && let Some(implied) = scheme.implied_hash
        && implied != digest
    {
        findings.fail(
            ProblemCode::DigestSignatureAlgorithmMismatch,
            format!(
                "the signature algorithm hashes with {implied} but the digest algorithm is {digest}"
            ),
        );
    }
    let weak = digest.is_some_and(DigestAlgorithm::is_weak)
        || scheme
            .as_ref()
            .and_then(|s| s.implied_hash)
            .is_some_and(DigestAlgorithm::is_weak);
    if weak {
        findings.note(
            ProblemCode::WeakAlgorithm,
            "SHA-1 is a weak digest algorithm",
        );
    }
    let signature_algorithm = Some(signature_algorithm_name(
        &signer_info.signature_algorithm,
        scheme.as_ref(),
        digest,
    ));

    let signer_cert = find_signer(&signer_info.sid, &parsed.certificates, extra_certs);
    if signer_cert.is_none() {
        findings.fail(
            ProblemCode::SignerCertNotFound,
            "no certificate matches the SignerInfo's signer identifier",
        );
    }

    // The bytes the signature covers, already hashed.
    let mut pades_attrs = PadesAttrs::default();
    let mut message_digest_matches = None;
    let prehash: Option<Vec<u8>> = match &signer_info.signed_attrs {
        Some(raw) => {
            check_signed_attributes(
                raw,
                signer_info,
                econtent_type,
                signer_cert.as_deref(),
                &mut pades_attrs,
                &mut findings,
            );
            if let Some(digest) = digest {
                if let Some(expected) = &pades_attrs.message_digest {
                    match document_digest_for(digest) {
                        Some(actual) if &actual == expected => message_digest_matches = Some(true),
                        Some(_) => {
                            message_digest_matches = Some(false);
                            findings.note(
                                ProblemCode::DigestMismatch,
                                "the digest of the signed bytes differs from the message-digest attribute",
                            );
                        }
                        None => message_digest_matches = Some(false),
                    }
                }
                // RFC 5652 §5.4: the signature covers the DER of the SET OF, tag 0x31.
                let mut retagged = raw.clone();
                if let Some(first) = retagged.first_mut() {
                    *first = TAG_SET;
                }
                Some(digest.digest(&[&retagged]))
            } else {
                None
            }
        }
        // Without signed attributes the signature covers the content itself.
        None => digest.and_then(document_digest_for),
    };

    let mut signature_ok = false;
    if let (Some(prehash), Some(scheme), Some(digest), Some(cert_der)) =
        (&prehash, &scheme, digest, &signer_cert)
        && !findings.invalid
    {
        match check_value(
            cert_der,
            scheme,
            digest,
            prehash,
            &signer_info.signature,
            &mut findings,
        ) {
            Ok(()) => signature_ok = true,
            Err(problem) => {
                findings.problems.push(problem);
                findings.invalid = true;
            }
        }
    }
    let signature_valid = signature_ok && !findings.invalid;
    let intact = match &signer_info.signed_attrs {
        Some(_) => message_digest_matches == Some(true),
        None => signature_valid,
    };
    CmsVerification {
        intact,
        signature_valid,
        digest,
        signature_algorithm,
        signer_cert,
        pades_attrs,
        problems: findings.problems,
        warnings: findings.warnings,
    }
}

/// Verifies the signature value with the signer certificate's key.
fn check_value(
    cert_der: &[u8],
    scheme: &SignatureScheme,
    digest: DigestAlgorithm,
    prehash: &[u8],
    signature: &[u8],
    findings: &mut Findings,
) -> std::result::Result<(), Problem> {
    let key = CertParts::parse(cert_der)
        .and_then(|parts| parts.public_key())
        .map_err(|err| match err {
            Error::Unsupported(message) => Problem::new(ProblemCode::UnsupportedAlgorithm, message),
            other => Problem::new(
                ProblemCode::SignatureInvalid,
                format!("the signer certificate's key is unusable: {other}"),
            ),
        })?;
    if let KeyKind::Rsa { bits } = key.kind()
        && bits < crate::algorithms::MIN_RSA_SIGNING_BITS
    {
        findings
            .warnings
            .push(format!("the signer's RSA key has only {bits} bits"));
    }
    let result = match scheme.scheme {
        Scheme::RsaPkcs1v15 => key
            .verify_rsa_pkcs1v15(digest, prehash, signature)
            .map(|_| ()),
        Scheme::RsaPss { salt_len } => key.verify_rsa_pss(digest, salt_len, prehash, signature),
        Scheme::Ecdsa => key.verify_ecdsa(prehash, signature).map(|_| ()),
    };
    result.map_err(|VerifyFailure::Invalid(message)| {
        Problem::new(ProblemCode::SignatureInvalid, message)
    })
}

/// The report name of the signature algorithm, for example `sha256WithRSAEncryption`.
fn signature_algorithm_name(
    alg: &AlgorithmId,
    scheme: Option<&SignatureScheme>,
    digest: Option<DigestAlgorithm>,
) -> String {
    let Some(scheme) = scheme else {
        return algorithm_name(&alg.oid);
    };
    let hash = scheme.implied_hash.or(digest);
    match (scheme.scheme, hash) {
        (Scheme::RsaPss { .. }, _) => "rsassa-pss".to_owned(),
        (Scheme::RsaPkcs1v15, Some(hash)) => SignatureAlgorithm::RsaPkcs1v15
            .signature_name(hash)
            .to_owned(),
        (Scheme::Ecdsa, Some(hash)) => SignatureAlgorithm::Ecdsa.signature_name(hash).to_owned(),
        (Scheme::RsaPkcs1v15, None) => "rsaEncryption".to_owned(),
        (Scheme::Ecdsa, None) => "ecdsa".to_owned(),
    }
}

/// The certificate that `sid` names, from the CMS certificates first, then `extra`.
fn find_signer(sid: &SignerIdentifier, certs: &[Vec<u8>], extra: &[Vec<u8>]) -> Option<Vec<u8>> {
    let mut candidates = certs.iter().chain(extra.iter());
    match sid {
        SignerIdentifier::IssuerAndSerialNumber { issuer, serial } => {
            let serial_content = tlv::read_exact(serial, 2)
                .ok()
                .map(|el| el.content(serial).to_vec())?;
            candidates
                .find(|der| {
                    CertParts::parse(der).is_ok_and(|parts| {
                        cert::serials_match(parts.serial_content, &serial_content)
                            && cert::names_match(parts.issuer, issuer)
                    })
                })
                .cloned()
        }
        SignerIdentifier::SubjectKeyIdentifier(key_id) => candidates
            .find(|der| cert::subject_key_identifier(der).as_deref() == Some(key_id.as_slice()))
            .cloned(),
    }
}

/// Checks the signed attributes (brief §5 V7) and fills `pades`.
fn check_signed_attributes(
    raw: &[u8],
    signer_info: &ParsedSignerInfo,
    econtent_type: &str,
    signer_cert: Option<&[u8]>,
    pades: &mut PadesAttrs,
    findings: &mut Findings,
) {
    if let Ok(set) = tlv::read_exact(raw, MAX_DEPTH)
        && !is_der_attribute_set(raw, &set)
    {
        findings
            .warnings
            .push("signedAttrs not DER; OpenSSL would reject".to_owned());
    }
    let attrs = attributes(raw);
    let find = |dotted: &'static str| -> Vec<&Vec<Vec<u8>>> {
        let wanted = oid_bytes(dotted);
        attrs
            .iter()
            .filter(|(attr_type, _)| *attr_type == wanted)
            .map(|(_, values)| values)
            .collect()
    };

    // content-type: exactly one attribute with one OID value, equal to the eContentType.
    match unique_value(&find(oid::CONTENT_TYPE)) {
        Some(value) => {
            let content_type = tlv::read_exact(value, 2)
                .ok()
                .filter(|el| el.tag == TAG_OID)
                .and_then(|el| oid_to_string(el.content(value)));
            pades.content_type = content_type.clone();
            if content_type.as_deref() != Some(econtent_type) {
                findings.fail(
                    ProblemCode::ContentTypeMismatch,
                    "the content-type attribute differs from the eContentType",
                );
            }
        }
        None => findings.fail(
            ProblemCode::ContentTypeMismatch,
            "the content-type attribute is missing or not single-valued",
        ),
    }

    // message-digest: exactly one attribute with one OCTET STRING value.
    let message_digest = unique_value(&find(oid::MESSAGE_DIGEST)).and_then(|value| {
        tlv::read_exact(value, 2)
            .ok()
            .filter(|el| el.tag == TAG_OCTET_STRING)
            .map(|el| el.content(value).to_vec())
    });
    match message_digest {
        Some(md) => pades.message_digest = Some(md),
        None => findings.fail(
            ProblemCode::MessageDigestMissing,
            "the message-digest attribute is missing or not a single OCTET STRING",
        ),
    }

    // ESS signing-certificate-v2 (RFC 5035) and v1 (RFC 2634). pyHanko checks v2 when present,
    // else v1; so does Folioxide.
    let v2 = find(oid::SIGNING_CERTIFICATE_V2);
    let v1 = find(oid::SIGNING_CERTIFICATE);
    if !v2.is_empty() {
        let matched = unique_value(&v2)
            .zip(signer_cert)
            .is_some_and(|(value, cert)| ess_cert_id_matches(value, cert, true));
        pades.signing_certificate_v2 = Some(matched);
        if !matched && signer_cert.is_some() {
            findings.fail(
                ProblemCode::SigningCertificateMismatch,
                "the signing-certificate-v2 attribute does not identify the signer certificate",
            );
        }
    }
    if !v1.is_empty() {
        let matched = unique_value(&v1)
            .zip(signer_cert)
            .is_some_and(|(value, cert)| ess_cert_id_matches(value, cert, false));
        pades.signing_certificate_v1 = Some(matched);
        if !matched && signer_cert.is_some() && v2.is_empty() {
            findings.fail(
                ProblemCode::SigningCertificateMismatch,
                "the signing-certificate attribute does not identify the signer certificate",
            );
        }
    }

    // signing-time (RFC 5652 §11.3): reported, PAdES forbids it.
    let signing_time = find(oid::SIGNING_TIME);
    if !signing_time.is_empty() {
        pades.signing_time = Some(
            unique_value(&signing_time)
                .and_then(decode_time)
                .unwrap_or_default(),
        );
    }

    // CMSAlgorithmProtection (RFC 6211).
    let protection = find(oid::CMS_ALGORITHM_PROTECTION);
    if !protection.is_empty() {
        let ok = unique_value(&protection).is_some_and(|value| {
            algorithm_protection_matches(
                value,
                &signer_info.digest_algorithm,
                &signer_info.signature_algorithm,
            )
        });
        if !ok {
            findings.fail(
                ProblemCode::AlgorithmProtectionMismatch,
                "the CMSAlgorithmProtection attribute does not match the algorithms used",
            );
        }
    }
}

/// The single value of the single attribute in `found`, or `None`.
fn unique_value<'a>(found: &[&'a Vec<Vec<u8>>]) -> Option<&'a [u8]> {
    match found {
        [values] => match values.as_slice() {
            [value] => Some(value.as_slice()),
            _ => None,
        },
        _ => None,
    }
}

/// Whether the attribute set is DER: minimal definite lengths, no constructed strings, the
/// attributes and each attribute's values in DER `SET OF` order (X.690 §10, §11.6).
fn is_der_attribute_set(raw: &[u8], set: &Element) -> bool {
    if !set.minimal_length || set.indefinite {
        return false;
    }
    let mut previous: Option<&[u8]> = None;
    for attribute in tlv::children(raw, set, 0, MAX_DEPTH) {
        let Ok(attribute) = attribute else {
            return false;
        };
        let encoded = attribute.raw(raw);
        if previous.is_some_and(|p| tlv::der_set_order(p, encoded) == std::cmp::Ordering::Greater) {
            return false;
        }
        previous = Some(encoded);
        if !tlv::is_der_tree(raw, &attribute, 1, MAX_DEPTH) {
            return false;
        }
    }
    true
}

/// Checks the first `ESSCertID(v2)` of a `SigningCertificate(V2)` value against `cert`:
/// certHash, and issuerSerial when present (RFC 5035 §4, RFC 2634 §5.4.1; as pyHanko's
/// `check_ess_certid`).
fn ess_cert_id_matches(value: &[u8], cert: &[u8], v2: bool) -> bool {
    let Ok(outer) = tlv::read_exact(value, MAX_DEPTH) else {
        return false;
    };
    let Some(Ok(certs)) = tlv::children(value, &outer, 0, MAX_DEPTH).next() else {
        return false;
    };
    let Some(Ok(cert_id)) = tlv::children(value, &certs, 1, MAX_DEPTH).next() else {
        return false;
    };
    let fields: Vec<Element> = tlv::children(value, &cert_id, 2, MAX_DEPTH)
        .filter_map(std::result::Result::ok)
        .collect();
    let mut fields = fields.iter().peekable();
    let mut hash = DigestAlgorithm::Sha1;
    if v2 {
        hash = DigestAlgorithm::Sha256;
        if let Some(alg) = fields.next_if(|f| f.tag == TAG_SEQUENCE) {
            match algorithm_id(value, alg, 3).ok().and_then(|a| a.digest()) {
                Some(digest) => hash = digest,
                None => return false,
            }
        }
    }
    let Some(cert_hash) = fields.next().filter(|f| f.tag == TAG_OCTET_STRING) else {
        return false;
    };
    if cert_hash.content(value) != hash.digest(&[cert]).as_slice() {
        return false;
    }
    match fields.next() {
        None => true,
        Some(issuer_serial) => issuer_serial_matches(value, issuer_serial, cert),
    }
}

/// `IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber, issuerUID OPTIONAL }`: exactly
/// one GeneralName, a directoryName equal to the certificate's issuer, and the same serial.
fn issuer_serial_matches(input: &[u8], issuer_serial: &Element, cert: &[u8]) -> bool {
    let Ok(parts) = CertParts::parse(cert) else {
        return false;
    };
    let fields: Vec<Element> = tlv::children(input, issuer_serial, 3, MAX_DEPTH)
        .filter_map(std::result::Result::ok)
        .collect();
    let (Some(general_names), Some(serial)) = (fields.first(), fields.get(1)) else {
        return false;
    };
    if general_names.tag != TAG_SEQUENCE || serial.tag != TAG_INTEGER {
        return false;
    }
    let names: Vec<Element> = tlv::children(input, general_names, 4, MAX_DEPTH)
        .filter_map(std::result::Result::ok)
        .collect();
    let [directory_name] = names.as_slice() else {
        return false;
    };
    if directory_name.tag != TAG_CONTEXT_4 {
        return false;
    }
    let name = directory_name.content(input);
    cert::names_match(name, parts.issuer)
        && cert::serials_match(serial.content(input), parts.serial_content)
}

/// `CMSAlgorithmProtection ::= SEQUENCE { digestAlgorithm, signatureAlgorithm [1] IMPLICIT
/// OPTIONAL, macAlgorithm [2] IMPLICIT OPTIONAL }` (RFC 6211 §2): the digest algorithm and,
/// for a SignedData, the signature algorithm must equal the SignerInfo's (pyHanko's
/// `validate_algorithm_protection`).
fn algorithm_protection_matches(
    value: &[u8],
    digest: &AlgorithmId,
    signature: &AlgorithmId,
) -> bool {
    let Ok(seq) = tlv::read_exact(value, MAX_DEPTH) else {
        return false;
    };
    let fields: Vec<Element> = tlv::children(value, &seq, 0, MAX_DEPTH)
        .filter_map(std::result::Result::ok)
        .collect();
    let Some(Ok(protected_digest)) = fields.first().map(|f| algorithm_id(value, f, 1)) else {
        return false;
    };
    if !same_algorithm(&protected_digest, digest) {
        return false;
    }
    let Some(signature_field) = fields.iter().find(|f| f.tag == TAG_CONTEXT_1) else {
        // Not valid for signed data without a signature algorithm.
        return false;
    };
    // [1] IMPLICIT AlgorithmIdentifier: re-tag the field as a SEQUENCE to read it.
    let mut retagged = signature_field.raw(value).to_vec();
    if let Some(first) = retagged.first_mut() {
        *first = TAG_SEQUENCE;
    }
    let protected_signature = tlv::read_exact(&retagged, MAX_DEPTH)
        .ok()
        .and_then(|el| algorithm_id(&retagged, &el, 0).ok());
    protected_signature.is_some_and(|p| same_algorithm(&p, signature))
}

/// A `Time` (UTCTime or GeneralizedTime) as RFC 3339 UTC.
fn decode_time(value: &[u8]) -> Option<String> {
    let element = tlv::read_exact(value, 2).ok()?;
    let time = match element.tag {
        TAG_UTC_TIME => der::asn1::UtcTime::from_der(value).ok()?.to_date_time(),
        TAG_GENERALIZED_TIME => der::asn1::GeneralizedTime::from_der(value)
            .ok()?
            .to_date_time(),
        _ => return None,
    };
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minutes(),
        time.seconds()
    ))
}

/// See [`super::verify_and_normalize`].
pub(crate) fn verify_and_normalize(
    cert_der: &[u8],
    alg: SignatureAlgorithm,
    digest: DigestAlgorithm,
    to_be_signed: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>> {
    let key: PublicKey = CertParts::parse(cert_der)?.public_key()?;
    if key.kind().algorithm() != alg {
        return Err(Error::InvalidArgument(format!(
            "the certificate holds a {:?} key, which cannot verify {alg} signatures",
            key.kind()
        )));
    }
    let hashed = digest.digest(&[to_be_signed]);
    let result = match alg {
        SignatureAlgorithm::RsaPkcs1v15 => key.verify_rsa_pkcs1v15(digest, &hashed, signature),
        SignatureAlgorithm::Ecdsa => key.verify_ecdsa(&hashed, signature),
    };
    result.map_err(|VerifyFailure::Invalid(message)| Error::SignatureInvalid(message))
}

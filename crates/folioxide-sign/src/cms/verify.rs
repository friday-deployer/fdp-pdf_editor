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
/// Also read for an `id-RSASSA-PSS` SubjectPublicKeyInfo, whose parameters restrict the key
/// (RFC 4055 §3.1; [`PublicKey::from_spki_der`]).
///
/// The SEQUENCE is read as its definition orders it (M4 final fix round 2, finding 2): each
/// field at most once and in the order `[0]`, `[1]`, `[2]`, `[3]`, each explicit tag holding
/// exactly one element, the INTEGERs minimal, and nothing else before the SEQUENCE's end. A
/// repeated or out-of-order field is no `RSASSA-PSS-params` (X.680 §25, X.690 §8.9):
/// asn1crypto refuses it ("Unknown element") and OpenSSL's template decoder cannot decode such
/// a key, whereas a reader that lets a repeated field overwrite the earlier one takes another
/// hash or salt length than a first-wins reader (pyHanko compares the first salt length). A
/// default written out (`[0]` sha1, `[2] 20`) stays accepted, as by both references.
///
/// The two hash AlgorithmIdentifiers, the one of `[0]` and the one MGF1 takes as its
/// parameter, have absent or NULL parameters and nothing else (RFC 4055 §2.1: the SHA
/// functions take no parameters, and implementations "MUST accept" both encodings; M4 closing
/// round, finding 7). pyHanko compares a key's parameters with a signature's structurally, so
/// an INTEGER, an empty OCTET STRING or an empty SEQUENCE there had made a PSS-keyed trust
/// anchor that pyHanko does not trust verify its certificates here.
pub(crate) fn pss_parameters(
    params: Option<&[u8]>,
) -> std::result::Result<(DigestAlgorithm, usize), String> {
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
    // The position of the field read last: the next one must come later in the definition.
    let mut last: Option<u8> = None;
    for field in tlv::children(params, &seq, 0, 8) {
        let field = field.map_err(|_| bad("malformed"))?;
        let position = match field.tag {
            TAG_CONTEXT_0 => 0,
            TAG_CONTEXT_1 => 1,
            TAG_CONTEXT_2 => 2,
            TAG_CONTEXT_3 => 3,
            _ => return Err(bad("unknown field")),
        };
        if last.is_some_and(|last| position <= last) {
            return Err(bad("unknown field (a field repeated or out of order)"));
        }
        last = Some(position);
        let inner = match tlv::children_vec(params, &field, 1, 8, 1).as_deref() {
            Ok([inner]) => *inner,
            Ok(_) => return Err(bad("empty field")),
            Err(_) => return Err(bad("a field that is not one element")),
        };
        match field.tag {
            TAG_CONTEXT_0 => {
                let alg = algorithm_id(params, &inner, 2).map_err(|_| bad("hashAlgorithm"))?;
                if !null_or_absent(alg.parameters.as_deref()) {
                    return Err(bad(
                        "unknown field (hashAlgorithm parameters that are neither absent nor \
                         NULL, RFC 4055 §2.1)",
                    ));
                }
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
                if !null_or_absent(mgf_alg.parameters.as_deref()) {
                    return Err(bad(
                        "unknown field (MGF1 hash parameters that are neither absent nor NULL, \
                         RFC 4055 §2.1)",
                    ));
                }
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

/// Whether AlgorithmIdentifier `parameters` (the whole element) are absent or exactly a DER
/// NULL (`05 00`).
pub(crate) fn null_or_absent(parameters: Option<&[u8]>) -> bool {
    parameters.is_none_or(|p| p == [tlv::TAG_NULL, 0x00])
}

/// The value of a minimal, non-negative INTEGER of at most four octets (X.690 §8.3.2).
fn small_unsigned(content: &[u8], tag: u8) -> Option<usize> {
    if tag != TAG_INTEGER {
        return None;
    }
    let value = tlv::integer_canonical(content);
    if value.len() != content.len()
        || value.is_empty()
        || value.len() > 4
        || value.first().is_some_and(|&b| b & 0x80 != 0)
    {
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
    a.oid == b.oid
        && (a.parameters == b.parameters
            || (null_or_absent(a.parameters.as_deref()) && null_or_absent(b.parameters.as_deref())))
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

/// What kind of SignedData a verification expects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Content<'a> {
    /// A detached signature over external data: eContentType `id-data`, no eContent, and an
    /// ESS signing-certificate attribute that does not match the signer makes the signature
    /// invalid.
    Detached,
    /// Encapsulated content of this eContentType (a timestamp token's TSTInfo): eContent
    /// present; the ESS attributes are only reported in `pades_attrs` (the caller decides,
    /// M4 brief §5 V7b step 5).
    Encapsulated(&'a str),
}

/// See [`super::verify_detached`].
pub(crate) fn verify_detached(
    parsed: &ParsedCms,
    document_digest_for: &dyn Fn(DigestAlgorithm) -> Option<Vec<u8>>,
    extra_certs: &[Vec<u8>],
) -> CmsVerification {
    verify_signed_data(parsed, Content::Detached, document_digest_for, extra_certs)
}

/// See [`super::verify_encapsulated`].
pub(crate) fn verify_encapsulated(
    parsed: &ParsedCms,
    expected_econtent_type: &str,
    extra_certs: &[Vec<u8>],
) -> CmsVerification {
    let content = parsed.econtent.as_deref();
    let content_digest = |digest: DigestAlgorithm| content.map(|c| digest.digest(&[c]));
    verify_signed_data(
        parsed,
        Content::Encapsulated(expected_econtent_type),
        &content_digest,
        extra_certs,
    )
}

/// The verification of [`verify_detached`] and [`verify_encapsulated`]: `content_digest_for(d)`
/// is the digest with `d` of the signed content (the external data, or the eContent octets).
fn verify_signed_data(
    parsed: &ParsedCms,
    content: Content<'_>,
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
    match content {
        Content::Detached => {
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
        }
        Content::Encapsulated(expected) => {
            if econtent_type != expected {
                findings.fail(
                    ProblemCode::ContentTypeMismatch,
                    format!("the eContentType is {econtent_type}, not {expected}"),
                );
            }
            if parsed.econtent.is_none() {
                findings.fail(
                    ProblemCode::CmsMalformed,
                    "the SignedData has no encapsulated content",
                );
            }
        }
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
                content == Content::Detached,
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
        // An embedded value: strict DER only, as OpenSSL verifies it (M4 QA finding F1; the
        // P1363 and non-minimal tolerance is for `finish` only, `verify_and_normalize`).
        Scheme::Ecdsa => key.verify_ecdsa_der(prehash, signature),
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

/// Checks the signed attributes (brief §5 V7) and fills `pades`. With `ess_fails`, an ESS
/// signing-certificate attribute that does not identify the signer makes the signature invalid;
/// without it the attribute is only reported in `pades`.
fn check_signed_attributes(
    raw: &[u8],
    signer_info: &ParsedSignerInfo,
    econtent_type: &str,
    signer_cert: Option<&[u8]>,
    ess_fails: bool,
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
        if ess_fails && !matched && signer_cert.is_some() {
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
        if ess_fails && !matched && signer_cert.is_some() && v2.is_empty() {
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
/// attributes and each attribute's values in DER `SET OF` order (X.690 §10, §11.6), BOOLEANs
/// `00` or `FF` and BIT STRINGs with clear unused bits (§11.1, §11.2.1).
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
        if !tlv::is_der_tree(raw, &attribute, 1, MAX_DEPTH)
            || !tlv::der_primitive_contents(raw, &attribute, 1, MAX_DEPTH)
        {
            return false;
        }
    }
    true
}

/// Whether the raw `signedAttrs` element (`[0] IMPLICIT SET OF Attribute`) is DER, as
/// [`is_der_attribute_set`] checks it. RFC 5652 §5.4 computes the signature over the DER
/// encoding of the attributes, and verifiers that re-encode before they verify (OpenSSL's
/// `PKCS7_signatureVerify` re-encodes each attribute and sorts its values; BouncyCastle, under EU
/// DSS, re-encodes the whole set) refuse a signature made over any other encoding (M4 QA round
/// 3 finding 2).
pub(crate) fn signed_attributes_are_der(raw: &[u8]) -> bool {
    tlv::read_exact(raw, MAX_DEPTH).is_ok_and(|set| is_der_attribute_set(raw, &set))
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

/// The most `ESSCertID`s [`check_signing_certificates`] reads in one attribute.
const MAX_ESS_CERT_IDS: usize = crate::cms::MAX_CERTIFICATES;

/// One `ESSCertID` (RFC 2634 §5.4.1) or `ESSCertIDv2` (RFC 5035 §4), read strictly.
struct EssCertId<'a> {
    /// The hash algorithm of `cert_hash` (SHA-1 for v1, the DEFAULT SHA-256 for v2).
    hash: DigestAlgorithm,
    /// The certificate hash.
    cert_hash: &'a [u8],
    /// The `IssuerSerial`, when present (in `value`).
    issuer_serial: Option<Element>,
}

/// The `ESSCertID(v2)`s of a `SigningCertificate(V2)` attribute value (RFC 2634 §5.4, RFC 5035
/// §3), read as a whitelist: `SEQUENCE { certs SEQUENCE OF ESSCertID(v2), policies SEQUENCE
/// OPTIONAL }` with at least one and at most [`MAX_ESS_CERT_IDS`] identifiers; each one a
/// hash algorithm Folioxide implements with absent or NULL parameters (v2 only; RFC 5754 §2), a
/// certHash of that algorithm's length, and an optional `IssuerSerial`, nothing else. A
/// timestamp token's attribute has already been decoded whole, `policies` and the issuer names
/// included, by the token's shape check (`tsp::shape`, QA round 3 finding 3); this reads what
/// the binding needs.
fn ess_cert_ids(value: &[u8], v2: bool) -> std::result::Result<Vec<EssCertId<'_>>, String> {
    let malformed = |what: &str| format!("the signing-certificate attribute is malformed: {what}");
    let outer = tlv::read_exact(value, MAX_DEPTH).map_err(|e| malformed(&e.to_string()))?;
    let parts = tlv::children_vec(value, &outer, 0, MAX_DEPTH, 2)
        .map_err(|_| malformed("more than certs and policies"))?;
    let (certs, policies) = match parts.as_slice() {
        [certs] => (certs, None),
        [certs, policies] => (certs, Some(policies)),
        _ => return Err(malformed("no certs")),
    };
    if outer.tag != TAG_SEQUENCE
        || certs.tag != TAG_SEQUENCE
        || policies.is_some_and(|p| p.tag != TAG_SEQUENCE)
    {
        return Err(malformed("not a SEQUENCE"));
    }
    let ids = tlv::children_vec(value, certs, 1, MAX_DEPTH, MAX_ESS_CERT_IDS).map_err(|_| {
        malformed(&format!(
            "more than {MAX_ESS_CERT_IDS} certificate identifiers"
        ))
    })?;
    if ids.is_empty() {
        return Err(malformed("the list of certificate identifiers is empty"));
    }
    let mut out = Vec::with_capacity(ids.len());
    for id in &ids {
        let fields = tlv::children_vec(value, id, 2, MAX_DEPTH, 3)
            .map_err(|_| malformed("an identifier has too many fields"))?;
        if id.tag != TAG_SEQUENCE {
            return Err(malformed("an identifier is not a SEQUENCE"));
        }
        let mut fields = fields.iter().peekable();
        let mut hash = if v2 {
            DigestAlgorithm::Sha256
        } else {
            DigestAlgorithm::Sha1
        };
        if v2 && let Some(algorithm) = fields.next_if(|f| f.tag == TAG_SEQUENCE) {
            let algorithm = algorithm_id(value, algorithm, 3)
                .map_err(|_| malformed("the hash algorithm does not parse"))?;
            hash = algorithm
                .digest()
                .filter(|_| {
                    algorithm
                        .parameters
                        .as_deref()
                        .is_none_or(|p| p == [0x05, 0x00])
                })
                .ok_or_else(|| {
                    format!(
                        "the signing-certificate-v2 hash algorithm {} is not supported (or has \
                         parameters other than NULL)",
                        algorithm.oid
                    )
                })?;
        }
        let cert_hash = fields
            .next()
            .filter(|f| f.tag == TAG_OCTET_STRING)
            .map(|f| f.content(value))
            .ok_or_else(|| malformed("an identifier has no certHash OCTET STRING"))?;
        if cert_hash.len() != hash.output_len() {
            return Err(malformed(&format!(
                "a {hash} certHash has {} bytes, not {}",
                cert_hash.len(),
                hash.output_len()
            )));
        }
        let issuer_serial = fields.next().copied();
        if issuer_serial.is_some_and(|f| f.tag != TAG_SEQUENCE) || fields.next().is_some() {
            return Err(malformed(
                "an identifier holds more than a hash algorithm, a certHash and an IssuerSerial",
            ));
        }
        out.push(EssCertId {
            hash,
            cert_hash,
            issuer_serial,
        });
    }
    Ok(out)
}

/// Whether `id` (read from `value`) identifies `cert`: its certHash, and its `IssuerSerial` when
/// present, which must be exactly `{ issuer, serialNumber }` (RFC 5035 §4, as OpenSSL's
/// `ESS_ISSUER_SERIAL`).
fn ess_cert_id_names(value: &[u8], id: &EssCertId<'_>, cert: &[u8], cert_digest: &[u8]) -> bool {
    id.cert_hash == cert_digest
        && id.issuer_serial.is_none_or(|issuer_serial| {
            tlv::children_vec(value, &issuer_serial, 3, MAX_DEPTH, 2).is_ok_and(|f| f.len() == 2)
                && issuer_serial_matches(value, &issuer_serial, cert)
        })
}

/// The certificates that the later identifiers of an ESS signing-certificate attribute may name
/// ([`check_signing_certificates`]).
#[derive(Clone, Copy, Debug)]
pub(crate) enum EssIssuers<'a> {
    /// The certificates of this pool linked to the signer by verified issuer signatures
    /// ([`linked_issuers`](crate::x509info::linked_issuers)): the stand-in for a verified chain
    /// when no validated path is at hand.
    Linked(&'a [Vec<u8>]),
    /// Exactly these certificates: a validated certification path above the signer, its trust
    /// anchor included, which is the chain OpenSSL checks them against.
    Path(&'a [Vec<u8>]),
}

/// Checks the ESS signing-certificate binding of a timestamp token as OpenSSL's
/// `OSSL_ESS_check_signing_certs` does (RFC 3161 §2.4.1, RFC 5035 §5.4, RFC 2634 §5.4; M4 QA
/// round 1 finding F3): at least one of signing-certificate (v1) and signing-certificate-v2
/// is present among the raw `signed_attrs`; **each** one present is a single attribute with
/// one value; its first identifier names `signer`, and every later identifier names one of the
/// `issuers` other than `signer` (OpenSSL: a later identifier that names the signer is
/// `ESS_R_ESS_CERT_ID_WRONG_ORDER`). pyHanko only reads the first identifier of v2 (or of v1
/// without v2).
///
/// The issuers are never found by name alone (M4 QA round 2 finding 3): a decoy certificate
/// that carries an issuer's subject name but not its key is not linked by a verified
/// signature, so a later identifier naming it fails, as it fails in OpenSSL, which looks for it
/// in the verified chain.
///
/// # Errors
/// What is wrong, as one sentence.
pub(crate) fn check_signing_certificates(
    signed_attrs: &[u8],
    signer: &[u8],
    issuers: EssIssuers<'_>,
) -> std::result::Result<(), String> {
    let attrs = attributes(signed_attrs);
    let mut present = 0;
    let mut chain: Option<Vec<&[u8]>> = None;
    let mut digests: std::collections::HashMap<(DigestAlgorithm, usize), Vec<u8>> =
        std::collections::HashMap::new();
    for (dotted, v2, name) in [
        (oid::SIGNING_CERTIFICATE_V2, true, "signing-certificate-v2"),
        (oid::SIGNING_CERTIFICATE, false, "signing-certificate"),
    ] {
        let wanted = oid_bytes(dotted);
        let found: Vec<&Vec<Vec<u8>>> = attrs
            .iter()
            .filter(|(attr_type, _)| *attr_type == wanted)
            .map(|(_, values)| values)
            .collect();
        if found.is_empty() {
            continue;
        }
        present += 1;
        let value = unique_value(&found)
            .ok_or_else(|| format!("the {name} attribute is not one attribute with one value"))?;
        let ids = ess_cert_ids(value, v2)?;
        let mut ids = ids.iter();
        if !ids.next().is_some_and(|first| {
            ess_cert_id_names(value, first, signer, &first.hash.digest(&[signer]))
        }) {
            return Err(format!(
                "the first identifier of the {name} attribute does not name the TSA certificate"
            ));
        }
        for later in ids {
            let chain = chain.get_or_insert_with(|| match issuers {
                EssIssuers::Linked(pool) => crate::x509info::linked_issuers(signer, pool),
                EssIssuers::Path(path) => path
                    .iter()
                    .map(Vec::as_slice)
                    .filter(|cert| *cert != signer)
                    .collect(),
            });
            // Each certificate is hashed once per algorithm, however many identifiers there are.
            let named = chain.iter().enumerate().any(|(index, cert)| {
                let digest = digests
                    .entry((later.hash, index))
                    .or_insert_with(|| later.hash.digest(&[cert]));
                ess_cert_id_names(value, later, cert, digest)
            });
            if !named {
                return Err(match issuers {
                    EssIssuers::Linked(_) => format!(
                        "a later identifier of the {name} attribute names no certificate that \
                         issued the TSA certificate or one of its issuers (each checked by name \
                         and signature)"
                    ),
                    EssIssuers::Path(_) => format!(
                        "a later identifier of the {name} attribute names no certificate of the \
                         TSA certificate's validated path to the trust anchor, which is where \
                         OpenSSL looks for it"
                    ),
                });
            }
        }
    }
    if present == 0 {
        return Err("the token has no ESS signing-certificate attribute (v1 or v2)".to_owned());
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cms::tlv::{TAG_NULL, tlv, tlv_parts};

    /// The raw `signedAttrs` (`[0]`) holding `attrs` (whole `Attribute`s).
    fn signed_attrs(attrs: &[Vec<u8>]) -> Vec<u8> {
        tlv(TAG_CONTEXT_0, &attrs.concat())
    }

    /// An `Attribute` of the dotted type `oid` with the single value `value`.
    fn attribute(dotted: &'static str, value: &[u8]) -> Vec<u8> {
        tlv_parts(
            TAG_SEQUENCE,
            &[&tlv(TAG_OID, &oid_bytes(dotted)), &tlv(TAG_SET, value)],
        )
    }

    /// `SigningCertificate(V2) { certs { ids } }`.
    fn signing_certificate(ids: &[Vec<u8>]) -> Vec<u8> {
        tlv(TAG_SEQUENCE, &tlv(TAG_SEQUENCE, &ids.concat()))
    }

    /// An `ESSCertID(v2)` without issuerSerial: `fields` then the certHash.
    fn cert_id(fields: &[&[u8]], hash: &[u8]) -> Vec<u8> {
        let mut content: Vec<u8> = fields.concat();
        content.extend(tlv(TAG_OCTET_STRING, hash));
        tlv(TAG_SEQUENCE, &content)
    }

    #[test]
    fn ess_attributes_are_read_as_a_whitelist() {
        // Not a certificate: nothing here parses it, the identifiers name its bytes.
        let tsa: &[u8] = b"the TSA certificate";
        let sha256 = DigestAlgorithm::Sha256.digest(&[tsa]);
        let sha1 = DigestAlgorithm::Sha1.digest(&[tsa]);
        let v2 =
            |ids: &[Vec<u8>]| attribute(oid::SIGNING_CERTIFICATE_V2, &signing_certificate(ids));
        let v1 = |ids: &[Vec<u8>]| attribute(oid::SIGNING_CERTIFICATE, &signing_certificate(ids));
        let check = |attrs: &[Vec<u8>]| {
            check_signing_certificates(&signed_attrs(attrs), tsa, EssIssuers::Linked(&[]))
        };

        assert_eq!(check(&[v2(&[cert_id(&[], &sha256)])]), Ok(()));
        assert_eq!(check(&[v1(&[cert_id(&[], &sha1)])]), Ok(()));
        assert_eq!(
            check(&[v2(&[cert_id(&[], &sha256)]), v1(&[cert_id(&[], &sha1)])]),
            Ok(())
        );
        let sha384 = tlv(TAG_SEQUENCE, &tlv(TAG_OID, &oid_bytes(oid::SHA384)));
        let sha384_hash = DigestAlgorithm::Sha384.digest(&[tsa]);
        assert_eq!(check(&[v2(&[cert_id(&[&sha384], &sha384_hash)])]), Ok(()));

        let refused = |attrs: &[Vec<u8>], why: &str| {
            let err = check(attrs).unwrap_err();
            assert!(err.contains(why), "{why}: {err}");
        };
        refused(&[], "no ESS signing-certificate attribute");
        // Each attribute present is checked (OpenSSL), not v2 alone (pyHanko).
        refused(
            &[v2(&[cert_id(&[], &sha256)]), v1(&[cert_id(&[], &[0; 20])])],
            "first identifier of the signing-certificate attribute",
        );
        // A later identifier must name a certificate of the chain: here there is none.
        refused(
            &[v2(&[cert_id(&[], &sha256), cert_id(&[], &[7; 32])])],
            "a later identifier",
        );
        refused(&[v2(&[])], "list of certificate identifiers is empty");
        refused(
            &[v2(&[cert_id(&[], &sha256[..31])])],
            "certHash has 31 bytes",
        );
        let sha256_octets = tlv(
            TAG_SEQUENCE,
            &[
                tlv(TAG_OID, &oid_bytes(oid::SHA256)),
                tlv(TAG_OCTET_STRING, &[]),
            ]
            .concat(),
        );
        refused(
            &[v2(&[cert_id(&[&sha256_octets], &sha256)])],
            "not supported (or has parameters other than NULL)",
        );
        let unknown = tlv(TAG_SEQUENCE, &tlv(TAG_OID, &[0x2A, 0x03]));
        refused(
            &[v2(&[cert_id(&[&unknown], &sha256)])],
            "1.2.3 is not supported",
        );
        // Something after the issuerSerial, too many fields, an issuerSerial that is no SEQUENCE.
        let null = tlv(TAG_NULL, &[]);
        let after = [
            tlv(TAG_OCTET_STRING, &sha256),
            tlv(TAG_SEQUENCE, &[]),
            null.clone(),
        ]
        .concat();
        refused(
            &[v2(&[tlv(TAG_SEQUENCE, &after)])],
            "more than a hash algorithm",
        );
        let four = [after, null].concat();
        refused(&[v2(&[tlv(TAG_SEQUENCE, &four)])], "too many fields");
        let not_sequence = [tlv(TAG_OCTET_STRING, &sha256), tlv(TAG_INTEGER, &[1])].concat();
        refused(
            &[v2(&[tlv(TAG_SEQUENCE, &not_sequence)])],
            "more than a hash algorithm",
        );
        // One attribute with two values, and two attributes.
        let two_values = tlv_parts(
            TAG_SEQUENCE,
            &[
                &tlv(TAG_OID, &oid_bytes(oid::SIGNING_CERTIFICATE_V2)),
                &tlv_parts(
                    TAG_SET,
                    &[
                        &signing_certificate(&[cert_id(&[], &sha256)]),
                        &signing_certificate(&[cert_id(&[], &sha256)]),
                    ],
                ),
            ],
        );
        refused(&[two_values], "not one attribute with one value");
        let once = v2(&[cert_id(&[], &sha256)]);
        refused(&[once.clone(), once], "not one attribute with one value");
        // Garbage values never panic.
        refused(
            &[attribute(oid::SIGNING_CERTIFICATE_V2, &[0x05, 0x00])],
            "malformed",
        );
        assert!(check_signing_certificates(b"garbage", tsa, EssIssuers::Linked(&[])).is_err());
        assert!(check_signing_certificates(b"garbage", tsa, EssIssuers::Path(&[])).is_err());
    }

    #[test]
    fn later_identifiers_name_a_listed_issuer_other_than_the_signer() {
        // Not certificates: with `Path`, nothing parses them, the identifiers name their bytes.
        let tsa: &[u8] = b"the TSA certificate";
        let root = b"the root".to_vec();
        let hash = |c: &[u8]| DigestAlgorithm::Sha256.digest(&[c]);
        let v2 = |ids: &[Vec<u8>]| {
            signed_attrs(&[attribute(
                oid::SIGNING_CERTIFICATE_V2,
                &signing_certificate(ids),
            )])
        };
        let path = [tsa.to_vec(), root.clone()];
        let named = v2(&[cert_id(&[], &hash(tsa)), cert_id(&[], &hash(&root))]);
        assert_eq!(
            check_signing_certificates(&named, tsa, EssIssuers::Path(&path)),
            Ok(())
        );
        // The root is not a linked issuer of bytes that are no certificate.
        let err = check_signing_certificates(&named, tsa, EssIssuers::Linked(&path)).unwrap_err();
        assert!(err.contains("checked by name and signature"), "{err}");
        // A later identifier never names the signer itself (OpenSSL: wrong order).
        let twice = v2(&[cert_id(&[], &hash(tsa)), cert_id(&[], &hash(tsa))]);
        let err = check_signing_certificates(&twice, tsa, EssIssuers::Path(&path)).unwrap_err();
        assert!(err.contains("validated path to the trust anchor"), "{err}");
    }

    #[test]
    fn pss_parameters_are_read_in_their_order_each_field_once() {
        // M4 final fix round 2, finding 2: a repeated or out-of-order field let the last
        // value win, where pyHanko reads the first and OpenSSL cannot decode the parameters.
        let hash = |dotted: &'static str| {
            tlv_parts(
                TAG_SEQUENCE,
                &[&tlv(TAG_OID, &oid_bytes(dotted)), &[TAG_NULL, 0x00]],
            )
        };
        let sha256 = hash("2.16.840.1.101.3.4.2.1");
        let sha1 = hash("1.3.14.3.2.26");
        let mgf1 = |h: &[u8]| tlv_parts(TAG_SEQUENCE, &[&tlv(TAG_OID, &oid_bytes(oid::MGF1)), h]);
        let int = |v: &[u8]| tlv(TAG_INTEGER, v);
        let params = |fields: &[Vec<u8>]| tlv(TAG_SEQUENCE, &fields.concat());
        let f0 = |h: &[u8]| tlv(TAG_CONTEXT_0, h);
        let f1 = |h: &[u8]| tlv(TAG_CONTEXT_1, &mgf1(h));
        let f2 = |v: &[u8]| tlv(TAG_CONTEXT_2, &int(v));
        let f3 = |v: &[u8]| tlv(TAG_CONTEXT_3, &int(v));
        let read = |fields: &[Vec<u8>]| pss_parameters(Some(&params(fields)));

        // Accepted: the defaults, absent or written out, and every field once, in order.
        assert_eq!(pss_parameters(None), Ok((DigestAlgorithm::Sha1, 20)));
        assert_eq!(read(&[]), Ok((DigestAlgorithm::Sha1, 20)));
        assert_eq!(
            read(&[f0(&sha1), f1(&sha1), f2(&[20]), f3(&[1])]),
            Ok((DigestAlgorithm::Sha1, 20))
        );
        assert_eq!(
            read(&[f0(&sha256), f1(&sha256), f2(&[32])]),
            Ok((DigestAlgorithm::Sha256, 32))
        );
        assert_eq!(
            read(&[f0(&sha256), f1(&sha256), f2(&[0x00, 0x80])]),
            Ok((DigestAlgorithm::Sha256, 128))
        );

        // Refused: QA's variants (r8-pss-spkiq-dup-hash-last-sha1, -dup-salt-last-20,
        // -out-of-order; r8-pss-tokparams-dup-hash-last-sha1, -dup-salt-last-20) and their
        // neighbours.
        let refused: [(&str, Vec<Vec<u8>>); 9] = [
            (
                "hash twice",
                vec![f0(&sha256), f0(&sha1), f1(&sha1), f2(&[20])],
            ),
            (
                "salt twice",
                vec![f0(&sha1), f1(&sha1), f2(&[64]), f2(&[20])],
            ),
            ("mgf twice", vec![f0(&sha1), f1(&sha256), f1(&sha1)]),
            ("trailer twice", vec![f3(&[1]), f3(&[1])]),
            ("out of order", vec![f1(&sha1), f0(&sha1), f2(&[20])]),
            (
                "salt before hash",
                vec![f2(&[32]), f0(&sha256), f1(&sha256)],
            ),
            (
                "two elements in one field",
                vec![tlv(TAG_CONTEXT_2, &[int(&[32]), int(&[20])].concat())],
            ),
            ("a padded salt length", vec![f2(&[0x00, 0x20])]),
            (
                "an element after the fields",
                vec![f0(&sha256), f1(&sha256), f2(&[32]), int(&[1])],
            ),
        ];
        for (name, fields) in refused {
            assert!(read(&fields).is_err(), "{name}: {:?}", read(&fields));
        }
        let err = read(&[f0(&sha256), f0(&sha1)]).unwrap_err();
        assert!(err.contains("repeated or out of order"), "{err}");
        // An empty explicit tag, and bytes after the SEQUENCE.
        assert!(read(&[tlv(TAG_CONTEXT_0, &[])]).is_err());
        let mut trailing = params(&[f2(&[20])]);
        trailing.push(0x00);
        assert!(pss_parameters(Some(&trailing)).is_err());
    }

    #[test]
    fn pss_hash_parameters_are_absent_or_null() {
        // M4 closing round, finding 7 (variants r9-pssanchor-int-hash-only, -int-mgf-only,
        // -int-both, -octets-both, -seq-both, r9-pss256-anchor-hash-alg-int-params): RFC 4055
        // §2.1 allows only absent or NULL parameters on the hash AlgorithmIdentifiers, and
        // pyHanko compares them structurally.
        let sha256 = |parameters: &[&[u8]]| {
            let mut parts: Vec<&[u8]> = Vec::new();
            let oid = tlv(TAG_OID, &oid_bytes("2.16.840.1.101.3.4.2.1"));
            parts.push(&oid);
            parts.extend_from_slice(parameters);
            tlv_parts(TAG_SEQUENCE, &parts)
        };
        let mgf1 = |h: &[u8]| tlv_parts(TAG_SEQUENCE, &[&tlv(TAG_OID, &oid_bytes(oid::MGF1)), h]);
        let read = |hash: &[u8], mgf_hash: &[u8]| {
            let fields = [
                tlv(TAG_CONTEXT_0, hash),
                tlv(TAG_CONTEXT_1, &mgf1(mgf_hash)),
                tlv(TAG_CONTEXT_2, &tlv(TAG_INTEGER, &[32])),
            ];
            pss_parameters(Some(&tlv(TAG_SEQUENCE, &fields.concat())))
        };
        let null: &[u8] = &[TAG_NULL, 0x00];
        let (with_null, absent) = (sha256(&[null]), sha256(&[]));
        // Accepted: NULL or absent, in both places and in any mix (the r9 controls).
        for (hash, mgf_hash) in [
            (&with_null, &with_null),
            (&absent, &absent),
            (&with_null, &absent),
            (&absent, &with_null),
        ] {
            assert_eq!(read(hash, mgf_hash), Ok((DigestAlgorithm::Sha256, 32)));
        }
        // Refused: any other parameters, in the hash, in the MGF1 hash, or in both.
        let integer = tlv(TAG_INTEGER, &[1]);
        let octets = tlv(TAG_OCTET_STRING, &[]);
        let sequence = tlv(TAG_SEQUENCE, &[]);
        let null_with_content = tlv(TAG_NULL, &[0x00]);
        for (name, odd) in [
            ("INTEGER", &integer),
            ("empty OCTET STRING", &octets),
            ("empty SEQUENCE", &sequence),
            ("NULL with content", &null_with_content),
        ] {
            let odd = sha256(&[odd]);
            for (place, hash, mgf_hash) in [
                ("hash", &odd, &with_null),
                ("MGF1 hash", &with_null, &odd),
                ("both", &odd, &odd),
            ] {
                let err = read(hash, mgf_hash).unwrap_err();
                assert!(
                    err.contains("neither absent nor NULL"),
                    "{name} {place}: {err}"
                );
            }
        }
        // Two parameters (r9-pssanchor-two-params-hash) are no AlgorithmIdentifier at all.
        assert!(read(&sha256(&[null, null]), &with_null).is_err());
    }
}

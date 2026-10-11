//! CMS `SignedData` for PDF signatures: building, parsing and verifying (RFC 5652, RFC 5035,
//! PAdES baseline B-B; M3 brief §3.1 and §4.3).
//!
//! **Building** (Folioxide's own assembly on `der` 0.8; no RustCrypto type in the API):
//! 1. [`build_signed_attrs`] returns the DER signed attributes with the universal `SET` tag
//!    `0x31`: exactly the bytes that are signed (RFC 5652 §5.4). There are three attributes,
//!    DER-sorted: content-type (`id-data`), message-digest and ESS signing-certificate-v2. There
//!    is never a signing-time attribute: PAdES puts the claimed time in `/M`.
//! 2. A [`Signer`](crate::signer::Signer) or an external device signs those bytes.
//! 3. [`assemble`] wraps everything in a `ContentInfo(SignedData)`: detached (no eContent), the
//!    input certificates byte for byte, one SignerInfo whose `signedAttrs` carry the same
//!    length and content octets under the `[0] IMPLICIT` tag `0xA0`.
//!
//! [`cms_len_upper_bound`] gives the exact (RSA) or maximal (ECDSA) size of that ContentInfo
//! before anything is signed, which sizes the `/Contents` placeholder (brief §4.2).
//!
//! **Parsing** ([`parse`]) walks BER or DER with raw slices: the signed attributes are kept as
//! found, because re-encoding them would re-sort a `SET OF` and break signatures that
//! asn1crypto-based verifiers accept (brief §4.3). Depth, certificate and attribute counts are
//! bounded ([`MAX_DEPTH`], [`MAX_CERTIFICATES`], [`MAX_ATTRIBUTES`]).
//!
//! **Verification** ([`verify_detached`]) never panics and never fails: every defect becomes a
//! [`Problem`] in the [`CmsVerification`]. [`verify_raw`] and [`verify_and_normalize`] check a
//! bare signature value with a certificate (the two-phase flow's `finish`).
//!
//! ```
//! use folioxide_sign::algorithms::DigestAlgorithm;
//! use folioxide_sign::cms::{self, SignedAttrsInput};
//!
//! // Without a certificate nothing can be built; with one, the result starts with 0x31.
//! let input = SignedAttrsInput {
//!     digest: DigestAlgorithm::Sha256,
//!     document_digest: &[0; 32],
//!     signer_cert_der: b"not a certificate",
//! };
//! assert!(cms::build_signed_attrs(&input).is_err());
//! assert!(cms::parse(b"not a CMS").is_err());
//! ```

use std::ops::Range;

use crate::algorithms::{DigestAlgorithm, KeyKind, SignatureAlgorithm, oid};
use crate::error::Result;
use crate::problem::Problem;

mod build;
pub(crate) mod decode;
pub(crate) mod tlv;
pub(crate) mod verify;

pub(crate) use decode::oid_to_string;

/// The deepest ASN.1 nesting [`parse`] follows (M3 brief R-18).
pub const MAX_DEPTH: usize = 32;
/// The most certificates [`parse`] accepts in `SignedData.certificates` (M3 brief R-18).
pub const MAX_CERTIFICATES: usize = 64;
/// The most attributes [`parse`] accepts in one `signedAttrs` or `unsignedAttrs` (M3 brief R-18).
pub const MAX_ATTRIBUTES: usize = 64;

/// The inputs of [`build_signed_attrs`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedAttrsInput<'a> {
    /// The digest algorithm of the signature: it hashes the document and the signer
    /// certificate (ESS certHash).
    pub digest: DigestAlgorithm,
    /// The digest of the signed byte ranges, the message-digest attribute value. Its length
    /// must be the digest's output length.
    pub document_digest: &'a [u8],
    /// The signer certificate (DER), for signing-certificate-v2: its hash, issuer and serial.
    pub signer_cert_der: &'a [u8],
}

/// The DER `SignedAttributes` as a universal `SET` (first byte `0x31`): exactly the bytes that
/// are signed (RFC 5652 §5.4).
///
/// The attributes are content-type = `id-data`, message-digest = `document_digest` and
/// signing-certificate-v2 (RFC 5035 §3) for the signer certificate, sorted as DER requires
/// (X.690 §11.6). The ESSCertIDv2 `hashAlgorithm` is omitted for SHA-256 (its DEFAULT) and
/// present, without parameters, for SHA-384 and SHA-512. The length does not depend on the
/// digest value, so a zero digest sizes the placeholder.
///
/// # Errors
/// [`Error::InvalidArgument`](crate::Error::InvalidArgument) when `document_digest` has the
/// wrong length, [`Error::Certificate`](crate::Error::Certificate) when the certificate does not
/// parse.
pub fn build_signed_attrs(input: &SignedAttrsInput<'_>) -> Result<Vec<u8>> {
    build::build_signed_attrs(input)
}

/// An upper bound of the DER length of the ContentInfo that [`assemble`] will produce for
/// these signed attributes, certificates and algorithm.
///
/// For RSA it is exact (the signature is the modulus length); for ECDSA it assumes the longest
/// DER signature (72 bytes for P-256, 104 for P-384), so the result is at most a few bytes
/// above the real length.
///
/// # Errors
/// [`Error::InvalidArgument`](crate::Error::InvalidArgument) when `alg` does not match `kind`
/// or the combination may not sign ([`check_signing_combination`](crate::algorithms::check_signing_combination)).
pub fn cms_len_upper_bound(
    signed_attrs: &[u8],
    chain_der: &[Vec<u8>],
    alg: SignatureAlgorithm,
    kind: KeyKind,
    digest: DigestAlgorithm,
) -> Result<usize> {
    build::cms_len_upper_bound(signed_attrs, chain_der, alg, kind, digest)
}

/// Assembles the DER `ContentInfo(SignedData)` (brief §4.3).
///
/// - `signed_attrs`: the `0x31`-tagged bytes from [`build_signed_attrs`] that were signed.
/// - `signature`: for RSA the modulus length (a shorter value is left-padded with zeros, a
///   longer one is invalid); for ECDSA a DER `ECDSA-Sig-Value` (re-encoded with minimal
///   INTEGERs) or IEEE P1363 `r || s` of exactly twice the field size. The value is not
///   verified here: call [`verify_and_normalize`] first.
/// - `chain_der`: the signer certificate first; every certificate is embedded byte for byte
///   and the `SET OF` is DER-sorted. The SignerInfo identifies the signer by
///   IssuerAndSerialNumber, copied raw from `chain_der[0]`.
///
/// # Errors
/// [`Error::SignatureInvalid`](crate::Error::SignatureInvalid) when the signature has neither
/// form, [`Error::Certificate`](crate::Error::Certificate) when `chain_der[0]` does not parse,
/// [`Error::InvalidArgument`](crate::Error::InvalidArgument) for an empty chain or signed
/// attributes that do not start with `0x31`.
pub fn assemble(
    signed_attrs: &[u8],
    signature: &[u8],
    chain_der: &[Vec<u8>],
    alg: SignatureAlgorithm,
    kind: KeyKind,
    digest: DigestAlgorithm,
) -> Result<Vec<u8>> {
    build::assemble(signed_attrs, signature, chain_der, alg, kind, digest)
}

/// Verifies `signature` over `to_be_signed` with the public key of `cert_der`, hashing with
/// `digest` (used by `finish` before embedding).
///
/// An ECDSA signature may be DER or IEEE P1363; both interpretations are tried when the bytes
/// admit both. A short RSA signature is left-padded with zeros, as OpenSSL does.
///
/// # Errors
/// [`Error::SignatureInvalid`](crate::Error::SignatureInvalid) when it does not verify,
/// [`Error::Certificate`](crate::Error::Certificate) when the certificate or its key does not
/// parse, [`Error::Unsupported`](crate::Error::Unsupported) for keys other than RSA, P-256 and
/// P-384.
pub fn verify_raw(
    cert_der: &[u8],
    alg: SignatureAlgorithm,
    digest: DigestAlgorithm,
    to_be_signed: &[u8],
    signature: &[u8],
) -> Result<()> {
    verify::verify_and_normalize(cert_der, alg, digest, to_be_signed, signature).map(|_| ())
}

/// Like [`verify_raw`], and returns the signature value to embed: for RSA the value left-padded
/// with zeros to the modulus length (unchanged when it already has it), for ECDSA the minimal
/// DER `ECDSA-Sig-Value` of the interpretation (DER first, then P1363) that verifies (brief §4.3
/// "Normalisation", step 4).
///
/// # Errors
/// As [`verify_raw`].
pub fn verify_and_normalize(
    cert_der: &[u8],
    alg: SignatureAlgorithm,
    digest: DigestAlgorithm,
    to_be_signed: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>> {
    verify::verify_and_normalize(cert_der, alg, digest, to_be_signed, signature)
}

/// Parses a BER or DER `ContentInfo`, keeping raw slices (brief §4.3).
///
/// Bytes after the outer element (the zero padding of `/Contents`) are not parsed;
/// [`ParsedCms::raw`] says where the element ends. A ContentInfo that is not `SignedData`
/// parses, with no signer infos: [`verify_detached`] reports it as
/// [`ProblemCode::NotSignedData`](crate::ProblemCode::NotSignedData).
///
/// # Errors
/// [`Error::Syntax`](crate::Error::Syntax) with code `Syntax` when the bytes are not a
/// well-formed ContentInfo, and with code `LimitExceeded` when a limit ([`MAX_DEPTH`],
/// [`MAX_CERTIFICATES`], [`MAX_ATTRIBUTES`]) is exceeded.
pub fn parse(cms: &[u8]) -> Result<ParsedCms> {
    decode::parse(cms)
}

/// A parsed `ContentInfo`, with the raw bytes of every part a verifier needs.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedCms {
    /// `ContentInfo.contentType`, dotted ([`oid::ID_SIGNED_DATA`] for a signature).
    pub content_type: String,
    /// `encapContentInfo.eContentType`, dotted; `None` when the content is not SignedData.
    pub econtent_type: Option<String>,
    /// `encapContentInfo.eContent` (the OCTET STRING contents); `None` for a detached signature.
    pub econtent: Option<Vec<u8>>,
    /// Every SignerInfo, in file order.
    pub signer_infos: Vec<ParsedSignerInfo>,
    /// The DER of every `CertificateChoices::certificate`, raw and in file order (other
    /// choices are skipped).
    pub certificates: Vec<Vec<u8>>,
    /// The byte range of the outer ContentInfo element in the parsed input; anything after it
    /// is padding.
    pub raw: Range<usize>,
}

/// A parsed `SignerInfo` (RFC 5652 §5.3), with raw bytes.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedSignerInfo {
    /// `version` (1 for IssuerAndSerialNumber, 3 for SubjectKeyIdentifier).
    pub version: u32,
    /// `sid`: which certificate signed.
    pub sid: SignerIdentifier,
    /// `digestAlgorithm`.
    pub digest_algorithm: AlgorithmId,
    /// The `signedAttrs` element exactly as found, `[0]` tag (`0xA0`) and original length
    /// octets included; `None` when absent. The signature covers these bytes with the first
    /// byte replaced by `0x31`.
    pub signed_attrs: Option<Vec<u8>>,
    /// `signatureAlgorithm`.
    pub signature_algorithm: AlgorithmId,
    /// The contents of the `signature` OCTET STRING.
    pub signature: Vec<u8>,
    /// The `unsignedAttrs` element exactly as found (`[1]` tag included); `None` when absent.
    pub unsigned_attrs: Option<Vec<u8>>,
    /// The byte range of this SignerInfo in the parsed input.
    pub raw: Range<usize>,
}

/// How a SignerInfo names its certificate (RFC 5652 §5.3 `SignerIdentifier`).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignerIdentifier {
    /// `issuerAndSerialNumber`.
    IssuerAndSerialNumber {
        /// The raw DER of the issuer `Name`, compared byte for byte with the certificates'.
        issuer: Vec<u8>,
        /// The raw DER of the serial number `INTEGER` (tag and length included).
        serial: Vec<u8>,
    },
    /// `subjectKeyIdentifier` `[0]`: the key identifier bytes.
    SubjectKeyIdentifier(Vec<u8>),
}

/// A raw `AlgorithmIdentifier`: the OID and the undecoded parameters.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlgorithmId {
    /// The algorithm OID, dotted (see [`oid`]).
    pub oid: String,
    /// The DER of the parameters (tag and length included); `None` when absent. An explicit
    /// `NULL` is `Some(vec![0x05, 0x00])`.
    pub parameters: Option<Vec<u8>>,
}

impl AlgorithmId {
    /// The digest algorithm with this OID, if Folioxide implements it.
    pub fn digest(&self) -> Option<DigestAlgorithm> {
        DigestAlgorithm::from_oid(&self.oid)
    }
}

/// Verifies a detached CMS signature over a precomputed document digest (brief §5 V6–V8).
///
/// `document_digest_for(d)` returns the digest of the signed bytes with algorithm `d`, the
/// SignerInfo's `digestAlgorithm`; `None` makes `intact` false. `extra_certs` (DER) join the
/// CMS certificates when looking for the signer certificate.
///
/// The checks: SignedData with exactly one SignerInfo, `eContentType` = `id-data` and no
/// eContent, exactly one content-type attribute equal to the eContentType and exactly one
/// message-digest attribute, matching ESS signing-certificate(-v2) and CMSAlgorithmProtection
/// attributes when present, the signer certificate found by `sid`, a signature algorithm whose
/// hash equals the digest algorithm, and the signature over the original signed-attribute
/// bytes re-tagged `0x31`. Every failure is a [`Problem`]; the function never panics.
///
/// - Signature algorithms: RSA PKCS#1 v1.5 (also under `rsaEncryption`), RSA-PSS (MGF1 on the
///   same hash), ECDSA on P-256 and P-384 (DER or IEEE P1363 values; high-S accepted). RSA keys
///   of 1024 to 8192 bits; below 2048 bits a warning is added.
/// - The ESS signing-certificate-v2 attribute is checked when present, else v1 (as pyHanko);
///   the first ESSCertID must match the certHash, and the issuerSerial when present.
/// - Without signed attributes the signature covers the content itself and `intact` equals
///   `signature_valid` (pyHanko's rule).
/// - Signed attributes that are not DER (unsorted, non-minimal lengths) are verified as found,
///   with a warning: OpenSSL re-encodes and would reject them, asn1crypto/pyHanko accept them.
pub fn verify_detached(
    parsed: &ParsedCms,
    document_digest_for: &dyn Fn(DigestAlgorithm) -> Option<Vec<u8>>,
    extra_certs: &[Vec<u8>],
) -> CmsVerification {
    verify::verify_detached(parsed, document_digest_for, extra_certs)
}

/// The result of [`verify_detached`].
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CmsVerification {
    /// The digest of the signed bytes equals the message-digest attribute (without signed
    /// attributes: equals `signature_valid`, as pyHanko).
    pub intact: bool,
    /// The signature verifies with the signer certificate and the CMS structure is acceptable.
    pub signature_valid: bool,
    /// The SignerInfo's digest algorithm, when Folioxide implements it.
    pub digest: Option<DigestAlgorithm>,
    /// The signature algorithm's RFC name, for example `"sha256WithRSAEncryption"`.
    pub signature_algorithm: Option<String>,
    /// The signer certificate (DER), when found.
    pub signer_cert: Option<Vec<u8>>,
    /// What the PAdES baseline checks need from the signed attributes.
    pub pades_attrs: PadesAttrs,
    /// What is wrong with the signature; empty when nothing is.
    ///
    /// Every problem makes `signature_valid` false except two: `DigestMismatch` only makes
    /// `intact` false, and `WeakAlgorithm` (SHA-1) leaves both as computed but means the
    /// signature must never be trusted (brief §5 V7).
    pub problems: Vec<Problem>,
    /// Observations that do not invalidate the signature, for example signed attributes that
    /// are not DER-sorted.
    pub warnings: Vec<String>,
}

impl CmsVerification {
    /// A verification that failed with `problem`: not intact, not valid, nothing else known.
    pub fn failed(problem: Problem) -> CmsVerification {
        CmsVerification {
            problems: vec![problem],
            ..CmsVerification::default()
        }
    }
}

/// The signed attributes the PAdES baseline profile looks at (brief §4.6, §5 V8).
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PadesAttrs {
    /// The content-type attribute value, dotted; `None` when absent.
    pub content_type: Option<String>,
    /// The message-digest attribute value; `None` when absent.
    pub message_digest: Option<Vec<u8>>,
    /// ESS signing-certificate-v2 (RFC 5035): `None` when absent, `Some(true)` when it matches
    /// the signer certificate (certHash, and issuerSerial when present), else `Some(false)`.
    pub signing_certificate_v2: Option<bool>,
    /// ESS signing-certificate v1 (RFC 2634), as `signing_certificate_v2`.
    pub signing_certificate_v1: Option<bool>,
    /// The signing-time attribute: `None` when absent (as PAdES requires), else its value as
    /// RFC 3339 when it decodes, or an empty string when it does not.
    pub signing_time: Option<String>,
}

impl PadesAttrs {
    /// Whether the signed attributes meet PAdES baseline B-B (ETSI EN 319 142-1 §6.3 and EN 319
    /// 122-1 §6.3 as profiled by it): content-type = `id-data`, a message-digest, a matching
    /// signing-certificate-v2, no signing-certificate v1 and no signing-time.
    ///
    /// The other B-B conditions (SubFilter, one signer, detached, `/M`, no `/Cert`, the signer
    /// certificate in `certificates`) are checked by the PDF verifier.
    ///
    /// ```
    /// use folioxide_sign::cms::PadesAttrs;
    ///
    /// assert!(!PadesAttrs::default().is_baseline_b());
    /// ```
    pub fn is_baseline_b(&self) -> bool {
        self.content_type.as_deref() == Some(oid::ID_DATA)
            && self.message_digest.is_some()
            && self.signing_certificate_v2 == Some(true)
            && self.signing_certificate_v1.is_none()
            && self.signing_time.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProblemCode;

    fn baseline() -> PadesAttrs {
        PadesAttrs {
            content_type: Some(oid::ID_DATA.to_owned()),
            message_digest: Some(vec![0; 32]),
            signing_certificate_v2: Some(true),
            signing_certificate_v1: None,
            signing_time: None,
        }
    }

    #[test]
    fn baseline_b_needs_every_attribute_condition() {
        assert!(baseline().is_baseline_b());

        let variants: [fn(&mut PadesAttrs); 7] = [
            |a| a.content_type = None,
            |a| a.content_type = Some(oid::ID_SIGNED_DATA.to_owned()),
            |a| a.message_digest = None,
            |a| a.signing_certificate_v2 = None,
            |a| a.signing_certificate_v2 = Some(false),
            |a| a.signing_certificate_v1 = Some(true),
            |a| a.signing_time = Some("2026-10-10T12:00:00Z".to_owned()),
        ];
        for (i, mutate) in variants.iter().enumerate() {
            let mut attrs = baseline();
            mutate(&mut attrs);
            assert!(!attrs.is_baseline_b(), "variant {i}");
        }
    }

    #[test]
    fn failed_verification_is_neither_intact_nor_valid() {
        let v = CmsVerification::failed(Problem::new(ProblemCode::CmsMalformed, "garbage"));
        assert!(!v.intact && !v.signature_valid);
        assert_eq!(v.problems.len(), 1);
        assert_eq!(v.problems[0].code, ProblemCode::CmsMalformed);
        assert!(v.signer_cert.is_none() && v.digest.is_none());
    }

    #[test]
    fn algorithm_id_digest_lookup() {
        let sha384 = AlgorithmId {
            oid: oid::SHA384.to_owned(),
            parameters: Some(vec![0x05, 0x00]),
        };
        assert_eq!(sha384.digest(), Some(DigestAlgorithm::Sha384));
        let rsa = AlgorithmId {
            oid: oid::SHA256_WITH_RSA.to_owned(),
            parameters: None,
        };
        assert_eq!(rsa.digest(), None);
    }
}

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
//! **Signature timestamps** (M4 brief §3.1, §4.3; RFC 3161 Appendix A):
//! [`assemble_with_timestamp`] adds one `id-aa-signatureTimeStampToken` unsigned attribute,
//! [`cms_len_upper_bound_with_timestamp`] sizes it, [`signature_timestamp_tokens`] reads the
//! tokens of a SignerInfo, and [`verify_encapsulated`] verifies a token's encapsulated TSTInfo.
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
use crate::tsp::{MAX_TIMESTAMP_TOKENS, OID_AA_SIGNATURE_TIME_STAMP_TOKEN};

mod build;
pub(crate) mod decode;
pub(crate) mod tlv;
pub(crate) mod verify;

pub(crate) use decode::oid_to_string;

/// The deepest ASN.1 nesting [`parse`] follows (M3 brief R-18).
pub const MAX_DEPTH: usize = 32;
/// The most certificates [`parse`] accepts in `SignedData.certificates` (M3 brief R-18).
pub const MAX_CERTIFICATES: usize = 64;
/// The most attributes [`parse`] accepts in one `signedAttrs` (M3 brief R-18), and the most it
/// reads of one `unsignedAttrs`: unsigned attributes are not signed, so more of them are not
/// an error; the ones after the limit are not read (M4 QA round 1 finding F10).
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
/// [`MAX_CERTIFICATES`], [`MAX_ATTRIBUTES`] signed attributes) is exceeded.
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
///   same hash), ECDSA on P-256 and P-384 (the value must be a minimal DER `ECDSA-Sig-Value`,
///   as OpenSSL and pyHanko verify it: IEEE P1363 `r || s` and redundant leading zero octets
///   make `signature_valid` false; high-S accepted). RSA keys of 1024 to 8192 bits; below 2048
///   bits a warning is added.
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

/// Verifies a CMS with encapsulated content: a timestamp token's TSTInfo (M4 brief §3.1, §5
/// V7b step 4).
///
/// The checks: SignedData with exactly one SignerInfo, `eContentType` equals
/// `expected_econtent_type` and eContent is present, exactly one content-type attribute equal
/// to it and exactly one message-digest attribute equal to the digest of the eContent octets
/// (`intact`), the signer certificate found by `sid` among the CMS certificates and
/// `extra_certs`, a signature algorithm whose hash equals the digest algorithm, and the
/// signature over the original signed attributes re-tagged `0x31` (`signature_valid`). The
/// algorithms are those of [`verify_detached`]. Never fails, never panics.
///
/// The ESS signing-certificate attributes (v2, RFC 5035; v1, RFC 2634, whose SHA-1 certHash is
/// not a weak-algorithm problem) are **reported** in [`pades_attrs`](CmsVerification::pades_attrs)
/// (their first identifier) and do not change `signature_valid`: a timestamp verifier checks
/// them as a separate step (M4 brief §4.2 step 6, §5 V7b step 5), which
/// [`verify_token`](crate::tsp::verify_token) does as OpenSSL does: every attribute present,
/// every identifier.
///
/// ```
/// use folioxide_sign::cms;
/// use folioxide_sign::tsp::OID_CT_TST_INFO;
///
/// // A ContentInfo that is not SignedData is neither intact nor valid.
/// let id_data = [0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
/// let parsed = cms::parse(&id_data)?;
/// let v = cms::verify_encapsulated(&parsed, OID_CT_TST_INFO, &[]);
/// assert!(!v.intact && !v.signature_valid);
/// # Ok::<(), folioxide_sign::Error>(())
/// ```
pub fn verify_encapsulated(
    parsed: &ParsedCms,
    expected_econtent_type: &str,
    extra_certs: &[Vec<u8>],
) -> CmsVerification {
    verify::verify_encapsulated(parsed, expected_econtent_type, extra_certs)
}

/// [`assemble`] plus `unsignedAttrs [1]` holding exactly one `id-aa-signatureTimeStampToken`
/// attribute with exactly one value, `token_der`, byte for byte (M4 brief §4.3; RFC 3161
/// Appendix A). The signed attributes and the signature value are unchanged, so the signature
/// stays valid; only the lengths of the SignerInfo, `signerInfos`, SignedData, `[0]` and the
/// ContentInfo grow. A BER token is embedded verbatim (DECISIONS D13 D-12): the CMS around it
/// stays DER.
///
/// The token is not verified here (see [`validate_response`](crate::tsp::validate_response)
/// and [`verify_token`](crate::tsp::verify_token)); it must be one BER or DER `SEQUENCE`.
///
/// # Errors
/// As [`assemble`]; [`Error::InvalidArgument`](crate::Error::InvalidArgument) when `token_der`
/// is not one BER or DER `SEQUENCE`.
#[allow(clippy::too_many_arguments)] // The brief's signature (M4 brief §3.1).
pub fn assemble_with_timestamp(
    signed_attrs: &[u8],
    signature: &[u8],
    chain_der: &[Vec<u8>],
    alg: SignatureAlgorithm,
    kind: KeyKind,
    digest: DigestAlgorithm,
    token_der: &[u8],
) -> Result<Vec<u8>> {
    build::assemble_with_timestamp(
        signed_attrs,
        signature,
        chain_der,
        alg,
        kind,
        digest,
        token_der,
    )
}

/// [`cms_len_upper_bound`] for a CMS that also carries a signature timestamp token of exactly
/// `token_len` bytes (M4 brief §4.4): exact for RSA, at most a few bytes above the real length
/// for ECDSA. A `token_len` of 0 is [`cms_len_upper_bound`].
///
/// # Errors
/// As [`cms_len_upper_bound`]; [`Error::InvalidArgument`](crate::Error::InvalidArgument) for a
/// `token_len` above [`MAX_CONTENTS_RESERVE`](crate::placeholder::MAX_CONTENTS_RESERVE).
pub fn cms_len_upper_bound_with_timestamp(
    signed_attrs: &[u8],
    chain_der: &[Vec<u8>],
    alg: SignatureAlgorithm,
    kind: KeyKind,
    digest: DigestAlgorithm,
    token_len: usize,
) -> Result<usize> {
    build::cms_len_upper_bound_with_timestamp(signed_attrs, chain_der, alg, kind, digest, token_len)
}

/// The signature timestamp tokens of a SignerInfo: the raw bytes of every value of every
/// `id-aa-signatureTimeStampToken` attribute of its `unsignedAttrs`, in order (RFC 3161
/// Appendix A; M4 brief §5 V7b).
///
/// At most [`MAX_TIMESTAMP_TOKENS`]` + 1` tokens are returned, so a caller can tell that there
/// were more than it verifies, and only the first [`MAX_ATTRIBUTES`] attributes are read.
/// Unsigned attributes that do not parse end the list (it never fails): what was read before
/// is returned. The verifier says in its report when that happened (M4 QA round 3 finding 1).
pub fn signature_timestamp_tokens(si: &ParsedSignerInfo) -> Vec<Vec<u8>> {
    signature_timestamp_tokens_read(si).0
}

/// [`signature_timestamp_tokens`], and whether the unsigned attributes it read (up to the
/// limits) all parsed: `false` when an attribute, or a value of a timestamp token attribute,
/// could not be read, for example a token with a truncated or huge declared length or nested
/// deeper than [`MAX_DEPTH`]. A caller cannot tell such a damaged signature timestamp from no
/// timestamp at all, and says so (M4 QA round 3 finding 1): unsigned attributes are not
/// signed, so anyone can damage them.
pub(crate) fn signature_timestamp_tokens_read(si: &ParsedSignerInfo) -> (Vec<Vec<u8>>, bool) {
    let mut tokens = Vec::new();
    let Some(raw) = si.unsigned_attrs.as_deref() else {
        return (tokens, true);
    };
    let Ok(outer) = tlv::read_exact(raw, MAX_DEPTH) else {
        return (tokens, false);
    };
    for attribute in tlv::children(raw, &outer, 0, MAX_DEPTH).take(MAX_ATTRIBUTES) {
        let Ok(attribute) = attribute else {
            return (tokens, false);
        };
        let mut parts = tlv::children(raw, &attribute, 1, MAX_DEPTH);
        let (Some(Ok(attr_type)), Some(Ok(values))) = (parts.next(), parts.next()) else {
            return (tokens, false);
        };
        if attribute.tag != tlv::TAG_SEQUENCE
            || attr_type.tag != tlv::TAG_OID
            || values.tag != tlv::TAG_SET
        {
            return (tokens, false);
        }
        let is_token = oid_to_string(attr_type.content(raw)).as_deref()
            == Some(OID_AA_SIGNATURE_TIME_STAMP_TOKEN);
        if !is_token {
            continue;
        }
        for value in tlv::children(raw, &values, 2, MAX_DEPTH) {
            let Ok(value) = value else {
                return (tokens, false);
            };
            tokens.push(value.raw(raw).to_vec());
            if tokens.len() > MAX_TIMESTAMP_TOKENS {
                return (tokens, true);
            }
        }
    }
    (tokens, true)
}

/// The byte ranges, within `input`, of every value of every `id-aa-signatureTimeStampToken`
/// attribute of the `unsignedAttrs` element `attrs` (read at `depth`): what a DER check treats
/// as opaque, because a TSA's token is embedded verbatim (M4 brief §4.3, DECISIONS D13 D-12).
pub(crate) fn timestamp_value_ranges(
    input: &[u8],
    attrs: &tlv::Element,
    depth: usize,
) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    for attribute in tlv::children(input, attrs, depth, MAX_DEPTH).take(MAX_ATTRIBUTES) {
        let Ok(attribute) = attribute else {
            break;
        };
        let mut parts = tlv::children(input, &attribute, depth + 1, MAX_DEPTH);
        let (Some(Ok(attr_type)), Some(Ok(values))) = (parts.next(), parts.next()) else {
            continue;
        };
        let is_token = attr_type.tag == tlv::TAG_OID
            && oid_to_string(attr_type.content(input)).as_deref()
                == Some(OID_AA_SIGNATURE_TIME_STAMP_TOKEN);
        if is_token && values.tag == tlv::TAG_SET {
            ranges.extend(
                tlv::children(input, &values, depth + 2, MAX_DEPTH)
                    .map_while(std::result::Result::ok)
                    .map(|value| value.start..value.end),
            );
        }
    }
    ranges
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

    /// A SignerInfo whose `unsignedAttrs` is `unsigned` (raw, `[1]` tag included).
    fn signer_info_with(unsigned: Option<Vec<u8>>) -> ParsedSignerInfo {
        let algorithm = AlgorithmId {
            oid: oid::SHA256.to_owned(),
            parameters: None,
        };
        ParsedSignerInfo {
            version: 1,
            sid: SignerIdentifier::SubjectKeyIdentifier(vec![1]),
            digest_algorithm: algorithm.clone(),
            signed_attrs: None,
            signature_algorithm: algorithm,
            signature: vec![0; 4],
            unsigned_attrs: unsigned,
            raw: 0..0,
        }
    }

    /// An `Attribute` of type `oid_content` (DER content octets) with `values`.
    fn attribute(oid_content: &[u8], values: &[&[u8]]) -> Vec<u8> {
        tlv::tlv_parts(
            tlv::TAG_SEQUENCE,
            &[
                &tlv::tlv(tlv::TAG_OID, oid_content),
                &tlv::tlv_parts(tlv::TAG_SET, values),
            ],
        )
    }

    #[test]
    fn signature_timestamp_tokens_in_order() {
        const TST: &[u8] = &[
            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
        ];
        const SIGNING_TIME: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05];
        let token = |n: u8| tlv::tlv(tlv::TAG_SEQUENCE, &[0x02, 0x01, n]);
        let (one, two, three) = (token(1), token(2), token(3));
        let unsigned = tlv::tlv_parts(
            tlv::TAG_CONTEXT_1,
            &[
                &attribute(TST, &[&one, &two]),
                &attribute(SIGNING_TIME, &[&tlv::tlv(tlv::TAG_UTC_TIME, b"x")]),
                &attribute(TST, &[&three]),
            ],
        );
        let si = signer_info_with(Some(unsigned.clone()));
        assert_eq!(signature_timestamp_tokens(&si), [one, two, three]);

        assert!(signature_timestamp_tokens(&signer_info_with(None)).is_empty());
        // Garbage and truncations: nothing or a prefix, never a panic.
        for len in 0..unsigned.len() {
            let si = signer_info_with(Some(unsigned[..len].to_vec()));
            assert!(signature_timestamp_tokens(&si).len() <= 3);
        }

        // At most MAX_TIMESTAMP_TOKENS + 1 tokens.
        let many: Vec<Vec<u8>> = (0..20).map(token).collect();
        let refs: Vec<&[u8]> = many.iter().map(Vec::as_slice).collect();
        let flood = tlv::tlv(tlv::TAG_CONTEXT_1, &attribute(TST, &refs));
        let tokens = signature_timestamp_tokens(&signer_info_with(Some(flood)));
        assert_eq!(tokens.len(), MAX_TIMESTAMP_TOKENS + 1);
        assert_eq!(tokens[0], many[0]);
    }

    #[test]
    fn timestamp_additions_refuse_bad_inputs() {
        let parsed = ParsedCms {
            content_type: oid::ID_SIGNED_DATA.to_owned(),
            econtent_type: Some(crate::tsp::OID_CT_TST_INFO.to_owned()),
            econtent: Some(vec![0x30, 0x00]),
            signer_infos: Vec::new(),
            certificates: Vec::new(),
            raw: 0..0,
        };
        let v = verify_encapsulated(&parsed, crate::tsp::OID_CT_TST_INFO, &[]);
        assert!(!v.intact && !v.signature_valid);
        assert_eq!(v.problems[0].code, ProblemCode::SignerInfoCount);
        let kind = KeyKind::EcP256;
        let (alg, digest) = (SignatureAlgorithm::Ecdsa, DigestAlgorithm::Sha256);
        assert!(assemble_with_timestamp(&[0x31, 0], &[], &[], alg, kind, digest, &[]).is_err());
        assert!(cms_len_upper_bound_with_timestamp(&[0x31, 0], &[], alg, kind, digest, 1).is_err());
        let too_long = crate::placeholder::MAX_CONTENTS_RESERVE + 1;
        let err = cms_len_upper_bound_with_timestamp(&[0x31, 0], &[], alg, kind, digest, too_long)
            .unwrap_err();
        assert!(err.to_string().contains("cannot fit"), "{err}");
    }

    #[test]
    fn timestamp_value_ranges_find_every_token() {
        const TST: &[u8] = &[
            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
        ];
        let one = tlv::tlv(tlv::TAG_SEQUENCE, &[0x05, 0x00]);
        let unsigned = tlv::tlv_parts(
            tlv::TAG_CONTEXT_1,
            &[
                &attribute(&[0x2A, 0x03], &[&one]),
                &attribute(TST, &[&one, &one]),
            ],
        );
        let element = tlv::read_exact(&unsigned, MAX_DEPTH).unwrap();
        let ranges = timestamp_value_ranges(&unsigned, &element, 0);
        assert_eq!(ranges.len(), 2);
        for range in ranges {
            assert_eq!(&unsigned[range], one.as_slice());
        }
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

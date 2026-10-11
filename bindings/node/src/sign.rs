//! Signing and verification (M3 brief §3.3; ARCHITECTURE §A.7, "Class shape").
//!
//! - [`LocalSigner`]: a private key with its certificate chain, loaded from PKCS#12 or PEM; it
//!   signs bytes on the JavaScript thread (`sign`) or on the libuv thread pool (`signAsync`).
//! - `PdfDocument.prepareSignature` / `prepareSignatureAsync`: the first phase of signing
//!   (the incremental update with the placeholders, the byte-range digest and the signed
//!   attributes), which returns a [`PreparedSignature`]. The document is not changed.
//! - [`PreparedSignature`]: the bytes an external signer signs (`toBeSigned`,
//!   `toBeSignedDigest`, `toBeSignedDigestInfo`), then `finish` with the signature value or
//!   `embedCms` with a whole CMS, which returns the signed file. It holds the prepared file
//!   (reported to V8 as external memory) until one of them succeeds; a refused value leaves it,
//!   so the caller can try again. `serialize`/`deserialize` carry it between processes in the
//!   core's versioned binary form.
//! - `PdfDocument.verifySignatures`: verification on the thread pool, one
//!   [`SignatureReport`] per signature dictionary.
//!
//! The JavaScript facade (`index.js`) composes these into `signPdf(doc, { signer })`, awaiting
//! an asynchronous signer (a KMS, WebCrypto, `node:crypto`) between the two phases in
//! JavaScript, so no thread-safe function is needed.
//!
//! The report objects have the JSON shape of the core's `serde` DTOs (`camelCase` names, `null`
//! for absent values, enums as their `camelCase` strings, an object id as `{ num, gen }`), with
//! one difference: certificates' `der` is a `Buffer` where serde writes an array of numbers.
//!
//! Certificates may be given as DER or as PEM text (one or more `CERTIFICATE` blocks in one
//! `Uint8Array`), wherever a list of certificates is taken.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use folioxide::{DigestAlgorithm, SignatureAlgorithm, Signer as _};
use napi::bindgen_prelude::{AsyncTask, Buffer, Either, ObjectFinalize, Uint8Array};
use napi::{Env, Task};
use napi_derive::napi;
use zeroize::Zeroizing;

use crate::document::{PdfDocument, Pending, Shared};
use crate::dto::{integer_in, page_index};
use crate::error::{
    self, BindingError, JsResult, closed, finishing, from_core, invalid_argument, signer_closed,
};

// ---- names -----------------------------------------------------------------------------------

/// A signature algorithm: RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) or ECDSA on P-256 or P-384 (the
/// curve comes from the certificate).
#[napi(string_enum)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigAlg {
    /// RSASSA-PKCS1-v1_5.
    #[napi(value = "rsa-pkcs1v15")]
    RsaPkcs1v15,
    /// ECDSA.
    #[napi(value = "ecdsa")]
    Ecdsa,
}

/// A digest algorithm for signing.
#[napi(string_enum)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestAlg {
    /// SHA-256.
    #[napi(value = "sha256")]
    Sha256,
    /// SHA-384.
    #[napi(value = "sha384")]
    Sha384,
    /// SHA-512.
    #[napi(value = "sha512")]
    Sha512,
}

/// The `/SubFilter` of a signature dictionary (ISO 32000-2 §12.8.3.1, Table 260). Folioxide
/// writes the same CMS (PAdES baseline B-B signed attributes) for both.
#[napi(string_enum)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubFilter {
    /// A PAdES signature (ETSI EN 319 142-1). The default.
    #[napi(value = "ETSI.CAdES.detached")]
    EtsiCadesDetached,
    /// A detached PKCS#7/CMS signature.
    #[napi(value = "adbe.pkcs7.detached")]
    AdbePkcs7Detached,
}

/// Whether a signature uses an existing signature field, creates one, or either.
#[napi(string_enum = "camelCase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldMode {
    /// Sign the named field when it exists and is an unsigned signature field, otherwise create
    /// it; without a name, create a new field. The default.
    CreateOrUse,
    /// Sign the named existing field (`E_NOT_FOUND` when there is none).
    ExistingOnly,
    /// Always create a new field (`E_INVALID_ARGUMENT` when the name is taken).
    CreateOnly,
}

/// What a signature dictionary is.
#[napi(string_enum = "camelCase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureKind {
    /// A signature.
    Signature,
    /// A document timestamp (listed, not verified, until RFC 3161 support).
    DocTimeStamp,
}

/// How much of the file a signature's byte ranges cover (pyHanko's `SignatureCoverageLevel`).
#[napi(string_enum = "camelCase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    /// The whole file but the signature's own `/Contents`.
    EntireFile,
    /// One complete revision; later revisions were appended (see `modification`).
    EntireRevision,
    /// A block from the start that does not end at a revision of the file.
    ContiguousBlockFromStart,
    /// Anything else.
    Unclear,
}

/// What the revisions appended after a signature changed (pyHanko's `ModificationLevel`),
/// from harmless to anything.
#[napi(string_enum = "camelCase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModificationLevel {
    /// Nothing was appended.
    None,
    /// Updates that keep the content: re-listed objects, `/Info`, metadata, new invisible
    /// signature fields.
    LtaUpdates,
    /// Signing (a new signature) and filling signature fields.
    FormFilling,
    /// Annotation changes.
    Annotations,
    /// Anything else, or a change that cannot be attributed (a repaired structure).
    Other,
}

/// The PAdES baseline level a signature meets (ETSI EN 319 142-1 §6).
#[napi(string_enum)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PadesLevel {
    /// PAdES-B-B.
    #[napi(value = "B-B")]
    BB,
}

/// The JavaScript name of a signature algorithm.
fn sig_alg_name(algorithm: SignatureAlgorithm) -> String {
    algorithm.name().to_owned()
}

/// Parses `'rsa-pkcs1v15'` or `'ecdsa'`.
///
/// # Errors
/// `E_INVALID_ARGUMENT` for any other string.
pub fn parse_sig_alg(text: &str, what: &str) -> JsResult<SignatureAlgorithm> {
    match text {
        "rsa-pkcs1v15" => Ok(SignatureAlgorithm::RsaPkcs1v15),
        "ecdsa" => Ok(SignatureAlgorithm::Ecdsa),
        other => Err(invalid_argument(format!(
            "{what} must be 'rsa-pkcs1v15' or 'ecdsa', not {:?}",
            short(other)
        ))),
    }
}

/// Parses `'sha256'`, `'sha384'` or `'sha512'` (SHA-1 is never used to sign).
///
/// # Errors
/// `E_INVALID_ARGUMENT` for any other string.
pub fn parse_digest(text: &str, what: &str) -> JsResult<DigestAlgorithm> {
    match text {
        "sha256" => Ok(DigestAlgorithm::Sha256),
        "sha384" => Ok(DigestAlgorithm::Sha384),
        "sha512" => Ok(DigestAlgorithm::Sha512),
        other => Err(invalid_argument(format!(
            "{what} must be 'sha256', 'sha384' or 'sha512', not {:?}",
            short(other)
        ))),
    }
}

/// Parses `'ETSI.CAdES.detached'` or `'adbe.pkcs7.detached'`.
///
/// # Errors
/// `E_INVALID_ARGUMENT` for any other string.
pub fn parse_sub_filter(text: &str) -> JsResult<folioxide::SubFilter> {
    folioxide::SubFilter::from_name(text).ok_or_else(|| {
        invalid_argument(format!(
            "subFilter must be 'ETSI.CAdES.detached' or 'adbe.pkcs7.detached', not {:?}",
            short(text)
        ))
    })
}

/// Parses `'createOrUse'`, `'existingOnly'` or `'createOnly'`.
///
/// # Errors
/// `E_INVALID_ARGUMENT` for any other string.
pub fn parse_field_mode(text: &str) -> JsResult<folioxide::FieldMode> {
    match text {
        "createOrUse" => Ok(folioxide::FieldMode::CreateOrUse),
        "existingOnly" => Ok(folioxide::FieldMode::ExistingOnly),
        "createOnly" => Ok(folioxide::FieldMode::CreateOnly),
        other => Err(invalid_argument(format!(
            "field.mode must be 'createOrUse', 'existingOnly' or 'createOnly', not {:?}",
            short(other)
        ))),
    }
}

/// A PDF date string (ISO 32000-2 §7.9.4, read leniently).
///
/// # Errors
/// `E_INVALID_ARGUMENT` when it is not one.
fn parse_date(text: &str, what: &str) -> JsResult<folioxide::PdfDate> {
    folioxide::PdfDate::parse(text.as_bytes()).ok_or_else(|| {
        invalid_argument(format!(
            "{what} must be a PDF date string such as \"D:20261010120000Z\" (ISO 32000-2 \
             §7.9.4) or a Date, not {:?}",
            short(text)
        ))
    })
}

/// At most the first 40 characters of `text`, for quoting caller input in messages.
fn short(text: &str) -> String {
    text.chars().take(40).collect()
}

/// Whether `bytes` is PEM text: it starts (after whitespace) with `-----BEGIN`. DER
/// certificates start with a SEQUENCE tag (`0x30`), so the two cannot be confused.
fn is_pem(bytes: &[u8]) -> bool {
    bytes.trim_ascii_start().starts_with(b"-----BEGIN")
}

/// Certificates from JavaScript: each entry is one DER certificate, or PEM text with one or
/// more `CERTIFICATE` blocks (in their order).
///
/// # Errors
/// `E_INVALID_ARGUMENT` for PEM text that is not UTF-8; `E_CERTIFICATE` for PEM text without a
/// certificate or with one that does not parse. DER entries are checked where they are used.
pub fn certificates(list: &[Uint8Array], what: &str) -> JsResult<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(list.len());
    for (i, item) in list.iter().enumerate() {
        let bytes: &[u8] = item;
        if is_pem(bytes) {
            let text = std::str::from_utf8(bytes).map_err(|_| {
                invalid_argument(format!("{what}[{i}] looks like PEM text but is not UTF-8"))
            })?;
            let certs =
                folioxide::certificates_from_pem(text).map_err(|err| from_core(&err.into()))?;
            out.extend(certs);
        } else {
            out.push(bytes.to_vec());
        }
    }
    Ok(out)
}

// ---- options ---------------------------------------------------------------------------------

/// Which signature field to sign or create (the core `FieldSpec`).
#[napi(object)]
#[derive(Clone, Debug, Default)]
pub struct SignatureFieldSpec {
    /// The field name: an existing field's fully qualified name, or a new field's partial name
    /// (no `.`). Default: a new field `Signature1`, `Signature2`, … (the first free name).
    pub name: Option<String>,
    /// The 0-based index of the page that holds a new field's widget. Default 0.
    pub page: Option<f64>,
    /// Whether an existing field may be used and a new one created. Default `'createOrUse'`.
    #[napi(ts_type = "FieldMode")]
    pub mode: Option<String>,
}

impl SignatureFieldSpec {
    /// The core field specification.
    ///
    /// # Errors
    /// `E_INVALID_ARGUMENT` for a page that is not an integer or an unknown mode;
    /// `E_PAGE_OUT_OF_RANGE` for a negative page.
    pub fn into_core(self) -> JsResult<folioxide::FieldSpec> {
        let mut spec = folioxide::FieldSpec::new().with_name(self.name);
        if let Some(page) = self.page {
            spec = spec.with_page(page_index(page)?);
        }
        if let Some(mode) = self.mode {
            spec = spec.with_mode(parse_field_mode(&mode)?);
        }
        Ok(spec)
    }
}

/// Options for `prepareSignature` and `prepareSignatureAsync` (the core `PrepareRequest`).
#[napi(object)]
#[derive(Default)]
pub struct PrepareSignatureOptions {
    /// The certificates: the signer's first, then the intermediates (the root is optional).
    /// Each entry is a DER certificate, or PEM text with one or more certificates.
    pub certificate_chain: Vec<Uint8Array>,
    /// The signature algorithm of the signer's key.
    #[napi(ts_type = "SigAlg")]
    pub algorithm: String,
    /// The digest algorithm. Default: SHA-256 for RSA and P-256 keys, SHA-384 for P-384 keys.
    #[napi(ts_type = "DigestAlg")]
    pub digest: Option<String>,
    /// The claimed signing time `/M`, a PDF date string (the facade also takes a `Date`, and
    /// defaults to now).
    pub signing_time: String,
    /// Which signature field to sign or create. Default: a new field on the first page.
    pub field: Option<SignatureFieldSpec>,
    /// The `/SubFilter`. Default `'ETSI.CAdES.detached'`.
    #[napi(ts_type = "SubFilter")]
    pub sub_filter: Option<String>,
    /// `/Name`: the signer's name.
    pub name: Option<String>,
    /// `/Reason`: why the document is signed.
    pub reason: Option<String>,
    /// `/Location`: where it is signed.
    pub location: Option<String>,
    /// `/ContactInfo`: how to reach the signer.
    pub contact_info: Option<String>,
    /// The bytes of DER the `/Contents` placeholder holds. Default: the exact size of the CMS
    /// plus a margin, at least 8192. A value below what the CMS needs throws
    /// `E_SIGNATURE_PLACEHOLDER_TOO_SMALL` with `details.needed`.
    pub contents_reserve: Option<f64>,
}

impl PrepareSignatureOptions {
    /// The core request.
    ///
    /// # Errors
    /// `E_INVALID_ARGUMENT` for an empty certificate chain, an unknown algorithm, digest,
    /// SubFilter or field mode, a signing time that is not a PDF date, or a reserve that is not
    /// a non-negative integer; the errors of [`certificates`] and
    /// [`SignatureFieldSpec::into_core`].
    pub fn into_core(self) -> JsResult<folioxide::PrepareRequest> {
        let chain = certificates(&self.certificate_chain, "certificateChain")?;
        if chain.is_empty() {
            return Err(invalid_argument(
                "certificateChain must hold the signer's certificate (and its intermediates)",
            ));
        }
        let algorithm = parse_sig_alg(&self.algorithm, "algorithm")?;
        let signing_time = parse_date(&self.signing_time, "signingTime")?;
        let mut options = folioxide::SignatureOptions::new(signing_time)
            .with_name(self.name)
            .with_reason(self.reason)
            .with_location(self.location)
            .with_contact_info(self.contact_info);
        if let Some(digest) = self.digest {
            options = options.with_digest(Some(parse_digest(&digest, "digest")?));
        }
        if let Some(field) = self.field {
            options = options.with_field(field.into_core()?);
        }
        if let Some(sub_filter) = self.sub_filter {
            options = options.with_sub_filter(parse_sub_filter(&sub_filter)?);
        }
        if let Some(reserve) = self.contents_reserve {
            // The core refuses 0 and anything above its maximum (4 MiB).
            let reserve = integer_in(reserve, 0, MAX_SAFE_INTEGER, "contentsReserve")?;
            options = options.with_contents_reserve(Some(usize::try_from(reserve).unwrap_or(0)));
        }
        Ok(folioxide::PrepareRequest::new(chain, algorithm, signing_time).with_options(options))
    }
}

/// `Number.MAX_SAFE_INTEGER`: the largest integer a JavaScript number holds exactly.
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// Options for `verifySignatures` (the core `VerifyOptions`).
#[napi(object)]
#[derive(Default)]
pub struct VerifyOptions {
    /// Trusted root certificates (DER, or PEM text). Without any, `trusted` is `null` in every
    /// report.
    pub trust_anchors: Option<Vec<Uint8Array>>,
    /// More certificates (DER, or PEM text) for finding signers and building certification
    /// paths, besides those the signatures carry.
    pub extra_certificates: Option<Vec<Uint8Array>>,
    /// The time at which certificates must be valid, a PDF date string (the facade also takes
    /// a `Date`, and defaults to now). Absent: the signer's claimed signing time, with a
    /// warning in each report.
    pub validation_time: Option<String>,
}

impl VerifyOptions {
    /// The core options.
    ///
    /// # Errors
    /// `E_INVALID_ARGUMENT` for a validation time that is not a PDF date; the errors of
    /// [`certificates`].
    pub fn into_core(self) -> JsResult<folioxide::VerifyOptions> {
        let anchors = certificates(&self.trust_anchors.unwrap_or_default(), "trustAnchors")?;
        let extra = certificates(
            &self.extra_certificates.unwrap_or_default(),
            "extraCertificates",
        )?;
        let time = self
            .validation_time
            .map(|text| parse_date(&text, "validationTime"))
            .transpose()?;
        Ok(folioxide::VerifyOptions::new()
            .with_trust_anchors_der(anchors)
            .with_extra_certs_der(extra)
            .with_validation_time(time))
    }
}

// ---- the report ------------------------------------------------------------------------------

/// An indirect object's identifier (§7.3.10): `{ num, gen }`.
#[napi(object)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ObjectRef {
    /// The object number.
    pub num: u32,
    /// The generation number (`gen`).
    #[napi(js_name = "gen")]
    #[cfg_attr(test, serde(rename = "gen"))]
    pub generation: u32,
}

impl From<folioxide::ObjectId> for ObjectRef {
    fn from(id: folioxide::ObjectId) -> ObjectRef {
        ObjectRef {
            num: id.num,
            generation: u32::from(id.generation()),
        }
    }
}

/// Why a signature is not valid: a stable `camelCase` code and a message.
#[napi(object)]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct SignatureProblem {
    /// The category, for example `"digestMismatch"` or `"gapNotContents"`.
    pub code: String,
    /// What exactly was wrong, in English.
    pub message: String,
}

impl From<folioxide::Problem> for SignatureProblem {
    fn from(problem: folioxide::Problem) -> SignatureProblem {
        SignatureProblem {
            code: problem.code.as_str().to_owned(),
            message: problem.message,
        }
    }
}

/// A certificate's public key.
#[napi(object, use_nullable = true)]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize), serde(rename_all = "camelCase"))]
pub struct KeyDescription {
    /// `"rsa"` or `"ec"`; for other keys, the dotted OID of the key algorithm.
    pub algorithm: String,
    /// The key size in bits (the RSA modulus or the curve's field size); 0 when unknown.
    pub bits: u32,
    /// For EC keys, the curve: `"P-256"`, `"P-384"`, or a dotted OID.
    pub curve: Option<String>,
}

impl From<folioxide::KeyDescription> for KeyDescription {
    fn from(key: folioxide::KeyDescription) -> KeyDescription {
        KeyDescription {
            algorithm: key.algorithm,
            bits: key.bits,
            curve: key.curve,
        }
    }
}

/// Information about an X.509 certificate (RFC 5280).
#[napi(object, use_nullable = true)]
#[cfg_attr(test, derive(serde::Serialize), serde(rename_all = "camelCase"))]
pub struct CertificateInfo {
    /// The subject as RFC 4514 text, most specific first (`"CN=…,OU=…,O=…"`).
    pub subject: String,
    /// The issuer, in the same form.
    pub issuer: String,
    /// The subject's common name (`CN`).
    pub common_name: Option<String>,
    /// The serial number, uppercase hexadecimal.
    pub serial_hex: String,
    /// The start of the validity period, RFC 3339 UTC.
    pub not_before: String,
    /// The end of the validity period, RFC 3339 UTC.
    pub not_after: String,
    /// The SHA-256 fingerprint of the DER, lowercase hexadecimal.
    pub sha256_hex: String,
    /// The public key.
    pub key: KeyDescription,
    /// The key usages by their RFC 5280 names (`"digitalSignature"`, `"nonRepudiation"`, …).
    pub key_usage: Vec<String>,
    /// The extended key usages, as dotted OIDs.
    pub ext_key_usage: Vec<String>,
    /// Whether the certificate is a CA certificate (basicConstraints `cA`).
    pub is_ca: bool,
    /// The certificate's DER.
    #[cfg_attr(test, serde(serialize_with = "tests::bytes"))]
    pub der: Buffer,
}

impl From<folioxide::CertificateInfo> for CertificateInfo {
    fn from(info: folioxide::CertificateInfo) -> CertificateInfo {
        CertificateInfo {
            subject: info.subject,
            issuer: info.issuer,
            common_name: info.common_name,
            serial_hex: info.serial_hex,
            not_before: info.not_before,
            not_after: info.not_after,
            sha256_hex: info.sha256_hex,
            key: info.key.into(),
            key_usage: info.key_usage,
            ext_key_usage: info.ext_key_usage,
            is_ca: info.is_ca,
            der: info.der.into(),
        }
    }
}

/// The verification result of one signature dictionary (the core `SignatureReport`).
///
/// `intact`, `signatureValid`, `trusted`, `coverage` and `modification` use pyHanko 0.37's
/// vocabulary and are never more lenient than it (they agree with it except in the M3 brief's
/// deliberate differences, where Folioxide is stricter); the signature is valid exactly when
/// `byteRangeOk`, `intact` and `signatureValid` are true, `fieldName` is set, `problems` is empty
/// and `coverage` is `'entireFile'` or `'entireRevision'`.
#[napi(object, use_nullable = true)]
#[cfg_attr(test, derive(serde::Serialize), serde(rename_all = "camelCase"))]
pub struct SignatureReport {
    /// The fully qualified name of the signature field; `null` for a signature dictionary no
    /// field refers to (problem `orphan`).
    pub field_name: Option<String>,
    /// A signature or a document timestamp.
    #[napi(ts_type = "SignatureKind")]
    pub kind: String,
    /// The signature dictionary's object.
    pub sig_object: ObjectRef,
    /// The `/SubFilter`, for example `"ETSI.CAdES.detached"`.
    pub sub_filter: Option<String>,
    /// The `/ByteRange` as written; `null` when it is missing or not an array of integers.
    pub byte_range: Option<Vec<i64>>,
    /// The byte range is sound: four integers from 0, inside the file, whose gap is exactly this
    /// dictionary's `/Contents`, in an uncompressed dictionary inside the signed bytes.
    pub byte_range_ok: bool,
    /// The digest of the signed bytes equals the CMS message digest.
    pub intact: bool,
    /// The CMS signature verifies with the signer certificate.
    pub signature_valid: bool,
    /// How much of the file the byte ranges cover.
    #[napi(ts_type = "Coverage")]
    pub coverage: String,
    /// The index (oldest first) of the revision the signature covers.
    pub signed_revision: Option<u32>,
    /// What later revisions changed.
    #[napi(ts_type = "ModificationLevel")]
    pub modification: String,
    /// The objects later revisions list, sorted: at most 1,024 of them (the first by object
    /// number), with a warning giving the full count when there are more.
    pub changed_objects: Vec<ObjectRef>,
    /// The digest algorithm, for example `"sha256"`.
    pub digest_algorithm: Option<String>,
    /// The signature algorithm, for example `"sha256WithRSAEncryption"`.
    pub signature_algorithm: Option<String>,
    /// The signer certificate.
    pub signer: Option<CertificateInfo>,
    /// Every certificate of the CMS, in file order.
    pub chain: Vec<CertificateInfo>,
    /// Whether a certification path to a trust anchor validates; `null` without anchors.
    pub trusted: Option<bool>,
    /// The claimed signing time `/M`, RFC 3339.
    pub claimed_time: Option<String>,
    /// `/Name`.
    pub name: Option<String>,
    /// `/Reason`.
    pub reason: Option<String>,
    /// `/Location`.
    pub location: Option<String>,
    /// `/ContactInfo`.
    pub contact_info: Option<String>,
    /// The PAdES baseline level the signature meets.
    #[napi(ts_type = "PadesLevel")]
    pub pades_level: Option<String>,
    /// For a certification signature, its DocMDP permissions `P` (1–3).
    pub docmdp: Option<u32>,
    /// Whether later revisions respect the DocMDP permissions; `null` until certification
    /// signatures are supported.
    pub docmdp_ok: Option<bool>,
    /// Why the signature is not valid; empty when nothing is wrong.
    pub problems: Vec<SignatureProblem>,
    /// Observations that do not make the signature invalid.
    pub warnings: Vec<String>,
}

impl From<folioxide::SignatureReport> for SignatureReport {
    fn from(report: folioxide::SignatureReport) -> SignatureReport {
        SignatureReport {
            field_name: report.field_name,
            kind: report.kind.as_str().to_owned(),
            sig_object: report.sig_object.into(),
            sub_filter: report.sub_filter,
            byte_range: report.byte_range,
            byte_range_ok: report.byte_range_ok,
            intact: report.intact,
            signature_valid: report.signature_valid,
            coverage: report.coverage.as_str().to_owned(),
            signed_revision: report
                .signed_revision
                .map(|k| u32::try_from(k).unwrap_or(u32::MAX)),
            modification: report.modification.as_str().to_owned(),
            changed_objects: report
                .changed_objects
                .into_iter()
                .map(ObjectRef::from)
                .collect(),
            digest_algorithm: report.digest_algorithm,
            signature_algorithm: report.signature_algorithm,
            signer: report.signer.map(CertificateInfo::from),
            chain: report
                .chain
                .into_iter()
                .map(CertificateInfo::from)
                .collect(),
            trusted: report.trusted,
            claimed_time: report.claimed_time,
            name: report.name,
            reason: report.reason,
            location: report.location,
            contact_info: report.contact_info,
            pades_level: report.pades_level.map(|level| level.as_str().to_owned()),
            docmdp: report.docmdp.map(u32::from),
            docmdp_ok: report.docmdp_ok,
            problems: report
                .problems
                .into_iter()
                .map(SignatureProblem::from)
                .collect(),
            warnings: report.warnings,
        }
    }
}

// ---- tasks -----------------------------------------------------------------------------------

/// Why an asynchronous task on a document failed.
#[derive(Debug)]
pub enum DocumentTaskError {
    /// The core's error.
    Core(folioxide::Error),
    /// The document was dropped before the task ran (it cannot be: a closed document is kept
    /// until the tasks started on it end; kept for robustness).
    Closed,
}

impl DocumentTaskError {
    fn into_js(self) -> BindingError {
        match self {
            DocumentTaskError::Core(err) => from_core(&err),
            DocumentTaskError::Closed => closed(),
        }
    }
}

/// Runs `op` on the document of a task, on the thread pool, then ends the task's hold on the
/// document (`pending`).
fn with_document<T>(
    shared: &Shared,
    pending: &mut Option<Pending>,
    op: impl FnOnce(&folioxide::Document) -> folioxide::Result<T>,
) -> Result<T, DocumentTaskError> {
    let result = {
        let guard = shared.lock();
        match guard.as_ref() {
            None => Err(DocumentTaskError::Closed),
            Some(doc) => op(doc).map_err(DocumentTaskError::Core),
        }
    };
    // The lock is released: synchronous methods may run again (and, if the document was closed
    // meanwhile, the last task drops it here).
    *pending = None;
    result
}

/// Prepares a signature on the libuv thread pool (`prepareSignatureAsync`).
pub struct PrepareTask {
    shared: Arc<Shared>,
    request: folioxide::PrepareRequest,
    /// Marks the document busy until the work is done (dropped at the end of `compute`).
    pending: Option<Pending>,
}

#[napi]
impl Task for PrepareTask {
    type Output = Result<folioxide::PreparedSignature, DocumentTaskError>;
    type JsValue = PreparedSignature;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let request = &self.request;
        Ok(with_document(&self.shared, &mut self.pending, |doc| {
            Ok(folioxide::prepare(doc, request)?)
        }))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        // Preparing read the pages and the form: report what the document holds now.
        self.shared.report_if_free(&env);
        output
            .map(|prepared| PreparedSignature::reported(&env, prepared))
            .map_err(|err| error::into_rejection(env, err.into_js()))
    }
}

/// Verifies a document's signatures on the libuv thread pool (`verifySignatures`).
pub struct VerifyTask {
    shared: Arc<Shared>,
    options: folioxide::VerifyOptions,
    /// Marks the document busy until the work is done (dropped at the end of `compute`).
    pending: Option<Pending>,
}

#[napi]
impl Task for VerifyTask {
    type Output = Result<Vec<SignatureReport>, DocumentTaskError>;
    type JsValue = Vec<SignatureReport>;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let options = &self.options;
        Ok(with_document(&self.shared, &mut self.pending, |doc| {
            let reports = folioxide::verify(doc, options)?;
            Ok(reports.into_iter().map(SignatureReport::from).collect())
        }))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        // Verifying resolved every object: report what the document holds now.
        self.shared.report_if_free(&env);
        output.map_err(|err| error::into_rejection(env, err.into_js()))
    }
}

/// What a [`FinishTask`] does with its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Finishing {
    /// `finish`: the input is a signature value.
    Signature,
    /// `embedCms`: the input is a whole CMS.
    Cms,
}

/// Finishes `prepared` with `input`. A refusal gives the prepared signature back with the
/// error ([`folioxide::FinishError`]).
fn finish_with(
    prepared: folioxide::PreparedSignature,
    input: &[u8],
    how: Finishing,
) -> Result<Vec<u8>, folioxide::FinishError> {
    match how {
        Finishing::Signature => prepared.try_finish(input),
        Finishing::Cms => prepared.try_embed_cms(input),
    }
}

/// Finishes a prepared signature on the libuv thread pool (`finishAsync`, `embedCmsAsync`).
///
/// It holds the core value while it runs. `resolve` puts a refused value back into the
/// JavaScript object's [`Slot`], so the caller can try again.
pub struct FinishTask {
    /// The slot of the `PreparedSignature` this task finishes.
    slot: Arc<Mutex<Slot>>,
    /// The core value, until it is finished; a refused value is kept here for `resolve`.
    prepared: Option<folioxide::PreparedSignature>,
    input: Vec<u8>,
    how: Finishing,
}

#[napi]
impl Task for FinishTask {
    type Output = folioxide::Result<Vec<u8>>;
    type JsValue = Buffer;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let Some(prepared) = self.prepared.take() else {
            return Ok(Err(folioxide::sign::Error::InvalidArgument(
                ALREADY_FINISHED.to_owned(),
            )
            .into()));
        };
        Ok(match finish_with(prepared, &self.input, self.how) {
            Ok(pdf) => Ok(pdf),
            Err(refused) => {
                let (error, prepared) = refused.into_parts();
                self.prepared = Some(prepared);
                Err(error.into())
            }
        })
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        self.settle(&env, output.is_ok());
        output
            .map(Buffer::from)
            .map_err(|err| error::into_rejection(env, from_core(&err)))
    }
}

impl FinishTask {
    /// Hands the outcome to the JavaScript object's slot: a success finishes it, a refusal puts
    /// the value back so the caller can try again.
    fn settle(&mut self, env: &Env, succeeded: bool) {
        let mut slot = lock(&self.slot);
        slot.in_flight = false;
        if succeeded {
            slot.finished(env);
        } else {
            slot.prepared = self.prepared.take();
        }
    }
}

/// Signs bytes with a local key on the libuv thread pool (`LocalSigner.signAsync`).
pub struct SignTask {
    signer: Arc<folioxide::LocalSigner>,
    digest: DigestAlgorithm,
    data: Vec<u8>,
}

#[napi]
impl Task for SignTask {
    type Output = folioxide::Result<Vec<u8>>;
    type JsValue = Buffer;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        Ok(self
            .signer
            .sign(self.digest, &self.data)
            .map_err(folioxide::Error::from))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        output
            .map(Buffer::from)
            .map_err(|err| error::into_rejection(env, from_core(&err)))
    }
}

// ---- PdfDocument ---------------------------------------------------------------------------

#[napi]
impl PdfDocument {
    /// The first phase of signing: builds the incremental update that adds an invisible
    /// signature (the document's pending changes, the field and the signature dictionary with
    /// its placeholders), digests the signed byte ranges and builds the signed attributes. The
    /// document is not changed.
    ///
    /// Sign the returned object's `toBeSigned` (or `toBeSignedDigest`) with the key of the
    /// first certificate, then call its `finish` with the signature value.
    ///
    /// Throws `E_INVALID_ARGUMENT` for invalid options (an empty chain, an algorithm that does
    /// not match the certificate, …), `E_SIGNATURE_PLACEHOLDER_TOO_SMALL` for a
    /// `contentsReserve` below what the CMS needs, `E_UNSUPPORTED` for a document whose
    /// structure was repaired or that has bytes before its header (save it in full first),
    /// `E_DOC_MDP_FORBIDS` for a certified document that allows no changes,
    /// `E_PAGE_OUT_OF_RANGE`, `E_NOT_FOUND`, `E_CERTIFICATE`.
    #[napi]
    pub fn prepare_signature(
        &self,
        env: Env,
        options: PrepareSignatureOptions,
    ) -> Result<PreparedSignature, BindingError> {
        let request = options.into_core()?;
        let prepared = self.read(&env, |doc| Ok(folioxide::prepare(doc, &request)?))?;
        Ok(PreparedSignature::reported(&env, prepared))
    }

    /// Like `prepareSignature`, on the libuv thread pool.
    #[napi(ts_return_type = "Promise<PreparedSignature>")]
    pub fn prepare_signature_async(
        &self,
        options: PrepareSignatureOptions,
    ) -> Result<AsyncTask<PrepareTask>, BindingError> {
        let request = options.into_core()?;
        let (shared, pending) = self.start_task()?;
        Ok(AsyncTask::new(PrepareTask {
            shared,
            request,
            pending: Some(pending),
        }))
    }

    /// Verifies every signature of the document, on the libuv thread pool: one report per
    /// signature dictionary, in signing order, dictionaries no field refers to last.
    ///
    /// Rejects with `E_INVALID_ARGUMENT` when the document has unsaved changes (verify the
    /// saved file) or an option is invalid.
    #[napi(ts_return_type = "Promise<Array<SignatureReport>>")]
    pub fn verify_signatures(
        &self,
        options: Option<VerifyOptions>,
    ) -> Result<AsyncTask<VerifyTask>, BindingError> {
        let options = options.unwrap_or_default().into_core()?;
        let (shared, pending) = self.start_task()?;
        Ok(AsyncTask::new(VerifyTask {
            shared,
            options,
            pending: Some(pending),
        }))
    }
}

// ---- PreparedSignature -----------------------------------------------------------------------

/// The message of the error `finish` and `embedCms` throw once a finish succeeded.
const ALREADY_FINISHED: &str = "this PreparedSignature was already finished: the first \
    successful finish, finishAsync, embedCms or embedCmsAsync takes it; prepare the signature \
    again to sign once more";

/// What a [`PreparedSignature`] shares with its running `finishAsync` or `embedCmsAsync`.
///
/// Only the JavaScript thread locks it (the methods, and the task's `resolve`), so the lock is
/// never contended.
#[derive(Default)]
struct Slot {
    /// The core value: `None` once a finish succeeded, or while a task holds it.
    prepared: Option<folioxide::PreparedSignature>,
    /// A `finishAsync` or `embedCmsAsync` holds the value.
    in_flight: bool,
    /// A finish succeeded.
    finished: bool,
    /// The bytes reported to V8 as external memory (the prepared file), until a finish succeeds
    /// or the object is finalized.
    reported: i64,
}

impl Slot {
    /// Takes the core value for a finish.
    ///
    /// # Errors
    /// `E_BUSY` while a `finishAsync` or `embedCmsAsync` holds it, `E_INVALID_ARGUMENT` once a
    /// finish succeeded.
    fn take(&mut self) -> JsResult<folioxide::PreparedSignature> {
        if self.in_flight {
            return Err(finishing());
        }
        self.prepared
            .take()
            .ok_or_else(|| invalid_argument(ALREADY_FINISHED))
    }

    /// A finish succeeded: the prepared file is gone, and V8 gets its memory back.
    fn finished(&mut self, env: &Env) {
        self.finished = true;
        self.prepared = None;
        give_back(env, std::mem::take(&mut self.reported));
    }
}

/// Locks `slot`. Nothing panics while it is held, so a poisoned lock still holds a consistent
/// slot.
fn lock(slot: &Mutex<Slot>) -> MutexGuard<'_, Slot> {
    slot.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A prepared signature: the file with the placeholders, and the bytes to sign.
///
/// Sign `toBeSigned` (or `toBeSignedDigest`) with the signer's key, then call `finish` with the
/// signature value (or `embedCms` with a whole CMS): either returns the signed file. The first
/// of `finish`, `finishAsync`, `embedCms` and `embedCmsAsync` **that succeeds** takes the
/// prepared file; a later call throws `E_INVALID_ARGUMENT`. A refused value or CMS leaves it as
/// it was, so the caller can try again with a corrected one. While `finishAsync` or
/// `embedCmsAsync` runs, the other three and `serialize` throw `E_BUSY`.
#[napi(custom_finalize)]
pub struct PreparedSignature {
    /// The core value and its state, shared with a running `finishAsync` or `embedCmsAsync`.
    slot: Arc<Mutex<Slot>>,
    /// The bytes to sign, kept after the value is taken so the getters keep working.
    to_be_signed: Vec<u8>,
    digest: DigestAlgorithm,
    algorithm: SignatureAlgorithm,
    sub_filter: folioxide::SubFilter,
    capacity: usize,
    byte_range: [u64; 4],
    warnings: Vec<String>,
}

impl PreparedSignature {
    /// A new object for `prepared`, without reporting its memory.
    fn new(prepared: folioxide::PreparedSignature) -> PreparedSignature {
        PreparedSignature {
            to_be_signed: prepared.to_be_signed().to_vec(),
            digest: prepared.digest_algorithm(),
            algorithm: prepared.algorithm(),
            sub_filter: prepared.sub_filter(),
            capacity: prepared.contents_capacity(),
            byte_range: prepared.byte_range(),
            warnings: prepared.warnings().to_vec(),
            slot: Arc::new(Mutex::new(Slot {
                prepared: Some(prepared),
                ..Slot::default()
            })),
        }
    }

    /// A new object for `prepared`, whose file is reported to V8 as external memory.
    fn reported(env: &Env, prepared: folioxide::PreparedSignature) -> PreparedSignature {
        let object = PreparedSignature::new(prepared);
        {
            let mut slot = lock(&object.slot);
            let size = slot
                .prepared
                .as_ref()
                .map_or(0, |p| i64::try_from(p.pdf().len()).unwrap_or(i64::MAX));
            if size > 0 && env.adjust_external_memory(size).is_ok() {
                slot.reported = size;
            }
        }
        object
    }

    /// Finishes on the JavaScript thread. A refused input puts the core value back.
    fn finish_now(&self, env: &Env, input: &[u8], how: Finishing) -> Result<Buffer, BindingError> {
        let prepared = lock(&self.slot).take()?;
        match finish_with(prepared, input, how) {
            Ok(pdf) => {
                lock(&self.slot).finished(env);
                Ok(Buffer::from(pdf))
            }
            Err(refused) => {
                let (error, prepared) = refused.into_parts();
                lock(&self.slot).prepared = Some(prepared);
                Err(from_core(&error.into()))
            }
        }
    }

    /// A task that finishes on the thread pool; it takes the core value at once.
    fn finish_task(&self, input: Vec<u8>, how: Finishing) -> JsResult<FinishTask> {
        let mut slot = lock(&self.slot);
        let prepared = slot.take()?;
        slot.in_flight = true;
        Ok(FinishTask {
            slot: Arc::clone(&self.slot),
            prepared: Some(prepared),
            input,
            how,
        })
    }
}

/// Gives `reported` bytes of external memory back to V8.
fn give_back(env: &Env, reported: i64) {
    if reported != 0 {
        // A failure leaves V8's count high, which only makes it collect sooner.
        let _ = env.adjust_external_memory(-reported);
    }
}

/// The object was garbage-collected: V8 gets the memory of a prepared file that was never
/// finished back. (A task still running keeps the value until it is done.)
impl ObjectFinalize for PreparedSignature {
    fn finalize(self, env: Env) -> napi::Result<()> {
        let reported = std::mem::take(&mut lock(&self.slot).reported);
        give_back(&env, reported);
        Ok(())
    }
}

#[napi]
impl PreparedSignature {
    /// Reads the form `serialize` writes (the core's versioned binary form) and checks every
    /// invariant again: the file, the byte range and the signed attributes must be unchanged.
    ///
    /// Throws `E_INVALID_ARGUMENT` for bytes that are not a serialized prepared signature of
    /// this version, or that were changed; `E_CERTIFICATE` or `E_UNSUPPORTED` for a signer
    /// certificate that does not parse or has an unsupported key.
    #[napi(factory)]
    pub fn deserialize(env: Env, data: Uint8Array) -> Result<PreparedSignature, BindingError> {
        folioxide::PreparedSignature::from_bytes(&data)
            .map(|prepared| PreparedSignature::reported(&env, prepared))
            .map_err(|err| from_core(&err.into()))
    }

    /// The bytes to sign: the DER signed attributes (RFC 5652 §5.4, universal `SET` tag), for
    /// "sign message" APIs that hash themselves (`node:crypto` `sign`, WebCrypto, KMS `RAW`).
    #[napi(getter)]
    pub fn to_be_signed(&self) -> Buffer {
        Buffer::from(self.to_be_signed.clone())
    }

    /// The digest of `toBeSigned` with `digestAlgorithm`, for "sign digest" HSM and KMS APIs.
    #[napi(getter)]
    pub fn to_be_signed_digest(&self) -> Buffer {
        Buffer::from(self.digest.digest(&[&self.to_be_signed]))
    }

    /// The DER `DigestInfo` of `toBeSignedDigest` (RFC 8017 §9.2), for raw RSA signing
    /// (PKCS#11 `CKM_RSA_PKCS`).
    #[napi(getter)]
    pub fn to_be_signed_digest_info(&self) -> Buffer {
        let digest = self.digest.digest(&[&self.to_be_signed]);
        Buffer::from(self.digest.digest_info(&digest))
    }

    /// The digest algorithm the signature uses.
    #[napi(getter, ts_return_type = "DigestAlg")]
    pub fn digest_algorithm(&self) -> String {
        self.digest.name().to_owned()
    }

    /// The signature algorithm of the signer's key.
    #[napi(getter, ts_return_type = "SigAlg")]
    pub fn algorithm(&self) -> String {
        sig_alg_name(self.algorithm)
    }

    /// The `/SubFilter` of the signature dictionary.
    #[napi(getter, ts_return_type = "SubFilter")]
    pub fn sub_filter(&self) -> String {
        self.sub_filter.name().to_owned()
    }

    /// The bytes of DER the `/Contents` placeholder holds.
    #[napi(getter)]
    pub fn contents_capacity(&self) -> u32 {
        u32::try_from(self.capacity).unwrap_or(u32::MAX)
    }

    /// `[0, a, b, c]`: the signed byte ranges `[0, a)` and `[b, b + c)` of the finished file;
    /// `[a, b)` is the `/Contents` hexadecimal string.
    #[napi(getter)]
    pub fn byte_range(&self) -> Vec<f64> {
        // File offsets are below 10^10 (the ByteRange placeholder's width), exact in an f64.
        self.byte_range.iter().map(|&v| v as f64).collect()
    }

    /// Observations from preparing, for example an AcroForm `/NeedAppearances true` left as it
    /// is.
    #[napi(getter)]
    pub fn warnings(&self) -> Vec<String> {
        self.warnings.clone()
    }

    /// Whether `finish`, `finishAsync`, `embedCms` or `embedCmsAsync` succeeded (and took the
    /// prepared file).
    #[napi(getter)]
    pub fn is_finished(&self) -> bool {
        lock(&self.slot).finished
    }

    /// Finishes the file with `signature`, the signature value over `toBeSigned`: returns the
    /// signed PDF. RSA: the modulus length; ECDSA: DER or IEEE P1363 (`r || s`). The value is
    /// verified with the signer certificate before it is embedded. A refused value leaves the
    /// prepared signature as it was: call `finish` again with the right one.
    ///
    /// Throws `E_SIGNATURE_INVALID` when the value does not verify (another key, another
    /// digest, other bytes), `E_INVALID_ARGUMENT` when a finish succeeded already, `E_BUSY`
    /// while `finishAsync` or `embedCmsAsync` runs.
    #[napi]
    pub fn finish(&self, env: Env, signature: Uint8Array) -> Result<Buffer, BindingError> {
        self.finish_now(&env, &signature, Finishing::Signature)
    }

    /// Like `finish`, on the libuv thread pool. Until it settles, the other finishing methods
    /// and `serialize` throw `E_BUSY`.
    #[napi(ts_return_type = "Promise<Buffer>")]
    pub fn finish_async(
        &self,
        signature: Uint8Array,
    ) -> Result<AsyncTask<FinishTask>, BindingError> {
        self.finish_task(signature.to_vec(), Finishing::Signature)
            .map(AsyncTask::new)
    }

    /// Finishes the file with `cms`, a whole CMS `ContentInfo` (DER) that a signing service
    /// made over the prepared byte ranges: returns the signed PDF. The CMS must sign exactly
    /// these bytes, with one signer whose signature verifies; for `'ETSI.CAdES.detached'` it
    /// must also meet PAdES baseline B-B. A refused CMS leaves the prepared signature as it was.
    ///
    /// Throws `E_SIGNATURE_INVALID` when it signs other bytes or does not verify,
    /// `E_INVALID_ARGUMENT` when it is not such a CMS or a finish succeeded already,
    /// `E_SIGNATURE_PLACEHOLDER_TOO_SMALL` (with `details.needed`) when it is larger than
    /// `contentsCapacity`, `E_BUSY` while `finishAsync` or `embedCmsAsync` runs.
    #[napi]
    pub fn embed_cms(&self, env: Env, cms: Uint8Array) -> Result<Buffer, BindingError> {
        self.finish_now(&env, &cms, Finishing::Cms)
    }

    /// Like `embedCms`, on the libuv thread pool. Until it settles, the other finishing
    /// methods and `serialize` throw `E_BUSY`.
    #[napi(ts_return_type = "Promise<Buffer>")]
    pub fn embed_cms_async(&self, cms: Uint8Array) -> Result<AsyncTask<FinishTask>, BindingError> {
        self.finish_task(cms.to_vec(), Finishing::Cms)
            .map(AsyncTask::new)
    }

    /// The prepared signature in the core's versioned binary form (magic `FXPS`, version 1),
    /// to finish it later or in another process with `PreparedSignature.deserialize`. It holds
    /// the whole prepared file.
    ///
    /// Throws `E_INVALID_ARGUMENT` when a finish succeeded already, `E_BUSY` while
    /// `finishAsync` or `embedCmsAsync` runs.
    #[napi]
    pub fn serialize(&self) -> Result<Buffer, BindingError> {
        let slot = lock(&self.slot);
        if slot.in_flight {
            return Err(finishing());
        }
        slot.prepared
            .as_ref()
            .map(|prepared| Buffer::from(prepared.to_bytes()))
            .ok_or_else(|| invalid_argument(ALREADY_FINISHED))
    }
}

// ---- LocalSigner -----------------------------------------------------------------------------

/// A secret given as a string or as UTF-8 bytes, lent to `f` as text. The binding's copy of a
/// string is wiped when `f` returns; bytes are read in place, so the caller can wipe them.
///
/// # Errors
/// `E_INVALID_ARGUMENT` for bytes that are not UTF-8 (the message names `name`, never the
/// value); the errors of `f`.
fn with_secret<T>(
    secret: Either<String, Uint8Array>,
    name: &str,
    f: impl FnOnce(&str) -> JsResult<T>,
) -> JsResult<T> {
    match secret {
        Either::A(text) => {
            let text = Zeroizing::new(text);
            f(&text)
        }
        Either::B(bytes) => {
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| invalid_argument(format!("{name} is not valid UTF-8")))?;
            f(text)
        }
    }
}

/// A private key held in memory with its certificate chain, loaded from PKCS#12 or PEM.
///
/// RSA signatures use the blinded path; on servers where an attacker can time many signatures,
/// prefer ECDSA keys or an external signer (KMS, HSM), because the `rsa` crate has an
/// unpatched timing advisory (RUSTSEC-2023-0071).
///
/// **Key hygiene.** The key is held in memory that is wiped when it is dropped: at `close()`, or
/// when the object is garbage-collected if that comes first (a `signAsync` already running
/// keeps it until it is done). The binding wipes its own copies of the password and of the PEM
/// key once the key is loaded, but cannot wipe what JavaScript holds: strings are immutable and
/// garbage-collected. To keep a secret out of the JavaScript heap as a string, pass it as a
/// `Uint8Array` (UTF-8) and `fill(0)` it after loading. `p12-keystore` keeps an unwiped copy of
/// a PKCS#12 key while the file is loaded; it is dropped before `fromPkcs12` returns.
#[napi]
pub struct LocalSigner {
    /// The key; `None` once `close()` was called.
    inner: Option<Arc<folioxide::LocalSigner>>,
}

impl LocalSigner {
    /// A new object for `signer`.
    fn new(signer: folioxide::LocalSigner) -> LocalSigner {
        LocalSigner {
            inner: Some(Arc::new(signer)),
        }
    }

    /// The key.
    ///
    /// # Errors
    /// `E_CLOSED` once `close()` was called.
    fn key(&self) -> JsResult<&Arc<folioxide::LocalSigner>> {
        self.inner.as_ref().ok_or_else(signer_closed)
    }

    /// The digest for `digest`, or the key's default.
    fn digest(&self, digest: Option<String>) -> JsResult<DigestAlgorithm> {
        let key = self.key()?;
        match digest {
            Some(text) => parse_digest(&text, "digest"),
            None => Ok(folioxide::default_digest(key.key_kind())),
        }
    }

    /// A task that signs `data` on the thread pool; it holds a reference to the key.
    fn sign_task(&self, data: &[u8], digest: Option<String>) -> JsResult<SignTask> {
        Ok(SignTask {
            digest: self.digest(digest)?,
            signer: Arc::clone(self.key()?),
            data: data.to_vec(),
        })
    }
}

#[napi]
impl LocalSigner {
    /// Loads the key and its certificate chain from a PKCS#12 (`.p12`, `.pfx`) file. The MAC is
    /// checked before anything is decrypted; modern (AES) and legacy (3DES, RC2-40) files load.
    /// The password is a string or its UTF-8 bytes.
    ///
    /// Throws `E_WRONG_PASSWORD` for a wrong password, `E_UNSUPPORTED` for an unsupported
    /// encryption scheme, `E_KEY_LOAD` for anything else (no key, a corrupt file, a key that
    /// does not match its certificate, an RSA key below 2048 bits, excessive key-derivation
    /// parameters), `E_INVALID_ARGUMENT` for a password that is not UTF-8. Messages never
    /// contain the password.
    #[napi(factory)]
    pub fn from_pkcs12(
        data: Uint8Array,
        password: Either<String, Uint8Array>,
    ) -> Result<LocalSigner, BindingError> {
        with_secret(password, "password", |password| {
            folioxide::LocalSigner::from_pkcs12(&data, password)
                .map(LocalSigner::new)
                .map_err(|err| from_core(&err.into()))
        })
    }

    /// Loads the key from PEM (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `RSA PRIVATE KEY` or
    /// `EC PRIVATE KEY`) and the certificates from one or more `CERTIFICATE` blocks; the
    /// certificate that matches the key is put first. The key and its password are strings or
    /// their UTF-8 bytes.
    ///
    /// Throws `E_PASSWORD_REQUIRED` for an encrypted key without a password,
    /// `E_WRONG_PASSWORD` when it does not decrypt, `E_CERTIFICATE` when the certificates do not
    /// parse, `E_UNSUPPORTED` for legacy OpenSSL encryption or an unsupported key type,
    /// `E_KEY_LOAD` for anything else (no certificate matches the key, an RSA key below 2048
    /// bits, excessive key-derivation parameters), `E_INVALID_ARGUMENT` for bytes that are not
    /// UTF-8.
    #[napi(factory)]
    pub fn from_pem(
        key_pem: Either<String, Uint8Array>,
        certs_pem: String,
        key_password: Option<Either<String, Uint8Array>>,
    ) -> Result<LocalSigner, BindingError> {
        with_secret(key_pem, "keyPem", |key_pem| {
            let load = |password: Option<&str>| {
                folioxide::LocalSigner::from_pem(key_pem, &certs_pem, password)
                    .map(LocalSigner::new)
                    .map_err(|err| from_core(&err.into()))
            };
            match key_password {
                Some(password) => {
                    with_secret(password, "keyPassword", |password| load(Some(password)))
                }
                None => load(None),
            }
        })
    }

    /// Wipes the key from memory now, instead of when the object is garbage-collected. Every
    /// method then throws `E_CLOSED`; a `signAsync` already running finishes first and wipes
    /// the key when it is done. Calling it again does nothing.
    #[napi]
    pub fn close(&mut self) {
        self.inner = None;
    }

    /// Whether `close()` was called.
    #[napi(getter)]
    pub fn is_closed(&self) -> bool {
        self.inner.is_none()
    }

    /// The DER certificates: the signer's first, then the intermediates (and the root, when
    /// the file has it).
    ///
    /// Throws `E_CLOSED` after `close()`.
    #[napi(getter)]
    pub fn certificate_chain(&self) -> Result<Vec<Buffer>, BindingError> {
        Ok(self
            .key()?
            .certificate_chain()
            .iter()
            .map(|der| Buffer::from(der.clone()))
            .collect())
    }

    /// The signature algorithm of the key.
    ///
    /// Throws `E_CLOSED` after `close()`.
    #[napi(getter, ts_return_type = "SigAlg")]
    pub fn algorithm(&self) -> Result<String, BindingError> {
        Ok(sig_alg_name(self.key()?.algorithm()))
    }

    /// The digest used when none is given: SHA-256 for RSA and P-256 keys, SHA-384 for P-384
    /// keys.
    ///
    /// Throws `E_CLOSED` after `close()`.
    #[napi(getter, ts_return_type = "DigestAlg")]
    pub fn default_digest(&self) -> Result<String, BindingError> {
        Ok(folioxide::default_digest(self.key()?.key_kind())
            .name()
            .to_owned())
    }

    /// Signs `data` (hashing it with `digest`, default `defaultDigest`): RSA PKCS#1 v1.5 (the
    /// modulus length) or ECDSA (a DER `ECDSA-Sig-Value`, deterministic per RFC 6979).
    ///
    /// Throws `E_INVALID_ARGUMENT` for an unknown digest, `E_CRYPTO` when signing fails,
    /// `E_CLOSED` after `close()`.
    #[napi]
    pub fn sign(
        &self,
        data: Uint8Array,
        #[napi(ts_arg_type = "DigestAlg")] digest: Option<String>,
    ) -> Result<Buffer, BindingError> {
        let digest = self.digest(digest)?;
        self.key()?
            .sign(digest, &data)
            .map(Buffer::from)
            .map_err(|err| from_core(&err.into()))
    }

    /// Like `sign`, on the libuv thread pool.
    #[napi(ts_return_type = "Promise<Buffer>")]
    pub fn sign_async(
        &self,
        data: Uint8Array,
        #[napi(ts_arg_type = "DigestAlg")] digest: Option<String>,
    ) -> Result<AsyncTask<SignTask>, BindingError> {
        self.sign_task(&data, digest).map(AsyncTask::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Buffer` as serde writes a `Vec<u8>`: an array of numbers.
    pub(super) fn bytes<S: serde::Serializer>(buffer: &Buffer, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(buffer.len()))?;
        for byte in buffer.iter() {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }

    /// A file of the committed test PKI (`fixtures/pki`).
    fn pki(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/pki")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
    }

    fn pki_text(name: &str) -> String {
        String::from_utf8(pki(name)).expect("PEM is UTF-8")
    }

    /// A one-page PDF with a classic cross-reference table.
    fn one_page_pdf() -> Vec<u8> {
        let objects = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
        ];
        let mut out = b"%PDF-1.7\n".to_vec();
        let mut offsets = Vec::new();
        for (i, body) in objects.iter().enumerate() {
            offsets.push(out.len());
            out.extend(format!("{} 0 obj\n{body}\nendobj\n", i + 1).bytes());
        }
        let xref = out.len();
        out.extend(b"xref\n0 4\n0000000000 65535 f \n");
        for offset in offsets {
            out.extend(format!("{offset:010} 00000 n \n").bytes());
        }
        out.extend(
            format!("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").bytes(),
        );
        out
    }

    fn open(pdf: Vec<u8>) -> folioxide::Document {
        folioxide::Document::open(pdf, &folioxide::OpenOptions::default()).expect("opens")
    }

    fn p256_signer() -> folioxide::LocalSigner {
        let certs = pki_text("signer-p256.pem") + &pki_text("intermediate.pem");
        folioxide::LocalSigner::from_pem(&pki_text("signer-p256.key.pem"), &certs, None)
            .expect("loads")
    }

    fn time() -> folioxide::PdfDate {
        folioxide::PdfDate::parse(b"D:20261010120000Z").expect("a date")
    }

    /// A `Uint8Array` (napi-rs creates one from a `Vec` without a JavaScript environment).
    fn array(bytes: &[u8]) -> Uint8Array {
        Uint8Array::new(bytes.to_vec())
    }

    /// JSON with every number as an `f64`, as JavaScript holds it.
    fn js_numbers(value: serde_json::Value) -> serde_json::Value {
        use serde_json::Value;
        match value {
            Value::Number(n) => n
                .as_f64()
                .and_then(serde_json::Number::from_f64)
                .map_or(Value::Null, Value::Number),
            Value::Array(items) => Value::Array(items.into_iter().map(js_numbers).collect()),
            Value::Object(map) => {
                Value::Object(map.into_iter().map(|(k, v)| (k, js_numbers(v))).collect())
            }
            other => other,
        }
    }

    fn json<T: serde::Serialize>(value: &T) -> serde_json::Value {
        js_numbers(serde_json::to_value(value).expect("serializes"))
    }

    /// Two signatures, verified against the test root: one covers its revision, the other the
    /// whole file.
    fn two_signature_reports() -> Vec<folioxide::SignatureReport> {
        let signer = p256_signer();
        let first = folioxide::sign(
            &open(one_page_pdf()),
            &folioxide::SignRequest::new(&signer, time()),
        )
        .expect("signs");
        let request = folioxide::SignRequest::new(&signer, time());
        let options = request
            .options
            .clone()
            .with_reason(Some("Genehmigt – 承認 ✓".to_owned()));
        let second = folioxide::sign(&open(first), &request.with_options(options)).expect("signs");
        let anchors = folioxide::certificates_from_pem(&pki_text("root.pem")).expect("root");
        let options = folioxide::VerifyOptions::new()
            .with_trust_anchors_der(anchors)
            .with_validation_time(Some(time()));
        folioxide::verify_bytes(second, &options).expect("verifies")
    }

    /// The report objects have the JSON shape of the core's serde DTOs (ARCHITECTURE §A.7):
    /// `camelCase` names, `null` for absent values, enums as strings, `{ num, gen }` ids.
    #[test]
    fn report_json_matches_the_core() {
        let reports = two_signature_reports();
        assert_eq!(reports.len(), 2);
        for core in reports {
            let binding = SignatureReport::from(core.clone());
            assert_eq!(json(&binding), json(&core));
        }
        // An orphan-like report with every optional value absent and problems present.
        let mut core = two_signature_reports().remove(0);
        core.field_name = None;
        core.signer = None;
        core.trusted = None;
        core.pades_level = None;
        core.problems.push(folioxide::Problem::new(
            folioxide::ProblemCode::Orphan,
            "no field refers to it",
        ));
        let binding = SignatureReport::from(core.clone());
        assert_eq!(json(&binding), json(&core));
        let value = json(&binding);
        assert_eq!(value["fieldName"], serde_json::Value::Null);
        assert_eq!(value["padesLevel"], serde_json::Value::Null);
        assert_eq!(value["problems"][0]["code"], "orphan");
    }

    #[test]
    fn reports_carry_the_verdict() {
        let reports: Vec<SignatureReport> = two_signature_reports()
            .into_iter()
            .map(SignatureReport::from)
            .collect();
        let [first, second] = &reports[..] else {
            panic!("two reports");
        };
        assert_eq!(first.coverage, "entireRevision");
        assert_eq!(first.modification, "formFilling");
        assert_eq!(second.coverage, "entireFile");
        assert_eq!(second.modification, "none");
        assert_eq!(second.reason.as_deref(), Some("Genehmigt – 承認 ✓"));
        for report in &reports {
            assert!(report.intact && report.signature_valid && report.byte_range_ok);
            assert_eq!(report.trusted, Some(true));
            assert_eq!(report.pades_level.as_deref(), Some("B-B"));
            assert_eq!(report.kind, "signature");
            let signer = report.signer.as_ref().expect("signer");
            assert_eq!(signer.key.curve.as_deref(), Some("P-256"));
            assert_eq!(&signer.der[..], &p256_signer().certificate_chain()[0][..]);
        }
    }

    #[test]
    fn names_parse_strictly() {
        assert_eq!(
            parse_sig_alg("ecdsa", "algorithm").ok(),
            Some(SignatureAlgorithm::Ecdsa)
        );
        assert_eq!(
            parse_sig_alg("rsa-pkcs1v15", "algorithm").ok(),
            Some(SignatureAlgorithm::RsaPkcs1v15)
        );
        assert_eq!(
            parse_digest("sha384", "digest").ok(),
            Some(DigestAlgorithm::Sha384)
        );
        for bad in ["ECDSA", "rsa", "rsa-pss", ""] {
            let err = parse_sig_alg(bad, "algorithm").expect_err(bad);
            assert_eq!(err.status, "E_INVALID_ARGUMENT");
            assert!(
                err.reason.contains("'rsa-pkcs1v15' or 'ecdsa'"),
                "{}",
                err.reason
            );
        }
        // SHA-1 is never used to sign; spellings other than the three names are refused.
        for bad in ["sha1", "SHA-256", "sha-256", "md5"] {
            assert!(parse_digest(bad, "digest").is_err(), "{bad}");
        }
        assert_eq!(
            parse_sub_filter("adbe.pkcs7.detached").ok(),
            Some(folioxide::SubFilter::AdbePkcs7Detached)
        );
        assert!(parse_sub_filter("adbe.pkcs7.sha1").is_err());
        assert_eq!(
            parse_field_mode("existingOnly").ok(),
            Some(folioxide::FieldMode::ExistingOnly)
        );
        assert!(parse_field_mode("ExistingOnly").is_err());
        assert!(parse_date("D:2026", "signingTime").is_ok());
        // The ISO 8601 form some producers write is read too (PdfDate::parse).
        assert_eq!(
            parse_date("2026-10-10T12:00:00Z", "signingTime").ok(),
            Some(time())
        );
        assert!(parse_date("10/10/2026", "signingTime").is_err());
    }

    #[test]
    fn certificates_take_der_and_pem() {
        let signer = pki("signer-p256.pem");
        let intermediate = pki("intermediate.pem");
        let mut both = signer.clone();
        both.extend_from_slice(b"\n");
        both.extend_from_slice(&intermediate);
        let der = folioxide::certificates_from_pem(&pki_text("root.pem")).expect("root");
        let list = [
            array(&both),
            array(&der[0]),
            array(b"  \n-----BEGIN CERTIFICATE-----\n"),
        ];
        // The last entry is PEM text without a certificate.
        let err = certificates(&list, "chain").expect_err("no certificate");
        assert_eq!(err.status, "E_CERTIFICATE");
        let certs = certificates(&list[..2], "chain").expect("certificates");
        assert_eq!(certs.len(), 3);
        assert_eq!(certs[2], der[0]);
        assert_eq!(certs[0], p256_signer().certificate_chain()[0]);
        // DER is passed on unchecked (prepare and verify check it where it is used).
        assert_eq!(
            certificates(&[array(b"\x30\x00")], "chain").expect("bytes"),
            vec![b"\x30\x00".to_vec()]
        );
        let err = certificates(&[array(b"-----BEGIN \xFF")], "chain").expect_err("not UTF-8");
        assert_eq!(err.status, "E_INVALID_ARGUMENT");
    }

    fn prepare_options() -> PrepareSignatureOptions {
        PrepareSignatureOptions {
            certificate_chain: vec![
                array(&pki("signer-p256.pem")),
                array(&pki("intermediate.pem")),
            ],
            algorithm: "ecdsa".to_owned(),
            signing_time: "D:20261010120000Z".to_owned(),
            ..PrepareSignatureOptions::default()
        }
    }

    #[test]
    fn prepare_options_convert() {
        let request = PrepareSignatureOptions {
            digest: Some("sha512".to_owned()),
            field: Some(SignatureFieldSpec {
                name: Some("Approval".to_owned()),
                page: Some(0.0),
                mode: Some("createOnly".to_owned()),
            }),
            sub_filter: Some("adbe.pkcs7.detached".to_owned()),
            name: Some("Jane".to_owned()),
            reason: Some("Approved".to_owned()),
            location: Some("Berlin".to_owned()),
            contact_info: Some("jane@example.com".to_owned()),
            contents_reserve: Some(16384.0),
            ..prepare_options()
        }
        .into_core()
        .expect("valid options");
        assert_eq!(request.chain_der.len(), 2);
        assert_eq!(request.algorithm, SignatureAlgorithm::Ecdsa);
        let expected = folioxide::SignatureOptions::new(time())
            .with_digest(Some(DigestAlgorithm::Sha512))
            .with_field(
                folioxide::FieldSpec::new()
                    .with_name(Some("Approval".to_owned()))
                    .with_mode(folioxide::FieldMode::CreateOnly),
            )
            .with_sub_filter(folioxide::SubFilter::AdbePkcs7Detached)
            .with_name(Some("Jane".to_owned()))
            .with_reason(Some("Approved".to_owned()))
            .with_location(Some("Berlin".to_owned()))
            .with_contact_info(Some("jane@example.com".to_owned()))
            .with_contents_reserve(Some(16384));
        assert_eq!(request.options, expected);
        // The defaults are the core's.
        let defaults = prepare_options().into_core().expect("defaults");
        assert_eq!(defaults.options, folioxide::SignatureOptions::new(time()));
    }

    #[test]
    fn prepare_options_reject_bad_values() {
        let cases: Vec<(PrepareSignatureOptions, &str)> = vec![
            (
                PrepareSignatureOptions {
                    certificate_chain: Vec::new(),
                    ..prepare_options()
                },
                "E_INVALID_ARGUMENT",
            ),
            (
                PrepareSignatureOptions {
                    algorithm: "dsa".to_owned(),
                    ..prepare_options()
                },
                "E_INVALID_ARGUMENT",
            ),
            (
                PrepareSignatureOptions {
                    signing_time: "yesterday".to_owned(),
                    ..prepare_options()
                },
                "E_INVALID_ARGUMENT",
            ),
            (
                PrepareSignatureOptions {
                    digest: Some("sha1".to_owned()),
                    ..prepare_options()
                },
                "E_INVALID_ARGUMENT",
            ),
            (
                PrepareSignatureOptions {
                    sub_filter: Some("ETSI.RFC3161".to_owned()),
                    ..prepare_options()
                },
                "E_INVALID_ARGUMENT",
            ),
            (
                PrepareSignatureOptions {
                    contents_reserve: Some(1.5),
                    ..prepare_options()
                },
                "E_INVALID_ARGUMENT",
            ),
            (
                PrepareSignatureOptions {
                    contents_reserve: Some(-1.0),
                    ..prepare_options()
                },
                "E_INVALID_ARGUMENT",
            ),
            (
                PrepareSignatureOptions {
                    field: Some(SignatureFieldSpec {
                        page: Some(-1.0),
                        ..SignatureFieldSpec::default()
                    }),
                    ..prepare_options()
                },
                "E_PAGE_OUT_OF_RANGE",
            ),
            (
                PrepareSignatureOptions {
                    field: Some(SignatureFieldSpec {
                        mode: Some("replace".to_owned()),
                        ..SignatureFieldSpec::default()
                    }),
                    ..prepare_options()
                },
                "E_INVALID_ARGUMENT",
            ),
        ];
        for (options, code) in cases {
            let err = options.into_core().expect_err("rejected");
            assert_eq!(err.status, code, "{}", err.reason);
        }
    }

    #[test]
    fn verify_options_convert() {
        let options = VerifyOptions {
            trust_anchors: Some(vec![array(&pki("root.pem"))]),
            extra_certificates: Some(vec![array(&pki("intermediate.pem"))]),
            validation_time: Some("D:20261010120000Z".to_owned()),
        }
        .into_core()
        .expect("valid");
        assert_eq!(options.trust_anchors_der.len(), 1);
        assert_eq!(options.extra_certs_der.len(), 1);
        assert_eq!(options.validation_time, Some(time()));
        assert_eq!(
            VerifyOptions::default().into_core().expect("defaults"),
            folioxide::VerifyOptions::default()
        );
        let err = VerifyOptions {
            validation_time: Some("now".to_owned()),
            ..VerifyOptions::default()
        }
        .into_core()
        .expect_err("not a date");
        assert_eq!(err.status, "E_INVALID_ARGUMENT");
    }

    #[test]
    fn tasks_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<PrepareTask>();
        assert_send::<VerifyTask>();
        assert_send::<FinishTask>();
        assert_send::<SignTask>();
    }

    /// The prepared signature of `one_page_pdf` for the P-256 signer.
    fn prepared() -> folioxide::PreparedSignature {
        let request = prepare_options().into_core().expect("request");
        folioxide::prepare(&open(one_page_pdf()), &request).expect("prepares")
    }

    /// An `Env` for the code paths that never call into V8: nothing was reported as external
    /// memory, and no error is turned into a JavaScript value.
    fn no_v8() -> Env {
        Env::from_raw(std::ptr::null_mut())
    }

    #[test]
    fn a_prepared_signature_is_kept_until_a_finish_succeeds() {
        let object = PreparedSignature::new(prepared());
        let expected = prepared();
        assert_eq!(&object.to_be_signed()[..], expected.to_be_signed());
        assert_eq!(
            &object.to_be_signed_digest()[..],
            &expected.to_be_signed_digest()[..]
        );
        assert_eq!(
            &object.to_be_signed_digest_info()[..],
            &expected.to_be_signed_digest_info()[..]
        );
        assert_eq!(object.digest_algorithm(), "sha256");
        assert_eq!(object.algorithm(), "ecdsa");
        assert_eq!(object.sub_filter(), "ETSI.CAdES.detached");
        assert_eq!(
            object.contents_capacity() as usize,
            expected.contents_capacity()
        );
        assert_eq!(object.byte_range()[0], 0.0);
        assert!(!object.is_finished());
        let serialized = object.serialize().expect("serializes");
        assert_eq!(&serialized[..], &expected.to_bytes()[..]);

        // Refused values and CMSes leave the prepared signature as it was.
        let env = no_v8();
        let other = folioxide::LocalSigner::from_pem(
            &pki_text("signer-p384.key.pem"),
            &pki_text("signer-p384.pem"),
            None,
        )
        .expect("loads");
        let wrong = other
            .sign(expected.digest_algorithm(), expected.to_be_signed())
            .expect("signs");
        for (input, how, code) in [
            (&wrong[..], Finishing::Signature, "E_SIGNATURE_INVALID"),
            (&b""[..], Finishing::Signature, "E_SIGNATURE_INVALID"),
            (&b"garbage"[..], Finishing::Cms, "E_INVALID_ARGUMENT"),
        ] {
            let err = object.finish_now(&env, input, how).err().expect("refused");
            assert_eq!(err.status, code);
            assert!(!object.is_finished());
            assert_eq!(
                &object.serialize().expect("still there")[..],
                &serialized[..]
            );
        }

        // The right value finishes the file; then the value is gone, the getters keep working.
        let value = p256_signer()
            .sign(expected.digest_algorithm(), expected.to_be_signed())
            .expect("signs");
        let signed = object
            .finish_now(&env, &value, Finishing::Signature)
            .expect("finishes");
        assert!(signed.starts_with(&one_page_pdf()));
        assert_eq!(
            &signed[..],
            &expected.clone().finish(&value).expect("finishes")[..]
        );
        assert!(object.is_finished());
        for how in [Finishing::Signature, Finishing::Cms] {
            let err = object
                .finish_now(&env, &value, how)
                .err()
                .expect("finished");
            assert_eq!(err.status, "E_INVALID_ARGUMENT");
            assert!(err.reason.contains("already finished"), "{}", err.reason);
        }
        assert_eq!(
            object.serialize().err().map(|e| e.status),
            Some("E_INVALID_ARGUMENT".to_owned())
        );
        assert_eq!(&object.to_be_signed()[..], expected.to_be_signed());
    }

    #[test]
    fn finish_tasks_hold_the_value_and_give_a_refused_one_back() {
        let env = no_v8();
        let object = PreparedSignature::new(prepared());
        let expected = prepared();
        let wrong = p256_signer()
            .sign(expected.digest_algorithm(), b"other bytes")
            .expect("signs");

        // While a task holds the value, every other finishing call and serialize are busy.
        let mut task = object
            .finish_task(wrong.clone(), Finishing::Signature)
            .expect("starts");
        for how in [Finishing::Signature, Finishing::Cms] {
            let err = object.finish_now(&env, &wrong, how).err().expect("busy");
            assert_eq!(err.status, "E_BUSY");
            let err = object.finish_task(wrong.clone(), how).err().expect("busy");
            assert_eq!(err.status, "E_BUSY");
        }
        assert_eq!(
            object.serialize().err().map(|e| e.status),
            Some("E_BUSY".to_owned())
        );
        assert!(!object.is_finished());

        // A refused value goes back to the object.
        let err = task.compute().expect("compute").expect_err("refused");
        assert_eq!(from_core(&err).status, "E_SIGNATURE_INVALID");
        task.settle(&env, false);
        assert!(!object.is_finished());
        assert_eq!(
            &object.serialize().expect("back")[..],
            &expected.to_bytes()[..]
        );

        // The right value finishes it.
        let value = p256_signer()
            .sign(expected.digest_algorithm(), expected.to_be_signed())
            .expect("signs");
        let mut task = object
            .finish_task(value.clone(), Finishing::Signature)
            .expect("starts");
        let signed = task.compute().expect("compute").expect("finishes");
        task.settle(&env, true);
        assert!(object.is_finished());
        let reports = folioxide::verify_bytes(signed, &folioxide::VerifyOptions::default())
            .expect("verifies");
        assert!(reports[0].is_valid());
        // A task whose value was taken refuses to run again.
        let err = task.compute().expect("compute").expect_err("taken");
        assert_eq!(from_core(&err).status, "E_INVALID_ARGUMENT");
        assert_eq!(
            object
                .finish_task(value, Finishing::Signature)
                .err()
                .map(|e| e.status),
            Some("E_INVALID_ARGUMENT".to_owned())
        );
    }

    #[test]
    fn document_tasks_release_the_document() {
        let expected = prepared();
        let doc = PdfDocument::new(open(one_page_pdf()));
        let (shared, pending) = doc.start_task().expect("starts");
        let mut task = PrepareTask {
            shared,
            request: prepare_options().into_core().expect("request"),
            pending: Some(pending),
        };
        assert!(doc.try_lock().is_err());
        let prepared = task.compute().expect("compute").expect("prepares");
        assert!(doc.try_lock().is_ok());
        assert_eq!(prepared.to_be_signed(), expected.to_be_signed());

        // Verification of a document without signatures, and of one with unsaved changes.
        let (shared, pending) = doc.start_task().expect("starts");
        let mut task = VerifyTask {
            shared,
            options: folioxide::VerifyOptions::default(),
            pending: Some(pending),
        };
        assert!(
            task.compute()
                .expect("compute")
                .expect("verifies")
                .is_empty()
        );
        assert!(doc.try_lock().is_ok());

        let new = PdfDocument::new(folioxide::Document::new());
        let (shared, pending) = new.start_task().expect("starts");
        let mut task = VerifyTask {
            shared,
            options: folioxide::VerifyOptions::default(),
            pending: Some(pending),
        };
        let err = task
            .compute()
            .expect("compute")
            .err()
            .expect("unsaved changes");
        assert_eq!(err.into_js().status, "E_INVALID_ARGUMENT");
    }

    #[test]
    fn sign_task_signs_with_the_local_key() {
        let signer = Arc::new(p256_signer());
        let mut task = SignTask {
            signer: Arc::clone(&signer),
            digest: DigestAlgorithm::Sha384,
            data: b"to be signed".to_vec(),
        };
        let value = task.compute().expect("compute").expect("signs");
        // RFC 6979: the same bytes and digest give the same signature.
        assert_eq!(
            value,
            signer
                .sign(DigestAlgorithm::Sha384, b"to be signed")
                .expect("signs")
        );
    }

    #[test]
    fn local_signer_loads_and_reports_errors_with_codes() {
        let signer = LocalSigner::from_pkcs12(
            array(&pki("signer-rsa2048-modern.p12")),
            Either::A("folioxide".to_owned()),
        )
        .expect("loads");
        assert_eq!(signer.algorithm().expect("open"), "rsa-pkcs1v15");
        assert_eq!(signer.default_digest().expect("open"), "sha256");
        assert_eq!(signer.certificate_chain().expect("open").len(), 3);
        let value = signer.sign(array(b"data"), None).expect("signs");
        assert_eq!(value.len(), 256);
        assert_eq!(
            signer
                .sign(array(b"data"), Some("sha1".to_owned()))
                .err()
                .map(|e| e.status),
            Some("E_INVALID_ARGUMENT".to_owned())
        );

        let err = LocalSigner::from_pkcs12(
            array(&pki("signer-rsa2048-modern.p12")),
            Either::A("wrong-secret".to_owned()),
        )
        .err()
        .expect("wrong password");
        assert_eq!(err.status, "E_WRONG_PASSWORD");
        assert!(!err.reason.contains("wrong-secret"));
        let err = LocalSigner::from_pem(
            Either::A(pki_text("signer-p384.key.enc.pem")),
            pki_text("signer-p384.pem"),
            None,
        )
        .err()
        .expect("needs a password");
        assert_eq!(err.status, "E_PASSWORD_REQUIRED");
        let signer = LocalSigner::from_pem(
            Either::A(pki_text("signer-p384.key.enc.pem")),
            pki_text("signer-p384.pem"),
            Some(Either::A("folioxide".to_owned())),
        )
        .expect("decrypts");
        assert_eq!(signer.default_digest().expect("open"), "sha384");
        let err = LocalSigner::from_pkcs12(array(b"garbage"), Either::A("folioxide".to_owned()))
            .err()
            .expect("garbage");
        assert_eq!(err.status, "E_KEY_LOAD");
    }

    #[test]
    fn local_signer_takes_secrets_as_bytes_and_closes() {
        // The password and the PEM key as UTF-8 bytes, which the caller can wipe.
        let mut signer = LocalSigner::from_pkcs12(
            array(&pki("signer-p256-modern.p12")),
            Either::B(array(b"folioxide")),
        )
        .expect("loads");
        let from_pem = LocalSigner::from_pem(
            Either::B(array(&pki("signer-p384.key.enc.pem"))),
            pki_text("signer-p384.pem"),
            Some(Either::B(array(b"folioxide"))),
        )
        .expect("decrypts");
        assert_eq!(from_pem.default_digest().expect("open"), "sha384");
        for (password, code) in [
            (&b"\xFF\xFE"[..], "E_INVALID_ARGUMENT"),
            (&b"wrong-secret"[..], "E_WRONG_PASSWORD"),
        ] {
            let err = LocalSigner::from_pkcs12(
                array(&pki("signer-p256-modern.p12")),
                Either::B(array(password)),
            )
            .err()
            .expect("refused");
            assert_eq!(err.status, code);
            assert!(!err.reason.contains("wrong-secret"), "{}", err.reason);
        }
        let err = LocalSigner::from_pem(
            Either::B(array(b"\xFF-----BEGIN PRIVATE KEY-----")),
            pki_text("signer-p384.pem"),
            None,
        )
        .err()
        .expect("not UTF-8");
        assert_eq!(err.status, "E_INVALID_ARGUMENT");
        assert!(err.reason.contains("keyPem"), "{}", err.reason);

        // close() wipes the key: every method throws E_CLOSED, a second close does nothing.
        assert!(!signer.is_closed());
        let mut task = signer.sign_task(b"data", None).expect("starts");
        signer.close();
        assert!(signer.is_closed());
        signer.close();
        assert!(signer.is_closed());
        let closed = |result: Result<(), BindingError>| result.err().map(|e| e.status);
        let expected = Some("E_CLOSED".to_owned());
        assert_eq!(closed(signer.certificate_chain().map(drop)), expected);
        assert_eq!(closed(signer.algorithm().map(drop)), expected);
        assert_eq!(closed(signer.default_digest().map(drop)), expected);
        assert_eq!(
            closed(signer.sign(array(b"data"), None).map(drop)),
            expected
        );
        assert_eq!(
            closed(signer.sign_async(array(b"data"), None).map(drop)),
            expected
        );
        // A task started before close() still signs; it drops the last reference to the key.
        assert_eq!(Arc::strong_count(&task.signer), 1);
        assert!(task.compute().expect("compute").is_ok());
    }
}

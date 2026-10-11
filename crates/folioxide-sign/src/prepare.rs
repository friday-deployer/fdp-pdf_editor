//! The first phase of signing: [`prepare`], [`PrepareRequest`], [`SignatureOptions`] and
//! [`PreparedSignature`], which carries the prepared file and the bytes to sign between the two
//! phases (M3 brief §3.2, §4.2 and §4.4; ARCHITECTURE §A.6.5).
//!
//! [`prepare`] does everything but the signature itself:
//!
//! 1. It checks the document ([`check_signable`](crate::placeholder::check_signable)) and places
//!    the field ([`field`]), before any cryptography.
//! 2. It sizes `/Contents` exactly: the signed attributes for a zero digest (their length does not
//!    depend on the digest value), then [`cms_len_upper_bound`](crate::cms::cms_len_upper_bound),
//!    then the reserve of [`contents_reserve`](crate::placeholder::contents_reserve) (brief §4.2,
//!    D-7). An explicit reserve that is too small fails here, with
//!    [`Error::PlaceholderTooSmall`], before anything is signed.
//! 3. It writes the incremental update with the placeholders and patches the byte range
//!    ([`placeholder`]).
//! 4. It digests the signed byte ranges and builds the signed attributes with that digest
//!    ([`build_signed_attrs`](crate::cms::build_signed_attrs)).
//!
//! The [`PreparedSignature`] then gives the bytes an external signer signs:
//! [`to_be_signed`](PreparedSignature::to_be_signed) for "sign message" APIs (the DER signed
//! attributes with the universal `SET` tag `0x31`, RFC 5652 §5.4),
//! [`to_be_signed_digest`](PreparedSignature::to_be_signed_digest) for "sign digest" APIs, and
//! [`to_be_signed_digest_info`](PreparedSignature::to_be_signed_digest_info) for raw RSA
//! (PKCS#11 `CKM_RSA_PKCS`). It can be stored between the phases with
//! [`to_bytes`](PreparedSignature::to_bytes) / [`from_bytes`](PreparedSignature::from_bytes)
//! (or serde, behind the `serde` feature); loading re-checks every invariant (brief §4.4).
//!
//! The second phase is [`PreparedSignature::finish`] with the signature value, or
//! [`PreparedSignature::embed_cms`] with a complete CMS ([`finish`](crate::finish)).

use std::fmt;
use std::ops::Range;
use std::sync::Arc;

use folioxide_model::{Document, PdfDate};
use folioxide_syntax::{
    Lexer, ObjectId, ObjectLocation, OpenOptions, SharedBytes, Store, TokenKind, XrefEntry,
};

use crate::algorithms::{
    DigestAlgorithm, KeyKind, SignatureAlgorithm, check_signing_combination, default_digest,
};
use crate::cms::{self, MAX_CERTIFICATES, SignedAttrsInput};
use crate::error::{Error, Result};
use crate::field::{self, FieldSpec, SubFilter};
use crate::placeholder::{self, MAX_CONTENTS_RESERVE};
use crate::x509info;

/// The options of a signature: which field, the claimed signing time, the digest, the
/// SubFilter, the optional text entries of the signature dictionary and the `/Contents`
/// reserve (M3 brief §3.2).
///
/// With the `serde` feature the fields are `camelCase` (`signingTime` as a PDF date string,
/// `subFilter`, `contactInfo`, `contentsReserve`); all but `signingTime` are optional.
///
/// ```
/// use folioxide_model::PdfDate;
/// use folioxide_sign::algorithms::DigestAlgorithm;
/// use folioxide_sign::prepare::SignatureOptions;
///
/// let time = PdfDate::parse(b"D:20261010120000Z").unwrap();
/// let options = SignatureOptions::new(time)
///     .with_reason(Some("Approved".into()))
///     .with_digest(Some(DigestAlgorithm::Sha384));
/// assert_eq!(options.reason.as_deref(), Some("Approved"));
/// assert_eq!(options.contents_reserve, None);
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SignatureOptions {
    /// Which field to sign or create. Default: a new field `Signature{n}` on the first page.
    #[cfg_attr(feature = "serde", serde(default))]
    pub field: FieldSpec,
    /// The claimed signing time, written as `/M` (§12.8.1 Table 258). PAdES B-B requires it and
    /// has no CMS signing-time attribute (brief §4.6). The core has no clock: the caller passes
    /// it.
    pub signing_time: PdfDate,
    /// The digest algorithm; `None`: [`default_digest`] of the key (SHA-256 for RSA and P-256,
    /// SHA-384 for P-384). SHA-1 is refused.
    #[cfg_attr(feature = "serde", serde(default))]
    pub digest: Option<DigestAlgorithm>,
    /// The `/SubFilter`. Default `ETSI.CAdES.detached`.
    #[cfg_attr(feature = "serde", serde(default))]
    pub sub_filter: SubFilter,
    /// `/Name`: the name of the signer (§12.8.1 Table 258), a text string.
    #[cfg_attr(feature = "serde", serde(default))]
    pub name: Option<String>,
    /// `/Reason`: the reason for signing, a text string.
    #[cfg_attr(feature = "serde", serde(default))]
    pub reason: Option<String>,
    /// `/Location`: where the document was signed, a text string.
    #[cfg_attr(feature = "serde", serde(default))]
    pub location: Option<String>,
    /// `/ContactInfo`: how to reach the signer, a text string.
    #[cfg_attr(feature = "serde", serde(default))]
    pub contact_info: Option<String>,
    /// The bytes of DER the `/Contents` placeholder holds; `None`: the exact CMS size plus a
    /// margin, at least 8192 ([`default_contents_reserve`](crate::placeholder::default_contents_reserve)).
    /// At most [`MAX_CONTENTS_RESERVE`].
    #[cfg_attr(feature = "serde", serde(default))]
    pub contents_reserve: Option<usize>,
}

impl SignatureOptions {
    /// The default options with the claimed signing time `signing_time`.
    pub fn new(signing_time: PdfDate) -> Self {
        SignatureOptions {
            field: FieldSpec::default(),
            signing_time,
            digest: None,
            sub_filter: SubFilter::default(),
            name: None,
            reason: None,
            location: None,
            contact_info: None,
            contents_reserve: None,
        }
    }

    /// Sets [`SignatureOptions::field`].
    #[must_use]
    pub fn with_field(mut self, field: FieldSpec) -> Self {
        self.field = field;
        self
    }

    /// Sets [`SignatureOptions::signing_time`].
    #[must_use]
    pub fn with_signing_time(mut self, signing_time: PdfDate) -> Self {
        self.signing_time = signing_time;
        self
    }

    /// Sets [`SignatureOptions::digest`].
    #[must_use]
    pub fn with_digest(mut self, digest: Option<DigestAlgorithm>) -> Self {
        self.digest = digest;
        self
    }

    /// Sets [`SignatureOptions::sub_filter`].
    #[must_use]
    pub fn with_sub_filter(mut self, sub_filter: SubFilter) -> Self {
        self.sub_filter = sub_filter;
        self
    }

    /// Sets [`SignatureOptions::name`].
    #[must_use]
    pub fn with_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    /// Sets [`SignatureOptions::reason`].
    #[must_use]
    pub fn with_reason(mut self, reason: Option<String>) -> Self {
        self.reason = reason;
        self
    }

    /// Sets [`SignatureOptions::location`].
    #[must_use]
    pub fn with_location(mut self, location: Option<String>) -> Self {
        self.location = location;
        self
    }

    /// Sets [`SignatureOptions::contact_info`].
    #[must_use]
    pub fn with_contact_info(mut self, contact_info: Option<String>) -> Self {
        self.contact_info = contact_info;
        self
    }

    /// Sets [`SignatureOptions::contents_reserve`].
    #[must_use]
    pub fn with_contents_reserve(mut self, contents_reserve: Option<usize>) -> Self {
        self.contents_reserve = contents_reserve;
        self
    }
}

/// What [`prepare`] needs: the signer's certificate chain and algorithm, and the options.
///
/// With the `serde` feature the fields are `chainDer`, `algorithm` and `options`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct PrepareRequest {
    /// The DER certificates: the signer's first, then intermediates (the root is optional).
    /// They are embedded in the CMS byte for byte. At most
    /// [`MAX_CERTIFICATES`].
    pub chain_der: Vec<Vec<u8>>,
    /// The signature algorithm; it must match the signer certificate's key.
    pub algorithm: SignatureAlgorithm,
    /// The signature options.
    pub options: SignatureOptions,
}

impl PrepareRequest {
    /// A request with the default [`SignatureOptions`] for `signing_time`.
    pub fn new(
        chain_der: Vec<Vec<u8>>,
        algorithm: SignatureAlgorithm,
        signing_time: PdfDate,
    ) -> Self {
        PrepareRequest {
            chain_der,
            algorithm,
            options: SignatureOptions::new(signing_time),
        }
    }

    /// Sets [`PrepareRequest::options`].
    #[must_use]
    pub fn with_options(mut self, options: SignatureOptions) -> Self {
        self.options = options;
        self
    }
}

/// Builds the incremental update that adds a signature to `doc` (the document's pending edits,
/// the field, widget, page and AcroForm edits, and the signature dictionary), patches its
/// `/ByteRange`, digests the signed ranges and builds the signed attributes. `doc` is not
/// changed.
///
/// See the [module documentation](self) for the steps, and [`PreparedSignature`] for what to
/// do next.
///
/// The two-phase flow for a key that stays elsewhere (an HSM, a KMS, WebCrypto): prepare with
/// the certificate chain alone, have the key sign
/// [`to_be_signed`](PreparedSignature::to_be_signed), then
/// [`finish`](PreparedSignature::finish). Here a [`LocalSigner`](crate::signer::LocalSigner)
/// from the test PKI plays the external key:
///
/// ```
/// use folioxide_model::{Document, PdfDate};
/// use folioxide_sign::prepare::{PrepareRequest, prepare};
/// use folioxide_sign::signer::{LocalSigner, Signer};
/// use folioxide_sign::verify_pdf::{VerifyOptions, verify_bytes};
/// use folioxide_syntax::OpenOptions;
///
/// # let pki = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pki");
/// # let p12 = std::fs::read(pki.join("signer-p256-modern.p12"))?;
/// let key = LocalSigner::from_pkcs12(&p12, "folioxide")?;
/// let source = folioxide_testkit::fixtures::syntax::minimal();
/// let doc = Document::open(source.clone(), &OpenOptions::default())?;
/// let time = PdfDate::parse(b"D:20261010120000Z").expect("a PDF date");
///
/// // Phase 1: the incremental update with its placeholders, and the bytes to sign.
/// let chain = key.certificate_chain().to_vec();
/// let prepared = prepare(&doc, &PrepareRequest::new(chain, key.algorithm(), time))?;
/// assert!(prepared.contents_capacity() >= 8192);
///
/// // Phase 2: the key signs to_be_signed() (the DER signed attributes); finish builds the
/// // CMS, checks it and writes it into /Contents.
/// let value = key.sign(prepared.digest_algorithm(), prepared.to_be_signed())?;
/// let signed = prepared.finish(&value)?;
/// assert!(signed.starts_with(&source));
/// assert!(verify_bytes(signed, &VerifyOptions::default())?[0].is_valid());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
/// - [`Error::InvalidArgument`]: an empty certificate chain or one with more than
///   [`MAX_CERTIFICATES`] certificates; an algorithm that does not
///   match the signer certificate's key; a digest or key the combination rules refuse
///   ([`check_signing_combination`]); a reserve of 0 or above [`MAX_CONTENTS_RESERVE`]; a file
///   too large for the ten-digit byte range.
/// - [`Error::PlaceholderTooSmall`]: an explicit [`SignatureOptions::contents_reserve`] below the
///   size the CMS needs (`needed` is that size: retry with it).
/// - The refusals of [`check_signable`](crate::placeholder::check_signable)
///   ([`Error::Unsupported`], [`Error::DocMdpForbids`], [`Error::InvalidArgument`]) and the field
///   placement errors ([`Error::PageOutOfRange`], [`Error::NotFound`], ...; see
///   [`FieldSpec`]).
/// - [`Error::Certificate`] or [`Error::Unsupported`] for a signer certificate that does not
///   parse or has an unsupported key.
pub fn prepare(doc: &Document, req: &PrepareRequest) -> Result<PreparedSignature> {
    prepare_with(doc, req, &RealCms)
}

/// [`prepare`] with the CMS operations of `cms`.
pub(crate) fn prepare_with(
    doc: &Document,
    req: &PrepareRequest,
    cms: &dyn CmsBackend,
) -> Result<PreparedSignature> {
    let options = &req.options;

    // Arguments that need no work.
    let signer_cert = check_chain(&req.chain_der)?;
    if let Some(reserve) = options.contents_reserve
        && (reserve == 0 || reserve > MAX_CONTENTS_RESERVE)
    {
        return Err(Error::InvalidArgument(format!(
            "the /Contents reserve must be between 1 and {MAX_CONTENTS_RESERVE} bytes, not \
             {reserve}"
        )));
    }

    // The document and the field, before any cryptography (brief §4.5 "Preconditions").
    placeholder::check_signable(doc)?;
    let plan = field::plan(doc, &options.field)?;

    // Key, algorithm and digest (brief §3.1).
    let key_kind = cms.key_kind(signer_cert)?;
    if req.algorithm != key_kind.algorithm() {
        return Err(Error::InvalidArgument(format!(
            "the signer certificate has a {} key, but the algorithm is {}",
            key_kind.algorithm(),
            req.algorithm
        )));
    }
    let digest = options.digest.unwrap_or_else(|| default_digest(key_kind));
    check_signing_combination(key_kind, digest)?;

    // Exact size first (brief §4.2 step 1): the signed attributes' length does not depend on the
    // digest value.
    let zero = vec![0u8; digest.output_len()];
    let sizing_attrs = cms.build_signed_attrs(&SignedAttrsInput {
        digest,
        document_digest: &zero,
        signer_cert_der: signer_cert,
    })?;
    let needed = cms.cms_len_upper_bound(
        &sizing_attrs,
        &req.chain_der,
        req.algorithm,
        key_kind,
        digest,
    )?;
    let reserve = placeholder::contents_reserve(options.contents_reserve, needed)?;

    // The update, the byte range and the digest (steps 2–5).
    let written = placeholder::write_with_plan(doc, plan, options, reserve)?;
    let document_digest = written.digest(digest);

    // The bytes to sign (step 6).
    let signed_attrs = cms.build_signed_attrs(&SignedAttrsInput {
        digest,
        document_digest: &document_digest,
        signer_cert_der: signer_cert,
    })?;
    if signed_attrs.len() != sizing_attrs.len() {
        let needed = cms.cms_len_upper_bound(
            &signed_attrs,
            &req.chain_der,
            req.algorithm,
            key_kind,
            digest,
        )?;
        if needed > reserve {
            return Err(Error::PlaceholderTooSmall {
                needed,
                reserved: reserve,
            });
        }
    }
    if message_digest_of(&signed_attrs).as_deref() != Some(document_digest.as_slice()) {
        return Err(Error::Crypto(
            "the signed attributes do not carry the document digest".to_owned(),
        ));
    }

    Ok(PreparedSignature {
        pdf: written.pdf,
        contents_range: written.contents_range,
        byte_range_token: written.byte_range_token,
        byte_range: written.byte_range,
        document_digest,
        signed_attrs_der: signed_attrs,
        digest,
        algorithm: req.algorithm,
        key_kind,
        chain_der: req.chain_der.clone(),
        sub_filter: options.sub_filter,
        warnings: written.warnings,
    })
}

/// The signer certificate of a non-empty chain of at most [`MAX_CERTIFICATES`].
fn check_chain(chain: &[Vec<u8>]) -> Result<&[u8]> {
    if chain.len() > MAX_CERTIFICATES {
        return Err(Error::InvalidArgument(format!(
            "the certificate chain has {} certificates; at most {MAX_CERTIFICATES} are allowed",
            chain.len()
        )));
    }
    chain
        .first()
        .map(Vec::as_slice)
        .ok_or_else(|| Error::InvalidArgument("the certificate chain is empty".to_owned()))
}

// =================================================================================================
// The CMS operations prepare needs
// =================================================================================================

/// The certificate and CMS operations of [`prepare`] and the [`PreparedSignature`] checks
/// (brief §3.1): [`RealCms`] in the library; unit tests substitute a double, so that the PDF
/// layout can be tested on its own.
pub(crate) trait CmsBackend {
    /// [`x509info::certificate_key_kind`].
    fn key_kind(&self, cert_der: &[u8]) -> Result<KeyKind>;
    /// [`cms::build_signed_attrs`].
    fn build_signed_attrs(&self, input: &SignedAttrsInput<'_>) -> Result<Vec<u8>>;
    /// [`cms::cms_len_upper_bound`].
    fn cms_len_upper_bound(
        &self,
        signed_attrs: &[u8],
        chain_der: &[Vec<u8>],
        alg: SignatureAlgorithm,
        kind: KeyKind,
        digest: DigestAlgorithm,
    ) -> Result<usize>;
}

/// The library's CMS operations: [`x509info`] and [`cms`].
pub(crate) struct RealCms;

impl CmsBackend for RealCms {
    fn key_kind(&self, cert_der: &[u8]) -> Result<KeyKind> {
        x509info::certificate_key_kind(cert_der)
    }

    fn build_signed_attrs(&self, input: &SignedAttrsInput<'_>) -> Result<Vec<u8>> {
        cms::build_signed_attrs(input)
    }

    fn cms_len_upper_bound(
        &self,
        signed_attrs: &[u8],
        chain_der: &[Vec<u8>],
        alg: SignatureAlgorithm,
        kind: KeyKind,
        digest: DigestAlgorithm,
    ) -> Result<usize> {
        cms::cms_len_upper_bound(signed_attrs, chain_der, alg, kind, digest)
    }
}

// =================================================================================================
// PreparedSignature
// =================================================================================================

/// The version of the [`PreparedSignature::to_bytes`] format (and of the serde form).
pub const PREPARED_SIGNATURE_VERSION: u32 = 1;

/// The first four bytes of [`PreparedSignature::to_bytes`].
pub const PREPARED_SIGNATURE_MAGIC: [u8; 4] = *b"FXPS";

/// The most warnings a stored [`PreparedSignature`] may carry.
const MAX_WARNINGS: usize = 64;

/// A signature prepared by [`prepare`]: the complete output file with the byte range patched and
/// `/Contents` still all zeros, and the bytes an external signer signs (M3 brief §3.2, §4.4).
///
/// Sign [`to_be_signed`](Self::to_be_signed) (or its digest) with the key of the first
/// certificate of the chain, then finish the file with the signature value
/// ([`finish`](Self::finish)), or embed a whole CMS made elsewhere
/// ([`embed_cms`](Self::embed_cms)).
///
/// It can be stored between the two phases with [`to_bytes`](Self::to_bytes) and
/// [`from_bytes`](Self::from_bytes), or with serde (feature `serde`); both re-check every
/// invariant when loading: the `/Contents` token holds only zeros, the byte range covers
/// exactly the file without it, the digest of the ranges is the recorded one, the signed
/// attributes are exactly those [`prepare`] builds for that digest and the signer certificate
/// (so neither an attribute nor the certificate can be changed), the signer certificate's key is
/// the recorded kind, and the file's signature dictionary carries the recorded `/SubFilter`.
///
/// `Debug` prints the layout and the algorithms, not the file.
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedSignature {
    /// The complete output, `/ByteRange` patched, `/Contents` all `0`.
    pub(crate) pdf: Vec<u8>,
    /// `[a, b)`: the `/Contents` hexadecimal string token, `<` to after `>`.
    pub(crate) contents_range: (u64, u64),
    /// The `/ByteRange` array token, `[` to after `]`.
    pub(crate) byte_range_token: (u64, u64),
    /// `[0, a, b, pdf.len() - b]`.
    pub(crate) byte_range: [u64; 4],
    /// `H(pdf[0..a] ‖ pdf[b..])`.
    pub(crate) document_digest: Vec<u8>,
    /// The DER signed attributes, universal `SET` tag `0x31`: the bytes to sign.
    pub(crate) signed_attrs_der: Vec<u8>,
    /// The digest algorithm.
    pub(crate) digest: DigestAlgorithm,
    /// The signature algorithm.
    pub(crate) algorithm: SignatureAlgorithm,
    /// The signer key's kind.
    pub(crate) key_kind: KeyKind,
    /// The DER certificates, the signer's first.
    pub(crate) chain_der: Vec<Vec<u8>>,
    /// The `/SubFilter` written.
    pub(crate) sub_filter: SubFilter,
    /// Observations from preparing, for example `/NeedAppearances true` left unchanged.
    pub(crate) warnings: Vec<String>,
}

impl PreparedSignature {
    /// The bytes to sign: the DER signed attributes with the universal `SET` tag `0x31` (RFC 5652
    /// §5.4), for "sign message" APIs that hash themselves.
    pub fn to_be_signed(&self) -> &[u8] {
        &self.signed_attrs_der
    }

    /// `H(to_be_signed)` with [`digest_algorithm`](Self::digest_algorithm), for "sign digest"
    /// HSM and KMS APIs.
    pub fn to_be_signed_digest(&self) -> Vec<u8> {
        self.digest.digest(&[&self.signed_attrs_der])
    }

    /// The DER `DigestInfo { algorithm, H(to_be_signed) }` (RFC 8017 §9.2), for raw RSA signing
    /// (PKCS#11 `CKM_RSA_PKCS`).
    pub fn to_be_signed_digest_info(&self) -> Vec<u8> {
        self.digest.digest_info(&self.to_be_signed_digest())
    }

    /// The digest algorithm of the signature.
    pub fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest
    }

    /// The signature algorithm.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// The kind of the signer's key.
    pub fn key_kind(&self) -> KeyKind {
        self.key_kind
    }

    /// `R`: the bytes of DER that fit in `/Contents`.
    pub fn contents_capacity(&self) -> usize {
        let (a, b) = self.contents_range;
        usize::try_from(b.saturating_sub(a).saturating_sub(2) / 2).unwrap_or(0)
    }

    /// The `/SubFilter` of the signature dictionary.
    pub fn sub_filter(&self) -> SubFilter {
        self.sub_filter
    }

    /// The DER certificate chain, the signer's first.
    pub fn chain_der(&self) -> &[Vec<u8>] {
        &self.chain_der
    }

    /// The prepared file: the source, then the update; `/ByteRange` patched and `/Contents` all
    /// zeros (not yet a valid signature).
    pub fn pdf(&self) -> &[u8] {
        &self.pdf
    }

    /// `[0, a, b, c]`: the signed byte ranges `[0, a)` and `[b, b + c)`, `b + c` the file length.
    pub fn byte_range(&self) -> [u64; 4] {
        self.byte_range
    }

    /// `(a, b)`: where the `/Contents` hexadecimal string is, from its `<` to after its `>`.
    pub fn contents_range(&self) -> (u64, u64) {
        self.contents_range
    }

    /// The digest of the signed byte ranges: the message-digest attribute's value.
    pub fn document_digest(&self) -> &[u8] {
        &self.document_digest
    }

    /// Observations from preparing, for example an AcroForm `/NeedAppearances true` left
    /// unchanged.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// The versioned binary form (brief §3.2, D-17): the magic `FXPS`, the format version
    /// ([`PREPARED_SIGNATURE_VERSION`]) and every field, length-prefixed, big-endian:
    ///
    /// ```text
    /// "FXPS" u32:version
    /// u8:sub_filter u8:algorithm u8:digest u8:key_kind u32:rsa_bits
    /// u64:a u64:b  u64:byte_range_token_start u64:byte_range_token_end  4 × u64:byte_range
    /// bytes32:document_digest  bytes32:signed_attrs_der
    /// u32:count × bytes32:certificate  u32:count × bytes32:warning (UTF-8)
    /// bytes64:pdf
    /// ```
    ///
    /// `bytes32` is a `u32` length and the bytes, `bytes64` a `u64` length and the bytes. The
    /// codes are `sub_filter` 0 `ETSI.CAdES.detached`, 1 `adbe.pkcs7.detached`; `algorithm` 0
    /// RSA PKCS#1 v1.5, 1 ECDSA; `digest` 0 SHA-256, 1 SHA-384, 2 SHA-512; `key_kind` 0 RSA,
    /// 1 P-256, 2 P-384.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.pdf.len().saturating_add(
            self.signed_attrs_der.len() + self.chain_der.iter().map(Vec::len).sum::<usize>() + 256,
        ));
        out.extend_from_slice(&PREPARED_SIGNATURE_MAGIC);
        out.extend_from_slice(&PREPARED_SIGNATURE_VERSION.to_be_bytes());
        out.push(sub_filter_code(self.sub_filter));
        out.push(algorithm_code(self.algorithm));
        out.push(digest_code(self.digest));
        let (kind, bits) = key_kind_code(self.key_kind);
        out.push(kind);
        out.extend_from_slice(&bits.to_be_bytes());
        for value in [
            self.contents_range.0,
            self.contents_range.1,
            self.byte_range_token.0,
            self.byte_range_token.1,
        ]
        .into_iter()
        .chain(self.byte_range)
        {
            out.extend_from_slice(&value.to_be_bytes());
        }
        push_bytes32(&mut out, &self.document_digest);
        push_bytes32(&mut out, &self.signed_attrs_der);
        push_count(&mut out, self.chain_der.len());
        for cert in &self.chain_der {
            push_bytes32(&mut out, cert);
        }
        push_count(&mut out, self.warnings.len());
        for warning in &self.warnings {
            push_bytes32(&mut out, warning.as_bytes());
        }
        out.extend_from_slice(&(self.pdf.len() as u64).to_be_bytes());
        out.extend_from_slice(&self.pdf);
        out
    }

    /// Reads the form [`to_bytes`](Self::to_bytes) writes and re-checks every invariant
    /// (brief §4.4).
    ///
    /// For a signature finished later, by another process or after a round trip to a signing
    /// service:
    ///
    /// ```
    /// use folioxide_model::{Document, PdfDate};
    /// use folioxide_sign::prepare::{PrepareRequest, PreparedSignature, prepare};
    /// use folioxide_sign::signer::{LocalSigner, Signer};
    /// use folioxide_syntax::OpenOptions;
    ///
    /// # let pki = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pki");
    /// # let p12 = std::fs::read(pki.join("signer-p256-modern.p12"))?;
    /// # let key = LocalSigner::from_pkcs12(&p12, "folioxide")?;
    /// # let doc = Document::open(
    /// #     folioxide_testkit::fixtures::syntax::minimal(),
    /// #     &OpenOptions::default(),
    /// # )?;
    /// # let time = PdfDate::parse(b"D:20261010120000Z").expect("a PDF date");
    /// let request = PrepareRequest::new(key.certificate_chain().to_vec(), key.algorithm(), time);
    /// let stored: Vec<u8> = prepare(&doc, &request)?.to_bytes();
    ///
    /// // Later: load it (every invariant is checked again), sign and finish.
    /// let prepared = PreparedSignature::from_bytes(&stored)?;
    /// let value = key.sign(prepared.digest_algorithm(), prepared.to_be_signed())?;
    /// let signed = prepared.finish(&value)?;
    /// # assert!(!signed.is_empty());
    ///
    /// // A changed byte (here the last byte of the prepared file) is refused.
    /// let mut tampered = stored.clone();
    /// let last = tampered.len() - 1;
    /// tampered[last] ^= 1;
    /// assert!(PreparedSignature::from_bytes(&tampered).is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`]: not this format (magic, truncated, trailing bytes, unknown
    ///   codes), another version, or an invariant that does not hold (the file, the byte range
    ///   or the signed attributes were changed).
    /// - [`Error::Certificate`] or [`Error::Unsupported`]: the signer certificate does not parse
    ///   or has an unsupported key.
    pub fn from_bytes(bytes: &[u8]) -> Result<PreparedSignature> {
        Self::from_bytes_with(bytes, &RealCms)
    }

    /// [`from_bytes`](Self::from_bytes) with the CMS operations of `cms`.
    pub(crate) fn from_bytes_with(bytes: &[u8], cms: &dyn CmsBackend) -> Result<PreparedSignature> {
        let mut r = Reader {
            data: bytes,
            pos: 0,
        };
        if r.take(4)? != PREPARED_SIGNATURE_MAGIC {
            return Err(invalid("not a prepared signature (no FXPS magic)"));
        }
        let version = r.u32()?;
        if version != PREPARED_SIGNATURE_VERSION {
            return Err(invalid(&format!(
                "format version {version} is not supported (this library reads version \
                 {PREPARED_SIGNATURE_VERSION})"
            )));
        }
        let sub_filter = sub_filter_from_code(r.u8()?)?;
        let algorithm = algorithm_from_code(r.u8()?)?;
        let digest = digest_from_code(r.u8()?)?;
        let kind = r.u8()?;
        let bits = r.u32()?;
        let key_kind = key_kind_from_code(kind, bits)?;
        let contents_range = (r.u64()?, r.u64()?);
        let byte_range_token = (r.u64()?, r.u64()?);
        let byte_range = [r.u64()?, r.u64()?, r.u64()?, r.u64()?];
        let document_digest = r.bytes32()?.to_vec();
        let signed_attrs_der = r.bytes32()?.to_vec();
        let certificates = r.count(MAX_CERTIFICATES, "certificates")?;
        let mut chain_der = Vec::with_capacity(certificates);
        for _ in 0..certificates {
            chain_der.push(r.bytes32()?.to_vec());
        }
        let warning_count = r.count(MAX_WARNINGS, "warnings")?;
        let mut warnings = Vec::with_capacity(warning_count);
        for _ in 0..warning_count {
            let text =
                std::str::from_utf8(r.bytes32()?).map_err(|_| invalid("a warning is not UTF-8"))?;
            warnings.push(text.to_owned());
        }
        let pdf = r.bytes64()?.to_vec();
        if r.pos != bytes.len() {
            return Err(invalid("trailing bytes after the prepared signature"));
        }
        let prepared = PreparedSignature {
            pdf,
            contents_range,
            byte_range_token,
            byte_range,
            document_digest,
            signed_attrs_der,
            digest,
            algorithm,
            key_kind,
            chain_der,
            sub_filter,
            warnings,
        };
        prepared.validated(cms)
    }

    /// Checks every invariant of brief §4.4 and returns the prepared signature: the fields
    /// ([`check_fields`](Self::check_fields)), then the signature dictionary in the file
    /// ([`check_signature_dictionary`]): the object of the newest revision that holds both
    /// placeholders is a `/Type /Sig` dictionary whose `/SubFilter` is the recorded one, so a
    /// stored state whose SubFilter code was changed can never label a CMS with a SubFilter the
    /// file does not carry (R-16).
    ///
    /// The file is moved into a shared buffer for the check and back, never copied.
    ///
    /// # Errors
    /// As [`check_fields`](Self::check_fields); [`Error::InvalidArgument`] when the file's
    /// signature dictionary does not match.
    pub(crate) fn validated(mut self, cms: &dyn CmsBackend) -> Result<PreparedSignature> {
        self.validate(cms)?;
        Ok(self)
    }

    /// [`validated`](Self::validated) in place: the file is back in `self` whatever the
    /// outcome, so a caller can return the prepared signature with the error
    /// ([`try_finish`](Self::try_finish)).
    ///
    /// # Errors
    /// As [`validated`](Self::validated).
    pub(crate) fn validate(&mut self, cms: &dyn CmsBackend) -> Result<()> {
        self.check_fields(cms)?;
        let pdf = std::mem::take(&mut self.pdf);
        let (pdf, checked) = check_signature_dictionary(
            pdf,
            self.byte_range_token,
            self.contents_range,
            self.sub_filter,
        );
        self.pdf = pdf;
        checked
    }

    /// Checks the invariants of brief §4.4 that need no parse of the file: the placeholders,
    /// the byte range, the digest, the signed attributes (exactly those
    /// [`build_signed_attrs`](crate::cms::build_signed_attrs) makes for the digest algorithm,
    /// the document digest and the signer certificate, so neither an attribute nor the
    /// certificate its ESS certHash names can be changed) and the signer.
    ///
    /// # Errors
    /// [`Error::InvalidArgument`] for a broken invariant; the errors of
    /// [`CmsBackend::key_kind`] and [`CmsBackend::build_signed_attrs`] for the signer
    /// certificate.
    pub(crate) fn check_fields(&self, cms: &dyn CmsBackend) -> Result<()> {
        let len = self.pdf.len() as u64;
        let (a, b) = self.contents_range;
        // The /Contents token: `<`, an even, non-zero number of `0` digits, `>`.
        if !(a < b && b <= len) {
            return Err(invalid("the /Contents range is outside the file"));
        }
        let token = usize::try_from(a)
            .ok()
            .zip(usize::try_from(b).ok())
            .and_then(|(a, b)| self.pdf.get(a..b))
            .ok_or_else(|| invalid("the /Contents range is outside the file"))?;
        let digits = token
            .strip_prefix(b"<")
            .and_then(|t| t.strip_suffix(b">"))
            .ok_or_else(|| invalid("the /Contents range is not a hexadecimal string token"))?;
        if digits.is_empty() || digits.len() % 2 != 0 {
            return Err(invalid("the /Contents placeholder has no room for a CMS"));
        }
        if digits.iter().any(|&d| d != b'0') {
            return Err(invalid(
                "the /Contents placeholder is not all zeros: the signature was finished or \
                 the file changed",
            ));
        }

        // The byte range: the whole file but the /Contents token, and its text says so.
        if self.byte_range != [0, a, b, len - b] {
            return Err(invalid(
                "the /ByteRange does not cover exactly the file without /Contents",
            ));
        }
        let written = parse_byte_range_token(&self.pdf, self.byte_range_token)
            .ok_or_else(|| invalid("the /ByteRange text is not an array of four integers"))?;
        if written != self.byte_range || self.byte_range_token.1 > a {
            return Err(invalid(
                "the /ByteRange written in the file does not match the prepared byte range",
            ));
        }

        // The digest of the ranges, and the signed attributes that carry it.
        if self.document_digest.len() != self.digest.output_len()
            || placeholder::signed_digest(&self.pdf, self.contents_range, self.digest)
                != self.document_digest
        {
            return Err(invalid(
                "the digest of the signed byte ranges does not match: the file changed",
            ));
        }
        if self.signed_attrs_der.first() != Some(&0x31) {
            return Err(invalid(
                "the signed attributes do not start with the SET tag 0x31",
            ));
        }
        if message_digest_of(&self.signed_attrs_der).as_deref()
            != Some(self.document_digest.as_slice())
        {
            return Err(invalid(
                "the signed attributes do not carry the document digest as message-digest",
            ));
        }

        // The signer.
        let signer_cert = check_chain(&self.chain_der)?;
        if cms.key_kind(signer_cert)? != self.key_kind {
            return Err(invalid(
                "the signer certificate's key is not the recorded key kind",
            ));
        }
        if self.algorithm != self.key_kind.algorithm() {
            return Err(invalid("the algorithm does not match the key kind"));
        }
        check_signing_combination(self.key_kind, self.digest)
            .map_err(|err| invalid(&err.to_string()))?;
        if self.warnings.len() > MAX_WARNINGS {
            return Err(invalid("too many warnings"));
        }

        // The signed attributes are deterministic: content-type, this message-digest and the
        // signing-certificate-v2 of this certificate, nothing else (brief §4.3). A stored state
        // with an extra attribute (signing-time, a policy), another content type or the certHash
        // of another certificate would have an external signer sign attributes Folioxide never
        // builds.
        let rebuilt = cms.build_signed_attrs(&SignedAttrsInput {
            digest: self.digest,
            document_digest: &self.document_digest,
            signer_cert_der: signer_cert,
        })?;
        if rebuilt != self.signed_attrs_der {
            return Err(invalid(
                "the signed attributes are not the ones prepare builds for this digest and \
                 signer certificate: an attribute or the certificate was changed",
            ));
        }
        Ok(())
    }
}

/// Checks the signature dictionary of a prepared file (brief §4.4): `pdf` opens without repair,
/// and an uncompressed object of its newest revision is a `/Type /Sig` dictionary whose
/// `/ByteRange` and `/Contents` value tokens are exactly `byte_range_token` and
/// `contents_range`, and whose `/SubFilter` is `sub_filter` (each key once). Returns `pdf`
/// (moved in and out of the shared buffer the store reads, not copied) and the verdict.
fn check_signature_dictionary(
    pdf: Vec<u8>,
    byte_range_token: (u64, u64),
    contents_range: (u64, u64),
    sub_filter: SubFilter,
) -> (Vec<u8>, Result<()>) {
    let shared = Arc::new(pdf);
    let source: SharedBytes = shared.clone();
    let verdict = signature_dictionary_matches(
        source,
        shared.as_slice(),
        byte_range_token,
        contents_range,
        sub_filter,
    );
    // The store and its source are gone: the buffer is unique again.
    (Arc::unwrap_or_clone(shared), verdict)
}

/// The check of [`check_signature_dictionary`] over the store's `source` (whose bytes are
/// `bytes`).
fn signature_dictionary_matches(
    source: SharedBytes,
    bytes: &[u8],
    (br_start, br_end): (u64, u64),
    (a, b): (u64, u64),
    sub_filter: SubFilter,
) -> Result<()> {
    let store = Store::open(source, &OpenOptions::default())
        .map_err(|err| invalid(&format!("the prepared file does not open: {err}")))?;
    if store.structure_repaired() || store.header_offset() != 0 {
        return Err(invalid("the prepared file's structure is not intact"));
    }
    let newest = store
        .revisions()
        .len()
        .checked_sub(1)
        .ok_or_else(|| invalid("the prepared file has no revision"))?;
    let listed = store
        .revision_entries(newest)
        .map_err(|_| invalid("the prepared file's newest section cannot be read"))?;
    let holder = listed.iter().find_map(|&(num, entry)| {
        let XrefEntry::InFile { r#gen, .. } = entry else {
            return None;
        };
        let id = ObjectId::new(num, r#gen);
        match store.object_location(id)? {
            ObjectLocation::InFile { start, end } if start <= br_start && b <= end => {
                Some((id, start, end))
            }
            _ => None,
        }
    });
    let (id, start, end) = holder.ok_or_else(|| {
        invalid("no object of the newest revision holds the /ByteRange and /Contents placeholders")
    })?;
    let spans = usize::try_from(start)
        .ok()
        .zip(usize::try_from(end).ok())
        .and_then(|(start, end)| placeholder::dict_value_spans(bytes, start, end).ok())
        .ok_or_else(|| invalid("the signature dictionary cannot be read"))?;
    let only = |key: &[u8]| {
        let mut found = spans.iter().filter(|(k, _)| k.as_slice() == key);
        match (found.next(), found.next()) {
            (Some((_, range)), None) => Some((range.start as u64, range.end as u64)),
            _ => None,
        }
    };
    if only(b"ByteRange") != Some((br_start, br_end)) || only(b"Contents") != Some((a, b)) {
        return Err(invalid(
            "the /ByteRange and /Contents placeholders are not the signature dictionary's own",
        ));
    }
    let value = store
        .resolve(id)
        .map_err(|_| invalid("the signature dictionary cannot be read"))?;
    let dict = value
        .as_dict()
        .filter(|d| d.is_type(b"Sig"))
        .ok_or_else(|| invalid("the placeholders are not in a /Type /Sig dictionary"))?;
    let written = only(b"SubFilter").and(dict.get_name(b"SubFilter"));
    if written.map(|name| name.as_bytes()) != Some(sub_filter.name().as_bytes()) {
        return Err(invalid(&format!(
            "the signature dictionary's /SubFilter is not the recorded {}",
            sub_filter.name()
        )));
    }
    Ok(())
}

impl fmt::Debug for PreparedSignature {
    /// Prints the layout and the algorithms, not the file or the certificates.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedSignature")
            .field("len", &self.pdf.len())
            .field("byte_range", &self.byte_range)
            .field("contents_range", &self.contents_range)
            .field("digest", &self.digest)
            .field("algorithm", &self.algorithm)
            .field("key_kind", &self.key_kind)
            .field("sub_filter", &self.sub_filter)
            .field("certificates", &self.chain_der.len())
            .field("warnings", &self.warnings)
            .finish_non_exhaustive()
    }
}

/// An [`Error::InvalidArgument`] about a stored prepared signature.
fn invalid(message: &str) -> Error {
    Error::InvalidArgument(format!("prepared signature: {message}"))
}

/// The four integers of the `/ByteRange` array token at `(start, end)`: `[`, four integers, `]`
/// ending exactly at `end`.
fn parse_byte_range_token(pdf: &[u8], (start, end): (u64, u64)) -> Option<[u64; 4]> {
    let start = usize::try_from(start).ok()?;
    let end = usize::try_from(end).ok()?;
    let region = pdf.get(..end)?;
    if start >= end {
        return None;
    }
    let mut lexer = Lexer::new(region, start);
    let mut next = || lexer.next_token().ok().flatten();
    let open = next()?;
    if open.kind != TokenKind::ArrayStart || open.start != start {
        return None;
    }
    let mut values = [0u64; 4];
    for value in &mut values {
        match next()?.kind {
            TokenKind::Integer(v) => *value = u64::try_from(v).ok()?,
            _ => return None,
        }
    }
    let close = next()?;
    (close.kind == TokenKind::ArrayEnd && close.end == end).then_some(values)
}

// ---- the signed attributes ----------------------------------------------------------------------

/// The DER of the message-digest attribute type, 1.2.840.113549.1.9.4 (RFC 5652 §11.2).
const MESSAGE_DIGEST_OID: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04,
];

/// One DER element at `pos`: its tag, its content range and its end. Definite lengths only
/// (DER), at most four length octets, single-octet tags; `None` when malformed or out of
/// bounds.
fn der_element(data: &[u8], pos: usize) -> Option<(u8, Range<usize>, usize)> {
    let tag = *data.get(pos)?;
    if tag & 0x1F == 0x1F {
        return None;
    }
    let first = *data.get(pos.checked_add(1)?)?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2usize)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 4 {
            return None;
        }
        let octets = data.get(pos.checked_add(2)?..pos.checked_add(2)?.checked_add(count)?)?;
        let len = octets
            .iter()
            .fold(0usize, |acc, &o| (acc << 8) | usize::from(o));
        (len, 2 + count)
    };
    let start = pos.checked_add(header)?;
    let end = start.checked_add(len)?;
    (end <= data.len()).then_some((tag, start..end, end))
}

/// The value of the single message-digest attribute in DER signed attributes (`SET OF
/// Attribute`, tag `0x31`, the whole input one element); `None` when the input is not that
/// shape, or has no or several message-digest attributes or values.
pub(crate) fn message_digest_of(signed_attrs: &[u8]) -> Option<Vec<u8>> {
    let (tag, content, end) = der_element(signed_attrs, 0)?;
    if tag != 0x31 || end != signed_attrs.len() {
        return None;
    }
    let mut found = None;
    let mut pos = content.start;
    while pos < content.end {
        let (tag, attribute, next) = der_element(signed_attrs, pos)?;
        if tag != 0x30 || next > content.end {
            return None;
        }
        pos = next;
        let (oid_tag, oid, after_oid) = der_element(signed_attrs, attribute.start)?;
        let oid_element = signed_attrs.get(attribute.start..oid.end)?;
        if oid_tag != 0x06 || oid_element != MESSAGE_DIGEST_OID {
            continue;
        }
        let (set_tag, values, after_set) = der_element(signed_attrs, after_oid)?;
        let (value_tag, value, after_value) = der_element(signed_attrs, values.start)?;
        if set_tag != 0x31
            || after_set != attribute.end
            || value_tag != 0x04
            || after_value != values.end
            || found.is_some()
        {
            return None;
        }
        found = Some(signed_attrs.get(value)?.to_vec());
    }
    found
}

// ---- the binary format --------------------------------------------------------------------------

/// A bounds-checked reader over the binary form.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.data.len())
            .ok_or_else(|| invalid("truncated"))?;
        let bytes = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| invalid("truncated"))?;
        self.pos = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8> {
        self.take(1)?
            .first()
            .copied()
            .ok_or_else(|| invalid("truncated"))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| invalid("truncated"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| invalid("truncated"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// A `u32` length and that many bytes (never more than the input holds).
    fn bytes32(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.u32()?).map_err(|_| invalid("truncated"))?;
        self.take(len)
    }

    /// A `u64` length and that many bytes (never more than the input holds).
    fn bytes64(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.u64()?).map_err(|_| invalid("truncated"))?;
        self.take(len)
    }

    /// A `u32` count of at most `max`.
    fn count(&mut self, max: usize, what: &str) -> Result<usize> {
        let count = usize::try_from(self.u32()?).unwrap_or(usize::MAX);
        if count > max {
            return Err(invalid(&format!("more than {max} {what}")));
        }
        Ok(count)
    }
}

/// Appends a `u32` length and `bytes` (every stored field is far below 4 GiB: certificates and
/// attributes are bounded by the CMS limits, the file is stored with a `u64` length).
fn push_bytes32(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes.get(..len as usize).unwrap_or(bytes));
}

/// Appends a `u32` count.
fn push_count(out: &mut Vec<u8>, count: usize) {
    out.extend_from_slice(&u32::try_from(count).unwrap_or(u32::MAX).to_be_bytes());
}

fn sub_filter_code(sub_filter: SubFilter) -> u8 {
    match sub_filter {
        SubFilter::EtsiCadesDetached => 0,
        SubFilter::AdbePkcs7Detached => 1,
    }
}

fn sub_filter_from_code(code: u8) -> Result<SubFilter> {
    match code {
        0 => Ok(SubFilter::EtsiCadesDetached),
        1 => Ok(SubFilter::AdbePkcs7Detached),
        _ => Err(invalid("unknown SubFilter code")),
    }
}

fn algorithm_code(algorithm: SignatureAlgorithm) -> u8 {
    match algorithm {
        SignatureAlgorithm::RsaPkcs1v15 => 0,
        SignatureAlgorithm::Ecdsa => 1,
    }
}

fn algorithm_from_code(code: u8) -> Result<SignatureAlgorithm> {
    match code {
        0 => Ok(SignatureAlgorithm::RsaPkcs1v15),
        1 => Ok(SignatureAlgorithm::Ecdsa),
        _ => Err(invalid("unknown signature algorithm code")),
    }
}

/// SHA-1 never signs, so it has no code: [`check_signing_combination`] refused it already.
fn digest_code(digest: DigestAlgorithm) -> u8 {
    match digest {
        DigestAlgorithm::Sha256 => 0,
        DigestAlgorithm::Sha384 => 1,
        DigestAlgorithm::Sha512 => 2,
        DigestAlgorithm::Sha1 => 0xFF,
    }
}

fn digest_from_code(code: u8) -> Result<DigestAlgorithm> {
    match code {
        0 => Ok(DigestAlgorithm::Sha256),
        1 => Ok(DigestAlgorithm::Sha384),
        2 => Ok(DigestAlgorithm::Sha512),
        _ => Err(invalid("unknown digest algorithm code")),
    }
}

fn key_kind_code(kind: KeyKind) -> (u8, u32) {
    match kind {
        KeyKind::Rsa { bits } => (0, bits),
        KeyKind::EcP256 => (1, 0),
        KeyKind::EcP384 => (2, 0),
    }
}

fn key_kind_from_code(code: u8, bits: u32) -> Result<KeyKind> {
    match (code, bits) {
        (0, bits) => Ok(KeyKind::Rsa { bits }),
        (1, 0) => Ok(KeyKind::EcP256),
        (2, 0) => Ok(KeyKind::EcP384),
        _ => Err(invalid("unknown key kind code")),
    }
}

// ---- serde --------------------------------------------------------------------------------------

#[cfg(feature = "serde")]
mod serde_impl {
    //! The serde form of [`PreparedSignature`]: its fields, `camelCase`, with the format
    //! version; deserializing re-checks every invariant (`try_from`).

    use super::*;

    /// The serialized fields, borrowed.
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ReprRef<'a> {
        version: u32,
        pdf: &'a [u8],
        contents_range: (u64, u64),
        byte_range_token: (u64, u64),
        byte_range: [u64; 4],
        document_digest: &'a [u8],
        signed_attrs_der: &'a [u8],
        digest: DigestAlgorithm,
        algorithm: SignatureAlgorithm,
        key_kind: KeyKind,
        chain_der: &'a [Vec<u8>],
        sub_filter: SubFilter,
        warnings: &'a [String],
    }

    /// The deserialized fields, before the checks.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct Repr {
        version: u32,
        pdf: Vec<u8>,
        contents_range: (u64, u64),
        byte_range_token: (u64, u64),
        byte_range: [u64; 4],
        document_digest: Vec<u8>,
        signed_attrs_der: Vec<u8>,
        digest: DigestAlgorithm,
        algorithm: SignatureAlgorithm,
        key_kind: KeyKind,
        chain_der: Vec<Vec<u8>>,
        sub_filter: SubFilter,
        #[serde(default)]
        warnings: Vec<String>,
    }

    impl serde::Serialize for PreparedSignature {
        fn serialize<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            ReprRef {
                version: PREPARED_SIGNATURE_VERSION,
                pdf: &self.pdf,
                contents_range: self.contents_range,
                byte_range_token: self.byte_range_token,
                byte_range: self.byte_range,
                document_digest: &self.document_digest,
                signed_attrs_der: &self.signed_attrs_der,
                digest: self.digest,
                algorithm: self.algorithm,
                key_kind: self.key_kind,
                chain_der: &self.chain_der,
                sub_filter: self.sub_filter,
                warnings: &self.warnings,
            }
            .serialize(serializer)
        }
    }

    impl<'de> serde::Deserialize<'de> for PreparedSignature {
        fn deserialize<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> std::result::Result<Self, D::Error> {
            let repr = Repr::deserialize(deserializer)?;
            PreparedSignature::from_repr(repr, &RealCms).map_err(serde::de::Error::custom)
        }
    }

    impl PreparedSignature {
        /// The prepared signature of `repr`, checked (brief §4.4).
        pub(crate) fn from_repr(repr: Repr, cms: &dyn CmsBackend) -> Result<PreparedSignature> {
            if repr.version != PREPARED_SIGNATURE_VERSION {
                return Err(invalid(&format!(
                    "format version {} is not supported (this library reads version \
                     {PREPARED_SIGNATURE_VERSION})",
                    repr.version
                )));
            }
            if repr.chain_der.len() > MAX_CERTIFICATES || repr.warnings.len() > MAX_WARNINGS {
                return Err(invalid("too many certificates or warnings"));
            }
            let prepared = PreparedSignature {
                pdf: repr.pdf,
                contents_range: repr.contents_range,
                byte_range_token: repr.byte_range_token,
                byte_range: repr.byte_range,
                document_digest: repr.document_digest,
                signed_attrs_der: repr.signed_attrs_der,
                digest: repr.digest,
                algorithm: repr.algorithm,
                key_kind: repr.key_kind,
                chain_der: repr.chain_der,
                sub_filter: repr.sub_filter,
                warnings: repr.warnings,
            };
            prepared.validated(cms)
        }
    }
}

/// A stand-in for the certificate and CMS operations, for testing the PDF side on its own
/// while they are M3 stage-0 stubs: "certificates" are tags naming their key, and the signed
/// attributes have the real shape (a DER `SET` of content-type, message-digest and a
/// signing-certificate-v2-like attribute).
#[cfg(test)]
pub(crate) mod test_double {
    use super::*;

    /// The double's "certificate" with an RSA-2048 key.
    pub(crate) const RSA_CERT: &[u8] = b"fake-cert:rsa2048";
    /// The double's "certificate" with an RSA-1024 key (too small to sign).
    pub(crate) const RSA1024_CERT: &[u8] = b"fake-cert:rsa1024";
    /// The double's "certificate" with a P-256 key.
    pub(crate) const P256_CERT: &[u8] = b"fake-cert:p256";
    /// The double's "certificate" with a P-384 key.
    pub(crate) const P384_CERT: &[u8] = b"fake-cert:p384";
    /// What the double's CMS adds to the signed attributes, certificates and signature.
    pub(crate) const OVERHEAD: usize = 1500;

    /// The test double.
    pub(crate) struct FakeCms;

    /// A DER element (definite length).
    pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let octets: Vec<u8> = len
                .to_be_bytes()
                .into_iter()
                .skip_while(|&b| b == 0)
                .collect();
            out.push(0x80 | octets.len() as u8);
            out.extend(octets);
        }
        out.extend_from_slice(content);
        out
    }

    impl CmsBackend for FakeCms {
        fn key_kind(&self, cert_der: &[u8]) -> Result<KeyKind> {
            match cert_der {
                RSA_CERT => Ok(KeyKind::Rsa { bits: 2048 }),
                RSA1024_CERT => Ok(KeyKind::Rsa { bits: 1024 }),
                P256_CERT => Ok(KeyKind::EcP256),
                P384_CERT => Ok(KeyKind::EcP384),
                _ => Err(Error::Certificate("not a test-double certificate".into())),
            }
        }

        fn build_signed_attrs(&self, input: &SignedAttrsInput<'_>) -> Result<Vec<u8>> {
            if input.document_digest.len() != input.digest.output_len() {
                return Err(Error::InvalidArgument("digest length".into()));
            }
            self.key_kind(input.signer_cert_der)?;
            const CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
            const ID_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
            const SIGNING_CERT_V2: &[u8] = &[
                0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
            ];
            let attribute = |oid: &[u8], value: Vec<u8>| {
                tlv(0x30, &[tlv(0x06, oid), tlv(0x31, &value)].concat())
            };
            let cert_hash = input.digest.digest(&[input.signer_cert_der]);
            let mut attributes = [
                attribute(CONTENT_TYPE, tlv(0x06, ID_DATA)),
                attribute(
                    // `MESSAGE_DIGEST_OID` without its tag and length.
                    &MESSAGE_DIGEST_OID[2..],
                    tlv(0x04, input.document_digest),
                ),
                attribute(
                    SIGNING_CERT_V2,
                    tlv(0x30, &tlv(0x30, &tlv(0x30, &tlv(0x04, &cert_hash)))),
                ),
            ];
            // DER SET OF: sorted encodings (X.690 §11.6).
            attributes.sort();
            Ok(tlv(0x31, &attributes.concat()))
        }

        fn cms_len_upper_bound(
            &self,
            signed_attrs: &[u8],
            chain_der: &[Vec<u8>],
            _alg: SignatureAlgorithm,
            kind: KeyKind,
            _digest: DigestAlgorithm,
        ) -> Result<usize> {
            Ok(signed_attrs.len()
                + chain_der.iter().map(Vec::len).sum::<usize>()
                + kind.max_signature_len()
                + OVERHEAD)
        }
    }
}

#[cfg(test)]
mod tests {
    use folioxide_model::InfoUpdate;
    use folioxide_syntax::{IncrementalOptions, OpenOptions, Store};
    use folioxide_testkit::fixtures::syntax;

    use super::test_double::{FakeCms, P256_CERT, P384_CERT, RSA_CERT, RSA1024_CERT};
    use super::*;
    use crate::placeholder::default_contents_reserve;

    fn time() -> PdfDate {
        PdfDate::parse(b"D:20261010120000Z").unwrap()
    }

    fn open(bytes: &[u8]) -> Document {
        Document::open(bytes.to_vec(), &OpenOptions::default()).unwrap()
    }

    fn request(cert: &[u8], algorithm: SignatureAlgorithm) -> PrepareRequest {
        PrepareRequest::new(
            vec![cert.to_vec(), b"fake-intermediate".to_vec()],
            algorithm,
            time(),
        )
    }

    fn prepared(source: &[u8], req: &PrepareRequest) -> PreparedSignature {
        prepare_with(&open(source), req, &FakeCms).unwrap()
    }

    fn p256() -> PreparedSignature {
        prepared(
            &syntax::minimal(),
            &request(P256_CERT, SignatureAlgorithm::Ecdsa),
        )
    }

    /// The size the double's CMS needs for this request.
    fn needed(req: &PrepareRequest, kind: KeyKind, digest: DigestAlgorithm) -> usize {
        let zero = vec![0; digest.output_len()];
        let attrs = FakeCms
            .build_signed_attrs(&SignedAttrsInput {
                digest,
                document_digest: &zero,
                signer_cert_der: &req.chain_der[0],
            })
            .unwrap();
        FakeCms
            .cms_len_upper_bound(&attrs, &req.chain_der, req.algorithm, kind, digest)
            .unwrap()
    }

    #[test]
    fn prepare_digest_matches_ranges() {
        let cases = [
            (
                RSA_CERT,
                SignatureAlgorithm::RsaPkcs1v15,
                None,
                KeyKind::Rsa { bits: 2048 },
                DigestAlgorithm::Sha256,
            ),
            (
                P256_CERT,
                SignatureAlgorithm::Ecdsa,
                None,
                KeyKind::EcP256,
                DigestAlgorithm::Sha256,
            ),
            (
                P384_CERT,
                SignatureAlgorithm::Ecdsa,
                None,
                KeyKind::EcP384,
                DigestAlgorithm::Sha384,
            ),
            (
                RSA_CERT,
                SignatureAlgorithm::RsaPkcs1v15,
                Some(DigestAlgorithm::Sha512),
                KeyKind::Rsa { bits: 2048 },
                DigestAlgorithm::Sha512,
            ),
            (
                P256_CERT,
                SignatureAlgorithm::Ecdsa,
                Some(DigestAlgorithm::Sha384),
                KeyKind::EcP256,
                DigestAlgorithm::Sha384,
            ),
        ];
        for source in [syntax::minimal(), syntax::xref_stream(), syntax::objstm()] {
            for (cert, alg, digest, kind, expected_digest) in cases {
                let req = request(cert, alg);
                let req = req.clone().with_options(req.options.with_digest(digest));
                let p = prepared(&source, &req);
                assert_eq!(p.digest_algorithm(), expected_digest);
                assert_eq!(p.algorithm(), alg);
                assert_eq!(p.key_kind(), kind);

                let pdf = p.pdf();
                assert!(pdf.starts_with(&source), "the source is a prefix");
                let [zero, a, b, c] = p.byte_range();
                assert_eq!((zero, b + c), (0, pdf.len() as u64));
                assert_eq!(p.contents_range(), (a, b));
                let (a, b) = (a as usize, b as usize);
                assert_eq!(pdf[a], b'<');
                assert_eq!(pdf[b - 1], b'>');
                assert!(pdf[a + 1..b - 1].iter().all(|&d| d == b'0'));

                // The digest is over exactly the two ranges.
                let expected = expected_digest.digest(&[&pdf[..a], &pdf[b..]]);
                assert_eq!(p.document_digest(), expected.as_slice());
                // The bytes to sign carry it, with the SET tag.
                assert_eq!(p.to_be_signed()[0], 0x31);
                assert_eq!(message_digest_of(p.to_be_signed()), Some(expected));
                assert_eq!(
                    p.to_be_signed_digest(),
                    expected_digest.digest(&[p.to_be_signed()])
                );
                let info = p.to_be_signed_digest_info();
                assert!(info.ends_with(&p.to_be_signed_digest()));
                assert_eq!(info, expected_digest.digest_info(&p.to_be_signed_digest()));

                // Exact sizing: the default reserve of the exact need.
                assert_eq!(
                    p.contents_capacity(),
                    default_contents_reserve(needed(&req, kind, expected_digest))
                );
                assert!(p.contents_capacity() >= 8192);
                assert_eq!(p.chain_der(), req.chain_der.as_slice());
                assert_eq!(p.sub_filter(), SubFilter::EtsiCadesDetached);
                p.clone().validated(&FakeCms).unwrap();
            }
        }
    }

    #[test]
    fn prepare_does_not_mutate_document() {
        let source = syntax::minimal();
        let mut doc = open(&source);
        let mut update = InfoUpdate::default();
        update.title = Some(Some("Pending title".into()));
        doc.set_info(&update).unwrap();
        let edited = doc.store().edited_ids();
        let pending = doc
            .save_incremental(&IncrementalOptions::default())
            .unwrap();
        let next = doc.store().next_object_number();

        let p = prepare_with(
            &doc,
            &request(P256_CERT, SignatureAlgorithm::Ecdsa),
            &FakeCms,
        )
        .unwrap();

        assert_eq!(doc.store().edited_ids(), edited);
        assert!(doc.is_modified());
        assert_eq!(doc.store().next_object_number(), next);
        assert_eq!(
            doc.save_incremental(&IncrementalOptions::default())
                .unwrap(),
            pending,
            "the document is unchanged"
        );
        // The pending edit is in the same, single revision as the signature.
        let signed = Document::open(p.pdf().to_vec(), &OpenOptions::default()).unwrap();
        assert_eq!(
            signed.info().unwrap().title.as_deref(),
            Some("Pending title")
        );
        assert_eq!(
            signed.store().revisions().len(),
            open(&source).store().revisions().len() + 1
        );
    }

    #[test]
    fn prepare_rejects_too_small_reserve() {
        let req = request(P256_CERT, SignatureAlgorithm::Ecdsa);
        let need = needed(&req, KeyKind::EcP256, DigestAlgorithm::Sha256);
        let doc = open(&syntax::minimal());

        let small = req
            .clone()
            .with_options(req.options.clone().with_contents_reserve(Some(100)));
        let err = prepare_with(&doc, &small, &FakeCms).unwrap_err();
        assert!(
            matches!(err, Error::PlaceholderTooSmall { needed, reserved: 100 } if needed == need),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!("signature placeholder too small: needed {need} bytes, reserved 100")
        );

        // Retrying with exactly `needed` works, and the reserve is exactly that.
        let exact = req
            .clone()
            .with_options(req.options.clone().with_contents_reserve(Some(need)));
        let p = prepare_with(&doc, &exact, &FakeCms).unwrap();
        assert_eq!(p.contents_capacity(), need);

        for bad in [0, MAX_CONTENTS_RESERVE + 1] {
            let bad = req
                .clone()
                .with_options(req.options.clone().with_contents_reserve(Some(bad)));
            let err = prepare_with(&doc, &bad, &FakeCms).unwrap_err();
            assert_eq!(
                err.code(),
                folioxide_syntax::ErrorCode::InvalidArgument,
                "{err}"
            );
        }
    }

    #[test]
    fn prepare_checks_the_request() {
        let doc = open(&syntax::minimal());
        let code = |req: &PrepareRequest| prepare_with(&doc, req, &FakeCms).unwrap_err().code();
        use folioxide_syntax::ErrorCode;

        let mut empty = request(P256_CERT, SignatureAlgorithm::Ecdsa);
        empty.chain_der.clear();
        assert_eq!(code(&empty), ErrorCode::InvalidArgument);

        let mut long = request(P256_CERT, SignatureAlgorithm::Ecdsa);
        long.chain_der = vec![P256_CERT.to_vec(); MAX_CERTIFICATES + 1];
        assert_eq!(code(&long), ErrorCode::InvalidArgument);

        // The algorithm must match the key.
        assert_eq!(
            code(&request(P256_CERT, SignatureAlgorithm::RsaPkcs1v15)),
            ErrorCode::InvalidArgument
        );
        // SHA-1 and small RSA keys never sign.
        let sha1 = request(RSA_CERT, SignatureAlgorithm::RsaPkcs1v15);
        let sha1 = sha1
            .clone()
            .with_options(sha1.options.with_digest(Some(DigestAlgorithm::Sha1)));
        assert_eq!(code(&sha1), ErrorCode::InvalidArgument);
        assert_eq!(
            code(&request(RSA1024_CERT, SignatureAlgorithm::RsaPkcs1v15)),
            ErrorCode::InvalidArgument
        );
        // A certificate the CMS side cannot read.
        assert_eq!(
            code(&request(b"garbage", SignatureAlgorithm::Ecdsa)),
            ErrorCode::Certificate
        );
    }

    #[test]
    fn prepared_types_are_send_sync_static() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<PreparedSignature>();
        assert_send_sync::<PrepareRequest>();
        assert_send_sync::<SignatureOptions>();
        assert_send_sync::<crate::placeholder::PlaceholderPdf>();
        assert_send_sync::<crate::field::SignatureField>();
    }

    #[test]
    fn prepare_is_deterministic() {
        let a = p256();
        let b = p256();
        assert_eq!(a, b);
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn prepared_signature_bytes_roundtrip() {
        for p in [
            p256(),
            prepared(
                &syntax::hybrid(),
                &request(RSA_CERT, SignatureAlgorithm::RsaPkcs1v15),
            ),
            prepared(
                &syntax::xref_stream(),
                &request(P384_CERT, SignatureAlgorithm::Ecdsa),
            ),
        ] {
            let bytes = p.to_bytes();
            assert_eq!(&bytes[..4], b"FXPS");
            assert_eq!(&bytes[4..8], &1u32.to_be_bytes());
            let back = PreparedSignature::from_bytes_with(&bytes, &FakeCms).unwrap();
            assert_eq!(back, p);
            assert_eq!(back.to_bytes(), bytes);
            assert_eq!(back.to_be_signed(), p.to_be_signed());
        }
        // With the library's own certificate parsing, fake certificates never load.
        assert!(PreparedSignature::from_bytes(&p256().to_bytes()).is_err());
    }

    #[test]
    fn prepared_signature_tamper_rejected() {
        let p = p256();
        let (a, b) = p.contents_range();
        let (a, b) = (a as usize, b as usize);
        let (t0, _) = p.byte_range_token;
        type Mutation = Box<dyn Fn(&mut PreparedSignature)>;
        let mutations: Vec<(&str, Mutation)> = vec![
            ("byte in part 1", Box::new(|p| p.pdf[20] ^= 1)),
            (
                "byte in part 2",
                Box::new(move |p| {
                    let at = b + 3;
                    p.pdf[at] ^= 1;
                }),
            ),
            ("contents digit", Box::new(move |p| p.pdf[a + 1] = b'1')),
            ("contents delimiter", Box::new(move |p| p.pdf[a] = b'(')),
            ("byte range value", Box::new(|p| p.byte_range[3] -= 1)),
            (
                "byte range text",
                Box::new(move |p| {
                    // `[0 a ...`: turn the first digit of `a` into another digit.
                    let at = t0 as usize + 3;
                    p.pdf[at] = if p.pdf[at] == b'9' {
                        b'8'
                    } else {
                        p.pdf[at] + 1
                    };
                }),
            ),
            ("byte range token", Box::new(|p| p.byte_range_token.1 -= 1)),
            ("contents range", Box::new(|p| p.contents_range.1 -= 2)),
            ("document digest", Box::new(|p| p.document_digest[0] ^= 1)),
            (
                "signed attrs digest",
                Box::new(|p| {
                    let last = p.signed_attrs_der.len() - 1;
                    let digest = p.document_digest.clone();
                    let at = p
                        .signed_attrs_der
                        .windows(digest.len())
                        .position(|w| w == digest)
                        .unwrap();
                    p.signed_attrs_der[at] ^= 1;
                    let _ = last;
                }),
            ),
            (
                "signed attrs tag",
                Box::new(|p| p.signed_attrs_der[0] = 0xA0),
            ),
            (
                "digest algorithm",
                Box::new(|p| p.digest = DigestAlgorithm::Sha384),
            ),
            ("key kind", Box::new(|p| p.key_kind = KeyKind::EcP384)),
            (
                "signer certificate",
                Box::new(|p| p.chain_der[0] = P384_CERT.to_vec()),
            ),
            (
                "algorithm",
                Box::new(|p| p.algorithm = SignatureAlgorithm::RsaPkcs1v15),
            ),
            ("no chain", Box::new(|p| p.chain_der.clear())),
            // QA findings 1 and 7: fields the file or the signed attributes pin down.
            (
                "sub filter code",
                Box::new(|p| p.sub_filter = SubFilter::AdbePkcs7Detached),
            ),
            (
                "extra signed attribute",
                Box::new(|p| {
                    // A signing-time attribute appended inside the SET, the message digest kept.
                    let time = super::test_double::tlv(
                        0x30,
                        &[
                            super::test_double::tlv(
                                0x06,
                                &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05],
                            ),
                            super::test_double::tlv(
                                0x31,
                                &super::test_double::tlv(0x17, b"261010120000Z"),
                            ),
                        ]
                        .concat(),
                    );
                    let (_, content, _) = der_element(&p.signed_attrs_der, 0).unwrap();
                    let inner = [&p.signed_attrs_der[content], time.as_slice()].concat();
                    p.signed_attrs_der = super::test_double::tlv(0x31, &inner);
                    assert!(message_digest_of(&p.signed_attrs_der).is_some());
                }),
            ),
            (
                "signed attributes of another certificate",
                Box::new(|p| {
                    // Another certificate's ESS certHash, the message digest kept.
                    let other = FakeCms
                        .build_signed_attrs(&SignedAttrsInput {
                            digest: p.digest,
                            document_digest: &p.document_digest,
                            signer_cert_der: P384_CERT,
                        })
                        .unwrap();
                    p.signed_attrs_der = other;
                }),
            ),
            (
                "truncated file",
                Box::new(|p| {
                    p.pdf.pop();
                }),
            ),
        ];
        for (name, mutate) in &mutations {
            let mut tampered = p.clone();
            mutate(&mut tampered);
            assert!(tampered.clone().validated(&FakeCms).is_err(), "{name}");
            let err =
                PreparedSignature::from_bytes_with(&tampered.to_bytes(), &FakeCms).expect_err(name);
            assert!(
                matches!(err.code(), folioxide_syntax::ErrorCode::InvalidArgument),
                "{name}: {err}"
            );
        }

        // The binary form itself: magic, version, codes, counts, truncation, trailing bytes.
        let bytes = p.to_bytes();
        let load = |bytes: &[u8]| PreparedSignature::from_bytes_with(bytes, &FakeCms);
        let mut magic = bytes.clone();
        magic[0] = b'X';
        assert!(load(&magic).is_err());
        let mut version = bytes.clone();
        version[7] = 2;
        assert!(
            load(&version)
                .unwrap_err()
                .to_string()
                .contains("version 2")
        );
        for (at, value) in [(8, 9), (9, 9), (10, 3), (11, 7)] {
            let mut code = bytes.clone();
            code[at] = value;
            assert!(load(&code).is_err(), "code at {at}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(load(&trailing).is_err());
        // Every truncation is an error, never a panic or a huge allocation.
        for len in (0..bytes.len())
            .step_by(97)
            .chain(bytes.len() - 8..bytes.len())
        {
            assert!(load(&bytes[..len]).is_err(), "truncated to {len}");
        }
        // A claimed length beyond the input is an error, not an allocation.
        let mut huge = bytes[..8 + 4 + 4 * 2 + 8 * 8].to_vec();
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(load(&huge).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn prepared_signature_serde_roundtrip() {
        let p = p256();
        let json = serde_json::to_value(&p).unwrap();
        for key in [
            "version",
            "pdf",
            "contentsRange",
            "byteRangeToken",
            "byteRange",
            "documentDigest",
            "signedAttrsDer",
            "digest",
            "algorithm",
            "keyKind",
            "chainDer",
            "subFilter",
            "warnings",
        ] {
            assert!(json.get(key).is_some(), "missing {key}");
        }
        assert_eq!(json["version"], 1);
        assert_eq!(json["digest"], "sha256");
        assert_eq!(json["algorithm"], "ecdsa");
        assert_eq!(json["keyKind"], "ecP256");
        assert_eq!(json["subFilter"], "ETSI.CAdES.detached");

        let load = |json: serde_json::Value| {
            let repr: serde_impl::Repr = serde_json::from_value(json).unwrap();
            PreparedSignature::from_repr(repr, &FakeCms)
        };
        assert_eq!(load(json.clone()).unwrap(), p);
        // Through a string too.
        let text = serde_json::to_string(&p).unwrap();
        assert_eq!(load(serde_json::from_str(&text).unwrap()).unwrap(), p);

        // Deserializing re-checks the invariants.
        let mut tampered = json.clone();
        tampered["pdf"][20] = (p.pdf()[20] ^ 1).into();
        assert!(load(tampered).is_err());
        let mut version = json.clone();
        version["version"] = 2.into();
        assert!(load(version).is_err());
        let mut range = json.clone();
        range["byteRange"][3] = 1.into();
        assert!(load(range).is_err());
        // Unknown fields are refused.
        let mut extra = json.clone();
        extra["extra"] = 1.into();
        assert!(serde_json::from_value::<serde_impl::Repr>(extra).is_err());
        // The public path checks the certificate with the library's own parser, which refuses
        // the double's fake certificates.
        assert!(serde_json::from_value::<PreparedSignature>(json).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn options_and_request_serde_shapes() {
        let options = SignatureOptions::new(time())
            .with_reason(Some("R".into()))
            .with_sub_filter(SubFilter::AdbePkcs7Detached)
            .with_contents_reserve(Some(9000));
        let json = serde_json::to_value(&options).unwrap();
        assert_eq!(json["signingTime"], "D:20261010120000Z");
        assert_eq!(json["subFilter"], "adbe.pkcs7.detached");
        assert_eq!(json["contentsReserve"], 9000);
        assert_eq!(json["field"]["mode"], "createOrUse");
        assert!(json.get("contactInfo").is_some());
        let back: SignatureOptions = serde_json::from_value(json).unwrap();
        assert_eq!(back, options);
        // Only the signing time is required.
        let minimal: SignatureOptions =
            serde_json::from_value(serde_json::json!({"signingTime": "D:20261010120000Z"}))
                .unwrap();
        assert_eq!(minimal, SignatureOptions::new(time()));

        let req = request(P256_CERT, SignatureAlgorithm::Ecdsa);
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["algorithm"], "ecdsa");
        assert!(json["chainDer"].is_array());
        assert_eq!(serde_json::from_value::<PrepareRequest>(json).unwrap(), req);
    }

    #[test]
    fn message_digest_lookup() {
        let attrs = FakeCms
            .build_signed_attrs(&SignedAttrsInput {
                digest: DigestAlgorithm::Sha256,
                document_digest: &[7; 32],
                signer_cert_der: P256_CERT,
            })
            .unwrap();
        assert_eq!(message_digest_of(&attrs), Some(vec![7; 32]));
        // Not a single SET element, or truncated: nothing.
        assert_eq!(message_digest_of(&attrs[..attrs.len() - 1]), None);
        assert_eq!(message_digest_of(&[attrs.clone(), vec![0]].concat()), None);
        let mut retagged = attrs.clone();
        retagged[0] = 0xA0;
        assert_eq!(message_digest_of(&retagged), None);
        assert_eq!(message_digest_of(&[]), None);
        // Two message-digest attributes are ambiguous.
        let md = super::test_double::tlv(
            0x30,
            &[
                MESSAGE_DIGEST_OID.to_vec(),
                super::test_double::tlv(0x31, &super::test_double::tlv(0x04, &[1; 32])),
            ]
            .concat(),
        );
        let twice = super::test_double::tlv(0x31, &[md.clone(), md].concat());
        assert_eq!(message_digest_of(&twice), None);
        // Every truncation of a valid input is handled.
        for len in 0..attrs.len() {
            let _ = message_digest_of(&attrs[..len]);
        }
        // Long-form lengths.
        let long = super::test_double::tlv(
            0x31,
            &super::test_double::tlv(
                0x30,
                &[
                    MESSAGE_DIGEST_OID.to_vec(),
                    super::test_double::tlv(0x31, &super::test_double::tlv(0x04, &[9; 200])),
                ]
                .concat(),
            ),
        );
        assert_eq!(message_digest_of(&long), Some(vec![9; 200]));
    }

    #[test]
    fn byte_range_token_parse() {
        let pdf = b"xx[0 12 34 56     ]yy";
        assert_eq!(parse_byte_range_token(pdf, (2, 19)), Some([0, 12, 34, 56]));
        assert_eq!(parse_byte_range_token(pdf, (2, 18)), None);
        assert_eq!(parse_byte_range_token(pdf, (3, 19)), None);
        assert_eq!(parse_byte_range_token(pdf, (2, 99)), None);
        assert_eq!(parse_byte_range_token(b"[0 1 2 -3]", (0, 10)), None);
        assert_eq!(parse_byte_range_token(b"[0 1 2 3.0]", (0, 11)), None);
        assert_eq!(parse_byte_range_token(b"[0 1 2]", (0, 7)), None);
    }

    #[test]
    fn debug_prints_no_bytes() {
        let p = p256();
        let debug = format!("{p:?}");
        assert!(debug.contains("PreparedSignature"));
        assert!(debug.len() < 600, "{debug}");
        let store = Store::open_bytes(p.pdf().to_vec(), &OpenOptions::default()).unwrap();
        assert!(!store.structure_repaired());
    }
}

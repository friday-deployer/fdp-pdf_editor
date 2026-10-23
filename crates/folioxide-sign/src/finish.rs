//! The second phase of signing (M3 brief §3.2 and §4.4; ARCHITECTURE §A.6.5):
//! [`PreparedSignature::finish`] with a signature value, and [`PreparedSignature::embed_cms`]
//! with a complete CMS made elsewhere (a remote signing service).
//!
//! Both re-check the invariants of the prepared signature, then check what they are given
//! **before** anything is written, so a finished file never carries a signature that does not
//! verify:
//!
//! - `finish(signature)` verifies the value with the signer certificate over
//!   [`to_be_signed`](PreparedSignature::to_be_signed) (an ECDSA value may be DER or IEEE P1363;
//!   both interpretations are tried), assembles the CMS ([`cms::assemble`]) and embeds it;
//! - `embed_cms(cms)` parses the CMS ([`cms::parse`]), requires exactly one SignerInfo and a
//!   detached signature, verifies it over the prepared byte ranges ([`cms::verify_detached`]:
//!   the message-digest must be the digest of the ranges and the signature must verify with
//!   the CMS's own signer certificate), and for `ETSI.CAdES.detached` requires a DER
//!   SignedData with the PAdES baseline B-B signed attributes (content-type, matching
//!   signing-certificate-v2, no signing-time): Folioxide never labels a non-B-B CMS
//!   `ETSI.CAdES.detached`.
//!
//! Both start from a prepared signature whose invariants hold (brief §4.4, checked again here):
//! the signed attributes are exactly those `prepare` builds, and the file's signature
//! dictionary carries the recorded `/SubFilter`. `finish` also verifies the CMS it assembled
//! before writing it.
//!
//! [`PreparedSignature::try_finish`] and [`PreparedSignature::try_embed_cms`] make the same
//! checks but give the prepared signature back with the error ([`FinishError`]), so a caller
//! whose external signer returned a wrong value can try again without preparing again.
//!
//! **Signature timestamps** (M4 brief §3.1): a CMS given to `embed_cms` may carry
//! `id-aa-signatureTimeStampToken` unsigned attributes; every token must then verify over the
//! CMS's signature value (brief §5 V7b: intact and valid), or the CMS is refused. The B-T flow
//! that timestamps a signature value itself is [`bt`](crate::bt).
//!
//! **Embedding** (brief §4.2 step 7): the DER is written as uppercase hexadecimal digits right
//! after the `/Contents` `<`; the rest of the `2R` digits stay `0`. The DER length delimits the
//! CMS, so verifiers ignore the zero padding. A CMS longer than the reserve `R` fails with
//! [`Error::PlaceholderTooSmall`] (`needed` is the CMS length, `reserved` is `R`), and nothing
//! is written. `prepare` sizes the reserve for the largest CMS `finish` can produce, so only
//! `embed_cms` with a CMS larger than the prepared chain needs can overflow.

use std::fmt;
use std::ops::Range;

use crate::algorithms::{DigestAlgorithm, oid};
use crate::cms::{self, tlv};
use crate::error::{Error, Result};
use crate::field::SubFilter;
use crate::placeholder;
use crate::prepare::{PreparedSignature, RealCms};
use crate::problem::ProblemCode;

/// A refused [`PreparedSignature::try_finish`] or [`PreparedSignature::try_embed_cms`]: the
/// reason, and the prepared signature, unchanged, to try again with a corrected signature
/// value or CMS without preparing again.
///
/// `Debug` and `Display` show the error (and the prepared signature's layout), never the file.
#[derive(Debug)]
pub struct FinishError {
    error: Error,
    prepared: Box<PreparedSignature>,
}

impl FinishError {
    /// A refusal of `prepared` with `error` (also used by [`bt`](crate::bt)).
    pub(crate) fn new(error: Error, prepared: PreparedSignature) -> FinishError {
        FinishError {
            error,
            prepared: Box::new(prepared),
        }
    }

    /// Why the value was refused: the error [`finish`](PreparedSignature::finish) or
    /// [`embed_cms`](PreparedSignature::embed_cms) returns for it.
    pub fn error(&self) -> &Error {
        &self.error
    }

    /// The error and the prepared signature, to try again.
    pub fn into_parts(self) -> (Error, PreparedSignature) {
        (self.error, *self.prepared)
    }

    /// The error, dropping the prepared signature.
    pub fn into_error(self) -> Error {
        self.error
    }
}

impl fmt::Display for FinishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}

impl std::error::Error for FinishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<FinishError> for Error {
    fn from(err: FinishError) -> Error {
        err.error
    }
}

impl PreparedSignature {
    /// Finishes the file with `signature`, the signature value over
    /// [`to_be_signed`](Self::to_be_signed) made with the key of the first certificate of the
    /// chain and [`digest_algorithm`](Self::digest_algorithm): returns the complete signed PDF.
    ///
    /// - RSA: exactly the modulus length (a shorter value is left-padded with zeros, as OpenSSL
    ///   does).
    /// - ECDSA: a DER `ECDSA-Sig-Value` (non-minimal INTEGERs are re-encoded) or IEEE P1363
    ///   `r || s`, as WebCrypto and most KMSes return it.
    ///
    /// An external RSA key (an HSM, a KMS, `node:crypto`) signs the prepared bytes; here a
    /// [`LocalSigner`](crate::signer::LocalSigner) from the test PKI plays it. A value made
    /// with another key is refused before anything is written:
    ///
    /// ```
    /// use folioxide_model::{Document, PdfDate};
    /// use folioxide_sign::Error;
    /// use folioxide_sign::algorithms::SignatureAlgorithm;
    /// use folioxide_sign::keys::certificates_from_pem;
    /// use folioxide_sign::prepare::{PrepareRequest, prepare};
    /// use folioxide_sign::signer::{LocalSigner, Signer};
    /// use folioxide_syntax::OpenOptions;
    ///
    /// # let pki = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pki");
    /// # let read = |name: &str| std::fs::read_to_string(pki.join(name));
    /// # let hsm = LocalSigner::from_pkcs12(
    /// #     &std::fs::read(pki.join("signer-rsa2048-modern.p12"))?,
    /// #     "folioxide",
    /// # )?;
    /// # let other_key = LocalSigner::from_pem(
    /// #     &read("signer-rsa3072.key.pem")?,
    /// #     &read("signer-rsa3072.pem")?,
    /// #     None,
    /// # )?;
    /// // The certificate chain is all the preparing side needs.
    /// let chain = certificates_from_pem(
    ///     &(read("signer-rsa2048.pem")? + &read("intermediate.pem")?),
    /// )?;
    /// let doc = Document::open(
    ///     folioxide_testkit::fixtures::syntax::minimal(),
    ///     &OpenOptions::default(),
    /// )?;
    /// let time = PdfDate::parse(b"D:20261010120000Z").expect("a PDF date");
    /// let request = PrepareRequest::new(chain, SignatureAlgorithm::RsaPkcs1v15, time);
    /// let prepared = prepare(&doc, &request)?;
    ///
    /// // A value by another key does not verify with the certificate: refused.
    /// let wrong = other_key.sign(prepared.digest_algorithm(), prepared.to_be_signed())?;
    /// let err = prepared.clone().finish(&wrong).unwrap_err();
    /// assert!(matches!(err, Error::SignatureInvalid(_)), "{err}");
    ///
    /// // The right key's value finishes the file.
    /// let value = hsm.sign(prepared.digest_algorithm(), prepared.to_be_signed())?;
    /// let signed: Vec<u8> = prepared.finish(&value)?;
    /// # assert!(signed.ends_with(b"%%EOF\n"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    /// - [`Error::SignatureInvalid`]: the value does not verify with the signer certificate (a
    ///   different key, a different digest, other bytes), or has neither ECDSA form.
    /// - [`Error::PlaceholderTooSmall`]: the CMS does not fit in the reserve (not expected for a
    ///   prepared signature, whose reserve is sized for this chain).
    /// - [`Error::InvalidArgument`]: an invariant of the prepared signature does not hold
    ///   (brief §4.4); or, for `ETSI.CAdES.detached`, a certificate of the chain is not
    ///   DER-encoded, so the CMS could not be PAdES B-B.
    /// - [`Error::Crypto`]: the assembled CMS fails its own verification (checked before it is
    ///   written).
    /// - [`Error::Certificate`] or [`Error::Unsupported`] for a signer certificate that does not
    ///   parse or has an unsupported key.
    pub fn finish(self, signature: &[u8]) -> Result<Vec<u8>> {
        self.try_finish(signature).map_err(FinishError::into_error)
    }

    /// Like [`finish`](Self::finish), but a refused value gives the prepared signature back
    /// with the error, unchanged, so the caller can try again (an HSM or KMS that signed with
    /// the wrong key, a WebCrypto value passed in the wrong form) without preparing again.
    /// Every check runs before the file is touched, so whatever fails, nothing is lost.
    ///
    /// ```
    /// # use folioxide_model::{Document, PdfDate};
    /// # use folioxide_sign::prepare::{PrepareRequest, prepare};
    /// # use folioxide_sign::signer::{LocalSigner, Signer};
    /// # use folioxide_syntax::OpenOptions;
    /// # let pki = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pki");
    /// # let key = LocalSigner::from_pkcs12(
    /// #     &std::fs::read(pki.join("signer-p256-modern.p12"))?,
    /// #     "folioxide",
    /// # )?;
    /// # let doc = Document::open(
    /// #     folioxide_testkit::fixtures::syntax::minimal(),
    /// #     &OpenOptions::default(),
    /// # )?;
    /// # let time = PdfDate::parse(b"D:20261010120000Z").expect("a PDF date");
    /// let request = PrepareRequest::new(key.certificate_chain().to_vec(), key.algorithm(), time);
    /// let prepared = prepare(&doc, &request)?;
    ///
    /// // A value over other bytes is refused, and the prepared signature comes back.
    /// let wrong = key.sign(prepared.digest_algorithm(), b"other bytes")?;
    /// let (err, prepared) = prepared.try_finish(&wrong).unwrap_err().into_parts();
    /// assert_eq!(err.code(), folioxide_syntax::ErrorCode::SignatureInvalid);
    ///
    /// let value = key.sign(prepared.digest_algorithm(), prepared.to_be_signed())?;
    /// let signed = prepared.try_finish(&value)?;
    /// # assert!(signed.ends_with(b"%%EOF\n"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    /// As [`finish`](Self::finish), in a [`FinishError`] that holds the prepared signature.
    pub fn try_finish(mut self, signature: &[u8]) -> std::result::Result<Vec<u8>, FinishError> {
        let checked = self
            .validate(&RealCms)
            .and_then(|()| self.signature_cms(signature))
            .and_then(|der| self.embed_position(&der).map(|at| (der, at)));
        match checked {
            Ok((der, at)) => Ok(self.write_der(at, &der)),
            Err(error) => Err(FinishError::new(error, self)),
        }
    }

    /// [`finish`](Self::finish) without re-checking the invariants: for a prepared signature
    /// that [`prepare`](crate::prepare::prepare) has just built and checked.
    pub(crate) fn finish_checked(self, signature: &[u8]) -> Result<Vec<u8>> {
        let der = self.signature_cms(signature)?;
        self.embed_der(&der)
    }

    /// The CMS [`finish`](Self::finish) embeds for `signature`: the value verified with the
    /// signer certificate, assembled, and the result verified as a verifier will.
    ///
    /// # Errors
    /// As [`finish`](Self::finish), except [`Error::PlaceholderTooSmall`].
    fn signature_cms(&self, signature: &[u8]) -> Result<Vec<u8>> {
        let value = self.normalized_signature(signature)?;
        let der = cms::assemble(
            &self.signed_attrs_der,
            &value,
            &self.chain_der,
            self.algorithm,
            self.key_kind,
            self.digest,
        )?;
        self.check_assembled(&der, None)?;
        Ok(der)
    }

    /// `signature` verified with the signer certificate over
    /// [`to_be_signed`](Self::to_be_signed) and normalized as it is embedded
    /// ([`cms::verify_and_normalize`]): the value a signature timestamp covers (M4 brief §4.5).
    ///
    /// # Errors
    /// [`Error::SignatureInvalid`] when it does not verify; the certificate errors of
    /// [`cms::verify_and_normalize`].
    pub(crate) fn normalized_signature(&self, signature: &[u8]) -> Result<Vec<u8>> {
        let signer = self
            .chain_der
            .first()
            .ok_or_else(|| Error::InvalidArgument("the certificate chain is empty".to_owned()))?;
        cms::verify_and_normalize(
            signer,
            self.algorithm,
            self.digest,
            &self.signed_attrs_der,
            signature,
        )
        .map_err(|err| match err {
            Error::SignatureInvalid(message) => Error::SignatureInvalid(format!(
                "the signature value does not verify with the signer certificate over the \
                 prepared signed attributes: {message}"
            )),
            other => other,
        })
    }

    /// Verifies the CMS `finish` assembled as a verifier will (brief §4.4, defence in depth):
    /// it parses, signs the prepared byte ranges, verifies with its signer certificate, has no
    /// problem, and for `ETSI.CAdES.detached` is PAdES baseline B-B and DER. With `token`, the
    /// SignerInfo carries exactly that signature timestamp token, and it verifies over the
    /// signature value (M4 brief §5 V7b: intact and valid).
    ///
    /// # Errors
    /// - [`Error::Crypto`]: it does not verify (an inconsistent prepared signature).
    /// - [`Error::InvalidArgument`]: for `ETSI.CAdES.detached`, a chain certificate is not DER.
    pub(crate) fn check_assembled(&self, der: &[u8], token: Option<&[u8]>) -> Result<()> {
        let parsed = cms::parse(der)
            .map_err(|err| Error::Crypto(format!("the assembled CMS does not parse: {err}")))?;
        let verification = cms::verify_detached(&parsed, &|d| Some(self.digest_for(d)), &[]);
        let mut failures: Vec<String> = verification
            .problems
            .iter()
            .map(ToString::to_string)
            .collect();
        if !verification.intact || !verification.signature_valid {
            failures.push("it does not verify over the prepared byte ranges".to_owned());
        }
        if self.sub_filter == SubFilter::EtsiCadesDetached
            && !verification.pades_attrs.is_baseline_b()
        {
            failures.push("it is not PAdES baseline B-B".to_owned());
        }
        if let Some(token) = token {
            match parsed.signer_infos.as_slice() {
                [signer_info] => {
                    let tokens = cms::signature_timestamp_tokens(signer_info);
                    if tokens.as_slice() != [token] {
                        failures.push(
                            "it does not carry exactly the one signature timestamp token"
                                .to_owned(),
                        );
                    }
                    if let Err(reason) = token_verifies(token, &signer_info.signature) {
                        failures.push(reason);
                    }
                }
                _ => failures.push("it does not have exactly one SignerInfo".to_owned()),
            }
        }
        if !failures.is_empty() {
            return Err(Error::Crypto(format!(
                "the assembled CMS fails its own verification: {}",
                failures.join("; ")
            )));
        }
        // The certificates are embedded byte for byte (brief §4.3): a chain certificate that is
        // not DER makes the SignedData BER, which is not PAdES B-B.
        if self.sub_filter == SubFilter::EtsiCadesDetached && !is_der_cms(der, &parsed) {
            return Err(Error::InvalidArgument(
                "a certificate of the chain is not DER-encoded, so the CMS is not PAdES \
                 baseline B-B and cannot be labelled ETSI.CAdES.detached (prepare with \
                 adbe.pkcs7.detached instead)"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// The digest of the prepared byte ranges with `algorithm`.
    pub(crate) fn digest_for(&self, algorithm: DigestAlgorithm) -> Vec<u8> {
        if algorithm == self.digest {
            self.document_digest.clone()
        } else {
            placeholder::signed_digest(&self.pdf, self.contents_range, algorithm)
        }
    }

    /// Finishes the file with `cms_der`, a complete DER (or BER) `ContentInfo(SignedData)` that
    /// a remote signing service made over the prepared byte ranges: returns the complete signed
    /// PDF.
    ///
    /// The CMS must sign this file: exactly one SignerInfo, no encapsulated content, a
    /// message-digest equal to the digest of the prepared byte ranges (with the SignerInfo's
    /// digest algorithm, which may differ from [`digest_algorithm`](Self::digest_algorithm)),
    /// and a signature that verifies with the signer certificate the CMS carries. For
    /// `ETSI.CAdES.detached` it must also meet PAdES baseline B-B: DER-encoded as a whole (EN
    /// 319 142-1; BER is accepted only for `adbe.pkcs7.detached`), content-type `id-data`, a
    /// signing-certificate-v2 that matches the signer, no signing-certificate v1, no
    /// signing-time. Zero bytes after the CMS are ignored; other trailing bytes are refused.
    ///
    /// A signing service that returns a whole CMS; here it is built with
    /// [`cms::assemble`] from a test-PKI key. A CMS over another
    /// document's bytes is refused:
    ///
    /// ```
    /// use folioxide_model::{Document, PdfDate};
    /// use folioxide_sign::cms;
    /// use folioxide_sign::prepare::{PrepareRequest, PreparedSignature, prepare};
    /// use folioxide_sign::signer::{LocalSigner, Signer};
    /// use folioxide_syntax::OpenOptions;
    ///
    /// # let pki = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pki");
    /// # let p12 = std::fs::read(pki.join("signer-p256-modern.p12"))?;
    /// let service = LocalSigner::from_pkcs12(&p12, "folioxide")?;
    /// // What the service does with the bytes to sign it is given.
    /// let make_cms = |prepared: &PreparedSignature| -> folioxide_sign::Result<Vec<u8>> {
    ///     let value = service.sign(prepared.digest_algorithm(), prepared.to_be_signed())?;
    ///     cms::assemble(
    ///         prepared.to_be_signed(),
    ///         &value,
    ///         service.certificate_chain(),
    ///         service.algorithm(),
    ///         service.key_kind(),
    ///         prepared.digest_algorithm(),
    ///     )
    /// };
    ///
    /// let time = PdfDate::parse(b"D:20261010120000Z").expect("a PDF date");
    /// let request =
    ///     PrepareRequest::new(service.certificate_chain().to_vec(), service.algorithm(), time);
    /// let open = |pdf: Vec<u8>| Document::open(pdf, &OpenOptions::default());
    /// let minimal = open(folioxide_testkit::fixtures::syntax::minimal())?;
    /// let prepared = prepare(&minimal, &request)?;
    /// let cms_der = make_cms(&prepared)?;
    /// let signed = prepared.clone().embed_cms(&cms_der)?;
    /// # assert!(signed.len() > cms_der.len());
    ///
    /// // The same CMS for another file: its message digest does not match.
    /// let other = prepare(&open(folioxide_testkit::fixtures::syntax::xref_stream())?, &request)?;
    /// assert!(other.embed_cms(&cms_der).is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    /// - [`Error::SignatureInvalid`]: the CMS signs different bytes ("CMS signs different
    ///   bytes"), or its signature does not verify.
    /// - [`Error::InvalidArgument`]: not a parsable ContentInfo, not exactly one SignerInfo,
    ///   encapsulated content, a weak (SHA-1) digest, not DER or not B-B for
    ///   `ETSI.CAdES.detached`, bytes around the CMS, or a broken invariant of the prepared
    ///   signature.
    /// - [`Error::PlaceholderTooSmall`]: the CMS is longer than the reserve (`needed` is its
    ///   length: prepare again with that `contents_reserve`).
    /// - [`Error::InvalidArgument`] `"the CMS's signature timestamp is not valid: …"`: an
    ///   `id-aa-signatureTimeStampToken` unsigned attribute holds a token that does not verify
    ///   over the signature value (M4 brief §3.1, §5 V7b: intact and valid).
    pub fn embed_cms(self, cms_der: &[u8]) -> Result<Vec<u8>> {
        self.try_embed_cms(cms_der).map_err(FinishError::into_error)
    }

    /// Like [`embed_cms`](Self::embed_cms), but a refused CMS gives the prepared signature back
    /// with the error, unchanged, so the caller can try again with a corrected CMS without
    /// preparing again. Every check runs before the file is touched.
    ///
    /// # Errors
    /// As [`embed_cms`](Self::embed_cms), in a [`FinishError`] that holds the prepared
    /// signature.
    pub fn try_embed_cms(mut self, cms_der: &[u8]) -> std::result::Result<Vec<u8>, FinishError> {
        let checked = self
            .validate(&RealCms)
            .and_then(|()| self.checked_cms(cms_der))
            .and_then(|der| self.embed_position(der).map(|at| (der, at)));
        match checked {
            Ok((der, at)) => Ok(self.write_der(at, der)),
            Err(error) => Err(FinishError::new(error, self)),
        }
    }

    /// The `ContentInfo` element of `cms_der` that [`embed_cms`](Self::embed_cms) embeds, after
    /// every check of the CMS (the invariants were checked before).
    ///
    /// # Errors
    /// As [`embed_cms`](Self::embed_cms), except [`Error::PlaceholderTooSmall`].
    fn checked_cms<'a>(&self, cms_der: &'a [u8]) -> Result<&'a [u8]> {
        let parsed = cms::parse(cms_der).map_err(|err| {
            Error::InvalidArgument(format!("the CMS is not a parsable ContentInfo: {err}"))
        })?;
        let der = cms_der
            .get(parsed.raw.clone())
            .ok_or_else(|| Error::InvalidArgument("the CMS is not a ContentInfo".to_owned()))?;
        let trailing = cms_der.get(parsed.raw.end..).unwrap_or_default();
        if parsed.raw.start != 0 || trailing.iter().any(|&b| b != 0) {
            return Err(Error::InvalidArgument(
                "the CMS has bytes before or after its ContentInfo element".to_owned(),
            ));
        }
        if parsed.signer_infos.len() != 1 {
            return Err(Error::InvalidArgument(format!(
                "the CMS has {} SignerInfos; a PDF signature has exactly one",
                parsed.signer_infos.len()
            )));
        }
        if parsed.econtent.is_some() {
            return Err(Error::InvalidArgument(
                "the CMS encapsulates its content; a PDF signature is detached".to_owned(),
            ));
        }

        let digest_for = |algorithm: DigestAlgorithm| Some(self.digest_for(algorithm));
        let verification = cms::verify_detached(&parsed, &digest_for, &[]);
        let has = |code: ProblemCode| verification.problems.iter().any(|p| p.code == code);
        if !verification.intact
            || has(ProblemCode::DigestMismatch)
            || has(ProblemCode::MessageDigestMissing)
        {
            return Err(Error::SignatureInvalid(
                "CMS signs different bytes: its message-digest is not the digest of the \
                 prepared byte ranges"
                    .to_owned(),
            ));
        }
        if !verification.signature_valid {
            let problems: Vec<String> = verification
                .problems
                .iter()
                .map(ToString::to_string)
                .collect();
            return Err(Error::SignatureInvalid(format!(
                "the CMS signature does not verify: {}",
                problems.join("; ")
            )));
        }
        if has(ProblemCode::WeakAlgorithm) {
            return Err(Error::InvalidArgument(
                "the CMS uses a weak digest (SHA-1); Folioxide never signs with it".to_owned(),
            ));
        }
        // EN 319 142-1 requires a DER-encoded SignedData (brief §4.3, §4.6): a BER CMS
        // (indefinite lengths, non-minimal lengths, unsorted SETs) is never labelled
        // ETSI.CAdES.detached.
        if self.sub_filter == SubFilter::EtsiCadesDetached && !is_der_cms(der, &parsed) {
            return Err(Error::InvalidArgument(
                "the CMS is not DER-encoded (indefinite or non-minimal lengths, constructed \
                 strings or unsorted SETs), so it is not PAdES baseline B-B and cannot be \
                 labelled ETSI.CAdES.detached (prepare with adbe.pkcs7.detached instead)"
                    .to_owned(),
            ));
        }
        if self.sub_filter == SubFilter::EtsiCadesDetached
            && !verification.pades_attrs.is_baseline_b()
        {
            let attrs = &verification.pades_attrs;
            let mut needs = Vec::new();
            if attrs.content_type.as_deref() != Some(oid::ID_DATA) {
                needs.push("a content-type attribute of id-data");
            }
            if attrs.signing_certificate_v2 != Some(true) {
                needs.push("a signing-certificate-v2 attribute that matches the signer");
            }
            if attrs.signing_certificate_v1.is_some() {
                needs.push("no signing-certificate (v1) attribute");
            }
            if attrs.signing_time.is_some() {
                needs.push("no signing-time attribute (PAdES puts the time in /M)");
            }
            return Err(Error::InvalidArgument(format!(
                "the CMS is not PAdES baseline B-B, so it cannot be labelled \
                 ETSI.CAdES.detached (prepare with adbe.pkcs7.detached instead); it needs {}",
                needs.join(", ")
            )));
        }
        // Signature timestamps (M4 brief §3.1): every token verifies over the signature value.
        if let [signer_info] = parsed.signer_infos.as_slice() {
            for token in cms::signature_timestamp_tokens(signer_info) {
                token_verifies(&token, &signer_info.signature).map_err(|reason| {
                    Error::InvalidArgument(format!(
                        "the CMS's signature timestamp is not valid: {reason}"
                    ))
                })?;
            }
        }
        Ok(der)
    }

    /// Writes `der` as uppercase hexadecimal digits after the `/Contents` `<` and returns the
    /// file (brief §4.2 step 7).
    ///
    /// # Errors
    /// [`Error::PlaceholderTooSmall`] when `der` is longer than the reserve.
    pub(crate) fn embed_der(self, der: &[u8]) -> Result<Vec<u8>> {
        let at = self.embed_position(der)?;
        Ok(self.write_der(at, der))
    }

    /// Where the hexadecimal digits of `der` go in the file: right after the `/Contents` `<`.
    ///
    /// # Errors
    /// [`Error::PlaceholderTooSmall`] when `der` is longer than the reserve;
    /// [`Error::InvalidArgument`] when the range is not in the file.
    pub(crate) fn embed_position(&self, der: &[u8]) -> Result<Range<usize>> {
        let reserved = self.contents_capacity();
        if der.len() > reserved {
            return Err(Error::PlaceholderTooSmall {
                needed: der.len(),
                reserved,
            });
        }
        let invalid = || Error::InvalidArgument("the /Contents range is invalid".to_owned());
        let start = usize::try_from(self.contents_range.0)
            .ok()
            .and_then(|a| a.checked_add(1))
            .ok_or_else(invalid)?;
        let end = der
            .len()
            .checked_mul(2)
            .and_then(|n| start.checked_add(n))
            .ok_or_else(invalid)?;
        if self.pdf.get(start..end).is_none() {
            return Err(invalid());
        }
        Ok(start..end)
    }

    /// Writes `der` as uppercase hexadecimal digits at `at` (from
    /// [`embed_position`](Self::embed_position), which checked it) and returns the file.
    pub(crate) fn write_der(self, at: Range<usize>, der: &[u8]) -> Vec<u8> {
        let mut pdf = self.pdf;
        if let Some(digits) = pdf.get_mut(at) {
            for (pair, &byte) in digits.chunks_exact_mut(2).zip(der) {
                if let [high, low] = pair {
                    *high = hex_digit(byte >> 4);
                    *low = hex_digit(byte & 0x0F);
                }
            }
        }
        pdf
    }
}

/// Brief §5 V7b on a signature timestamp token over `signature_value`: `Ok` when it is intact
/// and valid, else the problems as one sentence.
fn token_verifies(token: &[u8], signature_value: &[u8]) -> std::result::Result<(), String> {
    let expected = |digest: DigestAlgorithm| Some(digest.digest(&[signature_value]));
    let verification = crate::tsp::verify_token(token, &expected, &[]);
    if verification.intact && verification.valid {
        return Ok(());
    }
    let problems: Vec<String> = verification
        .problems
        .iter()
        .map(ToString::to_string)
        .collect();
    Err(if problems.is_empty() {
        "the token does not verify".to_owned()
    } else {
        problems.join("; ")
    })
}

/// Whether the `ContentInfo` of `parsed` (in `der`) is DER-encoded as a whole, as EN 319 142-1
/// requires for PAdES (brief §4.3, §4.6): definite minimal lengths, no constructed strings,
/// every universal `SET OF` sorted (X.690 §10, §11.6), and the implicitly tagged `SET OF`s too:
/// the certificates and each SignerInfo's signed and unsigned attributes. Certificates count:
/// a SignedData that carries a non-DER certificate is not DER.
///
/// The values of `id-aa-signatureTimeStampToken` unsigned attributes are opaque (M4 brief §4.3,
/// DECISIONS D13 D-12): a TSA's token is embedded verbatim, so a BER token does not make the
/// signer's CMS non-DER (the attribute around it must still be DER).
pub(crate) fn is_der_cms(der: &[u8], parsed: &cms::ParsedCms) -> bool {
    let Some(raw) = der.get(parsed.raw.clone()) else {
        return false;
    };
    let Ok(outer) = tlv::read_exact(raw, cms::MAX_DEPTH) else {
        return false;
    };
    // The token values, in `raw` coordinates.
    let base = parsed.raw.start;
    let mut opaque: Vec<Range<usize>> = Vec::new();
    for info in &parsed.signer_infos {
        let Some(start) = info.raw.start.checked_sub(base) else {
            return false;
        };
        let Ok(signer_info) = tlv::read(raw, start, raw.len(), 0, cms::MAX_DEPTH) else {
            return false;
        };
        let unsigned = tlv::children(raw, &signer_info, 0, cms::MAX_DEPTH)
            .filter_map(std::result::Result::ok)
            .find(|child| child.tag == tlv::TAG_CONTEXT_1);
        if let Some(unsigned) = unsigned {
            opaque.extend(cms::timestamp_value_ranges(raw, &unsigned, 1));
        }
    }
    if !tlv::is_der_tree_except(raw, &outer, 0, cms::MAX_DEPTH, &opaque) {
        return false;
    }
    let certificates_sorted = parsed
        .certificates
        .iter()
        .zip(parsed.certificates.iter().skip(1))
        .all(|(a, b)| tlv::der_set_order(a, b) != std::cmp::Ordering::Greater);
    let attributes_sorted = parsed.signer_infos.iter().all(|info| {
        [info.signed_attrs.as_deref(), info.unsigned_attrs.as_deref()]
            .into_iter()
            .flatten()
            .all(implicit_set_is_der)
    });
    certificates_sorted && attributes_sorted
}

/// Whether an implicitly tagged `SET OF` (`[n] IMPLICIT`) is DER, its elements sorted: checked
/// with the universal `SET` tag, which [`tlv::is_der_tree`] orders. Timestamp token values are
/// opaque, as in [`is_der_cms`].
fn implicit_set_is_der(element: &[u8]) -> bool {
    let mut retagged = element.to_vec();
    if let Some(tag) = retagged.first_mut() {
        *tag = tlv::TAG_SET;
    }
    tlv::read_exact(&retagged, cms::MAX_DEPTH).is_ok_and(|set| {
        let opaque = cms::timestamp_value_ranges(&retagged, &set, 0);
        tlv::is_der_tree_except(&retagged, &set, 0, cms::MAX_DEPTH, &opaque)
    })
}

/// The uppercase hexadecimal digit of a nibble (brief §4.2: `hex = UPPER(cms)`).
fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        10..=15 => b'A' + (nibble - 10),
        _ => b'0',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_digits_are_uppercase() {
        let digits: Vec<u8> = (0..16).map(hex_digit).collect();
        assert_eq!(digits, b"0123456789ABCDEF");
        assert_eq!(hex_digit(16), b'0');
    }
}

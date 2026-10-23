//! One-step signing with a [`Signer`]: [`sign`] and [`SignRequest`], which run
//! [`prepare`], the signer and [`finish`](PreparedSignature::finish) (M3 brief §3.2;
//! ARCHITECTURE §A.6.5).
//!
//! The signature is an invisible PAdES B-B signature (`/SubFilter /ETSI.CAdES.detached` by
//! default) in its own incremental update: the source bytes are a prefix of the output, and the
//! document's pending edits go into the same revision as the signature. The document itself is
//! not changed: open the returned bytes to keep working.
//!
//! **Sizing and retry** (brief §4.2, R-15): `prepare` computes the exact CMS size before
//! anything is signed. With the default reserve the CMS always fits. An explicit
//! [`SignatureOptions::contents_reserve`] that is too small fails in `prepare` with
//! [`Error::PlaceholderTooSmall`]; `sign` then prepares once more with exactly the size needed,
//! before the signer is asked for anything.
//!
//! **B-T** (M4 brief §3.1): with a [`Timestamper`]
//! ([`SignRequest::with_timestamper`]), `sign` budgets
//! [`DEFAULT_TSA_RESERVE`] bytes of token unless
//! [`SignatureOptions::tsa_reserve`] is set, timestamps the signature value and embeds the
//! token, retrying once with a larger reserve when the token does not fit (DECISIONS D13 D-8).
//! The signer and the timestamper may therefore each be called twice.

use std::fmt;

use folioxide_model::{Document, PdfDate};

use crate::bt::TimestampParams;
use crate::error::{Error, Result};
use crate::prepare::{PrepareRequest, PreparedSignature, SignatureOptions, prepare};
use crate::signer::Signer;
use crate::tsp::{DEFAULT_TSA_RESERVE, Timestamper};

/// The bytes added to the `needed` of a token overflow when [`sign`] prepares again (M4 brief
/// §3.1 step 4, DECISIONS D13 D-8): a second token of the same TSA may be a little longer.
pub const TSA_RETRY_MARGIN: usize = 1024;

/// What [`sign`] needs: the signer and the signature options (M3 brief §3.2), and for PAdES B-T
/// a timestamper (M4 brief §3.1).
///
/// ```
/// use folioxide_model::PdfDate;
/// use folioxide_sign::sign::SignRequest;
/// use folioxide_sign::signer::LocalSigner;
///
/// fn request(signer: &LocalSigner) -> SignRequest<'_> {
///     let time = PdfDate::parse(b"D:20261010120000Z").expect("a PDF date");
///     let request = SignRequest::new(signer, time);
///     let options = request.options.clone().with_reason(Some("Approved".into()));
///     request.with_options(options)
/// }
/// ```
#[non_exhaustive]
#[derive(Clone)]
pub struct SignRequest<'a> {
    /// The signer: its certificate chain, algorithm and key.
    pub signer: &'a dyn Signer,
    /// The signature options (field, signing time, digest, SubFilter, text entries, reserve).
    pub options: SignatureOptions,
    /// The provider of an RFC 3161 signature timestamp (PAdES B-T); `None`: no timestamp
    /// (B-B).
    pub timestamper: Option<&'a dyn Timestamper>,
    /// The parameters of the timestamp request, used with [`timestamper`](Self::timestamper).
    pub timestamp: TimestampParams,
}

impl<'a> SignRequest<'a> {
    /// A request with the default [`SignatureOptions`] for `signing_time`, without a
    /// timestamper.
    pub fn new(signer: &'a dyn Signer, signing_time: PdfDate) -> Self {
        SignRequest {
            signer,
            options: SignatureOptions::new(signing_time),
            timestamper: None,
            timestamp: TimestampParams::default(),
        }
    }

    /// Sets [`SignRequest::options`].
    #[must_use]
    pub fn with_options(mut self, options: SignatureOptions) -> Self {
        self.options = options;
        self
    }

    /// Timestamps the signature with `timestamper` and `params` (PAdES B-T): sets
    /// [`SignRequest::timestamper`] and [`SignRequest::timestamp`].
    #[must_use]
    pub fn with_timestamper(
        mut self,
        timestamper: &'a dyn Timestamper,
        params: TimestampParams,
    ) -> Self {
        self.timestamper = Some(timestamper);
        self.timestamp = params;
        self
    }

    /// The [`PrepareRequest`] for this signer and these options.
    fn prepare_request(&self, options: SignatureOptions) -> PrepareRequest {
        PrepareRequest::new(
            self.signer.certificate_chain().to_vec(),
            self.signer.algorithm(),
            options.signing_time,
        )
        .with_options(options)
    }
}

impl fmt::Debug for SignRequest<'_> {
    /// Prints the signer's key kind, the options and whether there is a timestamper, never key
    /// material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignRequest")
            .field("key_kind", &self.signer.key_kind())
            .field("certificates", &self.signer.certificate_chain().len())
            .field("options", &self.options)
            .field("timestamper", &self.timestamper.is_some())
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

/// Signs `doc` with `req.signer`: [`prepare`], then the signer over
/// [`to_be_signed`](PreparedSignature::to_be_signed), then
/// [`finish`](PreparedSignature::finish). Returns the complete signed PDF (the source, then one
/// incremental update); `doc` is not changed.
///
/// When an explicit [`SignatureOptions::contents_reserve`] is too small, `sign` prepares once
/// more with exactly the size the CMS needs (the error's `needed`), before the signer signs
/// anything.
///
/// **With a [`Timestamper`]** ([`SignRequest::with_timestamper`], PAdES B-T, M4 brief §3.1):
/// 1. `prepare` with [`DEFAULT_TSA_RESERVE`] bytes of token budget unless
///    [`SignatureOptions::tsa_reserve`] is set;
/// 2. the signer signs;
/// 3. [`timestamp_request`](PreparedSignature::timestamp_request) with
///    [`SignRequest::timestamp`], the timestamper, then
///    [`finish_with_timestamp`](PreparedSignature::finish_with_timestamp);
/// 4. when the token does not fit ([`Error::PlaceholderTooSmall`]), **once** more from step 1
///    with `contents_reserve = needed +` [`TSA_RETRY_MARGIN`] (DECISIONS D13 D-8): the signer
///    and the timestamper are then called twice.
///
/// ```
/// use folioxide_model::{Document, PdfDate};
/// use folioxide_sign::sign::{SignRequest, sign};
/// use folioxide_sign::signer::LocalSigner;
/// use folioxide_syntax::OpenOptions;
///
/// # let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pki");
/// # let key_pem = std::fs::read_to_string(root.join("signer-p256.key.pem"))?;
/// # let certs_pem = std::fs::read_to_string(root.join("signer-p256.pem"))?
/// #     + &std::fs::read_to_string(root.join("intermediate.pem"))?;
/// let signer = LocalSigner::from_pem(&key_pem, &certs_pem, None)?;
/// let source = folioxide_testkit::fixtures::syntax::minimal();
/// let doc = Document::open(source.clone(), &OpenOptions::default())?;
/// let time = PdfDate::parse(b"D:20261010120000Z").expect("a PDF date");
///
/// let signed = sign(&doc, &SignRequest::new(&signer, time))?;
/// assert!(signed.starts_with(&source));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
/// - The errors of [`prepare`] (refusals, field placement, certificate and algorithm checks).
/// - [`Error::InvalidArgument`]: the signer's [`key_kind`](Signer::key_kind) is not the key of
///   its first certificate.
/// - The errors of [`Signer::sign`].
/// - [`Error::SignatureInvalid`]: the signer's value does not verify with its certificate.
/// - With a timestamper: the errors of [`Timestamper::timestamp`],
///   [`Error::TimestampInvalid`] for a response that fails validation, and
///   [`Error::PlaceholderTooSmall`] when the token still does not fit after the retry.
pub fn sign(doc: &Document, req: &SignRequest<'_>) -> Result<Vec<u8>> {
    let Some(timestamper) = req.timestamper else {
        let prepared = prepare_with_retry(doc, req, &req.options)?;
        let signature = sign_prepared(req, &prepared)?;
        return prepared.finish_checked(&signature);
    };
    let mut options = req.options.clone();
    if options.tsa_reserve.is_none() {
        options.tsa_reserve = Some(DEFAULT_TSA_RESERVE);
    }
    match sign_timestamped(doc, req, timestamper, &options) {
        Err(Error::PlaceholderTooSmall { needed, .. }) => {
            let reserve = needed.saturating_add(TSA_RETRY_MARGIN);
            let options = options.with_contents_reserve(Some(reserve));
            sign_timestamped(doc, req, timestamper, &options)
        }
        other => other,
    }
}

/// One B-T attempt of [`sign`] with `options`.
fn sign_timestamped(
    doc: &Document,
    req: &SignRequest<'_>,
    timestamper: &dyn Timestamper,
    options: &SignatureOptions,
) -> Result<Vec<u8>> {
    let prepared = prepare_with_retry(doc, req, options)?;
    let signature = sign_prepared(req, &prepared)?;
    let request = prepared.timestamp_request(&signature, &req.timestamp)?;
    let response = timestamper.timestamp(&request)?;
    prepared.finish_with_timestamp_checked(&signature, &request, &response)
}

/// The signer's value over the prepared bytes, after checking that its key is the
/// certificate's.
fn sign_prepared(req: &SignRequest<'_>, prepared: &PreparedSignature) -> Result<Vec<u8>> {
    if req.signer.key_kind() != prepared.key_kind() {
        return Err(Error::InvalidArgument(format!(
            "the signer has a {:?} key, but its certificate has a {:?} key",
            req.signer.key_kind(),
            prepared.key_kind()
        )));
    }
    req.signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
}

/// [`prepare`] with `options`, retried once with exactly `needed` bytes when an explicit
/// reserve was too small.
fn prepare_with_retry(
    doc: &Document,
    req: &SignRequest<'_>,
    options: &SignatureOptions,
) -> Result<PreparedSignature> {
    match prepare(doc, &req.prepare_request(options.clone())) {
        Err(Error::PlaceholderTooSmall { needed, .. }) if options.contents_reserve.is_some() => {
            let options = options.clone().with_contents_reserve(Some(needed));
            prepare(doc, &req.prepare_request(options))
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::{DigestAlgorithm, KeyKind, SignatureAlgorithm};

    struct NoSigner;

    impl Signer for NoSigner {
        fn certificate_chain(&self) -> &[Vec<u8>] {
            &[]
        }
        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::Ecdsa
        }
        fn key_kind(&self) -> KeyKind {
            KeyKind::EcP256
        }
        fn sign(&self, _: DigestAlgorithm, _: &[u8]) -> Result<Vec<u8>> {
            Err(Error::Crypto("never called".into()))
        }
    }

    #[test]
    fn request_builders_and_debug() {
        let time = PdfDate::parse(b"D:20261010120000Z").unwrap();
        let request = SignRequest::new(&NoSigner, time);
        assert_eq!(request.options, SignatureOptions::new(time));
        let request =
            request.with_options(SignatureOptions::new(time).with_reason(Some("R".into())));
        assert_eq!(request.options.reason.as_deref(), Some("R"));
        let debug = format!("{request:?}");
        assert!(
            debug.contains("SignRequest") && debug.contains("EcP256"),
            "{debug}"
        );
        let prepare = request.prepare_request(request.options.clone());
        assert_eq!(prepare.algorithm, SignatureAlgorithm::Ecdsa);
        assert_eq!(prepare.options.signing_time, time);
        assert!(prepare.chain_der.is_empty());
    }

    #[test]
    fn timestamper_builder() {
        let time = PdfDate::parse(b"D:20261010120000Z").unwrap();
        let tsa = |_: &[u8]| -> Result<Vec<u8>> { Err(Error::Crypto("never called".into())) };
        let request = SignRequest::new(&NoSigner, time);
        assert!(request.timestamper.is_none());
        assert_eq!(request.timestamp, TimestampParams::default());
        let params = TimestampParams::new().with_nonce(Some(1));
        let request = request.with_timestamper(&tsa, params.clone());
        assert!(request.timestamper.is_some());
        assert_eq!(request.timestamp, params);
        let debug = format!("{request:?}");
        assert!(debug.contains("timestamper: true"), "{debug}");

        // The empty chain fails in prepare, before the signer or the TSA is called.
        let doc = Document::open(
            folioxide_testkit::fixtures::syntax::minimal(),
            &folioxide_syntax::OpenOptions::default(),
        )
        .unwrap();
        let err = sign(&doc, &request).unwrap_err();
        assert_eq!(err.code(), folioxide_syntax::ErrorCode::InvalidArgument);
    }

    #[test]
    fn an_empty_chain_fails_before_signing() {
        let doc = Document::open(
            folioxide_testkit::fixtures::syntax::minimal(),
            &folioxide_syntax::OpenOptions::default(),
        )
        .unwrap();
        let time = PdfDate::parse(b"D:20261010120000Z").unwrap();
        let err = sign(&doc, &SignRequest::new(&NoSigner, time)).unwrap_err();
        assert_eq!(err.code(), folioxide_syntax::ErrorCode::InvalidArgument);
    }
}

//! PAdES B-T: signing with an RFC 3161 signature timestamp (M4 brief §3.1, §4.2–§4.5;
//! ARCHITECTURE §A.6.4 and §A.6.5).
//!
//! The two-phase flow, for hosts whose TSA call is asynchronous (Node) or remote:
//!
//! ```text
//! prepared = prepare(doc, req { tsa_reserve })        // FXPS v1, unchanged
//! sig = signer(to_be_signed)
//! req_der = prepared.timestamp_request(sig, params)   // verify_and_normalize(sig) first;
//!                                                     // imprint = H(normalized value)
//! resp = TSA(req_der)                                 // the host: an HTTP POST of
//!                                                     // application/timestamp-query
//! pdf = prepared.finish_with_timestamp(sig, req_der, resp)
//! ```
//!
//! [`PreparedSignature`] stays stateless: the caller keeps `req_der` between the calls, and
//! [`finish_with_timestamp`](PreparedSignature::finish_with_timestamp) checks that it is this
//! signature's request and that the response answers it. The one-step
//! [`sign`](crate::sign::sign) does the same with a [`Timestamper`](crate::tsp::Timestamper)
//! ([`SignRequest::with_timestamper`](crate::sign::SignRequest::with_timestamper)).
//!
//! **What `finish_with_timestamp` checks** (M4 brief §4.2), before anything is written: the
//! signature value as [`finish`](PreparedSignature::finish) does; the response with
//! [`validate_response`](crate::tsp::validate_response) against the request (steps 1–8); that
//! the request is this signature's (step 9: it parses, `certReq` is true, its imprint is the
//! digest of the normalized signature value); and the assembled CMS as a verifier will, the
//! token included (M4 brief §5 V7b). A CMS longer than the reserve gives
//! [`Error::PlaceholderTooSmall`] with the length needed.
//!
//! ```
//! use folioxide_model::{Document, PdfDate};
//! use folioxide_sign::bt::TimestampParams;
//! use folioxide_sign::prepare::{PrepareRequest, prepare};
//! use folioxide_sign::signer::{LocalSigner, Signer};
//! use folioxide_sign::tsp::TimeStampReq;
//! use folioxide_syntax::OpenOptions;
//!
//! # let pki = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pki");
//! # let p12 = std::fs::read(pki.join("signer-p256-modern.p12"))?;
//! let signer = LocalSigner::from_pkcs12(&p12, "folioxide")?;
//! let doc = Document::open(
//!     folioxide_testkit::fixtures::syntax::minimal(),
//!     &OpenOptions::default(),
//! )?;
//! let time = PdfDate::parse(b"D:20261010120000Z").expect("a PDF date");
//! let request = PrepareRequest::new(signer.certificate_chain().to_vec(), signer.algorithm(), time);
//! let prepared = prepare(&doc, &request.clone().with_options(
//!     request.options.clone().with_tsa_reserve(Some(8192)),
//! ))?;
//!
//! let value = signer.sign(prepared.digest_algorithm(), prepared.to_be_signed())?;
//! let params = TimestampParams::new().with_nonce(Some(42));
//! let request_der = prepared.timestamp_request(&value, &params)?;
//! let tsq = TimeStampReq::from_der(&request_der)?;
//! assert!(tsq.cert_req);
//! assert_eq!(tsq.nonce.as_deref(), Some(&[42][..]));
//! // The host sends request_der to its TSA, then calls
//! // prepared.finish_with_timestamp(&value, &request_der, &response_der).
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::algorithms::DigestAlgorithm;
use crate::cms;
use crate::error::{Error, Result};
use crate::finish::FinishError;
use crate::prepare::{PreparedSignature, RealCms};
use crate::tsp::{self, MessageImprint, TimeStampReq};

/// The parameters of a signature timestamp request (M4 brief §3.1).
///
/// With the `serde` feature the fields are `digest`, `policy` and `nonce`, all optional.
///
/// ```
/// use folioxide_sign::algorithms::DigestAlgorithm;
/// use folioxide_sign::bt::TimestampParams;
///
/// let params = TimestampParams::new()
///     .with_digest(Some(DigestAlgorithm::Sha384))
///     .with_nonce(Some(0x0102_0304_0506_0708));
/// assert_eq!(params.policy, None);
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase", default)
)]
pub struct TimestampParams {
    /// The imprint's digest algorithm; `None`: the signature's digest algorithm (DECISIONS D13
    /// D-11).
    pub digest: Option<DigestAlgorithm>,
    /// `reqPolicy`, a dotted OID; `None`: the TSA's default policy.
    pub policy: Option<String>,
    /// The request nonce, from 1 to 2^64 - 1 (brief §4.1: a positive INTEGER; 0 is refused);
    /// `None`: a random nonce from the operating-system RNG
    /// ([`random_nonce`](crate::tsp::random_nonce), feature `sys-rng`), or
    /// [`Error::InvalidArgument`] without that feature (DECISIONS
    /// D13 D-10).
    pub nonce: Option<u64>,
}

impl TimestampParams {
    /// The default parameters: the signature's digest, the TSA's policy, a random nonce.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`TimestampParams::digest`].
    #[must_use]
    pub fn with_digest(mut self, digest: Option<DigestAlgorithm>) -> Self {
        self.digest = digest;
        self
    }

    /// Sets [`TimestampParams::policy`].
    #[must_use]
    pub fn with_policy(mut self, policy: Option<String>) -> Self {
        self.policy = policy;
        self
    }

    /// Sets [`TimestampParams::nonce`].
    #[must_use]
    pub fn with_nonce(mut self, nonce: Option<u64>) -> Self {
        self.nonce = nonce;
        self
    }
}

impl PreparedSignature {
    /// Verifies and normalizes `signature` exactly as [`finish`](Self::finish) does, then
    /// returns the DER `TimeStampReq` over `H(normalized signature value)` (M4 brief §4.5): an
    /// ECDSA value given as IEEE P1363 is timestamped as the DER value that is embedded.
    ///
    /// The request has `certReq` true, the nonce of `params` (or a random one), the policy of
    /// `params`, and the imprint digest of `params` (default: the signature's digest; SHA-1 is
    /// refused). The prepared signature is not changed: keep the request for
    /// [`finish_with_timestamp`](Self::finish_with_timestamp).
    ///
    /// # Errors
    /// The errors of [`finish`](Self::finish) for the signature value;
    /// [`Error::InvalidArgument`] for a policy that is not a dotted OID, a SHA-1 imprint, a
    /// nonce of 0, or a missing nonce without the `sys-rng` feature; [`Error::Crypto`] when the
    /// RNG fails.
    pub fn timestamp_request(&self, signature: &[u8], params: &TimestampParams) -> Result<Vec<u8>> {
        let value = self.normalized_signature(signature)?;
        let digest = params.digest.unwrap_or(self.digest);
        if digest.is_weak() {
            return Err(Error::InvalidArgument(format!(
                "{digest} is not allowed for a timestamp imprint; use sha256, sha384 or sha512"
            )));
        }
        if let Some(policy) = &params.policy
            && const_oid::ObjectIdentifier::new(policy).is_err()
        {
            return Err(Error::InvalidArgument(format!(
                "the timestamp policy {policy:?} is not a dotted OID"
            )));
        }
        let nonce = match params.nonce {
            // Brief §4.1: the nonce is a positive INTEGER (manager ruling R-24).
            Some(0) => {
                return Err(Error::InvalidArgument(
                    "the timestamp nonce must be positive: from 1 to 2^64 - 1".to_owned(),
                ));
            }
            Some(nonce) => nonce,
            None => default_nonce()?,
        };
        let imprint = MessageImprint::new(digest, digest.digest(&[&value]));
        Ok(TimeStampReq::new(imprint, Some(nonce), params.policy.clone()).to_der())
    }

    /// [`finish`](Self::finish) with a signature timestamp: validates `response_der` against
    /// `request_der` ([`validate_response`](crate::tsp::validate_response), M4 brief §4.2),
    /// checks that `request_der` is this signature's request (it parses, `certReq` is true and
    /// its imprint is the digest of the normalized signature value), embeds the token as the
    /// unsigned attribute `id-aa-signatureTimeStampToken`
    /// ([`assemble_with_timestamp`](crate::cms::assemble_with_timestamp)) and checks the result
    /// before writing it. Returns the complete signed PDF.
    ///
    /// # Errors
    /// The errors of [`finish`](Self::finish);
    /// [`Error::TimestampInvalid`] for a response or request that fails a check;
    /// [`Error::PlaceholderTooSmall`] when the CMS with the token does not fit (prepare again
    /// with `contents_reserve` at least `needed`).
    pub fn finish_with_timestamp(
        self,
        signature: &[u8],
        request_der: &[u8],
        response_der: &[u8],
    ) -> Result<Vec<u8>> {
        self.try_finish_with_timestamp(signature, request_der, response_der)
            .map_err(FinishError::into_error)
    }

    /// [`finish_with_timestamp`](Self::finish_with_timestamp), giving the prepared signature
    /// back with the error ([`FinishError`]) so a caller can try again with another value or
    /// response without preparing again. Every check runs before the file is touched.
    ///
    /// # Errors
    /// As [`finish_with_timestamp`](Self::finish_with_timestamp), with the prepared signature.
    pub fn try_finish_with_timestamp(
        mut self,
        signature: &[u8],
        request_der: &[u8],
        response_der: &[u8],
    ) -> std::result::Result<Vec<u8>, FinishError> {
        let checked = self
            .validate(&RealCms)
            .and_then(|()| self.timestamped_cms(signature, request_der, response_der))
            .and_then(|der| self.embed_position(&der).map(|at| (der, at)));
        match checked {
            Ok((der, at)) => Ok(self.write_der(at, &der)),
            Err(error) => Err(FinishError::new(error, self)),
        }
    }

    /// [`finish_with_timestamp`](Self::finish_with_timestamp) without re-checking the
    /// invariants: for a prepared signature that [`prepare`](crate::prepare::prepare) has just
    /// built ([`sign`](crate::sign::sign)).
    pub(crate) fn finish_with_timestamp_checked(
        self,
        signature: &[u8],
        request_der: &[u8],
        response_der: &[u8],
    ) -> Result<Vec<u8>> {
        let der = self.timestamped_cms(signature, request_der, response_der)?;
        self.embed_der(&der)
    }

    /// The CMS with the signature timestamp (brief §4.2 steps 1–9, §4.3), checked as a
    /// verifier will.
    fn timestamped_cms(
        &self,
        signature: &[u8],
        request_der: &[u8],
        response_der: &[u8],
    ) -> Result<Vec<u8>> {
        let value = self.normalized_signature(signature)?;
        let request = TimeStampReq::from_der(request_der).map_err(|err| {
            Error::TimestampInvalid(format!("the timestamp request does not parse: {err}"))
        })?;
        // Steps 1–8: the response answers the request.
        let validated = tsp::validate_response(&request, response_der)?;
        // Step 9: the request is this signature's.
        if !request.cert_req {
            return Err(Error::TimestampInvalid(
                "the timestamp request does not ask for the TSA certificate (certReq is false)"
                    .to_owned(),
            ));
        }
        let digest = request.imprint.digest;
        if digest.is_weak() {
            return Err(Error::TimestampInvalid(format!(
                "the timestamp request's imprint uses {digest}, a weak algorithm"
            )));
        }
        if request.imprint.hashed_message != digest.digest(&[&value]) {
            return Err(Error::TimestampInvalid(
                "the timestamp request is not this signature's request: its imprint is not the \
                 digest of the signature value"
                    .to_owned(),
            ));
        }
        let der = cms::assemble_with_timestamp(
            &self.signed_attrs_der,
            &value,
            &self.chain_der,
            self.algorithm,
            self.key_kind,
            self.digest,
            &validated.token_der,
        )?;
        self.check_assembled(&der, Some(&validated.token_der))?;
        Ok(der)
    }
}

/// The nonce of a request whose parameters give none (DECISIONS D13 D-10): random with the
/// `sys-rng` feature, else refused.
fn default_nonce() -> Result<u64> {
    #[cfg(feature = "sys-rng")]
    {
        tsp::random_nonce()
    }
    #[cfg(not(feature = "sys-rng"))]
    {
        Err(Error::InvalidArgument(
            "a timestamp request needs a nonce: set TimestampParams::nonce (the sys-rng feature, \
             which draws one, is off)"
                .to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use folioxide_model::{Document, PdfDate};
    use folioxide_syntax::OpenOptions;

    use super::*;
    use crate::algorithms::SignatureAlgorithm;
    use crate::prepare::test_double::{FakeCms, P256_CERT};
    use crate::prepare::{PrepareRequest, prepare_with};

    fn prepared() -> PreparedSignature {
        let doc = Document::open(
            folioxide_testkit::fixtures::syntax::minimal(),
            &OpenOptions::default(),
        )
        .unwrap();
        let time = PdfDate::parse(b"D:20261010120000Z").unwrap();
        let req = PrepareRequest::new(vec![P256_CERT.to_vec()], SignatureAlgorithm::Ecdsa, time);
        prepare_with(&doc, &req, &FakeCms).unwrap()
    }

    #[test]
    fn params_builders() {
        let params = TimestampParams::new()
            .with_digest(Some(DigestAlgorithm::Sha512))
            .with_policy(Some("1.2.3.4.1".into()))
            .with_nonce(Some(7));
        assert_eq!(params.digest, Some(DigestAlgorithm::Sha512));
        assert_eq!(params.policy.as_deref(), Some("1.2.3.4.1"));
        assert_eq!(params.nonce, Some(7));
        assert_eq!(TimestampParams::new(), TimestampParams::default());
    }

    #[test]
    fn requests_need_a_valid_value_and_policy() {
        let p = prepared();
        // FakeCms prepares with a fake certificate, which the real verification refuses.
        let err = p
            .timestamp_request(&[0; 64], &TimestampParams::default())
            .unwrap_err();
        assert_eq!(
            err.code(),
            folioxide_syntax::ErrorCode::Certificate,
            "{err}"
        );
        let (err, back) = p
            .clone()
            .try_finish_with_timestamp(&[0; 64], &[], &[])
            .unwrap_err()
            .into_parts();
        assert!(!err.to_string().is_empty());
        assert_eq!(back, p);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn params_serde() {
        let params = TimestampParams::new().with_nonce(Some(1));
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"digest": null, "policy": null, "nonce": 1})
        );
        let back: TimestampParams =
            serde_json::from_value(serde_json::json!({"nonce": 1})).unwrap();
        assert_eq!(back, params);
    }
}

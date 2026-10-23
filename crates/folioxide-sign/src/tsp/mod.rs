//! RFC 3161 timestamps (Time-Stamp Protocol), with RFC 5816 ESSCertIDv2: Folioxide's own DER
//! types for requests, responses and tokens, response validation and token verification (M4
//! brief §3.1, §4.1, §4.2 and §5 V7b; ARCHITECTURE §A.6.4).
//!
//! - **Requesting.** [`TimeStampReq`] is the request (`certReq` true, a nonce, no extensions);
//!   [`TimeStampReq::to_der`] writes it exactly as `openssl ts -query -cert` does. A
//!   [`Timestamper`] sends it to a TSA and returns the DER [`TimeStampResp`]. The core has no
//!   network I/O: hosts implement [`Timestamper`] (or use the two-phase flow of
//!   [`bt`](crate::bt) for async hosts).
//! - **Validating a response** ([`validate_response`], signing side): the ordered checks of
//!   brief §4.2, each failure an [`Error::TimestampInvalid`](crate::Error::TimestampInvalid)
//!   naming the check.
//! - **Verifying a token** ([`verify_token`], verification side): never fails, never panics;
//!   every defect is a [`Problem`] in the [`TokenVerification`].
//!
//! `genTime` is parsed by [`GenTime::parse`], never by `der::asn1::GeneralizedTime`, which
//! rejects fractional seconds (brief R-3).
//!
//! **Parsing** uses the bounded BER/DER reader of the CMS code: the depth is at most
//! [`MAX_DEPTH`](crate::cms::MAX_DEPTH), the certificate and attribute counts are those of
//! [`cms::parse`](crate::cms::parse), every slice is bounds-checked, and every defect is an
//! error or a problem, never a panic (brief R-19).
//!
//! ```
//! use folioxide_sign::algorithms::DigestAlgorithm;
//! use folioxide_sign::tsp::{MessageImprint, TimeStampReq};
//!
//! let digest = DigestAlgorithm::Sha256;
//! let imprint = MessageImprint::new(digest, digest.digest(&[b"signature value"]));
//! let request = TimeStampReq::new(imprint, Some(0x0102_0304_0506_0708), None);
//! assert!(request.cert_req);
//! assert_eq!(request.nonce.as_deref(), Some(&[1, 2, 3, 4, 5, 6, 7, 8][..]));
//! let der = request.to_der();
//! assert_eq!(der[0], 0x30);
//! assert_eq!(der.len(), 69);
//! ```

use const_oid::ObjectIdentifier;

use crate::algorithms::DigestAlgorithm;
use crate::cms::tlv;
use crate::error::Result;
use crate::problem::Problem;

mod check;
pub(crate) mod parse;
pub(crate) mod shape;

/// `id-ct-TSTInfo` (RFC 3161 §2.4.2): the eContentType of a timestamp token.
pub const OID_CT_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

/// `id-aa-signatureTimeStampToken` (RFC 3161 Appendix A): the unsigned attribute of a
/// SignerInfo that holds a timestamp token over its signature value.
pub const OID_AA_SIGNATURE_TIME_STAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";

/// `id-kp-timeStamping` (RFC 3161 §2.3): the only extended key usage a TSA certificate may
/// have, and it must be critical.
pub const OID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";

/// The bytes of timestamp token budgeted in `/Contents` when signing with a timestamper and no
/// explicit [`tsa_reserve`](crate::prepare::SignatureOptions::tsa_reserve) (DECISIONS D13
/// D-8). The OpenSSL test token with two RSA certificates is 3131 bytes, so this leaves room for
/// TSA chains of about three certificates (brief R-5).
pub const DEFAULT_TSA_RESERVE: usize = 8192;

/// The most signature timestamp tokens verified per SignerInfo; more get a warning (brief §5
/// V7b, R-19).
pub const MAX_TIMESTAMP_TOKENS: usize = 8;

/// The `messageImprint` of a request or a TSTInfo (RFC 3161 §2.4.1): the hash algorithm and the
/// hash of the timestamped data.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageImprint {
    /// The hash algorithm.
    pub digest: DigestAlgorithm,
    /// The hash of the timestamped data (for a signature timestamp, of the signature value's
    /// OCTET STRING contents).
    pub hashed_message: Vec<u8>,
}

impl MessageImprint {
    /// The imprint `hashed_message` made with `digest`.
    pub fn new(digest: DigestAlgorithm, hashed_message: Vec<u8>) -> MessageImprint {
        MessageImprint {
            digest,
            hashed_message,
        }
    }
}

/// An RFC 3161 `TimeStampReq` (§2.4.1): version 1, no extensions.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeStampReq {
    /// What is timestamped.
    pub imprint: MessageImprint,
    /// `reqPolicy`, a dotted OID; `None`: the TSA's default policy.
    pub policy: Option<String>,
    /// The nonce as the content octets of a minimal, positive DER INTEGER (a leading `0x00`
    /// when the top bit is set); `None`: no nonce.
    pub nonce: Option<Vec<u8>>,
    /// `certReq`: whether the TSA must include its certificate in the token.
    pub cert_req: bool,
}

impl TimeStampReq {
    /// A request for `imprint` with `cert_req = true`, `nonce` as a positive INTEGER (a leading
    /// `0x00` when its top bit is set) and the optional `policy` (a dotted OID).
    ///
    /// ```
    /// use folioxide_sign::algorithms::DigestAlgorithm;
    /// use folioxide_sign::tsp::{MessageImprint, TimeStampReq};
    ///
    /// let imprint = MessageImprint::new(DigestAlgorithm::Sha256, vec![0; 32]);
    /// let request = TimeStampReq::new(imprint, Some(0x8000_0000_0000_0000), None);
    /// assert_eq!(request.nonce.as_deref(), Some(&[0, 0x80, 0, 0, 0, 0, 0, 0, 0][..]));
    /// ```
    pub fn new(
        imprint: MessageImprint,
        nonce: Option<u64>,
        policy: Option<String>,
    ) -> TimeStampReq {
        TimeStampReq {
            imprint,
            policy,
            nonce: nonce.map(positive_integer_octets),
            cert_req: true,
        }
    }

    /// The DER `TimeStampReq` (brief §4.1, DECISIONS D13 D-11): `version` 1, `messageImprint`
    /// with `hashAlgorithm` `{OID, NULL}` (as `openssl ts -query` writes it), `reqPolicy` when
    /// set, `nonce` when set, and `certReq` written explicitly as `01 01 FF` when true (DER
    /// omits a DEFAULT only when the value equals it). No extensions.
    ///
    /// A `policy` that is not a dotted OID is written as an empty OID (`06 00`), which every
    /// TSA refuses; [`PreparedSignature::timestamp_request`](crate::prepare::PreparedSignature::timestamp_request)
    /// refuses such a policy before writing a request.
    pub fn to_der(&self) -> Vec<u8> {
        let algorithm = tlv::tlv_parts(
            tlv::TAG_SEQUENCE,
            &[
                &tlv::tlv(tlv::TAG_OID, &oid_content(self.imprint.digest.oid())),
                &[tlv::TAG_NULL, 0x00],
            ],
        );
        let imprint = tlv::tlv_parts(
            tlv::TAG_SEQUENCE,
            &[
                &algorithm,
                &tlv::tlv(tlv::TAG_OCTET_STRING, &self.imprint.hashed_message),
            ],
        );
        let mut content = tlv::tlv(tlv::TAG_INTEGER, &[1]);
        content.extend_from_slice(&imprint);
        if let Some(policy) = &self.policy {
            tlv::push_tlv(&mut content, tlv::TAG_OID, &oid_content(policy));
        }
        if let Some(nonce) = &self.nonce {
            tlv::push_tlv(&mut content, tlv::TAG_INTEGER, nonce);
        }
        if self.cert_req {
            content.extend_from_slice(&[TAG_BOOLEAN, 0x01, 0xFF]);
        }
        tlv::tlv(tlv::TAG_SEQUENCE, &content)
    }

    /// Reads a DER `TimeStampReq`, strictly (Folioxide wrote it): one DER element, version 1,
    /// a hash algorithm Folioxide implements with absent or `NULL` parameters and a hash of its
    /// length, an optional policy, an optional minimal non-negative nonce, `certReq` written
    /// only as `TRUE`, and no extensions.
    ///
    /// ```
    /// use folioxide_sign::algorithms::DigestAlgorithm;
    /// use folioxide_sign::tsp::{MessageImprint, TimeStampReq};
    ///
    /// let imprint = MessageImprint::new(DigestAlgorithm::Sha256, vec![7; 32]);
    /// let request = TimeStampReq::new(imprint, Some(42), Some("1.2.3.4.1".into()));
    /// assert_eq!(TimeStampReq::from_der(&request.to_der())?, request);
    /// assert!(TimeStampReq::from_der(b"not a request").is_err());
    /// # Ok::<(), folioxide_sign::Error>(())
    /// ```
    ///
    /// # Errors
    /// [`Error::TimestampInvalid`](crate::Error::TimestampInvalid) when the bytes are not a
    /// version-1 request in DER.
    pub fn from_der(der: &[u8]) -> Result<TimeStampReq> {
        parse::request(der)
    }
}

/// `PKIStatus` (RFC 3161 §2.4.2).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PkiStatus {
    /// `granted` (0): a token is present.
    Granted,
    /// `grantedWithMods` (1): a token is present, with modifications the TSA chose (accepted,
    /// DECISIONS D13 D-9).
    GrantedWithMods,
    /// `rejection` (2).
    Rejection,
    /// `waiting` (3).
    Waiting,
    /// `revocationWarning` (4).
    RevocationWarning,
    /// `revocationNotification` (5).
    RevocationNotification,
    /// Any other value.
    Unknown(i64),
}

/// `PKIStatusInfo` (RFC 3161 §2.4.2): the status, its free text and the failure bits.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PkiStatusInfo {
    /// The status.
    pub status: PkiStatus,
    /// `statusString`: each `UTF8String` of the `PKIFreeText`, in order.
    pub status_string: Vec<String>,
    /// `failInfo`: bit `i` set when `PKIFailureInfo` bit `i` is (`badAlg` 0, `badRequest` 2,
    /// `badDataFormat` 5, `timeNotAvailable` 14, `unacceptedPolicy` 15, `unacceptedExtension`
    /// 16, `addInfoNotAvailable` 17, `systemFailure` 25).
    pub fail_info: Option<u32>,
}

/// A `TimeStampResp` (RFC 3161 §2.4.2).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeStampResp {
    /// The status.
    pub status: PkiStatusInfo,
    /// The `timeStampToken` ContentInfo, raw bytes exactly as received (never re-encoded).
    pub token: Option<Vec<u8>>,
}

impl TimeStampResp {
    /// Reads a BER or DER `TimeStampResp`: the status, its free text (at most 16 strings,
    /// decoded as UTF-8 with replacement characters), the failure bits, and the token's
    /// ContentInfo exactly as received. Nothing about the token is checked here (see
    /// [`validate_response`]).
    ///
    /// ```
    /// use folioxide_sign::tsp::{PkiStatus, TimeStampResp};
    ///
    /// // SEQUENCE { PKIStatusInfo { INTEGER 2, PKIFreeText { "busy" }, failInfo badAlg } }
    /// let der = [
    ///     0x30, 0x11, 0x30, 0x0F, 0x02, 0x01, 0x02, 0x30, 0x06, 0x0C, 0x04, b'b', b'u', b's',
    ///     b'y', 0x03, 0x02, 0x07, 0x80,
    /// ];
    /// let response = TimeStampResp::from_der(&der)?;
    /// assert_eq!(response.status.status, PkiStatus::Rejection);
    /// assert_eq!(response.status.status_string, ["busy"]);
    /// assert_eq!(response.status.fail_info, Some(1));
    /// assert_eq!(response.token, None);
    /// # Ok::<(), folioxide_sign::Error>(())
    /// ```
    ///
    /// # Errors
    /// [`Error::TimestampInvalid`](crate::Error::TimestampInvalid) when the bytes are not a
    /// `TimeStampResp`.
    pub fn from_der(der: &[u8]) -> Result<TimeStampResp> {
        parse::response(der)
    }
}

/// A TSTInfo `genTime` (RFC 3161 §2.4.2): `YYYYMMDDhhmmss[.f{1,9}]Z`, in UTC.
///
/// Ordered by instant (then by the number of fraction digits written).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GenTime {
    /// Whole seconds since 1970-01-01T00:00:00Z (POSIX time, no leap seconds).
    pub unix_seconds: i64,
    /// The fraction of the second, in nanoseconds (below 1,000,000,000).
    pub nanos: u32,
    /// How many fraction digits the token wrote (0–9), kept for display.
    pub fraction_digits: u8,
}

impl GenTime {
    /// Parses the content octets of a `GeneralizedTime` in the RFC 3161 form
    /// `YYYYMMDDhhmmss[.f{1,9}]Z` (brief §4.1): the dot is required before a fraction, and the
    /// time ends in `Z`. A fraction with trailing zeros is accepted
    /// ([`has_trailing_zeros`](Self::has_trailing_zeros) tells, and the verifiers warn).
    ///
    /// ```
    /// use folioxide_sign::tsp::GenTime;
    ///
    /// let time = GenTime::parse(b"20261011035141.825589Z")?;
    /// assert_eq!(time.to_rfc3339(), "2026-10-11T03:51:41.825589Z");
    /// assert_eq!((time.nanos, time.fraction_digits), (825_589_000, 6));
    /// assert!(GenTime::parse(b"20261011035141+0200").is_err());
    /// # Ok::<(), folioxide_sign::Error>(())
    /// ```
    ///
    /// # Errors
    /// [`Error::TimestampInvalid`](crate::Error::TimestampInvalid) for another form (a time
    /// zone offset, no `Z`, seconds above 59, no such date, more than nine fraction digits).
    pub fn parse(generalized_time: &[u8]) -> Result<GenTime> {
        parse::gen_time(generalized_time)
    }

    /// Whether the fraction ends in a zero digit, which RFC 3161 §2.4.2 forbids ("MUST NOT
    /// include trailing zeros"); Folioxide accepts it with a warning.
    pub fn has_trailing_zeros(&self) -> bool {
        let digits = u32::from(self.fraction_digits.min(9));
        digits > 0 && (self.nanos / 10u32.pow(9 - digits)).is_multiple_of(10)
    }

    /// The whole second of `genTime` as a [`UnixTime`](crate::x509info::UnixTime).
    pub fn unix_time(&self) -> crate::x509info::UnixTime {
        crate::x509info::UnixTime(self.unix_seconds)
    }

    /// The time as RFC 3339 UTC with [`fraction_digits`](Self::fraction_digits) fraction
    /// digits, for example `2026-10-11T03:51:41.825589Z`.
    pub fn to_rfc3339(&self) -> String {
        let days = self.unix_seconds.div_euclid(86_400);
        let second_of_day = self.unix_seconds.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        let mut text = format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
            second_of_day / 3600,
            second_of_day % 3600 / 60,
            second_of_day % 60
        );
        let digits = u32::from(self.fraction_digits.min(9));
        if digits > 0 {
            let nanos = self.nanos.min(999_999_999);
            let fraction = nanos / 10u32.pow(9 - digits);
            text.push_str(&format!(".{fraction:0width$}", width = digits as usize));
        }
        text.push('Z');
        text
    }
}

/// `Accuracy` (RFC 3161 §2.4.2): the deviation of `genTime` around the UTC time.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accuracy {
    /// Whole seconds.
    pub seconds: Option<u64>,
    /// Milliseconds, 1–999.
    pub millis: Option<u16>,
    /// Microseconds, 1–999.
    pub micros: Option<u16>,
}

/// A `TSTInfo` (RFC 3161 §2.4.2): what the TSA signed.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TstInfo {
    /// `version`; 1 for every token Folioxide accepts.
    pub version: u32,
    /// The TSA policy, a dotted OID.
    pub policy: String,
    /// What was timestamped.
    pub imprint: MessageImprint,
    /// `serialNumber`: the content octets of the INTEGER.
    pub serial: Vec<u8>,
    /// `genTime`.
    pub gen_time: GenTime,
    /// `accuracy`, when present.
    pub accuracy: Option<Accuracy>,
    /// `ordering`.
    pub ordering: bool,
    /// `nonce`: the content octets of the INTEGER, when present.
    pub nonce: Option<Vec<u8>>,
    /// `tsa` as RFC 4514 text when it is a `directoryName`; `None` otherwise (another
    /// `GeneralName` gives a warning).
    pub tsa_name: Option<String>,
    /// Whether `extensions` is present (a non-empty list of well-formed `Extension`s, else the
    /// TSTInfo does not decode; none is interpreted).
    pub has_extensions: bool,
}

impl TstInfo {
    /// Decodes a BER or DER `TSTInfo` (the eContent octets of a token). Any version is
    /// returned (verifiers require 1); `genTime` is read with [`GenTime::parse`]; `tsa` is
    /// returned as RFC 4514 text when it is a `directoryName`.
    ///
    /// # Errors
    /// [`Error::TimestampInvalid`](crate::Error::TimestampInvalid) when the bytes are not a
    /// `TSTInfo`, or its imprint algorithm is not one Folioxide implements.
    pub fn from_der(der: &[u8]) -> Result<TstInfo> {
        let raw = parse::tst_info(der)?;
        raw.to_tst_info().ok_or_else(|| {
            crate::Error::TimestampInvalid(format!(
                "the TSTInfo imprint algorithm {} is not supported",
                raw.imprint_algorithm.oid
            ))
        })
    }
}

/// The provider of timestamps: sends a DER `TimeStampReq` to a TSA and returns the DER
/// `TimeStampResp` it answered (RFC 3161 §3.4: an HTTP POST of `application/timestamp-query`,
/// answered with `application/timestamp-reply`).
///
/// It is synchronous, and **there is no network in the core**: hosts implement it (a Tauri app
/// with an HTTP client, a test with a mock TSA). Async hosts such as Node use the two-phase flow
/// instead ([`PreparedSignature::timestamp_request`](crate::prepare::PreparedSignature::timestamp_request)
/// and [`PreparedSignature::finish_with_timestamp`](crate::prepare::PreparedSignature::finish_with_timestamp)).
///
/// **Transport failures** are reported as
/// [`Error::TimestampInvalid`](crate::Error::TimestampInvalid)`("TSA request failed: …")`. The
/// response itself is validated by the caller ([`validate_response`]), so an implementation
/// returns whatever the TSA sent.
///
/// Any `Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync` closure is a `Timestamper`.
pub trait Timestamper: Send + Sync {
    /// Sends `request_der` to the TSA and returns its DER `TimeStampResp`.
    ///
    /// # Errors
    /// [`Error::TimestampInvalid`](crate::Error::TimestampInvalid)`("TSA request failed: …")`
    /// when the TSA cannot be reached or answers with a transport error.
    fn timestamp(&self, request_der: &[u8]) -> Result<Vec<u8>>;
}

impl<F> Timestamper for F
where
    F: Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync,
{
    fn timestamp(&self, request_der: &[u8]) -> Result<Vec<u8>> {
        self(request_der)
    }
}

/// A random 64-bit nonce from the operating-system RNG (feature `sys-rng`, DECISIONS D13 D-10),
/// never 0: brief §4.1 makes the nonce a positive INTEGER, so a zero draw is drawn again (manager
/// ruling R-24, M4 QA round 5 finding 4).
///
/// # Errors
/// [`Error::Crypto`](crate::Error::Crypto) when the RNG fails, or returns 0 four times in a
/// row (a broken RNG: the chance of one zero is 2^-64).
#[cfg(feature = "sys-rng")]
pub fn random_nonce() -> Result<u64> {
    for _ in 0..NONCE_DRAWS {
        let nonce = getrandom::u64()
            .map_err(|err| crate::Error::Crypto(format!("the system RNG failed: {err}")))?;
        if nonce != 0 {
            return Ok(nonce);
        }
    }
    Err(crate::Error::Crypto(format!(
        "the system RNG returned 0 for the nonce {NONCE_DRAWS} times in a row"
    )))
}

/// The most draws [`random_nonce`] makes for a non-zero nonce.
#[cfg(feature = "sys-rng")]
const NONCE_DRAWS: usize = 4;

/// What a successful [`validate_response`] returns: the token and what it says.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedToken {
    /// The `timeStampToken` ContentInfo, exactly as the TSA sent it (embedded byte for byte).
    pub token_der: Vec<u8>,
    /// The decoded TSTInfo.
    pub tst_info: TstInfo,
    /// The TSA certificate (DER), the token's signer.
    pub tsa_cert_der: Vec<u8>,
    /// Observations that do not refuse the token, for example a BER token embedded verbatim
    /// (DECISIONS D13 D-12) or a `genTime` fraction with trailing zeros.
    pub warnings: Vec<String>,
}

/// Validates a TSA's response to `request` on the signing side (brief §4.2 steps 1–8, in
/// order): the status is `granted` or `grantedWithMods`; a token is present; it is a SignedData
/// with one SignerInfo, eContentType `id-ct-TSTInfo` and eContent, and the whole token passes
/// the whitelist of [`verify_token`]'s step 1 (DER signed attributes and ESS attributes that
/// decode whole, every name with strings OpenSSL converts to UTF-8 included); its TSTInfo is
/// version 1, its `extensions` and its `tsa` GeneralName decode, with the request's
/// imprint (the same algorithm with absent or NULL parameters), nonce and policy and a parsable
/// `genTime`; the TSA signature verifies with the certificate in the token; every ESS
/// signing-certificate attribute (v1, v2) identifies it, each later identifier a certificate of
/// the token that issued it or one of its issuers (each link checked by name and signature),
/// and the TSTInfo `tsa` name, when present, is one of its names; the certificate passes
/// [`check_tsa_certificate`](crate::x509info::check_tsa_certificate) and is valid at `genTime`.
/// Folioxide never embeds a token its own verifier would call malformed or invalid without
/// trust anchors. With anchors the verifier also requires the later identifiers to name
/// certificates of the validated path (as OpenSSL does), which the signing side cannot check:
/// a TSA that names, say, a re-issued copy of its root (same name and key) instead of the
/// verifier's anchor gives a token that verifies as not valid there.
///
/// The signer's side never accepts less than this: `grantedWithMods` is accepted (D-9; pyHanko's
/// signer accepts only `granted`), a nonce is compared as an INTEGER value, NULL and absent
/// hash parameters are the same algorithm, and a BER token is accepted and returned verbatim
/// with a warning (D-12). The certificate must be in the token itself (`certReq` is true). A
/// token signed with SHA-1 is refused.
///
/// # Errors
/// [`Error::TimestampInvalid`](crate::Error::TimestampInvalid) at the first failed check, the
/// message naming it (for a refusal: `TSA refused: status <n>, "<statusString>", failInfo
/// <names>`).
pub fn validate_response(request: &TimeStampReq, response_der: &[u8]) -> Result<ValidatedToken> {
    check::validate_response(request, response_der)
}

/// Verifies a timestamp token on the verification side (brief §5 V7b steps 1–8, V7c): never
/// fails, never panics.
///
/// `expected_imprint(alg)` gives the digest with the TSTInfo's algorithm of the timestamped data
/// (the signature value, or the byte ranges of a document timestamp); `None` makes the token not
/// intact. `extra_certs` (DER) join the token's certificates when looking for the TSA
/// certificate. Trust (step 9) is separate:
/// [`build_trust_for`](crate::x509info::build_trust_for) with
/// [`TrustPurpose::TimeStamping`](crate::x509info::TrustPurpose::TimeStamping).
///
/// The steps:
///
/// 1. one SignedData with one SignerInfo, eContentType `id-ct-TSTInfo` and eContent, read as
///    a whitelist (QA round 1 findings F5, F6): `SignedData.version` 3, `digestAlgorithms`
///    listing only digests Folioxide implements (absent or NULL parameters) and the
///    SignerInfo's, every certificate entry an X.509 certificate that decodes with names
///    OpenSSL can read, every CRL one that decodes (with its issuer name), the SignerInfo
///    version that its signer
///    identifier implies (RFC 5652 §5.3), its digest and PKCS #1 or ECDSA signature algorithms
///    without parameters other than NULL, every primitive of the token and its TSTInfo a
///    valid encoding of its type (no padded INTEGER, no invalid OBJECT IDENTIFIER or UTF-8, no
///    BMPString surrogate or UniversalString beyond Unicode, which OpenSSL cannot convert in a
///    name; QA round 4 finding 1),
///    the signed attributes present and DER (RFC 5652 §5.4 signs their DER encoding, and
///    OpenSSL and BouncyCastle verify over a DER re-encoding; QA round 3 finding 2), and every
///    ESS signing-certificate attribute decoding as OpenSSL's templates read it, `policies` and
///    the IssuerSerial names included (QA round 3 finding 3); else `TimestampMalformed`;
/// 2. a version-1 TSTInfo whose `extensions`, when present, are a non-empty list of
///    `Extension`s (QA round 3 finding 4) and whose `tsa`, when present, is one GeneralName
///    that decodes as OpenSSL's `GENERAL_NAME` template reads it (QA round 4 finding 2), else
///    `TimestampMalformed`;
/// 3. `intact` when the imprint is the expected digest and its hash algorithm has absent or
///    NULL parameters (`TimestampImprintMismatch`; SHA-1 also gives `WeakAlgorithm`, an unknown
///    algorithm `UnsupportedAlgorithm`);
/// 4. the TSA's CMS signature ([`verify_encapsulated`](crate::cms::verify_encapsulated)),
///    else `TimestampSignatureInvalid`;
/// 5. the ESS binding as OpenSSL checks it: every signing-certificate attribute present (v2
///    and v1) a single value whose first identifier names the TSA certificate and whose later
///    identifiers name certificates among the token's certificates and `extra_certs` that
///    issued it or one of its issuers, each link checked by name (RFC 5280 §7.1) **and** by a
///    verified signature, so a decoy that only carries an issuer's name never counts (QA
///    round 2 finding 3), else `TimestampEssMismatch` (pyHanko reads only the first
///    identifier of v2, or of v1 without v2); and the TSTInfo `tsa` name, when present, the TSA
///    certificate's subject or one of its subjectAltName entries (RFC 3161 §2.4.2; a
///    `directoryName` compared as OpenSSL's `X509_NAME_cmp` does, the subjectAltName decoded as
///    the `tsa` name is), else `TsaNameMismatch`;
/// 6. [`check_tsa_certificate`](crate::x509info::check_tsa_certificate), else
///    `TsaCertificateUnsuitable`;
/// 7. `genTime` within the TSA certificate's validity, else `TsaCertificateNotValidAtGenTime`;
/// 8. `valid` when 4–7 hold.
///
/// OpenSSL checks the later ESS identifiers against the chain it verified to a trust anchor.
/// [`verify_pdf`](crate::verify_pdf) does the same when trust anchors are given: a token whose
/// TSA certificate is trusted through a path above it is also not valid when a later
/// identifier names no certificate of that path (V7b step 9). Callers that build trust
/// themselves with [`build_trust_for`](crate::x509info::build_trust_for) get the
/// anchor-independent check of step 5 only.
///
/// ```
/// use folioxide_sign::ProblemCode;
/// use folioxide_sign::tsp::verify_token;
///
/// let verification = verify_token(b"garbage", &|_| None, &[]);
/// assert!(!verification.intact && !verification.valid);
/// assert_eq!(verification.problems[0].code, ProblemCode::TimestampMalformed);
/// ```
pub fn verify_token(
    token_der: &[u8],
    expected_imprint: &dyn Fn(DigestAlgorithm) -> Option<Vec<u8>>,
    extra_certs: &[Vec<u8>],
) -> TokenVerification {
    check::verify_token(token_der, expected_imprint, extra_certs, &[])
}

/// [`verify_token`] with `anchors` (trust anchors, DER) among the certificates the later ESS
/// identifiers may name; they are never taken as the TSA certificate (V7b step 5).
pub(crate) fn verify_token_with_anchors(
    token_der: &[u8],
    expected_imprint: &dyn Fn(DigestAlgorithm) -> Option<Vec<u8>>,
    extra_certs: &[Vec<u8>],
    anchors: &[Vec<u8>],
) -> TokenVerification {
    check::verify_token(token_der, expected_imprint, extra_certs, anchors)
}

/// V7b step 9 (QA round 2 finding 3): every later identifier of every ESS signing-certificate
/// attribute of `token_der` names a certificate of `path`, the validated certification path of
/// `tsa_cert` (signer first, trust anchor last), other than `tsa_cert` itself. This is the
/// chain OpenSSL's `OSSL_ESS_check_signing_certs` searches.
///
/// # Errors
/// The sentence of the failure (the problem `TimestampEssMismatch`).
pub(crate) fn ess_on_path(
    token_der: &[u8],
    tsa_cert: &[u8],
    path: &[Vec<u8>],
) -> std::result::Result<(), String> {
    check::ess_on_path(token_der, tsa_cert, path)
}

/// The result of [`verify_token`].
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenVerification {
    /// The `messageImprint` is the expected digest (V7b step 3).
    pub intact: bool,
    /// The TSA signature verifies, the ESS attributes and the `tsa` name match, the TSA
    /// certificate is suitable and valid at `genTime` (V7b steps 4–8).
    pub valid: bool,
    /// The decoded TSTInfo, when it decodes.
    pub tst_info: Option<TstInfo>,
    /// The TSA certificate (DER), when found.
    pub tsa_cert: Option<Vec<u8>>,
    /// Every certificate of the token (DER), in file order.
    pub certificates: Vec<Vec<u8>>,
    /// The TSA's signature algorithm, for example `"sha256WithRSAEncryption"`.
    pub signature_algorithm: Option<String>,
    /// Why the token is not intact or not valid; empty when nothing is wrong.
    pub problems: Vec<Problem>,
    /// Observations that do not make the token invalid.
    pub warnings: Vec<String>,
}

// ---- helpers ------------------------------------------------------------------------------------

/// The DER `BOOLEAN` tag (X.690 §8.2).
const TAG_BOOLEAN: u8 = 0x01;

/// The content octets of the minimal positive DER INTEGER with value `value` (X.690 §8.3): no
/// redundant leading zero octet, and one `0x00` before an octet whose top bit is set.
fn positive_integer_octets(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    // Keep at least the last octet (the value 0 is the single octet 00).
    let skip = bytes.iter().take_while(|&&b| b == 0).count().min(7);
    let significant = bytes.get(skip..).unwrap_or_default();
    let mut out = Vec::with_capacity(significant.len() + 1);
    if significant.first().is_some_and(|&b| b & 0x80 != 0) {
        out.push(0);
    }
    out.extend_from_slice(significant);
    out
}

/// The DER content octets of the dotted OID `dotted`; empty when it is not an OID.
fn oid_content(dotted: &str) -> Vec<u8> {
    ObjectIdentifier::new(dotted)
        .map(|oid| oid.as_bytes().to_vec())
        .unwrap_or_default()
}

/// The proleptic Gregorian date of the day `days` after 1970-01-01 (Howard Hinnant's
/// `civil_from_days`, the inverse of [`UnixTime::from_pdf_date`](crate::x509info::UnixTime)'s
/// `days_from_civil`). Defined for every `i64` day count derived from a POSIX time.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March = 0
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = yoe
        .saturating_add(era.saturating_mul(400))
        .saturating_add(i64::from(month <= 2));
    // Lossless: `month` is 1–12 and `day` 1–31.
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_octets_are_minimal_positive_integers() {
        assert_eq!(positive_integer_octets(0), [0x00]);
        assert_eq!(positive_integer_octets(1), [0x01]);
        assert_eq!(positive_integer_octets(0x7F), [0x7F]);
        assert_eq!(positive_integer_octets(0x80), [0x00, 0x80]);
        assert_eq!(positive_integer_octets(0x0100), [0x01, 0x00]);
        assert_eq!(
            positive_integer_octets(0x0102_0304_0506_0708),
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
        assert_eq!(
            positive_integer_octets(u64::MAX),
            [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn request_der_layout() {
        let imprint = MessageImprint::new(DigestAlgorithm::Sha384, vec![0xAB; 48]);
        let mut request = TimeStampReq::new(imprint, None, Some("1.2.3.4.1".into()));
        let der = request.to_der();
        // SEQUENCE { INTEGER 1, SEQUENCE { SEQUENCE { sha384, NULL }, OCTET STRING }, OID policy,
        // BOOLEAN TRUE }: the hash and the policy, no nonce.
        let algorithm = [
            0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
            0x00,
        ];
        let mut expected = vec![0x30, 0x4F, 0x02, 0x01, 0x01, 0x30, 0x41];
        expected.extend_from_slice(&algorithm);
        expected.extend_from_slice(&[0x04, 0x30]);
        expected.extend_from_slice(&[0xAB; 48]);
        expected.extend_from_slice(&[0x06, 0x04, 0x2A, 0x03, 0x04, 0x01]);
        expected.extend_from_slice(&[0x01, 0x01, 0xFF]);
        assert_eq!(der, expected);

        // certReq false is the DEFAULT, so DER omits it.
        request.cert_req = false;
        assert!(!request.to_der().ends_with(&[0x01, 0x01, 0xFF]));
        // A policy that is not an OID is an empty OID, which a TSA refuses.
        request.policy = Some("not an oid".into());
        assert!(request.to_der().ends_with(&[0x06, 0x00]));
    }

    #[test]
    fn gen_time_rfc3339() {
        let at = |unix_seconds, nanos, fraction_digits| GenTime {
            unix_seconds,
            nanos,
            fraction_digits,
        };
        assert_eq!(at(0, 0, 0).to_rfc3339(), "1970-01-01T00:00:00Z");
        // 2026-10-11T03:51:41.825589Z, pyHanko's DummyTimeStamper style (brief §6.2).
        assert_eq!(
            at(1_791_690_701, 825_589_000, 6).to_rfc3339(),
            "2026-10-11T03:51:41.825589Z"
        );
        assert_eq!(
            at(1_791_633_630, 500_000_000, 1).to_rfc3339(),
            "2026-10-10T12:00:30.5Z"
        );
        assert_eq!(
            at(1_791_633_630, 50_000_000, 3).to_rfc3339(),
            "2026-10-10T12:00:30.050Z"
        );
        assert_eq!(at(-1, 0, 0).to_rfc3339(), "1969-12-31T23:59:59Z");
        assert_eq!(at(951_782_400, 0, 0).to_rfc3339(), "2000-02-29T00:00:00Z");
        assert_eq!(at(951_868_800, 0, 0).to_rfc3339(), "2000-03-01T00:00:00Z");
        // Out-of-range fields are clamped, never a panic.
        assert_eq!(
            at(0, u32::MAX, 200).to_rfc3339(),
            "1970-01-01T00:00:00.999999999Z"
        );
        let _ = at(i64::MIN, 0, 9).to_rfc3339();
        let _ = at(i64::MAX, 0, 9).to_rfc3339();
        // Ordered by instant first.
        assert!(at(1, 0, 0) < at(1, 1, 0) && at(1, 999, 9) < at(2, 0, 0));
    }

    #[test]
    fn requests_round_trip_and_refuse_non_der() {
        let imprint = MessageImprint::new(DigestAlgorithm::Sha256, vec![0; 32]);
        let request = TimeStampReq::new(imprint, Some(1), None);
        assert_eq!(TimeStampReq::from_der(&request.to_der()).unwrap(), request);
        // A long-form length where the short form fits is not DER.
        let mut lax = request.to_der();
        lax.splice(1..2, [0x81, lax[1]]);
        assert!(TimeStampReq::from_der(&lax).is_err());
        assert!(TimeStampResp::from_der(&[]).is_err());
        assert!(GenTime::parse(b"20261010120030").is_err());
        assert!(TstInfo::from_der(&[]).is_err());
        assert!(validate_response(&request, &[]).is_err());
    }

    #[test]
    fn trailing_zero_fractions() {
        let parse = |s: &str| GenTime::parse(s.as_bytes()).unwrap();
        assert!(!parse("20261010120030Z").has_trailing_zeros());
        assert!(!parse("20261010120030.5Z").has_trailing_zeros());
        assert!(parse("20261010120030.50Z").has_trailing_zeros());
        assert!(parse("20261010120030.0Z").has_trailing_zeros());
        assert!(!parse("20261010120030.000000001Z").has_trailing_zeros());
        assert_eq!(parse("20261010120030Z").unix_time().secs(), 1_791_633_630);
    }

    #[cfg(feature = "sys-rng")]
    #[test]
    fn random_nonces_differ() {
        let a = random_nonce().unwrap();
        let b = random_nonce().unwrap();
        let c = random_nonce().unwrap();
        assert!(a != b || b != c);
        // R-24: positive (brief §4.1).
        assert!(a != 0 && b != 0 && c != 0);
    }

    #[test]
    fn closures_are_timestampers() {
        let echo = |request: &[u8]| -> Result<Vec<u8>> { Ok(request.to_vec()) };
        let timestamper: &dyn Timestamper = &echo;
        assert_eq!(timestamper.timestamp(b"req").unwrap(), b"req");
    }
}

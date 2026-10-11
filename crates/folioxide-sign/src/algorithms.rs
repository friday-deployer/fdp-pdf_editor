//! Digest and signature algorithms, key kinds and the object identifiers Folioxide uses
//! (M3 brief §3.1 and §4.3).
//!
//! - [`DigestAlgorithm`]: SHA-256, SHA-384 and SHA-512 for signing; SHA-1 for verification only.
//!   [`DigestAlgorithm::hasher`] streams, [`DigestAlgorithm::digest`] hashes a list of slices.
//! - [`SignatureAlgorithm`]: RSA PKCS#1 v1.5 or ECDSA. The curve comes from the certificate, and
//!   RSA-PSS is verification-only and internal.
//! - [`KeyKind`]: RSA with its modulus size, P-256 or P-384.
//! - [`default_digest`] and [`check_signing_combination`]: the allowed signing combinations.
//! - [`oid`]: the dotted object identifiers of every algorithm and attribute in the CMS.
//!
//! Only Folioxide's own types appear here; the RustCrypto hashers stay private (ARCHITECTURE
//! §A.5 gap 5).

use std::fmt;

use const_oid::ObjectIdentifier;
use sha2::Digest as _;

use crate::error::{Error, Result};

/// Dotted object identifiers (RFC 5652, RFC 5035, RFC 5754, RFC 4055, RFC 5758, RFC 5480,
/// RFC 6211, RFC 3161).
///
/// They are plain strings so that no RustCrypto type appears in the public API. Every constant is
/// checked against its DER encoding in the unit tests.
pub mod oid {
    /// `id-data` (RFC 5652 §4): the eContentType of a detached PDF signature.
    pub const ID_DATA: &str = "1.2.840.113549.1.7.1";
    /// `id-signedData` (RFC 5652 §5.1): the contentType of the ContentInfo.
    pub const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
    /// `id-contentType` (RFC 5652 §11.1): the content-type signed attribute.
    pub const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
    /// `id-messageDigest` (RFC 5652 §11.2): the message-digest signed attribute.
    pub const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
    /// `id-signingTime` (RFC 5652 §11.3). PAdES B-B forbids it; the time goes in `/M`.
    pub const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
    /// `id-aa-signingCertificate` (RFC 2634 §5.4): ESS signing-certificate v1 (SHA-1 only).
    pub const SIGNING_CERTIFICATE: &str = "1.2.840.113549.1.9.16.2.12";
    /// `id-aa-signingCertificateV2` (RFC 5035 §3): ESS signing-certificate v2.
    pub const SIGNING_CERTIFICATE_V2: &str = "1.2.840.113549.1.9.16.2.47";
    /// `id-aa-signatureTimeStampToken` (RFC 3161 Appendix A): the B-T unsigned attribute (M4).
    pub const SIGNATURE_TIME_STAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";
    /// `id-aa-CMSAlgorithmProtection` (RFC 6211 §2).
    pub const CMS_ALGORITHM_PROTECTION: &str = "1.2.840.113549.1.9.52";

    /// `id-sha1` (RFC 3370 §2.1). Verification only.
    pub const SHA1: &str = "1.3.14.3.2.26";
    /// `id-sha256` (RFC 5754 §2.2).
    pub const SHA256: &str = "2.16.840.1.101.3.4.2.1";
    /// `id-sha384` (RFC 5754 §2.3).
    pub const SHA384: &str = "2.16.840.1.101.3.4.2.2";
    /// `id-sha512` (RFC 5754 §2.4).
    pub const SHA512: &str = "2.16.840.1.101.3.4.2.3";

    /// `rsaEncryption` (RFC 8017 Appendix C): the RSA SubjectPublicKeyInfo algorithm, also
    /// accepted as a CMS signatureAlgorithm on verification (RFC 3370 §3.2).
    pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
    /// `sha1WithRSAEncryption` (RFC 8017 Appendix C). Verification only.
    pub const SHA1_WITH_RSA: &str = "1.2.840.113549.1.1.5";
    /// `id-mgf1` (RFC 8017 Appendix B.2.1): the mask generation function of RSASSA-PSS.
    pub const MGF1: &str = "1.2.840.113549.1.1.8";
    /// `id-RSASSA-PSS` (RFC 4055 §3.1). Verification only.
    pub const RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
    /// `sha256WithRSAEncryption` (RFC 4055 §5).
    pub const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
    /// `sha384WithRSAEncryption` (RFC 4055 §5).
    pub const SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
    /// `sha512WithRSAEncryption` (RFC 4055 §5).
    pub const SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";

    /// `id-ecPublicKey` (RFC 5480 §2.1.1): the EC SubjectPublicKeyInfo algorithm, also accepted
    /// as a CMS signatureAlgorithm on verification.
    pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
    /// `ecdsa-with-SHA1` (RFC 3279 §2.2.3). Verification only.
    pub const ECDSA_WITH_SHA1: &str = "1.2.840.10045.4.1";
    /// `ecdsa-with-SHA256` (RFC 5758 §3.2).
    pub const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
    /// `ecdsa-with-SHA384` (RFC 5758 §3.2).
    pub const ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
    /// `ecdsa-with-SHA512` (RFC 5758 §3.2).
    pub const ECDSA_WITH_SHA512: &str = "1.2.840.10045.4.3.4";
    /// `prime256v1` / `secp256r1` / NIST P-256 (RFC 5480 §2.1.1.1).
    pub const PRIME256V1: &str = "1.2.840.10045.3.1.7";
    /// `secp384r1` / NIST P-384 (RFC 5480 §2.1.1.1).
    pub const SECP384R1: &str = "1.3.132.0.34";
}

/// The smallest RSA modulus Folioxide signs with, in bits (M3 brief D-12).
pub const MIN_RSA_SIGNING_BITS: u32 = 2048;
/// The smallest RSA modulus Folioxide verifies, in bits; below 2048 bits a warning is reported
/// (M3 brief D-12).
pub const MIN_RSA_VERIFY_BITS: u32 = 1024;
/// The largest RSA modulus Folioxide accepts, in bits (`rsa`'s `RsaPublicKey::MAX_SIZE`; a
/// defence against bignum denial of service, M3 brief R-18).
pub const MAX_RSA_BITS: u32 = 8192;

/// A message digest algorithm.
///
/// SHA-256, SHA-384 and SHA-512 are used for signing. SHA-1 exists for verifying legacy
/// signatures only: Folioxide never signs with it ([`check_signing_combination`]).
///
/// With the `serde` feature it is the string `"sha256"`, `"sha384"`, `"sha512"` or `"sha1"`,
/// the same text [`DigestAlgorithm::name`] returns (and the Node binding's `DigestAlg`).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum DigestAlgorithm {
    /// SHA-256 (FIPS 180-4).
    Sha256,
    /// SHA-384 (FIPS 180-4).
    Sha384,
    /// SHA-512 (FIPS 180-4).
    Sha512,
    /// SHA-1 (FIPS 180-4). Verification only; reported as a weak algorithm.
    Sha1,
}

impl DigestAlgorithm {
    /// Every digest algorithm, the signing ones first.
    pub const ALL: [DigestAlgorithm; 4] = [
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
        DigestAlgorithm::Sha1,
    ];

    /// The length of a digest in bytes: 32, 48, 64, or 20 for SHA-1.
    pub fn output_len(self) -> usize {
        match self {
            DigestAlgorithm::Sha256 => 32,
            DigestAlgorithm::Sha384 => 48,
            DigestAlgorithm::Sha512 => 64,
            DigestAlgorithm::Sha1 => 20,
        }
    }

    /// A streaming hasher for this algorithm.
    pub fn hasher(self) -> Hasher {
        Hasher::new(self)
    }

    /// The digest of the concatenation of `parts`, for example the two signed ranges of a
    /// `/ByteRange` (ISO 32000-2 §12.8.1).
    ///
    /// ```
    /// use folioxide_sign::algorithms::DigestAlgorithm;
    ///
    /// let split = DigestAlgorithm::Sha256.digest(&[b"ab", b"c"]);
    /// assert_eq!(split, DigestAlgorithm::Sha256.digest(&[b"abc"]));
    /// assert_eq!(split.len(), 32);
    /// ```
    pub fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        let mut hasher = self.hasher();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize()
    }

    /// The short lowercase name: `"sha256"`, `"sha384"`, `"sha512"` or `"sha1"` (the Node
    /// binding's `DigestAlg` and the report's `digestAlgorithm`).
    pub fn name(self) -> &'static str {
        match self {
            DigestAlgorithm::Sha256 => "sha256",
            DigestAlgorithm::Sha384 => "sha384",
            DigestAlgorithm::Sha512 => "sha512",
            DigestAlgorithm::Sha1 => "sha1",
        }
    }

    /// Parses a name as [`DigestAlgorithm::name`] writes it, ignoring ASCII case and accepting
    /// the hyphenated spelling (`"SHA-256"`).
    pub fn from_name(name: &str) -> Option<DigestAlgorithm> {
        let lower = name.to_ascii_lowercase();
        let compact = match lower.strip_prefix("sha-") {
            Some(bits) => format!("sha{bits}"),
            None => lower,
        };
        DigestAlgorithm::ALL
            .into_iter()
            .find(|alg| compact == alg.name())
    }

    /// The dotted object identifier (RFC 5754 §2, RFC 3370 §2.1).
    pub fn oid(self) -> &'static str {
        match self {
            DigestAlgorithm::Sha256 => oid::SHA256,
            DigestAlgorithm::Sha384 => oid::SHA384,
            DigestAlgorithm::Sha512 => oid::SHA512,
            DigestAlgorithm::Sha1 => oid::SHA1,
        }
    }

    /// The algorithm with this dotted object identifier, if Folioxide implements it.
    pub fn from_oid(dotted: &str) -> Option<DigestAlgorithm> {
        DigestAlgorithm::ALL
            .into_iter()
            .find(|alg| alg.oid() == dotted)
    }

    /// Whether the algorithm is weak (SHA-1): signatures that use it are reported with
    /// `WeakAlgorithm` and are never trusted (M3 brief §5 V7, R-12).
    pub fn is_weak(self) -> bool {
        self == DigestAlgorithm::Sha1
    }

    /// The DER `DigestInfo ::= SEQUENCE { AlgorithmIdentifier { oid, NULL }, OCTET STRING hash }`
    /// of RFC 8017 §9.2 step 2: the input of a raw RSA PKCS#1 v1.5 signing operation, for
    /// example PKCS#11 `CKM_RSA_PKCS`.
    ///
    /// `hash` is normally a digest made with this algorithm; its length is not checked.
    ///
    /// ```
    /// use folioxide_sign::algorithms::DigestAlgorithm;
    ///
    /// let hash = DigestAlgorithm::Sha256.digest(&[b"abc"]);
    /// let info = DigestAlgorithm::Sha256.digest_info(&hash);
    /// // The 19-byte prefix of RFC 8017 §9.2 note 1, then the hash.
    /// assert_eq!(info[..4], [0x30, 0x31, 0x30, 0x0d]);
    /// assert_eq!(info[19..], hash[..]);
    /// ```
    pub fn digest_info(self, hash: &[u8]) -> Vec<u8> {
        let oid = match self {
            DigestAlgorithm::Sha256 => &OID_SHA256,
            DigestAlgorithm::Sha384 => &OID_SHA384,
            DigestAlgorithm::Sha512 => &OID_SHA512,
            DigestAlgorithm::Sha1 => &OID_SHA1,
        };
        let mut algorithm = Vec::with_capacity(16);
        push_tlv(&mut algorithm, TAG_OID, oid.as_bytes());
        push_tlv(&mut algorithm, TAG_NULL, &[]);
        let mut content = Vec::with_capacity(algorithm.len() + hash.len() + 8);
        push_tlv(&mut content, TAG_SEQUENCE, &algorithm);
        push_tlv(&mut content, TAG_OCTET_STRING, hash);
        let mut out = Vec::with_capacity(content.len() + 6);
        push_tlv(&mut out, TAG_SEQUENCE, &content);
        out
    }
}

impl fmt::Display for DigestAlgorithm {
    /// Writes [`DigestAlgorithm::name`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A streaming hash computation: [`Hasher::update`] any number of times, then
/// [`Hasher::finalize`].
///
/// ```
/// use folioxide_sign::algorithms::DigestAlgorithm;
///
/// let mut hasher = DigestAlgorithm::Sha384.hasher();
/// hasher.update(b"a");
/// hasher.update(b"bc");
/// assert_eq!(hasher.finalize(), DigestAlgorithm::Sha384.digest(&[b"abc"]));
/// ```
#[derive(Clone)]
pub struct Hasher {
    inner: HasherInner,
}

#[derive(Clone)]
enum HasherInner {
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Sha1(sha1::Sha1),
}

impl Hasher {
    /// A new hasher for `algorithm`.
    pub fn new(algorithm: DigestAlgorithm) -> Hasher {
        let inner = match algorithm {
            DigestAlgorithm::Sha256 => HasherInner::Sha256(sha2::Sha256::new()),
            DigestAlgorithm::Sha384 => HasherInner::Sha384(sha2::Sha384::new()),
            DigestAlgorithm::Sha512 => HasherInner::Sha512(sha2::Sha512::new()),
            DigestAlgorithm::Sha1 => HasherInner::Sha1(sha1::Sha1::new()),
        };
        Hasher { inner }
    }

    /// The algorithm this hasher computes.
    pub fn algorithm(&self) -> DigestAlgorithm {
        match self.inner {
            HasherInner::Sha256(_) => DigestAlgorithm::Sha256,
            HasherInner::Sha384(_) => DigestAlgorithm::Sha384,
            HasherInner::Sha512(_) => DigestAlgorithm::Sha512,
            HasherInner::Sha1(_) => DigestAlgorithm::Sha1,
        }
    }

    /// Feeds `data` into the hash.
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.inner {
            HasherInner::Sha256(h) => h.update(data),
            HasherInner::Sha384(h) => h.update(data),
            HasherInner::Sha512(h) => h.update(data),
            HasherInner::Sha1(h) => h.update(data),
        }
    }

    /// The digest of everything fed in, [`DigestAlgorithm::output_len`] bytes.
    pub fn finalize(self) -> Vec<u8> {
        match self.inner {
            HasherInner::Sha256(h) => h.finalize().to_vec(),
            HasherInner::Sha384(h) => h.finalize().to_vec(),
            HasherInner::Sha512(h) => h.finalize().to_vec(),
            HasherInner::Sha1(h) => h.finalize().to_vec(),
        }
    }
}

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hasher")
            .field("algorithm", &self.algorithm())
            .finish_non_exhaustive()
    }
}

/// A signature algorithm family.
///
/// The curve of an ECDSA key comes from its certificate ([`KeyKind`]). RSA-PSS is accepted
/// when verifying but is internal: Folioxide does not create RSA-PSS signatures.
///
/// With the `serde` feature it is the string `"rsa-pkcs1v15"` or `"ecdsa"`, the same text
/// [`SignatureAlgorithm::name`] returns (and the Node binding's `SigAlg`).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2).
    #[cfg_attr(feature = "serde", serde(rename = "rsa-pkcs1v15"))]
    RsaPkcs1v15,
    /// ECDSA (FIPS 186-5) on P-256 or P-384.
    Ecdsa,
}

impl SignatureAlgorithm {
    /// The name the Node binding uses: `"rsa-pkcs1v15"` or `"ecdsa"`.
    pub fn name(self) -> &'static str {
        match self {
            SignatureAlgorithm::RsaPkcs1v15 => "rsa-pkcs1v15",
            SignatureAlgorithm::Ecdsa => "ecdsa",
        }
    }

    /// Parses a name as [`SignatureAlgorithm::name`] writes it.
    pub fn from_name(name: &str) -> Option<SignatureAlgorithm> {
        [SignatureAlgorithm::RsaPkcs1v15, SignatureAlgorithm::Ecdsa]
            .into_iter()
            .find(|alg| alg.name() == name)
    }

    /// The dotted OID of the CMS `signatureAlgorithm` for this algorithm with `digest`, for
    /// example `sha256WithRSAEncryption` (RFC 4055 §5) or `ecdsa-with-SHA384` (RFC 5758 §3.2).
    pub fn signature_oid(self, digest: DigestAlgorithm) -> &'static str {
        match (self, digest) {
            (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha256) => oid::SHA256_WITH_RSA,
            (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha384) => oid::SHA384_WITH_RSA,
            (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha512) => oid::SHA512_WITH_RSA,
            (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha1) => oid::SHA1_WITH_RSA,
            (SignatureAlgorithm::Ecdsa, DigestAlgorithm::Sha256) => oid::ECDSA_WITH_SHA256,
            (SignatureAlgorithm::Ecdsa, DigestAlgorithm::Sha384) => oid::ECDSA_WITH_SHA384,
            (SignatureAlgorithm::Ecdsa, DigestAlgorithm::Sha512) => oid::ECDSA_WITH_SHA512,
            (SignatureAlgorithm::Ecdsa, DigestAlgorithm::Sha1) => oid::ECDSA_WITH_SHA1,
        }
    }

    /// The RFC name of the CMS `signatureAlgorithm` for this algorithm with `digest`, for
    /// example `"sha256WithRSAEncryption"` or `"ecdsa-with-SHA384"` (the report's
    /// `signatureAlgorithm`).
    pub fn signature_name(self, digest: DigestAlgorithm) -> &'static str {
        match (self, digest) {
            (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha256) => "sha256WithRSAEncryption",
            (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha384) => "sha384WithRSAEncryption",
            (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha512) => "sha512WithRSAEncryption",
            (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha1) => "sha1WithRSAEncryption",
            (SignatureAlgorithm::Ecdsa, DigestAlgorithm::Sha256) => "ecdsa-with-SHA256",
            (SignatureAlgorithm::Ecdsa, DigestAlgorithm::Sha384) => "ecdsa-with-SHA384",
            (SignatureAlgorithm::Ecdsa, DigestAlgorithm::Sha512) => "ecdsa-with-SHA512",
            (SignatureAlgorithm::Ecdsa, DigestAlgorithm::Sha1) => "ecdsa-with-SHA1",
        }
    }
}

impl fmt::Display for SignatureAlgorithm {
    /// Writes [`SignatureAlgorithm::name`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The kind and size of a signing key, taken from the signer certificate's public key.
///
/// With the `serde` feature it is `{"rsa": {"bits": 2048}}`, `"ecP256"` or `"ecP384"`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum KeyKind {
    /// An RSA key.
    Rsa {
        /// The modulus size in bits.
        bits: u32,
    },
    /// An ECDSA key on NIST P-256 (`prime256v1`).
    EcP256,
    /// An ECDSA key on NIST P-384 (`secp384r1`).
    EcP384,
}

impl KeyKind {
    /// The signature algorithm family of this key.
    pub fn algorithm(self) -> SignatureAlgorithm {
        match self {
            KeyKind::Rsa { .. } => SignatureAlgorithm::RsaPkcs1v15,
            KeyKind::EcP256 | KeyKind::EcP384 => SignatureAlgorithm::Ecdsa,
        }
    }

    /// The largest signature value this key produces, in bytes: the modulus length for RSA
    /// (RFC 8017 §8.2.1), and the longest DER `ECDSA-Sig-Value` for ECDSA (72 bytes for P-256,
    /// 104 for P-384: two INTEGERs with a leading zero byte, RFC 5480 §2.2 / X.690 §8.3).
    pub fn max_signature_len(self) -> usize {
        match self {
            KeyKind::Rsa { bits } => usize::try_from(bits.div_ceil(8)).unwrap_or(usize::MAX),
            KeyKind::EcP256 => 72,
            KeyKind::EcP384 => 104,
        }
    }

    /// The length of an IEEE P1363 `r || s` signature for an ECDSA key (64 bytes for P-256, 96
    /// for P-384), or `None` for RSA.
    pub fn p1363_len(self) -> Option<usize> {
        match self {
            KeyKind::Rsa { .. } => None,
            KeyKind::EcP256 => Some(64),
            KeyKind::EcP384 => Some(96),
        }
    }

    /// The dotted OID of the named curve of an ECDSA key (RFC 5480 §2.1.1.1), or `None` for RSA.
    pub fn curve_oid(self) -> Option<&'static str> {
        match self {
            KeyKind::Rsa { .. } => None,
            KeyKind::EcP256 => Some(oid::PRIME256V1),
            KeyKind::EcP384 => Some(oid::SECP384R1),
        }
    }
}

/// The digest Folioxide signs with when the caller does not choose one: SHA-256 for RSA and
/// P-256 keys, SHA-384 for P-384 keys (M3 brief §3.1).
///
/// ```
/// use folioxide_sign::algorithms::{DigestAlgorithm, KeyKind, default_digest};
///
/// assert_eq!(default_digest(KeyKind::Rsa { bits: 3072 }), DigestAlgorithm::Sha256);
/// assert_eq!(default_digest(KeyKind::EcP384), DigestAlgorithm::Sha384);
/// ```
pub fn default_digest(kind: KeyKind) -> DigestAlgorithm {
    match kind {
        KeyKind::Rsa { .. } | KeyKind::EcP256 => DigestAlgorithm::Sha256,
        KeyKind::EcP384 => DigestAlgorithm::Sha384,
    }
}

/// Checks that Folioxide may sign with this key and digest (M3 brief §3.1, D-12).
///
/// Allowed: RSA keys of 2048 to 8192 bits, P-256 and P-384 keys, each with SHA-256, SHA-384 or
/// SHA-512. SHA-1 is never allowed for signing, and RSA keys outside that size range are
/// refused; both give [`Error::InvalidArgument`].
///
/// ```
/// use folioxide_sign::algorithms::{DigestAlgorithm, KeyKind, check_signing_combination};
///
/// assert!(check_signing_combination(KeyKind::EcP256, DigestAlgorithm::Sha512).is_ok());
/// assert!(check_signing_combination(KeyKind::EcP256, DigestAlgorithm::Sha1).is_err());
/// assert!(check_signing_combination(KeyKind::Rsa { bits: 1024 }, DigestAlgorithm::Sha256).is_err());
/// ```
pub fn check_signing_combination(kind: KeyKind, digest: DigestAlgorithm) -> Result<()> {
    if digest.is_weak() {
        return Err(Error::InvalidArgument(format!(
            "{digest} is not allowed for signing; use sha256, sha384 or sha512"
        )));
    }
    if let KeyKind::Rsa { bits } = kind
        && !(MIN_RSA_SIGNING_BITS..=MAX_RSA_BITS).contains(&bits)
    {
        return Err(Error::InvalidArgument(format!(
            "RSA keys must have {MIN_RSA_SIGNING_BITS} to {MAX_RSA_BITS} bits to sign, \
             this one has {bits}"
        )));
    }
    Ok(())
}

// DER encodings of the digest OIDs, for `DigestAlgorithm::digest_info`. `new_unwrap` runs at
// compile time, so a malformed literal is a build error, never a runtime panic.
const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::SHA1);
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::SHA256);
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::SHA384);
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap(oid::SHA512);

const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;

/// Appends the DER TLV `tag || length || content` (X.690 §8.1.3: the short form below 128, else
/// the minimal long form).
fn push_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        // Lossless: len < 128.
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let significant = bytes.get(skip..).unwrap_or_default();
        // Lossless: at most size_of::<usize>() <= 16 length octets.
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        digits
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    /// FIPS 180-4 / NIST CSVS example vectors for "abc".
    #[test]
    fn digests_match_fips_180_4_abc_vectors() {
        let cases = [
            (
                DigestAlgorithm::Sha1,
                "a9993e364706816aba3e25717850c26c9cd0d89d",
            ),
            (
                DigestAlgorithm::Sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                DigestAlgorithm::Sha384,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
                 8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                DigestAlgorithm::Sha512,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
        ];
        for (alg, expected) in cases {
            let one_shot = alg.digest(&[b"abc"]);
            assert_eq!(hex(&one_shot), expected.replace(' ', ""), "{alg}");
            assert_eq!(one_shot.len(), alg.output_len(), "{alg}");
            assert_eq!(alg.digest(&[b"a", b"", b"bc"]), one_shot, "{alg}");

            let mut hasher = alg.hasher();
            assert_eq!(hasher.algorithm(), alg);
            hasher.update(b"ab");
            let fork = hasher.clone();
            hasher.update(b"c");
            assert_eq!(hasher.finalize(), one_shot, "{alg}");
            assert_ne!(fork.finalize(), one_shot, "{alg}: clones are independent");
        }
        assert_eq!(
            format!("{:?}", DigestAlgorithm::Sha256.hasher()),
            "Hasher { algorithm: Sha256, .. }"
        );
    }

    /// RFC 8017 §9.2 note 1: the DER prefixes of DigestInfo.
    #[test]
    fn digest_info_matches_rfc_8017_prefixes() {
        let cases = [
            (
                DigestAlgorithm::Sha1,
                "30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14",
            ),
            (
                DigestAlgorithm::Sha256,
                "30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20",
            ),
            (
                DigestAlgorithm::Sha384,
                "30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30",
            ),
            (
                DigestAlgorithm::Sha512,
                "30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40",
            ),
        ];
        for (alg, prefix) in cases {
            let hash = alg.digest(&[b"folioxide"]);
            let mut expected = unhex(prefix);
            expected.extend_from_slice(&hash);
            assert_eq!(alg.digest_info(&hash), expected, "{alg}");
        }
    }

    #[test]
    fn push_tlv_uses_minimal_long_form_lengths() {
        for (len, header) in [
            (0usize, vec![0x04, 0x00]),
            (127, vec![0x04, 0x7f]),
            (128, vec![0x04, 0x81, 0x80]),
            (255, vec![0x04, 0x81, 0xff]),
            (256, vec![0x04, 0x82, 0x01, 0x00]),
            (70_000, vec![0x04, 0x83, 0x01, 0x11, 0x70]),
        ] {
            let mut out = Vec::new();
            push_tlv(&mut out, TAG_OCTET_STRING, &vec![0xAB; len]);
            assert_eq!(out[..header.len()], header[..], "length {len}");
            assert_eq!(out.len(), header.len() + len);
        }
    }

    #[test]
    fn oid_constants_are_well_formed_and_distinct() {
        let all = [
            oid::ID_DATA,
            oid::ID_SIGNED_DATA,
            oid::CONTENT_TYPE,
            oid::MESSAGE_DIGEST,
            oid::SIGNING_TIME,
            oid::SIGNING_CERTIFICATE,
            oid::SIGNING_CERTIFICATE_V2,
            oid::SIGNATURE_TIME_STAMP_TOKEN,
            oid::CMS_ALGORITHM_PROTECTION,
            oid::SHA1,
            oid::SHA256,
            oid::SHA384,
            oid::SHA512,
            oid::RSA_ENCRYPTION,
            oid::SHA1_WITH_RSA,
            oid::MGF1,
            oid::RSASSA_PSS,
            oid::SHA256_WITH_RSA,
            oid::SHA384_WITH_RSA,
            oid::SHA512_WITH_RSA,
            oid::EC_PUBLIC_KEY,
            oid::ECDSA_WITH_SHA1,
            oid::ECDSA_WITH_SHA256,
            oid::ECDSA_WITH_SHA384,
            oid::ECDSA_WITH_SHA512,
            oid::PRIME256V1,
            oid::SECP384R1,
        ];
        let mut seen = std::collections::HashSet::new();
        for dotted in all {
            let parsed = ObjectIdentifier::new(dotted).unwrap();
            assert_eq!(parsed.to_string(), dotted);
            assert!(seen.insert(dotted), "duplicate {dotted}");
        }
        // Spot checks of the DER content octets against the RFC listings.
        let der = |dotted: &str| hex(ObjectIdentifier::new(dotted).unwrap().as_bytes());
        assert_eq!(der(oid::ID_DATA), "2a864886f70d010701");
        assert_eq!(der(oid::SIGNING_CERTIFICATE_V2), "2a864886f70d010910022f");
        assert_eq!(der(oid::SHA256_WITH_RSA), "2a864886f70d01010b");
        assert_eq!(der(oid::ECDSA_WITH_SHA384), "2a8648ce3d040303");
        assert_eq!(der(oid::PRIME256V1), "2a8648ce3d030107");
        assert_eq!(der(oid::SECP384R1), "2b81040022");
    }

    #[test]
    fn digest_names_and_oids_round_trip() {
        for alg in DigestAlgorithm::ALL {
            assert_eq!(DigestAlgorithm::from_name(alg.name()), Some(alg));
            assert_eq!(DigestAlgorithm::from_oid(alg.oid()), Some(alg));
            assert_eq!(alg.to_string(), alg.name());
        }
        assert_eq!(
            DigestAlgorithm::from_name("SHA-384"),
            Some(DigestAlgorithm::Sha384)
        );
        assert_eq!(
            DigestAlgorithm::from_name("Sha-1"),
            Some(DigestAlgorithm::Sha1)
        );
        assert_eq!(DigestAlgorithm::from_name("md5"), None);
        assert_eq!(DigestAlgorithm::from_name("sha-2-56"), None);
        assert_eq!(DigestAlgorithm::from_name("sha256-"), None);
        assert_eq!(DigestAlgorithm::from_name(""), None);
        assert_eq!(DigestAlgorithm::from_oid(oid::SHA256_WITH_RSA), None);
        assert!(DigestAlgorithm::Sha1.is_weak());
        assert!(!DigestAlgorithm::Sha256.is_weak());
    }

    #[test]
    fn signature_algorithm_names_and_oids() {
        for alg in [SignatureAlgorithm::RsaPkcs1v15, SignatureAlgorithm::Ecdsa] {
            assert_eq!(SignatureAlgorithm::from_name(alg.name()), Some(alg));
            assert_eq!(alg.to_string(), alg.name());
        }
        assert_eq!(SignatureAlgorithm::from_name("rsa-pss"), None);
        let rsa = SignatureAlgorithm::RsaPkcs1v15;
        let ec = SignatureAlgorithm::Ecdsa;
        assert_eq!(
            rsa.signature_oid(DigestAlgorithm::Sha256),
            oid::SHA256_WITH_RSA
        );
        assert_eq!(
            rsa.signature_oid(DigestAlgorithm::Sha512),
            oid::SHA512_WITH_RSA
        );
        assert_eq!(
            ec.signature_oid(DigestAlgorithm::Sha384),
            oid::ECDSA_WITH_SHA384
        );
        assert_eq!(
            ec.signature_oid(DigestAlgorithm::Sha1),
            oid::ECDSA_WITH_SHA1
        );
        assert_eq!(
            rsa.signature_name(DigestAlgorithm::Sha256),
            "sha256WithRSAEncryption"
        );
        assert_eq!(
            ec.signature_name(DigestAlgorithm::Sha512),
            "ecdsa-with-SHA512"
        );
    }

    #[test]
    fn key_kinds() {
        let rsa = KeyKind::Rsa { bits: 2048 };
        assert_eq!(rsa.algorithm(), SignatureAlgorithm::RsaPkcs1v15);
        assert_eq!(rsa.max_signature_len(), 256);
        assert_eq!(KeyKind::Rsa { bits: 2047 }.max_signature_len(), 256);
        assert_eq!(rsa.p1363_len(), None);
        assert_eq!(rsa.curve_oid(), None);
        assert_eq!(KeyKind::EcP256.algorithm(), SignatureAlgorithm::Ecdsa);
        assert_eq!(KeyKind::EcP256.max_signature_len(), 72);
        assert_eq!(KeyKind::EcP384.max_signature_len(), 104);
        assert_eq!(KeyKind::EcP256.p1363_len(), Some(64));
        assert_eq!(KeyKind::EcP384.p1363_len(), Some(96));
        assert_eq!(KeyKind::EcP384.curve_oid(), Some(oid::SECP384R1));
    }

    #[test]
    fn default_digests_and_signing_combinations() {
        assert_eq!(
            default_digest(KeyKind::Rsa { bits: 4096 }),
            DigestAlgorithm::Sha256
        );
        assert_eq!(default_digest(KeyKind::EcP256), DigestAlgorithm::Sha256);
        assert_eq!(default_digest(KeyKind::EcP384), DigestAlgorithm::Sha384);

        let signing = [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ];
        for kind in [
            KeyKind::Rsa { bits: 2048 },
            KeyKind::Rsa { bits: 8192 },
            KeyKind::EcP256,
            KeyKind::EcP384,
        ] {
            for digest in signing {
                check_signing_combination(kind, digest).unwrap();
            }
            let err = check_signing_combination(kind, DigestAlgorithm::Sha1).unwrap_err();
            assert_eq!(err.code(), folioxide_syntax::ErrorCode::InvalidArgument);
        }
        for bits in [0, 1024, 2047, 8193] {
            let err = check_signing_combination(KeyKind::Rsa { bits }, DigestAlgorithm::Sha256)
                .unwrap_err();
            assert!(matches!(err, Error::InvalidArgument(_)), "{bits}: {err}");
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_names_match_the_node_vocabulary() {
        use serde_json::{from_str, to_string};

        for alg in DigestAlgorithm::ALL {
            assert_eq!(to_string(&alg).unwrap(), format!("\"{}\"", alg.name()));
            assert_eq!(
                from_str::<DigestAlgorithm>(&to_string(&alg).unwrap()).unwrap(),
                alg
            );
        }
        for alg in [SignatureAlgorithm::RsaPkcs1v15, SignatureAlgorithm::Ecdsa] {
            assert_eq!(to_string(&alg).unwrap(), format!("\"{}\"", alg.name()));
            assert_eq!(
                from_str::<SignatureAlgorithm>(&to_string(&alg).unwrap()).unwrap(),
                alg
            );
        }
        let rsa = KeyKind::Rsa { bits: 2048 };
        assert_eq!(to_string(&rsa).unwrap(), r#"{"rsa":{"bits":2048}}"#);
        assert_eq!(
            from_str::<KeyKind>(r#"{"rsa":{"bits":2048}}"#).unwrap(),
            rsa
        );
        assert_eq!(to_string(&KeyKind::EcP256).unwrap(), "\"ecP256\"");
        assert_eq!(from_str::<KeyKind>("\"ecP384\"").unwrap(), KeyKind::EcP384);
    }
}

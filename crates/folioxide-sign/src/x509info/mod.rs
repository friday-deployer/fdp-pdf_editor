//! X.509 certificate information and trust evaluation (M3 brief §3.1, §5 V9).
//!
//! - [`certificate_info`]: the [`CertificateInfo`] DTO of a DER certificate (subject, issuer,
//!   serial, validity, fingerprint, key, key usages, CA flag), read with the lenient `Raw`
//!   profile so that one odd certificate never makes a report unreadable.
//! - [`certificate_key_kind`]: the [`KeyKind`] of a certificate's public key.
//! - [`build_trust`]: path building from a signer certificate through a pool of candidates to
//!   caller-supplied trust anchors, and validation of that path at a given [`UnixTime`]
//!   (RFC 5280 §6.1 without revocation, policies or name constraints; no network).

use folioxide_model::PdfDate;
use sha2::Digest as _;

use crate::algorithms::{KeyKind, oid};
use crate::error::Result;
use crate::keys::public::{curve_name, rsa_modulus_bits};
use crate::problem::Problem;

pub(crate) mod cert;
mod chain;

pub use chain::{
    KNOWN_CRITICAL_EXTENSIONS, MAX_CANDIDATES, MAX_COMPLETE_PATHS, MAX_EXPANSIONS,
    MAX_PATH_CERTIFICATES, MAX_SIGNATURE_CHECKS, MIN_RSA_TRUST_BITS,
};

/// Information about one X.509 certificate (RFC 5280), for reports and the Node binding.
///
/// With the `serde` feature its fields are `camelCase` (`serialHex`, `notBefore`, ...).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct CertificateInfo {
    /// The subject as RFC 4514 text, most specific RDN first, for example
    /// `"CN=Folioxide Test Signer RSA-2048,OU=TEST ONLY - DO NOT TRUST,O=Folioxide Test PKI"`
    /// (the order pdfsig prints).
    pub subject: String,
    /// The issuer as RFC 4514 text, in the same order.
    pub issuer: String,
    /// The subject's first common name (`CN`), if any.
    pub common_name: Option<String>,
    /// The serial number in uppercase hexadecimal, without separators or a sign byte.
    pub serial_hex: String,
    /// The start of the validity period, RFC 3339 UTC (`2026-01-01T00:00:00Z`).
    pub not_before: String,
    /// The end of the validity period, RFC 3339 UTC.
    pub not_after: String,
    /// The SHA-256 fingerprint of the exact DER, lowercase hexadecimal.
    pub sha256_hex: String,
    /// The subject public key.
    pub key: KeyDescription,
    /// The key usages (RFC 5280 §4.2.1.3) by their RFC names, for example `"digitalSignature"`,
    /// `"nonRepudiation"`; empty when the extension is absent.
    pub key_usage: Vec<String>,
    /// The extended key usages (RFC 5280 §4.2.1.12) as dotted OIDs; empty when absent.
    pub ext_key_usage: Vec<String>,
    /// Whether basicConstraints marks the certificate as a CA.
    pub is_ca: bool,
    /// The certificate's DER, exactly as given.
    pub der: Vec<u8>,
}

/// A certificate's public key.
///
/// With the `serde` feature it is `{"algorithm": "ec", "bits": 256, "curve": "P-256"}`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct KeyDescription {
    /// `"rsa"` or `"ec"`; for other keys, the dotted OID of the SubjectPublicKeyInfo algorithm.
    pub algorithm: String,
    /// The key size in bits: the RSA modulus length or the curve's field size; 0 when unknown.
    pub bits: u32,
    /// For EC keys, the curve: `"P-256"`, `"P-384"`, or the dotted OID of another named curve.
    pub curve: Option<String>,
}

impl KeyDescription {
    /// The [`KeyKind`] of this key when Folioxide can sign with or verify it: RSA, P-256 or
    /// P-384.
    ///
    /// ```
    /// use folioxide_sign::algorithms::KeyKind;
    /// use folioxide_sign::x509info::KeyDescription;
    ///
    /// let rsa = KeyDescription::new("rsa", 3072, None);
    /// assert_eq!(rsa.key_kind(), Some(KeyKind::Rsa { bits: 3072 }));
    /// assert_eq!(KeyDescription::new("ec", 521, Some("1.3.132.0.35")).key_kind(), None);
    /// ```
    pub fn key_kind(&self) -> Option<KeyKind> {
        match (self.algorithm.as_str(), self.curve.as_deref()) {
            ("rsa", _) => Some(KeyKind::Rsa { bits: self.bits }),
            ("ec", Some("P-256")) => Some(KeyKind::EcP256),
            ("ec", Some("P-384")) => Some(KeyKind::EcP384),
            _ => None,
        }
    }

    /// A key description from its parts.
    pub fn new(algorithm: &str, bits: u32, curve: Option<&str>) -> KeyDescription {
        KeyDescription {
            algorithm: algorithm.to_owned(),
            bits,
            curve: curve.map(str::to_owned),
        }
    }
}

/// The [`CertificateInfo`] of a DER certificate.
///
/// The certificate is read with the lenient `Raw` profile of `x509-cert` (for example, serial
/// numbers longer than 20 bytes are accepted), and its bytes are never re-encoded.
///
/// # Errors
/// [`Error::Certificate`](crate::Error::Certificate) when the bytes are not a certificate.
pub fn certificate_info(der: &[u8]) -> Result<CertificateInfo> {
    let parts = cert::CertParts::parse(der)?;
    let certificate = cert::decode(der)?;
    let tbs = certificate.tbs_certificate();

    let common_name = tbs.subject().iter().find_map(|atv| {
        (atv.oid == const_oid::db::rfc4519::CN).then(|| directory_string(&atv.value))?
    });
    let validity = tbs.validity();

    let mut key_usage = Vec::new();
    if let Ok(Some((_, ku))) = tbs.get_extension::<x509_cert::ext::pkix::KeyUsage>() {
        let names: [(bool, &str); 9] = [
            (ku.digital_signature(), "digitalSignature"),
            (ku.non_repudiation(), "nonRepudiation"),
            (ku.key_encipherment(), "keyEncipherment"),
            (ku.data_encipherment(), "dataEncipherment"),
            (ku.key_agreement(), "keyAgreement"),
            (ku.key_cert_sign(), "keyCertSign"),
            (ku.crl_sign(), "cRLSign"),
            (ku.encipher_only(), "encipherOnly"),
            (ku.decipher_only(), "decipherOnly"),
        ];
        key_usage = names
            .into_iter()
            .filter(|(set, _)| *set)
            .map(|(_, name)| name.to_owned())
            .collect();
    }
    let ext_key_usage = match tbs.get_extension::<x509_cert::ext::pkix::ExtendedKeyUsage>() {
        Ok(Some((_, eku))) => eku.0.iter().map(ToString::to_string).collect(),
        _ => Vec::new(),
    };
    let is_ca = matches!(
        tbs.get_extension::<x509_cert::ext::pkix::BasicConstraints>(),
        Ok(Some((_, bc))) if bc.ca
    );

    Ok(CertificateInfo {
        subject: tbs.subject().to_string(),
        issuer: tbs.issuer().to_string(),
        common_name,
        serial_hex: serial_hex(parts.serial_content),
        not_before: rfc3339(&validity.not_before),
        not_after: rfc3339(&validity.not_after),
        sha256_hex: sha2::Sha256::digest(der)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        key: key_description(parts.spki),
        key_usage,
        ext_key_usage,
        is_ca,
        der: der.to_vec(),
    })
}

/// The text of a `DirectoryString` (RFC 5280 §4.1.2.4) in the encodings certificates use.
fn directory_string(value: &der::Any) -> Option<String> {
    use der::asn1::{Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef};
    use der::{Tag, Tagged as _};
    match value.tag() {
        Tag::Utf8String => Utf8StringRef::try_from(value)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::PrintableString => PrintableStringRef::try_from(value)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::Ia5String => Ia5StringRef::try_from(value)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::TeletexString => TeletexStringRef::try_from(value)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::BmpString => {
            // UCS-2 big endian (X.680 §41.16).
            let units: Vec<u16> = value
                .value()
                .chunks_exact(2)
                .map(|pair| {
                    u16::from_be_bytes([
                        pair.first().copied().unwrap_or(0),
                        pair.get(1).copied().unwrap_or(0),
                    ])
                })
                .collect();
            String::from_utf16(&units).ok()
        }
        _ => None,
    }
}

/// The serial number content octets as uppercase hexadecimal without leading zero octets (the
/// sign padding of a positive INTEGER); `"00"` for zero.
fn serial_hex(content: &[u8]) -> String {
    let skip = content.iter().take_while(|&&b| b == 0).count();
    let significant = content.get(skip..).unwrap_or_default();
    if significant.is_empty() {
        return "00".to_owned();
    }
    significant.iter().map(|b| format!("{b:02X}")).collect()
}

/// A certificate time as RFC 3339 UTC, for example `2075-12-31T23:59:59Z`.
fn rfc3339(time: &x509_cert::time::Time) -> String {
    let t = time.to_date_time();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minutes(),
        t.seconds()
    )
}

/// The [`KeyDescription`] of a DER SubjectPublicKeyInfo; unknown parts are left empty rather
/// than failing, so any certificate can be described.
fn key_description(spki_der: &[u8]) -> KeyDescription {
    let Ok(info) = spki::SubjectPublicKeyInfoRef::try_from(spki_der) else {
        return KeyDescription::new("", 0, None);
    };
    let algorithm = info.algorithm.oid.to_string();
    match algorithm.as_str() {
        oid::RSA_ENCRYPTION | oid::RSASSA_PSS => {
            let bits = rsa_modulus_bits(info.subject_public_key.raw_bytes()).unwrap_or(0);
            KeyDescription::new("rsa", bits, None)
        }
        oid::EC_PUBLIC_KEY => {
            let curve = info.algorithm.parameters_oid().ok().map(|c| c.to_string());
            let bits = match curve.as_deref() {
                Some(oid::PRIME256V1) | Some("1.3.132.0.10") => 256,
                Some(oid::SECP384R1) => 384,
                Some("1.3.132.0.35") => 521,
                _ => 0,
            };
            let curve = curve.map(|c| match c.as_str() {
                oid::PRIME256V1 | oid::SECP384R1 => curve_name(&c),
                _ => c,
            });
            KeyDescription::new("ec", bits, curve.as_deref())
        }
        other => KeyDescription::new(other, 0, None),
    }
}

/// The [`KeyKind`] of a DER certificate's public key: what `prepare` records for the signer
/// certificate and what sizes the CMS.
///
/// # Errors
/// [`Error::Certificate`](crate::Error::Certificate) when the certificate or its key does not
/// parse, [`Error::Unsupported`](crate::Error::Unsupported) for keys other than RSA, P-256 and
/// P-384.
pub fn certificate_key_kind(der: &[u8]) -> Result<KeyKind> {
    Ok(cert::CertParts::parse(der)?.public_key()?.kind())
}

/// A point in time: whole seconds since 1970-01-01T00:00:00Z, ignoring leap seconds (POSIX
/// time). Trust is evaluated at an explicit time because the core has no clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(pub i64);

impl UnixTime {
    /// The time `secs` seconds after 1970-01-01T00:00:00Z (negative: before).
    pub const fn from_secs(secs: i64) -> UnixTime {
        UnixTime(secs)
    }

    /// Seconds since 1970-01-01T00:00:00Z.
    pub const fn secs(self) -> i64 {
        self.0
    }

    /// The instant a PDF date names (ISO 32000-2 §7.9.4). A date without a UTC offset is read
    /// as UTC.
    ///
    /// The fields are used as they are, so a date that [`PdfDate::new`] would reject (a month
    /// of 13) gives a meaningless but well-defined time; it never panics.
    ///
    /// ```
    /// use folioxide_model::PdfDate;
    /// use folioxide_sign::x509info::UnixTime;
    ///
    /// let date = PdfDate::parse(b"D:20261010120000+02'00'").unwrap();
    /// assert_eq!(UnixTime::from_pdf_date(&date), UnixTime(1_791_626_400));
    /// ```
    pub fn from_pdf_date(date: &PdfDate) -> UnixTime {
        let days = days_from_civil(
            i64::from(date.year),
            i64::from(date.month),
            i64::from(date.day),
        );
        let seconds_of_day =
            i64::from(date.hour) * 3600 + i64::from(date.minute) * 60 + i64::from(date.second);
        // A local time is UTC + offset, so UTC = local − offset (§7.9.4).
        let offset = i64::from(date.offset_minutes.unwrap_or(0)) * 60;
        UnixTime(days * 86_400 + seconds_of_day - offset)
    }
}

/// Days from 1970-01-01 to the proleptic Gregorian date `y-m-d` (Howard Hinnant's
/// `days_from_civil`). Every intermediate value stays far inside `i64` for `u16` years.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400; // [0, 399]
    let mp = (month + 9).rem_euclid(12); // March = 0
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The result of [`build_trust`].
///
/// `trusted` is true exactly when `reasons` is empty and `path` is not.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustResult {
    /// A path from the signer to a trust anchor was found, and every check on it passed.
    pub trusted: bool,
    /// The path that was validated (DER), signer first, anchor last: the trusted path, or else
    /// the first complete path that failed validation; empty when no path reaches an anchor.
    /// When the signer is itself an anchor, the path is the signer alone.
    pub path: Vec<Vec<u8>>,
    /// Why the signer is not trusted, one sentence each; empty when it is.
    pub reasons: Vec<String>,
    /// Observations that do not affect trust (ignored candidate certificates).
    pub warnings: Vec<String>,
    /// Typed problems for the signature report: [`WeakAlgorithm`](crate::ProblemCode::WeakAlgorithm)
    /// when a certificate of the path (or the only candidate issuer) is signed with MD2, MD5 or
    /// SHA-1, or the path uses an RSA key below [`MIN_RSA_TRUST_BITS`].
    pub problems: Vec<Problem>,
}

/// Builds and checks a certification path from `signer_der` through `pool` to one of
/// `anchors`, at time `at` (brief §5 V9; decisions D-10, D-12, D-16).
///
/// - **Building:** a bounded depth-first search over the anchors, then the pool (for a PDF
///   signature: the CMS certificates plus the caller's extra certificates), matching each
///   certificate's issuer name to a candidate's subject and verifying the signature with the
///   candidate's key (RSA PKCS#1 v1.5, RSA-PSS, ECDSA P-256/P-384). At most
///   [`MAX_PATH_CERTIFICATES`] certificates below the anchor and [`MAX_CANDIDATES`] candidates
///   are considered.
/// - **Validation:** every certificate below the anchor must be valid at `at` and free of
///   unknown critical extensions ([`KNOWN_CRITICAL_EXTENSIONS`]), and must not be signed with a
///   weak hash (MD2, MD5, SHA-1: problem `WeakAlgorithm`); issuers need `basicConstraints cA`
///   (with every `pathLenConstraint` respected) and, when key usage is present, `keyCertSign`;
///   the signer's key usage, when present, needs digitalSignature **or** nonRepudiation (D-10;
///   pyHanko accepts nonRepudiation only).
/// - The anchor contributes only its name and key (RFC 5280 §6.1.1 (d)): its own validity and
///   extensions are not checked. A signer that is itself an anchor is trusted when its own
///   checks pass.
/// - RSA keys of 1024 to 8192 bits verify (D-12), but an RSA key below
///   [`MIN_RSA_TRUST_BITS`] (2048) for the signer or any issuer, the anchor included, makes the
///   path untrusted with `WeakAlgorithm`, as in pyHanko.
///
/// There is no revocation checking, no policy or name-constraint processing and no network
/// access. The function never panics and never fails: every defect is a reason.
///
/// ```
/// use folioxide_sign::x509info::{UnixTime, build_trust};
///
/// // Without anchors nothing is trusted.
/// let result = build_trust(b"not a certificate", &[], &[], UnixTime(0));
/// assert!(!result.trusted);
/// assert!(result.path.is_empty());
/// assert!(!result.reasons.is_empty());
/// ```
pub fn build_trust(
    signer_der: &[u8],
    pool: &[Vec<u8>],
    anchors: &[Vec<u8>],
    at: UnixTime,
) -> TrustResult {
    chain::build_trust(signer_der, pool, anchors, at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_time_from_pdf_dates() {
        let parse = |s: &str| UnixTime::from_pdf_date(&PdfDate::parse(s.as_bytes()).unwrap());
        assert_eq!(parse("D:19700101000000Z"), UnixTime(0));
        assert_eq!(parse("D:20000301000000Z"), UnixTime(951_868_800));
        assert_eq!(parse("D:20261010120000Z"), UnixTime(1_791_633_600));
        // Without an offset the time is read as UTC.
        assert_eq!(parse("D:20261010120000"), UnixTime(1_791_633_600));
        assert_eq!(parse("D:20261010120000+02'00'"), UnixTime(1_791_626_400));
        assert_eq!(parse("D:20261010120000-05'30'"), UnixTime(1_791_653_400));
        assert_eq!(parse("D:19691231235959Z"), UnixTime(-1));
        // 2024 is a leap year: 29 February exists.
        assert_eq!(
            parse("D:20240301000000Z").secs() - parse("D:20240228000000Z").secs(),
            2 * 86_400
        );
        assert_eq!(UnixTime::from_secs(42).secs(), 42);
    }

    #[test]
    fn unix_time_never_panics_on_odd_fields() {
        let mut date = PdfDate::parse(b"D:20261010120000Z").unwrap();
        for (month, day, offset) in [
            (0, 0, Some(i32::MIN)),
            (13, 99, Some(i32::MAX)),
            (255, 255, None),
        ] {
            date.month = month;
            date.day = day;
            date.offset_minutes = offset;
            date.year = u16::MAX;
            let _ = UnixTime::from_pdf_date(&date);
            date.year = 0;
            let _ = UnixTime::from_pdf_date(&date);
        }
    }

    #[test]
    fn key_descriptions() {
        assert_eq!(
            KeyDescription::new("ec", 256, Some("P-256")).key_kind(),
            Some(KeyKind::EcP256)
        );
        assert_eq!(
            KeyDescription::new("ec", 384, Some("P-384")).key_kind(),
            Some(KeyKind::EcP384)
        );
        assert_eq!(KeyDescription::new("ec", 0, None).key_kind(), None);
        assert_eq!(KeyDescription::new("1.3.101.112", 0, None).key_kind(), None);
    }

    #[test]
    fn trust_without_inputs_is_untrusted() {
        let result = build_trust(&[], &[], &[], UnixTime(0));
        assert!(!result.trusted);
        assert!(result.path.is_empty());
        assert_eq!(result.reasons.len(), 1);
        assert!(result.problems.is_empty());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn certificate_info_serde_is_camel_case() {
        let info = CertificateInfo {
            subject: "CN=a".into(),
            issuer: "CN=b".into(),
            common_name: Some("a".into()),
            serial_hex: "01".into(),
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after: "2027-01-01T00:00:00Z".into(),
            sha256_hex: "00".into(),
            key: KeyDescription::new("ec", 256, Some("P-256")),
            key_usage: vec!["digitalSignature".into()],
            ext_key_usage: vec![],
            is_ca: false,
            der: vec![0x30, 0x00],
        };
        let json = serde_json::to_value(&info).unwrap();
        for key in [
            "subject",
            "issuer",
            "commonName",
            "serialHex",
            "notBefore",
            "notAfter",
            "sha256Hex",
            "key",
            "keyUsage",
            "extKeyUsage",
            "isCa",
            "der",
        ] {
            assert!(json.get(key).is_some(), "missing {key}: {json}");
        }
        assert_eq!(json["key"]["curve"], "P-256");
        let back: CertificateInfo = serde_json::from_value(json).unwrap();
        assert_eq!(back, info);
    }
}

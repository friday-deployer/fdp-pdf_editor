//! Verification problems: why a signature is not valid (M3 brief §3.2 `ProblemCode`, §5; M4
//! brief §3.3 adds the timestamp and DocMDP codes).
//!
//! A [`Problem`] is a machine-readable [`ProblemCode`] plus a human-readable message. The CMS
//! verifier ([`cms::verify_detached`](crate::cms::verify_detached)) and the PDF verifier both
//! report them, so the type lives at the crate root and is shared by both.

use std::fmt;

/// The category of a verification problem (M3 brief §3.2, M4 brief §3.3).
///
/// With the `serde` feature it is the `camelCase` string [`ProblemCode::as_str`] returns, for
/// example `"byteRangeMissing"`. The enum is `#[non_exhaustive]`: match it with a wildcard arm.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum ProblemCode {
    // Signature dictionary and /ByteRange (ISO 32000-2 §12.8.1; brief §5 V1–V5).
    /// A field's `/V` is not an indirect reference.
    SigValueNotIndirect,
    /// A field's `/V` does not resolve to a dictionary.
    SigDictNotDictionary,
    /// The signature dictionary has no `/ByteRange`.
    ByteRangeMissing,
    /// `/ByteRange` is an indirect object (it could live in an unsigned later revision).
    ByteRangeIndirect,
    /// `/ByteRange` is not an array of exactly four non-negative integers with `o1 + l1 < o2`.
    ByteRangeMalformed,
    /// The first signed range does not start at byte 0.
    ByteRangeNotFromZero,
    /// A signed range ends past the end of the file.
    ByteRangeOutOfBounds,
    /// The signature dictionary has no `/Contents`.
    ContentsMissing,
    /// `/Contents` is not a direct hexadecimal string.
    ContentsNotHex,
    /// The gap between the signed ranges is not exactly this dictionary's `/Contents` token
    /// (signature wrapping).
    GapNotContents,
    /// The signature dictionary is stored in an object stream, so its `/Contents` cannot be
    /// excluded from the signed bytes.
    SigDictCompressed,
    /// The signature dictionary lies outside the signed bytes.
    SigDictOutsideSignedRange,
    /// A later revision redefines the signature dictionary.
    SigDictRedefinedLater,
    /// The signature dictionary or its field (with its `/Lock` and DocMDP `/Reference`) is not
    /// written canonically, so readers differ on what it holds: an entry written twice or a
    /// dictionary with a duplicate key (ISO 32000-2 §7.3.7; pyHanko keeps the first value,
    /// Folioxide's parser the last; M4 QA round 2, finding 8), or, since manager ruling R-12,
    /// any value the canonical-input gate refuses (a number with two signs or an exponent, an
    /// integer beyond ±2,147,483,647 or longer than 11 characters, a real longer than 40
    /// characters or beyond ±3.403 × 10³⁸, a name with `#00`, a token the lexer repairs: `/P
    /// 4294967298` is one). It decides which bytes are signed when it is `/ByteRange` or
    /// `/Contents` (the signature is then not intact), or which signature the field holds. An
    /// ambiguous `/Reference` or field `/Lock` is `DocMdpInvalid` too, with `P = 1` in force.
    SigDictAmbiguous,
    /// The signed bytes end at a revision that the newest revision's `/Prev` chain skips.
    SignedRevisionNotInChain,

    // CMS structure (RFC 5652; brief §5 V7).
    /// `/Contents` does not hold a parsable CMS ContentInfo.
    CmsMalformed,
    /// The ContentInfo is not `id-signedData`.
    NotSignedData,
    /// The SignedData has no SignerInfo or more than one.
    SignerInfoCount,
    /// A detached signature carries encapsulated content.
    EContentPresent,
    /// The content-type attribute is missing, repeated or differs from the eContentType.
    ContentTypeMismatch,
    /// The message-digest attribute is missing or repeated.
    MessageDigestMissing,
    /// The digest of the signed bytes differs from the message-digest attribute.
    DigestMismatch,
    /// No certificate matches the SignerInfo's `sid`.
    SignerCertNotFound,
    /// The ESS signing-certificate(-v2) attribute does not match the signer certificate.
    SigningCertificateMismatch,
    /// The CMSAlgorithmProtection attribute (RFC 6211) does not match the algorithms used.
    AlgorithmProtectionMismatch,

    // Algorithms and SubFilter.
    /// The hash of `signatureAlgorithm` differs from `digestAlgorithm`.
    DigestSignatureAlgorithmMismatch,
    /// The digest, signature algorithm, key type or curve is not implemented.
    UnsupportedAlgorithm,
    /// The `/SubFilter` is not one Folioxide verifies.
    UnsupportedSubFilter,
    /// The signature value does not verify with the signer certificate's public key.
    SignatureInvalid,
    /// A weak algorithm (SHA-1) is used; the signature is never trusted.
    WeakAlgorithm,

    // State of the file.
    /// The file's structure was repaired while reading, so changes after the signed revision
    /// cannot be attributed.
    StructureRepaired,
    /// A signature dictionary that no signature field references.
    Orphan,
    /// A document timestamp that is listed but not verified (M3). Retired by M4 (DECISIONS D13
    /// D-19): kept in the enum, and no longer reported once document timestamps are verified
    /// (M4 brief §5 V1).
    PendingTimestampVerification,

    // RFC 3161 timestamps (M4 brief §3.3, §5 V7b and V7c). For a signature timestamp these are
    // in `TimestampInfo::problems` (DECISIONS D13 D-6); for a document timestamp, whose token is
    // the signature, in the report's own problems.
    /// A timestamp token is not a SignedData with exactly one SignerInfo, eContentType
    /// `id-ct-TSTInfo` and eContent, something it carries is not what RFC 3161 and RFC 5652
    /// allow or does not decode (its SignedData or SignerInfo version, its digest algorithms,
    /// a certificate, an encoding; M4 QA round 1 findings F5, F6), or its TSTInfo does not
    /// decode or is not version 1 (V7b steps 1 and 2).
    TimestampMalformed,
    /// The token's `messageImprint` is not the digest of the timestamped data: the signature
    /// value for a signature timestamp, the signed byte ranges for a document timestamp, or its
    /// hash algorithm has parameters other than NULL (RFC 5754 §2; V7b step 3).
    TimestampImprintMismatch,
    /// The TSA's CMS signature over the TSTInfo does not verify (V7b step 4).
    TimestampSignatureInvalid,
    /// The token has no ESS signing-certificate (v1 or v2) attribute, or one of them does not
    /// identify the TSA certificate first and certificates of its chain after it (RFC 3161
    /// §2.4.1, RFC 5816, as OpenSSL checks; V7b step 5).
    TimestampEssMismatch,
    /// The TSA certificate is not suitable for timestamping: the extended key usage is not
    /// exactly a critical `id-kp-timeStamping`, or the key usage allows more than
    /// digitalSignature and nonRepudiation (RFC 3161 §2.3, OpenSSL's purpose check; DECISIONS
    /// D13 D-4; V7b step 6); or OpenSSL refuses the certificate in any chain: an extension type
    /// twice, a known extension that does not decode (manager ruling R-22 (c)), or a critical
    /// extension OpenSSL does not handle, such as a critical key identifier (M4 closing round,
    /// findings 8 and 11).
    TsaCertificateUnsuitable,
    /// The token's `genTime` is outside the TSA certificate's validity period (RFC 3161 §2.4.2;
    /// V7b step 7).
    TsaCertificateNotValidAtGenTime,
    /// The TSTInfo `tsa` field names a TSA that is not the TSA certificate: neither its subject
    /// nor one of its subjectAltName entries (RFC 3161 §2.4.2 "MUST correspond to one of the
    /// subject names included in the certificate"; OpenSSL's `ts_check_signer_name`; M4 QA
    /// round 1 finding F2).
    TsaNameMismatch,

    // DocMDP (ISO 32000-2 §12.8.2.2; M4 brief §5 V11).
    /// The DocMDP declaration cannot be read: `/P` is not 1, 2 or 3, the transform parameters
    /// are not a dictionary, the signature dictionary has more than one DocMDP reference, its
    /// `/Reference` is not an array of reference dictionaries with a `/TransformMethod` name,
    /// or the field's lock dictionary (or its `/P`) is malformed. `P = 1` is then in force for
    /// `docmdp_ok` (pyHanko raises on each).
    DocMdpInvalid,
    /// A certification (DocMDP) signature is not the first signed field of the document
    /// (§12.8.2.2.1: "it shall be the first signed field").
    CertificationNotFirst,
}

impl ProblemCode {
    /// Every problem code, in declaration order.
    pub const ALL: &'static [ProblemCode] = &[
        ProblemCode::SigValueNotIndirect,
        ProblemCode::SigDictNotDictionary,
        ProblemCode::ByteRangeMissing,
        ProblemCode::ByteRangeIndirect,
        ProblemCode::ByteRangeMalformed,
        ProblemCode::ByteRangeNotFromZero,
        ProblemCode::ByteRangeOutOfBounds,
        ProblemCode::ContentsMissing,
        ProblemCode::ContentsNotHex,
        ProblemCode::GapNotContents,
        ProblemCode::SigDictCompressed,
        ProblemCode::SigDictOutsideSignedRange,
        ProblemCode::SigDictRedefinedLater,
        ProblemCode::SigDictAmbiguous,
        ProblemCode::SignedRevisionNotInChain,
        ProblemCode::CmsMalformed,
        ProblemCode::NotSignedData,
        ProblemCode::SignerInfoCount,
        ProblemCode::EContentPresent,
        ProblemCode::ContentTypeMismatch,
        ProblemCode::MessageDigestMissing,
        ProblemCode::DigestMismatch,
        ProblemCode::SignerCertNotFound,
        ProblemCode::SigningCertificateMismatch,
        ProblemCode::AlgorithmProtectionMismatch,
        ProblemCode::DigestSignatureAlgorithmMismatch,
        ProblemCode::UnsupportedAlgorithm,
        ProblemCode::UnsupportedSubFilter,
        ProblemCode::SignatureInvalid,
        ProblemCode::WeakAlgorithm,
        ProblemCode::StructureRepaired,
        ProblemCode::Orphan,
        ProblemCode::PendingTimestampVerification,
        ProblemCode::TimestampMalformed,
        ProblemCode::TimestampImprintMismatch,
        ProblemCode::TimestampSignatureInvalid,
        ProblemCode::TimestampEssMismatch,
        ProblemCode::TsaCertificateUnsuitable,
        ProblemCode::TsaCertificateNotValidAtGenTime,
        ProblemCode::TsaNameMismatch,
        ProblemCode::DocMdpInvalid,
        ProblemCode::CertificationNotFirst,
    ];

    /// The code as a `camelCase` string, for example `"byteRangeMissing"`: the JSON value and
    /// the Node binding's `problems[].code`.
    pub const fn as_str(self) -> &'static str {
        match self {
            ProblemCode::SigValueNotIndirect => "sigValueNotIndirect",
            ProblemCode::SigDictNotDictionary => "sigDictNotDictionary",
            ProblemCode::ByteRangeMissing => "byteRangeMissing",
            ProblemCode::ByteRangeIndirect => "byteRangeIndirect",
            ProblemCode::ByteRangeMalformed => "byteRangeMalformed",
            ProblemCode::ByteRangeNotFromZero => "byteRangeNotFromZero",
            ProblemCode::ByteRangeOutOfBounds => "byteRangeOutOfBounds",
            ProblemCode::ContentsMissing => "contentsMissing",
            ProblemCode::ContentsNotHex => "contentsNotHex",
            ProblemCode::GapNotContents => "gapNotContents",
            ProblemCode::SigDictCompressed => "sigDictCompressed",
            ProblemCode::SigDictOutsideSignedRange => "sigDictOutsideSignedRange",
            ProblemCode::SigDictRedefinedLater => "sigDictRedefinedLater",
            ProblemCode::SigDictAmbiguous => "sigDictAmbiguous",
            ProblemCode::SignedRevisionNotInChain => "signedRevisionNotInChain",
            ProblemCode::CmsMalformed => "cmsMalformed",
            ProblemCode::NotSignedData => "notSignedData",
            ProblemCode::SignerInfoCount => "signerInfoCount",
            ProblemCode::EContentPresent => "eContentPresent",
            ProblemCode::ContentTypeMismatch => "contentTypeMismatch",
            ProblemCode::MessageDigestMissing => "messageDigestMissing",
            ProblemCode::DigestMismatch => "digestMismatch",
            ProblemCode::SignerCertNotFound => "signerCertNotFound",
            ProblemCode::SigningCertificateMismatch => "signingCertificateMismatch",
            ProblemCode::AlgorithmProtectionMismatch => "algorithmProtectionMismatch",
            ProblemCode::DigestSignatureAlgorithmMismatch => "digestSignatureAlgorithmMismatch",
            ProblemCode::UnsupportedAlgorithm => "unsupportedAlgorithm",
            ProblemCode::UnsupportedSubFilter => "unsupportedSubFilter",
            ProblemCode::SignatureInvalid => "signatureInvalid",
            ProblemCode::WeakAlgorithm => "weakAlgorithm",
            ProblemCode::StructureRepaired => "structureRepaired",
            ProblemCode::Orphan => "orphan",
            ProblemCode::PendingTimestampVerification => "pendingTimestampVerification",
            ProblemCode::TimestampMalformed => "timestampMalformed",
            ProblemCode::TimestampImprintMismatch => "timestampImprintMismatch",
            ProblemCode::TimestampSignatureInvalid => "timestampSignatureInvalid",
            ProblemCode::TimestampEssMismatch => "timestampEssMismatch",
            ProblemCode::TsaCertificateUnsuitable => "tsaCertificateUnsuitable",
            ProblemCode::TsaCertificateNotValidAtGenTime => "tsaCertificateNotValidAtGenTime",
            ProblemCode::TsaNameMismatch => "tsaNameMismatch",
            ProblemCode::DocMdpInvalid => "docMdpInvalid",
            ProblemCode::CertificationNotFirst => "certificationNotFirst",
        }
    }
}

impl fmt::Display for ProblemCode {
    /// Writes [`ProblemCode::as_str`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One verification problem: a stable [`ProblemCode`] and a message for people.
///
/// With the `serde` feature it is `{"code": "digestMismatch", "message": "…"}`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct Problem {
    /// The category.
    pub code: ProblemCode,
    /// What exactly was wrong, in English.
    pub message: String,
}

impl Problem {
    /// A problem with `code` and `message`.
    ///
    /// ```
    /// use folioxide_sign::{Problem, ProblemCode};
    ///
    /// let p = Problem::new(ProblemCode::DigestMismatch, "the signed bytes were changed");
    /// assert_eq!(p.to_string(), "digestMismatch: the signed bytes were changed");
    /// ```
    pub fn new(code: ProblemCode, message: impl Into<String>) -> Problem {
        Problem {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for Problem {
    /// Writes `code: message`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_camel_case_and_unique() {
        let mut seen = std::collections::HashSet::new();
        assert_eq!(ProblemCode::ALL.len(), 42);
        for code in ProblemCode::ALL {
            let s = code.as_str();
            assert!(seen.insert(s), "duplicate {s}");
            assert!(s.starts_with(|c: char| c.is_ascii_lowercase()), "{s}");
            assert!(s.chars().all(|c| c.is_ascii_alphanumeric()), "{s}");
            // camelCase of the variant name: the Debug text with its first letter lowered.
            let debug = format!("{code:?}");
            let mut chars = debug.chars();
            let first = chars.next().unwrap().to_ascii_lowercase();
            assert_eq!(s, format!("{first}{}", chars.as_str()));
            assert_eq!(code.to_string(), s);
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_uses_the_camel_case_codes() {
        for &code in ProblemCode::ALL {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            assert_eq!(serde_json::from_str::<ProblemCode>(&json).unwrap(), code);
        }
        let problem = Problem::new(ProblemCode::GapNotContents, "gap");
        let json = serde_json::to_string(&problem).unwrap();
        assert_eq!(json, r#"{"code":"gapNotContents","message":"gap"}"#);
        assert_eq!(serde_json::from_str::<Problem>(&json).unwrap(), problem);
    }
}

//! Verification problems: why a signature is not valid (M3 brief §3.2 `ProblemCode`, §5).
//!
//! A [`Problem`] is a machine-readable [`ProblemCode`] plus a human-readable message. The CMS
//! verifier ([`cms::verify_detached`](crate::cms::verify_detached)) and the PDF verifier both
//! report them, so the type lives at the crate root and is shared by both.

use std::fmt;

/// The category of a verification problem (M3 brief §3.2).
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
    /// A document timestamp, which M3 lists but does not verify (M4).
    PendingTimestampVerification,
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
        assert_eq!(ProblemCode::ALL.len(), 32);
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

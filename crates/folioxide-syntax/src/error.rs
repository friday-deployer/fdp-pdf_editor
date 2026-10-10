//! The error vocabulary shared by every Folioxide crate (ARCHITECTURE §A.4).
//!
//! [`ErrorCode`] is defined once, here, and every crate's error type exposes
//! `fn code(&self) -> ErrorCode`. The Node binding maps a code to a JavaScript error code by
//! prefixing `E_`, for example [`ErrorCode::WrongPassword`] becomes `"E_WRONG_PASSWORD"`.
//!
//! [`Error`] is the error type of this crate. Errors caused by input bytes carry the byte offset
//! (relative to the buffer that was being parsed) where the problem was detected.

use std::borrow::Cow;
use std::fmt;

use crate::filters::FilterError;
use crate::limits::LimitKind;
use crate::object::ObjectId;

/// A stable, machine-readable error category.
///
/// The list is shared by all Folioxide crates, so it contains codes this crate never produces
/// itself (for example [`ErrorCode::Font`]). It is `#[non_exhaustive]`: match it with a wildcard
/// arm. With the crate feature `serde`, codes serialize as `SCREAMING_SNAKE_CASE` strings, the
/// same text [`ErrorCode::as_str`] returns.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "SCREAMING_SNAKE_CASE")
)]
pub enum ErrorCode {
    /// Malformed PDF syntax (ISO 32000-2 §7.2–7.3).
    Syntax,
    /// A broken or unusable cross-reference table, stream or trailer (§7.5).
    Xref,
    /// A required object does not exist.
    MissingObject,
    /// An object has the wrong type for its role, for example a `/Pages` entry that is not a
    /// dictionary.
    TypeMismatch,
    /// A configured [`Limits`](crate::Limits) value was exceeded.
    LimitExceeded,
    /// A stream filter failed to decode its data (§7.4).
    Filter,
    /// The input uses a feature this version does not support.
    Unsupported,
    /// The document is encrypted and a password is needed to open it.
    PasswordRequired,
    /// The supplied password is wrong.
    WrongPassword,
    /// The document's permissions forbid the requested operation.
    PermissionDenied,
    /// The caller passed an invalid argument.
    InvalidArgument,
    /// A page index is out of range.
    PageOutOfRange,
    /// A named item (field, annotation, attachment, ...) was not found.
    NotFound,
    /// A font could not be parsed, embedded or subset.
    Font,
    /// An image could not be decoded or embedded.
    Image,
    /// A cryptographic operation failed.
    Crypto,
    /// A private key could not be loaded.
    KeyLoad,
    /// A certificate could not be parsed or is unusable.
    Certificate,
    /// The space reserved for a signature is too small for the signature value.
    SignaturePlaceholderTooSmall,
    /// A signature is cryptographically invalid.
    SignatureInvalid,
    /// The document's DocMDP permissions forbid the change.
    DocMdpForbids,
    /// A timestamp token is invalid.
    TimestampInvalid,
    /// An I/O operation failed.
    Io,
}

impl ErrorCode {
    /// Every error code, in declaration order.
    pub const ALL: &'static [ErrorCode] = &[
        ErrorCode::Syntax,
        ErrorCode::Xref,
        ErrorCode::MissingObject,
        ErrorCode::TypeMismatch,
        ErrorCode::LimitExceeded,
        ErrorCode::Filter,
        ErrorCode::Unsupported,
        ErrorCode::PasswordRequired,
        ErrorCode::WrongPassword,
        ErrorCode::PermissionDenied,
        ErrorCode::InvalidArgument,
        ErrorCode::PageOutOfRange,
        ErrorCode::NotFound,
        ErrorCode::Font,
        ErrorCode::Image,
        ErrorCode::Crypto,
        ErrorCode::KeyLoad,
        ErrorCode::Certificate,
        ErrorCode::SignaturePlaceholderTooSmall,
        ErrorCode::SignatureInvalid,
        ErrorCode::DocMdpForbids,
        ErrorCode::TimestampInvalid,
        ErrorCode::Io,
    ];

    /// The code as a `SCREAMING_SNAKE_CASE` string, for example `"WRONG_PASSWORD"`.
    ///
    /// ```
    /// use folioxide_syntax::ErrorCode;
    ///
    /// assert_eq!(ErrorCode::DocMdpForbids.as_str(), "DOC_MDP_FORBIDS");
    /// ```
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Syntax => "SYNTAX",
            ErrorCode::Xref => "XREF",
            ErrorCode::MissingObject => "MISSING_OBJECT",
            ErrorCode::TypeMismatch => "TYPE_MISMATCH",
            ErrorCode::LimitExceeded => "LIMIT_EXCEEDED",
            ErrorCode::Filter => "FILTER",
            ErrorCode::Unsupported => "UNSUPPORTED",
            ErrorCode::PasswordRequired => "PASSWORD_REQUIRED",
            ErrorCode::WrongPassword => "WRONG_PASSWORD",
            ErrorCode::PermissionDenied => "PERMISSION_DENIED",
            ErrorCode::InvalidArgument => "INVALID_ARGUMENT",
            ErrorCode::PageOutOfRange => "PAGE_OUT_OF_RANGE",
            ErrorCode::NotFound => "NOT_FOUND",
            ErrorCode::Font => "FONT",
            ErrorCode::Image => "IMAGE",
            ErrorCode::Crypto => "CRYPTO",
            ErrorCode::KeyLoad => "KEY_LOAD",
            ErrorCode::Certificate => "CERTIFICATE",
            ErrorCode::SignaturePlaceholderTooSmall => "SIGNATURE_PLACEHOLDER_TOO_SMALL",
            ErrorCode::SignatureInvalid => "SIGNATURE_INVALID",
            ErrorCode::DocMdpForbids => "DOC_MDP_FORBIDS",
            ErrorCode::TimestampInvalid => "TIMESTAMP_INVALID",
            ErrorCode::Io => "IO",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// An error from the syntax layer.
///
/// Match on [`Error::code`] for a stable category; the variants carry details for messages and
/// diagnostics. Offsets are byte positions in the buffer that was being parsed (the whole file
/// for top-level objects, the decoded container for objects inside an object stream).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Malformed syntax at `offset` (ISO 32000-2 §7.2–7.3).
    #[error("syntax error at byte {offset}: {message}")]
    Syntax {
        /// Byte offset where the problem was detected.
        offset: u64,
        /// What was wrong.
        message: Cow<'static, str>,
    },
    /// The data ended in the middle of a token or object.
    #[error("unexpected end of data at byte {offset} while reading {context}")]
    UnexpectedEof {
        /// Byte offset of the end of the data.
        offset: u64,
        /// What was being read, for example `"literal string"`.
        context: &'static str,
    },
    /// A configured limit was exceeded.
    #[error("limit {limit} = {max} exceeded{}", at(.offset))]
    LimitExceeded {
        /// The limit that was exceeded.
        limit: LimitKind,
        /// The configured value of that limit.
        max: u64,
        /// Byte offset where the limit was hit, if the input position is meaningful.
        offset: Option<u64>,
    },
    /// An object had the wrong type.
    #[error("type mismatch: expected {expected}, found {found}{}", at(.offset))]
    TypeMismatch {
        /// The expected type, for example `"dictionary"`.
        expected: &'static str,
        /// The type that was found, as given by [`Object::type_name`](crate::Object::type_name).
        found: &'static str,
        /// Byte offset of the object, if known.
        offset: Option<u64>,
    },
    /// The cross-reference data or trailer is unusable (§7.5).
    #[error("cross-reference error{}: {message}", at(.offset))]
    Xref {
        /// Byte offset where the problem was detected, if known.
        offset: Option<u64>,
        /// What was wrong.
        message: Cow<'static, str>,
    },
    /// An object that must exist does not.
    #[error("object {id} not found")]
    MissingObject {
        /// The missing object's identifier.
        id: ObjectId,
    },
    /// The input uses a feature that is not supported.
    #[error("unsupported: {message}")]
    Unsupported {
        /// What is not supported.
        message: Cow<'static, str>,
    },
    /// The caller passed an invalid argument.
    #[error("invalid argument: {message}")]
    InvalidArgument {
        /// What was wrong with the argument.
        message: Cow<'static, str>,
    },
    /// A stream filter could not decode its data (§7.4).
    ///
    /// The code depends on the filter error ([`Error::code`]): corrupt data and invalid
    /// `/DecodeParms` are [`ErrorCode::Filter`], a decoding limit is
    /// [`ErrorCode::LimitExceeded`], and a filter this layer does not decode is
    /// [`ErrorCode::Unsupported`].
    #[error("stream filter error{}: {source}", at(.offset))]
    Filter {
        /// Byte offset of the stream data in the source, if known.
        offset: Option<u64>,
        /// The filter error.
        source: FilterError,
    },
    /// Any other error, identified by its [`ErrorCode`].
    #[error("{message}{}", at(.offset))]
    Other {
        /// The error category.
        code: ErrorCode,
        /// Byte offset where the problem was detected, if meaningful.
        offset: Option<u64>,
        /// What went wrong.
        message: Cow<'static, str>,
    },
}

/// Formats an optional offset as `" at byte N"`, or nothing.
fn at(offset: &Option<u64>) -> AtOffset {
    AtOffset(*offset)
}

struct AtOffset(Option<u64>);

impl fmt::Display for AtOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(offset) => write!(f, " at byte {offset}"),
            None => Ok(()),
        }
    }
}

impl Error {
    /// Creates an error with the given code and message and no offset.
    ///
    /// ```
    /// use folioxide_syntax::{Error, ErrorCode};
    ///
    /// let err = Error::new(ErrorCode::PasswordRequired, "the document is encrypted");
    /// assert_eq!(err.code(), ErrorCode::PasswordRequired);
    /// assert_eq!(err.offset(), None);
    /// ```
    pub fn new(code: ErrorCode, message: impl Into<Cow<'static, str>>) -> Self {
        Error::Other {
            code,
            offset: None,
            message: message.into(),
        }
    }

    /// Creates an error with the given code, byte offset and message.
    pub fn at(code: ErrorCode, offset: u64, message: impl Into<Cow<'static, str>>) -> Self {
        Error::Other {
            code,
            offset: Some(offset),
            message: message.into(),
        }
    }

    /// Creates an [`Error::Syntax`].
    pub fn syntax(offset: u64, message: impl Into<Cow<'static, str>>) -> Self {
        Error::Syntax {
            offset,
            message: message.into(),
        }
    }

    /// Creates an [`Error::UnexpectedEof`].
    pub fn eof(offset: u64, context: &'static str) -> Self {
        Error::UnexpectedEof { offset, context }
    }

    /// Creates an [`Error::LimitExceeded`] for `limit`, whose configured value is `max`.
    pub fn limit(limit: LimitKind, max: u64, offset: Option<u64>) -> Self {
        Error::LimitExceeded { limit, max, offset }
    }

    /// Creates an [`Error::TypeMismatch`] for an object of type `found` where `expected` was
    /// required.
    pub fn type_mismatch(expected: &'static str, found: &'static str) -> Self {
        Error::TypeMismatch {
            expected,
            found,
            offset: None,
        }
    }

    /// Creates an [`Error::InvalidArgument`].
    pub fn invalid_argument(message: impl Into<Cow<'static, str>>) -> Self {
        Error::InvalidArgument {
            message: message.into(),
        }
    }

    /// Creates an [`Error::Unsupported`].
    pub fn unsupported(message: impl Into<Cow<'static, str>>) -> Self {
        Error::Unsupported {
            message: message.into(),
        }
    }

    /// The stable category of this error.
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Syntax { .. } | Error::UnexpectedEof { .. } => ErrorCode::Syntax,
            Error::LimitExceeded { .. } => ErrorCode::LimitExceeded,
            Error::TypeMismatch { .. } => ErrorCode::TypeMismatch,
            Error::Xref { .. } => ErrorCode::Xref,
            Error::MissingObject { .. } => ErrorCode::MissingObject,
            Error::Unsupported { .. } => ErrorCode::Unsupported,
            Error::InvalidArgument { .. } => ErrorCode::InvalidArgument,
            Error::Filter { source, .. } => filter_error_code(source),
            Error::Other { code, .. } => *code,
        }
    }

    /// The byte offset where the error was detected, if the error is tied to a position.
    pub fn offset(&self) -> Option<u64> {
        match self {
            Error::Syntax { offset, .. } | Error::UnexpectedEof { offset, .. } => Some(*offset),
            Error::LimitExceeded { offset, .. }
            | Error::TypeMismatch { offset, .. }
            | Error::Xref { offset, .. }
            | Error::Filter { offset, .. }
            | Error::Other { offset, .. } => *offset,
            Error::MissingObject { .. }
            | Error::Unsupported { .. }
            | Error::InvalidArgument { .. } => None,
        }
    }
}

/// The [`ErrorCode`] of a [`FilterError`] (M1 brief, WP1.2/WP1.3 contract): corrupt data and
/// invalid parameters are [`ErrorCode::Filter`], limits are [`ErrorCode::LimitExceeded`], and
/// filters this layer does not decode are [`ErrorCode::Unsupported`].
pub const fn filter_error_code(error: &FilterError) -> ErrorCode {
    match error {
        FilterError::Corrupt { .. } | FilterError::InvalidParams { .. } => ErrorCode::Filter,
        FilterError::LimitExceeded { .. } => ErrorCode::LimitExceeded,
        FilterError::Unsupported { .. } => ErrorCode::Unsupported,
    }
}

impl From<FilterError> for Error {
    /// Wraps a filter error without an offset; see [`Error::Filter`] for the resulting code.
    fn from(source: FilterError) -> Self {
        Error::Filter {
            offset: None,
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_screaming_snake_case_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for code in ErrorCode::ALL {
            let s = code.as_str();
            assert!(seen.insert(s), "duplicate {s}");
            assert!(
                s.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'),
                "{s}"
            );
            assert_eq!(code.to_string(), s);
        }
        assert_eq!(ErrorCode::ALL.len(), 23);
    }

    #[test]
    fn error_codes_and_offsets() {
        let cases: Vec<(Error, ErrorCode, Option<u64>)> = vec![
            (Error::syntax(5, "x"), ErrorCode::Syntax, Some(5)),
            (Error::eof(7, "name"), ErrorCode::Syntax, Some(7)),
            (
                Error::limit(LimitKind::MaxNestingDepth, 256, Some(9)),
                ErrorCode::LimitExceeded,
                Some(9),
            ),
            (
                Error::type_mismatch("dictionary", "integer"),
                ErrorCode::TypeMismatch,
                None,
            ),
            (
                Error::Xref {
                    offset: Some(3),
                    message: "bad".into(),
                },
                ErrorCode::Xref,
                Some(3),
            ),
            (
                Error::MissingObject {
                    id: ObjectId::new(4, 0),
                },
                ErrorCode::MissingObject,
                None,
            ),
            (Error::unsupported("x"), ErrorCode::Unsupported, None),
            (
                Error::invalid_argument("x"),
                ErrorCode::InvalidArgument,
                None,
            ),
            (
                Error::new(ErrorCode::PasswordRequired, "x"),
                ErrorCode::PasswordRequired,
                None,
            ),
            (
                Error::at(ErrorCode::Filter, 11, "x"),
                ErrorCode::Filter,
                Some(11),
            ),
        ];
        for (err, code, offset) in cases {
            assert_eq!(err.code(), code, "{err}");
            assert_eq!(err.offset(), offset, "{err}");
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn messages_mention_offsets() {
        assert_eq!(
            Error::syntax(12, "unexpected `)`").to_string(),
            "syntax error at byte 12: unexpected `)`"
        );
        assert_eq!(
            Error::limit(LimitKind::MaxNestingDepth, 256, Some(300)).to_string(),
            "limit max_nesting_depth = 256 exceeded at byte 300"
        );
        assert_eq!(
            Error::MissingObject {
                id: ObjectId::new(12, 0)
            }
            .to_string(),
            "object 12 0 R not found"
        );
        assert_eq!(
            Error::new(ErrorCode::Io, "disk on fire").to_string(),
            "disk on fire"
        );
    }

    /// With the `serde` feature, codes use the same `SCREAMING_SNAKE_CASE` text as `as_str`.
    #[cfg(feature = "serde")]
    #[test]
    fn error_codes_serde_names() {
        use serde::Deserialize;
        use serde::de::IntoDeserializer;
        use serde::de::value::{Error as DeError, StrDeserializer};

        for &code in ErrorCode::ALL {
            let de: StrDeserializer<'_, DeError> = code.as_str().into_deserializer();
            assert_eq!(ErrorCode::deserialize(de).unwrap(), code);
        }
    }

    #[test]
    fn filter_errors_map_to_codes() {
        use crate::filters::Filter;
        let cases = [
            (
                FilterError::Corrupt {
                    filter: Filter::Flate,
                    detail: "bad header".into(),
                },
                ErrorCode::Filter,
            ),
            (
                FilterError::InvalidParams {
                    detail: "predictor 99".into(),
                },
                ErrorCode::Filter,
            ),
            (
                FilterError::LimitExceeded { limit: 16 },
                ErrorCode::LimitExceeded,
            ),
            (
                FilterError::Unsupported {
                    filter: Filter::Dct,
                },
                ErrorCode::Unsupported,
            ),
        ];
        for (filter_error, code) in cases {
            assert_eq!(filter_error_code(&filter_error), code);
            let err = Error::from(filter_error.clone());
            assert_eq!(err.code(), code, "{err}");
            assert_eq!(err.offset(), None);
            assert!(err.to_string().contains(&filter_error.to_string()), "{err}");
            // The filter error stays reachable as the source.
            let source = std::error::Error::source(&err).unwrap();
            assert_eq!(source.to_string(), filter_error.to_string());
        }
        let err = Error::Filter {
            offset: Some(40),
            source: FilterError::LimitExceeded { limit: 1 },
        };
        assert_eq!(err.offset(), Some(40));
        assert!(err.to_string().contains("at byte 40"), "{err}");
    }

    #[test]
    fn error_is_send_sync_and_small() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Error>();
        // Keep `Result<T>` cheap to return on hot paths.
        assert!(std::mem::size_of::<Error>() <= 64);
    }
}

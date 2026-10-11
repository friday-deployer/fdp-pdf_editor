//! The facade's unified error (ARCHITECTURE §A.4; M3 brief §3.2 "Facade").
//!
//! Every layer has its own error type with a `code()`; the facade wraps them in one
//! [`enum@Error`] whose [`Error::code`] is the wrapped error's [`ErrorCode`], so callers (and the
//! Node binding's `err.code = "E_<CODE>"`) see one stable vocabulary whichever layer failed.

use std::fmt;

use folioxide_syntax::ErrorCode;

/// The result type of the facade.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// An error from any Folioxide layer.
///
/// - [`Error::Syntax`]: opening, parsing, editing or writing a document (the syntax and model
///   layers' [`SyntaxError`](crate::SyntaxError)).
/// - [`Error::Sign`] (feature `signatures`): key loading, signing and verification
///   ([`sign::Error`](folioxide_sign::Error)). A signing error that wraps a syntax error is
///   converted to [`Error::Syntax`], so the same failure always has the same variant.
///
/// `Display` and `source()` are the wrapped error's. Match on [`Error::code`] for a stable
/// category; the enum is `#[non_exhaustive]` and gains a variant per error-bearing layer.
///
/// ```
/// use folioxide::{Document, Error, ErrorCode, OpenOptions};
///
/// let err: Error = Document::open(b"not a PDF".to_vec(), &OpenOptions::default()).unwrap_err().into();
/// assert_eq!(err.code(), ErrorCode::Xref);
/// assert!(matches!(err, Error::Syntax(_)));
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// An error of the syntax and model layers.
    Syntax(folioxide_syntax::Error),
    /// An error of the signature layer that does not wrap a syntax error.
    #[cfg(feature = "signatures")]
    Sign(folioxide_sign::Error),
}

impl Error {
    /// The stable category of this error: the wrapped error's code.
    ///
    /// ```
    /// # #[cfg(feature = "signatures")] {
    /// use folioxide::{Error, ErrorCode};
    ///
    /// let err = Error::from(folioxide::sign::Error::PlaceholderTooSmall { needed: 9000, reserved: 8192 });
    /// assert_eq!(err.code(), ErrorCode::SignaturePlaceholderTooSmall);
    /// // The Display text is the wrapped error's (the Node facade parses this one).
    /// assert_eq!(err.to_string(), "signature placeholder too small: needed 9000 bytes, reserved 8192");
    /// # }
    /// ```
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Syntax(err) => err.code(),
            #[cfg(feature = "signatures")]
            Error::Sign(err) => err.code(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Syntax(err) => fmt::Display::fmt(err, f),
            #[cfg(feature = "signatures")]
            Error::Sign(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Syntax(err) => std::error::Error::source(err),
            #[cfg(feature = "signatures")]
            Error::Sign(err) => std::error::Error::source(err),
        }
    }
}

impl From<folioxide_syntax::Error> for Error {
    fn from(err: folioxide_syntax::Error) -> Error {
        Error::Syntax(err)
    }
}

#[cfg(feature = "signatures")]
impl From<folioxide_sign::Error> for Error {
    /// `Sign(Syntax(e))` becomes `Syntax(e)`; every other signing error is `Sign(..)`.
    fn from(err: folioxide_sign::Error) -> Error {
        match err {
            folioxide_sign::Error::Syntax(err) => Error::Syntax(err),
            other => Error::Sign(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syntax_errors_keep_code_message_and_source() {
        let inner = folioxide_syntax::Error::new(ErrorCode::PageOutOfRange, "page 9 of 2");
        let message = inner.to_string();
        let err = Error::from(inner);
        assert_eq!(err.code(), ErrorCode::PageOutOfRange);
        assert_eq!(err.to_string(), message);
        assert!(std::error::Error::source(&err).is_none());
        assert!(matches!(err, Error::Syntax(_)));
    }

    #[cfg(feature = "signatures")]
    #[test]
    fn sign_errors_map_one_to_one() {
        use folioxide_sign::Error as SignError;

        let cases = [
            (SignError::WrongPassword, ErrorCode::WrongPassword),
            (SignError::PasswordRequired, ErrorCode::PasswordRequired),
            (SignError::KeyLoad("k".into()), ErrorCode::KeyLoad),
            (SignError::Certificate("c".into()), ErrorCode::Certificate),
            (SignError::Crypto("c".into()), ErrorCode::Crypto),
            (SignError::Unsupported("u".into()), ErrorCode::Unsupported),
            (
                SignError::InvalidArgument("i".into()),
                ErrorCode::InvalidArgument,
            ),
            (SignError::NotFound("n".into()), ErrorCode::NotFound),
            (SignError::PageOutOfRange(4), ErrorCode::PageOutOfRange),
            (
                SignError::PlaceholderTooSmall {
                    needed: 2,
                    reserved: 1,
                },
                ErrorCode::SignaturePlaceholderTooSmall,
            ),
            (
                SignError::SignatureInvalid("s".into()),
                ErrorCode::SignatureInvalid,
            ),
            (
                SignError::DocMdpForbids("d".into()),
                ErrorCode::DocMdpForbids,
            ),
        ];
        for (inner, code) in cases {
            let message = inner.to_string();
            let err = Error::from(inner);
            assert!(matches!(err, Error::Sign(_)), "{err:?}");
            assert_eq!(err.code(), code);
            assert_eq!(err.to_string(), message);
        }
    }

    #[cfg(feature = "signatures")]
    #[test]
    fn sign_wrapping_a_syntax_error_becomes_syntax() {
        let inner = folioxide_syntax::Error::new(ErrorCode::Xref, "no xref");
        let err = Error::from(folioxide_sign::Error::Syntax(inner));
        assert!(matches!(err, Error::Syntax(_)), "{err:?}");
        assert_eq!(err.code(), ErrorCode::Xref);
        assert_eq!(err.to_string(), "no xref");
    }

    #[test]
    fn error_is_send_sync_static() {
        fn assert_send_sync<T: Send + Sync + 'static + std::error::Error>() {}
        assert_send_sync::<Error>();
    }
}

//! The error type of `folioxide-sign` (M3 brief §3.2 "Errors", ARCHITECTURE §A.4).
//!
//! Every variant maps onto exactly one [`ErrorCode`] through [`Error::code`], which the Node
//! binding turns into `err.code = "E_<CODE>"`. Messages never contain passwords or key material.

use folioxide_syntax::ErrorCode;

/// The result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// An error from signing, key loading, CMS processing or certificate handling.
///
/// Match on [`Error::code`] for a stable category; the variants carry details for messages.
/// The enum is `#[non_exhaustive]`: match it with a wildcard arm.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error from the syntax and model layers (opening, parsing or writing the PDF). Its code
    /// is the wrapped error's code.
    #[error(transparent)]
    Syntax(#[from] folioxide_syntax::Error),
    /// The password for a PKCS#12 file or an encrypted private key is wrong.
    #[error("wrong password")]
    WrongPassword,
    /// The private key is encrypted and no password was given.
    #[error("the private key is encrypted and a password is required")]
    PasswordRequired,
    /// A private key or its certificate chain could not be loaded, or they do not belong
    /// together. The message never contains the password or key bytes.
    #[error("could not load the private key: {0}")]
    KeyLoad(String),
    /// A certificate could not be parsed or is unusable.
    #[error("certificate error: {0}")]
    Certificate(String),
    /// A cryptographic operation failed (for example the RNG or the signing primitive).
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
    /// The input uses an algorithm, key type, curve or format this version does not support.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// The caller passed an invalid argument or an invalid combination of options.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// A named item (for example a signature field) was not found.
    #[error("not found: {0}")]
    NotFound(String),
    /// A 0-based page index is past the last page; the value is the index.
    #[error("page index {0} is out of range")]
    PageOutOfRange(usize),
    /// The `/Contents` placeholder is too small for the CMS signature.
    ///
    /// The Display text is fixed (M3 brief §3.2), because the JavaScript facade parses it into
    /// `err.details = { needed, reserved }`:
    /// `"signature placeholder too small: needed {needed} bytes, reserved {reserved}"`.
    #[error("signature placeholder too small: needed {needed} bytes, reserved {reserved}")]
    PlaceholderTooSmall {
        /// Bytes of DER the CMS needs.
        needed: usize,
        /// Bytes of DER the placeholder holds.
        reserved: usize,
    },
    /// A signature value does not verify, or a CMS does not sign the prepared bytes.
    #[error("signature invalid: {0}")]
    SignatureInvalid(String),
    /// The document's DocMDP permissions forbid the change (ISO 32000-2 §12.8.2.2).
    #[error("DocMDP permissions forbid the change: {0}")]
    DocMdpForbids(String),
}

impl Error {
    /// The stable category of this error.
    ///
    /// ```
    /// use folioxide_sign::Error;
    /// use folioxide_syntax::ErrorCode;
    ///
    /// let err = Error::PlaceholderTooSmall { needed: 9000, reserved: 8192 };
    /// assert_eq!(err.code(), ErrorCode::SignaturePlaceholderTooSmall);
    /// assert_eq!(
    ///     err.to_string(),
    ///     "signature placeholder too small: needed 9000 bytes, reserved 8192"
    /// );
    /// ```
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Syntax(err) => err.code(),
            Error::WrongPassword => ErrorCode::WrongPassword,
            Error::PasswordRequired => ErrorCode::PasswordRequired,
            Error::KeyLoad(_) => ErrorCode::KeyLoad,
            Error::Certificate(_) => ErrorCode::Certificate,
            Error::Crypto(_) => ErrorCode::Crypto,
            Error::Unsupported(_) => ErrorCode::Unsupported,
            Error::InvalidArgument(_) => ErrorCode::InvalidArgument,
            Error::NotFound(_) => ErrorCode::NotFound,
            Error::PageOutOfRange(_) => ErrorCode::PageOutOfRange,
            Error::PlaceholderTooSmall { .. } => ErrorCode::SignaturePlaceholderTooSmall,
            Error::SignatureInvalid(_) => ErrorCode::SignatureInvalid,
            Error::DocMdpForbids(_) => ErrorCode::DocMdpForbids,
        }
    }
}

/// The message of the M3 stage-0 stubs, whose bodies are filled in stage 1.
#[allow(dead_code)] // Kept for the PDF-side stubs of later stages.
pub(crate) const STAGE_1: &str = "M3 stage 1";

/// `Err(Error::Unsupported("M3 stage 1"))`: the body of every stage-0 stub (M3 brief §2).
#[allow(dead_code)] // Kept for the PDF-side stubs of later stages.
pub(crate) fn not_yet<T>() -> Result<T> {
    Err(Error::Unsupported(STAGE_1.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_maps_to_its_code() {
        let cases = [
            (Error::WrongPassword, ErrorCode::WrongPassword),
            (Error::PasswordRequired, ErrorCode::PasswordRequired),
            (Error::KeyLoad("x".into()), ErrorCode::KeyLoad),
            (Error::Certificate("x".into()), ErrorCode::Certificate),
            (Error::Crypto("x".into()), ErrorCode::Crypto),
            (Error::Unsupported("x".into()), ErrorCode::Unsupported),
            (
                Error::InvalidArgument("x".into()),
                ErrorCode::InvalidArgument,
            ),
            (Error::NotFound("x".into()), ErrorCode::NotFound),
            (Error::PageOutOfRange(3), ErrorCode::PageOutOfRange),
            (
                Error::PlaceholderTooSmall {
                    needed: 1,
                    reserved: 0,
                },
                ErrorCode::SignaturePlaceholderTooSmall,
            ),
            (
                Error::SignatureInvalid("x".into()),
                ErrorCode::SignatureInvalid,
            ),
            (Error::DocMdpForbids("x".into()), ErrorCode::DocMdpForbids),
        ];
        for (err, code) in cases {
            assert_eq!(err.code(), code, "{err:?}");
        }
    }

    #[test]
    fn syntax_errors_keep_their_code_and_message() {
        fn open() -> Result<()> {
            Err(folioxide_syntax::Error::new(
                ErrorCode::PasswordRequired,
                "the document is encrypted",
            ))?;
            Ok(())
        }
        let err = open().unwrap_err();
        assert_eq!(err.code(), ErrorCode::PasswordRequired);
        assert_eq!(err.to_string(), "the document is encrypted");

        let xref = Error::from(folioxide_syntax::Error::syntax(7, "bad token"));
        assert_eq!(xref.code(), ErrorCode::Syntax);
    }

    #[test]
    fn placeholder_too_small_display_is_fixed() {
        let err = Error::PlaceholderTooSmall {
            needed: 12345,
            reserved: 8192,
        };
        assert_eq!(
            err.to_string(),
            "signature placeholder too small: needed 12345 bytes, reserved 8192"
        );
    }

    #[test]
    fn stage_0_stub_error_is_unsupported() {
        let err = not_yet::<()>().unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
        assert_eq!(err.to_string(), "unsupported: M3 stage 1");
    }
}

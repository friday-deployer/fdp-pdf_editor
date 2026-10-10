//! Errors at the JavaScript boundary (ARCHITECTURE §A.7, "Errors").
//!
//! Every error the binding throws (or rejects a promise with) is a JavaScript `Error` whose
//! `code` property is `"E_"` followed by the core [`ErrorCode`] in `SCREAMING_SNAKE_CASE`
//! (`E_SYNTAX`, `E_PAGE_OUT_OF_RANGE`, …), or [`E_BUSY`] or [`E_CLOSED`], which only the binding
//! uses. napi-rs
//! sets `err.code` from the error's status, so the binding's functions return
//! [`JsResult`], whose status is that code as a string.
//!
//! Messages are the core error's `Display` text, cut to [`MAX_MESSAGE_LEN`] bytes: the core
//! never puts passwords or key material in a message, and the cut bounds the few messages that
//! quote a token from the file (an unknown keyword, for example).

use folioxide::ErrorCode;
use napi::{Env, JsError};

/// The result type of the binding's helpers: on error, a napi error whose status (the JS
/// `err.code`) is an `E_*` code. (`#[napi]` functions spell it `Result<T, BindingError>`: the
/// macro recognizes a fallible function by the name `Result`.)
pub type JsResult<T> = napi::Result<T, String>;

/// The error type of [`JsResult`].
pub type BindingError = napi::Error<String>;

/// The `code` of the error a synchronous method throws while an asynchronous method
/// (`saveAsync`, `saveIncrementalAsync`) has the document (ARCHITECTURE §A.7: sync methods never
/// block the event loop).
pub const E_BUSY: &str = "E_BUSY";

/// The `code` of the error every method throws (and every asynchronous method rejects with)
/// once the document was closed (`close()`, ARCHITECTURE §A.7 "Native memory").
pub const E_CLOSED: &str = "E_CLOSED";

/// The longest error message passed to JavaScript, in bytes; longer ones are cut at a character
/// boundary and end with `…`.
pub const MAX_MESSAGE_LEN: usize = 1024;

/// The JavaScript error code for a core error code: `E_` + its `SCREAMING_SNAKE_CASE` name.
pub fn js_code(code: ErrorCode) -> String {
    format!("E_{}", code.as_str())
}

/// The JavaScript error for a core error.
pub fn from_core(err: &folioxide::Error) -> BindingError {
    with_code(err.code(), err.to_string())
}

/// A JavaScript error with the code of `code` and `message` (cut to [`MAX_MESSAGE_LEN`]).
pub fn with_code(code: ErrorCode, message: impl Into<String>) -> BindingError {
    napi::Error::new(js_code(code), bounded(message.into()))
}

/// An `E_INVALID_ARGUMENT` error.
pub fn invalid_argument(message: impl Into<String>) -> BindingError {
    with_code(ErrorCode::InvalidArgument, message)
}

/// An `E_PAGE_OUT_OF_RANGE` error.
pub fn page_out_of_range(message: impl Into<String>) -> BindingError {
    with_code(ErrorCode::PageOutOfRange, message)
}

/// The [`E_BUSY`] error.
pub fn busy() -> BindingError {
    napi::Error::new(
        E_BUSY.to_owned(),
        "the document is busy: an asynchronous operation (saveAsync or saveIncrementalAsync) \
         is using it; await it before calling a synchronous method"
            .to_owned(),
    )
}

/// The [`E_CLOSED`] error.
pub fn closed() -> BindingError {
    napi::Error::new(
        E_CLOSED.to_owned(),
        "the document was closed: its memory was freed by close(); open the file again to use it"
            .to_owned(),
    )
}

/// `message` cut to at most [`MAX_MESSAGE_LEN`] bytes at a character boundary, with `…` when
/// something was cut.
pub fn bounded(mut message: String) -> String {
    if message.len() <= MAX_MESSAGE_LEN {
        return message;
    }
    let ellipsis = '…';
    let mut end = MAX_MESSAGE_LEN - ellipsis.len_utf8();
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message.truncate(end);
    message.push(ellipsis);
    message
}

/// Turns a binding error into the error an asynchronous task rejects its promise with.
///
/// [`napi::Task`] errors carry a [`napi::Status`], which cannot hold an `E_*` code. So the
/// JavaScript error object is built here, on the JavaScript thread (task `resolve` runs there),
/// with its `code`, and the returned error refers to that object: napi-rs rejects the promise
/// with the object itself.
pub fn into_rejection(env: Env, err: BindingError) -> napi::Error {
    let value = JsError::from(err).into_unknown(env);
    napi::Error::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_e_prefixed_screaming_snake() {
        assert_eq!(js_code(ErrorCode::Syntax), "E_SYNTAX");
        assert_eq!(js_code(ErrorCode::PageOutOfRange), "E_PAGE_OUT_OF_RANGE");
        assert_eq!(js_code(ErrorCode::PasswordRequired), "E_PASSWORD_REQUIRED");
        for &code in ErrorCode::ALL {
            let js = js_code(code);
            assert!(js.starts_with("E_"));
            assert!(
                js.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                "{js}"
            );
        }
    }

    #[test]
    fn core_errors_keep_their_code_and_message() {
        let err = folioxide::Error::invalid_argument("a page rotation must be a multiple of 90");
        let js = from_core(&err);
        assert_eq!(js.status, "E_INVALID_ARGUMENT");
        assert_eq!(js.reason, err.to_string());
        assert_eq!(busy().status, E_BUSY);
        assert_eq!(closed().status, E_CLOSED);
    }

    #[test]
    fn long_messages_are_cut_at_a_character_boundary() {
        assert_eq!(bounded("short".to_owned()), "short");
        let exact = "x".repeat(MAX_MESSAGE_LEN);
        assert_eq!(bounded(exact.clone()), exact);
        // Two-byte characters, so that the cut falls inside one at an odd length.
        let long = "é".repeat(MAX_MESSAGE_LEN);
        let cut = bounded(long);
        assert!(cut.len() <= MAX_MESSAGE_LEN, "{}", cut.len());
        assert!(cut.ends_with('…'));
        assert!(cut.trim_end_matches('…').chars().all(|c| c == 'é'));
    }
}

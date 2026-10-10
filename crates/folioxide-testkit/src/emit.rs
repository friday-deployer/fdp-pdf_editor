//! Writing oracle cases: `<suite dir>/<name>.pdf` plus `<name>.expect.json` (ARCHITECTURE §A.9,
//! "Oracle mechanism").
//!
//! Tests call [`emit_case`] unconditionally; it only writes when the crate is built with the
//! `emit` feature (as `cargo xtask oracle` does) and is a no-op otherwise. [`ExpectJson`] builds
//! the small JSON object that `tools/oracles/run_suite.py` reads, without a serde dependency.
//!
//! ```
//! use folioxide_testkit::ExpectJson;
//!
//! let expect = ExpectJson::new()
//!     .int("pages", 2)
//!     .string("version", "1.7")
//!     .string("oracleSkip", "repaired by Folioxide; qpdf warns");
//! assert_eq!(
//!     expect.to_json(),
//!     "{\n  \"pages\": 2,\n  \"version\": \"1.7\",\n  \"oracleSkip\": \"repaired by Folioxide; qpdf warns\"\n}\n"
//! );
//! ```

use std::io;
use std::path::{Path, PathBuf};

use crate::{EMIT_ENABLED, is_valid_suite_name, oracle_dir};

/// The suffix of an oracle expectation file, next to `<name>.pdf`.
pub const EXPECT_SUFFIX: &str = ".expect.json";

/// A JSON object with keys in insertion order, for `<name>.expect.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpectJson {
    entries: Vec<(String, String)>,
}

impl ExpectJson {
    /// An empty object.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `key` to a JSON value given as text (for arrays and nested objects). The text is
    /// written verbatim and must be valid JSON. Setting a key again replaces its value in place.
    #[must_use]
    pub fn raw(mut self, key: &str, json: impl Into<String>) -> Self {
        let json = json.into();
        match self.entries.iter_mut().find(|(k, _)| k == key) {
            Some((_, value)) => *value = json,
            None => self.entries.push((key.to_owned(), json)),
        }
        self
    }

    /// Sets `key` to an integer.
    #[must_use]
    pub fn int(self, key: &str, value: i64) -> Self {
        self.raw(key, value.to_string())
    }

    /// Sets `key` to a string.
    #[must_use]
    pub fn string(self, key: &str, value: &str) -> Self {
        self.raw(key, json_string(value))
    }

    /// Sets `key` to a boolean.
    #[must_use]
    pub fn bool(self, key: &str, value: bool) -> Self {
        self.raw(key, if value { "true" } else { "false" })
    }

    /// Sets `key` to `null`.
    #[must_use]
    pub fn null(self, key: &str) -> Self {
        self.raw(key, "null")
    }

    /// Sets `key` to an object of strings, entries in the given order (for example
    /// `knownFailures`, which maps check names to reasons).
    ///
    /// ```
    /// use folioxide_testkit::ExpectJson;
    ///
    /// let expect = ExpectJson::new().string_map("knownFailures", &[("structure.pypdf", "why")]);
    /// assert_eq!(expect.get("knownFailures"), Some(r#"{"structure.pypdf": "why"}"#));
    /// ```
    #[must_use]
    pub fn string_map(self, key: &str, entries: &[(&str, &str)]) -> Self {
        let body: Vec<String> = entries
            .iter()
            .map(|(name, value)| format!("{}: {}", json_string(name), json_string(value)))
            .collect();
        self.raw(key, format!("{{{}}}", body.join(", ")))
    }

    /// The value text of `key`, if set.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The object as JSON text: one key per line, two-space indent, trailing newline.
    pub fn to_json(&self) -> String {
        if self.entries.is_empty() {
            return "{}\n".to_owned();
        }
        let body: Vec<String> = self
            .entries
            .iter()
            .map(|(key, value)| format!("  {}: {value}", json_string(key)))
            .collect();
        format!("{{\n{}\n}}\n", body.join(",\n"))
    }
}

/// `value` as a JSON string literal, with quotes, backslashes and control characters escaped
/// (RFC 8259 §7).
///
/// ```
/// assert_eq!(folioxide_testkit::emit::json_string("a\"b\\\n"), r#""a\"b\\\n""#);
/// ```
pub fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Writes the oracle case `name` of `suite` when the `emit` feature is enabled: `<name>.pdf` and
/// `<name>.expect.json` in [`oracle_dir`]`(suite)`, which is created. Returns the PDF's path, or
/// `None` without the feature (nothing is written).
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] if `suite` or `name` is not a valid name (see
/// [`is_valid_suite_name`]; the same rule applies to case names), and any I/O error from
/// writing.
pub fn emit_case(
    suite: &str,
    name: &str,
    pdf: &[u8],
    expect: &ExpectJson,
) -> io::Result<Option<PathBuf>> {
    if !EMIT_ENABLED {
        return Ok(None);
    }
    let dir = oracle_dir(suite).ok_or_else(|| invalid(format!("invalid suite name {suite:?}")))?;
    write_case(&dir, name, pdf, expect).map(Some)
}

/// Writes `<dir>/<name>.pdf` and `<dir>/<name>.expect.json`, creating `dir`, whether or not the
/// `emit` feature is enabled. Returns the PDF's path.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] if `name` is not a valid case name (ASCII letters, digits,
/// `-` and `_`), and any I/O error from writing.
pub fn write_case(dir: &Path, name: &str, pdf: &[u8], expect: &ExpectJson) -> io::Result<PathBuf> {
    if !is_valid_suite_name(name) {
        return Err(invalid(format!("invalid case name {name:?}")));
    }
    std::fs::create_dir_all(dir)?;
    let pdf_path = dir.join(format!("{name}.pdf"));
    std::fs::write(&pdf_path, pdf)?;
    std::fs::write(dir.join(format!("{name}{EXPECT_SUFFIX}")), expect.to_json())?;
    Ok(pdf_path)
}

/// Writes a supporting file `name` of `suite` when the `emit` feature is enabled, next to the
/// cases: for example the source of an incremental update that a case's `prefixOf` names (a
/// relative `prefixOf` path is resolved against the case's directory first). The runner only
/// takes files with a sibling `<name>.expect.json` as cases, so a supporting file is never one
/// unless such a file exists. Returns the path, or `None` without the feature (nothing is
/// written).
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] if `suite` is not a valid suite name or `name` is not a valid
/// file name (see [`is_valid_file_name`]), and any I/O error from writing.
pub fn emit_file(suite: &str, name: &str, bytes: &[u8]) -> io::Result<Option<PathBuf>> {
    if !EMIT_ENABLED {
        return Ok(None);
    }
    let dir = oracle_dir(suite).ok_or_else(|| invalid(format!("invalid suite name {suite:?}")))?;
    write_file(&dir, name, bytes).map(Some)
}

/// Writes `<dir>/<name>`, creating `dir`, whether or not the `emit` feature is enabled. Returns
/// the path.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] if `name` is not a valid file name (see
/// [`is_valid_file_name`]), and any I/O error from writing.
pub fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
    if !is_valid_file_name(name) {
        return Err(invalid(format!("invalid file name {name:?}")));
    }
    std::fs::create_dir_all(dir)?;
    let path = dir.join(name);
    std::fs::write(&path, bytes)?;
    Ok(path)
}

/// Whether `name` is a valid supporting file name for [`emit_file`]: a single path component of
/// ASCII letters, digits, `-`, `_` and `.`, which neither starts with `.` nor ends with
/// [`EXPECT_SUFFIX`] (so it cannot escape the suite directory, be hidden, or pose as a case's
/// expectation).
///
/// ```
/// use folioxide_testkit::emit::is_valid_file_name;
///
/// assert!(is_valid_file_name("minimal.source.pdf"));
/// assert!(!is_valid_file_name("../minimal.pdf"));
/// assert!(!is_valid_file_name(".hidden"));
/// assert!(!is_valid_file_name("case.expect.json"));
/// ```
pub fn is_valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && !name.ends_with(EXPECT_SUFFIX)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escapes_control_characters() {
        assert_eq!(json_string("\u{1}é"), "\"\\u0001é\"");
        assert_eq!(json_string(""), "\"\"");
    }

    #[test]
    fn expect_json_replaces_keys_in_place() {
        let e = ExpectJson::new()
            .int("a", 1)
            .bool("b", true)
            .null("c")
            .raw("d", "[1, 2]")
            .int("a", -3);
        assert_eq!(e.get("a"), Some("-3"));
        assert_eq!(e.get("zz"), None);
        assert_eq!(
            e.to_json(),
            "{\n  \"a\": -3,\n  \"b\": true,\n  \"c\": null,\n  \"d\": [1, 2]\n}\n"
        );
        assert_eq!(ExpectJson::new().to_json(), "{}\n");
        let map = ExpectJson::new()
            .string_map("m", &[("a\"", "1"), ("b", "")])
            .string_map("empty", &[]);
        assert_eq!(map.get("m"), Some(r#"{"a\"": "1", "b": ""}"#));
        assert_eq!(map.get("empty"), Some("{}"));
    }

    #[test]
    fn write_case_writes_both_files_and_rejects_bad_names() {
        let dir =
            std::env::temp_dir().join(format!("folioxide-testkit-emit-{}", std::process::id()));
        let expect = ExpectJson::new().int("pages", 1);
        let path = write_case(&dir, "case_1", b"%PDF-1.7\n", &expect).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"%PDF-1.7\n");
        assert_eq!(
            std::fs::read_to_string(dir.join("case_1.expect.json")).unwrap(),
            expect.to_json()
        );
        for bad in ["", "../x", "a.b", "a/b"] {
            let err = write_case(&dir, bad, b"", &expect).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_file_writes_supporting_files_and_rejects_bad_names() {
        let dir =
            std::env::temp_dir().join(format!("folioxide-testkit-file-{}", std::process::id()));
        let path = write_file(&dir, "case-1.source.pdf", b"%PDF-1.4\n").unwrap();
        assert_eq!(path, dir.join("case-1.source.pdf"));
        assert_eq!(std::fs::read(&path).unwrap(), b"%PDF-1.4\n");
        for bad in [
            "",
            ".",
            "..",
            "../x",
            "a/b",
            "a\\b",
            ".x",
            "x.expect.json",
            "é",
        ] {
            let err = write_file(&dir, bad, b"").unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{bad:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
        let result = emit_file("../bad", "x.pdf", b"");
        if EMIT_ENABLED {
            assert!(result.is_err());
        } else {
            assert!(matches!(result, Ok(None)));
        }
    }

    #[test]
    fn emit_case_respects_the_feature() {
        let result = emit_case("../bad", "x", b"", &ExpectJson::new());
        if EMIT_ENABLED {
            assert!(result.is_err());
        } else {
            assert!(matches!(result, Ok(None)));
        }
    }
}

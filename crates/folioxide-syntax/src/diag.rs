//! Leniency policy and diagnostics (ARCHITECTURE §A.4, "Leniency is a policy").
//!
//! Real-world PDF files are often slightly broken. In [`Strictness::Lenient`] mode (the default)
//! the syntax layer repairs what it can and records a [`Diagnostic`] for every repair, so callers
//! can see exactly what was fixed. In [`Strictness::Strict`] mode the same situations are errors.
//!
//! Diagnostics are delivered to a [`DiagnosticSink`]. [`DiagnosticLog`] is the standard,
//! thread-safe sink; it stores at most [`Limits::max_diagnostics`] entries and only counts the
//! rest, so a file full of small defects cannot exhaust memory.

use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::limits::Limits;

/// How strictly input is validated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum Strictness {
    /// Repair what can be repaired and record a [`Diagnostic`] for each repair (the default).
    #[default]
    Lenient,
    /// Treat every situation that lenient mode would repair as an error.
    Strict,
}

/// The category of a [`Diagnostic`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum DiagnosticKind {
    /// A malformed number was accepted, for example `--5` read as `-5` (§7.3.3).
    MalformedNumber,
    /// A hexadecimal string contained a character that is neither a hex digit nor white-space;
    /// it was skipped (§7.3.4.3).
    InvalidHexDigit,
    /// A `#` in a name was not followed by two hex digits, or encoded a NUL byte; it was kept
    /// literally (§7.3.5).
    InvalidNameEscape,
    /// A dictionary contained the same key twice; the last value wins (§7.3.7).
    DuplicateKey,
    /// A dictionary key was not a name; the entry was skipped (§7.3.7).
    InvalidDictKey,
    /// A dictionary key had no value; the key was dropped (§7.3.7).
    MissingDictValue,
    /// An unknown keyword inside an array or dictionary was replaced by `null`.
    UnknownKeyword,
    /// An array or dictionary was not closed before an object-level keyword such as `endobj`
    /// or `stream`; it was closed implicitly.
    UnclosedContainer,
    /// `N G R` with an object or generation number out of range was replaced by `null`
    /// (§7.3.10).
    InvalidReference,
    /// The `stream` keyword was not followed by CRLF or LF (§7.3.8.1).
    StreamKeywordEol,
    /// A stream's `/Length` was missing, invalid or wrong; the data was delimited by scanning
    /// for `endstream` (§7.3.8.1).
    StreamLength,
    /// A stream had no `endstream` keyword.
    MissingEndstream,
    /// An indirect object had no `endobj` keyword (§7.3.10).
    MissingEndobj,
    /// An indirect object had no value; it was read as `null`.
    EmptyObject,
    /// The `stream` keyword followed a value that is not a dictionary; the stream was ignored.
    StreamWithoutDict,
    /// Bytes before the `%PDF-` header shift every offset in the file (§7.5.2).
    HeaderOffset,
    /// The file has no `%PDF-` header (§7.5.2); version 1.4 and offsets counted from byte 0
    /// were assumed.
    MissingHeader,
    /// The `%PDF-` header has no valid `M.m` version (§7.5.2); version 1.4 was assumed.
    MalformedHeader,
    /// A cross-reference entry pointed to the wrong place and was corrected by a local search.
    XrefOffsetRepaired,
    /// A cross-reference subsection had the wrong starting number and was shifted.
    XrefSubsectionShifted,
    /// A malformed cross-reference entry or section was skipped.
    XrefMalformed,
    /// The cross-reference data was unusable; objects were found by a full scan of the file.
    XrefReconstructed,
    /// A `/Prev` or `/XRefStm` chain looped or exceeded its limit; the chain was cut.
    XrefLoop,
    /// The trailer was missing or broken and was rebuilt.
    TrailerRebuilt,
    /// A reference named a generation that does not match the cross-reference entry.
    WrongGeneration,
    /// An object could not be parsed and is treated as `null`.
    ObjectUnreadable,
    /// An object stream was malformed (§7.5.7).
    ObjectStream,
    /// An indirect `/Length` or another reference chain could not be resolved.
    UnresolvedReference,
    /// A stream filter stopped early; only part of the data was decoded (§7.4).
    FilterTruncated,
    /// A `/Crypt` filter other than `/Identity` in a document that is not encrypted was treated
    /// as the identity filter (§7.4.10, §7.6.6).
    CryptFilterIgnored,
    /// A cross-reference stream entry has a type this reader does not know (3 or more). It is
    /// conforming and reads as a reference to the null object (§7.5.8.3); recorded in both
    /// modes, it is not a repair.
    XrefUnknownEntryType,
    /// Object headers, an `xref` table or a `trailer`, at the start of a line, follow the last
    /// revision without a `startxref` that leads to them: an incremental update that no reader
    /// reaches through the cross-reference chain (a save that stopped before its `startxref`,
    /// content appended outside any revision, a second file appended to the first, §7.5.6), or
    /// the update of a `startxref` that leads nowhere. Lenient mode ignores the update, as qpdf,
    /// poppler and pypdf do, unless qpdf would rebuild the file: when the last `startxref`
    /// starts more than 1054 bytes before the end of the file and an object header follows
    /// it, or when the chain was found only by repairing the last `startxref`; then the file is
    /// reconstructed so that the update is used. Either way the structure counts as repaired;
    /// strict mode refuses the file. Header-like text in a comment or in the middle of a line
    /// is no update.
    UnreferencedUpdate,
    /// Anything else. Always the last variant.
    Other,
}

impl DiagnosticKind {
    /// Every diagnostic kind, in declaration order.
    pub const ALL: &'static [DiagnosticKind] = &[
        DiagnosticKind::MalformedNumber,
        DiagnosticKind::InvalidHexDigit,
        DiagnosticKind::InvalidNameEscape,
        DiagnosticKind::DuplicateKey,
        DiagnosticKind::InvalidDictKey,
        DiagnosticKind::MissingDictValue,
        DiagnosticKind::UnknownKeyword,
        DiagnosticKind::UnclosedContainer,
        DiagnosticKind::InvalidReference,
        DiagnosticKind::StreamKeywordEol,
        DiagnosticKind::StreamLength,
        DiagnosticKind::MissingEndstream,
        DiagnosticKind::MissingEndobj,
        DiagnosticKind::EmptyObject,
        DiagnosticKind::StreamWithoutDict,
        DiagnosticKind::HeaderOffset,
        DiagnosticKind::MissingHeader,
        DiagnosticKind::MalformedHeader,
        DiagnosticKind::XrefOffsetRepaired,
        DiagnosticKind::XrefSubsectionShifted,
        DiagnosticKind::XrefMalformed,
        DiagnosticKind::XrefReconstructed,
        DiagnosticKind::XrefLoop,
        DiagnosticKind::TrailerRebuilt,
        DiagnosticKind::WrongGeneration,
        DiagnosticKind::ObjectUnreadable,
        DiagnosticKind::ObjectStream,
        DiagnosticKind::UnresolvedReference,
        DiagnosticKind::FilterTruncated,
        DiagnosticKind::CryptFilterIgnored,
        DiagnosticKind::XrefUnknownEntryType,
        DiagnosticKind::UnreferencedUpdate,
        DiagnosticKind::Other,
    ];

    /// A short, stable `camelCase` identifier, for example `"streamLength"`; the same text
    /// the `serde` feature uses.
    pub const fn as_str(self) -> &'static str {
        match self {
            DiagnosticKind::MalformedNumber => "malformedNumber",
            DiagnosticKind::InvalidHexDigit => "invalidHexDigit",
            DiagnosticKind::InvalidNameEscape => "invalidNameEscape",
            DiagnosticKind::DuplicateKey => "duplicateKey",
            DiagnosticKind::InvalidDictKey => "invalidDictKey",
            DiagnosticKind::MissingDictValue => "missingDictValue",
            DiagnosticKind::UnknownKeyword => "unknownKeyword",
            DiagnosticKind::UnclosedContainer => "unclosedContainer",
            DiagnosticKind::InvalidReference => "invalidReference",
            DiagnosticKind::StreamKeywordEol => "streamKeywordEol",
            DiagnosticKind::StreamLength => "streamLength",
            DiagnosticKind::MissingEndstream => "missingEndstream",
            DiagnosticKind::MissingEndobj => "missingEndobj",
            DiagnosticKind::EmptyObject => "emptyObject",
            DiagnosticKind::StreamWithoutDict => "streamWithoutDict",
            DiagnosticKind::HeaderOffset => "headerOffset",
            DiagnosticKind::MissingHeader => "missingHeader",
            DiagnosticKind::MalformedHeader => "malformedHeader",
            DiagnosticKind::XrefOffsetRepaired => "xrefOffsetRepaired",
            DiagnosticKind::XrefSubsectionShifted => "xrefSubsectionShifted",
            DiagnosticKind::XrefMalformed => "xrefMalformed",
            DiagnosticKind::XrefReconstructed => "xrefReconstructed",
            DiagnosticKind::XrefLoop => "xrefLoop",
            DiagnosticKind::TrailerRebuilt => "trailerRebuilt",
            DiagnosticKind::WrongGeneration => "wrongGeneration",
            DiagnosticKind::ObjectUnreadable => "objectUnreadable",
            DiagnosticKind::ObjectStream => "objectStream",
            DiagnosticKind::UnresolvedReference => "unresolvedReference",
            DiagnosticKind::FilterTruncated => "filterTruncated",
            DiagnosticKind::CryptFilterIgnored => "cryptFilterIgnored",
            DiagnosticKind::XrefUnknownEntryType => "xrefUnknownEntryType",
            DiagnosticKind::UnreferencedUpdate => "unreferencedUpdate",
            DiagnosticKind::Other => "other",
        }
    }
}

impl fmt::Display for DiagnosticKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A record of one repair or leniency decision.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct Diagnostic {
    /// Byte offset of the problem in the buffer being parsed, if it is tied to a position.
    pub offset: Option<u64>,
    /// The category of the problem.
    pub kind: DiagnosticKind,
    /// A human-readable description.
    pub message: String,
}

impl Diagnostic {
    /// Creates a diagnostic.
    pub fn new(kind: DiagnosticKind, offset: Option<u64>, message: impl Into<String>) -> Self {
        Diagnostic {
            offset,
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.offset {
            Some(offset) => write!(f, "[{}] at byte {offset}: {}", self.kind, self.message),
            None => write!(f, "[{}] {}", self.kind, self.message),
        }
    }
}

/// Receives diagnostics.
///
/// Implemented by [`DiagnosticLog`] and by every `Fn(Diagnostic)` closure, so tests and tools
/// can collect diagnostics ad hoc:
///
/// ```
/// use std::cell::RefCell;
/// use folioxide_syntax::{parse_object, Diagnostic, DiagnosticKind, ParseCtx};
///
/// let seen = RefCell::new(Vec::<Diagnostic>::new());
/// let sink = |d: Diagnostic| seen.borrow_mut().push(d);
/// let ctx = ParseCtx::default().with_diagnostics(&sink);
/// let (obj, _) = parse_object(b"--5", 0, &ctx)?;
/// assert_eq!(obj.as_int(), Some(-5));
/// assert_eq!(seen.borrow()[0].kind, DiagnosticKind::MalformedNumber);
/// # Ok::<(), folioxide_syntax::Error>(())
/// ```
pub trait DiagnosticSink {
    /// Records one diagnostic.
    fn report(&self, diagnostic: Diagnostic);
}

impl<F: Fn(Diagnostic)> DiagnosticSink for F {
    fn report(&self, diagnostic: Diagnostic) {
        self(diagnostic);
    }
}

/// A thread-safe, bounded collection of diagnostics.
///
/// Stores at most `capacity` diagnostics; further ones are counted in
/// [`DiagnosticLog::dropped`] but not stored.
#[derive(Debug)]
pub struct DiagnosticLog {
    inner: Mutex<LogInner>,
}

#[derive(Debug, Default)]
struct LogInner {
    entries: Vec<Diagnostic>,
    capacity: usize,
    dropped: u64,
}

impl DiagnosticLog {
    /// Creates an empty log that stores at most `capacity` diagnostics.
    pub fn new(capacity: usize) -> Self {
        DiagnosticLog {
            inner: Mutex::new(LogInner {
                entries: Vec::new(),
                capacity,
                dropped: 0,
            }),
        }
    }

    /// Creates an empty log bounded by [`Limits::max_diagnostics`].
    pub fn with_limits(limits: &Limits) -> Self {
        Self::new(usize::try_from(limits.max_diagnostics).unwrap_or(usize::MAX))
    }

    // A panic while the lock is held cannot leave the log inconsistent (every update is a single
    // push or increment), so a poisoned lock is simply recovered.
    fn lock(&self) -> MutexGuard<'_, LogInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records one diagnostic, or counts it as dropped when the log is full.
    pub fn push(&self, diagnostic: Diagnostic) {
        let mut inner = self.lock();
        if inner.entries.len() < inner.capacity {
            inner.entries.push(diagnostic);
        } else {
            inner.dropped = inner.dropped.saturating_add(1);
        }
    }

    /// A copy of the stored diagnostics, oldest first.
    pub fn snapshot(&self) -> Vec<Diagnostic> {
        self.lock().entries.clone()
    }

    /// Removes and returns the stored diagnostics, oldest first, and resets the dropped count.
    pub fn take(&self) -> Vec<Diagnostic> {
        let mut inner = self.lock();
        inner.dropped = 0;
        std::mem::take(&mut inner.entries)
    }

    /// The number of stored diagnostics.
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Whether no diagnostic is stored.
    pub fn is_empty(&self) -> bool {
        self.lock().entries.is_empty()
    }

    /// The number of diagnostics that were reported after the log was full.
    pub fn dropped(&self) -> u64 {
        self.lock().dropped
    }
}

impl Default for DiagnosticLog {
    /// A log bounded by the default [`Limits::max_diagnostics`].
    fn default() -> Self {
        Self::with_limits(&Limits::DEFAULT)
    }
}

impl Clone for DiagnosticLog {
    fn clone(&self) -> Self {
        let inner = self.lock();
        DiagnosticLog {
            inner: Mutex::new(LogInner {
                entries: inner.entries.clone(),
                capacity: inner.capacity,
                dropped: inner.dropped,
            }),
        }
    }
}

impl DiagnosticSink for DiagnosticLog {
    fn report(&self, diagnostic: Diagnostic) {
        self.push(diagnostic);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_is_bounded() {
        let log = DiagnosticLog::new(2);
        for i in 0..5 {
            log.report(Diagnostic::new(DiagnosticKind::Other, Some(i), "x"));
        }
        assert_eq!(log.len(), 2);
        assert_eq!(log.dropped(), 3);
        let entries = log.snapshot();
        assert_eq!(entries[0].offset, Some(0));
        assert_eq!(entries[1].offset, Some(1));
        let clone = log.clone();
        assert_eq!(log.take().len(), 2);
        assert!(log.is_empty());
        assert_eq!(log.dropped(), 0);
        assert_eq!(clone.len(), 2);
        assert_eq!(clone.dropped(), 3);
    }

    #[test]
    fn default_log_uses_limits() {
        let log = DiagnosticLog::with_limits(&Limits::default().with_max_diagnostics(0));
        log.push(Diagnostic::new(DiagnosticKind::Other, None, "x"));
        assert!(log.is_empty());
        assert_eq!(log.dropped(), 1);
        let log = DiagnosticLog::default();
        log.push(Diagnostic::new(DiagnosticKind::Other, None, "x"));
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn log_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DiagnosticLog>();
        assert_send_sync::<Diagnostic>();
    }

    #[test]
    fn all_lists_every_kind_in_declaration_order() {
        for (i, &kind) in DiagnosticKind::ALL.iter().enumerate() {
            assert_eq!(kind as usize, i, "{kind}");
        }
        // `Other` stays the last variant, so this also proves that none is missing.
        assert_eq!(
            DiagnosticKind::ALL.len(),
            DiagnosticKind::Other as usize + 1
        );
    }

    #[test]
    fn kind_identifiers_are_unique_camel_case() {
        let mut seen = std::collections::HashSet::new();
        for kind in DiagnosticKind::ALL {
            let s = kind.as_str();
            assert!(seen.insert(s), "duplicate {s}");
            assert!(s.bytes().all(|b| b.is_ascii_alphabetic()), "{s}");
            assert!(s.as_bytes()[0].is_ascii_lowercase(), "{s}");
            assert_eq!(kind.to_string(), s);
        }
    }

    /// With the `serde` feature, kinds use the same text as `as_str`.
    #[cfg(feature = "serde")]
    #[test]
    fn kind_serde_names() {
        use serde::Deserialize;
        use serde::de::IntoDeserializer;
        use serde::de::value::{Error as DeError, StrDeserializer};

        for &kind in DiagnosticKind::ALL {
            let de: StrDeserializer<'_, DeError> = kind.as_str().into_deserializer();
            assert_eq!(DiagnosticKind::deserialize(de).unwrap(), kind);
        }
    }

    #[test]
    fn display() {
        let d = Diagnostic::new(DiagnosticKind::StreamLength, Some(42), "scanned");
        assert_eq!(d.to_string(), "[streamLength] at byte 42: scanned");
        let d = Diagnostic::new(DiagnosticKind::Other, None, "hm");
        assert_eq!(d.to_string(), "[other] hm");
        assert_eq!(Strictness::default(), Strictness::Lenient);
    }
}

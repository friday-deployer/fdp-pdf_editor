//! Cross-reference tables, cross-reference streams and the trailer chain (ISO 32000-2
//! §7.5.4–§7.5.8).
//!
//! The [`Store`] uses this module while opening a file:
//!
//! 1. [`find_header`] locates `%PDF-` (bytes before it shift every offset, Annex H), and
//!    [`Markers`] finds the `startxref` keywords: the last one first, and the earlier ones only
//!    when they are needed (a last `startxref` that leads nowhere, or a revision whose end is not
//!    right after its section).
//! 2. [`read_chain`] reads the newest cross-reference section and follows `/Prev` (and, for
//!    hybrid files, `/XRefStm`) to the oldest one. Each section becomes a [`Revision`]; the
//!    entries of all sections are merged so that the newest section wins, and within a hybrid
//!    section the table wins over its `/XRefStm` stream, free entries included (see
//!    `Merger::add` for the §7.5.8.4 rule).
//!
//! Every section offset is validated: it must point at `xref` or at an `N G obj` header (after
//! optional white-space). Otherwise the section is searched for within ±64 bytes; when that fails
//! for the newest section the caller falls back to a full reconstruction (`repair.rs`).
//!
//! # Cost
//!
//! Reading the chain costs time and memory linear in the file size, however the sections are
//! arranged ([`XrefBudget`]): the sections read (every attempt included) may parse at most
//! [`LimitKind::XrefBytes`] bytes (`max(1 MiB, 4 × file length)`), which bounds sections that
//! overlap or never end, and they may hold at most [`LimitKind::XrefEntries`] entries together
//! (`max(2^20, 4 × file length)`), which bounds highly compressed cross-reference streams and long
//! `/Prev` chains of them. At most [`LimitKind::ObjectCap`] in-use entries are kept
//! (`min(max_objects, max(4096, file length))`), the lowest numbers ([`object_cap`]): a file
//! cannot claim more objects than it has bytes. All three scale with
//! [`Limits::budget_scale`](crate::Limits::budget_scale) and are reported under their own
//! [`LimitKind`].
//! Rows of a cross-reference stream are merged as they are decoded, without a copy per section.
//!
//! All positions handled here are absolute byte positions in the source buffer; offsets read from
//! the file are relative to the `%PDF-` header and are converted on the way in.

use std::collections::HashSet;

use crate::diag::DiagnosticKind;
use crate::error::{Error, ErrorCode, Result};
use crate::lexer::{Lexer, Token, TokenKind, find_bytes, is_regular, is_whitespace};
use crate::limits::{LimitKind, Limits};
use crate::object::{Dict, Object, ObjectId, keys};
use crate::parser::parse_object;
use crate::store::{Chain, Charge, Mode, Store};

/// How the cross-reference information of a [`Revision`] is stored (§7.5.4, §7.5.8).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum XrefKind {
    /// A classic `xref` table followed by a `trailer` dictionary (§7.5.4, §7.5.5).
    Table,
    /// A cross-reference stream, whose dictionary is also the trailer (§7.5.8).
    Stream,
    /// A table whose trailer has `/XRefStm`, pointing at a cross-reference stream with the
    /// entries of compressed objects (a hybrid-reference file, §7.5.8.4).
    Hybrid,
    /// The cross-reference data was unusable and was rebuilt by scanning the whole file for
    /// `N G obj` headers. Such a file has no trustworthy revision structure: write it with a full
    /// save, not an incremental one.
    Reconstructed,
}

/// One cross-reference section of the file and its trailer: the original file or one
/// incremental update (§7.5.6).
///
/// [`Store::revisions`](crate::Store::revisions) lists them in `/Prev` order, oldest first:
/// these are *logical* sections, not byte ranges in file order. A linearized file (Annex F), for
/// example, has its newest section (the first-page cross-reference table) near the start of the
/// file. So neither `startxref` nor `eof_end` has to grow from one revision to the next, and an
/// incremental update is appended after the end of the source, never after an `eof_end`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub struct Revision {
    /// The offset of this revision's cross-reference section, as a `startxref` value would give
    /// it: relative to the `%PDF-` header. When the file's own offset was wrong, this is the
    /// repaired one. For a file whose writer counted the bytes before the header (see
    /// [`Store::offset_base`](crate::Store::offset_base)), the file's own `/Prev` and `startxref`
    /// values are this plus [`Store::header_offset`](crate::Store::header_offset).
    pub startxref: u64,
    /// The absolute position just past this revision's `%%EOF` marker and the end-of-line after
    /// it: a signature that covers `[0, eof_end)` covers exactly the file up to this revision.
    ///
    /// It is found from the `startxref` keyword whose value points at this revision's section
    /// (the first such keyword after the section), so a linearized file's first-page section
    /// ends where the file does, not at the dummy `startxref 0` after it. Without such a keyword,
    /// the first `%%EOF` shortly after the section counts. Without a `%%EOF` (a damaged file): the
    /// end of the `startxref` line, or the end of the section, or for the newest revision the end
    /// of the file.
    pub eof_end: u64,
    /// The absolute position just past the section itself: past the trailer dictionary of a
    /// table, or past the cross-reference stream object.
    pub section_end: u64,
    /// For a hybrid section ([`XrefKind::Hybrid`]), the offset of the `/XRefStm` stream that was
    /// read, relative to the header like [`Revision::startxref`].
    pub xref_stm: Option<u64>,
    /// How the cross-reference information is stored.
    pub xref_kind: XrefKind,
    /// The trailer dictionary as written (for a cross-reference stream, the stream dictionary,
    /// which doubles as the trailer).
    pub trailer: Dict,
}

/// Which position the offsets in a file count from (Annex H).
///
/// ISO 32000-2 counts offsets from the `%PDF-` header, so bytes before the header (junk, a mail
/// header) do not shift them. Some writers count them anyway. When the header is at byte 0 both
/// conventions agree, and this is [`OffsetBase::HeaderRelative`].
///
/// The enum is `#[non_exhaustive]`, like [`XrefKind`] and [`XrefEntry`]: a `match` outside this
/// crate needs a wildcard arm.
///
/// ```
/// use folioxide_syntax::OffsetBase;
///
/// fn describe(base: OffsetBase) -> &'static str {
///     match base {
///         OffsetBase::HeaderRelative => "from the header",
///         OffsetBase::Absolute => "from byte 0",
///         _ => "another convention",
///     }
/// }
/// assert_eq!(describe(OffsetBase::default()), "from the header");
/// ```
///
/// Without the wildcard arm the `match` does not compile:
///
/// ```compile_fail,E0004
/// # use folioxide_syntax::OffsetBase;
/// fn describe(base: OffsetBase) -> &'static str {
///     match base {
///         OffsetBase::HeaderRelative => "from the header",
///         OffsetBase::Absolute => "from byte 0",
///     }
/// }
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum OffsetBase {
    /// Offsets count from the `%PDF-` header, as the standard says (and every file whose header
    /// is at byte 0).
    #[default]
    HeaderRelative,
    /// Offsets count from the first byte of the file, junk before the header included.
    Absolute,
}

/// One cross-reference entry (§7.5.4 and §7.5.8.3, Table 18), as
/// [`Store::revision_entries`](crate::Store::revision_entries) reports it.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XrefEntry {
    /// A free entry: the object does not exist. `gen` is the generation a re-use must take.
    ///
    /// An entry that refers to the null object also reads as a free entry with generation 0: a
    /// cross-reference stream entry of an unknown type (§7.5.8.3: "any other value shall be
    /// interpreted as a reference to the null object"), and an in-use entry whose generation or
    /// offset is out of range. Like a free entry, it hides the entries of older sections.
    Free {
        /// The generation for the next use of this object number.
        r#gen: u16,
    },
    /// An uncompressed object at the absolute position `pos` of the source (the header offset is
    /// already added).
    InFile {
        /// Absolute position of the object's `N G obj` header, as the entry gives it.
        pos: u64,
        /// The generation.
        r#gen: u16,
    },
    /// A compressed object: entry `index` of the object stream `stream` (generation 0).
    InObjStm {
        /// The object number of the object stream.
        stream: u32,
        /// The index of the object within the object stream.
        index: u32,
    },
}

impl XrefEntry {
    /// Whether this is a free entry.
    pub fn is_free(self) -> bool {
        matches!(self, XrefEntry::Free { .. })
    }

    /// The entry that stands for the null object (see [`XrefEntry::Free`]).
    const NULL: XrefEntry = XrefEntry::Free { r#gen: 0 };
}

/// The `%PDF-` header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    /// Absolute position of `%PDF-`: the base of every offset in the file.
    pub offset: usize,
    /// The version from the header, if it is well formed.
    pub version: Option<(u8, u8)>,
}

/// Annex H: readers should accept the header anywhere in the first 1024 bytes.
const HEADER_WINDOW: usize = 1024;

/// How far around a wrong offset to look for the object or section it should point at (ARCHITECTURE
/// §A.10 trap #3).
pub(crate) const LOCAL_SEARCH: usize = 64;

/// How many candidate positions of the local search are tried as cross-reference sections.
const MAX_SECTION_CANDIDATES: usize = 4;

/// The longest run of white-space accepted inside an `N G obj` header by the fast matchers. Real
/// files use one or two bytes; a bound keeps every probe `O(1)`.
const MAX_HEADER_SPACE: usize = 32;

/// How far after a section, or after a `startxref` value, to look for `startxref` or `%%EOF`.
const EOF_WINDOW: usize = 2048;

/// The `startxref` keyword (§7.5.5).
const STARTXREF: &[u8] = b"startxref";

/// How far after `startxref` its value may start (white-space and comments included).
const STARTXREF_VALUE_WINDOW: usize = 256;

/// How many earlier `startxref` values are tried when the last one leads to no section.
pub(crate) const MAX_STARTXREF_FALLBACKS: usize = 8;

/// The most in-use objects the store keeps for a file of `len` bytes ([`LimitKind::ObjectCap`]):
/// `min(max_objects, max(4096, len))`, scaled by `Limits::budget_scale`. A real object costs
/// several bytes of the file, even compressed, so a file that claims more objects than it has
/// bytes is hostile, and this bounds the memory a small file can make the store reserve.
pub(crate) fn object_cap(limits: &Limits, len: usize) -> u64 {
    limits.budget(LimitKind::ObjectCap, len as u64)
}

/// Finds `%PDF-`: first in the first 1024 bytes (Annex H), then anywhere in the file.
pub(crate) fn find_header(bytes: &[u8]) -> Option<Header> {
    const MARKER: &[u8] = b"%PDF-";
    let window = bytes
        .get(..HEADER_WINDOW.saturating_add(MARKER.len()))
        .unwrap_or(bytes);
    let offset = find_bytes(window, MARKER, 0).or_else(|| find_bytes(bytes, MARKER, 0))?;
    let version = bytes
        .get(offset.saturating_add(MARKER.len())..)
        .and_then(parse_version);
    Some(Header { offset, version })
}

/// Parses `M.m` (the version after `%PDF-`).
fn parse_version(rest: &[u8]) -> Option<(u8, u8)> {
    let digits = |s: &[u8]| -> Option<(u8, usize)> {
        let len = s.iter().take_while(|b| b.is_ascii_digit()).count();
        let text = std::str::from_utf8(s.get(..len)?).ok()?;
        Some((text.parse().ok()?, len))
    };
    let (major, len) = digits(rest)?;
    if rest.get(len) != Some(&b'.') {
        return None;
    }
    let (minor, _) = digits(rest.get(len + 1..)?)?;
    Some((major, minor))
}

/// A `startxref` keyword and the offset after it (§7.5.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Marker {
    /// Absolute position of the keyword.
    pub at: usize,
    /// The offset after it, if it is a non-negative integer.
    pub value: Option<u64>,
    /// The absolute end of that integer (of the keyword, without one).
    pub value_end: usize,
}

/// Reads the `startxref` keyword at `at`. The value is read within a small window, so reading
/// many markers stays linear even when they sit in one long comment.
fn marker_at(bytes: &[u8], at: usize) -> Marker {
    let after = at.saturating_add(STARTXREF.len());
    let end = after
        .saturating_add(STARTXREF_VALUE_WINDOW)
        .min(bytes.len());
    let window = bytes.get(..end).unwrap_or(bytes);
    let mut lexer = Lexer::new(window, after);
    match lexer.next_token() {
        Ok(Some(Token {
            kind: TokenKind::Integer(n),
            end,
            ..
        })) => Marker {
            at,
            value: u64::try_from(n).ok(),
            value_end: end,
        },
        _ => Marker {
            at,
            value: None,
            value_end: after,
        },
    }
}

/// The last `startxref` keyword before `end`.
fn marker_before(bytes: &[u8], end: usize) -> Option<Marker> {
    let at = bytes
        .get(..end)?
        .windows(STARTXREF.len())
        .rposition(|window| window == STARTXREF)?;
    Some(marker_at(bytes, at))
}

/// The value after the last `startxref` keyword in the file (§7.5.5), if it is a non-negative
/// integer.
#[cfg(test)]
fn find_startxref(bytes: &[u8]) -> Option<u64> {
    marker_before(bytes, bytes.len())?.value
}

/// The `startxref` keywords of a file. The last one is found at once (a search from the end);
/// the others only when they are needed, by one backward search over the file that keeps the
/// newest `max` of them.
pub(crate) struct Markers<'b> {
    bytes: &'b [u8],
    max: usize,
    last: Option<Marker>,
    all: Option<Vec<Marker>>,
    /// `(value, position)` of every marker in `all` that has a value, sorted.
    by_value: Option<Vec<(u64, usize)>>,
}

impl<'b> Markers<'b> {
    pub(crate) fn new(bytes: &'b [u8], max: usize) -> Markers<'b> {
        Markers {
            bytes,
            max,
            last: marker_before(bytes, bytes.len()),
            all: None,
            by_value: None,
        }
    }

    /// The last `startxref` in the file.
    pub(crate) fn last(&self) -> Option<Marker> {
        self.last
    }

    /// The newest `max` markers, in file order.
    pub(crate) fn all(&mut self) -> &[Marker] {
        let (bytes, max) = (self.bytes, self.max);
        self.all.get_or_insert_with(|| {
            let mut found = Vec::new();
            let mut end = bytes.len();
            while found.len() < max {
                let Some(marker) = marker_before(bytes, end) else {
                    break;
                };
                end = marker.at;
                found.push(marker);
            }
            found.reverse();
            found
        })
    }

    /// The first marker at or after `from` whose value is one of `values`, in `O(log n)`.
    fn first_with_value(&mut self, values: &[u64], from: usize) -> Option<Marker> {
        if self.by_value.is_none() {
            let mut index: Vec<(u64, usize)> = self
                .all()
                .iter()
                .filter_map(|m| Some((m.value?, m.at)))
                .collect();
            index.sort_unstable();
            self.by_value = Some(index);
        }
        let index = self.by_value.as_deref()?;
        let at = values
            .iter()
            .filter_map(|&value| {
                let first = index.partition_point(|&entry| entry < (value, from));
                index
                    .get(first)
                    .filter(|entry| entry.0 == value)
                    .map(|e| e.1)
            })
            .min()?;
        Some(marker_at(self.bytes, at))
    }
}

/// Matches an `N G obj` header at `pos`, after at most a little white-space, in `O(1)`.
///
/// Returns the identifier and the position just past `obj`. Comments inside the header are not
/// accepted here (the full parser accepts them); this matcher is for probing many positions.
pub(crate) fn object_header_at(bytes: &[u8], pos: usize) -> Option<(ObjectId, usize)> {
    let mut i = skip_space(bytes, pos, 0)?;
    let (num, after_num) = read_digits(bytes, i, 10)?;
    i = skip_space(bytes, after_num, 1)?;
    let (r#gen, after_gen) = read_digits(bytes, i, 5)?;
    i = skip_space(bytes, after_gen, 1)?;
    let after = i.checked_add(3)?;
    if bytes.get(i..after) != Some(b"obj") || bytes.get(after).is_some_and(|&b| is_regular(b)) {
        return None;
    }
    let num = u32::try_from(num).ok()?;
    let r#gen = u16::try_from(r#gen).ok()?;
    Some((ObjectId::new(num, r#gen), after))
}

/// Whether the keyword `xref` starts at `pos`, after at most a little white-space; returns the
/// position of the keyword.
fn xref_keyword_at(bytes: &[u8], pos: usize) -> Option<usize> {
    let i = skip_space(bytes, pos, 0)?;
    let after = i.checked_add(4)?;
    (bytes.get(i..after) == Some(b"xref") && !bytes.get(after).is_some_and(|&b| is_regular(b)))
        .then_some(i)
}

/// Skips between `min` and [`MAX_HEADER_SPACE`] white-space bytes.
fn skip_space(bytes: &[u8], pos: usize, min: usize) -> Option<usize> {
    let count = bytes
        .get(pos..)?
        .iter()
        .take(MAX_HEADER_SPACE + 1)
        .take_while(|&&b| is_whitespace(b))
        .count();
    (count >= min && count <= MAX_HEADER_SPACE).then_some(pos + count)
}

/// Reads 1 to `max` decimal digits.
fn read_digits(bytes: &[u8], pos: usize, max: usize) -> Option<(u64, usize)> {
    let rest = bytes.get(pos..)?;
    let len = rest
        .iter()
        .take(max + 1)
        .take_while(|b| b.is_ascii_digit())
        .count();
    if len == 0 || len > max {
        return None;
    }
    let mut value = 0u64;
    for &d in rest.get(..len)? {
        value = value * 10 + u64::from(d - b'0');
    }
    Some((value, pos + len))
}

/// `end`, plus one end-of-line (CR LF, CR or LF) if one follows.
fn with_eol(bytes: &[u8], end: usize) -> u64 {
    let eol = match (bytes.get(end), bytes.get(end + 1)) {
        (Some(b'\r'), Some(b'\n')) => 2,
        (Some(b'\r' | b'\n'), _) => 1,
        _ => 0,
    };
    (end + eol) as u64
}

/// The absolute end of the `%%EOF` marker (and one EOL after it) that follows `from`, looking
/// at most [`EOF_WINDOW`] bytes ahead.
pub(crate) fn eof_end_after(bytes: &[u8], from: usize) -> Option<u64> {
    let window = bytes.get(from..from.saturating_add(EOF_WINDOW).min(bytes.len()))?;
    let at = from + find_bytes(window, b"%%EOF", 0)?;
    Some(with_eol(bytes, at + 5))
}

/// The end of the revision that the `startxref` keyword `marker` closes: past the `%%EOF` (and
/// its EOL) that follows the value, or, without one before the next `startxref`, past the value
/// line.
fn eof_after_marker(bytes: &[u8], marker: &Marker) -> u64 {
    let from = marker.value_end;
    let window = bytes
        .get(from..from.saturating_add(EOF_WINDOW).min(bytes.len()))
        .unwrap_or_default();
    // A `%%EOF` after the next `startxref` belongs to another revision.
    let stop = find_bytes(window, STARTXREF, 0).unwrap_or(window.len());
    match find_bytes(window.get(..stop).unwrap_or_default(), b"%%EOF", 0) {
        Some(at) => with_eol(bytes, from + at + 5),
        None => with_eol(bytes, from),
    }
}

/// The end of the revision whose section ends at `section_end` and whose `startxref` holds one of
/// `values`: the first `startxref` keyword after the section with such a value closes it.
fn revision_eof(
    bytes: &[u8],
    markers: &mut Markers<'_>,
    section_end: usize,
    values: [u64; 3],
) -> Option<u64> {
    let matches = |m: &Marker| m.value.is_some_and(|v| values.contains(&v));
    // Usually the keyword right after the section.
    let window = bytes.get(section_end..section_end.saturating_add(EOF_WINDOW).min(bytes.len()))?;
    if let Some(at) = find_bytes(window, STARTXREF, 0) {
        let marker = marker_at(bytes, section_end + at);
        if matches(&marker) {
            return Some(eof_after_marker(bytes, &marker));
        }
    }
    // Otherwise (a linearized file's first-page section, or more objects after a stream) any
    // later one.
    markers
        .first_with_value(&values, section_end)
        .map(|m| eof_after_marker(bytes, &m))
}

/// What reading the cross-reference sections of one file may cost, all sections and every
/// attempt together (see the module documentation).
#[derive(Clone, Copy, Debug)]
pub(crate) struct XrefBudget {
    /// Source bytes the reader may still parse.
    bytes: u64,
    /// Entries it may still read.
    rows: u64,
    /// The initial number of bytes, for diagnostics ([`LimitKind::XrefBytes`]).
    max_bytes: u64,
    /// The initial number of entries, for diagnostics ([`LimitKind::XrefEntries`]).
    max_rows: u64,
}

impl XrefBudget {
    /// The budget for a file of `len` bytes.
    pub(crate) fn for_len(limits: &Limits, len: usize) -> XrefBudget {
        let len = len as u64;
        let rows = limits.budget(LimitKind::XrefEntries, len);
        let bytes = limits.budget(LimitKind::XrefBytes, len);
        XrefBudget {
            bytes,
            rows,
            max_bytes: bytes,
            max_rows: rows,
        }
    }

    /// Whether nothing more can be read.
    pub(crate) fn is_exhausted(&self) -> bool {
        self.bytes == 0 || self.rows == 0
    }
}

/// How the newest section was found (see [`Store::offset_base`](crate::Store::offset_base)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum How {
    /// At the offset, counted from the header.
    Exact,
    /// At the offset counted from byte 0, although the header is later.
    Absolute,
    /// By the local search.
    Nearby,
}

/// The result of reading the `/Prev` chain.
#[derive(Debug)]
pub(crate) struct XrefChain {
    /// The merged in-use entries, sorted by object number: for each number, the entry of the
    /// newest section that lists it, unless that entry is free.
    pub entries: Vec<(u32, XrefEntry)>,
    /// Every object number some section lists, free entries included.
    pub listed: HashSet<u32>,
    /// The numbers whose merged entry is free (or stands for the null object), grouped by the
    /// absolute position of the section (table or cross-reference stream) that lists them: a
    /// definition after that position is newer than the deletion (see
    /// `Store::shadowed_definition`).
    pub freed: Vec<(usize, Vec<u32>)>,
    /// The largest object number listed (free entries included).
    pub max_object_number: Option<u32>,
    /// True when in-use entries were dropped because of [`object_cap`].
    pub overflow: bool,
    /// The revisions, oldest first.
    pub revisions: Vec<Revision>,
    /// False when an older section could not be read or the chain was cut by
    /// [`Limits::max_xref_sections`](crate::Limits::max_xref_sections) or the budget, so objects
    /// that only older sections list may be missing.
    pub complete: bool,
    /// The absolute positions of every section read (tables, cross-reference streams and
    /// `/XRefStm` streams), ascending. Objects end before them (see `Store::region_end`).
    pub section_starts: Vec<usize>,
    /// How the newest section was found.
    pub newest: How,
}

/// One cross-reference section as read from the file.
struct Section {
    kind: XrefKind,
    /// The entries of a table, in file order. The rows of a cross-reference stream go to the
    /// [`Merger`] as they are decoded, so this is empty for a stream.
    entries: Vec<(u32, XrefEntry)>,
    trailer: Dict,
    /// Absolute position of `xref` or of the stream's object header.
    pos: usize,
    /// Absolute position just past the trailer dictionary or the stream object.
    end: usize,
    /// For a hybrid section, the absolute position of the `/XRefStm` stream that was read.
    hidden: Option<usize>,
}

enum Located {
    Section(Section, How),
    /// The offset leads to a section that was already read.
    Loop(usize),
    /// Reading the section would exceed the [`XrefBudget`]; the limit that stands for it.
    OverBudget(LimitKind),
    /// No section at or near the offset.
    Missing,
}

/// Why a section could not be read.
enum SectionError {
    /// The [`XrefBudget`] ran out; the limit that stands for it.
    Budget(LimitKind),
    /// The section is unusable (or, in strict mode, needed a repair).
    Failed(Error),
}

impl From<Error> for SectionError {
    fn from(err: Error) -> SectionError {
        SectionError::Failed(err)
    }
}

/// Whether a [`Merger`] merges sections into one view or collects one section's entries as
/// written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MergeMode {
    Merge,
    Collect,
}

/// Merges the entries of the sections, newest section first.
struct Merger {
    mode: MergeMode,
    /// The object numbers merged so far (free entries included).
    seen: HashSet<u32>,
    /// `Merge`: the in-use entries kept, one per number. `Collect`: every entry, in file order.
    entries: Vec<(u32, XrefEntry)>,
    /// The most in-use entries `Merge` keeps ([`object_cap`]): the lowest numbers.
    cap: usize,
    /// Set when in-use entries were dropped because of `cap`.
    overflow: bool,
    max_num: Option<u32>,
    /// `Merge`: the numbers whose entry (the newest one) is free, grouped by the section that
    /// lists them, in merge order (4 bytes per entry).
    freed: Vec<(usize, Vec<u32>)>,
    /// The absolute position of the section whose entries are being added.
    section: usize,
}

impl Merger {
    fn new(mode: MergeMode, cap: u64) -> Merger {
        Merger {
            mode,
            seen: HashSet::new(),
            entries: Vec::new(),
            cap: usize::try_from(cap).unwrap_or(usize::MAX),
            overflow: false,
            max_num: None,
            freed: Vec::new(),
            section: 0,
        }
    }

    /// Starts adding the entries of the section at the absolute position `pos`.
    fn begin_section(&mut self, pos: usize) {
        self.section = pos;
    }

    /// Adds one entry of the section being merged; entries of newer sections were added before.
    ///
    /// # Hybrid-reference files
    ///
    /// ISO 32000-2 §7.5.8.4 fixes the order in which a reader that understands cross-reference
    /// streams looks an object up: "if an entry is not found in any given standard
    /// cross-reference section, the search shall proceed to a cross-reference stream specified by
    /// the XRefStm entry before looking in the previous cross-reference section (the Prev entry in
    /// the trailer)". So the table of a hybrid section is added first, then its `/XRefStm`
    /// stream, then the older sections, and per object number:
    ///
    /// 1. the table of the newest section that lists the number at all, **free entries
    ///    included**;
    /// 2. otherwise that section's `/XRefStm` stream;
    /// 3. otherwise the older sections, in the same way.
    ///
    /// A free entry *is* an entry: when the table of a section marks an object free, the
    /// `/XRefStm` stream of that same section is not consulted for it, and the object is
    /// deleted. The note in §7.5.8.4 describes the layout writers produce: a hidden (compressed)
    /// object has its in-use entry in the stream and a free entry in "some previous section,
    /// typically the section referenced by the Prev entry"; the newer section's stream overrides
    /// that older free entry ("A PDF reader shall look in the cross-reference stream first, find
    /// the object there, and shall ignore the free entry in the previous section"), while the
    /// newer section's own table leaves the hidden object out of its subsections (Acrobat; Word
    /// writes an empty table).
    ///
    /// This is how qpdf 12, poppler 24 and pdf.js read hybrid files, and the reading of the PDF
    /// Association's issue tracker (pdf-issues #237). It also matches what a reader that ignores
    /// `/XRefStm` sees, so a well-formed hybrid file means the same to both kinds of reader.
    fn add(&mut self, num: u32, entry: XrefEntry) {
        if self.mode == MergeMode::Collect {
            self.entries.push((num, entry));
            return;
        }
        if !self.seen.insert(num) {
            return;
        }
        self.max_num = self.max_num.max(Some(num));
        if entry.is_free() {
            match self.freed.last_mut() {
                Some((at, nums)) if *at == self.section => nums.push(num),
                _ => self.freed.push((self.section, vec![num])),
            }
            return;
        }
        if self.entries.len() >= self.cap.saturating_mul(2).max(1) {
            self.compact();
        }
        self.entries.push((num, entry));
    }

    /// Keeps the `cap` lowest-numbered in-use entries (`Merge`), sorted by number. Run whenever
    /// twice as many have accumulated, so memory stays within `2 × cap` entries.
    fn compact(&mut self) {
        self.entries.sort_unstable_by_key(|&(num, _)| num);
        if self.entries.len() > self.cap {
            self.entries.truncate(self.cap);
            self.overflow = true;
        }
    }
}

/// Reads the cross-reference chain that starts at `startxref` (relative to the header).
///
/// Returns `Ok(None)` when the newest section cannot be read at all, which calls for a full
/// reconstruction (or another `startxref`). Repairs are reported through the store's policy, so
/// in strict mode they are errors. `budget` is shared by every attempt to read the file's chain.
pub(crate) fn read_chain(
    store: &Store,
    startxref: u64,
    budget: &mut XrefBudget,
    markers: &mut Markers<'_>,
) -> Result<Option<XrefChain>> {
    let mut reader = ChainReader::new(store, *budget, MergeMode::Merge, false);
    let chain = reader.chain(startxref, markers);
    *budget = reader.budget;
    chain
}

/// The entries of one revision's section as written: the table's or stream's entries in file
/// order, then those of the `/XRefStm` stream at `hidden`, if any. `pos` and `hidden` are
/// absolute positions of sections that were read when the file was opened. Reads quietly, with a
/// budget of its own.
pub(crate) fn section_entries(
    store: &Store,
    pos: usize,
    hidden: Option<usize>,
) -> Result<Vec<(u32, XrefEntry)>> {
    let budget = XrefBudget::for_len(store.limits(), store.bytes().len());
    let mut reader = ChainReader::new(store, budget, MergeMode::Collect, true);
    for (at, want_stream) in std::iter::once((pos, false)).chain(hidden.map(|h| (h, true))) {
        let section = match reader.read_section(at) {
            Ok(section) => section,
            Err(SectionError::Failed(err)) => return Err(err),
            Err(SectionError::Budget(limit)) => {
                return Err(Error::limit(
                    limit,
                    reader.limit_value(limit),
                    Some(at as u64),
                ));
            }
        };
        if want_stream && section.kind != XrefKind::Stream {
            return Err(Error::Xref {
                offset: Some(at as u64),
                message: "/XRefStm does not point at a cross-reference stream".into(),
            });
        }
        for (num, entry) in section.entries {
            reader.merger.add(num, entry);
        }
    }
    Ok(reader.merger.entries)
}

struct ChainReader<'s> {
    store: &'s Store,
    bytes: &'s [u8],
    header_offset: u64,
    /// Absolute positions of the sections read so far (loop detection).
    visited: HashSet<usize>,
    sections: u32,
    budget: XrefBudget,
    merger: Merger,
    /// Report nothing (a second read of sections already reported at open time).
    quiet: bool,
}

impl<'s> ChainReader<'s> {
    fn new(store: &'s Store, budget: XrefBudget, mode: MergeMode, quiet: bool) -> ChainReader<'s> {
        let bytes = store.bytes();
        ChainReader {
            store,
            bytes,
            header_offset: store.header_offset(),
            visited: HashSet::new(),
            sections: 0,
            budget,
            merger: Merger::new(mode, object_cap(store.limits(), bytes.len())),
            quiet,
        }
    }

    // ---- policy -------------------------------------------------------------------------------

    /// A repair of the cross-reference structure: a diagnostic in lenient mode, an error in strict
    /// mode.
    fn repair(
        &self,
        kind: DiagnosticKind,
        offset: Option<u64>,
        message: impl FnOnce() -> String,
    ) -> Result<()> {
        self.store
            .recover_structure(self.quiet, kind, offset, message)
    }

    /// A limit that cuts the chain: a diagnostic in lenient mode, an error in strict mode.
    fn limit(&self, limit: LimitKind, message: impl FnOnce() -> String) -> Result<()> {
        self.store.recover_structure_limit(
            self.quiet,
            DiagnosticKind::XrefLoop,
            limit,
            self.limit_value(limit),
            message,
        )
    }

    /// The value reported for `limit`: the limit itself, or the budget it names.
    fn limit_value(&self, limit: LimitKind) -> u64 {
        match limit {
            LimitKind::XrefEntries => self.budget.max_rows,
            LimitKind::XrefBytes => self.budget.max_bytes,
            other => self.store.limits().budget(other, self.bytes.len() as u64),
        }
    }

    /// Reports that the budget stopped the chain.
    fn over_budget(&self, limit: LimitKind) -> Result<()> {
        self.limit(limit, || match limit {
            LimitKind::XrefEntries => format!(
                "the cross-reference sections hold more than {} entries, more than a file of {} \
                 bytes can; older sections ignored",
                self.budget.max_rows,
                self.bytes.len()
            ),
            _ => format!(
                "the cross-reference sections overlap or are too large to read for a file of {} \
                 bytes; older sections ignored",
                self.bytes.len()
            ),
        })
    }

    // ---- the chain ----------------------------------------------------------------------------

    fn chain(&mut self, startxref: u64, markers: &mut Markers<'_>) -> Result<Option<XrefChain>> {
        let limits = *self.store.limits();
        let mut newest_first: Vec<Revision> = Vec::new();
        let mut newest = How::Exact;
        let mut complete = true;
        let mut next = Some(startxref);
        while let Some(offset) = next.take() {
            if self.sections >= limits.max_xref_sections {
                self.limit(LimitKind::MaxXrefSections, || {
                    format!(
                        "more than {} cross-reference sections; older sections ignored",
                        limits.max_xref_sections
                    )
                })?;
                complete = false;
                break;
            }
            let (mut section, how) = match self.locate(offset)? {
                Located::Section(section, how) => (section, how),
                Located::Loop(pos) => {
                    self.repair(DiagnosticKind::XrefLoop, Some(pos as u64), || {
                        format!("/Prev {offset} leads back to a section already read; chain cut")
                    })?;
                    break;
                }
                Located::OverBudget(limit) => {
                    self.over_budget(limit)?;
                    if newest_first.is_empty() {
                        return Ok(None);
                    }
                    complete = false;
                    break;
                }
                Located::Missing if newest_first.is_empty() => return Ok(None),
                Located::Missing => {
                    self.repair(DiagnosticKind::XrefMalformed, None, || {
                        format!("/Prev {offset} does not point at a cross-reference section")
                    })?;
                    complete = false;
                    break;
                }
            };
            if newest_first.is_empty() {
                newest = how;
            }
            // The table first, then its /XRefStm stream (§7.5.8.4, see `Merger::add`).
            self.merger.begin_section(section.pos);
            for (num, entry) in std::mem::take(&mut section.entries) {
                self.merger.add(num, entry);
            }
            let section = self.with_hidden_stream(section)?;
            next = self.prev_offset(&section.trailer)?;
            let relative = |pos: usize| {
                (pos as u64)
                    .checked_sub(self.header_offset)
                    .unwrap_or(pos as u64)
            };
            let startxref = relative(section.pos);
            let fallback_end = if newest_first.is_empty() {
                self.bytes.len()
            } else {
                section.end
            };
            let eof_end = revision_eof(
                self.bytes,
                markers,
                section.end,
                [offset, startxref, section.pos as u64],
            )
            .or_else(|| eof_end_after(self.bytes, section.end))
            .unwrap_or(fallback_end as u64);
            newest_first.push(Revision {
                startxref,
                eof_end,
                section_end: section.end as u64,
                xref_stm: section.hidden.map(relative),
                xref_kind: section.kind,
                trailer: section.trailer,
            });
        }
        newest_first.reverse();
        let mut section_starts: Vec<usize> = self.visited.iter().copied().collect();
        section_starts.sort_unstable();
        let mut merger = std::mem::replace(&mut self.merger, Merger::new(MergeMode::Merge, 0));
        merger.compact();
        Ok(Some(XrefChain {
            entries: merger.entries,
            listed: merger.seen,
            freed: merger.freed,
            max_object_number: merger.max_num,
            overflow: merger.overflow,
            revisions: newest_first,
            complete,
            section_starts,
            newest,
        }))
    }

    /// The `/Prev` offset of a trailer, if any.
    fn prev_offset(&self, trailer: &Dict) -> Result<Option<u64>> {
        match trailer.get(keys::PREV) {
            None | Some(Object::Null) => Ok(None),
            Some(Object::Int(n)) if *n >= 0 => Ok(u64::try_from(*n).ok()),
            Some(other) => {
                let found = other.type_name();
                self.repair(DiagnosticKind::XrefMalformed, None, || {
                    format!("trailer /Prev is not a valid offset ({found}); older sections ignored")
                })?;
                Ok(None)
            }
        }
    }

    /// Finds and reads the section at `offset` (relative to the header): at the offset, at the
    /// offset taken as absolute (some writers ignore junk before the header), then nearby.
    fn locate(&mut self, offset: u64) -> Result<Located> {
        let exact = self.header_offset.checked_add(offset).map(usize::try_from);
        let mut tried: Vec<usize> = Vec::new();
        let mut direct: Vec<(usize, How)> = Vec::new();
        if let Some(Ok(pos)) = exact {
            direct.push((pos, How::Exact));
        }
        if self.header_offset > 0
            && let Ok(pos) = usize::try_from(offset)
        {
            direct.push((pos, How::Absolute));
        }
        for (pos, how) in direct {
            match self.try_section(pos, &mut tried)? {
                Some(Located::Section(section, _)) => {
                    if how == How::Absolute {
                        self.repair(DiagnosticKind::XrefOffsetRepaired, Some(pos as u64), || {
                            format!(
                                "cross-reference offset {offset} is absolute although the \
                                 header is at byte {}",
                                self.header_offset
                            )
                        })?;
                    }
                    return Ok(Located::Section(section, how));
                }
                Some(other) => return Ok(other),
                None => {}
            }
        }
        // Local search around the expected position, nearest candidates first.
        let Some(Ok(center)) = exact else {
            return Ok(Located::Missing);
        };
        let mut candidates: Vec<usize> = (center.saturating_sub(LOCAL_SEARCH)
            ..=center.saturating_add(LOCAL_SEARCH).min(self.bytes.len()))
            .filter(|&p| !tried.contains(&p) && self.starts_section(p))
            .collect();
        candidates.sort_by_key(|&p| p.abs_diff(center));
        candidates.truncate(MAX_SECTION_CANDIDATES);
        for pos in candidates {
            match self.try_section(pos, &mut tried)? {
                Some(Located::Section(section, _)) => {
                    self.repair(DiagnosticKind::XrefOffsetRepaired, Some(pos as u64), || {
                        format!(
                            "cross-reference section expected at byte {center} found at byte {pos}"
                        )
                    })?;
                    return Ok(Located::Section(section, How::Nearby));
                }
                Some(other) => return Ok(other),
                None => {}
            }
        }
        Ok(Located::Missing)
    }

    /// Whether `pos` is the first byte of `xref` or of an `N G obj` header (the start of a
    /// number, not its middle).
    fn starts_section(&self, pos: usize) -> bool {
        let starts_token = pos == 0 || self.bytes.get(pos - 1).is_some_and(|&b| !is_regular(b));
        starts_token
            && match self.bytes.get(pos) {
                Some(b'x') => xref_keyword_at(self.bytes, pos) == Some(pos),
                Some(b) if b.is_ascii_digit() => object_header_at(self.bytes, pos).is_some(),
                _ => false,
            }
    }

    /// Reads a section at `pos` if one is there. Returns `Ok(None)` when there is none; a section
    /// that was already read is a loop.
    fn try_section(&mut self, pos: usize, tried: &mut Vec<usize>) -> Result<Option<Located>> {
        tried.push(pos);
        let start = if let Some(at) = xref_keyword_at(self.bytes, pos) {
            at
        } else if object_header_at(self.bytes, pos).is_some() {
            crate::lexer::skip_whitespace_and_comments(self.bytes, pos)
        } else {
            return Ok(None);
        };
        if self.visited.contains(&start) {
            return Ok(Some(Located::Loop(start)));
        }
        match self.read_section(start) {
            Ok(section) => {
                self.visited.insert(start);
                self.sections = self.sections.saturating_add(1);
                Ok(Some(Located::Section(section, How::Exact)))
            }
            Err(SectionError::Budget(limit)) => {
                // The budget is spent: nothing more is read for this file (no other `startxref`
                // is tried either).
                self.budget.bytes = 0;
                self.budget.rows = 0;
                Ok(Some(Located::OverBudget(limit)))
            }
            // A limit is a policy decision, not damage: report it.
            Err(SectionError::Failed(err)) if err.code() == ErrorCode::LimitExceeded => Err(err),
            Err(SectionError::Failed(err)) => {
                if self.store.is_strict() {
                    return Err(err);
                }
                if !self.quiet {
                    self.store
                        .note_structure(DiagnosticKind::XrefMalformed, err.offset(), || {
                            format!("unusable cross-reference section at byte {start}: {err}")
                        });
                }
                Ok(None)
            }
        }
    }

    /// For a table whose trailer has `/XRefStm`, reads that stream (§7.5.8.4); its rows go to the
    /// merger right after the table's. The stream's own `/Prev` is ignored: the table's trailer
    /// continues the chain.
    fn with_hidden_stream(&mut self, mut section: Section) -> Result<Section> {
        if section.kind != XrefKind::Table {
            return Ok(section);
        }
        let offset = match section.trailer.get(keys::XREF_STM) {
            None | Some(Object::Null) => return Ok(section),
            Some(Object::Int(n)) if *n >= 0 => *n as u64,
            Some(_) => {
                self.repair(
                    DiagnosticKind::XrefMalformed,
                    Some(section.pos as u64),
                    || "trailer /XRefStm is not a valid offset; ignored".to_owned(),
                )?;
                return Ok(section);
            }
        };
        let limits = self.store.limits();
        if self.sections >= limits.max_xref_sections {
            self.limit(LimitKind::MaxXrefSections, || {
                "too many cross-reference sections; /XRefStm ignored".to_owned()
            })?;
            return Ok(section);
        }
        match self.locate(offset)? {
            Located::Section(hidden, _) if hidden.kind == XrefKind::Stream => {
                section.hidden = Some(hidden.pos);
                section.kind = XrefKind::Hybrid;
            }
            Located::Section(..) | Located::Missing => {
                self.repair(
                    DiagnosticKind::XrefMalformed,
                    Some(section.pos as u64),
                    || format!("/XRefStm {offset} does not point at a cross-reference stream"),
                )?;
            }
            Located::Loop(pos) => {
                self.repair(DiagnosticKind::XrefLoop, Some(pos as u64), || {
                    format!("/XRefStm {offset} points at a section already read")
                })?;
            }
            Located::OverBudget(limit) => self.over_budget(limit)?,
        }
        Ok(section)
    }

    /// Reads the section at `pos`, charging the bytes it parses to the budget. Each section may
    /// parse at most what is left of the budget; a parse that fails is charged everything it was
    /// allowed (an unterminated string runs to the end of what it may read).
    fn read_section(&mut self, pos: usize) -> std::result::Result<Section, SectionError> {
        if self.budget.bytes == 0 {
            return Err(SectionError::Budget(LimitKind::XrefBytes));
        }
        let len = self.bytes.len();
        let end = usize::try_from(self.budget.bytes)
            .map_or(len, |allowed| pos.saturating_add(allowed))
            .min(len);
        let mut reached = end;
        let result = if xref_keyword_at(self.bytes, pos) == Some(pos) {
            self.read_table(pos, end, &mut reached)
        } else {
            self.read_stream(pos, end, &mut reached)
        };
        let used = reached.saturating_sub(pos).max(1) as u64;
        self.budget.bytes = self.budget.bytes.saturating_sub(used);
        match result {
            // A parse that ran into the end of the budget, not of the file.
            Err(SectionError::Failed(err))
                if end < len && reached == end && err.code() != ErrorCode::LimitExceeded =>
            {
                Err(SectionError::Budget(LimitKind::XrefBytes))
            }
            other => other,
        }
    }

    // ---- tables (§7.5.4) ----------------------------------------------------------------------

    /// Reads `xref`, its subsections and the trailer, within `bytes[..end]`. Entries are read
    /// token by token, so every end-of-line variant (`SP CR`, `SP LF`, `CR LF`, and the invalid
    /// bare `LF` or `CR`) works.
    fn read_table(
        &mut self,
        pos: usize,
        window_end: usize,
        reached: &mut usize,
    ) -> std::result::Result<Section, SectionError> {
        let store = self.store;
        let bytes = self.bytes.get(..window_end).unwrap_or(self.bytes);
        let ctx = store.parse_ctx(self.quiet);
        let mut lexer = Lexer::with_ctx(bytes, pos + 4, &ctx);
        let mut entries: Vec<(u32, XrefEntry)> = Vec::new();
        let mut first_subsection = true;
        let trailer_at = loop {
            let mark = lexer.position();
            match lexer.next_token() {
                Ok(Some(Token {
                    kind: TokenKind::Integer(start),
                    ..
                })) => {
                    let count = match lexer.next_token() {
                        Ok(Some(Token {
                            kind: TokenKind::Integer(count),
                            ..
                        })) => count,
                        _ => break self.trailer_after_damage(mark, window_end)?,
                    };
                    let (Ok(start), Ok(count)) = (u64::try_from(start), u64::try_from(count))
                    else {
                        break self.trailer_after_damage(mark, window_end)?;
                    };
                    self.read_subsection(&mut lexer, start, count, first_subsection, &mut entries)?;
                    first_subsection = false;
                }
                Ok(Some(Token {
                    kind: TokenKind::Keyword(b"trailer"),
                    end,
                    ..
                })) => break Some(end),
                _ => break self.trailer_after_damage(mark, window_end)?,
            }
        };
        let Some(trailer_at) = trailer_at else {
            return Err(Error::Xref {
                offset: Some(pos as u64),
                message: "cross-reference table without a trailer".into(),
            }
            .into());
        };
        let (trailer, trailer_end) = parse_object(bytes, trailer_at, &ctx)?;
        *reached = trailer_end;
        let Object::Dict(trailer) = trailer else {
            return Err(Error::Xref {
                offset: Some(trailer_at as u64),
                message: format!("the trailer is a {}, not a dictionary", trailer.type_name())
                    .into(),
            }
            .into());
        };
        Ok(Section {
            kind: XrefKind::Table,
            entries,
            trailer,
            pos,
            end: trailer_end,
            hidden: None,
        })
    }

    /// The table is damaged at `mark`: report it and find the next `trailer` keyword before `end`
    /// through the store's keyword index (one linear scan for the whole file, however many tables
    /// are damaged).
    fn trailer_after_damage(&self, mark: usize, end: usize) -> Result<Option<usize>> {
        self.repair(DiagnosticKind::XrefMalformed, Some(mark as u64), || {
            "malformed cross-reference table; skipped to the trailer".to_owned()
        })?;
        Ok(self
            .store
            .scan_index()
            .next_trailer(mark)
            .map(|at| at + b"trailer".len())
            .filter(|&at| at < end))
    }

    /// Reads the entries of one subsection `start count`. Entries are read while the next three
    /// tokens are `offset generation n|f`, so a wrong `count` (too large or too small) only costs
    /// a diagnostic. Every entry read is charged to the budget.
    fn read_subsection(
        &mut self,
        lexer: &mut Lexer<'_>,
        start: u64,
        count: u64,
        first_subsection: bool,
        entries: &mut Vec<(u32, XrefEntry)>,
    ) -> std::result::Result<(), SectionError> {
        let max_objects = self.store.limits().max_objects;
        let subsection_at = Lexer::position(lexer) as u64;
        let mut raw: Vec<RawEntry> = Vec::new();
        loop {
            let mark = Lexer::position(lexer);
            match read_raw_entry(lexer) {
                Some(_) if raw.len() as u64 >= self.budget.rows => {
                    return Err(SectionError::Budget(LimitKind::XrefEntries));
                }
                Some(entry) => raw.push(entry),
                None => {
                    lexer.set_position(mark);
                    break;
                }
            }
            if raw.len() >= max_objects as usize {
                break;
            }
        }
        self.budget.rows -= raw.len() as u64;
        if raw.len() as u64 != count {
            self.repair(DiagnosticKind::XrefMalformed, Some(subsection_at), || {
                format!(
                    "cross-reference subsection {start} {count} has {} entries",
                    raw.len()
                )
            })?;
        }

        // A first subsection that starts at 1 although its first entry is object 0's free entry
        // (`0000000000 65535 f`) is off by one (trap #3).
        let mut base = start;
        if first_subsection && start == 1 && raw.first().is_some_and(|e| !e.in_use) {
            let shift = self.subsection_is_shifted(&raw);
            if shift {
                self.repair(
                    DiagnosticKind::XrefSubsectionShifted,
                    Some(subsection_at),
                    || "cross-reference subsection starts at 1 instead of 0; renumbered".to_owned(),
                )?;
                base = 0;
            }
        }

        let mut invalid: Option<(u32, usize)> = None;
        let mut invalid_count = 0usize;
        for (k, entry) in raw.into_iter().enumerate() {
            let Some(num) = base
                .checked_add(k as u64)
                .and_then(|n| u32::try_from(n).ok())
                .filter(|&n| n < max_objects)
            else {
                self.store.recover_structure_limit(
                    self.quiet,
                    DiagnosticKind::XrefMalformed,
                    LimitKind::MaxObjects,
                    u64::from(max_objects),
                    || format!("object number {base} + {k} exceeds max_objects"),
                )?;
                break;
            };
            let entry = match (u16::try_from(entry.r#gen), entry.in_use) {
                (Ok(r#gen), false) => XrefEntry::Free { r#gen },
                (Ok(r#gen), true) => match self.header_offset.checked_add(entry.offset) {
                    Some(pos) => XrefEntry::InFile { pos, r#gen },
                    None => {
                        invalid.get_or_insert((num, entry.at));
                        invalid_count += 1;
                        XrefEntry::NULL
                    }
                },
                // §7.5.4: generations are at most 65535. The entry stands for the null object
                // and hides older entries for the number, as any entry does.
                (Err(_), _) => {
                    invalid.get_or_insert((num, entry.at));
                    invalid_count += 1;
                    XrefEntry::NULL
                }
            };
            if num == 0 && !entry.is_free() {
                // §7.5.4: object 0 is always the head of the free list.
                continue;
            }
            entries.push((num, entry));
        }
        if let Some((num, at)) = invalid {
            self.repair(DiagnosticKind::XrefMalformed, Some(at as u64), || {
                format!(
                    "{invalid_count} cross-reference entries (the first for object {num}) have a \
                     generation or offset out of range; read as null"
                )
            })?;
        }
        Ok(())
    }

    /// Decides whether a subsection declared as starting at 1 is really numbered from 0, by
    /// checking which object number the first in-use entry's offset holds. Without a usable
    /// entry, the free first entry with generation 65535 decides (as pdf.js does).
    fn subsection_is_shifted(&self, raw: &[RawEntry]) -> bool {
        if let Some((k, entry)) = raw.iter().enumerate().find(|(_, e)| e.in_use)
            && let Some(pos) = self
                .header_offset
                .checked_add(entry.offset)
                .and_then(|p| usize::try_from(p).ok())
            && let Some((id, _)) = object_header_at(self.bytes, pos)
        {
            let k = k as u64;
            if u64::from(id.num) == k {
                return true;
            }
            if u64::from(id.num) == k + 1 {
                return false;
            }
        }
        raw.first().is_some_and(|e| e.r#gen == 65535)
    }

    // ---- streams (§7.5.8) ---------------------------------------------------------------------

    /// Reads a cross-reference stream object at `pos`, within `bytes[..end]`, and merges its rows.
    fn read_stream(
        &mut self,
        pos: usize,
        end: usize,
        reached: &mut usize,
    ) -> std::result::Result<Section, SectionError> {
        let store = self.store;
        let obj = store.parse_source_object(pos, end, self.quiet)?;
        *reached = obj.end;
        let Object::Stream(stream) = obj.object else {
            return Err(Error::Xref {
                offset: Some(pos as u64),
                message: format!(
                    "object {} is a {}, not a cross-reference stream",
                    obj.id,
                    obj.object.type_name()
                )
                .into(),
            }
            .into());
        };
        if !stream.dict.is_type(keys::XREF) {
            if stream.dict.get(keys::W).is_none() {
                return Err(Error::Xref {
                    offset: Some(pos as u64),
                    message: format!("object {} is not a cross-reference stream", obj.id).into(),
                }
                .into());
            }
            self.repair(DiagnosticKind::XrefMalformed, Some(pos as u64), || {
                format!("cross-reference stream {} has no /Type /XRef", obj.id)
            })?;
        }
        let layout = self.stream_layout(&stream.dict, pos)?;
        if self.budget.rows == 0 && layout.claimed > 0 {
            return Err(SectionError::Budget(LimitKind::XrefEntries));
        }
        // §7.5.8.2: cross-reference streams are never encrypted, and their dictionary entries
        // are direct, so no reference needs resolving here. The data may hold at most the rows
        // left in the budget (plus a PNG predictor's tag byte per row).
        let cap = self
            .budget
            .rows
            .saturating_mul(layout.entry_len as u64 + 1)
            .saturating_add(64);
        let cap = usize::try_from(cap).unwrap_or(usize::MAX);
        let decoded = store
            .decode_capped(
                &stream,
                Mode::Peek(&Chain::EMPTY),
                self.quiet,
                cap,
                Charge::Once,
            )?
            .ok_or(SectionError::Budget(LimitKind::XrefEntries))?;
        if !decoded.remaining.is_empty() {
            return Err(Error::Xref {
                offset: Some(pos as u64),
                message: "cross-reference stream uses an image filter".into(),
            }
            .into());
        }
        let rows = (decoded.data.len() / layout.entry_len) as u64;
        let used = rows.min(layout.claimed);
        if used > self.budget.rows {
            return Err(SectionError::Budget(LimitKind::XrefEntries));
        }
        self.budget.rows -= used;
        self.stream_rows(&layout, &decoded.data, pos)?;
        Ok(Section {
            kind: XrefKind::Stream,
            entries: Vec::new(),
            trailer: stream.dict,
            pos,
            end: obj.end,
            hidden: None,
        })
    }

    /// Reads `/W` and `/Index` (§7.5.8.2).
    fn stream_layout(&self, dict: &Dict, pos: usize) -> Result<StreamLayout> {
        let bad = |message: String| Error::Xref {
            offset: Some(pos as u64),
            message: message.into(),
        };
        // /W: three field widths in bytes; a zero width means "use the default" (trap #4).
        let widths: Vec<usize> = dict
            .get_array(keys::W)
            .ok_or_else(|| bad("cross-reference stream has no /W array".to_owned()))?
            .iter()
            .map(|w| {
                w.as_int()
                    .and_then(|w| usize::try_from(w).ok())
                    .filter(|&w| w <= 8)
            })
            .collect::<Option<_>>()
            .ok_or_else(|| bad("/W must hold integers from 0 to 8".to_owned()))?;
        let widths = match widths.as_slice() {
            [a, b, c] => [*a, *b, *c],
            [a, b, c, ..] => {
                self.repair(DiagnosticKind::XrefMalformed, Some(pos as u64), || {
                    "/W has more than three entries; extra ones ignored".to_owned()
                })?;
                [*a, *b, *c]
            }
            _ => return Err(bad("/W must have three entries".to_owned())),
        };
        let entry_len = widths.iter().sum::<usize>();
        if entry_len == 0 {
            return Err(bad("/W describes empty entries".to_owned()));
        }

        // /Index: pairs of (first object number, count); default [0 /Size].
        let index: Vec<(u64, u64)> = match dict.get(keys::INDEX) {
            None | Some(Object::Null) => {
                let size = dict
                    .get_int(keys::SIZE)
                    .and_then(|s| u64::try_from(s).ok())
                    .ok_or_else(|| bad("cross-reference stream has no valid /Size".to_owned()))?;
                vec![(0, size)]
            }
            Some(Object::Array(items)) => {
                let numbers: Option<Vec<u64>> = items
                    .iter()
                    .map(|n| n.as_int().and_then(|n| u64::try_from(n).ok()))
                    .collect();
                let numbers = numbers
                    .filter(|n| n.len() % 2 == 0)
                    .ok_or_else(|| bad("/Index must hold pairs of non-negative integers".into()))?;
                numbers
                    .chunks_exact(2)
                    .filter_map(|pair| match pair {
                        [first, count] => Some((*first, *count)),
                        _ => None,
                    })
                    .collect()
            }
            Some(_) => return Err(bad("/Index is not an array".to_owned())),
        };
        let claimed = index
            .iter()
            .fold(0u64, |sum, &(_, count)| sum.saturating_add(count));
        Ok(StreamLayout {
            widths,
            entry_len,
            index,
            claimed,
        })
    }

    /// Merges the binary entries of a cross-reference stream (§7.5.8.3).
    fn stream_rows(&mut self, layout: &StreamLayout, data: &[u8], pos: usize) -> Result<()> {
        let max_objects = self.store.limits().max_objects;
        self.merger.begin_section(pos);
        let [w0, w1, _] = layout.widths;
        let mut rows = data.chunks_exact(layout.entry_len);
        let mut invalid: Option<u32> = None;
        let mut invalid_count = 0usize;
        let mut unknown: Option<(u32, u64)> = None;
        let mut unknown_count = 0usize;
        'subsections: for &(first, count) in &layout.index {
            for k in 0..count {
                let Some(row) = rows.next() else {
                    self.repair(DiagnosticKind::XrefMalformed, Some(pos as u64), || {
                        "cross-reference stream data is shorter than /Index says".to_owned()
                    })?;
                    break 'subsections;
                };
                let Some(num) = first
                    .checked_add(k)
                    .and_then(|n| u32::try_from(n).ok())
                    .filter(|&n| n < max_objects)
                else {
                    self.store.recover_structure_limit(
                        self.quiet,
                        DiagnosticKind::XrefMalformed,
                        LimitKind::MaxObjects,
                        u64::from(max_objects),
                        || format!("object number {first} + {k} exceeds max_objects"),
                    )?;
                    break 'subsections;
                };
                let (f0, rest) = row.split_at_checked(w0).unwrap_or((&[], &[]));
                let (f1, f2) = rest.split_at_checked(w1).unwrap_or((&[], &[]));
                let kind = if w0 == 0 { 1 } else { be_number(f0) };
                let field2 = be_number(f1);
                let field3 = be_number(f2);
                let entry = match kind {
                    0 => XrefEntry::Free {
                        r#gen: u16::try_from(field3).unwrap_or(u16::MAX),
                    },
                    1 => match (
                        u16::try_from(field3),
                        self.header_offset.checked_add(field2),
                    ) {
                        (Ok(r#gen), Some(pos)) => XrefEntry::InFile { pos, r#gen },
                        _ => {
                            invalid.get_or_insert(num);
                            invalid_count += 1;
                            XrefEntry::NULL
                        }
                    },
                    2 => match (u32::try_from(field2), u32::try_from(field3)) {
                        (Ok(stream), Ok(index)) => XrefEntry::InObjStm { stream, index },
                        _ => {
                            invalid.get_or_insert(num);
                            invalid_count += 1;
                            XrefEntry::NULL
                        }
                    },
                    // §7.5.8.3: "Any other value shall be interpreted as a reference to the null
                    // object, thus permitting new entry types to be defined in the future". Such
                    // an entry is conforming (not damage, so not an error in strict mode). It
                    // hides older entries for the number, as any entry does: skipping it would
                    // let an older section's object show through where a conforming reader sees
                    // null.
                    other => {
                        unknown.get_or_insert((num, other));
                        unknown_count += 1;
                        XrefEntry::NULL
                    }
                };
                if num == 0 && !entry.is_free() {
                    continue;
                }
                self.merger.add(num, entry);
            }
        }
        if let Some(num) = invalid {
            self.repair(DiagnosticKind::XrefMalformed, Some(pos as u64), || {
                format!(
                    "{invalid_count} cross-reference stream entries (the first for object {num}) \
                     have fields out of range; read as null"
                )
            })?;
        }
        if let Some((num, kind)) = unknown
            && !self.quiet
        {
            self.store.note(
                DiagnosticKind::XrefUnknownEntryType,
                Some(pos as u64),
                || {
                    format!(
                        "{unknown_count} cross-reference stream entries (the first for object \
                         {num}) have type {kind}, which this reader does not know; read as \
                         references to the null object (§7.5.8.3)"
                    )
                },
            );
        }
        Ok(())
    }
}

/// The layout of a cross-reference stream's data (§7.5.8.2).
struct StreamLayout {
    /// `/W`: the widths of the three fields.
    widths: [usize; 3],
    /// Bytes per row (not 0).
    entry_len: usize,
    /// `/Index`: (first object number, count) pairs.
    index: Vec<(u64, u64)>,
    /// The rows `/Index` claims, together.
    claimed: u64,
}

/// A big-endian unsigned number of at most eight bytes.
fn be_number(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

/// One raw entry of a cross-reference table.
#[derive(Clone, Copy, Debug)]
struct RawEntry {
    offset: u64,
    r#gen: u64,
    in_use: bool,
    at: usize,
}

/// Reads `offset generation n|f`, or returns `None` (the caller rewinds).
fn read_raw_entry(lexer: &mut Lexer<'_>) -> Option<RawEntry> {
    let int = |lexer: &mut Lexer<'_>| match lexer.next_token() {
        Ok(Some(Token {
            kind: TokenKind::Integer(n),
            start,
            ..
        })) => u64::try_from(n).ok().map(|n| (n, start)),
        _ => None,
    };
    let (offset, at) = int(lexer)?;
    let (r#gen, _) = int(lexer)?;
    let in_use = match lexer.next_token() {
        Ok(Some(Token {
            kind: TokenKind::Keyword(b"n"),
            ..
        })) => true,
        Ok(Some(Token {
            kind: TokenKind::Keyword(b"f"),
            ..
        })) => false,
        _ => return None,
    };
    Some(RawEntry {
        offset,
        r#gen,
        in_use,
        at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_and_version() {
        assert_eq!(
            find_header(b"%PDF-1.7\n"),
            Some(Header {
                offset: 0,
                version: Some((1, 7))
            })
        );
        assert_eq!(
            find_header(b"junk\r\n%PDF-2.0 x"),
            Some(Header {
                offset: 6,
                version: Some((2, 0))
            })
        );
        assert_eq!(find_header(b"%PDF-x").unwrap().version, None);
        assert_eq!(find_header(b"%PDF-1").unwrap().version, None);
        assert_eq!(find_header(b"%PDF-1.999").unwrap().version, None);
        assert_eq!(find_header(b"no header"), None);
        // Beyond the 1024-byte window, the whole file is searched.
        let mut far = vec![b' '; 5000];
        far.extend_from_slice(b"%PDF-1.4");
        assert_eq!(find_header(&far).unwrap().offset, 5000);
    }

    #[test]
    fn startxref_value() {
        assert_eq!(find_startxref(b"x startxref\n123\n%%EOF"), Some(123));
        assert_eq!(
            find_startxref(b"startxref 1 %%EOF startxref\r\n 77 %%EOF\n"),
            Some(77)
        );
        assert_eq!(find_startxref(b"startxref -5 %%EOF"), None);
        assert_eq!(find_startxref(b"startxref"), None);
        assert_eq!(find_startxref(b"nothing"), None);
    }

    #[test]
    fn fast_header_matcher() {
        assert_eq!(
            object_header_at(b"12 0 obj<<>>", 0),
            Some((ObjectId::new(12, 0), 8))
        );
        assert_eq!(
            object_header_at(b"\r\n7 65535 obj\n", 0),
            Some((ObjectId::new(7, 65535), 13))
        );
        assert_eq!(object_header_at(b"7 0 object", 0), None);
        assert_eq!(object_header_at(b"7 0obj", 0), None);
        assert_eq!(object_header_at(b"7 65536 obj", 0), None);
        assert_eq!(object_header_at(b"99999999999 0 obj", 0), None);
        assert_eq!(object_header_at(b"7 0 R", 0), None);
        assert_eq!(
            object_header_at(b"7 0 obj", 0),
            Some((ObjectId::new(7, 0), 7))
        );
        let spaced = format!("7{}0 obj", " ".repeat(40));
        assert_eq!(object_header_at(spaced.as_bytes(), 0), None);
        assert_eq!(object_header_at(b"7 0 obj", 99), None);
        assert_eq!(xref_keyword_at(b"  xref\n", 0), Some(2));
        assert_eq!(xref_keyword_at(b"xrefs", 0), None);
    }

    #[test]
    fn eof_end_variants() {
        assert_eq!(eof_end_after(b"trailer<<>>%%EOF\r\nX", 0), Some(18));
        assert_eq!(eof_end_after(b"%%EOF\nX", 0), Some(6));
        assert_eq!(eof_end_after(b"%%EOF\rX", 0), Some(6));
        assert_eq!(eof_end_after(b"%%EOF", 0), Some(5));
        assert_eq!(eof_end_after(b"nothing", 0), None);
        assert_eq!(eof_end_after(b"x", 10), None);
    }

    #[test]
    fn startxref_markers() {
        let file = b"startxref 1 %%EOF\nstartxref\n%%EOF\n% startxref 7\nstartxref\r\n 22\r\n%%EOF";
        let mut markers = Markers::new(file, 16);
        let last = markers.last().unwrap();
        assert_eq!(last.value, Some(22));
        assert_eq!(&file[last.value_end - 2..last.value_end], b"22");
        let all: Vec<Option<u64>> = markers.all().iter().map(|m| m.value).collect();
        // The one inside a comment counts too (only the value after it matters).
        assert_eq!(all, [Some(1), None, Some(7), Some(22)]);
        assert!(markers.all().windows(2).all(|w| w[0].at < w[1].at));
        // Only the newest `max` are kept.
        let mut newest = Markers::new(file, 2);
        assert_eq!(newest.all().len(), 2);
        assert_eq!(newest.all()[1], last);
        // A value far after the keyword is not read.
        let far = format!("startxref{}5", " ".repeat(STARTXREF_VALUE_WINDOW + 1));
        assert_eq!(marker_at(far.as_bytes(), 0).value, None);
        assert_eq!(Markers::new(b"none", 4).last(), None);
    }

    #[test]
    fn revision_ends() {
        // The %%EOF after a startxref value, with its EOL.
        let file = b"xref trailer<<>>\nstartxref\n5\n%%EOF\r\nNEXT";
        let marker = marker_at(file, 17);
        assert_eq!(marker.value, Some(5));
        assert_eq!(eof_after_marker(file, &marker), file.len() as u64 - 4);
        // Without a %%EOF before the next startxref: the end of the value line.
        let file = b"startxref\n5\nstartxref\n9\n%%EOF\n";
        let marker = marker_at(file, 0);
        assert_eq!(eof_after_marker(file, &marker), 12);
        // The section's own startxref is found right after it, or later by value.
        let file = b"S1 startxref\n0\n%%EOF\nS2 startxref\n3\n%%EOF\n";
        let mut markers = Markers::new(file, 16);
        assert_eq!(
            revision_eof(file, &mut markers, 2, [3, 3, 3]),
            Some(file.len() as u64)
        );
        assert_eq!(revision_eof(file, &mut markers, 2, [0, 0, 0]), Some(21));
        assert_eq!(revision_eof(file, &mut markers, 2, [8, 8, 8]), None);
    }

    #[test]
    fn budgets_scale_with_the_file() {
        let limits = Limits::default();
        assert_eq!(object_cap(&limits, 10), 4096);
        assert_eq!(object_cap(&limits, 100_000), 100_000);
        assert_eq!(object_cap(&limits, 1 << 40), 10_000_000);
        assert_eq!(object_cap(&limits.with_max_objects(100), 100_000), 100);
        let small = XrefBudget::for_len(&limits, 10);
        assert_eq!((small.bytes, small.rows), (1 << 20, 1 << 20));
        let large = XrefBudget::for_len(&limits, 10 << 20);
        assert_eq!((large.bytes, large.rows), (40 << 20, 40 << 20));
        assert_eq!((large.max_bytes, large.max_rows), (40 << 20, 40 << 20));
        assert!(!large.is_exhausted());
        // Trusted files can raise every budget at once.
        let scaled = XrefBudget::for_len(&limits.with_budget_scale(4), 10 << 20);
        assert_eq!((scaled.bytes, scaled.rows), (160 << 20, 160 << 20));
        assert_eq!(object_cap(&limits.with_budget_scale(4), 100_000), 400_000);
        let mut merger = Merger::new(MergeMode::Merge, 2);
        for num in [9, 8, 7, 6, 5, 4, 3, 9] {
            merger.add(num, XrefEntry::InFile { pos: 0, r#gen: 0 });
        }
        merger.add(1, XrefEntry::Free { r#gen: 0 });
        merger.compact();
        // The lowest numbers are kept; the free entry and the repeated 9 take no room.
        let kept: Vec<u32> = merger.entries.iter().map(|e| e.0).collect();
        assert_eq!(kept, [3, 4]);
        assert!(merger.overflow);
        assert_eq!(merger.max_num, Some(9));
    }

    #[test]
    fn merger_records_free_entries_by_section() {
        // Newest section first: its free entries hide older entries and are recorded with its
        // position; a number already merged is not recorded again.
        let mut merger = Merger::new(MergeMode::Merge, 100);
        merger.begin_section(500);
        merger.add(3, XrefEntry::Free { r#gen: 1 });
        merger.add(4, XrefEntry::InFile { pos: 10, r#gen: 0 });
        merger.add(7, XrefEntry::NULL);
        merger.begin_section(200);
        merger.add(3, XrefEntry::InFile { pos: 20, r#gen: 0 });
        merger.add(0, XrefEntry::Free { r#gen: 65535 });
        merger.add(4, XrefEntry::Free { r#gen: 1 });
        assert_eq!(merger.freed, [(500, vec![3, 7]), (200, vec![0])]);
        let kept: Vec<u32> = merger.entries.iter().map(|e| e.0).collect();
        assert_eq!(kept, [4]);
        // Collecting one section's entries records nothing.
        let mut collect = Merger::new(MergeMode::Collect, 100);
        collect.add(3, XrefEntry::Free { r#gen: 1 });
        assert!(collect.freed.is_empty());
    }

    #[test]
    fn big_endian_fields() {
        assert_eq!(be_number(&[]), 0);
        assert_eq!(be_number(&[1, 2]), 0x0102);
        assert_eq!(be_number(&[0xff; 8]), u64::MAX);
    }
}

//! Reconstruction of damaged files (ARCHITECTURE §A.10 trap #3).
//!
//! When the cross-reference data is missing or unusable, the [`Store`] rebuilds it
//! from one linear scan of the whole file ([`scan`]), which records:
//!
//! - every `N G obj` header that starts a line (after optional white-space): the candidate
//!   object definitions. Like qpdf and poppler, which rebuild a file from the headers at the
//!   start of its lines, the scan ignores header-like text in the middle of a line, and so
//!   inside a `%` comment, which runs to the end of its line;
//! - the positions of every `endstream`, `endobj` and `trailer` keyword, which also serve as
//!   the parser's [`KeywordIndex`]: stream recovery then costs `O(log n)` per object instead of
//!   a search through the rest of the file,
//! - the objects whose dictionaries mention `/ObjStm`, `/Catalog` or `/XRef`, so object streams,
//!   the catalog and cross-reference stream trailers can be found without parsing every object,
//! - the position of every header-like text, line start or not, in file order: where the
//!   cross-reference data cannot say where an object ends, the next one does (the store bounds
//!   each object's parse by it).
//!
//! [`definitions`] turns the candidates into the object definitions, keyed by number *and*
//! generation (`5 0 obj` and `5 1 obj` are different objects, §7.3.10): it parses the
//! candidates in file order, and a candidate that lies inside an object that parsed
//! successfully (a header inside another object's string, dictionary or stream data) is text,
//! not a definition, while one inside what a failed parse read is taken unparsed, as qpdf
//! takes every header at the start of a line. Of the definitions of one object, the last one
//! wins, as incremental updates append to the file (one inside stream data only counts when no
//! other one defines that object).
//!
//! [`reconstruct_entries`] turns the definitions into cross-reference entries, including the
//! objects inside the object streams it finds. [`find_trailer`] picks the newest usable
//! trailer, and [`find_catalog`] finds the `/Type /Catalog` object when no trailer has a
//! `/Root`. [`update_after`] looks for an incremental update after the last revision with the
//! same line-start rule, without the full scan.
//!
//! The scan is built at most once per store, either for a reconstruction at open time or lazily
//! the first time an object's offset or a stream's `/Length` turns out to be wrong; the
//! definitions are derived from it at most once, when they are needed.
//!
//! # Cost
//!
//! Everything here is linear in the file size. The object streams a reconstruction reads are
//! decoded only for their member lists and not kept (the store decodes and caches a container
//! when one of its objects is resolved), and together they may decode at most
//! [`reconstruct_budget`] bytes: a few megabytes of compressed zeros cannot make opening a file
//! decode gigabytes. Trailer candidates are parsed only up to the next object header or
//! `trailer` keyword, so an unterminated string in one of them cannot make each parse run to the
//! end of the file. The parses that tell definitions from text inside other objects each start
//! after what the one before covered (a successful parse: its object) or read (a failed one,
//! whose headers count unparsed), so together they read the file about once, without a budget
//! (see [`definitions`]); a literal string that never closes stops them after a few kilobytes
//! ([`ParenIndex`]), and a hexadecimal string ends at its first invalid byte.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};

use crate::diag::{Diagnostic, DiagnosticKind, DiagnosticSink, Strictness};
use crate::lexer::{ParenIndex, is_regular, is_whitespace};
use crate::limits::{LimitKind, Limits};
use crate::object::{Dict, Object, ObjectId, keys};
use crate::parser::{KeywordIndex, ParseBudget, ParseCtx, parse_indirect_extent, parse_object};
use crate::store::{Location, Store};
use crate::xref::{XrefEntry, object_header_at};

/// How many `trailer`, cross-reference stream, catalog and object-stream candidates are tried,
/// newest first.
const MAX_CANDIDATES: usize = 64;

/// The decoded bytes a reconstruction of a file of `len` bytes may spend reading object streams
/// ([`LimitKind::ReconstructDecoded`]): `max(16 MiB, 16 × len)`, scaled by
/// `Limits::budget_scale`. Real object streams compress their objects a few times; a container
/// that needs more is skipped, with a diagnostic.
pub(crate) fn reconstruct_budget(limits: &Limits, len: usize) -> u64 {
    limits.budget(LimitKind::ReconstructDecoded, len as u64)
}

/// The longest run of white-space accepted between the parts of an `N G obj` header by the
/// backward matcher (keeps the scan linear).
const MAX_SPACE: usize = 32;

/// A definition of an object: where its header is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Found {
    /// The generation in the header.
    pub r#gen: u16,
    /// Absolute position of the header's first digit.
    pub pos: usize,
    /// Whether the header lies inside stream data (after `stream`, before `endstream` or
    /// `endobj`).
    pub in_stream: bool,
}

impl Found {
    /// Whether this definition, which comes later in the file, replaces `older`: a clean
    /// definition beats one inside stream data; otherwise the later one wins.
    fn replaces(&self, older: &Found) -> bool {
        !self.in_stream || older.in_stream
    }
}

/// An `N G obj` header at the start of a line (see [`scan`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Candidate {
    /// The number and generation in the header.
    pub id: ObjectId,
    /// Absolute position of the header's first digit.
    pub pos: usize,
    /// Whether the header lies inside stream data.
    pub in_stream: bool,
}

/// The result of one linear scan of the source.
#[derive(Debug, Default)]
pub(crate) struct ScanIndex {
    /// Positions of every `endstream` byte sequence, ascending.
    endstream: Vec<usize>,
    /// Positions of every `endobj` byte sequence, ascending.
    endobj: Vec<usize>,
    /// Positions of every `trailer` keyword, ascending.
    trailers: Vec<usize>,
    /// Positions of every header-like text (its first digit), ascending, line start or not,
    /// including headers inside stream data or strings and later definitions of the same
    /// object: what bounds an object's parse when the cross-reference data cannot.
    headers: Vec<usize>,
    /// The headers at the start of a line, ascending: the candidate definitions.
    candidates: Vec<Candidate>,
    /// Headers of objects whose dictionary mentions `/ObjStm`, in file order.
    pub objstm: Vec<(ObjectId, usize)>,
    /// Headers of objects that mention `/Catalog`, in file order.
    catalogs: Vec<(ObjectId, usize)>,
    /// Headers of objects that mention `/XRef`, in file order.
    xref_streams: Vec<(ObjectId, usize)>,
}

impl ScanIndex {
    /// The heap memory the index holds, in bytes (see [`Store::memory_estimate`]).
    ///
    /// [`Store::memory_estimate`]: crate::Store::memory_estimate
    pub fn heap_size(&self) -> u64 {
        fn vec<T>(items: &Vec<T>) -> u64 {
            (items.capacity() as u64).saturating_mul(std::mem::size_of::<T>() as u64)
        }
        [
            vec(&self.endstream),
            vec(&self.endobj),
            vec(&self.trailers),
            vec(&self.headers),
            vec(&self.candidates),
            vec(&self.objstm),
            vec(&self.catalogs),
            vec(&self.xref_streams),
        ]
        .into_iter()
        .fold(0, u64::saturating_add)
    }

    /// The first `endstream` at or after `from`.
    pub fn next_endstream(&self, from: usize) -> Option<usize> {
        next_at_or_after(&self.endstream, from)
    }

    /// The first `endobj` at or after `from`.
    pub fn next_endobj(&self, from: usize) -> Option<usize> {
        next_at_or_after(&self.endobj, from)
    }

    /// The first `trailer` keyword at or after `from`.
    pub fn next_trailer(&self, from: usize) -> Option<usize> {
        next_at_or_after(&self.trailers, from)
    }

    /// The first `trailer` keyword at or after `from` that starts a line (see [`at_line_start`]).
    pub fn next_line_trailer(&self, bytes: &[u8], from: usize) -> Option<usize> {
        let at = self.trailers.partition_point(|&p| p < from);
        self.trailers
            .get(at..)?
            .iter()
            .copied()
            .find(|&p| at_line_start(bytes, p))
    }

    /// The position of the first header-like text that starts after `pos`.
    pub fn next_header_after(&self, pos: usize) -> Option<usize> {
        let at = self.headers.partition_point(|&p| p <= pos);
        self.headers.get(at).copied()
    }
}

impl KeywordIndex for ScanIndex {
    fn next_endstream(&self, from: usize) -> Option<usize> {
        ScanIndex::next_endstream(self, from)
    }

    fn next_endobj(&self, from: usize) -> Option<usize> {
        ScanIndex::next_endobj(self, from)
    }
}

fn next_at_or_after(sorted: &[usize], from: usize) -> Option<usize> {
    sorted.get(sorted.partition_point(|&p| p < from)).copied()
}

/// Whether `pos` starts a line: between it and the previous end-of-line marker (or the start of
/// the file) there is nothing but white-space other than an EOL (space, tab, form feed, NUL).
/// Such a position is never inside a `%` comment, which runs to the end of its line (§7.2.4).
///
/// Linear over a scan: the white-space before one token is walked once.
pub(crate) fn at_line_start(bytes: &[u8], pos: usize) -> bool {
    let mut i = pos;
    while let Some(prev) = i.checked_sub(1) {
        match bytes.get(prev) {
            Some(b'\n' | b'\r') => return true,
            Some(b' ' | b'\t' | b'\x0c' | b'\0') => i = prev,
            Some(_) | None => return false,
        }
    }
    true
}

/// Scans `bytes` once. Every list grows at most linearly with the input.
pub(crate) fn scan(bytes: &[u8]) -> ScanIndex {
    let mut index = ScanIndex::default();
    // The last of `stream`, `endstream` and `endobj` seen was `stream`: we are in stream data.
    let mut in_stream = false;
    // The most recent candidate header, which encloses the names found after it.
    let mut current: Option<(ObjectId, usize)> = None;
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'e' if starts_with(bytes, i, b"endstream") => {
                index.endstream.push(i);
                in_stream = false;
                i += b"endstream".len();
                continue;
            }
            b'e' if starts_with(bytes, i, b"endobj") => {
                index.endobj.push(i);
                in_stream = false;
                i += b"endobj".len();
                continue;
            }
            b's' if keyword_at(bytes, i, b"stream") => {
                in_stream = true;
                i += b"stream".len();
                continue;
            }
            b't' if keyword_at(bytes, i, b"trailer") => {
                index.trailers.push(i);
                i += b"trailer".len();
                continue;
            }
            b'o' if keyword_at(bytes, i, b"obj") => {
                if let Some((id, pos)) = header_before(bytes, i) {
                    index.headers.push(pos);
                    if at_line_start(bytes, pos) {
                        index.candidates.push(Candidate { id, pos, in_stream });
                        current = Some((id, pos));
                    }
                }
                i += b"obj".len();
                continue;
            }
            b'/' => {
                for (name, list) in [
                    (&b"/ObjStm"[..], &mut index.objstm),
                    (b"/Catalog", &mut index.catalogs),
                    (b"/XRef", &mut index.xref_streams),
                ] {
                    if name_at(bytes, i, name)
                        && let Some(header) = current
                        && list.last() != Some(&header)
                    {
                        list.push(header);
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    index
}

/// The object definitions among the scan's candidates (see [`definitions`]).
#[derive(Debug, Default)]
pub(crate) struct Definitions {
    /// The definition of each object, by number and generation.
    by_id: HashMap<ObjectId, Found>,
    /// For each number, the definition that wins over all its generations (the newest).
    by_num: HashMap<u32, Found>,
    /// The position of every definition, ascending (superseded ones included).
    positions: Vec<usize>,
    /// The bytes the parses of [`definitions`] read together (for linearity tests).
    #[cfg(test)]
    read: u64,
}

impl Definitions {
    /// The heap memory the definitions hold, in bytes (see [`Store::memory_estimate`]): each
    /// map entry with its key, its value and a control byte.
    ///
    /// [`Store::memory_estimate`]: crate::Store::memory_estimate
    pub fn heap_size(&self) -> u64 {
        fn map<K, V>(map: &HashMap<K, V>) -> u64 {
            let entry = std::mem::size_of::<(K, V)>() + 1;
            (map.capacity() as u64).saturating_mul(entry as u64)
        }
        let positions =
            (self.positions.capacity() as u64).saturating_mul(std::mem::size_of::<usize>() as u64);
        map(&self.by_id)
            .saturating_add(map(&self.by_num))
            .saturating_add(positions)
    }

    fn add(&mut self, candidate: &Candidate) {
        let found = Found {
            r#gen: candidate.id.r#gen,
            pos: candidate.pos,
            in_stream: candidate.in_stream,
        };
        self.positions.push(candidate.pos);
        for best in [
            self.by_id.entry(candidate.id).or_insert(found),
            self.by_num.entry(candidate.id.num).or_insert(found),
        ] {
            if found.replaces(best) {
                *best = found;
            }
        }
    }

    /// The definition of object `id` (number and generation).
    pub fn get(&self, id: ObjectId) -> Option<Found> {
        self.by_id.get(&id).copied()
    }

    /// The definition of object `id`, or, when no definition has its generation, the newest
    /// definition of its number (whose generation the caller then reports).
    pub fn find(&self, id: ObjectId) -> Option<Found> {
        self.get(id).or_else(|| self.newest(id.num))
    }

    /// The newest definition of number `num`, whatever its generation.
    pub fn newest(&self, num: u32) -> Option<Found> {
        self.by_num.get(&num).copied()
    }

    /// Every object defined, with its definition, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (ObjectId, Found)> + '_ {
        self.by_id.iter().map(|(&id, &found)| (id, found))
    }

    /// The position of the first definition at or after `pos`.
    pub fn next_at_or_after(&self, pos: usize) -> Option<usize> {
        next_at_or_after(&self.positions, pos)
    }

    /// The bytes the parses of [`definitions`] read together (stream data, which they locate
    /// without reading it, aside): about the length of the file at most.
    #[cfg(test)]
    pub fn bytes_read(&self) -> u64 {
        self.read
    }

    /// The number of objects defined.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }
}

/// The memory one parse of [`definitions`] may build (an array of millions of numbers is not
/// worth more to find where it ends): a parse that needs more counts as failed.
const COVER_MEMORY: u64 = 64 << 20;

/// Notes, during a parse of [`definitions`], whether the parser had to guess where the object
/// ends: a container closed by an object-level keyword (`N G obj` inside an array or a
/// dictionary), a stream without `endstream`, or `stream` after a value that is not a
/// dictionary. Such a parse does not tell where the object ends, so it counts as failed.
struct ExtentWatch {
    guessed: Cell<bool>,
    /// Where the keyword that closed the open containers is, if one did.
    closed_at: Cell<Option<usize>>,
}

impl DiagnosticSink for ExtentWatch {
    fn report(&self, diagnostic: Diagnostic) {
        if matches!(
            diagnostic.kind,
            DiagnosticKind::UnclosedContainer
                | DiagnosticKind::MissingEndstream
                | DiagnosticKind::StreamWithoutDict
        ) {
            self.guessed.set(true);
        }
        if diagnostic.kind == DiagnosticKind::UnclosedContainer && self.closed_at.get().is_none() {
            let at = diagnostic.offset.and_then(|at| usize::try_from(at).ok());
            self.closed_at.set(at);
        }
    }
}

/// The longest `N G obj` header the scan matches (see [`header_before`]).
const MAX_HEADER: usize = 10 + MAX_SPACE + 5 + MAX_SPACE + b"obj".len();

/// Where the stretch of a parse from `pos` that guessed where its object ends (see
/// [`ExtentWatch`]) stops, when it read up to `to`: before the header `N G obj` whose `obj`
/// (at `closed`) closed the object's containers, so that the object that header starts is
/// parsed in turn (reading that header again: a few bytes); otherwise at `to`.
fn guessed_stop(
    bytes: &[u8],
    scan: &ScanIndex,
    pos: usize,
    to: usize,
    closed: Option<usize>,
) -> usize {
    closed
        .filter(|&at| keyword_at(bytes, at, b"obj"))
        .and_then(|at| {
            let i = scan.headers.partition_point(|&p| p < at).checked_sub(1)?;
            let header = *scan.headers.get(i)?;
            (header > pos && at - header <= MAX_HEADER).then_some(header)
        })
        .unwrap_or(to)
}

/// Tells the object definitions among the scan's candidates (headers at the start of a line)
/// from text that only looks like one, in one pass over the candidates in file order. A
/// candidate that the pass reaches is parsed with the real parser (lenient, quiet):
///
/// - when the parse succeeds, the object is a definition, and the candidates inside it (up to
///   its end: a header inside its string, dictionary or stream data) are text, skipped;
/// - when it fails, or succeeds only by guessing where the object ends (see [`ExtentWatch`]),
///   the object is a definition, and so is every candidate inside what the parse read (up to
///   where it stopped): those are taken unparsed, as qpdf takes every header at the start of a
///   line, since nothing tells whether the damaged object encloses them. (When a header
///   `N G obj` closed the object's containers, the stretch ends before it: that header starts
///   the next object, which is parsed in turn.)
///
/// The pass then goes on with the first candidate after that stretch. The stretches never
/// overlap, and a parse reads past its stretch at most one lookahead token and the white-space
/// and comments before it (after an integer value; after a number there, one more that starts
/// with `R`: see [`parse_indirect_extent`]), or the header that closed its containers. A token
/// is read ahead only by the parse whose value it follows: the next parse starts at the first
/// candidate after the stretch, not before that token, and reads again at most the number or
/// the header it starts with. So together the parses read the file about once: linear by
/// construction ([`Definitions::bytes_read`]). An indirect `/Length` is read from the last
/// candidate for that object, parsed only up to the next header after it: each such object
/// once, and those stretches never overlap either.
///
/// A literal string that never closes would make its parse read the rest of the file, and
/// take every header after it unparsed; it fails after a few kilobytes instead
/// ([`ParenIndex`]), which takes only the headers in those kilobytes.
///
/// A hexadecimal string ends, and its parse fails, at its first byte that is neither a
/// hexadecimal digit nor white-space (§7.3.4.3), where qpdf's token ends
/// ([`ParseCtx::with_hex_ending_at_invalid_byte`]); value reads stay lenient and skip such a
/// byte. Read leniently here, one stray byte would run the string on to the next `>` anywhere in
/// the file, and a parse that then succeeded would take every header before that `>` for text,
/// hiding a redefinition after a damaged object.
///
/// Numbers at or above `limits.max_objects` are no definitions (but their objects still cover
/// the text inside them).
pub(crate) fn definitions(bytes: &[u8], scan: &ScanIndex, limits: &Limits) -> Definitions {
    let mut defs = Definitions::default();
    let read = Cell::new(0u64);
    let account = |from: usize, to: usize| {
        read.set(read.get().saturating_add(to.saturating_sub(from) as u64));
    };
    let last: HashMap<ObjectId, usize> = scan.candidates.iter().map(|c| (c.id, c.pos)).collect();
    let lengths: RefCell<HashMap<ObjectId, Option<i64>>> = RefCell::new(HashMap::new());
    let strings = ParenIndex::new(bytes);
    let quiet = ParseCtx::new(*limits, Strictness::Lenient)
        .with_keyword_index(scan)
        .with_string_ends(&strings)
        .with_hex_ending_at_invalid_byte();
    let length_of = |r: ObjectId| -> Option<i64> {
        if let Some(&known) = lengths.borrow().get(&r) {
            return known;
        }
        let value = last.get(&r).and_then(|&pos| {
            // Within its own stretch, up to the next header (as the store bounds an object's
            // parse by its region), without the indexes, which describe the whole file.
            let own = bytes.get(..scan.next_header_after(pos).unwrap_or(bytes.len()))?;
            let budget = ParseBudget::new(COVER_MEMORY, LimitKind::ObjStmParsed, COVER_MEMORY);
            let ctx = ParseCtx::new(*limits, Strictness::Lenient).with_budget(&budget);
            let (result, to) = parse_indirect_extent(own, pos, &ctx, &|_| None);
            account(pos, to);
            result.ok()?.object.as_int()
        });
        lengths.borrow_mut().insert(r, value);
        value
    };
    // The stretch the last parse covered: up to `end`, its candidates are text (`text`: the
    // parse succeeded) or taken unparsed (it failed).
    let (mut end, mut text) = (0usize, false);
    for candidate in &scan.candidates {
        if candidate.pos < end {
            if text {
                continue;
            }
        } else {
            let watch = ExtentWatch {
                guessed: Cell::new(false),
                closed_at: Cell::new(None),
            };
            let budget = ParseBudget::new(COVER_MEMORY, LimitKind::ObjStmParsed, COVER_MEMORY);
            let ctx = quiet.with_diagnostics(&watch).with_budget(&budget);
            let (result, to) = parse_indirect_extent(bytes, candidate.pos, &ctx, &length_of);
            account(candidate.pos, to);
            (end, text) = match result {
                Ok(parsed) if !watch.guessed.get() => (parsed.end, true),
                Ok(_) => {
                    let closed = watch.closed_at.get();
                    (guessed_stop(bytes, scan, candidate.pos, to, closed), false)
                }
                Err(_) => (to, false),
            };
        }
        if candidate.id.num < limits.max_objects {
            defs.add(candidate);
        }
    }
    #[cfg(test)]
    {
        defs.read = read.get();
    }
    defs
}

/// What [`update_after`] found after the end of the last revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Update {
    /// The absolute position of the first object header, `xref` or `trailer` keyword.
    pub first: usize,
    /// The absolute position of the first object header (`N G obj`), if any.
    pub header: Option<usize>,
}

/// Looks for the parts of an incremental update in `bytes[from..]` (§7.5.6): object headers
/// (`N G obj`), and `xref` or `trailer` keywords, each at the start of a line (see
/// [`at_line_start`]), which is where qpdf and poppler look for them when they rebuild a file.
/// Anything else there (white-space, comments, a repeated `%%EOF`, binary junk, header-like
/// text in a comment or in the middle of a line) is not an update. Linear in the bytes after
/// `from`, without building the scan of the whole file.
pub(crate) fn update_after(bytes: &[u8], from: usize) -> Option<Update> {
    let mut first: Option<usize> = None;
    let mut i = from;
    while let Some(&b) = bytes.get(i) {
        let found = match b {
            b'o' if keyword_at(bytes, i, b"obj") => header_before(bytes, i)
                .map(|(_, pos)| pos)
                .filter(|&pos| pos >= from && at_line_start(bytes, pos)),
            b't' if keyword_at(bytes, i, b"trailer") && at_line_start(bytes, i) => Some(i),
            b'x' if keyword_at(bytes, i, b"xref") && at_line_start(bytes, i) => Some(i),
            _ => None,
        };
        if let Some(pos) = found {
            let earliest = first.map_or(pos, |f| f.min(pos));
            if b == b'o' {
                // The first header settles both answers: every keyword found so far is before it.
                return Some(Update {
                    first: earliest,
                    header: Some(pos),
                });
            }
            first = Some(earliest);
        }
        i += 1;
    }
    Some(Update {
        first: first?,
        header: None,
    })
}

fn starts_with(bytes: &[u8], pos: usize, needle: &[u8]) -> bool {
    bytes
        .get(pos..)
        .is_some_and(|rest| rest.starts_with(needle))
}

/// `keyword` at `pos`, delimited on both sides (not part of a longer run of regular characters).
fn keyword_at(bytes: &[u8], pos: usize, keyword: &[u8]) -> bool {
    starts_with(bytes, pos, keyword)
        && (pos == 0 || bytes.get(pos - 1).is_some_and(|&b| !is_regular(b)))
        && !bytes
            .get(pos + keyword.len())
            .is_some_and(|&b| is_regular(b))
}

/// The name `name` (with its `/`) at `pos`, not followed by more regular characters.
fn name_at(bytes: &[u8], pos: usize, name: &[u8]) -> bool {
    starts_with(bytes, pos, name) && !bytes.get(pos + name.len()).is_some_and(|&b| is_regular(b))
}

/// Matches `N G` backwards from the `obj` keyword at `obj_pos`, in bounded time.
fn header_before(bytes: &[u8], obj_pos: usize) -> Option<(ObjectId, usize)> {
    let gen_end = skip_space_back(bytes, obj_pos)?;
    let (r#gen, gen_start) = digits_back(bytes, gen_end, 5)?;
    let num_end = skip_space_back(bytes, gen_start)?;
    let (num, num_start) = digits_back(bytes, num_end, 10)?;
    if num_start > 0 && bytes.get(num_start - 1).is_some_and(|&b| is_regular(b)) {
        return None;
    }
    let num = u32::try_from(num).ok()?;
    let r#gen = u16::try_from(r#gen).ok()?;
    Some((ObjectId::new(num, r#gen), num_start))
}

/// Moves back over 1 to [`MAX_SPACE`] white-space bytes ending just before `end`.
fn skip_space_back(bytes: &[u8], end: usize) -> Option<usize> {
    let mut i = end;
    while i > 0 && end - i < MAX_SPACE && bytes.get(i - 1).is_some_and(|&b| is_whitespace(b)) {
        i -= 1;
    }
    (i < end).then_some(i)
}

/// Reads 1 to `max` digits ending just before `end`; returns the value and where they start.
fn digits_back(bytes: &[u8], end: usize, max: usize) -> Option<(u64, usize)> {
    let mut start = end;
    while start > 0 && end - start <= max && bytes.get(start - 1).is_some_and(u8::is_ascii_digit) {
        start -= 1;
    }
    if start == end || end - start > max {
        return None;
    }
    let mut value = 0u64;
    for &d in bytes.get(start..end)? {
        value = value * 10 + u64::from(d - b'0');
    }
    Some((value, start))
}

/// The cross-reference entries rebuilt from the definitions (see [`reconstruct_entries`]).
#[derive(Debug, Default)]
pub(crate) struct Rebuilt {
    /// One entry per number: its newest definition.
    pub entries: BTreeMap<u32, XrefEntry>,
    /// The other generations defined for numbers in `entries`, sorted by number and
    /// generation: distinct objects (§7.3.10), which only a reference with their generation
    /// resolves to.
    pub others: Vec<(u32, XrefEntry)>,
}

/// Rebuilds cross-reference entries from the definitions (see [`definitions`]): one in-file
/// entry per object (number and generation), then the members of every object stream found,
/// where an object stream later in the file overrides earlier definitions of generation 0 (and
/// earlier object streams). For each number, the newest definition is the entry the merged
/// view shows; the other generations are kept as distinct objects, as qpdf keeps them.
///
/// The store's slots are replaced on the way (object streams are decoded through the store, for
/// their member lists only: see [`Store::reconstruction_objstm`]).
pub(crate) fn reconstruct_entries(store: &mut Store) -> Rebuilt {
    let max_objects = store.limits().max_objects;
    // Every object, with the position that makes it newer or older than others.
    let mut defs: BTreeMap<(u32, u16), (XrefEntry, usize)> = BTreeMap::new();
    // For each number, the generation of its newest definition and where it is.
    let mut newest: HashMap<u32, (u16, usize)> = HashMap::new();
    let containers = {
        let definitions = store.definitions();
        for (id, found) in definitions.iter() {
            if id.num == 0 {
                continue;
            }
            let entry = XrefEntry::InFile {
                pos: found.pos as u64,
                r#gen: found.r#gen,
            };
            defs.insert((id.num, id.r#gen), (entry, found.pos));
            if let Some(best) = definitions.newest(id.num) {
                newest.insert(id.num, (best.r#gen, best.pos));
            }
        }
        store.scan_index().objstm.clone()
    };
    let split = |defs: &BTreeMap<(u32, u16), (XrefEntry, usize)>,
                 newest: &HashMap<u32, (u16, usize)>| {
        let mut rebuilt = Rebuilt::default();
        for (&(num, r#gen), &(entry, _)) in defs {
            if newest.get(&num).is_some_and(|&(g, _)| g == r#gen) {
                rebuilt.entries.insert(num, entry);
            } else {
                rebuilt.others.push((num, entry));
            }
        }
        rebuilt
    };
    let first = split(&defs, &newest);
    let installed: Vec<(u32, XrefEntry)> = first.entries.into_iter().collect();
    store.install(&installed, &first.others);
    for (id, pos) in containers {
        // Only the definition that won is a container: object streams are named by number.
        if store.location(id.num) != Some(Location::InFile { pos: pos as u64 }) {
            continue;
        }
        let Some(stm) = store.reconstruction_objstm(id.num) else {
            continue;
        };
        for (index, member) in stm.members() {
            if member.num >= max_objects || member.num == id.num {
                continue;
            }
            // A newer uncompressed definition of the number wins.
            if newest.get(&member.num).is_some_and(|&(_, at)| at > pos) {
                continue;
            }
            // A compressed object has generation 0 (§7.5.7).
            let entry = XrefEntry::InObjStm {
                stream: id.num,
                index,
            };
            defs.insert((member.num, 0), (entry, pos));
            newest.insert(member.num, (0, pos));
        }
    }
    split(&defs, &newest)
}

/// The newest usable trailer found by the scan: the last `trailer` dictionary or
/// cross-reference stream dictionary that has a `/Root`. If a newer candidate without `/Root`
/// has an `/Encrypt`, that entry is kept (the document is encrypted either way). Like object
/// headers, a `trailer` keyword counts only at the start of a line (not in a comment or in the
/// middle of a line), where qpdf and poppler look for it.
///
/// Each candidate is parsed only up to the next object header or `trailer` keyword after it, so
/// the parses together read each byte at most twice.
pub(crate) fn find_trailer(store: &Store) -> Option<Dict> {
    enum Candidate {
        Keyword(usize),
        Stream(usize),
    }
    let scan = store.scan_index();
    let bytes = store.bytes();
    let mut candidates: Vec<(usize, Candidate)> = scan
        .trailers
        .iter()
        .rev()
        .filter(|&&p| at_line_start(bytes, p))
        .take(MAX_CANDIDATES)
        .map(|&p| (p, Candidate::Keyword(p)))
        .chain(
            scan.xref_streams
                .iter()
                .rev()
                .take(MAX_CANDIDATES)
                .map(|&(_, p)| (p, Candidate::Stream(p))),
        )
        .collect();
    candidates.sort_by_key(|c| std::cmp::Reverse(c.0));
    let ctx = store.parse_ctx(true);
    // The bytes a candidate at `p` may read: up to the next header or `trailer` keyword.
    let region = |p: usize| {
        let end = [scan.next_header_after(p), scan.next_trailer(p + 1)]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(bytes.len());
        bytes.get(..end).unwrap_or(bytes)
    };
    let mut chosen: Option<Dict> = None;
    let mut encrypt: Option<Object> = None;
    for (_, candidate) in candidates {
        let dict = match candidate {
            Candidate::Keyword(p) => match parse_object(region(p), p + b"trailer".len(), &ctx) {
                Ok((Object::Dict(dict), _)) => dict,
                _ => continue,
            },
            // The stream dictionary is the trailer (§7.5.8.2); its data is not needed.
            Candidate::Stream(p) => {
                let Some((_, after)) = object_header_at(bytes, p) else {
                    continue;
                };
                match parse_object(region(p), after, &ctx) {
                    Ok((Object::Dict(dict), _)) if dict.is_type(keys::XREF) => dict,
                    _ => continue,
                }
            }
        };
        if encrypt.is_none()
            && let Some(value) = dict.get(keys::ENCRYPT).filter(|v| !v.is_null())
        {
            encrypt = Some(value.clone());
        }
        if dict.get_ref(keys::ROOT).is_some() {
            chosen = Some(dict);
            break;
        }
    }
    let mut chosen = chosen?;
    if chosen.get(keys::ENCRYPT).is_none_or(Object::is_null)
        && let Some(value) = encrypt
    {
        chosen.insert(keys::ENCRYPT, value);
    }
    Some(chosen)
}

/// Finds the document catalog (`/Type /Catalog`), newest first: first among uncompressed
/// objects, then inside object streams (read for their member lists only, like a
/// reconstruction does; the store decodes and caches the one that holds the catalog).
pub(crate) fn find_catalog(store: &Store) -> Option<ObjectId> {
    let scan = store.scan_index();
    let is_catalog = |id: ObjectId| {
        store
            .resolve(id)
            .is_ok_and(|obj| obj.as_dict().is_some_and(|d| d.is_type(keys::CATALOG)))
    };
    for &(id, pos) in scan.catalogs.iter().rev().take(MAX_CANDIDATES) {
        if store.location_of(id) == Some(Location::InFile { pos: pos as u64 }) && is_catalog(id) {
            return Some(id);
        }
    }
    for &(id, pos) in scan.objstm.iter().rev().take(MAX_CANDIDATES) {
        if store.location(id.num) != Some(Location::InFile { pos: pos as u64 }) {
            continue;
        }
        let Some(stm) = store.reconstruction_objstm(id.num) else {
            continue;
        };
        for (index, member) in stm.members() {
            let here = Location::InObjStm {
                stream: id.num,
                index,
            };
            if stm.member_contains(member, b"/Catalog")
                && store.location(member.num) == Some(here)
                && is_catalog(ObjectId::new(member.num, 0))
            {
                return Some(ObjectId::new(member.num, 0));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The definitions of `file` with the default limits.
    fn defs(file: &[u8]) -> Definitions {
        definitions(file, &scan(file), &Limits::default())
    }

    fn id(num: u32, r#gen: u16) -> ObjectId {
        ObjectId::new(num, r#gen)
    }

    #[test]
    fn scan_finds_headers_and_keywords() {
        let file = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n\
                     2 0 obj<</Length 9>>stream\n3 0 obj x\nendstream\nendobj\n\
                     12 3 obj [/XRef] endobj trailer << /Root 1 0 R >>\n\
                     4 0 obj << /Type /ObjStm >> stream\nxx\nendstream endobj";
        let index = scan(file);
        // Every header at a line start is a candidate; `3 0 obj` inside stream data is flagged.
        let candidates: Vec<(ObjectId, bool)> = index
            .candidates
            .iter()
            .map(|c| (c.id, c.in_stream))
            .collect();
        assert_eq!(
            candidates,
            [
                (id(1, 0), false),
                (id(2, 0), false),
                (id(3, 0), true),
                (id(12, 3), false),
                (id(4, 0), false)
            ]
        );
        assert_eq!(index.catalogs, [(id(1, 0), 9)]);
        assert_eq!(index.xref_streams.len(), 1);
        assert_eq!(index.objstm.len(), 1);
        assert_eq!(index.trailers.len(), 1);
        assert_eq!(index.headers.len(), 5);
        assert!(index.headers.is_sorted());
        assert_eq!(index.next_header_after(0), Some(9));
        assert_eq!(index.next_header_after(9), Some(find(file, b"2 0 obj")));
        assert_eq!(index.next_header_after(file.len()), None);
        let first_endstream = index.next_endstream(0).unwrap();
        assert!(file[first_endstream..].starts_with(b"endstream"));
        assert_eq!(index.next_endstream(first_endstream), Some(first_endstream));
        assert!(index.next_endstream(file.len()).is_none());
        let endobj = index.next_endobj(0).unwrap();
        assert!(file[endobj..].starts_with(b"endobj"));
        assert_eq!(
            KeywordIndex::next_endobj(&index, endobj + 1),
            index.next_endobj(endobj + 1)
        );
        assert_eq!(
            KeywordIndex::next_endstream(&index, 0),
            Some(first_endstream)
        );
        // `3 0 obj` is inside the data of stream 2, which parses: no definition. The others
        // are, with their generations.
        let defs = defs(file);
        assert_eq!(defs.get(id(1, 0)).unwrap().pos, 9);
        assert_eq!(defs.get(id(12, 3)).unwrap().r#gen, 3);
        assert!(defs.get(id(12, 0)).is_none());
        assert_eq!(defs.find(id(12, 0)), defs.get(id(12, 3)));
        assert!(defs.get(id(3, 0)).is_none());
        assert_eq!(defs.len(), 4);
        assert!(defs.bytes_read() <= file.len() as u64);
        // Object numbers at or above the limit are no definitions.
        let few = definitions(file, &index, &Limits::default().with_max_objects(5));
        assert!(few.get(id(12, 3)).is_none());
        assert_eq!(few.len(), 3);
    }

    fn find(bytes: &[u8], needle: &[u8]) -> usize {
        bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap()
    }

    #[test]
    fn clean_definition_beats_one_in_stream_data() {
        // Stream 6 starts in the middle of a line, so it is no definition and covers nothing:
        // the header at a line start inside its data is a candidate, flagged as in stream data,
        // and loses to the clean definition.
        let file = b"5 0 obj (a) endobj 6 0 obj<<>>stream\n5 0 obj (fake)\nendstream endobj";
        assert_eq!(defs(file).get(id(5, 0)).unwrap().pos, 0);
        // Later clean definitions win.
        let file = b"5 0 obj (a) endobj\n5 0 obj (b) endobj";
        assert_eq!(defs(file).get(id(5, 0)).unwrap().pos, 19);
    }

    #[test]
    fn header_text_that_is_no_definition() {
        let good = b"5 0 obj\n(good)\nendobj\n";
        let cases: [(&str, &[u8]); 5] = [
            // In a comment, and in the middle of a line (as qpdf and poppler read lines).
            ("comment", b"% see 5 0 obj (evil) endobj\n"),
            ("mid-line", b"7 0 obj (seven) endobj 5 0 obj (evil) endobj\n"),
            // At a line start, but inside a string, a dictionary or stream data of an object
            // that parses.
            ("string", b"6 0 obj\n(x\n5 0 obj\n(evil)\nendobj\n)\nendobj\n"),
            (
                "array",
                b"6 0 obj\n[ (x) <<\n/A (\n5 0 obj\n(evil)\nendobj\n) >> ]\nendobj\n",
            ),
            (
                "stream",
                b"6 0 obj\n<< /Length 25 >>\nstream\nq\n5 0 obj\n(evil)\nendobj\nQ\nendstream\nendobj\n",
            ),
        ];
        for (name, decoy) in cases {
            let file = [&good[..], decoy].concat();
            let defs = defs(&file);
            assert_eq!(defs.get(id(5, 0)).map(|f| f.pos), Some(0), "{name}");
            // The object at the start of the line is a definition, and nothing else is.
            let line = match name {
                "comment" => None,
                "mid-line" => Some(7),
                _ => Some(6),
            };
            if let Some(num) = line {
                assert_eq!(
                    defs.get(id(num, 0)).map(|f| f.pos),
                    Some(good.len()),
                    "{name}"
                );
            }
            assert_eq!(defs.len(), 1 + usize::from(line.is_some()), "{name}");
        }
        // The same text where nothing encloses it is a definition, also after white-space, on
        // the line after a comment, or spread over lines.
        for (decoy, at) in [
            (&b"5 0 obj (evil) endobj\n"[..], 0),
            (b"  \t5 0 obj (evil) endobj\n", 3),
            (b"% a comment\n5 0 obj (evil) endobj\n", 12),
            (b"5\n0\nobj (evil) endobj\n", 0),
        ] {
            let file = [&good[..], decoy].concat();
            assert_eq!(
                defs(&file).get(id(5, 0)).map(|f| f.pos),
                Some(good.len() + at),
                "{}",
                decoy.escape_ascii()
            );
        }
        // An enclosing object whose end the parser has to guess covers nothing past what it
        // read: a dictionary closed by the next header (which starts the next object, parsed in
        // turn), a stream without `endstream` (whose data it did not read; the definition inside
        // stream data still loses to a clean one).
        for (broken, wins) in [
            (&b"6 0 obj\n<< /A 1\n5 0 obj\n(evil)\nendobj\n"[..], true),
            (
                b"6 0 obj\n<< /Length 999 >>\nstream\nq\n5 0 obj\n(evil)\nendobj\n",
                false,
            ),
        ] {
            let file = [&good[..], broken].concat();
            let at = find(&file[1..], b"5 0 obj") + 1;
            let defs = defs(&file);
            assert_eq!(defs.next_at_or_after(good.len() + 1), Some(at));
            let winner = if wins { at } else { 0 };
            assert_eq!(defs.get(id(5, 0)).map(|f| f.pos), Some(winner));
        }
        // An object that fails to parse (here, a string that never closes) covers nothing: the
        // headers in what it read are definitions, taken unparsed, as qpdf takes them.
        let file = [&good[..], b"6 0 obj\n(x\n5 0 obj\n(evil)\nendobj\n"].concat();
        assert_eq!(
            defs(&file).get(id(5, 0)).map(|f| f.pos),
            Some(find(&file[1..], b"5 0 obj") + 1)
        );
    }

    #[test]
    fn indirect_lengths_are_read_for_the_extent() {
        // Stream 6's /Length is object 7, defined after it: the data, which holds a header at a
        // line start and no `endstream` of its own before the real one... is delimited by it.
        let data = b"q\n5 0 obj\n(evil)\nendobj\nQ";
        let mut file = b"5 0 obj\n(good)\nendobj\n6 0 obj\n<< /Length 7 0 R >>\nstream\n".to_vec();
        file.extend_from_slice(data);
        file.extend_from_slice(b"\nendstream\nendobj\n");
        file.extend_from_slice(format!("7 0 obj\n{}\nendobj\n", data.len()).as_bytes());
        let defs = defs(&file);
        assert_eq!(defs.get(id(5, 0)).map(|f| f.pos), Some(0));
        assert!(defs.get(id(7, 0)).is_some());
    }

    #[test]
    fn generations_are_distinct_objects() {
        let file =
            b"5 0 obj\n(gen0)\nendobj\n5 1 obj\n(gen1)\nendobj\n5 0 obj\n(gen0 again)\nendobj\n";
        let defs = defs(file);
        assert_eq!(
            defs.get(id(5, 0)).unwrap().pos,
            find(file, b"5 0 obj\n(gen0 again)")
        );
        assert_eq!(defs.get(id(5, 1)).unwrap().pos, find(file, b"5 1 obj"));
        assert_eq!(defs.newest(5), defs.get(id(5, 0)));
        assert_eq!(defs.find(id(5, 2)), defs.newest(5));
        assert_eq!(defs.len(), 2);
    }

    /// `count` objects from number `first` on, each `N 0 obj` and `body` on lines of their own,
    /// then `tail`.
    fn run(first: u32, count: u32, body: &str, tail: &str) -> Vec<u8> {
        let mut run: Vec<u8> = (first..first + count)
            .flat_map(|n| format!("{n} 0 obj\n{body}\n").into_bytes())
            .collect();
        run.extend_from_slice(tail.as_bytes());
        run
    }

    /// Runs of `count` damaged objects (name, body, tail, definitions found) whose parses each
    /// read on to the same place, so that checking every header on its own would read the run
    /// once per object (quadratic), as the coverage budgets of an earlier design did
    /// (M1 QA round 5):
    pub(crate) fn damaged_runs(count: u32) -> Vec<(&'static str, String, String, usize)> {
        let n = count as usize;
        vec![
            // hexadecimal strings that, read leniently, all run to the same `>`, where every
            // parse fails at the lone `>` after it (the coverage parses end each one at its
            // first invalid byte instead), with no `endobj`, one at the end, or one for each
            // object;
            ("hex", "[<".into(), ">>\n".into(), n),
            ("hex, one endobj", "[<".into(), ">>\nendobj\n".into(), n),
            ("hex, endobj each", "[<\nendobj".into(), ">>\n".into(), n),
            // literal strings that never close (each object opens one more), in containers;
            (
                "unclosed strings",
                "<< /A << /B [ (".into(),
                String::new(),
                n,
            ),
            ("unbalanced", "((((".into(), ")))".into(), n),
            // arrays nested too deep, each failing at the limit;
            ("deep", "[".repeat(300), String::new(), n),
            // an integer whose reference lookahead could read the hexadecimal string after it;
            ("integer, hex", "1 <".into(), ">\n".into(), n),
            // nested strings that all close at the end: the first object holds all the others;
            ("closed at the end", "(".into(), ")".repeat(n), 1),
            // the same in arrays, closed by the header of one more object: a guessed end.
            (
                "interrupted",
                "[ (".into(),
                format!("{}\n9999999 0 obj\n(last)\nendobj\n", ")".repeat(n)),
                n + 1,
            ),
        ]
    }

    #[test]
    fn the_coverage_parses_read_the_file_about_once() {
        // Each parse skips what the one before covered (a successful one) or read (a failed one,
        // whose headers count unparsed), so together they read the file about once, whatever
        // the damage: no budget is needed. Twice the objects cost about twice as much.
        let [small, large] = [damaged_runs(2_000), damaged_runs(4_000)];
        for ((name, body, tail, found), (_, _, large_tail, large_found)) in
            small.into_iter().zip(large)
        {
            let mut read = Vec::new();
            for (count, tail, found) in [(2_000, tail, found), (4_000, large_tail, large_found)] {
                let file = run(1, count, &body, &tail);
                let defs = defs(&file);
                assert_eq!(defs.len(), found, "{name}");
                let bytes = defs.bytes_read();
                assert!(
                    bytes <= 2 * file.len() as u64,
                    "{name}: {bytes} / {}",
                    file.len()
                );
                read.push(bytes);
            }
            assert!(read[1] <= 3 * read[0], "{name}: {read:?}");
        }
        // A literal string that never closes stops after a few kilobytes: ten thousand of them,
        // one per line, are read about once (each parse takes the few kilobytes it read).
        let file = run(1, 10_000, "(", "");
        let defs = defs(&file);
        assert_eq!(defs.len(), 10_000);
        assert!(defs.bytes_read() <= 2 * file.len() as u64);
    }

    #[test]
    fn damaged_objects_take_only_what_they_read() {
        // A damaged prefix, `5 0 obj (good)`, then object 6 whose dictionary string holds the
        // header `5 0 obj (evil)`. A failed parse takes the headers in what it read, unparsed,
        // as qpdf takes every header at the start of a line; the pass then goes on, so object 6,
        // when it lies past that, parses and covers its text.
        let good = "5 0 obj\n(good)\nendobj\n";
        let six = "6 0 obj\n<< /S [ (\n5 0 obj\n(evil)\nendobj\n) ] >>\nendobj\n";
        let gap = format!("%{}\n", "p".repeat(2 * crate::lexer::LONG_STRING));
        let deep = "[".repeat(300);
        let cases: [(&str, String, bool); 7] = [
            // Arrays nested too deep fail at the limit, before the next object.
            (
                "deep",
                format!("60 0 obj\n{deep}\nendobj\n61 0 obj\n{deep}\nendobj\n"),
                false,
            ),
            // A string that never closes takes the headers in the few kilobytes it read...
            (
                "string",
                "60 0 obj\n(unterminated \\( string\nendobj\n".into(),
                true,
            ),
            // ... but not those after them.
            (
                "string, far",
                format!("60 0 obj\n(never closed\n{gap}"),
                false,
            ),
            // A hexadecimal string ends at its first invalid byte (the `n` of `endobj`, the
            // first `z`), as qpdf's token does, not at the next `>`, which may be anywhere in the
            // file (here the last line): the objects after it are parsed in turn.
            ("hex", "60 0 obj\n[<\nendobj\n".into(), false),
            (
                "hex, invalid digit",
                "60 0 obj\n<41 zz\nendobj\n".into(),
                false,
            ),
            // A dictionary closed by the next header: that object is parsed in turn.
            ("interrupted", "60 0 obj\n<< /A 1\n".into(), false),
            // An integer without `endobj` before the next header (read ahead as `N G R`).
            ("integer", "60 0 obj\n42\n".into(), false),
        ];
        for (name, prefix, taken) in cases {
            let file = format!("{prefix}{good}{six}%>\n").into_bytes();
            let defs = defs(&file);
            let at = prefix.len();
            let evil = rfind(&file, b"5 0 obj");
            let five = if taken { evil } else { at };
            assert_eq!(defs.get(id(5, 0)).map(|f| f.pos), Some(five), "{name}");
            assert_eq!(
                defs.get(id(6, 0)).map(|f| f.pos),
                Some(at + good.len()),
                "{name}"
            );
            assert_eq!(defs.get(id(60, 0)).map(|f| f.pos), Some(0), "{name}");
            assert_eq!(
                defs.next_at_or_after(at + good.len() + 1),
                taken.then_some(evil)
            );
        }
    }

    #[test]
    fn a_hex_string_ends_at_its_first_invalid_byte() {
        // Expert probe P13: `7 0 obj <41 zz`, then 6 and an orphan `5 0 obj` at the top level,
        // and a `>` on the last line. Read leniently, the hexadecimal string would skip the
        // `z`s and run to that `>`, and its parse would succeed and cover 6 and the orphan,
        // which would be text. It ends at the first `z` instead, as qpdf's token does: the
        // parse fails there, and 6 and the orphan are parsed in turn, both definitions.
        let file = b"5 0 obj\n(good)\nendobj\n7 0 obj\n<41 zz\nendobj\n6 0 obj\n(six)\nendobj\n\
                     5 0 obj\n(orphan)\nendobj\n%>\n";
        let defs = defs(file);
        assert_eq!(
            defs.get(id(7, 0)).map(|f| f.pos),
            Some(find(file, b"7 0 obj"))
        );
        assert_eq!(
            defs.get(id(6, 0)).map(|f| f.pos),
            Some(find(file, b"6 0 obj"))
        );
        assert_eq!(
            defs.get(id(5, 0)).map(|f| f.pos),
            Some(rfind(file, b"5 0 obj"))
        );
        assert_eq!(defs.len(), 3);
    }

    fn rfind(bytes: &[u8], needle: &[u8]) -> usize {
        bytes
            .windows(needle.len())
            .rposition(|w| w == needle)
            .unwrap()
    }

    #[test]
    fn line_starts() {
        let text = b"a\n b\r\t\x00c d\x0c\ne";
        assert!(at_line_start(text, 0));
        assert!(at_line_start(text, 3));
        assert!(at_line_start(text, 7));
        assert!(!at_line_start(text, 9));
        assert!(at_line_start(text, 12));
        assert!(at_line_start(b"", 0));
        // Past the end: the white-space walk starts from the end.
        assert!(!at_line_start(b"ab", 5));
    }

    #[test]
    fn header_matcher_boundaries() {
        assert_eq!(header_before(b"12 0 obj", 5), Some((id(12, 0), 0)));
        assert_eq!(header_before(b"x12 0 obj", 6), None);
        assert_eq!(header_before(b">>12 0 obj", 7), Some((id(12, 0), 2)));
        assert_eq!(header_before(b"12 0obj", 4), None);
        assert_eq!(header_before(b"12 123456 obj", 10), None);
        assert_eq!(header_before(b"12345678901 0 obj", 14), None);
        assert_eq!(header_before(b"0 obj", 2), None);
        let spaced = format!("1{}0 obj", " ".repeat(40));
        assert_eq!(header_before(spaced.as_bytes(), spaced.len() - 3), None);
        // `endobj` and `xobj` are not headers.
        assert!(scan(b"1 0 endobj 2 0 xobj").candidates.is_empty());
    }

    #[test]
    fn updates_after_a_position() {
        let file = b"%%EOF\n% junk startxref 12 %%EOF\n\x00\xFF 7 0 objx endobjs";
        // Junk, `startxref`, `%%EOF`, words that only contain the keywords: no update.
        assert_eq!(update_after(file, 0), None);
        assert_eq!(update_after(file, file.len()), None);
        assert_eq!(update_after(file, file.len() + 1), None);
        let file = b"%%EOF\nxref\n0 1\ntrailer << >>\n5 0 obj (x) endobj\n6 0 obj";
        assert_eq!(
            update_after(file, 0),
            Some(Update {
                first: 6,
                header: Some(29),
            })
        );
        // From inside the table: the trailer, then the header.
        assert_eq!(
            update_after(file, 7),
            Some(Update {
                first: 15,
                header: Some(29),
            })
        );
        // A trailer alone, and a header whose number starts right at the position.
        let file = b"junk\ntrailer\n<< /Root 1 0 R >>";
        assert_eq!(
            update_after(file, 0),
            Some(Update {
                first: 5,
                header: None,
            })
        );
        // Only headers that start at or after the position count, in the file's own context.
        assert_eq!(update_after(b"x12 0 obj", 1), None);
        assert_eq!(update_after(b"12 0 obj", 1), None);
        assert_eq!(
            update_after(b"%%EOF\n12 0 obj", 6),
            Some(Update {
                first: 6,
                header: Some(6),
            })
        );
        // Header-like text in a comment or in the middle of a line, and keywords in the middle
        // of a line, are no update (QA: `%junk 1 0 obj` and NULs after a linearized file).
        for junk in [
            &b"\n%junk 1 0 obj\n\x00\x00\x00"[..],
            b"\njunk 1 0 obj (junk) endobj\n",
            b"\n% trailer << /Root 9 0 R >>\n",
            b"\n%PDF-1.4\n%garbage 3 0 obj\n",
            b"\njunk trailer << >> xref\n",
        ] {
            assert_eq!(update_after(junk, 0), None, "{}", junk.escape_ascii());
        }
        // The same at the start of a line (after white-space) is.
        assert_eq!(
            update_after(b"\x00\n \t1 0 obj (x)\n", 0),
            Some(Update {
                first: 4,
                header: Some(4),
            })
        );
        assert_eq!(
            update_after(b"%%EOF\r  trailer\n<<>>", 0),
            Some(Update {
                first: 8,
                header: None,
            })
        );
    }

    #[test]
    fn scan_is_linear_on_hostile_input() {
        // A megabyte of nothing but headers and keywords; a quadratic scan would not finish.
        let mut file = Vec::new();
        for i in 0..40_000u32 {
            file.extend_from_slice(format!("{i} 0 obj<<>>stream\n").as_bytes());
        }
        let index = scan(&file);
        assert_eq!(index.candidates.len(), 40_000);
        assert!(index.next_endstream(0).is_none());
        // Without `endstream`, no stream says where it ends: every header is a definition.
        assert_eq!(definitions(&file, &index, &Limits::default()).len(), 40_000);
    }
}

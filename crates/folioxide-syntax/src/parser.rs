//! The object parser (ISO 32000-2 §7.3).
//!
//! - [`parse_object`] parses one direct object (including `N G R` references).
//! - [`parse_indirect_at`] parses an indirect object `N G obj … endobj`, including a stream's
//!   dictionary and the byte range of its data (§7.3.8, §7.3.10).
//!
//! The parser is **iterative**: nesting is kept on an explicit heap stack, never on the call
//! stack, and is bounded by [`Limits::max_nesting_depth`]. Hostile input such as 100,000 nested
//! `[` therefore returns [`ErrorCode::LimitExceeded`](crate::ErrorCode::LimitExceeded) instead of
//! overflowing the stack.
//!
//! Leniency follows [`Strictness`] (see [`crate::diag`]); every repair is reported to the
//! [`ParseCtx`]'s diagnostics sink.

use std::cell::Cell;
use std::collections::VecDeque;
use std::fmt;
use std::ops::Range;

use crate::diag::{Diagnostic, DiagnosticKind, DiagnosticSink, Strictness};
use crate::error::{Error, Result};
use crate::lexer::{
    Lexer, StringEnds, Token, TokenKind, find_bytes, is_whitespace, skip_whitespace_and_comments,
};
use crate::limits::{LimitKind, Limits};
use crate::object::{Dict, Name, Object, ObjectId, PdfString, Stream, StreamData};

/// Pre-computed positions of the keywords that stream recovery searches for, in one buffer.
///
/// When a stream's `/Length` is missing or wrong, [`parse_indirect_at`] searches forward for
/// `endstream` (and, if there is none, for `endobj`). Searching the buffer again for every broken
/// object is quadratic on a hostile file with many of them; an index built by one linear scan
/// answers each search in `O(log n)`. The [`Store`](crate::Store) builds one lazily, the first
/// time recovery needs it, and attaches it with [`ParseCtx::with_keyword_index`].
///
/// An index describes exactly one buffer: only attach it to a context that parses that buffer.
/// The parser checks every position it returns (the keyword must really be there, at or after
/// `from`) and falls back to a plain search otherwise; an answer of `None` is trusted. A wrong
/// index can therefore make recovery slower or miss a keyword, but never yields a range outside
/// the buffer.
pub trait KeywordIndex {
    /// The position of the first `endstream` (as a byte sequence, anywhere) at or after `from`.
    fn next_endstream(&self, from: usize) -> Option<usize>;
    /// The position of the first `endobj` (as a byte sequence, anywhere) at or after `from`.
    fn next_endobj(&self, from: usize) -> Option<usize>;
}

/// A bound on the memory one parse may allocate for the objects it builds (crate-internal: the
/// [`Store`](crate::Store) uses it for objects inside object streams, whose decoded data can be
/// a thousand times larger than the file).
///
/// The parser charges every value it creates with an estimate of what it costs: the size of an
/// [`Object`], plus the bytes of a string or a name, plus a dictionary's boxed map and the
/// overhead of each of its entries. Once the charges exceed the budget, the parse fails with
/// [`ErrorCode::LimitExceeded`](crate::ErrorCode::LimitExceeded) for the limit the budget
/// stands for. What a parse used is available afterwards, failed or not.
pub(crate) struct ParseBudget {
    /// The most this parse may use.
    max: u64,
    used: Cell<u64>,
    /// The limit reported when the budget is exceeded, and its value.
    limit: LimitKind,
    reported: u64,
}

impl ParseBudget {
    /// A budget of `max` bytes; exceeding it reports `limit` with the value `reported`.
    pub(crate) fn new(max: u64, limit: LimitKind, reported: u64) -> ParseBudget {
        ParseBudget {
            max,
            used: Cell::new(0),
            limit,
            reported,
        }
    }

    /// The bytes charged so far.
    pub(crate) fn used(&self) -> u64 {
        self.used.get()
    }

    /// Charges `weight` bytes for a value at byte `at`.
    fn charge(&self, weight: u64, at: usize) -> Result<()> {
        let used = self.used.get().saturating_add(weight);
        self.used.set(used);
        if used > self.max {
            return Err(Error::limit(self.limit, self.reported, Some(at as u64)));
        }
        Ok(())
    }
}

/// What one value costs a [`ParseBudget`], apart from its payload.
const VALUE_WEIGHT: u64 = std::mem::size_of::<Object>() as u64;
/// What a dictionary's boxed map costs, apart from its entries.
const DICT_WEIGHT: u64 = std::mem::size_of::<indexmap::IndexMap<Name, Object>>() as u64;
/// What one dictionary entry costs beyond its key and value: the key's slot in the entry, the
/// stored hash and the index table.
const ENTRY_WEIGHT: u64 = (std::mem::size_of::<Name>() + 3 * std::mem::size_of::<usize>()) as u64;

/// The weight of a finished scalar value: its [`VALUE_WEIGHT`] plus its heap bytes.
fn scalar_weight(value: &Object) -> u64 {
    let payload = match value {
        Object::String(s) => s.bytes.len(),
        Object::Name(n) => n.as_bytes().len(),
        _ => 0,
    };
    VALUE_WEIGHT.saturating_add(payload as u64)
}

/// The policy for one parse: limits, strictness and where diagnostics go.
///
/// It is cheap to copy. The default is lenient with the default [`Limits`], no diagnostics
/// sink (diagnostics are discarded) and no [`KeywordIndex`].
#[derive(Clone, Copy)]
pub struct ParseCtx<'a> {
    limits: Limits,
    strictness: Strictness,
    sink: Option<&'a dyn DiagnosticSink>,
    keywords: Option<&'a dyn KeywordIndex>,
    strings: Option<&'a dyn StringEnds>,
    /// Whether a hexadecimal string ends, with an error, at its first invalid byte (see
    /// [`ParseCtx::with_hex_ending_at_invalid_byte`]).
    hex_ends_at_invalid: bool,
    budget: Option<&'a ParseBudget>,
}

impl<'a> ParseCtx<'a> {
    /// Creates a context without a diagnostics sink.
    pub fn new(limits: Limits, strictness: Strictness) -> Self {
        ParseCtx {
            limits,
            strictness,
            sink: None,
            keywords: None,
            strings: None,
            hex_ends_at_invalid: false,
            budget: None,
        }
    }

    /// Bounds the memory of the objects this context's parses build (see [`ParseBudget`]).
    #[must_use]
    pub(crate) fn with_budget(mut self, budget: &'a ParseBudget) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Charges `weight` to the budget, if there is one.
    fn charge(&self, weight: u64, at: usize) -> Result<()> {
        match self.budget {
            Some(budget) => budget.charge(weight, at),
            None => Ok(()),
        }
    }

    /// Sets the keyword index that stream recovery uses instead of searching the buffer.
    /// The index must describe the buffer this context is used to parse (see [`KeywordIndex`]).
    #[must_use]
    pub fn with_keyword_index(mut self, index: &'a dyn KeywordIndex) -> Self {
        self.keywords = Some(index);
        self
    }

    /// The keyword index, if any.
    pub fn keyword_index(&self) -> Option<&'a dyn KeywordIndex> {
        self.keywords
    }

    /// Sets the index that tells the lexer whether a long literal string closes at all, so that
    /// one that never does fails without being read to the end of the buffer (see
    /// [`StringEnds`]). The index must describe the buffer this context is used to parse.
    #[must_use]
    pub(crate) fn with_string_ends(mut self, index: &'a dyn StringEnds) -> Self {
        self.strings = Some(index);
        self
    }

    /// The literal-string index, if any.
    pub(crate) fn string_ends(&self) -> Option<&'a dyn StringEnds> {
        self.strings
    }

    /// Makes a hexadecimal string end at its first byte that is neither a hexadecimal digit nor
    /// white-space (§7.3.4.3), with a syntax error there, as qpdf's tokenizer ends the token,
    /// instead of skipping the byte and reading on to the next `>` (which may be anywhere in the
    /// file). Crate-internal: the coverage parses of `repair::definitions` use it to tell how far
    /// a damaged object reaches; value reads stay lenient.
    #[must_use]
    pub(crate) fn with_hex_ending_at_invalid_byte(mut self) -> Self {
        self.hex_ends_at_invalid = true;
        self
    }

    /// Whether hexadecimal strings end at their first invalid byte (see
    /// [`ParseCtx::with_hex_ending_at_invalid_byte`]).
    pub(crate) fn hex_ends_at_invalid_byte(&self) -> bool {
        self.hex_ends_at_invalid
    }

    /// The first `endstream` in `bytes` at or after `from`, through the keyword index when
    /// there is one.
    fn find_endstream(&self, bytes: &[u8], from: usize) -> Option<usize> {
        self.find_keyword(bytes, b"endstream", from, |index| {
            index.next_endstream(from)
        })
    }

    /// The first `endobj` in `bytes` at or after `from`, through the keyword index when there
    /// is one.
    fn find_endobj(&self, bytes: &[u8], from: usize) -> Option<usize> {
        self.find_keyword(bytes, b"endobj", from, |index| index.next_endobj(from))
    }

    fn find_keyword(
        &self,
        bytes: &[u8],
        needle: &[u8],
        from: usize,
        lookup: impl FnOnce(&dyn KeywordIndex) -> Option<usize>,
    ) -> Option<usize> {
        match self.keywords {
            Some(index) => match lookup(index) {
                // Trust, but verify: a stale or foreign index must not produce a wrong range.
                Some(at) if at >= from && starts_with_at(bytes, at, needle) => Some(at),
                // The index is for another buffer (or wrong): search the slow way.
                Some(_) => find_bytes(bytes, needle, from),
                // "None" is trusted: re-searching here would make the hostile case (many
                // streams and no `endstream` at all) quadratic again.
                None => None,
            },
            None => find_bytes(bytes, needle, from),
        }
    }

    /// Sets the limits.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets the strictness.
    #[must_use]
    pub fn with_strictness(mut self, strictness: Strictness) -> Self {
        self.strictness = strictness;
        self
    }

    /// Sets the sink that receives diagnostics.
    #[must_use]
    pub fn with_diagnostics(mut self, sink: &'a dyn DiagnosticSink) -> Self {
        self.sink = Some(sink);
        self
    }

    /// The limits.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The strictness.
    pub fn strictness(&self) -> Strictness {
        self.strictness
    }

    /// The diagnostics sink, if any.
    pub fn diagnostics(&self) -> Option<&'a dyn DiagnosticSink> {
        self.sink
    }

    /// Sends a diagnostic to the sink, if there is one.
    pub fn report(&self, diagnostic: Diagnostic) {
        if let Some(sink) = self.sink {
            sink.report(diagnostic);
        }
    }

    /// Applies the leniency policy to a repairable problem: in lenient mode, reports a
    /// diagnostic of `kind` and returns `Ok`; in strict mode, returns a syntax error (or, without
    /// an offset, an error with code [`ErrorCode::Syntax`](crate::ErrorCode::Syntax)).
    ///
    /// The message is only built when it is needed.
    pub fn recover(
        &self,
        kind: DiagnosticKind,
        offset: Option<u64>,
        message: impl FnOnce() -> String,
    ) -> Result<()> {
        match self.strictness {
            Strictness::Strict => Err(match offset {
                Some(offset) => Error::syntax(offset, message()),
                None => Error::new(crate::ErrorCode::Syntax, message()),
            }),
            Strictness::Lenient => {
                if let Some(sink) = self.sink {
                    sink.report(Diagnostic::new(kind, offset, message()));
                }
                Ok(())
            }
        }
    }
}

impl Default for ParseCtx<'_> {
    fn default() -> Self {
        ParseCtx::new(Limits::DEFAULT, Strictness::Lenient)
    }
}

impl fmt::Debug for ParseCtx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParseCtx")
            .field("limits", &self.limits)
            .field("strictness", &self.strictness)
            .field("diagnostics", &self.sink.is_some())
            .field("keyword_index", &self.keywords.is_some())
            .field("string_ends", &self.strings.is_some())
            .field("hex_ends_at_invalid_byte", &self.hex_ends_at_invalid)
            .field("budget", &self.budget.map(ParseBudget::used))
            .finish()
    }
}

/// An indirect object as parsed by [`parse_indirect_at`].
#[derive(Clone, Debug, PartialEq)]
pub struct IndirectObject {
    /// The identifier from the object header `N G obj`.
    pub id: ObjectId,
    /// The value. For a stream, an [`Object::Stream`] whose data is
    /// [`StreamData::Source`] with the same range as [`IndirectObject::stream_data_range`].
    pub object: Object,
    /// For a stream, the byte range of its (still encoded) data in the parsed buffer.
    pub stream_data_range: Option<Range<u64>>,
    /// The byte offset just past the object: after `endobj`, or, when `endobj` is missing,
    /// after the last part that was read.
    pub end: usize,
}

/// Parses one direct object starting at byte `pos` (leading white-space and comments are
/// skipped) and returns it with the offset just past its last token.
///
/// `N G R` is read as a reference. A stream cannot be parsed this way (use
/// [`parse_indirect_at`]); `stream`, `endobj` and other object-level keywords end the object.
///
/// ```
/// use folioxide_syntax::{parse_object, Object, ObjectId, ParseCtx};
///
/// let (obj, end) = parse_object(b"<< /Kids [3 0 R] /Count 1 >> trailing", 0, &ParseCtx::default())?;
/// let dict = obj.as_dict().unwrap();
/// assert_eq!(dict.get_array(b"Kids").unwrap()[0], Object::Ref(ObjectId::new(3, 0)));
/// assert_eq!(end, 28);
/// # Ok::<(), folioxide_syntax::Error>(())
/// ```
///
/// # Errors
/// [`ErrorCode::Syntax`](crate::ErrorCode::Syntax) for malformed input (or, in strict mode,
/// anything lenient mode would repair) and
/// [`ErrorCode::LimitExceeded`](crate::ErrorCode::LimitExceeded) when nesting deeper than
/// [`Limits::max_nesting_depth`] or a string longer than [`Limits::max_string_len`].
pub fn parse_object(bytes: &[u8], pos: usize, ctx: &ParseCtx<'_>) -> Result<(Object, usize)> {
    let mut parser = Parser::new(bytes, pos, ctx);
    let object = parser.parse_value()?;
    Ok((object, parser.tokens.last_end))
}

/// Parses an indirect object header `N G obj` at byte `pos` (after optional white-space) and
/// returns its identifier and the offset just past `obj`.
///
/// # Errors
/// [`ErrorCode::Syntax`](crate::ErrorCode::Syntax) if there is no valid header at `pos`.
pub fn parse_indirect_header(
    bytes: &[u8],
    pos: usize,
    ctx: &ParseCtx<'_>,
) -> Result<(ObjectId, usize)> {
    let mut lexer = Lexer::with_ctx(bytes, pos, ctx);
    lexer.skip_whitespace();
    let header_start = lexer.position() as u64;
    let bad = || Error::syntax(header_start, "expected an object header `N G obj`");
    let num = match lexer.next_token() {
        Ok(Some(Token {
            kind: TokenKind::Integer(n),
            ..
        })) => u32::try_from(n).map_err(|_| bad())?,
        _ => return Err(bad()),
    };
    let r#gen = match lexer.next_token() {
        Ok(Some(Token {
            kind: TokenKind::Integer(g),
            ..
        })) => u16::try_from(g).map_err(|_| bad())?,
        _ => return Err(bad()),
    };
    match lexer.next_token() {
        Ok(Some(Token {
            kind: TokenKind::Keyword(b"obj"),
            end,
            ..
        })) => Ok((ObjectId::new(num, r#gen), end)),
        _ => Err(bad()),
    }
}

/// Parses the indirect object `N G obj … endobj` at byte `offset` of `bytes`.
///
/// For a stream, the data range is taken from `/Length`, which is either a direct integer or a
/// reference resolved through `length_resolver` (which returns `None` when the value cannot be
/// determined, for example because of a reference cycle). The range is relative to `bytes`.
///
/// **Recovery** (lenient mode, each reported as a [`Diagnostic`]; errors in strict mode):
/// - If `endstream` does not follow the data at `start + Length` (after optional white-space),
///   or `/Length` is missing or unusable, the data ends at the first `endstream` after its start,
///   minus the EOL before it ([`DiagnosticKind::StreamLength`]).
/// - Without any `endstream`, the data ends at `start + Length` if that is inside the buffer,
///   else before the next `endobj`, else at the end of the buffer
///   ([`DiagnosticKind::MissingEndstream`]).
/// - `stream` followed by a lone CR, by spaces before the EOL, or by no EOL at all is accepted
///   ([`DiagnosticKind::StreamKeywordEol`]); §7.3.8.1 requires CRLF or LF.
/// - A missing `endobj` is tolerated ([`DiagnosticKind::MissingEndobj`]), as is an object
///   without a value, read as `null` ([`DiagnosticKind::EmptyObject`]).
///
/// ```
/// use folioxide_syntax::{parse_indirect_at, ObjectId, ParseCtx};
///
/// let file = b"7 0 obj\n<< /Length 5 >>\nstream\nHello\nendstream\nendobj\n";
/// let obj = parse_indirect_at(file, 0, &ParseCtx::default(), &|_| None)?;
/// assert_eq!(obj.id, ObjectId::new(7, 0));
/// assert_eq!(obj.stream_data_range, Some(31..36));
/// assert_eq!(obj.end, file.len() - 1);
/// # Ok::<(), folioxide_syntax::Error>(())
/// ```
///
/// # Errors
/// [`ErrorCode::Syntax`](crate::ErrorCode::Syntax) if there is no object header at `offset` or
/// the value is malformed, and the errors of [`parse_object`].
pub fn parse_indirect_at(
    bytes: &[u8],
    offset: usize,
    ctx: &ParseCtx<'_>,
    length_resolver: &dyn Fn(ObjectId) -> Option<i64>,
) -> Result<IndirectObject> {
    parse_indirect_extent(bytes, offset, ctx, length_resolver).0
}

/// [`parse_indirect_at`], also returning how far the parse read, failed or not: the end of the
/// last token the lexer read (the lookahead after a value included, or where the lexer stopped
/// on an error), at least the end of the header (`offset` when there is no header). Stream
/// data is located (by `/Length`, or by the keyword index), not read, so it does not count, nor
/// does the white-space before a keyword checked byte by byte (`endobj`, `stream`).
///
/// Past the end of a value, the parser reads ahead only after an integer, for a reference
/// `N G R`: one lookahead token, and the white-space and comments before it, lexed only when its
/// first byte can start a number (see `Tokens::peek_if`), so never a string; and, only when that
/// token is a number, one more that starts with `R` (`42 7 Rx` reads `Rx`). A token is thus read
/// ahead only by the parse whose value it follows. Crate-internal: `repair::definitions` skips
/// the bytes a parse read.
pub(crate) fn parse_indirect_extent(
    bytes: &[u8],
    offset: usize,
    ctx: &ParseCtx<'_>,
    length_resolver: &dyn Fn(ObjectId) -> Option<i64>,
) -> (Result<IndirectObject>, usize) {
    let mut read = offset;
    let result = parse_indirect_inner(bytes, offset, ctx, length_resolver, &mut read);
    (result, read)
}

/// [`parse_indirect_extent`], keeping how far it read in `read`.
fn parse_indirect_inner(
    bytes: &[u8],
    offset: usize,
    ctx: &ParseCtx<'_>,
    length_resolver: &dyn Fn(ObjectId) -> Option<i64>,
    read: &mut usize,
) -> Result<IndirectObject> {
    let (id, header_end) = parse_indirect_header(bytes, offset, ctx)?;
    *read = header_end;

    // An object without a value: `N G obj endobj`.
    let value_pos = skip_whitespace_and_comments(bytes, header_end);
    if starts_with_at(bytes, value_pos, b"endobj") {
        ctx.recover(DiagnosticKind::EmptyObject, Some(value_pos as u64), || {
            format!("object {id} has no value; read as null")
        })?;
        return Ok(IndirectObject {
            id,
            object: Object::Null,
            stream_data_range: None,
            end: value_pos + b"endobj".len(),
        });
    }

    let mut parser = Parser::new(bytes, header_end, ctx);
    let value = parser.parse_value();
    *read = parser.tokens.read_to().max(header_end);
    let object = value?;
    let value_end = parser.tokens.last_end;
    let after_value = skip_whitespace_and_comments(bytes, value_end);

    if starts_with_at(bytes, after_value, b"stream") {
        let keyword_end = after_value + b"stream".len();
        return match object {
            Object::Dict(dict) => parse_stream(bytes, id, dict, keyword_end, ctx, length_resolver),
            other => {
                ctx.recover(
                    DiagnosticKind::StreamWithoutDict,
                    Some(after_value as u64),
                    || {
                        format!(
                            "`stream` after a {} in object {id}; stream ignored",
                            other.type_name()
                        )
                    },
                )?;
                Ok(IndirectObject {
                    id,
                    object: other,
                    stream_data_range: None,
                    end: value_end,
                })
            }
        };
    }

    let end = finish_object(bytes, id, value_end, ctx)?;
    Ok(IndirectObject {
        id,
        object,
        stream_data_range: None,
        end,
    })
}

/// Reads the `endobj` keyword after `pos` and returns the offset past it, or tolerates its
/// absence and returns `pos`.
fn finish_object(bytes: &[u8], id: ObjectId, pos: usize, ctx: &ParseCtx<'_>) -> Result<usize> {
    let at = skip_whitespace_and_comments(bytes, pos);
    if starts_with_at(bytes, at, b"endobj") {
        Ok(at + b"endobj".len())
    } else {
        ctx.recover(DiagnosticKind::MissingEndobj, Some(at as u64), || {
            format!("object {id} has no `endobj`")
        })?;
        Ok(pos)
    }
}

/// Parses the stream that follows `dict`; `keyword_end` is just past the `stream` keyword.
fn parse_stream(
    bytes: &[u8],
    id: ObjectId,
    dict: Dict,
    keyword_end: usize,
    ctx: &ParseCtx<'_>,
    length_resolver: &dyn Fn(ObjectId) -> Option<i64>,
) -> Result<IndirectObject> {
    let start = stream_data_start(bytes, keyword_end, ctx)?;

    // §7.3.8.2: /Length is a non-negative integer, possibly an indirect reference.
    let length_obj = dict.get(crate::keys::LENGTH);
    let declared: Option<u64> = match length_obj {
        Some(Object::Int(n)) => u64::try_from(*n).ok(),
        Some(Object::Ref(r)) => length_resolver(*r).and_then(|n| u64::try_from(n).ok()),
        _ => None,
    };
    let declared_end = declared
        .and_then(|len| usize::try_from(len).ok())
        .and_then(|len| start.checked_add(len))
        .filter(|&end| end <= bytes.len());

    // The normal case: `endstream` follows the declared data, after optional white-space
    // (§7.3.8.1: an EOL should precede `endstream` and is not counted in /Length).
    let (data_end, after_data) = match declared_end.and_then(|end| {
        let kw = skip_pdf_whitespace(bytes, end);
        starts_with_at(bytes, kw, b"endstream").then_some((end, kw + b"endstream".len()))
    }) {
        Some(found) => found,
        None => {
            let why = || match (length_obj, declared) {
                (None, _) => "stream has no /Length".to_owned(),
                (Some(Object::Ref(r)), None) => {
                    format!("stream /Length {r} could not be resolved")
                }
                (Some(other), None) => {
                    format!(
                        "stream /Length is not a valid length ({})",
                        other.type_name()
                    )
                }
                (Some(_), Some(len)) => format!("stream /Length {len} is wrong"),
            };
            match ctx.find_endstream(bytes, start) {
                Some(kw) => {
                    let end = trim_eol_before(bytes, start, kw);
                    ctx.recover(DiagnosticKind::StreamLength, Some(start as u64), || {
                        format!(
                            "{} in object {id}; data delimited by `endstream` ({} bytes)",
                            why(),
                            end - start
                        )
                    })?;
                    (end, kw + b"endstream".len())
                }
                None => {
                    let end = match declared_end {
                        Some(end) => end,
                        None => match ctx.find_endobj(bytes, start) {
                            Some(kw) => trim_eol_before(bytes, start, kw),
                            None => bytes.len(),
                        },
                    };
                    ctx.recover(DiagnosticKind::MissingEndstream, Some(start as u64), || {
                        format!(
                            "stream in object {id} has no `endstream` ({} bytes kept)",
                            end - start
                        )
                    })?;
                    (end, end)
                }
            }
        }
    };

    let end = finish_object(bytes, id, after_data, ctx)?;
    let range = start as u64..data_end as u64;
    Ok(IndirectObject {
        id,
        object: Object::Stream(Box::new(Stream {
            dict,
            data: StreamData::Source(range.clone()),
        })),
        stream_data_range: Some(range),
        end,
    })
}

/// Returns the offset where stream data starts, given the offset just past `stream`.
/// §7.3.8.1: the keyword is followed by CRLF or LF, never a lone CR (trap #1).
fn stream_data_start(bytes: &[u8], keyword_end: usize, ctx: &ParseCtx<'_>) -> Result<usize> {
    match (bytes.get(keyword_end), bytes.get(keyword_end + 1)) {
        (Some(b'\r'), Some(b'\n')) => Ok(keyword_end + 2),
        (Some(b'\n'), _) => Ok(keyword_end + 1),
        (Some(b'\r'), _) => {
            ctx.recover(
                DiagnosticKind::StreamKeywordEol,
                Some(keyword_end as u64),
                || "`stream` is followed by a lone CR".to_owned(),
            )?;
            Ok(keyword_end + 1)
        }
        _ => {
            // Tolerate spaces before the EOL; without any EOL the data starts right away.
            let mut i = keyword_end;
            while matches!(bytes.get(i), Some(b' ' | b'\t' | b'\x0c' | b'\0')) {
                i += 1;
            }
            let start = match (bytes.get(i), bytes.get(i + 1)) {
                (Some(b'\r'), Some(b'\n')) => i + 2,
                (Some(b'\n' | b'\r'), _) => i + 1,
                _ => keyword_end,
            };
            ctx.recover(
                DiagnosticKind::StreamKeywordEol,
                Some(keyword_end as u64),
                || "`stream` is not followed by an end-of-line marker".to_owned(),
            )?;
            Ok(start)
        }
    }
}

/// `pos` moved back over one EOL (CRLF, LF or CR) that ends just before it, but not below
/// `floor`.
fn trim_eol_before(bytes: &[u8], floor: usize, pos: usize) -> usize {
    if pos >= floor + 2 && bytes.get(pos - 2..pos) == Some(b"\r\n") {
        pos - 2
    } else if pos > floor && matches!(bytes.get(pos - 1), Some(b'\r' | b'\n')) {
        pos - 1
    } else {
        pos
    }
}

/// Skips white-space (not comments).
fn skip_pdf_whitespace(bytes: &[u8], mut pos: usize) -> usize {
    while bytes.get(pos).is_some_and(|&b| is_whitespace(b)) {
        pos += 1;
    }
    pos
}

fn starts_with_at(bytes: &[u8], pos: usize, needle: &[u8]) -> bool {
    bytes
        .get(pos..)
        .is_some_and(|rest| rest.starts_with(needle))
}

/// Keywords that end an object: inside an open array or dictionary they close it implicitly
/// (lenient mode).
fn is_structural_keyword(k: &[u8]) -> bool {
    matches!(
        k,
        b"endobj" | b"stream" | b"endstream" | b"obj" | b"xref" | b"trailer" | b"startxref"
    )
}

/// A token stream with up to two tokens of lookahead (for `N G R`).
struct Tokens<'a> {
    lexer: Lexer<'a>,
    lookahead: VecDeque<Result<Option<Token<'a>>>>,
    /// The end offset of the last token returned by [`Tokens::next`].
    last_end: usize,
}

impl<'a> Tokens<'a> {
    fn fill(&mut self, n: usize) {
        while self.lookahead.len() <= n {
            let item = match self.lookahead.back() {
                // Never lex past the end or past an error.
                Some(Ok(None)) => Ok(None),
                Some(Err(e)) => Err(e.clone()),
                _ => self.lexer.next_token(),
            };
            self.lookahead.push_back(item);
        }
    }

    fn peek(&mut self, n: usize) -> Option<&Token<'a>> {
        self.fill(n);
        match self.lookahead.get(n) {
            Some(Ok(Some(tok))) => Some(tok),
            _ => None,
        }
    }

    /// [`Tokens::peek`], except that the token `n` places ahead, when it is the next one to lex,
    /// is lexed only if its first byte passes `first`: a lookahead for a number or `R` never
    /// reads a string. The tokens are the same either way (one not lexed here is lexed when it is
    /// needed); only how far the lexer has read differs (see [`parse_indirect_extent`]).
    fn peek_if(&mut self, n: usize, first: fn(u8) -> bool) -> Option<&Token<'a>> {
        if self.lookahead.len() == n && matches!(self.lookahead.back(), None | Some(Ok(Some(_)))) {
            let data = self.lexer.data();
            let at = skip_whitespace_and_comments(data, self.lexer.position());
            if !data.get(at).copied().is_some_and(first) {
                return None;
            }
        }
        self.peek(n)
    }

    /// How far the lexer has read: the end of the last token it lexed, lookahead included, or
    /// where it stopped on an error.
    fn read_to(&self) -> usize {
        self.lexer.position()
    }

    fn next(&mut self) -> Result<Option<Token<'a>>> {
        self.fill(0);
        let item = self.lookahead.pop_front().unwrap_or(Ok(None));
        if let Ok(Some(tok)) = &item {
            self.last_end = tok.end;
        }
        item
    }
}

/// An open container on the explicit parse stack.
enum Frame {
    Array {
        items: Vec<Object>,
    },
    Dict {
        dict: Dict,
        /// A key waiting for its value, with the key's offset.
        key: Option<(Name, usize)>,
    },
}

struct Parser<'a> {
    tokens: Tokens<'a>,
    ctx: &'a ParseCtx<'a>,
    len: usize,
}

impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8], pos: usize, ctx: &'a ParseCtx<'a>) -> Self {
        let lexer = Lexer::with_ctx(bytes, pos, ctx);
        Parser {
            tokens: Tokens {
                last_end: lexer.position(),
                lexer,
                lookahead: VecDeque::with_capacity(2),
            },
            ctx,
            len: bytes.len(),
        }
    }

    /// Parses one value, iteratively.
    fn parse_value(&mut self) -> Result<Object> {
        // Clamped: `Object`'s derived `Clone`, `Drop`, `PartialEq` and `Debug` recurse.
        let max_depth = usize::from(self.ctx.limits().effective_nesting_depth());
        let mut stack: Vec<(Frame, usize)> = Vec::new();
        loop {
            // An object-level keyword inside a container closes every open container.
            if !stack.is_empty()
                && let Some(Token {
                    kind: TokenKind::Keyword(k),
                    start,
                    ..
                }) = self.tokens.peek(0)
                && is_structural_keyword(k)
            {
                let (at, keyword) = (*start, k.escape_ascii().to_string());
                self.ctx
                    .recover(DiagnosticKind::UnclosedContainer, Some(at as u64), || {
                        format!(
                            "`{keyword}` inside an unclosed array or dictionary; closed implicitly"
                        )
                    })?;
                return self.close_all(stack);
            }

            let Some(tok) = self.tokens.next()? else {
                let context = match stack.last() {
                    None => "object",
                    Some((Frame::Array { .. }, _)) => "array",
                    Some((Frame::Dict { .. }, _)) => "dictionary",
                };
                return Err(Error::eof(self.len as u64, context));
            };
            let at = tok.start;
            let value = match tok.kind {
                TokenKind::Integer(n) => self.integer_or_reference(n, at)?,
                TokenKind::Real(r) => Object::Real(r),
                TokenKind::LiteralString(s) => Object::String(PdfString {
                    bytes: s.into_owned(),
                    hex: false,
                }),
                TokenKind::HexString(s) => Object::String(PdfString {
                    bytes: s,
                    hex: true,
                }),
                TokenKind::Name(n) => Object::Name(Name::from(n)),
                TokenKind::ArrayStart => {
                    self.ctx.charge(VALUE_WEIGHT, at)?;
                    Self::open(
                        &mut stack,
                        Frame::Array { items: Vec::new() },
                        at,
                        max_depth,
                    )?;
                    continue;
                }
                TokenKind::DictStart => {
                    self.ctx
                        .charge(VALUE_WEIGHT.saturating_add(DICT_WEIGHT), at)?;
                    let frame = Frame::Dict {
                        dict: Dict::new(),
                        key: None,
                    };
                    Self::open(&mut stack, frame, at, max_depth)?;
                    continue;
                }
                TokenKind::ArrayEnd => match stack.pop() {
                    Some((Frame::Array { mut items }, _)) => {
                        items.shrink_to_fit();
                        Object::Array(items)
                    }
                    Some((Frame::Dict { .. }, _)) => {
                        return Err(Error::syntax(at as u64, "`]` closes a dictionary"));
                    }
                    None => return Err(Error::syntax(at as u64, "unexpected `]`")),
                },
                TokenKind::DictEnd => match stack.pop() {
                    Some((frame @ Frame::Dict { .. }, start)) => self.close(frame, start)?,
                    Some((Frame::Array { .. }, _)) => {
                        return Err(Error::syntax(at as u64, "`>>` closes an array"));
                    }
                    None => return Err(Error::syntax(at as u64, "unexpected `>>`")),
                },
                TokenKind::BraceOpen | TokenKind::BraceClose => {
                    return Err(Error::syntax(
                        at as u64,
                        "`{` and `}` are only valid in PostScript calculator functions",
                    ));
                }
                TokenKind::Keyword(b"true") => Object::Bool(true),
                TokenKind::Keyword(b"false") => Object::Bool(false),
                TokenKind::Keyword(b"null") => Object::Null,
                TokenKind::Keyword(k) => {
                    if stack.is_empty() {
                        return Err(Error::syntax(
                            at as u64,
                            format!("expected an object, found `{}`", k.escape_ascii()),
                        ));
                    }
                    self.ctx
                        .recover(DiagnosticKind::UnknownKeyword, Some(at as u64), || {
                            format!("unknown keyword `{}` replaced by null", k.escape_ascii())
                        })?;
                    Object::Null
                }
            };
            // Containers were charged when they were opened.
            if !matches!(value, Object::Array(_) | Object::Dict(_)) {
                self.ctx.charge(scalar_weight(&value), at)?;
            }
            match stack.last_mut() {
                None => return Ok(value),
                Some((frame, _)) => self.attach(frame, value, at)?,
            }
        }
    }

    /// Pushes a new container, enforcing [`Limits::max_nesting_depth`].
    fn open(
        stack: &mut Vec<(Frame, usize)>,
        frame: Frame,
        at: usize,
        max_depth: usize,
    ) -> Result<()> {
        if stack.len() >= max_depth {
            return Err(Error::limit(
                LimitKind::MaxNestingDepth,
                max_depth as u64,
                Some(at as u64),
            ));
        }
        stack.push((frame, at));
        Ok(())
    }

    /// `n` alone, or the reference `n g R` (§7.3.10).
    fn integer_or_reference(&mut self, n: i64, at: usize) -> Result<Object> {
        // Only a token that can be an integer, then `R`, is worth lexing ahead.
        let r#gen = match self
            .tokens
            .peek_if(0, |b| b.is_ascii_digit() || b == b'+' || b == b'-')
        {
            Some(Token {
                kind: TokenKind::Integer(g),
                ..
            }) => *g,
            _ => return Ok(Object::Int(n)),
        };
        if !matches!(
            self.tokens.peek_if(1, |b| b == b'R'),
            Some(Token {
                kind: TokenKind::Keyword(b"R"),
                ..
            })
        ) {
            return Ok(Object::Int(n));
        }
        self.tokens.next()?;
        self.tokens.next()?;
        match (u32::try_from(n), u16::try_from(r#gen)) {
            (Ok(num), Ok(r#gen)) => Ok(Object::Ref(ObjectId::new(num, r#gen))),
            _ => {
                self.ctx
                    .recover(DiagnosticKind::InvalidReference, Some(at as u64), || {
                        format!(
                            "reference `{n} {} R` is out of range; replaced by null",
                            r#gen
                        )
                    })?;
                Ok(Object::Null)
            }
        }
    }

    /// Adds a finished value to the innermost open container.
    fn attach(&self, frame: &mut Frame, value: Object, at: usize) -> Result<()> {
        match frame {
            Frame::Array { items } => items.push(value),
            Frame::Dict { dict, key } => match key.take() {
                Some((k, key_at)) => {
                    self.ctx.charge(ENTRY_WEIGHT, key_at)?;
                    if dict.contains_key(k.as_bytes()) {
                        self.ctx.recover(
                            DiagnosticKind::DuplicateKey,
                            Some(key_at as u64),
                            || format!("duplicate dictionary key {k}; the last value wins"),
                        )?;
                    }
                    dict.insert(k, value);
                }
                None => match value {
                    Object::Name(n) => *key = Some((n, at)),
                    other => {
                        self.ctx.recover(
                            DiagnosticKind::InvalidDictKey,
                            Some(at as u64),
                            || {
                                format!(
                                    "dictionary key must be a name, found a {}; entry skipped",
                                    other.type_name()
                                )
                            },
                        )?;
                    }
                },
            },
        }
        Ok(())
    }

    /// Turns a finished frame into its value.
    fn close(&self, frame: Frame, start: usize) -> Result<Object> {
        match frame {
            Frame::Array { mut items } => {
                items.shrink_to_fit();
                Ok(Object::Array(items))
            }
            Frame::Dict { mut dict, key } => {
                dict.shrink_to_fit();
                if let Some((k, key_at)) = key {
                    self.ctx
                        .recover(DiagnosticKind::MissingDictValue, Some(key_at as u64), || {
                            format!(
                                "dictionary key {k} has no value (dictionary at byte {start}); key dropped"
                            )
                        })?;
                }
                Ok(Object::Dict(dict))
            }
        }
    }

    /// Closes every open container, innermost first, and returns the outermost value.
    fn close_all(&self, mut stack: Vec<(Frame, usize)>) -> Result<Object> {
        let mut value = None;
        while let Some((mut frame, start)) = stack.pop() {
            if let Some((v, at)) = value.take() {
                self.attach(&mut frame, v, at)?;
            }
            value = Some((self.close(frame, start)?, start));
        }
        value
            .map(|(v, _)| v)
            .ok_or_else(|| Error::syntax(self.tokens.last_end as u64, "no open container"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;
    use std::cell::RefCell;

    fn parse(input: &[u8]) -> Object {
        parse_object(input, 0, &ParseCtx::default())
            .unwrap_or_else(|e| panic!("{:?}: {e}", input.escape_ascii()))
            .0
    }

    fn parse_strict(input: &[u8]) -> Result<(Object, usize)> {
        parse_object(
            input,
            0,
            &ParseCtx::default().with_strictness(Strictness::Strict),
        )
    }

    /// Parses leniently and returns the object and the diagnostic kinds.
    fn parse_diag(input: &[u8]) -> (Result<Object>, Vec<DiagnosticKind>) {
        let diags = RefCell::new(Vec::new());
        let sink = |d: Diagnostic| diags.borrow_mut().push(d.kind);
        let ctx = ParseCtx::default().with_diagnostics(&sink);
        let result = parse_object(input, 0, &ctx).map(|(o, _)| o);
        (result, diags.into_inner())
    }

    fn name(s: &str) -> Object {
        Object::name(s)
    }

    fn r(num: u32, r#gen: u16) -> Object {
        Object::Ref(ObjectId::new(num, r#gen))
    }

    fn dict(entries: Vec<(&str, Object)>) -> Object {
        Object::Dict(
            entries
                .into_iter()
                .map(|(k, v)| (Name::from(k), v))
                .collect(),
        )
    }

    #[test]
    fn parses_every_object_type() {
        let cases: Vec<(&[u8], Object)> = vec![
            (b"null", Object::Null),
            (b"true", Object::Bool(true)),
            (b"false", Object::Bool(false)),
            (b"-42", Object::Int(-42)),
            (b"--42", Object::Int(-42)),
            (b"3.25", Object::Real(3.25)),
            (b"(a\\)b)", Object::literal_string("a)b")),
            (b"<4142>", Object::hex_string("AB")),
            (b"/Na#20me", name("Na me")),
            (b"12 0 R", r(12, 0)),
            (b"12 65535 R", r(12, 65535)),
            (b"[]", Object::Array(vec![])),
            (b"<<>>", dict(vec![])),
            (
                b"[1 2 R 3 4 5 R 6]",
                Object::Array(vec![r(1, 2), Object::Int(3), r(4, 5), Object::Int(6)]),
            ),
            (
                b"[1 2 3]",
                Object::Array(vec![Object::Int(1), Object::Int(2), Object::Int(3)]),
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(parse(input), expected, "{:?}", input.escape_ascii());
        }
    }

    #[test]
    fn parses_nested_structures() {
        let input =
            b"<< /Type /Page /MediaBox [0 0 612.0 792] /Resources << /Font << /F1 5 0 R >> >> \
                      /Contents [6 0 R 7 0 R] /Annots [] /Note (x) /Empty <<>> /N null >>";
        let expected = dict(vec![
            ("Type", name("Page")),
            (
                "MediaBox",
                Object::Array(vec![
                    Object::Int(0),
                    Object::Int(0),
                    Object::Real(612.0),
                    Object::Int(792),
                ]),
            ),
            (
                "Resources",
                dict(vec![("Font", dict(vec![("F1", r(5, 0))]))]),
            ),
            ("Contents", Object::Array(vec![r(6, 0), r(7, 0)])),
            ("Annots", Object::Array(vec![])),
            ("Note", Object::literal_string("x")),
            ("Empty", dict(vec![])),
            ("N", Object::Null),
        ]);
        assert_eq!(parse(input), expected);
        // Key order is preserved.
        let parsed = parse(input);
        let keys: Vec<&[u8]> = parsed
            .as_dict()
            .unwrap()
            .keys()
            .map(Name::as_bytes)
            .collect();
        assert_eq!(
            keys,
            [
                &b"Type"[..],
                b"MediaBox",
                b"Resources",
                b"Contents",
                b"Annots",
                b"Note",
                b"Empty",
                b"N"
            ]
        );
        // No white-space needed around delimiters.
        assert_eq!(
            parse(b"<</A[1/B(c)<44>]/E<</F 1 0 R>>>>"),
            dict(vec![
                (
                    "A",
                    Object::Array(vec![
                        Object::Int(1),
                        name("B"),
                        Object::literal_string("c"),
                        Object::hex_string("D"),
                    ])
                ),
                ("E", dict(vec![("F", r(1, 0))])),
            ])
        );
    }

    #[test]
    fn end_offsets() {
        let ctx = ParseCtx::default();
        let cases: Vec<(&[u8], usize)> = vec![
            (b"  12 rest", 4),
            (b"12 0 obj", 2),
            (b"12 0 R%x", 6),
            (b"[1 2]   ", 5),
            (b"<< /A 1 >>x", 10),
            (b"(s) 5", 3),
            (b"1 2", 1),
        ];
        for (input, end) in cases {
            let (_, got) = parse_object(input, 0, &ctx).unwrap();
            assert_eq!(got, end, "{:?}", input.escape_ascii());
        }
        // Parsing from a position.
        let (obj, end) = parse_object(b"1 0 obj 42 endobj", 8, &ctx).unwrap();
        assert_eq!((obj, end), (Object::Int(42), 10));
    }

    #[test]
    fn lenient_repairs_and_strict_errors() {
        let cases: Vec<(&[u8], Object, DiagnosticKind)> = vec![
            (
                b"<< /A 1 /A 2 >>",
                dict(vec![("A", Object::Int(2))]),
                DiagnosticKind::DuplicateKey,
            ),
            (
                b"<< /A 1 2 /B 3 >>",
                dict(vec![("A", Object::Int(1)), ("B", Object::Int(3))]),
                DiagnosticKind::InvalidDictKey,
            ),
            (
                b"<< /A 1 [2] /B 3 >>",
                dict(vec![("A", Object::Int(1)), ("B", Object::Int(3))]),
                DiagnosticKind::InvalidDictKey,
            ),
            (
                b"<< /A 1 /B >>",
                dict(vec![("A", Object::Int(1))]),
                DiagnosticKind::MissingDictValue,
            ),
            (
                b"[1 foo 2]",
                Object::Array(vec![Object::Int(1), Object::Null, Object::Int(2)]),
                DiagnosticKind::UnknownKeyword,
            ),
            (
                b"[1 R]",
                Object::Array(vec![Object::Int(1), Object::Null]),
                DiagnosticKind::UnknownKeyword,
            ),
            (
                b"[-1 0 R]",
                Object::Array(vec![Object::Null]),
                DiagnosticKind::InvalidReference,
            ),
            (
                b"[1 65536 R]",
                Object::Array(vec![Object::Null]),
                DiagnosticKind::InvalidReference,
            ),
            (
                b"[4294967296 0 R]",
                Object::Array(vec![Object::Null]),
                DiagnosticKind::InvalidReference,
            ),
            (
                b"<< /Type /Catalog /Pages 2 0 R endobj",
                dict(vec![("Type", name("Catalog")), ("Pages", r(2, 0))]),
                DiagnosticKind::UnclosedContainer,
            ),
            (
                b"<< /K [1 << /L 2 stream",
                dict(vec![(
                    "K",
                    Object::Array(vec![Object::Int(1), dict(vec![("L", Object::Int(2))])]),
                )]),
                DiagnosticKind::UnclosedContainer,
            ),
        ];
        for (input, expected, kind) in cases {
            let (result, diags) = parse_diag(input);
            assert_eq!(result.unwrap(), expected, "{:?}", input.escape_ascii());
            assert_eq!(diags, [kind], "{:?}", input.escape_ascii());
            let err = parse_strict(input).unwrap_err();
            assert_eq!(err.code(), ErrorCode::Syntax, "{:?}", input.escape_ascii());
            assert!(err.offset().is_some());
        }
        // Implicit close leaves the keyword for the caller.
        let (_, end) = parse_object(b"<< /A 1 endobj", 0, &ParseCtx::default()).unwrap();
        assert_eq!(end, 7);
    }

    #[test]
    fn syntax_errors() {
        let cases: Vec<(&[u8], ErrorCode, u64)> = vec![
            (b"", ErrorCode::Syntax, 0),
            (b"   ", ErrorCode::Syntax, 3),
            (b"[1 2", ErrorCode::Syntax, 4),
            (b"<< /A", ErrorCode::Syntax, 5),
            (b"]", ErrorCode::Syntax, 0),
            (b">>", ErrorCode::Syntax, 0),
            (b"[1 >>", ErrorCode::Syntax, 3),
            (b"<< /A ]", ErrorCode::Syntax, 6),
            (b"endobj", ErrorCode::Syntax, 0),
            (b"R", ErrorCode::Syntax, 0),
            (b"foo", ErrorCode::Syntax, 0),
            (b"{ 1 }", ErrorCode::Syntax, 0),
            (b"[ ) ]", ErrorCode::Syntax, 2),
            (b"(unterminated", ErrorCode::Syntax, 13),
        ];
        for (input, code, offset) in cases {
            let err = parse_object(input, 0, &ParseCtx::default()).unwrap_err();
            assert_eq!(err.code(), code, "{:?}: {err}", input.escape_ascii());
            assert_eq!(
                err.offset(),
                Some(offset),
                "{:?}: {err}",
                input.escape_ascii()
            );
        }
    }

    #[test]
    fn reference_lookahead_does_not_swallow_errors_after_the_object() {
        // `5` is complete; the bad token after it belongs to the caller.
        let (obj, end) = parse_object(b"5 ) x", 0, &ParseCtx::default()).unwrap();
        assert_eq!((obj, end), (Object::Int(5), 1));
        let (obj, end) = parse_object(b"5 6 )", 0, &ParseCtx::default()).unwrap();
        assert_eq!((obj, end), (Object::Int(5), 1));
    }

    #[test]
    fn an_extent_reads_past_the_value_only_its_lookahead() {
        // What a parse reads past its value (`parse_indirect_extent`): after an integer, the
        // white-space and comments, then one token that starts like a number, and, after a
        // number, one more that starts with `R` (for `N G R`); never a string, and nothing after
        // any other value.
        let cases: [(&[u8], &[u8]); 7] = [
            (b"1 0 obj\n42\nendobj\n", b"42"),
            (b"1 0 obj\n42\n%a comment\n5 0 obj\n", b"5"),
            (b"1 0 obj\n42 (string)\n", b"42"),
            (b"1 0 obj\n42 <41>\n", b"42"),
            (b"1 0 obj\n42 7 Rx\n", b"Rx"),
            (b"1 0 obj\n42 7x Rx\n", b"7x"),
            (b"1 0 obj\n(s)\n5 0 obj\n", b"(s)"),
        ];
        for (input, last) in cases {
            let (result, to) = parse_indirect_extent(input, 0, &ParseCtx::default(), &|_| None);
            assert!(result.is_ok(), "{:?}", input.escape_ascii());
            let at = input.windows(last.len()).position(|w| w == last).unwrap();
            assert_eq!(to, at + last.len(), "{:?}", input.escape_ascii());
        }
    }

    #[test]
    fn depth_limit_errors_not_overflow() {
        // Run on a deliberately small stack: an implementation that recursed per nesting level
        // would overflow it long before 100,000 levels.
        let handle = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                for opener in [&b"["[..], b"<<", b"<</A ", b"[<</K "] {
                    let input = opener.repeat(100_000);
                    let err = parse_object(&input, 0, &ParseCtx::default()).unwrap_err();
                    assert_eq!(err.code(), ErrorCode::LimitExceeded);
                    assert!(matches!(
                        err,
                        Error::LimitExceeded {
                            limit: LimitKind::MaxNestingDepth,
                            max: 256,
                            ..
                        }
                    ));
                    // The error is reported where the 257th container opens.
                    let per_level = opener.len();
                    let expected = if per_level == 6 {
                        // `[<</K ` opens two containers per repetition.
                        128 * per_level
                    } else {
                        256 * per_level
                    };
                    assert_eq!(err.offset(), Some(expected as u64), "{opener:?}");
                }
                // Exactly at the limit is fine.
                let mut ok = b"[".repeat(256);
                ok.extend(b"]".repeat(256));
                assert!(parse_object(&ok, 0, &ParseCtx::default()).is_ok());
                let mut too_deep = b"[".repeat(257);
                too_deep.extend(b"]".repeat(257));
                assert!(parse_object(&too_deep, 0, &ParseCtx::default()).is_err());
                // A configured limit applies.
                let ctx =
                    ParseCtx::default().with_limits(Limits::default().with_max_nesting_depth(2));
                assert!(parse_object(b"[[1]]", 0, &ctx).is_ok());
                assert!(parse_object(b"[[[1]]]", 0, &ctx).is_err());
                // The limit also applies inside indirect objects.
                let mut obj = b"1 0 obj\n".to_vec();
                obj.extend(b"[".repeat(100_000));
                assert_eq!(
                    parse_indirect_at(&obj, 0, &ParseCtx::default(), &|_| None)
                        .unwrap_err()
                        .code(),
                    ErrorCode::LimitExceeded
                );
            })
            .unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn nesting_depth_is_clamped() {
        // `Object`'s derived Clone, Drop, PartialEq and Debug recurse once per level, so a depth
        // limit raised to 65,535 would let a file overflow the stack after a successful parse.
        // The parser clamps it to Limits::MAX_NESTING_DEPTH, whether it was set through the
        // setter or the public field.
        let raised = Limits {
            max_nesting_depth: u16::MAX,
            ..Limits::default()
        };
        assert_eq!(raised.effective_nesting_depth(), Limits::MAX_NESTING_DEPTH);
        assert_eq!(
            Limits::default()
                .with_max_nesting_depth(u16::MAX)
                .max_nesting_depth,
            Limits::MAX_NESTING_DEPTH
        );
        let max = usize::from(Limits::MAX_NESTING_DEPTH);
        let nested = |depth: usize| {
            let mut text = b"[".repeat(depth);
            text.extend(b"]".repeat(depth));
            text
        };
        // A 2 MiB thread (Rust's default for spawned threads) in a debug build.
        let handle = std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || {
                for limits in [raised, Limits::default().with_max_nesting_depth(u16::MAX)] {
                    let ctx = ParseCtx::default().with_limits(limits);
                    let err = parse_object(&nested(60_000), 0, &ctx).unwrap_err();
                    assert!(
                        matches!(
                            err,
                            Error::LimitExceeded {
                                limit: LimitKind::MaxNestingDepth,
                                max: 512,
                                ..
                            }
                        ),
                        "{err:?}"
                    );
                    assert!(parse_object(&nested(max + 1), 0, &ctx).is_err());
                    // The deepest object accepted survives every recursive operation.
                    let (deepest, _) = parse_object(&nested(max), 0, &ctx).unwrap();
                    let copy = deepest.clone();
                    assert_eq!(copy, deepest);
                    assert!(format!("{copy:?}").len() > max);
                    drop(copy);
                    drop(deepest);
                }
            })
            .unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn parse_budget_bounds_the_objects_built() {
        let value = std::mem::size_of::<Object>() as u64;
        let measure = |input: &[u8]| {
            let budget = ParseBudget::new(u64::MAX, LimitKind::ObjStmParsed, 0);
            let ctx = ParseCtx::default().with_budget(&budget);
            parse_object(input, 0, &ctx).unwrap();
            budget.used()
        };
        // Each value costs an Object; strings and names their bytes; dictionaries their map
        // and each entry its overhead.
        assert_eq!(measure(b"0"), value);
        assert_eq!(measure(b"[0 1 2]"), 4 * value);
        assert_eq!(measure(b"(abcd)"), value + 4);
        assert_eq!(measure(b"5 0 R"), value);
        assert_eq!(
            measure(b"<< /Ab 1 >>"),
            3 * value + DICT_WEIGHT + ENTRY_WEIGHT + 2
        );
        // Over the budget: the parse stops there with the limit the budget stands for.
        let input = format!("[{}]", "0 ".repeat(10_000));
        let budget = ParseBudget::new(100 * value, LimitKind::ObjStmParsed, 12_345);
        let ctx = ParseCtx::default().with_budget(&budget);
        let err = parse_object(input.as_bytes(), 0, &ctx).unwrap_err();
        assert!(
            matches!(
                err,
                Error::LimitExceeded {
                    limit: LimitKind::ObjStmParsed,
                    max: 12_345,
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(budget.used(), 101 * value);
        assert!(format!("{ctx:?}").contains("budget: Some"));
        // Without a budget nothing is counted.
        assert_eq!(parse(input.as_bytes()).as_array().unwrap().len(), 10_000);
    }

    #[test]
    fn finished_arrays_keep_no_spare_capacity() {
        let input = format!("[[{}] << /A [1 2 3 4 5] >>]", "7 ".repeat(1000));
        let obj = parse(input.as_bytes());
        let outer = obj.as_array().unwrap();
        let inner = outer[0].as_array().unwrap();
        assert_eq!(inner.len(), 1000);
        let Object::Array(v) = &outer[0] else {
            unreachable!()
        };
        assert_eq!(v.capacity(), 1000);
        let Object::Array(v) = &obj else {
            unreachable!()
        };
        assert_eq!(v.capacity(), 2);
    }

    #[test]
    fn wide_arrays_are_fine() {
        let mut input = b"[".to_vec();
        for i in 0..100_000 {
            input.extend(format!("{i} ").bytes());
        }
        input.push(b']');
        let obj = parse(&input);
        assert_eq!(obj.as_array().unwrap().len(), 100_000);
    }

    #[test]
    fn parse_ctx_accessors() {
        let ctx = ParseCtx::new(Limits::default().with_max_ref_chain(3), Strictness::Strict);
        assert_eq!(ctx.limits().max_ref_chain, 3);
        assert_eq!(ctx.strictness(), Strictness::Strict);
        assert!(ctx.diagnostics().is_none());
        assert!(format!("{ctx:?}").contains("Strict"));
        assert!(
            ctx.recover(DiagnosticKind::Other, None, || "x".into())
                .is_err()
        );
        let seen = RefCell::new(0);
        let sink = |_d: Diagnostic| *seen.borrow_mut() += 1;
        let ctx = ParseCtx::default().with_diagnostics(&sink);
        ctx.report(Diagnostic::new(DiagnosticKind::Other, None, "x"));
        assert!(
            ctx.recover(DiagnosticKind::Other, Some(1), || "y".into())
                .is_ok()
        );
        assert_eq!(*seen.borrow(), 2);
    }

    // ---- indirect objects -------------------------------------------------------------------

    struct Parsed {
        obj: IndirectObject,
        diags: Vec<DiagnosticKind>,
    }

    fn indirect(input: &[u8], lengths: &dyn Fn(ObjectId) -> Option<i64>) -> Parsed {
        let diags = RefCell::new(Vec::new());
        let sink = |d: Diagnostic| diags.borrow_mut().push(d.kind);
        let ctx = ParseCtx::default().with_diagnostics(&sink);
        let obj = parse_indirect_at(input, 0, &ctx, lengths)
            .unwrap_or_else(|e| panic!("{:?}: {e}", input.escape_ascii()));
        Parsed {
            obj,
            diags: diags.into_inner(),
        }
    }

    fn indirect_strict(input: &[u8]) -> Result<IndirectObject> {
        parse_indirect_at(
            input,
            0,
            &ParseCtx::default().with_strictness(Strictness::Strict),
            &|_| Some(5),
        )
    }

    fn data<'b>(input: &'b [u8], obj: &IndirectObject) -> &'b [u8] {
        let range = obj.stream_data_range.clone().unwrap();
        &input[range.start as usize..range.end as usize]
    }

    #[test]
    fn indirect_plain_objects() {
        let input = b"12 3 obj\n<< /A 1 >>\nendobj\n13 0 obj";
        let p = indirect(input, &|_| None);
        assert_eq!(p.obj.id, ObjectId::new(12, 3));
        assert_eq!(p.obj.object, dict(vec![("A", Object::Int(1))]));
        assert_eq!(p.obj.stream_data_range, None);
        assert_eq!(p.obj.end, 26);
        assert!(p.diags.is_empty());

        // From an offset, with comments around.
        let input = b"junk %c\n 4 0 obj % header\n (s) % value\n endobj";
        let obj = parse_indirect_at(input, 4, &ParseCtx::default(), &|_| None).unwrap();
        assert_eq!(obj.id, ObjectId::new(4, 0));
        assert_eq!(obj.object, Object::literal_string("s"));
        assert_eq!(obj.end, input.len());

        // A reference as the value.
        let p = indirect(b"1 0 obj 2 0 R endobj", &|_| None);
        assert_eq!(p.obj.object, r(2, 0));
        assert_eq!(p.obj.end, 20);
        // `endobj` glued to the value.
        let p = indirect(b"1 0 obj<</A 1>>endobj", &|_| None);
        assert_eq!(p.obj.end, 21);
        assert!(p.diags.is_empty());
    }

    #[test]
    fn missing_endobj_is_tolerated() {
        let input = b"1 0 obj\n<< /A 1 >>\n2 0 obj\n<< >>\nendobj";
        let p = indirect(input, &|_| None);
        assert_eq!(p.obj.object, dict(vec![("A", Object::Int(1))]));
        assert_eq!(p.obj.end, 18);
        assert_eq!(p.diags, [DiagnosticKind::MissingEndobj]);
        let p = indirect(b"1 0 obj 5", &|_| None);
        assert_eq!(p.obj.object, Object::Int(5));
        assert_eq!(p.obj.end, 9);
        assert_eq!(p.diags, [DiagnosticKind::MissingEndobj]);
        assert!(indirect_strict(input).is_err());
    }

    #[test]
    fn empty_object_is_null() {
        let p = indirect(b"1 0 obj endobj", &|_| None);
        assert_eq!(p.obj.object, Object::Null);
        assert_eq!(p.obj.end, 14);
        assert_eq!(p.diags, [DiagnosticKind::EmptyObject]);
        assert!(indirect_strict(b"1 0 obj endobj").is_err());
    }

    #[test]
    fn bad_headers() {
        let cases: Vec<&[u8]> = vec![
            b"",
            b"1 0",
            b"1 0 R",
            b"x 0 obj",
            b"-1 0 obj 1 endobj",
            b"1 65536 obj 1 endobj",
            b"4294967296 0 obj 1 endobj",
            b"1 0 obj",
            b"1 0 obj )",
        ];
        for input in cases {
            let err = parse_indirect_at(input, 0, &ParseCtx::default(), &|_| None).unwrap_err();
            assert_eq!(err.code(), ErrorCode::Syntax, "{:?}", input.escape_ascii());
        }
        assert_eq!(
            parse_indirect_header(b" 7 1 obj", 0, &ParseCtx::default()).unwrap(),
            (ObjectId::new(7, 1), 8)
        );
    }

    #[test]
    fn stream_with_correct_length() {
        for eol in [&b"\r\n"[..], b"\n"] {
            let mut input = b"5 0 obj\n<< /Length 10 >>\nstream".to_vec();
            input.extend_from_slice(eol);
            let start = input.len();
            input.extend_from_slice(b"0123456789\nendstream\nendobj\n");
            let p = indirect(&input, &|_| None);
            assert_eq!(
                p.obj.stream_data_range,
                Some(start as u64..start as u64 + 10)
            );
            assert_eq!(data(&input, &p.obj), b"0123456789");
            assert_eq!(p.obj.end, input.len() - 1);
            assert!(p.diags.is_empty(), "{:?}", p.diags);
            let stream = p.obj.object.as_stream().unwrap();
            assert_eq!(stream.dict.get_int(b"Length"), Some(10));
            assert_eq!(
                stream.data,
                StreamData::Source(start as u64..start as u64 + 10)
            );
        }
        // Data that contains `endstream` is fine when /Length is right.
        let input = b"1 0 obj<</Length 9>>stream\nendstream\nendstream\nendobj";
        let p = indirect(input, &|_| None);
        assert_eq!(data(input, &p.obj), b"endstream");
        assert!(p.diags.is_empty());
        // No EOL before endstream, and an empty stream.
        let input = b"1 0 obj<</Length 3>>stream\nabcendstream endobj";
        assert_eq!(data(input, &indirect(input, &|_| None).obj), b"abc");
        let input = b"1 0 obj<</Length 0>>stream\n\nendstream endobj";
        assert_eq!(data(input, &indirect(input, &|_| None).obj), b"");
    }

    #[test]
    fn stream_length_wrong_recovers() {
        // Too short, too long, past the end of the file, negative, and not a number.
        for length in ["4", "15", "999999", "-3", "(x)", "4.0"] {
            let input = format!(
                "1 0 obj\n<< /Length {length} >>\nstream\r\n0123456789\r\nendstream\nendobj\n2 0 obj"
            );
            let input = input.as_bytes();
            let p = indirect(input, &|_| None);
            assert_eq!(data(input, &p.obj), b"0123456789", "/Length {length}");
            assert_eq!(p.diags, [DiagnosticKind::StreamLength], "/Length {length}");
            assert_eq!(&input[p.obj.end - 6..p.obj.end], b"endobj");
            assert!(indirect_strict(input).is_err(), "/Length {length}");
        }
        // Missing /Length.
        let input = b"1 0 obj<<>>stream\nabc\nendstream endobj";
        let p = indirect(input, &|_| None);
        assert_eq!(data(input, &p.obj), b"abc");
        assert_eq!(p.diags, [DiagnosticKind::StreamLength]);
    }

    #[test]
    fn stream_length_indirect() {
        let input = b"1 0 obj<</Length 9 0 R>>stream\nabcde\nendstream endobj";
        let resolver = |id: ObjectId| (id == ObjectId::new(9, 0)).then_some(5);
        let p = indirect(input, &resolver);
        assert_eq!(data(input, &p.obj), b"abcde");
        assert!(p.diags.is_empty());
        // Unresolvable (missing, cycle, ...): scan for endstream.
        let p = indirect(input, &|_| None);
        assert_eq!(data(input, &p.obj), b"abcde");
        assert_eq!(p.diags, [DiagnosticKind::StreamLength]);
        // Resolved to a wrong or negative value: scan too.
        for wrong in [2, -1, i64::MAX] {
            let p = indirect(input, &|_| Some(wrong));
            assert_eq!(data(input, &p.obj), b"abcde", "{wrong}");
            assert_eq!(p.diags, [DiagnosticKind::StreamLength]);
        }
    }

    #[test]
    fn stream_keyword_eol_variants() {
        // Lone CR (trap #1): accepted with a diagnostic.
        let input = b"1 0 obj<</Length 3>>stream\rabc\nendstream endobj";
        let p = indirect(input, &|_| None);
        assert_eq!(data(input, &p.obj), b"abc");
        assert_eq!(p.diags, [DiagnosticKind::StreamKeywordEol]);
        // Spaces before the EOL.
        let input = b"1 0 obj<</Length 3>>stream  \r\nabc\nendstream endobj";
        let p = indirect(input, &|_| None);
        assert_eq!(data(input, &p.obj), b"abc");
        assert_eq!(p.diags, [DiagnosticKind::StreamKeywordEol]);
        // No EOL at all.
        let input = b"1 0 obj<</Length 3>>streamabc\nendstream endobj";
        let p = indirect(input, &|_| None);
        assert_eq!(data(input, &p.obj), b"abc");
        assert_eq!(p.diags, [DiagnosticKind::StreamKeywordEol]);
        assert!(indirect_strict(b"1 0 obj<</Length 3>>stream\rabc\nendstream endobj").is_err());
        // Comments between the dictionary and `stream`.
        let input = b"1 0 obj<</Length 3>> % c\nstream\nabc\nendstream endobj";
        let p = indirect(input, &|_| None);
        assert_eq!(data(input, &p.obj), b"abc");
        assert!(p.diags.is_empty());
    }

    #[test]
    fn stream_without_endstream() {
        // Valid /Length but no endstream (truncated file): keep the declared data.
        let input = b"1 0 obj<</Length 3>>stream\nabcdef";
        let p = indirect(input, &|_| None);
        assert_eq!(data(input, &p.obj), b"abc");
        assert_eq!(
            p.diags,
            [
                DiagnosticKind::MissingEndstream,
                DiagnosticKind::MissingEndobj
            ]
        );
        // No usable /Length: up to the next endobj.
        let input = b"1 0 obj<<>>stream\nabc\nendobj";
        let p = indirect(input, &|_| None);
        assert_eq!(data(input, &p.obj), b"abc");
        assert_eq!(p.obj.end, input.len());
        assert_eq!(p.diags, [DiagnosticKind::MissingEndstream]);
        // Nothing at all: up to the end of the buffer.
        let input = b"1 0 obj<<>>stream\nabc";
        let p = indirect(input, &|_| None);
        assert_eq!(data(input, &p.obj), b"abc");
        assert_eq!(p.obj.end, input.len());
        // `stream` at the very end.
        let input = b"1 0 obj<<>>stream";
        let p = indirect(input, &|_| None);
        assert_eq!(data(input, &p.obj), b"");
    }

    /// A [`KeywordIndex`] built naively for tests, plus a call counter.
    struct TestIndex {
        endstream: Vec<usize>,
        endobj: Vec<usize>,
        calls: std::cell::Cell<usize>,
    }

    impl TestIndex {
        fn of(bytes: &[u8]) -> Self {
            let all = |needle: &[u8]| {
                (0..bytes.len())
                    .filter(|&i| bytes[i..].starts_with(needle))
                    .collect()
            };
            TestIndex {
                endstream: all(b"endstream"),
                endobj: all(b"endobj"),
                calls: std::cell::Cell::new(0),
            }
        }
    }

    impl KeywordIndex for TestIndex {
        fn next_endstream(&self, from: usize) -> Option<usize> {
            self.calls.set(self.calls.get() + 1);
            self.endstream.iter().copied().find(|&p| p >= from)
        }
        fn next_endobj(&self, from: usize) -> Option<usize> {
            self.calls.set(self.calls.get() + 1);
            self.endobj.iter().copied().find(|&p| p >= from)
        }
    }

    #[test]
    fn keyword_index_is_used_for_recovery() {
        let input = b"1 0 obj<</Length 99>>stream\nabcde\nendstream endobj";
        let index = TestIndex::of(input);
        let ctx = ParseCtx::default().with_keyword_index(&index);
        assert!(format!("{ctx:?}").contains("keyword_index: true"));
        let obj = parse_indirect_at(input, 0, &ctx, &|_| None).unwrap();
        assert_eq!(data(input, &obj), b"abcde");
        assert_eq!(index.calls.get(), 1);
        // No endstream: the index answers `None` for it and then finds `endobj`.
        let input = b"1 0 obj<<>>stream\nabc\nendobj";
        let index = TestIndex::of(input);
        let ctx = ParseCtx::default().with_keyword_index(&index);
        let obj = parse_indirect_at(input, 0, &ctx, &|_| None).unwrap();
        assert_eq!(data(input, &obj), b"abc");
        assert_eq!(index.calls.get(), 2);
        // A correct length never consults the index.
        let input = b"1 0 obj<</Length 3>>stream\nabc\nendstream endobj";
        let index = TestIndex::of(input);
        let ctx = ParseCtx::default().with_keyword_index(&index);
        parse_indirect_at(input, 0, &ctx, &|_| None).unwrap();
        assert_eq!(index.calls.get(), 0);
    }

    #[test]
    fn foreign_keyword_index_is_never_unsound() {
        // An index for another buffer points at positions that do not hold the keyword (or lie
        // before the data); the parser falls back to a plain search.
        struct Wrong;
        impl KeywordIndex for Wrong {
            fn next_endstream(&self, _from: usize) -> Option<usize> {
                Some(3)
            }
            fn next_endobj(&self, _from: usize) -> Option<usize> {
                Some(usize::MAX)
            }
        }
        let ctx = ParseCtx::default().with_keyword_index(&Wrong);
        let input = b"1 0 obj<</Length 99>>stream\nabcde\nendstream endobj";
        let obj = parse_indirect_at(input, 0, &ctx, &|_| None).unwrap();
        assert_eq!(data(input, &obj), b"abcde");
        let input = b"1 0 obj<<>>stream\nabc";
        struct NoEndstreamWrongEndobj;
        impl KeywordIndex for NoEndstreamWrongEndobj {
            fn next_endstream(&self, _from: usize) -> Option<usize> {
                None
            }
            fn next_endobj(&self, _from: usize) -> Option<usize> {
                Some(1)
            }
        }
        let ctx = ParseCtx::default().with_keyword_index(&NoEndstreamWrongEndobj);
        let obj = parse_indirect_at(input, 0, &ctx, &|_| None).unwrap();
        assert_eq!(data(input, &obj), b"abc");
        assert!(ctx.keyword_index().is_some());
    }

    #[test]
    fn stream_after_non_dictionary() {
        let input = b"1 0 obj [1] stream\nabc\nendstream endobj";
        let p = indirect(input, &|_| None);
        assert_eq!(p.obj.object, Object::Array(vec![Object::Int(1)]));
        assert_eq!(p.obj.stream_data_range, None);
        assert_eq!(p.diags, [DiagnosticKind::StreamWithoutDict]);
        assert!(indirect_strict(input).is_err());
    }

    #[test]
    fn unclosed_dictionary_before_stream() {
        let input = b"1 0 obj << /Length 3 stream\nabc\nendstream\nendobj";
        let p = indirect(input, &|_| None);
        assert_eq!(data(input, &p.obj), b"abc");
        assert_eq!(p.diags, [DiagnosticKind::UnclosedContainer]);
    }

    /// Deterministic pseudo-random inputs never panic, in both strictness modes.
    #[test]
    fn random_input_never_panics() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        const PIECES: &[&[u8]] = &[
            b"<<",
            b">>",
            b"[",
            b"]",
            b"(",
            b")",
            b"<",
            b">",
            b"/N",
            b" ",
            b"\n",
            b"\r",
            b"1",
            b"0",
            b"-",
            b".",
            b"R",
            b"obj",
            b"endobj",
            b"stream",
            b"endstream",
            b"/Length",
            b"%",
            b"\\",
            b"true",
            b"null",
            b"x",
            b"#",
            b"{",
        ];
        for _ in 0..4000 {
            let mut input = b"1 0 obj ".to_vec();
            for _ in 0..next() % 40 {
                let r = next();
                if r % 7 == 0 {
                    input.push((r >> 16) as u8);
                } else {
                    input.extend_from_slice(PIECES[(r >> 8) as usize % PIECES.len()]);
                }
            }
            for strictness in [Strictness::Lenient, Strictness::Strict] {
                let ctx = ParseCtx::default().with_strictness(strictness);
                if let Ok((_, end)) = parse_object(&input, 8, &ctx) {
                    assert!(end <= input.len());
                }
                if let Ok(obj) = parse_indirect_at(&input, 0, &ctx, &|_| Some(3)) {
                    assert!(obj.end <= input.len());
                    if let Some(range) = obj.stream_data_range {
                        assert!(range.start <= range.end && range.end <= input.len() as u64);
                    }
                }
            }
        }
    }
}

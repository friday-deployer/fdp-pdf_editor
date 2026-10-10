//! The PDF lexer (ISO 32000-2 §7.2 and the token rules of §7.3).
//!
//! [`Lexer`] turns bytes into [`Token`]s with their byte positions. It handles every token form of
//! §7.3: numbers (§7.3.3, without exponents), literal strings with balanced parentheses, escapes,
//! octal codes and line continuations (§7.3.4.2), hexadecimal strings with white-space and an odd
//! digit count (§7.3.4.3), names with `#xx` escapes (§7.3.5), the delimiters `[ ] << >> { }`,
//! comments (§7.2.4, skipped like white-space) and keywords (`true`, `obj`, `R`, `stream`, ...).
//!
//! It is lenient in the ways real files require (ARCHITECTURE §A.10 trap #2), and records a
//! [`Diagnostic`] for each repair; in [`Strictness::Strict`] mode repairs are errors instead:
//! - `--5` (and any run of several signs) is read as `-5` if any sign is `-`, otherwise `+5`.
//! - A character in a hex string that is neither a hex digit nor white-space is skipped. (The
//!   crate-internal coverage parses of `repair::definitions` end the string there instead, with
//!   an error, as qpdf does.)
//! - A `#` in a name that is not followed by two hex digits is kept as a literal `#`.
//!
//! The lexer never panics, never recurses and allocates at most the decoded size of one token,
//! bounded by [`Limits::max_string_len`](crate::Limits::max_string_len).

use std::borrow::Cow;

use crate::diag::{Diagnostic, DiagnosticKind, DiagnosticSink, Strictness};
use crate::error::{Error, Result};
use crate::limits::{LimitKind, Limits};
use crate::parser::ParseCtx;

/// Whether `b` is a PDF white-space character (§7.2.3, Table 1): NUL, HT, LF, FF, CR or SP.
pub const fn is_whitespace(b: u8) -> bool {
    matches!(b, 0x00 | 0x09 | 0x0A | 0x0C | 0x0D | 0x20)
}

/// Whether `b` is a PDF delimiter character (§7.2.3, Table 2): `( ) < > [ ] { } / %`.
pub const fn is_delimiter(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

/// Whether `b` is a PDF regular character: neither white-space nor a delimiter (§7.2.3).
pub const fn is_regular(b: u8) -> bool {
    !is_whitespace(b) && !is_delimiter(b)
}

/// The value of an ASCII hex digit.
pub(crate) const fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Returns the position of the first byte at or after `pos` that is neither white-space nor part
/// of a comment (§7.2.4). Returns `data.len()` at the end of the data.
pub fn skip_whitespace_and_comments(data: &[u8], pos: usize) -> usize {
    let mut i = pos;
    while let Some(&b) = data.get(i) {
        if is_whitespace(b) {
            i += 1;
        } else if b == b'%' {
            // A comment runs to the end of the line; the EOL itself is white-space.
            i += 1;
            while let Some(&c) = data.get(i) {
                if c == b'\r' || c == b'\n' {
                    break;
                }
                i += 1;
            }
        } else {
            break;
        }
    }
    i.min(data.len())
}

/// Returns the position of the first occurrence of `needle` in `haystack` at or after `from`.
pub(crate) fn find_bytes(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let first = *needle.first()?;
    let mut i = from;
    while let Some(rest) = haystack.get(i..) {
        let at = i + rest.iter().position(|&b| b == first)?;
        if haystack.get(at..at + needle.len()) == Some(needle) {
            return Some(at);
        }
        i = at + 1;
    }
    None
}

/// How many decoded bytes of a literal string a lexer with a [`StringEnds`] index reads before
/// it asks whether the string closes at all.
pub(crate) const LONG_STRING: usize = 4096;

/// Tells a lexer whether a literal string closes before the end of its data (crate-internal:
/// the parses of `repair::definitions` attach one through [`ParseCtx::with_string_ends`]).
///
/// Without it, a string that never closes is read to the end of the data before it fails. With
/// it, a lexer that has read [`LONG_STRING`] bytes of a string asks once, and stops there when
/// the string never closes. The outcome is the same (an error), but the parse has read only the
/// first few kilobytes of the string: `repair::definitions` takes the object headers in what a
/// failed parse read, unparsed, so one unterminated string takes only those, not every header
/// after it.
pub(crate) trait StringEnds {
    /// Whether the literal string the lexer is reading in `data` closes before the end of the
    /// data: the next byte to read is `at` (not escaped) and `depth` (at least 1) parentheses
    /// are open. `None` when the index does not describe `data`.
    fn closes(&self, data: &[u8], at: usize, depth: usize) -> Option<bool>;
}

/// How many bytes one entry of the lowest level of a [`ParenIndex`] summarises.
const PAREN_BLOCK: usize = 4096;
/// How many entries of one level of a [`ParenIndex`] one entry of the next level summarises.
const PAREN_FANOUT: usize = 64;

/// The parentheses of one buffer, summarised by blocks: a [`StringEnds`] index, built on first
/// use by one pass over the buffer, in about 1/256 of its size.
///
/// Inside a literal string a backslash escapes the next byte (§7.3.4.2: `\(`, `\)`, `\\`,
/// `\ddd`, a line continuation), so whether a byte is escaped depends only on the run of
/// backslashes just before it, which never reaches back past the string's opening `(`. Every
/// literal string therefore sees the same unescaped parentheses after its start, and its depth
/// is the running sum of +1 for each unescaped `(` and -1 for each unescaped `)`. The index keeps
/// that sum's total and lowest prefix for each block of [`PAREN_BLOCK`] bytes, and for each group
/// of [`PAREN_FANOUT`] entries of a level: a string closes inside a span when its depth plus the
/// span's lowest prefix reaches 0. An answer costs at most [`PAREN_BLOCK`] bytes plus
/// [`PAREN_FANOUT`] entries per level.
pub(crate) struct ParenIndex<'a> {
    data: &'a [u8],
    /// [`PAREN_BLOCK`] and [`PAREN_FANOUT`] (smaller in tests, for many levels on little data).
    block: usize,
    fanout: usize,
    levels: std::cell::OnceCell<Vec<Vec<ParenSpan>>>,
}

/// The parentheses of a span of bytes: the sum of their +1 and -1, and the lowest sum of a
/// prefix of the span (0 for the empty prefix).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ParenSpan {
    total: i64,
    low: i64,
}

impl ParenSpan {
    /// This span followed by `next`.
    fn then(self, next: ParenSpan) -> ParenSpan {
        ParenSpan {
            total: self.total + next.total,
            low: self.low.min(self.total + next.low),
        }
    }
}

impl<'a> ParenIndex<'a> {
    /// An index of `data` (built when it is first asked).
    pub(crate) fn new(data: &'a [u8]) -> Self {
        ParenIndex {
            data,
            block: PAREN_BLOCK,
            fanout: PAREN_FANOUT,
            levels: std::cell::OnceCell::new(),
        }
    }

    /// An index of `data` with blocks of `block` bytes and groups of `fanout` entries.
    #[cfg(test)]
    fn with_shape(data: &'a [u8], block: usize, fanout: usize) -> Self {
        ParenIndex {
            block: block.max(1),
            fanout: fanout.max(2),
            ..ParenIndex::new(data)
        }
    }

    fn levels(&self) -> &[Vec<ParenSpan>] {
        self.levels.get_or_init(|| {
            let mut level = Vec::with_capacity(self.data.len().div_ceil(self.block));
            let mut escaped = false;
            for block in self.data.chunks(self.block) {
                let mut span = ParenSpan::default();
                for &b in block {
                    let delta = match b {
                        _ if escaped => {
                            escaped = false;
                            0
                        }
                        b'\\' => {
                            escaped = true;
                            0
                        }
                        b'(' => 1,
                        b')' => -1,
                        _ => 0,
                    };
                    span.total += delta;
                    span.low = span.low.min(span.total);
                }
                level.push(span);
            }
            let mut levels = vec![level];
            while let Some(below) = levels.last().filter(|l| l.len() > self.fanout) {
                let up = below
                    .chunks(self.fanout)
                    .map(|group| {
                        group
                            .iter()
                            .fold(ParenSpan::default(), |acc, &span| acc.then(span))
                    })
                    .collect();
                levels.push(up);
            }
            levels
        })
    }
}

impl StringEnds for ParenIndex<'_> {
    fn closes(&self, data: &[u8], at: usize, depth: usize) -> Option<bool> {
        if !std::ptr::eq(data, self.data) {
            return None;
        }
        let mut depth = i64::try_from(depth).ok()?;
        // The rest of the block of `at`, byte by byte.
        let block = at / self.block;
        let end = block
            .saturating_add(1)
            .saturating_mul(self.block)
            .min(data.len());
        let mut escaped = false;
        for &b in data.get(at..end).unwrap_or_default() {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(true);
                    }
                }
                _ => {}
            }
        }
        // Then whole spans: the rest of each group, one level up when a group is done. (A
        // backslash at the end of the block escapes the next block's first byte, as the index
        // counted it.)
        let levels = self.levels();
        let mut next = block + 1;
        for (k, level) in levels.iter().enumerate() {
            let top = k + 1 == levels.len();
            while let Some(span) = level.get(next) {
                if !top && next.is_multiple_of(self.fanout) {
                    break;
                }
                if depth + span.low <= 0 {
                    return Some(true);
                }
                depth += span.total;
                next += 1;
            }
            if next >= level.len() {
                return Some(false);
            }
            next /= self.fanout;
        }
        Some(false)
    }
}

/// A token and its position in the input.
#[derive(Clone, Debug, PartialEq)]
pub struct Token<'a> {
    /// What was read.
    pub kind: TokenKind<'a>,
    /// Byte offset of the first byte of the token (for strings and names, the `(`, `<` or `/`).
    pub start: usize,
    /// Byte offset just past the last byte of the token.
    pub end: usize,
}

/// The kinds of token (§7.2, §7.3).
#[derive(Clone, Debug, PartialEq)]
pub enum TokenKind<'a> {
    /// An integer (§7.3.3). Integers outside the `i64` range are read as [`TokenKind::Real`].
    Integer(i64),
    /// A real number (§7.3.3); always finite.
    Real(f64),
    /// A literal string `(...)`, decoded (§7.3.4.2). Borrowed when it contains no escape and
    /// no CR.
    LiteralString(Cow<'a, [u8]>),
    /// A hexadecimal string `<...>`, decoded (§7.3.4.3).
    HexString(Vec<u8>),
    /// A name, decoded and without the `/` (§7.3.5). Borrowed when it contains no `#`.
    Name(Cow<'a, [u8]>),
    /// `[`
    ArrayStart,
    /// `]`
    ArrayEnd,
    /// `<<`
    DictStart,
    /// `>>`
    DictEnd,
    /// `{` (PostScript calculator functions, §7.10.5)
    BraceOpen,
    /// `}`
    BraceClose,
    /// Any other run of regular characters: `true`, `false`, `null`, `obj`, `endobj`, `R`,
    /// `stream`, `xref`, an operator in a content stream, or garbage.
    Keyword(&'a [u8]),
}

/// A PDF tokenizer over a byte slice.
///
/// ```
/// use folioxide_syntax::{Lexer, TokenKind};
///
/// let mut lexer = Lexer::new(b"<< /Type /Page >>", 0);
/// let tok = lexer.next_token()?.unwrap();
/// assert_eq!((tok.kind, tok.start, tok.end), (TokenKind::DictStart, 0, 2));
/// let tok = lexer.next_token()?.unwrap();
/// assert_eq!(tok.kind, TokenKind::Name(b"Type"[..].into()));
/// # Ok::<(), folioxide_syntax::Error>(())
/// ```
///
/// The lexer is also an iterator over `Result<Token>`; the iterator stops after the first error.
/// [`Lexer::next_token`] can be called again after an error and resumes after the bad input.
pub struct Lexer<'a> {
    data: &'a [u8],
    pos: usize,
    strictness: Strictness,
    max_string_len: usize,
    sink: Option<&'a dyn DiagnosticSink>,
    /// Whether literal strings close, for parses that attach an index (see [`StringEnds`]).
    strings: Option<&'a dyn StringEnds>,
    /// Whether a hexadecimal string ends, with an error, at its first invalid byte (see
    /// [`ParseCtx::with_hex_ending_at_invalid_byte`]).
    hex_ends_at_invalid: bool,
    fused: bool,
}

impl std::fmt::Debug for Lexer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lexer")
            .field("len", &self.data.len())
            .field("pos", &self.pos)
            .field("strictness", &self.strictness)
            .field("max_string_len", &self.max_string_len)
            .finish_non_exhaustive()
    }
}

impl<'a> Lexer<'a> {
    /// Creates a lenient lexer over `data`, starting at byte `start`, with the default
    /// [`Limits`] and no diagnostics sink. A `start` past the end is treated as the end.
    pub fn new(data: &'a [u8], start: usize) -> Self {
        Lexer {
            data,
            pos: start.min(data.len()),
            strictness: Strictness::Lenient,
            max_string_len: Limits::DEFAULT.max_string_len,
            sink: None,
            strings: None,
            hex_ends_at_invalid: false,
            fused: false,
        }
    }

    /// Creates a lexer that takes its strictness, limits and diagnostics sink from `ctx`.
    pub fn with_ctx(data: &'a [u8], start: usize, ctx: &ParseCtx<'a>) -> Self {
        Lexer {
            data,
            pos: start.min(data.len()),
            strictness: ctx.strictness(),
            max_string_len: ctx.limits().max_string_len,
            sink: ctx.diagnostics(),
            strings: ctx.string_ends(),
            hex_ends_at_invalid: ctx.hex_ends_at_invalid_byte(),
            fused: false,
        }
    }

    /// Sets the strictness.
    #[must_use]
    pub fn with_strictness(mut self, strictness: Strictness) -> Self {
        self.strictness = strictness;
        self
    }

    /// Sets the maximum decoded length of a string or name token.
    #[must_use]
    pub fn with_max_string_len(mut self, max: usize) -> Self {
        self.max_string_len = max;
        self
    }

    /// Sets the sink that receives diagnostics for lenient repairs.
    #[must_use]
    pub fn with_diagnostics(mut self, sink: &'a dyn DiagnosticSink) -> Self {
        self.sink = Some(sink);
        self
    }

    /// The input.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The current byte offset: where the next token (or white-space before it) starts.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Moves to byte offset `pos` (clamped to the end of the data).
    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos.min(self.data.len());
        self.fused = false;
    }

    /// Skips white-space and comments; afterwards [`Lexer::position`] is at the next token.
    pub fn skip_whitespace(&mut self) {
        self.pos = skip_whitespace_and_comments(self.data, self.pos);
    }

    /// Whether only white-space and comments remain.
    pub fn is_at_end(&self) -> bool {
        skip_whitespace_and_comments(self.data, self.pos) >= self.data.len()
    }

    /// Reads the next token, or returns `Ok(None)` at the end of the data.
    ///
    /// On error the position moves past the offending input, so lexing can resume.
    pub fn next_token(&mut self) -> Result<Option<Token<'a>>> {
        self.skip_whitespace();
        let start = self.pos;
        let Some(&b) = self.data.get(start) else {
            return Ok(None);
        };
        let kind = match b {
            b'[' => self.single(TokenKind::ArrayStart),
            b']' => self.single(TokenKind::ArrayEnd),
            b'{' => self.single(TokenKind::BraceOpen),
            b'}' => self.single(TokenKind::BraceClose),
            b'<' => {
                if self.data.get(start + 1) == Some(&b'<') {
                    self.pos = start + 2;
                    TokenKind::DictStart
                } else {
                    self.lex_hex_string()?
                }
            }
            b'>' => {
                if self.data.get(start + 1) == Some(&b'>') {
                    self.pos = start + 2;
                    TokenKind::DictEnd
                } else {
                    self.pos = start + 1;
                    return Err(Error::syntax(start as u64, "unexpected `>`"));
                }
            }
            b'(' => self.lex_literal_string()?,
            b')' => {
                self.pos = start + 1;
                return Err(Error::syntax(start as u64, "unbalanced `)`"));
            }
            b'/' => self.lex_name()?,
            _ => self.lex_regular()?,
        };
        Ok(Some(Token {
            kind,
            start,
            end: self.pos,
        }))
    }

    fn single(&mut self, kind: TokenKind<'a>) -> TokenKind<'a> {
        self.pos += 1;
        kind
    }

    /// Records a repair (lenient) or fails (strict).
    fn recover(
        &self,
        kind: DiagnosticKind,
        offset: usize,
        message: impl FnOnce() -> String,
    ) -> Result<()> {
        match self.strictness {
            Strictness::Strict => Err(Error::syntax(offset as u64, message())),
            Strictness::Lenient => {
                if let Some(sink) = self.sink {
                    sink.report(Diagnostic::new(kind, Some(offset as u64), message()));
                }
                Ok(())
            }
        }
    }

    /// Fails with `LimitExceeded` if a token decoded so far to `len` bytes is too long; `scan` is
    /// the current scan position, where lexing resumes after the error.
    fn check_len(&mut self, len: usize, start: usize, scan: usize) -> Result<()> {
        if len > self.max_string_len {
            self.pos = scan.max(start + 1).min(self.data.len());
            Err(Error::limit(
                LimitKind::MaxStringLen,
                self.max_string_len as u64,
                Some(start as u64),
            ))
        } else {
            Ok(())
        }
    }

    /// Gives up on the literal string that starts at `start` once it has run to [`LONG_STRING`]
    /// decoded bytes, when the lexer's [`StringEnds`] index says that it never closes: reading on
    /// to the end of the data would fail all the same. `at` is the next byte to read and `depth`
    /// the parentheses open there. The position stays at `at`, where reading stopped (as for a
    /// string that is too long), so that it tells how far the lexer read.
    fn check_closes(&mut self, len: usize, start: usize, at: usize, depth: usize) -> Result<()> {
        if len == LONG_STRING
            && let Some(index) = self.strings
            && index.closes(self.data, at, depth) == Some(false)
        {
            self.pos = at;
            return Err(Error::syntax(
                at as u64,
                format!(
                    "the literal string at byte {start} is not closed before the end of the data"
                ),
            ));
        }
        Ok(())
    }

    /// Literal string, §7.3.4.2. `self.pos` is at the opening `(`.
    fn lex_literal_string(&mut self) -> Result<TokenKind<'a>> {
        let start = self.pos;
        let body = start + 1;
        let mut i = body;
        let mut depth = 1usize;
        // `None` while the decoded string equals the raw bytes `data[body..i]`.
        let mut owned: Option<Vec<u8>> = None;
        let mut len = 0usize;
        loop {
            let Some(&c) = self.data.get(i) else {
                self.pos = self.data.len();
                return Err(Error::eof(self.data.len() as u64, "literal string"));
            };
            match c {
                b'(' => {
                    depth += 1;
                    push(&mut owned, c);
                    i += 1;
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    push(&mut owned, c);
                    i += 1;
                }
                b'\\' => {
                    let buf = owned.get_or_insert_with(|| {
                        self.data
                            .get(body..i)
                            .map(<[u8]>::to_vec)
                            .unwrap_or_default()
                    });
                    i += 1;
                    let Some(&e) = self.data.get(i) else {
                        self.pos = self.data.len();
                        return Err(Error::eof(self.data.len() as u64, "literal string"));
                    };
                    match e {
                        b'n' => buf.push(b'\n'),
                        b'r' => buf.push(b'\r'),
                        b't' => buf.push(b'\t'),
                        b'b' => buf.push(0x08),
                        b'f' => buf.push(0x0C),
                        b'(' | b')' | b'\\' => buf.push(e),
                        b'\r' => {
                            // Line continuation: backslash + EOL are not part of the string.
                            if self.data.get(i + 1) == Some(&b'\n') {
                                i += 1;
                            }
                            i += 1;
                            continue;
                        }
                        b'\n' => {
                            i += 1;
                            continue;
                        }
                        b'0'..=b'7' => {
                            // \ddd: one to three octal digits; high-order overflow is ignored.
                            let mut value = u32::from(e - b'0');
                            let mut digits = 1;
                            while digits < 3 {
                                match self.data.get(i + 1) {
                                    Some(&d @ b'0'..=b'7') => {
                                        value = value * 8 + u32::from(d - b'0');
                                        digits += 1;
                                        i += 1;
                                    }
                                    _ => break,
                                }
                            }
                            buf.push((value & 0xFF) as u8);
                        }
                        // Any other escaped character: the backslash is ignored.
                        _ => buf.push(e),
                    }
                    i += 1;
                    len += 1;
                    self.check_len(len, start, i)?;
                    self.check_closes(len, start, i, depth)?;
                    continue;
                }
                b'\r' => {
                    // An unescaped EOL (CR, LF or CRLF) reads as a single LF.
                    let buf = owned.get_or_insert_with(|| {
                        self.data
                            .get(body..i)
                            .map(<[u8]>::to_vec)
                            .unwrap_or_default()
                    });
                    buf.push(b'\n');
                    if self.data.get(i + 1) == Some(&b'\n') {
                        i += 1;
                    }
                    i += 1;
                }
                _ => {
                    push(&mut owned, c);
                    i += 1;
                }
            }
            len += 1;
            self.check_len(len, start, i)?;
            self.check_closes(len, start, i, depth)?;
        }
        // `i` is at the closing `)`.
        self.pos = i + 1;
        let value = match owned {
            Some(v) => Cow::Owned(v),
            None => Cow::Borrowed(self.data.get(body..i).unwrap_or_default()),
        };
        Ok(TokenKind::LiteralString(value))
    }

    /// Hexadecimal string, §7.3.4.3. `self.pos` is at the opening `<`.
    ///
    /// A byte that is neither a hexadecimal digit nor white-space is skipped (a repair), unless
    /// the lexer ends hexadecimal strings at their first invalid byte
    /// ([`ParseCtx::with_hex_ending_at_invalid_byte`]): then the token fails there, and the
    /// position is left at that byte, where qpdf's next token starts (past the opening `<`, so
    /// lexing still advances).
    fn lex_hex_string(&mut self) -> Result<TokenKind<'a>> {
        let start = self.pos;
        let mut i = start + 1;
        let mut out = Vec::new();
        let mut high: Option<u8> = None;
        let mut reported = false;
        loop {
            let Some(&c) = self.data.get(i) else {
                self.pos = self.data.len();
                return Err(Error::eof(self.data.len() as u64, "hexadecimal string"));
            };
            i += 1;
            if c == b'>' {
                break;
            }
            if is_whitespace(c) {
                continue;
            }
            match hex_value(c) {
                Some(v) => match high.take() {
                    Some(h) => {
                        out.push((h << 4) | v);
                        self.check_len(out.len(), start, i)?;
                    }
                    None => high = Some(v),
                },
                None if self.hex_ends_at_invalid => {
                    self.pos = i - 1;
                    return Err(Error::syntax(
                        (i - 1) as u64,
                        format!("invalid character 0x{c:02X} ends the hexadecimal string"),
                    ));
                }
                None => {
                    if !reported {
                        reported = true;
                        self.pos = i;
                        self.recover(DiagnosticKind::InvalidHexDigit, i - 1, || {
                            format!("invalid character 0x{c:02X} in hexadecimal string skipped")
                        })?;
                    }
                }
            }
        }
        // An odd number of digits: the missing final digit is 0.
        if let Some(h) = high {
            out.push(h << 4);
            self.check_len(out.len(), start, i)?;
        }
        self.pos = i;
        Ok(TokenKind::HexString(out))
    }

    /// Name, §7.3.5. `self.pos` is at the `/`.
    fn lex_name(&mut self) -> Result<TokenKind<'a>> {
        let start = self.pos;
        let body = start + 1;
        let mut i = body;
        let mut owned: Option<Vec<u8>> = None;
        let mut len = 0usize;
        while let Some(&c) = self.data.get(i) {
            if !is_regular(c) {
                break;
            }
            if c == b'#' {
                let hi = self.data.get(i + 1).copied().and_then(hex_value);
                let lo = self.data.get(i + 2).copied().and_then(hex_value);
                let buf = owned.get_or_insert_with(|| {
                    self.data
                        .get(body..i)
                        .map(<[u8]>::to_vec)
                        .unwrap_or_default()
                });
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        let v = (h << 4) | l;
                        if v == 0 {
                            // §7.3.5: the NUL character shall not appear in a name.
                            self.pos = i + 3;
                            self.recover(DiagnosticKind::InvalidNameEscape, i, || {
                                "name contains #00 (NUL)".to_owned()
                            })?;
                        }
                        buf.push(v);
                        i += 3;
                    }
                    _ => {
                        self.pos = i + 1;
                        self.recover(DiagnosticKind::InvalidNameEscape, i, || {
                            "`#` in a name is not followed by two hex digits; kept literally"
                                .to_owned()
                        })?;
                        buf.push(b'#');
                        i += 1;
                    }
                }
            } else {
                push(&mut owned, c);
                i += 1;
            }
            len += 1;
            self.check_len(len, start, i)?;
        }
        self.pos = i;
        let value = match owned {
            Some(v) => Cow::Owned(v),
            None => Cow::Borrowed(self.data.get(body..i).unwrap_or_default()),
        };
        Ok(TokenKind::Name(value))
    }

    /// A run of regular characters: a number (§7.3.3) or a keyword.
    fn lex_regular(&mut self) -> Result<TokenKind<'a>> {
        let start = self.pos;
        let mut i = start;
        while self.data.get(i).is_some_and(|&b| is_regular(b)) {
            i += 1;
        }
        self.pos = i;
        let run = self.data.get(start..i).unwrap_or_default();
        match self.number(run, start)? {
            Some(kind) => Ok(kind),
            None => Ok(TokenKind::Keyword(run)),
        }
    }

    /// Interprets `run` as a number: `sign* digits* ('.' digits*)?` with at least one digit.
    /// Returns `None` if it is not a number (then it is a keyword).
    fn number(&self, run: &[u8], start: usize) -> Result<Option<TokenKind<'a>>> {
        let signs = run.iter().take_while(|&&b| b == b'+' || b == b'-').count();
        let (sign_run, body) = run.split_at(signs);
        let mut digits = 0usize;
        let mut has_dot = false;
        for &b in body {
            match b {
                b'0'..=b'9' => digits += 1,
                b'.' if !has_dot => has_dot = true,
                _ => return Ok(None),
            }
        }
        if digits == 0 {
            return Ok(None);
        }
        let negative = sign_run.contains(&b'-');
        if signs > 1 {
            self.recover(DiagnosticKind::MalformedNumber, start, || {
                format!(
                    "number `{}` has several signs; read as {}",
                    run.escape_ascii(),
                    if negative { "negative" } else { "positive" }
                )
            })?;
        }
        if !has_dot && let Some(i) = parse_integer(body, negative) {
            return Ok(Some(TokenKind::Integer(i)));
        }
        // A real, or an integer outside the i64 range (read as a real, as Acrobat does).
        // `body` is ASCII digits with at most one '.', which `f64::from_str` accepts
        // (including "5." and ".5") and rounds correctly.
        let magnitude = std::str::from_utf8(body)
            .ok()
            .and_then(|s| s.parse::<f64>().ok());
        match magnitude {
            Some(m) if m.is_finite() => Ok(Some(TokenKind::Real(if negative { -m } else { m }))),
            _ => Err(Error::syntax(start as u64, "number out of range")),
        }
    }
}

/// Appends `c` to `owned` if the token has diverged from its raw bytes.
fn push(owned: &mut Option<Vec<u8>>, c: u8) {
    if let Some(buf) = owned {
        buf.push(c);
    }
}

/// Parses ASCII digits as an `i64`, or `None` on overflow.
fn parse_integer(digits: &[u8], negative: bool) -> Option<i64> {
    let mut value: i64 = 0;
    for &d in digits {
        let d = i64::from(d.wrapping_sub(b'0'));
        value = value.checked_mul(10)?;
        value = if negative {
            value.checked_sub(d)?
        } else {
            value.checked_add(d)?
        };
    }
    Some(value)
}

impl<'a> Iterator for Lexer<'a> {
    type Item = Result<Token<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.fused {
            return None;
        }
        match self.next_token() {
            Ok(Some(tok)) => Some(Ok(tok)),
            Ok(None) => None,
            Err(e) => {
                self.fused = true;
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;
    use std::cell::RefCell;

    use TokenKind as T;

    fn lit(b: &[u8]) -> TokenKind<'_> {
        T::LiteralString(Cow::Borrowed(b))
    }

    fn name(b: &[u8]) -> TokenKind<'_> {
        T::Name(Cow::Borrowed(b))
    }

    fn kinds(input: &[u8]) -> Vec<TokenKind<'_>> {
        Lexer::new(input, 0)
            .map(|t| {
                t.unwrap_or_else(|e| panic!("{:?}: {e}", input.escape_ascii()))
                    .kind
            })
            .collect()
    }

    fn strict_err(input: &[u8]) -> Error {
        Lexer::new(input, 0)
            .with_strictness(Strictness::Strict)
            .collect::<Result<Vec<_>>>()
            .expect_err("strict mode must reject this input")
    }

    /// Every example of ISO 32000-2 §7.2–7.3, plus the leniencies of ARCHITECTURE §A.10 trap #2.
    #[test]
    fn lexer_spec_examples() {
        let cases: Vec<(&[u8], Vec<TokenKind<'_>>)> = vec![
            // §7.3.2 booleans, §7.3.9 null: keywords for the parser.
            (b"true false null", vec![
                T::Keyword(b"true"),
                T::Keyword(b"false"),
                T::Keyword(b"null"),
            ]),
            // §7.3.3 integers.
            (b"123 43445 +17 -98 0", vec![
                T::Integer(123),
                T::Integer(43445),
                T::Integer(17),
                T::Integer(-98),
                T::Integer(0),
            ]),
            // §7.3.3 reals.
            (b"34.5 -3.62 +123.6 4. -.002 0.0", vec![
                T::Real(34.5),
                T::Real(-3.62),
                T::Real(123.6),
                T::Real(4.0),
                T::Real(-0.002),
                T::Real(0.0),
            ]),
            // Trap #2 number forms.
            (b".5 5. -.5 +17 00012 -0", vec![
                T::Real(0.5),
                T::Real(5.0),
                T::Real(-0.5),
                T::Integer(17),
                T::Integer(12),
                T::Integer(0),
            ]),
            (b"--5 -+5 +-5.5 ++3", vec![
                T::Integer(-5),
                T::Integer(-5),
                T::Real(-5.5),
                T::Integer(3),
            ]),
            // i64 range edges; larger integers become reals.
            (b"9223372036854775807 -9223372036854775808 9223372036854775808", vec![
                T::Integer(i64::MAX),
                T::Integer(i64::MIN),
                T::Real(9_223_372_036_854_775_808.0),
            ]),
            // No exponents (§7.3.3): these are keywords, not numbers.
            (b"1e5 1.5E3 . - + 1.2.3 12abc", vec![
                T::Keyword(b"1e5"),
                T::Keyword(b"1.5E3"),
                T::Keyword(b"."),
                T::Keyword(b"-"),
                T::Keyword(b"+"),
                T::Keyword(b"1.2.3"),
                T::Keyword(b"12abc"),
            ]),
            // §7.3.4.2 literal strings.
            (b"(This is a string)", vec![lit(b"This is a string")]),
            (b"(Strings may contain newlines\nand such.)", vec![lit(
                b"Strings may contain newlines\nand such.",
            )]),
            (
                b"(Strings may contain balanced parentheses ( ) and\nspecial characters (*!&}^% and so on).)",
                vec![lit(
                    b"Strings may contain balanced parentheses ( ) and\nspecial characters (*!&}^% and so on).",
                )],
            ),
            (b"(The following is an empty string.)()", vec![
                lit(b"The following is an empty string."),
                lit(b""),
            ]),
            (b"(It has zero (0) length.)", vec![lit(b"It has zero (0) length.")]),
            // Escapes (Table 3).
            (b"(a\\nb\\rc\\td\\be\\ff\\(g\\)h\\\\i)", vec![T::LiteralString(Cow::Owned(
                b"a\nb\rc\td\x08e\x0cf(g)h\\i".to_vec(),
            ))]),
            // Line continuation with LF, CR and CRLF.
            (b"(These \\\ntwo strings \\\rare \\\r\nthe same.)", vec![T::LiteralString(
                Cow::Owned(b"These two strings are the same.".to_vec()),
            )]),
            (b"(So does this one.\\n)", vec![T::LiteralString(Cow::Owned(
                b"So does this one.\n".to_vec(),
            ))]),
            // Octal escapes: 1-3 digits; \0053 is \005 followed by '3'; overflow ignored.
            (b"(This string contains \\245two octal characters\\307.)", vec![T::LiteralString(
                Cow::Owned(b"This string contains \xA5two octal characters\xC7.".to_vec()),
            )]),
            (b"(\\0053\\053\\53\\5)", vec![T::LiteralString(Cow::Owned(
                b"\x053++\x05".to_vec(),
            ))]),
            (b"(\\777\\400)", vec![T::LiteralString(Cow::Owned(vec![0xFF, 0x00]))]),
            // Unknown escape: the backslash is ignored.
            (b"(\\q\\%)", vec![T::LiteralString(Cow::Owned(b"q%".to_vec()))]),
            // Unescaped EOLs (CR, CRLF, LF) all read as LF.
            (b"(a\rb\r\nc\nd)", vec![T::LiteralString(Cow::Owned(b"a\nb\nc\nd".to_vec()))]),
            // Strings may hold any byte, including delimiters and '%'.
            (b"(<</%[]>>\x00\xff)", vec![lit(b"<</%[]>>\x00\xff")]),
            // §7.3.4.3 hexadecimal strings.
            (b"<4E6F762073686D6F7A206B6120706F702E>", vec![T::HexString(
                b"Nov shmoz ka pop.".to_vec(),
            )]),
            (b"<901FA3>", vec![T::HexString(vec![0x90, 0x1F, 0xA3])]),
            (b"<901FA>", vec![T::HexString(vec![0x90, 0x1F, 0xA0])]),
            (b"< 90 1f\r\na\t3\x0c\x00 >", vec![T::HexString(vec![0x90, 0x1F, 0xA3])]),
            (b"<>", vec![T::HexString(vec![])]),
            // §7.3.5 names (Table 4).
            (b"/Name1", vec![name(b"Name1")]),
            (b"/ASomewhatLongerName", vec![name(b"ASomewhatLongerName")]),
            (b"/A;Name_With-Various***Characters?", vec![name(
                b"A;Name_With-Various***Characters?",
            )]),
            (b"/1.2", vec![name(b"1.2")]),
            (b"/$$", vec![name(b"$$")]),
            (b"/@pattern", vec![name(b"@pattern")]),
            (b"/.notdef", vec![name(b".notdef")]),
            (b"/Lime#20Green", vec![T::Name(Cow::Owned(b"Lime Green".to_vec()))]),
            (b"/paired#28#29parentheses", vec![T::Name(Cow::Owned(
                b"paired()parentheses".to_vec(),
            ))]),
            (b"/The_Key_of_F#23_Minor", vec![T::Name(Cow::Owned(
                b"The_Key_of_F#_Minor".to_vec(),
            ))]),
            (b"/A#42", vec![T::Name(Cow::Owned(b"AB".to_vec()))]),
            (b"/a#e9", vec![T::Name(Cow::Owned(b"a\xe9".to_vec()))]),
            // The empty name, and names ended by delimiters.
            (b"/ /A/B[/C]", vec![
                name(b""),
                name(b"A"),
                name(b"B"),
                T::ArrayStart,
                name(b"C"),
                T::ArrayEnd,
            ]),
            // §7.2.4 comments are white-space; '%' inside a string is not a comment.
            (b"abc% comment ( /%) blah blah blah\n123", vec![
                T::Keyword(b"abc"),
                T::Integer(123),
            ]),
            (b"(a%b)%c\r1%d", vec![lit(b"a%b"), T::Integer(1)]),
            // §7.2.3 white-space: NUL, HT, LF, FF, CR, SP all separate tokens.
            (b"1\x002\t3\n4\x0c5\r6 7", (1..=7).map(T::Integer).collect()),
            // Delimiters.
            (b"[]<<>>{}", vec![
                T::ArrayStart,
                T::ArrayEnd,
                T::DictStart,
                T::DictEnd,
                T::BraceOpen,
                T::BraceClose,
            ]),
            (b"<</A[1(x)<41>]>>", vec![
                T::DictStart,
                name(b"A"),
                T::ArrayStart,
                T::Integer(1),
                lit(b"x"),
                T::HexString(vec![0x41]),
                T::ArrayEnd,
                T::DictEnd,
            ]),
            // §7.3.10 references and object headers are token sequences.
            (b"12 0 R 12 0 obj endobj", vec![
                T::Integer(12),
                T::Integer(0),
                T::Keyword(b"R"),
                T::Integer(12),
                T::Integer(0),
                T::Keyword(b"obj"),
                T::Keyword(b"endobj"),
            ]),
            // Numbers end at delimiters.
            (b"1.5[2]3/N", vec![
                T::Real(1.5),
                T::ArrayStart,
                T::Integer(2),
                T::ArrayEnd,
                T::Integer(3),
                name(b"N"),
            ]),
            // A comment inside an array hides delimiters up to the EOL (CR here).
            (
                b"[1%c ]\r2]",
                vec![T::ArrayStart, T::Integer(1), T::Integer(2), T::ArrayEnd],
            ),
            // An octal escape stops at a non-octal digit.
            (
                b"(\\18\\9)",
                vec![T::LiteralString(Cow::Owned(b"\x018\x39".to_vec()))],
            ),
            // More number forms: sign with a leading period, trailing period, and lone signs.
            (
                b"+.5 0. -. +-",
                vec![
                    T::Real(0.5),
                    T::Real(0.0),
                    T::Keyword(b"-."),
                    T::Keyword(b"+-"),
                ],
            ),
            (b"", vec![]),
            (b"  % only a comment", vec![]),
        ];
        for (input, expected) in cases {
            assert_eq!(kinds(input), expected, "input {:?}", input.escape_ascii());
        }
    }

    #[test]
    fn token_positions() {
        let toks: Vec<Token<'_>> = Lexer::new(b" /A (b) <43> 12 -.5 [", 0)
            .collect::<Result<_>>()
            .unwrap();
        let spans: Vec<(usize, usize)> = toks.iter().map(|t| (t.start, t.end)).collect();
        assert_eq!(
            spans,
            [(1, 3), (4, 7), (8, 12), (13, 15), (16, 19), (20, 21)]
        );
        let mut lexer = Lexer::new(b"1 2 3", 2);
        assert_eq!(lexer.position(), 2);
        assert_eq!(lexer.next_token().unwrap().unwrap().kind, T::Integer(2));
        lexer.set_position(0);
        assert_eq!(lexer.next_token().unwrap().unwrap().kind, T::Integer(1));
        assert!(!lexer.is_at_end());
        lexer.set_position(100);
        assert_eq!(lexer.position(), 5);
        assert!(lexer.is_at_end());
        assert_eq!(lexer.next_token().unwrap(), None);
        assert_eq!(lexer.data(), b"1 2 3");
    }

    #[test]
    fn borrowed_when_possible() {
        let mut lexer = Lexer::new(b"(plain) (esc\\n) /Plain /Esc#20", 0);
        let mut next = || lexer.next_token().unwrap().unwrap().kind;
        assert!(matches!(next(), T::LiteralString(Cow::Borrowed(_))));
        assert!(matches!(next(), T::LiteralString(Cow::Owned(_))));
        assert!(matches!(next(), T::Name(Cow::Borrowed(_))));
        assert!(matches!(next(), T::Name(Cow::Owned(_))));
    }

    #[test]
    fn lenient_repairs_report_diagnostics() {
        let cases: Vec<(&[u8], TokenKind<'_>, DiagnosticKind)> = vec![
            (b"--5", T::Integer(-5), DiagnosticKind::MalformedNumber),
            (
                b"<4G1>",
                T::HexString(vec![0x41]),
                DiagnosticKind::InvalidHexDigit,
            ),
            (
                b"/A#4",
                T::Name(Cow::Owned(b"A#4".to_vec())),
                DiagnosticKind::InvalidNameEscape,
            ),
            (
                b"/A#",
                T::Name(Cow::Owned(b"A#".to_vec())),
                DiagnosticKind::InvalidNameEscape,
            ),
            (
                b"/A#zz",
                T::Name(Cow::Owned(b"A#zz".to_vec())),
                DiagnosticKind::InvalidNameEscape,
            ),
            (
                b"/A#00",
                T::Name(Cow::Owned(b"A\x00".to_vec())),
                DiagnosticKind::InvalidNameEscape,
            ),
        ];
        for (input, expected, kind) in cases {
            let diags = RefCell::new(Vec::new());
            let sink = |d: Diagnostic| diags.borrow_mut().push(d);
            let tokens: Vec<TokenKind<'_>> = Lexer::new(input, 0)
                .with_diagnostics(&sink)
                .map(|t| t.unwrap().kind)
                .collect();
            assert_eq!(tokens, vec![expected], "{:?}", input.escape_ascii());
            let diags = diags.borrow();
            assert_eq!(diags.len(), 1, "{:?}", input.escape_ascii());
            assert_eq!(diags[0].kind, kind);
            assert!(diags[0].offset.is_some());
            // Strict mode rejects the same input.
            assert_eq!(strict_err(input).code(), ErrorCode::Syntax);
        }
        // Only the first bad hex character of a string is reported.
        let diags = RefCell::new(Vec::new());
        let sink = |d: Diagnostic| diags.borrow_mut().push(d);
        let tok = Lexer::new(b"<4G1HZ>", 0)
            .with_diagnostics(&sink)
            .next_token()
            .unwrap()
            .unwrap();
        assert_eq!(tok.kind, T::HexString(vec![0x41]));
        assert_eq!(diags.borrow().len(), 1);
        assert_eq!(diags.borrow()[0].offset, Some(2));
    }

    #[test]
    fn errors_carry_offsets_and_allow_resuming() {
        let cases: Vec<(&[u8], u64, &str)> = vec![
            (b"  )", 2, "unbalanced"),
            (b"1 >", 2, "unexpected `>`"),
            (b"(abc", 4, "literal string"),
            (b"(abc\\", 5, "literal string"),
            (b"<41", 3, "hexadecimal string"),
            (b"((a)", 4, "literal string"),
        ];
        for (input, offset, needle) in cases {
            let err = Lexer::new(input, 0)
                .collect::<Result<Vec<_>>>()
                .unwrap_err();
            assert_eq!(err.code(), ErrorCode::Syntax, "{err}");
            assert_eq!(err.offset(), Some(offset), "{err}");
            assert!(err.to_string().contains(needle), "{err}");
        }
        // After an error, next_token resumes; the iterator is fused.
        let mut lexer = Lexer::new(b") 1", 0);
        assert!(lexer.next_token().is_err());
        assert_eq!(lexer.next_token().unwrap().unwrap().kind, T::Integer(1));
        let mut lexer = Lexer::new(b") 1", 0);
        assert!(lexer.next().unwrap().is_err());
        assert!(lexer.next().is_none());
    }

    #[test]
    fn huge_numbers_are_errors_not_infinities() {
        let mut digits = vec![b'9'; 400];
        let err = Lexer::new(&digits, 0).next_token().unwrap_err();
        assert_eq!(err.code(), ErrorCode::Syntax);
        digits.extend_from_slice(b".5");
        assert!(Lexer::new(&digits, 0).next_token().is_err());
        // 308 digits still fit in an f64.
        let digits = [b'1'; 308];
        match Lexer::new(&digits, 0).next_token().unwrap().unwrap().kind {
            T::Real(r) => assert!(r.is_finite() && r > 1e307),
            other => panic!("{other:?}"),
        }
        // Long fractions are fine.
        let mut long = b"0.".to_vec();
        long.extend(std::iter::repeat_n(b'3', 10_000));
        match Lexer::new(&long, 0).next_token().unwrap().unwrap().kind {
            T::Real(r) => assert!((r - 1.0 / 3.0).abs() < 1e-15),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn string_length_is_limited() {
        let cases: Vec<&[u8]> = vec![
            b"(abcdef)",
            b"(ab\\ncde)",
            b"<414243444546>",
            b"/abcdef",
            b"/ab#20cde",
        ];
        for input in cases {
            let err = Lexer::new(input, 0)
                .with_max_string_len(5)
                .next_token()
                .unwrap_err();
            assert_eq!(
                err.code(),
                ErrorCode::LimitExceeded,
                "{:?}",
                input.escape_ascii()
            );
            assert!(
                Lexer::new(input, 0)
                    .with_max_string_len(6)
                    .next_token()
                    .is_ok(),
                "{:?}",
                input.escape_ascii()
            );
        }
        // An odd hex digit count pads to a 6th byte.
        assert!(
            Lexer::new(b"<41424344454>", 0)
                .with_max_string_len(5)
                .next_token()
                .is_err()
        );
    }

    #[test]
    fn deep_parentheses_do_not_recurse() {
        let mut s = vec![b'('; 200_000];
        s.extend(std::iter::repeat_n(b')', 200_000));
        match Lexer::new(&s, 0).next_token().unwrap().unwrap().kind {
            T::LiteralString(v) => assert_eq!(v.len(), 399_998),
            other => panic!("{other:?}"),
        }
    }

    /// A xorshift generator for deterministic random tests.
    fn xorshift(seed: u64) -> impl FnMut() -> u64 {
        let mut state = seed;
        move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        }
    }

    #[test]
    fn paren_index_answers_as_the_lexer_reads() {
        // Random buffers full of parentheses, backslashes (escapes, `\\`, `\ddd`, line
        // continuations) and EOLs; every few `(` start a string, and every few bytes inside it
        // the index is asked from there, with the depth there. Its answer must be the lexer's:
        // the string closes, or it runs into the end. Shapes with tiny blocks and groups give
        // many levels on little data.
        const ALPHABET: &[u8] = b"((()))\\\\\\ab\r\n07";
        let mut next = xorshift(0x2545_F491_4F6C_DD1D);
        for round in 0..30 {
            let len = (next() % 1500) as usize + round;
            let data: Vec<u8> = (0..len)
                .map(|_| ALPHABET[next() as usize % ALPHABET.len()])
                .collect();
            for (block, fanout) in [(1, 2), (3, 2), (8, 4), (64, 3), (PAREN_BLOCK, PAREN_FANOUT)] {
                let index = ParenIndex::with_shape(&data, block, fanout);
                let starts = data.iter().enumerate().filter(|&(_, &b)| b == b'(');
                for (s, _) in starts.step_by(7) {
                    let closes = matches!(
                        Lexer::new(&data, s).next_token(),
                        Ok(Some(Token {
                            kind: T::LiteralString(_),
                            ..
                        }))
                    );
                    // Walk the string as the lexer does, asking at unescaped bytes.
                    let (mut i, mut depth, mut escaped) = (s + 1, 1usize, false);
                    while let Some(&b) = data.get(i) {
                        if !escaped && (i - s) % 5 == 1 {
                            assert_eq!(
                                index.closes(&data, i, depth),
                                Some(closes),
                                "round {round}, shape {block}/{fanout}, string at {s}, byte {i}"
                            );
                        }
                        match b {
                            _ if escaped => escaped = false,
                            b'\\' => escaped = true,
                            b'(' => depth += 1,
                            b')' => {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                        i += 1;
                    }
                    assert_eq!(depth == 0, closes);
                }
            }
        }
        // A long run of backslashes across block boundaries, and the end of the data.
        let mut data = b"(".to_vec();
        data.extend(std::iter::repeat_n(b'\\', 9));
        data.extend_from_slice(b")x)");
        for block in 1..12 {
            let index = ParenIndex::with_shape(&data, block, 2);
            assert_eq!(index.closes(&data, 1, 1), Some(true), "{block}");
            assert_eq!(index.closes(&data, 1, 2), Some(false), "{block}");
            assert_eq!(index.closes(&data, data.len(), 1), Some(false), "{block}");
        }
        // An index answers only for its own buffer.
        let other = data.clone();
        assert_eq!(ParenIndex::new(&data).closes(&other, 1, 1), None);
        assert_eq!(ParenIndex::new(&[]).closes(&[], 0, 1), Some(false));
    }

    #[test]
    fn a_hex_string_can_end_at_its_first_invalid_byte() {
        // Lenient by default: the invalid bytes are skipped, the string runs to the next `>`.
        let data = b"<41 zz\nendobj\n6 0 obj\n(six)\n%>\n";
        let close = data.iter().position(|&b| b == b'>').unwrap();
        let mut lexer = Lexer::new(data, 0);
        let tok = lexer.next_token().unwrap().unwrap();
        assert_eq!(tok.end, close + 1);
        // 41, then the digits of `endobj`, `6 0` and `obj`: E D B 6 0 B.
        assert_eq!(tok.kind, T::HexString(vec![0x41, 0xED, 0xB6, 0x0B]));
        // Ending at the first invalid byte (as qpdf's tokenizer does, for the coverage parses of
        // `repair::definitions`): an error at the first `z`, where the position is left, so the
        // next token starts there.
        let ctx = ParseCtx::default().with_hex_ending_at_invalid_byte();
        assert!(format!("{ctx:?}").contains("hex_ends_at_invalid_byte: true"));
        let log = crate::DiagnosticLog::new(16);
        let ctx = ctx.with_diagnostics(&log);
        let mut lexer = Lexer::with_ctx(data, 0, &ctx);
        let err = lexer.next_token().unwrap_err();
        assert_eq!((err.code(), err.offset()), (ErrorCode::Syntax, Some(4)));
        assert_eq!(lexer.position(), 4);
        assert_eq!(lexer.next_token().unwrap().unwrap().kind, T::Keyword(b"zz"));
        assert!(log.snapshot().is_empty());
        // Valid strings read the same either way, white-space, odd digit counts and all; a `<`
        // inside one is invalid too, and the next string starts there.
        for (data, value) in [
            (&b"<41 4 2\n43>"[..], &[0x41, 0x42, 0x43][..]),
            (b"<414>", &[0x41, 0x40]),
            (b"<>", &[]),
        ] {
            let plain = Lexer::new(data, 0).next_token().unwrap().unwrap();
            let ending = Lexer::with_ctx(data, 0, &ctx)
                .next_token()
                .unwrap()
                .unwrap();
            assert_eq!(plain, ending);
            assert_eq!(ending.kind, T::HexString(value.to_vec()));
        }
        let mut lexer = Lexer::with_ctx(b"<41<42>", 0, &ctx);
        assert_eq!(lexer.next_token().unwrap_err().offset(), Some(3));
        let tok = lexer.next_token().unwrap().unwrap();
        assert_eq!((tok.kind, tok.start), (T::HexString(vec![0x42]), 3));
        // Still an end-of-data error when the string never closes.
        let err = Lexer::with_ctx(b"<41 42", 0, &ctx)
            .next_token()
            .unwrap_err();
        assert!(
            matches!(err, Error::UnexpectedEof { offset: 6, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_long_string_that_never_closes_stops_early_with_an_index() {
        let long = "a".repeat(2 * LONG_STRING);
        let cases: Vec<(Vec<u8>, bool)> = vec![
            // Closed: the same token with and without the index.
            (format!("({long})").into_bytes(), true),
            (format!("((\\({long}) x)").into_bytes(), true),
            (format!("({long}\\\\)").into_bytes(), true),
            // Never closed: an error either way, but read only a little way with the index.
            (format!("({long}").into_bytes(), false),
            (format!("(({long})").into_bytes(), false),
            (format!("({long}\\)").into_bytes(), false),
            (format!("(\\\n{long}\\").into_bytes(), false),
            // Short strings never ask.
            (b"(abc".to_vec(), false),
        ];
        for (data, closes) in cases {
            let plain = Lexer::new(&data, 0).next_token();
            let index = ParenIndex::new(&data);
            let ctx = ParseCtx::default().with_string_ends(&index);
            assert!(format!("{ctx:?}").contains("string_ends: true"));
            let mut lexer = Lexer::with_ctx(&data, 0, &ctx);
            let indexed = lexer.next_token();
            assert_eq!(plain.is_ok(), closes);
            match (plain, indexed) {
                (Ok(a), Ok(b)) => assert_eq!(a, b),
                (Err(a), Err(b)) => {
                    assert_eq!(a.offset(), Some(data.len() as u64));
                    if data.len() > LONG_STRING {
                        // Stopped after LONG_STRING decoded bytes, not at the end, and read no
                        // further than that.
                        assert_eq!(b.code(), ErrorCode::Syntax);
                        assert!(b.offset().unwrap() < (LONG_STRING + 8) as u64, "{b}");
                        assert_eq!(Some(lexer.position() as u64), b.offset());
                    } else {
                        assert_eq!(lexer.position(), data.len());
                        assert_eq!(a, b);
                    }
                }
                (a, b) => panic!("{a:?} / {b:?}"),
            }
        }
    }

    #[test]
    fn character_classes() {
        for b in 0..=255u8 {
            let classes = [is_whitespace(b), is_delimiter(b), is_regular(b)];
            assert_eq!(classes.iter().filter(|&&c| c).count(), 1, "byte {b:#x}");
        }
        assert_eq!(skip_whitespace_and_comments(b" %x\r\n %y", 0), 8);
        assert_eq!(skip_whitespace_and_comments(b" %x\r\n a", 0), 6);
        assert_eq!(skip_whitespace_and_comments(b"a", 5), 1);
        assert_eq!(find_bytes(b"xxendstreamyy", b"endstream", 0), Some(2));
        assert_eq!(find_bytes(b"xxendstreamyy", b"endstream", 3), None);
        assert_eq!(find_bytes(b"eendstream", b"endstream", 0), Some(1));
        assert_eq!(find_bytes(b"abc", b"", 0), None);
        assert_eq!(find_bytes(b"abc", b"c", 10), None);
    }

    #[test]
    fn with_ctx_takes_policy_from_ctx() {
        let ctx = ParseCtx::new(Limits::default().with_max_string_len(2), Strictness::Strict);
        let mut lexer = Lexer::with_ctx(b"--1", 0, &ctx);
        assert!(lexer.next_token().is_err());
        let mut lexer = Lexer::with_ctx(b"(abc)", 0, &ctx);
        assert_eq!(
            lexer.next_token().unwrap_err().code(),
            ErrorCode::LimitExceeded
        );
        assert!(format!("{lexer:?}").contains("Strict"));
    }

    /// A deterministic pseudo-random sweep: arbitrary bytes never panic and always make progress.
    #[test]
    fn random_input_never_panics() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        const ALPHABET: &[u8] = b"()<>[]{}/%#\\ \r\n\t0123456789.+-abcdefRobjtrue";
        for _ in 0..3000 {
            let len = (next() % 64) as usize;
            let input: Vec<u8> = (0..len)
                .map(|_| {
                    let r = next();
                    if r % 4 == 0 {
                        (r >> 8) as u8
                    } else {
                        ALPHABET[(r >> 8) as usize % ALPHABET.len()]
                    }
                })
                .collect();
            for strictness in [Strictness::Lenient, Strictness::Strict] {
                let mut lexer = Lexer::new(&input, 0).with_strictness(strictness);
                let mut last = 0;
                for _ in 0..=input.len() + 1 {
                    let result = lexer.next_token();
                    assert!(lexer.position() <= input.len());
                    match result {
                        Ok(None) => break,
                        Ok(Some(tok)) => {
                            assert!(tok.start < tok.end && tok.end <= input.len());
                            if let T::Real(r) = tok.kind {
                                assert!(r.is_finite());
                            }
                        }
                        Err(_) => {}
                    }
                    assert!(lexer.position() > last || lexer.is_at_end());
                    last = lexer.position();
                }
            }
        }
    }
}

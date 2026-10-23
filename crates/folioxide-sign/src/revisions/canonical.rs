//! The canonical-input gate (M4 QA round 3, manager ruling R-12): a strict lexical check of the
//! raw bytes of an object, so that the classifier grants a level below `Other` only for objects
//! that every reader reads the same way.
//!
//! Folioxide's lexer is lenient, as viewers are, but viewers are lenient in different ways: a
//! number spelled `++2` or `+-260` is 2 or −260 to Folioxide and 0 to PDFium; an integer such as
//! `4294967296` or `-2147483648` is a large number to Folioxide and poppler and 0 to PDFium; a
//! dictionary that writes a key twice gives the first value to pyHanko and pypdf and the last to
//! Folioxide, qpdf and poppler (ISO 32000-2 §7.3.7). Rather than chase each such differential,
//! the classifier reads only canonical bytes, and an object that is not canonical makes its
//! revision `Other`. Canonical means (ruling R-12):
//!
//! - no dictionary, at any depth, writes a key twice;
//! - an integer is `[+-]?[0-9]+` (one optional sign) with a magnitude of at most `2^31 − 1`
//!   ([`MAX_CANONICAL_INTEGER`]; ruling R-12 allows `−2^31`, but PDFium reads `-2147483648` as 0,
//!   QA round 3 variant `A2-r3-square-rect-y2-int32-min-cert3`, so the range is symmetric) and
//!   at most [`MAX_INTEGER_CHARS`] characters, the length of `-2147483647` (M4 QA round 4,
//!   finding 2: PDFium reads a number padded with leading zeros to 256 characters or more as 0,
//!   Folioxide and poppler read its value); this holds for the object and generation numbers of
//!   a reference too;
//! - a real is `[+-]?([0-9]+\.[0-9]*|\.[0-9]+)` with a magnitude of at most
//!   [`MAX_CANONICAL_REAL`] and at most [`MAX_REAL_CHARS`] characters (ISO 32000-2 Annex C);
//! - a name has no `#00` and no `#` that two hexadecimal digits do not follow (§7.3.5), and a
//!   hexadecimal string holds only hexadecimal digits and white-space (§7.3.4.3): every repair
//!   the lexer makes is a defect;
//! - the value is well-formed: dictionaries of name keys and values, arrays, references
//!   `N G R` of unsigned integers, and the keywords `true`, `false` and `null` only.
//!
//! [`scan_value`] reads one direct value in **one linear pass** with the public lexer (bounded by
//! the store's nesting and string limits), and reports the first defect, the top-level keys whose
//! entry it affects, and the tokens read (the work the classifier charges to its budget).

use std::collections::{BTreeSet, HashSet, VecDeque};

use folioxide_syntax::{Diagnostic, Lexer, Limits, Token, TokenKind};

/// The largest magnitude of a canonical integer: `2^31 − 1` (ISO 32000-2 Annex C: an integer is
/// at least 32 bits; readers that store it in 32 bits read a larger one as 0).
pub(crate) const MAX_CANONICAL_INTEGER: i64 = 2_147_483_647;

/// The most characters of a canonical integer, its sign included: those of `-2147483647`. A
/// longer integer within range is padded with leading zeros, which readers do not all read the
/// same way (PDFium reads a word of 256 characters or more as 0; M4 QA round 4, finding 2).
pub(crate) const MAX_INTEGER_CHARS: usize = 11;

/// The bytes of a token a defect message shows; a longer token is cut there.
const SHOWN_CHARS: usize = 24;

/// The largest magnitude of a canonical real (ISO 32000-2 Annex C: about ±3.403 × 10^38, the
/// single-precision range).
pub(crate) const MAX_CANONICAL_REAL: f64 = 3.403e38;

/// The most characters of a canonical real (sign and point included).
pub(crate) const MAX_REAL_CHARS: usize = 40;

/// The key [`Scan::ambiguous_keys`] reports for a value that is not a dictionary but holds a
/// defect somewhere inside (an array of dictionaries).
pub(crate) const WHOLE_VALUE: &[u8] = b"";

/// What [`scan_value`] found in one value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Scan {
    /// Where the value ends (past its last token).
    pub(crate) end: usize,
    /// The tokens read.
    pub(crate) tokens: u64,
    /// The first defect, with its byte offset: why a reader may read the value differently.
    pub(crate) defect: Option<String>,
    /// For a dictionary: its top-level keys whose entry reads differently in different readers
    /// (a key written twice, or a value with a defect anywhere inside); for any other value
    /// with a defect, [`WHOLE_VALUE`].
    pub(crate) ambiguous_keys: BTreeSet<Vec<u8>>,
    /// A top-level key of the dictionary is itself not canonical (a name with `#00`): which
    /// entry it names cannot be known.
    pub(crate) key_defect: bool,
    /// The value is a dictionary (or a stream's dictionary).
    pub(crate) is_dict: bool,
    /// The object numbers of the references the value holds, in every value of every key (the
    /// first value of a key written twice included): every object some reader may follow.
    pub(crate) references: Vec<u32>,
    /// A reference whose object or generation number is not a canonical unsigned integer, so
    /// which object a reader follows cannot be known.
    pub(crate) doubtful_reference: bool,
}

/// Counts the repairs the lexer reports.
#[derive(Default)]
struct Repairs {
    count: std::cell::Cell<u64>,
}

impl folioxide_syntax::DiagnosticSink for Repairs {
    fn report(&self, _diagnostic: Diagnostic) {
        self.count.set(self.count.get().saturating_add(1));
    }
}

/// A token, and whether the lexer repaired anything to read it.
type Read<'a> = (Token<'a>, bool);

/// The tokens of a value, with two tokens of look-ahead (references are `N G R`). A lexer error
/// is kept in the queue and fails the scan only when it is reached.
struct Tokens<'a> {
    lexer: Lexer<'a>,
    repairs: &'a Repairs,
    ahead: VecDeque<Result<Read<'a>, ()>>,
    read: u64,
}

impl<'a> Tokens<'a> {
    /// Lexes one more token into the queue (`false` at the end of the data).
    fn fill(&mut self) -> bool {
        let before = self.repairs.count.get();
        let next = match self.lexer.next_token() {
            Ok(Some(token)) => Ok((token, self.repairs.count.get() != before)),
            Ok(None) => return false,
            Err(_) => Err(()),
        };
        self.ahead.push_back(next);
        true
    }

    /// The next token; `Err` at the end of the data or for input that is no token.
    fn next(&mut self) -> Result<Read<'a>, ()> {
        if self.ahead.is_empty() && !self.fill() {
            return Err(());
        }
        self.read = self.read.saturating_add(1);
        self.ahead.pop_front().ok_or(())?
    }

    /// The kind of the token `i` places ahead (0: the next one), if it is one.
    fn peek(&mut self, i: usize) -> Option<&TokenKind<'a>> {
        while self.ahead.len() <= i {
            if !self.fill() {
                return None;
            }
        }
        match self.ahead.get(i)? {
            Ok((token, _)) => Some(&token.kind),
            Err(()) => None,
        }
    }
}

/// An open container of the value being read.
enum Frame {
    Array,
    /// A dictionary: the keys read so far, and whether a key is expected next.
    Dict {
        keys: HashSet<Vec<u8>>,
        want_key: bool,
    },
}

/// Why the raw bytes `raw` of a number token read as `kind` are not canonical (see the module
/// documentation); `None` when they are.
fn number_defect(raw: &[u8], kind: &TokenKind<'_>) -> Option<String> {
    let text = shown(raw);
    let signs = raw.iter().take_while(|&&b| b == b'+' || b == b'-').count();
    if signs > 1 {
        return Some(format!(
            "the number `{text}` is written with several signs, which readers read differently \
             (Folioxide by its signs, PDFium as 0)"
        ));
    }
    match kind {
        TokenKind::Integer(value)
            if value.unsigned_abs() > MAX_CANONICAL_INTEGER.unsigned_abs() =>
        {
            Some(format!(
                "the integer `{text}` is outside ±{MAX_CANONICAL_INTEGER}, which readers that keep \
                 integers in 32 bits (PDFium) read as 0 (ISO 32000-2 Annex C)"
            ))
        }
        TokenKind::Integer(_) => (raw.len() > MAX_INTEGER_CHARS).then(|| {
            format!(
                "the integer `{text}` is longer than {MAX_INTEGER_CHARS} characters (padded with \
                 leading zeros), which readers read differently (Folioxide and poppler by its \
                 value, PDFium as 0 from 256 characters on)"
            )
        }),
        TokenKind::Real(value) => {
            if !raw.contains(&b'.') {
                Some(format!(
                    "the integer `{text}` is outside the 64-bit range (Folioxide reads it as a \
                     real, PDFium as 0; ISO 32000-2 Annex C)"
                ))
            } else if raw.len() > MAX_REAL_CHARS || value.abs() > MAX_CANONICAL_REAL {
                Some(format!(
                    "the real `{text}` is longer than {MAX_REAL_CHARS} characters or larger than \
                     {MAX_CANONICAL_REAL:e} (ISO 32000-2 Annex C)"
                ))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The raw bytes of a token as a defect message shows them: at most [`SHOWN_CHARS`] bytes, and
/// the length of a longer token.
fn shown(raw: &[u8]) -> String {
    match raw.get(..SHOWN_CHARS) {
        Some(head) if raw.len() > SHOWN_CHARS => format!(
            "{}… ({} characters)",
            String::from_utf8_lossy(head),
            raw.len()
        ),
        _ => String::from_utf8_lossy(raw).into_owned(),
    }
}

/// Whether the raw bytes of a number token are an unsigned integer (an object or generation
/// number of a reference).
fn is_unsigned(raw: &[u8]) -> bool {
    !raw.is_empty() && raw.iter().all(u8::is_ascii_digit)
}

/// Reads the direct value at `pos` of `bytes` (leading white-space and comments skipped; a
/// stream's dictionary ends at its `>>`, before `stream`) and checks that it is canonical (see
/// the module documentation). `Err` when the bytes there are no well-formed value. One pass,
/// linear in the value's bytes.
pub(crate) fn scan_value(bytes: &[u8], pos: usize, limits: &Limits) -> Result<Scan, ()> {
    let repairs = Repairs::default();
    let lexer = Lexer::new(bytes, pos)
        .with_max_string_len(limits.max_string_len)
        .with_diagnostics(&repairs);
    let mut tokens = Tokens {
        lexer,
        repairs: &repairs,
        ahead: VecDeque::new(),
        read: 0,
    };
    let max_depth = usize::from(limits.max_nesting_depth.clamp(1, Limits::MAX_NESTING_DEPTH));
    let mut out = Scan::default();
    let mut stack: Vec<Frame> = Vec::new();
    // The top-level key whose value is being read (for a top-level dictionary).
    let mut top_key: Option<Vec<u8>> = None;
    let mut top_is_dict = false;
    // Records a defect at `at`, against the entry being read.
    let note = |out: &mut Scan, top_key: &Option<Vec<u8>>, top_is_dict: bool, at: usize, what| {
        if out.defect.is_none() {
            out.defect = Some(format!("byte {at}: {what}"));
        }
        let key = match top_key {
            Some(key) if top_is_dict => key.clone(),
            _ => WHOLE_VALUE.to_vec(),
        };
        out.ambiguous_keys.insert(key);
    };
    loop {
        let (token, repaired) = tokens.next()?;
        let depth = stack.len();
        // A dictionary expects a key or its end.
        if let Some(Frame::Dict { keys, want_key }) = stack.last_mut()
            && *want_key
        {
            match token.kind {
                TokenKind::DictEnd => {
                    stack.pop();
                }
                TokenKind::Name(name) => {
                    let name = name.into_owned();
                    *want_key = false;
                    let twice = !keys.insert(name.clone());
                    if depth == 1 && top_is_dict {
                        top_key = Some(name.clone());
                        if repaired {
                            out.key_defect = true;
                        }
                    }
                    if repaired {
                        note(
                            &mut out,
                            &top_key,
                            top_is_dict,
                            token.start,
                            "a token the lexer repairs: a key with `#00` or a `#` without two \
                             hexadecimal digits (ISO 32000-2 §7.3.5)"
                                .to_owned(),
                        );
                    }
                    if twice {
                        note(
                            &mut out,
                            &top_key,
                            top_is_dict,
                            token.start,
                            format!(
                                "a dictionary with a duplicate key /{} (ISO 32000-2 §7.3.7; \
                                 readers differ on which value counts: Folioxide, qpdf and \
                                 poppler take the last, pyHanko and pypdf the first)",
                                String::from_utf8_lossy(&name)
                            ),
                        );
                    }
                    continue;
                }
                _ => return Err(()),
            }
            if stack.is_empty() {
                out.end = token.end;
                break;
            }
            continue;
        }
        // A value: it fills the slot of the dictionary that holds it.
        if let Some(Frame::Dict { want_key, .. }) = stack.last_mut() {
            *want_key = true;
        }
        let raw = bytes.get(token.start..token.end).unwrap_or_default();
        // A number's spelling is judged on its raw bytes below; any other repair is a defect.
        if repaired && !matches!(token.kind, TokenKind::Integer(_) | TokenKind::Real(_)) {
            note(
                &mut out,
                &top_key,
                top_is_dict,
                token.start,
                "a token the lexer repairs: a name with `#00` or a `#` without two hexadecimal \
                 digits (ISO 32000-2 §7.3.5), or a hexadecimal string with a character that is \
                 no hexadecimal digit (§7.3.4.3)"
                    .to_owned(),
            );
        }
        match token.kind {
            TokenKind::DictStart | TokenKind::ArrayStart => {
                if depth >= max_depth {
                    return Err(());
                }
                if depth == 0 {
                    top_is_dict = token.kind == TokenKind::DictStart;
                }
                stack.push(if token.kind == TokenKind::DictStart {
                    Frame::Dict {
                        keys: HashSet::new(),
                        want_key: true,
                    }
                } else {
                    Frame::Array
                });
                continue;
            }
            TokenKind::ArrayEnd => match stack.last() {
                Some(Frame::Array) => {
                    stack.pop();
                }
                _ => return Err(()),
            },
            TokenKind::Integer(_) => {
                if let Some(problem) = number_defect(raw, &token.kind) {
                    note(&mut out, &top_key, top_is_dict, token.start, problem);
                }
                // `N G R`: a reference, whose numbers are unsigned.
                let reference = matches!(tokens.peek(0), Some(TokenKind::Integer(_)))
                    && matches!(tokens.peek(1), Some(TokenKind::Keyword(b"R")));
                if reference {
                    let (generation, _) = tokens.next()?;
                    let (keyword, _) = tokens.next()?;
                    let generation_raw = bytes
                        .get(generation.start..generation.end)
                        .unwrap_or_default();
                    let signed = !is_unsigned(raw) || !is_unsigned(generation_raw);
                    if signed {
                        note(
                            &mut out,
                            &top_key,
                            top_is_dict,
                            token.start,
                            "a reference whose object or generation number has a sign".to_owned(),
                        );
                    }
                    let generation_defect = number_defect(generation_raw, &generation.kind);
                    // A generation beyond 16 bits (§7.3.10) is no reference to Folioxide's
                    // parser, and other readers may truncate it.
                    let target = match (&token.kind, &generation.kind) {
                        (TokenKind::Integer(value), TokenKind::Integer(generation))
                            if u16::try_from(*generation).is_ok() =>
                        {
                            u32::try_from(*value).ok()
                        }
                        _ => None,
                    };
                    match target {
                        Some(target)
                            if !signed
                                && generation_defect.is_none()
                                && number_defect(raw, &token.kind).is_none() =>
                        {
                            out.references.push(target);
                        }
                        _ => out.doubtful_reference = true,
                    }
                    if let Some(problem) = generation_defect {
                        note(&mut out, &top_key, top_is_dict, generation.start, problem);
                    }
                    if stack.is_empty() {
                        out.end = keyword.end;
                        break;
                    }
                    continue;
                }
            }
            TokenKind::Real(_) => {
                if let Some(problem) = number_defect(raw, &token.kind) {
                    note(&mut out, &top_key, top_is_dict, token.start, problem);
                }
            }
            TokenKind::LiteralString(_) | TokenKind::HexString(_) | TokenKind::Name(_) => {}
            TokenKind::Keyword(b"true" | b"false" | b"null") => {}
            TokenKind::Keyword(_)
            | TokenKind::DictEnd
            | TokenKind::BraceOpen
            | TokenKind::BraceClose => return Err(()),
        }
        if stack.is_empty() {
            out.end = token.end;
            break;
        }
    }
    out.tokens = tokens.read;
    out.is_dict = top_is_dict;
    Ok(out)
}

/// Why the raw bytes of a number token (`raw`, read by the lexer as `kind`) are not a canonical
/// unsigned integer: an object stream's header numbers and offsets (§7.5.7).
pub(crate) fn unsigned_integer_defect(raw: &[u8], kind: &TokenKind<'_>) -> Option<String> {
    if !is_unsigned(raw) {
        return Some(format!("`{}` is not an unsigned integer", shown(raw)));
    }
    number_defect(raw, kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(text: &str) -> Result<Scan, ()> {
        scan_value(text.as_bytes(), 0, &Limits::DEFAULT)
    }

    fn defect(text: &str) -> Option<String> {
        scan(text)
            .unwrap_or_else(|()| panic!("{text}: no value"))
            .defect
    }

    #[test]
    fn canonical_values_have_no_defect() {
        for text in [
            "0",
            "-0",
            "+17",
            "2147483647",
            "-2147483647",
            "0400",
            "00000000400",
            "-0000000400",
            "0000000004 00000 R",
            "400.",
            "+400",
            "-.5",
            ".5",
            "3.14",
            "1234567890123456789012345678901234567.0",
            "(a (b) c)",
            "<48 65>",
            "/Fl#61te",
            "true",
            "null",
            "5 0 R",
            "[1 0 R 2 0 R 3]",
            "[1 0 2]",
            "<< /A 1 /B << /A 2 >> /C [<< /A 1 >> << /A 2 >>] >>",
            "<< /Length 5 >>\nstream\nhello",
        ] {
            assert_eq!(defect(text), None, "{text}");
        }
    }

    #[test]
    fn number_spellings_are_defects() {
        for (text, needle) in [
            ("++2", "several signs"),
            ("+-260", "several signs"),
            ("--60", "several signs"),
            ("4294967296", "outside"),
            ("2147483648", "outside"),
            ("-2147483648", "outside"),
            ("123456789012", "outside"),
            ("99999999999999999999", "64-bit"),
            ("1000000000000000000000000000000", "64-bit"),
            ("1000000000000000000000000000000000000000", "64-bit"),
            ("1000000000000000000000000000000000000000.0", "longer"),
            ("400000000000000000000000000000000000000.0", "longer"),
            ("[72 600 272 +++630]", "several signs"),
            ("<< /Rect [0 0 0 4294967296] >>", "outside"),
            ("4294967296 0 R", "outside"),
            ("5 99999999999 R", "outside"),
            // M4 QA round 4, finding 2: zero-padded integers and references.
            ("000000000340", "longer than 11"),
            ("+00000000340", "longer than 11"),
            ("[300 300 400 000000000000000340]", "longer than 11"),
            ("0000000000004 0 R", "longer than 11"),
            ("4 000000000000 R", "longer than 11"),
        ] {
            let found = defect(text).unwrap_or_default();
            assert!(found.contains(needle), "{text}: {found}");
        }
        assert!(defect("+5 0 R").unwrap_or_default().contains("reference"));
        // A long token is shown cut, with its length.
        let padded = format!("{}340", "0".repeat(100_000));
        let found = defect(&padded).unwrap_or_default();
        assert!(found.contains("(100003 characters)"), "{}", found.len());
        assert!(found.len() < 400, "{}", found.len());
        // A zero-padded reference names no object every reader follows.
        let padded = format!("<< /Contents {}4 0 R >>", "0".repeat(300));
        let scanned = scan(&padded).unwrap();
        assert!(scanned.doubtful_reference && scanned.references.is_empty());
    }

    #[test]
    fn names_strings_and_keys() {
        assert!(
            defect("/Byte#00Range")
                .unwrap_or_default()
                .contains("repairs")
        );
        assert!(defect("/A#4").unwrap_or_default().contains("repairs"));
        assert!(defect("<4X65>").unwrap_or_default().contains("repairs"));
        let dup = scan("<< /A 1 /B 2 /A 3 >>").unwrap();
        assert!(dup.defect.unwrap().contains("duplicate key /A"));
        assert_eq!(dup.ambiguous_keys, [b"A".to_vec()].into());
        let nested = scan("<< /A 1 /B << /C 1 /C 2 >> /D ++4 >>").unwrap();
        assert_eq!(nested.ambiguous_keys, [b"B".to_vec(), b"D".to_vec()].into());
        assert!(!nested.key_defect);
        let key = scan("<< /Byte#00Range [0 1 2 3] >>").unwrap();
        assert!(key.key_defect);
        let array = scan("[<< /A 1 /A 2 >>]").unwrap();
        assert_eq!(array.ambiguous_keys, [WHOLE_VALUE.to_vec()].into());
    }

    #[test]
    fn malformed_values_are_refused() {
        for text in [
            "",
            "<< /A",
            "<< /A >>",
            "<< 1 2 >>",
            "<< /A 1 0 >>",
            "[1 0 R 0 R]",
            "[1 2",
            "endobj",
            "{ 1 }",
            ">>",
            "]",
        ] {
            assert!(scan(text).is_err(), "{text}");
        }
        // Nested beyond the limit.
        let deep = "[".repeat(600) + &"]".repeat(600);
        assert!(scan(&deep).is_err());
    }

    #[test]
    fn the_scan_ends_after_the_value_and_counts_tokens() {
        let text = "<< /A 1 0 R /B [1 2] >> endobj";
        let scanned = scan(text).unwrap();
        assert_eq!(scanned.end, text.find(" endobj").unwrap());
        assert_eq!(scanned.tokens, 11);
        // A value followed by a lexer error is still read.
        let scanned = scan("7 )").unwrap();
        assert_eq!((scanned.end, scanned.defect), (1, None));
    }

    #[test]
    fn the_scan_collects_the_references_of_every_value() {
        // Both values of a key written twice: a first-wins reader follows 1, a last-wins one 2.
        let scanned = scan("<< /A 1 0 R /A 2 0 R /B [3 0 R << /C 4 0 R >>] >>").unwrap();
        assert_eq!(scanned.references, [1, 2, 3, 4]);
        assert!(!scanned.doubtful_reference);
        // A reference whose numbers are not canonical names no object every reader follows.
        for text in [
            "<< /A +1 0 R >>",
            "<< /A 1 -0 R >>",
            "<< /A 4294967306 0 R >>",
        ] {
            let scanned = scan(text).unwrap();
            assert!(scanned.doubtful_reference, "{text}");
            assert!(scanned.defect.is_some(), "{text}");
        }
        // A generation beyond 16 bits (§7.3.10) is canonical, but readers may truncate it.
        let scanned = scan("<< /A 1 99999 R >>").unwrap();
        assert!(scanned.doubtful_reference && scanned.defect.is_none());
    }
}

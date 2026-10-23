//! The `/ByteRange` and `/Contents` placeholders of a signature dictionary: writing the
//! incremental update that holds them, locating their tokens in the output, patching the byte
//! range in place and sizing the reserve (ISO 32000-2 §12.8.1; M3 brief §4.1 and §4.2).
//!
//! [`write_placeholder`] is the PDF half of [`prepare`](crate::prepare::prepare), without any
//! cryptography: it appends one incremental update to the document's source with
//!
//! - the document's pending edits (same revision as the signature, ARCHITECTURE §A.6.1);
//! - the field, widget, page and AcroForm objects of the field placement
//!   ([`field`], brief §4.5);
//! - the signature dictionary, keys in this order: `/Type /Sig /Filter /Adobe.PPKLite
//!   /SubFilter … /M (D:…)`, then `/Name`, `/Reason`, `/Location`, `/ContactInfo` when given,
//!   then for a certification signature `/Reference [<</Type /SigRef /TransformMethod /DocMDP
//!   /TransformParams <</Type /TransformParams /P n /V /1.2>>>>]` (all direct; M4 brief §4.6),
//!   then `/ByteRange [0 a b c]` and `/Contents <00…00>` last, so the byte range lies in the first
//!   signed part. It is never compressed (an incremental update has no object streams), and
//!   `/Contents` is `2R` hexadecimal zeros with no white-space.
//!
//! and then fills in the byte range: `a` is the position of the `/Contents` `<`, `b` the
//! position just after its `>`, and `c` the length of the rest of the file. The values are
//! file-absolute (§12.8.1), written in plain decimal over the 10-digit placeholder
//! [`BYTE_RANGE_PLACEHOLDER`] and padded with spaces, so the length of the file never changes.
//! What remains for a signature is to hash `pdf[0..a] ‖ pdf[b..]` ([`PlaceholderPdf::digest`])
//! and to write the CMS as hexadecimal digits after the `<`.
//!
//! **Sizing** (brief §4.2, DECISIONS D10 D-7): the reserve `R` (bytes of DER that fit in
//! `/Contents`) is the caller's [`SignatureOptions::contents_reserve`] when given, else
//! [`default_contents_reserve`] of the exact CMS size: at least [`MIN_CONTENTS_RESERVE`].
//!
//! **Refusals** ([`check_signable`]; brief §4.5 "Preconditions", DECISIONS D10): a document
//! without source bytes, junk before `%PDF-` (byte ranges are file-absolute while the file's
//! offsets are not; pyHanko cannot read such files), a repaired cross-reference structure (other
//! readers may see another document: a full save comes first), and a certified document whose
//! DocMDP permissions are `P = 1` (§12.8.2.2). The other certification rules of M4 brief §4.6
//! belong to the field placement.

use std::fmt;
use std::ops::Range;

use folioxide_model::Document;
use folioxide_syntax::{
    Dict, IncrementalOptions, Lexer, Object, ObjectId, PdfString, Token, TokenKind,
};

use crate::algorithms::DigestAlgorithm;
use crate::docmdp;
use crate::error::{Error, Result};
use crate::field::{self, FieldPlan};
use crate::prepare::SignatureOptions;

/// The value each of the last three `/ByteRange` numbers has before it is patched: ten digits,
/// enough for files up to 9,999,999,999 bytes (brief §4.2).
pub const BYTE_RANGE_PLACEHOLDER: i64 = 9_999_999_999;

/// The largest value a patched `/ByteRange` number can have: it must fit in the ten digits of
/// [`BYTE_RANGE_PLACEHOLDER`].
pub const MAX_BYTE_RANGE_VALUE: u64 = 9_999_999_999;

/// The smallest default `/Contents` reserve, in bytes of DER (brief §4.2, D-7).
pub const MIN_CONTENTS_RESERVE: usize = 8192;

/// The largest `/Contents` reserve, in bytes of DER (4 MiB, brief §4.2).
pub const MAX_CONTENTS_RESERVE: usize = 4 * 1024 * 1024;

/// The slack the default reserve adds to the exact CMS size before rounding (brief §4.2).
pub const RESERVE_MARGIN: usize = 512;

/// The default reserve is a multiple of this many bytes (brief §4.2).
pub const RESERVE_GRANULE: usize = 1024;

/// The default `/Contents` reserve for a CMS of at most `needed` bytes:
/// `max(8192, round_up_1024(needed + 512))` (brief §4.2). In M4 a timestamp reserve joins it.
///
/// ```
/// use folioxide_sign::placeholder::default_contents_reserve;
///
/// assert_eq!(default_contents_reserve(3000), 8192);
/// assert_eq!(default_contents_reserve(7681), 9216);
/// ```
pub fn default_contents_reserve(needed: usize) -> usize {
    let padded = needed.saturating_add(RESERVE_MARGIN);
    let rounded = padded
        .div_ceil(RESERVE_GRANULE)
        .saturating_mul(RESERVE_GRANULE);
    rounded.max(MIN_CONTENTS_RESERVE)
}

/// The `/Contents` reserve for a CMS of at most `needed` bytes: `explicit` when given, else
/// [`default_contents_reserve`].
///
/// ```
/// use folioxide_sign::placeholder::contents_reserve;
/// use folioxide_sign::Error;
///
/// assert_eq!(contents_reserve(None, 3000)?, 8192);
/// assert_eq!(contents_reserve(Some(4000), 3000)?, 4000);
/// assert!(matches!(
///     contents_reserve(Some(100), 3000),
///     Err(Error::PlaceholderTooSmall { needed: 3000, reserved: 100 })
/// ));
/// # Ok::<(), Error>(())
/// ```
///
/// # Errors
/// - [`Error::PlaceholderTooSmall`] when `explicit` is below `needed`.
/// - [`Error::InvalidArgument`] when the reserve is 0 or above [`MAX_CONTENTS_RESERVE`].
pub fn contents_reserve(explicit: Option<usize>, needed: usize) -> Result<usize> {
    let reserve = match explicit {
        Some(reserved) if reserved < needed => {
            return Err(Error::PlaceholderTooSmall { needed, reserved });
        }
        Some(reserved) => reserved,
        None => default_contents_reserve(needed),
    };
    check_reserve(reserve)?;
    Ok(reserve)
}

/// Checks that `reserve` is between 1 and [`MAX_CONTENTS_RESERVE`].
fn check_reserve(reserve: usize) -> Result<()> {
    if reserve == 0 || reserve > MAX_CONTENTS_RESERVE {
        return Err(Error::InvalidArgument(format!(
            "the /Contents reserve must be between 1 and {MAX_CONTENTS_RESERVE} bytes, not \
             {reserve}"
        )));
    }
    Ok(())
}

/// Checks that a signature can be appended to `doc` (brief §4.5 "Preconditions", DECISIONS
/// D10): the checks [`prepare`](crate::prepare::prepare) and [`write_placeholder`] make before
/// any other work.
///
/// # Errors
/// - [`Error::InvalidArgument`]: the document has no source bytes (a new document: save it and
///   sign the saved file).
/// - [`Error::Unsupported`]: bytes before `%PDF-` ("save a full copy first"); a repaired
///   cross-reference structure or an object away from its offset ("full save required", naming
///   the existing signatures a full save would invalidate).
/// - [`Error::DocMdpForbids`]: the document is certified with DocMDP permissions `P = 1` (the
///   catalog's `/Perms /DocMDP` signature, or a signed field's DocMDP reference; M4 brief §4.6
///   rule (b)).
/// - The errors of [`Store::resolve`](folioxide_syntax::Store::resolve) while reading the
///   catalog.
pub fn check_signable(doc: &Document) -> Result<()> {
    let store = doc.store();
    if !store.has_source() {
        return Err(Error::InvalidArgument(
            "the document has no source bytes to append a signature to; save it, open the \
             saved file and sign that"
                .to_owned(),
        ));
    }
    let junk = store.header_offset();
    if junk != 0 {
        return Err(Error::Unsupported(format!(
            "{junk} bytes before %PDF-; save a full copy first (signature byte ranges count from \
             byte 0 of the file)"
        )));
    }
    if store.structure_repaired() {
        let existing = field::signature_fields(doc)
            .map(|fields| fields.iter().filter(|f| f.signed).count())
            .unwrap_or(0);
        let mut message = "the file's cross-reference structure was repaired when it was opened, \
                           so other readers may see another document: full save required"
            .to_owned();
        match existing {
            0 => {}
            1 => message.push_str("; it would invalidate the 1 existing signature"),
            n => message.push_str(&format!(
                "; it would invalidate the {n} existing signatures"
            )),
        }
        return Err(Error::Unsupported(message));
    }
    store.check_incremental()?;
    if docmdp::certification(doc)?.is_some_and(|c| c.p == 1) {
        return Err(Error::DocMdpForbids(
            "DocMDP rule (b): the document is certified with DocMDP permissions P = 1: no \
             changes, signatures included, are allowed (ISO 32000-2 §12.8.2.2)"
                .to_owned(),
        ));
    }
    Ok(())
}

/// A document with a signature placeholder appended: the complete output with the `/ByteRange`
/// patched and `/Contents` all zeros, and where its parts are (brief §4.2).
///
/// The file is `pdf`; the source is its first `source_len` bytes, unchanged.
/// `byte_range == [0, a, b, pdf.len() - b]` with `contents_range == (a, b)`.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub struct PlaceholderPdf {
    /// The whole file: the source, then the incremental update.
    pub pdf: Vec<u8>,
    /// The patched `/ByteRange`: `[0, a, b, c]`, `c = pdf.len() - b`.
    pub byte_range: [u64; 4],
    /// Where the `/ByteRange` array token is, `[` to after `]`, absolute.
    pub byte_range_token: (u64, u64),
    /// Where the `/Contents` hexadecimal string is, `[a, b)`: from its `<` to after its `>`.
    pub contents_range: (u64, u64),
    /// The signature dictionary's object (a new number).
    pub sig_dict: ObjectId,
    /// The signed field's object: the new merged field and widget, or the existing field.
    pub field: ObjectId,
    /// The signed field's fully qualified name.
    pub field_name: String,
    /// Whether the field (and its widget) is new.
    pub field_created: bool,
    /// The length of the source, where the update starts.
    pub source_len: u64,
    /// Observations, for example an AcroForm with `/NeedAppearances true` (left unchanged).
    pub warnings: Vec<String>,
}

impl PlaceholderPdf {
    /// `R`: the bytes of DER that fit in `/Contents` (half the hexadecimal digits).
    pub fn contents_capacity(&self) -> usize {
        let (a, b) = self.contents_range;
        usize::try_from(b.saturating_sub(a).saturating_sub(2) / 2).unwrap_or(0)
    }

    /// The two signed parts: `pdf[0..a]` and `pdf[b..]` (§12.8.1).
    pub fn signed_parts(&self) -> (&[u8], &[u8]) {
        signed_parts(&self.pdf, self.contents_range)
    }

    /// The digest of the signed parts, `H(pdf[0..a] ‖ pdf[b..])`, streamed (brief §4.2 step 5).
    pub fn digest(&self, algorithm: DigestAlgorithm) -> Vec<u8> {
        signed_digest(&self.pdf, self.contents_range, algorithm)
    }
}

impl fmt::Debug for PlaceholderPdf {
    /// Prints the layout, not the bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlaceholderPdf")
            .field("len", &self.pdf.len())
            .field("byte_range", &self.byte_range)
            .field("contents_range", &self.contents_range)
            .field("sig_dict", &self.sig_dict)
            .field("field", &self.field)
            .field("field_name", &self.field_name)
            .field("field_created", &self.field_created)
            .field("source_len", &self.source_len)
            .field("warnings", &self.warnings)
            .finish_non_exhaustive()
    }
}

/// `pdf[0..a]` and `pdf[b..]`, empty where the range is out of bounds.
pub(crate) fn signed_parts(pdf: &[u8], (a, b): (u64, u64)) -> (&[u8], &[u8]) {
    let a = usize::try_from(a).unwrap_or(usize::MAX);
    let b = usize::try_from(b).unwrap_or(usize::MAX);
    (
        pdf.get(..a).unwrap_or_default(),
        pdf.get(b..).unwrap_or_default(),
    )
}

/// `H(pdf[0..a] ‖ pdf[b..])`, streamed.
pub(crate) fn signed_digest(
    pdf: &[u8],
    contents_range: (u64, u64),
    algorithm: DigestAlgorithm,
) -> Vec<u8> {
    let (first, second) = signed_parts(pdf, contents_range);
    let mut hasher = algorithm.hasher();
    hasher.update(first);
    hasher.update(second);
    hasher.finalize()
}

/// Appends a signature placeholder to `doc` as [`prepare`](crate::prepare::prepare) would, and
/// returns the patched file, without any cryptography; `doc` is not changed.
///
/// The reserve is [`SignatureOptions::contents_reserve`], or [`MIN_CONTENTS_RESERVE`] bytes when
/// it is `None` (only `prepare` knows the size of the CMS). [`SignatureOptions::digest`] is not
/// used. This is for callers that build the whole CMS themselves, and for inspecting what a
/// signature adds to a document.
///
/// ```
/// use folioxide_model::{Document, PdfDate};
/// use folioxide_sign::placeholder::write_placeholder;
/// use folioxide_sign::prepare::SignatureOptions;
/// use folioxide_syntax::OpenOptions;
///
/// let source = folioxide_testkit::fixtures::syntax::minimal();
/// let doc = Document::open(source.clone(), &OpenOptions::default())?;
/// let time = PdfDate::parse(b"D:20261010120000Z").unwrap();
/// let placeholder = write_placeholder(&doc, &SignatureOptions::new(time))?;
///
/// let [zero, a, b, c] = placeholder.byte_range;
/// assert_eq!((zero, b + c), (0, placeholder.pdf.len() as u64));
/// assert_eq!(placeholder.pdf[a as usize], b'<');
/// assert!(placeholder.pdf.starts_with(&source));
/// assert_eq!(placeholder.field_name, "Signature1");
/// # Ok::<(), folioxide_sign::Error>(())
/// ```
///
/// # Errors
/// - The refusals of [`check_signable`].
/// - The certification rules of M4 brief §4.6 ([`Error::DocMdpForbids`]; see
///   [`SignatureOptions::certification`]).
/// - The appearance errors of a visible signature ([`SignatureOptions::appearance`]; see
///   [`appearance`](crate::appearance)). Without a certificate, the default appearance text
///   names the signer only by [`SignatureOptions::name`].
/// - The field placement errors (brief §4.5): [`Error::PageOutOfRange`],
///   [`Error::InvalidArgument`], [`Error::NotFound`], [`Error::Unsupported`]; see
///   [`FieldSpec`](crate::field::FieldSpec) and [`FieldMode`](crate::field::FieldMode).
/// - [`Error::InvalidArgument`]: a reserve of 0 or above [`MAX_CONTENTS_RESERVE`]; a file too
///   large for the ten-digit byte range.
/// - The errors of [`incremental_suffix_with_overlay`](folioxide_syntax::incremental_suffix_with_overlay).
pub fn write_placeholder(doc: &Document, options: &SignatureOptions) -> Result<PlaceholderPdf> {
    let reserve = options.contents_reserve.unwrap_or(MIN_CONTENTS_RESERVE);
    check_reserve(reserve)?;
    check_signable(doc)?;
    // No certificate here: the default appearance text names the signer only by
    // `options.name`.
    let plan = field::plan(doc, options, None)?;
    write_with_plan(doc, plan, options, reserve)
}

/// Writes the update for a field placement `plan` with a reserve of `reserve` bytes, then
/// patches the byte range (brief §4.2 steps 2–4). The caller has run [`check_signable`].
pub(crate) fn write_with_plan(
    doc: &Document,
    plan: FieldPlan,
    options: &SignatureOptions,
    reserve: usize,
) -> Result<PlaceholderPdf> {
    check_reserve(reserve)?;
    let store = doc.store();
    let FieldPlan {
        sig,
        field,
        name,
        created,
        mut objects,
        warnings,
    } = plan;
    objects.insert(sig, Object::Dict(signature_dict(options, reserve)));

    let layout = store.incremental_suffix_with_overlay(
        &IncrementalOptions::new().with_deterministic(true),
        &objects,
    )?;
    let source = store.source();
    let source_len = source.len() as u64;
    if layout.base() != source_len {
        return Err(internal(
            "the update does not start at the end of the source",
        ));
    }
    let span = layout
        .spans()
        .iter()
        .find(|(id, _)| *id == sig)
        .map(|(_, span)| span.clone())
        .ok_or_else(|| internal("the update does not hold the signature dictionary"))?;

    let mut pdf = Vec::with_capacity(source.len().saturating_add(layout.suffix().len()));
    pdf.extend_from_slice(source);
    pdf.extend_from_slice(layout.suffix());

    let (byte_range_token, contents) = locate_placeholders(&pdf, span, reserve)?;
    let total = pdf.len() as u64;
    let a = contents.start as u64;
    let b = contents.end as u64;
    let byte_range = [0, a, b, total.saturating_sub(b)];
    let token = pdf
        .get_mut(byte_range_token.clone())
        .ok_or_else(|| internal("the /ByteRange token is outside the file"))?;
    patch_byte_range(token, byte_range)?;

    Ok(PlaceholderPdf {
        pdf,
        byte_range,
        byte_range_token: (byte_range_token.start as u64, byte_range_token.end as u64),
        contents_range: (a, b),
        sig_dict: sig,
        field,
        field_name: name,
        field_created: created,
        source_len,
        warnings,
    })
}

/// The signature dictionary with its placeholders (brief §4.1), keys in the order of the module
/// documentation: `/ByteRange` before `/Contents`, `/Contents` last.
fn signature_dict(options: &SignatureOptions, reserve: usize) -> Dict {
    let mut dict = Dict::with_capacity(11);
    dict.insert("Type", Object::name("Sig"));
    dict.insert("Filter", Object::name("Adobe.PPKLite"));
    dict.insert("SubFilter", Object::name(options.sub_filter.name()));
    // §12.8.1 Table 258: the signing time as a date string (§7.9.4); PAdES B-B requires /M
    // and has no CMS signing-time (brief §4.6).
    dict.insert(
        "M",
        Object::String(PdfString::new_literal(
            options.signing_time.to_pdf_string().into_bytes(),
        )),
    );
    let texts = [
        ("Name", &options.name),
        ("Reason", &options.reason),
        ("Location", &options.location),
        ("ContactInfo", &options.contact_info),
    ];
    for (key, value) in texts {
        if let Some(value) = value {
            dict.insert(key, field::text_object(value));
        }
    }
    // §12.8.2.2: a certification signature's DocMDP transform, before /ByteRange so that
    // /Contents stays last (M4 brief §4.6).
    if let Some(permissions) = options.certification {
        dict.insert(
            "Reference",
            Object::Array(vec![Object::Dict(docmdp::reference_dictionary(
                permissions,
            ))]),
        );
    }
    dict.insert(
        "ByteRange",
        Object::Array(vec![
            Object::Int(0),
            Object::Int(BYTE_RANGE_PLACEHOLDER),
            Object::Int(BYTE_RANGE_PLACEHOLDER),
            Object::Int(BYTE_RANGE_PLACEHOLDER),
        ]),
    );
    dict.insert("Contents", Object::hex_string(vec![0u8; reserve]));
    dict
}

/// The text of the unpatched `/ByteRange` array, as the serializer writes it (brief §1:
/// arrays are `[a b c]` with single spaces).
fn byte_range_placeholder_text() -> String {
    format!("[0 {BYTE_RANGE_PLACEHOLDER} {BYTE_RANGE_PLACEHOLDER} {BYTE_RANGE_PLACEHOLDER}]")
}

/// Finds the `/ByteRange` array token and the `/Contents` hexadecimal string token of the
/// signature dictionary written at `span` (brief §4.2 step 3), checking that they are exactly
/// the placeholders: the `/ByteRange` text as [`byte_range_placeholder_text`] and a `/Contents`
/// of `2 * reserve` digits without white-space.
fn locate_placeholders(
    pdf: &[u8],
    span: Range<u64>,
    reserve: usize,
) -> Result<(Range<usize>, Range<usize>)> {
    let start = usize::try_from(span.start).map_err(|_| internal("span out of range"))?;
    let end = usize::try_from(span.end).map_err(|_| internal("span out of range"))?;
    let entries = dict_value_spans(pdf, start, end)?;
    let value_of = |key: &[u8]| {
        entries
            .iter()
            .find(|(k, _)| k.as_slice() == key)
            .map(|(_, range)| range.clone())
    };
    let byte_range = value_of(b"ByteRange")
        .ok_or_else(|| internal("the signature dictionary has no /ByteRange"))?;
    let contents = value_of(b"Contents")
        .ok_or_else(|| internal("the signature dictionary has no /Contents"))?;
    if pdf.get(byte_range.clone()) != Some(byte_range_placeholder_text().as_bytes()) {
        return Err(internal(
            "the /ByteRange placeholder was not written as expected",
        ));
    }
    // `<` + 2R digits + `>`: no white-space (pyHanko's ENTIRE_FILE formula, brief §1).
    let expected_len = reserve.checked_mul(2).and_then(|n| n.checked_add(2));
    let digits_ok = pdf
        .get(contents.start.saturating_add(1)..contents.end.saturating_sub(1))
        .is_some_and(|digits| digits.iter().all(|&d| d == b'0'));
    if Some(contents.len()) != expected_len
        || pdf.get(contents.start) != Some(&b'<')
        || pdf.get(contents.end.wrapping_sub(1)) != Some(&b'>')
        || !digits_ok
        || byte_range.end > contents.start
    {
        return Err(internal(
            "the /Contents placeholder was not written as expected",
        ));
    }
    Ok((byte_range, contents))
}

/// The byte range of the value of every top-level key of the dictionary of the indirect object
/// whose `N G obj` header is at `start` in `data` (lexing stops at `end`), in file order: the
/// key without its `/`, and the value's token range (from `[` to after `]` for an array, `<<` to
/// after `>>` for a dictionary, `N G R` for a reference).
///
/// # Errors
/// [`ErrorCode::Syntax`](folioxide_syntax::ErrorCode::Syntax) when the bytes are not an
/// indirect object holding a dictionary, or nest deeper than 64 levels.
pub(crate) fn dict_value_spans(
    data: &[u8],
    start: usize,
    end: usize,
) -> Result<Vec<(Vec<u8>, Range<usize>)>> {
    const MAX_NESTING: usize = 64;
    let bad = |message: &str| dict_error(start, message);
    let region = data
        .get(..end)
        .ok_or_else(|| bad("the object lies outside the data"))?;
    let mut lexer = Lexer::new(region, start);
    let number = next_token(&mut lexer, start)?.kind;
    let generation = next_token(&mut lexer, start)?.kind;
    let keyword = next_token(&mut lexer, start)?.kind;
    let is_header = matches!(number, TokenKind::Integer(_))
        && matches!(generation, TokenKind::Integer(_))
        && keyword == TokenKind::Keyword(b"obj");
    if !is_header || next_token(&mut lexer, start)?.kind != TokenKind::DictStart {
        return Err(bad("not an indirect object holding a dictionary"));
    }

    let mut entries = Vec::new();
    loop {
        let key = next_token(&mut lexer, start)?;
        let key = match key.kind {
            TokenKind::DictEnd => break,
            TokenKind::Name(name) => name.into_owned(),
            _ => return Err(bad("a dictionary key is not a name")),
        };
        let value = next_token(&mut lexer, start)?;
        let value_start = value.start;
        let value_end = match value.kind {
            TokenKind::ArrayStart | TokenKind::DictStart => {
                let mut depth = 1usize;
                loop {
                    let token = next_token(&mut lexer, start)?;
                    match token.kind {
                        TokenKind::ArrayStart | TokenKind::DictStart => {
                            depth += 1;
                            if depth > MAX_NESTING {
                                return Err(bad("the value nests too deeply"));
                            }
                        }
                        TokenKind::ArrayEnd | TokenKind::DictEnd => {
                            depth -= 1;
                            if depth == 0 {
                                break token.end;
                            }
                        }
                        _ => {}
                    }
                }
            }
            TokenKind::Integer(_) => {
                // `N G R` is one value (§7.3.10); otherwise the integer stands alone.
                let after = lexer.position();
                let generation = lexer.next_token()?;
                let keyword = lexer.next_token()?;
                match (generation, keyword) {
                    (Some(g), Some(r))
                        if matches!(g.kind, TokenKind::Integer(_))
                            && r.kind == TokenKind::Keyword(b"R") =>
                    {
                        r.end
                    }
                    _ => {
                        lexer.set_position(after);
                        value.end
                    }
                }
            }
            TokenKind::ArrayEnd | TokenKind::DictEnd => {
                return Err(bad("a dictionary value is missing"));
            }
            _ => value.end,
        };
        entries.push((key, value_start..value_end));
    }
    Ok(entries)
}

/// The next token of a signature dictionary's object at `start`; the end of the data is an
/// error.
fn next_token<'a>(lexer: &mut Lexer<'a>, start: usize) -> Result<Token<'a>> {
    lexer
        .next_token()?
        .ok_or_else(|| dict_error(start, "the object ends early"))
}

/// A syntax error about the signature dictionary's object at `start`.
fn dict_error(start: usize, message: &str) -> Error {
    Error::Syntax(folioxide_syntax::Error::syntax(
        start as u64,
        format!("signature dictionary: {message}"),
    ))
}

/// Overwrites the `/ByteRange` placeholder `token` (from `[` to after `]`) with
/// `[0 a b c` in plain decimal, spaces, and `]`: the same length (brief §4.2 step 4, R-1).
///
/// # Errors
/// [`Error::InvalidArgument`] when a value does not fit in ten digits ("file too large for the
/// ByteRange placeholder") or the text does not fit in the token.
pub(crate) fn patch_byte_range(token: &mut [u8], values: [u64; 4]) -> Result<()> {
    if values.iter().any(|&v| v > MAX_BYTE_RANGE_VALUE) {
        return Err(Error::InvalidArgument(format!(
            "file too large for the ByteRange placeholder: signed files are limited to \
             {MAX_BYTE_RANGE_VALUE} bytes"
        )));
    }
    let [v0, v1, v2, v3] = values;
    let text = format!("[{v0} {v1} {v2} {v3}");
    let Some(padding) = token.len().checked_sub(text.len().saturating_add(1)) else {
        return Err(Error::InvalidArgument(
            "the /ByteRange values do not fit in the placeholder".to_owned(),
        ));
    };
    let patched = text
        .bytes()
        .chain(std::iter::repeat_n(b' ', padding))
        .chain(std::iter::once(b']'));
    for (slot, byte) in token.iter_mut().zip(patched) {
        *slot = byte;
    }
    Ok(())
}

/// An error for a broken internal invariant of the placeholder writer.
fn internal(message: &str) -> Error {
    Error::Syntax(folioxide_syntax::Error::new(
        folioxide_syntax::ErrorCode::Syntax,
        format!("signature placeholder: {message}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_reserve_rounds_up_with_a_floor() {
        assert_eq!(default_contents_reserve(0), MIN_CONTENTS_RESERVE);
        assert_eq!(default_contents_reserve(7680), MIN_CONTENTS_RESERVE);
        assert_eq!(default_contents_reserve(7681), 9216);
        assert_eq!(default_contents_reserve(10_000), 10_240 + 1024);
        // Saturating, never overflowing; `contents_reserve` refuses such a size.
        assert!(default_contents_reserve(usize::MAX) > MAX_CONTENTS_RESERVE);
    }

    #[test]
    fn reserve_bounds() {
        assert_eq!(contents_reserve(None, 100).unwrap(), 8192);
        assert_eq!(contents_reserve(Some(100), 100).unwrap(), 100);
        assert!(matches!(
            contents_reserve(Some(99), 100),
            Err(Error::PlaceholderTooSmall {
                needed: 100,
                reserved: 99
            })
        ));
        for bad in [Some(0), Some(MAX_CONTENTS_RESERVE + 1)] {
            let err = contents_reserve(bad, 0).unwrap_err();
            assert_eq!(err.code(), folioxide_syntax::ErrorCode::InvalidArgument);
        }
        // The default of a huge CMS is over the limit too.
        let err = contents_reserve(None, MAX_CONTENTS_RESERVE).unwrap_err();
        assert_eq!(err.code(), folioxide_syntax::ErrorCode::InvalidArgument);
        assert_eq!(
            contents_reserve(Some(MAX_CONTENTS_RESERVE), 0).unwrap(),
            MAX_CONTENTS_RESERVE
        );
    }

    #[test]
    fn patch_keeps_the_width_and_writes_no_leading_zeros() {
        let placeholder = byte_range_placeholder_text();
        assert_eq!(placeholder.len(), 36);
        for values in [
            [0, 1, 2, 3],
            [0, 1234, 5678, 90],
            [0, 9_999_999_998, 9_999_999_999, 0],
            [
                0,
                MAX_BYTE_RANGE_VALUE,
                MAX_BYTE_RANGE_VALUE,
                MAX_BYTE_RANGE_VALUE,
            ],
        ] {
            let mut token = placeholder.clone().into_bytes();
            patch_byte_range(&mut token, values).unwrap();
            assert_eq!(token.len(), placeholder.len());
            let text = String::from_utf8(token).unwrap();
            let [v0, v1, v2, v3] = values;
            let expected = format!("[{v0} {v1} {v2} {v3}");
            assert!(text.starts_with(&expected), "{text}");
            assert!(text.ends_with(']'));
            assert!(
                text[expected.len()..text.len() - 1]
                    .bytes()
                    .all(|b| b == b' ')
            );
        }
    }

    #[test]
    fn patch_refuses_values_beyond_ten_digits() {
        let mut token = byte_range_placeholder_text().into_bytes();
        let err = patch_byte_range(&mut token, [0, 1, MAX_BYTE_RANGE_VALUE + 1, 0]).unwrap_err();
        assert_eq!(err.code(), folioxide_syntax::ErrorCode::InvalidArgument);
        assert!(err.to_string().contains("file too large"), "{err}");
        // A token too short for the text is refused, not overrun.
        let mut short = b"[0 1]".to_vec();
        assert!(patch_byte_range(&mut short, [0, 10, 20, 30]).is_err());
        assert_eq!(short, b"[0 1]");
    }

    #[test]
    fn dict_value_spans_finds_every_top_level_value() {
        let data =
            b"xx 12 0 obj\n<</A [1 [2] 3] /B 4 0 R /C <00> /D 5 /E <</F 6>> /G (x)>>\nendobj\n";
        let entries = dict_value_spans(data, 3, data.len()).unwrap();
        let text: Vec<(String, &str)> = entries
            .iter()
            .map(|(k, r)| {
                (
                    String::from_utf8(k.clone()).unwrap(),
                    std::str::from_utf8(&data[r.clone()]).unwrap(),
                )
            })
            .collect();
        assert_eq!(
            text,
            [
                ("A".to_owned(), "[1 [2] 3]"),
                ("B".to_owned(), "4 0 R"),
                ("C".to_owned(), "<00>"),
                ("D".to_owned(), "5"),
                ("E".to_owned(), "<</F 6>>"),
                ("G".to_owned(), "(x)"),
            ]
        );
    }

    #[test]
    fn dict_value_spans_rejects_what_is_not_a_dictionary_object() {
        for data in [
            &b"1 0 obj\n[1 2]\nendobj\n"[..],
            b"1 0 obj\n<</A 1",
            b"<</A 1>>",
            b"1 0 obj\n<<1 2>>\nendobj\n",
            b"1 0 obj\n<</A>>\nendobj\n",
        ] {
            assert!(dict_value_spans(data, 0, data.len()).is_err(), "{data:?}");
        }
        // Nesting is bounded.
        let mut deep = b"1 0 obj\n<</A ".to_vec();
        deep.extend(std::iter::repeat_n(b'[', 100));
        deep.extend(std::iter::repeat_n(b']', 100));
        deep.extend_from_slice(b">>\nendobj\n");
        assert!(dict_value_spans(&deep, 0, deep.len()).is_err());
        // An end past the data is an error, not a panic.
        assert!(dict_value_spans(b"1 0 obj", 0, 100).is_err());
    }

    #[test]
    fn signed_parts_never_panic() {
        let pdf = b"0123456789";
        assert_eq!(signed_parts(pdf, (3, 5)), (&b"012"[..], &b"56789"[..]));
        assert_eq!(signed_parts(pdf, (30, 50)), (&b""[..], &b""[..]));
        assert_eq!(
            signed_parts(pdf, (u64::MAX, u64::MAX)),
            (&b""[..], &b""[..])
        );
        assert_eq!(
            signed_digest(pdf, (3, 5), DigestAlgorithm::Sha256),
            DigestAlgorithm::Sha256.digest(&[b"012", b"56789"])
        );
    }
}

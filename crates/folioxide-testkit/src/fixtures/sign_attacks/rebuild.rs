//! Updates that read differently once a reader rebuilds the cross-reference data from the bytes
//! (M4 QA round 5; manager rulings R-17, R-18 and R-21): poppler 24.02 rebuilds when it finds no
//! `startxref` in the last 1,024 bytes of the file, PDFium when an entry is not 20 bytes long or
//! junk precedes `startxref`, and a rebuilding reader takes object text it finds in stream data,
//! strings and comments, and every member of every object stream, for objects.
//!
//! - **Padded tails**: a valid fill followed by tens of kilobytes of end-of-lines, spaces, NUL,
//!   comments or a mix after its `%%EOF` ([`tail_padded`]).
//! - **Object text inside data**: a fill whose new appearance stream, or whose value string,
//!   holds `4 0 obj … endobj` at the start of a line; and the control of a 4 MiB line of digits
//!   in an appearance stream ([`parser_ap_stream_long_digit_line`], which the scan reads in
//!   linear time).
//! - **A corrupted `startxref`**.
//! - **Hidden object-stream members**: an update whose new object stream holds a page its
//!   section does not list (ruling R-18).
//! - **Non-canonical tables**: a subsection header padded with zeros, 19-byte entries (ruling
//!   R-21).
//!
//! Every generator takes a **signed** document and appends one revision. `None` when an
//! expected object is missing.

use folioxide_syntax::{Dict, Object, ObjectId, OpenOptions, Store, Stream, StreamData};

use super::parser_diff::{raw_update, ser, stream_bytes};
use super::{last_startxref, with_incremental};
use crate::fixtures::forms::{self, AMOUNT, Fill, field_by_name};

/// The text a rebuilding reader takes for object 4 (the form's page content, painted black):
/// QA's payload (M4 QA round 5, findings 10 and 13).
const FAKE_PAGE_CONTENT: &str =
    "4 0 obj\n<< /Length 20 >>\nstream\n0 g 0 0 612 792 re f\nendstream\nendobj";

/// The bytes of padding the tail generators append (QA used 31,500 to 40,000).
const TAIL_PAD: usize = 40_000;

/// `pdf` filled (`Amount` = "900 EUR" with a new appearance), then `pad` repeated after the
/// update's `%%EOF` until at least `len` bytes follow it.
pub fn tail_padded(pdf: &[u8], pad: &[u8], len: usize) -> Option<Vec<u8>> {
    if pad.is_empty() {
        return None;
    }
    let mut out = super::form_fill_text_value_and_ap(pdf)?;
    let mut added = 0;
    while added < len {
        out.extend_from_slice(pad);
        added += pad.len();
    }
    Some(out)
}

/// `parser_tail_pad_lf` (M4 QA round 5, finding 17, variant A1-r6-tailpad-lf-40k): a fill, then
/// 40,000 line feeds.
pub fn parser_tail_pad_lf(pdf: &[u8]) -> Option<Vec<u8>> {
    tail_padded(pdf, b"\n", TAIL_PAD)
}

/// `parser_tail_pad_space` (finding 18): 40,000 spaces.
pub fn parser_tail_pad_space(pdf: &[u8]) -> Option<Vec<u8>> {
    tail_padded(pdf, b" ", TAIL_PAD)
}

/// `parser_tail_pad_nul` (finding 19): 40,000 NUL bytes.
pub fn parser_tail_pad_nul(pdf: &[u8]) -> Option<Vec<u8>> {
    tail_padded(pdf, b"\0", TAIL_PAD)
}

/// `parser_tail_pad_crlf` (finding 20): 20,000 CR LF pairs.
pub fn parser_tail_pad_crlf(pdf: &[u8]) -> Option<Vec<u8>> {
    tail_padded(pdf, b"\r\n", TAIL_PAD)
}

/// `parser_tail_pad_comment` (findings 10 and 16, variant A1-r5-tail-pad-comment-31500): 31,500
/// bytes of comment lines.
pub fn parser_tail_pad_comment(pdf: &[u8]) -> Option<Vec<u8>> {
    tail_padded(pdf, b"% padding comment line\n", 31_500)
}

/// `parser_tail_pad_mixed` (findings 21 and 22): form feeds, tabs, spaces, line feeds and
/// comments mixed.
pub fn parser_tail_pad_mixed(pdf: &[u8]) -> Option<Vec<u8>> {
    tail_padded(pdf, b"\x0c\t \n% c\r\n  \t\n", TAIL_PAD)
}

/// `parser_tail_extra_eol`: a fill, then one more end-of-line than an update writes after its
/// `%%EOF` (three bytes in all; manager ruling R-17 (b) allows two).
pub fn parser_tail_extra_eol(pdf: &[u8]) -> Option<Vec<u8>> {
    tail_padded(pdf, b"\n\n", 2)
}

/// `parser_fake_object_in_ap_stream` (finding 13, variants A1-r5-layout-fake-object-in-ap-stream-
/// data, C3-r6-tailpad-fill-*): `Amount` filled with a new appearance stream whose data holds
/// [`FAKE_PAGE_CONTENT`] at the start of a line, unencoded.
pub fn parser_fake_object_in_ap_stream(pdf: &[u8]) -> Option<Vec<u8>> {
    fill_with_ap_data(pdf, format!("{FAKE_PAGE_CONTENT}\n").as_bytes())
}

/// The length of the digit line of [`parser_ap_stream_long_digit_line`]: 4 MiB (QA timed 1 to
/// 16 MB).
pub const LONG_DIGIT_LINE: usize = 4 << 20;

/// `parser_ap_stream_long_digit_line` (M4 closing round, findings 2 and 6; variants
/// `gd_digits*MB`, `perf_digits`): `Amount` filled with a new appearance stream whose data holds,
/// after its drawing, one line of [`LONG_DIGIT_LINE`] digits `1`, unencoded. No reader takes it
/// for structure, so it stays a fill; a scan that read the digit run again from every 255-byte
/// piece of the line took minutes (an ASCIIHex image with a blank area holds such a line too).
pub fn parser_ap_stream_long_digit_line(pdf: &[u8]) -> Option<Vec<u8>> {
    let mut data = vec![b'1'; LONG_DIGIT_LINE];
    data.push(b'\n');
    fill_with_ap_data(pdf, &data)
}

/// `pdf` with `Amount` filled ("900 EUR") and a new appearance stream (unencoded) whose data is
/// a small drawing, a line feed and `extra`.
fn fill_with_ap_data(pdf: &[u8], extra: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let (id, _) = field_by_name(store, AMOUNT)?;
        let mut form = Dict::new();
        form.insert("Type", Object::name("XObject"));
        form.insert("Subtype", Object::name("Form"));
        form.insert(
            "BBox",
            Object::Array([0, 0, 200, 30].map(Object::Int).to_vec()),
        );
        let mut data = b"q 0 g 0 0 10 10 re f Q\n".to_vec();
        data.extend_from_slice(extra);
        let stream = Stream::new(form, StreamData::Encoded(data));
        let stream = store.add(Object::Stream(Box::new(stream))).ok()?;
        let mut ap = Dict::new();
        ap.insert("N", Object::Ref(stream));
        let mut field = store.resolve(id).ok()?.as_dict()?.clone();
        field.insert("V", Object::literal_string("900 EUR"));
        field.insert("AP", Object::Dict(ap));
        store.set(id, Object::Dict(field)).ok()
    })
}

/// `parser_fake_object_in_value_string` (variant A1-r5-layout-fake-object-in-contents-string):
/// `Amount` filled with a value string that holds [`FAKE_PAGE_CONTENT`] after a line break,
/// written as raw end-of-lines inside the literal string, which ISO 32000-2 §7.3.4.2 allows (the
/// serializer escapes them as `\n`, which keeps everything on one line; each two-byte escape is
/// replaced by a CR LF pair of the same length, so the offsets stay valid).
pub fn parser_fake_object_in_value_string(pdf: &[u8]) -> Option<Vec<u8>> {
    let value = format!("900 EUR\n{FAKE_PAGE_CONTENT}");
    let mut filled = forms::fill(pdf, &Fill::text(AMOUNT, &value))?;
    let escaped = value.replace('\n', "\\n").into_bytes();
    let raw = value.replace('\n', "\r\n").into_bytes();
    let from = pdf.len();
    let mut replaced = false;
    let mut at = from;
    while let Some(k) = filled
        .get(at..)?
        .windows(escaped.len())
        .position(|w| w == escaped.as_slice())
    {
        let pos = at + k;
        filled.get_mut(pos..pos + raw.len())?.copy_from_slice(&raw);
        replaced = true;
        at = pos + raw.len();
    }
    replaced.then_some(filled)
}

/// Fill values that hold the words a rebuilding reader looks for inside a line, where none
/// takes them for file structure (M4 final fix round 2, finding 3, variants
/// F1-k-honest-fill-value-*): poppler matches them only at the start of a line or of a 255-byte
/// piece, PDFium and pdf.js an object header only as words (`N G obj` ended by a delimiter).
pub const HONEST_STRUCTURE_WORDS: [&str; 7] = [
    "see xref table",
    "startxref",
    "Room 12 3 object",
    "Item 4 7 objective",
    "trailer <b>",
    "trailer park",
    "999 EUR",
];

/// `parser_honest_fill_structure_words` (the control of finding 3): `Amount` filled with every
/// value of [`HONEST_STRUCTURE_WORDS`] on one line, with a new appearance.
pub fn parser_honest_fill_structure_words(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::fill(pdf, &Fill::text(AMOUNT, &HONEST_STRUCTURE_WORDS.join("; ")))
}

/// `updated` (a signed file with one more revision) with the `/Size` of its newest trailer, or
/// of its newest cross-reference stream dictionary, written as `size`. The dictionary follows
/// the position `startxref` names, so no offset moves.
pub fn with_last_size(updated: &[u8], size: &str) -> Option<Vec<u8>> {
    let section = usize::try_from(last_startxref(updated)?).ok()?;
    let key = b"/Size";
    let at = section
        + updated
            .get(section..)?
            .windows(key.len())
            .position(|w| w == key)?
        + key.len();
    let value = at
        + updated
            .get(at..)?
            .iter()
            .take_while(|b| b.is_ascii_whitespace())
            .count();
    let end = value
        + updated
            .get(value..)?
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
    let mut out = updated.get(..at)?.to_vec();
    out.push(b' ');
    out.extend_from_slice(size.as_bytes());
    out.extend_from_slice(updated.get(end..)?);
    Some(out)
}

/// `parser_trailer_size_shrunk` (M4 closing round, finding 13): a fill whose trailer gives
/// `/Size 3`, far below the objects the file defines. PDFium shrinks its object table to the
/// newest `/Size` and drops the page's content, fonts and widgets; poppler, pyHanko and
/// Folioxide read past it.
pub fn parser_trailer_size_shrunk(pdf: &[u8]) -> Option<Vec<u8>> {
    with_last_size(&super::form_fill_text_value_and_ap(pdf)?, "3")
}

/// `parser_trailer_size_shrunk_info_only`: the same `/Size 3` on an update that only adds
/// `/Info` (otherwise `ltaUpdates`).
pub fn parser_trailer_size_shrunk_info_only(pdf: &[u8]) -> Option<Vec<u8>> {
    with_last_size(&super::isa_info_only(pdf)?, "3")
}

/// `parser_trailer_size_off_by_one`: a fill whose trailer gives `/Size` equal to the highest
/// object number the file lists (one too small: that object is dropped).
pub fn parser_trailer_size_off_by_one(pdf: &[u8]) -> Option<Vec<u8>> {
    let filled = super::form_fill_text_value_and_ap(pdf)?;
    let store = Store::open_bytes(filled.clone(), &OpenOptions::default()).ok()?;
    let mut highest = 0;
    for index in 0..store.revisions().len() {
        for (num, _) in store.revision_entries(index).ok()? {
            highest = highest.max(num);
        }
    }
    with_last_size(&filled, &highest.to_string())
}

/// `parser_startxref_corrupted` (manager ruling R-17 (c)): a fill whose last `startxref` names
/// a position one byte past its cross-reference section.
pub fn parser_startxref_corrupted(pdf: &[u8]) -> Option<Vec<u8>> {
    let filled = super::form_fill_text_value_and_ap(pdf)?;
    let value = last_startxref(&filled)?;
    let key = b"startxref\n";
    let at = filled.windows(key.len()).rposition(|w| w == key)? + key.len();
    let digits = value.to_string();
    if filled.get(at..at + digits.len())? != digits.as_bytes() {
        return None;
    }
    let mut out = filled.get(..at)?.to_vec();
    out.extend_from_slice(value.checked_add(1)?.to_string().as_bytes());
    out.extend_from_slice(filled.get(at + digits.len()..)?);
    Some(out)
}

/// The first page of `pdf`, its dictionary, and the next object number.
fn first_page(pdf: &[u8]) -> Option<(ObjectId, Dict, u32)> {
    let store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default()).ok()?;
    let page = forms::page_id(&store, 0)?;
    let dict = store.resolve(page).ok()?.as_dict()?.clone();
    Some((page, dict, store.next_object_number()))
}

/// The value bytes of an object stream (`/Type /ObjStm`, unencoded) holding `members` (object
/// number, value bytes) in order.
fn object_stream(members: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut header = String::new();
    let mut body = Vec::new();
    for (num, value) in members {
        header.push_str(&format!("{num} {} ", body.len()));
        body.extend_from_slice(value);
        body.push(b'\n');
    }
    let mut data = header.clone().into_bytes();
    data.extend_from_slice(&body);
    let mut out = format!(
        "<< /Type /ObjStm /N {} /First {} /Length {} >>\nstream\n",
        members.len(),
        header.len(),
        data.len()
    )
    .into_bytes();
    out.extend_from_slice(&data);
    out.extend_from_slice(b"\nendstream");
    out
}

/// `parser_objstm_member_unlisted` (M4 QA round 5, finding 27, variants
/// R5v-hidden-objstm-member-*): an update with a classic table that lists an orphan content
/// stream painting the page black and a new object stream whose one member is the first page,
/// re-pointed to that stream; no section lists the member (a classic table cannot). Folioxide,
/// poppler and pyHanko follow the section (an orphan and an object stream: `ltaUpdates`); a
/// reader that rebuilds the cross-reference data takes the member for the page (PDFium: the
/// whole page black).
pub fn parser_objstm_member_unlisted(pdf: &[u8]) -> Option<Vec<u8>> {
    let (page, mut dict, next) = first_page(pdf)?;
    let (black, container) = (next, next.checked_add(1)?);
    dict.insert("Contents", Object::Ref(ObjectId::new(black, 0)));
    let objects = [
        (black, stream_bytes(b"0 g 0 0 612 792 re f")),
        (
            container,
            object_stream(&[(page.num, ser(&Object::Dict(dict)))]),
        ),
    ];
    raw_update(pdf, &objects, &[0, 1], |tail| tail.kept.clone())
}

/// `pdf` filled, its update's table rewritten by `rewrite` (the table's bytes from `xref` to
/// `trailer`), the `startxref` moved to match.
fn table_rewritten(pdf: &[u8], rewrite: impl FnOnce(&[u8]) -> Vec<u8>) -> Option<Vec<u8>> {
    let filled = super::form_fill_text_value_and_ap(pdf)?;
    let xref = usize::try_from(last_startxref(&filled)?).ok()?;
    if filled.get(xref..xref + 4)? != b"xref" || xref < pdf.len() {
        return None;
    }
    let trailer = xref
        + filled
            .get(xref..)?
            .windows(7)
            .position(|w| w == b"trailer")?;
    let keyword = filled.windows(9).rposition(|w| w == b"startxref")?;
    let mut out = filled.get(..xref)?.to_vec();
    out.extend(rewrite(filled.get(xref..trailer)?));
    out.extend_from_slice(filled.get(trailer..keyword)?);
    out.extend_from_slice(format!("startxref\n{xref}\n%%EOF\n").as_bytes());
    Some(out)
}

/// `parser_xref_subsection_padded` (M4 QA round 5, findings 11 and 30, variants
/// A7-r5-xref-subsection-start-padded-*, R5v-xref-subsection-number-padded-300-*): a fill whose
/// table writes the first number of each subsection header after 32 zeros (PDFium reads a long
/// word as 0).
pub fn parser_xref_subsection_padded(pdf: &[u8]) -> Option<Vec<u8>> {
    table_rewritten(pdf, |table| {
        let text = String::from_utf8_lossy(table);
        let mut out = String::new();
        for line in text.split_inclusive('\n') {
            let header = line.trim_end().split(' ').collect::<Vec<_>>();
            if let [first, count] = header.as_slice()
                && !first.is_empty()
                && first.bytes().all(|b| b.is_ascii_digit())
                && count.bytes().all(|b| b.is_ascii_digit())
            {
                out.push_str(&"0".repeat(32));
            }
            out.push_str(line);
        }
        out.into_bytes()
    })
}

/// `parser_xref_entries_19_bytes` (finding 11, variant A1-r5-layout-entries-19-bytes-no-
/// unlisted-body): a fill whose table entries end in a lone line feed (19 bytes), which makes
/// PDFium rebuild the cross-reference data.
pub fn parser_xref_entries_19_bytes(pdf: &[u8]) -> Option<Vec<u8>> {
    table_rewritten(pdf, |table| {
        let text = String::from_utf8_lossy(table);
        text.replace(" n\r\n", " n\n")
            .replace(" f\r\n", " f\n")
            .replace(" n \n", " n\n")
            .replace(" f \n", " f\n")
            .into_bytes()
    })
}

/// A form XObject dictionary (`/BBox bbox`, `/Matrix matrix`).
fn form_with_matrix(bbox: [i64; 4], matrix: [i64; 6]) -> Dict {
    let mut dict = Dict::new();
    dict.insert("Type", Object::name("XObject"));
    dict.insert("Subtype", Object::name("Form"));
    dict.insert("BBox", Object::Array(bbox.map(Object::Int).to_vec()));
    dict.insert("Matrix", Object::Array(matrix.map(Object::Int).to_vec()));
    dict
}

/// The `/BBox` and `/Matrix` of [`form_fill_ap_matrix_small_bbox`] and
/// [`sigfield_ap_matrix_small_bbox`]: a one-unit box translated by 100,000, every entry within
/// ±10^5 but its corner mapped to 100,001 (manager ruling R-21; M4 QA round 5, finding 28: PDFium
/// placed a one-unit box translated by 10^7 3,540 pixels away).
const SMALL_BBOX: ([i64; 4], [i64; 6]) = ([0, 0, 1, 1], [1, 0, 0, 1, 100_000, 0]);

/// `form_fill_ap_matrix_small_bbox` (finding 28, variants R5v-ap-fill-bbox-1x1-matrix-translate-
/// *): `Amount` filled with a new appearance whose one-unit `/BBox` its `/Matrix` maps beyond
/// ±10^5.
pub fn form_fill_ap_matrix_small_bbox(pdf: &[u8]) -> Option<Vec<u8>> {
    let (bbox, matrix) = SMALL_BBOX;
    fill_with_form(pdf, form_with_matrix(bbox, matrix), b"0 g 0 0 1 1 re f")
}

/// `Amount` filled with "900 EUR" and a new appearance stream of dictionary `dict` and content
/// `content`.
fn fill_with_form(pdf: &[u8], dict: Dict, content: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let (id, _) = field_by_name(store, AMOUNT)?;
        let stream = Stream::new(dict, StreamData::Decoded(content.to_vec()));
        let stream = store.add(Object::Stream(Box::new(stream))).ok()?;
        let mut ap = Dict::new();
        ap.insert("N", Object::Ref(stream));
        let mut field = store.resolve(id).ok()?.as_dict()?.clone();
        field.insert("V", Object::literal_string("900 EUR"));
        field.insert("AP", Object::Dict(ap));
        store.set(id, Object::Dict(field)).ok()
    })
}

/// A form XObject dictionary with the real `/BBox bbox` and `/Matrix matrix`, and the content
/// that fills the box black.
fn tiny_form((bbox, matrix): ([f64; 4], [f64; 6])) -> (Dict, Vec<u8>) {
    let mut dict = Dict::new();
    dict.insert("Type", Object::name("XObject"));
    dict.insert("Subtype", Object::name("Form"));
    dict.insert("BBox", Object::Array(bbox.map(Object::Real).to_vec()));
    dict.insert("Matrix", Object::Array(matrix.map(Object::Real).to_vec()));
    let [x1, y1, x2, y2] = bbox;
    let content = format!("0 g {x1} {y1} {} {} re f", x2 - x1, y2 - y1).into_bytes();
    (dict, content)
}

/// A 0.01-unit `/BBox` translated by 99,999 (M4 final fix round 2, findings 2 and 4, variants
/// F4-k-pdfium-bbox-*-translate-99999 and R3-k-pdfium-late-bbox-*): every number and every
/// mapped corner is within ±10^5, but the box is scaled by 20,000 onto a 200-unit widget, which
/// PDFium does in single precision (2,100 and 2,806 pixels outside the widget).
const TINY_BBOX_1E5: ([f64; 4], [f64; 6]) =
    ([0.0, 0.0, 0.01, 0.01], [1.0, 0.0, 0.0, 1.0, 99_999.0, 0.0]);

/// A 0.1-unit `/BBox` translated by 99,999.9 (variant F4-k-newap-matrix-real-spelling-99999.9:
/// 390 pixels outside the field).
const TINY_BBOX_REAL: ([f64; 4], [f64; 6]) =
    ([0.0, 0.0, 0.1, 0.1], [1.0, 0.0, 0.0, 1.0, 99_999.9, 0.0]);

/// `Amount` filled with "900 EUR" and a new appearance stream with the real `/BBox bbox` and
/// `/Matrix matrix` that fills its box black (the QA variants and controls of findings 2 and 4).
pub fn form_fill_ap_form(pdf: &[u8], bbox: [f64; 4], matrix: [f64; 6]) -> Option<Vec<u8>> {
    let (dict, content) = tiny_form((bbox, matrix));
    fill_with_form(pdf, dict, &content)
}

/// `form_fill_ap_tiny_bbox_translate_1e5`: `Amount` filled with a new appearance of
/// [`TINY_BBOX_1E5`].
pub fn form_fill_ap_tiny_bbox_translate_1e5(pdf: &[u8]) -> Option<Vec<u8>> {
    let (dict, content) = tiny_form(TINY_BBOX_1E5);
    fill_with_form(pdf, dict, &content)
}

/// `form_fill_ap_matrix_tiny_bbox`: `Amount` filled with a new appearance of
/// [`TINY_BBOX_REAL`].
pub fn form_fill_ap_matrix_tiny_bbox(pdf: &[u8]) -> Option<Vec<u8>> {
    let (dict, content) = tiny_form(TINY_BBOX_REAL);
    fill_with_form(pdf, dict, &content)
}

/// `sigfield_ap_tiny_bbox_translate_1e5`: a new visible signature widget (200 by 60) whose
/// appearance is [`TINY_BBOX_1E5`].
pub fn sigfield_ap_tiny_bbox_translate_1e5(pdf: &[u8]) -> Option<Vec<u8>> {
    sigfield_with_tiny_form(pdf, TINY_BBOX_1E5)
}

/// `sigfield_ap_matrix_tiny_bbox` (variant R3-k-pdfium-late-bbox-01-*: 80 pixels outside the
/// widget): a new visible signature widget whose appearance is a 0.1-unit box translated by
/// 99,999.
pub fn sigfield_ap_matrix_tiny_bbox(pdf: &[u8]) -> Option<Vec<u8>> {
    sigfield_with_tiny_form(
        pdf,
        ([0.0, 0.0, 0.1, 0.1], [1.0, 0.0, 0.0, 1.0, 99_999.0, 0.0]),
    )
}

/// A new visible signature widget whose appearance is [`tiny_form`] of `geometry`.
fn sigfield_with_tiny_form(pdf: &[u8], geometry: ([f64; 4], [f64; 6])) -> Option<Vec<u8>> {
    super::sigfield_with_appearance(pdf, [100, 100, 300, 160], |store| {
        let (dict, content) = tiny_form(geometry);
        let stream = Stream::new(dict, StreamData::Decoded(content));
        store.add(Object::Stream(Box::new(stream))).ok()
    })
}

/// `sigfield_ap_matrix_small_bbox` (finding 28, variants R5v-ap-bbox-1x1-matrix-translate-*): a
/// new visible signature widget whose appearance has the one-unit `/BBox` and the `/Matrix` of
/// [`form_fill_ap_matrix_small_bbox`].
pub fn sigfield_ap_matrix_small_bbox(pdf: &[u8]) -> Option<Vec<u8>> {
    super::sigfield_with_appearance(pdf, [100, 100, 300, 160], |store| {
        let (bbox, matrix) = SMALL_BBOX;
        let stream = Stream::new(
            form_with_matrix(bbox, matrix),
            StreamData::Decoded(b"0 g 0 0 1 1 re f".to_vec()),
        );
        store.add(Object::Stream(Box::new(stream))).ok()
    })
}

/// `pdf` with a raw revision written with a cross-reference stream (`/W [1 4 2]`): the
/// uncompressed `objects`, the object stream `container` holding `members` in order, and the
/// compressed entries `listed` (object number, index in the container); the stream lists every
/// uncompressed object, the container and itself (ISO 32000-2 §7.5.8).
fn xref_stream_update(
    pdf: &[u8],
    objects: &[(u32, Vec<u8>)],
    container: u32,
    members: &[(u32, Vec<u8>)],
    listed: &[(u32, u32)],
) -> Option<Vec<u8>> {
    let tail = super::parser_diff::tail(pdf)?;
    let mut out = pdf.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    // (number, type, field 2, field 3) rows, sorted by number at the end.
    let mut rows: Vec<(u32, u8, u32, u16)> = Vec::new();
    let mut write = |out: &mut Vec<u8>, num: u32, value: &[u8]| -> Option<()> {
        rows.push((num, 1, u32::try_from(out.len()).ok()?, 0));
        out.extend(format!("{num} 0 obj\n").into_bytes());
        out.extend_from_slice(value);
        out.extend_from_slice(b"\nendobj\n");
        Some(())
    };
    for (num, value) in objects {
        write(&mut out, *num, value)?;
    }
    write(&mut out, container, &object_stream(members))?;
    for &(num, index) in listed {
        rows.push((num, 2, container, u16::try_from(index).ok()?));
    }
    let xref = objects
        .iter()
        .map(|(num, _)| *num)
        .chain(members.iter().map(|(num, _)| *num))
        .chain([container, tail.next])
        .max()?
        .checked_add(1)?;
    let xref_at = u32::try_from(out.len()).ok()?;
    rows.push((xref, 1, xref_at, 0));
    rows.sort_by_key(|row| row.0);
    let mut data = Vec::new();
    let mut index = String::new();
    for (num, kind, field2, field3) in &rows {
        data.push(*kind);
        data.extend(field2.to_be_bytes());
        data.extend(field3.to_be_bytes());
        index.push_str(&format!("{num} 1 "));
    }
    out.extend(
        format!(
            "{xref} 0 obj\n<< /Type /XRef /Size {} /W [1 4 2] /Index [{}]{} /Prev {} /Length {} \
             >>\nstream\n",
            xref + 1,
            index.trim_end(),
            tail.kept,
            tail.prev,
            data.len()
        )
        .into_bytes(),
    );
    out.extend(&data);
    out.extend(format!("\nendstream\nendobj\nstartxref\n{xref_at}\n%%EOF\n").into_bytes());
    Some(out)
}

/// The control of ruling R-18: an update with a cross-reference stream and a new object stream
/// whose one member, an orphan dictionary, the stream lists at its index (`ltaUpdates`, as
/// pyHanko: an object stream and an orphan).
pub fn parser_objstm_member_listed_control(pdf: &[u8]) -> Option<Vec<u8>> {
    let (_, _, next) = first_page(pdf)?;
    let (orphan, container) = (next, next.checked_add(1)?);
    xref_stream_update(
        pdf,
        &[],
        container,
        &[(orphan, b"<< /Note (an orphan) >>".to_vec())],
        &[(orphan, 0)],
    )
}

/// Ruling R-18: an update whose classic table re-lists the first page uncompressed and also
/// writes a new object stream holding a copy of the page painted black (the member number the
/// revision writes elsewhere).
pub fn parser_objstm_member_listed_elsewhere(pdf: &[u8]) -> Option<Vec<u8>> {
    let (page, dict, next) = first_page(pdf)?;
    let (black, container) = (next, next.checked_add(1)?);
    let mut painted = dict.clone();
    painted.insert("Contents", Object::Ref(ObjectId::new(black, 0)));
    let objects = [
        (page.num, ser(&Object::Dict(dict))),
        (black, stream_bytes(b"0 g 0 0 612 792 re f")),
        (
            container,
            object_stream(&[(page.num, ser(&Object::Dict(painted)))]),
        ),
    ];
    raw_update(pdf, &objects, &[0, 1, 2], |tail| tail.kept.clone())
}

/// Ruling R-18: an update with a cross-reference stream whose new object stream holds two orphan
/// dictionaries, each listed at the other's index.
pub fn parser_objstm_member_index_mismatch(pdf: &[u8]) -> Option<Vec<u8>> {
    let (_, _, next) = first_page(pdf)?;
    let (first, second, container) = (next, next.checked_add(1)?, next.checked_add(2)?);
    xref_stream_update(
        pdf,
        &[],
        container,
        &[
            (first, b"<< /Note (first) >>".to_vec()),
            (second, b"<< /Note (second) >>".to_vec()),
        ],
        &[(first, 1), (second, 0)],
    )
}

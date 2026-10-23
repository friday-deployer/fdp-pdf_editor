//! Parser differentials after signing (M4 QA round 1, manager ruling R-1): revisions whose bytes
//! readers read differently, so that a reader with another duplicate-key or object-stream policy
//! than Folioxide's sees another document.
//!
//! - **Duplicate dictionary keys** (ISO 32000-2 §7.3.7 forbids them): Folioxide, qpdf and poppler
//!   keep the last value, pyHanko and pypdf the first. A re-listed object that writes the hostile
//!   value first and the signed value last looks unchanged to a last-wins reader.
//! - **An object stream that holds an object twice** (§7.5.7), the cross-reference stream naming
//!   the second copy: pyHanko and pypdf take the first.
//! - **A trailer `/Root` written twice**: a first-wins reader opens another catalog (the
//!   Hide-and-Replace root switch with a duplicate-key disguise).
//! - **A section that lists a number twice.**
//!
//! Every generator takes a **signed** document and appends one revision of raw bytes (a classic
//! cross-reference table, or a cross-reference stream), because the incremental writer never
//! writes such bytes. `None` when an expected object is missing.

use folioxide_syntax::{Dict, Object, ObjectId, OpenOptions, Store, serialize_object};

use super::{last_startxref, with_incremental};
use crate::fixtures::forms::{self, AGREE, AMOUNT, field_by_name};

/// A serialized value.
pub(super) fn ser(value: &Object) -> Vec<u8> {
    let mut out = Vec::new();
    serialize_object(value, &mut out);
    out
}

/// A dictionary of pre-serialized entries, in order: `<< /K1 v1 /K2 v2 … >>` (a key may repeat).
fn dict_bytes(entries: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    let mut out = b"<<".to_vec();
    for (key, value) in entries {
        out.push(b' ');
        out.extend(ser(&Object::name(*key)));
        out.push(b' ');
        out.extend_from_slice(value);
    }
    out.extend_from_slice(b" >>");
    out
}

/// `dict` with `key` written twice, `first` then `last` (in place of its own entry, which comes
/// first), the other entries in their order.
fn duplicate_key(dict: &Dict, key: &[u8], first: Vec<u8>, last: Vec<u8>) -> Vec<u8> {
    let mut entries: Vec<(&[u8], Vec<u8>)> = vec![(key, first), (key, last)];
    for (k, v) in dict.iter() {
        if k.as_bytes() != key {
            entries.push((k.as_bytes(), ser(v)));
        }
    }
    dict_bytes(&entries)
}

/// The value bytes of a stream object with `data` and no filter.
pub(super) fn stream_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = format!("<< /Length {} >>\nstream\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\nendstream");
    out
}

/// What a raw update copies from the newest trailer of the signed file.
pub(super) struct Tail {
    /// The newest trailer's `/Root`, `/Info` and `/ID` entries, serialized (`/Root 1 0 R …`).
    pub(super) kept: String,
    /// The first object number the update may use.
    pub(super) next: u32,
    /// The `startxref` of the signed file: the update's `/Prev`.
    pub(super) prev: u64,
}

/// The [`Tail`] of `pdf`.
pub(super) fn tail(pdf: &[u8]) -> Option<Tail> {
    let store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default()).ok()?;
    let trailer = store.trailer();
    let mut kept = String::new();
    for key in [b"Root".as_slice(), b"Info", b"ID"] {
        if let Some(value) = trailer.get(key) {
            kept.push_str(&format!(
                " /{} {}",
                String::from_utf8_lossy(key),
                String::from_utf8_lossy(&ser(value))
            ));
        }
    }
    Some(Tail {
        kept,
        next: store.next_object_number(),
        prev: last_startxref(pdf)?,
    })
}

/// `pdf` with a raw revision: `objects` (number, value bytes; generation 0) and a classic
/// cross-reference table with one subsection per listing (`listings`: the indices into
/// `objects` each subsection gives, so a number may be listed twice), and the trailer entries
/// `trailer(tail)` (without `/Size` and `/Prev`, which are added).
pub(super) fn raw_update(
    pdf: &[u8],
    objects: &[(u32, Vec<u8>)],
    listings: &[usize],
    trailer: impl FnOnce(&Tail) -> String,
) -> Option<Vec<u8>> {
    let tail = tail(pdf)?;
    let mut out = pdf.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    let mut offsets = Vec::with_capacity(objects.len());
    for (num, value) in objects {
        offsets.push(out.len());
        out.extend(format!("{num} 0 obj\n").into_bytes());
        out.extend_from_slice(value);
        out.extend_from_slice(b"\nendobj\n");
    }
    let size = objects
        .iter()
        .map(|(num, _)| num + 1)
        .chain([tail.next])
        .max()?;
    let xref = out.len();
    out.extend_from_slice(b"xref\n0 1\n0000000000 65535 f \n");
    for &index in listings {
        let (num, _) = objects.get(index)?;
        let at = offsets.get(index)?;
        out.extend(format!("{num} 1\n{at:010} 00000 n \n").into_bytes());
    }
    let entries = trailer(&tail);
    out.extend(
        format!(
            "trailer\n<< /Size {size}{entries} /Prev {} >>\nstartxref\n{xref}\n%%EOF\n",
            tail.prev
        )
        .into_bytes(),
    );
    Some(out)
}

/// `pdf` with a raw revision that re-lists object `id` as `value` (the newest trailer's `/Root`,
/// `/Info` and `/ID` kept).
fn relist(pdf: &[u8], id: ObjectId, value: Vec<u8>) -> Option<Vec<u8>> {
    raw_update(pdf, &[(id.num, value)], &[0], |tail| tail.kept.clone())
}

/// The object and dictionary of the form field `name` of `pdf`.
fn field(pdf: &[u8], name: &str) -> Option<(ObjectId, Dict)> {
    let store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default()).ok()?;
    let (id, _) = field_by_name(&store, name)?;
    let dict = store.resolve(id).ok()?.as_dict()?.clone();
    Some((id, dict))
}

/// `[x1 y1+dy x2 y2+dy]` of a `/Rect`.
fn moved(rect: &Object, dy: f64) -> Option<Vec<u8>> {
    let values: Vec<f64> = rect
        .as_array()?
        .iter()
        .map(Object::as_f64)
        .collect::<Option<_>>()?;
    let [x1, y1, x2, y2] = values.as_slice() else {
        return None;
    };
    Some(ser(&Object::Array(
        [*x1, y1 + dy, *x2, y2 + dy]
            .into_iter()
            .map(Object::Real)
            .collect(),
    )))
}

/// `parser_dup_key_rect_moved_first`: the field `Amount` re-listed with `/Rect` twice, moved
/// 100 points up first and the signed value last (Folioxide's parser reads the signed one).
pub fn parser_dup_key_rect_moved_first(pdf: &[u8]) -> Option<Vec<u8>> {
    let (id, dict) = field(pdf, AMOUNT)?;
    let rect = dict.get(b"Rect")?;
    let value = duplicate_key(&dict, b"Rect", moved(rect, 100.0)?, ser(rect));
    relist(pdf, id, value)
}

/// `parser_dup_key_rect_original_first`: the same with the signed `/Rect` first and the moved
/// one last (a first-wins reader sees no change; Folioxide reads the moved widget).
pub fn parser_dup_key_rect_original_first(pdf: &[u8]) -> Option<Vec<u8>> {
    let (id, dict) = field(pdf, AMOUNT)?;
    let rect = dict.get(b"Rect")?;
    let value = duplicate_key(&dict, b"Rect", ser(rect), moved(rect, 100.0)?);
    relist(pdf, id, value)
}

/// `parser_dup_key_flags_hidden_first`: `Amount` re-listed with `/F 2` (Hidden) first and its
/// signed `/F` last.
pub fn parser_dup_key_flags_hidden_first(pdf: &[u8]) -> Option<Vec<u8>> {
    let (id, dict) = field(pdf, AMOUNT)?;
    let flags = dict.get(b"F")?;
    let value = duplicate_key(&dict, b"F", ser(&Object::Int(2)), ser(flags));
    relist(pdf, id, value)
}

/// `parser_dup_key_value_evil_first`: `Amount` re-listed with `/V (900 EUR)` first and its
/// signed `/V` last.
pub fn parser_dup_key_value_evil_first(pdf: &[u8]) -> Option<Vec<u8>> {
    let (id, dict) = field(pdf, AMOUNT)?;
    let v = dict.get(b"V")?;
    let value = duplicate_key(&dict, b"V", ser(&Object::literal_string("900 EUR")), ser(v));
    relist(pdf, id, value)
}

/// The first page's content stream of `pdf`.
fn page_content(pdf: &[u8]) -> Option<(ObjectId, ObjectId, Dict)> {
    let store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default()).ok()?;
    let page = forms::page_id(&store, 0)?;
    let dict = store.resolve(page).ok()?.as_dict()?.clone();
    let content = dict.get_ref(b"Contents")?;
    Some((page, content, dict))
}

/// `parser_dup_key_ap_page_content_first`: `Amount` re-listed with `/AP << /N page content >>`
/// first and its signed `/AP` last.
pub fn parser_dup_key_ap_page_content_first(pdf: &[u8]) -> Option<Vec<u8>> {
    let (id, dict) = field(pdf, AMOUNT)?;
    let (_, content, _) = page_content(pdf)?;
    let ap = dict.get(b"AP")?;
    let evil = dict_bytes(&[(b"N", ser(&Object::Ref(content)))]);
    let value = duplicate_key(&dict, b"AP", evil, ser(ap));
    relist(pdf, id, value)
}

/// `parser_dup_key_ap_n_reverse`: `Amount` re-listed with `/AP << /N page content /N signed >>`
/// (the duplicate key nested in the appearance dictionary, the signed stream last).
pub fn parser_dup_key_ap_n_reverse(pdf: &[u8]) -> Option<Vec<u8>> {
    let (id, dict) = field(pdf, AMOUNT)?;
    let (_, content, _) = page_content(pdf)?;
    let normal = dict.get_dict(b"AP")?.get(b"N")?;
    let ap = dict_bytes(&[(b"N", ser(&Object::Ref(content))), (b"N", ser(normal))]);
    let mut entries: Vec<(&[u8], Vec<u8>)> = Vec::new();
    for (k, v) in dict.iter() {
        if k.as_bytes() == b"AP" {
            entries.push((b"AP", ap.clone()));
        } else {
            entries.push((k.as_bytes(), ser(v)));
        }
    }
    relist(pdf, id, dict_bytes(&entries))
}

/// `parser_dup_key_checkbox_state_first`: the check box `Agree` re-listed with `/AS /Yes`
/// first and its signed `/AS /Off` last (its value stays `/Off`).
pub fn parser_dup_key_checkbox_state_first(pdf: &[u8]) -> Option<Vec<u8>> {
    let (id, dict) = field(pdf, AGREE)?;
    let state = dict.get(b"AS")?;
    let value = duplicate_key(&dict, b"AS", ser(&Object::name("Yes")), ser(state));
    relist(pdf, id, value)
}

/// `parser_dup_key_page_annots_empty_first`: the first page re-listed with `/Annots []` first
/// and its signed `/Annots` last (a first-wins reader shows no field and no annotation).
pub fn parser_dup_key_page_annots_empty_first(pdf: &[u8]) -> Option<Vec<u8>> {
    let (page, _, dict) = page_content(pdf)?;
    let annots = dict.get(b"Annots")?;
    let value = duplicate_key(&dict, b"Annots", b"[]".to_vec(), ser(annots));
    relist(pdf, page, value)
}

/// `parser_dup_key_page_contents_new_first`: the first page re-listed with `/Contents` a new
/// stream ("REPLACED") first and its signed content last.
pub fn parser_dup_key_page_contents_new_first(pdf: &[u8]) -> Option<Vec<u8>> {
    let (page, content, dict) = page_content(pdf)?;
    let next = tail(pdf)?.next;
    let value = duplicate_key(
        &dict,
        b"Contents",
        ser(&Object::Ref(ObjectId::new(next, 0))),
        ser(&Object::Ref(content)),
    );
    let objects = [
        (page.num, value),
        (
            next,
            stream_bytes(b"BT /F1 18 Tf 72 720 Td (REPLACED) Tj ET"),
        ),
    ];
    raw_update(pdf, &objects, &[0, 1], |tail| tail.kept.clone())
}

/// A new one-page document's objects from `next` on: catalog, pages, page, content (with the
/// first page's `/Resources` when it has direct ones), "THIS IS NOT THE SIGNED DOCUMENT".
fn other_document(pdf: &[u8], next: u32) -> Option<Vec<(u32, Vec<u8>)>> {
    let (_, _, page) = page_content(pdf)?;
    let resources = page
        .get(b"Resources")
        .map_or_else(|| b"<< >>".to_vec(), ser);
    let (catalog, pages, leaf, content) = (next, next + 1, next + 2, next + 3);
    let mut page = format!(
        "<< /Type /Page /Parent {pages} 0 R /MediaBox [0 0 612 792] /Contents {content} 0 R \
         /Resources "
    )
    .into_bytes();
    page.extend(resources);
    page.extend_from_slice(b" >>");
    Some(vec![
        (
            catalog,
            format!("<< /Type /Catalog /Pages {pages} 0 R >>").into_bytes(),
        ),
        (
            pages,
            format!("<< /Type /Pages /Kids [{leaf} 0 R] /Count 1 >>").into_bytes(),
        ),
        (leaf, page),
        (
            content,
            stream_bytes(b"BT /F1 24 Tf 72 700 Td (THIS IS NOT THE SIGNED DOCUMENT) Tj ET"),
        ),
    ])
}

/// `parser_dup_key_trailer_root_new_first`: a revision that adds another document and whose
/// trailer has `/Root` twice, the new catalog first and the signed one last (pyHanko and pypdf
/// open the other document).
pub fn parser_dup_key_trailer_root_new_first(pdf: &[u8]) -> Option<Vec<u8>> {
    let next = tail(pdf)?.next;
    let objects = other_document(pdf, next)?;
    raw_update(pdf, &objects, &[0, 1, 2, 3], |tail| {
        format!(" /Root {next} 0 R{}", tail.kept)
    })
}

/// `parser_dup_key_catalog_pages_new_first`: the catalog re-listed with `/Pages` twice, a new
/// page tree first and the signed one last.
pub fn parser_dup_key_catalog_pages_new_first(pdf: &[u8]) -> Option<Vec<u8>> {
    let store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default()).ok()?;
    let root = store.root_id()?;
    let catalog = store.resolve(root).ok()?.as_dict()?.clone();
    let pages = catalog.get(b"Pages")?;
    let next = store.next_object_number();
    let mut objects = other_document(pdf, next)?;
    objects.remove(0); // the new pages, page and content only
    let value = duplicate_key(
        &catalog,
        b"Pages",
        ser(&Object::Ref(ObjectId::new(next + 1, 0))),
        ser(pages),
    );
    objects.insert(0, (root.num, value));
    raw_update(pdf, &objects, &[0, 1, 2, 3], |tail| tail.kept.clone())
}

/// `parser_dup_key_annotation_rect_new_first`: the existing annotation of
/// [`annotated_input`](super::annotated_input) re-listed with `/Rect` moved over the page
/// first and its signed `/Rect` last.
pub fn parser_dup_key_annotation_rect_new_first(pdf: &[u8]) -> Option<Vec<u8>> {
    let store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default()).ok()?;
    let id = store.object_ids().into_iter().find(|&id| {
        store.resolve(id).ok().is_some_and(|o| {
            o.as_dict().is_some_and(|d| {
                d.get_str_bytes(b"NM") == Some(super::EXISTING_ANNOTATION.as_bytes())
            })
        })
    })?;
    let dict = store.resolve(id).ok()?.as_dict()?.clone();
    let rect = dict.get(b"Rect")?;
    let value = duplicate_key(&dict, b"Rect", moved(rect, 300.0)?, ser(rect));
    relist(pdf, id, value)
}

/// `parser_xref_lists_number_twice`: `Amount` re-listed unchanged, but in two subsections of
/// the same table with the same entry.
pub fn parser_xref_lists_number_twice(pdf: &[u8]) -> Option<Vec<u8>> {
    let (id, dict) = field(pdf, AMOUNT)?;
    raw_update(
        pdf,
        &[(id.num, ser(&Object::Dict(dict)))],
        &[0, 0],
        |tail| tail.kept.clone(),
    )
}

/// `parser_objstm_object_twice`: a revision with a cross-reference stream whose new object
/// stream holds `Amount` twice, moved 100 points up first and the signed dictionary second; the
/// cross-reference stream names the second copy (Folioxide reads the signed dictionary, pyHanko
/// and pypdf the first copy).
pub fn parser_objstm_object_twice(pdf: &[u8]) -> Option<Vec<u8>> {
    let (id, dict) = field(pdf, AMOUNT)?;
    let tail = tail(pdf)?;
    let mut moved_dict = dict.clone();
    let rect = moved(dict.get(b"Rect")?, 100.0)?;
    moved_dict.insert(
        "Rect",
        folioxide_syntax::parse_object(&rect, 0, &folioxide_syntax::ParseCtx::default())
            .ok()?
            .0,
    );
    let first = ser(&Object::Dict(moved_dict));
    let second = ser(&Object::Dict(dict));
    let header = format!("{} 0 {} {} ", id.num, id.num, first.len() + 1);
    let mut data = header.clone().into_bytes();
    data.extend(&first);
    data.push(b'\n');
    data.extend(&second);
    let (container, xref) = (tail.next, tail.next + 1);
    let mut out = pdf.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    let container_at = out.len();
    out.extend(
        format!(
            "{container} 0 obj\n<< /Type /ObjStm /N 2 /First {} /Length {} >>\nstream\n",
            header.len(),
            data.len()
        )
        .into_bytes(),
    );
    out.extend(&data);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    let xref_at = out.len();
    // /W [1 4 2]: Amount → (2, container, index 1); the container and the stream → type 1.
    let mut rows = vec![2u8];
    rows.extend(container.to_be_bytes());
    rows.extend(1u16.to_be_bytes());
    for at in [container_at, xref_at] {
        rows.push(1);
        rows.extend(u32::try_from(at).ok()?.to_be_bytes());
        rows.extend(0u16.to_be_bytes());
    }
    out.extend(
        format!(
            "{xref} 0 obj\n<< /Type /XRef /Size {} /W [1 4 2] /Index [{} 1 {container} 2]{} \
             /Prev {} /Length {} >>\nstream\n",
            xref + 1,
            id.num,
            tail.kept,
            tail.prev,
            rows.len()
        )
        .into_bytes(),
    );
    out.extend(&rows);
    out.extend(format!("\nendstream\nendobj\nstartxref\n{xref_at}\n%%EOF\n").into_bytes());
    Some(out)
}

/// The control of the parser differential rules: `Amount` re-listed with an unchanged
/// dictionary through the incremental writer (a re-listing, `LtaUpdates`).
pub fn parser_relist_control(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let (id, _) = field_by_name(store, AMOUNT)?;
        let value = store.resolve(id).ok()?;
        store.set(id, Object::clone(&value)).ok()
    })
}

// ---- number spellings readers read differently (M4 QA round 3, manager ruling R-12) ----------

/// `value` (serialized) with `prefix` written before its first number: before the value itself,
/// or after the `[` of an array.
fn respelled(value: &[u8], prefix: &[u8]) -> Vec<u8> {
    let at = usize::from(value.first() == Some(&b'['));
    let mut out = value.get(..at).unwrap_or_default().to_vec();
    out.extend_from_slice(prefix);
    out.extend_from_slice(value.get(at..).unwrap_or_default());
    out
}

/// `Amount` re-listed with the first number of its `key` entry written with `prefix` before it.
fn relist_respelled(pdf: &[u8], key: &[u8], prefix: &[u8]) -> Option<Vec<u8>> {
    let (id, dict) = field(pdf, AMOUNT)?;
    relist_dict_respelled(pdf, id, &dict, key, prefix)
}

/// The dictionary object `id` (`dict`) re-listed with the first number of its `key` entry
/// written with `prefix` before it.
fn relist_dict_respelled(
    pdf: &[u8],
    id: ObjectId,
    dict: &Dict,
    key: &[u8],
    prefix: &[u8],
) -> Option<Vec<u8>> {
    dict.get(key)?;
    let entries: Vec<(&[u8], Vec<u8>)> = dict
        .iter()
        .map(|(k, v)| {
            let value = ser(v);
            if k.as_bytes() == key {
                (k.as_bytes(), respelled(&value, prefix))
            } else {
                (k.as_bytes(), value)
            }
        })
        .collect();
    relist(pdf, id, dict_bytes(&entries))
}

/// `parser_relisted_flags_multisign` (QA variant F1-h-unhide-by-spelling-00): on the form whose
/// `Amount` widget is hidden (`/F 6`), `Amount` re-listed with its flags written `++6`.
/// Folioxide's lexer reads the signed 6 (the object looked re-listed), PDFium reads 0 and shows
/// the hidden widget; pyHanko cannot read the number.
pub fn parser_relisted_flags_multisign(pdf: &[u8]) -> Option<Vec<u8>> {
    relist_respelled(pdf, b"F", b"++")
}

/// `parser_relisted_rect_multisign` (QA variant F8-h-rect-x-spelled-72-00): `Amount` re-listed
/// with the first number of its `/Rect` written with `++` (PDFium: 0, the widget moves).
pub fn parser_relisted_rect_multisign(pdf: &[u8]) -> Option<Vec<u8>> {
    relist_respelled(pdf, b"Rect", b"++")
}

/// `Amount` re-listed with the first number of its `key` entry padded with `zeros` leading zeros
/// (M4 QA round 4, finding 2). Folioxide, poppler and pyHanko read the signed value (a
/// re-listing); PDFium reads a word of 256 characters or more as 0 (the `/Rect`: the widget
/// moves, 4,131 pixels outside at 1,000 zeros, variant F1-i-relisted-rect-zero-padded-1000; the
/// `/F` of a hidden widget: it shows).
pub fn parser_relisted_padded(pdf: &[u8], key: &[u8], zeros: usize) -> Option<Vec<u8>> {
    relist_respelled(pdf, key, "0".repeat(zeros).as_bytes())
}

/// `parser_relisted_rect_zero_padded`: [`parser_relisted_padded`] for `Amount`'s `/Rect` with
/// [`ORACLE_ZERO_PADDING`](super::ORACLE_ZERO_PADDING) zeros.
pub fn parser_relisted_rect_zero_padded(pdf: &[u8]) -> Option<Vec<u8>> {
    parser_relisted_padded(pdf, b"Rect", super::ORACLE_ZERO_PADDING)
}

/// `parser_relisted_flags_zero_padded`: on the form whose `Amount` widget is hidden (`/F 6`),
/// [`parser_relisted_padded`] for its `/F`.
pub fn parser_relisted_flags_zero_padded(pdf: &[u8]) -> Option<Vec<u8>> {
    parser_relisted_padded(pdf, b"F", super::ORACLE_ZERO_PADDING)
}

/// The first page re-listed with the object number of its `/Contents` reference padded with
/// `zeros` leading zeros (variant R3-i-page-contents-ref-zero-padded-300). Folioxide and poppler
/// follow the signed content stream; PDFium reads the number as 0 from 256 characters on,
/// follows no stream and blanks the page text (pyHanko cannot read a 300-zero reference).
pub fn parser_relisted_page_contents_padded(pdf: &[u8], zeros: usize) -> Option<Vec<u8>> {
    let store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default()).ok()?;
    let page = forms::page_id(&store, 0)?;
    let dict = store.resolve(page).ok()?.as_dict()?.clone();
    dict.get_ref(b"Contents")?;
    relist_dict_respelled(pdf, page, &dict, b"Contents", "0".repeat(zeros).as_bytes())
}

/// `parser_relisted_page_contents_zero_padded`: [`parser_relisted_page_contents_padded`] with
/// [`ORACLE_ZERO_PADDING`](super::ORACLE_ZERO_PADDING) zeros.
pub fn parser_relisted_page_contents_zero_padded(pdf: &[u8]) -> Option<Vec<u8>> {
    parser_relisted_page_contents_padded(pdf, super::ORACLE_ZERO_PADDING)
}

/// `parser_relisted_rect_plus_control`: the control, the first number of `Amount`'s `/Rect`
/// written with one `+` (canonical, ruling R-12: every reader reads the signed value): a
/// re-listing.
pub fn parser_relisted_rect_plus_control(pdf: &[u8]) -> Option<Vec<u8>> {
    relist_respelled(pdf, b"Rect", b"+")
}

/// The form prepared (raw bytes, **before** signing) so that its page draws a form XObject `/Fx`
/// from an indirect `/XObject` dictionary that writes `/Fx` twice: first `Amount`'s appearance
/// stream, last an empty form XObject (M4 QA round 3, manager ruling R-12 (2)). To a first-wins
/// reader such as pyHanko the appearance stream has a second use, as page content; Folioxide's
/// last-wins parser sees none, so an in-place rewrite of that stream (brief §5.1 F5) changed the
/// page for first-wins viewers while it looked like a fill.
pub fn form_ap_shared_first_wins_input(pdf: &[u8]) -> Option<Vec<u8>> {
    use folioxide_syntax::{Stream, StreamData};
    let mut xobjects = None;
    let mut blank = None;
    let shared = with_incremental(pdf, |store| {
        let page = ObjectId::new(forms::ids::PAGE, 0);
        let mut dict = store.resolve(page).ok()?.as_dict()?.clone();
        let mut empty = Dict::new();
        empty.insert("Type", Object::name("XObject"));
        empty.insert("Subtype", Object::name("Form"));
        empty.insert(
            "BBox",
            Object::Array(vec![
                Object::Int(0),
                Object::Int(0),
                Object::Int(1),
                Object::Int(1),
            ]),
        );
        let empty = store
            .add(Object::Stream(Box::new(Stream::new(
                empty,
                StreamData::Decoded(Vec::new()),
            ))))
            .ok()?;
        let mut names = Dict::new();
        names.insert("Fx", Object::Ref(empty));
        let names_id = store.add(Object::Dict(names)).ok()?;
        let mut resources = dict.get_dict(b"Resources")?.clone();
        resources.insert("XObject", Object::Ref(names_id));
        dict.insert("Resources", Object::Dict(resources));
        let drawn = Stream::new(
            Dict::new(),
            StreamData::Decoded(b"q 1 0 0 1 320 600 cm /Fx Do Q".to_vec()),
        );
        let drawn = store.add(Object::Stream(Box::new(drawn))).ok()?;
        dict.insert(
            "Contents",
            Object::Array(vec![
                Object::Ref(ObjectId::new(forms::ids::CONTENT, 0)),
                Object::Ref(drawn),
            ]),
        );
        xobjects = Some(names_id);
        blank = Some(empty);
        store.set(page, Object::Dict(dict)).ok()
    })?;
    let (names_id, empty) = (xobjects?, blank?);
    let names = Dict::new();
    let value = duplicate_key(
        &names,
        b"Fx",
        ser(&Object::Ref(ObjectId::new(forms::ids::AMOUNT_AP, 0))),
        ser(&Object::Ref(empty)),
    );
    relist(&shared, names_id, value)
}

/// The form prepared (raw bytes, **before** signing) with a use of `Amount`'s appearance stream
/// that only first-wins readers reach, `hops` objects away from the page-tree root (M4 QA round
/// 4, finding 1, variants F5-i-inplace-ap-two-hop-hidden-use and -three-hop-): the root is
/// re-listed with `/Extra << /Hop first /Hop decoy >>`, a key written twice whose last value (an
/// empty dictionary) is what Folioxide's last-wins parser reads. With `hops` 1 the first value
/// is the appearance stream itself (`/Fx` instead of `/Hop`); with 2 it is a canonical carrier
/// `<< /Fx 8 0 R >>`; with 3 a carrier array `[C 0 R]` whose `C` is `<< /Q 8 0 R >>`. To a
/// first-wins reader the stream has a second use, so rewriting it in place (brief §5.1 F5) is
/// not a fill there (pyHanko: `other`).
pub fn form_ap_hidden_hop_input(pdf: &[u8], hops: usize) -> Option<Vec<u8>> {
    let ap = Object::Ref(ObjectId::new(forms::ids::AMOUNT_AP, 0));
    let mut first = None;
    let mut decoy = None;
    let mut root = None;
    let carried = with_incremental(pdf, |store| {
        let catalog = store.root_id()?;
        let pages = store.resolve(catalog).ok()?.as_dict()?.get_ref(b"Pages")?;
        let mut held = ap.clone();
        if hops >= 3 {
            let mut inner = Dict::new();
            inner.insert("Q", held);
            let inner = store.add(Object::Dict(inner)).ok()?;
            held = Object::Ref(store.add(Object::Array(vec![Object::Ref(inner)])).ok()?);
        } else if hops == 2 {
            let mut carrier = Dict::new();
            carrier.insert("Fx", held);
            held = Object::Ref(store.add(Object::Dict(carrier)).ok()?);
        }
        first = Some(held);
        decoy = Some(store.add(Object::Dict(Dict::new())).ok()?);
        root = Some(pages);
        Some(())
    })?;
    let (first, decoy, pages) = (first?, decoy?, root?);
    let key: &[u8] = if hops <= 1 { b"Fx" } else { b"Hop" };
    let extra = duplicate_key(&Dict::new(), key, ser(&first), ser(&Object::Ref(decoy)));
    let store = Store::open_bytes(carried.clone(), &OpenOptions::default()).ok()?;
    let dict = store.resolve(pages).ok()?.as_dict()?.clone();
    let mut entries: Vec<(&[u8], Vec<u8>)> =
        dict.iter().map(|(k, v)| (k.as_bytes(), ser(v))).collect();
    entries.push((b"Extra", extra));
    relist(&carried, pages, dict_bytes(&entries))
}

/// [`form_ap_dict_indirect_input`](super::form_ap_dict_indirect_input) with the page-tree root
/// re-listed with `/Extra << /Fx D /Fx decoy >>`, where `D` is `Amount`'s indirect `/AP`
/// dictionary: Folioxide's last-wins reading sees one use of `D`, a first-wins reader such as
/// pyHanko two (manager ruling R-19, M4 QA round 5, finding 7, variants
/// F4-j-hop-indirect-ap-dict-*, F4-j-hidden-ghost-widget-shares-ap-dict-*).
pub fn form_ap_dict_hidden_carrier_input(pdf: &[u8]) -> Option<Vec<u8>> {
    let indirect = super::form_ap_dict_indirect_input(pdf)?;
    let mut decoy = None;
    let mut found = None;
    let carried = with_incremental(&indirect, |store| {
        let (amount, _) = field_by_name(store, AMOUNT)?;
        let ap = store.resolve(amount).ok()?.as_dict()?.get_ref(b"AP")?;
        let catalog = store.root_id()?;
        let pages = store.resolve(catalog).ok()?.as_dict()?.get_ref(b"Pages")?;
        decoy = Some(store.add(Object::Dict(Dict::new())).ok()?);
        found = Some((ap, pages));
        Some(())
    })?;
    let (decoy, (ap, pages)) = (decoy?, found?);
    let extra = duplicate_key(
        &Dict::new(),
        b"Fx",
        ser(&Object::Ref(ap)),
        ser(&Object::Ref(decoy)),
    );
    let store = Store::open_bytes(carried.clone(), &OpenOptions::default()).ok()?;
    let dict = store.resolve(pages).ok()?.as_dict()?.clone();
    let mut entries: Vec<(&[u8], Vec<u8>)> =
        dict.iter().map(|(k, v)| (k.as_bytes(), ser(v))).collect();
    entries.push((b"Extra", extra));
    relist(&carried, pages, dict_bytes(&entries))
}

/// `updated` (`pdf` with one classic-table revision appended by the incremental writer) with
/// `before_section` inserted just before the appended `xref` keyword and `before_startxref`
/// just before its `startxref`, the `startxref` value moved to match. The entries point before
/// the insertions, so they stay right.
fn insert_in_update(
    pdf: &[u8],
    updated: &[u8],
    before_section: &[u8],
    before_startxref: &[u8],
) -> Option<Vec<u8>> {
    let xref = usize::try_from(last_startxref(updated)?).ok()?;
    let keyword = updated.windows(9).rposition(|w| w == b"startxref")?;
    if xref < pdf.len() || updated.get(xref..xref + 4)? != b"xref" || keyword < xref {
        return None;
    }
    let mut out = updated.get(..xref)?.to_vec();
    out.extend_from_slice(before_section);
    out.extend_from_slice(updated.get(xref..keyword)?);
    out.extend_from_slice(before_startxref);
    out.extend_from_slice(
        format!("startxref\n{}\n%%EOF\n", xref + before_section.len()).as_bytes(),
    );
    Some(out)
}

/// A body for the page's content stream (object 4 of the form) that paints the page black: what
/// a reader that rebuilds the cross-reference data takes for object 4 when an update holds it
/// unlisted.
const BLACK_PAGE_BODY: &[u8] =
    b"4 0 obj\n<< /Length 20 >>\nstream\n0 g 0 0 612 792 re f\nendstream\nendobj\n";

/// `parser_unlisted_object_body` (M4 QA round 4, finding 3, variant
/// F8-i-xref-trigger-xref-entries-19-bytes without its trigger): a valid fill of `Amount`
/// whose update also holds a body `4 0 obj` (the page content, painted black) that its
/// cross-reference section does not list. Folioxide, poppler and pyHanko follow the section (a
/// fill); PDFium, once something makes it rebuild the cross-reference data (a 19-byte entry,
/// junk before `startxref`), takes the black page (477,210 pixels outside the fill).
pub fn parser_unlisted_object_body(pdf: &[u8]) -> Option<Vec<u8>> {
    let filled = super::form_fill_text_value_and_ap(pdf)?;
    insert_in_update(pdf, &filled, BLACK_PAGE_BODY, b"")
}

/// `parser_junk_before_startxref` (finding 3): a valid fill of `Amount` whose update has bytes
/// other than white-space and comments between its trailer dictionary and `startxref`, which
/// makes PDFium rebuild the cross-reference data.
pub fn parser_junk_before_startxref(pdf: &[u8]) -> Option<Vec<u8>> {
    let filled = super::form_fill_text_value_and_ap(pdf)?;
    insert_in_update(pdf, &filled, b"", b"junk 1 0 R\n")
}

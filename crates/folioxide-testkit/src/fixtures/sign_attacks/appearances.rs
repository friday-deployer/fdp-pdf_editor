//! What a new widget or annotation paints, and where (M4 QA round 1, manager rulings R-2 and
//! R-3, QA finding R5): signature widgets with annotation flags no signer writes, appearances
//! that are no form XObject clipped to the `/Rect`, and markup annotations whose geometry or
//! synthesized appearance reaches outside their `/Rect`.
//!
//! Every generator takes a **signed** document and appends one revision through `Store` edits
//! and the incremental writer. `None` when an expected object is missing.

use folioxide_syntax::{Dict, Object, ObjectId, Store, Stream, StreamData};

use super::{
    add_overlay_appearance, append_to_array_entry, first_page, overlay_widget, rect,
    with_incremental,
};
use crate::fixtures::forms::{self, AMOUNT, Annot, field_by_name};

// ---- new signature widgets --------------------------------------------------------------------

/// A revision that adds a visible signature widget registered at the root of `/Fields`, on the
/// page `page` (0-based), at `[100 100 300 160]`, with the flags `flags` and the appearance
/// `appearance(store, page)` (`None`: the page overlay of [`add_overlay_appearance`]).
fn new_sig_widget(
    pdf: &[u8],
    page: usize,
    flags: i64,
    rect_values: [i64; 4],
    appearance: impl FnOnce(&mut Store, ObjectId) -> Option<Object>,
) -> Option<Vec<u8>> {
    new_sig_widget_at(pdf, page, flags, rect(rect_values), appearance)
}

/// [`new_sig_widget`] with the `/Rect` value `rect_value` as written (M4 QA round 2, finding 4:
/// a `/Rect` that is not four numbers).
fn new_sig_widget_at(
    pdf: &[u8],
    page: usize,
    flags: i64,
    rect_value: Object,
    appearance: impl FnOnce(&mut Store, ObjectId) -> Option<Object>,
) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let page = forms::page_id(store, page)?;
        let ap = appearance(store, page)?;
        let mut widget = overlay_widget(page, vec![("Rect", rect_value)]);
        widget.insert("F", Object::Int(flags));
        if !ap.is_null() {
            widget.insert("AP", ap);
        }
        let id = store.add(Object::Dict(widget)).ok()?;
        append_to_array_entry(store, page, b"Annots", id)?;
        let root = store.root_id()?;
        let catalog = store.resolve(root).ok()?.as_dict()?.clone();
        match catalog.get(b"AcroForm")? {
            Object::Ref(acroform) => append_to_array_entry(store, *acroform, b"Fields", id),
            _ => None,
        }
    })
}

/// `/AP << /N overlay >>` with the page overlay of [`add_overlay_appearance`].
fn overlay_ap(store: &mut Store, page: ObjectId) -> Option<Object> {
    let overlay = add_overlay_appearance(store, page)?;
    let mut ap = Dict::new();
    ap.insert("N", Object::Ref(overlay));
    Some(Object::Dict(ap))
}

/// A new stream of `content` with the dictionary `dict`.
fn add_stream(store: &mut Store, dict: Dict, content: &[u8]) -> Option<ObjectId> {
    let stream = Stream::new(dict, StreamData::Decoded(content.to_vec()));
    store.add(Object::Stream(Box::new(stream))).ok()
}

/// The page overlay's content (white over the page, then text), in a new stream with `dict`.
fn bare_overlay(store: &mut Store, dict: Dict) -> Option<ObjectId> {
    add_stream(
        store,
        dict,
        b"1 1 1 rg 0 0 612 792 re f 0 g BT /F1 24 Tf 72 720 Td (FORGED: pay 1 EUR) Tj ET",
    )
}

/// `sigfield_flags_nozoom`: a new visible signature widget with `/F 12` (Print | NoZoom).
pub fn sigfield_flags_nozoom(pdf: &[u8]) -> Option<Vec<u8>> {
    new_sig_widget(pdf, 0, 12, [100, 100, 300, 160], overlay_ap)
}

/// `sigfield_flags_hidden`: a new visible signature widget with `/F 6` (Print | Hidden).
pub fn sigfield_flags_hidden(pdf: &[u8]) -> Option<Vec<u8>> {
    new_sig_widget(pdf, 0, 6, [100, 100, 300, 160], overlay_ap)
}

/// `sigfield_flags_noview`: a new visible signature widget with `/F 36` (Print | NoView): it
/// prints but is not shown on screen.
pub fn sigfield_flags_noview(pdf: &[u8]) -> Option<Vec<u8>> {
    new_sig_widget(pdf, 0, 36, [100, 100, 300, 160], overlay_ap)
}

/// `sigfield_flags_toggle_noview`: a new visible signature widget with `/F 260` (Print |
/// ToggleNoView).
pub fn sigfield_flags_toggle_noview(pdf: &[u8]) -> Option<Vec<u8>> {
    new_sig_widget(pdf, 0, 260, [100, 100, 300, 160], overlay_ap)
}

/// `sigfield_invisible_flags_hidden`: a new invisible signature field (`/Rect [0 0 0 0]`, no
/// appearance) with `/F 2` (Hidden).
pub fn sigfield_invisible_flags_hidden(pdf: &[u8]) -> Option<Vec<u8>> {
    new_sig_widget(pdf, 0, 2, [0, 0, 0, 0], |_, _| Some(Object::Null))
}

/// `sigfield_norotate_rotated_page`: a new visible signature widget with `/F 20` (Print |
/// NoRotate) on the second page of [`forms::rotated_pages`] (`/Rotate 90`): poppler paints its
/// appearance unrotated, outside its `/Rect` (QA variant R3-rot90-raw-norotate-flag).
pub fn sigfield_norotate_rotated_page(pdf: &[u8]) -> Option<Vec<u8>> {
    new_sig_widget(pdf, 1, 20, [100, 100, 300, 160], |store, _| {
        let mut dict = form_dict([0, 0, 200, 60]);
        dict.insert("Resources", Object::Dict(Dict::new()));
        let stream = add_stream(store, dict, b"0 0 1 rg 0 0 200 60 re f")?;
        let mut ap = Dict::new();
        ap.insert("N", Object::Ref(stream));
        Some(Object::Dict(ap))
    })
}

/// A new visible signature widget with `/F 132` and a black form XObject appearance of 100 by
/// 40, whose `/Rect` is `rect_value` (M4 QA round 2, finding 4, variants R3-rect-*: poppler reads
/// an entry it cannot use as 0 and paints the appearance elsewhere than the `/Rect` says).
fn sig_widget_with_rect(pdf: &[u8], rect_value: Object) -> Option<Vec<u8>> {
    new_sig_widget_at(pdf, 0, 132, rect_value, |store, _| {
        let stream = add_stream(store, form_dict([0, 0, 100, 40]), b"0 g 0 0 100 40 re f")?;
        let mut ap = Dict::new();
        ap.insert("N", Object::Ref(stream));
        Some(Object::Dict(ap))
    })
}

/// A new visible signature widget (`/F 132`) with the integer `/Rect` `rect` whose `/AP /N` is
/// the stream `appearance` adds (M4 QA round 5, finding 28).
pub(super) fn sigfield_with_appearance(
    pdf: &[u8],
    rect_values: [i64; 4],
    appearance: impl FnOnce(&mut Store) -> Option<ObjectId>,
) -> Option<Vec<u8>> {
    new_sig_widget(pdf, 0, 132, rect_values, |store, _| {
        let stream = appearance(store)?;
        let mut ap = Dict::new();
        ap.insert("N", Object::Ref(stream));
        Some(Object::Dict(ap))
    })
}

/// `sigfield_rect_null_entry`: a new visible signature widget with `/Rect [null 300 400 340]`
/// (QA variant R3-rect-first-null: poppler paints x 0 to 400).
pub fn sigfield_rect_null_entry(pdf: &[u8]) -> Option<Vec<u8>> {
    sig_widget_with_rect(
        pdf,
        Object::Array(vec![
            Object::Null,
            Object::Int(300),
            Object::Int(400),
            Object::Int(340),
        ]),
    )
}

/// `sigfield_rect_string_entry`: `/Rect [300 300 (400) 340]` (QA variant
/// R3-rect-spelling-string).
pub fn sigfield_rect_string_entry(pdf: &[u8]) -> Option<Vec<u8>> {
    sig_widget_with_rect(
        pdf,
        Object::Array(vec![
            Object::Int(300),
            Object::Int(300),
            Object::literal_string("400"),
            Object::Int(340),
        ]),
    )
}

/// `sigfield_rect_wrong_length`: `/Rect [300 300 400]`, three numbers.
pub fn sigfield_rect_wrong_length(pdf: &[u8]) -> Option<Vec<u8>> {
    sig_widget_with_rect(
        pdf,
        Object::Array(vec![Object::Int(300), Object::Int(300), Object::Int(400)]),
    )
}

/// `/Type /XObject /Subtype /Form /BBox bbox`.
fn form_dict(bbox: [i64; 4]) -> Dict {
    let mut dict = Dict::new();
    dict.insert("Type", Object::name("XObject"));
    dict.insert("Subtype", Object::name("Form"));
    dict.insert("BBox", rect(bbox));
    dict
}

/// `/AP << /N s >>` for the page overlay in a new stream with `dict` (no `/BBox`, or no
/// `/Subtype`), the page's `/Resources` added.
fn bare_ap(store: &mut Store, page: ObjectId, mut dict: Dict) -> Option<Object> {
    if let Some(resources) = store
        .resolve(page)
        .ok()?
        .as_dict()?
        .get(b"Resources")
        .cloned()
    {
        dict.insert("Resources", resources);
    }
    let stream = bare_overlay(store, dict)?;
    let mut ap = Dict::new();
    ap.insert("N", Object::Ref(stream));
    Some(Object::Dict(ap))
}

/// `/Type /XObject /Subtype /Form` without `/BBox`.
fn form_without_bbox() -> Dict {
    let mut dict = Dict::new();
    dict.insert("Type", Object::name("XObject"));
    dict.insert("Subtype", Object::name("Form"));
    dict
}

/// `sigfield_ap_no_bbox`: a new visible signature widget whose `/AP /N` is a form XObject
/// without `/BBox` that paints over the whole page: PDFium does not clip it to the `/Rect` (QA
/// variant R5-ap-no-bbox-new-stream).
pub fn sigfield_ap_no_bbox(pdf: &[u8]) -> Option<Vec<u8>> {
    new_sig_widget(pdf, 0, 4, [100, 100, 300, 160], |store, page| {
        bare_ap(store, page, form_without_bbox())
    })
}

/// `sigfield_ap_no_subtype`: the same appearance with a `/BBox` but neither `/Type` nor
/// `/Subtype` (no form XObject).
pub fn sigfield_ap_no_subtype(pdf: &[u8]) -> Option<Vec<u8>> {
    new_sig_widget(pdf, 0, 4, [100, 100, 300, 160], |store, page| {
        let mut dict = Dict::new();
        dict.insert("BBox", rect([0, 0, 612, 792]));
        bare_ap(store, page, dict)
    })
}

/// `sigfield_ap_state_dict`: a new visible signature widget whose `/AP /N` is a dictionary of
/// appearance states (no `/AS`) holding a form XObject without `/BBox`.
pub fn sigfield_ap_state_dict(pdf: &[u8]) -> Option<Vec<u8>> {
    new_sig_widget(pdf, 0, 4, [100, 100, 300, 160], |store, page| {
        let Object::Dict(ap) = bare_ap(store, page, form_without_bbox())? else {
            return None;
        };
        let mut states = Dict::new();
        states.insert("On", ap.get(b"N")?.clone());
        let mut outer = Dict::new();
        outer.insert("N", Object::Dict(states));
        Some(Object::Dict(outer))
    })
}

/// `sigfield_ap_page_content`: a new visible signature widget whose `/AP /N` is the page's own
/// content stream (an existing object, no form XObject; QA variant
/// R5-ap-existing-page-content-stream).
pub fn sigfield_ap_page_content(pdf: &[u8]) -> Option<Vec<u8>> {
    new_sig_widget(pdf, 0, 4, [100, 100, 300, 160], |store, page| {
        let content = store.resolve(page).ok()?.as_dict()?.get_ref(b"Contents")?;
        let mut ap = Dict::new();
        ap.insert("N", Object::Ref(content));
        Some(Object::Dict(ap))
    })
}

/// `form_fill_ap_no_bbox`: the text field `Amount` filled (`/V (900 EUR)`) with a new
/// appearance without `/BBox` that paints over the page (QA variant
/// R5-textfield-fill-ap-no-bbox).
pub fn form_fill_ap_no_bbox(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let (id, _) = field_by_name(store, AMOUNT)?;
        let page = first_page(store)?;
        let ap = bare_ap(store, page, form_without_bbox())?;
        let mut field = store.resolve(id).ok()?.as_dict()?.clone();
        field.insert("V", Object::literal_string("900 EUR"));
        field.insert("AP", ap);
        store.set(id, Object::Dict(field)).ok()
    })
}

/// `form_fill_ap_matrix_magnitude` (M4 QA round 4, finding 4, variant
/// F4-i-newap-bbox-ok-matrix-int32max): `Amount` filled with a new appearance whose `/BBox` is
/// `[0 0 200 30]` and whose `/Matrix` translates by 2,147,483,647, a canonical integer that
/// PDFium maps onto the `/Rect` in single precision and places elsewhere (3,270 pixels
/// outside); poppler and pyHanko accept it.
pub fn form_fill_ap_matrix_magnitude(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let (id, _) = field_by_name(store, AMOUNT)?;
        let mut dict = form_dict([0, 0, 200, 30]);
        dict.insert(
            "Matrix",
            Object::Array([1, 0, 0, 1, 2_147_483_647, 0].map(Object::Int).to_vec()),
        );
        let stream = add_stream(store, dict, b"0 g -5000 -5000 10000 10000 re f")?;
        let mut ap = Dict::new();
        ap.insert("N", Object::Ref(stream));
        let mut field = store.resolve(id).ok()?.as_dict()?.clone();
        field.insert("V", Object::literal_string("900 EUR"));
        field.insert("AP", Object::Dict(ap));
        store.set(id, Object::Dict(field)).ok()
    })
}

/// `sigfield_rect_magnitude` (M4 QA round 4, finding 13, variants R5w-rect-mag-y1-minus-*): a
/// new visible signature widget with `/Rect [60 -1000000000 260 260]`, canonical integers that
/// PDFium maps in single precision and paints elsewhere (3,800 pixels outside the nominal
/// area); poppler paints nothing there, pyHanko does not read the `/Rect`.
pub fn sigfield_rect_magnitude(pdf: &[u8]) -> Option<Vec<u8>> {
    sigfield_with_rect(pdf, [60, -1_000_000_000, 260, 260])
}

/// A new visible signature widget (`/F 132`, a black form XObject appearance of 100 by 40)
/// with the integer `/Rect` `rect`.
pub fn sigfield_with_rect(pdf: &[u8], rect: [i64; 4]) -> Option<Vec<u8>> {
    sig_widget_with_rect(pdf, Object::Array(rect.map(Object::Int).to_vec()))
}

// ---- new markup annotations (D-1, ruling R-2) -------------------------------------------------

/// `[n …]` of reals.
fn reals(values: &[f64]) -> Object {
    Object::Array(values.iter().copied().map(Object::Real).collect())
}

/// A quadrilateral across the page's middle (`[60 390 560 390 60 330 560 330]`), over signed
/// text, in a 20 by 20 `/Rect`.
fn quad_outside(subtype: &str) -> Annot {
    Annot::new(subtype, [60.0, 330.0, 80.0, 350.0])
        .with("C", reals(&[1.0, 1.0, 0.0]))
        .with(
            "QuadPoints",
            reals(&[60.0, 390.0, 560.0, 390.0, 60.0, 330.0, 560.0, 330.0]),
        )
}

/// `annots_highlight_quadpoints_outside`: a highlight with an appearance stream, a 20 by 20
/// `/Rect` and a quadrilateral across the page: poppler draws a highlight from its
/// `/QuadPoints`, appearance or not (QA variant A2-highlight-AP-present-quadpoints-outside).
pub fn annots_highlight_quadpoints_outside(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(
        pdf,
        &quad_outside("Highlight").with_appearance(b"q 1 1 0 rg 0 0 20 20 re f Q"),
    )
}

/// `annots_highlight_no_ap`: the same highlight without an appearance stream (viewers
/// synthesize it from `/QuadPoints`).
pub fn annots_highlight_no_ap(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(pdf, &quad_outside("Highlight"))
}

/// `annots_underline_quadpoints_outside`: an underline with the same geometry and an
/// appearance stream.
pub fn annots_underline_quadpoints_outside(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(
        pdf,
        &quad_outside("Underline").with_appearance(b"q 0 G 1 w 0 1 m 20 1 l S Q"),
    )
}

/// `annots_ink_inklist_outside`: an ink stroke whose `/InkList` crosses the page, in a small
/// `/Rect`, with an appearance stream.
pub fn annots_ink_inklist_outside(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(
        pdf,
        &Annot::new("Ink", [60.0, 100.0, 80.0, 120.0])
            .with(
                "InkList",
                Object::Array(vec![reals(&[60.0, 100.0, 300.0, 450.0, 560.0, 100.0])]),
            )
            .with_appearance(b"q 0 0 1 RG 1 w 1 1 m 19 19 l S Q"),
    )
}

/// `annots_line_outside`: a line whose `/L` crosses the page, in a small `/Rect`.
pub fn annots_line_outside(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(
        pdf,
        &Annot::new("Line", [50.0, 450.0, 70.0, 470.0])
            .with("L", reals(&[50.0, 452.0, 560.0, 452.0]))
            .with_appearance(b"q 0 G 1 w 0 2 m 20 2 l S Q"),
    )
}

/// `annots_polygon_vertices_outside`: a polygon whose `/Vertices` reach across the page.
pub fn annots_polygon_vertices_outside(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(
        pdf,
        &Annot::new("Polygon", [50.0, 432.0, 70.0, 452.0])
            .with(
                "Vertices",
                reals(&[50.0, 432.0, 560.0, 432.0, 560.0, 492.0, 50.0, 492.0]),
            )
            .with("IC", reals(&[1.0, 0.0, 0.0]))
            .with_appearance(b"q 1 0 0 rg 0 0 20 20 re f Q"),
    )
}

/// `annots_text_no_ap`: a sticky note with a 1 by 1 `/Rect` and no appearance stream: viewers
/// draw their own icon of about 20 by 20 points (QA variant A2-text-noAP-icon-tiny-rect).
pub fn annots_text_no_ap(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(
        pdf,
        &Annot::new("Text", [72.0, 700.0, 73.0, 701.0])
            .with("Name", Object::name("Comment"))
            .with("Contents", Object::literal_string("Look here")),
    )
}

/// `annots_text_nozoom`: a sticky note with an appearance stream and `/F 28` (Print | NoZoom |
/// NoRotate), as Acrobat writes them: drawn at a fixed size whatever the zoom.
pub fn annots_text_nozoom(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(
        pdf,
        &Annot::new("Text", [400.0, 700.0, 420.0, 720.0])
            .with("F", Object::Int(28))
            .with("Name", Object::name("Comment"))
            .with_appearance(b"q 1 1 0 rg 0 G 0.5 0.5 19 19 re B Q"),
    )
}

/// The sticky note of [`Annot::text`] (with its appearance stream and popup) on the page with
/// 0-based index `page`.
fn text_on_page(pdf: &[u8], page: usize) -> Option<Vec<u8>> {
    forms::annotate(
        pdf,
        &Annot {
            page,
            ..Annot::text()
        },
    )
}

/// `annots_text_rotated_page_90`: the sticky note of [`Annot::text`] on the second page of
/// [`forms::rotated_pages`] (`/Rotate 90`): a Text annotation does not rotate with the page (ISO
/// 32000-2 §12.5.6.4), so poppler draws it upright at its `/Rect`'s corner, outside the `/Rect`
/// (M4 QA round 2, finding 7, variant A2-r2-text-ap-f4-rotated-page-90).
pub fn annots_text_rotated_page_90(pdf: &[u8]) -> Option<Vec<u8>> {
    text_on_page(pdf, 1)
}

/// `annots_text_rotated_page_180`: the same on the third page (`/Rotate 180`).
pub fn annots_text_rotated_page_180(pdf: &[u8]) -> Option<Vec<u8>> {
    text_on_page(pdf, 2)
}

/// `annots_text_rotated_page_270`: the same on the fourth page (`/Rotate 270`).
pub fn annots_text_rotated_page_270(pdf: &[u8]) -> Option<Vec<u8>> {
    text_on_page(pdf, 3)
}

/// `annots_text_upright_page_control`: the same on the first page (`/Rotate 0`): allowed (D-1).
pub fn annots_text_upright_page_control(pdf: &[u8]) -> Option<Vec<u8>> {
    text_on_page(pdf, 0)
}

/// `annots_square_rotated_page_control`: the square of [`Annot::square`] on the second page
/// (`/Rotate 90`): a square rotates with the page, inside its `/Rect` (allowed, D-1).
pub fn annots_square_rotated_page_control(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(
        pdf,
        &Annot {
            page: 1,
            ..Annot::square()
        },
    )
}

/// `pdf` with a revision that sets `/Rotate 90` on its root page-tree node, before signing:
/// every page inherits it (§7.7.3.4; QA variant A2-r2-text-ap-f4-inherited-rotate-pages-node).
pub fn rotated_page_tree_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let root = store.root_id()?;
        let pages = store.resolve(root).ok()?.as_dict()?.get_ref(b"Pages")?;
        let mut dict = store.resolve(pages).ok()?.as_dict()?.clone();
        dict.insert("Rotate", Object::Int(90));
        store.set(pages, Object::Dict(dict)).ok()
    })
}

/// `annots_square_negative_rd`: a square whose `/RD` insets are negative (the drawn rectangle
/// extends outside the `/Rect` where viewers synthesize it).
pub fn annots_square_negative_rd(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(
        pdf,
        &Annot::square().with("RD", reals(&[-100.0, -100.0, -100.0, -100.0])),
    )
}

/// The annotation of `annot` added in a revision, then its `/AP /N` stream object replaced by
/// `edit(store, page, stream)` (the new value of the stream object, or `None` to give up).
fn annotate_with_stream(
    pdf: &[u8],
    annot: &Annot,
    edit: impl FnOnce(&mut Store, ObjectId, ObjectId) -> Option<Object>,
) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let (id, _) = forms::add_annotation(store, annot)?;
        let page = first_page(store)?;
        let dict = store.resolve(id).ok()?.as_dict()?.clone();
        let stream = dict.get_dict(b"AP")?.get_ref(b"N")?;
        let value = edit(store, page, stream)?;
        store.set(stream, value).ok()
    })
}

/// `annots_square_ap_no_bbox`: a square whose appearance stream has no `/BBox` and paints over
/// the page (QA variant R5-annotation-square-ap-no-bbox).
pub fn annots_square_ap_no_bbox(pdf: &[u8]) -> Option<Vec<u8>> {
    annotate_with_stream(pdf, &Annot::square(), |store, page, _| {
        let mut dict = form_without_bbox();
        if let Some(resources) = store
            .resolve(page)
            .ok()?
            .as_dict()?
            .get(b"Resources")
            .cloned()
        {
            dict.insert("Resources", resources);
        }
        let stream = Stream::new(
            dict,
            StreamData::Decoded(
                b"1 1 1 rg 0 0 612 792 re f 0 g BT /F1 24 Tf 72 720 Td (FORGED) Tj ET".to_vec(),
            ),
        );
        Some(Object::Stream(Box::new(stream)))
    })
}

/// `annots_square_ap_page_content`: a square whose `/AP /N` is the page's content stream (an
/// existing object, no form XObject).
pub fn annots_square_ap_page_content(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let page = first_page(store)?;
        let content = store.resolve(page).ok()?.as_dict()?.get_ref(b"Contents")?;
        let (id, _) = forms::add_annotation(store, &Annot::square())?;
        let mut dict = store.resolve(id).ok()?.as_dict()?.clone();
        let mut ap = Dict::new();
        ap.insert("N", Object::Ref(content));
        dict.insert("AP", Object::Dict(ap));
        store.set(id, Object::Dict(dict)).ok()
    })
}

// ---- number spellings readers read differently (M4 QA round 3, manager ruling R-12) ----------

/// `updated` (`pdf` with a revision appended) with the one occurrence of `from` in the appended
/// bytes replaced by `to`, of the same length (the cross-reference offsets stay right). `None`
/// unless `from` occurs exactly once there.
fn respell(pdf: &[u8], mut updated: Vec<u8>, from: &[u8], to: &[u8]) -> Option<Vec<u8>> {
    if from.len() != to.len() || from.is_empty() {
        return None;
    }
    let suffix = updated.get(pdf.len()..)?;
    let mut found = suffix
        .windows(from.len())
        .enumerate()
        .filter(|(_, window)| *window == from)
        .map(|(at, _)| at);
    let at = found.next()?;
    if found.next().is_some() {
        return None;
    }
    let start = pdf.len().checked_add(at)?;
    updated
        .get_mut(start..start.checked_add(to.len())?)?
        .copy_from_slice(to);
    Some(updated)
}

/// [`respell`] for a `to` of any length: `updated` with the one occurrence of `from` in the bytes
/// appended to `pdf` replaced by `to`, and the appended revision's classic cross-reference
/// entries and `startxref` shifted to match (its objects precede its cross-reference section,
/// as the incremental writer writes them, with 20-byte entries). `None` unless `from` occurs
/// exactly once there, before the section.
fn respell_resized(pdf: &[u8], updated: &[u8], from: &[u8], to: &[u8]) -> Option<Vec<u8>> {
    let suffix = updated.get(pdf.len()..)?;
    let mut found = suffix
        .windows(from.len())
        .enumerate()
        .filter(|(_, window)| *window == from)
        .map(|(at, _)| at);
    let at = pdf.len().checked_add(found.next()?)?;
    if found.next().is_some() || from.is_empty() {
        return None;
    }
    let startxref = updated.windows(9).rposition(|w| w == b"startxref")?;
    let number_at = startxref + 9;
    let digits: Vec<u8> = updated
        .get(number_at..)?
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .take_while(u8::is_ascii_digit)
        .collect();
    let xref: usize = std::str::from_utf8(&digits).ok()?.parse().ok()?;
    if xref <= at {
        return None;
    }
    let grow = to.len().checked_sub(from.len());
    let shift = |offset: usize| match grow {
        Some(grow) => offset.checked_add(grow),
        None => offset.checked_sub(from.len() - to.len()),
    };
    let mut out = updated.get(..at)?.to_vec();
    out.extend_from_slice(to);
    out.extend_from_slice(updated.get(at + from.len()..startxref)?);
    let new_xref = shift(xref)?;
    // The section: `xref`, subsections `first count` and their entries.
    let section = out.get(new_xref..)?;
    if !section.starts_with(b"xref") {
        return None;
    }
    let mut pos = new_xref + 4;
    loop {
        while out.get(pos).is_some_and(u8::is_ascii_whitespace) {
            pos += 1;
        }
        if out.get(pos..)?.starts_with(b"trailer") {
            break;
        }
        let line_end = pos + out.get(pos..)?.iter().position(|&b| b == b'\n')?;
        let header = std::str::from_utf8(out.get(pos..line_end)?).ok()?;
        let count: usize = header.split_whitespace().nth(1)?.parse().ok()?;
        pos = line_end + 1;
        for _ in 0..count {
            let entry = out.get(pos..pos + 20)?;
            if entry.get(17) == Some(&b'n') {
                let offset: usize = std::str::from_utf8(entry.get(..10)?).ok()?.parse().ok()?;
                if offset > at {
                    let text = format!("{:010}", shift(offset)?);
                    out.get_mut(pos..pos + 10)?.copy_from_slice(text.as_bytes());
                }
            }
            pos += 20;
        }
    }
    out.extend_from_slice(format!("startxref\n{new_xref}\n%%EOF\n").as_bytes());
    Some(out)
}

/// `sigfield_rect_padded(pdf, index, zeros)` (M4 QA round 4, finding 2, variants
/// R3-i-rect-zero-padded-*): a new visible signature widget with `/Rect [300 300 400 340]` whose
/// number `index` is written with `zeros` leading zeros. Folioxide, poppler and pyHanko read the
/// number's value; PDFium reads a word of 256 characters or more as 0 and paints the appearance
/// outside the `/Rect` (29,700 pixels for y2, 11,920 for x1).
pub fn sigfield_rect_padded(pdf: &[u8], index: usize, zeros: usize) -> Option<Vec<u8>> {
    let numbers = [300, 300, 400, 340];
    let rect = Object::Array(numbers.iter().map(|&n| Object::Int(n)).collect());
    let updated = sig_widget_with_rect(pdf, rect)?;
    let padded: Vec<String> = numbers
        .iter()
        .enumerate()
        .map(|(i, n)| {
            if i == index {
                format!("{}{n}", "0".repeat(zeros))
            } else {
                n.to_string()
            }
        })
        .collect();
    let to = format!("[{}]", padded.join(" "));
    respell_resized(pdf, &updated, b"[300 300 400 340]", to.as_bytes())
}

/// The leading zeros of the zero-padded corpus cases (M4 QA round 4, finding 2): more than the
/// canonical-input gate allows (an integer has at most 11 characters), few enough that every
/// installed reader reads the number (pypdf reads at most about 45 characters per number, so the oracle's
/// extraction runs and pyHanko's verdict is compared). PDFium misreads from 256 characters on;
/// QA's lengths (260, 1,000 and 100,000 zeros) are Rust tests of their own.
pub const ORACLE_ZERO_PADDING: usize = 32;

/// `sigfield_rect_zero_padded` (variants R3-i-rect-zero-padded-integer-*): the `/Rect` y2
/// written with [`ORACLE_ZERO_PADDING`] leading zeros.
pub fn sigfield_rect_zero_padded(pdf: &[u8]) -> Option<Vec<u8>> {
    sigfield_rect_padded(pdf, 3, ORACLE_ZERO_PADDING)
}

/// `sigfield_rect_zero_padded_x1` (variants R3-i-rect-zero-padded-x1-*): the `/Rect` x1 written
/// with [`ORACLE_ZERO_PADDING`] leading zeros.
pub fn sigfield_rect_zero_padded_x1(pdf: &[u8]) -> Option<Vec<u8>> {
    sigfield_rect_padded(pdf, 0, ORACLE_ZERO_PADDING)
}

/// `sigfield_rect_integer_overflow` (QA variants R3-h-num-y2-4294967296-03,
/// A3-r3-newsigwidget-rect-y2-2pow32-approval): a new visible signature widget with `/Rect [300
/// 300 400 4294967296]`. Folioxide's lexer reads the large integer, PDFium reads 0 and paints
/// the appearance over y 0 to 300.
pub fn sigfield_rect_integer_overflow(pdf: &[u8]) -> Option<Vec<u8>> {
    sig_widget_with_rect(
        pdf,
        Object::Array(vec![
            Object::Int(300),
            Object::Int(300),
            Object::Int(400),
            Object::Int(4_294_967_296),
        ]),
    )
}

/// `sigfield_rect_int32_min` (QA variant A3-r3-newsigwidget-rect-y2-int32-min-approval): `/Rect
/// [300 300 400 -2147483648]`, which PDFium reads as 0 too.
pub fn sigfield_rect_int32_min(pdf: &[u8]) -> Option<Vec<u8>> {
    sig_widget_with_rect(
        pdf,
        Object::Array(vec![
            Object::Int(300),
            Object::Int(300),
            Object::Int(400),
            Object::Int(-2_147_483_648),
        ]),
    )
}

/// `sigfield_rect_multisign` (QA variants R5z-rect-multisign-last, R5z-rect-plusminus): `/Rect
/// [300 300 400 --341]`, which Folioxide reads as −341 and PDFium as 0.
pub fn sigfield_rect_multisign(pdf: &[u8]) -> Option<Vec<u8>> {
    let updated = sig_widget_with_rect(
        pdf,
        Object::Array(vec![
            Object::Int(300),
            Object::Int(300),
            Object::Int(400),
            Object::Int(-3417),
        ]),
    )?;
    respell(pdf, updated, b"-3417", b"--341")
}

/// `annots_square_rect_integer_overflow` (QA variant A2-r3-square-rect-y2-2pow32-cert3): the
/// square of [`Annot::square`] with `/Rect [300 300 400 4294967296]` (PDFium: y 0 to 300).
pub fn annots_square_rect_integer_overflow(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(
        pdf,
        &Annot::square().with(
            "Rect",
            Object::Array(vec![
                Object::Int(300),
                Object::Int(300),
                Object::Int(400),
                Object::Int(4_294_967_296),
            ]),
        ),
    )
}

// ---- page trees readers walk differently (M4 QA round 3, manager ruling R-13) -----------------

/// `pdf` with `/Rotate 90` on its root page-tree node and its first page's `/Parent` changed by
/// `parent` (given the store, the page and the root node), before signing.
fn rotated_tree_with_parent(
    pdf: &[u8],
    parent: impl FnOnce(&mut Store, ObjectId) -> Option<Option<Object>>,
) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let root = store.root_id()?;
        let pages = store.resolve(root).ok()?.as_dict()?.get_ref(b"Pages")?;
        let mut node = store.resolve(pages).ok()?.as_dict()?.clone();
        node.insert("Rotate", Object::Int(90));
        store.set(pages, Object::Dict(node)).ok()?;
        let page = forms::page_id(store, 0)?;
        let new_parent = parent(store, page)?;
        let mut dict = store.resolve(page).ok()?.as_dict()?.clone();
        match new_parent {
            Some(value) => {
                dict.insert("Parent", value);
            }
            None => {
                dict.remove(b"Parent".as_slice());
            }
        }
        store.set(page, Object::Dict(dict)).ok()
    })
}

/// `pdf` (`minimal`-like: one page) with a second page, listed both by the root node's `/Kids`
/// and by the `/Kids` of the first page, which also gets `/Rotate 90` (M4 QA round 4, finding
/// 10, base `pt_pagekids_rot_cert3`): poppler walks the first page as a page (its `/Type`) and
/// lists two pages, the first rotated; PDFium walks it as a node (its `/Kids`) and lists the
/// second page twice, upright.
pub fn page_with_kids_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let root = store.root_id()?;
        let pages = store.resolve(root).ok()?.as_dict()?.get_ref(b"Pages")?;
        let first = forms::page_id(store, 0)?;
        let mut first_dict = store.resolve(first).ok()?.as_dict()?.clone();
        let mut second = first_dict.clone();
        second.remove(b"Annots".as_slice());
        let second = store.add(Object::Dict(second)).ok()?;
        first_dict.insert("Rotate", Object::Int(90));
        first_dict.insert("Kids", Object::Array(vec![Object::Ref(second)]));
        store.set(first, Object::Dict(first_dict)).ok()?;
        let mut node = store.resolve(pages).ok()?.as_dict()?.clone();
        node.insert(
            "Kids",
            Object::Array(vec![Object::Ref(first), Object::Ref(second)]),
        );
        node.insert("Count", Object::Int(2));
        store.set(pages, Object::Dict(node)).ok()
    })
}

/// `pdf` whose root page-tree node has `/Rotate 90` and whose first page has no `/Parent` (QA
/// variant A2-r3-text-page-without-parent-key-in-rotated-tree): poppler inherits the rotation
/// along `/Kids`, PDFium follows the missing `/Parent` and draws the page upright.
pub fn rotated_tree_page_without_parent_input(pdf: &[u8]) -> Option<Vec<u8>> {
    rotated_tree_with_parent(pdf, |_, _| Some(None))
}

/// `pdf` whose root page-tree node has `/Rotate 90` and whose first page's `/Parent` is a new
/// `/Pages` node without `/Rotate` that the tree does not reach (QA variant
/// A2-r3-text-parent-chain-upright-kids-chain-rotated).
pub fn rotated_tree_parent_elsewhere_input(pdf: &[u8]) -> Option<Vec<u8>> {
    rotated_tree_with_parent(pdf, |store, page| {
        let mut node = Dict::new();
        node.insert("Type", Object::name("Pages"));
        node.insert("Kids", Object::Array(vec![Object::Ref(page)]));
        node.insert("Count", Object::Int(1));
        let node = store.add(Object::Dict(node)).ok()?;
        Some(Some(Object::Ref(node)))
    })
}

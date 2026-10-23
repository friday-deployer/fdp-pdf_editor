//! Annotations after signing (M4 brief §5.2, §5.4): the markup annotations a reviewer adds to a
//! document certified with `P = 3` (D-1), and the variants the annotation whitelist refuses.
//!
//! Every generator takes a **signed** document whose first page has an existing annotation
//! ([`annotated_input`], prepared **before** signing) and appends one revision. `None` when the
//! expected objects are missing.

use folioxide_syntax::{Dict, Object, ObjectId, Store};

use super::with_incremental;
use crate::fixtures::forms::{self, Annot};

/// The `/NM` of the annotation [`annotated_input`] adds.
pub const EXISTING_ANNOTATION: &str = "existing-square";

/// `pdf` with a revision that adds a reviewer's square annotation (`/NM (existing-square)`) to
/// its first page, before signing: the existing annotation of the `annots_existing_*` cases.
pub fn annotated_input(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(
        pdf,
        &Annot::square()
            .with("NM", Object::literal_string(EXISTING_ANNOTATION))
            .with("Contents", Object::literal_string("Signed comment")),
    )
}

/// The existing annotation of [`annotated_input`].
fn existing(store: &Store) -> Option<ObjectId> {
    store.object_ids().into_iter().find(|&id| {
        store.resolve(id).ok().is_some_and(|o| {
            o.as_dict()
                .is_some_and(|d| d.get_str_bytes(b"NM") == Some(EXISTING_ANNOTATION.as_bytes()))
        })
    })
}

// ---- the D-1 markup annotations (M4 brief §0.2) -------------------------------------------------

/// `*_text_popup`: a sticky note with its popup.
pub fn markup_text_popup(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(pdf, &Annot::text())
}

/// `*_highlight`: a highlight over the page heading.
pub fn markup_highlight(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(pdf, &Annot::highlight())
}

/// `*_square`: a red square.
pub fn markup_square(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(pdf, &Annot::square())
}

/// `*_ink`: a freehand stroke.
pub fn markup_ink(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(pdf, &Annot::ink())
}

/// `*_freetext`: free text with its own font in the appearance.
pub fn markup_freetext(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(pdf, &Annot::free_text())
}

/// `*_stamp`: an "Approved" stamp.
pub fn markup_stamp(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(pdf, &Annot::stamp())
}

/// `annots_reply`: a sticky note replying (`/IRT`) to the existing annotation (A5).
pub fn annots_reply(pdf: &[u8]) -> Option<Vec<u8>> {
    let target = existing(
        &folioxide_syntax::Store::open_bytes(
            pdf.to_vec(),
            &folioxide_syntax::OpenOptions::default(),
        )
        .ok()?,
    )?;
    forms::annotate(
        pdf,
        &Annot::text()
            .with("IRT", Object::Ref(target))
            .with("RT", Object::name("R")),
    )
}

// ---- refused (OTHER for Folioxide and pyHanko) --------------------------------------------------

/// `annots_link_uri`: a link annotation with a URI action over the page.
pub fn annots_link_uri(pdf: &[u8]) -> Option<Vec<u8>> {
    let mut action = Dict::new();
    action.insert("S", Object::name("URI"));
    action.insert("URI", Object::literal_string("https://example.invalid/pay"));
    forms::annotate(
        pdf,
        &Annot::new("Link", [0.0, 0.0, 612.0, 792.0]).with("A", Object::Dict(action)),
    )
}

/// `annots_js_action`: a square with a page-open JavaScript action (`/AA /PO`).
pub fn annots_js_action(pdf: &[u8]) -> Option<Vec<u8>> {
    let mut js = Dict::new();
    js.insert("S", Object::name("JavaScript"));
    js.insert("JS", Object::literal_string("app.alert('signed');"));
    let mut aa = Dict::new();
    aa.insert("PO", Object::Dict(js));
    forms::annotate(pdf, &Annot::square().with("AA", Object::Dict(aa)))
}

/// `annots_file_attachment`: a file attachment annotation.
pub fn annots_file_attachment(pdf: &[u8]) -> Option<Vec<u8>> {
    let mut spec = Dict::new();
    spec.insert("Type", Object::name("Filespec"));
    spec.insert("F", Object::literal_string("invoice.exe"));
    forms::annotate(
        pdf,
        &Annot::new("FileAttachment", [400.0, 600.0, 420.0, 620.0])
            .with("FS", Object::Dict(spec))
            .with("Name", Object::name("PushPin")),
    )
}

/// `annots_widget_added`: a new text widget disguised among the annotations (on the page, in no
/// field tree), with an appearance that draws text.
pub fn annots_widget_added(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(
        pdf,
        &Annot::new("Widget", [72.0, 600.0, 300.0, 630.0])
            .with("FT", Object::name("Tx"))
            .with("T", Object::literal_string("Injected"))
            .with("V", Object::literal_string("900 EUR"))
            .with_appearance(b"BT /Helv 12 Tf 2 8 Td (900 EUR) Tj ET"),
    )
}

/// `annots_oc`: a square under optional content (`/OC`, a new optional content group).
pub fn annots_oc(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let mut group = Dict::new();
        group.insert("Type", Object::name("OCG"));
        group.insert("Name", Object::literal_string("Hidden layer"));
        let group = store.add(Object::Dict(group)).ok()?;
        forms::add_annotation(store, &Annot::square().with("OC", Object::Ref(group)))?;
        Some(())
    })
}

/// `annots_noview_print`: a square that prints but is not shown on screen (`/F` Print | NoView).
pub fn annots_noview_print(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(pdf, &Annot::square().with("F", Object::Int(36)))
}

/// `annots_popup_foreign_parent`: a new popup whose `/Parent` is the existing annotation (A4).
pub fn annots_popup_foreign_parent(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let parent = existing(store)?;
        let popup = Annot::new("Popup", [300.0, 400.0, 460.0, 480.0])
            .with("Parent", Object::Ref(parent))
            .with("Open", Object::Bool(true));
        forms::add_annotation(store, &popup)?;
        Some(())
    })
}

/// `annots_existing_removed`: the existing annotation removed from the page's `/Annots`.
pub fn annots_existing_removed(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_page_annots(pdf, |store, annots| {
        let target = existing(store)?;
        let before = annots.len();
        annots.retain(|a| a.as_ref() != Some(target));
        (annots.len() < before).then_some(())
    })
}

/// `annots_existing_modified`: the existing annotation's `/Contents` changed.
pub fn annots_existing_modified(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let target = existing(store)?;
        let mut dict = store.resolve(target).ok()?.as_dict()?.clone();
        dict.insert("Contents", Object::literal_string("Changed comment"));
        store.set(target, Object::Dict(dict)).ok()
    })
}

/// `annots_reordered`: the page's `/Annots` reversed (the existing annotation and the signature
/// widget swap places).
pub fn annots_reordered(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_page_annots(pdf, |_, annots| {
        if annots.len() < 2 {
            return None;
        }
        annots.reverse();
        Some(())
    })
}

/// `annots_redact`: a redaction annotation over the page heading.
pub fn annots_redact(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(
        pdf,
        &Annot::new("Redact", [70.0, 715.0, 300.0, 740.0])
            .with("OverlayText", Object::literal_string("PAID")),
    )
}

/// `annots_structparent`: a square with a `/StructParent` (A2 refuses structure links).
pub fn annots_structparent(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(pdf, &Annot::square().with("StructParent", Object::Int(7)))
}

/// `annots_popup_without_parent`: a popup alone (A4).
pub fn annots_popup_without_parent(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::annotate(
        pdf,
        &Annot::new("Popup", [300.0, 400.0, 460.0, 480.0]).with("Open", Object::Bool(true)),
    )
}

/// `annots_irt_unlisted`: a reply (`/IRT`) to an annotation that no page lists (A5).
pub fn annots_irt_unlisted(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let ghost = store
            .add(Object::Dict(Annot::square().entries.into_iter().fold(
                Dict::new(),
                |mut d, (k, v)| {
                    d.insert(k.as_str(), v);
                    d
                },
            )))
            .ok()?;
        forms::add_annotation(store, &Annot::text().with("IRT", Object::Ref(ghost)))?;
        Some(())
    })
}

/// Edits the first page's `/Annots` (direct or indirect) in a new revision.
fn edit_page_annots(
    pdf: &[u8],
    edit: impl FnOnce(&Store, &mut Vec<Object>) -> Option<()>,
) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let page = forms::page_id(store, 0)?;
        let mut dict = store.resolve(page).ok()?.as_dict()?.clone();
        match dict.get(b"Annots").cloned()? {
            Object::Ref(array) => {
                let mut items = store.resolve(array).ok()?.as_array()?.to_vec();
                edit(store, &mut items)?;
                store.set(array, Object::Array(items)).ok()
            }
            Object::Array(mut items) => {
                edit(store, &mut items)?;
                dict.insert("Annots", Object::Array(items));
                store.set(page, Object::Dict(dict)).ok()
            }
            _ => None,
        }
    })
}

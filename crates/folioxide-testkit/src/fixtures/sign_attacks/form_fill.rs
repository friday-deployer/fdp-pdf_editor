//! Generic form filling after signing (M4 brief §5.1, §5.4): the control cases a form filler
//! produces, and the variants the form-filling whitelist must refuse.
//!
//! Every generator takes a **signed** [`acroform`](crate::fixtures::forms::acroform) document (or
//! one of the variants the `*_input` functions prepare **before** signing) and appends one
//! revision through `Store` edits and the incremental writer. `None` when the expected field is
//! missing.

use folioxide_syntax::{Dict, Object, ObjectId, Store, Stream, StreamData};

use super::with_incremental;
use crate::fixtures::forms::{
    self, AGREE, AMOUNT, CHOICE, COUNTRY, Fill, FillAppearance, FillValue, field_by_name, ids,
};

// =================================================================================================
// Inputs: variants of the form document, prepared before signing.
// =================================================================================================

/// Edits the dictionary of the field `name` of `pdf` in a new revision.
fn edit_named(pdf: &[u8], name: &str, edit: impl FnOnce(&mut Store, &mut Dict)) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let (id, _) = field_by_name(store, name)?;
        let mut dict = store.resolve(id).ok()?.as_dict()?.clone();
        edit(store, &mut dict);
        store.set(id, Object::Dict(dict)).ok()
    })
}

/// The form with the text field `Amount` hidden: `/F 6` (Hidden | Print, §12.5.3).
pub fn form_hidden_widget_input(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, AMOUNT, |_, dict| {
        dict.insert("F", Object::Int(6));
    })
}

/// The empty signature fields of [`form_flagged_widgets_input`], each with the annotation flags
/// its widget carries (§12.5.3): NoRotate (20 = Print | NoRotate), NoZoom (12), Hidden (6) and
/// NoView (36).
pub const FLAGGED_SIG_FIELDS: [(&str, i64); 4] = [
    ("NoRotateSig", 20),
    ("NoZoomSig", 12),
    ("HiddenSig", 6),
    ("NoViewSig", 36),
];

/// The `/Rect` of the empty signature field `index` of [`FLAGGED_SIG_FIELDS`].
pub fn flagged_sig_field_rect(index: usize) -> [i64; 4] {
    let y = 200 + 70 * index as i64;
    [320, y, 520, y + 50]
}

/// The form with widgets drawn upright or unscaled (M4 QA round 2, expert finding and finding 5):
/// its page turned by 90 degrees (`/Rotate 90`), the text field `Amount` and the check box
/// `Agree` with `/F 20` (Print | NoRotate), and four new empty signature fields
/// ([`FLAGGED_SIG_FIELDS`]) whose widgets set NoRotate, NoZoom, Hidden or NoView. Prepared before
/// signing.
pub fn form_flagged_widgets_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let page = forms::page_id(store, 0)?;
        let mut page_dict = store.resolve(page).ok()?.as_dict()?.clone();
        page_dict.insert("Rotate", Object::Int(90));
        store.set(page, Object::Dict(page_dict)).ok()?;
        for name in [AMOUNT, AGREE] {
            let (id, _) = field_by_name(store, name)?;
            let mut dict = store.resolve(id).ok()?.as_dict()?.clone();
            dict.insert("F", Object::Int(20));
            store.set(id, Object::Dict(dict)).ok()?;
        }
        let root = store.root_id()?;
        let acroform = store.resolve(root).ok()?.as_dict()?.get_ref(b"AcroForm")?;
        for (index, (name, flags)) in FLAGGED_SIG_FIELDS.iter().enumerate() {
            let mut field = Dict::new();
            field.insert("Type", Object::name("Annot"));
            field.insert("Subtype", Object::name("Widget"));
            field.insert("FT", Object::name("Sig"));
            field.insert("T", Object::literal_string(*name));
            field.insert("F", Object::Int(*flags));
            field.insert(
                "Rect",
                Object::Array(
                    flagged_sig_field_rect(index)
                        .into_iter()
                        .map(Object::Int)
                        .collect(),
                ),
            );
            field.insert("P", Object::Ref(page));
            let id = store.add(Object::Dict(field)).ok()?;
            forms::append_to_annots(store, page, id)?;
            let mut form = store.resolve(acroform).ok()?.as_dict()?.clone();
            let mut fields = form.get_array(b"Fields")?.to_vec();
            fields.push(Object::Ref(id));
            form.insert("Fields", Object::Array(fields));
            store.set(acroform, Object::Dict(form)).ok()?;
        }
        Some(())
    })
}

/// The form with the text field `Amount` ReadOnly (`/Ff 1`, §12.7.4.1).
pub fn form_readonly_input(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, AMOUNT, |_, dict| {
        dict.insert("Ff", Object::Int(1));
    })
}

/// The form with an XFA form in the AcroForm (`/XFA`, a stream of XDP datasets; §12.7.9).
pub fn form_xfa_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let xdp = b"<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\"><xfa:datasets \
            xmlns:xfa=\"http://www.xfa.org/schema/xfa-data/1.0/\"><xfa:data><form>\
            <Amount>100 EUR</Amount></form></xfa:data></xfa:datasets></xdp:xdp>";
        let stream = Stream::new(Dict::new(), StreamData::Decoded(xdp.to_vec()));
        let xfa = store.add(Object::Stream(Box::new(stream))).ok()?;
        let id = ObjectId::new(ids::ACROFORM, 0);
        let mut acroform = store.resolve(id).ok()?.as_dict()?.clone();
        acroform.insert("XFA", Object::Ref(xfa));
        store.set(id, Object::Dict(acroform)).ok()
    })
}

/// The form with an orphan check box widget: on the page (its `/Annots`), with the states
/// `/Yes` and `/Off` and `/AS /Off`, but in no field tree (not in `/Fields`).
pub fn form_orphan_widget_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let page = forms::page_id(store, 0)?;
        let yes = ObjectId::new(ids::AGREE_YES, 0);
        let off = ObjectId::new(ids::AGREE_OFF, 0);
        let mut normal = Dict::new();
        normal.insert("Yes", Object::Ref(yes));
        normal.insert("Off", Object::Ref(off));
        let mut ap = Dict::new();
        ap.insert("N", Object::Dict(normal));
        let mut widget = Dict::new();
        widget.insert("Type", Object::name("Annot"));
        widget.insert("Subtype", Object::name("Widget"));
        widget.insert("FT", Object::name("Btn"));
        widget.insert("T", Object::literal_string("Orphan"));
        widget.insert("AS", Object::name("Off"));
        widget.insert("F", Object::Int(4));
        widget.insert("Rect", int_rect([200, 550, 220, 570]));
        widget.insert("P", Object::Ref(page));
        widget.insert("AP", Object::Dict(ap));
        let id = store.add(Object::Dict(widget)).ok()?;
        forms::append_to_annots(store, page, id)
    })
}

/// The form whose page also draws the `Amount` field's appearance stream as a form XObject
/// `/Fx` (so the stream has a second use, M4 brief §5.1 F5).
pub fn form_ap_shared_with_page_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let page = ObjectId::new(ids::PAGE, 0);
        let mut dict = store.resolve(page).ok()?.as_dict()?.clone();
        let mut resources = dict.get_dict(b"Resources")?.clone();
        let mut xobjects = Dict::new();
        xobjects.insert("Fx", Object::Ref(ObjectId::new(ids::AMOUNT_AP, 0)));
        resources.insert("XObject", Object::Dict(xobjects));
        dict.insert("Resources", Object::Dict(resources));
        let drawn = Stream::new(
            Dict::new(),
            StreamData::Decoded(b"q 1 0 0 1 320 600 cm /Fx Do Q".to_vec()),
        );
        let drawn = store.add(Object::Stream(Box::new(drawn))).ok()?;
        dict.insert(
            "Contents",
            Object::Array(vec![
                Object::Ref(ObjectId::new(ids::CONTENT, 0)),
                Object::Ref(drawn),
            ]),
        );
        store.set(page, Object::Dict(dict)).ok()
    })
}

/// The form whose `Amount` appearance stream keeps its own `/Resources << /Font << /Helv … >>
/// >>` but draws its text with `/F9`, a name those resources lack (M4 QA round 1, the F7
/// residual: a viewer may look the name up in the AcroForm's `/DR`).
pub fn form_ap_missing_font_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let id = ObjectId::new(ids::AMOUNT_AP, 0);
        let value = store.resolve(id).ok()?;
        let Object::Stream(stream) = &*value else {
            return None;
        };
        let content = b"/Tx BMC q BT /F9 12 Tf 0 g 2 9 Td (100 EUR) Tj ET Q EMC".to_vec();
        let mut dict = stream.dict.clone();
        dict.remove(b"Filter".as_slice());
        dict.remove(b"DecodeParms".as_slice());
        dict.remove(b"Length".as_slice());
        store
            .set(
                id,
                Object::Stream(Box::new(Stream::new(dict, StreamData::Decoded(content)))),
            )
            .ok()
    })
}

/// The form whose `Amount` appearance stream is replaced by `content` with the resources
/// `resources(store)` (M4 QA round 2, finding 22).
fn amount_appearance(
    pdf: &[u8],
    content: &[u8],
    resources: impl FnOnce(&mut Store) -> Option<Dict>,
) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let id = ObjectId::new(ids::AMOUNT_AP, 0);
        let value = store.resolve(id).ok()?;
        let Object::Stream(stream) = &*value else {
            return None;
        };
        let mut dict = stream.dict.clone();
        for key in [b"Filter".as_slice(), b"DecodeParms", b"Length"] {
            dict.remove(key);
        }
        dict.insert("Resources", Object::Dict(resources(store)?));
        let stream = Stream::new(dict, StreamData::Decoded(content.to_vec()));
        store.set(id, Object::Stream(Box::new(stream))).ok()
    })
}

/// The form whose `Amount` appearance paints with a tiling pattern (§8.7.3.1) whose cell, a
/// content stream without resources of its own, draws text with `/F9`, a name no resources
/// define (M4 QA round 2, finding 22, variant R1x-pattern-stream-no-resources).
pub fn form_ap_pattern_input(pdf: &[u8]) -> Option<Vec<u8>> {
    amount_appearance(
        pdf,
        b"/Tx BMC q /Pattern cs /P0 scn 0 0 200 30 re f Q EMC",
        |store| {
            let mut cell = Dict::new();
            cell.insert("Type", Object::name("Pattern"));
            cell.insert("PatternType", Object::Int(1));
            cell.insert("PaintType", Object::Int(1));
            cell.insert("TilingType", Object::Int(1));
            cell.insert(
                "BBox",
                Object::Array([0, 0, 40, 20].map(Object::Int).to_vec()),
            );
            cell.insert("XStep", Object::Int(40));
            cell.insert("YStep", Object::Int(20));
            let cell = Stream::new(
                cell,
                StreamData::Decoded(b"BT /F9 9 Tf 0 g 1 6 Td (EUR) Tj ET".to_vec()),
            );
            let cell = store.add(Object::Stream(Box::new(cell))).ok()?;
            let mut patterns = Dict::new();
            patterns.insert("P0", Object::Ref(cell));
            let mut resources = Dict::new();
            resources.insert("Pattern", Object::Dict(patterns));
            Some(resources)
        },
    )
}

/// The form whose `Amount` appearance draws text in a Type 3 font (§9.6.4) without resources of
/// its own, whose glyph procedure uses `/F9`, a name no resources define (M4 QA round 2, finding
/// 22, variant R1x-type3-charproc-no-resources).
pub fn form_ap_type3_input(pdf: &[u8]) -> Option<Vec<u8>> {
    type3_appearance(pdf, false)
}

/// [`form_ap_type3_input`] with the Type 3 font's `/Subtype` an indirect object (`/Type3`), which
/// readers dereference (M4 QA round 4, finding 12, variant R1w-subtype-t3-indirect).
pub fn form_ap_type3_indirect_subtype_input(pdf: &[u8]) -> Option<Vec<u8>> {
    type3_appearance(pdf, true)
}

/// The form XObject `/Subtype`, as a name or (`indirect`) as a new indirect name object.
fn subtype(store: &mut Store, name: &str, indirect: bool) -> Option<Object> {
    if indirect {
        Some(Object::Ref(store.add(Object::name(name)).ok()?))
    } else {
        Some(Object::name(name))
    }
}

/// The form XObject `/X` (its `/Subtype /Form` direct, or `indirect`) without resources of its
/// own, whose content uses `/F9`, a name no resources define.
fn form_using_f9(store: &mut Store, indirect: bool) -> Option<ObjectId> {
    let mut form = Dict::new();
    form.insert("Type", Object::name("XObject"));
    form.insert("Subtype", subtype(store, "Form", indirect)?);
    form.insert(
        "BBox",
        Object::Array([0, 0, 200, 30].map(Object::Int).to_vec()),
    );
    let form = Stream::new(
        form,
        StreamData::Decoded(b"BT /F9 9 Tf 0 g 2 9 Td (EUR) Tj ET".to_vec()),
    );
    store.add(Object::Stream(Box::new(form))).ok()
}

/// The form whose `Amount` appearance draws a nested form XObject whose `/Subtype /Form` is an
/// indirect object and whose content uses `/F9` (M4 QA round 4, finding 12, variants
/// R1w-subtype-form-indirect and R2w-dr-gains-hexescaped-name-used-in-nested): readers
/// dereference `/Subtype` and draw it.
pub fn form_ap_indirect_subtype_input(pdf: &[u8]) -> Option<Vec<u8>> {
    amount_appearance(pdf, b"/Tx BMC q /X Do Q EMC", |store| {
        let form = form_using_f9(store, true)?;
        let mut forms = Dict::new();
        forms.insert("X", Object::Ref(form));
        let mut resources = Dict::new();
        resources.insert("XObject", Object::Dict(forms));
        Some(resources)
    })
}

/// The form whose `Amount` appearance, without `/Resources` of its own, draws `/Fm0`, a form
/// XObject that only the page's `/Resources` define and whose content uses `/F9` (M4 QA round
/// 4, finding 12, variant R1w-page-level-form): readers resolve the appearance's names in the
/// page's resources (ISO 32000-2 §7.8.3).
pub fn form_ap_page_level_form_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let form = form_using_f9(store, false)?;
        let page = ObjectId::new(ids::PAGE, 0);
        let mut dict = store.resolve(page).ok()?.as_dict()?.clone();
        let mut resources = dict.get_dict(b"Resources")?.clone();
        let mut forms = Dict::new();
        forms.insert("Fm0", Object::Ref(form));
        resources.insert("XObject", Object::Dict(forms));
        dict.insert("Resources", Object::Dict(resources));
        store.set(page, Object::Dict(dict)).ok()?;
        let id = ObjectId::new(ids::AMOUNT_AP, 0);
        let value = store.resolve(id).ok()?;
        let Object::Stream(stream) = &*value else {
            return None;
        };
        let mut dict = stream.dict.clone();
        for key in [
            b"Filter".as_slice(),
            b"DecodeParms",
            b"Length",
            b"Resources",
        ] {
            dict.remove(key);
        }
        let stream = Stream::new(
            dict,
            StreamData::Decoded(b"/Tx BMC q /Fm0 Do Q EMC".to_vec()),
        );
        store.set(id, Object::Stream(Box::new(stream))).ok()
    })
}

/// The form whose `Amount` appearance draws text in a Type 3 font without resources of its own
/// (its `/Subtype` indirect when `indirect`), whose glyph uses `/F9`.
fn type3_appearance(pdf: &[u8], indirect: bool) -> Option<Vec<u8>> {
    amount_appearance(
        pdf,
        b"/Tx BMC q BT /T3 12 Tf 0 g 2 9 Td (a) Tj ET Q EMC",
        |store| {
            let glyph = Stream::new(
                Dict::new(),
                StreamData::Decoded(b"500 0 d0 BT /F9 9 Tf (a) Tj ET".to_vec()),
            );
            let glyph = store.add(Object::Stream(Box::new(glyph))).ok()?;
            let mut procs = Dict::new();
            procs.insert("a", Object::Ref(glyph));
            let mut font = Dict::new();
            font.insert("Type", Object::name("Font"));
            font.insert("Subtype", subtype(store, "Type3", indirect)?);
            font.insert(
                "FontBBox",
                Object::Array([0, 0, 500, 700].map(Object::Int).to_vec()),
            );
            font.insert(
                "FontMatrix",
                Object::Array(
                    [0.001, 0.0, 0.0, 0.001, 0.0, 0.0]
                        .map(Object::Real)
                        .to_vec(),
                ),
            );
            font.insert("CharProcs", Object::Dict(procs));
            font.insert("FirstChar", Object::Int(97));
            font.insert("LastChar", Object::Int(97));
            font.insert("Widths", Object::Array(vec![Object::Int(500)]));
            let mut differences = Dict::new();
            differences.insert(
                "Differences",
                Object::Array(vec![Object::Int(97), Object::name("a")]),
            );
            font.insert("Encoding", Object::Dict(differences));
            let font = store.add(Object::Dict(font)).ok()?;
            let mut fonts = Dict::new();
            fonts.insert("T3", Object::Ref(font));
            let mut resources = Dict::new();
            resources.insert("Font", Object::Dict(fonts));
            Some(resources)
        },
    )
}

/// A form XObject (a transparency group, §11.6.6) whose content draws text with `/F9`, a name
/// no resources define, without resources of its own.
fn group_using_f9(store: &mut Store) -> Option<ObjectId> {
    let mut group = Dict::new();
    group.insert("Type", Object::name("XObject"));
    group.insert("Subtype", Object::name("Form"));
    group.insert(
        "BBox",
        Object::Array([0, 0, 200, 30].map(Object::Int).to_vec()),
    );
    let mut transparency = Dict::new();
    transparency.insert("S", Object::name("Transparency"));
    transparency.insert("CS", Object::name("DeviceGray"));
    group.insert("Group", Object::Dict(transparency));
    let group = Stream::new(
        group,
        StreamData::Decoded(b"BT /F9 9 Tf 1 g 1 6 Td (EUR) Tj ET".to_vec()),
    );
    store.add(Object::Stream(Box::new(group))).ok()
}

/// The form whose `Amount` appearance sets a graphics state (§8.4.5) whose soft mask's
/// transparency group (`/SMask << /S /Luminosity /G … >>`, §11.6.5.2) draws text with `/F9`, a
/// name no resources define (M4 QA round 3, findings 6 and 21, variant
/// R1y-extgstate-smask-group).
pub fn form_ap_extgstate_smask_input(pdf: &[u8]) -> Option<Vec<u8>> {
    amount_appearance(
        pdf,
        b"/Tx BMC q /GS0 gs 0 g 0 0 200 30 re f Q EMC",
        |store| {
            let group = group_using_f9(store)?;
            let mut mask = Dict::new();
            mask.insert("Type", Object::name("Mask"));
            mask.insert("S", Object::name("Luminosity"));
            mask.insert("G", Object::Ref(group));
            let mut state = Dict::new();
            state.insert("Type", Object::name("ExtGState"));
            state.insert("SMask", Object::Dict(mask));
            let mut states = Dict::new();
            states.insert("GS0", Object::Dict(state));
            let mut resources = Dict::new();
            resources.insert("ExtGState", Object::Dict(states));
            Some(resources)
        },
    )
}

/// The form whose `Amount` appearance sets a graphics state whose `/Font` entry (§8.4.5, Table
/// 57: `[font size]`) is a Type 3 font without resources of its own, whose glyph procedure uses
/// `/F9`, a name no resources define (M4 QA round 3, variant R1y-extgstate-font-type3).
pub fn form_ap_extgstate_font_input(pdf: &[u8]) -> Option<Vec<u8>> {
    amount_appearance(
        pdf,
        b"/Tx BMC q /GS0 gs BT 0 g 2 9 Td (a) Tj ET Q EMC",
        |store| {
            let glyph = Stream::new(
                Dict::new(),
                StreamData::Decoded(b"500 0 d0 BT /F9 9 Tf (a) Tj ET".to_vec()),
            );
            let glyph = store.add(Object::Stream(Box::new(glyph))).ok()?;
            let mut procs = Dict::new();
            procs.insert("a", Object::Ref(glyph));
            let mut font = Dict::new();
            font.insert("Type", Object::name("Font"));
            font.insert("Subtype", Object::name("Type3"));
            font.insert(
                "FontBBox",
                Object::Array([0, 0, 500, 700].map(Object::Int).to_vec()),
            );
            font.insert(
                "FontMatrix",
                Object::Array(
                    [0.001, 0.0, 0.0, 0.001, 0.0, 0.0]
                        .map(Object::Real)
                        .to_vec(),
                ),
            );
            font.insert("CharProcs", Object::Dict(procs));
            font.insert("FirstChar", Object::Int(97));
            font.insert("LastChar", Object::Int(97));
            font.insert("Widths", Object::Array(vec![Object::Int(500)]));
            let font = store.add(Object::Dict(font)).ok()?;
            let mut state = Dict::new();
            state.insert("Type", Object::name("ExtGState"));
            state.insert(
                "Font",
                Object::Array(vec![Object::Ref(font), Object::Int(12)]),
            );
            let mut states = Dict::new();
            states.insert("GS0", Object::Dict(state));
            let mut resources = Dict::new();
            resources.insert("ExtGState", Object::Dict(states));
            Some(resources)
        },
    )
}

/// `form_signed_dup_checkbox_relisted` (M4 QA round 3, finding 5, variant
/// F3-h-signed-dup-AS-yes-first-relist-off): on the form whose signed check box `Agree` writes
/// `/AS` twice (`/Yes` first, the signed `/Off` last), `Agree` re-listed as Folioxide's parser
/// reads it (`/AS /Off`, clean bytes): a first-wins reader (pyHanko) sees the box unchecked by
/// the update.
pub fn form_agree_relisted(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let (id, _) = field_by_name(store, AGREE)?;
        let value = store.resolve(id).ok()?;
        store.set(id, Object::clone(&value)).ok()
    })
}

/// [`form_ap_page_level_form_input`] with `Amount`'s appearance given `resources` of its own
/// that lack an `/XObject` category, so PDFium looks `/Fm0` up in the page's resources (M4 QA
/// round 5, finding 29).
fn page_level_form_with_own_resources(pdf: &[u8], resources: Dict) -> Option<Vec<u8>> {
    let prepared = form_ap_page_level_form_input(pdf)?;
    with_incremental(&prepared, |store| {
        let id = ObjectId::new(ids::AMOUNT_AP, 0);
        let value = store.resolve(id).ok()?;
        let Object::Stream(stream) = &*value else {
            return None;
        };
        let mut dict = stream.dict.clone();
        for key in [b"Filter".as_slice(), b"DecodeParms", b"Length"] {
            dict.remove(key);
        }
        dict.insert("Resources", Object::Dict(resources));
        let data = store.stream_data(stream).ok()?.data;
        let stream = Stream::new(dict, StreamData::Decoded(data));
        store.set(id, Object::Stream(Box::new(stream))).ok()
    })
}

/// [`form_ap_page_level_form_input`] with an empty `/Resources` on `Amount`'s appearance
/// (variant R1v-own-resources-empty-page-form).
pub fn form_ap_page_level_form_ownres_empty_input(pdf: &[u8]) -> Option<Vec<u8>> {
    page_level_form_with_own_resources(pdf, Dict::new())
}

/// [`form_ap_page_level_form_input`] with `/Resources << /Font << /Helv … >> >>` on `Amount`'s
/// appearance: no `/XObject` (variant R1v-own-resources-font-only-page-form).
pub fn form_ap_page_level_form_font_only_input(pdf: &[u8]) -> Option<Vec<u8>> {
    let mut fonts = Dict::new();
    fonts.insert("Helv", Object::Ref(ObjectId::new(ids::FONT, 0)));
    let mut resources = Dict::new();
    resources.insert("Font", Object::Dict(fonts));
    page_level_form_with_own_resources(pdf, resources)
}

/// The form whose page-tree root holds the page's resources and `/Fm0`, a form XObject whose
/// content uses `/F9`, while the page has no `/Resources` and its `/Parent` is a node outside
/// the tree; `Amount`'s appearance, without resources, draws `/Fm0` (M4 QA round 5, finding 29,
/// variant R1v-bare-ap-parent-chain-differs-from-kids-walk: poppler inherits the root's
/// resources along `/Kids`, a `/Parent` climb never reaches them).
pub fn form_ap_page_level_form_parent_mismatch_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let form = form_using_f9(store, false)?;
        let page = ObjectId::new(ids::PAGE, 0);
        let mut page_dict = store.resolve(page).ok()?.as_dict()?.clone();
        let root = page_dict.get_ref(b"Parent")?;
        let mut resources = page_dict.get_dict(b"Resources")?.clone();
        let mut forms = Dict::new();
        forms.insert("Fm0", Object::Ref(form));
        resources.insert("XObject", Object::Dict(forms));
        let mut root_dict = store.resolve(root).ok()?.as_dict()?.clone();
        root_dict.insert("Resources", Object::Dict(resources));
        store.set(root, Object::Dict(root_dict)).ok()?;
        let mut detached = Dict::new();
        detached.insert("Type", Object::name("Pages"));
        detached.insert("Kids", Object::Array(vec![Object::Ref(page)]));
        detached.insert("Count", Object::Int(1));
        let detached = store.add(Object::Dict(detached)).ok()?;
        page_dict.remove(b"Resources".as_slice());
        page_dict.insert("Parent", Object::Ref(detached));
        store.set(page, Object::Dict(page_dict)).ok()?;
        let id = ObjectId::new(ids::AMOUNT_AP, 0);
        let value = store.resolve(id).ok()?;
        let Object::Stream(stream) = &*value else {
            return None;
        };
        let mut dict = stream.dict.clone();
        for key in [
            b"Filter".as_slice(),
            b"DecodeParms",
            b"Length",
            b"Resources",
        ] {
            dict.remove(key);
        }
        let stream = Stream::new(
            dict,
            StreamData::Decoded(b"/Tx BMC q /Fm0 Do Q EMC".to_vec()),
        );
        store.set(id, Object::Stream(Box::new(stream))).ok()
    })
}

/// The form whose `Amount` `/AP` is an indirect dictionary, used once (manager ruling R-19:
/// the control).
pub fn form_ap_dict_indirect_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| indirect_amount_ap(store).map(|_| ()))
}

/// `Amount`'s `/AP` made an indirect dictionary; its object.
fn indirect_amount_ap(store: &mut Store) -> Option<ObjectId> {
    let (id, _) = field_by_name(store, AMOUNT)?;
    let mut field = store.resolve(id).ok()?.as_dict()?.clone();
    let ap = store.deref(field.get(b"AP")?).ok()?.as_dict()?.clone();
    let ap = store.add(Object::Dict(ap)).ok()?;
    field.insert("AP", Object::Ref(ap));
    store.set(id, Object::Dict(field)).ok()?;
    Some(ap)
}

/// [`form_ap_dict_indirect_input`] with a second text field `Twin`, a merged widget on the page
/// and in `/Fields`, whose `/AP` is the same dictionary (M4 QA round 5, finding 7, variants
/// F4-j-two-widgets-share-ap-dict-*): pyHanko then refuses every later revision.
pub fn form_ap_dict_shared_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let ap = indirect_amount_ap(store)?;
        let (amount, _) = field_by_name(store, AMOUNT)?;
        let mut twin = store.resolve(amount).ok()?.as_dict()?.clone();
        twin.insert("T", Object::literal_string("Twin"));
        twin.insert("AP", Object::Ref(ap));
        twin.insert(
            "Rect",
            Object::Array([300, 600, 500, 630].map(Object::Int).to_vec()),
        );
        let twin = store.add(Object::Dict(twin)).ok()?;
        let page = ObjectId::new(ids::PAGE, 0);
        super::append_to_array_entry(store, page, b"Annots", twin)?;
        super::append_to_array_entry(store, ObjectId::new(ids::ACROFORM, 0), b"Fields", twin)
    })
}

/// The non-terminal text-field parents of [`form_ap_dict_shared_parents_input`], each with its
/// named terminal kid and the kid's `/Rect`.
pub const AP_DICT_PARENTS: [(&str, &str, [i64; 4]); 2] = [
    ("P", "C", [300, 540, 500, 570]),
    ("Q", "D", [300, 480, 500, 510]),
];

/// The form with two non-terminal text fields [`AP_DICT_PARENTS`] whose `/AP` is one indirect
/// appearance dictionary (M4 closing round, finding 10; the expert's `nt-shared-*` files): each
/// parent has a named terminal kid (a text field merged with its widget, with a private direct
/// `/AP`), and the parents' dictionary is never drawn. pyHanko's `_list_fields` yields every
/// named field node and `GenericFieldModificationRule` checks the old `/AP` of each, so it
/// refuses every later revision then. Prepared before signing.
pub fn form_ap_dict_shared_parents_input(pdf: &[u8]) -> Option<Vec<u8>> {
    ap_dict_parents(pdf, true)
}

/// The control of [`form_ap_dict_shared_parents_input`]: each parent has an indirect `/AP`
/// dictionary of its own (each used once).
pub fn form_ap_dict_private_parents_input(pdf: &[u8]) -> Option<Vec<u8>> {
    ap_dict_parents(pdf, false)
}

/// The parents of [`AP_DICT_PARENTS`], their `/AP` one dictionary (`shared`) or two.
fn ap_dict_parents(pdf: &[u8], shared: bool) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let (amount, _) = field_by_name(store, AMOUNT)?;
        let template = store.resolve(amount).ok()?.as_dict()?.clone();
        let normal = store
            .deref(
                store
                    .deref(template.get(b"AP")?)
                    .ok()?
                    .as_dict()?
                    .get(b"N")?,
            )
            .ok()?
            .as_stream()?
            .clone();
        let mut parent_ap = None;
        let page = ObjectId::new(ids::PAGE, 0);
        for (parent_name, kid_name, rect) in AP_DICT_PARENTS {
            let ap = match parent_ap {
                Some(ap) if shared => ap,
                _ => {
                    let stream = store.add(Object::Stream(Box::new(normal.clone()))).ok()?;
                    let mut dict = Dict::new();
                    dict.insert("N", Object::Ref(stream));
                    store.add(Object::Dict(dict)).ok()?
                }
            };
            parent_ap = Some(ap);
            let mut parent = Dict::new();
            parent.insert("FT", Object::name("Tx"));
            parent.insert("T", Object::literal_string(parent_name));
            parent.insert("AP", Object::Ref(ap));
            let parent_id = store.add(Object::Dict(parent.clone())).ok()?;
            let kid_stream = store.add(Object::Stream(Box::new(normal.clone()))).ok()?;
            let mut kid_ap = Dict::new();
            kid_ap.insert("N", Object::Ref(kid_stream));
            let mut kid = template.clone();
            for key in [b"FT".as_slice(), b"V", b"StructParent"] {
                kid.remove(key);
            }
            kid.insert("T", Object::literal_string(kid_name));
            kid.insert("Parent", Object::Ref(parent_id));
            kid.insert("Rect", Object::Array(rect.map(Object::Int).to_vec()));
            kid.insert("AP", Object::Dict(kid_ap));
            let kid_id = store.add(Object::Dict(kid)).ok()?;
            parent.insert("Kids", Object::Array(vec![Object::Ref(kid_id)]));
            store.set(parent_id, Object::Dict(parent)).ok()?;
            super::append_to_array_entry(store, page, b"Annots", kid_id)?;
            super::append_to_array_entry(
                store,
                ObjectId::new(ids::ACROFORM, 0),
                b"Fields",
                parent_id,
            )?;
        }
        Some(())
    })
}

/// The second empty visible signature field of [`form_sig_ap_dict_shared_input`] and
/// [`form_sig_ap_dict_private_input`], below [`forms::VISIBLE`].
pub const SECOND_SIG_FIELD: &str = "SigB";

/// The `/Rect` of [`SECOND_SIG_FIELD`].
pub const SECOND_SIG_FIELD_RECT: [i64; 4] = [300, 20, 500, 80];

/// The form whose empty visible signature field [`forms::VISIBLE`] has an indirect `/AP`
/// dictionary `<< /N stream >>` (a light grey form XObject over its `/Rect`) that a second empty
/// visible signature field [`SECOND_SIG_FIELD`] uses too (M4 final fix round 2, finding 1,
/// variants R3-k-two-sigfields-shared-*): pyHanko then refuses a later revision that signs
/// either field (its `SigFieldModificationRule` checks the old `/AP` dictionary of a field that
/// becomes signed). Prepared before signing.
pub fn form_sig_ap_dict_shared_input(pdf: &[u8]) -> Option<Vec<u8>> {
    sig_ap_dicts(pdf, true)
}

/// The control of [`form_sig_ap_dict_shared_input`]: each of the two fields has an indirect
/// `/AP` dictionary of its own (each used once).
pub fn form_sig_ap_dict_private_input(pdf: &[u8]) -> Option<Vec<u8>> {
    sig_ap_dicts(pdf, false)
}

/// [`forms::VISIBLE`] with an indirect `/AP` dictionary, and the new field
/// [`SECOND_SIG_FIELD`] with the same one (`shared`) or a copy.
fn sig_ap_dicts(pdf: &[u8], shared: bool) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let [x1, y1, x2, y2] = forms::VISIBLE_RECT;
        let mut form = Dict::new();
        form.insert("Type", Object::name("XObject"));
        form.insert("Subtype", Object::name("Form"));
        form.insert(
            "BBox",
            Object::Array([0, 0, x2 - x1, y2 - y1].map(Object::Int).to_vec()),
        );
        let content = format!("0.9 g 0 0 {} {} re f", x2 - x1, y2 - y1).into_bytes();
        let stream = Stream::new(form, StreamData::Decoded(content));
        let normal = store.add(Object::Stream(Box::new(stream))).ok()?;
        let mut ap = Dict::new();
        ap.insert("N", Object::Ref(normal));
        let first = store.add(Object::Dict(ap.clone())).ok()?;
        let second = if shared {
            first
        } else {
            store.add(Object::Dict(ap)).ok()?
        };
        let (visible, _) = field_by_name(store, forms::VISIBLE)?;
        let mut dict = store.resolve(visible).ok()?.as_dict()?.clone();
        dict.insert("AP", Object::Ref(first));
        store.set(visible, Object::Dict(dict.clone())).ok()?;
        dict.insert("T", Object::literal_string(SECOND_SIG_FIELD));
        dict.insert(
            "Rect",
            Object::Array(SECOND_SIG_FIELD_RECT.map(Object::Int).to_vec()),
        );
        dict.insert("AP", Object::Ref(second));
        // The copy is no tagged widget (only the original is in the structure tree).
        dict.remove(b"StructParent".as_slice());
        let twin = store.add(Object::Dict(dict)).ok()?;
        let page = ObjectId::new(ids::PAGE, 0);
        super::append_to_array_entry(store, page, b"Annots", twin)?;
        super::append_to_array_entry(store, ObjectId::new(ids::ACROFORM, 0), b"Fields", twin)
    })
}

/// `form_dr_adds_name_missing_from_ap_resources`: on [`form_ap_missing_font_input`], the
/// AcroForm's `/DR /Font` gains `/F9` (a bold font), the name the signed appearance stream
/// uses but its own resources lack.
pub fn form_dr_adds_name_missing_from_ap_resources(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let mut font = Dict::new();
        font.insert("Type", Object::name("Font"));
        font.insert("Subtype", Object::name("Type1"));
        font.insert("BaseFont", Object::name("Helvetica-Bold"));
        let font = store.add(Object::Dict(font)).ok()?;
        let acroform = ObjectId::new(ids::ACROFORM, 0);
        let mut dict = store.resolve(acroform).ok()?.as_dict()?.clone();
        let mut dr = dict.get_dict(b"DR")?.clone();
        let mut fonts = dr.get_dict(b"Font")?.clone();
        fonts.insert("F9", Object::Ref(font));
        dr.insert("Font", Object::Dict(fonts));
        dict.insert("DR", Object::Dict(dr));
        store.set(acroform, Object::Dict(dict)).ok()
    })
}

/// The form with a text field `Split` whose widget is a separate kid (the field has `/Kids
/// [widget]`, the widget `/Parent`): the `Amount` widget becomes `Split`'s kid.
pub fn form_split_field_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let widget = ObjectId::new(ids::AMOUNT, 0);
        let mut kid = store.resolve(widget).ok()?.as_dict()?.clone();
        let mut field = Dict::new();
        field.insert("FT", Object::name("Tx"));
        field.insert("T", Object::literal_string("Split"));
        field.insert("V", Object::literal_string("100 EUR"));
        field.insert("DA", Object::literal_string("/Helv 12 Tf 0 g"));
        field.insert("Kids", Object::Array(vec![Object::Ref(widget)]));
        let field = store.add(Object::Dict(field)).ok()?;
        for key in [b"FT".as_slice(), b"T", b"V", b"DA"] {
            kid.remove(key);
        }
        kid.insert("Parent", Object::Ref(field));
        store.set(widget, Object::Dict(kid)).ok()?;
        let acroform = ObjectId::new(ids::ACROFORM, 0);
        let mut dict = store.resolve(acroform).ok()?.as_dict()?.clone();
        let fields: Vec<Object> = dict
            .get_array(b"Fields")?
            .iter()
            .map(|f| {
                if f.as_ref() == Some(widget) {
                    Object::Ref(field)
                } else {
                    f.clone()
                }
            })
            .collect();
        dict.insert("Fields", Object::Array(fields));
        store.set(acroform, Object::Dict(dict)).ok()
    })
}

// =================================================================================================
// Controls: what form fillers write (FormFilling for Folioxide and pyHanko).
// =================================================================================================

/// `form_fill_text_value_and_ap`: `Amount` filled with "900 EUR" and a new appearance stream.
pub fn form_fill_text_value_and_ap(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::fill(pdf, &Fill::text(AMOUNT, "900 EUR"))
}

/// `form_fill_text_value_only`: `Amount`'s `/V` alone ("900 EUR"; the signed appearance stays).
pub fn form_fill_text_value_only(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::fill(
        pdf,
        &Fill::text(AMOUNT, "900 EUR").with_appearance(FillAppearance::ValueOnly),
    )
}

/// `form_fill_inplace_ap`: `Amount` filled, its signed appearance stream rewritten in place
/// (pyHanko's `_allow_in_place_appearance_update`).
pub fn form_fill_inplace_ap(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::fill(
        pdf,
        &Fill::text(AMOUNT, "900 EUR").with_appearance(FillAppearance::InPlace),
    )
}

/// `form_fill_checkbox_on`: the check box `Agree` checked (`/V /Yes`, `/AS /Yes`).
pub fn form_fill_checkbox_on(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::fill(pdf, &Fill::state(AGREE, "Yes"))
}

/// `form_fill_radio_value_only`: the radio group `Choice`'s `/V /B` alone (its kid widgets keep
/// their `/AS`).
pub fn form_fill_radio_value_only(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, CHOICE, |_, dict| {
        dict.insert("V", Object::name("B"));
    })
}

/// `form_fill_choice`: the combo box `Country` set to "Italy", with a new appearance stream.
pub fn form_fill_choice(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::fill(pdf, &Fill::text(COUNTRY, "Italy"))
}

/// `form_fill_tagged_objr`: [`form_fill_text_value_and_ap`] on the tagged form, where the
/// structure tree's `/OBJR` refers to the widget (D-24).
pub fn form_fill_tagged_objr(pdf: &[u8]) -> Option<Vec<u8>> {
    form_fill_text_value_and_ap(pdf)
}

/// `form_fill_dr_font_added`: `Amount` filled with an appearance in Helvetica-Bold, which the
/// filler adds to the AcroForm's `/DR` as the new name `/HeBo` (no signed `/DA` names it).
pub fn form_fill_dr_font_added(pdf: &[u8]) -> Option<Vec<u8>> {
    let filled = forms::fill(pdf, &Fill::text(AMOUNT, "900 EUR"))?;
    with_incremental(&filled, |store| {
        let mut font = Dict::new();
        font.insert("Type", Object::name("Font"));
        font.insert("Subtype", Object::name("Type1"));
        font.insert("BaseFont", Object::name("Helvetica-Bold"));
        let font = store.add(Object::Dict(font)).ok()?;
        let acroform = ObjectId::new(ids::ACROFORM, 0);
        let mut dict = store.resolve(acroform).ok()?.as_dict()?.clone();
        let mut dr = dict.get_dict(b"DR")?.clone();
        let mut fonts = dr.get_dict(b"Font")?.clone();
        fonts.insert("HeBo", Object::Ref(font));
        dr.insert("Font", Object::Dict(fonts));
        dict.insert("DR", Object::Dict(dr));
        store.set(acroform, Object::Dict(dict)).ok()
    })
}

// =================================================================================================
// Equal-strict: OTHER for Folioxide and pyHanko.
// =================================================================================================

/// `form_fill_radio_b`: the radio group `Choice` set to `/B`, its kid widgets' `/AS` switched
/// (pyHanko 0.37 allows no change to a kid widget: OTHER).
pub fn form_fill_radio_b(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::fill(pdf, &Fill::state(CHOICE, "B"))
}

/// `form_kid_widget_ap`: on [`form_split_field_input`], `Split` filled with a new appearance
/// on its kid widget (pyHanko: OTHER).
pub fn form_kid_widget_ap(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::fill(pdf, &Fill::text("Split", "900 EUR"))
}

/// `form_widget_rect_moved`: `Amount`'s widget moved over the page heading.
pub fn form_widget_rect_moved(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, AMOUNT, |_, dict| {
        dict.insert("Rect", int_rect([72, 715, 272, 745]));
    })
}

/// `form_mk_added`: `Amount` gains appearance characteristics (`/MK`, a red background).
pub fn form_mk_added(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, AMOUNT, |_, dict| {
        let mut mk = Dict::new();
        mk.insert(
            "BG",
            Object::Array(vec![Object::Int(1), Object::Int(0), Object::Int(0)]),
        );
        dict.insert("MK", Object::Dict(mk));
    })
}

/// `form_dv_set`: `Amount` gains a default value `/DV` (what a reset shows).
pub fn form_dv_set(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, AMOUNT, |_, dict| {
        dict.insert("DV", Object::literal_string("0 EUR"));
    })
}

/// `form_tu_set`: `Amount` gains a tooltip `/TU`.
pub fn form_tu_set(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, AMOUNT, |_, dict| {
        dict.insert("TU", Object::literal_string("Pay this"));
    })
}

/// `form_kid_added`: the radio group `Choice` gains a third kid widget (a new state `/C`) on the
/// page.
pub fn form_kid_added(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let page = ObjectId::new(ids::PAGE, 0);
        let choice = ObjectId::new(ids::CHOICE, 0);
        let mut normal = Dict::new();
        normal.insert("C", Object::Ref(ObjectId::new(ids::CHOICE_A_ON, 0)));
        normal.insert("Off", Object::Ref(ObjectId::new(ids::CHOICE_A_OFF, 0)));
        let mut ap = Dict::new();
        ap.insert("N", Object::Dict(normal));
        let mut kid = Dict::new();
        kid.insert("Type", Object::name("Annot"));
        kid.insert("Subtype", Object::name("Widget"));
        kid.insert("Parent", Object::Ref(choice));
        kid.insert("AS", Object::name("Off"));
        kid.insert("F", Object::Int(4));
        kid.insert("Rect", int_rect([152, 500, 172, 520]));
        kid.insert("P", Object::Ref(page));
        kid.insert("AP", Object::Dict(ap));
        let kid = store.add(Object::Dict(kid)).ok()?;
        let mut dict = store.resolve(choice).ok()?.as_dict()?.clone();
        let mut kids = dict.get_array(b"Kids")?.to_vec();
        kids.push(Object::Ref(kid));
        dict.insert("Kids", Object::Array(kids));
        store.set(choice, Object::Dict(dict)).ok()?;
        forms::append_to_annots(store, page, kid)
    })
}

/// `form_field_renamed`: `Amount`'s partial name `/T` changed to `Total`.
pub fn form_field_renamed(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, AMOUNT, |_, dict| {
        dict.insert("T", Object::literal_string("Total"));
    })
}

/// `form_orphan_widget_as_changed`: on [`form_orphan_widget_input`], the orphan check box
/// widget's `/AS` set to `/Yes`.
pub fn form_orphan_widget_as_changed(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let id = store.object_ids().into_iter().find(|&id| {
            store.resolve(id).ok().is_some_and(|o| {
                o.as_dict()
                    .is_some_and(|d| d.get_str_bytes(b"T") == Some(b"Orphan".as_slice()))
            })
        })?;
        let mut dict = store.resolve(id).ok()?.as_dict()?.clone();
        dict.insert("AS", Object::name("Yes"));
        store.set(id, Object::Dict(dict)).ok()
    })
}

/// `form_inplace_ap_shared_with_page`: on [`form_ap_shared_with_page_input`], `Amount` filled
/// with its appearance stream rewritten in place; the page draws that stream too.
pub fn form_inplace_ap_shared_with_page(pdf: &[u8]) -> Option<Vec<u8>> {
    form_fill_inplace_ap(pdf)
}

// =================================================================================================
// Stricter than pyHanko (M4 brief §0.1: OTHER for Folioxide, FORM_FILLING for pyHanko).
// =================================================================================================

/// `form_widget_unhidden`: on [`form_hidden_widget_input`], `Amount`'s widget revealed (`/F 6`
/// → `/F 4`).
pub fn form_widget_unhidden(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, AMOUNT, |_, dict| {
        dict.insert("F", Object::Int(4));
    })
}

/// `form_widget_hidden`: `Amount`'s widget hidden (`/F 4` → `/F 2`).
pub fn form_widget_hidden(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, AMOUNT, |_, dict| {
        dict.insert("F", Object::Int(2));
    })
}

/// `form_field_da_changed`: `Amount`'s `/DA` restyled to white text.
pub fn form_field_da_changed(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, AMOUNT, |_, dict| {
        dict.insert("DA", Object::literal_string("/Helv 12 Tf 1 g"));
    })
}

/// `form_field_q_changed`: `Amount`'s quadding set to right-aligned (`/Q 2`).
pub fn form_field_q_changed(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, AMOUNT, |_, dict| {
        dict.insert("Q", Object::Int(2));
    })
}

/// `form_field_ff_changed`: `Amount` made a password field (`/Ff` bit 14, §12.7.5.3), which
/// masks the value.
pub fn form_field_ff_changed(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, AMOUNT, |_, dict| {
        dict.insert("Ff", Object::Int(8192));
    })
}

/// `form_ap_changed_without_value`: `Amount` given a new appearance showing "1 EUR" while its
/// `/V` stays "100 EUR" (a shadow Replace).
pub fn form_ap_changed_without_value(pdf: &[u8]) -> Option<Vec<u8>> {
    let filled = forms::fill(pdf, &Fill::text(AMOUNT, "1 EUR"))?;
    // Put the signed value back: only the appearance changed.
    with_incremental(&filled, |store| {
        let (id, _) = field_by_name(store, AMOUNT)?;
        let mut dict = store.resolve(id).ok()?.as_dict()?.clone();
        dict.insert("V", Object::literal_string("100 EUR"));
        store.set(id, Object::Dict(dict)).ok()
    })
}

/// `form_checkbox_ap_replaced`: `Agree` checked, with its `/Yes` appearance replaced by a new
/// stream (filling only selects a signed state).
pub fn form_checkbox_ap_replaced(pdf: &[u8]) -> Option<Vec<u8>> {
    let checked = form_fill_checkbox_on(pdf)?;
    with_incremental(&checked, |store| {
        let (id, _) = field_by_name(store, AGREE)?;
        let mut dict = store.resolve(id).ok()?.as_dict()?.clone();
        let mut form = Dict::new();
        form.insert("Type", Object::name("XObject"));
        form.insert("Subtype", Object::name("Form"));
        form.insert("BBox", int_rect([0, 0, 20, 20]));
        let stream = Stream::new(
            form,
            StreamData::Decoded(b"q 1 0 0 rg 0 0 20 20 re f Q".to_vec()),
        );
        let yes = store.add(Object::Stream(Box::new(stream))).ok()?;
        let mut normal = Dict::new();
        normal.insert("Yes", Object::Ref(yes));
        normal.insert("Off", Object::Ref(ObjectId::new(ids::AGREE_OFF, 0)));
        let mut ap = Dict::new();
        ap.insert("N", Object::Dict(normal));
        dict.insert("AP", Object::Dict(ap));
        store.set(id, Object::Dict(dict)).ok()
    })
}

/// `form_readonly_field_filled`: on [`form_readonly_input`], the ReadOnly `Amount` filled.
pub fn form_readonly_field_filled(pdf: &[u8]) -> Option<Vec<u8>> {
    form_fill_text_value_and_ap(pdf)
}

/// `form_fill_with_xfa`: on [`form_xfa_input`], `Amount` filled (the XFA datasets still say
/// "100 EUR").
pub fn form_fill_with_xfa(pdf: &[u8]) -> Option<Vec<u8>> {
    form_fill_text_value_and_ap(pdf)
}

/// `form_fill_under_own_fieldmdp`: `Amount` (not locked) filled on a document whose signature
/// carries FieldMDP locking `Country`.
pub fn form_fill_under_own_fieldmdp(pdf: &[u8]) -> Option<Vec<u8>> {
    form_fill_text_value_and_ap(pdf)
}

/// `form_as_unknown_state`: `Agree` set to `/V /Maybe` and `/AS /Maybe`, a state its widget does
/// not have, so it draws nothing.
pub fn form_as_unknown_state(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, AGREE, |_, dict| {
        dict.insert("V", Object::name("Maybe"));
        dict.insert("AS", Object::name("Maybe"));
    })
}

/// `form_value_indirect`: `Amount`'s `/V` set to a reference to a new string object.
pub fn form_value_indirect(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, AMOUNT, |store, dict| {
        if let Ok(value) = store.add(Object::literal_string("900 EUR")) {
            dict.insert("V", Object::Ref(value));
        }
    })
}

/// `form_checkbox_as_without_value`: `Agree`'s `/AS` set to `/Yes` while its `/V` stays `/Off`
/// (the check box shows checked; the value says unchecked).
pub fn form_checkbox_as_without_value(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_named(pdf, AGREE, |_, dict| {
        dict.insert("AS", Object::name("Yes"));
    })
}

/// `form_fill_value_removed`: `Amount`'s `/V` removed (a control: FormFilling).
pub fn form_fill_value_removed(pdf: &[u8]) -> Option<Vec<u8>> {
    forms::fill(
        pdf,
        &Fill {
            field: AMOUNT.to_owned(),
            value: FillValue::Remove,
            appearance: FillAppearance::ValueOnly,
        },
    )
}

/// `[x1 y1 x2 y2]` of integers.
fn int_rect(values: [i64; 4]) -> Object {
    Object::Array(values.into_iter().map(Object::Int).collect())
}

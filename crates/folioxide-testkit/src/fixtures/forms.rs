//! Deterministic AcroForm documents, and the incremental updates of form filling and
//! annotating that the M4 modification classifier judges (M4 brief §3.4, §5.1, §5.2).
//!
//! - [`acroform`]: a one-page form with a text field, a check box, a radio group, a combo box
//!   and two empty signature fields (one visible, one invisible); [`acroform_tagged`] is the
//!   same tagged, with a structure tree whose `/OBJR` dictionaries refer to the widgets;
//!   [`acroform_text_fields`] has `n` text fields (the linear-time tests).
//! - [`fill`] and [`fill_all`]: what a form filler appends: new values, the matching appearance
//!   states of buttons, and new (or rewritten) appearance streams of text and choice fields.
//! - [`annotate`]: what a reviewer appends: a new annotation (and its popup) on a page.
//!
//! Everything is built from `folioxide-syntax` alone: the documents with the byte-level
//! [`PdfBuilder`], the updates through `Store` edits and the incremental writer, so the
//! fixtures do not depend on what they test.

use folioxide_syntax::{
    Dict, IncrementalOptions, Object, ObjectId, OpenOptions, Store, Stream, StreamData,
};

use crate::builder::{PdfBuilder, XrefOpts};
use crate::fixtures::id_array;

/// The text field of [`acroform`]: merged with its widget, `/V (100 EUR)`, an `/AP /N` stream
/// and its own `/DA`.
pub const AMOUNT: &str = "Amount";
/// The check box of [`acroform`]: states `/Yes` and `/Off`, `/AS /Off`.
pub const AGREE: &str = "Agree";
/// The radio group of [`acroform`]: two kid widgets with the states `/A` and `/B`.
pub const CHOICE: &str = "Choice";
/// The combo box of [`acroform`], with `/Opt [(France) (Germany) (Italy)]`.
pub const COUNTRY: &str = "Country";
/// The empty visible signature field of [`acroform`], at [`VISIBLE_RECT`].
pub const VISIBLE: &str = "Visible";
/// The empty invisible signature field of [`acroform`].
pub const INVISIBLE: &str = "Invisible";
/// The `/Rect` of the [`VISIBLE`] signature field (M4 brief §3.4).
pub const VISIBLE_RECT: [i64; 4] = [300, 100, 500, 160];

/// The object numbers of [`acroform`]'s objects (fixed: the documents are byte-for-byte
/// deterministic).
pub mod ids {
    /// The catalog.
    pub const CATALOG: u32 = 1;
    /// The page.
    pub const PAGE: u32 = 3;
    /// The page's content stream.
    pub const CONTENT: u32 = 4;
    /// The Helvetica font, `/DR /Font /Helv` and the page's `/F1`.
    pub const FONT: u32 = 5;
    /// The AcroForm.
    pub const ACROFORM: u32 = 6;
    /// The text field `Amount` (merged with its widget).
    pub const AMOUNT: u32 = 7;
    /// The `Amount` widget's `/AP /N` stream.
    pub const AMOUNT_AP: u32 = 8;
    /// The check box `Agree` (merged with its widget).
    pub const AGREE: u32 = 9;
    /// The `Agree` widget's `/Yes` appearance.
    pub const AGREE_YES: u32 = 10;
    /// The `Agree` widget's `/Off` appearance.
    pub const AGREE_OFF: u32 = 11;
    /// The radio group `Choice` (a field with two kid widgets).
    pub const CHOICE: u32 = 12;
    /// The `Choice` kid widget with state `/A`.
    pub const CHOICE_A: u32 = 13;
    /// The `Choice` kid widget with state `/B`.
    pub const CHOICE_B: u32 = 14;
    /// The `/A` appearance of kid A.
    pub const CHOICE_A_ON: u32 = 15;
    /// The `/B` appearance of kid B.
    pub const CHOICE_B_ON: u32 = 16;
    /// The `/Off` appearance of kid A.
    pub const CHOICE_A_OFF: u32 = 17;
    /// The `/Off` appearance of kid B.
    pub const CHOICE_B_OFF: u32 = 18;
    /// The combo box `Country` (merged with its widget).
    pub const COUNTRY: u32 = 19;
    /// The `Country` widget's `/AP /N` stream.
    pub const COUNTRY_AP: u32 = 20;
    /// The empty visible signature field `Visible`.
    pub const VISIBLE: u32 = 21;
    /// The empty invisible signature field `Invisible`.
    pub const INVISIBLE: u32 = 22;
    /// The structure tree root of [`acroform_tagged`](super::acroform_tagged).
    pub const STRUCT_TREE_ROOT: u32 = 23;
}

/// The widgets of [`acroform`] in page `/Annots` order, with the structure element number that
/// refers to each in [`acroform_tagged`].
const WIDGETS: [u32; 7] = [
    ids::AMOUNT,
    ids::AGREE,
    ids::CHOICE_A,
    ids::CHOICE_B,
    ids::COUNTRY,
    ids::VISIBLE,
    ids::INVISIBLE,
];

/// The appearance of a checked check box: a cross (§12.7.5.2.3).
const CROSS: &[u8] = b"q 0 G 2 w 3 3 m 17 17 l S 3 17 m 17 3 l S Q";
/// The appearance of an empty check box or radio button: a frame.
const FRAME: &[u8] = b"q 0 G 1 w 0.5 0.5 19 19 re S Q";
/// The appearance of a selected radio button: a frame and a dot.
const DOT: &[u8] = b"q 0 G 1 w 0.5 0.5 19 19 re S 0 g 6 6 8 8 re f Q";

/// `acroform`: the form document of M4 brief §3.4 (see the module documentation and [`ids`]):
/// a text field `Amount` (`/V (100 EUR)`, an appearance stream that shows it, its own `/DA`), a
/// check box `Agree` (`/AP /N << /Yes /Off >>`, `/AS /Off`), a radio group `Choice` (two kid
/// widgets with the states `/A` and `/B`), a combo box `Country` (`/Opt`, `/V (Germany)`), an
/// empty visible signature field `Visible` at [`VISIBLE_RECT`] and an empty invisible one
/// `Invisible`, with the AcroForm's `/DR /Font /Helv` and `/DA`.
///
/// ```
/// use folioxide_syntax::{OpenOptions, Store};
/// use folioxide_testkit::fixtures::forms;
///
/// let store = Store::open_bytes(forms::acroform(), &OpenOptions::default())?;
/// assert!(!store.structure_repaired());
/// # Ok::<(), folioxide_syntax::Error>(())
/// ```
pub fn acroform() -> Vec<u8> {
    build(false)
}

/// `acroform_tagged`: [`acroform`] as a tagged PDF (§14.7): `/MarkInfo << /Marked true >>`, a
/// `/StructTreeRoot` whose `/Document` element has one `/Form` element per widget with an
/// `/OBJR` dictionary (`/Obj` the widget, `/Pg` the page) as its `/K`, and a `/ParentTree` that
/// maps each widget's `/StructParent` to its element (the structure pyHanko's
/// `_find_in_structure_tree` accepts, M4 brief D-24).
pub fn acroform_tagged() -> Vec<u8> {
    build(true)
}

/// A text-field appearance stream (§12.7.4.3) showing `text` in a box of `width` × `height`.
fn text_appearance(text: &str, height: i64) -> Vec<u8> {
    let baseline = (height - 12) / 2 + 2;
    format!(
        "/Tx BMC q BT /Helv 12 Tf 0 g 2 {baseline} Td ({}) Tj ET Q EMC",
        escape(text)
    )
    .into_bytes()
}

/// `text` as the content of a literal string: `\`, `(` and `)` escaped (§7.3.4.2).
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '\\' | '(' | ')') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The dictionary text of a form XObject appearance of `width` × `height`, with the Helvetica
/// font `font` as `/Helv` when given.
fn form_xobject(width: i64, height: i64, font: Option<u32>) -> String {
    let resources = font
        .map(|f| format!(" /Resources << /Font << /Helv {f} 0 R >> >>"))
        .unwrap_or_default();
    format!("<< /Type /XObject /Subtype /Form /BBox [0 0 {width} {height}]{resources} >>")
}

/// Builds [`acroform`] (`tagged`: [`acroform_tagged`]).
fn build(tagged: bool) -> Vec<u8> {
    let name = if tagged {
        "acroform-tagged"
    } else {
        "acroform"
    };
    let struct_parent = |i: usize| {
        if tagged {
            format!(" /StructParent {i}")
        } else {
            String::new()
        }
    };
    let mut b = PdfBuilder::new();
    b.header("1.7");
    let tagging = if tagged {
        format!(
            " /StructTreeRoot {} 0 R /MarkInfo << /Marked true >>",
            ids::STRUCT_TREE_ROOT
        )
    } else {
        String::new()
    };
    b.obj(
        ids::CATALOG,
        0,
        format!(
            "<< /Type /Catalog /Pages 2 0 R /AcroForm {} 0 R{tagging} >>",
            ids::ACROFORM
        ),
    );
    b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    let annots: Vec<String> = WIDGETS.iter().map(|w| format!("{w} 0 R")).collect();
    b.obj(
        ids::PAGE,
        0,
        format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {} 0 R \
             /Resources << /Font << /F1 {} 0 R >> >> /Annots [{}] >>",
            ids::CONTENT,
            ids::FONT,
            annots.join(" ")
        ),
    );
    b.stream_obj(
        ids::CONTENT,
        0,
        "",
        b"BT /F1 18 Tf 72 720 Td (Folioxide form) Tj ET \
          BT /F1 10 Tf 72 635 Td (Amount) Tj 0 -50 Td (I agree) Tj 0 -50 Td (Choice A / B) Tj \
          0 -60 Td (Country) Tj ET",
        None,
    );
    b.obj(
        ids::FONT,
        0,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
    );
    b.obj(
        ids::ACROFORM,
        0,
        format!(
            "<< /Fields [{} 0 R {} 0 R {} 0 R {} 0 R {} 0 R {} 0 R] /DR << /Font << /Helv {} 0 R \
             >> >> /DA (/Helv 0 Tf 0 g) >>",
            ids::AMOUNT,
            ids::AGREE,
            ids::CHOICE,
            ids::COUNTRY,
            ids::VISIBLE,
            ids::INVISIBLE,
            ids::FONT
        ),
    );
    // The text field and its appearance.
    b.obj(
        ids::AMOUNT,
        0,
        format!(
            "<< /Type /Annot /Subtype /Widget /FT /Tx /T (Amount) /V (100 EUR) \
             /DA (/Helv 12 Tf 0 g) /F 4 /Rect [72 600 272 630] /P 3 0 R /AP << /N {} 0 R >>{} >>",
            ids::AMOUNT_AP,
            struct_parent(0)
        ),
    );
    b.stream_obj(
        ids::AMOUNT_AP,
        0,
        form_xobject(200, 30, Some(ids::FONT)),
        &text_appearance("100 EUR", 30),
        None,
    );
    // The check box.
    b.obj(
        ids::AGREE,
        0,
        format!(
            "<< /Type /Annot /Subtype /Widget /FT /Btn /T (Agree) /V /Off /AS /Off /F 4 \
             /Rect [72 550 92 570] /P 3 0 R /AP << /N << /Yes {} 0 R /Off {} 0 R >> >>{} >>",
            ids::AGREE_YES,
            ids::AGREE_OFF,
            struct_parent(1)
        ),
    );
    b.stream_obj(ids::AGREE_YES, 0, form_xobject(20, 20, None), CROSS, None);
    b.stream_obj(ids::AGREE_OFF, 0, form_xobject(20, 20, None), FRAME, None);
    // The radio group: Radio (bit 16) | NoToggleToOff (bit 15), §12.7.5.2.4.
    b.obj(
        ids::CHOICE,
        0,
        format!(
            "<< /FT /Btn /Ff 49152 /T (Choice) /V /Off /Kids [{} 0 R {} 0 R] >>",
            ids::CHOICE_A,
            ids::CHOICE_B
        ),
    );
    for (i, (kid, state, on, off, x)) in [
        (ids::CHOICE_A, "A", ids::CHOICE_A_ON, ids::CHOICE_A_OFF, 72),
        (ids::CHOICE_B, "B", ids::CHOICE_B_ON, ids::CHOICE_B_OFF, 112),
    ]
    .into_iter()
    .enumerate()
    {
        b.obj(
            kid,
            0,
            format!(
                "<< /Type /Annot /Subtype /Widget /Parent {} 0 R /AS /Off /F 4 \
                 /Rect [{x} 500 {} 520] /P 3 0 R /AP << /N << /{state} {on} 0 R /Off {off} 0 R \
                 >> >>{} >>",
                ids::CHOICE,
                x + 20,
                struct_parent(2 + i)
            ),
        );
    }
    b.stream_obj(ids::CHOICE_A_ON, 0, form_xobject(20, 20, None), DOT, None);
    b.stream_obj(ids::CHOICE_B_ON, 0, form_xobject(20, 20, None), DOT, None);
    b.stream_obj(
        ids::CHOICE_A_OFF,
        0,
        form_xobject(20, 20, None),
        FRAME,
        None,
    );
    b.stream_obj(
        ids::CHOICE_B_OFF,
        0,
        form_xobject(20, 20, None),
        FRAME,
        None,
    );
    // The combo box (Combo, bit 18).
    b.obj(
        ids::COUNTRY,
        0,
        format!(
            "<< /Type /Annot /Subtype /Widget /FT /Ch /Ff 131072 /T (Country) /V (Germany) \
             /Opt [(France) (Germany) (Italy)] /DA (/Helv 10 Tf 0 g) /F 4 \
             /Rect [72 440 272 460] /P 3 0 R /AP << /N {} 0 R >>{} >>",
            ids::COUNTRY_AP,
            struct_parent(4)
        ),
    );
    b.stream_obj(
        ids::COUNTRY_AP,
        0,
        form_xobject(200, 20, Some(ids::FONT)),
        &text_appearance("Germany", 20),
        None,
    );
    // The empty signature fields.
    let [x1, y1, x2, y2] = VISIBLE_RECT;
    b.obj(
        ids::VISIBLE,
        0,
        format!(
            "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Visible) /F 4 \
             /Rect [{x1} {y1} {x2} {y2}] /P 3 0 R{} >>",
            struct_parent(5)
        ),
    );
    b.obj(
        ids::INVISIBLE,
        0,
        format!(
            "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Invisible) /F 4 /Rect [0 0 0 0] \
             /P 3 0 R{} >>",
            struct_parent(6)
        ),
    );
    if tagged {
        // 23 root, 24 /Document, 25.. one /Form element per widget, then the parent tree.
        let root = ids::STRUCT_TREE_ROOT;
        let document = root + 1;
        let first_form = root + 2;
        let parent_tree = first_form + WIDGETS.len() as u32;
        b.obj(
            root,
            0,
            format!(
                "<< /Type /StructTreeRoot /K [{document} 0 R] /ParentTree {parent_tree} 0 R \
                 /ParentTreeNextKey {} >>",
                WIDGETS.len()
            ),
        );
        let forms: Vec<String> = (0..WIDGETS.len())
            .map(|i| format!("{} 0 R", first_form + i as u32))
            .collect();
        b.obj(
            document,
            0,
            format!(
                "<< /Type /StructElem /S /Document /P {root} 0 R /K [{}] >>",
                forms.join(" ")
            ),
        );
        let mut nums = Vec::new();
        for (i, widget) in WIDGETS.iter().enumerate() {
            let element = first_form + i as u32;
            b.obj(
                element,
                0,
                format!(
                    "<< /Type /StructElem /S /Form /P {document} 0 R /Pg 3 0 R \
                     /K << /Type /OBJR /Obj {widget} 0 R /Pg 3 0 R >> >>"
                ),
            );
            nums.push(format!("{i} {element} 0 R"));
        }
        b.obj(parent_tree, 0, format!("<< /Nums [{}] >>", nums.join(" ")));
    }
    b.xref_table(XrefOpts::default());
    let trailer = format!("/Size {} /Root 1 0 R /ID {}", b.size(), id_array(name));
    b.trailer(trailer).startxref(None).eof();
    b.build()
}

/// `acroform_text_fields`: a one-page form with `n` text fields `F0` … `F{n-1}`, each merged with
/// its widget (a small `/Rect` on a grid), with its own appearance stream and `/DA`, all at the
/// root of `/Fields` (an indirect array) and in the page's `/Annots` (an indirect array). For
/// the tests that the classification is linear in the size of the form.
pub fn acroform_text_fields(n: usize) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.7");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R /AcroForm 6 0 R >>");
    b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    b.obj(
        3,
        0,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R \
         /Resources << /Font << /F1 5 0 R >> >> /Annots 8 0 R >>",
    );
    b.stream_obj(
        4,
        0,
        "",
        b"BT /F1 18 Tf 72 760 Td (Many fields) Tj ET",
        None,
    );
    b.obj(
        5,
        0,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
    );
    b.obj(
        6,
        0,
        "<< /Fields 7 0 R /DR << /Font << /Helv 5 0 R >> >> /DA (/Helv 0 Tf 0 g) >>",
    );
    let first = 9u32;
    let refs: Vec<String> = (0..n)
        .map(|i| format!("{} 0 R", first + 2 * i as u32))
        .collect();
    let refs = refs.join(" ");
    b.obj(7, 0, format!("[{refs}]"));
    b.obj(8, 0, format!("[{refs}]"));
    for i in 0..n {
        let field = first + 2 * i as u32;
        let column = (i % 50) as i64;
        let row = ((i / 50) % 70) as i64;
        let (x, y) = (10 + column * 12, 20 + row * 10);
        b.obj(
            field,
            0,
            format!(
                "<< /Type /Annot /Subtype /Widget /FT /Tx /T (F{i}) /V ({i}) /DA (/Helv 6 Tf 0 g) \
                 /F 4 /Rect [{x} {y} {} {}] /P 3 0 R /AP << /N {} 0 R >> >>",
                x + 10,
                y + 8,
                field + 1
            ),
        );
        b.stream_obj(
            field + 1,
            0,
            form_xobject(10, 8, Some(5)),
            format!("/Tx BMC q BT /Helv 6 Tf 0 g 1 1 Td ({i}) Tj ET Q EMC").as_bytes(),
            None,
        );
    }
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array("acroform-text-fields")
    );
    b.trailer(trailer).startxref(None).eof();
    b.build()
}

// =================================================================================================
// Form filling (M4 brief §5.1).
// =================================================================================================

/// The value a [`Fill`] gives a field.
#[derive(Clone, Debug, PartialEq)]
pub enum FillValue {
    /// A text string: a text field or a combo box (`/V (text)`).
    Text(String),
    /// A name: a check box or a radio group (`/V /State`); its widgets' `/AS` follow it.
    Name(String),
    /// An array of text strings: a multiple-selection list box.
    Texts(Vec<String>),
    /// No value: `/V` removed.
    Remove,
}

/// What a [`Fill`] does to the appearance of a text or choice field's widgets (§12.7.4.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FillAppearance {
    /// A new appearance stream showing the value, as `/AP << /N new >>` (a direct dictionary):
    /// what form fillers write. The default.
    #[default]
    NewStream,
    /// The value only; the stored appearance is kept.
    ValueOnly,
    /// The existing `/AP /N` stream object rewritten in place to show the value (pyHanko's
    /// `_allow_in_place_appearance_update`).
    InPlace,
}

/// One field filled by [`fill`]: its fully qualified name, its new value and what happens to its
/// appearance.
#[derive(Clone, Debug, PartialEq)]
pub struct Fill {
    /// The fully qualified field name (§12.7.4.2).
    pub field: String,
    /// The new value.
    pub value: FillValue,
    /// The appearance of a text or choice field (buttons switch `/AS` instead).
    pub appearance: FillAppearance,
}

impl Fill {
    /// Fills the text or choice field `field` with `text` and a new appearance stream.
    pub fn text(field: &str, text: &str) -> Fill {
        Fill {
            field: field.to_owned(),
            value: FillValue::Text(text.to_owned()),
            appearance: FillAppearance::NewStream,
        }
    }

    /// Sets the check box or radio group `field` to the state `state` (`Off` clears it).
    pub fn state(field: &str, state: &str) -> Fill {
        Fill {
            field: field.to_owned(),
            value: FillValue::Name(state.to_owned()),
            appearance: FillAppearance::ValueOnly,
        }
    }

    /// The same fill with `appearance`.
    #[must_use]
    pub fn with_appearance(mut self, appearance: FillAppearance) -> Fill {
        self.appearance = appearance;
        self
    }
}

/// Appends a revision that fills one field ([`fill_all`]).
pub fn fill(pdf: &[u8], fill: &Fill) -> Option<Vec<u8>> {
    fill_all(pdf, std::slice::from_ref(fill))
}

/// Appends a revision that fills the fields of `fills`, as a form filler does: each field's
/// `/V`; for a check box or radio group each widget's `/AS` (the state when its `/AP /N` has
/// it, else `/Off`); for a text or choice field the appearance of [`Fill::appearance`]. `None`
/// when a field is missing or the update cannot be written.
pub fn fill_all(pdf: &[u8], fills: &[Fill]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        for fill in fills {
            apply_fill(store, fill)?;
        }
        Some(())
    })
}

/// [`fill_all`] for one field, on `store`.
fn apply_fill(store: &mut Store, fill: &Fill) -> Option<()> {
    let (field, field_type) = field_by_name(store, &fill.field)?;
    let mut dict = store.resolve(field).ok()?.as_dict()?.clone();
    match &fill.value {
        FillValue::Text(text) => {
            dict.insert("V", Object::literal_string(text.as_bytes()));
        }
        FillValue::Name(name) => {
            dict.insert("V", Object::name(name.as_str()));
        }
        FillValue::Texts(texts) => {
            dict.insert(
                "V",
                Object::Array(
                    texts
                        .iter()
                        .map(|t| Object::literal_string(t.as_bytes()))
                        .collect(),
                ),
            );
        }
        FillValue::Remove => {
            dict.remove(b"V");
        }
    }
    let kids: Vec<ObjectId> = match dict.get(b"Kids") {
        Some(kids) => store
            .deref(kids)
            .ok()?
            .as_array()?
            .iter()
            .filter_map(Object::as_ref)
            .collect(),
        None => Vec::new(),
    };
    let shown = match &fill.value {
        FillValue::Text(text) => text.clone(),
        FillValue::Texts(texts) => texts.join(", "),
        FillValue::Name(name) => name.clone(),
        FillValue::Remove => String::new(),
    };
    if field_type == b"Btn" {
        let state = match &fill.value {
            FillValue::Name(name) => name.clone(),
            _ => "Off".to_owned(),
        };
        if kids.is_empty() {
            set_state(store, &mut dict, &state)?;
        } else {
            for kid in kids {
                let mut kid_dict = store.resolve(kid).ok()?.as_dict()?.clone();
                if set_state(store, &mut kid_dict, &state)? {
                    store.set(kid, Object::Dict(kid_dict)).ok()?;
                }
            }
        }
    } else if kids.is_empty() {
        set_text_appearance(store, &mut dict, &shown, fill.appearance)?;
    } else {
        for kid in kids {
            let mut kid_dict = store.resolve(kid).ok()?.as_dict()?.clone();
            set_text_appearance(store, &mut kid_dict, &shown, fill.appearance)?;
            store.set(kid, Object::Dict(kid_dict)).ok()?;
        }
    }
    store.set(field, Object::Dict(dict)).ok()
}

/// Sets the widget `widget`'s `/AS` to `state` when its `/AP /N` has that state, else to `/Off`
/// (§12.7.5.2.3); `true` when it changed.
fn set_state(store: &Store, widget: &mut Dict, state: &str) -> Option<bool> {
    let normal = widget
        .get(b"AP")
        .and_then(|ap| store.deref(ap).ok())
        .and_then(|ap| ap.as_dict().and_then(|ap| ap.get(b"N").cloned()))
        .and_then(|n| store.deref(&n).ok().and_then(|n| n.as_dict().cloned()))
        .unwrap_or_default();
    let target = if state != "Off" && normal.contains_key(state.as_bytes()) {
        state
    } else {
        "Off"
    };
    if widget
        .get_name(b"AS")
        .is_some_and(|s| s.as_bytes() == target.as_bytes())
    {
        return Some(false);
    }
    widget.insert("AS", Object::name(target));
    Some(true)
}

/// Gives the text or choice widget `widget` the appearance of `how` showing `text`.
fn set_text_appearance(
    store: &mut Store,
    widget: &mut Dict,
    text: &str,
    how: FillAppearance,
) -> Option<()> {
    let (width, height) = rect_size(store, widget)?;
    match how {
        FillAppearance::ValueOnly => Some(()),
        FillAppearance::NewStream => {
            let stream = text_stream(store, width, height, text)?;
            let id = store.add(Object::Stream(Box::new(stream))).ok()?;
            let mut ap = Dict::new();
            ap.insert("N", Object::Ref(id));
            widget.insert("AP", Object::Dict(ap));
            Some(())
        }
        FillAppearance::InPlace => {
            let normal = widget
                .get(b"AP")
                .and_then(|ap| store.deref(ap).ok())
                .and_then(|ap| ap.as_dict().and_then(|d| d.get_ref(b"N")))?;
            let old = store.resolve(normal).ok()?;
            let Object::Stream(old) = &*old else {
                return None;
            };
            let dict = old.dict.clone();
            let mut dict = dict;
            dict.remove(b"Filter");
            dict.remove(b"DecodeParms");
            dict.remove(b"Length");
            let stream = Stream::new(dict, StreamData::Decoded(text_appearance(text, height)));
            store.set(normal, Object::Stream(Box::new(stream))).ok()
        }
    }
}

/// A new text appearance stream of `width` × `height` showing `text` with the first Helvetica
/// font of the document as `/Helv` (§12.7.4.3).
fn text_stream(store: &Store, width: i64, height: i64, text: &str) -> Option<Stream> {
    let mut dict = Dict::new();
    dict.insert("Type", Object::name("XObject"));
    dict.insert("Subtype", Object::name("Form"));
    dict.insert("BBox", int_array(&[0, 0, width, height]));
    if let Some(font) = helvetica(store) {
        let mut fonts = Dict::new();
        fonts.insert("Helv", Object::Ref(font));
        let mut resources = Dict::new();
        resources.insert("Font", Object::Dict(fonts));
        dict.insert("Resources", Object::Dict(resources));
    }
    Some(Stream::new(
        dict,
        StreamData::Decoded(text_appearance(text, height)),
    ))
}

/// The width and height of a widget's `/Rect`, rounded (at least 1 × 1).
fn rect_size(store: &Store, widget: &Dict) -> Option<(i64, i64)> {
    let rect = widget.get(b"Rect").and_then(|r| store.deref(r).ok())?;
    let values: Vec<f64> = rect.as_array()?.iter().filter_map(Object::as_f64).collect();
    let [x1, y1, x2, y2] = values.as_slice() else {
        return None;
    };
    // Rounded page coordinates: the casts saturate on hostile values.
    #[allow(clippy::cast_possible_truncation)]
    let size = |a: f64, b: f64| ((a - b).abs().round() as i64).max(1);
    Some((size(*x2, *x1), size(*y2, *y1)))
}

/// `[a b c d]` of integers.
fn int_array(values: &[i64]) -> Object {
    Object::Array(values.iter().copied().map(Object::Int).collect())
}

/// The first Helvetica font object of the store (a `/Type /Font` with `/BaseFont /Helvetica`).
pub(crate) fn helvetica(store: &Store) -> Option<ObjectId> {
    store.object_ids().into_iter().find(|&id| {
        store.resolve(id).ok().is_some_and(|obj| {
            obj.as_dict().is_some_and(|d| {
                d.is_type(b"Font")
                    && d.get_name(b"BaseFont")
                        .is_some_and(|f| f.as_bytes() == b"Helvetica")
            })
        })
    })
}

/// The field with the fully qualified name `name` (§12.7.4.2: partial names joined with `.`),
/// found from the AcroForm's `/Fields` through `/Kids`, and its field type (`/FT`, inherited).
pub(crate) fn field_by_name(store: &Store, name: &str) -> Option<(ObjectId, Vec<u8>)> {
    let root = store.root_id()?;
    let catalog = store.resolve(root).ok()?;
    let acroform = catalog
        .as_dict()?
        .get(b"AcroForm")
        .and_then(|a| store.deref(a).ok())?
        .as_dict()?
        .clone();
    let mut level: Vec<Object> = acroform
        .get(b"Fields")
        .and_then(|f| store.deref(f).ok())?
        .as_array()?
        .to_vec();
    let mut inherited: Option<Vec<u8>> = None;
    let parts: Vec<&str> = name.split('.').collect();
    for (depth, part) in parts.iter().enumerate() {
        let found = level.iter().find_map(|item| {
            let id = item.as_ref()?;
            let dict = store.resolve(id).ok()?.as_dict()?.clone();
            (dict.get_str_bytes(b"T") == Some(part.as_bytes())).then_some((id, dict))
        })?;
        let (id, dict) = found;
        if let Some(ft) = dict.get_name(b"FT") {
            inherited = Some(ft.as_bytes().to_vec());
        }
        if depth + 1 == parts.len() {
            return Some((id, inherited.unwrap_or_default()));
        }
        level = dict
            .get(b"Kids")
            .and_then(|k| store.deref(k).ok())?
            .as_array()?
            .to_vec();
    }
    None
}

// =================================================================================================
// Annotating (M4 brief §5.2).
// =================================================================================================

/// The annotation [`annotate`] adds to a page: its subtype, its `/Rect`, its other entries, an
/// appearance stream and an optional popup.
#[derive(Clone, Debug, PartialEq)]
pub struct Annot {
    /// The `/Subtype` name (§12.5.6), for example `Text`, `Square`, `Link`.
    pub subtype: String,
    /// The `/Rect` in default user space.
    pub rect: [f64; 4],
    /// The other entries, written after `/Type /Annot /Subtype /Rect /P /F 4` (an entry with a
    /// key written before replaces it).
    pub entries: Vec<(String, Object)>,
    /// The content of a new `/AP /N` form XObject (with the document's Helvetica as `/Helv`);
    /// `None`: no appearance.
    pub appearance: Option<Vec<u8>>,
    /// Adds a `/Popup` annotation (§12.5.6.14) whose `/Parent` is this annotation, and the
    /// annotation's `/Popup` entry; both join the page's `/Annots`.
    pub popup: bool,
    /// The 0-based page index.
    pub page: usize,
}

impl Annot {
    /// An annotation of `subtype` at `rect` with no other entries, no appearance and no popup.
    pub fn new(subtype: &str, rect: [f64; 4]) -> Annot {
        Annot {
            subtype: subtype.to_owned(),
            rect,
            entries: Vec::new(),
            appearance: None,
            popup: false,
            page: 0,
        }
    }

    /// Adds (or replaces) the entry `key`.
    #[must_use]
    pub fn with(mut self, key: &str, value: Object) -> Annot {
        self.entries.retain(|(k, _)| k != key);
        self.entries.push((key.to_owned(), value));
        self
    }

    /// Removes the entry `key` (including the defaults `/F` and `/P`).
    #[must_use]
    pub fn without(mut self, key: &str) -> Annot {
        self.entries.retain(|(k, _)| k != key);
        self.entries.push((key.to_owned(), Object::Null));
        self
    }

    /// Sets the appearance stream's content.
    #[must_use]
    pub fn with_appearance(mut self, content: &[u8]) -> Annot {
        self.appearance = Some(content.to_vec());
        self
    }

    /// Adds a popup.
    #[must_use]
    pub fn with_popup(mut self) -> Annot {
        self.popup = true;
        self
    }

    /// The markup entries every reviewer's annotation has (§12.5.6.2): `/T (Reviewer)`,
    /// `/Contents`, `/M`, `/CreationDate`, `/NM`, `/C`.
    fn markup(subtype: &str, rect: [f64; 4], contents: &str, colour: [f64; 3]) -> Annot {
        Annot::new(subtype, rect)
            .with("T", Object::literal_string("Reviewer"))
            .with("Contents", Object::literal_string(contents))
            .with("M", Object::literal_string("D:20261011120000Z"))
            .with("CreationDate", Object::literal_string("D:20261011120000Z"))
            .with(
                "NM",
                Object::literal_string(format!("folioxide-{}", subtype.to_lowercase())),
            )
            .with(
                "C",
                Object::Array(colour.iter().copied().map(Object::Real).collect()),
            )
    }

    /// A sticky note (`/Text`, §12.5.6.4) with a popup and an icon appearance.
    pub fn text() -> Annot {
        Annot::markup(
            "Text",
            [400.0, 700.0, 420.0, 720.0],
            "Please review",
            [1.0, 1.0, 0.0],
        )
        .with("Name", Object::name("Comment"))
        .with("Open", Object::Bool(false))
        .with_appearance(b"q 1 1 0 rg 0 G 0.5 0.5 19 19 re B Q")
        .with_popup()
    }

    /// A highlight (`/Highlight`, §12.5.6.10) over the page heading. Its `/Rect` holds the
    /// quadrilateral with a margin of a quarter of its height plus half a unit on every side,
    /// where poppler draws the highlight's rounded caps (M4 QA round 1, ruling R-2).
    pub fn highlight() -> Annot {
        Annot::markup(
            "Highlight",
            [63.0, 708.0, 307.0, 747.0],
            "Heading",
            [1.0, 1.0, 0.0],
        )
        .with(
            "QuadPoints",
            Object::Array(
                [70.0, 740.0, 300.0, 740.0, 70.0, 715.0, 300.0, 715.0]
                    .into_iter()
                    .map(Object::Real)
                    .collect(),
            ),
        )
        .with_appearance(b"q 1 1 0 rg 7 7 230 25 re f Q")
    }

    /// A square (`/Square`, §12.5.6.8) with a red border.
    pub fn square() -> Annot {
        Annot::markup(
            "Square",
            [60.0, 300.0, 260.0, 380.0],
            "See here",
            [1.0, 0.0, 0.0],
        )
        .with("BS", border(2))
        .with_appearance(b"q 1 0 0 RG 2 w 1 1 198 78 re S Q")
    }

    /// Ink (`/Ink`, §12.5.6.13): a freehand stroke.
    pub fn ink() -> Annot {
        Annot::markup(
            "Ink",
            [100.0, 200.0, 300.0, 260.0],
            "Scribble",
            [0.0, 0.0, 1.0],
        )
        .with(
            "InkList",
            Object::Array(vec![Object::Array(
                [110.0, 210.0, 150.0, 250.0, 200.0, 215.0, 290.0, 250.0]
                    .into_iter()
                    .map(Object::Real)
                    .collect(),
            )]),
        )
        .with("BS", border(1))
        .with_appearance(b"q 0 0 1 RG 1 w 10 10 m 50 50 l 100 15 l 190 50 l S Q")
    }

    /// Free text (`/FreeText`, §12.5.6.6) with its `/DA` and a text appearance.
    pub fn free_text() -> Annot {
        Annot::markup(
            "FreeText",
            [320.0, 600.0, 520.0, 630.0],
            "Approved",
            [1.0, 1.0, 1.0],
        )
        .with("DA", Object::literal_string("/Helv 12 Tf 0 g"))
        .with("Q", Object::Int(0))
        .with_appearance(
            b"q 0 G 1 w 0.5 0.5 199 29 re S BT /Helv 12 Tf 0 g 4 10 Td (Approved) Tj ET Q",
        )
    }

    /// A rubber stamp (`/Stamp`, §12.5.6.12) named `/Approved`.
    pub fn stamp() -> Annot {
        Annot::markup(
            "Stamp",
            [380.0, 480.0, 560.0, 540.0],
            "Approved",
            [0.0, 0.5, 0.0],
        )
        .with("Name", Object::name("Approved"))
        .with_appearance(b"q 0 0.5 0 RG 3 w 2 2 176 56 re S Q")
    }
}

/// A border style dictionary of width `width` (§12.5.4).
fn border(width: i64) -> Object {
    let mut bs = Dict::new();
    bs.insert("W", Object::Int(width));
    bs.insert("S", Object::name("S"));
    Object::Dict(bs)
}

/// Appends a revision that adds `annot` (and its popup) at the end of the page's `/Annots`, as a
/// reviewer's viewer does: `/Type /Annot /Subtype … /Rect … /P page /F 4` (Print), then the
/// entries, a new appearance stream when given. `None` when the page is missing or the update
/// cannot be written.
pub fn annotate(pdf: &[u8], annot: &Annot) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| add_annotation(store, annot).map(|_| ()))
}

/// [`annotate`] on `store`: the new annotation's identifier (and its popup's).
pub fn add_annotation(store: &mut Store, annot: &Annot) -> Option<(ObjectId, Option<ObjectId>)> {
    let page = page_id(store, annot.page)?;
    let mut dict = Dict::new();
    dict.insert("Type", Object::name("Annot"));
    dict.insert("Subtype", Object::name(annot.subtype.as_str()));
    dict.insert(
        "Rect",
        Object::Array(annot.rect.iter().copied().map(Object::Real).collect()),
    );
    dict.insert("P", Object::Ref(page));
    dict.insert("F", Object::Int(4));
    for (key, value) in &annot.entries {
        if value.is_null() {
            dict.remove(key.as_bytes());
        } else {
            dict.insert(key.as_str(), value.clone());
        }
    }
    if let Some(content) = &annot.appearance {
        let [x1, y1, x2, y2] = annot.rect;
        let mut form = Dict::new();
        form.insert("Type", Object::name("XObject"));
        form.insert("Subtype", Object::name("Form"));
        form.insert(
            "BBox",
            Object::Array(vec![
                Object::Int(0),
                Object::Int(0),
                Object::Real((x2 - x1).abs()),
                Object::Real((y2 - y1).abs()),
            ]),
        );
        if let Some(font) = helvetica(store) {
            let mut fonts = Dict::new();
            fonts.insert("Helv", Object::Ref(font));
            let mut resources = Dict::new();
            resources.insert("Font", Object::Dict(fonts));
            form.insert("Resources", Object::Dict(resources));
        }
        let stream = Stream::new(form, StreamData::Decoded(content.clone()));
        let appearance = store.add(Object::Stream(Box::new(stream))).ok()?;
        let mut ap = Dict::new();
        ap.insert("N", Object::Ref(appearance));
        dict.insert("AP", Object::Dict(ap));
    }
    let id = store.add(Object::Dict(dict.clone())).ok()?;
    append_to_annots(store, page, id)?;
    let popup = if annot.popup {
        let [_, _, x2, y2] = annot.rect;
        let mut popup = Dict::new();
        popup.insert("Type", Object::name("Annot"));
        popup.insert("Subtype", Object::name("Popup"));
        popup.insert(
            "Rect",
            Object::Array(
                [x2, y2 - 80.0, x2 + 160.0, y2]
                    .into_iter()
                    .map(Object::Real)
                    .collect(),
            ),
        );
        popup.insert("P", Object::Ref(page));
        // No NoZoom or NoRotate (Acrobat writes /F 28): a popup drawn at a fixed size or
        // unrotated is not confined to its /Rect (M4 QA round 1, ruling R-2).
        popup.insert("Parent", Object::Ref(id));
        popup.insert("Open", Object::Bool(false));
        let popup_id = store.add(Object::Dict(popup)).ok()?;
        dict.insert("Popup", Object::Ref(popup_id));
        store.set(id, Object::Dict(dict)).ok()?;
        append_to_annots(store, page, popup_id)?;
        Some(popup_id)
    } else {
        None
    };
    Some((id, popup))
}

/// The page with 0-based index `index`, walking the page tree from the catalog's `/Pages`
/// (depth-bounded).
pub fn page_id(store: &Store, index: usize) -> Option<ObjectId> {
    let root = store.root_id()?;
    let pages = store.resolve(root).ok()?.as_dict()?.get_ref(b"Pages")?;
    let mut leaves = Vec::new();
    let mut stack = vec![(pages, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > 32 || leaves.len() > index {
            break;
        }
        let dict = store.resolve(node).ok()?.as_dict()?.clone();
        if dict.is_type(b"Page") {
            leaves.push(node);
            continue;
        }
        let kids = dict.get(b"Kids").and_then(|k| store.deref(k).ok())?;
        for kid in kids.as_array()?.iter().rev() {
            if let Some(kid) = kid.as_ref() {
                stack.push((kid, depth + 1));
            }
        }
    }
    leaves.get(index).copied()
}

/// Appends a reference to `item` to the `/Annots` of `page` (direct, created when absent, or the
/// indirect array object).
pub fn append_to_annots(store: &mut Store, page: ObjectId, item: ObjectId) -> Option<()> {
    let mut dict = store.resolve(page).ok()?.as_dict()?.clone();
    match dict.get(b"Annots").cloned() {
        Some(Object::Ref(array)) => {
            let mut items = store.resolve(array).ok()?.as_array()?.to_vec();
            items.push(Object::Ref(item));
            store.set(array, Object::Array(items)).ok()
        }
        Some(Object::Array(mut items)) => {
            items.push(Object::Ref(item));
            dict.insert("Annots", Object::Array(items));
            store.set(page, Object::Dict(dict)).ok()
        }
        None | Some(Object::Null) => {
            dict.insert("Annots", Object::Array(vec![Object::Ref(item)]));
            store.set(page, Object::Dict(dict)).ok()
        }
        Some(_) => None,
    }
}

/// The `/Rotate` of each page of [`rotated_pages`], in page order.
pub const ROTATIONS: [i64; 4] = [0, 90, 180, 270];

/// `rotated_pages`: a four-page document whose pages are turned by [`ROTATIONS`] (0, 90, 180
/// and 270 degrees, §7.7.3.3), each US Letter (`/MediaBox [0 0 612 792]`) with the heading
/// `Page N, /Rotate R` in Helvetica at the top of its default user space. For visible
/// signatures on rotated pages (M4 brief §4.7, D-18).
pub fn rotated_pages() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.7");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>");
    let first = 4u32;
    let kids: Vec<String> = (0..ROTATIONS.len() as u32)
        .map(|i| format!("{} 0 R", first + 2 * i))
        .collect();
    b.obj(
        2,
        0,
        format!(
            "<< /Type /Pages /Kids [{}] /Count {} >>",
            kids.join(" "),
            ROTATIONS.len()
        ),
    );
    b.obj(
        3,
        0,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
    );
    for (i, rotate) in ROTATIONS.iter().enumerate() {
        let page = first + 2 * i as u32;
        b.obj(
            page,
            0,
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Rotate {rotate} \
                 /Contents {} 0 R /Resources << /Font << /F1 3 0 R >> >> >>",
                page + 1
            ),
        );
        b.stream_obj(
            page + 1,
            0,
            "",
            format!(
                "BT /F1 18 Tf 72 720 Td (Page {}, /Rotate {rotate}) Tj ET",
                i + 1
            )
            .as_bytes(),
            None,
        );
    }
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array("rotated-pages")
    );
    b.trailer(trailer).startxref(None).eof();
    b.build()
}

/// The empty signature field of [`with_split_signature_field`], whose widget is a kid.
pub const SPLIT: &str = "Split";

/// `with_split_signature_field`: `pdf` (an [`acroform`]-like document with an indirect
/// `/Fields` holder) with a revision that adds an empty signature field [`SPLIT`] whose widget
/// is a separate `/Kids` object (`/Parent` the field, `/Rect [300 300 500 360]`) on the first
/// page: the case a visible signature does not support (DECISIONS D13 D-18).
pub fn with_split_signature_field(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let page = page_id(store, 0)?;
        let field = store.add(Object::Null).ok()?;
        let mut widget = Dict::new();
        widget.insert("Type", Object::name("Annot"));
        widget.insert("Subtype", Object::name("Widget"));
        widget.insert("Parent", Object::Ref(field));
        widget.insert("F", Object::Int(4));
        widget.insert(
            "Rect",
            Object::Array([300, 300, 500, 360].map(Object::Int).to_vec()),
        );
        widget.insert("P", Object::Ref(page));
        let widget = store.add(Object::Dict(widget)).ok()?;
        let mut dict = Dict::new();
        dict.insert("FT", Object::name("Sig"));
        dict.insert("T", Object::literal_string(SPLIT));
        dict.insert("Kids", Object::Array(vec![Object::Ref(widget)]));
        store.set(field, Object::Dict(dict)).ok()?;
        append_to_annots(store, page, widget)?;
        let root = store.root_id()?;
        let acroform = store.resolve(root).ok()?.as_dict()?.get_ref(b"AcroForm")?;
        let mut acroform_dict = store.resolve(acroform).ok()?.as_dict()?.clone();
        let mut fields = acroform_dict.get_array(b"Fields")?.to_vec();
        fields.push(Object::Ref(field));
        acroform_dict.insert("Fields", Object::Array(fields));
        store.set(acroform, Object::Dict(acroform_dict)).ok()
    })
}

/// Opens `pdf`, lets `edit` change it, and returns `pdf` with the edits appended as one
/// incremental update (`None` when `edit` gives up or the update cannot be written).
pub fn with_incremental(
    pdf: &[u8],
    edit: impl FnOnce(&mut Store) -> Option<()>,
) -> Option<Vec<u8>> {
    let mut store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default()).ok()?;
    edit(&mut store)?;
    store.save_incremental(&IncrementalOptions::default()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(pdf: Vec<u8>) -> Store {
        let store = Store::open_bytes(pdf, &OpenOptions::default()).unwrap();
        assert!(!store.structure_repaired());
        store
    }

    fn dict(store: &Store, num: u32) -> Dict {
        store
            .resolve(ObjectId::new(num, 0))
            .unwrap()
            .as_dict()
            .unwrap()
            .clone()
    }

    #[test]
    fn the_form_documents_are_deterministic_and_well_formed() {
        assert_eq!(acroform(), acroform());
        assert_eq!(acroform_tagged(), acroform_tagged());
        let store = open(acroform());
        assert_eq!(
            field_by_name(&store, AMOUNT),
            Some((ObjectId::new(ids::AMOUNT, 0), b"Tx".to_vec()))
        );
        assert_eq!(
            field_by_name(&store, CHOICE),
            Some((ObjectId::new(ids::CHOICE, 0), b"Btn".to_vec()))
        );
        assert_eq!(field_by_name(&store, "Missing"), None);
        assert_eq!(
            dict(&store, ids::VISIBLE)
                .get_array(b"Rect")
                .map(<[_]>::len),
            Some(4)
        );
        let tagged = open(acroform_tagged());
        let root = dict(&tagged, ids::CATALOG);
        assert_eq!(
            root.get_ref(b"StructTreeRoot"),
            Some(ObjectId::new(ids::STRUCT_TREE_ROOT, 0))
        );
        assert_eq!(dict(&tagged, ids::AMOUNT).get_int(b"StructParent"), Some(0));
        let many = open(acroform_text_fields(30));
        assert_eq!(
            field_by_name(&many, "F29").map(|(_, t)| t),
            Some(b"Tx".to_vec())
        );
    }

    #[test]
    fn filling_sets_values_states_and_appearances() {
        let base = acroform();
        let filled = fill_all(
            &base,
            &[
                Fill::text(AMOUNT, "900 EUR"),
                Fill::state(AGREE, "Yes"),
                Fill::state(CHOICE, "B"),
                Fill::text(COUNTRY, "Italy").with_appearance(FillAppearance::InPlace),
            ],
        )
        .unwrap();
        assert!(filled.starts_with(&base));
        let store = open(filled);
        let amount = dict(&store, ids::AMOUNT);
        assert_eq!(amount.get_str_bytes(b"V"), Some(b"900 EUR".as_slice()));
        let ap = amount.get_dict(b"AP").unwrap().get_ref(b"N").unwrap();
        assert!(ap.num > ids::INVISIBLE, "a new stream");
        let agree = dict(&store, ids::AGREE);
        assert_eq!(agree.get_name(b"V").unwrap().as_bytes(), b"Yes");
        assert_eq!(agree.get_name(b"AS").unwrap().as_bytes(), b"Yes");
        assert_eq!(
            dict(&store, ids::CHOICE).get_name(b"V").unwrap().as_bytes(),
            b"B"
        );
        assert_eq!(
            dict(&store, ids::CHOICE_A)
                .get_name(b"AS")
                .unwrap()
                .as_bytes(),
            b"Off"
        );
        assert_eq!(
            dict(&store, ids::CHOICE_B)
                .get_name(b"AS")
                .unwrap()
                .as_bytes(),
            b"B"
        );
        // In place: the same stream object, new data.
        let country = dict(&store, ids::COUNTRY);
        assert_eq!(
            country.get_dict(b"AP").unwrap().get_ref(b"N"),
            Some(ObjectId::new(ids::COUNTRY_AP, 0))
        );
        let entries = store.revision_entries(1).unwrap();
        assert!(entries.iter().any(|(num, _)| *num == ids::COUNTRY_AP));
        // A missing field is None.
        assert_eq!(fill(&base, &Fill::text("Nope", "x")), None);
    }

    #[test]
    fn annotating_appends_to_the_page() {
        let base = acroform();
        let annotated = annotate(&base, &Annot::text()).unwrap();
        let store = open(annotated);
        let page = dict(&store, ids::PAGE);
        let annots = page.get_array(b"Annots").unwrap();
        assert_eq!(annots.len(), WIDGETS.len() + 2, "the note and its popup");
        let note = annots[WIDGETS.len()].as_ref().unwrap();
        let popup = annots[WIDGETS.len() + 1].as_ref().unwrap();
        let note_dict = store.resolve(note).unwrap().as_dict().unwrap().clone();
        assert_eq!(note_dict.get_ref(b"Popup"), Some(popup));
        assert_eq!(note_dict.get_ref(b"P"), Some(ObjectId::new(ids::PAGE, 0)));
        let popup_dict = store.resolve(popup).unwrap().as_dict().unwrap().clone();
        assert_eq!(popup_dict.get_ref(b"Parent"), Some(note));
        for preset in [
            Annot::highlight(),
            Annot::square(),
            Annot::ink(),
            Annot::free_text(),
            Annot::stamp(),
        ] {
            let annotated = annotate(&base, &preset).unwrap();
            assert!(annotated.starts_with(&base));
            open(annotated);
        }
        // An entry can be removed or replaced.
        let without_p = Annot::square().without("P").with("F", Object::Int(36));
        let store = open(annotate(&base, &without_p).unwrap());
        let annots = dict(&store, ids::PAGE);
        let last = annots
            .get_array(b"Annots")
            .unwrap()
            .last()
            .unwrap()
            .as_ref()
            .unwrap();
        let last = store.resolve(last).unwrap().as_dict().unwrap().clone();
        assert!(!last.contains_key(b"P"));
        assert_eq!(last.get_int(b"F"), Some(36));
    }
}

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! M3 brief §6.2 "field / placeholder / prepare (Dev A)": the field placement rules of §4.1
//! and §4.5 (new and existing fields, auto-naming, `/AcroForm` and `/Annots` in every shape,
//! `/SigFlags` and the keys a later signature must not touch), checked on the incremental
//! update [`write_placeholder`] appends. The placement is the same code `prepare` runs before
//! any cryptography.

use std::collections::BTreeSet;

use folioxide_model::{Document, PdfDate};
use folioxide_sign::Error;
use folioxide_sign::field::{FieldMode, FieldSpec, signature_fields};
use folioxide_sign::placeholder::{PlaceholderPdf, write_placeholder};
use folioxide_sign::prepare::SignatureOptions;
use folioxide_syntax::{Dict, ErrorCode, Object, ObjectId, OpenOptions, XrefEntry};
use folioxide_testkit::fixtures::{id_array, syntax};
use folioxide_testkit::{PdfBuilder, XrefOpts};

// ---- helpers ------------------------------------------------------------------------------------

fn time() -> PdfDate {
    PdfDate::parse(b"D:20261010120000Z").unwrap()
}

fn open(bytes: &[u8]) -> Document {
    Document::open(bytes.to_vec(), &OpenOptions::default()).unwrap()
}

fn options(spec: FieldSpec) -> SignatureOptions {
    SignatureOptions::new(time()).with_field(spec)
}

fn named(name: &str) -> FieldSpec {
    FieldSpec::new().with_name(Some(name.to_owned()))
}

fn place(source: &[u8], spec: FieldSpec) -> Result<PlaceholderPdf, Error> {
    write_placeholder(&open(source), &options(spec))
}

/// A one-page document: 1 catalog (plus `catalog_extra`), 2 page tree, 3 page (plus
/// `page_extra`), 4 contents, then the `extra` objects numbered from 5; a classic xref table.
fn build(catalog_extra: &str, page_extra: &str, extra: &[&str]) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.7");
    b.obj(
        1,
        0,
        format!("<< /Type /Catalog /Pages 2 0 R {catalog_extra} >>"),
    );
    b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    b.obj(
        3,
        0,
        format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R {page_extra} >>"
        ),
    );
    b.stream_obj(4, 0, "", b"BT ET", None);
    for (i, body) in extra.iter().enumerate() {
        b.obj(5 + i as u32, 0, body);
    }
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array("sign-field")
    );
    b.trailer(trailer).startxref(None).eof();
    b.build()
}

/// The object numbers the appended update writes (in use), from its own xref section.
fn written(p: &PlaceholderPdf) -> BTreeSet<u32> {
    let doc = open(&p.pdf);
    let store = doc.store();
    let last = store.revisions().len() - 1;
    store
        .revision_entries(last)
        .unwrap()
        .into_iter()
        .filter(|(_, entry)| matches!(entry, XrefEntry::InFile { .. }))
        .map(|(num, _)| num)
        .collect()
}

/// Object `num` (generation 0) of `pdf`, as a dictionary.
fn dict(pdf: &[u8], num: u32) -> Dict {
    let doc = open(pdf);
    doc.store()
        .resolve(ObjectId::new(num, 0))
        .unwrap()
        .as_dict()
        .unwrap_or_else(|| panic!("object {num} is not a dictionary"))
        .clone()
}

/// Object `num` (generation 0) of `pdf`.
fn object(pdf: &[u8], num: u32) -> Object {
    let doc = open(pdf);
    Object::clone(&doc.store().resolve(ObjectId::new(num, 0)).unwrap())
}

fn refs(values: &[ObjectId]) -> Object {
    Object::Array(values.iter().map(|&id| Object::Ref(id)).collect())
}

/// The catalog's AcroForm of `pdf`, wherever it is.
fn acroform(pdf: &[u8]) -> Dict {
    let doc = open(pdf);
    let catalog = doc.catalog().unwrap();
    let value = catalog.as_dict().unwrap().get(b"AcroForm").unwrap().clone();
    doc.store()
        .deref(&value)
        .unwrap()
        .as_dict()
        .unwrap()
        .clone()
}

fn code(result: Result<PlaceholderPdf, Error>) -> ErrorCode {
    result.unwrap_err().code()
}

/// An unsigned signature field, merged with its widget, on page 3.
const EMPTY_SIG_FIELD: &str =
    "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Approval) /F 132 /Rect [0 0 0 0] /P 3 0 R >>";

/// A signature dictionary (as signed fields carry; nothing is verified here).
const SIG_DICT: &str = "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached \
                        /ByteRange [0 1 2 3] /Contents <00> >>";

// ---- fields -------------------------------------------------------------------------------------

#[test]
fn field_auto_name_signature_n() {
    // No form: Signature1.
    let first = place(&syntax::minimal(), FieldSpec::new()).unwrap();
    assert_eq!(first.field_name, "Signature1");
    assert!(first.field_created);

    // Signature1 (unsigned) and Signature3 exist, and Signature2 only as a nested name: the
    // smallest unused fully qualified name is Signature2, and the empty Signature1 is not taken
    // over implicitly (D-18).
    let pdf = build(
        "/AcroForm 5 0 R",
        "/Annots [6 0 R 8 0 R 9 0 R]",
        &[
            "<< /Fields [6 0 R 7 0 R 9 0 R] >>",
            "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) /Rect [0 0 0 0] /P 3 0 R >>",
            "<< /T (form) /FT /Sig /Kids [8 0 R] >>",
            "<< /Type /Annot /Subtype /Widget /T (Signature2) /Parent 7 0 R /Rect [0 0 0 0] /P 3 0 R >>",
            "<< /Type /Annot /Subtype /Widget /FT /Tx /T (Signature3) /Rect [0 0 10 10] /P 3 0 R >>",
        ],
    );
    let p = place(&pdf, FieldSpec::new()).unwrap();
    assert_eq!(p.field_name, "Signature2");
    assert!(p.field_created);
    assert!(p.field.num >= 10);

    // Sequential: a second placeholder on top of the first one is Signature2.
    let second = place(&first.pdf, FieldSpec::new()).unwrap();
    assert_eq!(second.field_name, "Signature2");
    let names: Vec<String> = signature_fields(&open(&second.pdf))
        .unwrap()
        .into_iter()
        .map(|f| f.name)
        .collect();
    assert_eq!(names, ["Signature1", "Signature2"]);
}

#[test]
fn field_new_invisible_widget_dict() {
    let p = place(&syntax::minimal(), FieldSpec::new()).unwrap();
    let w = p.field;
    let s = p.sig_dict;
    assert_eq!((w.generation(), s.generation()), (0, 0));

    // Exactly the keys and values of §4.1, in that order.
    let widget = dict(&p.pdf, w.num);
    let keys: Vec<&[u8]> = widget.keys().map(|k| k.as_bytes()).collect();
    assert_eq!(
        keys,
        [
            b"Type".as_slice(),
            b"Subtype",
            b"FT",
            b"T",
            b"V",
            b"F",
            b"Rect",
            b"P"
        ]
    );
    assert!(widget.get(b"Type").unwrap().is_name(b"Annot"));
    assert!(widget.get(b"Subtype").unwrap().is_name(b"Widget"));
    assert!(widget.get(b"FT").unwrap().is_name(b"Sig"));
    assert_eq!(widget.get_str_bytes(b"T"), Some(b"Signature1".as_slice()));
    assert_eq!(widget.get(b"V"), Some(&Object::Ref(s)), "/V is indirect");
    assert_eq!(widget.get_int(b"F"), Some(132));
    assert_eq!(
        widget.get(b"Rect"),
        Some(&Object::Array(vec![
            Object::Int(0),
            Object::Int(0),
            Object::Int(0),
            Object::Int(0)
        ]))
    );
    assert_eq!(widget.get(b"P"), Some(&Object::Ref(ObjectId::new(3, 0))));
    assert!(!widget.contains_key(b"AP"));
    // Byte for byte, as the writer serialized it.
    let text = format!(
        "{} 0 obj\n<</Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) /V {} 0 R /F 132 \
         /Rect [0 0 0 0] /P 3 0 R>>\nendobj\n",
        w.num, s.num
    );
    assert!(p.pdf.windows(text.len()).any(|win| win == text.as_bytes()));

    // The widget is on the page and at the root of /AcroForm /Fields.
    assert_eq!(dict(&p.pdf, 3).get(b"Annots"), Some(&refs(&[w])));
    assert_eq!(acroform(&p.pdf).get(b"Fields"), Some(&refs(&[w])));
    assert!(dict(&p.pdf, s.num).get(b"Type").unwrap().is_name(b"Sig"));
    let fields = signature_fields(&open(&p.pdf)).unwrap();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].field, Some(w));
    assert!(fields[0].signed);
    assert_eq!(fields[0].value, Some(s));

    // A Unicode name is a UTF-16BE text string.
    let p = place(&syntax::minimal(), named("Unterschrift \u{3042}")).unwrap();
    let names: Vec<String> = signature_fields(&open(&p.pdf))
        .unwrap()
        .into_iter()
        .map(|f| f.name)
        .collect();
    assert_eq!(names, ["Unterschrift \u{3042}"]);
}

#[test]
fn field_existing_empty_used() {
    let pdf = build(
        "/AcroForm 5 0 R",
        "/Annots [6 0 R]",
        &[
            "<< /Fields [6 0 R] /DA (/Helv 0 Tf 0 g) >>",
            EMPTY_SIG_FIELD,
        ],
    );
    for mode in [FieldMode::CreateOrUse, FieldMode::ExistingOnly] {
        let p = place(&pdf, named("Approval").with_mode(mode)).unwrap();
        assert!(!p.field_created);
        assert_eq!(p.field, ObjectId::new(6, 0));
        assert_eq!(p.field_name, "Approval");
        assert!(p.sig_dict.num >= 7);
        // Only /V on the field object; the page keeps its /Annots, /Fields is unchanged, and the
        // AcroForm gains /SigFlags 3 because no signed field existed.
        assert_eq!(written(&p), BTreeSet::from([5, 6, p.sig_dict.num]));
        let field = dict(&p.pdf, 6);
        assert_eq!(field.get(b"V"), Some(&Object::Ref(p.sig_dict)));
        let mut before = field.clone();
        before.remove(b"V");
        assert_eq!(
            Object::Dict(before),
            object(&pdf, 6),
            "nothing else changes"
        );
        let form = acroform(&p.pdf);
        assert_eq!(form.get(b"Fields"), Some(&refs(&[ObjectId::new(6, 0)])));
        assert_eq!(form.get_int(b"SigFlags"), Some(3));
        assert_eq!(
            form.get_str_bytes(b"DA"),
            Some(b"/Helv 0 Tf 0 g".as_slice())
        );
    }

    // A field whose /FT is inherited, addressed by its fully qualified name.
    let pdf = build(
        "/AcroForm 5 0 R",
        "/Annots [7 0 R]",
        &[
            "<< /Fields [6 0 R] /SigFlags 3 >>",
            "<< /FT /Sig /T (approvals) /Kids [7 0 R] >>",
            "<< /Type /Annot /Subtype /Widget /T (manager) /Parent 6 0 R /Rect [0 0 0 0] /P 3 0 R >>",
        ],
    );
    let p = place(&pdf, named("approvals.manager")).unwrap();
    assert!(!p.field_created);
    assert_eq!(p.field, ObjectId::new(7, 0));
    // /SigFlags is 3 already: the AcroForm is not rewritten.
    assert_eq!(written(&p), BTreeSet::from([7, p.sig_dict.num]));
}

#[test]
fn field_existing_signed_rejected() {
    let pdf = build(
        "/AcroForm 5 0 R",
        "/Annots [6 0 R]",
        &[
            "<< /Fields [6 0 R] /SigFlags 3 >>",
            "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Approval) /V 7 0 R /F 132 /Rect [0 0 0 0] /P 3 0 R >>",
            SIG_DICT,
        ],
    );
    for mode in [FieldMode::CreateOrUse, FieldMode::ExistingOnly] {
        let err = place(&pdf, named("Approval").with_mode(mode)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
        assert!(err.to_string().contains("already signed"), "{err}");
    }
    // A field that is not a signature field, and one with child fields.
    let pdf = build(
        "/AcroForm 5 0 R",
        "/Annots [6 0 R 8 0 R]",
        &[
            "<< /Fields [6 0 R 7 0 R] >>",
            "<< /Type /Annot /Subtype /Widget /FT /Tx /T (Text1) /Rect [0 0 10 10] /P 3 0 R >>",
            "<< /FT /Sig /T (group) /Kids [8 0 R] >>",
            "<< /Type /Annot /Subtype /Widget /T (child) /Parent 7 0 R /Rect [0 0 0 0] /P 3 0 R >>",
        ],
    );
    assert_eq!(
        code(place(&pdf, named("Text1"))),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        code(place(&pdf, named("group"))),
        ErrorCode::InvalidArgument
    );
    // Other modes and names.
    assert_eq!(
        code(place(
            &pdf,
            named("group.child").with_mode(FieldMode::CreateOnly)
        )),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        code(place(
            &pdf,
            named("Missing").with_mode(FieldMode::ExistingOnly)
        )),
        ErrorCode::NotFound
    );
    assert_eq!(
        code(place(
            &pdf,
            FieldSpec::new().with_mode(FieldMode::ExistingOnly)
        )),
        ErrorCode::InvalidArgument
    );
    // A new name is fine with CreateOnly.
    let p = place(&pdf, named("New").with_mode(FieldMode::CreateOnly)).unwrap();
    assert!(p.field_created);
}

#[test]
fn field_name_with_dot_rejected() {
    for mode in [FieldMode::CreateOrUse, FieldMode::CreateOnly] {
        let err = place(&syntax::minimal(), named("a.b").with_mode(mode)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
        assert!(err.to_string().contains("'.'"), "{err}");
    }
    assert_eq!(
        code(place(&syntax::minimal(), named(""))),
        ErrorCode::InvalidArgument
    );
    // The page must exist.
    assert!(matches!(
        place(&syntax::minimal(), FieldSpec::new().with_page(1)),
        Err(Error::PageOutOfRange(1))
    ));
}

#[test]
fn field_lock_unsupported() {
    let with = |extra: &str| {
        build(
            "/AcroForm 5 0 R",
            "/Annots [6 0 R]",
            &[
                "<< /Fields [6 0 R] >>",
                &format!(
                    "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Approval) /F 132 /Rect [0 0 0 0] \
                     /P 3 0 R {extra} >>"
                ),
                "<< /Type /SigFieldLock /Action /All >>",
            ],
        )
    };
    let err = place(&with("/Lock 7 0 R"), named("Approval")).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported, "{err}");
    assert!(err.to_string().contains("/Lock"), "{err}");
    // Required seed-value constraints are unsupported; optional ones are fine (D-13).
    let err = place(
        &with("/SV << /Ff 1 /SubFilter [/adbe.pkcs7.detached] >>"),
        named("Approval"),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported, "{err}");
    let p = place(&with("/SV << /Ff 0 /Reasons [(OK)] >>"), named("Approval")).unwrap();
    assert!(!p.field_created);
    let p = place(&with("/SV << /Reasons [(OK)] >>"), named("Approval")).unwrap();
    assert!(!p.field_created);
}

// ---- AcroForm and annotations -------------------------------------------------------------------

#[test]
fn acroform_created_indirect_sigflags_3() {
    let p = place(&syntax::minimal(), FieldSpec::new()).unwrap();
    let catalog = dict(&p.pdf, 1);
    let Some(Object::Ref(a)) = catalog.get(b"AcroForm").cloned() else {
        panic!("the catalog's /AcroForm is not indirect: {catalog:?}");
    };
    // A new number, above the widget and the signature dictionary.
    assert!(a.num > p.field.num && a.num > p.sig_dict.num);
    let form = dict(&p.pdf, a.num);
    assert_eq!(form.len(), 2, "{form:?}");
    assert_eq!(form.get(b"Fields"), Some(&refs(&[p.field])));
    assert_eq!(form.get_int(b"SigFlags"), Some(3));
    // The update: catalog, page, widget, signature dictionary, AcroForm.
    assert_eq!(
        written(&p),
        BTreeSet::from([1, 3, p.field.num, p.sig_dict.num, a.num])
    );
}

#[test]
fn acroform_direct_dict_updated() {
    let pdf = build(
        "/AcroForm << /Fields [] /DA (/Helv 0 Tf 0 g) /DR << /Font << >> >> >>",
        "",
        &[],
    );
    let p = place(&pdf, FieldSpec::new()).unwrap();
    // The catalog holds the AcroForm: it is the object edited, and no AcroForm object is new.
    assert_eq!(
        written(&p),
        BTreeSet::from([1, 3, p.field.num, p.sig_dict.num])
    );
    let catalog = dict(&p.pdf, 1);
    let form = catalog.get_dict(b"AcroForm").expect("still direct");
    assert_eq!(form.get(b"Fields"), Some(&refs(&[p.field])));
    assert_eq!(form.get_int(b"SigFlags"), Some(3));
    assert_eq!(
        form.get_str_bytes(b"DA"),
        Some(b"/Helv 0 Tf 0 g".as_slice())
    );
    assert!(form.get_dict(b"DR").is_some());
}

#[test]
fn fields_indirect_array_updated() {
    let pdf = build(
        "/AcroForm 5 0 R",
        "/Annots [7 0 R]",
        &[
            "<< /Fields 6 0 R /SigFlags 3 >>",
            "[7 0 R]",
            "<< /Type /Annot /Subtype /Widget /FT /Tx /T (Name) /Rect [0 0 10 10] /P 3 0 R >>",
        ],
    );
    let p = place(&pdf, FieldSpec::new()).unwrap();
    // The array object is edited; the AcroForm (SigFlags 3 already) is not.
    assert_eq!(
        written(&p),
        BTreeSet::from([3, 6, p.field.num, p.sig_dict.num])
    );
    assert_eq!(
        object(&p.pdf, 6),
        refs(&[ObjectId::new(7, 0), p.field]),
        "the new field is appended at the root"
    );
    assert_eq!(
        dict(&p.pdf, 5).get(b"Fields"),
        Some(&Object::Ref(ObjectId::new(6, 0)))
    );
}

#[test]
fn annots_indirect_array_updated() {
    let pdf = build(
        "",
        "/Annots 5 0 R",
        &[
            "[6 0 R]",
            "<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /Border [0 0 0] >>",
        ],
    );
    let p = place(&pdf, FieldSpec::new()).unwrap();
    let catalog = dict(&p.pdf, 1);
    let Some(Object::Ref(a)) = catalog.get(b"AcroForm").cloned() else {
        panic!("no indirect AcroForm");
    };
    // The /Annots array object is edited, the page is not.
    assert_eq!(
        written(&p),
        BTreeSet::from([1, 5, p.field.num, p.sig_dict.num, a.num])
    );
    assert_eq!(object(&p.pdf, 5), refs(&[ObjectId::new(6, 0), p.field]));
    assert_eq!(
        dict(&p.pdf, 3).get(b"Annots"),
        Some(&Object::Ref(ObjectId::new(5, 0)))
    );

    // A reference to a missing /Annots array reads as no annotations: the page gets its own.
    let pdf = build("", "/Annots 50 0 R", &[]);
    let p = place(&pdf, FieldSpec::new()).unwrap();
    assert_eq!(dict(&p.pdf, 3).get(b"Annots"), Some(&refs(&[p.field])));
    // /Annots of the wrong type is refused.
    let pdf = build("", "/Annots 7", &[]);
    assert_eq!(code(place(&pdf, FieldSpec::new())), ErrorCode::TypeMismatch);
}

#[test]
fn second_signature_keeps_acroform_keys() {
    // A document with a signed field: the AcroForm's /SigFlags 1, /DA and /NeedAppearances
    // must survive a second signature untouched; only /Fields changes (brief §4.5, D-5, D-6).
    let pdf = build(
        "/AcroForm 5 0 R",
        "/Annots [6 0 R]",
        &[
            "<< /Fields [6 0 R] /SigFlags 1 /DA (/Helv 0 Tf 0 g) /NeedAppearances true >>",
            "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) /V 7 0 R /F 132 /Rect [0 0 0 0] /P 3 0 R >>",
            SIG_DICT,
        ],
    );
    let before = acroform(&pdf);
    let p = place(&pdf, FieldSpec::new()).unwrap();
    assert_eq!(p.field_name, "Signature2");
    assert!(
        p.warnings.iter().any(|w| w.contains("NeedAppearances")),
        "{:?}",
        p.warnings
    );
    let after = acroform(&p.pdf);
    assert_eq!(
        after.get(b"Fields"),
        Some(&refs(&[ObjectId::new(6, 0), p.field]))
    );
    let without_fields = |d: &Dict| {
        let mut d = d.clone();
        d.remove(b"Fields");
        d
    };
    assert_eq!(without_fields(&after), without_fields(&before));
    assert_eq!(after.get_int(b"SigFlags"), Some(1));
    assert_eq!(after.get_bool(b"NeedAppearances"), Some(true));

    // Our own sequential placeholders: the second leaves every AcroForm key but /Fields alone.
    let first = place(&syntax::minimal(), FieldSpec::new()).unwrap();
    let second = place(&first.pdf, FieldSpec::new()).unwrap();
    let (a1, a2) = (acroform(&first.pdf), acroform(&second.pdf));
    assert_eq!(without_fields(&a1), without_fields(&a2));
    assert_eq!(a2.get(b"Fields"), Some(&refs(&[first.field, second.field])));
    // New numbers above everything the first update used.
    assert!(second.field.num > first.sig_dict.num);
}

#[test]
fn existing_field_sets_sig_flags_only_while_unsigned() {
    // An empty field in a form that already has a signed field: /V is set, the AcroForm is
    // not touched at all (its /Fields does not change).
    let pdf = build(
        "/AcroForm 5 0 R",
        "/Annots [6 0 R 7 0 R]",
        &[
            "<< /Fields [6 0 R 7 0 R] /SigFlags 1 >>",
            EMPTY_SIG_FIELD,
            "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signed) /V 8 0 R /F 132 /Rect [0 0 0 0] /P 3 0 R >>",
            SIG_DICT,
        ],
    );
    let p = place(&pdf, named("Approval")).unwrap();
    assert_eq!(written(&p), BTreeSet::from([6, p.sig_dict.num]));
    assert_eq!(acroform(&p.pdf).get_int(b"SigFlags"), Some(1));
}

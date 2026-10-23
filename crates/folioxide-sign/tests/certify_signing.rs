#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Certification signatures, the signing side (M4 brief §4.6, §6.2 "Certification, signing
//! side"): the `/Reference` DocMDP transform and the catalog's `/Perms`, the refusals that keep a
//! certified document valid, and what stays allowed.

mod sign_support;

use folioxide_model::Rect;
use folioxide_sign::Error;
use folioxide_sign::appearance::SignatureAppearance;
use folioxide_sign::docmdp::DocMdpPermissions;
use folioxide_sign::field::{FieldMode, FieldSpec};
use folioxide_sign::prepare::{PrepareRequest, SignatureOptions, prepare};
use folioxide_sign::report::ModificationLevel;
use folioxide_sign::sign::{SignRequest, sign};
use folioxide_sign::signer::Signer;
use folioxide_syntax::{ErrorCode, Object, ObjectId};
use folioxide_testkit::fixtures::{forms, id_array, syntax};
use folioxide_testkit::{PdfBuilder, XrefOpts};
use sign_support::*;

/// Signs `source` with RSA-2048 and `options`; the error when signing is refused.
fn try_sign(source: &[u8], options: SignatureOptions) -> Result<Vec<u8>, Error> {
    let signer = rsa2048();
    sign(
        &open(source),
        &SignRequest::new(&signer, time()).with_options(options),
    )
}

/// The default options, certifying with `p`.
fn certify(p: DocMdpPermissions) -> SignatureOptions {
    SignatureOptions::new(time()).with_certification(Some(p))
}

/// `source` certified with `p` by RSA-2048.
fn certified(source: &[u8], p: DocMdpPermissions) -> Vec<u8> {
    try_sign(source, certify(p)).unwrap_or_else(|e| panic!("certifying failed: {e}"))
}

/// The value of object `id` in the newest revision of `pdf`.
fn object(pdf: &[u8], id: ObjectId) -> Object {
    open(pdf).store().resolve(id).unwrap().as_ref().clone()
}

/// The catalog of the newest revision of `pdf`.
fn catalog(pdf: &[u8]) -> folioxide_syntax::Dict {
    let doc = open(pdf);
    doc.catalog().unwrap().as_dict().unwrap().clone()
}

/// The signature dictionary of the newest signature field `name`.
fn sig_dict_id(pdf: &[u8], name: &str) -> ObjectId {
    let doc = open(pdf);
    folioxide_sign::field::signature_fields(&doc)
        .unwrap()
        .into_iter()
        .find(|f| f.name == name)
        .and_then(|f| f.value)
        .unwrap_or_else(|| panic!("no signed field {name}"))
}

/// Asserts that `result` is a `DocMdpForbids` refusal whose message contains `rule`.
fn assert_forbidden(result: Result<Vec<u8>, Error>, rule: &str) {
    match result {
        Err(err @ Error::DocMdpForbids(_)) => {
            assert_eq!(err.code(), ErrorCode::DocMdpForbids);
            assert!(err.to_string().contains(rule), "{err}");
        }
        Err(other) => panic!("expected DocMdpForbids ({rule}), got {other}"),
        Ok(_) => panic!("expected DocMdpForbids ({rule}), the signature was made"),
    }
}

#[test]
fn certify_p1_writes_reference_and_perms() {
    let source = syntax::minimal();
    let signed = certified(&source, DocMdpPermissions::NoChanges);
    let sig = sig_dict_id(&signed, "Signature1");

    // The signature dictionary: /Reference exactly as brief §4.6 (all direct), before
    // /ByteRange, with /Contents last.
    let text = String::from_utf8_lossy(&signed[source.len()..]).into_owned();
    let start = text.find(&format!("{} 0 obj", sig.num)).unwrap();
    let dict_text = &text[start..];
    let reference = "/Reference [<</Type /SigRef /TransformMethod /DocMDP /TransformParams \
                     <</Type /TransformParams /P 1 /V /1.2>>>>]";
    let at = dict_text
        .find(reference)
        .unwrap_or_else(|| panic!("{dict_text}"));
    let byte_range = dict_text.find("/ByteRange").unwrap();
    let contents = dict_text.find("/Contents").unwrap();
    assert!(at < byte_range && byte_range < contents, "{dict_text}");
    for absent in ["/Data", "/DigestMethod", "/DigestValue"] {
        assert!(!dict_text[..contents].contains(absent), "{absent}");
    }
    let Object::Dict(dict) = object(&signed, sig) else {
        panic!("a signature dictionary")
    };
    let references = dict.get_array(b"Reference").unwrap();
    assert_eq!(references.len(), 1);
    assert!(matches!(references[0], Object::Dict(_)), "direct");

    // The catalog: /Perms << /DocMDP sig >>, direct.
    let catalog = catalog(&signed);
    let perms = catalog.get_dict(b"Perms").expect("a direct /Perms");
    assert_eq!(perms.len(), 1);
    assert_eq!(perms.get_ref(b"DocMDP"), Some(sig));
    // /SigFlags 3 as in M3 (no field was signed yet).
    let acroform = catalog.get_ref(b"AcroForm").unwrap();
    let Object::Dict(acroform) = object(&signed, acroform) else {
        panic!("an AcroForm")
    };
    assert_eq!(acroform.get_int(b"SigFlags"), Some(3));

    // Verification: a sound certification with P = 1 and nothing after it.
    let reports = verify(&signed);
    let r = &reports[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.docmdp, Some(1));
    assert_eq!(r.docmdp_ok, Some(true));
    assert_eq!(r.modification, ModificationLevel::None);
}

#[test]
fn certify_p2_default_writes_p2() {
    assert_eq!(DocMdpPermissions::default(), DocMdpPermissions::FormFilling);
    let signed = certified(&syntax::minimal(), DocMdpPermissions::default());
    let sig = sig_dict_id(&signed, "Signature1");
    let Object::Dict(dict) = object(&signed, sig) else {
        panic!("a signature dictionary")
    };
    let reference = dict.get_array(b"Reference").unwrap()[0]
        .as_dict()
        .unwrap()
        .clone();
    let params = reference.get_dict(b"TransformParams").unwrap();
    assert_eq!(params.get_int(b"P"), Some(2));
    assert!(params.get(b"V").unwrap().is_name(b"1.2"));
    let r = &verify(&signed)[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!((r.docmdp, r.docmdp_ok), (Some(2), Some(true)));

    // P = 3 is written as 3.
    let signed = certified(
        &syntax::minimal(),
        DocMdpPermissions::FormFillingAndAnnotations,
    );
    assert_eq!(verify(&signed)[0].docmdp, Some(3));
}

#[test]
fn certify_p1_then_sign_rejected() {
    let signed = certified(&syntax::minimal(), DocMdpPermissions::NoChanges);
    assert_forbidden(try_sign(&signed, SignatureOptions::new(time())), "P = 1");
    // An existing empty field is refused too.
    let form = certified(&forms::acroform(), DocMdpPermissions::NoChanges);
    let existing = SignatureOptions::new(time())
        .with_field(FieldSpec::new().with_name(Some(forms::INVISIBLE.into())));
    assert_forbidden(try_sign(&form, existing), "P = 1");
}

#[test]
fn certify_twice_rejected() {
    let signed = certified(&syntax::minimal(), DocMdpPermissions::FormFilling);
    assert_forbidden(
        try_sign(&signed, certify(DocMdpPermissions::FormFilling)),
        "rule (a)",
    );
    // A catalog that already has /Perms /DocMDP, with no signed field: refused as well.
    let mut b = PdfBuilder::new();
    b.header("1.7");
    b.obj(
        1,
        0,
        "<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 6 0 R >> >>",
    );
    b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    b.obj(
        3,
        0,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
    );
    b.stream_obj(4, 0, "", b"BT ET", None);
    b.obj(
        6,
        0,
        "<< /Type /Sig /Reference [<< /TransformMethod /DocMDP /TransformParams << /P 2 >> >>] >>",
    );
    b.xref_table(XrefOpts::default());
    b.trailer(format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array("perms-only")
    ))
    .startxref(None)
    .eof();
    let perms_only = b.build();
    let err = try_sign(&perms_only, certify(DocMdpPermissions::FormFilling)).unwrap_err();
    assert!(matches!(err, Error::DocMdpForbids(_)), "{err}");
    assert!(err.to_string().contains("/Perms /DocMDP"), "{err}");
}

#[test]
fn certify_after_approval_rejected() {
    let approved = sign_default(&syntax::minimal(), &rsa2048());
    assert_forbidden(
        try_sign(&approved, certify(DocMdpPermissions::FormFilling)),
        "rule (a)",
    );
    // Even into another, empty field: the certification must be the first signature.
    let form = sign_with(
        &forms::acroform(),
        &rsa2048(),
        SignatureOptions::new(time())
            .with_field(FieldSpec::new().with_name(Some(forms::INVISIBLE.into()))),
    );
    let into_visible = certify(DocMdpPermissions::FormFilling).with_field(
        FieldSpec::new()
            .with_name(Some(forms::VISIBLE.into()))
            .with_mode(FieldMode::ExistingOnly),
    );
    let result = try_sign(&form, into_visible);
    assert_forbidden(result, "\"Invisible\" is signed already");
}

#[test]
fn certify_after_doc_timestamp_rejected() {
    let path = repo().join("fixtures/sign/pdf/pyhanko-doc-timestamp.pdf");
    let stamped = std::fs::read(&path).unwrap();
    assert_forbidden(
        try_sign(&stamped, certify(DocMdpPermissions::NoChanges)),
        "rule (a)",
    );
}

#[test]
fn certify_p2_new_visible_field_refused() {
    for p in [
        DocMdpPermissions::FormFilling,
        DocMdpPermissions::FormFillingAndAnnotations,
    ] {
        let signed = certified(&syntax::minimal(), p);
        let visible = SignatureOptions::new(time()).with_appearance(Some(
            SignatureAppearance::new(Rect::new(72.0, 600.0, 272.0, 660.0)),
        ));
        assert_forbidden(try_sign(&signed, visible.clone()), "rule (b)");
        // The two-phase flow refuses it the same way, before anything is signed.
        let signer = rsa2048();
        let req = PrepareRequest::new(
            signer.certificate_chain().to_vec(),
            signer.algorithm(),
            time(),
        )
        .with_options(visible);
        let err = prepare(&open(&signed), &req).unwrap_err();
        assert!(matches!(err, Error::DocMdpForbids(_)), "{err}");
    }
    // On a document that is not certified, the same visible signature is made.
    let visible = SignatureOptions::new(time()).with_appearance(Some(SignatureAppearance::new(
        Rect::new(72.0, 600.0, 272.0, 660.0),
    )));
    let signed = try_sign(&syntax::minimal(), visible).unwrap();
    let r = &verify(&signed)[0];
    assert!(r.is_valid(), "{}", summary(r));
}

#[test]
fn certify_p2_then_approval_ok() {
    let certified = certified(&syntax::minimal(), DocMdpPermissions::FormFilling);
    let approved = sign_with(
        &certified,
        &p256(),
        SignatureOptions::new(time())
            .with_field(FieldSpec::new().with_name(Some("Approval".into()))),
    );
    let reports = verify(&approved);
    assert_eq!(reports.len(), 2);
    let (certification, approval) = (&reports[0], &reports[1]);
    assert!(certification.is_valid(), "{}", summary(certification));
    assert_eq!(certification.docmdp, Some(2));
    assert_eq!(
        certification.docmdp_ok,
        Some(true),
        "{:?}",
        certification.warnings
    );
    assert_eq!(certification.modification, ModificationLevel::FormFilling);
    assert!(certification.is_acceptable(ModificationLevel::FormFilling));
    // The approval: no declaration of its own; P = 2 is in force, nothing came after it.
    assert!(approval.is_valid(), "{}", summary(approval));
    assert_eq!(approval.docmdp, None);
    assert_eq!(approval.docmdp_ok, Some(true));
    assert_eq!(approval.modification, ModificationLevel::None);
}

#[test]
fn certify_p2_existing_visible_field_signed_ok() {
    // The certification in a new invisible field, then an approval in the existing empty
    // visible field `Visible` (pyHanko probe `p2_existing_visible_signed`: FORM_FILLING, True).
    let certified = certified(&forms::acroform(), DocMdpPermissions::FormFilling);
    let options = SignatureOptions::new(time()).with_field(
        FieldSpec::new()
            .with_name(Some(forms::VISIBLE.into()))
            .with_mode(FieldMode::ExistingOnly),
    );
    let approved = sign_with(&certified, &p256(), options);
    let reports = verify(&approved);
    let certification = reports
        .iter()
        .find(|r| r.docmdp.is_some())
        .expect("the certification");
    assert!(certification.is_valid(), "{}", summary(certification));
    assert_eq!(certification.modification, ModificationLevel::FormFilling);
    assert_eq!(
        certification.docmdp_ok,
        Some(true),
        "{:?}",
        certification.warnings
    );
    let approval = reports
        .iter()
        .find(|r| r.field_name.as_deref() == Some(forms::VISIBLE))
        .unwrap();
    assert!(approval.is_valid(), "{}", summary(approval));
}

/// `minimal` with a catalog `/Perms` that holds a usage-rights signature `/UR3` (an Adobe Reader
/// extensions signature), direct or (`indirect`) as object 6.
fn with_ur3(indirect: bool) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.7");
    let perms = if indirect {
        "6 0 R"
    } else {
        "<< /UR3 7 0 R >>"
    };
    b.obj(
        1,
        0,
        format!("<< /Type /Catalog /Pages 2 0 R /Perms {perms} >>"),
    );
    b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    b.obj(
        3,
        0,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R \
         /Resources << /Font << /F1 5 0 R >> >> >>",
    );
    b.stream_obj(
        4,
        0,
        "",
        b"BT /F1 24 Tf 72 720 Td (Reader extended) Tj ET",
        None,
    );
    b.obj(
        5,
        0,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    );
    b.obj(6, 0, "<< /UR3 7 0 R >>");
    b.obj(
        7,
        0,
        "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached \
         /Reference [<< /TransformMethod /UR3 /TransformParams << /Type /TransformParams \
         /V /2.2 /Document [/FullSave] >> >>] >>",
    );
    b.xref_table(XrefOpts::default());
    b.trailer(format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array("ur3")
    ))
    .startxref(None)
    .eof();
    b.build()
}

#[test]
fn certify_keeps_ur3_with_warning() {
    let source = with_ur3(false);
    let signer = rsa2048();
    let req = PrepareRequest::new(
        signer.certificate_chain().to_vec(),
        signer.algorithm(),
        time(),
    )
    .with_options(certify(DocMdpPermissions::FormFilling));
    let prepared = prepare(&open(&source), &req).unwrap();
    assert!(
        prepared
            .warnings()
            .iter()
            .any(|w| w.contains("usage-rights signature will no longer validate")),
        "{:?}",
        prepared.warnings()
    );
    let signed = certified(&source, DocMdpPermissions::FormFilling);
    let sig = sig_dict_id(&signed, "Signature1");
    let perms = catalog(&signed).get_dict(b"Perms").unwrap().clone();
    assert_eq!(perms.get_ref(b"UR3"), Some(ObjectId::new(7, 0)), "kept");
    assert_eq!(perms.get_ref(b"DocMDP"), Some(sig));
}

#[test]
fn certify_indirect_perms_updated() {
    let source = with_ur3(true);
    let signed = certified(&source, DocMdpPermissions::NoChanges);
    let sig = sig_dict_id(&signed, "Signature1");
    // The catalog still refers to the /Perms object, which was edited.
    let catalog = catalog(&signed);
    assert_eq!(catalog.get_ref(b"Perms"), Some(ObjectId::new(6, 0)));
    let Object::Dict(perms) = object(&signed, ObjectId::new(6, 0)) else {
        panic!("the /Perms dictionary")
    };
    assert_eq!(perms.get_ref(b"DocMDP"), Some(sig));
    assert_eq!(perms.get_ref(b"UR3"), Some(ObjectId::new(7, 0)));
    // The update lists object 6.
    let doc = open(&signed);
    let newest = doc.store().revisions().len() - 1;
    let listed = doc.store().revision_entries(newest).unwrap();
    assert!(listed.iter().any(|(num, _)| *num == 6));
    let r = &verify(&signed)[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.docmdp, Some(1));
}

#[test]
fn certification_with_an_appearance_allowed() {
    // Rule (c): the certifier's own field may be visible (M4 brief §4.6).
    let options = certify(DocMdpPermissions::FormFilling).with_appearance(Some(
        SignatureAppearance::new(Rect::new(72.0, 600.0, 272.0, 660.0)),
    ));
    let signed = try_sign(&syntax::minimal(), options).unwrap();
    let r = &verify(&signed)[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.docmdp, Some(2));
    assert_eq!(r.docmdp_ok, Some(true));
    let doc = open(&signed);
    let field = folioxide_sign::field::signature_fields(&doc).unwrap()[0]
        .field
        .unwrap();
    let widget = object(&signed, field);
    let widget = widget.as_dict().unwrap();
    assert!(widget.get_dict(b"AP").unwrap().get_ref(b"N").is_some());
    assert_eq!(
        widget.get(b"Rect"),
        Some(&Rect::new(72.0, 600.0, 272.0, 660.0).to_object())
    );
    // An approval in a new visible field is then refused (D-3), an invisible one is not.
    let visible = SignatureOptions::new(time())
        .with_field(FieldSpec::new().with_name(Some("Approval".into())))
        .with_appearance(Some(SignatureAppearance::new(Rect::new(
            72.0, 500.0, 272.0, 560.0,
        ))));
    assert_forbidden(try_sign(&signed, visible), "rule (b)");
}

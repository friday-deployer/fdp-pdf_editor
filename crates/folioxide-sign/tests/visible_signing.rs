#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Visible signatures (M4 brief §4.7, §6.2 "Visible"; DECISIONS D13 D-16, D-17, D-18): the
//! widget and its appearance stream, rotated pages, the text layout, the JPEG image, existing
//! fields, the rect checks, what a later signature makes of a visible one, determinism, and a
//! visible B-T certification in one signature.

mod sign_support;

use folioxide_content::standard14::Standard14Font as Metrics;
use folioxide_model::Rect;
use folioxide_sign::Error;
use folioxide_sign::appearance::{AppearanceText, SignatureAppearance};
use folioxide_sign::docmdp::DocMdpPermissions;
use folioxide_sign::field::{FieldMode, FieldSpec};
use folioxide_sign::prepare::{PrepareRequest, SignatureOptions, prepare};
use folioxide_sign::report::{ModificationLevel, PadesLevel};
use folioxide_sign::signer::Signer;
use folioxide_syntax::{ErrorCode, Object, XrefEntry};
use folioxide_testkit::fixtures::{forms, syntax};
use sign_support::corpus::change_classes;
use sign_support::visible::*;
use sign_support::*;

/// Signs `source` with RSA-2048 and `options`; the error when signing is refused.
fn try_sign(source: &[u8], options: SignatureOptions) -> Result<Vec<u8>, Error> {
    let signer = rsa2048();
    folioxide_sign::sign::sign(
        &open(source),
        &folioxide_sign::sign::SignRequest::new(&signer, time()).with_options(options),
    )
}

/// Prepares (phase 1) a signature of `source` by RSA-2048 with `options`.
fn prepared(
    source: &[u8],
    options: SignatureOptions,
) -> folioxide_sign::prepare::PreparedSignature {
    let signer = rsa2048();
    let req = PrepareRequest::new(
        signer.certificate_chain().to_vec(),
        signer.algorithm(),
        time(),
    )
    .with_options(options);
    prepare(&open(source), &req).unwrap()
}

/// The keys of `dict`, in order.
fn keys(dict: &folioxide_syntax::Dict) -> Vec<String> {
    dict.keys()
        .map(|k| String::from_utf8_lossy(k.as_bytes()).into_owned())
        .collect()
}

/// The numbers of the array `value`.
fn numbers(value: &Object) -> Vec<f64> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_f64().unwrap())
        .collect()
}

/// Asserts that `result` failed with `code`, and returns the message.
fn refused(result: Result<Vec<u8>, Error>, code: ErrorCode) -> String {
    match result {
        Err(err) => {
            assert_eq!(err.code(), code, "{err}");
            err.to_string()
        }
        Ok(_) => panic!("expected {code:?}, the signature was made"),
    }
}

#[test]
fn visible_signature_has_ap_and_rect() {
    let source = syntax::minimal();
    let signed = sign_with(&source, &rsa2048(), visible_at(rect()));
    let r = &verify(&signed)[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.trusted, Some(true));

    // The merged field and widget: M3's keys, a real /Rect and /AP last; no /MK upright.
    let (widget_id, widget) = field(&signed, "Signature1");
    assert_eq!(
        keys(&widget),
        ["Type", "Subtype", "FT", "T", "V", "F", "Rect", "P", "AP"]
    );
    assert_eq!(widget.get(b"F"), Some(&Object::Int(132)));
    assert_eq!(numbers(widget.get(b"Rect").unwrap()), RECT);

    // /AP /N: an indirect form XObject of the rect's size, with its own resources.
    let (form_id, form, content) = normal_appearance(&signed, &widget);
    assert!(form.dict.is_type(b"XObject"));
    assert_eq!(form.dict.get_name(b"Subtype").unwrap(), "Form");
    assert_eq!(
        numbers(form.dict.get(b"BBox").unwrap()),
        [0.0, 0.0, 200.0, 60.0]
    );
    assert!(
        form.dict.get(b"Matrix").is_none(),
        "identity on an upright page"
    );
    let font_id = resource(&form, b"Font", b"F1");
    let doc = open(&signed);
    let font = doc.store().resolve(font_id).unwrap();
    let font = font.as_dict().unwrap();
    assert!(font.is_type(b"Font"));
    assert_eq!(font.get_name(b"Subtype").unwrap(), "Type1");
    assert_eq!(font.get_name(b"BaseFont").unwrap(), "Helvetica");
    assert_eq!(font.get_name(b"Encoding").unwrap(), "WinAnsiEncoding");
    assert_eq!(font.get_array(b"Widths").unwrap().len(), 224);
    // §9.6.2.2 (PDF 2.0): an indirect font descriptor, from the AFM metrics, no font program.
    let descriptor = doc
        .store()
        .resolve(
            font.get_ref(b"FontDescriptor")
                .expect("an indirect /FontDescriptor"),
        )
        .unwrap();
    let descriptor = descriptor.as_dict().unwrap();
    assert!(descriptor.is_type(b"FontDescriptor"));
    assert_eq!(descriptor.get_name(b"FontName").unwrap(), "Helvetica");
    assert_eq!(descriptor.get_int(b"Flags"), Some(32));
    assert_eq!(descriptor.get_int(b"Ascent"), Some(718));
    assert_eq!(descriptor.get_int(b"Descent"), Some(-207));
    assert_eq!(descriptor.get_int(b"StemV"), Some(88));
    for key in [b"FontFile".as_slice(), b"FontFile2", b"FontFile3"] {
        assert!(!descriptor.contains_key(key), "not embedded");
    }
    // The decoded content: /F1 … Tf and the signer's name in WinAnsi bytes.
    let text = String::from_utf8_lossy(&content);
    assert!(text.contains("/F1 ") && text.contains(" Tf\n"), "{text}");
    let shown = shown_strings(&content);
    assert_eq!(
        shown[0],
        b"Digitally signed by Folioxide Test Signer RSA-2048"
    );
    assert_eq!(shown[1], b"Date: 2026-10-10 12:00:00 +00:00");
    assert_eq!(shown.len(), 2);

    // The page's /Annots gained the widget; everything is in the signature's own update,
    // uncompressed (an incremental update without object streams).
    let page = doc.page(0).unwrap().object().unwrap();
    let annots = page
        .as_dict()
        .unwrap()
        .get_array(b"Annots")
        .unwrap()
        .to_vec();
    assert_eq!(annots.last().and_then(Object::as_ref), Some(widget_id));
    let store = doc.store();
    assert_eq!(store.revisions().len(), 2);
    let listed = store.revision_entries(1).unwrap();
    for id in [widget_id, form_id, font_id, r_sig(&signed)] {
        let entry = listed.iter().find(|(num, _)| *num == id.num);
        assert!(
            matches!(entry, Some((_, XrefEntry::InFile { .. }))),
            "{id} in the newest revision, in the file"
        );
    }
}

/// The signature dictionary of `Signature1`.
fn r_sig(pdf: &[u8]) -> folioxide_syntax::ObjectId {
    let (_, widget) = field(pdf, "Signature1");
    widget.get_ref(b"V").unwrap()
}

#[test]
fn visible_signature_rotated_page_matrix() {
    let source = forms::rotated_pages();
    // §4.7: /Matrix by rotation, with (W, H) the visual size.
    for (page, rotate, matrix) in [
        (1usize, 90i64, [0.0, 1.0, -1.0, 0.0, 200.0, 0.0]),
        (2, 180, [-1.0, 0.0, 0.0, -1.0, 200.0, 60.0]),
        (3, 270, [0.0, -1.0, 1.0, 0.0, 0.0, 60.0]),
    ] {
        let options = visible_at(rect()).with_field(FieldSpec::new().with_page(page));
        let signed = sign_with(&source, &rsa2048(), options);
        let r = &verify(&signed)[0];
        assert!(r.is_valid(), "{rotate}: {}", summary(r));
        let (_, widget) = field(&signed, "Signature1");
        assert_eq!(numbers(widget.get(b"Rect").unwrap()), RECT, "{rotate}");
        assert_eq!(
            widget.get_dict(b"MK").and_then(|mk| mk.get(b"R")),
            Some(&Object::Int(rotate))
        );
        let (_, form, _) = normal_appearance(&signed, &widget);
        let bbox = numbers(form.dict.get(b"BBox").unwrap());
        let m = numbers(form.dict.get(b"Matrix").unwrap());
        assert_eq!(m, matrix, "{rotate}");
        if rotate == 180 {
            assert_eq!(bbox, [0.0, 0.0, 200.0, 60.0]);
        } else {
            assert_eq!(bbox, [0.0, 0.0, 60.0, 200.0], "{rotate}: (W, H) = (h, w)");
        }
        // §12.5.5: the transformed BBox is exactly the rect's size (step b only translates).
        let corners = [
            (bbox[0], bbox[1]),
            (bbox[2], bbox[1]),
            (bbox[0], bbox[3]),
            (bbox[2], bbox[3]),
        ]
        .map(|(x, y)| (m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]));
        let xs = corners.map(|c| c.0);
        let ys = corners.map(|c| c.1);
        let span = |v: [f64; 4]| {
            v.iter().copied().fold(f64::MIN, f64::max) - v.iter().copied().fold(f64::MAX, f64::min)
        };
        assert_eq!((span(xs), span(ys)), (200.0, 60.0), "{rotate}");
    }
    // A rect that is tall in user space reads 200 x 60 on a page turned by 90 degrees: the
    // form's visual size is the rect's, swapped, so the default text fits at a readable size.
    let [a, b, c, d] = TALL_RECT;
    let options = visible_at(Rect::new(a, b, c, d)).with_field(FieldSpec::new().with_page(1));
    let signed = sign_with(&source, &rsa2048(), options);
    let (_, widget) = field(&signed, "Signature1");
    let (_, form, content) = normal_appearance(&signed, &widget);
    assert_eq!(
        numbers(form.dict.get(b"BBox").unwrap()),
        [0.0, 0.0, 200.0, 60.0]
    );
    assert_eq!(
        numbers(form.dict.get(b"Matrix").unwrap()),
        [0.0, 1.0, -1.0, 0.0, 60.0, 0.0]
    );
    assert!(shown_strings(&content)[0].ends_with(b"RSA-2048"));
    // Page 0 (upright): no /MK, no /Matrix.
    let signed = sign_with(&source, &rsa2048(), visible_at(rect()));
    let (_, widget) = field(&signed, "Signature1");
    assert!(widget.get(b"MK").is_none());
}

#[test]
fn visible_signature_text_fits_rect() {
    let options = visible_at(Rect::new(300.0, 100.0, 450.0, 140.0))
        .with_reason(Some("I approve this document".into()))
        .with_location(Some("Berlin".into()));
    let prepared = prepared(&syntax::minimal(), options);
    assert!(prepared.warnings().is_empty(), "{:?}", prepared.warnings());
    let (_, widget) = field(prepared.pdf(), "Signature1");
    let (_, _, content) = normal_appearance(prepared.pdf(), &widget);
    let size = font_size(&content);
    assert!((4.0..=12.0).contains(&size), "{size}");
    let shown = shown_strings(&content);
    assert_eq!(shown.len(), 4, "name, date, reason, location");
    // p = min(2, 150/20, 40/20) = 2: every line fits in the 146-point text width and the
    // four lines in the 36-point height.
    for line in &shown {
        assert!(
            Metrics::Helvetica.text_width(line, size) <= 146.0 + 1e-9,
            "{line:?}"
        );
        assert!(!line.contains(&0x85), "nothing was cut");
    }
    assert!(4.0 * 1.2 * size <= 36.0 + 1e-9, "{size}");
}

#[test]
fn visible_signature_long_name_truncated_with_warning() {
    let long = "Folioxide Test Signer with a remarkably long name".repeat(3);
    let options = visible_at(Rect::new(300.0, 100.0, 400.0, 115.0)).with_name(Some(long));
    let prepared = prepared(&syntax::minimal(), options);
    assert!(
        prepared.warnings().iter().any(|w| w.contains("shortened")),
        "{:?}",
        prepared.warnings()
    );
    let (_, widget) = field(prepared.pdf(), "Signature1");
    let (_, _, content) = normal_appearance(prepared.pdf(), &widget);
    assert_eq!(font_size(&content), 4.0);
    let first = &shown_strings(&content)[0];
    assert_eq!(first.last(), Some(&0x85), "ends with WinAnsi ellipsis");
    assert!(first.starts_with(b"Digitally signed by Folioxide"));
    // p = min(2, 100/20, 15/20) = 0.75: the cut line fits the 98.5-point text width.
    assert!(Metrics::Helvetica.text_width(first, 4.0) <= 98.5 + 1e-9);
    // The prepared signature still finishes and verifies.
    let signer = rsa2048();
    let value = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let signed = prepared.finish(&value).unwrap();
    assert!(verify(&signed)[0].is_valid());
}

#[test]
fn visible_signature_non_win_ansi_replaced_with_warning() {
    let options = visible_at(rect()).with_name(Some("Łukasz Żółć".into()));
    let prepared = prepared(&syntax::minimal(), options);
    assert!(
        prepared.warnings().iter().any(|w| {
            w == "4 characters cannot be shown with the standard 14 fonts (embedded fonts: M7)"
        }),
        "{:?}",
        prepared.warnings()
    );
    let (_, widget) = field(prepared.pdf(), "Signature1");
    let (_, _, content) = normal_appearance(prepared.pdf(), &widget);
    // Ł, Ż, ł and ć have no WinAnsi code (D-16); ó is 0xF3.
    assert_eq!(
        shown_strings(&content)[0],
        b"Digitally signed by ?ukasz ?\xF3??".to_vec()
    );
}

#[test]
fn visible_signature_image_left_keeps_aspect() {
    let jpeg = image("gray-baseline.jpg");
    let options = SignatureOptions::new(time()).with_appearance(Some(
        SignatureAppearance::new(rect()).with_image(Some(jpeg.clone())),
    ));
    let signed = sign_with(&syntax::minimal(), &p256(), options);
    assert!(verify(&signed)[0].is_valid());
    let (_, widget) = field(&signed, "Signature1");
    let (_, form, content) = normal_appearance(&signed, &widget);
    let image_id = resource(&form, b"XObject", b"Im1");
    let doc = open(&signed);
    let object = doc.store().resolve(image_id).unwrap();
    let stream = object.as_stream().unwrap();
    assert_eq!(stream.dict.get_name(b"Subtype").unwrap(), "Image");
    assert_eq!(stream.dict.get(b"Width"), Some(&Object::Int(85)));
    assert_eq!(stream.dict.get(b"Height"), Some(&Object::Int(110)));
    assert_eq!(stream.dict.get_name(b"ColorSpace").unwrap(), "DeviceGray");
    assert_eq!(stream.dict.get_name(b"Filter").unwrap(), "DCTDecode");
    // DCT passthrough (D-17): the JPEG bytes unchanged.
    assert_eq!(
        doc.store().raw_stream_data(stream).unwrap().as_ref(),
        jpeg.as_slice()
    );
    // `w 0 0 h x y cm /Im1 Do`: the aspect ratio kept, vertically centred in the 60-point box.
    let text = String::from_utf8_lossy(&content);
    let cm = text.lines().find(|l| l.ends_with(" cm")).unwrap();
    let m: Vec<f64> = cm.split(' ').take(6).map(|v| v.parse().unwrap()).collect();
    assert!((m[0] / m[3] - 85.0 / 110.0).abs() < 1e-6, "{cm}");
    assert_eq!((m[1], m[2]), (0.0, 0.0));
    assert!((m[5] - (60.0 - m[3]) / 2.0).abs() < 1e-6, "{cm}");
    assert!(text.contains("/Im1 Do"), "{text}");
    // The text starts right of the column: x = p + iw + p.
    let td = text.lines().find(|l| l.ends_with(" Td")).unwrap();
    let x: f64 = td.split(' ').next().unwrap().parse().unwrap();
    assert!((x - (2.0 + m[0] + 2.0)).abs() < 1e-6, "{td}");
}

#[test]
fn visible_signature_existing_field_rect_used() {
    let existing = |rect: Option<Rect>| {
        SignatureOptions::new(time())
            .with_field(
                FieldSpec::new()
                    .with_name(Some(forms::VISIBLE.into()))
                    .with_mode(FieldMode::ExistingOnly),
            )
            .with_appearance(Some(
                SignatureAppearance::for_existing_field().with_rect(rect),
            ))
    };
    let source = forms::acroform();
    let (_, before) = field(&source, forms::VISIBLE);
    for rect in [None, Some(Rect::new(500.0, 160.0, 300.0, 100.0))] {
        let signed = sign_with(&source, &rsa2048(), existing(rect));
        let r = &verify(&signed)[0];
        assert!(r.is_valid(), "{}", summary(r));
        let (_, widget) = field(&signed, forms::VISIBLE);
        // D-18: the /Rect (and every other key) unchanged; only /V and /AP are new.
        assert_eq!(widget.get(b"Rect"), before.get(b"Rect"));
        let mut expected = keys(&before);
        expected.extend(["V".to_owned(), "AP".to_owned()]);
        assert_eq!(keys(&widget), expected);
        let (_, form, _) = normal_appearance(&signed, &widget);
        assert_eq!(
            numbers(form.dict.get(b"BBox").unwrap()),
            [0.0, 0.0, 200.0, 60.0]
        );
    }
}

#[test]
fn visible_existing_field_rect_mismatch_rejected() {
    let options = SignatureOptions::new(time())
        .with_field(FieldSpec::new().with_name(Some(forms::VISIBLE.into())))
        .with_appearance(Some(SignatureAppearance::new(Rect::new(
            300.0, 100.0, 500.0, 161.0,
        ))));
    let message = refused(
        try_sign(&forms::acroform(), options),
        ErrorCode::InvalidArgument,
    );
    assert!(message.contains("never changed"), "{message}");
    // An existing field without an area cannot show an appearance.
    let options = SignatureOptions::new(time())
        .with_field(FieldSpec::new().with_name(Some(forms::INVISIBLE.into())))
        .with_appearance(Some(SignatureAppearance::for_existing_field()));
    let message = refused(
        try_sign(&forms::acroform(), options),
        ErrorCode::InvalidArgument,
    );
    assert!(message.contains("no widget area"), "{message}");
    // A new field needs a rect.
    let options = SignatureOptions::new(time())
        .with_appearance(Some(SignatureAppearance::for_existing_field()));
    refused(
        try_sign(&syntax::minimal(), options),
        ErrorCode::InvalidArgument,
    );
}

#[test]
fn visible_rect_beyond_the_geometry_magnitude_rejected() {
    // M4 QA round 4, finding 13 (api_probe3 `rect-1e15-huge`), manager ruling R-21: a rect
    // whose coordinates, width or height exceed ±10^5 would make the signer write a widget and
    // an appearance the verifier makes Other for any earlier signature (PDFium maps them in
    // single precision and paints elsewhere), so it is refused.
    for bad in [
        Rect::new(-1e15, -1e15, 1e15, 1e15),
        Rect::new(60.0, -1e9, 260.0, 260.0),
        Rect::new(-6e4, 100.0, 6e4, 160.0),
        Rect::new(0.0, 100.0, 100_001.0, 160.0),
    ] {
        let message = refused(
            try_sign(&syntax::minimal(), visible_at(bad)),
            ErrorCode::InvalidArgument,
        );
        assert!(message.contains("beyond"), "{bad:?}: {message}");
    }
    // At the bound the signature is made, and an earlier signature stays FormFilling for it.
    let once = sign_with(
        &syntax::minimal(),
        &rsa2048(),
        SignatureOptions::new(time()),
    );
    let twice = sign_with(
        &once,
        &rsa2048(),
        visible_at(Rect::new(0.0, 0.0, 1e5, 100.0))
            .with_field(FieldSpec::new().with_name(Some("Wide".into()))),
    );
    let first = verify(&twice)
        .into_iter()
        .find(|r| r.field_name.as_deref() == Some("Signature1"))
        .unwrap();
    assert_eq!(
        first.modification,
        folioxide_sign::report::ModificationLevel::FormFilling,
        "{:?}",
        first.warnings
    );
}

#[test]
fn visible_existing_hidden_field_rejected() {
    // Manager ruling R-3 (M4 QA round 1): an existing empty field whose widget is Hidden or
    // NoView (or drawn at a fixed size or unrotated) cannot show a visible signature: refused,
    // and signing it invisibly is still fine.
    for (flags, name) in [
        (6, "Hidden"),
        (36, "NoView"),
        (20, "NoRotate"),
        (12, "NoZoom"),
    ] {
        let source = forms::with_incremental(&forms::acroform(), |store| {
            let id = folioxide_syntax::ObjectId::new(forms::ids::VISIBLE, 0);
            let mut dict = store.resolve(id).ok()?.as_dict()?.clone();
            dict.insert("F", folioxide_syntax::Object::Int(flags));
            store.set(id, folioxide_syntax::Object::Dict(dict)).ok()
        })
        .unwrap();
        let options = SignatureOptions::new(time())
            .with_field(FieldSpec::new().with_name(Some(forms::VISIBLE.into())))
            .with_appearance(Some(SignatureAppearance::for_existing_field()));
        let message = refused(try_sign(&source, options), ErrorCode::InvalidArgument);
        assert!(message.contains(name), "/F {flags}: {message}");
        let options = SignatureOptions::new(time())
            .with_field(FieldSpec::new().with_name(Some(forms::VISIBLE.into())));
        assert!(try_sign(&source, options).is_ok(), "/F {flags} invisibly");
    }
}

#[test]
fn visible_existing_separate_widget_unsupported() {
    let source = forms::with_split_signature_field(&forms::acroform()).unwrap();
    let options = SignatureOptions::new(time())
        .with_field(FieldSpec::new().with_name(Some(forms::SPLIT.into())))
        .with_appearance(Some(SignatureAppearance::for_existing_field()));
    let message = refused(try_sign(&source, options), ErrorCode::Unsupported);
    assert!(message.contains("/Kids"), "{message}");
    // Signed invisibly, the same field is fine (M3).
    let options = SignatureOptions::new(time())
        .with_field(FieldSpec::new().with_name(Some(forms::SPLIT.into())));
    let signed = try_sign(&source, options).unwrap();
    assert!(verify(&signed)[0].is_valid());
}

#[test]
fn visible_rect_outside_crop_box_rejected() {
    for rect in [
        Rect::new(700.0, 800.0, 800.0, 900.0),
        Rect::new(-200.0, -200.0, -100.0, -100.0),
    ] {
        let message = refused(
            try_sign(&syntax::minimal(), visible_at(rect)),
            ErrorCode::InvalidArgument,
        );
        assert!(message.contains("crop box"), "{message}");
    }
    let mut nan = rect();
    nan.urx = f64::NAN;
    refused(
        try_sign(&syntax::minimal(), visible_at(nan)),
        ErrorCode::InvalidArgument,
    );
}

#[test]
fn visible_rect_zero_area_rejected() {
    for rect in [
        Rect::new(300.0, 100.0, 300.0, 160.0),
        Rect::new(300.0, 100.0, 500.0, 100.0),
        Rect::new(300.0, 100.0, 300.000_000_000_01, 100.000_000_000_01),
    ] {
        let message = refused(
            try_sign(&syntax::minimal(), visible_at(rect)),
            ErrorCode::InvalidArgument,
        );
        assert!(message.contains("no area"), "{message}");
    }
}

#[test]
fn visible_then_second_signature_formfilling() {
    // A later signature after our visible one: form filling for it (a new signature field).
    let first = sign_with(&syntax::minimal(), &rsa2048(), visible_at(rect()));
    let second = sign_with(&first, &p256(), SignatureOptions::new(time()));
    let reports = verify(&second);
    assert_eq!(reports.len(), 2);
    assert!(reports[0].is_valid() && reports[1].is_valid());
    assert_eq!(reports[0].modification, ModificationLevel::FormFilling);
    assert_eq!(reports[0].docmdp_ok, Some(true));

    // Our visible signature after an earlier one: a new visible signature field with its
    // appearance (class `signature`), form filling, as pyHanko says.
    let invisible = sign_with(
        &syntax::minimal(),
        &rsa2048(),
        SignatureOptions::new(time()),
    );
    let visible = sign_with(&invisible, &p256(), visible_at(rect()));
    let reports = verify(&visible);
    assert!(reports[1].is_valid(), "{}", summary(&reports[1]));
    assert_eq!(
        reports[0].modification,
        ModificationLevel::FormFilling,
        "{:?}",
        reports[0].warnings
    );
    assert_eq!(change_classes(&reports[0]), ["signature"]);
    assert!(reports[0].is_acceptable(ModificationLevel::FormFilling));

    // An existing visible field signed with an appearance after a P = 2 certification: form
    // filling, docmdp_ok true (probe p2_existing_visible_signed).
    let certified = sign_with(
        &forms::acroform(),
        &rsa2048(),
        SignatureOptions::new(time()).with_certification(Some(DocMdpPermissions::FormFilling)),
    );
    let existing = SignatureOptions::new(time())
        .with_field(FieldSpec::new().with_name(Some(forms::VISIBLE.into())))
        .with_appearance(Some(SignatureAppearance::for_existing_field()));
    let signed = sign_with(&certified, &p256(), existing);
    let reports = verify(&signed);
    assert_eq!(reports[0].modification, ModificationLevel::FormFilling);
    assert_eq!(
        reports[0].docmdp_ok,
        Some(true),
        "{:?}",
        reports[0].warnings
    );
    assert!(reports[1].is_valid());
}

#[test]
fn sign_visible_is_deterministic() {
    let options = || {
        SignatureOptions::new(time())
            .with_field(FieldSpec::new().with_page(1))
            .with_appearance(Some(
                SignatureAppearance::new(rect())
                    .with_image(Some(image("rgb-baseline.jpg")))
                    .with_border_width(1.0)
                    .with_text(AppearanceText::Lines(vec!["Approved".into(), "€ 5".into()])),
            ))
    };
    let source = forms::rotated_pages();
    let a = prepared(&source, options());
    let b = prepared(&source, options());
    assert_eq!(a.pdf(), b.pdf());
    let one = sign_with(&source, &rsa2048(), options());
    let two = sign_with(&source, &rsa2048(), options());
    assert_eq!(
        one, two,
        "RSA PKCS#1 v1.5 is deterministic, and so is the update"
    );
}

#[test]
fn visible_bt_certified_combined() {
    // P = 2 certification, visible, B-T: one signature.
    let options = visible_at(rect()).with_certification(Some(DocMdpPermissions::FormFilling));
    let signed = sign_bt(&syntax::minimal(), &rsa2048(), options);
    let r = &verify(&signed)[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.docmdp, Some(2));
    assert_eq!(r.docmdp_ok, Some(true));
    assert_eq!(r.pades_level, Some(PadesLevel::BT), "{}", summary(r));
    let token = r.timestamp.as_ref().expect("a signature timestamp");
    assert!(token.intact && token.valid, "{token:?}");
    let (_, widget) = field(&signed, "Signature1");
    assert_eq!(numbers(widget.get(b"Rect").unwrap()), RECT);
    let (_, _, content) = normal_appearance(&signed, &widget);
    // The date is the claimed signing time, never the token's genTime.
    assert_eq!(
        shown_strings(&content)[1],
        b"Date: 2026-10-10 12:00:00 +00:00"
    );
    // A new visible approval on it is refused (D-3), an invisible one is form filling.
    let refused_visible = refused(
        try_sign(&signed, visible_at(Rect::new(72.0, 500.0, 272.0, 560.0))),
        ErrorCode::DocMdpForbids,
    );
    assert!(refused_visible.contains("rule (b)"), "{refused_visible}");
    let approved = sign_with(&signed, &p256(), SignatureOptions::new(time()));
    let reports = verify(&approved);
    assert_eq!(reports[0].modification, ModificationLevel::FormFilling);
    assert_eq!(reports[0].docmdp_ok, Some(true));
}

#[test]
fn visible_prepare_never_panics_on_mutated_documents() {
    // The visible branch reads the document (an existing field's /Rect, /Kids and /P, the pages'
    // /Annots, /Rotate and crop box): seeded mutations of a form and of the rotated pages, then
    // a visible signature in the existing field and in a new one. Errors are fine; panics are not.
    let signer = rsa2048();
    let chain = signer.certificate_chain().to_vec();
    let existing = SignatureOptions::new(time())
        .with_field(FieldSpec::new().with_name(Some(forms::VISIBLE.into())))
        .with_appearance(Some(SignatureAppearance::for_existing_field()));
    let new_field = visible_at(rect()).with_field(FieldSpec::new().with_page(1));
    let mut prepared = 0;
    for (seed, base) in [
        (0x5649_5349, forms::acroform()),
        (0x524f_5441, forms::rotated_pages()),
    ] {
        for mutated in folioxide_testkit::mutate::mutations(&base, seed, 1_000) {
            let Ok(doc) =
                folioxide_model::Document::open(mutated, &folioxide_syntax::OpenOptions::default())
            else {
                continue;
            };
            for options in [&existing, &new_field] {
                let req = PrepareRequest::new(chain.clone(), signer.algorithm(), time())
                    .with_options(options.clone());
                if prepare(&doc, &req).is_ok() {
                    prepared += 1;
                }
            }
        }
    }
    assert!(prepared > 100, "{prepared} mutated documents were prepared");
}

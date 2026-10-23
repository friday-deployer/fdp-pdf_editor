#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! New signature widgets after signing (M4 QA round 1, manager ruling R-3; finding R5) against
//! the `sigfield_*` and `existing_field_*` cases of the attack corpus: a later signer's new
//! widget may carry only the flags signers write (4 or 132: never Hidden, NoZoom, NoRotate,
//! NoView or ToggleNoView), and its appearance must be new form XObjects with a `/BBox`, which
//! viewers clip to the widget's `/Rect`. pyHanko does not look at either, so these cases are
//! stricter than pyHanko (`DELIBERATE_DIFFERENCES`).

mod sign_support;

use folioxide_sign::report::{Coverage, ModificationLevel, SignatureReport};
use sign_support::corpus::{attacked, corpus, our_value, pyhanko_value, signature1};
use sign_support::summary;

/// The report of `Signature1` after `name`: sound over its revision, `Other`, with a warning
/// that names `needle`, and a deliberate row against pyHanko's level.
fn assert_refused(name: &str, needle: &str) -> SignatureReport {
    let r = signature1(&attacked(name));
    let s = summary(&r);
    let base = corpus().into_iter().find(|c| c.name == name).unwrap().base;
    assert!(r.intact && r.signature_valid && r.is_valid(), "{name}: {s}");
    assert_eq!(r.coverage, Coverage::EntireRevision, "{name}: {s}");
    assert_eq!(r.signed_revision, Some(base.signed_revision()), "{name}");
    assert_eq!(
        r.modification,
        ModificationLevel::Other,
        "{name}: {s} {:?}",
        r.warnings
    );
    assert_eq!(r.docmdp_ok, Some(false), "{name}");
    assert!(
        r.warnings.iter().any(|w| w.contains(needle)),
        "{name}: no warning names {needle:?}: {:?}",
        r.warnings
    );
    assert_eq!(our_value(name, "modification"), Some("other"), "{name}");
    assert_ne!(pyhanko_value(name, "modification"), Some("other"), "{name}");
    r
}

// ---- M4 QA round 3, ruling R-12: /Rect numbers that readers read differently ----------------

#[test]
fn attacks_sigfield_rect_integer_overflow() {
    // QA variants R3-h-num-y2-4294967296-03, A3-r3-newsigwidget-rect-y2-2pow32-approval:
    // PDFium reads the integer beyond 32 bits as 0 and paints outside the /Rect.
    assert_refused("sigfield_rect_integer_overflow", "outside ±2147483647");
}

#[test]
fn attacks_sigfield_rect_int32_min() {
    // QA variant A3-r3-newsigwidget-rect-y2-int32-min-approval: -2147483648 is 0 to PDFium.
    assert_refused("sigfield_rect_int32_min", "outside ±2147483647");
}

#[test]
fn attacks_sigfield_rect_zero_padded() {
    // M4 QA round 4, finding 2 (variants R3-i-rect-zero-padded-integer-*): PDFium reads a word
    // of 256 characters or more as 0; a canonical integer has at most 11 characters.
    assert_refused("sigfield_rect_zero_padded", "longer than 11 characters");
}

#[test]
fn attacks_sigfield_rect_zero_padded_x1() {
    // Variants R3-i-rect-zero-padded-x1-*.
    assert_refused("sigfield_rect_zero_padded_x1", "longer than 11 characters");
}

#[test]
fn attacks_sigfield_rect_magnitude() {
    // M4 QA round 4, finding 13: canonical, but beyond ±10^5 (PDFium places it elsewhere;
    // manager ruling R-21).
    assert_refused("sigfield_rect_magnitude", "within ±1e5");
}

#[test]
fn sigfield_rect_magnitudes_qa_tried() {
    // Variants R5w-rect-*: 10^9, 2 × 10^9 and 2^31 − 1 are Other; up to 10^5 a signature
    // field (FormFilling; manager ruling R-21 lowered the bound from 10^7).
    let base = sign_support::corpus::signed_base();
    for (rect, other) in [
        ([60, -1_000_000_000, 260, 260], true),
        ([60, -2_000_000_000, 260, 260], true),
        ([60, 200, 260, -2_147_483_647], true),
        ([60, 200, 260, 10_000_000], true),
        ([60, 200, 260, 100_001], true),
        ([60, 200, 260, 100_000], false),
        ([-100_000, 200, 260, 300], false),
    ] {
        let pdf = folioxide_testkit::fixtures::sign_attacks::sigfield_with_rect(&base, rect)
            .expect("the widget applies");
        let r = signature1(&pdf);
        let want = if other {
            ModificationLevel::Other
        } else {
            ModificationLevel::FormFilling
        };
        assert_eq!(r.modification, want, "{rect:?}: {:?}", r.warnings);
    }
}

#[test]
fn sigfield_rect_zero_padded_at_every_length_qa_tried() {
    // The QA lengths (260, 1,000 and 100,000 zeros; pyHanko cannot read the last, Python's int
    // digit limit), on x1 and on y2, and 12 characters, the first length refused; the control,
    // 11 characters, stays a signature field (FormFilling).
    let base = sign_support::corpus::signed_base();
    for index in [0, 3] {
        for zeros in [260, 1000, 100_000, 9] {
            let pdf = folioxide_testkit::fixtures::sign_attacks::sigfield_rect_padded(
                &base, index, zeros,
            )
            .expect("the padded widget applies");
            let r = signature1(&pdf);
            assert!(r.is_valid(), "{index}/{zeros}: {}", summary(&r));
            assert_eq!(
                r.modification,
                ModificationLevel::Other,
                "{index}/{zeros}: {:?}",
                r.warnings
            );
            assert!(
                r.warnings
                    .iter()
                    .any(|w| w.contains("longer than 11 characters")),
                "{index}/{zeros}: {:?}",
                r.warnings
            );
        }
        let zeros = 8;
        let pdf =
            folioxide_testkit::fixtures::sign_attacks::sigfield_rect_padded(&base, index, zeros)
                .expect("the padded widget applies");
        let r = signature1(&pdf);
        assert_eq!(
            r.modification,
            ModificationLevel::FormFilling,
            "{index}/{zeros}: {:?}",
            r.warnings
        );
    }
}

#[test]
fn attacks_sigfield_rect_multisign() {
    // QA variants R5z-rect-multisign-last, R5z-rect-plusminus: `--341` is -341 to Folioxide and
    // 0 to PDFium; pyHanko cannot read the file (PYHANKO_RAISES).
    let name = "sigfield_rect_multisign";
    let r = signature1(&attacked(name));
    assert!(
        r.intact && r.signature_valid && r.is_valid(),
        "{}",
        summary(&r)
    );
    assert_eq!(r.modification, ModificationLevel::Other, "{:?}", r.warnings);
    assert_eq!(r.docmdp_ok, Some(false));
    assert!(
        r.warnings.iter().any(|w| w.contains("several signs")),
        "{:?}",
        r.warnings
    );
    assert!(sign_support::corpus::pyhanko_raises(name).is_some());
}

#[test]
fn attacks_sigfield_flags_nozoom() {
    assert_refused("sigfield_flags_nozoom", "NoZoom");
}

#[test]
fn attacks_sigfield_flags_hidden() {
    assert_refused("sigfield_flags_hidden", "Hidden");
}

#[test]
fn attacks_sigfield_flags_noview() {
    assert_refused("sigfield_flags_noview", "NoView");
}

#[test]
fn attacks_sigfield_flags_toggle_noview() {
    assert_refused("sigfield_flags_toggle_noview", "ToggleNoView");
}

#[test]
fn attacks_sigfield_invisible_flags_hidden() {
    assert_refused("sigfield_invisible_flags_hidden", "Hidden");
}

#[test]
fn attacks_sigfield_norotate_rotated_page() {
    // QA variant R3-rot90-raw-norotate-flag: poppler paints the widget unrotated, outside its
    // /Rect, on the page turned by 90 degrees.
    assert_refused("sigfield_norotate_rotated_page", "NoRotate");
}

#[test]
fn attacks_sigfield_ap_no_bbox() {
    assert_refused("sigfield_ap_no_bbox", "/BBox");
}

#[test]
fn attacks_sigfield_ap_no_subtype() {
    assert_refused("sigfield_ap_no_subtype", "form XObject");
}

#[test]
fn attacks_sigfield_ap_state_dict() {
    assert_refused("sigfield_ap_state_dict", "appearance states");
}

#[test]
fn attacks_sigfield_ap_page_content() {
    assert_refused("sigfield_ap_page_content", "existing object");
}

#[test]
fn attacks_existing_field_signed_ap_no_bbox() {
    assert_refused("existing_field_signed_ap_no_bbox", "/BBox");
}

#[test]
fn attacks_sigfield_rect_null_entry() {
    // M4 QA round 2, finding 4 (variant R3-rect-first-null): viewers read the null as 0 and
    // paint the appearance elsewhere than the /Rect says.
    assert_refused("sigfield_rect_null_entry", "four finite numbers");
}

#[test]
fn attacks_sigfield_rect_string_entry() {
    assert_refused("sigfield_rect_string_entry", "four finite numbers");
}

#[test]
fn attacks_sigfield_rect_wrong_length() {
    assert_refused("sigfield_rect_wrong_length", "four finite numbers");
}

#[test]
fn attacks_existing_field_signed_flags_norotate() {
    // M4 QA round 2, finding 5 (variant R3-existing-field-norotate-rot90-pyhanko): the existing
    // NoRotate field signed with an appearance on a page rotated by 90.
    assert_refused("existing_field_signed_flags_norotate", "NoRotate");
}

#[test]
fn attacks_existing_field_signed_flags_nozoom() {
    assert_refused("existing_field_signed_flags_nozoom", "NoZoom");
}

#[test]
fn attacks_existing_field_signed_flags_hidden() {
    assert_refused("existing_field_signed_flags_hidden", "Hidden");
}

#[test]
fn attacks_existing_field_signed_flags_noview() {
    assert_refused("existing_field_signed_flags_noview", "NoView");
}

#[test]
fn attacks_existing_field_hidden_signed_invisibly() {
    // The control: the Hidden field signed invisibly (a /V, no appearance): FormFilling, as for
    // pyHanko (QA round 2 checked it on pyHanko-signed files).
    let name = "existing_field_hidden_signed_invisibly";
    let r = signature1(&attacked(name));
    assert!(r.is_valid(), "{name}: {}", summary(&r));
    assert_eq!(
        r.modification,
        ModificationLevel::FormFilling,
        "{name}: {} {:?}",
        summary(&r),
        r.warnings
    );
    assert_eq!(our_value(name, "modification"), None, "equal to pyHanko");
}

#[test]
fn control_new_visible_sig_field_is_form_filling() {
    // The same widget with /F 4 and a form XObject appearance: FormFilling, as for pyHanko.
    let r = signature1(&attacked("shadow_overlay_sig_widget_registered"));
    assert_eq!(
        r.modification,
        ModificationLevel::FormFilling,
        "{}",
        summary(&r)
    );
}

/// Every `sigfield_*` and `existing_field_*` case of the corpus has its test above.
#[test]
fn every_widget_case_is_tested() {
    let source = include_str!("attacks_widgets.rs");
    for case in corpus() {
        if case.name.starts_with("sigfield_") || case.name.starts_with("existing_field_") {
            let test = format!("fn attacks_{}()", case.name);
            assert!(source.contains(&test), "{} has no test", case.name);
        }
    }
}

#[test]
fn attacks_sigfield_ap_tiny_bbox_translate_1e5() {
    // Final fix round 2, findings 2 and 4 (variants R3-k-pdfium-late-bbox-001-*): every number
    // within ±10^5, but a 0.01-unit box scaled by 20,000 onto the widget far from the origin.
    assert_refused("sigfield_ap_tiny_bbox_translate_1e5", "single precision");
}

#[test]
fn attacks_sigfield_ap_matrix_tiny_bbox() {
    // Variants R3-k-pdfium-late-bbox-01-*: a 0.1-unit box.
    assert_refused("sigfield_ap_matrix_tiny_bbox", "single precision");
}

#[test]
fn attacks_sigfield_ap_matrix_small_bbox() {
    // Manager ruling R-21, M4 QA round 5, finding 28 (variants
    // R5v-ap-bbox-1x1-matrix-translate-*): a one-unit /BBox that the /Matrix maps beyond ±10^5.
    assert_refused(
        "sigfield_ap_matrix_small_bbox",
        "mapped through its /Matrix",
    );
}

// ---- final fix round 2, finding 1: a signature field's appearance dictionary used twice -------

/// The report of `Signature1` after `name`, `Other` with a warning naming ruling R-19, like
/// pyHanko (no deliberate row).
fn assert_shared_sig_ap_other(name: &str) -> SignatureReport {
    let r = signature1(&attacked(name));
    let s = summary(&r);
    let base = corpus().into_iter().find(|c| c.name == name).unwrap().base;
    assert!(r.intact && r.signature_valid && r.is_valid(), "{name}: {s}");
    assert_eq!(r.signed_revision, Some(base.signed_revision()), "{name}");
    assert_eq!(
        r.modification,
        ModificationLevel::Other,
        "{name}: {s} {:?}",
        r.warnings
    );
    assert_eq!(r.docmdp_ok, Some(false), "{name}");
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("unsigned signature field") && w.contains("R-19")),
        "{name}: {:?}",
        r.warnings
    );
    assert_eq!(our_value(name, "modification"), None, "equal to pyHanko");
    r
}

/// The report of `Signature1` after `name`: `FormFilling`, as for pyHanko.
fn assert_shared_sig_ap_control(name: &str) {
    let r = signature1(&attacked(name));
    assert!(r.is_valid(), "{name}: {}", summary(&r));
    assert_eq!(
        r.modification,
        ModificationLevel::FormFilling,
        "{name}: {} {:?}",
        summary(&r),
        r.warnings
    );
    assert_eq!(r.docmdp_ok, Some(true), "{name}");
    assert_eq!(our_value(name, "modification"), None, "equal to pyHanko");
}

#[test]
fn attacks_sigfield_ap_dict_shared_signed_next() {
    // Variants R3-k-two-sigfields-shared-ours-then-{ours,pyhanko}: the empty fields Visible and
    // SigB share one indirect /AP dictionary; a later revision signs Visible (keeping it), which
    // pyHanko's SigFieldModificationRule refuses (other).
    assert_shared_sig_ap_other("sigfield_ap_dict_shared_signed_next");
}

#[test]
fn attacks_sigfield_ap_dict_shared_visible_next() {
    // Variant R3-k-two-sigfields-shared-ours-visible-appearance-on-second: the signing revision
    // gives the field an appearance of its own; the old dictionary is shared all the same.
    assert_shared_sig_ap_other("sigfield_ap_dict_shared_visible_next");
}

#[test]
fn attacks_sigfield_ap_dict_shared_cert2_then_second() {
    // Variants R3-k-two-sigfields-shared-cert2-then-{ours,pyhanko}-approval: under a P = 2
    // certification, pyHanko says other and docmdpOk false; so does Folioxide.
    let r = assert_shared_sig_ap_other("sigfield_ap_dict_shared_cert2_then_second");
    assert_eq!(r.docmdp, Some(2));
    assert!(!r.is_acceptable(ModificationLevel::FormFilling));
}

#[test]
fn attacks_sigfield_ap_dict_shared_control_private() {
    // The control: each field has a dictionary of its own (used once): FormFilling.
    assert_shared_sig_ap_control("sigfield_ap_dict_shared_control_private");
}

#[test]
fn attacks_sigfield_ap_dict_shared_unrelated_fill() {
    // The neighbouring control: the shared dictionary stays, but no revision signs either field;
    // pyHanko checks a signature field's /AP only when the field becomes signed (FormFilling).
    assert_shared_sig_ap_control("sigfield_ap_dict_shared_unrelated_fill");
}

#[test]
fn shared_sig_ap_dict_signing_the_second_field_too() {
    // The same rule for the other field of the pair (SigB, which the signed revision lists
    // after Visible), and for a signature that signed one of the pair itself: signing Visible
    // first leaves the dictionary used twice, so signing SigB later is other for it.
    let base = sign_support::corpus::Base::FormSigApDictShared.bytes();
    let second = sign_support::sign_with(
        &base,
        &sign_support::p256(),
        folioxide_sign::prepare::SignatureOptions::new(sign_support::time()).with_field(
            folioxide_sign::field::FieldSpec::new()
                .with_name(Some(
                    folioxide_testkit::fixtures::sign_attacks::SECOND_SIG_FIELD.to_owned(),
                ))
                .with_mode(folioxide_sign::field::FieldMode::ExistingOnly),
        ),
    );
    let r = signature1(&second);
    assert_eq!(r.modification, ModificationLevel::Other, "{:?}", r.warnings);
    // Visible signed by the first signature, SigB by the second.
    let input = folioxide_testkit::fixtures::sign_attacks::form_sig_ap_dict_shared_input(
        &folioxide_testkit::fixtures::forms::acroform(),
    )
    .unwrap();
    let options = |field: &str| {
        folioxide_sign::prepare::SignatureOptions::new(sign_support::time()).with_field(
            folioxide_sign::field::FieldSpec::new()
                .with_name(Some(field.to_owned()))
                .with_mode(folioxide_sign::field::FieldMode::ExistingOnly),
        )
    };
    let first = sign_support::sign_with(
        &input,
        &sign_support::rsa2048(),
        options(folioxide_testkit::fixtures::forms::VISIBLE),
    );
    let both = sign_support::sign_with(
        &first,
        &sign_support::p256(),
        options(folioxide_testkit::fixtures::sign_attacks::SECOND_SIG_FIELD),
    );
    let reports = sign_support::verify_plain(&both);
    let visible = reports
        .iter()
        .find(|r| r.field_name.as_deref() == Some(folioxide_testkit::fixtures::forms::VISIBLE))
        .unwrap();
    assert_eq!(
        visible.modification,
        ModificationLevel::Other,
        "{:?}",
        visible.warnings
    );
    assert!(visible.warnings.iter().any(|w| w.contains("R-19")));
    // Only the first signature: nothing after it.
    let alone = sign_support::verify_plain(&first);
    assert_eq!(alone[0].modification, ModificationLevel::None);
    // Folioxide's signer warns before it signs the second field of the pair (and not the
    // first field of a document that nobody signed yet).
    use folioxide_sign::prepare::{PrepareRequest, prepare};
    use folioxide_sign::signer::Signer;
    let signer = sign_support::p256();
    let warnings = |pdf: &[u8], field: &str| {
        let request = PrepareRequest::new(
            signer.certificate_chain().to_vec(),
            signer.algorithm(),
            sign_support::time(),
        )
        .with_options(options(field));
        prepare(&sign_support::open(pdf), &request)
            .unwrap()
            .warnings()
            .to_vec()
    };
    let second = warnings(
        &first,
        folioxide_testkit::fixtures::sign_attacks::SECOND_SIG_FIELD,
    );
    assert!(
        second
            .iter()
            .any(|w| w.contains("appearance dictionary") && w.contains("\"Visible\"")),
        "{second:?}"
    );
    assert!(
        warnings(&input, folioxide_testkit::fixtures::forms::VISIBLE).is_empty(),
        "nothing signed yet"
    );
}

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The generic form-filling whitelist (M4 brief §5.1, rule V10 (4′)) against the `form_*` cases
//! of the attack corpus (§5.4): one `attacks_<case>` test each, on approval signatures over the
//! `forms::acroform` documents (RSA-2048, our own signer), filled by the generators of
//! `folioxide_testkit::fixtures::sign_attacks`.
//!
//! - **controls**: what pyHanko 0.37 calls `FORM_FILLING`, and Folioxide too;
//! - **stricter**: the §0.1 rows, `Other` for Folioxide where pyHanko says `FORM_FILLING`, each a
//!   `DELIBERATE_DIFFERENCES` row;
//! - **equal-strict**: `Other` for both.

mod sign_support;

use folioxide_sign::report::{Coverage, ModificationLevel, SignatureReport};
use sign_support::corpus::{
    DELIBERATE_DIFFERENCES, attacked, change_classes, corpus, our_value, signature1,
};
use sign_support::summary;

/// The report of `Signature1` after the attack `name`: intact and valid over the revision it
/// signed (the case's base), and modified at `level`.
fn assert_revision(name: &str, level: ModificationLevel) -> SignatureReport {
    let r = signature1(&attacked(name));
    let s = summary(&r);
    let base = corpus().into_iter().find(|c| c.name == name).unwrap().base;
    assert!(r.intact && r.signature_valid, "{name}: {s}");
    assert!(r.is_valid(), "{name}: {s}");
    assert_eq!(r.coverage, Coverage::EntireRevision, "{name}: {s}");
    assert_eq!(r.signed_revision, Some(base.signed_revision()), "{name}");
    assert_eq!(r.modification, level, "{name}: {s} {:?}", r.warnings);
    assert_eq!(r.docmdp, None, "{name}: an approval");
    r
}

/// A control: `FormFilling` (= pyHanko), `docmdp_ok` true under the default P = 2, acceptable
/// at `FormFilling`, and the change classes are `classes`.
fn assert_control(name: &str, classes: &[&str]) {
    let r = assert_revision(name, ModificationLevel::FormFilling);
    assert_eq!(r.docmdp_ok, Some(true), "{name}");
    assert!(r.is_acceptable(ModificationLevel::FormFilling), "{name}");
    assert!(!r.is_acceptable(ModificationLevel::LtaUpdates), "{name}");
    assert_eq!(change_classes(&r), classes, "{name}");
    assert!(
        !DELIBERATE_DIFFERENCES.iter().any(|(c, ..)| *c == name),
        "{name}: a control equals pyHanko"
    );
}

/// `Other`, never acceptable, with a warning that names `needle`.
fn assert_other(name: &str, needle: &str) -> SignatureReport {
    let r = assert_revision(name, ModificationLevel::Other);
    assert_eq!(r.docmdp_ok, Some(false), "{name}");
    assert!(!r.is_acceptable(ModificationLevel::Annotations), "{name}");
    assert!(
        r.warnings.iter().any(|w| w.contains(needle)),
        "{name}: no warning names {needle:?}: {:?}",
        r.warnings
    );
    r
}

/// A stricter case: `Other` (ours) where pyHanko says `formFilling`, from the deliberate table.
fn assert_stricter(name: &str, needle: &str) {
    assert_other(name, needle);
    assert_eq!(our_value(name, "modification"), Some("other"), "{name}");
    assert_eq!(
        sign_support::corpus::pyhanko_value(name, "modification"),
        Some("formFilling"),
        "{name}"
    );
}

/// An equal-strict case: `Other` for both, so no deliberate row.
fn assert_equal_strict(name: &str, needle: &str) {
    assert_other(name, needle);
    assert_eq!(our_value(name, "modification"), None, "{name}");
}

// ---- controls: FormFilling for Folioxide and pyHanko ------------------------------------------

#[test]
fn attacks_form_fill_text_value_and_ap() {
    assert_control("form_fill_text_value_and_ap", &["formFill"]);
}

#[test]
fn attacks_form_fill_text_value_only() {
    assert_control("form_fill_text_value_only", &["formFill"]);
}

#[test]
fn attacks_form_fill_inplace_ap() {
    assert_control("form_fill_inplace_ap", &["formFill"]);
}

#[test]
fn attacks_form_fill_checkbox_on() {
    assert_control("form_fill_checkbox_on", &["formFill"]);
}

#[test]
fn attacks_form_fill_radio_value_only() {
    assert_control("form_fill_radio_value_only", &["formFill"]);
}

#[test]
fn attacks_form_fill_choice() {
    assert_control("form_fill_choice", &["formFill"]);
}

#[test]
fn attacks_form_fill_tagged_objr() {
    // D-24: the widgets are in the structure tree (an /OBJR each), which is an expected context.
    assert_control("form_fill_tagged_objr", &["formFill"]);
}

#[test]
fn attacks_form_fill_dr_font_added() {
    assert_control("form_fill_dr_font_added", &["defaultResources", "formFill"]);
}

#[test]
fn attacks_form_fill_value_removed() {
    assert_control("form_fill_value_removed", &["formFill"]);
}

// ---- stricter than pyHanko (M4 brief §0.1) ---------------------------------------------------

#[test]
fn attacks_form_widget_unhidden() {
    assert_stricter("form_widget_unhidden", "annotation flags /F");
}

#[test]
fn attacks_form_widget_hidden() {
    assert_stricter("form_widget_hidden", "annotation flags /F");
}

#[test]
fn attacks_form_field_da_changed() {
    assert_stricter("form_field_da_changed", "/DA");
}

#[test]
fn attacks_form_field_q_changed() {
    assert_stricter("form_field_q_changed", "/Q");
}

#[test]
fn attacks_form_field_ff_changed() {
    assert_stricter("form_field_ff_changed", "/Ff");
}

#[test]
fn attacks_form_ap_changed_without_value() {
    assert_stricter("form_ap_changed_without_value", "(F4)");
}

#[test]
fn attacks_form_checkbox_ap_replaced() {
    assert_stricter("form_checkbox_ap_replaced", "(F3)");
}

#[test]
fn attacks_form_readonly_field_filled() {
    assert_stricter("form_readonly_field_filled", "ReadOnly");
}

#[test]
fn attacks_form_fill_with_xfa() {
    assert_stricter("form_fill_with_xfa", "/XFA");
}

#[test]
fn attacks_form_as_unknown_state() {
    assert_stricter("form_as_unknown_state", "names no appearance state");
}

#[test]
fn attacks_form_value_indirect() {
    assert_stricter("form_value_indirect", "(F2)");
}

#[test]
fn attacks_form_checkbox_as_without_value() {
    assert_stricter("form_checkbox_as_without_value", "(F3)");
}

// ---- OTHER for Folioxide and pyHanko ----------------------------------------------------------

#[test]
fn attacks_form_fill_radio_b() {
    // Selecting another radio button sets /AS on two kid widgets; pyHanko 0.37 allows no change
    // to a kid widget (probe radio_b: OTHER), so this brief §5.4 "control" is equal-strict.
    assert_equal_strict("form_fill_radio_b", "kid of its field");
}

#[test]
fn attacks_form_fill_under_own_fieldmdp() {
    // F0, D-23: generic form filling is off when the evaluated signature has FieldMDP (M11).
    // Brief §0.1 lists it as stricter than pyHanko, but pyHanko 0.37 also reports OTHER here
    // (it refuses the update as touching the locked field Country), so it is equal-strict.
    assert_equal_strict("form_fill_under_own_fieldmdp", "FieldMDP");
}

#[test]
fn attacks_form_kid_widget_ap() {
    assert_equal_strict("form_kid_widget_ap", "kid of its field");
}

#[test]
fn attacks_form_widget_rect_moved() {
    assert_equal_strict("form_widget_rect_moved", "/Rect");
}

#[test]
fn attacks_form_mk_added() {
    assert_equal_strict("form_mk_added", "/MK");
}

#[test]
fn attacks_form_dv_set() {
    assert_equal_strict("form_dv_set", "/DV");
}

#[test]
fn attacks_form_tu_set() {
    assert_equal_strict("form_tu_set", "/TU");
}

#[test]
fn attacks_form_kid_added() {
    assert_equal_strict("form_kid_added", "/Widget annotation");
}

#[test]
fn attacks_form_field_renamed() {
    assert_equal_strict("form_field_renamed", "/T,");
}

#[test]
fn attacks_form_orphan_widget_as_changed() {
    // The orphan widget is in no field tree: no form-filling role explains its change.
    assert_equal_strict("form_orphan_widget_as_changed", "changes an object");
}

#[test]
fn attacks_form_inplace_ap_shared_with_page() {
    assert_equal_strict("form_inplace_ap_shared_with_page", "also uses elsewhere");
}

#[test]
fn attacks_form_fill_ap_no_bbox() {
    // QA finding R5: the new appearance has no /BBox, so PDFium paints it over the page.
    assert_stricter("form_fill_ap_no_bbox", "/BBox");
}

#[test]
fn attacks_form_fill_ap_matrix_magnitude() {
    // M4 QA round 4, finding 4 (variant F4-i-newap-bbox-ok-matrix-int32max): a new
    // appearance's /Matrix translating by 2147483647 is placed elsewhere by PDFium.
    assert_stricter(
        "form_fill_ap_matrix_magnitude",
        "/Matrix has an entry beyond",
    );
}

#[test]
fn attacks_form_dr_adds_name_used_in_ap_pattern() {
    // M4 QA round 2, finding 22: a name used only in a tiling pattern cell of a signed
    // appearance is a signed name.
    assert_stricter("form_dr_adds_name_used_in_ap_pattern", "already names");
}

#[test]
fn attacks_form_dr_adds_name_used_in_ap_type3_glyph() {
    // The same for a Type 3 font's glyph procedure.
    assert_stricter("form_dr_adds_name_used_in_ap_type3_glyph", "already names");
}

#[test]
fn attacks_form_dr_adds_name_used_in_ap_indirect_subtype() {
    // M4 QA round 4, finding 12: a nested form whose /Subtype /Form is indirect is read.
    assert_stricter(
        "form_dr_adds_name_used_in_ap_indirect_subtype",
        "already names",
    );
}

#[test]
fn attacks_form_dr_adds_name_used_in_ap_type3_indirect_subtype() {
    // The same for a Type 3 font whose /Subtype /Type3 is indirect.
    assert_stricter(
        "form_dr_adds_name_used_in_ap_type3_indirect_subtype",
        "already names",
    );
}

#[test]
fn attacks_form_dr_adds_name_used_in_ap_page_level_form() {
    // A signed appearance without /Resources resolves /Fm0 in the page's resources; the form
    // there uses /F9.
    assert_stricter(
        "form_dr_adds_name_used_in_ap_page_level_form",
        "already names",
    );
}

#[test]
fn attacks_form_fill_norotate_widget_rotated_page() {
    // M4 QA round 2, expert finding: Amount's widget is NoRotate on a page rotated by 90, so the
    // filled appearance is drawn upright at the /Rect's corner, outside the /Rect (poppler:
    // 12,067 pixels): OTHER (F0).
    assert_stricter("form_fill_norotate_widget_rotated_page", "NoRotate");
}

#[test]
fn attacks_form_checkbox_norotate_rotated_page() {
    // The same for the check box's /AS toggle (F3).
    assert_stricter("form_checkbox_norotate_rotated_page", "NoRotate");
}

#[test]
fn attacks_form_dr_adds_name_missing_from_ap_resources() {
    // The F7 residual (brief §5.5 scope (2)): the name a signed appearance stream uses but its
    // own /Resources lack is a signed name; adding it to /DR is OTHER.
    assert_stricter(
        "form_dr_adds_name_missing_from_ap_resources",
        "a form XObject it draws",
    );
}

/// Every `form_*` case of the corpus has its test above (the brief §6.2 rule "every `form_*` …
/// case of §5.4").
// ---- M4 QA round 3 ------------------------------------------------------------------------------

#[test]
fn attacks_form_signed_dup_rect_clean_fill() {
    // Finding 5 (variant F0-h-signed-dup-Rect-first-elsewhere-clean-relist): the signed field
    // writes /Rect twice; a clean fill rewrites it with Folioxide's (last) value, which moves
    // the widget for first-wins readers. Ruling R-12 (2): the signed copy of a changed object
    // must be canonical. Other, as pyHanko.
    assert_equal_strict("form_signed_dup_rect_clean_fill", "duplicate key /Rect");
}

#[test]
fn attacks_form_signed_dup_checkbox_relisted() {
    // Finding 5 (variant F3-h-signed-dup-AS-yes-first-relist-off): pyHanko (first-wins) sees a
    // fill from /Yes to /Off where Folioxide's last-wins reading saw a re-listing.
    assert_stricter("form_signed_dup_checkbox_relisted", "duplicate key /AS");
}

#[test]
fn attacks_form_inplace_ap_shared_first_wins() {
    // Ruling R-12 (2), the usage index: the signed page draws /Fx from an /XObject dictionary
    // that writes /Fx twice, Amount's appearance stream first. Folioxide's last-wins parser saw
    // the stream used once, so rewriting it in place (F5) looked like a fill, while first-wins
    // readers (pyHanko, pypdf) draw it as page content too.
    assert_equal_strict(
        "form_inplace_ap_shared_first_wins",
        "where the signed revision uses it cannot be known",
    );
}

#[test]
fn attacks_form_inplace_ap_hidden_one_hop() {
    // M4 QA round 4, finding 1, the control shape: the signed page-tree root writes /Extra
    // with /Fx twice, Amount's appearance stream first. The raw bytes name the stream, which
    // Folioxide's reading does not: the usage cannot be known.
    assert_equal_strict(
        "form_inplace_ap_hidden_one_hop",
        "where the signed revision uses it cannot be known",
    );
}

#[test]
fn attacks_form_inplace_ap_hidden_two_hops() {
    // Variant F5-i-inplace-ap-two-hop-hidden-use: the first value is a carrier << /Fx 8 0 R >>
    // that only first-wins readers reach. The walk follows the raw references of the
    // non-canonical root, so the carrier's use of the stream is recorded (pyHanko: other).
    assert_equal_strict(
        "form_inplace_ap_hidden_two_hops",
        "which the signed revision also uses elsewhere",
    );
}

#[test]
fn attacks_form_inplace_ap_hidden_three_hops() {
    // Variant F5-i-inplace-ap-three-hop-hidden-use: [C 0 R], C = << /Q 8 0 R >>.
    assert_equal_strict(
        "form_inplace_ap_hidden_three_hops",
        "which the signed revision also uses elsewhere",
    );
}

#[test]
fn attacks_form_dr_adds_name_used_in_ap_extgstate_smask() {
    // Findings 6 and 21 (variant R1y-extgstate-smask-group).
    assert_stricter(
        "form_dr_adds_name_used_in_ap_extgstate_smask",
        "adds /DR /Font /F9",
    );
}

#[test]
fn attacks_form_dr_adds_name_used_in_ap_extgstate_font() {
    // Findings 6 and 21 (variant R1y-extgstate-font-type3).
    assert_stricter(
        "form_dr_adds_name_used_in_ap_extgstate_font",
        "adds /DR /Font /F9",
    );
}

#[test]
fn every_form_case_is_tested() {
    let source = include_str!("attacks_formfill.rs");
    let corpus_source = include_str!("attacks_corpus.rs");
    for case in corpus() {
        if case.name.starts_with("form_") {
            let test = format!("fn attacks_{}()", case.name);
            assert!(
                source.contains(&test) || corpus_source.contains(&test),
                "{} has no test",
                case.name
            );
        }
    }
}

// ---- M4 QA round 5: rulings R-19 and R-21, finding 29 ----------------------------------------

#[test]
fn attacks_form_fill_ap_matrix_small_bbox() {
    // Ruling R-21, finding 28: a one-unit /BBox the /Matrix maps to 100,001.
    assert_stricter(
        "form_fill_ap_matrix_small_bbox",
        "mapped through its /Matrix",
    );
}

#[test]
fn attacks_form_fill_ap_tiny_bbox_translate_1e5() {
    // Final fix round 2, findings 2 and 4 (variants F4-k-pdfium-bbox-*): a 0.01-unit box
    // translated by 99,999 and scaled by 20,000 onto the field, which PDFium does in single
    // precision.
    assert_stricter("form_fill_ap_tiny_bbox_translate_1e5", "single precision");
}

#[test]
fn attacks_form_fill_ap_matrix_tiny_bbox() {
    // Variant F4-k-newap-matrix-real-spelling-99999.9.
    assert_stricter("form_fill_ap_matrix_tiny_bbox", "single precision");
}

#[test]
fn tiny_boxes_qa_tried() {
    // The QA variants (findings 2 and 4) refused, and the QA controls (a box of 1, 0.5 or 0.1
    // units near the origin, a box of the field's size far from it) fills; a 1-unit box
    // translated by 50,000 is refused too (the bound is about the precision, not the pixels QA
    // saw for it).
    let base = sign_support::corpus::Base::Form.bytes();
    let fill = |bbox: [f64; 4], matrix: [f64; 6]| {
        folioxide_testkit::fixtures::sign_attacks::form_fill_ap_form(&base, bbox, matrix).unwrap()
    };
    let translate = |tx: f64| [1.0, 0.0, 0.0, 1.0, tx, 0.0];
    for (bbox, matrix, other) in [
        ([0.0, 0.0, 0.01, 0.01], translate(99_999.0), true),
        ([0.0, 0.0, 0.01, 0.01], translate(50_000.0), true),
        ([0.0, 0.0, 0.01, 0.01], translate(10_000.0), true),
        ([0.0, 0.0, 0.1, 0.1], translate(99_999.9), true),
        ([0.0, 0.0, 1.0, 1.0], translate(50_000.0), true),
        ([0.0, 0.0, 1.0, 1.0], translate(0.0), false),
        ([0.0, 0.0, 0.5, 0.5], translate(0.0), false),
        ([0.0, 0.0, 0.1, 0.1], translate(0.0), false),
        ([0.0, 0.0, 200.0, 30.0], translate(99_000.0), false),
    ] {
        let r = signature1(&fill(bbox, matrix));
        let want = if other {
            ModificationLevel::Other
        } else {
            ModificationLevel::FormFilling
        };
        assert_eq!(
            r.modification, want,
            "{bbox:?} {matrix:?}: {:?}",
            r.warnings
        );
    }
}

#[test]
fn attacks_form_ap_dict_indirect_fill_control() {
    // Ruling R-19, the control: an indirect /AP dictionary used once; the fill gives the field a
    // new appearance (FormFilling, as pyHanko).
    assert_control("form_ap_dict_indirect_fill_control", &["formFill"]);
}

#[test]
fn attacks_form_ap_dict_shared_repointed() {
    // Ruling R-19, finding 7 (variants F4-j-two-widgets-share-ap-dict-amount-repointed-*):
    // pyHanko refuses any update while a field's /AP dictionary has two contexts.
    assert_equal_strict("form_ap_dict_shared_repointed", "R-19");
}

#[test]
fn attacks_form_ap_dict_shared_unrelated_fill() {
    // Variant F4-j-two-widgets-share-ap-dict-unrelated-fill-control.
    assert_equal_strict("form_ap_dict_shared_unrelated_fill", "R-19");
}

#[test]
fn attacks_form_ap_dict_shared_info_only() {
    // Variant F8-j-shared-ap-dict-then-info-only: only /Info changes, and pyHanko still says
    // other.
    assert_equal_strict("form_ap_dict_shared_info_only", "R-19");
}

#[test]
fn attacks_form_ap_dict_shared_hidden_carrier() {
    // Variants F4-j-hop-indirect-ap-dict-*: the second context is a first-wins carrier that
    // Folioxide's last-wins reading does not see; the raw-reference index counts it.
    assert_equal_strict("form_ap_dict_shared_hidden_carrier", "R-19");
}

#[test]
fn attacks_form_ap_dict_shared_nonterminal_parents() {
    // Closing round, finding 10 (the expert's nt-shared-2.pdf): the non-terminal text fields P
    // and Q share one indirect /AP dictionary (never drawn); pyHanko's _list_fields yields every
    // named field node, and its GenericFieldModificationRule refuses the later co-signature.
    assert_equal_strict("form_ap_dict_shared_nonterminal_parents", "R-19");
}

#[test]
fn attacks_form_ap_dict_shared_nonterminal_parents_cert2() {
    // nt-shared-cert.pdf: under a P = 2 certification pyHanko says other and docmdpOk false.
    let r = assert_certified(
        "form_ap_dict_shared_nonterminal_parents_cert2",
        ModificationLevel::Other,
    );
    assert_eq!(r.docmdp_ok, Some(false));
    assert!(
        r.warnings.iter().any(|w| w.contains("R-19")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn attacks_form_ap_dict_private_nonterminal_parents() {
    // The control nt-private-2.pdf: each parent has a dictionary of its own (used once):
    // FormFilling, as pyHanko.
    let r = assert_revision(
        "form_ap_dict_private_nonterminal_parents",
        ModificationLevel::FormFilling,
    );
    assert_eq!(r.docmdp_ok, Some(true));
    assert!(
        !r.warnings.iter().any(|w| w.contains("R-19")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn attacks_form_ap_dict_private_nonterminal_parents_cert2() {
    // nt-private-cert.pdf: the control under a P = 2 certification (pyHanko: FORM_FILLING, True).
    let r = assert_certified(
        "form_ap_dict_private_nonterminal_parents_cert2",
        ModificationLevel::FormFilling,
    );
    assert_eq!(r.docmdp_ok, Some(true));
}

/// [`assert_revision`] for a case on a P = 2 certification: the same checks, `docmdp` 2, and no
/// deliberate difference from pyHanko.
fn assert_certified(name: &str, level: ModificationLevel) -> SignatureReport {
    let r = signature1(&attacked(name));
    let s = summary(&r);
    let base = corpus().into_iter().find(|c| c.name == name).unwrap().base;
    assert!(r.intact && r.signature_valid && r.is_valid(), "{name}: {s}");
    assert_eq!(r.coverage, Coverage::EntireRevision, "{name}: {s}");
    assert_eq!(r.signed_revision, Some(base.signed_revision()), "{name}");
    assert_eq!(r.modification, level, "{name}: {s} {:?}", r.warnings);
    assert_eq!(r.docmdp, Some(2), "{name}");
    assert_eq!(our_value(name, "modification"), None, "{name}");
    assert_eq!(our_value(name, "docmdpOk"), None, "{name}");
    r
}

#[test]
fn attacks_form_dr_adds_name_used_in_ap_ownres_empty() {
    // Finding 29 (variant R1v-own-resources-empty-page-form).
    assert_stricter("form_dr_adds_name_used_in_ap_ownres_empty", "already names");
}

#[test]
fn attacks_form_dr_adds_name_used_in_ap_ownres_font_only() {
    // Finding 29 (variant R1v-own-resources-font-only-page-form).
    assert_stricter(
        "form_dr_adds_name_used_in_ap_ownres_font_only",
        "already names",
    );
}

#[test]
fn attacks_form_dr_adds_name_used_in_ap_parent_mismatch() {
    // Finding 29 (variant R1v-bare-ap-parent-chain-differs-from-kids-walk): the resources a
    // /Kids walk inherits are read, and a tree whose /Parent chains disagree with it makes the
    // collection incomplete, so no new /DR name is allowed.
    assert_stricter("form_dr_adds_name_used_in_ap_parent_mismatch", "/DR");
}

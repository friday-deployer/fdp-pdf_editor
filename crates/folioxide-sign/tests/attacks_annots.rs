#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The Annotations whitelist (M4 brief §5.2, rule V10 (9), D-1) against the `annots_*` cases of
//! the attack corpus (§5.4) and the markup annotation after an approval signature.
//!
//! The `annots_*` cases append one revision to `minimal.pdf` with a reviewer's square annotation,
//! certified with `P = 3` (the one permission level that grants annotation creation): each
//! refused variant is `Other` for Folioxide and pyHanko, so `docmdp_ok` is false. The markup
//! annotations that P = 3 allows are the `certify_p3_*` cases of `certify_corpus.rs`.

mod sign_support;

use folioxide_sign::report::{Coverage, ModificationLevel, SignatureReport};
use sign_support::corpus::{
    MORE_LENIENT, attacked, change_classes, corpus, our_value, pyhanko_value, signature1,
};
use sign_support::summary;

/// The report of `Signature1` after the attack `name`, sound over its revision, at `level`.
fn assert_revision(name: &str, level: ModificationLevel) -> SignatureReport {
    let r = signature1(&attacked(name));
    let s = summary(&r);
    let base = corpus().into_iter().find(|c| c.name == name).unwrap().base;
    assert!(r.intact && r.signature_valid && r.is_valid(), "{name}: {s}");
    assert_eq!(r.coverage, Coverage::EntireRevision, "{name}: {s}");
    assert_eq!(r.signed_revision, Some(base.signed_revision()), "{name}");
    assert_eq!(r.modification, level, "{name}: {s} {:?}", r.warnings);
    r
}

/// A refused annotation change after a `P = 3` certification: `Other` for both, `docmdp_ok`
/// false, never acceptable, and a warning naming `needle`.
fn assert_refused(name: &str, needle: &str) {
    let r = assert_revision(name, ModificationLevel::Other);
    assert_eq!(r.docmdp, Some(3), "{name}");
    assert_eq!(r.docmdp_ok, Some(false), "{name}");
    assert!(!r.is_acceptable(ModificationLevel::Annotations), "{name}");
    assert!(
        r.warnings.iter().any(|w| w.contains(needle)),
        "{name}: no warning names {needle:?}: {:?}",
        r.warnings
    );
    assert_eq!(
        our_value(name, "modification"),
        None,
        "{name}: equal to pyHanko"
    );
}

// ---- D-1 after an approval signature ----------------------------------------------------------

#[test]
fn attacks_approval_markup_annotation_added() {
    // D-1 (more lenient than pyHanko, M4 brief §0.2): a markup annotation from the add-only
    // whitelist is Annotations; pyHanko reports OTHER.
    let name = "approval_markup_annotation_added";
    let r = assert_revision(name, ModificationLevel::Annotations);
    assert_eq!(change_classes(&r), ["annotation"], "{name}");
    assert_eq!(our_value(name, "modification"), Some("annotations"));
    assert_eq!(pyhanko_value(name, "modification"), Some("other"));
    assert!(MORE_LENIENT.iter().any(|(c, ..)| *c == name));
    // D-13: the default P = 2 in force does not grant annotations (docmdp_ok false), so not
    // even a caller who accepts Annotations accepts the document.
    assert!(!r.is_acceptable(ModificationLevel::Annotations), "{name}");
}

#[test]
fn approval_annotation_docmdp_not_ok() {
    // An approval signature has no DocMDP of its own and no certification is in force, so P = 2
    // (§5.3 C2): an annotation exceeds form filling, so docmdp_ok is false (pyHanko: OTHER, so
    // false too), and the document is not acceptable at Annotations.
    let r = signature1(&attacked("approval_markup_annotation_added"));
    assert_eq!(r.docmdp, None);
    assert_eq!(r.modification, ModificationLevel::Annotations);
    assert_eq!(r.docmdp_ok, Some(false), "{}", summary(&r));
}

// ---- refused under P = 3 (OTHER for Folioxide and pyHanko) ------------------------------------

#[test]
fn attacks_annots_link_uri() {
    assert_refused("annots_link_uri", "/Link annotation");
}

#[test]
fn attacks_annots_js_action() {
    assert_refused("annots_js_action", "has /AA");
}

#[test]
fn attacks_annots_file_attachment() {
    assert_refused("annots_file_attachment", "/FileAttachment annotation");
}

#[test]
fn attacks_annots_widget_added() {
    assert_refused("annots_widget_added", "/Widget annotation");
}

#[test]
fn attacks_annots_oc() {
    assert_refused("annots_oc", "has /OC");
}

#[test]
fn attacks_annots_noview_print() {
    assert_refused("annots_noview_print", "NoView");
}

#[test]
fn attacks_annots_popup_foreign_parent() {
    assert_refused("annots_popup_foreign_parent", "(A4)");
}

#[test]
fn attacks_annots_existing_removed() {
    assert_refused("annots_existing_removed", "existing entries changed");
}

#[test]
fn attacks_annots_existing_modified() {
    assert_refused("annots_existing_modified", "changes an object");
}

#[test]
fn attacks_annots_reordered() {
    assert_refused("annots_reordered", "reordered");
}

#[test]
fn attacks_annots_redact() {
    assert_refused("annots_redact", "/Redact annotation");
}

#[test]
fn attacks_annots_structparent() {
    assert_refused("annots_structparent", "/StructParent");
}

#[test]
fn attacks_annots_popup_without_parent() {
    assert_refused("annots_popup_without_parent", "(A4)");
}

#[test]
fn attacks_annots_irt_unlisted() {
    assert_refused("annots_irt_unlisted", "(A5)");
}

// ---- drawn outside the /Rect (M4 QA round 1, ruling R-2; finding R5) ---------------------------

#[test]
fn attacks_annots_highlight_quadpoints_outside() {
    // poppler draws a highlight from its /QuadPoints even with an appearance stream.
    assert_refused("annots_highlight_quadpoints_outside", "/QuadPoints");
}

#[test]
fn attacks_annots_highlight_no_ap() {
    assert_refused("annots_highlight_no_ap", "/QuadPoints");
}

#[test]
fn attacks_annots_underline_quadpoints_outside() {
    assert_refused("annots_underline_quadpoints_outside", "/QuadPoints");
}

#[test]
fn attacks_annots_ink_inklist_outside() {
    assert_refused("annots_ink_inklist_outside", "/InkList");
}

#[test]
fn attacks_annots_line_outside() {
    assert_refused("annots_line_outside", "/L ");
}

#[test]
fn attacks_annots_polygon_vertices_outside() {
    assert_refused("annots_polygon_vertices_outside", "/Vertices");
}

#[test]
fn attacks_annots_text_no_ap() {
    // Viewers draw their own icon of about 20 points for a note without an appearance.
    assert_refused("annots_text_no_ap", "no appearance stream");
}

#[test]
fn attacks_annots_text_nozoom() {
    assert_refused("annots_text_nozoom", "NoZoom");
}

#[test]
fn attacks_annots_square_negative_rd() {
    assert_refused("annots_square_negative_rd", "/RD");
}

#[test]
fn attacks_annots_square_ap_no_bbox() {
    assert_refused("annots_square_ap_no_bbox", "/BBox");
}

#[test]
fn attacks_annots_square_ap_page_content() {
    assert_refused("annots_square_ap_page_content", "existing object");
}

#[test]
fn attacks_approval_highlight_quadpoints_outside() {
    // After an approval signature (D-1 applies) the same highlight is OTHER too.
    let name = "approval_highlight_quadpoints_outside";
    let r = assert_revision(name, ModificationLevel::Other);
    assert_eq!(r.docmdp_ok, Some(false), "{name}");
    assert!(
        r.warnings.iter().any(|w| w.contains("/QuadPoints")),
        "{:?}",
        r.warnings
    );
    assert_eq!(our_value(name, "modification"), None, "equal to pyHanko");
}

#[test]
fn attacks_annots_text_rotated_page_90() {
    // M4 QA round 2, finding 7: a Text annotation does not rotate with its page (ISO 32000-2
    // §12.5.6.4), so on a page rotated by 90 poppler paints it outside its /Rect (8,408 pixels,
    // variant A2-r2-text-ap-f4-rotated-page-90-rot90_cert3).
    assert_refused("annots_text_rotated_page_90", "Text annotation");
}

#[test]
fn attacks_annots_text_rotated_page_180() {
    assert_refused("annots_text_rotated_page_180", "Text annotation");
}

#[test]
fn attacks_annots_text_rotated_page_270() {
    assert_refused("annots_text_rotated_page_270", "Text annotation");
}

#[test]
fn attacks_annots_text_inherited_rotate() {
    // The page inherits /Rotate 90 from its page-tree node (§7.7.3.4; variant
    // A2-r2-text-ap-f4-inherited-rotate-pages-node).
    assert_refused("annots_text_inherited_rotate", "Text annotation");
}

#[test]
fn attacks_approval_text_rotated_page() {
    // After an approval signature (D-1 applies) the same sticky note is OTHER too (variant
    // A2-r2-text-ap-f4-rotated-page-90-rot90_approval).
    let name = "approval_text_rotated_page";
    let r = assert_revision(name, ModificationLevel::Other);
    assert_eq!(r.docmdp_ok, Some(false), "{name}");
    assert!(
        r.warnings.iter().any(|w| w.contains("Text annotation")),
        "{:?}",
        r.warnings
    );
    assert_eq!(our_value(name, "modification"), None, "equal to pyHanko");
}

/// Every `annots_*` case of the corpus has its test above.
// ---- M4 QA round 3 ------------------------------------------------------------------------------

#[test]
fn attacks_annots_square_rect_integer_overflow() {
    // Finding 12 (variant A2-r3-square-rect-y2-2pow32-cert3): PDFium reads the /Rect's
    // 4294967296 as 0 and paints the square outside the /Rect Folioxide read (ruling R-12).
    assert_refused("annots_square_rect_integer_overflow", "outside ±2147483647");
}

#[test]
fn attacks_annots_text_page_without_parent() {
    // Finding 11 (variant A2-r3-text-page-without-parent-key-in-rotated-tree): poppler
    // inherits /Rotate 90 along /Kids, PDFium follows the missing /Parent (ruling R-13).
    assert_refused("annots_text_page_without_parent", "manager ruling R-13");
}

#[test]
fn attacks_annots_text_parent_chain_upright() {
    // Finding 11 (variant A2-r3-text-parent-chain-upright-kids-chain-rotated).
    assert_refused("annots_text_parent_chain_upright", "manager ruling R-13");
}

#[test]
fn attacks_annots_text_page_with_kids() {
    // M4 QA round 4, finding 10 (variants A2-r4-pt-pagekids-*): the first page has /Rotate 90
    // and /Kids listing the second page; poppler walks it as a page, PDFium as a node (two
    // pages, both upright). ISO 32000-2 §7.7.3.3 allows /Kids only in /Pages nodes.
    assert_refused("annots_text_page_with_kids", "has /Kids");
}

#[test]
fn every_annots_case_is_tested() {
    let source = include_str!("attacks_annots.rs");
    for case in corpus() {
        if case.name.starts_with("annots_") || case.name.starts_with("approval_") {
            let test = format!("fn attacks_{}()", case.name);
            assert!(source.contains(&test), "{} has no test", case.name);
        }
    }
}

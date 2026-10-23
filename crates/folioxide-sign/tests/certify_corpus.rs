#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The certification corpus (M4 brief §5.3, §5.4 "Certification", §6.3 suite `certify`): one
//! `certify_<case>` test per case of `certify_corpus()`, each asserting the certification
//! signature's `modification`, `docmdp`, `docmdp_ok` and change classes, plus the named
//! classifier tests of brief §6.2 about certification (C1, C2, C3, D-1, D-2, D-13).
//!
//! The documents are certified by Folioxide itself (RSA-2048), then changed by the generators of
//! `folioxide_testkit::fixtures::{forms, sign_attacks}`, an approval by our P-256 key, or a raw
//! signature (`sign_raw`) where Folioxide refuses to sign (D-3).

mod sign_support;

use folioxide_sign::ProblemCode;
use folioxide_sign::report::{ModificationLevel, SignatureReport};
use sign_support::corpus::{
    DELIBERATE_DIFFERENCES, MORE_LENIENT, certified_case, certify_corpus, change_classes,
    our_value, pyhanko_value, signature1,
};
use sign_support::{summary, verify_plain};

use ModificationLevel::{Annotations, FormFilling, LtaUpdates, Other};

/// The certification signature (`Signature1`) of the case `name`: intact and valid over its
/// revision, with `modification`, `docmdp = p`, `docmdp_ok = ok` and the change classes
/// `classes`.
fn assert_certified(
    name: &str,
    modification: ModificationLevel,
    p: u8,
    ok: bool,
    classes: &[&str],
) -> SignatureReport {
    let r = signature1(&certified_case(name));
    let s = summary(&r);
    assert!(r.intact && r.signature_valid && r.is_valid(), "{name}: {s}");
    assert_eq!(r.modification, modification, "{name}: {s} {:?}", r.warnings);
    assert_eq!(r.docmdp, Some(p), "{name}");
    assert_eq!(r.docmdp_ok, Some(ok), "{name}: {:?}", r.warnings);
    assert_eq!(change_classes(&r), classes, "{name}: {:?}", r.warnings);
    r
}

/// The report of the field `field` in the case `name`.
fn field_report(name: &str, field: &str) -> SignatureReport {
    verify_plain(&certified_case(name))
        .into_iter()
        .find(|r| r.field_name.as_deref() == Some(field))
        .unwrap_or_else(|| panic!("{name}: {field} is listed"))
}

/// The warning of rule C1 (a new visible signature field after a certification signature).
const C1: &str = "after a certification signature (M4 brief §5.3 C1";

// ---- certified, nothing after ----------------------------------------------------------------

#[test]
fn certify_p1_alone() {
    let r = assert_certified("certify_p1_alone", ModificationLevel::None, 1, true, &[]);
    assert!(r.is_acceptable(ModificationLevel::None));
}

#[test]
fn certify_p2_alone() {
    assert_certified("certify_p2_alone", ModificationLevel::None, 2, true, &[]);
}

#[test]
fn certify_p3_alone() {
    assert_certified("certify_p3_alone", ModificationLevel::None, 3, true, &[]);
}

// ---- P = 2: form filling and signing ---------------------------------------------------------

#[test]
fn certify_p2_text_fill() {
    let r = assert_certified("certify_p2_text_fill", FormFilling, 2, true, &["formFill"]);
    assert!(r.is_acceptable(FormFilling));
}

#[test]
fn certify_p2_checkbox_fill() {
    assert_certified(
        "certify_p2_checkbox_fill",
        FormFilling,
        2,
        true,
        &["formFill"],
    );
}

#[test]
fn certify_p2_approval() {
    // Our invisible approval in a new field: SignatureField + Signature, FormFilling, allowed.
    assert_certified(
        "certify_p2_approval",
        FormFilling,
        2,
        true,
        &["signatureField", "signature"],
    );
    let approval = field_report("certify_p2_approval", "Approval");
    assert!(approval.is_valid(), "{}", summary(&approval));
    assert_eq!(approval.docmdp, None);
    assert!(approval.problems.is_empty());
    // C2: the certification in force (P = 2) judges the approval; nothing follows it.
    assert_eq!(approval.modification, ModificationLevel::None);
    assert_eq!(approval.docmdp_ok, Some(true));
}

#[test]
fn certify_p2_existing_visible_signed() {
    // C1 concerns new fields only: signing the existing visible field stays FormFilling (probe
    // p2_existing_visible_signed).
    assert_certified(
        "certify_p2_existing_visible_signed",
        FormFilling,
        2,
        true,
        &["signature"],
    );
    let approval = field_report("certify_p2_existing_visible_signed", "Visible");
    assert!(approval.is_valid(), "{}", summary(&approval));
}

// ---- P = 1: no changes ------------------------------------------------------------------------

#[test]
fn certify_p1_fill() {
    // ROADMAP M4 acceptance #3's "false" case: P = 1 then a form fill (pyHanko: false too).
    let r = assert_certified("certify_p1_fill", FormFilling, 1, false, &["formFill"]);
    assert!(!r.is_acceptable(FormFilling), "D-13");
}

#[test]
fn certify_p1_info_changed() {
    // D-2 (stricter): pyHanko accepts LTA_UPDATES under P = 1.
    let name = "certify_p1_info_changed";
    assert_certified(name, LtaUpdates, 1, false, &["metadata"]);
    assert_eq!(our_value(name, "docmdpOk"), Some("false"));
    assert_eq!(pyhanko_value(name, "docmdpOk"), Some("true"));
}

#[test]
fn certify_p1_xmp_changed() {
    let name = "certify_p1_xmp_changed";
    assert_certified(name, LtaUpdates, 1, false, &["metadata"]);
    assert_eq!(our_value(name, "docmdpOk"), Some("false"));
    assert_eq!(pyhanko_value(name, "docmdpOk"), Some("true"));
}

#[test]
fn certify_p1_doc_timestamp() {
    // The document timestamp and its bookkeeping (/Info /ModDate and /Producer, /Version, the
    // ESIC extension) as pyHanko's timestamper writes them: class DocTimeStamp only.
    assert_certified(
        "certify_p1_doc_timestamp",
        LtaUpdates,
        1,
        true,
        &["docTimeStamp"],
    );
}

#[test]
fn certify_p1_doc_timestamp_xmp() {
    // pyHanko's timestamper also rewrites an existing XMP packet's xmp:ModifyDate (probed on
    // pyhanko-certified-p1-dts.pdf): bookkeeping of the timestamp, class DocTimeStamp only.
    assert_certified(
        "certify_p1_doc_timestamp_xmp",
        LtaUpdates,
        1,
        true,
        &["docTimeStamp"],
    );
}

#[test]
fn certify_p1_doc_timestamp_xmp_title_changed() {
    // The same revision with a dc:title added to the packet: Metadata, not allowed by P = 1.
    assert_certified(
        "certify_p1_doc_timestamp_xmp_title_changed",
        LtaUpdates,
        1,
        false,
        &["metadata", "docTimeStamp"],
    );
}

#[test]
fn certify_p1_doc_timestamp_title_changed() {
    // A /Title change in a later revision is not the timestamper's bookkeeping.
    assert_certified(
        "certify_p1_doc_timestamp_title_changed",
        LtaUpdates,
        1,
        false,
        &["metadata", "docTimeStamp"],
    );
}

#[test]
fn certify_p1_doc_timestamp_then_info_bookkeeping() {
    // Manager ruling R-8 (QA findings 24, 32): a /ModDate and /Producer rewrite in a revision
    // after the timestamp's is not its bookkeeping, even with nothing else in it.
    assert_certified(
        "certify_p1_doc_timestamp_then_info_bookkeeping",
        LtaUpdates,
        1,
        false,
        &["metadata", "docTimeStamp"],
    );
}

#[test]
fn certify_p1_doc_timestamp_then_relisted_with_info_bookkeeping() {
    // M4 QA round 2, finding 21: the plain revision re-lists the timestamp's dictionary; the
    // revision that adds the timestamp is the one that first writes it, so the /Info rewrite of
    // the re-listing revision is Metadata.
    assert_certified(
        "certify_p1_doc_timestamp_then_relisted_with_info_bookkeeping",
        LtaUpdates,
        1,
        false,
        &["metadata", "docTimeStamp"],
    );
}

#[test]
fn certify_p1_doc_timestamp_then_xmp_bookkeeping() {
    // R-8, QA variant R4-dts-then-separate-xmp-revision: stricter than pyHanko (true).
    assert_certified(
        "certify_p1_doc_timestamp_then_xmp_bookkeeping",
        LtaUpdates,
        1,
        false,
        &["metadata", "docTimeStamp"],
    );
}

/// A case whose document timestamp rewrites the XMP packet into malformed XML (QA finding 22):
/// not an XMP packet, so `Other` and `docmdp_ok` false (pyHanko's `MetadataUpdateRule` refuses
/// it too).
fn assert_xmp_refused(name: &str) {
    let r = signature1(&certified_case(name));
    assert!(r.intact && r.signature_valid, "{name}: {}", summary(&r));
    assert_eq!(
        r.modification,
        Other,
        "{name}: {} {:?}",
        summary(&r),
        r.warnings
    );
    assert_eq!(r.docmdp, Some(1), "{name}");
    assert_eq!(r.docmdp_ok, Some(false), "{name}");
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("the new stream is not an XMP packet")),
        "{name}: {:?}",
        r.warnings
    );
}

#[test]
fn certify_p1_doc_timestamp_xmp_value_lt() {
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_value_lt");
}

#[test]
fn certify_p1_doc_timestamp_xmp_undefined_entity() {
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_undefined_entity");
}

#[test]
fn certify_p1_doc_timestamp_xmp_bad_charref() {
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_bad_charref");
}

#[test]
fn certify_p1_doc_timestamp_xmp_dup_attribute() {
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_dup_attribute");
}

#[test]
fn certify_p1_doc_timestamp_xmp_attribute_without_value() {
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_attribute_without_value");
}

#[test]
fn certify_p1_doc_timestamp_xmp_flate_then_ahx() {
    // M4 QA round 4, finding 11 (variants R4w-dec-flate-*-dts): in the timestamp's revision too,
    // a packet pyHanko cannot decode (its FlateDecode returns a memoryview, on which its ASCII
    // decoders raise) is no XMP packet (pyHanko: other).
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_flate_then_ahx");
}

#[test]
fn certify_p1_doc_timestamp_xmp_flate_then_a85() {
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_flate_then_a85");
}

#[test]
fn certify_p1_doc_timestamp_xmp_flate_crypt_ahx() {
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_flate_crypt_ahx");
}

#[test]
fn certify_p1_doc_timestamp_xmp_flate_flate_ahx() {
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_flate_flate_ahx");
}

#[test]
fn certify_p1_doc_timestamp_xmp_hex_charref_sign() {
    // QA round 2, finding 18 (R4x-hexcharref-plus-*): `&#x+30;` is no character reference.
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_hex_charref_sign");
}

#[test]
fn certify_p1_doc_timestamp_xmp_ns_uri_with_space() {
    // Finding 20 (R4x-ns-uri-with-space-*): a namespace name is a URI reference (RFC 3986).
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_ns_uri_with_space");
}

#[test]
fn certify_p1_doc_timestamp_xmp_xmlns_reserved_uri() {
    // Findings 27, 28: no prefix may be bound to the xmlns namespace (Namespaces in XML §3).
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_xmlns_reserved_uri");
}

#[test]
fn certify_p1_doc_timestamp_xmp_default_ns_xml() {
    // Findings 29, 30: the default namespace may not be the xml namespace.
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_default_ns_xml");
}

#[test]
fn certify_p1_doc_timestamp_xmp_xmldecl_version_2() {
    // Findings 19, 24: an XML declaration names version 1.0 (XML 1.0 §2.8).
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_xmldecl_version_2");
}

#[test]
fn certify_p1_doc_timestamp_xmp_xmldecl_standalone_maybe() {
    // Finding 25: standalone is yes or no.
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_xmldecl_standalone_maybe");
}

#[test]
fn certify_p1_doc_timestamp_xmp_xmldecl_uppercase() {
    // Finding 26: a processing instruction target `XML` is reserved (XML 1.0 §2.6).
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_xmldecl_uppercase");
}

#[test]
fn certify_p1_doc_timestamp_xmp_xmldecl_not_first() {
    // Finding 19: the XML declaration is valid only at the very start of the packet.
    assert_xmp_refused("certify_p1_doc_timestamp_xmp_xmldecl_not_first");
}

#[test]
fn certify_p1_doc_timestamp_xmp_xmldecl_valid() {
    // The control: a valid declaration is well-formed XMP, so the packet that gained it is a
    // Metadata change (not the timestamp's bookkeeping, which P = 1 refuses), never Other.
    assert_certified(
        "certify_p1_doc_timestamp_xmp_xmldecl_valid",
        LtaUpdates,
        1,
        false,
        &["metadata", "docTimeStamp"],
    );
}

#[test]
fn doc_timestamp_xmp_attribute_flood_is_linear() {
    // QA findings 23, 25, 26: 100,000 repeated attributes in the timestamp's XMP rewrite took
    // seconds per signature with the old (quadratic) masker; the packet is refused at once now.
    let flood = " xmp:ModifyDate=\"2026-10-11T05:25:28+00:00\"".repeat(100_000);
    let pdf = sign_support::corpus::certified_p1_xmp_dts("2026-10-11T05:25:27+00:00", &flood);
    let (r, _) = folioxide_testkit::budget::within(std::time::Duration::from_secs(20), move || {
        signature1(&pdf)
    })
    .expect("the verification is linear in the packet");
    assert_eq!(r.modification, Other, "{}", summary(&r));
    assert_eq!(r.docmdp_ok, Some(false));
    // A thousand distinct new attributes (well-formed, within the per-tag limit): masked in
    // one pass, and not the timestamp's bookkeeping (they are new), so Metadata.
    let many: String = (0..1000).map(|a| format!(" xmp:a{a}=\"x\"")).collect();
    let pdf = sign_support::corpus::certified_p1_xmp_dts("2026-10-11T05:25:27+00:00", &many);
    let (r, _) = folioxide_testkit::budget::within(std::time::Duration::from_secs(20), move || {
        signature1(&pdf)
    })
    .expect("the verification is linear in the packet");
    assert_eq!(r.modification, LtaUpdates, "{}", summary(&r));
    assert_eq!(r.docmdp_ok, Some(false));
    assert_eq!(change_classes(&r), ["metadata", "docTimeStamp"]);
}

// ---- C1: new visible signature fields --------------------------------------------------------

/// A C1 case: `Other`, `docmdp_ok` false, the C1 warning.
fn assert_c1(name: &str, p: u8) {
    let r = signature1(&certified_case(name));
    assert_eq!(r.modification, Other, "{name}: {}", summary(&r));
    assert_eq!(r.docmdp, Some(p), "{name}");
    assert_eq!(r.docmdp_ok, Some(false), "{name}");
    assert!(
        r.warnings.iter().any(|w| w.contains(C1)),
        "{name}: {:?}",
        r.warnings
    );
}

#[test]
fn certify_p2_new_visible_approval() {
    assert_c1("certify_p2_new_visible_approval", 2);
    // The approval itself is sound; only the certification's verdict changes.
    let approval = field_report("certify_p2_new_visible_approval", "Approval");
    assert!(approval.is_valid(), "{}", summary(&approval));
}

#[test]
fn certify_p3_new_visible_approval() {
    assert_c1("certify_p3_new_visible_approval", 3);
}

#[test]
fn certify_p2_new_visible_field() {
    assert_c1("certify_p2_new_visible_field", 2);
}

// ---- annotations ------------------------------------------------------------------------------

#[test]
fn certify_p1_annotation() {
    let r = signature1(&certified_case("certify_p1_annotation"));
    assert_eq!(r.modification, Other, "{}", summary(&r));
    assert_eq!(r.docmdp_ok, Some(false));
    assert!(r.warnings.iter().any(|w| w.contains("only P = 3")));
}

#[test]
fn certify_p2_annotation() {
    let r = signature1(&certified_case("certify_p2_annotation"));
    assert_eq!(r.modification, Other, "{}", summary(&r));
    assert_eq!(r.docmdp, Some(2));
    assert_eq!(r.docmdp_ok, Some(false));
}

/// A D-1 case: `Annotations` and `docmdp_ok` true under P = 3; pyHanko's `other`/false from
/// the [`MORE_LENIENT`] table.
fn assert_p3_annotation(name: &str) {
    assert_certified(name, Annotations, 3, true, &["annotation"]);
    assert_eq!(our_value(name, "modification"), Some("annotations"));
    assert_eq!(pyhanko_value(name, "modification"), Some("other"));
    assert_eq!(pyhanko_value(name, "docmdpOk"), Some("false"));
}

#[test]
fn certify_p3_text_popup() {
    assert_p3_annotation("certify_p3_text_popup");
}

#[test]
fn certify_p3_highlight() {
    assert_p3_annotation("certify_p3_highlight");
}

#[test]
fn certify_p3_square() {
    assert_p3_annotation("certify_p3_square");
}

#[test]
fn certify_p3_ink() {
    assert_p3_annotation("certify_p3_ink");
}

#[test]
fn certify_p3_freetext() {
    assert_p3_annotation("certify_p3_freetext");
}

#[test]
fn certify_p3_stamp() {
    assert_p3_annotation("certify_p3_stamp");
}

#[test]
fn certify_p3_text_upright_page() {
    // M4 QA round 2, finding 7: on the rotated document's upright page a sticky note is allowed.
    assert_p3_annotation("certify_p3_text_upright_page");
}

#[test]
fn certify_p3_square_rotated_page() {
    // Other markup rotates with its page, inside its /Rect: allowed on a page rotated by 90.
    assert_p3_annotation("certify_p3_square_rotated_page");
}

#[test]
fn certify_p3_reply() {
    assert_p3_annotation("certify_p3_reply");
}

#[test]
fn certify_p3_approval_then_markup() {
    // Manager ruling R-7 (QA finding 31): C3 judges the certification's own window; an approval
    // in a P = 3 certified document keeps D-1 too: Annotations, and P_effective = 3 makes its
    // docmdp_ok true. Recorded in brief §0.2 and the MORE_LENIENT table.
    let name = "certify_p3_approval_then_markup";
    assert_certified(
        name,
        Annotations,
        3,
        true,
        &["signatureField", "signature", "annotation"],
    );
    let approval = field_report(name, "Approval");
    assert!(approval.is_valid(), "{}", summary(&approval));
    assert_eq!(
        approval.modification, Annotations,
        "{:?}",
        approval.warnings
    );
    assert_eq!(approval.docmdp, None);
    assert_eq!(approval.docmdp_ok, Some(true));
    assert!(approval.is_acceptable(Annotations));
    assert_eq!(
        our_value(name, "Approval.modification"),
        Some("annotations")
    );
    assert_eq!(pyhanko_value(name, "Approval.modification"), Some("other"));
    assert_eq!(our_value(name, "Approval.docmdpOk"), Some("true"));
    assert_eq!(pyhanko_value(name, "Approval.docmdpOk"), Some("false"));
}

// ---- field locks with /P (manager ruling R-4, QA finding 30) ---------------------------------

/// A lock case: `Signature1` (an approval in a field whose `/Lock` has `/P p`) is intact and
/// valid, with `modification`, `docmdp = p` and `docmdp_ok = ok` (the oracle compares all
/// three with pyHanko, whose `docmdp_level` reads the lock).
fn assert_locked(name: &str, modification: ModificationLevel, p: u8, ok: bool) -> SignatureReport {
    let r = signature1(&certified_case(name));
    assert!(r.intact && r.signature_valid, "{name}: {}", summary(&r));
    assert!(r.problems.is_empty(), "{name}: {:?}", r.problems);
    assert_eq!(r.modification, modification, "{name}: {:?}", r.warnings);
    assert_eq!(r.docmdp, Some(p), "{name}");
    assert_eq!(r.docmdp_ok, Some(ok), "{name}: {:?}", r.warnings);
    r
}

#[test]
fn lock_p1_alone() {
    let r = assert_locked("lock_p1_alone", ModificationLevel::None, 1, true);
    assert!(r.is_acceptable(ModificationLevel::None));
}

#[test]
fn lock_p1_then_invisible_approval() {
    let name = "lock_p1_then_invisible_approval";
    let r = assert_locked(name, FormFilling, 1, false);
    assert!(
        !r.is_acceptable(FormFilling),
        "the lock's P = 1 forbids the approval"
    );
    // The approval itself: P = 1 is in force for it too, and nothing follows it.
    let approval = field_report(name, "Approval");
    assert!(approval.is_valid(), "{}", summary(&approval));
    assert_eq!(approval.docmdp, None);
    assert_eq!(approval.docmdp_ok, Some(true));
}

#[test]
fn lock_p1_then_visible_approval() {
    let r = assert_locked("lock_p1_then_visible_approval", Other, 1, false);
    assert!(
        r.warnings.iter().any(|w| w.contains(C1)),
        "{:?}",
        r.warnings
    );
}

#[test]
fn lock_p2_then_invisible_approval() {
    let r = assert_locked("lock_p2_then_invisible_approval", FormFilling, 2, true);
    assert!(r.is_acceptable(FormFilling));
}

#[test]
fn lock_p2_then_new_visible_approval() {
    let r = assert_locked("lock_p2_then_new_visible_approval", Other, 2, false);
    assert!(
        r.warnings.iter().any(|w| w.contains(C1)),
        "{:?}",
        r.warnings
    );
}

/// M4 QA round 4, expert finding (ISO 32000-2 §12.7.5.5: a field lock's `/P` "shall specify
/// permissions less than or equal to the permissions already in effect"; a greater number is
/// ignored): the certification grants `certified`, an approval's field lock declares 3, and a
/// Square annotation follows. The approval reports its own `docmdp` 3, but `P_effective` is
/// `certified`, so the annotation is `Other` for it too (pyHanko: other, docmdpOk false).
fn assert_lock_beyond_certification(name: &str, certified: u8) {
    let cert = signature1(&certified_case(name));
    assert!(cert.is_valid(), "{name}: {}", summary(&cert));
    assert_eq!(cert.docmdp, Some(certified), "{name}");
    assert_eq!(cert.modification, Other, "{name}: {:?}", cert.warnings);
    assert_eq!(cert.docmdp_ok, Some(false), "{name}");
    let approver = field_report(name, "Approver");
    assert!(approver.is_valid(), "{name}: {}", summary(&approver));
    assert_eq!(approver.docmdp, Some(3), "{name}: the lock's own P");
    assert_eq!(
        approver.modification, Other,
        "{name}: {:?}",
        approver.warnings
    );
    assert_eq!(approver.docmdp_ok, Some(false), "{name}");
    assert!(!approver.is_acceptable(Annotations), "{name}");
    assert!(
        approver
            .warnings
            .iter()
            .any(|w| w.contains("do not allow them")),
        "{name}: {:?}",
        approver.warnings
    );
}

#[test]
fn lock_p3_after_p2_certification_then_markup() {
    assert_lock_beyond_certification("lock_p3_after_p2_certification_then_markup", 2);
}

#[test]
fn lock_p3_after_p1_certification_then_markup() {
    assert_lock_beyond_certification("lock_p3_after_p1_certification_then_markup", 1);
}

#[test]
fn lock_p3_after_p3_certification_then_markup_is_d1() {
    // The control (not an oracle case, a MORE_LENIENT shape): under a P = 3 certification the
    // lock's 3 is what is in force, and the annotation is Annotations for the approval too (D-1,
    // ruling R-7).
    let certified = sign_support::corpus::certify(
        &folioxide_testkit::fixtures::syntax::minimal(),
        folioxide_sign::docmdp::DocMdpPermissions::FormFillingAndAnnotations,
    );
    let approved = sign_support::corpus::locked_approval(&certified, 3);
    let pdf = folioxide_testkit::fixtures::sign_attacks::markup_square(&approved).unwrap();
    let approver = verify_plain(&pdf)
        .into_iter()
        .find(|r| r.field_name.as_deref() == Some("Approver"))
        .unwrap();
    assert!(approver.is_valid(), "{}", summary(&approver));
    assert_eq!(
        approver.modification, Annotations,
        "{:?}",
        approver.warnings
    );
    assert_eq!(approver.docmdp_ok, Some(true));
}

#[test]
fn signing_on_top_of_a_lock_p1_is_refused() {
    // The signing side reads the lock too (docmdp::certification): rule (b) for P = 1.
    let locked = certified_case("lock_p1_alone");
    let doc = sign_support::open(&locked);
    let signer = sign_support::p256();
    let err = folioxide_sign::sign::sign(
        &doc,
        &folioxide_sign::sign::SignRequest::new(&signer, sign_support::time()),
    )
    .unwrap_err();
    assert!(
        matches!(err, folioxide_sign::Error::DocMdpForbids(_)),
        "{err}"
    );
}

// ---- malformed DocMDP declarations (manager ruling R-6, QA finding 12) -----------------------

/// A case whose certification declaration is malformed: `DocMdpInvalid`, no `docmdp`, and
/// `P = 1` in force, so the later approval makes `docmdp_ok` false (pyHanko raises).
fn assert_docmdp_invalid(name: &str, needle: &str) {
    let r = signature1(&certified_case(name));
    assert!(r.intact && r.signature_valid, "{name}: {}", summary(&r));
    assert!(
        r.has_problem(ProblemCode::DocMdpInvalid),
        "{name}: {:?}",
        r.problems
    );
    assert!(
        r.problems.iter().any(|p| p.message.contains(needle)),
        "{name}: {:?}",
        r.problems
    );
    assert!(!r.is_valid(), "{name}");
    assert_eq!(r.docmdp, None, "{name}");
    assert_eq!(r.modification, FormFilling, "{name}: {:?}", r.warnings);
    assert_eq!(
        r.docmdp_ok,
        Some(false),
        "{name}: P = 1 is in force, never 2"
    );
}

#[test]
fn docmdp_reference_not_array() {
    assert_docmdp_invalid("docmdp_reference_not_array", "not an array");
}

#[test]
fn docmdp_reference_without_transform_method() {
    assert_docmdp_invalid(
        "docmdp_reference_without_transform_method",
        "no /TransformMethod",
    );
}

#[test]
fn docmdp_p_out_of_range() {
    assert_docmdp_invalid("docmdp_p_out_of_range", "/P is 4");
}

#[test]
fn docmdp_p_huge_integer() {
    // M4 QA round 3, ruling R-12: the signed /Reference holds a number readers read differently
    // (4294967298: PDFium 0), so the declaration is ambiguous (SigDictAmbiguous) and invalid.
    let name = "docmdp_p_huge_integer";
    assert_docmdp_invalid(name, "number or name spelling");
    let r = signature1(&certified_case(name));
    assert!(
        r.has_problem(ProblemCode::SigDictAmbiguous),
        "{:?}",
        r.problems
    );
}

#[test]
fn docmdp_p_not_an_integer() {
    assert_docmdp_invalid("docmdp_p_not_an_integer", "/P is a string");
}

#[test]
fn docmdp_two_references() {
    let name = "docmdp_two_references";
    assert_docmdp_invalid(name, "2 /Reference entries");
    assert_eq!(our_value(name, "docmdpOk"), Some("false"));
    assert_eq!(pyhanko_value(name, "docmdpOk"), Some("true"));
}

#[test]
fn docmdp_p_missing() {
    // ISO 32000-2 Table 257: /P absent means 2 (pyHanko raises: a DELIBERATE row).
    let name = "docmdp_p_missing";
    let r = signature1(&certified_case(name));
    assert!(r.is_valid(), "{}", summary(&r));
    assert_eq!(r.docmdp, Some(2));
    assert_eq!(r.modification, FormFilling, "{:?}", r.warnings);
    assert_eq!(r.docmdp_ok, Some(true));
    assert_eq!(our_value(name, "docmdp"), Some("2"));
    assert_eq!(pyhanko_value(name, "docmdp"), Some("raises"));
}

// ---- duplicate keys in what the signature signs (M4 QA round 2, finding 8) -------------------

/// A case whose signature dictionary or field declares DocMDP permissions with a duplicate key:
/// `SigDictAmbiguous` and `DocMdpInvalid`, no `docmdp`, `P = 1` in force (pyHanko reads the
/// first value, here 1), so the later change makes `docmdp_ok` false, at `modification`.
fn assert_dupkey_declaration(name: &str, modification: ModificationLevel) {
    let r = signature1(&certified_case(name));
    assert!(r.intact && r.signature_valid, "{name}: {}", summary(&r));
    for code in [ProblemCode::DocMdpInvalid, ProblemCode::SigDictAmbiguous] {
        assert!(r.has_problem(code), "{name}: {code}: {:?}", r.problems);
    }
    assert!(
        r.problems
            .iter()
            .any(|p| p.message.contains("written twice")),
        "{name}: {:?}",
        r.problems
    );
    assert!(!r.is_valid(), "{name}");
    assert_eq!(r.docmdp, None, "{name}");
    assert_eq!(r.modification, modification, "{name}: {:?}", r.warnings);
    assert_eq!(r.docmdp_ok, Some(false), "{name}: P = 1 is in force");
    assert_eq!(
        our_value(name, "docmdpOk"),
        None,
        "{name}: equal to pyHanko"
    );
}

#[test]
fn docmdp_dupkey_reference_then_fill() {
    // QA variant C3-r2-dupkey-reference-p1-first-p3-last-then-fill: ours read P = 3 last-wins
    // (docmdp_ok true), pyHanko P = 1 first-wins (false).
    assert_dupkey_declaration("docmdp_dupkey_reference_then_fill", FormFilling);
}

#[test]
fn docmdp_dupkey_transform_params_p_then_fill() {
    // QA variant C3-r2-dupkey-p-in-params-p1-first: `/P 1 /P 3` inside /TransformParams.
    assert_dupkey_declaration("docmdp_dupkey_transform_params_p_then_fill", FormFilling);
}

#[test]
fn docmdp_dupkey_reference_in_approval_then_fill() {
    // QA variant C3-r2-dupkey-reference-in-approval-p1-first-then-fill: no /Perms; ours read
    // P = 2 (true), pyHanko the first /Reference's P = 1 (false).
    assert_dupkey_declaration("docmdp_dupkey_reference_in_approval_then_fill", FormFilling);
}

#[test]
fn lock_dupkey_p1_first_then_invisible_approval() {
    // QA variant C3-r2-dupkey-lock-p1-first-p3-last: the field's /Lock written twice.
    assert_dupkey_declaration("lock_dupkey_p1_first_then_invisible_approval", FormFilling);
}

#[test]
fn dupkey_byterange_fake_first() {
    // QA variants C3-r2-dupkey-byterange-fake-first-in-sigdict and -cert1: a fake /ByteRange
    // first and the real one last. pyHanko digests the first (not intact) and `openssl cms
    // -verify` of the first range fails; Folioxide read the last and called it intact. Neither
    // reading is trusted now: not intact, coverage unclear, Other.
    let r = signature1(&certified_case("dupkey_byterange_fake_first"));
    assert!(!r.intact, "{}", summary(&r));
    assert!(
        r.has_problem(ProblemCode::SigDictAmbiguous),
        "{:?}",
        r.problems
    );
    assert!(!r.byte_range_ok && !r.is_valid());
    assert_eq!(r.coverage, folioxide_sign::report::Coverage::Unclear);
    assert_eq!(r.modification, Other);
    assert_eq!(r.docmdp, Some(1));
    assert_eq!(r.docmdp_ok, Some(false));
    assert_ne!(r.trusted, Some(true));
}

#[test]
fn signing_on_top_of_an_ambiguous_declaration_is_refused() {
    // The signing side reads the duplicate key as pyHanko's first value would and as the
    // verifier does: P = 1 (rule (b)), so Folioxide refuses to sign on top.
    for name in [
        "docmdp_dupkey_reference_then_fill",
        "docmdp_dupkey_transform_params_p_then_fill",
        "docmdp_dupkey_reference_in_approval_then_fill",
        "lock_dupkey_p1_first_then_invisible_approval",
    ] {
        let doc = sign_support::open(&certified_case(name));
        let signer = sign_support::p256();
        let err = folioxide_sign::sign::sign(
            &doc,
            &folioxide_sign::sign::SignRequest::new(&signer, sign_support::time()),
        )
        .unwrap_err();
        assert!(
            matches!(err, folioxide_sign::Error::DocMdpForbids(_)),
            "{name}: {err}"
        );
    }
}

#[test]
fn signing_on_top_of_a_malformed_certification_is_refused() {
    // R-6, signing side: an unreadable declaration counts as P = 1 (rule (b)), never 2.
    for name in [
        "docmdp_reference_not_array",
        "docmdp_reference_without_transform_method",
        "docmdp_p_out_of_range",
        "docmdp_p_huge_integer",
        "docmdp_p_not_an_integer",
        "docmdp_two_references",
    ] {
        let doc = sign_support::open(&certified_case(name));
        let signer = sign_support::p256();
        let err = folioxide_sign::sign::sign(
            &doc,
            &folioxide_sign::sign::SignRequest::new(&signer, sign_support::time()),
        )
        .unwrap_err();
        assert!(
            matches!(err, folioxide_sign::Error::DocMdpForbids(_)),
            "{name}: {err}"
        );
    }
    // A missing /P is 2: an invisible approval is allowed.
    let doc = sign_support::open(&certified_case("docmdp_p_missing"));
    let signer = sign_support::p256();
    folioxide_sign::sign::sign(
        &doc,
        &folioxide_sign::sign::SignRequest::new(&signer, sign_support::time()),
    )
    .unwrap();
}

// ---- the named classifier tests of brief §6.2 -------------------------------------------------

#[test]
fn p3_annotation_after_certify_classified_annotations() {
    // D-1: P = 3 permits annotation creation (ISO 32000-2 Table 257).
    for name in [
        "certify_p3_text_popup",
        "certify_p3_highlight",
        "certify_p3_square",
        "certify_p3_ink",
        "certify_p3_freetext",
        "certify_p3_stamp",
        "certify_p3_reply",
    ] {
        let r = signature1(&certified_case(name));
        assert_eq!(r.modification, Annotations, "{name}: {}", summary(&r));
        assert_eq!(r.docmdp_ok, Some(true), "{name}");
        assert!(r.is_acceptable(Annotations), "{name}");
        assert!(!r.is_acceptable(FormFilling), "{name}");
    }
}

#[test]
fn p2_annotation_after_certify_docmdp_not_ok() {
    let r = signature1(&certified_case("certify_p2_annotation"));
    assert_eq!(r.docmdp, Some(2));
    assert_eq!(r.docmdp_ok, Some(false), "{}", summary(&r));
    assert!(
        !r.is_acceptable(Other),
        "D-13: docmdp_ok false is never acceptable"
    );
}

#[test]
fn certification_new_visible_sig_field_other() {
    // C1: a new visible signature field after a certification is Other (pyHanko
    // valid_when_certifying=False); the same approval invisible, or in an existing field, is not.
    for (name, p) in [
        ("certify_p2_new_visible_approval", 2),
        ("certify_p3_new_visible_approval", 3),
        ("certify_p2_new_visible_field", 2),
    ] {
        assert_c1(name, p);
    }
    for name in ["certify_p2_approval", "certify_p2_existing_visible_signed"] {
        let r = signature1(&certified_case(name));
        assert_eq!(r.modification, FormFilling, "{name}: {}", summary(&r));
        assert_eq!(r.docmdp_ok, Some(true), "{name}");
    }
}

#[test]
fn p1_doc_timestamp_docmdp_ok() {
    // D-2: under P = 1 the classes Relisting, Orphan, XrefStream and DocTimeStamp are allowed.
    let r = signature1(&certified_case("certify_p1_doc_timestamp"));
    assert_eq!(r.modification, LtaUpdates, "{}", summary(&r));
    assert_eq!(r.docmdp_ok, Some(true));
    assert!(r.is_acceptable(LtaUpdates));
    let r = signature1(&certified_case("certify_p1_doc_timestamp_title_changed"));
    assert_eq!(r.docmdp_ok, Some(false));
}

#[test]
fn is_acceptable_requires_docmdp_ok() {
    // D-13: valid and within the caller's level, but the certification forbids it.
    let r = signature1(&certified_case("certify_p1_fill"));
    assert!(r.is_valid());
    assert!(r.modification <= FormFilling);
    assert_eq!(r.docmdp_ok, Some(false));
    assert!(!r.is_acceptable(FormFilling));
    assert!(!r.is_acceptable(Other));
    // The same fill under P = 2 is acceptable.
    let r = signature1(&certified_case("certify_p2_text_fill"));
    assert_eq!(r.docmdp_ok, Some(true));
    assert!(r.is_acceptable(FormFilling));
    assert!(!r.is_acceptable(LtaUpdates));
}

/// Every case of the certification corpus has its test above, and the deliberate rows that name
/// certification cases are the ones asserted above.
#[test]
fn every_certify_case_is_tested() {
    let source = include_str!("certify_corpus.rs");
    for case in certify_corpus() {
        let test = format!("fn {}()", case.name);
        assert!(source.contains(&test), "{} has no test", case.name);
    }
    let deliberate: Vec<&str> = DELIBERATE_DIFFERENCES
        .iter()
        .chain(MORE_LENIENT)
        .map(|(case, ..)| *case)
        .filter(|case| case.starts_with("certify_"))
        .collect();
    for case in deliberate {
        assert!(
            certify_corpus().iter().any(|c| c.name == case),
            "{case} is not a certification case"
        );
    }
}

// ---- M4 QA round 5: manager rulings R-18 and R-20 --------------------------------------------

/// The document timestamp `Timestamp1` of the case `name`, and the certification's report.
fn timestamp_then_markup(name: &str) -> (SignatureReport, SignatureReport) {
    let certification = signature1(&certified_case(name));
    let timestamp = field_report(name, "Timestamp1");
    assert_eq!(
        timestamp.kind,
        folioxide_sign::report::SignatureKind::DocTimeStamp,
        "{name}"
    );
    assert_eq!(timestamp.docmdp_ok, None, "{name}: ruling R-5");
    (certification, timestamp)
}

#[test]
fn certify_p2_doc_timestamp_then_markup() {
    // Ruling R-20 (finding 14, variant C2-r6-cert2-dts-square-eval-dts): the timestamp is judged
    // with the P = 2 in force, so the annotation is Other for it too (pyHanko: other), and
    // is_acceptable(Annotations) is false for every entry.
    let (certification, timestamp) = timestamp_then_markup("certify_p2_doc_timestamp_then_markup");
    assert_eq!(certification.modification, Other);
    assert_eq!(certification.docmdp_ok, Some(false));
    assert_eq!(timestamp.modification, Other, "{:?}", timestamp.warnings);
    assert!(
        timestamp.warnings.iter().any(|w| w.contains("R-20")),
        "{:?}",
        timestamp.warnings
    );
    assert!(!timestamp.is_acceptable(Annotations));
}

#[test]
fn certify_p1_doc_timestamp_then_markup() {
    // Variant C2-r2-cert1-dts-annot-eval-dts-null.
    let (certification, timestamp) = timestamp_then_markup("certify_p1_doc_timestamp_then_markup");
    assert_eq!(certification.modification, Other);
    assert_eq!(timestamp.modification, Other, "{:?}", timestamp.warnings);
    assert!(!timestamp.is_acceptable(Annotations));
}

#[test]
fn certify_p3_doc_timestamp_then_markup() {
    // The control (variant C2-r6-cert3-dts-square-eval-dts-control): under P = 3 the annotation
    // is Annotations for the timestamp too (D-1).
    let (certification, timestamp) = timestamp_then_markup("certify_p3_doc_timestamp_then_markup");
    assert_eq!(certification.modification, Annotations);
    assert_eq!(certification.docmdp_ok, Some(true));
    assert_eq!(
        timestamp.modification, Annotations,
        "{:?}",
        timestamp.warnings
    );
}

#[test]
fn approval_doc_timestamp_then_markup_is_other_for_the_timestamp() {
    // Ruling R-20 (variant C2-r6-approval-dts-square-eval-dts): without a certification P = 2 is
    // in force, so the timestamp's level is Other, while the approval keeps D-1's Annotations
    // with docmdp_ok false (M4 brief §0.2).
    let approved = sign_support::sign_default(
        &folioxide_testkit::fixtures::syntax::minimal(),
        &sign_support::rsa2048(),
    );
    let stamped =
        folioxide_testkit::fixtures::sign_attacks::doc_timestamp_like_pyhanko(&approved).unwrap();
    let pdf = folioxide_testkit::fixtures::sign_attacks::markup_square(&stamped).unwrap();
    let reports = verify_plain(&pdf);
    let approval = reports
        .iter()
        .find(|r| r.field_name.as_deref() == Some("Signature1"))
        .unwrap();
    let timestamp = reports
        .iter()
        .find(|r| r.field_name.as_deref() == Some("Timestamp1"))
        .unwrap();
    assert_eq!(
        approval.modification, Annotations,
        "{:?}",
        approval.warnings
    );
    assert_eq!(approval.docmdp_ok, Some(false));
    assert_eq!(timestamp.modification, Other, "{:?}", timestamp.warnings);
    assert_eq!(timestamp.docmdp_ok, None);
    assert!(!timestamp.is_acceptable(Annotations));
}

#[test]
fn certify_p1_objstm_member_unlisted() {
    // Ruling R-18 (finding 27): stricter than pyHanko's ltaUpdates/true.
    let r = signature1(&certified_case("certify_p1_objstm_member_unlisted"));
    assert!(r.is_valid(), "{}", summary(&r));
    assert_eq!(r.modification, Other, "{:?}", r.warnings);
    assert_eq!(r.docmdp, Some(1));
    assert_eq!(r.docmdp_ok, Some(false));
    assert!(
        r.warnings.iter().any(|w| w.contains("R-18")),
        "{:?}",
        r.warnings
    );
    assert_eq!(
        our_value("certify_p1_objstm_member_unlisted", "docmdpOk"),
        Some("false")
    );
    assert_eq!(
        pyhanko_value("certify_p1_objstm_member_unlisted", "modification"),
        Some("ltaUpdates")
    );
}

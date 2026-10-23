#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! V11 (M4 brief §5): what a signature declares about DocMDP, on raw signatures that Folioxide's
//! signing API would not write (`sign_raw`): `/P` absent, out of range or not an integer, two
//! DocMDP references, no `/TransformParams`, a `/V` other than `/1.2`, a `/Perms` that does not
//! name the signature, and a certification that is not the first signature
//! (`CertificationNotFirst`).

mod sign_support;

use folioxide_sign::ProblemCode;
use folioxide_sign::docmdp::DocMdpPermissions;
use folioxide_sign::report::{ModificationLevel, SignatureReport};
use folioxide_syntax::{Dict, Object};
use folioxide_testkit::fixtures::syntax;
use sign_support::corpus::certify;
use sign_support::*;

/// A DocMDP signature reference dictionary with the transform parameters `params` (`None`:
/// no `/TransformParams`).
fn docmdp_reference(params: Option<Vec<(&str, Object)>>) -> Object {
    let mut reference = Dict::new();
    reference.insert("Type", Object::name("SigRef"));
    reference.insert("TransformMethod", Object::name("DocMDP"));
    if let Some(params) = params {
        let mut dict = Dict::new();
        dict.insert("Type", Object::name("TransformParams"));
        for (key, value) in params {
            dict.insert(key, value);
        }
        reference.insert("TransformParams", Object::Dict(dict));
    }
    Object::Dict(reference)
}

/// `minimal.pdf` signed raw with the `/Reference` array `references`, named in the catalog's
/// `/Perms /DocMDP` when `perms`; the report of that signature.
fn raw_certification(references: Vec<Object>, perms: bool) -> SignatureReport {
    raw_on(&syntax::minimal(), references, perms)
}

/// [`raw_certification`] on `source`.
fn raw_on(source: &[u8], references: Vec<Object>, perms: bool) -> SignatureReport {
    let pdf = sign_raw(
        source,
        &rsa2048(),
        &RawSignature {
            name: "Raw1".to_owned(),
            sig: vec![("Reference", Object::Array(references))],
            perms,
            ..RawSignature::default()
        },
    );
    verify_plain(&pdf)
        .into_iter()
        .find(|r| r.field_name.as_deref() == Some("Raw1"))
        .expect("Raw1 is listed")
}

/// The transform parameters `/P p /V /1.2`.
fn params(p: Object) -> Option<Vec<(&'static str, Object)>> {
    Some(vec![("P", p), ("V", Object::name("1.2"))])
}

#[test]
fn docmdp_raw_certification_is_read() {
    // The control: a raw P = 1 certification reads as Folioxide's own.
    let r = raw_certification(vec![docmdp_reference(params(Object::Int(1)))], true);
    assert!(r.is_valid(), "{}", summary(&r));
    assert_eq!(r.docmdp, Some(1));
    assert_eq!(r.docmdp_ok, Some(true));
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

#[test]
fn docmdp_p_absent_means_2() {
    // ISO 32000-2 Table 257: /P is optional, default 2.
    let r = raw_certification(
        vec![docmdp_reference(Some(vec![("V", Object::name("1.2"))]))],
        true,
    );
    assert!(r.is_valid(), "{}", summary(&r));
    assert_eq!(r.docmdp, Some(2));
}

#[test]
fn docmdp_p_out_of_range_invalid() {
    for p in [0, 4, -1] {
        let r = raw_certification(vec![docmdp_reference(params(Object::Int(p)))], true);
        assert!(r.has_problem(ProblemCode::DocMdpInvalid), "P = {p}");
        assert_eq!(r.docmdp, None, "P = {p}");
        assert!(!r.is_valid(), "P = {p}");
        assert!(!r.is_acceptable(ModificationLevel::Other), "P = {p}");
    }
}

#[test]
fn docmdp_p_not_integer_invalid() {
    for p in [
        Object::Real(2.0),
        Object::name("2"),
        Object::literal_string("2"),
    ] {
        let r = raw_certification(vec![docmdp_reference(params(p.clone()))], true);
        assert!(r.has_problem(ProblemCode::DocMdpInvalid), "{p:?}");
        assert_eq!(r.docmdp, None, "{p:?}");
    }
}

#[test]
fn docmdp_transform_params_missing_invalid() {
    let r = raw_certification(vec![docmdp_reference(None)], true);
    assert!(r.has_problem(ProblemCode::DocMdpInvalid), "{}", summary(&r));
}

#[test]
fn docmdp_two_references_invalid() {
    let r = raw_certification(
        vec![
            docmdp_reference(params(Object::Int(2))),
            docmdp_reference(params(Object::Int(3))),
        ],
        true,
    );
    assert!(r.has_problem(ProblemCode::DocMdpInvalid), "{}", summary(&r));
    assert_eq!(r.docmdp, None);
}

#[test]
fn docmdp_invalid_declaration_is_judged_as_p1() {
    // C2: a certification whose permissions cannot be read is held to P = 1 (fail safe).
    let pdf = sign_raw(
        &syntax::minimal(),
        &rsa2048(),
        &RawSignature {
            name: "Raw1".to_owned(),
            sig: vec![(
                "Reference",
                Object::Array(vec![docmdp_reference(params(Object::Int(7)))]),
            )],
            perms: true,
            ..RawSignature::default()
        },
    );
    let changed = folioxide_testkit::fixtures::sign_attacks::isa_info_only(&pdf).unwrap();
    let r = verify_plain(&changed)
        .into_iter()
        .find(|r| r.field_name.as_deref() == Some("Raw1"))
        .unwrap();
    assert_eq!(
        r.modification,
        ModificationLevel::LtaUpdates,
        "{}",
        summary(&r)
    );
    assert_eq!(r.docmdp_ok, Some(false));
}

#[test]
fn docmdp_version_other_than_1_2_warns() {
    let r = raw_certification(
        vec![docmdp_reference(Some(vec![
            ("P", Object::Int(2)),
            ("V", Object::name("1.1")),
        ]))],
        true,
    );
    assert_eq!(r.docmdp, Some(2));
    assert!(r.is_valid(), "{}", summary(&r));
    assert!(
        r.warnings.iter().any(|w| w.contains("/V is /1.1")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn docmdp_perms_not_naming_the_signature_warns() {
    let r = raw_certification(vec![docmdp_reference(params(Object::Int(2)))], false);
    assert_eq!(r.docmdp, Some(2));
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("/Perms /DocMDP does not name")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn docmdp_certification_not_first() {
    // An approval first, then a (raw) certification: §12.8.2.2.1, a certification signature
    // shall be the first signed field.
    let approved = sign_default(&syntax::minimal(), &p256());
    let r = raw_on(
        &approved,
        vec![docmdp_reference(params(Object::Int(2)))],
        true,
    );
    assert!(
        r.has_problem(ProblemCode::CertificationNotFirst),
        "{}",
        summary(&r)
    );
    assert!(!r.is_valid());
    // The approval before it is not judged by the late certification (C2: only certifications
    // that end before the signature count). Without /Perms the catalog stays unchanged, so the
    // late revision only adds a signature.
    let reports = verify_plain(&sign_raw(
        &approved,
        &rsa2048(),
        &RawSignature {
            name: "Raw1".to_owned(),
            sig: vec![(
                "Reference",
                Object::Array(vec![docmdp_reference(params(Object::Int(1)))]),
            )],
            perms: false,
            ..RawSignature::default()
        },
    ));
    let first = reports
        .iter()
        .find(|r| r.field_name.as_deref() == Some("Signature1"))
        .unwrap();
    assert_eq!(first.docmdp, None);
    assert_eq!(first.modification, ModificationLevel::FormFilling);
    assert_eq!(
        first.docmdp_ok,
        Some(true),
        "P = 2 by default, not the later P = 1"
    );
}

#[test]
fn docmdp_approval_after_p1_is_judged_by_p1() {
    // C2: an approval signed after a P = 1 certification is judged by P = 1: a form fill after
    // it is not allowed (raw approval, since Folioxide refuses to sign after P = 1).
    let certified = certify(
        &folioxide_testkit::fixtures::forms::acroform(),
        DocMdpPermissions::NoChanges,
    );
    let approved = sign_raw(
        &certified,
        &p256(),
        &RawSignature {
            name: "Approval".to_owned(),
            ..RawSignature::default()
        },
    );
    let filled =
        folioxide_testkit::fixtures::sign_attacks::form_fill_text_value_and_ap(&approved).unwrap();
    let reports = verify_plain(&filled);
    let approval = reports
        .iter()
        .find(|r| r.field_name.as_deref() == Some("Approval"))
        .unwrap();
    assert_eq!(approval.docmdp, None);
    assert_eq!(
        approval.modification,
        ModificationLevel::FormFilling,
        "{}",
        summary(approval)
    );
    assert_eq!(approval.docmdp_ok, Some(false));
    assert!(!approval.is_acceptable(ModificationLevel::FormFilling));
}

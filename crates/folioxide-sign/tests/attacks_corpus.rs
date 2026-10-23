#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The defences against the published PDF-signature attack classes (M3 brief §5.1): one test per
//! case of the corpus, each asserting what Folioxide reports (the "Ours" column) on a really
//! signed file attacked by the stage-1 generators of `folioxide_testkit::fixtures::sign_attacks`.
//! Deliberate differences from pyHanko come from the single `DELIBERATE_DIFFERENCES` table.

mod sign_support;

use folioxide_sign::ProblemCode;
use folioxide_sign::report::{Coverage, ModificationLevel, SignatureReport};
use folioxide_sign::signer::Signer;
use folioxide_syntax::{Dict, IncrementalOptions, Object, ObjectId, OpenOptions, Store};
use folioxide_testkit::fixtures::{sign_attacks as mutators, syntax};
use sign_support::corpus::{
    COSIGNER_FIELD, DELIBERATE_DIFFERENCES, LATER_SIGNER_FIELDS, MORE_LENIENT, PYHANKO_RAISES,
    Reference, attacked, certify_corpus, corpus, our_value, pyhanko_raises, signed_base,
};
use sign_support::*;

/// The report of the signature field `Signature1` after the attack `name`.
fn field_report(name: &str) -> SignatureReport {
    verify_plain(&attacked(name))
        .into_iter()
        .find(|r| r.field_name.as_deref() == Some("Signature1"))
        .unwrap_or_else(|| panic!("{name}: Signature1 is listed"))
}

/// Every report after the attack `name`.
fn all_reports(name: &str) -> Vec<SignatureReport> {
    verify_plain(&attacked(name))
}

/// The USF dictionary checks: listed, structurally broken, not intact, not valid.
fn assert_usf_structural(name: &str, codes: &[ProblemCode]) {
    let r = field_report(name);
    let s = summary(&r);
    assert!(!r.byte_range_ok, "{name}: {s}");
    assert!(!r.intact, "{name}: {s}");
    assert!(!r.is_valid(), "{name}: {s}");
    assert!(
        codes.iter().any(|&c| r.has_problem(c)),
        "{name}: {s}, want one of {codes:?}"
    );
    assert_eq!(r.pades_level, None, "{name}");
    assert_eq!(r.modification, ModificationLevel::Other, "{name}");
}

/// The USF `/Contents` cases also have no valid signature.
fn assert_usf_contents(name: &str, codes: &[ProblemCode]) {
    assert_usf_structural(name, codes);
    assert!(!field_report(name).signature_valid, "{name}");
}

/// A CMS-level USF case: the signature is not valid and says why.
fn assert_usf_cms(name: &str, codes: &[ProblemCode]) {
    let r = field_report(name);
    let s = summary(&r);
    assert!(!r.signature_valid, "{name}: {s}");
    assert!(!r.is_valid(), "{name}: {s}");
    assert!(
        codes.iter().any(|&c| r.has_problem(c)),
        "{name}: {s}, want one of {codes:?}"
    );
    assert_eq!(r.pades_level, None, "{name}");
}

/// An appended revision after an intact, valid signature: the signed revision is still
/// covered, and the modification level is `level`.
fn assert_revision(name: &str, level: ModificationLevel) -> SignatureReport {
    let r = field_report(name);
    let s = summary(&r);
    let base = corpus().into_iter().find(|c| c.name == name).unwrap().base;
    assert!(r.intact && r.signature_valid, "{name}: {s}");
    assert_eq!(r.coverage, Coverage::EntireRevision, "{name}: {s}");
    assert_eq!(r.signed_revision, Some(base.signed_revision()), "{name}");
    assert_eq!(r.modification, level, "{name}: {s} {:?}", r.warnings);
    r
}

/// An attack that changed what the signature covers: the signature over its revision is
/// still sound, but the document is not acceptable (`modification` is `Other`).
fn assert_changed_after_signing(name: &str) -> SignatureReport {
    let r = assert_revision(name, ModificationLevel::Other);
    assert!(r.is_valid(), "{name}: the signed revision itself is intact");
    assert!(
        !r.is_acceptable(ModificationLevel::FormFilling),
        "{name}: never acceptable"
    );
    r
}

/// Our value for a deliberate difference, parsed as a modification level.
fn deliberate_modification(name: &str) -> ModificationLevel {
    match our_value(name, "modification") {
        Some("other") => ModificationLevel::Other,
        Some("formFilling") => ModificationLevel::FormFilling,
        other => panic!("{name}: no deliberate modification difference ({other:?})"),
    }
}

/// A deliberately stricter `Other` whose warnings name `needle`.
fn assert_deliberately_other(name: &str, needle: &str) -> SignatureReport {
    let r = assert_changed_after_signing(name);
    assert_eq!(r.modification, deliberate_modification(name), "{name}");
    assert!(
        r.warnings.iter().any(|w| w.contains(needle)),
        "{name}: no warning names {needle:?}: {:?}",
        r.warnings
    );
    r
}

#[test]
fn deliberate_differences_are_stricter_and_name_real_cases() {
    let names: Vec<&str> = corpus()
        .iter()
        .map(|c| c.name)
        .chain(certify_corpus().iter().map(|c| c.name))
        .collect();
    let coverage_rank = |c: &str| match c {
        "entireFile" => 3,
        "entireRevision" => 2,
        "contiguousBlockFromStart" => 1,
        "unclear" => 0,
        other => panic!("coverage {other}"),
    };
    let modification_rank = |m: &str| match m {
        "none" => 0,
        "ltaUpdates" => 1,
        "formFilling" => 2,
        "annotations" => 3,
        "other" => 4,
        other => panic!("modification {other}"),
    };
    for (case, field, ours, pyhanko, reason) in DELIBERATE_DIFFERENCES {
        assert!(names.contains(case), "{case} is not a corpus case");
        assert!(!reason.is_empty());
        match *field {
            "coverage" => assert!(coverage_rank(ours) < coverage_rank(pyhanko), "{case}"),
            "modification" => {
                assert!(
                    modification_rank(ours) > modification_rank(pyhanko),
                    "{case}"
                );
            }
            // `docmdp_ok`: `false` is the stricter verdict.
            "docmdpOk" => assert_eq!((*ours, *pyhanko), ("false", "true"), "{case}"),
            // Manager ruling R-6: the one row where pyHanko raises and Folioxide reads the ISO
            // default (a missing /P is 2), recorded and pinned by knownFailures.
            "docmdp" => {
                assert_eq!(
                    (*case, *ours, *pyhanko),
                    ("docmdp_p_missing", "2", "raises")
                );
                assert!(reason.starts_with("R-6"), "{case}: {reason}");
            }
            other => panic!("{case}: field {other}"),
        }
    }
}

/// D-1 (M4 brief §0.2) is the only deliberate difference where Folioxide is more lenient than
/// pyHanko: markup annotations reported `Annotations` (pyHanko: `OTHER`) and, under `P = 3`,
/// `docmdp_ok` true (pyHanko: false). Every row names a real case and nothing else.
#[test]
fn more_lenient_rows_are_d1_annotations_only() {
    let names: Vec<&str> = corpus()
        .iter()
        .map(|c| c.name)
        .chain(certify_corpus().iter().map(|c| c.name))
        .collect();
    for (case, field, ours, pyhanko, reason) in MORE_LENIENT {
        assert!(names.contains(case), "{case} is not a corpus case");
        assert!(reason.starts_with("D-1"), "{case}: {reason}");
        // `<field name>.<field>` rows are another signature's (manager ruling R-7: the approval
        // after a P = 3 certification).
        let key: &str = match field.split_once('.') {
            Some((signature, key)) => {
                assert_eq!(signature, "Approval", "{case}");
                assert_eq!(*case, "certify_p3_approval_then_markup", "{case}");
                key
            }
            None => field,
        };
        match key {
            "modification" => assert_eq!((*ours, *pyhanko), ("annotations", "other"), "{case}"),
            "docmdpOk" => {
                assert_eq!((*ours, *pyhanko), ("true", "false"), "{case}");
                assert!(
                    case.starts_with("certify_p3_"),
                    "{case}: only P = 3 grants it"
                );
            }
            other => panic!("{case}: field {other}"),
        }
        assert!(
            !DELIBERATE_DIFFERENCES
                .iter()
                .any(|(c, f, ..)| c == case && f == field),
            "{case}: {field} is in both tables"
        );
    }
}

#[test]
fn every_generator_applies_and_no_attack_is_valid() {
    for case in corpus() {
        let pdf = attacked(case.name);
        let reports = verify_plain(&pdf);
        assert!(
            !reports.is_empty(),
            "{}: the signature is never omitted",
            case.name
        );
        // The attacked signature is never reported valid with no modification (a co-signer's
        // own, later signature may be).
        let unchanged_valid = reports.iter().any(|r| {
            !r.field_name
                .as_deref()
                .is_some_and(|f| LATER_SIGNER_FIELDS.contains(&f))
                && r.is_valid()
                && r.modification == ModificationLevel::None
                && r.problems.is_empty()
        });
        assert!(
            !unchanged_valid,
            "{}: {:?}",
            case.name,
            reports.iter().map(summary).collect::<Vec<_>>()
        );
        if case.reference == Reference::Rejected {
            assert!(
                reports
                    .iter()
                    .all(|r| !r.is_valid() || r.modification == ModificationLevel::Other),
                "{}",
                case.name
            );
        }
        if case.reference == Reference::PyhankoRaises {
            // The signed bytes are untouched (pdfsig and OpenSSL validate them); the attack is
            // the unattributable structure after them, or (M4 QA round 3, ruling R-12) a
            // number spelled with two signs, which pyHanko cannot read either.
            assert!(pyhanko_raises(case.name).is_some(), "{}", case.name);
            let r = &reports[0];
            assert!(
                r.intact && r.signature_valid,
                "{}: {}",
                case.name,
                summary(r)
            );
            assert_eq!(r.modification, ModificationLevel::Other, "{}", case.name);
            if case.name.starts_with("isa_") {
                assert!(
                    r.has_problem(ProblemCode::StructureRepaired),
                    "{}",
                    case.name
                );
                assert!(!r.is_valid(), "{}", case.name);
            }
        }
    }
}

// ---- USF: the dictionary and the byte range (V3, V4) ---------------------------------------------

#[test]
fn attacks_usf_contents_missing() {
    assert_usf_contents("usf_contents_missing", &[ProblemCode::ContentsMissing]);
}

#[test]
fn attacks_usf_contents_null() {
    assert_usf_contents(
        "usf_contents_null",
        &[ProblemCode::ContentsNotHex, ProblemCode::ContentsMissing],
    );
}

#[test]
fn attacks_usf_contents_empty_hex() {
    assert_usf_contents(
        "usf_contents_empty_hex",
        &[ProblemCode::GapNotContents, ProblemCode::CmsMalformed],
    );
}

#[test]
fn attacks_usf_contents_literal_string() {
    assert_usf_contents(
        "usf_contents_literal_string",
        &[ProblemCode::ContentsNotHex],
    );
}

#[test]
fn attacks_usf_byterange_missing() {
    assert_usf_structural("usf_byterange_missing", &[ProblemCode::ByteRangeMissing]);
    assert_eq!(field_report("usf_byterange_missing").byte_range, None);
}

#[test]
fn attacks_usf_byterange_null() {
    assert_usf_structural("usf_byterange_null", &[ProblemCode::ByteRangeMalformed]);
}

#[test]
fn attacks_usf_byterange_two_values() {
    assert_usf_structural(
        "usf_byterange_two_values",
        &[ProblemCode::ByteRangeMalformed],
    );
    assert_eq!(
        field_report("usf_byterange_two_values").coverage,
        Coverage::Unclear
    );
}

#[test]
fn attacks_usf_byterange_negative() {
    assert_usf_structural("usf_byterange_negative", &[ProblemCode::ByteRangeMalformed]);
}

#[test]
fn attacks_usf_byterange_not_from_zero() {
    assert_usf_structural(
        "usf_byterange_not_from_zero",
        &[ProblemCode::ByteRangeNotFromZero],
    );
    assert_eq!(
        field_report("usf_byterange_not_from_zero").coverage,
        Coverage::Unclear
    );
}

#[test]
fn attacks_usf_byterange_past_eof() {
    assert_usf_structural(
        "usf_byterange_past_eof",
        &[ProblemCode::ByteRangeOutOfBounds],
    );
}

#[test]
fn attacks_usf_byterange_reals() {
    assert_usf_structural("usf_byterange_reals", &[ProblemCode::ByteRangeMalformed]);
    assert_eq!(field_report("usf_byterange_reals").byte_range, None);
}

#[test]
fn attacks_usf_byterange_indirect() {
    assert_usf_structural("usf_byterange_indirect", &[ProblemCode::ByteRangeIndirect]);
}

#[test]
fn attacks_usf_byterange_zeroes() {
    assert_usf_structural("usf_byterange_zeroes", &[ProblemCode::ByteRangeMalformed]);
}

// ---- USF: the SubFilter and the CMS (V2, V7) -----------------------------------------------------

#[test]
fn attacks_usf_subfilter_unknown() {
    assert_usf_cms(
        "usf_subfilter_unknown",
        &[ProblemCode::UnsupportedSubFilter],
    );
}

#[test]
fn attacks_usf_cms_garbage() {
    assert_usf_cms("usf_cms_garbage", &[ProblemCode::CmsMalformed]);
    assert!(!field_report("usf_cms_garbage").intact);
}

/// The CMS of the signature after the attack `name`, re-parsed: the generator really made the
/// structural change it names, and the byte ranges are untouched.
fn attacked_cms(name: &str) -> folioxide_sign::cms::ParsedCms {
    let pdf = attacked(name);
    let base = folioxide_sign::cms::parse(&signature_cms(&signed_base())).unwrap();
    let r = field_report(name);
    assert_eq!(pdf.len(), signed_base().len(), "{name}: same placeholder");
    assert_eq!(r.coverage, Coverage::EntireFile, "{name}: {}", summary(&r));
    assert!(r.byte_range_ok, "{name}: {}", summary(&r));
    let cms = folioxide_sign::cms::parse(&signature_cms(&pdf)).unwrap();
    assert_eq!(base.signer_infos.len(), 1);
    assert!(!base.certificates.is_empty() && base.econtent.is_none());
    cms
}

/// The DER in the `/Contents` of the (only) signature of `pdf`, padding included.
fn signature_cms(pdf: &[u8]) -> Vec<u8> {
    let range = verify_plain(pdf)[0].byte_range.clone().unwrap();
    let (a, b) = (range[1] as usize, range[2] as usize);
    let hex = &pdf[a + 1..b - 1];
    hex.chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn attacks_usf_cms_two_signerinfos() {
    let name = "usf_cms_two_signerinfos";
    assert_eq!(attacked_cms(name).signer_infos.len(), 2);
    assert_usf_cms(name, &[ProblemCode::SignerInfoCount]);
    let r = field_report(name);
    // The first SignerInfo is the real one: only the count makes the signature invalid.
    assert_eq!(r.problems.len(), 1, "{}", summary(&r));
    assert_eq!(verify(&attacked(name))[0].trusted, Some(false));
}

#[test]
fn attacks_usf_cms_no_certificates() {
    let name = "usf_cms_no_certificates";
    assert!(attacked_cms(name).certificates.is_empty());
    assert_usf_cms(name, &[ProblemCode::SignerCertNotFound]);
    let r = field_report(name);
    assert!(r.signer.is_none() && r.chain.is_empty(), "{}", summary(&r));
    // With the signer certificate passed in, the signature verifies again, but a CMS without
    // its signing certificate is never PAdES B-B (brief §4.6).
    let with_cert = folioxide_sign::verify_pdf::verify_bytes(
        attacked(name),
        &folioxide_sign::verify_pdf::VerifyOptions::new()
            .with_extra_certs_der(rsa2048().certificate_chain().to_vec()),
    )
    .unwrap();
    let r = &with_cert[0];
    assert!(r.intact && r.signature_valid, "{}", summary(r));
    assert_eq!(r.pades_level, None);
}

#[test]
fn attacks_usf_cms_econtent_present() {
    let name = "usf_cms_econtent_present";
    assert!(attacked_cms(name).econtent.is_some());
    assert_usf_cms(name, &[ProblemCode::EContentPresent]);
}

#[test]
fn attacks_usf_ess_mismatch() {
    // The stage-1 generator corrupts the signing-certificate-v2 attribute inside the signed
    // attributes, so the signature over them no longer verifies (pyHanko: valid False too).
    assert_usf_cms(
        "usf_ess_mismatch",
        &[
            ProblemCode::SigningCertificateMismatch,
            ProblemCode::SignatureInvalid,
        ],
    );
    let r = field_report("usf_ess_mismatch");
    assert!(
        r.intact,
        "the document bytes are untouched: {}",
        summary(&r)
    );
    assert_eq!(r.coverage, Coverage::EntireFile);
}

#[test]
fn attacks_usf_content_type_missing() {
    assert_usf_cms(
        "usf_content_type_missing",
        &[ProblemCode::ContentTypeMismatch],
    );
}

// ---- ISA: appended revisions (V5, V10) -----------------------------------------------------------

#[test]
fn attacks_isa_classic_content_replaced() {
    let r = assert_revision("isa_classic_content_replaced", ModificationLevel::Other);
    assert!(
        r.changed_objects.contains(&ObjectId::new(4, 0)),
        "{:?}",
        r.changed_objects
    );
    assert!(
        r.is_valid(),
        "the signed revision itself is intact: {}",
        summary(&r)
    );
}

#[test]
fn attacks_isa_objects_without_xref() {
    let name = "isa_objects_without_xref";
    let r = assert_revision(name, deliberate_modification(name));
    assert!(
        r.has_problem(ProblemCode::StructureRepaired),
        "{}",
        summary(&r)
    );
    assert!(
        r.problems[0].message.contains("UnreferencedUpdate"),
        "{}",
        r.problems[0]
    );
}

#[test]
fn attacks_isa_xref_without_trailer() {
    let name = "isa_xref_without_trailer";
    let r = assert_revision(name, deliberate_modification(name));
    assert!(r.has_problem(ProblemCode::StructureRepaired));
}

#[test]
fn attacks_isa_bad_startxref_update() {
    let r = field_report("isa_bad_startxref_update");
    let s = summary(&r);
    // The signed bytes are untouched: pdfsig and OpenSSL validate them, and so do we.
    assert!(r.intact && r.signature_valid, "{s}");
    assert_eq!(r.modification, ModificationLevel::Other, "{s}");
    assert!(r.has_problem(ProblemCode::StructureRepaired), "{s}");
    assert!(
        r.problems
            .iter()
            .any(|p| p.message.contains("UnreferencedUpdate")),
        "{s}"
    );
    assert!(!r.is_valid());
    assert_eq!(
        verify(&attacked("isa_bad_startxref_update"))[0].trusted,
        Some(true),
        "the signer is still trusted; the document is not"
    );
}

#[test]
fn attacks_isa_prev_skips_signed_revision() {
    let r = field_report("isa_prev_skips_signed_revision");
    let s = summary(&r);
    assert!(r.intact && r.signature_valid, "{s}");
    assert_eq!(r.coverage, Coverage::ContiguousBlockFromStart, "{s}");
    assert!(r.has_problem(ProblemCode::SignedRevisionNotInChain), "{s}");
    assert!(r.has_problem(ProblemCode::StructureRepaired), "{s}");
    assert_eq!(r.modification, ModificationLevel::Other);
    assert!(!r.byte_range_ok && !r.is_valid());
}

#[test]
fn pyhanko_raises_table_names_real_cases() {
    let cases = corpus();
    for (name, reason) in PYHANKO_RAISES {
        let case = cases.iter().find(|c| c.name == *name).unwrap();
        assert_eq!(case.reference, Reference::PyhankoRaises, "{name}");
        assert!(!reason.is_empty());
    }
    for case in &cases {
        assert_eq!(
            case.reference == Reference::PyhankoRaises,
            pyhanko_raises(case.name).is_some(),
            "{}",
            case.name
        );
    }
}

#[test]
fn attacks_isa_free_object() {
    let r = assert_revision("isa_free_object", ModificationLevel::Other);
    assert!(
        r.changed_objects.iter().any(|id| id.num == 4),
        "{:?}",
        r.changed_objects
    );
}

#[test]
fn attacks_isa_relist_identical() {
    let r = assert_revision("isa_relist_identical", ModificationLevel::LtaUpdates);
    assert!(r.is_valid());
}

#[test]
fn attacks_isa_info_only() {
    let r = assert_revision("isa_info_only", ModificationLevel::LtaUpdates);
    assert!(r.is_valid());
}

#[test]
fn attacks_isa_hybrid_table_vs_xrefstm() {
    // Expert finding 13: a real hybrid update, well formed, whose table and cross-reference
    // stream disagree about the page content (pyHanko reads the table: LTA_UPDATES).
    let name = "isa_hybrid_table_vs_xrefstm";
    let pdf = attacked(name);
    let doc = open(&pdf);
    let store = doc.store();
    assert!(!store.structure_repaired(), "a well-formed file");
    let newest = store.revisions().last().unwrap();
    assert!(newest.xref_stm.is_some(), "a hybrid section");
    let r = assert_revision(name, deliberate_modification(name));
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("table and its stream disagree")),
        "{:?}",
        r.warnings
    );
    assert!(r.is_valid() && !r.is_acceptable(ModificationLevel::Annotations));
}

#[test]
fn attacks_isa_objstm_container_overwritten() {
    let name = "isa_objstm_container_overwritten";
    let r = assert_revision(name, deliberate_modification(name));
    assert!(!r.is_valid(), "{}", summary(&r));
}

// ---- SWA: the gap is not the dictionary's /Contents (V4, V5) --------------------------------------

#[test]
fn attacks_swa_part2_moved() {
    // The CCS 2019 signature wrapping on pyHanko's layout: the signed bytes are intact and the
    // signature verifies, but the gap is no longer the /Contents token (brief §5.1 "Ours").
    let name = "swa_part2_moved";
    let base = sign_support::corpus::pyhanko_base();
    let pdf = attacked(name);
    let r = field_report(name);
    let s = summary(&r);
    assert!(r.intact && r.signature_valid, "{s}");
    assert!(r.has_problem(ProblemCode::GapNotContents), "{s}");
    assert!(!r.byte_range_ok, "{s}");
    assert_eq!(r.coverage, Coverage::Unclear, "{s}");
    assert_eq!(r.modification, ModificationLevel::Other);
    assert_eq!(r.pades_level, None);
    assert!(!r.is_valid(), "{s}");
    // It is the real wrapping: the new byte range ends at the end of the file, and its two parts
    // are the signed bytes of the original, part 2 moved to the end.
    let base_range = verify_plain(&base)[0].byte_range.clone().unwrap();
    let range = r.byte_range.clone().unwrap();
    assert_eq!(range[..2], base_range[..2]);
    assert_eq!(range[3], base_range[3]);
    assert!(range[2] > base_range[2]);
    assert_eq!((range[2] + range[3]) as usize, pdf.len());
    let part2 = |pdf: &[u8], range: &[i64]| pdf[range[2] as usize..].to_vec();
    assert_eq!(part2(&pdf, &range), part2(&base, &base_range));
    // The file is well formed: no repair was needed to read it.
    let doc = open(&pdf);
    assert!(!doc.store().structure_repaired(), "{s}");
    // Our own layout (/ByteRange in signed part 1) cannot be wrapped this way.
    assert!(folioxide_testkit::fixtures::sign_attacks::swa_part2_moved(&signed_base()).is_none());
}

#[test]
fn attacks_swa_part2_shifted() {
    // The naive attempt: bytes inserted inside part 2 without a new /ByteRange.
    let r = field_report("swa_part2_shifted");
    let s = summary(&r);
    assert!(r.has_problem(ProblemCode::GapNotContents), "{s}");
    assert!(!r.intact && !r.byte_range_ok, "{s}");
    assert_eq!(r.coverage, Coverage::Unclear, "{s}");
    assert_eq!(r.modification, ModificationLevel::Other);
    assert_eq!(r.pades_level, None);
    assert!(!r.is_valid(), "{s}");
}

#[test]
fn attacks_swa_gap_points_at_other_contents() {
    let r = field_report("swa_gap_points_at_other_contents");
    let s = summary(&r);
    assert!(r.has_problem(ProblemCode::GapNotContents), "{s}");
    assert!(!r.byte_range_ok);
    assert_eq!(r.coverage, Coverage::Unclear);
    // As pyHanko: not intact (the range no longer covers the signed bytes), the CMS verifies.
    assert!(!r.intact && r.signature_valid, "{s}");
    assert!(!r.is_valid());
}

#[test]
fn attacks_swa_two_dicts_same_byterange() {
    let reports = all_reports("swa_two_dicts_same_byterange");
    assert_eq!(reports.len(), 2);
    let field = &reports[0];
    assert!(field.is_valid(), "{}", summary(field));
    assert_eq!(field.coverage, Coverage::EntireRevision);
    // An unreferenced new dictionary is an orphan object, as in pyHanko.
    assert_eq!(
        field.modification,
        ModificationLevel::LtaUpdates,
        "{:?}",
        field.warnings
    );
    let second = &reports[1];
    let s = summary(second);
    assert_eq!(second.field_name, None, "{s}");
    assert!(second.has_problem(ProblemCode::GapNotContents), "{s}");
    assert!(
        second.has_problem(ProblemCode::SigDictOutsideSignedRange),
        "{s}"
    );
    assert!(!second.byte_range_ok && !second.is_valid());
}

#[test]
fn attacks_swa_sig_dict_redefined_in_update() {
    let name = "swa_sig_dict_redefined_in_update";
    let r = field_report(name);
    let s = summary(&r);
    assert!(r.has_problem(ProblemCode::SigDictRedefinedLater), "{s}");
    assert!(r.has_problem(ProblemCode::GapNotContents), "{s}");
    assert!(r.has_problem(ProblemCode::SigDictOutsideSignedRange), "{s}");
    assert!(!r.byte_range_ok && !r.is_valid());
    assert_eq!(our_value(name, "coverage"), Some(r.coverage.as_str()));
    assert_eq!(r.modification, ModificationLevel::Other);
}

// ---- Shadow: hide, replace, hide-and-replace (V10) -----------------------------------------------

#[test]
fn attacks_shadow_hide_overlay_removed() {
    let r = assert_revision("shadow_hide_overlay_removed", ModificationLevel::Other);
    assert!(
        r.changed_objects.contains(&ObjectId::new(3, 0)),
        "{:?}",
        r.changed_objects
    );
}

#[test]
fn attacks_shadow_hide_repoint_to_signed_bytes() {
    let r = assert_revision(
        "shadow_hide_repoint_to_signed_bytes",
        ModificationLevel::Other,
    );
    assert!(
        r.changed_objects.contains(&ObjectId::new(4, 0)),
        "{:?}",
        r.changed_objects
    );
}

#[test]
fn attacks_shadow_replace_font() {
    let r = assert_revision("shadow_replace_font", ModificationLevel::Other);
    assert!(
        r.changed_objects.contains(&ObjectId::new(5, 0)),
        "{:?}",
        r.changed_objects
    );
}

#[test]
fn attacks_shadow_replace_field_value() {
    // The stage-1 generator replaces the value of the first widget, here the signature field
    // itself: the field's /V is no longer a signature dictionary, and the dictionary it named is
    // listed as an orphan whose later changes are OTHER.
    let reports = all_reports("shadow_replace_field_value");
    assert!(
        reports.iter().all(|r| !r.is_valid()),
        "{:?}",
        reports.iter().map(summary).collect::<Vec<_>>()
    );
    let field = reports
        .iter()
        .find(|r| r.field_name.as_deref() == Some("Signature1"))
        .unwrap();
    assert!(
        field.has_problem(ProblemCode::SigValueNotIndirect),
        "{}",
        summary(field)
    );
    let orphan = reports.iter().find(|r| r.field_name.is_none()).unwrap();
    assert!(orphan.has_problem(ProblemCode::Orphan));
    assert_eq!(orphan.modification, ModificationLevel::Other);
}

#[test]
fn attacks_shadow_root_switch() {
    let r = assert_revision("shadow_root_switch", ModificationLevel::Other);
    assert!(
        r.warnings.iter().any(|w| w.contains("/Root")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn attacks_shadow_short_length_in_update() {
    let name = "shadow_short_length_in_update";
    let r = assert_revision(name, deliberate_modification(name));
    assert!(r.has_problem(ProblemCode::StructureRepaired));
}

// ---- Overlays and new signature fields (QA findings 3, 9, 11) ------------------------------------

#[test]
fn attacks_shadow_overlay_sig_widget_registered() {
    // The control: a visible signature field registered in /Fields is form filling, as in
    // pyHanko (QA A3).
    let r = assert_revision(
        "shadow_overlay_sig_widget_registered",
        ModificationLevel::FormFilling,
    );
    assert!(r.is_acceptable(ModificationLevel::FormFilling));
    assert!(!r.is_acceptable(ModificationLevel::LtaUpdates));
}

#[test]
fn attacks_shadow_overlay_sig_widget_rect_indirect() {
    // QA T1 / expert atk_rect: the indirect /Rect is read through its reference (visible), and
    // the new array object is explained by no rule.
    let r = assert_changed_after_signing("shadow_overlay_sig_widget_rect_indirect");
    assert!(
        r.warnings.iter().any(|w| w.contains("no allowed change")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn attacks_shadow_overlay_widget_page_only() {
    // QA A3b / T1b: a signature widget on the page but not in /Fields.
    assert_changed_after_signing("shadow_overlay_widget_page_only");
}

#[test]
fn attacks_shadow_overlay_stamp_ft_sig() {
    // QA T2: a stamp annotation that carries /FT /Sig is not a signature widget.
    assert_changed_after_signing("shadow_overlay_stamp_ft_sig");
}

#[test]
fn attacks_shadow_overlay_sig_widget_no_rect() {
    // QA T3, and M4 QA round 2 finding 4: a new signature widget needs a /Rect of four finite
    // numbers (signers write [0 0 0 0] for an invisible one); without one viewers place its
    // appearance elsewhere than its /Rect says. pyHanko treats it as invisible (formFilling).
    assert_deliberately_other("shadow_overlay_sig_widget_no_rect", "four finite numbers");
}

#[test]
fn attacks_shadow_overlay_sig_widget_zero_width() {
    // QA T5: a zero-width /Rect is invisible; the appearance stream is form filling.
    assert_revision(
        "shadow_overlay_sig_widget_zero_width",
        ModificationLevel::FormFilling,
    );
}

#[test]
fn attacks_shadow_new_sig_field_aa_indirect() {
    // Expert atk_aa: the field's indirect /AA and its JavaScript action are not laundered by
    // the new field's level.
    assert_changed_after_signing("shadow_new_sig_field_aa_indirect");
}

#[test]
fn attacks_shadow_new_sig_field_aa_direct() {
    // Expert atk_aa_direct, QA role_inv_AA_js: a new invisible signature field with a direct
    // JavaScript /AA. The whitelist refuses it (no signer writes /AA); pyHanko: LTA_UPDATES.
    assert_deliberately_other("shadow_new_sig_field_aa_direct", "with /AA");
}

#[test]
fn attacks_shadow_new_sig_field_a_javascript() {
    assert_deliberately_other("shadow_new_sig_field_a_javascript", "with /A,");
}

#[test]
fn attacks_shadow_new_sig_field_a_launch() {
    assert_deliberately_other("shadow_new_sig_field_a_launch", "with /A,");
}

#[test]
fn attacks_shadow_new_sig_field_a_uri() {
    assert_deliberately_other("shadow_new_sig_field_a_uri", "with /A,");
}

#[test]
fn attacks_shadow_new_sig_field_oc() {
    assert_deliberately_other("shadow_new_sig_field_oc", "with /OC");
}

#[test]
fn attacks_new_sig_field_mk() {
    // The control: appearance characteristics (/MK, which Acrobat writes) stay allowed on a new
    // invisible signature field, as in pyHanko.
    let r = assert_revision("new_sig_field_mk", ModificationLevel::LtaUpdates);
    assert!(r.is_acceptable(ModificationLevel::LtaUpdates));
}

#[test]
fn attacks_shadow_new_sig_field_ap() {
    // Expert atk_ap: an invisible field's new appearance stream is form filling.
    assert_revision("shadow_new_sig_field_ap", ModificationLevel::FormFilling);
}

// ---- One object, two roles (expert finding 10) ----------------------------------------------------

#[test]
fn attacks_shadow_info_alias_content() {
    // /Info is the page content stream: replacing it is not a document-information update.
    let r = assert_changed_after_signing("shadow_info_alias_content");
    assert!(
        r.warnings.iter().any(|w| w.contains("/Info is the stream")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn attacks_shadow_markinfo_alias_font() {
    // /MarkInfo is also the page font: changing it is a font change.
    let r = assert_changed_after_signing("shadow_markinfo_alias_font");
    assert!(
        r.warnings.iter().any(|w| w.contains("also uses elsewhere")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn attacks_shadow_info_alias_annotation() {
    // /Info is also a page annotation: hiding it is not a document-information update.
    let r = assert_changed_after_signing("shadow_info_alias_annotation");
    assert!(
        r.warnings.iter().any(|w| w.contains("also uses elsewhere")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn alias_bases_are_sound_before_the_attack() {
    // The prepared documents themselves sign and verify: the role checks only refuse changes to
    // the aliased object.
    for base in [
        sign_support::corpus::Base::InfoAliasContent,
        sign_support::corpus::Base::MarkInfoAliasFont,
        sign_support::corpus::Base::InfoAliasAnnotation,
        sign_support::corpus::Base::InfoAliasPageParent,
        sign_support::corpus::Base::MarkInfoAliasPageParent,
        sign_support::corpus::Base::UnsignedFields,
        sign_support::corpus::Base::TextField,
        sign_support::corpus::Base::InfoMetadata,
    ] {
        let reports = verify_plain(&base.bytes());
        assert_eq!(reports.len(), 1, "{base:?}");
        assert!(reports[0].is_valid(), "{base:?}: {}", summary(&reports[0]));
        assert_eq!(reports[0].coverage, Coverage::EntireFile);
        assert_eq!(reports[0].modification, ModificationLevel::None);
    }
}

// ---- A role object that is also a page's /Parent (expert finding, round 2) -----------------------

#[test]
fn attacks_shadow_info_alias_page_parent() {
    // The /Info dictionary is the page's /Parent outside the /Kids tree: the page inherits its
    // /Resources from it (pdf.js, MuPDF, pdfium), so the "information update" replaces the font.
    let name = "shadow_info_alias_page_parent";
    let r = assert_changed_after_signing(name);
    assert_eq!(r.modification, deliberate_modification(name));
    assert!(
        r.warnings.iter().any(|w| w.contains("page-tree")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn attacks_shadow_markinfo_alias_page_parent() {
    let name = "shadow_markinfo_alias_page_parent";
    let r = assert_changed_after_signing(name);
    assert_eq!(r.modification, deliberate_modification(name));
}

/// `pdf` with a revision that lets `edit` change the store.
fn update(pdf: &[u8], edit: impl FnOnce(&mut Store)) -> Vec<u8> {
    let mut store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default()).unwrap();
    edit(&mut store);
    store
        .save_incremental(&IncrementalOptions::default())
        .unwrap()
}

/// The dictionary of object `id`.
fn dict_of(store: &Store, id: ObjectId) -> Dict {
    store.resolve(id).unwrap().as_dict().unwrap().clone()
}

/// The object of the field (or other dictionary) whose `/T` is `name`.
fn object_named(store: &Store, name: &str) -> ObjectId {
    store
        .object_ids()
        .into_iter()
        .find(|&id| {
            store
                .resolve(id)
                .unwrap()
                .as_dict()
                .and_then(|d| d.get_str_bytes(b"T"))
                == Some(name.as_bytes())
        })
        .unwrap_or_else(|| panic!("no object named {name}"))
}

#[test]
fn a_page_parent_alias_is_a_use_even_without_page_keys() {
    // The usage rule alone, without the page-tree keys the belt-and-braces check looks for: the
    // page's /Parent is the /Info dictionary (which holds only a /Title), so the dictionary is
    // used as page material and any change to it is OTHER, even a harmless one.
    let input = update(&syntax::minimal(), |store| {
        let info = store
            .add(Object::Dict(Dict::from_iter([(
                "Title".into(),
                Object::literal_string("Invoice"),
            )])))
            .unwrap();
        let page = object_with_type(store, b"Page");
        let mut dict = dict_of(store, page);
        dict.insert("Parent", Object::Ref(info));
        store.set(page, Object::Dict(dict)).unwrap();
        store
            .set_trailer_entry(b"Info".as_slice(), Object::Ref(info))
            .unwrap();
    });
    let signed = sign_default(&input, &rsa2048());
    assert!(verify_plain(&signed)[0].is_valid());
    let attacked = update(&signed, |store| {
        let info = store.trailer().get_ref(b"Info").unwrap();
        let mut dict = dict_of(store, info);
        dict.insert("Title", Object::literal_string("Paid"));
        store.set(info, Object::Dict(dict)).unwrap();
    });
    let r = &verify_plain(&attacked)[0];
    assert_eq!(r.modification, ModificationLevel::Other, "{}", summary(r));
    assert!(
        r.warnings.iter().any(|w| w.contains("also uses elsewhere")),
        "{:?}",
        r.warnings
    );

    // The control: the same /Title change when /Info is only document information.
    let input = update(&syntax::minimal(), |store| {
        let info = store
            .add(Object::Dict(Dict::from_iter([(
                "Title".into(),
                Object::literal_string("Invoice"),
            )])))
            .unwrap();
        store
            .set_trailer_entry(b"Info".as_slice(), Object::Ref(info))
            .unwrap();
    });
    let attacked = update(&sign_default(&input, &rsa2048()), |store| {
        let info = store.trailer().get_ref(b"Info").unwrap();
        let mut dict = dict_of(store, info);
        dict.insert("Title", Object::literal_string("Paid"));
        store.set(info, Object::Dict(dict)).unwrap();
    });
    let r = &verify_plain(&attacked)[0];
    assert_eq!(
        r.modification,
        ModificationLevel::LtaUpdates,
        "{}",
        summary(r)
    );
}

/// The first object with `/Type <ty>`.
fn object_with_type(store: &Store, ty: &[u8]) -> ObjectId {
    store
        .object_ids()
        .into_iter()
        .find(|&id| {
            store
                .resolve(id)
                .unwrap()
                .as_dict()
                .is_some_and(|d| d.is_type(ty))
        })
        .unwrap()
}

// ---- Existing signature fields that stay unsigned (QA finding, round 2) -------------------------

#[test]
fn attacks_shadow_unsigned_field_ap_added() {
    // QA poc1: an appearance that paints over the page, on a field that stays unsigned.
    let r = assert_changed_after_signing("shadow_unsigned_field_ap_added");
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("an unsigned signature field")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn attacks_shadow_unsigned_field_ap_repointed() {
    assert_changed_after_signing("shadow_unsigned_field_ap_repointed");
}

#[test]
fn attacks_shadow_unsigned_field_hidden() {
    assert_changed_after_signing("shadow_unsigned_field_hidden");
}

#[test]
fn attacks_shadow_unsigned_field_as_added() {
    assert_changed_after_signing("shadow_unsigned_field_as_added");
}

#[test]
fn attacks_shadow_unsigned_field_parent_ap() {
    assert_changed_after_signing("shadow_unsigned_field_parent_ap");
}

#[test]
fn attacks_unsigned_field_flags_only() {
    // The control: /Ff is always modifiable (pyHanko's FORMFIELD_ALWAYS_MODIFIABLE).
    let r = assert_revision("unsigned_field_flags_only", ModificationLevel::LtaUpdates);
    assert!(r.is_acceptable(ModificationLevel::LtaUpdates));
}

#[test]
fn attacks_acroform_dr_removed() {
    // QA finding: pyHanko raises "Key /DR was deleted".
    assert_changed_after_signing("acroform_dr_removed");
}

#[test]
fn a_changed_acroform_dr_stays_form_filling() {
    // A /DR that changes (here: gains a font) is form filling, stricter than pyHanko's
    // LTA_UPDATES for the AcroForm object; a /DR that is no longer a dictionary is OTHER.
    let signed = sign_support::corpus::Base::UnsignedFields.bytes();
    let with_dr = |dr: Object| {
        update(&signed, |store| {
            let root = store.root_id().unwrap();
            let acroform = dict_of(store, root).get_ref(b"AcroForm").unwrap();
            let mut dict = dict_of(store, acroform);
            dict.insert("DR", dr);
            store.set(acroform, Object::Dict(dict)).unwrap();
        })
    };
    let mut fonts = Dict::new();
    fonts.insert("Helv", Object::Ref(ObjectId::new(5, 0)));
    fonts.insert("Cour", Object::Ref(ObjectId::new(5, 0)));
    let mut dr = Dict::new();
    dr.insert("Font", Object::Dict(fonts));
    let report = |pdf: &[u8]| {
        verify_plain(pdf)
            .into_iter()
            .find(|r| r.field_name.as_deref() == Some("Signature1"))
            .unwrap()
    };
    let r = report(&with_dr(Object::Dict(dr)));
    assert_eq!(
        r.modification,
        ModificationLevel::FormFilling,
        "{}",
        summary(&r)
    );
    let r = report(&with_dr(Object::Int(0)));
    assert_eq!(r.modification, ModificationLevel::Other, "{}", summary(&r));
}

/// A new signature dictionary (the second signer's), unsigned in substance: enough for the
/// modification analysis, which judges the structure of the update and not the later CMS.
fn new_sig_dict(store: &mut Store) -> ObjectId {
    let mut sig = Dict::new();
    sig.insert("Type", Object::name("Sig"));
    sig.insert("Filter", Object::name("Adobe.PPKLite"));
    sig.insert("SubFilter", Object::name("ETSI.CAdES.detached"));
    sig.insert("ByteRange", Object::Array(vec![Object::Int(0); 4]));
    sig.insert(
        "Contents",
        Object::String(folioxide_syntax::PdfString::new_hex(vec![0; 8])),
    );
    store.add(Object::Dict(sig)).unwrap()
}

/// The report of `Signature1` (the first signature) on `pdf`.
fn first_signature(pdf: &[u8]) -> SignatureReport {
    verify_plain(pdf)
        .into_iter()
        .find(|r| r.field_name.as_deref() == Some("Signature1"))
        .unwrap()
}

#[test]
fn signing_an_unsigned_field_may_set_its_appearance() {
    // The legitimate flow pyHanko allows at FORM_FILLING: the revision that signs the field
    // (a new /V) may also give it an appearance and change its flags.
    let signed = sign_support::corpus::Base::UnsignedFields.bytes();
    for field in ["CoSigner", "Witness", "Approver"] {
        let pdf = update(&signed, |store| {
            let id = object_named(store, field);
            let sig = new_sig_dict(store);
            // A form XObject with a /BBox (QA finding R5: an appearance without one, or that
            // is not a form XObject, is OTHER; `signing_an_unsigned_field_with_a_bare_stream`).
            let overlay = store
                .add(Object::Stream(Box::new(folioxide_syntax::Stream::new(
                    Dict::from_iter([
                        ("Type".into(), Object::name("XObject")),
                        ("Subtype".into(), Object::name("Form")),
                        (
                            "BBox".into(),
                            Object::Array([0, 0, 100, 30].map(Object::Int).to_vec()),
                        ),
                    ]),
                    folioxide_syntax::StreamData::Decoded(b"0 g".to_vec()),
                ))))
                .unwrap();
            let mut dict = dict_of(store, id);
            dict.insert("V", Object::Ref(sig));
            let mut ap = Dict::new();
            ap.insert("N", Object::Ref(overlay));
            dict.insert("AP", Object::Dict(ap));
            dict.insert("F", Object::Int(132));
            dict.insert("AS", Object::name("N"));
            store.set(id, Object::Dict(dict)).unwrap();
        });
        let r = first_signature(&pdf);
        assert_eq!(
            r.modification,
            ModificationLevel::FormFilling,
            "{field}: {}",
            summary(&r)
        );
    }
}

#[test]
fn signing_an_unsigned_field_with_a_bare_stream() {
    // QA finding R5: an appearance that is not a form XObject with a /BBox (here a stream with
    // neither, and one with a /BBox of no area on a visible widget) is not clipped to the
    // widget's /Rect by every viewer (PDFium paints it over the page): OTHER.
    let signed = sign_support::corpus::Base::UnsignedFields.bytes();
    for dict in [
        Dict::new(),
        Dict::from_iter([
            ("Subtype".into(), Object::name("Form")),
            ("BBox".into(), Object::Array(vec![Object::Int(0); 4])),
        ]),
    ] {
        let pdf = update(&signed, |store| {
            let id = object_named(store, "CoSigner");
            let sig = new_sig_dict(store);
            let overlay = store
                .add(Object::Stream(Box::new(folioxide_syntax::Stream::new(
                    dict.clone(),
                    folioxide_syntax::StreamData::Decoded(b"0 g 0 0 612 792 re f".to_vec()),
                ))))
                .unwrap();
            let mut field = dict_of(store, id);
            field.insert("V", Object::Ref(sig));
            let mut ap = Dict::new();
            ap.insert("N", Object::Ref(overlay));
            field.insert("AP", Object::Dict(ap));
            store.set(id, Object::Dict(field)).unwrap();
        });
        let r = first_signature(&pdf);
        assert_eq!(r.modification, ModificationLevel::Other, "{}", summary(&r));
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("BBox") || w.contains("form XObject")),
            "{:?}",
            r.warnings
        );
    }
}

#[test]
fn a_field_with_a_null_value_counts_as_signed() {
    // pyHanko's previously_signed is "'/V' in field": a field whose /V is null cannot be
    // signed later without making the earlier signature OTHER.
    let base = update(
        &mutators::unsigned_sig_fields_input(&syntax::minimal()).unwrap(),
        |store| {
            let id = object_named(store, "CoSigner");
            let mut dict = dict_of(store, id);
            dict.insert("V", Object::Null);
            store.set(id, Object::Dict(dict)).unwrap();
        },
    );
    let signed = sign_default(&base, &rsa2048());
    assert!(first_signature(&signed).is_valid());
    let pdf = update(&signed, |store| {
        let id = object_named(store, "CoSigner");
        let sig = new_sig_dict(store);
        let mut dict = dict_of(store, id);
        dict.insert("V", Object::Ref(sig));
        store.set(id, Object::Dict(dict)).unwrap();
    });
    let r = first_signature(&pdf);
    assert_eq!(r.modification, ModificationLevel::Other, "{}", summary(&r));
}

#[test]
fn every_key_mutation_of_an_unsigned_field_is_at_least_as_strict_as_pyhanko() {
    // The differential of QA's exhaustive enumeration, with pyHanko's rule as the reference
    // (SigFieldModificationRule.check_form_field): a signature field that stays unsigned may
    // change only /Ff (LTA_UPDATES); any other change of its dictionary, and any change of a
    // kid widget, is OTHER. Every key of every unsigned field is deleted and set to a few
    // values, and the keys an attacker would add are added.
    let signed = sign_support::corpus::Base::UnsignedFields.bytes();
    let store = Store::open_bytes(signed.clone(), &OpenOptions::default()).unwrap();
    let kid = store
        .object_ids()
        .into_iter()
        .find(|&id| {
            store
                .resolve(id)
                .unwrap()
                .as_dict()
                .is_some_and(|d| d.contains_key(b"Parent") && d.is_type(b"Annot"))
        })
        .unwrap();
    let targets = [
        ("CoSigner", object_named(&store, "CoSigner"), true),
        ("Witness", object_named(&store, "Witness"), true),
        ("Approver", object_named(&store, "Approver"), true),
        ("Approver's widget", kid, false),
    ];
    let font = ObjectId::new(5, 0);
    let mut checked = 0;
    for (label, id, is_field) in targets {
        let original = dict_of(&store, id);
        let mut variants: Vec<(String, Option<Object>, &[u8])> = Vec::new();
        let keys: Vec<Vec<u8>> = original.keys().map(|k| k.as_bytes().to_vec()).collect();
        let values = |new_ap: bool| -> Vec<(&'static str, Object)> {
            let mut out = vec![
                ("null", Object::Null),
                ("0", Object::Int(0)),
                ("2", Object::Int(2)),
                ("/Hidden", Object::name("Hidden")),
                ("(X)", Object::literal_string("X")),
                (
                    "[0 0 612 792]",
                    Object::Array(vec![
                        Object::Int(0),
                        Object::Int(0),
                        Object::Int(612),
                        Object::Int(792),
                    ]),
                ),
                ("font ref", Object::Ref(font)),
            ];
            if new_ap {
                out.push((
                    "<< /N font >>",
                    Object::Dict(Dict::from_iter([("N".into(), Object::Ref(font))])),
                ));
            }
            out
        };
        for key in &keys {
            variants.push((format!("del /{}", String::from_utf8_lossy(key)), None, key));
            for (text, value) in values(true) {
                variants.push((
                    format!("/{} {text}", String::from_utf8_lossy(key)),
                    Some(value),
                    key,
                ));
            }
        }
        const ADDED: &[&[u8]] = &[
            b"F",
            b"Ff",
            b"AP",
            b"AS",
            b"V",
            b"DA",
            b"Q",
            b"MK",
            b"AA",
            b"A",
            b"Rect",
            b"Lock",
            b"SV",
            b"Type",
            b"Subtype",
            b"Kids",
            b"Parent",
            b"OC",
            b"Contents",
        ];
        for key in ADDED.iter().copied().filter(|k| !original.contains_key(k)) {
            for (text, value) in values(true) {
                variants.push((
                    format!("+/{} {text}", String::from_utf8_lossy(key)),
                    Some(value),
                    key,
                ));
            }
        }
        for (what, value, key) in variants {
            let mut dict = original.clone();
            match &value {
                None => {
                    dict.remove(key);
                }
                Some(v) => {
                    dict.insert(key.to_vec(), v.clone());
                }
            }
            if dict == original {
                continue;
            }
            let pdf = update(&signed, |store| {
                store.set(id, Object::Dict(dict.clone())).unwrap();
            });
            let pyhanko_at_least = if is_field && key == b"Ff" {
                ModificationLevel::LtaUpdates
            } else {
                ModificationLevel::Other
            };
            let r = first_signature(&pdf);
            assert!(
                r.modification >= pyhanko_at_least,
                "{label} {what}: ours {} below pyHanko's {pyhanko_at_least}",
                r.modification
            );
            // And exactly that: the /Ff control is not stricter than needed.
            assert_eq!(
                r.modification,
                pyhanko_at_least,
                "{label} {what}: {}",
                summary(&r)
            );
            checked += 1;
        }
    }
    assert!(checked > 300, "{checked}");
}

// ---- The AcroForm's appearance controls (expert finding, round 3) --------------------------------

#[test]
fn attacks_shadow_acroform_need_appearances_set() {
    // Expert mk_na: viewers regenerate the text field from its /V and show "900 EUR".
    assert_deliberately_other("shadow_acroform_need_appearances_set", "/NeedAppearances");
}

#[test]
fn attacks_shadow_acroform_da_changed() {
    // Expert atk_da_white: white text in every regenerated field without its own /DA.
    assert_deliberately_other("shadow_acroform_da_changed", "/DA");
}

#[test]
fn attacks_shadow_acroform_dr_name_replaced() {
    // Expert atk_dr_font: the font the /DA selects is re-pointed.
    assert_deliberately_other("shadow_acroform_dr_name_replaced", "/Helv of /DR /Font");
}

#[test]
fn attacks_acroform_dr_name_added() {
    // The control: a new /DR name (the font of a later signer's appearance) is form filling,
    // as in pyHanko.
    let r = assert_revision("acroform_dr_name_added", ModificationLevel::FormFilling);
    assert!(r.is_acceptable(ModificationLevel::FormFilling));
}

#[test]
fn attacks_acroform_da_added() {
    // Any change to the AcroForm /DA is OTHER, even a /DA added where the only field is the
    // signature field (manager decision, round 5; pyHanko: LTA_UPDATES).
    assert_deliberately_other("acroform_da_added", "adds /DA");
}

#[test]
fn attacks_shadow_acroform_need_appearances_removed_stale_ap() {
    // Expert mk2: signed with /NeedAppearances true, viewers showed the constructed "900 EUR";
    // once it is removed they show the stale stored "100 EUR".
    assert_deliberately_other(
        "shadow_acroform_need_appearances_removed_stale_ap",
        "removes /NeedAppearances",
    );
}

#[test]
fn attacks_cosigner_removes_need_appearances() {
    // The pyHanko co-signing flow: the second signature's revision removes /NeedAppearances
    // true, so the first signature is OTHER (pyHanko: FORM_FILLING); the second is untouched.
    let name = "cosigner_removes_need_appearances";
    assert_deliberately_other(name, "removes /NeedAppearances");
    let reports = all_reports(name);
    assert_eq!(
        reports.len(),
        2,
        "{:?}",
        reports.iter().map(summary).collect::<Vec<_>>()
    );
    let cosigner = reports
        .iter()
        .find(|r| r.field_name.as_deref() == Some(COSIGNER_FIELD))
        .unwrap();
    assert!(cosigner.is_valid(), "{}", summary(cosigner));
    assert_eq!(cosigner.coverage, Coverage::EntireFile);
    assert_eq!(cosigner.modification, ModificationLevel::None);
}

#[test]
fn attacks_acroform_need_appearances_false_added() {
    // Harmless in itself (absent means false), but any change to the key is refused.
    assert_deliberately_other(
        "acroform_need_appearances_false_added",
        "adds /NeedAppearances",
    );
}

#[test]
fn attacks_shadow_acroform_da_removed() {
    assert_deliberately_other("shadow_acroform_da_removed", "removes /DA");
}

#[test]
fn attacks_shadow_acroform_da_added_noap() {
    // Expert u_da_added_white: the signed field has no appearance stream and no /DA of its own.
    assert_deliberately_other("shadow_acroform_da_added_noap", "adds /DA");
}

#[test]
fn attacks_shadow_acroform_da_added_ap_not_stream() {
    // Expert u_n_plaindict: /AP /N present but no stream, so viewers draw with the added /DA.
    assert_deliberately_other("shadow_acroform_da_added_ap_not_stream", "adds /DA");
}

#[test]
fn attacks_shadow_acroform_da_added_orphan_widget() {
    // Expert u_orphan: a text widget on the page that /Fields does not list.
    assert_deliberately_other("shadow_acroform_da_added_orphan_widget", "adds /DA");
}

#[test]
fn attacks_shadow_acroform_dr_font_orphan_widget_da() {
    // Expert u_orphan_f7: the orphan widget's own /DA selects /F7, which the update adds to /DR.
    assert_deliberately_other(
        "shadow_acroform_dr_font_orphan_widget_da",
        "adds /DR /Font /F7, which the signed revision already names",
    );
}

#[test]
fn attacks_shadow_acroform_q_changed() {
    assert_deliberately_other("shadow_acroform_q_changed", "changes /Q");
}

#[test]
fn attacks_shadow_acroform_dr_name_removed() {
    assert_deliberately_other("shadow_acroform_dr_name_removed", "/Helv of /DR /Font");
}

#[test]
fn attacks_shadow_acroform_dr_da_font_added() {
    assert_deliberately_other("shadow_acroform_dr_da_font_added", "already names");
}

#[test]
fn attacks_shadow_acroform_dr_encoding_added() {
    // QA nit: kept OTHER; a real Acrobat co-signed sample is to be checked before M4.
    assert_deliberately_other("shadow_acroform_dr_encoding_added", "changes /DR /Encoding");
}

#[test]
fn attacks_shadow_new_sig_field_parent() {
    assert_deliberately_other("shadow_new_sig_field_parent", "with /Parent,");
}

/// The text-field base ([`Base::TextField`](sign_support::corpus::Base::TextField)) with `edit`
/// applied to its AcroForm dictionary in a revision before signing.
fn text_field_base_with(edit: impl FnOnce(&mut Store, &mut Dict)) -> Vec<u8> {
    let input = mutators::text_field_form_input(&syntax::minimal()).unwrap();
    let input = update(&input, |store| {
        let acroform = acroform_id(store);
        let mut dict = dict_of(store, acroform);
        edit(store, &mut dict);
        store.set(acroform, Object::Dict(dict)).unwrap();
    });
    let signed = sign_default(&input, &rsa2048());
    let r = first_signature(&signed);
    assert!(r.is_valid(), "{}", summary(&r));
    signed
}

/// The document's indirect AcroForm.
fn acroform_id(store: &Store) -> ObjectId {
    let root = store.root_id().unwrap();
    dict_of(store, root).get_ref(b"AcroForm").unwrap()
}

/// The modification level of the first signature after a revision that lets `edit` change the
/// AcroForm dictionary of `signed`.
fn after_acroform_edit(signed: &[u8], edit: impl FnOnce(&mut Store, &mut Dict)) -> SignatureReport {
    let pdf = update(signed, |store| {
        let acroform = acroform_id(store);
        let mut dict = dict_of(store, acroform);
        edit(store, &mut dict);
        store.set(acroform, Object::Dict(dict)).unwrap();
    });
    first_signature(&pdf)
}

/// Sets `key` of `dict` to `value`.
fn set(dict: &mut Dict, key: &str, value: Object) {
    dict.insert(key, value);
}

/// A new Courier font object.
fn courier(store: &mut Store) -> ObjectId {
    store
        .add(Object::Dict(Dict::from_iter([
            ("Type".into(), Object::name("Font")),
            ("Subtype".into(), Object::name("Type1")),
            ("BaseFont".into(), Object::name("Courier")),
        ])))
        .unwrap()
}

/// The `/DR /Font` dictionary of an AcroForm dictionary (both direct).
fn dr_fonts(acroform: &Dict) -> Dict {
    acroform
        .get_dict(b"DR")
        .and_then(|dr| dr.get_dict(b"Font"))
        .cloned()
        .unwrap()
}

/// `acroform` with `/DR /Font` replaced by `fonts` (direct).
fn set_dr_fonts(acroform: &mut Dict, fonts: Object) {
    let mut dr = acroform.get_dict(b"DR").cloned().unwrap_or_default();
    dr.insert("Font", fonts);
    acroform.insert("DR", Object::Dict(dr));
}

#[test]
fn every_acroform_control_change_follows_the_whitelist() {
    // The whitelist of brief §5 V10 (3) over the AcroForm keys a later revision can touch, on a
    // document signed with a /DA, a /DR font /Helv, no /NeedAppearances and no /Q.
    use ModificationLevel::{FormFilling, Other};
    let signed = sign_support::corpus::Base::TextField.bytes();
    type Edit = fn(&mut Store, &mut Dict);
    let cases: Vec<(&str, Edit, ModificationLevel)> = vec![
        (
            "NeedAppearances true",
            |_, d| set(d, "NeedAppearances", Object::Bool(true)),
            Other,
        ),
        (
            "NeedAppearances false",
            |_, d| set(d, "NeedAppearances", Object::Bool(false)),
            Other,
        ),
        (
            "NeedAppearances 1",
            |_, d| set(d, "NeedAppearances", Object::Int(1)),
            Other,
        ),
        (
            "DA changed",
            |_, d| set(d, "DA", Object::literal_string("/Helv 20 Tf 1 g")),
            Other,
        ),
        (
            "DA changed to a non-string",
            |_, d| set(d, "DA", Object::Int(0)),
            Other,
        ),
        (
            "DA removed",
            |_, d| {
                d.remove(b"DA".as_slice());
            },
            Other,
        ),
        ("Q added", |_, d| set(d, "Q", Object::Int(2)), Other),
        ("Q 0 added", |_, d| set(d, "Q", Object::Int(0)), Other),
        (
            "SigFlags changed",
            |_, d| set(d, "SigFlags", Object::Int(1)),
            Other,
        ),
        (
            "XFA added",
            |_, d| set(d, "XFA", Object::Array(Vec::new())),
            Other,
        ),
        (
            "CO added",
            |_, d| set(d, "CO", Object::Array(Vec::new())),
            Other,
        ),
        (
            "DR name added",
            |s, d| {
                let font = courier(s);
                let mut fonts = dr_fonts(d);
                fonts.insert("Cour", Object::Ref(font));
                set_dr_fonts(d, Object::Dict(fonts));
            },
            FormFilling,
        ),
        (
            "DR name re-pointed",
            |s, d| {
                let font = courier(s);
                let mut fonts = dr_fonts(d);
                fonts.insert("Helv", Object::Ref(font));
                set_dr_fonts(d, Object::Dict(fonts));
            },
            Other,
        ),
        (
            "DR name removed",
            |_, d| set_dr_fonts(d, Object::Dict(Dict::new())),
            Other,
        ),
        (
            "DR font category removed",
            |_, d| {
                let mut dr = d.get_dict(b"DR").cloned().unwrap();
                dr.remove(b"Font".as_slice());
                d.insert("DR", Object::Dict(dr));
            },
            Other,
        ),
        (
            "DR font category indirect, same names",
            |s, d| {
                let fonts = s.add(Object::Dict(dr_fonts(d))).unwrap();
                set_dr_fonts(d, Object::Ref(fonts));
            },
            FormFilling,
        ),
        (
            "DR font category indirect, name re-pointed",
            |s, d| {
                let font = courier(s);
                let mut fonts = dr_fonts(d);
                fonts.insert("Helv", Object::Ref(font));
                let fonts = s.add(Object::Dict(fonts)).unwrap();
                set_dr_fonts(d, Object::Ref(fonts));
            },
            Other,
        ),
        (
            "DR XObject category added",
            |s, d| {
                let font = courier(s);
                let mut dr = d.get_dict(b"DR").cloned().unwrap();
                dr.insert(
                    "ExtGState",
                    Object::Dict(Dict::from_iter([("GS1".into(), Object::Ref(font))])),
                );
                d.insert("DR", Object::Dict(dr));
            },
            FormFilling,
        ),
        (
            "DR ProcSet added",
            |_, d| {
                let mut dr = d.get_dict(b"DR").cloned().unwrap();
                dr.insert(
                    "ProcSet",
                    Object::Array(vec![Object::name("PDF"), Object::name("Text")]),
                );
                d.insert("DR", Object::Dict(dr));
            },
            FormFilling,
        ),
        (
            "DR Encoding added",
            |_, d| {
                let mut dr = d.get_dict(b"DR").cloned().unwrap();
                dr.insert("Encoding", Object::Dict(Dict::new()));
                d.insert("DR", Object::Dict(dr));
            },
            Other,
        ),
        (
            "DR Properties added",
            |_, d| {
                let mut dr = d.get_dict(b"DR").cloned().unwrap();
                dr.insert("Properties", Object::Dict(Dict::new()));
                d.insert("DR", Object::Dict(dr));
            },
            Other,
        ),
        (
            "DR not a dictionary",
            |_, d| set(d, "DR", Object::Int(0)),
            Other,
        ),
    ];
    for (what, edit, want) in cases {
        let r = after_acroform_edit(&signed, edit);
        assert_eq!(r.modification, want, "{what}: {}", summary(&r));
        if want == Other {
            assert!(
                r.warnings.iter().any(|w| w.contains("the AcroForm")),
                "{what}: {:?}",
                r.warnings
            );
        }
    }
}

#[test]
fn acroform_controls_of_a_document_signed_with_them_set() {
    use ModificationLevel::Other;
    // Signed with /NeedAppearances true: removing it, setting it false or changing it is OTHER
    // (expert finding: viewers then show the stale stored appearances instead of those they
    // constructed when the document was signed), even though pyHanko's signer removes it.
    let signed = text_field_base_with(|_, d| set(d, "NeedAppearances", Object::Bool(true)));
    type Edit = fn(&mut Store, &mut Dict);
    let edits: [(&str, Edit); 3] = [
        ("removed", |_, d| {
            d.remove(b"NeedAppearances".as_slice());
        }),
        ("false", |_, d| {
            set(d, "NeedAppearances", Object::Bool(false))
        }),
        ("1", |_, d| set(d, "NeedAppearances", Object::Int(1))),
    ];
    for (what, edit) in edits {
        let r = after_acroform_edit(&signed, edit);
        assert_eq!(r.modification, Other, "{what}: {}", summary(&r));
        assert!(
            r.warnings.iter().any(|w| w.contains("/NeedAppearances")),
            "{what}: {:?}",
            r.warnings
        );
    }
    // Signed with /NeedAppearances false: removing it (no effect) is OTHER all the same.
    let signed = text_field_base_with(|_, d| set(d, "NeedAppearances", Object::Bool(false)));
    let r = after_acroform_edit(&signed, |_, d| {
        d.remove(b"NeedAppearances".as_slice());
    });
    assert_eq!(r.modification, Other, "{}", summary(&r));

    // Signed without /DA, the field with its appearance stream: adding one is OTHER all the
    // same (manager decision, round 5: no exception for a /DA added where there is none), with
    // /NeedAppearances true too; adding a non-string is no better.
    for need_appearances in [false, true] {
        let signed = text_field_base_with(|_, d| {
            d.remove(b"DA".as_slice());
            if need_appearances {
                set(d, "NeedAppearances", Object::Bool(true));
            }
        });
        let r = after_acroform_edit(&signed, |_, d| {
            set(d, "DA", Object::literal_string("/Helv 0 Tf 0 g"));
        });
        assert_eq!(r.modification, Other, "{}", summary(&r));
        assert!(
            r.warnings.iter().any(|w| w.contains("adds /DA")),
            "{:?}",
            r.warnings
        );
        let r = after_acroform_edit(&signed, |_, d| set(d, "DA", Object::Int(0)));
        assert_eq!(r.modification, Other, "{}", summary(&r));
    }

    // Signed with a /Q: changing or removing it is OTHER.
    let signed = text_field_base_with(|_, d| set(d, "Q", Object::Int(1)));
    for value in [Some(Object::Int(2)), None] {
        let r = after_acroform_edit(&signed, |_, d| match value {
            Some(v) => set(d, "Q", v),
            None => {
                d.remove(b"Q".as_slice());
            }
        });
        assert_eq!(r.modification, Other, "{}", summary(&r));
    }
}

#[test]
fn a_dr_font_name_the_signed_da_selects_cannot_be_added_later() {
    // Signed with an AcroForm /DA that selects /Helv while /DR has no /Helv (a name that does
    // not resolve): adding /Helv later would change what the regenerated appearances draw, as a
    // dangling reference that now resolves would.
    use ModificationLevel::{FormFilling, Other};
    let signed = text_field_base_with(|_, d| set_dr_fonts(d, Object::Dict(Dict::new())));
    let r = after_acroform_edit(&signed, |s, d| {
        let font = courier(s);
        set_dr_fonts(
            d,
            Object::Dict(Dict::from_iter([("Helv".into(), Object::Ref(font))])),
        );
    });
    assert_eq!(r.modification, Other, "{}", summary(&r));
    assert!(
        r.warnings.iter().any(|w| w.contains("already names")),
        "{:?}",
        r.warnings
    );
    // Another name is a plain addition.
    let r = after_acroform_edit(&signed, |s, d| {
        let font = courier(s);
        set_dr_fonts(
            d,
            Object::Dict(Dict::from_iter([("Cour".into(), Object::Ref(font))])),
        );
    });
    assert_eq!(r.modification, FormFilling, "{}", summary(&r));
}

/// The text field without an appearance stream, in an AcroForm without `/DA`
/// ([`Base::TextFieldNoAppearance`](sign_support::corpus::Base::TextFieldNoAppearance)), with
/// `edit` applied to the field's dictionary in a revision before signing.
fn no_appearance_base_with_field(edit: impl FnOnce(&mut Dict)) -> Vec<u8> {
    let input = mutators::text_field_no_appearance_input(&syntax::minimal()).unwrap();
    let input = update(&input, |store| {
        let id = object_named(store, "Amount");
        let mut dict = dict_of(store, id);
        edit(&mut dict);
        store.set(id, Object::Dict(dict)).unwrap();
    });
    let signed = sign_default(&input, &rsa2048());
    let r = first_signature(&signed);
    assert!(r.is_valid(), "{}", summary(&r));
    signed
}

#[test]
fn a_da_added_is_other_whatever_the_signed_fields_have() {
    // The former exception (a /DA added where none was, when every field had an appearance
    // stream or a /DA of its own) leaked twice (expert findings, round 5), so it is gone: every
    // AcroForm /DA added later is OTHER, even when the field has a /DA of its own, and for each
    // /AP /N that is no stream (the expert's variants: pyHanko raises IndirectObjectExpected on
    // the direct ones).
    let add_da = |_: &mut Store, d: &mut Dict| {
        set(d, "DA", Object::literal_string("/Helv 20 Tf 1 g"));
    };
    let mut variants: Vec<(&str, Vec<u8>)> = vec![(
        "field /DA",
        no_appearance_base_with_field(|d| {
            d.insert("DA", Object::literal_string("/Helv 20 Tf 0 g"));
        }),
    )];
    for (what, n) in [
        ("/N empty dictionary", "<< >>"),
        ("/N state dictionary without /AS", "<< /On 1 0 R >>"),
        ("/N integer", "0"),
        ("/N null", "null"),
    ] {
        let n =
            folioxide_syntax::parse_object(n.as_bytes(), 0, &folioxide_syntax::ParseCtx::default())
                .unwrap()
                .0;
        variants.push((
            what,
            no_appearance_base_with_field(|d| {
                d.insert("AP", Object::Dict(Dict::from_iter([("N".into(), n)])));
            }),
        ));
    }
    for (what, signed) in variants {
        let r = after_acroform_edit(&signed, add_da);
        assert_eq!(
            r.modification,
            ModificationLevel::Other,
            "{what}: {}",
            summary(&r)
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("adds /DA")),
            "{what}: {:?}",
            r.warnings
        );
    }
}

#[test]
fn a_font_the_signed_da_selects_without_white_space_is_guarded() {
    // Expert probe u_tightda_dr_f2: the field's /DA "0 g/F2 20 Tf" selects /F2, which /DR does
    // not have; a name ends at the delimiter `/` (ISO 32000-2 7.2.3), so adding /DR /Font /F2
    // later is OTHER (it was form filling while /DA was split at white-space only).
    use ModificationLevel::{FormFilling, Other};
    for da in ["0 g/F2 20 Tf", "/F3 9 Tf/F2 20 Tf", "/F2 12 Tf0 g"] {
        let signed = no_appearance_base_with_field(|d| {
            d.insert("DA", Object::literal_string(da));
        });
        let add_font = |name: &'static str| {
            move |s: &mut Store, d: &mut Dict| {
                let font = courier(s);
                let mut fonts = dr_fonts(d);
                fonts.insert(name, Object::Ref(font));
                set_dr_fonts(d, Object::Dict(fonts));
            }
        };
        let r = after_acroform_edit(&signed, add_font("F2"));
        assert_eq!(r.modification, Other, "{da}: {}", summary(&r));
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("/F2, which the signed revision already names")),
            "{da}: {:?}",
            r.warnings
        );
        let r = after_acroform_edit(&signed, add_font("Cour"));
        assert_eq!(r.modification, FormFilling, "{da}: {}", summary(&r));
    }
}

#[test]
fn a_dr_name_any_signed_annotation_names_cannot_be_added_later() {
    // The /DR guard reads every annotation on every page of the signed revision (expert finding,
    // round 5: an orphan widget's /DA), not only the field tree: a FreeText annotation's /DA
    // (§12.5.6.6), the /DA an orphan widget inherits from its field outside /Fields, and the
    // names of an appearance stream without /Resources of its own (some viewers resolve them in
    // /DR; here the registered field's, which names /GS9 and /F9), in every /DR category.
    use ModificationLevel::{FormFilling, Other};
    let input = mutators::orphan_widget_bare_appearance_input(&syntax::minimal()).unwrap();
    let input = update(&input, |store| {
        let page = {
            let root = store.root_id().unwrap();
            let pages = dict_of(store, root).get_ref(b"Pages").unwrap();
            dict_of(store, pages).get_array(b"Kids").unwrap()[0]
                .as_ref()
                .unwrap()
        };
        let free_text = store
            .add(Object::Dict(Dict::from_iter([
                ("Type".into(), Object::name("Annot")),
                ("Subtype".into(), Object::name("FreeText")),
                ("Rect".into(), Object::Array(vec![Object::Int(72); 4])),
                ("Contents".into(), Object::literal_string("note")),
                ("DA".into(), Object::literal_string("/F8 12 Tf 0 g")),
            ])))
            .unwrap();
        // An orphan widget whose field (outside /Fields too) has the /DA it inherits.
        let field = store
            .add(Object::Dict(Dict::from_iter([
                ("FT".into(), Object::name("Tx")),
                ("T".into(), Object::literal_string("Hidden")),
                ("V".into(), Object::literal_string("900 EUR")),
                ("DA".into(), Object::literal_string("/F6 12 Tf 0 g")),
            ])))
            .unwrap();
        let kid = store
            .add(Object::Dict(Dict::from_iter([
                ("Type".into(), Object::name("Annot")),
                ("Subtype".into(), Object::name("Widget")),
                ("Rect".into(), Object::Array(vec![Object::Int(300); 4])),
                ("Parent".into(), Object::Ref(field)),
            ])))
            .unwrap();
        let mut page_dict = dict_of(store, page);
        let mut annots = page_dict.get_array(b"Annots").unwrap().to_vec();
        annots.extend([Object::Ref(free_text), Object::Ref(kid)]);
        page_dict.insert("Annots", Object::Array(annots));
        store.set(page, Object::Dict(page_dict)).unwrap();
    });
    let signed = sign_default(&input, &rsa2048());
    assert!(first_signature(&signed).is_valid());
    let add = |category: &'static str, name: &'static str| {
        move |s: &mut Store, d: &mut Dict| {
            let font = courier(s);
            let mut dr = d.get_dict(b"DR").cloned().unwrap();
            let mut names = dr
                .get_dict(category.as_bytes())
                .cloned()
                .unwrap_or_default();
            names.insert(name, Object::Ref(font));
            dr.insert(category, Object::Dict(names));
            d.insert("DR", Object::Dict(dr));
        }
    };
    for (category, name, want) in [
        ("Font", "F6", Other),
        ("Font", "F7", Other),
        ("Font", "F8", Other),
        ("Font", "F9", Other),
        ("ExtGState", "GS9", Other),
        ("XObject", "F8", Other),
        ("Font", "Cour", FormFilling),
        ("ExtGState", "GS1", FormFilling),
    ] {
        let r = after_acroform_edit(&signed, add(category, name));
        assert_eq!(r.modification, want, "/{category} /{name}: {}", summary(&r));
        if want == Other {
            assert!(
                r.warnings
                    .iter()
                    .any(|w| w.contains(&format!("/{category} /{name}, which the signed"))),
                "/{category} /{name}: {:?}",
                r.warnings
            );
        }
    }
}

#[test]
fn an_indirect_dr_category_is_compared_by_its_names() {
    // Signed with /DR << /Font 12 0 R >>: re-pointing /Font to a new dictionary with the same
    // names plus one is form filling; one that re-points /Helv is OTHER, and so is any change of
    // the signed category object itself (an object of the signed revision with no role).
    use ModificationLevel::{FormFilling, Other};
    let signed = text_field_base_with(|s, d| {
        let fonts = s.add(Object::Dict(dr_fonts(d))).unwrap();
        set_dr_fonts(d, Object::Ref(fonts));
    });
    let category = |store: &Store| {
        let acroform = dict_of(store, acroform_id(store));
        acroform
            .get_dict(b"DR")
            .and_then(|dr| dr.get_ref(b"Font"))
            .unwrap()
    };
    let r = after_acroform_edit(&signed, |s, d| {
        let font = courier(s);
        let mut fonts = dict_of(s, category(s));
        fonts.insert("Cour", Object::Ref(font));
        let fonts = s.add(Object::Dict(fonts)).unwrap();
        set_dr_fonts(d, Object::Ref(fonts));
    });
    assert_eq!(r.modification, FormFilling, "{}", summary(&r));
    let r = after_acroform_edit(&signed, |s, d| {
        let font = courier(s);
        let mut fonts = dict_of(s, category(s));
        fonts.insert("Helv", Object::Ref(font));
        let fonts = s.add(Object::Dict(fonts)).unwrap();
        set_dr_fonts(d, Object::Ref(fonts));
    });
    assert_eq!(r.modification, Other, "{}", summary(&r));
    let pdf = update(&signed, |s| {
        let id = category(s);
        let font = courier(s);
        let mut fonts = dict_of(s, id);
        fonts.insert("Helv", Object::Ref(font));
        s.set(id, Object::Dict(fonts)).unwrap();
    });
    let r = first_signature(&pdf);
    assert_eq!(r.modification, Other, "{}", summary(&r));
}

// ---- Classes M3 does not classify yet (DECISIONS D10 D-9) ---------------------------------------

#[test]
fn attacks_form_field_value_changed() {
    // Generic form filling, classified since M4 WP4.2A (brief §5.1): a text field's new /V
    // alone is form filling, as pyHanko says (it was OTHER in M3, D-9).
    let r = assert_revision("form_field_value_changed", ModificationLevel::FormFilling);
    assert_eq!(r.docmdp_ok, Some(true), "P = 2 is in force for an approval");
    assert!(r.is_acceptable(ModificationLevel::FormFilling));
}

#[test]
fn attacks_dss_added() {
    // The document security store: OTHER until M11 (pyHanko: LTA_UPDATES).
    assert_deliberately_other("dss_added", "changes the catalog");
}

// ---- Role objects the new revision no longer points to (QA finding, round 3) ---------------------

#[test]
fn attacks_shadow_info_repoint_old_changed() {
    let r = assert_changed_after_signing("shadow_info_repoint_old_changed");
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("no longer names it as /Info")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn attacks_shadow_info_removed_old_changed() {
    assert_deliberately_other(
        "shadow_info_removed_old_changed",
        "no longer names it as /Info",
    );
}

#[test]
fn attacks_info_changed_in_place() {
    assert_revision("info_changed_in_place", ModificationLevel::LtaUpdates);
}

#[test]
fn attacks_shadow_metadata_repoint_old_changed() {
    let r = assert_changed_after_signing("shadow_metadata_repoint_old_changed");
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("no longer names it as /Metadata")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn attacks_shadow_metadata_removed_old_changed() {
    let r = assert_changed_after_signing("shadow_metadata_removed_old_changed");
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("no longer names it as /Metadata")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn attacks_metadata_changed_in_place() {
    assert_revision("metadata_changed_in_place", ModificationLevel::LtaUpdates);
}

#[test]
fn attacks_metadata_changed_not_well_formed() {
    // QA finding 22 (variant R4-approval-plain-update-invalid-xml): a duplicate attribute makes
    // the packet malformed XML, so not XMP: Other, as in pyHanko.
    let r = assert_changed_after_signing("metadata_changed_not_well_formed");
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("the new stream is not an XMP packet")),
        "{:?}",
        r.warnings
    );
}

/// M4 QA round 3, findings 19 and 20: a new `/Metadata` packet pyHanko does not read as XMP
/// (libxml2's limits, or data its filters do not decode): Other, as pyHanko.
fn assert_metadata_not_xmp(name: &str) {
    let r = assert_changed_after_signing(name);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("the new stream is not an XMP packet")),
        "{name}: {:?}",
        r.warnings
    );
    assert_eq!(
        our_value(name, "modification"),
        None,
        "{name}: equal to pyHanko"
    );
}

#[test]
fn attacks_metadata_xmp_comment_over_lxml_limit() {
    assert_metadata_not_xmp("metadata_xmp_comment_over_lxml_limit");
}

#[test]
fn attacks_metadata_xmp_name_over_lxml_limit() {
    assert_metadata_not_xmp("metadata_xmp_name_over_lxml_limit");
}

#[test]
fn attacks_metadata_flate_bad_adler() {
    assert_metadata_not_xmp("metadata_flate_bad_adler");
}

#[test]
fn attacks_metadata_runlength() {
    assert_metadata_not_xmp("metadata_runlength");
}

#[test]
fn attacks_metadata_ascii85_without_eod() {
    assert_metadata_not_xmp("metadata_ascii85_without_eod");
}

#[test]
fn attacks_metadata_flate_then_ascii() {
    // M4 QA round 4, finding 11 (variants R4w-dec-flate-then-ahx/-a85/-crypt-ahx/-flate-ahx,
    // approval context): pyHanko's FlateDecode returns a memoryview, on which its ASCIIHex and
    // ASCII85 decoders raise, so it cannot read the packet ("/Metadata XML syntax could not be
    // validated"): Other, as pyHanko (docmdpOk false).
    for name in [
        "metadata_flate_then_ahx",
        "metadata_flate_then_a85",
        "metadata_flate_crypt_ahx",
        "metadata_flate_flate_ahx",
    ] {
        assert_metadata_not_xmp(name);
        assert_eq!(field_report(name).docmdp_ok, Some(false), "{name}");
    }
}

#[test]
fn catalog_role_dictionaries_keep_their_role_only_while_named() {
    // /Extensions and /MarkInfo: changing the signed dictionary is an LTA update while the
    // catalog still names it, OTHER once the same revision points the catalog elsewhere.
    for key in ["Extensions", "MarkInfo"] {
        let input = update(&syntax::minimal(), |store| {
            let value = match key {
                "Extensions" => Dict::from_iter([(
                    "ADBE".into(),
                    Object::Dict(Dict::from_iter([
                        ("BaseVersion".into(), Object::name("1.7")),
                        ("ExtensionLevel".into(), Object::Int(3)),
                    ])),
                )]),
                _ => Dict::from_iter([("Marked".into(), Object::Bool(true))]),
            };
            let id = store.add(Object::Dict(value)).unwrap();
            let root = store.root_id().unwrap();
            let mut catalog = dict_of(store, root);
            catalog.insert(key, Object::Ref(id));
            store.set(root, Object::Dict(catalog)).unwrap();
        });
        let signed = sign_default(&input, &rsa2048());
        let role = |store: &Store| {
            dict_of(store, store.root_id().unwrap())
                .get_ref(key.as_bytes())
                .unwrap()
        };
        let change_old = |store: &mut Store| {
            let id = role(store);
            let mut dict = dict_of(store, id);
            dict.insert("Changed", Object::Bool(true));
            store.set(id, Object::Dict(dict)).unwrap();
        };
        let in_place = update(&signed, change_old);
        let r = first_signature(&in_place);
        assert_eq!(
            r.modification,
            ModificationLevel::LtaUpdates,
            "{key}: {}",
            summary(&r)
        );
        let repointed = update(&signed, |store| {
            let old = role(store);
            let copy = store.add(Object::Dict(dict_of(store, old))).unwrap();
            change_old(store);
            let root = store.root_id().unwrap();
            let mut catalog = dict_of(store, root);
            catalog.insert(key, Object::Ref(copy));
            store.set(root, Object::Dict(catalog)).unwrap();
        });
        let r = first_signature(&repointed);
        assert_eq!(
            r.modification,
            ModificationLevel::Other,
            "{key}: {}",
            summary(&r)
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains(&format!("no longer names it as /{key}"))),
            "{key}: {:?}",
            r.warnings
        );
    }
}

#[test]
fn an_annots_array_keeps_its_role_only_while_its_page_names_it() {
    // The page's /Annots is an indirect array. A revision that adds an invisible signature field
    // and appends it to that array is an LTA update; one that also points the page to a new
    // array (holding the field) while appending to the old one is OTHER.
    let input = update(&syntax::minimal(), |store| {
        let annots = store.add(Object::Array(Vec::new())).unwrap();
        let page = object_with_type(store, b"Page");
        let mut dict = dict_of(store, page);
        dict.insert("Annots", Object::Ref(annots));
        store.set(page, Object::Dict(dict)).unwrap();
    });
    let signed = sign_default(&input, &rsa2048());
    assert!(first_signature(&signed).is_valid());
    let add_field = |store: &mut Store, repoint: bool| {
        let page = object_with_type(store, b"Page");
        let field = store
            .add(Object::Dict(Dict::from_iter([
                ("Type".into(), Object::name("Annot")),
                ("Subtype".into(), Object::name("Widget")),
                ("FT".into(), Object::name("Sig")),
                ("T".into(), Object::literal_string("Later")),
                ("F".into(), Object::Int(132)),
                ("Rect".into(), Object::Array(vec![Object::Int(0); 4])),
                ("P".into(), Object::Ref(page)),
            ])))
            .unwrap();
        let acroform = acroform_id(store);
        let mut form = dict_of(store, acroform);
        let mut fields = form.get_array(b"Fields").unwrap().to_vec();
        fields.push(Object::Ref(field));
        form.insert("Fields", Object::Array(fields));
        store.set(acroform, Object::Dict(form)).unwrap();
        let annots = dict_of(store, page).get_ref(b"Annots").unwrap();
        let mut items = store.resolve(annots).unwrap().as_array().unwrap().to_vec();
        items.push(Object::Ref(field));
        store.set(annots, Object::Array(items.clone())).unwrap();
        if repoint {
            let fresh = store.add(Object::Array(items)).unwrap();
            let mut dict = dict_of(store, page);
            dict.insert("Annots", Object::Ref(fresh));
            store.set(page, Object::Dict(dict)).unwrap();
        }
    };
    let r = first_signature(&update(&signed, |s| add_field(s, false)));
    assert_eq!(
        r.modification,
        ModificationLevel::LtaUpdates,
        "{}",
        summary(&r)
    );
    let r = first_signature(&update(&signed, |s| add_field(s, true)));
    assert_eq!(r.modification, ModificationLevel::Other, "{}", summary(&r));
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("no longer names it as /Annots")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn a_new_signature_field_may_carry_no_action_optional_content_or_parent() {
    // Every forbidden key on a new invisible signature field is OTHER; the keys signers write
    // (/MK, /TU, /DA, /Lock, /SV) are not.
    let signed = signed_base();
    let with = |key: &str, value: Object| {
        update(&signed, |store| {
            let page = object_with_type(store, b"Page");
            let mut dict = Dict::from_iter([
                ("Type".into(), Object::name("Annot")),
                ("Subtype".into(), Object::name("Widget")),
                ("FT".into(), Object::name("Sig")),
                ("T".into(), Object::literal_string("Later")),
                ("F".into(), Object::Int(132)),
                ("Rect".into(), Object::Array(vec![Object::Int(0); 4])),
                ("P".into(), Object::Ref(page)),
            ]);
            dict.insert(key, value);
            let field = store.add(Object::Dict(dict)).unwrap();
            let acroform = acroform_id(store);
            let mut form = dict_of(store, acroform);
            let mut fields = form.get_array(b"Fields").unwrap().to_vec();
            fields.push(Object::Ref(field));
            form.insert("Fields", Object::Array(fields));
            store.set(acroform, Object::Dict(form)).unwrap();
            let mut page_dict = dict_of(store, page);
            let mut annots = page_dict.get_array(b"Annots").unwrap_or_default().to_vec();
            annots.push(Object::Ref(field));
            page_dict.insert("Annots", Object::Array(annots));
            store.set(page, Object::Dict(page_dict)).unwrap();
        })
    };
    let action = Object::Dict(Dict::from_iter([
        ("S".into(), Object::name("JavaScript")),
        ("JS".into(), Object::literal_string("app.alert(1)")),
    ]));
    let sig_field = object_named(
        &Store::open_bytes(signed.clone(), &OpenOptions::default()).unwrap(),
        "Signature1",
    );
    for (key, value) in [
        ("A", action.clone()),
        ("AA", Object::Dict(Dict::from_iter([("PO".into(), action)]))),
        (
            "OC",
            Object::Dict(Dict::from_iter([("Type".into(), Object::name("OCMD"))])),
        ),
        ("Parent", Object::Ref(sig_field)),
    ] {
        let r = first_signature(&with(key, value));
        assert_eq!(
            r.modification,
            ModificationLevel::Other,
            "/{key}: {}",
            summary(&r)
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains(&format!("with /{key},"))),
            "/{key}: {:?}",
            r.warnings
        );
    }
    for (key, value) in [
        (
            "MK",
            Object::Dict(Dict::from_iter([(
                "BG".into(),
                Object::Array(vec![Object::Int(1)]),
            )])),
        ),
        ("TU", Object::literal_string("Sign here")),
        ("DA", Object::literal_string("/Helv 0 Tf 0 g")),
        (
            "Lock",
            Object::Dict(Dict::from_iter([("Action".into(), Object::name("All"))])),
        ),
        (
            "SV",
            Object::Dict(Dict::from_iter([("Ff".into(), Object::Int(1))])),
        ),
    ] {
        let r = first_signature(&with(key, value));
        assert_eq!(
            r.modification,
            ModificationLevel::LtaUpdates,
            "/{key}: {}",
            summary(&r)
        );
    }
}

// ---- The same defences on another signature layout -----------------------------------------------

#[test]
fn attacks_apply_to_ecdsa_signatures_on_xref_streams() {
    // P-256 over an xref-stream file: the update is a cross-reference stream.
    let base = sign_default(&folioxide_testkit::fixtures::syntax::xref_stream(), &p256());
    for case in corpus() {
        let Some(pdf) = (case.generate)(&base) else {
            continue;
        };
        let reports = verify_plain(&pdf);
        assert!(!reports.is_empty(), "{}", case.name);
        // A co-signer's own, later signature may be valid and unchanged (as in
        // `every_generator_applies_and_no_attack_is_valid`).
        let changed_or_broken = reports
            .iter()
            .filter(|r| {
                !r.field_name
                    .as_deref()
                    .is_some_and(|f| LATER_SIGNER_FIELDS.contains(&f))
            })
            .all(|r| !r.is_valid() || r.modification != ModificationLevel::None);
        assert!(
            changed_or_broken,
            "{}: {:?}",
            case.name,
            reports.iter().map(summary).collect::<Vec<_>>()
        );
    }
}

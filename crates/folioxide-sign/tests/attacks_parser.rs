#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Parser differentials after signing (M4 QA round 1, manager ruling R-1) against the `parser_*`
//! cases of the attack corpus: revisions whose bytes readers read differently (a duplicate
//! dictionary key at any depth, a trailer `/Root` written twice, an object stream that holds an
//! object twice, a section that lists a number twice). Folioxide's parser keeps the last value
//! of a duplicate key, pyHanko the first; the classifier does not depend on that choice: every
//! such revision is `Other`.

mod sign_support;

use folioxide_sign::report::{Coverage, ModificationLevel, SignatureReport};
use sign_support::corpus::{Base, attacked, corpus, our_value, pyhanko_value, signature1};
use sign_support::summary;

/// The report of `Signature1` after `name`: sound over its revision, at `level`.
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

/// `Other` with a warning that names `needle`; `docmdp_ok` false and never acceptable.
fn assert_ambiguous(name: &str, needle: &str) {
    let r = assert_revision(name, ModificationLevel::Other);
    assert_eq!(r.docmdp_ok, Some(false), "{name}");
    assert!(!r.is_acceptable(ModificationLevel::Annotations), "{name}");
    assert!(
        r.warnings.iter().any(|w| w.contains(needle)),
        "{name}: no warning names {needle:?}: {:?}",
        r.warnings
    );
    if let Some(ours) = our_value(name, "modification") {
        assert_eq!(ours, "other", "{name}");
        assert_ne!(pyhanko_value(name, "modification"), Some("other"), "{name}");
    }
}

#[test]
fn attacks_parser_relist_control() {
    // The same re-listing without a duplicate: LtaUpdates, as for pyHanko.
    let r = assert_revision("parser_relist_control", ModificationLevel::LtaUpdates);
    assert_eq!(r.docmdp_ok, Some(true));
}

#[test]
fn attacks_parser_dup_key_rect_moved_first() {
    assert_ambiguous("parser_dup_key_rect_moved_first", "duplicate key");
}

#[test]
fn attacks_parser_dup_key_rect_original_first() {
    assert_ambiguous("parser_dup_key_rect_original_first", "duplicate key");
}

#[test]
fn attacks_parser_dup_key_flags_hidden_first() {
    assert_ambiguous("parser_dup_key_flags_hidden_first", "duplicate key");
}

#[test]
fn attacks_parser_dup_key_value_evil_first() {
    assert_ambiguous("parser_dup_key_value_evil_first", "duplicate key");
}

#[test]
fn attacks_parser_dup_key_ap_page_content_first() {
    assert_ambiguous("parser_dup_key_ap_page_content_first", "duplicate key");
}

#[test]
fn attacks_parser_dup_key_ap_n_reverse() {
    assert_ambiguous("parser_dup_key_ap_n_reverse", "duplicate key");
}

#[test]
fn attacks_parser_dup_key_checkbox_state_first() {
    assert_ambiguous("parser_dup_key_checkbox_state_first", "duplicate key");
}

#[test]
fn attacks_parser_dup_key_page_annots_empty_first() {
    assert_ambiguous("parser_dup_key_page_annots_empty_first", "duplicate key");
}

#[test]
fn attacks_parser_dup_key_page_contents_new_first() {
    assert_ambiguous("parser_dup_key_page_contents_new_first", "duplicate key");
}

#[test]
fn attacks_parser_dup_key_trailer_root_new_first() {
    assert_ambiguous(
        "parser_dup_key_trailer_root_new_first",
        "trailer reads differently",
    );
}

#[test]
fn attacks_parser_dup_key_catalog_pages_new_first() {
    assert_ambiguous("parser_dup_key_catalog_pages_new_first", "duplicate key");
}

#[test]
fn attacks_parser_dup_key_annotation_rect_new_first() {
    assert_ambiguous("parser_dup_key_annotation_rect_new_first", "duplicate key");
}

#[test]
fn attacks_parser_xref_lists_number_twice() {
    assert_ambiguous("parser_xref_lists_number_twice", "more than once");
}

#[test]
fn attacks_parser_objstm_object_twice() {
    assert_ambiguous("parser_objstm_object_twice", "twice");
}

// ---- M4 QA round 3, ruling R-12: re-listed numbers spelled for another reader ----------------

/// `Other`: a re-listed signed object whose number is spelled with two signs, which Folioxide's
/// lexer reads as the signed value and PDFium as 0; pyHanko cannot read the file.
fn assert_respelled(name: &str) {
    let r = assert_revision(name, ModificationLevel::Other);
    assert_eq!(r.docmdp_ok, Some(false), "{name}");
    assert!(
        r.warnings.iter().any(|w| w.contains("several signs")),
        "{name}: {:?}",
        r.warnings
    );
    assert!(
        sign_support::corpus::pyhanko_raises(name).is_some(),
        "{name}"
    );
}

#[test]
fn attacks_parser_relisted_flags_multisign() {
    // QA variant F1-h-unhide-by-spelling-00: the hidden widget's /F 6 written `++6` (PDFium: 0,
    // shown) looked like a re-listing.
    assert_respelled("parser_relisted_flags_multisign");
}

#[test]
fn attacks_parser_relisted_rect_multisign() {
    // QA variant F8-h-rect-x-spelled-72-00.
    assert_respelled("parser_relisted_rect_multisign");
}

/// `Other`, stricter than pyHanko's re-listing: a re-listed signed object whose number is padded
/// with leading zeros, which Folioxide, poppler and pyHanko read as the signed value and PDFium
/// as 0 (M4 QA round 4, finding 2).
fn assert_zero_padded(name: &str) {
    let r = assert_revision(name, ModificationLevel::Other);
    assert_eq!(r.docmdp_ok, Some(false), "{name}");
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("longer than 11 characters")),
        "{name}: {:?}",
        r.warnings
    );
    match sign_support::corpus::pyhanko_raises(name) {
        // A padded reference: pyHanko cannot read the file.
        Some(_) => assert_eq!(our_value(name, "modification"), None, "{name}"),
        None => assert_eq!(our_value(name, "modification"), Some("other"), "{name}"),
    }
}

#[test]
fn attacks_parser_relisted_rect_zero_padded() {
    // Variant F1-i-relisted-rect-zero-padded-1000.
    assert_zero_padded("parser_relisted_rect_zero_padded");
}

#[test]
fn attacks_parser_relisted_flags_zero_padded() {
    assert_zero_padded("parser_relisted_flags_zero_padded");
}

#[test]
fn attacks_parser_relisted_page_contents_zero_padded() {
    // Variant R3-i-page-contents-ref-zero-padded-300: the reference names no object every
    // reader follows.
    assert_zero_padded("parser_relisted_page_contents_zero_padded");
}

#[test]
fn relisted_zero_padding_at_the_lengths_qa_tried() {
    // The corpus rows use 32 zeros (every installed reader reads them, so the oracle compares
    // pyHanko); QA's lengths, at which PDFium reads 0, are Other too, and 12 characters is the
    // first length refused while 11 stay a re-listing.
    use folioxide_testkit::fixtures::sign_attacks as m;
    let form = |base: Base| base.bytes();
    let cases: Vec<(Vec<u8>, ModificationLevel)> = vec![
        (
            m::parser_relisted_padded(&form(Base::Form), b"Rect", 1000).unwrap(),
            ModificationLevel::Other,
        ),
        (
            m::parser_relisted_padded(&form(Base::FormHidden), b"F", 300).unwrap(),
            ModificationLevel::Other,
        ),
        (
            m::parser_relisted_page_contents_padded(&form(Base::Ours), 300).unwrap(),
            ModificationLevel::Other,
        ),
        (
            // /Rect [72 …]: 9 zeros make 11 characters.
            m::parser_relisted_padded(&form(Base::Form), b"Rect", 9).unwrap(),
            ModificationLevel::LtaUpdates,
        ),
        (
            m::parser_relisted_padded(&form(Base::Form), b"Rect", 10).unwrap(),
            ModificationLevel::Other,
        ),
    ];
    for (index, (pdf, level)) in cases.into_iter().enumerate() {
        let r = signature1(&pdf);
        assert!(r.is_valid(), "{index}: {}", summary(&r));
        assert_eq!(r.modification, level, "{index}: {:?}", r.warnings);
    }
}

/// `Other`, stricter than pyHanko's fill: the update holds bytes its cross-reference section
/// does not account for (M4 QA round 4, finding 3).
fn assert_layout_refused(name: &str, needle: &str) {
    let r = assert_revision(name, ModificationLevel::Other);
    assert_eq!(r.docmdp_ok, Some(false), "{name}");
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("rebuilds the cross-reference data") && w.contains(needle)),
        "{name}: {:?}",
        r.warnings
    );
    assert_eq!(our_value(name, "modification"), Some("other"), "{name}");
}

#[test]
fn attacks_parser_unlisted_object_body() {
    // Variant F8-i-xref-trigger-xref-entries-19-bytes: an unlisted `4 0 obj` before the xref.
    assert_layout_refused(
        "parser_unlisted_object_body",
        "that its cross-reference section does not list there",
    );
}

#[test]
fn attacks_parser_junk_before_startxref() {
    assert_layout_refused("parser_junk_before_startxref", "neither an object");
}

#[test]
fn attacks_parser_relisted_rect_plus_control() {
    // One sign is canonical: every reader reads the signed value, a re-listing (pyHanko too).
    let r = assert_revision(
        "parser_relisted_rect_plus_control",
        ModificationLevel::LtaUpdates,
    );
    assert_eq!(r.docmdp_ok, Some(true));
}

/// Every `parser_*` case of the corpus has its test above.
#[test]
fn every_parser_case_is_tested() {
    let source = include_str!("attacks_parser.rs");
    for case in corpus() {
        if case.name.starts_with("parser_") {
            let test = format!("fn attacks_{}()", case.name);
            assert!(source.contains(&test), "{} has no test", case.name);
        }
    }
}

// ---- a revision chain readers follow differently (M4 QA round 2, finding 9) ---------------------

/// `pdf` (a signed `minimal.pdf`) with an update whose trailer gives `/Prev` twice: `first`, then
/// `last` (byte offsets of cross-reference sections).
fn with_two_prevs(pdf: &[u8], first: u64, last: u64) -> Vec<u8> {
    let store = folioxide_syntax::Store::open_bytes(pdf.to_vec(), &Default::default()).unwrap();
    let size = store.max_object_number() + 1;
    let root = store.root_id().unwrap();
    let mut out = pdf.to_vec();
    let xref = out.len();
    out.extend_from_slice(
        format!(
            "xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size {size} /Root {} {} R /Prev \
             {first} /Prev {last} >>\nstartxref\n{xref}\n%%EOF\n",
            root.num, root.r#gen
        )
        .as_bytes(),
    );
    out
}

#[test]
fn a_trailer_with_two_prev_values_is_refused() {
    // QA variant A7-r2-trailer-dup-prev-real-first: `/Prev <signed> /Prev <unsigned base>`. A
    // last-wins reader (Folioxide's parser) follows the base and sees no signature, while
    // pyHanko, pypdf and pdfsig follow the signed revision and list it (pyHanko: other): an
    // empty list would let a "no signatures" policy branch through, so verification is an
    // error (ErrorCode::Xref).
    let signed = sign_support::corpus::signed_base();
    let store = folioxide_syntax::Store::open_bytes(signed.clone(), &Default::default()).unwrap();
    let [base, real] = store.revisions() else {
        panic!("two revisions")
    };
    let (base, real) = (base.startxref, real.startxref);
    for (first, last) in [(real, base), (base, real)] {
        let pdf = with_two_prevs(&signed, first, last);
        let err = folioxide_sign::verify_pdf::verify_bytes(pdf, &Default::default()).unwrap_err();
        assert_eq!(err.code(), folioxide_syntax::ErrorCode::Xref, "{err}");
        assert!(err.to_string().contains("/Prev twice"), "{err}");
    }
    // The same value twice is no ambiguity: the update is judged as any other (R-1: its trailer
    // has a duplicate key, so the signature's level is Other).
    let pdf = with_two_prevs(&signed, real, real);
    let reports = folioxide_sign::verify_pdf::verify_bytes(pdf, &Default::default()).unwrap();
    let r = &reports[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.modification, ModificationLevel::Other, "{:?}", r.warnings);
}

#[test]
fn signing_on_top_of_two_prev_values_is_refused() {
    // M4 QA round 3, finding 13 (refusals3.py): a P = 1 certified file with an update whose
    // trailer gives `/Prev <signed> /Prev <unsigned base>`. Folioxide's last-wins reading follows
    // the base and sees no certification, so rule (b) did not refuse and an approval was written
    // over it (verification then failed with E_XREF). The signing side now refuses any file
    // whose revision chain readers follow differently, in either order.
    use folioxide_sign::docmdp::DocMdpPermissions;
    use folioxide_sign::prepare::SignatureOptions;
    use folioxide_sign::sign::{SignRequest, sign};
    let certified = sign_support::corpus::certify(
        &folioxide_testkit::fixtures::syntax::minimal(),
        DocMdpPermissions::NoChanges,
    );
    let store =
        folioxide_syntax::Store::open_bytes(certified.clone(), &Default::default()).unwrap();
    let [base, real] = store.revisions() else {
        panic!("two revisions")
    };
    let (base, real) = (base.startxref, real.startxref);
    let signer = sign_support::rsa2048();
    for (first, last) in [(real, base), (base, real)] {
        let pdf = with_two_prevs(&certified, first, last);
        let doc = sign_support::open(&pdf);
        let request = SignRequest::new(&signer, sign_support::time())
            .with_options(SignatureOptions::new(sign_support::time()));
        let err = sign(&doc, &request).unwrap_err();
        assert_eq!(err.code(), folioxide_syntax::ErrorCode::Xref, "{err}");
        assert!(err.to_string().contains("/Prev twice"), "{err}");
    }
    // The control: the same value twice reads the same everywhere, so rule (b) applies (P = 1).
    let pdf = with_two_prevs(&certified, real, real);
    let doc = sign_support::open(&pdf);
    let request = SignRequest::new(&signer, sign_support::time())
        .with_options(SignatureOptions::new(sign_support::time()));
    let err = sign(&doc, &request).unwrap_err();
    assert_eq!(
        err.code(),
        folioxide_syntax::ErrorCode::DocMdpForbids,
        "{err}"
    );
}

// ---- M4 QA round 5, manager rulings R-17, R-18 and R-21: rebuild-proof updates -------------

/// `Other` for a file whose end makes poppler rebuild the cross-reference data (ruling R-17
/// (a), (b)); pyHanko cannot read it (EOF marker not found).
fn assert_tail_refused(name: &str) {
    let r = assert_revision(name, ModificationLevel::Other);
    assert_eq!(r.docmdp_ok, Some(false), "{name}");
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("the file ends with") && w.contains("R-17")),
        "{name}: {:?}",
        r.warnings
    );
    assert!(
        sign_support::corpus::pyhanko_raises(name).is_some(),
        "{name}"
    );
}

#[test]
fn attacks_parser_tail_pad_lf() {
    // Findings 13 and 17 (variant A1-r6-tailpad-lf-40k).
    assert_tail_refused("parser_tail_pad_lf");
}

#[test]
fn attacks_parser_tail_pad_space() {
    assert_tail_refused("parser_tail_pad_space");
}

#[test]
fn attacks_parser_tail_pad_nul() {
    assert_tail_refused("parser_tail_pad_nul");
}

#[test]
fn attacks_parser_tail_pad_crlf() {
    assert_tail_refused("parser_tail_pad_crlf");
}

#[test]
fn attacks_parser_tail_pad_comment() {
    // Findings 10 and 16 (variant A1-r5-tail-pad-comment-31500).
    assert_tail_refused("parser_tail_pad_comment");
}

#[test]
fn attacks_parser_tail_pad_mixed() {
    // Findings 21 and 22.
    assert_tail_refused("parser_tail_pad_mixed");
}

#[test]
fn attacks_parser_tail_extra_eol() {
    // Ruling R-17 (b): three bytes after %%EOF; pyHanko reads a fill (a deliberate row).
    let r = assert_revision("parser_tail_extra_eol", ModificationLevel::Other);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("after its last `%%EOF`")),
        "{:?}",
        r.warnings
    );
    assert_eq!(
        our_value("parser_tail_extra_eol", "modification"),
        Some("other")
    );
}

#[test]
fn tails_at_the_bound_stay_fills() {
    // The controls of ruling R-17 (b): one or two end-of-line bytes after the fill's %%EOF.
    use folioxide_testkit::fixtures::sign_attacks as m;
    let form = Base::Form.bytes();
    for (pad, level) in [
        (&b"\n"[..], ModificationLevel::FormFilling),
        (b"\r", ModificationLevel::FormFilling),
        (b"\n\n", ModificationLevel::Other),
        (b" ", ModificationLevel::Other),
        (b"\0", ModificationLevel::Other),
    ] {
        let pdf = m::tail_padded(&form, pad, pad.len()).unwrap();
        let r = signature1(&pdf);
        assert!(r.is_valid(), "{pad:?}: {}", summary(&r));
        assert_eq!(r.modification, level, "{pad:?}: {:?}", r.warnings);
    }
}

#[test]
fn attacks_parser_fake_object_in_ap_stream() {
    // Ruling R-17 (d), findings 10 and 13.
    assert_layout_refused("parser_fake_object_in_ap_stream", "object header");
}

#[test]
fn attacks_parser_fake_object_in_value_string() {
    assert_layout_refused("parser_fake_object_in_value_string", "object header");
}

#[test]
fn attacks_parser_honest_fill_structure_words() {
    // Final fix round 2, finding 3 (variants F1-k-honest-fill-value-*): a fill whose value holds
    // `xref`, `startxref`, `12 3 object`, `4 7 objective` and `trailer <b>` inside its line is a
    // fill, as for pyHanko.
    let r = assert_revision(
        "parser_honest_fill_structure_words",
        ModificationLevel::FormFilling,
    );
    assert_eq!(r.docmdp_ok, Some(true));
    assert_eq!(
        our_value("parser_honest_fill_structure_words", "modification"),
        None
    );
}

#[test]
fn attacks_parser_ap_stream_long_digit_line() {
    // Closing round, findings 2 and 6 (variants gd_digits*MB, perf_digits): a fill whose new
    // appearance stream holds one 4 MiB line of digits is a fill, as for pyHanko; the rebuild
    // scan reads it in linear time (16 MB took three minutes before, quadratic in the line).
    let r = assert_revision(
        "parser_ap_stream_long_digit_line",
        ModificationLevel::FormFilling,
    );
    assert_eq!(r.docmdp_ok, Some(true));
    assert_eq!(
        our_value("parser_ap_stream_long_digit_line", "modification"),
        None
    );
}

#[test]
fn honest_fill_values_with_structure_words_stay_fills() {
    // Each value of the finding on its own, and the same words where poppler looks (the start
    // of a line inside the value string): those are Other.
    use folioxide_testkit::fixtures::forms::{self, AMOUNT, Fill};
    use folioxide_testkit::fixtures::sign_attacks::HONEST_STRUCTURE_WORDS;
    let form = Base::Form.bytes();
    for value in HONEST_STRUCTURE_WORDS {
        let pdf = forms::fill(&form, &Fill::text(AMOUNT, value)).unwrap();
        let r = signature1(&pdf);
        assert!(r.is_valid(), "{value}: {}", summary(&r));
        assert_eq!(
            r.modification,
            ModificationLevel::FormFilling,
            "{value}: {:?}",
            r.warnings
        );
    }
    // A raw line break (CR LF, the same length as the serializer's `\n` escape) before the word.
    for (value, other) in [
        ("see\nxref table", true),
        ("see\nstartxref", true),
        ("Item\n4 7 objective", true),
        ("Room\n12 3 object", true),
        ("see\ntrailer <b>", false),
        ("see\ntrailer park", false),
        ("see\n999 EUR", false),
    ] {
        let filled = forms::fill(&form, &Fill::text(AMOUNT, value)).unwrap();
        let escaped = value.replace('\n', "\\n");
        let at = filled
            .windows(escaped.len())
            .rposition(|w| w == escaped.as_bytes())
            .unwrap();
        let mut pdf = filled.clone();
        pdf[at..at + escaped.len()].copy_from_slice(value.replace('\n', "\r\n").as_bytes());
        let r = signature1(&pdf);
        assert!(r.intact && r.signature_valid, "{value}: {}", summary(&r));
        let want = if other {
            ModificationLevel::Other
        } else {
            ModificationLevel::FormFilling
        };
        assert_eq!(r.modification, want, "{value:?}: {:?}", r.warnings);
    }
}

#[test]
fn attacks_parser_startxref_corrupted() {
    // Ruling R-17 (c): the store repairs the structure, so the change cannot be attributed.
    let r = signature1(&attacked("parser_startxref_corrupted"));
    assert!(r.intact && r.signature_valid, "{}", summary(&r));
    assert_eq!(r.modification, ModificationLevel::Other, "{:?}", r.warnings);
    assert_eq!(r.docmdp_ok, Some(false));
    assert!(
        r.has_problem(folioxide_sign::ProblemCode::StructureRepaired)
            || r.warnings.iter().any(|w| w.contains("R-17")),
        "{}: {:?}",
        summary(&r),
        r.warnings
    );
    assert_eq!(
        our_value("parser_startxref_corrupted", "modification"),
        Some("other")
    );
}

#[test]
fn attacks_parser_objstm_member_unlisted() {
    // Ruling R-18, finding 27 (variants R5v-hidden-objstm-member-*): pyHanko says ltaUpdates.
    let r = assert_revision("parser_objstm_member_unlisted", ModificationLevel::Other);
    assert_eq!(r.docmdp_ok, Some(false));
    assert!(
        r.warnings.iter().any(|w| w.contains("R-18")),
        "{:?}",
        r.warnings
    );
    assert_eq!(
        sign_support::corpus::pyhanko_value("parser_objstm_member_unlisted", "modification"),
        Some("ltaUpdates")
    );
}

#[test]
fn attacks_parser_xref_subsection_padded() {
    // Ruling R-21, findings 11 and 30.
    assert_layout_refused("parser_xref_subsection_padded", "subsection header");
}

#[test]
fn attacks_parser_xref_entries_19_bytes() {
    // Ruling R-21: a 19-byte entry makes PDFium rebuild.
    assert_layout_refused("parser_xref_entries_19_bytes", "entry");
}

#[test]
fn object_stream_members_must_be_listed_where_they_are() {
    // Ruling R-18 (Rust-only variants of finding 27): a correctly listed object stream in an
    // update stays an LTA update; a member the revision also writes uncompressed, and members
    // listed at each other's index, are Other.
    use folioxide_testkit::fixtures::sign_attacks as m;
    let base = Base::Ours.bytes();
    let control = signature1(&m::parser_objstm_member_listed_control(&base).unwrap());
    assert!(control.is_valid(), "{}", summary(&control));
    assert_eq!(
        control.modification,
        ModificationLevel::LtaUpdates,
        "{:?}",
        control.warnings
    );
    assert_eq!(control.docmdp_ok, Some(true));
    for pdf in [
        m::parser_objstm_member_listed_elsewhere(&base).unwrap(),
        m::parser_objstm_member_index_mismatch(&base).unwrap(),
    ] {
        // The store itself repairs a member found at another index (StructureRepaired).
        let r = signature1(&pdf);
        assert!(r.intact && r.signature_valid, "{}", summary(&r));
        assert_eq!(r.modification, ModificationLevel::Other, "{:?}", r.warnings);
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("R-18") || w.contains("holds another object"))
                || r.has_problem(folioxide_sign::ProblemCode::StructureRepaired),
            "{}: {:?}",
            summary(&r),
            r.warnings
        );
    }
}

#[test]
fn attacks_parser_trailer_size_shrunk() {
    // Closing round, finding 13 (manager ruling R-26): the fill's trailer gives /Size 3; PDFium
    // keeps only the objects numbered below the newest /Size, so it would show the page without
    // its content, fonts and widgets. pyHanko (non-strict) reads past it: formFilling.
    assert_size_refused("parser_trailer_size_shrunk", "/Size 3");
}

#[test]
fn attacks_parser_trailer_size_shrunk_info_only() {
    // The same /Size 3 on an /Info-only update (pyHanko: ltaUpdates).
    assert_size_refused("parser_trailer_size_shrunk_info_only", "/Size 3");
}

#[test]
fn attacks_parser_trailer_size_off_by_one() {
    // /Size equal to the highest object number listed: that object is dropped.
    assert_size_refused(
        "parser_trailer_size_off_by_one",
        "but the file's sections list",
    );
}

#[test]
fn attacks_parser_trailer_size_over_declared_info_only() {
    // M4 final fix round 2 (verification round), expert finding 1, the expert's gap3.pdf: an
    // /Info-only update whose trailer says /Size 100 over objects numbered up to 8. ISO 32000-2
    // Table 15 wants the highest number + 1, but a larger /Size drops no object in any reader:
    // ltaUpdates, as for pyHanko.
    let r = assert_revision(
        "parser_trailer_size_over_declared_info_only",
        ModificationLevel::LtaUpdates,
    );
    assert_eq!(r.docmdp_ok, Some(true));
}

#[test]
fn attacks_parser_trailer_size_over_declared_then_cosigned() {
    // The same update, then our own co-signature (the expert's gap4.pdf): the signer numbers its
    // new objects from the declared /Size, as pyHanko's writer does, so the co-signature's own
    // /Size is not below 100 (manager ruling R-26) and Signature1 stays formFilling, as for
    // pyHanko. It was other while the signer numbered from the highest listed number + 1.
    use folioxide_syntax::{OpenOptions, Store};
    use sign_support::corpus::{COSIGNER_FIELD, OVER_DECLARED_SIZE};
    let name = "parser_trailer_size_over_declared_then_cosigned";
    let r = assert_revision(name, ModificationLevel::FormFilling);
    assert_eq!(r.docmdp_ok, Some(true));
    assert!(
        r.is_acceptable(ModificationLevel::FormFilling),
        "{:?}",
        r.warnings
    );
    assert!(
        !r.warnings.iter().any(|w| w.contains("/Size")),
        "{:?}",
        r.warnings
    );
    assert_eq!(our_value(name, "modification"), None);

    let pdf = attacked(name);
    let store = Store::open_bytes(pdf.clone(), &OpenOptions::default()).unwrap();
    let newest = store.revisions().len() - 1;
    let size = store.revisions()[newest].trailer.get_int(b"Size").unwrap();
    assert!(size > i64::from(OVER_DECLARED_SIZE), "/Size {size}");
    // Every number the co-signature lists is one an earlier revision lists (an edited object)
    // or a new one from the declared /Size up.
    let earlier: Vec<u32> = (0..newest)
        .flat_map(|index| store.revision_entries(index).unwrap())
        .map(|(num, _)| num)
        .collect();
    for (num, _) in store.revision_entries(newest).unwrap() {
        assert!(
            earlier.contains(&num) || num >= OVER_DECLARED_SIZE,
            "object {num} is new below the declared /Size"
        );
    }
    let cosigner = sign_support::verify_plain(&pdf)
        .into_iter()
        .find(|r| r.field_name.as_deref() == Some(COSIGNER_FIELD))
        .unwrap();
    assert!(cosigner.is_valid(), "{}", summary(&cosigner));
    assert_eq!(cosigner.modification, ModificationLevel::None);
}

#[test]
fn save_incremental_after_an_over_declared_size_keeps_lta_updates() {
    // Manager ruling R-30 (a) (QA reproductions h_save.mjs, size_incr.mjs and
    // exp10/save_inc.mjs): pyHanko's signature on minimal.pdf, an /Info-only update whose
    // trailer over-declares /Size, then a plain Document::save_incremental after set_info. The
    // incremental writer keeps the declared /Size (it wrote the highest number + 1, below the
    // previous /Size, for which the verifier made the signature other), so Signature1 stays
    // ltaUpdates, as for pyHanko (validate_sig.py: LTA_UPDATES for both sizes).
    use folioxide_model::{Document, InfoUpdate};
    use folioxide_syntax::{IncrementalOptions, OpenOptions, Store};
    use folioxide_testkit::fixtures::sign_attacks as m;
    let base = Base::PyHanko.bytes();
    for size in [100u32, 99_999] {
        let declared =
            m::with_last_size(&m::isa_info_only(&base).unwrap(), &size.to_string()).unwrap();
        let before = signature1(&declared);
        assert_eq!(
            before.modification,
            ModificationLevel::LtaUpdates,
            "/Size {size}: {:?}",
            before.warnings
        );

        let mut doc = Document::open(declared.clone(), &OpenOptions::default()).unwrap();
        let mut update = InfoUpdate::default();
        update.title = Some(Some("x".to_owned()));
        doc.set_info(&update).unwrap();
        let saved = doc
            .save_incremental(&IncrementalOptions::default())
            .unwrap();
        assert!(saved.starts_with(&declared), "/Size {size}");

        let store = Store::open_bytes(saved.clone(), &OpenOptions::default()).unwrap();
        assert!(!store.structure_repaired(), "{:?}", store.diagnostics());
        let newest = store.revisions().len() - 1;
        let declared_store = Store::open_bytes(declared.clone(), &OpenOptions::default()).unwrap();
        assert_eq!(newest, declared_store.revisions().len(), "/Size {size}");
        assert_eq!(
            store.revisions()[newest].trailer.get_int(b"Size"),
            Some(i64::from(size)),
            "/Size {size}"
        );
        assert!(store.max_object_number() < size, "/Size {size}");

        let r = signature1(&saved);
        let s = summary(&r);
        assert!(
            r.intact && r.signature_valid && r.is_valid(),
            "/Size {size}: {s}"
        );
        assert_eq!(r.coverage, Coverage::EntireRevision, "/Size {size}: {s}");
        assert_eq!(
            r.modification,
            ModificationLevel::LtaUpdates,
            "/Size {size}: {s} {:?}",
            r.warnings
        );
        assert_eq!(r.docmdp_ok, Some(true), "/Size {size}");
        assert!(
            !r.warnings.iter().any(|w| w.contains("/Size")),
            "/Size {size}: {:?}",
            r.warnings
        );
    }
}

/// `Other` for a `/Size` defect (closing round, finding 13), with a warning that names `needle`,
/// and a deliberate difference from pyHanko, which reads past the `/Size`.
fn assert_size_refused(name: &str, needle: &str) {
    assert_ambiguous(name, needle);
    let r = signature1(&attacked(name));
    assert!(
        r.warnings.iter().any(|w| w.contains("PDFium keeps only")),
        "{name}: {:?}",
        r.warnings
    );
    assert_eq!(our_value(name, "modification"), Some("other"), "{name}");
}

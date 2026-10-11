#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Verification of signed files (M3 brief §5, §6.2 "verify"): every report field of our own
//! signatures, tampering, appended revisions, the gap check, discovery (orphans, document
//! timestamps, direct values), the input rules, coverage tolerances, repairs and the validation
//! time.

mod sign_support;

use folioxide_model::{Document, InfoUpdate};
use folioxide_sign::ProblemCode;
use folioxide_sign::placeholder::write_placeholder;
use folioxide_sign::prepare::SignatureOptions;
use folioxide_sign::report::{Coverage, ModificationLevel, PadesLevel, SignatureKind};
use folioxide_sign::verify_pdf::{VerifyOptions, verify as verify_doc, verify_bytes};
use folioxide_syntax::{ErrorCode, IncrementalOptions, Object, ObjectId, OpenOptions};
use folioxide_testkit::fixtures::{id_array, sign_attacks, syntax};
use folioxide_testkit::{PdfBuilder, XrefOpts};
use sign_support::*;

#[test]
fn verify_unsigned_documents_have_no_reports() {
    for (name, source) in syntax::all() {
        let Ok(doc) = Document::open(source, &OpenOptions::default()) else {
            continue;
        };
        assert!(
            verify_doc(&doc, &VerifyOptions::default())
                .unwrap()
                .is_empty(),
            "{name}"
        );
    }
}

#[test]
fn verify_own_signature_all_fields() {
    let options = SignatureOptions::new(time())
        .with_name(Some("Folioxide Tester".into()))
        .with_reason(Some("Approved \u{2014} v2".into()))
        .with_location(Some("Berlin".into()))
        .with_contact_info(Some("+49 30 000000".into()));
    let signed = sign_with(&syntax::minimal(), &rsa2048(), options);
    let reports = verify(&signed);
    assert_eq!(reports.len(), 1);
    let r = &reports[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.field_name.as_deref(), Some("Signature1"));
    assert_eq!(r.kind, SignatureKind::Signature);
    assert_ne!(r.sig_object, ObjectId::new(0, 0));
    assert_eq!(r.sub_filter.as_deref(), Some("ETSI.CAdES.detached"));
    let range = r.byte_range.clone().unwrap();
    assert_eq!(range.len(), 4);
    assert_eq!(range[0], 0);
    assert_eq!((range[2] + range[3]) as usize, signed.len());
    assert!(r.byte_range_ok && r.intact && r.signature_valid);
    assert_eq!(r.coverage, Coverage::EntireFile);
    assert_eq!(r.signed_revision, Some(1));
    assert_eq!(r.modification, ModificationLevel::None);
    assert!(r.changed_objects.is_empty());
    assert_eq!(r.digest_algorithm.as_deref(), Some("sha256"));
    assert_eq!(
        r.signature_algorithm.as_deref(),
        Some("sha256WithRSAEncryption")
    );
    let signer = r.signer.as_ref().unwrap();
    assert_eq!(
        signer.common_name.as_deref(),
        Some("Folioxide Test Signer RSA-2048")
    );
    assert_eq!(r.chain.len(), 3);
    assert!(r.chain.iter().any(|c| c.der == signer.der));
    assert!(r.trusted.is_some());
    if trust_implemented() {
        assert_eq!(r.trusted, Some(true), "{:?}", r.warnings);
    }
    assert_eq!(r.claimed_time.as_deref(), Some("2026-10-10T12:00:00Z"));
    assert_eq!(r.name.as_deref(), Some("Folioxide Tester"));
    assert_eq!(r.reason.as_deref(), Some("Approved \u{2014} v2"));
    assert_eq!(r.location.as_deref(), Some("Berlin"));
    assert_eq!(r.contact_info.as_deref(), Some("+49 30 000000"));
    assert_eq!(r.pades_level, Some(PadesLevel::BB));
    assert_eq!(r.docmdp, None);
    assert_eq!(r.docmdp_ok, None);
    assert!(r.problems.is_empty());

    // Without trust anchors there is no trust verdict.
    let plain = verify_plain(&signed);
    assert_eq!(plain[0].trusted, None);
    assert!(plain[0].is_valid());
}

#[test]
fn verify_detects_byte_flip_in_range() {
    let signed = sign_default(&syntax::minimal(), &p256());
    let range = verify(&signed)[0].byte_range.clone().unwrap();
    let (a, b) = (range[1] as usize, range[2] as usize);
    // A byte in signed part 1 (inside the page content), and in part 2 (a hexadecimal digit of
    // the update's trailer /ID, after the gap).
    let content_at = signed
        .windows(8)
        .position(|w| w == b"minimal)")
        .expect("the page text");
    assert!(content_at < a);
    let id_at = b
        + signed[b..]
            .windows(6)
            .position(|w| w == b"/ID [<")
            .expect("the update's trailer /ID after the gap")
        + 6;
    for (at, replacement) in [(content_at, signed[content_at] ^ 0x01), (id_at, b'F')] {
        let mut tampered = signed.clone();
        assert_ne!(tampered[at], replacement);
        tampered[at] = replacement;
        let reports = verify(&tampered);
        let r = &reports[0];
        assert!(!r.intact, "flip at {at}: {}", summary(r));
        assert!(r.signature_valid, "the signed attributes still verify");
        assert!(r.has_problem(ProblemCode::DigestMismatch));
        assert!(!r.is_valid());
        // pyHanko: `trusted = valid and intact and ...`: a changed document is never trusted,
        // although the signer's certification path is fine.
        assert_eq!(r.trusted, Some(false), "{:?}", r.warnings);
        assert!(
            r.warnings.iter().any(|w| w.contains("not intact")),
            "{:?}",
            r.warnings
        );
    }
}

#[test]
fn verify_detects_appended_revision() {
    let signed = sign_default(&syntax::minimal(), &rsa2048());
    // An /Info update after signing: LTA-level, as pyHanko's DocInfoRule.
    let mut doc = open(&signed);
    let mut update = InfoUpdate::default();
    update.title = Some(Some("Changed later".into()));
    doc.set_info(&update).unwrap();
    let with_info = doc
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    let r = &verify(&with_info)[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.coverage, Coverage::EntireRevision);
    assert_eq!(r.signed_revision, Some(1));
    assert_eq!(
        r.modification,
        ModificationLevel::LtaUpdates,
        "{:?}",
        r.warnings
    );
    assert!(!r.changed_objects.is_empty());

    // A page content change after signing: OTHER, and the changed object is named.
    let mut doc = open(&signed);
    let page = doc.page_ids().unwrap()[0].0;
    let content = doc
        .store()
        .resolve(page)
        .unwrap()
        .as_dict()
        .unwrap()
        .get_ref(b"Contents")
        .unwrap();
    let stream = folioxide_syntax::Stream::new(
        folioxide_syntax::Dict::new(),
        folioxide_syntax::StreamData::Decoded(b"BT /F1 12 Tf (changed) Tj ET".to_vec()),
    );
    doc.store_mut()
        .set(content, Object::Stream(Box::new(stream)))
        .unwrap();
    let with_content = doc
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    let r = &verify(&with_content)[0];
    assert!(r.intact && r.signature_valid, "{}", summary(r));
    assert_eq!(r.coverage, Coverage::EntireRevision);
    assert_eq!(r.modification, ModificationLevel::Other);
    assert!(
        r.changed_objects.contains(&content),
        "{:?}",
        r.changed_objects
    );
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("modified after signing"))
    );

    // Both in sequence: the worst level counts.
    let mut doc = open(&with_info);
    let page = doc.page_ids().unwrap()[0].0;
    let mut page_dict = doc
        .store()
        .resolve(page)
        .unwrap()
        .as_dict()
        .unwrap()
        .clone();
    page_dict.insert("Rotate", Object::Int(90));
    doc.store_mut().set(page, Object::Dict(page_dict)).unwrap();
    let both = doc
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    let r = &verify(&both)[0];
    assert_eq!(r.modification, ModificationLevel::Other);
}

#[test]
fn verify_rejects_byterange_gap_mismatch() {
    let signed = sign_default(&syntax::minimal(), &rsa2048());
    let wrapped = sign_attacks::swa_gap_points_at_other_contents(&signed).unwrap();
    let reports = verify(&wrapped);
    assert_eq!(reports.len(), 1);
    let r = &reports[0];
    assert!(r.has_problem(ProblemCode::GapNotContents), "{}", summary(r));
    assert!(!r.byte_range_ok);
    assert_eq!(r.coverage, Coverage::Unclear);
    assert_eq!(r.modification, ModificationLevel::Other);
    assert_eq!(r.pades_level, None);
    assert!(!r.is_valid());
}

#[test]
fn verify_rejects_whitespace_in_contents_gap() {
    // Same length, same CMS: the last four padding digits of /Contents become "00  ". The gap is
    // still the /Contents token and the CMS is intact, but the token is not two digits per byte,
    // so pyHanko's formula (2 * len(Contents) + 2) no longer explains the gap: UNCLEAR for it,
    // and the same for us (expert finding 12, ws_contents).
    let signed = sign_default(&syntax::minimal(), &rsa2048());
    let range = verify(&signed)[0].byte_range.clone().unwrap();
    let b = range[2] as usize;
    assert_eq!(&signed[b - 5..b], b"0000>");
    let mut spaced = signed.clone();
    spaced[b - 3..b - 1].copy_from_slice(b"  ");
    let r = &verify(&spaced)[0];
    let s = summary(r);
    assert!(r.intact && r.signature_valid, "{s}");
    assert!(r.has_problem(ProblemCode::GapNotContents), "{s}");
    assert!(!r.byte_range_ok, "{s}");
    assert_eq!(r.coverage, Coverage::Unclear, "{s}");
    assert_eq!(r.modification, ModificationLevel::Other);
    assert_eq!(r.pades_level, None);
    assert!(!r.is_valid(), "{s}");

    // An odd digit count whose padded value still spans 2 * len + 2 bytes is what pyHanko's
    // formula accepts (ENTIRE_FILE): the last digit becomes a space, the decoded length is
    // unchanged.
    let mut odd = signed.clone();
    odd[b - 2] = b' ';
    let r = &verify(&odd)[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.coverage, Coverage::EntireFile);
}

#[test]
fn verify_pyhanko_fixture_agrees() {
    // Every pyHanko-made fixture of fixtures/sign/pdf; the field-by-field comparison with
    // pyHanko's own validation is interop_pyhanko.rs.
    let fixtures = pyhanko_fixtures();
    assert!(fixtures.len() >= 8, "{} pyHanko fixtures", fixtures.len());
    for (name, pdf) in fixtures {
        let reports = verify(&pdf);
        if name == "pyhanko-empty-field.pdf" {
            assert!(reports.is_empty(), "an unsigned field is not a signature");
            continue;
        }
        assert!(!reports.is_empty(), "{name}");
        for r in &reports {
            // pyHanko signs with /Contents before /ByteRange: the gap check must not depend on
            // the key order.
            assert!(r.byte_range_ok, "{name}: {}", summary(r));
            assert!(r.intact, "{name}: {}", summary(r));
            assert!(r.field_name.is_some(), "{name}");
            assert!(
                matches!(r.coverage, Coverage::EntireFile | Coverage::EntireRevision),
                "{name}: {}",
                summary(r)
            );
            if r.kind == SignatureKind::DocTimeStamp {
                assert!(r.has_problem(ProblemCode::PendingTimestampVerification));
            } else {
                assert!(r.is_valid(), "{name}: {}", summary(r));
                assert_eq!(r.trusted, Some(true), "{name}: {:?}", r.warnings);
            }
        }
        let last = reports.last().unwrap();
        assert_eq!(last.coverage, Coverage::EntireFile, "{name}");
        assert_eq!(last.modification, ModificationLevel::None, "{name}");
        // Earlier signatures: a later signature is form filling, a document timestamp an LTA
        // update, as pyHanko says.
        for r in &reports[..reports.len() - 1] {
            assert!(
                r.modification <= ModificationLevel::FormFilling,
                "{name}: {} {:?}",
                summary(r),
                r.warnings
            );
        }
    }
}

#[test]
fn verify_pending_edits_rejected() {
    let signed = sign_default(&syntax::minimal(), &p256());
    let mut doc = open(&signed);
    let mut update = InfoUpdate::default();
    update.title = Some(Some("pending".into()));
    doc.set_info(&update).unwrap();
    let err = verify_doc(&doc, &VerifyOptions::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
}

#[test]
fn verify_orphan_reported() {
    let signed = sign_default(&syntax::minimal(), &rsa2048());
    let with_orphan = sign_attacks::swa_two_dicts_same_byterange(&signed).unwrap();
    let reports = verify(&with_orphan);
    assert_eq!(reports.len(), 2);
    // The field's signature first, the orphan last.
    let (field, orphan) = (&reports[0], &reports[1]);
    assert_eq!(field.field_name.as_deref(), Some("Signature1"));
    assert!(field.is_valid(), "{}", summary(field));
    assert_eq!(field.coverage, Coverage::EntireRevision);
    assert_eq!(orphan.field_name, None);
    assert!(
        orphan.has_problem(ProblemCode::Orphan),
        "{}",
        summary(orphan)
    );
    assert!(orphan.has_problem(ProblemCode::GapNotContents));
    assert!(!orphan.byte_range_ok);
    assert!(!orphan.is_valid());
}

/// A signed-looking file whose only signature dictionary is a document timestamp
/// (`/SubFilter /ETSI.RFC3161`, §12.8.5) holding a CMS that is not a timestamp token.
fn doc_timestamp_file() -> Vec<u8> {
    let doc = open(&syntax::minimal());
    let placeholder = write_placeholder(&doc, &SignatureOptions::new(time())).unwrap();
    let mut pdf = placeholder.pdf.clone();
    // Relabel the SubFilter in place, keeping every offset.
    let from = b"/ETSI.CAdES.detached";
    let at = pdf.windows(from.len()).position(|w| w == from).unwrap();
    pdf[at..at + from.len()].copy_from_slice(b"/ETSI.RFC3161       ");
    // Any DER fills /Contents (a CMS from the fixtures).
    let cms = std::fs::read(repo().join("fixtures/sign/openssl-p256-cades.p7s")).unwrap();
    let start = placeholder.contents_range.0 as usize + 1;
    for (i, byte) in cms.iter().enumerate() {
        let hex = format!("{byte:02X}");
        pdf[start + 2 * i..start + 2 * i + 2].copy_from_slice(hex.as_bytes());
    }
    pdf
}

#[test]
fn verify_doc_timestamp_listed() {
    let reports = verify(&doc_timestamp_file());
    assert_eq!(reports.len(), 1);
    let r = &reports[0];
    assert_eq!(r.kind, SignatureKind::DocTimeStamp);
    assert_eq!(r.sub_filter.as_deref(), Some("ETSI.RFC3161"));
    assert!(
        r.has_problem(ProblemCode::PendingTimestampVerification),
        "{}",
        summary(r)
    );
    assert!(!r.signature_valid);
    assert!(!r.is_valid());
    assert!(
        r.byte_range_ok,
        "the byte range itself is sound: {}",
        summary(r)
    );
    assert_eq!(r.coverage, Coverage::EntireFile);
}

#[test]
fn verify_direct_and_broken_values() {
    // A field whose /V is a direct dictionary, and one whose /V is an integer.
    let mut b = PdfBuilder::new();
    b.header("1.7");
    b.obj(
        1,
        0,
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R 5 0 R] >> >>",
    );
    b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    b.obj(
        3,
        0,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R 5 0 R] >>",
    );
    b.obj(
        4,
        0,
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Direct) /Rect [0 0 0 0] /P 3 0 R \
         /V << /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached \
         /ByteRange [0 10 20 30] /Contents <00> >> >>",
    );
    b.obj(
        5,
        0,
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Number) /Rect [0 0 0 0] /P 3 0 R /V 7 >>",
    );
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array("direct-v")
    );
    b.trailer(trailer).startxref(None).eof();
    let reports = verify_plain(&b.build());
    assert_eq!(reports.len(), 2);
    let direct = reports
        .iter()
        .find(|r| r.field_name.as_deref() == Some("Direct"))
        .unwrap();
    assert!(direct.has_problem(ProblemCode::SigValueNotIndirect));
    assert!(!direct.byte_range_ok && !direct.is_valid());
    let number = reports
        .iter()
        .find(|r| r.field_name.as_deref() == Some("Number"))
        .unwrap();
    assert!(number.has_problem(ProblemCode::SigDictNotDictionary));
    assert!(!number.is_valid());
}

#[test]
fn verify_trailing_eol_tolerated() {
    let signed = sign_default(&syntax::minimal(), &p384());
    for tail in [&b"\r\n"[..], b"\n", b"% a comment, not an update\n"] {
        let mut longer = signed.clone();
        longer.extend_from_slice(tail);
        let r = &verify(&longer)[0];
        assert!(r.is_valid(), "{tail:?}: {}", summary(r));
        assert_eq!(r.coverage, Coverage::EntireRevision, "{tail:?}");
        assert_eq!(r.signed_revision, Some(1));
        assert_eq!(r.modification, ModificationLevel::None, "{tail:?}");
    }
    // The signed bytes may also end a byte or two before the revision's end of line: the
    // newest revision is found with up to two CR/LF bytes of slack.
    let mut b = PdfBuilder::new();
    b.header("1.7");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>");
    b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    b.obj(
        3,
        0,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
    );
    b.xref_table(XrefOpts::default());
    let trailer = format!("/Size {} /Root 1 0 R /ID {}", b.size(), id_array("crlf"));
    b.trailer(trailer).startxref(None).raw(b"%%EOF\r\n");
    let crlf = b.build();
    let signed = sign_default(&crlf, &p256());
    let r = &verify(&signed)[0];
    assert!(r.is_valid(), "{}", summary(r));
}

#[test]
fn verify_whole_file_repaired_is_none_with_warning() {
    // A content stream whose /Length is wrong: the store repairs it when the object is read
    // (a recovered object), while the cross-reference structure is sound, so it can be signed.
    let mut b = PdfBuilder::new();
    b.header("1.7");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>");
    b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    b.obj(
        3,
        0,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
    );
    b.obj(
        4,
        0,
        "<< /Length 3 >>\nstream\nBT (short length) Tj ET\nendstream",
    );
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array("short-length")
    );
    b.trailer(trailer).startxref(None).eof();
    let source = b.build();
    let signed = sign_default(&source, &rsa2048());

    let doc = open(&signed);
    let reports = verify_doc(&doc, &VerifyOptions::default()).unwrap();
    assert!(
        !doc.store().recovered_objects().is_empty() || doc.store().structure_repaired(),
        "the fixture must need a repair"
    );
    let r = &reports[0];
    assert_eq!(r.coverage, Coverage::EntireFile);
    assert_eq!(r.modification, ModificationLevel::None);
    assert!(r.is_valid(), "{}", summary(r));
    assert!(
        r.warnings.iter().any(|w| w.contains("repaired")),
        "{:?}",
        r.warnings
    );

    // The same repair with a later revision: the change cannot be attributed.
    let mut doc = open(&signed);
    let mut update = InfoUpdate::default();
    update.title = Some(Some("later".into()));
    doc.set_info(&update).unwrap();
    let later = doc
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    let r = &verify(&later)[0];
    assert_eq!(r.coverage, Coverage::EntireRevision);
    assert_eq!(r.modification, ModificationLevel::Other);
    assert!(
        r.has_problem(ProblemCode::StructureRepaired),
        "{}",
        summary(r)
    );
    assert!(!r.is_valid());
}

#[test]
fn verify_validation_time_option() {
    let signed = sign_default(&syntax::minimal(), &p256());
    let claimed = |r: &folioxide_sign::report::SignatureReport| {
        r.warnings
            .iter()
            .any(|w| w.contains("claimed signing time"))
    };
    // Anchors without a time: validated at /M, with a warning.
    let at_claimed = verify_bytes(
        signed.clone(),
        &VerifyOptions::new().with_trust_anchors_der(anchors()),
    )
    .unwrap();
    assert!(claimed(&at_claimed[0]), "{:?}", at_claimed[0].warnings);
    assert!(at_claimed[0].trusted.is_some());
    // With a validation time: no warning.
    let at_time = verify(&signed);
    assert!(!claimed(&at_time[0]), "{:?}", at_time[0].warnings);
    if trust_implemented() {
        assert_eq!(at_time[0].trusted, Some(true));
        // Long after the certificates expire (2075), the signer is not trusted.
        let late = folioxide_model::PdfDate::parse(b"D:20800101000000Z").unwrap();
        let reports = verify_bytes(
            signed,
            &VerifyOptions::new()
                .with_trust_anchors_der(anchors())
                .with_validation_time(Some(late)),
        )
        .unwrap();
        assert_eq!(reports[0].trusted, Some(false));
    }
}

#[test]
fn verify_bytes_refuses_unreadable_input() {
    assert!(verify_bytes(b"not a pdf".to_vec(), &VerifyOptions::default()).is_err());
}

/// A one-page file whose signature field's `/V` is object 5 in the object stream 6 (M3 brief
/// §5 V4, R-4). With `compress: false` the stream is stored as is, so the ByteRange can leave
/// out exactly the `/Contents` hex string inside it, and the CMS is made over those ranges: the
/// digest and the signature check out, and only the location of the dictionary is wrong. With
/// `compress: true` the same dictionary text is Flate-compressed afterwards, as a rewrite with
/// object streams (qpdf, pikepdf) does.
fn sig_dict_in_object_stream(compress: bool) -> Vec<u8> {
    use folioxide_sign::algorithms::DigestAlgorithm;
    use folioxide_sign::cms;
    use folioxide_sign::signer::Signer;
    use folioxide_testkit::{ObjStmOpts, XrefStreamOpts};

    const RESERVE: usize = 8192;
    let build = |sig_dict: &str, compress: bool| {
        let mut b = PdfBuilder::new();
        b.header("1.7");
        b.obj(
            1,
            0,
            "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 >> >>",
        )
        .obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .obj(
            3,
            0,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>",
        )
        .obj(
            4,
            0,
            "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) /V 5 0 R \
             /Rect [0 0 0 0] /F 132 /P 3 0 R >>",
        )
        .objstm(
            6,
            &[(5, sig_dict)],
            ObjStmOpts::new().with_compression(compress),
        )
        .xref_stream(
            7,
            XrefStreamOpts::new()
                .with_trailer(format!("/Root 1 0 R /ID {}", id_array("objstm-sig"))),
        );
        b.startxref(None).eof();
        b.build()
    };
    let field = |value: usize| format!("{value:<10}");
    let dict = |byte_range: [usize; 3], contents_hex: &str| {
        format!(
            "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached \
             /ByteRange [0 {} {} {}] /Contents <{contents_hex}> /M (D:20261010120000Z) >>",
            field(byte_range[0]),
            field(byte_range[1]),
            field(byte_range[2])
        )
    };

    // Lay the file out with placeholders, then find where /Contents landed.
    let zeros = "0".repeat(RESERVE * 2);
    let mut pdf = build(&dict([0; 3], &zeros), false);
    let hex_start = find(&pdf, format!("/Contents <{zeros}>").as_bytes()) + "/Contents ".len();
    let hex_end = hex_start + zeros.len() + 2;
    let ranges = [hex_start, hex_end, pdf.len() - hex_end];
    // Same lengths, so nothing moves.
    pdf = build(&dict(ranges, &zeros), false);
    assert_eq!(find(&pdf, b"/Contents <") + "/Contents ".len(), hex_start);

    // The CMS over exactly those ranges.
    let signer = rsa2048();
    let digest = DigestAlgorithm::Sha256;
    let document_digest = digest.digest(&[&pdf[..hex_start], &pdf[hex_end..]]);
    let chain = signer.certificate_chain().to_vec();
    let signed_attrs = cms::build_signed_attrs(&cms::SignedAttrsInput {
        digest,
        document_digest: &document_digest,
        signer_cert_der: &chain[0],
    })
    .unwrap();
    let signature = signer.sign(digest, &signed_attrs).unwrap();
    let cms_der = cms::assemble(
        &signed_attrs,
        &signature,
        &chain,
        signer.algorithm(),
        signer.key_kind(),
        digest,
    )
    .unwrap();
    assert!(cms_der.len() <= RESERVE);
    let mut hex: String = cms_der.iter().map(|b| format!("{b:02X}")).collect();
    hex.push_str(&"0".repeat(RESERVE * 2 - hex.len()));
    let pdf = build(&dict(ranges, &hex), compress);
    if !compress {
        assert_eq!(
            digest.digest(&[&pdf[..hex_start], &pdf[hex_end..]]),
            document_digest
        );
    }
    pdf
}

fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap()
}

/// M3 brief §5 V4 and R-4: a signature dictionary in an object stream can never leave its
/// own `/Contents` out of the signed bytes, so it is `SigDictCompressed` and not
/// `byteRangeOk`, even when the ByteRange skips exactly the hex string and the digest and the
/// signature are correct.
///
/// Folioxide is stricter than the oracles here: on the uncompressed file pyHanko 0.37.0
/// reports intact, valid, `ENTIRE_FILE` and `NONE`, and `pdfsig` "Signature is Valid" (checked
/// when this test was written). On the compressed file pyHanko reports not intact,
/// `CONTIGUOUS_BLOCK_FROM_START` and `OTHER`.
#[test]
fn verify_sig_dict_in_object_stream_is_compressed() {
    let pdf = sig_dict_in_object_stream(false);
    let reports = verify(&pdf);
    assert_eq!(reports.len(), 1);
    let r = &reports[0];
    assert_eq!(r.field_name.as_deref(), Some("Signature1"));
    assert_eq!(r.sig_object, ObjectId::new(5, 0));
    // The cryptography alone would accept it.
    assert!(r.intact && r.signature_valid, "{}", summary(r));
    assert!(
        r.has_problem(ProblemCode::SigDictCompressed),
        "{}",
        summary(r)
    );
    assert!(!r.byte_range_ok, "{}", summary(r));
    assert!(!r.is_valid());
    let message = &r
        .problems
        .iter()
        .find(|p| p.code == ProblemCode::SigDictCompressed)
        .unwrap()
        .message;
    assert!(message.contains("6 0 R"), "{message}");

    // Compressed, as a rewrite with object streams leaves it: the stale ByteRange no longer
    // matches either.
    let pdf = sig_dict_in_object_stream(true);
    let r = &verify(&pdf)[0];
    assert!(
        r.has_problem(ProblemCode::SigDictCompressed),
        "{}",
        summary(r)
    );
    assert!(
        !r.byte_range_ok && !r.intact && !r.is_valid(),
        "{}",
        summary(r)
    );
}

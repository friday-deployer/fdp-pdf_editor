#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The signature oracle suites (M3 brief §6.3): `sign-bb`, `sign-tamper` and `sign-attacks`.
//!
//! Every case writes its expect.json `signatures[]` values (`intact`, `valid`, `trusted`,
//! `coverage`, `modification`, `pades`) **from Folioxide's own report** (brief §0;
//! `sign_support::oracle`), so `cargo xtask oracle --suite <s>` is a pyHanko / pdfsig / OpenSSL
//! versus Folioxide differential. Where Folioxide is deliberately stricter, the expect file
//! carries pyHanko's value from the `DELIBERATE_DIFFERENCES` table and the Rust test asserts
//! ours. Cases where every oracle rejects the signature use `rejected: true` (DECISIONS D10
//! D-3); cases pyHanko cannot read carry our values and list the pyHanko row in
//! `knownFailures`.

mod sign_support;

use folioxide_model::{Document, InfoUpdate};
use folioxide_sign::ProblemCode;
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::cms;
use folioxide_sign::field::{FieldMode, FieldSpec, SubFilter};
use folioxide_sign::prepare::{PrepareRequest, SignatureOptions, prepare};
use folioxide_sign::report::{Coverage, ModificationLevel, SignatureKind};
use folioxide_sign::sign::{SignRequest, sign};
use folioxide_sign::signer::{LocalSigner, Signer};
use folioxide_syntax::OpenOptions;
use folioxide_testkit::emit::{emit_file, json_string};
use folioxide_testkit::fixtures::{id_array, qpdf, syntax};
use folioxide_testkit::{EMIT_ENABLED, ExpectJson, PdfBuilder, XrefOpts, emit_case};
use sign_support::corpus::{
    ATTACKED_FIELD, Reference, attacked, corpus, pyhanko_raises, pyhanko_value,
};
use sign_support::oracle::{TRUST_ROOT, entry, signatures, startxref_count};
use sign_support::*;

/// One oracle case: the signed file, its input (for `prefixOf`), and the expectation.
struct Case {
    name: String,
    pdf: Vec<u8>,
    input: Option<Vec<u8>>,
    expect: ExpectJson,
}

/// A `sign-bb` case: `signed` was made from `input`; every signature must be sound.
fn bb_case(name: &str, input: &[u8], signed: Vec<u8>, require_trust: Option<bool>) -> Case {
    assert!(signed.starts_with(input), "{name}: prefix");
    let reports = verify(&signed);
    assert!(!reports.is_empty(), "{name}");
    for (i, r) in reports.iter().enumerate() {
        if r.kind == SignatureKind::DocTimeStamp {
            // A document timestamp of the input: listed, intact, not verified in M3.
            assert!(r.intact && r.byte_range_ok, "{name}: {}", summary(r));
            assert!(
                r.problems
                    .iter()
                    .all(|p| p.code == ProblemCode::PendingTimestampVerification),
                "{name}: {}",
                summary(r)
            );
        } else {
            assert!(
                r.intact && r.signature_valid && r.byte_range_ok,
                "{name}: {}",
                summary(r)
            );
            assert!(r.problems.is_empty(), "{name}: {}", summary(r));
        }
        let last = i + 1 == reports.len();
        if last {
            assert_eq!(r.coverage, Coverage::EntireFile, "{name}");
            assert_eq!(r.modification, ModificationLevel::None, "{name}");
        } else {
            assert_eq!(r.coverage, Coverage::EntireRevision, "{name}");
        }
        if trust_implemented()
            && let Some(trusted) = require_trust
            && last
        {
            assert_eq!(r.trusted, Some(trusted), "{name}: {:?}", r.warnings);
        }
    }
    let doc = open(&signed);
    let mut expect = ExpectJson::new()
        .raw("trustRoots", format!("[{}]", json_string(TRUST_ROOT)))
        .int("pages", doc.page_count().unwrap() as i64)
        .int("revisions", startxref_count(&signed))
        .string("prefixOf", &format!("{name}.input.pdf"))
        .raw("signatures", signatures(&reports, true));
    let known = bb_known_failures(name);
    if !known.is_empty() {
        expect = expect.string_map("knownFailures", &known);
    }
    Case {
        name: name.to_owned(),
        pdf: signed,
        input: Some(input.to_vec()),
        expect,
    }
}

/// Reader warnings on the **input** of a case, which the signature's incremental update keeps
/// byte for byte (the writer suite lists the same ones for these sources).
fn bb_known_failures(name: &str) -> Vec<(&'static str, &'static str)> {
    const NOT_ZERO_INDEXED: &str = "pypdf 6 strict mode warns 'Xref table not zero-indexed' for \
        the source's own update sections, whose first subsection does not start at 0 (ISO \
        32000-2 §7.5.6 allows it); the signature's update keeps them byte for byte, and its own \
        section starts at 0";
    const LINEARIZED_TABLE: &str = "pypdf 6 strict mode warns 'Xref table not zero-indexed' for \
        the source's first-page cross-reference table, whose only subsection starts at the \
        linearization dictionary's number (Annex F); the signature's update keeps it byte for \
        byte";
    match name {
        "multi-revision" => vec![("structure.pypdf", NOT_ZERO_INDEXED)],
        "linearized" => vec![("structure.pypdf", LINEARIZED_TABLE)],
        _ => Vec::new(),
    }
}

/// Signs `input` once with `signer` and `options` as a `sign-bb` case.
fn bb_single(name: &str, input: &[u8], signer: &LocalSigner, options: SignatureOptions) -> Case {
    let signed = sign_with(input, signer, options);
    bb_case(name, input, signed, Some(true))
}

/// A document with an unsigned signature field `Approval` (merged with its widget).
fn empty_field_document() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.7");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>");
    b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    b.obj(
        3,
        0,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots [6 0 R] \
         /Resources << /Font << /F1 7 0 R >> >> >>",
    );
    b.stream_obj(
        4,
        0,
        "",
        b"BT /F1 12 Tf 72 720 Td (Approval form) Tj ET",
        None,
    );
    b.obj(5, 0, "<< /Fields [6 0 R] >>");
    b.obj(
        6,
        0,
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Approval) /F 132 /Rect [0 0 0 0] /P 3 0 R >>",
    );
    b.obj(
        7,
        0,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    );
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array("empty-field")
    );
    b.trailer(trailer).startxref(None).eof();
    b.build()
}

/// The `sign-bb` cases (brief §6.3).
fn bb_cases() -> Vec<Case> {
    let minimal = syntax::minimal();
    let options = || SignatureOptions::new(time());
    let mut cases = vec![
        bb_single("rsa2048-p12-modern", &minimal, &rsa2048(), options()),
        bb_single(
            "rsa2048-p12-3des",
            &minimal,
            &p12("signer-rsa2048-3des.p12"),
            options(),
        ),
        bb_single(
            "rsa2048-p12-rc2-40",
            &minimal,
            &p12("signer-rsa2048-rc2-40.p12"),
            options(),
        ),
        bb_single(
            "rsa2048-pkcs1-pem",
            &minimal,
            &pem_signer("signer-rsa2048.key.pkcs1.pem", "signer-rsa2048.pem"),
            options(),
        ),
        bb_single(
            "rsa3072-pem-sha384",
            &minimal,
            &rsa3072(),
            options().with_digest(Some(DigestAlgorithm::Sha384)),
        ),
        bb_single(
            "rsa3072-pem-sha512",
            &minimal,
            &rsa3072(),
            options().with_digest(Some(DigestAlgorithm::Sha512)),
        ),
        bb_single(
            "p256-p12",
            &minimal,
            &p12("signer-p256-modern.p12"),
            options(),
        ),
        bb_single(
            "p256-sec1-pem",
            &minimal,
            &pem_signer("signer-p256.key.sec1.pem", "signer-p256.pem"),
            options(),
        ),
        bb_single("p384-sha384", &minimal, &p384(), options()),
        bb_single(
            "unicode-reason",
            &minimal,
            &p256(),
            options()
                .with_reason(Some("Freigegeben \u{2014} \u{3042}\u{3044}".into()))
                .with_location(Some("K\u{f6}ln".into())),
        ),
        bb_single(
            "adbe-pkcs7-detached",
            &minimal,
            &rsa2048(),
            options().with_sub_filter(SubFilter::AdbePkcs7Detached),
        ),
        bb_single(
            "small-reserve-retry",
            &minimal,
            &p256(),
            options().with_contents_reserve(Some(100)),
        ),
    ];

    // The external flow: a P-256 signer that returns IEEE P1363, and a whole CMS.
    let signer = p256();
    let request = PrepareRequest::new(
        signer.certificate_chain().to_vec(),
        signer.algorithm(),
        time(),
    );
    let prepared = prepare(&open(&minimal), &request).unwrap();
    let der = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let p1363 = der_to_p1363(&der, 32);
    cases.push(bb_case(
        "external-p256-p1363",
        &minimal,
        prepared.finish(&p1363).unwrap(),
        Some(true),
    ));
    let signer = rsa2048();
    let request = PrepareRequest::new(
        signer.certificate_chain().to_vec(),
        signer.algorithm(),
        time(),
    );
    let prepared = prepare(&open(&minimal), &request).unwrap();
    let value = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let cms_der = cms::assemble(
        prepared.to_be_signed(),
        &value,
        signer.certificate_chain(),
        signer.algorithm(),
        signer.key_kind(),
        prepared.digest_algorithm(),
    )
    .unwrap();
    cases.push(bb_case(
        "embed-cms-rsa2048",
        &minimal,
        prepared.embed_cms(&cms_der).unwrap(),
        Some(true),
    ));

    // Several signatures.
    let first = sign_default(&minimal, &rsa2048());
    cases.push(bb_case(
        "two-signatures",
        &minimal,
        sign_default(&first, &p256()),
        Some(true),
    ));
    let xref_stream = syntax::xref_stream();
    let one = sign_default(&xref_stream, &rsa2048());
    let two = sign_with(
        &one,
        &p384(),
        options().with_field(FieldSpec::new().with_name(Some("Approval".into()))),
    );
    let three = sign_with(
        &two,
        &rsa3072(),
        options().with_digest(Some(DigestAlgorithm::Sha512)),
    );
    cases.push(bb_case("three-mixed", &xref_stream, three, Some(true)));

    // Field and edit cases.
    let empty = empty_field_document();
    cases.push(bb_single(
        "existing-empty-field",
        &empty,
        &p256(),
        options().with_field(
            FieldSpec::new()
                .with_name(Some("Approval".into()))
                .with_mode(FieldMode::ExistingOnly),
        ),
    ));
    let mut doc = open(&minimal);
    let mut update = InfoUpdate::default();
    update.title = Some(Some("Signed with a pending title".into()));
    doc.set_info(&update).unwrap();
    let signed = sign(&doc, &SignRequest::new(&rsa2048(), time())).unwrap();
    let mut case = bb_case("pending-title", &minimal, signed, Some(true));
    case.expect = case.expect.raw(
        "info",
        format!(
            "{{\"Title\": {}}}",
            json_string("Signed with a pending title")
        ),
    );
    cases.push(case);

    // One per cross-reference shape.
    for (name, input) in [
        ("xref-stream", syntax::xref_stream()),
        ("hybrid", syntax::hybrid()),
        ("objstm", syntax::objstm()),
        ("xref-stream-incremental", syntax::xref_stream_incremental()),
        ("multi-revision", syntax::multi_revision()),
        ("linearized", qpdf::read_committed("linearized").unwrap()),
    ] {
        cases.push(bb_single(name, &input, &rsa2048(), options()));
    }

    // Untrusted signers: the signature is sound, the certificate is not.
    cases.push(bb_case(
        "wrong-ku",
        &minimal,
        sign_default(&minimal, &pem_signer("wrong-ku.key.pem", "wrong-ku.pem")),
        Some(false),
    ));
    cases.push(bb_case(
        "expired",
        &minimal,
        sign_default(&minimal, &pem_signer("expired.key.pem", "expired.pem")),
        Some(false),
    ));

    // On top of every pyHanko-made fixture that can be signed (WP3.2B; the P=1 certified one
    // cannot): the earlier signatures (and a document timestamp) become form filling, and a
    // P=2 certification allows it (docmdp 2, docmdpOk true).
    let mut after = 0;
    for (file, source) in pyhanko_fixtures() {
        let doc = Document::open(source.clone(), &OpenOptions::default()).unwrap();
        if let Err(err) = folioxide_sign::placeholder::check_signable(&doc) {
            assert_eq!(file, "pyhanko-certified-p1.pdf", "{err}");
            continue;
        }
        let stem = file.trim_end_matches(".pdf").replace('.', "-");
        let signed = sign_default(&source, &p256());
        let case = bb_case(&format!("after-{stem}"), &source, signed, Some(true));
        let reports = verify(&case.pdf);
        for r in &reports[..reports.len() - 1] {
            assert_eq!(r.modification, ModificationLevel::FormFilling, "{file}");
        }
        if file == "pyhanko-certified-p2.pdf" {
            assert_eq!(reports[0].docmdp, Some(2));
            assert!(
                case.expect
                    .get("signatures")
                    .unwrap()
                    .contains("\"docmdpOk\": true")
            );
        }
        cases.push(case);
        after += 1;
    }
    assert!(after >= 6, "{after} cases on top of pyHanko fixtures");
    cases
}

/// IEEE P1363 `r || s` of a DER `ECDSA-Sig-Value`.
fn der_to_p1363(der: &[u8], half: usize) -> Vec<u8> {
    let mut pos = 2;
    let mut out = Vec::new();
    for _ in 0..2 {
        let len = der[pos + 1] as usize;
        let int: Vec<u8> = der[pos + 2..pos + 2 + len]
            .iter()
            .copied()
            .skip_while(|&b| b == 0)
            .collect();
        out.extend(std::iter::repeat_n(0, half - int.len()));
        out.extend(int);
        pos += 2 + len;
    }
    out
}

/// The `sign-tamper` cases: bytes changed after signing.
fn tamper_cases() -> Vec<Case> {
    let signed = sign_default(&syntax::minimal(), &p256());
    let range = verify(&signed)[0].byte_range.clone().unwrap();
    let (a, b) = (range[1] as usize, range[2] as usize);
    let page_text = signed.windows(8).position(|w| w == b"minimal)").unwrap();
    let trailer_id = b + signed[b..].windows(6).position(|w| w == b"/ID [<").unwrap() + 6;
    let cms_len = {
        let report = &verify(&signed)[0];
        let _ = report;
        // The DER length of the CMS: the outer element of the /Contents value.
        let hex = &signed[a + 1..b - 1];
        let byte = |i: usize| {
            u8::from_str_radix(std::str::from_utf8(&hex[2 * i..2 * i + 2]).unwrap(), 16).unwrap()
        };
        let first = byte(1) as usize;
        if first < 0x80 {
            2 + first
        } else {
            let n = first & 0x7F;
            2 + n + (0..n).fold(0usize, |acc, i| (acc << 8) | byte(2 + i) as usize)
        }
    };
    let padding_digit = a + 1 + 2 * cms_len + 10;
    assert!(padding_digit < b - 1);

    let mut cases = Vec::new();
    for (name, at, value) in [
        (
            "tamper-part1-page-content",
            page_text,
            signed[page_text] ^ 0x01,
        ),
        ("tamper-part2-trailer-id", trailer_id, b'F'),
        ("tamper-nonzero-padding", padding_digit, b'1'),
    ] {
        let mut pdf = signed.clone();
        assert_ne!(pdf[at], value);
        pdf[at] = value;
        let reports = verify(&pdf);
        let r = &reports[0];
        let mut expect = ExpectJson::new()
            .raw("trustRoots", format!("[{}]", json_string(TRUST_ROOT)))
            .raw("signatures", signatures(&reports, false));
        if name == "tamper-nonzero-padding" {
            // Bytes after the CMS are not signed and are ignored (D-19): still intact and valid.
            assert!(r.intact && r.signature_valid, "{name}: {}", summary(r));
            assert!(
                r.warnings
                    .iter()
                    .any(|w| w.contains("non-zero bytes after the CMS"))
            );
            expect = expect.string_map(
                "knownFailures",
                &[("signatures[0].padding", "tamper: non-zero padding")],
            );
        } else {
            // ROADMAP §M3 acceptance #3: a changed byte inside the signed range.
            assert!(!r.intact, "{name}: {}", summary(r));
            assert!(!r.is_valid());
        }
        cases.push(Case {
            name: name.to_owned(),
            pdf,
            input: None,
            expect,
        });
    }
    cases
}

/// The `sign-attacks` cases: the corpus on our RSA-2048 signature (signature wrapping on
/// pyHanko's, whose `/ByteRange` is in signed part 2).
fn attack_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for case in corpus() {
        let pdf = attacked(case.name);
        let reports = verify_plain(&pdf);
        let mut expect = ExpectJson::new();
        match case.reference {
            Reference::Rejected => {
                let entries: Vec<String> = reports
                    .iter()
                    .filter_map(|r| r.field_name.as_deref())
                    .map(|field| {
                        format!("{{\"field\": {}, \"rejected\": true}}", json_string(field))
                    })
                    .collect();
                expect = expect.raw("signatures", format!("[{}]", entries.join(", ")));
            }
            Reference::Status | Reference::PyhankoRaises => {
                // A deliberate difference concerns the attacked signature; a later signature
                // in the same case (a co-signer's) is compared as it is.
                let entries: Vec<String> = reports
                    .iter()
                    .filter(|r| r.field_name.is_some())
                    .map(|r| {
                        let attacked = r.field_name.as_deref() == Some(ATTACKED_FIELD);
                        let overrides = |field: &str| {
                            attacked.then(|| pyhanko_value(case.name, field)).flatten()
                        };
                        entry(r, &overrides, false)
                    })
                    .collect();
                expect = expect.raw("signatures", format!("[{}]", entries.join(", ")));
            }
        }
        let known = attack_known_failures(case.name);
        if !known.is_empty() {
            expect = expect.string_map("knownFailures", &known);
        }
        cases.push(Case {
            name: case.name.replace('_', "-"),
            pdf,
            input: None,
            expect,
        });
    }
    cases
}

/// Oracle checks that are expected to fail on an attack file, with the reason: the structure
/// rows of the files that are malformed by design (the attack is a broken cross-reference
/// structure that a lenient reader repairs), and the pyHanko and extraction rows of the files
/// pyHanko cannot read ([`PYHANKO_RAISES`](sign_support::corpus::PYHANKO_RAISES)).
fn attack_known_failures(name: &str) -> Vec<(&'static str, &'static str)> {
    const BAD_STARTXREF: &str = "attack by design: the appended update's startxref points past \
        the end of the file, so the reader must reconstruct the cross-reference data (pikepdf \
        warns 'file is damaged', pypdf strict mode refuses the broken xref)";
    const PREV_ZERO: &str = "attack by design: the appended trailer's /Prev 0 skips the signed \
        revision and names no cross-reference section, so the reader must reconstruct the \
        cross-reference data";
    const PART2_SHIFTED: &str = "attack by design: bytes inserted inside signed part 2 move every \
        later object and the cross-reference table away from their offsets";
    match name.replace('-', "_").as_str() {
        "isa_bad_startxref_update" => vec![
            ("structure.pikepdf", BAD_STARTXREF),
            ("structure.pypdf", BAD_STARTXREF),
            (
                "signatures.pyhanko",
                pyhanko_raises("isa_bad_startxref_update").unwrap(),
            ),
        ],
        "isa_prev_skips_signed_revision" => vec![
            ("structure.pdfinfo", PREV_ZERO),
            ("structure.pikepdf", PREV_ZERO),
            ("structure.pypdf", PREV_ZERO),
            (
                "signatures.pyhanko",
                pyhanko_raises("isa_prev_skips_signed_revision").unwrap(),
            ),
            (
                "signatures.count.fields",
                "extract_cms (pypdf) follows the trailer's /Prev 0 and finds no signature field",
            ),
            (
                "signatures[0].extract",
                "extract_cms (pypdf) follows the trailer's /Prev 0 and finds no signature \
                 dictionary, so the OpenSSL route cannot run; pdfsig validates the signature",
            ),
        ],
        "swa_part2_shifted" => vec![
            ("structure.pdfinfo", PART2_SHIFTED),
            ("structure.pikepdf", PART2_SHIFTED),
            ("structure.pypdf", PART2_SHIFTED),
        ],
        "shadow_overlay_sig_widget_no_rect" => vec![(
            "structure.pdfinfo",
            "attack by design: the new widget has no /Rect, which every annotation needs \
             (ISO 32000-2 §12.5.2), so poppler reports a bad bounding box; pyHanko treats it as \
             invisible and its appearance as form filling, as Folioxide does (QA T3)",
        )],
        // The gap row is the SWA defence itself (brief §5.1): intact and valid for pyHanko,
        // pdfsig and us, but the gap is not the /Contents token.
        "swa_part2_moved" => vec![(
            "signatures[0].extract",
            "signature wrapping by design: the /ByteRange gap holds the /Contents token plus the \
             unsigned dictionary tail and the attacker's cross-reference section, so extract_cms \
             refuses it (Folioxide: gapNotContents); pyHanko (unclear/other) and pdfsig validate \
             the signed bytes, as Folioxide does",
        )],
        // Reader differentials on CMS structure: pyHanko and Folioxide refuse the SignedData,
        // one secondary oracle checks less and accepts it.
        "usf_cms_two_signerinfos" => vec![(
            "signatures[0].rejected.pdfsig",
            "poppler/NSS verifies only SignerInfo 0 (the real one) and ignores the second; \
             pyHanko (CMSExtractionError) and Folioxide (signerInfoCount) refuse a SignedData \
             with two SignerInfos, and OpenSSL fails on the corrupted second one",
        )],
        "usf_cms_econtent_present" => vec![(
            "signatures[0].rejected.openssl",
            "openssl cms -verify checks the signed attributes against the detached byte ranges \
             it is given and ignores the encapsulated content; pyHanko (FORMAT_FAILURE) and \
             Folioxide (eContentPresent) refuse eContent on a detached SubFilter, and pdfsig \
             reports a digest mismatch",
        )],
        _ => Vec::new(),
    }
}

/// Writes the cases of `suite` and their inputs.
fn emit(suite: &str, cases: &[Case]) -> usize {
    let mut written = 0;
    for case in cases {
        if let Some(input) = &case.input {
            emit_file(suite, &format!("{}.input.pdf", case.name), input).unwrap();
        }
        if emit_case(suite, &case.name, &case.pdf, &case.expect)
            .unwrap()
            .is_some()
        {
            written += 1;
        }
    }
    written
}

#[test]
fn oracle_sign_bb() {
    let cases = bb_cases();
    assert!(cases.len() >= 18, "{} cases", cases.len());
    let written = emit("sign-bb", &cases);
    assert_eq!(written, if EMIT_ENABLED { cases.len() } else { 0 });
}

#[test]
fn oracle_sign_tamper() {
    let cases = tamper_cases();
    assert!(cases.len() >= 3);
    let written = emit("sign-tamper", &cases);
    assert_eq!(written, if EMIT_ENABLED { cases.len() } else { 0 });
}

#[test]
fn oracle_sign_attacks() {
    let cases = attack_cases();
    // Every case is oracle-checked: none is skipped (the D-3 `rejected` key covers the cases
    // pyHanko refuses or does not list).
    assert!(
        cases.iter().all(|c| c.expect.get("oracleSkip").is_none()),
        "no sign-attacks case may skip the oracle"
    );
    let checked = cases
        .iter()
        .filter(|c| {
            !c.expect
                .get("signatures")
                .unwrap_or_default()
                .contains("rejected")
        })
        .count();
    assert!(checked >= 12, "only {checked} checked cases");
    let written = emit("sign-attacks", &cases);
    assert_eq!(written, if EMIT_ENABLED { cases.len() } else { 0 });
}

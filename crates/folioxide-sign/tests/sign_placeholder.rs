#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! M3 brief §6.2 "placeholder" and the PDF side of "prepare" (Dev A): the incremental update
//! with the `/ByteRange` and `/Contents` placeholders (§4.1, §4.2) on every syntax fixture,
//! the in-place byte-range patch, the uncompressed signature dictionary, `/M`, object numbering
//! that never reuses a freed number, pending edits in the same revision, and the refusals of
//! §4.5 "Preconditions" (DECISIONS D10), which `prepare` makes before any cryptography.

use folioxide_model::{Document, InfoUpdate, PdfDate};
use folioxide_sign::Error;
use folioxide_sign::algorithms::{DigestAlgorithm, SignatureAlgorithm};
use folioxide_sign::field::{FieldSpec, SubFilter};
use folioxide_sign::placeholder::{
    BYTE_RANGE_PLACEHOLDER, MAX_CONTENTS_RESERVE, MIN_CONTENTS_RESERVE, PlaceholderPdf,
    check_signable, write_placeholder,
};
use folioxide_sign::prepare::{PrepareRequest, SignatureOptions, prepare};
use folioxide_syntax::{
    ErrorCode, IncrementalOptions, Object, ObjectLocation, OpenOptions, PdfString, Store,
    Strictness, XrefEntry, XrefKind,
};
use folioxide_testkit::fixtures::{id_array, qpdf, syntax};
use folioxide_testkit::{PdfBuilder, XrefOpts};

// ---- helpers ------------------------------------------------------------------------------------

fn time() -> PdfDate {
    PdfDate::parse(b"D:20261010120000Z").unwrap()
}

fn open(bytes: &[u8]) -> Document {
    Document::open(bytes.to_vec(), &OpenOptions::default()).unwrap()
}

fn place(source: &[u8], options: &SignatureOptions) -> Result<PlaceholderPdf, Error> {
    write_placeholder(&open(source), options)
}

fn default_place(source: &[u8]) -> PlaceholderPdf {
    place(source, &SignatureOptions::new(time())).unwrap()
}

/// A request whose (fake) certificate is never read: the refusals come first.
fn fake_request() -> PrepareRequest {
    PrepareRequest::new(
        vec![b"not read before the refusals".to_vec()],
        SignatureAlgorithm::Ecdsa,
        time(),
    )
}

/// The decimal text of `[0 a b c` padded with spaces to the placeholder width, then `]`.
fn expected_byte_range_text(values: [u64; 4]) -> String {
    let width =
        format!("[0 {BYTE_RANGE_PLACEHOLDER} {BYTE_RANGE_PLACEHOLDER} {BYTE_RANGE_PLACEHOLDER}]")
            .len();
    let [v0, v1, v2, v3] = values;
    let head = format!("[{v0} {v1} {v2} {v3}");
    format!("{head}{}]", " ".repeat(width - head.len() - 1))
}

/// Every layout property of brief §4.2, checked on the reopened output.
fn check_layout(source: &[u8], p: &PlaceholderPdf) {
    let pdf = &p.pdf;
    let len = pdf.len() as u64;
    assert!(
        pdf.starts_with(source),
        "the source is a prefix, byte for byte"
    );
    assert_eq!(p.source_len, source.len() as u64);

    let [zero, a, b, c] = p.byte_range;
    assert_eq!(zero, 0);
    assert_eq!(b + c, len, "the second range ends at the end of the file");
    assert_eq!(p.contents_range, (a, b));
    let r = p.contents_capacity();
    assert_eq!(
        b - a,
        2 * r as u64 + 2,
        "/Contents is exactly 2R hex digits"
    );
    let (au, bu) = (a as usize, b as usize);
    assert_eq!(pdf[au], b'<');
    assert_eq!(pdf[bu - 1], b'>');
    assert!(pdf[au + 1..bu - 1].iter().all(|&d| d == b'0'));
    assert_eq!(&pdf[au - 10..au], b"/Contents ");
    assert_eq!(&pdf[bu..bu + 2], b">>", "/Contents is the last key");

    // The patched /ByteRange text, in place, same width, no leading zeros.
    let (t0, t1) = p.byte_range_token;
    let text = std::str::from_utf8(&pdf[t0 as usize..t1 as usize]).unwrap();
    assert_eq!(text, expected_byte_range_text(p.byte_range));
    assert!(t1 <= a, "the byte range lies in the first signed part");

    // The digest of the ranges.
    assert_eq!(
        p.digest(DigestAlgorithm::Sha256),
        DigestAlgorithm::Sha256.digest(&[&pdf[..au], &pdf[bu..]])
    );
    let (first, second) = p.signed_parts();
    assert_eq!((first.len(), second.len()), (au, c as usize));

    // Reopened: one more revision, ending at the end of the file, nothing repaired.
    let before = Store::open_bytes(source.to_vec(), &OpenOptions::default()).unwrap();
    let store = Store::open_bytes(pdf.clone(), &OpenOptions::default()).unwrap();
    assert!(!store.structure_repaired());
    assert_eq!(store.revisions().len(), before.revisions().len() + 1);
    assert_eq!(store.revisions().last().unwrap().eof_end, len);
    assert!(
        store.check_incremental().is_ok(),
        "the output takes the next signature"
    );

    // The signature dictionary: uncompressed, inside the signed bytes, its /Contents token is
    // exactly the gap, and its values are the patched ones.
    let Some(ObjectLocation::InFile { start, end }) = store.object_location(p.sig_dict) else {
        panic!("the signature dictionary is not an uncompressed object");
    };
    assert!(start >= p.source_len && start < a && b < end);
    assert!(end <= b + c);
    let sig = store.resolve(p.sig_dict).unwrap();
    let sig = sig.as_dict().unwrap();
    assert_eq!(
        sig.get(b"ByteRange"),
        Some(&Object::Array(
            p.byte_range
                .iter()
                .map(|&v| Object::Int(v as i64))
                .collect()
        ))
    );
    assert_eq!(
        sig.get(b"Contents"),
        Some(&Object::String(PdfString::new_hex(vec![0u8; r])))
    );
    assert!(sig.get(b"Type").unwrap().is_name(b"Sig"));
    if p.field_created {
        assert!(matches!(
            store.object_location(p.field),
            Some(ObjectLocation::InFile { .. })
        ));
    }
    // The update's own xref lists both, uncompressed.
    let entries = store.revision_entries(store.revisions().len() - 1).unwrap();
    for id in [p.sig_dict, p.field] {
        let entry = entries
            .iter()
            .find(|(num, _)| *num == id.num)
            .map(|(_, e)| *e);
        assert!(
            matches!(entry, Some(XrefEntry::InFile { .. })),
            "{id}: {entry:?}"
        );
    }
    // The page count does not change.
    let doc = Document::from_store(store).unwrap();
    assert_eq!(
        doc.page_count().unwrap(),
        open(source).page_count().unwrap()
    );
}

/// A one-page document whose catalog has `catalog_extra`, then the `extra` objects numbered from
/// 5. The `startxref` is off by `skew` bytes when it is not 0 (a structure the store repairs).
fn build(catalog_extra: &str, extra: &[&str], skew: u64) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.7");
    b.obj(
        1,
        0,
        format!("<< /Type /Catalog /Pages 2 0 R {catalog_extra} >>"),
    );
    b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    b.obj(
        3,
        0,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots [6 0 R] >>",
    );
    b.stream_obj(4, 0, "", b"BT ET", None);
    for (i, body) in extra.iter().enumerate() {
        b.obj(5 + i as u32, 0, body);
    }
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array("sign-placeholder")
    );
    b.trailer(trailer);
    let offset = b.last_xref_offset().unwrap();
    b.startxref(Some(offset + skew)).eof();
    b.build()
}

/// A document with a signed signature field (and a structure that is repaired when `skew` is
/// not 0).
fn signed_field_document(skew: u64) -> Vec<u8> {
    build(
        "/AcroForm 5 0 R",
        &[
            "<< /Fields [6 0 R] /SigFlags 3 >>",
            "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) /V 7 0 R /F 132 /Rect [0 0 0 0] /P 3 0 R >>",
            "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [0 1 2 3] /Contents <00> >>",
        ],
        skew,
    )
}

// ---- the placeholder ----------------------------------------------------------------------------

#[test]
fn placeholder_byterange_width_constant() {
    let source = syntax::minimal();
    for reserve in [1, 2, 100, MIN_CONTENTS_RESERVE, 20_000] {
        let options = SignatureOptions::new(time()).with_contents_reserve(Some(reserve));
        let p = place(&source, &options).unwrap();
        assert_eq!(p.contents_capacity(), reserve);
        let (t0, t1) = p.byte_range_token;
        assert_eq!(t1 - t0, 36, "[0 + three ten-digit placeholders + ]");
        check_layout(&source, &p);
        // Every offset after the patched token is still right: a strict reader, which refuses
        // any repair, reads every object of the output.
        let strict = OpenOptions::new().with_strictness(Strictness::Strict);
        let store = Store::open_bytes(p.pdf.clone(), &strict).unwrap();
        for id in store.object_ids() {
            store.resolve(id).unwrap();
        }
        assert!(store.recovered_objects().is_empty());
    }
}

#[test]
fn byterange_patch_no_leading_zeros() {
    let source = syntax::minimal();
    let p = default_place(&source);
    let (t0, t1) = p.byte_range_token;
    let text = std::str::from_utf8(&p.pdf[t0 as usize..t1 as usize]).unwrap();
    let inner = text.strip_prefix('[').unwrap().strip_suffix(']').unwrap();
    let numbers: Vec<&str> = inner.split_whitespace().collect();
    assert_eq!(numbers.len(), 4);
    for (written, value) in numbers.iter().zip(p.byte_range) {
        assert_eq!(
            *written,
            value.to_string(),
            "plain decimal, no leading zeros"
        );
    }
    // File-absolute values (§12.8.1): `a` is where the `<` is in the whole file.
    let [_, a, b, _] = p.byte_range;
    assert_eq!(p.pdf[a as usize], b'<');
    assert_eq!(p.pdf[b as usize - 1], b'>');
    // Only spaces pad: after the fourth number come spaces, then `]`.
    let [_, _, _, c] = p.byte_range;
    let tail = &text[text.rfind(&format!(" {c}")).unwrap() + 1 + c.to_string().len()..];
    assert!(tail.ends_with(']'));
    assert!(
        tail[..tail.len() - 1].bytes().all(|b| b == b' '),
        "{text:?}"
    );
    assert_eq!(text.len(), 36);
}

#[test]
fn sig_dict_uncompressed_on_objstm_fixture() {
    let mut sources: Vec<(&str, Vec<u8>)> = [
        "objstm",
        "objstm-extends",
        "xref-stream",
        "xref-stream-incremental",
        "hybrid",
    ]
    .into_iter()
    .map(|name| (name, syntax::get(name).unwrap()))
    .collect();
    sources.push((
        "linearized-objstm",
        qpdf::read_committed("linearized-objstm").unwrap(),
    ));
    for (name, source) in &sources {
        let p = default_place(source);
        check_layout(source, &p);
        let store = Store::open_bytes(p.pdf.clone(), &OpenOptions::default()).unwrap();
        // A stream (or hybrid) source gets a cross-reference stream update.
        assert_eq!(
            store.revisions().last().unwrap().xref_kind,
            XrefKind::Stream,
            "{name}"
        );
        for id in [p.sig_dict, p.field] {
            assert!(
                matches!(
                    store.object_location(id),
                    Some(ObjectLocation::InFile { .. })
                ),
                "{name}: {id} is compressed"
            );
        }
    }
}

#[test]
fn m_entry_present() {
    let source = syntax::minimal();
    let options = SignatureOptions::new(time());
    let p = place(&source, &options).unwrap();
    let store = Store::open_bytes(p.pdf.clone(), &OpenOptions::default()).unwrap();
    let sig = store.resolve(p.sig_dict).unwrap();
    let sig = sig.as_dict().unwrap();
    assert_eq!(
        sig.get(b"M"),
        Some(&Object::literal_string(b"D:20261010120000Z".to_vec()))
    );
    let keys: Vec<&[u8]> = sig.keys().map(|k| k.as_bytes()).collect();
    assert_eq!(
        keys,
        [
            b"Type".as_slice(),
            b"Filter",
            b"SubFilter",
            b"M",
            b"ByteRange",
            b"Contents"
        ]
    );
    assert!(sig.get(b"Filter").unwrap().is_name(b"Adobe.PPKLite"));
    assert!(
        sig.get(b"SubFilter")
            .unwrap()
            .is_name(b"ETSI.CAdES.detached")
    );

    // With a UT offset, the optional text entries (one of them Unicode) and the other
    // SubFilter; never /Cert, /Prop_Build or /Reference (brief §4.1).
    let time = PdfDate::parse(b"D:20261010120000+05'30'").unwrap();
    let options = SignatureOptions::new(time)
        .with_name(Some("Jane Doe".into()))
        .with_reason(Some("Gepr\u{fc}ft \u{2713}".into()))
        .with_location(Some("Z\u{fc}rich".into()))
        .with_contact_info(Some("jane@example.org".into()))
        .with_sub_filter(SubFilter::AdbePkcs7Detached);
    let p = place(&source, &options).unwrap();
    check_layout(&source, &p);
    let store = Store::open_bytes(p.pdf.clone(), &OpenOptions::default()).unwrap();
    let sig = store.resolve(p.sig_dict).unwrap();
    let sig = sig.as_dict().unwrap();
    assert_eq!(
        sig.get_str_bytes(b"M"),
        Some(b"D:20261010120000+05'30'".as_slice())
    );
    let keys: Vec<&[u8]> = sig.keys().map(|k| k.as_bytes()).collect();
    assert_eq!(
        keys,
        [
            b"Type".as_slice(),
            b"Filter",
            b"SubFilter",
            b"M",
            b"Name",
            b"Reason",
            b"Location",
            b"ContactInfo",
            b"ByteRange",
            b"Contents"
        ]
    );
    assert!(
        sig.get(b"SubFilter")
            .unwrap()
            .is_name(b"adbe.pkcs7.detached")
    );
    let text =
        |key: &[u8]| folioxide_model::text::decode_text_string(sig.get_str_bytes(key).unwrap());
    assert_eq!(text(b"Name"), "Jane Doe");
    assert_eq!(text(b"Reason"), "Gepr\u{fc}ft \u{2713}");
    assert!(
        sig.get_str_bytes(b"Reason")
            .unwrap()
            .starts_with(&[0xFE, 0xFF])
    );
    assert_eq!(text(b"Location"), "Z\u{fc}rich");
    assert_eq!(text(b"ContactInfo"), "jane@example.org");
    for absent in [b"Cert".as_slice(), b"Prop_Build", b"Reference"] {
        assert!(!sig.contains_key(absent));
    }
}

#[test]
fn placeholder_on_every_syntax_fixture() {
    let mut sources: Vec<(String, Vec<u8>)> = syntax::all()
        .into_iter()
        .map(|(name, pdf)| (name.to_owned(), pdf))
        .collect();
    for info in qpdf::infos() {
        sources.push((
            info.name.to_owned(),
            qpdf::read_committed(info.name).unwrap(),
        ));
    }
    let mut signed = 0;
    for (name, source) in &sources {
        // Encrypted files do not open in M3.
        let Ok(doc) = Document::open(source.clone(), &OpenOptions::default()) else {
            continue;
        };
        let store = doc.store();
        let refusable = store.header_offset() != 0 || store.check_incremental().is_err();
        let result = write_placeholder(&doc, &SignatureOptions::new(time()));
        if refusable {
            let err = result.expect_err(name);
            assert_eq!(err.code(), ErrorCode::Unsupported, "{name}: {err}");
            continue;
        }
        let p = result.unwrap_or_else(|err| panic!("{name}: {err}"));
        check_layout(source, &p);
        assert_eq!(p.field_name, "Signature1", "{name}");
        // And a second signature on top.
        let second = default_place(&p.pdf);
        check_layout(&p.pdf, &second);
        assert_eq!(second.field_name, "Signature2", "{name}");
        signed += 1;
    }
    assert!(signed >= 15, "only {signed} fixtures took a signature");
}

#[test]
fn placeholder_never_reuses_freed_numbers() {
    // Objects 1–5, with number 9 listed as free in the table (gen 1): new objects start at 10.
    let mut b = PdfBuilder::new();
    b.header("1.7");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>");
    b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    b.obj(
        3,
        0,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
    );
    b.free(9, 1);
    b.xref_table(XrefOpts::default());
    let trailer = format!("/Size {} /Root 1 0 R /ID {}", b.size(), id_array("freed"));
    b.trailer(trailer).startxref(None).eof();
    let source = b.build();
    let p = default_place(&source);
    check_layout(&source, &p);
    let catalog = open(&p.pdf).catalog().unwrap();
    let acroform = catalog.as_dict().unwrap().get_ref(b"AcroForm").unwrap();
    for id in [p.field, p.sig_dict, acroform] {
        assert!(id.num >= 10, "{id} reuses a freed or listed number");
    }

    // multi-revision frees /Info 6 in its last revision; nothing new takes number 6.
    let source = syntax::multi_revision();
    let before = open(&source).store().next_object_number();
    let p = default_place(&source);
    assert!(p.field.num >= before && p.sig_dict.num >= before);
    assert!(p.field.num > 8);
}

#[test]
fn placeholder_pending_edits_same_revision() {
    let source = syntax::minimal();
    let mut doc = open(&source);
    let mut update = InfoUpdate::default();
    update.title = Some(Some("Signed with pending edits".into()));
    doc.set_info(&update).unwrap();
    let pending_before = doc
        .save_incremental(&IncrementalOptions::default())
        .unwrap();

    let p = write_placeholder(&doc, &SignatureOptions::new(time())).unwrap();
    check_layout(&source, &p);
    // One revision holds the edit and the signature.
    let signed = open(&p.pdf);
    assert_eq!(
        signed.info().unwrap().title.as_deref(),
        Some("Signed with pending edits")
    );
    assert_eq!(
        signed.store().revisions().len(),
        open(&source).store().revisions().len() + 1
    );
    // The document is not changed.
    assert!(doc.is_modified());
    assert_eq!(
        doc.save_incremental(&IncrementalOptions::default())
            .unwrap(),
        pending_before
    );
}

#[test]
fn placeholder_is_deterministic() {
    let source = syntax::xref_stream();
    assert_eq!(default_place(&source), default_place(&source));
}

#[test]
fn placeholder_reserve_bounds() {
    let source = syntax::minimal();
    for reserve in [0, MAX_CONTENTS_RESERVE + 1] {
        let options = SignatureOptions::new(time()).with_contents_reserve(Some(reserve));
        let err = place(&source, &options).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    }
    let p = default_place(&source);
    assert_eq!(p.contents_capacity(), MIN_CONTENTS_RESERVE);
}

// ---- refusals (brief §4.5 "Preconditions", DECISIONS D10) -----------------------------------------

#[test]
fn prepare_refuses_junk_before_header() {
    let doc = open(&syntax::junk_before_header());
    assert_ne!(doc.store().header_offset(), 0);
    for err in [
        prepare(&doc, &fake_request()).unwrap_err(),
        write_placeholder(&doc, &SignatureOptions::new(time())).unwrap_err(),
        check_signable(&doc).unwrap_err(),
    ] {
        assert_eq!(err.code(), ErrorCode::Unsupported, "{err}");
        assert!(err.to_string().contains("bytes before %PDF-"), "{err}");
        assert!(err.to_string().contains("save a full copy first"), "{err}");
    }
}

#[test]
fn prepare_refuses_repaired_structure() {
    // A startxref that misses the table by three bytes: the store finds the table, but marks
    // the structure repaired.
    let doc = open(&build("", &[], 3));
    assert!(doc.store().structure_repaired());
    let err = prepare(&doc, &fake_request()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported, "{err}");
    assert!(err.to_string().contains("full save required"), "{err}");
    assert!(!err.to_string().contains("existing signature"), "{err}");

    // With a signed field, the message names what a full save would invalidate.
    let doc = open(&signed_field_document(3));
    assert!(doc.store().structure_repaired());
    let err = prepare(&doc, &fake_request()).unwrap_err();
    assert!(
        err.to_string()
            .contains("it would invalidate the 1 existing signature"),
        "{err}"
    );
    // The same document, not repaired, takes a second signature.
    let p = default_place(&signed_field_document(0));
    assert_eq!(p.field_name, "Signature2");

    // Every repaired syntax fixture is refused.
    for (name, source) in syntax::all() {
        let Ok(doc) = Document::open(source, &OpenOptions::default()) else {
            continue;
        };
        if doc.store().structure_repaired() {
            let err = write_placeholder(&doc, &SignatureOptions::new(time())).unwrap_err();
            assert_eq!(err.code(), ErrorCode::Unsupported, "{name}: {err}");
        }
    }
}

#[test]
fn prepare_refuses_certified_p1() {
    let certified = |params: &str| {
        build(
            "/Perms << /DocMDP 5 0 R >>",
            &[&format!(
                "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached \
                 /ByteRange [0 1 2 3] /Contents <00> /Reference [<< /Type /SigRef \
                 /TransformMethod /DocMDP /TransformParams << /Type /TransformParams {params} \
                 /V /1.2 >> >>] >>"
            )],
            0,
        )
    };
    let doc = open(&certified("/P 1"));
    for err in [
        prepare(&doc, &fake_request()).unwrap_err(),
        write_placeholder(&doc, &SignatureOptions::new(time())).unwrap_err(),
    ] {
        assert!(matches!(err, Error::DocMdpForbids(_)), "{err:?}");
        assert_eq!(err.code(), ErrorCode::DocMdpForbids);
    }
    // P = 2, P = 3 and the default (2) allow an approval signature.
    for params in ["/P 2", "/P 3", ""] {
        let source = certified(params);
        let p = default_place(&source);
        check_layout(&source, &p);
    }
}

#[test]
fn prepare_refuses_documents_without_source_or_pages() {
    let err = prepare(&Document::new(), &fake_request()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");

    // A document without pages has nowhere to put the widget.
    let mut b = PdfBuilder::new();
    b.header("1.7");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>");
    b.obj(2, 0, "<< /Type /Pages /Kids [] /Count 0 >>");
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array("no-pages")
    );
    b.trailer(trailer).startxref(None).eof();
    let doc = open(&b.build());
    assert!(matches!(
        prepare(&doc, &fake_request()),
        Err(Error::PageOutOfRange(0))
    ));
    // Field errors come before any cryptography too.
    let doc = open(&syntax::minimal());
    let request = fake_request();
    let options = request
        .options
        .clone()
        .with_field(FieldSpec::new().with_name(Some("a.b".into())));
    let err = prepare(&doc, &request.with_options(options)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    // An empty chain is refused before anything else.
    let mut empty = fake_request();
    empty.chain_der.clear();
    assert_eq!(
        prepare(&doc, &empty).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
}

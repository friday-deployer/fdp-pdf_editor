#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! M3 brief WP3.1A-pre acceptance tests (brief §6.2, "syntax (Dev A)"): the overlay-aware
//! incremental writer ([`Store::incremental_suffix_with_overlay`]), object locations
//! ([`Store::object_location`]), [`Store::next_object_number`] skipping freed numbers, and the
//! serializer contract a signature's `/ByteRange` and `/Contents` depend on (brief §1, §4.2).

use std::collections::BTreeMap;

use folioxide_syntax::{
    Dict, IncrementalLayout, IncrementalOptions, Object, ObjectId, ObjectLocation, OpenOptions,
    ParseCtx, Store, StreamData, parse_indirect_at, serialize_object,
};
use folioxide_testkit::fixtures::syntax;

// ---- helpers ------------------------------------------------------------------------------------

fn open(bytes: &[u8]) -> Store {
    Store::open_bytes(bytes.to_vec(), &OpenOptions::default()).unwrap()
}

/// The whole output of an overlay update: the source, then the appended suffix.
fn output(source: &[u8], layout: &IncrementalLayout) -> Vec<u8> {
    let mut out = source.to_vec();
    out.extend_from_slice(layout.suffix());
    out
}

/// A signature-dictionary-shaped object with the exact `/ByteRange` and `/Contents` placeholders
/// of §4.2: an array `[0 9999999999 9999999999 9999999999]` and a hexadecimal string of `2 * r`
/// zero digits.
fn sig_placeholder(r: usize) -> Object {
    let mut dict = Dict::new();
    dict.insert("Type", Object::name("Sig"));
    dict.insert("Filter", Object::name("Adobe.PPKLite"));
    dict.insert("SubFilter", Object::name("ETSI.CAdES.detached"));
    dict.insert(
        "ByteRange",
        Object::Array(vec![
            Object::Int(0),
            Object::Int(9_999_999_999),
            Object::Int(9_999_999_999),
            Object::Int(9_999_999_999),
        ]),
    );
    dict.insert("Contents", Object::hex_string(vec![0u8; r]));
    Object::Dict(dict)
}

fn reparse(output: &[u8], span: &std::ops::Range<u64>) -> folioxide_syntax::IndirectObject {
    let start = usize::try_from(span.start).unwrap();
    parse_indirect_at(output, start, &ParseCtx::default(), &|_| None).unwrap()
}

// ---- overlay writer -----------------------------------------------------------------------------

#[test]
fn writer_overlay_spans_exact() {
    // Every span starts at a `N G obj` header and ends just past the end-of-line after `endobj`,
    // and `output[span]` re-parses to exactly the object the overlay gave.
    let source = syntax::minimal();
    let store = open(&source);
    let next = store.next_object_number();

    let mut overlay: BTreeMap<ObjectId, Object> = BTreeMap::new();
    // A replacement of an object in use (the catalog), and two new objects above every number
    // in use: a signature placeholder and its widget annotation.
    let mut catalog = Dict::new();
    catalog.insert("Type", Object::name("Catalog"));
    catalog.insert("Pages", ObjectId::new(2, 0));
    catalog.insert("AcroForm", ObjectId::new(next + 2, 0));
    overlay.insert(ObjectId::new(1, 0), Object::Dict(catalog));
    overlay.insert(ObjectId::new(next, 0), sig_placeholder(16));
    let mut widget = Dict::new();
    widget.insert("Type", Object::name("Annot"));
    widget.insert("Subtype", Object::name("Widget"));
    widget.insert("FT", Object::name("Sig"));
    widget.insert("V", ObjectId::new(next, 0));
    overlay.insert(ObjectId::new(next + 1, 0), Object::Dict(widget));

    let layout = store
        .incremental_suffix_with_overlay(&IncrementalOptions::default(), &overlay)
        .unwrap();
    let out = output(&source, &layout);

    assert_eq!(layout.base(), source.len() as u64);
    assert_eq!(
        out.len() as u64,
        layout.base() + layout.suffix().len() as u64
    );
    assert_eq!(
        layout.spans().len(),
        overlay.len(),
        "one span per overlay object"
    );

    for (id, span) in layout.spans() {
        let header = format!("{} {} obj", id.num, id.r#gen);
        assert!(
            out[usize::try_from(span.start).unwrap()..].starts_with(header.as_bytes()),
            "{id}: span must start at its header"
        );
        assert!(
            out[..usize::try_from(span.end).unwrap()].ends_with(b"endobj\n"),
            "{id}: span must end just past the EOL after endobj"
        );
        let parsed = reparse(&out, span);
        assert_eq!(parsed.id, *id);
        assert_eq!(&parsed.object, overlay.get(id).unwrap(), "{id}");
    }

    // The signature placeholder is serialized with the exact tokens §4.2 relies on.
    let sig_span = layout
        .spans()
        .iter()
        .find(|(id, _)| id.num == next)
        .map(|(_, span)| span)
        .unwrap();
    let sig_bytes =
        &out[usize::try_from(sig_span.start).unwrap()..usize::try_from(sig_span.end).unwrap()];
    assert!(
        find(
            sig_bytes,
            b"/ByteRange [0 9999999999 9999999999 9999999999]"
        )
        .is_some(),
        "the ByteRange placeholder must be `[0 9999999999 9999999999 9999999999]`"
    );
    let contents = [b"/Contents <".to_vec(), vec![b'0'; 32], b">".to_vec()].concat();
    assert!(
        find(sig_bytes, &contents).is_some(),
        "/Contents must be 2*R uppercase hex digits with no whitespace"
    );

    // The result reopens as one more revision, and the overlay won.
    let reopened = open(&out);
    assert_eq!(reopened.revisions().len(), store.revisions().len() + 1);
    let catalog = reopened.resolve(ObjectId::new(1, 0)).unwrap();
    assert_eq!(
        catalog.as_dict().unwrap().get_ref(b"AcroForm"),
        Some(ObjectId::new(next + 2, 0))
    );
    assert_eq!(
        &*reopened.resolve(ObjectId::new(next, 0)).unwrap(),
        overlay.get(&ObjectId::new(next, 0)).unwrap()
    );

    // Each span's end is the object_location end plus the one trailing EOL byte.
    for (id, span) in layout.spans() {
        if let Some(ObjectLocation::InFile { start, end }) = reopened.object_location(*id) {
            assert_eq!(start, span.start, "{id} start");
            assert_eq!(
                end + 1,
                span.end,
                "{id} end (object_location excludes the EOL)"
            );
        } else {
            panic!("{id} should be uncompressed in the reopened file");
        }
    }
}

#[test]
fn writer_overlay_does_not_mutate_store() {
    let source = syntax::minimal();
    let store = open(&source);
    let before_ids = store.object_ids();
    let before_next = store.next_object_number();
    let before_catalog = store.resolve(ObjectId::new(1, 0)).unwrap();
    assert!(!store.is_modified());

    let new = ObjectId::new(before_next, 0);
    let mut overlay: BTreeMap<ObjectId, Object> = BTreeMap::new();
    overlay.insert(ObjectId::new(1, 0), sig_placeholder(8)); // replace the catalog
    overlay.insert(new, sig_placeholder(16)); // a new object

    let layout = store
        .incremental_suffix_with_overlay(&IncrementalOptions::default(), &overlay)
        .unwrap();
    assert!(!layout.suffix().is_empty());

    // Nothing about the store changed: not its edits, not its numbering, not what it resolves.
    assert!(!store.is_modified());
    assert_eq!(store.object_ids(), before_ids);
    assert_eq!(store.next_object_number(), before_next);
    assert!(!store.contains(new));
    assert_eq!(store.resolve(ObjectId::new(1, 0)).unwrap(), before_catalog);
    assert!(store.object_location(new).is_none());
}

#[test]
fn writer_overlay_never_compressed() {
    // A fixture whose newest revision is a cross-reference stream (objstm) and one whose newest
    // is a plain stream (xref-stream): the overlay's new signature object is written
    // uncompressed, never inside an object stream, so its `/Contents` stays byte-addressable.
    for source in [syntax::objstm(), syntax::xref_stream()] {
        let store = open(&source);
        let new = ObjectId::new(store.next_object_number(), 0);
        let mut overlay: BTreeMap<ObjectId, Object> = BTreeMap::new();
        overlay.insert(new, sig_placeholder(64));

        let layout = store
            .incremental_suffix_with_overlay(&IncrementalOptions::default(), &overlay)
            .unwrap();
        let out = output(&source, &layout);
        let reopened = open(&out);

        match reopened.object_location(new) {
            Some(ObjectLocation::InFile { start, end }) => {
                let span = &out[usize::try_from(start).unwrap()..usize::try_from(end).unwrap()];
                assert!(span.starts_with(format!("{} 0 obj", new.num).as_bytes()));
                assert!(span.ends_with(b"endobj"));
            }
            other => panic!("overlay object must be uncompressed, got {other:?}"),
        }
        assert_eq!(
            &*reopened.resolve(new).unwrap(),
            overlay.get(&new).unwrap(),
            "the overlay object round-trips"
        );
    }
}

#[test]
fn writer_overlay_rejects_bad_ids() {
    // An overlay id that is neither in use nor a fresh number (a reused freed/unlisted number)
    // is refused before anything is written.
    let source = syntax::minimal();
    let store = open(&source);
    let next = store.next_object_number();
    // A number strictly below `next` that is not in use: object 0 and a gap number.
    let mut bad: BTreeMap<ObjectId, Object> = BTreeMap::new();
    bad.insert(ObjectId::new(0, 0), Object::Null);
    assert!(
        store
            .incremental_suffix_with_overlay(&IncrementalOptions::default(), &bad)
            .is_err()
    );
    // A fresh number (>= next) is fine; `next - 1` is object 5 (in use) so pick `next + 5`.
    let mut ok: BTreeMap<ObjectId, Object> = BTreeMap::new();
    ok.insert(ObjectId::new(next + 5, 0), Object::Null);
    assert!(
        store
            .incremental_suffix_with_overlay(&IncrementalOptions::default(), &ok)
            .is_ok()
    );
}

// ---- next_object_number -------------------------------------------------------------------------

#[test]
fn next_object_number_skips_freed() {
    // `objstm-extends` lists numbers up to 13; numbers 6, 8 and 9 are free. The next number is
    // above every listed number (free entries included), never one of the free holes, and freeing
    // the object it hands out never lets that number be reused (pyHanko reads reuse as clobbering,
    // brief §1, R-7).
    let mut store = open(&syntax::objstm_extends());
    let next = store.next_object_number();
    assert!(next > store.max_object_number());
    for hole in [6u32, 8, 9] {
        assert!(
            next > hole,
            "next {next} must be above the free hole {hole}"
        );
        assert!(store.resolve(ObjectId::new(hole, 0)).unwrap().is_null());
    }
    let added = store.add(Object::Null).unwrap();
    assert_eq!(added, ObjectId::new(next, 0));
    assert!(![6, 8, 9].contains(&added.num));

    store.free(added).unwrap();
    assert_eq!(
        store.next_object_number(),
        next + 1,
        "a freed number is not reused"
    );
    assert_eq!(store.add(Object::Null).unwrap(), ObjectId::new(next + 1, 0));
}

// ---- object_location ----------------------------------------------------------------------------

#[test]
fn object_location_in_file_and_objstm() {
    // objstm: object 1 (catalog) is member 0 of object stream 6; content stream 4 is in the file.
    let source = syntax::objstm();
    let mut store = open(&source);

    assert_eq!(
        store.object_location(ObjectId::new(1, 0)),
        Some(ObjectLocation::InObjStm {
            stream: 6,
            index: 0
        })
    );

    let Some(ObjectLocation::InFile { start, end }) = store.object_location(ObjectId::new(4, 0))
    else {
        panic!("object 4 is uncompressed in the file");
    };
    let (start, end) = (
        usize::try_from(start).unwrap(),
        usize::try_from(end).unwrap(),
    );
    assert!(source[start..].starts_with(b"4 0 obj"));
    assert!(source[..end].ends_with(b"endobj"));
    let parsed = parse_indirect_at(&source[..end], start, &ParseCtx::default(), &|_| None).unwrap();
    assert_eq!(parsed.id, ObjectId::new(4, 0));
    assert!(matches!(&parsed.object, Object::Stream(_)));

    // Free, missing and object 0 have no location.
    assert!(store.object_location(ObjectId::new(0, 0)).is_none());
    assert!(store.object_location(ObjectId::new(9999, 0)).is_none());
    // A generation that does not match the entry: none.
    assert!(store.object_location(ObjectId::new(4, 7)).is_none());

    // An edited object reports its SOURCE location (the edit lives only in memory); an added
    // object has no source definition.
    let before = store.object_location(ObjectId::new(4, 0));
    store
        .set(
            ObjectId::new(4, 0),
            Object::Stream(Box::new(folioxide_stream())),
        )
        .unwrap();
    assert_eq!(store.object_location(ObjectId::new(4, 0)), before);
    let added = store.add(Object::Null).unwrap();
    assert!(store.object_location(added).is_none());
}

/// A tiny decoded stream, for the "edited object keeps its source location" check.
fn folioxide_stream() -> folioxide_syntax::Stream {
    folioxide_syntax::Stream::new(Dict::new(), StreamData::Decoded(b"BT ET".to_vec()))
}

// ---- serializer contract ------------------------------------------------------------------------

#[test]
fn contents_hex_no_whitespace() {
    // Hexadecimal strings are `<HEX...>`, uppercase, with no whitespace, whatever their length;
    // arrays are `[a b c]` with single spaces. pyHanko's ENTIRE_FILE formula assumes 2 hex
    // digits per byte and no whitespace (brief §1, §4.2).
    for len in [0usize, 1, 2, 16, 20, 300] {
        let mut out = Vec::new();
        serialize_object(&Object::hex_string(vec![0u8; len]), &mut out);
        assert_eq!(out.first(), Some(&b'<'));
        assert_eq!(out.last(), Some(&b'>'));
        assert_eq!(
            out.len(),
            2 * len + 2,
            "2 hex digits per byte, length {len}"
        );
        let inner = &out[1..out.len() - 1];
        assert!(
            inner.iter().all(|b| *b == b'0'),
            "zero bytes are `0` digits"
        );
        assert!(
            inner.iter().all(|b| !b.is_ascii_whitespace()),
            "no whitespace, length {len}"
        );
    }

    // Uppercase hex digits, no separators.
    let mut out = Vec::new();
    serialize_object(&Object::hex_string(vec![0xAB, 0xCD, 0xEF, 0x12]), &mut out);
    assert_eq!(out, b"<ABCDEF12>");

    // Arrays: one space between elements, none at the brackets, nested arrays too.
    let mut out = Vec::new();
    serialize_object(
        &Object::Array(vec![
            Object::Int(0),
            Object::Int(9_999_999_999),
            Object::Array(vec![Object::Int(1), Object::Int(2)]),
        ]),
        &mut out,
    );
    assert_eq!(out, b"[0 9999999999 [1 2]]");

    // The sig dict as §4.2 writes it: /ByteRange before /Contents, both exact.
    let mut out = Vec::new();
    serialize_object(&sig_placeholder(16), &mut out);
    let text = String::from_utf8(out).unwrap();
    let br = text.find("/ByteRange").unwrap();
    let ct = text.find("/Contents").unwrap();
    assert!(br < ct, "/ByteRange must precede /Contents");
    assert!(text.contains("/ByteRange [0 9999999999 9999999999 9999999999]"));
    assert!(text.contains(&format!("/Contents <{}>", "0".repeat(32))));
}

/// The first position of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

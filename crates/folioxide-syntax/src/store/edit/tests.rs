//! Edit-layer tests (M2 brief WP2.1, "Store edit API").

use std::sync::Arc;

use folioxide_testkit::fixtures::syntax;
use folioxide_testkit::{LengthSpec, PdfBuilder, XrefOpts};

use super::*;
use crate::{Dict, ErrorCode, IncrementalOptions, Limits, Stream, StreamData, XrefEntry};

const CONTENT: &[u8] = b"BT /F1 24 Tf 72 720 Td (source) Tj ET";

/// Objects 1–5 (catalog, page tree, page, content stream, font), the content stream's length
/// in object 6 (an indirect `/Length`), object 8 with generation 2, and a free entry for 7
/// (next generation 3). The newest number listed is 8.
fn sample() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.4");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>")
        .obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .obj(
            3,
            0,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R \
             /Resources << /Font << /F1 5 0 R >> >> >>",
        )
        .stream_obj(4, 0, "", CONTENT, Some(LengthSpec::Raw(b"6 0 R".to_vec())))
        .obj(
            5,
            0,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        )
        .obj(6, 0, CONTENT.len().to_string())
        .obj(8, 2, "(eight)")
        .free(7, 3);
    b.xref_table(XrefOpts::default());
    let trailer = format!("/Size {} /Root 1 0 R", b.size());
    b.trailer(trailer).startxref(None).eof();
    b.build()
}

fn open(bytes: Vec<u8>) -> Store {
    Store::open_bytes(bytes, &OpenOptions::default()).unwrap()
}

fn id(num: u32, r#gen: u16) -> ObjectId {
    ObjectId::new(num, r#gen)
}

fn code(result: Result<impl std::fmt::Debug>) -> ErrorCode {
    result.unwrap_err().code()
}

#[test]
fn the_sample_reads_cleanly() {
    let store = open(sample());
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
    assert_eq!(store.max_object_number(), 8);
    assert_eq!(store.next_object_number(), 9);
    assert!(store.has_source());
    assert!(!store.is_modified());
    assert!(store.edited_ids().is_empty());
    assert_eq!(
        store.revision_entries(0).unwrap().iter().find(|e| e.0 == 7),
        Some(&(7, XrefEntry::Free { r#gen: 3 }))
    );
}

#[test]
fn new_empty_has_no_source() {
    let mut store = Store::new_empty((2, 0));
    assert!(!store.has_source());
    assert_eq!(store.version(), (2, 0));
    assert!(store.revisions().is_empty());
    assert!(store.trailer().is_empty());
    assert_eq!(store.root_id(), None);
    assert!(store.source().is_empty());
    assert!(store.resolve(id(1, 0)).unwrap().is_null());
    assert_eq!(store.next_object_number(), 1);
    assert!(store.object_ids().is_empty());
    let first = store.add(Object::Dict(Dict::new())).unwrap();
    assert_eq!(first, id(1, 0));
    assert_eq!(store.add(Object::Null).unwrap(), id(2, 0));
    store.set_trailer_entry(keys::ROOT, first.into()).unwrap();
    assert_eq!(store.root_id(), Some(first));
    assert!(store.is_modified());
    assert_eq!(store.object_ids(), vec![id(1, 0), id(2, 0)]);
}

#[test]
fn set_replaces_and_keeps_snapshots() {
    let mut store = open(sample());
    let before = store.resolve(id(5, 0)).unwrap();
    store.set(id(5, 0), Object::Int(42)).unwrap();
    assert_eq!(*store.resolve(id(5, 0)).unwrap(), Object::Int(42));
    assert!(before.as_dict().unwrap().is_type(b"Font"));
    // Setting again replaces the edit; an object of generation 2 is set with its generation.
    store.set(id(5, 0), Object::Int(43)).unwrap();
    store
        .set(id(8, 2), Object::literal_string("eight, edited"))
        .unwrap();
    assert_eq!(*store.resolve(id(5, 0)).unwrap(), Object::Int(43));
    assert_eq!(
        store.resolve(id(8, 2)).unwrap().as_str_bytes(),
        Some(&b"eight, edited"[..])
    );
    assert_eq!(store.edited_ids(), vec![id(5, 0), id(8, 2)]);
    assert!(store.is_modified());
    // deref follows references to edited objects.
    let reference = Object::Ref(id(5, 0));
    assert_eq!(*store.deref(&reference).unwrap(), Object::Int(43));
}

#[test]
fn set_refuses_objects_not_in_use() {
    let mut store = open(sample());
    let refused = |store: &mut Store, target: ObjectId| -> String {
        let err = store.set(target, Object::Null).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{target}");
        err.to_string()
    };
    assert!(refused(&mut store, id(0, 0)).contains("object 0"));
    assert!(refused(&mut store, id(0, 65535)).contains("object 0"));
    // Free in the source, under either generation.
    refused(&mut store, id(7, 0));
    refused(&mut store, id(7, 3));
    // Never used, and not yet added.
    refused(&mut store, id(9, 0));
    refused(&mut store, id(1000, 0));
    // A generation mismatch says which generation is in use.
    assert!(refused(&mut store, id(8, 0)).contains("generation 2"));
    assert!(refused(&mut store, id(1, 1)).contains("generation 0"));
    // Nothing was recorded.
    assert!(!store.is_modified());
    for target in [id(7, 0), id(9, 0), id(8, 0)] {
        assert_eq!(code(store.get_mut(target)), ErrorCode::InvalidArgument);
        assert_eq!(code(store.free(target)), ErrorCode::InvalidArgument);
    }
    assert!(!store.is_modified());
}

#[test]
fn get_mut_is_copy_on_write() {
    let mut store = open(sample());
    let root = store.root_id().unwrap();
    let snapshot = store.resolve(root).unwrap();
    store
        .get_mut(root)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .insert("Lang", Object::literal_string("en"));
    let edited = store.resolve(root).unwrap();
    assert!(edited.as_dict().unwrap().contains_key(b"Lang"));
    assert!(!snapshot.as_dict().unwrap().contains_key(b"Lang"));
    // A snapshot of the edited object stays a snapshot too.
    store
        .get_mut(root)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .insert("Extra", 1);
    assert!(!edited.as_dict().unwrap().contains_key(b"Extra"));
    let latest = store.resolve(root).unwrap();
    assert!(latest.as_dict().unwrap().contains_key(b"Extra"));
    drop((edited, latest));
    // Without snapshots, later calls edit in place (no clone).
    let before = Arc::as_ptr(&store.resolve(root).unwrap());
    store.get_mut(root).unwrap();
    assert_eq!(Arc::as_ptr(&store.resolve(root).unwrap()), before);
    // The source's own copy is untouched: a fresh store reads it as it was.
    assert_eq!(store.edited_ids(), vec![root]);
    // get_mut on an added object.
    let added = store.add(Object::Array(Vec::new())).unwrap();
    store
        .get_mut(added)
        .unwrap()
        .as_array_mut()
        .unwrap()
        .push(Object::Int(1));
    assert_eq!(
        store
            .resolve(added)
            .unwrap()
            .as_array()
            .map(<[Object]>::len),
        Some(1)
    );
}

#[test]
fn add_numbers_after_every_listed_number() {
    let mut store = open(sample());
    // 7 is free in the source and 8 is the newest number listed: never reused.
    assert_eq!(store.add(Object::Int(1)).unwrap(), id(9, 0));
    assert_eq!(store.add(Object::Int(2)).unwrap(), id(10, 0));
    assert_eq!(store.next_object_number(), 11);
    // Freeing an added object does not give its number back.
    store.free(id(10, 0)).unwrap();
    assert_eq!(store.add(Object::Int(3)).unwrap(), id(11, 0));
    assert_eq!(store.max_object_number(), 8);

    // The object limit.
    let limits = Limits::default().with_max_objects(11);
    let options = OpenOptions::default().with_limits(limits);
    let mut store = Store::open_bytes(sample(), &options).unwrap();
    assert_eq!(store.add(Object::Null).unwrap(), id(9, 0));
    assert_eq!(store.add(Object::Null).unwrap(), id(10, 0));
    let err = store.add(Object::Null).unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);
    assert_eq!(store.next_object_number(), 11);
}

#[test]
fn free_reads_as_null_and_bumps_the_generation() {
    let mut store = open(sample());
    assert_eq!(store.generation_of(8), Some(2));
    assert_eq!(store.generation_of(7), None);
    assert_eq!(store.generation_of(0), None);
    assert_eq!(store.generation_of(99), None);
    store.free(id(8, 2)).unwrap();
    assert!(store.resolve(id(8, 2)).unwrap().is_null());
    assert!(!store.contains(id(8, 2)));
    assert_eq!(store.generation_of(8), Some(3));
    assert!(!store.object_ids().contains(&id(8, 2)));
    assert!(store.is_modified());
    assert_eq!(store.edited_ids(), vec![id(8, 2)]);
    let err = store.free(id(8, 2)).unwrap_err();
    assert!(err.to_string().contains("was freed"), "{err}");
    assert_eq!(
        code(store.set(id(8, 2), Object::Null)),
        ErrorCode::InvalidArgument
    );
    assert_eq!(code(store.get_mut(id(8, 2))), ErrorCode::InvalidArgument);
    assert_eq!(
        code(store.set(id(8, 3), Object::Null)),
        ErrorCode::InvalidArgument
    );

    // Generation 65535 stays.
    let mut b = PdfBuilder::new();
    b.header("1.4");
    b.obj(1, 0, "<< /Type /Catalog >>").obj(2, 65535, "(last)");
    b.xref_table(XrefOpts::default());
    let trailer = format!("/Size {} /Root 1 0 R", b.size());
    b.trailer(trailer).startxref(None).eof();
    let mut store = open(b.build());
    store.free(id(2, 65535)).unwrap();
    assert_eq!(store.generation_of(2), Some(65535));

    // An added object, freed.
    let mut store = open(sample());
    let added = store.add(Object::Int(1)).unwrap();
    assert_eq!(store.generation_of(added.num), Some(0));
    store.free(added).unwrap();
    assert_eq!(store.generation_of(added.num), Some(1));
    assert!(store.resolve(added).unwrap().is_null());
    assert!(!store.object_ids().contains(&added));
}

#[test]
fn object_ids_follow_the_edits() {
    let mut store = open(sample());
    let source = store.object_ids();
    assert_eq!(
        source,
        vec![
            id(1, 0),
            id(2, 0),
            id(3, 0),
            id(4, 0),
            id(5, 0),
            id(6, 0),
            id(8, 2)
        ]
    );
    store.set(id(5, 0), Object::Null).unwrap();
    store.free(id(6, 0)).unwrap();
    let added = store.add(Object::Null).unwrap();
    let mut expected = source;
    expected.retain(|&i| i != id(6, 0));
    expected.push(added);
    assert_eq!(store.object_ids(), expected);
    for i in store.object_ids() {
        assert!(store.contains(i), "{i}");
    }
}

#[test]
fn stream_data_sees_edits() {
    let mut store = open(sample());
    // The source stream decodes as written.
    let stream = store.resolve(id(4, 0)).unwrap();
    assert_eq!(
        store.stream_data(stream.as_stream().unwrap()).unwrap().data,
        CONTENT
    );
    // An edited stream with encoded data and a /Filter given by a reference to an added name.
    let filter = store.add(Object::name("ASCIIHexDecode")).unwrap();
    let mut dict = Dict::new();
    dict.insert(keys::FILTER, filter);
    let encoded = Stream::new(dict, StreamData::Encoded(b"48 69>".to_vec()));
    store.set(id(4, 0), encoded.into()).unwrap();
    let edited = store.resolve(id(4, 0)).unwrap();
    assert_eq!(
        store.stream_data(edited.as_stream().unwrap()).unwrap().data,
        b"Hi"
    );
    // Decoded data is returned as is.
    let plain = Stream::new(Dict::new(), StreamData::Decoded(b"plain".to_vec()));
    store.set(id(4, 0), plain.into()).unwrap();
    let edited = store.resolve(id(4, 0)).unwrap();
    assert_eq!(
        store.stream_data(edited.as_stream().unwrap()).unwrap().data,
        b"plain"
    );
    // A stream whose dictionary alone was edited keeps its source data.
    let mut store = open(sample());
    store
        .get_mut(id(4, 0))
        .unwrap()
        .as_stream_mut()
        .unwrap()
        .dict
        .insert("Edited", true);
    let edited = store.resolve(id(4, 0)).unwrap();
    assert_eq!(
        store.stream_data(edited.as_stream().unwrap()).unwrap().data,
        CONTENT
    );
}

#[test]
fn edits_never_change_how_the_source_is_read() {
    // The indirect /Length of stream 4 is edited before stream 4 is parsed: the source is still
    // parsed with the source's length.
    let mut store = open(sample());
    store.set(id(6, 0), Object::Int(3)).unwrap();
    let stream = store.resolve(id(4, 0)).unwrap();
    assert_eq!(
        store.stream_data(stream.as_stream().unwrap()).unwrap().data,
        CONTENT
    );
    assert_eq!(
        *store.deref(&Object::Ref(id(6, 0))).unwrap(),
        Object::Int(3)
    );
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());

    // An object stream container edited (once no object in use is read from it) before an
    // object it held is read: that object still comes from the source's container, not from
    // the edit.
    let mut store = open(syntax::objstm());
    let (member, container) = store
        .revision_entries(0)
        .unwrap()
        .into_iter()
        .find_map(|(num, entry)| match entry {
            XrefEntry::InObjStm { stream, .. } if num != 1 => Some((num, stream)),
            _ => None,
        })
        .unwrap();
    for held in store.object_stream_members(id(container, 0)) {
        if held != id(member, 0) {
            store.set(held, Object::Null).unwrap();
        }
    }
    store.free(id(member, 0)).unwrap();
    store.set(id(container, 0), Object::Null).unwrap();
    assert!(store.resolve(id(container, 0)).unwrap().is_null());
    let object = store.resolve_source(id(member, 0)).unwrap();
    assert!(object.as_dict().is_some(), "{object:?}");
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
}

#[test]
fn object_streams_cannot_be_edited_while_they_hold_objects() {
    // objstm: catalog 1, page tree 2, page 3, font 5 and /Info 7 in object stream 6;
    // cross-reference stream 8.
    let mut store = open(syntax::objstm());
    let container = id(6, 0);
    let held = [id(1, 0), id(2, 0), id(3, 0), id(5, 0), id(7, 0)];
    assert_eq!(store.object_stream_members(container), held);
    for other in [id(1, 0), id(4, 0), id(8, 0), id(99, 0)] {
        assert!(store.object_stream_members(other).is_empty(), "{other}");
    }
    let refused = |result: Result<()>| {
        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        err.to_string()
    };
    let message = refused(store.set(container, Object::Null));
    assert!(message.contains("§7.5.7"), "{message}");
    assert!(
        message.contains("holds object 1 0 R and 4 other objects"),
        "{message}"
    );
    refused(store.free(container));
    refused(store.get_mut(container).map(|_| ()));
    assert!(!store.is_modified());

    // Replacing or freeing the objects it holds releases it, one by one.
    store
        .set(id(1, 0), store.resolve(id(1, 0)).unwrap().as_ref().clone())
        .unwrap();
    store.get_mut(id(2, 0)).unwrap();
    store.get_mut(id(3, 0)).unwrap();
    store.set(id(7, 0), Object::Null).unwrap();
    assert_eq!(store.object_stream_members(container), [id(5, 0)]);
    let message = refused(store.free(container));
    assert!(message.contains("holds object 5 0 R in use"), "{message}");
    store.free(id(5, 0)).unwrap();
    assert!(store.object_stream_members(container).is_empty());
    store.free(container).unwrap();
    // The cross-reference stream is no container: readers find it by its position, so freeing
    // it is harmless.
    store.free(id(8, 0)).unwrap();

    // The update gives every object that was in the container an entry of its own, so the
    // container can go.
    let out = store
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    let reopened = open(out);
    assert!(
        reopened.diagnostics().is_empty(),
        "{:?}",
        reopened.diagnostics()
    );
    let catalog = reopened.resolve(reopened.root_id().unwrap()).unwrap();
    assert!(catalog.as_dict().unwrap().is_type(b"Catalog"));
    let page = reopened.resolve(id(3, 0)).unwrap();
    assert!(page.as_dict().unwrap().is_type(b"Page"));
    for freed in [id(5, 0), container, id(8, 0)] {
        assert!(reopened.resolve(freed).unwrap().is_null(), "{freed}");
    }

    // Hybrid: catalog 1 and page tree 2 in object stream 6, hidden cross-reference stream 7.
    let mut store = open(syntax::hybrid());
    assert_eq!(store.object_stream_members(id(6, 0)), [id(1, 0), id(2, 0)]);
    refused(store.set(id(6, 0), Object::Null));
    store.set(id(7, 0), Object::Null).unwrap();
    let reopened = open(
        store
            .save_incremental(&IncrementalOptions::default())
            .unwrap(),
    );
    assert!(
        reopened.diagnostics().is_empty(),
        "{:?}",
        reopened.diagnostics()
    );
    let catalog = reopened.resolve(reopened.root_id().unwrap()).unwrap();
    assert!(catalog.as_dict().unwrap().is_type(b"Catalog"));
}

#[test]
fn a_container_that_is_no_stream_holds_nothing() {
    // A file whose type 2 entry for object 4 names object 3, a page dictionary, as its object
    // stream: object 4 cannot be read from it, and the page stays editable.
    let mut b = PdfBuilder::new();
    b.header("1.5");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>")
        .obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .obj(
            3,
            0,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
        );
    let compressed = folioxide_testkit::XrefEntry::Compressed {
        stream: 3,
        index: 0,
    };
    b.xref_stream(
        5,
        folioxide_testkit::XrefStreamOpts::new()
            .with_entry(4, compressed)
            .with_trailer("/Root 1 0 R"),
    );
    b.startxref(None).eof();
    let mut store = open(b.build());
    assert!(matches!(
        store.location(4),
        Some(Location::InObjStm { stream: 3, .. })
    ));
    assert!(store.object_stream_members(id(3, 0)).is_empty());
    store.get_mut(id(3, 0)).unwrap();
    store.set(id(3, 0), Object::Null).unwrap();
}

#[test]
fn trailer_entries() {
    let mut store = open(sample());
    let invalid = |result: Result<()>| {
        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        err.to_string()
    };
    // Values of the wrong kind.
    invalid(store.set_trailer_entry(keys::ROOT, Object::Dict(Dict::new())));
    invalid(store.set_trailer_entry(keys::ROOT, Object::Ref(id(0, 0))));
    invalid(store.set_trailer_entry(keys::INFO, Object::Int(1)));
    invalid(store.set_trailer_entry(keys::ID, Object::literal_string("x")));
    invalid(store.set_trailer_entry(keys::ID, Object::Array(vec![Object::literal_string("x")])));
    invalid(store.set_trailer_entry(keys::ID, Object::Array(vec![Object::Int(1); 2])));
    // Keys the writer computes, encryption, and anything else.
    for key in [
        keys::SIZE,
        keys::PREV,
        keys::XREF_STM,
        keys::W,
        keys::INDEX,
        keys::FILTER,
        keys::DECODE_PARMS,
        keys::LENGTH,
        keys::TYPE,
    ] {
        let message = invalid(store.set_trailer_entry(key, Object::Int(1)));
        assert!(message.contains("computed by the writer"), "{message}");
        assert_eq!(
            code(store.remove_trailer_entry(key)),
            ErrorCode::InvalidArgument
        );
    }
    assert!(invalid(store.set_trailer_entry(keys::ENCRYPT, Object::Null)).contains("M5"));
    assert!(invalid(store.set_trailer_entry(b"Custom", Object::Null)).contains("/Root, /Info"));
    assert!(!store.is_modified());

    // Setting a key to its value is no edit.
    store
        .set_trailer_entry(keys::ROOT, id(1, 0).into())
        .unwrap();
    assert!(!store.is_modified());

    // The allowed ones.
    let info = store.add(Object::Dict(Dict::new())).unwrap();
    store.set_trailer_entry(keys::INFO, info.into()).unwrap();
    let ids = Object::Array(vec![
        Object::hex_string(vec![1; 16]),
        Object::hex_string(vec![2; 16]),
    ]);
    store.set_trailer_entry(keys::ID, ids.clone()).unwrap();
    assert_eq!(store.trailer().get_ref(keys::INFO), Some(info));
    assert_eq!(store.trailer().get(keys::ID), Some(&ids));
    assert!(store.is_modified());

    // Removing: /Root never, /Info and /ID yes.
    assert_eq!(
        code(store.remove_trailer_entry(keys::ROOT)),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        store.remove_trailer_entry(keys::INFO).unwrap(),
        Some(Object::Ref(info))
    );
    assert_eq!(store.remove_trailer_entry(keys::INFO).unwrap(), None);
    assert_eq!(store.remove_trailer_entry(keys::ID).unwrap(), Some(ids));
    assert!(store.trailer().get(keys::INFO).is_none());

    // A trailer edit alone is a modification.
    let mut store = open(sample());
    store
        .set_trailer_entry(keys::ROOT, id(3, 0).into())
        .unwrap();
    assert!(store.is_modified());
    assert!(store.edited_ids().is_empty());
    assert_eq!(store.root_id(), Some(id(3, 0)));
}

#[test]
fn an_edited_store_is_shared_between_threads() {
    let mut store = open(sample());
    store.set(id(5, 0), Object::Int(5)).unwrap();
    let added = store.add(Object::Int(9)).unwrap();
    let store = Arc::new(store);
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                for _ in 0..50 {
                    assert_eq!(*store.resolve(id(5, 0)).unwrap(), Object::Int(5));
                    assert_eq!(*store.resolve(added).unwrap(), Object::Int(9));
                    assert!(store.resolve(id(4, 0)).unwrap().as_stream().is_some());
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn add_never_takes_the_number_of_a_dangling_reference() {
    // The page tree lists 9 0 R, which no section lists (the newest number is 4): the reference
    // means null, and a new object must not become a page. The trailer's /Info 12 0 R dangles
    // too, and a reference beyond max_objects can never be taken anyway.
    let mut b = PdfBuilder::new();
    b.header("1.4");
    b.obj(
        1,
        0,
        "<< /Type /Catalog /Pages 2 0 R /Far 4000000000 0 R >>",
    )
    .obj(2, 0, "<< /Type /Pages /Kids [3 0 R 9 0 R] /Count 2 >>")
    .obj(3, 0, "<< /Type /Page /Parent 2 0 R >>")
    .obj(4, 0, "[7 0 R]");
    b.xref_table(XrefOpts::default());
    let trailer = format!("/Size {} /Root 1 0 R /Info 12 0 R", b.size());
    b.trailer(trailer).startxref(None).eof();
    let bytes = b.build();
    let mut store = open(bytes.clone());
    assert_eq!(store.max_object_number(), 4);
    assert_eq!(store.next_object_number(), 13);
    let added = store.add(Object::Int(1)).unwrap();
    assert_eq!(added, id(13, 0));
    assert_eq!(store.next_object_number(), 14);
    assert!(store.resolve(id(9, 0)).unwrap().is_null());
    // The walk is done once: a dangling reference an edit introduces is the editor's own.
    store
        .get_mut(id(4, 0))
        .unwrap()
        .as_array_mut()
        .unwrap()
        .push(Object::Ref(id(20, 0)));
    assert_eq!(store.add(Object::Int(2)).unwrap(), id(14, 0));

    // Without dangling references, numbering follows the sections.
    let store = open(sample());
    assert_eq!(store.next_object_number(), 9);
    // A reference inside an object stream counts as well.
    let mut b = PdfBuilder::new();
    b.header("1.5");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>");
    b.objstm(
        3,
        &[(2, "<< /Type /Pages /Kids [] /Count 0 /Extra 30 0 R >>")],
        folioxide_testkit::ObjStmOpts::default(),
    );
    b.xref_stream(
        4,
        folioxide_testkit::XrefStreamOpts::default().with_trailer("/Root 1 0 R"),
    );
    b.startxref(None).eof();
    let mut store = open(b.build());
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
    assert_eq!(store.max_object_number(), 4);
    assert_eq!(store.add(Object::Null).unwrap(), id(31, 0));
    // A new document has nothing to walk.
    let mut store = Store::new_empty((1, 7));
    assert_eq!(store.add(Object::Null).unwrap(), id(1, 0));
}

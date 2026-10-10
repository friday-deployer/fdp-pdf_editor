//! Memory estimate tests.

use folioxide_testkit::fixtures::syntax;
use folioxide_testkit::{PdfBuilder, XrefOpts};

use super::*;
use crate::{OpenOptions, StreamData};

fn open(bytes: Vec<u8>) -> Store {
    Store::open_bytes(bytes, &OpenOptions::default()).unwrap()
}

/// A file with `count` small dictionaries (each with a 40-byte string) reachable from the
/// catalog, and a classic table.
fn many_objects(count: u32) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.4");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R /All 3 0 R >>")
        .obj(2, 0, "<< /Type /Pages /Kids [] /Count 0 >>");
    let refs: String = (0..count).map(|i| format!("{} 0 R ", 10 + i)).collect();
    b.obj(3, 0, format!("[{refs}]"));
    for i in 0..count {
        b.obj(10 + i, 0, format!("<< /N {i} /S ({:040}) >>", i));
    }
    b.xref_table(XrefOpts::default());
    let trailer = format!("/Size {} /Root 1 0 R", b.size());
    b.trailer(trailer).startxref(None).eof();
    b.build()
}

#[test]
fn objects_are_weighed_by_what_they_own() {
    let base = (size_of::<Object>() + 2 * size_of::<usize>()) as u64;
    assert_eq!(heap_size(&Object::Int(7)), base);
    assert_eq!(heap_size(&Object::Null), base);
    assert_eq!(
        heap_size(&Object::literal_string(vec![b'x'; 1000])),
        base + 1000
    );
    // An array owns its elements' slots and what they own.
    let array = Object::Array(vec![Object::Int(1), Object::literal_string(vec![0; 10])]);
    let Object::Array(items) = &array else {
        unreachable!()
    };
    let slots = (items.capacity() * size_of::<Object>()) as u64;
    assert_eq!(heap_size(&array), base + slots + 10);
    // Stream data the stream owns counts; data in the source does not.
    let owned = Stream::new(Dict::new(), StreamData::Decoded(vec![0; 4096]));
    let source = Stream::new(Dict::new(), StreamData::Source(0..4096));
    assert_eq!(heap_size(&owned.into()) - heap_size(&source.into()), 4096);
    // The walk is iterative: nesting costs no stack.
    let mut deep = Object::Null;
    for _ in 0..1000 {
        deep = Object::Array(vec![deep]);
    }
    assert!(heap_size(&deep) >= base + 1000 * size_of::<Object>() as u64);
}

#[test]
fn the_estimate_grows_as_objects_are_read() {
    let bytes = many_objects(2000);
    let len = bytes.len() as u64;
    let store = open(bytes);
    let opened = store.memory_estimate();
    // The source and one slot per object, at least.
    assert!(opened >= len + 2000 * size_of::<Slot>() as u64, "{opened}");
    // Reading every object caches it: each dictionary costs at least its two entries.
    for id in store.object_ids() {
        store.resolve(id).unwrap();
    }
    let read = store.memory_estimate();
    let per_dict = 2 * (size_of::<Name>() + size_of::<Object>()) as u64 + 40;
    assert!(read >= opened + 2000 * per_dict, "{opened} -> {read}");
    // Reading again costs nothing more.
    for id in store.object_ids() {
        store.resolve(id).unwrap();
    }
    assert_eq!(store.memory_estimate(), read);
    // A full save reads everything too.
    let store = open(many_objects(2000));
    store.save(&crate::SaveOptions::default()).unwrap();
    assert!(store.memory_estimate() >= read - 1024);
}

#[test]
fn the_estimate_follows_the_edits() {
    let mut store = open(syntax::minimal());
    let opened = store.memory_estimate();
    let mb = 1 << 20;

    // A set, an add and a free are weighed when they are made.
    let data = Stream::new(Dict::new(), StreamData::Decoded(vec![7; mb]));
    let added = store.add(data.into()).unwrap();
    let with_stream = store.memory_estimate();
    assert!(
        with_stream >= opened + mb as u64,
        "{opened} -> {with_stream}"
    );
    assert!(
        with_stream < opened + mb as u64 + 4096,
        "{opened} -> {with_stream}"
    );
    store.set(added, Object::Int(1)).unwrap();
    assert!(store.memory_estimate() < opened + 4096);
    store.free(added).unwrap();
    let freed = store.memory_estimate();
    assert!(freed < opened + 4096);

    // An object changed through get_mut is measured again by the next estimate.
    let root = store.root_id().unwrap();
    store
        .get_mut(root)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .insert("Big", Object::literal_string(vec![b'x'; mb]));
    let grown = store.memory_estimate();
    assert!(grown >= freed + mb as u64, "{freed} -> {grown}");
    store
        .get_mut(root)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .remove(b"Big");
    let shrunk = store.memory_estimate();
    assert!(shrunk < grown - mb as u64 + 4096, "{grown} -> {shrunk}");
    // Asking again without edits gives the same answer.
    assert_eq!(store.memory_estimate(), shrunk);
}

#[test]
fn a_repaired_file_counts_its_scan() {
    // Without a cross-reference table, the store scans the file and keeps the scan.
    let mut b = PdfBuilder::new();
    b.header("1.4");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>").obj(
        2,
        0,
        "<< /Type /Pages /Kids [] /Count 0 >>",
    );
    for i in 0..1000 {
        b.obj(10 + i, 0, format!("<< /N {i} >>"));
    }
    b.trailer("<< /Root 1 0 R >>").eof();
    let store = open(b.build());
    assert!(store.structure_repaired());
    let scan = store.scan.get().map_or(0, |scan| scan.heap_size());
    let definitions = store.definitions.get().map_or(0, |d| d.heap_size());
    assert!(scan + definitions >= 1000 * size_of::<usize>() as u64);
    assert!(store.memory_estimate() >= store.source().len() as u64 + scan + definitions);
}

#[test]
fn a_new_store_is_small() {
    let store = Store::new_empty((1, 7));
    assert!(
        store.memory_estimate() < 64 * 1024,
        "{}",
        store.memory_estimate()
    );
}

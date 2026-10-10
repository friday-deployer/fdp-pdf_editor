#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! `open_is_lazy` (M1 brief WP1.5, acceptance criterion 3): opening the generated 2,000-page
//! file and resolving its catalog parses fewer than 50 objects. The file is built by
//! `folioxide_testkit::fixtures::syntax::lazy_pages` at test time (it is not committed).

use folioxide_syntax::{OpenOptions, Store, Strictness, XrefKind};
use folioxide_testkit::exercise::page_count;
use folioxide_testkit::fixtures::syntax::{self, LAZY_PAGE_COUNT};

/// The acceptance bound.
const MAX_PARSED_AFTER_ROOT: usize = 50;

#[test]
fn open_is_lazy() {
    let bytes = syntax::lazy_pages();
    let store = Store::open_bytes(bytes, &OpenOptions::default()).unwrap();
    // Catalog, root page tree, font, 20 intermediate nodes, then 2,000 pages and their 2,000
    // content streams.
    assert_eq!(
        store.object_ids().len(),
        3 + 20 + 2 * LAZY_PAGE_COUNT as usize
    );
    assert_eq!(store.revisions().len(), 1);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Table);

    let root = store.root_id().expect("the trailer has /Root");
    let catalog = store.resolve(root).unwrap();
    assert!(catalog.as_dict().unwrap().is_type(b"Catalog"));
    let parsed = store.parsed_object_count();
    assert!(
        parsed < MAX_PARSED_AFTER_ROOT,
        "opening and resolving the root parsed {parsed} objects"
    );
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());

    // The counter is real: walking the whole page tree parses every node and page.
    assert_eq!(page_count(&store), Some(LAZY_PAGE_COUNT));
    assert!(
        store.parsed_object_count() > LAZY_PAGE_COUNT as usize,
        "{}",
        store.parsed_object_count()
    );
}

#[test]
fn open_is_lazy_strict() {
    let options = OpenOptions::default().with_strictness(Strictness::Strict);
    let store = Store::open_bytes(syntax::lazy_pages(), &options).unwrap();
    store.resolve(store.root_id().unwrap()).unwrap();
    assert!(store.parsed_object_count() < MAX_PARSED_AFTER_ROOT);
}

#[test]
fn open_is_lazy_with_object_streams() {
    // The same document with every dictionary in object streams of 100 objects and a
    // cross-reference stream: opening parses the xref stream and the catalog's container only.
    let store = Store::open_bytes(
        syntax::many_pages_compressed(LAZY_PAGE_COUNT),
        &OpenOptions::default(),
    )
    .unwrap();
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Stream);
    store.resolve(store.root_id().unwrap()).unwrap();
    let parsed = store.parsed_object_count();
    assert!(parsed < MAX_PARSED_AFTER_ROOT, "{parsed}");
    assert_eq!(page_count(&store), Some(LAZY_PAGE_COUNT));
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
}

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! `Document` as a whole: opening, threading (ARCHITECTURE §A.8: `Document` is
//! `Send + Sync + 'static`), diagnostics.

mod common;

use std::sync::Arc;
use std::thread;

use common::open;
use folioxide_model::{
    DocInfo, Document, InfoUpdate, Page, PageId, PageInfo, PdfDate, Rect, Rotation, Trapped,
};
use folioxide_syntax::{ErrorCode, OpenOptions, Strictness, shared_bytes};
use folioxide_testkit::fixtures::{model, syntax};

/// `Document` and the DTOs can be shared between threads and moved into them; a `Page` view
/// can be shared too.
#[test]
fn document_is_send_sync() {
    fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync_static::<Document>();
    assert_send_sync_static::<PageId>();
    assert_send_sync_static::<Rect>();
    assert_send_sync_static::<Rotation>();
    assert_send_sync_static::<DocInfo>();
    assert_send_sync_static::<PdfDate>();
    assert_send_sync_static::<Trapped>();
    assert_send_sync_static::<InfoUpdate>();
    assert_send_sync_static::<PageInfo>();
    assert_send_sync::<Page<'_>>();

    // And it works: eight threads read every page of one document at once.
    let doc = Arc::new(open(model::inherited_attributes()));
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let doc = Arc::clone(&doc);
            thread::spawn(move || {
                let mut sizes = Vec::new();
                for round in 0..20 {
                    let count = doc.page_count().unwrap();
                    let i = (t + round) % count;
                    let page = doc.page(i).unwrap();
                    sizes.push((i, page.effective_size(), page.rotation()));
                }
                sizes
            })
        })
        .collect();
    for handle in handles {
        for (i, size, rotation) in handle.join().unwrap() {
            let expected = model::INHERITED_PAGES[i];
            assert_eq!(rotation.degrees(), expected.rotate);
            let [llx, lly, urx, ury] = expected.crop_box;
            let (w, h) = (urx - llx, ury - lly);
            if rotation.is_sideways() {
                assert_eq!(size, (h, w));
            } else {
                assert_eq!(size, (w, h));
            }
        }
    }
    // A well-formed document: nothing to report, however many threads read it.
    assert!(doc.diagnostics().is_empty(), "{:?}", doc.diagnostics());
}

/// The three constructors give the same document; opening errors are the store's.
#[test]
fn constructors() {
    let pdf = syntax::minimal();
    let a = Document::open(pdf.clone(), &OpenOptions::default()).unwrap();
    let b = Document::open_shared(shared_bytes(pdf.clone()), &OpenOptions::default()).unwrap();
    let store = folioxide_syntax::Store::open_bytes(pdf, &OpenOptions::default()).unwrap();
    let c = Document::from_store(store).unwrap();
    for doc in [&a, &b, &c] {
        assert_eq!(doc.page_count().unwrap(), 1);
        assert_eq!(doc.version(), (1, 4));
        assert!(
            doc.catalog()
                .unwrap()
                .as_dict()
                .unwrap()
                .is_type(b"Catalog")
        );
        assert!(doc.diagnostics().is_empty());
        assert_eq!(doc.dropped_diagnostics(), 0);
    }

    let err = Document::open(b"not a pdf".to_vec(), &OpenOptions::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Xref);
    let err = Document::open(syntax::encrypted(), &OpenOptions::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::PasswordRequired);
}

/// The store's repair diagnostics come first, then the model's.
#[test]
fn diagnostics_combine_store_and_model() {
    // A file without a cross-reference table, so the store reconstructs it, and a wrong /Count.
    let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
        2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 2 >>\nendobj\n\
        3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] >>\nendobj\n\
        trailer\n<< /Root 1 0 R >>\n%%EOF\n"
        .to_vec();
    let doc = Document::open(pdf.clone(), &OpenOptions::default()).unwrap();
    assert_eq!(doc.page_count().unwrap(), 1);
    let diagnostics = doc.diagnostics();
    let store_count = doc.store().diagnostics().len();
    assert!(store_count > 0);
    assert!(diagnostics.len() > store_count);
    assert!(
        diagnostics[store_count..]
            .iter()
            .any(|d| d.message.contains("/Count 2 but 1"))
    );
    // Strict mode refuses the damaged structure itself.
    let strict = OpenOptions::default().with_strictness(Strictness::Strict);
    assert!(Document::open(pdf, &strict).is_err());
}

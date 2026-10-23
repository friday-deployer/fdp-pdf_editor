#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The Annotations whitelist stays linear in the size of the file (M4 QA round 2, finding 1; the
//! M1 "linear by construction" lesson): a geometry array is read only when it is written in the
//! annotation itself, so thousands of annotations that name one shared 65,536-number array cost
//! nothing per reference, and the geometry values read are work of the verification's budget.
//! QA's crafted files took 17.9 s (30,000 highlights sharing one `/QuadPoints` array) and 32.6 s
//! (one `/InkList` of 65,536 references to a 32,768-point stroke) before the fix.

mod sign_support;

use std::time::Duration;

use folioxide_sign::report::ModificationLevel;
use folioxide_syntax::{
    Dict, IncrementalOptions, Object, ObjectId, OpenOptions, Store, Stream, StreamData,
};
use folioxide_testkit::budget::within;
use sign_support::corpus::{Base, signature1};
use sign_support::summary;

/// The first page of `store`.
fn first_page(store: &Store) -> ObjectId {
    folioxide_testkit::fixtures::forms::page_id(store, 0).unwrap()
}

/// A new appearance stream of 20 by 20 (a form XObject with a `/BBox`), shared by the
/// annotations of a test.
fn appearance(store: &mut Store) -> Object {
    let mut form = Dict::new();
    form.insert("Type", Object::name("XObject"));
    form.insert("Subtype", Object::name("Form"));
    form.insert(
        "BBox",
        Object::Array([0, 0, 20, 20].map(Object::Int).to_vec()),
    );
    let stream = Stream::new(form, StreamData::Decoded(b"0 g 0 0 20 20 re f".to_vec()));
    let id = store.add(Object::Stream(Box::new(stream))).unwrap();
    let mut ap = Dict::new();
    ap.insert("N", Object::Ref(id));
    Object::Dict(ap)
}

/// `pdf` (the P = 3 certified, annotated document) with a revision that appends to the first
/// page's `/Annots` the annotations `build(store, page, ap, i)` makes for `i` in `0..count`.
fn annotated(
    pdf: &[u8],
    count: usize,
    mut build: impl FnMut(&mut Store, ObjectId, &Object, usize) -> Dict,
) -> Vec<u8> {
    let mut store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default()).unwrap();
    let page = first_page(&store);
    let ap = appearance(&mut store);
    let mut added = Vec::with_capacity(count);
    for i in 0..count {
        let dict = build(&mut store, page, &ap, i);
        added.push(Object::Ref(store.add(Object::Dict(dict)).unwrap()));
    }
    let mut page_dict = store.resolve(page).unwrap().as_dict().unwrap().clone();
    let mut annots = store
        .deref(page_dict.get(b"Annots").unwrap())
        .unwrap()
        .as_array()
        .unwrap()
        .to_vec();
    annots.extend(added);
    page_dict.insert("Annots", Object::Array(annots));
    store.set(page, Object::Dict(page_dict)).unwrap();
    store
        .save_incremental(&IncrementalOptions::default())
        .unwrap()
}

/// A markup annotation of `subtype` at `[60 300 80 320]` on `page` with the appearance `ap`.
fn markup(subtype: &str, page: ObjectId, ap: &Object) -> Dict {
    let mut dict = Dict::new();
    dict.insert("Type", Object::name("Annot"));
    dict.insert("Subtype", Object::name(subtype));
    dict.insert(
        "Rect",
        Object::Array([60, 300, 80, 320].map(Object::Int).to_vec()),
    );
    dict.insert("P", Object::Ref(page));
    dict.insert("F", Object::Int(4));
    dict.insert("AP", ap.clone());
    dict
}

/// `n` reals `[x0 y0 x1 y1 ...]` inside `[60 300 80 320]` (well inside the margins).
fn points(n: usize) -> Vec<Object> {
    (0..n)
        .map(|i| Object::Real(if i % 2 == 0 { 70.0 } else { 310.0 }))
        .collect()
}

/// The certification's report on `pdf`, within a fixed budget.
fn verified(pdf: Vec<u8>) -> folioxide_sign::report::SignatureReport {
    // A few seconds in a debug build; QA's files took tens of seconds before the fix.
    let (r, took) = within(Duration::from_secs(30), move || signature1(&pdf))
        .unwrap_or_else(|overrun| panic!("{overrun}"));
    eprintln!("verified in {took:.2?}");
    r
}

#[test]
fn shared_quadpoints_arrays_are_not_read_per_annotation() {
    // 3,000 highlights whose /QuadPoints are one shared indirect array of 65,536 numbers (QA's
    // crafted file had 30,000): an indirect geometry array is refused unread.
    let base = Base::CertifiedP3Annotated.bytes();
    let mut shared: Option<ObjectId> = None;
    let pdf = annotated(&base, 3_000, |store, page, ap, _| {
        let quads = *shared.get_or_insert_with(|| {
            store
                .add(Object::Array(points(65_536)))
                .expect("the shared array")
        });
        let mut dict = markup("Highlight", page, ap);
        dict.insert("QuadPoints", Object::Ref(quads));
        dict
    });
    let r = verified(pdf);
    assert_eq!(r.modification, ModificationLevel::Other, "{}", summary(&r));
    assert!(
        r.warnings.iter().any(|w| w.contains("direct array")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn an_ink_list_of_shared_strokes_is_not_read_per_reference() {
    // One ink annotation whose /InkList is 65,536 references to one 32,768-point stroke (QA's
    // crafted file, 32.6 s before the fix).
    let base = Base::CertifiedP3Annotated.bytes();
    let pdf = annotated(&base, 1, |store, page, ap, _| {
        let stroke = store.add(Object::Array(points(65_536))).unwrap();
        let mut dict = markup("Ink", page, ap);
        dict.insert("InkList", Object::Array(vec![Object::Ref(stroke); 65_536]));
        dict
    });
    let r = verified(pdf);
    assert_eq!(r.modification, ModificationLevel::Other, "{}", summary(&r));
    assert!(
        r.warnings.iter().any(|w| w.contains("/InkList")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn many_direct_annotations_are_linear() {
    // The legitimate shape: 2,000 highlights, each with its own direct quadrilateral, sharing one
    // appearance stream: Annotations under P = 3, checked in one pass over their bytes.
    let base = Base::CertifiedP3Annotated.bytes();
    let pdf = annotated(&base, 2_000, |_, page, ap, _| {
        let mut dict = markup("Highlight", page, ap);
        dict.insert(
            "QuadPoints",
            Object::Array(
                [66.0, 314.0, 74.0, 314.0, 66.0, 306.0, 74.0, 306.0]
                    .map(Object::Real)
                    .to_vec(),
            ),
        );
        dict
    });
    let r = verified(pdf);
    assert_eq!(
        r.modification,
        ModificationLevel::Annotations,
        "{} {:?}",
        summary(&r),
        r.warnings.iter().take(3).collect::<Vec<_>>()
    );
    assert_eq!(r.docmdp_ok, Some(true));
}

#[test]
fn one_annotation_listed_on_many_pages_is_checked_once() {
    // A new annotation with a large direct geometry (65,536 numbers in all) listed again and
    // again: the classifier checks it once per comparison, not once per listing (it is Other
    // anyway: the same annotation twice on a page).
    let base = Base::CertifiedP3Annotated.bytes();
    let mut first: Option<Dict> = None;
    let pdf = annotated(&base, 1, |_, page, ap, _| {
        let mut dict = markup("Ink", page, ap);
        dict.insert(
            "InkList",
            Object::Array(vec![Object::Array(points(65_536))]),
        );
        first = Some(dict.clone());
        dict
    });
    let mut store = Store::open_bytes(pdf, &OpenOptions::default()).unwrap();
    let page = first_page(&store);
    let mut page_dict = store.resolve(page).unwrap().as_dict().unwrap().clone();
    let mut annots = page_dict.get_array(b"Annots").unwrap().to_vec();
    let last = annots.last().cloned().unwrap();
    annots.extend(std::iter::repeat_n(last, 20_000));
    page_dict.insert("Annots", Object::Array(annots));
    store.set(page, Object::Dict(page_dict)).unwrap();
    let pdf = store
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    let r = verified(pdf);
    assert!(first.is_some());
    assert!(
        r.modification >= ModificationLevel::Annotations,
        "{}",
        summary(&r)
    );
}

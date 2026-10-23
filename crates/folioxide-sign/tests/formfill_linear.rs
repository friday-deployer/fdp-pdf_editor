#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The form-filling whitelist stays linear in the size of the form (M4 brief §6.2
//! `form_fill_classification_linear`, R-18): a signed form with 5,000 text fields, every one of
//! them filled (a new `/V` and its appearance stream rewritten in place) in one revision, is
//! classified within a fixed budget.

mod sign_support;

use std::time::Duration;

use folioxide_sign::report::ModificationLevel;
use folioxide_syntax::{IncrementalOptions, Object, OpenOptions, Store, Stream, StreamData};
use folioxide_testkit::budget::within;
use folioxide_testkit::fixtures::forms;
use sign_support::*;

/// The number of fields of the form.
const FIELDS: usize = 5_000;

/// `pdf` with a revision that fills every text field at the root of `/Fields`: `/V (filled i)` and
/// the field's `/AP /N` stream rewritten in place to show it. One pass over `/Fields`.
fn fill_every_field(pdf: &[u8]) -> Vec<u8> {
    let mut store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default()).unwrap();
    let root = store.root_id().unwrap();
    let catalog = store.resolve(root).unwrap().as_dict().unwrap().clone();
    let acroform = store
        .resolve(catalog.get_ref(b"AcroForm").unwrap())
        .unwrap()
        .as_dict()
        .unwrap()
        .clone();
    let fields = store
        .resolve(acroform.get_ref(b"Fields").unwrap())
        .unwrap()
        .as_array()
        .unwrap()
        .to_vec();
    // The text fields, not the signature field signing appended.
    let fields: Vec<_> = fields
        .iter()
        .map(|f| f.as_ref().unwrap())
        .filter(|&id| {
            let field = store.resolve(id).unwrap();
            field
                .as_dict()
                .unwrap()
                .get_name(b"FT")
                .map(|n| n.as_bytes())
                == Some(b"Tx")
        })
        .collect();
    assert_eq!(fields.len(), FIELDS);
    for (i, &id) in fields.iter().enumerate() {
        let mut dict = store.resolve(id).unwrap().as_dict().unwrap().clone();
        let text = format!("filled {i}");
        dict.insert("V", Object::literal_string(text.as_bytes()));
        let normal = dict.get_dict(b"AP").unwrap().get_ref(b"N").unwrap();
        let old = store.resolve(normal).unwrap();
        let Object::Stream(old) = &*old else {
            panic!("the appearance is a stream")
        };
        let mut stream_dict = old.dict.clone();
        stream_dict.remove(b"Length");
        stream_dict.remove(b"Filter");
        let content = format!("/Tx BMC q BT /Helv 6 Tf 0 g 1 1 Td ({text}) Tj ET Q EMC");
        let stream = Stream::new(stream_dict, StreamData::Decoded(content.into_bytes()));
        store.set(normal, Object::Stream(Box::new(stream))).unwrap();
        store.set(id, Object::Dict(dict)).unwrap();
    }
    store
        .save_incremental(&IncrementalOptions::default())
        .unwrap()
}

#[test]
fn form_fill_classification_linear() {
    let signed = sign_default(&forms::acroform_text_fields(FIELDS), &rsa2048());
    let filled = fill_every_field(&signed);
    // About 1.7 s in a debug build (1,000 fields: 0.3 s; 20,000: 7 s), so the budget leaves room
    // for a loaded CI machine but not for a quadratic pass over the fields and their uses.
    let budget = Duration::from_secs(20);
    let (reports, took) =
        within(budget, move || verify_plain(&filled)).unwrap_or_else(|overrun| panic!("{overrun}"));
    let r = &reports[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(
        r.modification,
        ModificationLevel::FormFilling,
        "{}: {:?}",
        summary(r),
        r.warnings.iter().take(3).collect::<Vec<_>>()
    );
    assert_eq!(r.docmdp_ok, Some(true));
    eprintln!("{FIELDS} filled fields classified in {took:.2?}");
}

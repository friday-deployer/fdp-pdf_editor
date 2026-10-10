#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Name trees and number trees (ISO 32000-2 §7.9.6, §7.9.7; M2 brief AC3).

mod common;

use common::{build, open};
use folioxide_model::{Document, NameTree, NumberTree};
use folioxide_syntax::{ErrorCode, Limits, Object, ObjectId, OpenOptions, ParseCtx, parse_object};
use folioxide_testkit::fixtures::model;

/// The catalog entry at `path` (dictionaries followed through references), as written: the
/// last value is not dereferenced, so a tree root keeps its object id.
fn catalog_entry(doc: &Document, path: &[&[u8]]) -> Object {
    let mut dict = doc.catalog().unwrap().as_dict().unwrap().clone();
    let (last, parents) = path.split_last().unwrap();
    for key in parents {
        let value = doc.store().deref(dict.get(key).unwrap()).unwrap();
        dict = value.as_dict().unwrap().clone();
    }
    dict.get(last).unwrap().clone()
}

fn object(text: &str) -> Object {
    parse_object(text.as_bytes(), 0, &ParseCtx::default())
        .unwrap()
        .0
}

/// Lookups in a three-level name tree: through `/Limits`, through a node whose `/Limits` are
/// wrong (the full-walk fallback), past a cycle, and for missing keys.
#[test]
fn name_tree_lookup() {
    let doc = open(model::trees());
    let root = catalog_entry(&doc, &[b"Names", b"Dests"]);
    assert_eq!(root, Object::Ref(ObjectId::new(10, 0)));
    let tree = NameTree::new(doc.store(), &root);

    let entries = tree.entries().unwrap();
    let keys: Vec<&[u8]> = entries.iter().map(|(k, _)| k.as_slice()).collect();
    let expected: Vec<&[u8]> = model::NAMED_DESTS
        .iter()
        .map(|(k, _)| k.as_bytes())
        .collect();
    assert_eq!(keys, expected);

    for (key, page) in model::NAMED_DESTS {
        let value = tree
            .get(key.as_bytes())
            .unwrap()
            .unwrap_or_else(|| panic!("{key}"));
        // A destination array, a dictionary with /D, or a reference to one (§12.3.2.4).
        let value = doc.store().deref(&value).unwrap();
        let dest = match value.as_dict() {
            Some(dict) => dict.get(b"D").unwrap().clone(),
            None => value.into_owned(),
        };
        assert_eq!(
            dest.as_array().unwrap()[0],
            Object::Ref(ObjectId::new(page, 0)),
            "{key}"
        );
    }
    // Values come back as written: `chapter1` is an indirect object.
    assert_eq!(
        tree.get(b"chapter1").unwrap(),
        Some(Object::Ref(ObjectId::new(30, 0)))
    );
    // `zeta` sits under /Limits that exclude it; the fallback still finds it.
    assert!(tree.get(b"zeta").unwrap().is_some());
    for missing in [&b""[..], b"a", b"alphabet", b"mu", b"zzz", b"\xFE\xFF"] {
        assert_eq!(tree.get(missing).unwrap(), None, "{missing:?}");
    }

    // A direct root with /Names only.
    let direct = object("<< /Names [(b) 2 (a) 1 (c) 3 (odd)] >>");
    let tree = NameTree::new(doc.store(), &direct);
    assert_eq!(tree.get(b"a").unwrap(), Some(Object::Int(1)));
    assert_eq!(tree.get(b"odd").unwrap(), None);
    assert_eq!(tree.entries().unwrap().len(), 3);
    // Not a tree at all.
    assert!(
        NameTree::new(doc.store(), &Object::Int(3))
            .entries()
            .unwrap()
            .is_empty()
    );
}

/// Lookups in a number tree with an intermediate node (§7.9.7), as used by `/PageLabels`.
#[test]
fn number_tree_lookup() {
    let doc = open(model::trees());
    let root = catalog_entry(&doc, &[b"PageLabels"]);
    let tree = NumberTree::new(doc.store(), &root);
    let entries = tree.entries().unwrap();
    let keys: Vec<i64> = entries.iter().map(|(k, _)| *k).collect();
    let expected: Vec<i64> = model::PAGE_LABELS.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, expected);
    for (key, style) in model::PAGE_LABELS {
        let label = tree.get(key).unwrap().unwrap();
        assert!(
            label
                .as_dict()
                .unwrap()
                .get(b"S")
                .unwrap()
                .is_name(style.as_bytes())
        );
    }
    assert_eq!(
        tree.get(9)
            .unwrap()
            .unwrap()
            .as_dict()
            .unwrap()
            .get_int(b"St"),
        Some(10)
    );
    for missing in [-1, 1, 3, 4, 6, 10, i64::MAX, i64::MIN] {
        assert_eq!(tree.get(missing).unwrap(), None, "{missing}");
    }

    // Integral reals as keys are accepted; other keys are skipped.
    let direct = object("<< /Nums [1 (one) 2.0 (two) /x (bad) 3.5 (bad) 4 (four)] >>");
    let tree = NumberTree::new(doc.store(), &direct);
    let keys: Vec<i64> = tree.entries().unwrap().iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, [1, 2, 4]);
}

/// Tree walks are bounded: a chain of kids deeper than `max_nesting_depth` is an error, and a
/// cycle is visited once.
#[test]
fn trees_are_bounded() {
    // Objects 10..=19: a chain of /Kids, 10 levels deep, ending in a leaf; 19 also lists 10.
    let mut objects: Vec<(u32, String)> = vec![
        (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
        (2, "<< /Type /Pages /Kids [] /Count 0 >>".to_owned()),
    ];
    for n in 10..19 {
        objects.push((n, format!("<< /Kids [{} 0 R] >>", n + 1)));
    }
    objects.push((19, "<< /Kids [10 0 R 20 0 R] >>".to_owned()));
    objects.push((20, "<< /Nums [7 (seven)] /Names [(k) (v)] >>".to_owned()));
    let objects: Vec<(u32, &str)> = objects.iter().map(|(n, b)| (*n, b.as_str())).collect();
    let pdf = build("1.4", &objects, "");

    let doc = open(pdf.clone());
    let root = Object::Ref(ObjectId::new(10, 0));
    let numbers = NumberTree::new(doc.store(), &root);
    assert_eq!(
        numbers.get(7).unwrap(),
        Some(Object::literal_string("seven"))
    );
    assert_eq!(numbers.entries().unwrap().len(), 1);
    let names = NameTree::new(doc.store(), &root);
    assert_eq!(names.get(b"k").unwrap(), Some(Object::literal_string("v")));

    let options = OpenOptions::default().with_limits(Limits::default().with_max_nesting_depth(5));
    let doc = Document::open(pdf, &options).unwrap();
    let numbers = NumberTree::new(doc.store(), &root);
    assert_eq!(
        numbers.entries().unwrap_err().code(),
        ErrorCode::LimitExceeded
    );
    assert_eq!(numbers.get(7).unwrap_err().code(), ErrorCode::LimitExceeded);
}

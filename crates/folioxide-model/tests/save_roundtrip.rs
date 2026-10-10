#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Document-level save round trips over every fixture (M2 brief WP2.6; acceptance criterion 7,
//! "writer output for every fixture reopens with no new diagnostics beyond those of the
//! source").
//!
//! Every syntax fixture, every qpdf fixture and every document-model fixture that opens is read
//! through the model (every page's [`PageInfo`], the Info dictionary, the version), then saved in
//! full (with a cross-reference table, and with object streams) and, when the source takes one
//! ([`Store::check_incremental`]), incrementally after a `set_info`. Each output must reopen
//! without a repair and show the same pages and Info (the new title for the update), a version
//! no lower than the source's, and, kind by kind, no more diagnostics than the source gave after
//! the same reads. The store-level counterpart, over raw objects, is
//! `crates/folioxide-syntax/tests/writer_acceptance.rs`.
//!
//! [`Store::check_incremental`]: folioxide_syntax::Store::check_incremental

use std::collections::BTreeMap;

use folioxide_model::{DocInfo, Document, InfoUpdate, PageInfo};
use folioxide_syntax::{ErrorCode, IncrementalOptions, OpenOptions, SaveOptions};
use folioxide_testkit::fixtures::{model, qpdf, syntax};

/// Every fixture, by name: the syntax fixtures, the qpdf ones as `qpdf-<name>` and the model ones
/// as `model-<name>`.
fn fixtures() -> Vec<(String, Vec<u8>)> {
    let mut all: Vec<(String, Vec<u8>)> = syntax::all()
        .into_iter()
        .map(|(name, bytes)| (name.to_owned(), bytes))
        .collect();
    for info in qpdf::infos() {
        all.push((
            format!("qpdf-{}", info.name),
            qpdf::read_committed(info.name).unwrap(),
        ));
    }
    for (name, bytes) in [
        ("inherited-attributes", model::inherited_attributes()),
        ("rotations", model::rotations()),
        ("crop-box-quirks", model::crop_box_quirks()),
        ("page-tree-cycle", model::page_tree_cycle()),
        ("wrong-count", model::wrong_count()),
        ("deep-page-tree", model::deep_page_tree(8)),
        ("trees", model::trees()),
        ("info-strings", model::info_strings()),
    ] {
        all.push((format!("model-{name}"), bytes));
    }
    all
}

/// What a document shows through the model, after reading all of it.
#[derive(Debug)]
struct View {
    pages: Result<Vec<PageInfo>, ErrorCode>,
    info: Result<DocInfo, ErrorCode>,
    version: (u8, u8),
    /// The number of diagnostics of each kind, after the reads above.
    diagnostics: BTreeMap<String, usize>,
}

/// Reads every page (all five boxes, rotation, PageInfo), the Info dictionary and the version,
/// then counts the diagnostics by kind.
fn view(doc: &Document) -> View {
    let pages = doc
        .page_count()
        .map(|count| {
            (0..count)
                .map(|i| {
                    let page = doc.page(i).unwrap();
                    let _ = (page.bleed_box(), page.trim_box(), page.art_box());
                    page.info()
                })
                .collect()
        })
        .map_err(|err| err.code());
    let info = doc.info().map_err(|err| err.code());
    let version = doc.version();
    let mut diagnostics = BTreeMap::new();
    for diagnostic in doc.diagnostics() {
        *diagnostics
            .entry(diagnostic.kind.as_str().to_owned())
            .or_insert(0) += 1;
    }
    View {
        pages,
        info,
        version,
        diagnostics,
    }
}

/// Reopens `pdf` and checks it against the source's view: the same pages, `info`, a version no
/// lower, and no kind of diagnostic more often.
fn check_output(what: &str, pdf: Vec<u8>, before: &View, info: &Result<DocInfo, ErrorCode>) {
    let doc = Document::open(pdf, &OpenOptions::default())
        .unwrap_or_else(|err| panic!("{what}: does not reopen: {err}"));
    assert!(!doc.store().structure_repaired(), "{what}: repaired");
    let after = view(&doc);
    assert_eq!(after.pages, before.pages, "{what}: pages");
    assert_eq!(&after.info, info, "{what}: info");
    assert!(after.version >= before.version, "{what}: version");
    for (kind, &count) in &after.diagnostics {
        let was = before.diagnostics.get(kind).copied().unwrap_or(0);
        assert!(
            count <= was,
            "{what}: {count} {kind} diagnostics, the source gave {was}: {:?}",
            doc.diagnostics()
        );
    }
}

#[test]
fn writer_output_reopens_with_the_same_model_and_no_new_diagnostics() {
    let mut full = 0;
    let mut incremental = 0;
    let mut refused = Vec::new();
    for (name, bytes) in fixtures() {
        let doc = match Document::open(bytes.clone(), &OpenOptions::default()) {
            Ok(doc) => doc,
            Err(err) => {
                // Only the encrypted fixtures do not open in M2.
                assert!(
                    matches!(
                        err.code(),
                        ErrorCode::PasswordRequired | ErrorCode::Unsupported
                    ),
                    "{name}: {err}"
                );
                continue;
            }
        };
        let before = view(&doc);

        for (variant, options) in [
            ("full", SaveOptions::default()),
            ("objstm", SaveOptions::default().with_object_streams(true)),
        ] {
            let pdf = doc
                .save(&options)
                .unwrap_or_else(|err| panic!("{name} {variant}: {err}"));
            check_output(&format!("{name} {variant}"), pdf, &before, &before.info);
            full += 1;
        }

        if doc.store().check_incremental().is_err() {
            refused.push(name);
            continue;
        }
        let mut edited = Document::open(bytes.clone(), &OpenOptions::default()).unwrap();
        let title = format!("{name} \u{2013} Grüße");
        edited
            .set_info(&InfoUpdate::default().with_title(Some(&title)))
            .unwrap();
        let pdf = edited
            .save_incremental(&IncrementalOptions::default())
            .unwrap_or_else(|err| panic!("{name} incremental: {err}"));
        assert!(pdf.starts_with(&bytes), "{name}: prefix");
        let expected_info = before.info.clone().map(|mut info| {
            info.title = Some(title.clone());
            info
        });
        check_output(&format!("{name} incremental"), pdf, &before, &expected_info);
        incremental += 1;
    }
    println!("{full} full saves, {incremental} incremental saves, refused: {refused:?}");
    // Every fixture that opens was saved in full; the incremental updates cover every kind of
    // source section, and the refusals are the damaged fixtures.
    assert!(full >= 2 * 30, "{full} full saves");
    assert!(incremental >= 15, "{incremental} incremental saves");
    for name in [
        "minimal",
        "multi-revision",
        "xref-stream",
        "hybrid",
        "model-inherited-attributes",
    ] {
        assert!(!refused.contains(&name.to_owned()), "{name} was refused");
    }
    for name in ["missing-xref", "xref-offsets-off-by-n", "prev-loop"] {
        assert!(refused.contains(&name.to_owned()), "{name} was not refused");
    }
}

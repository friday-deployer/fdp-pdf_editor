#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Writer and store-edit acceptance tests (M2 brief WP2.1 and WP2.4, acceptance criteria 2 and
//! 7), over every fixture that applies: the committed syntax fixtures (`fixtures/syntax/`), the
//! linearized files qpdf wrote (`fixtures/qpdf/`), the document-model fixtures generated at test
//! time ([`folioxide_testkit::fixtures::model`]), and, for the full writer, the small hostile
//! files (`fixtures/hostile/`).
//!
//! Graph equality (modulo renumbering for a full save, with the same numbers for an incremental
//! update) is [`folioxide_testkit::graph`].

use std::collections::{BTreeSet, HashMap};

use folioxide_syntax::{
    Dict, ErrorCode, IncrementalOptions, IncrementalUpdate, Object, ObjectId, OffsetBase,
    OpenOptions, SaveOptions, Store, StreamCompression, StreamData, XrefEntry, XrefKind, XrefStyle,
    keys,
};
use folioxide_testkit::PdfBuilder;
use folioxide_testkit::exercise::page_count;
use folioxide_testkit::fixtures::{hostile, model, qpdf, syntax};
use folioxide_testkit::graph::{GraphOptions, compare_graphs, graph_diff};

// ---- fixtures and helpers -----------------------------------------------------------------------

/// Every fixture as `(name, bytes)`: the committed syntax fixtures, the qpdf ones as
/// `qpdf-<name>`, and the document-model fixtures as `model-<name>`.
fn fixtures() -> Vec<(String, Vec<u8>)> {
    let mut all: Vec<(String, Vec<u8>)> = syntax::all()
        .into_iter()
        .map(|(name, bytes)| (name.to_owned(), bytes))
        .collect();
    for info in qpdf::infos() {
        let bytes = qpdf::read_committed(info.name).unwrap();
        all.push((format!("qpdf-{}", info.name), bytes));
    }
    all.extend(model_fixtures());
    all
}

/// The document-model fixtures (well-formed files with classic tables): inherited attributes,
/// rotations, broken page trees, name and number trees, Info strings in every encoding.
fn model_fixtures() -> Vec<(String, Vec<u8>)> {
    [
        ("model-inherited-attributes", model::inherited_attributes()),
        ("model-rotations", model::rotations()),
        ("model-page-tree-cycle", model::page_tree_cycle()),
        ("model-wrong-count", model::wrong_count()),
        // Deeper than the default `max_page_tree_depth` (64).
        ("model-deep-page-tree", model::deep_page_tree(70)),
        ("model-trees", model::trees()),
        ("model-info-strings", model::info_strings()),
    ]
    .into_iter()
    .map(|(name, bytes)| (name.to_owned(), bytes))
    .collect()
}

fn open(bytes: &[u8]) -> Store {
    Store::open_bytes(bytes.to_vec(), &OpenOptions::default()).unwrap()
}

/// The fixtures that open (lenient), with their stores.
fn openable() -> Vec<(String, Vec<u8>, Store)> {
    fixtures()
        .into_iter()
        .filter_map(|(name, bytes)| {
            let store = Store::open_bytes(bytes.clone(), &OpenOptions::default()).ok()?;
            Some((name, bytes, store))
        })
        .collect()
}

/// Whether an incremental update may be appended to `store` (a revision structure that other
/// readers resolve the same way, [`Store::check_incremental`]).
fn appendable(store: &Store) -> bool {
    store.check_incremental().is_ok()
}

/// Sets `/Title` in the document information dictionary, creating it (and linking it from the
/// trailer) when the document has none.
fn set_title(store: &mut Store, title: &str) {
    let info = store
        .trailer()
        .get_ref(keys::INFO)
        .filter(|&id| store.contains(id) && store.resolve(id).unwrap().as_dict().is_some());
    match info {
        Some(info) => {
            store
                .get_mut(info)
                .unwrap()
                .as_dict_mut()
                .unwrap()
                .insert("Title", Object::literal_string(title));
        }
        None => {
            let mut dict = Dict::new();
            dict.insert("Title", Object::literal_string(title));
            let id = store.add(dict.into()).unwrap();
            store.set_trailer_entry(keys::INFO, id.into()).unwrap();
        }
    }
}

/// The `/Title` of the document information dictionary.
fn title(store: &Store) -> Option<Vec<u8>> {
    let info = store.deref(store.trailer().get(keys::INFO)?).ok()?;
    info.as_dict()?.get_str_bytes(b"Title").map(<[u8]>::to_vec)
}

/// The kinds of the diagnostics recorded so far, as strings.
fn diagnostic_kinds(store: &Store) -> BTreeSet<String> {
    store
        .diagnostics()
        .iter()
        .map(|d| d.kind.as_str().to_owned())
        .collect()
}

/// The xref entries of the newest revision of `bytes`, by number.
fn newest_entries(bytes: &[u8]) -> HashMap<u32, XrefEntry> {
    let store = open(bytes);
    let last = store.revisions().len() - 1;
    store.revision_entries(last).unwrap().into_iter().collect()
}

// ---- acceptance tests (M2 brief, criterion 2) ---------------------------------------------------

#[test]
fn incremental_prefix_preserved_all_fixtures() {
    let mut checked = Vec::new();
    for (name, bytes, mut store) in openable() {
        if !appendable(&store) {
            continue;
        }
        let revisions = store.revisions().len();
        let pages = page_count(&store);
        let new_title = format!("Edited {name} \u{e9}");
        set_title(&mut store, &new_title);
        let out = store
            .save_incremental(&IncrementalOptions::default())
            .unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(&out[..bytes.len()], &bytes[..], "{name}: prefix changed");
        let suffix = store
            .incremental_suffix(&IncrementalOptions::default())
            .unwrap();
        assert_eq!(&out[bytes.len()..], &suffix[..], "{name}: suffix");

        let reopened = open(&out);
        assert_eq!(
            title(&reopened).as_deref(),
            Some(new_title.as_bytes()),
            "{name}: title"
        );
        assert_eq!(reopened.revisions().len(), revisions + 1, "{name}");
        assert!(
            !reopened.structure_repaired(),
            "{name}: {:?}",
            reopened.diagnostics()
        );
        assert_eq!(page_count(&reopened), pages, "{name}: pages");
        // The new revision ends where the file does.
        assert_eq!(
            reopened.revisions().last().unwrap().eof_end,
            out.len() as u64,
            "{name}"
        );
        // The updated file means what the edited store meant, object for object, with the same
        // numbers.
        let same = GraphOptions::default().with_same_numbers(true);
        let comparison = compare_graphs(&store, &reopened, &same);
        assert!(comparison.is_equal(), "{name}: {comparison}");
        // Reading the whole update (the comparison read both documents) reports nothing that
        // reading the source did not.
        let new_kinds: BTreeSet<String> = diagnostic_kinds(&reopened)
            .difference(&diagnostic_kinds(&store))
            .cloned()
            .collect();
        assert!(
            new_kinds.is_empty(),
            "{name}: new diagnostics {new_kinds:?}"
        );
        checked.push(name);
    }
    // Every appendable fixture: the healthy ones, those with damaged objects (not structure),
    // junk before the header, both qpdf linearized files, and the model fixtures.
    for name in [
        "minimal",
        "multi-revision",
        "xref-stream",
        "xref-stream-incremental",
        "hybrid",
        "objstm",
        "junk-before-header",
        "stream-length-wrong",
        "qpdf-linearized",
        "qpdf-linearized-objstm",
        "model-inherited-attributes",
        "model-page-tree-cycle",
        "model-deep-page-tree",
        "model-info-strings",
    ] {
        assert!(checked.iter().any(|c| c == name), "{name} was not checked");
    }
    assert!(
        checked.len() >= 15,
        "only {} fixtures: {checked:?}",
        checked.len()
    );
}

#[test]
fn incremental_matches_previous_xref_kind() {
    let mut kinds = BTreeSet::new();
    for (name, _, mut store) in openable() {
        if !appendable(&store) {
            continue;
        }
        let previous = store.revisions().last().unwrap().xref_kind;
        let expected = match previous {
            XrefKind::Table => XrefKind::Table,
            _ => XrefKind::Stream,
        };
        set_title(&mut store, "kind");
        let update = store
            .incremental_update(&IncrementalOptions::default())
            .unwrap();
        assert_eq!(update.xref_kind, Some(expected), "{name}");
        let out = store
            .save_incremental(&IncrementalOptions::default())
            .unwrap();
        let reopened = open(&out);
        assert_eq!(
            reopened.revisions().last().unwrap().xref_kind,
            expected,
            "{name}"
        );
        let section = &out[update.xref_pos.unwrap() as usize..];
        match expected {
            XrefKind::Table => assert!(section.starts_with(b"xref\n0 "), "{name}"),
            _ => {
                // The stream lists itself under the next unused number.
                let num = store.next_object_number();
                assert!(
                    section.starts_with(format!("{num} 0 obj\n<</Type /XRef").as_bytes()),
                    "{name}"
                );
                assert!(matches!(
                    reopened
                        .revision_entries(reopened.revisions().len() - 1)
                        .unwrap()
                        .into_iter()
                        .find(|&(n, _)| n == num),
                    Some((_, XrefEntry::InFile { .. }))
                ));
            }
        }
        kinds.insert(format!("{previous:?}"));
    }
    // Tables, streams and hybrids were all covered.
    assert_eq!(
        kinds.into_iter().collect::<Vec<_>>(),
        ["Hybrid", "Stream", "Table"]
    );
}

#[test]
fn incremental_refuses_reconstructed() {
    let mut refused = Vec::new();
    for (name, bytes, mut store) in openable() {
        if appendable(&store) {
            continue;
        }
        // Even an unedited one: an incremental save of it is never meaningful.
        let err = store
            .save_incremental(&IncrementalOptions::default())
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported, "{name}: {err}");
        assert!(err.to_string().contains("full save"), "{name}: {err}");
        set_title(&mut store, "refused");
        for err in [
            store
                .save_incremental(&IncrementalOptions::default())
                .unwrap_err(),
            store
                .incremental_suffix(&IncrementalOptions::default())
                .unwrap_err(),
        ] {
            assert_eq!(err.code(), ErrorCode::Unsupported, "{name}: {err}");
        }
        // A full save is the way out, and the result takes incremental updates.
        let full = store.save(&SaveOptions::default()).unwrap();
        let mut rewritten = open(&full);
        assert!(appendable(&rewritten), "{name}");
        assert_eq!(
            title(&rewritten).as_deref(),
            Some(&b"refused"[..]),
            "{name}"
        );
        set_title(&mut rewritten, "appended");
        let out = rewritten
            .save_incremental(&IncrementalOptions::default())
            .unwrap();
        assert!(out.starts_with(&full));
        assert_eq!(title(&open(&out)).as_deref(), Some(&b"appended"[..]));
        let _ = bytes;
        refused.push(name);
    }
    assert!(refused.iter().any(|n| n == "missing-xref"), "{refused:?}");
    assert!(
        refused.iter().any(|n| n == "startxref-off-by-n"),
        "{refused:?}"
    );
    assert!(refused.iter().any(|n| n == "prev-loop"), "{refused:?}");
    // Objects away from their offsets: the store finds them, qpdf and poppler reconstruct.
    assert!(
        refused.iter().any(|n| n == "xref-offsets-off-by-n"),
        "{refused:?}"
    );
    let store = open(&syntax::xref_offsets_off_by_n());
    assert!(!store.structure_repaired());
    let err = store.check_incremental().unwrap_err();
    assert!(
        err.to_string().contains("1 0 R is not at the position"),
        "{err}"
    );

    // The reconstructed kind itself.
    let store = open(&syntax::missing_xref());
    assert_eq!(
        store.revisions().last().unwrap().xref_kind,
        XrefKind::Reconstructed
    );

    // A new document has nothing to append to.
    let mut store = Store::new_empty((1, 7));
    let catalog = store.add(Dict::new().into()).unwrap();
    store.set_trailer_entry(keys::ROOT, catalog.into()).unwrap();
    for err in [
        store
            .save_incremental(&IncrementalOptions::default())
            .unwrap_err(),
        store
            .incremental_suffix(&IncrementalOptions::default())
            .unwrap_err(),
    ] {
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    }

    // Nothing edited: the source as it is, and no suffix.
    let bytes = syntax::minimal();
    let store = open(&bytes);
    assert!(!store.is_modified());
    assert_eq!(
        store
            .save_incremental(&IncrementalOptions::default())
            .unwrap(),
        bytes
    );
    assert!(
        store
            .incremental_suffix(&IncrementalOptions::default())
            .unwrap()
            .is_empty()
    );
}

/// The full-save option sets the round trip covers: the default, object streams, a table,
/// recompression, and everything kept as it is (no garbage collection, no renumbering, no
/// compression).
fn full_save_options() -> Vec<(&'static str, SaveOptions)> {
    vec![
        ("default", SaveOptions::default()),
        ("objstm", SaveOptions::default().with_object_streams(true)),
        ("table", SaveOptions::default().with_xref(XrefStyle::Table)),
        (
            "recompress",
            SaveOptions::default().with_compress(StreamCompression::Recompress),
        ),
        (
            "keep",
            SaveOptions::default()
                .with_compress(StreamCompression::Keep)
                .with_gc(false)
                .with_renumber(false),
        ),
    ]
}

#[test]
fn full_save_roundtrip_deep_equal() {
    let mut checked = 0;
    for (name, _, store) in openable() {
        // Numbers are kept without renumbering unless a reconstruction found two generations
        // of one number (the later ones are numbered anew).
        let ids = store.object_ids();
        let unique_numbers = ids.windows(2).all(|w| w[0].num != w[1].num);
        for (label, opts) in full_save_options() {
            let out = store
                .save(&opts)
                .unwrap_or_else(|err| panic!("{name} ({label}): {err}"));
            let saved = open(&out);
            assert!(
                saved.diagnostics().is_empty(),
                "{name} ({label}): {:?}",
                saved.diagnostics()
            );
            assert!(!saved.structure_repaired(), "{name} ({label})");
            let expected_kind = match opts.xref {
                XrefStyle::Table => XrefKind::Table,
                _ if opts.object_streams => XrefKind::Stream,
                // Auto: a stream when the source's newest section used one.
                _ => match store.revisions().last().unwrap().xref_kind {
                    XrefKind::Stream | XrefKind::Hybrid => XrefKind::Stream,
                    _ => XrefKind::Table,
                },
            };
            assert_eq!(
                saved.revisions().last().unwrap().xref_kind,
                expected_kind,
                "{name} ({label})"
            );
            let graph = GraphOptions::default().with_same_numbers(!opts.renumber && unique_numbers);
            let comparison = compare_graphs(&store, &saved, &graph);
            assert!(comparison.is_equal(), "{name} ({label}): {comparison}");
            assert_eq!(page_count(&saved), page_count(&store), "{name} ({label})");
            if opts.renumber {
                // Dense numbering from 1: the catalog first.
                assert_eq!(saved.root_id(), Some(ObjectId::new(1, 0)), "{name}");
            }
            // Everything written resolves, and reading it (data included) reports nothing the
            // source did not (truncated Flate data is copied as it is).
            for id in saved.object_ids() {
                saved.resolve(id).unwrap();
            }
            let new_kinds: BTreeSet<String> = diagnostic_kinds(&saved)
                .difference(&diagnostic_kinds(&store))
                .cloned()
                .collect();
            assert!(new_kinds.is_empty(), "{name} ({label}): {new_kinds:?}");
            if opts.object_streams {
                let compressed = saved
                    .revision_entries(0)
                    .unwrap()
                    .into_iter()
                    .filter(|(_, e)| matches!(e, XrefEntry::InObjStm { .. }))
                    .count();
                assert!(compressed >= 3, "{name}: {compressed} compressed objects");
            }
            // The output takes an incremental update.
            assert!(appendable(&saved), "{name} ({label})");
            checked += 1;
        }
    }
    assert!(checked >= 5 * 30, "{checked}");

    // With edits: the saved graph is the edited one.
    let mut store = open(&syntax::multi_revision());
    set_title(&mut store, "edited");
    let page = store.add(Object::Dict(Dict::new())).unwrap();
    let root = store.root_id().unwrap();
    store
        .get_mut(root)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .insert("Extra", page);
    let saved = open(&store.save(&SaveOptions::default()).unwrap());
    assert_eq!(graph_diff(&store, &saved), None);
    assert_eq!(title(&saved).as_deref(), Some(&b"edited"[..]));
    // And the source's graph is not: the differences name the paths to the edits.
    let source = open(&syntax::multi_revision());
    let comparison = compare_graphs(&source, &saved, &GraphOptions::default());
    let paths: Vec<&str> = comparison
        .differences
        .iter()
        .map(|d| d.path.as_str())
        .collect();
    assert_eq!(
        paths,
        ["trailer /Info", "trailer /Root → 1 0 R | 1 0 R"],
        "{comparison}"
    );
}

#[test]
fn full_save_of_hostile_seeds() {
    // The small instances of the resource-exhaustion shapes: every one that opens saves, and the
    // output reopens cleanly with the same graph (or the save fails with a documented code).
    let mut saved_count = 0;
    for (name, bytes) in hostile::seeds() {
        let Ok(store) = Store::open_bytes(bytes, &OpenOptions::default()) else {
            continue;
        };
        let out = match store.save(&SaveOptions::default()) {
            Ok(out) => out,
            Err(err) => {
                assert!(
                    matches!(
                        err.code(),
                        ErrorCode::LimitExceeded | ErrorCode::InvalidArgument
                    ),
                    "{name}: {err}"
                );
                continue;
            }
        };
        let saved = open(&out);
        assert!(!saved.structure_repaired(), "{name}");
        assert!(
            saved.diagnostics().is_empty(),
            "{name}: {:?}",
            saved.diagnostics()
        );
        let comparison = compare_graphs(&store, &saved, &GraphOptions::default());
        assert!(comparison.is_equal(), "{name}: {comparison}");
        saved_count += 1;
    }
    assert!(saved_count >= 5, "{saved_count}");
}

#[test]
fn gc_removes_unreachable() {
    let mut store = open(&syntax::minimal());
    let marker = Object::literal_string("unreachable-marker");
    let mut orphan = Dict::new();
    orphan.insert("Marker", marker.clone());
    let orphan = store.add(orphan.into()).unwrap();
    // An object only an orphan refers to is unreachable too.
    let mut chained = Dict::new();
    chained.insert("Marker", Object::literal_string("chained-marker"));
    let chained = store.add(chained.into()).unwrap();
    store
        .get_mut(orphan)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .insert("Next", chained);
    let contains = |bytes: &[u8], text: &[u8]| bytes.windows(text.len()).any(|w| w == text);

    let out = store.save(&SaveOptions::default()).unwrap();
    assert!(!contains(&out, b"unreachable-marker"));
    assert!(!contains(&out, b"chained-marker"));
    let saved = open(&out);
    // Catalog, page tree, page, content stream, font.
    assert_eq!(saved.object_ids().len(), 5);
    assert_eq!(graph_diff(&store, &saved), None);

    // Without garbage collection both stay.
    let out = store.save(&SaveOptions::default().with_gc(false)).unwrap();
    assert!(contains(&out, b"unreachable-marker"));
    assert!(contains(&out, b"chained-marker"));
    assert_eq!(open(&out).object_ids().len(), 7);

    // A freed object disappears; the reference to it becomes null.
    let mut store = open(&syntax::minimal());
    store.free(ObjectId::new(5, 0)).unwrap();
    let saved = open(&store.save(&SaveOptions::default()).unwrap());
    assert_eq!(saved.object_ids().len(), 4);
    assert_eq!(graph_diff(&store, &saved), None);

    // The source's structure is not copied, even without garbage collection: the object
    // stream and the cross-reference stream of `objstm` are rebuilt, not kept.
    let store = open(&syntax::objstm());
    let out = store.save(&SaveOptions::default().with_gc(false)).unwrap();
    let saved = open(&out);
    let count = |ty: &[u8]| {
        saved
            .object_ids()
            .into_iter()
            .filter(|&id| {
                let obj = saved.resolve(id).unwrap();
                obj.as_stream().is_some_and(|s| s.dict.is_type(ty))
            })
            .count()
    };
    // Only the output's own cross-reference stream, which lists itself.
    assert_eq!(count(b"XRef"), 1);
    assert_eq!(count(b"ObjStm"), 0);
    assert_eq!(graph_diff(&store, &saved), None);
    // An indirect /Length is not kept for its own sake.
    let store = open(&syntax::length_indirect_cycle());
    let lengths_before = store.object_ids().len();
    let saved = open(&store.save(&SaveOptions::default()).unwrap());
    assert!(saved.object_ids().len() < lengths_before);
    assert_eq!(graph_diff(&store, &saved), None);
}

#[test]
fn deterministic_save_is_byte_stable() {
    let options = [
        SaveOptions::default().with_deterministic(true),
        SaveOptions::default()
            .with_deterministic(true)
            .with_object_streams(true),
        SaveOptions::default()
            .with_deterministic(true)
            .with_compress(StreamCompression::Recompress),
        SaveOptions::default()
            .with_deterministic(true)
            .with_renumber(false)
            .with_gc(false),
    ];
    let incremental = IncrementalOptions::default().with_deterministic(true);
    for (name, bytes) in fixtures() {
        let edit = |store: &mut Store| {
            set_title(store, "stable");
            let mut content = Dict::new();
            content.insert("Note", Object::literal_string("added"));
            let stream = folioxide_syntax::Stream::new(
                content,
                StreamData::Decoded(b"BT /F1 12 Tf (x) Tj ET".to_vec()),
            );
            store.add(stream.into()).unwrap();
        };
        let (Ok(mut first), Ok(mut second)) = (
            Store::open_bytes(bytes.clone(), &OpenOptions::default()),
            Store::open_bytes(bytes.clone(), &OpenOptions::default()),
        ) else {
            continue;
        };
        edit(&mut first);
        edit(&mut second);
        for opts in &options {
            let a = first.save(opts).unwrap();
            let b = second.save(opts).unwrap();
            assert!(a == b, "{name}: {opts:?}");
            // Saving again from the same store gives the same bytes too.
            assert!(first.save(opts).unwrap() == a, "{name}: {opts:?}");
        }
        if appendable(&first) {
            let a = first.save_incremental(&incremental).unwrap();
            let b = second.save_incremental(&incremental).unwrap();
            assert!(a == b, "{name}: incremental");
        }
    }

    // The generated identifiers are content digests: a different edit gives another one.
    let ids = |title_text: &str| {
        let mut store = open(&syntax::minimal());
        set_title(&mut store, title_text);
        let saved = open(&store.save(&SaveOptions::default()).unwrap());
        saved.trailer().get(keys::ID).cloned().unwrap()
    };
    assert_eq!(ids("one"), ids("one"));
    assert_ne!(ids("one"), ids("two"));
}

#[test]
fn free_entry_generation_bumped() {
    // A table revision: freeing 5 0 R writes `5 1 f`.
    let mut store = open(&syntax::minimal());
    store.free(ObjectId::new(5, 0)).unwrap();
    assert_eq!(store.generation_of(5), Some(1));
    assert!(!store.contains(ObjectId::new(5, 0)));
    assert!(store.resolve(ObjectId::new(5, 0)).unwrap().is_null());
    let out = store
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    assert_eq!(
        newest_entries(&out).get(&5),
        Some(&XrefEntry::Free { r#gen: 1 })
    );
    let reopened = open(&out);
    assert!(reopened.resolve(ObjectId::new(5, 0)).unwrap().is_null());
    assert!(!reopened.object_ids().contains(&ObjectId::new(5, 0)));
    assert!(
        reopened.diagnostics().is_empty(),
        "{:?}",
        reopened.diagnostics()
    );

    // A stream revision: a type 0 entry with generation 1.
    let mut store = open(&syntax::xref_stream());
    store.free(ObjectId::new(5, 0)).unwrap();
    let out = store
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    assert_eq!(
        newest_entries(&out).get(&5),
        Some(&XrefEntry::Free { r#gen: 1 })
    );

    // An object of generation 3 gets 4; one of generation 65535 keeps 65535 (never reused).
    let mut b = PdfBuilder::new();
    b.header("1.4");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R /Extra 5 0 R >>")
        .obj(2, 0, "<< /Type /Pages /Kids [] /Count 0 >>")
        .obj(3, 3, "(three)")
        .obj(4, 65535, "(last)")
        .obj(5, 0, "(five)");
    b.xref_table(Default::default());
    let trailer = format!("/Size {} /Root 1 0 R", b.size());
    b.trailer(trailer).startxref(None).eof();
    let bytes = b.build();
    let mut store = open(&bytes);
    assert!(appendable(&store), "{:?}", store.diagnostics());
    assert_eq!(store.generation_of(4), Some(65535));
    store.free(ObjectId::new(3, 3)).unwrap();
    store.free(ObjectId::new(4, 65535)).unwrap();
    assert_eq!(store.generation_of(3), Some(4));
    assert_eq!(store.generation_of(4), Some(65535));
    let out = store
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    let entries = newest_entries(&out);
    assert_eq!(entries.get(&3), Some(&XrefEntry::Free { r#gen: 4 }));
    assert_eq!(entries.get(&4), Some(&XrefEntry::Free { r#gen: 65535 }));
    // The free list: 0 → 3 → 4 → 0.
    let suffix = &out[bytes.len()..];
    let text = String::from_utf8_lossy(suffix);
    assert!(text.contains("0000000003 65535 f\r\n"), "{text}");
    assert!(text.contains("0000000004 00004 f\r\n"), "{text}");
    assert!(text.contains("0000000000 65535 f\r\n"), "{text}");
    // A full save without renumbering keeps the bumped generations for the freed numbers.
    let full = store
        .save(&SaveOptions::default().with_renumber(false))
        .unwrap();
    let entries = newest_entries(&full);
    assert_eq!(entries.get(&3), Some(&XrefEntry::Free { r#gen: 4 }));
    assert_eq!(entries.get(&4), Some(&XrefEntry::Free { r#gen: 65535 }));
    assert!(matches!(
        entries.get(&5),
        Some(XrefEntry::InFile { r#gen: 0, .. })
    ));
    let text = String::from_utf8_lossy(&full);
    assert!(text.contains("xref\n0 6\n0000000003 65535 f\r\n"), "{text}");
}

#[test]
fn xref_table_zero_indexed() {
    let section = |bytes: &[u8]| -> String {
        let store = open(bytes);
        let last = store.revisions().last().unwrap();
        let pos = (store.header_offset() + last.startxref) as usize;
        String::from_utf8_lossy(&bytes[pos..]).into_owned()
    };
    // A full save: one subsection from 0, with object 0 at the head of the free list.
    for (name, _, store) in openable() {
        let out = store
            .save(&SaveOptions::default().with_xref(XrefStyle::Table))
            .unwrap();
        let text = section(&out);
        let size = store_size(&out);
        assert!(
            text.starts_with(&format!("xref\n0 {size}\n0000000000 65535 f\r\n")),
            "{name}: {}",
            &text[..40]
        );
        assert_eq!(text.matches(" n\r\n").count() as u32, size - 1, "{name}");
    }
    // An incremental update after a table: the first subsection is `0 1` (or `0 N` when object 1
    // changed too), even though object 0 did not change.
    let mut store = open(&syntax::multi_revision());
    set_title(&mut store, "zero");
    let out = store
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    let text = section(&out);
    assert!(
        text.starts_with("xref\n0 1\n0000000000 65535 f\r\n"),
        "{text}"
    );
    // Every entry is 20 bytes.
    let table = &text[text.find('\n').unwrap() + 1..text.find("trailer").unwrap()];
    for line in table.split_inclusive('\n') {
        let fields = line.split(' ').count();
        if fields == 3 {
            assert_eq!(line.len(), 20, "{line:?}");
        }
    }
}

/// The trailer `/Size` of the newest revision of `bytes`.
fn store_size(bytes: &[u8]) -> u32 {
    let store = open(bytes);
    u32::try_from(store.trailer().get_int(keys::SIZE).unwrap()).unwrap()
}

#[test]
fn edited_stream_decoded_is_flate_encoded() {
    let plain = b"BT /F1 24 Tf 72 720 Td (edited content) Tj ET".to_vec();
    let edit = |store: &mut Store| {
        let content = ObjectId::new(4, 0);
        let mut dict = Dict::new();
        // A stale filter: the writer replaces it.
        dict.insert(keys::FILTER, Object::name("ASCIIHexDecode"));
        dict.insert(keys::LENGTH, 1);
        let stream = folioxide_syntax::Stream::new(dict, StreamData::Decoded(plain.clone()));
        store.set(content, stream.into()).unwrap();
        // The edit reads back as it was given.
        let read = store.resolve(content).unwrap();
        assert_eq!(
            store.stream_data(read.as_stream().unwrap()).unwrap().data,
            plain
        );
    };
    let check = |bytes: &[u8], content: ObjectId, flate: bool| {
        let store = open(bytes);
        let obj = store.resolve(content).unwrap();
        let stream = obj.as_stream().unwrap();
        let raw = store.raw_stream_data(stream).unwrap();
        if flate {
            assert!(
                stream
                    .dict
                    .get_name(keys::FILTER)
                    .is_some_and(|f| f == "FlateDecode")
            );
            assert_ne!(&*raw, &plain[..]);
        } else {
            assert!(!stream.dict.contains_key(keys::FILTER));
            assert_eq!(&*raw, &plain[..]);
        }
        assert!(!stream.dict.contains_key(keys::DECODE_PARMS));
        assert_eq!(stream.dict.get_int(keys::LENGTH), Some(raw.len() as i64));
        assert_eq!(store.stream_data(stream).unwrap().data, plain);
        assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
    };
    // Incremental: the object keeps its number.
    let mut store = open(&syntax::minimal());
    edit(&mut store);
    let out = store
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    check(&out, ObjectId::new(4, 0), true);
    // Full save: the content stream is object 4 after renumbering too (catalog, pages, page,
    // then the page's entries in order: /Resources' font comes first, then /Contents).
    let out = store.save(&SaveOptions::default()).unwrap();
    let saved = open(&out);
    let page = saved
        .deref(
            &saved
                .resolve(saved.root_id().unwrap())
                .unwrap()
                .as_dict()
                .unwrap()
                .get(keys::PAGES)
                .cloned()
                .unwrap(),
        )
        .unwrap()
        .as_dict()
        .unwrap()
        .get_array(keys::KIDS)
        .unwrap()[0]
        .as_ref()
        .unwrap();
    let content = saved
        .resolve(page)
        .unwrap()
        .as_dict()
        .unwrap()
        .get_ref(keys::CONTENTS)
        .unwrap();
    check(&out, content, true);
    // Keep: written unfiltered.
    let out = store
        .save(&SaveOptions::default().with_compress(StreamCompression::Keep))
        .unwrap();
    check(&out, content, false);
}

// ---- hardening (M2 brief WP2.4) -----------------------------------------------------------------

/// Checks what [`IncrementalUpdate`] reports against the file it makes (`out`, reopened as
/// `reopened`): the positions M3 builds its `/ByteRange` on are absolute and exact.
fn check_update_positions(
    name: &str,
    source: &[u8],
    update: &IncrementalUpdate,
    out: &[u8],
    reopened: &Store,
) {
    assert_eq!(update.start, source.len() as u64, "{name}");
    assert_eq!(out.len() as u64, update.start + update.bytes.len() as u64);
    assert!(
        out.starts_with(source) && out.ends_with(&update.bytes),
        "{name}"
    );
    let last = reopened.revisions().len() - 1;
    let revision = &reopened.revisions()[last];
    let entries: HashMap<u32, XrefEntry> = reopened
        .revision_entries(last)
        .unwrap()
        .into_iter()
        .collect();
    let xref_pos = update.xref_pos.unwrap();
    let mut previous_end = update.start;
    for (id, range) in &update.objects {
        // In order, inside the update, before its cross-reference section.
        assert!(
            range.start >= previous_end && range.end <= xref_pos,
            "{name}: {id}"
        );
        previous_end = range.end;
        let text = &out[range.start as usize..range.end as usize];
        let header = format!("{} {} obj", id.num, id.r#gen);
        assert!(text.starts_with(header.as_bytes()), "{name}: {id}");
        assert!(text.ends_with(b"endobj\n"), "{name}: {id}");
        // The new section points at exactly that position (absolute in the store).
        assert_eq!(
            entries.get(&id.num),
            Some(&XrefEntry::InFile {
                pos: range.start,
                r#gen: id.r#gen
            }),
            "{name}: {id}"
        );
    }
    // The section: where `startxref` says (in the file's offset base), of the reported kind.
    let base = match reopened.offset_base() {
        OffsetBase::Absolute => 0,
        _ => reopened.header_offset(),
    };
    assert_eq!(revision.startxref + base, xref_pos, "{name}");
    assert_eq!(Some(revision.xref_kind), update.xref_kind, "{name}");
    assert!(revision.section_end > xref_pos, "{name}");
    assert!(revision.section_end <= revision.eof_end, "{name}");
    // The new revision ends where the file does.
    assert_eq!(revision.eof_end, out.len() as u64, "{name}");
}

#[test]
fn incremental_updates_chain_on_every_fixture() {
    // Three updates in a row on every appendable fixture, as sequential signatures (M3) make
    // them: (1) a new dictionary linked from the catalog and a new title, (2) that dictionary
    // edited and a new stream (decoded data, Flate-encoded by the writer) linked from it, (3)
    // both unlinked and freed. Each update keeps its source byte for byte, adds one revision,
    // reports exact positions, means what the edited store meant (same numbers), and reads
    // without a repair or a new kind of diagnostic.
    let mut chained = Vec::new();
    for (name, bytes, mut store) in openable() {
        if !appendable(&store) {
            continue;
        }
        let root = store.root_id().unwrap();
        let mut current = bytes;
        let mut added: Vec<ObjectId> = Vec::new();
        for round in 0..3 {
            match round {
                0 => {
                    set_title(&mut store, &format!("{name}, round 1"));
                    let mut dict = Dict::new();
                    dict.insert("Round", 1);
                    let id = store.add(dict.into()).unwrap();
                    store
                        .get_mut(root)
                        .unwrap()
                        .as_dict_mut()
                        .unwrap()
                        .insert("FolioxideTest", id);
                    added.push(id);
                }
                1 => {
                    let stream = folioxide_syntax::Stream::new(
                        Dict::new(),
                        StreamData::Decoded(b"round 2 data ".repeat(20)),
                    );
                    let stream = store.add(stream.into()).unwrap();
                    let dict = store.get_mut(added[0]).unwrap().as_dict_mut().unwrap();
                    dict.insert("Round", 2);
                    dict.insert("Data", stream);
                    added.push(stream);
                }
                _ => {
                    store
                        .get_mut(root)
                        .unwrap()
                        .as_dict_mut()
                        .unwrap()
                        .remove(b"FolioxideTest");
                    for &id in &added {
                        store.free(id).unwrap();
                    }
                }
            }
            let revisions = store.revisions().len();
            let pages = page_count(&store);
            let update = store
                .incremental_update(&IncrementalOptions::default())
                .unwrap_or_else(|err| panic!("{name} round {round}: {err}"));
            let out = [current.as_slice(), &update.bytes].concat();
            let reopened = open(&out);
            let label = format!("{name} round {round}");
            check_update_positions(&label, &current, &update, &out, &reopened);
            assert_eq!(reopened.revisions().len(), revisions + 1, "{label}");
            assert!(!reopened.structure_repaired(), "{label}");
            assert_eq!(page_count(&reopened), pages, "{label}");
            let same = GraphOptions::default().with_same_numbers(true);
            let comparison = compare_graphs(&store, &reopened, &same);
            assert!(comparison.is_equal(), "{label}: {comparison}");
            let new_kinds: BTreeSet<String> = diagnostic_kinds(&reopened)
                .difference(&diagnostic_kinds(&store))
                .cloned()
                .collect();
            assert!(new_kinds.is_empty(), "{label}: {new_kinds:?}");
            current = out;
            store = reopened;
        }
        // The freed numbers have free entries with the next generation, and are not reused.
        let last = store.revisions().len() - 1;
        let entries: HashMap<u32, XrefEntry> =
            store.revision_entries(last).unwrap().into_iter().collect();
        for id in &added {
            assert_eq!(
                entries.get(&id.num),
                Some(&XrefEntry::Free { r#gen: 1 }),
                "{name}: {id}"
            );
            assert!(store.resolve(*id).unwrap().is_null());
        }
        let next = store.add(Object::Null).unwrap();
        assert!(added.iter().all(|id| next.num > id.num), "{name}");
        chained.push(name);
    }
    assert!(chained.len() >= 20, "{chained:?}");
}

#[test]
fn next_object_number_is_above_every_listed_number() {
    // M3 numbers its signature objects from `next_object_number()`: never a number any section
    // lists (free entries included, a hybrid's hidden stream entries too), never a number an
    // object refers to (a dangling reference must keep meaning null), never a number reused.
    let mut dangling = Vec::new();
    for (name, _, mut store) in openable() {
        let next = store.next_object_number();
        assert!(next > store.max_object_number(), "{name}");
        for k in 0..store.revisions().len() {
            let Ok(entries) = store.revision_entries(k) else {
                continue;
            };
            for (num, _) in entries {
                assert!(
                    num < next,
                    "{name}: revision {k} lists {num}, next is {next}"
                );
            }
        }
        let mut referenced = 0;
        for id in store.object_ids() {
            assert!(id.num < next, "{name}");
            let object = store.resolve(id).unwrap();
            let mut stack: Vec<&Object> = vec![&object];
            while let Some(obj) = stack.pop() {
                match obj {
                    Object::Ref(r) => referenced = referenced.max(r.num),
                    Object::Array(items) => stack.extend(items),
                    Object::Dict(dict) => stack.extend(dict.values()),
                    Object::Stream(s) => stack.extend(s.dict.values()),
                    _ => {}
                }
            }
        }
        assert!(
            referenced < next,
            "{name}: {referenced} is referenced, next is {next}"
        );
        if next > store.max_object_number() + 1 {
            dangling.push(name.clone());
        }
        let added = store.add(Object::Null).unwrap();
        assert_eq!(added, ObjectId::new(next, 0), "{name}");
        store.free(added).unwrap();
        assert_eq!(store.next_object_number(), next + 1, "{name}");
        assert_eq!(store.add(Object::Null).unwrap().num, next + 1, "{name}");
    }
    // The page tree of `wrong_count` lists the missing object 8 among its kids: a new object
    // must not become a page.
    assert!(
        dangling.contains(&"model-wrong-count".to_owned()),
        "{dangling:?}"
    );
    let mut store = open(&model::wrong_count());
    assert_eq!(store.max_object_number(), 7);
    let pages = page_count(&store);
    set_title(&mut store, "not a page");
    assert_eq!(
        store.trailer().get_ref(keys::INFO),
        Some(ObjectId::new(9, 0))
    );
    assert_eq!(page_count(&store), pages);
    let reopened = open(
        &store
            .save_incremental(&IncrementalOptions::default())
            .unwrap(),
    );
    assert!(reopened.resolve(ObjectId::new(8, 0)).unwrap().is_null());
}

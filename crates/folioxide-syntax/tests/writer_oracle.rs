#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Oracle suite `writer` (M2 brief WP2.4, acceptance criterion 4).
//!
//! Every fixture that opens (the committed syntax fixtures, the linearized files qpdf wrote, and
//! the document-model fixtures generated at test time) gets a new `/Title` and is saved; each
//! output becomes the oracle case `target/oracle/writer/<case>.pdf` plus `<case>.expect.json`
//! when the tests are built with the `folioxide-testkit/emit` feature (`cargo xtask oracle
//! --suite writer`). Without the feature the test still builds every case and checks every
//! expectation with our own reader, and writes nothing.
//!
//! - `<fixture>-full`: a full save with the default options; `<fixture>-objstm`: a full save
//!   with object streams (and so a cross-reference stream).
//! - `<fixture>-incr`: an incremental update, for every fixture that takes one
//!   ([`Store::check_incremental`]: not reconstructed, structure not repaired, every object at
//!   its offset); `<fixture>-incr2`, for a few, a second update on top of the first, as
//!   sequential signatures make them.
//! - `new-document` and `new-document-objstm`: a document built from nothing
//!   ([`Store::new_empty`]).
//!
//! Every case expects `pages` (our page walk, which the writer must not change), `version`,
//! `info.Title` (a UTF-16BE text string, so the oracles decode it, §7.9.2.2) and, except for
//! the model fixtures, `objectCount` (as in the `syntax` suite; qpdf adds objects when it
//! materializes inherited page attributes or repairs a page without `/Resources`, which every
//! model fixture needs); every incremental case also expects `prefixOf` (its source: a
//! committed fixture, or a supporting file written next to the case) and `revisions` (the
//! source's plus one). The runner also checks the structure of every case with pdfinfo,
//! pikepdf/qpdf (`check_pdf_syntax`, warnings included) and pypdf in strict mode.
//!
//! A check that fails because of what the *source* holds is listed under `knownFailures` with
//! the reason ([`known_failures`]): it still runs, and the entry fails as soon as the check
//! passes. Every such failure was checked against the source itself, which fails the same
//! check: damage an incremental update keeps by design (truncated Flate data, a wrong
//! `/Length`, a `/Length` cycle, an object stream qpdf cannot read), an oracle's limitation on
//! the source's own layout (pypdf on update sections that do not start at object 0 and on bytes
//! before the header, a linearized file without a first-page `startxref`), and the model
//! fixtures' deliberately broken page trees and pages without `/Resources`. No case is skipped.

use std::collections::BTreeMap;

use folioxide_syntax::{
    Dict, IncrementalOptions, Object, OpenOptions, PdfString, SaveOptions, Store, keys,
};
use folioxide_testkit::exercise::page_count;
use folioxide_testkit::fixtures::{model, qpdf, syntax};
use folioxide_testkit::{EMIT_ENABLED, ExpectJson, emit::emit_file, emit_case};

/// The oracle suite name.
const SUITE: &str = "writer";

/// The acceptance criterion: at least this many cases are checked rather than skipped.
const MIN_CHECKED: usize = 15;

/// A fixture the suite saves.
struct Fixture {
    name: String,
    bytes: Vec<u8>,
    /// The committed file, relative to the repository root (`prefixOf` names it); `None` for a
    /// fixture generated at test time, whose bytes are written next to its cases instead.
    committed: Option<String>,
}

/// Every fixture: the committed syntax fixtures, the qpdf ones as `qpdf-<name>`, and the
/// document-model fixtures as `model-<name>`.
fn fixtures() -> Vec<Fixture> {
    let mut all: Vec<Fixture> = syntax::infos()
        .iter()
        .map(|info| Fixture {
            name: info.name.to_owned(),
            bytes: syntax::read_committed(info.name).unwrap_or_else(|err| {
                panic!(
                    "fixtures/syntax/{}.pdf: {err} (run `cargo xtask fixtures`)",
                    info.name
                )
            }),
            committed: Some(format!("fixtures/syntax/{}.pdf", info.name)),
        })
        .collect();
    for info in qpdf::infos() {
        all.push(Fixture {
            name: format!("qpdf-{}", info.name),
            bytes: qpdf::read_committed(info.name).unwrap(),
            committed: Some(format!("fixtures/qpdf/{}.pdf", info.name)),
        });
    }
    for (name, bytes) in [
        ("model-inherited-attributes", model::inherited_attributes()),
        ("model-rotations", model::rotations()),
        ("model-page-tree-cycle", model::page_tree_cycle()),
        ("model-wrong-count", model::wrong_count()),
        ("model-deep-page-tree", model::deep_page_tree(8)),
        ("model-trees", model::trees()),
        ("model-info-strings", model::info_strings()),
    ] {
        all.push(Fixture {
            name: name.to_owned(),
            bytes,
            committed: None,
        });
    }
    all
}

/// The fixtures whose incremental output gets a second update on top (`<fixture>-incr2`): one
/// per kind of newest section (table, stream, hybrid), several revisions, and Info strings.
const CHAINED: [&str; 5] = [
    "minimal",
    "multi-revision",
    "xref-stream",
    "hybrid",
    "model-info-strings",
];

/// Checks the oracle runner expects to fail for `case`, with the reason. Every reason is a
/// property of the source that the output keeps, not of what the writer adds.
fn known_failures(case: &str) -> Vec<(&'static str, &'static str)> {
    const NOT_ZERO_INDEXED: &str = "pypdf 6 strict mode warns 'Xref table not zero-indexed' for \
        the source's own update sections, whose first subsection does not start at 0 (ISO \
        32000-2 §7.5.6 allows it; the syntax suite lists the same failure for the source); an \
        incremental update keeps those sections byte for byte, and its own section starts at 0";
    const LINEARIZED_TABLE: &str = "pypdf 6 strict mode warns 'Xref table not zero-indexed' for \
        the source's first-page cross-reference table, whose only subsection starts at the \
        linearization dictionary's number (Annex F; the syntax suite lists the same failure for \
        the source); an incremental update keeps it byte for byte";
    const LINEARIZED_STREAM: &str = "qpdf writes no startxref after the first-page \
        cross-reference stream of a linearized file (Annex F.3.3), so counting startxref \
        keywords finds one revision fewer than the file has; pyHanko, pikepdf and our reader \
        count the first-page section as a revision";
    const JUNK: &str = "the source has bytes before %PDF- (ISO 32000-2 Annex H, accepted by \
        pikepdf/qpdf and poppler), which an incremental update keeps byte for byte: pypdf's \
        strict mode refuses them and reads the version from the junk, and pyHanko refuses the \
        header";
    const TRUNCATED_FLATE: &str = "the source's content stream holds truncated Flate data, which \
        the writer copies as encoded without decoding it (§A.3 rule: source streams are never \
        re-encoded, and truncated data is never recompressed): qpdf warns when it decodes it, as \
        it does for the source";
    const DAMAGED: &str = "the source is damaged (not oracle-clean in the syntax suite) and an \
        incremental update never rewrites it: the oracles repair the source part as they repair \
        the source itself; a full save is the way to a clean file (its case passes)";
    const NO_RESOURCES: &str = "the source's pages have no /Resources, which ISO 32000-2 \
        §7.7.3.3 Table 31 requires (the model fixtures leave it out): qpdf repairs every such \
        page with a warning, for the source as well; the writer keeps page dictionaries as they \
        are";
    const PAGE_TREE_CYCLE: &str = "the source's page tree is cyclic on purpose (model fixture \
        page_tree_cycle: a node lists the root and itself among its kids): qpdf refuses the loop \
        in every operation and pypdf raises, for the source as well; the writer keeps the page \
        tree as it is (pdfinfo and our reader count its two pages)";
    const WRONG_COUNT: &str = "the source's page tree is wrong on purpose (model fixture \
        wrong_count: /Count 7 for three leaves, one of them without /Type, and a font, a missing \
        object and an integer among the kids): pdfinfo trusts /Count (7), pypdf counts 3, qpdf \
        refuses the missing kid, and our page walk counts the two typed leaves; the same \
        happens with the source, and the writer keeps the page tree as it is";
    const UNREADABLE: &str = "qpdf and poppler cannot read the source at all (its object \
        stream claims /N 1000 members, so they find no catalog), and pypdf's strict mode refuses \
        the /N; an incremental update keeps the source byte for byte, so they cannot read the \
        update either (prefixOf and revisions still pass); the full saves of this fixture are \
        clean";
    let incremental = case.ends_with("-incr") || case.ends_with("-incr2");
    let fixture = case
        .strip_suffix("-incr2")
        .or_else(|| case.strip_suffix("-incr"))
        .or_else(|| case.strip_suffix("-objstm"))
        .or_else(|| case.strip_suffix("-full"))
        .unwrap_or(case);
    match (fixture, incremental) {
        ("multi-revision", true) => vec![("structure.pypdf", NOT_ZERO_INDEXED)],
        ("qpdf-linearized", true) => vec![("structure.pypdf", LINEARIZED_TABLE)],
        ("qpdf-linearized-objstm", true) => vec![("revisions.startxref", LINEARIZED_STREAM)],
        ("junk-before-header", true) => vec![
            ("structure.pypdf", JUNK),
            ("version.pypdf", JUNK),
            ("revisions.pyhanko", JUNK),
        ],
        ("flate-truncated", _) => vec![("structure.pikepdf", TRUNCATED_FLATE)],
        ("stream-length-wrong", true) => {
            vec![("structure.pikepdf", DAMAGED), ("structure.pypdf", DAMAGED)]
        }
        ("length-indirect-cycle", true) => {
            vec![("structure.pikepdf", DAMAGED), ("structure.pypdf", DAMAGED)]
        }
        ("objstm-n-too-large", true) => [
            "structure.pdfinfo",
            "structure.pikepdf",
            "structure.pypdf",
            "pages.pdfinfo",
            "pages.pikepdf",
            "version.pdfinfo",
            "version.pikepdf",
            "objectCount.pikepdf",
            "info.Title.pdfinfo",
            "info.pikepdf",
        ]
        .into_iter()
        .map(|check| (check, UNREADABLE))
        .collect(),
        ("model-rotations" | "model-trees" | "model-info-strings" | "model-deep-page-tree", _) => {
            vec![("structure.pikepdf", NO_RESOURCES)]
        }
        ("model-page-tree-cycle", _) => [
            "structure.pikepdf",
            "structure.pypdf",
            "pages.pikepdf",
            "pages.pypdf",
            "version.pikepdf",
            "info.pikepdf",
        ]
        .into_iter()
        .map(|check| (check, PAGE_TREE_CYCLE))
        .collect(),
        ("model-wrong-count", _) => [
            "structure.pikepdf",
            "structure.pypdf",
            "pages.pdfinfo",
            "pages.pikepdf",
            "pages.pypdf",
            "version.pikepdf",
            "info.pikepdf",
        ]
        .into_iter()
        .map(|check| (check, WRONG_COUNT))
        .collect(),
        _ => Vec::new(),
    }
}

/// `text` as a text string (§7.9.2.2): UTF-16BE with a byte order mark, so every oracle has to
/// decode it.
fn text_string(text: &str) -> Object {
    let mut bytes = vec![0xFE, 0xFF];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_be_bytes());
    }
    Object::String(PdfString::new_hex(bytes))
}

/// The title a case's document gets.
fn title_for(case: &str) -> String {
    format!("Folioxide {case} \u{2013} Grüße 日本")
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
                .insert("Title", text_string(title));
        }
        None => {
            let mut dict = Dict::new();
            dict.insert("Title", text_string(title));
            let id = store.add(dict.into()).unwrap();
            store.set_trailer_entry(keys::INFO, id.into()).unwrap();
        }
    }
}

/// Whether an incremental update may be appended to `store` (a revision structure that other
/// readers resolve the same way, [`Store::check_incremental`]).
fn appendable(store: &Store) -> bool {
    store.check_incremental().is_ok()
}

fn open(bytes: &[u8]) -> Store {
    Store::open_bytes(bytes.to_vec(), &OpenOptions::default()).unwrap()
}

/// The version a reader takes: the header's, or the catalog's `/Version` when it is higher
/// (§7.7.2).
fn effective_version(store: &Store) -> String {
    let header = store.version();
    let catalog = store
        .resolve(store.root_id().unwrap())
        .unwrap()
        .as_dict()
        .and_then(|d| {
            d.get_name(keys::VERSION)
                .and_then(|n| n.as_str().map(str::to_owned))
        })
        .and_then(|v| {
            let (major, minor) = v.split_once('.')?;
            Some((major.parse::<u8>().ok()?, minor.parse::<u8>().ok()?))
        });
    let (major, minor) = catalog.map_or(header, |c| c.max(header));
    format!("{major}.{minor}")
}

/// `objectCount`: the in-use objects that resolve to a non-null object (see the `syntax`
/// suite and `tools/oracles/check_pdf.py`).
fn object_count(store: &Store) -> usize {
    store
        .object_ids()
        .into_iter()
        .filter(|&id| store.resolve(id).is_ok_and(|obj| !obj.is_null()))
        .count()
}

/// One oracle case.
struct Case {
    name: String,
    pdf: Vec<u8>,
    expect: ExpectJson,
}

/// The expectations every case has, read from the output with our reader, after checking that
/// the output shows `pages` pages and `title`; `objectCount` with `count_objects`.
fn expectation(
    case: &str,
    out: &[u8],
    pages: Option<u32>,
    title: &str,
    count_objects: bool,
) -> ExpectJson {
    let saved = open(out);
    assert!(!saved.structure_repaired(), "{case}");
    assert_eq!(page_count(&saved), pages, "{case}: pages");
    let info = saved
        .deref(saved.trailer().get(keys::INFO).unwrap())
        .unwrap();
    let raw = info.as_dict().unwrap().get_str_bytes(b"Title").unwrap();
    assert_eq!(raw, text_bytes(title), "{case}: title");
    let mut expect = ExpectJson::new()
        .int("pages", i64::from(pages.unwrap_or(0)))
        .string("version", &effective_version(&saved))
        .raw(
            "info",
            format!(
                "{{\"Title\": {}}}",
                folioxide_testkit::emit::json_string(title)
            ),
        );
    if count_objects {
        expect = expect.int("objectCount", object_count(&saved) as i64);
    }
    let known = known_failures(case);
    if !known.is_empty() {
        expect = expect.string_map("knownFailures", &known);
    }
    expect
}

/// The bytes of [`text_string`]`(text)`.
fn text_bytes(text: &str) -> Vec<u8> {
    match text_string(text) {
        Object::String(s) => s.bytes,
        _ => unreachable!(),
    }
}

/// Every case of the suite, and the supporting files (sources of incremental updates that are
/// not committed), by name.
fn cases() -> (Vec<Case>, BTreeMap<String, Vec<u8>>) {
    let mut cases = Vec::new();
    let mut files = BTreeMap::new();
    for fixture in fixtures() {
        let Ok(store) = Store::open_bytes(fixture.bytes.clone(), &OpenOptions::default()) else {
            continue;
        };
        let pages = page_count(&store);
        // qpdf materializes inherited page attributes, and repairs pages without /Resources,
        // as new objects when it reads the page tree, so it counts more objects than the model
        // fixtures (all of whose page trees need one or the other) hold.
        let count_objects = fixture.committed.is_some();
        for (suffix, opts) in [
            ("full", SaveOptions::default()),
            ("objstm", SaveOptions::default().with_object_streams(true)),
        ] {
            let case = format!("{}-{suffix}", fixture.name);
            let mut edited = open(&fixture.bytes);
            let title = title_for(&case);
            set_title(&mut edited, &title);
            let pdf = edited
                .save(&opts)
                .unwrap_or_else(|err| panic!("{case}: {err}"));
            let expect = expectation(&case, &pdf, pages, &title, count_objects);
            cases.push(Case {
                name: case,
                pdf,
                expect,
            });
        }
        if !appendable(&store) {
            continue;
        }
        // The source of the first update: the committed file, or a supporting file.
        let source_path = match &fixture.committed {
            Some(path) => path.clone(),
            None => {
                let file = format!("{}.source.pdf", fixture.name);
                files.insert(file.clone(), fixture.bytes.clone());
                file
            }
        };
        let mut source = fixture.bytes.clone();
        let mut source_path = source_path;
        let rounds = if CHAINED.contains(&fixture.name.as_str()) {
            2
        } else {
            1
        };
        for round in 1..=rounds {
            let case = if round == 1 {
                format!("{}-incr", fixture.name)
            } else {
                format!("{}-incr{round}", fixture.name)
            };
            let mut edited = open(&source);
            let revisions = edited.revisions().len();
            let title = title_for(&case);
            set_title(&mut edited, &title);
            let pdf = edited
                .save_incremental(&IncrementalOptions::default())
                .unwrap_or_else(|err| panic!("{case}: {err}"));
            assert!(pdf.starts_with(&source), "{case}");
            assert_eq!(open(&pdf).revisions().len(), revisions + 1, "{case}");
            let expect = expectation(&case, &pdf, pages, &title, count_objects)
                .string("prefixOf", &source_path)
                .int("revisions", (revisions + 1) as i64);
            source.clone_from(&pdf);
            source_path = format!("{case}.pdf");
            cases.push(Case {
                name: case,
                pdf,
                expect,
            });
        }
    }
    // A document made from nothing: one page, saved with a table and with object streams.
    for (case, opts) in [
        ("new-document", SaveOptions::default()),
        (
            "new-document-objstm",
            SaveOptions::default().with_object_streams(true),
        ),
    ] {
        let mut store = new_document();
        let title = title_for(case);
        set_title(&mut store, &title);
        let pdf = store.save(&opts).unwrap();
        let expect = expectation(case, &pdf, Some(1), &title, true);
        cases.push(Case {
            name: case.to_owned(),
            pdf,
            expect,
        });
    }
    (cases, files)
}

/// A one-page US Letter document built with [`Store::new_empty`]: catalog, page tree, page, and
/// a content stream (decoded data, which the writer Flate-encodes).
fn new_document() -> Store {
    let mut store = Store::new_empty((1, 7));
    let content = folioxide_syntax::Stream::new(
        Dict::new(),
        folioxide_syntax::StreamData::Decoded(b"0 0 1 rg 72 72 144 144 re f".to_vec()),
    );
    let content = store.add(content.into()).unwrap();
    let pages = folioxide_syntax::ObjectId::new(store.next_object_number() + 1, 0);
    let mut page = Dict::new();
    page.insert(keys::TYPE, Object::name("Page"));
    page.insert(keys::PARENT, pages);
    page.insert(
        keys::MEDIA_BOX,
        Object::Array(vec![0.into(), 0.into(), 612.into(), 792.into()]),
    );
    page.insert(keys::CONTENTS, content);
    // Required (§7.7.3.3, Table 31); qpdf repairs a page without it, with a warning.
    page.insert(keys::RESOURCES, Dict::new());
    let page = store.add(page.into()).unwrap();
    let mut tree = Dict::new();
    tree.insert(keys::TYPE, Object::name("Pages"));
    tree.insert(keys::KIDS, Object::Array(vec![page.into()]));
    tree.insert(keys::COUNT, 1);
    assert_eq!(store.add(tree.into()).unwrap(), pages);
    let mut catalog = Dict::new();
    catalog.insert(keys::TYPE, Object::name("Catalog"));
    catalog.insert(keys::PAGES, pages);
    let catalog = store.add(catalog.into()).unwrap();
    store.set_trailer_entry(keys::ROOT, catalog.into()).unwrap();
    store
}

#[test]
fn writer_oracle_cases() {
    let (cases, files) = cases();
    let mut written = 0;
    for (name, bytes) in &files {
        emit_file(SUITE, name, bytes).unwrap_or_else(|err| panic!("{name}: {err}"));
    }
    for case in &cases {
        let written_to = emit_case(SUITE, &case.name, &case.pdf, &case.expect)
            .unwrap_or_else(|err| panic!("{}: {err}", case.name));
        if written_to.is_some() {
            written += 1;
        }
    }
    // No case is skipped.
    assert!(cases.iter().all(|c| c.expect.get("oracleSkip").is_none()));
    assert!(cases.len() >= MIN_CHECKED, "only {} cases", cases.len());
    assert_eq!(written, if EMIT_ENABLED { cases.len() } else { 0 });
}

#[test]
fn the_suite_covers_every_writer_path() {
    let (cases, files) = cases();
    let names: Vec<&str> = cases.iter().map(|c| c.name.as_str()).collect();
    // Full saves of every fixture that opens, damaged ones included; incremental updates of the
    // appendable ones, chained for a few; new documents.
    for name in [
        "minimal-full",
        "minimal-objstm",
        "missing-xref-full",
        "prev-loop-objstm",
        "qpdf-linearized-objstm-full",
        "model-trees-objstm",
        "minimal-incr",
        "minimal-incr2",
        "xref-stream-incr",
        "xref-stream-incr2",
        "hybrid-incr2",
        "multi-revision-incr2",
        "junk-before-header-incr",
        "qpdf-linearized-incr",
        "qpdf-linearized-objstm-incr",
        "model-info-strings-incr2",
        "new-document",
        "new-document-objstm",
    ] {
        assert!(names.contains(&name), "{name} is missing");
    }
    // Reconstructed and repaired files take no incremental update.
    assert!(!names.contains(&"missing-xref-incr"));
    assert!(!names.contains(&"startxref-off-by-n-incr"));
    let incremental: Vec<&Case> = cases
        .iter()
        .filter(|c| c.name.ends_with("-incr") || c.name.ends_with("-incr2"))
        .collect();
    assert!(incremental.len() >= 20, "{}", incremental.len());
    for case in &incremental {
        // Every incremental case names its source and its revision count.
        let prefix = case.expect.get("prefixOf").unwrap();
        let prefix = prefix.trim_matches('"');
        assert!(
            prefix.starts_with("fixtures/")
                || files.contains_key(prefix)
                || names.contains(&prefix.trim_end_matches(".pdf")),
            "{}: {prefix}",
            case.name
        );
        assert!(case.expect.get("revisions").is_some(), "{}", case.name);
    }
    // Every known failure belongs to a case of the suite.
    let with_known = cases
        .iter()
        .filter(|c| c.expect.get("knownFailures").is_some())
        .count();
    assert!(with_known <= 32, "{with_known}");
    // The titles are UTF-16BE text strings.
    assert_eq!(&text_bytes("A")[..], &[0xFE, 0xFF, 0x00, 0x41]);
}

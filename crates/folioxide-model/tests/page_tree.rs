#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The page tree and page attributes (ISO 32000-2 §7.7.3, §14.11.2; M2 brief AC3, ARCHITECTURE
//! §A.10 trap #10): inheritance, cycles, wrong `/Count`, rotation, boxes and limits.

mod common;

use common::{build, corners, diagnostics_with, open, open_strict};
use folioxide_model::{Document, PageId, Rect, Rotation};
use folioxide_syntax::{ErrorCode, Limits, ObjectId, OpenOptions, shared_bytes};
use folioxide_testkit::fixtures::{model, qpdf, syntax};

fn id(num: u32) -> ObjectId {
    ObjectId::new(num, 0)
}

fn page_numbers(doc: &Document) -> Vec<u32> {
    doc.page_ids()
        .unwrap()
        .into_iter()
        .map(|p| p.0.num)
        .collect()
}

fn font_names(doc: &Document, index: usize) -> Vec<String> {
    let resources = doc.page(index).unwrap().resources().unwrap().unwrap();
    let fonts = doc.store().deref(resources.get(b"Font").unwrap()).unwrap();
    fonts
        .as_dict()
        .unwrap()
        .keys()
        .map(|k| k.as_str().unwrap().to_owned())
        .collect()
}

/// `/MediaBox`, `/CropBox` and `/Rotate` come from the nearest ancestor that has them, one or
/// two levels up (§7.7.3.4).
#[test]
fn inherited_attributes() {
    let doc = open(model::inherited_attributes());
    assert_eq!(doc.page_count().unwrap(), model::INHERITED_PAGES.len());
    for (i, expected) in model::INHERITED_PAGES.iter().enumerate() {
        let page = doc.page(i).unwrap();
        assert_eq!(page.index(), i);
        assert_eq!(page.id(), PageId(id(expected.id)), "page {i}");
        assert_eq!(corners(page.media_box()), expected.media_box, "page {i}");
        assert_eq!(corners(page.crop_box()), expected.crop_box, "page {i}");
        assert_eq!(page.rotation().degrees(), expected.rotate, "page {i}");
    }

    // Page 0 has no attributes of its own: its media box is its grandparent's.
    let first = doc.page(0).unwrap();
    assert_eq!(first.ancestors(), &[id(3), id(2)]);
    let leaf = first.object().unwrap();
    assert!(leaf.as_dict().unwrap().get(b"MediaBox").is_none());
    assert_eq!(corners(first.media_box()), [0.0, 0.0, 595.0, 842.0]);
    // The crop box (575 x 790) turned a quarter: 790 wide, 575 high.
    assert_eq!(first.rotation(), Rotation::R90);
    assert_eq!(first.effective_size(), (790.0, 575.0));
    // Bleed, trim and art boxes default to the crop box.
    for r in [first.bleed_box(), first.trim_box(), first.art_box()] {
        assert_eq!(corners(r), [10.0, 10.0, 585.0, 800.0]);
    }

    // Page 1 overrides the media box and the rotation; the inherited crop box is clipped to
    // its own media box.
    let second = doc.page(1).unwrap();
    assert_eq!(second.ancestors(), &[id(3), id(2)]);
    assert_eq!(second.rotation(), Rotation::R0);
    assert_eq!(second.effective_size(), (575.0, 782.0));

    // Page 3: its own crop box is clipped to the media box; the bleed box too (to the media
    // box, not the crop box); the art box lies outside the media box and is ignored.
    let last = doc.page(3).unwrap();
    assert_eq!(last.ancestors(), &[id(10), id(2)]);
    assert_eq!(corners(last.bleed_box()), [0.0, 0.0, 310.0, 410.0]);
    assert_eq!(corners(last.trim_box()), [20.0, 20.0, 280.0, 380.0]);
    assert_eq!(corners(last.art_box()), [0.0, 0.0, 300.0, 400.0]);
    assert_eq!(last.effective_size(), (300.0, 400.0));

    // The tree is well formed: the only diagnostic is the art box.
    let diagnostics = doc.diagnostics();
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert!(
        diagnostics[0].message.contains("/ArtBox"),
        "{diagnostics:?}"
    );
}

/// `/Resources` is inherited too, also when the ancestor's value is an indirect object; the
/// nearest one wins (§7.7.3.4).
#[test]
fn inherited_resources() {
    let doc = open(model::inherited_attributes());
    for (i, expected) in model::INHERITED_PAGES.iter().enumerate() {
        assert_eq!(font_names(&doc, i), expected.fonts, "page {i}");
    }
    // Neither the page nor an ancestor has resources.
    let doc = open(model::rotations());
    assert_eq!(doc.page(0).unwrap().resources().unwrap(), None);

    // A /Resources that is not a dictionary is skipped in favour of the parent's, and so is a
    // reference to a missing object (null, §7.3.10).
    let pdf = build(
        "1.4",
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (
                2,
                "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 10 10] \
                 /Resources << /Font << /Root 5 0 R >> >> >>",
            ),
            (3, "<< /Type /Page /Parent 2 0 R /Resources /Oops >>"),
            (4, "<< /Type /Page /Parent 2 0 R /Resources 99 0 R >>"),
            (5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
        ],
        "",
    );
    let doc = open(pdf);
    assert_eq!(font_names(&doc, 0), ["Root"]);
    assert_eq!(font_names(&doc, 1), ["Root"]);
    assert_eq!(diagnostics_with(&doc, "/Resources").len(), 1);
}

/// A kid that leads back to an ancestor, or to itself, is skipped: every `/Pages` node is
/// walked once, so the walk ends, and reports it. A page listed twice is two pages.
#[test]
fn page_tree_cycle_detected() {
    for doc in [
        open(model::page_tree_cycle()),
        open_strict(model::page_tree_cycle()),
    ] {
        assert_eq!(page_numbers(&doc), [3, 5, 5]);
        assert_eq!(doc.page_count().unwrap(), 3);
        let repeats = diagnostics_with(&doc, "appears more than once");
        let message = |obj: &str| repeats.iter().any(|d| d.message.contains(obj));
        assert!(
            message("node 2 0 R") && message("node 4 0 R"),
            "{repeats:?}"
        );
        assert_eq!(repeats.len(), 2, "{repeats:?}");
        let listed = diagnostics_with(&doc, "listed more than once");
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert!(
            listed[0].message.contains("page 5 0 R")
                && listed[0].message.contains("page 2 as well as page 1"),
            "{listed:?}"
        );
        // The /Count values leave the second listing out.
        assert_eq!(diagnostics_with(&doc, "/Count").len(), 2);
        // Every page is readable.
        for i in 0..3 {
            assert_eq!(doc.page(i).unwrap().media_box(), Rect::US_LETTER);
        }
    }
}

/// A page listed more than once is a page each time (poppler, pypdf and qpdf count it so), with
/// a diagnostic; `/Pages` nodes stay walked once. Each listing inherits from the nodes above it
/// (§7.7.3.4); edits of the page object show at every index it has.
#[test]
fn repeated_page_is_a_page_each_time() {
    let doc = open_strict(model::repeated_page());
    assert_eq!(doc.page_count().unwrap(), 3);
    assert_eq!(page_numbers(&doc), model::REPEATED_PAGE_IDS);
    assert_eq!(doc.page(1).unwrap().id(), doc.page(0).unwrap().id());
    // The index of a page is its first listing.
    assert_eq!(doc.page_index(PageId(id(3))).unwrap(), Some(0));
    assert_eq!(doc.page_index(PageId(id(4))).unwrap(), Some(2));
    // /Count 3 is right; the only diagnostic is the repeat.
    let diagnostics = doc.diagnostics();
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert!(
        diagnostics[0]
            .message
            .contains("page 3 0 R is listed more than once"),
        "{diagnostics:?}"
    );
    for i in 0..2 {
        let page = doc.page(i).unwrap();
        assert_eq!(page.media_box(), Rect::US_LETTER);
        assert_eq!(page.rotation(), Rotation::R90);
    }
    assert_eq!(
        corners(doc.page(2).unwrap().media_box()),
        [0.0, 0.0, 300.0, 400.0]
    );

    // A page listed under two nodes inherits from each, as the walk reached it; a /Pages node
    // listed twice (here by node 4, then by the root) is walked once, where it is listed first.
    let pdf = build(
        "1.7",
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (
                2,
                "<< /Type /Pages /Kids [3 0 R 4 0 R 6 0 R] /Count 5 /MediaBox [0 0 612 792] >>",
            ),
            (3, "<< /Type /Page /Parent 2 0 R >>"),
            (
                4,
                "<< /Type /Pages /Parent 2 0 R /Kids [3 0 R 5 0 R 6 0 R] /Count 3 \
                 /MediaBox [0 0 595 842] /Rotate 90 >>",
            ),
            (5, "<< /Type /Page /Parent 4 0 R >>"),
            (
                6,
                "<< /Type /Pages /Parent 2 0 R /Kids [5 0 R] /Count 1 /Rotate 180 >>",
            ),
        ],
        "",
    );
    let doc = open(pdf);
    assert_eq!(page_numbers(&doc), [3, 3, 5, 5]);
    let page = |i: usize| doc.page(i).unwrap();
    assert_eq!(page(0).ancestors(), &[id(2)]);
    assert_eq!(page(1).ancestors(), &[id(4), id(2)]);
    assert_eq!(page(2).ancestors(), &[id(4), id(2)]);
    assert_eq!(page(3).ancestors(), &[id(6), id(4), id(2)]);
    assert_eq!(
        [0, 1, 2, 3].map(|i| page(i).rotation().degrees()),
        [0, 90, 90, 180]
    );
    assert_eq!(page(0).media_box(), Rect::US_LETTER);
    assert_eq!(page(1).media_box(), Rect::new(0.0, 0.0, 595.0, 842.0));
    assert_eq!(diagnostics_with(&doc, "listed more than once").len(), 2);
    assert_eq!(
        diagnostics_with(&doc, "node 6 0 R appears more than once").len(),
        1
    );

    // A setter changes the page object, so every index of the page shows it.
    let mut doc = open(model::repeated_page());
    doc.set_rotation(1, Rotation::R180).unwrap();
    assert_eq!(doc.page(0).unwrap().rotation(), Rotation::R180);
    assert_eq!(doc.store().edited_ids(), [id(3)]);
}

/// `page_count` counts the pages the walk reaches, whatever `/Count` says, and reports every
/// `/Count` that disagrees. Kids that are not pages are skipped; a leaf without `/Type` is a
/// page.
#[test]
fn wrong_count_uses_leaf_walk() {
    let doc = open(model::wrong_count());
    assert_eq!(doc.page_count().unwrap(), 3);
    assert_eq!(page_numbers(&doc), [3, 5, 6]);
    // The page without /Type has its own media box.
    assert_eq!(
        corners(doc.page(2).unwrap().media_box()),
        [0.0, 0.0, 100.0, 100.0]
    );
    let counts = diagnostics_with(&doc, "/Count");
    assert_eq!(counts.len(), 2, "{counts:?}");
    assert!(counts.iter().any(|d| d.message.contains("/Count 7 but 3")));
    assert!(counts.iter().any(|d| d.message.contains("/Count 1 but 2")));
    assert_eq!(diagnostics_with(&doc, "has /Type /Font").len(), 1);
    assert_eq!(
        diagnostics_with(&doc, "kid 8 0 R of node 2 0 R is null").len(),
        1
    );
    assert_eq!(diagnostics_with(&doc, "lists an integer").len(), 1);
    // The walk is cached: asking again adds nothing.
    let before = doc.diagnostics().len();
    assert_eq!(doc.page_count().unwrap(), 3);
    assert_eq!(doc.diagnostics().len(), before);

    let err = doc.page(3).unwrap_err();
    assert_eq!(err.code(), ErrorCode::PageOutOfRange);
    assert!(err.to_string().contains("3 pages"), "{err}");
}

/// `/Rotate` is normalized from any multiple of 90, negative ones included; other numbers give
/// 0 and a diagnostic; a value that is not a number is ignored in favour of the inherited one.
#[test]
fn rotation_normalized() {
    let doc = open(model::rotations());
    assert_eq!(doc.page_count().unwrap(), model::ROTATIONS.len());
    for (i, (value, degrees)) in model::ROTATIONS.iter().enumerate() {
        let page = doc.page(i).unwrap();
        assert_eq!(page.rotation().degrees(), *degrees, "/Rotate {value}");
        let size = page.effective_size();
        if page.rotation().is_sideways() {
            assert_eq!(size, (792.0, 612.0), "/Rotate {value}");
        } else {
            assert_eq!(size, (612.0, 792.0), "/Rotate {value}");
        }
    }
    assert_eq!(diagnostics_with(&doc, "not a multiple of 90").len(), 1);
    assert_eq!(diagnostics_with(&doc, "/Rotate of").len(), 1);
    assert_eq!(Rotation::from_degrees(-450), Some(Rotation::R270));
}

/// The media box falls back to US Letter with a diagnostic; an invalid box is ignored in favour
/// of the inherited one; a crop box outside the media box is ignored.
#[test]
fn box_fallbacks() {
    let pdf = build(
        "1.4",
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (
                2,
                "<< /Type /Pages /Kids [3 0 R 4 0 R 5 0 R 6 0 R] /Count 4 >>",
            ),
            // No media box anywhere.
            (3, "<< /Type /Page /Parent 2 0 R >>"),
            // Invalid boxes; then a valid one with references and reversed corners.
            (
                4,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 0 0] /CropBox [0 0 (a) 1] >>",
            ),
            (
                5,
                "<< /Type /Page /Parent 2 0 R /MediaBox 7 0 R /CropBox [500 500 600 600] >>",
            ),
            (
                6,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100] /Rotate 7 0 R >>",
            ),
            (7, "[200 8 0 R 0 0]"),
            (8, "300.5"),
        ],
        "",
    );
    let doc = open(pdf);
    let page = doc.page(0).unwrap();
    assert_eq!(page.media_box(), Rect::US_LETTER);
    assert_eq!(page.crop_box(), Rect::US_LETTER);
    assert_eq!(diagnostics_with(&doc, "US Letter assumed").len(), 1);

    assert_eq!(doc.page(1).unwrap().media_box(), Rect::US_LETTER);
    assert_eq!(
        diagnostics_with(&doc, "/MediaBox of 4 0 R is invalid").len(),
        1
    );
    assert_eq!(doc.page(1).unwrap().crop_box(), Rect::US_LETTER);
    assert_eq!(
        diagnostics_with(&doc, "/CropBox of 4 0 R is invalid").len(),
        1
    );

    let third = doc.page(2).unwrap();
    assert_eq!(corners(third.media_box()), [0.0, 0.0, 200.0, 300.5]);
    assert_eq!(third.crop_box(), third.media_box());
    assert_eq!(diagnostics_with(&doc, "does not overlap").len(), 1);

    // An indirect /Rotate that is not a number: ignored, the default 0 applies.
    let fourth = doc.page(3).unwrap();
    assert_eq!(fourth.rotation(), Rotation::R0);
    assert_eq!(fourth.media_box(), Rect::US_LETTER);
    assert_eq!(
        diagnostics_with(&doc, "/Rotate of 6 0 R is invalid").len(),
        1
    );
}

/// The walk is bounded by `Limits::max_page_tree_depth`, counting the root as depth 1.
#[test]
fn page_tree_depth_limit() {
    let default_depth = u32::from(Limits::default().max_page_tree_depth);
    let doc = open(model::deep_page_tree(default_depth));
    assert_eq!(doc.page_count().unwrap(), 1);
    assert_eq!(
        doc.page(0).unwrap().ancestors().len(),
        default_depth as usize
    );

    let doc = open(model::deep_page_tree(default_depth + 1));
    let err = doc.page_count().unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);
    assert!(err.to_string().contains("max_page_tree_depth"), "{err}");
    // The error is cached with the walk, and every page accessor reports it.
    assert_eq!(doc.page(0).unwrap_err().code(), ErrorCode::LimitExceeded);
    assert_eq!(doc.page_ids().unwrap_err().code(), ErrorCode::LimitExceeded);

    let options = OpenOptions::default().with_limits(Limits::default().with_max_page_tree_depth(3));
    let doc = Document::open(model::deep_page_tree(3), &options).unwrap();
    assert_eq!(doc.page_count().unwrap(), 1);
    let doc = Document::open(model::deep_page_tree(4), &options).unwrap();
    assert_eq!(
        doc.page_count().unwrap_err().code(),
        ErrorCode::LimitExceeded
    );
}

/// Odd page-tree roots: a root that is a page, a missing `/Pages`, a direct `/Pages`
/// dictionary, and a root without `/Type`.
#[test]
fn page_tree_roots() {
    let root_is_page = build(
        "1.4",
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Page /MediaBox [0 0 50 50] >>"),
        ],
        "",
    );
    let doc = open(root_is_page);
    assert_eq!(page_numbers(&doc), [2]);
    assert!(doc.page(0).unwrap().ancestors().is_empty());
    assert_eq!(
        corners(doc.page(0).unwrap().media_box()),
        [0.0, 0.0, 50.0, 50.0]
    );
    assert_eq!(
        diagnostics_with(&doc, "is a page, not a /Pages node").len(),
        1
    );

    let no_pages = build("1.4", &[(1, "<< /Type /Catalog >>")], "");
    let doc = open(no_pages);
    assert_eq!(doc.page_count().unwrap(), 0);
    assert_eq!(doc.page(0).unwrap_err().code(), ErrorCode::PageOutOfRange);
    assert_eq!(diagnostics_with(&doc, "has no /Pages").len(), 1);

    let direct = build(
        "1.4",
        &[(
            1,
            "<< /Type /Catalog /Pages << /Type /Pages /Kids [] /Count 0 >> >>",
        )],
        "",
    );
    let doc = open(direct);
    assert_eq!(doc.page_count().unwrap(), 0);
    assert_eq!(diagnostics_with(&doc, "not an indirect reference").len(), 1);

    let untyped = build(
        "1.4",
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Kids [3 0 R] /Count 1 >>"),
            (3, "<< /Type /Page /Parent 2 0 R >>"),
        ],
        "",
    );
    let doc = open(untyped);
    assert_eq!(page_numbers(&doc), [3]);
    assert_eq!(diagnostics_with(&doc, "has /Kids but no /Type").len(), 1);

    // A wrong /Parent is reported; inheritance follows the walk.
    let wrong_parent = build(
        "1.4",
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (
                2,
                "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 20 30] >>",
            ),
            (3, "<< /Type /Page /Parent 4 0 R >>"),
            (
                4,
                "<< /Type /Pages /Kids [] /Count 0 /MediaBox [0 0 1 1] >>",
            ),
        ],
        "",
    );
    let doc = open(wrong_parent);
    assert_eq!(
        corners(doc.page(0).unwrap().media_box()),
        [0.0, 0.0, 20.0, 30.0]
    );
    assert_eq!(
        diagnostics_with(&doc, "/Parent of 3 0 R is not 2 0 R").len(),
        1
    );
}

/// Every committed syntax fixture that opens has the page count its description gives, and
/// every page has a media box; the qpdf-written (linearized) files too.
#[test]
fn fixture_page_counts() {
    let mut opened = 0;
    for info in syntax::infos() {
        let pdf = syntax::get(info.name).unwrap();
        let Ok(doc) = Document::open(pdf, &OpenOptions::default()) else {
            continue;
        };
        opened += 1;
        let count = doc.page_count().unwrap();
        assert_eq!(count, info.pages as usize, "{}", info.name);
        for i in 0..count {
            let size = doc.page(i).unwrap().effective_size();
            assert!(size.0 > 0.0 && size.1 > 0.0, "{}", info.name);
        }
    }
    assert!(opened >= 20, "only {opened} fixtures opened");

    for info in qpdf::infos() {
        let bytes = qpdf::read_committed(info.name).unwrap();
        let doc = Document::open_shared(shared_bytes(bytes), &OpenOptions::default()).unwrap();
        assert_eq!(
            doc.page_count().unwrap(),
            qpdf::PAGES as usize,
            "{}",
            info.name
        );
        assert_eq!(doc.version(), info.version, "{}", info.name);
    }
}

/// A two-level tree of 250 pages (`syntax::many_pages`), in object streams too: every page
/// inherits the root's media box and resources.
#[test]
fn many_pages_inherit_from_the_root() {
    for pdf in [syntax::many_pages(250), syntax::many_pages_compressed(250)] {
        let doc = open(pdf);
        assert_eq!(doc.page_count().unwrap(), 250);
        let ids = doc.page_ids().unwrap();
        for (i, id) in ids.iter().enumerate() {
            let page = doc.page(i).unwrap();
            assert_eq!(page.id(), *id);
            assert_eq!(doc.page_index(*id).unwrap(), Some(i));
            assert_eq!(page.media_box(), Rect::US_LETTER);
            assert_eq!(page.ancestors().len(), 2);
            assert!(page.resources().unwrap().unwrap().get(b"Font").is_some());
        }
        assert!(doc.diagnostics().is_empty(), "{:?}", doc.diagnostics());
        assert_eq!(doc.page_index(PageId(id(1))).unwrap(), None);
    }
}

/// `store_mut` drops the cached walk; walking again gives the same pages.
#[test]
fn store_mut_drops_the_cached_walk() {
    let mut doc = open(model::inherited_attributes());
    let before = doc.page_ids().unwrap();
    let _ = doc.store_mut();
    assert_eq!(doc.page_ids().unwrap(), before);
    let store = doc.into_store();
    let doc = Document::from_store(store).unwrap();
    assert_eq!(doc.page_ids().unwrap(), before);
}

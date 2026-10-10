#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The document model never panics on damaged input (CLAUDE.md "never panic on untrusted
//! input"; M2 brief AC7): every model fixture and a few syntax fixtures are mutated with
//! [`folioxide_testkit::mutate`], and each mutation that opens is read through the whole
//! read-side API (the page tree, every page's boxes, rotation, size and resources, the Info
//! dictionary, the version, and the catalog's name and number trees), then saved in full,
//! edited through the write side (Info, page boxes and rotation) and saved again, in full and
//! incrementally; a full save that succeeds must reopen.
//!
//! [`document_pipeline_never_panics_on_mutated_input`] runs the brief's pipeline at the
//! `Document` level over at least 20 000 mutations ([`PIPELINE_MUTATIONS`]): open, page count,
//! every page's media box, crop box, rotation and [`PageInfo`], the Info dictionary, `set_info`,
//! a full save that must reopen and show the same pages and the new title, and an incremental
//! save whenever [`Store::check_incremental`] allows one, which must keep the source as its
//! prefix and reopen with one more revision, the same pages and the new title. It checks the
//! model's invariants on every page it reads (a media box with an area, a crop box inside it, a
//! displayed size that follows the rotation).
//!
//! The runs are deterministic (a fixed seed per base) and cycle through lenient, strict and
//! lenient-with-tiny-limits options. Set `FOLIOXIDE_MODEL_MUTATIONS=<n>` for `n` mutations per
//! base instead of [`MUTATIONS_PER_BASE`], and `FOLIOXIDE_PIPELINE_MUTATIONS=<n>` for `n`
//! pipeline mutations in total instead of [`PIPELINE_MUTATIONS`].
//!
//! [`Store::check_incremental`]: folioxide_syntax::Store::check_incremental

use std::panic::{AssertUnwindSafe, catch_unwind};

use folioxide_model::{Document, InfoUpdate, NameTree, NumberTree, PageInfo, Rect, Rotation};
use folioxide_syntax::{
    ErrorCode, IncrementalOptions, Limits, Object, OpenOptions, SaveOptions, Strictness,
};
use folioxide_testkit::fixtures::{model, syntax};
use folioxide_testkit::mutate::Mutator;

/// Mutations per base file.
const MUTATIONS_PER_BASE: usize = 400;

/// The bases: every model fixture and the syntax fixtures with the most page-tree structure.
fn bases() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("inherited", model::inherited_attributes()),
        ("rotations", model::rotations()),
        ("cycle", model::page_tree_cycle()),
        ("wrong-count", model::wrong_count()),
        ("deep", model::deep_page_tree(6)),
        ("trees", model::trees()),
        ("info", model::info_strings()),
        ("minimal", syntax::minimal()),
        ("multi-revision", syntax::multi_revision()),
        ("objstm", syntax::objstm()),
        ("many-pages", syntax::many_pages(12)),
    ]
}

fn options(i: usize) -> OpenOptions {
    match i % 3 {
        0 => OpenOptions::default(),
        1 => OpenOptions::default().with_strictness(Strictness::Strict),
        _ => OpenOptions::default().with_limits(
            Limits::default()
                .with_max_page_tree_depth(2)
                .with_max_nesting_depth(4)
                .with_max_objects(64)
                .with_max_ref_chain(2),
        ),
    }
}

/// Uses every read-side accessor; errors are fine, panics are not.
fn read_everything(doc: &Document) {
    let _ = doc.version();
    let _ = doc.info();
    let _ = doc.page_ids();
    if let Ok(count) = doc.page_count() {
        for i in 0..count.min(64) {
            let page = doc.page(i).unwrap();
            let _ = page.media_box();
            let _ = page.crop_box();
            let _ = page.bleed_box();
            let _ = page.trim_box();
            let _ = page.art_box();
            let _ = page.rotation();
            let (w, h) = page.effective_size();
            assert!(!w.is_nan() && !h.is_nan());
            let _ = page.resources();
            let _ = page.object();
        }
        assert!(doc.page(count).is_err());
    }
    if let Ok(catalog) = doc.catalog()
        && let Some(catalog) = catalog.as_dict()
    {
        if let Some(Object::Dict(names)) = catalog.get(b"Names")
            && let Some(dests) = names.get(b"Dests")
        {
            let tree = NameTree::new(doc.store(), dests);
            let _ = tree.entries();
            let _ = tree.get(b"zeta");
        }
        if let Some(labels) = catalog.get(b"PageLabels") {
            let tree = NumberTree::new(doc.store(), labels);
            let _ = tree.entries();
            let _ = tree.get(5);
        }
    }
    let _ = doc.diagnostics();
}

/// Saves, edits and saves again; errors are fine, panics are not. A full save that succeeds
/// gives a file that opens again.
fn edit_and_save(doc: &mut Document, options: &OpenOptions) {
    let saved = doc.save(&SaveOptions::default());
    let _ = doc.set_info(
        &InfoUpdate::default()
            .with_title(Some("Mutated \u{1F600}"))
            .with_author(None)
            .with_custom("Note", Some("x")),
    );
    if let Ok(count) = doc.page_count() {
        for i in 0..count.min(8) {
            let _ = doc.set_rotation(i, Rotation::R90);
            let _ = doc.set_crop_box(i, None);
            let _ = doc.set_media_box(i, Rect::new(0.0, 0.0, 300.0, 400.0));
            let _ = doc.set_crop_box(i, Some(Rect::new(10.0, 10.0, 290.0, 390.0)));
        }
    }
    let _ = doc.save_incremental(&IncrementalOptions::default());
    let _ = doc.save(&SaveOptions::default().with_object_streams(true));
    for pdf in [saved, doc.save(&SaveOptions::default())]
        .into_iter()
        .flatten()
    {
        let reopened = Document::open(pdf, options);
        assert!(
            reopened.is_ok(),
            "a full save does not reopen: {:?}",
            reopened.err()
        );
    }
}

#[test]
fn model_never_panics_on_mutated_input() {
    let per_base = std::env::var("FOLIOXIDE_MODEL_MUTATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MUTATIONS_PER_BASE);
    let mut opened = 0usize;
    let mut total = 0usize;
    for (name, base) in bases() {
        // A fixed seed per base (FNV-1a of the name), so failures reproduce.
        let seed = name.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
        });
        let mut mutator = Mutator::new(seed);
        for i in 0..per_base {
            let input = mutator.mutate(&base);
            total += 1;
            let result = catch_unwind(AssertUnwindSafe(|| {
                if let Ok(mut doc) = Document::open(input.clone(), &options(i)) {
                    read_everything(&doc);
                    edit_and_save(&mut doc, &options(i));
                    true
                } else {
                    false
                }
            }));
            match result {
                Ok(true) => opened += 1,
                Ok(false) => {}
                Err(_) => panic!("panic on mutation {i} of {name} (seed {seed:#x})"),
            }
        }
    }
    // Most mutations still open, so the model code was exercised.
    assert!(
        opened * 2 > total,
        "only {opened} of {total} mutations opened"
    );
}

// ---- the Document pipeline (M2 brief, acceptance criterion 7) ----------------------------------

/// Mutations of the Document pipeline, over all its bases together (the M2 brief asks for at
/// least 20 000).
const PIPELINE_MUTATIONS: usize = 21_000;

/// The title the pipeline sets: outside PDFDocEncoding, so it is written as UTF-16BE.
const PIPELINE_TITLE: &str = "Mutated \u{1F600} Grüße";

/// The pipeline's bases: [`bases`], the crop box fixture, and the syntax fixtures whose newest
/// section is a cross-reference stream or a hybrid section, so that the incremental saves write
/// every kind of section.
fn pipeline_bases() -> Vec<(&'static str, Vec<u8>)> {
    let mut all = bases();
    all.extend([
        ("crop-box-quirks", model::crop_box_quirks()),
        ("xref-stream", syntax::xref_stream()),
        ("hybrid", syntax::hybrid()),
    ]);
    all
}

/// A fixed seed for `name` (FNV-1a), so that a failure reproduces.
fn seed_of(name: &str) -> u64 {
    name.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// How far the pipeline got, counted over the mutations of one base.
#[derive(Clone, Copy, Debug, Default)]
struct Reached {
    mutations: usize,
    opened: usize,
    pages_read: usize,
    full_saves: usize,
    incremental_saves: usize,
    incremental_refused: usize,
}

impl std::ops::AddAssign for Reached {
    fn add_assign(&mut self, other: Reached) {
        self.mutations += other.mutations;
        self.opened += other.opened;
        self.pages_read += other.pages_read;
        self.full_saves += other.full_saves;
        self.incremental_saves += other.incremental_saves;
        self.incremental_refused += other.incremental_refused;
    }
}

/// Every page's [`PageInfo`], read through [`Document::page`] and the page's accessors, with
/// the model's invariants checked; `None` when the page tree cannot be walked (an error is fine,
/// a panic is not).
fn read_pages(doc: &Document) -> Option<Vec<PageInfo>> {
    let count = doc.page_count().ok()?;
    let mut pages = Vec::with_capacity(count);
    for i in 0..count {
        let page = doc.page(i).expect("a page below page_count() is readable");
        let media = page.media_box();
        let crop = page.crop_box();
        let rotation = page.rotation();
        let info = page.info();
        // §14.11.2: a media box with an area (US Letter when none is valid), and a crop box
        // with an area inside it.
        let coords = [media.llx, media.lly, media.urx, media.ury];
        assert!(coords.iter().all(|v| v.is_finite()), "page {i}: {media:?}");
        assert!(
            media.width() > 0.0 && media.height() > 0.0,
            "page {i}: {media:?}"
        );
        assert!(
            media.contains(&crop),
            "page {i}: {crop:?} outside {media:?}"
        );
        assert!(
            crop.width() > 0.0 && crop.height() > 0.0,
            "page {i}: {crop:?}"
        );
        // PageInfo is the accessors' values, and the displayed size follows the rotation.
        let size = if rotation.is_sideways() {
            (crop.height(), crop.width())
        } else {
            (crop.width(), crop.height())
        };
        assert_eq!(
            (info.index, info.media_box, info.crop_box, info.rotation),
            (i, media, crop, rotation),
            "page {i}"
        );
        assert_eq!((info.width, info.height), size, "page {i}");
        assert_eq!(page.effective_size(), size, "page {i}");
        pages.push(info);
    }
    let err = doc.page(count).expect_err("no page at page_count()");
    assert_eq!(err.code(), ErrorCode::PageOutOfRange);
    Some(pages)
}

/// Whether two coordinates are equal up to the writer's rounding (a real is written with at most
/// ten fractional digits, ARCHITECTURE §A.3).
fn close(a: f64, b: f64) -> bool {
    a == b || (a - b).abs() <= 1e-9 * a.abs().max(b.abs()).max(1.0)
}

/// Asserts that a saved and reopened document shows the pages the source showed.
fn assert_same_pages(what: &str, before: Option<&[PageInfo]>, after: Option<&[PageInfo]>) {
    let (Some(before), Some(after)) = (before, after) else {
        assert_eq!(
            before.is_some(),
            after.is_some(),
            "{what}: the page tree reads in one of source and output only"
        );
        return;
    };
    assert_eq!(before.len(), after.len(), "{what}: page count");
    for (a, b) in before.iter().zip(after) {
        let rects = [(a.media_box, b.media_box), (a.crop_box, b.crop_box)];
        let same = a.rotation == b.rotation
            && rects.iter().all(|(r, s)| {
                close(r.llx, s.llx)
                    && close(r.lly, s.lly)
                    && close(r.urx, s.urx)
                    && close(r.ury, s.ury)
            });
        assert!(same, "{what}: page {} was {a:?}, is {b:?}", a.index);
    }
}

/// Asserts that `doc` shows the pipeline's title, when its Info dictionary can be read.
fn assert_title(what: &str, doc: &Document) {
    if let Ok(info) = doc.info() {
        assert_eq!(info.title.as_deref(), Some(PIPELINE_TITLE), "{what}");
    }
}

/// The pipeline for one input: open, page count, every page's boxes, rotation and PageInfo,
/// `info`, `set_info`, a full save (reopened), an incremental save when the source takes one
/// (reopened). Errors are fine; panics and broken guarantees are not.
fn pipeline(input: Vec<u8>, options: &OpenOptions, reached: &mut Reached) {
    let Ok(mut doc) = Document::open(input, options) else {
        return;
    };
    reached.opened += 1;
    let pages = read_pages(&doc);
    if pages.is_some() {
        reached.pages_read += 1;
    }
    let _ = doc.info();
    let update = InfoUpdate::default()
        .with_title(Some(PIPELINE_TITLE))
        .with_author(None)
        .with_mod_date(folioxide_model::PdfDate::new(2026, 10, 10, 12, 0, 0));
    let titled = doc.set_info(&update).is_ok();
    if titled {
        assert_title("set_info", &doc);
    }

    // A full save always gives a file that opens, with the same pages.
    if let Ok(pdf) = doc.save(&SaveOptions::default()) {
        reached.full_saves += 1;
        let reopened = Document::open(pdf, options)
            .unwrap_or_else(|err| panic!("a full save does not reopen: {err}"));
        assert_same_pages(
            "full save",
            pages.as_deref(),
            read_pages(&reopened).as_deref(),
        );
        if titled {
            assert_title("full save", &reopened);
        }
    }

    // An incremental save keeps the source as its prefix and adds one revision, unless the
    // source's structure is one other readers may resolve differently (check_incremental).
    let allowed = doc.store().check_incremental();
    let result = doc.save_incremental(&IncrementalOptions::default());
    match (allowed, result) {
        (Ok(()), Ok(pdf)) => {
            let source = doc.store().source();
            assert!(pdf.starts_with(source), "the source is not the prefix");
            if !doc.is_modified() {
                assert_eq!(pdf.len(), source.len(), "an update without edits");
                return;
            }
            reached.incremental_saves += 1;
            let reopened = Document::open(pdf, options)
                .unwrap_or_else(|err| panic!("an incremental save does not reopen: {err}"));
            assert_eq!(
                reopened.store().revisions().len(),
                doc.store().revisions().len() + 1,
                "revisions"
            );
            assert_same_pages(
                "incremental save",
                pages.as_deref(),
                read_pages(&reopened).as_deref(),
            );
            if titled {
                assert_title("incremental save", &reopened);
            }
        }
        // No object number left for the cross-reference stream (tiny limits).
        (Ok(()), Err(err)) => assert_eq!(err.code(), ErrorCode::LimitExceeded, "{err}"),
        (Err(refusal), Ok(_)) => {
            panic!("an incremental save that check_incremental refuses: {refusal}")
        }
        (Err(_), Err(err)) => {
            reached.incremental_refused += 1;
            assert!(
                matches!(
                    err.code(),
                    ErrorCode::Unsupported | ErrorCode::InvalidArgument
                ),
                "{err}"
            );
        }
    }
}

/// Runs the pipeline over `count` mutations of `base`.
fn pipeline_base(name: &str, base: &[u8], count: usize) -> Reached {
    let seed = seed_of(&format!("pipeline/{name}"));
    let mut mutator = Mutator::new(seed);
    let mut reached = Reached::default();
    for i in 0..count {
        let input = mutator.mutate(base);
        reached.mutations += 1;
        let options = options(i);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut local = Reached::default();
            pipeline(input, &options, &mut local);
            local
        }));
        match result {
            Ok(local) => reached += local,
            Err(payload) => {
                let message = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("(no message)");
                panic!("pipeline mutation {i} of {name} (seed {seed:#x}): {message}");
            }
        }
    }
    reached
}

#[test]
fn document_pipeline_never_panics_on_mutated_input() {
    let requested = std::env::var("FOLIOXIDE_PIPELINE_MUTATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(PIPELINE_MUTATIONS);
    let bases = pipeline_bases();
    let per_base = requested.div_ceil(bases.len());
    // One thread per base: each base's run is deterministic on its own, so the result does not
    // depend on scheduling. Large stacks, as for any thread that may drop deep objects.
    let reached: Vec<Reached> = std::thread::scope(|scope| {
        let handles: Vec<_> = bases
            .iter()
            .map(|(name, base)| {
                std::thread::Builder::new()
                    .name(format!("pipeline-{name}"))
                    .stack_size(16 << 20)
                    .spawn_scoped(scope, move || pipeline_base(name, base, per_base))
                    .unwrap()
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|_| panic!("a pipeline thread failed"))
            })
            .collect()
    });
    let mut total = Reached::default();
    for r in reached {
        total += r;
    }
    println!("{total:?}");
    assert!(total.mutations >= requested, "{total:?}");
    // Most mutations open, and most of those read their pages and save in full. Most of the
    // files that open needed a repair, which check_incremental refuses to append to (about 85 %
    // of them), but more than one in ten take an incremental update: the pipeline was
    // exercised to its end.
    assert!(total.opened * 2 > total.mutations, "{total:?}");
    assert!(total.pages_read * 4 > total.opened * 3, "{total:?}");
    assert!(total.full_saves * 4 > total.opened * 3, "{total:?}");
    assert!(total.incremental_saves * 10 > total.opened, "{total:?}");
    assert!(total.incremental_refused > 0, "{total:?}");
}

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Oracle suite `model` (M2 brief WP2.6, acceptance criterion 5): poppler's `pdfinfo -box -f 1
//! -l N` must agree with our [`PageInfo`] on every page (media box, crop box, rotation and
//! displayed size: the `boxes` expect key of `tools/oracles/run_suite.py`).
//!
//! Each case is a document-model fixture as generated, or that fixture after the page setters
//! and [`Document::set_info`], saved in full (with a cross-reference table, and with object
//! streams) and incrementally. With the `folioxide-testkit/emit` feature (`cargo xtask oracle
//! --suite model`) every case is written to `target/oracle/model/<case>.pdf` plus
//! `<case>.expect.json`; without it the test still builds every case and checks every
//! expectation with our own reader, and writes nothing.
//!
//! - `inherited-attributes`: boxes and rotation inherited from one and two levels up
//!   (§7.7.3.4); `-full` is a full save without edits; `-setters-{full,objstm,incr}` change an
//!   inherited media box, crop box and rotation of each page (the setters write the value on the
//!   page, never on the `/Pages` node), shrink a media box under an existing crop box, and set
//!   the Info dictionary.
//! - `rotations`: every kind of `/Rotate` value; `-normalized-{full,objstm,incr}` write each
//!   page's rotation as we read it, which poppler then reads alike.
//! - `crop-box-quirks`: crop boxes poppler clips differently; `-setters-{full,objstm,incr}`
//!   write the crop boxes as we read them (clipped inside the media box), which poppler then
//!   reads alike.
//! - `repeated-page`: a page tree that lists the same page twice, which poppler (like pypdf and
//!   qpdf) reads as two pages; `-setters-{full,objstm,incr}` edit the page through each of its
//!   indices and another page, and keep the tree as it is.
//! - `parent-mismatch`: `/Parent` entries that disagree with the page tree (readers that
//!   inherit along `/Parent` see other values); `-setters-{full,objstm,incr}` write the values on
//!   the pages, so that every reader agrees with poppler and us.
//!
//! Every case expects `pages`, `version` and `boxes` (our [`PageInfo`] for every page, in its
//! serde JSON shape); the setter cases also expect `info` (a UTF-16BE title, a PDFDocEncoding
//! author, a modification date), and the incremental ones `prefixOf` (their source case) and
//! `revisions`. The runner also checks the structure of every case with pdfinfo, pikepdf/qpdf
//! and pypdf in strict mode.
//!
//! What poppler reads differently from ISO 32000-2 (and from us) is listed under
//! `knownFailures` with the reason ([`known_failures`]): a raw `/Rotate 45`, an ignored
//! `/Rotate 90.0`, and crop boxes that do not lie inside the media box; so are the qpdf warnings
//! about the page-tree defects the fixtures have on purpose. Those checks still run,
//! and an entry fails as soon as its check passes. No case is skipped, and every case checks
//! every page.

use folioxide_model::{Document, InfoUpdate, PageInfo, PdfDate, Rect, Rotation};
use folioxide_syntax::{IncrementalOptions, ObjectId, OpenOptions, SaveOptions};
use folioxide_testkit::fixtures::model;
use folioxide_testkit::{EMIT_ENABLED, ExpectJson, emit::json_string, emit_case};

/// The oracle suite name.
const SUITE: &str = "model";

/// The fewest cases the suite must check (every one has a `boxes` expectation).
const MIN_CASES: usize = 12;

/// One oracle case.
struct Case {
    name: String,
    pdf: Vec<u8>,
    expect: ExpectJson,
    /// Our reading of every page of `pdf`, after reopening it.
    pages: Vec<PageInfo>,
}

const ROTATE_45: &str = "poppler 24.02 reads /Rotate only as an integer and does not check that \
    it is a multiple of 90 (PageAttrs in Page.cc): it shows /Rotate 45 as 45, where ISO 32000-2 \
    §7.7.3.3 requires a multiple of 90 and we (like pdf.js) use 0";
const ROTATE_REAL: &str = "poppler 24.02 ignores a /Rotate that is not an integer: the page's \
    /Rotate 90.0 is skipped and the inherited /Rotate 180 shown (and so an upright size), where we \
    accept an integral real as 90 (§7.7.3.3 says integer; integral reals occur in real files)";
const NO_RESOURCES: &str = "the fixture's pages have no /Resources, which ISO 32000-2 §7.7.3.3 \
    Table 31 requires: qpdf repairs every such page with a warning (the writer suite lists the \
    same failure); the setters do not add page attributes they were not asked to set";
const CROP_WIDER: &str = "poppler 24.02 replaces a crop box wider than the media box by the \
    media box's horizontal extent before clamping it ([100 0 500 400] in [0 0 300 400] becomes \
    [0 0 300 400]), where §14.11.2 intersects the two ([100 0 300 400]); the setter cases write \
    the intersection, which poppler then reads alike";
const CROP_OUTSIDE: &str = "poppler 24.02 clamps a crop box that does not overlap the media box \
    into a box without area ([400 0 500 400] in [0 0 300 400] becomes [300 0 300 400], size 0 x \
    400), where we ignore it with a diagnostic and use the media box (§14.11.2 default); the \
    setter cases remove it";

const REPEATED_PAGE: &str = "the fixture's page tree lists page 3 twice on purpose (model \
    fixture repeated_page; the writer keeps the page tree as it is): qpdf warns that the kid \
    appears more than once and copies the page object to make the second listing a page of its \
    own, which is the reading poppler, pypdf and we share (three pages, the first two alike)";
const PARENT_MISMATCH: &str = "the fixture's page tree root has a /Parent on purpose (model \
    fixture parent_mismatch: ISO 32000-2 §7.7.3.2 prohibits it in the root; the writer keeps the \
    page tree as it is): qpdf follows it, warns that the catalog's /Pages does not point to the \
    root of the page tree, and corrects that";

/// Checks the oracle runner expects to fail for `case`, with the reason: what poppler reads
/// differently in the source fixture, and what qpdf warns about in it. The setter cases fix the
/// page values, so only the warnings about the page tree itself (`NO_RESOURCES`,
/// `REPEATED_PAGE`, `PARENT_MISMATCH`) stay for them.
fn known_failures(case: &str) -> Vec<(&'static str, &'static str)> {
    match case {
        c if c.starts_with("repeated-page") => vec![("structure.pikepdf", REPEATED_PAGE)],
        c if c.starts_with("parent-mismatch") => vec![("structure.pikepdf", PARENT_MISMATCH)],
        "rotations" => vec![
            ("structure.pikepdf", NO_RESOURCES),
            ("boxes[8].rotation.pdfinfo", ROTATE_45),
            ("boxes[9].rotation.pdfinfo", ROTATE_REAL),
            ("boxes[9].size.pdfinfo", ROTATE_REAL),
        ],
        c if c.starts_with("rotations-") => vec![("structure.pikepdf", NO_RESOURCES)],
        "crop-box-quirks" => vec![
            ("boxes[0].cropBox.pdfinfo", CROP_WIDER),
            ("boxes[0].size.pdfinfo", CROP_WIDER),
            ("boxes[1].cropBox.pdfinfo", CROP_OUTSIDE),
            ("boxes[1].size.pdfinfo", CROP_OUTSIDE),
        ],
        _ => Vec::new(),
    }
}

fn open(pdf: &[u8]) -> Document {
    Document::open(pdf.to_vec(), &OpenOptions::default()).unwrap()
}

/// Every page's [`PageInfo`].
fn page_infos(doc: &Document) -> Vec<PageInfo> {
    (0..doc.page_count().unwrap())
        .map(|i| doc.page(i).unwrap().info())
        .collect()
}

/// A page's expected values: media box, crop box (both `[llx lly urx ury]`) and rotation.
type Expected = ([f64; 4], [f64; 4], u16);

/// Asserts that `pages` show `expected`, page by page, with the displayed size following.
fn assert_pages(case: &str, pages: &[PageInfo], expected: &[Expected]) {
    assert_eq!(pages.len(), expected.len(), "{case}: page count");
    for (info, &(media, crop, degrees)) in pages.iter().zip(expected) {
        let i = info.index;
        let rect = |[a, b, c, d]: [f64; 4]| Rect::new(a, b, c, d);
        assert_eq!(info.media_box, rect(media), "{case}: page {i} media box");
        assert_eq!(info.crop_box, rect(crop), "{case}: page {i} crop box");
        assert_eq!(
            info.rotation.degrees(),
            degrees,
            "{case}: page {i} rotation"
        );
        let (w, h) = (crop[2] - crop[0], crop[3] - crop[1]);
        let size = if degrees % 180 == 90 { (h, w) } else { (w, h) };
        assert_eq!((info.width, info.height), size, "{case}: page {i} size");
    }
}

/// The title the setter cases give their document: not in PDFDocEncoding, so it is written as
/// UTF-16BE and every oracle has to decode it (§7.9.2.2).
fn title_for(case: &str) -> String {
    format!("Folioxide {case} \u{2013} Grüße 日本")
}

/// The modification date the setter cases set (the core has no clock; the caller passes it).
fn mod_date() -> PdfDate {
    PdfDate::new(2026, 10, 10, 9, 30, 0)
        .and_then(|d| d.with_offset(Some(120)))
        .unwrap()
}

/// Sets the Info entries the setter cases check.
fn set_info(doc: &mut Document, case: &str) {
    doc.set_info(
        &InfoUpdate::default()
            .with_title(Some(&title_for(case)))
            .with_author(Some("Zoë Folioxide"))
            .with_mod_date(Some(mod_date())),
    )
    .unwrap();
}

/// The expectation for `pdf`, read back with our reader: `pages`, `version` and `boxes`, plus
/// `info` when `titled`, and the case's known failures. Also checks that the file reopens
/// without a repair, and returns our reading of its pages.
fn case(name: &str, pdf: Vec<u8>, titled: bool, source_diagnostics: usize) -> Case {
    let doc = open(&pdf);
    assert!(!doc.store().structure_repaired(), "{name}: repaired");
    let pages = page_infos(&doc);
    // Writer output adds no diagnostics to those of its source (acceptance criterion 7); the
    // setters even remove the reason for some.
    assert!(
        doc.diagnostics().len() <= source_diagnostics,
        "{name}: {:?}",
        doc.diagnostics()
    );
    let (major, minor) = doc.version();
    let mut expect = ExpectJson::new()
        .int("pages", pages.len() as i64)
        .string("version", &format!("{major}.{minor}"))
        .raw("boxes", serde_json::to_string(&pages).unwrap());
    if titled {
        let info = doc.info().unwrap();
        assert_eq!(
            info.title.as_deref(),
            Some(title_for(name).as_str()),
            "{name}"
        );
        assert_eq!(info.mod_date, Some(mod_date()), "{name}");
        expect = expect.raw(
            "info",
            format!(
                "{{\"Title\": {}, \"Author\": {}, \"ModDate\": {}}}",
                json_string(&title_for(name)),
                json_string("Zoë Folioxide"),
                json_string(&mod_date().to_pdf_string())
            ),
        );
    }
    let known = known_failures(name);
    if !known.is_empty() {
        expect = expect.string_map("knownFailures", &known);
    }
    Case {
        name: name.to_owned(),
        pdf,
        expect,
        pages,
    }
}

/// The saved forms of an edited document: `<base>-full` (a table), `<base>-objstm` (object
/// streams, and so a cross-reference stream) and `<base>-incr` (an incremental update of
/// `source`, which is the case `source_case`). `edit` makes the same edits on a fresh document
/// each time, since each case has its own title.
fn saved_cases(
    base: &str,
    source: &[u8],
    source_case: &str,
    edit: impl Fn(&mut Document),
) -> Vec<Case> {
    let source_diagnostics = {
        let doc = open(source);
        let _ = page_infos(&doc);
        doc.diagnostics().len()
    };
    let mut out = Vec::new();
    let variants = [
        ("full", Some(SaveOptions::default())),
        (
            "objstm",
            Some(SaveOptions::default().with_object_streams(true)),
        ),
        ("incr", None),
    ];
    for (suffix, options) in variants {
        let name = format!("{base}-{suffix}");
        let mut doc = open(source);
        edit(&mut doc);
        set_info(&mut doc, &name);
        let pdf = match &options {
            Some(options) => doc.save(options).unwrap(),
            None => doc
                .save_incremental(&IncrementalOptions::default())
                .unwrap(),
        };
        let mut c = case(&name, pdf, true, source_diagnostics);
        if options.is_none() {
            assert!(c.pdf.starts_with(source), "{name}: prefix");
            let revisions = doc.store().revisions().len() + 1;
            assert_eq!(open(&c.pdf).store().revisions().len(), revisions, "{name}");
            c.expect = c
                .expect
                .string("prefixOf", &format!("{source_case}.pdf"))
                .int("revisions", revisions as i64);
        }
        out.push(c);
    }
    out
}

/// The cases built from [`model::inherited_attributes`].
fn inherited_cases() -> Vec<Case> {
    let source = model::inherited_attributes();
    let source_case = case("inherited-attributes", source.clone(), false, 0);
    let expected: Vec<Expected> = model::INHERITED_PAGES
        .iter()
        .map(|p| (p.media_box, p.crop_box, p.rotate))
        .collect();
    assert_pages(&source_case.name, &source_case.pages, &expected);
    let unedited = open(&source).save(&SaveOptions::default()).unwrap();
    let full = case("inherited-attributes-full", unedited, false, 0);
    assert_eq!(full.pages, source_case.pages);

    let setters = saved_cases(
        "inherited-attributes-setters",
        &source,
        &source_case.name,
        |doc| {
            // Page 0 inherits everything: US Letter replaces the A4 from its grandparent, and
            // the crop box it inherits from its parent ([10 10 585 800]) is clipped to it.
            doc.set_media_box(0, Rect::US_LETTER).unwrap();
            // It inherits /Rotate 90 from the root: 0 is written on the page.
            doc.set_rotation(0, Rotation::R0).unwrap();
            // Page 1 inherits its crop box: removing it writes its media box as its crop box.
            doc.set_crop_box(1, None).unwrap();
            // Page 2 inherits /Rotate -90 (270) from its parent.
            doc.set_rotation(2, Rotation::R90).unwrap();
            // Page 3 has its own crop box; a media box narrower than the new crop box clips it.
            doc.set_crop_box(3, Some(Rect::new(50.0, 60.0, 250.0, 350.5)))
                .unwrap();
            doc.set_media_box(3, Rect::new(0.0, 0.0, 150.0, 300.0))
                .unwrap();
            // Only the four page objects change (and the Info dictionary is added): the
            // `/Pages` nodes the values were inherited from are untouched (§7.7.3.4).
            let pages: Vec<ObjectId> = doc.page_ids().unwrap().into_iter().map(|p| p.0).collect();
            assert_eq!(doc.store().edited_ids(), pages);
        },
    );
    let expected = [
        ([0.0, 0.0, 612.0, 792.0], [10.0, 10.0, 585.0, 792.0], 0),
        ([0.0, 0.0, 612.0, 792.0], [0.0, 0.0, 612.0, 792.0], 0),
        ([0.0, 0.0, 595.0, 842.0], [0.0, 0.0, 595.0, 842.0], 90),
        ([0.0, 0.0, 150.0, 300.0], [50.0, 60.0, 150.0, 300.0], 180),
    ];
    for c in &setters {
        assert_pages(&c.name, &c.pages, &expected);
    }
    let mut cases = vec![source_case, full];
    cases.extend(setters);
    cases
}

/// The cases built from [`model::rotations`].
fn rotation_cases() -> Vec<Case> {
    let source = model::rotations();
    let source_diagnostics = {
        let doc = open(&source);
        let _ = page_infos(&doc);
        doc.diagnostics().len()
    };
    let source_case = case("rotations", source.clone(), false, source_diagnostics);
    let read: Vec<u16> = model::ROTATIONS.iter().map(|(_, r)| *r).collect();
    let letter = [0.0, 0.0, 612.0, 792.0];
    let expected: Vec<Expected> = read.iter().map(|&r| (letter, letter, r)).collect();
    assert_pages(&source_case.name, &source_case.pages, &expected);

    let normalized = saved_cases("rotations-normalized", &source, &source_case.name, |doc| {
        for i in 0..doc.page_count().unwrap() {
            let rotation = doc.page(i).unwrap().rotation();
            doc.set_rotation(i, rotation).unwrap();
        }
        doc.set_rotation(0, Rotation::R270).unwrap();
    });
    let mut expected = expected;
    expected[0].2 = 270;
    for c in &normalized {
        assert_pages(&c.name, &c.pages, &expected);
    }
    let mut cases = vec![source_case];
    cases.extend(normalized);
    cases
}

/// The cases built from [`model::crop_box_quirks`].
fn crop_box_cases() -> Vec<Case> {
    let source = model::crop_box_quirks();
    // Page 1's crop box lies outside its media box: a diagnostic.
    let source_case = case("crop-box-quirks", source.clone(), false, 1);
    let media = [0.0, 0.0, 300.0, 400.0];
    let expected: Vec<Expected> = model::CROP_BOX_QUIRKS
        .iter()
        .map(|&crop| (media, crop, 0))
        .collect();
    assert_pages(&source_case.name, &source_case.pages, &expected);

    let setters = saved_cases(
        "crop-box-quirks-setters",
        &source,
        &source_case.name,
        |doc| {
            // Write the crop box as we read it: clipped inside the media box.
            let crop = doc.page(0).unwrap().crop_box();
            doc.set_crop_box(0, Some(crop)).unwrap();
            // Remove the crop box outside the media box: the crop box is the media box.
            doc.set_crop_box(1, None).unwrap();
            // A media box narrower than the crop box: the crop box is clipped and written too,
            // so that readers that clip differently agree.
            doc.set_media_box(2, Rect::new(0.0, 0.0, 150.0, 300.0))
                .unwrap();
            // Normalizes the reversed corners.
            let crop = doc.page(3).unwrap().crop_box();
            doc.set_crop_box(3, Some(crop)).unwrap();
        },
    );
    let mut expected = expected;
    expected[2] = ([0.0, 0.0, 150.0, 300.0], [50.0, 50.0, 150.0, 300.0], 0);
    for c in &setters {
        assert_pages(&c.name, &c.pages, &expected);
        // The setters removed the reason for the source's diagnostic.
        assert!(open(&c.pdf).diagnostics().is_empty(), "{}", c.name);
    }
    let mut cases = vec![source_case];
    cases.extend(setters);
    cases
}

/// The cases built from [`model::repeated_page`].
fn repeated_page_cases() -> Vec<Case> {
    let source = model::repeated_page();
    // The repeated listing is the only diagnostic.
    let source_case = case("repeated-page", source.clone(), false, 1);
    let letter = [0.0, 0.0, 612.0, 792.0];
    let small = [0.0, 0.0, 300.0, 400.0];
    let expected = [
        (letter, letter, 90),
        (letter, letter, 90),
        (small, small, 0),
    ];
    assert_pages(&source_case.name, &source_case.pages, &expected);

    let setters = saved_cases("repeated-page-setters", &source, &source_case.name, |doc| {
        // Pages 0 and 1 are the same page object: an edit through either index shows at
        // both.
        doc.set_rotation(1, Rotation::R180).unwrap();
        doc.set_crop_box(0, Some(Rect::new(50.0, 50.0, 400.0, 500.0)))
            .unwrap();
        doc.set_media_box(2, Rect::new(0.0, 0.0, 200.0, 250.0))
            .unwrap();
        assert_eq!(
            doc.store().edited_ids(),
            [ObjectId::new(3, 0), ObjectId::new(4, 0)]
        );
    });
    let crop = [50.0, 50.0, 400.0, 500.0];
    let media = [0.0, 0.0, 200.0, 250.0];
    let expected = [(letter, crop, 180), (letter, crop, 180), (media, media, 0)];
    for c in &setters {
        assert_pages(&c.name, &c.pages, &expected);
    }
    let mut cases = vec![source_case];
    cases.extend(setters);
    cases
}

/// The cases built from [`model::parent_mismatch`].
fn parent_mismatch_cases() -> Vec<Case> {
    let source = model::parent_mismatch();
    let source_diagnostics = {
        let doc = open(&source);
        let _ = page_infos(&doc);
        doc.diagnostics().len()
    };
    let source_case = case("parent-mismatch", source.clone(), false, source_diagnostics);
    let letter = [0.0, 0.0, 612.0, 792.0];
    assert_pages(
        &source_case.name,
        &source_case.pages,
        &[(letter, letter, 0), (letter, letter, 0)],
    );

    let setters = saved_cases(
        "parent-mismatch-setters",
        &source,
        &source_case.name,
        |doc| {
            // Each value a /Parent reader would inherit differently is written on the page.
            doc.set_rotation(0, Rotation::R0).unwrap();
            doc.set_crop_box(0, None).unwrap();
            doc.set_rotation(1, Rotation::R0).unwrap();
            doc.set_media_box(1, Rect::new(0.0, 0.0, 150.0, 150.0))
                .unwrap();
            assert_eq!(
                doc.store().edited_ids(),
                [ObjectId::new(3, 0), ObjectId::new(4, 0)]
            );
        },
    );
    let small = [0.0, 0.0, 150.0, 150.0];
    let expected = [(letter, letter, 0), (small, small, 0)];
    for c in &setters {
        assert_pages(&c.name, &c.pages, &expected);
    }
    let mut cases = vec![source_case];
    cases.extend(setters);
    cases
}

fn cases() -> Vec<Case> {
    let mut cases = inherited_cases();
    cases.extend(rotation_cases());
    cases.extend(crop_box_cases());
    cases.extend(repeated_page_cases());
    cases.extend(parent_mismatch_cases());
    cases
}

#[test]
fn model_oracle_cases() {
    let cases = cases();
    let mut written = 0;
    for case in &cases {
        let path = emit_case(SUITE, &case.name, &case.pdf, &case.expect)
            .unwrap_or_else(|err| panic!("{}: {err}", case.name));
        if path.is_some() {
            written += 1;
        }
    }
    assert!(cases.len() >= MIN_CASES, "only {} cases", cases.len());
    assert_eq!(written, if EMIT_ENABLED { cases.len() } else { 0 });
}

#[test]
fn every_case_checks_every_page() {
    let cases = cases();
    let mut names: Vec<&str> = cases.iter().map(|c| c.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), cases.len(), "duplicate case names");
    for case in &cases {
        // No case is skipped, and every page has an entry with every PageInfo field.
        assert!(case.expect.get("oracleSkip").is_none(), "{}", case.name);
        let boxes: serde_json::Value =
            serde_json::from_str(case.expect.get("boxes").unwrap()).unwrap();
        let boxes = boxes.as_array().unwrap();
        assert_eq!(boxes.len(), case.pages.len(), "{}", case.name);
        assert!(!boxes.is_empty(), "{}", case.name);
        for (i, entry) in boxes.iter().enumerate() {
            let entry = entry.as_object().unwrap();
            for key in [
                "index", "width", "height", "mediaBox", "cropBox", "rotation",
            ] {
                assert!(
                    entry.contains_key(key),
                    "{}: page {i} lacks {key}",
                    case.name
                );
            }
            assert_eq!(entry["index"], i, "{}", case.name);
        }
        // Known failures name only checks of pages the case has.
        for (check, _) in known_failures(&case.name) {
            if let Some(rest) = check.strip_prefix("boxes[") {
                let page: usize = rest.split(']').next().unwrap().parse().unwrap();
                assert!(page < boxes.len(), "{}: {check}", case.name);
            }
        }
    }
    // Every saving path: full with a table, full with object streams, incremental.
    for suffix in ["-full", "-objstm", "-incr"] {
        assert!(
            names.iter().any(|n| n.ends_with(suffix)),
            "no {suffix} case"
        );
    }
}

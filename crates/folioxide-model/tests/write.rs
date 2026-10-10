#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The write side of the document model (M2 brief WP2.3, acceptance criterion 3): new
//! documents, the Info dictionary, page boxes and rotation with inherited values materialized on
//! the page (§7.7.3.4), and round trips through incremental updates and full saves.

mod common;

use common::{build, corners, diagnostics_with, open, open_strict};
use folioxide_model::{DocInfo, Document, InfoUpdate, PageInfo, PdfDate, Rect, Rotation, Trapped};
use folioxide_syntax::{
    DiagnosticKind, ErrorCode, IncrementalOptions, Object, ObjectId, SaveOptions,
    StreamCompression, XrefStyle,
};
use folioxide_testkit::fixtures::{model, syntax};

fn id(num: u32) -> ObjectId {
    ObjectId::new(num, 0)
}

/// The page infos of every page.
fn page_infos(doc: &Document) -> Vec<PageInfo> {
    (0..doc.page_count().unwrap())
        .map(|i| doc.page(i).unwrap().info())
        .collect()
}

/// The object `num` as the document's store resolves it now.
fn object(doc: &Document, num: u32) -> Object {
    Object::clone(&doc.store().resolve(id(num)).unwrap())
}

/// The entry `key` of the dictionary object `num`.
fn entry(doc: &Document, num: u32, key: &[u8]) -> Option<Object> {
    object(doc, num).as_dict().unwrap().get(key).cloned()
}

/// A rectangle as the array a setter writes.
fn rect_object(llx: i64, lly: i64, urx: i64, ury: i64) -> Object {
    Object::Array(vec![
        Object::Int(llx),
        Object::Int(lly),
        Object::Int(urx),
        Object::Int(ury),
    ])
}

/// Saves `doc` incrementally, checks that the original bytes are a prefix and that
/// `incremental_suffix` is the rest, and reopens the result in strict mode: it must have one
/// more revision.
fn save_incremental_and_reopen(doc: &Document, source: &[u8]) -> Document {
    let options = IncrementalOptions::default();
    let out = doc.save_incremental(&options).unwrap();
    assert_eq!(&out[..source.len()], source, "the original bytes are kept");
    assert_eq!(
        &out[source.len()..],
        &doc.incremental_suffix(&options).unwrap()[..]
    );
    let reopened = open_strict(out);
    assert_eq!(
        reopened.store().revisions().len(),
        doc.store().revisions().len() + 1
    );
    reopened
}

/// Saves `doc` with a full rewrite (with and without object streams) and reopens each result in
/// strict mode.
fn save_full_and_reopen(doc: &Document) -> Vec<Document> {
    [
        SaveOptions::default(),
        SaveOptions::default().with_object_streams(true),
    ]
    .iter()
    .map(|options| open_strict(doc.save(options).unwrap()))
    .collect()
}

// ---- the Info dictionary ------------------------------------------------------------------------

/// Setting the Info dictionary of a document without one creates a dictionary object and links
/// it from the trailer; it survives an incremental update (table and stream sections) and a
/// full save.
#[test]
fn set_info_creates_info_dict() {
    for (name, pdf) in [
        ("minimal", syntax::minimal()),
        // Its last revision freed the old /Info: the new one gets a new number.
        ("multi-revision", syntax::multi_revision()),
        ("xref-stream", syntax::xref_stream()),
        ("hybrid", syntax::hybrid()),
    ] {
        let mut doc = open(pdf.clone());
        assert!(doc.store().trailer().get(b"Info").is_none(), "{name}");
        assert_eq!(doc.info().unwrap(), DocInfo::default(), "{name}");
        let next = doc.store().next_object_number();

        doc.set_info(
            &InfoUpdate::default()
                .with_title(Some("Created"))
                .with_producer(Some("folioxide")),
        )
        .unwrap();
        let info_id = doc.store().trailer().get_ref(b"Info").unwrap();
        assert_eq!(info_id, id(next), "{name}: a new object");
        assert_eq!(doc.store().edited_ids(), vec![info_id], "{name}");
        let dict = object(&doc, next);
        let keys: Vec<&[u8]> = dict
            .as_dict()
            .unwrap()
            .keys()
            .map(|k| k.as_bytes())
            .collect();
        assert_eq!(keys, [&b"Title"[..], b"Producer"], "{name}");
        let info = doc.info().unwrap();
        assert_eq!(info.title.as_deref(), Some("Created"), "{name}");
        assert_eq!(info.producer.as_deref(), Some("folioxide"), "{name}");

        let reopened = save_incremental_and_reopen(&doc, &pdf);
        assert_eq!(reopened.info().unwrap(), info, "{name}");
        assert!(reopened.diagnostics().is_empty(), "{name}");
        for full in save_full_and_reopen(&doc) {
            assert_eq!(full.info().unwrap(), info, "{name}");
        }
    }

    // Removing entries from a document without an Info dictionary creates nothing.
    let mut doc = open(syntax::minimal());
    doc.set_info(
        &InfoUpdate::default()
            .with_title(None)
            .with_custom("X", None),
    )
    .unwrap();
    assert!(!doc.is_modified());
    assert!(doc.store().trailer().get(b"Info").is_none());
}

/// An existing Info dictionary is changed in place: the same object, the other entries kept as
/// they are (an indirect `/Producer`, an invalid `/Creator`, a custom entry).
#[test]
fn set_info_edits_in_place() {
    let pdf = model::info_strings();
    let mut doc = open(pdf.clone());
    let before = doc.info().unwrap();
    doc.set_info(
        &InfoUpdate::default()
            .with_title(Some("Replaced"))
            .with_keywords(None),
    )
    .unwrap();
    assert_eq!(doc.store().trailer().get_ref(b"Info"), Some(id(9)));
    assert_eq!(doc.store().edited_ids(), vec![id(9)]);
    assert_eq!(entry(&doc, 9, b"Producer"), Some(Object::Ref(id(8))));
    assert_eq!(entry(&doc, 9, b"Creator"), Some(Object::name("NotAString")));
    assert_eq!(entry(&doc, 9, b"Keywords"), None);

    let mut expected = before;
    expected.title = Some("Replaced".to_owned());
    expected.keywords = None;
    let info = doc.info().unwrap();
    assert_eq!(info, expected);

    let reopened = save_incremental_and_reopen(&doc, &pdf);
    assert_eq!(reopened.info().unwrap(), expected);
    assert_eq!(reopened.store().trailer().get_ref(b"Info"), Some(id(9)));
    for full in save_full_and_reopen(&doc) {
        assert_eq!(full.info().unwrap(), expected);
    }
}

/// AC3 round trip: `set_info` → `save_incremental` → reopen → `info()` is equal, for text that
/// needs UTF-16BE (Cyrillic, CJK, characters outside the BMP), PDFDocEncoding text with
/// typographic characters and characters a literal string escapes, dates with offsets,
/// `/Trapped`, custom entries and removals; after table, stream, hybrid and object-stream
/// revisions. A full save gives the same.
#[test]
fn set_info_roundtrip_incremental() {
    let texts = [
        "\u{41F}\u{440}\u{438}\u{43C}\u{435}\u{440}",
        "\u{65E5}\u{672C}\u{8A9E}\u{306E}\u{30BF}\u{30A4}\u{30C8}\u{30EB}",
        "Zo\u{EB} \u{1F600}",
        "\u{201C}Quotes\u{201D} \u{2014} \u{FB01} \u{20AC}5",
        "(parentheses) \\ backslash\r\nand lines",
        "\u{FE}\u{FF} starts like a byte order mark",
        "",
    ];
    let creation = PdfDate::new(1999, 12, 31, 23, 59, 59)
        .unwrap()
        .with_offset(Some(-480))
        .unwrap();
    let modified = PdfDate::new(2026, 10, 10, 0, 0, 0)
        .unwrap()
        .with_offset(Some(0))
        .unwrap();
    for (name, pdf) in [
        ("minimal", syntax::minimal()),
        ("objstm", syntax::objstm()),
        ("hybrid", syntax::hybrid()),
        ("info", model::info_strings()),
    ] {
        for text in texts {
            let mut doc = open(pdf.clone());
            doc.set_info(
                &InfoUpdate::default()
                    .with_title(Some(text))
                    .with_author(Some("\u{410}\u{432}\u{442}\u{43E}\u{440}"))
                    .with_subject(None)
                    .with_creation_date(Some(creation))
                    .with_mod_date(Some(modified))
                    .with_trapped(Some(Trapped::Unknown))
                    .with_custom("D\u{E9}partement", Some("R&D \u{2014} \u{7814}\u{7A76}"))
                    .with_custom("Company", None),
            )
            .unwrap();
            let info = doc.info().unwrap();
            assert_eq!(info.title.as_deref(), Some(text), "{name}");
            assert_eq!(info.subject, None, "{name}");
            assert_eq!(info.creation_date, Some(creation), "{name}");
            assert_eq!(info.mod_date, Some(modified), "{name}");
            assert_eq!(info.trapped, Some(Trapped::Unknown), "{name}");
            assert_eq!(
                info.custom.get("D\u{E9}partement").map(String::as_str),
                Some("R&D \u{2014} \u{7814}\u{7A76}"),
                "{name}"
            );
            assert_eq!(info.custom.get("Company"), None, "{name}");

            let reopened = save_incremental_and_reopen(&doc, &pdf);
            assert_eq!(reopened.info().unwrap(), info, "{name}: {text:?}");
            for full in save_full_and_reopen(&doc) {
                assert_eq!(full.info().unwrap(), info, "{name}: {text:?}");
            }
        }
    }
}

/// Text outside PDFDocEncoding is written as a hexadecimal UTF-16BE string with a byte order
/// mark; PDFDocEncoded text as a literal string (§7.9.2.2).
#[test]
fn set_info_text_string_encoding() {
    let mut doc = Document::new();
    doc.set_info(
        &InfoUpdate::default()
            .with_title(Some("\u{65E5}\u{672C}"))
            .with_author(Some("Caf\u{E9} \u{2014}")),
    )
    .unwrap();
    let info_id = doc.store().trailer().get_ref(b"Info").unwrap();
    let dict = object(&doc, info_id.num);
    let dict = dict.as_dict().unwrap();
    let title = dict.get_string(b"Title").unwrap();
    assert!(title.hex);
    assert_eq!(title.as_bytes(), b"\xFE\xFF\x65\xE5\x67\x2C");
    let author = dict.get_string(b"Author").unwrap();
    assert!(!author.hex);
    assert_eq!(author.as_bytes(), b"Caf\xE9 \x84");
}

/// Setting what is already there edits nothing, whatever form the old string has.
#[test]
fn set_info_edits_only_what_changes() {
    let mut doc = open(model::info_strings());
    // The empty update; values equal to the current ones (a hexadecimal /Title with the same
    // bytes, the name /False, a literal custom entry); removing an absent entry.
    doc.set_info(&InfoUpdate::default()).unwrap();
    doc.set_info(
        &InfoUpdate::default()
            .with_title(Some("\u{201C}Folio\u{201D} \u{2014} \u{FB01}nal \u{20AC}5"))
            .with_trapped(Some(Trapped::False))
            .with_custom("Company", Some("ACME"))
            .with_custom("Absent", None),
    )
    .unwrap();
    assert!(!doc.is_modified());
    assert_eq!(
        doc.save_incremental(&IncrementalOptions::default())
            .unwrap(),
        model::info_strings()
    );
    assert!(
        doc.incremental_suffix(&IncrementalOptions::default())
            .unwrap()
            .is_empty()
    );
}

/// Custom keys that are empty, longer than 127 bytes (the name limit of ISO 32000-1 Annex C),
/// hold a NUL character or name a standard entry are refused.
#[test]
fn set_info_rejects_invalid_custom_keys() {
    let mut doc = open(model::info_strings());
    let long = "x".repeat(128);
    for key in ["", "Title", "ModDate", "Trapped", "a\0b", &long] {
        let err = doc
            .set_info(
                &InfoUpdate::default()
                    .with_title(Some("ignored"))
                    .with_custom(key, Some("x")),
            )
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{key:?}");
    }
    assert!(!doc.is_modified());
    // 127 bytes is the longest key; it is written as it is.
    let longest = "y".repeat(127);
    doc.set_info(&InfoUpdate::default().with_custom(&longest, Some("v")))
        .unwrap();
    let pdf = doc.save(&SaveOptions::default()).unwrap();
    assert!(
        pdf.windows(128)
            .any(|w| w[0] == b'/' && w[1..] == *longest.as_bytes())
    );
    assert_eq!(
        open_strict(pdf).info().unwrap().custom.get(&longest),
        Some(&"v".to_owned())
    );
}

/// A key a set refuses can still be removed: an entry a file has with an overlong name (which
/// poppler warns about) is taken out.
#[test]
fn set_info_removes_an_overlong_key() {
    let long = "K".repeat(200);
    let info = format!("<< /Title (T) /{long} (too long) >>");
    let pdf = build(
        "1.4",
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [] /Count 0 >>"),
            (3, &info),
        ],
        "/Info 3 0 R",
    );
    let mut doc = open(pdf.clone());
    assert!(doc.info().unwrap().custom.contains_key(&long));
    doc.set_info(&InfoUpdate::default().with_custom(&long, None))
        .unwrap();
    let reopened = save_incremental_and_reopen(&doc, &pdf);
    let info = reopened.info().unwrap();
    assert!(info.custom.is_empty(), "{info:?}");
    assert_eq!(info.title.as_deref(), Some("T"));
}

/// An `/Info` that is a direct dictionary, not a dictionary at all, or a reference to a free
/// object is replaced by a new dictionary object (its entries kept when it was a dictionary).
#[test]
fn set_info_replaces_a_direct_or_broken_info() {
    const CATALOG: &str = "<< /Type /Catalog /Pages 2 0 R >>";
    const PAGES: &str = "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>";
    const PAGE: &str = "<< /Type /Page /Parent 2 0 R >>";

    // A direct dictionary (§14.3.3 asks for an indirect reference).
    let pdf = build(
        "1.4",
        &[(1, CATALOG), (2, PAGES), (3, PAGE)],
        "/Info << /Title (Direct) /Author (Kept) >>",
    );
    let mut doc = open(pdf.clone());
    assert_eq!(doc.info().unwrap().title.as_deref(), Some("Direct"));
    doc.set_info(&InfoUpdate::default().with_title(Some("New")))
        .unwrap();
    let info_id = doc.store().trailer().get_ref(b"Info").unwrap();
    assert_eq!(info_id, id(4));
    let info = doc.info().unwrap();
    assert_eq!(info.title.as_deref(), Some("New"));
    assert_eq!(info.author.as_deref(), Some("Kept"));
    assert_eq!(
        save_incremental_and_reopen(&doc, &pdf).info().unwrap(),
        info
    );

    // Not a dictionary: replaced, with a metadata diagnostic.
    let pdf = build(
        "1.4",
        &[
            (1, CATALOG),
            (2, PAGES),
            (3, PAGE),
            (4, "(not a dictionary)"),
        ],
        "/Info 4 0 R",
    );
    let mut doc = open(pdf.clone());
    doc.set_info(&InfoUpdate::default().with_title(Some("New")))
        .unwrap();
    assert_eq!(doc.store().trailer().get_ref(b"Info"), Some(id(5)));
    let replaced = diagnostics_with(&doc, "replaced by a new Info dictionary");
    assert_eq!(replaced.len(), 1);
    assert_eq!(replaced[0].kind, DiagnosticKind::Metadata);
    assert_eq!(
        save_incremental_and_reopen(&doc, &pdf)
            .info()
            .unwrap()
            .title
            .as_deref(),
        Some("New")
    );

    // A reference to an object that does not exist.
    let pdf = build("1.4", &[(1, CATALOG), (2, PAGES), (3, PAGE)], "/Info 9 0 R");
    let mut doc = open(pdf.clone());
    doc.set_info(&InfoUpdate::default().with_author(Some("A")))
        .unwrap();
    let info_id = doc.store().trailer().get_ref(b"Info").unwrap();
    assert_ne!(info_id, id(9));
    assert_eq!(
        save_incremental_and_reopen(&doc, &pdf)
            .info()
            .unwrap()
            .author
            .as_deref(),
        Some("A")
    );
}

// ---- page boxes and rotation ----------------------------------------------------------------

/// AC3: the setters write inherited values on the page object, never on the `/Pages` node they
/// come from, so the sibling pages keep what they inherit (§7.7.3.4); the changes survive an
/// incremental update and a full save.
#[test]
fn setter_materializes_inherited_box() {
    let pdf = model::inherited_attributes();
    let mut doc = open(pdf.clone());
    let before = page_infos(&doc);
    let nodes_before: Vec<Object> = [2, 3, 10].iter().map(|&n| object(&doc, n)).collect();

    // Page 0 (object 4) inherits its media box from its grandparent 2 and its crop box from 3.
    assert_eq!(entry(&doc, 4, b"MediaBox"), None);
    assert_eq!(entry(&doc, 4, b"CropBox"), None);
    doc.set_media_box(0, Rect::new(0.0, 0.0, 612.0, 792.0))
        .unwrap();
    assert_eq!(
        entry(&doc, 4, b"MediaBox"),
        Some(rect_object(0, 0, 612, 792))
    );
    // The inherited crop box [10 10 585 800] reaches above the new media box: it is
    // materialized on the page, clipped, so that every reader shows the same crop box.
    assert_eq!(
        entry(&doc, 4, b"CropBox"),
        Some(rect_object(10, 10, 585, 792))
    );
    let page = doc.page(0).unwrap();
    assert_eq!(corners(page.media_box()), [0.0, 0.0, 612.0, 792.0]);
    assert_eq!(corners(page.crop_box()), [10.0, 10.0, 585.0, 792.0]);
    // The rotation is still inherited.
    assert_eq!(page.rotation(), Rotation::R90);
    assert_eq!(entry(&doc, 4, b"Rotate"), None);

    // Page 2 (object 11) inherits /Rotate -90 from node 10; page 3 (object 12) is a sibling.
    doc.set_rotation(2, Rotation::R0).unwrap();
    assert_eq!(entry(&doc, 11, b"Rotate"), Some(Object::Int(0)));
    assert_eq!(doc.page(2).unwrap().rotation(), Rotation::R0);

    // Page 1 (object 5) inherits its crop box from node 3: removing the crop box writes the
    // media box as the page's crop box, since removing nothing would keep the inherited one.
    doc.set_crop_box(1, None).unwrap();
    assert_eq!(
        entry(&doc, 5, b"CropBox"),
        Some(rect_object(0, 0, 612, 792))
    );
    let page = doc.page(1).unwrap();
    assert_eq!(page.crop_box(), page.media_box());

    // Page 3 (object 12) has a crop box of its own: the new one replaces it, clipped to the
    // media box.
    doc.set_crop_box(3, Some(Rect::new(-50.0, -50.0, 250.0, 350.0)))
        .unwrap();
    assert_eq!(
        entry(&doc, 12, b"CropBox"),
        Some(rect_object(0, 0, 250, 350))
    );

    // Only the pages changed; the /Pages nodes are untouched.
    assert_eq!(doc.store().edited_ids(), vec![id(4), id(5), id(11), id(12)]);
    let nodes_after: Vec<Object> = [2, 3, 10].iter().map(|&n| object(&doc, n)).collect();
    assert_eq!(nodes_after, nodes_before);
    let after = page_infos(&doc);
    assert_eq!(after[0].rotation, before[0].rotation);
    assert_eq!(after[3].media_box, before[3].media_box);
    assert_eq!(after[3].rotation, before[3].rotation);
    assert_eq!((after[0].width, after[0].height), (782.0, 575.0));
    assert_eq!((after[3].width, after[3].height), (250.0, 350.0));

    // Reopened after an incremental update (same object numbers) and after full saves.
    let reopened = save_incremental_and_reopen(&doc, &pdf);
    assert_eq!(page_infos(&reopened), after);
    let nodes_reopened: Vec<Object> = [2, 3, 10].iter().map(|&n| object(&reopened, n)).collect();
    assert_eq!(nodes_reopened, nodes_before);
    assert!(
        reopened.diagnostics().is_empty(),
        "{:?}",
        reopened.diagnostics()
    );
    for full in save_full_and_reopen(&doc) {
        assert_eq!(page_infos(&full), after);
    }
}

/// The media box setter clips the page's crop box into the new media box, or drops it when
/// they no longer overlap.
#[test]
fn set_media_box_clips_the_crop_box() {
    let pdf = model::inherited_attributes();
    let mut doc = open(pdf.clone());
    // Page 1 (object 5) has its own media box and inherits the crop box [10 10 585 800].
    doc.set_media_box(1, Rect::new(0.0, 0.0, 300.0, 300.0))
        .unwrap();
    assert_eq!(
        entry(&doc, 5, b"MediaBox"),
        Some(rect_object(0, 0, 300, 300))
    );
    assert_eq!(
        entry(&doc, 5, b"CropBox"),
        Some(rect_object(10, 10, 300, 300))
    );

    // Page 3 (object 12) has its own crop box and none to inherit: a media box that does not
    // overlap it removes it (the crop box becomes the media box).
    doc.set_media_box(3, Rect::new(400.0, 500.0, 500.0, 600.0))
        .unwrap();
    assert_eq!(entry(&doc, 12, b"CropBox"), None);
    let page = doc.page(3).unwrap();
    assert_eq!(corners(page.crop_box()), [400.0, 500.0, 500.0, 600.0]);
    // A crop box inside the new media box stays as it is: page 0 inherits [10 10 585 800].
    doc.set_media_box(0, Rect::new(0.0, 0.0, 1000.0, 1000.0))
        .unwrap();
    assert_eq!(entry(&doc, 4, b"CropBox"), None);
    assert_eq!(
        corners(doc.page(0).unwrap().crop_box()),
        [10.0, 10.0, 585.0, 800.0]
    );

    let infos = page_infos(&doc);
    assert_eq!(page_infos(&save_incremental_and_reopen(&doc, &pdf)), infos);
}

/// A page without any valid media box gets the US Letter box readers assume written on it when
/// its crop box is set (§7.7.3.3 requires a media box).
#[test]
fn set_crop_box_materializes_the_default_media_box() {
    let pdf = build(
        "1.4",
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (3, "<< /Type /Page /Parent 2 0 R >>"),
        ],
        "",
    );
    let mut doc = open(pdf.clone());
    doc.set_crop_box(0, Some(Rect::new(0.0, 0.0, 100.0, 100.0)))
        .unwrap();
    assert_eq!(
        entry(&doc, 3, b"MediaBox"),
        Some(rect_object(0, 0, 612, 792))
    );
    assert_eq!(
        entry(&doc, 3, b"CropBox"),
        Some(rect_object(0, 0, 100, 100))
    );
    let reopened = save_incremental_and_reopen(&doc, &pdf);
    assert!(
        reopened.diagnostics().is_empty(),
        "{:?}",
        reopened.diagnostics()
    );
    assert_eq!(
        corners(reopened.page(0).unwrap().crop_box()),
        [0.0, 0.0, 100.0, 100.0]
    );
}

/// The rotation setter normalizes the page's own value, overrides an inherited or invalid one,
/// and edits nothing when the page already has the value.
#[test]
fn set_rotation_cases() {
    let pdf = model::rotations();
    let mut doc = open(pdf.clone());
    // Page 6 (object 16) has /Rotate 450: setting 90 writes the normalized value.
    doc.set_rotation(6, Rotation::R90).unwrap();
    assert_eq!(entry(&doc, 16, b"Rotate"), Some(Object::Int(90)));
    // Page 10 (object 20) has /Rotate /Ninety, so it inherits 180: setting 180 replaces the
    // invalid value.
    doc.set_rotation(10, Rotation::R180).unwrap();
    assert_eq!(entry(&doc, 20, b"Rotate"), Some(Object::Int(180)));
    // Page 1 (object 11) already has /Rotate 90.
    let edited = doc.store().edited_ids();
    doc.set_rotation(1, Rotation::R90).unwrap();
    assert_eq!(doc.store().edited_ids(), edited);
    let rotations: Vec<Rotation> = page_infos(&doc).iter().map(|p| p.rotation).collect();
    let reopened = save_incremental_and_reopen(&doc, &pdf);
    let reopened_rotations: Vec<Rotation> =
        page_infos(&reopened).iter().map(|p| p.rotation).collect();
    assert_eq!(reopened_rotations, rotations);

    // No /Rotate anywhere: R0 edits nothing; another value is written, and R0 then too.
    let pdf = syntax::minimal();
    let mut doc = open(pdf.clone());
    doc.set_rotation(0, Rotation::R0).unwrap();
    assert!(!doc.is_modified());
    doc.set_rotation(0, Rotation::R270).unwrap();
    assert_eq!(entry(&doc, 3, b"Rotate"), Some(Object::Int(270)));
    assert_eq!(
        save_incremental_and_reopen(&doc, &pdf)
            .page(0)
            .unwrap()
            .rotation(),
        Rotation::R270
    );
    doc.set_rotation(0, Rotation::R0).unwrap();
    assert_eq!(entry(&doc, 3, b"Rotate"), Some(Object::Int(0)));
}

/// Setting a value the page already has edits nothing, so an incremental update stays empty.
#[test]
fn setters_edit_only_what_changes() {
    let pdf = model::inherited_attributes();
    let mut doc = open(pdf.clone());
    // Page 1 (object 5) has its own media box (given here with its corners swapped) and
    // /Rotate 0. Its inherited crop box reaches outside the media box, but since the media box
    // does not change, neither does the crop box.
    doc.set_media_box(1, Rect::new(612.0, 792.0, 0.0, 0.0))
        .unwrap();
    doc.set_rotation(1, Rotation::R0).unwrap();
    assert!(!doc.is_modified());
    // Page 3 (object 12): its own crop box [-100 -100 300 400] is written clipped; setting the
    // same box again changes nothing more.
    doc.set_crop_box(3, Some(Rect::new(0.0, 0.0, 300.0, 400.0)))
        .unwrap();
    let edited = object(&doc, 12);
    doc.set_crop_box(3, Some(Rect::new(0.0, 0.0, 300.0, 400.0)))
        .unwrap();
    assert_eq!(object(&doc, 12), edited);
    assert_eq!(doc.store().edited_ids(), vec![id(12)]);
}

/// Invalid rectangles and page indices are refused without editing anything.
#[test]
fn setters_reject_invalid_input() {
    let mut doc = open(model::inherited_attributes());
    let mut bad = vec![
        Rect::new(0.0, 0.0, 0.0, 100.0),
        Rect::new(0.0, 0.0, f64::NAN, 100.0),
        Rect::new(0.0, 0.0, f64::INFINITY, 100.0),
        Rect::new(-1e39, 0.0, 100.0, 100.0),
    ];
    // Public fields can make a rectangle that `Rect::new` would not.
    let mut swapped = Rect::new(0.0, 0.0, 100.0, 100.0);
    swapped.urx = -1.0;
    swapped.llx = 1.0;
    let zero_width = {
        let mut r = Rect::new(0.0, 0.0, 100.0, 100.0);
        r.urx = 0.0;
        r
    };
    bad.push(zero_width);
    for rect in &bad {
        let err = doc.set_media_box(0, *rect).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{rect:?}");
        let err = doc.set_crop_box(0, Some(*rect)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{rect:?}");
    }
    // A crop box outside the media box.
    let err = doc
        .set_crop_box(0, Some(Rect::new(1000.0, 1000.0, 1100.0, 1100.0)))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.to_string().contains("does not overlap"), "{err}");
    // Page indices past the end.
    let letter = Rect::new(0.0, 0.0, 612.0, 792.0);
    assert_eq!(
        doc.set_media_box(4, letter).unwrap_err().code(),
        ErrorCode::PageOutOfRange
    );
    assert_eq!(
        doc.set_crop_box(4, None).unwrap_err().code(),
        ErrorCode::PageOutOfRange
    );
    assert_eq!(
        doc.set_rotation(4, Rotation::R90).unwrap_err().code(),
        ErrorCode::PageOutOfRange
    );
    assert!(!doc.is_modified());
    // A rectangle whose corners are swapped is normalized, not refused.
    doc.set_media_box(0, swapped).unwrap();
    assert_eq!(
        entry(&doc, 4, b"MediaBox"),
        Some(rect_object(-1, 0, 1, 100))
    );
}

/// A box is checked as it will be written: reals have at most 10 fractional digits, so a box
/// that rounds to no area is refused (it would reopen as an invalid box, and readers would fall
/// back to US Letter), and the document in memory holds the rounded box its saved file holds.
#[test]
fn setters_round_boxes_as_written() {
    let pdf = model::inherited_attributes();
    let mut doc = open(pdf.clone());
    for rect in [
        Rect::new(0.0, 0.0, 1e-12, 1e-12),
        Rect::new(0.1, 0.0, 0.1 + 1e-12, 10.0),
        Rect::new(-4e-11, -4e-11, 4e-11, 100.0),
    ] {
        let err = doc.set_media_box(0, rect).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{rect:?}");
        assert!(err.to_string().contains("10 fractional digits"), "{err}");
        let err = doc.set_crop_box(0, Some(rect)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{rect:?}");
    }
    assert!(!doc.is_modified());

    // 0.1 + 0.2 is written as 0.3, and 1/3 with 10 fractional digits: the page says so before
    // the save already.
    let media = Rect::new(0.0, 0.0, 0.1 + 0.2, 1000.0 / 3.0);
    doc.set_media_box(3, media).unwrap();
    doc.set_crop_box(2, Some(Rect::new(0.25, 1e-11, 100.0 / 7.0, 200.0)))
        .unwrap();
    let expected_media = Rect::new(0.0, 0.0, 0.3, 333.3333333333);
    assert_eq!(doc.page(3).unwrap().media_box(), expected_media);
    assert_eq!(
        doc.page(2).unwrap().crop_box(),
        Rect::new(0.25, 0.0, 14.2857142857, 200.0)
    );
    // Setting the same box again changes nothing.
    let edited = object(&doc, 12);
    doc.set_media_box(3, media).unwrap();
    assert_eq!(object(&doc, 12), edited);
    let infos = page_infos(&doc);
    assert_eq!(page_infos(&save_incremental_and_reopen(&doc, &pdf)), infos);
    for full in save_full_and_reopen(&doc) {
        assert_eq!(page_infos(&full), infos);
    }

    // A crop box is clipped to the media box, then rounded: here the media box of the file has
    // more digits than are written, and the clipped box rounds to no area.
    let pdf = build(
        "1.4",
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 0.00000000014 10] >>",
            ),
        ],
        "",
    );
    let mut doc = open(pdf);
    let err = doc
        .set_crop_box(0, Some(Rect::new(0.0000000001, 0.0, 1.0, 10.0)))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.to_string().contains("does not overlap"), "{err}");
    assert!(!doc.is_modified());
}

/// When a `/Parent` disagrees with the page tree, readers that inherit along `/Parent` (pdf.js;
/// qpdf for the crop box and the rotation) see other inherited values than those read along the
/// tree (poppler, us). The setters count a value inherited either way, so that after the edit every reader
/// shows the value set: `/Rotate 0` and the default crop box are written on the page instead of
/// being left to inheritance.
#[test]
fn setters_follow_the_parent_chain() {
    let pdf = model::parent_mismatch();
    let mut doc = open(pdf.clone());
    // What we (and poppler) read: two upright US Letter pages, no crop box.
    for page in page_infos(&doc) {
        assert_eq!(page.media_box, Rect::US_LETTER);
        assert_eq!(page.crop_box, Rect::US_LETTER);
        assert_eq!(page.rotation, Rotation::R0);
    }
    assert_eq!(doc.page(0).unwrap().ancestors(), &[id(2)]);
    let nodes_before: Vec<Object> = [2, 5, 6].iter().map(|&n| object(&doc, n)).collect();

    // Page 0 (object 3) has /Parent 5 0 R, which has /Rotate 90, a /CropBox and an A4-like
    // /MediaBox: R0 is written, and removing the crop box writes the media box as the crop box,
    // and as the media box too (the two paths give different media boxes to clip it to).
    doc.set_rotation(0, Rotation::R0).unwrap();
    assert!(doc.is_modified());
    assert_eq!(entry(&doc, 3, b"Rotate"), Some(Object::Int(0)));
    doc.set_crop_box(0, None).unwrap();
    assert_eq!(
        entry(&doc, 3, b"CropBox"),
        Some(rect_object(0, 0, 612, 792))
    );
    assert_eq!(
        entry(&doc, 3, b"MediaBox"),
        Some(rect_object(0, 0, 612, 792))
    );

    // Page 1 (object 4) has the right /Parent, but the root has /Parent 6 0 R (prohibited),
    // whose /Rotate 180 and /CropBox [20 20 200 200] a /Parent reader inherits. R0 is written;
    // a media box under that crop box writes the crop box readers along the tree see (the
    // default, the media box), so that no reader clips [20 20 200 200].
    doc.set_rotation(1, Rotation::R0).unwrap();
    assert_eq!(entry(&doc, 4, b"Rotate"), Some(Object::Int(0)));
    doc.set_media_box(1, Rect::new(0.0, 0.0, 150.0, 150.0))
        .unwrap();
    assert_eq!(
        entry(&doc, 4, b"MediaBox"),
        Some(rect_object(0, 0, 150, 150))
    );
    assert_eq!(
        entry(&doc, 4, b"CropBox"),
        Some(rect_object(0, 0, 150, 150))
    );

    // Only the two pages changed.
    assert_eq!(doc.store().edited_ids(), vec![id(3), id(4)]);
    let nodes_after: Vec<Object> = [2, 5, 6].iter().map(|&n| object(&doc, n)).collect();
    assert_eq!(nodes_after, nodes_before);
    let infos = page_infos(&doc);
    assert_eq!(infos[1].crop_box, Rect::new(0.0, 0.0, 150.0, 150.0));
    let reopened = save_incremental_and_reopen(&doc, &pdf);
    assert_eq!(page_infos(&reopened), infos);
    for full in save_full_and_reopen(&doc) {
        assert_eq!(page_infos(&full), infos);
    }

    // A crop box inside the new media box on the /Parent path only is written as the crop box
    // read along the tree; one inside along both paths is left alone.
    let mut doc = open(pdf.clone());
    doc.set_media_box(0, Rect::new(0.0, 0.0, 600.0, 600.0))
        .unwrap();
    assert_eq!(entry(&doc, 3, b"CropBox"), None);
    doc.set_media_box(0, Rect::new(0.0, 0.0, 250.0, 250.0))
        .unwrap();
    assert_eq!(
        entry(&doc, 3, b"CropBox"),
        Some(rect_object(0, 0, 250, 250))
    );

    // A /Parent chain that loops, or runs past the depth limit, ends.
    let pdf = build(
        "1.4",
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (
                2,
                "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 612 792] >>",
            ),
            (3, "<< /Type /Page /Parent 5 0 R >>"),
            (4, "<< /Type /Page /Parent 4 0 R >>"),
            (5, "<< /Type /Pages /Parent 6 0 R /Kids [] /Count 0 >>"),
            (
                6,
                "<< /Type /Pages /Parent 5 0 R /Kids [] /Count 0 /Rotate 90 >>",
            ),
        ],
        "",
    );
    let mut doc = open(pdf);
    doc.set_rotation(0, Rotation::R0).unwrap();
    assert_eq!(entry(&doc, 3, b"Rotate"), Some(Object::Int(0)));
    // Page 1 is its own /Parent: nothing above it has a /Rotate.
    doc.set_rotation(1, Rotation::R0).unwrap();
    assert_eq!(doc.store().edited_ids(), vec![id(3)]);
}

/// Setters work on pages stored in object streams; the update rewrites them as plain objects.
#[test]
fn setters_on_compressed_pages() {
    let pdf = syntax::objstm();
    let mut doc = open(pdf.clone());
    doc.set_media_box(0, Rect::new(0.0, 0.0, 420.0, 595.0))
        .unwrap();
    doc.set_rotation(0, Rotation::R180).unwrap();
    doc.set_crop_box(0, Some(Rect::new(10.0, 10.0, 410.0, 585.0)))
        .unwrap();
    doc.set_info(&InfoUpdate::default().with_title(Some("A5")))
        .unwrap();
    let infos = page_infos(&doc);
    let reopened = save_incremental_and_reopen(&doc, &pdf);
    assert_eq!(page_infos(&reopened), infos);
    assert_eq!(reopened.info().unwrap().title.as_deref(), Some("A5"));
    for full in save_full_and_reopen(&doc) {
        assert_eq!(page_infos(&full), infos);
    }
}

/// The setters keep the cached page-tree walk (they change no key the walk reads); an edit of
/// an object of the page tree drops it.
#[test]
fn setters_keep_the_cached_page_tree() {
    let cached = |doc: &Document| format!("{doc:?}").contains("pages: Some(");
    let mut doc = open(model::inherited_attributes());
    assert_eq!(doc.page_count().unwrap(), 4);
    assert!(cached(&doc));
    doc.set_media_box(0, Rect::new(0.0, 0.0, 612.0, 792.0))
        .unwrap();
    doc.set_crop_box(1, None).unwrap();
    doc.set_rotation(2, Rotation::R0).unwrap();
    doc.set_info(&InfoUpdate::default().with_title(Some("Cached")))
        .unwrap();
    assert!(cached(&doc));

    // A hostile file whose Info dictionary is the page-tree root: changing it drops the walk.
    let pdf = build(
        "1.4",
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (
                2,
                "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] /Title (Tree) >>",
            ),
            (3, "<< /Type /Page /Parent 2 0 R >>"),
        ],
        "/Info 2 0 R",
    );
    let mut doc = open(pdf);
    assert_eq!(doc.page_count().unwrap(), 1);
    assert_eq!(doc.info().unwrap().title.as_deref(), Some("Tree"));
    doc.set_info(&InfoUpdate::default().with_custom("Note", Some("x")))
        .unwrap();
    assert!(!cached(&doc));
    assert_eq!(doc.page_count().unwrap(), 1);
    // store_mut drops it too.
    assert!(cached(&doc));
    let _ = doc.store_mut();
    assert!(!cached(&doc));
}

/// `PageInfo` gathers what the page accessors say.
#[test]
fn page_info_matches_the_accessors() {
    let doc = open(model::inherited_attributes());
    for (i, expected) in model::INHERITED_PAGES.iter().enumerate() {
        let page = doc.page(i).unwrap();
        let info = page.info();
        assert_eq!(info.index, i);
        assert_eq!(info.media_box, page.media_box());
        assert_eq!(info.crop_box, page.crop_box());
        assert_eq!(info.rotation, page.rotation());
        assert_eq!((info.width, info.height), page.effective_size());
        assert_eq!(corners(info.media_box), expected.media_box);
        assert_eq!(corners(info.crop_box), expected.crop_box);
        assert_eq!(info.rotation.degrees(), expected.rotate);
    }
}

// ---- new documents and saving -----------------------------------------------------------------

/// AC3: `Document::new` is an empty, valid PDF 1.7 document; every full-save variant reopens in
/// strict mode with no diagnostics, and the saved file takes an incremental update.
#[test]
fn new_document_saves_valid() {
    let doc = Document::new();
    assert_eq!(doc.page_count().unwrap(), 0);
    assert_eq!(doc.version(), (1, 7));
    assert_eq!(doc.info().unwrap(), DocInfo::default());
    assert!(doc.diagnostics().is_empty());
    assert!(doc.is_modified());
    assert!(!doc.store().has_source());
    let catalog = doc.catalog().unwrap();
    assert!(catalog.as_dict().unwrap().is_type(b"Catalog"));
    assert!(matches!(doc.page(0), Err(e) if e.code() == ErrorCode::PageOutOfRange));

    for options in [
        SaveOptions::default(),
        SaveOptions::default().with_object_streams(true),
        SaveOptions::default().with_xref(XrefStyle::Table),
        SaveOptions::default().with_xref(XrefStyle::Stream),
        SaveOptions::default().with_renumber(false),
        SaveOptions::default().with_compress(StreamCompression::Keep),
        SaveOptions::default().with_deterministic(true),
    ] {
        let pdf = doc.save(&options).unwrap();
        assert!(pdf.starts_with(b"%PDF-1.7\n"), "{options:?}");
        assert_eq!(
            doc.save(&options).unwrap(),
            pdf,
            "deterministic: {options:?}"
        );
        let mut reopened = open_strict(pdf.clone());
        assert_eq!(reopened.page_count().unwrap(), 0);
        assert_eq!(reopened.version(), (1, 7));
        assert!(
            reopened.diagnostics().is_empty(),
            "{:?}",
            reopened.diagnostics()
        );
        assert!(!reopened.store().structure_repaired());
        assert_eq!(reopened.store().revisions().len(), 1);
        let catalog = reopened.catalog().unwrap();
        let catalog = catalog.as_dict().unwrap();
        assert!(catalog.is_type(b"Catalog"));
        let pages = reopened
            .store()
            .deref(catalog.get(b"Pages").unwrap())
            .unwrap();
        let pages = pages.as_dict().unwrap();
        assert!(pages.is_type(b"Pages"));
        assert_eq!(pages.get_int(b"Count"), Some(0));
        assert_eq!(pages.get_array(b"Kids"), Some(&[][..]));

        // The saved file takes an incremental update.
        reopened
            .set_info(&InfoUpdate::default().with_title(Some("Second revision")))
            .unwrap();
        let updated = save_incremental_and_reopen(&reopened, &pdf);
        assert_eq!(
            updated.info().unwrap().title.as_deref(),
            Some("Second revision")
        );
    }

    // A new document has no file to append to.
    let options = IncrementalOptions::default();
    assert_eq!(
        doc.save_incremental(&options).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        doc.incremental_suffix(&options).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    // `Default` is `new`.
    let options = SaveOptions::default();
    assert_eq!(
        Document::default().save(&options).unwrap(),
        doc.save(&options).unwrap()
    );
}

/// A new document with an Info dictionary saves and reopens with it.
#[test]
fn new_document_with_info() {
    let mut doc = Document::new();
    let date = PdfDate::new(2026, 10, 10, 8, 0, 0)
        .unwrap()
        .with_offset(Some(120))
        .unwrap();
    doc.set_info(
        &InfoUpdate::default()
            .with_title(Some("\u{41D}\u{43E}\u{432}\u{44B}\u{439} \u{1F4C4}"))
            .with_creator(Some("folioxide"))
            .with_creation_date(Some(date))
            .with_mod_date(Some(date)),
    )
    .unwrap();
    let info = doc.info().unwrap();
    for reopened in save_full_and_reopen(&doc) {
        assert_eq!(reopened.info().unwrap(), info);
        assert!(
            reopened.diagnostics().is_empty(),
            "{:?}",
            reopened.diagnostics()
        );
    }
}

/// Saving delegates to the writer: an unedited document saves incrementally as its own bytes,
/// and `is_modified` follows the edits.
#[test]
fn save_delegates_to_the_writer() {
    let pdf = model::inherited_attributes();
    let mut doc = open(pdf.clone());
    assert!(!doc.is_modified());
    assert_eq!(
        doc.save_incremental(&IncrementalOptions::default())
            .unwrap(),
        pdf
    );
    assert_eq!(
        doc.save(&SaveOptions::default()).unwrap(),
        doc.store().save(&SaveOptions::default()).unwrap()
    );
    doc.set_rotation(0, Rotation::R0).unwrap();
    assert!(doc.is_modified());

    // A repaired structure cannot be updated incrementally; a full save is required.
    let mut doc = open(syntax::missing_xref());
    assert!(doc.store().structure_repaired());
    doc.set_info(&InfoUpdate::default().with_title(Some("Repaired")))
        .unwrap();
    assert_eq!(
        doc.save_incremental(&IncrementalOptions::default())
            .unwrap_err()
            .code(),
        ErrorCode::Unsupported
    );
    let full = open_strict(doc.save(&SaveOptions::default()).unwrap());
    assert_eq!(full.info().unwrap().title.as_deref(), Some("Repaired"));
}

// ---- diagnostics --------------------------------------------------------------------------------

/// The model's diagnostics carry the model's kinds, never `Other`.
#[test]
fn model_diagnostic_kinds() {
    let kinds_of = |doc: &Document, needle: &str| -> Vec<DiagnosticKind> {
        diagnostics_with(doc, needle)
            .iter()
            .map(|d| d.kind)
            .collect()
    };
    let doc = open(model::wrong_count());
    doc.page_count().unwrap();
    let kinds = kinds_of(&doc, "page tree:");
    assert!(!kinds.is_empty());
    assert!(
        kinds.iter().all(|&k| k == DiagnosticKind::PageTree),
        "{kinds:?}"
    );

    let doc = open(model::rotations());
    for i in 0..doc.page_count().unwrap() {
        doc.page(i).unwrap().rotation();
    }
    let kinds = kinds_of(&doc, "Rotate");
    assert!(!kinds.is_empty());
    assert!(
        kinds.iter().all(|&k| k == DiagnosticKind::PageAttribute),
        "{kinds:?}"
    );

    let doc = open(model::info_strings());
    doc.info().unwrap();
    let kinds = kinds_of(&doc, "info:");
    assert!(!kinds.is_empty());
    assert!(
        kinds.iter().all(|&k| k == DiagnosticKind::Metadata),
        "{kinds:?}"
    );

    let doc = open(build(
        "1.4",
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R /Version (1.7) >>"),
            (2, "<< /Type /Pages /Kids [] /Count 0 >>"),
        ],
        "",
    ));
    doc.version();
    assert_eq!(kinds_of(&doc, "version:"), [DiagnosticKind::Catalog]);

    // No model diagnostic of any model fixture is `Other`.
    for pdf in [
        model::inherited_attributes(),
        model::rotations(),
        model::page_tree_cycle(),
        model::wrong_count(),
        model::trees(),
        model::info_strings(),
    ] {
        let doc = open(pdf);
        let store_count = doc.store().diagnostics().len();
        for i in 0..doc.page_count().unwrap() {
            let _ = doc.page(i).unwrap().info();
            let _ = doc.page(i).unwrap().resources();
        }
        let _ = doc.info();
        let _ = doc.version();
        let diagnostics = doc.diagnostics();
        assert!(
            diagnostics[store_count..]
                .iter()
                .all(|d| d.kind != DiagnosticKind::Other),
            "{diagnostics:?}"
        );
    }
}

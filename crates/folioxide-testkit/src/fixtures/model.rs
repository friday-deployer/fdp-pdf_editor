//! Document-model fixtures (M2): page trees with inherited attributes, rotations, crop boxes that
//! readers clip differently, broken page trees, name and number trees, and Info dictionaries
//! with every text-string encoding (ISO 32000-2 §7.7.3, §7.9, §14.3.3, §14.11.2; ARCHITECTURE
//! §A.10 traps #10 and #17).
//!
//! The files are generated at test time and not committed. Each function documents the
//! structure it builds and what a correct reader sees; the `folioxide-model` tests check those
//! expectations. Every file has a classic cross-reference table and a fixed `/ID`.
//!
//! ```
//! use folioxide_testkit::fixtures::model;
//!
//! let pdf = model::inherited_attributes();
//! assert!(pdf.starts_with(b"%PDF-1.7"));
//! ```

use super::id_array;
use crate::builder::{PdfBuilder, XrefOpts};

/// A content stream that shows `text` with font `/F1` at 12 points.
fn content(text: &str) -> Vec<u8> {
    format!("BT /F1 12 Tf 72 700 Td ({text}) Tj ET").into_bytes()
}

/// A Type 1 standard font dictionary.
fn font(base: &str) -> String {
    format!("<< /Type /Font /Subtype /Type1 /BaseFont /{base} >>")
}

/// Builds a file with a classic cross-reference table: the dictionaries `objects`, then the
/// content streams `streams`, in the order given, with `/Root 1 0 R` and `trailer_extra` in the
/// trailer.
fn document(
    name: &str,
    version: &str,
    objects: &[(u32, String)],
    streams: &[(u32, Vec<u8>)],
    trailer_extra: &str,
) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header(version);
    for (num, body) in objects {
        b.obj(*num, 0, body);
    }
    for (num, data) in streams {
        b.stream_obj(*num, 0, "", data, None);
    }
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R {trailer_extra} /ID {}",
        b.size(),
        id_array(name)
    );
    b.trailer(trailer).startxref(None).eof();
    b.build()
}

/// The pages of [`inherited_attributes`], in order, with what a reader sees on each: media box,
/// crop box, `/Rotate` in degrees, and the resource font names.
pub const INHERITED_PAGES: [InheritedPage; 4] = [
    InheritedPage {
        id: 4,
        media_box: [0.0, 0.0, 595.0, 842.0],
        crop_box: [10.0, 10.0, 585.0, 800.0],
        rotate: 90,
        fonts: &["F1"],
    },
    InheritedPage {
        id: 5,
        media_box: [0.0, 0.0, 612.0, 792.0],
        crop_box: [10.0, 10.0, 585.0, 792.0],
        rotate: 0,
        fonts: &["F2"],
    },
    InheritedPage {
        id: 11,
        media_box: [0.0, 0.0, 595.0, 842.0],
        crop_box: [0.0, 0.0, 595.0, 842.0],
        rotate: 270,
        fonts: &["F3"],
    },
    InheritedPage {
        id: 12,
        media_box: [0.0, 0.0, 595.0, 842.0],
        crop_box: [0.0, 0.0, 300.0, 400.0],
        rotate: 180,
        fonts: &["F3"],
    },
];

/// One page of [`inherited_attributes`] and the attributes it has once inheritance is applied.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct InheritedPage {
    /// The page object's number (generation 0).
    pub id: u32,
    /// The media box, `[llx lly urx ury]`.
    pub media_box: [f64; 4],
    /// The crop box, clipped to the media box.
    pub crop_box: [f64; 4],
    /// The rotation in degrees, normalized to 0, 90, 180 or 270.
    pub rotate: u16,
    /// The font names in the page's resource dictionary.
    pub fonts: &'static [&'static str],
}

/// A four-page document whose pages inherit every inheritable attribute (§7.7.3.4) from one or
/// two levels up, a well-formed file (see [`INHERITED_PAGES`]). `pdfinfo -box` (poppler 24.02)
/// shows the same media boxes, crop boxes and rotations; for the art box of page 4 it shows the
/// zero-width `[595 0 595 100]` (poppler clamps each coordinate into the media box), where
/// folioxide ignores a box that does not overlap the media box. The crop boxes are chosen so
/// that clipping agrees: poppler replaces a crop box taller or wider than the media box by the
/// media box's extent in that direction instead of intersecting the two (§14.11.2).
///
/// ```text
/// 2  Pages  root: /MediaBox [0 0 595 842] (A4)  /Rotate 90  /Resources << /Font << /F1 >> >>
/// ├─ 3  Pages  /CropBox [10 10 585 800]
/// │  ├─ 4  Page  (everything inherited: A4 from its grandparent, crop box from 3)
/// │  └─ 5  Page  /MediaBox [0 0 612 792] /Rotate 0 /Resources << /Font << /F2 >> >>
/// │            (the inherited crop box is clipped to the page's own media box, [10 10 585 792])
/// └─ 10 Pages  /Rotate -90  /Resources 22 0 R (indirect: << /Font << /F3 >> >>)
///    ├─ 11 Page  (rotation 270, resources from 10)
///    └─ 12 Page  /Rotate 180  /CropBox [-100 -100 300 400] (clipped to [0 0 300 400])
///               /BleedBox [-5 -5 310 410] /TrimBox [20 20 280 380] /ArtBox [700 0 800 100]
///               (outside the media box: ignored, so the art box is the crop box)
/// ```
pub fn inherited_attributes() -> Vec<u8> {
    let objects = vec![
        (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
        (
            2,
            "<< /Type /Pages /Kids [3 0 R 10 0 R] /Count 4 /MediaBox [0 0 595 842] /Rotate 90 \
             /Resources << /Font << /F1 20 0 R >> >> >>"
                .to_owned(),
        ),
        (
            3,
            "<< /Type /Pages /Parent 2 0 R /Kids [4 0 R 5 0 R] /Count 2 \
             /CropBox [10 10 585 800] >>"
                .to_owned(),
        ),
        (
            4,
            "<< /Type /Page /Parent 3 0 R /Contents 30 0 R >>".to_owned(),
        ),
        (
            5,
            "<< /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792] /Rotate 0 \
             /Resources << /Font << /F2 21 0 R >> >> /Contents 31 0 R >>"
                .to_owned(),
        ),
        (
            10,
            "<< /Type /Pages /Parent 2 0 R /Kids [11 0 R 12 0 R] /Count 2 /Rotate -90 \
             /Resources 22 0 R >>"
                .to_owned(),
        ),
        (
            11,
            "<< /Type /Page /Parent 10 0 R /Contents 32 0 R >>".to_owned(),
        ),
        (
            12,
            "<< /Type /Page /Parent 10 0 R /Rotate 180 /CropBox [-100 -100 300 400] \
             /BleedBox [-5 -5 310 410] /TrimBox [20 20 280 380] /ArtBox [700 0 800 100] \
             /Contents 33 0 R >>"
                .to_owned(),
        ),
        (20, font("Helvetica")),
        (21, font("Times-Roman")),
        (22, "<< /Font << /F3 23 0 R >> >>".to_owned()),
        (23, font("Courier")),
    ];
    let streams = vec![
        (30, content("Page 1")),
        (31, content("Page 2")),
        (32, content("Page 3")),
        (33, content("Page 4")),
    ];
    document("model-inherited", "1.7", &objects, &streams, "")
}

/// The `/Rotate` values of [`rotations`], page by page, with the rotation a reader uses: the
/// value normalized to 0–270 (negative values and values of 360 or more included), 0 for a
/// number that is not a multiple of 90, and the inherited 180 for a value that is not a number.
pub const ROTATIONS: [(&str, u16); 11] = [
    ("0", 0),
    ("90", 90),
    ("180", 180),
    ("270", 270),
    ("360", 0),
    ("-90", 270),
    ("450", 90),
    ("-270", 90),
    ("45", 0),
    ("90.0", 90),
    ("/Ninety", 180),
];

/// One page per entry of [`ROTATIONS`] (objects 10, 11, …), each with that `/Rotate` value,
/// under a root page tree with `/Rotate 180` and a US Letter media box.
///
/// poppler 24.02 (`pdfinfo -box`) agrees except on two pages: it shows `/Rotate 45` as 45 (it
/// does not check for a multiple of 90) and ignores the real `90.0`, so that page inherits 180.
/// The pages have no `/Resources` (qpdf warns and repairs them).
pub fn rotations() -> Vec<u8> {
    let mut objects = vec![(1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned())];
    let kids: Vec<String> = (0..ROTATIONS.len())
        .map(|i| format!("{} 0 R", 10 + i))
        .collect();
    objects.push((
        2,
        format!(
            "<< /Type /Pages /Kids [{}] /Count {} /Rotate 180 /MediaBox [0 0 612 792] >>",
            kids.join(" "),
            ROTATIONS.len()
        ),
    ));
    for (i, (rotate, _)) in ROTATIONS.iter().enumerate() {
        objects.push((
            u32::try_from(10 + i).unwrap_or(u32::MAX),
            format!("<< /Type /Page /Parent 2 0 R /Rotate {rotate} >>"),
        ));
    }
    document("model-rotations", "1.4", &objects, &[], "")
}

/// A page tree with cycles and a page listed twice. The pages are 3, 5 and 5 again: a reader
/// skips the nodes that lead back up (poppler checks the nodes above, a visited set does the
/// same) but counts a page each time it is listed (poppler, pypdf, qpdf); the `/Count` values
/// (2 and 1) leave the second listing out.
///
/// ```text
/// 2  Pages  /Kids [3 0 R 4 0 R]  /Count 2
/// ├─ 3  Page
/// └─ 4  Pages  /Kids [5 0 R 2 0 R 4 0 R 5 0 R]  /Count 1
///    ├─ 5  Page
///    ├─ 2  (the root again: a cycle)
///    ├─ 4  (itself: a cycle)
///    └─ 5  (again: the same page listed twice)
/// ```
pub fn page_tree_cycle() -> Vec<u8> {
    let objects = vec![
        (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
        (
            2,
            "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 612 792] >>".to_owned(),
        ),
        (3, "<< /Type /Page /Parent 2 0 R >>".to_owned()),
        (
            4,
            "<< /Type /Pages /Parent 2 0 R /Kids [5 0 R 2 0 R 4 0 R 5 0 R] /Count 1 >>".to_owned(),
        ),
        (5, "<< /Type /Page /Parent 4 0 R >>".to_owned()),
    ];
    document("model-page-tree-cycle", "1.4", &objects, &[], "")
}

/// A page tree whose `/Count` values are wrong: the root says 7 and node 4 says 1, but the tree
/// has three pages (3, 5 and 6), and one of them (6) has no `/Type`. Kid 7 is a font, kid 8 is
/// missing, and the root lists an integer among its kids: all three are skipped.
pub fn wrong_count() -> Vec<u8> {
    let objects = vec![
        (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
        (
            2,
            "<< /Type /Pages /Kids [3 0 R 4 0 R 7 0 R 8 0 R 42] /Count 7 \
             /MediaBox [0 0 612 792] >>"
                .to_owned(),
        ),
        (3, "<< /Type /Page /Parent 2 0 R >>".to_owned()),
        (
            4,
            "<< /Type /Pages /Parent 2 0 R /Kids [5 0 R 6 0 R] /Count 1 >>".to_owned(),
        ),
        (5, "<< /Type /Page /Parent 4 0 R >>".to_owned()),
        (6, "<< /Parent 4 0 R /MediaBox [0 0 100 100] >>".to_owned()),
        (7, font("Helvetica")),
    ];
    document("model-wrong-count", "1.4", &objects, &[], "")
}

/// A page tree `depth` levels deep: a chain of `/Pages` nodes 2, 3, … each with one kid, and a
/// single page at the bottom (the last object).
pub fn deep_page_tree(depth: u32) -> Vec<u8> {
    let depth = depth.max(1);
    let mut objects = vec![(1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned())];
    for level in 0..depth {
        let num = 2 + level;
        let parent = if level == 0 {
            String::new()
        } else {
            format!("/Parent {} 0 R ", num - 1)
        };
        objects.push((
            num,
            format!(
                "<< /Type /Pages {parent}/Kids [{} 0 R] /Count 1 >>",
                num + 1
            ),
        ));
    }
    objects.push((
        2 + depth,
        format!(
            "<< /Type /Page /Parent {} 0 R /MediaBox [0 0 612 792] >>",
            1 + depth
        ),
    ));
    document("model-deep-page-tree", "1.4", &objects, &[], "")
}

/// The named destinations of [`trees`] and the destination page each one names, in key order.
pub const NAMED_DESTS: [(&str, u32); 6] = [
    ("alpha", 3),
    ("beta", 3),
    ("chapter1", 3),
    ("nu", 3),
    ("omega", 3),
    ("zeta", 3),
];

/// The page-label ranges of [`trees`]: the first page index of each range and its `/S` style.
pub const PAGE_LABELS: [(i64, &str); 4] = [(0, "r"), (2, "D"), (5, "A"), (9, "D")];

/// A one-page document with a name tree (`/Names /Dests`, §7.9.6) and a number tree
/// (`/PageLabels`, §7.9.7), each three levels deep with `/Limits` on every node below the root.
///
/// Name tree (root 10): intermediate nodes 11 (`alpha`–`chapter1`) and 12 (`nu`–`zeta`); 11
/// has the leaf 13 (`alpha`, `beta`, `chapter1`, the last value as an indirect object 30); 12
/// lists the leaf 14 (`nu`, `omega`) and itself (a cycle), and the leaf 15 (`zeta`), whose
/// `/Limits` wrongly say `(a) (b)`.
///
/// Number tree (root 20): leaves 21 (keys 0 and 2, `/Limits [0 2]`) and 22 (keys 5 and 9,
/// `/Limits [5 9]`), the second through an intermediate node 23 (`/Limits [5 9]`).
pub fn trees() -> Vec<u8> {
    let dest = "[3 0 R /XYZ 0 792 0]";
    let objects = vec![
        (
            1,
            "<< /Type /Catalog /Pages 2 0 R /Names << /Dests 10 0 R >> /PageLabels 20 0 R >>"
                .to_owned(),
        ),
        (
            2,
            "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>".to_owned(),
        ),
        (3, "<< /Type /Page /Parent 2 0 R >>".to_owned()),
        (10, "<< /Kids [11 0 R 12 0 R] >>".to_owned()),
        (
            11,
            "<< /Limits [(alpha) (chapter1)] /Kids [13 0 R] >>".to_owned(),
        ),
        (
            12,
            "<< /Limits [(nu) (zeta)] /Kids [14 0 R 12 0 R 15 0 R] >>".to_owned(),
        ),
        (
            13,
            format!(
                "<< /Limits [(alpha) (chapter1)] /Names [(alpha) {dest} (beta) << /D {dest} >> \
                 (chapter1) 30 0 R] >>"
            ),
        ),
        (
            14,
            format!("<< /Limits [(nu) (omega)] /Names [(nu) {dest} (omega) {dest}] >>"),
        ),
        (
            15,
            format!("<< /Limits [(a) (b)] /Names [(zeta) {dest}] >>"),
        ),
        (20, "<< /Kids [21 0 R 23 0 R] >>".to_owned()),
        (
            21,
            "<< /Limits [0 2] /Nums [0 << /S /r >> 2 << /S /D >>] >>".to_owned(),
        ),
        (
            22,
            "<< /Limits [5 9] /Nums [5 << /S /A /P (A-) >> 9 << /S /D /St 10 >>] >>".to_owned(),
        ),
        (23, "<< /Limits [5 9] /Kids [22 0 R] >>".to_owned()),
        (30, format!("<< /D {dest} >>")),
    ];
    document("model-trees", "1.7", &objects, &[], "")
}

/// A one-page document whose Info dictionary (object 9) uses every text-string encoding
/// (§7.9.2.2) and several date forms (§7.9.4):
///
/// - `/Title`: PDFDocEncoding with typographic characters, `“Folio” — ﬁnal €5` (bytes
///   `8D 'Folio' 8E ' ' 84 ' ' 93 'nal ' A0 '5'`)
/// - `/Author`: UTF-16BE with a byte order mark and a surrogate pair, `Zoë 😀`
/// - `/Subject`: UTF-8 with a byte order mark (PDF 2.0), `Ünïcödé`
/// - `/Keywords`: a hexadecimal UTF-16BE string with a language marker (`ja`), `日本`
/// - `/Creator`: a name instead of a string (invalid: left out)
/// - `/Producer`: an indirect string (object 8), `folioxide-testkit`
/// - `/CreationDate`: `D:20240229133005+05'30'`
/// - `/ModDate`: `20240301` (partial, no `D:`)
/// - `/Trapped`: `/False`
/// - `/Company` (custom): `ACME`; `/Pages` (custom, an integer: left out)
pub fn info_strings() -> Vec<u8> {
    let objects = vec![
        (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
        (
            2,
            "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>".to_owned(),
        ),
        (3, "<< /Type /Page /Parent 2 0 R >>".to_owned()),
        (8, "(folioxide-testkit)".to_owned()),
        (
            9,
            "<< /Title <8D466F6C696F8E208420936E616C20A035> \
             /Author <FEFF005A006F00EB0020D83DDE00> \
             /Subject <EFBBBFC39C6EC3AF63C3B664C3A9> \
             /Keywords <FEFF001B6A61001B65E5672C> \
             /Creator /NotAString \
             /Producer 8 0 R \
             /CreationDate (D:20240229133005+05'30') \
             /ModDate (20240301) \
             /Trapped /False \
             /Company (ACME) \
             /Pages 3 >>"
                .to_owned(),
        ),
    ];
    document("model-info", "1.7", &objects, &[], "/Info 9 0 R")
}

/// The crop boxes a reader that follows §14.11.2 sees on the pages of [`crop_box_quirks`], page
/// by page, `[llx lly urx ury]`: the crop box intersected with the media box, or the media box
/// when they do not overlap.
pub const CROP_BOX_QUIRKS: [[f64; 4]; 4] = [
    [100.0, 0.0, 300.0, 400.0],
    [0.0, 0.0, 300.0, 400.0],
    [50.0, 50.0, 250.0, 350.0],
    [10.75, 20.125, 250.25, 350.5],
];

/// A four-page document whose crop boxes readers clip differently (§14.11.2), a well-formed
/// file: the root page tree has `/MediaBox [0 0 300 400]` and an empty `/Resources`, and each
/// page has a `/CropBox` (see [`CROP_BOX_QUIRKS`] for what a reader that intersects sees).
///
/// ```text
/// 3  Page  /CropBox [100 0 500 400]  wider than the media box and offset: [100 0 300 400]
///          (poppler 24.02 replaces a crop box wider than the media box by the media box's
///          horizontal extent before clamping: [0 0 300 400])
/// 4  Page  /CropBox [400 0 500 400]  outside the media box: ignored, so the media box
///          (poppler clamps it into the box without area [300 0 300 400])
/// 5  Page  /CropBox [50 50 250 350]  inside: every reader agrees
/// 6  Page  /MediaBox [300 400 0 0] /CropBox [250.25 350.5 10.75 20.125]
///          (corners reversed, real coordinates: normalized by every reader, §7.9.5)
/// ```
pub fn crop_box_quirks() -> Vec<u8> {
    let objects = vec![
        (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
        (
            2,
            "<< /Type /Pages /Kids [3 0 R 4 0 R 5 0 R 6 0 R] /Count 4 /MediaBox [0 0 300 400] \
             /Resources << >> >>"
                .to_owned(),
        ),
        (
            3,
            "<< /Type /Page /Parent 2 0 R /CropBox [100 0 500 400] >>".to_owned(),
        ),
        (
            4,
            "<< /Type /Page /Parent 2 0 R /CropBox [400 0 500 400] >>".to_owned(),
        ),
        (
            5,
            "<< /Type /Page /Parent 2 0 R /CropBox [50 50 250 350] >>".to_owned(),
        ),
        (
            6,
            "<< /Type /Page /Parent 2 0 R /MediaBox [300 400 0 0] \
             /CropBox [250.25 350.5 10.75 20.125] >>"
                .to_owned(),
        ),
    ];
    document("model-crop-box-quirks", "1.7", &objects, &[], "")
}

/// The page objects of [`repeated_page`], in page order: page 3 is listed twice.
pub const REPEATED_PAGE_IDS: [u32; 3] = [3, 3, 4];

/// A three-page document whose page tree lists the same page object twice (ISO 32000-2 §7.7.3.2
/// does not define it, but it occurs in real files), with `/Count 3`. poppler, pypdf and qpdf
/// (which copies the page object) read three pages, the first two the same; see
/// [`REPEATED_PAGE_IDS`].
///
/// ```text
/// 2  Pages  /Kids [3 0 R 3 0 R 4 0 R]  /Count 3  /MediaBox [0 0 612 792]  /Resources << >>
/// ├─ 3  Page  /Rotate 90
/// ├─ 3  (the same page again)
/// └─ 4  Page  /MediaBox [0 0 300 400]
/// ```
pub fn repeated_page() -> Vec<u8> {
    let objects = vec![
        (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
        (
            2,
            "<< /Type /Pages /Kids [3 0 R 3 0 R 4 0 R] /Count 3 /MediaBox [0 0 612 792] \
             /Resources << >> >>"
                .to_owned(),
        ),
        (3, "<< /Type /Page /Parent 2 0 R /Rotate 90 >>".to_owned()),
        (
            4,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 400] >>".to_owned(),
        ),
    ];
    document("model-repeated-page", "1.7", &objects, &[], "")
}

/// A two-page document whose `/Parent` entries disagree with the page tree, so that readers
/// inherit different attributes (ISO 32000-2 §7.7.3.4 defines inheritance through the
/// ancestors; the file is malformed). Readers that inherit along the page tree (poppler, this
/// crate) see two upright US Letter pages without a crop box of their own; readers that inherit
/// along `/Parent` (pdf.js, and qpdf for `/CropBox` and `/Rotate`) see the values of nodes 5
/// and 6.
///
/// ```text
/// 2  Pages  /Kids [3 0 R 4 0 R]  /Count 2  /MediaBox [0 0 612 792]  /Resources << >>
/// │         /Parent 6 0 R  (the root has a /Parent, which §7.7.3.2 prohibits)
/// ├─ 3  Page  /Parent 5 0 R  (not the node that lists it)
/// └─ 4  Page  /Parent 2 0 R
/// 5  Pages  /Kids []  /Count 0  /MediaBox [0 0 500 500]  /CropBox [10 10 300 400]  /Rotate 90
/// 6  Pages  /Kids [2 0 R]  /Count 2  /CropBox [20 20 200 200]  /Rotate 180
/// ```
pub fn parent_mismatch() -> Vec<u8> {
    let objects = vec![
        (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
        (
            2,
            "<< /Type /Pages /Parent 6 0 R /Kids [3 0 R 4 0 R] /Count 2 \
             /MediaBox [0 0 612 792] /Resources << >> >>"
                .to_owned(),
        ),
        (3, "<< /Type /Page /Parent 5 0 R >>".to_owned()),
        (4, "<< /Type /Page /Parent 2 0 R >>".to_owned()),
        (
            5,
            "<< /Type /Pages /Kids [] /Count 0 /MediaBox [0 0 500 500] \
             /CropBox [10 10 300 400] /Rotate 90 >>"
                .to_owned(),
        ),
        (
            6,
            "<< /Type /Pages /Kids [2 0 R] /Count 2 /CropBox [20 20 200 200] /Rotate 180 >>"
                .to_owned(),
        ),
    ];
    document("model-parent-mismatch", "1.7", &objects, &[], "")
}

//! Syntax-layer fixtures (M1): healthy files of every cross-reference kind, and broken files for
//! every repair case the store must handle (ISO 32000-2 §7.5, ARCHITECTURE §A.10 traps #1–#5).
//!
//! [`all`] generates every committed fixture; `cargo xtask fixtures` writes each one to
//! `fixtures/syntax/<name>.pdf`. [`infos`] describes them (purpose, conformance, page count),
//! and each one also has its own function here. [`lazy_pages`] and [`many_pages`] build large
//! page trees at test time; they are not committed.
//!
//! Every fixture is deterministic (fixed `/ID`, fixed Flate level) and well under 200 KB. Unless
//! described otherwise, documents have the same five objects: `1` catalog, `2` page tree, `3`
//! page, `4` content stream, `5` font (Helvetica, not embedded).
//!
//! ```
//! use folioxide_testkit::fixtures::syntax;
//!
//! let all = syntax::all();
//! assert!(all.iter().any(|(name, _)| *name == "hybrid"));
//! for (name, pdf) in &all {
//!     assert!(pdf.len() < 200 * 1024, "{name}");
//! }
//! ```

use folioxide_syntax::ObjectId;
use folioxide_syntax::filters::encode_flate;

use super::{id_array, id_array_updated};
use crate::builder::{
    FLATE_LEVEL, LengthSpec, ObjStmOpts, PdfBuilder, XrefEol, XrefOpts, XrefStreamOpts,
};

/// The page count of [`lazy_pages`] (the `open_is_lazy` acceptance test).
pub const LAZY_PAGE_COUNT: u32 = 2000;

/// Pages per intermediate page-tree node in [`many_pages`] and [`many_pages_compressed`].
pub const PAGES_PER_NODE: u32 = 100;

/// Objects per object stream in [`many_pages_compressed`].
pub const OBJECTS_PER_OBJSTM: usize = 100;

/// Description of one committed syntax fixture.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct FixtureInfo {
    /// The name; the committed file is `fixtures/syntax/<name>.pdf`.
    pub name: &'static str,
    /// What the file contains and what it tests.
    pub description: &'static str,
    /// Whether a conforming reader opens the file without any repair. Broken files (and the
    /// encrypted ones, whose encryption is not real) are `false`.
    pub conforming: bool,
    /// Whether the external oracles read the file without errors or warnings: pikepdf/qpdf
    /// (`Pdf.open` and `check_pdf_syntax()`) and poppler (`pdfinfo`). Checked with pikepdf 10.16
    /// (qpdf 12.4) and poppler 24.02 when the fixture was added. Some non-conforming files are
    /// clean because those readers tolerate the defect silently (19-byte xref entries, junk
    /// before the header, an `/Extends` loop).
    pub oracle_clean: bool,
    /// The number of pages the document has once it is read (or repaired) correctly.
    pub pages: u32,
    /// The generator.
    pub generate: fn() -> Vec<u8>,
}

/// Every committed fixture, healthy ones first.
const FIXTURES: &[FixtureInfo] = &[
    FixtureInfo {
        name: "minimal",
        description: "one page, classic xref table and trailer (PDF 1.4)",
        conforming: true,
        oracle_clean: true,
        pages: 1,
        generate: minimal,
    },
    FixtureInfo {
        name: "multi-revision",
        description: "three revisions linked by /Prev: an updated content stream and /Info, then a new page, an updated page tree and a freed object (gen 1); update sections have several subsections",
        conforming: true,
        oracle_clean: true,
        pages: 2,
        generate: multi_revision,
    },
    FixtureInfo {
        name: "xref-stream",
        description: "cross-reference stream (PDF 1.5) with Flate and the PNG Up predictor (/Predictor 12)",
        conforming: true,
        oracle_clean: true,
        pages: 1,
        generate: xref_stream,
    },
    FixtureInfo {
        name: "xref-stream-incremental",
        description: "two revisions, both cross-reference streams; the update has /Prev and an /Index with two runs",
        conforming: true,
        oracle_clean: true,
        pages: 1,
        generate: xref_stream_incremental,
    },
    FixtureInfo {
        name: "hybrid",
        description: "hybrid-reference file (§7.5.8.4): catalog and page tree only in an object stream, reachable through the trailer's /XRefStm; the table's subsections skip them",
        conforming: true,
        oracle_clean: true,
        pages: 1,
        generate: hybrid,
    },
    FixtureInfo {
        name: "objstm",
        description: "catalog, page tree, page, font and /Info in one object stream; xref stream with type 2 entries",
        conforming: true,
        oracle_clean: true,
        pages: 1,
        generate: objstm,
    },
    FixtureInfo {
        name: "objstm-extends",
        description: "three object streams chained by /Extends (12 -> 11 -> 10)",
        conforming: true,
        oracle_clean: true,
        pages: 1,
        generate: objstm_extends,
    },
    FixtureInfo {
        name: "xref-eol-space-lf",
        description: "xref entries end with SP LF (20 bytes)",
        conforming: true,
        oracle_clean: true,
        pages: 1,
        generate: xref_eol_space_lf,
    },
    FixtureInfo {
        name: "xref-eol-space-cr",
        description: "xref entries end with SP CR (20 bytes); xref and subsection lines end with CR",
        conforming: true,
        oracle_clean: true,
        pages: 1,
        generate: xref_eol_space_cr,
    },
    FixtureInfo {
        name: "xref-eol-crlf",
        description: "xref entries end with CR LF (20 bytes)",
        conforming: true,
        oracle_clean: true,
        pages: 1,
        generate: xref_eol_crlf,
    },
    FixtureInfo {
        name: "xref-eol-lf",
        description: "xref entries end with a lone LF (19 bytes)",
        conforming: false,
        oracle_clean: true,
        pages: 1,
        generate: xref_eol_lf,
    },
    FixtureInfo {
        name: "xref-eol-cr",
        description: "xref entries end with a lone CR (19 bytes)",
        conforming: false,
        oracle_clean: true,
        pages: 1,
        generate: xref_eol_cr,
    },
    FixtureInfo {
        name: "xref-subsection-starts-at-1",
        description: "the only subsection lists object 0's entry first but says it starts at 1, so every object is off by one",
        conforming: false,
        oracle_clean: false,
        pages: 1,
        generate: xref_subsection_starts_at_1,
    },
    FixtureInfo {
        name: "xref-offsets-off-by-n",
        description: "every in-use xref offset is 5 bytes too large",
        conforming: false,
        oracle_clean: false,
        pages: 1,
        generate: xref_offsets_off_by_n,
    },
    FixtureInfo {
        name: "startxref-off-by-n",
        description: "startxref points 8 bytes past the xref keyword",
        conforming: false,
        oracle_clean: false,
        pages: 1,
        generate: startxref_off_by_n,
    },
    FixtureInfo {
        name: "prev-loop",
        description: "two revisions whose /Prev entries point at each other",
        conforming: false,
        oracle_clean: false,
        pages: 1,
        generate: prev_loop,
    },
    FixtureInfo {
        name: "junk-before-header",
        description: "118 bytes of mail headers before %PDF-; offsets are relative to the header",
        conforming: false,
        oracle_clean: true,
        pages: 1,
        generate: junk_before_header,
    },
    FixtureInfo {
        name: "xref-stream-w0",
        description: "xref stream with /W [0 3 0]: the type and generation fields are absent and take their defaults (1 and 0); /Index skips object 0",
        conforming: true,
        oracle_clean: true,
        pages: 1,
        generate: xref_stream_w0,
    },
    FixtureInfo {
        name: "stream-length-wrong",
        description: "the page has four content streams whose /Length is too short (4), too long (6), missing (7), and too long on a Flate stream (8)",
        conforming: false,
        oracle_clean: false,
        pages: 1,
        generate: stream_length_wrong,
    },
    FixtureInfo {
        name: "length-indirect-cycle",
        description: "content stream 4 has /Length 4 0 R (itself); stream 6 has /Length 7 0 R where 7 and 8 refer to each other; stream 9 has a valid indirect /Length 10 0 R",
        conforming: false,
        oracle_clean: false,
        pages: 1,
        generate: length_indirect_cycle,
    },
    FixtureInfo {
        name: "missing-xref",
        description: "objects only; no xref, trailer or startxref (the trailer must be rebuilt from the /Type /Catalog object)",
        conforming: false,
        oracle_clean: false,
        pages: 1,
        generate: missing_xref,
    },
    FixtureInfo {
        name: "missing-xref-with-trailer",
        description: "objects and a trailer, but no xref section and no startxref",
        conforming: false,
        oracle_clean: false,
        pages: 1,
        generate: missing_xref_with_trailer,
    },
    FixtureInfo {
        name: "flate-truncated",
        description: "the Flate content stream is cut 8 bytes short (with a /Length that matches the cut data)",
        conforming: false,
        oracle_clean: false,
        pages: 1,
        generate: flate_truncated,
    },
    FixtureInfo {
        name: "objstm-extends-loop",
        description: "object streams 9 and 10 name each other in /Extends",
        conforming: false,
        oracle_clean: true,
        pages: 1,
        generate: objstm_extends_loop,
    },
    FixtureInfo {
        name: "objstm-n-too-large",
        description: "the object stream says /N 1000 but holds 4 objects",
        conforming: false,
        oracle_clean: false,
        pages: 1,
        generate: objstm_n_too_large,
    },
    FixtureInfo {
        name: "encrypted",
        description: "trailer /Encrypt with a /Standard handler (R2); the data is not actually encrypted, the file only tests detection (PasswordRequired)",
        conforming: false,
        oracle_clean: false,
        pages: 1,
        generate: encrypted,
    },
    FixtureInfo {
        name: "encrypted-unknown-handler",
        description: "trailer /Encrypt with the public-key handler /Adobe.PubSec, which the syntax layer does not support (Unsupported)",
        conforming: false,
        oracle_clean: false,
        pages: 1,
        generate: encrypted_unknown_handler,
    },
];

/// Descriptions of every committed fixture, in the order of [`all`].
pub fn infos() -> &'static [FixtureInfo] {
    FIXTURES
}

/// The description of the fixture called `name`.
pub fn info(name: &str) -> Option<&'static FixtureInfo> {
    FIXTURES.iter().find(|info| info.name == name)
}

/// Every committed fixture as `(name, bytes)`; the file name is `<name>.pdf`.
pub fn all() -> Vec<(&'static str, Vec<u8>)> {
    FIXTURES
        .iter()
        .map(|info| (info.name, (info.generate)()))
        .collect()
}

/// Generates the fixture called `name`.
pub fn get(name: &str) -> Option<Vec<u8>> {
    info(name).map(|info| (info.generate)())
}

/// The path of the committed fixture `name`: `<workspace>/fixtures/syntax/<name>.pdf`.
pub fn committed_path(name: &str) -> std::path::PathBuf {
    super::fixtures_dir()
        .join("syntax")
        .join(format!("{name}.pdf"))
}

/// Reads the committed fixture `name` (byte for byte what [`get`] generates, as long as
/// `cargo xtask fixtures --check` passes).
///
/// # Errors
/// Any I/O error, for example when the file was never generated (`cargo xtask fixtures`).
///
/// ```
/// use folioxide_testkit::fixtures::syntax;
///
/// assert_eq!(syntax::read_committed("minimal")?, syntax::minimal());
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn read_committed(name: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(committed_path(name))
}

// ---------------------------------------------------------------------------------------------
// Shared pieces
// ---------------------------------------------------------------------------------------------

const CATALOG: &str = "<< /Type /Catalog /Pages 2 0 R >>";
const PAGES: &str = "<< /Type /Pages /Kids [3 0 R] /Count 1 >>";
const FONT: &str = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";

/// A US Letter page under page tree 2, using font 5 as `/F1`.
fn page(contents: &str) -> String {
    format!(
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
         /Resources << /Font << /F1 5 0 R >> >> /Contents {contents} >>"
    )
}

/// A content stream that shows `text` at height `y`.
pub(crate) fn content(text: &str, y: u32) -> Vec<u8> {
    format!("BT /F1 24 Tf 72 {y} Td ({text}) Tj ET").into_bytes()
}

/// Writes objects 1–5: catalog, page tree, page, content stream showing `text`, font.
pub(crate) fn one_page(b: &mut PdfBuilder, text: &str) {
    b.obj(1, 0, CATALOG)
        .obj(2, 0, PAGES)
        .obj(3, 0, page("4 0 R"))
        .stream_obj(4, 0, "", &content(text, 720), None)
        .obj(5, 0, FONT);
}

/// Writes the trailer, `startxref` (pointing at the last section) and `%%EOF`.
fn finish(b: &mut PdfBuilder, trailer: &str) -> Vec<u8> {
    b.trailer(trailer).startxref(None).eof();
    b.build()
}

/// A one-page file with a classic xref table written with `opts`.
fn one_page_table(name: &str, opts: XrefOpts) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.4");
    one_page(&mut b, name);
    b.xref_table(opts);
    let trailer = format!("/Size {} /Root 1 0 R /ID {}", b.size(), id_array(name));
    finish(&mut b, &trailer)
}

// ---------------------------------------------------------------------------------------------
// Healthy files
// ---------------------------------------------------------------------------------------------

/// `minimal`: one page, classic xref table and trailer.
pub fn minimal() -> Vec<u8> {
    one_page_table("minimal", XrefOpts::default())
}

/// `multi-revision`: three revisions linked by `/Prev`.
///
/// 1. Objects 1–5 plus `/Info` 6.
/// 2. Content stream 4 and `/Info` 6 replaced (subsections `4 1` and `6 1`).
/// 3. Page tree 2 replaced, `/Info` 6 freed with generation 1, page 7 and its content
///    stream 8 added (subsections `2 1` and `6 3`). The final document has two pages and no
///    `/Info`.
pub fn multi_revision() -> Vec<u8> {
    const NAME: &str = "multi-revision";
    let mut b = PdfBuilder::new();
    b.header("1.4");
    one_page(&mut b, "Revision 1");
    b.obj(
        6,
        0,
        "<< /Title (Revision 1) /Producer (folioxide-testkit) >>",
    );
    b.xref_table(XrefOpts::default());
    let rev1 = b.last_xref_offset().unwrap_or(0);
    b.trailer(format!(
        "/Size {} /Root 1 0 R /Info 6 0 R /ID {}",
        b.size(),
        id_array(NAME)
    ))
    .startxref(None)
    .eof();

    b.stream_obj(4, 0, "", &content("Revision 2", 720), None)
        .obj(
            6,
            0,
            "<< /Title (Revision 2) /Producer (folioxide-testkit) >>",
        );
    b.xref_table(XrefOpts::default());
    let rev2 = b.last_xref_offset().unwrap_or(0);
    b.trailer(format!(
        "/Size {} /Root 1 0 R /Info 6 0 R /Prev {rev1} /ID {}",
        b.size(),
        id_array_updated(NAME, "multi-revision/2")
    ))
    .startxref(None)
    .eof();

    b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R 7 0 R] /Count 2 >>")
        .free(6, 1)
        .obj(
            7,
            0,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
             /Resources << /Font << /F1 5 0 R >> >> /Contents 8 0 R >>",
        )
        .stream_obj(8, 0, "", &content("Revision 3, page 2", 720), None);
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /Prev {rev2} /ID {}",
        b.size(),
        id_array_updated(NAME, "multi-revision/3")
    );
    finish(&mut b, &trailer)
}

/// `xref-stream`: objects 1–5 and a cross-reference stream 6 with Flate and `/Predictor 12`.
pub fn xref_stream() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.5");
    one_page(&mut b, "xref-stream");
    b.xref_stream(
        6,
        XrefStreamOpts::new()
            .with_predictor(true)
            .with_trailer(format!("/Root 1 0 R /ID {}", id_array("xref-stream"))),
    );
    b.startxref(None).eof();
    b.build()
}

/// `xref-stream-incremental`: `xref-stream`, then an update (also a cross-reference stream)
/// that replaces content stream 4 and adds `/Info` 7, with `/Prev` and `/Index [4 1 7 2]`.
pub fn xref_stream_incremental() -> Vec<u8> {
    const NAME: &str = "xref-stream-incremental";
    let mut b = PdfBuilder::new();
    b.header("1.5");
    one_page(&mut b, "Revision 1");
    b.xref_stream(
        6,
        XrefStreamOpts::new()
            .with_predictor(true)
            .with_trailer(format!("/Root 1 0 R /ID {}", id_array(NAME))),
    );
    let rev1 = b.last_xref_offset().unwrap_or(0);
    b.startxref(None).eof();

    b.stream_obj(4, 0, "", &content("Revision 2", 720), None)
        .obj(
            7,
            0,
            "<< /Title (Revision 2) /Producer (folioxide-testkit) >>",
        );
    b.xref_stream(
        8,
        XrefStreamOpts::new()
            .with_predictor(true)
            .with_trailer(format!(
                "/Root 1 0 R /Info 7 0 R /Prev {rev1} /ID {}",
                id_array_updated(NAME, "xref-stream-incremental/2")
            )),
    );
    b.startxref(None).eof();
    b.build()
}

/// `hybrid`: a hybrid-reference file (§7.5.8.4). Page 3, content 4 and font 5 are plain
/// objects; the catalog 1 and page tree 2 are only in object stream 6. The hidden
/// cross-reference stream 7 (named by `/XRefStm`) lists 1 and 2 as compressed; the table's
/// subsections (`0 1` and `3 5`) skip them, so a reader that ignores `/XRefStm` cannot find the
/// catalog.
pub fn hybrid() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.5");
    b.obj(3, 0, page("4 0 R"))
        .stream_obj(4, 0, "", &content("hybrid", 720), None)
        .obj(5, 0, FONT)
        .objstm(6, &[(1, CATALOG), (2, PAGES)], ObjStmOpts::new());
    b.xref_stream(7, XrefStreamOpts::new().with_hybrid(true));
    let xref_stm = b.offset_of(7, 0).unwrap_or(0);
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /XRefStm {xref_stm} /ID {}",
        b.size(),
        id_array("hybrid")
    );
    finish(&mut b, &trailer)
}

/// `objstm`: catalog 1, page tree 2, page 3, font 5 and `/Info` 7 in object stream 6;
/// a Flate content stream 4; cross-reference stream 8.
pub fn objstm() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.5");
    b.flate_stream_obj(4, 0, "", &content("objstm", 720));
    b.objstm(
        6,
        &[
            (1, CATALOG.to_owned()),
            (2, PAGES.to_owned()),
            (3, page("4 0 R")),
            (5, FONT.to_owned()),
            (
                7,
                "<< /Title (Object streams) /Producer (folioxide-testkit) >>".to_owned(),
            ),
        ],
        ObjStmOpts::new(),
    );
    b.xref_stream(
        8,
        XrefStreamOpts::new().with_trailer(format!(
            "/Root 1 0 R /Info 7 0 R /ID {}",
            id_array("objstm")
        )),
    );
    b.startxref(None).eof();
    b.build()
}

/// `objstm-extends`: object stream 10 holds font 5 and `/Info` 7; 11 (`/Extends 10 0 R`) holds
/// page tree 2 and page 3; 12 (`/Extends 11 0 R`) holds catalog 1. Content stream 4 is plain;
/// cross-reference stream 13. Object numbers 6, 8 and 9 are unused (free).
pub fn objstm_extends() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.5");
    b.stream_obj(4, 0, "", &content("objstm-extends", 720), None);
    b.objstm(
        10,
        &[
            (5, FONT),
            (
                7,
                "<< /Title (Extends chain) /Producer (folioxide-testkit) >>",
            ),
        ],
        ObjStmOpts::new(),
    );
    b.objstm(
        11,
        &[(2, PAGES.to_owned()), (3, page("4 0 R"))],
        ObjStmOpts::new().with_extends(ObjectId::new(10, 0)),
    );
    b.objstm(
        12,
        &[(1, CATALOG)],
        ObjStmOpts::new().with_extends(ObjectId::new(11, 0)),
    );
    b.xref_stream(
        13,
        XrefStreamOpts::new().with_trailer(format!(
            "/Root 1 0 R /Info 7 0 R /ID {}",
            id_array("objstm-extends")
        )),
    );
    b.startxref(None).eof();
    b.build()
}

// ---------------------------------------------------------------------------------------------
// Cross-reference repair cases
// ---------------------------------------------------------------------------------------------

/// `xref-eol-space-lf`: entries end with `SP LF`.
pub fn xref_eol_space_lf() -> Vec<u8> {
    one_page_table(
        "xref-eol-space-lf",
        XrefOpts::new().with_eol_variant(XrefEol::SpaceLf),
    )
}

/// `xref-eol-space-cr`: entries end with `SP CR`.
pub fn xref_eol_space_cr() -> Vec<u8> {
    one_page_table(
        "xref-eol-space-cr",
        XrefOpts::new().with_eol_variant(XrefEol::SpaceCr),
    )
}

/// `xref-eol-crlf`: entries end with `CR LF`.
pub fn xref_eol_crlf() -> Vec<u8> {
    one_page_table(
        "xref-eol-crlf",
        XrefOpts::new().with_eol_variant(XrefEol::CrLf),
    )
}

/// `xref-eol-lf`: 19-byte entries ending with a lone `LF`.
pub fn xref_eol_lf() -> Vec<u8> {
    one_page_table("xref-eol-lf", XrefOpts::new().with_eol_variant(XrefEol::Lf))
}

/// `xref-eol-cr`: 19-byte entries ending with a lone `CR`.
pub fn xref_eol_cr() -> Vec<u8> {
    one_page_table("xref-eol-cr", XrefOpts::new().with_eol_variant(XrefEol::Cr))
}

/// `xref-subsection-starts-at-1`: the section reads `xref 1 6` followed by object 0's free entry
/// (`0000000000 65535 f`) and the entries of objects 1–5.
pub fn xref_subsection_starts_at_1() -> Vec<u8> {
    one_page_table(
        "xref-subsection-starts-at-1",
        XrefOpts::new().with_first_subsection_start(1),
    )
}

/// `xref-offsets-off-by-n`: every in-use offset is 5 too large (inside the ±64-byte search
/// window of the store).
pub fn xref_offsets_off_by_n() -> Vec<u8> {
    one_page_table("xref-offsets-off-by-n", XrefOpts::new().with_offset_skew(5))
}

/// `startxref-off-by-n`: `startxref` is 8 more than the offset of `xref`.
pub fn startxref_off_by_n() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.4");
    one_page(&mut b, "startxref-off-by-n");
    b.xref_table(XrefOpts::default());
    let wrong = b.last_xref_offset().unwrap_or(0) + 8;
    b.trailer(format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array("startxref-off-by-n")
    ))
    .startxref(Some(wrong))
    .eof();
    b.build()
}

/// `prev-loop`: revision 1's trailer has `/Prev` pointing at revision 2's xref section, whose
/// trailer has `/Prev` pointing back at revision 1. Revision 2 replaces content stream 4.
pub fn prev_loop() -> Vec<u8> {
    const NAME: &str = "prev-loop";
    let mut b = PdfBuilder::new();
    b.header("1.4");
    one_page(&mut b, "Revision 1");
    b.xref_table(XrefOpts::default());
    let rev1 = b.last_xref_offset().unwrap_or(0);
    b.raw(format!(
        "trailer\n<</Size {} /Root 1 0 R /ID {} /Prev ",
        b.size(),
        id_array(NAME)
    ));
    let forward = b.placeholder();
    b.raw(">>\n").startxref(None).eof();

    b.stream_obj(4, 0, "", &content("Revision 2", 720), None);
    b.xref_table(XrefOpts::default());
    let rev2 = b.last_xref_offset().unwrap_or(0);
    b.fill(forward, rev2);
    let trailer = format!(
        "/Size {} /Root 1 0 R /Prev {rev1} /ID {}",
        b.size(),
        id_array_updated(NAME, "prev-loop/2")
    );
    finish(&mut b, &trailer)
}

/// The junk of `junk-before-header`: 118 bytes, so a ±64-byte offset search alone cannot
/// compensate for it.
const MAIL_JUNK: &[u8] = b"Received: from mail.example.org\r\n\
Content-Type: application/pdf; name=\"junk.pdf\"\r\n\
Content-Transfer-Encoding: binary\r\n\r\n";

/// `junk-before-header`: 118 bytes of mail headers before `%PDF-`; offsets count from the header.
pub fn junk_before_header() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.junk_prefix(MAIL_JUNK).header("1.4");
    one_page(&mut b, "junk-before-header");
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array("junk-before-header")
    );
    finish(&mut b, &trailer)
}

/// `xref-stream-w0`: cross-reference stream 6 with `/W [0 3 0]` and `/Index [1 6]`.
pub fn xref_stream_w0() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.5");
    one_page(&mut b, "xref-stream-w0");
    b.xref_stream(
        6,
        XrefStreamOpts::new()
            .with_widths([0, 3, 0])
            .with_trailer(format!("/Root 1 0 R /ID {}", id_array("xref-stream-w0"))),
    );
    b.startxref(None).eof();
    b.build()
}

// ---------------------------------------------------------------------------------------------
// Stream /Length and reconstruction cases
// ---------------------------------------------------------------------------------------------

/// `stream-length-wrong`: page 3 has `/Contents [4 0 R 6 0 R 7 0 R 8 0 R]`:
/// - 4: `/Length` 7 too short;
/// - 6: `/Length` 20 too long (it ends inside object 7's header);
/// - 7: no `/Length`;
/// - 8: Flate data with a `/Length` 5 too long.
///
/// Each stream shows one line of text (`BT /F1 24 Tf 72 <y> Td (<text>) Tj ET`).
pub fn stream_length_wrong() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.4");
    let short = content("Length too short", 720);
    let long = content("Length too long", 690);
    let missing = content("Length missing", 660);
    let flate = encode_flate(&content("Flate, Length too long", 630), FLATE_LEVEL);
    b.obj(1, 0, CATALOG)
        .obj(2, 0, PAGES)
        .obj(3, 0, page("[4 0 R 6 0 R 7 0 R 8 0 R]"))
        .stream_obj(
            4,
            0,
            "",
            &short,
            Some(LengthSpec::Direct(short.len() as i64 - 7)),
        )
        .obj(5, 0, FONT)
        .stream_obj(
            6,
            0,
            "",
            &long,
            Some(LengthSpec::Direct(long.len() as i64 + 20)),
        )
        .stream_obj(7, 0, "", &missing, Some(LengthSpec::Omit))
        .stream_obj(
            8,
            0,
            "/Filter /FlateDecode",
            &flate,
            Some(LengthSpec::Direct(flate.len() as i64 + 5)),
        );
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array("stream-length-wrong")
    );
    finish(&mut b, &trailer)
}

/// `length-indirect-cycle`: page 3 has `/Contents [4 0 R 6 0 R 9 0 R]`:
/// - 4: `/Length 4 0 R`, the stream itself;
/// - 6: `/Length 7 0 R`, where 7 is `8 0 R` and 8 is `7 0 R`;
/// - 9: `/Length 10 0 R`, where 10 holds the correct length (written after the stream, the
///   usual reason for an indirect length).
pub fn length_indirect_cycle() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.4");
    let ok = content("indirect Length", 660);
    b.obj(1, 0, CATALOG)
        .obj(2, 0, PAGES)
        .obj(3, 0, page("[4 0 R 6 0 R 9 0 R]"))
        .stream_obj(
            4,
            0,
            "",
            &content("Length refers to its own stream", 720),
            Some(LengthSpec::Indirect(ObjectId::new(4, 0))),
        )
        .obj(5, 0, FONT)
        .stream_obj(
            6,
            0,
            "",
            &content("Length is a reference cycle", 690),
            Some(LengthSpec::Indirect(ObjectId::new(7, 0))),
        )
        .obj(7, 0, "8 0 R")
        .obj(8, 0, "7 0 R")
        .stream_obj(
            9,
            0,
            "",
            &ok,
            Some(LengthSpec::Indirect(ObjectId::new(10, 0))),
        )
        .obj(10, 0, ok.len().to_string());
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array("length-indirect-cycle")
    );
    finish(&mut b, &trailer)
}

/// `missing-xref`: header, objects 1–5 and `%%EOF`; nothing else.
pub fn missing_xref() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.4");
    one_page(&mut b, "missing-xref");
    b.eof();
    b.build()
}

/// `missing-xref-with-trailer`: header, objects 1–5, a trailer and `%%EOF`; no xref section and
/// no `startxref`.
pub fn missing_xref_with_trailer() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.4");
    one_page(&mut b, "missing-xref-with-trailer");
    b.trailer(format!(
        "/Size 6 /Root 1 0 R /ID {}",
        id_array("missing-xref-with-trailer")
    ))
    .eof();
    b.build()
}

/// `flate-truncated`: content stream 4 is Flate data with its last 8 bytes (the Adler-32
/// checksum and the end of the final block) cut off; `/Length` matches the cut data. The
/// content is 60 lines of text, so a useful prefix decodes.
pub fn flate_truncated() -> Vec<u8> {
    let mut text = Vec::new();
    for line in 0..60u32 {
        text.extend_from_slice(
            format!(
                "BT /F1 10 Tf 72 {} Td (Line {line} of a truncated stream) Tj ET\n",
                760 - line * 12
            )
            .as_bytes(),
        );
    }
    let mut data = encode_flate(&text, FLATE_LEVEL);
    data.truncate(data.len().saturating_sub(8));
    let mut b = PdfBuilder::new();
    b.header("1.4");
    b.obj(1, 0, CATALOG)
        .obj(2, 0, PAGES)
        .obj(3, 0, page("4 0 R"))
        .stream_obj(4, 0, "/Filter /FlateDecode", &data, None)
        .obj(5, 0, FONT);
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array("flate-truncated")
    );
    finish(&mut b, &trailer)
}

/// `objstm-extends-loop`: object stream 9 (font 5) says `/Extends 10 0 R` and object stream 10
/// (catalog 1, page tree 2, page 3) says `/Extends 9 0 R`; content stream 4 is plain;
/// cross-reference stream 11. Every object is still reachable through the xref stream.
pub fn objstm_extends_loop() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.5");
    b.stream_obj(4, 0, "", &content("objstm-extends-loop", 720), None);
    b.objstm(
        9,
        &[(5, FONT)],
        ObjStmOpts::new().with_extends(ObjectId::new(10, 0)),
    );
    b.objstm(
        10,
        &[
            (1, CATALOG.to_owned()),
            (2, PAGES.to_owned()),
            (3, page("4 0 R")),
        ],
        ObjStmOpts::new().with_extends(ObjectId::new(9, 0)),
    );
    b.xref_stream(
        11,
        XrefStreamOpts::new().with_trailer(format!(
            "/Root 1 0 R /ID {}",
            id_array("objstm-extends-loop")
        )),
    );
    b.startxref(None).eof();
    b.build()
}

/// `objstm-n-too-large`: catalog 1, page tree 2, page 3 and font 5 in object stream 6, whose
/// dictionary says `/N 1000`; content stream 4 is plain; cross-reference stream 7.
pub fn objstm_n_too_large() -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.5");
    b.stream_obj(4, 0, "", &content("objstm-n-too-large", 720), None);
    b.objstm(
        6,
        &[
            (1, CATALOG.to_owned()),
            (2, PAGES.to_owned()),
            (3, page("4 0 R")),
            (5, FONT.to_owned()),
        ],
        ObjStmOpts::new().with_n(1000),
    );
    b.xref_stream(
        7,
        XrefStreamOpts::new().with_trailer(format!(
            "/Root 1 0 R /ID {}",
            id_array("objstm-n-too-large")
        )),
    );
    b.startxref(None).eof();
    b.build()
}

// ---------------------------------------------------------------------------------------------
// Encryption detection
// ---------------------------------------------------------------------------------------------

/// A one-page file whose trailer has `/Encrypt 6 0 R`, with `encrypt` as object 6.
fn encrypted_with(name: &str, encrypt: &str) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.4");
    one_page(&mut b, name);
    b.obj(6, 0, encrypt);
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /Encrypt 6 0 R /ID {}",
        b.size(),
        id_array(name)
    );
    finish(&mut b, &trailer)
}

/// `encrypted`: `/Encrypt` names a standard security handler dictionary (`/V 1 /R 2`, 40-bit
/// RC4) with fixed `/O` and `/U` values. Nothing is actually encrypted: the file only tests that
/// opening it reports `PasswordRequired`.
pub fn encrypted() -> Vec<u8> {
    let o = super::hex_upper(
        &[
            super::file_id("encrypted/O"),
            super::file_id("encrypted/O2"),
        ]
        .concat(),
    );
    let u = super::hex_upper(
        &[
            super::file_id("encrypted/U"),
            super::file_id("encrypted/U2"),
        ]
        .concat(),
    );
    encrypted_with(
        "encrypted",
        &format!("<< /Filter /Standard /V 1 /R 2 /Length 40 /O <{o}> /U <{u}> /P -3904 >>"),
    )
}

/// `encrypted-unknown-handler`: `/Encrypt` names the public-key security handler
/// `/Adobe.PubSec` (§7.6.5), which the syntax layer does not support.
pub fn encrypted_unknown_handler() -> Vec<u8> {
    encrypted_with(
        "encrypted-unknown-handler",
        "<< /Filter /Adobe.PubSec /SubFilter /adbe.pkcs7.s4 /V 1 /R 2 /Recipients [<3000>] /P -3904 >>",
    )
}

// ---------------------------------------------------------------------------------------------
// Large page trees (generated at test time, never committed)
// ---------------------------------------------------------------------------------------------

/// The [`LAZY_PAGE_COUNT`]-page file for the `open_is_lazy` test: [`many_pages`]`(2000)`.
pub fn lazy_pages() -> Vec<u8> {
    many_pages(LAZY_PAGE_COUNT)
}

/// The object numbers of a [`many_pages`] document.
struct PageTreeLayout {
    pages: u32,
    nodes: u32,
}

impl PageTreeLayout {
    fn new(pages: u32) -> Self {
        PageTreeLayout {
            pages,
            nodes: pages.div_ceil(PAGES_PER_NODE),
        }
    }

    /// Object number of intermediate node `node` (0-based).
    fn node(&self, node: u32) -> u32 {
        4 + node
    }

    /// Object number of page `page` (0-based); its content stream is the next number.
    fn page(&self, page: u32) -> u32 {
        4 + self.nodes + 2 * page
    }

    /// The objects that are not streams: `(number, body)`, in number order.
    fn dict_objects(&self) -> Vec<(u32, String)> {
        let mut objects = Vec::with_capacity(3 + self.nodes as usize + self.pages as usize);
        objects.push((1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()));
        let kids: Vec<String> = (0..self.nodes)
            .map(|n| format!("{} 0 R", self.node(n)))
            .collect();
        // MediaBox and Resources are inherited from the root (§7.7.3.4).
        objects.push((
            2,
            format!(
                "<< /Type /Pages /Kids [{}] /Count {} /MediaBox [0 0 612 792] \
                 /Resources << /Font << /F1 3 0 R >> >> >>",
                kids.join(" "),
                self.pages
            ),
        ));
        objects.push((3, FONT.to_owned()));
        for n in 0..self.nodes {
            let first = n * PAGES_PER_NODE;
            let last = (first + PAGES_PER_NODE).min(self.pages);
            let kids: Vec<String> = (first..last)
                .map(|p| format!("{} 0 R", self.page(p)))
                .collect();
            objects.push((
                self.node(n),
                format!(
                    "<< /Type /Pages /Parent 2 0 R /Kids [{}] /Count {} >>",
                    kids.join(" "),
                    last - first
                ),
            ));
        }
        for p in 0..self.pages {
            let node = self.node(p / PAGES_PER_NODE);
            objects.push((
                self.page(p),
                format!(
                    "<< /Type /Page /Parent {node} 0 R /Contents {} 0 R >>",
                    self.page(p) + 1
                ),
            ));
        }
        objects
    }

    fn page_content(page: u32) -> Vec<u8> {
        format!("BT /F1 12 Tf 72 720 Td (Page {}) Tj ET", page + 1).into_bytes()
    }
}

/// A document with `pages` pages and a classic xref table: catalog 1, root page tree 2 (with
/// the inherited `/MediaBox` and `/Resources`), font 3, intermediate page-tree nodes from 4 with
/// [`PAGES_PER_NODE`] pages each, then every page followed by its content stream.
pub fn many_pages(pages: u32) -> Vec<u8> {
    let layout = PageTreeLayout::new(pages);
    let mut b = PdfBuilder::new();
    b.header("1.4");
    // Dictionaries up to the first page, then each page followed by its content stream.
    for (num, body) in layout.dict_objects() {
        b.obj(num, 0, body);
        if num >= layout.page(0) {
            let page = (num - layout.page(0)) / 2;
            b.stream_obj(num + 1, 0, "", &PageTreeLayout::page_content(page), None);
        }
    }
    b.xref_table(XrefOpts::default());
    let trailer = format!(
        "/Size {} /Root 1 0 R /ID {}",
        b.size(),
        id_array(&format!("many-pages-{pages}"))
    );
    finish(&mut b, &trailer)
}

/// The same document as [`many_pages`], with every dictionary in object streams of
/// [`OBJECTS_PER_OBJSTM`] objects (numbered after the content streams) and a cross-reference
/// stream at the end.
pub fn many_pages_compressed(pages: u32) -> Vec<u8> {
    let layout = PageTreeLayout::new(pages);
    let mut b = PdfBuilder::new();
    b.header("1.5");
    for p in 0..pages {
        b.stream_obj(
            layout.page(p) + 1,
            0,
            "",
            &PageTreeLayout::page_content(p),
            None,
        );
    }
    let mut next = layout.page(pages);
    let objects = layout.dict_objects();
    for chunk in objects.chunks(OBJECTS_PER_OBJSTM) {
        b.objstm(next, chunk, ObjStmOpts::new());
        next += 1;
    }
    b.xref_stream(
        next,
        XrefStreamOpts::new()
            .with_predictor(true)
            .with_trailer(format!(
                "/Root 1 0 R /ID {}",
                id_array(&format!("many-pages-compressed-{pages}"))
            )),
    );
    b.startxref(None).eof();
    b.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_kebab_case() {
        let mut names: Vec<&str> = FIXTURES.iter().map(|f| f.name).collect();
        for name in &names {
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{name}"
            );
        }
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), FIXTURES.len());
    }

    #[test]
    fn generation_is_deterministic_and_small() {
        for (name, pdf) in all() {
            assert_eq!(get(name).unwrap(), pdf, "{name}");
            assert!(pdf.len() < 200 * 1024, "{name}: {} bytes", pdf.len());
        }
        assert!(get("no-such-fixture").is_none());
    }

    #[test]
    fn every_fixture_ends_with_eof_marker_and_has_a_header() {
        for (name, pdf) in all() {
            assert!(pdf.ends_with(b"%%EOF\n"), "{name}");
            let header = pdf.windows(5).position(|w| w == b"%PDF-").unwrap();
            assert_eq!(header == 0, name != "junk-before-header", "{name}");
        }
    }

    #[test]
    fn junk_is_longer_than_the_search_window() {
        assert_eq!(MAIL_JUNK.len(), 118);
    }

    #[test]
    fn page_tree_layout() {
        let layout = PageTreeLayout::new(250);
        assert_eq!(layout.nodes, 3);
        assert_eq!(layout.node(2), 6);
        assert_eq!(layout.page(0), 7);
        assert_eq!(layout.page(249), 7 + 498);
        let objects = layout.dict_objects();
        assert_eq!(objects.len(), 3 + 3 + 250);
        assert!(objects[5].1.ends_with("/Count 50 >>"));
        let empty = PageTreeLayout::new(0);
        assert_eq!(empty.dict_objects().len(), 3);
        assert!(many_pages(0).ends_with(b"%%EOF\n"));
    }
}

//! Helpers shared by the integration tests: building small documents and opening them.
#![allow(dead_code)]

use folioxide_model::{Document, Rect};
use folioxide_syntax::{Diagnostic, OpenOptions, Strictness};
use folioxide_testkit::builder::{PdfBuilder, XrefOpts};

/// A file with header `version`, the objects `(number, body)` in order, a classic xref table,
/// and `/Root 1 0 R` plus `trailer_extra` in the trailer.
pub fn build(version: &str, objects: &[(u32, &str)], trailer_extra: &str) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header(version);
    for (num, body) in objects {
        b.obj(*num, 0, body);
    }
    b.xref_table(XrefOpts::default());
    let trailer = format!("/Size {} /Root 1 0 R {trailer_extra}", b.size());
    b.trailer(trailer).startxref(None).eof();
    b.build()
}

/// Opens `pdf` with the default (lenient) options.
pub fn open(pdf: Vec<u8>) -> Document {
    Document::open(pdf, &OpenOptions::default()).expect("the document opens")
}

/// Opens `pdf` in strict mode.
pub fn open_strict(pdf: Vec<u8>) -> Document {
    Document::open(
        pdf,
        &OpenOptions::default().with_strictness(Strictness::Strict),
    )
    .expect("the document opens in strict mode")
}

/// The corners of a rectangle.
pub fn corners(r: Rect) -> [f64; 4] {
    [r.llx, r.lly, r.urx, r.ury]
}

/// The diagnostics whose message contains `needle`.
pub fn diagnostics_with(doc: &Document, needle: &str) -> Vec<Diagnostic> {
    doc.diagnostics()
        .into_iter()
        .filter(|d| d.message.contains(needle))
        .collect()
}

//! Fixtures written by qpdf: layouts that real writers produce and [`PdfBuilder`] does not, read
//! from the committed files in `fixtures/qpdf/`.
//!
//! They are written by `tools/fixtures/qpdf.py` with pikepdf and libqpdf from the oracle venv
//! (`bash tools/setup-venv.sh`), not by Rust code, so there is no generator here: [`infos`]
//! describes them and [`read_committed`] reads them. The script's `--check` (run by the oracle
//! self-tests in CI) regenerates them with the pinned pikepdf and libqpdf and compares the
//! bytes; `fixtures/README.md` records the versions.
//!
//! Each file is a three-page document ([`PAGES`]): page `k` shows `(<name>, page k)` in a shared
//! Helvetica font, and the trailer has an `/Info` dictionary with a `/Title`.
//!
//! [`PdfBuilder`]: crate::PdfBuilder
//!
//! ```
//! use folioxide_syntax::{OpenOptions, Store};
//! use folioxide_testkit::fixtures::qpdf;
//!
//! for info in qpdf::infos() {
//!     let bytes = qpdf::read_committed(info.name).unwrap();
//!     let store = Store::open_bytes(bytes, &OpenOptions::default()).unwrap();
//!     assert_eq!(store.revisions().len(), 2, "{}", info.name);
//! }
//! ```

use folioxide_syntax::XrefKind;

/// The page count of every qpdf fixture.
pub const PAGES: u32 = 3;

/// Description of one committed qpdf fixture.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct QpdfFixture {
    /// The name; the committed file is `fixtures/qpdf/<name>.pdf`.
    pub name: &'static str,
    /// What the file contains and what it tests.
    pub description: &'static str,
    /// How its cross-reference sections are stored (both sections the same way).
    pub xref_kind: XrefKind,
    /// The header version qpdf wrote.
    pub version: (u8, u8),
}

/// The committed qpdf fixtures, in the order of `tools/fixtures/qpdf.py`.
const FIXTURES: &[QpdfFixture] = &[
    QpdfFixture {
        name: "linearized",
        description: "linearized by qpdf (Annex F) with cross-reference tables: the first-page \
                      section near the start, followed by a dummy `startxref 0` and `%%EOF`, \
                      the main section at the end, whose `startxref` points back at the \
                      first-page section",
        xref_kind: XrefKind::Table,
        version: (1, 3),
    },
    QpdfFixture {
        name: "linearized-objstm",
        description: "linearized by qpdf with object streams: both sections are \
                      cross-reference streams, and the first-page one has no `startxref` of \
                      its own",
        xref_kind: XrefKind::Stream,
        version: (1, 5),
    },
];

/// Descriptions of every committed qpdf fixture.
pub fn infos() -> &'static [QpdfFixture] {
    FIXTURES
}

/// The path of the committed fixture `name`: `<workspace>/fixtures/qpdf/<name>.pdf`.
pub fn committed_path(name: &str) -> std::path::PathBuf {
    super::fixtures_dir()
        .join("qpdf")
        .join(format!("{name}.pdf"))
}

/// Reads the committed fixture `name`.
///
/// # Errors
/// Any I/O error, for example for a name that [`infos`] does not list.
pub fn read_committed(name: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(committed_path(name))
}

/// The text page `page` (1-based) of the fixture `name` shows, as its content stream holds it.
pub fn page_content(name: &str, page: u32) -> Vec<u8> {
    format!("BT /F1 24 Tf 72 720 Td ({name}, page {page}) Tj ET").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_fixture_is_committed_and_nothing_else() {
        let dir = super::super::fixtures_dir().join("qpdf");
        let mut committed: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".pdf"))
            .collect();
        committed.sort();
        let mut listed: Vec<String> = infos().iter().map(|i| format!("{}.pdf", i.name)).collect();
        listed.sort();
        assert_eq!(committed, listed);
        for info in infos() {
            let bytes = read_committed(info.name).unwrap();
            let (major, minor) = info.version;
            assert!(
                bytes.starts_with(format!("%PDF-{major}.{minor}").as_bytes()),
                "{}",
                info.name
            );
            assert!(bytes.len() < 200 * 1024, "{}", info.name);
        }
        assert!(read_committed("no-such-fixture").is_err());
    }
}

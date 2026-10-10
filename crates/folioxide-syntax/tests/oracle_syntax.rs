#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Oracle suite `syntax` (M1 brief WP1.5, acceptance criterion 7).
//!
//! Every committed fixture of `fixtures/syntax/` becomes the oracle case
//! `target/oracle/syntax/<name>.pdf` plus `<name>.expect.json` when the tests are built with the
//! `folioxide-testkit/emit` feature (`cargo xtask oracle --suite syntax`); without the feature
//! the test still computes and checks every expectation, and writes nothing.
//!
//! - **Oracle-clean fixtures** (pikepdf/qpdf and poppler read them without repair, see
//!   `FixtureInfo::oracle_clean`) expect `pages` (our page-tree walk), `version` (the header
//!   version; no fixture has a catalog `/Version`) and `objectCount`: the number of in-use
//!   objects in our merged cross-reference data that resolve to a non-null object.
//!   `tools/oracles/check_pdf.py` (`check_object_count`) documents how that is compared with
//!   pikepdf's `len(pdf.objects)`.
//! - A few oracle-clean fixtures hit a documented limitation of one oracle; those checks are
//!   listed under `knownFailures` with the reason ([`known_failures`]), so they still run and
//!   the entry fails once the limitation is gone.
//! - **Every other fixture** is marked `oracleSkip` with the reason: the oracles would have to
//!   repair (or, for the fake encryption, refuse) it, so there is nothing to compare.
//! - The linearized files that qpdf wrote (`fixtures/qpdf/`, `folioxide_testkit::fixtures::qpdf`)
//!   are cases `qpdf-<name>` with the same expectations: qpdf wrote them, so they are clean by
//!   construction, and the oracles check that we count their objects and pages as qpdf does.

use folioxide_syntax::{OpenOptions, Store};
use folioxide_testkit::exercise::page_count;
use folioxide_testkit::fixtures::{qpdf, syntax};
use folioxide_testkit::{EMIT_ENABLED, ExpectJson, emit_case};

/// The oracle suite name.
const SUITE: &str = "syntax";

/// The acceptance criterion: at least this many cases are checked rather than skipped.
const MIN_CHECKED: usize = 6;

/// Checks of the oracle runner that are expected to fail on an oracle-clean fixture, with the
/// reason: limitations of pypdf, which pikepdf/qpdf and poppler do not share.
fn known_failures(name: &str) -> &'static [(&'static str, &'static str)] {
    match name {
        "multi-revision" => &[(
            "structure.pypdf",
            "pypdf 6 strict mode warns 'Xref table not zero-indexed' for every update section \
             whose first subsection does not start at 0, which ISO 32000-2 §7.5.6 allows",
        )],
        "qpdf-linearized" => &[(
            "structure.pypdf",
            "pypdf 6 strict mode warns 'Xref table not zero-indexed' for the first-page \
             cross-reference table of a linearized file, whose only subsection starts at the \
             linearization dictionary's number (ISO 32000-2 Annex F, §7.5.4)",
        )],
        "junk-before-header" => &[
            (
                "structure.pypdf",
                "pypdf strict mode refuses bytes before %PDF-, which pikepdf/qpdf and poppler \
                 accept (ISO 32000-2 Annex H)",
            ),
            (
                "version.pypdf",
                "pypdf reads the version from the first bytes of the file, which are the junk",
            ),
        ],
        _ => &[],
    }
}

/// The committed bytes of `fixtures/syntax/<name>.pdf`.
fn committed(name: &str) -> Vec<u8> {
    syntax::read_committed(name).unwrap_or_else(|err| {
        panic!("fixtures/syntax/{name}.pdf: {err} (run `cargo xtask fixtures`)")
    })
}

/// `objectCount`: the in-use objects of the merged cross-reference data that resolve to a
/// non-null object.
fn object_count(store: &Store) -> usize {
    store
        .object_ids()
        .into_iter()
        .filter(|&id| store.resolve(id).is_ok_and(|obj| !obj.is_null()))
        .count()
}

/// The expectation for the fixture `name`, or the reason it is skipped.
fn expectation(name: &str) -> Result<ExpectJson, String> {
    let info = syntax::info(name).unwrap();
    if !info.oracle_clean {
        return Err(format!(
            "{}: pikepdf/qpdf or poppler would have to repair or refuse this file, so there \
             is nothing to compare",
            info.description
        ));
    }
    let mut expect = clean_expectation(name, &committed(name), info.pages);
    let known = known_failures(name);
    if !known.is_empty() {
        expect = expect.string_map("knownFailures", known);
    }
    Ok(expect)
}

/// `pages`, `version` and `objectCount` for an oracle-clean file with `pages` pages.
fn clean_expectation(name: &str, bytes: &[u8], pages: u32) -> ExpectJson {
    let store = Store::open_bytes(bytes.to_vec(), &OpenOptions::default())
        .unwrap_or_else(|err| panic!("{name}: {err}"));
    let count = object_count(&store);
    assert_eq!(
        count,
        store.object_ids().len(),
        "{name}: an in-use object of an oracle-clean fixture resolves to null"
    );
    assert_eq!(page_count(&store), Some(pages), "{name}");
    let (major, minor) = store.version();
    ExpectJson::new()
        .int("pages", i64::from(pages))
        .string("version", &format!("{major}.{minor}"))
        .int("objectCount", count as i64)
}

/// The committed bytes of `fixtures/qpdf/<name>.pdf`.
fn committed_qpdf(name: &str) -> Vec<u8> {
    qpdf::read_committed(name).unwrap_or_else(|err| {
        panic!("fixtures/qpdf/{name}.pdf: {err} (run `tools/fixtures/qpdf.py`)")
    })
}

#[test]
fn syntax_oracle_cases() {
    let mut checked = 0;
    let mut written = 0;
    for info in syntax::infos() {
        let expect = match expectation(info.name) {
            Ok(expect) => {
                checked += 1;
                expect
            }
            Err(reason) => ExpectJson::new().string("oracleSkip", &reason),
        };
        let written_to = emit_case(SUITE, info.name, &committed(info.name), &expect)
            .unwrap_or_else(|err| panic!("{}: {err}", info.name));
        if written_to.is_some() {
            written += 1;
        }
    }
    for info in qpdf::infos() {
        let bytes = committed_qpdf(info.name);
        let case = format!("qpdf-{}", info.name);
        let mut expect = clean_expectation(&case, &bytes, qpdf::PAGES);
        let known = known_failures(&case);
        if !known.is_empty() {
            expect = expect.string_map("knownFailures", known);
        }
        checked += 1;
        let written_to =
            emit_case(SUITE, &case, &bytes, &expect).unwrap_or_else(|err| panic!("{case}: {err}"));
        if written_to.is_some() {
            written += 1;
        }
    }
    assert!(
        checked >= MIN_CHECKED,
        "only {checked} oracle-clean fixtures"
    );
    assert_eq!(
        written,
        if EMIT_ENABLED {
            syntax::infos().len() + qpdf::infos().len()
        } else {
            0
        }
    );
}

#[test]
fn expectations_of_known_fixtures() {
    // The counts the oracle compares, spelled out for a few fixtures.
    let expect = expectation("minimal").unwrap();
    assert_eq!(expect.get("objectCount"), Some("5"));
    assert_eq!(expect.get("version"), Some("\"1.4\""));
    // Three revisions; /Info 6 is freed by the last one (pikepdf lists it as null).
    let expect = expectation("multi-revision").unwrap();
    assert_eq!(expect.get("objectCount"), Some("7"));
    assert_eq!(expect.get("pages"), Some("2"));
    assert!(
        expect
            .get("knownFailures")
            .unwrap()
            .contains("structure.pypdf")
    );
    // The object stream container and the cross-reference stream count, and so does every
    // object inside the object stream.
    assert_eq!(expectation("objstm").unwrap().get("objectCount"), Some("8"));
    assert_eq!(expectation("hybrid").unwrap().get("objectCount"), Some("7"));
    // The linearized files: every object of both sections counts, the linearization
    // dictionary and the hint stream included (and, with object streams, the containers, both
    // cross-reference streams and the compressed objects).
    for (name, objects) in [("linearized", 12), ("linearized-objstm", 15)] {
        let expect = clean_expectation(name, &committed_qpdf(name), qpdf::PAGES);
        assert_eq!(
            expect.get("objectCount"),
            Some(objects.to_string().as_str()),
            "{name}"
        );
        assert_eq!(expect.get("pages"), Some("3"), "{name}");
    }
    let skip = expectation("prev-loop").unwrap_err();
    assert!(skip.contains("/Prev"), "{skip}");
    // Every fixture with known failures is oracle-clean (others are skipped wholesale).
    for info in syntax::infos() {
        assert!(
            known_failures(info.name).is_empty() || info.oracle_clean,
            "{}",
            info.name
        );
    }
}

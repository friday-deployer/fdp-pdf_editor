#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The oracle suite `certify` (M4 brief §6.3): the certification corpus (`certify_corpus()`),
//! the pyHanko-certified fixtures, and the committed pyHanko files of the cases that pyHanko must
//! create (`pyhanko-certified-p1-dts.pdf`, `pyhanko-certified-p2-visible-approval.pdf`) when
//! they are present.
//!
//! Every case writes its expect.json `signatures[]` values (`intact`, `valid`, `trusted`,
//! `coverage`, `modification`, `docmdp`, `docmdpOk`) **from Folioxide's own report**
//! (`sign_support::oracle`), `docmdpOk` for every signature (an approval's verdict under the
//! certification in force). Where Folioxide deliberately differs (D-2 stricter, D-1 more
//! lenient), the expect file carries pyHanko's value for the certification signature and
//! `certify_corpus.rs` asserts ours.

mod sign_support;

use folioxide_testkit::emit::json_string;
use folioxide_testkit::{EMIT_ENABLED, ExpectJson, emit_case};
use sign_support::corpus::{ATTACKED_FIELD, certify_corpus, pyhanko_value};
use sign_support::oracle::{TRUST_ROOT, entry_with, startxref_count};
use sign_support::*;

/// One oracle case.
struct Case {
    name: String,
    pdf: Vec<u8>,
    expect: ExpectJson,
}

/// The case `name` for `pdf`: our reports of every field signature, with pyHanko's value for
/// the deliberate differences of `deliberate` (a corpus case name): the certification
/// signature's (`field` rows), and another signature's (`<field name>.<field>` rows, manager
/// ruling R-7), and `known` as `knownFailures`.
fn case(
    name: &str,
    pdf: Vec<u8>,
    deliberate: Option<&'static str>,
    known: &[(&str, &str)],
) -> Case {
    let reports = verify(&pdf);
    assert!(!reports.is_empty(), "{name}");
    let entries: Vec<String> = reports
        .iter()
        .filter(|r| r.field_name.is_some())
        .map(|r| {
            let field_name = r.field_name.as_deref().unwrap_or_default();
            let overrides = |field: &str| {
                deliberate.and_then(|case| {
                    if field_name == ATTACKED_FIELD {
                        pyhanko_value(case, field)
                    } else {
                        pyhanko_value(case, &format!("{field_name}.{field}"))
                    }
                })
            };
            entry_with(r, &overrides, false, true)
        })
        .collect();
    let doc = open(&pdf);
    let mut expect = ExpectJson::new()
        .raw("trustRoots", format!("[{}]", json_string(TRUST_ROOT)))
        .int("pages", doc.page_count().unwrap() as i64)
        .int("revisions", startxref_count(&pdf))
        .raw("signatures", format!("[{}]", entries.join(", ")));
    if !known.is_empty() {
        expect = expect.string_map("knownFailures", known);
    }
    Case {
        name: name.replace('_', "-"),
        pdf,
        expect,
    }
}

/// The committed pyHanko files of the suite (brief §6.3), those present in the checkout.
const PYHANKO_FILES: &[&str] = &[
    "pyhanko-certified-p1.pdf",
    "pyhanko-certified-p2.pdf",
    "pyhanko-certified-p1-dts.pdf",
    "pyhanko-certified-p2-visible-approval.pdf",
];

/// Every case of the suite.
fn certify_cases() -> Vec<Case> {
    let mut cases: Vec<Case> = certify_corpus()
        .into_iter()
        .filter(|c| c.oracle)
        .map(|c| case(c.name, (c.build)(), Some(c.name), c.known_failures))
        .collect();
    for file in PYHANKO_FILES {
        let path = repo().join("fixtures/sign/pdf").join(file);
        if let Ok(pdf) = std::fs::read(&path) {
            let name = file.trim_end_matches(".pdf");
            cases.push(case(name, pdf, None, &[]));
        }
    }
    cases
}

#[test]
fn oracle_certify() {
    let cases = certify_cases();
    // Brief §6.3: at least 10 checked cases, none skipped.
    assert!(cases.len() >= 10, "{} cases", cases.len());
    assert!(cases.iter().all(|c| c.expect.get("oracleSkip").is_none()));
    // The suite's table: P = 1, 2 and 3 alone; P = 2 fills and approvals; P = 1 + fill and +
    // /Info change; P = 2 + annotation; P = 3 + markup annotation.
    for name in [
        "certify-p1-alone",
        "certify-p2-alone",
        "certify-p3-alone",
        "certify-p2-text-fill",
        "certify-p2-checkbox-fill",
        "certify-p2-approval",
        "certify-p2-existing-visible-signed",
        "certify-p1-fill",
        "certify-p1-info-changed",
        "certify-p2-new-visible-approval",
        "certify-p2-annotation",
        "certify-p3-square",
    ] {
        assert!(cases.iter().any(|c| c.name == name), "{name} missing");
    }
    let mut written = 0;
    for case in &cases {
        if emit_case("certify", &case.name, &case.pdf, &case.expect)
            .unwrap()
            .is_some()
        {
            written += 1;
        }
    }
    assert_eq!(written, if EMIT_ENABLED { cases.len() } else { 0 });
}

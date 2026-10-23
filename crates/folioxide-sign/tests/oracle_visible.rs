#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The oracle suite `visible` (M4 brief §6.3): every case of `visible_cases()` (default text,
//! a JPEG on the left, pages rotated by 90, 180 and 270 degrees, an existing visible field, a
//! visible signature followed by a second one, a visible approval after an invisible
//! signature, a visible B-T certification, an existing visible field signed after a P = 2
//! certification).
//!
//! Each case writes, from Folioxide's own reports (`sign_support::oracle`), the `signatures[]`
//! values (intact, valid, trusted, coverage, modification, `docmdp`/`docmdpOk`, the PAdES level
//! and the signature timestamp), plus:
//! - `textContains: ["Folioxide Test Signer"]`: `pdftotext` reads the signer's name from the
//!   appearance stream;
//! - `renderProbes`: `pdftoppm -r 72 -gray` shows at least 50 dark pixels inside the widget's
//!   rect, mapped through the page's `/Rotate` (the rotated cases probe the rotated raster).

mod sign_support;

use folioxide_testkit::emit::json_string;
use folioxide_testkit::{EMIT_ENABLED, ExpectJson, emit_case};
use sign_support::oracle::{TRUST_ROOT, entry_with, startxref_count};
use sign_support::visible::visible_cases;
use sign_support::*;

/// The fewest dark pixels the widget's rect must show (brief §6.3: `minDark ≥ 50`).
const MIN_DARK: i64 = 50;

#[test]
fn oracle_visible() {
    let cases = visible_cases();
    // Brief §6.3: at least 5 cases; the rotated pages at 90, 180 and 270 degrees.
    assert!(cases.len() >= 5, "{} cases", cases.len());
    for name in [
        "visible-rsa2048-default",
        "visible-p256-image-left",
        "visible-rotate-90",
        "visible-rotate-180",
        "visible-rotate-270",
        "visible-existing-field",
        "visible-then-second-signature",
    ] {
        assert!(cases.iter().any(|c| c.name == name), "{name} missing");
    }
    let mut written = 0;
    for case in &cases {
        let reports = verify(&case.pdf);
        assert!(
            reports.iter().all(|r| r.is_valid()),
            "{}: {:?}",
            case.name,
            reports.iter().map(summary).collect::<Vec<_>>()
        );
        let entries: Vec<String> = reports
            .iter()
            .filter(|r| r.field_name.is_some())
            .map(|r| entry_with(r, &|_| None, true, true))
            .collect();
        let [x0, y0, x1, y1] = case.rect;
        let probe = format!(
            "[{{\"page\": {}, \"rect\": [{x0}, {y0}, {x1}, {y1}], \"minDark\": {MIN_DARK}}}]",
            case.page
        );
        let doc = open(&case.pdf);
        let expect = ExpectJson::new()
            .raw("trustRoots", format!("[{}]", json_string(TRUST_ROOT)))
            .int("pages", doc.page_count().unwrap() as i64)
            .int("revisions", startxref_count(&case.pdf))
            .raw("signatures", format!("[{}]", entries.join(", ")))
            .raw(
                "textContains",
                format!("[{}]", json_string("Folioxide Test Signer")),
            )
            .raw("renderProbes", probe);
        if emit_case("visible", case.name, &case.pdf, &expect)
            .unwrap()
            .is_some()
        {
            written += 1;
        }
    }
    assert_eq!(written, if EMIT_ENABLED { cases.len() } else { 0 });
}

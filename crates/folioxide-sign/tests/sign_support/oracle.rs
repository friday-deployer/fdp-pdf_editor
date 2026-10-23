//! The expect.json `signatures[]` entries of the signature oracle suites (M3 brief §0, §6.3),
//! written **from Folioxide's own report**, so that `cargo xtask oracle` is a pyHanko / pdfsig /
//! OpenSSL versus Folioxide differential. Shared by `oracle_sign.rs` (`sign-bb`, `sign-tamper`,
//! `sign-attacks`), `interop_pyhanko.rs` (`sign-interop`) and `oracle_certify.rs` (`certify`).

use folioxide_sign::report::{PadesLevel, SignatureKind, SignatureReport};
use folioxide_testkit::emit::json_string;

/// The trust root every signature case names (relative to the repository root).
pub const TRUST_ROOT: &str = "fixtures/pki/root.pem";

/// The `signatures[]` entry of one report; `overrides` gives pyHanko's value for a field where
/// Folioxide deliberately differs. `pades` is written only for sound signatures (the `sign-bb`
/// suite): the profile check looks at the CMS alone, while Folioxide never calls a signature
/// that is not intact B-B.
///
/// `pades` is `"B-T"` or `"B-B"` as reported (M4 brief §5 V8), and `timestamp` is `true` for a
/// sound selected signature timestamp, `"invalid"` for a token that is not (M4 brief D-22) and
/// `false` without one (always for a document timestamp).
///
/// One value is not Folioxide's own, by design: a document timestamp is `valid` when it is
/// intact (M3 listed document timestamps without verifying the token; pyHanko and `openssl ts
/// -verify` validate it). `docmdp` and `docmdpOk` (M4 brief V11, §5.3; overridable as
/// `"docmdpOk"`) are written for a signature that declares DocMDP permissions; `docmdpOk` never
/// for a document timestamp (pyHanko has no such verdict for one).
pub fn entry(
    report: &SignatureReport,
    overrides: &dyn Fn(&str) -> Option<&'static str>,
    pades: bool,
) -> String {
    entry_with(report, overrides, pades, false)
}

/// [`entry`], also writing `docmdpOk` for a signature that declares no DocMDP permissions when
/// `every_docmdp_ok` (the `certify` suite: an approval's verdict under the certification in
/// force, which pyHanko computes as well).
pub fn entry_with(
    report: &SignatureReport,
    overrides: &dyn Fn(&str) -> Option<&'static str>,
    pades: bool,
    every_docmdp_ok: bool,
) -> String {
    let field = report.field_name.as_deref().unwrap_or_default();
    let coverage = overrides("coverage").unwrap_or(report.coverage.as_str());
    let modification = overrides("modification").unwrap_or(report.modification.as_str());
    let timestamp = report.kind == SignatureKind::DocTimeStamp;
    let valid = report.signature_valid || (timestamp && report.intact);
    let mut parts = vec![
        format!("\"field\": {}", json_string(field)),
        format!("\"intact\": {}", report.intact),
        format!("\"valid\": {valid}"),
    ];
    if let Some(trusted) = report.trusted {
        parts.push(format!("\"trusted\": {trusted}"));
    }
    parts.push(format!("\"coverage\": {}", json_string(coverage)));
    parts.push(format!("\"modification\": {}", json_string(modification)));
    if let Some(p) = report.docmdp {
        parts.push(format!("\"docmdp\": {p}"));
    }
    // pyHanko's `validate_pdf_timestamp` reports no docmdp_ok for a document timestamp (its
    // DocumentTimestampStatus leaves it None), so none is written for one.
    if !timestamp && (report.docmdp.is_some() || every_docmdp_ok) {
        let ok =
            overrides("docmdpOk").or(report.docmdp_ok.map(|ok| if ok { "true" } else { "false" }));
        if let Some(ok) = ok {
            parts.push(format!("\"docmdpOk\": {ok}"));
        }
    }
    if pades && !timestamp {
        parts.push(match report.pades_level {
            Some(PadesLevel::BT) => "\"pades\": \"B-T\"".to_owned(),
            Some(PadesLevel::BB) => "\"pades\": \"B-B\"".to_owned(),
            _ => "\"pades\": false".to_owned(),
        });
    }
    let token = match &report.timestamp {
        _ if timestamp => "false",
        Some(t) if t.intact && t.valid => "true",
        Some(_) => "\"invalid\"",
        None => "false",
    };
    parts.push(format!("\"timestamp\": {token}"));
    format!("{{{}}}", parts.join(", "))
}

/// The `signatures` array for the field signatures of `reports` (orphans are not pyHanko
/// signatures).
pub fn signatures(reports: &[SignatureReport], pades: bool) -> String {
    let entries: Vec<String> = reports
        .iter()
        .filter(|r| r.field_name.is_some())
        .map(|r| entry(r, &|_| None, pades))
        .collect();
    format!("[{}]", entries.join(", "))
}

/// The number of `startxref` keywords, as the runner counts revisions.
pub fn startxref_count(pdf: &[u8]) -> i64 {
    let key = b"startxref";
    pdf.windows(key.len())
        .enumerate()
        .filter(|(i, w)| {
            *w == key && (*i == 0 || !pdf.get(i - 1).is_some_and(|b: &u8| b.is_ascii_alphabetic()))
        })
        .count() as i64
}

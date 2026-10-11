//! The expect.json `signatures[]` entries of the signature oracle suites (M3 brief §0, §6.3),
//! written **from Folioxide's own report**, so that `cargo xtask oracle` is a pyHanko / pdfsig /
//! OpenSSL versus Folioxide differential. Shared by `oracle_sign.rs` (`sign-bb`, `sign-tamper`,
//! `sign-attacks`) and `interop_pyhanko.rs` (`sign-interop`).

use folioxide_sign::report::{ModificationLevel, PadesLevel, SignatureKind, SignatureReport};
use folioxide_testkit::emit::json_string;

/// The trust root every signature case names (relative to the repository root).
pub const TRUST_ROOT: &str = "fixtures/pki/root.pem";

/// The `signatures[]` entry of one report; `overrides` gives pyHanko's value for a field where
/// Folioxide deliberately differs. `pades` is written only for sound signatures (the `sign-bb`
/// suite): the profile check looks at the CMS alone, while Folioxide never calls a signature
/// that is not intact B-B.
///
/// Two values are not Folioxide's own, by design:
/// - a document timestamp is `valid` when it is intact: M3 lists document timestamps without
///   verifying the token (`PendingTimestampVerification`, `signature_valid` false; brief §5 V1),
///   while pyHanko and `openssl ts -verify` validate it (`interop_pyhanko.rs` asserts ours);
/// - `docmdpOk` (None in our report until M4, V11) is what ISO 32000-2 §12.8.2.2 allows at the
///   reported modification level: P=1 nothing, P=2 form filling and signing, P=3 also
///   annotations.
pub fn entry(
    report: &SignatureReport,
    overrides: &dyn Fn(&str) -> Option<&'static str>,
    pades: bool,
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
        let allowed = match p {
            1 => ModificationLevel::None,
            2 => ModificationLevel::FormFilling,
            _ => ModificationLevel::Annotations,
        };
        parts.push(format!("\"docmdp\": {p}"));
        parts.push(format!("\"docmdpOk\": {}", report.modification <= allowed));
    }
    if pades && !timestamp {
        parts.push(match report.pades_level {
            Some(PadesLevel::BB) => "\"pades\": \"B-B\"".to_owned(),
            _ => "\"pades\": false".to_owned(),
        });
    }
    parts.push("\"timestamp\": false".to_owned());
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

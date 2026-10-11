//! V2–V4: the signature dictionary, its `/ByteRange` and `/Contents`, and the gap check
//! (brief §5; the USF and SWA defences of brief §5.1).
//!
//! - `/ByteRange` must be a **direct** array (an indirect one could live in an unsigned later
//!   revision) of exactly four integers, each `>= 0`, with `o1 == 0`, `l1 > 0`, `o1 + l1 < o2`
//!   and `o2 + l2 <= file length` (checked arithmetic).
//! - The digest is still computed over the pairs **as written** whenever every value is a
//!   non-negative integer, their number is even and every pair lies inside the file (pyHanko's
//!   `byte_range_digest`), so `intact` agrees with pyHanko even for an odd byte range.
//! - `/Contents` must be a direct hexadecimal string.
//! - The dictionary must be an uncompressed object (an object-stream member can never leave
//!   its `/Contents` out of the signed bytes), must end inside the signed bytes, and its
//!   `/Contents` value token, found by re-lexing the object from the file, must span exactly the
//!   gap `[o1 + l1, o2)` and decode to the parsed value (signature wrapping, ISO 32000-2
//!   §12.8.1: the range covers the whole file except the `/Contents` value), with exactly two
//!   hexadecimal digits per byte and no white-space (`2 * len(Contents) + 2` bytes, the length
//!   pyHanko's coverage formulas assume).

use folioxide_model::Document;
use folioxide_syntax::{Dict, Object, ObjectId, ObjectLocation};

use crate::placeholder::dict_value_spans;
use crate::problem::ProblemCode;
use crate::report::{SignatureKind, SignatureReport};

/// What the dictionary checks found, for the CMS and coverage steps.
#[derive(Clone, Debug, Default)]
pub(crate) struct Checked {
    /// The signed byte ranges `(offset, length)` as written, when they can be digested.
    pub(crate) ranges: Option<Vec<(usize, usize)>>,
    /// The `/Contents` bytes, when `/Contents` is a string.
    pub(crate) contents: Option<Vec<u8>>,
    /// The gap of the byte range is exactly this dictionary's `/Contents` token.
    pub(crate) gap_ok: bool,
}

/// The kind of a signature dictionary: a document timestamp for `/Type /DocTimeStamp` or
/// `/SubFilter /ETSI.RFC3161` (§12.8.5).
pub(crate) fn kind_of(dict: &Dict) -> SignatureKind {
    let rfc3161 = dict
        .get_name(b"SubFilter")
        .is_some_and(|s| s == b"ETSI.RFC3161");
    if dict.is_type(b"DocTimeStamp") || rfc3161 {
        SignatureKind::DocTimeStamp
    } else {
        SignatureKind::Signature
    }
}

/// Checks the signature dictionary `dict` (object `sig`, when indirect) of `doc` and fills the
/// dictionary fields of `report` (`sub_filter`, `byte_range`, the text entries and the
/// problems).
pub(crate) fn check(
    doc: &Document,
    sig: Option<ObjectId>,
    dict: &Dict,
    report: &mut SignatureReport,
) -> Checked {
    let store = doc.store();
    let source = store.source();
    let file_len = source.len();
    let mut checked = Checked::default();

    // V2: /Filter and /SubFilter (§12.8.1 Table 255).
    match dict.get_name(b"Filter") {
        None => report.warn("the signature dictionary has no /Filter"),
        Some(filter) if filter != b"Adobe.PPKLite" => report.warn(format!(
            "the signature dictionary's /Filter is /{filter}, not /Adobe.PPKLite"
        )),
        Some(_) => {}
    }
    report.sub_filter = dict
        .get_name(b"SubFilter")
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned());
    text_entries(dict, report);

    // V3: /ByteRange.
    let mut values: Option<Vec<i64>> = None;
    match dict.get(b"ByteRange") {
        None => report.problem(
            ProblemCode::ByteRangeMissing,
            "the signature dictionary has no /ByteRange",
        ),
        Some(value) => {
            let resolved = match value {
                Object::Ref(id) => {
                    report.problem(
                        ProblemCode::ByteRangeIndirect,
                        format!(
                            "/ByteRange is the indirect object {id}, which a later revision \
                             could replace"
                        ),
                    );
                    store.resolve(*id).ok().map(|o| Object::clone(&o))
                }
                direct => Some(direct.clone()),
            };
            match resolved.as_ref().and_then(Object::as_array) {
                Some(items) => {
                    let ints: Option<Vec<i64>> = items.iter().map(Object::as_int).collect();
                    match ints {
                        Some(ints) => values = Some(ints),
                        None => report.problem(
                            ProblemCode::ByteRangeMalformed,
                            "/ByteRange holds values that are not integers",
                        ),
                    }
                }
                None => report.problem(
                    ProblemCode::ByteRangeMalformed,
                    "/ByteRange is not an array",
                ),
            }
        }
    }
    if let Some(values) = &values {
        check_values(values, file_len as u64, report);
        checked.ranges = digest_ranges(values, file_len);
    }
    report.byte_range = values.clone();

    // V4: /Contents.
    match dict.get(b"Contents") {
        None => report.problem(
            ProblemCode::ContentsMissing,
            "the signature dictionary has no /Contents",
        ),
        Some(Object::String(s)) if s.hex => checked.contents = Some(s.bytes.clone()),
        Some(Object::String(_)) => report.problem(
            ProblemCode::ContentsNotHex,
            "/Contents is a literal string, not a hexadecimal string",
        ),
        Some(Object::Ref(id)) => report.problem(
            ProblemCode::ContentsNotHex,
            format!("/Contents is the indirect object {id}, not a direct hexadecimal string"),
        ),
        Some(other) => report.problem(
            ProblemCode::ContentsNotHex,
            format!(
                "/Contents is a {}, not a hexadecimal string",
                other.type_name()
            ),
        ),
    }

    // V4: where the dictionary is, and the gap.
    let Some(sig) = sig else {
        return checked;
    };
    let (start, end) = match store.object_location(sig) {
        Some(ObjectLocation::InFile { start, end }) => (start, end),
        Some(ObjectLocation::InObjStm { stream, .. }) => {
            report.problem(
                ProblemCode::SigDictCompressed,
                format!(
                    "the signature dictionary is in the object stream {stream} 0 R, so its \
                     /Contents cannot be left out of the signed bytes"
                ),
            );
            return checked;
        }
        _ => {
            report.problem(
                ProblemCode::GapNotContents,
                "the signature dictionary cannot be located in the file",
            );
            return checked;
        }
    };
    let gap = match values.as_deref() {
        Some([o1, l1, o2, l2]) if *o1 >= 0 && *l1 >= 0 && *o2 >= 0 && *l2 >= 0 => {
            if let Some(signed_end) = o2.checked_add(*l2)
                && end > signed_end as u64
            {
                report.problem(
                    ProblemCode::SigDictOutsideSignedRange,
                    format!(
                        "the signature dictionary ends at {end}, after the signed bytes \
                         ({signed_end})"
                    ),
                );
            }
            o1.checked_add(*l1).map(|a| (a as u64, *o2 as u64))
        }
        _ => None,
    };
    let Some((a, b)) = gap else {
        return checked;
    };
    let spans = usize::try_from(start)
        .ok()
        .zip(usize::try_from(end).ok())
        .and_then(|(s, e)| dict_value_spans(source, s, e).ok());
    let token = spans.and_then(|entries| {
        entries
            .into_iter()
            .rev()
            .find(|(key, _)| key.as_slice() == b"Contents")
            .map(|(_, range)| range)
    });
    match token {
        Some(range) if range.start as u64 == a && range.end as u64 == b => {
            let token_len = range.len();
            let decoded = source.get(range).and_then(decode_hex_token);
            // pyHanko's coverage formulas count `2 * len(Contents) + 2` bytes for the token
            // (`<`, two digits per byte, `>`): a token with white-space or an odd digit count
            // spans a different number of bytes, so its gap is not "fully explained" (brief §4.2
            // writes no white-space; pyHanko reports such a gap UNCLEAR).
            let exact = decoded
                .as_ref()
                .and_then(|d| d.len().checked_mul(2)?.checked_add(2))
                == Some(token_len);
            if decoded.is_some() && decoded == checked.contents && exact {
                checked.gap_ok = true;
            } else if decoded.is_some() && decoded == checked.contents {
                report.problem(
                    ProblemCode::GapNotContents,
                    "the /Contents token in the /ByteRange gap holds white-space or an odd number \
                     of digits, so the gap is not exactly two digits per byte of the parsed \
                     /Contents value",
                );
            } else {
                report.problem(
                    ProblemCode::GapNotContents,
                    "the bytes in the /ByteRange gap are not the parsed /Contents value",
                );
            }
        }
        Some(range) => report.problem(
            ProblemCode::GapNotContents,
            format!(
                "the /ByteRange gap is [{a}, {b}), but the dictionary's /Contents token is at \
                 [{}, {})",
                range.start, range.end
            ),
        ),
        None => report.problem(
            ProblemCode::GapNotContents,
            "the /Contents token cannot be found in the signature dictionary's bytes",
        ),
    }
    checked
}

/// V3 on the integer values of `/ByteRange`.
fn check_values(values: &[i64], file_len: u64, report: &mut SignatureReport) {
    let [o1, l1, o2, l2] = values else {
        report.problem(
            ProblemCode::ByteRangeMalformed,
            format!("/ByteRange has {} values, not 4", values.len()),
        );
        return;
    };
    if values.iter().any(|&v| v < 0) {
        report.problem(
            ProblemCode::ByteRangeMalformed,
            "/ByteRange has a negative value",
        );
        return;
    }
    if *o1 != 0 {
        report.problem(
            ProblemCode::ByteRangeNotFromZero,
            format!("the first signed range starts at {o1}, not 0"),
        );
    }
    let gap_ok = *l1 > 0 && o1.checked_add(*l1).is_some_and(|end| end < *o2);
    if !gap_ok {
        report.problem(
            ProblemCode::ByteRangeMalformed,
            format!("/ByteRange [{o1} {l1} {o2} {l2}] has no gap between non-empty ranges"),
        );
    }
    let within = o2
        .checked_add(*l2)
        .and_then(|end| u64::try_from(end).ok())
        .is_some_and(|end| end <= file_len);
    if !within {
        report.problem(
            ProblemCode::ByteRangeOutOfBounds,
            format!("the second signed range [{o2}, {o2} + {l2}) ends past the end of the file ({file_len} bytes)"),
        );
    }
}

/// The pairs of `values` as `(offset, length)` when every value is non-negative, their number is
/// even and non-zero, and every pair lies inside the file.
fn digest_ranges(values: &[i64], file_len: usize) -> Option<Vec<(usize, usize)>> {
    if values.is_empty() || !values.len().is_multiple_of(2) {
        return None;
    }
    values
        .chunks_exact(2)
        .map(|pair| {
            let [offset, length] = pair else {
                return None;
            };
            let offset = usize::try_from(*offset).ok()?;
            let length = usize::try_from(*length).ok()?;
            (offset.checked_add(length)? <= file_len).then_some((offset, length))
        })
        .collect()
}

/// The bytes of a hexadecimal string token `<…>` (white-space ignored, an odd final digit
/// followed by 0, §7.3.4.3); `None` when the token is not one.
fn decode_hex_token(token: &[u8]) -> Option<Vec<u8>> {
    let digits = token.strip_prefix(b"<")?.strip_suffix(b">")?;
    let mut out = Vec::with_capacity(digits.len() / 2);
    let mut high: Option<u8> = None;
    for &c in digits {
        if matches!(c, b'\0' | b'\t' | b'\n' | 0x0C | b'\r' | b' ') {
            continue;
        }
        let nibble = (c as char).to_digit(16)? as u8;
        match high.take() {
            Some(h) => out.push((h << 4) | nibble),
            None => high = Some(nibble),
        }
    }
    if let Some(h) = high {
        out.push(h << 4);
    }
    Some(out)
}

/// `/M`, `/Name`, `/Reason`, `/Location` and `/ContactInfo` (§12.8.1 Table 255).
fn text_entries(dict: &Dict, report: &mut SignatureReport) {
    let text = |key: &[u8]| {
        dict.get_str_bytes(key)
            .map(folioxide_model::text::decode_text_string)
    };
    report.name = text(b"Name");
    report.reason = text(b"Reason");
    report.location = text(b"Location");
    report.contact_info = text(b"ContactInfo");
    if let Some(m) = dict.get_str_bytes(b"M") {
        match folioxide_model::PdfDate::parse(m) {
            Some(date) => report.claimed_time = Some(date.to_rfc3339()),
            None => report.warn("/M is not a valid PDF date"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_tokens() {
        assert_eq!(decode_hex_token(b"<0A1b>"), Some(vec![0x0A, 0x1B]));
        assert_eq!(decode_hex_token(b"<0A 1\nb>"), Some(vec![0x0A, 0x1B]));
        assert_eq!(decode_hex_token(b"<ABC>"), Some(vec![0xAB, 0xC0]));
        assert_eq!(decode_hex_token(b"<>"), Some(vec![]));
        assert_eq!(decode_hex_token(b"<0G>"), None);
        assert_eq!(decode_hex_token(b"(00)"), None);
        assert_eq!(decode_hex_token(b"<00"), None);
    }

    #[test]
    fn ranges_as_written() {
        assert_eq!(
            digest_ranges(&[0, 10, 20, 5], 25),
            Some(vec![(0, 10), (20, 5)])
        );
        assert_eq!(digest_ranges(&[0, 10, 20, 6], 25), None, "past the end");
        assert_eq!(digest_ranges(&[0, 10, 20], 25), None, "odd");
        assert_eq!(digest_ranges(&[], 25), None);
        assert_eq!(digest_ranges(&[0, -1], 25), None);
        assert_eq!(digest_ranges(&[0, 0], 25), Some(vec![(0, 0)]));
        assert_eq!(
            digest_ranges(&[0, 2, 5, 2, 9, 1], 25),
            Some(vec![(0, 2), (5, 2), (9, 1)])
        );
        assert_eq!(digest_ranges(&[i64::MAX, i64::MAX], 100), None);
    }

    #[test]
    fn value_checks() {
        let codes = |values: &[i64]| {
            let mut report = SignatureReport::new(SignatureKind::Signature, ObjectId::new(1, 0));
            check_values(values, 100, &mut report);
            report.problems.iter().map(|p| p.code).collect::<Vec<_>>()
        };
        assert!(codes(&[0, 10, 20, 80]).is_empty());
        assert_eq!(codes(&[0, 10, 20]), [ProblemCode::ByteRangeMalformed]);
        assert_eq!(codes(&[0, -1, 0, 0]), [ProblemCode::ByteRangeMalformed]);
        assert_eq!(codes(&[1, 2, 4, 4]), [ProblemCode::ByteRangeNotFromZero]);
        assert_eq!(codes(&[0, 0, 0, 0]), [ProblemCode::ByteRangeMalformed]);
        assert_eq!(codes(&[0, 10, 20, 81]), [ProblemCode::ByteRangeOutOfBounds]);
        assert_eq!(
            codes(&[0, 10, i64::MAX, i64::MAX]),
            [ProblemCode::ByteRangeOutOfBounds]
        );
    }

    #[test]
    fn kinds() {
        let mut dict = Dict::new();
        dict.insert("Type", Object::name("Sig"));
        assert_eq!(kind_of(&dict), SignatureKind::Signature);
        dict.insert("SubFilter", Object::name("ETSI.RFC3161"));
        assert_eq!(kind_of(&dict), SignatureKind::DocTimeStamp);
        let mut ts = Dict::new();
        ts.insert("Type", Object::name("DocTimeStamp"));
        assert_eq!(kind_of(&ts), SignatureKind::DocTimeStamp);
    }
}

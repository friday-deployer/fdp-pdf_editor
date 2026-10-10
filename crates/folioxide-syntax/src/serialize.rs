//! The object serializer (ISO 32000-2 §7.3, ARCHITECTURE §A.10 trap #25).
//!
//! Output is compact, deterministic and readable: one space between array elements and
//! between dictionary entries, `<</Key value>>` for dictionaries, and:
//! - **Reals** never use exponents (§7.3.3) and have at most 10 fractional digits. The shortest
//!   decimal that reads back as the same `f64` is used whenever it fits in 10 fractional
//!   digits; otherwise the value is rounded to 10 fractional digits (9 when the integer part
//!   has 6 digits, to stay within 15 significant digits). Trailing zeros are trimmed, `-0` is
//!   written as `0.0`, and integral reals keep `.0` so they read back as reals. Formatting is
//!   idempotent: writing the value a reader got back produces the same text. Values PDF cannot
//!   hold are mapped by a fixed rule (NaN to `0.0`, magnitudes beyond [`MAX_REAL`] and the
//!   infinities clamped to it; see [`format_real`]), so every object serializes to readable PDF.
//! - **Names** escape `#`, delimiters and every byte outside `!`..`~` as `#xx` (§7.3.5).
//! - **Strings** are written literal or hex according to [`PdfString::hex`]; literal strings
//!   escape `(`, `)`, `\`, CR and LF (§7.3.4.2).
//!
//! The serializer is iterative, so arbitrarily deep object trees cannot overflow the stack.

use crate::error::{Error, Result};
use crate::lexer::is_delimiter;
use crate::object::{Dict, Name, Object, ObjectId, PdfString, StreamData};

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Appends the PDF form of a direct object to `out`.
///
/// For an [`Object::Stream`] only the stream dictionary is written: stream data can only appear
/// in an indirect object (see [`serialize_indirect`]).
///
/// ```
/// use folioxide_syntax::{serialize_object, Dict, Object, ObjectId};
///
/// let mut d = Dict::new();
/// d.insert("Type", Object::name("Page"));
/// d.insert("MediaBox", vec![0.into(), 0.into(), 612.5.into(), 792.into()]);
/// d.insert("Parent", ObjectId::new(2, 0));
/// let mut out = Vec::new();
/// serialize_object(&Object::Dict(d), &mut out);
/// assert_eq!(out, b"<</Type /Page /MediaBox [0 0 612.5 792] /Parent 2 0 R>>");
/// ```
pub fn serialize_object(object: &Object, out: &mut Vec<u8>) {
    enum Item<'a> {
        Object(&'a Object),
        Key(&'a Name),
        Raw(&'static [u8]),
    }
    let mut work = vec![Item::Object(object)];
    while let Some(item) = work.pop() {
        match item {
            Item::Raw(bytes) => out.extend_from_slice(bytes),
            Item::Key(name) => write_name(name.as_bytes(), out),
            Item::Object(object) => match object {
                Object::Null => out.extend_from_slice(b"null"),
                Object::Bool(true) => out.extend_from_slice(b"true"),
                Object::Bool(false) => out.extend_from_slice(b"false"),
                Object::Int(i) => write_int(*i, out),
                Object::Real(r) => write_real(*r, out),
                Object::String(s) => write_string(s, out),
                Object::Name(n) => write_name(n.as_bytes(), out),
                Object::Ref(id) => write_ref(*id, out),
                Object::Array(items) => {
                    out.push(b'[');
                    work.push(Item::Raw(b"]"));
                    for (i, item) in items.iter().enumerate().rev() {
                        work.push(Item::Object(item));
                        if i > 0 {
                            work.push(Item::Raw(b" "));
                        }
                    }
                }
                Object::Dict(dict) => push_dict(dict, &mut work, out),
                Object::Stream(stream) => push_dict(&stream.dict, &mut work, out),
            },
        }
    }

    fn push_dict<'a>(dict: &'a Dict, work: &mut Vec<Item<'a>>, out: &mut Vec<u8>) {
        out.extend_from_slice(b"<<");
        work.push(Item::Raw(b">>"));
        for (i, (key, value)) in dict.iter().enumerate().rev() {
            work.push(Item::Object(value));
            work.push(Item::Raw(b" "));
            work.push(Item::Key(key));
            if i > 0 {
                work.push(Item::Raw(b" "));
            }
        }
    }
}

/// Appends an indirect object `N G obj … endobj` to `out` (§7.3.10).
///
/// For a stream (§7.3.8), the data written is, in order of preference:
/// 1. `encoded_stream_bytes`, which must match the dictionary's `/Filter`;
/// 2. the bytes of [`StreamData::Encoded`];
/// 3. the bytes of [`StreamData::Decoded`], written unfiltered: `/Filter` and `/DecodeParms`
///    are left out of the written dictionary.
///
/// `/Length` is always written as the length of the data actually written, replacing any
/// existing value in place or appended at the end. The dictionary is otherwise written as is.
///
/// ```
/// use folioxide_syntax::{serialize_indirect, Dict, Object, ObjectId, Stream, StreamData};
///
/// let stream = Stream::new(Dict::new(), StreamData::Decoded(b"BT ET".to_vec()));
/// let mut out = Vec::new();
/// serialize_indirect(ObjectId::new(4, 0), &stream.into(), None, &mut out)?;
/// assert_eq!(out, b"4 0 obj\n<</Length 5>>\nstream\nBT ET\nendstream\nendobj\n");
/// # Ok::<(), folioxide_syntax::Error>(())
/// ```
///
/// # Errors
/// [`ErrorCode::InvalidArgument`](crate::ErrorCode::InvalidArgument) if `object` is a stream
/// whose data is [`StreamData::Source`] and no `encoded_stream_bytes` are given (the source
/// bytes are not reachable from here), or if `encoded_stream_bytes` is given for an object that
/// is not a stream.
pub fn serialize_indirect(
    id: ObjectId,
    object: &Object,
    encoded_stream_bytes: Option<&[u8]>,
    out: &mut Vec<u8>,
) -> Result<()> {
    let header = |out: &mut Vec<u8>| {
        write_u64(u64::from(id.num), out);
        out.push(b' ');
        write_u64(u64::from(id.r#gen), out);
        out.extend_from_slice(b" obj\n");
    };
    match object {
        Object::Stream(stream) => {
            let (data, unfiltered): (&[u8], bool) = match (encoded_stream_bytes, &stream.data) {
                (Some(bytes), _) => (bytes, false),
                (None, StreamData::Encoded(bytes)) => (bytes, false),
                (None, StreamData::Decoded(bytes)) => (bytes, true),
                (None, StreamData::Source(_)) => {
                    return Err(Error::invalid_argument(format!(
                        "stream {id} refers to source bytes; pass its encoded data explicitly"
                    )));
                }
            };
            header(out);
            write_stream_dict(&stream.dict, data.len(), unfiltered, out);
            // §7.3.8.1: `stream` is followed by an EOL (CRLF or LF); an EOL before
            // `endstream` is not counted in /Length.
            out.extend_from_slice(b"\nstream\n");
            out.extend_from_slice(data);
            out.extend_from_slice(b"\nendstream\nendobj\n");
            Ok(())
        }
        _ => {
            if encoded_stream_bytes.is_some() {
                return Err(Error::invalid_argument(format!(
                    "stream data given for object {id}, which is a {}",
                    object.type_name()
                )));
            }
            header(out);
            serialize_object(object, out);
            out.extend_from_slice(b"\nendobj\n");
            Ok(())
        }
    }
}

/// Writes a stream dictionary with `/Length` set to `len`, optionally without `/Filter` and
/// `/DecodeParms`.
fn write_stream_dict(dict: &Dict, len: usize, unfiltered: bool, out: &mut Vec<u8>) {
    out.extend_from_slice(b"<<");
    let mut first = true;
    let mut wrote_length = false;
    for (key, value) in dict {
        let key_bytes = key.as_bytes();
        if unfiltered
            && (key_bytes == crate::keys::FILTER || key_bytes == crate::keys::DECODE_PARMS)
        {
            continue;
        }
        if !first {
            out.push(b' ');
        }
        first = false;
        write_name(key_bytes, out);
        out.push(b' ');
        if key_bytes == crate::keys::LENGTH {
            write_u64(len as u64, out);
            wrote_length = true;
        } else {
            serialize_object(value, out);
        }
    }
    if !wrote_length {
        if !first {
            out.push(b' ');
        }
        out.extend_from_slice(b"/Length ");
        write_u64(len as u64, out);
    }
    out.extend_from_slice(b">>");
}

/// Appends `N G R`.
fn write_ref(id: ObjectId, out: &mut Vec<u8>) {
    write_u64(u64::from(id.num), out);
    out.push(b' ');
    write_u64(u64::from(id.r#gen), out);
    out.extend_from_slice(b" R");
}

/// Appends an integer in decimal.
pub fn write_int(value: i64, out: &mut Vec<u8>) {
    if value < 0 {
        out.push(b'-');
    }
    write_u64(value.unsigned_abs(), out);
}

fn write_u64(mut value: u64, out: &mut Vec<u8>) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        if let Some(slot) = buf.get_mut(i) {
            *slot = b'0' + (value % 10) as u8;
        }
        value /= 10;
        if value == 0 || i == 0 {
            break;
        }
    }
    out.extend_from_slice(buf.get(i..).unwrap_or_default());
}

/// Formats a real number for PDF: no exponent, at most 10 fractional digits, trailing zeros
/// trimmed, `-0` as `0.0`, and integral values with a trailing `.0` (§7.3.3).
///
/// The shortest decimal that reads back as exactly `value` is used when it has at most 10
/// fractional digits; otherwise `value` is rounded (see the [module docs](self)).
///
/// # Values PDF cannot hold
///
/// Every `f64` produces readable output; the serializer has no error path, so values outside
/// what PDF can express are mapped, by this fixed rule:
///
/// - NaN is written as `0.0`;
/// - the infinities, and finite values beyond [`MAX_REAL`] in magnitude (about `3.403e38`, the
///   largest real ISO 32000 implementations must accept, Annex C), are clamped to `±MAX_REAL`
///   (39 digits), so no reader that stores reals as 32-bit floats overflows on them;
/// - values below `5e-11` in magnitude are written as `0.0` (there are at most 10 fractional
///   digits).
///
/// [`canonical_real`] gives the value a reader gets back. Callers that must not lose a value
/// (coordinates are well within these bounds) check it before writing.
///
/// ```
/// use folioxide_syntax::serialize::{MAX_REAL, format_real};
///
/// assert_eq!(format_real(1.0), "1.0");
/// assert_eq!(format_real(-0.0), "0.0");
/// assert_eq!(format_real(0.1 + 0.2), "0.3");
/// assert_eq!(format_real(1234567.8), "1234567.8");
/// assert_eq!(format_real(1e-7), "0.0000001");
/// assert_eq!(format_real(1e21), "1000000000000000000000.0");
/// assert_eq!(format_real(f64::NAN), "0.0");
/// assert_eq!(format_real(f64::INFINITY), format_real(MAX_REAL));
/// assert_eq!(format_real(-1e300), format_real(-MAX_REAL));
/// assert_eq!(format_real(MAX_REAL).len(), 41);
/// ```
pub fn format_real(value: f64) -> String {
    let value = if value.is_nan() {
        0.0
    } else {
        value.clamp(-MAX_REAL, MAX_REAL)
    };
    // Rust's `Display` for floats prints the shortest digits that read back as the same value,
    // in positional notation (never with an exponent).
    let shortest = value.to_string();
    let text = match shortest.split_once('.') {
        Some((integer, fraction)) if fraction.len() > 10 => {
            // Round, keeping at most 15 significant digits (DBL_DIG): such a decimal is exactly
            // the shortest form of the `f64` a reader gets back, so writing that value again
            // gives the same text. The shortest form has at most 17 significant digits, so
            // the integer part has at most 6 here and at least 9 fractional digits remain.
            let integer_digits = integer
                .trim_start_matches('-')
                .trim_start_matches('0')
                .len();
            let places = 10usize.min(15usize.saturating_sub(integer_digits));
            format!("{value:.places$}")
        }
        _ => shortest,
    };
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.as_str()),
    };
    let digits = if digits.contains('.') {
        digits.trim_end_matches('0').trim_end_matches('.')
    } else {
        digits
    };
    if digits.bytes().all(|b| b == b'0' || b == b'.') {
        return "0.0".to_owned();
    }
    let mut result = String::with_capacity(digits.len() + 3);
    if negative {
        result.push('-');
    }
    result.push_str(digits);
    if !digits.contains('.') {
        result.push_str(".0");
    }
    result
}

/// The largest magnitude the serializer writes for a real: `f32::MAX` (about `3.403e38`), the
/// limit ISO 32000 gives for reals that implementations must accept (ISO 32000-1 Annex C,
/// Table C.1). Larger values and the infinities are clamped to it (see [`format_real`]).
pub const MAX_REAL: f64 = f32::MAX as f64;

/// Appends a real number formatted by [`format_real`] (non-finite and huge values are mapped as
/// it documents).
pub fn write_real(value: f64, out: &mut Vec<u8>) {
    out.extend_from_slice(format_real(value).as_bytes());
}

/// The value a reader gets back after `value` is written by this serializer: `value` rounded
/// as [`format_real`] rounds it.
///
/// ```
/// use folioxide_syntax::serialize::canonical_real;
///
/// assert_eq!(canonical_real(0.5), 0.5);
/// assert_eq!(canonical_real(1.0 / 3.0), 0.3333333333);
/// assert_eq!(canonical_real(-1e-12), 0.0);
/// ```
pub fn canonical_real(value: f64) -> f64 {
    format_real(value).parse().unwrap_or(0.0)
}

/// Appends a name with its leading `/`, escaping every byte that is not a regular printable
/// ASCII character other than `#` as `#xx` (§7.3.5). The output is always printable ASCII.
///
/// ```
/// use folioxide_syntax::serialize::write_name;
///
/// let mut out = Vec::new();
/// write_name(b"paired()parentheses", &mut out);
/// assert_eq!(out, b"/paired#28#29parentheses");
/// ```
pub fn write_name(name: &[u8], out: &mut Vec<u8>) {
    out.push(b'/');
    for &b in name {
        if (0x21..=0x7E).contains(&b) && b != b'#' && !is_delimiter(b) {
            out.push(b);
        } else {
            out.push(b'#');
            push_hex(b, out);
        }
    }
}

/// Appends a string in the form recorded by [`PdfString::hex`].
pub fn write_string(string: &PdfString, out: &mut Vec<u8>) {
    if string.hex {
        write_hex_string(&string.bytes, out);
    } else {
        write_literal_string(&string.bytes, out);
    }
}

/// Appends a literal string `(...)`, escaping `(`, `)`, `\`, CR and LF (§7.3.4.2). Every other
/// byte is written as is.
pub fn write_literal_string(bytes: &[u8], out: &mut Vec<u8>) {
    out.reserve(bytes.len() + 2);
    out.push(b'(');
    for &b in bytes {
        match b {
            b'(' | b')' | b'\\' => {
                out.push(b'\\');
                out.push(b);
            }
            // A raw CR would read back as LF, so EOL bytes are always escaped.
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\n' => out.extend_from_slice(b"\\n"),
            _ => out.push(b),
        }
    }
    out.push(b')');
}

/// Appends a hexadecimal string `<...>` with upper-case digits (§7.3.4.3).
pub fn write_hex_string(bytes: &[u8], out: &mut Vec<u8>) {
    out.reserve(bytes.len() * 2 + 2);
    out.push(b'<');
    for &b in bytes {
        push_hex(b, out);
    }
    out.push(b'>');
}

fn push_hex(b: u8, out: &mut Vec<u8>) {
    let hi = HEX_UPPER.get(usize::from(b >> 4)).copied().unwrap_or(b'0');
    let lo = HEX_UPPER
        .get(usize::from(b & 0x0F))
        .copied()
        .unwrap_or(b'0');
    out.push(hi);
    out.push(lo);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::{Lexer, TokenKind};
    use crate::parser::{ParseCtx, parse_indirect_at, parse_object};
    use crate::{Stream, Strictness};

    fn to_string(object: &Object) -> String {
        let mut out = Vec::new();
        serialize_object(object, &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn real_formatting_no_exponent() {
        let cases: &[(f64, &str)] = &[
            (0.0, "0.0"),
            (-0.0, "0.0"),
            (1.0, "1.0"),
            (-1.0, "-1.0"),
            (0.5, "0.5"),
            (-0.5, "-0.5"),
            (100.0, "100.0"),
            (612.0, "612.0"),
            (123.456, "123.456"),
            (1234567.8, "1234567.8"),
            (0.1 + 0.2, "0.3"),
            (1.0 / 3.0, "0.3333333333"),
            (-2.0 / 3.0, "-0.6666666667"),
            (std::f64::consts::PI, "3.1415926536"),
            (0.123_456_789_012_345, "0.123456789"),
            (1e-7, "0.0000001"),
            (1e-10, "0.0000000001"),
            (1e-11, "0.0"),
            (-1e-11, "0.0"),
            (4e-11, "0.0"),
            (6e-11, "0.0000000001"),
            (0.000_012_5, "0.0000125"),
            (1e15, "1000000000000000.0"),
            (1e20, "100000000000000000000.0"),
            (1e21, "1000000000000000000000.0"),
            (123_456_789_012_345_680.0, "123456789012345680.0"),
            (9_007_199_254_740_993.0, "9007199254740992.0"),
            (f64::NAN, "0.0"),
            (f64::MIN_POSITIVE, "0.0"),
        ];
        for &(value, expected) in cases {
            assert_eq!(format_real(value), expected, "{value:?}");
        }
        // Magnitudes up to MAX_REAL are written in full; beyond it, and the infinities, are
        // clamped to it (ISO 32000 Annex C), so readers with 32-bit reals do not overflow.
        assert_eq!(format_real(1e38), format!("1{}.0", "0".repeat(38)));
        let max = format_real(MAX_REAL);
        assert_eq!(max, "340282346638528860000000000000000000000.0");
        for huge in [f64::INFINITY, f64::MAX, 1e300, 3.5e38] {
            assert_eq!(format_real(huge), max, "{huge:?}");
            assert_eq!(format_real(-huge), format!("-{max}"), "{huge:?}");
            assert_eq!(canonical_real(huge), MAX_REAL);
        }
        assert_eq!(canonical_real(f64::NAN), 0.0);
        assert_eq!(canonical_real(f64::NEG_INFINITY), -MAX_REAL);
        // The clamped text reads back as the same value.
        let mut lexer = Lexer::new(max.as_bytes(), 0).with_strictness(Strictness::Strict);
        assert_eq!(
            lexer.next_token().unwrap().unwrap().kind,
            TokenKind::Real(MAX_REAL)
        );
        // Through serialize_object too: no value makes the output unreadable.
        let mut out = Vec::new();
        serialize_object(
            &Object::Array(vec![
                Object::Real(f64::NAN),
                Object::Real(f64::INFINITY),
                Object::Real(f64::MIN_POSITIVE),
            ]),
            &mut out,
        );
        assert_eq!(out, format!("[0.0 {max} 0.0]").as_bytes());
    }

    /// Every formatted real is valid PDF syntax that reads back as a real: exactly when the
    /// shortest form has at most 10 fractional digits, and rounded otherwise.
    #[test]
    fn real_formatting_round_trips() {
        let mut state = 0x1234_5678_9ABC_DEF1u64;
        let mut values = vec![
            f64::MAX,
            f64::MIN,
            f64::EPSILON,
            1e308,
            -1e308,
            1e-308,
            0.1,
            72.0,
        ];
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let v = f64::from_bits(state);
            if v.is_finite() {
                values.push(v);
            }
            // Also typical PDF magnitudes.
            values.push((state % 2_000_000) as f64 / 997.0 - 1000.0);
        }
        for v in values {
            let text = format_real(v);
            assert!(!text.contains(['e', 'E']), "{v:?} -> {text}");
            let fraction = text.split_once('.').map(|(_, f)| f.len()).unwrap();
            assert!((1..=10).contains(&fraction), "{v:?} -> {text}");
            let mut lexer = Lexer::new(text.as_bytes(), 0).with_strictness(Strictness::Strict);
            let back = match lexer.next_token().unwrap().unwrap().kind {
                TokenKind::Real(r) => r,
                other => panic!("{v:?} -> {text} -> {other:?}"),
            };
            assert!(lexer.next_token().unwrap().is_none());
            assert_eq!(back, canonical_real(v));
            // Idempotent: writing the value read back gives the same text.
            assert_eq!(format_real(back), text, "{v:?}");
            // Beyond MAX_REAL the value is clamped; below it, kept or rounded.
            let v = v.clamp(-MAX_REAL, MAX_REAL);
            let shortest = v.to_string();
            if shortest.split_once('.').is_none_or(|(_, f)| f.len() <= 10) {
                assert_eq!(back, v, "{v:?} -> {text}");
            } else {
                assert!(
                    (back - v).abs() <= 5.1e-11 * v.abs().max(1.0),
                    "{v:?} -> {text}"
                );
            }
            assert!(text.len() <= 42, "{v:?} -> {text}");
        }
    }

    #[test]
    fn integers() {
        for (value, expected) in [
            (0i64, "0"),
            (7, "7"),
            (-7, "-7"),
            (1_000_000, "1000000"),
            (i64::MAX, "9223372036854775807"),
            (i64::MIN, "-9223372036854775808"),
        ] {
            let mut out = Vec::new();
            write_int(value, &mut out);
            assert_eq!(out, expected.as_bytes());
        }
    }

    #[test]
    fn name_escape_roundtrip() {
        // Every byte value, alone and inside a name.
        for b in 0..=255u8 {
            for name in [vec![b], vec![b'A', b, b'z']] {
                let mut out = Vec::new();
                write_name(&name, &mut out);
                assert!(
                    out.iter().all(|c| (0x21..=0x7E).contains(c)),
                    "{:?}",
                    out.escape_ascii()
                );
                let mut lexer = Lexer::new(&out, 0);
                let tok = lexer.next_token().unwrap().unwrap();
                assert_eq!(
                    tok.kind,
                    TokenKind::Name(name.clone().into()),
                    "byte {b:#04x}"
                );
                assert_eq!(tok.end, out.len());
            }
        }
        // §7.3.5 Table 4 examples, written back canonically.
        let cases: &[(&[u8], &[u8])] = &[
            (b"Name1", b"/Name1"),
            (
                b"A;Name_With-Various***Characters?",
                b"/A;Name_With-Various***Characters?",
            ),
            (b"1.2", b"/1.2"),
            (b"$$", b"/$$"),
            (b"@pattern", b"/@pattern"),
            (b".notdef", b"/.notdef"),
            (b"Lime Green", b"/Lime#20Green"),
            (b"paired()parentheses", b"/paired#28#29parentheses"),
            (b"The_Key_of_F#_Minor", b"/The_Key_of_F#23_Minor"),
            (b"", b"/"),
            (b"a/b%c[d]e<f>g{h}", b"/a#2Fb#25c#5Bd#5De#3Cf#3Eg#7Bh#7D"),
            (b"\x00\t\n\r \x7f\x80\xff", b"/#00#09#0A#0D#20#7F#80#FF"),
        ];
        for &(name, expected) in cases {
            let mut out = Vec::new();
            write_name(name, &mut out);
            assert_eq!(out, expected, "{:?}", name.escape_ascii());
            assert_eq!(Name::from(name).to_string().as_bytes(), expected);
        }
        // A random sample of longer names.
        let mut state = 7u64;
        for _ in 0..2000 {
            let name: Vec<u8> = (0..(state % 17))
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1);
                    (state >> 56) as u8
                })
                .collect();
            state = state.wrapping_add(3);
            let object = Object::Name(Name::from(name));
            let text = to_string(&object);
            let (back, end) = parse_object(text.as_bytes(), 0, &ParseCtx::default()).unwrap();
            assert_eq!(back, object);
            assert_eq!(end, text.len());
        }
    }

    #[test]
    fn strings() {
        let cases: &[(PdfString, &[u8])] = &[
            (PdfString::new_literal("plain"), b"(plain)"),
            (PdfString::new_literal(""), b"()"),
            (PdfString::new_literal("a(b)c"), b"(a\\(b\\)c)"),
            (PdfString::new_literal(")("), b"(\\)\\()"),
            (PdfString::new_literal("back\\slash"), b"(back\\\\slash)"),
            (
                PdfString::new_literal("cr\rlf\ncrlf\r\n"),
                b"(cr\\rlf\\ncrlf\\r\\n)",
            ),
            (
                PdfString::new_literal(b"\x00\t\x08\x0c\xff%/".to_vec()),
                b"(\x00\t\x08\x0c\xff%/)",
            ),
            (PdfString::new_hex(vec![0x00, 0xAB, 0x7F]), b"<00AB7F>"),
            (PdfString::new_hex(vec![]), b"<>"),
        ];
        for (string, expected) in cases {
            let mut out = Vec::new();
            write_string(string, &mut out);
            assert_eq!(out, *expected, "{string:?}");
            let (back, _) = parse_object(&out, 0, &ParseCtx::default()).unwrap();
            assert_eq!(back, Object::String(string.clone()));
        }
        // Every byte survives a literal round trip.
        let all: Vec<u8> = (0..=255).collect();
        let object = Object::literal_string(all);
        let text = {
            let mut out = Vec::new();
            serialize_object(&object, &mut out);
            out
        };
        assert_eq!(
            parse_object(&text, 0, &ParseCtx::default()).unwrap().0,
            object
        );
    }

    #[test]
    fn objects() {
        let mut dict = Dict::new();
        dict.insert("A", Object::Null);
        dict.insert("B", true);
        dict.insert(
            "C",
            vec![Object::Int(1), Object::Real(2.5), Object::name("N")],
        );
        dict.insert("D", ObjectId::new(3, 1));
        dict.insert("E", Dict::new());
        dict.insert("F", Object::Array(vec![]));
        dict.insert("", Object::Bool(false));
        let cases: Vec<(Object, &str)> = vec![
            (Object::Null, "null"),
            (Object::Bool(true), "true"),
            (Object::Bool(false), "false"),
            (Object::Int(-3), "-3"),
            (Object::Real(-3.0), "-3.0"),
            (Object::Ref(ObjectId::new(10, 2)), "10 2 R"),
            (Object::Array(vec![]), "[]"),
            (Object::Dict(Dict::new()), "<<>>"),
            (
                Object::Dict(dict),
                "<</A null /B true /C [1 2.5 /N] /D 3 1 R /E <<>> /F [] / false>>",
            ),
            (
                Object::Array(vec![
                    Object::Array(vec![Object::Array(vec![])]),
                    Object::literal_string("s"),
                    Object::hex_string("h"),
                ]),
                "[[[]] (s) <68>]",
            ),
        ];
        for (object, expected) in cases {
            let text = to_string(&object);
            assert_eq!(text, expected);
            let (back, end) = parse_object(text.as_bytes(), 0, &ParseCtx::default()).unwrap();
            assert_eq!(back, object);
            assert_eq!(end, text.len());
        }
        // A stream as a direct object: only its dictionary.
        let mut d = Dict::new();
        d.insert("Length", 3);
        let stream: Object = Stream::new(d, StreamData::Decoded(b"abc".to_vec())).into();
        assert_eq!(to_string(&stream), "<</Length 3>>");
    }

    #[test]
    fn indirect_objects() {
        let mut out = Vec::new();
        serialize_indirect(ObjectId::new(12, 0), &Object::Int(5), None, &mut out).unwrap();
        assert_eq!(out, b"12 0 obj\n5\nendobj\n");

        // A stream with explicit encoded bytes: /Length is replaced in place.
        let mut dict = Dict::new();
        dict.insert("Length", 999);
        dict.insert("Filter", Object::name("FlateDecode"));
        let stream: Object = Stream::new(dict.clone(), StreamData::Source(0..10)).into();
        let mut out = Vec::new();
        serialize_indirect(ObjectId::new(3, 1), &stream, Some(b"xyz"), &mut out).unwrap();
        assert_eq!(
            out,
            b"3 1 obj\n<</Length 3 /Filter /FlateDecode>>\nstream\nxyz\nendstream\nendobj\n"
        );
        // Source data without bytes is an error.
        let err =
            serialize_indirect(ObjectId::new(3, 1), &stream, None, &mut Vec::new()).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidArgument);
        // Bytes for a non-stream are an error.
        let err = serialize_indirect(
            ObjectId::new(3, 1),
            &Object::Null,
            Some(b""),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidArgument);

        // Encoded data: written as is, /Length appended.
        let mut dict = Dict::new();
        dict.insert("Filter", Object::name("ASCIIHexDecode"));
        let stream: Object = Stream::new(dict.clone(), StreamData::Encoded(b"41>".to_vec())).into();
        let mut out = Vec::new();
        serialize_indirect(ObjectId::new(1, 0), &stream, None, &mut out).unwrap();
        assert_eq!(
            out,
            b"1 0 obj\n<</Filter /ASCIIHexDecode /Length 3>>\nstream\n41>\nendstream\nendobj\n"
        );

        // Decoded data: written unfiltered.
        dict.insert("DecodeParms", Dict::new());
        dict.insert("Type", Object::name("XObject"));
        let stream: Object = Stream::new(dict, StreamData::Decoded(b"A".to_vec())).into();
        let mut out = Vec::new();
        serialize_indirect(ObjectId::new(1, 0), &stream, None, &mut out).unwrap();
        assert_eq!(
            out,
            b"1 0 obj\n<</Type /XObject /Length 1>>\nstream\nA\nendstream\nendobj\n"
        );
    }

    #[test]
    fn indirect_objects_parse_back() {
        let mut dict = Dict::new();
        dict.insert("Type", Object::name("XObject"));
        dict.insert("Length", 0);
        let data = b"\r\nendstream inside\r\n".to_vec();
        let stream: Object = Stream::new(dict, StreamData::Encoded(data.clone())).into();
        let mut out = b"%PDF-1.7\n".to_vec();
        let offset = out.len();
        serialize_indirect(ObjectId::new(9, 4), &stream, None, &mut out).unwrap();
        let parsed = parse_indirect_at(&out, offset, &ParseCtx::default(), &|_| None).unwrap();
        assert_eq!(parsed.id, ObjectId::new(9, 4));
        assert_eq!(parsed.end, out.len() - 1);
        let range = parsed.stream_data_range.unwrap();
        assert_eq!(&out[range.start as usize..range.end as usize], data);
        let parsed_stream = parsed.object.as_stream().unwrap();
        assert_eq!(
            parsed_stream.dict.get_int(b"Length"),
            Some(data.len() as i64)
        );
        assert!(parsed_stream.dict.is_type(b"XObject"));
    }

    #[test]
    fn deep_objects_serialize_without_recursion() {
        let handle = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let mut object = Object::Int(1);
                for _ in 0..100_000 {
                    object = Object::Array(vec![object]);
                }
                let mut out = Vec::new();
                serialize_object(&object, &mut out);
                // Dismantle iteratively before asserting: the derived Drop recurses once per
                // level, which would overflow this small stack.
                let mut current = object;
                while let Object::Array(mut items) = current {
                    current = items.pop().unwrap_or(Object::Null);
                }
                out
            })
            .unwrap();
        let out = handle.join().unwrap();
        assert_eq!(out.len(), 200_001);
        assert!(out[..100_000].iter().all(|&b| b == b'['));
        assert_eq!(out[100_000], b'1');
        assert!(out[100_001..].iter().all(|&b| b == b']'));
    }

    /// Replaces every real by the value a reader gets back after serialization.
    fn canonicalize(object: &Object) -> Object {
        match object {
            Object::Real(r) => Object::Real(canonical_real(*r)),
            Object::Array(items) => Object::Array(items.iter().map(canonicalize).collect()),
            Object::Dict(dict) => Object::Dict(
                dict.iter()
                    .map(|(k, v)| (k.clone(), canonicalize(v)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }

        fn bytes(&mut self, max: u64) -> Vec<u8> {
            (0..self.below(max)).map(|_| self.next() as u8).collect()
        }

        fn object(&mut self, depth: u32) -> Object {
            let kinds = if depth == 0 { 7 } else { 9 };
            match self.below(kinds) {
                0 => Object::Null,
                1 => Object::Bool(self.next().is_multiple_of(2)),
                2 => Object::Int(self.next() as i64 >> self.below(64)),
                3 => {
                    let v = f64::from_bits(self.next());
                    Object::Real(if v.is_finite() {
                        v
                    } else {
                        self.below(1_000_000) as f64 / 7.0
                    })
                }
                4 => Object::String(PdfString {
                    bytes: self.bytes(20),
                    hex: self.next().is_multiple_of(2),
                }),
                5 => Object::Name(Name::from(self.bytes(12))),
                6 => Object::Ref(ObjectId::new(self.next() as u32, self.next() as u16)),
                7 => Object::Array((0..self.below(5)).map(|_| self.object(depth - 1)).collect()),
                _ => Object::Dict(
                    (0..self.below(5))
                        .map(|_| (Name::from(self.bytes(6)), self.object(depth - 1)))
                        .collect(),
                ),
            }
        }
    }

    /// Deterministic stand-in for the WP1.4 property test: random object trees serialize and
    /// parse back equal (after real rounding).
    #[test]
    fn random_objects_round_trip() {
        let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
        for _ in 0..5000 {
            let object = rng.object(4);
            let mut out = Vec::new();
            serialize_object(&object, &mut out);
            let (back, end) = parse_object(&out, 0, &ParseCtx::default())
                .unwrap_or_else(|e| panic!("{object:?} -> {:?}: {e}", out.escape_ascii()));
            assert_eq!(end, out.len());
            assert_eq!(back, canonicalize(&object), "{:?}", out.escape_ascii());
            // Serialization is a fixed point after one round.
            let mut again = Vec::new();
            serialize_object(&back, &mut again);
            assert_eq!(again, out);
        }
    }
}

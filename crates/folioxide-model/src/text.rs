//! Text strings (ISO 32000-2 §7.9.2.2) and PDFDocEncoding (Annex D.3).
//!
//! A *text string* is a PDF string that holds human-readable text, such as the entries of the
//! Info dictionary (§14.3.3) or an outline title. Its bytes are one of three encodings:
//!
//! - **UTF-16BE** when they start with the byte order mark `FE FF` (§7.9.2.2.1);
//! - **UTF-8** when they start with `EF BB BF` (PDF 2.0);
//! - **PDFDocEncoding** otherwise: a single-byte encoding that is ISO Latin-1 with 40 code points
//!   replaced (typographic quotes, dashes, ligatures, the euro sign, spacing accents) and a few
//!   left undefined (Annex D.3, Table D.2).
//!
//! [`decode_text_string`] reads all three (plus UTF-16LE with its `FF FE` mark, which the
//! standard does not allow but some writers produce), and [`encode_text_string`] writes
//! PDFDocEncoding when it can represent the text and UTF-16BE otherwise.
//!
//! ```
//! use folioxide_model::text::{decode_text_string, encode_text_string};
//!
//! // PDFDocEncoding: 0x93 is the "fi" ligature, 0xA0 the euro sign.
//! assert_eq!(decode_text_string(b"\x93ve \xA0"), "\u{FB01}ve \u{20AC}");
//! assert_eq!(encode_text_string("\u{FB01}ve \u{20AC}"), b"\x93ve \xA0");
//!
//! // Text outside PDFDocEncoding becomes UTF-16BE with a byte order mark.
//! assert_eq!(encode_text_string("\u{3042}"), b"\xFE\xFF\x30\x42");
//! assert_eq!(decode_text_string(b"\xFE\xFF\x30\x42"), "\u{3042}");
//! ```

/// The byte order mark of a UTF-16BE text string (§7.9.2.2.1).
pub const UTF16BE_BOM: [u8; 2] = [0xFE, 0xFF];

/// The byte order mark of a UTF-8 text string (PDF 2.0, §7.9.2.2.1).
pub const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// The byte order mark of a UTF-16LE string: not allowed by ISO 32000, but written by some
/// producers; [`decode_text_string`] accepts it, as pdf.js and qpdf do.
const UTF16LE_BOM: [u8; 2] = [0xFF, 0xFE];

/// U+001B ESCAPE, which delimits a language marker inside a Unicode text string (§7.9.2.2.1).
const ESC: u16 = 0x1B;

/// The PDFDocEncoding codes whose character differs from ISO Latin-1 (Annex D.3, Table D.2),
/// with their Unicode code points: the eight spacing accents at 0x18–0x1F, the typographic
/// characters at 0x80–0x9E, and the euro sign at 0xA0. Checked against qpdf 12.4 and pypdf 6.
const SPECIALS: [(u8, char); 40] = [
    (0x18, '\u{02D8}'), // breve
    (0x19, '\u{02C7}'), // caron
    (0x1A, '\u{02C6}'), // circumflex (modifier letter circumflex accent)
    (0x1B, '\u{02D9}'), // dotaccent (dot above)
    (0x1C, '\u{02DD}'), // hungarumlaut (double acute accent)
    (0x1D, '\u{02DB}'), // ogonek
    (0x1E, '\u{02DA}'), // ring (ring above)
    (0x1F, '\u{02DC}'), // tilde (small tilde)
    (0x80, '\u{2022}'), // bullet
    (0x81, '\u{2020}'), // dagger
    (0x82, '\u{2021}'), // daggerdbl
    (0x83, '\u{2026}'), // ellipsis
    (0x84, '\u{2014}'), // emdash
    (0x85, '\u{2013}'), // endash
    (0x86, '\u{0192}'), // florin
    (0x87, '\u{2044}'), // fraction (fraction slash)
    (0x88, '\u{2039}'), // guilsinglleft
    (0x89, '\u{203A}'), // guilsinglright
    (0x8A, '\u{2212}'), // minus
    (0x8B, '\u{2030}'), // perthousand
    (0x8C, '\u{201E}'), // quotedblbase
    (0x8D, '\u{201C}'), // quotedblleft
    (0x8E, '\u{201D}'), // quotedblright
    (0x8F, '\u{2018}'), // quoteleft
    (0x90, '\u{2019}'), // quoteright
    (0x91, '\u{201A}'), // quotesinglbase
    (0x92, '\u{2122}'), // trademark
    (0x93, '\u{FB01}'), // fi
    (0x94, '\u{FB02}'), // fl
    (0x95, '\u{0141}'), // Lslash
    (0x96, '\u{0152}'), // OE
    (0x97, '\u{0160}'), // Scaron
    (0x98, '\u{0178}'), // Ydieresis
    (0x99, '\u{017D}'), // Zcaron
    (0x9A, '\u{0131}'), // dotlessi
    (0x9B, '\u{0142}'), // lslash
    (0x9C, '\u{0153}'), // oe
    (0x9D, '\u{0161}'), // scaron
    (0x9E, '\u{017E}'), // zcaron
    (0xA0, '\u{20AC}'), // Euro
];

/// The character that PDFDocEncoding assigns to `byte` (Annex D.3, Table D.2), or `None` when
/// the code is undefined: 0x00–0x08, 0x0B, 0x0C, 0x0E–0x17, 0x7F, 0x9F and 0xAD.
///
/// The defined codes are tab, line feed and carriage return, printable ASCII, ISO Latin-1 from
/// 0xA1 (soft hyphen 0xAD excepted), and the 40 characters that replace Latin-1 control codes
/// and the non-breaking space (0xA0 is the euro sign).
///
/// ```
/// use folioxide_model::text::pdf_doc_char;
///
/// assert_eq!(pdf_doc_char(b'A'), Some('A'));
/// assert_eq!(pdf_doc_char(0x18), Some('\u{02D8}')); // breve
/// assert_eq!(pdf_doc_char(0x8D), Some('\u{201C}')); // left double quotation mark
/// assert_eq!(pdf_doc_char(0xA0), Some('\u{20AC}')); // euro sign
/// assert_eq!(pdf_doc_char(0xAD), None);
/// ```
pub fn pdf_doc_char(byte: u8) -> Option<char> {
    match byte {
        0x09 | 0x0A | 0x0D | 0x20..=0x7E | 0xA1..=0xAC | 0xAE..=0xFF => Some(char::from(byte)),
        _ => SPECIALS.iter().find(|(b, _)| *b == byte).map(|(_, c)| *c),
    }
}

/// The PDFDocEncoding code of `c`, or `None` when PDFDocEncoding cannot represent it.
///
/// Only defined codes are produced (see [`pdf_doc_char`]); the inverse of that function.
pub fn pdf_doc_byte(c: char) -> Option<u8> {
    match c {
        '\t' | '\n' | '\r' | ' '..='~' | '\u{A1}'..='\u{AC}' | '\u{AE}'..='\u{FF}' => {
            u8::try_from(u32::from(c)).ok()
        }
        _ => SPECIALS.iter().find(|(_, ch)| *ch == c).map(|(b, _)| *b),
    }
}

/// Decodes PDFDocEncoding bytes (Annex D.3).
///
/// Undefined codes are decoded the way qpdf, pdf.js and PDFBox decode them: the C0 control
/// codes 0x00–0x17 as the control characters U+0000–U+0017, and 0x7F, 0x9F and 0xAD as
/// U+FFFD REPLACEMENT CHARACTER. Every byte yields exactly one character.
///
/// ```
/// use folioxide_model::text::decode_pdf_doc;
///
/// assert_eq!(decode_pdf_doc(b"caf\xE9 \x84 \x7F"), "caf\u{E9} \u{2014} \u{FFFD}");
/// ```
pub fn decode_pdf_doc(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match pdf_doc_char(b) {
            Some(c) => c,
            None if b < 0x18 => char::from(b),
            None => char::REPLACEMENT_CHARACTER,
        })
        .collect()
}

/// Encodes `text` in PDFDocEncoding, or returns `None` when a character has no code.
///
/// Only defined codes are produced, so control characters other than tab, line feed and
/// carriage return, U+00AD SOFT HYPHEN and U+FFFD make the result `None`.
pub fn encode_pdf_doc(text: &str) -> Option<Vec<u8>> {
    text.chars().map(pdf_doc_byte).collect()
}

/// Decodes a text string (§7.9.2.2), whatever its encoding.
///
/// - `FE FF …`: UTF-16BE. Unpaired surrogates and a final odd byte become U+FFFD.
/// - `EF BB BF …`: UTF-8 (PDF 2.0). Invalid sequences become U+FFFD.
/// - `FF FE …`: UTF-16LE. Not allowed by the standard; accepted as pdf.js and qpdf accept it.
/// - anything else: PDFDocEncoding ([`decode_pdf_doc`]).
///
/// Language markers in Unicode strings (§7.9.2.2.1: U+001B, a two-letter ISO 639 language code,
/// an optional two-letter ISO 3166 country code, U+001B) are removed. Decoding never fails; it
/// is lossy for malformed input.
///
/// ```
/// use folioxide_model::text::decode_text_string;
///
/// assert_eq!(decode_text_string(b"Hello"), "Hello");
/// assert_eq!(decode_text_string(b"\xFE\xFF\x00H\x00i"), "Hi");
/// assert_eq!(decode_text_string(b"\xEF\xBB\xBFgr\xC3\xBC\xC3\x9F"), "gr\u{FC}\u{DF}");
/// // A language marker ("en", country "US") is not part of the text.
/// assert_eq!(decode_text_string(b"\xFE\xFF\x00\x1Benus\x00\x1B\x00H\x00i"), "Hi");
/// ```
pub fn decode_text_string(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&UTF16BE_BOM) {
        decode_utf16(rest, u16::from_be_bytes)
    } else if let Some(rest) = bytes.strip_prefix(&UTF8_BOM) {
        strip_utf8_language_markers(&String::from_utf8_lossy(rest))
    } else if let Some(rest) = bytes.strip_prefix(&UTF16LE_BOM) {
        decode_utf16(rest, u16::from_le_bytes)
    } else {
        decode_pdf_doc(bytes)
    }
}

/// Encodes `text` as a text string (§7.9.2.2): PDFDocEncoding when every character has a code
/// there, otherwise UTF-16BE with the `FE FF` byte order mark (surrogate pairs for characters
/// outside the Basic Multilingual Plane).
///
/// PDFDocEncoding is also avoided when its bytes would start with a byte order mark (`þÿ`,
/// `ï»¿` or `ÿþ` at the start of the text), which a reader would take for a Unicode string.
/// The result always decodes back to `text` with [`decode_text_string`].
///
/// ```
/// use folioxide_model::text::encode_text_string;
///
/// assert_eq!(encode_text_string("Caf\u{E9}"), b"Caf\xE9");
/// assert_eq!(encode_text_string("\u{1F600}"), b"\xFE\xFF\xD8\x3D\xDE\x00");
/// // "þÿ" would read as a UTF-16 byte order mark.
/// assert_eq!(encode_text_string("\u{FE}\u{FF}"), b"\xFE\xFF\x00\xFE\x00\xFF");
/// ```
pub fn encode_text_string(text: &str) -> Vec<u8> {
    if let Some(bytes) = encode_pdf_doc(text) {
        let looks_unicode = bytes.starts_with(&UTF16BE_BOM)
            || bytes.starts_with(&UTF8_BOM)
            || bytes.starts_with(&UTF16LE_BOM);
        if !looks_unicode {
            return bytes;
        }
    }
    encode_utf16be(text)
}

/// `text` as UTF-16BE with the `FE FF` byte order mark.
pub fn encode_utf16be(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 2 * text.len());
    out.extend_from_slice(&UTF16BE_BOM);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out
}

/// Decodes UTF-16 code units built from byte pairs by `unit`, dropping language markers.
fn decode_utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> String {
    let pairs = bytes.chunks_exact(2);
    let odd = !pairs.remainder().is_empty();
    let units: Vec<u16> = pairs
        .filter_map(|p| <[u8; 2]>::try_from(p).ok())
        .map(unit)
        .collect();
    let units = strip_utf16_language_markers(&units);
    let mut out: String = char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    if odd {
        out.push(char::REPLACEMENT_CHARACTER);
    }
    out
}

/// Whether a UTF-16 code unit holds two ASCII letters, as the bytes of a language or country
/// code inside a language marker do (§7.9.2.2.1: the codes are ASCII bytes, not code units).
fn is_letter_pair(unit: u16) -> bool {
    unit.to_be_bytes().iter().all(u8::is_ascii_alphabetic)
}

/// Removes language markers from UTF-16 code units: ESC, one unit holding the two-letter
/// language code, optionally one unit holding the two-letter country code, ESC. An ESC that does
/// not start such a marker is kept.
fn strip_utf16_language_markers(units: &[u16]) -> Vec<u16> {
    let mut out = Vec::with_capacity(units.len());
    let mut i = 0;
    while let Some(&u) = units.get(i) {
        if u == ESC {
            let marker_len = [3usize, 4].into_iter().find(|&len| {
                units.get(i + len - 1) == Some(&ESC)
                    && units
                        .get(i + 1..i + len - 1)
                        .is_some_and(|codes| codes.iter().all(|&c| is_letter_pair(c)))
            });
            if let Some(len) = marker_len {
                i += len;
                continue;
            }
        }
        out.push(u);
        i += 1;
    }
    out
}

/// Removes language markers from decoded UTF-8 text: ESC, two or four ASCII letters, ESC.
fn strip_utf8_language_markers(text: &str) -> String {
    if !text.contains('\u{1B}') {
        return text.to_owned();
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        if c == '\u{1B}' {
            let marker_len = [4usize, 6].into_iter().find(|&len| {
                chars.get(i + len - 1) == Some(&'\u{1B}')
                    && chars
                        .get(i + 1..i + len - 1)
                        .is_some_and(|codes| codes.iter().all(char::is_ascii_alphabetic))
            });
            if let Some(len) = marker_len {
                i += len;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every PDFDocEncoding code that differs from ISO Latin-1, as Annex D.3 lists it (and as
    /// qpdf 12.4 decodes it: `str(pikepdf.String(bytes([code])))`).
    const ANNEX_D: &[(u8, u32)] = &[
        (0x18, 0x02D8),
        (0x19, 0x02C7),
        (0x1A, 0x02C6),
        (0x1B, 0x02D9),
        (0x1C, 0x02DD),
        (0x1D, 0x02DB),
        (0x1E, 0x02DA),
        (0x1F, 0x02DC),
        (0x80, 0x2022),
        (0x81, 0x2020),
        (0x82, 0x2021),
        (0x83, 0x2026),
        (0x84, 0x2014),
        (0x85, 0x2013),
        (0x86, 0x0192),
        (0x87, 0x2044),
        (0x88, 0x2039),
        (0x89, 0x203A),
        (0x8A, 0x2212),
        (0x8B, 0x2030),
        (0x8C, 0x201E),
        (0x8D, 0x201C),
        (0x8E, 0x201D),
        (0x8F, 0x2018),
        (0x90, 0x2019),
        (0x91, 0x201A),
        (0x92, 0x2122),
        (0x93, 0xFB01),
        (0x94, 0xFB02),
        (0x95, 0x0141),
        (0x96, 0x0152),
        (0x97, 0x0160),
        (0x98, 0x0178),
        (0x99, 0x017D),
        (0x9A, 0x0131),
        (0x9B, 0x0142),
        (0x9C, 0x0153),
        (0x9D, 0x0161),
        (0x9E, 0x017E),
        (0xA0, 0x20AC),
    ];

    const UNDEFINED: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x0F, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x7F, 0x9F, 0xAD,
    ];

    #[test]
    fn table_matches_annex_d() {
        for code in 0..=255u8 {
            let expected = if let Some((_, cp)) = ANNEX_D.iter().find(|(b, _)| *b == code) {
                char::from_u32(*cp)
            } else if UNDEFINED.contains(&code) {
                None
            } else {
                Some(char::from(code))
            };
            assert_eq!(pdf_doc_char(code), expected, "code {code:#04X}");
        }
        assert_eq!(SPECIALS.len(), ANNEX_D.len());
        // 256 codes, 24 undefined.
        assert_eq!((0..=255u8).filter_map(pdf_doc_char).count(), 232);
    }

    #[test]
    fn encoding_is_the_inverse_of_the_table() {
        for code in 0..=255u8 {
            if let Some(c) = pdf_doc_char(code) {
                assert_eq!(pdf_doc_byte(c), Some(code), "{c:?}");
            }
        }
        // Every char with a code maps back to one byte: no two codes share a character.
        let mut seen = std::collections::HashSet::new();
        for c in (0..=255u8).filter_map(pdf_doc_char) {
            assert!(seen.insert(c), "{c:?} twice");
        }
        for c in [
            '\u{0}', '\u{1}', '\u{17}', '\u{7F}', '\u{80}', '\u{9F}', '\u{A0}', '\u{AD}',
        ] {
            assert_eq!(pdf_doc_byte(c), None, "{c:?}");
        }
        assert_eq!(pdf_doc_byte('\u{FFFD}'), None);
        assert_eq!(pdf_doc_byte('\u{3042}'), None);
    }

    #[test]
    fn spacing_accents_0x18_to_0x1f() {
        let bytes: Vec<u8> = (0x18..=0x1F).collect();
        let text = decode_pdf_doc(&bytes);
        assert_eq!(
            text,
            "\u{02D8}\u{02C7}\u{02C6}\u{02D9}\u{02DD}\u{02DB}\u{02DA}\u{02DC}"
        );
        assert_eq!(encode_text_string(&text), bytes);
        // The neighbours are undefined control codes, passed through as qpdf does.
        assert_eq!(decode_pdf_doc(&[0x17, 0x20]), "\u{17} ");
    }

    #[test]
    fn range_0x7f_to_0x9f() {
        let bytes: Vec<u8> = (0x7F..=0x9F).collect();
        let text = decode_pdf_doc(&bytes);
        let chars: Vec<char> = text.chars().collect();
        assert_eq!(chars.len(), bytes.len());
        assert_eq!(chars[0], char::REPLACEMENT_CHARACTER, "0x7F is undefined");
        assert_eq!(chars[1], '\u{2022}', "0x80 bullet");
        assert_eq!(chars[0x8A - 0x7F], '\u{2212}', "0x8A minus");
        assert_eq!(chars[0x9E - 0x7F], '\u{017E}', "0x9E zcaron");
        assert_eq!(
            chars[0x9F - 0x7F],
            char::REPLACEMENT_CHARACTER,
            "0x9F is undefined"
        );
        // The defined ones round-trip through PDFDocEncoding.
        let defined: String = chars[1..chars.len() - 1].iter().collect();
        assert_eq!(encode_text_string(&defined), &bytes[1..bytes.len() - 1]);
        // U+FFFD has no PDFDocEncoding code (qpdf writes 0x9F for it, which reads back as
        // U+FFFD only by accident): it needs UTF-16.
        assert_eq!(encode_text_string("\u{FFFD}"), b"\xFE\xFF\xFF\xFD");
    }

    #[test]
    fn soft_hyphen_0xad_and_euro_0xa0() {
        assert_eq!(decode_pdf_doc(b"\xAC\xAD\xAE"), "\u{AC}\u{FFFD}\u{AE}");
        assert_eq!(decode_pdf_doc(b"\xA0"), "\u{20AC}");
        // U+00A0 NO-BREAK SPACE and U+00AD SOFT HYPHEN are not in PDFDocEncoding.
        assert_eq!(encode_text_string("a\u{A0}"), b"\xFE\xFF\x00a\x00\xA0");
        assert_eq!(encode_text_string("a\u{AD}"), b"\xFE\xFF\x00a\x00\xAD");
        assert_eq!(encode_text_string("\u{20AC}5"), b"\xA05");
    }

    #[test]
    fn every_defined_code_round_trips() {
        let bytes: Vec<u8> = (0..=255u8).filter(|&b| pdf_doc_char(b).is_some()).collect();
        let text = decode_text_string(&bytes);
        assert_eq!(encode_text_string(&text), bytes);
        assert_eq!(decode_text_string(&encode_text_string(&text)), text);
    }

    #[test]
    fn utf16_decoding_is_lossy_not_failing() {
        // Unpaired high surrogate, then 'A', then an odd trailing byte.
        assert_eq!(
            decode_text_string(b"\xFE\xFF\xD8\x00\x00A\x00"),
            "\u{FFFD}A\u{FFFD}"
        );
        // A surrogate pair.
        assert_eq!(decode_text_string(b"\xFE\xFF\xD8\x3D\xDE\x00"), "\u{1F600}");
        // Only the byte order mark.
        assert_eq!(decode_text_string(b"\xFE\xFF"), "");
        // UTF-16LE.
        assert_eq!(decode_text_string(b"\xFF\xFEH\x00i\x00"), "Hi");
    }

    #[test]
    fn language_markers() {
        // ESC "ja" ESC in UTF-16BE: the code is one unit of two ASCII bytes.
        assert_eq!(
            decode_text_string(b"\xFE\xFF\x00\x1Bja\x00\x1B\x30\x42"),
            "\u{3042}"
        );
        // A lone ESC is kept.
        assert_eq!(decode_text_string(b"\xFE\xFF\x00\x1B\x00A"), "\u{1B}A");
        // UTF-8: ESC "en" "US" ESC.
        assert_eq!(decode_text_string(b"\xEF\xBB\xBF\x1BenUS\x1Bhi"), "hi");
        assert_eq!(
            decode_text_string(b"\xEF\xBB\xBF\x1Be1\x1Bhi"),
            "\u{1B}e1\u{1B}hi"
        );
        // PDFDocEncoding 0x1B is DOT ABOVE, not an escape.
        assert_eq!(decode_text_string(b"\x1Ben\x1B"), "\u{02D9}en\u{02D9}");
    }

    #[test]
    fn invalid_utf8_is_replaced() {
        assert_eq!(decode_text_string(b"\xEF\xBB\xBFa\xFFb"), "a\u{FFFD}b");
    }

    #[test]
    fn encoding_avoids_byte_order_marks() {
        for text in ["\u{FE}\u{FF}x", "\u{EF}\u{BB}\u{BF}x", "\u{FF}\u{FE}x"] {
            let encoded = encode_text_string(text);
            assert!(encoded.starts_with(&UTF16BE_BOM), "{text:?}");
            assert_eq!(decode_text_string(&encoded), text);
        }
        // Not at the start: PDFDocEncoding is fine.
        assert_eq!(encode_text_string("x\u{FE}\u{FF}"), b"x\xFE\xFF");
        assert_eq!(encode_text_string(""), b"");
    }

    #[test]
    fn control_characters_need_utf16() {
        assert_eq!(encode_text_string("a\tb\r\n"), b"a\tb\r\n");
        assert_eq!(encode_text_string("\u{1}"), b"\xFE\xFF\x00\x01");
        assert_eq!(decode_text_string(b"\x01"), "\u{1}");
    }
}

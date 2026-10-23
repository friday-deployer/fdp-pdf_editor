//! WinAnsiEncoding (ISO 32000-2 Annex D.2), the single-byte encoding the standard-14 fonts of
//! this crate are written with.
//!
//! WinAnsiEncoding is Windows code page 1252 restricted to the codes that name a glyph:
//!
//! - 0x20–0x7E are ASCII. 0x27 is `quotesingle` and 0x60 is `grave` (Annex D.2 note 3 on
//!   StandardEncoding, where they are `quoteright` and `quoteleft`).
//! - 0x80–0x9F hold the cp1252 punctuation and letters (`Euro` at 0x80, `ellipsis` at 0x85,
//!   `bullet` at 0x95, …). The five codes cp1252 leaves undefined, 0x81, 0x8D, 0x8F, 0x90 and
//!   0x9D, are unused, like 0x7F and the control codes below 0x20.
//! - 0xA0–0xFF are ISO 8859-1. 0xA0 is the glyph `space` and 0xAD the glyph `hyphen` (notes 4
//!   and 5); [`win_ansi_encode`] maps U+00A0 NO-BREAK SPACE and U+00AD SOFT HYPHEN there.
//!
//! Annex D.2 note 6 says the unused codes above 0x20 display as a bullet. The encoder never
//! produces them, and [`win_ansi_decode`] returns `None` for them.
//!
//! ```
//! use folioxide_content::encoding::{win_ansi_decode, win_ansi_encode};
//!
//! let text = win_ansi_encode("Ünïcödé “quotes” – €5 … ✓");
//! assert_eq!(text.bytes, b"\xDCn\xEFc\xF6d\xE9 \x93quotes\x94 \x96 \x805 \x85 ?");
//! assert_eq!(text.replaced, 1);
//! assert_eq!(win_ansi_decode(0x80), Some('€'));
//! assert_eq!(win_ansi_decode(0x81), None);
//! ```

/// The byte written for a character WinAnsiEncoding cannot encode: `?` (decision D-16).
pub const REPLACEMENT: u8 = b'?';

/// Text encoded with [`win_ansi_encode`].
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WinAnsiText {
    /// The encoded bytes: one per character of the input.
    pub bytes: Vec<u8>,
    /// How many characters had no WinAnsiEncoding code and were written as
    /// [`REPLACEMENT`] (`?`).
    pub replaced: usize,
}

impl WinAnsiText {
    /// The warning for replaced characters, or `None` when nothing was replaced: "N characters
    /// cannot be shown with the standard 14 fonts (embedded fonts: M7)".
    ///
    /// ```
    /// use folioxide_content::encoding::win_ansi_encode;
    ///
    /// assert_eq!(win_ansi_encode("plain").warning(), None);
    /// assert_eq!(
    ///     win_ansi_encode("Ж и Ω").warning().as_deref(),
    ///     Some("3 characters cannot be shown with the standard 14 fonts (embedded fonts: M7)")
    /// );
    /// ```
    pub fn warning(&self) -> Option<String> {
        match self.replaced {
            0 => None,
            1 => Some(
                "1 character cannot be shown with the standard 14 fonts (embedded fonts: M7)"
                    .to_owned(),
            ),
            n => Some(format!(
                "{n} characters cannot be shown with the standard 14 fonts (embedded fonts: M7)"
            )),
        }
    }
}

/// Encodes `text` in WinAnsiEncoding, one byte per character. Characters without a code
/// (outside Windows-1252, or control characters) become [`REPLACEMENT`] (`?`) and are counted
/// in [`WinAnsiText::replaced`]. No normalization is applied: a letter followed by a combining
/// accent is two characters, and the accent is replaced.
pub fn win_ansi_encode(text: &str) -> WinAnsiText {
    let mut bytes = Vec::with_capacity(text.len());
    let mut replaced = 0usize;
    for c in text.chars() {
        match win_ansi_code(c) {
            Some(code) => bytes.push(code),
            None => {
                bytes.push(REPLACEMENT);
                replaced = replaced.saturating_add(1);
            }
        }
    }
    WinAnsiText { bytes, replaced }
}

/// The WinAnsiEncoding code of `c`, or `None` when it has none.
///
/// ```
/// use folioxide_content::encoding::win_ansi_code;
///
/// assert_eq!(win_ansi_code('A'), Some(0x41));
/// assert_eq!(win_ansi_code('\u{2122}'), Some(0x99)); // trademark
/// assert_eq!(win_ansi_code('\u{00A0}'), Some(0xA0)); // no-break space: glyph `space`
/// assert_eq!(win_ansi_code('\t'), None);
/// assert_eq!(win_ansi_code('\u{0141}'), None); // Ł
/// ```
pub fn win_ansi_code(c: char) -> Option<u8> {
    let scalar = u32::from(c);
    match scalar {
        0x20..=0x7E | 0xA0..=0xFF => u8::try_from(scalar).ok(),
        _ => {
            let position = HIGH_CHARS.iter().position(|&h| h == Some(c))?;
            u8::try_from(0x80 + position).ok()
        }
    }
}

/// The character WinAnsiEncoding code `code` stands for, or `None` for an unused code (below
/// 0x20, 0x7F, 0x81, 0x8D, 0x8F, 0x90, 0x9D). 0xA0 decodes to U+00A0 and 0xAD to U+00AD, the
/// inverse of [`win_ansi_code`].
pub fn win_ansi_decode(code: u8) -> Option<char> {
    match code {
        0x20..=0x7E | 0xA0..=0xFF => Some(char::from(code)),
        0x80..=0x9F => HIGH_CHARS.get(usize::from(code - 0x80)).copied().flatten(),
        _ => None,
    }
}

/// The glyph name Annex D.2 gives WinAnsiEncoding code `code` (the Adobe Glyph List name the
/// standard-14 font metrics use), or `None` for an unused code.
///
/// ```
/// use folioxide_content::encoding::win_ansi_glyph_name;
///
/// assert_eq!(win_ansi_glyph_name(0x27), Some("quotesingle"));
/// assert_eq!(win_ansi_glyph_name(0x80), Some("Euro"));
/// assert_eq!(win_ansi_glyph_name(0xA0), Some("space"));
/// assert_eq!(win_ansi_glyph_name(0x9D), None);
/// ```
pub fn win_ansi_glyph_name(code: u8) -> Option<&'static str> {
    let index = usize::from(code.checked_sub(0x20)?);
    GLYPH_NAMES
        .get(index)
        .copied()
        .filter(|name| !name.is_empty())
}

/// Unicode for codes 0x80..=0x9F (Windows-1252); `None` for the five codes it leaves undefined.
const HIGH_CHARS: [Option<char>; 32] = [
    Some('\u{20AC}'), // 0x80 Euro
    None,             // 0x81
    Some('\u{201A}'), // 0x82 quotesinglbase
    Some('\u{0192}'), // 0x83 florin
    Some('\u{201E}'), // 0x84 quotedblbase
    Some('\u{2026}'), // 0x85 ellipsis
    Some('\u{2020}'), // 0x86 dagger
    Some('\u{2021}'), // 0x87 daggerdbl
    Some('\u{02C6}'), // 0x88 circumflex
    Some('\u{2030}'), // 0x89 perthousand
    Some('\u{0160}'), // 0x8A Scaron
    Some('\u{2039}'), // 0x8B guilsinglleft
    Some('\u{0152}'), // 0x8C OE
    None,             // 0x8D
    Some('\u{017D}'), // 0x8E Zcaron
    None,             // 0x8F
    None,             // 0x90
    Some('\u{2018}'), // 0x91 quoteleft
    Some('\u{2019}'), // 0x92 quoteright
    Some('\u{201C}'), // 0x93 quotedblleft
    Some('\u{201D}'), // 0x94 quotedblright
    Some('\u{2022}'), // 0x95 bullet
    Some('\u{2013}'), // 0x96 endash
    Some('\u{2014}'), // 0x97 emdash
    Some('\u{02DC}'), // 0x98 tilde
    Some('\u{2122}'), // 0x99 trademark
    Some('\u{0161}'), // 0x9A scaron
    Some('\u{203A}'), // 0x9B guilsinglright
    Some('\u{0153}'), // 0x9C oe
    None,             // 0x9D
    Some('\u{017E}'), // 0x9E zcaron
    Some('\u{0178}'), // 0x9F Ydieresis
];

/// Annex D.2 glyph names for codes 0x20..=0xFF; empty for unused codes.
#[rustfmt::skip]
const GLYPH_NAMES: [&str; 224] = [
    // 0x20
    "space", "exclam", "quotedbl", "numbersign", "dollar", "percent", "ampersand", "quotesingle",
    "parenleft", "parenright", "asterisk", "plus", "comma", "hyphen", "period", "slash",
    // 0x30
    "zero", "one", "two", "three", "four", "five", "six", "seven",
    "eight", "nine", "colon", "semicolon", "less", "equal", "greater", "question",
    // 0x40
    "at", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
    // 0x50
    "P", "Q", "R", "S", "T", "U", "V", "W",
    "X", "Y", "Z", "bracketleft", "backslash", "bracketright", "asciicircum", "underscore",
    // 0x60
    "grave", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
    // 0x70
    "p", "q", "r", "s", "t", "u", "v", "w",
    "x", "y", "z", "braceleft", "bar", "braceright", "asciitilde", "",
    // 0x80
    "Euro", "", "quotesinglbase", "florin", "quotedblbase", "ellipsis", "dagger", "daggerdbl",
    "circumflex", "perthousand", "Scaron", "guilsinglleft", "OE", "", "Zcaron", "",
    // 0x90
    "", "quoteleft", "quoteright", "quotedblleft", "quotedblright", "bullet", "endash", "emdash",
    "tilde", "trademark", "scaron", "guilsinglright", "oe", "", "zcaron", "Ydieresis",
    // 0xA0
    "space", "exclamdown", "cent", "sterling", "currency", "yen", "brokenbar", "section",
    "dieresis", "copyright", "ordfeminine", "guillemotleft", "logicalnot", "hyphen", "registered", "macron",
    // 0xB0
    "degree", "plusminus", "twosuperior", "threesuperior", "acute", "mu", "paragraph", "periodcentered",
    "cedilla", "onesuperior", "ordmasculine", "guillemotright", "onequarter", "onehalf", "threequarters", "questiondown",
    // 0xC0
    "Agrave", "Aacute", "Acircumflex", "Atilde", "Adieresis", "Aring", "AE", "Ccedilla",
    "Egrave", "Eacute", "Ecircumflex", "Edieresis", "Igrave", "Iacute", "Icircumflex", "Idieresis",
    // 0xD0
    "Eth", "Ntilde", "Ograve", "Oacute", "Ocircumflex", "Otilde", "Odieresis", "multiply",
    "Oslash", "Ugrave", "Uacute", "Ucircumflex", "Udieresis", "Yacute", "Thorn", "germandbls",
    // 0xE0
    "agrave", "aacute", "acircumflex", "atilde", "adieresis", "aring", "ae", "ccedilla",
    "egrave", "eacute", "ecircumflex", "edieresis", "igrave", "iacute", "icircumflex", "idieresis",
    // 0xF0
    "eth", "ntilde", "ograve", "oacute", "ocircumflex", "otilde", "odieresis", "divide",
    "oslash", "ugrave", "uacute", "ucircumflex", "udieresis", "yacute", "thorn", "ydieresis",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_and_glyph_names_agree_on_used_codes() {
        for code in 0..=255u8 {
            assert_eq!(
                win_ansi_decode(code).is_some(),
                win_ansi_glyph_name(code).is_some(),
                "{code:#04X}"
            );
        }
        let used = (0..=255u8)
            .filter(|&c| win_ansi_decode(c).is_some())
            .count();
        // 95 ASCII + 27 in 0x80..=0x9F + 96 in 0xA0..=0xFF.
        assert_eq!(used, 95 + 27 + 96);
    }

    #[test]
    fn every_code_round_trips() {
        for code in 0..=255u8 {
            if let Some(c) = win_ansi_decode(code) {
                assert_eq!(win_ansi_code(c), Some(code), "{code:#04X}");
            }
        }
    }

    #[test]
    fn warning_counts_characters() {
        let text = win_ansi_encode("\u{1F600}");
        assert_eq!(text.bytes, b"?");
        assert_eq!(
            text.warning().as_deref(),
            Some("1 character cannot be shown with the standard 14 fonts (embedded fonts: M7)")
        );
    }
}

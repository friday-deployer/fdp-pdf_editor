//! Standard-14 metrics and WinAnsiEncoding (M4 brief §4.7 "Fonts" and "WinAnsi", §6.2
//! "Content"): the AFM values the brief verified by hand, the by-glyph-name mapping, the font
//! dictionary, Annex D.2, the `?` replacement, and the Adobe notice in the `NOTICE` files.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;

use folioxide_content::encoding::{
    REPLACEMENT, win_ansi_code, win_ansi_decode, win_ansi_encode, win_ansi_glyph_name,
};
use folioxide_content::standard14::{ADOBE_AFM_NOTICE, Standard14Font};
use folioxide_syntax::{Object, serialize_object};

#[test]
fn standard14_helvetica_widths_match_afm() {
    let helvetica = Standard14Font::Helvetica;
    // Brief §4.7 "Verified values" (Helvetica.afm in PDFBox 3.0.3), by WinAnsi code.
    for (code, glyph, width) in [
        (0x20u8, "space", 278u16),
        (b'A', "A", 667),
        (b'W', "W", 944),
        (0x27, "quotesingle", 191), // AFM C 169 (StandardEncoding); WinAnsi 0x27
        (0x95, "bullet", 350),
        (0x85, "ellipsis", 1000),
        (0x80, "Euro", 556), // AFM C -1; WinAnsi 0x80
    ] {
        assert_eq!(helvetica.win_ansi_width(code), width, "{glyph}");
        assert_eq!(helvetica.glyph_width(glyph), Some(width), "{glyph}");
        assert_eq!(win_ansi_glyph_name(code), Some(glyph));
    }
    // 0x60 is grave in WinAnsi (StandardEncoding's quoteleft is 0x60 in the AFM).
    assert_eq!(
        helvetica.win_ansi_width(0x60),
        helvetica.glyph_width("grave").unwrap()
    );
    assert_eq!(helvetica.glyph_width("quoteleft"), Some(222));
    assert_eq!(helvetica.win_ansi_width(0x60), 333);
    assert_eq!(helvetica.bbox(), [-166, -225, 1000, 931]);
    assert_eq!(helvetica.ascent(), 718);
    assert_eq!(helvetica.descent(), -207);
    assert_eq!(helvetica.cap_height(), 718);
    assert_eq!(helvetica.x_height(), 523);
    assert_eq!(helvetica.stem_v(), 88);

    // Helvetica-Bold.afm.
    let bold = Standard14Font::HelveticaBold;
    for (code, width) in [
        (0x20u8, 278u16),
        (b'A', 722),
        (b'W', 944),
        (0x27, 238),
        (0x95, 350),
        (0x85, 1000),
        (0x80, 556),
        (0x8E, 611),
        (0xFF, 556),
    ] {
        assert_eq!(bold.win_ansi_width(code), width, "{code:#04X}");
    }
    assert_eq!(bold.bbox(), [-170, -228, 1003, 962]);
    assert_eq!(
        (bold.ascent(), bold.descent(), bold.cap_height()),
        (718, -207, 718)
    );
    assert_eq!((bold.x_height(), bold.stem_v()), (532, 140));

    for &font in Standard14Font::ALL {
        for code in 0..=255u8 {
            let expected = match (code, win_ansi_glyph_name(code)) {
                (0..=0x1F, _) => 0,
                (_, Some(glyph)) => font.glyph_width(glyph).unwrap(),
                // Unused codes above 0x20 show a bullet (Annex D.2 note 6).
                (_, None) => font.glyph_width("bullet").unwrap(),
            };
            assert_eq!(font.win_ansi_width(code), expected, "{font:?} {code:#04X}");
        }
        assert_eq!(font.glyph_width("no-such-glyph"), None);
        assert_eq!(Standard14Font::from_base_font(font.base_font()), Some(font));
    }
    assert_eq!(Standard14Font::default(), Standard14Font::Helvetica);
    assert_eq!(Standard14Font::HelveticaBold.base_font(), "Helvetica-Bold");

    // text_width sums the WinAnsi widths at the font size.
    let encoded = win_ansi_encode("AW €…").bytes;
    let units = 667 + 944 + 278 + 556 + 1000;
    assert_eq!(helvetica.text_width(&encoded, 1000.0), f64::from(units));
    assert_eq!(
        helvetica.text_width(&encoded, 12.0),
        f64::from(units) * 12.0 / 1000.0
    );
    assert_eq!(helvetica.text_width(b"", 12.0), 0.0);
    assert_eq!(helvetica.text_width(b"\x00\x1F", 12.0), 0.0);
}

#[test]
fn standard14_font_dict_has_widths() {
    for &font in Standard14Font::ALL {
        let dict = font.font_dict();
        let keys: Vec<&[u8]> = dict.keys().map(|k| k.as_bytes()).collect();
        assert_eq!(
            keys,
            [
                &b"Type"[..],
                b"Subtype",
                b"BaseFont",
                b"Encoding",
                b"FirstChar",
                b"LastChar",
                b"Widths"
            ]
        );
        assert_eq!(dict.get_name(b"Type").unwrap(), "Font");
        assert_eq!(dict.get_name(b"Subtype").unwrap(), "Type1");
        assert_eq!(dict.get_name(b"BaseFont").unwrap(), font.base_font());
        assert_eq!(dict.get_name(b"Encoding").unwrap(), "WinAnsiEncoding");
        assert_eq!(dict.get_int(b"FirstChar"), Some(32));
        assert_eq!(dict.get_int(b"LastChar"), Some(255));
        let widths = dict.get_array(b"Widths").unwrap();
        assert_eq!(widths.len(), 224);
        for (i, width) in widths.iter().enumerate() {
            let code = u8::try_from(32 + i).unwrap();
            assert_eq!(
                width,
                &Object::Int(i64::from(font.win_ansi_width(code))),
                "{font:?} {code:#04X}"
            );
        }
    }
    // As the serializer writes it.
    let mut out = Vec::new();
    serialize_object(
        &Object::Dict(Standard14Font::Helvetica.font_dict()),
        &mut out,
    );
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.starts_with(
            "<</Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding \
             /FirstChar 32 /LastChar 255 /Widths [278 278 355 556 556 889 667 191 333 333 "
        ),
        "{text}"
    );
    assert!(text.ends_with(" 500 556 500]>>"), "{text}");
}

#[test]
fn win_ansi_encode_table_d2() {
    // ASCII is itself, with quotesingle at 0x27 and grave at 0x60.
    for code in 0x20..=0x7Eu8 {
        assert_eq!(win_ansi_decode(code), Some(char::from(code)));
        assert_eq!(win_ansi_code(char::from(code)), Some(code));
    }
    assert_eq!(win_ansi_glyph_name(0x27), Some("quotesingle"));
    assert_eq!(win_ansi_glyph_name(0x60), Some("grave"));
    // 0xA0..=0xFF is ISO 8859-1; 0xA0 is the glyph space and 0xAD the glyph hyphen.
    for code in 0xA0..=0xFFu8 {
        assert_eq!(win_ansi_decode(code), Some(char::from(code)));
        assert_eq!(win_ansi_code(char::from(code)), Some(code));
    }
    assert_eq!(win_ansi_code('\u{00A0}'), Some(0xA0));
    assert_eq!(win_ansi_code('\u{00AD}'), Some(0xAD));
    assert_eq!(win_ansi_glyph_name(0xA0), Some("space"));
    assert_eq!(win_ansi_glyph_name(0xAD), Some("hyphen"));
    // 0x80..=0x9F: Annex D.2's glyphs, with their Unicode values (Windows-1252).
    let high: [(u8, char, &str); 27] = [
        (0x80, '\u{20AC}', "Euro"),
        (0x82, '\u{201A}', "quotesinglbase"),
        (0x83, '\u{0192}', "florin"),
        (0x84, '\u{201E}', "quotedblbase"),
        (0x85, '\u{2026}', "ellipsis"),
        (0x86, '\u{2020}', "dagger"),
        (0x87, '\u{2021}', "daggerdbl"),
        (0x88, '\u{02C6}', "circumflex"),
        (0x89, '\u{2030}', "perthousand"),
        (0x8A, '\u{0160}', "Scaron"),
        (0x8B, '\u{2039}', "guilsinglleft"),
        (0x8C, '\u{0152}', "OE"),
        (0x8E, '\u{017D}', "Zcaron"),
        (0x91, '\u{2018}', "quoteleft"),
        (0x92, '\u{2019}', "quoteright"),
        (0x93, '\u{201C}', "quotedblleft"),
        (0x94, '\u{201D}', "quotedblright"),
        (0x95, '\u{2022}', "bullet"),
        (0x96, '\u{2013}', "endash"),
        (0x97, '\u{2014}', "emdash"),
        (0x98, '\u{02DC}', "tilde"),
        (0x99, '\u{2122}', "trademark"),
        (0x9A, '\u{0161}', "scaron"),
        (0x9B, '\u{203A}', "guilsinglright"),
        (0x9C, '\u{0153}', "oe"),
        (0x9E, '\u{017E}', "zcaron"),
        (0x9F, '\u{0178}', "Ydieresis"),
    ];
    for (code, c, glyph) in high {
        assert_eq!(win_ansi_decode(code), Some(c), "{code:#04X}");
        assert_eq!(win_ansi_code(c), Some(code), "{c}");
        assert_eq!(win_ansi_glyph_name(code), Some(glyph), "{code:#04X}");
    }
    // Unused codes: never produced, never decoded.
    let unused: Vec<u8> = (0..=255u8)
        .filter(|&c| win_ansi_decode(c).is_none())
        .collect();
    let mut expected: Vec<u8> = (0x00..0x20).collect();
    expected.extend([0x7F, 0x81, 0x8D, 0x8F, 0x90, 0x9D]);
    assert_eq!(unused, expected);
    for code in expected {
        assert_eq!(win_ansi_glyph_name(code), None);
    }
    // Every character of the first plane that encodes, decodes back to itself.
    let mut encodable = 0;
    for scalar in 0..=0xFFFFu32 {
        let Some(c) = char::from_u32(scalar) else {
            continue;
        };
        if let Some(code) = win_ansi_code(c) {
            encodable += 1;
            assert_eq!(win_ansi_decode(code), Some(c));
        }
    }
    assert_eq!(encodable, 95 + 27 + 96);
    assert_eq!(win_ansi_code('?'), Some(REPLACEMENT));

    let text = win_ansi_encode("Grüße, Zoë: “€ 1 000” – …");
    assert_eq!(
        text.bytes,
        b"Gr\xFC\xDFe, Zo\xEB: \x93\x80 1 000\x94 \x96 \x85"
    );
    assert_eq!(text.replaced, 0);
    assert_eq!(text.warning(), None);
}

#[test]
fn win_ansi_unmappable_replaced() {
    let text = win_ansi_encode("Łódź → 東京\tok\u{301}?");
    // Ł, ź, →, 東, 京, TAB and the combining acute: 7 replaced; ó and the literal '?' are kept.
    assert_eq!(text.bytes, b"?\xF3d? ? ???ok??");
    assert_eq!(text.replaced, 7);
    assert_eq!(
        text.warning().as_deref(),
        Some("7 characters cannot be shown with the standard 14 fonts (embedded fonts: M7)")
    );
    // One byte per character, whatever the UTF-8 length.
    let emoji = win_ansi_encode("\u{1F600}\u{1F600}");
    assert_eq!(emoji.bytes, b"??");
    assert_eq!(emoji.replaced, 2);
    // Control characters have no glyph.
    for c in ['\0', '\n', '\r', '\u{7F}', '\u{81}', '\u{9D}'] {
        assert_eq!(win_ansi_code(c), None, "{c:?}");
    }
    assert_eq!(win_ansi_encode("").bytes, b"");
}

/// The Adobe notice travels with the metrics (brief §4.7 "Licence", §6.1).
#[test]
fn notice_files_carry_adobe_afm_notice() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for path in [crate_dir.join("NOTICE"), crate_dir.join("../../NOTICE")] {
        let notice = std::fs::read_to_string(&path).unwrap();
        assert!(notice.contains(ADOBE_AFM_NOTICE), "{}", path.display());
        for &font in Standard14Font::ALL {
            assert!(
                notice.contains(font.copyright_notice()),
                "{}: {font:?}",
                path.display()
            );
        }
        assert!(notice.contains("derived (widths\nextracted) from the Adobe AFM files"));
    }
    let generated =
        std::fs::read_to_string(crate_dir.join("src/standard14/afm_tables.rs")).unwrap();
    assert!(generated.contains(&format!("// {ADOBE_AFM_NOTICE}\n")));
    assert!(generated.contains("derived (widths extracted) from the Adobe AFM files"));
    assert!(ADOBE_AFM_NOTICE.starts_with("This file and the 14 PostScript(R) AFM files"));
    assert!(ADOBE_AFM_NOTICE.ends_with("support the use of the AFM files."));
}

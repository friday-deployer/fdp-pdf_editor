#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Text strings, dates and the Info dictionary (ISO 32000-2 §7.9.2.2, §7.9.4, §14.3.3, Annex
//! D.3; M2 brief AC3, ARCHITECTURE §A.10 trap #17).

mod common;

use common::{build, diagnostics_with, open};
use folioxide_model::text::{
    decode_pdf_doc, decode_text_string, encode_pdf_doc, encode_text_string, pdf_doc_char,
};
use folioxide_model::{DocInfo, PdfDate, Trapped};
use folioxide_testkit::fixtures::model;

/// Every defined PDFDocEncoding code decodes to its Annex D.3 character and encodes back to the
/// same byte; text made of PDFDocEncoding characters is written in PDFDocEncoding.
#[test]
fn text_string_pdfdoc_roundtrip() {
    // Byte → text → byte for every defined code, one at a time and all together.
    let defined: Vec<u8> = (0..=255u8).filter(|&b| pdf_doc_char(b).is_some()).collect();
    assert_eq!(defined.len(), 232);
    for &b in &defined {
        let text = decode_text_string(&[b]);
        assert_eq!(text.chars().count(), 1, "{b:#04X}");
        assert_eq!(encode_text_string(&text), [b], "{b:#04X} {text:?}");
    }
    let text = decode_text_string(&defined);
    assert_eq!(encode_text_string(&text), defined);

    // Text → bytes → text for typical strings.
    let samples = [
        ("Annual report 2024", &b"Annual report 2024"[..]),
        (
            "Caf\u{E9} cr\u{E8}me br\u{FB}l\u{E9}e",
            b"Caf\xE9 cr\xE8me br\xFBl\xE9e",
        ),
        (
            "\u{201C}quoted\u{201D} \u{2014} \u{2018}x\u{2019} \u{2026}",
            b"\x8Dquoted\x8E \x84 \x8Fx\x90 \x83",
        ),
        (
            "\u{FB01}\u{FB02} \u{0152}\u{0153} \u{0160}\u{0161} \u{017D}\u{017E}",
            b"\x93\x94 \x96\x9C \x97\x9D \x99\x9E",
        ),
        (
            "\u{20AC}100 \u{2122} \u{2022} \u{2020}\u{2021}",
            b"\xA0100 \x92 \x80 \x81\x82",
        ),
        (
            "\u{02D8}\u{02C7}\u{02C6}\u{02D9}\u{02DD}\u{02DB}\u{02DA}\u{02DC}",
            b"\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
        ),
        ("tab\there\r\nline", b"tab\there\r\nline"),
    ];
    for (text, bytes) in samples {
        assert_eq!(encode_text_string(text), bytes, "{text:?}");
        assert_eq!(encode_pdf_doc(text).as_deref(), Some(bytes), "{text:?}");
        assert_eq!(decode_text_string(bytes), text, "{text:?}");
    }

    // The tricky ranges: 0x18–0x1F are accents, 0x7F, 0x9F and 0xAD are undefined.
    assert_eq!(
        decode_pdf_doc(b"\x17\x18\x1F\x20"),
        "\u{17}\u{02D8}\u{02DC} "
    );
    assert_eq!(decode_pdf_doc(b"\x7E\x7F\x80"), "~\u{FFFD}\u{2022}");
    assert_eq!(
        decode_pdf_doc(b"\x9E\x9F\xA0\xA1"),
        "\u{017E}\u{FFFD}\u{20AC}\u{A1}"
    );
    assert_eq!(decode_pdf_doc(b"\xAC\xAD\xAE"), "\u{AC}\u{FFFD}\u{AE}");
    for undefined in [0x7F, 0x9F, 0xAD] {
        assert_eq!(pdf_doc_char(undefined), None);
    }
    // Latin-1 characters PDFDocEncoding redefines are not written as their Latin-1 bytes.
    for c in ['\u{80}', '\u{9F}', '\u{A0}', '\u{AD}', '\u{7F}'] {
        assert_eq!(encode_pdf_doc(&c.to_string()), None, "{c:?}");
        let encoded = encode_text_string(&c.to_string());
        assert!(encoded.starts_with(b"\xFE\xFF"), "{c:?}");
        assert_eq!(decode_text_string(&encoded), c.to_string());
    }
}

/// UTF-16BE text strings start with the byte order mark `FE FF` (§7.9.2.2.1); text outside
/// PDFDocEncoding is written that way, and decoding is lossy, never failing.
#[test]
fn text_string_utf16_bom() {
    let samples = [
        "\u{65E5}\u{672C}\u{8A9E}",
        "\u{41F}\u{440}\u{438}\u{432}\u{435}\u{442}",
        "\u{1F600} emoji outside the BMP",
        "mixed \u{E9} and \u{3042}",
        "\u{FEFF}starts with a BOM character",
    ];
    for text in samples {
        let encoded = encode_text_string(text);
        assert!(encoded.starts_with(&[0xFE, 0xFF]), "{text:?}");
        assert_eq!(encoded.len() % 2, 0);
        assert_eq!(decode_text_string(&encoded), text, "{text:?}");
    }
    assert_eq!(
        encode_text_string("\u{3042}\u{1F600}"),
        b"\xFE\xFF\x30\x42\xD8\x3D\xDE\x00"
    );
    // Malformed UTF-16: unpaired surrogates and an odd trailing byte become U+FFFD.
    assert_eq!(decode_text_string(b"\xFE\xFF\xDE\x00\x00a"), "\u{FFFD}a");
    assert_eq!(decode_text_string(b"\xFE\xFF\x00a\xD8\x3D"), "a\u{FFFD}");
    assert_eq!(decode_text_string(b"\xFE\xFF\x00a\x00"), "a\u{FFFD}");
    // UTF-8 with its byte order mark (PDF 2.0), and UTF-16LE (tolerated).
    assert_eq!(decode_text_string(b"\xEF\xBB\xBF\xE2\x82\xAC"), "\u{20AC}");
    assert_eq!(decode_text_string(b"\xFF\xFE\x42\x30"), "\u{3042}");
    // Language markers are dropped (§7.9.2.2.1).
    assert_eq!(
        decode_text_string(b"\xFE\xFF\x00\x1Bfr\x00\x1B\x00o\x00u\x00i"),
        "oui"
    );
    // PDFDocEncoding text that starts like a byte order mark is written as UTF-16.
    let tricky = "\u{FE}\u{FF} looks like a BOM";
    assert_eq!(decode_text_string(&encode_text_string(tricky)), tricky);
}

/// Date strings in the forms real files use (§7.9.4).
#[test]
fn pdf_date_lenient_forms() {
    /// Year, month, day, hour, minute, second.
    type Fields = (u16, u8, u8, u8, u8, u8);
    let cases: &[(&str, Fields, Option<i32>)] = &[
        (
            "D:20230615143005+02'00'",
            (2023, 6, 15, 14, 30, 5),
            Some(120),
        ),
        (
            "D:20230615143005+02'00",
            (2023, 6, 15, 14, 30, 5),
            Some(120),
        ),
        (
            "D:20230615143005-0530",
            (2023, 6, 15, 14, 30, 5),
            Some(-330),
        ),
        ("D:20230615143005-05", (2023, 6, 15, 14, 30, 5), Some(-300)),
        ("D:20230615143005Z", (2023, 6, 15, 14, 30, 5), Some(0)),
        ("D:20230615143005Z00'00'", (2023, 6, 15, 14, 30, 5), Some(0)),
        ("D:20230615143005", (2023, 6, 15, 14, 30, 5), None),
        ("20230615143005+01'00'", (2023, 6, 15, 14, 30, 5), Some(60)),
        ("D:202306151430", (2023, 6, 15, 14, 30, 0), None),
        ("D:2023061514", (2023, 6, 15, 14, 0, 0), None),
        ("D:20230615", (2023, 6, 15, 0, 0, 0), None),
        ("D:202306", (2023, 6, 1, 0, 0, 0), None),
        ("D:2023", (2023, 1, 1, 0, 0, 0), None),
        ("D:2023Z", (2023, 1, 1, 0, 0, 0), Some(0)),
        (
            " D:20230615143005+02'00'\0",
            (2023, 6, 15, 14, 30, 5),
            Some(120),
        ),
        (
            "2023-06-15T14:30:05+02:00",
            (2023, 6, 15, 14, 30, 5),
            Some(120),
        ),
        ("2023-06-15 14:30", (2023, 6, 15, 14, 30, 0), None),
    ];
    for (text, (year, month, day, hour, minute, second), offset) in cases {
        let date = PdfDate::parse(text.as_bytes()).unwrap_or_else(|| panic!("{text:?}"));
        assert_eq!(
            (
                date.year,
                date.month,
                date.day,
                date.hour,
                date.minute,
                date.second
            ),
            (*year, *month, *day, *hour, *minute, *second),
            "{text:?}"
        );
        assert_eq!(date.offset_minutes, *offset, "{text:?}");
        // The full form written back parses to the same date.
        assert_eq!(PdfDate::parse(date.to_pdf_string().as_bytes()), Some(date));
    }
    for text in [
        "",
        "D:",
        "D:23",
        "today",
        "D:20231301",
        "D:20230631",
        "D:20230615250000",
    ] {
        assert_eq!(PdfDate::parse(text.as_bytes()), None, "{text:?}");
    }
    let date = PdfDate::parse(b"D:20230615143005-05'30'").unwrap();
    assert_eq!(date.to_rfc3339(), "2023-06-15T14:30:05-05:30");
    assert_eq!(date.to_pdf_string(), "D:20230615143005-05'30'");
}

/// The Info dictionary, with every text-string encoding, dates, `/Trapped`, custom keys and
/// invalid entries.
#[test]
fn info_is_decoded() {
    let doc = open(model::info_strings());
    let info = doc.info().unwrap();
    assert_eq!(
        info.title.as_deref(),
        Some("\u{201C}Folio\u{201D} \u{2014} \u{FB01}nal \u{20AC}5")
    );
    assert_eq!(info.author.as_deref(), Some("Zo\u{EB} \u{1F600}"));
    assert_eq!(info.subject.as_deref(), Some("\u{DC}n\u{EF}c\u{F6}d\u{E9}"));
    assert_eq!(info.keywords.as_deref(), Some("\u{65E5}\u{672C}"));
    assert_eq!(info.creator, None);
    assert_eq!(info.producer.as_deref(), Some("folioxide-testkit"));
    let created = info.creation_date.unwrap();
    assert_eq!(created.to_rfc3339(), "2024-02-29T13:30:05+05:30");
    let modified = info.mod_date.unwrap();
    assert_eq!(modified.to_rfc3339(), "2024-03-01T00:00:00");
    assert_eq!(info.trapped, Some(Trapped::False));
    assert_eq!(info.custom.len(), 1);
    assert_eq!(info.custom.get("Company").map(String::as_str), Some("ACME"));
    assert_eq!(diagnostics_with(&doc, "/Creator is a name").len(), 1);
    assert_eq!(diagnostics_with(&doc, "/Pages is an integer").len(), 1);

    // No Info dictionary.
    let doc = open(model::inherited_attributes());
    assert_eq!(doc.info().unwrap(), DocInfo::default());
    assert!(doc.diagnostics().is_empty());
}

/// Info entries of the wrong kind are left out with a diagnostic, never an error.
#[test]
fn info_invalid_entries() {
    let pdf = build(
        "1.4",
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [] /Count 0 >>"),
            (
                3,
                "<< /Title 42 /CreationDate (yesterday) /ModDate 5 /Trapped /Maybe \
                 /Author 99 0 R /Subject null >>",
            ),
        ],
        "/Info 3 0 R",
    );
    let doc = open(pdf);
    let info = doc.info().unwrap();
    assert_eq!(info, DocInfo::default());
    assert_eq!(diagnostics_with(&doc, "/Title is an integer").len(), 1);
    assert_eq!(
        diagnostics_with(&doc, "/CreationDate is not a date (\"yesterday\")").len(),
        1
    );
    assert_eq!(
        diagnostics_with(&doc, "/ModDate is not a date (an integer)").len(),
        1
    );
    assert_eq!(diagnostics_with(&doc, "/Trapped is not").len(), 1);
    // A reference to a missing object and a null value are absent entries (§7.3.7).
    assert_eq!(doc.diagnostics().len(), 4, "{:?}", doc.diagnostics());

    let not_a_dict = build(
        "1.4",
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [] /Count 0 >>"),
            (3, "[(Title)]"),
        ],
        "/Info 3 0 R",
    );
    let doc = open(not_a_dict);
    assert_eq!(doc.info().unwrap(), DocInfo::default());
    assert_eq!(diagnostics_with(&doc, "/Info is an array").len(), 1);
}

/// The catalog's `/Version` raises the header version, never lowers it (§7.7.2).
#[test]
fn version_from_catalog() {
    let with_version = |version: &str| {
        let catalog = format!("<< /Type /Catalog /Pages 2 0 R /Version {version} >>");
        open(build(
            "1.4",
            &[(1, &catalog), (2, "<< /Type /Pages /Kids [] /Count 0 >>")],
            "",
        ))
    };
    assert_eq!(with_version("/1.7").version(), (1, 7));
    assert_eq!(with_version("/2.0").version(), (2, 0));
    assert_eq!(with_version("/1.3").version(), (1, 4));
    let doc = with_version("(1.7)");
    assert_eq!(doc.version(), (1, 4));
    assert_eq!(diagnostics_with(&doc, "not a version name").len(), 1);
    let doc = with_version("/one.seven");
    assert_eq!(doc.version(), (1, 4));
    assert_eq!(open(model::inherited_attributes()).version(), (1, 7));
}

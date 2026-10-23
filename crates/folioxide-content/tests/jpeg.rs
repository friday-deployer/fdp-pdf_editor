//! JPEG header parsing and the `/DCTDecode` passthrough XObject (M4 brief §4.7 "JPEG", §6.2
//! "Content", decision D-17), on the committed `fixtures/images/*.jpg` and on headers built
//! here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use folioxide_content::image::jpeg::{self, JpegInfo, MAX_JPEG_LEN};
use folioxide_syntax::{ErrorCode, Object, StreamData};
use proptest::prelude::*;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/images")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The byte offset of the first `FF code` marker.
fn marker(data: &[u8], code: u8) -> usize {
    data.windows(2).position(|w| w == [0xFF, code]).unwrap()
}

/// Checks the XObject of `data` and returns its info.
fn xobject(data: &[u8], color_space: &str, color_transform_0: bool) -> JpegInfo {
    let (stream, info) = jpeg::image_xobject(data.to_vec()).unwrap();
    assert_eq!(info, jpeg::parse_header(data).unwrap());
    let dict = &stream.dict;
    assert_eq!(dict.get_name(b"Type").unwrap(), "XObject");
    assert_eq!(dict.get_name(b"Subtype").unwrap(), "Image");
    assert_eq!(dict.get_int(b"Width"), Some(i64::from(info.width)));
    assert_eq!(dict.get_int(b"Height"), Some(i64::from(info.height)));
    assert_eq!(dict.get_name(b"ColorSpace").unwrap(), color_space);
    assert_eq!(dict.get_int(b"BitsPerComponent"), Some(8));
    assert_eq!(dict.get_name(b"Filter").unwrap(), "DCTDecode");
    assert_eq!(dict.get_int(b"Length"), Some(data.len() as i64));
    match dict.get_dict(b"DecodeParms") {
        Some(parms) if color_transform_0 => {
            assert_eq!(parms.len(), 1);
            assert_eq!(parms.get_int(b"ColorTransform"), Some(0));
        }
        None if !color_transform_0 => {}
        other => panic!("DecodeParms {other:?}, expected ColorTransform 0: {color_transform_0}"),
    }
    // Passthrough: the bytes are the file, unchanged and still encoded.
    assert_eq!(stream.data, StreamData::Encoded(data.to_vec()));
    info
}

#[test]
fn jpeg_baseline_gray() {
    let data = fixture("gray-baseline.jpg");
    let info = xobject(&data, "DeviceGray", false);
    assert_eq!(info.width, 85);
    assert_eq!(info.height, 110);
    assert_eq!(info.components, 1);
    assert_eq!(info.bits_per_component, 8);
    assert!(!info.progressive);
    assert_eq!(info.adobe_transform, None);
    assert!(!info.rgb_component_ids);
    assert_eq!(info.color_space(), "DeviceGray");
}

#[test]
fn jpeg_baseline_rgb() {
    let data = fixture("rgb-baseline.jpg");
    let info = xobject(&data, "DeviceRGB", false);
    assert_eq!((info.width, info.height, info.components), (48, 32, 3));
    assert!(!info.progressive);
    assert_eq!(info.adobe_transform, None);
    assert!(!info.rgb_component_ids);

    // SOF1 (extended sequential) is the same as far as the PDF is concerned.
    let mut sof1 = data.clone();
    let at = marker(&sof1, 0xC0);
    sof1[at + 1] = 0xC1;
    let info = xobject(&sof1, "DeviceRGB", false);
    assert!(!info.progressive);
}

#[test]
fn jpeg_progressive() {
    let data = fixture("rgb-progressive.jpg");
    let info = xobject(&data, "DeviceRGB", false);
    assert_eq!((info.width, info.height, info.components), (48, 32, 3));
    assert!(info.progressive);
}

#[test]
fn jpeg_rgb_ids_color_transform_0() {
    // Component IDs 'R', 'G', 'B' and no APP14: RGB, so /ColorTransform 0.
    let data = fixture("rgb-ids.jpg");
    let info = xobject(&data, "DeviceRGB", true);
    assert!(info.rgb_component_ids);
    assert_eq!(info.adobe_transform, None);
    assert!(info.needs_color_transform_0());

    // The same image with its APP14 marker: the marker governs (§7.4.8), no /DecodeParms.
    let adobe = fixture("rgb-adobe.jpg");
    let info = xobject(&adobe, "DeviceRGB", false);
    assert!(info.rgb_component_ids);
    assert_eq!(info.adobe_transform, Some(0));
    assert!(!info.needs_color_transform_0());

    // IDs 1, 2, 3 (JFIF YCbCr) need nothing.
    assert!(
        !jpeg::parse_header(&fixture("rgb-baseline.jpg"))
            .unwrap()
            .rgb_component_ids
    );
}

/// Inserts `segment` (marker, length and body) right after SOI.
fn with_segment(data: &[u8], segment: &[u8]) -> Vec<u8> {
    let mut out = data[..2].to_vec();
    out.extend_from_slice(segment);
    out.extend_from_slice(&data[2..]);
    out
}

fn app14(transform: u8) -> Vec<u8> {
    let mut segment = vec![0xFF, 0xEE, 0x00, 0x0E];
    segment.extend_from_slice(b"Adobe");
    segment.extend_from_slice(&[0x00, 0x64, 0x00, 0x00, 0x00, 0x00, transform]);
    segment
}

#[test]
fn jpeg_app14_transform_recorded() {
    assert_eq!(
        jpeg::parse_header(&fixture("rgb-adobe.jpg"))
            .unwrap()
            .adobe_transform,
        Some(0)
    );
    let base = fixture("rgb-baseline.jpg");
    let ycc = with_segment(&base, &app14(1));
    let info = xobject(&ycc, "DeviceRGB", false);
    assert_eq!(info.adobe_transform, Some(1));

    // The last APP14 counts, as in libjpeg.
    let twice = with_segment(&with_segment(&base, &app14(1)), &app14(0));
    assert_eq!(jpeg::parse_header(&twice).unwrap().adobe_transform, Some(1));

    // An APP14 marker that is too short, or not Adobe's, is ignored.
    let short = with_segment(
        &base,
        &[
            0xFF, 0xEE, 0x00, 0x0D, b'A', b'd', b'o', b'b', b'e', 0, 0x64, 0, 0, 0, 0,
        ],
    );
    assert_eq!(jpeg::parse_header(&short).unwrap().adobe_transform, None);
    let mut other = app14(1);
    other[4] = b'X';
    assert_eq!(
        jpeg::parse_header(&with_segment(&base, &other))
            .unwrap()
            .adobe_transform,
        None
    );

    // With APP14 and RGB IDs, the marker governs: no ColorTransform 0.
    let rgb_ids = fixture("rgb-ids.jpg");
    let info = xobject(&with_segment(&rgb_ids, &app14(1)), "DeviceRGB", false);
    assert_eq!(info.adobe_transform, Some(1));
    assert!(info.rgb_component_ids);
}

/// A minimal JPEG header: SOI, SOF `code` (P, Y, X, components with IDs `ids`), SOS.
fn header(code: u8, precision: u8, height: u16, width: u16, ids: &[u8]) -> Vec<u8> {
    let mut out = vec![0xFF, 0xD8, 0xFF, code];
    out.extend_from_slice(&u16::try_from(8 + 3 * ids.len()).unwrap().to_be_bytes());
    out.push(precision);
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(&width.to_be_bytes());
    out.push(u8::try_from(ids.len()).unwrap());
    for &id in ids {
        out.extend_from_slice(&[id, 0x11, 0x00]);
    }
    out.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
    out
}

fn code_of(data: &[u8]) -> ErrorCode {
    jpeg::parse_header(data).unwrap_err().code()
}

#[test]
fn jpeg_rejects_arithmetic_lossless_12bit_cmyk_dnl_truncated_no_sof() {
    assert!(jpeg::parse_header(&header(0xC0, 8, 2, 3, &[1, 2, 3])).is_ok());

    // Arithmetic coding (SOF9..SOF11, SOF13..SOF15), lossless (SOF3), hierarchical (SOF5..7,
    // DHP, EXP) and the JPG extension marker: Unsupported.
    for code in [
        0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF, 0xC3, 0xC5, 0xC6, 0xC7, 0xC8, 0xDE, 0xDF,
    ] {
        assert_eq!(
            code_of(&header(code, 8, 2, 3, &[1, 2, 3])),
            ErrorCode::Unsupported,
            "{code:#04X}"
        );
    }
    // 12- and 16-bit precision.
    for precision in [12, 16] {
        assert_eq!(
            code_of(&header(0xC0, precision, 2, 3, &[1])),
            ErrorCode::Unsupported
        );
        assert_eq!(
            code_of(&header(0xC2, precision, 2, 3, &[1])),
            ErrorCode::Unsupported
        );
    }
    // CMYK: the committed file and a built header; two components as well.
    let cmyk = fixture("cmyk.jpg");
    let err = jpeg::parse_header(&cmyk).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);
    assert!(err.to_string().contains("CMYK"), "{err}");
    assert_eq!(
        jpeg::image_xobject(cmyk).unwrap_err().code(),
        ErrorCode::Unsupported
    );
    assert_eq!(
        code_of(&header(0xC0, 8, 2, 3, b"CMYK")),
        ErrorCode::Unsupported
    );
    assert_eq!(
        code_of(&header(0xC0, 8, 2, 3, &[1, 2])),
        ErrorCode::Unsupported
    );
    // Height 0: defined by a DNL marker after the first scan.
    let err = jpeg::parse_header(&header(0xC0, 8, 0, 3, &[1])).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);
    assert!(err.to_string().contains("DNL"), "{err}");

    // Truncated: every proper prefix of a fixture up to the end of its SOS header.
    for name in [
        "gray-baseline.jpg",
        "rgb-baseline.jpg",
        "rgb-progressive.jpg",
        "rgb-ids.jpg",
    ] {
        let data = fixture(name);
        let sos = marker(&data, 0xDA);
        let sos_end = sos + 2 + usize::from(u16::from_be_bytes([data[sos + 2], data[sos + 3]]));
        assert!(jpeg::parse_header(&data[..sos_end]).is_ok(), "{name}");
        for len in 0..sos_end {
            assert_eq!(code_of(&data[..len]), ErrorCode::Image, "{name}[..{len}]");
        }
    }

    // No SOF before the scan, EOI before the scan, no SOI, a second SOI.
    let no_sof = [
        0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
    ];
    assert_eq!(code_of(&no_sof), ErrorCode::Image);
    assert_eq!(code_of(&[0xFF, 0xD8, 0xFF, 0xD9]), ErrorCode::Image);
    assert_eq!(code_of(b"\x89PNG\r\n\x1a\n"), ErrorCode::Image);
    assert_eq!(code_of(&[]), ErrorCode::Image);
    let mut second_soi = header(0xC0, 8, 2, 3, &[1]);
    second_soi.splice(2..2, [0xFF, 0xD8]);
    assert_eq!(code_of(&second_soi), ErrorCode::Image);

    // Malformed SOF segments and markers.
    let good = header(0xC0, 8, 2, 3, &[1]);
    let mut wrong_len = good.clone();
    wrong_len[5] = 12; // 8 + 3 * 1 = 11
    assert_eq!(code_of(&wrong_len), ErrorCode::Image);
    let mut zero_width = good.clone();
    zero_width[9..11].copy_from_slice(&[0, 0]);
    assert_eq!(code_of(&zero_width), ErrorCode::Image);
    assert_eq!(code_of(&header(0xC0, 8, 2, 3, &[])), ErrorCode::Image);
    let mut two_sof = good[..2].to_vec();
    two_sof.extend_from_slice(&good[2..15]);
    two_sof.extend_from_slice(&good[2..]);
    assert_eq!(code_of(&two_sof), ErrorCode::Image);
    let mut short_len = good.clone();
    short_len[4..6].copy_from_slice(&[0, 1]);
    assert_eq!(code_of(&short_len), ErrorCode::Image);
    let mut past_end = good.clone();
    past_end[4..6].copy_from_slice(&[0xFF, 0xF0]);
    assert_eq!(code_of(&past_end), ErrorCode::Image);
    let mut reserved = good.clone();
    reserved.splice(2..2, [0xFF, 0x02, 0x00, 0x02]);
    assert_eq!(code_of(&reserved), ErrorCode::Image);
    let mut stuffed = good.clone();
    stuffed.splice(2..2, [0xFF, 0x00]);
    assert_eq!(code_of(&stuffed), ErrorCode::Image);
    let mut junk = good.clone();
    junk.insert(2, 0x42);
    assert_eq!(code_of(&junk), ErrorCode::Image);
    let mut extension = good;
    extension.splice(2..2, [0xFF, 0xF7, 0x00, 0x02]); // JPEG-LS SOF55
    assert_eq!(code_of(&extension), ErrorCode::Unsupported);
}

/// The walk is one pass over the segments: 16 MiB of comment segments or of fill bytes parse
/// in well under a second, even unoptimized.
#[test]
fn jpeg_parse_is_linear() {
    let tail = header(0xC0, 8, 2, 3, &[1]);
    let mut comments = vec![0xFF, 0xD8];
    while comments.len() + 65_537 + tail.len() < MAX_JPEG_LEN {
        comments.extend_from_slice(&[0xFF, 0xFE, 0xFF, 0xFF]);
        comments.resize(comments.len() + 65_533, b'c');
    }
    comments.extend_from_slice(&tail[2..]);
    let mut fill = vec![0xFF, 0xD8];
    fill.resize(MAX_JPEG_LEN - tail.len(), 0xFF);
    fill.extend_from_slice(&tail[2..]);
    for data in [comments, fill] {
        assert!(data.len() <= MAX_JPEG_LEN);
        let start = Instant::now();
        assert_eq!(jpeg::parse_header(&data).unwrap().width, 3);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
    }
}

/// What `parse_header` promises on any input.
fn check(data: &[u8]) {
    match jpeg::parse_header(data) {
        Ok(info) => {
            assert!(info.width > 0 && info.height > 0);
            assert!(matches!(info.components, 1 | 3));
            assert_eq!(info.bits_per_component, 8);
            assert!(!info.rgb_component_ids || info.components == 3);
            let (stream, again) = jpeg::image_xobject(data.to_vec()).unwrap();
            assert_eq!(again, info);
            assert_eq!(stream.data, StreamData::Encoded(data.to_vec()));
            assert_eq!(stream.dict.get(b"Filter"), Some(&Object::name("DCTDecode")));
        }
        Err(err) => {
            assert!(
                matches!(err.code(), ErrorCode::Image | ErrorCode::Unsupported),
                "{err}"
            );
            assert_eq!(
                jpeg::image_xobject(data.to_vec()).unwrap_err().code(),
                err.code()
            );
        }
    }
}

/// A fixture with `edits` applied: (position, operation, byte).
fn mutate(base: &[u8], edits: &[(usize, u8, u8)]) -> Vec<u8> {
    let mut data = base.to_vec();
    for &(pos, operation, byte) in edits {
        if data.is_empty() {
            data.push(byte);
            continue;
        }
        let at = pos % data.len();
        match operation % 4 {
            0 => data[at] = byte,
            1 => data.insert(at, byte),
            2 => {
                data.remove(at);
            }
            _ => data.truncate(at),
        }
    }
    data
}

const SEEDS: [&str; 6] = [
    "gray-baseline.jpg",
    "rgb-baseline.jpg",
    "rgb-progressive.jpg",
    "rgb-adobe.jpg",
    "rgb-ids.jpg",
    "cmyk.jpg",
];

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10_000,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// 10,000 inputs: mutated fixtures (most cases) and arbitrary bytes behind an SOI.
    #[test]
    fn jpeg_parse_never_panics(
        seed in 0usize..SEEDS.len() + 1,
        edits in prop::collection::vec((0usize..4096, any::<u8>(), any::<u8>()), 0..8),
        random in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let data = match SEEDS.get(seed) {
            Some(name) => mutate(&fixture(name), &edits),
            None => {
                let mut data = vec![0xFF, 0xD8];
                data.extend_from_slice(&random);
                data
            }
        };
        check(&data);
        check(&random);
    }
}

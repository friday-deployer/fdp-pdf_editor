//! JPEG passthrough: a header parser and the `/DCTDecode` image XObject (ISO 32000-2 §7.4.8,
//! §8.9.5; ITU-T T.81 Annex B; decision D-17).
//!
//! [`parse_header`] walks the marker segments up to the first scan (SOS) in one bounded pass
//! and reports what the image dictionary needs. It reads at most [`MAX_JPEG_LEN`] bytes, keeps
//! no allocation proportional to the input or the pixel count, and never decodes pixels.
//!
//! **Supported:** baseline and extended sequential (SOF0, SOF1) and progressive (SOF2) Huffman
//! coding, 8 bits per component, one (gray) or three (YCbCr or RGB) components: what every
//! PDF viewer decodes.
//!
//! **Refused** with [`ErrorCode::Unsupported`]: lossless, hierarchical and arithmetic coding
//! (SOF3, SOF5–SOF7, SOF9–SOF11, SOF13–SOF15, and the `JPG`, `DHP` and `EXP` markers), 12- and
//! 16-bit precision, a height of 0 (defined later by a DNL marker), four components (CMYK and
//! YCCK, whose Adobe inversion is not handled until M7) and other component counts.
//!
//! **Refused** with [`ErrorCode::Image`]: anything malformed. That is, no SOI, a segment
//! length below 2 or past the end of the data, an SOF whose length is not `8 + 3·Nf`, a width
//! or component count of 0, sampling factors outside 1–4 or a table selector above 3, two SOF
//! segments, a scan before the SOF, EOI or a second SOI before the scan, reserved markers, and
//! data that ends before the scan.
//!
//! **Colour transform** (§7.4.8, Table 13 `ColorTransform`): an Adobe APP14 marker governs the
//! transform, so with one the dictionary has no `/DecodeParms`. Three components with the IDs
//! `'R'`, `'G'`, `'B'` and no APP14 marker are RGB (libjpeg's rule), and get
//! `/DecodeParms << /ColorTransform 0 >>` so readers that would apply the default (1, YCbCr)
//! do not. The EXIF orientation tag is ignored: the image is drawn as stored.
//!
//! **Not checked:** the entropy-coded scan data after SOS is passed through unread, so a JPEG
//! whose header declares a size its scan cannot hold (65535 × 65535 with a four-byte scan) is
//! accepted, and viewers draw nothing (or an error box) for it (M4 QA round 5, finding 2; a
//! recorded limitation, manager ruling R-24).
//!
//! ```
//! use folioxide_content::image::jpeg;
//!
//! // SOI, SOF0 (8-bit, 2 x 3, one component), SOS: enough header for the parser.
//! let header = [
//!     0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x03, 0x00, 0x02, 0x01, 0x01, 0x11, 0x00,
//!     0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
//! ];
//! let info = jpeg::parse_header(&header)?;
//! assert_eq!((info.width, info.height, info.components), (2, 3, 1));
//!
//! let (image, _) = jpeg::image_xobject(header.to_vec())?;
//! assert_eq!(image.dict.get_name(b"ColorSpace").unwrap(), "DeviceGray");
//! assert_eq!(image.dict.get_name(b"Filter").unwrap(), "DCTDecode");
//! # Ok::<(), folioxide_syntax::Error>(())
//! ```
//!
//! [`ErrorCode::Unsupported`]: folioxide_syntax::ErrorCode::Unsupported
//! [`ErrorCode::Image`]: folioxide_syntax::ErrorCode::Image

use std::borrow::Cow;

use folioxide_syntax::{Dict, Error, ErrorCode, Object, Result, Stream, StreamData};

/// The largest JPEG [`parse_header`] and [`image_xobject`] accept: 16 MiB.
pub const MAX_JPEG_LEN: usize = 16 * 1024 * 1024;

/// What the header of a supported JPEG says (see [`parse_header`]).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JpegInfo {
    /// Samples per line (`X` of the SOF segment), at least 1.
    pub width: u16,
    /// Lines (`Y` of the SOF segment), at least 1.
    pub height: u16,
    /// Components (`Nf`): 1 (gray) or 3 (colour).
    pub components: u8,
    /// Sample precision (`P`): always 8.
    pub bits_per_component: u8,
    /// Whether the frame is progressive (SOF2).
    pub progressive: bool,
    /// The transform byte of an Adobe APP14 marker (0: none, RGB or CMYK; 1: YCbCr; 2: YCCK),
    /// when there is one; the last one counts, as in libjpeg.
    pub adobe_transform: Option<u8>,
    /// Whether there are three components with the IDs `'R'`, `'G'`, `'B'` (0x52, 0x47, 0x42).
    pub rgb_component_ids: bool,
}

impl JpegInfo {
    /// The PDF colour space of the decoded samples: `DeviceGray` for one component,
    /// `DeviceRGB` for three.
    pub fn color_space(&self) -> &'static str {
        if self.components == 1 {
            "DeviceGray"
        } else {
            "DeviceRGB"
        }
    }

    /// Whether the image dictionary needs `/DecodeParms << /ColorTransform 0 >>`: three
    /// components marked RGB by their IDs, and no Adobe APP14 marker to govern the transform.
    pub fn needs_color_transform_0(&self) -> bool {
        self.components == 3 && self.rgb_component_ids && self.adobe_transform.is_none()
    }
}

/// Parses the header of a JPEG file up to its first scan (SOS), in one bounded pass.
///
/// # Errors
/// - [`ErrorCode::Image`] for a malformed header or input longer than [`MAX_JPEG_LEN`] (the
///   error carries the byte offset of the problem);
/// - [`ErrorCode::Unsupported`] for a well-formed JPEG this version cannot pass through (see
///   the [module documentation](self)).
pub fn parse_header(data: &[u8]) -> Result<JpegInfo> {
    if data.len() > MAX_JPEG_LEN {
        return Err(Error::new(
            ErrorCode::Image,
            format!(
                "the JPEG data has {} bytes, more than the 16 MiB limit",
                data.len()
            ),
        ));
    }
    if data.get(..2) != Some(&[0xFF, 0xD8][..]) {
        return Err(malformed(0, "not a JPEG file: no SOI marker (FF D8)"));
    }
    let mut pos = 2usize;
    let mut frame: Option<Frame> = None;
    let mut adobe_transform = None;
    loop {
        // A marker: FF, any number of fill bytes FF (B.1.1.2), then the marker code.
        let marker_at = pos;
        match data.get(pos) {
            Some(0xFF) => {}
            Some(&byte) => {
                return Err(malformed(
                    pos,
                    format!("expected a marker, found the byte {byte:#04X}"),
                ));
            }
            None => return Err(truncated(pos)),
        }
        pos += 1;
        while data.get(pos) == Some(&0xFF) {
            pos += 1;
        }
        let Some(&code) = data.get(pos) else {
            return Err(truncated(pos));
        };
        pos += 1;
        match code {
            // TEM and RST0..RST7 stand alone (B.1.1.4): no length follows.
            0x01 | 0xD0..=0xD7 => continue,
            0x00 => {
                return Err(malformed(
                    marker_at,
                    "a stuffed FF 00 outside the scan data",
                ));
            }
            0xD8 => return Err(malformed(marker_at, "a second SOI marker")),
            0xD9 => return Err(malformed(marker_at, "EOI before the first scan")),
            _ => {}
        }
        // Every other marker starts a segment whose big-endian length counts itself (B.1.1.4).
        let length = match (data.get(pos), data.get(pos + 1)) {
            (Some(&hi), Some(&lo)) => usize::from(u16::from_be_bytes([hi, lo])),
            _ => return Err(truncated(pos)),
        };
        if length < 2 {
            return Err(malformed(
                pos,
                format!("segment FF {code:02X} has length {length}"),
            ));
        }
        let end = pos + length; // pos <= 16 MiB + 2 and length <= 65535: no overflow.
        let Some(body) = data.get(pos + 2..end) else {
            return Err(malformed(
                pos,
                format!("segment FF {code:02X} of length {length} runs past the end of the data"),
            ));
        };
        match code {
            0xC0..=0xC2 => {
                if frame.is_some() {
                    return Err(malformed(marker_at, "more than one SOF segment"));
                }
                frame = Some(parse_frame(code, body, marker_at)?);
            }
            0xC3 | 0xC5..=0xCB | 0xCD..=0xCF | 0xDE | 0xDF => {
                return Err(Error::unsupported(format!(
                    "{} JPEG (marker FF {code:02X}): only baseline, extended sequential and \
                     progressive Huffman coding (SOF0, SOF1, SOF2) can be passed through",
                    coding_name(code)
                )));
            }
            // APP14 "Adobe": the transform byte follows "Adobe", DCTEncodeVersion, APP14Flags0
            // and APP14Flags1, at offset 11 (libjpeg reads it when the data has 12 bytes).
            0xEE => {
                if body.len() >= 12 && body.starts_with(b"Adobe") {
                    adobe_transform = body.get(11).copied();
                }
            }
            0xDA => {
                let Some(frame) = frame else {
                    return Err(malformed(marker_at, "a scan (SOS) before any SOF segment"));
                };
                return Ok(JpegInfo {
                    width: frame.width,
                    height: frame.height,
                    components: frame.components,
                    bits_per_component: 8,
                    progressive: frame.progressive,
                    adobe_transform,
                    rgb_component_ids: frame.rgb_component_ids,
                });
            }
            // DHT, DAC, DQT, DNL, DRI, APPn, COM: tables and metadata, skipped.
            0xC4 | 0xCC | 0xDB..=0xDD | 0xE0..=0xED | 0xEF | 0xFE => {}
            // JPGn (FF F0..FF FD) are extensions libjpeg cannot decode; the rest is reserved.
            0xF0..=0xFD => {
                return Err(Error::unsupported(format!(
                    "JPEG extension marker FF {code:02X}"
                )));
            }
            _ => {
                return Err(malformed(
                    marker_at,
                    format!("reserved marker FF {code:02X}"),
                ));
            }
        }
        pos = end;
    }
}

/// The image XObject for a JPEG (§8.9.5), with the data passed through unchanged:
///
/// `<< /Type /XObject /Subtype /Image /Width w /Height h /ColorSpace /DeviceGray|/DeviceRGB
/// /BitsPerComponent 8 /Filter /DCTDecode [/DecodeParms << /ColorTransform 0 >>] /Length n >>`
///
/// and [`StreamData::Encoded`] holding `data`. See the [module documentation](self) for when
/// `/DecodeParms` is written.
///
/// # Errors
/// Those of [`parse_header`].
pub fn image_xobject(data: Vec<u8>) -> Result<(Stream, JpegInfo)> {
    let info = parse_header(&data)?;
    let mut dict = Dict::with_capacity(10);
    dict.insert("Type", Object::name("XObject"));
    dict.insert("Subtype", Object::name("Image"));
    dict.insert("Width", i64::from(info.width));
    dict.insert("Height", i64::from(info.height));
    dict.insert("ColorSpace", Object::name(info.color_space()));
    dict.insert("BitsPerComponent", 8);
    dict.insert("Filter", Object::name("DCTDecode"));
    if info.needs_color_transform_0() {
        let mut parms = Dict::with_capacity(1);
        parms.insert("ColorTransform", 0);
        dict.insert("DecodeParms", parms);
    }
    // At most 16 MiB, so the cast is exact; the writers set /Length again anyway.
    dict.insert("Length", i64::try_from(data.len()).unwrap_or(i64::MAX));
    Ok((Stream::new(dict, StreamData::Encoded(data)), info))
}

/// The parts of a supported SOF segment the image dictionary needs.
struct Frame {
    width: u16,
    height: u16,
    components: u8,
    progressive: bool,
    rgb_component_ids: bool,
}

/// Parses the body (after the length) of an SOF0, SOF1 or SOF2 segment that starts at byte
/// `at` (B.2.2).
fn parse_frame(code: u8, body: &[u8], at: usize) -> Result<Frame> {
    let (&precision, rest) = body
        .split_first()
        .ok_or_else(|| malformed(at, "empty SOF segment"))?;
    let (Some(&[y_hi, y_lo]), Some(&[x_hi, x_lo]), Some(&nf)) = (
        rest.get(..2).and_then(|s| <&[u8; 2]>::try_from(s).ok()),
        rest.get(2..4).and_then(|s| <&[u8; 2]>::try_from(s).ok()),
        rest.get(4),
    ) else {
        return Err(malformed(
            at,
            format!("SOF segment of {} bytes is too short", body.len() + 2),
        ));
    };
    let expected = 8 + 3 * usize::from(nf);
    if body.len() + 2 != expected {
        return Err(malformed(
            at,
            format!(
                "SOF segment has length {} but {nf} components need {expected}",
                body.len() + 2
            ),
        ));
    }
    if precision != 8 {
        return Err(Error::unsupported(format!(
            "{precision}-bit JPEG: only 8 bits per component can be passed through"
        )));
    }
    let height = u16::from_be_bytes([y_hi, y_lo]);
    let width = u16::from_be_bytes([x_hi, x_lo]);
    if width == 0 {
        return Err(malformed(at, "JPEG width is 0"));
    }
    if height == 0 {
        return Err(Error::unsupported(
            "JPEG height 0 (the height follows in a DNL marker) cannot be passed through",
        ));
    }
    match nf {
        0 => return Err(malformed(at, "SOF segment declares 0 components")),
        1 | 3 => {}
        4 => {
            return Err(Error::unsupported(
                "four-component (CMYK or YCCK) JPEG: CMYK images arrive with M7",
            ));
        }
        n => {
            return Err(Error::unsupported(format!(
                "{n}-component JPEG: only gray (1) and colour (3) can be passed through"
            )));
        }
    }
    let specs = rest.get(5..).unwrap_or_default();
    let mut ids = [0u8; 3];
    for (index, spec) in specs.chunks_exact(3).enumerate() {
        let (id, sampling, table) = match spec {
            &[id, sampling, table] => (id, sampling, table),
            _ => continue,
        };
        let (h, v) = (sampling >> 4, sampling & 0x0F);
        if !(1..=4).contains(&h) || !(1..=4).contains(&v) {
            return Err(malformed(
                at,
                format!("component {id} has sampling factors {h}x{v}"),
            ));
        }
        if table > 3 {
            return Err(malformed(
                at,
                format!("component {id} uses quantization table {table}"),
            ));
        }
        if let Some(slot) = ids.get_mut(index) {
            *slot = id;
        }
    }
    Ok(Frame {
        width,
        height,
        components: nf,
        progressive: code == 0xC2,
        rgb_component_ids: nf == 3 && ids == *b"RGB",
    })
}

/// What the unsupported frame marker `code` codes.
fn coding_name(code: u8) -> &'static str {
    match code {
        0xC3 => "lossless",
        0xC5..=0xC7 | 0xDE | 0xDF => "hierarchical",
        0xC9..=0xCB | 0xCD..=0xCF => "arithmetic-coded",
        _ => "extension (JPG)",
    }
}

fn malformed(offset: usize, message: impl Into<Cow<'static, str>>) -> Error {
    let message = message.into();
    Error::at(
        ErrorCode::Image,
        u64::try_from(offset).unwrap_or(u64::MAX),
        format!("malformed JPEG: {message}"),
    )
}

fn truncated(offset: usize) -> Error {
    malformed(offset, "the data ends before the first scan")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SOI, an optional extra segment, SOF (`code`, P, Y, X, components), SOS.
    fn jpeg(code: u8, precision: u8, height: u16, width: u16, ids: &[u8]) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8, 0xFF, code];
        let len = 8 + 3 * ids.len();
        out.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        out.push(precision);
        out.extend_from_slice(&height.to_be_bytes());
        out.extend_from_slice(&width.to_be_bytes());
        out.push(u8::try_from(ids.len()).unwrap());
        for &id in ids {
            out.extend_from_slice(&[id, 0x11, 0]);
        }
        out.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
        out
    }

    #[test]
    fn fill_bytes_and_standalone_markers_are_skipped() {
        let base = jpeg(0xC0, 8, 4, 5, &[1]);
        let mut data = vec![0xFF, 0xD8, 0xFF, 0xFF, 0xFF, 0xD0, 0xFF, 0x01];
        data.extend_from_slice(base.get(2..).unwrap());
        let info = parse_header(&data).unwrap();
        assert_eq!((info.width, info.height), (5, 4));
    }

    #[test]
    fn sampling_and_table_selectors_are_checked() {
        let mut data = jpeg(0xC0, 8, 4, 5, &[1]);
        data[13] = 0x51; // H = 5
        assert_eq!(parse_header(&data).unwrap_err().code(), ErrorCode::Image);
        let mut data = jpeg(0xC0, 8, 4, 5, &[1]);
        data[14] = 4; // Tq = 4
        assert_eq!(parse_header(&data).unwrap_err().code(), ErrorCode::Image);
    }

    #[test]
    fn errors_carry_offsets() {
        let err = parse_header(&[0xFF, 0xD8, 0x00]).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Image);
        assert_eq!(err.offset(), Some(2));
    }

    #[test]
    fn oversized_input_is_refused_before_parsing() {
        let mut data = jpeg(0xC0, 8, 4, 5, &[1]);
        data.resize(MAX_JPEG_LEN + 1, 0);
        assert_eq!(parse_header(&data).unwrap_err().code(), ErrorCode::Image);
        data.truncate(MAX_JPEG_LEN);
        assert!(parse_header(&data).is_ok());
    }

    #[test]
    fn unsupported_markers_name_the_coding() {
        for (code, word) in [
            (0xC3, "lossless"),
            (0xC5, "hierarchical"),
            (0xC9, "arithmetic"),
            (0xCF, "arithmetic"),
            (0xC8, "JPG"),
        ] {
            let err = parse_header(&jpeg(code, 8, 4, 5, &[1])).unwrap_err();
            assert_eq!(err.code(), ErrorCode::Unsupported, "{code:#04X}");
            assert!(err.to_string().contains(word), "{code:#04X}: {err}");
        }
    }
}

//! Predictors for Flate and LZW (ISO 32000-2 §7.4.4.4), decode side.
//!
//! - **TIFF predictor 2:** each sample is stored as the difference from the same component of the
//!   pixel to its left (TIFF 6.0 §14), for 1, 2, 4, 8 and 16 bits per component.
//! - **PNG predictors 10–15:** each row starts with a tag byte that selects the algorithm for that
//!   row (0 None, 1 Sub, 2 Up, 3 Average, 4 Paeth; RFC 2083 §6), whichever of 10–15 `/Predictor`
//!   says. Bytes are predicted at byte level with `bpp = ceil(Colors × BitsPerComponent / 8)`.
//!
//! Rows are `ceil(Colors × BitsPerComponent × Columns / 8)` bytes, computed with checked
//! arithmetic. Nothing is allocated from the row size: the output is at most as long as the input.
//! A partial last row is decoded as far as it goes and flagged truncated.

use super::{Decoded, Filter, FilterError, FilterParams};

/// Row geometry shared by both predictor families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Layout {
    colors: usize,
    bits_per_component: usize,
    /// Bytes per complete pixel, at least 1 (PNG's `bpp`).
    bytes_per_pixel: usize,
    /// Bytes per row, without the PNG tag byte.
    row_len: usize,
    /// Samples (components) per row: `Colors × Columns`.
    samples_per_row: usize,
}

/// A validated predictor configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Predictor {
    None,
    Tiff(Layout),
    Png(Layout),
}

fn invalid(detail: impl Into<String>) -> FilterError {
    FilterError::InvalidParams {
        detail: detail.into(),
    }
}

impl Layout {
    fn from_params(params: &FilterParams) -> Result<Layout, FilterError> {
        if params.colors == 0 {
            return Err(invalid("/Colors must be at least 1"));
        }
        if !matches!(params.bits_per_component, 1 | 2 | 4 | 8 | 16) {
            return Err(invalid(format!(
                "/BitsPerComponent {} is not 1, 2, 4, 8 or 16",
                params.bits_per_component
            )));
        }
        if params.columns == 0 {
            return Err(invalid("/Columns must be at least 1"));
        }
        let colors = usize::from(params.colors);
        let bits_per_component = usize::from(params.bits_per_component);
        let columns =
            usize::try_from(params.columns).map_err(|_| invalid("/Columns is too large"))?;
        let bits_per_pixel = colors
            .checked_mul(bits_per_component)
            .ok_or_else(|| invalid("pixel size overflows"))?;
        let row_bits = bits_per_pixel
            .checked_mul(columns)
            .ok_or_else(|| invalid("row size overflows"))?;
        let row_len = row_bits.div_ceil(8);
        // PNG rows carry one more byte, the tag; make sure that size exists too.
        row_len
            .checked_add(1)
            .ok_or_else(|| invalid("row size overflows"))?;
        let samples_per_row = colors
            .checked_mul(columns)
            .ok_or_else(|| invalid("row size overflows"))?;
        Ok(Layout {
            colors,
            bits_per_component,
            bytes_per_pixel: bits_per_pixel.div_ceil(8).max(1),
            row_len,
            samples_per_row,
        })
    }
}

impl Predictor {
    /// Validates `params`. `/Predictor` 0 and 1 mean no prediction; 2 and 10–15 need valid
    /// `/Colors`, `/BitsPerComponent` and `/Columns`; anything else is invalid.
    pub(super) fn from_params(params: &FilterParams) -> Result<Predictor, FilterError> {
        match params.predictor {
            0 | 1 => Ok(Predictor::None),
            2 => Ok(Predictor::Tiff(Layout::from_params(params)?)),
            10..=15 => Ok(Predictor::Png(Layout::from_params(params)?)),
            other => Err(invalid(format!("unknown /Predictor {other}"))),
        }
    }
}

/// Undoes `predictor` on the output of `filter` (Flate or LZW).
pub(super) fn apply(
    filter: Filter,
    predictor: Predictor,
    decoded: Decoded,
) -> Result<Decoded, FilterError> {
    match predictor {
        Predictor::None => Ok(decoded),
        Predictor::Tiff(layout) => Ok(tiff(&layout, decoded)),
        Predictor::Png(layout) => png(filter, &layout, decoded),
    }
}

/// The Paeth predictor (RFC 2083 §6.6): whichever of left, up and up-left is closest to
/// `left + up - up_left`, ties resolved in that order.
fn paeth(left: u8, up: u8, up_left: u8) -> u8 {
    let (a, b, c) = (i16::from(left), i16::from(up), i16::from(up_left));
    let p = a + b - c;
    let (pa, pb, pc) = ((p - a).abs(), (p - b).abs(), (p - c).abs());
    if pa <= pb && pa <= pc {
        left
    } else if pb <= pc {
        up
    } else {
        up_left
    }
}

fn png(filter: Filter, layout: &Layout, decoded: Decoded) -> Result<Decoded, FilterError> {
    let Decoded {
        data: input,
        mut truncated,
    } = decoded;
    let bpp = layout.bytes_per_pixel;
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    // `Layout::from_params` checked that this does not overflow.
    let stride = layout.row_len.saturating_add(1);
    for chunk in input.chunks(stride) {
        let Some((&tag, raw)) = chunk.split_first() else {
            break;
        };
        if raw.len() < layout.row_len {
            truncated = true;
        }
        let row_start = out.len();
        // Start of the previous output row; `None` on the first row, whose "up" bytes are 0.
        let prev_start = row_start.checked_sub(layout.row_len);
        let up = |out: &[u8], j: usize| {
            prev_start
                .and_then(|p| out.get(p + j))
                .copied()
                .unwrap_or(0)
        };
        let left = |out: &[u8], j: usize| {
            j.checked_sub(bpp)
                .and_then(|k| out.get(row_start + k))
                .copied()
                .unwrap_or(0)
        };
        let up_left = |out: &[u8], j: usize| match (prev_start, j.checked_sub(bpp)) {
            (Some(p), Some(k)) => out.get(p + k).copied().unwrap_or(0),
            _ => 0,
        };
        match tag {
            0 => out.extend_from_slice(raw),
            1 => {
                for (j, &x) in raw.iter().enumerate() {
                    let predicted = left(&out, j);
                    out.push(x.wrapping_add(predicted));
                }
            }
            2 => {
                for (j, &x) in raw.iter().enumerate() {
                    let predicted = up(&out, j);
                    out.push(x.wrapping_add(predicted));
                }
            }
            3 => {
                for (j, &x) in raw.iter().enumerate() {
                    let sum = u16::from(left(&out, j)) + u16::from(up(&out, j));
                    // The average of two bytes fits in a byte.
                    out.push(x.wrapping_add((sum / 2) as u8));
                }
            }
            4 => {
                for (j, &x) in raw.iter().enumerate() {
                    let predicted = paeth(left(&out, j), up(&out, j), up_left(&out, j));
                    out.push(x.wrapping_add(predicted));
                }
            }
            other => {
                return super::corrupt_or_truncated(
                    filter,
                    out,
                    format!("invalid PNG predictor tag {other} (row at output byte {row_start})"),
                );
            }
        }
    }
    Ok(Decoded {
        data: out,
        truncated,
    })
}

fn tiff(layout: &Layout, decoded: Decoded) -> Decoded {
    let Decoded {
        data: mut buf,
        mut truncated,
    } = decoded;
    let colors = layout.colors;
    for row in buf.chunks_mut(layout.row_len) {
        if row.len() < layout.row_len {
            truncated = true;
        }
        match layout.bits_per_component {
            8 => {
                for j in colors..row.len() {
                    let prev = row.get(j - colors).copied().unwrap_or(0);
                    if let Some(byte) = row.get_mut(j) {
                        *byte = byte.wrapping_add(prev);
                    }
                }
            }
            16 => {
                let samples = layout.samples_per_row.min(row.len() / 2);
                for s in colors..samples {
                    let prev = read_u16(row, s - colors);
                    let value = read_u16(row, s).wrapping_add(prev);
                    write_u16(row, s, value);
                }
            }
            bits => {
                // 1, 2 or 4 bits: samples never straddle a byte.
                let samples = layout
                    .samples_per_row
                    .min(row.len().saturating_mul(8) / bits);
                let mask = (1u8 << bits) - 1;
                for s in colors..samples {
                    let prev = read_bits(row, s - colors, bits);
                    let value = read_bits(row, s, bits).wrapping_add(prev) & mask;
                    write_bits(row, s, bits, value);
                }
            }
        }
    }
    Decoded {
        data: buf,
        truncated,
    }
}

fn read_u16(row: &[u8], sample: usize) -> u16 {
    let hi = row.get(2 * sample).copied().unwrap_or(0);
    let lo = row.get(2 * sample + 1).copied().unwrap_or(0);
    u16::from_be_bytes([hi, lo])
}

fn write_u16(row: &mut [u8], sample: usize, value: u16) {
    let [hi, lo] = value.to_be_bytes();
    if let Some(byte) = row.get_mut(2 * sample) {
        *byte = hi;
    }
    if let Some(byte) = row.get_mut(2 * sample + 1) {
        *byte = lo;
    }
}

/// Byte index and right shift of a `bits`-wide sample (most significant bits first).
fn bit_position(sample: usize, bits: usize) -> (usize, usize) {
    let bit = sample * bits;
    (bit / 8, 8 - bits - bit % 8)
}

fn read_bits(row: &[u8], sample: usize, bits: usize) -> u8 {
    let (index, shift) = bit_position(sample, bits);
    let mask = (1u8 << bits) - 1;
    (row.get(index).copied().unwrap_or(0) >> shift) & mask
}

fn write_bits(row: &mut [u8], sample: usize, bits: usize, value: u8) {
    let (index, shift) = bit_position(sample, bits);
    let mask = ((1u8 << bits) - 1) << shift;
    if let Some(byte) = row.get_mut(index) {
        *byte = (*byte & !mask) | ((value << shift) & mask);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::test_vectors::{PNG_VECTORS, PredictorVector, TIFF_VECTORS};
    use crate::filters::tests::hex;
    use crate::filters::{DecodeLimits, decode, encode_flate, lzw};

    fn params(predictor: u8, colors: u8, bpc: u8, columns: u32) -> FilterParams {
        FilterParams::default()
            .with_predictor(predictor)
            .with_colors(colors)
            .with_bits_per_component(bpc)
            .with_columns(columns)
    }

    fn flate_with(params: &FilterParams, predicted: &[u8]) -> Result<Decoded, FilterError> {
        decode(
            Filter::Flate,
            &encode_flate(predicted, 6),
            params,
            &DecodeLimits::default(),
        )
    }

    fn check_vectors(vectors: &[PredictorVector], predictor_values: &[u8]) {
        for (i, v) in vectors.iter().enumerate() {
            let encoded = hex(v.encoded);
            let expected = hex(v.expected);
            for &predictor in predictor_values {
                let p = params(predictor, v.colors, v.bits_per_component, v.columns);
                let decoded = flate_with(&p, &encoded).unwrap();
                assert!(!decoded.truncated, "vector {i}, predictor {predictor}");
                assert_eq!(decoded.data, expected, "vector {i}, predictor {predictor}");
                // Predictors apply to LZW output in the same way.
                let lzw_encoded = lzw::encode_for_tests(&encoded, true);
                let decoded = decode(Filter::Lzw, &lzw_encoded, &p, &DecodeLimits::default());
                assert_eq!(decoded.unwrap().data, expected, "LZW vector {i}");
            }
        }
    }

    #[test]
    fn png_predictor_all_types() {
        // Hand-computed: one 8-bit component, three columns, one row per tag (RFC 2083 §6).
        let predicted = [
            0, 10, 20, 30, // None
            1, 1, 2, 3, // Sub: 1, 1+1, 2+1+... → 1 3 6
            2, 5, 5, 250, // Up: 1+5, 3+5, 6+250 (mod 256) → 6 8 0
            3, 4, 4, 4, // Average: 4+(0+6)/2, 4+(7+8)/2, 4+(11+0)/2 → 7 11 9
            4, 1, 1, 1, // Paeth → 8 12 10
        ];
        let expected = [10, 20, 30, 1, 3, 6, 6, 8, 0, 7, 11, 9, 8, 12, 10];
        for predictor in 10..=15 {
            let decoded = flate_with(&params(predictor, 1, 8, 3), &predicted).unwrap();
            assert_eq!(decoded, Decoded::complete(expected.to_vec()));
        }
        // qpdf-decoded vectors: every tag in every row position, for several pixel layouts
        // (bpp 1 with sub-byte samples, 2, 3, 6 and 8).
        check_vectors(PNG_VECTORS, &[10, 11, 12, 13, 14, 15]);
    }

    #[test]
    fn tiff_predictor_all_depths() {
        // Hand-computed: two 8-bit components, three columns; components accumulate separately.
        let decoded = flate_with(
            &params(2, 2, 8, 3),
            &[1, 100, 1, 1, 1, 255, 5, 6, 1, 1, 1, 1],
        )
        .unwrap();
        assert_eq!(decoded.data, [1, 100, 2, 101, 3, 100, 5, 6, 6, 7, 7, 8]);
        // qpdf-decoded vectors for 1, 2, 4, 8 and 16 bits per component.
        check_vectors(TIFF_VECTORS, &[2]);
    }

    #[test]
    fn predictor_params_validated() {
        let ok = |p: FilterParams| Predictor::from_params(&p).is_ok();
        assert!(
            ok(params(1, 0, 3, 0)),
            "no predictor: other values are ignored"
        );
        assert!(ok(params(0, 1, 8, 1)), "0 is treated as no predictor");
        for predictor in [3, 4, 9, 16, 255] {
            assert!(!ok(params(predictor, 1, 8, 1)), "predictor {predictor}");
        }
        for bpc in [0, 3, 5, 7, 12, 32] {
            assert!(!ok(params(12, 1, bpc, 1)), "bpc {bpc}");
        }
        assert!(!ok(params(12, 0, 8, 1)));
        assert!(!ok(params(2, 1, 8, 0)));
        // The largest values are accepted: nothing is allocated from them.
        assert!(ok(params(15, 255, 16, u32::MAX)));
        // And a bad configuration is reported before any decompression happens.
        let err = decode(
            Filter::Flate,
            b"not even flate",
            &params(7, 1, 8, 1),
            &DecodeLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(err, FilterError::InvalidParams { .. }));
    }

    #[test]
    fn predictor_partial_rows_and_bad_tags() {
        // Huge /Columns with little data: one partial row, decoded and flagged.
        let decoded = flate_with(&params(12, 3, 16, u32::MAX), &[2, 1, 2, 3]).unwrap();
        assert_eq!(decoded.data, [1, 2, 3]);
        assert!(decoded.truncated);
        let decoded = flate_with(&params(2, 1, 8, u32::MAX), &[1, 2, 3]).unwrap();
        assert_eq!(decoded.data, [1, 3, 6]);
        assert!(decoded.truncated);
        // A partial last PNG row.
        let decoded = flate_with(&params(10, 1, 8, 2), &[0, 1, 2, 1, 5]).unwrap();
        assert_eq!(decoded.data, [1, 2, 5]);
        assert!(decoded.truncated);
        // An unknown tag stops decoding: earlier rows survive.
        let decoded = flate_with(&params(10, 1, 8, 2), &[0, 1, 2, 5, 1, 1, 0, 3, 4]).unwrap();
        assert_eq!(decoded.data, [1, 2]);
        assert!(decoded.truncated);
        let err = flate_with(&params(10, 1, 8, 2), &[9, 1, 2]).unwrap_err();
        assert!(matches!(
            err,
            FilterError::Corrupt {
                filter: Filter::Flate,
                ..
            }
        ));
        // Empty data stays empty.
        assert_eq!(flate_with(&params(15, 3, 8, 10), &[]).unwrap().data, b"");
    }

    #[test]
    fn paeth_ties() {
        assert_eq!(paeth(0, 0, 0), 0);
        assert_eq!(paeth(10, 10, 10), 10);
        assert_eq!(paeth(1, 2, 3), 1); // p = 0: pa 1, pb 2, pc 3
        assert_eq!(paeth(255, 0, 255), 0); // p = 0: pa 255, pb 0
        assert_eq!(paeth(12, 9, 11), 9); // p = 10: pa 2, pb 1, pc 1, b wins the tie with c
    }
}

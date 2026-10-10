//! `ASCIIHexDecode` (ISO 32000-2 §7.4.2).
//!
//! Pairs of hexadecimal digits, white space ignored, `>` ends the data. An odd final digit is
//! completed with 0. A missing `>` is tolerated; any other character is invalid.

use super::output::LimitedOutput;
use super::{Decoded, Filter, FilterError, is_pdf_whitespace};

/// Encodes `data` as `/ASCIIHexDecode` data: upper-case hex digits followed by the `>` marker.
pub fn encode_ascii_hex(data: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(data.len().saturating_mul(2).saturating_add(1));
    for &byte in data {
        for nibble in [byte >> 4, byte & 0x0F] {
            if let Some(&digit) = DIGITS.get(usize::from(nibble)) {
                out.push(digit);
            }
        }
    }
    out.push(b'>');
    out
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decodes `/ASCIIHexDecode` data into at most `max` bytes.
pub(super) fn decode(data: &[u8], max: usize) -> Result<Decoded, FilterError> {
    let mut out = LimitedOutput::new(max, data.len() / 2);
    let mut high: Option<u8> = None;
    for &byte in data {
        if byte == b'>' {
            break;
        }
        if is_pdf_whitespace(byte) {
            continue;
        }
        let Some(value) = hex_value(byte) else {
            if let Some(high) = high {
                out.push(high << 4)?;
            }
            return super::corrupt_or_truncated(
                Filter::AsciiHex,
                out.into_vec(),
                format!("invalid character 0x{byte:02X}"),
            );
        };
        match high.take() {
            Some(high) => out.push((high << 4) | value)?,
            None => high = Some(value),
        }
    }
    // §7.4.2: "If the filter encounters the EOD marker after reading an odd number of hexadecimal
    // digits, it shall behave as if a 0 followed the last digit."
    if let Some(high) = high {
        out.push(high << 4)?;
    }
    Ok(Decoded::complete(out.into_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::tests::lcg_bytes;

    #[test]
    fn ascii_hex_spec_cases() {
        let decoded = decode(b"48 65\n6C6c\t6F>", usize::MAX).unwrap();
        assert_eq!(decoded, Decoded::complete(b"Hello".to_vec()));
        // Odd digit count: the last digit is completed with 0.
        assert_eq!(
            decode(b"901FA>", usize::MAX).unwrap().data,
            [0x90, 0x1F, 0xA0]
        );
        assert_eq!(decode(b"7>", usize::MAX).unwrap().data, [0x70]);
        // Data after the EOD marker is ignored; a missing marker is tolerated.
        assert_eq!(decode(b"41>42", usize::MAX).unwrap().data, b"A");
        assert_eq!(
            decode(b"4142", usize::MAX).unwrap(),
            Decoded::complete(b"AB".to_vec())
        );
        assert_eq!(
            decode(b"", usize::MAX).unwrap(),
            Decoded::complete(Vec::new())
        );
        assert_eq!(
            decode(b">", usize::MAX).unwrap(),
            Decoded::complete(Vec::new())
        );
    }

    #[test]
    fn ascii_hex_invalid_character() {
        let decoded = decode(b"4142G43>", usize::MAX).unwrap();
        assert_eq!(decoded.data, b"AB");
        assert!(decoded.truncated);
        let err = decode(b"zz>", usize::MAX).unwrap_err();
        assert!(matches!(
            err,
            FilterError::Corrupt {
                filter: Filter::AsciiHex,
                ..
            }
        ));
    }

    #[test]
    fn ascii_hex_limit() {
        assert_eq!(decode(b"414243>", 3).unwrap().data, b"ABC");
        assert_eq!(
            decode(b"414243>", 2).unwrap_err(),
            FilterError::LimitExceeded { limit: 2 }
        );
    }

    #[test]
    fn ascii_hex_roundtrip() {
        assert_eq!(encode_ascii_hex(b"\x00\x7F\xFFa"), b"007FFF61>");
        assert_eq!(encode_ascii_hex(b""), b">");
        for seed in 0..20 {
            let data = lcg_bytes(seed, seed as usize * 13, 256);
            let decoded = decode(&encode_ascii_hex(&data), usize::MAX).unwrap();
            assert_eq!(decoded, Decoded::complete(data));
        }
    }
}

//! `ASCII85Decode` (ISO 32000-2 §7.4.3).
//!
//! Groups of five characters `!`..`u` encode four bytes in base 85; `z` stands for four zero bytes
//! (only between groups); white space is ignored; `~>` ends the data. A final partial group of
//! *n* characters (2 to 4) encodes *n* − 1 bytes.
//!
//! Leniency: a leading `<~` (Adobe's framing, not part of PDF) is skipped, a missing `~>` is
//! tolerated, and `~` alone ends the data. Invalid characters, a `z` inside a group, a group
//! whose value exceeds 2³² − 1 and a final group of one character are corrupt data.

use super::output::LimitedOutput;
use super::{Decoded, Filter, FilterError, is_pdf_whitespace};

/// Encodes `data` as `/ASCII85Decode` data, ending with the `~>` marker.
///
/// All-zero groups of four bytes are written as `z`. No line breaks are inserted (stream data is
/// exempt from the 255-character line limit of §7.5.1).
pub fn encode_ascii85(data: &[u8]) -> Vec<u8> {
    let groups = data.len().div_ceil(4);
    let mut out = Vec::with_capacity(groups.saturating_mul(5).saturating_add(2));
    for chunk in data.chunks(4) {
        let mut word = [0u8; 4];
        for (slot, &byte) in word.iter_mut().zip(chunk) {
            *slot = byte;
        }
        let mut value = u32::from_be_bytes(word);
        if chunk.len() == 4 && value == 0 {
            out.push(b'z');
            continue;
        }
        let mut digits = [0u8; 5];
        for digit in digits.iter_mut().rev() {
            // `value % 85 < 85`, so the cast is lossless.
            *digit = b'!' + (value % 85) as u8;
            value /= 85;
        }
        // A partial group of n bytes is written as its first n + 1 characters.
        out.extend(digits.iter().take(chunk.len() + 1));
    }
    out.extend_from_slice(b"~>");
    out
}

/// Accumulates one five-character group.
struct Group {
    value: u64,
    count: usize,
}

impl Group {
    /// Appends the bytes of a complete group (`count == 5`), or of a padded partial one.
    /// Returns `false` if the value does not fit in 32 bits.
    fn flush(&mut self, out: &mut LimitedOutput) -> Result<bool, FilterError> {
        let produced = self.count.saturating_sub(1);
        // §7.4.3: pad a final partial group with `u` (84) to five characters.
        for _ in self.count..5 {
            self.value = self.value * 85 + 84;
        }
        let Ok(word) = u32::try_from(self.value) else {
            return Ok(false);
        };
        out.extend_from_slice(word.to_be_bytes().get(..produced).unwrap_or_default())?;
        self.value = 0;
        self.count = 0;
        Ok(true)
    }
}

/// Decodes `/ASCII85Decode` data into at most `max` bytes.
pub(super) fn decode(data: &[u8], max: usize) -> Result<Decoded, FilterError> {
    let mut out = LimitedOutput::new(max, data.len() / 5 * 4 + 4);
    let mut group = Group { value: 0, count: 0 };

    // Skip Adobe's optional `<~` prefix (it can never start valid PDF ASCII85 data: `<` would be
    // a one-character group).
    let start = data
        .iter()
        .position(|&b| !is_pdf_whitespace(b))
        .unwrap_or(data.len());
    let mut input = data.get(start..).unwrap_or_default();
    if let Some(rest) = input.strip_prefix(b"<~") {
        input = rest;
    }

    for &byte in input {
        match byte {
            b'~' => break,
            b'z' if group.count == 0 => out.extend_repeat(0, 4)?,
            b'!'..=b'u' => {
                group.value = group.value * 85 + u64::from(byte - b'!');
                group.count += 1;
                if group.count == 5 && !group.flush(&mut out)? {
                    return super::corrupt_or_truncated(
                        Filter::Ascii85,
                        out.into_vec(),
                        "group value exceeds 2^32 - 1",
                    );
                }
            }
            _ if is_pdf_whitespace(byte) => {}
            b'z' => {
                return super::corrupt_or_truncated(
                    Filter::Ascii85,
                    out.into_vec(),
                    "'z' inside a group",
                );
            }
            _ => {
                return super::corrupt_or_truncated(
                    Filter::Ascii85,
                    out.into_vec(),
                    format!("invalid character 0x{byte:02X}"),
                );
            }
        }
    }
    match group.count {
        0 => Ok(Decoded::complete(out.into_vec())),
        // One character cannot encode a byte: the data is damaged at the end.
        1 => Ok(Decoded {
            data: out.into_vec(),
            truncated: true,
        }),
        _ => {
            if group.flush(&mut out)? {
                Ok(Decoded::complete(out.into_vec()))
            } else {
                super::corrupt_or_truncated(
                    Filter::Ascii85,
                    out.into_vec(),
                    "final group value exceeds 2^32 - 1",
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::test_vectors::ASCII85_PYTHON;
    use crate::filters::tests::lcg_bytes;

    fn a85(data: &[u8]) -> Decoded {
        decode(data, usize::MAX).unwrap()
    }

    #[test]
    fn ascii85_z_and_eod() {
        // `z` is four zero bytes, between groups only.
        assert_eq!(a85(b"z~>"), Decoded::complete(vec![0; 4]));
        assert_eq!(a85(b"zz~>").data, vec![0; 8]);
        assert_eq!(a85(b"9jqo^z~>").data, b"Man \0\0\0\0");
        assert_eq!(a85(b"z9jqo^~>").data, b"\0\0\0\0Man ");
        // `z` inside a group is corrupt: what came before survives.
        let decoded = a85(b"9jqo^9jz~>");
        assert_eq!(decoded.data, b"Man ");
        assert!(decoded.truncated);
        assert!(matches!(
            decode(b"9jz~>", usize::MAX).unwrap_err(),
            FilterError::Corrupt {
                filter: Filter::Ascii85,
                ..
            }
        ));
        // `!!!!!` is also four zero bytes (the long form).
        assert_eq!(a85(b"!!!!!~>").data, vec![0; 4]);

        // EOD: data after `~>` is ignored; `~` alone ends the data; a missing EOD is tolerated.
        assert_eq!(a85(b"9jqo^~>9jqo^").data, b"Man ");
        assert_eq!(a85(b"9jqo^~"), Decoded::complete(b"Man ".to_vec()));
        assert_eq!(a85(b"9jqo^"), Decoded::complete(b"Man ".to_vec()));
        assert_eq!(a85(b"~>"), Decoded::complete(Vec::new()));
        assert_eq!(a85(b""), Decoded::complete(Vec::new()));

        // Final partial groups of 2, 3 and 4 characters give 1, 2 and 3 bytes.
        assert_eq!(a85(b"9`~>").data, b"M");
        assert_eq!(a85(b"9jn~>").data, b"Ma");
        assert_eq!(a85(b"9jqo~>").data, b"Man");
        // A final group of one character is damaged data: flagged, earlier bytes kept.
        let decoded = a85(b"9jqo^9~>");
        assert_eq!(decoded.data, b"Man ");
        assert!(decoded.truncated);

        // White space anywhere, Adobe's `<~` prefix, and both together.
        assert_eq!(a85(b" 9j\nqo\r\n^\t\x0C\x00~>").data, b"Man ");
        assert_eq!(a85(b"<~9jqo^~>").data, b"Man ");
        assert_eq!(a85(b"\n <~ z ~>").data, vec![0; 4]);
    }

    #[test]
    fn ascii85_invalid_data() {
        // Value above 2^32 - 1.
        assert!(matches!(
            decode(b"uuuuu~>", usize::MAX).unwrap_err(),
            FilterError::Corrupt {
                filter: Filter::Ascii85,
                ..
            }
        ));
        let decoded = a85(b"zs8W-!~>");
        assert_eq!(decoded.data, [0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(!decoded.truncated);
        let decoded = a85(b"zs8W-\"~>");
        assert_eq!(decoded.data, [0; 4]);
        assert!(decoded.truncated);
        // Characters outside `!`..`u`.
        let decoded = a85(b"9jqo^v~>");
        assert_eq!(decoded.data, b"Man ");
        assert!(decoded.truncated);
    }

    #[test]
    fn ascii85_matches_python_base64() {
        // (input, Python `base64.a85encode(input)` + "~>").
        for (input, encoded) in ASCII85_PYTHON {
            assert_eq!(encode_ascii85(input), *encoded, "encoding {input:?}");
            assert_eq!(
                a85(encoded),
                Decoded::complete(input.to_vec()),
                "decoding {encoded:?}"
            );
        }
    }

    #[test]
    fn ascii85_roundtrip_and_limit() {
        for seed in 0..40 {
            let mut data = lcg_bytes(seed, seed as usize * 7, 256);
            if seed % 3 == 0 {
                data.extend_from_slice(&[0; 9]);
            }
            assert_eq!(a85(&encode_ascii85(&data)), Decoded::complete(data));
        }
        // `z` expands 4:1, so the cap matters.
        assert_eq!(
            decode(&[b'z'; 100], 399).unwrap_err(),
            FilterError::LimitExceeded { limit: 399 }
        );
        assert_eq!(decode(&[b'z'; 100], 400).unwrap().data.len(), 400);
    }
}

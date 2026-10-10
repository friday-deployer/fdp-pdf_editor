//! `RunLengthDecode` (ISO 32000-2 §7.4.5).
//!
//! A length byte *L* is followed by *L* + 1 literal bytes (0 ≤ *L* ≤ 127) or by one byte to repeat
//! 257 − *L* times (129 ≤ *L* ≤ 255); 128 ends the data. A missing end-of-data byte is tolerated;
//! a run cut short by the end of the input keeps what is there and is flagged truncated.

use super::output::LimitedOutput;
use super::{Decoded, FilterError};

const END_OF_DATA: u8 = 128;

/// Decodes `/RunLengthDecode` data into at most `max` bytes.
pub(super) fn decode(data: &[u8], max: usize) -> Result<Decoded, FilterError> {
    let mut out = LimitedOutput::new(max, data.len().saturating_mul(2));
    let mut input = data;
    while let Some((&length, rest)) = input.split_first() {
        input = rest;
        match length {
            END_OF_DATA => break,
            0..=127 => {
                let count = usize::from(length) + 1;
                match input.split_at_checked(count) {
                    Some((literal, rest)) => {
                        out.extend_from_slice(literal)?;
                        input = rest;
                    }
                    None => {
                        out.extend_from_slice(input)?;
                        return Ok(Decoded {
                            data: out.into_vec(),
                            truncated: true,
                        });
                    }
                }
            }
            129..=255 => {
                let Some((&byte, rest)) = input.split_first() else {
                    return Ok(Decoded {
                        data: out.into_vec(),
                        truncated: true,
                    });
                };
                out.extend_repeat(byte, 257 - usize::from(length))?;
                input = rest;
            }
        }
    }
    Ok(Decoded::complete(out.into_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::test_vectors::{RUN_LENGTH_ENCODED, RUN_LENGTH_QPDF};
    use crate::filters::tests::hex;

    fn rl(data: &[u8]) -> Decoded {
        decode(data, usize::MAX).unwrap()
    }

    #[test]
    fn run_length_runs() {
        // Literal run of 3, repeat run of 4 ('x' × (257 − 253)), EOD, ignored trailing data.
        assert_eq!(
            rl(b"\x02abc\xFDx\x80zzz"),
            Decoded::complete(b"abcxxxx".to_vec())
        );
        // Longest runs: 128 literal bytes and 128 repeats.
        let mut literal = vec![127u8];
        literal.extend(0..128u8);
        assert_eq!(rl(&literal).data, (0..128u8).collect::<Vec<_>>());
        assert_eq!(rl(b"\x81q").data, vec![b'q'; 128]);
        // Missing EOD is fine; empty input is empty output.
        assert_eq!(rl(b"\x00a\xFFb"), Decoded::complete(b"abb".to_vec()));
        assert_eq!(rl(b""), Decoded::complete(Vec::new()));
        assert_eq!(rl(b"\x80"), Decoded::complete(Vec::new()));
    }

    #[test]
    fn run_length_truncated() {
        let decoded = rl(b"\x00a\x05bc");
        assert_eq!(decoded.data, b"abc");
        assert!(decoded.truncated);
        let decoded = rl(b"\x00a\xF0");
        assert_eq!(decoded.data, b"a");
        assert!(decoded.truncated);
    }

    #[test]
    fn run_length_matches_qpdf() {
        let decoded = rl(&hex(RUN_LENGTH_ENCODED));
        assert_eq!(decoded, Decoded::complete(hex(RUN_LENGTH_QPDF)));
    }

    #[test]
    fn run_length_limit() {
        // 2 input bytes give 128 output bytes: 64:1, so the cap matters.
        let bomb: Vec<u8> = [0x81, 0x00].repeat(1000);
        assert_eq!(
            decode(&bomb, 128 * 1000 - 1).unwrap_err(),
            FilterError::LimitExceeded {
                limit: 128 * 1000 - 1
            }
        );
        assert_eq!(decode(&bomb, 128 * 1000).unwrap().data.len(), 128 * 1000);
    }
}

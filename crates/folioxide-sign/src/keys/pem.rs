//! PEM blocks (RFC 7468): finding them in text and decoding their base64.
//!
//! The scanner accepts any text around the blocks (OpenSSL's `subject=` lines, comments) and
//! base64 wrapped at any line width; it reports explicit headers (`Proc-Type:`, `DEK-Info:`, the
//! RFC 1421 form OpenSSL uses for legacy encrypted keys) instead of decoding them.

use zeroize::Zeroizing;

/// One `-----BEGIN <label>----- ... -----END <label>-----` block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PemBlock<'a> {
    /// The type label, for example `PRIVATE KEY`.
    pub label: &'a str,
    /// The block from the start of its BEGIN line to the end of its END line.
    pub text: &'a str,
    /// The lines between the boundaries.
    pub body: &'a str,
}

impl PemBlock<'_> {
    /// Whether the block has RFC 1421 headers such as `Proc-Type: 4,ENCRYPTED`.
    pub(crate) fn has_headers(&self) -> bool {
        self.body.lines().any(|line| line.contains(':'))
    }

    /// Whether the block is a legacy OpenSSL encrypted key (`Proc-Type: 4,ENCRYPTED`).
    pub(crate) fn is_legacy_encrypted(&self) -> bool {
        self.body
            .lines()
            .any(|line| line.trim_start().starts_with("Proc-Type:") && line.contains("ENCRYPTED"))
    }

    /// The decoded bytes, in a buffer that is wiped when dropped. `None` when the base64 is
    /// malformed.
    pub(crate) fn decode(&self) -> Option<Zeroizing<Vec<u8>>> {
        let mut decoder = der::pem::Decoder::new_detect_wrap(self.text.as_bytes()).ok()?;
        // One exactly-sized buffer, so no reallocation leaves an unwiped copy behind.
        let mut buf = Zeroizing::new(vec![0u8; decoder.remaining_len()]);
        let len = decoder.decode(&mut buf).ok()?.len();
        if !decoder.is_finished() {
            return None;
        }
        buf.truncate(len);
        Some(buf)
    }
}

/// Every PEM block in `text`, in order. A BEGIN line without its END line ends the scan.
pub(crate) fn blocks(text: &str) -> Vec<PemBlock<'_>> {
    const BEGIN: &str = "-----BEGIN ";
    const DASHES: &str = "-----";
    let mut out = Vec::new();
    let mut rest_start = 0;
    while let Some(found) = text.get(rest_start..).and_then(|rest| rest.find(BEGIN)) {
        let begin = rest_start + found;
        let label_start = begin + BEGIN.len();
        let Some(label_len) = text.get(label_start..).and_then(|r| r.find(DASHES)) else {
            break;
        };
        let label = text
            .get(label_start..label_start + label_len)
            .unwrap_or_default();
        let after_begin = label_start + label_len + DASHES.len();
        let end_marker = format!("-----END {label}-----");
        let Some(end_found) = text.get(after_begin..).and_then(|r| r.find(&end_marker)) else {
            break;
        };
        let end_start = after_begin + end_found;
        let end = end_start + end_marker.len();
        if !label.contains('\n') && !label.contains('\r') {
            out.push(PemBlock {
                label,
                text: text.get(begin..end).unwrap_or_default(),
                body: text.get(after_begin..end_start).unwrap_or_default(),
            });
        }
        rest_start = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO: &str = "-----BEGIN TEST-----\naGVsbG8=\n-----END TEST-----";

    #[test]
    fn finds_blocks_between_other_text() {
        let text = format!(
            "subject=CN=x\n{HELLO}\nnoise\r\n{}\r\n",
            HELLO.replace('\n', "\r\n")
        );
        let found = blocks(&text);
        assert_eq!(found.len(), 2);
        for block in &found {
            assert_eq!(block.label, "TEST");
            assert_eq!(block.decode().unwrap().as_slice(), b"hello");
            assert!(!block.has_headers());
        }
    }

    #[test]
    fn wide_lines_decode() {
        let data: Vec<u8> = (0u8..=200).collect();
        let b64 = der::pem::encode_string("X", der::pem::LineEnding::LF, &data).unwrap();
        // Re-wrap at 76 columns, as some tools do.
        let body: String = b64.lines().filter(|l| !l.starts_with("-----")).collect();
        let wrapped: Vec<String> = body
            .as_bytes()
            .chunks(76)
            .map(|c| String::from_utf8(c.to_vec()).unwrap())
            .collect();
        let pem = format!(
            "-----BEGIN X-----\n{}\n-----END X-----\n",
            wrapped.join("\n")
        );
        assert_eq!(
            blocks(&pem)[0].decode().unwrap().as_slice(),
            data.as_slice()
        );
    }

    #[test]
    fn headers_and_garbage() {
        let legacy = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----";
        let block = blocks(legacy)[0];
        assert!(block.has_headers() && block.is_legacy_encrypted());
        assert!(blocks("-----BEGIN X-----\nAAAA").is_empty());
        assert!(blocks("no pem here").is_empty());
        let bad = "-----BEGIN X-----\n!!!!\n-----END X-----";
        assert!(blocks(bad)[0].decode().is_none());
    }
}

//! Stream filters (ISO 32000-2 §7.4): decoders, predictors and encoders.
//!
//! This module turns encoded stream bytes into plain bytes and back. It knows nothing about the
//! object model: callers (the store) read `/Filter` and `/DecodeParms` from the stream dictionary,
//! map them to [`Filter`] and [`FilterParams`], and call [`decode_chain`].
//!
//! # Policy
//!
//! - **Lenient.** Decoders never discard data they could decode. When the input ends early or
//!   turns corrupt part way through, the decoder returns everything decoded up to that point with
//!   [`Decoded::truncated`] set, and the caller decides whether that is a diagnostic (lenient) or
//!   an error (strict). Only input that is corrupt *before any output* is an error
//!   ([`FilterError::Corrupt`]).
//! - **Bounded.** Every decoder stops as soon as its output would exceed
//!   [`DecodeLimits::max_output`] and returns [`FilterError::LimitExceeded`], so decompression
//!   bombs cost at most `max_output` bytes of memory. Nothing is allocated from sizes that the
//!   input *claims* (predictor columns, run lengths): buffers grow only with real output.
//! - **No panics.** Arithmetic on sizes taken from the file is checked.
//!
//! # Supported filters
//!
//! | Filter | Decode | Encode |
//! |---|---|---|
//! | `FlateDecode` (§7.4.4) | yes, with predictors; partial when truncated | [`encode_flate`] |
//! | `LZWDecode` (§7.4.4) | yes, with predictors and `/EarlyChange` | no |
//! | `ASCIIHexDecode` (§7.4.2) | yes | [`encode_ascii_hex`] |
//! | `ASCII85Decode` (§7.4.3) | yes | [`encode_ascii85`] |
//! | `RunLengthDecode` (§7.4.5) | yes | no |
//! | `DCTDecode`, `JPXDecode`, `JBIG2Decode`, `CCITTFaxDecode` | passed through (see below) | no |
//! | `Crypt` (§7.4.10) | identity: the security handler decrypts before decoding | no |
//!
//! The image codecs are left encoded ([`Filter::is_passthrough`]): [`decode_chain`] stops at the
//! first one and reports the rest of the chain to the caller.

mod ascii85;
mod ascii_hex;
mod flate;
mod lzw;
mod output;
mod predictor;
mod run_length;

#[cfg(test)]
mod test_vectors;
#[cfg(test)]
mod tests;

use std::borrow::Cow;
use std::fmt;

pub use ascii_hex::encode_ascii_hex;
pub use ascii85::encode_ascii85;
pub use flate::encode_flate;

/// A standard stream filter (ISO 32000-2 §7.4.1, Table 6).
///
/// Map a `/Filter` name to a variant with [`Filter::from_name`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Filter {
    /// `FlateDecode`: zlib/deflate compression (§7.4.4), optionally with a predictor.
    Flate,
    /// `LZWDecode`: LZW compression (§7.4.4), optionally with a predictor.
    Lzw,
    /// `ASCIIHexDecode`: hexadecimal text (§7.4.2).
    AsciiHex,
    /// `ASCII85Decode`: base-85 text (§7.4.3).
    Ascii85,
    /// `RunLengthDecode`: byte-oriented run-length encoding (§7.4.5).
    RunLength,
    /// `DCTDecode`: JPEG image data (§7.4.8). Passed through, never decoded here.
    Dct,
    /// `JPXDecode`: JPEG 2000 image data (§7.4.9). Passed through, never decoded here.
    Jpx,
    /// `JBIG2Decode`: JBIG2 monochrome image data (§7.4.7). Passed through, never decoded here.
    Jbig2,
    /// `CCITTFaxDecode`: CCITT Group 3/4 fax data (§7.4.6). Passed through, never decoded here.
    CcittFax,
    /// `Crypt`: a crypt filter (§7.4.10). Decryption belongs to the security handler, which runs
    /// before the filter chain, so the decoders here treat it as the identity.
    Crypt,
}

impl Filter {
    /// Every filter, in the order of ISO 32000-2 Table 6 (handy for tests and fuzzers).
    pub const ALL: [Filter; 10] = [
        Filter::AsciiHex,
        Filter::Ascii85,
        Filter::Lzw,
        Filter::Flate,
        Filter::RunLength,
        Filter::CcittFax,
        Filter::Jbig2,
        Filter::Dct,
        Filter::Jpx,
        Filter::Crypt,
    ];

    /// Maps a filter name (the bytes of a PDF name, without the `/`) to a filter.
    ///
    /// Accepts the full names of Table 6 and the inline-image abbreviations of §8.9.7 Table 92
    /// (`AHx`, `A85`, `LZW`, `Fl`, `RL`, `CCF`, `DCT`). Returns `None` for anything else; matching
    /// is case-sensitive, as names are.
    pub fn from_name(name: &[u8]) -> Option<Filter> {
        Some(match name {
            b"FlateDecode" | b"Fl" => Filter::Flate,
            b"LZWDecode" | b"LZW" => Filter::Lzw,
            b"ASCIIHexDecode" | b"AHx" => Filter::AsciiHex,
            b"ASCII85Decode" | b"A85" => Filter::Ascii85,
            b"RunLengthDecode" | b"RL" => Filter::RunLength,
            b"DCTDecode" | b"DCT" => Filter::Dct,
            b"JPXDecode" => Filter::Jpx,
            b"JBIG2Decode" => Filter::Jbig2,
            b"CCITTFaxDecode" | b"CCF" => Filter::CcittFax,
            b"Crypt" => Filter::Crypt,
            _ => return None,
        })
    }

    /// The full filter name of Table 6, without the `/` (for example `"FlateDecode"`).
    pub const fn name(self) -> &'static str {
        match self {
            Filter::Flate => "FlateDecode",
            Filter::Lzw => "LZWDecode",
            Filter::AsciiHex => "ASCIIHexDecode",
            Filter::Ascii85 => "ASCII85Decode",
            Filter::RunLength => "RunLengthDecode",
            Filter::Dct => "DCTDecode",
            Filter::Jpx => "JPXDecode",
            Filter::Jbig2 => "JBIG2Decode",
            Filter::CcittFax => "CCITTFaxDecode",
            Filter::Crypt => "Crypt",
        }
    }

    /// True for the image codecs that this layer leaves encoded: DCT, JPX, JBIG2 and CCITT.
    ///
    /// [`decode_chain`] stops at the first such filter and reports it, and every filter after it,
    /// in [`ChainOutput::remaining`]. [`decode`] refuses them with [`FilterError::Unsupported`].
    pub const fn is_passthrough(self) -> bool {
        matches!(
            self,
            Filter::Dct | Filter::Jpx | Filter::Jbig2 | Filter::CcittFax
        )
    }

    /// True for the filters that take predictor parameters (`/Predictor`, `/Colors`,
    /// `/BitsPerComponent`, `/Columns`): Flate and LZW (§7.4.4.4, Table 8).
    pub const fn supports_predictor(self) -> bool {
        matches!(self, Filter::Flate | Filter::Lzw)
    }
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Decode parameters for Flate and LZW (ISO 32000-2 §7.4.4.4, Table 8).
///
/// [`Default`] gives the spec defaults: `/Predictor 1` (none), `/Colors 1`,
/// `/BitsPerComponent 8`, `/Columns 1` and `/EarlyChange 1`. Other filters ignore these values.
/// The values are only validated when a predictor is in use (`predictor >= 2`), by [`decode`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FilterParams {
    /// `/Predictor`: 1 = none, 2 = TIFF predictor 2, 10–15 = PNG predictors (the per-row tag
    /// selects the algorithm, whichever of 10–15 is given). 0 is treated as 1; other values are
    /// rejected with [`FilterError::InvalidParams`].
    pub predictor: u8,
    /// `/Colors`: interleaved colour components per sample, at least 1.
    pub colors: u8,
    /// `/BitsPerComponent`: 1, 2, 4, 8 or 16.
    pub bits_per_component: u8,
    /// `/Columns`: samples per row, at least 1.
    pub columns: u32,
    /// `/EarlyChange` (LZW only): `true` (the default, `1`) increases the code width one code
    /// early, as Adobe's encoder does; `false` (`0`) postpones it as long as possible.
    pub early_change: bool,
}

impl FilterParams {
    /// The spec defaults (same as [`Default::default`]).
    pub const fn new() -> FilterParams {
        FilterParams {
            predictor: 1,
            colors: 1,
            bits_per_component: 8,
            columns: 1,
            early_change: true,
        }
    }

    /// Sets `/Predictor`.
    pub const fn with_predictor(mut self, predictor: u8) -> FilterParams {
        self.predictor = predictor;
        self
    }

    /// Sets `/Colors`.
    pub const fn with_colors(mut self, colors: u8) -> FilterParams {
        self.colors = colors;
        self
    }

    /// Sets `/BitsPerComponent`.
    pub const fn with_bits_per_component(mut self, bits_per_component: u8) -> FilterParams {
        self.bits_per_component = bits_per_component;
        self
    }

    /// Sets `/Columns`.
    pub const fn with_columns(mut self, columns: u32) -> FilterParams {
        self.columns = columns;
        self
    }

    /// Sets `/EarlyChange`.
    pub const fn with_early_change(mut self, early_change: bool) -> FilterParams {
        self.early_change = early_change;
        self
    }
}

impl Default for FilterParams {
    fn default() -> FilterParams {
        FilterParams::new()
    }
}

/// Resource limits for decoding.
///
/// The store builds this from its document-wide `Limits` (`max_decoded_stream`).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DecodeLimits {
    /// The most bytes any single decoding step may produce. A decoder that would produce more stops
    /// and returns [`FilterError::LimitExceeded`]. Default: 512 MiB
    /// ([`DecodeLimits::DEFAULT_MAX_OUTPUT`]).
    pub max_output: usize,
    /// The most filters [`decode_chain`] accepts in one chain (each step may produce up to
    /// `max_output` bytes, so this bounds the work per stream). Default: 16
    /// ([`DecodeLimits::DEFAULT_MAX_CHAIN_LEN`]); real files use one to three.
    pub max_chain_len: usize,
}

impl DecodeLimits {
    /// Default for [`DecodeLimits::max_output`]: 512 MiB, matching `Limits::max_decoded_stream`.
    pub const DEFAULT_MAX_OUTPUT: usize = 512 * 1024 * 1024;
    /// Default for [`DecodeLimits::max_chain_len`].
    pub const DEFAULT_MAX_CHAIN_LEN: usize = 16;

    /// Limits with the given output cap and the default chain length.
    pub const fn new(max_output: usize) -> DecodeLimits {
        DecodeLimits {
            max_output,
            max_chain_len: DecodeLimits::DEFAULT_MAX_CHAIN_LEN,
        }
    }

    /// Sets [`DecodeLimits::max_output`].
    pub const fn with_max_output(mut self, max_output: usize) -> DecodeLimits {
        self.max_output = max_output;
        self
    }

    /// Sets [`DecodeLimits::max_chain_len`].
    pub const fn with_max_chain_len(mut self, max_chain_len: usize) -> DecodeLimits {
        self.max_chain_len = max_chain_len;
        self
    }
}

impl Default for DecodeLimits {
    fn default() -> DecodeLimits {
        DecodeLimits::new(DecodeLimits::DEFAULT_MAX_OUTPUT)
    }
}

/// The result of [`decode`].
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Decoded {
    /// The decoded bytes. When `truncated` is set, this is everything that could be decoded before
    /// the input ended or turned corrupt.
    pub data: Vec<u8>,
    /// True when the input ended in the middle of an encoded unit or contained invalid data, so
    /// `data` may be incomplete. A missing end-of-data marker at a clean boundary (`>`, `~>`, LZW
    /// code 257, RunLength 128) is tolerated and does not set this; for Flate, a missing end of the
    /// final deflate block does.
    pub truncated: bool,
}

impl Decoded {
    /// A complete (not truncated) result.
    pub const fn complete(data: Vec<u8>) -> Decoded {
        Decoded {
            data,
            truncated: false,
        }
    }
}

/// The result of [`decode_chain`].
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainOutput {
    /// The bytes after every decodable filter has been applied.
    pub data: Vec<u8>,
    /// The filters that were not applied: the first passthrough filter
    /// ([`Filter::is_passthrough`]) and every filter after it, in chain order. Empty when the whole
    /// chain was decoded.
    pub remaining: Vec<Filter>,
    /// True when any step reported [`Decoded::truncated`].
    pub truncated: bool,
}

/// Why a filter could not decode its input.
///
/// The store maps these to `ErrorCode`: `Corrupt` and `InvalidParams` to `Filter`,
/// `LimitExceeded` to `LimitExceeded`, and `Unsupported` to `Unsupported`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    /// The input is not valid data for `filter`, and nothing could be decoded before the problem.
    /// (Corruption after some output gives a truncated [`Decoded`] instead.)
    #[error("corrupt {filter} data: {detail}")]
    Corrupt {
        /// The filter whose input is corrupt.
        filter: Filter,
        /// What is wrong, for diagnostics.
        detail: String,
    },
    /// Decoding would exceed a [`DecodeLimits`] value: `max_output` (bytes produced by one step)
    /// or `max_chain_len` (filters in one chain). `limit` is the value that was exceeded.
    #[error("filter decoding limit exceeded (limit {limit})")]
    LimitExceeded {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The filter is not decoded by this layer (the passthrough image codecs).
    #[error("{filter} is not decoded by the syntax layer")]
    Unsupported {
        /// The filter that was asked for.
        filter: Filter,
    },
    /// The decode parameters are invalid (for example an unknown predictor or zero columns).
    #[error("invalid filter parameters: {detail}")]
    InvalidParams {
        /// What is wrong, for diagnostics.
        detail: String,
    },
}

/// Decodes `data` with one filter.
///
/// Flate and LZW apply the predictor from `params` after decompressing. `Crypt` is the identity
/// (decryption is the security handler's job, §7.6). The passthrough image codecs
/// ([`Filter::is_passthrough`]) return [`FilterError::Unsupported`].
///
/// # Errors
///
/// - [`FilterError::LimitExceeded`] when the output would exceed `limits.max_output`.
/// - [`FilterError::Corrupt`] when the input is invalid before anything could be decoded.
/// - [`FilterError::InvalidParams`] for an invalid predictor configuration.
/// - [`FilterError::Unsupported`] for DCT, JPX, JBIG2 and CCITT.
pub fn decode(
    filter: Filter,
    data: &[u8],
    params: &FilterParams,
    limits: &DecodeLimits,
) -> Result<Decoded, FilterError> {
    let max = limits.max_output;
    match filter {
        Filter::Flate | Filter::Lzw => {
            // Validate the predictor first: it is cheap, and a bad configuration should not cost a
            // full decompression.
            let predictor = predictor::Predictor::from_params(params)?;
            let decoded = if filter == Filter::Flate {
                flate::decode(data, max)?
            } else {
                lzw::decode(data, params.early_change, max)?
            };
            predictor::apply(filter, predictor, decoded)
        }
        Filter::AsciiHex => ascii_hex::decode(data, max),
        Filter::Ascii85 => ascii85::decode(data, max),
        Filter::RunLength => run_length::decode(data, max),
        Filter::Crypt => {
            if data.len() > max {
                return Err(FilterError::LimitExceeded { limit: max });
            }
            Ok(Decoded::complete(data.to_vec()))
        }
        Filter::Dct | Filter::Jpx | Filter::Jbig2 | Filter::CcittFax => {
            Err(FilterError::Unsupported { filter })
        }
    }
}

/// Decodes `data` through a filter chain, as given by a stream's `/Filter` and `/DecodeParms`
/// arrays (§7.3.8.2: the first filter is applied first).
///
/// Decoding stops at the first passthrough filter (DCT, JPX, JBIG2, CCITT); that filter and every
/// one after it are returned in [`ChainOutput::remaining`], with `data` decoded up to that point.
/// `Crypt` entries are skipped (identity). A truncated step does not stop the chain: later filters
/// decode the partial data and [`ChainOutput::truncated`] is set.
///
/// # Errors
///
/// - [`FilterError::LimitExceeded`] when the chain is longer than `limits.max_chain_len`, when a
///   step would produce more than `limits.max_output` bytes, or when there is nothing to decode and
///   `data` itself is longer than `limits.max_output`.
/// - Any error of [`decode`] from a step.
pub fn decode_chain(
    filters: &[(Filter, FilterParams)],
    data: &[u8],
    limits: &DecodeLimits,
) -> Result<ChainOutput, FilterError> {
    if filters.len() > limits.max_chain_len {
        return Err(FilterError::LimitExceeded {
            limit: limits.max_chain_len,
        });
    }
    let mut current: Cow<'_, [u8]> = Cow::Borrowed(data);
    let mut truncated = false;
    let mut remaining = Vec::new();
    for (index, (filter, params)) in filters.iter().enumerate() {
        if filter.is_passthrough() {
            remaining = filters
                .get(index..)
                .unwrap_or_default()
                .iter()
                .map(|(f, _)| *f)
                .collect();
            break;
        }
        if *filter == Filter::Crypt {
            continue;
        }
        let decoded = decode(*filter, &current, params, limits)?;
        truncated |= decoded.truncated;
        current = Cow::Owned(decoded.data);
    }
    if current.len() > limits.max_output {
        return Err(FilterError::LimitExceeded {
            limit: limits.max_output,
        });
    }
    Ok(ChainOutput {
        data: current.into_owned(),
        remaining,
        truncated,
    })
}

/// Shared helper for decoders: corruption before any output is an error, corruption after some
/// output is a truncated result.
fn corrupt_or_truncated(
    filter: Filter,
    data: Vec<u8>,
    detail: impl Into<String>,
) -> Result<Decoded, FilterError> {
    if data.is_empty() {
        Err(FilterError::Corrupt {
            filter,
            detail: detail.into(),
        })
    } else {
        Ok(Decoded {
            data,
            truncated: true,
        })
    }
}

/// PDF white-space characters (§7.2.3, Table 1): NUL, HT, LF, FF, CR and SP.
const fn is_pdf_whitespace(byte: u8) -> bool {
    matches!(byte, 0x00 | 0x09 | 0x0A | 0x0C | 0x0D | 0x20)
}

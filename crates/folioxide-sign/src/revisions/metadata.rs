//! The data of a `/Metadata` stream, decoded for the XMP check exactly as pyHanko decodes it (M4
//! QA round 3, finding 20).
//!
//! pyHanko's `MetadataUpdateRule` reads a new or changed `/Metadata` stream through its own
//! filters (`pdf_utils/filters.py`, `generic.py` `StreamObject.data`), and an update whose
//! stream does not decode there is `OTHER` ("/Metadata XML syntax could not be validated").
//! Folioxide's syntax layer decodes leniently, as viewers do: a Flate stream with a wrong or
//! missing Adler-32, raw deflate without a zlib header, ASCII85 without `~>`, LZW and RunLength.
//! Judging the XML of such a stream would be more lenient than pyHanko (DECISIONS D10.1), so the
//! XMP check decodes the raw bytes itself, accepting only what pyHanko decodes, to the bytes
//! pyHanko gets:
//!
//! - `/Filter` absent, a name, or a direct array of names, each `/FlateDecode` (`/Fl`),
//!   `/ASCIIHexDecode` (`/AHx`), `/ASCII85Decode` (`/A85`) or `/Crypt` with the `/Identity`
//!   filter (a no-op); anything else (LZW, RunLength, DCT, ...) is not decoded, and neither is
//!   an ASCIIHexDecode or ASCII85Decode that follows a FlateDecode, with or without filters
//!   between them (pyHanko's FlateDecode returns a `memoryview`, on which its ASCII decoders
//!   raise; M4 QA round 4 finding 11);
//! - FlateDecode: a complete zlib stream (RFC 1950 header without a preset dictionary, deflate
//!   data that reaches its final block, a matching Adler-32), as Python's `zlib.decompress`;
//!   what follows it is ignored, as there. `/DecodeParms` may not set a `/Predictor` other than
//!   1 (pyHanko implements only some PNG predictors, and those as if each sample were one byte);
//! - ASCIIHexDecode: hexadecimal digits and white-space up to the first `>`, which is required;
//!   an odd final digit is followed by 0 (§7.4.2);
//! - ASCII85Decode: groups of `!`–`u` (or `z` for four zeros) and white-space up to the first
//!   `~>`, which is required; a final group has 2 to 4 characters, and every group fits in 32
//!   bits (§7.4.3); the final group is decoded as pyHanko decodes it;
//! - the stream's `/Length` is the data's length (no repaired stream extent), and it has no
//!   `/F`, `/FFilter` or `/FDecodeParms` (§7.3.8.2: data in an external file, which readers
//!   that honour it read instead of the embedded bytes).
//!
//! Each filter is one pass over its input, and every output is capped.

use folioxide_syntax::{Dict, Object, Store, Stream, StreamData};

/// The most filters of a chain the check decodes.
const MAX_FILTERS: usize = 8;

/// Python's `\s` on bytes (pyHanko's `WS_REGEX`), the white-space ASCIIHex and ASCII85 data may
/// hold.
fn is_python_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

/// One filter of the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Filter {
    Flate,
    AsciiHex,
    Ascii85,
    /// `/Crypt` with the `/Identity` filter.
    Identity,
}

/// The decoded data of the `/Metadata` stream `stream` of `store`, decoded as pyHanko decodes it
/// (see the module documentation), when it is at most `cap` bytes at every step; `None` when
/// pyHanko would not decode it, or it is larger.
pub(super) fn decode(store: &Store, stream: &Stream, cap: usize) -> Option<Vec<u8>> {
    // §7.3.8.2: with /F the data is an external file's, and readers that honour it ignore the
    // embedded bytes, which pyHanko reads: not decoded.
    if [b"F".as_slice(), b"FFilter", b"FDecodeParms"]
        .iter()
        .any(|key| stream.dict.contains_key(key))
    {
        return None;
    }
    let raw: Vec<u8> = match &stream.data {
        StreamData::Source(_) | StreamData::Encoded(_) => {
            let raw = store.raw_stream_data(stream).ok()?;
            let length = stream
                .dict
                .get(b"Length")
                .and_then(|l| store.deref(l).ok())
                .and_then(|l| l.as_int())?;
            if usize::try_from(length).ok()? != raw.len() {
                return None;
            }
            raw.into_owned()
        }
        StreamData::Decoded(data) if !stream.dict.contains_key(b"Filter") => data.clone(),
        _ => return None,
    };
    let mut data = raw;
    // pyHanko's FlateDecode (predictor 1, the only one decoded here) returns a `memoryview`, which
    // a later FlateDecode accepts (`zlib.decompress`) and the Identity crypt filter passes on
    // (pyHanko skips it), but on which ASCIIHexDecode and ASCII85Decode raise (`data.split`:
    // "'memoryview' object has no attribute 'split'", M4 QA round 4 finding 11). Such a chain
    // does not decode there, so it is not decoded here either.
    let mut memoryview = false;
    for (filter, params) in chain(store, &stream.dict)? {
        data = match filter {
            Filter::Identity => data,
            Filter::Flate => {
                let predictor = params
                    .as_ref()
                    .and_then(|p| p.get(b"Predictor"))
                    .map(|p| store.deref(p).ok().and_then(|p| p.as_int()));
                if !matches!(predictor, None | Some(Some(1))) {
                    return None;
                }
                memoryview = true;
                miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&data, cap).ok()?
            }
            Filter::AsciiHex | Filter::Ascii85 if memoryview => return None,
            Filter::AsciiHex => ascii_hex(&data)?,
            Filter::Ascii85 => ascii85(&data)?,
        };
        if data.len() > cap {
            return None;
        }
    }
    (data.len() <= cap).then_some(data)
}

/// The filters of `dict` with their parameters (`None` for null or absent ones), as pyHanko
/// pairs them (a single parameter dictionary goes with the first filter); `None` for a chain the
/// check does not decode.
fn chain(store: &Store, dict: &Dict) -> Option<Vec<(Filter, Option<Dict>)>> {
    let names: Vec<Vec<u8>> = match dict.get(b"Filter") {
        None => return Some(Vec::new()),
        Some(Object::Name(name)) => vec![name.as_bytes().to_vec()],
        Some(Object::Array(items)) => items
            .iter()
            .map(|item| item.as_name().map(|n| n.as_bytes().to_vec()))
            .collect::<Option<_>>()?,
        Some(_) => return None,
    };
    if names.len() > MAX_FILTERS {
        return None;
    }
    let params: Vec<Option<Dict>> = match dict.get(b"DecodeParms") {
        None | Some(Object::Null) => Vec::new(),
        Some(Object::Dict(params)) => vec![Some(params.clone())],
        Some(Object::Array(items)) => items
            .iter()
            .take(names.len())
            .map(|item| match &*store.deref(item).ok()? {
                Object::Null => Some(None),
                Object::Dict(params) => Some(Some(params.clone())),
                _ => None,
            })
            .collect::<Option<_>>()?,
        Some(_) => return None,
    };
    let mut out = Vec::with_capacity(names.len());
    for (index, name) in names.iter().enumerate() {
        let params = params.get(index).cloned().flatten();
        let filter = match name.as_slice() {
            b"FlateDecode" | b"Fl" => Filter::Flate,
            b"ASCIIHexDecode" | b"AHx" => Filter::AsciiHex,
            b"ASCII85Decode" | b"A85" => Filter::Ascii85,
            b"Crypt" => {
                let identity = params
                    .as_ref()
                    .and_then(|p| p.get(b"Name"))
                    .is_none_or(|n| n.is_name(b"Identity"));
                if !identity {
                    return None;
                }
                Filter::Identity
            }
            _ => return None,
        };
        out.push((filter, params));
    }
    Some(out)
}

/// The value of a hexadecimal digit.
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// ASCIIHexDecode as pyHanko's `ASCIIHexDecode.decode` (§7.4.2): digits and white-space up to the
/// first `>` (required), an odd final digit followed by 0.
fn ascii_hex(data: &[u8]) -> Option<Vec<u8>> {
    let end = data.iter().position(|&b| b == b'>')?;
    let mut out = Vec::with_capacity(end / 2 + 1);
    let mut high: Option<u8> = None;
    for &byte in data.get(..end)? {
        if is_python_space(byte) {
            continue;
        }
        let digit = hex_digit(byte)?;
        match high.take() {
            Some(h) => out.push(h << 4 | digit),
            None => high = Some(digit),
        }
    }
    if let Some(h) = high {
        out.push(h << 4);
    }
    Some(out)
}

/// The powers of 85 of an ASCII85 group (pyHanko's `POWS`).
const POWS: [u64; 5] = [85 * 85 * 85 * 85, 85 * 85 * 85, 85 * 85, 85, 1];

/// ASCII85Decode as pyHanko's `ASCII85Decode.decode` (§7.4.3): groups of `!`–`u` (`z` for four
/// zeros at the start of a group) and white-space up to the first `~>` (required); a final group
/// of 2 to 4 characters is decoded as pyHanko does (its value plus the last power used, the first
/// `n − 1` bytes kept); a group whose value does not fit in 32 bits is refused, as `struct.pack`
/// refuses it there.
fn ascii85(data: &[u8]) -> Option<Vec<u8>> {
    let end = data.windows(2).position(|w| w == b"~>")?;
    let digits: Vec<u8> = data
        .get(..end)?
        .iter()
        .copied()
        .filter(|&b| !is_python_space(b))
        .collect();
    let mut out = Vec::with_capacity(digits.len() / 5 * 4 + 4);
    let mut at = 0usize;
    while let Some(&first) = digits.get(at) {
        if first == b'z' {
            out.extend_from_slice(&[0, 0, 0, 0]);
            at += 1;
            continue;
        }
        let group = digits.get(at..(at + 5).min(digits.len()))?;
        if group.len() < 2 {
            return None; // "Nonzero ASCII85 group must have at least two digits."
        }
        let mut value: u64 = 0;
        let mut last = 1u64;
        for (&digit, &pow) in group.iter().zip(&POWS) {
            let digit = digit.checked_sub(0x21).filter(|&d| d < 85)?;
            value += u64::from(digit) * pow;
            last = pow;
        }
        if group.len() < 5 {
            value += last;
        }
        let value = u32::try_from(value).ok()?;
        let bytes = value.to_be_bytes();
        out.extend_from_slice(bytes.get(..group.len() - 1)?);
        at += group.len();
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use folioxide_syntax::OpenOptions;

    fn store() -> Store {
        Store::open_bytes(
            folioxide_testkit::fixtures::syntax::minimal(),
            &OpenOptions::default(),
        )
        .unwrap()
    }

    fn stream(dict: &str, data: &[u8]) -> Stream {
        let dict = folioxide_syntax::parse_object(dict.as_bytes(), 0, &Default::default())
            .unwrap()
            .0
            .as_dict()
            .unwrap()
            .clone();
        let mut dict = dict;
        dict.insert("Length", Object::Int(data.len() as i64));
        Stream {
            dict,
            data: StreamData::Encoded(data.to_vec()),
        }
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        miniz_oxide::deflate::compress_to_vec_zlib(data, 6)
    }

    #[test]
    fn flate_is_decoded_as_python_zlib_decompress() {
        let s = store();
        let packet = b"<x:xmpmeta xmlns:x='adobe:ns:meta/'/>";
        let good = zlib(packet);
        let flate = |data: &[u8]| decode(&s, &stream("<< /Filter /FlateDecode >>", data), 1 << 20);
        assert_eq!(flate(&good).as_deref(), Some(&packet[..]));
        // Trailing data, and a second stream, are ignored (Python: the first stream only).
        let mut trailing = good.clone();
        trailing.extend_from_slice(b"garbage");
        assert_eq!(flate(&trailing).as_deref(), Some(&packet[..]));
        let mut two = good.clone();
        two.extend(zlib(b"second"));
        assert_eq!(flate(&two).as_deref(), Some(&packet[..]));
        // Refused: a wrong Adler-32, a stream cut before it, raw deflate without a header.
        let mut bad_adler = good.clone();
        *bad_adler.last_mut().unwrap() ^= 1;
        assert_eq!(flate(&bad_adler), None);
        assert_eq!(flate(&good[..good.len() - 4]), None);
        assert_eq!(flate(&good[2..good.len() - 4]), None);
        // /Fl is FlateDecode; /Predictor other than 1 is refused.
        let fl = decode(&s, &stream("<< /Filter /Fl >>", &good), 1 << 20);
        assert_eq!(fl.as_deref(), Some(&packet[..]));
        for params in [
            "<< /Predictor 2 /Columns 1 >>",
            "<< /Predictor 12 /Columns 1 >>",
        ] {
            let dict = format!("<< /Filter /FlateDecode /DecodeParms {params} >>");
            assert_eq!(decode(&s, &stream(&dict, &good), 1 << 20), None, "{params}");
        }
        let one = "<< /Filter /FlateDecode /DecodeParms << /Predictor 1 >> >>";
        assert!(decode(&s, &stream(one, &good), 1 << 20).is_some());
        // The cap.
        assert_eq!(
            decode(&s, &stream("<< /Filter /FlateDecode >>", &good), 8),
            None
        );
    }

    #[test]
    fn other_filters_are_not_decoded() {
        let s = store();
        for filter in [
            "/LZWDecode",
            "/RunLengthDecode",
            "/DCTDecode",
            "/Foo",
            "[/FlateDecode /LZWDecode]",
            "1",
        ] {
            let dict = format!("<< /Filter {filter} >>");
            assert_eq!(
                decode(&s, &stream(&dict, b"abc"), 1 << 20),
                None,
                "{filter}"
            );
        }
        let crypt = "<< /Filter /Crypt /DecodeParms << /Name /Identity >> >>";
        assert_eq!(
            decode(&s, &stream(crypt, b"abc"), 1 << 20).as_deref(),
            Some(&b"abc"[..])
        );
        let crypt = "<< /Filter /Crypt /DecodeParms << /Name /StdCF >> >>";
        assert_eq!(decode(&s, &stream(crypt, b"abc"), 1 << 20), None);
        // No filter, and a /Length that is not the data's.
        assert_eq!(
            decode(&s, &stream("<< >>", b"abc"), 1 << 20).as_deref(),
            Some(&b"abc"[..])
        );
        let mut wrong = stream("<< >>", b"abc");
        wrong.dict.insert("Length", Object::Int(2));
        assert_eq!(decode(&s, &wrong, 1 << 20), None);
        assert_eq!(
            decode(&s, &stream("<< /F (x.xml) >>", b"abc"), 1 << 20),
            None
        );
    }

    #[test]
    fn flate_then_ascii_filter_is_not_decoded() {
        // pyHanko: FlateDecode returns a memoryview, and ASCIIHexDecode / ASCII85Decode call
        // `data.split` on it (AttributeError), so the chain does not decode (QA round 4,
        // finding 11: variants R4w-dec-flate-then-ahx, -then-a85, -crypt-ahx, -flate-ahx).
        let s = store();
        let packet = b"<x:xmpmeta xmlns:x='adobe:ns:meta/'/>";
        let hex: Vec<u8> = packet
            .iter()
            .flat_map(|b| format!("{b:02X}").into_bytes())
            .chain(*b">")
            .collect();
        let a85 = b"87cURDZ~>".to_vec();
        let crypt = "<< /Name /Identity >>";
        for (filter, params, data) in [
            ("[/FlateDecode /ASCIIHexDecode]", "null", zlib(&hex)),
            ("[/Fl /AHx]", "null", zlib(&hex)),
            ("[/FlateDecode /ASCII85Decode]", "null", zlib(&a85)),
            (
                "[/Fl /Crypt /AHx]",
                &format!("[null {crypt} null]"),
                zlib(&hex),
            ),
            ("[/Fl /Fl /AHx]", "null", zlib(&zlib(&hex))),
            (
                "[/FlateDecode /ASCIIHexDecode]",
                "[<< /Predictor 1 >> null]",
                zlib(&hex),
            ),
        ] {
            let dict = format!("<< /Filter {filter} /DecodeParms {params} >>");
            assert_eq!(decode(&s, &stream(&dict, &data), 1 << 20), None, "{dict}");
        }
        // The controls pyHanko decodes: an ASCII filter first, and Flate after Flate.
        let hex_then_flate: Vec<u8> = zlib(packet)
            .iter()
            .flat_map(|b| format!("{b:02X}").into_bytes())
            .chain(*b">")
            .collect();
        let controls = [
            ("[/AHx /Fl]", hex_then_flate.clone()),
            ("[/AHx /Fl /Fl]", {
                let twice = zlib(&zlib(packet));
                twice
                    .iter()
                    .flat_map(|b| format!("{b:02X}").into_bytes())
                    .chain(*b">")
                    .collect()
            }),
            ("[/Fl /Fl]", zlib(&zlib(packet))),
            ("[/Crypt /AHx /Fl]", hex_then_flate),
        ];
        for (filter, data) in controls {
            let dict = format!("<< /Filter {filter} >>");
            assert_eq!(
                decode(&s, &stream(&dict, &data), 1 << 20).as_deref(),
                Some(&packet[..]),
                "{filter}"
            );
        }
        // ASCII85 then ASCIIHex: both return bytes in pyHanko. `1cRBN4o~>` is `4865>`.
        let decoded = decode(
            &s,
            &stream("<< /Filter [/A85 /AHx] >>", b"1cRBN4o~>"),
            1 << 20,
        );
        assert_eq!(decoded.as_deref(), Some(&b"He"[..]));
    }

    #[test]
    fn ascii_hex_needs_its_end_marker() {
        assert_eq!(
            ascii_hex(b"48 65\n6C6C 6F>").as_deref(),
            Some(&b"Hello"[..])
        );
        assert_eq!(ascii_hex(b"4>trailing").as_deref(), Some(&[0x40][..]));
        assert_eq!(ascii_hex(b"4865"), None, "no EOD");
        assert_eq!(ascii_hex(b"48X65>"), None, "not a digit");
        assert_eq!(
            ascii_hex(b"48\x0065>"),
            None,
            "NUL is no Python white-space"
        );
    }

    #[test]
    fn ascii85_is_decoded_as_pyhanko_decodes_it() {
        // "Hello" is `87cURDZ` in ASCII85.
        assert_eq!(ascii85(b"87cUR DZ~>").as_deref(), Some(&b"Hello"[..]));
        assert_eq!(ascii85(b"z~>").as_deref(), Some(&[0, 0, 0, 0][..]));
        assert_eq!(ascii85(b"87cURDZ"), None, "no EOD");
        assert_eq!(
            ascii85(b"<~87cURDZ~>"),
            None,
            "a <~ prefix is data to pyHanko, and ~ no digit"
        );
        assert_eq!(ascii85(b"87cURD~>"), None, "a final group of one character");
        assert_eq!(ascii85(b"87zURDZ~>"), None, "z inside a group");
        assert_eq!(ascii85(b"uuuuu~>"), None, "more than 32 bits");
        assert_eq!(ascii85(b"87cv~>"), None, "v is no digit");
    }
}

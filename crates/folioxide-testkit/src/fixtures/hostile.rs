//! Hostile files for resource-exhaustion tests: small inputs built to make a reader do far more
//! work, or hold far more memory, than their size justifies (ARCHITECTURE §A.9 layer 3; the M1
//! QA robustness findings). Their size knobs let a test scale them up until a regression would
//! take minutes or gigabytes; those scaled-up files are generated at test time and never
//! committed. The small instances of [`seeds`] are also committed under `fixtures/hostile/` by
//! `cargo xtask fixtures` (checked with `--check`, like `fixtures/syntax/`), so the fuzz corpora
//! (the nightly fuzz workflow seeds from `fixtures/`) start from every hostile shape.
//!
//! Every file is a readable one-page document, objects 1–5 as in [`super::syntax`] (catalog,
//! page tree, page, content stream showing [`TEXT`], font), plus the hostile part. A test can
//! therefore check both that the reader stays within its budget and that it still reads the
//! document. The hostile parts claim object numbers from [`CLAIM_START`] up, so the readable
//! objects keep their numbers.
//!
//! | Generator | Hostile part | Reader path |
//! |---|---|---|
//! | [`xref_stream_chain`] | cross-reference streams chained by `/Prev`, each claiming many rows from a few bytes of Flate data | `/Prev` chain, xref-stream rows |
//! | [`overlapping_xref_streams`] | uncompressed cross-reference streams whose `/Length` all reach the end of one shared tail | `/Prev` chain, section parsing |
//! | [`huge_index`] | one cross-reference stream whose `/Index` claims up to 2^32 rows | xref-stream rows, object cap |
//! | [`many_subsections`] | one cross-reference stream with thousands of `/Index` pairs, optionally all overlapping | xref-stream rows |
//! | [`objstm_bombs`] | no cross-reference data; object streams that each decode to megabytes of zeros | full reconstruction (object-stream member lists) |
//! | [`objstm_cache_bombs`] | the same object streams, listed by a cross-reference stream | resolving compressed objects (the decoded-container cache) |
//! | [`objstm_header_pairs`] | an object stream whose header lists millions of `number offset` pairs, all at offset 0 | the member table of a container |
//! | [`objstm_big_array`] | an object stream holding one array of millions of `0` | the objects parsed from a container |
//! | [`unterminated_trailers`] | no cross-reference data; many `trailer` dictionaries whose strings never end | full reconstruction (trailer search) |
//!
//! [`zlib_zeros`] builds the Flate data: a valid zlib stream for a prefix followed by any number
//! of zero bytes, written directly in a fraction of a millisecond per megabyte (1,032 decoded
//! bytes per encoded byte, the most Deflate allows), so a test can make a gigabyte bomb without
//! compressing a gigabyte.
//!
//! ```
//! use folioxide_syntax::{OpenOptions, Store};
//! use folioxide_testkit::fixtures::hostile;
//!
//! for (name, pdf) in hostile::seeds() {
//!     let store = Store::open_bytes(pdf, &OpenOptions::default()).unwrap();
//!     assert!(store.root_id().is_some(), "{name}");
//! }
//! ```

use folioxide_syntax::ObjectId;
use folioxide_syntax::filters::encode_flate;

use super::syntax::one_page;
use crate::builder::{PdfBuilder, XrefEntry, XrefOpts, XrefStreamOpts};

/// The text the content stream (object 4) of every hostile file shows.
pub const TEXT: &str = "hostile";

/// The first object number that hostile parts claim; objects below it are the readable document
/// and the hostile objects themselves.
pub const CLAIM_START: u32 = 1000;

/// Object number of the first hostile object (cross-reference stream or object stream); the
/// next ones follow.
const FIRST_HOSTILE: u32 = 6;

/// The width of each stream header in [`overlapping_xref_streams`] (`N 0 obj` to `stream` EOL).
const OVERLAP_HEADER: usize = 160;

/// One small instance of a generator ([`seeds`]), committed as `fixtures/hostile/<name>.pdf`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct SeedInfo {
    /// The name, `hostile-<shape>`; the committed file is `fixtures/hostile/<name>.pdf`. The
    /// prefix keeps the names distinct from the syntax fixtures when a fuzz corpus collects
    /// both in one directory.
    pub name: &'static str,
    /// The generator call and the hostile shape it makes.
    pub description: &'static str,
    /// The generator.
    pub generate: fn() -> Vec<u8>,
}

/// The seeds, in the order of [`seeds`].
const SEEDS: &[SeedInfo] = &[
    SeedInfo {
        name: "hostile-xref-stream-chain",
        description: "`xref_stream_chain(8, 64)`: 8 cross-reference streams chained by /Prev, \
                      each claiming 64 rows from a few bytes of Flate data",
        generate: || xref_stream_chain(8, 64),
    },
    SeedInfo {
        name: "hostile-overlapping-xref-streams",
        description: "`overlapping_xref_streams(8, 256)`: 8 uncompressed cross-reference \
                      streams whose /Length all reach the end of one 256-byte tail",
        generate: || overlapping_xref_streams(8, 256),
    },
    SeedInfo {
        name: "hostile-huge-index",
        description: "`huge_index(4294967295, 16)`: a cross-reference stream whose /Index claims \
                      2^32 - 1 rows over 16 rows of data",
        generate: || huge_index(u64::from(u32::MAX), 16),
    },
    SeedInfo {
        name: "hostile-many-subsections",
        description: "`many_subsections(32, 4, 0)`: a cross-reference stream with 32 /Index \
                      subsections that all claim the same 4 numbers",
        generate: || many_subsections(32, 4, 0),
    },
    SeedInfo {
        name: "hostile-objstm-bombs",
        description: "`objstm_bombs(4, 16384)`: no cross-reference data; 4 object streams that \
                      decode to 16 KiB of mostly zeros each",
        generate: || objstm_bombs(4, 16 << 10),
    },
    SeedInfo {
        name: "hostile-objstm-cache-bombs",
        description: "`objstm_cache_bombs(4, 16384)`: the same 4 object streams, listed by a \
                      cross-reference stream",
        generate: || objstm_cache_bombs(4, 16 << 10),
    },
    SeedInfo {
        name: "hostile-unterminated-trailers",
        description: "`unterminated_trailers(8, 1024)`: no cross-reference data; 8 trailer \
                      dictionaries whose strings never end, then 1 KiB of padding",
        generate: || unterminated_trailers(8, 1024),
    },
    SeedInfo {
        name: "hostile-objstm-header-pairs",
        description: "`objstm_header_pairs(5000)`: an object stream whose header lists 5,000 \
                      members, all at offset 0",
        generate: || objstm_header_pairs(5_000),
    },
    SeedInfo {
        name: "hostile-objstm-big-array",
        description: "`objstm_big_array(5000)`: an object stream holding one array of 5,000 \
                      zeros",
        generate: || objstm_big_array(5_000),
    },
];

/// Small instances of every generator, for mutation bases and fuzz seeds: each one has the
/// hostile shape (a chain, overlapping sections, an outsized `/Index`, bombs, unterminated
/// trailers, an object-stream header of many pairs, a huge array in an object stream) at a size
/// that reads in about a millisecond, so mutations and fuzzing explore around it quickly. Tests
/// scale the generators up themselves. [`seed_infos`] describes them; `cargo xtask fixtures`
/// commits them as `fixtures/hostile/<name>.pdf`.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    SEEDS
        .iter()
        .map(|info| (info.name, (info.generate)()))
        .collect()
}

/// Descriptions of the [`seeds`], in the same order.
pub fn seed_infos() -> &'static [SeedInfo] {
    SEEDS
}

/// The path of the committed seed `name`: `<workspace>/fixtures/hostile/<name>.pdf`.
pub fn committed_path(name: &str) -> std::path::PathBuf {
    super::fixtures_dir()
        .join("hostile")
        .join(format!("{name}.pdf"))
}

/// Reads the committed seed `name` (byte for byte what [`seeds`] generates, as long as
/// `cargo xtask fixtures --check` passes).
///
/// # Errors
/// Any I/O error, for example when the file was never generated (`cargo xtask fixtures`).
pub fn read_committed(name: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(committed_path(name))
}

// ---------------------------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------------------------

/// The readable document with its cross-reference table, trailer, `startxref` and `%%EOF`.
/// Returns the table's offset, for a `/Prev`.
fn base(b: &mut PdfBuilder) -> u64 {
    b.header("1.5");
    one_page(b, TEXT);
    b.xref_table(XrefOpts::default());
    let table = b.last_xref_offset().unwrap_or(0);
    let trailer = format!("/Size {} /Root 1 0 R", b.size());
    b.trailer(trailer).startxref(None).eof();
    table
}

/// The readable document, then `sections` cross-reference streams chained by `/Prev` (the last
/// one is where `startxref` points). Each one claims `rows` in-use objects from
/// [`CLAIM_START`] (`/W [0 1 0]`: type 1 and generation 0 by default, offset 0) with
/// `rows / 1032` bytes of Flate data.
///
/// A reader that merges every section reads `sections × rows` rows: 500 sections of 100,000
/// rows are 50 million rows from a 170 KB file.
pub fn xref_stream_chain(sections: u32, rows: u32) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    let mut prev = base(&mut b);
    let data = zlib_zeros(b"", u64::from(rows));
    for k in 0..sections {
        let at = b.position();
        let dict = format!(
            "/Type /XRef /Size {} /W [0 1 0] /Index [{CLAIM_START} {rows}] /Filter /FlateDecode \
             /Root 1 0 R /Prev {prev}",
            u64::from(CLAIM_START) + u64::from(rows),
        );
        b.stream_obj(FIRST_HOSTILE.saturating_add(k), 0, dict, &data, None);
        b.startxref(Some(at)).eof();
        prev = at;
    }
    b.into_bytes()
}

/// The readable document, then `sections` uncompressed cross-reference streams written back to
/// back, followed by `tail` zero bytes. Every stream's `/Length` reaches the end of the tail, so
/// its data is all the stream headers after it plus the whole tail; each one claims `tail`
/// objects from [`CLAIM_START`] (`/W [0 1 0]`) and points `/Prev` at the one before it.
///
/// A reader that parses each section on its own reads about `sections² / 2` headers plus
/// `sections × tail` bytes: 400 sections and a 200 KB tail are about 90 MB of parsing from a
/// 260 KB file.
pub fn overlapping_xref_streams(sections: u32, tail: u32) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    let table = base(&mut b);
    let first = b.position();
    let width = OVERLAP_HEADER as u64;
    let count = u64::from(sections);
    for k in 0..count {
        let at = first + k * width;
        let prev = if k == 0 { table } else { at - width };
        let length = (count - k - 1) * width + u64::from(tail);
        // Fixed-width numbers, so every header has the same length before padding.
        let mut header = format!(
            "{} 0 obj\n<< /Type /XRef /Size {} /W [0 1 0] /Index [{CLAIM_START} {tail}] \
             /Root 1 0 R /Prev {prev:010} /Length {length:010} >>",
            u64::from(FIRST_HOSTILE) + k,
            u64::from(CLAIM_START) + u64::from(tail),
        )
        .into_bytes();
        let end = b"\nstream\n";
        header.resize(
            OVERLAP_HEADER.saturating_sub(end.len()).max(header.len()),
            b' ',
        );
        header.extend_from_slice(end);
        b.raw(header);
    }
    let tail_len = usize::try_from(tail).unwrap_or(usize::MAX);
    b.raw(vec![0u8; tail_len]).raw(b"\nendstream\nendobj\n");
    let last = first + count.saturating_sub(1) * width;
    b.startxref(Some(if count == 0 { table } else { last }))
        .eof();
    b.into_bytes()
}

/// The readable document, then one cross-reference stream whose `/Index` is
/// `[CLAIM_START claimed]` (`/W [0 1 0]`) and whose data is `rows` zero rows. With
/// `claimed > rows` the stream claims far more rows than it holds (`claimed` may be up to
/// 2^32 - 1); with `claimed == rows` it really lists them, from `rows / 1032` bytes.
pub fn huge_index(claimed: u64, rows: u64) -> Vec<u8> {
    let index = format!("{CLAIM_START} {claimed}");
    xref_stream_with_index(&index, u64::from(CLAIM_START) + claimed, rows)
}

/// The readable document, then one cross-reference stream with `pairs` `/Index` subsections of
/// `count` rows each, starting at [`CLAIM_START`] and `stride` numbers apart (a stride of 0
/// makes them all claim the same numbers), and `pairs × count` zero rows of data (`/W [0 1 0]`).
pub fn many_subsections(pairs: u32, count: u32, stride: u32) -> Vec<u8> {
    let mut index = String::new();
    for i in 0..u64::from(pairs) {
        if i > 0 {
            index.push(' ');
        }
        let start = u64::from(CLAIM_START) + i * u64::from(stride);
        index.push_str(&format!("{start} {count}"));
    }
    let size = u64::from(CLAIM_START) + u64::from(pairs) * u64::from(stride.max(1)) + 1;
    xref_stream_with_index(&index, size, u64::from(pairs) * u64::from(count))
}

/// [`huge_index`] and [`many_subsections`]: the readable document, then one compressed
/// cross-reference stream with the given `/Index` text and `rows` zero rows, `/Prev` pointing
/// at the table.
fn xref_stream_with_index(index: &str, size: u64, rows: u64) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    let table = base(&mut b);
    let at = b.position();
    let dict = format!(
        "/Type /XRef /Size {size} /W [0 1 0] /Index [{index}] /Filter /FlateDecode /Root 1 0 R \
         /Prev {table}"
    );
    b.stream_obj(FIRST_HOSTILE, 0, dict, &zlib_zeros(b"", rows), None);
    b.startxref(Some(at)).eof();
    b.into_bytes()
}

/// The readable document without any cross-reference data (so a reader must reconstruct it),
/// then `containers` object streams. Object stream `k` holds one object, number
/// `CLAIM_START + k` (the string `(member k)`), followed by zero bytes up to `decoded` bytes in
/// all; it is Flate-compressed to about `decoded / 1032` bytes. The file ends with a
/// `trailer` that names the catalog, and `%%EOF`.
///
/// A reconstruction that decodes every container to list its members decodes
/// `containers × decoded` bytes, and keeps them if it caches the containers: 40 containers of
/// 64 MiB are 2.5 GiB from a 2.6 MB file.
pub fn objstm_bombs(containers: u32, decoded: u64) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.5");
    one_page(&mut b, TEXT);
    for k in 0..containers {
        bomb_container(&mut b, k, decoded);
    }
    let size = CLAIM_START.saturating_add(containers);
    b.trailer(format!("/Size {size} /Root 1 0 R")).eof();
    b.into_bytes()
}

/// The readable document, then `containers` object streams as in [`objstm_bombs`] (object
/// `CLAIM_START + k`, the string `(member k)`, in container `k`, then zeros up to `decoded`
/// bytes), all listed by a cross-reference stream (type 2 entries, §7.5.8.3), so resolving
/// object `CLAIM_START + k` decodes container `k`.
///
/// A store that keeps every decoded container holds `containers × decoded` bytes once their
/// objects are resolved: 10 containers of 400 MiB are 4 GiB from a 4 MB file, within the
/// default `max_total_decoded`.
pub fn objstm_cache_bombs(containers: u32, decoded: u64) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.5");
    one_page(&mut b, TEXT);
    let mut opts = XrefStreamOpts::new().with_trailer("/Root 1 0 R");
    for k in 0..containers {
        let stream = bomb_container(&mut b, k, decoded);
        opts = opts.with_entry(
            CLAIM_START.saturating_add(k),
            XrefEntry::Compressed { stream, index: 0 },
        );
    }
    b.xref_stream(FIRST_HOSTILE.saturating_add(containers), opts);
    b.startxref(None).eof();
    b.into_bytes()
}

/// Writes object stream `FIRST_HOSTILE + k` holding object `CLAIM_START + k` (`(member k)`)
/// followed by zeros up to `decoded` bytes, and returns its object number.
fn bomb_container(b: &mut PdfBuilder, k: u32, decoded: u64) -> u32 {
    let member = CLAIM_START.saturating_add(k);
    let header = format!("{member} 0\n");
    let mut prefix = header.clone().into_bytes();
    prefix.extend_from_slice(format!("(member {k})").as_bytes());
    let zeros = decoded.saturating_sub(prefix.len() as u64);
    let dict = format!(
        "/Type /ObjStm /N 1 /First {} /Filter /FlateDecode",
        header.len()
    );
    let num = FIRST_HOSTILE.saturating_add(k);
    b.stream_obj(num, 0, dict, &zlib_zeros(&prefix, zeros), None);
    num
}

/// The readable document, then object stream `6` whose header lists `pairs` members, all at
/// offset 0 (`/N` = `pairs`): object [`CLAIM_START`] first, then object 1 in the shortest pair
/// there is (`1 0 `, four bytes) for the rest; followed by the string `(member)`,
/// Flate-compressed (about 600 decoded bytes per encoded byte). A cross-reference stream lists
/// `CLAIM_START` as entry 0 of the container, so resolving it decodes the container.
///
/// A reader that keeps a table entry per header pair builds `pairs` of them from `4 × pairs`
/// decoded bytes: 8 million pairs are 32 MB decoded from a file of about 55 KB, and at 48 bytes
/// per entry 380 MB of tables (M1 QA round 2 measured 14 bytes of memory per decoded byte).
pub fn objstm_header_pairs(pairs: u32) -> Vec<u8> {
    let mut data = Vec::new();
    if pairs > 0 {
        data.extend_from_slice(format!("{CLAIM_START} 0 ").as_bytes());
        let rest = usize::try_from(pairs - 1).unwrap_or(0);
        data.extend_from_slice(&b"1 0 ".repeat(rest));
    }
    let first = data.len();
    data.extend_from_slice(b"(member)");
    one_container(pairs, first, &data)
}

/// The decoded length of the object stream of [`objstm_header_pairs`]`(pairs)`.
pub fn objstm_header_pairs_decoded(pairs: u32) -> u64 {
    let header = match pairs {
        0 => 0,
        _ => format!("{CLAIM_START} 0 ").len() as u64 + 4 * (u64::from(pairs) - 1),
    };
    header + "(member)".len() as u64
}

/// The readable document, then object stream `6` holding one object, [`CLAIM_START`]: an array
/// of `elements` zeros (`[0 0 0 ... ]`, two decoded bytes per element), Flate-compressed (about
/// 600 decoded bytes per encoded byte) and listed by a cross-reference stream.
///
/// A reader that builds every element of the array keeps one object per two decoded bytes: 25
/// million elements are 50 MB decoded from a file of about 90 KB, and gigabytes of objects.
pub fn objstm_big_array(elements: u32) -> Vec<u8> {
    let header = format!("{CLAIM_START} 0\n");
    let mut data = header.clone().into_bytes();
    data.push(b'[');
    data.extend_from_slice(&b"0 ".repeat(usize::try_from(elements).unwrap_or(0)));
    data.push(b']');
    one_container(1, header.len(), &data)
}

/// The readable document, then object stream `6` with decoded `data` (`/N` `n`, `/First`
/// `first`), and a cross-reference stream that lists the container and [`CLAIM_START`] as its
/// entry 0.
fn one_container(n: u32, first: usize, data: &[u8]) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.5");
    one_page(&mut b, TEXT);
    let dict = format!("/Type /ObjStm /N {n} /First {first} /Filter /FlateDecode");
    b.stream_obj(FIRST_HOSTILE, 0, dict, &encode_flate(data, 6), None);
    let opts = XrefStreamOpts::new()
        .with_trailer("/Root 1 0 R")
        .with_entry(
            CLAIM_START,
            XrefEntry::Compressed {
                stream: FIRST_HOSTILE,
                index: 0,
            },
        );
    b.xref_stream(FIRST_HOSTILE.saturating_add(1), opts);
    b.startxref(None).eof();
    b.into_bytes()
}

/// The readable document without any cross-reference data, a usable `trailer` naming the
/// catalog, then `count` `trailer` dictionaries whose string never ends, then `padding` bytes of
/// `x`.
///
/// A reader that parses each trailer candidate to the end of the file reads
/// `count × padding` bytes.
pub fn unterminated_trailers(count: u32, padding: usize) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.5");
    one_page(&mut b, TEXT);
    b.trailer("/Size 6 /Root 1 0 R");
    for _ in 0..count {
        b.raw(b"trailer\n<< /Size 6 /Info (unterminated\n");
    }
    b.raw(vec![b'x'; padding]);
    b.into_bytes()
}

/// The object identifier of a hostile file's catalog.
pub const ROOT: ObjectId = ObjectId::new(1, 0);

// ---------------------------------------------------------------------------------------------
// Flate bombs
// ---------------------------------------------------------------------------------------------

/// A zlib stream (RFC 1950, as `/FlateDecode` reads it) that decodes to `prefix` followed by
/// `zeros` zero bytes, with a correct Adler-32 checksum.
///
/// The prefix is stored uncompressed; the zeros are one Deflate block (RFC 1951 §3.2.7) whose
/// dynamic Huffman code gives a length-258, distance-1 match two bits, so the output is about
/// `prefix.len() + zeros / 1032` bytes and is written without ever holding the zeros.
///
/// ```
/// use folioxide_syntax::filters::{DecodeLimits, Filter, FilterParams, decode};
/// use folioxide_testkit::fixtures::hostile::zlib_zeros;
///
/// let data = zlib_zeros(b"head", 1 << 20);
/// assert!(data.len() < 1100, "{}", data.len());
/// let out = decode(Filter::Flate, &data, &FilterParams::new(), &DecodeLimits::default()).unwrap();
/// assert!(!out.truncated);
/// assert_eq!(out.data.len(), 4 + (1 << 20));
/// assert!(out.data.starts_with(b"head") && out.data[4..].iter().all(|&b| b == 0));
/// ```
pub fn zlib_zeros(prefix: &[u8], zeros: u64) -> Vec<u8> {
    let mut bits = BitWriter::default();
    // CMF: Deflate with a 32 KiB window; FLG: no dictionary, check bits make 0x7801 % 31 == 0.
    bits.out.extend_from_slice(&[0x78, 0x01]);
    for chunk in prefix.chunks(usize::from(u16::MAX)) {
        // A stored block that is never the last one (BFINAL 0, BTYPE 00).
        bits.put(0, 3);
        bits.align();
        let len = u16::try_from(chunk.len()).unwrap_or(u16::MAX);
        bits.out.extend_from_slice(&len.to_le_bytes());
        bits.out.extend_from_slice(&(!len).to_le_bytes());
        bits.out.extend_from_slice(chunk);
    }
    if zeros == 0 {
        // The last block: stored and empty.
        bits.put(1, 3);
        bits.align();
        bits.out.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);
    } else {
        zero_block(&mut bits, zeros);
        bits.align();
    }
    let adler = adler32_zeros(adler32(prefix), zeros);
    bits.out.extend_from_slice(&adler.to_be_bytes());
    bits.out
}

/// Writes the last Deflate block: a literal zero, then length-258 distance-1 matches, then
/// literal zeros for the rest, with this dynamic Huffman code:
///
/// - literal/length codes: `0` (literal zero) `10`, `256` (end of block) `11`, `285` (length
///   258) `0`; distance code `0` (distance 1) `0`;
/// - code-length codes: `1` `10`, `2` `11`, `18` (a run of 11–138 zero lengths) `0`.
fn zero_block(bits: &mut BitWriter, zeros: u64) {
    // BFINAL 1, BTYPE 10 (dynamic Huffman).
    bits.put(1, 1);
    bits.put(2, 2);
    // HLIT: 286 literal/length codes (up to 285); HDIST: 1 distance code; HCLEN: 18 code-length
    // code lengths, in the order of RFC 1951 §3.2.7 (up to the one for length 1).
    bits.put(286 - 257, 5);
    bits.put(0, 5);
    bits.put(18 - 4, 4);
    const ORDER: [u8; 18] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1];
    for symbol in ORDER {
        let length = match symbol {
            18 => 1,
            1 | 2 => 2,
            _ => 0,
        };
        bits.put(length, 3);
    }
    // The 286 + 1 code lengths: 0 → 2, 1–255 → 0, 256 → 2, 257–284 → 0, 285 → 1, distance 0 → 1.
    let (one, two) = (
        |b: &mut BitWriter| b.code(0b10, 2),
        |b: &mut BitWriter| b.code(0b11, 2),
    );
    let zero_run = |b: &mut BitWriter, run: u64| {
        b.code(0, 1);
        b.put(run - 11, 7);
    };
    two(bits);
    zero_run(bits, 138);
    zero_run(bits, 117);
    two(bits);
    zero_run(bits, 28);
    one(bits);
    one(bits);
    // The data.
    let literal_zero = |b: &mut BitWriter| b.code(0b10, 2);
    literal_zero(bits);
    let rest = zeros - 1;
    // Each match is two zero bits (length code `0`, distance code `0`).
    bits.zero_bits((rest / 258) * 2);
    for _ in 0..rest % 258 {
        literal_zero(bits);
    }
    bits.code(0b11, 2);
}

/// Deflate's bit order: values least significant bit first, Huffman codes most significant bit
/// first (RFC 1951 §3.1.1).
#[derive(Default)]
struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    filled: u32,
}

impl BitWriter {
    /// Appends the low `count` bits of `value` (at most 32), least significant first.
    fn put(&mut self, value: u64, count: u32) {
        self.acc |= (value & ((1 << count) - 1)) << self.filled;
        self.filled += count;
        while self.filled >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.filled -= 8;
        }
    }

    /// Appends a Huffman code of `length` bits, most significant first.
    fn code(&mut self, code: u64, length: u32) {
        let mut reversed = 0;
        for i in 0..length {
            reversed |= ((code >> i) & 1) << (length - 1 - i);
        }
        self.put(reversed, length);
    }

    /// Appends `count` zero bits, whole bytes at a time.
    fn zero_bits(&mut self, count: u64) {
        let mut count = count;
        while count > 0 && self.filled != 0 {
            self.put(0, 1);
            count -= 1;
        }
        let bytes = usize::try_from(count / 8).unwrap_or(usize::MAX);
        self.out.resize(self.out.len().saturating_add(bytes), 0);
        self.put(0, (count % 8) as u32);
    }

    /// Pads to a byte boundary with zero bits.
    fn align(&mut self) {
        if self.filled > 0 {
            self.put(0, 8 - self.filled);
        }
    }
}

/// The Adler-32 modulus (RFC 1950 §8.2).
const ADLER_MOD: u64 = 65521;

/// Adler-32 of `data`.
fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u64, 0u64);
    for &byte in data {
        a = (a + u64::from(byte)) % ADLER_MOD;
        b = (b + a) % ADLER_MOD;
    }
    ((b << 16) | a) as u32
}

/// Extends the Adler-32 `adler` with `zeros` zero bytes: `a` stays, `b` grows by `zeros × a`.
fn adler32_zeros(adler: u32, zeros: u64) -> u32 {
    let a = u64::from(adler & 0xFFFF);
    let b = u64::from(adler >> 16);
    let b = (b + (zeros % ADLER_MOD) * a) % ADLER_MOD;
    ((b << 16) | a) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use folioxide_syntax::filters::{DecodeLimits, Filter, FilterParams, decode, encode_flate};
    use folioxide_syntax::{Object, OpenOptions, Store, Strictness};

    fn inflate(data: &[u8]) -> Vec<u8> {
        let out = decode(
            Filter::Flate,
            data,
            &FilterParams::new(),
            &DecodeLimits::default(),
        )
        .unwrap();
        assert!(!out.truncated);
        out.data
    }

    #[test]
    fn zlib_zeros_round_trips() {
        for prefix in [&b""[..], b"x", b"12 0\n(member)", &[7u8; 70_000]] {
            for zeros in [0u64, 1, 2, 257, 258, 259, 516, 1000, 65_536, 1 << 20] {
                let data = zlib_zeros(prefix, zeros);
                let mut expected = prefix.to_vec();
                expected.resize(prefix.len() + zeros as usize, 0);
                assert!(
                    inflate(&data) == expected,
                    "prefix {} + {zeros} zeros",
                    prefix.len()
                );
            }
        }
        // The checksum is the real one: the same bytes compressed by miniz_oxide end with it.
        let reference = encode_flate(&[0u8; 5000], 6);
        assert_eq!(
            zlib_zeros(b"", 5000)[zlib_zeros(b"", 5000).len() - 4..],
            reference[reference.len() - 4..]
        );
    }

    #[test]
    fn zlib_zeros_is_a_bomb() {
        // A gigabyte in about a megabyte, written in milliseconds.
        let data = zlib_zeros(b"", 1 << 30);
        assert!(data.len() < (1 << 30) / 1000, "{}", data.len());
        let limits = DecodeLimits::new(1 << 20);
        assert!(decode(Filter::Flate, &data, &FilterParams::new(), &limits).is_err());
    }

    #[test]
    fn every_hostile_file_is_a_readable_document() {
        let mut cases = seeds();
        cases.push(("chain, no sections", xref_stream_chain(0, 10)));
        cases.push(("overlap, no sections", overlapping_xref_streams(0, 10)));
        cases.push(("no bombs", objstm_bombs(0, 0)));
        for (name, pdf) in cases {
            for strictness in [Strictness::Lenient, Strictness::Strict] {
                let options = OpenOptions::default().with_strictness(strictness);
                let store = match Store::open_bytes(pdf.clone(), &options) {
                    Ok(store) => store,
                    // Strict mode may refuse a hostile file; lenient mode never does.
                    Err(_) if strictness == Strictness::Strict => continue,
                    Err(err) => panic!("{name}: {err}"),
                };
                let catalog = store.resolve(ROOT).unwrap();
                assert!(catalog.as_dict().unwrap().is_type(b"Catalog"), "{name}");
                let content = store.resolve(ObjectId::new(4, 0)).unwrap();
                let Object::Stream(stream) = &*content else {
                    panic!("{name}: object 4 is a {}", content.type_name());
                };
                assert_eq!(
                    store.stream_data(stream).unwrap().data,
                    crate::fixtures::syntax::content(TEXT, 720),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn objstm_bombs_hold_their_members() {
        for pdf in [objstm_bombs(3, 4096), objstm_cache_bombs(3, 4096)] {
            check_bomb_members(pdf);
        }
        // Only the cache bombs are listed by cross-reference data.
        let store =
            Store::open_bytes(objstm_cache_bombs(3, 4096), &OpenOptions::default()).unwrap();
        assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
    }

    fn check_bomb_members(pdf: Vec<u8>) {
        let store = Store::open_bytes(pdf, &OpenOptions::default()).unwrap();
        for k in 0..3u32 {
            let member = store.resolve(ObjectId::new(CLAIM_START + k, 0)).unwrap();
            assert_eq!(
                member.as_str_bytes(),
                Some(format!("member {k}").as_bytes()),
                "{k}"
            );
            let container = store.resolve(ObjectId::new(FIRST_HOSTILE + k, 0)).unwrap();
            let Object::Stream(stream) = &*container else {
                panic!("{k}");
            };
            assert_eq!(store.stream_data(stream).unwrap().data.len(), 4096);
        }
    }

    #[test]
    fn seeds_are_described_and_distinct() {
        let seeds = seeds();
        assert_eq!(seeds.len(), seed_infos().len());
        let mut names = std::collections::BTreeSet::new();
        for ((name, pdf), info) in seeds.iter().zip(seed_infos()) {
            assert_eq!(*name, info.name);
            assert!(name.starts_with("hostile-"), "{name}");
            assert!(names.insert(*name), "{name} twice");
            assert!(!info.description.is_empty(), "{name}");
            // Small enough to commit (fixtures/README.md) and to read in about a millisecond.
            assert!(pdf.len() < 64 * 1024, "{name}: {} bytes", pdf.len());
            assert_eq!(*pdf, (info.generate)(), "{name} is not deterministic");
            assert!(
                read_committed(name).is_ok_and(|committed| committed == *pdf),
                "fixtures/hostile/{name}.pdf is missing or stale: run `cargo xtask fixtures`"
            );
        }
        assert!(
            committed_path("hostile-huge-index")
                .ends_with("fixtures/hostile/hostile-huge-index.pdf")
        );
    }

    #[test]
    fn object_stream_shapes_hold_their_member() {
        for pairs in [1, 2, 10] {
            let store =
                Store::open_bytes(objstm_header_pairs(pairs), &OpenOptions::default()).unwrap();
            let member = store.resolve(ObjectId::new(CLAIM_START, 0)).unwrap();
            assert_eq!(member.as_str_bytes(), Some(&b"member"[..]), "{pairs}");
            let container = store.resolve(ObjectId::new(FIRST_HOSTILE, 0)).unwrap();
            let Object::Stream(stream) = &*container else {
                panic!(
                    "{pairs}: object {FIRST_HOSTILE} is a {}",
                    container.type_name()
                );
            };
            let decoded = store.stream_data(stream).unwrap().data;
            assert_eq!(decoded.len() as u64, objstm_header_pairs_decoded(pairs));
            assert!(decoded.starts_with(format!("{CLAIM_START} 0 ").as_bytes()));
        }
        let store = Store::open_bytes(objstm_big_array(10), &OpenOptions::default()).unwrap();
        let member = store.resolve(ObjectId::new(CLAIM_START, 0)).unwrap();
        assert_eq!(member.as_array().map(<[Object]>::len), Some(10));
        assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
        // Highly compressed: a million pairs or elements take a few kilobytes.
        assert!(objstm_header_pairs(1_000_000).len() < 30_000);
        assert!(objstm_big_array(1_000_000).len() < 15_000);
    }

    #[test]
    fn overlapping_headers_have_a_fixed_width() {
        let pdf = overlapping_xref_streams(3, 100);
        let first = pdf
            .windows(b"6 0 obj".len())
            .position(|w| w == b"6 0 obj")
            .unwrap();
        for k in 0..3 {
            let at = first + k * OVERLAP_HEADER;
            let header = format!("{} 0 obj", FIRST_HOSTILE as usize + k);
            assert!(pdf[at..].starts_with(header.as_bytes()), "{k}");
            assert!(pdf[..at + OVERLAP_HEADER].ends_with(b"\nstream\n"), "{k}");
        }
    }
}

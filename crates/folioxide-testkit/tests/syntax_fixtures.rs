#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Verifies the syntax fixtures independently of the store: a small, strict cross-reference
//! reader (built only on the `folioxide-syntax` parser and filters) checks that every healthy
//! fixture is exactly what it claims to be, and that every broken one has precisely its defect.

use std::collections::{BTreeMap, BTreeSet};

use folioxide_syntax::filters::{DecodeLimits, Filter, FilterParams, decode_chain};
use folioxide_syntax::{
    DiagnosticKind, DiagnosticLog, Dict, ErrorCode, Limits, Object, ObjectId, ParseCtx, Strictness,
    parse_indirect_at, parse_object,
};
use folioxide_testkit::fixtures::syntax;

// ---------------------------------------------------------------------------------------------
// A strict mini reader
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entry {
    Free { generation: u16 },
    InUse { offset: u64, generation: u16 },
    Compressed { stream: u32, index: u32 },
}

#[derive(Debug, Default)]
struct Table {
    /// `(written start, entries)` per subsection.
    subsections: Vec<(u32, Vec<Entry>)>,
    /// The length of every entry seen (20 when conforming).
    entry_lens: BTreeSet<usize>,
    trailer: Dict,
}

fn strict() -> ParseCtx<'static> {
    ParseCtx::new(Limits::DEFAULT, Strictness::Strict)
}

fn header_offset(bytes: &[u8]) -> usize {
    bytes.windows(5).position(|w| w == b"%PDF-").unwrap()
}

fn rfind(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    bytes.windows(needle.len()).rposition(|w| w == needle)
}

fn find(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    bytes.windows(needle.len()).position(|w| w == needle)
}

fn startxref(bytes: &[u8]) -> u64 {
    let at = rfind(bytes, b"startxref").expect("startxref");
    let (value, _) = parse_object(bytes, at + 9, &strict()).unwrap();
    u64::try_from(value.as_int().unwrap()).unwrap()
}

fn digits(bytes: &[u8]) -> u64 {
    assert!(
        bytes.iter().all(u8::is_ascii_digit),
        "{:?}",
        bytes.escape_ascii().to_string()
    );
    std::str::from_utf8(bytes).unwrap().parse().unwrap()
}

/// Reads a table section at `pos`: `xref`, subsections of fixed-width entries, `trailer`.
fn read_table(bytes: &[u8], pos: usize) -> Table {
    assert_eq!(&bytes[pos..pos + 4], b"xref");
    let mut p = pos + 4;
    let skip_eol = |p: &mut usize| {
        while matches!(bytes[*p], b'\r' | b'\n') {
            *p += 1;
        }
    };
    skip_eol(&mut p);
    let mut table = Table::default();
    while !bytes[p..].starts_with(b"trailer") {
        let line_end = p + bytes[p..]
            .iter()
            .position(|&b| b == b'\r' || b == b'\n')
            .unwrap();
        let line = std::str::from_utf8(&bytes[p..line_end]).unwrap();
        let (start, count) = line.split_once(' ').unwrap();
        let (start, count): (u32, usize) = (start.parse().unwrap(), count.parse().unwrap());
        p = line_end;
        skip_eol(&mut p);
        let mut entries = Vec::new();
        for _ in 0..count {
            let field = digits(&bytes[p..p + 10]);
            assert_eq!(bytes[p + 10], b' ');
            let generation = u16::try_from(digits(&bytes[p + 11..p + 16])).unwrap();
            assert_eq!(bytes[p + 16], b' ');
            let kind = bytes[p + 17];
            let len = match &bytes[p + 18..p + 20] {
                b" \r" | b" \n" | b"\r\n" => 20,
                [b'\n' | b'\r', _] => 19,
                other => panic!("bad entry end {other:?}"),
            };
            table.entry_lens.insert(len);
            entries.push(match kind {
                b'n' => Entry::InUse {
                    offset: field,
                    generation,
                },
                b'f' => Entry::Free { generation },
                other => panic!("bad entry type {other}"),
            });
            p += len;
        }
        table.subsections.push((start, entries));
    }
    let (trailer, _) = parse_object(bytes, p + 7, &strict()).unwrap();
    table.trailer = trailer.as_dict().unwrap().clone();
    table
}

fn filter_chain(dict: &Dict) -> Vec<(Filter, FilterParams)> {
    let filters: Vec<Object> = match dict.get(b"Filter") {
        None => Vec::new(),
        Some(Object::Array(items)) => items.clone(),
        Some(other) => vec![other.clone()],
    };
    let parms: Vec<Object> = match dict.get(b"DecodeParms") {
        None => Vec::new(),
        Some(Object::Array(items)) => items.clone(),
        Some(other) => vec![other.clone()],
    };
    filters
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let filter = Filter::from_name(f.as_name().unwrap().as_bytes()).unwrap();
            let mut params = FilterParams::new();
            if let Some(p) = parms.get(i).and_then(Object::as_dict) {
                let int = |k: &[u8]| p.get_int(k);
                if let Some(v) = int(b"Predictor") {
                    params = params.with_predictor(u8::try_from(v).unwrap());
                }
                if let Some(v) = int(b"Columns") {
                    params = params.with_columns(u32::try_from(v).unwrap());
                }
                if let Some(v) = int(b"Colors") {
                    params = params.with_colors(u8::try_from(v).unwrap());
                }
                if let Some(v) = int(b"BitsPerComponent") {
                    params = params.with_bits_per_component(u8::try_from(v).unwrap());
                }
            }
            (filter, params)
        })
        .collect()
}

/// Decodes stream data completely (no truncation, no passthrough filter left).
fn decode_stream(bytes: &[u8], dict: &Dict, range: &std::ops::Range<u64>) -> Vec<u8> {
    let raw = &bytes[range.start as usize..range.end as usize];
    let out = decode_chain(&filter_chain(dict), raw, &DecodeLimits::default()).unwrap();
    assert!(!out.truncated && out.remaining.is_empty());
    out.data
}

/// Reads a cross-reference stream at `pos`: entries in `/Index` order, and the dictionary.
fn read_xref_stream(bytes: &[u8], pos: usize) -> (Vec<(u32, Entry)>, Dict) {
    let obj = parse_indirect_at(bytes, pos, &strict(), &|_| None).unwrap();
    let stream = obj.object.as_stream().unwrap();
    let dict = stream.dict.clone();
    assert!(dict.is_type(b"XRef"));
    let data = decode_stream(bytes, &dict, &obj.stream_data_range.unwrap());
    let w: Vec<usize> = dict
        .get_array(b"W")
        .unwrap()
        .iter()
        .map(|o| usize::try_from(o.as_int().unwrap()).unwrap())
        .collect();
    let size = u32::try_from(dict.get_int(b"Size").unwrap()).unwrap();
    let index: Vec<u32> = match dict.get_array(b"Index") {
        Some(items) => items
            .iter()
            .map(|o| u32::try_from(o.as_int().unwrap()).unwrap())
            .collect(),
        None => vec![0, size],
    };
    let row = w.iter().sum::<usize>();
    let field = |r: &[u8], i: usize| -> Option<u64> {
        let start: usize = w[..i].iter().sum();
        (w[i] > 0).then(|| {
            r[start..start + w[i]]
                .iter()
                .fold(0, |a, &b| (a << 8) | u64::from(b))
        })
    };
    let mut rows = data.chunks_exact(row);
    let mut entries = Vec::new();
    for pair in index.chunks(2) {
        for num in pair[0]..pair[0] + pair[1] {
            let r = rows.next().expect("enough rows");
            // §7.5.8.2: a missing type field means type 1; a missing third field means 0.
            let entry = match field(r, 0).unwrap_or(1) {
                0 => Entry::Free {
                    generation: u16::try_from(field(r, 2).unwrap_or(0)).unwrap(),
                },
                1 => Entry::InUse {
                    offset: field(r, 1).unwrap(),
                    generation: u16::try_from(field(r, 2).unwrap_or(0)).unwrap(),
                },
                2 => Entry::Compressed {
                    stream: u32::try_from(field(r, 1).unwrap()).unwrap(),
                    index: u32::try_from(field(r, 2).unwrap_or(0)).unwrap(),
                },
                t => panic!("type {t}"),
            };
            entries.push((num, entry));
        }
    }
    assert!(rows.next().is_none(), "extra rows");
    (entries, dict)
}

/// A document read through its cross-reference sections, newest first.
struct Doc<'a> {
    bytes: &'a [u8],
    header: usize,
    entries: BTreeMap<u32, Entry>,
    trailer: Dict,
    sections: usize,
    entry_lens: BTreeSet<usize>,
}

impl<'a> Doc<'a> {
    fn open(bytes: &'a [u8]) -> Doc<'a> {
        let header = header_offset(bytes);
        let mut doc = Doc {
            bytes,
            header,
            entries: BTreeMap::new(),
            trailer: Dict::new(),
            sections: 0,
            entry_lens: BTreeSet::new(),
        };
        let mut next = Some(startxref(bytes));
        let mut seen = BTreeSet::new();
        while let Some(offset) = next {
            assert!(seen.insert(offset), "/Prev loop at {offset}");
            let pos = header + offset as usize;
            let trailer = if bytes[pos..].starts_with(b"xref") {
                let table = read_table(bytes, pos);
                doc.entry_lens.extend(&table.entry_lens);
                for (start, entries) in &table.subsections {
                    for (num, entry) in (*start..).zip(entries) {
                        doc.entries.entry(num).or_insert(*entry);
                    }
                }
                // §7.5.8.4: a hybrid table's /XRefStm fills in what the table does not list.
                if let Some(stm) = table.trailer.get_int(b"XRefStm") {
                    let (entries, _) = read_xref_stream(bytes, header + stm as usize);
                    for (num, entry) in entries {
                        doc.entries.entry(num).or_insert(entry);
                    }
                }
                table.trailer
            } else {
                let (entries, dict) = read_xref_stream(bytes, pos);
                for (num, entry) in entries {
                    doc.entries.entry(num).or_insert(entry);
                }
                dict
            };
            if doc.sections == 0 {
                doc.trailer = trailer.clone();
            }
            doc.sections += 1;
            next = trailer.get_int(b"Prev").map(|p| u64::try_from(p).unwrap());
        }
        doc
    }

    fn resolve(&self, id: ObjectId) -> Object {
        match self.entries.get(&id.num) {
            Some(&Entry::InUse { offset, generation }) => {
                assert_eq!(generation, id.r#gen, "{id}");
                let obj =
                    parse_indirect_at(self.bytes, self.header + offset as usize, &strict(), &|r| {
                        self.resolve(r).as_int()
                    })
                    .unwrap_or_else(|e| panic!("{id} at {offset}: {e}"));
                assert_eq!(obj.id, id);
                obj.object
            }
            Some(&Entry::Compressed { stream, index }) => {
                assert_eq!(id.r#gen, 0);
                let (container, data) = self.objstm(stream);
                let n = usize::try_from(container.get_int(b"N").unwrap()).unwrap();
                let first = usize::try_from(container.get_int(b"First").unwrap()).unwrap();
                let header = &data[..first];
                let mut pairs = Vec::new();
                let mut pos = 0;
                for _ in 0..2 * n {
                    let (v, end) = parse_object(header, pos, &strict()).unwrap();
                    pairs.push(usize::try_from(v.as_int().unwrap()).unwrap());
                    pos = end;
                }
                let index = index as usize;
                assert_eq!(
                    pairs[2 * index],
                    id.num as usize,
                    "objstm {stream} index {index}"
                );
                let (obj, _) =
                    parse_object(&data, first + pairs[2 * index + 1], &strict()).unwrap();
                obj
            }
            Some(Entry::Free { .. }) | None => Object::Null,
        }
    }

    fn objstm(&self, num: u32) -> (Dict, Vec<u8>) {
        let Some(&Entry::InUse { offset, .. }) = self.entries.get(&num) else {
            panic!("object stream {num} is not in use");
        };
        let obj = parse_indirect_at(
            self.bytes,
            self.header + offset as usize,
            &strict(),
            &|_| None,
        )
        .unwrap();
        let stream = obj.object.as_stream().unwrap();
        assert!(stream.dict.is_type(b"ObjStm"));
        let data = decode_stream(self.bytes, &stream.dict, &obj.stream_data_range.unwrap());
        (stream.dict.clone(), data)
    }

    /// Decodes the data of stream object `id`.
    fn stream_data(&self, id: ObjectId) -> Vec<u8> {
        let Some(&Entry::InUse { offset, .. }) = self.entries.get(&id.num) else {
            panic!("{id} is not an uncompressed object");
        };
        let obj = parse_indirect_at(self.bytes, self.header + offset as usize, &strict(), &|r| {
            self.resolve(r).as_int()
        })
        .unwrap();
        let stream = obj.object.as_stream().unwrap();
        decode_stream(self.bytes, &stream.dict, &obj.stream_data_range.unwrap())
    }

    /// Walks the page tree from `/Root`, checking `/Type`, `/Parent` and `/Count`.
    fn page_count(&self) -> u32 {
        let root = self.trailer.get_ref(b"Root").unwrap();
        let catalog = self.resolve(root);
        let catalog = catalog.as_dict().unwrap();
        assert!(catalog.is_type(b"Catalog"));
        let mut seen = BTreeSet::new();
        self.count(catalog.get_ref(b"Pages").unwrap(), None, &mut seen)
    }

    fn count(&self, id: ObjectId, parent: Option<ObjectId>, seen: &mut BTreeSet<ObjectId>) -> u32 {
        assert!(seen.insert(id), "page tree cycle at {id}");
        let node = self.resolve(id);
        let node = node.as_dict().unwrap();
        assert_eq!(node.get_ref(b"Parent"), parent, "{id}");
        if node.is_type(b"Page") {
            return 1;
        }
        assert!(node.is_type(b"Pages"), "{id}");
        let total: u32 = node
            .get_array(b"Kids")
            .unwrap()
            .iter()
            .map(|kid| self.count(kid.as_ref().unwrap(), Some(id), seen))
            .sum();
        assert_eq!(node.get_int(b"Count"), Some(i64::from(total)), "{id}");
        total
    }

    /// Resolves every listed object and decodes every stream, all strictly.
    fn check_all_objects(&self) {
        for (&num, entry) in &self.entries {
            match *entry {
                Entry::InUse { generation, .. } => {
                    let id = ObjectId::new(num, generation);
                    if matches!(self.resolve(id), Object::Stream(_)) {
                        self.stream_data(id);
                    }
                }
                Entry::Compressed { .. } => {
                    let obj = self.resolve(ObjectId::new(num, 0));
                    assert!(!matches!(obj, Object::Stream(_) | Object::Null), "{num}");
                }
                Entry::Free { .. } => {}
            }
        }
        let max = self.entries.keys().next_back().copied().unwrap_or(0);
        assert_eq!(self.trailer.get_int(b"Size"), Some(i64::from(max) + 1));
    }
}

/// Object headers found by scanning for `N G obj` at line starts, as a full reconstruction does.
fn scan_objects(bytes: &[u8]) -> BTreeMap<u32, usize> {
    let mut found = BTreeMap::new();
    for pos in 0..bytes.len() {
        if pos > 0 && bytes[pos - 1] != b'\n' {
            continue;
        }
        if let Ok((id, _)) = folioxide_syntax::parse_indirect_header(bytes, pos, &strict()) {
            found.insert(id.num, pos);
        }
    }
    found
}

fn fixture(name: &str) -> Vec<u8> {
    syntax::get(name).unwrap_or_else(|| panic!("no fixture {name}"))
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

/// Fixtures the strict reader opens as they are (some are non-conforming in ways it tolerates:
/// 19-byte entries, junk before the header, an /Extends loop it does not follow, encryption it
/// does not apply).
const READABLE: &[&str] = &[
    "minimal",
    "multi-revision",
    "xref-stream",
    "xref-stream-incremental",
    "hybrid",
    "objstm",
    "objstm-extends",
    "xref-eol-space-lf",
    "xref-eol-space-cr",
    "xref-eol-crlf",
    "xref-eol-lf",
    "xref-eol-cr",
    "junk-before-header",
    "xref-stream-w0",
    "objstm-extends-loop",
    "encrypted",
    "encrypted-unknown-handler",
];

#[test]
fn every_conforming_fixture_is_readable_by_the_strict_reader() {
    for info in syntax::infos() {
        if info.conforming {
            assert!(READABLE.contains(&info.name), "{}", info.name);
        }
    }
}

#[test]
fn readable_fixtures_resolve_every_object_and_have_the_right_page_count() {
    for name in READABLE {
        let pdf = fixture(name);
        let doc = Doc::open(&pdf);
        doc.check_all_objects();
        let info = syntax::info(name).unwrap();
        assert_eq!(doc.page_count(), info.pages, "{name}");
    }
}

#[test]
fn healthy_files_have_the_advertised_structure() {
    let doc_of = |name: &str| fixture(name);

    let pdf = doc_of("minimal");
    let doc = Doc::open(&pdf);
    assert_eq!((doc.sections, doc.entries.len()), (1, 6));
    assert!(pdf.starts_with(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n"));

    let pdf = doc_of("multi-revision");
    let doc = Doc::open(&pdf);
    assert_eq!(doc.sections, 3);
    assert_eq!(pdf.windows(9).filter(|w| w == b"startxref").count(), 3);
    assert_eq!(doc.entries[&6], Entry::Free { generation: 1 });
    assert!(doc.trailer.get(b"Info").is_none());
    assert_eq!(
        doc.stream_data(ObjectId::new(4, 0)),
        b"BT /F1 24 Tf 72 720 Td (Revision 2) Tj ET"
    );
    let newest = read_table(&pdf, startxref(&pdf) as usize);
    let starts: Vec<(u32, usize)> = newest
        .subsections
        .iter()
        .map(|(s, e)| (*s, e.len()))
        .collect();
    assert_eq!(starts, [(2, 1), (6, 3)]);

    let pdf = doc_of("xref-stream");
    let (_, dict) = read_xref_stream(&pdf, startxref(&pdf) as usize);
    assert_eq!(
        dict.get_dict(b"DecodeParms").unwrap().get_int(b"Predictor"),
        Some(12)
    );

    let pdf = doc_of("xref-stream-incremental");
    let doc = Doc::open(&pdf);
    assert_eq!(doc.sections, 2);
    let (_, dict) = read_xref_stream(&pdf, startxref(&pdf) as usize);
    let index: Vec<i64> = dict
        .get_array(b"Index")
        .unwrap()
        .iter()
        .map(|o| o.as_int().unwrap())
        .collect();
    assert_eq!(index, [4, 1, 7, 2]);
    assert!(dict.get_int(b"Prev").is_some());

    let pdf = doc_of("hybrid");
    let doc = Doc::open(&pdf);
    let table = read_table(&pdf, startxref(&pdf) as usize);
    let listed: BTreeSet<u32> = table
        .subsections
        .iter()
        .flat_map(|(start, e)| (*start..).take(e.len()))
        .collect();
    assert!(!listed.contains(&1) && !listed.contains(&2), "{listed:?}");
    assert!(matches!(
        doc.entries[&1],
        Entry::Compressed {
            stream: 6,
            index: 0
        }
    ));
    assert!(table.trailer.get_int(b"XRefStm").is_some());

    let pdf = doc_of("objstm");
    let doc = Doc::open(&pdf);
    let compressed: Vec<u32> = doc
        .entries
        .iter()
        .filter(|(_, e)| matches!(e, Entry::Compressed { .. }))
        .map(|(n, _)| *n)
        .collect();
    assert_eq!(compressed, [1, 2, 3, 5, 7]);

    let pdf = doc_of("objstm-extends");
    let doc = Doc::open(&pdf);
    assert_eq!(
        doc.objstm(12).0.get_ref(b"Extends"),
        Some(ObjectId::new(11, 0))
    );
    assert_eq!(
        doc.objstm(11).0.get_ref(b"Extends"),
        Some(ObjectId::new(10, 0))
    );
    assert_eq!(doc.objstm(10).0.get_ref(b"Extends"), None);

    let pdf = doc_of("xref-stream-w0");
    let (entries, dict) = read_xref_stream(&pdf, startxref(&pdf) as usize);
    let w: Vec<i64> = dict
        .get_array(b"W")
        .unwrap()
        .iter()
        .map(|o| o.as_int().unwrap())
        .collect();
    assert_eq!(w, [0, 3, 0]);
    assert_eq!(entries.first().unwrap().0, 1);
    assert!(
        entries
            .iter()
            .all(|(_, e)| matches!(e, Entry::InUse { generation: 0, .. }))
    );
}

#[test]
fn xref_eol_variants() {
    for (name, eol, len) in [
        ("xref-eol-space-lf", &b" \n"[..], 20),
        ("xref-eol-space-cr", b" \r", 20),
        ("xref-eol-crlf", b"\r\n", 20),
        ("xref-eol-lf", b"\n", 19),
        ("xref-eol-cr", b"\r", 19),
    ] {
        let pdf = fixture(name);
        let doc = Doc::open(&pdf);
        assert_eq!(doc.entry_lens, BTreeSet::from([len]), "{name}");
        let at = startxref(&pdf) as usize;
        let first_entry = &pdf[at..]
            .windows(18)
            .position(|w| w == b"0000000000 65535 f")
            .unwrap();
        let after = at + first_entry + 18;
        assert_eq!(&pdf[after..after + eol.len()], eol, "{name}");
        assert_eq!(syntax::info(name).unwrap().conforming, len == 20, "{name}");
    }
}

#[test]
fn xref_subsection_starting_at_1_is_off_by_one() {
    let pdf = fixture("xref-subsection-starts-at-1");
    let table = read_table(&pdf, startxref(&pdf) as usize);
    let (start, entries) = &table.subsections[0];
    assert_eq!(*start, 1);
    assert_eq!(entries[0], Entry::Free { generation: 65535 });
    // Read as starting at 0, every entry points at its object.
    for (num, entry) in (0u32..).zip(entries) {
        if let Entry::InUse { offset, .. } = entry {
            let obj = parse_indirect_at(&pdf, *offset as usize, &strict(), &|_| None).unwrap();
            assert_eq!(obj.id.num, num);
        }
    }
}

#[test]
fn xref_offsets_off_by_n() {
    let pdf = fixture("xref-offsets-off-by-n");
    let table = read_table(&pdf, startxref(&pdf) as usize);
    let (_, entries) = &table.subsections[0];
    for (num, entry) in (0u32..).zip(entries) {
        if let Entry::InUse { offset, .. } = entry {
            let offset = *offset as usize;
            assert!(parse_indirect_at(&pdf, offset, &strict(), &|_| None).is_err());
            let obj = parse_indirect_at(&pdf, offset - 5, &strict(), &|_| None).unwrap();
            assert_eq!(obj.id.num, num);
        }
    }
}

#[test]
fn startxref_off_by_n() {
    let pdf = fixture("startxref-off-by-n");
    let value = startxref(&pdf) as usize;
    assert!(!pdf[value..].starts_with(b"xref"));
    assert!(pdf[value - 8..].starts_with(b"xref"));
}

#[test]
fn prev_loop() {
    let pdf = fixture("prev-loop");
    let newest = startxref(&pdf);
    let t2 = read_table(&pdf, newest as usize);
    let older = u64::try_from(t2.trailer.get_int(b"Prev").unwrap()).unwrap();
    let t1 = read_table(&pdf, older as usize);
    assert_eq!(t1.trailer.get_int(b"Prev"), Some(newest as i64));
    let result = std::panic::catch_unwind(|| Doc::open(&pdf).sections);
    assert!(result.is_err(), "the strict reader must see the loop");
}

#[test]
fn junk_before_header() {
    let pdf = fixture("junk-before-header");
    let doc = Doc::open(&pdf);
    assert_eq!(doc.header, 118);
    // Offsets are relative to the header: as absolute offsets they point at the wrong bytes.
    let Entry::InUse { offset, .. } = doc.entries[&1] else {
        panic!()
    };
    assert!(parse_indirect_at(&pdf, offset as usize, &strict(), &|_| None).is_err());
}

#[test]
fn stream_length_wrong_recovers_in_lenient_mode_only() {
    let pdf = fixture("stream-length-wrong");
    let table = read_table(&pdf, startxref(&pdf) as usize);
    let entries = &table.subsections[0].1;
    let expected: [(u32, &[u8]); 4] = [
        (4, b"BT /F1 24 Tf 72 720 Td (Length too short) Tj ET"),
        (6, b"BT /F1 24 Tf 72 690 Td (Length too long) Tj ET"),
        (7, b"BT /F1 24 Tf 72 660 Td (Length missing) Tj ET"),
        (8, b"BT /F1 24 Tf 72 630 Td (Flate, Length too long) Tj ET"),
    ];
    for (num, content) in expected {
        let Entry::InUse { offset, .. } = entries[num as usize] else {
            panic!()
        };
        let err = parse_indirect_at(&pdf, offset as usize, &strict(), &|_| None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Syntax, "{num}");
        let log = DiagnosticLog::new(16);
        let ctx = ParseCtx::default().with_diagnostics(&log);
        let obj = parse_indirect_at(&pdf, offset as usize, &ctx, &|_| None).unwrap();
        assert_eq!(
            log.snapshot()[0].kind,
            DiagnosticKind::StreamLength,
            "{num}"
        );
        let dict = &obj.object.as_stream().unwrap().dict;
        assert_eq!(
            decode_stream(&pdf, dict, &obj.stream_data_range.unwrap()),
            content,
            "{num}"
        );
    }
}

#[test]
fn length_indirect_cycle() {
    let pdf = fixture("length-indirect-cycle");
    let table = read_table(&pdf, startxref(&pdf) as usize);
    let entries = &table.subsections[0].1;
    let at = |num: usize| match entries[num] {
        Entry::InUse { offset, .. } => offset as usize,
        _ => panic!(),
    };
    let lenient = ParseCtx::default();
    let value = |num: usize| {
        parse_indirect_at(&pdf, at(num), &lenient, &|_| None)
            .unwrap()
            .object
    };
    let length = |num: usize| value(num).as_stream().unwrap().dict.get(b"Length").cloned();
    assert_eq!(length(4), Some(Object::Ref(ObjectId::new(4, 0))));
    assert_eq!(length(6), Some(Object::Ref(ObjectId::new(7, 0))));
    assert_eq!(value(7), Object::Ref(ObjectId::new(8, 0)));
    assert_eq!(value(8), Object::Ref(ObjectId::new(7, 0)));
    assert_eq!(length(9), Some(Object::Ref(ObjectId::new(10, 0))));
    // Stream 9's indirect length is correct: a strict parse with the resolved value succeeds.
    let len10 = value(10).as_int();
    let obj = parse_indirect_at(&pdf, at(9), &strict(), &|_| len10).unwrap();
    let range = obj.stream_data_range.unwrap();
    assert_eq!(
        &pdf[range.start as usize..range.end as usize],
        b"BT /F1 24 Tf 72 660 Td (indirect Length) Tj ET"
    );
    // Without a usable length, streams 4 and 6 need the endstream scan.
    for num in [4, 6] {
        assert!(parse_indirect_at(&pdf, at(num), &strict(), &|_| None).is_err());
    }
}

#[test]
fn missing_xref_files_need_a_full_scan() {
    for name in ["missing-xref", "missing-xref-with-trailer"] {
        let pdf = fixture(name);
        assert!(find(&pdf, b"\nxref").is_none(), "{name}");
        assert!(find(&pdf, b"startxref").is_none(), "{name}");
        assert_eq!(
            find(&pdf, b"trailer").is_some(),
            name.ends_with("with-trailer")
        );
        let objects = scan_objects(&pdf);
        assert_eq!(
            objects.keys().copied().collect::<Vec<_>>(),
            [1, 2, 3, 4, 5],
            "{name}"
        );
        for (&num, &pos) in &objects {
            let obj = parse_indirect_at(&pdf, pos, &strict(), &|_| None).unwrap();
            assert_eq!(obj.id, ObjectId::new(num, 0));
        }
        let catalog = parse_indirect_at(&pdf, objects[&1], &strict(), &|_| None).unwrap();
        assert!(catalog.object.as_dict().unwrap().is_type(b"Catalog"));
    }
}

#[test]
fn flate_truncated_decodes_partially() {
    let pdf = fixture("flate-truncated");
    let doc = Doc::open(&pdf);
    let Entry::InUse { offset, .. } = doc.entries[&4] else {
        panic!()
    };
    let obj = parse_indirect_at(&pdf, offset as usize, &strict(), &|_| None).unwrap();
    let dict = &obj.object.as_stream().unwrap().dict;
    let range = obj.stream_data_range.unwrap();
    let raw = &pdf[range.start as usize..range.end as usize];
    let out = decode_chain(&filter_chain(dict), raw, &DecodeLimits::default()).unwrap();
    assert!(out.truncated);
    assert!(
        out.data
            .starts_with(b"BT /F1 10 Tf 72 760 Td (Line 0 of a truncated stream) Tj ET\n")
    );
    assert_eq!(doc.page_count(), 1);
}

#[test]
fn objstm_defects() {
    let pdf = fixture("objstm-extends-loop");
    let doc = Doc::open(&pdf);
    assert_eq!(
        doc.objstm(9).0.get_ref(b"Extends"),
        Some(ObjectId::new(10, 0))
    );
    assert_eq!(
        doc.objstm(10).0.get_ref(b"Extends"),
        Some(ObjectId::new(9, 0))
    );

    let pdf = fixture("objstm-n-too-large");
    let (entries, _) = read_xref_stream(&pdf, startxref(&pdf) as usize);
    let Some((_, Entry::InUse { offset, .. })) = entries.iter().find(|(n, _)| *n == 6) else {
        panic!()
    };
    let obj = parse_indirect_at(&pdf, *offset as usize, &strict(), &|_| None).unwrap();
    let stream = obj.object.as_stream().unwrap();
    assert_eq!(stream.dict.get_int(b"N"), Some(1000));
    let data = decode_stream(&pdf, &stream.dict, &obj.stream_data_range.unwrap());
    let first = usize::try_from(stream.dict.get_int(b"First").unwrap()).unwrap();
    let header = std::str::from_utf8(&data[..first]).unwrap();
    assert_eq!(header.split_ascii_whitespace().count(), 8, "four pairs");
}

#[test]
fn encrypted_trailers() {
    for (name, filter) in [
        ("encrypted", &b"Standard"[..]),
        ("encrypted-unknown-handler", b"Adobe.PubSec"),
    ] {
        let pdf = fixture(name);
        let doc = Doc::open(&pdf);
        let encrypt = doc.resolve(doc.trailer.get_ref(b"Encrypt").unwrap());
        let encrypt = encrypt.as_dict().unwrap();
        assert_eq!(
            encrypt.get_name(b"Filter").unwrap().as_bytes(),
            filter,
            "{name}"
        );
        assert_eq!(doc.trailer.get_array(b"ID").unwrap().len(), 2);
    }
    let pdf = fixture("encrypted");
    let doc = Doc::open(&pdf);
    let encrypt = doc.resolve(ObjectId::new(6, 0));
    let encrypt = encrypt.as_dict().unwrap();
    assert_eq!(encrypt.get_string(b"O").unwrap().len(), 32);
    assert_eq!(encrypt.get_string(b"U").unwrap().len(), 32);
    assert_eq!(encrypt.get_int(b"R"), Some(2));
}

#[test]
fn large_page_trees() {
    for (pages, compressed) in [
        (0, false),
        (1, false),
        (250, false),
        (250, true),
        (101, true),
    ] {
        let pdf = if compressed {
            syntax::many_pages_compressed(pages)
        } else {
            syntax::many_pages(pages)
        };
        let doc = Doc::open(&pdf);
        doc.check_all_objects();
        assert_eq!(doc.page_count(), pages, "{pages} {compressed}");
    }
}

#[test]
fn lazy_file_has_2000_pages_and_is_not_tiny() {
    let pdf = syntax::lazy_pages();
    let doc = Doc::open(&pdf);
    assert_eq!(doc.page_count(), syntax::LAZY_PAGE_COUNT);
    // 1 catalog + 1 root + 1 font + 20 nodes + 2,000 pages + 2,000 content streams.
    assert_eq!(doc.trailer.get_int(b"Size"), Some(4024));
    // Too large to commit (fixtures must stay under 200 KB), so it is generated at test time.
    assert!(pdf.len() > 200 * 1024, "{} bytes", pdf.len());
    let compressed = syntax::many_pages_compressed(syntax::LAZY_PAGE_COUNT);
    assert_eq!(Doc::open(&compressed).page_count(), syntax::LAZY_PAGE_COUNT);
}

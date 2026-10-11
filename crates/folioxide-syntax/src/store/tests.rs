//! Store, cross-reference, object stream and repair tests (M1 brief WP1.3 acceptance tests),
//! with inline byte fixtures built by [`Pdf`].

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use super::*;
use crate::filters::{encode_ascii_hex, encode_flate};

// ---- a tiny byte-level PDF builder ----------------------------------------------------------

/// A cross-reference row for [`Pdf::table_rows`] and [`Pdf::xref_stream`].
#[derive(Clone, Copy, Debug)]
enum Row {
    /// A free entry with this generation.
    Free(u16),
    /// The recorded offset and generation of this object.
    At(u32),
    /// Compressed: (object stream, index).
    In(u32, u32),
}

/// Writes PDF bytes and records object offsets (relative to the start of the buffer).
#[derive(Default)]
struct Pdf {
    buf: Vec<u8>,
    objects: BTreeMap<u32, (usize, u16)>,
}

impl Pdf {
    fn new() -> Pdf {
        let mut pdf = Pdf::default();
        pdf.raw(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
        pdf
    }

    fn raw(&mut self, bytes: impl AsRef<[u8]>) -> &mut Pdf {
        self.buf.extend_from_slice(bytes.as_ref());
        self
    }

    fn pos(&self) -> usize {
        self.buf.len()
    }

    fn obj(&mut self, num: u32, body: &str) -> &mut Pdf {
        self.obj_gen(num, 0, body)
    }

    fn obj_gen(&mut self, num: u32, r#gen: u16, body: &str) -> &mut Pdf {
        self.objects.insert(num, (self.pos(), r#gen));
        self.raw(format!("{num} {gen} obj\n{body}\nendobj\n"))
    }

    /// A stream with a correct `/Length` and `dict` as extra dictionary entries.
    fn stream(&mut self, num: u32, dict: &str, data: &[u8]) -> &mut Pdf {
        self.stream_with(num, &format!("<< /Length {} {dict} >>", data.len()), data)
    }

    /// A stream with the dictionary written exactly as given.
    fn stream_with(&mut self, num: u32, dict: &str, data: &[u8]) -> &mut Pdf {
        self.objects.insert(num, (self.pos(), 0));
        self.raw(format!("{num} 0 obj\n{dict}\nstream\n"))
            .raw(data)
            .raw("\nendstream\nendobj\n")
    }

    /// An object stream holding `members`, Flate-compressed.
    fn objstm(&mut self, num: u32, members: &[(u32, &str)], extra: &str) -> &mut Pdf {
        let (data, first) = objstm_data(members);
        let encoded = encode_flate(&data, 6);
        let dict = format!(
            "<< /Type /ObjStm /N {} /First {first} /Filter /FlateDecode /Length {} {extra} >>",
            members.len(),
            encoded.len()
        );
        self.stream_with(num, &dict, &encoded)
    }

    fn size(&self) -> u32 {
        self.objects.keys().next_back().map_or(1, |n| n + 1)
    }

    /// One row per object number up to the largest: recorded objects in use, the rest free.
    fn all_rows(&self) -> Vec<(u32, Row)> {
        (0..self.size())
            .map(|n| {
                let row = if self.objects.contains_key(&n) {
                    Row::At(n)
                } else {
                    Row::Free(if n == 0 { 65535 } else { 0 })
                };
                (n, row)
            })
            .collect()
    }

    /// A classic table for every recorded object; returns its offset.
    fn table(&mut self, eol: &str) -> usize {
        let rows = self.all_rows();
        self.table_rows(&rows, eol, None)
    }

    /// A classic table with the given rows (consecutive numbers form subsections). The first
    /// subsection header can claim a different start (`first_start`).
    fn table_rows(&mut self, rows: &[(u32, Row)], eol: &str, first_start: Option<u32>) -> usize {
        let at = self.pos();
        let mut runs: Vec<(u32, Vec<Row>)> = Vec::new();
        for &(num, row) in rows {
            match runs.last_mut() {
                Some((start, run)) if *start + run.len() as u32 == num => run.push(row),
                _ => runs.push((num, vec![row])),
            }
        }
        let mut text = String::from("xref\n");
        for (i, (start, run)) in runs.iter().enumerate() {
            let shown = if i == 0 {
                first_start.unwrap_or(*start)
            } else {
                *start
            };
            text += &format!("{shown} {}\n", run.len());
            for row in run {
                match *row {
                    Row::Free(g) => text += &format!("0000000000 {g:05} f{eol}"),
                    Row::At(n) => {
                        let (off, g) = self.objects[&n];
                        text += &format!("{off:010} {g:05} n{eol}");
                    }
                    Row::In(..) => panic!("tables cannot hold compressed entries"),
                }
            }
        }
        self.raw(text);
        at
    }

    fn trailer(&mut self, extra: &str) -> &mut Pdf {
        let size = self.size();
        self.raw(format!("trailer\n<< /Size {size} {extra} >>\n"))
    }

    fn startxref(&mut self, at: usize) -> &mut Pdf {
        self.raw(format!("startxref\n{at}\n%%EOF\n"))
    }

    /// Table, trailer and startxref.
    fn finish(&mut self, trailer: &str) -> Vec<u8> {
        let at = self.table("\r\n");
        self.trailer(trailer).startxref(at);
        self.buf.clone()
    }

    /// A Flate-compressed cross-reference stream object `num` with `rows`; returns its offset.
    fn xref_stream(&mut self, num: u32, w: [usize; 3], rows: &[(u32, Row)], extra: &str) -> usize {
        let at = self.pos();
        self.objects.insert(num, (at, 0));
        let mut data = Vec::new();
        let put = |data: &mut Vec<u8>, width: usize, value: u64| {
            for i in (0..width).rev() {
                data.push((value >> (8 * i)) as u8);
            }
        };
        let mut index: Vec<(u32, u32)> = Vec::new();
        for &(num, row) in rows {
            let (t, f2, f3) = match row {
                Row::Free(g) => (0, 0, u64::from(g)),
                Row::At(n) => {
                    let (off, g) = self.objects[&n];
                    (1, off as u64, u64::from(g))
                }
                Row::In(s, i) => (2, u64::from(s), u64::from(i)),
            };
            put(&mut data, w[0], t);
            put(&mut data, w[1], f2);
            put(&mut data, w[2], f3);
            match index.last_mut() {
                Some((start, count)) if *start + *count == num => *count += 1,
                _ => index.push((num, 1)),
            }
        }
        let size = rows.iter().map(|r| r.0).chain([num]).max().unwrap() + 1;
        let index: Vec<String> = index.iter().map(|(s, c)| format!("{s} {c}")).collect();
        let encoded = encode_flate(&data, 6);
        let dict = format!(
            "<< /Type /XRef /Size {size} /W [{} {} {}] /Index [{}] /Filter /FlateDecode \
             /Length {} {extra} >>",
            w[0],
            w[1],
            w[2],
            index.join(" "),
            encoded.len()
        );
        self.stream_with(num, &dict, &encoded);
        at
    }

    /// Overwrites the 10 bytes at `at` with `value`, zero-padded.
    fn patch(&mut self, at: usize, value: usize) {
        self.buf[at..at + 10].copy_from_slice(format!("{value:010}").as_bytes());
    }
}

/// The decoded data of an object stream and its `/First`.
fn objstm_data(members: &[(u32, &str)]) -> (Vec<u8>, usize) {
    let mut head = String::new();
    let mut body = String::new();
    for (num, text) in members {
        head += &format!("{num} {} ", body.len());
        body += text;
        body.push('\n');
    }
    let first = head.len();
    ((head + &body).into_bytes(), first)
}

const CONTENT: &[u8] = b"BT /F1 12 Tf 72 720 Td (Hello) Tj ET";

/// The byte position of the first occurrence of `needle`.
fn find(bytes: &[u8], needle: &[u8]) -> usize {
    bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap_or_else(|| panic!("{:?} not found", needle.escape_ascii().to_string()))
}

/// The byte position of the last occurrence of `needle`.
fn rfind(bytes: &[u8], needle: &[u8]) -> usize {
    bytes
        .windows(needle.len())
        .rposition(|w| w == needle)
        .unwrap_or_else(|| panic!("{:?} not found", needle.escape_ascii().to_string()))
}

/// Catalog, page tree, one page and a content stream.
fn simple_doc() -> Pdf {
    let mut pdf = Pdf::new();
    pdf.obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .obj(
            3,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
        )
        .stream(4, "", CONTENT);
    pdf
}

fn simple_bytes() -> Vec<u8> {
    simple_doc().finish("/Root 1 0 R")
}

/// Objects 1–3 compressed in object stream 5, a content stream 4, cross-reference stream 6.
fn compressed_doc() -> Vec<u8> {
    let mut pdf = Pdf::new();
    pdf.objstm(
        5,
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>"),
        ],
        "",
    )
    .stream(4, "", CONTENT);
    let at = pdf.xref_stream(
        6,
        [1, 2, 1],
        &[
            (0, Row::Free(255)),
            (1, Row::In(5, 0)),
            (2, Row::In(5, 1)),
            (3, Row::In(5, 2)),
            (4, Row::At(4)),
            (5, Row::At(5)),
            (6, Row::At(6)),
        ],
        "/Root 1 0 R",
    );
    pdf.startxref(at);
    pdf.buf
}

fn options(strictness: Strictness) -> OpenOptions {
    OpenOptions::default().with_strictness(strictness)
}

fn open(bytes: &[u8]) -> Store {
    Store::open_bytes(bytes.to_vec(), &OpenOptions::default())
        .unwrap_or_else(|e| panic!("open failed: {e}"))
}

fn open_strict(bytes: &[u8]) -> Result<Store> {
    Store::open_bytes(bytes.to_vec(), &options(Strictness::Strict))
}

fn kinds(store: &Store) -> Vec<DiagnosticKind> {
    store.diagnostics().iter().map(|d| d.kind).collect()
}

fn has(store: &Store, kind: DiagnosticKind) -> bool {
    kinds(store).contains(&kind)
}

fn id(num: u32) -> ObjectId {
    ObjectId::new(num, 0)
}

fn root(store: &Store) -> Arc<Object> {
    store.resolve(store.root_id().unwrap()).unwrap()
}

fn is_type(obj: &Object, ty: &[u8]) -> bool {
    obj.as_dict().is_some_and(|d| d.is_type(ty))
}

/// The decoded data of stream object `num`.
fn stream_of(store: &Store, num: u32) -> Vec<u8> {
    let obj = store.resolve(id(num)).unwrap();
    let stream = obj
        .as_stream()
        .unwrap_or_else(|| panic!("{num} is {obj:?}"));
    store.stream_data(stream).unwrap().data
}

/// Checks the simple document's objects.
fn check_simple(store: &Store) {
    assert!(is_type(&root(store), b"Catalog"));
    assert!(is_type(&store.resolve(id(2)).unwrap(), b"Pages"));
    assert!(is_type(&store.resolve(id(3)).unwrap(), b"Page"));
    assert_eq!(stream_of(store, 4), CONTENT);
}

/// Runs `f` on another thread and fails if it does not finish in time (deadlock guard).
fn within(seconds: u64, f: impl FnOnce() + Send + 'static) {
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    match rx.recv_timeout(Duration::from_secs(seconds)) {
        Ok(()) => handle.join().unwrap(),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            if let Err(panic) = handle.join() {
                std::panic::resume_unwind(panic);
            }
        }
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("did not finish in {seconds} s"),
    }
}

// ---- basics ---------------------------------------------------------------------------------

#[test]
fn store_is_send_sync() {
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<Store>();
    assert_send_sync::<Arc<Store>>();
    assert_send_sync::<OpenOptions>();
    assert_send_sync::<StreamBytes>();
    assert_send_sync::<Revision>();
}

#[test]
fn opens_a_well_formed_file_without_diagnostics() {
    let bytes = simple_bytes();
    let store = open_strict(&bytes).unwrap();
    check_simple(&store);
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
    assert_eq!(store.version(), (1, 7));
    assert_eq!(store.header_offset(), 0);
    assert_eq!(store.object_ids(), [id(1), id(2), id(3), id(4)]);
    assert_eq!(store.max_object_number(), 4);
    assert_eq!(store.root_id(), Some(id(1)));
    assert_eq!(store.trailer().get_int(b"Size"), Some(5));
    let revisions = store.revisions();
    assert_eq!(revisions.len(), 1);
    assert_eq!(revisions[0].xref_kind, XrefKind::Table);
    assert_eq!(revisions[0].eof_end, bytes.len() as u64);
    assert!(bytes[..revisions[0].section_end as usize].ends_with(b">>"));
    assert!(bytes[revisions[0].section_end as usize..].starts_with(b"\nstartxref"));
    assert_eq!(revisions[0].xref_stm, None);
    assert!(!store.structure_repaired());
    assert!(store.recovered_objects().is_empty());
    assert_eq!(store.offset_base(), OffsetBase::HeaderRelative);
    assert_eq!(store.source(), &bytes[..]);
    assert_eq!((**store.shared_source()).as_ref(), &bytes[..]);
    assert_eq!(store.options().strictness, Strictness::Strict);
    assert_eq!(store.limits(), &Limits::default());
    assert_eq!(store.dropped_diagnostics(), 0);
    // One slot per in-use object; the free entry of object 0 takes none.
    assert!(format!("{store:?}").contains("slots: 4"), "{store:?}");
    assert!(
        std::mem::size_of::<Slot>() <= 48,
        "{}",
        std::mem::size_of::<Slot>()
    );
}

#[test]
fn resolution_is_cached_and_counted() {
    let store = open(&simple_bytes());
    // The catalog is parsed (and cached) at open time.
    assert_eq!(store.parsed_object_count(), 1);
    let a = store.resolve(id(2)).unwrap();
    let b = store.resolve(id(2)).unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    assert_eq!(store.parsed_object_count(), 2);
    // Stream data ranges are absolute and point at the raw data.
    let obj = store.resolve(id(4)).unwrap();
    let stream = obj.as_stream().unwrap();
    assert_eq!(&*store.raw_stream_data(stream).unwrap(), CONTENT);
    let decoded = store.stream_data(stream).unwrap();
    assert!(decoded.is_fully_decoded());
    assert!(!decoded.truncated);
    assert_eq!(store.total_decoded(), CONTENT.len() as u64);
}

#[test]
fn free_missing_and_wrong_generation_are_null() {
    let mut pdf = simple_doc();
    pdf.obj_gen(6, 2, "(gen two)");
    let bytes = pdf.finish("/Root 1 0 R");
    let store = open(&bytes);
    // Object 5 is free in the table, 99 is missing, 0 is always free.
    for missing in [id(5), id(99), id(0)] {
        assert!(store.resolve(missing).unwrap().is_null(), "{missing}");
    }
    assert!(store.diagnostics().is_empty());
    assert_eq!(
        store.resolve(ObjectId::new(6, 2)).unwrap().as_str_bytes(),
        Some(&b"gen two"[..])
    );
    assert!(store.resolve(ObjectId::new(6, 0)).unwrap().is_null());
    assert_eq!(kinds(&store), [DiagnosticKind::WrongGeneration]);
    // Also in strict mode: a reference to an undefined object is legal (§7.3.10).
    let strict = open_strict(&bytes).unwrap();
    assert!(strict.resolve(ObjectId::new(6, 0)).unwrap().is_null());
    assert!(!strict.object_ids().contains(&id(5)));
    assert_eq!(strict.max_object_number(), 6);
}

#[test]
fn concurrent_resolution_parses_each_object_once() {
    let store = Arc::new(open(&compressed_doc()));
    let ids = store.object_ids();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let store = Arc::clone(&store);
            let ids = ids.clone();
            std::thread::spawn(move || {
                ids.iter()
                    .map(|&id| store.resolve(id).unwrap())
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let results: Vec<Vec<Arc<Object>>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for other in &results[1..] {
        for (a, b) in results[0].iter().zip(other) {
            assert!(Arc::ptr_eq(a, b));
        }
    }
    // Every object parsed exactly once (the xref stream counts too).
    assert_eq!(store.parsed_object_count(), ids.len() + 1);
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
}

#[test]
fn deref_follows_chains_with_limits() {
    let mut pdf = simple_doc();
    pdf.obj(5, "6 0 R").obj(6, "7 0 R").obj(7, "42");
    pdf.obj(8, "9 0 R").obj(9, "8 0 R");
    let bytes = pdf.finish("/Root 1 0 R");
    let store = open(&bytes);
    let direct = Object::Int(3);
    assert_eq!(store.deref(&direct).unwrap(), Resolved::Direct(&direct));
    let five = Object::Ref(id(5));
    let resolved = store.deref(&five).unwrap();
    assert_eq!(resolved.as_int(), Some(42));
    assert_eq!(*resolved.clone().into_arc(), Object::Int(42));
    assert_eq!(resolved.into_owned(), Object::Int(42));
    assert_eq!(Resolved::Direct(&direct).into_owned(), direct);
    assert_eq!(*Resolved::Direct(&direct).into_arc(), direct);
    assert_eq!(Resolved::Direct(&direct).as_ref(), &direct);
    // `resolve` does not follow references.
    assert_eq!(*store.resolve(id(5)).unwrap(), Object::Ref(id(6)));
    // A loop ends in null with a diagnostic.
    assert!(store.deref(&Object::Ref(id(8))).unwrap().is_null());
    assert!(has(&store, DiagnosticKind::UnresolvedReference));
    // A chain longer than max_ref_chain too.
    let short = OpenOptions::default().with_limits(Limits::default().with_max_ref_chain(2));
    let store = Store::open_bytes(bytes.clone(), &short).unwrap();
    assert!(store.deref(&Object::Ref(id(5))).unwrap().is_null());
    assert!(has(&store, DiagnosticKind::UnresolvedReference));
    // Strict mode: errors.
    let strict = open_strict(&bytes).unwrap();
    assert_eq!(
        strict.deref(&Object::Ref(id(8))).unwrap_err().code(),
        ErrorCode::Syntax
    );
    let strict = Store::open_bytes(bytes, &short.with_strictness(Strictness::Strict)).unwrap();
    assert_eq!(
        strict.deref(&Object::Ref(id(5))).unwrap_err().code(),
        ErrorCode::LimitExceeded
    );
}

#[test]
fn options_and_shared_bytes() {
    let options = OpenOptions::new()
        .with_strictness(Strictness::Strict)
        .with_limits(Limits::default().with_max_objects(7));
    assert_eq!(options.strictness, Strictness::Strict);
    assert_eq!(options.limits.max_objects, 7);
    assert_eq!(OpenOptions::new(), OpenOptions::default());
    static FILE: &[u8] =
        b"%PDF-1.0\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>";
    let store = Store::open(shared_bytes(FILE), &OpenOptions::default()).unwrap();
    assert!(is_type(&root(&store), b"Catalog"));
    assert_eq!(store.version(), (1, 0));
}

// ---- cross-reference tables (trap #3) --------------------------------------------------------

#[test]
fn xref_table_eol_variants() {
    // The three valid 2-byte EOLs of §7.5.4, and the invalid bare LF and CR (19-byte entries).
    for (eol, valid) in [
        (" \r", true),
        (" \n", true),
        ("\r\n", true),
        ("\n", false),
        ("\r", false),
    ] {
        let mut pdf = simple_doc();
        let at = pdf.table(eol);
        pdf.trailer("/Root 1 0 R").startxref(at);
        let store = open(&pdf.buf);
        check_simple(&store);
        assert!(
            store.diagnostics().is_empty(),
            "{eol:?}: {:?}",
            store.diagnostics()
        );
        if valid {
            check_simple(&open_strict(&pdf.buf).unwrap());
        }
    }
}

#[test]
fn xref_subsection_starts_at_1_repaired() {
    let mut pdf = simple_doc();
    let rows = pdf.all_rows();
    let at = pdf.table_rows(&rows, "\r\n", Some(1));
    pdf.trailer("/Root 1 0 R").startxref(at);
    let store = open(&pdf.buf);
    check_simple(&store);
    assert_eq!(kinds(&store), [DiagnosticKind::XrefSubsectionShifted]);
    assert_eq!(store.object_ids(), [id(1), id(2), id(3), id(4)]);
    assert_eq!(open_strict(&pdf.buf).unwrap_err().code(), ErrorCode::Xref);

    // A subsection that legitimately starts at 1 (no entry for object 0) is left alone.
    let mut pdf = simple_doc();
    let rows: Vec<_> = pdf.all_rows().into_iter().skip(1).collect();
    let at = pdf.table_rows(&rows, "\r\n", None);
    pdf.trailer("/Root 1 0 R").startxref(at);
    let store = open_strict(&pdf.buf).unwrap();
    check_simple(&store);

    // Without a usable in-use entry, the free 65535 entry decides (as pdf.js does).
    let mut pdf = simple_doc();
    let at = pdf.pos();
    pdf.raw("xref\n1 2\n0000000000 65535 f\r\n0000999999 00000 n\r\n");
    pdf.trailer("/Root 1 0 R").startxref(at);
    let store = open(&pdf.buf);
    assert!(has(&store, DiagnosticKind::XrefSubsectionShifted));
    // Object 1's entry was garbage, so it was found by scanning; 2-4 are not listed at all.
    assert!(is_type(&root(&store), b"Catalog"));
    assert!(store.resolve(id(2)).unwrap().is_null());
    assert_eq!(store.object_ids(), [id(1)]);
}

#[test]
fn startxref_off_by_n_repaired() {
    for skew in [5i64, -7, 40] {
        let mut pdf = simple_doc();
        let at = pdf.table("\r\n");
        pdf.trailer("/Root 1 0 R")
            .startxref((at as i64 + skew) as usize);
        let store = open(&pdf.buf);
        check_simple(&store);
        assert_eq!(
            kinds(&store),
            [DiagnosticKind::XrefOffsetRepaired],
            "{skew}"
        );
        assert_eq!(store.revisions()[0].startxref, at as u64);
        assert_eq!(open_strict(&pdf.buf).unwrap_err().code(), ErrorCode::Xref);
    }
    // A cross-reference stream found by the local search.
    let mut bytes = compressed_doc();
    let line = rfind(&bytes, b"startxref\n") + "startxref\n".len();
    let value: usize = String::from_utf8_lossy(&bytes[line..])
        .lines()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    bytes.truncate(line);
    bytes.extend_from_slice(format!("{}\n%%EOF\n", value - 3).as_bytes());
    let store = open(&bytes);
    assert!(is_type(&root(&store), b"Catalog"));
    assert_eq!(kinds(&store), [DiagnosticKind::XrefOffsetRepaired]);
    // Far off: nothing nearby, so the file is reconstructed.
    let mut pdf = simple_doc();
    pdf.table("\r\n");
    pdf.trailer("/Root 1 0 R").startxref(100_000);
    let store = open(&pdf.buf);
    check_simple(&store);
    assert!(has(&store, DiagnosticKind::XrefReconstructed));
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
}

#[test]
fn object_offsets_are_repaired_lazily() {
    // Every in-use offset is 3 bytes too far: found by the ±64-byte search.
    let mut pdf = simple_doc();
    for entry in pdf.objects.values_mut() {
        entry.0 += 3;
    }
    let bytes = pdf.finish("/Root 1 0 R");
    let store = open(&bytes);
    // Open parses the catalog only: one repair so far.
    assert_eq!(kinds(&store), [DiagnosticKind::XrefOffsetRepaired]);
    check_simple(&store);
    assert_eq!(kinds(&store), [DiagnosticKind::XrefOffsetRepaired; 4]);
    assert_eq!(open_strict(&bytes).unwrap_err().code(), ErrorCode::Xref);

    // Offsets that point nowhere near: found by scanning the file (once).
    let mut pdf = simple_doc();
    for entry in pdf.objects.values_mut() {
        entry.0 = 500 + entry.0 * 7;
    }
    let store = open(&pdf.finish("/Root 1 0 R"));
    check_simple(&store);
    assert_eq!(kinds(&store), [DiagnosticKind::XrefOffsetRepaired; 4]);

    // An object that exists nowhere is null in lenient mode.
    let mut pdf = simple_doc();
    pdf.objects.insert(7, (40, 0));
    let store = open(&pdf.finish("/Root 1 0 R"));
    assert!(store.resolve(id(7)).unwrap().is_null());
    assert_eq!(kinds(&store), [DiagnosticKind::ObjectUnreadable]);
}

#[test]
fn junk_before_header() {
    let junk = b"Content-Type: application/pdf\r\n\r\n\x00\x01 garbage\n".to_vec();
    let mut bytes = junk.clone();
    bytes.extend_from_slice(&simple_bytes());
    let store = open(&bytes);
    assert_eq!(store.header_offset(), junk.len() as u64);
    check_simple(&store);
    assert_eq!(kinds(&store), [DiagnosticKind::HeaderOffset]);
    // Stream ranges are absolute in the source.
    let obj = store.resolve(id(4)).unwrap();
    let StreamData::Source(range) = &obj.as_stream().unwrap().data else {
        panic!("not a source stream");
    };
    assert_eq!(&bytes[range.start as usize..range.end as usize], CONTENT);
    assert_eq!(store.revisions()[0].eof_end, bytes.len() as u64);
    assert_eq!(open_strict(&bytes).unwrap_err().code(), ErrorCode::Syntax);

    // A writer that counted the junk in its offsets (absolute offsets): repaired too.
    let mut pdf = Pdf::default();
    pdf.raw(&junk).raw(b"%PDF-1.6\n");
    pdf.obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .obj(3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>")
        .stream(4, "", CONTENT);
    let bytes = pdf.finish("/Root 1 0 R");
    let store = open(&bytes);
    check_simple(&store);
    assert_eq!(store.version(), (1, 6));
    assert!(has(&store, DiagnosticKind::XrefOffsetRepaired));
}

#[test]
fn missing_header_is_tolerated() {
    let bytes = simple_bytes();
    let headerless = &bytes[9..];
    // Offsets are now off by 9: the local search repairs them.
    let store = open(headerless);
    check_simple(&store);
    assert_eq!(store.version(), (1, 4));
    assert_eq!(kinds(&store)[0], DiagnosticKind::MissingHeader);
    assert_eq!(
        open_strict(headerless).unwrap_err().code(),
        ErrorCode::Syntax
    );

    // A header without a valid version: 1.4 is assumed, and that is reported.
    let mut malformed = bytes.clone();
    malformed[5..8].copy_from_slice(b"x.y");
    let store = open(&malformed);
    check_simple(&store);
    assert_eq!(store.version(), (1, 4));
    assert_eq!(kinds(&store), [DiagnosticKind::MalformedHeader]);
    let err = open_strict(&malformed).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Syntax);
    assert_eq!(err.offset(), Some(0));
}

#[test]
fn prev_loop_detected() {
    // Revision 1 (objects 1-4) whose /Prev points at revision 2, which points back.
    let mut pdf = simple_doc();
    let t1 = pdf.table("\r\n");
    pdf.raw("trailer\n<< /Size 5 /Root 1 0 R /Prev ");
    let prev_at = pdf.pos();
    pdf.raw("0000000000 >>\n").startxref(t1);
    pdf.obj(4, "(updated)");
    let t2 = pdf.table_rows(&[(4, Row::At(4))], "\r\n", None);
    pdf.raw(format!("trailer\n<< /Size 5 /Root 1 0 R /Prev {t1} >>\n"))
        .startxref(t2);
    pdf.patch(prev_at, t2);
    let store = open(&pdf.buf);
    assert_eq!(kinds(&store), [DiagnosticKind::XrefLoop]);
    assert_eq!(store.revisions().len(), 2);
    assert_eq!(
        store.resolve(id(4)).unwrap().as_str_bytes(),
        Some(&b"updated"[..])
    );
    assert!(is_type(&root(&store), b"Catalog"));
    assert_eq!(open_strict(&pdf.buf).unwrap_err().code(), ErrorCode::Xref);

    // A section whose /Prev is itself.
    let mut pdf = simple_doc();
    let at = pdf.table("\r\n");
    pdf.trailer(&format!("/Root 1 0 R /Prev {at}"))
        .startxref(at);
    let store = open(&pdf.buf);
    check_simple(&store);
    assert_eq!(kinds(&store), [DiagnosticKind::XrefLoop]);
    assert_eq!(store.revisions().len(), 1);
}

/// Revision 1 (objects 1-4), then three updates: object 5 added, 4 changed, 3 freed.
fn incremental_doc() -> (Vec<u8>, Vec<usize>, Vec<usize>) {
    let mut pdf = simple_doc();
    let mut tables = Vec::new();
    let mut ends = Vec::new();
    let t = pdf.table("\r\n");
    pdf.trailer("/Root 1 0 R").startxref(t);
    tables.push(t);
    ends.push(pdf.pos());

    pdf.obj(5, "(five)");
    let t = pdf.table_rows(&[(5, Row::At(5))], "\r\n", None);
    pdf.raw(format!(
        "trailer\n<< /Size 6 /Root 1 0 R /Prev {} >>\n",
        tables[0]
    ))
    .startxref(t);
    tables.push(t);
    ends.push(pdf.pos());

    pdf.stream(4, "", b"q 1 0 0 1 0 0 cm Q");
    let t = pdf.table_rows(&[(4, Row::At(4))], " \n", None);
    pdf.raw(format!(
        "trailer\n<< /Size 6 /Root 1 0 R /Prev {} >>\n",
        tables[1]
    ))
    .startxref(t);
    tables.push(t);
    ends.push(pdf.pos());

    let t = pdf.table_rows(&[(3, Row::Free(1))], " \r", None);
    pdf.raw(format!(
        "trailer\n<< /Size 6 /Root 1 0 R /Prev {} >>\n",
        tables[2]
    ))
    .startxref(t);
    tables.push(t);
    ends.push(pdf.pos());
    (pdf.buf, tables, ends)
}

#[test]
fn revisions_follow_the_prev_chain() {
    let (bytes, tables, ends) = incremental_doc();
    let store = open_strict(&bytes).unwrap();
    let revisions = store.revisions();
    assert_eq!(revisions.len(), 4);
    for (i, revision) in revisions.iter().enumerate() {
        assert_eq!(revision.startxref, tables[i] as u64, "revision {i}");
        assert_eq!(revision.eof_end, ends[i] as u64, "revision {i}");
        assert_eq!(revision.xref_kind, XrefKind::Table);
    }
    assert_eq!(store.trailer(), &revisions[3].trailer);
    // The newest entry wins: 4 changed, 3 freed, 5 added.
    assert_eq!(stream_of(&store, 4), b"q 1 0 0 1 0 0 cm Q");
    assert!(store.resolve(id(3)).unwrap().is_null());
    assert_eq!(store.object_ids(), [id(1), id(2), id(4), id(5)]);
    assert_eq!(
        store.resolve(id(5)).unwrap().as_str_bytes(),
        Some(&b"five"[..])
    );
    assert!(store.diagnostics().is_empty());
}

#[test]
fn max_xref_sections_cuts_the_chain() {
    let (bytes, ..) = incremental_doc();
    let limits = Limits::default().with_max_xref_sections(2);
    let store =
        Store::open_bytes(bytes.clone(), &OpenOptions::default().with_limits(limits)).unwrap();
    assert_eq!(store.revisions().len(), 2);
    assert!(has(&store, DiagnosticKind::XrefLoop));
    assert!(has(&store, DiagnosticKind::XrefReconstructed));
    // Objects only the cut sections list are recovered by the scan.
    assert!(is_type(&root(&store), b"Catalog"));
    assert_eq!(
        store.resolve(id(5)).unwrap().as_str_bytes(),
        Some(&b"five"[..])
    );
    let strict = OpenOptions::default()
        .with_limits(limits)
        .with_strictness(Strictness::Strict);
    let err = Store::open_bytes(bytes, &strict).unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);
}

#[test]
fn trailer_root_is_rebuilt() {
    // The newest trailer lacks /Root: taken from the older one.
    let (mut bytes, tables, _) = incremental_doc();
    let last = rfind(&bytes, b"/Root 1 0 R");
    bytes[last..last + 11].copy_from_slice(b"           ");
    let store = open(&bytes);
    assert_eq!(store.root_id(), Some(id(1)));
    assert!(has(&store, DiagnosticKind::TrailerRebuilt));
    assert_eq!(store.revisions()[3].startxref, tables[3] as u64);

    // No trailer has /Root: the catalog is found by scanning.
    let bytes = simple_doc().finish("/Info 2 0 R");
    let store = open(&bytes);
    assert_eq!(store.root_id(), Some(id(1)));
    assert_eq!(store.trailer().get_ref(b"Info"), Some(id(2)));
    assert_eq!(kinds(&store), [DiagnosticKind::TrailerRebuilt]);
    assert_eq!(open_strict(&bytes).unwrap_err().code(), ErrorCode::Xref);
}

#[test]
fn no_catalog_anywhere_fails() {
    for bytes in [
        &b""[..],
        b"garbage",
        b"%PDF-1.7\n1 0 obj (x) endobj\n",
        b"%PDF-1.7\nxref\n0 1\n0000000000 65535 f\r\ntrailer << >>\nstartxref\n9\n%%EOF",
    ] {
        let err = Store::open_bytes(bytes.to_vec(), &OpenOptions::default()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Xref, "{:?}", bytes.escape_ascii());
    }
}

// ---- cross-reference streams and hybrids (trap #4) -----------------------------------------

#[test]
fn xref_stream_w0_default() {
    // /W [0 2 1]: no type field, so every entry is type 1 (§7.5.8.2).
    let mut pdf = simple_doc();
    let rows: Vec<_> = (1..=4).map(|n| (n, Row::At(n))).collect();
    let at = pdf.xref_stream(5, [0, 2, 1], &rows, "/Root 1 0 R");
    pdf.startxref(at);
    let store = open_strict(&pdf.buf).unwrap();
    check_simple(&store);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Stream);
    assert!(store.trailer().is_type(b"XRef"));
    assert!(store.diagnostics().is_empty());

    // /W [1 2 0]: no generation field, so generations are 0.
    let mut pdf = simple_doc();
    let rows: Vec<_> = (1..=4).map(|n| (n, Row::At(n))).collect();
    let at = pdf.xref_stream(5, [1, 2, 0], &rows, "/Root 1 0 R");
    pdf.startxref(at);
    check_simple(&open_strict(&pdf.buf).unwrap());
}

#[test]
fn xref_stream_index_and_prev() {
    // Revision 1: an xref stream for objects 0-5. Revision 2: an xref stream with
    // /Index [4 1 7 2] (object 4 replaced, object 7 added) and /Prev.
    let mut pdf = simple_doc();
    let rows: Vec<_> = std::iter::once((0, Row::Free(255)))
        .chain((1..=4).map(|n| (n, Row::At(n))))
        .collect();
    let first = pdf.xref_stream(5, [1, 2, 1], &rows, "/Root 1 0 R");
    pdf.startxref(first);
    pdf.stream(4, "", b"0 g");
    pdf.obj(7, "(seven)");
    let second = pdf.xref_stream(
        8,
        [1, 2, 1],
        &[(4, Row::At(4)), (7, Row::At(7)), (8, Row::At(8))],
        &format!("/Root 1 0 R /Prev {first}"),
    );
    pdf.startxref(second);
    let store = open_strict(&pdf.buf).unwrap();
    assert_eq!(store.revisions().len(), 2);
    assert_eq!(stream_of(&store, 4), b"0 g");
    assert_eq!(
        store.resolve(id(7)).unwrap().as_str_bytes(),
        Some(&b"seven"[..])
    );
    assert_eq!(store.revisions()[0].startxref, first as u64);
    assert!(store.diagnostics().is_empty());
}

#[test]
fn xref_stream_errors_are_repaired_or_reported() {
    // /W with a width over 8, /Index with an odd length, /W not an array: the stream is
    // unusable, so the file is reconstructed (lenient) or refused (strict).
    for (w, index) in [("[1 9 1]", "[0 1]"), ("[1 2 1]", "[0]"), ("5", "[0 1]")] {
        let mut pdf = simple_doc();
        let at = pdf.pos();
        let data = encode_flate(b"\x01\x00\x0f\x00", 6);
        let dict = format!(
            "<< /Type /XRef /Size 6 /W {w} /Index {index} /Filter /FlateDecode /Length {} \
             /Root 1 0 R >>",
            data.len()
        );
        pdf.stream_with(5, &dict, &data);
        pdf.startxref(at);
        let store = open(&pdf.buf);
        check_simple(&store);
        assert!(
            has(&store, DiagnosticKind::XrefReconstructed),
            "{w} {index}"
        );
        assert!(open_strict(&pdf.buf).is_err(), "{w} {index}");
    }
}

/// A hybrid-reference revision on top of [`simple_doc`]: object 5 in the file, object stream 20
/// holding 10, 11 and a second 5, and the hidden cross-reference stream 30 listing all three as
/// compressed. `listed` gives the rows of the table besides objects 0-5 and 20; `extra` is added
/// to the trailer.
fn hybrid_doc(listed: &[(u32, Row)], extra: &str) -> Vec<u8> {
    let mut pdf = simple_doc();
    pdf.obj(5, "(file five)");
    pdf.objstm(
        20,
        &[(10, "(ten)"), (11, "(eleven)"), (5, "(compressed five)")],
        "",
    );
    // The hidden cross-reference stream for the compressed objects (§7.5.8.4).
    let hidden = pdf.xref_stream(
        30,
        [1, 2, 1],
        &[
            (5, Row::In(20, 2)),
            (10, Row::In(20, 0)),
            (11, Row::In(20, 1)),
        ],
        "",
    );
    let mut rows = vec![(0, Row::Free(65535))];
    rows.extend((1..=5).map(|n| (n, Row::At(n))));
    rows.extend_from_slice(listed);
    rows.push((20, Row::At(20)));
    rows.sort_by_key(|r| r.0);
    let at = pdf.table_rows(&rows, "\r\n", None);
    pdf.raw(format!(
        "trailer\n<< /Size 31 /Root 1 0 R /XRefStm {hidden} {extra} >>\n"
    ))
    .startxref(at);
    pdf.buf
}

fn str_of(store: &Store, num: u32) -> Option<Vec<u8>> {
    store
        .resolve(id(num))
        .unwrap()
        .as_str_bytes()
        .map(<[u8]>::to_vec)
}

#[test]
fn hybrid_xrefstm() {
    // The layout writers produce (§7.5.8.4): the table's subsections leave the hidden objects 10
    // and 11 out, so the search proceeds to the /XRefStm stream for them.
    let bytes = hybrid_doc(&[], "");
    let store = open_strict(&bytes).unwrap();
    check_simple(&store);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Hybrid);
    assert_eq!(str_of(&store, 10).as_deref(), Some(&b"ten"[..]));
    assert_eq!(str_of(&store, 11).as_deref(), Some(&b"eleven"[..]));
    // An object the table lists in use is taken from the table, not from the stream.
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"file five"[..]));
    assert_eq!(
        store.object_ids(),
        [1, 2, 3, 4, 5, 10, 11, 20].map(id).to_vec()
    );
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());

    // With a broken /XRefStm the table alone is used (10 is then missing), and that is reported.
    let at = find(&bytes, b"/XRefStm ") + "/XRefStm ".len();
    let mut broken = bytes.clone();
    broken[at] = b'9';
    let store = open(&broken);
    check_simple(&store);
    assert!(has(&store, DiagnosticKind::XrefMalformed));
    assert!(store.resolve(id(10)).unwrap().is_null());
}

#[test]
fn hybrid_table_free_entry_beats_its_own_xrefstm() {
    // The table of the hybrid section marks 10 free: that entry is found first, so the section's
    // /XRefStm is not consulted for 10, which is deleted (as in qpdf, poppler and pdf.js, and as
    // a reader that ignores /XRefStm sees it). 11 is not listed, so the stream supplies it.
    let bytes = hybrid_doc(&[(10, Row::Free(1))], "");
    for store in [open(&bytes), open_strict(&bytes).unwrap()] {
        check_simple(&store);
        assert!(store.resolve(id(10)).unwrap().is_null());
        assert!(store.resolve(ObjectId::new(10, 1)).unwrap().is_null());
        assert_eq!(str_of(&store, 11).as_deref(), Some(&b"eleven"[..]));
        assert!(!store.object_ids().contains(&id(10)));
        assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
    }
}

#[test]
fn hybrid_xrefstm_overrides_free_entries_of_older_sections() {
    // The note in §7.5.8.4: a hidden object has a free entry in a previous section and its real
    // entry in the newer section's /XRefStm stream; the stream wins over the older free entry.
    // `empty_table`: the update's table is `0 0`, as Word writes it, and the stream also lists
    // the container; otherwise the update's table lists the container only.
    for empty_table in [false, true] {
        let mut pdf = simple_doc();
        let rows = [
            (0, Row::Free(65535)),
            (1, Row::At(1)),
            (2, Row::At(2)),
            (3, Row::At(3)),
            (4, Row::At(4)),
            (10, Row::Free(0)),
            (11, Row::Free(0)),
        ];
        let base = pdf.table_rows(&rows, "\r\n", None);
        pdf.raw("trailer\n<< /Size 12 /Root 1 0 R >>\n")
            .startxref(base);
        pdf.objstm(20, &[(10, "(ten)"), (11, "(eleven)")], "");
        let mut hidden_rows = vec![(10, Row::In(20, 0)), (11, Row::In(20, 1))];
        if empty_table {
            hidden_rows.push((20, Row::At(20)));
        }
        let hidden = pdf.xref_stream(30, [1, 2, 1], &hidden_rows, "");
        let at = if empty_table {
            let at = pdf.pos();
            pdf.raw("xref\n0 0\n");
            at
        } else {
            pdf.table_rows(&[(20, Row::At(20))], "\r\n", None)
        };
        pdf.raw(format!(
            "trailer\n<< /Size 31 /Root 1 0 R /Prev {base} /XRefStm {hidden} >>\n"
        ))
        .startxref(at);
        let store = open_strict(&pdf.buf).unwrap();
        check_simple(&store);
        let kinds_of: Vec<_> = store.revisions().iter().map(|r| r.xref_kind).collect();
        assert_eq!(kinds_of, [XrefKind::Table, XrefKind::Hybrid]);
        assert_eq!(str_of(&store, 10).as_deref(), Some(&b"ten"[..]));
        assert_eq!(str_of(&store, 11).as_deref(), Some(&b"eleven"[..]));
        assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
    }
}

// ---- object streams (trap #5) -------------------------------------------------------------

#[test]
fn compressed_objects_resolve() {
    let store = open_strict(&compressed_doc()).unwrap();
    check_simple(&store);
    assert_eq!(store.object_ids().len(), 6);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Stream);
    // Compressed objects have generation 0 only.
    assert!(store.resolve(ObjectId::new(1, 1)).unwrap().is_null());
}

/// Containers 20 (objects 10, 11), 21 /Extends 20 (12), 22 /Extends 21 (13). The cross-reference
/// stream puts 10 in container 22 (wrong) and 14 in 22 (absent everywhere).
fn extends_doc(loop_back: bool) -> Vec<u8> {
    let mut pdf = simple_doc();
    let extends_20 = if loop_back { "/Extends 22 0 R" } else { "" };
    pdf.objstm(20, &[(10, "(ten)"), (11, "(eleven)")], extends_20)
        .objstm(21, &[(12, "(twelve)")], "/Extends 20 0 R")
        .objstm(22, &[(13, "(thirteen)")], "/Extends 21 0 R");
    let mut rows: Vec<_> = (1..=4).map(|n| (n, Row::At(n))).collect();
    rows.extend([
        (10, Row::In(22, 0)),
        (11, Row::In(20, 1)),
        (12, Row::In(21, 0)),
        (13, Row::In(22, 0)),
        (14, Row::In(22, 5)),
        (20, Row::At(20)),
        (21, Row::At(21)),
        (22, Row::At(22)),
    ]);
    let at = pdf.xref_stream(30, [1, 2, 1], &rows, "/Root 1 0 R");
    pdf.startxref(at);
    pdf.buf
}

#[test]
fn objstm_extends_chain() {
    let store = open(&extends_doc(false));
    check_simple(&store);
    for (num, text) in [(11, "eleven"), (12, "twelve"), (13, "thirteen")] {
        assert_eq!(
            store.resolve(id(num)).unwrap().as_str_bytes(),
            Some(text.as_bytes())
        );
    }
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
    // 10 is not where the cross-reference stream says: found by following /Extends 22 → 21 → 20.
    assert_eq!(
        store.resolve(id(10)).unwrap().as_str_bytes(),
        Some(&b"ten"[..])
    );
    assert_eq!(kinds(&store), [DiagnosticKind::ObjectStream]);
    // 14 is nowhere: null.
    assert!(store.resolve(id(14)).unwrap().is_null());
    assert!(has(&store, DiagnosticKind::ObjectUnreadable));
    // Diagnostics about compressed objects carry no file offset.
    assert!(store.diagnostics().iter().all(|d| d.offset.is_none()));
    // Strict mode refuses the misplaced object.
    let strict = open_strict(&extends_doc(false)).unwrap();
    assert_eq!(
        strict.resolve(id(13)).unwrap().as_str_bytes(),
        Some(&b"thirteen"[..])
    );
    assert!(strict.resolve(id(10)).is_err());

    // A loop in /Extends (20 → 22 → 21 → 20) is detected.
    let store = open(&extends_doc(true));
    within(10, move || {
        assert_eq!(
            store.resolve(id(10)).unwrap().as_str_bytes(),
            Some(&b"ten"[..])
        );
        assert!(store.resolve(id(14)).unwrap().is_null());
        let messages: Vec<String> = store.diagnostics().into_iter().map(|d| d.message).collect();
        assert!(messages.iter().any(|m| m.contains("loops")), "{messages:?}");
    });
}

#[test]
fn objstm_validation() {
    // /N or /First broken: the members are unreadable (null in lenient mode).
    for dict in [
        "/Type /ObjStm /N -1 /First 4",
        "/Type /ObjStm /N 1 /First 999",
        "/Type /ObjStm /First 4",
    ] {
        let mut pdf = simple_doc();
        pdf.stream(20, dict, b"10 0 (ten)");
        let rows: Vec<_> = (1..=4)
            .map(|n| (n, Row::At(n)))
            .chain([(10, Row::In(20, 0)), (20, Row::At(20))])
            .collect();
        let at = pdf.xref_stream(30, [1, 2, 1], &rows, "/Root 1 0 R");
        pdf.startxref(at);
        let store = open(&pdf.buf);
        assert!(store.resolve(id(10)).unwrap().is_null(), "{dict}");
        assert_eq!(kinds(&store), [DiagnosticKind::ObjectUnreadable], "{dict}");
        let strict = open_strict(&pdf.buf).unwrap();
        assert!(strict.resolve(id(10)).is_err(), "{dict}");
    }
    // A container that is not a stream, or is itself compressed, is unusable.
    let mut pdf = simple_doc();
    pdf.obj(20, "<< /Type /ObjStm /N 1 /First 5 >>");
    let rows: Vec<_> = (1..=4)
        .map(|n| (n, Row::At(n)))
        .chain([
            (10, Row::In(20, 0)),
            (11, Row::In(12, 0)),
            (12, Row::In(20, 1)),
            (20, Row::At(20)),
        ])
        .collect();
    let at = pdf.xref_stream(30, [1, 2, 1], &rows, "/Root 1 0 R");
    pdf.startxref(at);
    let store = open(&pdf.buf);
    assert!(store.resolve(id(10)).unwrap().is_null());
    assert!(store.resolve(id(11)).unwrap().is_null());
    assert_eq!(kinds(&store), [DiagnosticKind::ObjectUnreadable; 2]);
}

// ---- stream lengths (trap #1) ---------------------------------------------------------------

#[test]
fn stream_length_wrong_recovers_through_store() {
    for length in ["5", "9999", "-1", "/Foo"] {
        let mut pdf = simple_doc();
        pdf.stream_with(4, &format!("<< /Length {length} >>"), CONTENT);
        let bytes = pdf.finish("/Root 1 0 R");
        let store = open(&bytes);
        assert_eq!(stream_of(&store, 4), CONTENT, "/Length {length}");
        assert_eq!(
            kinds(&store),
            [DiagnosticKind::StreamLength],
            "/Length {length}"
        );
        let strict = open_strict(&bytes).unwrap();
        assert_eq!(strict.resolve(id(4)).unwrap_err().code(), ErrorCode::Syntax);
    }
}

#[test]
fn length_indirect_cycle() {
    let mut pdf = simple_doc();
    // A normal indirect /Length.
    pdf.stream_with(5, "<< /Length 6 0 R >>", b"hello")
        .obj(6, "5");
    // A stream whose /Length is itself.
    pdf.stream_with(7, "<< /Length 7 0 R >>", b"self");
    // A /Length behind a reference cycle 9 → 10 → 9.
    pdf.stream_with(8, "<< /Length 9 0 R >>", b"cycle")
        .obj(9, "10 0 R")
        .obj(10, "9 0 R");
    // Two streams whose lengths are each other.
    pdf.stream_with(11, "<< /Length 12 0 R >>", b"left")
        .stream_with(12, "<< /Length 11 0 R >>", b"right");
    let bytes = pdf.finish("/Root 1 0 R");

    let store = Arc::new(open(&bytes));
    let shared = Arc::clone(&store);
    within(10, move || {
        assert_eq!(stream_of(&shared, 5), b"hello");
        assert!(
            shared.diagnostics().is_empty(),
            "{:?}",
            shared.diagnostics()
        );
        for (num, data) in [
            (7, &b"self"[..]),
            (8, b"cycle"),
            (11, b"left"),
            (12, b"right"),
        ] {
            assert_eq!(stream_of(&shared, num), data, "object {num}");
        }
    });
    assert_eq!(kinds(&store), [DiagnosticKind::StreamLength; 4]);
    let strict = open_strict(&bytes).unwrap();
    assert_eq!(stream_of(&strict, 5), b"hello");
    assert!(strict.resolve(id(7)).is_err());

    // Racing threads on the mutual pair must not deadlock (nested loads never wait).
    for _ in 0..20 {
        let store = Arc::new(open(&bytes));
        within(10, move || {
            let handles: Vec<_> = [11, 12, 11, 12]
                .into_iter()
                .map(|num| {
                    let store = Arc::clone(&store);
                    std::thread::spawn(move || stream_of(&store, num))
                })
                .collect();
            for handle in handles {
                assert!(!handle.join().unwrap().is_empty());
            }
        });
    }

    // An object stream whose /Length is one of its own members.
    let mut pdf = simple_doc();
    let (data, first) = objstm_data(&[(21, "5"), (22, "(inside)")]);
    let encoded = encode_flate(&data, 6);
    let dict =
        format!("<< /Type /ObjStm /N 2 /First {first} /Filter /FlateDecode /Length 21 0 R >>");
    pdf.stream_with(20, &dict, &encoded);
    let rows: Vec<_> = (1..=4)
        .map(|n| (n, Row::At(n)))
        .chain([
            (20, Row::At(20)),
            (21, Row::In(20, 0)),
            (22, Row::In(20, 1)),
        ])
        .collect();
    let at = pdf.xref_stream(30, [1, 2, 1], &rows, "/Root 1 0 R");
    pdf.startxref(at);
    let store = open(&pdf.buf);
    within(10, move || {
        assert_eq!(
            store.resolve(id(22)).unwrap().as_str_bytes(),
            Some(&b"inside"[..])
        );
        assert_eq!(store.resolve(id(21)).unwrap().as_int(), Some(5));
        assert_eq!(kinds(&store), [DiagnosticKind::StreamLength]);
    });
}

#[test]
fn hostile_streams_without_endstream_stay_linear() {
    // 30,000 streams with a wrong /Length and no `endstream` or `endobj` anywhere after them.
    // Searching the rest of the file for each would be quadratic (~10^10 byte comparisons);
    // the lazily built keyword index answers each search in O(log n).
    const N: u32 = 30_000;
    let mut pdf = Pdf::new();
    pdf.obj(1, "<< /Type /Catalog >>");
    for num in 2..N {
        pdf.objects.insert(num, (pdf.pos(), 0));
        pdf.raw(format!("{num} 0 obj\n<< /Length 999999 >>\nstream\nxx\n"));
    }
    let bytes = pdf.finish("/Root 1 0 R");
    let store = open(&bytes);
    for num in 2..N {
        assert!(store.resolve(id(num)).unwrap().as_stream().is_some());
    }
    assert!(store.dropped_diagnostics() > 0, "diagnostics are capped");
    // The same file without its cross-reference table is reconstructed in linear time too.
    let cut = rfind(&bytes, b"xref\n");
    let store = open(&bytes[..cut]);
    assert_eq!(store.object_ids().len(), N as usize - 1);
    assert!(is_type(&root(&store), b"Catalog"));
}

// ---- reconstruction ------------------------------------------------------------------------

#[test]
fn missing_xref_full_reconstruct() {
    // Objects and a trailer, but no table and no startxref.
    let mut pdf = simple_doc();
    pdf.trailer("/Root 1 0 R /Info 2 0 R");
    let store = open(&pdf.buf);
    check_simple(&store);
    assert_eq!(kinds(&store), [DiagnosticKind::XrefReconstructed]);
    assert_eq!(store.revisions().len(), 1);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
    assert_eq!(store.trailer().get_ref(b"Info"), Some(id(2)));
    assert_eq!(store.object_ids(), [id(1), id(2), id(3), id(4)]);
    assert_eq!(open_strict(&pdf.buf).unwrap_err().code(), ErrorCode::Xref);

    // No trailer either: the catalog is found and the trailer rebuilt.
    let pdf = simple_doc();
    let store = open(&pdf.buf);
    check_simple(&store);
    assert_eq!(
        kinds(&store),
        [
            DiagnosticKind::XrefReconstructed,
            DiagnosticKind::TrailerRebuilt
        ]
    );
    assert_eq!(store.trailer().get_int(b"Size"), Some(5));
    assert_eq!(&store.revisions()[0].trailer, store.trailer());

    // A later definition of an object wins (an unrecorded incremental update).
    let mut pdf = simple_doc();
    pdf.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 /Updated true >>");
    let store = open(&pdf.buf);
    let pages = store.resolve(id(2)).unwrap();
    assert_eq!(pages.as_dict().unwrap().get_bool(b"Updated"), Some(true));

    // Compressed objects: the object streams found by the scan are decoded, and the catalog is
    // found inside one.
    let bytes = compressed_doc();
    let xref_obj = rfind(&bytes, b"6 0 obj");
    let store = open(&bytes[..xref_obj]);
    check_simple(&store);
    assert!(has(&store, DiagnosticKind::TrailerRebuilt));
    assert_eq!(store.object_ids().len(), 5);

    // The damaged cross-reference stream still serves as the trailer.
    let mut damaged = bytes.clone();
    let start = xref_obj + find(&bytes[xref_obj..], b"stream\n") + "stream\n".len();
    for b in &mut damaged[start..start + 6] {
        *b = b'!';
    }
    let store = open(&damaged);
    check_simple(&store);
    assert_eq!(
        kinds(&store),
        [
            DiagnosticKind::XrefMalformed,
            DiagnosticKind::XrefReconstructed
        ]
    );
}

#[test]
fn encrypted_returns_password_required() {
    let encrypt = "<< /Filter /Standard /V 2 /R 3 /Length 128 /O <00> /U <00> /P -4 >>";
    // Direct /Encrypt.
    let bytes = simple_doc().finish(&format!("/Root 1 0 R /Encrypt {encrypt} /ID [<01> <01>]"));
    for strictness in [Strictness::Lenient, Strictness::Strict] {
        let err = Store::open_bytes(bytes.clone(), &options(strictness)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::PasswordRequired, "{err}");
    }
    // Indirect /Encrypt.
    let mut pdf = simple_doc();
    pdf.obj(9, encrypt);
    let err = Store::open_bytes(
        pdf.finish("/Root 1 0 R /Encrypt 9 0 R"),
        &OpenOptions::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::PasswordRequired);
    // Another security handler.
    let bytes = simple_doc().finish("/Root 1 0 R /Encrypt << /Filter /Adobe.PubSec /V 4 >>");
    let err = Store::open_bytes(bytes, &OpenOptions::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);
    // Unusable /Encrypt values.
    for value in ["<< /V 2 >>", "42", "99 0 R"] {
        let bytes = simple_doc().finish(&format!("/Root 1 0 R /Encrypt {value}"));
        let err = Store::open_bytes(bytes, &OpenOptions::default()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported, "{value}");
    }
    // `/Encrypt null` is no encryption.
    check_simple(&open(&simple_doc().finish("/Root 1 0 R /Encrypt null")));
    // The catalog in an object stream whose (encrypted) data cannot be decoded: encryption is
    // reported before the catalog is looked at.
    let mut pdf = simple_doc();
    pdf.stream(
        9,
        "/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode",
        b"\x8e\x01ciphertext",
    );
    pdf.obj(10, encrypt);
    let mut rows: Vec<_> = (2..=4).map(|n| (n, Row::At(n))).collect();
    rows.insert(0, (1, Row::In(9, 0)));
    rows.extend([(9, Row::At(9)), (10, Row::At(10))]);
    let at = pdf.xref_stream(11, [1, 2, 1], &rows, "/Root 1 0 R /Encrypt 10 0 R");
    pdf.startxref(at);
    let err = Store::open_bytes(pdf.buf, &OpenOptions::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::PasswordRequired);
    // A reconstructed encrypted file is still recognised.
    let mut pdf = simple_doc();
    pdf.trailer(&format!("/Root 1 0 R /Encrypt {encrypt}"));
    let err = Store::open_bytes(pdf.buf, &OpenOptions::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::PasswordRequired);
}

// ---- stream data and filters ----------------------------------------------------------------

/// A document with stream 5 given by `dict` and `data`, plus any extra objects.
fn with_stream(dict: &str, data: &[u8], extra: &[(u32, &str)]) -> Vec<u8> {
    let mut pdf = simple_doc();
    pdf.stream(5, dict, data);
    for (num, body) in extra {
        pdf.obj(*num, body);
    }
    pdf.finish("/Root 1 0 R")
}

/// Two rows of three bytes with the PNG "Up" predictor tag, and their decoded form.
const PNG_ROWS: &[u8] = &[2, 1, 2, 3, 2, 1, 1, 1];
const PNG_DECODED: &[u8] = &[1, 2, 3, 2, 3, 4];

#[test]
fn decode_parms_variants() {
    let flate = encode_flate(PNG_ROWS, 6);
    let parms = "<< /Predictor 12 /Columns 3 >>";
    // A single dictionary.
    let store = open(&with_stream(
        &format!("/Filter /FlateDecode /DecodeParms {parms}"),
        &flate,
        &[],
    ));
    assert_eq!(stream_of(&store, 5), PNG_DECODED);
    // An array with a null for the first filter.
    let hex = encode_ascii_hex(&flate);
    let store = open(&with_stream(
        &format!("/Filter [/ASCIIHexDecode /FlateDecode] /DecodeParms [null {parms}]"),
        &hex,
        &[],
    ));
    assert_eq!(stream_of(&store, 5), PNG_DECODED);
    // A short array: missing entries are defaults.
    let store = open(&with_stream(
        "/Filter [/ASCIIHexDecode /FlateDecode] /DecodeParms [null]",
        &hex,
        &[],
    ));
    assert_eq!(stream_of(&store, 5), PNG_ROWS);
    // Missing /DecodeParms.
    let store = open(&with_stream("/Filter /FlateDecode", &flate, &[]));
    assert_eq!(stream_of(&store, 5), PNG_ROWS);
    // References for /Filter, /DecodeParms and a value inside it.
    let store = open(&with_stream(
        "/Filter 6 0 R /DecodeParms 7 0 R",
        &flate,
        &[
            (6, "/FlateDecode"),
            (7, "<< /Predictor 12 /Columns 8 0 R >>"),
            (8, "3"),
        ],
    ));
    assert_eq!(stream_of(&store, 5), PNG_DECODED);
    // A lone dictionary for a chain applies to each filter (only Flate reads it).
    let store = open(&with_stream(
        &format!("/Filter [/ASCIIHexDecode /FlateDecode] /DecodeParms {parms}"),
        &hex,
        &[],
    ));
    assert_eq!(stream_of(&store, 5), PNG_DECODED);
    assert!(store.diagnostics().is_empty());
}

#[test]
fn invalid_decode_parms_are_filter_errors() {
    let flate = encode_flate(PNG_ROWS, 6);
    for parms in [
        "<< /Predictor 300 >>",
        "<< /Predictor -1 >>",
        "<< /Colors 256 >>",
        "<< /BitsPerComponent 1000 >>",
        "<< /Columns -3 >>",
        "<< /Columns 99999999999 >>",
        "<< /Predictor /Up >>",
        "<< /Predictor 99 >>",
        "5",
        "[5]",
    ] {
        let store = open(&with_stream(
            &format!("/Filter /FlateDecode /DecodeParms {parms}"),
            &flate,
            &[],
        ));
        let obj = store.resolve(id(5)).unwrap();
        let err = store.stream_data(obj.as_stream().unwrap()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Filter, "{parms}: {err}");
        assert!(matches!(err, Error::Filter { .. }), "{parms}: {err:?}");
    }
    // /EarlyChange must be 0 or 1 (LZW only).
    let store = open(&with_stream(
        "/Filter /LZWDecode /DecodeParms << /EarlyChange 2 >>",
        b"\x80",
        &[],
    ));
    let obj = store.resolve(id(5)).unwrap();
    assert_eq!(
        store
            .stream_data(obj.as_stream().unwrap())
            .unwrap_err()
            .code(),
        ErrorCode::Filter
    );
    // Parameters of filters that do not use them are ignored.
    let store = open(&with_stream(
        "/Filter /ASCIIHexDecode /DecodeParms << /Predictor 300 >>",
        b"414243>",
        &[],
    ));
    assert_eq!(stream_of(&store, 5), b"ABC");
}

#[test]
fn filter_chain_errors_and_passthrough() {
    let get = |dict: &str, data: &[u8]| {
        let store = open(&with_stream(dict, data, &[]));
        let obj = store.resolve(id(5)).unwrap();
        (store.stream_data(obj.as_stream().unwrap()), kinds(&store))
    };
    // Image filters stay applied.
    let (out, _) = get("/Filter [/ASCIIHexDecode /DCTDecode]", b"FFD8FF>");
    let out = out.unwrap();
    assert_eq!(out.data, [0xFF, 0xD8, 0xFF]);
    assert_eq!(out.remaining, [Filter::Dct]);
    assert!(!out.is_fully_decoded());
    // Unknown filters are unsupported; malformed /Filter values are filter errors.
    assert_eq!(
        get("/Filter /Foo", b"x").0.unwrap_err().code(),
        ErrorCode::Unsupported
    );
    assert_eq!(
        get("/Filter 5", b"x").0.unwrap_err().code(),
        ErrorCode::Filter
    );
    assert_eq!(
        get("/Filter [5]", b"x").0.unwrap_err().code(),
        ErrorCode::Filter
    );
    let long = format!("/Filter [{}]", "/AHx ".repeat(17));
    assert_eq!(
        get(&long, b"x").0.unwrap_err().code(),
        ErrorCode::LimitExceeded
    );
    // Corrupt data is a filter error with the stream's offset.
    let err = get("/Filter /FlateDecode", b"not zlib at all")
        .0
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Filter);
    assert!(err.offset().is_some());
    // A /Crypt filter other than /Identity in an unencrypted file: identity plus a diagnostic.
    let (out, diags) = get("/Filter /Crypt /DecodeParms << /Name /StdCF >>", b"plain");
    assert_eq!(out.unwrap().data, b"plain");
    assert_eq!(diags, [DiagnosticKind::CryptFilterIgnored]);
    let (out, diags) = get(
        "/Filter [/Crypt] /DecodeParms [<< /Name /Identity >>]",
        b"plain",
    );
    assert_eq!(out.unwrap().data, b"plain");
    assert!(diags.is_empty());
    let strict = open_strict(&with_stream(
        "/Filter /Crypt /DecodeParms << /Name /StdCF >>",
        b"plain",
        &[],
    ))
    .unwrap();
    let obj = strict.resolve(id(5)).unwrap();
    assert_eq!(
        strict
            .stream_data(obj.as_stream().unwrap())
            .unwrap_err()
            .code(),
        ErrorCode::Filter
    );
}

#[test]
fn truncated_stream_is_diagnostic_or_error() {
    let text: Vec<u8> = (0..20_000u32).flat_map(|i| i.to_le_bytes()).collect();
    let flate = encode_flate(&text, 6);
    let cut = &flate[..flate.len() / 2];
    let bytes = with_stream("/Filter /FlateDecode", cut, &[]);
    let store = open(&bytes);
    let obj = store.resolve(id(5)).unwrap();
    let out = store.stream_data(obj.as_stream().unwrap()).unwrap();
    assert!(out.truncated);
    assert!(!out.data.is_empty() && text.starts_with(&out.data));
    assert_eq!(kinds(&store), [DiagnosticKind::FilterTruncated]);
    let strict = open_strict(&bytes).unwrap();
    let obj = strict.resolve(id(5)).unwrap();
    let err = strict.stream_data(obj.as_stream().unwrap()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Filter);
}

#[test]
fn capped_decode_stops_at_the_callers_cap() {
    let data = vec![b'a'; 100_000];
    let flate = encode_flate(&data, 6);
    let bytes = with_stream("/Filter /FlateDecode", &flate, &[]);
    let store = Store::open_bytes(bytes, &OpenOptions::default()).unwrap();
    let obj = store.resolve(id(5)).unwrap();
    let stream = obj.as_stream().unwrap();
    // Below the cap: the data. Above it: `None`, and only the cap was paid for.
    let full = store.stream_data_capped(stream, 100_000).unwrap().unwrap();
    assert_eq!(full.data, data);
    let fresh = Store::open_bytes(
        with_stream("/Filter /FlateDecode", &flate, &[]),
        &OpenOptions::default(),
    )
    .unwrap();
    let obj = fresh.resolve(id(5)).unwrap();
    assert!(
        fresh
            .stream_data_capped(obj.as_stream().unwrap(), 1000)
            .unwrap()
            .is_none()
    );
    assert!(fresh.total_decoded() <= 1000, "{}", fresh.total_decoded());
    // The document limit still applies when it is the smaller one.
    let limits = Limits::default().with_max_decoded_stream(100);
    let small = Store::open_bytes(
        with_stream("/Filter /FlateDecode", &flate, &[]),
        &OpenOptions::default().with_limits(limits),
    )
    .unwrap();
    let obj = small.resolve(id(5)).unwrap();
    let err = small
        .stream_data_capped(obj.as_stream().unwrap(), 1_000_000)
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);
}

#[test]
fn decode_limits_are_enforced() {
    let data = vec![b'a'; 1000];
    let flate = encode_flate(&data, 6);
    let bytes = with_stream("/Filter /FlateDecode", &flate, &[]);
    // Per stream.
    let limits = Limits::default().with_max_decoded_stream(100);
    let store =
        Store::open_bytes(bytes.clone(), &OpenOptions::default().with_limits(limits)).unwrap();
    let obj = store.resolve(id(5)).unwrap();
    let err = store.stream_data(obj.as_stream().unwrap()).unwrap_err();
    assert!(
        matches!(
            err,
            Error::LimitExceeded {
                limit: LimitKind::MaxDecodedStream,
                max: 100,
                ..
            }
        ),
        "{err:?}"
    );
    // Per document: each stream of the source counts once, so decoding the same stream again
    // (an editor re-reading page content) is free, and a second stream exceeds the total.
    let limits = Limits::default().with_max_total_decoded(1500);
    let mut pdf = simple_doc();
    pdf.stream(5, "/Filter /FlateDecode", &flate)
        .stream(6, "/Filter /FlateDecode", &flate);
    let two = pdf.finish("/Root 1 0 R");
    let store = Store::open_bytes(two, &OpenOptions::default().with_limits(limits)).unwrap();
    let obj = store.resolve(id(5)).unwrap();
    let stream = obj.as_stream().unwrap();
    for _ in 0..100 {
        assert_eq!(store.stream_data(stream).unwrap().data.len(), 1000);
    }
    assert_eq!(store.total_decoded(), 1000);
    let other = store.resolve(id(6)).unwrap();
    let err = store.stream_data(other.as_stream().unwrap()).unwrap_err();
    assert!(
        matches!(
            err,
            Error::LimitExceeded {
                limit: LimitKind::MaxTotalDecoded,
                ..
            }
        ),
        "{err:?}"
    );
    // The failed decode used up the rest of the budget...
    assert_eq!(store.total_decoded(), 1500);
    // ...but what was decoded before is still available.
    assert_eq!(store.stream_data(stream).unwrap().data.len(), 1000);
    // Data the caller supplies is bounded per stream only.
    let mut dict = Dict::new();
    dict.insert("Filter", Object::name("FlateDecode"));
    let owned = Stream::new(dict, StreamData::Encoded(flate.clone()));
    for _ in 0..3 {
        assert_eq!(store.stream_data(&owned).unwrap().data.len(), 1000);
    }
    assert_eq!(store.total_decoded(), 1500);
    // A stream that stops at the per-stream limit is charged what it was allowed to produce,
    // so many bombs cannot each cost a full decode for free.
    let limits = Limits::default()
        .with_max_decoded_stream(400)
        .with_max_total_decoded(1000);
    let mut pdf = simple_doc();
    for num in 5..10 {
        pdf.stream(num, "/Filter /FlateDecode", &flate);
    }
    let store = Store::open_bytes(
        pdf.finish("/Root 1 0 R"),
        &OpenOptions::default().with_limits(limits),
    )
    .unwrap();
    let codes: Vec<_> = (5..10)
        .map(|num| {
            let obj = store.resolve(id(num)).unwrap();
            match store.stream_data(obj.as_stream().unwrap()) {
                Err(Error::LimitExceeded { limit, .. }) => limit,
                other => panic!("{other:?}"),
            }
        })
        .collect();
    assert_eq!(
        codes,
        [
            LimitKind::MaxDecodedStream,
            LimitKind::MaxDecodedStream,
            LimitKind::MaxTotalDecoded,
            LimitKind::MaxTotalDecoded,
            LimitKind::MaxTotalDecoded
        ]
    );
    assert_eq!(store.total_decoded(), 1000);
    // Unfiltered data counts too.
    let limits = Limits::default().with_max_decoded_stream(10);
    let store =
        Store::open_bytes(simple_bytes(), &OpenOptions::default().with_limits(limits)).unwrap();
    let obj = store.resolve(id(4)).unwrap();
    assert_eq!(
        store
            .stream_data(obj.as_stream().unwrap())
            .unwrap_err()
            .code(),
        ErrorCode::LimitExceeded
    );
    // A limit hit while decoding a cross-reference stream surfaces even in lenient mode.
    let limits = Limits::default().with_max_decoded_stream(16);
    let err = Store::open_bytes(
        compressed_doc(),
        &OpenOptions::default().with_limits(limits),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);
}

#[test]
fn raw_and_owned_stream_data() {
    let store = open(&simple_bytes());
    let foreign = Stream::new(Dict::new(), StreamData::Source(10..100_000));
    assert_eq!(
        store.raw_stream_data(&foreign).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    let mut dict = Dict::new();
    dict.insert("Filter", Object::name("FlateDecode"));
    let decoded = Stream::new(dict, StreamData::Decoded(b"plain".to_vec()));
    assert_eq!(&*store.raw_stream_data(&decoded).unwrap(), b"plain");
    assert_eq!(store.stream_data(&decoded).unwrap().data, b"plain");
    let mut dict = Dict::new();
    dict.insert("Filter", Object::name("ASCIIHexDecode"));
    let encoded = Stream::new(dict, StreamData::Encoded(b"6869>".to_vec()));
    assert_eq!(store.stream_data(&encoded).unwrap().data, b"hi");
    assert_eq!(&*store.raw_stream_data(&encoded).unwrap(), b"6869>");
}

// ---- laziness and robustness ----------------------------------------------------------------

/// A flat page tree with `pages` pages, each with its own content stream.
fn many_pages(pages: u32) -> Vec<u8> {
    let mut pdf = Pdf::new();
    let kids: String = (0..pages).map(|k| format!("{} 0 R ", 4 + 2 * k)).collect();
    pdf.obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .obj(
            2,
            &format!("<< /Type /Pages /Count {pages} /Kids [{kids}] >>"),
        )
        .obj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
    for k in 0..pages {
        pdf.obj(
            4 + 2 * k,
            &format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
                 /Resources << /Font << /F1 3 0 R >> >> /Contents {} 0 R >>",
                5 + 2 * k
            ),
        );
        pdf.stream(
            5 + 2 * k,
            "",
            format!("BT /F1 12 Tf 72 720 Td (Page {k}) Tj ET").as_bytes(),
        );
    }
    pdf.finish("/Root 1 0 R")
}

#[test]
fn open_is_lazy() {
    let bytes = many_pages(2000);
    let store = open_strict(&bytes).unwrap();
    // Opening parses the catalog only (to check it); resolving it again is free.
    assert_eq!(store.parsed_object_count(), 1);
    assert!(is_type(&root(&store), b"Catalog"));
    assert!(store.parsed_object_count() < 50);
    assert_eq!(store.parsed_object_count(), 1);
    assert_eq!(store.object_ids().len(), 4003);
    // A page deep in the tree costs one more parse.
    assert!(is_type(&store.resolve(id(4 + 2 * 1999)).unwrap(), b"Page"));
    assert_eq!(store.parsed_object_count(), 2);
}

/// Opens `bytes` and touches everything: no panic is the only requirement.
fn exercise(bytes: &[u8], strictness: Strictness) {
    let Ok(store) = Store::open_bytes(bytes.to_vec(), &options(strictness)) else {
        return;
    };
    for id in store.object_ids() {
        if let Ok(obj) = store.resolve(id) {
            if let Object::Stream(stream) = &*obj {
                let _ = store.stream_data(stream);
                let _ = store.raw_stream_data(stream);
            }
            let _ = store.deref(&Object::Ref(id));
        }
    }
    let _ = store.diagnostics();
}

#[test]
fn mutated_inputs_never_panic() {
    let (incremental, ..) = incremental_doc();
    let fixtures = [
        simple_bytes(),
        compressed_doc(),
        incremental,
        extends_doc(true),
        with_stream(
            "/Filter [/ASCIIHexDecode /FlateDecode] /DecodeParms [null << /Predictor 12 /Columns 3 >>]",
            &encode_ascii_hex(&encode_flate(PNG_ROWS, 6)),
            &[],
        ),
    ];
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for base in &fixtures {
        for _ in 0..250 {
            let mut bytes = base.clone();
            let len = bytes.len();
            match next() % 4 {
                0 => {
                    for _ in 0..1 + next() % 4 {
                        let at = next() as usize % len;
                        bytes[at] ^= 1 << (next() % 8);
                    }
                }
                1 => bytes.truncate(next() as usize % len),
                2 => {
                    let at = next() as usize % len;
                    bytes.insert(at, next() as u8);
                }
                _ => {
                    let from = next() as usize % len;
                    let chunk = bytes[from..(from + 64).min(len)].to_vec();
                    let at = next() as usize % len;
                    bytes.splice(at..at, chunk);
                }
            }
            exercise(&bytes, Strictness::Lenient);
            exercise(&bytes, Strictness::Strict);
        }
    }
}

/// How [`overlapping_doc`] nests each object inside the previous one.
#[derive(Clone, Copy, Debug)]
enum Overlap {
    /// `N 0 obj %`: every header is inside the previous object's comment (one long line).
    Comment,
    /// `N 0 obj (`: every header is inside the previous object's (unterminated) string.
    String,
    /// `N 0 obj << /Length 999999999 >> stream`: every header is inside the previous object's
    /// stream data, and only the last stream has an `endstream`.
    Stream,
}

/// A hostile file whose objects 2..`count` overlap: each one's header lies inside the previous
/// object, and the cross-reference table points at every header. A megabyte of padding follows
/// the last header, so that an object whose parse ran on to the end of the enclosing objects
/// would cost about a megabyte: `count` of them, gigabytes. `skew` is added to every recorded
/// offset; `junk` extra entries per object point inside its header (at no header of theirs).
fn overlapping_doc(kind: Overlap, count: u32, skew: i64, junk: u32) -> Vec<u8> {
    const PAD: usize = 1 << 20;
    let mut pdf = Pdf::new();
    pdf.obj(1, "<< /Type /Catalog >>");
    let opening = match kind {
        Overlap::Comment => "%",
        Overlap::String => "(",
        Overlap::Stream => "<< /Length 999999999 >> stream\n",
    };
    for num in 2..count {
        pdf.objects.insert(num, (pdf.pos(), 0));
        pdf.raw(format!("{num} 0 obj {opening} "));
    }
    pdf.raw(vec![b'x'; PAD]);
    pdf.raw(match kind {
        Overlap::Comment => "\n42\nendobj\n".to_owned(),
        Overlap::String => format!("{}\nendobj\n", ")".repeat(count as usize)),
        Overlap::Stream => "\nendstream\nendobj\n".to_owned(),
    });
    for num in 2..count {
        let (at, _) = pdf.objects[&num];
        for j in 0..junk {
            pdf.objects
                .insert(count + num * junk + j, (at + 1 + j as usize, 0));
        }
    }
    for entry in pdf.objects.values_mut() {
        entry.0 = (entry.0 as i64 + skew) as usize;
    }
    pdf.finish("/Root 1 0 R")
}

#[test]
fn overlapping_objects_resolve_in_linear_time() {
    // Every object's parse is bounded by the next object's position (`Store::region_end`), so
    // resolving every object and decoding every stream reads each byte a bounded number of
    // times. Unbounded, each of these files would cost tens of gigabytes of lexing or copying.
    for (kind, count, skew, junk) in [
        (Overlap::Comment, 20_000, 0, 0),
        (Overlap::String, 20_000, 0, 0),
        (Overlap::Stream, 20_000, 0, 0),
        // Every offset 3 bytes early: each object is found by the local search, and the next
        // object's position is checked after the same shift.
        (Overlap::Comment, 20_000, -3, 0),
        // Positions inside each header that hold no header of their own: the next positions
        // cannot be checked, so the next header found by the scan bounds each object.
        (Overlap::String, 5_000, 0, 8),
    ] {
        let bytes = overlapping_doc(kind, count, skew, junk);
        let len = bytes.len() as u64;
        within(60, move || {
            let started = std::time::Instant::now();
            let store = open(&bytes);
            let mut raw = 0u64;
            let mut values = 0usize;
            for object_id in store.object_ids() {
                let obj = store.resolve(object_id).unwrap();
                match &*obj {
                    Object::Stream(stream) => {
                        raw += store.raw_stream_data(stream).unwrap().len() as u64;
                        store.stream_data(stream).unwrap();
                    }
                    Object::Null => {}
                    _ => values += 1,
                }
            }
            // Only the catalog and the last object, which really ends in the padding, have a
            // value; every other object's region ends before its value does.
            let expected = match kind {
                Overlap::Stream => 1,
                _ => 2,
            };
            assert_eq!(values, expected, "{kind:?} {skew} {junk}");
            // Every stream's data stays within its own region.
            assert!(raw <= len, "{kind:?}: {raw} bytes of stream data in {len}");
            assert!(store.total_decoded() <= len);
            // A table that can be checked needs no scan of the file (streams without
            // `endstream` need one anyway, as the keyword index).
            if !matches!(kind, Overlap::Stream) {
                assert_eq!(
                    store.scan.get().is_some(),
                    junk > 0,
                    "{kind:?} {skew} {junk}"
                );
            }
            eprintln!("{kind:?} skew {skew} junk {junk}: {:?}", started.elapsed());
        });
    }
}

#[test]
fn objects_end_where_the_next_one_starts() {
    // A well-formed object is never cut: its region ends at the next object.
    let bytes = simple_bytes();
    let store = open_strict(&bytes).unwrap();
    for (num, next) in [(1u32, b"2 0 obj".as_slice()), (3, b"4 0 obj"), (4, b"xref")] {
        let Some(Location::InFile { pos }) = store.location(num) else {
            panic!("{num} is not in the file");
        };
        let end = store.region_end(pos as usize, pos);
        assert!(bytes[end..].starts_with(next), "object {num} ends at {end}");
    }
    check_simple(&store);
    assert!(store.scan.get().is_none());

    // An entry that points at the wrong place does not cut the object before it.
    let mut pdf = simple_doc();
    pdf.objects.get_mut(&3).unwrap().0 -= 9;
    let bytes = pdf.finish("/Root 1 0 R");
    let store = open(&bytes);
    let Some(Location::InFile { pos }) = store.location(2) else {
        panic!("2 is not in the file");
    };
    let end = store.region_end(pos as usize, pos);
    assert!(
        bytes[end..].starts_with(b"4 0 obj"),
        "object 2 ends at {end}"
    );
    check_simple(&store);
    assert_eq!(kinds(&store), [DiagnosticKind::XrefOffsetRepaired]);
    assert!(store.scan.get().is_none());

    // An entry that points inside another object's header (`12 0 obj` read from its second
    // digit is `2 0 obj`) does not cut that object either.
    let mut pdf = Pdf::new();
    pdf.obj(1, "<< /Type /Catalog >>").obj(12, "(twelve)");
    let at = pdf.objects[&12].0;
    pdf.objects.insert(2, (at + 1, 0));
    let store = open_strict(&pdf.finish("/Root 1 0 R")).unwrap();
    assert_eq!(str_of(&store, 12).as_deref(), Some(&b"twelve"[..]));
    assert_eq!(str_of(&store, 2).as_deref(), Some(&b"twelve"[..]));
}

#[test]
fn shared_indirect_lengths_are_loaded_once() {
    // 5,000 streams share the /Length object 9999, whose value is followed by a megabyte of
    // comment. Nothing resolves 9999 before the streams, so each stream's load peeks it: the
    // peek memo makes that one private load, not 5,000 (which would lex five gigabytes).
    const STREAMS: u32 = 5_000;
    let mut pdf = simple_doc();
    for num in 10..10 + STREAMS {
        pdf.stream_with(num, "<< /Length 9999 0 R >>", b"data");
    }
    pdf.obj(9999, &format!("4 % {}", "x".repeat(1 << 20)));
    let bytes = pdf.finish("/Root 1 0 R");
    let store = Arc::new(open(&bytes));
    let shared = Arc::clone(&store);
    within(60, move || {
        for num in 10..10 + STREAMS {
            assert_eq!(stream_of(&shared, num), b"data");
        }
    });
    // The catalog, the streams, and one private load of 9999.
    assert_eq!(store.parsed_object_count(), 2 + STREAMS as usize);
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());

    // The same with the /Length inside a 2 MiB object stream that nothing decodes first: one
    // private decode, where one per stream would also exhaust `max_total_decoded`.
    let mut pdf = simple_doc();
    let padding = format!("({})", "y".repeat(2 << 20));
    pdf.objstm(20, &[(21, "4"), (22, &padding)], "");
    for num in 30..30 + STREAMS {
        pdf.stream_with(num, "<< /Length 21 0 R >>", b"data");
    }
    let mut rows: Vec<_> = (1..=4).map(|n| (n, Row::At(n))).collect();
    rows.push((20, Row::At(20)));
    rows.push((21, Row::In(20, 0)));
    rows.push((22, Row::In(20, 1)));
    rows.extend((30..30 + STREAMS).map(|n| (n, Row::At(n))));
    let at = pdf.xref_stream(9, [1, 4, 2], &rows, "/Root 1 0 R");
    pdf.startxref(at);
    let store = Arc::new(open(&pdf.buf));
    let shared = Arc::clone(&store);
    within(60, move || {
        for num in 30..30 + STREAMS {
            assert_eq!(stream_of(&shared, num), b"data");
        }
    });
    // The container once, the streams, and the cross-reference stream (7 bytes per row).
    let container = (2 << 20) as u64 + 100;
    let streams = 4 * u64::from(STREAMS);
    let xref = 7 * rows.len() as u64;
    assert!(
        store.total_decoded() < container + streams + xref + 1000,
        "{} bytes decoded",
        store.total_decoded()
    );
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
}

#[test]
fn peek_memo_skips_results_that_depend_on_the_call_path() {
    // 11 and 12 are each other's /Length. Peeking 12 from 11's load refuses 11 (a cycle on the
    // call path), so that private load of 12 scans for `endstream` and must not be remembered:
    // 12's own load, where 11 can be peeked, must not reuse it.
    let mut pdf = simple_doc();
    pdf.stream_with(11, "<< /Length 12 0 R >>", b"left")
        .stream_with(12, "<< /Length 11 0 R >>", b"right");
    let store = open(&pdf.finish("/Root 1 0 R"));
    assert_eq!(stream_of(&store, 11), b"left");
    assert!(lock(&store.peeked_objects).get(&id(12)).is_none());
    assert_eq!(stream_of(&store, 12), b"right");
    // A plain integer does not depend on the call path.
    let mut pdf = simple_doc();
    pdf.stream_with(5, "<< /Length 6 0 R >>", b"hello")
        .obj(6, "5");
    let store = open(&pdf.finish("/Root 1 0 R"));
    assert_eq!(stream_of(&store, 5), b"hello");
    let memo = lock(&store.peeked_objects).get(&id(6)).cloned();
    assert_eq!(memo.flatten().and_then(|o| o.as_int()), Some(5));
    // The blocking load still parses (and would report) the object itself.
    assert_eq!(store.resolve(id(6)).unwrap().as_int(), Some(5));
}

#[test]
fn nested_length_lookups_are_bounded() {
    // Stream k's /Length is stream k+1, 200 deep: every lookup would parse the next stream,
    // which needs the next length. Nested loads stop at the chain bound (max_ref_chain, at most
    // 16 levels whatever the limit says), so this runs on a small (256 KiB) stack even in debug
    // builds, and falls back to scanning for `endstream`.
    const DEPTH: u32 = 200;
    let mut pdf = simple_doc();
    for k in 0..DEPTH {
        let num = 10 + k;
        pdf.stream_with(num, &format!("<< /Length {} 0 R >>", num + 1), b"data");
    }
    pdf.obj(10 + DEPTH, "4");
    let bytes = pdf.finish("/Root 1 0 R");
    for max_ref_chain in [32, u16::MAX] {
        let bytes = bytes.clone();
        let limits = Limits::default().with_max_ref_chain(max_ref_chain);
        let handle = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                let store =
                    Store::open_bytes(bytes, &OpenOptions::default().with_limits(limits)).unwrap();
                assert_eq!(stream_of(&store, 10), b"data");
                assert!(has(&store, DiagnosticKind::StreamLength));
                // The last stream's length is a plain integer.
                assert_eq!(stream_of(&store, 9 + DEPTH), b"data");
            })
            .unwrap();
        handle.join().unwrap();
    }
}

#[test]
fn header_generation_mismatch_is_accepted_leniently() {
    // The table says generation 0, the header says 1: same object, reported.
    let mut pdf = simple_doc();
    let at = pdf.pos();
    pdf.raw("5 1 obj\n(five)\nendobj\n");
    pdf.objects.insert(5, (at, 0));
    let bytes = pdf.finish("/Root 1 0 R");
    let store = open(&bytes);
    assert_eq!(
        store.resolve(id(5)).unwrap().as_str_bytes(),
        Some(&b"five"[..])
    );
    assert_eq!(kinds(&store), [DiagnosticKind::XrefMalformed]);
    assert!(open_strict(&bytes).unwrap().resolve(id(5)).is_err());
}

#[cfg(feature = "serde")]
#[test]
fn serde_names() {
    use serde::Deserialize;
    use serde::de::IntoDeserializer;
    use serde::de::value::{Error as DeError, MapDeserializer, StrDeserializer};

    let entries = vec![("strictness", "strict")];
    let de = MapDeserializer::<_, DeError>::new(entries.into_iter());
    let options = OpenOptions::deserialize(de).unwrap();
    assert_eq!(
        options,
        OpenOptions::default().with_strictness(Strictness::Strict)
    );
    for (text, kind) in [
        ("table", XrefKind::Table),
        ("stream", XrefKind::Stream),
        ("hybrid", XrefKind::Hybrid),
        ("reconstructed", XrefKind::Reconstructed),
    ] {
        let de: StrDeserializer<'_, DeError> = text.into_deserializer();
        assert_eq!(XrefKind::deserialize(de).unwrap(), kind);
    }
    for (text, base) in [
        ("headerRelative", OffsetBase::HeaderRelative),
        ("absolute", OffsetBase::Absolute),
    ] {
        let de: StrDeserializer<'_, DeError> = text.into_deserializer();
        assert_eq!(OffsetBase::deserialize(de).unwrap(), base);
    }
}

#[test]
fn unusable_root_is_repaired() {
    // The table does not list the catalog's number at all: the scan fills it in.
    let mut pdf = simple_doc();
    let rows: Vec<_> = pdf.all_rows().into_iter().filter(|r| r.0 != 1).collect();
    let at = pdf.table_rows(&rows, "\r\n", None);
    pdf.trailer("/Root 1 0 R").startxref(at);
    let store = open(&pdf.buf);
    check_simple(&store);
    assert_eq!(kinds(&store), [DiagnosticKind::XrefReconstructed]);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Table);
    assert_eq!(open_strict(&pdf.buf).unwrap_err().code(), ErrorCode::Xref);

    // /Root names an object that is not a dictionary: the catalog is found instead.
    let bytes = simple_doc().finish("/Root 4 0 R");
    let store = open(&bytes);
    assert_eq!(store.root_id(), Some(id(1)));
    check_simple(&store);
    assert_eq!(kinds(&store), [DiagnosticKind::TrailerRebuilt]);
    assert_eq!(open_strict(&bytes).unwrap_err().code(), ErrorCode::Xref);

    // No catalog anywhere: opening fails.
    let mut pdf = Pdf::new();
    pdf.obj(1, "(not a catalog)");
    let bytes = pdf.finish("/Root 1 0 R");
    let err = Store::open_bytes(bytes, &OpenOptions::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Xref);
}

// ---- bounded work on hostile cross-reference data (QA round 1) --------------------------------

/// Opens `bytes` leniently with the default limits, on another thread with a deadline.
fn open_within(seconds: u64, bytes: Vec<u8>) -> Store {
    let (tx, rx) = mpsc::channel();
    within(seconds, move || {
        let store = Store::open_bytes(bytes, &OpenOptions::default())
            .unwrap_or_else(|e| panic!("open failed: {e}"));
        let _ = tx.send(store);
    });
    rx.recv().unwrap()
}

/// [`simple_doc`] with its table, then `sections` cross-reference streams chained by /Prev, each
/// claiming `rows` in-use entries (/W [0 1 0]: type 1 and generation 0 by default, offset 0)
/// for objects 1000 and up, from a few hundred bytes of Flate data.
fn compressed_chain(sections: u32, rows: u32) -> Vec<u8> {
    let mut pdf = simple_doc();
    let base = pdf.table("\r\n");
    pdf.trailer("/Root 1 0 R").startxref(base);
    let zeros = encode_flate(&vec![0u8; rows as usize], 9);
    let mut prev = base;
    for k in 0..sections {
        let at = pdf.pos();
        let dict = format!(
            "<< /Type /XRef /Size {} /W [0 1 0] /Index [1000 {rows}] /Filter /FlateDecode \
             /Length {} /Root 1 0 R /Prev {prev} >>",
            1000 + rows,
            zeros.len()
        );
        pdf.stream_with(100 + k, &dict, &zeros);
        pdf.startxref(at);
        prev = at;
    }
    pdf.buf
}

#[test]
fn xref_stream_chains_are_bounded() {
    // 500 sections of 100,000 rows each: 50 million rows from a 200 KB file, which once took
    // minutes to merge. The reader stops at max(2^20, 4 × file length) rows and cuts the chain.
    let bytes = compressed_chain(500, 100_000);
    let len = bytes.len();
    assert!(len < 250_000, "{len}");
    let started = std::time::Instant::now();
    let store = open_within(60, bytes.clone());
    eprintln!("compressed chain: {:?}", started.elapsed());
    let rows_read: usize = store.revisions().len() * 100_000;
    assert!(rows_read <= (4 * len).max(1 << 20), "{rows_read} rows read");
    assert!(store.revisions().len() < 500);
    assert!(has(&store, DiagnosticKind::XrefLoop), "{:?}", kinds(&store));
    // The cut-off base revision's objects are recovered by the scan.
    assert!(has(&store, DiagnosticKind::XrefReconstructed));
    check_simple(&store);
    assert!(store.structure_repaired());
    // Strict mode refuses the file.
    assert_eq!(
        open_strict(&bytes).unwrap_err().code(),
        ErrorCode::LimitExceeded
    );
}

#[test]
fn overlapping_xref_streams_are_bounded() {
    // 400 uncompressed cross-reference streams, each with a /Length that reaches the end of one
    // shared tail of 200,000 rows: every section would read all the sections after it plus the
    // tail. The reader charges each section's bytes and rows to the file's budget.
    const SECTIONS: usize = 400;
    const TAIL: usize = 200_000;
    let mut pdf = simple_doc();
    let base = pdf.table("\r\n");
    pdf.trailer("/Root 1 0 R").startxref(base);
    // Each header is padded to a fixed width, so the lengths are known in advance.
    const WIDTH: usize = 200;
    let first = pdf.pos();
    let mut starts = Vec::new();
    for k in 0..SECTIONS {
        let at = first + k * WIDTH;
        starts.push(at);
        let prev = if k == 0 { base } else { at - WIDTH };
        let mut header = format!(
            "{} 0 obj\n<< /Type /XRef /W [0 1 0] /Index [1000 {TAIL}] /Root 1 0 R /Prev {prev} \
             /Length ",
            100 + k
        );
        let data_start = at + WIDTH;
        let length = (SECTIONS - k - 1) * WIDTH + TAIL;
        header += &format!("{length} >>");
        let pad = WIDTH - header.len() - "\nstream\n".len();
        header += &" ".repeat(pad);
        header += "\nstream\n";
        assert_eq!(header.len(), WIDTH);
        assert_eq!(at + header.len(), data_start);
        pdf.raw(header);
    }
    pdf.raw(vec![0u8; TAIL]).raw("\nendstream\nendobj\n");
    pdf.startxref(*starts.last().unwrap());
    let len = pdf.buf.len();
    let started = std::time::Instant::now();
    let store = open_within(60, pdf.buf.clone());
    eprintln!("overlapping streams: {:?}", started.elapsed());
    // About four times the file's bytes, then the chain is cut.
    assert!(
        store.revisions().len() * TAIL <= 4 * len + (1 << 20),
        "{} sections",
        store.revisions().len()
    );
    assert!(has(&store, DiagnosticKind::XrefLoop), "{:?}", kinds(&store));
    check_simple(&store);
    assert_eq!(
        open_strict(&pdf.buf).unwrap_err().code(),
        ErrorCode::LimitExceeded
    );
}

/// [`simple_doc`] with its table, then one cross-reference stream with `rows` rows of `width`
/// zero bytes for objects 1000 and up (/W `w`), Flate-compressed to almost nothing.
fn claimed_objects(rows: u32, w: [u8; 3]) -> Vec<u8> {
    let mut pdf = simple_doc();
    let base = pdf.table("\r\n");
    pdf.trailer("/Root 1 0 R").startxref(base);
    let width: usize = w.iter().map(|&b| usize::from(b)).sum();
    let zeros = encode_flate(&vec![0u8; rows as usize * width], 9);
    let at = pdf.pos();
    let dict = format!(
        "<< /Type /XRef /Size {} /W [{} {} {}] /Index [1000 {rows}] /Filter /FlateDecode \
         /Length {} /Root 1 0 R /Prev {base} >>",
        1000 + rows,
        w[0],
        w[1],
        w[2],
        zeros.len()
    );
    pdf.stream_with(99, &dict, &zeros);
    pdf.startxref(at);
    pdf.buf
}

#[test]
fn tiny_files_cannot_claim_millions_of_objects() {
    // 900,000 in-use entries (offset 0) from a file of a few kilobytes: at most one object per
    // byte of the file is kept (at least 4096), the lowest numbers, so the catalog survives.
    let bytes = claimed_objects(900_000, [0, 1, 0]);
    let len = bytes.len();
    assert!(len < 4096, "{len}");
    let store = open_within(60, bytes.clone());
    assert_eq!(store.object_ids().len(), 4096);
    assert!(
        store
            .object_ids()
            .starts_with(&[id(1), id(2), id(3), id(4)])
    );
    check_simple(&store);
    assert!(
        has(&store, DiagnosticKind::XrefMalformed),
        "{:?}",
        kinds(&store)
    );
    assert!(store.structure_repaired());
    // The slots of the kept objects are all the store holds per object.
    assert!(store.slots.len() * std::mem::size_of::<Slot>() <= 4096 * 48);
    // Strict mode names the derived budget (not max_objects, which is 10 million) and says
    // how to raise it.
    let err = open_strict(&bytes).unwrap_err();
    assert!(
        matches!(
            err,
            Error::LimitExceeded {
                limit: LimitKind::ObjectCap,
                max: 4096,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(err.to_string().contains("budget_scale"), "{err}");
    // A caller that trusts the file raises the derived budgets; max_objects still applies.
    let trusted = |limits: Limits| {
        OpenOptions::default()
            .with_strictness(Strictness::Strict)
            .with_limits(limits)
    };
    let store = Store::open_bytes(
        bytes.clone(),
        &trusted(Limits::default().with_budget_scale(300)),
    )
    .unwrap();
    assert_eq!(store.object_ids().len(), 900_004);
    let err = Store::open_bytes(
        bytes.clone(),
        &trusted(
            Limits::default()
                .with_budget_scale(300)
                .with_max_objects(100_000),
        ),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            Error::LimitExceeded {
                limit: LimitKind::MaxObjects,
                max: 100_000,
                ..
            }
        ),
        "{err:?}"
    );

    // 900,000 free entries (/W [1 0 0], type 0) cost no memory at all.
    let store = open_within(60, claimed_objects(900_000, [1, 0, 0]));
    assert_eq!(store.object_ids(), [id(1), id(2), id(3), id(4)]);
    assert_eq!(store.slots.len(), 4);
    assert_eq!(store.max_object_number(), 1000 + 899_999);
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());

    // Ten million rows claimed by a 10 KB file: more rows than the reader reads for a file of
    // that size, so the stream is not used at all and the file is reconstructed.
    let bytes = claimed_objects(10_000_000, [0, 1, 0]);
    assert!(bytes.len() < 20_000, "{}", bytes.len());
    let store = open_within(60, bytes.clone());
    check_simple(&store);
    assert!(store.object_ids().len() <= 4096);
    assert!(has(&store, DiagnosticKind::XrefLoop), "{:?}", kinds(&store));
    let err = open_strict(&bytes).unwrap_err();
    assert!(
        matches!(
            err,
            Error::LimitExceeded {
                limit: LimitKind::XrefEntries,
                max: 1_048_576,
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn reconstruction_reads_object_streams_without_keeping_them() {
    // No cross-reference data: a real object stream holding 10, then four object streams that
    // each decode to 32 MiB of zeros. Opening reads their member lists only, within
    // max(16 MiB, 16 × file length) decoded bytes, and keeps none of them.
    let mut pdf = simple_doc();
    pdf.objstm(20, &[(10, "(ten)")], "");
    let bomb = encode_flate(&vec![0u8; 32 << 20], 9);
    for num in 21..25 {
        let dict = format!(
            "<< /Type /ObjStm /N 0 /First 0 /Filter /FlateDecode /Length {} >>",
            bomb.len()
        );
        pdf.stream_with(num, &dict, &bomb);
    }
    pdf.trailer("/Root 1 0 R");
    let len = pdf.buf.len();
    assert!(len < 1 << 20, "{len}");
    let store = open_within(60, pdf.buf);
    assert!(lock(&store.objstm_cache).entries.is_empty());
    assert_eq!(store.objstm_cache_bytes(), 0);
    assert!(
        store.total_decoded() <= (16 << 20) + 1000,
        "{} bytes decoded",
        store.total_decoded()
    );
    let messages: Vec<String> = store.diagnostics().into_iter().map(|d| d.message).collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("object stream 21 decodes to more")),
        "{messages:?}"
    );
    // The real container's object is recovered (and its container cached on use).
    check_simple(&store);
    assert_eq!(str_of(&store, 10).as_deref(), Some(&b"ten"[..]));
    assert_eq!(lock(&store.objstm_cache).entries.len(), 1);
    assert!(store.recovered_objects().contains(&id(10)));
}

#[test]
fn trailer_candidates_are_parsed_within_their_region() {
    // A trailer whose string never ends before the next `trailer` keyword: parsed on to the end
    // of the file, its string would swallow the next trailer and give a /Root. Each candidate is
    // parsed only up to the next trailer keyword or object header instead.
    let mut pdf = simple_doc();
    pdf.raw("trailer\n<< /Root 1 0 R >>\n")
        .raw("trailer\n<< /Root 3 0 R /Junk (abc\n")
        .raw("trailer\n<< /Size 5 >> ) >>\n");
    let store = open(&pdf.buf);
    let trailer = repair::find_trailer(&store).unwrap();
    assert_eq!(trailer.get_ref(b"Root"), Some(id(1)));
    check_simple(&store);
    assert!(!has(&store, DiagnosticKind::TrailerRebuilt));

    // 64 broken candidates before four megabytes: each stops at the next one.
    let mut pdf = simple_doc();
    pdf.raw("trailer\n<< /Root 1 0 R >>\n");
    for _ in 0..64 {
        pdf.raw("trailer\n<< /Info (unterminated\n");
    }
    pdf.raw(vec![b'x'; 4 << 20]);
    let store = open_within(60, pdf.buf);
    check_simple(&store);
}

#[test]
fn an_earlier_startxref_is_tried() {
    // A multi-revision file with a bogus `startxref` appended: the last startxref leads nowhere,
    // so the one before it is used, and the revisions survive.
    let (mut bytes, tables, ends) = incremental_doc();
    let original = bytes.len();
    bytes.extend_from_slice(b"\nstartxref\n99999999\n%%EOF\n");
    let store = open(&bytes);
    let revisions = store.revisions();
    assert_eq!(revisions.len(), 4);
    for (i, revision) in revisions.iter().enumerate() {
        assert_eq!(revision.startxref, tables[i] as u64, "revision {i}");
        assert_eq!(revision.eof_end, ends[i] as u64, "revision {i}");
        assert_eq!(revision.xref_kind, XrefKind::Table);
    }
    assert_eq!(revisions[3].eof_end, original as u64);
    assert_eq!(kinds(&store), [DiagnosticKind::XrefMalformed]);
    assert!(store.structure_repaired());
    assert!(store.resolve(id(3)).unwrap().is_null());
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"five"[..]));
    // Strict mode does not guess.
    assert_eq!(open_strict(&bytes).unwrap_err().code(), ErrorCode::Xref);
    // A last startxref without a number is skipped the same way.
    let mut bytes = incremental_doc().0;
    bytes.extend_from_slice(b"startxref\n%%EOF\n");
    let store = open(&bytes);
    assert_eq!(store.revisions().len(), 4);
}

#[test]
fn revision_entries_report_each_section() {
    let (bytes, ..) = incremental_doc();
    let store = open_strict(&bytes).unwrap();
    let entry = |num: u32| match store.location(num) {
        Some(Location::InFile { pos }) => XrefEntry::InFile { pos, r#gen: 0 },
        other => panic!("{other:?}"),
    };
    assert_eq!(store.revision_entries(0).unwrap().len(), 5);
    assert_eq!(store.revision_entries(1).unwrap(), [(5, entry(5))]);
    assert_eq!(store.revision_entries(2).unwrap(), [(4, entry(4))]);
    // A freed object is a change too.
    assert_eq!(
        store.revision_entries(3).unwrap(),
        [(3, XrefEntry::Free { r#gen: 1 })]
    );
    assert_eq!(
        store.revision_entries(4).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    assert!(store.diagnostics().is_empty());

    // A hybrid section: the table's entries, then those of its /XRefStm stream, free entries
    // and entries the table overrides included.
    let bytes = hybrid_doc(&[(10, Row::Free(1))], "");
    let store = open_strict(&bytes).unwrap();
    let revision = &store.revisions()[0];
    let hidden = find(&bytes, b"30 0 obj") as u64;
    assert_eq!(revision.xref_stm, Some(hidden));
    let entries = store.revision_entries(0).unwrap();
    let numbers: Vec<u32> = entries.iter().map(|e| e.0).collect();
    assert_eq!(numbers, [0, 1, 2, 3, 4, 5, 10, 20, 5, 10, 11]);
    assert_eq!(entries[6].1, XrefEntry::Free { r#gen: 1 });
    assert_eq!(
        entries[9].1,
        XrefEntry::InObjStm {
            stream: 20,
            index: 0
        }
    );
    // The merged view takes the table's entries: 5 from the file, 10 deleted.
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"file five"[..]));
    assert!(store.resolve(id(10)).unwrap().is_null());

    // A reconstructed file has no section.
    let mut pdf = simple_doc();
    pdf.trailer("/Root 1 0 R");
    let store = open(&pdf.buf);
    assert_eq!(
        store.revision_entries(0).unwrap_err().code(),
        ErrorCode::Xref
    );
}

#[test]
fn revisions_end_at_their_own_startxref() {
    // A linearized layout (Annex F): the first-page section near the start, followed by a dummy
    // `startxref 0`, and the main section at the end, whose startxref points back at the
    // first-page section. Both revisions end with the file.
    let mut pdf = Pdf::new();
    pdf.obj(5, "<< /Linearized 1 /L 0 /O 3 /E 0 /N 1 /T 0 /H [0 0] >>");
    let first_page = pdf.pos();
    // The first-page section lists objects 1-5; its /Prev is patched to the main section.
    pdf.raw("xref\n1 5\n");
    let rows_at = pdf.pos();
    pdf.raw("0000000000 00000 n\r\n".repeat(5));
    pdf.raw("trailer\n<< /Size 6 /Root 1 0 R /Prev ");
    let prev_at = pdf.pos();
    pdf.raw("0000000000 >>\nstartxref\n0\n%%EOF\n");
    pdf.obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .obj(
            3,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
        )
        .stream(4, "", CONTENT);
    let main = pdf.table_rows(&[(0, Row::Free(65535))], "\r\n", None);
    pdf.raw("trailer\n<< /Size 6 >>\n").startxref(first_page);
    for (k, num) in (1..=5).enumerate() {
        let off = pdf.objects[&num].0;
        pdf.patch(rows_at + 20 * k, off);
    }
    pdf.patch(prev_at, main);
    let bytes = pdf.buf.clone();
    let store = open_strict(&bytes).unwrap();
    check_simple(&store);
    let revisions = store.revisions();
    assert_eq!(revisions.len(), 2);
    assert_eq!(revisions[0].startxref, main as u64);
    assert_eq!(revisions[1].startxref, first_page as u64);
    // The newest (first-page) revision is not cut at the dummy `startxref 0 %%EOF`.
    assert_eq!(revisions[1].eof_end, bytes.len() as u64);
    assert_eq!(revisions[0].eof_end, bytes.len() as u64);
    assert!(revisions[1].section_end < revisions[0].section_end);

    // An update whose cross-reference stream is followed by more than 2 KB of objects before
    // its startxref: its end is still at its own %%EOF.
    let mut pdf = simple_doc();
    let base = pdf.table("\r\n");
    pdf.trailer("/Root 1 0 R").startxref(base);
    let first_end = pdf.pos();
    pdf.obj(5, "(five)");
    let rows = [(5, Row::At(5)), (6, Row::At(6))];
    let at = pdf.pos();
    pdf.objects.insert(6, (at, 0));
    let xref = pdf.xref_stream(6, [1, 2, 1], &rows, &format!("/Root 1 0 R /Prev {base}"));
    pdf.obj(7, &format!("({})", "z".repeat(3000)));
    pdf.startxref(xref);
    let bytes = pdf.buf.clone();
    let store = open_strict(&bytes).unwrap();
    let revisions = store.revisions();
    assert_eq!(revisions[0].eof_end, first_end as u64);
    assert_eq!(revisions[1].eof_end, bytes.len() as u64);

    // A revision without %%EOF ends after its startxref line, not at the next update's %%EOF.
    let (bytes, tables, ends) = incremental_doc();
    let eof = find(&bytes[..ends[0]], b"%%EOF");
    let mut cut = bytes[..eof].to_vec();
    cut.extend_from_slice(&bytes[eof + "%%EOF\n".len()..]);
    let store = open(&cut);
    assert_eq!(store.revisions()[0].startxref, tables[0] as u64);
    assert_eq!(store.revisions()[0].eof_end, eof as u64);
    assert_eq!(store.revisions()[3].eof_end, cut.len() as u64);
}

#[test]
fn repairs_and_recovered_objects_are_reported() {
    // An appended update whose trailer names /Root 9, an object no section lists: the scan
    // finds it, and both the repair and the object are reported.
    let (mut bytes, tables, _) = incremental_doc();
    let at = bytes.len();
    bytes.extend_from_slice(b"9 0 obj\n<< /Type /Catalog /Pages 2 0 R /Shadow true >>\nendobj\n");
    let table = bytes.len();
    bytes.extend_from_slice(
        format!(
            "xref\n0 0\ntrailer\n<< /Size 10 /Root 9 0 R /Prev {} >>\nstartxref\n{table}\n%%EOF\n",
            tables[3]
        )
        .as_bytes(),
    );
    let store = open(&bytes);
    assert_eq!(store.root_id(), Some(id(9)));
    assert!(root(&store).as_dict().unwrap().get_bool(b"Shadow") == Some(true));
    assert!(store.structure_repaired());
    assert!(store.recovered_objects().contains(&id(9)), "{at}");
    assert_eq!(store.revisions().len(), 5);
    assert_eq!(store.revision_entries(4).unwrap(), []);

    // Locations repaired at resolve time join the list as objects are resolved; the structure
    // itself was fine.
    let mut pdf = simple_doc();
    pdf.objects.get_mut(&3).unwrap().0 += 3;
    let store = open(&pdf.finish("/Root 1 0 R"));
    assert!(!store.structure_repaired());
    assert!(store.recovered_objects().is_empty());
    check_simple(&store);
    assert_eq!(store.recovered_objects(), [id(3)]);

    // A reconstructed file: everything was recovered.
    let mut pdf = simple_doc();
    pdf.trailer("/Root 1 0 R");
    let store = open(&pdf.buf);
    assert!(store.structure_repaired());
    assert_eq!(store.recovered_objects(), store.object_ids());

    // An object found in another object stream than its entry says.
    let store = open(&extends_doc(false));
    assert!(!store.structure_repaired());
    assert!(store.resolve(id(10)).unwrap().as_str_bytes().is_some());
    assert_eq!(store.recovered_objects(), [id(10)]);
}

#[test]
fn offset_base_is_detected() {
    let junk = b"Content-Type: application/pdf\r\n\r\n".to_vec();
    // Offsets relative to the header, as the standard says.
    let mut bytes = junk.clone();
    bytes.extend_from_slice(&simple_bytes());
    let store = open(&bytes);
    assert_eq!(store.offset_base(), OffsetBase::HeaderRelative);
    // Offsets counted from byte 0 (the junk included).
    let mut pdf = Pdf::default();
    pdf.raw(&junk).raw(b"%PDF-1.6\n");
    pdf.obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .obj(3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>")
        .stream(4, "", CONTENT);
    let bytes = pdf.finish("/Root 1 0 R");
    let store = open(&bytes);
    check_simple(&store);
    assert_eq!(store.offset_base(), OffsetBase::Absolute);
    // Revision::startxref stays header-relative.
    let xref = rfind(&bytes, b"\nxref\n") as u64 + 1;
    assert_eq!(store.revisions()[0].startxref, xref - junk.len() as u64);
    // Without junk the two agree.
    assert_eq!(
        open(&simple_bytes()).offset_base(),
        OffsetBase::HeaderRelative
    );
}

#[test]
fn unknown_xref_entry_types_read_as_null() {
    // The base revision has object 5; an update's cross-reference stream gives 5 the type 3,
    // which is a reference to the null object (§7.5.8.3): 5 is null, not the older object.
    let mut pdf = simple_doc();
    pdf.obj(5, "(five)");
    let base = pdf.table("\r\n");
    pdf.trailer("/Root 1 0 R").startxref(base);
    let at = pdf.pos();
    let data = encode_flate(&[3, 0, 0, 0, 1, 0, 0, 0], 6);
    let dict = format!(
        "<< /Type /XRef /Size 7 /W [1 2 1] /Index [5 1 6 1] /Filter /FlateDecode /Length {} \
         /Root 1 0 R /Prev {base} >>",
        data.len()
    );
    pdf.stream_with(6, &dict, &data);
    pdf.startxref(at);
    // The entry is conforming, so it is noted (in both modes), not repaired: strict mode
    // accepts the file and the structure counts as intact.
    for store in [open(&pdf.buf), open_strict(&pdf.buf).unwrap()] {
        assert!(store.resolve(id(5)).unwrap().is_null());
        assert!(!store.object_ids().contains(&id(5)));
        assert_eq!(kinds(&store), [DiagnosticKind::XrefUnknownEntryType]);
        assert!(store.diagnostics()[0].message.contains("type 3"));
        assert!(!store.structure_repaired());
        assert_eq!(
            store.revision_entries(1).unwrap()[0],
            (5, XrefEntry::Free { r#gen: 0 })
        );
        assert!(is_type(&root(&store), b"Catalog"));
    }
    // A type-1 entry whose fields are out of range is damage: repaired leniently, an error in
    // strict mode.
    let mut pdf = simple_doc();
    pdf.obj(5, "(five)");
    let base = pdf.table("\r\n");
    pdf.trailer("/Root 1 0 R").startxref(base);
    let at = pdf.pos();
    // /W [1 1 4]: the generation field 0x00010000 does not fit 16 bits.
    let data = encode_flate(&[1, 9, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0], 6);
    let dict = format!(
        "<< /Type /XRef /Size 7 /W [1 1 4] /Index [5 1 6 1] /Filter /FlateDecode /Length {} \
         /Root 1 0 R /Prev {base} >>",
        data.len()
    );
    pdf.stream_with(6, &dict, &data);
    pdf.startxref(at);
    let store = open(&pdf.buf);
    assert!(store.resolve(id(5)).unwrap().is_null());
    assert_eq!(kinds(&store), [DiagnosticKind::XrefMalformed]);
    assert!(store.structure_repaired());
    assert_eq!(open_strict(&pdf.buf).unwrap_err().code(), ErrorCode::Xref);

    // A table entry with a generation over 65535 hides the older entry too.
    let mut pdf = simple_doc();
    pdf.obj(5, "(five)");
    let base = pdf.table("\r\n");
    pdf.trailer("/Root 1 0 R").startxref(base);
    let at = pdf.pos();
    pdf.raw("xref\n5 1\n0000000009 99999 n\r\n");
    pdf.raw(format!("trailer\n<< /Size 6 /Root 1 0 R /Prev {base} >>\n"))
        .startxref(at);
    let store = open(&pdf.buf);
    assert!(store.resolve(id(5)).unwrap().is_null());
    assert_eq!(kinds(&store), [DiagnosticKind::XrefMalformed]);
}

#[test]
fn a_cached_container_is_not_kept_twice() {
    // Stream 30's /Length is object 21, inside object stream 20: loading 30 decodes 20
    // privately and quietly, and caches it. The first blocking load of one of its objects
    // replaces that entry with its own decode (which reports diagnostics), free of budget: the
    // cache never holds the container twice.
    let mut pdf = simple_doc();
    pdf.objstm(20, &[(21, "4"), (22, "(twenty-two)")], "");
    pdf.stream_with(30, "<< /Length 21 0 R >>", b"data");
    let rows: Vec<_> = (1..=4)
        .map(|n| (n, Row::At(n)))
        .chain([
            (20, Row::At(20)),
            (21, Row::In(20, 0)),
            (22, Row::In(20, 1)),
            (30, Row::At(30)),
        ])
        .collect();
    let at = pdf.xref_stream(9, [1, 2, 1], &rows, "/Root 1 0 R");
    pdf.startxref(at);
    let store = open(&pdf.buf);
    assert_eq!(stream_of(&store, 30), b"data");
    let quiet = |store: &Store| lock(&store.objstm_cache).entries.get(&20).map(|e| e.quiet);
    assert_eq!(quiet(&store), Some(true));
    let weight = store.objstm_cache_bytes();
    assert!(weight > 0);
    let decoded = store.total_decoded();
    assert_eq!(str_of(&store, 22).as_deref(), Some(&b"twenty-two"[..]));
    assert_eq!(quiet(&store), Some(false));
    assert_eq!(lock(&store.objstm_cache).entries.len(), 1);
    assert_eq!(store.objstm_cache_bytes(), weight);
    // Decoding the container a second time costs no budget.
    assert_eq!(store.total_decoded(), decoded);
    // A later peek uses the cache.
    assert_eq!(stream_of(&store, 30), b"data");
    assert_eq!(quiet(&store), Some(false));
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
}

// ---- object stream resources (M1 QA fix round 2) ---------------------------------------------

/// The simple document plus object streams 20, 21, ... from `containers`: each is the decoded
/// data of one container (`/N`, `/First`, data), Flate-compressed, with every listed member in
/// a cross-reference stream (type 2 entries, at the index given).
fn objstm_doc(containers: &[(u32, usize, Vec<u8>)], members: &[(u32, u32, u32)]) -> Vec<u8> {
    let mut pdf = simple_doc();
    for (k, (n, first, data)) in containers.iter().enumerate() {
        let encoded = encode_flate(data, 9);
        let dict = format!(
            "<< /Type /ObjStm /N {n} /First {first} /Filter /FlateDecode /Length {} >>",
            encoded.len()
        );
        pdf.stream_with(20 + k as u32, &dict, &encoded);
    }
    let mut rows: Vec<(u32, Row)> = (1..=4).map(|n| (n, Row::At(n))).collect();
    rows.extend((0..containers.len() as u32).map(|k| (20 + k, Row::At(20 + k))));
    rows.extend(
        members
            .iter()
            .map(|&(num, stm, index)| (num, Row::In(stm, index))),
    );
    rows.sort_by_key(|r| r.0);
    let at = pdf.xref_stream(9, [1, 4, 2], &rows, "/Root 1 0 R");
    pdf.startxref(at);
    pdf.buf
}

/// The decoded data of a container holding `members` (number, text), padded with spaces to
/// `len` bytes after the last member.
fn padded_container(members: &[(u32, &str)], len: usize) -> (u32, usize, Vec<u8>) {
    let (mut data, first) = objstm_data(members);
    data.resize(len.max(data.len()), b' ');
    (members.len() as u32, first, data)
}

/// Six containers of 1 MiB each (20 to 25), holding objects `a`, `b` and `c` (100 + k,
/// 200 + k, 300 + k for container 20 + k).
fn six_containers() -> Vec<u8> {
    const MIB: usize = 1 << 20;
    let containers: Vec<_> = (0..6u32)
        .map(|k| {
            let a = format!("(a{k})");
            let b = format!("(b{k})");
            let c = format!("(c{k})");
            padded_container(&[(100 + k, &a), (200 + k, &b), (300 + k, &c)], MIB)
        })
        .collect();
    let members: Vec<(u32, u32, u32)> = (0..6u32)
        .flat_map(|k| {
            [
                (100 + k, 20 + k, 0),
                (200 + k, 20 + k, 1),
                (300 + k, 20 + k, 2),
            ]
        })
        .collect();
    objstm_doc(&containers, &members)
}

/// The text of the object `member + k` of [`six_containers`] (`member` is 100, 200 or 300).
fn six_containers_text(member: u32, k: u32) -> Vec<u8> {
    let letter = ["a", "b", "c"][(member / 100 - 1) as usize];
    format!("{letter}{k}").into_bytes()
}

fn decodes(store: &Store) -> usize {
    store.objstm_decodes.load(Ordering::Relaxed)
}

/// Whether object `num` is loaded: its slot is filled, or a settling pass left it for the
/// slot's first load.
fn is_loaded(store: &Store, num: u32) -> bool {
    store.slot(num).is_some_and(|s| s.parsed.get().is_some())
        || lock(&store.settled).contains_key(&num)
}

#[test]
fn the_object_stream_cache_is_bounded() {
    // A cache of 2.5 MiB: resolving one object of each container keeps at most the cache's
    // worth (plus the container in use), the least recently used first out.
    const MIB: usize = 1 << 20;
    let bytes = six_containers();
    let budget = 5 * MIB / 2;
    let limits = Limits::default().with_max_objstm_cache(budget);
    let store =
        Store::open_bytes(bytes.clone(), &OpenOptions::default().with_limits(limits)).unwrap();
    // (Opening decoded the cross-reference stream.)
    let at_open = store.total_decoded();
    for k in 0..6u32 {
        let a = store.resolve(id(100 + k)).unwrap();
        assert_eq!(a.as_str_bytes(), Some(format!("a{k}").as_bytes()));
        assert!(
            store.objstm_cache_bytes() <= (budget + MIB + 4096) as u64,
            "{} bytes cached after container {k}",
            store.objstm_cache_bytes()
        );
    }
    // Two containers fit, the others were dropped, oldest first.
    let cached: Vec<u32> = {
        let cache = lock(&store.objstm_cache);
        let mut nums: Vec<u32> = cache.lru.values().copied().collect();
        nums.sort_unstable();
        nums
    };
    assert_eq!(cached, [24, 25]);
    let decoded = store.total_decoded();
    assert_eq!(decoded - at_open, 6 * MIB as u64);
    assert_eq!(decodes(&store), 6);
    // A cached container costs nothing more.
    assert_eq!(str_of(&store, 205).as_deref(), Some(&b"b5"[..]));
    assert_eq!(decodes(&store), 6);
    assert!(!is_loaded(&store, 305));
    // A dropped one is decoded again, without a charge (each source stream counts once), and
    // its objects that were not loaded yet are loaded with it: 300 needs it no more.
    assert!(!is_loaded(&store, 300));
    assert_eq!(str_of(&store, 200).as_deref(), Some(&b"b0"[..]));
    assert_eq!(decodes(&store), 7);
    assert_eq!(store.total_decoded(), decoded);
    assert!(is_loaded(&store, 300));
    assert!(!is_loaded(&store, 301));
    assert_eq!(str_of(&store, 300).as_deref(), Some(&b"c0"[..]));
    assert_eq!(decodes(&store), 7);
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());

    // With the default cache, all six stay.
    let store = open(&bytes);
    for k in 0..6u32 {
        store.resolve(id(100 + k)).unwrap();
        store.resolve(id(200 + k)).unwrap();
    }
    assert_eq!(lock(&store.objstm_cache).lru.len(), 6);
    assert_eq!(store.total_decoded(), at_open + 6 * MIB as u64);
    assert_eq!(decodes(&store), 6);
}

#[test]
fn a_thrashing_cache_neither_exhausts_the_budget_nor_decodes_without_end() {
    // A long-lived store reads objects in an order that makes the cache thrash: the first
    // object of every container, then the second, then the third, round after round. With
    // exactly the budget the six containers need once, everything resolves: decoding a dropped
    // container again is not charged. And each container is decoded at most twice, because the
    // second decode loads all of its objects that were not loaded yet.
    const MIB: usize = 1 << 20;
    let bytes = six_containers();
    let at_open = open(&bytes).total_decoded();
    let limits = Limits::default()
        .with_max_objstm_cache(5 * MIB / 2)
        .with_max_total_decoded(at_open + 6 * MIB as u64);
    for strictness in [Strictness::Lenient, Strictness::Strict] {
        let options = OpenOptions::default()
            .with_limits(limits)
            .with_strictness(strictness);
        let store = Store::open_bytes(bytes.clone(), &options).unwrap();
        for round in 0..5 {
            for member in [100, 200, 300] {
                for k in 0..6u32 {
                    let object = store.resolve(id(member + k)).unwrap();
                    assert_eq!(
                        object.as_str_bytes(),
                        Some(six_containers_text(member, k).as_slice()),
                        "round {round}, object {}",
                        member + k
                    );
                }
            }
            assert_eq!(decodes(&store), 12, "{strictness:?} round {round}");
            assert_eq!(store.total_decoded(), at_open + 6 * MIB as u64);
        }
        // Reading the containers' own data again is free too.
        for k in 0..6u32 {
            let container = store.resolve(id(20 + k)).unwrap();
            let data = store.stream_data(container.as_stream().unwrap()).unwrap();
            assert_eq!(data.data.len(), MIB);
        }
        assert_eq!(store.total_decoded(), at_open + 6 * MIB as u64);
        assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
    }

    // A genuine bomb is still bounded: every container counts once, so a budget below what
    // six distinct containers decode to stops the sixth, in both modes.
    let limits = limits.with_max_total_decoded(at_open + 11 * MIB as u64 / 2);
    for strictness in [Strictness::Lenient, Strictness::Strict] {
        let options = OpenOptions::default()
            .with_limits(limits)
            .with_strictness(strictness);
        let store = Store::open_bytes(bytes.clone(), &options).unwrap();
        for k in 0..5u32 {
            store.resolve(id(100 + k)).unwrap();
        }
        let err = store.resolve(id(105)).unwrap_err();
        assert!(
            matches!(
                err,
                Error::LimitExceeded {
                    limit: LimitKind::MaxTotalDecoded,
                    ..
                }
            ),
            "{err:?}"
        );
        // The stopped decode counted what it was allowed: nothing is left for another one.
        assert_eq!(store.total_decoded(), limits.max_total_decoded);
    }
}

#[test]
fn nested_loads_take_what_a_settle_left() {
    // Expert (M1 QA round 4): a nested load (here the indirect /Length of stream 30) of a member
    // that a blocking settle had already parsed into the settled memo parsed it again
    // privately. It now uses the memo's object, which stays there for the slot's first load.
    const MIB: usize = 1 << 20;
    let mut pdf = simple_doc();
    let containers = [
        padded_container(&[(100, "(a)"), (101, "4"), (102, "(c)")], MIB),
        padded_container(&[(200, "(b)")], MIB),
    ];
    for (k, (n, first, data)) in containers.iter().enumerate() {
        let encoded = encode_flate(data, 9);
        let dict = format!(
            "<< /Type /ObjStm /N {n} /First {first} /Filter /FlateDecode /Length {} >>",
            encoded.len()
        );
        pdf.stream_with(20 + k as u32, &dict, &encoded);
    }
    pdf.stream_with(30, "<< /Length 101 0 R >>", b"abcd");
    let mut rows: Vec<(u32, Row)> = [1, 2, 3, 4, 20, 21, 30]
        .into_iter()
        .map(|n| (n, Row::At(n)))
        .collect();
    rows.extend([
        (100, Row::In(20, 0)),
        (101, Row::In(20, 1)),
        (102, Row::In(20, 2)),
        (200, Row::In(21, 0)),
    ]);
    rows.sort_by_key(|r| r.0);
    let at = pdf.xref_stream(9, [1, 4, 2], &rows, "/Root 1 0 R");
    pdf.startxref(at);
    // A cache that keeps one container: 21 drops 20, and 102 decodes it again and settles 101.
    let limits = Limits::default().with_max_objstm_cache(MIB + MIB / 2);
    let store = Store::open_bytes(pdf.buf, &OpenOptions::default().with_limits(limits)).unwrap();
    assert_eq!(str_of(&store, 100).as_deref(), Some(&b"a"[..]));
    assert_eq!(str_of(&store, 200).as_deref(), Some(&b"b"[..]));
    assert_eq!(str_of(&store, 102).as_deref(), Some(&b"c"[..]));
    assert_eq!(decodes(&store), 3);
    assert!(lock(&store.settled).contains_key(&101));
    assert!(store.slot(101).unwrap().parsed.get().is_none());
    // Stream 30 is the only object parsed: its /Length comes from the memo.
    let parsed = store.parsed_object_count();
    assert_eq!(stream_of(&store, 30), b"abcd");
    assert_eq!(store.parsed_object_count(), parsed + 1);
    assert!(lock(&store.settled).contains_key(&101));
    // The slot's first load takes it.
    assert_eq!(*store.resolve(id(101)).unwrap(), Object::Int(4));
    assert_eq!(store.parsed_object_count(), parsed + 1);
    assert!(!lock(&store.settled).contains_key(&101));
    assert_eq!(decodes(&store), 3);
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
}

#[test]
fn threads_on_a_thrashing_cache_settle_containers_without_deadlock() {
    // Eight threads read the objects of six containers in different orders through a cache
    // that holds two: containers are dropped and decoded again while other threads fill the
    // slots a settling pass wants. Every object reads right, once, and nothing deadlocks.
    const MIB: usize = 1 << 20;
    let limits = Limits::default().with_max_objstm_cache(5 * MIB / 2);
    let store = Arc::new(
        Store::open_bytes(
            six_containers(),
            &OpenOptions::default().with_limits(limits),
        )
        .unwrap(),
    );
    let at_open = store.parsed_object_count();
    let shared = Arc::clone(&store);
    within(120, move || {
        let handles: Vec<_> = (0..8u32)
            .map(|t| {
                let store = Arc::clone(&shared);
                std::thread::spawn(move || {
                    let mut order: Vec<(u32, u32)> = [100, 200, 300]
                        .into_iter()
                        .flat_map(|member| (0..6u32).map(move |k| (member, k)))
                        .collect();
                    let len = order.len();
                    order.rotate_left((t as usize * 5) % len);
                    if t % 2 == 1 {
                        order.reverse();
                    }
                    order
                        .into_iter()
                        .map(|(member, k)| {
                            let object = store.resolve(id(member + k)).unwrap();
                            assert_eq!(
                                object.as_str_bytes(),
                                Some(six_containers_text(member, k).as_slice())
                            );
                            (member + k, object)
                        })
                        .collect::<BTreeMap<u32, Arc<Object>>>()
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for other in &results[1..] {
            for (num, object) in other {
                assert!(Arc::ptr_eq(object, &results[0][num]), "{num}");
            }
        }
    });
    // 18 members and 6 containers, each parsed once by its own load; a settling pass may parse
    // a member another thread is loading at the same time (it never waits for that thread), at
    // most once per thread.
    let parsed = store.parsed_object_count() - at_open;
    assert!((18 + 6..=18 * 9 + 6).contains(&parsed), "{parsed}");
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
}

/// `containers` object streams (20, 21, ...) of `members` objects each, numbered from 100 on:
/// object `100 + k × members + i` is `[n n n]` (its own number three times), entry `i` of
/// container `20 + k`. Small containers, so that a test can drop and decode them over and over.
fn many_members(containers: u32, members: u32) -> Vec<u8> {
    let texts: Vec<Vec<(u32, String)>> = (0..containers)
        .map(|k| {
            (0..members)
                .map(|i| {
                    let n = 100 + k * members + i;
                    (n, format!("[{n} {n} {n}]"))
                })
                .collect()
        })
        .collect();
    let built: Vec<(u32, usize, Vec<u8>)> = texts
        .iter()
        .map(|list| {
            let refs: Vec<(u32, &str)> = list.iter().map(|(n, t)| (*n, t.as_str())).collect();
            padded_container(&refs, 0)
        })
        .collect();
    let rows: Vec<(u32, u32, u32)> = (0..containers)
        .flat_map(|k| (0..members).map(move |i| (100 + k * members + i, 20 + k, i)))
        .collect();
    objstm_doc(&built, &rows)
}

#[test]
fn settling_never_waits_on_another_slot() {
    // Expert reproducer (M1 QA round 3): eight threads resolve the members of six containers of
    // sixty objects in random orders, through a cache that holds no container at all, so that
    // nearly every load decodes its container again and settles it. A settling pass that waited
    // on the slots of the other members deadlocked (thread A settling X's container waits on Y,
    // which thread B fills while it settles the same container and waits on X). Many rounds on
    // fresh stores, under a timeout.
    const CONTAINERS: u32 = 6;
    const MEMBERS: u32 = 60;
    const THREADS: u64 = 8;
    let bytes = Arc::new(many_members(CONTAINERS, MEMBERS));
    let total = CONTAINERS * MEMBERS;
    within(60, move || {
        for round in 0..40u64 {
            let limits = Limits::default().with_max_objstm_cache(1);
            let store = Arc::new(
                Store::open_bytes(bytes.to_vec(), &OpenOptions::default().with_limits(limits))
                    .unwrap(),
            );
            let handles: Vec<_> = (0..THREADS)
                .map(|t| {
                    let store = Arc::clone(&store);
                    std::thread::spawn(move || {
                        // xorshift64, a different sequence per thread and round.
                        let mut x = round * 7919 + t * 104_729 + 1;
                        for _ in 0..total {
                            x ^= x << 13;
                            x ^= x >> 7;
                            x ^= x << 17;
                            let n = 100 + (x % u64::from(total)) as u32;
                            let object = store.resolve(id(n)).unwrap();
                            let items = object.as_array().unwrap_or_else(|| panic!("{n}"));
                            assert_eq!(items.first(), Some(&Object::Int(i64::from(n))));
                        }
                    })
                })
                .collect();
            for handle in handles {
                handle.join().unwrap();
            }
            assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
        }
    });
}

#[test]
fn nested_loads_settle_a_dropped_container() {
    // Streams whose /Length is a compressed integer: loading a stream peeks at its length,
    // which decodes the container privately (a nested load never waits on the cache). With
    // room for one container only, the two containers take turns; when a dropped one is
    // decoded again by a nested load, the lengths it holds go to the peek memo, so later
    // streams do not decode it once more.
    const MIB: usize = 1 << 20;
    let first = padded_container(&[(40, "4"), (41, "4"), (42, "4")], MIB);
    let second = padded_container(&[(50, "4"), (51, "4")], MIB);
    let mut pdf = simple_doc();
    for (k, (n, first, data)) in [first, second].iter().enumerate() {
        let encoded = encode_flate(data, 9);
        let dict = format!(
            "<< /Type /ObjStm /N {n} /First {first} /Filter /FlateDecode /Length {} >>",
            encoded.len()
        );
        pdf.stream_with(20 + k as u32, &dict, &encoded);
    }
    let lengths = [(60, 40), (61, 50), (62, 41), (63, 51), (64, 42)];
    for (stream, length) in lengths {
        pdf.stream_with(stream, &format!("<< /Length {length} 0 R >>"), b"data");
    }
    let mut rows: Vec<(u32, Row)> = (1..=4).map(|n| (n, Row::At(n))).collect();
    rows.extend([(20, Row::At(20)), (21, Row::At(21))]);
    rows.extend(
        [40, 41, 42]
            .iter()
            .enumerate()
            .map(|(i, &n)| (n, Row::In(20, i as u32))),
    );
    rows.extend(
        [50, 51]
            .iter()
            .enumerate()
            .map(|(i, &n)| (n, Row::In(21, i as u32))),
    );
    rows.extend(lengths.iter().map(|&(n, _)| (n, Row::At(n))));
    rows.sort_by_key(|r| r.0);
    let at = pdf.xref_stream(9, [1, 4, 2], &rows, "/Root 1 0 R");
    pdf.startxref(at);
    let limits = Limits::default().with_max_objstm_cache(MIB);
    let store = Store::open_bytes(pdf.buf, &OpenOptions::default().with_limits(limits)).unwrap();
    let decoded = store.total_decoded();
    let memo = |num: u32| lock(&store.peeked_objects).contains_key(&id(num));
    // 60 (container 20), 61 (container 21, which drops 20).
    assert_eq!(stream_of(&store, 60), b"data");
    assert_eq!(stream_of(&store, 61), b"data");
    assert_eq!(decodes(&store), 2);
    assert!(!memo(42));
    // 62: container 20 again, which settles 42 as well.
    assert_eq!(stream_of(&store, 62), b"data");
    assert_eq!(decodes(&store), 3);
    assert!(memo(41) && memo(42));
    // 63: container 21 again (dropping 20); 64 then needs no container.
    assert_eq!(stream_of(&store, 63), b"data");
    assert_eq!(decodes(&store), 4);
    assert!(!lock(&store.objstm_cache).entries.contains_key(&20));
    assert_eq!(stream_of(&store, 64), b"data");
    assert_eq!(decodes(&store), 4);
    assert!(!lock(&store.objstm_cache).entries.contains_key(&20));
    // Each container's source data counts once, however often it was decoded.
    assert_eq!(store.total_decoded() - decoded, 2 * MIB as u64 + 5 * 4);
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
    // The lengths were never resolved: nested loads report nothing and fill no slot.
    assert!(!is_loaded(&store, 40) && !is_loaded(&store, 42));
}

#[test]
fn an_extends_walk_through_a_dropped_container_is_charged_again() {
    // The cross-reference data puts 31 and 32 in container 20, which does not hold them; it
    // /Extends container 21, which does. With room for one container, every walk drops one of
    // them: decoding 21 again to follow 20's /Extends is charged again (a damaged file must
    // not make the store decode the same containers over and over for free), while 20, decoded
    // again for the objects it is named for, is not.
    const MIB: usize = 1 << 20;
    let (n0, first0, data0) = padded_container(&[(30, "(thirty)")], MIB);
    let (n1, first1, data1) = padded_container(&[(31, "(thirty-one)"), (32, "(thirty-two)")], MIB);
    let mut pdf = simple_doc();
    for (num, n, first, data, extra) in [
        (20, n0, first0, &data0, "/Extends 21 0 R"),
        (21, n1, first1, &data1, ""),
    ] {
        let encoded = encode_flate(data, 9);
        let dict = format!(
            "<< /Type /ObjStm /N {n} /First {first} /Filter /FlateDecode /Length {} {extra} >>",
            encoded.len()
        );
        pdf.stream_with(num, &dict, &encoded);
    }
    let mut rows: Vec<(u32, Row)> = (1..=4).map(|n| (n, Row::At(n))).collect();
    rows.extend([
        (20, Row::At(20)),
        (21, Row::At(21)),
        (30, Row::In(20, 0)),
        (31, Row::In(20, 1)),
        (32, Row::In(20, 2)),
    ]);
    let at = pdf.xref_stream(9, [1, 4, 2], &rows, "/Root 1 0 R");
    pdf.startxref(at);
    let limits = Limits::default().with_max_objstm_cache(MIB + MIB / 2);
    let store = Store::open_bytes(pdf.buf, &OpenOptions::default().with_limits(limits)).unwrap();
    let decoded = store.total_decoded();
    // 31: 20, then 21 through /Extends (which drops 20).
    assert_eq!(str_of(&store, 31).as_deref(), Some(&b"thirty-one"[..]));
    assert_eq!(decodes(&store), 2);
    assert_eq!(store.total_decoded() - decoded, 2 * MIB as u64);
    assert!(store.recovered_objects().contains(&id(31)));
    // 30: 20 again, free; settling it loads 32, whose walk decodes 21 again (dropped by 20):
    // charged again.
    assert_eq!(str_of(&store, 30).as_deref(), Some(&b"thirty"[..]));
    assert_eq!(decodes(&store), 4);
    assert!(is_loaded(&store, 32));
    assert_eq!(store.total_decoded() - decoded, 3 * MIB as u64);
    assert_eq!(str_of(&store, 32).as_deref(), Some(&b"thirty-two"[..]));
    assert_eq!(decodes(&store), 4);
}

#[test]
fn object_streams_have_a_decoded_cap() {
    // A container that decodes to 2 MiB, with max_objstm_decoded = 1 MiB: its objects cannot
    // be resolved, in either mode; the rest of the document reads.
    let container = padded_container(&[(100, "(hundred)")], 2 << 20);
    let bytes = objstm_doc(&[container], &[(100, 20, 0)]);
    let limits = Limits::default().with_max_objstm_decoded(1 << 20);
    for strictness in [Strictness::Lenient, Strictness::Strict] {
        let options = OpenOptions::default()
            .with_limits(limits)
            .with_strictness(strictness);
        let store = Store::open_bytes(bytes.clone(), &options).unwrap();
        check_simple(&store);
        let before = store.total_decoded();
        let err = store.resolve(id(100)).unwrap_err();
        assert!(
            matches!(
                err,
                Error::LimitExceeded {
                    limit: LimitKind::MaxObjStmDecoded,
                    max: 1_048_576,
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(store.objstm_cache_bytes(), 0);
        // The decode stopped at the cap, and that much is charged.
        assert_eq!(store.total_decoded() - before, 1 << 20);
    }
    // The default cap (64 MiB) lets it through.
    assert_eq!(str_of(&open(&bytes), 100).as_deref(), Some(&b"hundred"[..]));

    // A reconstruction skips such a container (with a diagnostic) but reads the others.
    let mut pdf = simple_doc();
    pdf.objstm(20, &[(10, "(ten)")], "");
    let big = encode_flate(&padded_container(&[(11, "(eleven)")], 2 << 20).2, 9);
    let first = objstm_data(&[(11, "(eleven)")]).1;
    pdf.stream_with(
        21,
        &format!(
            "<< /Type /ObjStm /N 1 /First {first} /Filter /FlateDecode /Length {} >>",
            big.len()
        ),
        &big,
    );
    pdf.trailer("/Root 1 0 R");
    let store =
        Store::open_bytes(pdf.buf.clone(), &OpenOptions::default().with_limits(limits)).unwrap();
    assert_eq!(str_of(&store, 10).as_deref(), Some(&b"ten"[..]));
    assert!(store.resolve(id(11)).unwrap().is_null());
    assert!(
        store
            .diagnostics()
            .iter()
            .any(|d| d.message.contains("more than max_objstm_decoded")),
        "{:?}",
        store.diagnostics()
    );
}

#[test]
fn object_stream_members_are_capped() {
    // A container whose header lists object 100 at offset 0 twenty thousand times (`100 0`
    // compresses to almost nothing): a file of a few kilobytes keeps at most 4096 objects, so
    // no more members are read, and the tables stay small.
    let pairs = 20_000;
    let mut data = "100 0 ".repeat(pairs).into_bytes();
    let first = data.len();
    data.extend_from_slice(b"(hundred)");
    let bytes = objstm_doc(&[(pairs as u32, first, data)], &[(100, 20, 3)]);
    assert!(bytes.len() < 4096, "{}", bytes.len());
    let store = open(&bytes);
    assert_eq!(str_of(&store, 100).as_deref(), Some(&b"hundred"[..]));
    let container = store.objstm(20, false).unwrap().0;
    assert!(container.capped);
    assert_eq!(container.members().count(), 4096);
    // 20 bytes per member, plus the data.
    assert!(
        container.weight() <= (first + 9 + 4096 * 20 + 256) as u64,
        "{}",
        container.weight()
    );
    assert!(
        store
            .diagnostics()
            .iter()
            .any(|d| d.kind == DiagnosticKind::ObjectStream
                && d.message.contains("lists more than 4096 objects")),
        "{:?}",
        store.diagnostics()
    );
    // Strict mode refuses a container with more members than the cap, naming the bound that
    // holds (here max_objects, set low; the offsets increase, which strict mode requires).
    let pairs = 2_000;
    let mut data: Vec<u8> = (0..pairs)
        .flat_map(|k| format!("100 {k} ").into_bytes())
        .collect();
    let first = data.len();
    // Member 999 (the last one kept) starts at offset 999 and, with the rest ignored, runs to
    // the end of the data.
    data.resize(first + 999, b' ');
    data.extend_from_slice(b"(hundred)");
    data.resize(first + pairs + 16, b' ');
    let bytes = objstm_doc(&[(pairs as u32, first, data)], &[(100, 20, 999)]);
    let limits = Limits::default().with_max_objects(1000);
    let strict = OpenOptions::default()
        .with_strictness(Strictness::Strict)
        .with_limits(limits);
    let err = Store::open_bytes(bytes.clone(), &strict)
        .unwrap()
        .resolve(id(100))
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::LimitExceeded {
                limit: LimitKind::MaxObjects,
                max: 1000,
                ..
            }
        ),
        "{err:?}"
    );
    let lenient = Store::open_bytes(bytes, &OpenOptions::default().with_limits(limits)).unwrap();
    assert_eq!(str_of(&lenient, 100).as_deref(), Some(&b"hundred"[..]));
    assert_eq!(lenient.objstm(20, false).unwrap().0.members().count(), 1000);
}

#[test]
fn objects_in_object_streams_have_a_memory_budget() {
    // Three members of 2.5 million `0` each (5 MB decoded, a few kilobytes compressed): parsed,
    // each takes 80 MB of objects, more than a small file may spend (64 MiB). Resolving one
    // fails at the budget instead of building it; the budget is then spent for the store, while
    // uncompressed objects still read.
    let array = format!("[{}]", "0 ".repeat(2_500_000));
    let small = "[1 2 3]";
    let container = padded_container(&[(100, small), (101, &array), (102, small)], 0);
    let bytes = objstm_doc(&[container], &[(100, 20, 0), (101, 20, 1), (102, 20, 2)]);
    assert!(bytes.len() < 64 << 10, "{}", bytes.len());
    let budget = 64u64 << 20;
    for strictness in [Strictness::Lenient, Strictness::Strict] {
        let store = Store::open_bytes(bytes.clone(), &options(strictness)).unwrap();
        assert_eq!(
            store
                .resolve(id(100))
                .unwrap()
                .as_array()
                .map(<[Object]>::len),
            Some(3)
        );
        let err = store.resolve(id(101)).unwrap_err();
        assert!(
            matches!(
                err,
                Error::LimitExceeded {
                    limit: LimitKind::ObjStmParsed,
                    max,
                    ..
                } if max == budget
            ),
            "{err:?}"
        );
        // What the failed parse built was charged (about the budget), and nothing more.
        let used = store.objstm_parsed_bytes();
        assert!(used > budget && used < budget + 1024, "{used}");
        assert!(store.resolve(id(102)).is_err());
        check_simple(&store);
    }
    // A trusted caller raises the budget.
    let limits = Limits::default().with_budget_scale(2);
    let store = Store::open_bytes(bytes, &OpenOptions::default().with_limits(limits)).unwrap();
    let array = store.resolve(id(101)).unwrap();
    assert_eq!(array.as_array().map(<[Object]>::len), Some(2_500_000));
    // 32 bytes per element, and nothing spare.
    assert!(store.objstm_parsed_bytes() >= 2_500_000 * 32);
    assert!(store.objstm_parsed_bytes() < 2_500_000 * 32 + 1024);
}

#[test]
fn an_appended_update_with_a_bad_startxref_is_not_hidden() {
    // An update after the fourth revision redefines object 5 with a valid table, but its own
    // startxref is bogus. The earlier startxref would lead to a consistent chain that hides the
    // update; other readers reconstruct the file and show it, and so does the store.
    let (mut bytes, tables, _) = incremental_doc();
    let at = bytes.len();
    bytes.extend_from_slice(b"5 0 obj\n(new five)\nendobj\n");
    let table = bytes.len();
    bytes.extend_from_slice(
        format!(
            "xref\n5 1\n{at:010} 00000 n\r\ntrailer\n<< /Size 6 /Root 1 0 R /Prev {} >>\n\
             startxref\n99999999\n%%EOF\n",
            tables[3]
        )
        .as_bytes(),
    );
    assert!(table > at);
    let store = open(&bytes);
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"new five"[..]));
    assert!(store.structure_repaired());
    assert_eq!(store.revisions().len(), 1);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
    assert!(store.recovered_objects().contains(&id(5)));
    // An update that no startxref leads to.
    let report = diagnostic(&store, DiagnosticKind::UnreferencedUpdate);
    assert!(
        report.message.contains("is reconstructed"),
        "{}",
        report.message
    );
    assert_eq!(report.offset, Some(at as u64));
    assert!(is_type(&root(&store), b"Catalog"));
    // The newest definitions win, as in the revisions: object 4 as revision 3 changed it.
    assert_eq!(stream_of(&store, 4), b"q 1 0 0 1 0 0 cm Q");
    assert_eq!(open_strict(&bytes).unwrap_err().code(), ErrorCode::Xref);

    // A trailer alone after the revisions (an update that only changes the trailer) counts too.
    let (mut bytes, tables, _) = incremental_doc();
    bytes.extend_from_slice(
        format!(
            "xref\n0 0\ntrailer\n<< /Size 6 /Root 1 0 R /Prev {} /Info 5 0 R >>\n\
             startxref\n99999999\n%%EOF\n",
            tables[3]
        )
        .as_bytes(),
    );
    let store = open(&bytes);
    assert_eq!(store.revisions().len(), 1);
    assert_eq!(store.trailer().get_ref(b"Info"), Some(id(5)));

    // Pure junk after the last revision still keeps the revisions (an_earlier_startxref_is_tried).
    let (mut bytes, ..) = incremental_doc();
    bytes.extend_from_slice(b"\nstartxref\n99999999\n%%EOF\n% junk\n");
    assert_eq!(open(&bytes).revisions().len(), 4);
}

/// `bytes` with a last `startxref` appended that leads nowhere.
fn with_bad_tail(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.extend_from_slice(b"startxref\n99999999\n%%EOF\n");
    bytes
}

/// The diagnostic of kind `kind` (the first one).
fn diagnostic(store: &Store, kind: DiagnosticKind) -> Diagnostic {
    store
        .diagnostics()
        .into_iter()
        .find(|d| d.kind == kind)
        .unwrap_or_else(|| panic!("no {kind}: {:?}", store.diagnostics()))
}

#[test]
fn an_earlier_chain_that_hides_a_definition_is_not_used() {
    // QA reproducer: one revision lists `5 0 obj (good)`, and an orphan `5 0 obj (evil)` sits
    // before its table; the last startxref leads nowhere. The earlier startxref leads to a
    // valid chain that shows "good", but qpdf, pdf.js and poppler reconstruct the file, where
    // the last definition wins, and show "evil" (pikepdf 10.16 / qpdf 12.4.2, poppler 24), so
    // the store reconstructs it too.
    let build = |orphan: bool| {
        let mut pdf = simple_doc();
        pdf.obj(5, "(good)");
        if orphan {
            pdf.raw("5 0 obj\n(evil)\nendobj\n");
        }
        pdf.finish("/Root 1 0 R /Info 5 0 R")
    };
    let bytes = with_bad_tail(build(true));
    let store = open(&bytes);
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"evil"[..]));
    assert!(store.structure_repaired());
    assert_eq!(store.revisions().len(), 1);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
    assert!(store.recovered_objects().contains(&id(5)));
    let shadow = diagnostic(&store, DiagnosticKind::XrefMalformed);
    assert_eq!(shadow.offset, Some(rfind(&bytes, b"5 0 obj") as u64));
    assert!(
        shadow.message.contains("object 5") && shadow.message.contains("is reconstructed"),
        "{}",
        shadow.message
    );
    check_simple(&store);
    assert_eq!(store.trailer().get_ref(b"Info"), Some(id(5)));
    assert_eq!(open_strict(&bytes).unwrap_err().code(), ErrorCode::Xref);
    // Read through its own startxref, the file shows the definition its table lists, as every
    // reader does.
    assert_eq!(
        str_of(&open(&build(true)), 5).as_deref(),
        Some(&b"good"[..])
    );
    // Without the orphan the earlier chain shows what a reconstruction shows: it is kept.
    let store = open(&with_bad_tail(build(false)));
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Table);
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"good"[..]));
    assert_eq!(kinds(&store), [DiagnosticKind::XrefMalformed]);
    assert!(store.recovered_objects().is_empty());

    // A deletion before a definition: the second revision frees 6, and the body of the third
    // defines 6 again without listing it. Readers that reconstruct show it (pikepdf: "evil
    // six"). A deletion after the last definition holds (an_earlier_startxref_is_tried).
    let mut pdf = simple_doc();
    pdf.obj(6, "(six)");
    let first = pdf.table("\r\n");
    pdf.trailer("/Root 1 0 R /Info 6 0 R").startxref(first);
    let second = pdf.table_rows(&[(6, Row::Free(1))], "\r\n", None);
    pdf.raw(format!(
        "trailer\n<< /Size 7 /Root 1 0 R /Info 6 0 R /Prev {first} >>\n"
    ))
    .startxref(second);
    pdf.raw("6 0 obj\n(evil six)\nendobj\n").obj(5, "(five)");
    let third = pdf.table_rows(&[(5, Row::At(5))], "\r\n", None);
    pdf.raw(format!(
        "trailer\n<< /Size 7 /Root 1 0 R /Info 6 0 R /Prev {second} >>\n"
    ))
    .startxref(third);
    let store = open(&pdf.buf);
    assert!(store.resolve(id(6)).unwrap().is_null());
    assert_eq!(store.revisions().len(), 3);
    let store = open(&with_bad_tail(pdf.buf.clone()));
    assert_eq!(str_of(&store, 6).as_deref(), Some(&b"evil six"[..]));
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"five"[..]));
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
    assert!(
        diagnostic(&store, DiagnosticKind::XrefMalformed)
            .message
            .contains("object 6")
    );

    // A number no section lists, defined in the body: reconstructed, so that it shows.
    let mut pdf = simple_doc();
    pdf.raw("7 0 obj\n(seven)\nendobj\n");
    let good = pdf.finish("/Root 1 0 R /Info 7 0 R");
    assert!(open(&good).resolve(id(7)).unwrap().is_null());
    let store = open(&with_bad_tail(good));
    assert_eq!(str_of(&store, 7).as_deref(), Some(&b"seven"[..]));
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
}

#[test]
fn an_earlier_chain_of_object_streams_is_compared_too() {
    // A compressed object defined again, uncompressed, after its object stream wins in a
    // reconstruction; one defined before it (an older, uncompressed version) does not. The
    // cross-reference stream does not list itself here, which is no reason to reconstruct.
    let build = |stale: Option<bool>, self_listed: bool| {
        let mut pdf = Pdf::new();
        let pages = "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 /Stale true >>\nendobj\n";
        if stale == Some(false) {
            pdf.raw(pages);
        }
        pdf.objstm(
            5,
            &[
                (1, "<< /Type /Catalog /Pages 2 0 R >>"),
                (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
                (3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>"),
            ],
            "",
        )
        .stream(4, "", CONTENT);
        if stale == Some(true) {
            pdf.raw(pages);
        }
        let mut rows = vec![
            (0, Row::Free(255)),
            (1, Row::In(5, 0)),
            (2, Row::In(5, 1)),
            (3, Row::In(5, 2)),
            (4, Row::At(4)),
            (5, Row::At(5)),
        ];
        if self_listed {
            let at = pdf.pos();
            pdf.objects.insert(6, (at, 0));
            rows.push((6, Row::At(6)));
        }
        let at = pdf.xref_stream(6, [1, 2, 1], &rows, "/Root 1 0 R");
        pdf.startxref(at);
        with_bad_tail(pdf.buf)
    };
    let stale = |store: &Store| {
        store
            .resolve(id(2))
            .unwrap()
            .as_dict()
            .unwrap()
            .get(b"Stale")
            .is_some()
    };
    for self_listed in [false, true] {
        let store = open(&build(None, self_listed));
        assert_eq!(
            store.revisions()[0].xref_kind,
            XrefKind::Stream,
            "{self_listed}"
        );
        assert!(!stale(&store));
        let store = open(&build(Some(false), self_listed));
        assert_eq!(
            store.revisions()[0].xref_kind,
            XrefKind::Stream,
            "{self_listed}"
        );
        assert!(!stale(&store));
        let store = open(&build(Some(true), self_listed));
        assert_eq!(
            store.revisions()[0].xref_kind,
            XrefKind::Reconstructed,
            "{self_listed}"
        );
        assert!(stale(&store));
    }
}

/// The simple document with `5 0 obj (good)` and `/Info 5 0 R`, then `decoy` (raw bytes,
/// listed in no section), then object 6 holding `six` (a string, or any value), all listed in
/// one table (`table`) or none (a file to reconstruct).
fn with_decoy(decoy: &str, six: &str, table: bool) -> Vec<u8> {
    let mut pdf = simple_doc();
    pdf.obj(5, "(good)");
    pdf.raw(decoy);
    pdf.obj(6, six);
    if table {
        pdf.finish("/Root 1 0 R /Info 5 0 R")
    } else {
        pdf.trailer("/Root 1 0 R /Info 5 0 R");
        pdf.buf
    }
}

#[test]
fn header_text_never_shadows_a_valid_chain() {
    // QA round 3: header-like text that is no object definition, before the table of a valid
    // revision whose last startxref leads nowhere. The chain shows "good" for each, so the
    // earlier startxref keeps the revision. Before the fix the shadow check took the text for a
    // later definition and reconstructed the file, showing "evil" (and object 6, cut at the
    // text, as null). qpdf (pikepdf 10.16 / qpdf 12.4.2) agrees for the comment, the string
    // token at the start of a line (its 10-byte token cut swallows the header on the next line)
    // and the other generation; it takes the header inside the dictionary's string and inside
    // stream data (its line scan does, as pdf.js does) and shows "evil". That is a deliberate
    // difference (ARCHITECTURE §A.10 trap #14): text inside an object that parses never changes
    // what a valid chain resolves to.
    let string_six = "(x\n5 0 obj\n(evil)\nendobj\n)";
    let cases: [(&str, &str, &str); 5] = [
        ("comment", "% see 5 0 obj (evil) endobj\n", "(six)"),
        ("string", "", string_six),
        (
            "dictionary",
            "",
            "<< /A [ (\n5 0 obj\n(evil)\nendobj\n) ] /B 1 >>",
        ),
        (
            "stream data",
            "",
            "<< /Length 25 >>\nstream\nq\n5 0 obj\n(evil)\nendobj\nQ\nendstream",
        ),
        // Another generation is another object (§7.3.10): it does not shadow `5 0`.
        ("generation", "5 1 obj\n(gen1)\nendobj\n", "(six)"),
    ];
    for (name, decoy, six) in cases {
        let valid = with_decoy(decoy, six, true);
        let reference = open(&valid);
        assert!(reference.diagnostics().is_empty(), "{name}");
        let six_value = reference.resolve(id(6)).unwrap();
        assert!(!six_value.is_null(), "{name}");
        let bytes = with_bad_tail(valid);
        let store = open(&bytes);
        assert_eq!(store.revisions().len(), 1, "{name}");
        assert_eq!(store.revisions()[0].xref_kind, XrefKind::Table, "{name}");
        assert_eq!(str_of(&store, 5).as_deref(), Some(&b"good"[..]), "{name}");
        assert_eq!(store.resolve(id(6)).unwrap(), six_value, "{name}");
        // Only the earlier startxref is reported.
        assert_eq!(kinds(&store), [DiagnosticKind::XrefMalformed], "{name}");
        check_simple(&store);
        assert_eq!(open_strict(&bytes).unwrap_err().code(), ErrorCode::Xref);
    }
    // The string survives whole.
    let store = open(&with_bad_tail(with_decoy("", string_six, true)));
    assert_eq!(
        str_of(&store, 6).as_deref(),
        Some(&b"x\n5 0 obj\n(evil)\nendobj\n"[..])
    );
    // A reconstruction would also show `5 1 obj` as object 5 1, which the revision does not
    // list: the store adds it (recovered), so `5 1 R` resolves as qpdf resolves it, while
    // `5 0 R` keeps the revision's object. Read through its own startxref, the file has no
    // object 5 1, as for every reader.
    let valid = with_decoy("5 1 obj\n(gen1)\nendobj\n", "(six)", true);
    assert!(open(&valid).resolve(ObjectId::new(5, 1)).unwrap().is_null());
    let store = open(&with_bad_tail(valid));
    let gen1 = store.resolve(ObjectId::new(5, 1)).unwrap();
    assert_eq!(gen1.as_str_bytes(), Some(&b"gen1"[..]));
    assert_eq!(store.recovered_objects(), [ObjectId::new(5, 1)]);
    assert!(store.object_ids().contains(&ObjectId::new(5, 1)));

    // A true shadow still counts: the same text at the start of a line, outside every object.
    let store = open(&with_bad_tail(with_decoy(
        "5 0 obj\n(evil)\nendobj\n",
        "(six)",
        true,
    )));
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"evil"[..]));
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
}

/// The simple document, then `count` objects from number 60 on holding `body` (listed in the
/// table, or written raw and listed nowhere), then the hexadecimal-string closer `>>` when the
/// body is [`HEX_RUN`], a comment of `gap` bytes (none for 0), `5 0 obj (good)`, and object 6
/// holding a dictionary whose string holds the header `5 0 obj (evil)` at the start of a line.
/// `table`: a table and trailer (otherwise only a trailer).
fn damaged_then_decoy(body: &str, count: u32, listed: bool, gap: usize, table: bool) -> Vec<u8> {
    let mut pdf = simple_doc();
    for k in 0..count {
        if listed {
            pdf.obj(60 + k, body);
        } else {
            pdf.raw(format!("{} 0 obj\n{body}\nendobj\n", 60 + k));
        }
    }
    if body == HEX_RUN {
        pdf.raw(">>\n");
    }
    if gap > 0 {
        pdf.raw(format!("%{}\n", "p".repeat(gap)));
    }
    pdf.obj(5, "(good)");
    pdf.obj(6, "<< /S [ (\n5 0 obj\n(evil)\nendobj\n) ] >>");
    if table {
        pdf.finish("/Root 1 0 R /Info 5 0 R")
    } else {
        pdf.trailer("/Root 1 0 R /Info 5 0 R");
        pdf.buf
    }
}

/// A body for [`damaged_then_decoy`]: an array whose hexadecimal string, read leniently, runs
/// to the next `>`, where the parse then fails at the lone `>` after it. Many of them in a row
/// all run to the same `>`, so checking each of them on its own that way would read the run once
/// per object: quadratic in their number. (The coverage parses of `repair::definitions` end each
/// string at its first invalid byte, as qpdf does; values are still read leniently, each within
/// its object's region.)
const HEX_RUN: &str = "[<";

/// A body for [`damaged_then_decoy`]: a literal string that never closes.
const UNTERMINATED: &str = "(unterminated \\( string";

/// The string inside object 6 of [`damaged_then_decoy`], if 6 reads whole.
fn decoy_six(store: &Store) -> Option<Vec<u8>> {
    let six = store.resolve(id(6)).unwrap();
    let first = six
        .as_dict()?
        .get_array(b"S")?
        .first()?
        .as_str_bytes()?
        .to_vec();
    Some(first)
}

#[test]
fn damaged_objects_never_let_header_text_after_them_shadow_a_valid_chain() {
    // Expert reproducers (M1 QA rounds 4 and 5): damaged objects before `5 0 obj (good)` and
    // object 6, whose dictionary string holds the header `5 0 obj (evil)`: forty arrays nested
    // too deep, six strings that never close followed by 8 KiB, and two thousand hexadecimal
    // strings that, read leniently, all run to the same `>`. Each damaged object takes only what
    // its parse read (up to the nesting limit, the few kilobytes of a string that never closes,
    // the first invalid byte of a hexadecimal string), so object 6, after that, parses and
    // covers its text: the valid chain (bad tail) is kept, 5 reads "good", 6 whole. qpdf shows
    // "evil" and 6 whole, as it takes headers inside dictionary strings (trap #14). An earlier
    // design charged these checks to a budget, which a short prefix could exhaust (round 4) or
    // which, once cut, quadratic region bounds made slow to resolve (round 5).
    let deep = "[".repeat(300);
    let far = 2 * crate::lexer::LONG_STRING;
    for (name, body, count, gap) in [
        ("deep", deep.as_str(), 40, 0),
        ("strings", UNTERMINATED, 6, far),
        ("hex", HEX_RUN, 2000, 0),
    ] {
        // Listed in the table: the chain is valid and kept.
        let bytes = with_bad_tail(damaged_then_decoy(body, count, true, gap, true));
        let store = open(&bytes);
        assert_eq!(store.revisions()[0].xref_kind, XrefKind::Table, "{name}");
        assert_eq!(str_of(&store, 5).as_deref(), Some(&b"good"[..]), "{name}");
        assert_eq!(
            decoy_six(&store).as_deref(),
            Some(&b"\n5 0 obj\n(evil)\nendobj\n"[..]),
            "{name}"
        );
        // Only the earlier startxref is reported.
        assert_eq!(kinds(&store), [DiagnosticKind::XrefMalformed], "{name}");
        check_simple(&store);
        // Listed nowhere: reconstructed (the unlisted objects are newer data), where the header
        // inside 6 is no definition either.
        for bytes in [
            with_bad_tail(damaged_then_decoy(body, count, false, gap, true)),
            damaged_then_decoy(body, count, false, gap, false),
        ] {
            let store = open(&bytes);
            assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
            assert_eq!(str_of(&store, 5).as_deref(), Some(&b"good"[..]), "{name}");
            assert!(decoy_six(&store).is_some(), "{name}");
            assert!(!has(&store, DiagnosticKind::Other), "{name}");
            check_simple(&store);
        }
    }
}

#[test]
fn headers_inside_a_damaged_object_count_as_qpdf_counts_them() {
    // The six strings that never close right before 5 and 6: the first one's parse reads a few
    // kilobytes, which hold 5, 6 and the header inside 6's string. Nothing tells whether that
    // damaged object encloses them, so all are definitions, taken unparsed, as qpdf takes every
    // header at the start of a line: the later `5 0 obj` shadows the valid chain, which is
    // reconstructed, and 5 reads "evil", as in qpdf. Object 6 ends where the next definition
    // starts (the header in its string), as every object's region does, so it reads as null;
    // qpdf, which does not bound objects by the next one, reads it whole (trap #14).
    for bytes in [
        with_bad_tail(damaged_then_decoy(UNTERMINATED, 6, true, 0, true)),
        damaged_then_decoy(UNTERMINATED, 6, false, 0, false),
    ] {
        let store = open(&bytes);
        assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
        assert_eq!(str_of(&store, 5).as_deref(), Some(&b"evil"[..]));
        assert!(store.resolve(id(6)).unwrap().is_null());
        check_simple(&store);
    }
}

#[test]
fn a_definition_after_damaged_objects_still_shadows_a_valid_chain() {
    // Expert reproducers (M1 QA round 5, V5D/V5H/V5J): damaged objects that are cheap to write
    // (hexadecimal strings that, read leniently, run to the same `>`, or literal strings that
    // close far away before a lone `>`), then 5 (good), 6, and an orphan `5 0 obj (orphan)` at
    // the top level after them. Nothing encloses the orphan, so it is a definition: the valid
    // chain (bad tail) does not show what a reconstruction shows, and the file is
    // reconstructed, with 5 "orphan", as in qpdf. (Once the coverage budget of an earlier design
    // ran out, the orphan counted unchecked and the chain was kept, with 5 "good".)
    for (name, body, closer) in [
        ("hex", HEX_RUN, ">>\n".to_owned()),
        ("strings", "[(", format!("{} >\n", ")".repeat(5))),
    ] {
        let mut pdf = simple_doc();
        for k in 0..5 {
            pdf.obj(60 + k, body);
        }
        pdf.raw(format!("%{}\n", "p".repeat(10_000)));
        pdf.raw(closer);
        pdf.obj(5, "(good)").obj(6, "(six)");
        pdf.raw("5 0 obj\n(orphan)\nendobj\n");
        let valid = pdf.finish("/Root 1 0 R /Info 5 0 R");
        assert_eq!(
            str_of(&open(&valid), 5).as_deref(),
            Some(&b"good"[..]),
            "{name}"
        );
        let store = open(&with_bad_tail(valid));
        assert_eq!(
            store.revisions()[0].xref_kind,
            XrefKind::Reconstructed,
            "{name}"
        );
        assert_eq!(str_of(&store, 5).as_deref(), Some(&b"orphan"[..]), "{name}");
        assert_eq!(str_of(&store, 6).as_deref(), Some(&b"six"[..]), "{name}");
        assert!(has(&store, DiagnosticKind::XrefMalformed), "{name}");
        check_simple(&store);
    }
}

#[test]
fn a_hex_string_with_an_invalid_byte_hides_no_definition_after_it() {
    // Expert probe P13 (shadow-attack shape): `5 0 obj (good)`, then object 7 `<41 zz`, 6, an
    // orphan `5 0 obj (orphan)` at the top level, and a `>` on the last line before the table.
    // Read leniently, 7's hexadecimal string skipped the `z`s and ran to that `>`, so the
    // coverage parse of 7 succeeded and took 6 and the orphan for text: the valid chain (bad
    // tail) was kept, with 5 "good", and a reconstruction showed 6 as null. Coverage parses end
    // a hexadecimal string at its first invalid byte, as qpdf's token does: the orphan is a
    // definition, the chain is reconstructed, and 5 reads "orphan", 6 "six", as in qpdf.
    let build = |table: bool| {
        let mut pdf = simple_doc();
        pdf.obj(5, "(good)").obj(7, "<41 zz").obj(6, "(six)");
        pdf.raw("5 0 obj\n(orphan)\nendobj\n%>\n");
        if table {
            pdf.finish("/Root 1 0 R /Info 5 0 R")
        } else {
            pdf.trailer("/Root 1 0 R /Info 5 0 R");
            pdf.buf
        }
    };
    // Read through its own startxref, the file shows what its table lists.
    let store = open(&build(true));
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Table);
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"good"[..]));
    let bytes = with_bad_tail(build(true));
    let store = open(&bytes);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
    let shadow = diagnostic(&store, DiagnosticKind::XrefMalformed);
    assert!(shadow.message.contains("object 5"), "{}", shadow.message);
    assert_eq!(shadow.offset, Some(rfind(&bytes, b"5 0 obj") as u64));
    for store in [store, open(&build(false))] {
        assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
        assert_eq!(str_of(&store, 5).as_deref(), Some(&b"orphan"[..]));
        assert_eq!(str_of(&store, 6).as_deref(), Some(&b"six"[..]));
        // Object 7 itself reads leniently, within its region (up to 6): its string never
        // closes there, so it reads as null, as in qpdf.
        assert!(store.resolve(id(7)).unwrap().is_null());
        assert_eq!(store.trailer().get_ref(b"Info"), Some(id(5)));
        check_simple(&store);
    }
}

#[test]
fn an_object_after_damaged_objects_reads_whole() {
    // Expert reproducer (M1 QA round 5, V5B): a damaged run, then 5 (good) and object 6 whose
    // dictionary string holds two headers, `5 0 obj (evil)` and `7 0 obj (seven-evil)`, without
    // cross-reference data. Object 6 parses after the run and covers both, so neither is a
    // definition: 6 reads whole (it read as null, cut at the first header, when the budget had
    // run out), 5 "good", and 7 is not defined. qpdf takes both headers (5 "evil", 7
    // "seven-evil") and reads 6 whole (trap #14).
    let mut pdf = simple_doc();
    for k in 0..8 {
        pdf.obj(60 + k, HEX_RUN);
    }
    pdf.raw(format!("%{}\n>>\n", "p".repeat(10_000)));
    pdf.obj(5, "(good)");
    pdf.obj(
        6,
        "<< /S [ (\n5 0 obj\n(evil)\nendobj\n7 0 obj\n(seven-evil)\nendobj\n) ] >>",
    );
    pdf.trailer("/Root 1 0 R /Info 5 0 R");
    let store = open(&pdf.buf);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"good"[..]));
    assert_eq!(
        decoy_six(&store).as_deref(),
        Some(&b"\n5 0 obj\n(evil)\nendobj\n7 0 obj\n(seven-evil)\nendobj\n"[..])
    );
    assert!(store.resolve(id(7)).unwrap().is_null());
    assert!(!store.object_ids().contains(&id(7)));
    check_simple(&store);
}

/// A file of `count` damaged objects `N 0 obj` (from 10 on), each holding `body` on a line of
/// its own, then `tail`, between a catalog, a page tree and a trailer, without cross-reference
/// data (the shapes of QA's round-5 timing probes).
fn damaged_file(count: u32, body: &str, tail: &str) -> Vec<u8> {
    let mut file = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
                     2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n"
        .to_vec();
    for n in 10..10 + count {
        file.extend_from_slice(format!("{n} 0 obj\n{body}\n").as_bytes());
    }
    file.extend_from_slice(tail.as_bytes());
    file.extend_from_slice(b"trailer\n<< /Size 10 /Root 1 0 R >>\n");
    file
}

/// Opens `bytes` and resolves every object, then returns the bytes that telling definitions
/// from text read and the bytes of the regions the objects were parsed within.
fn resolve_all_work(bytes: &[u8]) -> (u64, u64) {
    let store = open(bytes);
    let ids = store.object_ids();
    for id in &ids {
        // Lenient: unreadable objects are null; a limit (nesting) is an error.
        let _ = store.resolve(*id);
    }
    check_catalog(&store);
    let defs = store.definitions().bytes_read();
    (defs, store.region_bytes.load(Ordering::Relaxed))
}

/// The catalog of a [`damaged_file`] still reads.
fn check_catalog(store: &Store) {
    assert!(is_type(&root(store), b"Catalog"));
}

#[test]
fn resolving_damaged_objects_is_linear() {
    // QA round 5: after the coverage budget of an earlier design ran out, an object's region
    // ran on to the first object after the next `endobj`, so with no `endobj` at all (or a
    // single one at the end) every region reached the end of the file, and resolving every
    // object was quadratic (40,000 objects `N 0 obj [<`: 25 s; 200,000: more than 300 s).
    // Regions end at the next definition again, and the coverage pass is linear by
    // construction: twice the objects, about twice the work, and never much more than the file.
    for (name, body, tail) in [
        ("hex", "[<", ">>\n"),
        ("hex, one endobj", "[<", ">>\nendobj\n"),
        ("hex, endobj each", "[<\nendobj", ">>\n"),
        ("unclosed strings", "<< /A << /B [ (", ""),
    ] {
        let mut work = Vec::new();
        for count in [20_000, 40_000] {
            let bytes = damaged_file(count, body, tail);
            let len = bytes.len() as u64;
            let (defs, regions) = resolve_all_work(&bytes);
            assert!(defs <= 2 * len, "{name}, {count}: {defs} / {len}");
            assert!(regions <= 2 * len, "{name}, {count}: {regions} / {len}");
            work.push((defs, regions));
        }
        let [(d1, r1), (d2, r2)] = work[..] else {
            unreachable!()
        };
        assert!(d2 <= 3 * d1 && r2 <= 3 * r1, "{name}: {work:?}");
    }
}

#[test]
fn a_file_damaged_throughout_opens_in_linear_time() {
    // Twenty thousand hexadecimal strings that, read leniently, all run to the same `>`, before
    // 5 (good) and 6 (whose dictionary string holds a header): each coverage parse ends its
    // string at its first invalid byte (the `n` of its `endobj`), 6 parses after them, and every
    // object's region ends at the next one, so opening and resolving everything reads the file a
    // few times at most.
    let bytes = damaged_then_decoy(HEX_RUN, 20_000, true, 0, false);
    let len = bytes.len() as u64;
    within(60, move || {
        let store = open(&bytes);
        let ids = store.object_ids();
        assert!(ids.len() > 20_000);
        for id in ids {
            store.resolve(id).unwrap();
        }
        assert_eq!(str_of(&store, 5).as_deref(), Some(&b"good"[..]));
        assert!(decoy_six(&store).is_some());
        assert!(store.definitions().bytes_read() <= 2 * len);
        assert!(store.region_bytes.load(Ordering::Relaxed) <= 2 * len);
    });
}

#[test]
fn a_reconstruction_keys_objects_by_number_and_generation() {
    // QA round 3: a file without cross-reference data, where `5 0 obj (good)` is followed by an
    // orphan `5 1 obj (gen1)`, and /Info is 5 0 R. qpdf keeps both objects and shows "good";
    // the store took the last header of number 5, whatever its generation, and showed null.
    let bytes = with_decoy("5 1 obj\n(gen1)\nendobj\n", "(six)", false);
    let store = open(&bytes);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"good"[..]));
    let info = store.deref(store.trailer().get(b"Info").unwrap()).unwrap();
    assert_eq!(info.as_str_bytes(), Some(&b"good"[..]));
    let gen1 = store.resolve(ObjectId::new(5, 1)).unwrap();
    assert_eq!(gen1.as_str_bytes(), Some(&b"gen1"[..]));
    // A generation nothing defines is null, as for qpdf.
    assert!(store.resolve(ObjectId::new(5, 2)).unwrap().is_null());
    assert!(has(&store, DiagnosticKind::WrongGeneration));
    let ids = store.object_ids();
    assert_eq!(
        ids,
        [
            id(1),
            id(2),
            id(3),
            id(4),
            id(5),
            ObjectId::new(5, 1),
            id(6)
        ]
    );
    assert_eq!(store.recovered_objects(), ids);
    // The newest definition of a number is the one the merged view shows: with the generations
    // the other way round, `5 1` is defined last.
    let mut pdf = simple_doc();
    pdf.obj_gen(5, 1, "(gen1)")
        .obj(5, "(gen0)")
        .obj_gen(5, 1, "(gen1 again)");
    pdf.trailer("/Root 1 0 R /Info 5 1 R");
    let store = open(&pdf.buf);
    let info = store.deref(store.trailer().get(b"Info").unwrap()).unwrap();
    assert_eq!(info.as_str_bytes(), Some(&b"gen1 again"[..]));
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"gen0"[..]));
    assert_eq!(store.location(5), store.location_of(ObjectId::new(5, 1)));

    // Header text inside another object, in a comment or in the middle of a line is no
    // definition: object 6 stays whole, and 5 is "good".
    let string_six = "(x\n5 0 obj\n(evil)\nendobj\n)";
    for (name, decoy, six) in [
        ("string", "", string_six),
        ("comment", "% see 5 0 obj (evil) endobj\n", "(six)"),
        (
            "stream data",
            "",
            "<< /Length 25 >>\nstream\nq\n5 0 obj\n(evil)\nendobj\nQ\nendstream",
        ),
    ] {
        let store = open(&with_decoy(decoy, six, false));
        assert_eq!(str_of(&store, 5).as_deref(), Some(&b"good"[..]), "{name}");
        assert!(!store.resolve(id(6)).unwrap().is_null(), "{name}");
        assert_eq!(store.object_ids().len(), 6, "{name}");
    }
    let store = open(&with_decoy("", string_six, false));
    assert_eq!(
        str_of(&store, 6).as_deref(),
        Some(&b"x\n5 0 obj\n(evil)\nendobj\n"[..])
    );
    // In the middle of a line, a header does not count even when it is a real object (qpdf
    // and poppler read the first token of each line), while the one at the start does.
    let mut pdf = simple_doc();
    pdf.obj(5, "(good)");
    pdf.raw("7 0 obj (seven) endobj 5 0 obj (evil) endobj\n");
    pdf.trailer("/Root 1 0 R /Info 5 0 R");
    let store = open(&pdf.buf);
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"good"[..]));
    assert_eq!(str_of(&store, 7).as_deref(), Some(&b"seven"[..]));

    // The same goes for the `trailer` keyword: in a comment or in the middle of a line it is
    // no trailer, at the start of a line (after white-space) it is (pikepdf: root 1, 1, 9).
    for (tail, root) in [
        ("% trailer << /Root 9 0 R >>\n", 1),
        ("(x) trailer << /Root 9 0 R >>\n", 1),
        ("   trailer << /Root 9 0 R >>\n", 9),
    ] {
        let mut pdf = simple_doc();
        pdf.obj(9, "<< /Type /Catalog /Pages 2 0 R /Decoy true >>");
        pdf.trailer("/Root 1 0 R").raw(tail);
        assert_eq!(open(&pdf.buf).root_id(), Some(id(root)), "{tail:?}");
    }
}

/// The simple document with `5 0 obj (old)` and `/Info 5 0 R`, then an incremental update cut
/// short: it redefines 5 as `(new…)` (padded with `pad` bytes), with its table and trailer when
/// `table`, but with no `startxref` and no `%%EOF`. Returns the bytes and where the update
/// starts.
fn cut_update(pad: usize, table: bool) -> (Vec<u8>, usize) {
    let mut pdf = simple_doc();
    pdf.obj(5, "(old)");
    let base = pdf.table("\r\n");
    pdf.trailer("/Root 1 0 R /Info 5 0 R").startxref(base);
    let update = pdf.pos();
    pdf.obj(5, &format!("(new{})", "x".repeat(pad)));
    if table {
        pdf.table_rows(&[(5, Row::At(5))], "\r\n", None);
        pdf.raw(format!(
            "trailer\n<< /Size 6 /Root 1 0 R /Info 5 0 R /Prev {base} >>\n"
        ));
    }
    (pdf.buf, update)
}

/// How far from the end of `bytes` its last `startxref` starts.
fn startxref_distance(bytes: &[u8]) -> usize {
    bytes.len() - rfind(bytes, b"startxref")
}

#[test]
fn an_update_that_no_startxref_leads_to_is_reported() {
    // A save cut short after its objects, table and trailer: the last startxref leads to the
    // previous revision, which the store reads, as qpdf does when that startxref is within the
    // last 1054 bytes (and poppler and pypdf always do). The update is reported as a repair,
    // so a signature verifier sees content outside every revision.
    let (bytes, update) = cut_update(10, true);
    let store = open(&bytes);
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"old"[..]));
    assert_eq!(store.revisions().len(), 1);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Table);
    assert!(store.structure_repaired());
    assert_eq!(kinds(&store), [DiagnosticKind::UnreferencedUpdate]);
    let report = diagnostic(&store, DiagnosticKind::UnreferencedUpdate);
    assert_eq!(report.offset, Some(update as u64));
    assert!(report.message.contains("ignored"), "{}", report.message);
    assert!(store.recovered_objects().is_empty());
    assert_eq!(open_strict(&bytes).unwrap_err().code(), ErrorCode::Xref);
    // Objects alone count, and so do a table and trailer alone.
    let (objects, _) = cut_update(10, false);
    assert_eq!(kinds(&open(&objects)), [DiagnosticKind::UnreferencedUpdate]);
    let mut trailer = cut_update(10, false).0;
    trailer.truncate(update);
    trailer.extend_from_slice(b"trailer\n<< /Size 6 /Root 1 0 R >>\n");
    let store = open(&trailer);
    assert_eq!(kinds(&store), [DiagnosticKind::UnreferencedUpdate]);
    assert!(store.structure_repaired());

    // When the last startxref starts more than 1054 bytes before the end, qpdf does not find
    // it and reconstructs the file, where the newest definitions win (pikepdf 10.16 / qpdf
    // 12.4.2, measured at 1054 and 1055 bytes); so does the store.
    let pad = 10 + 1054 - startxref_distance(&bytes);
    let (at_limit, _) = cut_update(pad, true);
    assert_eq!(startxref_distance(&at_limit), 1054);
    let store = open(&at_limit);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Table);
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"old"[..]));
    let (beyond, update) = cut_update(pad + 1, true);
    assert_eq!(startxref_distance(&beyond), 1055);
    let store = open(&beyond);
    assert!(str_of(&store, 5).unwrap().starts_with(b"newx"));
    assert_eq!(store.revisions().len(), 1);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
    assert!(store.structure_repaired());
    assert_eq!(
        kinds(&store),
        [
            DiagnosticKind::UnreferencedUpdate,
            DiagnosticKind::XrefReconstructed
        ]
    );
    let report = diagnostic(&store, DiagnosticKind::UnreferencedUpdate);
    assert_eq!(report.offset, Some(update as u64));
    assert!(
        report.message.contains("is reconstructed"),
        "{}",
        report.message
    );
    // The newest trailer is used.
    assert!(store.trailer().get_int(b"Prev").is_some());
    check_simple(&store);
    assert_eq!(open_strict(&beyond).unwrap_err().code(), ErrorCode::Xref);
    // Objects alone that far: reconstructed too.
    let (objects, _) = cut_update(pad + 200, false);
    assert!(startxref_distance(&objects) > 1054);
    let store = open(&objects);
    assert!(str_of(&store, 5).unwrap().starts_with(b"newx"));
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
    // A table and trailer alone that far (no object after the last startxref): qpdf reads
    // the chain, and so does the store.
    let mut trailer = cut_update(10, false).0;
    trailer.truncate(update);
    trailer.extend_from_slice(
        format!(
            "trailer\n<< /Size 6 /Root 1 0 R /Pad ({}) >>\n",
            "x".repeat(1100)
        )
        .as_bytes(),
    );
    assert!(startxref_distance(&trailer) > 1054);
    let store = open(&trailer);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Table);
    assert_eq!(kinds(&store), [DiagnosticKind::UnreferencedUpdate]);

    // Expert round 3 (E_append_oldstartxref_big): objects appended with a startxref that leads
    // back to the old table, then more than 1054 bytes of junk. qpdf does not find that
    // startxref near the end, scans the file, finds it after the last object header, and reads
    // the chain it leads to: "good". So does the store, the update reported and ignored. The
    // same without the junk.
    for junk in [0, 1200] {
        let mut pdf = simple_doc();
        pdf.obj(5, "(good)");
        let table = pdf.table("\r\n");
        pdf.trailer("/Root 1 0 R /Info 5 0 R").startxref(table);
        let update = pdf.pos();
        pdf.raw("5 0 obj (appended) endobj\n").startxref(table);
        if junk > 0 {
            pdf.raw(format!("%{}\n", "j".repeat(junk)));
        }
        assert_eq!(startxref_distance(&pdf.buf) > 1054, junk > 0);
        let store = open(&pdf.buf);
        assert_eq!(str_of(&store, 5).as_deref(), Some(&b"good"[..]), "{junk}");
        assert_eq!(store.revisions().len(), 1);
        assert_eq!(store.revisions()[0].xref_kind, XrefKind::Table);
        assert_eq!(kinds(&store), [DiagnosticKind::UnreferencedUpdate]);
        let report = diagnostic(&store, DiagnosticKind::UnreferencedUpdate);
        assert_eq!(report.offset, Some(update as u64));
        assert!(report.message.contains("ignored"), "{}", report.message);
    }

    // Strict mode refuses these files, with a message that says what was found and nothing
    // about what lenient mode would do with it (Expert round 3).
    for bytes in [&bytes, &beyond] {
        let err = open_strict(bytes).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("no startxref leads to them"), "{message}");
        assert!(
            !message.contains("ignored") && !message.contains("reconstructed"),
            "{message}"
        );
    }

    // Junk after the last %%EOF is no update: words that merely contain the keywords, binary
    // data, another %%EOF.
    let mut junk = simple_bytes();
    junk.extend_from_slice(b"%%EOF\r\n% xrefs trailers 1 0 objects\n\x00\xFF\xFE 12 0 objx\n");
    let store = open(&junk);
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
    assert!(!store.structure_repaired());
    // Header-like text in a comment or in the middle of a line, then NULs, close to the end or
    // far from it (QA round 3: after a valid file, `%junk 1 0 obj` made it repaired, and strict
    // mode refused it). qpdf reads the chain either way.
    for (tail, nuls) in [
        ("\n%junk 1 0 obj\n", 64),
        ("\n%junk 1 0 obj\n", 1200),
        ("\njunk 1 0 obj (junk) endobj\n", 64),
        ("\n%PDF-1.4\n%garbage 3 0 obj\n", 3),
        ("\n% trailer << /Root 9 0 R >>\n", 0),
    ] {
        let mut junk = simple_bytes();
        junk.extend_from_slice(tail.as_bytes());
        junk.resize(junk.len() + nuls, 0);
        let store = open(&junk);
        assert!(
            store.diagnostics().is_empty(),
            "{tail:?}: {:?}",
            store.diagnostics()
        );
        assert!(!store.structure_repaired());
        check_simple(&store);
        assert!(open_strict(&junk).is_ok(), "{tail:?}");
    }
    // And the usual end of a file is nothing at all.
    let store = open(&simple_bytes());
    assert!(store.diagnostics().is_empty());
}

#[test]
fn concatenated_files_read_as_qpdf_reads_them() {
    // Two complete files, one after the other (QA round 3). The last startxref is the second
    // file's, counted from the second file's start. When it happens to lead to the first file's
    // table, qpdf reads that chain and ignores the second file; so does the store, which
    // reports the second file as an update no startxref leads to.
    let doc = |tag: &str, extra: bool| {
        let mut pdf = simple_doc();
        pdf.obj(5, &format!("({tag})"));
        let info = if extra {
            pdf.obj(7, "(seven)");
            "/Info 7 0 R"
        } else {
            "/Info 5 0 R"
        };
        pdf.finish(&format!("/Root 1 0 R {info}"))
    };
    let first = doc("A", false);
    let same = [first.clone(), doc("B", false)].concat();
    let store = open(&same);
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"A"[..]));
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Table);
    assert_eq!(kinds(&store), [DiagnosticKind::UnreferencedUpdate]);
    assert_eq!(
        diagnostic(&store, DiagnosticKind::UnreferencedUpdate).offset,
        Some(first.len() as u64 + find(&doc("B", false), b"1 0 obj") as u64)
    );
    // When it leads near the first file's table but not to it, qpdf finds no table there and
    // rebuilds the file, where the second file's objects (defined last) win. The store, which
    // finds the first table by its local search, sees the second file after that chain's
    // revisions and reconstructs the file too.
    let longer = [first, doc("B", true)].concat();
    let store = open(&longer);
    assert_eq!(store.revisions()[0].xref_kind, XrefKind::Reconstructed);
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"B"[..]));
    let info = store.deref(store.trailer().get(b"Info").unwrap()).unwrap();
    assert_eq!(info.as_str_bytes(), Some(&b"seven"[..]));
    assert!(has(&store, DiagnosticKind::UnreferencedUpdate));
    check_simple(&store);
    assert_eq!(open_strict(&longer).unwrap_err().code(), ErrorCode::Xref);
}

#[test]
fn object_level_repairs_mark_objects_recovered() {
    // Repairs that decide what an object holds, which other readers may decide differently,
    // put the object in recovered_objects() (lenient mode; the structure itself is fine).
    type WriteFour = fn(&mut Pdf);
    let cases: [(&str, WriteFour); 4] = [
        ("wrong /Length", |pdf| {
            pdf.stream_with(4, "<< /Length 5 >>", CONTENT);
        }),
        ("no endobj", |pdf| {
            pdf.objects.insert(4, (pdf.pos(), 0));
            pdf.raw(format!(
                "4 0 obj\n<< /Length {} >>\nstream\n",
                CONTENT.len()
            ))
            .raw(CONTENT)
            .raw("\nendstream\n");
        }),
        ("no endstream", |pdf| {
            pdf.objects.insert(4, (pdf.pos(), 0));
            pdf.raw("4 0 obj\n<< >>\nstream\n")
                .raw(CONTENT)
                .raw("\nendobj\n");
        }),
        ("stream keyword with a lone CR", |pdf| {
            pdf.objects.insert(4, (pdf.pos(), 0));
            pdf.raw(format!(
                "4 0 obj\n<< /Length {} >>\nstream\r",
                CONTENT.len()
            ))
            .raw(CONTENT)
            .raw("\nendstream\nendobj\n");
        }),
    ];
    for (name, write_four) in cases {
        let mut pdf = Pdf::new();
        pdf.obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            .obj(
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
            );
        write_four(&mut pdf);
        let bytes = pdf.finish("/Root 1 0 R");
        let store = open(&bytes);
        assert!(store.recovered_objects().is_empty(), "{name}");
        assert_eq!(stream_of(&store, 4), CONTENT, "{name}");
        assert_eq!(store.recovered_objects(), [id(4)], "{name}");
        assert!(!store.structure_repaired(), "{name}");
        // The objects that needed nothing stay out of the list.
        check_simple(&store);
        assert_eq!(store.recovered_objects(), [id(4)], "{name}");
    }

    // A header generation that differs from the entry's.
    let mut pdf = simple_doc();
    let at = pdf.pos();
    pdf.raw("5 1 obj\n(five)\nendobj\n");
    pdf.objects.insert(5, (at, 0));
    let store = open(&pdf.finish("/Root 1 0 R"));
    check_simple(&store);
    assert!(store.recovered_objects().is_empty());
    assert_eq!(str_of(&store, 5).as_deref(), Some(&b"five"[..]));
    assert_eq!(store.recovered_objects(), [id(5)]);
}

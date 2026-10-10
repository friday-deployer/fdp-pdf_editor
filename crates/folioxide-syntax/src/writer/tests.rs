//! Writer unit tests (M2 brief WP2.1): the section formats, and the rules of both writers that
//! the acceptance tests (`tests/writer_acceptance.rs`) do not pin down one by one.

use folioxide_testkit::fixtures::{qpdf, syntax};
use folioxide_testkit::{PdfBuilder, XrefOpts};

use super::md5::md5;
use super::*;
use crate::store::OpenOptions;
use crate::{ErrorCode, OffsetBase, XrefEntry};

fn open(bytes: &[u8]) -> Store {
    Store::open_bytes(bytes.to_vec(), &OpenOptions::default()).unwrap()
}

fn id(num: u32, r#gen: u16) -> ObjectId {
    ObjectId::new(num, r#gen)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The entries of the newest revision of `bytes`, by number.
fn newest_entries(bytes: &[u8]) -> std::collections::BTreeMap<u32, XrefEntry> {
    let store = open(bytes);
    let last = store.revisions().len() - 1;
    store.revision_entries(last).unwrap().into_iter().collect()
}

/// A one-page file with a classic table, `extra` objects (number, generation, body) after the
/// five standard ones, and `trailer` entries after `/Size` and `/Root`.
fn file(extra: &[(u32, u16, &str)], trailer: &str) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.4");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>")
        .obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .obj(
            3,
            0,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
        )
        .stream_obj(4, 0, "", b"BT ET", None)
        .obj(5, 0, "<< /Producer (test) >>");
    for &(num, r#gen, body) in extra {
        b.obj(num, r#gen, body);
    }
    b.xref_table(XrefOpts::default());
    let trailer = format!("/Size {} /Root 1 0 R {trailer}", b.size());
    b.trailer(trailer).startxref(None).eof();
    b.build()
}

// ---- section formats ----------------------------------------------------------------------------

#[test]
fn free_list_links_from_object_0() {
    let mut entries = vec![
        (0, Entry::Free { next: 9, r#gen: 0 }),
        (
            1,
            Entry::InFile {
                offset: 15,
                r#gen: 0,
            },
        ),
        (2, Entry::Free { next: 0, r#gen: 4 }),
        (3, Entry::Free { next: 0, r#gen: 1 }),
        (
            4,
            Entry::InObjStm {
                stream: 1,
                index: 0,
            },
        ),
        (7, Entry::Free { next: 0, r#gen: 0 }),
    ];
    link_free_list(&mut entries);
    let free: Vec<(u32, u32, u16)> = entries
        .iter()
        .filter_map(|&(num, e)| match e {
            Entry::Free { next, r#gen } => Some((num, next, r#gen)),
            _ => None,
        })
        .collect();
    assert_eq!(free, [(0, 2, 65535), (2, 3, 4), (3, 7, 1), (7, 0, 0)]);
    let mut lone = vec![(0, Entry::Free { next: 5, r#gen: 0 })];
    link_free_list(&mut lone);
    assert_eq!(
        lone,
        [(
            0,
            Entry::Free {
                next: 0,
                r#gen: 65535
            }
        )]
    );
}

#[test]
fn subsections_are_runs_of_numbers() {
    let entry = Entry::Free { next: 0, r#gen: 0 };
    let entries: Vec<(u32, Entry)> = [0, 1, 2, 5, 7, 8, u32::MAX]
        .into_iter()
        .map(|n| (n, entry))
        .collect();
    assert_eq!(
        subsections(&entries),
        [(0, 3), (5, 1), (7, 2), (u32::MAX, 1)]
    );
    assert!(subsections(&[]).is_empty());
}

#[test]
fn table_entries_are_20_bytes() {
    let mut entries = vec![
        (0, Entry::Free { next: 0, r#gen: 0 }),
        (
            1,
            Entry::InFile {
                offset: 17,
                r#gen: 0,
            },
        ),
        (2, Entry::Free { next: 0, r#gen: 1 }),
        (
            5,
            Entry::InFile {
                offset: MAX_TABLE_OFFSET,
                r#gen: 65535,
            },
        ),
    ];
    link_free_list(&mut entries);
    let mut out = Vec::new();
    write_table(&entries, &mut out).unwrap();
    assert_eq!(
        out,
        b"xref\n0 3\n0000000002 65535 f\r\n0000000017 00000 n\r\n0000000000 00001 f\r\n\
          5 1\n9999999999 65535 n\r\n"
    );
    let too_far = [(
        1,
        Entry::InFile {
            offset: MAX_TABLE_OFFSET + 1,
            r#gen: 0,
        },
    )];
    let err = write_table(&too_far, &mut Vec::new()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);
    let compressed = [(
        1,
        Entry::InObjStm {
            stream: 2,
            index: 0,
        },
    )];
    let err = write_table(&compressed, &mut Vec::new()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

#[test]
fn xref_stream_rows_use_the_smallest_widths() {
    assert_eq!(field_width(0), 1);
    assert_eq!(field_width(255), 1);
    assert_eq!(field_width(256), 2);
    assert_eq!(field_width(u64::from(u32::MAX)), 4);
    assert_eq!(field_width(u64::MAX), 8);
    let entries = [
        (
            0,
            Entry::Free {
                next: 0,
                r#gen: 65535,
            },
        ),
        (
            1,
            Entry::InFile {
                offset: 70_000,
                r#gen: 0,
            },
        ),
        (
            2,
            Entry::InObjStm {
                stream: 1,
                index: 3,
            },
        ),
        (9, Entry::Free { next: 0, r#gen: 1 }),
    ];
    let mut trailer = Dict::new();
    trailer.insert(keys::SIZE, 10);
    let stream = xref_stream(&entries, trailer, None);
    let dict = &stream.dict;
    assert!(dict.is_type(b"XRef"));
    assert_eq!(dict.keys().next().map(Name::as_bytes), Some(&b"Type"[..]));
    assert_eq!(
        dict.get(keys::W),
        Some(&Object::Array(vec![1.into(), 3.into(), 2.into()]))
    );
    assert_eq!(
        dict.get(keys::INDEX),
        Some(&Object::Array(vec![0.into(), 3.into(), 9.into(), 1.into()]))
    );
    assert!(!dict.contains_key(keys::FILTER));
    let StreamData::Encoded(data) = &stream.data else {
        panic!("{:?}", stream.data);
    };
    assert_eq!(
        data,
        &[
            0, 0, 0, 0, 0xFF, 0xFF, // free, generation 65535
            1, 0x01, 0x11, 0x70, 0, 0, // offset 70000
            2, 0, 0, 1, 0, 3, // object stream 1, index 3
            0, 0, 0, 0, 0, 1, // free, generation 1
        ]
    );
    let compressed = xref_stream(&entries, Dict::new(), Some(6));
    assert!(compressed.dict.get_name(keys::FILTER).is_some());
}

#[test]
fn options_have_the_documented_defaults() {
    let options = SaveOptions::default();
    assert_eq!(options, SaveOptions::new());
    assert_eq!(options.xref, XrefStyle::Auto);
    assert!(!options.object_streams);
    assert_eq!(options.compress, StreamCompression::CompressNew);
    assert!(options.gc && options.renumber && !options.deterministic);
    assert_eq!(options.id, None);
    assert_eq!(options.min_version, None);
    assert_eq!(options.flate_level, 6);
    let set = SaveOptions::new()
        .with_xref(XrefStyle::Stream)
        .with_object_streams(true)
        .with_compress(StreamCompression::Keep)
        .with_gc(false)
        .with_renumber(false)
        .with_deterministic(true)
        .with_id(Some([vec![1], vec![2]]))
        .with_min_version(Some((1, 7)))
        .with_flate_level(9);
    assert_eq!(
        (set.xref, set.object_streams, set.compress),
        (XrefStyle::Stream, true, StreamCompression::Keep)
    );
    assert!(!set.gc && !set.renumber && set.deterministic);
    assert_eq!(set.id, Some([vec![1], vec![2]]));
    assert_eq!((set.min_version, set.flate_level), (Some((1, 7)), 9));
    let incremental = IncrementalOptions::new()
        .with_deterministic(true)
        .with_id1(Some(vec![7]));
    assert!(incremental.deterministic);
    assert_eq!(incremental.id1, Some(vec![7]));
    assert_eq!(IncrementalOptions::default(), IncrementalOptions::new());
}

// ---- full save ----------------------------------------------------------------------------------

#[test]
fn header_version_rules() {
    let header = |bytes: &[u8]| String::from_utf8_lossy(&bytes[..8]).into_owned();
    let store = open(&syntax::minimal());
    let plain = store.save(&SaveOptions::default()).unwrap();
    assert_eq!(header(&plain), "%PDF-1.4");
    assert_eq!(&plain[8..15], b"\n%\xE2\xE3\xCF\xD3\n");
    let stream = store
        .save(&SaveOptions::default().with_xref(XrefStyle::Stream))
        .unwrap();
    assert_eq!(header(&stream), "%PDF-1.5");
    let objstm = store
        .save(&SaveOptions::default().with_object_streams(true))
        .unwrap();
    assert_eq!(header(&objstm), "%PDF-1.5");
    let min = store
        .save(&SaveOptions::default().with_min_version(Some((1, 7))))
        .unwrap();
    assert_eq!(header(&min), "%PDF-1.7");
    // The minimum never lowers the source's version.
    let low = store
        .save(&SaveOptions::default().with_min_version(Some((1, 2))))
        .unwrap();
    assert_eq!(header(&low), "%PDF-1.4");
    // Junk before the source's header is dropped.
    let junk = open(&syntax::junk_before_header());
    assert!(junk.header_offset() > 0);
    let out = junk.save(&SaveOptions::default()).unwrap();
    assert!(out.starts_with(b"%PDF-"));
    assert_eq!(open(&out).header_offset(), 0);
    // A new document writes its own version.
    let mut new = Store::new_empty((2, 0));
    let root = new.add(Dict::new().into()).unwrap();
    new.set_trailer_entry(keys::ROOT, root.into()).unwrap();
    assert_eq!(
        header(&new.save(&SaveOptions::default()).unwrap()),
        "%PDF-2.0"
    );
}

#[test]
fn header_names_a_pdf_version() {
    let header = |bytes: &[u8]| String::from_utf8_lossy(&bytes[..8]).into_owned();
    let store = open(&syntax::minimal());
    // Every PDF version is a valid minimum.
    for version in (0..=7).map(|minor| (1, minor)).chain([(2, 0)]) {
        let options = SaveOptions::default().with_min_version(Some(version));
        assert!(options.validate().is_ok(), "{version:?}");
        let out = store.save(&options).unwrap();
        let expected = version.max((1, 4));
        assert_eq!(header(&out), format!("%PDF-{}.{}", expected.0, expected.1));
    }
    // Anything else is refused, before anything is written.
    for version in [(0, 9), (1, 8), (1, 9), (2, 1), (3, 0), (9, 9), (255, 255)] {
        let options = SaveOptions::default().with_min_version(Some(version));
        for err in [
            options.validate().unwrap_err(),
            store.save(&options).unwrap_err(),
        ] {
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{version:?}");
            assert!(err.to_string().contains("not a PDF version"), "{err}");
        }
    }
    // A source (or new document) whose header names no PDF version is written with the next
    // PDF version up, or 2.0 above it.
    for (source, written) in [
        ("0.9", "1.0"),
        ("1.8", "2.0"),
        ("1.9", "2.0"),
        ("2.1", "2.0"),
        ("9.9", "2.0"),
        ("255.255", "2.0"),
    ] {
        let mut b = PdfBuilder::new();
        b.header(source);
        b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>").obj(
            2,
            0,
            "<< /Type /Pages /Kids [] /Count 0 >>",
        );
        b.xref_table(XrefOpts::default());
        let trailer = format!("/Size {} /Root 1 0 R", b.size());
        b.trailer(trailer).startxref(None).eof();
        let odd = open(&b.build());
        let out = odd.save(&SaveOptions::default()).unwrap();
        let line_end = out.iter().position(|&b| b == b'\n').unwrap();
        assert_eq!(
            &out[..line_end],
            format!("%PDF-{written}").as_bytes(),
            "{source}"
        );
        assert_eq!(open(&out).version(), header_version(odd.version()));
        // The cross-reference stream minimum still applies below it.
        let stream = odd
            .save(&SaveOptions::default().with_xref(XrefStyle::Stream))
            .unwrap();
        let expected = if source == "0.9" { "1.5" } else { written };
        assert_eq!(header(&stream)[5..], *expected, "{source}");
    }
    let mut new = Store::new_empty((7, 3));
    let root = new.add(Dict::new().into()).unwrap();
    new.set_trailer_entry(keys::ROOT, root.into()).unwrap();
    assert_eq!(
        header(&new.save(&SaveOptions::default()).unwrap()),
        "%PDF-2.0"
    );
}

#[test]
fn file_identifier_rules() {
    let ids = |bytes: &[u8]| -> [Vec<u8>; 2] {
        let store = open(bytes);
        let items = store.trailer().get_array(keys::ID).unwrap().to_vec();
        let get = |i: usize| items[i].as_str_bytes().unwrap().to_vec();
        [get(0), get(1)]
    };
    let original = ids(&syntax::minimal());
    // The source's first element stays; the second is the MD5 of the body.
    let store = open(&syntax::minimal());
    let out = store.save(&SaveOptions::default()).unwrap();
    let [first, second] = ids(&out);
    assert_eq!(first, original[0]);
    let body_end = open(&out).revisions()[0].startxref as usize;
    assert!(out[body_end..].starts_with(b"xref\n"));
    assert_eq!(second, md5(&out[..body_end]).to_vec());
    // The options' identifier, verbatim.
    let given = [b"first".to_vec(), b"second".to_vec()];
    let out = store
        .save(&SaveOptions::default().with_id(Some(given.clone())))
        .unwrap();
    assert_eq!(ids(&out), given);
    // No /ID: the digest twice (§14.4: both elements are equal when a file is first written).
    let mut store = open(&syntax::minimal());
    store.remove_trailer_entry(keys::ID).unwrap();
    let [first, second] = ids(&store.save(&SaveOptions::default()).unwrap());
    assert_eq!(first, second);
    assert_eq!(first.len(), 16);
    // A /ID set with set_trailer_entry gives the first element.
    let mut store = open(&syntax::minimal());
    let set = Object::Array(vec![
        Object::hex_string(b"permanent".to_vec()),
        Object::hex_string(b"changing".to_vec()),
    ]);
    store.set_trailer_entry(keys::ID, set).unwrap();
    let [first, second] = ids(&store.save(&SaveOptions::default()).unwrap());
    assert_eq!(first, b"permanent");
    assert_ne!(second, b"changing");

    // Incremental: the first element stays, the second is the update's digest or the option.
    let mut store = open(&syntax::minimal());
    store.set(id(5, 0), Object::Null).unwrap();
    let out = store
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    let [first, second] = ids(&out);
    assert_eq!(first, original[0]);
    assert_ne!(second, original[1]);
    assert_eq!(second.len(), 16);
    let out = store
        .save_incremental(&IncrementalOptions::default().with_id1(Some(b"next".to_vec())))
        .unwrap();
    assert_eq!(ids(&out), [original[0].clone(), b"next".to_vec()]);
    // Without a source /ID, both elements are generated.
    let bytes = file(&[], "");
    let mut store = open(&bytes);
    assert!(store.trailer().get(keys::ID).is_none());
    store.set(id(5, 0), Object::Null).unwrap();
    let [first, second] = ids(&store
        .save_incremental(&IncrementalOptions::default())
        .unwrap());
    assert_eq!(first, second);
}

#[test]
fn invalid_documents_are_refused() {
    // No /Root.
    let store = Store::new_empty((1, 7));
    let err = store.save(&SaveOptions::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.to_string().contains("/Root"), "{err}");
    // A /Root that is no dictionary.
    let mut store = Store::new_empty((1, 7));
    let root = store.add(Object::Int(1)).unwrap();
    store.set_trailer_entry(keys::ROOT, root.into()).unwrap();
    let err = store.save(&SaveOptions::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    // A freed catalog, for both writers.
    let mut store = open(&syntax::minimal());
    store.free(id(1, 0)).unwrap();
    for err in [
        store.save(&SaveOptions::default()).unwrap_err(),
        store
            .save_incremental(&IncrementalOptions::default())
            .unwrap_err(),
    ] {
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    }
    // A stream nested inside a dictionary or an array, for both writers.
    let nested = Object::Stream(Box::new(Stream::new(
        Dict::new(),
        StreamData::Decoded(Vec::new()),
    )));
    for value in [
        Object::Array(vec![Object::Int(1), nested.clone()]),
        Object::Dict([(Name::from("S"), nested.clone())].into_iter().collect()),
        Object::Stream(Box::new(Stream::new(
            [(Name::from("S"), nested.clone())].into_iter().collect(),
            StreamData::Decoded(Vec::new()),
        ))),
    ] {
        let mut store = open(&syntax::minimal());
        // Reachable from the page (object 3), so the full save writes it.
        store.set(id(5, 0), value).unwrap();
        for err in [
            store.save(&SaveOptions::default()).unwrap_err(),
            store
                .save_incremental(&IncrementalOptions::default())
                .unwrap_err(),
        ] {
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
            assert!(err.to_string().contains("§7.3.8"), "{err}");
        }
    }
    // Object streams need a cross-reference stream.
    let store = open(&syntax::minimal());
    let err = store
        .save(
            &SaveOptions::default()
                .with_xref(XrefStyle::Table)
                .with_object_streams(true),
        )
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

#[test]
fn object_streams_hold_only_what_may_be_compressed() {
    // 250 small objects, a signature dictionary, a document timestamp, and an object of
    // generation 2, all reachable from the catalog.
    let mut extra: Vec<(u32, u16, String)> =
        (10..260).map(|n| (n, 0, format!("<< /N {n} >>"))).collect();
    extra.push((300, 0, "<< /Type /Sig /Contents <00> >>".to_owned()));
    extra.push((301, 0, "<< /Type /DocTimeStamp >>".to_owned()));
    extra.push((302, 2, "(second generation)".to_owned()));
    let refs: String = (10..260)
        .chain([300, 301])
        .map(|n| format!("{n} 0 R "))
        .collect();
    let mut b = PdfBuilder::new();
    b.header("1.4");
    b.obj(
        1,
        0,
        format!("<< /Type /Catalog /Pages 2 0 R /All [{refs} 302 2 R] >>"),
    )
    .obj(2, 0, "<< /Type /Pages /Kids [] /Count 0 >>");
    for (num, r#gen, body) in &extra {
        b.obj(*num, *r#gen, body);
    }
    b.xref_table(XrefOpts::default());
    let trailer = format!("/Size {} /Root 1 0 R", b.size());
    b.trailer(trailer).startxref(None).eof();
    let store = open(&b.build());
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());

    for renumber in [true, false] {
        let out = store
            .save(
                &SaveOptions::default()
                    .with_object_streams(true)
                    .with_renumber(renumber),
            )
            .unwrap();
        let saved = open(&out);
        assert!(saved.diagnostics().is_empty(), "{:?}", saved.diagnostics());
        let entries = saved.revision_entries(0).unwrap();
        let mut per_container: std::collections::BTreeMap<u32, usize> = Default::default();
        for &(num, entry) in &entries {
            if let XrefEntry::InObjStm { stream, .. } = entry {
                *per_container.entry(stream).or_default() += 1;
                let object = saved.resolve(id(num, 0)).unwrap();
                let signature = object
                    .as_dict()
                    .is_some_and(|d| d.is_type(b"Sig") || d.is_type(b"DocTimeStamp"));
                assert!(!signature, "{num}");
            }
        }
        // 250 + catalog + page tree = 252 compressed objects, at most 100 per container; once
        // renumbered, the object of generation 2 has generation 0 and is compressed too.
        let expected = 252 + usize::from(renumber);
        assert_eq!(
            per_container.values().sum::<usize>(),
            expected,
            "{renumber}"
        );
        assert_eq!(per_container.len(), 3);
        assert!(per_container.values().all(|&n| n <= 100));
        // The signature dictionaries (and, kept, the object of generation 2) are uncompressed.
        let catalog = saved.resolve(saved.root_id().unwrap()).unwrap();
        let all = catalog.as_dict().unwrap().get_array(b"All").unwrap();
        let uncompressed = if renumber {
            &all[250..252]
        } else {
            &all[250..]
        };
        for item in uncompressed {
            let target = item.as_ref().unwrap();
            assert!(
                matches!(
                    entries.iter().find(|e| e.0 == target.num),
                    Some((_, XrefEntry::InFile { .. }))
                ),
                "{target}"
            );
        }
        let second = saved.deref(&all[252]).unwrap();
        assert_eq!(second.as_str_bytes(), Some(&b"second generation"[..]));
        if !renumber {
            assert_eq!(all[252], Object::Ref(id(302, 2)));
        }
    }
}

#[test]
fn object_streams_exclude_signatures_without_type() {
    // §12.8.1 Table 255: /Type is optional in a signature dictionary. Each body, and whether it
    // must stay out of object streams.
    let bodies: [(&str, bool); 7] = [
        // A PAdES signature value as many signers write it.
        (
            "<< /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached \
             /ByteRange [0 10 20 30] /Contents <0001> /M (D:20261010) >>",
            true,
        ),
        // A prepared signature placeholder.
        ("<< /ByteRange [0 0 0 0] /Contents <0000> >>", true),
        // A signature with a handler but no byte range (an MDP or UR3 signature may omit it).
        (
            "<< /Filter /Adobe.PPKLite /Contents <00> /Reference [] >>",
            true,
        ),
        ("<< /SubFilter /adbe.pkcs7.detached /Contents <00> >>", true),
        ("<< /Type /Sig >>", true),
        // Not signatures: text /Contents without a handler, and a plain dictionary.
        ("<< /Type /Annot /Subtype /Text /Contents (note) >>", false),
        ("<< /N 1 >>", false),
    ];
    let mut b = PdfBuilder::new();
    b.header("1.7");
    let refs: String = (0..bodies.len())
        .map(|i| format!("{} 0 R ", 10 + i))
        .collect();
    b.obj(
        1,
        0,
        format!("<< /Type /Catalog /Pages 2 0 R /All [{refs}] >>"),
    )
    .obj(2, 0, "<< /Type /Pages /Kids [] /Count 0 >>");
    for (i, (body, _)) in bodies.iter().enumerate() {
        b.obj(10 + i as u32, 0, *body);
    }
    b.xref_table(XrefOpts::default());
    let trailer = format!("/Size {} /Root 1 0 R", b.size());
    b.trailer(trailer).startxref(None).eof();
    let store = open(&b.build());
    assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());

    for renumber in [true, false] {
        let out = store
            .save(
                &SaveOptions::default()
                    .with_object_streams(true)
                    .with_renumber(renumber),
            )
            .unwrap();
        let saved = open(&out);
        let entries = saved.revision_entries(0).unwrap();
        let catalog = saved.resolve(saved.root_id().unwrap()).unwrap();
        let all = catalog.as_dict().unwrap().get_array(b"All").unwrap();
        for (item, (body, signature)) in all.iter().zip(bodies) {
            let target = item.as_ref().unwrap();
            let entry = entries.iter().find(|e| e.0 == target.num).map(|e| e.1);
            if signature {
                assert!(matches!(entry, Some(XrefEntry::InFile { .. })), "{body}");
            } else {
                assert!(matches!(entry, Some(XrefEntry::InObjStm { .. })), "{body}");
            }
        }
    }
}

/// `data` as ASCIIHex text with its end marker.
fn encode_ascii_hex_text(data: &[u8]) -> Vec<u8> {
    let mut out = crate::filters::encode_ascii_hex(data);
    if !out.ends_with(b">") {
        out.push(b'>');
    }
    out
}

#[test]
fn recompress_reencodes_what_it_can() {
    let mut b = PdfBuilder::new();
    b.header("1.4");
    let hex = encode_ascii_hex_text(b"hex encoded content");
    b.obj(
        1,
        0,
        "<< /Type /Catalog /Pages 2 0 R /S [3 0 R 4 0 R 5 0 R] >>",
    )
    .obj(2, 0, "<< /Type /Pages /Kids [] /Count 0 >>")
    .stream_obj(3, 0, "/Filter /ASCIIHexDecode", &hex, None)
    .stream_obj(
        4,
        0,
        "/Filter /DCTDecode",
        b"\xFF\xD8not really a jpeg",
        None,
    )
    .stream_obj(5, 0, "/DL 99", b"plain", None);
    b.xref_table(XrefOpts::default());
    let trailer = format!("/Size {} /Root 1 0 R", b.size());
    b.trailer(trailer).startxref(None).eof();
    let store = open(&b.build());
    let streams = |bytes: &[u8]| -> Vec<(Dict, Vec<u8>, Vec<u8>)> {
        let saved = open(bytes);
        let catalog = saved.resolve(saved.root_id().unwrap()).unwrap();
        catalog
            .as_dict()
            .unwrap()
            .get_array(b"S")
            .unwrap()
            .iter()
            .map(|r| {
                let obj = saved.deref(r).unwrap().into_owned();
                let stream = obj.as_stream().unwrap();
                let raw = saved.raw_stream_data(stream).unwrap().into_owned();
                let decoded = saved.stream_data(stream).unwrap().data;
                (stream.dict.clone(), raw, decoded)
            })
            .collect()
    };
    let filter = |d: &Dict| d.get_name(keys::FILTER).map(|n| n.as_bytes().to_vec());
    // CompressNew: copied as encoded.
    let kept = streams(&store.save(&SaveOptions::default()).unwrap());
    assert_eq!(filter(&kept[0].0), Some(b"ASCIIHexDecode".to_vec()));
    assert_eq!(kept[0].1, hex);
    assert_eq!(kept[2].1, b"plain");
    // Recompress: the hex and the plain streams become Flate (and /DL is right), the JPEG is
    // copied.
    let out = store
        .save(&SaveOptions::default().with_compress(StreamCompression::Recompress))
        .unwrap();
    let recompressed = streams(&out);
    assert_eq!(filter(&recompressed[0].0), Some(b"FlateDecode".to_vec()));
    assert_eq!(recompressed[0].2, b"hex encoded content");
    assert_eq!(filter(&recompressed[1].0), Some(b"DCTDecode".to_vec()));
    assert_eq!(recompressed[1].1, b"\xFF\xD8not really a jpeg");
    assert_eq!(filter(&recompressed[2].0), Some(b"FlateDecode".to_vec()));
    assert_eq!(recompressed[2].2, b"plain");
    assert_eq!(recompressed[2].0.get_int(keys::DL), Some(5));
    // Truncated data is copied as it is.
    let truncated = open(&syntax::flate_truncated());
    let source_content = truncated.resolve(id(4, 0)).unwrap();
    let source_raw = truncated
        .raw_stream_data(source_content.as_stream().unwrap())
        .unwrap()
        .into_owned();
    let out = truncated
        .save(&SaveOptions::default().with_compress(StreamCompression::Recompress))
        .unwrap();
    assert!(contains(&out, &source_raw));
}

#[test]
fn custom_trailer_entries_are_kept() {
    let bytes = file(&[(6, 0, "(kept)")], "/Info 5 0 R /Custom 6 0 R /Flag true");
    let store = open(&bytes);
    // Full save: carried over, with references renumbered.
    let saved = open(&store.save(&SaveOptions::default()).unwrap());
    assert_eq!(saved.trailer().get_bool(b"Flag"), Some(true));
    let custom = saved
        .deref(saved.trailer().get(b"Custom").unwrap())
        .unwrap();
    assert_eq!(custom.as_str_bytes(), Some(&b"kept"[..]));
    // Incremental: §7.5.6, the update's trailer has every entry of the previous one but /Prev.
    let mut store = open(&bytes);
    store.set(id(4, 0), Object::Null).unwrap();
    store.remove_trailer_entry(keys::INFO).unwrap();
    let out = store
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    let reopened = open(&out);
    let trailer = &reopened.revisions().last().unwrap().trailer;
    assert_eq!(trailer.get_bool(b"Flag"), Some(true));
    assert_eq!(trailer.get_ref(b"Custom"), Some(id(6, 0)));
    assert!(trailer.get(keys::INFO).is_none());
    assert_eq!(trailer.get_int(keys::SIZE), Some(7));
    assert_eq!(
        trailer.get_int(keys::PREV),
        Some(open(&bytes).revisions()[0].startxref as i64)
    );
}

#[test]
fn without_gc_the_old_structure_is_dropped() {
    // The linearization dictionary would describe the old layout.
    for info in qpdf::infos() {
        let store = open(&qpdf::read_committed(info.name).unwrap());
        let out = store.save(&SaveOptions::default().with_gc(false)).unwrap();
        assert!(!contains(&out, b"/Linearized"), "{}", info.name);
        let saved = open(&out);
        assert!(saved.diagnostics().is_empty(), "{:?}", saved.diagnostics());
    }
}

#[test]
fn generations_of_one_number_both_survive() {
    // No cross-reference data: the reconstruction keeps `5 0 obj` and `5 1 obj`, which are
    // different objects (§7.3.10).
    let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Both [5 0 R 5 1 R] >>\nendobj\n\
2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n5 0 obj\n(zero)\nendobj\n\
5 1 obj\n(one)\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";
    let store = open(pdf);
    assert!(store.object_ids().contains(&id(5, 0)));
    assert!(store.object_ids().contains(&id(5, 1)));
    for renumber in [true, false] {
        let saved = open(
            &store
                .save(&SaveOptions::default().with_renumber(renumber))
                .unwrap(),
        );
        assert!(!saved.structure_repaired());
        let catalog = saved.resolve(saved.root_id().unwrap()).unwrap();
        let both = catalog
            .as_dict()
            .unwrap()
            .get_array(b"Both")
            .unwrap()
            .to_vec();
        let texts: Vec<Vec<u8>> = both
            .iter()
            .map(|r| saved.deref(r).unwrap().as_str_bytes().unwrap().to_vec())
            .collect();
        assert_eq!(texts, [b"zero".to_vec(), b"one".to_vec()], "{renumber}");
    }
}

// ---- incremental save ---------------------------------------------------------------------------

#[test]
fn an_eol_is_added_only_when_the_source_lacks_one() {
    let mut bytes = syntax::minimal();
    assert!(bytes.ends_with(b"%%EOF\n"));
    bytes.pop();
    for (source, eol) in [
        (bytes.clone(), true),
        ([bytes.as_slice(), b"\r"].concat(), false),
        ([bytes.as_slice(), b"\n"].concat(), false),
    ] {
        let mut store = open(&source);
        store.set(id(5, 0), Object::Null).unwrap();
        let suffix = store
            .incremental_suffix(&IncrementalOptions::default())
            .unwrap();
        assert_eq!(suffix.starts_with(b"\n"), eol);
        assert!(suffix[usize::from(eol)..].starts_with(b"5 0 obj\n"));
        let out = [source.as_slice(), &suffix].concat();
        let reopened = open(&out);
        assert!(
            !reopened.structure_repaired(),
            "{:?}",
            reopened.diagnostics()
        );
        assert_eq!(reopened.revisions().len(), 2);
    }
}

#[test]
fn offsets_follow_the_files_offset_base() {
    let junk = b"Junk before the header\n";
    // Header-relative offsets (the standard): the update counts from the header too.
    let mut b = PdfBuilder::new();
    b.junk_prefix(junk).header("1.4");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>").obj(
        2,
        0,
        "<< /Type /Pages /Kids [] /Count 0 >>",
    );
    b.xref_table(XrefOpts::default());
    b.trailer("/Size 3 /Root 1 0 R").startxref(None).eof();
    let bytes = b.build();
    let mut store = open(&bytes);
    assert_eq!(store.offset_base(), OffsetBase::HeaderRelative);
    assert!(!store.structure_repaired(), "{:?}", store.diagnostics());
    let startxref = store.revisions()[0].startxref;
    let header_offset = store.header_offset();
    assert_eq!(header_offset, junk.len() as u64);
    store
        .get_mut(id(1, 0))
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .insert("Lang", Object::literal_string("en"));
    let update = store
        .incremental_update(&IncrementalOptions::default())
        .unwrap();
    let out = [bytes.as_slice(), &update.bytes].concat();
    let reopened = open(&out);
    assert_eq!(reopened.offset_base(), OffsetBase::HeaderRelative);
    assert!(
        !reopened.structure_repaired(),
        "{:?}",
        reopened.diagnostics()
    );
    assert_eq!(reopened.revisions().len(), 2);
    let catalog = reopened.resolve(id(1, 0)).unwrap();
    assert!(catalog.as_dict().unwrap().contains_key(b"Lang"));
    assert!(reopened.recovered_objects().is_empty());
    assert_eq!(
        reopened.revisions()[1].trailer.get_int(keys::PREV),
        Some(startxref as i64)
    );
    let xref_pos = update.xref_pos.unwrap();
    assert!(
        String::from_utf8_lossy(&update.bytes)
            .ends_with(&format!("startxref\n{}\n%%EOF\n", xref_pos - header_offset))
    );
    assert_eq!(reopened.revisions()[1].startxref, xref_pos - header_offset);
    // The diagnostic of the junk is the source's; the update adds none.
    assert_eq!(reopened.diagnostics().len(), store.diagnostics().len());

    // Absolute offsets (the writer counted the junk): the store finds the section at its offset
    // taken as absolute, which is a repair of the structure (other readers count from the
    // header and must reconstruct), so an update is refused and a full save is the way out.
    let skew = junk.len() as i64;
    let mut b = PdfBuilder::new();
    b.junk_prefix(junk).header("1.4");
    b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>").obj(
        2,
        0,
        "<< /Type /Pages /Kids [] /Count 0 >>",
    );
    b.xref_table(XrefOpts::default().with_offset_skew(skew));
    let xref = b.last_xref_offset().unwrap() + junk.len() as u64;
    b.trailer("/Size 3 /Root 1 0 R").startxref(Some(xref)).eof();
    let mut store = open(&b.build());
    assert_eq!(store.offset_base(), OffsetBase::Absolute);
    assert!(store.structure_repaired());
    store.set(id(2, 0), Object::Null).unwrap();
    let err = store
        .save_incremental(&IncrementalOptions::default())
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);
    let full = open(&store.save(&SaveOptions::default()).unwrap());
    assert_eq!(full.offset_base(), OffsetBase::HeaderRelative);
    assert!(!full.structure_repaired());
}

#[test]
fn offsets_in_either_base() {
    use super::incremental::offset_in_base;
    // Header-relative: positions minus the junk before the header.
    assert_eq!(offset_in_base(false, 23, 100).unwrap(), 77);
    assert_eq!(offset_in_base(false, 0, 100).unwrap(), 100);
    assert_eq!(
        offset_in_base(false, 23, 10).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    // Absolute: positions as they are.
    assert_eq!(offset_in_base(true, 23, 100).unwrap(), 100);
}

#[test]
fn xref_stream_number_stays_above_the_section() {
    use super::incremental::xref_stream_number;
    let in_file = Entry::InFile {
        offset: 9,
        r#gen: 0,
    };
    let free = Entry::Free { next: 0, r#gen: 1 };
    // The usual case: every listed number is below the store's next number.
    assert_eq!(xref_stream_number(12, &[]).unwrap(), 12);
    assert_eq!(
        xref_stream_number(12, &[(3, in_file), (11, free)]).unwrap(),
        12
    );
    // Objects numbered from the next number up (an overlay's new objects, M3): the stream
    // goes after them instead of taking the number of one of them.
    assert_eq!(
        xref_stream_number(12, &[(3, in_file), (12, in_file), (13, in_file)]).unwrap(),
        14
    );
    assert_eq!(xref_stream_number(12, &[(40, free)]).unwrap(), 41);
    assert_eq!(
        xref_stream_number(12, &[(u32::MAX, in_file)])
            .unwrap_err()
            .code(),
        ErrorCode::LimitExceeded
    );
}

#[test]
fn incremental_update_reports_positions() {
    let bytes = syntax::xref_stream();
    let mut store = open(&bytes);
    store.set(id(5, 0), Object::literal_string("five")).unwrap();
    let added = store.add(Object::Int(7)).unwrap();
    let update = store
        .incremental_update(&IncrementalOptions::default())
        .unwrap();
    assert_eq!(update.start, bytes.len() as u64);
    assert_eq!(update.xref_kind, Some(XrefKind::Stream));
    let out = [bytes.as_slice(), &update.bytes].concat();
    assert_eq!(
        update.objects.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        [id(5, 0), added]
    );
    for (object, range) in &update.objects {
        let text = &out[range.start as usize..range.end as usize];
        assert!(text.starts_with(format!("{} {} obj\n", object.num, object.r#gen).as_bytes()));
        assert!(text.ends_with(b"endobj\n"));
    }
    let xref = update.xref_pos.unwrap() as usize;
    let num = store.next_object_number();
    assert!(out[xref..].starts_with(format!("{num} 0 obj\n").as_bytes()));
    let reopened = open(&out);
    assert_eq!(
        reopened.revisions().last().unwrap().eof_end,
        out.len() as u64
    );
    assert_eq!(*reopened.resolve(added).unwrap(), Object::Int(7));
}

#[test]
fn objects_added_then_freed_leave_no_entry() {
    let mut store = open(&syntax::minimal());
    let kept = store.add(Object::Int(1)).unwrap();
    let dropped = store.add(Object::Int(2)).unwrap();
    store.free(dropped).unwrap();
    store.free(id(3, 0)).unwrap();
    let out = store
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    let entries = newest_entries(&out);
    assert!(matches!(
        entries.get(&kept.num),
        Some(XrefEntry::InFile { r#gen: 0, .. })
    ));
    assert!(!entries.contains_key(&dropped.num));
    assert_eq!(entries.get(&3), Some(&XrefEntry::Free { r#gen: 1 }));
    assert_eq!(
        open(&out).trailer().get_int(keys::SIZE),
        Some(i64::from(kept.num) + 1)
    );
}

#[test]
fn a_trailer_edit_alone_makes_an_update() {
    let bytes = syntax::minimal();
    let mut store = open(&bytes);
    store.remove_trailer_entry(keys::ID).unwrap();
    let update = store
        .incremental_update(&IncrementalOptions::default())
        .unwrap();
    assert!(update.objects.is_empty());
    let out = [bytes.as_slice(), &update.bytes].concat();
    let reopened = open(&out);
    assert_eq!(reopened.revisions().len(), 2);
    assert!(
        reopened.diagnostics().is_empty(),
        "{:?}",
        reopened.diagnostics()
    );
    // The update's own section lists object 0 only.
    assert!(
        String::from_utf8_lossy(&update.bytes).starts_with("xref\n0 1\n0000000000 65535 f\r\n")
    );
}

//! Revisions appended after a certification signature (M4 brief §5.3, §5.4): what a
//! document-timestamping service writes.

use folioxide_syntax::{Dict, Object, ObjectId, Store, Stream, StreamData, keys};

use super::with_incremental;
use crate::fixtures::forms;

/// The `/ByteRange` placeholder text of [`doc_timestamp_like_pyhanko`] before it is patched.
const BYTE_RANGE_PLACEHOLDER: &[u8] = b"[0 9999999999 9999999999 9999999999]";

/// The bytes of placeholder token in the document timestamp's `/Contents`.
const TOKEN_BYTES: usize = 2048;

/// `doc_timestamp_like_pyhanko`: a revision that adds a document timestamp (ISO 32000-2
/// §12.8.5) as pyHanko 0.37's `PdfTimeStamper` writes it (probed): an invisible signature field
/// `Timestamp1` (`/F 132`, `/Rect [0 0 0 0]`, `/TU (Timestamp)`) at the root of `/Fields` and on
/// the first page's `/Annots`, its `/Type /DocTimeStamp /SubFilter /ETSI.RFC3161` dictionary
/// with a `/ByteRange` over the whole file, and the timestamper's bookkeeping: the trailer's
/// `/Info` gains `/ModDate` and `/Producer`, the catalog gets `/Version /1.7` and the ESIC
/// developer extension. The token is a placeholder (zeros): the revision's structure is what the
/// modification analysis of earlier signatures judges. `None` without an indirect AcroForm.
pub fn doc_timestamp_like_pyhanko(pdf: &[u8]) -> Option<Vec<u8>> {
    doc_timestamp_revision(pdf, |_| Some(()))
}

/// The revision of [`doc_timestamp_like_pyhanko`], with `more` applied to the store last (more
/// changes in the same revision), its `/ByteRange` patched.
fn doc_timestamp_revision(
    pdf: &[u8],
    more: impl FnOnce(&mut Store) -> Option<()>,
) -> Option<Vec<u8>> {
    let mut out = with_incremental(pdf, |store| {
        let page = forms::page_id(store, 0)?;
        let mut dts = Dict::new();
        dts.insert("Type", Object::name("DocTimeStamp"));
        dts.insert("Filter", Object::name("Adobe.PPKLite"));
        dts.insert("SubFilter", Object::name("ETSI.RFC3161"));
        dts.insert(
            "ByteRange",
            Object::Array(vec![
                Object::Int(0),
                Object::Int(9_999_999_999),
                Object::Int(9_999_999_999),
                Object::Int(9_999_999_999),
            ]),
        );
        dts.insert("Contents", Object::hex_string(vec![0u8; TOKEN_BYTES]));
        let dts = store.add(Object::Dict(dts)).ok()?;
        let mut field = Dict::new();
        field.insert("FT", Object::name("Sig"));
        field.insert("T", Object::literal_string("Timestamp1"));
        field.insert("Type", Object::name("Annot"));
        field.insert("Subtype", Object::name("Widget"));
        field.insert("F", Object::Int(132));
        field.insert("Rect", Object::Array(vec![Object::Int(0); 4]));
        field.insert("P", Object::Ref(page));
        field.insert("TU", Object::literal_string("Timestamp"));
        field.insert("V", Object::Ref(dts));
        let field = store.add(Object::Dict(field)).ok()?;
        forms::append_to_annots(store, page, field)?;
        let root = store.root_id()?;
        let mut catalog = store.resolve(root).ok()?.as_dict()?.clone();
        let acroform = catalog.get_ref(b"AcroForm")?;
        let mut acroform_dict = store.resolve(acroform).ok()?.as_dict()?.clone();
        let mut fields = acroform_dict.get_array(b"Fields")?.to_vec();
        fields.push(Object::Ref(field));
        acroform_dict.insert("Fields", Object::Array(fields));
        store.set(acroform, Object::Dict(acroform_dict)).ok()?;
        // The bookkeeping of pyHanko's timestamper.
        let mut esic = Dict::new();
        esic.insert("Type", Object::name("DeveloperExtensions"));
        esic.insert("BaseVersion", Object::name("1.7"));
        esic.insert("ExtensionLevel", Object::Int(1));
        let mut extensions = Dict::new();
        extensions.insert("ESIC", Object::Dict(esic));
        catalog.insert("Version", Object::name("1.7"));
        catalog.insert("Extensions", Object::Dict(extensions));
        store.set(root, Object::Dict(catalog)).ok()?;
        set_info_bookkeeping(store)?;
        more(store)
    })?;
    // §12.8.1: /ByteRange [0 a b c] around the /Contents token, written over the placeholder.
    let at = out
        .windows(BYTE_RANGE_PLACEHOLDER.len())
        .rposition(|w| w == BYTE_RANGE_PLACEHOLDER)?;
    let zeros = "0".repeat(TOKEN_BYTES * 2);
    let token = format!("<{zeros}>");
    let a = out
        .windows(token.len())
        .rposition(|w| w == token.as_bytes())?;
    let b = a.checked_add(token.len())?;
    let c = out.len().checked_sub(b)?;
    let text = format!("[0 {a} {b} {c}");
    let padding = BYTE_RANGE_PLACEHOLDER.len().checked_sub(text.len() + 1)?;
    let patched: Vec<u8> = text
        .bytes()
        .chain(std::iter::repeat_n(b' ', padding))
        .chain(std::iter::once(b']'))
        .collect();
    out.get_mut(at..at + BYTE_RANGE_PLACEHOLDER.len())?
        .copy_from_slice(&patched);
    Some(out)
}

/// The trailer's `/Info` with `/ModDate` and `/Producer` set (the existing dictionary edited, or a
/// new one), as pyHanko's incremental writer does.
fn set_info_bookkeeping(store: &mut Store) -> Option<()> {
    set_info_values(store, "D:20261011120000Z", "pyHanko 0.37.0")
}

/// The trailer's `/Info` with `/ModDate date` and `/Producer producer` (the existing dictionary
/// edited, or a new one).
fn set_info_values(store: &mut Store, date: &str, producer: &str) -> Option<()> {
    let date = Object::literal_string(date);
    let producer = Object::literal_string(producer);
    match store.trailer().get_ref(keys::INFO) {
        Some(info) => {
            let mut dict = store.resolve(info).ok()?.as_dict()?.clone();
            dict.insert("ModDate", date);
            dict.insert("Producer", producer);
            store.set(info, Object::Dict(dict)).ok()
        }
        None => {
            let mut dict = Dict::new();
            dict.insert("ModDate", date);
            dict.insert("Producer", producer);
            let info = store.add(Object::Dict(dict)).ok()?;
            store.set_trailer_entry(keys::INFO, Object::Ref(info)).ok()
        }
    }
}

/// `doc_timestamp_with_title_changed`: [`doc_timestamp_like_pyhanko`] whose `/Info` also changes
/// `/Title` (no longer the timestamp's bookkeeping).
pub fn doc_timestamp_with_title_changed(pdf: &[u8]) -> Option<Vec<u8>> {
    let stamped = doc_timestamp_like_pyhanko(pdf)?;
    with_incremental(&stamped, |store| {
        let info = store.trailer().get_ref(keys::INFO)?;
        let mut dict = store.resolve(info).ok()?.as_dict()?.clone();
        dict.insert("Title", Object::literal_string("Paid in full"));
        store.set(info, Object::Dict(dict)).ok()
    })
}

/// `doc_timestamp_then_info_bookkeeping` (M4 QA round 1, findings 24 and 32; manager ruling
/// R-8): [`doc_timestamp_like_pyhanko`], then a separate revision (no timestamp in it) that
/// rewrites only the `/Info` `/ModDate` and `/Producer`. The bookkeeping exemption holds only
/// for what the timestamp's own revision writes, so this is `Metadata`.
pub fn doc_timestamp_then_info_bookkeeping(pdf: &[u8]) -> Option<Vec<u8>> {
    let stamped = doc_timestamp_like_pyhanko(pdf)?;
    with_incremental(&stamped, |store| {
        set_info_values(store, "D:20261012090000Z", "Folioxide")
    })
}

/// `doc_timestamp_then_relisted_with_info_bookkeeping` (M4 QA round 2, finding 21, variant
/// R4x-w-dts-dict-relisted-only-bookkeeping-info): [`doc_timestamp_like_pyhanko`], then a plain
/// revision (no new timestamp) that lists the document timestamp's dictionary again, unchanged,
/// and rewrites the `/Info` `/ModDate` and `/Producer`: a re-listing adds no timestamp, so the
/// rewrite is no bookkeeping of one (manager ruling R-8).
pub fn doc_timestamp_then_relisted_with_info_bookkeeping(pdf: &[u8]) -> Option<Vec<u8>> {
    let stamped = doc_timestamp_like_pyhanko(pdf)?;
    with_incremental(&stamped, |store| {
        let dts = doc_timestamp_dict(store)?;
        let value = store.resolve(dts).ok()?.as_ref().clone();
        store.set(dts, value).ok()?;
        set_info_values(store, "D:20261012090000Z", "Folioxide")
    })
}

/// An XMP packet as pyHanko 0.37 writes it (`pyhanko-certified-p1-dts.pdf`): one
/// `rdf:Description` declaring the `xmp` and `pdf` prefixes, with `xmp:ModifyDate = date`,
/// `pdf:Producer`, and `extra` attributes.
fn pyhanko_xmp_packet(date: &str, extra: &str) -> Vec<u8> {
    format!(
        "<?xpacket begin=\"\u{feff}\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
         <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"pyHanko 0.37.0\">\n\
         <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n\
         <rdf:Description xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\" \
         xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\" \
         xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmp:ModifyDate=\"{date}\" \
         pdf:Producer=\"pyHanko 0.37.0\"{extra} rdf:about=\"\"/>\n\
         </rdf:RDF>\n</x:xmpmeta>\n<?xpacket end=\"r\"?>\n"
    )
    .into_bytes()
}

/// An unsigned document for the XMP cases: `pdf` with a revision that adds a catalog
/// `/Metadata` stream holding a pyHanko-style packet (one `rdf:Description` with
/// `xmp:ModifyDate` and `pdf:Producer`), as pyHanko's certifier writes it.
pub fn pyhanko_xmp_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let mut dict = Dict::new();
        dict.insert("Type", Object::name("Metadata"));
        dict.insert("Subtype", Object::name("XML"));
        let packet = pyhanko_xmp_packet("2026-10-10T18:36:28+00:00", "");
        let stream = Stream::new(dict, StreamData::Decoded(packet));
        let metadata = store.add(Object::Stream(Box::new(stream))).ok()?;
        let root = store.root_id()?;
        let mut catalog = store.resolve(root).ok()?.as_dict()?.clone();
        catalog.insert("Metadata", Object::Ref(metadata));
        store.set(root, Object::Dict(catalog)).ok()
    })
}

/// Rewrites the catalog's XMP stream in place with a pyHanko packet of `date` and `extra`.
fn rewrite_xmp(store: &mut Store, date: &str, extra: &str) -> Option<()> {
    rewrite_xmp_with(store, pyhanko_xmp_packet(date, extra))
}

/// Rewrites the catalog's XMP stream in place with the packet `packet`.
fn rewrite_xmp_with(store: &mut Store, packet: Vec<u8>) -> Option<()> {
    let root = store.root_id()?;
    let metadata = store.resolve(root).ok()?.as_dict()?.get_ref(b"Metadata")?;
    let mut dict = store.resolve(metadata).ok()?.as_stream()?.dict.clone();
    dict.remove(b"Length");
    let stream = Stream::new(dict, StreamData::Decoded(packet));
    store.set(metadata, Object::Stream(Box::new(stream))).ok()
}

/// `doc_timestamp_with_xmp_bookkeeping`: on a document with a pyHanko XMP packet
/// ([`pyhanko_xmp_input`]), [`doc_timestamp_like_pyhanko`] whose revision also rewrites the
/// packet in place with a new `xmp:ModifyDate` and nothing else, as pyHanko's timestamper does
/// (probed: `pyhanko-certified-p1-dts.pdf`).
pub fn doc_timestamp_with_xmp_bookkeeping(pdf: &[u8]) -> Option<Vec<u8>> {
    doc_timestamp_revision(pdf, |store| {
        rewrite_xmp(store, "2026-10-11T05:25:27+00:00", "")
    })
}

/// `doc_timestamp_with_xmp_title_changed`: [`doc_timestamp_with_xmp_bookkeeping`] whose packet
/// also gains a `dc:title` (no longer the timestamp's bookkeeping).
pub fn doc_timestamp_with_xmp_title_changed(pdf: &[u8]) -> Option<Vec<u8>> {
    doc_timestamp_revision(pdf, |store| {
        rewrite_xmp(
            store,
            "2026-10-11T05:25:27+00:00",
            " dc:title=\"Paid in full\"",
        )
    })
}

/// `doc_timestamp_then_xmp_bookkeeping` (M4 QA round 1, findings 24 and 32; manager ruling
/// R-8; QA variant R4-dts-then-separate-xmp-revision): on a document with a pyHanko XMP packet,
/// [`doc_timestamp_with_xmp_bookkeeping`], then a separate revision (no timestamp in it) that
/// rewrites the packet with only a new `xmp:ModifyDate`: `Metadata`, not the timestamp's
/// bookkeeping (stricter than pyHanko, which accepts it).
pub fn doc_timestamp_then_xmp_bookkeeping(pdf: &[u8]) -> Option<Vec<u8>> {
    let stamped = doc_timestamp_with_xmp_bookkeeping(pdf)?;
    with_incremental(&stamped, |store| {
        rewrite_xmp(store, "2026-10-12T09:00:00+00:00", "")
    })
}

/// `doc_timestamp_with_xmp(pdf, date, extra)` (M4 QA round 1, findings 22, 23, 25 and 26; QA
/// variants R4-value-contains-lt, R4-value-undefined-entity, R4-value-bad-charref,
/// R4-dup-attribute, R4-unquoted-extra-garbage and the attribute flood): on a document with a
/// pyHanko XMP packet, [`doc_timestamp_like_pyhanko`] whose revision rewrites the packet with
/// `xmp:ModifyDate="date"` and the raw attribute text `extra`, which may make it malformed XML.
pub fn doc_timestamp_with_xmp(pdf: &[u8], date: &str, extra: &str) -> Option<Vec<u8>> {
    doc_timestamp_revision(pdf, |store| rewrite_xmp(store, date, extra))
}

/// `doc_timestamp_with_xmp_prolog(pdf, prolog)` (M4 QA round 2, findings 19 and 24–26; QA
/// variants R4x-xmldecl-*): [`doc_timestamp_with_xmp_bookkeeping`] whose rewritten packet
/// starts with the raw text `prolog` (an XML declaration, valid or not, XML 1.0 §2.8) before
/// its `<?xpacket?>` instruction.
pub fn doc_timestamp_with_xmp_prolog(pdf: &[u8], prolog: &str) -> Option<Vec<u8>> {
    doc_timestamp_revision(pdf, |store| {
        let mut packet = prolog.as_bytes().to_vec();
        packet.extend(pyhanko_xmp_packet("2026-10-11T05:25:27+00:00", ""));
        rewrite_xmp_with(store, packet)
    })
}

/// `doc_timestamp_with_xmp_flate_then_ascii(pdf, ascii85, crypt, twice)` (M4 QA round 4,
/// finding 11, variants R4w-dec-flate-*-dts): [`doc_timestamp_with_xmp_bookkeeping`] whose
/// rewritten packet is encoded for `/Filter [/FlateDecode (/FlateDecode) (/Crypt)
/// /ASCIIHexDecode]` (or `/ASCII85Decode`), a chain pyHanko cannot decode (its FlateDecode
/// returns a `memoryview`, on which the ASCII decoders raise).
pub fn doc_timestamp_with_xmp_flate_then_ascii(
    pdf: &[u8],
    ascii85: bool,
    crypt: bool,
    twice: bool,
) -> Option<Vec<u8>> {
    let packet = pyhanko_xmp_packet("2026-10-11T05:25:27+00:00", "");
    let (data, filters) = super::flate_then_ascii(&packet, ascii85, crypt, twice)?;
    doc_timestamp_revision(pdf, |store| {
        let root = store.root_id()?;
        let metadata = store.resolve(root).ok()?.as_dict()?.get_ref(b"Metadata")?;
        let mut dict = store.resolve(metadata).ok()?.as_stream()?.dict.clone();
        for key in [b"Filter".as_slice(), b"DecodeParms", b"Length"] {
            dict.remove(key);
        }
        dict.insert(
            "Filter",
            Object::Array(filters.iter().map(|f| Object::name(*f)).collect()),
        );
        let stream = Stream::new(dict, StreamData::Encoded(data));
        store.set(metadata, Object::Stream(Box::new(stream))).ok()
    })
}

/// The object of the first `/Type /DocTimeStamp` dictionary (tests).
pub fn doc_timestamp_dict(store: &Store) -> Option<ObjectId> {
    store.object_ids().into_iter().find(|&id| {
        store
            .resolve(id)
            .ok()
            .is_some_and(|o| o.as_dict().is_some_and(|d| d.is_type(b"DocTimeStamp")))
    })
}

//! The incremental writer: an update appended to the untouched source (ISO 32000-2 §7.5.6,
//! ARCHITECTURE §A.3 "Incremental save" and §A.10 trap #12).

use std::collections::BTreeMap;

use super::full::check_root;
use super::md5::Md5;
use super::{
    DEFAULT_FLATE_LEVEL, Entry, IncrementalLayout, IncrementalOptions, IncrementalUpdate,
    ObjectWriter, StreamCompression, carried_trailer, check_value, first_id, id_array,
    link_free_list, write_table, xref_stream,
};
use crate::error::{Error, Result};
use crate::limits::LimitKind;
use crate::object::{Dict, Object, ObjectId, keys};
use crate::serialize::{serialize_indirect, serialize_object};
use crate::store::{Edit, Store, next_generation};
use crate::xref::{OffsetBase, XrefKind};

/// One object the incremental writer writes: a value (set or added, or an overlay object) or a
/// free entry. It borrows from the store's edits and from the overlay, so neither is cloned.
enum Action<'a> {
    /// Write this value as the object's definition.
    Set(&'a Object),
    /// Write a free entry for this object number (see [`Edit::Free`]).
    Free,
}

/// The source followed by an incremental update that holds the edits (§7.5.6): what
/// [`incremental_update`] describes, appended to [`Store::source`]. When nothing was edited,
/// the source bytes, unchanged.
///
/// # Errors
/// See [`incremental_update`].
pub fn save_incremental(store: &Store, opts: &IncrementalOptions) -> Result<Vec<u8>> {
    let update = incremental_update(store, opts)?;
    let source = store.source();
    let mut out = Vec::with_capacity(source.len().saturating_add(update.bytes.len()));
    out.extend_from_slice(source);
    out.extend_from_slice(&update.bytes);
    Ok(out)
}

/// Only the bytes [`save_incremental`] appends to the source (empty when nothing was edited),
/// for a caller that appends them to the file in place (a desktop app, ARCHITECTURE §A.8).
///
/// # Errors
/// See [`incremental_update`].
pub fn incremental_suffix(store: &Store, opts: &IncrementalOptions) -> Result<Vec<u8>> {
    incremental_update(store, opts).map(|update| update.bytes)
}

/// Builds the incremental update (§7.5.6) that saves the edits after the source, which is never
/// changed or re-serialized, not even the bytes before its `%PDF-` header:
///
/// - an end-of-line first, when the source does not end with CR or LF;
/// - only the objects set or added, with their own numbers and generations, in order, never in
///   an object stream; stream data as [`StreamCompression::CompressNew`] says (edited
///   [`StreamData::Decoded`](crate::StreamData::Decoded) data is Flate-encoded, source and
///   [`StreamData::Encoded`](crate::StreamData::Encoded) data is copied as encoded);
/// - a cross-reference section of the same kind as the newest revision's (§7.5.6, §7.5.8.4): a
///   table after a table, whose first subsection lists object 0 (pypdf's strict mode refuses a
///   table that is not zero-indexed), or a cross-reference stream after a stream or hybrid
///   section, which takes [`Store::next_object_number`] (or one more than the highest number
///   the section lists, if that is higher) and lists itself. A freed object gets a
///   free entry with the next generation (§7.5.4; 65535 stays 65535), linked from object 0;
/// - a trailer with every entry of the newest one but those the writer computes (`/Size`: the
///   highest number + 1; `/Prev`: the newest revision's `startxref`), the edits of
///   [`Store::set_trailer_entry`] applied, and `/ID [orig0 new1]` (see
///   [`IncrementalOptions::id1`]; generated from the content when the source has none);
/// - `startxref` and `%%EOF`.
///
/// Offsets, `/Prev` and `startxref` count from where the source's own do
/// ([`Store::offset_base`], ARCHITECTURE §A.10 trap #12): from the `%PDF-` header, as the
/// standard says, so bytes before the header (which are kept) do not shift them. (A file whose
/// offsets count from byte 0 is a repaired structure for the store, which other readers must
/// reconstruct, so it is refused below; the writer would count from byte 0 for it.)
///
/// **Positions for signatures (M3):** the new file is the source followed by
/// [`IncrementalUpdate::bytes`], [`IncrementalUpdate::start`] + `bytes.len()` bytes long;
/// [`IncrementalUpdate::objects`] gives the absolute byte range of every object written. Reopened,
/// the file has one more revision, whose [`Revision::eof_end`](crate::Revision::eof_end) is the
/// new length. (The previous newest revision's `eof_end` is the source's length only when nothing
/// follows its `%%EOF`; the update is always appended after the whole source.)
///
/// The store is not changed: to keep editing after the update was appended, open the new file.
/// [`Store::check_incremental`] tells beforehand whether the source takes an update at all.
///
/// # Errors
/// - [`ErrorCode::InvalidArgument`](crate::ErrorCode::InvalidArgument): the store has no
///   source ([`Store::new_empty`]: save it with [`Store::save`]); the trailer's `/Root` does
///   not lead to a dictionary (the catalog was freed, say); an object holds a stream inside an
///   array or dictionary.
/// - [`ErrorCode::Unsupported`](crate::ErrorCode::Unsupported): the newest revision is
///   [`XrefKind::Reconstructed`], [`Store::structure_repaired`] is true, or an in-use object
///   is not where its cross-reference entry says (a wrong offset, which the store repairs by
///   searching near it, and which makes qpdf and poppler reconstruct the whole file). Other
///   readers may resolve such a structure differently from the store, so an update appended to
///   it could mean something else to them (DECISIONS D9.8): a full save is required (its output
///   takes updates). Also a table entry beyond ten digits of offset.
/// - [`ErrorCode::LimitExceeded`](crate::ErrorCode::LimitExceeded): no object number is left for
///   the cross-reference stream.
/// - The errors of [`Store::raw_stream_data`].
pub fn incremental_update(store: &Store, opts: &IncrementalOptions) -> Result<IncrementalUpdate> {
    build_update(store, opts, &BTreeMap::new())
}

/// Only the bytes an incremental update with an `overlay` appends to the source, with the
/// absolute byte layout of the result ([`IncrementalLayout`]): what a signature needs to compute
/// its `/ByteRange` over an update it has not committed to the store (ARCHITECTURE §A.6.1, §A.6.2).
///
/// The `overlay` objects are written as if they were edits ([`Store::set`]/[`Store::add`]), but
/// the store is **not** changed: an overlay object wins over a store edit of the same identifier,
/// and over the source's object. Each overlay identifier must either be in use (a replacement,
/// [`Store::contains`]) or have a number at least [`Store::next_object_number`] (a new object,
/// never a reused free number, ARCHITECTURE §A.6.1); any other identifier is
/// [`ErrorCode::InvalidArgument`](crate::ErrorCode::InvalidArgument). Overlay objects are written
/// uncompressed and never in an object stream, like every object of an incremental update (§7.5.6),
/// so a signature dictionary and its widget keep byte-exact `/Contents` and `/ByteRange`.
///
/// Everything else matches [`incremental_update`]: the same cross-reference kind, the same
/// trailer, the same offset base, and the source left byte for byte untouched. The store's own
/// pending edits are written too, in the same revision as the overlay, before being overridden by
/// any overlay object of the same identifier.
///
/// # Errors
/// The errors of [`incremental_update`], plus
/// [`ErrorCode::InvalidArgument`](crate::ErrorCode::InvalidArgument) for an overlay identifier
/// that is neither in use nor a fresh number (`>= next_object_number()`).
pub fn incremental_suffix_with_overlay(
    store: &Store,
    opts: &IncrementalOptions,
    overlay: &BTreeMap<ObjectId, Object>,
) -> Result<IncrementalLayout> {
    build_update(store, opts, overlay).map(IncrementalLayout)
}

/// Builds the incremental update of [`incremental_update`] and [`incremental_suffix_with_overlay`]:
/// the edits of the store, with `overlay` objects written on top (winning over a store edit of the
/// same identifier) without changing the store.
fn build_update(
    store: &Store,
    opts: &IncrementalOptions,
    overlay: &BTreeMap<ObjectId, Object>,
) -> Result<IncrementalUpdate> {
    let stream_kind = appendable_kind(store)?;
    let last = store.revisions().last().ok_or_else(no_revision)?;
    let carried = carried_trailer(store.trailer())?;
    let source = store.source();
    let start = source.len() as u64;
    check_overlay(store, overlay)?;
    if !store.is_modified() && overlay.is_empty() {
        return Ok(IncrementalUpdate {
            start,
            ..IncrementalUpdate::default()
        });
    }
    check_root(store)?;

    // ARCHITECTURE §A.10 trap #12: offsets in the file's own base. (In M1 a file whose
    // offsets count from byte 0 is always `structure_repaired`, so only header-relative files
    // get here today; the conversion stays general.)
    let header_offset = store.header_offset();
    let absolute = store.offset_base() == OffsetBase::Absolute;
    let offset_of = |pos: u64| offset_in_base(absolute, header_offset, pos);
    // The previous section's absolute position, in the same base.
    let prev = offset_of(last.startxref.saturating_add(header_offset))?;

    let mut out = Vec::new();
    if !matches!(source.last(), Some(b'\n' | b'\r')) {
        out.push(b'\n');
    }
    let writer = ObjectWriter {
        store,
        compress: StreamCompression::CompressNew,
        level: DEFAULT_FLATE_LEVEL,
    };
    let mut entries: Vec<(u32, Entry)> = Vec::new();
    let mut objects = Vec::new();
    for (id, action) in merged_actions(store, overlay) {
        match action {
            Action::Set(obj) => {
                check_value(id, obj)?;
                let pos = start.saturating_add(out.len() as u64);
                entries.push((
                    id.num,
                    Entry::InFile {
                        offset: offset_of(pos)?,
                        r#gen: id.r#gen,
                    },
                ));
                writer.write(id, obj, None, &mut out)?;
                objects.push((id, pos..start.saturating_add(out.len() as u64)));
            }
            // A number the source never listed (added, then freed) needs no entry.
            Action::Free if id.num <= store.max_object_number() => entries.push((
                id.num,
                Entry::Free {
                    next: 0,
                    r#gen: next_generation(id.r#gen),
                },
            )),
            Action::Free => {}
        }
    }

    // §14.4: the first element stays; the second is "based on the file's contents at the time
    // it was last updated".
    let id0 = first_id(store.trailer());
    let digest = {
        let mut md5 = Md5::new();
        md5.update(id0.as_deref().unwrap_or_default());
        md5.update(&start.to_be_bytes());
        md5.update(&last.startxref.to_be_bytes());
        md5.update(&out);
        md5.finish().to_vec()
    };
    let id = [
        id0.unwrap_or_else(|| digest.clone()),
        opts.id1.clone().unwrap_or(digest),
    ];

    let xref_num = if stream_kind {
        Some(xref_stream_number(store.next_object_number(), &entries)?)
    } else {
        None
    };
    let highest = entries
        .iter()
        .map(|&(num, _)| num)
        .chain(xref_num)
        .fold(store.max_object_number(), u32::max);
    let size = highest
        .checked_add(1)
        .ok_or_else(|| Error::limit(LimitKind::MaxObjects, u64::from(u32::MAX), None))?;
    let mut trailer = Dict::with_capacity(carried.len() + 3);
    trailer.insert(keys::SIZE, Object::from(size));
    for (key, value) in carried {
        trailer.insert(key, value);
    }
    trailer.insert(
        keys::PREV,
        Object::Int(i64::try_from(prev).unwrap_or(i64::MAX)),
    );
    trailer.insert(keys::ID, id_array(id));

    let xref_pos = start.saturating_add(out.len() as u64);
    let has_free = entries
        .iter()
        .any(|(_, entry)| matches!(entry, Entry::Free { .. }));
    match xref_num {
        Some(num) => {
            entries.push((
                num,
                Entry::InFile {
                    offset: offset_of(xref_pos)?,
                    r#gen: 0,
                },
            ));
            if has_free {
                entries.push((0, Entry::Free { next: 0, r#gen: 0 }));
            }
            entries.sort_by_key(|&(n, _)| n);
            link_free_list(&mut entries);
            let stream = xref_stream(&entries, trailer, Some(DEFAULT_FLATE_LEVEL));
            serialize_indirect(
                ObjectId::new(num, 0),
                &Object::Stream(Box::new(stream)),
                None,
                &mut out,
            )?;
        }
        None => {
            // The first subsection starts at 0 (the head of the free list).
            entries.push((0, Entry::Free { next: 0, r#gen: 0 }));
            entries.sort_by_key(|&(n, _)| n);
            link_free_list(&mut entries);
            write_table(&entries, &mut out)?;
            out.extend_from_slice(b"trailer\n");
            serialize_object(&Object::Dict(trailer), &mut out);
            out.push(b'\n');
        }
    }
    out.extend_from_slice(format!("startxref\n{}\n%%EOF\n", offset_of(xref_pos)?).as_bytes());
    Ok(IncrementalUpdate {
        bytes: out,
        start,
        objects,
        xref_pos: Some(xref_pos),
        xref_kind: Some(if stream_kind {
            XrefKind::Stream
        } else {
            XrefKind::Table
        }),
    })
}

/// The objects to write, by identifier in object-number order: the store's edits, with the
/// `overlay` objects on top. An overlay object wins over a store edit of the same identifier
/// (and over the source), so a signature can override a pending edit without touching the store.
/// Each [`Action`] borrows from the store's edits or the overlay, so nothing is cloned.
fn merged_actions<'a>(
    store: &'a Store,
    overlay: &'a BTreeMap<ObjectId, Object>,
) -> BTreeMap<ObjectId, Action<'a>> {
    let mut actions: BTreeMap<ObjectId, Action<'a>> = BTreeMap::new();
    for (&id, edit) in store.edits() {
        actions.insert(
            id,
            match edit {
                Edit::Set(obj) => Action::Set(obj),
                Edit::Free => Action::Free,
            },
        );
    }
    for (&id, obj) in overlay {
        actions.insert(id, Action::Set(obj));
    }
    actions
}

/// Checks the overlay identifiers of [`incremental_suffix_with_overlay`]: each must be in use (a
/// replacement) or at least [`Store::next_object_number`] (a fresh number, never a reused free
/// one, ARCHITECTURE §A.6.1). Object 0 is never a valid identifier.
fn check_overlay(store: &Store, overlay: &BTreeMap<ObjectId, Object>) -> Result<()> {
    if overlay.is_empty() {
        return Ok(());
    }
    let next = store.next_object_number();
    for &id in overlay.keys() {
        if id.num == 0 {
            return Err(Error::invalid_argument(
                "an overlay object cannot be object 0 (§7.5.4)",
            ));
        }
        if store.contains(id) || id.num >= next {
            continue;
        }
        return Err(Error::invalid_argument(format!(
            "overlay object {id} is neither in use nor a fresh number (>= {next}); a signature \
             overlay may only replace an object in use or add one above every number in use, \
             never reuse a freed number"
        )));
    }
    Ok(())
}

/// Whether an incremental update may be appended to `store`'s source, and if so whether its
/// cross-reference section is a stream (after a stream or hybrid section) rather than a table:
/// the refusals of [`incremental_update`] that depend on the source only (see
/// [`Store::check_incremental`]).
pub(super) fn appendable_kind(store: &Store) -> Result<bool> {
    if !store.has_source() {
        return Err(Error::invalid_argument(
            "an incremental update needs a source document to append to; save a new document \
             with a full save",
        ));
    }
    let last = store.revisions().last().ok_or_else(no_revision)?;
    let stream_kind = match last.xref_kind {
        XrefKind::Table => false,
        XrefKind::Stream | XrefKind::Hybrid => true,
        _ => return Err(full_save_required("the file was reconstructed from a scan")),
    };
    if store.structure_repaired() {
        return Err(full_save_required(
            "opening it repaired its cross-reference structure",
        ));
    }
    // An object whose entry gives the wrong position: the store finds it nearby, but qpdf and
    // poppler reconstruct the whole file, and then need not see the update as the store does
    // (poppler lost the new /Info of such a file in the writer oracle suite).
    if let Some(id) = store.first_misplaced_object() {
        return Err(full_save_required(&format!(
            "object {id} is not at the position its cross-reference entry gives"
        )));
    }
    Ok(stream_kind)
}

/// The number of an update's cross-reference stream: `next` ([`Store::next_object_number`]),
/// or one more than the highest number the update lists when that is higher, so that the stream
/// never shares a number with an object of its own section (§7.5.8.3: the stream lists itself).
///
/// The edit API keeps every edited or added number below `next` today ([`Store::set`] needs an
/// object in use, [`Store::add`] advances it), but an update that writes objects the store does
/// not hold (the overlay of a signature, M3) may number new ones from `next` up.
pub(super) fn xref_stream_number(next: u32, entries: &[(u32, Entry)]) -> Result<u32> {
    match entries.iter().map(|&(num, _)| num).max() {
        Some(highest) if highest >= next => highest
            .checked_add(1)
            .ok_or_else(|| Error::limit(LimitKind::MaxObjects, u64::from(u32::MAX), None)),
        _ => Ok(next),
    }
}

/// The error for a source without a revision.
fn no_revision() -> Error {
    Error::invalid_argument("the document has no revision to append an incremental update to")
}

/// The offset that refers to the absolute position `pos` of the file: counted from the `%PDF-`
/// header (`header_offset` bytes into the file), or from byte 0 when the file's own offsets are
/// `absolute` ([`OffsetBase::Absolute`], Annex H).
pub(super) fn offset_in_base(absolute: bool, header_offset: u64, pos: u64) -> Result<u64> {
    if absolute {
        Ok(pos)
    } else {
        pos.checked_sub(header_offset).ok_or_else(|| {
            Error::invalid_argument(format!(
                "position {pos} is before the header at byte {header_offset}"
            ))
        })
    }
}

/// The refusal of an incremental update to a file whose structure other readers may resolve
/// differently.
fn full_save_required(why: &str) -> Error {
    Error::unsupported(format!(
        "an incremental update cannot be appended to this file because {why}; other readers \
         may resolve its structure differently, so a full save is required"
    ))
}

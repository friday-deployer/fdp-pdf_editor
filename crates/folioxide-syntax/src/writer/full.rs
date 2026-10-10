//! The full writer: the whole document written again (ARCHITECTURE §A.3 "Full save").

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use super::md5::Md5;
use super::{
    Entry, ObjectWriter, SaveOptions, StreamCompression, XrefStyle, carried_trailer, first_id,
    id_array, link_free_list, max_version, nested_stream, write_header, write_table, xref_stream,
};
use crate::error::{Error, Result};
use crate::filters::encode_flate;
use crate::limits::LimitKind;
use crate::object::{Dict, Object, ObjectId, Stream, StreamData, keys};
use crate::serialize::{serialize_indirect, serialize_object};
use crate::store::{Store, next_generation};
use crate::xref::XrefKind;

/// The most objects one object stream holds (qpdf and Acrobat use 100; the M2 brief allows up
/// to 256).
const OBJSTM_MEMBERS: usize = 100;

/// Writes the whole document again (a full rewrite, ISO 32000-2 §7.5): the bytes of a complete
/// PDF file with a single revision.
///
/// 1. **Garbage collection** ([`SaveOptions::gc`]): only the objects reachable from the trailer
///    (`/Root`, `/Info`, and any other entry it carries) are written. A stream's `/Length` is
///    not followed: the writer writes every length directly. A reference to an object that is
///    not in use (free, freed, missing, or of another generation) is written as `null`, which
///    is what it means (§7.3.10).
/// 2. **Renumbering** ([`SaveOptions::renumber`]): objects are numbered densely from 1, in the
///    order of a breadth-first walk from the trailer (the catalog is object 1), with generation
///    0.
/// 3. **Header**: `%PDF-x.y` and a binary comment line; the version is the highest of the
///    source's header, [`SaveOptions::min_version`], and 1.5 when a cross-reference stream is
///    written, and always a PDF version (1.0 to 1.7, 2.0): a source header that names none
///    (`%PDF-1.9`, `%PDF-9.9`) becomes the next one up, or 2.0. Bytes before the source's header
///    are not written.
/// 4. **Streams**: source stream data is copied as encoded, without decoding it, unless
///    [`StreamCompression::Recompress`] is set; see [`StreamCompression`] for edited data.
/// 5. **Object streams** ([`SaveOptions::object_streams`], §7.5.7): every object that may be
///    compressed is packed, at most 100 per object stream; streams, objects of a generation
///    other than 0, and signature and document timestamp dictionaries never are (`/Type /Sig`
///    or `/Type /DocTimeStamp`, or, as `/Type` is optional in a signature dictionary, a
///    `/ByteRange`, or `/Contents` with a `/Filter` or `/SubFilter`).
/// 6. **Cross-reference section**: a table whose single subsection starts at 0, with 20-byte
///    entries and free entries linked from object 0 (§7.5.4), or a cross-reference stream that
///    lists itself (§7.5.8). The trailer has `/Size`, the carried entries and `/ID` (see
///    [`SaveOptions::id`]).
///
/// The store is not changed: to keep editing the saved document, open the output.
///
/// # Errors
/// - [`ErrorCode::InvalidArgument`](crate::ErrorCode::InvalidArgument): the options are invalid
///   ([`SaveOptions::validate`]: a [`SaveOptions::min_version`] that is not a PDF version,
///   [`XrefStyle::Table`] with object streams); the trailer has no `/Root` reference, or it
///   does not lead to a dictionary; an object holds a stream inside an array or dictionary.
/// - [`ErrorCode::Unsupported`](crate::ErrorCode::Unsupported): a table entry would need an
///   offset beyond ten digits (about 9.3 GiB), or the document is encrypted (M5).
/// - [`ErrorCode::LimitExceeded`](crate::ErrorCode::LimitExceeded): more objects than object
///   numbers allow.
/// - The errors of [`Store::resolve`] and [`Store::raw_stream_data`] (strict mode, limits).
pub fn save(store: &Store, opts: &SaveOptions) -> Result<Vec<u8>> {
    opts.validate()?;
    let xref_stream_kind = match opts.xref {
        XrefStyle::Table => false,
        XrefStyle::Stream => true,
        XrefStyle::Auto => {
            opts.object_streams
                || store
                    .revisions()
                    .last()
                    .is_some_and(|r| matches!(r.xref_kind, XrefKind::Stream | XrefKind::Hybrid))
        }
    };
    let carried = carried_trailer(store.trailer())?;
    check_root(store)?;
    let plan = Plan::collect(store, &carried, opts)?;

    let mut version = max_version(store.version(), opts.min_version.unwrap_or((1, 0)));
    if xref_stream_kind {
        version = max_version(version, (1, 5));
    }
    let mut out = Vec::new();
    write_header(version, &mut out);

    let level = opts.flate_level.min(9);
    let writer = ObjectWriter {
        store,
        compress: opts.compress,
        level,
    };
    let structure_level = match opts.compress {
        StreamCompression::Keep => None,
        _ => Some(level),
    };
    let mut entries: Vec<(u32, Entry)> = Vec::with_capacity(plan.objects.len() + 2);
    let mut next_num = plan.max_num().checked_add(1).ok_or_else(too_many_objects)?;
    let mut members: Vec<(ObjectId, Object)> = Vec::new();
    for (new, old, obj) in &plan.objects {
        let remap = Remap {
            map: &plan.map,
            owner: *old,
        };
        match &**obj {
            Object::Stream(stream) => {
                let dict = remap.dict(&stream.dict)?;
                entries.push((new.num, in_file(out.len(), new.r#gen)));
                writer.write(*new, obj, Some(dict), &mut out)?;
            }
            other => {
                let value = remap.value(other)?;
                if opts.object_streams && new.r#gen == 0 && !is_signature(&value) {
                    members.push((*new, value));
                    if members.len() >= OBJSTM_MEMBERS {
                        let num = take_number(&mut next_num)?;
                        write_object_stream(
                            num,
                            &members,
                            structure_level,
                            &mut entries,
                            &mut out,
                        )?;
                        members.clear();
                    }
                } else {
                    entries.push((new.num, in_file(out.len(), new.r#gen)));
                    writer.write(*new, &value, None, &mut out)?;
                }
            }
        }
    }
    if !members.is_empty() {
        let num = take_number(&mut next_num)?;
        write_object_stream(num, &members, structure_level, &mut entries, &mut out)?;
    }

    // §14.4: the identifier, from the options, else the trailer's first element (as read or
    // set) and a digest of the content, else the digest twice.
    let digest = {
        let mut md5 = Md5::new();
        md5.update(&out);
        md5.finish().to_vec()
    };
    let id = match &opts.id {
        Some(id) => id.clone(),
        None => [
            first_id(store.trailer()).unwrap_or_else(|| digest.clone()),
            digest,
        ],
    };
    let mut trailer = Dict::with_capacity(carried.len() + 2);
    let remap = Remap {
        map: &plan.map,
        owner: ObjectId::new(0, 0),
    };
    let xref_num = xref_stream_kind
        .then(|| take_number(&mut next_num))
        .transpose()?;
    let size = next_num;
    trailer.insert(keys::SIZE, Object::from(size));
    for (key, value) in &carried {
        let value = remap.value(value)?;
        // A dangling /Info (a freed or missing dictionary) is no /Info at all.
        if value.is_null() {
            continue;
        }
        trailer.insert(key.clone(), value);
    }
    trailer.insert(keys::ID, id_array(id));

    let xref_pos = out.len();
    match xref_num {
        Some(num) => {
            entries.push((num, in_file(xref_pos, 0)));
            let entries = complete(store, entries, size, opts.renumber);
            let stream = xref_stream(&entries, trailer, structure_level);
            write_stream_object(ObjectId::new(num, 0), stream, &mut out)?;
        }
        None => {
            let entries = complete(store, entries, size, opts.renumber);
            write_table(&entries, &mut out)?;
            out.extend_from_slice(b"trailer\n");
            serialize_object(&Object::Dict(trailer), &mut out);
            out.push(b'\n');
        }
    }
    out.extend_from_slice(format!("startxref\n{xref_pos}\n%%EOF\n").as_bytes());
    Ok(out)
}

/// Checks that the trailer's `/Root` is a reference that leads to a dictionary (§7.5.5).
pub(super) fn check_root(store: &Store) -> Result<()> {
    let Some(root) = store.trailer().get_ref(keys::ROOT) else {
        return Err(Error::invalid_argument(
            "the trailer has no /Root reference; set the catalog with set_trailer_entry",
        ));
    };
    if !store.contains(root) || store.deref(&Object::Ref(root))?.as_dict().is_none() {
        return Err(Error::invalid_argument(format!(
            "the trailer /Root {root} does not lead to a dictionary"
        )));
    }
    Ok(())
}

/// The objects to write and their new identifiers.
struct Plan {
    /// (new identifier, old identifier, object), by new identifier.
    objects: Vec<(ObjectId, ObjectId, Arc<Object>)>,
    /// Old identifier → new identifier, for every object written.
    map: HashMap<ObjectId, ObjectId>,
}

impl Plan {
    /// Walks the graph from the trailer's entries (`carried`) and numbers what it finds.
    fn collect(
        store: &Store,
        carried: &[(crate::Name, Object)],
        opts: &SaveOptions,
    ) -> Result<Plan> {
        let mut found: Vec<(ObjectId, Arc<Object>)> = Vec::new();
        let mut seen: HashSet<ObjectId> = HashSet::new();
        let mut queue: VecDeque<ObjectId> = VecDeque::new();
        let visit = |id: ObjectId, seen: &mut HashSet<ObjectId>, queue: &mut VecDeque<_>| {
            if store.contains(id) && seen.insert(id) {
                queue.push_back(id);
            }
        };
        for (_, value) in carried {
            for id in references(value) {
                visit(id, &mut seen, &mut queue);
            }
        }
        // Breadth first: the catalog first, then what it refers to, and so on.
        while let Some(id) = queue.pop_front() {
            let object = store.resolve(id)?;
            for child in references(&object) {
                visit(child, &mut seen, &mut queue);
            }
            found.push((id, object));
        }
        if !opts.gc {
            for id in store.object_ids() {
                if seen.contains(&id) {
                    continue;
                }
                let object = store.resolve(id)?;
                if is_structure(&object) {
                    continue;
                }
                seen.insert(id);
                found.push((id, object));
            }
        }

        let mut map = HashMap::with_capacity(found.len());
        let mut objects = Vec::with_capacity(found.len());
        if opts.renumber {
            for (i, (old, object)) in found.into_iter().enumerate() {
                let num = i
                    .checked_add(1)
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(too_many_objects)?;
                let new = ObjectId::new(num, 0);
                map.insert(old, new);
                objects.push((new, old, object));
            }
        } else {
            found.sort_by_key(|(id, _)| *id);
            let max = found.last().map_or(0, |(id, _)| id.num);
            let mut next = max.checked_add(1).ok_or_else(too_many_objects)?;
            let mut previous: Option<u32> = None;
            for (old, object) in found {
                // Two generations of one number (only after a reconstruction, §7.3.10): the
                // lowest keeps the number, the others are numbered after every other object.
                let new = if previous == Some(old.num) {
                    ObjectId::new(take_number(&mut next)?, 0)
                } else {
                    old
                };
                previous = Some(old.num);
                map.insert(old, new);
                objects.push((new, old, object));
            }
            objects.sort_by_key(|(new, _, _)| *new);
        }
        Ok(Plan { objects, map })
    }

    /// The highest object number written.
    fn max_num(&self) -> u32 {
        self.objects
            .iter()
            .map(|(new, _, _)| new.num)
            .max()
            .unwrap_or(0)
    }
}

/// Rewrites the references of a value through the renumbering map; a reference to an object
/// that is not written becomes `null`.
struct Remap<'m> {
    map: &'m HashMap<ObjectId, ObjectId>,
    /// The object being written, for errors.
    owner: ObjectId,
}

impl Remap<'_> {
    /// A copy of `value` (not a stream) with its references renumbered.
    fn value(&self, value: &Object) -> Result<Object> {
        let mut copy = value.clone();
        self.rewrite(&mut copy)?;
        Ok(copy)
    }

    /// A copy of a stream dictionary with its references renumbered.
    fn dict(&self, dict: &Dict) -> Result<Dict> {
        let mut copy = Object::Dict(dict.clone());
        self.rewrite(&mut copy)?;
        match copy {
            Object::Dict(dict) => Ok(dict),
            _ => Err(nested_stream(self.owner)),
        }
    }

    /// Renumbers the references inside `value` in place (iteratively: any depth is fine).
    fn rewrite(&self, value: &mut Object) -> Result<()> {
        let mut stack: Vec<&mut Object> = vec![value];
        while let Some(obj) = stack.pop() {
            match obj {
                Object::Ref(id) => {
                    let new = match self.map.get(id) {
                        Some(&new) => Object::Ref(new),
                        None => Object::Null,
                    };
                    *obj = new;
                }
                Object::Array(items) => stack.extend(items.iter_mut()),
                Object::Dict(dict) => stack.extend(dict.iter_mut().map(|(_, v)| v)),
                Object::Stream(_) => return Err(nested_stream(self.owner)),
                _ => {}
            }
        }
        Ok(())
    }
}

/// The references inside `value`, in order of appearance; a stream's `/Length` is skipped (the
/// writers write lengths directly, so an object that only holds a length is not needed).
fn references(value: &Object) -> Vec<ObjectId> {
    let mut refs = Vec::new();
    let mut stack: Vec<&Object> = match value {
        Object::Stream(stream) => stream
            .dict
            .iter()
            .rev()
            .filter(|(key, _)| key.as_bytes() != keys::LENGTH)
            .map(|(_, v)| v)
            .collect(),
        other => vec![other],
    };
    while let Some(obj) = stack.pop() {
        match obj {
            Object::Ref(id) => refs.push(*id),
            Object::Array(items) => stack.extend(items.iter().rev()),
            Object::Dict(dict) => stack.extend(dict.values().rev()),
            // A nested stream is refused when the object is written.
            Object::Stream(stream) => stack.extend(stream.dict.values().rev()),
            _ => {}
        }
    }
    refs
}

/// The source's cross-reference structure, which a full save replaces: cross-reference streams
/// (§7.5.8), object streams (§7.5.7), and the linearization dictionary (Annex F), which would
/// describe the old layout.
fn is_structure(object: &Object) -> bool {
    match object {
        Object::Stream(stream) => {
            stream.dict.is_type(keys::XREF) || stream.dict.is_type(keys::OBJ_STM)
        }
        Object::Dict(dict) => dict.contains_key(b"Linearized"),
        _ => false,
    }
}

/// Whether `value` is a signature or document timestamp dictionary (§12.8.1, §12.8.5), which is
/// never put in an object stream: a signature's byte range must cover its `/Contents` in the
/// file itself.
///
/// `/Type` is optional in a signature dictionary (§12.8.1 Table 255: "Optional if Sig;
/// Required if DocTimeStamp"), and many signed files leave it out, so a dictionary also counts
/// as one when it has a `/ByteRange`, which only signature dictionaries have, or `/Contents`
/// together with a signature handler (`/Filter` or `/SubFilter`; a direct dictionary with a
/// `/Filter` is no stream). Keeping some other dictionary out of an object stream by mistake
/// only costs a few bytes.
fn is_signature(value: &Object) -> bool {
    value.as_dict().is_some_and(|d| {
        d.is_type(b"Sig")
            || d.is_type(b"DocTimeStamp")
            || d.contains_key(b"ByteRange")
            || (d.contains_key(keys::CONTENTS)
                && (d.contains_key(keys::FILTER) || d.contains_key(b"SubFilter")))
    })
}

/// An in-file entry at `pos` (the output starts with the header, so positions are offsets).
fn in_file(pos: usize, r#gen: u16) -> Entry {
    Entry::InFile {
        offset: pos as u64,
        r#gen,
    }
}

/// Takes the number `next` holds and advances it.
fn take_number(next: &mut u32) -> Result<u32> {
    let num = *next;
    *next = num.checked_add(1).ok_or_else(too_many_objects)?;
    Ok(num)
}

/// The error for more objects than object numbers allow.
fn too_many_objects() -> Error {
    Error::limit(LimitKind::MaxObjects, u64::from(u32::MAX), None)
}

/// Writes object stream `num` holding `members` (already renumbered), Flate-encoded at `level`
/// unless `None`, and records its entries and the members' (§7.5.7).
fn write_object_stream(
    num: u32,
    members: &[(ObjectId, Object)],
    level: Option<u8>,
    entries: &mut Vec<(u32, Entry)>,
    out: &mut Vec<u8>,
) -> Result<()> {
    let mut header = String::new();
    let mut body: Vec<u8> = Vec::new();
    for (index, (id, value)) in members.iter().enumerate() {
        if index > 0 {
            header.push(' ');
        }
        header.push_str(&format!("{} {}", id.num, body.len()));
        serialize_object(value, &mut body);
        body.push(b'\n');
        let index = u32::try_from(index).map_err(|_| too_many_objects())?;
        entries.push((id.num, Entry::InObjStm { stream: num, index }));
    }
    header.push('\n');
    let first = header.len();
    let mut data = header.into_bytes();
    data.extend_from_slice(&body);
    let mut dict = Dict::with_capacity(5);
    dict.insert(keys::TYPE, Object::name(keys::OBJ_STM));
    dict.insert(keys::N, Object::Int(members.len() as i64));
    dict.insert(keys::FIRST, Object::Int(first as i64));
    let data = match level {
        Some(level) => {
            dict.insert(keys::FILTER, Object::name("FlateDecode"));
            encode_flate(&data, level)
        }
        None => data,
    };
    entries.push((num, in_file(out.len(), 0)));
    write_stream_object(
        ObjectId::new(num, 0),
        Stream::new(dict, StreamData::Encoded(data)),
        out,
    )
}

/// Writes a stream the writer built (encoded data, dictionary complete but for `/Length`).
fn write_stream_object(id: ObjectId, stream: Stream, out: &mut Vec<u8>) -> Result<()> {
    serialize_indirect(id, &Object::Stream(Box::new(stream)), None, out)
}

/// Every entry from 0 to `size - 1`: `entries` (the objects written, any order), object 0, and
/// a free entry for every other number, linked into the free list. The free entry of a number
/// that held an object the store knows (dropped, freed) takes the next generation (§7.5.4);
/// others take 0. With dense numbering there are no such numbers.
fn complete(
    store: &Store,
    mut entries: Vec<(u32, Entry)>,
    size: u32,
    renumbered: bool,
) -> Vec<(u32, Entry)> {
    entries.sort_by_key(|&(num, _)| num);
    let mut all: Vec<(u32, Entry)> = Vec::with_capacity(entries.len().saturating_add(1));
    let mut written = entries.into_iter().peekable();
    for num in 0..size {
        match written.next_if(|&(n, _)| n == num) {
            Some(entry) => all.push(entry),
            None => {
                let r#gen = if num == 0 || renumbered {
                    0
                } else {
                    gap_generation(store, num)
                };
                all.push((num, Entry::Free { next: 0, r#gen }));
            }
        }
    }
    link_free_list(&mut all);
    all
}

/// The generation of the free entry for object number `num`, not written: the next generation
/// of the object the store had under it (dropped by garbage collection), the generation of a
/// free entry an edit made, or 0.
fn gap_generation(store: &Store, num: u32) -> u16 {
    match store.generation_of(num) {
        Some(r#gen) if store.contains(ObjectId::new(num, r#gen)) => next_generation(r#gen),
        Some(r#gen) => r#gen,
        None => 0,
    }
}

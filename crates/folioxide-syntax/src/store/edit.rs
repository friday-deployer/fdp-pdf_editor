//! The edit layer of the store (M2 brief WP2.1, ARCHITECTURE §A.3 "Write path").
//!
//! Edits are kept beside the lazy store, which never changes what it read from the source: a
//! map from [`ObjectId`] to [`Edit`] (a replaced or added object, or a freed one), the number
//! the next added object gets, and the trailer entries changed by
//! [`Store::set_trailer_entry`]. Every public read ([`Store::resolve`], and through it
//! [`Store::deref`] and the references [`Store::stream_data`] follows) looks at the edits first;
//! the store's own loads read the source only. The writers ([`crate::writer`]) save the result.
//!
//! Object numbers are never reused: [`Store::add`] numbers new objects after every number the
//! source lists (in use or free), every number the source's objects refer to (a dangling
//! reference keeps meaning `null`), and every number added before, so a freed number stays free
//! and a reference to a freed object reads as `null` (§7.3.10) until the document is saved with
//! a full rewrite.
//!
//! An object stream of the source (§7.5.7) cannot be edited while it holds an object in use
//! that no edit replaced or freed: the store keeps reading that object from it as the source
//! has it, so an edit would change nothing in the store, while an incremental update that
//! replaced or freed the container would leave the object unreadable in the saved file.

use std::sync::Arc;

use super::{Location, OpenOptions, Store, shared_bytes};
use crate::error::{Error, Result};
use crate::limits::LimitKind;
use crate::object::{Object, ObjectId, keys};

/// One edit, keyed by the identifier of the object it applies to.
#[derive(Clone, Debug)]
pub(crate) enum Edit {
    /// The object's new value: replaced ([`Store::set`], [`Store::get_mut`]) or added
    /// ([`Store::add`]). Shared, so that [`Store::resolve`] hands out snapshots cheaply;
    /// [`Store::get_mut`] clones it when a snapshot is still held (copy-on-write).
    Set(Arc<Object>),
    /// The object was freed ([`Store::free`]): it reads as `null`, and an incremental update
    /// writes a free entry with the next generation.
    Free,
}

/// Trailer keys the writers compute themselves (§7.5.5 Table 15, §7.5.8.2 Table 17, and the
/// stream keys of Table 5 that a cross-reference stream's dictionary carries):
/// [`Store::set_trailer_entry`] refuses them, and the writers drop them when they carry the
/// trailer over.
pub(crate) const COMPUTED_TRAILER_KEYS: &[&[u8]] = &[
    keys::SIZE,
    keys::PREV,
    keys::XREF_STM,
    keys::W,
    keys::INDEX,
    keys::FILTER,
    keys::DECODE_PARMS,
    keys::LENGTH,
    keys::TYPE,
    keys::DL,
    keys::F,
    b"FFilter",
    b"FDecodeParms",
];

/// The generation of the free entry that replaces an object of generation `gen` (§7.5.4: "the
/// generation number shall be incremented by 1" when an object is freed). An object of
/// generation 65535 cannot be reused, so its free entry keeps 65535.
pub(crate) const fn next_generation(r#gen: u16) -> u16 {
    r#gen.saturating_add(1)
}

impl Store {
    // ---- creating -----------------------------------------------------------------------------

    /// A store for a brand-new document: no source bytes, no revisions, no objects, and an empty
    /// trailer. `version` is the header version a full save writes (at least; see
    /// [`SaveOptions`](crate::writer::SaveOptions)).
    ///
    /// Add the objects with [`Store::add`] and set the catalog with
    /// [`Store::set_trailer_entry`]; then save it with [`Store::save`]. An incremental save is
    /// impossible ([`ErrorCode::InvalidArgument`](crate::ErrorCode::InvalidArgument)): there is
    /// nothing to append to.
    ///
    /// ```
    /// use folioxide_syntax::{Dict, Object, SaveOptions, Store, keys};
    ///
    /// let mut store = Store::new_empty((1, 7));
    /// let mut pages = Dict::new();
    /// pages.insert(keys::TYPE, Object::name("Pages"));
    /// pages.insert(keys::KIDS, Object::Array(Vec::new()));
    /// pages.insert(keys::COUNT, 0);
    /// let pages = store.add(pages.into())?;
    /// let mut catalog = Dict::new();
    /// catalog.insert(keys::TYPE, Object::name("Catalog"));
    /// catalog.insert(keys::PAGES, pages);
    /// let catalog = store.add(catalog.into())?;
    /// store.set_trailer_entry(keys::ROOT, catalog.into())?;
    /// let pdf = store.save(&SaveOptions::default())?;
    /// assert!(pdf.starts_with(b"%PDF-1.7"));
    /// # Ok::<(), folioxide_syntax::Error>(())
    /// ```
    pub fn new_empty(version: (u8, u8)) -> Store {
        let mut store = Store::blank(shared_bytes(Vec::<u8>::new()), &OpenOptions::default());
        store.version = version;
        store
    }

    /// Whether the store was opened from a file (see [`Store::open`]); false for
    /// [`Store::new_empty`].
    pub fn has_source(&self) -> bool {
        self.has_source
    }

    // ---- editing objects ----------------------------------------------------------------------

    /// Replaces object `id` with `obj`.
    ///
    /// `id` must name an object in use: an object of the source with its generation, or one
    /// returned by [`Store::add`], not freed since. [`Store::resolve`] returns `obj` from now on;
    /// `Arc`s it handed out before keep the old value.
    ///
    /// A stream may only be the value itself, never nested inside an array or dictionary
    /// (§7.3.8); the writers refuse a nested stream. Stream data can be
    /// [`StreamData::Decoded`](crate::StreamData::Decoded) (the writer encodes it and fixes
    /// `/Length`, `/Filter` and `/DecodeParms`) or
    /// [`StreamData::Encoded`](crate::StreamData::Encoded) (written as is, with the
    /// dictionary's `/Filter`).
    ///
    /// # Errors
    /// [`ErrorCode::InvalidArgument`](crate::ErrorCode::InvalidArgument) when `id` is object 0,
    /// is not in use (free, freed, never used), has another generation than the object in use
    /// under its number, or is an object stream of the source that still holds objects in use
    /// (see [`Store::object_stream_members`]).
    pub fn set(&mut self, id: ObjectId, obj: Object) -> Result<()> {
        self.check_editable(id)?;
        self.edits.insert(id, Edit::Set(Arc::new(obj)));
        self.weigh_edit(id);
        Ok(())
    }

    /// The object `id`, mutably (copy-on-write): the first call clones the object into the
    /// edits, later calls return the edited object. `Arc`s that [`Store::resolve`] handed out
    /// before keep their value.
    ///
    /// ```
    /// use folioxide_syntax::{Object, OpenOptions, Store};
    ///
    /// let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n\
    /// 0000000000 65535 f\r\n0000000009 00000 n\r\ntrailer\n<< /Size 2 /Root 1 0 R >>\n\
    /// startxref\n45\n%%EOF\n";
    /// let mut store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default())?;
    /// let root = store.root_id().unwrap();
    /// let before = store.resolve(root)?;
    /// store.get_mut(root)?.as_dict_mut().unwrap().insert("Lang", Object::literal_string("en"));
    /// assert!(store.resolve(root)?.as_dict().unwrap().contains_key(b"Lang"));
    /// assert!(!before.as_dict().unwrap().contains_key(b"Lang"));
    /// assert_eq!(store.edited_ids(), vec![root]);
    /// # Ok::<(), folioxide_syntax::Error>(())
    /// ```
    ///
    /// # Errors
    /// - [`ErrorCode::InvalidArgument`](crate::ErrorCode::InvalidArgument) as for
    ///   [`Store::set`].
    /// - The errors of [`Store::resolve`] for a source object that cannot be read (strict
    ///   mode, or a limit); [`Store::set`] replaces such an object without reading it.
    pub fn get_mut(&mut self, id: ObjectId) -> Result<&mut Object> {
        if !matches!(self.edits.get(&id), Some(Edit::Set(_))) {
            self.check_editable(id)?;
            let object = Object::clone(&*self.resolve_source(id)?);
            self.edits.insert(id, Edit::Set(Arc::new(object)));
            self.weigh_edit(id);
        }
        // The caller may change it: the next memory estimate measures it again.
        self.lend_edit(id);
        match self.edits.get_mut(&id) {
            Some(Edit::Set(object)) => Ok(Arc::make_mut(object)),
            _ => Err(Error::invalid_argument(format!(
                "object {id} is not in use"
            ))),
        }
    }

    /// Adds `obj` as a new object and returns its identifier: the next unused number (after
    /// every number the source lists, in use or free, every number its objects refer to, and
    /// every number added before; see [`Store::next_object_number`]) with generation 0.
    ///
    /// The first call (or [`Store::next_object_number`]) reads every object of the source once,
    /// to find the references to numbers no section lists.
    ///
    /// # Errors
    /// [`ErrorCode::LimitExceeded`](crate::ErrorCode::LimitExceeded) when the number would reach
    /// [`Limits::max_objects`](crate::Limits::max_objects).
    pub fn add(&mut self, obj: Object) -> Result<ObjectId> {
        let num = self.next_object_number();
        let max = self.limits().max_objects;
        if num == 0 || num >= max {
            return Err(Error::limit(LimitKind::MaxObjects, u64::from(max), None));
        }
        // `num < max <= u32::MAX`: no overflow.
        self.next_num = num.saturating_add(1);
        let id = ObjectId::new(num, 0);
        self.edits.insert(id, Edit::Set(Arc::new(obj)));
        self.weigh_edit(id);
        Ok(id)
    }

    /// Frees object `id`: it reads as `null` from now on (as does every reference to it), and
    /// an incremental update writes a free entry for it with the next generation (§7.5.4; an
    /// object of generation 65535 keeps 65535 and is never reused). Its number is not reused by
    /// [`Store::add`]. A full save drops it; references to it are written as `null`.
    ///
    /// [`Store::object_ids`] also lists the source's own structure, which nothing refers to: its
    /// cross-reference streams (freeing one is harmless: readers find it by its position) and
    /// its object streams, which cannot be freed while they hold objects in use (see
    /// [`Store::object_stream_members`]). A pass that frees unreferenced objects skips those.
    ///
    /// # Errors
    /// [`ErrorCode::InvalidArgument`](crate::ErrorCode::InvalidArgument) as for
    /// [`Store::set`] (freeing an object twice included).
    pub fn free(&mut self, id: ObjectId) -> Result<()> {
        self.check_editable(id)?;
        self.edits.insert(id, Edit::Free);
        self.weigh_edit(id);
        Ok(())
    }

    // ---- editing the trailer ------------------------------------------------------------------

    /// Sets the trailer entry `key` (§7.5.5, Table 15). Allowed keys:
    ///
    /// - `/Root`: an indirect reference to the document catalog;
    /// - `/Info`: an indirect reference to the document information dictionary (§14.3.3);
    /// - `/ID`: an array of two byte strings (§14.4). The writers keep its first element and
    ///   compute the second from the content, unless their options give it.
    ///
    /// The writers compute `/Size`, `/Prev`, `/XRefStm`, `/W`, `/Index`, `/Filter`,
    /// `/DecodeParms`, `/Length` and `/Type` themselves, and `/Encrypt` arrives with encryption
    /// (M5); every other key is refused too. Setting a key to the value it has already is not
    /// an edit.
    ///
    /// # Errors
    /// [`ErrorCode::InvalidArgument`](crate::ErrorCode::InvalidArgument) for another key, or a
    /// value of the wrong kind.
    pub fn set_trailer_entry(&mut self, key: &[u8], value: Object) -> Result<()> {
        let name = String::from_utf8_lossy(key).into_owned();
        match key {
            keys::ROOT | keys::INFO => match value {
                Object::Ref(id) if id.num != 0 => {}
                _ => {
                    return Err(Error::invalid_argument(format!(
                        "trailer /{name} must be an indirect reference (§7.5.5), not a {}",
                        value.type_name()
                    )));
                }
            },
            keys::ID => {
                let two_strings = value.as_array().is_some_and(|items| {
                    items.len() == 2 && items.iter().all(|item| item.as_pdf_string().is_some())
                });
                if !two_strings {
                    return Err(Error::invalid_argument(
                        "trailer /ID must be an array of two byte strings (§14.4)",
                    ));
                }
            }
            _ => return Err(Self::refused_trailer_key(key)),
        }
        if self.trailer.get(key) != Some(&value) {
            self.trailer.insert(key, value);
            self.trailer_edited = true;
        }
        Ok(())
    }

    /// Removes the trailer entry `key` and returns its value (`None` when it was absent). Only
    /// `/Info` and `/ID` can be removed: a trailer must have `/Root`. A full save without `/ID`
    /// generates one (see [`SaveOptions`](crate::writer::SaveOptions)).
    ///
    /// # Errors
    /// [`ErrorCode::InvalidArgument`](crate::ErrorCode::InvalidArgument) for any other key.
    pub fn remove_trailer_entry(&mut self, key: &[u8]) -> Result<Option<Object>> {
        match key {
            keys::INFO | keys::ID => {
                let old = self.trailer.remove(key);
                if old.is_some() {
                    self.trailer_edited = true;
                }
                Ok(old)
            }
            keys::ROOT => Err(Error::invalid_argument(
                "trailer /Root cannot be removed: every document needs a catalog (§7.5.5); set \
                 another one instead",
            )),
            _ => Err(Self::refused_trailer_key(key)),
        }
    }

    /// The error for a trailer key that [`Store::set_trailer_entry`] does not accept.
    fn refused_trailer_key(key: &[u8]) -> Error {
        let name = String::from_utf8_lossy(key);
        if COMPUTED_TRAILER_KEYS.contains(&key) {
            Error::invalid_argument(format!(
                "trailer /{name} is computed by the writer and cannot be set"
            ))
        } else if key == keys::ENCRYPT {
            Error::invalid_argument("trailer /Encrypt cannot be set: encryption arrives in M5")
        } else {
            Error::invalid_argument(format!(
                "trailer /{name} cannot be edited; only /Root, /Info and /ID can"
            ))
        }
    }

    // ---- inspecting edits ---------------------------------------------------------------------

    /// Whether anything was edited: an object set, added or freed, or a trailer entry changed.
    pub fn is_modified(&self) -> bool {
        self.trailer_edited || !self.edits.is_empty()
    }

    /// The identifiers of the objects set, added or freed, sorted by number and generation.
    pub fn edited_ids(&self) -> Vec<ObjectId> {
        self.edits.keys().copied().collect()
    }

    /// Whether `id` names an object in use: an object of the source with its generation, or
    /// one set or added, and not freed. A reference to any other object reads as `null`.
    pub fn contains(&self, id: ObjectId) -> bool {
        match self.edits.get(&id) {
            Some(Edit::Set(_)) => true,
            Some(Edit::Free) => false,
            None => self.source_in_use(id),
        }
    }

    /// The generation the cross-reference data lists for object number `num` as the document
    /// stands now: the generation of the object in use under that number (from the source, set
    /// or added), or, for a number freed by [`Store::free`], the generation of its free entry
    /// (one more than the freed object's; 65535 stays 65535). `None` for object 0 and for a
    /// number not in use that no edit freed (free in the source, or never used).
    pub fn generation_of(&self, num: u32) -> Option<u16> {
        if num == 0 {
            return None;
        }
        let range = ObjectId::new(num, 0)..=ObjectId::new(num, u16::MAX);
        let mut freed = None;
        for (id, edit) in self.edits.range(range) {
            match edit {
                Edit::Set(_) => return Some(id.r#gen),
                Edit::Free => freed = freed.or(Some(id.r#gen)),
            }
        }
        let source = self.slot(num).map(|slot| slot.r#gen);
        match (freed, source) {
            // The object the merged cross-reference data shows was freed.
            (Some(r#gen), Some(shown)) if r#gen == shown => Some(next_generation(r#gen)),
            (_, Some(shown)) => Some(shown),
            (Some(r#gen), None) => Some(next_generation(r#gen)),
            (None, None) => None,
        }
    }

    /// The objects in use that the store reads from object `id` because it is an object stream
    /// of the source (§7.5.7) holding them, by number: the compressed objects the merged
    /// cross-reference data puts in it, without those an edit replaced or freed (an edited
    /// object is read from the edits, and an incremental update gives it an entry of its own).
    /// Empty for any other object, and for an object that the cross-reference data names as
    /// the container of compressed objects but that is no uncompressed stream (those objects
    /// cannot be read from it in any case).
    ///
    /// While this is not empty, `id` cannot be set, changed or freed ([`Store::set`],
    /// [`Store::get_mut`], [`Store::free`]): the store would go on reading these objects from
    /// the source's container, while an incremental update that replaced or freed it would
    /// leave them unreadable in the saved file (the catalog of a file whose page tree is in an
    /// object stream, for instance). A full save writes object streams of its own and never
    /// copies the source's.
    pub fn object_stream_members(&self, id: ObjectId) -> Vec<ObjectId> {
        // §7.5.8.3: a type 2 entry names its object stream by number only (the generation is
        // implicitly 0), and the store reads the container under that number whatever its
        // generation, so the number decides.
        let uncompressed = matches!(self.location(id.num), Some(Location::InFile { .. }));
        if !uncompressed || !self.source_in_use(id) {
            return Vec::new();
        }
        let members: Vec<ObjectId> = self
            .slots_in(id.num)
            .map(|slot| ObjectId::new(slot.num, slot.r#gen))
            .filter(|member| !self.edits.contains_key(member))
            .collect();
        // Only read the object when it names members (an edit of an object no type 2 entry
        // names never reads it).
        if members.is_empty()
            || !matches!(self.resolve_source(id).as_deref(), Ok(Object::Stream(_)))
        {
            return Vec::new();
        }
        members
    }

    /// The number [`Store::add`] gives the next new object, the smallest number above
    ///
    /// - every number any cross-reference section of the source lists, in use or free
    ///   ([`Store::max_object_number`]): a freed number is never reused (a reader comparing
    ///   revisions, such as a signature validator, would see an object clobbered);
    /// - every number an object of the source or a trailer of the source refers to, below
    ///   [`Limits::max_objects`](crate::Limits::max_objects): a reference to a number no section
    ///   lists means `null` (§7.3.10), and a new object under that number would silently become
    ///   its target (a page tree kid, an annotation; qpdf guards the same way with
    ///   `fixDanglingReferences`);
    /// - every number [`Store::add`] returned before.
    ///
    /// Every number from it up is unused, so it is also the `/Size` a cross-reference section
    /// needs to cover every number so far, and the first of the numbers an incremental update
    /// can give new objects.
    ///
    /// The references are found by one walk over every object of the source, on the first call
    /// of this method or [`Store::add`], and remembered (edits made later are not walked: a
    /// reference an edit introduces is the editor's own). Objects that cannot be read add
    /// nothing.
    pub fn next_object_number(&self) -> u32 {
        self.next_num.max(self.referenced_floor())
    }

    // ---- crate internals ----------------------------------------------------------------------

    /// One more than the largest object number below [`Limits::max_objects`] that an object or
    /// a trailer of the source refers to (0 when none does), computed once.
    ///
    /// [`Limits::max_objects`]: crate::Limits::max_objects
    fn referenced_floor(&self) -> u32 {
        *self.referenced_floor.get_or_init(|| {
            let max_objects = self.limits().max_objects;
            let mut highest: Option<u32> = None;
            let mut note = |value: &Object| {
                for num in referenced_numbers(value) {
                    if num < max_objects && highest.is_none_or(|h| num > h) {
                        highest = Some(num);
                    }
                }
            };
            for revision in self.revisions() {
                note(&Object::Dict(revision.trailer.clone()));
            }
            for id in self.source_ids() {
                // An object that cannot be read (strict mode, a limit) refers to nothing a
                // writer could write.
                if let Ok(object) = self.resolve_source(id) {
                    note(&object);
                }
            }
            highest.map_or(0, |h| h.saturating_add(1))
        })
    }

    /// The edits, by identifier.
    pub(crate) fn edits(&self) -> &std::collections::BTreeMap<ObjectId, Edit> {
        &self.edits
    }

    /// The source's in-use objects (every generation a reconstruction kept), edits aside.
    fn source_ids(&self) -> Vec<ObjectId> {
        self.slots
            .iter()
            .chain(&self.others)
            .map(|slot| ObjectId::new(slot.num, slot.r#gen))
            .collect()
    }

    /// Whether the source has an object `id` in use (with its generation), edits aside.
    pub(crate) fn source_in_use(&self, id: ObjectId) -> bool {
        id.num != 0 && self.slot_of(id).is_some_and(|slot| slot.r#gen == id.r#gen)
    }

    /// The generation of the object of number `num` that the source's merged cross-reference
    /// data shows, if one is in use.
    pub(crate) fn source_generation(&self, num: u32) -> Option<u16> {
        self.slot(num).map(|slot| slot.r#gen)
    }

    /// Checks that `id` may be edited: an object in use ([`Store::check_in_use`]) that is not an
    /// object stream holding objects in use ([`Store::object_stream_members`]).
    fn check_editable(&self, id: ObjectId) -> Result<()> {
        self.check_in_use(id)?;
        let members = self.object_stream_members(id);
        let Some(first) = members.first() else {
            return Ok(());
        };
        let others = match members.len() - 1 {
            0 => String::new(),
            1 => " and 1 other object".to_owned(),
            n => format!(" and {n} other objects"),
        };
        Err(Error::invalid_argument(format!(
            "object {id} is the object stream (§7.5.7) that holds object {first}{others} in \
             use; it cannot be changed or freed until each of them has been replaced or freed, \
             since an incremental update would leave them unreadable"
        )))
    }

    /// Checks that `id` names an object in use (see [`Store::contains`]).
    fn check_in_use(&self, id: ObjectId) -> Result<()> {
        if id.num == 0 {
            return Err(Error::invalid_argument(
                "object 0 is the head of the free list and is never in use (§7.5.4)",
            ));
        }
        if self.contains(id) {
            return Ok(());
        }
        if matches!(self.edits.get(&id), Some(Edit::Free)) {
            return Err(Error::invalid_argument(format!("object {id} was freed")));
        }
        Err(Error::invalid_argument(match self.generation_of(id.num) {
            Some(r#gen) if r#gen != id.r#gen && self.in_use_generation(id.num).is_some() => {
                format!(
                    "object {id} is not in use: object number {} has generation {gen}",
                    id.num
                )
            }
            _ => format!("object {id} is not in use"),
        }))
    }

    /// The generation of an object in use under number `num`, if there is one.
    fn in_use_generation(&self, num: u32) -> Option<u16> {
        let range = ObjectId::new(num, 0)..=ObjectId::new(num, u16::MAX);
        let edited = self.edits.range(range).find_map(|(id, edit)| match edit {
            Edit::Set(_) => Some(id.r#gen),
            Edit::Free => None,
        });
        edited.or_else(|| {
            self.source_generation(num)
                .filter(|&r#gen| self.contains(ObjectId::new(num, r#gen)))
        })
    }
}

/// The object numbers of the references inside `value` (a stream's dictionary included),
/// walked iteratively.
fn referenced_numbers(value: &Object) -> Vec<u32> {
    let mut numbers = Vec::new();
    let mut stack: Vec<&Object> = vec![value];
    while let Some(obj) = stack.pop() {
        match obj {
            Object::Ref(id) => numbers.push(id.num),
            Object::Array(items) => stack.extend(items),
            Object::Dict(dict) => stack.extend(dict.values()),
            Object::Stream(stream) => stack.extend(stream.dict.values()),
            _ => {}
        }
    }
    numbers
}

#[cfg(test)]
mod tests;

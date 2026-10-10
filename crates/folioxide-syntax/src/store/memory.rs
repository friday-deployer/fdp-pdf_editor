//! What a store holds in memory, for hosts that tell a garbage collector about native memory
//! (the Node binding reports it to V8 with `napi_adjust_external_memory`, ARCHITECTURE §A.7):
//! a small JavaScript object that owns a large store would otherwise look cheap to collect.
//!
//! The estimate is kept up to date as the store works, so reading it costs `O(1)` (plus the
//! edits handed out by [`Store::get_mut`] since the last estimate, which are measured again):
//!
//! - each source object is weighed once, when its first load caches it in its slot;
//! - each edit is weighed when it is made, and again after [`Store::get_mut`] lent it out;
//! - the source bytes, the cross-reference index, the object stream cache and the scan of a
//!   repaired file are sized from their lengths.

use std::collections::{HashMap, HashSet};
use std::mem::size_of;
use std::sync::PoisonError;
use std::sync::atomic::Ordering;

use super::{Edit, Slot, Store, lock};
use crate::object::{Dict, Name, Object, ObjectId, Stream, StreamData};
use crate::xref::Revision;

/// What an edit costs besides its object: its entry in the edit map (the identifier, the
/// `Edit`, and about as much again of B-tree node overhead) and its weight record here.
const EDIT_ENTRY: u64 =
    (2 * (size_of::<ObjectId>() + size_of::<Edit>()) + size_of::<(ObjectId, u64)>() + 1) as u64;

/// What the edits weigh (see [`Store::memory_estimate`]).
#[derive(Debug, Default)]
pub(super) struct EditWeights {
    /// The sum of `by_id`.
    total: u64,
    /// What each edit weighed when it was last measured.
    by_id: HashMap<ObjectId, u64>,
    /// Edits lent out by [`Store::get_mut`] since they were last measured: the caller may have
    /// changed them, so the next estimate measures them again.
    lent: HashSet<ObjectId>,
}

impl EditWeights {
    /// Records that edit `id` weighs `weight` now.
    fn record(&mut self, id: ObjectId, weight: u64) {
        let old = self.by_id.insert(id, weight).unwrap_or(0);
        self.total = self.total.saturating_sub(old).saturating_add(weight);
    }

    /// The memory of this record itself.
    fn heap_size(&self) -> u64 {
        let by_id = self.by_id.capacity() * (size_of::<(ObjectId, u64)>() + 1);
        let lent = self.lent.capacity() * (size_of::<ObjectId>() + 1);
        (by_id + lent) as u64
    }
}

impl Store {
    /// An estimate of the heap memory the store holds, in bytes: the source bytes (shared with
    /// the caller when the store was opened from [`SharedBytes`](crate::SharedBytes) it keeps
    /// too), the cross-reference index (one slot per object in use), the objects parsed and
    /// cached so far, the decoded object streams in the cache, the scan of a file that needed
    /// one (a repaired or reconstructed file), and the edits.
    ///
    /// It grows as objects are read (opening reads the structure only; a full save reads
    /// everything) and with the edits, and it is cheap to call after every operation. It is an
    /// estimate: object sizes follow the layout of [`Object`] and its parts, allocator overhead
    /// is left out, and the short-lived memos of nested loads are not counted.
    ///
    /// ```
    /// use folioxide_syntax::{Object, OpenOptions, Store};
    ///
    /// let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n\
    /// 0000000000 65535 f\r\n0000000009 00000 n\r\ntrailer\n<< /Size 2 /Root 1 0 R >>\n\
    /// startxref\n45\n%%EOF\n";
    /// let mut store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default())?;
    /// let opened = store.memory_estimate();
    /// assert!(opened > pdf.len() as u64);
    /// let big = store.add(Object::literal_string(vec![b'x'; 1 << 20]))?;
    /// assert!(store.memory_estimate() > opened + (1 << 20));
    /// store.free(big)?;
    /// assert!(store.memory_estimate() < opened + 1024);
    /// # Ok::<(), folioxide_syntax::Error>(())
    /// ```
    pub fn memory_estimate(&self) -> u64 {
        let edits = {
            let mut weights = lock(&self.edit_weights);
            let lent: Vec<ObjectId> = weights.lent.drain().collect();
            for id in lent {
                weights.record(id, edit_weight(self.edits.get(&id)));
            }
            weights.total.saturating_add(weights.heap_size())
        };
        let index = (self.slots.capacity() + self.others.capacity()) * size_of::<Slot>()
            + (self.by_position.capacity() + self.by_container.capacity()) * size_of::<u32>()
            + self.section_starts.capacity() * size_of::<usize>();
        let revisions: u64 = self
            .revisions
            .iter()
            .map(|revision| size_of::<Revision>() as u64 + dict_heap_size(&revision.trailer))
            .sum();
        let repair = self
            .scan
            .get()
            .map_or(0, |scan| scan.heap_size())
            .saturating_add(self.definitions.get().map_or(0, |d| d.heap_size()));
        [
            self.bytes().len() as u64,
            size_of::<Store>() as u64,
            index as u64,
            revisions,
            dict_heap_size(&self.trailer),
            self.cached_bytes.load(Ordering::Relaxed),
            lock(&self.objstm_cache).resident,
            repair,
            edits,
        ]
        .into_iter()
        .fold(0, u64::saturating_add)
    }

    /// Weighs edit `id` as it stands (after it was set, added, freed, or first copied by
    /// [`Store::get_mut`]).
    pub(super) fn weigh_edit(&mut self, id: ObjectId) {
        let weight = edit_weight(self.edits.get(&id));
        self.edit_weights
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .record(id, weight);
    }

    /// Notes that [`Store::get_mut`] lent edit `id` out: the next estimate measures it again.
    pub(super) fn lend_edit(&mut self, id: ObjectId) {
        self.edit_weights
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .lent
            .insert(id);
    }
}

/// What an edit weighs: its entry, and the object it sets.
fn edit_weight(edit: Option<&Edit>) -> u64 {
    let object = match edit {
        Some(Edit::Set(object)) => heap_size(object),
        Some(Edit::Free) | None => 0,
    };
    EDIT_ENTRY.saturating_add(object)
}

/// An estimate of the heap memory `object` takes when it is shared (in an `Arc`, as the store
/// keeps objects): the object itself with the `Arc`'s counters, and everything it owns.
pub(crate) fn heap_size(object: &Object) -> u64 {
    ((size_of::<Object>() + 2 * size_of::<usize>()) as u64).saturating_add(owned_size(object))
}

/// The heap memory `object` owns, the object itself aside, walked iteratively (any depth is
/// fine). Stream data the source holds ([`StreamData::Source`]) is not counted again; data a
/// stream owns is.
fn owned_size(object: &Object) -> u64 {
    let mut total: u64 = 0;
    let mut stack: Vec<&Object> = vec![object];
    while let Some(obj) = stack.pop() {
        let own = match obj {
            Object::String(string) => string.bytes.capacity() as u64,
            Object::Name(name) => name.as_bytes().len() as u64,
            Object::Array(items) => {
                stack.extend(items);
                (items.capacity() * size_of::<Object>()) as u64
            }
            Object::Dict(dict) => {
                stack.extend(dict.values());
                dict_own_size(dict)
            }
            Object::Stream(stream) => {
                stack.extend(stream.dict.values());
                let data = match &stream.data {
                    StreamData::Source(_) => 0,
                    StreamData::Encoded(data) | StreamData::Decoded(data) => data.capacity(),
                };
                ((size_of::<Stream>() + data) as u64).saturating_add(dict_own_size(&stream.dict))
            }
            _ => 0,
        };
        total = total.saturating_add(own);
    }
    total
}

/// The heap memory a dictionary owns (a trailer).
fn dict_heap_size(dict: &Dict) -> u64 {
    dict.values()
        .map(owned_size)
        .fold(dict_own_size(dict), u64::saturating_add)
}

/// The heap memory of a dictionary's own parts, its values' contents aside: the boxed map, and
/// for each entry its key (with the key's bytes), its value, and the map's stored hash and index
/// slots.
fn dict_own_size(dict: &Dict) -> u64 {
    let entry = size_of::<Name>() + size_of::<Object>() + 3 * size_of::<usize>();
    let keys: usize = dict.keys().map(|key| key.as_bytes().len()).sum();
    (size_of::<indexmap::IndexMap<Name, Object>>() + dict.len() * entry + keys) as u64
}

#[cfg(test)]
mod tests;

//! The lazy, thread-safe object store (ARCHITECTURE §A.3, M1 brief WP1.3).
//!
//! [`Store::open`] reads only the file's structure: the `%PDF-` header, the cross-reference
//! sections and trailers (or, for a damaged file, a reconstruction from one scan of the file),
//! plus the catalog, to check that it is usable. Every other object is parsed on first use by
//! [`Store::resolve`] and cached (each slot is a
//! [`OnceLock`]), object streams are decoded when one of their objects is first resolved and
//! kept in a cache of bounded size ([`Limits::max_objstm_cache`]), and stream data is decoded on
//! request by [`Store::stream_data`]. Every method takes `&self`, and [`Store`] is
//! `Send + Sync`, so any number of threads can read one store concurrently.
//!
//! # Leniency
//!
//! With [`Strictness::Lenient`] (the default) every repair is recorded as a [`Diagnostic`]
//! ([`Store::diagnostics`]) and an object that cannot be read resolves to `null`. With
//! [`Strictness::Strict`] the same situations are errors. Limits ([`Limits`]) are enforced in
//! both modes and surface as [`ErrorCode::LimitExceeded`].
//!
//! # Offsets
//!
//! Offsets in a PDF file are relative to the `%PDF-` header; bytes before it (junk) shift them.
//! The store converts every offset to an absolute position in the source buffer at open time, so
//! [`StreamData::Source`] ranges of the objects it returns are absolute: `&source[range]` is the
//! stream's raw data. Diagnostics and errors carry absolute positions too, except for objects
//! inside object streams, which have no position in the file.
//!
//! # Hostile files
//!
//! Opening a file costs time and memory linear in the file size, and resolving every object of
//! it, and decoding every stream, costs time linear in the file size plus the decoded output,
//! however the file is arranged:
//!
//! - the cross-reference reader works within a budget proportional to the file size: the
//!   sections it reads (overlapping ones, unterminated trailers and every failed attempt
//!   included) may parse [`LimitKind::XrefBytes`] bytes (about four times the file's), and hold
//!   at most [`LimitKind::XrefEntries`] entries together (`max(2^20, 4 × file length)`), so a
//!   `/Prev` chain of highly compressed cross-reference streams costs no more than one stream
//!   that size; a cut chain is a diagnostic in lenient mode;
//! - at most [`LimitKind::ObjectCap`] objects are kept (`min(max_objects, max(4096, file
//!   length))`), and free entries take no memory at all (see [`Limits::max_objects`]), so a tiny
//!   file cannot make the store reserve gigabytes; one in-use object costs about 50 bytes;
//! - a reconstruction reads the headers of the object streams it finds without caching them, and
//!   decodes at most [`LimitKind::ReconstructDecoded`] bytes doing so (`max(16 MiB, 16 × file
//!   length)`); trailers found by the scan are parsed only up to the next object or trailer; the
//!   parses that tell object definitions from header-like text inside other objects never
//!   overlap: each starts after what the one before covered (an object that parsed) or read (one
//!   that did not, whose headers then count unparsed), so together they read the file about once
//!   (a literal string that never closes stops after a few kilobytes);
//! - object streams, whose decoded data can be a thousand times larger than the file, are
//!   bounded three ways: one container decodes to at most [`Limits::max_objstm_decoded`] bytes
//!   and lists at most [`LimitKind::ObjectCap`] members; the decoded containers kept in memory
//!   take at most [`Limits::max_objstm_cache`] bytes (the least recently used ones are dropped;
//!   when one is decoded again for one of its objects, all of its objects not loaded yet are
//!   loaded with it, so however the cache thrashes, a container is decoded only a few times for
//!   its own objects); and the objects parsed from them take at most
//!   [`LimitKind::ObjStmParsed`] bytes of memory over the life of the store (`max(64 MiB, 128 ×
//!   file length)`), so `[0 0 0 ...]` decoded from a few kilobytes cannot become gigabytes of
//!   objects;
//! - each uncompressed object is parsed only within its region, which ends where the next object
//!   or cross-reference section starts, so objects that overlap (headers placed inside another
//!   object's string, comment or stream data) cannot make every parse run on to the end of the
//!   file; members of object streams are bounded the same way;
//! - stream recovery finds `endstream` and `endobj` through a keyword index built by one scan;
//! - the objects and object streams that nested loads (indirect `/Length` values, containers)
//!   load privately are remembered when that is safe, so a shared one is loaded once;
//! - [`Limits::max_total_decoded`] counts each stream of the file once (see
//!   [`Store::total_decoded`]), so a long-lived store does not run out of budget by decoding the
//!   same content again, while a file with many decompression bombs still stops at the limit.
//!
//! # Repairs and signatures
//!
//! A lenient open can repair the cross-reference structure, and then what the store shows may
//! differ from what a reader that follows the file's own cross-reference data shows. Callers that
//! must know (signature verification, incremental updates) check [`Store::structure_repaired`],
//! [`Store::recovered_objects`] and [`Store::offset_base`], and read each revision's own entries
//! with [`Store::revision_entries`].
//!
//! # Edits
//!
//! Edits (M2) are layered on top of the lazy store, which never changes what it read from the
//! source: [`Store::set`], [`Store::get_mut`] (copy-on-write), [`Store::add`] and
//! [`Store::free`] record replaced, added and freed objects, and [`Store::set_trailer_entry`]
//! changes `/Root`, `/Info` or `/ID`. Every public read sees the edits first ([`Store::resolve`],
//! [`Store::deref`], and through them [`Store::stream_data`]'s `/Filter` and `/DecodeParms`
//! references); the store's own loads (indirect `/Length` values, object stream containers) read
//! the source only, so an edit never changes how the source is parsed. An `Arc` handed out before
//! an edit stays a snapshot. Edits take `&mut self`, so they need no locks and the guarantees
//! above (`Send + Sync`, no waits between slots, linear resolution) are unchanged. The writers
//! ([`crate::writer`]) save the result as a full rewrite or as an incremental update.
//!
//! # Encryption
//!
//! Decryption arrives in M5. Until then, a document whose trailer has `/Encrypt` fails to open
//! with [`ErrorCode::PasswordRequired`] (standard security handler) or
//! [`ErrorCode::Unsupported`] (any other handler).

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use crate::diag::{Diagnostic, DiagnosticKind, DiagnosticLog, DiagnosticSink, Strictness};
use crate::error::{Error, ErrorCode, Result};
use crate::filters::{DecodeLimits, Filter, FilterError, FilterParams, decode_chain};
use crate::limits::{LimitKind, Limits};
use crate::object::{Dict, Name, Object, ObjectId, Stream, StreamData, keys};
use crate::objstm::{ContainerSink, ObjStm, ObjStmHeader};
use crate::parser::{IndirectObject, KeywordIndex, ParseBudget, ParseCtx, parse_indirect_at};
use crate::repair::{self, Definitions, ScanIndex};
use crate::xref::{
    self, How, LOCAL_SEARCH, MAX_STARTXREF_FALLBACKS, Markers, XrefBudget, XrefChain,
    object_header_at,
};

pub use crate::xref::{OffsetBase, Revision, XrefEntry, XrefKind};

mod edit;
mod memory;

pub(crate) use edit::{COMPUTED_TRAILER_KEYS, Edit, next_generation};

/// The bytes of a PDF file, shared between the [`Store`] and its users.
///
/// Anything that derefs to bytes works: a `Vec<u8>`, a `Box<[u8]>`, a `&'static [u8]`, or (with
/// a file-mapping crate) a memory map. Build one with [`shared_bytes`].
pub type SharedBytes = Arc<dyn AsRef<[u8]> + Send + Sync>;

/// Wraps `bytes` as [`SharedBytes`].
///
/// ```
/// use folioxide_syntax::shared_bytes;
///
/// let source = shared_bytes(b"%PDF-1.7".to_vec());
/// assert_eq!((*source).as_ref(), b"%PDF-1.7");
/// ```
pub fn shared_bytes<B: AsRef<[u8]> + Send + Sync + 'static>(bytes: B) -> SharedBytes {
    Arc::new(bytes)
}

/// Options for [`Store::open`].
///
/// The struct is `#[non_exhaustive]` (a password field arrives with encryption in M5): start
/// from [`OpenOptions::default()`] and use the `with_*` setters.
///
/// ```
/// use folioxide_syntax::{Limits, OpenOptions, Strictness};
///
/// let options = OpenOptions::default()
///     .with_strictness(Strictness::Strict)
///     .with_limits(Limits::default().with_max_objects(1_000));
/// assert_eq!(options.limits.max_objects, 1_000);
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase", default)
)]
pub struct OpenOptions {
    /// Whether repairs are diagnostics (lenient, the default) or errors (strict).
    pub strictness: Strictness,
    /// Resource limits for this document.
    pub limits: Limits,
}

impl OpenOptions {
    /// The default options: lenient, with the default [`Limits`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`OpenOptions::strictness`].
    #[must_use]
    pub fn with_strictness(mut self, strictness: Strictness) -> Self {
        self.strictness = strictness;
        self
    }

    /// Sets [`OpenOptions::limits`].
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }
}

/// Decoded stream data, as returned by [`Store::stream_data`].
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StreamBytes {
    /// The data after every filter this layer decodes has been applied.
    pub data: Vec<u8>,
    /// The image filters that are still applied to `data` (DCT, JPX, JBIG2, CCITT and anything
    /// after them, in chain order); empty when `data` is fully decoded.
    pub remaining: Vec<Filter>,
    /// True when a filter stopped early (truncated or corrupt input) and `data` is partial.
    /// Lenient mode records a [`DiagnosticKind::FilterTruncated`] diagnostic; strict mode
    /// returns an error instead.
    pub truncated: bool,
}

impl StreamBytes {
    /// Whether no filter remains to be applied.
    pub fn is_fully_decoded(&self) -> bool {
        self.remaining.is_empty()
    }
}

/// An object reached through [`Store::deref`]: the input itself when it was a direct object,
/// or the shared object at the end of a reference chain.
///
/// It dereferences to [`Object`], so the accessors work directly:
///
/// ```
/// # use folioxide_syntax::{Object, Store};
/// # fn demo(store: &Store, value: &Object) -> folioxide_syntax::Result<()> {
/// let resolved = store.deref(value)?;
/// if let Some(dict) = resolved.as_dict() {
///     println!("{} entries", dict.len());
/// }
/// # Ok(()) }
/// ```
#[derive(Clone, Debug, PartialEq)]
pub enum Resolved<'a> {
    /// The input object, which was not a reference.
    Direct(&'a Object),
    /// The object at the end of the reference chain (`null` for a missing or free object).
    Indirect(Arc<Object>),
}

impl Resolved<'_> {
    /// The object as a shared pointer (clones a direct object).
    pub fn into_arc(self) -> Arc<Object> {
        match self {
            Resolved::Direct(obj) => Arc::new(obj.clone()),
            Resolved::Indirect(obj) => obj,
        }
    }

    /// The object, owned (clones unless this is the only reference to an indirect object).
    pub fn into_owned(self) -> Object {
        match self {
            Resolved::Direct(obj) => obj.clone(),
            Resolved::Indirect(obj) => Arc::unwrap_or_clone(obj),
        }
    }
}

impl Deref for Resolved<'_> {
    type Target = Object;

    fn deref(&self) -> &Object {
        match self {
            Resolved::Direct(obj) => obj,
            Resolved::Indirect(obj) => obj,
        }
    }
}

impl AsRef<Object> for Resolved<'_> {
    fn as_ref(&self) -> &Object {
        self
    }
}

/// Where the merged cross-reference data says an in-use object is. A free object has no slot:
/// like an object no section lists, it reads as `null`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Location {
    /// Uncompressed, at absolute position `pos` of the source.
    InFile { pos: u64 },
    /// Entry `index` of the object stream `stream`.
    InObjStm { stream: u32, index: u32 },
}

/// One in-use object of the merged cross-reference data. A slot is 48 bytes; the store keeps one
/// per in-use object and nothing per free entry.
struct Slot {
    num: u32,
    /// The generation of the entry (0 for compressed objects).
    r#gen: u16,
    /// Set when the object's location did not come from the cross-reference data as written
    /// (see [`Store::recovered_objects`]).
    recovered: AtomicBool,
    loc: Location,
    /// The parsed object, filled on first use. In lenient mode an unreadable object is stored
    /// as `null` (and reported once); in strict mode the error is stored (boxed, to keep the
    /// slot small).
    parsed: OnceLock<Loaded>,
}

/// What loading a slot produced, after the leniency policy (see [`Store::settle`]).
type Loaded = std::result::Result<Arc<Object>, Box<Error>>;

impl Slot {
    /// The slot for an in-use entry; `None` for a free one.
    fn new(num: u32, entry: XrefEntry) -> Option<Self> {
        let (r#gen, loc) = match entry {
            XrefEntry::Free { .. } => return None,
            XrefEntry::InFile { pos, r#gen } => (r#gen, Location::InFile { pos }),
            XrefEntry::InObjStm { stream, index } => (0, Location::InObjStm { stream, index }),
        };
        Some(Slot {
            num,
            r#gen,
            recovered: AtomicBool::new(false),
            loc,
            parsed: OnceLock::new(),
        })
    }
}

type ObjStmCell = OnceLock<std::result::Result<Arc<ObjStm>, Error>>;

/// The decoded object streams the store keeps, by container number, within
/// [`Limits::max_objstm_cache`] bytes: when a newly decoded container does not fit, the least
/// recently used ones are dropped (decoding one of them again for its own objects settles all
/// of them, see [`Store::settle_container`]). Entries exist only for numbers whose slot is an
/// uncompressed object, so the map is bounded by the cross-reference data; a container that
/// could not be decoded is kept as its (small) error and never dropped.
#[derive(Default)]
struct ObjStmCache {
    entries: HashMap<u32, CacheEntry>,
    /// The entries that hold a decoded container, by last use (tick → container number).
    lru: BTreeMap<u64, u32>,
    tick: u64,
    /// The weight ([`ObjStm::weight`]) of the entries in `lru`.
    resident: u64,
    /// Containers dropped from the cache since they were last decoded.
    evicted: HashSet<u32>,
}

struct CacheEntry {
    cell: Arc<ObjStmCell>,
    /// The container's weight and its tick in the LRU order, once it is accounted.
    used: Option<(u64, u64)>,
    /// Filled by a nested load's private, quiet decode (which reported no diagnostics). A
    /// blocking load replaces it with its own decode, which reports them.
    quiet: bool,
}

impl ObjStmCache {
    /// The cell for container `num` for a blocking load: the cached one, or a new empty one
    /// (which also replaces a quiet entry).
    fn cell(&mut self, num: u32) -> Arc<ObjStmCell> {
        if self.entries.get(&num).is_some_and(|e| e.quiet) {
            self.remove(num);
        }
        let entry = self.entries.entry(num).or_insert_with(|| CacheEntry {
            cell: Arc::default(),
            used: None,
            quiet: false,
        });
        let cell = Arc::clone(&entry.cell);
        self.touch(num);
        cell
    }

    /// The decoded container `num`, if the cache holds it (for nested loads, which never wait).
    fn filled(&mut self, num: u32) -> Option<Result<Arc<ObjStm>>> {
        let done = self.entries.get(&num)?.cell.get()?.clone();
        self.touch(num);
        Some(done)
    }

    /// Marks entry `num` as the most recently used.
    fn touch(&mut self, num: u32) {
        let ObjStmCache {
            entries, lru, tick, ..
        } = self;
        if let Some(entry) = entries.get_mut(&num)
            && let Some((weight, old)) = entry.used
        {
            *tick += 1;
            lru.remove(&old);
            lru.insert(*tick, num);
            entry.used = Some((weight, *tick));
        }
    }

    /// Accounts the container a blocking load just stored in `cell` (the entry for `num`), and
    /// drops the least recently used others until the cache fits `budget`.
    fn account(&mut self, num: u32, cell: &Arc<ObjStmCell>, budget: u64) {
        let ObjStmCache {
            entries,
            lru,
            tick,
            resident,
            evicted,
        } = self;
        let Some(entry) = entries.get_mut(&num) else {
            return;
        };
        if !Arc::ptr_eq(&entry.cell, cell) || entry.used.is_some() {
            return;
        }
        // An error weighs nothing and stays.
        let Some(Ok(stm)) = entry.cell.get() else {
            return;
        };
        let weight = stm.weight();
        *tick += 1;
        entry.used = Some((weight, *tick));
        lru.insert(*tick, num);
        *resident = resident.saturating_add(weight);
        evicted.remove(&num);
        self.evict(num, budget);
    }

    /// Caches a container a nested load decoded privately, unless the cache has an entry for
    /// `num` already (filled, or being filled by a blocking load).
    fn insert_quiet(&mut self, num: u32, decoded: Result<Arc<ObjStm>>, budget: u64) {
        if self.entries.contains_key(&num) {
            return;
        }
        let cell = Arc::new(OnceLock::from(decoded));
        self.entries.insert(
            num,
            CacheEntry {
                cell: Arc::clone(&cell),
                used: None,
                quiet: true,
            },
        );
        self.account(num, &cell, budget);
    }

    /// Drops the least recently used containers, never `keep` (the newest), until the cache
    /// fits `budget`.
    fn evict(&mut self, keep: u32, budget: u64) {
        while self.resident > budget {
            let Some((_, &num)) = self.lru.first_key_value() else {
                break;
            };
            if num == keep {
                break;
            }
            self.remove(num);
            self.evicted.insert(num);
        }
    }

    /// Removes entry `num` and its weight.
    fn remove(&mut self, num: u32) {
        if let Some(entry) = self.entries.remove(&num)
            && let Some((weight, tick)) = entry.used
        {
            self.lru.remove(&tick);
            self.resident = self.resident.saturating_sub(weight);
        }
    }

    /// Whether container `num` was dropped since it was last decoded.
    fn was_evicted(&self, num: u32) -> bool {
        self.evicted.contains(&num)
    }
}

/// Where [`Store::header_near`] found an object's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeaderAt {
    /// At the entry's position; the header has generation `gen`.
    Exact { r#gen: u16 },
    /// At the entry's position taken as absolute (counted from byte 0, not the header).
    Absolute,
    /// Within ±64 bytes of the entry's position.
    Nearby,
}

/// How a decode of a source stream counts against [`Limits::max_total_decoded`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Charge {
    /// Each stream once, with the most bytes any decode of it produced (see
    /// [`Store::total_decoded`]).
    Once,
    /// In full, again: the store decodes an object stream it dropped from its cache to follow
    /// another one's `/Extends` (see [`Store::objstm_charge`]).
    Again,
}

/// Forwards the diagnostics of one object's parse (unless `quiet`) and notes whether any of
/// them is a repair that other readers may resolve differently (see
/// [`Store::recovered_objects`]).
struct RepairWatch<'s> {
    inner: &'s dyn DiagnosticSink,
    quiet: bool,
    hit: Cell<bool>,
}

impl DiagnosticSink for RepairWatch<'_> {
    fn report(&self, diagnostic: Diagnostic) {
        if matches!(
            diagnostic.kind,
            DiagnosticKind::StreamLength
                | DiagnosticKind::MissingEndstream
                | DiagnosticKind::MissingEndobj
                | DiagnosticKind::StreamKeywordEol
        ) {
            self.hit.set(true);
        }
        if !self.quiet {
            self.inner.report(diagnostic);
        }
    }
}

/// The chain of objects whose loading is in progress on the current call path.
///
/// Loading an object can require another one: the value of an indirect `/Length`, an object
/// stream container, a `/Filter` given by reference. Those nested loads never wait on a slot's
/// [`OnceLock`] (another thread may be filling it, or this very call path); they use a filled
/// slot or cached container if there is one, then the peek memo (see [`Store::peek_deref`]),
/// and otherwise load a private copy. The chain detects cycles on the call path (`5 0 obj << /Length 5 0 R >>`) and
/// bounds the nesting by [`Limits::max_ref_chain`] (and [`MAX_NESTED_LOADS`], to protect the
/// call stack).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Chain<'c> {
    num: Option<u32>,
    depth: u16,
    parent: Option<&'c Chain<'c>>,
    /// Set when a nested load below this link was refused because of the call path itself (a
    /// cycle, or the nesting bound). What the private load of this link produced then depends on
    /// the call path, so it must not go into the peek memo (or the object-stream cache).
    refused: Option<&'c Cell<bool>>,
}

impl<'c> Chain<'c> {
    /// The empty chain.
    pub(crate) const EMPTY: Chain<'static> = Chain {
        num: None,
        depth: 0,
        parent: None,
        refused: None,
    };

    fn root(num: u32) -> Chain<'static> {
        Chain {
            num: Some(num),
            depth: 1,
            parent: None,
            refused: None,
        }
    }

    fn contains(&self, num: u32) -> bool {
        let mut link = Some(self);
        while let Some(chain) = link {
            if chain.num == Some(num) {
                return true;
            }
            link = chain.parent;
        }
        false
    }

    /// The chain extended by `num`, whose refusals are recorded in `refused`.
    fn push(&'c self, num: u32, refused: &'c Cell<bool>) -> Chain<'c> {
        Chain {
            num: Some(num),
            depth: self.depth.saturating_add(1),
            parent: Some(self),
            refused: Some(refused),
        }
    }

    /// Records that a load was refused because of this call path.
    fn refuse(&self) {
        if let Some(refused) = self.refused {
            refused.set(true);
        }
    }

    /// Whether loading `num` must be refused on this call path: a cycle or the nesting bound
    /// (`max`). A refusal is recorded (see [`Chain::refuse`]).
    fn refuses(&self, num: u32, max: u16) -> bool {
        let refused = self.contains(num) || self.depth >= max;
        if refused {
            self.refuse();
        }
        refused
    }
}

/// How far from the end of the file qpdf looks for the last `startxref`: 1024 bytes for the
/// `%%EOF` marker, plus 30 for `startxref` and its value. When the last `startxref` starts
/// further back and an object header follows it, qpdf rebuilds the file from a scan (see
/// [`Store::unreferenced_update`]; measured with qpdf 12.4).
const STARTXREF_WINDOW: usize = 1054;

/// How many objects after an object's own position [`Store::region_end`] checks before it falls
/// back to the scan of the file. Each check is `O(1)`.
const REGION_CANDIDATES: usize = 8;

/// A hard bound on nested loads (see [`Chain`]), whatever [`Limits::max_ref_chain`] says: each
/// level can be a full object parse on the call stack. Legitimate files need two or three levels
/// (a stream, its indirect `/Length`, the integer); 16 levels fit in a 128 KiB stack even in debug
/// builds.
const MAX_NESTED_LOADS: u16 = 16;

/// How a load may obtain the objects it depends on.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Mode<'c> {
    /// Through the caches, waiting for other threads (public entry points only).
    Blocking,
    /// Without ever waiting on a cache: use filled entries, otherwise parse privately.
    Peek(&'c Chain<'c>),
}

/// The lazy object store of one PDF file.
///
/// ```
/// use folioxide_syntax::{OpenOptions, Store};
///
/// let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n\
/// 0000000000 65535 f\r\n0000000009 00000 n\r\ntrailer\n<< /Size 2 /Root 1 0 R >>\n\
/// startxref\n45\n%%EOF\n";
/// let store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default())?;
/// let root = store.trailer().get_ref(b"Root").unwrap();
/// assert!(store.resolve(root)?.as_dict().unwrap().is_type(b"Catalog"));
/// assert!(store.diagnostics().is_empty());
/// # Ok::<(), folioxide_syntax::Error>(())
/// ```
pub struct Store {
    source: SharedBytes,
    options: OpenOptions,
    header_offset: u64,
    version: (u8, u8),
    revisions: Vec<Revision>,
    trailer: Dict,
    /// The in-use objects, sorted by object number: one per number, the one the merged
    /// cross-reference data shows.
    slots: Vec<Slot>,
    /// Further generations of numbers in `slots`, sorted by number and generation: objects a
    /// reconstruction found besides the newest definition of their number. `5 0 obj` and
    /// `5 1 obj` are different objects (§7.3.10), and qpdf keeps both, so a reference resolves
    /// to the definition with its own generation. Empty for a file read through its
    /// cross-reference data.
    others: Vec<Slot>,
    /// The largest object number the cross-reference data lists, free entries included.
    max_object_number: u32,
    /// Which position the file's offsets count from.
    offset_base: OffsetBase,
    /// Set when opening repaired the cross-reference structure (see
    /// [`Store::structure_repaired`]).
    structure_repaired: AtomicBool,
    /// Indices ([`Store::slot_at`]: `slots`, then `others`) of the uncompressed objects inside
    /// the source, sorted by position: an object's region ends where the next one starts (see
    /// [`Store::region_end`]).
    by_position: Vec<u32>,
    /// Indices ([`Store::slot_at`]) of the compressed objects, sorted by object stream and
    /// index: the objects of one container (see [`Store::settle_container`]).
    by_container: Vec<u32>,
    /// Absolute positions of the cross-reference sections that were read, ascending; they end
    /// the regions of the objects before them too.
    section_starts: Vec<usize>,
    /// Decoded object streams, within [`Limits::max_objstm_cache`] bytes (see [`ObjStmCache`]).
    /// Nested loads put the containers they decode privately here too (see
    /// [`Store::peek_objstm`]).
    objstm_cache: Mutex<ObjStmCache>,
    /// Objects loaded privately by nested loads (see [`Store::peek_deref`]) whose result does not
    /// depend on the call path; `None` when the load failed. Bounded by the slots (and, for
    /// objects inside object streams, by [`LimitKind::ObjStmParsed`]).
    peeked_objects: Mutex<HashMap<ObjectId, Option<Arc<Object>>>>,
    /// Compressed objects that a blocking load settled with its container (see
    /// [`Store::settle_container`]), by number, waiting for their slot's first load to take
    /// them: settling never waits on another slot. Bounded by the slots (and by
    /// [`LimitKind::ObjStmParsed`]).
    settled: Mutex<HashMap<u32, Loaded>>,
    /// The memory of the objects parsed from object streams so far, as estimated by
    /// [`ParseBudget`]: at most [`LimitKind::ObjStmParsed`].
    objstm_parsed: AtomicU64,
    /// The scan of the whole file, built at most once (reconstruction, wrong offsets, wrong
    /// stream lengths).
    scan: OnceLock<ScanIndex>,
    /// The object definitions among the scan's headers, derived at most once (reconstruction,
    /// wrong offsets, comparing a chain with what a reconstruction shows).
    definitions: OnceLock<Definitions>,
    diagnostics: DiagnosticLog,
    /// Decoded bytes charged against `max_total_decoded` (see [`Store::total_decoded`]).
    total_decoded: AtomicU64,
    /// The bytes charged per stream of the source, by its data range: a stream decoded again is
    /// charged only for output beyond its earlier decodes. Bounded by the streams in the file.
    charged: Mutex<HashMap<(u64, u64), u64>>,
    /// The decoded bytes a reconstruction may still spend reading object stream headers.
    reconstruct_budget: AtomicU64,
    /// Objects parsed so far (for laziness tests).
    parsed_objects: AtomicUsize,
    /// The estimated heap memory of the objects the slots cache (see
    /// [`Store::memory_estimate`]): each slot's object is charged once, when its first load
    /// stores it.
    cached_bytes: AtomicU64,
    /// The estimated heap memory of the edits (see [`Store::memory_estimate`]).
    edit_weights: Mutex<memory::EditWeights>,
    /// Object streams decoded so far for their objects (for cache tests).
    #[cfg(test)]
    objstm_decodes: AtomicUsize,
    /// The bytes of the regions uncompressed objects were parsed within so far (for linearity
    /// tests: a parse reads at most its region, stream data aside).
    #[cfg(test)]
    region_bytes: AtomicU64,
    null: Arc<Object>,
    /// The edits (M2): replaced and added objects, and freed ones, by identifier. Every public
    /// read looks here first; the writers save them (see [`Edit`]).
    edits: BTreeMap<ObjectId, Edit>,
    /// The number [`Store::add`] gives the next new object: one more than any number the source
    /// lists or an edit added, so numbers are never reused.
    next_num: u32,
    /// One more than the largest object number (below [`Limits::max_objects`]) that the source's
    /// objects and trailers refer to, found by one walk over the source on first need (see
    /// [`Store::next_object_number`]): a new object never takes the number of a dangling
    /// reference.
    referenced_floor: OnceLock<u32>,
    /// Set when [`Store::set_trailer_entry`] or [`Store::remove_trailer_entry`] changed the
    /// trailer.
    trailer_edited: bool,
    /// Whether the store was opened from a file (false for [`Store::new_empty`]).
    has_source: bool,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("len", &self.bytes().len())
            .field("header_offset", &self.header_offset)
            .field("version", &self.version)
            .field("revisions", &self.revisions.len())
            .field("slots", &self.slots.len())
            .field("others", &self.others.len())
            .field("edits", &self.edits.len())
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

/// Makes the lazily built scan available to the parser as its [`KeywordIndex`].
struct LazyKeywords<'s>(&'s Store);

impl KeywordIndex for LazyKeywords<'_> {
    fn next_endstream(&self, from: usize) -> Option<usize> {
        self.0.scan_index().next_endstream(from)
    }

    fn next_endobj(&self, from: usize) -> Option<usize> {
        self.0.scan_index().next_endobj(from)
    }
}

impl Store {
    // ---- opening ------------------------------------------------------------------------------

    /// Opens a PDF file: reads its header, cross-reference data and trailer, and checks that
    /// the trailer's `/Root` is a dictionary (the only object parsed; it stays cached).
    ///
    /// A damaged file is repaired where possible (see the module documentation), with a
    /// [`Diagnostic`] for every repair in lenient mode.
    ///
    /// # Errors
    /// - [`ErrorCode::PasswordRequired`] / [`ErrorCode::Unsupported`]: the document is
    ///   encrypted (standard / other security handler); encryption arrives in M5.
    /// - [`ErrorCode::Xref`]: no document catalog could be found, even by a full scan; in strict
    ///   mode also any damaged cross-reference data or an unreadable catalog.
    /// - [`ErrorCode::Syntax`]: in strict mode, a missing `%PDF-` header.
    /// - [`ErrorCode::LimitExceeded`]: a [`Limits`] value was exceeded.
    pub fn open(source: SharedBytes, options: &OpenOptions) -> Result<Store> {
        let mut store = Store::blank(source, options);
        store.has_source = true;
        store.read_structure()?;
        store.next_num = store.max_object_number.saturating_add(1);
        Ok(store)
    }

    /// A store over `source` with nothing read yet: no revisions, no objects, no edits.
    fn blank(source: SharedBytes, options: &OpenOptions) -> Store {
        let len = (*source).as_ref().len();
        Store {
            source,
            options: options.clone(),
            header_offset: 0,
            version: (1, 4),
            revisions: Vec::new(),
            trailer: Dict::new(),
            slots: Vec::new(),
            others: Vec::new(),
            max_object_number: 0,
            offset_base: OffsetBase::HeaderRelative,
            structure_repaired: AtomicBool::new(false),
            by_position: Vec::new(),
            by_container: Vec::new(),
            section_starts: Vec::new(),
            objstm_cache: Mutex::new(ObjStmCache::default()),
            peeked_objects: Mutex::new(HashMap::new()),
            settled: Mutex::new(HashMap::new()),
            objstm_parsed: AtomicU64::new(0),
            scan: OnceLock::new(),
            definitions: OnceLock::new(),
            diagnostics: DiagnosticLog::with_limits(&options.limits),
            total_decoded: AtomicU64::new(0),
            charged: Mutex::new(HashMap::new()),
            reconstruct_budget: AtomicU64::new(repair::reconstruct_budget(&options.limits, len)),
            parsed_objects: AtomicUsize::new(0),
            cached_bytes: AtomicU64::new(0),
            edit_weights: Mutex::new(memory::EditWeights::default()),
            #[cfg(test)]
            objstm_decodes: AtomicUsize::new(0),
            #[cfg(test)]
            region_bytes: AtomicU64::new(0),
            null: Arc::new(Object::Null),
            edits: BTreeMap::new(),
            next_num: 1,
            referenced_floor: OnceLock::new(),
            trailer_edited: false,
            has_source: false,
        }
    }

    /// Opens a PDF file held in a vector; see [`Store::open`].
    ///
    /// # Errors
    /// See [`Store::open`].
    pub fn open_bytes(bytes: Vec<u8>, options: &OpenOptions) -> Result<Store> {
        Self::open(shared_bytes(bytes), options)
    }

    fn read_structure(&mut self) -> Result<()> {
        let source = Arc::clone(&self.source);
        let bytes: &[u8] = (*source).as_ref();

        // §7.5.2 and Annex H: the header, and the offset base.
        match xref::find_header(bytes) {
            Some(header) => {
                self.header_offset = header.offset as u64;
                if header.offset > 0 {
                    self.recover(
                        ErrorCode::Syntax,
                        DiagnosticKind::HeaderOffset,
                        Some(0),
                        || {
                            format!(
                                "{} bytes before the %PDF- header; offsets are relative to it",
                                header.offset
                            )
                        },
                    )?;
                }
                match header.version {
                    Some(version) => self.version = version,
                    None => self.recover(
                        ErrorCode::Syntax,
                        DiagnosticKind::MalformedHeader,
                        Some(header.offset as u64),
                        || "malformed version in the %PDF- header; assuming 1.4".to_owned(),
                    )?,
                }
            }
            None => self.recover(
                ErrorCode::Syntax,
                DiagnosticKind::MissingHeader,
                None,
                || "no %PDF- header; assuming version 1.4 and offsets from byte 0".to_owned(),
            )?,
        }

        // §7.5.5: startxref → the newest section → /Prev → ...
        let mut budget = XrefBudget::for_len(self.limits(), bytes.len());
        let max_markers = usize::try_from(self.limits().max_xref_sections)
            .unwrap_or(usize::MAX)
            .saturating_add(16)
            .min(1 << 16);
        let mut markers = Markers::new(bytes, max_markers);
        let newest = match self.read_chain_from_markers(&mut budget, &mut markers)? {
            Some((chain, damaged)) => Some(self.install_chain(chain, damaged)?),
            None => {
                self.recover_structure(false, DiagnosticKind::XrefReconstructed, None, || {
                    "no usable cross-reference data (startxref missing or wrong); objects were \
                     found by scanning the file"
                        .to_owned()
                })?;
                let rebuilt = repair::reconstruct_entries(self);
                let entries: Vec<(u32, XrefEntry)> = rebuilt.entries.into_iter().collect();
                self.install_checked(&entries, &rebuilt.others)?;
                // Every location came from the scan.
                for slot in self.slots.iter().chain(&self.others) {
                    slot.recovered.store(true, Ordering::Relaxed);
                }
                self.max_object_number = self.slots.last().map_or(0, |s| s.num);
                let trailer = repair::find_trailer(self).unwrap_or_default();
                self.revisions = vec![Revision {
                    startxref: markers.last().and_then(|m| m.value).unwrap_or(0),
                    eof_end: bytes.len() as u64,
                    section_end: bytes.len() as u64,
                    xref_stm: None,
                    xref_kind: XrefKind::Reconstructed,
                    trailer: trailer.clone(),
                }];
                self.trailer = trailer;
                None
            }
        };
        self.ensure_root()?;
        // Before the catalog is parsed: in an encrypted file it may sit in an (encrypted)
        // object stream that cannot be decoded yet.
        self.check_encryption()?;
        self.verify_root()?;
        self.offset_base = self.detect_offset_base(newest);
        Ok(())
    }

    /// Reads the cross-reference chain from the last `startxref` in the file.
    ///
    /// Data of an incremental update after the revisions that chain leads to (an update that no
    /// `startxref` leads to) is reported, and makes the file reconstructed when qpdf would
    /// reconstruct it (see [`Store::unreferenced_update`]).
    ///
    /// qpdf, pdf.js and poppler rebuild a file from a scan when its last `startxref` does not
    /// lead to a cross-reference section at its offset, and the last definition of each object
    /// (by position) wins. The store is more forgiving, but uses a chain such a file leads it
    /// to only when the chain shows what that reconstruction shows
    /// ([`Store::differs_from_reconstruction`]), and reconstructs the file otherwise (`None`).
    /// The flag returned with the chain says that it stands in for such a reconstruction:
    ///
    /// - when the section is found near the offset, or at the offset counted from byte 0
    ///   (concatenated files, where the last `startxref` counts from the start of the second
    ///   one, lead near a section of the first one);
    /// - in lenient mode, when the last `startxref` leads to no section at all (trailing junk
    ///   with a bogus `startxref`, say): the earlier `startxref` values are tried, newest first,
    ///   before the file is reconstructed, which keeps the revision structure of a file that is
    ///   fine apart from its tail.
    fn read_chain_from_markers(
        &self,
        budget: &mut XrefBudget,
        markers: &mut Markers<'_>,
    ) -> Result<Option<(XrefChain, bool)>> {
        let Some(last) = markers.last() else {
            return Ok(None);
        };
        if let Some(value) = last.value
            && let Some(chain) = xref::read_chain(self, value, budget, markers)?
        {
            let damaged = chain.newest != How::Exact && !self.is_strict();
            if damaged {
                let context = || {
                    format!(
                        "the last startxref (byte {}) does not lead to a cross-reference section \
                         at its offset, and the revisions read from the section found instead",
                        last.at
                    )
                };
                if self.differs_from_reconstruction(&chain, &context)? {
                    return Ok(None);
                }
            }
            return Ok((!self.unreferenced_update(&chain, last)?).then_some((chain, damaged)));
        }
        if self.is_strict() {
            return Ok(None);
        }
        let mut tried: Vec<u64> = last.value.into_iter().collect();
        let earlier: Vec<xref::Marker> = markers
            .all()
            .iter()
            .rev()
            .filter(|m| m.at < last.at)
            .copied()
            .collect();
        let mut attempts = 0;
        for marker in earlier {
            let Some(value) = marker.value.filter(|v| !tried.contains(v)) else {
                continue;
            };
            if attempts >= MAX_STARTXREF_FALLBACKS || budget.is_exhausted() {
                break;
            }
            attempts += 1;
            tried.push(value);
            let Some(chain) = xref::read_chain(self, value, budget, markers)? else {
                continue;
            };
            let context = || {
                format!(
                    "the last startxref (byte {}) leads to no cross-reference section, and the \
                     revisions that the startxref at byte {} leads to",
                    last.at, marker.at
                )
            };
            if self.differs_from_reconstruction(&chain, &context)? {
                return Ok(None);
            }
            self.recover_structure(
                false,
                DiagnosticKind::XrefMalformed,
                Some(last.at as u64),
                || {
                    format!(
                        "the last startxref (byte {}) leads to no cross-reference section; the \
                         startxref at byte {} was used",
                        last.at, marker.at
                    )
                },
            )?;
            return Ok(Some((chain, true)));
        }
        Ok(None)
    }

    /// Whether reading the file through `chain`, which a damaged structure led to, shows
    /// something else than the reconstruction that qpdf, pdf.js and poppler make of such a file
    /// (the last definition of each object by position wins). It does when anything but junk
    /// follows the chain's revisions (object headers or a `trailer` at the start of a line: an
    /// update whose own `startxref` is the damaged one, or a second file appended to the first),
    /// or when, before that tail, a definition is not where the chain resolves it
    /// ([`Store::shadowed_definition`]). The reason is reported as a repair; `context` says how
    /// the chain was found ("… the revisions that … leads to").
    fn differs_from_reconstruction(
        &self,
        chain: &XrefChain,
        context: &dyn Fn() -> String,
    ) -> Result<bool> {
        let tail = chain.revisions.iter().map(|r| r.eof_end).max().unwrap_or(0);
        if let Some(newer) = self.newer_data_after(tail) {
            self.recover_structure(
                false,
                DiagnosticKind::UnreferencedUpdate,
                Some(newer as u64),
                || {
                    format!(
                        "{} end at byte {tail}, before more objects or a trailer (byte {newer}); \
                         the file is reconstructed so that its newest data is used",
                        context()
                    )
                },
            )?;
            return Ok(true);
        }
        if let Some((num, at)) = self.shadowed_definition(chain) {
            self.recover_structure(
                false,
                DiagnosticKind::XrefMalformed,
                Some(at as u64),
                || {
                    format!(
                        "{} do not show object {num} as it is defined last (byte {at}); the file \
                         is reconstructed so that its newest definitions are used",
                        context()
                    )
                },
            )?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Reports data of an incremental update (object headers, `xref` or `trailer`, each at the
    /// start of a line) after the revisions of `chain`, which the last `startxref` (`last`) leads
    /// to: an update that no `startxref` leads to (§7.5.6), such as a save that stopped before
    /// writing its `startxref`, or content appended after a signed revision. Other readers may
    /// show it, so it is a [`DiagnosticKind::UnreferencedUpdate`] repair
    /// ([`Store::structure_repaired`]; an error in strict mode).
    ///
    /// Returns whether the file must be reconstructed instead of read through `chain`, which
    /// matches qpdf 12: it looks for the last `startxref` only in the last [`STARTXREF_WINDOW`]
    /// bytes of the file. When it is there, qpdf reads the chain and ignores the update (as do
    /// poppler and pypdf, whatever the distance). When it is not, qpdf scans the file, and still
    /// reads the chain when the last `startxref` comes after the last object header (warning
    /// that `startxref` was more than 1024 bytes before the end of the file); only when an object
    /// header follows the last `startxref` does it rebuild the file, where the newest
    /// definitions win.
    fn unreferenced_update(&self, chain: &XrefChain, last: xref::Marker) -> Result<bool> {
        let bytes = self.bytes();
        let tail = chain.revisions.iter().map(|r| r.eof_end).max().unwrap_or(0);
        let Some(update) = usize::try_from(tail)
            .ok()
            .and_then(|tail| repair::update_after(bytes, tail))
        else {
            return Ok(false);
        };
        let distance = bytes.len().saturating_sub(last.at);
        let reconstruct = distance > STARTXREF_WINDOW
            && repair::update_after(bytes, last.at).is_some_and(|after| after.header.is_some());
        let lenient = !self.is_strict();
        self.recover_structure(
            false,
            DiagnosticKind::UnreferencedUpdate,
            Some(update.first as u64),
            || {
                let what = if update.header.is_some() {
                    "objects"
                } else {
                    "an xref table or trailer"
                };
                let found = format!(
                    "{what} at byte {} follow the last revision, which ends at byte {tail}, and \
                     no startxref leads to them (an incremental update cut short, or data \
                     appended outside any revision)",
                    update.first
                );
                // Strict mode refuses the file: what lenient mode does is no part of the story.
                match (lenient, reconstruct) {
                    (false, _) => found,
                    (true, true) => format!(
                        "{found}; the last startxref is {distance} bytes before the end of the \
                         file, too far for readers that look for it near the end, and object \
                         headers follow it, so the file is reconstructed so that its newest data \
                         is used"
                    ),
                    (true, false) => {
                        format!("{found}; ignored, as readers that follow the last startxref do")
                    }
                }
            },
        )?;
        Ok(reconstruct)
    }

    /// The position of the first object definition (see [`repair::definitions`]) or `trailer`
    /// keyword at the start of a line, at or after `pos` (builds the scan).
    fn newer_data_after(&self, pos: u64) -> Option<usize> {
        let pos = usize::try_from(pos).ok()?;
        let header = self.definitions().next_at_or_after(pos);
        let trailer = self.scan_index().next_line_trailer(self.bytes(), pos);
        header.into_iter().chain(trailer).min()
    }

    /// Compares a cross-reference chain with the object definitions the scan of the file finds
    /// (built if needed; see [`repair::definitions`]: headers at the start of a line, outside
    /// every object that parses, by number and generation). Returns the lowest object number,
    /// and the position of its definition, that the chain does not resolve the way a
    /// reconstruction does (where the last definition by position wins, as in qpdf, pdf.js and
    /// poppler):
    ///
    /// - an in-file entry `N G` whose object the store would find elsewhere than at the
    ///   definition of `N G` (an orphan `N G obj` after the one the table lists, say). A
    ///   definition of another generation of `N` is another object (§7.3.10) and shadows
    ///   nothing;
    /// - a compressed entry `N` (generation 0, §7.5.7), when `N 0 obj` is defined, uncompressed,
    ///   after its object stream (or the object stream is not an uncompressed object of the
    ///   chain);
    /// - a free entry, when a definition of the number (any generation) comes after the section
    ///   that frees it (a deletion before the definition; a definition before it stays deleted,
    ///   as the revisions say, although a reconstruction would show it again if something still
    ///   referenced it, ARCHITECTURE §A.10 trap #14);
    /// - a number no section lists, defined anywhere.
    ///
    /// Header-like text in a comment, in the middle of a line, or inside another object's
    /// string, dictionary or stream data is no definition, so it never makes a valid chain
    /// reconstructed. Headers that start a cross-reference stream the chain read are not
    /// definitions to compare (a stream need not list itself). The scan does not decode object
    /// streams, so a member added to a later object stream than the one the entry names is not
    /// seen here.
    fn shadowed_definition(&self, chain: &XrefChain) -> Option<(u32, usize)> {
        let defs = self.definitions();
        let is_section = |pos: usize| chain.section_starts.binary_search(&pos).is_ok();
        let entry = |num: u32| {
            chain
                .entries
                .binary_search_by_key(&num, |&(n, _)| n)
                .ok()
                .and_then(|i| chain.entries.get(i))
                .map(|&(_, entry)| entry)
        };
        // Where the store finds an in-file entry's object (the scan's definition when only the
        // scan can find it, see `locate`).
        let found_at = |id: ObjectId, pos: u64| {
            self.header_near(id, pos)
                .map(|(at, _)| at)
                .or_else(|| defs.find(id).map(|found| found.pos))
        };
        let mut lowest: Option<(u32, usize)> = None;
        let mut note = |num: u32, at: usize| {
            if lowest.is_none_or(|(n, _)| num < n) {
                lowest = Some((num, at));
            }
        };
        for (id, found) in defs.iter() {
            let num = id.num;
            if num == 0 || is_section(found.pos) {
                continue;
            }
            let differs = match entry(num) {
                Some(XrefEntry::InFile { pos, r#gen }) => {
                    r#gen == id.r#gen && found_at(id, pos).is_some_and(|at| at != found.pos)
                }
                Some(XrefEntry::InObjStm { stream, .. }) => {
                    id.r#gen == 0
                        && match entry(stream) {
                            Some(XrefEntry::InFile { pos, r#gen }) => {
                                found_at(ObjectId::new(stream, r#gen), pos)
                                    .is_none_or(|at| found.pos > at)
                            }
                            _ => true,
                        }
                }
                // Free entries are compared below; a number no section lists is not in the
                // revisions at all.
                Some(XrefEntry::Free { .. }) | None => !chain.listed.contains(&num),
            };
            if differs {
                note(num, found.pos);
            }
        }
        for (section, nums) in &chain.freed {
            for &num in nums {
                if let Some(found) = defs.newest(num)
                    && num != 0
                    && found.pos > *section
                    && !is_section(found.pos)
                {
                    note(num, found.pos);
                }
            }
        }
        lowest
    }

    /// Installs the entries and revisions of a cross-reference chain, completed by a scan of the
    /// file when the chain is incomplete. Returns how the newest section was found.
    ///
    /// A chain that stands in for a reconstruction (`damaged`, see
    /// [`Store::read_chain_from_markers`]) shows every object as the reconstruction does, but a
    /// reconstruction also keeps the other generations it finds of the numbers the chain lists
    /// (`5 1 obj` besides the `5 0 obj` of the table: another object, §7.3.10): they are added
    /// (see [`Store::others`]), so that `5 1 R` resolves as qpdf resolves it, and listed in
    /// [`Store::recovered_objects`].
    fn install_chain(&mut self, chain: XrefChain, damaged: bool) -> Result<How> {
        let len = self.bytes().len();
        self.revisions = chain.revisions;
        self.section_starts = chain.section_starts;
        self.trailer = self.effective_trailer()?;
        let mut entries = chain.entries;
        let mut max_num = chain.max_object_number;
        if chain.overflow {
            let (kind, cap) = self.limits().object_cap(len as u64);
            self.recover_structure_limit(false, DiagnosticKind::XrefMalformed, kind, cap, || {
                format!(
                    "the cross-reference data lists more than {cap} objects in use, more \
                         than a file of {len} bytes can hold; the others are ignored"
                )
            })?;
        }
        // A catalog the cross-reference data does not list at all means the data is
        // incomplete, like a broken /Prev chain.
        let root_unlisted = self
            .root_id()
            .is_some_and(|root| !chain.listed.contains(&root.num));
        let mut added: Vec<u32> = Vec::new();
        let mut others: Vec<(u32, XrefEntry)> = Vec::new();
        if !chain.complete || root_unlisted {
            self.recover_structure(false, DiagnosticKind::XrefReconstructed, None, || {
                "cross-reference data is incomplete; objects it lacks were recovered by scanning \
                 the file"
                    .to_owned()
            })?;
            let listed = chain.listed;
            let rebuilt = repair::reconstruct_entries(self);
            for (num, entry) in rebuilt.entries {
                if !listed.contains(&num) {
                    entries.push((num, entry));
                    added.push(num);
                    max_num = max_num.max(Some(num));
                }
            }
            others = rebuilt
                .others
                .into_iter()
                .filter(|(num, _)| !listed.contains(num))
                .collect();
            entries.sort_unstable_by_key(|&(num, _)| num);
        }
        if damaged {
            others.extend(self.other_generations(&entries));
            others.sort_unstable_by_key(|&(num, entry)| (num, entry_generation(entry)));
        }
        self.install_checked(&entries, &others)?;
        for num in added {
            if let Some(slot) = self.slot(num) {
                slot.recovered.store(true, Ordering::Relaxed);
            }
        }
        for slot in &self.others {
            slot.recovered.store(true, Ordering::Relaxed);
        }
        self.max_object_number = max_num
            .unwrap_or(0)
            .max(self.slots.last().map_or(0, |s| s.num));
        Ok(chain.newest)
    }

    /// The definitions the scan finds (see [`repair::definitions`]) of other generations of the
    /// numbers that `entries` (sorted by number) lists in use, as in-file entries.
    fn other_generations(&self, entries: &[(u32, XrefEntry)]) -> Vec<(u32, XrefEntry)> {
        let generation = |num: u32| {
            entries
                .binary_search_by_key(&num, |&(n, _)| n)
                .ok()
                .and_then(|i| entries.get(i))
                .map(|&(_, entry)| entry_generation(entry))
        };
        self.definitions()
            .iter()
            .filter(|(id, _)| generation(id.num).is_some_and(|g| g != id.r#gen))
            .map(|(id, found)| {
                let entry = XrefEntry::InFile {
                    pos: found.pos as u64,
                    r#gen: id.r#gen,
                };
                (id.num, entry)
            })
            .collect()
    }

    /// [`Store::install`], reporting objects dropped because of [`xref::object_cap`].
    fn install_checked(
        &mut self,
        entries: &[(u32, XrefEntry)],
        others: &[(u32, XrefEntry)],
    ) -> Result<()> {
        if !self.install(entries, others) {
            return Ok(());
        }
        let len = self.bytes().len();
        let (kind, cap) = self.limits().object_cap(len as u64);
        self.recover_structure_limit(false, DiagnosticKind::XrefMalformed, kind, cap, || {
            format!(
                "more than {cap} objects in use, more than a file of {len} bytes can hold; \
                     the others are ignored"
            )
        })
    }

    /// Which position the file's offsets count from: how the newest section was found, or,
    /// when that does not tell (it was found nearby, or the file was reconstructed), where the
    /// catalog's entry (or its object stream's) holds the object.
    fn detect_offset_base(&self, newest: Option<How>) -> OffsetBase {
        if self.header_offset == 0 {
            return OffsetBase::HeaderRelative;
        }
        match newest {
            Some(How::Exact) => OffsetBase::HeaderRelative,
            Some(How::Absolute) => OffsetBase::Absolute,
            Some(How::Nearby) | None => self.root_offset_base().unwrap_or_default(),
        }
    }

    fn root_offset_base(&self) -> Option<OffsetBase> {
        let root = self.root_id()?;
        let num = match self.location(root.num)? {
            Location::InFile { .. } => root.num,
            Location::InObjStm { stream, .. } => stream,
        };
        let Location::InFile { pos } = self.location(num)? else {
            return None;
        };
        let bytes = self.bytes();
        let holds = |p: u64| {
            usize::try_from(p)
                .ok()
                .and_then(|p| object_header_at(bytes, p))
                .is_some_and(|(id, _)| id.num == num)
        };
        if holds(pos) {
            Some(OffsetBase::HeaderRelative)
        } else if pos.checked_sub(self.header_offset).is_some_and(holds) {
            Some(OffsetBase::Absolute)
        } else {
            None
        }
    }

    /// Makes sure `/Root` leads to a dictionary (parsing it now, which also caches it); when it
    /// does not, looks for the catalog instead.
    fn verify_root(&mut self) -> Result<()> {
        let Some(root) = self.root_id() else {
            return Ok(());
        };
        if self.resolve(root)?.as_dict().is_some() {
            return Ok(());
        }
        let Some(found) = repair::find_catalog(self).filter(|&found| found != root) else {
            return Err(Error::Xref {
                offset: None,
                message: format!(
                    "the trailer /Root {root} is not a dictionary, and no catalog was found"
                )
                .into(),
            });
        };
        self.recover_structure(false, DiagnosticKind::TrailerRebuilt, None, || {
            format!("the trailer /Root {root} is not a dictionary; using the catalog {found}")
        })?;
        self.trailer.insert(keys::ROOT, found);
        if let Some(newest) = self.revisions.last_mut()
            && newest.xref_kind == XrefKind::Reconstructed
        {
            newest.trailer = self.trailer.clone();
        }
        Ok(())
    }

    /// The newest trailer, with `/Root` and `/Encrypt` taken from older trailers when the
    /// newest one lacks them.
    fn effective_trailer(&self) -> Result<Dict> {
        let Some(newest) = self.revisions.last() else {
            return Ok(Dict::new());
        };
        let mut trailer = newest.trailer.clone();
        for key in [keys::ROOT, keys::ENCRYPT] {
            if trailer.get(key).is_some_and(|v| !v.is_null()) {
                continue;
            }
            let older = self
                .revisions
                .iter()
                .rev()
                .skip(1)
                .find_map(|r| r.trailer.get(key).filter(|v| !v.is_null()));
            if let Some(value) = older {
                let name = String::from_utf8_lossy(key).into_owned();
                self.recover_structure(false, DiagnosticKind::TrailerRebuilt, None, || {
                    format!("the newest trailer has no /{name}; taken from an older trailer")
                })?;
                trailer.insert(key, value.clone());
            }
        }
        Ok(trailer)
    }

    /// Makes sure the trailer has a `/Root`, rebuilding it from the scan when needed.
    fn ensure_root(&mut self) -> Result<()> {
        if self.trailer.get_ref(keys::ROOT).is_some() {
            return Ok(());
        }
        let rebuilt = repair::find_trailer(self).filter(|t| t.get_ref(keys::ROOT).is_some());
        let (root, from) = match rebuilt {
            Some(found) => (found.get_ref(keys::ROOT), found),
            None => (repair::find_catalog(self), Dict::new()),
        };
        let Some(root) = root else {
            return Err(Error::Xref {
                offset: None,
                message: "the document has no catalog: no trailer /Root and no /Type /Catalog \
                          object"
                    .into(),
            });
        };
        self.recover_structure(false, DiagnosticKind::TrailerRebuilt, None, || {
            format!("the trailer has no /Root; using {root}")
        })?;
        self.trailer.insert(keys::ROOT, root);
        for key in [keys::INFO, keys::ID, keys::ENCRYPT] {
            if self.trailer.get(key).is_none_or(Object::is_null)
                && let Some(value) = from.get(key)
            {
                self.trailer.insert(key, value.clone());
            }
        }
        if self.trailer.get(keys::SIZE).is_none() {
            let size = i64::from(self.max_object_number()) + 1;
            self.trailer.insert(keys::SIZE, size);
        }
        if let Some(newest) = self.revisions.last_mut()
            && newest.xref_kind == XrefKind::Reconstructed
        {
            newest.trailer = self.trailer.clone();
        }
        Ok(())
    }

    /// M1 cannot decrypt: report encrypted documents (§7.6).
    fn check_encryption(&self) -> Result<()> {
        let Some(encrypt) = self.trailer.get(keys::ENCRYPT).filter(|v| !v.is_null()) else {
            return Ok(());
        };
        let resolved = self.deref(encrypt)?;
        let Some(dict) = resolved.as_dict() else {
            return Err(Error::unsupported(format!(
                "the document is encrypted, but /Encrypt is a {}, not a dictionary",
                resolved.type_name()
            )));
        };
        match dict.get_name(keys::FILTER) {
            Some(filter) if filter == b"Standard" => Err(Error::new(
                ErrorCode::PasswordRequired,
                "the document is encrypted with the standard security handler; a password is \
                 required",
            )),
            Some(filter) => Err(Error::unsupported(format!(
                "the document is encrypted with the unsupported security handler {filter}"
            ))),
            None => Err(Error::unsupported(
                "the document is encrypted, but /Encrypt has no /Filter",
            )),
        }
    }

    /// Replaces the slots with the in-use `entries` (sorted by object number; free entries and
    /// in-use entries for object 0 are dropped), plus `others` (further generations of numbers
    /// in `entries`, sorted by number and generation, see [`Store::others`]), and forgets what
    /// was loaded for the previous slots. At most [`xref::object_cap`] objects are kept, the
    /// lowest numbers first; returns whether any were dropped.
    pub(crate) fn install(
        &mut self,
        entries: &[(u32, XrefEntry)],
        others: &[(u32, XrefEntry)],
    ) -> bool {
        *self
            .objstm_cache
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner) = ObjStmCache::default();
        self.peeked_objects
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.settled
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        *self.objstm_parsed.get_mut() = 0;
        *self.cached_bytes.get_mut() = 0;
        let len = self.bytes().len();
        let cap = usize::try_from(xref::object_cap(self.limits(), len)).unwrap_or(usize::MAX);
        let mut slots: Vec<Slot> = Vec::with_capacity(entries.len().min(cap));
        let mut dropped = false;
        for &(num, entry) in entries {
            let Some(slot) = Slot::new(num, entry).filter(|_| num != 0) else {
                continue;
            };
            if slots.len() >= cap {
                dropped = true;
                break;
            }
            slots.push(slot);
        }
        let mut kept: Vec<Slot> = Vec::new();
        for &(num, entry) in others {
            let Some(slot) = Slot::new(num, entry).filter(|_| num != 0) else {
                continue;
            };
            // Only generations of numbers that have a slot, distinct from its generation.
            let primary = slots
                .binary_search_by_key(&num, |s| s.num)
                .ok()
                .and_then(|i| slots.get(i));
            if primary.is_none_or(|p| p.r#gen == slot.r#gen) {
                continue;
            }
            if slots.len().saturating_add(kept.len()) >= cap {
                dropped = true;
                break;
            }
            kept.push(slot);
        }
        kept.sort_unstable_by_key(|s| (s.num, s.r#gen));
        kept.dedup_by_key(|s| (s.num, s.r#gen));
        self.slots = slots;
        self.others = kept;
        let len = len as u64;
        let indexed = || {
            self.slots
                .iter()
                .chain(&self.others)
                .enumerate()
                .filter_map(|(i, slot)| Some((u32::try_from(i).ok()?, slot)))
        };
        let mut by_position: Vec<(u64, u32)> = indexed()
            .filter_map(|(i, slot)| match slot.loc {
                Location::InFile { pos } if pos < len => Some((pos, i)),
                _ => None,
            })
            .collect();
        by_position.sort_unstable();
        let mut by_container: Vec<((u32, u32), u32)> = indexed()
            .filter_map(|(i, slot)| match slot.loc {
                Location::InObjStm { stream, index } => Some(((stream, index), i)),
                Location::InFile { .. } => None,
            })
            .collect();
        by_container.sort_unstable();
        self.by_position = by_position.into_iter().map(|(_, i)| i).collect();
        self.by_container = by_container.into_iter().map(|(_, i)| i).collect();
        dropped
    }

    // ---- introspection ------------------------------------------------------------------------

    /// The newest trailer dictionary (§7.5.5), or the cross-reference stream dictionary that
    /// serves as one (§7.5.8.2). When it was damaged, the repaired version: `/Root` (and
    /// `/Encrypt`) taken from an older trailer, or `/Root` set to the catalog found by a scan.
    /// Changes made with [`Store::set_trailer_entry`] and [`Store::remove_trailer_entry`] are
    /// included; [`Revision::trailer`] keeps each section's trailer as written.
    pub fn trailer(&self) -> &Dict {
        &self.trailer
    }

    /// The trailer's `/Root` reference (the document catalog), if it has one. After a
    /// successful [`Store::open`] it always does.
    pub fn root_id(&self) -> Option<ObjectId> {
        self.trailer.get_ref(keys::ROOT)
    }

    /// The revisions (cross-reference sections) of the file in `/Prev` order, oldest first. A
    /// reconstructed file has a single revision of kind [`XrefKind::Reconstructed`].
    ///
    /// These are logical sections, not byte ranges in file order: see [`Revision`] (a linearized
    /// file's newest section is near the start of the file, and `eof_end` need not grow).
    pub fn revisions(&self) -> &[Revision] {
        &self.revisions
    }

    /// The cross-reference entries of revision `index` (an index into [`Store::revisions`]) as
    /// its section writes them, read again from the source: the entries of the table or stream
    /// in file order, then, for a hybrid section, those of its `/XRefStm` stream. Free entries
    /// are included, an entry that stands for the null object reads as free with generation 0
    /// (see [`XrefEntry::Free`]), and a number can appear more than once (the first entry is the
    /// one the merged view uses for this section).
    ///
    /// This is what changed in a revision (ARCHITECTURE §A.6.7): the union of the table's and
    /// the stream's entries, free ones included, whatever a particular reader would take from
    /// either. The merged view of [`Store::resolve`] says what the newest revision means.
    ///
    /// # Errors
    /// - [`ErrorCode::InvalidArgument`] when `index` is out of range.
    /// - [`ErrorCode::Xref`] for a [`XrefKind::Reconstructed`] revision, which has no section.
    /// - In strict mode only, the errors of reading the section (it was read without errors when
    ///   the file was opened); [`ErrorCode::LimitExceeded`] in either mode.
    pub fn revision_entries(&self, index: usize) -> Result<Vec<(u32, XrefEntry)>> {
        let revision = self.revisions.get(index).ok_or_else(|| {
            Error::invalid_argument(format!(
                "revision {index} does not exist; the file has {}",
                self.revisions.len()
            ))
        })?;
        if revision.xref_kind == XrefKind::Reconstructed {
            return Err(Error::Xref {
                offset: None,
                message: "a reconstructed file has no cross-reference section to read".into(),
            });
        }
        let absolute = |offset: u64| {
            self.header_offset
                .checked_add(offset)
                .and_then(|p| usize::try_from(p).ok())
                .ok_or_else(|| Error::invalid_argument(format!("offset {offset} is out of range")))
        };
        let pos = absolute(revision.startxref)?;
        let hidden = revision.xref_stm.map(absolute).transpose()?;
        xref::section_entries(self, pos, hidden)
    }

    /// Whether opening the file had to repair its cross-reference structure: a section found
    /// away from its offset, a damaged table or stream read with repairs or skipped, a `/Prev` or
    /// `/XRefStm` that leads nowhere or loops, a chain cut by a limit, an earlier `startxref`
    /// used, objects recovered by scanning the file (a reconstruction, an incomplete chain, a
    /// catalog the data does not list), or a trailer rebuilt or its `/Root` replaced.
    ///
    /// When it is true, what the store shows need not be what a reader that follows the file's
    /// own cross-reference data shows, so the revision structure is no basis for signature
    /// verification without a warning (ARCHITECTURE §A.6.7) or for an incremental update (full
    /// save first). Always false for a store opened in strict mode, which refuses such files.
    pub fn structure_repaired(&self) -> bool {
        self.structure_repaired.load(Ordering::Relaxed)
            || self
                .revisions
                .iter()
                .any(|r| r.xref_kind == XrefKind::Reconstructed)
    }

    /// The objects that other readers may see differently, by number:
    ///
    /// - their location did not come from the cross-reference data as written: found by a scan
    ///   of the file (a reconstruction, or numbers the data lacks), by the search within ±64
    ///   bytes of a wrong offset, at their offset counted from byte 0 instead of the header, or as
    ///   another member (or in another object stream) than their entry says;
    /// - or their own bytes needed a repair that decides what they hold: a header whose
    ///   generation differs from the entry's, a stream `/Length` that does not end at
    ///   `endstream` (the data was delimited by searching for it), a missing `endstream` or
    ///   `endobj`, or a `stream` keyword without a proper end-of-line (lenient mode only;
    ///   [`DiagnosticKind::StreamLength`] and the others say which).
    ///
    /// Such an object can differ from what a reader that follows the cross-reference data, or a
    /// stream's `/Length`, sees (an object appended after the last `%%EOF`, listed in no section,
    /// or data hidden behind a short `/Length` in a later revision): a signature verifier treats
    /// it as a modification it cannot attribute to a revision (ARCHITECTURE §A.6.7). Objects are
    /// checked lazily, so they join this list as they are resolved: resolve what matters first.
    pub fn recovered_objects(&self) -> Vec<ObjectId> {
        let mut ids: Vec<ObjectId> = self
            .slots
            .iter()
            .chain(&self.others)
            .filter(|s| s.recovered.load(Ordering::Relaxed))
            .map(|s| ObjectId::new(s.num, s.r#gen))
            .collect();
        ids.sort_unstable_by_key(|id| (id.num, id.r#gen));
        ids
    }

    /// The first in-use object (by number) of the merged cross-reference data whose entry gives a
    /// position that does not hold its `N G obj` header with its number and generation: a
    /// wrong offset, which the store repairs when the object is loaded (the ±64-byte search, the
    /// scan; see [`Store::recovered_objects`]) but which makes qpdf and poppler reconstruct the
    /// whole file. Checked eagerly, in `O(1)` per entry (no parsing), for the incremental writer:
    /// an update appended to such a file can mean something else to those readers (DECISIONS
    /// D9.8), so it needs a full save. Compressed objects are not checked.
    pub(crate) fn first_misplaced_object(&self) -> Option<ObjectId> {
        let bytes = self.bytes();
        self.slots.iter().find_map(|slot| {
            let Location::InFile { pos } = slot.loc else {
                return None;
            };
            let id = ObjectId::new(slot.num, slot.r#gen);
            let found = usize::try_from(pos)
                .ok()
                .and_then(|p| object_header_at(bytes, p))
                .map(|(found, _)| found);
            (found != Some(id)).then_some(id)
        })
    }

    /// Which position the offsets in the file count from: the header (as the standard says, and
    /// always when the header is at byte 0), or byte 0 (a writer that counted the junk before the
    /// header). Taken from how the newest section was found, or from where the catalog is.
    ///
    /// [`Revision::startxref`] is header-relative either way; an incremental update should write
    /// its `/Prev` and offsets in the file's own base (ARCHITECTURE §A.10 trap #12).
    pub fn offset_base(&self) -> OffsetBase {
        self.offset_base
    }

    /// The position of `%PDF-` in the source: the number of junk bytes before the header,
    /// which every offset in the file is relative to.
    pub fn header_offset(&self) -> u64 {
        self.header_offset
    }

    /// The version in the `%PDF-` header, for example `(1, 7)`; `(1, 4)` when the header is
    /// missing or malformed. The catalog's `/Version` can override it (§7.7.2); that is the
    /// document model's business.
    pub fn version(&self) -> (u8, u8) {
        self.version
    }

    /// The identifiers of all in-use objects, by number (then generation: a reconstructed file
    /// can define several generations of one number, which are different objects, §7.3.10): the
    /// in-use objects of the merged cross-reference data, without those freed by
    /// [`Store::free`], plus those added by [`Store::add`]. Compressed objects have generation
    /// 0. Object 0 is never included.
    pub fn object_ids(&self) -> Vec<ObjectId> {
        let mut ids: Vec<ObjectId> = self
            .slots
            .iter()
            .chain(&self.others)
            .map(|s| ObjectId::new(s.num, s.r#gen))
            .filter(|id| !matches!(self.edits.get(id), Some(Edit::Free)))
            .collect();
        ids.extend(
            self.edits
                .iter()
                .filter(|(_, edit)| matches!(edit, Edit::Set(_)))
                .map(|(&id, _)| id),
        );
        ids.sort_unstable_by_key(|id| (id.num, id.r#gen));
        ids.dedup();
        ids
    }

    /// The largest object number in the merged cross-reference data of the source (in use or
    /// free), or 0 when there is none. Objects added with [`Store::add`] are numbered after it
    /// (see [`Store::next_object_number`]).
    pub fn max_object_number(&self) -> u32 {
        self.max_object_number
    }

    /// A copy of the diagnostics recorded so far (at most [`Limits::max_diagnostics`]), oldest
    /// first. Diagnostics accumulate as objects are resolved and streams decoded.
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        self.diagnostics.snapshot()
    }

    /// The number of diagnostics that were not stored because [`Limits::max_diagnostics`]
    /// was reached.
    pub fn dropped_diagnostics(&self) -> u64 {
        self.diagnostics.dropped()
    }

    /// The options the store was opened with.
    pub fn options(&self) -> &OpenOptions {
        &self.options
    }

    /// The limits in force (from [`OpenOptions::limits`]).
    pub fn limits(&self) -> &Limits {
        &self.options.limits
    }

    /// The source bytes.
    pub fn source(&self) -> &[u8] {
        self.bytes()
    }

    /// The shared source buffer (for an incremental save, which copies it unchanged).
    pub fn shared_source(&self) -> &SharedBytes {
        &self.source
    }

    /// The decoded bytes charged against [`Limits::max_total_decoded`] so far.
    ///
    /// Each stream of the source (by its data range) counts once, with the most bytes any decode
    /// of it produced, including the streams the store decodes itself (cross-reference streams,
    /// object streams); a decode that stops at a limit counts the bytes it was allowed. Decoding
    /// the same stream again costs nothing more, so a long-lived store (an editor that re-reads
    /// page content) does not run out of budget, while a file with many decompression bombs
    /// still stops at the limit. Streams whose data is not in the source
    /// ([`StreamData::Encoded`], [`StreamData::Decoded`]) belong to the caller and are only
    /// bounded per stream, by [`Limits::max_decoded_stream`].
    pub fn total_decoded(&self) -> u64 {
        self.total_decoded.load(Ordering::Relaxed)
    }

    /// The number of objects parsed so far (each indirect object, object stream member and
    /// cross-reference stream counts once per parse). For laziness tests.
    #[doc(hidden)]
    pub fn parsed_object_count(&self) -> usize {
        self.parsed_objects.load(Ordering::Relaxed)
    }

    /// The bytes the decoded object streams in the cache hold now (at most about
    /// [`Limits::max_objstm_cache`] plus one container). For resource tests.
    #[doc(hidden)]
    pub fn objstm_cache_bytes(&self) -> u64 {
        lock(&self.objstm_cache).resident
    }

    /// The memory charged to [`LimitKind::ObjStmParsed`] so far: the estimated size of the
    /// objects parsed from object streams. For resource tests.
    #[doc(hidden)]
    pub fn objstm_parsed_bytes(&self) -> u64 {
        self.objstm_parsed.load(Ordering::Relaxed)
    }

    // ---- resolving ----------------------------------------------------------------------------

    /// The object `id`: its edit, if it was set, added or freed (see [`Store::set`]), otherwise
    /// the source's object, parsed on first use and cached.
    ///
    /// A free or missing object is `null` (§7.3.10: a reference to an undefined object is a
    /// reference to `null`), and so is an object freed by [`Store::free`]. A generation that
    /// does not match the cross-reference entry gives `null` and a
    /// [`DiagnosticKind::WrongGeneration`] diagnostic. A reference stored as the object's value
    /// is returned as is; use [`Store::deref`] to follow reference chains.
    ///
    /// The returned `Arc` is a snapshot: a later edit of the object does not change it.
    ///
    /// # Errors
    /// In lenient mode only [`ErrorCode::LimitExceeded`]; an unreadable object is `null` plus a
    /// [`DiagnosticKind::ObjectUnreadable`] diagnostic. In strict mode, also the error that made
    /// the object unreadable (and any repair the object needed).
    pub fn resolve(&self, id: ObjectId) -> Result<Arc<Object>> {
        if !self.edits.is_empty() {
            match self.edits.get(&id) {
                Some(Edit::Set(object)) => return Ok(Arc::clone(object)),
                Some(Edit::Free) => return Ok(self.null()),
                None => {}
            }
        }
        self.resolve_source(id)
    }

    /// [`Store::resolve`] without the edits: the source's object `id`. The store's own loads
    /// use it (an object stream container), so an edit never changes how the source is read.
    pub(crate) fn resolve_source(&self, id: ObjectId) -> Result<Arc<Object>> {
        let Some(slot) = self.slot_of(id) else {
            return Ok(self.null());
        };
        if !self.generation_matches(slot, id) {
            return Ok(self.null());
        }
        slot.parsed
            .get_or_init(|| {
                let loaded = self.load_slot(slot);
                if let Ok(object) = &loaded {
                    self.cached_bytes
                        .fetch_add(memory::heap_size(object), Ordering::Relaxed);
                }
                loaded
            })
            .clone()
            .map_err(|err| *err)
    }

    /// Follows `obj` through references to a non-reference object.
    ///
    /// A direct object is returned as is. A chain longer than [`Limits::max_ref_chain`], or one
    /// that loops, ends in `null` with a [`DiagnosticKind::UnresolvedReference`] diagnostic in
    /// lenient mode.
    ///
    /// # Errors
    /// The errors of [`Store::resolve`]; in strict mode also [`ErrorCode::LimitExceeded`] for a
    /// chain that is too long and [`ErrorCode::Syntax`] for one that loops.
    pub fn deref<'a>(&self, obj: &'a Object) -> Result<Resolved<'a>> {
        let Object::Ref(first) = obj else {
            return Ok(Resolved::Direct(obj));
        };
        let max = usize::from(self.limits().max_ref_chain);
        let mut seen: Vec<u32> = Vec::new();
        let mut id = *first;
        loop {
            if seen.contains(&id.num) {
                let message = format!("reference chain from {first} loops at {id}");
                return match self.options.strictness {
                    Strictness::Strict => Err(Error::new(ErrorCode::Syntax, message)),
                    Strictness::Lenient => {
                        self.note(DiagnosticKind::UnresolvedReference, None, || message);
                        Ok(Resolved::Indirect(self.null()))
                    }
                };
            }
            if seen.len() >= max {
                self.recover_limit(
                    DiagnosticKind::UnresolvedReference,
                    LimitKind::MaxRefChain,
                    max as u64,
                    || format!("reference chain from {first} is longer than {max}"),
                )?;
                return Ok(Resolved::Indirect(self.null()));
            }
            seen.push(id.num);
            let target = self.resolve(id)?;
            match &*target {
                Object::Ref(next) => id = *next,
                _ => return Ok(Resolved::Indirect(target)),
            }
        }
    }

    fn slot(&self, num: u32) -> Option<&Slot> {
        // Fast path for the usual dense numbering.
        let base = self.slots.first()?.num;
        if let Some(slot) = num
            .checked_sub(base)
            .and_then(|i| self.slots.get(usize::try_from(i).ok()?))
            && slot.num == num
        {
            return Some(slot);
        }
        let at = self.slots.binary_search_by_key(&num, |s| s.num).ok()?;
        self.slots.get(at)
    }

    /// The slot of object `id`: the one of its number with its generation, else the one the
    /// merged cross-reference data shows for its number (whose generation then differs).
    fn slot_of(&self, id: ObjectId) -> Option<&Slot> {
        let slot = self.slot(id.num)?;
        if slot.r#gen == id.r#gen || self.others.is_empty() {
            return Some(slot);
        }
        let other = self
            .others
            .binary_search_by_key(&(id.num, id.r#gen), |s| (s.num, s.r#gen))
            .ok()
            .and_then(|i| self.others.get(i));
        Some(other.unwrap_or(slot))
    }

    /// The slot at index `i` of `slots` followed by `others` (the indices of
    /// [`Store::by_position`] and [`Store::by_container`]).
    fn slot_at(&self, i: u32) -> Option<&Slot> {
        let i = usize::try_from(i).ok()?;
        match i.checked_sub(self.slots.len()) {
            None => self.slots.get(i),
            Some(j) => self.others.get(j),
        }
    }

    /// Where the merged cross-reference data puts object `num`.
    pub(crate) fn location(&self, num: u32) -> Option<Location> {
        self.slot(num).map(|s| s.loc)
    }

    /// Where object `id` is, if the store has an object with its number and generation.
    pub(crate) fn location_of(&self, id: ObjectId) -> Option<Location> {
        self.slot_of(id)
            .filter(|s| s.r#gen == id.r#gen)
            .map(|s| s.loc)
    }

    /// Whether `id` matches the slot's entry; reports a mismatch.
    fn generation_matches(&self, slot: &Slot, id: ObjectId) -> bool {
        if slot.r#gen == id.r#gen {
            return true;
        }
        self.note(DiagnosticKind::WrongGeneration, None, || {
            format!(
                "reference {id} does not match the cross-reference entry (generation {}); read \
                 as null",
                slot.r#gen
            )
        });
        false
    }

    /// Records that object `id` was found somewhere else than its entry says, or needed a
    /// repair that decides what it holds (see [`Store::recovered_objects`]).
    fn mark_recovered(&self, id: ObjectId) {
        if let Some(slot) = self.slot_of(id).filter(|s| s.r#gen == id.r#gen) {
            slot.recovered.store(true, Ordering::Relaxed);
        }
    }

    fn null(&self) -> Arc<Object> {
        Arc::clone(&self.null)
    }

    /// Fills a slot (inside its `OnceLock`): take what a settling pass left for it (see
    /// [`Store::settle_container`]), or parse, then apply the leniency policy.
    fn load_slot(&self, slot: &Slot) -> Loaded {
        if matches!(slot.loc, Location::InObjStm { .. })
            && let Some(done) = self.take_settled(slot.num)
        {
            return done;
        }
        let chain = Chain::root(slot.num);
        let loaded = self.load(slot, &chain, Mode::Blocking, false);
        self.settle(slot, loaded)
    }

    /// Removes and returns what a settling pass loaded for compressed object `num`.
    fn take_settled(&self, num: u32) -> Option<Loaded> {
        let mut settled = lock(&self.settled);
        if settled.is_empty() {
            return None;
        }
        settled.remove(&num)
    }

    /// The leniency policy for what a blocking load of `slot` produced: in lenient mode an
    /// unreadable object is `null` (reported); a limit, or any error in strict mode, is kept.
    fn settle(&self, slot: &Slot, loaded: Result<Object>) -> Loaded {
        match loaded {
            Ok(object) => Ok(Arc::new(object)),
            Err(err) if self.is_strict() || err.code() == ErrorCode::LimitExceeded => {
                Err(Box::new(err))
            }
            Err(err) => {
                let id = ObjectId::new(slot.num, slot.r#gen);
                self.note(DiagnosticKind::ObjectUnreadable, err.offset(), || {
                    format!("object {id} could not be read ({err}); read as null")
                });
                Ok(self.null())
            }
        }
    }

    /// Loads the object of `slot`. `chain` already contains the slot's number.
    fn load(&self, slot: &Slot, chain: &Chain<'_>, mode: Mode<'_>, quiet: bool) -> Result<Object> {
        match slot.loc {
            Location::InFile { pos } => {
                let id = ObjectId::new(slot.num, slot.r#gen);
                let at = self.locate(id, pos, quiet)?;
                let bytes = self.bytes();
                let region = bytes.get(..self.region_end(at, pos)).unwrap_or(bytes);
                #[cfg(test)]
                self.region_bytes
                    .fetch_add(region.len().saturating_sub(at) as u64, Ordering::Relaxed);
                let keywords = LazyKeywords(self);
                let watch = RepairWatch {
                    inner: &self.diagnostics,
                    quiet,
                    hit: Cell::new(false),
                };
                let ctx = ParseCtx::new(self.options.limits, self.options.strictness)
                    .with_diagnostics(&watch)
                    .with_keyword_index(&keywords);
                let lengths = |r: ObjectId| self.peek_deref(r, chain)?.as_int();
                let parsed = parse_indirect_at(region, at, &ctx, &lengths)?;
                self.count_parse();
                if watch.hit.get() {
                    slot.recovered.store(true, Ordering::Relaxed);
                }
                Ok(parsed.object)
            }
            Location::InObjStm { stream, index } => {
                self.load_compressed(slot.num, stream, index, chain, mode, quiet)
            }
        }
    }

    /// Validates an uncompressed object's offset (trap #3): `N G obj` must be at `pos` (after
    /// optional white-space); otherwise at the offset taken as absolute (junk before the header
    /// that the writer did not account for), within ±64 bytes, or anywhere in the file (scan).
    fn locate(&self, id: ObjectId, pos: u64, quiet: bool) -> Result<usize> {
        let repaired = |found: usize, how: &str| -> Result<usize> {
            self.recover_as(
                quiet,
                ErrorCode::Xref,
                DiagnosticKind::XrefOffsetRepaired,
                Some(pos),
                || format!("object {id} is not at byte {pos}; found at byte {found} ({how})"),
            )?;
            self.mark_recovered(id);
            Ok(found)
        };
        match self.header_near(id, pos) {
            Some((p, HeaderAt::Exact { r#gen })) => {
                if r#gen != id.r#gen {
                    self.recover_as(
                        quiet,
                        ErrorCode::Xref,
                        DiagnosticKind::XrefMalformed,
                        Some(pos),
                        || format!("object {id} has generation {gen} in its header"),
                    )?;
                    // Readers that check the generation see another object (or none) here.
                    self.mark_recovered(id);
                }
                return Ok(p);
            }
            Some((p, HeaderAt::Absolute)) => return repaired(p, "offset taken as absolute"),
            Some((p, HeaderAt::Nearby)) => return repaired(p, "nearby"),
            None => {}
        }
        if !self.is_strict()
            && let Some(found) = self.definitions().find(id)
        {
            return repaired(found.pos, "by scanning the file");
        }
        Err(Error::Xref {
            offset: Some(pos),
            message: format!("object {id} is not at byte {pos} nor anywhere else in the file")
                .into(),
        })
    }

    /// Where the header of object `id`, whose entry says `pos`, is without a scan of the file
    /// (see [`Store::locate`]): at `pos` (`N G obj` with the right number, any generation), at
    /// `pos` taken as absolute, or the nearest position within ±64 bytes that holds `id`.
    fn header_near(&self, id: ObjectId, pos: u64) -> Option<(usize, HeaderAt)> {
        let bytes = self.bytes();
        if let Some(p) = usize::try_from(pos).ok().filter(|&p| p < bytes.len())
            && let Some((found, _)) = object_header_at(bytes, p)
            && found.num == id.num
        {
            return Some((p, HeaderAt::Exact { r#gen: found.r#gen }));
        }
        if let Some(p) = pos
            .checked_sub(self.header_offset)
            .filter(|_| self.header_offset > 0)
            .and_then(|p| usize::try_from(p).ok())
            && object_header_at(bytes, p).is_some_and(|(found, _)| found == id)
        {
            return Some((p, HeaderAt::Absolute));
        }
        // A position past the end (a truncated file, or a skewed offset near the end) is
        // searched from the end of the file.
        let center = usize::try_from(pos).unwrap_or(usize::MAX).min(bytes.len());
        let lo = center.saturating_sub(LOCAL_SEARCH);
        let hi = center.saturating_add(LOCAL_SEARCH).min(bytes.len());
        (lo..=hi)
            .filter(|&p| {
                bytes.get(p).is_some_and(u8::is_ascii_digit)
                    && (p == 0 || bytes.get(p - 1).is_some_and(|b| !b.is_ascii_digit()))
                    && object_header_at(bytes, p).is_some_and(|(found, _)| found == id)
            })
            .min_by_key(|&p| p.abs_diff(center))
            .map(|p| (p, HeaderAt::Nearby))
    }

    /// The end of the bytes that parsing the uncompressed object found at `at` (whose
    /// cross-reference position is `pos`) may read: the start of the next object or
    /// cross-reference section after it.
    ///
    /// In a well-formed file this is never inside the object. It matters when objects overlap:
    /// a hostile cross-reference table can point at `N G obj` headers inside another object's
    /// string, comment or stream data, so that every object's parse would run on to the end of
    /// the enclosing one, and resolving every object would cost time quadratic in the file size
    /// (decoding every stream too, since a stream without `endstream` takes the bytes up to the
    /// next `endobj`). Bounded by its region, each object costs at most the bytes up to the next
    /// object, and resolving every object is linear.
    ///
    /// The next object is taken from the cross-reference data, checked: its position must hold
    /// its own `N G obj` header (or does after the shift that relocated this object, for a table
    /// whose offsets are all skewed). When none of the next [`REGION_CANDIDATES`] positions
    /// checks out, or the scan relocated this object, the next header found by the scan of the
    /// file decides. A file whose table can be checked is never scanned for this.
    fn region_end(&self, at: usize, pos: u64) -> usize {
        let bytes = self.bytes();
        // The object's own header `N G obj` starts after at most a little white-space (`locate`
        // matched it with `object_header_at`); the next object starts after it.
        let header = at.saturating_add(
            bytes
                .get(at..)
                .unwrap_or_default()
                .iter()
                .take_while(|&&b| crate::lexer::is_whitespace(b))
                .count(),
        );
        let body = object_header_at(bytes, at).map_or(header, |(_, end)| end) as u64;
        let section = self
            .section_starts
            .get(self.section_starts.partition_point(|&p| (p as u64) < body))
            .copied();
        let below_section = |p: u64| section.is_none_or(|s| p < s as u64);
        let skew = i64::try_from(at as u64)
            .ok()
            .zip(i64::try_from(pos).ok())
            .map_or(0, |(at, pos)| at.saturating_sub(pos));
        let starts_object = |p: u64, num: u32| {
            usize::try_from(p)
                .ok()
                .and_then(|p| object_header_at(bytes, p))
                .is_some_and(|(id, _)| id.num == num)
        };
        // With a positive skew, objects whose own position is before this one's body can still
        // start after it once shifted.
        let low = body.saturating_sub(u64::try_from(skew).unwrap_or(0));
        let first = self
            .by_position
            .partition_point(|&i| self.position_of(i).is_some_and(|p| p < low));
        let mut unchecked = false;
        let mut next: Option<u64> = None;
        for &i in self.by_position.iter().skip(first).take(REGION_CANDIDATES) {
            let (Some(q), Some(slot)) = (self.position_of(i), self.slot_at(i)) else {
                continue;
            };
            let shifted = if skew == 0 {
                None
            } else {
                q.checked_add_signed(skew)
            };
            // Positions only grow from here on.
            if !below_section(q) && shifted.is_none_or(|p| !below_section(p)) {
                break;
            }
            let mut usable = [Some(q), shifted]
                .into_iter()
                .flatten()
                .filter(|&p| p >= body && below_section(p))
                .peekable();
            if usable.peek().is_some() {
                if let Some(p) = usable.find(|&p| starts_object(p, slot.num)) {
                    next = Some(p);
                    break;
                }
                unchecked = true;
            }
        }
        let end = match next {
            Some(p) => usize::try_from(p).ok(),
            // The table is no guide here: let the scan decide.
            None if unchecked => self.scan_index().next_header_after(header),
            // No object after this one in the table. When the scan relocated this object (it is
            // built then), the table is no guide either: a hostile table can put every entry
            // before the headers the scan finds. Otherwise the object is among the last (an
            // object relocated by the ±64-byte search has every later object's entry after it),
            // and the next section or the end of the file bounds it without a scan.
            None if at as u64 != pos => self
                .scan
                .get()
                .and_then(|scan| scan.next_header_after(header)),
            None => None,
        };
        [end, section]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(bytes.len())
            .min(bytes.len())
    }

    /// The position of the uncompressed slot at index `i` (see [`Store::slot_at`]).
    fn position_of(&self, i: u32) -> Option<u64> {
        match self.slot_at(i)?.loc {
            Location::InFile { pos } => Some(pos),
            _ => None,
        }
    }

    /// Loads the compressed object `num`, entry `index` of object stream `stream`.
    fn load_compressed(
        &self,
        num: u32,
        stream: u32,
        index: u32,
        chain: &Chain<'_>,
        mode: Mode<'_>,
        quiet: bool,
    ) -> Result<Object> {
        let (container, dropped) = match mode {
            Mode::Blocking => self.objstm(stream, false)?,
            Mode::Peek(_) => self.peek_objstm(stream, chain, false)?,
        };
        let object = self.compressed_member(num, Arc::clone(&container), index, chain, mode, quiet);
        if dropped {
            self.settle_container(&container, num, mode);
        }
        object
    }

    /// Object `num` of the decoded object stream `container`: entry `index`, or wherever
    /// [`Store::find_member`] finds it. Parsed within [`LimitKind::ObjStmParsed`].
    fn compressed_member(
        &self,
        num: u32,
        container: Arc<ObjStm>,
        index: u32,
        chain: &Chain<'_>,
        mode: Mode<'_>,
        quiet: bool,
    ) -> Result<Object> {
        let (holder, member) = match container.member_at(index, num) {
            Some(member) => (container, member),
            None => {
                let found = self.find_member(container, num, index, chain, mode, quiet)?;
                self.mark_recovered(ObjectId::new(num, 0));
                found
            }
        };
        let sink = ContainerSink {
            inner: &self.diagnostics,
            stream: holder.num,
        };
        // The objects of object streams are bounded by the file length too: their decoded data
        // can be a thousand times larger than the file (§7.5.7 containers are Flate-compressed).
        let total = self
            .limits()
            .budget(LimitKind::ObjStmParsed, self.bytes().len() as u64);
        let left = total.saturating_sub(self.objstm_parsed.load(Ordering::Relaxed));
        let budget = ParseBudget::new(left, LimitKind::ObjStmParsed, total);
        let mut ctx =
            ParseCtx::new(self.options.limits, self.options.strictness).with_budget(&budget);
        if !quiet {
            ctx = ctx.with_diagnostics(&sink);
        }
        let parsed = holder.parse_member(member, &ctx);
        self.objstm_parsed
            .fetch_add(budget.used(), Ordering::Relaxed);
        let object = parsed.map_err(|err| in_container(err, ObjectId::new(num, 0), holder.num))?;
        self.count_parse();
        Ok(object)
    }

    /// Called when loading object `except` decoded the object stream `stm` again after the
    /// cache had dropped it: loads, in the same pass, every other object that the
    /// cross-reference data puts in it and that is not loaded yet, so that none of them makes
    /// the store decode it again.
    ///
    /// A blocking load puts them, after the leniency policy (reporting their diagnostics), in
    /// the settled memo, where the first load of each slot takes its object (see
    /// [`Store::load_slot`]). A nested load, which never waits, puts the objects found in `stm`
    /// itself into the peek memo (quietly; objects that need its `/Extends` chain are left
    /// alone, as that result would depend on the call path). So, however the cache thrashes,
    /// the loads of a container's own objects decode it at most twice for blocking loads and
    /// twice for nested ones, plus once when a blocking load replaces a nested load's quiet
    /// decode: decoding a container again costs time proportional to its size once, which is
    /// why it is not charged against [`Limits::max_total_decoded`] again (each source stream
    /// counts once, see [`Store::total_decoded`]), and a long-lived store never runs out of that
    /// budget.
    ///
    /// No deadlock: this pass runs inside the `OnceLock` initialisation of `except`'s slot, so it
    /// never waits on another slot's `OnceLock` (two threads settling the same container would
    /// each wait for a slot the other is filling). It only skips the slots that are filled, and
    /// waits at most on containers' cells (for an `/Extends` walk) and, through them, on the
    /// slots of uncompressed objects, whose loads never wait on anything (see [`Chain`]). A
    /// thread that fills one of these slots meanwhile parses that object itself: the race costs
    /// a second parse (and its diagnostics again), never a wait. The pass keeps its result only
    /// while the slot is empty; an entry that loses the race by a hair stays unused, which
    /// costs memory only.
    fn settle_container(&self, stm: &Arc<ObjStm>, except: u32, mode: Mode<'_>) {
        for slot in self.slots_in(stm.num) {
            if slot.num == except || slot.parsed.get().is_some() {
                continue;
            }
            let Location::InObjStm { index, .. } = slot.loc else {
                continue;
            };
            match mode {
                Mode::Blocking => {
                    if lock(&self.settled).contains_key(&slot.num) {
                        continue;
                    }
                    let chain = Chain::root(slot.num);
                    let loaded = self.compressed_member(
                        slot.num,
                        Arc::clone(stm),
                        index,
                        &chain,
                        Mode::Blocking,
                        false,
                    );
                    let done = self.settle(slot, loaded);
                    let mut settled = lock(&self.settled);
                    // Filled by another thread meanwhile: its own load is the object.
                    if slot.parsed.get().is_none() {
                        settled.entry(slot.num).or_insert(done);
                    }
                }
                Mode::Peek(chain) => {
                    let here =
                        stm.member_at(index, slot.num).is_some() || stm.find(slot.num).is_some();
                    let id = ObjectId::new(slot.num, slot.r#gen);
                    if !here || lock(&self.peeked_objects).contains_key(&id) {
                        continue;
                    }
                    let loaded = self
                        .compressed_member(slot.num, Arc::clone(stm), index, chain, mode, true)
                        .ok()
                        .map(Arc::new);
                    lock(&self.peeked_objects).entry(id).or_insert(loaded);
                }
            }
        }
    }

    /// The slots of the compressed objects that the cross-reference data puts in object stream
    /// `stream`, by index.
    fn slots_in(&self, stream: u32) -> impl Iterator<Item = &Slot> + '_ {
        let container_of = |i: u32| match self.slot_at(i)?.loc {
            Location::InObjStm { stream, .. } => Some(stream),
            Location::InFile { .. } => None,
        };
        let start = self
            .by_container
            .partition_point(|&i| container_of(i).is_some_and(|s| s < stream));
        self.by_container
            .get(start..)
            .unwrap_or_default()
            .iter()
            .map_while(move |&i| {
                container_of(i)
                    .filter(|&s| s == stream)
                    .and_then(|_| self.slot_at(i))
            })
    }

    /// Finds object `num` when the cross-reference index does not lead to it: elsewhere in its
    /// container, or in the containers it `/Extends` (§7.5.7), following the chain with loop
    /// detection.
    fn find_member(
        &self,
        container: Arc<ObjStm>,
        num: u32,
        index: u32,
        chain: &Chain<'_>,
        mode: Mode<'_>,
        quiet: bool,
    ) -> Result<(Arc<ObjStm>, crate::objstm::Member)> {
        let first = container.num;
        let mut visited = vec![first];
        let mut current = container;
        loop {
            if let Some((found, member)) = current.find(num) {
                let holder = current.num;
                self.recover_as(
                    quiet,
                    ErrorCode::Syntax,
                    DiagnosticKind::ObjectStream,
                    None,
                    || {
                        format!(
                            "object {num} is not entry {index} of object stream {first}; found as \
                             entry {found} of object stream {holder}"
                        )
                    },
                )?;
                return Ok((current, member));
            }
            let Some(next) = current.extends else {
                break;
            };
            if visited.contains(&next.num) {
                self.recover_as(
                    quiet,
                    ErrorCode::Syntax,
                    DiagnosticKind::ObjectStream,
                    None,
                    || format!("/Extends chain of object stream {first} loops at {next}"),
                )?;
                break;
            }
            if visited.len() >= usize::from(self.limits().max_ref_chain) {
                self.recover_limit(
                    DiagnosticKind::ObjectStream,
                    LimitKind::MaxRefChain,
                    u64::from(self.limits().max_ref_chain),
                    || format!("/Extends chain of object stream {first} is too long"),
                )?;
                break;
            }
            visited.push(next.num);
            current = match mode {
                Mode::Blocking => self.objstm(next.num, true)?.0,
                Mode::Peek(_) => self.peek_objstm(next.num, chain, true)?.0,
            };
        }
        Err(Error::Other {
            code: ErrorCode::Syntax,
            offset: None,
            message: format!(
                "object {num} is not in object stream {first} or the streams it extends"
            )
            .into(),
        })
    }

    // ---- object streams -----------------------------------------------------------------------

    /// The decoded object stream `num`, from the cache or decoded now (and cached, see
    /// [`ObjStmCache`]). The flag says whether this call decoded it again after the cache had
    /// dropped it (the caller then settles its objects, see [`Store::settle_container`]).
    /// `extends`: the container is needed to follow another one's `/Extends` (see
    /// [`Store::objstm_charge`]).
    pub(crate) fn objstm(&self, num: u32, extends: bool) -> Result<(Arc<ObjStm>, bool)> {
        self.check_container(num)?;
        let (cell, dropped) = {
            let mut cache = lock(&self.objstm_cache);
            (cache.cell(num), cache.was_evicted(num))
        };
        let mut initialized = false;
        let decoded = cell
            .get_or_init(|| {
                initialized = true;
                let charge = Self::objstm_charge(dropped, extends);
                self.decode_objstm(num, &Chain::root(num), false, charge)
            })
            .clone();
        if initialized {
            lock(&self.objstm_cache).account(num, &cell, self.objstm_cache_budget());
        }
        Ok((decoded?, initialized && dropped))
    }

    /// The bytes the object-stream cache may hold.
    fn objstm_cache_budget(&self) -> u64 {
        self.limits().max_objstm_cache as u64
    }

    /// How decoding an object stream counts against [`Limits::max_total_decoded`]: once, by its
    /// source data (like any stream), when its own objects need it, since decoding it again for
    /// them settles them all ([`Store::settle_container`]). Only a container decoded again
    /// after the cache dropped it, to follow another one's `/Extends` (a damaged file: the
    /// cross-reference data names the wrong object stream), is charged again in full, so that
    /// such a chain cannot make the store decode the same containers over and over for free.
    fn objstm_charge(dropped: bool, extends: bool) -> Charge {
        if dropped && extends {
            Charge::Again
        } else {
            Charge::Once
        }
    }

    /// The object stream `num` without waiting on its cache: the cached container if it is
    /// ready, else a private decode (or an error on a cycle). The flag and `extends` are those
    /// of [`Store::objstm`].
    ///
    /// A private decode whose result does not depend on the call path (see [`Chain::refused`])
    /// goes into the cache, unless a blocking load is filling the entry already, so a container
    /// that many nested loads need before anything resolves one of its objects (a shared
    /// indirect `/Length` inside it, say) is decoded once, not once per load: that keeps
    /// resolving every object linear. Such an entry was decoded quietly; the first blocking load
    /// decodes the container again to report its diagnostics (see [`ObjStmCache::cell`]).
    fn peek_objstm(
        &self,
        num: u32,
        chain: &Chain<'_>,
        extends: bool,
    ) -> Result<(Arc<ObjStm>, bool)> {
        self.check_container(num)?;
        let (cached, dropped) = {
            let mut cache = lock(&self.objstm_cache);
            (cache.filled(num), cache.was_evicted(num))
        };
        if let Some(done) = cached {
            return Ok((done?, false));
        }
        if chain.refuses(num, self.max_nested()) {
            return Err(Error::new(
                ErrorCode::Syntax,
                format!("object stream {num} is needed to load itself"),
            ));
        }
        let refused = Cell::new(false);
        let charge = Self::objstm_charge(dropped, extends);
        let decoded = self.decode_objstm(num, &chain.push(num, &refused), true, charge);
        if refused.get() {
            chain.refuse();
        } else {
            lock(&self.objstm_cache).insert_quiet(num, decoded.clone(), self.objstm_cache_budget());
        }
        // A decode that depended on the call path is no basis for settling the objects.
        Ok((decoded?, dropped && !refused.get()))
    }

    /// An object stream must be an uncompressed object (it is a stream, §7.5.7). Checking this
    /// first also guarantees that loading a container never waits on another container.
    fn check_container(&self, num: u32) -> Result<()> {
        match self.location(num) {
            Some(Location::InFile { .. }) => Ok(()),
            _ => Err(Error::new(
                ErrorCode::Syntax,
                format!("object stream {num} is not an uncompressed object in the file"),
            )),
        }
    }

    /// Decodes and validates object stream `num`, within [`Limits::max_objstm_decoded`].
    /// `chain` contains `num`; references in the container's dictionary are only peeked (see
    /// [`Chain`]).
    fn decode_objstm(
        &self,
        num: u32,
        chain: &Chain<'_>,
        quiet: bool,
        charge: Charge,
    ) -> Result<Arc<ObjStm>> {
        let cap = self.limits().effective_objstm_decoded();
        #[cfg(test)]
        self.objstm_decodes.fetch_add(1, Ordering::Relaxed);
        self.build_objstm(num, chain, quiet, cap, charge)?
            .map(Arc::new)
            .ok_or_else(|| Error::limit(LimitKind::MaxObjStmDecoded, cap as u64, None))
    }

    /// Decodes object stream `num` for a reconstruction (its member list): quietly, without
    /// caching it, and within what is left of the reconstruction's decoding budget
    /// ([`repair::reconstruct_budget`]). `None` when it cannot be read, or when it does not fit
    /// (reported once).
    pub(crate) fn reconstruction_objstm(&self, num: u32) -> Option<ObjStm> {
        let left = self.reconstruct_budget.load(Ordering::Relaxed);
        if left == 0 || self.check_container(num).is_err() {
            return None;
        }
        let own = self.limits().effective_objstm_decoded();
        let cap = usize::try_from(left).unwrap_or(usize::MAX).min(own);
        match self.build_objstm(num, &Chain::root(num), true, cap, Charge::Once) {
            Ok(Some(stm)) => {
                let used = (stm.decoded_len() as u64).min(left);
                self.reconstruct_budget.fetch_sub(used, Ordering::Relaxed);
                Some(stm)
            }
            // Too large for any object stream: skipped, the work it cost charged.
            Ok(None) if (cap as u64) < left => {
                self.reconstruct_budget
                    .fetch_sub(cap as u64, Ordering::Relaxed);
                self.note(DiagnosticKind::ObjectStream, None, || {
                    format!(
                        "object stream {num} decodes to more than max_objstm_decoded ({cap} \
                         bytes); it was not searched"
                    )
                });
                None
            }
            Ok(None) => {
                self.reconstruct_budget.store(0, Ordering::Relaxed);
                self.note(DiagnosticKind::ObjectStream, None, || {
                    format!(
                        "object stream {num} decodes to more than the {left} bytes left for \
                         reconstructing the file; it and any later object streams were not \
                         searched"
                    )
                });
                None
            }
            Err(_) => None,
        }
    }

    /// Decodes and validates object stream `num`, with at most `cap` decoded bytes (`None` when
    /// the data is longer).
    fn build_objstm(
        &self,
        num: u32,
        chain: &Chain<'_>,
        quiet: bool,
        cap: usize,
        charge: Charge,
    ) -> Result<Option<ObjStm>> {
        let slot = self.slot(num).ok_or_else(|| {
            Error::new(ErrorCode::Syntax, format!("object stream {num} is missing"))
        })?;
        let id = ObjectId::new(num, slot.r#gen);
        let object = if quiet {
            match slot.parsed.get() {
                Some(Ok(done)) => Arc::clone(done),
                Some(Err(err)) => return Err((**err).clone()),
                None => Arc::new(self.load(slot, chain, Mode::Peek(chain), true)?),
            }
        } else {
            // The source's container, whatever an edit made of its object.
            self.resolve_source(id)?
        };
        let Object::Stream(stream) = &*object else {
            return Err(Error::new(
                ErrorCode::Syntax,
                format!(
                    "object stream {id} is a {}, not a stream",
                    object.type_name()
                ),
            ));
        };
        if !stream.dict.is_type(keys::OBJ_STM) {
            self.recover_as(
                quiet,
                ErrorCode::Syntax,
                DiagnosticKind::ObjectStream,
                None,
                || format!("object stream {id} has no /Type /ObjStm"),
            )?;
        }
        let mode = Mode::Peek(chain);
        let int = |key: &[u8]| -> Result<Option<i64>> {
            Ok(match stream.dict.get(key) {
                Some(value) => self.value(value, mode)?.as_int(),
                None => None,
            })
        };
        let header = ObjStmHeader {
            n: int(keys::N)?,
            first: int(keys::FIRST)?,
            extends: match stream.dict.get(keys::EXTENDS) {
                Some(Object::Ref(r)) => Some(*r),
                _ => None,
            },
        };
        let Some(decoded) = self.decode_capped(stream, mode, quiet, cap, charge)? else {
            return Ok(None);
        };
        if !decoded.remaining.is_empty() {
            return Err(Error::new(
                ErrorCode::Syntax,
                format!("object stream {id} uses an image filter"),
            ));
        }
        let repair = |message: String| {
            self.recover_as(
                quiet,
                ErrorCode::Syntax,
                DiagnosticKind::ObjectStream,
                None,
                || message,
            )
        };
        // A container cannot usefully list more objects than the store keeps.
        let len = self.bytes().len() as u64;
        let (limit, max_members) = self.limits().object_cap(len);
        let members = usize::try_from(max_members).unwrap_or(usize::MAX);
        let stm = ObjStm::parse(num, header, decoded.data, members, &repair)?;
        if stm.capped {
            if self.is_strict() {
                return Err(Error::limit(limit, max_members, None));
            }
            if !quiet {
                self.note(DiagnosticKind::ObjectStream, None, || {
                    format!(
                        "object stream {id} lists more than {max_members} objects, more than a \
                         file of {len} bytes can hold; the others are ignored"
                    )
                });
            }
        }
        Ok(Some(stm))
    }

    // ---- non-blocking loads -------------------------------------------------------------------

    /// Follows `id` through references without waiting on any cache (see [`Chain`]). Returns
    /// `None` for a cycle on the current call path, a chain that is too deep, or an object that
    /// cannot be loaded. Used for indirect `/Length` values (so the parser falls back to
    /// scanning for `endstream`) and for references inside stream dictionaries.
    ///
    /// An object that is not cached yet is loaded privately (quietly: the blocking load that
    /// fills its slot reports its diagnostics). When that load did not depend on the call path,
    /// its result goes into the peek memo, so that many streams sharing one indirect `/Length`
    /// that nothing has resolved yet cost one private load, not one each: without it, resolving
    /// every object of such a file would be quadratic.
    fn peek_deref(&self, id: ObjectId, chain: &Chain<'_>) -> Option<Arc<Object>> {
        if chain.refuses(id.num, self.max_nested()) {
            return None;
        }
        let slot = self.slot_of(id)?;
        if slot.r#gen != id.r#gen {
            return Some(self.null());
        }
        let refused = Cell::new(false);
        let link = chain.push(id.num, &refused);
        let object = match slot.parsed.get() {
            Some(Ok(done)) => Some(Arc::clone(done)),
            Some(Err(_)) => None,
            None => {
                // What a blocking settle left for the slot's first load (which takes it), or
                // else what an earlier nested load found.
                let settled = match slot.loc {
                    Location::InObjStm { .. } => lock(&self.settled)
                        .get(&slot.num)
                        .map(|done| done.as_ref().ok().map(Arc::clone)),
                    Location::InFile { .. } => None,
                };
                let memo = settled.or_else(|| lock(&self.peeked_objects).get(&id).cloned());
                match memo {
                    Some(done) => done,
                    None => {
                        let loaded = self
                            .load(slot, &link, Mode::Peek(&link), true)
                            .ok()
                            .map(Arc::new);
                        if !refused.get() {
                            lock(&self.peeked_objects)
                                .entry(id)
                                .or_insert_with(|| loaded.clone());
                        }
                        loaded
                    }
                }
            }
        };
        let resolved = object.and_then(|object| match &*object {
            Object::Ref(next) => self.peek_deref(*next, &link),
            _ => Some(object),
        });
        if refused.get() {
            chain.refuse();
        }
        resolved
    }

    /// The bound on nested loads: [`Limits::max_ref_chain`], at most [`MAX_NESTED_LOADS`].
    fn max_nested(&self) -> u16 {
        self.limits().max_ref_chain.min(MAX_NESTED_LOADS)
    }

    /// Resolves `obj` for use inside the store: blocking for public entry points, peeking for
    /// loads that may run inside a cache's initialisation.
    fn value<'a>(&self, obj: &'a Object, mode: Mode<'_>) -> Result<Resolved<'a>> {
        match (obj, mode) {
            (Object::Ref(_), Mode::Blocking) => self.deref(obj),
            (Object::Ref(id), Mode::Peek(chain)) => Ok(Resolved::Indirect(
                self.peek_deref(*id, chain).unwrap_or_else(|| self.null()),
            )),
            _ => Ok(Resolved::Direct(obj)),
        }
    }

    // ---- stream data --------------------------------------------------------------------------

    /// The raw (still encoded) data of `stream`: a slice of the source for
    /// [`StreamData::Source`], the owned bytes otherwise ([`StreamData::Decoded`] data is
    /// already plain).
    ///
    /// # Errors
    /// [`ErrorCode::InvalidArgument`] when a source range lies outside this store's source (the
    /// stream belongs to another document).
    pub fn raw_stream_data<'a>(&'a self, stream: &'a Stream) -> Result<Cow<'a, [u8]>> {
        match &stream.data {
            StreamData::Source(range) => {
                let bytes = self.bytes();
                usize::try_from(range.start)
                    .ok()
                    .zip(usize::try_from(range.end).ok())
                    .and_then(|(start, end)| bytes.get(start..end))
                    .map(Cow::Borrowed)
                    .ok_or_else(|| {
                        Error::invalid_argument(format!(
                            "stream data range {}..{} is outside the source ({} bytes)",
                            range.start,
                            range.end,
                            bytes.len()
                        ))
                    })
            }
            StreamData::Encoded(data) | StreamData::Decoded(data) => Ok(Cow::Borrowed(data)),
        }
    }

    /// The data of `stream`, decoded through its `/Filter` chain (§7.3.8, §7.4).
    ///
    /// Decoding stops at the first image filter (DCT, JPX, JBIG2, CCITT); the rest of the chain
    /// is returned in [`StreamBytes::remaining`]. `/DecodeParms` may be a dictionary, an array
    /// with `null` entries, or absent; references in either are resolved. A `/Crypt` filter
    /// other than `/Identity` cannot apply to an unencrypted document; it is treated as the
    /// identity with a diagnostic. [`StreamData::Decoded`] data is returned as is.
    ///
    /// # Errors
    /// - [`ErrorCode::LimitExceeded`] when the result would exceed
    ///   [`Limits::max_decoded_stream`], or the document's streams decoded so far (each counted
    ///   once, see [`Store::total_decoded`]) would exceed [`Limits::max_total_decoded`].
    /// - [`ErrorCode::Filter`] for corrupt data or invalid `/DecodeParms`, and in strict mode for
    ///   truncated data.
    /// - [`ErrorCode::Unsupported`] for an unknown filter name.
    /// - The errors of [`Store::raw_stream_data`] and [`Store::deref`].
    pub fn stream_data(&self, stream: &Stream) -> Result<StreamBytes> {
        self.decode_internal(stream, Mode::Blocking, false)
    }

    pub(crate) fn decode_internal(
        &self,
        stream: &Stream,
        mode: Mode<'_>,
        quiet: bool,
    ) -> Result<StreamBytes> {
        // Without a cap of its own, the decode never stops at one.
        self.decode_capped(stream, mode, quiet, usize::MAX, Charge::Once)?
            .ok_or_else(|| {
                Error::limit(
                    LimitKind::MaxDecodedStream,
                    self.limits().max_decoded_stream as u64,
                    None,
                )
            })
    }

    /// [`Store::stream_data`] with an output cap of the caller's own: `Ok(None)` when the data
    /// would decode to more than `cap` bytes (and `cap` is below the limits). `charge` says how
    /// the decode counts against [`Limits::max_total_decoded`].
    pub(crate) fn decode_capped(
        &self,
        stream: &Stream,
        mode: Mode<'_>,
        quiet: bool,
        cap: usize,
        charge: Charge,
    ) -> Result<Option<StreamBytes>> {
        if let StreamData::Decoded(data) = &stream.data {
            return Ok((data.len() <= cap).then(|| StreamBytes {
                data: data.clone(),
                remaining: Vec::new(),
                truncated: false,
            }));
        }
        let (offset, key) = match &stream.data {
            StreamData::Source(range) => (Some(range.start), Some((range.start, range.end))),
            _ => (None, None),
        };
        let raw = self.raw_stream_data(stream)?;
        let chain = self.filter_chain(&stream.dict, mode, quiet, offset)?;

        let limits = self.limits();
        let per_stream = limits.max_decoded_stream;
        // Only the source's own streams count against the total, each once (see
        // `total_decoded`): what this stream was already charged is available to it again,
        // unless the decode is charged again in full.
        let total = match key {
            Some(key) => {
                let charged = match charge {
                    Charge::Once => lock(&self.charged).get(&key).copied().unwrap_or(0),
                    Charge::Again => 0,
                };
                let left = limits
                    .max_total_decoded
                    .saturating_sub(self.total_decoded())
                    .saturating_add(charged);
                usize::try_from(left).unwrap_or(usize::MAX)
            }
            None => usize::MAX,
        };
        let limit = per_stream.min(total).min(cap);
        let total_limit =
            || Error::limit(LimitKind::MaxTotalDecoded, limits.max_total_decoded, offset);
        let output = match decode_chain(&chain, &raw, &DecodeLimits::new(limit)) {
            Ok(output) => output,
            // `filter_chain` already bounds the chain length, so this is the output cap. The
            // decoder produced that much before it stopped: charge it, so that many bombs
            // cannot each cost a full decode for free.
            Err(FilterError::LimitExceeded { .. }) => {
                if let Some(key) = key {
                    self.charge(key, limit as u64, charge);
                }
                return if cap < per_stream.min(total) {
                    Ok(None)
                } else if total < per_stream {
                    Err(total_limit())
                } else {
                    Err(Error::limit(
                        LimitKind::MaxDecodedStream,
                        per_stream as u64,
                        offset,
                    ))
                };
            }
            Err(source) => return Err(Error::Filter { offset, source }),
        };
        if let Some(key) = key
            && self.charge(key, output.data.len() as u64, charge) > limits.max_total_decoded
        {
            return Err(total_limit());
        }
        if output.truncated {
            self.recover_as(
                quiet,
                ErrorCode::Filter,
                DiagnosticKind::FilterTruncated,
                offset,
                || {
                    format!(
                        "stream data is truncated or corrupt; {} bytes decoded",
                        output.data.len()
                    )
                },
            )?;
        }
        Ok(Some(StreamBytes {
            data: output.data,
            remaining: output.remaining,
            truncated: output.truncated,
        }))
    }

    /// Charges `produced` decoded bytes of the source stream `key` (its data range) to
    /// [`Limits::max_total_decoded`]: with [`Charge::Once`] only what goes beyond the most an
    /// earlier decode of it produced, with [`Charge::Again`] all of it. Returns the new total.
    fn charge(&self, key: (u64, u64), produced: u64, charge: Charge) -> u64 {
        let delta = {
            let mut charged = lock(&self.charged);
            let entry = charged.entry(key).or_insert(0);
            let delta = match charge {
                Charge::Once => produced.saturating_sub(*entry),
                Charge::Again => produced,
            };
            *entry = (*entry).max(produced);
            delta
        };
        self.total_decoded
            .fetch_add(delta, Ordering::Relaxed)
            .saturating_add(delta)
    }

    /// Reads `/Filter` and `/DecodeParms` into a filter chain (§7.3.8.2, Table 5).
    fn filter_chain(
        &self,
        dict: &Dict,
        mode: Mode<'_>,
        quiet: bool,
        offset: Option<u64>,
    ) -> Result<Vec<(Filter, FilterParams)>> {
        let invalid = |detail: String| Error::Filter {
            offset,
            source: FilterError::InvalidParams { detail },
        };
        let filter_value = match dict.get(keys::FILTER) {
            Some(value) => Some(self.value(value, mode)?),
            None => None,
        };
        let names: Vec<Name> = match filter_value.as_deref() {
            None | Some(Object::Null) => return Ok(Vec::new()),
            Some(Object::Name(name)) => vec![name.clone()],
            Some(Object::Array(items)) => {
                if items.len() > DecodeLimits::DEFAULT_MAX_CHAIN_LEN {
                    return Err(Error::Filter {
                        offset,
                        source: FilterError::LimitExceeded {
                            limit: DecodeLimits::DEFAULT_MAX_CHAIN_LEN,
                        },
                    });
                }
                let mut names = Vec::with_capacity(items.len());
                for item in items {
                    match &*self.value(item, mode)? {
                        Object::Name(name) => names.push(name.clone()),
                        other => {
                            return Err(Error::Other {
                                code: ErrorCode::Filter,
                                offset,
                                message: format!(
                                    "/Filter array holds a {}, not a name",
                                    other.type_name()
                                )
                                .into(),
                            });
                        }
                    }
                }
                names
            }
            Some(other) => {
                return Err(Error::Other {
                    code: ErrorCode::Filter,
                    offset,
                    message: format!("/Filter is a {}, not a name or array", other.type_name())
                        .into(),
                });
            }
        };

        let parms_value = match dict.get(keys::DECODE_PARMS) {
            Some(value) => Some(self.value(value, mode)?),
            None => None,
        };
        let mut chain = Vec::with_capacity(names.len());
        for (i, name) in names.iter().enumerate() {
            let filter = Filter::from_name(name.as_bytes())
                .ok_or_else(|| Error::unsupported(format!("unknown stream filter {name}")))?;
            // §7.3.8.2: one dictionary for a single filter, or an array with one entry (a
            // dictionary or null) per filter. A lone dictionary with several filters is applied
            // to each; only Flate and LZW read these parameters.
            let parms: Option<Resolved<'_>> = match parms_value.as_deref() {
                None | Some(Object::Null) => None,
                Some(Object::Dict(_)) => parms_value.clone(),
                Some(Object::Array(items)) => match items.get(i) {
                    None => None,
                    Some(item) => match self.value(item, mode)? {
                        resolved if resolved.is_null() => None,
                        resolved if resolved.as_dict().is_some() => Some(resolved),
                        other => {
                            return Err(invalid(format!(
                                "/DecodeParms entry {i} is a {}, not a dictionary or null",
                                other.type_name()
                            )));
                        }
                    },
                },
                Some(other) => {
                    return Err(invalid(format!(
                        "/DecodeParms is a {}, not a dictionary or array",
                        other.type_name()
                    )));
                }
            };
            let parms = parms.as_ref().and_then(|p| p.as_dict());
            let params = self.filter_params(filter, parms, mode, offset)?;
            if filter == Filter::Crypt {
                // §7.4.10: without /Name, the crypt filter is /Identity.
                let crypt = parms.and_then(|p| p.get_name(b"Name").cloned());
                if let Some(crypt) = crypt.filter(|n| n != b"Identity") {
                    self.recover_as(
                        quiet,
                        ErrorCode::Filter,
                        DiagnosticKind::CryptFilterIgnored,
                        offset,
                        || {
                            format!(
                                "crypt filter {crypt} in an unencrypted document; treated as \
                                 identity"
                            )
                        },
                    )?;
                }
            }
            chain.push((filter, params));
        }
        Ok(chain)
    }

    /// Converts one `/DecodeParms` dictionary (Table 8) into [`FilterParams`].
    fn filter_params(
        &self,
        filter: Filter,
        parms: Option<&Dict>,
        mode: Mode<'_>,
        offset: Option<u64>,
    ) -> Result<FilterParams> {
        let mut params = FilterParams::new();
        let Some(parms) = parms.filter(|_| filter.supports_predictor()) else {
            return Ok(params);
        };
        let invalid = |detail: String| Error::Filter {
            offset,
            source: FilterError::InvalidParams { detail },
        };
        let int = |key: &str| -> Result<Option<i64>> {
            let Some(value) = parms.get(key.as_bytes()) else {
                return Ok(None);
            };
            match &*self.value(value, mode)? {
                Object::Null => Ok(None),
                Object::Int(n) => Ok(Some(*n)),
                other => Err(invalid(format!(
                    "/{key} is a {}, not an integer",
                    other.type_name()
                ))),
            }
        };
        let ranged = |key: &str, value: i64| invalid(format!("/{key} {value} is out of range"));
        if let Some(v) = int("Predictor")? {
            params = params.with_predictor(u8::try_from(v).map_err(|_| ranged("Predictor", v))?);
        }
        if let Some(v) = int("Colors")? {
            params = params.with_colors(u8::try_from(v).map_err(|_| ranged("Colors", v))?);
        }
        if let Some(v) = int("BitsPerComponent")? {
            params = params.with_bits_per_component(
                u8::try_from(v).map_err(|_| ranged("BitsPerComponent", v))?,
            );
        }
        if let Some(v) = int("Columns")? {
            params = params.with_columns(u32::try_from(v).map_err(|_| ranged("Columns", v))?);
        }
        if filter == Filter::Lzw
            && let Some(v) = int("EarlyChange")?
        {
            params = params.with_early_change(match v {
                0 => false,
                1 => true,
                _ => return Err(ranged("EarlyChange", v)),
            });
        }
        Ok(params)
    }

    // ---- internals shared with xref.rs and repair.rs ------------------------------------------

    pub(crate) fn bytes(&self) -> &[u8] {
        AsRef::<[u8]>::as_ref(&*self.source)
    }

    pub(crate) fn is_strict(&self) -> bool {
        self.options.strictness == Strictness::Strict
    }

    /// A parse context with the store's limits and strictness, reporting to the store's
    /// diagnostics unless `quiet`.
    pub(crate) fn parse_ctx(&self, quiet: bool) -> ParseCtx<'_> {
        let ctx = ParseCtx::new(self.options.limits, self.options.strictness);
        if quiet {
            ctx
        } else {
            ctx.with_diagnostics(&self.diagnostics)
        }
    }

    /// Parses the indirect object at absolute position `pos` of the source within
    /// `source[..end]` (cross-reference streams). An indirect `/Length` is only peeked.
    pub(crate) fn parse_source_object(
        &self,
        pos: usize,
        end: usize,
        quiet: bool,
    ) -> Result<IndirectObject> {
        let bytes = self.bytes();
        let region = bytes.get(..end).unwrap_or(bytes);
        let keywords = LazyKeywords(self);
        let ctx = self.parse_ctx(quiet).with_keyword_index(&keywords);
        let lengths = |r: ObjectId| self.peek_deref(r, &Chain::EMPTY)?.as_int();
        let parsed = parse_indirect_at(region, pos, &ctx, &lengths)?;
        self.count_parse();
        Ok(parsed)
    }

    /// The scan of the whole source, built on first use.
    pub(crate) fn scan_index(&self) -> &ScanIndex {
        self.scan.get_or_init(|| repair::scan(self.bytes()))
    }

    /// The object definitions among the scan's headers (see [`repair::definitions`]), derived
    /// on first use. Neither this nor the scan waits on a slot or a container, so both may be
    /// built inside a slot's initialisation.
    pub(crate) fn definitions(&self) -> &Definitions {
        self.definitions
            .get_or_init(|| repair::definitions(self.bytes(), self.scan_index(), self.limits()))
    }

    fn count_parse(&self) {
        self.parsed_objects.fetch_add(1, Ordering::Relaxed);
    }

    /// Applies the leniency policy to a repairable problem: a diagnostic in lenient mode, an
    /// error with `code` in strict mode.
    pub(crate) fn recover(
        &self,
        code: ErrorCode,
        kind: DiagnosticKind,
        offset: Option<u64>,
        message: impl FnOnce() -> String,
    ) -> Result<()> {
        self.recover_as(false, code, kind, offset, message)
    }

    /// [`Store::recover`], without recording the diagnostic when `quiet`.
    pub(crate) fn recover_as(
        &self,
        quiet: bool,
        code: ErrorCode,
        kind: DiagnosticKind,
        offset: Option<u64>,
        message: impl FnOnce() -> String,
    ) -> Result<()> {
        match self.options.strictness {
            Strictness::Strict => Err(match code {
                ErrorCode::Xref => Error::Xref {
                    offset,
                    message: message().into(),
                },
                ErrorCode::Syntax if offset.is_some() => {
                    Error::syntax(offset.unwrap_or_default(), message())
                }
                code => Error::Other {
                    code,
                    offset,
                    message: message().into(),
                },
            }),
            Strictness::Lenient => {
                if !quiet {
                    self.diagnostics
                        .report(Diagnostic::new(kind, offset, message()));
                }
                Ok(())
            }
        }
    }

    /// [`Store::recover_as`] for a repair of the cross-reference structure (an
    /// [`ErrorCode::Xref`] in strict mode), which also sets [`Store::structure_repaired`]
    /// unless `quiet`.
    pub(crate) fn recover_structure(
        &self,
        quiet: bool,
        kind: DiagnosticKind,
        offset: Option<u64>,
        message: impl FnOnce() -> String,
    ) -> Result<()> {
        if !quiet {
            self.structure_repaired.store(true, Ordering::Relaxed);
        }
        self.recover_as(quiet, ErrorCode::Xref, kind, offset, message)
    }

    /// [`Store::recover_limit`] for a limit that cuts the cross-reference structure, which also
    /// sets [`Store::structure_repaired`] unless `quiet`.
    pub(crate) fn recover_structure_limit(
        &self,
        quiet: bool,
        kind: DiagnosticKind,
        limit: LimitKind,
        max: u64,
        message: impl FnOnce() -> String,
    ) -> Result<()> {
        if self.is_strict() {
            return Err(Error::limit(limit, max, None));
        }
        if !quiet {
            self.structure_repaired.store(true, Ordering::Relaxed);
            self.note(kind, None, message);
        }
        Ok(())
    }

    /// [`Store::note`] for a cross-reference section that was skipped, which also sets
    /// [`Store::structure_repaired`].
    pub(crate) fn note_structure(
        &self,
        kind: DiagnosticKind,
        offset: Option<u64>,
        message: impl FnOnce() -> String,
    ) {
        self.structure_repaired.store(true, Ordering::Relaxed);
        self.note(kind, offset, message);
    }

    /// Applies the policy to an exceeded limit whose excess can be dropped: a diagnostic in
    /// lenient mode, [`ErrorCode::LimitExceeded`] in strict mode.
    pub(crate) fn recover_limit(
        &self,
        kind: DiagnosticKind,
        limit: LimitKind,
        max: u64,
        message: impl FnOnce() -> String,
    ) -> Result<()> {
        if self.is_strict() {
            return Err(Error::limit(limit, max, None));
        }
        self.note(kind, None, message);
        Ok(())
    }

    /// Records a diagnostic in either mode (for situations that are not errors).
    pub(crate) fn note(
        &self,
        kind: DiagnosticKind,
        offset: Option<u64>,
        message: impl FnOnce() -> String,
    ) {
        self.diagnostics
            .report(Diagnostic::new(kind, offset, message()));
    }
}

/// Locks one of the store's memo maps. A panic while the lock is held cannot leave a map
/// inconsistent (every update is a single insert), so a poisoned lock is simply recovered.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The generation of the object an in-use entry stands for (0 for a compressed one, §7.5.7).
fn entry_generation(entry: XrefEntry) -> u16 {
    match entry {
        XrefEntry::InFile { r#gen, .. } => r#gen,
        _ => 0,
    }
}

/// Re-labels an error from parsing inside object stream `stream`: its offset is relative to the
/// decoded container, so it is dropped and the context is added to the message.
fn in_container(err: Error, id: ObjectId, stream: u32) -> Error {
    match err {
        Error::LimitExceeded { limit, max, .. } => Error::LimitExceeded {
            limit,
            max,
            offset: None,
        },
        other => Error::Other {
            code: other.code(),
            offset: None,
            message: format!("object {id} in object stream {stream}: {other}").into(),
        },
    }
}

#[cfg(test)]
mod tests;

//! Resource limits for hostile input (ARCHITECTURE §A.3).
//!
//! Every allocation, recursion and loop whose size is driven by file contents is bounded by one of
//! the fields of [`Limits`], or by a budget derived from them and the length of the file (see
//! [`Limits::budget`]). The defaults are safe for untrusted files and generous enough for every
//! real-world document we know of; callers that process trusted, unusually large or dense files
//! can raise them through [`Limits`]'s `with_*` setters and [`Limits::budget_scale`].
//!
//! # Budgets derived from the file length
//!
//! A hostile file can claim far more structure than its bytes can hold (millions of
//! cross-reference rows in a few kilobytes of compressed data, say). Some bounds are therefore
//! proportional to the file's length, with a floor for small files, and multiplied by
//! [`Limits::budget_scale`]:
//!
//! | Budget ([`LimitKind`]) | Value for a file of `len` bytes | Bounds |
//! |---|---|---|
//! | [`LimitKind::XrefEntries`] | `max(2^20, 4 × len)` | cross-reference entries read, all sections together |
//! | [`LimitKind::XrefBytes`] | `max(1 MiB, 4 × len)` | bytes parsed reading cross-reference sections and trailers |
//! | [`LimitKind::ObjectCap`] | `min(max_objects, max(4096, len))` | in-use objects kept (and members of one object stream) |
//! | [`LimitKind::ReconstructDecoded`] | `max(16 MiB, 16 × len)` | object-stream bytes a reconstruction decodes |
//! | [`LimitKind::ObjStmParsed`] | `max(64 MiB, 128 × len)` | memory of the objects parsed from object streams |
//!
//! Exceeding one is reported under its own [`LimitKind`] (a diagnostic in lenient mode where the
//! excess can be dropped, [`ErrorCode::LimitExceeded`](crate::ErrorCode::LimitExceeded)
//! otherwise), so the message names the budget, not a field the caller did not set.

use core::fmt;

/// Resource limits applied while reading a document.
///
/// The struct is `#[non_exhaustive]` so new limits can be added without breaking callers: start
/// from [`Limits::default()`] and adjust single fields, either by assignment or with the `with_*`
/// setters.
///
/// ```
/// use folioxide_syntax::Limits;
///
/// let limits = Limits::default().with_max_nesting_depth(64);
/// assert_eq!(limits.max_nesting_depth, 64);
/// assert_eq!(limits.max_objects, 10_000_000);
/// assert_eq!(limits.max_objstm_cache, 64 << 20);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase", default)
)]
pub struct Limits {
    /// Maximum number of objects in a document: object numbers at or above it are ignored.
    /// Default 10,000,000.
    ///
    /// A file also cannot have more in-use objects than it has bytes: the store keeps at most
    /// [`LimitKind::ObjectCap`] = `min(max_objects, max(4096, file length))` of them, and its
    /// cross-reference reader reads at most [`LimitKind::XrefEntries`] entries over all sections
    /// together (see [`Limits::budget`]). One in-use object costs the store about 50 bytes; free
    /// entries cost nothing.
    pub max_objects: u32,
    /// Maximum nesting depth of arrays and dictionaries, for the parser and for every recursive
    /// walker over objects. Default 256; at most [`Limits::MAX_NESTING_DEPTH`].
    ///
    /// `Object`'s `Clone`, `Drop`, `PartialEq` and `Debug` recurse once per level, so the depth
    /// the parser accepts is clamped to [`Limits::MAX_NESTING_DEPTH`] (512) whatever this field
    /// says: a deeper limit would let a file make them overflow the stack. At that depth they
    /// need about 200 KiB of stack in release builds (about 600 KiB in debug builds).
    pub max_nesting_depth: u16,
    /// Maximum decoded size of a single stream, in bytes (Flate and LZW bombs).
    /// Default 512 MiB.
    pub max_decoded_stream: usize,
    /// Maximum total number of decoded bytes of the document's streams. Default 4 GiB.
    ///
    /// Each stream of the file counts once (with the most bytes any decode of it produced, or
    /// the bytes a decode that stopped at a limit was allowed), so decoding the same stream again
    /// costs nothing more and a long-lived store does not run out; a file with many
    /// decompression bombs still stops here. Streams whose data the caller supplies are bounded
    /// by [`Limits::max_decoded_stream`] only. See `Store::total_decoded`.
    pub max_total_decoded: u64,
    /// Maximum number of cross-reference sections followed through `/Prev` and `/XRefStm`.
    /// Default 4096.
    ///
    /// The sections together may also not take more than [`LimitKind::XrefBytes`] bytes to
    /// read (sections that overlap, or trailers that never end; see [`Limits::budget`]).
    pub max_xref_sections: u32,
    /// Maximum depth of the page tree. Default 64.
    pub max_page_tree_depth: u16,
    /// Maximum decoded length of a single string or name token, in bytes. Default 128 MiB.
    pub max_string_len: usize,
    /// Maximum number of pixels in an image (checked with `checked_mul` on width × height ×
    /// components × bits per component). Default 2^28.
    pub max_image_pixels: u64,
    /// Maximum length of a chain of references followed to reach a value, for example an
    /// indirect `/Length`. Default 32.
    pub max_ref_chain: u16,
    /// Maximum number of diagnostics recorded per document; further ones are counted but not
    /// stored, so a file full of small defects cannot exhaust memory. Default 10,000.
    pub max_diagnostics: u32,
    /// Maximum decoded size of one object stream (§7.5.7), in bytes. Default 64 MiB (and at
    /// most [`Limits::max_decoded_stream`]).
    ///
    /// Writers put about 100 to 200 objects in one object stream, a few hundred kilobytes
    /// decoded. A container that decodes to more is refused: resolving one of its objects is
    /// [`ErrorCode::LimitExceeded`](crate::ErrorCode::LimitExceeded) in both modes. A container
    /// also lists at most [`LimitKind::ObjectCap`] members; the rest are ignored.
    pub max_objstm_decoded: usize,
    /// The decoded object streams the store keeps in memory, in bytes (their data and member
    /// tables together). Default 64 MiB.
    ///
    /// Object streams are decoded when one of their objects is first resolved, and kept for
    /// the objects after it. When a newly decoded one does not fit, the least recently used
    /// ones are dropped; a dropped container is decoded again when another of its objects is
    /// resolved, and then every object of it not resolved yet is parsed in the same pass, so a
    /// file cannot make the store decode the same container over and over, and a long-lived
    /// store with scattered access still counts each container once against
    /// [`Limits::max_total_decoded`]. The container in use is always kept, so the cache can
    /// briefly hold one container more.
    pub max_objstm_cache: usize,
    /// Multiplies every budget derived from the file length (see [`Limits::budget`]): the
    /// cross-reference entries and bytes read, the in-use objects kept (still at most
    /// [`Limits::max_objects`]), the object-stream bytes a reconstruction decodes, and the
    /// memory of the objects parsed from object streams. Default 1; 0 counts as 1.
    ///
    /// Raise it for trusted files whose structure is unusually dense for their size;
    /// `u32::MAX` effectively turns the derived budgets off.
    pub budget_scale: u32,
}

impl Limits {
    /// The highest [`Limits::max_nesting_depth`] that takes effect: deeper values are clamped to
    /// it (see the field).
    pub const MAX_NESTING_DEPTH: u16 = 512;

    /// The default limits, as a constant (identical to [`Limits::default()`]).
    pub const DEFAULT: Limits = Limits {
        max_objects: 10_000_000,
        max_nesting_depth: 256,
        max_decoded_stream: 512 * 1024 * 1024,
        max_total_decoded: 4 * 1024 * 1024 * 1024,
        max_xref_sections: 4096,
        max_page_tree_depth: 64,
        max_string_len: 128 * 1024 * 1024,
        max_image_pixels: 1 << 28,
        max_ref_chain: 32,
        max_diagnostics: 10_000,
        max_objstm_decoded: 64 * 1024 * 1024,
        max_objstm_cache: 64 * 1024 * 1024,
        budget_scale: 1,
    };

    /// Returns the default limits.
    pub const fn new() -> Self {
        Self::DEFAULT
    }

    /// Returns the value of the field `kind` names, widened to `u64`, or `None` for a budget
    /// derived from the file length (see [`Limits::budget`]).
    ///
    /// ```
    /// use folioxide_syntax::{LimitKind, Limits};
    ///
    /// assert_eq!(Limits::default().get(LimitKind::MaxNestingDepth), Some(256));
    /// assert_eq!(Limits::default().get(LimitKind::XrefEntries), None);
    /// ```
    pub const fn get(&self, kind: LimitKind) -> Option<u64> {
        Some(match kind {
            LimitKind::MaxObjects => self.max_objects as u64,
            LimitKind::MaxNestingDepth => self.max_nesting_depth as u64,
            LimitKind::MaxDecodedStream => self.max_decoded_stream as u64,
            LimitKind::MaxTotalDecoded => self.max_total_decoded,
            LimitKind::MaxXrefSections => self.max_xref_sections as u64,
            LimitKind::MaxPageTreeDepth => self.max_page_tree_depth as u64,
            LimitKind::MaxStringLen => self.max_string_len as u64,
            LimitKind::MaxImagePixels => self.max_image_pixels,
            LimitKind::MaxRefChain => self.max_ref_chain as u64,
            LimitKind::MaxDiagnostics => self.max_diagnostics as u64,
            LimitKind::MaxObjStmDecoded => self.max_objstm_decoded as u64,
            LimitKind::XrefEntries
            | LimitKind::XrefBytes
            | LimitKind::ObjectCap
            | LimitKind::ReconstructDecoded
            | LimitKind::ObjStmParsed => return None,
        })
    }

    /// The bound `kind` sets for a file of `file_len` bytes: the field's value for a configured
    /// limit, or the budget derived from the file length (see the [module docs](self)),
    /// multiplied by [`Limits::budget_scale`].
    ///
    /// ```
    /// use folioxide_syntax::{LimitKind, Limits};
    ///
    /// let limits = Limits::default();
    /// assert_eq!(limits.budget(LimitKind::XrefEntries, 1000), 1 << 20);
    /// assert_eq!(limits.budget(LimitKind::XrefEntries, 1 << 20), 4 << 20);
    /// assert_eq!(limits.budget(LimitKind::ObjectCap, 100), 4096);
    /// assert_eq!(limits.budget(LimitKind::ObjectCap, 1 << 30), 10_000_000);
    /// assert_eq!(limits.with_budget_scale(2).budget(LimitKind::XrefBytes, 1 << 20), 8 << 20);
    /// assert_eq!(limits.budget(LimitKind::MaxRefChain, 1 << 20), 32);
    /// ```
    pub const fn budget(&self, kind: LimitKind, file_len: u64) -> u64 {
        let (per_byte, floor) = match kind {
            LimitKind::XrefEntries => (XREF_ENTRIES_PER_BYTE, MIN_XREF_ENTRIES),
            LimitKind::XrefBytes => (XREF_BYTES_PER_BYTE, MIN_XREF_BYTES),
            LimitKind::ObjectCap => (1, MIN_OBJECT_CAP),
            LimitKind::ReconstructDecoded => (RECONSTRUCT_PER_BYTE, MIN_RECONSTRUCT),
            LimitKind::ObjStmParsed => (OBJSTM_PARSED_PER_BYTE, MIN_OBJSTM_PARSED),
            _ => {
                return match self.get(kind) {
                    Some(value) => value,
                    None => u64::MAX,
                };
            }
        };
        let base = file_len.saturating_mul(per_byte);
        let base = if base > floor { base } else { floor };
        let scale = if self.budget_scale == 0 {
            1
        } else {
            self.budget_scale as u64
        };
        let scaled = base.saturating_mul(scale);
        match kind {
            LimitKind::ObjectCap if scaled > self.max_objects as u64 => self.max_objects as u64,
            _ => scaled,
        }
    }

    /// The limit that bounds the in-use objects of a file of `file_len` bytes:
    /// [`LimitKind::MaxObjects`] when that field is the smaller bound, else
    /// [`LimitKind::ObjectCap`]; with its value.
    pub const fn object_cap(&self, file_len: u64) -> (LimitKind, u64) {
        let cap = self.budget(LimitKind::ObjectCap, file_len);
        if cap == self.max_objects as u64 {
            (LimitKind::MaxObjects, cap)
        } else {
            (LimitKind::ObjectCap, cap)
        }
    }

    /// The decoded size one object stream may have: [`Limits::max_objstm_decoded`], at most
    /// [`Limits::max_decoded_stream`] (and `u32::MAX`, as members are addressed by 32-bit
    /// offsets).
    pub const fn effective_objstm_decoded(&self) -> usize {
        let mut cap = self.max_objstm_decoded;
        if self.max_decoded_stream < cap {
            cap = self.max_decoded_stream;
        }
        if cap > u32::MAX as usize {
            cap = u32::MAX as usize;
        }
        cap
    }

    /// Sets [`Limits::max_objects`].
    #[must_use]
    pub const fn with_max_objects(mut self, value: u32) -> Self {
        self.max_objects = value;
        self
    }

    /// Sets [`Limits::max_nesting_depth`], clamped to [`Limits::MAX_NESTING_DEPTH`].
    ///
    /// ```
    /// use folioxide_syntax::Limits;
    ///
    /// assert_eq!(Limits::default().with_max_nesting_depth(u16::MAX).max_nesting_depth, 512);
    /// ```
    #[must_use]
    pub const fn with_max_nesting_depth(mut self, value: u16) -> Self {
        self.max_nesting_depth = if value > Self::MAX_NESTING_DEPTH {
            Self::MAX_NESTING_DEPTH
        } else {
            value
        };
        self
    }

    /// The nesting depth the parser enforces: [`Limits::max_nesting_depth`], at most
    /// [`Limits::MAX_NESTING_DEPTH`] (the field is public, so it can hold more).
    pub const fn effective_nesting_depth(&self) -> u16 {
        if self.max_nesting_depth > Self::MAX_NESTING_DEPTH {
            Self::MAX_NESTING_DEPTH
        } else {
            self.max_nesting_depth
        }
    }

    /// Sets [`Limits::max_decoded_stream`].
    #[must_use]
    pub const fn with_max_decoded_stream(mut self, value: usize) -> Self {
        self.max_decoded_stream = value;
        self
    }

    /// Sets [`Limits::max_total_decoded`].
    #[must_use]
    pub const fn with_max_total_decoded(mut self, value: u64) -> Self {
        self.max_total_decoded = value;
        self
    }

    /// Sets [`Limits::max_xref_sections`].
    #[must_use]
    pub const fn with_max_xref_sections(mut self, value: u32) -> Self {
        self.max_xref_sections = value;
        self
    }

    /// Sets [`Limits::max_page_tree_depth`].
    #[must_use]
    pub const fn with_max_page_tree_depth(mut self, value: u16) -> Self {
        self.max_page_tree_depth = value;
        self
    }

    /// Sets [`Limits::max_string_len`].
    #[must_use]
    pub const fn with_max_string_len(mut self, value: usize) -> Self {
        self.max_string_len = value;
        self
    }

    /// Sets [`Limits::max_image_pixels`].
    #[must_use]
    pub const fn with_max_image_pixels(mut self, value: u64) -> Self {
        self.max_image_pixels = value;
        self
    }

    /// Sets [`Limits::max_ref_chain`].
    #[must_use]
    pub const fn with_max_ref_chain(mut self, value: u16) -> Self {
        self.max_ref_chain = value;
        self
    }

    /// Sets [`Limits::max_diagnostics`].
    #[must_use]
    pub const fn with_max_diagnostics(mut self, value: u32) -> Self {
        self.max_diagnostics = value;
        self
    }

    /// Sets [`Limits::max_objstm_decoded`].
    #[must_use]
    pub const fn with_max_objstm_decoded(mut self, value: usize) -> Self {
        self.max_objstm_decoded = value;
        self
    }

    /// Sets [`Limits::max_objstm_cache`].
    #[must_use]
    pub const fn with_max_objstm_cache(mut self, value: usize) -> Self {
        self.max_objstm_cache = value;
        self
    }

    /// Sets [`Limits::budget_scale`].
    #[must_use]
    pub const fn with_budget_scale(mut self, value: u32) -> Self {
        self.budget_scale = value;
        self
    }
}

/// [`LimitKind::XrefEntries`]: entries per byte of the file...
const XREF_ENTRIES_PER_BYTE: u64 = 4;
/// ...and at least this many, for small files with sparse, highly compressed streams.
const MIN_XREF_ENTRIES: u64 = 1 << 20;
/// [`LimitKind::XrefBytes`]: source bytes parsed per byte of the file...
const XREF_BYTES_PER_BYTE: u64 = 4;
/// ...and at least this many.
const MIN_XREF_BYTES: u64 = 1 << 20;
/// [`LimitKind::ObjectCap`]: a file of fewer bytes may still have this many in-use objects.
const MIN_OBJECT_CAP: u64 = 4096;
/// [`LimitKind::ReconstructDecoded`]: decoded bytes per byte of the file (real object streams
/// compress their objects a few times)...
const RECONSTRUCT_PER_BYTE: u64 = 16;
/// ...and at least this many.
const MIN_RECONSTRUCT: u64 = 16 << 20;
/// [`LimitKind::ObjStmParsed`]: bytes of parsed objects per byte of the file. Files made of
/// nothing but object streams of page, annotation or structure dictionaries (Flate level 6)
/// take 25 to 55 per byte when every object is resolved; long, highly repetitive number arrays
/// come close to this; a decompression bomb of `0 0 0 ...` would take about 16,000.
const OBJSTM_PARSED_PER_BYTE: u64 = 128;
/// ...and at least this many.
const MIN_OBJSTM_PARSED: u64 = 64 << 20;

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Names one field of [`Limits`], or one budget derived from the limits and the file length
/// (see [`Limits::budget`]); carried by [`Error::LimitExceeded`](crate::Error::LimitExceeded).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum LimitKind {
    /// [`Limits::max_objects`].
    MaxObjects,
    /// [`Limits::max_nesting_depth`].
    MaxNestingDepth,
    /// [`Limits::max_decoded_stream`].
    MaxDecodedStream,
    /// [`Limits::max_total_decoded`].
    MaxTotalDecoded,
    /// [`Limits::max_xref_sections`].
    MaxXrefSections,
    /// [`Limits::max_page_tree_depth`].
    MaxPageTreeDepth,
    /// [`Limits::max_string_len`].
    MaxStringLen,
    /// [`Limits::max_image_pixels`].
    MaxImagePixels,
    /// [`Limits::max_ref_chain`].
    MaxRefChain,
    /// [`Limits::max_diagnostics`].
    MaxDiagnostics,
    /// [`Limits::max_objstm_decoded`].
    MaxObjStmDecoded,
    /// Derived: the cross-reference entries read over all sections, `max(2^20, 4 × len)`.
    XrefEntries,
    /// Derived: the bytes parsed reading cross-reference sections and trailers,
    /// `max(1 MiB, 4 × len)`.
    XrefBytes,
    /// Derived: the in-use objects kept (and the members of one object stream),
    /// `min(max_objects, max(4096, len))`.
    ObjectCap,
    /// Derived: the object-stream bytes a reconstruction decodes, `max(16 MiB, 16 × len)`.
    ReconstructDecoded,
    /// Derived: the memory of the objects parsed from object streams over the life of a
    /// store, `max(64 MiB, 128 × len)` (an estimate: the size of each value, plus the bytes of
    /// strings and names, plus the overhead of dictionary entries).
    ObjStmParsed,
}

impl LimitKind {
    /// Every limit kind, in declaration order.
    pub const ALL: &'static [LimitKind] = &[
        LimitKind::MaxObjects,
        LimitKind::MaxNestingDepth,
        LimitKind::MaxDecodedStream,
        LimitKind::MaxTotalDecoded,
        LimitKind::MaxXrefSections,
        LimitKind::MaxPageTreeDepth,
        LimitKind::MaxStringLen,
        LimitKind::MaxImagePixels,
        LimitKind::MaxRefChain,
        LimitKind::MaxDiagnostics,
        LimitKind::MaxObjStmDecoded,
        LimitKind::XrefEntries,
        LimitKind::XrefBytes,
        LimitKind::ObjectCap,
        LimitKind::ReconstructDecoded,
        LimitKind::ObjStmParsed,
    ];

    /// Whether this is a budget derived from the file length (scaled by
    /// [`Limits::budget_scale`]) rather than a field of [`Limits`].
    pub const fn is_derived(self) -> bool {
        matches!(
            self,
            LimitKind::XrefEntries
                | LimitKind::XrefBytes
                | LimitKind::ObjectCap
                | LimitKind::ReconstructDecoded
                | LimitKind::ObjStmParsed
        )
    }

    /// The name of the corresponding [`Limits`] field, for example `"max_nesting_depth"`, or of
    /// the derived budget, for example `"xref_entries"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            LimitKind::MaxObjects => "max_objects",
            LimitKind::MaxNestingDepth => "max_nesting_depth",
            LimitKind::MaxDecodedStream => "max_decoded_stream",
            LimitKind::MaxTotalDecoded => "max_total_decoded",
            LimitKind::MaxXrefSections => "max_xref_sections",
            LimitKind::MaxPageTreeDepth => "max_page_tree_depth",
            LimitKind::MaxStringLen => "max_string_len",
            LimitKind::MaxImagePixels => "max_image_pixels",
            LimitKind::MaxRefChain => "max_ref_chain",
            LimitKind::MaxDiagnostics => "max_diagnostics",
            LimitKind::MaxObjStmDecoded => "max_objstm_decoded",
            LimitKind::XrefEntries => "xref_entries",
            LimitKind::XrefBytes => "xref_bytes",
            LimitKind::ObjectCap => "object_cap",
            LimitKind::ReconstructDecoded => "reconstruct_decoded",
            LimitKind::ObjStmParsed => "objstm_parsed",
        }
    }
}

/// The name; a derived budget says so, and how to raise it, for example
/// `xref_entries (derived from the file length; raise Limits::budget_scale)`.
impl fmt::Display for LimitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())?;
        if self.is_derived() {
            f.write_str(" (derived from the file length; raise Limits::budget_scale)")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_architecture() {
        let l = Limits::default();
        assert_eq!(l.max_objects, 10_000_000);
        assert_eq!(l.max_nesting_depth, 256);
        assert_eq!(l.max_decoded_stream, 512 << 20);
        assert_eq!(l.max_total_decoded, 4 << 30);
        assert_eq!(l.max_xref_sections, 4096);
        assert_eq!(l.max_page_tree_depth, 64);
        assert_eq!(l.max_string_len, 128 << 20);
        assert_eq!(l.max_image_pixels, 1 << 28);
        assert_eq!(l.max_ref_chain, 32);
        assert_eq!(l.max_diagnostics, 10_000);
        assert_eq!(l.max_objstm_decoded, 64 << 20);
        assert_eq!(l.max_objstm_cache, 64 << 20);
        assert_eq!(l.budget_scale, 1);
        assert_eq!(l, Limits::new());
        assert_eq!(l, Limits::DEFAULT);
    }

    /// With the `serde` feature, limits use camelCase keys and missing keys take defaults.
    #[cfg(feature = "serde")]
    #[test]
    fn limits_deserialize_partially() {
        use serde::Deserialize;
        use serde::de::value::{Error as DeError, MapDeserializer};

        let entries = vec![("maxNestingDepth", 64u64), ("maxDiagnostics", 5)];
        let de = MapDeserializer::<_, DeError>::new(entries.into_iter());
        let limits = Limits::deserialize(de).unwrap();
        assert_eq!(
            limits,
            Limits::default()
                .with_max_nesting_depth(64)
                .with_max_diagnostics(5)
        );
    }

    #[test]
    fn setters_and_get_agree() {
        let l = Limits::default()
            .with_max_objects(1)
            .with_max_nesting_depth(2)
            .with_max_decoded_stream(3)
            .with_max_total_decoded(4)
            .with_max_xref_sections(5)
            .with_max_page_tree_depth(6)
            .with_max_string_len(7)
            .with_max_image_pixels(8)
            .with_max_ref_chain(9)
            .with_max_diagnostics(10)
            .with_max_objstm_decoded(11)
            .with_max_objstm_cache(12)
            .with_budget_scale(13);
        let fields: Vec<LimitKind> = LimitKind::ALL
            .iter()
            .copied()
            .filter(|k| !k.is_derived())
            .collect();
        for (i, kind) in fields.iter().enumerate() {
            assert_eq!(l.get(*kind), Some(i as u64 + 1), "{kind}");
            assert_eq!(l.budget(*kind, 1 << 40), i as u64 + 1, "{kind}");
            assert!(kind.as_str().starts_with("max_"));
            assert_eq!(kind.to_string(), kind.as_str());
        }
        assert_eq!(l.max_objstm_cache, 12);
        assert_eq!(l.budget_scale, 13);
        for kind in LimitKind::ALL.iter().filter(|k| k.is_derived()) {
            assert_eq!(l.get(*kind), None, "{kind}");
            assert!(!kind.as_str().starts_with("max_"));
            assert!(kind.to_string().contains("budget_scale"), "{kind}");
        }
        assert_eq!(LimitKind::ALL.len(), 16);
    }

    #[test]
    fn derived_budgets_scale_with_the_file() {
        let l = Limits::default();
        let mib = 1u64 << 20;
        let cases = [
            (LimitKind::XrefEntries, 0, 1 << 20),
            (LimitKind::XrefEntries, 10 * mib, 40 * mib),
            (LimitKind::XrefBytes, 1000, mib),
            (LimitKind::XrefBytes, 10 * mib, 40 * mib),
            (LimitKind::ObjectCap, 0, 4096),
            (LimitKind::ObjectCap, 5000, 5000),
            (LimitKind::ObjectCap, u64::MAX, 10_000_000),
            (LimitKind::ReconstructDecoded, 0, 16 * mib),
            (LimitKind::ReconstructDecoded, 4 * mib, 64 * mib),
            (LimitKind::ObjStmParsed, 0, 64 * mib),
            (LimitKind::ObjStmParsed, 4 * mib, 512 * mib),
            (LimitKind::ObjStmParsed, u64::MAX, u64::MAX),
        ];
        for (kind, len, expected) in cases {
            assert_eq!(l.budget(kind, len), expected, "{kind} for {len} bytes");
        }
        // The scale multiplies every derived budget; 0 counts as 1; max_objects still caps.
        let scaled = l.with_budget_scale(3);
        assert_eq!(scaled.budget(LimitKind::XrefEntries, 0), 3 << 20);
        assert_eq!(scaled.budget(LimitKind::ObjectCap, 5000), 15_000);
        assert_eq!(scaled.budget(LimitKind::ObjectCap, 1 << 30), 10_000_000);
        assert_eq!(
            l.with_budget_scale(0).budget(LimitKind::XrefBytes, 0),
            l.budget(LimitKind::XrefBytes, 0)
        );
        assert_eq!(
            l.with_budget_scale(u32::MAX)
                .budget(LimitKind::ObjStmParsed, u64::MAX / 2),
            u64::MAX
        );
        // Which bound holds the objects down.
        assert_eq!(l.object_cap(5000), (LimitKind::ObjectCap, 5000));
        assert_eq!(l.object_cap(1 << 30), (LimitKind::MaxObjects, 10_000_000));
        // The object-stream cap is also bounded by the per-stream limit and by 32 bits.
        assert_eq!(l.effective_objstm_decoded(), 64 << 20);
        assert_eq!(
            l.with_max_decoded_stream(1000).effective_objstm_decoded(),
            1000
        );
        assert_eq!(
            l.with_max_objstm_decoded(usize::MAX)
                .with_max_decoded_stream(usize::MAX)
                .effective_objstm_decoded(),
            u32::MAX as usize
        );
    }
}

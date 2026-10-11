//! The document writers (M2 brief WP2.1, ARCHITECTURE §A.3 "Full save" and "Incremental save").
//!
//! - [`save`] (also [`Store::save`]) writes the whole document again: the objects reachable from
//!   the trailer (garbage collection), densely renumbered, with a fresh header, optionally packed
//!   into object streams, with a cross-reference table or stream, and stream data copied without
//!   decoding.
//! - [`save_incremental`], [`incremental_suffix`] and [`incremental_update`] (also on [`Store`])
//!   append an incremental update (§7.5.6) to the source, which stays byte for byte untouched: only
//!   the edited, added and freed objects, then a cross-reference section of the same kind as the
//!   newest revision's, and a trailer that links to it with `/Prev`. Signatures (M3) build on it.
//!
//! The core has no clock and no RNG, so the output depends only on the store and the options:
//! saving the same document with the same edits and options twice gives the same bytes. Generated
//! file identifiers (`/ID`, §14.4) are MD5 digests of the content written.
//!
//! ```
//! use folioxide_syntax::{IncrementalOptions, Object, OpenOptions, SaveOptions, Store};
//!
//! let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n\
//! 0000000000 65535 f\r\n0000000009 00000 n\r\ntrailer\n<< /Size 2 /Root 1 0 R >>\n\
//! startxref\n45\n%%EOF\n";
//! let mut store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default())?;
//! let root = store.root_id().unwrap();
//! store.get_mut(root)?.as_dict_mut().unwrap().insert("Lang", Object::literal_string("en"));
//!
//! // An incremental update: the original bytes, then the changed catalog and a new section.
//! let updated = store.save_incremental(&IncrementalOptions::default())?;
//! assert!(updated.starts_with(pdf));
//! let reopened = Store::open_bytes(updated, &OpenOptions::default())?;
//! assert_eq!(reopened.revisions().len(), 2);
//!
//! // A full rewrite.
//! let rewritten = store.save(&SaveOptions::default())?;
//! let reopened = Store::open_bytes(rewritten, &OpenOptions::default())?;
//! let catalog = reopened.resolve(reopened.root_id().unwrap())?;
//! assert!(catalog.as_dict().unwrap().contains_key(b"Lang"));
//! # Ok::<(), folioxide_syntax::Error>(())
//! ```

mod full;
mod incremental;
mod md5;
#[cfg(test)]
mod tests;

use std::borrow::Cow;
use std::ops::Range;

use crate::error::{Error, Result};
use crate::filters::encode_flate;
use crate::object::{Dict, Name, Object, ObjectId, PdfString, Stream, StreamData, keys};
use crate::serialize::serialize_indirect;
use crate::store::{COMPUTED_TRAILER_KEYS, Store};
use crate::xref::XrefKind;

pub use full::save;
pub use incremental::{
    incremental_suffix, incremental_suffix_with_overlay, incremental_update, save_incremental,
};

/// The Flate level [`SaveOptions::flate_level`] uses by default (zlib's default).
pub const DEFAULT_FLATE_LEVEL: u8 = 6;

/// The kind of cross-reference section a full save writes (§7.5.4, §7.5.8).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum XrefStyle {
    /// A cross-reference stream when [`SaveOptions::object_streams`] is set or the source's
    /// newest revision uses one (a stream or a hybrid section), otherwise a table.
    #[default]
    Auto,
    /// A classic `xref` table and `trailer` (§7.5.4). Cannot be combined with object streams.
    Table,
    /// A cross-reference stream (§7.5.8; the header becomes at least `%PDF-1.5`).
    Stream,
}

/// How a full save writes stream data (§7.3.8, §7.4).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum StreamCompression {
    /// Every stream as it is: source and [`StreamData::Encoded`] data as encoded,
    /// [`StreamData::Decoded`] data unfiltered (its `/Filter` and `/DecodeParms` dropped). The
    /// object streams and the cross-reference stream the writer makes are not compressed
    /// either (handy for reading the output).
    Keep,
    /// [`StreamData::Decoded`] data is Flate-encoded; source and [`StreamData::Encoded`] data is
    /// copied as encoded, without decoding it. Object streams and cross-reference streams are
    /// Flate-encoded.
    #[default]
    CompressNew,
    /// Like [`StreamCompression::CompressNew`], and every other stream that this layer decodes
    /// completely (no image codec in its chain, data not truncated, no external `/F` file) is
    /// decoded and Flate-encoded again at [`SaveOptions::flate_level`]. The others are copied as
    /// encoded.
    Recompress,
}

/// Options for a full save ([`save`]).
///
/// `#[non_exhaustive]`: start from [`SaveOptions::default()`] and use the `with_*` setters.
///
/// ```
/// use folioxide_syntax::{SaveOptions, StreamCompression, XrefStyle};
///
/// let options = SaveOptions::default()
///     .with_object_streams(true)
///     .with_compress(StreamCompression::Recompress)
///     .with_deterministic(true);
/// assert_eq!(options.xref, XrefStyle::Auto);
/// assert!(options.gc && options.renumber);
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase", default)
)]
pub struct SaveOptions {
    /// The kind of cross-reference section. Default [`XrefStyle::Auto`].
    pub xref: XrefStyle,
    /// Pack the objects that may be compressed into object streams (§7.5.7): every object that
    /// is not a stream, has generation 0, and is not a signature or document timestamp
    /// dictionary (`/Type /Sig` or `/Type /DocTimeStamp`, or, since `/Type` is optional in a
    /// signature dictionary, one with a `/ByteRange`, or with `/Contents` and a `/Filter` or
    /// `/SubFilter`), at most 100 per object stream (qpdf and Acrobat use 100; the M2 brief
    /// allows up to 256). Needs a cross-reference stream. Default false.
    pub object_streams: bool,
    /// How stream data is written. Default [`StreamCompression::CompressNew`].
    pub compress: StreamCompression,
    /// Write only the objects reachable from the trailer (`/Root`, `/Info` and any other entry
    /// it carries). Without it, every object in use is written, except the source's
    /// cross-reference structure the writer replaces (cross-reference streams, object streams
    /// and a linearization dictionary, Annex F). Default true.
    pub gc: bool,
    /// Number the objects densely from 1, in the order of a breadth-first walk from the
    /// trailer, all with generation 0. Without it, objects keep their numbers and generations
    /// (numbers not in use get free entries; after a reconstruction that found two generations
    /// of one number, the later ones get new numbers). Default true.
    pub renumber: bool,
    /// Ask for byte-identical output for identical input, edits and options. The core has no
    /// clock or RNG, so the writer is deterministic whatever this says; the flag states the
    /// requirement (golden tests) and stays meaningful if a later version gains a source of
    /// variation. Default false.
    pub deterministic: bool,
    /// The file identifier to write (`/ID`, §14.4), both elements. Without it: the trailer's
    /// `/ID` (as read, or set with [`Store::set_trailer_entry`]) with its second element
    /// recomputed, or, without one, an identifier generated from the content (both elements the
    /// MD5 digest of the bytes written before the cross-reference section; unique as far as the
    /// content is). Default `None`.
    pub id: Option<[Vec<u8>; 2]>,
    /// The lowest header version to write: a PDF version, 1.0 to 1.7 or 2.0 (§7.5.2; anything
    /// else makes [`save`] fail, see [`SaveOptions::validate`]). The header is the highest of
    /// the source's header version (or the one given to [`Store::new_empty`]), this, and 1.5
    /// when a cross-reference stream is written; a version no PDF has (a source header such as
    /// `%PDF-1.9` or `%PDF-9.9`) becomes the next PDF version up, or 2.0 above it. Default
    /// `None`.
    pub min_version: Option<(u8, u8)>,
    /// The Flate compression level, 0 (store) to 9 (best). Default 6.
    pub flate_level: u8,
}

impl Default for SaveOptions {
    fn default() -> Self {
        SaveOptions {
            xref: XrefStyle::Auto,
            object_streams: false,
            compress: StreamCompression::CompressNew,
            gc: true,
            renumber: true,
            deterministic: false,
            id: None,
            min_version: None,
            flate_level: DEFAULT_FLATE_LEVEL,
        }
    }
}

impl SaveOptions {
    /// The default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`SaveOptions::xref`].
    #[must_use]
    pub fn with_xref(mut self, xref: XrefStyle) -> Self {
        self.xref = xref;
        self
    }

    /// Sets [`SaveOptions::object_streams`].
    #[must_use]
    pub fn with_object_streams(mut self, object_streams: bool) -> Self {
        self.object_streams = object_streams;
        self
    }

    /// Sets [`SaveOptions::compress`].
    #[must_use]
    pub fn with_compress(mut self, compress: StreamCompression) -> Self {
        self.compress = compress;
        self
    }

    /// Sets [`SaveOptions::gc`].
    #[must_use]
    pub fn with_gc(mut self, gc: bool) -> Self {
        self.gc = gc;
        self
    }

    /// Sets [`SaveOptions::renumber`].
    #[must_use]
    pub fn with_renumber(mut self, renumber: bool) -> Self {
        self.renumber = renumber;
        self
    }

    /// Sets [`SaveOptions::deterministic`].
    #[must_use]
    pub fn with_deterministic(mut self, deterministic: bool) -> Self {
        self.deterministic = deterministic;
        self
    }

    /// Sets [`SaveOptions::id`].
    #[must_use]
    pub fn with_id(mut self, id: Option<[Vec<u8>; 2]>) -> Self {
        self.id = id;
        self
    }

    /// Sets [`SaveOptions::min_version`].
    #[must_use]
    pub fn with_min_version(mut self, min_version: Option<(u8, u8)>) -> Self {
        self.min_version = min_version;
        self
    }

    /// Sets [`SaveOptions::flate_level`] (values above 9 count as 9).
    #[must_use]
    pub fn with_flate_level(mut self, flate_level: u8) -> Self {
        self.flate_level = flate_level;
        self
    }

    /// Checks the options on their own, as [`save`] does first: a caller that collects options
    /// (a binding) can refuse them before it has a document to save.
    ///
    /// ```
    /// use folioxide_syntax::{ErrorCode, SaveOptions, XrefStyle};
    ///
    /// assert!(SaveOptions::default().with_min_version(Some((2, 0))).validate().is_ok());
    /// let header = SaveOptions::default().with_min_version(Some((9, 9))).validate();
    /// assert_eq!(header.unwrap_err().code(), ErrorCode::InvalidArgument);
    /// let table = SaveOptions::default()
    ///     .with_xref(XrefStyle::Table)
    ///     .with_object_streams(true)
    ///     .validate();
    /// assert_eq!(table.unwrap_err().code(), ErrorCode::InvalidArgument);
    /// ```
    ///
    /// # Errors
    /// [`ErrorCode::InvalidArgument`](crate::ErrorCode::InvalidArgument):
    /// [`SaveOptions::min_version`] is not a PDF version (1.0 to 1.7, or 2.0), or
    /// [`XrefStyle::Table`] is combined with [`SaveOptions::object_streams`].
    pub fn validate(&self) -> Result<()> {
        if let Some((major, minor)) = self.min_version
            && !is_pdf_version((major, minor))
        {
            return Err(Error::invalid_argument(format!(
                "min_version {major}.{minor} is not a PDF version; a header names 1.0 to 1.7 or \
                 2.0 (§7.5.2)"
            )));
        }
        if self.xref == XrefStyle::Table && self.object_streams {
            return Err(Error::invalid_argument(
                "object streams need a cross-reference stream (§7.5.7); use XrefStyle::Auto or \
                 XrefStyle::Stream",
            ));
        }
        Ok(())
    }
}

/// Options for an incremental save ([`save_incremental`]).
///
/// `#[non_exhaustive]`: start from [`IncrementalOptions::default()`] and use the `with_*`
/// setters.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase", default)
)]
pub struct IncrementalOptions {
    /// Ask for byte-identical output for identical input and edits; see
    /// [`SaveOptions::deterministic`] (the writer is deterministic either way). Default false.
    pub deterministic: bool,
    /// The second element of the new `/ID` (§14.4: "a changing identifier based on the file's
    /// contents at the time it was last updated"). Without it, the MD5 digest of the update (the
    /// first element of the identifier, the source's length and newest `startxref`, and the
    /// bytes of the objects the update writes). The first element is always kept. Default
    /// `None`.
    pub id1: Option<Vec<u8>>,
}

impl IncrementalOptions {
    /// The default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`IncrementalOptions::deterministic`].
    #[must_use]
    pub fn with_deterministic(mut self, deterministic: bool) -> Self {
        self.deterministic = deterministic;
        self
    }

    /// Sets [`IncrementalOptions::id1`].
    #[must_use]
    pub fn with_id1(mut self, id1: Option<Vec<u8>>) -> Self {
        self.id1 = id1;
        self
    }
}

/// An incremental update as [`incremental_update`] builds it: the bytes to append to the source,
/// and where its parts land in the new file (what a signature needs to compute its
/// `/ByteRange`, ARCHITECTURE §A.6.2).
///
/// The new file is `source ‖ bytes`: it is `start + bytes.len()` bytes long, and reopening it
/// shows one more revision, whose [`Revision::eof_end`](crate::Revision::eof_end) is that
/// length. All positions here are absolute (counted from byte 0 of the new file, junk before
/// the header included), like [`Revision::eof_end`](crate::Revision::eof_end).
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IncrementalUpdate {
    /// The bytes to append to the source: an end-of-line if the source does not end with one,
    /// the objects, the cross-reference section and trailer, `startxref` and `%%EOF`. Empty when
    /// nothing was edited.
    pub bytes: Vec<u8>,
    /// Where `bytes` start in the new file: the length of the source.
    pub start: u64,
    /// The objects the update writes, in order, with the absolute byte range of each, from its
    /// `N G obj` header to the end of the line after `endobj`.
    pub objects: Vec<(ObjectId, Range<u64>)>,
    /// The absolute position of the update's cross-reference section (`xref` keyword or
    /// cross-reference stream object); `None` when nothing was edited.
    pub xref_pos: Option<u64>,
    /// The kind of cross-reference section written: [`XrefKind::Table`] after a table,
    /// [`XrefKind::Stream`] after a stream or hybrid section; `None` when nothing was edited.
    pub xref_kind: Option<XrefKind>,
}

/// The absolute byte layout of an incremental update produced with an overlay
/// ([`incremental_suffix_with_overlay`]): what a signature needs to patch its `/ByteRange` and
/// locate its `/Contents` (brief §1, ARCHITECTURE §A.6.2).
///
/// It is a thin wrapper around [`IncrementalUpdate`] (the manager's reconciliation of the brief's
/// `IncrementalLayout` with M2's `IncrementalUpdate`, rather than a second, parallel type): the
/// brief's three fields map onto the update's, so that the overlay path shares every line with
/// [`incremental_update`]:
///
/// - `suffix` is [`IncrementalUpdate::bytes`]: the bytes appended to the source (a leading
///   end-of-line included when the source does not end with one);
/// - `base` is [`IncrementalUpdate::start`]: the absolute offset of `suffix[0]` in the output,
///   which equals the source length;
/// - `spans` is [`IncrementalUpdate::objects`]: the absolute span of every object written, from
///   its `N G obj` header to just past the end-of-line after `endobj`.
///
/// The accessors [`IncrementalLayout::suffix`], [`IncrementalLayout::base`] and
/// [`IncrementalLayout::spans`] give those under the brief's names; [`IncrementalLayout::update`]
/// and [`IncrementalLayout::into_update`] reach the wrapped [`IncrementalUpdate`] (with its
/// `xref_pos` and `xref_kind`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncrementalLayout(pub IncrementalUpdate);

impl IncrementalLayout {
    /// The bytes appended to the source ([`IncrementalUpdate::bytes`]).
    pub fn suffix(&self) -> &[u8] {
        &self.0.bytes
    }

    /// The absolute offset of `suffix[0]` in the output, equal to the source length
    /// ([`IncrementalUpdate::start`]).
    pub fn base(&self) -> u64 {
        self.0.start
    }

    /// The absolute span of every object written, from its `N G obj` header to just past the
    /// end-of-line after `endobj` ([`IncrementalUpdate::objects`]).
    pub fn spans(&self) -> &[(ObjectId, Range<u64>)] {
        &self.0.objects
    }

    /// The wrapped [`IncrementalUpdate`], for its `xref_pos` and `xref_kind`.
    pub fn update(&self) -> &IncrementalUpdate {
        &self.0
    }

    /// Unwraps into the [`IncrementalUpdate`].
    pub fn into_update(self) -> IncrementalUpdate {
        self.0
    }
}

impl Store {
    /// Writes the whole document again; see [`save`].
    ///
    /// # Errors
    /// See [`save`].
    pub fn save(&self, opts: &SaveOptions) -> Result<Vec<u8>> {
        save(self, opts)
    }

    /// The source followed by an incremental update with the edits; see [`save_incremental`].
    ///
    /// # Errors
    /// See [`save_incremental`].
    pub fn save_incremental(&self, opts: &IncrementalOptions) -> Result<Vec<u8>> {
        save_incremental(self, opts)
    }

    /// Only the bytes to append to the source; see [`incremental_suffix`].
    ///
    /// # Errors
    /// See [`save_incremental`].
    pub fn incremental_suffix(&self, opts: &IncrementalOptions) -> Result<Vec<u8>> {
        incremental_suffix(self, opts)
    }

    /// An incremental update with the `overlay` objects written on top of the edits, and its
    /// absolute byte layout; see [`incremental_suffix_with_overlay`].
    ///
    /// # Errors
    /// See [`incremental_suffix_with_overlay`].
    pub fn incremental_suffix_with_overlay(
        &self,
        opts: &IncrementalOptions,
        overlay: &std::collections::BTreeMap<ObjectId, Object>,
    ) -> Result<IncrementalLayout> {
        incremental_suffix_with_overlay(self, opts, overlay)
    }

    /// Checks that an incremental update may be appended to this store's source: `Ok` unless
    /// [`incremental_update`] refuses the source itself (no source, a reconstructed or repaired
    /// structure, an object away from its offset; see its errors). The edits are not checked
    /// (a freed catalog, a nested stream): those errors come from the save.
    ///
    /// ```
    /// use folioxide_syntax::{ErrorCode, OpenOptions, Store};
    ///
    /// let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n\
    /// 0000000000 65535 f\r\n0000000009 00000 n\r\ntrailer\n<< /Size 2 /Root 1 0 R >>\n\
    /// startxref\n45\n%%EOF\n";
    /// let store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default())?;
    /// assert!(store.check_incremental().is_ok());
    /// // Without a cross-reference table the file is reconstructed: a full save first.
    /// let broken = Store::open_bytes(pdf[..45].to_vec(), &OpenOptions::default())?;
    /// assert_eq!(broken.check_incremental().unwrap_err().code(), ErrorCode::Unsupported);
    /// # Ok::<(), folioxide_syntax::Error>(())
    /// ```
    ///
    /// # Errors
    /// The refusals of [`incremental_update`]: [`ErrorCode::InvalidArgument`] without a source,
    /// [`ErrorCode::Unsupported`] ("full save required") for a structure other readers may
    /// resolve differently.
    ///
    /// [`ErrorCode::InvalidArgument`]: crate::ErrorCode::InvalidArgument
    /// [`ErrorCode::Unsupported`]: crate::ErrorCode::Unsupported
    pub fn check_incremental(&self) -> Result<()> {
        incremental::appendable_kind(self).map(|_| ())
    }

    /// The incremental update with the positions of its parts; see [`incremental_update`].
    ///
    /// # Errors
    /// See [`save_incremental`].
    pub fn incremental_update(&self, opts: &IncrementalOptions) -> Result<IncrementalUpdate> {
        incremental_update(self, opts)
    }
}

// ---- shared by both writers ---------------------------------------------------------------------

/// Whether `version` is a version a PDF header names (§7.5.2): 1.0 to 1.7 (PDF 1.7 is ISO
/// 32000-1, the earlier ones are Adobe's references) or 2.0 (ISO 32000-2).
fn is_pdf_version(version: (u8, u8)) -> bool {
    matches!(version, (1, 0..=7) | (2, 0))
}

/// The PDF version a header names for `version`: itself when it is one ([`is_pdf_version`]),
/// otherwise the lowest PDF version above it (1.0 below 1.0, 2.0 for 1.8 and 1.9), or 2.0, the
/// highest, above 2.0. A source header (or [`Store::new_empty`]'s argument) may say any `M.m`
/// (`%PDF-9.9`); a written header only says what readers know.
fn header_version(version: (u8, u8)) -> (u8, u8) {
    match version {
        _ if is_pdf_version(version) => version,
        (0, _) => (1, 0),
        _ => (2, 0),
    }
}

/// `%PDF-x.y` for the PDF version [`header_version`] gives for `version`, then a comment line
/// of four bytes ≥ 0x80 so that file-transfer tools treat the file as binary (§7.5.2).
fn write_header(version: (u8, u8), out: &mut Vec<u8>) {
    let (major, minor) = header_version(version);
    out.extend_from_slice(format!("%PDF-{major}.{minor}\n").as_bytes());
    out.extend_from_slice(b"%\xE2\xE3\xCF\xD3\n");
}

/// The highest of two versions.
fn max_version(a: (u8, u8), b: (u8, u8)) -> (u8, u8) {
    a.max(b)
}

/// One entry of a cross-reference section being written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entry {
    /// A free entry: the next free object number (the linked list of §7.5.4) and the
    /// generation a re-use must take.
    Free { next: u32, r#gen: u16 },
    /// An uncompressed object at `offset` (in the file's offset base).
    InFile { offset: u64, r#gen: u16 },
    /// Member `index` of object stream `stream` (§7.5.8.3, type 2).
    InObjStm { stream: u32, index: u32 },
}

/// The largest offset a 20-byte table entry can hold (ten digits, §7.5.4).
const MAX_TABLE_OFFSET: u64 = 9_999_999_999;

/// Links the free entries of `entries` (sorted by number, object 0 included as a free entry)
/// into the list of §7.5.4: object 0 points to the first free number, each free entry to the
/// next, the last to 0. Object 0 has generation 65535.
fn link_free_list(entries: &mut [(u32, Entry)]) {
    let free: Vec<u32> = entries
        .iter()
        .filter(|(num, entry)| *num != 0 && matches!(entry, Entry::Free { .. }))
        .map(|&(num, _)| num)
        .collect();
    let mut next_of = free.iter().copied().skip(1).chain(std::iter::once(0));
    let first = free.first().copied().unwrap_or(0);
    for (num, entry) in entries.iter_mut() {
        if let Entry::Free { next, r#gen } = entry {
            if *num == 0 {
                *next = first;
                *r#gen = u16::MAX;
            } else {
                *next = next_of.next().unwrap_or(0);
            }
        }
    }
}

/// The runs of consecutive numbers in `entries` (sorted by number): `(first, count)` pairs, the
/// subsections of a table or the `/Index` of a stream.
fn subsections(entries: &[(u32, Entry)]) -> Vec<(u32, u32)> {
    let mut runs: Vec<(u32, u32)> = Vec::new();
    for &(num, _) in entries {
        match runs.last_mut() {
            Some((first, count)) if first.checked_add(*count) == Some(num) => *count += 1,
            _ => runs.push((num, 1)),
        }
    }
    runs
}

/// Writes a cross-reference table (§7.5.4) with 20-byte entries, `nnnnnnnnnn ggggg n\r\n`.
/// `entries` is sorted by number and starts with object 0, so the first subsection starts at 0
/// (pypdf's strict mode refuses a table that does not).
fn write_table(entries: &[(u32, Entry)], out: &mut Vec<u8>) -> Result<()> {
    out.extend_from_slice(b"xref\n");
    let mut rest = entries;
    for (first, count) in subsections(entries) {
        out.extend_from_slice(format!("{first} {count}\n").as_bytes());
        let (run, tail) = rest.split_at(usize::try_from(count).unwrap_or(0).min(rest.len()));
        rest = tail;
        for &(num, entry) in run {
            let line = match entry {
                Entry::Free { next, r#gen } => format!("{next:010} {gen:05} f\r\n"),
                Entry::InFile { offset, r#gen } => {
                    if offset > MAX_TABLE_OFFSET {
                        return Err(Error::unsupported(format!(
                            "object {num} is at byte {offset}, beyond the ten digits of a \
                             cross-reference table entry; use a cross-reference stream"
                        )));
                    }
                    format!("{offset:010} {gen:05} n\r\n")
                }
                Entry::InObjStm { .. } => {
                    return Err(Error::invalid_argument(format!(
                        "object {num} is in an object stream, which a cross-reference table \
                         cannot list (§7.5.7)"
                    )));
                }
            };
            out.extend_from_slice(line.as_bytes());
        }
    }
    Ok(())
}

/// The bytes a big-endian field needs for `value` (at least 1).
fn field_width(value: u64) -> usize {
    let bits = 64 - value.leading_zeros() as usize;
    bits.div_ceil(8).max(1)
}

/// Builds a cross-reference stream (§7.5.8): `dict` gets `/Type /XRef`, `/W` and `/Index` first
/// (followed by its own entries); the data is Flate-encoded at `level` when `compress`.
fn xref_stream(entries: &[(u32, Entry)], dict: Dict, compress: Option<u8>) -> Stream {
    let fields = |entry: Entry| -> (u8, u64, u64) {
        match entry {
            Entry::Free { next, r#gen } => (0, u64::from(next), u64::from(r#gen)),
            Entry::InFile { offset, r#gen } => (1, offset, u64::from(r#gen)),
            Entry::InObjStm { stream, index } => (2, u64::from(stream), u64::from(index)),
        }
    };
    let (w1, w2) = entries.iter().fold((1, 1), |(w1, w2), &(_, entry)| {
        let (_, a, b) = fields(entry);
        (w1.max(field_width(a)), w2.max(field_width(b)))
    });
    let mut data = Vec::with_capacity(entries.len().saturating_mul(1 + w1 + w2));
    for &(_, entry) in entries {
        let (kind, a, b) = fields(entry);
        data.push(kind);
        data.extend_from_slice(a.to_be_bytes().get(8 - w1..).unwrap_or_default());
        data.extend_from_slice(b.to_be_bytes().get(8 - w2..).unwrap_or_default());
    }
    let index: Vec<Object> = subsections(entries)
        .into_iter()
        .flat_map(|(first, count)| [Object::from(first), Object::from(count)])
        .collect();
    let mut full = Dict::with_capacity(dict.len() + 5);
    full.insert(keys::TYPE, Object::name(keys::XREF));
    for (key, value) in dict {
        full.insert(key, value);
    }
    full.insert(
        keys::W,
        Object::Array(vec![1.into(), (w1 as i64).into(), (w2 as i64).into()]),
    );
    full.insert(keys::INDEX, Object::Array(index));
    let data = match compress {
        Some(level) => {
            full.insert(keys::FILTER, Object::name("FlateDecode"));
            encode_flate(&data, level)
        }
        None => data,
    };
    Stream::new(full, StreamData::Encoded(data))
}

/// The entries of `trailer` a writer carries over: every entry but those it computes itself
/// (see [`COMPUTED_TRAILER_KEYS`]) and `/ID`, which it writes itself. `/Root` and `/Info` come
/// first.
fn carried_trailer(trailer: &Dict) -> Result<Vec<(Name, Object)>> {
    if trailer.get(keys::ENCRYPT).is_some_and(|v| !v.is_null()) {
        return Err(Error::unsupported(
            "saving an encrypted document arrives with encryption (M5)",
        ));
    }
    let mut carried: Vec<(Name, Object)> = Vec::with_capacity(trailer.len());
    for key in [keys::ROOT, keys::INFO] {
        if let Some(value) = trailer.get(key).filter(|v| !v.is_null()) {
            carried.push((Name::from(key), value.clone()));
        }
    }
    for (key, value) in trailer {
        let k = key.as_bytes();
        if k == keys::ROOT
            || k == keys::INFO
            || k == keys::ID
            || k == keys::ENCRYPT
            || COMPUTED_TRAILER_KEYS.contains(&k)
        {
            continue;
        }
        carried.push((key.clone(), value.clone()));
    }
    Ok(carried)
}

/// The first element of `trailer`'s `/ID`, if it is an array of two strings (§14.4).
fn first_id(trailer: &Dict) -> Option<Vec<u8>> {
    let items = trailer.get_array(keys::ID)?;
    match items {
        [Object::String(first), Object::String(_)] => Some(first.bytes.clone()),
        _ => None,
    }
}

/// `/ID [<a> <b>]`, as hexadecimal strings.
fn id_array(id: [Vec<u8>; 2]) -> Object {
    let [a, b] = id;
    Object::Array(vec![
        Object::String(PdfString::new_hex(a)),
        Object::String(PdfString::new_hex(b)),
    ])
}

/// Writes indirect objects with their stream data encoded as a [`StreamCompression`] says.
struct ObjectWriter<'s> {
    store: &'s Store,
    compress: StreamCompression,
    level: u8,
}

impl<'s> ObjectWriter<'s> {
    /// Writes `id`'s object `obj` as `N G obj ... endobj`. `dict` replaces a stream's dictionary
    /// (the full writer passes it with its references renumbered). The caller has checked that
    /// `obj` holds no nested stream ([`check_value`]).
    fn write(
        &self,
        id: ObjectId,
        obj: &Object,
        dict: Option<Dict>,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        match obj {
            Object::Stream(stream) => {
                let dict = dict.unwrap_or_else(|| stream.dict.clone());
                let (dict, data) = self.payload(dict, stream)?;
                // The data is given explicitly, so this placeholder is never read.
                let shell = Object::Stream(Box::new(Stream::new(dict, StreamData::Source(0..0))));
                serialize_indirect(id, &shell, Some(&data), out)
            }
            _ => serialize_indirect(id, obj, None, out),
        }
    }

    /// The dictionary and data to write for `stream`, whose dictionary (renumbered for a full
    /// save) is `dict`.
    fn payload<'a>(&self, mut dict: Dict, stream: &'a Stream) -> Result<(Dict, Cow<'a, [u8]>)>
    where
        's: 'a,
    {
        let plain: Option<Cow<'a, [u8]>> = match (&stream.data, self.compress) {
            (StreamData::Decoded(data), StreamCompression::Keep) => {
                dict.remove(keys::FILTER);
                dict.remove(keys::DECODE_PARMS);
                set_decoded_length(&mut dict, data.len());
                return Ok((dict, Cow::Borrowed(data)));
            }
            (StreamData::Decoded(data), _) => Some(Cow::Borrowed(data)),
            (_, StreamCompression::Recompress) => self.recompressible(stream).map(Cow::Owned),
            _ => None,
        };
        match plain {
            Some(plain) => {
                // §7.4.4: Flate, without a predictor; any earlier filter chain no longer applies.
                dict.insert(keys::FILTER, Object::name("FlateDecode"));
                dict.remove(keys::DECODE_PARMS);
                set_decoded_length(&mut dict, plain.len());
                Ok((dict, Cow::Owned(encode_flate(&plain, self.level))))
            }
            // Copied as encoded (zero decode), with its dictionary's /Filter.
            None => {
                let store: &'a Store = self.store;
                Ok((dict, store.raw_stream_data(stream)?))
            }
        }
    }

    /// The decoded data of `stream`, when this layer decodes it completely: no image codec in
    /// its chain, data not truncated, no external file (§7.3.8.2 `/F`: the data in the file is
    /// then ignored). `None` otherwise, or when decoding fails: the stream is copied as encoded.
    fn recompressible(&self, stream: &Stream) -> Option<Vec<u8>> {
        if stream.dict.contains_key(keys::F) {
            return None;
        }
        let decoded = self.store.stream_data(stream).ok()?;
        (decoded.is_fully_decoded() && !decoded.truncated).then_some(decoded.data)
    }
}

/// Keeps an existing `/DL` (the decoded length, §7.3.8.2) right after the data changed form.
fn set_decoded_length(dict: &mut Dict, len: usize) {
    if dict.contains_key(keys::DL) {
        dict.insert(
            keys::DL,
            Object::Int(i64::try_from(len).unwrap_or(i64::MAX)),
        );
    }
}

/// Refuses a stream nested inside object `id`'s value `obj` (in an array or dictionary, or in a
/// stream's dictionary): a stream can only be the value of an indirect object (§7.3.8), and the
/// serializer would write its dictionary alone. Iterative, so any depth is fine.
fn check_value(id: ObjectId, obj: &Object) -> Result<()> {
    let mut stack: Vec<&Object> = match obj {
        Object::Stream(stream) => stream.dict.values().collect(),
        other => vec![other],
    };
    while let Some(obj) = stack.pop() {
        match obj {
            Object::Array(items) => stack.extend(items),
            Object::Dict(dict) => stack.extend(dict.values()),
            Object::Stream(_) => return Err(nested_stream(id)),
            _ => {}
        }
    }
    Ok(())
}

/// The error for a stream nested inside object `id`.
fn nested_stream(id: ObjectId) -> Error {
    Error::invalid_argument(format!(
        "object {id} holds a stream inside an array or dictionary; a stream can only be the \
         value of an indirect object (§7.3.8)"
    ))
}

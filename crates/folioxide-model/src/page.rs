//! Pages: boxes, rotation, resources and inherited attributes (ISO 32000-2 §7.7.3.3–4, §14.11.2).
//!
//! A [`Page`] is a read view of one page object, borrowed from its
//! [`Document`](crate::Document). `/Resources`, `/MediaBox`, `/CropBox` and `/Rotate` are
//! *inheritable* (§7.7.3.4): when the page does not have them, the nearest `/Pages` node above
//! it that does supplies them. A value of the wrong type (a `/MediaBox` that is not an array of
//! four numbers, a `/Rotate` that is not a number) is ignored with a diagnostic, and the lookup
//! continues upwards, as poppler does.
//!
//! The page boundaries follow §14.11.2: the media box is required (US Letter, 612 × 792, with a
//! diagnostic when no valid one is found), the crop box defaults to the media box, and the
//! bleed, trim and art boxes (not inheritable) default to the crop box. Every box is clipped to
//! the media box; a box that does not overlap it is ignored with a diagnostic.

use std::sync::Arc;

use folioxide_syntax::serialize::{MAX_REAL, canonical_real};
use folioxide_syntax::{DiagnosticKind, Dict, Error, Object, ObjectId, Result, Store, keys};

use crate::Document;

/// `/CropBox` (§7.7.3.3, inheritable).
pub(crate) const CROP_BOX: &[u8] = b"CropBox";
/// `/BleedBox` (§14.11.2).
const BLEED_BOX: &[u8] = b"BleedBox";
/// `/TrimBox` (§14.11.2).
const TRIM_BOX: &[u8] = b"TrimBox";
/// `/ArtBox` (§14.11.2).
const ART_BOX: &[u8] = b"ArtBox";
/// `/Rotate` (§7.7.3.3, inheritable).
pub(crate) const ROTATE: &[u8] = b"Rotate";

/// Which page-tree nodes a lookup reads: the page object, its ancestors, or both (§7.7.3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /// The page object only.
    Own,
    /// The page's ancestors only, nearest first: what the page would inherit.
    Inherited,
    /// The page object, then its ancestors.
    All,
    /// The nodes reached by following `/Parent` from the page, nearest first (not the page
    /// itself): what a reader that inherits along `/Parent` (pdf.js; qpdf for `/CropBox` and
    /// `/Rotate`) finds above the page. The
    /// same nodes as [`Scope::Inherited`] unless a `/Parent` disagrees with the node that lists
    /// it, or the root has a `/Parent` (which §7.7.3.2 prohibits); see [`Page::parent_chain`].
    Parents,
}

/// A stable handle to a page: the object number and generation of its page object.
///
/// Unlike a page index, it does not change when pages are inserted or removed before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PageId(pub ObjectId);

impl PageId {
    /// The page object's identifier.
    pub const fn object_id(self) -> ObjectId {
        self.0
    }
}

impl From<PageId> for ObjectId {
    fn from(id: PageId) -> ObjectId {
        id.0
    }
}

/// A rectangle in default user space (§7.9.5), normalized so that `llx ≤ urx` and
/// `lly ≤ ury`.
///
/// The struct is `#[non_exhaustive]`: build one with [`Rect::new`], which normalizes.
///
/// ```
/// use folioxide_model::Rect;
///
/// let r = Rect::new(612.0, 792.0, 0.0, 0.0);
/// assert_eq!((r.llx, r.lly, r.urx, r.ury), (0.0, 0.0, 612.0, 792.0));
/// assert_eq!((r.width(), r.height()), (612.0, 792.0));
/// ```
///
/// With the `serde` feature it is the object `{ "llx": 0, "lly": 0, "urx": 612, "ury": 792 }`;
/// deserializing normalizes the corners like [`Rect::new`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase", from = "crate::serde_util::RawRect")
)]
pub struct Rect {
    /// The x coordinate of the lower-left corner.
    pub llx: f64,
    /// The y coordinate of the lower-left corner.
    pub lly: f64,
    /// The x coordinate of the upper-right corner.
    pub urx: f64,
    /// The y coordinate of the upper-right corner.
    pub ury: f64,
}

impl Rect {
    /// US Letter, `[0 0 612 792]`: the media box assumed when a page has none.
    pub const US_LETTER: Rect = Rect {
        llx: 0.0,
        lly: 0.0,
        urx: 612.0,
        ury: 792.0,
    };

    /// The rectangle with opposite corners `(x1, y1)` and `(x2, y2)`, in any order (§7.9.5:
    /// readers normalize the corners).
    pub fn new(x1: f64, y1: f64, x2: f64, y2: f64) -> Rect {
        Rect {
            llx: x1.min(x2),
            lly: y1.min(y2),
            urx: x1.max(x2),
            ury: y1.max(y2),
        }
    }

    /// The width, `urx - llx`.
    pub fn width(&self) -> f64 {
        self.urx - self.llx
    }

    /// The height, `ury - lly`.
    pub fn height(&self) -> f64 {
        self.ury - self.lly
    }

    /// The intersection of the two rectangles, or `None` when it has no area.
    pub fn intersect(&self, other: &Rect) -> Option<Rect> {
        let r = Rect {
            llx: self.llx.max(other.llx),
            lly: self.lly.max(other.lly),
            urx: self.urx.min(other.urx),
            ury: self.ury.min(other.ury),
        };
        (r.width() > 0.0 && r.height() > 0.0).then_some(r)
    }

    /// This rectangle as it reads back once written, for writing: normalized, with every
    /// coordinate rounded as the serializer writes it (at most 10 fractional digits,
    /// [`canonical_real`]), so that the document in memory says what its saved bytes say.
    /// `None` when a coordinate is not finite or is larger in magnitude than the largest real
    /// the serializer writes (about `3.403e38`, ISO 32000-1 Annex C), or when the rounded
    /// rectangle has no area (`[0 0 1e-12 1e-12]` would be written as `[0 0 0.0 0.0]`, which
    /// readers reject).
    pub(crate) fn checked(&self) -> Option<Rect> {
        let coords = [self.llx, self.lly, self.urx, self.ury];
        if !coords.iter().all(|v| v.is_finite() && v.abs() <= MAX_REAL) {
            return None;
        }
        let [x1, y1, x2, y2] = coords.map(canonical_real);
        let r = Rect::new(x1, y1, x2, y2);
        (r.width() > 0.0 && r.height() > 0.0).then_some(r)
    }

    /// Whether `other` lies entirely inside this rectangle (edges included).
    pub fn contains(&self, other: &Rect) -> bool {
        self.llx <= other.llx
            && self.lly <= other.lly
            && other.urx <= self.urx
            && other.ury <= self.ury
    }

    /// The rectangle as a PDF array `[llx lly urx ury]`.
    pub fn to_object(&self) -> Object {
        Object::Array(vec![
            number(self.llx),
            number(self.lly),
            number(self.urx),
            number(self.ury),
        ])
    }

    /// Reads a rectangle from a PDF array of four numbers (§7.9.5), following references to
    /// the array and its elements. `None` when the value is not such an array, when a number is
    /// not finite, or when the rectangle has no area.
    ///
    /// # Errors
    /// The errors of [`Store::deref`].
    pub fn from_object(store: &Store, value: &Object) -> Result<Option<Rect>> {
        let value = store.deref(value)?;
        let Some([a, b, c, d]) = value.as_array() else {
            return Ok(None);
        };
        let mut coords = [0.0; 4];
        for (slot, element) in coords.iter_mut().zip([a, b, c, d]) {
            match store.deref(element)?.as_f64() {
                Some(v) if v.is_finite() => *slot = v,
                _ => return Ok(None),
            }
        }
        let [x1, y1, x2, y2] = coords;
        let rect = Rect::new(x1, y1, x2, y2);
        Ok((rect.width() > 0.0 && rect.height() > 0.0).then_some(rect))
    }
}

/// An integral coordinate as an integer, anything else as a real.
fn number(v: f64) -> Object {
    // Integers only within the 32-bit range that ISO 32000-1 Annex C (Table C.1) asks readers
    // to accept; the conversion is exact there.
    if v.fract() == 0.0 && v.abs() <= f64::from(i32::MAX) {
        Object::Int(v as i64)
    } else {
        Object::Real(v)
    }
}

/// A page rotation: the number of degrees the page is turned clockwise when displayed or
/// printed (§7.7.3.3, `/Rotate`).
///
/// With the `serde` feature it is the number of degrees, `0`, `90`, `180` or `270`;
/// deserializing accepts any multiple of 90 and normalizes it like [`Rotation::from_degrees`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(into = "u16", try_from = "i64")
)]
pub enum Rotation {
    /// Upright (the default).
    #[default]
    R0,
    /// A quarter turn clockwise.
    R90,
    /// Upside down.
    R180,
    /// Three quarter turns clockwise (a quarter turn anticlockwise).
    R270,
}

impl Rotation {
    /// The rotation in degrees: 0, 90, 180 or 270.
    pub const fn degrees(self) -> u16 {
        match self {
            Rotation::R0 => 0,
            Rotation::R90 => 90,
            Rotation::R180 => 180,
            Rotation::R270 => 270,
        }
    }

    /// The rotation for any multiple of 90 degrees, negative ones included (`-90` is
    /// [`Rotation::R270`], `450` is [`Rotation::R90`]); `None` for other values.
    ///
    /// ```
    /// use folioxide_model::Rotation;
    ///
    /// assert_eq!(Rotation::from_degrees(-90), Some(Rotation::R270));
    /// assert_eq!(Rotation::from_degrees(720), Some(Rotation::R0));
    /// assert_eq!(Rotation::from_degrees(45), None);
    /// ```
    pub const fn from_degrees(degrees: i64) -> Option<Rotation> {
        match degrees.rem_euclid(360) {
            0 => Some(Rotation::R0),
            90 => Some(Rotation::R90),
            180 => Some(Rotation::R180),
            270 => Some(Rotation::R270),
            _ => None,
        }
    }

    /// Whether the rotation swaps the page's width and height (90 or 270 degrees).
    pub const fn is_sideways(self) -> bool {
        matches!(self, Rotation::R90 | Rotation::R270)
    }
}

impl From<Rotation> for u16 {
    /// The rotation in degrees ([`Rotation::degrees`]).
    fn from(rotation: Rotation) -> u16 {
        rotation.degrees()
    }
}

impl TryFrom<i64> for Rotation {
    type Error = Error;

    /// The rotation for a multiple of 90 degrees ([`Rotation::from_degrees`]).
    ///
    /// # Errors
    /// [`ErrorCode::InvalidArgument`](folioxide_syntax::ErrorCode::InvalidArgument) when
    /// `degrees` is not a multiple of 90.
    fn try_from(degrees: i64) -> Result<Rotation> {
        Rotation::from_degrees(degrees).ok_or_else(|| {
            Error::invalid_argument(format!(
                "a page rotation must be a multiple of 90 degrees, not {degrees}"
            ))
        })
    }
}

/// What a page looks like: its size as displayed, its boxes and its rotation (a plain value, for
/// bindings and serialization; see [`Page::info`]).
///
/// The struct is `#[non_exhaustive]`. With the `serde` feature its fields are `camelCase`:
/// `{ "index", "width", "height", "mediaBox", "cropBox", "rotation" }`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct PageInfo {
    /// The page's 0-based index.
    pub index: usize,
    /// The width as displayed: [`Page::effective_size`], the crop box's width, or its height
    /// when the page is rotated by 90 or 270 degrees.
    pub width: f64,
    /// The height as displayed (see [`PageInfo::width`]).
    pub height: f64,
    /// The media box ([`Page::media_box`]).
    pub media_box: Rect,
    /// The crop box ([`Page::crop_box`]), clipped to the media box.
    pub crop_box: Rect,
    /// The rotation ([`Page::rotation`]).
    pub rotation: Rotation,
}

/// A read view of one page, borrowed from its [`Document`].
///
/// Obtained from [`Document::page`]. Attribute lookups are not cached: each call resolves the
/// page object and, for inherited attributes, its ancestors (the store caches resolved objects).
/// To change a page, use the document's setters ([`Document::set_media_box`],
/// [`Document::set_crop_box`], [`Document::set_rotation`]), which take the page's index.
///
/// ```
/// use folioxide_model::{Document, Rect, Rotation};
/// use folioxide_syntax::OpenOptions;
///
/// // Two pages under a page tree node that gives them an A4 media box and a quarter turn
/// // (a file without a cross-reference table: the store finds the objects).
/// let pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
/// 2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 595 842] /Rotate 90 \
/// >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n\
/// 4 0 obj\n<< /Type /Page /Parent 2 0 R /CropBox [0 0 300 400] /Rotate 0 >>\nendobj\n\
/// trailer\n<< /Root 1 0 R >>\n%%EOF\n";
/// let doc = Document::open(pdf.to_vec(), &OpenOptions::default())?;
///
/// let first = doc.page(0)?;
/// assert_eq!(first.media_box(), Rect::new(0.0, 0.0, 595.0, 842.0)); // inherited (§7.7.3.4)
/// assert_eq!(first.crop_box(), first.media_box()); // the default (§14.11.2)
/// assert_eq!(first.rotation(), Rotation::R90); // inherited
/// assert_eq!(first.effective_size(), (842.0, 595.0)); // landscape as displayed
///
/// let second = doc.page(1)?;
/// assert_eq!(second.crop_box(), Rect::new(0.0, 0.0, 300.0, 400.0));
/// assert_eq!(second.rotation(), Rotation::R0); // its own /Rotate overrides the inherited one
/// assert_eq!(doc.page_index(second.id())?, Some(second.index()));
/// assert!(doc.page(2).is_err()); // ErrorCode::PageOutOfRange
/// # Ok::<(), folioxide_syntax::Error>(())
/// ```
pub struct Page<'a> {
    doc: &'a Document,
    index: usize,
    id: ObjectId,
    /// The `/Pages` nodes above the page, nearest first, as the page-tree walk reached it.
    ancestors: Vec<ObjectId>,
}

impl std::fmt::Debug for Page<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Page")
            .field("index", &self.index)
            .field("id", &self.id)
            .field("ancestors", &self.ancestors)
            .finish_non_exhaustive()
    }
}

impl<'a> Page<'a> {
    pub(crate) fn new(
        doc: &'a Document,
        index: usize,
        id: ObjectId,
        ancestors: Vec<ObjectId>,
    ) -> Self {
        Page {
            doc,
            index,
            id,
            ancestors,
        }
    }

    /// The page's stable handle.
    pub fn id(&self) -> PageId {
        PageId(self.id)
    }

    /// The page's 0-based index in the document.
    pub fn index(&self) -> usize {
        self.index
    }

    /// The `/Pages` nodes above the page, nearest first: the nodes it inherits attributes from.
    pub fn ancestors(&self) -> &[ObjectId] {
        &self.ancestors
    }

    /// The page object (a dictionary, `/Type /Page`).
    ///
    /// # Errors
    /// The errors of [`Store::deref`].
    pub fn object(&self) -> Result<Arc<Object>> {
        crate::resolve(self.store(), self.id)
    }

    /// The media box (§7.7.3.3, §14.11.2; inheritable): the page's physical boundaries.
    ///
    /// When neither the page nor its ancestors have a valid one, US Letter
    /// ([`Rect::US_LETTER`]) is returned and a diagnostic recorded, as pdf.js does.
    pub fn media_box(&self) -> Rect {
        self.lookup_box(keys::MEDIA_BOX, Scope::All)
            .unwrap_or_else(|| {
                self.report(format!(
                    "page {} ({}) has no valid /MediaBox; US Letter assumed",
                    self.index, self.id
                ));
                Rect::US_LETTER
            })
    }

    /// The crop box (§7.7.3.3, §14.11.2; inheritable): the region the page is displayed or
    /// printed in. Defaults to the media box and is clipped to it.
    pub fn crop_box(&self) -> Rect {
        let media = self.media_box();
        self.clipped_box(CROP_BOX, Scope::All, &media)
            .unwrap_or(media)
    }

    /// The bleed box (§14.11.2): the region to clip to in a production environment. Defaults
    /// to the crop box; clipped to the media box.
    pub fn bleed_box(&self) -> Rect {
        self.leaf_box(BLEED_BOX)
    }

    /// The trim box (§14.11.2): the intended dimensions of the finished page. Defaults to the
    /// crop box; clipped to the media box.
    pub fn trim_box(&self) -> Rect {
        self.leaf_box(TRIM_BOX)
    }

    /// The art box (§14.11.2): the extent of the page's meaningful content. Defaults to the
    /// crop box; clipped to the media box.
    pub fn art_box(&self) -> Rect {
        self.leaf_box(ART_BOX)
    }

    /// The rotation (§7.7.3.3, inheritable), normalized from any multiple of 90 degrees.
    ///
    /// A `/Rotate` that is a number but not a multiple of 90 gives [`Rotation::R0`] and a
    /// diagnostic (as pdf.js does); one that is not a number is ignored with a diagnostic and
    /// the lookup continues with the ancestors.
    pub fn rotation(&self) -> Rotation {
        self.rotation_in(Scope::All).unwrap_or_default()
    }

    /// The rotation found in the nodes `scope` covers, as [`Page::rotation`] reads it; `None`
    /// when none of them has a `/Rotate` that is a number.
    pub(crate) fn rotation_in(&self, scope: Scope) -> Option<Rotation> {
        self.lookup(ROTATE, scope, |store, value| {
            let value = store.deref(value)?;
            let degrees = match &*value {
                Object::Int(i) => Some(*i),
                // §7.7.3.3 says integer; integral reals (`90.0`) are common enough to accept.
                Object::Real(r) if r.fract() == 0.0 && r.abs() < 1e15 => Some(*r as i64),
                _ => None,
            };
            Ok(degrees.map(|d| {
                Rotation::from_degrees(d).unwrap_or_else(|| {
                    self.report(format!(
                        "page {} ({}) has /Rotate {d}, not a multiple of 90; 0 used",
                        self.index, self.id
                    ));
                    Rotation::R0
                })
            }))
        })
    }

    /// The page's size as displayed: the crop box's width and height, swapped when the page is
    /// rotated by 90 or 270 degrees.
    pub fn effective_size(&self) -> (f64, f64) {
        sideways_size(&self.crop_box(), self.rotation())
    }

    /// The page's size, boxes and rotation as a plain value.
    ///
    /// ```
    /// use folioxide_model::{Document, Rect, Rotation};
    /// use folioxide_syntax::OpenOptions;
    ///
    /// // A one-page file without a cross-reference table (the store finds the objects).
    /// let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
    /// 2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
    /// 3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Rotate 90 >>\nendobj\n\
    /// trailer\n<< /Root 1 0 R >>\n%%EOF\n";
    /// let doc = Document::open(pdf.to_vec(), &OpenOptions::default())?;
    /// let info = doc.page(0)?.info();
    /// assert_eq!(info.index, 0);
    /// assert_eq!((info.width, info.height), (842.0, 595.0));
    /// assert_eq!(info.media_box, Rect::new(0.0, 0.0, 595.0, 842.0));
    /// assert_eq!(info.crop_box, info.media_box);
    /// assert_eq!(info.rotation, Rotation::R90);
    /// # Ok::<(), folioxide_syntax::Error>(())
    /// ```
    pub fn info(&self) -> PageInfo {
        let crop_box = self.crop_box();
        let rotation = self.rotation();
        let (width, height) = sideways_size(&crop_box, rotation);
        PageInfo {
            index: self.index,
            width,
            height,
            media_box: self.media_box(),
            crop_box,
            rotation,
        }
    }

    /// The resource dictionary (§7.7.3.3, §7.8.3; inheritable), or `None` when neither the page
    /// nor its ancestors have one. A `/Resources` that is not a dictionary is ignored with a
    /// diagnostic.
    ///
    /// # Errors
    /// The errors of [`Store::deref`] (in lenient mode only
    /// [`ErrorCode::LimitExceeded`](folioxide_syntax::ErrorCode::LimitExceeded)).
    pub fn resources(&self) -> Result<Option<Dict>> {
        let mut found = None;
        for (id, dict) in self.nodes(Scope::All) {
            let dict = dict?;
            let Some(value) = dict.as_dict().and_then(|d| d.get(keys::RESOURCES)) else {
                continue;
            };
            let value = self.store().deref(value)?;
            match &*value {
                Object::Dict(resources) => {
                    found = Some(resources.clone());
                    break;
                }
                Object::Null => {}
                other => self.report(format!(
                    "the /Resources of {id} is {}, not a dictionary; ignored",
                    crate::type_phrase(other)
                )),
            }
        }
        Ok(found)
    }

    fn store(&self) -> &'a Store {
        self.doc.store()
    }

    fn report(&self, message: String) {
        self.doc
            .log()
            .report(DiagnosticKind::PageAttribute, message);
    }

    /// The nodes `scope` covers, nearest first: each id with the object it resolves to.
    fn nodes(&self, scope: Scope) -> impl Iterator<Item = (ObjectId, Result<Arc<Object>>)> + '_ {
        let (own, ancestors, parents) = match scope {
            Scope::Own => (Some(self.id), &[][..], Vec::new()),
            Scope::Inherited => (None, self.ancestors.as_slice(), Vec::new()),
            Scope::All => (Some(self.id), self.ancestors.as_slice(), Vec::new()),
            Scope::Parents => (None, &[][..], self.parent_chain()),
        };
        own.into_iter()
            .chain(ancestors.iter().copied())
            .chain(parents)
            .map(|id| (id, crate::resolve(self.store(), id)))
    }

    /// The nodes a reader that inherits along `/Parent` links reaches from the page, nearest
    /// first: the page's `/Parent`, that node's `/Parent`, and so on (pdf.js reads inherited
    /// attributes this way, §7.7.3.4 describes inheritance through the ancestors).
    ///
    /// Poppler and this crate inherit along the path the page-tree walk took instead
    /// ([`Page::ancestors`]); qpdf copies `/MediaBox` and `/Resources` from that path onto the
    /// page when it reads the tree, but follows `/Parent` for `/CropBox` and `/Rotate`. The
    /// paths agree unless a `/Parent` is wrong, which the walk reports. The chain ends at a node without an indirect `/Parent`, at a node already in it
    /// (a cycle), and after [`Limits::max_page_tree_depth`] nodes.
    ///
    /// [`Limits::max_page_tree_depth`]: folioxide_syntax::Limits::max_page_tree_depth
    pub(crate) fn parent_chain(&self) -> Vec<ObjectId> {
        let max = usize::from(self.store().limits().max_page_tree_depth);
        let mut chain: Vec<ObjectId> = Vec::new();
        let mut current = self.id;
        while chain.len() < max {
            let Ok(object) = crate::resolve(self.store(), current) else {
                break;
            };
            let Some(next) = object.as_dict().and_then(|d| d.get_ref(keys::PARENT)) else {
                break;
            };
            // The chain is at most `max` (64 by default) long, so a linear search is cheap.
            if next == self.id || chain.contains(&next) {
                break;
            }
            chain.push(next);
            current = next;
        }
        chain
    }

    /// Looks `key` up in the nodes `scope` covers, nearest first (§7.7.3.4). `read` turns a
    /// value into `Some(T)`, or `None` when the value is invalid: that value is ignored with a
    /// diagnostic and the lookup continues. Errors become diagnostics too, since the box and
    /// rotation accessors have no error channel.
    fn lookup<T>(
        &self,
        key: &[u8],
        scope: Scope,
        read: impl Fn(&Store, &Object) -> Result<Option<T>>,
    ) -> Option<T> {
        let name = String::from_utf8_lossy(key);
        for (id, object) in self.nodes(scope) {
            let object = match object {
                Ok(object) => object,
                Err(err) => {
                    self.report(format!("reading {id} for /{name}: {err}"));
                    continue;
                }
            };
            let Some(value) = object.as_dict().and_then(|d| d.get(key)) else {
                continue;
            };
            let value = match self.store().deref(value) {
                Ok(value) => value,
                Err(err) => {
                    self.report(format!("reading the /{name} of {id}: {err}"));
                    continue;
                }
            };
            // §7.3.7: an entry whose value is null (or a reference to a missing object) is
            // absent.
            if value.is_null() {
                continue;
            }
            match read(self.store(), &value) {
                Ok(Some(v)) => return Some(v),
                Ok(None) => self.report(format!("the /{name} of {id} is invalid; ignored")),
                Err(err) => self.report(format!("reading the /{name} of {id}: {err}")),
            }
        }
        None
    }

    /// A box looked up by [`Page::lookup`], as written (not clipped to the media box).
    pub(crate) fn lookup_box(&self, key: &[u8], scope: Scope) -> Option<Rect> {
        self.lookup(key, scope, Rect::from_object)
    }

    /// The value of `key` in the page object itself (not inherited), references followed;
    /// `None` when it is absent or null.
    pub(crate) fn own_entry(&self, key: &[u8]) -> Option<Object> {
        self.lookup(key, Scope::Own, |_, value| Ok(Some(value.clone())))
    }

    /// A box clipped to `media`; `None` when it is absent or does not overlap `media`.
    fn clipped_box(&self, key: &[u8], scope: Scope, media: &Rect) -> Option<Rect> {
        let rect = self.lookup_box(key, scope)?;
        let clipped = rect.intersect(media);
        if clipped.is_none() {
            self.report(format!(
                "the /{} of page {} ({}) does not overlap its media box; ignored",
                String::from_utf8_lossy(key),
                self.index,
                self.id
            ));
        }
        clipped
    }

    /// A box that is not inherited and defaults to the crop box (bleed, trim, art).
    fn leaf_box(&self, key: &[u8]) -> Rect {
        let media = self.media_box();
        self.clipped_box(key, Scope::Own, &media)
            .unwrap_or_else(|| self.crop_box())
    }
}

/// The size of `rect` as displayed with `rotation`: width and height, swapped when sideways.
fn sideways_size(rect: &Rect, rotation: Rotation) -> (f64, f64) {
    if rotation.is_sideways() {
        (rect.height(), rect.width())
    } else {
        (rect.width(), rect.height())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_normalization() {
        for (degrees, expected) in [
            (0, Some(Rotation::R0)),
            (90, Some(Rotation::R90)),
            (180, Some(Rotation::R180)),
            (270, Some(Rotation::R270)),
            (360, Some(Rotation::R0)),
            (450, Some(Rotation::R90)),
            (-90, Some(Rotation::R270)),
            (-180, Some(Rotation::R180)),
            (-270, Some(Rotation::R90)),
            (-360, Some(Rotation::R0)),
            (1, None),
            (-45, None),
            (i64::MAX, None),
            (i64::MIN, None),
        ] {
            assert_eq!(Rotation::from_degrees(degrees), expected, "{degrees}");
        }
        assert_eq!(Rotation::R270.degrees(), 270);
        assert!(Rotation::R90.is_sideways() && !Rotation::R180.is_sideways());
    }

    #[test]
    fn rect_checked_and_contains() {
        let r = Rect::new(0.0, 0.0, 100.0, 50.0);
        let mut swapped = r;
        swapped.llx = 100.0;
        swapped.urx = 0.0;
        assert_eq!(swapped.checked(), Some(r));
        for bad in [f64::NAN, f64::INFINITY, -1e39] {
            let mut x = r;
            x.urx = bad;
            assert_eq!(x.checked(), None, "{bad}");
        }
        let mut flat = r;
        flat.ury = 0.0;
        assert_eq!(flat.checked(), None);
        // The coordinates are rounded as the serializer writes them (10 fractional digits): a
        // box that is written without area is refused, and the rest are rounded.
        assert_eq!(Rect::new(0.0, 0.0, 1e-12, 1e-12).checked(), None);
        assert_eq!(Rect::new(0.5, 0.0, 0.5 + 1e-11, 1.0).checked(), None);
        assert_eq!(
            Rect::new(-0.0, 1e-11, 0.1 + 0.2, 2.0 / 3.0).checked(),
            Some(Rect::new(0.0, 0.0, 0.3, 0.6666666667))
        );
        // Rounding again changes nothing.
        let rounded = Rect::new(0.1, 1.0 / 7.0, 123456.123456789, 1e9 / 3.0)
            .checked()
            .unwrap();
        assert_eq!(rounded.checked(), Some(rounded));
        assert!(r.contains(&r));
        assert!(r.contains(&Rect::new(10.0, 10.0, 20.0, 20.0)));
        assert!(!r.contains(&Rect::new(10.0, 10.0, 200.0, 20.0)));
        // Integers within the 32-bit range are written as integers, larger ones as reals.
        assert_eq!(
            Rect::new(-2_147_483_647.0, 0.0, 3e9, 1.0).to_object(),
            Object::Array(vec![
                Object::Int(-2_147_483_647),
                Object::Int(0),
                Object::Real(3e9),
                Object::Int(1)
            ])
        );
    }

    #[test]
    fn rotation_conversions() {
        assert_eq!(u16::from(Rotation::R270), 270);
        assert_eq!(Rotation::try_from(-90).unwrap(), Rotation::R270);
        let err = Rotation::try_from(45).unwrap_err();
        assert_eq!(err.code(), folioxide_syntax::ErrorCode::InvalidArgument);
    }

    #[test]
    fn rect_normalizes_and_intersects() {
        let a = Rect::new(10.0, 20.0, 0.0, 0.0);
        assert_eq!((a.llx, a.lly, a.urx, a.ury), (0.0, 0.0, 10.0, 20.0));
        let b = Rect::new(5.0, 5.0, 50.0, 50.0);
        assert_eq!(a.intersect(&b), Some(Rect::new(5.0, 5.0, 10.0, 20.0)));
        assert_eq!(a.intersect(&Rect::new(10.0, 0.0, 20.0, 20.0)), None);
        assert_eq!(
            Rect::new(0.0, 0.0, 612.0, 792.5).to_object(),
            Object::Array(vec![
                Object::Int(0),
                Object::Int(0),
                Object::Int(612),
                Object::Real(792.5)
            ])
        );
    }
}

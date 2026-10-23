//! Signature fields and their widgets: [`SubFilter`], [`FieldSpec`], [`FieldMode`], the
//! discovery of existing fields ([`signature_fields`]) and the field placement rules of a new
//! signature (ISO 32000-2 §12.7.4, §12.7.5.5, §12.5.6.19; M3 brief §3.2, §4.1 and §4.5).
//!
//! **Placement** (what [`prepare`](crate::prepare::prepare) and
//! [`write_placeholder`](crate::placeholder::write_placeholder) do with a [`FieldSpec`]):
//!
//! - A new field is a merged field and widget annotation at the **root** of `/AcroForm
//!   /Fields` (never under `/Kids`): `/FT /Sig`, `/T` the partial name, `/V` an indirect
//!   reference to the new signature dictionary, `/F 132` (Print | Locked), `/Rect [0 0 0 0]`
//!   (invisible, so no `/AP`) and `/P` the page; the widget joins the page's `/Annots`.
//! - An existing, unsigned signature field named by [`FieldSpec::name`] is signed in place: only
//!   its `/V` is set (its widget is already on its page). A field that is signed already, or that
//!   is not a signature field, is refused ([`Error::InvalidArgument`]); one with a FieldMDP
//!   `/Lock` or a seed value dictionary with required constraints is
//!   [`Error::Unsupported`] (M11).
//! - Without a name a new field `Signature{n}` is created, `n` the smallest number from 1 that no
//!   fully qualified field name uses. An existing empty field is never taken over implicitly
//!   (DECISIONS D10, D-18).
//! - `/AcroForm`: created (indirect, `/Fields [W 0 R] /SigFlags 3`) when the catalog has none;
//!   otherwise the object that holds each changed value is edited: the catalog for a direct
//!   AcroForm, the AcroForm object, or the `/Fields` array object. `/SigFlags` becomes 3
//!   (SignaturesExist | AppendOnly, §12.7.3 Table 225) **only** while no signed signature field
//!   exists; once one does, no AcroForm key but `/Fields` changes, because pyHanko's diff policy
//!   would classify an earlier signature as `OTHER` otherwise (brief §4.5, D-6).
//!   `/NeedAppearances` is never touched; a warning says when it is true (D-5).
//! - A **visible** signature ([`SignatureOptions::appearance`]; M4 brief §4.7, DECISIONS D13
//!   D-18): a new field's widget gets the appearance's `/Rect` (default user space of the page,
//!   normalized and rounded as written; it must intersect the page's crop box), `/AP << /N … >>`
//!   (the appearance stream of [`appearance`], with its font and image, in
//!   the same incremental update) and `/MK << /R r >>` on a page rotated by `r ≠ 0`; `/F 132`
//!   stays. An existing empty field merged with its widget keeps its `/Rect` (an appearance
//!   rect must be `None` or equal to it) and gains only `/V` and `/AP`; a field whose widget is
//!   a separate `/Kids` object is [`Error::Unsupported`], and one whose widget has no area is
//!   [`Error::InvalidArgument`].
//! - A certification signature (M4 brief §4.6) is named by the catalog's `/Perms /DocMDP`
//!   (a new direct `/Perms`, or the existing `/Perms` dictionary or object edited; an existing
//!   `/UR3` is kept with a warning). It must be the document's first signature, and an approval
//!   signature on a certified document may not create a new visible field
//!   ([`Error::DocMdpForbids`]).
//!
//! The objects that change are collected as an overlay for
//! [`incremental_suffix_with_overlay`](folioxide_syntax::incremental_suffix_with_overlay): the
//! document itself is never modified.

use std::collections::{BTreeMap, HashSet};

use folioxide_model::text::{decode_text_string, encode_text_string};
use folioxide_model::{Document, PageId, Rect, Rotation};
use folioxide_syntax::serialize::canonical_real;
use folioxide_syntax::{Dict, LimitKind, Object, ObjectId, PdfString, Store};

use crate::appearance::{self, SignatureAppearance};
use crate::docmdp;
use crate::error::{Error, Result};
use crate::prepare::SignatureOptions;

/// The deepest `/Kids` nesting of the field tree that is followed (M3 brief §5 V1).
pub const MAX_FIELD_DEPTH: usize = 32;

/// The most field-tree nodes a walk visits (R-18): beyond it signing fails with
/// [`ErrorCode::LimitExceeded`](folioxide_syntax::ErrorCode::LimitExceeded) and verification
/// examines no further fields (their signature dictionaries are then reported as orphans).
pub const MAX_FIELDS: usize = 100_000;

/// The most bytes of partial names (`/T`, decoded) a walk keeps in total (R-18), with the same
/// consequences as [`MAX_FIELDS`]: a shared or very long `/T` cannot make the walk allocate
/// without bound.
pub const MAX_FIELD_NAME_BYTES_TOTAL: usize = 16 * 1024 * 1024;

/// The longest fully qualified field name that is reported in full; a longer one is shortened
/// to this many bytes and ends with `…` (R-18: a field with a long name and thousands of kids
/// would otherwise repeat the name in every kid's name).
pub const MAX_FIELD_NAME_BYTES: usize = 4096;

/// The annotation flags of a new signature widget: Print (bit 3) | Locked (bit 8)
/// (§12.5.3, Table 167).
pub const WIDGET_FLAGS: i64 = 132;

/// The `/SigFlags` value written while the document has no signed signature field yet:
/// SignaturesExist (bit 1) | AppendOnly (bit 2) (§12.7.3, Table 225).
pub const SIG_FLAGS: i64 = 3;

// Dictionary keys (ISO 32000-2 §12.7.3, §12.7.4, §12.7.5.5, §12.5.2, §12.8.2.2).
const ACRO_FORM: &[u8] = b"AcroForm";
const ANNOTS: &[u8] = b"Annots";
const FIELDS: &[u8] = b"Fields";
const FT: &[u8] = b"FT";
const KIDS: &[u8] = b"Kids";
const LOCK: &[u8] = b"Lock";
const NEED_APPEARANCES: &[u8] = b"NeedAppearances";
const SIG_FLAGS_KEY: &[u8] = b"SigFlags";
const SV: &[u8] = b"SV";
const SV_FF: &[u8] = b"Ff";
const T: &[u8] = b"T";
const V: &[u8] = b"V";
const PERMS: &[u8] = b"Perms";
const DOC_MDP: &[u8] = b"DocMDP";
const UR3: &[u8] = b"UR3";
const AP: &[u8] = b"AP";
const RECT: &[u8] = b"Rect";

/// The `/SubFilter` of the signature dictionary (§12.8.3.1, Table 260).
///
/// Folioxide writes the same CMS for both (PAdES B-B signed attributes); the SubFilter only
/// labels it. With the `serde` feature it is the PDF name, `"ETSI.CAdES.detached"` or
/// `"adbe.pkcs7.detached"`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SubFilter {
    /// `ETSI.CAdES.detached`: a PAdES signature (ETSI EN 319 142-1). The default.
    #[default]
    #[cfg_attr(feature = "serde", serde(rename = "ETSI.CAdES.detached"))]
    EtsiCadesDetached,
    /// `adbe.pkcs7.detached`: a detached PKCS#7/CMS signature (ISO 32000-1 §12.8.3.3).
    #[cfg_attr(feature = "serde", serde(rename = "adbe.pkcs7.detached"))]
    AdbePkcs7Detached,
}

impl SubFilter {
    /// The PDF name, without the slash: `"ETSI.CAdES.detached"` or `"adbe.pkcs7.detached"`.
    ///
    /// ```
    /// use folioxide_sign::field::SubFilter;
    ///
    /// assert_eq!(SubFilter::default().name(), "ETSI.CAdES.detached");
    /// assert_eq!(SubFilter::from_name("adbe.pkcs7.detached"), Some(SubFilter::AdbePkcs7Detached));
    /// ```
    pub fn name(self) -> &'static str {
        match self {
            SubFilter::EtsiCadesDetached => "ETSI.CAdES.detached",
            SubFilter::AdbePkcs7Detached => "adbe.pkcs7.detached",
        }
    }

    /// The SubFilter with this PDF name (as [`SubFilter::name`] writes it).
    pub fn from_name(name: &str) -> Option<SubFilter> {
        [SubFilter::EtsiCadesDetached, SubFilter::AdbePkcs7Detached]
            .into_iter()
            .find(|s| s.name() == name)
    }
}

/// Which signature field to sign, or which one to create (M3 brief §4.5).
///
/// The default creates a new invisible field `Signature{n}` on the first page. With the `serde`
/// feature the fields are `name`, `page` and `mode`, all optional.
///
/// ```
/// use folioxide_sign::field::{FieldMode, FieldSpec};
///
/// let spec = FieldSpec::new()
///     .with_name(Some("Approval".into()))
///     .with_mode(FieldMode::ExistingOnly);
/// assert_eq!(spec.name.as_deref(), Some("Approval"));
/// assert_eq!(spec.page, 0);
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase", default)
)]
pub struct FieldSpec {
    /// The field name. For an existing field, its fully qualified name (§12.7.4.2: the partial
    /// names joined with `.`); for a new field, its partial name, which must not contain `.`.
    /// `None`: a new field `Signature{n}`.
    pub name: Option<String>,
    /// The 0-based index of the page that holds a new field's widget. Default 0. It must be a
    /// page of the document even when an existing field is signed ([`Error::PageOutOfRange`]).
    pub page: usize,
    /// Whether an existing field may be used and whether a new one may be created.
    pub mode: FieldMode,
}

impl FieldSpec {
    /// The default: a new field `Signature{n}` on the first page.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`FieldSpec::name`].
    #[must_use]
    pub fn with_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    /// Sets [`FieldSpec::page`].
    #[must_use]
    pub fn with_page(mut self, page: usize) -> Self {
        self.page = page;
        self
    }

    /// Sets [`FieldSpec::mode`].
    #[must_use]
    pub fn with_mode(mut self, mode: FieldMode) -> Self {
        self.mode = mode;
        self
    }
}

/// Whether a signature uses an existing field, creates one, or either (M3 brief §4.5).
///
/// With the `serde` feature it is `"createOrUse"`, `"existingOnly"` or `"createOnly"`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum FieldMode {
    /// Sign the named field when it exists and is an unsigned signature field; otherwise create
    /// a new field with that name. Without a name, always create a new field. The default.
    #[default]
    CreateOrUse,
    /// Sign the named existing field; [`Error::NotFound`] when there is none, and
    /// [`Error::InvalidArgument`] without a name.
    ExistingOnly,
    /// Always create a new field; [`Error::InvalidArgument`] when the name is taken.
    CreateOnly,
}

/// A terminal signature field of the document, as [`signature_fields`] lists it.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SignatureField {
    /// The fully qualified field name (§12.7.4.2).
    pub name: String,
    /// The field dictionary's object; `None` when the field is a direct dictionary (which a new
    /// signature cannot use).
    pub field: Option<ObjectId>,
    /// Whether the field has a value (a `/V` that is not `null`): it is signed.
    pub signed: bool,
    /// The signature dictionary `/V` refers to, when `/V` is an indirect reference.
    pub value: Option<ObjectId>,
}

/// The terminal signature fields (`/FT /Sig`, the field's own or inherited) reachable from
/// `/AcroForm /Fields`, in document order, signed or not.
///
/// `/Kids` are followed to [`MAX_FIELD_DEPTH`] levels; an object met twice is visited once.
///
/// ```
/// use folioxide_model::Document;
/// use folioxide_sign::field::signature_fields;
/// use folioxide_syntax::OpenOptions;
///
/// let pdf = folioxide_testkit::fixtures::syntax::minimal();
/// let doc = Document::open(pdf, &OpenOptions::default())?;
/// assert!(signature_fields(&doc)?.is_empty());
/// # Ok::<(), folioxide_sign::Error>(())
/// ```
///
/// # Errors
/// The errors of [`Store::resolve`]; [`ErrorCode::LimitExceeded`] for a field tree deeper than
/// [`MAX_FIELD_DEPTH`]; [`ErrorCode::TypeMismatch`] when `/AcroForm` is not a dictionary.
///
/// [`ErrorCode::LimitExceeded`]: folioxide_syntax::ErrorCode::LimitExceeded
/// [`ErrorCode::TypeMismatch`]: folioxide_syntax::ErrorCode::TypeMismatch
pub fn signature_fields(doc: &Document) -> Result<Vec<SignatureField>> {
    let store = doc.store();
    let catalog = doc.catalog()?;
    let Some(acroform) = acroform_of(store, catalog.as_dict())? else {
        return Ok(Vec::new());
    };
    let nodes = walk_fields(store, &acroform.dict)?;
    let mut names = NameBudget::new();
    Ok(nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.terminal && node.is_signature())
        .map(|(index, node)| SignatureField {
            signed: node.is_signed(store),
            value: node.dict.get(V).and_then(Object::as_ref),
            name: names.name(&nodes, index).0,
            field: node.id,
        })
        .collect())
}

// =================================================================================================
// Field tree walk (shared with verification, brief §5 V1)
// =================================================================================================

/// One node of the field tree (§12.7.4).
///
/// The fully qualified name is not stored per node (a long parent name would be repeated in
/// every kid): it is built on demand from the partial names up the parent chain
/// ([`qualified_name_len`], [`NameBudget::name`]).
#[derive(Clone, Debug)]
pub(crate) struct FieldNode {
    /// The field dictionary's object; `None` for a direct dictionary.
    pub(crate) id: Option<ObjectId>,
    /// The field dictionary.
    pub(crate) dict: Dict,
    /// The partial name `/T`, decoded (§12.7.4.2); `None` without one.
    pub(crate) partial: Option<String>,
    /// The index of the parent node in the walk's output; `None` at the root of `/Fields`.
    pub(crate) parent: Option<usize>,
    /// The field type `/FT`, the node's own or inherited (§12.7.4.1, Table 226).
    pub(crate) field_type: Option<Vec<u8>>,
    /// No kid of this node is a field (a kid with `/T`): its kids, if any, are widgets.
    pub(crate) terminal: bool,
}

/// The partial names of node `index` and its ancestors that the fully qualified name joins,
/// from the root down (nodes without `/T` add nothing, §12.7.4.2).
fn name_parts(nodes: &[FieldNode], index: usize) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut at = Some(index);
    // The walk bounds the depth; the bound here only guards against a malformed parent chain.
    for _ in 0..=MAX_FIELD_DEPTH {
        let Some(node) = at.and_then(|i| nodes.get(i)) else {
            break;
        };
        if let Some(partial) = node.partial.as_deref() {
            parts.push(partial);
        }
        at = node.parent;
    }
    parts.reverse();
    parts
}

/// Joins partial names as the walk always did: an empty name so far is replaced, otherwise
/// `.` and the part are appended, writing at most `cap` bytes (on a character boundary); the
/// second value says whether the name was cut.
fn join_name(parts: &[&str], cap: usize) -> (String, bool) {
    let mut name = String::new();
    let mut cut = false;
    for part in parts {
        let separator = if name.is_empty() { "" } else { "." };
        for piece in [separator, part] {
            let room = cap.saturating_sub(name.len());
            if piece.len() <= room {
                name.push_str(piece);
            } else {
                let mut end = room;
                while end > 0 && !piece.is_char_boundary(end) {
                    end -= 1;
                }
                name.push_str(piece.get(..end).unwrap_or_default());
                cut = true;
                break;
            }
        }
        if cut {
            break;
        }
    }
    (name, cut)
}

/// The length in bytes of the fully qualified name of node `index`, without building it.
pub(crate) fn qualified_name_len(nodes: &[FieldNode], index: usize) -> usize {
    let parts = name_parts(nodes, index);
    let mut len = 0usize;
    for part in parts {
        if len > 0 {
            len = len.saturating_add(1);
        }
        len = len.saturating_add(part.len());
    }
    len
}

/// Builds fully qualified field names within a total budget ([`MAX_FIELD_NAME_BYTES_TOTAL`]),
/// each at most [`MAX_FIELD_NAME_BYTES`] long: a name past either limit is shortened and ends
/// with `…`.
pub(crate) struct NameBudget {
    left: usize,
}

impl NameBudget {
    pub(crate) fn new() -> NameBudget {
        NameBudget {
            left: MAX_FIELD_NAME_BYTES_TOTAL,
        }
    }

    /// The fully qualified name of node `index` and whether it was shortened.
    pub(crate) fn name(&mut self, nodes: &[FieldNode], index: usize) -> (String, bool) {
        let cap = MAX_FIELD_NAME_BYTES.min(self.left);
        let (mut name, cut) = join_name(&name_parts(nodes, index), cap);
        if cut {
            name.push('…');
        }
        self.left = self.left.saturating_sub(name.len());
        (name, cut)
    }
}

/// The fully qualified name of node `index` when it is exactly `wanted` (compared without
/// building a name of another length).
fn has_name(nodes: &[FieldNode], index: usize, wanted: &str) -> bool {
    qualified_name_len(nodes, index) == wanted.len()
        && join_name(&name_parts(nodes, index), wanted.len()).0 == wanted
}

impl FieldNode {
    /// Whether the field type is `/Sig`.
    pub(crate) fn is_signature(&self) -> bool {
        self.field_type.as_deref() == Some(b"Sig".as_slice())
    }

    /// Whether the field's own `/V` is present and not `null`.
    pub(crate) fn is_signed(&self, store: &Store) -> bool {
        self.dict
            .get(V)
            .is_some_and(|v| store.deref(v).is_ok_and(|v| !v.is_null()))
    }
}

/// Walks the field tree from `acroform`'s `/Fields`, depth first in document order.
///
/// # Errors
/// The errors of [`Store::resolve`]; [`ErrorCode::LimitExceeded`] for a tree deeper than
/// [`MAX_FIELD_DEPTH`].
///
/// [`ErrorCode::LimitExceeded`]: folioxide_syntax::ErrorCode::LimitExceeded
pub(crate) fn walk_fields(store: &Store, acroform: &Dict) -> Result<Vec<FieldNode>> {
    walk(store, acroform, true).map(|(nodes, _)| nodes)
}

/// [`walk_fields`] for verification (brief §5 V1): the walk stops descending at
/// [`MAX_FIELD_DEPTH`], and stops at [`MAX_FIELDS`] nodes or [`MAX_FIELD_NAME_BYTES_TOTAL`] bytes
/// of partial names, instead of failing, and says whether it did (the nodes at the depth limit
/// are then reported as terminal).
///
/// # Errors
/// The errors of [`Store::resolve`].
pub(crate) fn walk_fields_bounded(
    store: &Store,
    acroform: &Dict,
) -> Result<(Vec<FieldNode>, bool)> {
    walk(store, acroform, false)
}

/// The field tree walk; `fail_on_depth` chooses between an error and a truncation at
/// [`MAX_FIELD_DEPTH`], [`MAX_FIELDS`] and [`MAX_FIELD_NAME_BYTES_TOTAL`].
fn walk(store: &Store, acroform: &Dict, fail_on_depth: bool) -> Result<(Vec<FieldNode>, bool)> {
    struct Pending {
        item: Object,
        parent: Option<usize>,
        parent_type: Option<Vec<u8>>,
        depth: usize,
    }
    let limit = |kind: LimitKind, max: usize| {
        Error::Syntax(folioxide_syntax::Error::limit(kind, max as u64, None))
    };

    let roots = match acroform.get(FIELDS) {
        Some(fields) => store.deref(fields)?.as_array().map(<[Object]>::to_vec),
        None => None,
    }
    .unwrap_or_default();

    let mut out: Vec<FieldNode> = Vec::new();
    let mut truncated = false;
    let mut name_bytes = 0usize;
    let mut visited: HashSet<ObjectId> = HashSet::new();
    if roots.len() > MAX_FIELDS {
        if fail_on_depth {
            return Err(limit(LimitKind::MaxObjects, MAX_FIELDS));
        }
        truncated = true;
    }
    let mut stack: Vec<Pending> = roots
        .into_iter()
        .take(MAX_FIELDS)
        .rev()
        .map(|item| Pending {
            item,
            parent: None,
            parent_type: None,
            depth: 1,
        })
        .collect();

    while let Some(Pending {
        item,
        parent,
        parent_type,
        depth,
    }) = stack.pop()
    {
        let id = item.as_ref();
        if let Some(id) = id
            && !visited.insert(id)
        {
            continue;
        }
        if out.len() >= MAX_FIELDS {
            if fail_on_depth {
                return Err(limit(LimitKind::MaxObjects, MAX_FIELDS));
            }
            truncated = true;
            break;
        }
        let Some(dict) = field_dict(store, &item)? else {
            continue;
        };
        let partial = match dict.get(T) {
            Some(t) => store.deref(t)?.as_str_bytes().map(decode_text_string),
            None => None,
        };
        name_bytes = name_bytes.saturating_add(partial.as_ref().map_or(0, String::len));
        if name_bytes > MAX_FIELD_NAME_BYTES_TOTAL {
            if fail_on_depth {
                return Err(limit(LimitKind::MaxStringLen, MAX_FIELD_NAME_BYTES_TOTAL));
            }
            truncated = true;
            break;
        }
        let index = out.len();
        let own_type = match dict.get(FT) {
            Some(ft) => store.deref(ft)?.as_name().map(|n| n.as_bytes().to_vec()),
            None => None,
        };
        let field_type = own_type.or(parent_type);

        // Kids with a partial name are fields; the others are widget annotations (§12.7.4).
        let mut field_kids = Vec::new();
        if let Some(kids) = dict.get(KIDS)
            && let Some(kids) = store.deref(kids)?.as_array()
        {
            for kid in kids {
                if kid.as_ref().is_some_and(|k| visited.contains(&k)) {
                    continue;
                }
                if out
                    .len()
                    .saturating_add(stack.len())
                    .saturating_add(field_kids.len())
                    >= MAX_FIELDS
                {
                    if fail_on_depth {
                        return Err(limit(LimitKind::MaxObjects, MAX_FIELDS));
                    }
                    truncated = true;
                    break;
                }
                let is_field = match store.deref(kid)?.as_dict() {
                    Some(k) => k.contains_key(T),
                    None => false,
                };
                if is_field {
                    field_kids.push(kid.clone());
                }
            }
        }
        if !field_kids.is_empty() && depth >= MAX_FIELD_DEPTH {
            if fail_on_depth {
                return Err(Error::Syntax(folioxide_syntax::Error::limit(
                    LimitKind::MaxNestingDepth,
                    MAX_FIELD_DEPTH as u64,
                    None,
                )));
            }
            truncated = true;
            field_kids.clear();
        }
        let terminal = field_kids.is_empty();
        for kid in field_kids.into_iter().rev() {
            stack.push(Pending {
                item: kid,
                parent: Some(index),
                parent_type: field_type.clone(),
                depth: depth + 1,
            });
        }
        out.push(FieldNode {
            id,
            dict,
            partial,
            parent,
            field_type,
            terminal,
        });
    }
    Ok((out, truncated))
}

/// The dictionary `item` is or refers to, if it is one.
fn field_dict(store: &Store, item: &Object) -> Result<Option<Dict>> {
    Ok(store.deref(item)?.as_dict().cloned())
}

/// Where the document's interactive form dictionary is (§12.7.3).
#[derive(Clone, Debug)]
pub(crate) struct AcroFormLoc {
    /// The AcroForm object; `None` when it is a direct dictionary in the catalog.
    pub(crate) id: Option<ObjectId>,
    /// The AcroForm dictionary.
    pub(crate) dict: Dict,
}

/// The catalog's `/AcroForm`, or `None` when it has none (absent, `null`, or a reference to a
/// missing object).
///
/// # Errors
/// [`ErrorCode::TypeMismatch`](folioxide_syntax::ErrorCode::TypeMismatch) when `/AcroForm` is
/// neither a dictionary nor `null`; the errors of [`Store::deref`].
pub(crate) fn acroform_of(store: &Store, catalog: Option<&Dict>) -> Result<Option<AcroFormLoc>> {
    let Some(value) = catalog.and_then(|c| c.get(ACRO_FORM)) else {
        return Ok(None);
    };
    let resolved = store.deref(value)?;
    match &*resolved {
        Object::Null => Ok(None),
        Object::Dict(dict) => Ok(Some(AcroFormLoc {
            id: value.as_ref(),
            dict: dict.clone(),
        })),
        other => Err(type_mismatch("/AcroForm", "dictionary", other)),
    }
}

/// A [`TypeMismatch`](folioxide_syntax::ErrorCode::TypeMismatch) error naming the entry.
fn type_mismatch(what: &str, expected: &str, found: &Object) -> Error {
    Error::Syntax(folioxide_syntax::Error::new(
        folioxide_syntax::ErrorCode::TypeMismatch,
        format!(
            "{what} must be a {expected}, not a {}; repair the document first",
            found.type_name()
        ),
    ))
}

// =================================================================================================
// Placement (brief §4.5)
// =================================================================================================

/// How many numbers below [`Limits::max_objects`](folioxide_syntax::Limits::max_objects) the
/// newest trailer's `/Size` must leave for [`NewNumbers::new`] to number from it: far more than
/// any signature writes (its dictionary, a widget, an appearance with its font and image
/// objects, an AcroForm), so that following an over-declared `/Size` never makes signing run
/// out of numbers where numbering from [`Store::next_object_number`] would not.
const SIZE_HEADROOM: u32 = 1 << 16;

/// Object numbers for the new objects of a signature: from [`Store::next_object_number`] up,
/// or from the newest trailer's `/Size` when that is higher (see [`NewNumbers::new`]), never a
/// freed number (brief R-7).
#[derive(Clone, Copy, Debug)]
pub(crate) struct NewNumbers {
    next: u32,
    max: u32,
}

impl NewNumbers {
    /// Numbers from the larger of `store.next_object_number()` and the newest revision's
    /// trailer `/Size` (a direct integer that leaves [`SIZE_HEADROOM`] numbers below the
    /// limit), below the store's [`Limits::max_objects`](folioxide_syntax::Limits::max_objects).
    ///
    /// ISO 32000-2 §7.5.5 (Table 15) makes `/Size` one greater than the highest object number,
    /// so for a conforming file both starts are the same. A revision may over-declare it
    /// (`/Size 100` over objects up to 11). An update's `/Size` below the previous one makes
    /// the verifier call every earlier signature `Other`
    /// (`revisions::differential::size_ambiguity`, manager ruling R-26: PDFium keeps only the
    /// objects below the newest `/Size`). Numbering from the previous `/Size`, as pyHanko's
    /// incremental writer does, keeps the new `/Size` (the highest number it lists + 1) above
    /// it, so a co-signature leaves the earlier signatures' level where pyHanko leaves it and
    /// writes a conforming `/Size` (M4 final fix round 2, expert finding 1); the incremental
    /// writer itself also never writes a `/Size` below the previous one (ruling R-30 (a)). Every
    /// number from `next_object_number()` up is unused, so the numbers skipped below the
    /// previous `/Size` stay unused (§7.3.10: an unlisted number is `null`).
    pub(crate) fn new(store: &Store) -> NewNumbers {
        let max = store.limits().max_objects;
        let next = store.next_object_number();
        let declared = store
            .revisions()
            .last()
            .and_then(|newest| match newest.trailer.get(b"Size") {
                Some(Object::Int(size)) => u32::try_from(*size).ok(),
                _ => None,
            })
            .filter(|&size| size <= max.saturating_sub(SIZE_HEADROOM));
        NewNumbers {
            next: declared.map_or(next, |size| size.max(next)),
            max,
        }
    }

    /// The next new identifier, generation 0.
    ///
    /// # Errors
    /// [`ErrorCode::LimitExceeded`](folioxide_syntax::ErrorCode::LimitExceeded) when no number
    /// is left.
    pub(crate) fn take(&mut self) -> Result<ObjectId> {
        let num = self.next;
        if num == 0 || num >= self.max {
            return Err(Error::Syntax(folioxide_syntax::Error::limit(
                LimitKind::MaxObjects,
                u64::from(self.max),
                None,
            )));
        }
        self.next = num.saturating_add(1);
        Ok(ObjectId::new(num, 0))
    }
}

/// The objects an incremental update writes on top of the store's own state, without changing
/// the store: each edit starts from the overlay's version of the object, or the store's.
pub(crate) struct Overlay<'s> {
    store: &'s Store,
    objects: BTreeMap<ObjectId, Object>,
}

impl<'s> Overlay<'s> {
    /// An empty overlay over `store`.
    pub(crate) fn new(store: &'s Store) -> Self {
        Overlay {
            store,
            objects: BTreeMap::new(),
        }
    }

    /// The current value of `id`: the overlay's, or the store's (its edits included).
    pub(crate) fn current(&self, id: ObjectId) -> Result<Object> {
        match self.objects.get(&id) {
            Some(obj) => Ok(obj.clone()),
            None => Ok(Object::clone(&*self.store.resolve(id)?)),
        }
    }

    /// The current value of `id`, which must be a dictionary.
    fn current_dict(&self, id: ObjectId, what: &str) -> Result<Dict> {
        match self.current(id)? {
            Object::Dict(dict) => Ok(dict),
            other => Err(type_mismatch(what, "dictionary", &other)),
        }
    }

    /// Writes `obj` as object `id`.
    pub(crate) fn set(&mut self, id: ObjectId, obj: Object) {
        self.objects.insert(id, obj);
    }

    /// The objects.
    pub(crate) fn into_objects(self) -> BTreeMap<ObjectId, Object> {
        self.objects
    }
}

/// What the field placement decided: the signature dictionary's number, the field, and the
/// objects to write besides the signature dictionary.
#[derive(Debug)]
pub(crate) struct FieldPlan {
    /// The new signature dictionary's identifier (a new number).
    pub(crate) sig: ObjectId,
    /// The signed field: the new merged field/widget, or the existing field.
    pub(crate) field: ObjectId,
    /// The field's fully qualified name.
    pub(crate) name: String,
    /// Whether the field is new.
    pub(crate) created: bool,
    /// The field, widget, page, `/Annots`, AcroForm, `/Fields` and catalog objects that change,
    /// and a visible signature's appearance stream, font and image.
    pub(crate) objects: BTreeMap<ObjectId, Object>,
    /// Observations for the caller (for example `/NeedAppearances true`, or appearance text
    /// that was shortened).
    pub(crate) warnings: Vec<String>,
}

/// Which field the signature goes into.
enum Target {
    /// An existing, unsigned signature field.
    Existing { id: ObjectId, name: String },
    /// A new root-level field with this partial name.
    New { name: String },
}

/// Decides where the signature goes (brief §4.5) and builds the objects that change, without
/// changing `doc`: the field placement of `options.field`, and for a certification
/// (`options.certification`) the catalog's `/Perms /DocMDP` (M4 brief §4.6).
///
/// **Certification rules** (M4 brief §4.6, [`Error::DocMdpForbids`] naming the rule):
/// - (a) certifying is refused when any signature field of the document has a value (a
///   signature or a document timestamp: "it shall be the first signed field", §12.8.2.2.1), and
///   when the catalog already has `/Perms /DocMDP`, signed field or not;
/// - (b) on a certified document an approval signature (`P = 2` or `3`; `P = 1` is refused by
///   [`check_signable`](crate::placeholder::check_signable)) may use a new invisible field or an
///   existing empty field, visible or not, but not a **new visible** field (D-3: pyHanko reports
///   the certification `OTHER` then);
/// - (c) a certification may have an appearance: the field is the certifier's own.
///
/// With [`SignatureOptions::appearance`] the widget becomes visible (module documentation;
/// M4 brief §4.7): `signer` is the signer certificate's display name (common name, else
/// subject) for the default text, when known.
///
/// # Errors
/// - [`Error::DocMdpForbids`]: the certification rules above.
/// - [`Error::PageOutOfRange`]: `spec.page` is not a page (a document without pages cannot be
///   signed).
/// - [`Error::InvalidArgument`]: an empty name, a new name with `.`, a name that
///   [`FieldMode::CreateOnly`] finds taken, [`FieldMode::ExistingOnly`] without a name, a named
///   field that is not a terminal signature field or is signed already.
/// - [`Error::NotFound`]: [`FieldMode::ExistingOnly`] and no field has the name.
/// - [`Error::Unsupported`]: the field has a `/Lock` dictionary or a seed value dictionary with
///   required constraints (M11), or is a direct object; a visible signature in an existing field
///   whose widget is a separate `/Kids` object (D-18).
/// - [`Error::InvalidArgument`] for a visible signature: a new field without an appearance
///   rect; a rect that is not finite, has no area or misses the page's crop box; an existing
///   field whose widget has no area, lies on no page, has annotation flags other than Print,
///   ReadOnly, Locked and LockedContents (Hidden, NoView, NoZoom, NoRotate, ToggleNoView:
///   manager ruling R-3), or whose `/Rect` differs from the appearance rect; and the appearance errors of [`appearance`](crate::appearance) (font
///   size, border width, text limits, an image that is not a supported JPEG).
/// - [`ErrorCode::TypeMismatch`](folioxide_syntax::ErrorCode::TypeMismatch): the catalog, page,
///   `/AcroForm`, `/Fields`, `/Annots` or `/Perms` has the wrong type.
/// - The errors of [`Document::page_ids`] and [`Store::resolve`].
pub(crate) fn plan(
    doc: &Document,
    options: &SignatureOptions,
    signer: Option<&str>,
) -> Result<FieldPlan> {
    let spec = &options.field;
    let store = doc.store();
    let page_ids = doc.page_ids()?;
    let page = page_ids
        .get(spec.page)
        .map(|p| p.0)
        .ok_or(Error::PageOutOfRange(spec.page))?;
    let catalog_id = store.root_id().ok_or_else(|| {
        Error::Syntax(folioxide_syntax::Error::new(
            folioxide_syntax::ErrorCode::Xref,
            "the trailer has no /Root: there is no document catalog",
        ))
    })?;
    let catalog = doc.catalog()?;
    let acroform = acroform_of(store, catalog.as_dict())?;
    let fields = match &acroform {
        Some(acroform) => walk_fields(store, &acroform.dict)?,
        None => Vec::new(),
    };
    let signed_field = fields
        .iter()
        .position(|f| f.terminal && f.is_signature() && f.is_signed(store));
    let any_signed = signed_field.is_some();

    // Certification rule (a), before anything else is decided (M4 brief §4.6).
    if let Some(permissions) = options.certification {
        if let Some(index) = signed_field {
            let name = NameBudget::new().name(&fields, index).0;
            return Err(Error::DocMdpForbids(format!(
                "DocMDP rule (a): a certification signature (P = {}) must be the first signature \
                 of the document (ISO 32000-2 §12.8.2.2.1), but the field {name:?} is signed \
                 already",
                permissions.p()
            )));
        }
        if docmdp::has_perms_docmdp(doc)? {
            return Err(Error::DocMdpForbids(
                "DocMDP rule (a): the document is certified already (its catalog has /Perms \
                 /DocMDP); a document has at most one certification signature (ISO 32000-2 \
                 §12.8.2.2.1)"
                    .to_owned(),
            ));
        }
    }

    let target = choose_target(store, spec, &fields)?;

    // Rule (b), D-3: an approval signature on a certified document may not create a new
    // visible field (pyHanko's `valid_when_certifying`: the certification would be OTHER).
    if options.certification.is_none()
        && options.appearance.is_some()
        && matches!(target, Target::New { .. })
        && let Some(certified) = docmdp::certification(doc)?
    {
        return Err(Error::DocMdpForbids(format!(
            "DocMDP rule (b): the document is certified (P = {}), and a new visible signature \
             field would invalidate the certification (D-3; pyHanko reports such a change as \
             OTHER); sign invisibly, or sign an existing empty signature field",
            certified.p
        )));
    }

    let mut numbers = NewNumbers::new(store);
    let mut overlay = Overlay::new(store);
    let mut warnings = Vec::new();
    let visible = options
        .appearance
        .as_ref()
        .map(|app| (app, appearance::text_lines(app, options, signer)));
    let (sig, field, name, widget) = match target {
        Target::Existing { id, name } => {
            let sig = numbers.take()?;
            let mut dict = overlay.current_dict(id, "the signature field")?;
            if any_signed && let Some(warning) = shared_appearance_warning(&fields, id, &dict) {
                warnings.push(warning);
            }
            dict.insert(V, sig);
            if let Some((app, lines)) = &visible {
                // D-18: the field's own /Rect, never changed; only /V and /AP are written
                // (pyHanko's SigFieldModificationRule allows /AP when a field is signed).
                let (rect, rotation) = existing_widget(doc, &page_ids, &dict, id, &name, app)?;
                let built = appearance::build(app, rect, rotation, lines, &mut numbers)?;
                dict.insert(AP, appearance::ap_dict(built.normal));
                for (id, object) in built.objects {
                    overlay.set(id, object);
                }
                warnings.extend(built.warnings);
            }
            overlay.set(id, Object::Dict(dict));
            (sig, id, name, None)
        }
        Target::New { name } => {
            let widget = numbers.take()?;
            let sig = numbers.take()?;
            let mut dict = widget_dict(&name, sig, page);
            if let Some((app, lines)) = &visible {
                let page_view = doc.page(spec.page)?;
                let rect = app.rect.ok_or_else(|| {
                    Error::InvalidArgument(format!(
                        "a new visible signature field ({name:?}) needs an appearance rect; \
                         SignatureAppearance::for_existing_field() is for an existing empty \
                         signature field"
                    ))
                })?;
                let rect = appearance::checked_rect(rect, page_view.crop_box())?;
                let rotation = page_view.rotation();
                let built = appearance::build(app, rect, rotation, lines, &mut numbers)?;
                make_visible(&mut dict, rect, rotation, built.normal);
                for (id, object) in built.objects {
                    overlay.set(id, object);
                }
                warnings.extend(built.warnings);
            }
            overlay.set(widget, Object::Dict(dict));
            add_to_annots(&mut overlay, page, widget)?;
            (sig, widget, name, Some(widget))
        }
    };

    edit_acroform(
        &mut overlay,
        &mut numbers,
        catalog_id,
        acroform.as_ref(),
        widget,
        !any_signed,
        &mut warnings,
    )?;
    if options.certification.is_some() {
        add_perms(&mut overlay, catalog_id, sig, &mut warnings)?;
    }

    Ok(FieldPlan {
        sig,
        field,
        name,
        created: widget.is_some(),
        objects: overlay.into_objects(),
        warnings,
    })
}

/// Applies the naming and mode rules of brief §4.5.
fn choose_target(store: &Store, spec: &FieldSpec, fields: &[FieldNode]) -> Result<Target> {
    let Some(name) = spec.name.as_deref() else {
        if spec.mode == FieldMode::ExistingOnly {
            return Err(Error::InvalidArgument(
                "FieldMode::ExistingOnly needs a field name".to_owned(),
            ));
        }
        return Ok(Target::New {
            name: auto_name(fields),
        });
    };
    if name.is_empty() {
        return Err(Error::InvalidArgument(
            "the signature field name is empty".to_owned(),
        ));
    }
    let found = (0..fields.len()).find(|&index| has_name(fields, index, name));
    match found.and_then(|index| fields.get(index)) {
        Some(_) if spec.mode == FieldMode::CreateOnly => Err(Error::InvalidArgument(format!(
            "a field named {name:?} exists already (FieldMode::CreateOnly)"
        ))),
        Some(node) => {
            check_existing(store, node, name)?;
            let id = node.id.ok_or_else(|| {
                Error::Unsupported(format!(
                    "the signature field {name:?} is a direct dictionary in its parent; it \
                     cannot be signed in an incremental update"
                ))
            })?;
            Ok(Target::Existing {
                id,
                name: name.to_owned(),
            })
        }
        None if spec.mode == FieldMode::ExistingOnly => Err(Error::NotFound(format!(
            "no signature field named {name:?}"
        ))),
        None if name.contains('.') => Err(Error::InvalidArgument(format!(
            "a new field's name {name:?} must not contain '.' (ISO 32000-2 §12.7.4.2): new \
             signature fields are created at the root of /AcroForm /Fields"
        ))),
        None => Ok(Target::New {
            name: name.to_owned(),
        }),
    }
}

/// Checks that an existing field `name` can take the signature (brief §4.5, R-8, D-13).
fn check_existing(store: &Store, node: &FieldNode, name: &str) -> Result<()> {
    if !node.terminal {
        return Err(Error::InvalidArgument(format!(
            "the field {name:?} is not a terminal field (it has child fields)"
        )));
    }
    if !node.is_signature() {
        let found = node.field_type.as_deref().map_or_else(
            || "absent".to_owned(),
            |t| format!("/{}", String::from_utf8_lossy(t)),
        );
        return Err(Error::InvalidArgument(format!(
            "the field {name:?} is not a signature field (its /FT is {found})"
        )));
    }
    if node.is_signed(store) {
        return Err(Error::InvalidArgument(format!(
            "the signature field {name:?} is already signed"
        )));
    }
    if node.dict.contains_key(LOCK) {
        return Err(Error::Unsupported(format!(
            "the signature field {name:?} has a /Lock (FieldMDP) dictionary; FieldMDP arrives \
             in M11"
        )));
    }
    if let Some(sv) = node.dict.get(SV) {
        let flags = match store.deref(sv)?.as_dict().and_then(|sv| sv.get(SV_FF)) {
            Some(ff) => store.deref(ff)?.as_int().unwrap_or(0),
            None => 0,
        };
        if flags != 0 {
            return Err(Error::Unsupported(format!(
                "the signature field {name:?} has a seed value dictionary with required \
                 constraints (/Ff {flags}); seed values are not supported yet"
            )));
        }
    }
    Ok(())
}

/// `Signature{n}`, `n` the smallest number from 1 that no fully qualified name uses (D-18).
fn auto_name(fields: &[FieldNode]) -> String {
    // Only names as short as `Signature` and a number can collide; longer ones are not built.
    const LONGEST: usize = "Signature".len() + 20;
    let used: HashSet<String> = (0..fields.len())
        .filter(|&index| qualified_name_len(fields, index) <= LONGEST)
        .map(|index| join_name(&name_parts(fields, index), LONGEST).0)
        .collect();
    // `fields.len() + 1` candidates for at most `fields.len()` names: one is free.
    (1..=fields.len().saturating_add(1))
        .map(|n| format!("Signature{n}"))
        .find(|name| !used.contains(name))
        .unwrap_or_else(|| "Signature1".to_owned())
}

/// The warning for signing the existing field `id` (its dictionary `dict`) of a document that is
/// signed already, when its `/AP` is an indirect dictionary that another field of `fields` names
/// too (M4 final fix round 2, finding 1): pyHanko's `SigFieldModificationRule` then reports every
/// earlier signature's modification as `other` once this field is signed, and so does
/// Folioxide's verifier (manager ruling R-19), whether or not the new signature replaces the
/// appearance.
fn shared_appearance_warning(fields: &[FieldNode], id: ObjectId, dict: &Dict) -> Option<String> {
    let ap = dict.get_ref(AP)?;
    let mut names = NameBudget::new();
    let other = fields
        .iter()
        .enumerate()
        .find(|(_, node)| node.id != Some(id) && node.dict.get_ref(AP) == Some(ap))
        .map(|(index, _)| names.name(fields, index).0)?;
    Some(format!(
        "the signature field's appearance dictionary {ap} is the field {other:?}'s too: \
         pyHanko and Folioxide report the earlier signatures as modified (`other`) once this \
         field is signed"
    ))
}

/// The merged signature field and widget annotation dictionary of brief §4.1, keys in this
/// order: `/Type /Annot /Subtype /Widget /FT /Sig /T (name) /V sig /F 132 /Rect [0 0 0 0] /P
/// page` (§12.7.5.5, §12.5.6.19). The zero-area `/Rect` makes it invisible, so it needs no
/// `/AP` (§12.5.5).
fn widget_dict(name: &str, sig: ObjectId, page: ObjectId) -> Dict {
    let mut dict = Dict::with_capacity(8);
    dict.insert("Type", Object::name("Annot"));
    dict.insert("Subtype", Object::name("Widget"));
    dict.insert(FT, Object::name("Sig"));
    dict.insert(T, text_object(name));
    dict.insert(V, sig);
    dict.insert("F", WIDGET_FLAGS);
    dict.insert(
        "Rect",
        Object::Array(vec![
            Object::Int(0),
            Object::Int(0),
            Object::Int(0),
            Object::Int(0),
        ]),
    );
    dict.insert("P", page);
    dict
}

/// Makes the new widget `dict` visible (M4 brief §4.7 "Widget"): `/Rect` the widget rect
/// (default user space), `/AP << /N normal >>`, and `/MK << /R r >>` on a page rotated by
/// `r ≠ 0` (§12.5.6.19, Table 192: the widget's rotation, counter-clockwise like the page's
/// display turn is clockwise; the appearance's `/Matrix` already compensates it).
fn make_visible(dict: &mut Dict, rect: Rect, rotation: Rotation, normal: ObjectId) {
    dict.insert(RECT, rect.to_object());
    dict.insert(AP, appearance::ap_dict(normal));
    if rotation != Rotation::R0 {
        let mut mk = Dict::with_capacity(1);
        mk.insert("R", i64::from(rotation.degrees()));
        dict.insert("MK", mk);
    }
}

/// The widget rect and page rotation of the existing signature field `id` (dictionary `field`,
/// fully qualified name `name`) that a visible signature draws into (DECISIONS D13 D-18): the
/// field must be merged with its widget (no `/Kids`), its `/Rect` must have an area and equal
/// the appearance's rect when one is given, and its widget must be listed in a page's `/Annots`
/// (or name a page as `/P`).
fn existing_widget(
    doc: &Document,
    page_ids: &[PageId],
    field: &Dict,
    id: ObjectId,
    name: &str,
    app: &SignatureAppearance,
) -> Result<(Rect, Rotation)> {
    let store = doc.store();
    let has_kids = match field.get(KIDS) {
        Some(kids) => store.deref(kids)?.as_array().is_some_and(|k| !k.is_empty()),
        None => false,
    };
    if has_kids {
        return Err(Error::Unsupported(format!(
            "the signature field {name:?} has its widget as a separate /Kids object; a visible \
             signature can only use a field merged with its widget (D-18)"
        )));
    }
    // Manager ruling R-3 (M4 QA round 1): a widget that is hidden, shown only on screen or only
    // in print, or drawn at a fixed size or unrotated would show the appearance elsewhere than
    // in its /Rect, and the verifier makes the earlier signatures OTHER for it.
    if let Some(problem) = crate::revisions::geometry::annotation_flags_problem(store, field) {
        return Err(Error::InvalidArgument(format!(
            "the widget of the signature field {name:?} {problem}; it cannot show a visible \
             signature (sign it without an appearance)"
        )));
    }
    let rect = match field.get(RECT) {
        Some(value) => Rect::from_object(store, value)?,
        None => None,
    };
    let Some(rect) = rect else {
        return Err(Error::InvalidArgument(format!(
            "the signature field {name:?} has no widget area (its /Rect is missing or has no \
             area), so it cannot show an appearance; sign it without one"
        )));
    };
    // M4 QA round 4, finding 13, and manager ruling R-21: a /Rect beyond ±10^5 is placed
    // elsewhere by PDFium, and the verifier makes such an appearance Other.
    appearance::rect_within_magnitude(&rect).map_err(|_| {
        Error::InvalidArgument(format!(
            "the signature field {name:?} has a /Rect beyond ±1e5, which viewers that map \
             appearances in single precision place elsewhere; sign it without an appearance"
        ))
    })?;
    if let Some(wanted) = app.rect {
        // Both normalized (Rect::new orders the corners), compared as the serializer writes
        // them; a coordinate that is not finite never matches.
        let finite = [wanted.llx, wanted.lly, wanted.urx, wanted.ury]
            .iter()
            .all(|v| v.is_finite());
        let normal = Rect::new(wanted.llx, wanted.lly, wanted.urx, wanted.ury);
        let equal = [
            (normal.llx, rect.llx),
            (normal.lly, rect.lly),
            (normal.urx, rect.urx),
            (normal.ury, rect.ury),
        ]
        .iter()
        .all(|(a, b)| canonical_real(*a) == canonical_real(*b));
        if !(finite && equal) {
            return Err(Error::InvalidArgument(format!(
                "the appearance rect [{} {} {} {}] differs from the /Rect [{} {} {} {}] of the \
                 existing field {name:?}; an existing field's /Rect is never changed (D-18): \
                 give no rect, or this one",
                wanted.llx,
                wanted.lly,
                wanted.urx,
                wanted.ury,
                rect.llx,
                rect.lly,
                rect.urx,
                rect.ury
            )));
        }
    }
    let page = widget_page(store, page_ids, field, id)?.ok_or_else(|| {
        Error::InvalidArgument(format!(
            "the widget of the signature field {name:?} is on no page (no page's /Annots lists \
             it), so it cannot show an appearance"
        ))
    })?;
    Ok((rect, doc.page(page)?.rotation()))
}

/// The index of the page whose `/Annots` lists the widget `id`, else of the page its `/P`
/// names; `None` when neither is a page.
fn widget_page(
    store: &Store,
    page_ids: &[PageId],
    widget: &Dict,
    id: ObjectId,
) -> Result<Option<usize>> {
    for (index, page) in page_ids.iter().enumerate() {
        let page = store.resolve(page.0)?;
        let Some(annots) = page.as_dict().and_then(|p| p.get(ANNOTS)) else {
            continue;
        };
        if store
            .deref(annots)?
            .as_array()
            .is_some_and(|annots| annots.iter().any(|a| a.as_ref() == Some(id)))
        {
            return Ok(Some(index));
        }
    }
    let named = widget.get_ref(b"P");
    Ok(page_ids.iter().position(|page| Some(page.0) == named))
}

/// `text` as a text-string object (§7.9.2.2): a literal string when it is PDFDocEncoded, a
/// hexadecimal one when it is UTF-16BE (the M2 convention of `set_info`).
pub(crate) fn text_object(text: &str) -> Object {
    let bytes = encode_text_string(text);
    if bytes.starts_with(&[0xFE, 0xFF]) {
        Object::String(PdfString::new_hex(bytes))
    } else {
        Object::String(PdfString::new_literal(bytes))
    }
}

/// Appends a reference to `item` to `array` unless it is there already.
fn push_unique(array: &mut Vec<Object>, item: ObjectId) {
    if !array.iter().any(|o| o.as_ref() == Some(item)) {
        array.push(Object::Ref(item));
    }
}

/// Adds `widget` to the page's `/Annots` (§12.5.2): a new direct array when there is none, the
/// page's direct array, or the indirect array object.
fn add_to_annots(overlay: &mut Overlay<'_>, page: ObjectId, widget: ObjectId) -> Result<()> {
    let mut page_dict = overlay.current_dict(page, "the page object")?;
    match page_dict.get(ANNOTS).cloned() {
        None | Some(Object::Null) => {
            page_dict.insert(ANNOTS, Object::Array(vec![Object::Ref(widget)]));
            overlay.set(page, Object::Dict(page_dict));
        }
        Some(Object::Array(mut annots)) => {
            push_unique(&mut annots, widget);
            page_dict.insert(ANNOTS, Object::Array(annots));
            overlay.set(page, Object::Dict(page_dict));
        }
        Some(Object::Ref(array_id)) => match overlay.current(array_id)? {
            Object::Array(mut annots) => {
                push_unique(&mut annots, widget);
                overlay.set(array_id, Object::Array(annots));
            }
            // A reference to a missing object is `null` (§7.3.10): no annotations yet.
            Object::Null => {
                page_dict.insert(ANNOTS, Object::Array(vec![Object::Ref(widget)]));
                overlay.set(page, Object::Dict(page_dict));
            }
            other => return Err(type_mismatch("the page's /Annots", "array", &other)),
        },
        Some(other) => return Err(type_mismatch("the page's /Annots", "array", &other)),
    }
    Ok(())
}

/// Adds the new `widget` (if any) to `/AcroForm /Fields` and sets `/SigFlags 3` when
/// `set_sig_flags` (brief §4.5, D-6), editing the object that holds each value; creates an
/// indirect AcroForm when the catalog has none.
fn edit_acroform(
    overlay: &mut Overlay<'_>,
    numbers: &mut NewNumbers,
    catalog: ObjectId,
    acroform: Option<&AcroFormLoc>,
    widget: Option<ObjectId>,
    set_sig_flags: bool,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let Some(acroform) = acroform else {
        // An existing field is always reached through an AcroForm, so this is a new field.
        let Some(widget) = widget else {
            return Ok(());
        };
        // No interactive form yet: a new indirect AcroForm (§12.7.3, Table 224).
        let id = numbers.take()?;
        let mut dict = Dict::with_capacity(2);
        dict.insert(FIELDS, Object::Array(vec![Object::Ref(widget)]));
        dict.insert(SIG_FLAGS_KEY, SIG_FLAGS);
        overlay.set(id, Object::Dict(dict));
        let mut catalog_dict = overlay.current_dict(catalog, "the document catalog")?;
        catalog_dict.insert(ACRO_FORM, id);
        overlay.set(catalog, Object::Dict(catalog_dict));
        return Ok(());
    };

    // The AcroForm as it stands now (an earlier edit of this update may have touched its holder).
    let mut catalog_dict = None;
    let mut dict = match acroform.id {
        Some(id) => overlay.current_dict(id, "the /AcroForm")?,
        None => {
            let current = overlay.current_dict(catalog, "the document catalog")?;
            let dict = match current.get(ACRO_FORM) {
                Some(Object::Dict(dict)) => dict.clone(),
                _ => acroform.dict.clone(),
            };
            catalog_dict = Some(current);
            dict
        }
    };
    let mut changed = false;

    if let Some(widget) = widget {
        match dict.get(FIELDS).cloned() {
            None | Some(Object::Null) => {
                dict.insert(FIELDS, Object::Array(vec![Object::Ref(widget)]));
                changed = true;
            }
            Some(Object::Array(mut fields)) => {
                push_unique(&mut fields, widget);
                dict.insert(FIELDS, Object::Array(fields));
                changed = true;
            }
            Some(Object::Ref(array_id)) => match overlay.current(array_id)? {
                Object::Array(mut fields) => {
                    push_unique(&mut fields, widget);
                    overlay.set(array_id, Object::Array(fields));
                }
                Object::Null => {
                    dict.insert(FIELDS, Object::Array(vec![Object::Ref(widget)]));
                    changed = true;
                }
                other => return Err(type_mismatch("/AcroForm /Fields", "array", &other)),
            },
            Some(other) => return Err(type_mismatch("/AcroForm /Fields", "array", &other)),
        }
    }

    if set_sig_flags {
        let current = match dict.get(SIG_FLAGS_KEY) {
            Some(flags) => overlay.store.deref(flags)?.as_int(),
            None => None,
        };
        if current != Some(SIG_FLAGS) {
            dict.insert(SIG_FLAGS_KEY, SIG_FLAGS);
            changed = true;
        }
    }

    let need_appearances = match dict.get(NEED_APPEARANCES) {
        Some(value) => overlay.store.deref(value)?.as_bool() == Some(true),
        None => false,
    };
    if need_appearances {
        warnings.push(
            "the AcroForm has /NeedAppearances true; it is left unchanged (removing it could \
             blank fields that have no appearance stream)"
                .to_owned(),
        );
    }

    if changed {
        match (acroform.id, catalog_dict) {
            (Some(id), _) => overlay.set(id, Object::Dict(dict)),
            (None, Some(mut catalog_dict)) => {
                catalog_dict.insert(ACRO_FORM, Object::Dict(dict));
                overlay.set(catalog, Object::Dict(catalog_dict));
            }
            (None, None) => {}
        }
    }
    Ok(())
}

/// Names the certification signature `sig` in the catalog's `/Perms /DocMDP` (§12.8.6, M4 brief
/// §4.6): a new direct `/Perms` dictionary when the catalog has none; the catalog edited when
/// `/Perms` is direct; the `/Perms` object edited when it is indirect. An existing `/UR3`
/// usage-rights signature is kept, with a warning: the certification's update invalidates it.
fn add_perms(
    overlay: &mut Overlay<'_>,
    catalog: ObjectId,
    sig: ObjectId,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let mut catalog_dict = overlay.current_dict(catalog, "the document catalog")?;
    let warn_ur3 = |perms: &Dict, warnings: &mut Vec<String>| {
        if perms.contains_key(UR3) {
            warnings.push(
                "the catalog's /Perms has a /UR3 usage-rights signature; it is kept, but the \
                 usage-rights signature will no longer validate"
                    .to_owned(),
            );
        }
    };
    let direct = |mut perms: Dict, catalog_dict: &mut Dict| {
        perms.insert(DOC_MDP, sig);
        catalog_dict.insert(PERMS, Object::Dict(perms));
    };
    match catalog_dict.get(PERMS).cloned() {
        None | Some(Object::Null) => {
            direct(Dict::with_capacity(1), &mut catalog_dict);
            overlay.set(catalog, Object::Dict(catalog_dict));
        }
        Some(Object::Dict(perms)) => {
            warn_ur3(&perms, warnings);
            direct(perms, &mut catalog_dict);
            overlay.set(catalog, Object::Dict(catalog_dict));
        }
        Some(Object::Ref(id)) => match overlay.current(id)? {
            Object::Dict(mut perms) => {
                warn_ur3(&perms, warnings);
                perms.insert(DOC_MDP, sig);
                overlay.set(id, Object::Dict(perms));
            }
            // A reference to a missing object is `null` (§7.3.10): no /Perms yet.
            Object::Null => {
                direct(Dict::with_capacity(1), &mut catalog_dict);
                overlay.set(catalog, Object::Dict(catalog_dict));
            }
            other => return Err(type_mismatch("the catalog's /Perms", "dictionary", &other)),
        },
        Some(other) => return Err(type_mismatch("the catalog's /Perms", "dictionary", &other)),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(partial: &str, parent: Option<usize>) -> FieldNode {
        FieldNode {
            id: None,
            dict: Dict::new(),
            partial: Some(partial.to_owned()),
            parent,
            field_type: Some(b"Sig".to_vec()),
            terminal: true,
        }
    }

    #[test]
    fn auto_names_take_the_smallest_free_number() {
        assert_eq!(auto_name(&[]), "Signature1");
        assert_eq!(
            auto_name(&[node("Signature1", None), node("Signature3", None)]),
            "Signature2"
        );
        assert_eq!(
            auto_name(&[node("Signature1", None), node("Signature2", None)]),
            "Signature3"
        );
        // A nested name does not block a root-level one.
        assert_eq!(
            auto_name(&[node("form", None), node("Signature1", Some(0))]),
            "Signature1"
        );
    }

    #[test]
    fn qualified_names_are_built_on_demand_and_bounded() {
        let mut nameless = node("", None);
        nameless.partial = None;
        let nodes = [
            node("form", None),
            node("sig", Some(0)),
            nameless,
            node("kid", Some(2)),
            node("", None),
            node("after", Some(4)),
        ];
        let mut budget = NameBudget::new();
        assert_eq!(budget.name(&nodes, 1), ("form.sig".to_owned(), false));
        assert_eq!(qualified_name_len(&nodes, 1), 8);
        // A node without /T adds nothing; an empty name so far is replaced, as the walk always
        // joined names.
        assert_eq!(budget.name(&nodes, 3).0, "kid");
        assert_eq!(budget.name(&nodes, 5).0, "after");
        assert!(has_name(&nodes, 1, "form.sig"));
        assert!(!has_name(&nodes, 1, "form.si"));
        assert!(!has_name(&nodes, 1, "form"));

        // A long parent name is not repeated per kid: the reported names are capped, and so is
        // their total (QA finding 4).
        let long = "A".repeat(1_000_000);
        let mut wide = vec![node(&long, None)];
        wide.extend((0..100).map(|_| node("k", Some(0))));
        let mut budget = NameBudget::new();
        let (name, cut) = budget.name(&wide, 1);
        assert!(cut && name.ends_with('…'));
        assert!(name.len() <= MAX_FIELD_NAME_BYTES + '…'.len_utf8());
        assert_eq!(qualified_name_len(&wide, 1), 1_000_002);
        let mut total = 0;
        for index in 1..wide.len() {
            total += budget.name(&wide, index).0.len();
        }
        assert!(total <= MAX_FIELD_NAME_BYTES_TOTAL);
        // Cutting respects character boundaries.
        let (cut_name, cut) = join_name(&["\u{e9}\u{e9}"], 3);
        assert_eq!((cut_name.as_str(), cut), ("\u{e9}", true));
    }

    #[test]
    fn sub_filter_names_round_trip() {
        for sub_filter in [SubFilter::EtsiCadesDetached, SubFilter::AdbePkcs7Detached] {
            assert_eq!(SubFilter::from_name(sub_filter.name()), Some(sub_filter));
        }
        assert_eq!(SubFilter::from_name("ETSI.RFC3161"), None);
    }

    #[test]
    fn new_numbers_respect_the_limit() {
        let mut numbers = NewNumbers { next: 5, max: 7 };
        assert_eq!(numbers.take().unwrap(), ObjectId::new(5, 0));
        assert_eq!(numbers.take().unwrap(), ObjectId::new(6, 0));
        let err = numbers.take().unwrap_err();
        assert_eq!(err.code(), folioxide_syntax::ErrorCode::LimitExceeded);
    }

    #[test]
    fn new_numbers_start_at_an_over_declared_size() {
        // M4 final fix round 2, expert finding 1: `minimal.pdf` lists objects 0-5 under
        // `/Size 6`; its trailer respelled with another `/Size`.
        let with_size = |size: &str| {
            let source = folioxide_testkit::fixtures::syntax::minimal();
            let at = source.windows(8).position(|w| w == b"/Size 6 ").unwrap();
            let mut out = source[..at].to_vec();
            out.extend_from_slice(format!("/Size {size} ").as_bytes());
            out.extend_from_slice(&source[at + 8..]);
            Store::open_bytes(out, &folioxide_syntax::OpenOptions::default()).unwrap()
        };
        let start = |size: &str| NewNumbers::new(&with_size(size)).take().unwrap().num;
        // Conforming: the next number.
        assert_eq!(start("6"), 6);
        // Over-declared: from the declared /Size, as pyHanko numbers, so the update's /Size
        // (the highest number + 1) is not below it.
        assert_eq!(start("100"), 100);
        // Under-declared, not a direct integer, negative or too close to the object limit: the
        // next number (the verifier reports such a /Size, never the signer's numbering).
        let near_limit = (folioxide_syntax::Limits::default().max_objects - 10).to_string();
        for size in [
            "3",
            "0",
            "-5",
            "100.0",
            "5 0 R",
            near_limit.as_str(),
            "4294967296",
        ] {
            assert_eq!(start(size), 6, "/Size {size}");
        }
    }

    #[test]
    fn widget_dict_has_the_brief_keys_in_order() {
        let dict = widget_dict("Sig\u{e9}", ObjectId::new(9, 0), ObjectId::new(3, 0));
        let keys: Vec<&[u8]> = dict.keys().map(|k| k.as_bytes()).collect();
        assert_eq!(
            keys,
            [
                b"Type".as_slice(),
                b"Subtype",
                b"FT",
                b"T",
                b"V",
                b"F",
                b"Rect",
                b"P"
            ]
        );
        assert_eq!(dict.get_str_bytes(T), Some(b"Sig\xE9".as_slice()));
        // A name outside PDFDocEncoding becomes UTF-16BE, as a hexadecimal string.
        let unicode = widget_dict("\u{3042}", ObjectId::new(9, 0), ObjectId::new(3, 0));
        assert_eq!(
            unicode.get(T),
            Some(&Object::String(PdfString::new_hex(
                b"\xFE\xFF\x30\x42".to_vec()
            )))
        );
    }

    #[test]
    fn our_widget_flags_are_ones_the_verifier_allows() {
        // Ruling R-3: the signer never writes Hidden, NoZoom, NoRotate, NoView or ToggleNoView.
        assert_eq!(
            WIDGET_FLAGS & !crate::revisions::geometry::ALLOWED_ANNOTATION_FLAGS,
            0
        );
        assert_eq!(WIDGET_FLAGS & (2 | 8 | 16 | 32 | 256), 0);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_shapes() {
        let spec = FieldSpec::new()
            .with_name(Some("A".into()))
            .with_page(2)
            .with_mode(FieldMode::ExistingOnly);
        let json = serde_json::to_value(&spec).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"name": "A", "page": 2, "mode": "existingOnly"})
        );
        let back: FieldSpec = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(back, FieldSpec::default());
        assert_eq!(
            serde_json::to_value(SubFilter::AdbePkcs7Detached).unwrap(),
            "adbe.pkcs7.detached"
        );
        assert_eq!(
            serde_json::from_value::<SubFilter>("ETSI.CAdES.detached".into()).unwrap(),
            SubFilter::EtsiCadesDetached
        );
    }
}

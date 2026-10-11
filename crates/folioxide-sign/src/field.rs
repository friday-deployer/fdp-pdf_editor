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
//!
//! The objects that change are collected as an overlay for
//! [`incremental_suffix_with_overlay`](folioxide_syntax::incremental_suffix_with_overlay): the
//! document itself is never modified.

use std::collections::{BTreeMap, HashSet};

use folioxide_model::Document;
use folioxide_model::text::{decode_text_string, encode_text_string};
use folioxide_syntax::{Dict, LimitKind, Object, ObjectId, PdfString, Store};

use crate::error::{Error, Result};

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
const REFERENCE: &[u8] = b"Reference";
const TRANSFORM_METHOD: &[u8] = b"TransformMethod";
const TRANSFORM_PARAMS: &[u8] = b"TransformParams";

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
// DocMDP (§12.8.2.2)
// =================================================================================================

/// The DocMDP permission `/P` of a certified document: from the catalog's `/Perms /DocMDP`
/// signature dictionary, its `/Reference` entry with `/TransformMethod /DocMDP`, and that
/// entry's `/TransformParams /P` (default 2, §12.8.2.2 Table 257). `None` for a document that
/// is not certified.
///
/// # Errors
/// The errors of [`Store::deref`].
pub(crate) fn docmdp_permission(store: &Store, catalog: Option<&Dict>) -> Result<Option<i64>> {
    let deref_dict = |obj: Option<&Object>| -> Result<Option<Dict>> {
        match obj {
            Some(obj) => Ok(store.deref(obj)?.as_dict().cloned()),
            None => Ok(None),
        }
    };
    let Some(perms) = deref_dict(catalog.and_then(|c| c.get(PERMS)))? else {
        return Ok(None);
    };
    let Some(sig) = deref_dict(perms.get(DOC_MDP))? else {
        return Ok(None);
    };
    let references = match sig.get(REFERENCE) {
        Some(r) => store.deref(r)?.as_array().map(<[Object]>::to_vec),
        None => None,
    }
    .unwrap_or_default();
    for reference in &references {
        let Some(reference) = deref_dict(Some(reference))? else {
            continue;
        };
        let is_docmdp = match reference.get(TRANSFORM_METHOD) {
            Some(m) => store.deref(m)?.is_name(DOC_MDP),
            None => false,
        };
        if !is_docmdp {
            continue;
        }
        let params = deref_dict(reference.get(TRANSFORM_PARAMS))?;
        let p = match params.as_ref().and_then(|p| p.get(b"P")) {
            Some(p) => store.deref(p)?.as_int(),
            None => None,
        };
        return Ok(Some(p.unwrap_or(2)));
    }
    // A /Perms /DocMDP signature without a DocMDP reference: certified, default permissions.
    Ok(Some(2))
}

// =================================================================================================
// Placement (brief §4.5)
// =================================================================================================

/// Object numbers for the new objects of a signature: from [`Store::next_object_number`] up,
/// never a freed number (brief R-7).
#[derive(Clone, Copy, Debug)]
pub(crate) struct NewNumbers {
    next: u32,
    max: u32,
}

impl NewNumbers {
    /// Numbers from `store.next_object_number()`, below the store's
    /// [`Limits::max_objects`](folioxide_syntax::Limits::max_objects).
    pub(crate) fn new(store: &Store) -> NewNumbers {
        NewNumbers {
            next: store.next_object_number(),
            max: store.limits().max_objects,
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
    /// The field, widget, page, `/Annots`, AcroForm, `/Fields` and catalog objects that change.
    pub(crate) objects: BTreeMap<ObjectId, Object>,
    /// Observations for the caller (for example `/NeedAppearances true`).
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
/// changing `doc`.
///
/// # Errors
/// - [`Error::PageOutOfRange`]: `spec.page` is not a page (a document without pages cannot be
///   signed).
/// - [`Error::InvalidArgument`]: an empty name, a new name with `.`, a name that
///   [`FieldMode::CreateOnly`] finds taken, [`FieldMode::ExistingOnly`] without a name, a named
///   field that is not a terminal signature field or is signed already.
/// - [`Error::NotFound`]: [`FieldMode::ExistingOnly`] and no field has the name.
/// - [`Error::Unsupported`]: the field has a `/Lock` dictionary or a seed value dictionary with
///   required constraints (M11), or is a direct object.
/// - [`ErrorCode::TypeMismatch`](folioxide_syntax::ErrorCode::TypeMismatch): the catalog, page,
///   `/AcroForm`, `/Fields` or `/Annots` has the wrong type.
/// - The errors of [`Document::page_ids`] and [`Store::resolve`].
pub(crate) fn plan(doc: &Document, spec: &FieldSpec) -> Result<FieldPlan> {
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
    let any_signed = fields
        .iter()
        .any(|f| f.terminal && f.is_signature() && f.is_signed(store));

    let target = choose_target(store, spec, &fields)?;

    let mut numbers = NewNumbers::new(store);
    let mut overlay = Overlay::new(store);
    let mut warnings = Vec::new();
    let (sig, field, name, widget) = match target {
        Target::Existing { id, name } => {
            let sig = numbers.take()?;
            let mut dict = overlay.current_dict(id, "the signature field")?;
            dict.insert(V, sig);
            overlay.set(id, Object::Dict(dict));
            (sig, id, name, None)
        }
        Target::New { name } => {
            let widget = numbers.take()?;
            let sig = numbers.take()?;
            overlay.set(widget, Object::Dict(widget_dict(&name, sig, page)));
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

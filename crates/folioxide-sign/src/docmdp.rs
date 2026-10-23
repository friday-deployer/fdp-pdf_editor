//! DocMDP: certification signatures and their modification permissions (ISO 32000-2 §12.8.2.2;
//! M4 brief §3.2, §4.6, §5 V11 and §5.3).
//!
//! A certification signature carries a `/Reference` entry with `/TransformMethod /DocMDP`, and
//! the catalog's `/Perms /DocMDP` names its signature dictionary. Its `/TransformParams /P`
//! says which later changes keep the certification valid: [`DocMdpPermissions`].
//!
//! - **Signing** ([`prepare`](crate::prepare::prepare) with
//!   [`SignatureOptions::certification`](crate::prepare::SignatureOptions::certification)):
//!   the signature dictionary gets `/Reference [<</Type /SigRef /TransformMethod /DocMDP
//!   /TransformParams <</Type /TransformParams /P n /V /1.2>>>>]` (all direct, as pyHanko writes
//!   it), and the catalog `/Perms <</DocMDP sig>>`. A document is certified only by its first
//!   signature, and an approval signature on a certified document is limited by its `P` (brief
//!   §4.6, rules (a)–(c); [`Error::DocMdpForbids`](crate::Error::DocMdpForbids)).
//! - **Verification**: the `P` a signature declares (V11, with the `DocMdpInvalid` rules), and
//!   whether the later revisions respect the permissions in force (`docmdp_ok`, §5.3).

use std::collections::BTreeSet;

use folioxide_model::Document;
use folioxide_syntax::{Dict, Object, ObjectId, Store};

use crate::error::Result;
use crate::field;
use crate::problem::ProblemCode;
use crate::revisions::differential::{AmbiguousKeys, chain_ambiguity};

/// The DocMDP permissions `P` of a certification signature (ISO 32000-2 §12.8.2.2, Table
/// "Entries in the DocMDP transform parameters dictionary"). The discriminant is `P`.
///
/// With the `serde` feature it is the number `1`, `2` or `3`.
///
/// ```
/// use folioxide_sign::docmdp::DocMdpPermissions;
///
/// assert_eq!(DocMdpPermissions::default(), DocMdpPermissions::FormFilling);
/// assert_eq!(DocMdpPermissions::NoChanges.p(), 1);
/// assert_eq!(DocMdpPermissions::from_p(3), Some(DocMdpPermissions::FormFillingAndAnnotations));
/// assert_eq!(DocMdpPermissions::from_p(4), None);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(into = "u8", try_from = "u8")
)]
pub enum DocMdpPermissions {
    /// `P = 1`: no changes to the document are permitted; any change invalidates the
    /// certification.
    NoChanges = 1,
    /// `P = 2` (the default when `/P` is absent): filling in forms, instantiating page templates
    /// and signing.
    #[default]
    FormFilling = 2,
    /// `P = 3`: as `P = 2`, plus annotation creation, deletion and modification.
    FormFillingAndAnnotations = 3,
}

impl DocMdpPermissions {
    /// The `/P` value: 1, 2 or 3.
    pub fn p(self) -> u8 {
        self as u8
    }

    /// The permissions with `/P` value `p`; `None` unless `p` is 1, 2 or 3.
    pub fn from_p(p: i64) -> Option<DocMdpPermissions> {
        match p {
            1 => Some(DocMdpPermissions::NoChanges),
            2 => Some(DocMdpPermissions::FormFilling),
            3 => Some(DocMdpPermissions::FormFillingAndAnnotations),
            _ => None,
        }
    }
}

impl From<DocMdpPermissions> for u8 {
    /// [`DocMdpPermissions::p`].
    fn from(permissions: DocMdpPermissions) -> u8 {
        permissions.p()
    }
}

impl TryFrom<u8> for DocMdpPermissions {
    type Error = String;

    /// [`DocMdpPermissions::from_p`]; an error message for any value but 1, 2 and 3.
    fn try_from(p: u8) -> std::result::Result<DocMdpPermissions, String> {
        DocMdpPermissions::from_p(i64::from(p))
            .ok_or_else(|| format!("DocMDP permissions must be 1, 2 or 3, not {p}"))
    }
}

// Keys and names of signature references (§12.8.1 Table 255 `/Reference`, Table 256 "signature
// reference dictionary", Table 257 "DocMDP transform parameters").
const REFERENCE: &[u8] = b"Reference";
const TRANSFORM_METHOD: &[u8] = b"TransformMethod";
const TRANSFORM_PARAMS: &[u8] = b"TransformParams";
const DOC_MDP: &[u8] = b"DocMDP";
const FIELD_MDP: &[u8] = b"FieldMDP";
const PERMS: &[u8] = b"Perms";
const LOCK: &[u8] = b"Lock";

/// The `/V` of the DocMDP transform parameters that ISO 32000-2 Table 257 allows (a name).
const TRANSFORM_PARAMS_VERSION: &[u8] = b"1.2";

/// The signature reference dictionary of a certification with permissions `permissions`, as
/// [`prepare`](crate::prepare::prepare) writes it into `/Reference` (brief §4.6; pyHanko's
/// `docmdp_reference_dictionary`): `<</Type /SigRef /TransformMethod /DocMDP /TransformParams
/// <</Type /TransformParams /P n /V /1.2>>>>`, all direct, with no `/Data`, `/DigestMethod`
/// or `/DigestValue`. `/V /1.2` is a name (Table 257).
pub(crate) fn reference_dictionary(permissions: DocMdpPermissions) -> Dict {
    let mut params = Dict::with_capacity(3);
    params.insert("Type", Object::name("TransformParams"));
    params.insert("P", Object::Int(i64::from(permissions.p())));
    params.insert("V", Object::name("1.2"));
    let mut reference = Dict::with_capacity(3);
    reference.insert("Type", Object::name("SigRef"));
    reference.insert(TRANSFORM_METHOD, Object::name("DocMDP"));
    reference.insert(TRANSFORM_PARAMS, Object::Dict(params));
    reference
}

/// What a signature dictionary and its field declare about modification detection (brief §5
/// V11): DocMDP permissions (its own `/Reference`, or the field's `/Lock /P`) and FieldMDP.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Declared {
    /// The DocMDP permissions `P` (1–3) the signature sets for the document: the stricter of a
    /// valid DocMDP reference's and the field's `/Lock /P` (manager ruling R-4). `None` without
    /// either, or when one of them is not valid (`DocMdpInvalid`: then 1 is in force).
    pub(crate) permissions: Option<u8>,
    /// The dictionary is a certification signature: it has a DocMDP reference (or a
    /// `/Reference` that cannot be read), or the catalog's `/Perms /DocMDP` names it.
    pub(crate) certification: bool,
    /// The signature sets DocMDP permissions for the document: [`certification`](Self::certification),
    /// or its field's lock dictionary has `/P` (ISO 32000-2 §12.7.5.5, Table 236). Its own
    /// permissions are then in force for it (`permissions`, else 1), and a new visible signature
    /// field after it is `Other` (brief §5.3 C1; pyHanko's `docmdp_level` reads the lock too).
    pub(crate) restricts: bool,
    /// The dictionary has a `/Reference` with `/TransformMethod /FieldMDP`, or its field has a
    /// `/Lock` (M11: generic form filling is then `Other`, brief §5.1 F0).
    pub(crate) field_mdp: bool,
    /// `DocMdpInvalid` problems.
    pub(crate) problems: Vec<(ProblemCode, String)>,
    /// Observations (a `/V` other than `/1.2`, a `/Perms` that names another dictionary).
    pub(crate) warnings: Vec<String>,
}

/// What the `/Reference` array of a signature dictionary declares (ISO 32000-2 §12.8.1, Table
/// 255 `/Reference`, Table 256).
#[derive(Debug, Default)]
struct References {
    /// `None` without a DocMDP reference; else its `P` and the warning of
    /// [`transform_params_p`], or why the declaration is not valid: a `/Reference` that is not
    /// an array, an entry that is not a dictionary or has no `/TransformMethod` name, two DocMDP
    /// references, or invalid transform parameters (pyHanko raises on each: "Failed to read
    /// document permissions", or a `KeyError` / `TypeError`; manager ruling R-6).
    docmdp: Option<std::result::Result<(u8, Option<String>), String>>,
    /// A reference has `/TransformMethod /FieldMDP`.
    field_mdp: bool,
}

/// Why the DocMDP declaration that the objects `ids` of `store` (indirect parts of a
/// `/Reference` or a field lock) make reads differently in different readers: one of them is not
/// canonical at any depth (a duplicate key, M4 QA round 2, finding 8, ISO 32000-2 §7.3.7:
/// pyHanko keeps the first value, Folioxide's parser the last; or a number or name spelling
/// readers read differently, QA round 3, ruling R-12), or cannot be re-read.
fn declaration_ambiguity(
    store: &Store,
    duplicates: &AmbiguousKeys,
    ids: impl IntoIterator<Item = ObjectId>,
    what: &str,
) -> Option<String> {
    for id in ids {
        match duplicates.ambiguous_keys(store, id) {
            Ok(keys) if keys.is_empty() => {}
            Ok(_) => {
                return Some(format!(
                    "{what} {id} has a dictionary with a duplicate key, or a number or name \
                     spelling, that readers read differently (pyHanko keeps the first value of a \
                     key, Folioxide's parser the last, ISO 32000-2 §7.3.7; PDFium reads `++2` or \
                     `4294967298` as 0, manager ruling R-12)"
                ));
            }
            Err(reason) => {
                return Some(format!(
                    "{what} {id} cannot be checked for bytes that readers read differently: \
                     {reason}"
                ));
            }
        }
    }
    None
}

/// Reads the `/Reference` array of the signature dictionary `sig` ([`References`]); an indirect
/// array, entry or `/TransformParams` with a duplicate key makes the declaration invalid
/// ([`declaration_ambiguity`]).
fn read_references(store: &Store, sig: &Dict, duplicates: &AmbiguousKeys) -> References {
    let mut out = References::default();
    let Some(value) = sig.get(REFERENCE) else {
        return out;
    };
    let invalid = |reason: String| References {
        docmdp: Some(Err(reason)),
        field_mdp: false,
    };
    // The indirect objects the declaration is read from: the array, its entries and their
    // /TransformParams (a direct part is checked with the signature dictionary itself).
    let mut indirect: Vec<ObjectId> = value.as_ref().into_iter().collect();
    if let Ok(entries) = store.deref(value)
        && let Some(entries) = entries.as_array()
    {
        for entry in entries {
            indirect.extend(entry.as_ref());
            if let Some(params) = deref_dict(store, entry).and_then(|e| e.get_ref(TRANSFORM_PARAMS))
            {
                indirect.push(params);
            }
        }
    }
    if let Some(reason) =
        declaration_ambiguity(store, duplicates, indirect, "the /Reference object")
    {
        return invalid(reason);
    }
    let entries = match store.deref(value) {
        Ok(value) => match value.as_array() {
            Some(entries) => entries.to_vec(),
            None => {
                return invalid(format!(
                    "the signature dictionary's /Reference is {}, not an array of signature \
                     reference dictionaries (ISO 32000-2 Table 255)",
                    describe(&value)
                ));
            }
        },
        Err(err) => {
            return invalid(format!(
                "the signature dictionary's /Reference cannot be read: {err}"
            ));
        }
    };
    let mut docmdp_refs: Vec<Dict> = Vec::new();
    let mut problem: Option<String> = None;
    for (index, entry) in entries.iter().enumerate() {
        let Some(reference) = deref_dict(store, entry) else {
            problem.get_or_insert_with(|| {
                format!(
                    "/Reference entry {index} is not a signature reference dictionary (ISO \
                     32000-2 Table 256)"
                )
            });
            continue;
        };
        let method = reference
            .get(TRANSFORM_METHOD)
            .and_then(|m| store.deref(m).ok())
            .and_then(|m| m.as_name().map(|n| n.as_bytes().to_vec()));
        match method.as_deref() {
            Some(DOC_MDP) => docmdp_refs.push(reference),
            Some(FIELD_MDP) => out.field_mdp = true,
            // Another transform method (UR3, Identity): not about DocMDP.
            Some(_) => {}
            None => {
                problem.get_or_insert_with(|| {
                    format!(
                        "/Reference entry {index} has no /TransformMethod name (ISO 32000-2 \
                         Table 256: required)"
                    )
                });
            }
        }
    }
    out.docmdp = match (problem, docmdp_refs.as_slice()) {
        (Some(problem), _) => Some(Err(problem)),
        (None, []) => None,
        (None, [reference]) => Some(transform_params_p(store, reference)),
        (None, many) => Some(Err(format!(
            "the signature dictionary has {} /Reference entries with /TransformMethod /DocMDP; \
             ISO 32000-2 §12.8.2.2 allows one",
            many.len()
        ))),
    };
    out
}

/// The `/P` of the lock dictionary of the signature field `field` (ISO 32000-2 §12.7.5.5, Table
/// 236; PDF 2.0): the DocMDP permissions the document gets when the field is signed. `Ok(None)`
/// without a `/Lock` or without `/P` in it; `Err(reason)` for a `/Lock` that is not a
/// dictionary or a `/P` that is not the integer 1, 2 or 3 (pyHanko raises on both).
pub(crate) fn lock_permissions(
    store: &Store,
    field: &Dict,
    duplicates: &AmbiguousKeys,
) -> std::result::Result<Option<u8>, String> {
    let Some(lock) = field.get(LOCK) else {
        return Ok(None);
    };
    if let Some(reason) = declaration_ambiguity(
        store,
        duplicates,
        lock.as_ref(),
        "the field lock dictionary",
    ) {
        return Err(reason);
    }
    let lock = store
        .deref(lock)
        .map_err(|err| format!("the signature field's /Lock cannot be read: {err}"))?;
    let Some(lock) = lock.as_dict() else {
        return Err(format!(
            "the signature field's /Lock is {}, not a signature field lock dictionary (ISO \
             32000-2 Table 233)",
            describe(&lock)
        ));
    };
    let Some(p) = lock.get(b"P") else {
        return Ok(None);
    };
    let p = store
        .deref(p)
        .map_err(|err| format!("the signature field lock's /P cannot be read: {err}"))?;
    match p.as_int().and_then(DocMdpPermissions::from_p) {
        Some(permissions) => Ok(Some(permissions.p())),
        None => Err(format!(
            "the signature field lock's /P is {}, not the integer 1, 2 or 3 (ISO 32000-2 Table \
             236)",
            describe(&p)
        )),
    }
}

/// V11: what the signature dictionary `dict` (object `sig_object`) and its field `field` (when
/// known) declare (§12.8.2.2, §12.7.5.5):
///
/// - its own `/Reference` entry with `/TransformMethod /DocMDP`; `/TransformParams /P` absent
///   means 2 (Table 257); a `/Reference` that is not an array, an entry that is not a
///   dictionary or has no `/TransformMethod` name, a `/P` that is not the integer 1, 2 or 3, a
///   `/TransformParams` that is not a dictionary, and two DocMDP references are
///   `DocMdpInvalid`, and the signature is then a certification with `P = 1` in force (pyHanko
///   raises: "Failed to read document permissions"; manager ruling R-6); a `/V` other than
///   `/1.2` is a warning;
/// - M3's fallback: the catalog's `/Perms /DocMDP` names the dictionary, which has no DocMDP
///   reference: `P = 2`;
/// - the field's `/Lock /P` (PDF 2.0): the stricter of it and the DocMDP reference's `P` is the
///   signature's ([`Declared::restricts`], manager ruling R-4; pyHanko's `docmdp_level` reads
///   the lock when there is no DocMDP reference); a `/Lock` or `/P` that cannot be read is
///   `DocMdpInvalid`;
/// - a `/Reference` with `/TransformMethod /FieldMDP`, or any `/Lock`, sets
///   [`Declared::field_mdp`];
/// - a declaration read from bytes that readers read differently (M4 QA round 2, finding 8;
///   round 3, ruling R-12): the signature dictionary's `/Reference` entry written twice or not
///   canonical (a duplicate key inside, or a number such as `/P 4294967298` or `++2`), an
///   indirect part of it that is not canonical, the field's `/Lock` written twice or not
///   canonical ([`AmbiguousKeys`], `sig_keys` and `field_keys` the ambiguous entries of the
///   signature dictionary and of the field) is `DocMdpInvalid`, so `P = 1` is in force (pyHanko
///   keeps the first value of a key, Folioxide's parser the last; PDFium reads such numbers as
///   0).
pub(crate) fn declared(
    doc: &Document,
    dict: &Dict,
    sig_object: ObjectId,
    field: Option<&Dict>,
    ambiguity: &Ambiguity<'_>,
) -> Declared {
    let store = doc.store();
    let mut out = Declared::default();
    let mut references = read_references(store, dict, ambiguity.duplicates);
    if ambiguity.sig_keys.contains(REFERENCE) {
        references.docmdp = Some(Err(
            "the signature dictionary's /Reference is written twice, or holds a duplicate key \
             or a number or name spelling, which readers read differently (pyHanko keeps the \
             first value of a key, Folioxide's parser the last, ISO 32000-2 §7.3.7; manager \
             ruling R-12)"
                .to_owned(),
        ));
    }
    out.field_mdp = references.field_mdp;
    let perms_target = perms_docmdp(doc);
    let mut reference_p: Option<u8> = None;
    match references.docmdp {
        None => {
            // The catalog's /Perms /DocMDP names this dictionary: certified, default permissions.
            if perms_target == Some(sig_object) {
                out.certification = true;
                reference_p = Some(2);
            }
        }
        Some(Ok((p, version_warning))) => {
            out.certification = true;
            reference_p = Some(p);
            out.warnings.extend(version_warning);
            if perms_target != Some(sig_object) {
                out.warnings.push(
                    "the signature declares DocMDP permissions, but the catalog's /Perms /DocMDP \
                     does not name its signature dictionary (ISO 32000-2 §12.8.6)"
                        .to_owned(),
                );
            }
        }
        Some(Err(message)) => {
            out.certification = true;
            out.problems.push((ProblemCode::DocMdpInvalid, message));
        }
    }
    let mut lock_p: Option<u8> = None;
    if let Some(field) = field {
        out.field_mdp |= field.contains_key(LOCK);
        let lock = if ambiguity.field_keys.contains(LOCK) {
            Err(
                "the signature field's /Lock is written twice, or holds a duplicate key or a \
                 number or name spelling, which readers read differently (ISO 32000-2 §7.3.7; \
                 manager ruling R-12)"
                    .to_owned(),
            )
        } else {
            lock_permissions(store, field, ambiguity.duplicates)
        };
        match lock {
            Ok(p) => lock_p = p,
            Err(message) => {
                out.restricts = true;
                out.problems.push((ProblemCode::DocMdpInvalid, message));
            }
        }
    }
    out.restricts |= out.certification || lock_p.is_some();
    out.permissions = if out.problems.is_empty() {
        match (reference_p, lock_p) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    } else {
        None
    };
    out
}

/// The `/P` of a DocMDP signature reference dictionary's `/TransformParams` (default 2) and the
/// warning for a `/V` other than `/1.2`; `Err(reason)` for a declaration that is not valid.
fn transform_params_p(
    store: &Store,
    reference: &Dict,
) -> std::result::Result<(u8, Option<String>), String> {
    let params = reference
        .get(TRANSFORM_PARAMS)
        .and_then(|p| deref_dict(store, p))
        .ok_or_else(|| {
            "the DocMDP signature reference has no /TransformParams dictionary (ISO 32000-2 Table \
             256)"
                .to_owned()
        })?;
    let p = match params.get(b"P") {
        None => 2,
        Some(value) => {
            let value = store.deref(value).map_err(|err| err.to_string())?;
            match value.as_int().and_then(DocMdpPermissions::from_p) {
                Some(permissions) => permissions.p(),
                None => {
                    return Err(format!(
                        "the DocMDP transform parameters' /P is {}, not the integer 1, 2 or 3 \
                         (ISO 32000-2 Table 257)",
                        describe(&value)
                    ));
                }
            }
        }
    };
    let warning = match params.get(b"V") {
        None => None,
        Some(value) => match store.deref(value) {
            Ok(value) if value.is_name(TRANSFORM_PARAMS_VERSION) => None,
            Ok(value) => Some(format!(
                "the DocMDP transform parameters' /V is {}, not the name /1.2 (ISO 32000-2 Table \
                 257)",
                describe(&value)
            )),
            Err(_) => Some("the DocMDP transform parameters' /V cannot be read".to_owned()),
        },
    };
    Ok((p, warning))
}

/// A short description of a PDF value for messages: an integer or a name as written, else its
/// type.
fn describe(value: &Object) -> String {
    match value {
        Object::Int(n) => n.to_string(),
        Object::Name(name) => format!("/{}", String::from_utf8_lossy(name.as_bytes())),
        other => format!("a {}", other.type_name()),
    }
}

/// V11 for callers that need only `P` (1–3): the permissions of a valid certification
/// declaration of `dict` ([`declared`], without the field's lock).
///
/// Moved from `verify_pdf/crypto.rs` in M4 stage 0 (brief §2 WP4.0); since M4 stage 2 an
/// invalid declaration (`DocMdpInvalid`) gives `None`.
pub(crate) fn declared_permissions(
    doc: &Document,
    dict: &Dict,
    sig_object: ObjectId,
) -> Option<u8> {
    let duplicates = AmbiguousKeys::default();
    let ambiguity = Ambiguity::of(doc.store(), &duplicates, Some(sig_object), None);
    declared(doc, dict, sig_object, None, &ambiguity).permissions
}

/// The entries of a signature dictionary and of its field that read differently in different
/// readers (M4 QA round 2, finding 8; [`AmbiguousKeys::ambiguous_keys`]), with the cache that
/// checks the indirect parts of a DocMDP declaration.
pub(crate) struct Ambiguity<'a> {
    /// The cache of decoded object streams.
    pub(crate) duplicates: &'a AmbiguousKeys,
    /// The signature dictionary's top-level keys whose entry is ambiguous.
    pub(crate) sig_keys: BTreeSet<Vec<u8>>,
    /// The field's top-level keys whose entry is ambiguous.
    pub(crate) field_keys: BTreeSet<Vec<u8>>,
    /// Why the signature dictionary or the field cannot be re-read to check them, if it cannot.
    pub(crate) unreadable: Option<String>,
}

impl<'a> Ambiguity<'a> {
    /// The ambiguous entries of the signature dictionary `sig` and the field `field` of
    /// `store` (each when indirect). A definition that cannot be re-read counts as every entry
    /// ambiguous (fail closed): its `/Reference` and `/Lock` are then `DocMdpInvalid`.
    pub(crate) fn of(
        store: &Store,
        duplicates: &'a AmbiguousKeys,
        sig: Option<ObjectId>,
        field: Option<ObjectId>,
    ) -> Ambiguity<'a> {
        let mut unreadable = None;
        let mut keys = |id: Option<ObjectId>| -> BTreeSet<Vec<u8>> {
            let Some(id) = id else {
                return BTreeSet::new();
            };
            match duplicates.ambiguous_keys(store, id) {
                Ok(keys) => keys,
                Err(reason) => {
                    unreadable.get_or_insert(reason);
                    [REFERENCE.to_vec(), LOCK.to_vec()].into_iter().collect()
                }
            }
        };
        let sig_keys = keys(sig);
        let field_keys = keys(field);
        Ambiguity {
            duplicates,
            sig_keys,
            field_keys,
            unreadable,
        }
    }
}

/// The dictionary `obj` is or refers to, if it is one.
fn deref_dict(store: &Store, obj: &Object) -> Option<Dict> {
    store.deref(obj).ok().and_then(|o| o.as_dict().cloned())
}

/// The signature dictionary the catalog's `/Perms /DocMDP` names, when it is a reference.
fn perms_docmdp(doc: &Document) -> Option<ObjectId> {
    let store = doc.store();
    doc.catalog()
        .ok()
        .and_then(|c| c.as_dict().and_then(|d| d.get(PERMS).cloned()))
        .and_then(|perms| deref_dict(store, &perms))
        .and_then(|perms| perms.get_ref(DOC_MDP))
}

/// How a document is certified (brief §4.6 rule (b)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Certification {
    /// The DocMDP permissions in force (1–3): `/TransformParams /P` (2 when absent, or when
    /// only `/Perms` names the dictionary), a signed field's `/Lock /P`, and 1 for a
    /// declaration that cannot be read (manager ruling R-6).
    pub(crate) p: u8,
}

/// Whether `doc` is certified, and with which `P` (§12.8.2.2): the signature dictionary of the
/// catalog's `/Perms /DocMDP`, every signed signature field whose signature dictionary has a
/// DocMDP reference (a certification whose catalog `/Perms` is missing), and every signed
/// signature field whose lock dictionary has `/P` (§12.7.5.5, PDF 2.0; manager ruling R-4). A
/// declaration that cannot be read ([`declared`]'s `DocMdpInvalid` cases) counts as `P = 1`,
/// never as the default 2, and the smallest `P` found counts, so an ambiguous certification is
/// never read as more permissive: Folioxide refuses to sign on top of one (rule (b)).
///
/// # Errors
/// - [`Error::Syntax`](crate::Error::Syntax) with
///   [`ErrorCode::Xref`](folioxide_syntax::ErrorCode::Xref) when the revision chain reads
///   differently in different readers ([`chain_ambiguity`]: a trailer that gives `/Prev` or
///   `/XRefStm` twice with different values; M4 QA round 3, finding 13): a certification the
///   signer's own reading skips may be one other readers see, so nothing is signed on top of it,
///   as `verify` refuses such a file.
/// - The errors of [`Document::catalog`], [`Store::deref`] and the field tree walk.
pub(crate) fn certification(doc: &Document) -> Result<Option<Certification>> {
    let store = doc.store();
    if let Some(reason) = chain_ambiguity(store) {
        return Err(crate::Error::Syntax(folioxide_syntax::Error::Xref {
            offset: None,
            message: format!("the document cannot be signed: {reason}").into(),
        }));
    }
    let catalog = doc.catalog()?;
    let catalog = catalog.as_dict();
    let mut found: Option<u8> = None;
    let mut take = |p: u8| found = Some(found.map_or(p, |seen| seen.min(p)));
    let duplicates = AmbiguousKeys::default();
    // A declaration whose bytes readers read differently counts as P = 1 (M4 QA round 2,
    // finding 8): the stricter reading, as for any declaration that cannot be read.
    let reference_p = |sig_id: Option<ObjectId>, sig: &Dict| -> u8 {
        let ambiguity = Ambiguity::of(store, &duplicates, sig_id, None);
        if sig.contains_key(REFERENCE) && ambiguity.sig_keys.contains(REFERENCE) {
            return 1;
        }
        match read_references(store, sig, &duplicates).docmdp {
            None => 2,
            Some(Ok((p, _))) => p,
            Some(Err(_)) => 1,
        }
    };
    // The /Perms /DocMDP signature dictionary.
    let perms = match catalog.and_then(|c| c.get(PERMS)) {
        Some(perms) => store.deref(perms)?.as_dict().cloned(),
        None => None,
    };
    if let Some(sig) = perms.as_ref().and_then(|p| p.get(DOC_MDP)) {
        match store.deref(sig)?.as_dict() {
            // Certified, default permissions, unless the dictionary declares others.
            Some(dict) => take(reference_p(sig.as_ref(), dict)),
            // /Perms /DocMDP that names no signature dictionary: certified, unreadably.
            None => {
                if !store.deref(sig)?.is_null() {
                    take(1);
                }
            }
        }
    }
    // The signed fields: their signature dictionaries' DocMDP references, and their locks.
    if let Some(acroform) = field::acroform_of(store, catalog)? {
        let (nodes, _) = field::walk_fields_bounded(store, &acroform.dict)?;
        for node in nodes.iter().filter(|n| n.terminal && n.is_signature()) {
            let Some(value) = node.dict.get(b"V") else {
                continue;
            };
            let Some(sig) = store.deref(value)?.as_dict().cloned() else {
                continue;
            };
            if sig.contains_key(REFERENCE) {
                let p = reference_p(value.as_ref(), &sig);
                // A dictionary with no DocMDP reference (read either way) sets nothing.
                if p < 2 || read_references(store, &sig, &duplicates).docmdp.is_some() {
                    take(p);
                }
            }
            let lock_ambiguous = node.dict.contains_key(LOCK)
                && Ambiguity::of(store, &duplicates, None, node.id)
                    .field_keys
                    .contains(LOCK);
            match lock_permissions(store, &node.dict, &duplicates) {
                _ if lock_ambiguous => take(1),
                Ok(None) => {}
                Ok(Some(p)) => take(p),
                Err(_) => take(1),
            }
        }
    }
    Ok(found.map(|p| Certification { p }))
}

/// Whether the catalog of `doc` has a `/Perms` dictionary with a `/DocMDP` entry (brief §4.6
/// rule (a): the document is certified already, signed field or not).
///
/// # Errors
/// The errors of [`Document::catalog`] and [`Store::deref`].
pub(crate) fn has_perms_docmdp(doc: &Document) -> Result<bool> {
    let store = doc.store();
    let catalog = doc.catalog()?;
    let Some(perms) = catalog.as_dict().and_then(|c| c.get(PERMS)) else {
        return Ok(false);
    };
    let perms = store.deref(perms)?;
    Ok(perms
        .as_dict()
        .and_then(|p| p.get(DOC_MDP))
        .is_some_and(|value| !value.is_null()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use folioxide_syntax::OpenOptions;

    fn parse(text: &str) -> Object {
        folioxide_syntax::parse_object(text.as_bytes(), 0, &folioxide_syntax::ParseCtx::default())
            .unwrap()
            .0
    }

    fn minimal() -> Document {
        Document::open(
            folioxide_testkit::fixtures::syntax::minimal(),
            &OpenOptions::default(),
        )
        .unwrap()
    }

    #[test]
    fn permissions_round_trip_through_p() {
        for (permissions, p) in [
            (DocMdpPermissions::NoChanges, 1),
            (DocMdpPermissions::FormFilling, 2),
            (DocMdpPermissions::FormFillingAndAnnotations, 3),
        ] {
            assert_eq!(permissions.p(), p);
            assert_eq!(u8::from(permissions), p);
            assert_eq!(DocMdpPermissions::from_p(i64::from(p)), Some(permissions));
            assert_eq!(DocMdpPermissions::try_from(p), Ok(permissions));
        }
        for bad in [i64::MIN, -1, 0, 4, 256, i64::MAX] {
            assert_eq!(DocMdpPermissions::from_p(bad), None, "{bad}");
        }
        assert!(DocMdpPermissions::try_from(0).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_is_the_number_p() {
        let json = serde_json::to_value(DocMdpPermissions::FormFillingAndAnnotations).unwrap();
        assert_eq!(json, 3);
        let back: DocMdpPermissions = serde_json::from_value(serde_json::json!(1)).unwrap();
        assert_eq!(back, DocMdpPermissions::NoChanges);
        assert!(serde_json::from_value::<DocMdpPermissions>(serde_json::json!(4)).is_err());
        assert!(serde_json::from_value::<DocMdpPermissions>(serde_json::json!("2")).is_err());
    }

    #[test]
    fn declared_permissions_of_an_unsigned_document_is_none() {
        let doc = minimal();
        assert_eq!(
            declared_permissions(&doc, &Dict::new(), ObjectId::new(1, 0)),
            None
        );
        assert_eq!(certification(&doc).unwrap(), None);
        assert!(!has_perms_docmdp(&doc).unwrap());
    }

    #[test]
    fn the_reference_dictionary_is_the_briefs() {
        let reference = reference_dictionary(DocMdpPermissions::NoChanges);
        assert_eq!(
            Object::Dict(reference),
            parse(
                "<< /Type /SigRef /TransformMethod /DocMDP /TransformParams << /Type \
                 /TransformParams /P 1 /V /1.2 >> >>"
            )
        );
    }

    #[test]
    fn declarations_and_their_problems() {
        let doc = minimal();
        let sig = ObjectId::new(9, 0);
        let duplicates = AmbiguousKeys::default();
        let ambiguity = Ambiguity::of(doc.store(), &duplicates, None, None);
        let declare =
            |text: &str| declared(&doc, parse(text).as_dict().unwrap(), sig, None, &ambiguity);
        let reference = |params: &str| {
            format!("<< /Reference [<< /TransformMethod /DocMDP /TransformParams {params} >>] >>")
        };
        for (params, p) in [
            ("<< /P 1 /V /1.2 >>", 1),
            ("<< /P 3 >>", 3),
            ("<< /V /1.2 >>", 2),
            ("<< >>", 2),
        ] {
            let d = declare(&reference(params));
            assert_eq!(d.permissions, Some(p), "{params}");
            assert!(d.certification && d.problems.is_empty(), "{params}: {d:?}");
            // /Perms does not name the dictionary: a warning, not a problem.
            assert!(d.warnings.iter().any(|w| w.contains("/Perms")), "{d:?}");
        }
        // A /V other than /1.2 is a warning.
        let d = declare(&reference("<< /P 2 /V /2.0 >>"));
        assert_eq!(d.permissions, Some(2));
        assert!(d.warnings.iter().any(|w| w.contains("/2.0")), "{d:?}");
        // Invalid declarations.
        for params in [
            "<< /P 0 >>",
            "<< /P 4 >>",
            "<< /P 2.0 >>",
            "<< /P (2) >>",
            "7",
        ] {
            let d = declare(&reference(params));
            assert_eq!(d.permissions, None, "{params}");
            assert!(d.certification, "{params}");
            assert_eq!(d.problems.len(), 1, "{params}: {d:?}");
            assert_eq!(d.problems[0].0, ProblemCode::DocMdpInvalid);
        }
        let two = declare(
            "<< /Reference [<< /TransformMethod /DocMDP /TransformParams << /P 2 >> >> \
             << /TransformMethod /DocMDP /TransformParams << /P 3 >> >>] >>",
        );
        assert_eq!(two.permissions, None);
        assert!(
            two.problems[0].1.contains("2 /Reference entries"),
            "{two:?}"
        );
        // FieldMDP references are recorded, and are no certification.
        let field_mdp = declare(
            "<< /Reference [<< /TransformMethod /FieldMDP /TransformParams << /Action /All >> \
             >>] >>",
        );
        assert!(field_mdp.field_mdp && !field_mdp.certification);
        assert_eq!(field_mdp.permissions, None);
        // An approval signature declares nothing.
        assert_eq!(declare("<< /Type /Sig >>"), Declared::default());
        // Manager ruling R-6: a /Reference pyHanko cannot read is DocMdpInvalid, and makes the
        // signature a certification (P = 1 in force), never the default 2.
        for (text, needle) in [
            (
                "<< /Reference << /TransformMethod /DocMDP >> >>",
                "not an array",
            ),
            ("<< /Reference 7 >>", "not an array"),
            (
                "<< /Reference [7] >>",
                "not a signature reference dictionary",
            ),
            (
                "<< /Reference [<< /TransformParams << /P 2 >> >>] >>",
                "no /TransformMethod",
            ),
            (
                "<< /Reference [<< /TransformMethod (DocMDP) /TransformParams << /P 2 >> >>] >>",
                "no /TransformMethod",
            ),
        ] {
            let d = declare(text);
            assert_eq!(d.permissions, None, "{text}");
            assert!(d.certification && d.restricts, "{text}: {d:?}");
            assert_eq!(d.problems.len(), 1, "{text}: {d:?}");
            assert_eq!(d.problems[0].0, ProblemCode::DocMdpInvalid);
            assert!(d.problems[0].1.contains(needle), "{text}: {d:?}");
        }
        // Other transform methods are no DocMDP declaration.
        let ur =
            declare("<< /Reference [<< /TransformMethod /UR3 /TransformParams << /P 2 >> >>] >>");
        assert_eq!(ur, Declared::default());
    }

    #[test]
    fn ambiguous_declarations_are_invalid() {
        // M4 QA round 2, finding 8: a /Reference or field /Lock that readers read differently
        // (written twice, or with a duplicate key inside) is DocMdpInvalid, so P = 1 is in force.
        let doc = minimal();
        let sig = ObjectId::new(9, 0);
        let duplicates = AmbiguousKeys::default();
        let certify =
            "<< /Reference [<< /TransformMethod /DocMDP /TransformParams << /P 3 >> >>] >>";
        let lock = "<< /FT /Sig /Lock << /Type /SigFieldLock /Action /All /P 3 >> >>";
        let with = |sig_keys: &[&[u8]], field_keys: &[&[u8]]| Ambiguity {
            duplicates: &duplicates,
            sig_keys: sig_keys.iter().map(|k| k.to_vec()).collect(),
            field_keys: field_keys.iter().map(|k| k.to_vec()).collect(),
            unreadable: None,
        };
        let declare = |sig_text: &str, field_text: Option<&str>, ambiguity: &Ambiguity<'_>| {
            let field = field_text.map(parse);
            declared(
                &doc,
                parse(sig_text).as_dict().unwrap(),
                sig,
                field.as_ref().and_then(Object::as_dict),
                ambiguity,
            )
        };
        let clean = declare(certify, Some(lock), &with(&[], &[]));
        assert_eq!(clean.permissions, Some(3));
        for (keys, field_keys) in [
            (&[REFERENCE][..], &[][..]),
            (&[][..], &[LOCK][..]),
            (&[REFERENCE][..], &[LOCK][..]),
        ] {
            let d = declare(certify, Some(lock), &with(keys, field_keys));
            assert_eq!(d.permissions, None, "{d:?}");
            assert!(d.restricts, "{d:?}");
            assert!(
                d.problems
                    .iter()
                    .any(|(code, m)| *code == ProblemCode::DocMdpInvalid && m.contains("twice")),
                "{d:?}"
            );
        }
        // An ambiguous /M changes no declaration (the report has SigDictAmbiguous for it).
        let d = declare(certify, Some(lock), &with(&[b"M"], &[b"T"]));
        assert_eq!(d.permissions, Some(3), "{d:?}");
        // An approval with an ambiguous /Reference is an (unreadable) certification, as pyHanko
        // reads the first of two /Reference entries.
        let d = declare(certify, None, &with(&[REFERENCE], &[]));
        assert!(
            d.certification && d.restricts && d.permissions.is_none(),
            "{d:?}"
        );
    }

    #[test]
    fn a_field_lock_p_sets_the_signatures_permissions() {
        // Manager ruling R-4 (ISO 32000-2 §12.7.5.5 Table 236): the stricter of the DocMDP
        // reference's P and the field lock's P.
        let doc = minimal();
        let sig = ObjectId::new(9, 0);
        let duplicates = AmbiguousKeys::default();
        let ambiguity = Ambiguity::of(doc.store(), &duplicates, None, None);
        let declare = |sig_text: &str, field_text: &str| {
            let field = parse(field_text);
            declared(
                &doc,
                parse(sig_text).as_dict().unwrap(),
                sig,
                field.as_dict(),
                &ambiguity,
            )
        };
        let approval = "<< /Type /Sig >>";
        let certify = |p: u8| {
            format!(
                "<< /Reference [<< /TransformMethod /DocMDP /TransformParams << /P {p} >> >>] >>"
            )
        };
        let lock =
            |p: &str| format!("<< /FT /Sig /Lock << /Type /SigFieldLock /Action /All {p} >> >>");
        // An approval in a field locked with /P.
        for p in [1, 2, 3] {
            let d = declare(approval, &lock(&format!("/P {p}")));
            assert_eq!(d.permissions, Some(p), "{d:?}");
            assert!(d.restricts && d.field_mdp && !d.certification, "{d:?}");
            assert!(d.problems.is_empty(), "{d:?}");
        }
        // A lock without /P is FieldMDP only.
        let d = declare(approval, &lock(""));
        assert_eq!(d.permissions, None);
        assert!(d.field_mdp && !d.restricts, "{d:?}");
        // No lock: nothing.
        assert_eq!(declare(approval, "<< /FT /Sig >>"), Declared::default());
        // Both: the stricter.
        for (reference, locked, p) in [(3, 1, 1), (1, 3, 1), (2, 3, 2), (3, 2, 2)] {
            let d = declare(&certify(reference), &lock(&format!("/P {locked}")));
            assert_eq!(d.permissions, Some(p), "{reference} {locked}: {d:?}");
            assert!(d.certification && d.restricts, "{d:?}");
        }
        // A lock /P or /Lock that cannot be read: DocMdpInvalid, P = 1 in force.
        for field in [
            lock("/P 0"),
            lock("/P 4"),
            lock("/P (1)"),
            lock("/P 1.0"),
            "<< /FT /Sig /Lock 5 >>".to_owned(),
        ] {
            let d = declare(approval, &field);
            assert_eq!(d.permissions, None, "{field}");
            assert!(d.restricts && !d.certification, "{field}: {d:?}");
            assert_eq!(d.problems.len(), 1, "{field}: {d:?}");
            assert_eq!(d.problems[0].0, ProblemCode::DocMdpInvalid);
        }
        // An invalid lock also voids a valid reference's P.
        let d = declare(&certify(3), &lock("/P 9"));
        assert_eq!(d.permissions, None);
        assert!(d.certification && d.restricts);
    }

    /// `minimal()` with one signed signature field whose field carries `field_extra` and whose
    /// signature dictionary carries `sig_extra`.
    fn signed_field(field_extra: &str, sig_extra: &str) -> Document {
        let mut doc = minimal();
        let store = doc.store_mut();
        let sig = parse(&format!("<< /Type /Sig {sig_extra} >>"));
        let sig = store.add(sig).unwrap();
        let field = parse(&format!(
            "<< /FT /Sig /T (Signature1) /V {} 0 R {field_extra} >>",
            sig.num
        ));
        let field = store.add(field).unwrap();
        let acroform = parse(&format!("<< /Fields [{} 0 R] /SigFlags 3 >>", field.num));
        let acroform = store.add(acroform).unwrap();
        let root = store.root_id().unwrap();
        let mut catalog = store.resolve(root).unwrap().as_dict().unwrap().clone();
        catalog.insert("AcroForm", Object::Ref(acroform));
        store.set(root, Object::Dict(catalog)).unwrap();
        doc
    }

    #[test]
    fn certification_reads_locks_and_never_defaults_an_invalid_declaration() {
        let p = |doc: &Document| certification(doc).unwrap().map(|c| c.p);
        // An approval: not certified.
        assert_eq!(p(&signed_field("", "")), None);
        // A signed field locked with /P (rule (b) then applies, R-4).
        for locked in [1, 2, 3] {
            let lock = format!("/Lock << /Type /SigFieldLock /Action /All /P {locked} >>");
            assert_eq!(p(&signed_field(&lock, "")), Some(locked));
        }
        let reference = |params: &str| {
            format!("/Reference [<< /TransformMethod /DocMDP /TransformParams {params} >>]")
        };
        assert_eq!(p(&signed_field("", &reference("<< /P 3 >>"))), Some(3));
        // /P absent: the Table 257 default.
        assert_eq!(p(&signed_field("", &reference("<< >>"))), Some(2));
        // R-6: what cannot be read counts as P = 1, never as 2.
        for sig_extra in [
            reference("<< /P 7 >>"),
            reference("<< /P (2) >>"),
            reference("7"),
            "/Reference << /TransformMethod /DocMDP >>".to_owned(),
            "/Reference [<< /TransformParams << /P 3 >> >>]".to_owned(),
            "/Reference [<< /TransformMethod /DocMDP /TransformParams << /P 3 >> >> \
             << /TransformMethod /DocMDP /TransformParams << /P 3 >> >>]"
                .to_owned(),
        ] {
            assert_eq!(p(&signed_field("", &sig_extra)), Some(1), "{sig_extra}");
        }
        assert_eq!(
            p(&signed_field("/Lock << /Type /SigFieldLock /P 4 >>", "")),
            Some(1)
        );
        // The stricter of a reference and a lock.
        let lock = "/Lock << /Type /SigFieldLock /Action /All /P 1 >>";
        assert_eq!(p(&signed_field(lock, &reference("<< /P 3 >>"))), Some(1));
    }
}

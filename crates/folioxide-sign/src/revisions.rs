//! Revision analysis for verification (M3 brief §5 V5 and V10; ARCHITECTURE §A.6.7): which
//! revision a signature covers ([`Revisions::coverage`]), and what the revisions appended after
//! it changed ([`Revisions::modification`]).
//!
//! **Coverage** follows pyHanko's `evaluate_signature_coverage`: a byte range that is not four
//! values from 0, or whose gap is not the signature's own `/Contents`, is
//! [`Unclear`](Coverage::Unclear); one that ends at the end of the file is
//! [`EntireFile`](Coverage::EntireFile); one that ends at the `%%EOF` of a revision of the
//! file's revision chain (a trailing end-of-line tolerated), with every cross-reference section
//! up to it inside the signed bytes and the signature dictionary not redefined later, is
//! [`EntireRevision`](Coverage::EntireRevision); anything else is
//! [`ContiguousBlockFromStart`](Coverage::ContiguousBlockFromStart). Revisions are matched by
//! `eof_end` in any order, because a linearized file's revisions are not in file order.
//!
//! **Modification** follows pyHanko's `StandardDiffPolicy.review_file` and is never more lenient
//! than it (brief §0): the signed revision `k` is compared with **each** later revision `r` in
//! turn (cumulatively, so a change that a later revision undoes is still seen), and the result is
//! the worst level. Each revision's view is a store opened on the file's bytes up to that
//! revision's `%%EOF`, so an object is compared as the signer saw it and as that revision shows
//! it. The changed set of `(k, r)` is every number the cross-reference sections `k+1..=r` list
//! (the union of a hybrid section's table and stream, free entries included). Any appended
//! revision is at least [`LtaUpdates`](ModificationLevel::LtaUpdates), as in pyHanko.
//!
//! **The classifier is a whitelist** (brief §5 V10, the manager's design principle): a later
//! revision gets a level below [`Other`](ModificationLevel::Other) only for the exact changes
//! that legitimate later signers make; every other change to an object reachable from the
//! signed revision is `Other`. Where that is stricter than pyHanko, the attack corpus records it
//! (`DELIBERATE_DIFFERENCES`).
//!
//! - An entry identical to the one in force at `k`, or an object whose value is unchanged, is a
//!   re-listing. Freeing an object, changing its generation, reusing a number listed before, or
//!   changing an object stream container is `Other`.
//! - **Parser differentials** (manager ruling R-1; `differential`): a later revision is `Other`
//!   when an object it writes holds a dictionary with a duplicate key at any depth (ISO 32000-2
//!   §7.3.7; readers keep the first or the last value, so the classifier cannot know what a
//!   viewer shows), when an object stream it writes holds a number twice or has an
//!   inconsistent header, or when one of its cross-reference sections lists a number twice or
//!   its trailer (or cross-reference stream dictionary) has a duplicate key. The syntax layer
//!   keeps parsing last-wins; this is detected on the raw bytes.
//! - **The canonical-input gate** (manager ruling R-12; `canonical`): a level below `Other` is
//!   granted only when every object the decision reads is written canonically: (1) every
//!   object revisions `k+1..=r` write (object-stream members, their container's dictionary and
//!   header, the trailers and cross-reference stream dictionaries included), (2) the signed
//!   copy of every object a later revision relists or changes, the signed objects the form
//!   rules and the `/DR` guard read, and the objects of the signed revision the role usage index
//!   reads (one that is not canonical counts when its raw bytes may refer to a watched object
//!   that Folioxide's reading of it does not), and (3) the page-tree nodes a page rule consults.
//!   Canonical
//!   means no duplicate key at any depth, integers of one optional sign and digits within
//!   ±2,147,483,647, reals with a `.`, at most 40 characters and within ±3.403 × 10^38, no
//!   token the lexer repairs (a name with `#00` or a bad `#` escape, a bad hexadecimal digit)
//!   and unsigned reference numbers: PDFium reads `++6`, `4294967296` or `-2147483648` as 0
//!   where Folioxide's lexer reads a number. One linear token pass per object, cached and
//!   charged to the work budget.
//! - **Page-tree consistency** (manager ruling R-13): a rule that depends on the page (a new
//!   widget or annotation in a page's `/Annots`, the rotation a Text annotation needs) is
//!   granted only when the page is reached exactly once by the `/Kids` walk from the catalog's
//!   `/Pages`, every node's `/Parent` is the node that lists it, and the `/Rotate` inherited
//!   along that walk is a direct integer; poppler inherits along `/Kids`, PDFium along
//!   `/Parent`.
//! - A **new** object must be explained by a rule, as pyHanko's explained references (the lowest
//!   level of the rules that explain it counts): a cross-reference or object stream, the trailer's
//!   new `/Info` dictionary, the catalog's new XMP `/Metadata` stream, `/Extensions` or
//!   `/MarkInfo` dictionary, a new AcroForm or `/Fields` array (`LtaUpdates`) and what a new
//!   `/DR` holds (`FormFilling`); a new signature field registered at the root of the new
//!   `/AcroForm /Fields` (pyHanko's `SigFieldCreationRule`: `/FT /Sig`, a `/T` without `.`, a
//!   widget if anything, with only whitelisted keys (`SIG_FIELD_KEYS`: no `/A`, `/AA`, `/OC`,
//!   `/Parent`, … M4 QA round 2), `LtaUpdates` when invisible and `FormFilling` when its
//!   `/Rect`, read through references, has an area), with the new
//!   objects its `/AP`, `/Lock` and `/SV` hold (`FormFilling`); the signature dictionary the `/V`
//!   of such a field or of an existing unsigned signature field names (`FormFilling`; a document
//!   timestamp `LtaUpdates`) and its `/TransformParams`; the new `/AP` of an existing unsigned
//!   signature field that the revision signs, and its `/N /R /D` streams (`FormFilling`). A new
//!   signature widget's `/F` may set only Invisible, Print, ReadOnly, Locked and
//!   LockedContents (never Hidden, NoZoom, NoRotate, NoView or ToggleNoView: manager ruling
//!   R-3), and its `/Rect` must be four finite numbers (M4 QA round 2: viewers read an entry
//!   they cannot use as 0). A signature widget's new appearance must be a new form XObject
//!   (never an existing object) with a direct `/BBox` of four finite numbers (with an area when
//!   the widget is visible) and, if any, a `/Matrix` of six finite numbers (invertible when
//!   visible), and so must a filled field's new or rewritten appearance stream (QA finding R5:
//!   PDFium does not clip an appearance without `/BBox`); a page's new `/Annots` array
//!   (`LtaUpdates`); and an orphan, a new object neither the trailer nor a changed object
//!   reaches through new objects (`LtaUpdates`, pyHanko's `ignore_orphaned_objects`). Anything
//!   else new, an annotation on a page that is not a registered signature widget or a new
//!   signature field with an action for example, is `Other`, as is a new object an object of
//!   the signed revision already referred to (a dangling reference that now resolves).
//! - A **changed** object by its role in the signed revision, and only while revision `r` still
//!   gives it that role (its trailer or catalog still names it; pyHanko whitelists only what the
//!   new trailer and catalog point to): the catalog (pyHanko's `CatalogModificationRule`:
//!   `/Version`, `/Extensions`, `/MarkInfo` and an XMP `/Metadata` stream may change,
//!   `LtaUpdates`; `/AcroForm` as for the AcroForm; `/DSS` and every other key are `Other`), the
//!   catalog's indirect `/Extensions` or `/MarkInfo` dictionary (`LtaUpdates`), the AcroForm
//!   (exactly: (a) `/Fields` may gain new root-level signature fields, `LtaUpdates`; (b)
//!   `/SigFlags` only as signing requires, which no signing after a signature does, so any
//!   change is `Other` as in pyHanko; (c) `/DR` may gain new resource names that no signed
//!   `/DA` string, of the field tree or of any annotation on any page, and no signed
//!   appearance stream names, read with every content stream it draws (form XObjects, tiling
//!   patterns, Type 3 glyphs, and the soft-mask groups and Type 3 fonts of its graphics states;
//!   names decoded and as written), `FormFilling`; any change to
//!   `/NeedAppearances` or `/DA`, any `/Q` change, changing or removing a `/DR` name and any
//!   other key are `Other`), the `/Fields` array, an unsigned signature field (pyHanko's
//!   `SigFieldModificationRule`: a revision that signs it, its `/V` key absent before and now a
//!   new signature dictionary, may also change `/AP`, `/AS` and `/F`, `FormFilling`; a field that
//!   stays unsigned may change only `/Ff`, `LtaUpdates`), a page or `/Annots` array (only new
//!   signature widgets appended: `LtaUpdates`), the `/Info` dictionary or the XMP metadata stream
//!   (`LtaUpdates`); the form fields and the pages' annotations by the M4 rules below;
//!   everything else is `Other` (DECISIONS D10 D-9: stricter than pyHanko, for `/DSS` for
//!   example). A role is granted only when the object has no
//!   other use in the signed revision (pyHanko clears an overridden reference only once every
//!   path that reaches it is approved): an `/Info` dictionary that is also a page's content
//!   stream, or a `/MarkInfo` dictionary that is also a font, is `Other`. Unlike pyHanko, a
//!   page's `/Parent` counts as a use (a page inherits `/Resources`, `/MediaBox`, `/CropBox` and
//!   `/Rotate` through it), and an `/Info`, `/Extensions` or `/MarkInfo` dictionary with
//!   page-tree or form-field entries is never only information. The `/Info`, `/Extensions` and
//!   `/MarkInfo` objects are never streams (pyHanko's `safe_whitelist`), and a metadata stream
//!   must look like XMP (pyHanko's `MetadataUpdateRule`: well-formed XML without entities whose
//!   root is `x:xmpmeta`; a namespace-aware XML 1.0 well-formedness check in one linear pass,
//!   `xmp`, on fewer than 10,000,000 bytes, lxml's node and name limits included, of data
//!   decoded only through the filters pyHanko decodes, as it decodes them, `metadata`; M4 QA
//!   round 3) in both revisions.
//! - The trailer: a different `/Root` (the Hide-and-Replace root switch) or `/Encrypt` is
//!   `Other`, and `/Info` may only stay or point to a new object.
//!
//! **M4** (brief §5.1–§5.3) judges the revisions in the context of the evaluated signature
//! (whether it certifies, the `P` it declares, whether it has FieldMDP), and gives every
//! explained or classified change a change class (`Relisting`, `Orphan`, `XrefStream`,
//! `Metadata`, `SignatureField`, `Signature`, `DocTimeStamp`, `DefaultResources`, `FormFill`,
//! `Annotation`), which `docmdp_ok` reads under `P = 1`:
//!
//! - **Generic form filling** (`FormFilling`, class `FormFill`; DECISIONS D13): a form field of
//!   the signed revision, used only as a field (from `/Fields` or its parent's `/Kids`, from a
//!   page's `/Annots` when merged with its widget, or from the structure tree's `/OBJR` as
//!   pyHanko finds it), may change its `/V` to a direct value of its type (F1, F2), a merged
//!   check box's or radio button's `/AS` to a signed appearance state that its value selects
//!   (F3), and a merged text or choice field's `/AP` when its `/V` changes (F4: new streams, or
//!   its signed stream rewritten while the signed revision uses that stream only as that
//!   appearance, F5); nothing else. Not in a document with `/XFA`, nor for a signature with
//!   FieldMDP, a ReadOnly field, a pushbutton, or a field whose widget sets NoZoom or NoRotate
//!   (F0; M4 QA round 2: viewers draw such a widget outside its `/Rect`, §12.5.3); a widget that
//!   is a kid of its field may not change at all, as in pyHanko.
//! - **Annotations** (`Annotations`, class `Annotation`; D-1, the one level more lenient than
//!   pyHanko): a page's `/Annots` may gain new markup annotations and their popups (A1–A5),
//!   with no change to its existing entries, after an approval signature or a certification
//!   with `P = 3`; after a certification with `P = 1` or `P = 2` any new annotation is `Other`.
//!   Each must render inside its `/Rect` (manager ruling R-2; `geometry`): a markup annotation
//!   needs an `/AP /N` form XObject as above (no viewer then synthesizes one); its geometry
//!   (`/QuadPoints`, `/InkList`, `/L` and leader lines, `/Vertices`, `/Path`, `/CL`, with `/RD`,
//!   `/BE` and the border width; direct arrays of direct numbers, charged to the work budget)
//!   lies inside the `/Rect`; its `/F` sets no Hidden, NoZoom, NoRotate, NoView or
//!   ToggleNoView flag; and a Text annotation, which viewers draw as if NoZoom and NoRotate
//!   were set (§12.5.6.4), is allowed only on a page whose effective `/Rotate` is 0 (M4 QA
//!   round 2), inherited along a page tree every reader walks the same way (R-13).
//! - **Certification** (C1): when the evaluated signature certifies (or its field's `/Lock`
//!   has `/P`, manager ruling R-4), a new visible signature field is `Other`. A document
//!   timestamp's bookkeeping (the `/Info` `/ModDate` and `/Producer`, the catalog's `/Version`
//!   and ESIC extension, and the values of the XMP packet's `xmp:ModifyDate` and `pdf:Producer`
//!   attributes when nothing else of the packet or its stream dictionary but `/Length` changes)
//!   is class `DocTimeStamp`, not `Metadata`, only when the revision that adds the timestamp
//!   (the first that lists its dictionary) wrote it and no later revision of the window
//!   rewrote it (manager ruling R-8).
//!
//! The analyses of one verification share a work budget (the numbers they examine), so a file
//! with many signatures and revisions cannot make verification quadratic without bound (R-18).

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;
use std::sync::{Arc, OnceLock};

use folioxide_model::Document;
use folioxide_syntax::{
    Dict, Lexer, Object, ObjectId, Revision, SharedBytes, Store, Stream, TokenKind, XrefEntry,
    XrefKind,
};

use crate::field;
use crate::problem::ProblemCode;
use crate::report::{Coverage, ModificationLevel};
use crate::verify_pdf::MAX_CHANGED_OBJECTS;

pub(crate) mod canonical;
pub(crate) mod differential;
pub(crate) mod geometry;
mod metadata;
mod xmp;

use xmp::{looks_like_xmp, xmp_without_bookkeeping};

/// The most revisions a file may have for the modification analysis; beyond it every
/// signature that does not cover the whole file is `Other` (hostile input, R-18).
pub(crate) const MAX_ANALYSED_REVISIONS: usize = 1024;

/// The most revisions after a signed revision that are compared with it; beyond it the
/// modification level is `Other`.
pub(crate) const MAX_REVISIONS_AFTER_SIGNATURE: usize = 256;

/// The work budget of the modification analyses of one verification, besides
/// [`MODIFICATION_WORK_PER_ENTRY`] per cross-reference entry of the file: the entries they
/// examine in total (comparing the signed revision `k` with a later revision `r` examines the
/// entries of the sections `k+1..=r`, and opening the view of revision `r` reads the sections
/// `0..=r`). The 256 sequential signatures [`MAX_VERIFIED_SIGNATURES`] allows stay below it;
/// once it is spent, the remaining comparisons report `Other` (R-18).
///
/// [`MAX_VERIFIED_SIGNATURES`]: crate::verify_pdf::MAX_VERIFIED_SIGNATURES
pub(crate) const MAX_MODIFICATION_WORK: u64 = 12_000_000;

/// The modification work allowed per cross-reference entry of the file, on top of
/// [`MAX_MODIFICATION_WORK`], so a large document with a few signatures is analysed in full.
pub(crate) const MODIFICATION_WORK_PER_ENTRY: u64 = 4;

/// The deepest nesting followed when collecting the references of an object.
const MAX_REF_DEPTH: usize = 512;

/// The most notes one modification analysis keeps.
const MAX_NOTES: usize = 16;

/// The most uses of one object of the signed revision that are recorded; an object used more
/// often is treated as used elsewhere.
const MAX_USAGES: usize = 64;

/// The largest metadata stream decoded to check that it is XMP; a larger one is not XMP (QA
/// finding: a Flate bomb as `/Metadata` must not cost a large allocation). It is below libxml2's
/// 10,000,000-byte limit on one text node, comment, attribute value, CDATA section, processing
/// instruction or white-space run (`XML_MAX_TEXT_LENGTH`, `XML_MAX_LOOKUP_LIMIT`; lxml parses
/// pyHanko's `/Metadata` without `huge_tree`), so no packet Folioxide reads trips one of those
/// limits there (M4 QA round 3, finding 19: a 10.2 MB comment was XMP to Folioxide and not to
/// pyHanko).
pub(crate) const MAX_XMP_BYTES: usize = 9_999_999;

/// The metadata bytes decoded in total by the analyses of one verification; beyond it a
/// metadata stream that is not decoded yet is not XMP.
const MAX_XMP_TOTAL: usize = 64 * 1024 * 1024;

/// The tokens the canonical-input gate ([`canonical::scan_value`], manager ruling R-12) reads per
/// unit of the work budget: the scan of an object is charged once, when it is first checked.
const SCAN_TOKENS_PER_WORK: u64 = 8;

/// The result of [`Revisions::coverage`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoverageOutcome {
    /// The coverage level.
    pub(crate) coverage: Coverage,
    /// The signed revision, for `EntireFile` (when one ends there) and `EntireRevision`.
    pub(crate) signed_revision: Option<usize>,
    /// A structural problem found on the way (`SignedRevisionNotInChain`,
    /// `SigDictRedefinedLater`).
    pub(crate) problem: Option<(ProblemCode, String)>,
}

/// What the evaluated signature is, for the modification analysis (M4 brief §5 V10): the rules
/// that depend on the signature, not on the revisions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ModificationContext {
    /// The evaluated signature sets DocMDP permissions (a certification signature, or one whose
    /// field's `/Lock` has `/P`, manager ruling R-4): a new visible signature field is `Other`
    /// (brief §5.3 C1; pyHanko's `valid_when_certifying`, applied whenever its `docmdp_level`
    /// is set, which reads the lock too).
    pub(crate) certifying: bool,
    /// The `P` the evaluated signature sets (`None` for an approval without a lock `/P`, or a
    /// declaration that cannot be read). New annotations reach the `Annotations` level only for
    /// a signature that sets no permissions or sets `P = 3` (D-1, M4 brief §0.2); after any
    /// other they are `Other`, as in pyHanko.
    pub(crate) permissions: Option<u8>,
    /// The evaluated signature carries FieldMDP (a `/Lock` on its field, or a `/Reference`
    /// FieldMDP): generic form filling is `Other` until M11 (brief §5.1 F0, D-23).
    pub(crate) field_mdp: bool,
    /// The evaluated entry is a document timestamp (ISO 32000-2 §12.8.5). It has no `docmdp_ok`
    /// of its own (`None`, manager ruling R-5); it is judged with the permissions in force in
    /// [`ModificationContext::permissions`], which gate the markup-annotation rule only: new
    /// annotations reach `Annotations` only when `P = 3` is in force (manager ruling R-20; M4
    /// QA round 5, finding 14: a markup annotation after a document timestamp in a `P = 2`
    /// document was `Annotations` for the timestamp, which `is_acceptable(Annotations)`
    /// accepted, where pyHanko says `other`). The other `P = 1` restrictions show in the
    /// certification's own `docmdp_ok` only (M4 final fix round 2, finding 3).
    pub(crate) timestamp: bool,
}

/// What kind of change a later revision made (M4 brief §5 V10): every object a comparison
/// explains or classifies below `Other` gets one, and `docmdp_ok` for `P = 1` allows only
/// [`Relisting`](ChangeClass::Relisting), [`Orphan`](ChangeClass::Orphan),
/// [`XrefStream`](ChangeClass::XrefStream) and [`DocTimeStamp`](ChangeClass::DocTimeStamp)
/// (brief §5.3 C3, D-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ChangeClass {
    /// An object listed again with the entry or value it had (pyHanko: `LTA_UPDATES`).
    Relisting,
    /// A new object nothing reaches (pyHanko's `ignore_orphaned_objects`).
    Orphan,
    /// A new cross-reference stream or object stream.
    XrefStream,
    /// Document information: the trailer's `/Info`, the XMP `/Metadata`, the catalog's
    /// `/Version`, `/Extensions` and `/MarkInfo`.
    Metadata,
    /// A new invisible, empty signature field (with its `/Fields` and `/Annots` entries), or an
    /// unsigned signature field's `/Ff`.
    SignatureField,
    /// A signature dictionary, a signed field and its appearance, a new visible signature
    /// field.
    Signature,
    /// A document timestamp: its dictionary, its invisible field and the `/Fields`, `/Annots`
    /// and bookkeeping edits made only for it (the `/Info` `/ModDate` and `/Producer`, the
    /// catalog `/Version` and its ESIC developer extension, as pyHanko's timestamper writes).
    DocTimeStamp,
    /// New AcroForm `/DR` resource names.
    DefaultResources,
    /// Generic form filling (brief §5.1).
    FormFill,
    /// New markup annotations (brief §5.2, D-1).
    Annotation,
}

impl ChangeClass {
    /// The class in camelCase, for messages: `"relisting"`, `"formFill"`, ...
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            ChangeClass::Relisting => "relisting",
            ChangeClass::Orphan => "orphan",
            ChangeClass::XrefStream => "xrefStream",
            ChangeClass::Metadata => "metadata",
            ChangeClass::SignatureField => "signatureField",
            ChangeClass::Signature => "signature",
            ChangeClass::DocTimeStamp => "docTimeStamp",
            ChangeClass::DefaultResources => "defaultResources",
            ChangeClass::FormFill => "formFill",
            ChangeClass::Annotation => "annotation",
        }
    }

    /// The classes `P = 1` allows (brief §5.3 C3, D-2; the DSS joins in M11).
    pub(crate) const NO_CHANGES: [ChangeClass; 4] = [
        ChangeClass::Relisting,
        ChangeClass::Orphan,
        ChangeClass::XrefStream,
        ChangeClass::DocTimeStamp,
    ];
}

/// The result of [`Revisions::modification`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ModificationOutcome {
    /// The worst modification level.
    pub(crate) level: ModificationLevel,
    /// The classes of the changes below `Other` (brief §5 V10); when the level is `Other`, the
    /// classes of the changes that were allowed.
    pub(crate) classes: BTreeSet<ChangeClass>,
    /// The objects the later revisions list (free entries included), sorted: the first
    /// [`MAX_CHANGED_OBJECTS`] of them.
    pub(crate) changed: Vec<ObjectId>,
    /// How many objects the later revisions list in all.
    pub(crate) changed_total: usize,
    /// Why the level is what it is, for the report's warnings (at most [`MAX_NOTES`]).
    pub(crate) notes: Vec<String>,
}

/// What [`differential::container_members`] found for an object stream container: the object
/// numbers its header lists, or why its header cannot be trusted.
type ContainerCheck = std::result::Result<Vec<u32>, String>;

/// The key of [`Revisions::entry_check`]'s cache: an object number, the entry that gives it, and
/// (for a compressed object) its container's entry.
type EntryKey = (u32, XrefEntry, Option<XrefEntry>);

/// The revisions of a document, with what the analyses need cached: each section's entries,
/// a view of the document at each revision, and the references of every object.
pub(crate) struct Revisions<'d> {
    doc: &'d Document,
    /// Per revision: its entries as written (the first listing of a number in a section is the
    /// one in force), or `None` when the section cannot be read (a reconstructed file).
    entries: Vec<Option<Vec<(u32, XrefEntry)>>>,
    /// Per revision: the entry in force for each number the section lists.
    first: Vec<BTreeMap<u32, XrefEntry>>,
    /// Per number: the revisions whose section lists it, oldest first, with the entry in force
    /// there (the index behind [`Revisions::entry_at`]).
    history: BTreeMap<u32, Vec<(usize, XrefEntry)>>,
    /// Per revision: the numbers its section lists more than once with different entries (a
    /// hybrid section whose table and stream disagree).
    conflicts: Vec<BTreeSet<u32>>,
    /// Per revision: the numbers its section lists more than once with the same entry (two
    /// subsections of a table, or overlapping `/Index` ranges of a stream; R-1).
    repeated: Vec<BTreeSet<u32>>,
    /// Per revision: the highest object number the sections up to it list (free entries
    /// included), or `None` when one of them cannot be read ([`differential::size_ambiguity`]).
    highest_listed: Vec<Option<u32>>,
    /// Per revision: why its `/Size` lets a reader drop objects it lists
    /// ([`differential::size_ambiguity`], M4 closing round, finding 13), checked once.
    size_checks: Vec<OnceCell<Option<String>>>,
    /// Per revision: why its trailer or cross-reference stream dictionary reads differently in
    /// different readers ([`differential::section_ambiguity`]), checked once.
    section_checks: Vec<OnceCell<Option<String>>>,
    /// Per revision: why its bytes as a whole may read differently in a reader that rebuilds the
    /// cross-reference data ([`differential::layout_ambiguity`]), checked once.
    layout_checks: Vec<OnceCell<Option<String>>>,
    /// Why the end of the file lets a reader rebuild the cross-reference data from the bytes
    /// ([`differential::tail_ambiguity`], manager ruling R-17 (a), (b)), checked once.
    tail_check: OnceCell<Option<String>>,
    /// Per revision: why an object stream it writes holds an object its own section does not
    /// list there ([`Revisions::object_stream_check`], manager ruling R-18), checked once.
    object_stream_checks: Vec<OnceCell<Option<String>>>,
    /// Why an object an entry gives reads differently in different readers
    /// ([`differential::object_ambiguity`], [`differential::container_members`]; manager rulings
    /// R-1 and R-12), by number, entry and (for a compressed object) its container's entry,
    /// checked once.
    entry_checks: RefCell<HashMap<EntryKey, Option<String>>>,
    /// The header numbers of object stream containers ([`differential::container_members`]),
    /// by container number and the container's entry, checked once.
    container_checks: RefCell<HashMap<(u32, Option<XrefEntry>), ContainerCheck>>,
    /// The entries of sections `0..i`, summed: the work of comparing two revisions.
    listed_before: Vec<u64>,
    /// Per revision: the document as of that revision (its bytes up to its `%%EOF`), or `None`
    /// when that view is not the revision the chain shows.
    views: Vec<OnceCell<Option<Document>>>,
    /// The references of every in-use object of the newest view, by object number.
    refs: OnceCell<BTreeMap<u32, Vec<u32>>>,
    /// Whether the document's store read every object where its cross-reference sections say
    /// (no repair, nothing recovered), so a revision's view may share the store's parsed
    /// objects ([`Revisions::value_at`]).
    shareable: bool,
    /// Per revision: what the comparisons learned about objects as that revision shows them,
    /// shared by the comparisons of every signed revision with it.
    facts: Vec<RefCell<BTreeMap<u32, Rc<Fact>>>>,
    /// Per revision: its root-level fields.
    root_fields: Vec<OnceCell<RootFields>>,
    /// The modification analyses done, by signed revision and context (signatures that cover
    /// the same revision share one).
    outcomes: RefCell<BTreeMap<(usize, ModificationContext), ModificationOutcome>>,
    /// Per revision: the form fields its field tree reaches and the annotations its pages list
    /// (`None` when they cannot all be read), for the "role still in force" rules.
    presence: Vec<OnceCell<Option<Presence>>>,
    /// The work left for the modification analyses ([`MAX_MODIFICATION_WORK`]).
    work_left: Cell<u64>,
    /// Whether a metadata stream looks like XMP, by object number and the entry it is read from.
    xmp: RefCell<HashMap<(u32, Option<XrefEntry>), bool>>,
    /// The metadata bytes decoded so far ([`MAX_XMP_TOTAL`]).
    xmp_decoded: Cell<usize>,
    /// The appearance-stream bytes [`SignedNames`] decoded so far
    /// ([`MAX_BARE_APPEARANCE_TOTAL`]).
    appearance_decoded: Cell<usize>,
    /// The canonical-input checks of the objects verification reads in the signed revision
    /// ([`differential::AmbiguousKeys`]; M4 QA round 2, finding 8; round 3, ruling R-12).
    ambiguous_keys: differential::AmbiguousKeys,
    /// Per revision: its page tree as the `/Kids` walk reads it ([`PageWalk`], manager ruling
    /// R-13), walked once when a rule needs a page.
    page_walks: Vec<OnceCell<PageWalk>>,
}

impl<'d> Revisions<'d> {
    /// Reads the revision structure of `doc`.
    pub(crate) fn new(doc: &'d Document) -> Revisions<'d> {
        let store = doc.store();
        let count = store.revisions().len();
        let mut entries = Vec::with_capacity(count);
        let mut first = Vec::with_capacity(count);
        let mut conflicts = Vec::with_capacity(count);
        let mut repeated = Vec::with_capacity(count);
        let mut highest_listed = Vec::with_capacity(count);
        let mut highest = Some(0u32);
        let mut listed_before = Vec::with_capacity(count.saturating_add(1));
        listed_before.push(0u64);
        for index in 0..count {
            let listed = store.revision_entries(index).ok();
            highest = match (&listed, highest) {
                (Some(listed), Some(so_far)) => {
                    Some(listed.iter().map(|(num, _)| *num).fold(so_far, u32::max))
                }
                _ => None,
            };
            highest_listed.push(highest);
            let mut map: BTreeMap<u32, XrefEntry> = BTreeMap::new();
            let mut conflicting = BTreeSet::new();
            let mut again = BTreeSet::new();
            for (num, entry) in listed.iter().flatten() {
                match map.get(num) {
                    Some(seen) if seen != entry => {
                        conflicting.insert(*num);
                    }
                    Some(_) => {
                        again.insert(*num);
                    }
                    None => {
                        map.insert(*num, *entry);
                    }
                }
            }
            let so_far = listed_before.last().copied().unwrap_or(0);
            listed_before.push(so_far.saturating_add(listed.as_ref().map_or(0, Vec::len) as u64));
            entries.push(listed);
            first.push(map);
            conflicts.push(conflicting);
            repeated.push(again);
        }
        let total_entries = listed_before.last().copied().unwrap_or(0);
        let mut history: BTreeMap<u32, Vec<(usize, XrefEntry)>> = BTreeMap::new();
        for (index, map) in first.iter().enumerate() {
            for (&num, &entry) in map {
                history.entry(num).or_default().push((index, entry));
            }
        }
        Revisions {
            doc,
            entries,
            first,
            history,
            conflicts,
            repeated,
            highest_listed,
            size_checks: (0..count).map(|_| OnceCell::new()).collect(),
            section_checks: (0..count).map(|_| OnceCell::new()).collect(),
            layout_checks: (0..count).map(|_| OnceCell::new()).collect(),
            tail_check: OnceCell::new(),
            object_stream_checks: (0..count).map(|_| OnceCell::new()).collect(),
            entry_checks: RefCell::new(HashMap::new()),
            container_checks: RefCell::new(HashMap::new()),
            listed_before,
            views: (0..count).map(|_| OnceCell::new()).collect(),
            refs: OnceCell::new(),
            shareable: !store.structure_repaired() && store.recovered_objects().is_empty(),
            facts: (0..count).map(|_| RefCell::new(BTreeMap::new())).collect(),
            root_fields: (0..count).map(|_| OnceCell::new()).collect(),
            outcomes: RefCell::new(BTreeMap::new()),
            presence: (0..count).map(|_| OnceCell::new()).collect(),
            work_left: Cell::new(
                MAX_MODIFICATION_WORK
                    .saturating_add(total_entries.saturating_mul(MODIFICATION_WORK_PER_ENTRY)),
            ),
            xmp: RefCell::new(HashMap::new()),
            xmp_decoded: Cell::new(0),
            appearance_decoded: Cell::new(0),
            ambiguous_keys: differential::AmbiguousKeys::default(),
            page_walks: (0..count).map(|_| OnceCell::new()).collect(),
        }
    }

    /// The canonical-input checks of this verification ([`differential::AmbiguousKeys`]): the
    /// object streams they decode are read once.
    pub(crate) fn ambiguous_keys(&self) -> &differential::AmbiguousKeys {
        &self.ambiguous_keys
    }

    fn store(&self) -> &'d Store {
        self.doc.store()
    }

    /// The same analyses with a work budget of `work` (tests).
    #[cfg(test)]
    fn with_work_budget(self, work: u64) -> Self {
        self.work_left.set(work);
        self
    }

    fn revisions(&self) -> &'d [Revision] {
        self.store().revisions()
    }

    /// The entry in force for `num` as of revision `rev`: its newest listing in sections
    /// `0..=rev`.
    fn entry_at(&self, num: u32, rev: usize) -> Option<XrefEntry> {
        let listings = self.history.get(&num)?;
        let upto = listings.partition_point(|&(index, _)| index <= rev);
        listings.get(upto.checked_sub(1)?).map(|&(_, entry)| entry)
    }

    /// The newest revision up to `rev` whose section lists `num`.
    fn last_listing_upto(&self, num: u32, rev: usize) -> Option<usize> {
        let listings = self.history.get(&num)?;
        let upto = listings.partition_point(|&(index, _)| index <= rev);
        listings.get(upto.checked_sub(1)?).map(|&(index, _)| index)
    }

    /// The oldest revision of `after+1..=upto` whose section lists `num`.
    fn first_listing_between(&self, num: u32, after: usize, upto: usize) -> Option<usize> {
        let listings = self.history.get(&num)?;
        let from = listings.partition_point(|&(index, _)| index <= after);
        listings
            .get(from)
            .map(|&(index, _)| index)
            .filter(|&index| index <= upto)
    }

    /// The newest revision whose section lists `num`.
    fn last_listing(&self, num: u32) -> Option<usize> {
        self.history
            .get(&num)
            .and_then(|listings| listings.last())
            .map(|&(index, _)| index)
    }

    // ---- coverage (brief §5 V5) ----------------------------------------------------------------

    /// The coverage of a signature whose `/ByteRange` is `byte_range` (as written) and whose
    /// gap is (`gap_ok`) or is not this signature dictionary's own `/Contents`; `sig` is the
    /// signature dictionary's object, for the "redefined later" check.
    pub(crate) fn coverage(
        &self,
        byte_range: &[i64],
        gap_ok: bool,
        sig: Option<ObjectId>,
    ) -> CoverageOutcome {
        let unclear = CoverageOutcome {
            coverage: Coverage::Unclear,
            signed_revision: None,
            problem: None,
        };
        let len = self.store().source().len() as u64;
        let Some([start1, _, start2, len2]) = sane_byte_range(byte_range, len) else {
            return unclear;
        };
        let Some(end) = start2.checked_add(len2) else {
            return unclear;
        };
        // A signature dictionary that a revision after the signed one lists again: pyHanko's
        // signed revision is the last change of the dictionary, so its coverage check fails.
        let redefined = sig
            .zip(self.find_signed_revision(end))
            .and_then(|(sig, k)| {
                let last = self.last_listing(sig.num)?;
                (last > k).then(|| {
                    (
                        ProblemCode::SigDictRedefinedLater,
                        format!(
                            "revision {last}, after the signed revision {k}, lists the signature \
                         dictionary {sig}"
                        ),
                    )
                })
            });
        if start1 != 0 || !gap_ok {
            return CoverageOutcome {
                problem: redefined,
                ..unclear
            };
        }
        if end == len {
            return CoverageOutcome {
                coverage: Coverage::EntireFile,
                signed_revision: self.find_signed_revision(end),
                problem: None,
            };
        }
        let not_in_chain = |message: String| CoverageOutcome {
            coverage: Coverage::ContiguousBlockFromStart,
            signed_revision: None,
            problem: Some((ProblemCode::SignedRevisionNotInChain, message)),
        };
        let Some(k) = self.find_signed_revision(end) else {
            return not_in_chain(format!(
                "the signed bytes end at {end}, which is not the end of a revision of the \
                 file's revision chain"
            ));
        };
        let revisions = self.revisions();
        if let Some(late) = revisions
            .get(..=k)
            .unwrap_or_default()
            .iter()
            .position(|r| r.section_end > end)
        {
            return not_in_chain(format!(
                "the cross-reference section of revision {late} ends after the signed bytes"
            ));
        }
        if redefined.is_some() {
            return CoverageOutcome {
                coverage: Coverage::ContiguousBlockFromStart,
                signed_revision: None,
                problem: redefined,
            };
        }
        CoverageOutcome {
            coverage: Coverage::EntireRevision,
            signed_revision: Some(k),
            problem: None,
        }
    }

    /// The newest revision of the chain whose `%%EOF` ends where the signed bytes end, up to two
    /// end-of-line bytes apart (brief §5 V5; any revision, for linearized files).
    pub(crate) fn find_signed_revision(&self, end: u64) -> Option<usize> {
        let source = self.store().source();
        let eol_only = |a: u64, b: u64| {
            b - a <= 2
                && usize::try_from(a)
                    .ok()
                    .zip(usize::try_from(b).ok())
                    .and_then(|(a, b)| source.get(a..b))
                    .is_some_and(|gap| gap.iter().all(|&c| c == b'\r' || c == b'\n'))
        };
        self.revisions().iter().rposition(|revision| {
            let eof = revision.eof_end;
            revision.xref_kind != XrefKind::Reconstructed
                && (eof == end
                    || (eof > end && eol_only(end, eof))
                    || (end > eof && eol_only(eof, end)))
        })
    }

    // ---- modification (brief §5 V10) -----------------------------------------------------------

    /// What the revisions after revision `k` changed, compared with revision `k`, for a
    /// signature described by `ctx` (analysed once per revision and context).
    pub(crate) fn modification(&self, k: usize, ctx: &ModificationContext) -> ModificationOutcome {
        if let Some(known) = self.outcomes.borrow().get(&(k, *ctx)) {
            return known.clone();
        }
        let outcome = self.analyse(k, ctx);
        self.outcomes
            .borrow_mut()
            .insert((k, *ctx), outcome.clone());
        outcome
    }

    /// [`Revisions::modification`] without the cache.
    fn analyse(&self, k: usize, ctx: &ModificationContext) -> ModificationOutcome {
        let revisions = self.revisions();
        let count = revisions.len();
        let mut changed: BTreeSet<ObjectId> = BTreeSet::new();
        for listed in self.entries.iter().skip(k.saturating_add(1)).flatten() {
            for (num, entry) in listed {
                if *num != 0 {
                    changed.insert(ObjectId::new(*num, entry_gen(entry)));
                }
            }
        }
        let mut outcome = ModificationOutcome {
            level: ModificationLevel::None,
            classes: BTreeSet::new(),
            changed_total: changed.len(),
            changed: changed.into_iter().take(MAX_CHANGED_OBJECTS).collect(),
            notes: Vec::new(),
        };
        // Manager ruling R-17 (a), (b): bytes follow the signed revision (the signature covers it,
        // not the whole file), so the file must end where every reader finds its last
        // `startxref`; otherwise poppler rebuilds the cross-reference data from the bytes and
        // reads what the sections do not say (M4 QA round 5, findings 10, 13 and 16–26). This
        // holds even without a later revision: trailing white-space alone makes poppler read the
        // signed bytes another way.
        let tail = self.tail_check();
        if k.saturating_add(1) >= count {
            if let Some(reason) = tail {
                outcome.level = ModificationLevel::Other;
                outcome.notes.push(reason);
            }
            return outcome;
        }
        let mut diff = Diff {
            level: ModificationLevel::LtaUpdates,
            classes: BTreeSet::new(),
            notes: Vec::new(),
        };
        if let Some(reason) = tail {
            diff.other(reason);
        } else if count > MAX_ANALYSED_REVISIONS || count - k - 1 > MAX_REVISIONS_AFTER_SIGNATURE {
            diff.other(format!(
                "the file has {count} revisions, too many to analyse what the {} revisions \
                 after the signed one changed",
                count - k - 1
            ));
        } else if self.entries.iter().skip(k + 1).any(Option::is_none) {
            diff.other("a later revision's cross-reference section cannot be read".to_owned());
        } else {
            match self.view(k) {
                None => diff.other(self.unopened(k)),
                Some(old) => {
                    let base = Base::new(self, old, k);
                    // Ruling R-19: a shared field appearance dictionary makes every later
                    // revision Other, as in pyHanko.
                    if let Some(reason) = &base.shared_appearance {
                        diff.other(reason.clone());
                    }
                    for r in k + 1..count {
                        if !self.spend_work(k, r) {
                            diff.other(self.budget_spent(k));
                            break;
                        }
                        match self.view(r) {
                            Some(new) => self.compare(&base, old, new, k, r, ctx, &mut diff),
                            None => diff.other(self.unopened(r)),
                        }
                        if diff.level == ModificationLevel::Other {
                            break; // nothing later can make it worse
                        }
                    }
                }
            }
        }
        outcome.level = diff.level;
        outcome.classes = diff.classes;
        outcome.notes = diff.notes;
        outcome
    }

    /// Why the view of revision `rev` is missing: the work budget, or bytes that do not open as
    /// that revision.
    fn unopened(&self, rev: usize) -> String {
        if self.work_left.get() == 0 {
            self.budget_spent(rev)
        } else {
            format!("the bytes up to revision {rev} do not open as that revision")
        }
    }

    /// The note for a spent work budget.
    fn budget_spent(&self, k: usize) -> String {
        format!(
            "the file has too many revisions and changes to analyse after revision {k}: the \
             verification's work budget (cross-reference entries examined) is spent"
        )
    }

    /// Takes the work of comparing revision `k` with revision `r` (the entries of the sections
    /// `k+1..=r`) from the budget; `false` when it is spent.
    fn spend_work(&self, k: usize, r: usize) -> bool {
        let entries = |i: usize| self.listed_before.get(i).copied().unwrap_or(u64::MAX);
        let work = entries(r.saturating_add(1)).saturating_sub(entries(k.saturating_add(1)));
        self.spend(work.max(1))
    }

    /// Takes `work` from the budget; `false` (and an empty budget) when it does not suffice.
    fn spend(&self, work: u64) -> bool {
        match self.work_left.get().checked_sub(work) {
            Some(left) => {
                self.work_left.set(left);
                true
            }
            None => {
                self.work_left.set(0);
                false
            }
        }
    }

    /// The document as of revision `index`: a store over the file's bytes up to that revision's
    /// `%%EOF`, checked to show exactly revisions `0..=index` of the chain.
    fn view(&self, index: usize) -> Option<&Document> {
        self.views
            .get(index)?
            .get_or_init(|| {
                // Opening the view reads the sections 0..=index: that is work too.
                let sections = self
                    .listed_before
                    .get(index.saturating_add(1))
                    .copied()
                    .unwrap_or(u64::MAX);
                if self.spend(sections) {
                    self.open_view(index)
                } else {
                    None
                }
            })
            .as_ref()
    }

    fn open_view(&self, index: usize) -> Option<Document> {
        let store = self.store();
        let revisions = store.revisions();
        let revision = revisions.get(index)?;
        let len = usize::try_from(revision.eof_end).ok()?;
        if len > store.source().len() {
            return None;
        }
        let prefix: SharedBytes = Arc::new(Prefix {
            bytes: store.shared_source().clone(),
            len,
        });
        let view = Store::open(prefix, store.options()).ok()?;
        let same_chain = !view.structure_repaired()
            && view.revisions().len() == index + 1
            && view
                .revisions()
                .iter()
                .zip(revisions)
                .all(|(a, b)| a.startxref == b.startxref && a.xref_kind == b.xref_kind);
        if !same_chain {
            return None;
        }
        Document::from_store(view).ok()
    }

    /// Object `id` as the view of revision `rev` (`view`) shows it. When the same bytes are in
    /// force in the newest revision (the same uncompressed entry), the document store's parsed
    /// object is shared instead of parsing it again (verification resolved every object
    /// already); streams are always read from the view, whose `/Length` may differ.
    fn value_at(
        &self,
        view: &Store,
        rev: usize,
        id: ObjectId,
    ) -> folioxide_syntax::Result<Arc<Object>> {
        if self.shareable {
            let newest = self.revisions().len().saturating_sub(1);
            let entry = self.entry_at(id.num, rev);
            if matches!(entry, Some(XrefEntry::InFile { .. }))
                && entry == self.entry_at(id.num, newest)
                && let Ok(value) = self.store().resolve(id)
                && !matches!(*value, Object::Stream(_))
            {
                return Ok(value);
            }
        }
        view.resolve(id)
    }

    /// What object `num` (generation 0) is in revision `r` (`view`): its value, its kind and its
    /// references, computed once per revision; `None` when it cannot be read.
    fn fact(&self, view: &Store, r: usize, num: u32) -> Option<Rc<Fact>> {
        let cache = self.facts.get(r)?;
        if let Some(fact) = cache.borrow().get(&num) {
            return Some(Rc::clone(fact));
        }
        let value = self.value_at(view, r, ObjectId::new(num, 0)).ok()?;
        let position = match self.entry_at(num, r) {
            Some(XrefEntry::InFile { pos, .. }) => Some(pos),
            _ => None,
        };
        let fact = Rc::new(Fact {
            refs: references_of(&value),
            kind: classify_new(view, &value),
            value,
            position,
        });
        cache.borrow_mut().insert(num, Rc::clone(&fact));
        Some(fact)
    }

    /// The root-level fields of revision `r` (`view`, whose catalog is `catalog`), read once.
    fn root_fields_at(&self, view: &Store, r: usize, catalog: Option<&Dict>) -> &RootFields {
        static EMPTY: OnceLock<RootFields> = OnceLock::new();
        match self.root_fields.get(r) {
            Some(cell) => cell.get_or_init(|| {
                let fields = root_field_names(view, catalog);
                self.spend(fields.names.len() as u64);
                fields
            }),
            None => EMPTY.get_or_init(RootFields::default),
        }
    }

    /// The references of every in-use object of the newest view, by object number.
    fn references(&self) -> &BTreeMap<u32, Vec<u32>> {
        self.refs.get_or_init(|| {
            let store = self.store();
            let mut out: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
            for id in store.object_ids() {
                if let Ok(obj) = store.resolve(id) {
                    out.entry(id.num).or_default().extend(references_of(&obj));
                }
            }
            out
        })
    }

    /// Whether object `id` of `store` (the view of revision `rev`) is a stream whose data looks
    /// like an XMP packet ([`looks_like_xmp`]), decoding at most [`MAX_XMP_BYTES`] of it, as
    /// pyHanko decodes it ([`metadata::decode`]; M4 QA round 3, finding 20), each stream once per
    /// verification.
    fn is_xmp(&self, store: &Store, rev: usize, id: ObjectId) -> bool {
        let key = (id.num, self.entry_at(id.num, rev));
        if let Some(&known) = self.xmp.borrow().get(&key) {
            return known;
        }
        let verdict = match store.resolve(id).as_deref() {
            // Too large, or not decodable as pyHanko decodes it: not an XMP packet.
            Ok(Object::Stream(stream)) => self
                .xmp_data(store, stream)
                .is_some_and(|data| looks_like_xmp(&data)),
            _ => false,
        };
        self.xmp.borrow_mut().insert(key, verdict);
        verdict
    }

    /// The data of the metadata stream `stream` of `store`, decoded as pyHanko decodes it
    /// ([`metadata::decode`]), when it is at most [`MAX_XMP_BYTES`] and what is left of the
    /// verification's XMP budget (which it spends).
    fn xmp_data(&self, store: &Store, stream: &Stream) -> Option<Vec<u8>> {
        let left = MAX_XMP_TOTAL.saturating_sub(self.xmp_decoded.get());
        let data = metadata::decode(store, stream, MAX_XMP_BYTES.min(left))?;
        self.xmp_decoded
            .set(self.xmp_decoded.get().saturating_add(data.len()));
        Some(data)
    }

    /// Compares revision `r` with the signed revision `k` (pyHanko's `apply(old, new)`), for the
    /// signature `ctx` describes.
    #[allow(clippy::too_many_arguments)]
    fn compare(
        &self,
        base: &Base,
        old: &Document,
        new: &Document,
        k: usize,
        r: usize,
        ctx: &ModificationContext,
        diff: &mut Diff,
    ) {
        let old_store = old.store();
        let new_store = new.store();

        // The trailer: the catalog and the encryption must stay (Hide-and-Replace root switch).
        let old_trailer = old_store.trailer();
        let new_trailer = new_store.trailer();
        for key in [b"Root".as_slice(), b"Encrypt"] {
            if old_trailer.get(key) != new_trailer.get(key) {
                diff.other(format!(
                    "revision {r} changes the trailer's /{}",
                    String::from_utf8_lossy(key)
                ));
            }
        }

        // A hybrid section whose table and stream disagree: readers differ on what it means.
        for (index, conflicting) in self.conflicts.iter().enumerate().take(r + 1).skip(k + 1) {
            if let Some(num) = conflicting.iter().next() {
                diff.other(format!(
                    "the cross-reference section of revision {index} lists object {num} twice \
                     with different entries (its table and its stream disagree)"
                ));
            }
        }
        // R-1, parser differentials: a section that lists a number more than once, and a
        // trailer or cross-reference stream dictionary with a duplicate key.
        for index in k + 1..=r {
            if let Some(num) = self.repeated.get(index).and_then(|nums| nums.iter().next()) {
                diff.other(format!(
                    "the cross-reference section of revision {index} lists object {num} more than \
                     once; readers differ on which listing counts (parser differential)"
                ));
            }
            if let Some(reason) = self.section_check(index) {
                diff.other(reason);
            }
            if let Some(reason) = self.size_check(index) {
                diff.other(reason);
            }
            if let Some(reason) = self.layout_check(index) {
                diff.other(reason);
            }
            if let Some(reason) = self.object_stream_check(index) {
                diff.other(reason);
            }
        }

        // The numbers sections k+1..=r list, with their entries then and now.
        let listed: BTreeSet<u32> = self
            .entries
            .get(k + 1..=r)
            .unwrap_or_default()
            .iter()
            .flatten()
            .flatten()
            .map(|(num, _)| *num)
            .filter(|&num| num != 0)
            .collect();
        let section_positions: HashSet<u64> = self
            .revisions()
            .get(k + 1..=r)
            .unwrap_or_default()
            .iter()
            .flat_map(|rev| {
                let header = self.store().header_offset();
                [
                    Some(rev.startxref.saturating_add(header)),
                    rev.xref_stm.map(|s| s.saturating_add(header)),
                ]
            })
            .flatten()
            .collect();

        let mut new_values: BTreeMap<u32, Rc<Fact>> = BTreeMap::new();
        let mut changed: Vec<Changed> = Vec::new();
        for &num in &listed {
            let before = self.entry_at(num, k);
            let after = self.entry_at(num, r);
            if before == after {
                // A re-listing (probe C_relist: pyHanko LTA_UPDATES).
                diff.allow(ModificationLevel::LtaUpdates, ChangeClass::Relisting);
                continue;
            }
            // Rulings R-1 and R-12: bytes written after signing that readers read differently.
            if let Some(entry) = after.filter(in_use)
                && let Some(reason) = self.entry_check(new_store, r, num, entry)
            {
                diff.other(format!("revision {r}: {reason}"));
            }
            // Ruling R-12 (2): the signed copy of an object a later revision changes or relists
            // is read too (compared with the new one), so it must read the same in every reader
            // (QA round 3, finding 5: a signed field whose /Rect is written twice, filled with a
            // clean copy, changes another /Rect for a first-wins reader than for Folioxide).
            if let (Some(was), Some(_)) = (before.filter(in_use), after.filter(in_use))
                && let Some(reason) = self.entry_check(old_store, k, num, was)
            {
                diff.other(format!(
                    "the signed revision {k}'s copy of object {num}, which revision {r} changes or \
                     lists again: {reason}"
                ));
            }
            match (before.filter(in_use), after.filter(in_use)) {
                (None, None) => {}
                (Some(_), None) => diff.other(format!("revision {r} frees object {num}")),
                (None, Some(entry)) => {
                    if base.listed.contains(&num) {
                        diff.other(format!(
                            "revision {r} reuses object number {num}, which the signed revision \
                             lists"
                        ));
                    } else if entry_gen(&entry) != 0 {
                        diff.other(format!(
                            "revision {r} adds object {num} with a generation other than 0"
                        ));
                    } else {
                        match self.fact(new_store, r, num) {
                            Some(fact) => {
                                new_values.insert(num, fact);
                            }
                            None => diff.other(format!("new object {num} cannot be read")),
                        }
                    }
                }
                (Some(was), Some(now)) => {
                    let (was_gen, now_gen) = (entry_gen(&was), entry_gen(&now));
                    if was_gen != now_gen {
                        diff.other(format!(
                            "revision {r} changes the generation of object {num}"
                        ));
                        continue;
                    }
                    let id = ObjectId::new(num, now_gen);
                    match (
                        self.value_at(old_store, k, id),
                        self.value_at(new_store, r, id),
                    ) {
                        (Ok(old_value), Ok(new_value)) => {
                            if same_value(old_store, &old_value, new_store, &new_value) {
                                diff.allow(ModificationLevel::LtaUpdates, ChangeClass::Relisting);
                            } else {
                                changed.push(Changed {
                                    id,
                                    old: old_value,
                                    new: new_value,
                                });
                            }
                        }
                        _ => diff.other(format!("object {num} cannot be read in revision {r}")),
                    }
                }
            }
        }

        let old_catalog = old.catalog().ok();
        let new_catalog = new.catalog().ok();
        let old_catalog = old_catalog.as_deref().and_then(Object::as_dict);
        let new_catalog = new_catalog.as_deref().and_then(Object::as_dict);

        // New objects: what they are. A new signature field counts only when the new revision's
        // /AcroForm /Fields lists it at the root (pyHanko's SigFieldCreationRule).
        let root_fields = self.root_fields_at(new_store, r, new_catalog);
        let mut kinds: BTreeMap<u32, NewKind> = BTreeMap::new();
        for (&num, fact) in &new_values {
            let kind = if fact
                .position
                .is_some_and(|p| section_positions.contains(&p))
            {
                NewKind::XrefStream
            } else {
                fact.kind
            };
            let kind = match kind {
                // Not registered: judged as any other new object (an orphan, or unexplained).
                NewKind::SigField { .. } if !root_fields.contains_key(&num) => NewKind::Other,
                NewKind::SigField { .. } if !root_fields.is_unique(num) => {
                    diff.other(format!(
                        "revision {r} adds the signature field {num} with the name of another \
                         field"
                    ));
                    NewKind::Other
                }
                // The whitelist: no signer gives its new field an action or optional content
                // (stricter than pyHanko, which only looks at what the field's /AP, /Lock and
                // /SV hold).
                NewKind::SigField { visible, .. } => match forbidden_sig_field_key(&fact.value) {
                    Some(key) => {
                        diff.other(format!(
                            "revision {r} adds the signature field {num} with /{key}, which no \
                             signer writes on a new signature field (the whitelist of M4 brief \
                             §5.3; for example an action, optional content or a parent)"
                        ));
                        NewKind::Other
                    }
                    // R-3 and QA finding R5: the flags a signer writes (4 or 132), and an
                    // appearance viewers clip to the widget's /Rect.
                    None => {
                        match new_widget_problem(new_store, &new_values, &fact.value, visible) {
                            Some(problem) => {
                                diff.other(format!(
                                    "revision {r} adds the signature field {num}, which {problem}"
                                ));
                                NewKind::Other
                            }
                            None => kind,
                        }
                    }
                },
                kind => kind,
            };
            // C1 (M4 brief §5.3): after a certification signature, a new visible signature field
            // is not allowed (pyHanko's `valid_when_certifying=False`, probe
            // `p2_approval_visible`: OTHER). pyHanko applies it whenever the signature's
            // `docmdp_level` is set, which a field lock's /P sets too (manager ruling R-4).
            if ctx.certifying && matches!(kind, NewKind::SigField { visible: true, .. }) {
                diff.other(format!(
                    "revision {r} adds the visible signature field {num} after a certification \
                     signature (M4 brief §5.3 C1; a signature whose field lock has /P counts as \
                     one)"
                ));
            }
            kinds.insert(num, kind);
        }

        // The signature dictionaries the /V of a new field or of a changed unsigned signature
        // field names: those are signing (pyHanko's SigFieldModificationRule); any other new
        // signature dictionary is judged as any other new object.
        let mut values_of_fields: BTreeSet<u32> = BTreeSet::new();
        for (num, fact) in &new_values {
            if matches!(kinds.get(num), Some(NewKind::SigField { .. }))
                && let Some(v) = fact.value.as_dict().and_then(|d| d.get_ref(b"V"))
            {
                values_of_fields.insert(v.num);
            }
        }
        for change in &changed {
            // Only a field with no /V entry at all can be signed (pyHanko's previously_signed).
            if base.is_unsigned_sig_field(change.id.num)
                && change
                    .old
                    .as_dict()
                    .is_some_and(|old| !old.contains_key(b"V"))
                && let Some(v) = change.new.as_dict().and_then(|d| d.get_ref(b"V"))
            {
                values_of_fields.insert(v.num);
            }
        }
        for (num, kind) in kinds.iter_mut() {
            if matches!(kind, NewKind::SigDict { .. }) && !values_of_fields.contains(num) {
                *kind = NewKind::Other;
            }
        }
        // The revisions of the window that add a document timestamp: the bookkeeping edits
        // written in such a revision are part of it (ChangeClass::DocTimeStamp; ruling R-8:
        // only there, and only as the object's newest write of the window). A timestamp is
        // added by the revision that first writes its dictionary after the signed one; a later
        // revision that lists the dictionary again adds nothing (QA round 2, finding 21: a plain
        // revision re-listing it byte-identically must not exempt its own /Info rewrite).
        let dts_revisions: BTreeSet<usize> = kinds
            .iter()
            .filter(|(_, kind)| matches!(kind, NewKind::SigDict { timestamp: true }))
            .filter_map(|(&num, _)| self.first_listing_between(num, k, r))
            .collect();

        let cx = Cx {
            revisions: self,
            old: old_store,
            new: new_store,
            k,
            r,
            ctx: *ctx,
            new_values: &new_values,
            kinds: &kinds,
            new_catalog,
            dts_revisions,
            new_doc: new,
            walked: RefCell::new(HashMap::new()),
        };
        let mut explained = Explained::default();

        // The rules pyHanko applies to every comparison, whatever changed.
        cx.info_rule(&mut explained, diff);
        if let (Some(old_catalog), Some(new_catalog)) = (old_catalog, new_catalog) {
            cx.catalog_reference_rules(old_catalog, new_catalog, &mut explained, diff);
        }

        // What the new objects' kinds explain.
        for (&num, kind) in &kinds {
            let Some(value) = new_values.get(&num).map(|fact| &fact.value) else {
                continue;
            };
            match *kind {
                NewKind::XrefStream | NewKind::ObjStm => {
                    explained.add(num, ModificationLevel::LtaUpdates, ChangeClass::XrefStream);
                }
                NewKind::SigDict { timestamp } => {
                    let (level, class) = if timestamp {
                        (ModificationLevel::LtaUpdates, ChangeClass::DocTimeStamp)
                    } else {
                        (ModificationLevel::FormFilling, ChangeClass::Signature)
                    };
                    explained.add(num, level, class);
                    cx.explain_transform_params(value, class, &mut explained);
                }
                NewKind::SigField { visible, .. } => {
                    let dict = value.as_dict();
                    let v_ok = match dict.and_then(|d| d.get(b"V")) {
                        None | Some(Object::Null) => true,
                        Some(Object::Ref(sig)) => {
                            matches!(kinds.get(&sig.num), Some(NewKind::SigDict { .. }))
                        }
                        Some(_) => false,
                    };
                    if !v_ok {
                        diff.other(format!(
                            "the new signature field {num} has a /V that is not a new \
                             signature dictionary"
                        ));
                        continue;
                    }
                    let class = cx.sig_field_class(num);
                    explained.add(
                        num,
                        if visible {
                            ModificationLevel::FormFilling
                        } else {
                            ModificationLevel::LtaUpdates
                        },
                        class,
                    );
                    // pyHanko clears what the field's /AP, /Lock and /SV hold as form filling;
                    // anything else only the field refers to (an indirect /Rect) stays
                    // unexplained.
                    for key in [b"AP".as_slice(), b"Lock", b"SV"] {
                        if let Some(held) = dict.and_then(|d| d.get(key)) {
                            cx.explain_dependencies(
                                held,
                                ModificationLevel::FormFilling,
                                ChangeClass::Signature,
                                &mut explained,
                            );
                        }
                    }
                }
                NewKind::Other => {}
            }
        }

        // Changed objects: by their role in the signed revision.
        let rules = Rules {
            cx: &cx,
            base,
            reasons: RefCell::new(Vec::new()),
            classes: RefCell::new(BTreeSet::new()),
            annotations: RefCell::new(BTreeSet::new()),
            annotation_checks: RefCell::new(HashMap::new()),
        };
        for change in &changed {
            let level = rules.classify(base, change, diff);
            let classes = std::mem::take(&mut *rules.classes.borrow_mut());
            diff.raise(level);
            if level < ModificationLevel::Other {
                diff.classes.extend(classes);
            }
            rules.explain_changed(base, change, &mut explained);
        }
        // The annotations the pages' /Annots gained (brief §5.2), and what they hold.
        for &num in rules.annotations.borrow().iter() {
            explained.add(num, ModificationLevel::Annotations, ChangeClass::Annotation);
            if let Some(dict) = new_values.get(&num).and_then(|f| f.value.as_dict()) {
                for (key, value) in dict.iter() {
                    if ANNOTATION_LINKS.contains(&key.as_bytes()) {
                        continue; // judged as annotations of their own (A4, A5)
                    }
                    cx.explain_dependencies(
                        value,
                        ModificationLevel::Annotations,
                        ChangeClass::Annotation,
                        &mut explained,
                    );
                }
            }
        }

        // New objects: explained, orphans (pyHanko's ignore_orphaned_objects), or other.
        let reachable = cx.reachable_new(new_trailer, &changed);
        for &num in new_values.keys() {
            if base.dangling.contains(&num) {
                diff.other(format!(
                    "object {num}, added after signing, was already referenced by the signed \
                     revision"
                ));
            } else if !reachable.contains(&num) {
                diff.allow(ModificationLevel::LtaUpdates, ChangeClass::Orphan);
            } else if let Some((level, class)) = explained.get(num) {
                diff.allow(level, class);
            } else {
                diff.other(format!(
                    "revision {r} adds object {num}, which no allowed change explains"
                ));
            }
        }
    }

    /// [`differential::section_ambiguity`] of revision `index`, checked once (its tokens are
    /// work of the budget).
    fn section_check(&self, index: usize) -> Option<String> {
        let revision = self.revisions().get(index)?;
        self.section_checks
            .get(index)?
            .get_or_init(|| {
                let checked = differential::section_ambiguity(self.store(), index, revision);
                self.charged(checked.work, checked.verdict)
            })
            .clone()
    }

    /// [`differential::size_ambiguity`] of revision `index` (`index > 0`), checked once.
    fn size_check(&self, index: usize) -> Option<String> {
        let highest = self.highest_listed.get(index).copied().flatten();
        self.size_checks
            .get(index)?
            .get_or_init(|| differential::size_ambiguity(self.store(), index, highest))
            .clone()
    }

    /// [`differential::tail_ambiguity`] of the file, checked once.
    fn tail_check(&self) -> Option<String> {
        self.tail_check
            .get_or_init(|| differential::tail_ambiguity(self.store()))
            .clone()
    }

    /// [`differential::layout_ambiguity`] of revision `index` (`index > 0`), checked once (its
    /// tokens are work of the budget): its bytes run from the end of the revision before it to
    /// its own end, or to the end of the file for the newest revision.
    fn layout_check(&self, index: usize) -> Option<String> {
        let revisions = self.revisions();
        let revision = revisions.get(index)?;
        self.layout_checks
            .get(index)?
            .get_or_init(|| {
                let start = index
                    .checked_sub(1)
                    .and_then(|before| revisions.get(before))
                    .map_or(0, |before| before.eof_end);
                let end = if index + 1 == revisions.len() {
                    self.store().source().len() as u64
                } else {
                    revision.eof_end
                };
                let listed = self.entries.get(index).and_then(Option::as_deref);
                let kept = |num: u32, entry: XrefEntry| {
                    index
                        .checked_sub(1)
                        .is_some_and(|before| self.entry_at(num, before) == Some(entry))
                };
                let checked = differential::layout_ambiguity(
                    self.store(),
                    index,
                    revision,
                    (start, end),
                    listed,
                    &kept,
                );
                self.charged(checked.work, checked.verdict)
            })
            .clone()
    }

    /// `verdict`, after the `tokens` the canonical-input gate read are taken from the work
    /// budget ([`SCAN_TOKENS_PER_WORK`]); the budget note when they do not fit (fail closed).
    fn charged(&self, tokens: u64, verdict: Option<String>) -> Option<String> {
        if self.spend(tokens.div_ceil(SCAN_TOKENS_PER_WORK).max(1)) {
            verdict
        } else {
            Some(
                "the verification's work budget is spent, so the bytes of the objects the \
                 decision reads cannot all be checked (manager ruling R-12)"
                    .to_owned(),
            )
        }
    }

    /// Ruling R-12: why object `num` as revision `rev` (`view`) gives it reads differently in
    /// different readers ([`Revisions::entry_check`]); `None` when it is canonical, or not in use
    /// there (nothing to read).
    fn canonical_at(&self, view: &Store, rev: usize, num: u32) -> Option<String> {
        let entry = self.entry_at(num, rev).filter(in_use)?;
        self.entry_check(view, rev, num, entry)
    }

    /// Why the object `num` that `entry` (in force in revision `r`, `view`) gives reads
    /// differently in different readers (manager rulings R-1 and R-12): an uncompressed
    /// definition that is not canonical ([`canonical::scan_value`]: a duplicate key, a number,
    /// name or string spelling readers read differently), or a compressed object whose container
    /// is ambiguous or whose header position `index` holds another number. Checked once per
    /// number and entry; the tokens read are work of the budget.
    fn entry_check(&self, view: &Store, r: usize, num: u32, entry: XrefEntry) -> Option<String> {
        let container_entry = match entry {
            XrefEntry::InObjStm { stream, .. } => self.entry_at(stream, r),
            _ => None,
        };
        let cache_key = (num, entry, container_entry);
        if let Some(known) = self.entry_checks.borrow().get(&cache_key) {
            return known.clone();
        }
        let verdict = match entry {
            XrefEntry::InFile { r#gen, .. } => {
                let checked = differential::object_ambiguity(view, ObjectId::new(num, r#gen));
                self.charged(checked.work, checked.verdict)
            }
            XrefEntry::InObjStm { stream, index } => match self.container_check(view, r, stream) {
                Err(reason) => Some(reason),
                Ok(members) => {
                    let at = usize::try_from(index).ok().and_then(|i| members.get(i));
                    (at != Some(&num)).then(|| {
                        format!(
                            "the cross-reference entry of object {num} names position \
                                 {index} of object stream {stream}, which holds another object"
                        )
                    })
                }
            },
            _ => None,
        };
        self.entry_checks
            .borrow_mut()
            .insert(cache_key, verdict.clone());
        verdict
    }

    /// [`differential::container_members`] of the object stream `stream` as revision `r`
    /// (`view`) gives it, checked once per container and entry (its tokens are work of the
    /// budget).
    fn container_check(&self, view: &Store, r: usize, stream: u32) -> ContainerCheck {
        let key = (stream, self.entry_at(stream, r));
        if let Some(known) = self.container_checks.borrow().get(&key) {
            return known.clone();
        }
        let checked = differential::container_members(view, stream);
        let members = match self.charged(checked.work, None) {
            Some(reason) => Err(reason),
            None => checked.verdict,
        };
        self.container_checks
            .borrow_mut()
            .insert(key, members.clone());
        members
    }

    /// Manager ruling R-18 (M4 QA round 5, finding 27): why an object stream that revision
    /// `index` writes (a stream its section lists whose `/Type`, read through a reference too,
    /// is `/ObjStm`) holds an object that the same section does not list in it at that index, or
    /// has a header that readers may read differently ([`differential::container_members`]). A
    /// reader that rebuilds the cross-reference data takes every member of every object stream
    /// it finds for that object (PDFium does: QA's member, which no section listed, replaced the
    /// page, 466,059 pixels, after a P = 1 certification Folioxide called `ltaUpdates`), so each
    /// member must be an object of the revision, classified like any other. A classic table
    /// cannot list compressed objects, so a revision written with one adds no non-empty object
    /// stream. Checked once per revision, in that revision's view; `None` when every object
    /// stream it writes is sound.
    fn object_stream_check(&self, index: usize) -> Option<String> {
        self.object_stream_checks
            .get(index)?
            .get_or_init(|| {
                let Some(section) = self.first.get(index) else {
                    return Some(format!("revision {index} is not a revision of the file"));
                };
                let Some(view) = self.view(index) else {
                    return Some(self.unopened(index));
                };
                let view = view.store();
                for (&num, &entry) in section {
                    let XrefEntry::InFile { r#gen, .. } = entry else {
                        continue;
                    };
                    // An object that cannot be read is judged by the comparison.
                    let Ok(value) = view.resolve(ObjectId::new(num, r#gen)) else {
                        continue;
                    };
                    let Object::Stream(stream) = &*value else {
                        continue;
                    };
                    let object_stream = stream
                        .dict
                        .get(b"Type")
                        .and_then(|kind| view.deref(kind).ok())
                        .is_some_and(|kind| kind.is_name(b"ObjStm"));
                    if !object_stream {
                        continue;
                    }
                    if r#gen != 0 {
                        return Some(format!(
                            "revision {index} writes the object stream {num} with generation \
                             {gen}, not 0 (ISO 32000-2 §7.5.7)"
                        ));
                    }
                    let members = match self.container_check(view, index, num) {
                        Ok(members) => members,
                        Err(reason) => return Some(format!("revision {index}: {reason}")),
                    };
                    for (position, &member) in members.iter().enumerate() {
                        let expected =
                            u32::try_from(position)
                                .ok()
                                .map(|position| XrefEntry::InObjStm {
                                    stream: num,
                                    index: position,
                                });
                        if section.get(&member).copied() != expected {
                            return Some(format!(
                                "revision {index} writes the object stream {num}, which holds \
                                 object {member} at index {position}, where its own \
                                 cross-reference section does not list that object: a reader \
                                 that rebuilds the cross-reference data from the bytes takes it \
                                 for the object (manager ruling R-18)"
                            ));
                        }
                    }
                }
                None
            })
            .clone()
    }

    /// Manager ruling R-13 (M4 QA round 3, finding 11): the effective `/Rotate` of `page` in
    /// revision `r` (`view`, whose catalog is `catalog`), when every reader finds the page and
    /// its inherited attributes the same way ([`PageWalk::path`]: reached once by the `/Kids`
    /// walk, its `/Parent` chain the reverse of that walk) and every page-tree object consulted is
    /// canonical (ruling R-12 (3)); `Err` with the reason otherwise (fail closed). The rotation
    /// is the page's own `/Rotate`, else the nearest ancestor's (§7.7.3.3, §7.7.3.4), and must be
    /// a direct integer (poppler ignores a real or a reference, PDFium converts it). The tree is
    /// walked once per revision; the objects visited are work of the budget.
    fn page_rotation(
        &self,
        view: &Store,
        catalog: Option<&Dict>,
        r: usize,
        page: ObjectId,
    ) -> std::result::Result<i64, String> {
        let walk = self
            .page_walks
            .get(r)
            .ok_or_else(|| format!("revision {r} is not a revision of the file"))?
            .get_or_init(|| {
                let max_depth = usize::from(view.limits().max_page_tree_depth);
                let (walk, steps) =
                    PageWalk::read(view, catalog, max_depth, self.work_left.get().max(1));
                if self.spend(steps) {
                    walk
                } else {
                    PageWalk {
                        problem: Some(self.budget_spent(r)),
                        ..PageWalk::default()
                    }
                }
            });
        let (chain, consulted) = walk.path(page)?;
        for num in consulted {
            if let Some(reason) = self.canonical_at(view, r, num) {
                return Err(reason);
            }
        }
        for node in chain {
            let value = view
                .resolve(node)
                .map_err(|_| format!("the page-tree object {node} cannot be read"))?;
            match value.as_dict().and_then(|d| d.get(b"Rotate")) {
                None => {}
                Some(Object::Int(degrees)) => return Ok(*degrees),
                Some(_) => {
                    return Err(format!(
                        "the /Rotate of the page-tree object {node} is not a direct integer, \
                         which readers read differently (poppler ignores it, PDFium converts it)"
                    ));
                }
            }
        }
        Ok(0)
    }

    /// What revision `r` (`view`) holds for the "role still in force" rules: the fields its
    /// field tree reaches and the annotations its pages list; `None` when they cannot all be
    /// read within the limits. Computed once per revision; the objects visited are work.
    fn presence_at(&self, view: &Document, r: usize) -> Option<&Presence> {
        self.presence
            .get(r)?
            .get_or_init(|| {
                let presence = Presence::read(view)?;
                let work = presence.fields.len() + presence.annotations.len();
                self.spend(work as u64).then_some(presence)
            })
            .as_ref()
    }
}

/// What a revision's field tree and pages hold (M4 brief §5.1 F0, §5.2 A5).
struct Presence {
    /// The fields (indirect) the field tree reaches from `/AcroForm /Fields`.
    fields: BTreeSet<u32>,
    /// The annotations (indirect) every page's `/Annots` lists.
    annotations: BTreeSet<u32>,
}

impl Presence {
    /// Reads `doc`'s field tree and pages; `None` when either cannot be read in full.
    fn read(doc: &Document) -> Option<Presence> {
        let store = doc.store();
        let catalog = doc.catalog().ok()?;
        let mut fields = BTreeSet::new();
        if let Some(acroform) = field::acroform_of(store, catalog.as_dict()).ok()? {
            let (nodes, truncated) = field::walk_fields_bounded(store, &acroform.dict).ok()?;
            if truncated {
                return None;
            }
            fields.extend(nodes.iter().filter_map(|n| n.id).map(|id| id.num));
        }
        let mut annotations = BTreeSet::new();
        for page in doc.page_ids().ok()? {
            let value = store.resolve(page.0).ok()?;
            let Some(annots) = value.as_dict()?.get(b"Annots") else {
                continue;
            };
            let annots = store.deref(annots).ok()?;
            match &*annots {
                Object::Array(items) => {
                    if annotations.len().saturating_add(items.len()) > MAX_SIGNED_ANNOTATIONS {
                        return None;
                    }
                    annotations.extend(items.iter().filter_map(Object::as_ref).map(|id| id.num));
                }
                Object::Null => {}
                _ => return None,
            }
        }
        Some(Presence {
            fields,
            annotations,
        })
    }
}

/// An object of the signed revision that a later revision changed: its values then and now.
struct Changed {
    id: ObjectId,
    old: Arc<Object>,
    new: Arc<Object>,
}

/// The new objects a comparison explains, each at the lowest level a rule gives it (pyHanko
/// collects explained references per level and checks the lowest first), with the class of the
/// change that explains it at that level.
#[derive(Default)]
struct Explained(BTreeMap<u32, (ModificationLevel, ChangeClass)>);

impl Explained {
    fn add(&mut self, num: u32, level: ModificationLevel, class: ChangeClass) {
        let entry = self.0.entry(num).or_insert((level, class));
        if level < entry.0 {
            *entry = (level, class);
        }
    }

    fn get(&self, num: u32) -> Option<(ModificationLevel, ChangeClass)> {
        self.0.get(&num).copied()
    }
}

/// The keys of a new annotation that refer to other annotations, judged as annotations of their
/// own (brief §5.2 A4, A5) rather than as what the annotation holds.
const ANNOTATION_LINKS: &[&[u8]] = &[b"Popup", b"IRT", b"Parent", b"P"];

/// The context of one comparison of the signed revision `k` with a later revision `r`.
struct Cx<'a, 'd> {
    revisions: &'a Revisions<'d>,
    /// The view of revision `k`.
    old: &'a Store,
    /// The view of revision `r`.
    new: &'a Store,
    k: usize,
    r: usize,
    /// The evaluated signature.
    ctx: ModificationContext,
    /// The objects new since `k`, as revision `r` shows them.
    new_values: &'a BTreeMap<u32, Rc<Fact>>,
    /// What the new objects are.
    kinds: &'a BTreeMap<u32, NewKind>,
    /// The catalog of revision `r`.
    new_catalog: Option<&'a Dict>,
    /// The revisions `k+1..=r` that add a document timestamp: the bookkeeping edits written in
    /// them are part of it ([`Cx::written_with_timestamp`]).
    dts_revisions: BTreeSet<usize>,
    /// The document as of revision `r`.
    new_doc: &'a Document,
    /// The new objects whose dependencies are explained already, per level and class
    /// ([`Cx::explain_dependencies`]).
    walked: RefCell<HashMap<(ModificationLevel, ChangeClass), HashSet<u32>>>,
}

impl Cx<'_, '_> {
    /// Whether the newest write of object `num` in the revisions `k+1..=r` is in a revision that
    /// adds a document timestamp (manager ruling R-8: the bookkeeping exemptions hold only for
    /// what the timestamp's own revision writes, and only while no later revision rewrites it).
    fn written_with_timestamp(&self, num: u32) -> bool {
        self.revisions
            .last_listing_upto(num, self.r)
            .is_some_and(|rev| rev > self.k && self.dts_revisions.contains(&rev))
    }

    /// Whether `id` is a new object (not in use in the signed revision).
    fn is_new(&self, id: ObjectId) -> bool {
        self.new_values.contains_key(&id.num)
    }

    /// Explains at `level`, with `class`, the new objects `value` reaches through new objects
    /// (pyHanko's `collect_dependencies(since_revision=k+1)`). A new object is walked once per
    /// `(level, class)` in the comparison: its dependencies were explained with it, so the many
    /// annotations, fields or appearances that share new objects (a font, an appearance stream)
    /// cost the shared objects once (M4 QA round 2, finding 1: linear by construction).
    fn explain_dependencies(
        &self,
        value: &Object,
        level: ModificationLevel,
        class: ChangeClass,
        explained: &mut Explained,
    ) {
        let mut walked = self.walked.borrow_mut();
        let seen = walked.entry((level, class)).or_default();
        let mut queue: Vec<u32> = references_of(value)
            .into_iter()
            .filter(|n| self.new_values.contains_key(n) && !seen.contains(n))
            .collect();
        while let Some(num) = queue.pop() {
            if !seen.insert(num) {
                continue;
            }
            explained.add(num, level, class);
            if let Some(held) = self.new_values.get(&num) {
                queue.extend(
                    held.refs
                        .iter()
                        .copied()
                        .filter(|n| self.new_values.contains_key(n) && !seen.contains(n)),
                );
            }
        }
    }

    /// The new objects the new trailer or a changed object reaches through new objects; the
    /// others are orphans (pyHanko's `_find_orphans`).
    fn reachable_new(&self, trailer: &Dict, changed: &[Changed]) -> BTreeSet<u32> {
        let mut queue: Vec<u32> = trailer.values().flat_map(references_of).collect();
        for change in changed {
            queue.extend(references_of(&change.new));
        }
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        while let Some(num) = queue.pop() {
            let Some(fact) = self.new_values.get(&num) else {
                continue;
            };
            if seen.insert(num) {
                queue.extend(fact.refs.iter().copied());
            }
        }
        seen
    }

    /// pyHanko's `DocInfoRule` (`safe_whitelist`), on every comparison: `/Info` is never a
    /// stream; it may stay, or point to a new object (explained, `LtaUpdates`).
    fn info_rule(&self, explained: &mut Explained, diff: &mut Diff) {
        let r = self.r;
        let old_info = self.old.trailer().get_ref(b"Info");
        if let Some(id) = old_info
            && is_stream(self.old, id)
        {
            diff.other(format!(
                "the signed revision's trailer /Info is the stream {id}"
            ));
        }
        match self.new.trailer().get_ref(b"Info") {
            None => {}
            Some(id) if Some(id) == old_info => {
                if is_stream(self.new, id) {
                    diff.other(format!("revision {r}'s trailer /Info is the stream {id}"));
                }
            }
            Some(id) if self.is_new(id) => {
                let old_dict = old_info
                    .and_then(|old| self.old.resolve(old).ok())
                    .and_then(|old| old.as_dict().cloned())
                    .unwrap_or_default();
                let new_dict = self
                    .new_values
                    .get(&id.num)
                    .and_then(|fact| fact.value.as_dict().cloned())
                    .unwrap_or_default();
                explained.add(
                    id.num,
                    ModificationLevel::LtaUpdates,
                    self.info_class(id.num, &old_dict, &new_dict),
                );
            }
            Some(id) => diff.other(format!(
                "revision {r} points the trailer's /Info to the existing object {id}"
            )),
        }
    }

    /// The class of an `/Info` change from `old` to `new` (object `num`): the timestamp's own
    /// bookkeeping when the revision that adds a document timestamp wrote it
    /// ([`Cx::written_with_timestamp`]) and only `/ModDate` and `/Producer` changed (pyHanko's
    /// timestamper writes them), else [`ChangeClass::Metadata`].
    fn info_class(&self, num: u32, old: &Dict, new: &Dict) -> ChangeClass {
        let bookkeeping = Rules::changed_keys(old, new)
            .iter()
            .all(|key| *key == b"ModDate" || *key == b"Producer");
        if bookkeeping && self.written_with_timestamp(num) {
            ChangeClass::DocTimeStamp
        } else {
            ChangeClass::Metadata
        }
    }

    /// The class of an in-place change of the XMP metadata stream `num` from `old` to `new`: the
    /// timestamp's own bookkeeping when the revision that adds a document timestamp wrote it
    /// ([`Cx::written_with_timestamp`]), the stream
    /// dictionaries differ at most in `/Length`, and the decoded packets differ only in the
    /// values of the attributes `xmp:ModifyDate` and `pdf:Producer` ([`xmp_without_bookkeeping`]:
    /// the XMP twins of the `/Info` `/ModDate` and `/Producer` of [`Cx::info_class`], ISO 32000-2
    /// §14.3.2; pyHanko's timestamper rewrites exactly these, probed on
    /// `pyhanko-certified-p1-dts.pdf`), else [`ChangeClass::Metadata`]. Each packet is decoded
    /// again within the verification's XMP budget.
    fn xmp_class(&self, num: u32, old: &Object, new: &Object) -> ChangeClass {
        let bookkeeping = self.written_with_timestamp(num)
            && match (old, new) {
                (Object::Stream(old), Object::Stream(new)) => {
                    Rules::changed_keys(&old.dict, &new.dict)
                        .iter()
                        .all(|key| *key == b"Length")
                        && match (
                            self.revisions.xmp_data(self.old, old),
                            self.revisions.xmp_data(self.new, new),
                        ) {
                            (Some(old), Some(new)) => {
                                xmp_without_bookkeeping(&old).is_some_and(|masked| {
                                    xmp_without_bookkeeping(&new) == Some(masked)
                                })
                            }
                            _ => false,
                        }
                }
                _ => false,
            };
        if bookkeeping {
            ChangeClass::DocTimeStamp
        } else {
            ChangeClass::Metadata
        }
    }

    /// The class of a catalog `/Extensions` change from `old` to `new` (direct or indirect
    /// dictionaries; `num` the object written: the catalog, or the indirect dictionary): the
    /// timestamp's own when the revision that adds a document timestamp wrote it
    /// ([`Cx::written_with_timestamp`]) and the only change is a new `/ESIC` developer extension
    /// (ISO 32000-2 §7.12; ETSI's PAdES extension, which pyHanko's timestamper declares), else
    /// [`ChangeClass::Metadata`].
    fn extensions_class(
        &self,
        num: u32,
        old: Option<&Object>,
        new: Option<&Object>,
    ) -> ChangeClass {
        let read = |store: &Store, value: Option<&Object>| -> Option<Dict> {
            match value {
                None => Some(Dict::new()),
                Some(value) => store.deref(value).ok().and_then(|v| v.as_dict().cloned()),
            }
        };
        let esic_only = match (read(self.old, old), read(self.new, new)) {
            (Some(old), Some(new)) => {
                let changed = Rules::changed_keys(&old, &new);
                changed == [b"ESIC".as_slice()]
                    && !old.contains_key(b"ESIC")
                    && new
                        .get(b"ESIC")
                        .and_then(|esic| self.new.deref(esic).ok())
                        .and_then(|esic| esic.as_dict().cloned())
                        .is_some_and(|esic| {
                            esic.keys().all(|key| {
                                matches!(
                                    key.as_bytes(),
                                    b"Type" | b"BaseVersion" | b"ExtensionLevel" | b"URL"
                                )
                            })
                        })
            }
            _ => false,
        };
        if esic_only && self.written_with_timestamp(num) {
            ChangeClass::DocTimeStamp
        } else {
            ChangeClass::Metadata
        }
    }

    /// The class of a new signature field `num`: a new visible field is a signature's; an
    /// invisible one whose `/V` is a new document timestamp is the timestamp's; any other
    /// invisible one is [`ChangeClass::SignatureField`].
    fn sig_field_class(&self, num: u32) -> ChangeClass {
        match self.kinds.get(&num) {
            Some(NewKind::SigField { visible: true, .. }) => ChangeClass::Signature,
            Some(NewKind::SigField { .. }) => {
                let value = self
                    .new_values
                    .get(&num)
                    .and_then(|fact| fact.value.as_dict().and_then(|d| d.get_ref(b"V")));
                match value.and_then(|v| self.kinds.get(&v.num)) {
                    Some(NewKind::SigDict { timestamp: true }) => ChangeClass::DocTimeStamp,
                    _ => ChangeClass::SignatureField,
                }
            }
            _ => ChangeClass::Signature,
        }
    }

    /// The catalog keys pyHanko checks on every comparison: `/Extensions` and `/MarkInfo`
    /// (`compare_key_refs`: kept, never a stream, a new object explained), `/Metadata`
    /// (`MetadataUpdateRule`: an indirect XMP stream in both revisions, a new one explained) and
    /// a new AcroForm with its new `/Fields` and `/DR` (`FormUpdatingRule`).
    fn catalog_reference_rules(
        &self,
        old_catalog: &Dict,
        new_catalog: &Dict,
        explained: &mut Explained,
        diff: &mut Diff,
    ) {
        let r = self.r;
        for key in [b"Extensions".as_slice(), b"MarkInfo"] {
            let name = String::from_utf8_lossy(key);
            let old_ref = old_catalog.get_ref(key);
            if let Some(id) = old_ref
                && is_stream(self.old, id)
            {
                diff.other(format!(
                    "the signed revision's catalog /{name} is the stream {id}"
                ));
            }
            match new_catalog.get(key) {
                None if old_catalog.contains_key(key) => {
                    diff.other(format!("revision {r} removes the catalog's /{name}"));
                }
                Some(Object::Ref(id)) if Some(*id) == old_ref => {
                    if is_stream(self.new, *id) {
                        diff.other(format!("revision {r}'s catalog /{name} is the stream {id}"));
                    }
                }
                Some(Object::Ref(id)) if self.is_new(*id) => {
                    let class = if key == b"Extensions" {
                        self.extensions_class(id.num, old_catalog.get(key), new_catalog.get(key))
                    } else {
                        ChangeClass::Metadata
                    };
                    explained.add(id.num, ModificationLevel::LtaUpdates, class);
                }
                Some(Object::Ref(id)) => diff.other(format!(
                    "revision {r} points the catalog's /{name} to the existing object {id}"
                )),
                _ => {}
            }
        }

        match new_catalog.get(b"Metadata") {
            None => {}
            Some(Object::Ref(id)) => {
                if !self.revisions.is_xmp(self.new, r, *id) {
                    diff.other(format!(
                        "revision {r}'s /Metadata {id} is not an XMP stream (or is larger than \
                         {MAX_XMP_BYTES} bytes)"
                    ));
                }
                match old_catalog.get(b"Metadata") {
                    None => {}
                    Some(Object::Ref(old_id)) => {
                        if !self.revisions.is_xmp(self.old, self.k, *old_id) {
                            diff.other(format!(
                                "the signed revision's /Metadata {old_id} is not an XMP stream"
                            ));
                        }
                    }
                    Some(_) => diff.other(
                        "the signed revision's /Metadata is not an indirect reference".to_owned(),
                    ),
                }
                if self.is_new(*id) {
                    explained.add(id.num, ModificationLevel::LtaUpdates, ChangeClass::Metadata);
                }
            }
            Some(_) => diff.other(format!(
                "revision {r}'s /Metadata is not an indirect reference"
            )),
        }

        // A new AcroForm object, a new /Fields array and a new /DR (pyHanko's FormUpdatingRule;
        // whether the AcroForm may change at all is the catalog's and the AcroForm's rule).
        let acroform_ref = new_catalog.get_ref(b"AcroForm");
        if let Some(id) = acroform_ref.filter(|id| self.is_new(*id)) {
            explained.add(
                id.num,
                ModificationLevel::LtaUpdates,
                ChangeClass::SignatureField,
            );
        }
        let acroform = match new_catalog.get(b"AcroForm") {
            Some(value) => self
                .new
                .deref(value)
                .ok()
                .and_then(|v| v.as_dict().cloned()),
            None => None,
        };
        if let Some(acroform) = acroform {
            if let Some(id) = acroform.get_ref(b"Fields").filter(|id| self.is_new(*id)) {
                explained.add(
                    id.num,
                    ModificationLevel::LtaUpdates,
                    ChangeClass::SignatureField,
                );
            }
            if let Some(dr) = acroform.get(b"DR") {
                self.explain_dependencies(
                    dr,
                    ModificationLevel::FormFilling,
                    ChangeClass::DefaultResources,
                    explained,
                );
            }
        }
    }

    /// The `/TransformParams` dictionaries of a new signature dictionary's direct `/Reference`
    /// entries (pyHanko whitelists them with the signature), with the signature's `class`.
    fn explain_transform_params(
        &self,
        sig: &Object,
        class: ChangeClass,
        explained: &mut Explained,
    ) {
        let references = sig
            .as_dict()
            .and_then(|d| d.get_array(b"Reference"))
            .unwrap_or_default();
        for reference in references {
            if let Some(id) = reference
                .as_dict()
                .and_then(|d| d.get_ref(b"TransformParams"))
                .filter(|id| self.is_new(*id))
            {
                let level = if class == ChangeClass::DocTimeStamp {
                    ModificationLevel::LtaUpdates
                } else {
                    ModificationLevel::FormFilling
                };
                explained.add(id.num, level, class);
            }
        }
    }
}

/// What a comparison knows about an object as a later revision shows it.
struct Fact {
    /// Its value.
    value: Arc<Object>,
    /// What it is, before the comparison's own checks (a cross-reference stream, registration,
    /// signing).
    kind: NewKind,
    /// The numbers it refers to.
    refs: Vec<u32>,
    /// Where it is, when uncompressed.
    position: Option<u64>,
}

/// The root-level fields of a revision's `/AcroForm /Fields`: their numbers and how many root
/// fields share each one's `/T`.
#[derive(Default)]
struct RootFields {
    /// Field number to its partial name (`None` without a string `/T`).
    names: BTreeMap<u32, Option<Vec<u8>>>,
    /// How many root fields have each partial name.
    counts: BTreeMap<Vec<u8>, usize>,
}

impl RootFields {
    fn contains_key(&self, num: &u32) -> bool {
        self.names.contains_key(num)
    }

    /// Whether no other root field has the partial name of field `num` (pyHanko refuses
    /// duplicate names).
    fn is_unique(&self, num: u32) -> bool {
        match self.names.get(&num) {
            Some(Some(name)) => self.counts.get(name).copied().unwrap_or(0) <= 1,
            _ => true,
        }
    }
}

/// The root-level fields of the `/AcroForm /Fields` of `catalog` in `store` (references only).
fn root_field_names(store: &Store, catalog: Option<&Dict>) -> RootFields {
    let mut out = RootFields {
        names: BTreeMap::new(),
        counts: BTreeMap::new(),
    };
    let Ok(Some(acroform)) = field::acroform_of(store, catalog) else {
        return out;
    };
    let fields = match acroform.dict.get(b"Fields") {
        Some(value) => store
            .deref(value)
            .ok()
            .and_then(|v| v.as_array().map(<[Object]>::to_vec)),
        None => None,
    };
    for item in fields.unwrap_or_default() {
        let Some(id) = item.as_ref() else {
            continue;
        };
        let name = store.resolve(id).ok().and_then(|f| {
            f.as_dict()
                .and_then(|d| d.get_str_bytes(b"T"))
                .map(<[u8]>::to_vec)
        });
        if let Some(name) = &name {
            *out.counts.entry(name.clone()).or_default() += 1;
        }
        out.names.insert(id.num, name);
    }
    out
}

/// Where an object of the signed revision is used: the object that refers to it (or the
/// trailer), and the path of keys and indices inside that object.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Usage {
    from: Referrer,
    path: Vec<Step>,
    /// The reference is the `/Obj` of an object reference dictionary (`/Type /OBJR`, §14.7.5.3):
    /// a structure tree's pointer to an annotation (M4 brief D-24).
    objr: bool,
}

/// What refers to an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Referrer {
    Trailer,
    Object(u32),
}

/// One step of a path inside an object.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Step {
    Key(Vec<u8>),
    Index(usize),
}

impl Step {
    fn is_key(&self, key: &[u8]) -> bool {
        matches!(self, Step::Key(k) if k.as_slice() == key)
    }
}

/// What the analyses know about the signed revision `k`.
struct Base {
    /// Every number a section `0..=k` lists.
    listed: BTreeSet<u32>,
    /// Object stream containers in use at `k`.
    containers: BTreeSet<u32>,
    /// Numbers not in use at `k` that an object (or the trailer) of revision `k` refers to.
    dangling: BTreeSet<u32>,
    /// The catalog.
    root: Option<u32>,
    /// The indirect AcroForm.
    acroform: Option<u32>,
    /// The indirect `/Fields` array.
    fields_array: Option<u32>,
    /// The field objects: (signature field, signed, terminal).
    fields: BTreeMap<u32, (bool, bool, bool)>,
    /// The indirect `/Kids` arrays of fields, with the field whose `/Kids` each is.
    kids_arrays: BTreeMap<u32, u32>,
    /// The signed revision's AcroForm has `/XFA` (M4 brief §5.1 F0, D-23).
    xfa: bool,
    /// The form roles of the generic form-filling rules (M4 brief §5.1).
    form: FormRoles,
    /// The structure tree's `/K` links, for the `/OBJR` contexts of widgets (D-24).
    struct_tree: StructTree,
    /// The page objects.
    pages: BTreeSet<u32>,
    /// The indirect `/Annots` arrays of pages, each with the pages whose `/Annots` it is.
    annots_arrays: BTreeMap<u32, Vec<ObjectId>>,
    /// The trailer's `/Info` dictionary.
    info: Option<u32>,
    /// The catalog's `/Metadata` stream.
    metadata: Option<u32>,
    /// The catalog's indirect `/Extensions` dictionary.
    extensions: Option<u32>,
    /// The catalog's indirect `/MarkInfo` dictionary.
    mark_info: Option<u32>,
    /// The names the signed revision already takes, or may take, from the AcroForm's `/DR`
    /// ([`SignedNames`]).
    signed_names: BTreeSet<Vec<u8>>,
    /// Whether [`Base::signed_names`] is complete (not when the field tree, the pages, the
    /// strings or the appearance streams exceed the limits or cannot be read).
    signed_names_complete: bool,
    /// The indirect objects of the signed revision [`Base::signed_names`] was read from (the
    /// AcroForm, the field tree, the pages, their annotations, appearances and resources): a new
    /// `/DR` name is allowed only while every one of them reads the same in every reader
    /// (manager ruling R-12 (2)).
    signed_name_objects: Vec<u32>,
    /// Where the objects with a role that later revisions list are used in revision `k`.
    usages: BTreeMap<u32, Vec<Usage>>,
    /// Those used more than [`MAX_USAGES`] times.
    crowded: BTreeSet<u32>,
    /// Why [`Base::usages`] may miss a use another reader sees: the first object of revision
    /// `k` the index read that is not canonical (manager ruling R-12 (2); a key written twice
    /// hides from Folioxide's last-wins parser a reference that a first-wins reader follows).
    usage_defect: Option<String>,
    /// Manager ruling R-19 (M4 QA round 5, finding 7; closing round, finding 10): why the signed
    /// revision has a non-signature field node, terminal or not, whose `/AP` is an indirect
    /// dictionary used in more or fewer than one context (counted as raw references, so a
    /// first-wins carrier counts), which makes every later revision `Other`
    /// ([`Base::appearance_use_problem`]).
    shared_appearance: Option<String>,
    /// M4 final fix round 2, finding 1 (ruling R-19 for signature fields): the terminal unsigned
    /// signature fields of the signed revision whose `/AP` is an indirect dictionary used in more
    /// or fewer than one context, each with why. A later revision that signs one is `Other`:
    /// pyHanko's `SigFieldModificationRule` runs `_allow_appearance_update` for a field that
    /// goes from unsigned to signed, and refuses its old `/AP` dictionary when that is shared.
    shared_sig_appearances: BTreeMap<u32, String>,
}

impl Base {
    fn new(revisions: &Revisions<'_>, old: &Document, k: usize) -> Base {
        let store = old.store();
        let mut listed = BTreeSet::new();
        let mut containers = BTreeSet::new();
        for map in revisions.first.get(..=k).unwrap_or_default() {
            listed.extend(map.keys().copied());
        }
        for listing in revisions
            .entries
            .get(..=k)
            .unwrap_or_default()
            .iter()
            .flatten()
        {
            for (_, entry) in listing {
                if let XrefEntry::InObjStm { stream, .. } = entry {
                    containers.insert(*stream);
                }
            }
        }
        let in_use_at_k = |num: u32| revisions.entry_at(num, k).is_some_and(|e| in_use(&e));

        let catalog = old.catalog().ok();
        let catalog_dict = catalog.as_deref().and_then(Object::as_dict);
        let root = store.root_id().map(|id| id.num);
        let acroform_ref = catalog_dict.and_then(|c| c.get_ref(b"AcroForm"));
        let acroform = field::acroform_of(store, catalog_dict).ok().flatten();
        let fields_array = acroform
            .as_ref()
            .and_then(|a| a.dict.get_ref(b"Fields"))
            .map(|id| id.num);
        let mut fields = BTreeMap::new();
        let mut kids_arrays = BTreeMap::new();
        let mut form = FormRoles::default();
        let xfa = acroform
            .as_ref()
            .is_some_and(|acroform| acroform.dict.contains_key(b"XFA"));
        let mut signed_names = SignedNames::default();
        // Ruling R-19: the indirect /AP dictionaries of the non-signature field nodes, terminal
        // or not, with their field (pyHanko's GenericFieldModificationRule reads the field's own
        // /AP); and those of the terminal unsigned signature fields (finding 1 of the final fix
        // round 2: pyHanko's SigFieldModificationRule reads them when the field becomes signed).
        let mut field_appearances: BTreeMap<u32, u32> = BTreeMap::new();
        // (field, dictionary): two fields may share one.
        let mut sig_appearances: BTreeMap<u32, u32> = BTreeMap::new();
        let decoded = &revisions.appearance_decoded;
        if let Some(acroform) = &acroform {
            signed_names.add_da(store, &acroform.dict);
            let nodes = match field::walk_fields_bounded(store, &acroform.dict) {
                Ok((nodes, truncated)) => {
                    // Fields the walk did not reach have default appearance strings too.
                    signed_names.complete &= !truncated;
                    nodes
                }
                Err(_) => {
                    signed_names.complete = false;
                    Vec::new()
                }
            };
            form = FormRoles::read(store, &nodes);
            signed_names
                .objects
                .extend(acroform_ref.iter().map(|id| id.num));
            for node in nodes {
                if let Some(id) = node.id {
                    signed_names.objects.insert(id.num);
                }
                if node.terminal {
                    // The field, merged with its widget, or its widget kids.
                    signed_names.add_annotation(store, &node.dict, decoded);
                    signed_names.add_kids(store, &node.dict, decoded);
                } else {
                    signed_names.add_da(store, &node.dict);
                }
                if let (Some(kids), Some(id)) = (node.dict.get_ref(b"Kids"), node.id) {
                    kids_arrays.insert(kids.num, id.num);
                }
                if let Some(id) = node.id {
                    // Signed: a /V that is not null. The signature dictionary is shared with the
                    // document store rather than parsed again in this view.
                    let signed = match node.dict.get(b"V") {
                        None | Some(Object::Null) => false,
                        Some(Object::Ref(value)) => revisions
                            .value_at(store, k, *value)
                            .is_ok_and(|v| !v.is_null()),
                        Some(_) => true,
                    };
                    fields.insert(id.num, (node.is_signature(), signed, node.terminal));
                    // Closing round, finding 10: pyHanko's `_list_fields` yields every named
                    // field node, a non-terminal parent included, and GenericFieldModificationRule
                    // checks the /AP of each; Folioxide checks every node of the walk (the
                    // unnamed roots of /Fields too, the stricter side). A signature node that is
                    // not terminal cannot be signed below `Other` (any change to it is `Other`),
                    // so only terminal ones are kept for the signing rule.
                    if let Some(Object::Ref(ap)) = node.dict.get(b"AP")
                        && store
                            .resolve(*ap)
                            .is_ok_and(|value| value.as_dict().is_some())
                    {
                        if !node.is_signature() {
                            field_appearances.insert(ap.num, id.num);
                        } else if !signed && node.terminal {
                            sig_appearances.insert(id.num, ap.num);
                        }
                    }
                }
            }
        }
        let mut pages = BTreeSet::new();
        let mut annots_arrays: BTreeMap<u32, Vec<ObjectId>> = BTreeMap::new();
        let page_ids = old.page_ids();
        // Pages the walk cannot list have annotations too.
        signed_names.complete &= page_ids.is_ok();
        for page in page_ids.unwrap_or_default() {
            pages.insert(page.0.num);
            signed_names.objects.insert(page.0.num);
            let Ok(value) = store.resolve(page.0) else {
                signed_names.complete = false;
                continue;
            };
            let Some(dict) = value.as_dict() else {
                signed_names.complete = false;
                continue;
            };
            if let Some(annots) = dict.get_ref(b"Annots") {
                let owners = annots_arrays.entry(annots.num).or_default();
                owners.push(page.0);
                if owners.len() > 1 {
                    continue; // its annotations are read already
                }
            }
            // Every annotation on the page, whether or not the field tree lists it (expert
            // finding: an orphan text widget's /DA).
            signed_names.add_page_annotations(store, dict.get(b"Annots"), decoded);
        }
        // M4 QA round 4, finding 12: a signed stream without resources of its own (or, round 5
        // finding 29, without every category) draws what the page's resources name, so those
        // are read too, each page's or node's once: along every page's /Parent chain (PDFium)
        // and along the /Kids walk from the catalog's /Pages (poppler).
        if signed_names.bare {
            for page in old.page_ids().unwrap_or_default() {
                if let Ok(value) = store.resolve(page.0)
                    && let Some(dict) = value.as_dict()
                {
                    signed_names.add_page_resources(store, page.0, dict, decoded);
                }
            }
            let max_depth = usize::from(store.limits().max_page_tree_depth);
            let (walk, steps) = PageWalk::read(
                store,
                catalog_dict,
                max_depth,
                revisions.work_left.get().max(1),
            );
            if revisions.spend(steps) {
                signed_names.add_tree_resources(store, &walk, decoded);
            } else {
                signed_names.complete = false;
            }
        }
        // The annotations visited are work of the verification's budget (R-18).
        if !revisions.spend(signed_names.annotations as u64) {
            signed_names.complete = false;
        }
        let info = store.trailer().get_ref(b"Info").map(|id| id.num);
        let catalog_ref = |key: &[u8]| catalog_dict.and_then(|c| c.get_ref(key)).map(|id| id.num);
        let metadata = catalog_ref(b"Metadata");
        let extensions = catalog_ref(b"Extensions");
        let mark_info = catalog_ref(b"MarkInfo");

        // The references of revision k: the newest value of the objects no later revision
        // changed (it is their value at k), the old value of those that did change.
        let changed_later: BTreeSet<u32> = revisions
            .entries
            .iter()
            .skip(k + 1)
            .flatten()
            .flatten()
            .map(|(num, _)| *num)
            .collect();
        let mut old_values: BTreeMap<u32, Arc<Object>> = BTreeMap::new();
        for &num in &changed_later {
            if let Some(entry) = revisions.entry_at(num, k).filter(in_use)
                && let Ok(value) = store.resolve(ObjectId::new(num, entry_gen(&entry)))
            {
                old_values.insert(num, value);
            }
        }
        let newest = revisions.references();
        let old_refs: BTreeMap<u32, Vec<u32>> = old_values
            .iter()
            .map(|(&num, value)| (num, references_of(value)))
            .collect();
        let refs_at_k = |num: u32| -> &[u32] {
            if changed_later.contains(&num) {
                old_refs.get(&num).map(Vec::as_slice).unwrap_or_default()
            } else {
                newest.get(&num).map(Vec::as_slice).unwrap_or_default()
            }
        };

        // Dangling references: from every object of revision k and from the trailer.
        let trailer = Object::Dict(store.trailer().clone());
        let trailer_refs = references_of(&trailer);
        let mut targets: BTreeSet<u32> = trailer_refs.iter().copied().collect();
        for (referrer, refs) in newest {
            if !changed_later.contains(referrer) {
                targets.extend(refs.iter().copied());
            }
        }
        for refs in old_refs.values() {
            targets.extend(refs.iter().copied());
        }
        let dangling = targets
            .into_iter()
            .filter(|&t| t != 0 && !in_use_at_k(t))
            .collect();

        // The uses of the objects whose role a later change may claim (pyHanko clears an
        // overridden reference only when every path to it in the signed revision is approved).
        let mut watched: BTreeSet<u32> = [info, metadata, extensions, mark_info, fields_array]
            .into_iter()
            .flatten()
            .chain(acroform_ref.map(|id| id.num))
            .chain(annots_arrays.keys().copied())
            .chain(
                fields
                    .iter()
                    .filter(|(_, (signature, signed, terminal))| *signature && !signed && *terminal)
                    .map(|(&num, _)| num),
            )
            .chain(form.fields.keys().copied())
            .chain(form.ap_dicts.keys().copied())
            .chain(form.ap_streams.keys().copied())
            .collect();
        watched.retain(|num| changed_later.contains(num));
        // Ruling R-19: a field's indirect appearance dictionary is watched whether or not a
        // later revision changes it (pyHanko checks it for every field present in both).
        watched.extend(field_appearances.keys().copied());
        watched.extend(sig_appearances.values().copied());
        let mut usages: BTreeMap<u32, Vec<Usage>> = BTreeMap::new();
        let mut crowded = BTreeSet::new();
        let mut usage_defect = None;
        // The watched objects a non-canonical object's raw bytes may refer to where Folioxide's
        // reading does not (`None` for an object whose references cannot be known).
        let mut hidden_uses: Option<BTreeSet<u32>> = Some(BTreeSet::new());
        let field_tree: BTreeSet<u32> = fields.keys().copied().collect();
        if !watched.is_empty() {
            // Reachable from the trailer in revision k, in every reader. Ruling R-12 (2): the
            // index reads every reachable object, and a use that another reader finds where
            // Folioxide's parser does not (the first of two values of a key written twice, a
            // reference spelled with signs or out of range) would be a use the index misses.
            // Each object is checked once per entry (charged to the work budget). From one that
            // is not canonical the walk follows its raw references too (every value of every
            // key), so an object that only another reader reaches through it (a first-wins
            // carrier, one hop or more away: M4 QA round 4, finding 1) is read and its uses are
            // recorded like any other; the walk stays one visit per object.
            let mut reachable: BTreeSet<u32> = BTreeSet::new();
            let mut not_canonical: BTreeMap<u32, (String, Option<Vec<u32>>)> = BTreeMap::new();
            let mut queue: Vec<u32> = trailer_refs;
            while let Some(num) = queue.pop() {
                if num == 0 || !in_use_at_k(num) || !reachable.insert(num) {
                    continue;
                }
                queue.extend(refs_at_k(num).iter().copied());
                if let Some(reason) = revisions.canonical_at(store, k, num) {
                    let raw = revisions
                        .entry_at(num, k)
                        .and_then(|entry| differential::raw_references(store, num, entry));
                    if let Some(raw) = &raw {
                        queue.extend(raw.iter().copied());
                    }
                    not_canonical.insert(num, (reason, raw));
                }
            }
            // A non-canonical object counts when its raw bytes may refer to an object the index
            // watches that Folioxide's reading of it does not refer to, or when which objects
            // they refer to cannot be known (a reference whose numbers are not canonical).
            usage_defect = not_canonical.iter().find_map(|(&num, (reason, raw))| {
                let hidden = raw.as_ref().is_none_or(|raw| {
                    raw.iter()
                        .any(|t| watched.contains(t) && !refs_at_k(num).contains(t))
                });
                hidden.then(|| format!("object {num}: {reason}"))
            });
            for (&num, (_, raw)) in &not_canonical {
                match (raw, hidden_uses.as_mut()) {
                    (Some(raw), Some(hidden)) => hidden.extend(
                        raw.iter()
                            .filter(|t| watched.contains(t) && !refs_at_k(num).contains(t)),
                    ),
                    _ => hidden_uses = None,
                }
            }
            record_usages(
                &trailer,
                Referrer::Trailer,
                &watched,
                &field_tree,
                &mut usages,
                &mut crowded,
            );
            let current = revisions.store();
            for &num in &reachable {
                if !refs_at_k(num).iter().any(|t| watched.contains(t)) {
                    continue;
                }
                let value = match old_values.get(&num) {
                    Some(value) => Some(Arc::clone(value)),
                    None => revisions.entry_at(num, k).and_then(|entry| {
                        current.resolve(ObjectId::new(num, entry_gen(&entry))).ok()
                    }),
                };
                if let Some(value) = value {
                    record_usages(
                        &value,
                        Referrer::Object(num),
                        &watched,
                        &field_tree,
                        &mut usages,
                        &mut crowded,
                    );
                }
            }
        }

        let shared_appearance = field_appearances.iter().find_map(|(&ap, &field)| {
            Base::appearance_use_problem(ap, &usages, &crowded, hidden_uses.as_ref()).map(|uses| {
                format!(
                    "the signed revision's form field {field} has the indirect appearance \
                         dictionary {ap} 0 R, which the signed revision uses in {uses}: pyHanko \
                         refuses any update of a document whose field appearance dictionary has \
                         more than one context, and so does Folioxide (manager ruling R-19)"
                )
            })
        });
        let shared_sig_appearances = sig_appearances
            .iter()
            .filter_map(|(&field, &ap)| {
                let uses =
                    Base::appearance_use_problem(ap, &usages, &crowded, hidden_uses.as_ref())?;
                Some((
                    field,
                    format!(
                        "the signed revision's unsigned signature field {field} has the indirect \
                         appearance dictionary {ap} 0 R, which the signed revision uses in \
                         {uses}: pyHanko refuses to sign such a field afterwards (its \
                         SigFieldModificationRule checks the old appearance dictionary of a \
                         field that becomes signed), and so does Folioxide (manager ruling R-19)"
                    ),
                ))
            })
            .collect();
        Base {
            listed,
            containers,
            dangling,
            root,
            acroform: acroform_ref.map(|id| id.num),
            fields_array,
            fields,
            kids_arrays,
            xfa,
            form,
            struct_tree: StructTree::read(store, catalog_dict),
            pages,
            annots_arrays,
            info,
            metadata,
            extensions,
            mark_info,
            signed_names_complete: signed_names.complete,
            signed_name_objects: signed_names.objects.into_iter().collect(),
            signed_names: signed_names.names,
            usages,
            crowded,
            usage_defect,
            shared_appearance,
            shared_sig_appearances,
        }
    }

    /// Manager ruling R-19 (M4 QA round 5, finding 7; final fix round 2, finding 1; closing
    /// round, finding 10): how an indirect `/AP` dictionary `ap` of a field node of the signed
    /// revision (a terminal one for a signature field) is used, when
    /// that is in more or fewer than one context: its `usages` (each a referrer and a path), more
    /// than the index keeps (`crowded`), or a reference that only another reader follows
    /// (`hidden`, the raw references of objects that are not canonical; `None` when those cannot
    /// all be known). pyHanko's `_allow_appearance_update` refuses an old appearance dictionary
    /// used in several contexts (`SuspiciousModification`, so `OTHER`). It runs for every
    /// non-signature field present in both revisions, changed or not (for a later revision that
    /// only touches `/Info` too), and for a signature field that the later revision signs.
    /// `None` when it is used once.
    fn appearance_use_problem(
        ap: u32,
        usages: &BTreeMap<u32, Vec<Usage>>,
        crowded: &BTreeSet<u32>,
        hidden: Option<&BTreeSet<u32>>,
    ) -> Option<String> {
        let uses = usages.get(&ap).map_or(0, Vec::len);
        let hidden = hidden.is_none_or(|hidden| hidden.contains(&ap));
        let crowded = crowded.contains(&ap);
        (crowded || uses != 1 || hidden).then(|| {
            format!(
                "{} context{}{}",
                if crowded {
                    format!("{MAX_USAGES} or more")
                } else {
                    uses.to_string()
                },
                if uses == 1 && !crowded { "" } else { "s" },
                if hidden {
                    ", besides a use only a reader of non-canonical bytes finds"
                } else {
                    ""
                }
            )
        })
    }

    /// Whether `num` is an unsigned terminal signature field of the signed revision.
    fn is_unsigned_sig_field(&self, num: u32) -> bool {
        self.fields
            .get(&num)
            .is_some_and(|&(signature, signed, terminal)| signature && !signed && terminal)
    }

    /// Whether every use of `num` in the signed revision is one its roles account for: the
    /// trailer's `/Info`, the catalog's `/Metadata`, `/Extensions`, `/MarkInfo` or `/AcroForm`,
    /// the AcroForm's `/Fields`, a page's `/Annots`, and for an unsigned signature field its
    /// place in the field tree and on pages (pyHanko's expected contexts). The field tree's
    /// `/Parent` links do not count, as in pyHanko; any other `/Parent` (a page's) does
    /// ([`record_usages`]).
    fn only_used_in_role(&self, num: u32) -> bool {
        if self.crowded.contains(&num) {
            return false;
        }
        let uses = self.usages.get(&num).map_or(&[][..], Vec::as_slice);
        // An appearance dictionary or stream changed in place must be used once (brief §5.1 F4,
        // F5; pyHanko's relative contexts).
        if (self.form.ap_dicts.contains_key(&num) || self.form.ap_streams.contains_key(&num))
            && uses.len() != 1
        {
            return false;
        }
        uses.iter().all(|usage| self.usage_allowed(num, usage))
    }

    fn usage_allowed(&self, num: u32, usage: &Usage) -> bool {
        if self.form.contains(num) {
            return self.form_usage_allowed(num, usage);
        }
        let is_root = |from: Referrer| matches!(from, Referrer::Object(o) if Some(o) == self.root);
        let object = |from: Referrer| match from {
            Referrer::Object(o) => Some(o),
            Referrer::Trailer => None,
        };
        let path = usage.path.as_slice();
        let from = usage.from;
        let role = match path {
            [step] if from == Referrer::Trailer => step.is_key(b"Info") && self.info == Some(num),
            [step] if is_root(from) => {
                (step.is_key(b"Metadata") && self.metadata == Some(num))
                    || (step.is_key(b"Extensions") && self.extensions == Some(num))
                    || (step.is_key(b"MarkInfo") && self.mark_info == Some(num))
                    || (step.is_key(b"AcroForm") && self.acroform == Some(num))
            }
            [step] => {
                let o = object(from);
                (step.is_key(b"Fields")
                    && o.is_some()
                    && o == self.acroform
                    && self.fields_array == Some(num))
                    || (step.is_key(b"Annots")
                        && o.is_some_and(|o| self.pages.contains(&o))
                        && self.annots_arrays.contains_key(&num))
            }
            [a, b] if is_root(from) => {
                a.is_key(b"AcroForm") && b.is_key(b"Fields") && self.fields_array == Some(num)
            }
            _ => false,
        };
        if role {
            return true;
        }
        if !self.is_unsigned_sig_field(num) {
            return false;
        }
        // An unsigned signature field: in /Fields or a parent's /Kids, and on pages' /Annots.
        let Some(o) = object(from) else {
            return false;
        };
        match path {
            [Step::Index(_)] => {
                Some(o) == self.fields_array
                    || self.annots_arrays.contains_key(&o)
                    || self.kids_arrays.contains_key(&o)
            }
            [key, Step::Index(_)] => {
                (key.is_key(b"Fields") && Some(o) == self.acroform)
                    || (key.is_key(b"Annots") && self.pages.contains(&o))
                    || (key.is_key(b"Kids") && self.fields.contains_key(&o))
            }
            [a, b, Step::Index(_)] => {
                Some(o) == self.root && a.is_key(b"AcroForm") && b.is_key(b"Fields")
            }
            _ => false,
        }
    }

    /// The expected contexts of a form role (M4 brief §5.1 F0): a field in `/Fields` (at the
    /// root) or in its parent's `/Kids`, a merged widget in a page's `/Annots` and in a
    /// structure tree's `/OBJR /Obj` (D-24); an indirect appearance dictionary in its widget's
    /// `/AP`; an appearance stream in its widget's `/AP` (or its indirect `/AP` dictionary) as
    /// `/N`, `/D` or `/R`. Field-tree `/Parent` links are not recorded ([`record_usages`]).
    fn form_usage_allowed(&self, num: u32, usage: &Usage) -> bool {
        let Referrer::Object(o) = usage.from else {
            return false;
        };
        let path = usage.path.as_slice();
        if let Some(field) = self.form.fields.get(&num) {
            if usage.objr {
                return field.merged && self.struct_tree.is_objr_context(o, path);
            }
            let root_level = field.parent.is_none();
            return match path {
                [Step::Index(_)] => {
                    (root_level && Some(o) == self.fields_array)
                        || (field.parent.is_some()
                            && self.kids_arrays.get(&o).copied() == field.parent)
                        || (field.merged && self.annots_arrays.contains_key(&o))
                }
                [key, Step::Index(_)] => {
                    (key.is_key(b"Fields") && root_level && Some(o) == self.acroform)
                        || (key.is_key(b"Kids") && Some(o) == field.parent)
                        || (key.is_key(b"Annots") && field.merged && self.pages.contains(&o))
                }
                [a, b, Step::Index(_)] => {
                    root_level
                        && Some(o) == self.root
                        && a.is_key(b"AcroForm")
                        && b.is_key(b"Fields")
                }
                _ => false,
            };
        }
        let appearance_key =
            |step: &Step| step.is_key(b"N") || step.is_key(b"D") || step.is_key(b"R");
        if let Some(&owner) = self.form.ap_dicts.get(&num) {
            return o == owner && matches!(path, [key] if key.is_key(b"AP"));
        }
        if let Some(&owner) = self.form.ap_streams.get(&num) {
            return match path {
                [ap, key] => o == owner && ap.is_key(b"AP") && appearance_key(key),
                [key] => self.form.ap_dicts.get(&o) == Some(&owner) && appearance_key(key),
                _ => false,
            };
        }
        false
    }
}

/// The structure tree's `/K` links (§14.7.2), as far as pyHanko's `_find_in_structure_tree`
/// accepts a widget's object reference (`/OBJR`, §14.7.5.3) as its context (M4 brief D-24): a path
/// from the `/StructTreeRoot`'s `/K` through `/K` entries (and their arrays) that ends in `/K`
/// and `/Obj`.
#[derive(Clone, Debug, Default)]
struct StructTree {
    /// The objects reached from the `/StructTreeRoot`'s `/K` through `/K` entries.
    nodes: BTreeSet<u32>,
    /// Those that are the value of a `/K` entry itself (not an element of a `/K` array).
    k_values: BTreeSet<u32>,
}

/// The most structure tree objects [`StructTree::read`] visits; past it no `/OBJR` context is
/// accepted (fail closed).
const MAX_STRUCT_NODES: usize = 65_536;

impl StructTree {
    /// The `/K` links of the structure tree of `catalog` in `store`, bounded by
    /// [`MAX_STRUCT_NODES`] and [`MAX_REF_DEPTH`] (an empty tree past the bounds).
    fn read(store: &Store, catalog: Option<&Dict>) -> StructTree {
        let mut tree = StructTree::default();
        let root = catalog
            .and_then(|c| c.get(b"StructTreeRoot"))
            .and_then(|r| store.deref(r).ok())
            .and_then(|r| r.as_dict().cloned());
        let Some(root) = root else {
            return tree;
        };
        let mut seen: HashSet<u32> = HashSet::new();
        // (a /K value or one of its elements, depth, whether it is the /K value itself)
        let mut stack: Vec<(Object, usize, bool)> = root
            .get(b"K")
            .map(|k| vec![(k.clone(), 0, true)])
            .unwrap_or_default();
        while let Some((value, depth, direct)) = stack.pop() {
            if depth > MAX_REF_DEPTH || seen.len() > MAX_STRUCT_NODES {
                return StructTree::default();
            }
            match value {
                Object::Ref(id) => {
                    if direct {
                        tree.k_values.insert(id.num);
                    }
                    if !seen.insert(id.num) {
                        continue;
                    }
                    tree.nodes.insert(id.num);
                    if let Ok(node) = store.resolve(id)
                        && let Some(k) = node.as_dict().and_then(|d| d.get(b"K"))
                    {
                        stack.push((k.clone(), depth + 1, true));
                    }
                }
                Object::Array(items) => {
                    for item in items {
                        stack.push((item, depth + 1, false));
                    }
                }
                Object::Dict(dict) => {
                    if let Some(k) = dict.get(b"K") {
                        stack.push((k.clone(), depth + 1, true));
                    }
                }
                _ => {}
            }
        }
        tree
    }

    /// Whether an `/OBJR /Obj` reference from object `from` at `path` is a structure tree
    /// context pyHanko accepts: `from` a structure element reached through `/K`, the path made
    /// of `/K` entries and array indices and ending in `/K /Obj` (a direct object reference
    /// dictionary as the value of a `/K`); or `from` an indirect object reference dictionary
    /// that is itself the value of a `/K`, the path `/Obj`.
    fn is_objr_context(&self, from: u32, path: &[Step]) -> bool {
        let k_steps = path
            .iter()
            .all(|step| matches!(step, Step::Index(_)) || step.is_key(b"K") || step.is_key(b"Obj"));
        let ends_k_obj = matches!(path, [.., k, obj] if k.is_key(b"K") && obj.is_key(b"Obj"));
        (self.nodes.contains(&from) && k_steps && ends_k_obj)
            || (self.k_values.contains(&from) && matches!(path, [obj] if obj.is_key(b"Obj")))
    }
}

/// What a form field that is not a signature field is (§12.7.4, §12.7.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FormKind {
    /// `/FT /Tx`.
    Text,
    /// `/FT /Ch`.
    Choice,
    /// `/FT /Btn`, a check box or a radio button group.
    Button,
    /// `/FT /Btn` with the Pushbutton flag (bit 17): it has no value.
    Pushbutton,
}

/// A terminal form field of the signed revision that is not a signature field (brief §5.1 F0
/// (a)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FormField {
    kind: FormKind,
    /// ReadOnly (`/Ff` bit 1, the field's own or inherited, §12.7.4.1).
    read_only: bool,
    /// The field is merged with its widget: no `/Kids`, `/Subtype /Widget`.
    merged: bool,
    /// The parent field in the field tree; `None` at the root of `/Fields`.
    parent: Option<u32>,
    /// A widget of the field (the field merged with it, or a widget kid) sets NoZoom or
    /// NoRotate, a reserved flag, or an `/F` that cannot be read
    /// ([`geometry::form_widget_flags_ok`]): viewers draw it outside its `/Rect`, so filling the
    /// field is `Other` (M4 QA round 2).
    drawn_outside_rect: bool,
}

/// The objects of the signed revision the form-filling rules know (brief §5.1 F0): its terminal
/// form fields, the widget kids of those fields, and the indirect appearance dictionaries and
/// the appearance streams (of text and choice fields) of the fields merged with their widget.
#[derive(Clone, Debug, Default)]
struct FormRoles {
    fields: BTreeMap<u32, FormField>,
    /// Widgets that are kids of a terminal form field: pyHanko 0.37 allows no change to them
    /// (probes: a radio button's `/AS`, a kid widget's new `/AP`), so neither does Folioxide.
    kid_widgets: BTreeSet<u32>,
    /// Indirect `/AP` dictionaries of merged widgets, with their field (one field each).
    ap_dicts: BTreeMap<u32, u32>,
    /// `/AP /N`, `/D` and `/R` streams of merged text and choice widgets, with their field (one
    /// field each).
    ap_streams: BTreeMap<u32, u32>,
    /// Per field: the other indirect objects of the signed revision the form-filling rules read
    /// for it (its ancestors in the field tree, whose `/FT` and `/Ff` it inherits; its widget
    /// kids, whose `/F` F0 reads; its indirect `/AP` and `/AP /N` dictionaries, whose states F3
    /// reads), which must read the same in every reader (manager ruling R-12 (2)).
    reads: BTreeMap<u32, Vec<u32>>,
}

/// The field flags (§12.7.4.1 Table 227, §12.7.5.2.1 Table 229).
const FF_READ_ONLY: i64 = 1;
const FF_PUSHBUTTON: i64 = 1 << 16;

impl FormRoles {
    /// The form roles of a field tree walk (`nodes`, from [`field::walk_fields_bounded`], parents
    /// before their kids) of `store`.
    fn read(store: &Store, nodes: &[field::FieldNode]) -> FormRoles {
        let mut roles = FormRoles::default();
        let mut shared_ap: BTreeSet<u32> = BTreeSet::new();
        // The effective /Ff of each node: its own, or its parent's (inheritable, Table 226).
        let mut flags: Vec<i64> = Vec::with_capacity(nodes.len());
        for node in nodes {
            let own = node
                .dict
                .get(b"Ff")
                .and_then(|f| store.deref(f).ok())
                .and_then(|f| f.as_int());
            let inherited = node.parent.and_then(|p| flags.get(p).copied()).unwrap_or(0);
            flags.push(own.unwrap_or(inherited));
        }
        for (index, node) in nodes.iter().enumerate() {
            let (Some(id), true) = (node.id, node.terminal) else {
                continue;
            };
            let mut reads: Vec<u32> = Vec::new();
            let mut up = node.parent;
            for _ in 0..field::MAX_FIELD_DEPTH {
                let Some(parent) = up.and_then(|p| nodes.get(p)) else {
                    break;
                };
                reads.extend(parent.id.map(|p| p.num));
                up = parent.parent;
            }
            let flags = flags.get(index).copied().unwrap_or(0);
            let kind = match node.field_type.as_deref() {
                Some(b"Tx") => FormKind::Text,
                Some(b"Ch") => FormKind::Choice,
                Some(b"Btn") if flags & FF_PUSHBUTTON != 0 => FormKind::Pushbutton,
                Some(b"Btn") => FormKind::Button,
                _ => continue,
            };
            let kids = node.dict.get(b"Kids");
            let merged = kids.is_none()
                && node
                    .dict
                    .get_name(b"Subtype")
                    .is_some_and(|s| s.as_bytes() == b"Widget");
            let parent = node
                .parent
                .and_then(|p| nodes.get(p))
                .and_then(|p| p.id)
                .map(|p| p.num);
            let mut drawn_outside_rect =
                merged && !geometry::form_widget_flags_ok(store, &node.dict);
            if let Some(kids) = kids.and_then(|k| store.deref(k).ok())
                && let Some(kids) = kids.as_array()
            {
                for kid in kids.iter().filter_map(Object::as_ref) {
                    reads.push(kid.num);
                    let Ok(value) = store.resolve(kid) else {
                        continue;
                    };
                    let Some(widget) = value.as_dict().filter(|d| !d.contains_key(b"T")) else {
                        continue;
                    };
                    roles.kid_widgets.insert(kid.num);
                    drawn_outside_rect |= !geometry::form_widget_flags_ok(store, widget);
                }
            }
            roles.fields.insert(
                id.num,
                FormField {
                    kind,
                    read_only: flags & FF_READ_ONLY != 0,
                    merged,
                    parent,
                    drawn_outside_rect,
                },
            );
            if let Some(ap) = node.dict.get(b"AP") {
                reads.extend(ap.as_ref().map(|ap| ap.num));
                if let Some(normal) = store
                    .deref(ap)
                    .ok()
                    .and_then(|ap| ap.as_dict().and_then(|ap| ap.get_ref(b"N")))
                {
                    reads.push(normal.num);
                }
            }
            roles.reads.insert(id.num, reads);
            if !merged {
                continue;
            }
            let Some(ap) = node.dict.get(b"AP") else {
                continue;
            };
            if let Some(ap_id) = ap.as_ref()
                && roles.ap_dicts.insert(ap_id.num, id.num).is_some()
            {
                shared_ap.insert(ap_id.num);
            }
            if !matches!(kind, FormKind::Text | FormKind::Choice) {
                continue;
            }
            let Some(ap) = store.deref(ap).ok().and_then(|ap| ap.as_dict().cloned()) else {
                continue;
            };
            for key in [b"N".as_slice(), b"D", b"R"] {
                if let Some(stream) = ap.get(key).and_then(Object::as_ref)
                    && store
                        .resolve(stream)
                        .is_ok_and(|s| matches!(*s, Object::Stream(_)))
                    && roles
                        .ap_streams
                        .insert(stream.num, id.num)
                        .is_some_and(|f| f != id.num)
                {
                    shared_ap.insert(stream.num);
                }
            }
        }
        // An appearance object of two fields has no single owner: no role (any change: Other).
        for num in shared_ap {
            roles.ap_dicts.remove(&num);
            roles.ap_streams.remove(&num);
        }
        roles
    }

    /// Whether `num` has a form role whose uses are checked by [`Base::form_usage_allowed`].
    fn contains(&self, num: u32) -> bool {
        self.fields.contains_key(&num)
            || self.ap_dicts.contains_key(&num)
            || self.ap_streams.contains_key(&num)
    }
}

/// The resource categories of a resource dictionary (ISO 32000-2 §7.8.3, Table 34; `/ProcSet`
/// names no resource): a stream whose own `/Resources` lack one may draw from the page's
/// ([`SignedNames::bare`]).
const RESOURCE_CATEGORIES: &[&[u8]] = &[
    b"ExtGState",
    b"ColorSpace",
    b"Pattern",
    b"Shading",
    b"XObject",
    b"Font",
    b"Properties",
];

/// The most default appearance strings [`SignedNames`] reads in one signed revision.
const MAX_DA_STRINGS: usize = 4096;

/// The most names [`SignedNames`] keeps for one signed revision.
const MAX_SIGNED_NAMES: usize = 16_384;

/// The most `/Annots` entries of the signed revision's pages [`SignedNames`] visits.
const MAX_SIGNED_ANNOTATIONS: usize = 65_536;

/// The most appearance objects (streams, or dictionaries of appearance states) [`SignedNames`]
/// examines in one signed revision.
const MAX_SIGNED_APPEARANCES: usize = 16_384;

/// The largest appearance stream (or form XObject it draws) that [`SignedNames`] decodes to read
/// its names; a larger one makes the collection incomplete.
const MAX_BARE_APPEARANCE_BYTES: usize = 1024 * 1024;

/// The appearance-stream bytes [`SignedNames`] decodes in total in the analyses of one
/// verification; past it, a stream not decoded yet makes the collection incomplete.
const MAX_BARE_APPEARANCE_TOTAL: usize = 16 * 1024 * 1024;

/// The names the signed revision already takes, or may take, from the AcroForm's default
/// resources `/DR` (brief §5 V10 (3) (c)), which a later revision therefore may not add:
///
/// - every name token ([`for_each_name_token`]) of every default appearance string (`/DA`,
///   §12.7.4.3) of the signed revision: the AcroForm's, those of the fields and widgets of its
///   field tree, and those of **every annotation on every page** and its `/Parent` chain
///   (expert finding: an orphan text widget, on a page but in no `/Fields`, whose `/DA` names a
///   font `/DR` lacks, is drawn differently once a later revision adds that name; a FreeText
///   annotation's `/DA` names `/DR` fonts too, §12.5.6.6);
/// - every name token of every appearance stream (`/N`, `/R` and `/D`, or their appearance
///   states, §12.5.5) of those annotations and widgets, and of every content stream they draw:
///   the form XObjects of their `/Resources /XObject`, the tiling patterns of their `/Resources
///   /Pattern` and the glyph procedures of their Type 3 fonts, nested (QA round 2, finding 22),
///   **whether or not** the stream has a `/Resources` dictionary of its own: some viewers
///   resolve in `/DR` a name that a stream's own resources lack, or that a nested stream
///   without resources uses (M4 QA round 1, the F7 residual of brief §5.5 scope (2); poppler
///   24.02 and PDFium do not, pdf.js and MuPDF are unprobed). A name any of them uses is one a
///   later revision may not add to `/DR`.
///
/// A `/DA` selects its font with `Tf` but may name a colour space or a graphics state too, so
/// the names count in every `/DR` category. Past any bound ([`MAX_DA_STRINGS`],
/// [`MAX_SIGNED_NAMES`], [`MAX_SIGNED_ANNOTATIONS`], [`MAX_SIGNED_APPEARANCES`], the decoding
/// bounds), or when the field tree, the page tree or a page's `/Annots` cannot be read in full,
/// the collection is incomplete, and the rules then refuse every new `/DR` name.
struct SignedNames {
    names: BTreeSet<Vec<u8>>,
    /// The default appearance strings read.
    read: usize,
    /// The `/Annots` entries visited.
    annotations: usize,
    /// The appearance objects examined, by object number and what they are drawn as (each
    /// once per role: an object that is both, say, a form XObject and a graphics state's soft
    /// mask is read as each; M4 QA round 3, finding 21).
    appearances: HashSet<(u32, Drawn)>,
    /// The ancestors of page annotations read, by object number (each once).
    parents: HashSet<u32>,
    /// The indirect resource dictionaries, their category dictionaries and Type 3 `/CharProcs`
    /// read, by object number and role (each once per role).
    resources: HashSet<(u32, Role)>,
    /// The indirect objects of the signed revision read: the objects whose bytes the `/DR`
    /// guard relies on, which must read the same in every reader when a name is added (manager
    /// ruling R-12 (2)).
    objects: BTreeSet<u32>,
    /// A stream it read (an appearance, or a form XObject, tiling pattern or Type 3 font it
    /// draws) has no `/Resources` of its own, so its names resolve in the resources of the page
    /// it is drawn on (ISO 32000-2 §7.8.3, §8.10.2, §9.6.4; M4 QA round 4, finding 12), or
    /// resources that lack a category, which PDFium then looks up in the page's (M4 QA round 5,
    /// finding 29): the content streams those draw are read too
    /// ([`SignedNames::add_page_resources`], [`SignedNames::add_tree_resources`]).
    bare: bool,
    /// The page-tree objects whose `/Resources` were read, by object number (each once).
    page_resources: HashSet<u32>,
    /// The page-tree nodes reached by climbing `/Parent` chains, by object number (each once).
    tree_nodes: HashSet<u32>,
    /// Whether every string, annotation and stream was read and every name kept.
    complete: bool,
}

impl Default for SignedNames {
    fn default() -> Self {
        SignedNames {
            names: BTreeSet::new(),
            read: 0,
            annotations: 0,
            appearances: HashSet::new(),
            parents: HashSet::new(),
            resources: HashSet::new(),
            objects: BTreeSet::new(),
            bare: false,
            page_resources: HashSet::new(),
            tree_nodes: HashSet::new(),
            complete: true,
        }
    }
}

impl SignedNames {
    /// Adds the name tokens of `dict`'s `/DA` (direct, or through a reference).
    fn add_da(&mut self, store: &Store, dict: &Dict) {
        let Some(value) = dict.get(b"DA") else {
            return;
        };
        if self.read >= MAX_DA_STRINGS {
            self.complete = false;
            return;
        }
        self.read += 1;
        if let Object::Ref(id) = value {
            self.objects.insert(id.num);
        }
        if let Ok(value) = store.deref(value)
            && let Object::String(da) = &*value
        {
            self.add_names_of(da.as_bytes());
        }
    }

    /// Adds the name tokens of `data` ([`for_each_name_token`]), up to [`MAX_SIGNED_NAMES`] in
    /// all; data whose names cannot all be read makes the collection incomplete.
    fn add_names_of(&mut self, data: &[u8]) {
        let names = &mut self.names;
        let mut kept = true;
        let readable = for_each_name_token(data, |name| {
            if !names.contains(name) {
                if names.len() >= MAX_SIGNED_NAMES {
                    kept = false;
                    return false;
                }
                names.insert(name.to_vec());
            }
            true
        });
        if !readable || !kept {
            self.complete = false;
        }
    }

    /// Adds what an annotation of the signed revision (or a field merged with its widget) names:
    /// its `/DA` and its appearance streams with the form XObjects they draw. `decoded` counts
    /// the appearance bytes the verification decoded ([`MAX_BARE_APPEARANCE_TOTAL`]).
    fn add_annotation(&mut self, store: &Store, annotation: &Dict, decoded: &Cell<usize>) {
        self.add_da(store, annotation);
        if let Some(Object::Ref(id)) = annotation.get(b"AP") {
            self.objects.insert(id.num);
        }
        let Some(ap) = annotation.get(b"AP").and_then(|ap| store.deref(ap).ok()) else {
            return;
        };
        let Some(ap) = ap.as_dict() else {
            return;
        };
        for key in [b"N".as_slice(), b"R", b"D"] {
            if let Some(value) = ap.get(key) {
                self.add_appearance(store, value, true, decoded);
            }
        }
    }

    /// Adds the names of one appearance (§12.5.5): a stream, or (when `states`) a dictionary of
    /// appearance states whose values are streams. Each object is examined once.
    fn add_appearance(
        &mut self,
        store: &Store,
        value: &Object,
        states: bool,
        decoded: &Cell<usize>,
    ) {
        let resolved;
        let value = match value {
            Object::Ref(id) => {
                if self.appearances.contains(&(id.num, Drawn::Appearance)) {
                    return;
                }
                if self.appearances.len() >= MAX_SIGNED_APPEARANCES {
                    self.complete = false;
                    return;
                }
                self.appearances.insert((id.num, Drawn::Appearance));
                self.objects.insert(id.num);
                match store.resolve(*id) {
                    Ok(value) => {
                        resolved = value;
                        &*resolved
                    }
                    // Not readable: nothing a viewer draws.
                    Err(_) => return,
                }
            }
            direct => direct,
        };
        match value {
            Object::Stream(stream) => self.add_stream_names(store, stream, decoded),
            Object::Dict(dict) if states => {
                for state in dict.values() {
                    self.add_appearance(store, state, false, decoded);
                }
            }
            _ => {}
        }
    }

    /// Adds the name tokens of an appearance stream and of every content stream it draws,
    /// nested: the form XObjects of its `/Resources /XObject`, the tiling patterns of its
    /// `/Resources /Pattern` (§8.7.3.1: a pattern cell is a content stream), the glyph
    /// procedures (`/CharProcs`, §9.6.4) of the Type 3 fonts of its `/Resources /Font`, and,
    /// through its `/Resources /ExtGState` (§8.4.5), the transparency groups of soft masks
    /// (`/SMask /G`, §11.6.5.2) and the Type 3 fonts of `/Font` entries, with what their own
    /// resources name (QA round 2, finding 22; round 3, findings 6 and 21: a name used only in a
    /// tiling pattern, a Type 3 glyph or a soft mask's group without resources of its own).
    /// Each object once per role (what it is drawn as), at most [`MAX_SIGNED_APPEARANCES`] in
    /// all, with an explicit work list, decoding at most [`MAX_BARE_APPEARANCE_BYTES`] of each;
    /// one that cannot be decoded in full makes the collection incomplete.
    fn add_stream_names(&mut self, store: &Store, stream: &Stream, decoded: &Cell<usize>) {
        let mut pending: Vec<(ObjectId, Drawn)> = Vec::new();
        self.add_stream_tokens(store, stream, decoded, &mut pending);
        self.drain(store, pending, decoded);
    }

    /// Reads what `pending` holds, and what that draws in turn (the work list of
    /// [`SignedNames::add_stream_names`]).
    fn drain(&mut self, store: &Store, mut pending: Vec<(ObjectId, Drawn)>, decoded: &Cell<usize>) {
        while let Some((id, kind)) = pending.pop() {
            if self.appearances.contains(&(id.num, kind)) {
                continue;
            }
            if self.appearances.len() >= MAX_SIGNED_APPEARANCES {
                self.complete = false;
                return;
            }
            self.appearances.insert((id.num, kind));
            self.objects.insert(id.num);
            let Ok(value) = store.resolve(id) else {
                continue; // nothing a viewer draws
            };
            match (kind, &*value) {
                (Drawn::Form, Object::Stream(form)) if self.is_form(store, &form.dict) => {
                    self.add_stream_tokens(store, form, decoded, &mut pending);
                }
                // A tiling pattern (a stream; a shading pattern is a dictionary and names
                // nothing) and a glyph procedure are content streams.
                (Drawn::Pattern | Drawn::Glyph, Object::Stream(content)) => {
                    self.add_stream_tokens(store, content, decoded, &mut pending);
                }
                (Drawn::Font, Object::Dict(font)) => {
                    self.queue_type3(store, font, &mut pending);
                }
                (Drawn::GState, Object::Dict(state)) => {
                    self.queue_graphics_state(store, state, &mut pending);
                }
                (Drawn::SoftMask, Object::Dict(mask)) => {
                    if let Some(Object::Ref(group)) = mask.get(b"G") {
                        pending.push((*group, Drawn::Form));
                    }
                }
                _ => {}
            }
        }
    }

    /// The name the `key` entry of `dict` holds, direct or through a reference (readers
    /// dereference `/Subtype`; M4 QA round 4, finding 12: an indirect `/Subtype /Form` was not
    /// read as a form). The object a reference names is one the guard relies on.
    fn name_of(&mut self, store: &Store, dict: &Dict, key: &[u8]) -> Option<Vec<u8>> {
        let value = dict.get(key)?;
        if let Object::Ref(id) = value {
            self.objects.insert(id.num);
        }
        let value = store.deref(value).ok()?;
        value.as_name().map(|name| name.as_bytes().to_vec())
    }

    /// Whether an XObject stream (`dict`) is drawn as a form XObject (§8.10): its `/Subtype`,
    /// direct or indirect, is `/Form`, or it is no image and has a `/BBox` (read rather than
    /// skipped when its subtype cannot be read).
    fn is_form(&mut self, store: &Store, dict: &Dict) -> bool {
        match self.name_of(store, dict, b"Subtype").as_deref() {
            Some(b"Form") => true,
            Some(b"Image" | b"PS") => false,
            _ => dict.contains_key(b"BBox"),
        }
    }

    /// Adds the name tokens of one stream ([`SignedNames::add_names_of`]) and queues what its
    /// `/Resources` draw ([`SignedNames::queue_resources`]); a stream without `/Resources`
    /// resolves its names in the page's ([`SignedNames::bare`]).
    fn add_stream_tokens(
        &mut self,
        store: &Store,
        stream: &Stream,
        decoded: &Cell<usize>,
        pending: &mut Vec<(ObjectId, Drawn)>,
    ) {
        let left = MAX_BARE_APPEARANCE_TOTAL.saturating_sub(decoded.get());
        match store.stream_data_capped(stream, MAX_BARE_APPEARANCE_BYTES.min(left)) {
            Ok(Some(bytes)) if bytes.is_fully_decoded() && !bytes.truncated => {
                decoded.set(decoded.get().saturating_add(bytes.data.len()));
                self.add_names_of(&bytes.data);
            }
            _ => self.complete = false,
        }
        match stream.dict.get(b"Resources") {
            Some(resources) => {
                // PDFium looks a name up in the page's resources when the stream's own lack its
                // category (M4 QA round 5, finding 29: an empty /Resources, or one with /Font
                // only, drew a form only the page's resources define), so a stream whose
                // resources are not a dictionary with every category reads the page's too.
                let every_category = store
                    .deref(resources)
                    .ok()
                    .and_then(|r| {
                        r.as_dict()
                            .map(|d| RESOURCE_CATEGORIES.iter().all(|c| d.contains_key(c)))
                    })
                    .unwrap_or(false);
                if !every_category {
                    self.bare = true;
                }
                self.queue_resources(store, resources, pending);
            }
            None => self.bare = true,
        }
    }

    /// When a stream read has no `/Resources`, or resources without every category
    /// ([`SignedNames::bare`]), reads what the resources of the page `page` (`dict`) and of every
    /// ancestor along its `/Parent` chain draw: the form XObjects, tiling patterns, Type 3 glyphs
    /// and graphics states a resource-less appearance reaches through them (M4 QA round 4,
    /// finding 12, variant R1w-page-level-form). Every ancestor's, not only the nearest one with
    /// resources (§7.7.3.4): readers inherit along different paths (PDFium along `/Parent`,
    /// poppler along `/Kids`; [`SignedNames::add_tree_resources`] reads the `/Kids` walk's
    /// nodes; M4 QA round 5, finding 29). The page content itself is not read: what only it uses,
    /// viewers resolve in the page's resources, never in `/DR`. Each page-tree object's resources
    /// once, and each `/Parent` chain climbed once.
    fn add_page_resources(
        &mut self,
        store: &Store,
        page: ObjectId,
        dict: &Dict,
        decoded: &Cell<usize>,
    ) {
        self.add_node_resources(store, page.num, dict, decoded);
        let mut parent = dict.get(b"Parent").cloned();
        for _ in 0..usize::from(store.limits().max_page_tree_depth) {
            let Some(Object::Ref(up)) = parent.take() else {
                break;
            };
            if !self.tree_nodes.insert(up.num) {
                break; // this chain was climbed from here already
            }
            self.objects.insert(up.num);
            let Ok(value) = store.resolve(up) else {
                break;
            };
            let Some(node) = value.as_dict() else {
                break;
            };
            self.add_node_resources(store, up.num, node, decoded);
            parent = node.get(b"Parent").cloned();
        }
    }

    /// What the `/Resources` of the page-tree object `holder` (`dict`) draw, once per object.
    fn add_node_resources(
        &mut self,
        store: &Store,
        holder: u32,
        dict: &Dict,
        decoded: &Cell<usize>,
    ) {
        let Some(resources) = dict.get(b"Resources") else {
            return;
        };
        if !self.page_resources.insert(holder) {
            return;
        }
        let mut pending = Vec::new();
        self.queue_resources(store, resources, &mut pending);
        self.drain(store, pending, decoded);
    }

    /// [`SignedNames::add_node_resources`] for every node and page of the page tree's `/Kids` walk
    /// (`walk`; poppler inherits resources along it, M4 QA round 5, finding 29). A walk that is
    /// not one every reader walks the same way leaves the collection incomplete.
    fn add_tree_resources(&mut self, store: &Store, walk: &PageWalk, decoded: &Cell<usize>) {
        if walk.problem.is_some() {
            self.complete = false;
        }
        let nodes = walk.nodes.iter().map(|&(node, ..)| node);
        let pages = walk.pages.values().map(|&(page, ..)| page);
        for id in nodes.chain(pages) {
            self.objects.insert(id.num);
            if let Ok(value) = store.resolve(id)
                && let Some(dict) = value.as_dict()
            {
                self.add_node_resources(store, id.num, dict, decoded);
            }
        }
    }

    /// Queues the content streams a resource dictionary (`resources`, direct or a reference)
    /// draws: its `/XObject` entries (form XObjects), its `/Pattern` entries (tiling patterns),
    /// the glyph procedures of its Type 3 `/Font` entries, and what its `/ExtGState` entries
    /// draw ([`SignedNames::queue_graphics_state`]). An inline Type 3 font or graphics state is
    /// read at once.
    fn queue_resources(
        &mut self,
        store: &Store,
        resources: &Object,
        pending: &mut Vec<(ObjectId, Drawn)>,
    ) {
        // An indirect dictionary is read once per role, however many streams share it (linear
        // in the bytes of the signed revision's resources).
        if let Object::Ref(id) = resources {
            if !self.resources.insert((id.num, Role::Resources)) {
                return;
            }
            self.objects.insert(id.num);
        }
        let Some(resources) = store.deref(resources).ok() else {
            return;
        };
        let Some(resources) = resources.as_dict() else {
            return;
        };
        for (category, kind) in [
            (b"XObject".as_slice(), Drawn::Form),
            (b"Pattern", Drawn::Pattern),
            (b"Font", Drawn::Font),
            (b"ExtGState", Drawn::GState),
        ] {
            let Some(entries) = resources.get(category) else {
                continue;
            };
            if let Object::Ref(id) = entries {
                if !self.resources.insert((id.num, Role::Category(kind))) {
                    continue;
                }
                self.objects.insert(id.num);
            }
            let Ok(entries) = store.deref(entries) else {
                continue;
            };
            for value in entries.as_dict().into_iter().flat_map(Dict::values) {
                match value {
                    Object::Ref(id) => pending.push((*id, kind)),
                    Object::Dict(font) if kind == Drawn::Font => {
                        self.queue_type3(store, font, pending);
                    }
                    Object::Dict(state) if kind == Drawn::GState => {
                        self.queue_graphics_state(store, state, pending);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Queues what a graphics state parameter dictionary (§8.4.5, Table 57) draws: the
    /// transparency group of its soft mask (`/SMask` a soft-mask dictionary, direct or
    /// indirect, whose `/G` is a form XObject, §11.6.5.2), and its `/Font` entry (`[font size]`,
    /// a Type 3 font's glyphs). M4 QA round 3, findings 6 and 21: a name used only there was
    /// not read.
    fn queue_graphics_state(
        &mut self,
        store: &Store,
        state: &Dict,
        pending: &mut Vec<(ObjectId, Drawn)>,
    ) {
        match state.get(b"SMask") {
            Some(Object::Ref(mask)) => pending.push((*mask, Drawn::SoftMask)),
            Some(Object::Dict(mask)) => {
                if let Some(Object::Ref(group)) = mask.get(b"G") {
                    pending.push((*group, Drawn::Form));
                }
            }
            _ => {}
        }
        let font = state.get(b"Font").and_then(|f| match f {
            Object::Array(items) => items.first().cloned(),
            Object::Ref(id) => {
                self.objects.insert(id.num);
                store
                    .resolve(*id)
                    .ok()
                    .and_then(|a| a.as_array().and_then(|a| a.first().cloned()))
            }
            _ => None,
        });
        match font {
            Some(Object::Ref(id)) => pending.push((id, Drawn::Font)),
            Some(Object::Dict(font)) => self.queue_type3(store, &font, pending),
            _ => {}
        }
    }

    /// Queues the glyph procedures (`/CharProcs`) and the resources of the font `font` when it
    /// is a Type 3 font (§9.6.4: its glyphs are content streams, which use its `/Resources`, or
    /// the page's when it has none).
    fn queue_type3(&mut self, store: &Store, font: &Dict, pending: &mut Vec<(ObjectId, Drawn)>) {
        // The subtype direct or indirect (readers dereference it; M4 QA round 4, finding 12),
        // and a font with glyph procedures whose subtype cannot be read is read as Type 3.
        let type3 = match self.name_of(store, font, b"Subtype").as_deref() {
            Some(b"Type3") => true,
            Some(_) => false,
            None => font.contains_key(b"CharProcs"),
        };
        if !type3 {
            return;
        }
        let procs = font.get(b"CharProcs").filter(|procs| match procs {
            Object::Ref(id) => {
                self.objects.insert(id.num);
                self.resources.insert((id.num, Role::CharProcs))
            }
            _ => true,
        });
        if let Some(procs) = procs.and_then(|p| store.deref(p).ok()) {
            for value in procs.as_dict().into_iter().flat_map(Dict::values) {
                if let Object::Ref(id) = value {
                    pending.push((*id, Drawn::Glyph));
                }
            }
        }
        match font.get(b"Resources") {
            Some(resources) => self.queue_resources(store, resources, pending),
            None => self.bare = true,
        }
    }

    /// Adds the `/DA` and appearances of each widget kid of the terminal field `dict`.
    fn add_kids(&mut self, store: &Store, dict: &Dict, decoded: &Cell<usize>) {
        let Some(kids) = dict.get(b"Kids").and_then(|k| store.deref(k).ok()) else {
            return;
        };
        for kid in kids.as_array().unwrap_or_default() {
            if self.read >= MAX_DA_STRINGS {
                self.complete = false;
                return;
            }
            if let Object::Ref(id) = kid {
                self.objects.insert(id.num);
            }
            if let Ok(kid) = store.deref(kid)
                && let Some(kid) = kid.as_dict()
            {
                self.add_annotation(store, kid, decoded);
            }
        }
    }

    /// Adds every annotation of a page's `/Annots` (`annots`, direct or indirect): a value that
    /// is neither an array nor `null` makes the collection incomplete.
    fn add_page_annotations(
        &mut self,
        store: &Store,
        annots: Option<&Object>,
        decoded: &Cell<usize>,
    ) {
        let Some(annots) = annots else {
            return;
        };
        let Ok(annots) = store.deref(annots) else {
            self.complete = false;
            return;
        };
        let items = match &*annots {
            Object::Array(items) => items,
            Object::Null => return,
            _ => {
                self.complete = false;
                return;
            }
        };
        for item in items {
            if self.annotations >= MAX_SIGNED_ANNOTATIONS {
                self.complete = false;
                return;
            }
            self.annotations += 1;
            if let Object::Ref(id) = item {
                self.objects.insert(id.num);
            }
            if let Ok(annotation) = store.deref(item)
                && let Some(annotation) = annotation.as_dict()
            {
                self.add_annotation(store, annotation, decoded);
                self.add_parents(store, annotation);
            }
        }
    }

    /// Adds the `/DA` of the ancestors of a page's annotation, up its `/Parent` chain: a widget
    /// inherits its field's `/DA` (§12.7.4.1, Table 226), and the field of a widget outside
    /// `/Fields` is outside the field tree too. Each ancestor is read once; a chain deeper than
    /// [`field::MAX_FIELD_DEPTH`] makes the collection incomplete.
    fn add_parents(&mut self, store: &Store, annotation: &Dict) {
        let mut next = annotation.get(b"Parent").cloned();
        for _ in 0..field::MAX_FIELD_DEPTH {
            let Some(value) = next.take() else {
                return;
            };
            if let Object::Ref(id) = &value {
                if !self.parents.insert(id.num) {
                    return; // read already, with its own ancestors
                }
                self.objects.insert(id.num);
            }
            let Ok(parent) = store.deref(&value) else {
                return;
            };
            let Some(parent) = parent.as_dict() else {
                return;
            };
            self.add_da(store, parent);
            next = parent.get(b"Parent").cloned();
        }
        if next.is_some() {
            self.complete = false;
        }
    }
}

/// What an object [`SignedNames`] reads is drawn as.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Drawn {
    /// An annotation's appearance (`/AP` `/N`, `/R` or `/D`): a stream, or a dictionary of
    /// appearance states.
    Appearance,
    /// A `/Resources /XObject` entry, or a soft mask's group: drawn when it is a form XObject.
    Form,
    /// A `/Resources /Pattern` entry: drawn when it is a tiling pattern (a stream).
    Pattern,
    /// A `/Resources /Font` entry or a graphics state's `/Font`: its glyphs are drawn when it
    /// is a Type 3 font.
    Font,
    /// A Type 3 font's glyph procedure.
    Glyph,
    /// A `/Resources /ExtGState` entry: a graphics state parameter dictionary.
    GState,
    /// A graphics state's `/SMask`: a soft-mask dictionary, whose `/G` is drawn.
    SoftMask,
}

/// What an indirect dictionary [`SignedNames::queue_resources`] reads is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Role {
    /// A `/Resources` dictionary.
    Resources,
    /// A category dictionary of a resource dictionary (`/XObject`, `/Pattern`, `/Font`,
    /// `/ExtGState`), by what its entries are drawn as.
    Category(Drawn),
    /// A Type 3 font's `/CharProcs`.
    CharProcs,
}

/// Calls `visit` with each name token of a default appearance string (§12.7.4.3) or a content
/// stream (§7.8.2) until it returns `false`: **every** name token, read with the PDF tokenizer,
/// so a name ends at white-space or a delimiter (§7.2.3: `0 g/F2 20 Tf` and `/F2 20 Tf/F3 9 Tf`
/// name `F2` and `F3`), its `#xx` escapes are decoded (§7.3.5), and strings and comments are
/// skipped (QA and expert finding: splitting at white-space only read `0 g/F2` as one token). A
/// strict reader takes only the operands of the operators that select a resource (`Tf`, `Do`,
/// `cs`, `gs`, ...), but readers differ on an operator run together with what follows (§7.2.3
/// makes `Tf0` one token, while pdf.js splits the known operator off and reads `/Helv 12 Tf0 g`
/// as `/Helv 12 Tf 0 g`), so any name counts: a superset, which only makes the `/DR` guard
/// stricter.
///
/// A name written with `#xx` escapes counts both decoded and as written (M4 QA round 3,
/// variant `R2y-noap-da-hexname-dr-gains-literal-hash-name`: a reader that does not decode the
/// escapes of a `/DA` string's names looks up the name as written).
///
/// `false` when the data has an inline image (an `ID` operator, §8.9.7): its binary data is not
/// made of tokens, and a `(` in it would hide the names after it from the tokenizer while
/// content readers skip to `EI`.
fn for_each_name_token(data: &[u8], mut visit: impl FnMut(&[u8]) -> bool) -> bool {
    let mut lexer = Lexer::new(data, 0);
    loop {
        let before = lexer.position();
        match lexer.next_token() {
            Ok(None) => return true,
            Ok(Some(token)) => match token.kind {
                TokenKind::Name(name) => {
                    if !visit(&name) {
                        return true;
                    }
                    let written = data.get(token.start + 1..token.end).unwrap_or_default();
                    if written != name.as_ref() && !visit(written) {
                        return true;
                    }
                }
                TokenKind::Keyword(b"ID") => return false,
                _ => {}
            },
            // The lexer moves past the bad input; stop if it could not.
            Err(_) if lexer.position() > before => {}
            Err(_) => return true,
        }
    }
}

/// Records where `value` (the object `from`, or the trailer) refers to the `watched` numbers,
/// with the path to each reference.
///
/// A `/Parent` entry that refers to a field of `field_tree` is skipped: that is the field tree's
/// back link (a kid widget to its field), which pyHanko's paths skip too. Any other `/Parent` is
/// a use: a page inherits `/Resources`, `/MediaBox`, `/CropBox` and `/Rotate` from its `/Parent`
/// chain (§7.7.3.4), and pdf.js, MuPDF and pdfium follow `/Parent` for them, so a trailer `/Info`
/// or catalog `/MarkInfo` dictionary that is a page's `/Parent` is page content (expert finding:
/// the shadow Replace through page-attribute inheritance; stricter than pyHanko, which skips
/// every `/Parent`).
fn record_usages(
    value: &Object,
    from: Referrer,
    watched: &BTreeSet<u32>,
    field_tree: &BTreeSet<u32>,
    usages: &mut BTreeMap<u32, Vec<Usage>>,
    crowded: &mut BTreeSet<u32>,
) {
    let mut stack: Vec<(&Object, Vec<Step>, bool)> = vec![(value, Vec::new(), false)];
    while let Some((obj, path, objr)) = stack.pop() {
        if path.len() > MAX_REF_DEPTH {
            continue;
        }
        let dict = match obj {
            Object::Ref(id) => {
                if watched.contains(&id.num) {
                    let uses = usages.entry(id.num).or_default();
                    if uses.len() < MAX_USAGES {
                        uses.push(Usage { from, path, objr });
                    } else {
                        crowded.insert(id.num);
                    }
                }
                continue;
            }
            Object::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    if matches!(item, Object::Ref(_) | Object::Array(_) | Object::Dict(_)) {
                        let mut next = path.clone();
                        next.push(Step::Index(index));
                        stack.push((item, next, false));
                    }
                }
                continue;
            }
            Object::Dict(dict) => dict,
            Object::Stream(stream) => &stream.dict,
            _ => continue,
        };
        let is_objr = dict.is_type(b"OBJR");
        for (key, item) in dict.iter() {
            if !matches!(item, Object::Ref(_) | Object::Array(_) | Object::Dict(_)) {
                continue;
            }
            if key.as_bytes() == b"Parent"
                && matches!(item, Object::Ref(id) if field_tree.contains(&id.num))
            {
                continue;
            }
            let mut next = path.clone();
            next.push(Step::Key(key.as_bytes().to_vec()));
            stack.push((item, next, is_objr && key.as_bytes() == b"Obj"));
        }
    }
}

/// The level, the change classes and the reasons of one analysis.
struct Diff {
    level: ModificationLevel,
    classes: BTreeSet<ChangeClass>,
    notes: Vec<String>,
}

impl Diff {
    fn raise(&mut self, level: ModificationLevel) {
        self.level = self.level.max(level);
    }

    /// A change allowed at `level` (below `Other`), of class `class`.
    fn allow(&mut self, level: ModificationLevel, class: ChangeClass) {
        self.raise(level);
        if level < ModificationLevel::Other {
            self.classes.insert(class);
        }
    }

    fn other(&mut self, note: String) {
        self.raise(ModificationLevel::Other);
        if self.notes.len() < MAX_NOTES && !self.notes.contains(&note) {
            self.notes.push(note);
        }
    }
}

/// What a new object is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NewKind {
    /// The cross-reference stream of a later revision.
    XrefStream,
    /// An object stream.
    ObjStm,
    /// A terminal signature field (merged with its widget, or with no widget), visible or not.
    SigField {
        /// Its `/Rect` has an area (or cannot be read).
        visible: bool,
        /// It is a widget annotation (`/Subtype /Widget`), so it may join a page's `/Annots`.
        widget: bool,
    },
    /// A signature dictionary or a document timestamp.
    SigDict { timestamp: bool },
    /// Anything else.
    Other,
}

/// The kind of a new object from its value; `store` (the new revision's view) reads an
/// indirect `/Rect`.
///
/// A signature field is `/FT /Sig` (direct) without `/Kids`, with a direct string `/T` whose
/// text has no `.` (§12.7.4.2; pyHanko's field listing skips or refuses the others), and if it
/// has a `/Subtype`, it is `/Widget` (a `/Stamp` with `/FT /Sig` is no signature field).
fn classify_new(store: &Store, value: &Object) -> NewKind {
    if let Object::Stream(stream) = value {
        return if stream.dict.is_type(b"ObjStm") {
            NewKind::ObjStm
        } else {
            NewKind::Other
        };
    }
    let Some(dict) = value.as_dict() else {
        return NewKind::Other;
    };
    let has_signature_keys = dict.contains_key(b"ByteRange") || dict.contains_key(b"Contents");
    if dict.is_type(b"DocTimeStamp") && has_signature_keys {
        return NewKind::SigDict { timestamp: true };
    }
    if dict.is_type(b"Sig") && has_signature_keys {
        return NewKind::SigDict { timestamp: false };
    }
    let is_sig = dict.get_name(b"FT").is_some_and(|ft| ft == b"Sig");
    let name_ok = dict
        .get_str_bytes(b"T")
        .is_some_and(|t| !folioxide_model::text::decode_text_string(t).contains('.'));
    let subtype = dict.get(b"Subtype");
    let widget = dict.get_name(b"Subtype").is_some_and(|s| s == b"Widget");
    if is_sig && name_ok && !dict.contains_key(b"Kids") && (subtype.is_none() || widget) {
        return NewKind::SigField {
            visible: is_visible(store, dict),
            widget,
        };
    }
    NewKind::Other
}

/// The keys a new signature field (merged with its widget) may carry (M4 brief §5.3; QA round 2,
/// finding 23: a whitelist, as DECISIONS D12 demands): every other key is `Other`.
///
/// - What signers write (Folioxide, pyHanko 0.37 `SignatureFormField`, Acrobat): `/Type`,
///   `/Subtype`, `/FT`, `/T`, `/V`, `/F` (whitelisted values), `/Rect` (four numbers), `/P`,
///   `/AP` (a new form XObject), `/MK` (Acrobat's appearance characteristics; Folioxide writes
///   `/MK /R` on rotated pages); pyHanko also writes `/Lock` (a field lock with `/P` when an
///   approval sets DocMDP permissions) and `/SV` (seed values) on fields it creates: they
///   constrain what may be done after the new signature, which that signature's own report
///   judges (R-4), and change nothing the evaluated signature's signer saw.
/// - Descriptive or appearance entries whose effect stays inside the widget's `/Rect` (QA probes
///   in poppler and PDFium, 0 pixels outside, also with a 60-unit `/Border` and an `/MK`
///   background without `/AP`): `/TU`, `/TM`, `/Ff` (no signature field flag shows anything),
///   `/DA`, `/Q`, `/BS`, `/Border`, `/C`, `/H`, `/CA`, `/ca`, `/BM`, `/NM`, `/M`, `/Contents`,
///   `/Lang`, `/StructParent` (a link into the structure tree, which may not change), and `/AS`
///   (ignored: the appearance must be one stream).
///
/// Refused, in particular: an action `/A` (§12.5.6.19) or additional actions `/AA` (§12.6.3: on
/// focus, on page open, on activation), optional content `/OC` (§8.11: it shows or hides the
/// widget by a state set elsewhere), a `/Parent` (a field at the root of `/Fields` has none,
/// §12.7.4.1), `/Kids`, `/DV`, `/RV`, `/DS`, `/AF`, `/Popup` and every key of no signature
/// field or widget. A JavaScript, launch or URI action on a new invisible field would otherwise
/// pass as an LTA update (brief §5 V10 (1); stricter than pyHanko).
const SIG_FIELD_KEYS: &[&[u8]] = &[
    b"Type",
    b"Subtype",
    b"FT",
    b"T",
    b"V",
    b"F",
    b"Rect",
    b"P",
    b"AP",
    b"MK",
    b"Lock",
    b"SV",
    b"TU",
    b"TM",
    b"Ff",
    b"DA",
    b"Q",
    b"BS",
    b"Border",
    b"C",
    b"H",
    b"CA",
    b"ca",
    b"BM",
    b"NM",
    b"M",
    b"Contents",
    b"Lang",
    b"StructParent",
    b"AS",
];

/// The first key of the new signature field `value` that [`SIG_FIELD_KEYS`] does not allow.
fn forbidden_sig_field_key(value: &Object) -> Option<String> {
    let dict = value.as_dict()?;
    dict.keys()
        .map(|key| key.as_bytes())
        .find(|key| !SIG_FIELD_KEYS.contains(key))
        .map(|key| String::from_utf8_lossy(key).into_owned())
}

/// Why the new signature widget `value` (in `store`, the view of the revision that adds it,
/// whose new objects are `new_values`) is not one a signer writes: annotation flags other than
/// [`geometry::ALLOWED_ANNOTATION_FLAGS`] (manager ruling R-3: legitimate signers write 4 or
/// 132; NoRotate on a rotated page paints outside the `/Rect`, QA finding R3), a widget whose
/// `/Rect` is not four finite numbers (QA round 2, finding 4: viewers read an entry they cannot
/// use as 0 and paint the appearance elsewhere than the `/Rect` says; signers write `[0 0 0 0]`
/// for an invisible one), or an appearance that is not new form XObjects clipped to the `/Rect`
/// ([`new_appearance_problem`]).
fn new_widget_problem(
    store: &Store,
    new_values: &BTreeMap<u32, Rc<Fact>>,
    value: &Object,
    visible: bool,
) -> Option<String> {
    let dict = value.as_dict()?;
    if let Some(problem) = geometry::annotation_flags_problem(store, dict) {
        return Some(problem);
    }
    let widget = dict.get_name(b"Subtype").is_some_and(|s| s == b"Widget");
    if widget && geometry::rect_of(store, dict).is_none() {
        return Some(format!(
            "has no /Rect of four finite numbers within ±{:e}, so viewers place its appearance \
             elsewhere than its /Rect says (they read an entry they cannot use as 0, and PDFium \
             maps a larger one in single precision; ISO 32000-2 §12.5.2: /Rect is required)",
            geometry::MAX_GEOMETRY_MAGNITUDE
        ));
    }
    let rect = geometry::rect_of(store, dict);
    new_appearance_problem(store, new_values, dict.get(b"AP"), visible, rect, false)
}

/// Why the `/AP` value `ap` of a new or changed annotation (in `store`, whose new objects are
/// `new_values`) is not an appearance that viewers clip to the annotation's `/Rect` (QA finding
/// R5, manager ruling R-2): it must be a direct dictionary or a new one, with only `/N`
/// (required), `/D` and `/R`, each a reference to a **new** stream that is a form XObject with a
/// `/BBox` ([`geometry::appearance_stream_problem`]); an existing object, such as the page's
/// content stream, is never an appearance a later revision may name. `required`: an annotation
/// without `/AP` is refused too (a viewer would synthesize one, R-2). `rect`: the annotation's
/// `/Rect` ([`geometry::rect_of`]), which the appearance is mapped onto.
fn new_appearance_problem(
    store: &Store,
    new_values: &BTreeMap<u32, Rc<Fact>>,
    ap: Option<&Object>,
    visible: bool,
    rect: Option<geometry::Rect>,
    required: bool,
) -> Option<String> {
    let Some(ap) = ap else {
        return required.then(|| {
            "has no appearance stream (/AP /N), so viewers synthesize one from its other \
             entries, which may reach outside its /Rect"
                .to_owned()
        });
    };
    if let Object::Ref(id) = ap
        && !new_values.contains_key(&id.num)
    {
        return Some(format!(
            "has an /AP that is the existing object {id}, which the revision reuses"
        ));
    }
    let Some(dict) = store.deref(ap).ok().and_then(|ap| ap.as_dict().cloned()) else {
        return Some("has an /AP that is not a dictionary".to_owned());
    };
    if !dict.contains_key(b"N") {
        return Some("has an /AP without /N".to_owned());
    }
    for (key, value) in dict.iter() {
        let key = key.as_bytes();
        if !matches!(key, b"N" | b"D" | b"R") {
            return Some(format!(
                "has /AP /{}, which is not an appearance (only /N, /D and /R)",
                String::from_utf8_lossy(key)
            ));
        }
        let name = String::from_utf8_lossy(key);
        if let Object::Ref(id) = value
            && !new_values.contains_key(&id.num)
        {
            return Some(format!(
                "has an appearance /{name} that is the existing object {id} (for example the \
                 page's content stream), not a new appearance stream"
            ));
        }
        if let Some(problem) = geometry::appearance_stream_problem(store, value, visible, rect) {
            return Some(format!("has an appearance /{name} that {problem}"));
        }
    }
    None
}

/// Whether an annotation shows anything (§12.5.2): its `/Rect`, read through references, has an
/// area. No `/Rect` (or `null`) is invisible, as in pyHanko; a `/Rect` that cannot be read as
/// four numbers counts as visible (the stricter level). That only decides the level of a field
/// that is kept: a new signature widget whose `/Rect` is not four finite numbers is `Other`
/// whatever it shows ([`new_widget_problem`]; QA round 2, finding 4), and so is a signed
/// existing field given an appearance with one ([`Rules::unsigned_sig_field`]).
fn is_visible(store: &Store, dict: &Dict) -> bool {
    let Some(rect) = dict.get(b"Rect") else {
        return false;
    };
    let Ok(rect) = store.deref(rect) else {
        return true;
    };
    match &*rect {
        Object::Null => false,
        Object::Array(items) => match items.as_slice() {
            [x1, y1, x2, y2] => match (x1.as_f64(), y1.as_f64(), x2.as_f64(), y2.as_f64()) {
                // pyHanko: `abs(x1 - x2) * abs(y1 - y2)`, visible unless exactly 0 (NaN counts).
                (Some(x1), Some(y1), Some(x2), Some(y2)) => {
                    (x1 - x2).abs() * (y1 - y2).abs() != 0.0
                }
                _ => true,
            },
            _ => true,
        },
        _ => true,
    }
}

/// The level of a change of the trailer's `/Info` or the catalog's `/Extensions` or `/MarkInfo`
/// object (`what`): `LtaUpdates` for a dictionary that stays a dictionary (pyHanko's
/// `safe_whitelist`: never a stream), `Other` otherwise, and `Other` when either version
/// carries page-tree or form-field material ([`is_page_or_field_material`]).
fn information(
    old: &Object,
    new: &Object,
    what: &'static str,
) -> (ModificationLevel, &'static str) {
    match (old, new) {
        (Object::Dict(o), Object::Dict(n))
            if is_page_or_field_material(o) || is_page_or_field_material(n) =>
        {
            (
                ModificationLevel::Other,
                "a dictionary with page-tree or form-field entries (/Kids, /Resources, /MediaBox, \
                 /CropBox, /Rotate, /FT, /V or /DA) that is also the trailer's /Info or the \
                 catalog's /Extensions or /MarkInfo",
            )
        }
        (Object::Dict(_), Object::Dict(_)) => (ModificationLevel::LtaUpdates, what),
        _ => (ModificationLevel::Other, what),
    }
}

/// The keys of a page-tree node (`/Kids` and the inheritable `/Resources /MediaBox /CropBox
/// /Rotate`, §7.7.3.3–7.7.3.4) and of a form field (`/FT /V /DA`, §12.7.4).
const PAGE_OR_FIELD_KEYS: &[&[u8]] = &[
    b"Kids",
    b"Resources",
    b"MediaBox",
    b"CropBox",
    b"Rotate",
    b"FT",
    b"V",
    b"DA",
];

/// Whether a dictionary carries page-tree or form-field material (`/Type /Pages` or `/Page`, or
/// a key of [`PAGE_OR_FIELD_KEYS`]). A trailer `/Info`, catalog `/Extensions` or `/MarkInfo`
/// dictionary that does is not only document information, whatever refers to it: a page whose
/// `/Parent` it is inherits its `/Resources`, `/MediaBox`, `/CropBox` and `/Rotate` in pdf.js,
/// MuPDF and pdfium (§7.7.3.4; expert finding, the shadow Replace through page-attribute
/// inheritance).
fn is_page_or_field_material(dict: &Dict) -> bool {
    dict.is_type(b"Pages")
        || dict.is_type(b"Page")
        || PAGE_OR_FIELD_KEYS.iter().any(|key| dict.contains_key(key))
}

/// The page tree of a revision as the `/Kids` walk from the catalog's `/Pages` reads it (manager
/// ruling R-13, M4 QA round 3, finding 11). Readers find a page and its inherited attributes in
/// different ways: poppler and Folioxide's model along the `/Kids` path the walk took, PDFium and
/// pdf.js along the page's `/Parent` chain. They agree only when every node's `/Parent` is the
/// node whose `/Kids` lists it, the root has none, no node is reached twice and no page is listed
/// twice; a rule that depends on the page (its rotation for a Text annotation, which page an
/// annotation or a signature widget is on) holds only for such a tree.
#[derive(Debug, Default)]
struct PageWalk {
    /// Why the tree as a whole is not one every reader walks the same way.
    problem: Option<String>,
    /// The intermediate nodes walked: the node, its indirect `/Kids` array if any, and the index
    /// of its parent node (`None` for the root).
    nodes: Vec<(ObjectId, Option<u32>, Option<usize>)>,
    /// The pages, by object number: the page, the index of the node that lists it (`None` when
    /// the root is the page), and how many times the walk reached it.
    pages: HashMap<u32, (ObjectId, Option<usize>, usize)>,
}

impl PageWalk {
    /// Walks the page tree of `store` (whose catalog is `catalog`) from the catalog's `/Pages`:
    /// iterative, each node once, at most `max_depth` levels and `max_steps` objects and kids.
    /// `steps` returns the objects and kids visited (work for the budget).
    fn read(
        store: &Store,
        catalog: Option<&Dict>,
        max_depth: usize,
        max_steps: u64,
    ) -> (Self, u64) {
        let mut walk = PageWalk::default();
        let mut steps = 0u64;
        let fail = |mut walk: PageWalk, reason: String, steps: u64| {
            walk.problem = Some(reason);
            (walk, steps)
        };
        let Some(Object::Ref(root)) = catalog.and_then(|c| c.get(b"Pages")) else {
            return fail(
                walk,
                "the catalog's /Pages is not an indirect reference (ISO 32000-2 §7.7.2)".to_owned(),
                steps,
            );
        };
        let mut visited: HashSet<ObjectId> = HashSet::new();
        // (object, the index of the node whose /Kids lists it, depth)
        let mut stack: Vec<(ObjectId, Option<usize>, usize)> = vec![(*root, None, 0)];
        while let Some((id, parent, depth)) = stack.pop() {
            steps = steps.saturating_add(1);
            if steps > max_steps || depth > max_depth {
                return fail(
                    walk,
                    "the page tree is too large or too deep to walk within the limits".to_owned(),
                    steps,
                );
            }
            let Ok(value) = store.resolve(id) else {
                return fail(
                    walk,
                    format!("the page-tree object {id} cannot be read"),
                    steps,
                );
            };
            let Some(dict) = value.as_dict() else {
                return fail(
                    walk,
                    format!("the page-tree object {id} is not a dictionary"),
                    steps,
                );
            };
            // §7.7.3.2: /Parent is required in every node but the root, where it is
            // prohibited, and is the node that lists it.
            let expected = parent.and_then(|i| walk.nodes.get(i)).map(|node| node.0);
            let parent_ok = match (dict.get(b"Parent"), expected) {
                (None, None) => true,
                (Some(Object::Ref(named)), Some(expected)) => *named == expected,
                _ => false,
            };
            if !parent_ok {
                return fail(
                    walk,
                    format!(
                        "the /Parent of the page-tree object {id} is not the node whose /Kids \
                         lists it, so readers that follow /Parent (PDFium, pdf.js) and readers \
                         that follow /Kids (poppler) inherit different attributes (ISO 32000-2 \
                         §7.7.3.2, §7.7.3.4)"
                    ),
                    steps,
                );
            }
            // §7.7.3.3: only a /Pages node has /Kids, and only a page /Contents or /Annots
            // (Table 31). Readers tell the two apart differently (poppler by /Type, PDFium by
            // /Kids), so a dictionary that is both walks as a leaf in one and a node in the
            // other, and they number the pages and inherit attributes differently (M4 QA round
            // 4, finding 10).
            let page_only = [b"Contents".as_slice(), b"Annots"]
                .iter()
                .any(|key| dict.contains_key(key));
            let is_node = match dict.get_name(b"Type").map(|t| t.as_bytes()) {
                Some(b"Pages") => true,
                Some(b"Page") if dict.contains_key(b"Kids") => {
                    return fail(
                        walk,
                        format!(
                            "the page {id} has /Kids, which readers walk as a page (poppler, by \
                             its /Type) or as a node (PDFium), so they number the pages \
                             differently (ISO 32000-2 §7.7.3.3)"
                        ),
                        steps,
                    );
                }
                Some(b"Page") => false,
                None if dict.contains_key(b"Kids") && page_only => {
                    return fail(
                        walk,
                        format!(
                            "the page-tree object {id} has no /Type and both /Kids and a key \
                             only a page has, so readers walk it as a page or as a node (ISO \
                             32000-2 §7.7.3.3)"
                        ),
                        steps,
                    );
                }
                None => dict.contains_key(b"Kids"),
                Some(_) => {
                    return fail(
                        walk,
                        format!("the page-tree object {id} is neither /Pages nor /Page"),
                        steps,
                    );
                }
            };
            if !is_node {
                let page = walk.pages.entry(id.num).or_insert((id, parent, 0));
                if page.0 != id {
                    return fail(
                        walk,
                        format!("the page tree lists object {} with two generations", id.num),
                        steps,
                    );
                }
                page.2 += 1;
                continue;
            }
            if !visited.insert(id) {
                return fail(
                    walk,
                    format!(
                        "the page-tree node {id} is reached twice (a cycle, or listed by two \
                         nodes), so readers count its pages differently"
                    ),
                    steps,
                );
            }
            let (kids, kids_array) = match dict.get(b"Kids") {
                Some(Object::Array(items)) => (Some(items.clone()), None),
                Some(Object::Ref(array)) => (
                    store
                        .resolve(*array)
                        .ok()
                        .and_then(|a| a.as_array().map(<[Object]>::to_vec)),
                    Some(array.num),
                ),
                _ => (None, None),
            };
            let Some(kids) = kids else {
                return fail(
                    walk,
                    format!("the page-tree node {id} has no /Kids array"),
                    steps,
                );
            };
            let index = walk.nodes.len();
            walk.nodes.push((id, kids_array, parent));
            for kid in &kids {
                steps = steps.saturating_add(1);
                let Object::Ref(kid) = kid else {
                    return fail(
                        walk,
                        format!("the /Kids of the page-tree node {id} holds a direct object"),
                        steps,
                    );
                };
                stack.push((*kid, Some(index), depth + 1));
            }
        }
        (walk, steps)
    }

    /// The page and its ancestors up to the root (nearest first), and every object a reader
    /// consults for `page` (those, with their indirect `/Kids` arrays); `Err` when the tree or
    /// the page is not one every reader reads the same way: the page is reached exactly once by
    /// the walk, and its `/Parent` chain is the reverse of the walk's path (checked for every
    /// node).
    fn path(&self, page: ObjectId) -> std::result::Result<(Vec<ObjectId>, Vec<u32>), String> {
        if let Some(problem) = &self.problem {
            return Err(problem.clone());
        }
        let Some(&(id, parent, count)) = self.pages.get(&page.num) else {
            return Err(format!(
                "the page {page} is not reached by the /Kids walk from the catalog's /Pages"
            ));
        };
        if id != page {
            return Err(format!("the page tree lists {id}, not the page {page}"));
        }
        if count != 1 {
            return Err(format!(
                "the page tree lists the page {page} {count} times, so readers count it as \
                 different pages"
            ));
        }
        let mut chain = vec![page];
        let mut consulted = vec![page.num];
        let mut next = parent;
        while let Some(index) = next {
            let Some(&(node, kids_array, up)) = self.nodes.get(index) else {
                break;
            };
            chain.push(node);
            consulted.push(node.num);
            consulted.extend(kids_array);
            // Nodes come before their kids, so the indices fall and the loop ends.
            next = up.filter(|&up| up < index);
        }
        Ok((chain, consulted))
    }
}

/// Whether object `id` of `store` is a stream.
fn is_stream(store: &Store, id: ObjectId) -> bool {
    store
        .resolve(id)
        .is_ok_and(|value| matches!(*value, Object::Stream(_)))
}

/// The categories of an AcroForm `/DR` resource dictionary (§7.8.3, Table 34) that may gain
/// new names after signing ([`Rules::resource_names`]); `/ProcSet`, an array, may gain names
/// too ([`Rules::proc_sets`]). Any other `/DR` entry must stay as it was.
const DR_CATEGORIES: &[&[u8]] = &[
    b"Font",
    b"XObject",
    b"ColorSpace",
    b"ExtGState",
    b"Pattern",
    b"Shading",
];

/// The rules for changed objects (brief §5 V10).
struct Rules<'a, 'b, 'd> {
    cx: &'a Cx<'b, 'd>,
    /// What the analyses know about the signed revision (the names it takes from `/DR`).
    base: &'a Base,
    /// Why the rules applied to the current object refused a change (for the notes).
    reasons: RefCell<Vec<String>>,
    /// The classes of the changes the rules allowed for the current object.
    classes: RefCell<BTreeSet<ChangeClass>>,
    /// The new annotations the pages' `/Annots` gained that the §5.2 whitelist allowed.
    annotations: RefCell<BTreeSet<u32>>,
    /// What [`Rules::annotation_content`] found for each new annotation, checked once per
    /// comparison however many pages list it.
    annotation_checks: RefCell<HashMap<u32, std::result::Result<(), String>>>,
}

/// The markup annotation subtypes a later revision may add after a certification with `P = 3`
/// (M4 brief §5.2 A1; ISO 32000-2 §12.5.6.2, Table 171); a `Popup` may join one (A4).
const MARKUP_SUBTYPES: &[&[u8]] = &[
    b"Text",
    b"FreeText",
    b"Line",
    b"Square",
    b"Circle",
    b"Polygon",
    b"PolyLine",
    b"Highlight",
    b"Underline",
    b"Squiggly",
    b"StrikeOut",
    b"Caret",
    b"Ink",
    b"Stamp",
];

/// The keys every annotation of brief §5.2 may have (§12.5.2, Table 166).
const ANNOTATION_COMMON_KEYS: &[&[u8]] = &[
    b"Type",
    b"Subtype",
    b"Rect",
    b"Contents",
    b"P",
    b"NM",
    b"M",
    b"F",
    b"AP",
    b"AS",
    b"Border",
    b"C",
    b"BS",
    b"CA",
    b"ca",
    b"BM",
    b"Lang",
];

/// The keys of a markup annotation (§12.5.6.2, Table 170).
const ANNOTATION_MARKUP_KEYS: &[&[u8]] = &[
    b"T",
    b"Popup",
    b"RC",
    b"CreationDate",
    b"IRT",
    b"Subj",
    b"RT",
    b"IT",
];

/// The keys of one annotation subtype (brief §5.2 A2).
fn annotation_subtype_keys(subtype: &[u8]) -> &'static [&'static [u8]] {
    match subtype {
        b"Text" => &[b"Open", b"Name", b"State", b"StateModel"],
        b"FreeText" => &[b"DA", b"Q", b"DS", b"CL", b"BE", b"RD", b"LE"],
        b"Line" => &[
            b"L", b"LE", b"IC", b"LL", b"LLE", b"Cap", b"LLO", b"CP", b"CO",
        ],
        b"Square" | b"Circle" => &[b"IC", b"BE", b"RD"],
        b"Polygon" | b"PolyLine" => &[b"Vertices", b"LE", b"IC", b"BE", b"Path"],
        b"Highlight" | b"Underline" | b"Squiggly" | b"StrikeOut" => &[b"QuadPoints"],
        b"Caret" => &[b"RD", b"Sy"],
        b"Ink" => &[b"InkList", b"Path"],
        b"Stamp" => &[b"Name"],
        b"Popup" => &[b"Parent", b"Open"],
        _ => &[],
    }
}

impl Rules<'_, '_, '_> {
    /// `Other`, with `reason` for the notes.
    fn refuse(&self, reason: impl Into<String>) -> ModificationLevel {
        self.reasons.borrow_mut().push(reason.into());
        ModificationLevel::Other
    }

    /// Records the class of a change the current rule allows.
    fn class(&self, class: ChangeClass) {
        self.classes.borrow_mut().insert(class);
    }

    /// The number of the object the new trailer's `key` refers to.
    fn new_trailer_ref(&self, key: &[u8]) -> Option<u32> {
        self.cx.new.trailer().get_ref(key).map(|id| id.num)
    }

    /// The number of the object the new catalog's `key` refers to.
    fn new_catalog_ref(&self, key: &[u8]) -> Option<u32> {
        self.cx
            .new_catalog
            .and_then(|catalog| catalog.get_ref(key))
            .map(|id| id.num)
    }

    /// The number of the array the new AcroForm's `/Fields` refers to.
    fn new_fields_ref(&self) -> Option<u32> {
        field::acroform_of(self.cx.new, self.cx.new_catalog)
            .ok()
            .flatten()
            .and_then(|acroform| acroform.dict.get_ref(b"Fields"))
            .map(|id| id.num)
    }

    /// Whether every page whose `/Annots` the array `num` is in the signed revision (`owners`)
    /// still names it in the new revision.
    fn annots_still_owned(&self, num: u32, owners: &[ObjectId]) -> bool {
        owners.iter().all(|&page| {
            self.cx.new.resolve(page).ok().is_some_and(|page| {
                page.as_dict()
                    .and_then(|d| d.get_ref(b"Annots"))
                    .is_some_and(|id| id.num == num)
            })
        })
    }

    fn is_new_sig_field(&self, obj: &Object, on_page: bool) -> bool {
        obj.as_ref().is_some_and(|id| {
            matches!(self.cx.kinds.get(&id.num), Some(NewKind::SigField { widget, .. }) if *widget || !on_page)
        })
    }

    fn is_new_sig_dict(&self, obj: &Object) -> bool {
        obj.as_ref().is_some_and(|id| {
            matches!(
                self.cx.kinds.get(&id.num),
                Some(NewKind::SigDict { timestamp: false })
            )
        })
    }

    fn classify(&self, base: &Base, change: &Changed, diff: &mut Diff) -> ModificationLevel {
        let (id, old, new) = (change.id, &*change.old, &*change.new);
        let num = id.num;
        let r = self.cx.r;
        // Whether the role is one granted for a single path (blanket: the catalog and pages).
        let mut path_role = true;
        let (level, what) = if base.containers.contains(&num) {
            (ModificationLevel::Other, "an object stream container")
        } else if Some(num) == base.root {
            path_role = false;
            (
                self.dicts(old, new, |o, n| self.catalog(o, n)),
                "the catalog",
            )
        } else if Some(num) == base.acroform {
            let level = if self.new_catalog_ref(b"AcroForm") == Some(num) {
                self.dicts(old, new, |o, n| self.acroform(o, n))
            } else {
                self.refuse("the new catalog no longer names it as /AcroForm")
            };
            (level, "the AcroForm")
        } else if Some(num) == base.fields_array {
            let level = if self.new_fields_ref() == Some(num) {
                self.arrays(old, new, None)
            } else {
                self.refuse("the new AcroForm no longer names it as /Fields")
            };
            (level, "the AcroForm /Fields array")
        } else if let Some(&(signature, signed, terminal)) = base.fields.get(&num) {
            if signature && !signed && terminal {
                (
                    self.dicts(old, new, |o, n| self.unsigned_sig_field(num, o, n)),
                    "an unsigned signature field",
                )
            } else if signature && signed {
                (ModificationLevel::Other, "a signed signature field")
            } else if let Some(field) = base.form.fields.get(&num) {
                (
                    self.dicts(old, new, |o, n| self.form_field(num, field, o, n)),
                    "a form field",
                )
            } else {
                // A field that is not terminal, or of no known type.
                (ModificationLevel::Other, "a form field")
            }
        } else if base.form.kid_widgets.contains(&num) {
            (
                self.refuse(
                    "the widget is a kid of its field, and pyHanko 0.37 allows no change to such \
                     a widget (probes: a radio button's /AS, a kid widget's /AP); only the \
                     field's /V may change",
                ),
                "a form field's widget",
            )
        } else if let Some(&owner) = base.form.ap_dicts.get(&num) {
            (
                self.dicts(old, new, |o, n| self.form_ap_dict(owner, num, o, n)),
                "a form field's appearance dictionary",
            )
        } else if let Some(&owner) = base.form.ap_streams.get(&num) {
            (
                self.form_ap_stream(owner, num, new),
                "a form field's appearance stream",
            )
        } else if base.pages.contains(&num) {
            path_role = false;
            (self.dicts(old, new, |o, n| self.page(id, o, n)), "a page")
        } else if let Some(owners) = base.annots_arrays.get(&num) {
            let level = if self.annots_still_owned(num, owners) {
                self.arrays(old, new, Some(owners))
            } else {
                self.refuse("a page no longer names it as /Annots")
            };
            (level, "a page's /Annots array")
        } else if Some(num) == base.info {
            // pyHanko's safe_whitelist: an updated dictionary, never a stream; and only the
            // dictionary the new trailer names (QA finding: the old /Info changed while the
            // trailer moves to a new one or drops /Info).
            if self.new_trailer_ref(b"Info") == Some(num) {
                let class = match (old.as_dict(), new.as_dict()) {
                    (Some(o), Some(n)) => self.cx.info_class(num, o, n),
                    _ => ChangeClass::Metadata,
                };
                self.class(class);
                information(old, new, "the document information dictionary")
            } else {
                (
                    self.refuse("the new trailer no longer names it as /Info"),
                    "the document information dictionary",
                )
            }
        } else if Some(num) == base.metadata {
            let level = if self.new_catalog_ref(b"Metadata") != Some(num) {
                self.refuse("the new catalog no longer names it as /Metadata")
            } else if self.cx.revisions.is_xmp(self.cx.new, r, id) {
                self.class(self.cx.xmp_class(num, old, new));
                ModificationLevel::LtaUpdates
            } else {
                self.refuse("the new stream is not an XMP packet")
            };
            (level, "the XMP metadata")
        } else if Some(num) == base.extensions || Some(num) == base.mark_info {
            let key: &[u8] = if Some(num) == base.extensions {
                b"Extensions"
            } else {
                b"MarkInfo"
            };
            if self.new_catalog_ref(key) == Some(num) {
                let class = if key == b"Extensions" {
                    self.cx.extensions_class(num, Some(old), Some(new))
                } else {
                    ChangeClass::Metadata
                };
                self.class(class);
                information(old, new, "the catalog's /Extensions or /MarkInfo")
            } else {
                (
                    self.refuse(format!(
                        "the new catalog no longer names it as /{}",
                        String::from_utf8_lossy(key)
                    )),
                    "the catalog's /Extensions or /MarkInfo",
                )
            }
        } else {
            (ModificationLevel::Other, "an object")
        };
        let reasons = std::mem::take(&mut *self.reasons.borrow_mut());
        if level == ModificationLevel::Other {
            if reasons.is_empty() {
                diff.other(format!("revision {r} changes {what} ({id})"));
            }
            for reason in reasons {
                diff.other(format!("revision {r} changes {what} ({id}): {reason}"));
            }
            return level;
        }
        if path_role && let Some(reason) = &base.usage_defect {
            diff.other(format!(
                "revision {r} changes {what} ({id}), but where the signed revision uses it \
                 cannot be known, since not every object of it reads the same in every reader \
                 ({reason}; manager ruling R-12)"
            ));
            return ModificationLevel::Other;
        }
        if path_role && !base.only_used_in_role(num) {
            diff.other(format!(
                "revision {r} changes {what} ({id}), which the signed revision also uses \
                 elsewhere (for example as page content or a font)"
            ));
            return ModificationLevel::Other;
        }
        level
    }

    /// What a change explains of the new objects: the new `/AP` of an unsigned signature field
    /// that the revision signs, and its `/N /R /D` streams (pyHanko's `_allow_appearance_update`,
    /// called only for a field that goes from unsigned to signed, `FormFilling`); a page's new
    /// `/Annots` array (`LtaUpdates`); and what a filled form field's new appearance holds
    /// (brief §5.1 F6: `FormFilling`).
    fn explain_changed(&self, base: &Base, change: &Changed, explained: &mut Explained) {
        let num = change.id.num;
        // F6: an in-place appearance stream's new dependencies (fonts, images).
        if base.form.ap_streams.contains_key(&num) {
            self.cx.explain_dependencies(
                &change.new,
                ModificationLevel::FormFilling,
                ChangeClass::FormFill,
                explained,
            );
            return;
        }
        let Some(new) = change.new.as_dict() else {
            return;
        };
        if base.is_unsigned_sig_field(num)
            && change
                .old
                .as_dict()
                .is_some_and(|old| self.signs_field(old, new))
        {
            self.explain_appearance(new.get(b"AP"), ChangeClass::Signature, explained);
        }
        // F6: a filled field's new /AP, and an indirect /AP dictionary changed in place.
        if base.form.fields.contains_key(&num) {
            let old_ap = change.old.as_dict().and_then(|old| old.get(b"AP"));
            if old_ap != new.get(b"AP") {
                self.explain_appearance(new.get(b"AP"), ChangeClass::FormFill, explained);
            }
        }
        if base.form.ap_dicts.contains_key(&num) {
            for key in [b"N".as_slice(), b"R", b"D"] {
                if let Some(held) = new.get(key) {
                    self.cx.explain_dependencies(
                        held,
                        ModificationLevel::FormFilling,
                        ChangeClass::FormFill,
                        explained,
                    );
                }
            }
        }
        if base.pages.contains(&num)
            && let Some(id) = new.get_ref(b"Annots").filter(|id| self.cx.is_new(*id))
        {
            let class = change
                .old
                .as_dict()
                .map_or(ChangeClass::SignatureField, |old| {
                    self.page_items_class(old, new)
                });
            explained.add(id.num, ModificationLevel::LtaUpdates, class);
        }
    }

    /// Explains, at `FormFilling` with `class`, a new `/AP` value (a new object) and what its
    /// `/N`, `/R` and `/D` hold through new objects.
    fn explain_appearance(
        &self,
        ap: Option<&Object>,
        class: ChangeClass,
        explained: &mut Explained,
    ) {
        let Some(ap) = ap else {
            return;
        };
        if let Some(id) = ap.as_ref().filter(|id| self.cx.is_new(*id)) {
            explained.add(id.num, ModificationLevel::FormFilling, class);
        }
        let ap = self.cx.new.deref(ap).ok();
        if let Some(ap) = ap.as_deref().and_then(Object::as_dict) {
            for key in [b"N".as_slice(), b"R", b"D"] {
                if let Some(held) = ap.get(key) {
                    self.cx.explain_dependencies(
                        held,
                        ModificationLevel::FormFilling,
                        class,
                        explained,
                    );
                }
            }
        }
    }

    /// The class of what a page's `/Annots` gained from `old` to `new` (page dictionaries):
    /// annotations, else a signature's, else a signature field's, else a document timestamp's.
    fn page_items_class(&self, old: &Dict, new: &Dict) -> ChangeClass {
        let list = |store: &Store, dict: &Dict| -> Vec<Object> {
            dict.get(b"Annots")
                .and_then(|value| store.deref(value).ok())
                .and_then(|value| value.as_array().map(<[Object]>::to_vec))
                .unwrap_or_default()
        };
        let (old, new) = (list(self.cx.old, old), list(self.cx.new, new));
        let added = new.strip_prefix(old.as_slice()).unwrap_or_default();
        let classes: BTreeSet<ChangeClass> = added
            .iter()
            .filter_map(Object::as_ref)
            .map(|id| {
                if self.annotations.borrow().contains(&id.num) {
                    ChangeClass::Annotation
                } else {
                    self.cx.sig_field_class(id.num)
                }
            })
            .collect();
        [
            ChangeClass::Annotation,
            ChangeClass::Signature,
            ChangeClass::SignatureField,
            ChangeClass::DocTimeStamp,
        ]
        .into_iter()
        .find(|class| classes.contains(class))
        .unwrap_or(ChangeClass::SignatureField)
    }

    /// `rule` over two dictionaries; `Other` when either is not one.
    fn dicts(
        &self,
        old: &Object,
        new: &Object,
        rule: impl Fn(&Dict, &Dict) -> ModificationLevel,
    ) -> ModificationLevel {
        match (old.as_dict(), new.as_dict()) {
            (Some(o), Some(n)) => rule(o, n),
            _ => ModificationLevel::Other,
        }
    }

    /// An array of references that may only gain new signature fields at its end (`/Fields`),
    /// or new signature widgets and the annotations of brief §5.2 (a page's `/Annots` array,
    /// `pages` the pages whose `/Annots` it is).
    fn arrays(&self, old: &Object, new: &Object, pages: Option<&[ObjectId]>) -> ModificationLevel {
        let level = match (old.as_array(), new.as_array(), pages) {
            (Some(o), Some(n), Some(pages)) => self.appended_page_items(o, n, pages),
            (Some(o), Some(n), None) => self.appended_sig_fields(o, n, false),
            _ => ModificationLevel::Other,
        };
        if level == ModificationLevel::Other {
            return self.refuse(if pages.is_some() {
                "it gains something other than new signature widgets and allowed markup \
                 annotations at its end"
            } else {
                "it gains something other than new root-level signature fields at its end"
            });
        }
        level
    }

    /// `new` is `old` plus references to new registered signature fields (widgets, when
    /// `on_page`) at the end: `LtaUpdates`.
    fn appended_sig_fields(
        &self,
        old: &[Object],
        new: &[Object],
        on_page: bool,
    ) -> ModificationLevel {
        match new.strip_prefix(old) {
            Some(added) if added.iter().all(|o| self.is_new_sig_field(o, on_page)) => {
                for id in added.iter().filter_map(Object::as_ref) {
                    self.class(self.cx.sig_field_class(id.num));
                }
                ModificationLevel::LtaUpdates
            }
            _ => ModificationLevel::Other,
        }
    }

    /// Manager ruling R-13: the effective `/Rotate` of `page` in revision `r`, or why not every
    /// reader places the page the same way ([`Revisions::page_rotation`]).
    fn page_rotation(&self, page: ObjectId) -> std::result::Result<i64, String> {
        self.cx
            .revisions
            .page_rotation(self.cx.new, self.cx.new_catalog, self.cx.r, page)
    }

    /// A page's `/Annots` (`old` and `new` lists; `pages` the pages whose `/Annots` it is): the
    /// old entries stay, in order (brief §5.2 A7), and the entries added at the end are new
    /// registered signature widgets (`LtaUpdates`) or new annotations that the §5.2 whitelist
    /// allows (A1–A5, `Annotations`, D-1), on pages every reader places the same way (manager
    /// ruling R-13: which page shows a new widget or annotation, and how it is rotated, must not
    /// depend on whether a reader follows `/Kids` or `/Parent`).
    fn appended_page_items(
        &self,
        old: &[Object],
        new: &[Object],
        pages: &[ObjectId],
    ) -> ModificationLevel {
        let Some(added) = new.strip_prefix(old) else {
            return self.refuse("its existing entries changed, were removed or were reordered");
        };
        if !added.is_empty() {
            for &page in pages {
                if let Err(reason) = self.page_rotation(page) {
                    return self.refuse(format!(
                        "it gains annotations or signature widgets on the page {page}, which not \
                         every reader places the same way: {reason} (manager ruling R-13)"
                    ));
                }
            }
        }
        // The new annotations, read in place (never copied: one annotation listed on many
        // pages costs a lookup per page; QA round 2, finding 1).
        let mut candidates: BTreeMap<u32, &Dict> = BTreeMap::new();
        for item in added {
            if self.is_new_sig_field(item, true) {
                if let Some(id) = item.as_ref() {
                    self.class(self.cx.sig_field_class(id.num));
                }
                continue;
            }
            let Some(id) = item.as_ref() else {
                return self.refuse("it gains an entry that is not a reference to a new object");
            };
            let new_values: &BTreeMap<u32, Rc<Fact>> = self.cx.new_values;
            let dict = new_values
                .get(&id.num)
                .and_then(|fact| fact.value.as_dict());
            let Some(dict) = dict else {
                return self.refuse(format!(
                    "it gains {id}, which is not a new annotation dictionary"
                ));
            };
            candidates.insert(id.num, dict);
        }
        if candidates.is_empty() {
            return ModificationLevel::LtaUpdates;
        }
        // D-1 is limited to the rows of M4 brief §0.2: a certification with P = 3, or an
        // approval signature; after a certification with P = 1 or 2 new annotations are OTHER,
        // as in pyHanko (probes `p1_square`, `p2_square`). A document timestamp is judged with
        // the permissions in force, which are 2 without a certification (ruling R-20).
        if (self.cx.ctx.certifying || self.cx.ctx.timestamp) && self.cx.ctx.permissions != Some(3) {
            return self.refuse(
                "it gains annotations after a certification signature or document timestamp \
                 whose DocMDP permissions in force do not allow them (only P = 3 permits \
                 annotation creation, D-1; manager ruling R-20)",
            );
        }
        let [page] = pages else {
            return self
                .refuse("it gains annotations, and it is the /Annots array of more than one page");
        };
        for (&num, dict) in &candidates {
            if let Err(reason) = self.markup_annotation(num, dict, *page, &candidates) {
                return self.refuse(format!("it gains the annotation {num} 0 R, which {reason}"));
            }
        }
        self.annotations.borrow_mut().extend(candidates.keys());
        self.class(ChangeClass::Annotation);
        ModificationLevel::Annotations
    }

    /// Brief §5.2 A1–A5 for the new annotation `num` (`dict`) appended to the `/Annots` of
    /// `page`, with the other new annotations appended there (`batch`); `Err` says why not. What
    /// does not depend on the page is checked once per annotation and comparison
    /// ([`Rules::annotation_content`]).
    fn markup_annotation(
        &self,
        num: u32,
        dict: &Dict,
        page: ObjectId,
        batch: &BTreeMap<u32, &Dict>,
    ) -> std::result::Result<(), String> {
        let subtype = |d: &Dict| d.get_name(b"Subtype").map(|s| s.as_bytes().to_vec());
        let known = self.annotation_checks.borrow().get(&num).cloned();
        let content = match known {
            Some(content) => content,
            None => {
                let content = self.annotation_content(dict);
                self.annotation_checks
                    .borrow_mut()
                    .insert(num, content.clone());
                content
            }
        };
        content?;
        let popup = subtype(dict).is_some_and(|kind| kind == b"Popup");
        // A1: on the page that lists it.
        if dict.get(b"P").is_some_and(|p| p.as_ref() != Some(page)) {
            return Err("names another /P than the page whose /Annots lists it (A1)".to_owned());
        }
        // QA round 2, finding 7: a Text annotation does not rotate with the page (ISO 32000-2
        // §12.5.6.4: it behaves as if the NoZoom and NoRotate flags were always set), so a viewer
        // draws it upright, anchored at the upper-left corner of its /Rect; on a rotated page
        // poppler then paints it outside the /Rect. It is allowed only on a page whose effective
        // /Rotate (inherited, §7.7.3.4, along a page tree every reader walks the same way: ruling
        // R-13, QA round 3, finding 11) is 0.
        let upright = self
            .page_rotation(page)
            .is_ok_and(|degrees| degrees.rem_euclid(360) == 0);
        if subtype(dict).is_some_and(|kind| kind == b"Text") && !upright {
            return Err(
                "is a Text annotation (a sticky note, drawn upright and unscaled at its /Rect's \
                 corner, ISO 32000-2 §12.5.6.4) on a page whose /Rotate is not 0, where viewers \
                 paint it outside its /Rect (A2)"
                    .to_owned(),
            );
        }
        let this = ObjectId::new(num, 0);
        if popup {
            // A4: the popup of a new markup annotation of the same revision, on the same page.
            let parent = dict
                .get(b"Parent")
                .and_then(Object::as_ref)
                .and_then(|parent| batch.get(&parent.num));
            match parent {
                Some(parent) if subtype(parent).is_some_and(|s| s != b"Popup") => {}
                _ => {
                    return Err(
                        "is a Popup whose /Parent is not a new markup annotation on the \
                                same page (A4)"
                            .to_owned(),
                    );
                }
            }
        } else {
            if let Some(popup) = dict.get(b"Popup") {
                let popup = popup.as_ref().and_then(|p| batch.get(&p.num));
                let ok = popup.is_some_and(|p| {
                    subtype(p).is_some_and(|s| s == b"Popup") && p.get_ref(b"Parent") == Some(this)
                });
                if !ok {
                    return Err(
                        "has a /Popup that is not its own new Popup on the same page (A4)"
                            .to_owned(),
                    );
                }
            }
            // A5: a reply refers to an annotation of the revision.
            if let Some(irt) = dict.get(b"IRT") {
                let presence = self.cx.revisions.presence_at(self.cx.new_doc, self.cx.r);
                let listed = irt
                    .as_ref()
                    .zip(presence)
                    .is_some_and(|(irt, p)| p.annotations.contains(&irt.num));
                if !listed {
                    return Err(
                        "has an /IRT that is not an annotation listed on a page (A5)".to_owned(),
                    );
                }
            }
        }
        Ok(())
    }

    /// Brief §5.2 A1–A3 for a new annotation `dict`, the checks that do not depend on the page
    /// that lists it: a markup subtype or a Popup (A1), only the keys of its kind (A2), its
    /// flags (A3), its geometry inside its `/Rect` and its own appearance stream (R-2). The
    /// geometry values are work of the verification's budget ([`geometry::geometry_work`]).
    fn annotation_content(&self, dict: &Dict) -> std::result::Result<(), String> {
        let Some(kind) = dict.get_name(b"Subtype").map(|s| s.as_bytes().to_vec()) else {
            return Err("has no /Subtype name (A1)".to_owned());
        };
        let popup = kind == b"Popup";
        let name = String::from_utf8_lossy(&kind).into_owned();
        if !popup && !MARKUP_SUBTYPES.contains(&kind.as_slice()) {
            return Err(format!(
                "is a /{name} annotation, which is not one of the markup annotations the \
                 Annotations whitelist allows (A1)"
            ));
        }
        // A2: only the keys of the annotation's kind.
        let subtype_keys = annotation_subtype_keys(&kind);
        for key in dict.keys() {
            let key = key.as_bytes();
            let allowed = ANNOTATION_COMMON_KEYS.contains(&key)
                || (!popup && ANNOTATION_MARKUP_KEYS.contains(&key))
                || subtype_keys.contains(&key);
            if !allowed {
                return Err(format!(
                    "has /{}, which a /{name} annotation may not carry (A2)",
                    String::from_utf8_lossy(key)
                ));
            }
        }
        if dict.get(b"Type").is_some_and(|t| !t.is_name(b"Annot")) {
            return Err("has a /Type other than /Annot (A2)".to_owned());
        }
        // A3 and ruling R-2: no print-only content, and no flag that draws it at a fixed size,
        // unrotated or hidden (the whitelist of geometry::ALLOWED_ANNOTATION_FLAGS).
        if let Some(problem) = geometry::annotation_flags_problem(self.cx.new, dict) {
            return Err(format!("{problem} (A3)"));
        }
        // Ruling R-2: everything it draws lies inside its /Rect: its geometry keys (with the
        // border and line endings), and an appearance stream of its own that viewers clip to
        // the /Rect (a markup annotation without one is synthesized by viewers, A2). Reading
        // the geometry is work of the verification's budget (QA round 2, finding 1).
        if !self.cx.revisions.spend(geometry::geometry_work(dict)) {
            return Err(
                "cannot be checked: the verification's work budget is spent (the file has too \
                 many annotation geometry values)"
                    .to_owned(),
            );
        }
        if let Some(problem) = geometry::markup_geometry_problem(self.cx.new, &kind, dict) {
            return Err(format!("{problem} (A2)"));
        }
        if !popup
            && let Some(problem) = new_appearance_problem(
                self.cx.new,
                self.cx.new_values,
                dict.get(b"AP"),
                true,
                geometry::rect_of(self.cx.new, dict),
                true,
            )
        {
            return Err(format!("{problem} (A2)"));
        }
        Ok(())
    }

    /// The keys that differ between two dictionaries.
    fn changed_keys<'a>(old: &'a Dict, new: &'a Dict) -> Vec<&'a [u8]> {
        let mut keys: Vec<&[u8]> = old.keys().chain(new.keys()).map(|k| k.as_bytes()).collect();
        keys.sort_unstable();
        keys.dedup();
        keys.retain(|k| old.get(k) != new.get(k));
        keys
    }

    /// The catalog (§7.7.2), as pyHanko's `CatalogModificationRule`: only the keys of its
    /// `ROOT_EXEMPT_STRICT_COMPARISON` may change. `/Version` any way; `/Extensions` and
    /// `/MarkInfo` when kept (direct, or a reference that is unchanged or to a new object);
    /// `/Metadata` when removed or pointing to an XMP stream (`MetadataUpdateRule`); the AcroForm
    /// as [`Rules::acroform`]. `/DSS` (M11, D-9) and every other key are `Other`.
    fn catalog(&self, old: &Dict, new: &Dict) -> ModificationLevel {
        let mut level = ModificationLevel::LtaUpdates;
        for key in Self::changed_keys(old, new) {
            let key_level = match key {
                b"Version" => {
                    // pyHanko's timestamper raises /Version with its ESIC extension, in the
                    // revision that adds the timestamp (R-8).
                    let stamped = self
                        .base
                        .root
                        .is_some_and(|root| self.cx.written_with_timestamp(root));
                    self.class(if stamped {
                        ChangeClass::DocTimeStamp
                    } else {
                        ChangeClass::Metadata
                    });
                    ModificationLevel::LtaUpdates
                }
                b"Extensions" => {
                    let root = self.base.root.unwrap_or(0);
                    self.class(self.cx.extensions_class(root, old.get(key), new.get(key)));
                    self.kept_reference(old.get(key), new.get(key))
                }
                b"MarkInfo" => {
                    self.class(ChangeClass::Metadata);
                    self.kept_reference(old.get(key), new.get(key))
                }
                b"Metadata" => match new.get(key) {
                    None => {
                        self.class(ChangeClass::Metadata);
                        ModificationLevel::LtaUpdates
                    }
                    Some(Object::Ref(id))
                        if self.cx.revisions.is_xmp(self.cx.new, self.cx.r, *id) =>
                    {
                        self.class(ChangeClass::Metadata);
                        ModificationLevel::LtaUpdates
                    }
                    // §14.3.2: /Metadata is an indirect reference to a stream.
                    Some(_) => ModificationLevel::Other,
                },
                b"AcroForm" => match (old.get_dict(key), new.get_dict(key)) {
                    (Some(o), Some(n)) => self.acroform(o, n),
                    _ => ModificationLevel::Other,
                },
                // /DSS (M11) and everything else.
                _ => ModificationLevel::Other,
            };
            level = level.max(key_level);
        }
        level
    }

    /// pyHanko's `compare_key_refs` for a catalog key that may change: removing it is `Other`;
    /// a direct value, the same reference, or a reference to a new object is `LtaUpdates`; a
    /// reference to another existing object (which the update would clobber or reuse) is
    /// `Other`.
    fn kept_reference(&self, old: Option<&Object>, new: Option<&Object>) -> ModificationLevel {
        match new {
            None => ModificationLevel::Other,
            Some(Object::Ref(id)) => {
                let same = old.and_then(Object::as_ref) == Some(*id);
                if same || self.cx.is_new(*id) {
                    ModificationLevel::LtaUpdates
                } else {
                    ModificationLevel::Other
                }
            }
            Some(_) => ModificationLevel::LtaUpdates,
        }
    }

    /// The AcroForm (§12.7.3, Table 224), by the whitelist of what a later signer changes
    /// (brief §5 V10 (3), reduced by the manager in M3 QA round 5 after two rounds of bypasses
    /// of a narrower exception): (a) `/Fields` may gain new root-level signature fields
    /// (`LtaUpdates`; their widgets, signature dictionaries and the pages' `/Annots` are checked
    /// by the other rules); (b) `/SigFlags` may change only as signing requires, and no signing
    /// after a signature requires it (Folioxide writes `/SigFlags 3` only while no signed field
    /// exists, D-6, and pyHanko compares the key strictly), so any change is `Other`; (c) `/DR`
    /// may gain new resource names that nothing of the signed revision names
    /// ([`Rules::default_resources`], `FormFilling`). Everything else is `Other`: any change to
    /// `/NeedAppearances` or `/DA` (adding, removing or changing it), any `/Q` change and any
    /// other key. Those make viewers construct the appearances of the fields the signer saw,
    /// construct them differently, or stop constructing them and show stale stored ones (expert
    /// findings: poppler and MuPDF draw "900 EUR" instead of the signed "100 EUR", or the
    /// reverse once a `/NeedAppearances true` is removed, or white text once a `/DA` is added
    /// for a field that has neither an appearance stream nor a `/DA` of its own); pyHanko
    /// exempts all four keys from its AcroForm comparison (`LTA_UPDATES`). Removing
    /// `/NeedAppearances` is `Other` even in a revision that adds a signature, so the earlier
    /// signatures of a document whose later signer removed it (pyHanko's signer does) are
    /// `Other` (stricter than pyHanko, brief §0).
    fn acroform(&self, old: &Dict, new: &Dict) -> ModificationLevel {
        let mut level = ModificationLevel::LtaUpdates;
        for key in Self::changed_keys(old, new) {
            let key_level = match key {
                b"Fields" => {
                    let fields = match (old.get(key), new.get(key)) {
                        (Some(Object::Array(o)), Some(Object::Array(n))) => {
                            self.appended_sig_fields(o, n, false)
                        }
                        (None, Some(Object::Array(n))) => self.appended_sig_fields(&[], n, false),
                        _ => ModificationLevel::Other,
                    };
                    if fields == ModificationLevel::Other {
                        self.refuse(
                            "/Fields gains something other than new root-level signature fields",
                        )
                    } else {
                        fields
                    }
                }
                b"DR" => {
                    let level = self.default_resources(old.get(key), new.get(key));
                    self.class(ChangeClass::DefaultResources);
                    level
                }
                // §12.7.4.3: the default appearance of every field without its own. Deciding
                // which fields an added /DA cannot restyle proved unreliable (expert findings:
                // an /AP /N that is not a stream, a widget outside /Fields), so any change is
                // Other.
                b"DA" => {
                    let how = match (old.get(key), new.get(key)) {
                        (None, _) => "adds",
                        (_, None) => "removes",
                        _ => "changes",
                    };
                    self.refuse(format!(
                        "{how} /DA, the default appearance with which viewers construct the \
                         appearance of every field without its own"
                    ))
                }
                // §12.7.3: true makes viewers construct appearance streams for every field,
                // replacing the stored ones; removing a true makes them show the stored ones
                // instead of those they constructed when the document was signed.
                b"NeedAppearances" => {
                    let how = match (old.get(key), new.get(key)) {
                        (None, _) => "adds",
                        (_, None) => "removes",
                        _ => "changes",
                    };
                    self.refuse(format!(
                        "{how} /NeedAppearances, which decides whether viewers show the fields' \
                         stored appearances or construct new ones from their values"
                    ))
                }
                b"Q" => {
                    self.refuse("changes /Q (the default quadding of the fields without their own)")
                }
                other => self.refuse(format!(
                    "changes the AcroForm's /{}",
                    String::from_utf8_lossy(other)
                )),
            };
            level = level.max(key_level);
        }
        level
    }

    /// A changed AcroForm `/DR` (Table 224, the default resources of form appearances), by the
    /// whitelist (brief §5 V10 (3) (c)): it stays a dictionary (removing it, pyHanko's "Key /DR
    /// was deleted", a reference to another existing object, a stream or anything else is
    /// `Other`) and may only gain names. In each category of [`DR_CATEGORIES`] (and
    /// `/ProcSet`), read through an indirect category dictionary in either revision, every name
    /// of the signed revision keeps its value (raw); a new name is `FormFilling`, except a name
    /// the signed revision already names ([`SignedNames`]: a default appearance string or an
    /// appearance stream or a form XObject it draws; a name that would now resolve), or
    /// any new name when those could not all be read. Any other entry stays as it was (raw).
    /// Changing or removing a name changes what viewers draw when they regenerate a field's
    /// appearance (expert finding: the `/DR` font re-pointed); pyHanko allows it at
    /// FORM_FILLING.
    fn default_resources(&self, old: Option<&Object>, new: Option<&Object>) -> ModificationLevel {
        if self.kept_reference(old, new) == ModificationLevel::Other {
            return self.refuse("removes /DR or points it to another existing object");
        }
        let read = |store: &Store, value: &Object| -> Option<Dict> {
            store.deref(value).ok().and_then(|v| v.as_dict().cloned())
        };
        // Ruling R-12 (2): the signed /DR that the new one is compared with.
        if let Some(Object::Ref(id)) = old
            && let Some(reason) = self
                .cx
                .revisions
                .canonical_at(self.cx.old, self.cx.k, id.num)
        {
            return self.refuse(format!("the signed /DR {reason}"));
        }
        let old_dr = match old {
            None => Some(Dict::new()),
            Some(value) => read(self.cx.old, value),
        };
        let new_dr = new.and_then(|value| read(self.cx.new, value));
        let (Some(old_dr), Some(new_dr)) = (old_dr, new_dr) else {
            return self.refuse("/DR is not a dictionary (or is a stream)");
        };
        let mut keys: Vec<&[u8]> = old_dr
            .keys()
            .chain(new_dr.keys())
            .map(|k| k.as_bytes())
            .collect();
        keys.sort_unstable();
        keys.dedup();
        let mut level = ModificationLevel::FormFilling;
        for key in keys {
            let key_level = if DR_CATEGORIES.contains(&key) {
                self.resource_names(key, old_dr.get(key), new_dr.get(key))
            } else if key == b"ProcSet" {
                self.proc_sets(old_dr.get(key), new_dr.get(key))
            } else if old_dr.get(key) == new_dr.get(key) {
                ModificationLevel::FormFilling
            } else {
                self.refuse(format!("changes /DR /{}", String::from_utf8_lossy(key)))
            };
            level = level.max(key_level);
        }
        level
    }

    /// One category of the AcroForm `/DR` (a dictionary of names, §7.8.3), direct or indirect
    /// in either revision: every name of the signed revision keeps its value (raw); new names
    /// are `FormFilling`, except a name the signed revision already names
    /// ([`Base::signed_names`]), or any new name when that collection is incomplete.
    fn resource_names(
        &self,
        category: &[u8],
        old: Option<&Object>,
        new: Option<&Object>,
    ) -> ModificationLevel {
        let what = String::from_utf8_lossy(category);
        let read = |store: &Store, value: Option<&Object>| -> Option<Dict> {
            match value {
                None => Some(Dict::new()),
                Some(value) => store.deref(value).ok().and_then(|v| v.as_dict().cloned()),
            }
        };
        let (Some(old_names), Some(new_names)) = (read(self.cx.old, old), read(self.cx.new, new))
        else {
            return self.refuse(format!("/DR /{what} is not a dictionary"));
        };
        for (name, value) in old_names.iter() {
            if new_names.get(name.as_bytes()) != Some(value) {
                return self.refuse(format!(
                    "changes or removes the name /{} of /DR /{what}, which the signed revision \
                     has",
                    String::from_utf8_lossy(name.as_bytes())
                ));
            }
        }
        let added: Vec<&[u8]> = new_names
            .keys()
            .map(|name| name.as_bytes())
            .filter(|name| !old_names.contains_key(name))
            .collect();
        if let Some(name) = added
            .iter()
            .find(|name| self.base.signed_names.contains(**name))
        {
            return self.refuse(format!(
                "adds /DR /{what} /{}, which the signed revision already names (in a /DA, or in \
                 an appearance stream or a form XObject it draws)",
                String::from_utf8_lossy(name)
            ));
        }
        if !self.base.signed_names_complete
            && let Some(name) = added.first()
        {
            return self.refuse(format!(
                "adds /DR /{what} /{}, and the signed revision's default appearance strings, \
                 annotations or appearance streams cannot all be read to check that none names \
                 it",
                String::from_utf8_lossy(name)
            ));
        }
        // Ruling R-12 (2): what the signed names were read from (and the signed category
        // dictionary compared) must read the same in every reader, or another reader may name
        // what a new /DR entry gives.
        if let Some(name) = added.first() {
            let signed = old.and_then(Object::as_ref).map(|id| id.num);
            for &num in signed.iter().chain(&self.base.signed_name_objects) {
                if let Some(reason) = self.cx.revisions.canonical_at(self.cx.old, self.cx.k, num) {
                    return self.refuse(format!(
                        "adds /DR /{what} /{}, and the signed revision's object that names or \
                         holds the resources {reason}",
                        String::from_utf8_lossy(name)
                    ));
                }
            }
        }
        ModificationLevel::FormFilling
    }

    /// `/DR /ProcSet` (§14.2, an array of names), direct or indirect: it may only gain names.
    fn proc_sets(&self, old: Option<&Object>, new: Option<&Object>) -> ModificationLevel {
        let read = |store: &Store, value: Option<&Object>| -> Option<Vec<Object>> {
            match value {
                None => Some(Vec::new()),
                Some(value) => store
                    .deref(value)
                    .ok()
                    .and_then(|v| v.as_array().map(<[Object]>::to_vec)),
            }
        };
        match (read(self.cx.old, old), read(self.cx.new, new)) {
            (Some(o), Some(n)) if o.iter().all(|item| n.contains(item)) => {
                ModificationLevel::FormFilling
            }
            _ => self.refuse("changes or removes a /DR /ProcSet name"),
        }
    }

    /// An unsigned signature field (§12.7.5.5), as pyHanko's `SigFieldModificationRule`: a
    /// revision that **signs** it ([`Rules::signs_field`]) may set `/V`, a new `/AP` (direct,
    /// unchanged or a new object, a dictionary) and change `/AS` and `/F` (`FormFilling`); a
    /// field that stays unsigned may change only `/Ff` (`LtaUpdates`; pyHanko's
    /// `FORMFIELD_ALWAYS_MODIFIABLE`). A new appearance, appearance state or annotation flags
    /// without a signature would paint over or hide signed content: `Other` (QA finding: the
    /// shadow overlay through an existing field).
    fn unsigned_sig_field(&self, num: u32, old: &Dict, new: &Dict) -> ModificationLevel {
        // Final fix round 2, finding 1 (ruling R-19): pyHanko's `_allow_appearance_update`,
        // which runs for a field that had no /V and has one now, refuses the field's old
        // indirect /AP dictionary when the signed revision uses it in several contexts (two
        // unsigned signature fields sharing one: signing the second alters the first's
        // appearance too). Stricter than pyHanko, which checks only a new /AP that holds /N, /R
        // or /D: whatever the /AP becomes.
        if !old.contains_key(b"V")
            && new.contains_key(b"V")
            && let Some(reason) = self.base.shared_sig_appearances.get(&num)
        {
            return self.refuse(format!("is signed, but {reason}"));
        }
        let signing = self.signs_field(old, new);
        let mut level = ModificationLevel::LtaUpdates;
        let changed = Self::changed_keys(old, new);
        for &key in &changed {
            let key_level = match key {
                b"Ff" => {
                    self.class(ChangeClass::SignatureField);
                    ModificationLevel::LtaUpdates
                }
                b"V" | b"AS" | b"F" if signing => {
                    self.class(ChangeClass::Signature);
                    ModificationLevel::FormFilling
                }
                b"AP" if signing => {
                    self.class(ChangeClass::Signature);
                    self.appearance(
                        old.get(key),
                        new.get(key),
                        is_visible(self.cx.new, new),
                        geometry::rect_of(self.cx.new, new),
                    )
                }
                _ => ModificationLevel::Other,
            };
            level = level.max(key_level);
        }
        // Ruling R-3: the widget a signing revision gives a new appearance or new flags shows
        // them with the flags a signer writes, and inside a /Rect of four finite numbers (QA
        // round 2, finding 4: viewers read an unusable entry as 0).
        if signing && changed.iter().any(|key| matches!(*key, b"AP" | b"F")) {
            if let Some(problem) = geometry::annotation_flags_problem(self.cx.new, new) {
                return self.refuse(format!("the signed field's widget {problem}"));
            }
            let widget = new.get_name(b"Subtype").is_some_and(|s| s == b"Widget");
            if widget && new.contains_key(b"AP") && geometry::rect_of(self.cx.new, new).is_none() {
                return self.refuse(format!(
                    "the signed field's widget gets an appearance but has no /Rect of four \
                     finite numbers within ±{:e}, so viewers place it elsewhere than its /Rect \
                     says",
                    geometry::MAX_GEOMETRY_MAGNITUDE
                ));
            }
        }
        level
    }

    /// Whether a revision signs an unsigned signature field: the field had no `/V` entry at all
    /// (pyHanko's `previously_signed` is `'/V' in old_field`, so a `/V null` counts as signed)
    /// and its `/V` now refers to a new signature dictionary.
    fn signs_field(&self, old: &Dict, new: &Dict) -> bool {
        !old.contains_key(b"V") && new.get(b"V").is_some_and(|v| self.is_new_sig_dict(v))
    }

    /// A changed `/AP` of an unsigned signature field (pyHanko's `_allow_appearance_update`):
    /// direct, unchanged or a new object, never another existing object, and a dictionary whose
    /// `/N`, `/D` and `/R` are new form XObjects clipped to the widget's `/Rect` (QA finding R5,
    /// [`new_appearance_problem`]; `visible`: the widget's `/Rect` has an area).
    fn appearance(
        &self,
        old: Option<&Object>,
        new: Option<&Object>,
        visible: bool,
        rect: Option<geometry::Rect>,
    ) -> ModificationLevel {
        let Some(new) = new else {
            return ModificationLevel::Other;
        };
        if self.kept_reference(old, Some(new)) == ModificationLevel::Other {
            return ModificationLevel::Other;
        }
        // An /AP kept as the same indirect dictionary is judged as that object's change.
        let same = matches!(new, Object::Ref(id) if old.and_then(Object::as_ref) == Some(*id));
        match self.cx.new.deref(new) {
            Ok(value) if value.as_dict().is_some() => {
                if !same
                    && let Some(problem) = new_appearance_problem(
                        self.cx.new,
                        self.cx.new_values,
                        Some(new),
                        visible,
                        rect,
                        true,
                    )
                {
                    return self.refuse(format!("its new appearance {problem}"));
                }
                ModificationLevel::FormFilling
            }
            _ => ModificationLevel::Other,
        }
    }

    // ---- generic form filling (M4 brief §5.1) ---------------------------------------------------

    /// F0: why the form-filling rules do not apply to the field `num` (`field`), if they do not:
    /// the signed revision's AcroForm has `/XFA` (D-23), the evaluated signature has FieldMDP
    /// (D-23), the field is a pushbutton or ReadOnly in the signed revision (F1), a widget of
    /// the field sets NoZoom or NoRotate ([`FormField::drawn_outside_rect`], M4 QA round 2), or
    /// the field (and a merged widget) is no longer in revision `r`'s field tree (and on a page).
    fn form_preconditions(&self, num: u32, field: &FormField) -> Option<String> {
        if self.base.xfa {
            return Some(
                "the signed revision's AcroForm has /XFA, and XFA-aware viewers show its \
                 datasets, not the AcroForm's values (D-23)"
                    .to_owned(),
            );
        }
        if self.cx.ctx.field_mdp {
            return Some(
                "the evaluated signature has FieldMDP (M11), so generic form filling is not \
                 classified (D-23)"
                    .to_owned(),
            );
        }
        if field.kind == FormKind::Pushbutton {
            return Some("the field is a pushbutton, which has no value to fill".to_owned());
        }
        if field.read_only {
            return Some(
                "the field is ReadOnly in the signed revision (ISO 32000-2 §12.7.4.1: it shall \
                 not be changed by the user)"
                    .to_owned(),
            );
        }
        if field.drawn_outside_rect {
            return Some(
                "a widget of the field sets the annotation flag NoZoom or NoRotate (or flags \
                 that cannot be read), so viewers draw its appearance at a fixed size or \
                 upright at its /Rect's corner, outside the /Rect (ISO 32000-2 §12.5.3)"
                    .to_owned(),
            );
        }
        let Some(presence) = self.cx.revisions.presence_at(self.cx.new_doc, self.cx.r) else {
            return Some(format!(
                "revision {}'s field tree and pages cannot all be read",
                self.cx.r
            ));
        };
        if !presence.fields.contains(&num) {
            return Some(format!(
                "revision {}'s field tree no longer reaches the field",
                self.cx.r
            ));
        }
        if field.merged && !presence.annotations.contains(&num) {
            return Some(format!(
                "the field's widget is no longer on a page of revision {}",
                self.cx.r
            ));
        }
        // Ruling R-12 (2): what the rules read of the field in the signed revision (the field,
        // its ancestors, its widget kids and its appearance dictionaries) reads the same in
        // every reader.
        let reads = self
            .base
            .form
            .reads
            .get(&num)
            .map_or(&[][..], Vec::as_slice);
        for &read in std::iter::once(&num).chain(reads) {
            if let Some(reason) = self.cx.revisions.canonical_at(self.cx.old, self.cx.k, read) {
                return Some(format!(
                    "the signed revision's object the rules read for the field {reason}"
                ));
            }
        }
        None
    }

    /// F1–F4: a terminal form field that is not a signature field, merged with its widget or not
    /// (`field`, object `num`). Only `/V` may change (F1, F2); on a merged field and widget also
    /// `/AS` (buttons, F3) and `/AP` (text and choice fields, F4). Everything else is `Other`:
    /// `/F`, `/DA`, `/Q`, `/Ff`, `/Rect`, `/MK`, `/DV`, `/TU`, `/Opt`, `/AA`, ...
    fn form_field(&self, num: u32, field: &FormField, old: &Dict, new: &Dict) -> ModificationLevel {
        if let Some(reason) = self.form_preconditions(num, field) {
            return self.refuse(reason);
        }
        let value_changed = old.get(b"V") != new.get(b"V");
        let text_or_choice = matches!(field.kind, FormKind::Text | FormKind::Choice);
        let mut level = ModificationLevel::FormFilling;
        for key in Self::changed_keys(old, new) {
            let key_level = match key {
                b"V" => self.form_value(field, new.get(b"V")),
                b"AS" if field.merged && field.kind == FormKind::Button => {
                    self.form_state(old, new)
                }
                b"AP" if field.merged && text_or_choice => {
                    if value_changed {
                        self.form_appearance(
                            old.get(b"AP"),
                            new.get(b"AP"),
                            is_visible(self.cx.new, new),
                            geometry::rect_of(self.cx.new, new),
                        )
                    } else {
                        self.refuse(
                            "changes /AP while /V stays: the shown value would differ from the \
                             field's value (F4)",
                        )
                    }
                }
                b"AP" if field.kind == FormKind::Button => self.refuse(
                    "replaces a button's appearance: filling only selects one of the signed \
                     appearance states (F3)",
                ),
                b"F" => self.refuse(
                    "changes the widget's annotation flags /F, which hide or reveal it (ISO \
                     32000-2 §12.5.3)",
                ),
                b"DA" => self.refuse(
                    "changes /DA, which restyles the appearance viewers construct for the field",
                ),
                b"Q" => self.refuse("changes /Q, the alignment of the field's constructed text"),
                b"Ff" => self.refuse(
                    "changes the field flags /Ff (ReadOnly, Password, Comb or Multiline change \
                     how the value is shown or edited)",
                ),
                b"Rect" => self.refuse("moves the widget (/Rect)"),
                other => self.refuse(format!(
                    "changes the field's /{}, which form filling does not change (F1)",
                    String::from_utf8_lossy(other)
                )),
            };
            level = level.max(key_level);
        }
        if level < ModificationLevel::Other {
            self.class(ChangeClass::FormFill);
        }
        level
    }

    /// F1, F2: a new `/V` (`None`: removed) of a field of kind `field.kind`: a direct text string
    /// (text), a direct text string or array of text strings (choice), a direct name (button);
    /// never an indirect reference.
    fn form_value(&self, field: &FormField, value: Option<&Object>) -> ModificationLevel {
        let Some(value) = value else {
            return ModificationLevel::FormFilling;
        };
        if matches!(value, Object::Ref(_)) {
            return self.refuse("its new /V is an indirect reference (F2)");
        }
        let ok = match field.kind {
            FormKind::Text => matches!(value, Object::String(_)),
            FormKind::Choice => match value {
                Object::String(_) => true,
                Object::Array(items) => items.iter().all(|i| matches!(i, Object::String(_))),
                _ => false,
            },
            FormKind::Button => matches!(value, Object::Name(_)),
            FormKind::Pushbutton => false,
        };
        if ok {
            ModificationLevel::FormFilling
        } else {
            self.refuse(format!(
                "its new /V is a {}, not the value type of the field (F1)",
                value.type_name()
            ))
        }
    }

    /// F3: a merged button widget's new `/AS` (`old` and `new` are the field and widget): `/Off`
    /// or a state of the widget's `/AP /N` in the signed revision, and the state the field's
    /// `/V` in revision `r` selects (that state when the widget has it, else `/Off`).
    fn form_state(&self, old: &Dict, new: &Dict) -> ModificationLevel {
        let Some(state) = new.get(b"AS").and_then(Object::as_name) else {
            return self.refuse("removes /AS, or sets it to something that is no name (F3)");
        };
        let states: BTreeSet<Vec<u8>> = old
            .get(b"AP")
            .and_then(|ap| self.cx.old.deref(ap).ok())
            .and_then(|ap| ap.as_dict().and_then(|ap| ap.get(b"N").cloned()))
            .and_then(|n| {
                self.cx.old.deref(&n).ok().and_then(|n| {
                    n.as_dict()
                        .map(|d| d.keys().map(|k| k.as_bytes().to_vec()).collect())
                })
            })
            .unwrap_or_default();
        let state = state.as_bytes();
        if state != b"Off" && !states.contains(state) {
            return self.refuse(format!(
                "sets /AS /{}, which names no appearance state of the signed widget, so it \
                 draws nothing (F3)",
                String::from_utf8_lossy(state)
            ));
        }
        let value = new
            .get(b"V")
            .and_then(|v| self.cx.new.deref(v).ok())
            .and_then(|v| v.as_name().map(|n| n.as_bytes().to_vec()));
        let expected: &[u8] = match value.as_deref() {
            Some(v) if v != b"Off" && states.contains(v) => v,
            _ => b"Off",
        };
        if state != expected {
            return self.refuse(format!(
                "sets /AS /{}, while the field's /V selects /{} (F3)",
                String::from_utf8_lossy(state),
                String::from_utf8_lossy(expected)
            ));
        }
        ModificationLevel::FormFilling
    }

    /// F4: a merged text or choice widget's new `/AP` (the field's `/V` changed): a direct
    /// dictionary or a new object (pyHanko's `compare_key_refs`), with `/N` and optionally `/D`
    /// and `/R` only, each a new stream or the signed one (changed in place: F5).
    fn form_appearance(
        &self,
        old: Option<&Object>,
        new: Option<&Object>,
        visible: bool,
        rect: Option<geometry::Rect>,
    ) -> ModificationLevel {
        let Some(new) = new else {
            return self.refuse("removes /AP (F4)");
        };
        if let Object::Ref(id) = new
            && old.and_then(Object::as_ref) != Some(*id)
            && !self.cx.is_new(*id)
        {
            return self.refuse(format!(
                "points /AP to the existing object {id}, which the update would reuse (F4)"
            ));
        }
        let new_ap = self
            .cx
            .new
            .deref(new)
            .ok()
            .and_then(|ap| ap.as_dict().cloned());
        let Some(new_ap) = new_ap else {
            return self.refuse("its new /AP is not a dictionary (F4)");
        };
        let old_ap = old
            .and_then(|ap| self.cx.old.deref(ap).ok())
            .and_then(|ap| ap.as_dict().cloned())
            .unwrap_or_default();
        self.appearance_dict(&old_ap, &new_ap, visible, rect)
    }

    /// F4: a text or choice widget's appearance dictionary from `old` to `new`: only `/N`
    /// (required), `/D` and `/R`, each a new stream that is a form XObject clipped to the
    /// widget's `/Rect` ([`geometry::appearance_stream_problem`]; `visible`: the `/Rect` has an
    /// area), or the stream of the same key in `old` (changed in place: F5).
    fn appearance_dict(
        &self,
        old: &Dict,
        new: &Dict,
        visible: bool,
        rect: Option<geometry::Rect>,
    ) -> ModificationLevel {
        if !new.contains_key(b"N") {
            return self.refuse("its new appearance dictionary has no /N (F4)");
        }
        for (key, value) in new.iter() {
            let key = key.as_bytes();
            if !matches!(key, b"N" | b"D" | b"R") {
                return self.refuse(format!(
                    "its new appearance dictionary has /{} (F4: only /N, /D and /R)",
                    String::from_utf8_lossy(key)
                ));
            }
            let ok = match value {
                Object::Ref(id) if old.get(key) == Some(value) => {
                    // The signed stream, unchanged or changed in place (F5 judges it).
                    let _ = id;
                    true
                }
                Object::Ref(id) => {
                    self.cx.is_new(*id)
                        && self
                            .cx
                            .new_values
                            .get(&id.num)
                            .is_some_and(|fact| matches!(*fact.value, Object::Stream(_)))
                }
                _ => false,
            };
            if !ok {
                return self.refuse(format!(
                    "its new appearance /{} is not a new stream (F4)",
                    String::from_utf8_lossy(key)
                ));
            }
            if old.get(key) != Some(value)
                && let Some(problem) =
                    geometry::appearance_stream_problem(self.cx.new, value, visible, rect)
            {
                return self.refuse(format!(
                    "its new appearance /{} {problem} (F4)",
                    String::from_utf8_lossy(key)
                ));
            }
        }
        ModificationLevel::FormFilling
    }

    /// Whether the `/V` of the field `owner` differs between the signed revision and revision
    /// `r`, and the field as revision `r` shows it.
    fn owner_value_changed(&self, owner: u32) -> Option<(bool, Dict)> {
        let id = ObjectId::new(owner, 0);
        let old = self.cx.old.resolve(id).ok()?.as_dict()?.clone();
        let new = self.cx.new.resolve(id).ok()?.as_dict()?.clone();
        Some((old.get(b"V") != new.get(b"V"), new))
    }

    /// F4: the indirect `/AP` dictionary of the merged text or choice field `owner`, changed in
    /// place: the field's `/V` changed, the field still names it, and its new entries are those
    /// of [`Rules::appearance_dict`]. It must be used once (checked with the roles' uses).
    fn form_ap_dict(&self, owner: u32, num: u32, old: &Dict, new: &Dict) -> ModificationLevel {
        let Some(field) = self.base.form.fields.get(&owner) else {
            return ModificationLevel::Other;
        };
        if !matches!(field.kind, FormKind::Text | FormKind::Choice) {
            return self.refuse(
                "it is a button's appearance dictionary: filling only selects one of the signed \
                 appearance states (F3)",
            );
        }
        if let Some(reason) = self.form_preconditions(owner, field) {
            return self.refuse(format!("of field {owner} 0 R: {reason}"));
        }
        let Some((changed, new_field)) = self.owner_value_changed(owner) else {
            return self.refuse("its field cannot be read (F4)");
        };
        if !changed {
            return self.refuse(
                "it changes while its field's /V stays: the shown value would differ from the \
                 field's value (F4)",
            );
        }
        if new_field.get_ref(b"AP").map(|ap| ap.num) != Some(num) {
            return self.refuse("its field no longer names it as /AP (F4)");
        }
        let level = self.appearance_dict(
            old,
            new,
            is_visible(self.cx.new, &new_field),
            geometry::rect_of(self.cx.new, &new_field),
        );
        if level < ModificationLevel::Other {
            self.class(ChangeClass::FormFill);
        }
        level
    }

    /// F5: an appearance stream of the merged text or choice field `owner` changed in place
    /// (pyHanko's `_allow_in_place_appearance_update`): the field's `/V` changed, its appearance
    /// in revision `r` still names the stream, and the new value is a stream. It must be used
    /// once (checked with the roles' uses).
    fn form_ap_stream(&self, owner: u32, num: u32, new: &Object) -> ModificationLevel {
        let Some(field) = self.base.form.fields.get(&owner) else {
            return ModificationLevel::Other;
        };
        if let Some(reason) = self.form_preconditions(owner, field) {
            return self.refuse(format!("of field {owner} 0 R: {reason}"));
        }
        let Some((changed, new_field)) = self.owner_value_changed(owner) else {
            return self.refuse("its field cannot be read (F5)");
        };
        if !changed {
            return self.refuse(
                "it changes while its field's /V stays: the shown value would differ from the \
                 field's value (F5)",
            );
        }
        let still_named = new_field
            .get(b"AP")
            .and_then(|ap| self.cx.new.deref(ap).ok())
            .and_then(|ap| ap.as_dict().cloned())
            .is_some_and(|ap| {
                [b"N".as_slice(), b"D", b"R"]
                    .iter()
                    .any(|key| ap.get_ref(key).is_some_and(|id| id.num == num))
            });
        if !still_named {
            return self.refuse("its field's appearance no longer names it (F5)");
        }
        let Object::Stream(stream) = new else {
            return self.refuse("it is no longer a stream (F5)");
        };
        let visible = is_visible(self.cx.new, &new_field);
        let rect = geometry::rect_of(self.cx.new, &new_field);
        if let Some(problem) = geometry::form_dict_problem(&stream.dict, "it", visible, rect) {
            return self.refuse(format!("{problem} (F5)"));
        }
        self.class(ChangeClass::FormFill);
        ModificationLevel::FormFilling
    }

    /// A page (§7.7.3.3, object `page`): only new signature widgets and the markup annotations
    /// of brief §5.2 may be appended to `/Annots`; every other key stays.
    fn page(&self, page: ObjectId, old: &Dict, new: &Dict) -> ModificationLevel {
        let mut level = ModificationLevel::LtaUpdates;
        for key in Self::changed_keys(old, new) {
            let key_level = match key {
                b"Annots" => {
                    let list = |store: &Store, dict: &Dict| -> Option<Vec<Object>> {
                        match dict.get(b"Annots") {
                            None => Some(Vec::new()),
                            Some(value) => match &*store.deref(value).ok()? {
                                Object::Null => Some(Vec::new()),
                                Object::Array(items) => Some(items.clone()),
                                _ => None,
                            },
                        }
                    };
                    let annots_ok = match (old.get(b"Annots"), new.get(b"Annots")) {
                        // An indirect /Annots may stay, or move to a new array object.
                        (old_value, Some(Object::Ref(id))) => {
                            old_value.and_then(Object::as_ref) == Some(*id) || self.cx.is_new(*id)
                        }
                        _ => true,
                    };
                    let annots = match (list(self.cx.old, old), list(self.cx.new, new)) {
                        (Some(o), Some(n)) if annots_ok => {
                            self.appended_page_items(&o, &n, &[page])
                        }
                        _ => ModificationLevel::Other,
                    };
                    if annots == ModificationLevel::Other {
                        self.refuse(
                            "/Annots gains something other than new signature widgets and \
                             allowed markup annotations",
                        )
                    } else {
                        annots
                    }
                }
                other => self.refuse(format!(
                    "changes the page's /{}",
                    String::from_utf8_lossy(other)
                )),
            };
            level = level.max(key_level);
        }
        level
    }
}

/// A view of the first `len` bytes of a shared source.
struct Prefix {
    bytes: SharedBytes,
    len: usize,
}

impl AsRef<[u8]> for Prefix {
    fn as_ref(&self) -> &[u8] {
        let all: &[u8] = (*self.bytes).as_ref();
        all.get(..self.len).unwrap_or(all)
    }
}

/// Whether an entry is an object in use.
fn in_use(entry: &XrefEntry) -> bool {
    matches!(entry, XrefEntry::InFile { .. } | XrefEntry::InObjStm { .. })
}

/// The generation an entry gives (0 for a compressed object).
fn entry_gen(entry: &XrefEntry) -> u16 {
    match entry {
        XrefEntry::Free { r#gen } | XrefEntry::InFile { r#gen, .. } => *r#gen,
        _ => 0,
    }
}

/// Whether two values are the same object: equal values, or streams with equal dictionaries and
/// equal raw data.
fn same_value(old_store: &Store, old: &Object, new_store: &Store, new: &Object) -> bool {
    match (old, new) {
        (Object::Stream(a), Object::Stream(b)) => {
            a.dict == b.dict
                && match (old_store.raw_stream_data(a), new_store.raw_stream_data(b)) {
                    (Ok(x), Ok(y)) => x == y,
                    _ => false,
                }
        }
        _ => old == new,
    }
}

/// The object numbers `value` refers to (stream dictionaries included), without following the
/// references. Iterative, so a deep value cannot exhaust the stack.
pub(crate) fn references_of(value: &Object) -> Vec<u32> {
    let mut out = Vec::new();
    let mut stack: Vec<(&Object, usize)> = vec![(value, 0)];
    while let Some((obj, depth)) = stack.pop() {
        if depth > MAX_REF_DEPTH {
            continue;
        }
        match obj {
            Object::Ref(id) => out.push(id.num),
            Object::Array(items) => stack.extend(items.iter().map(|o| (o, depth + 1))),
            Object::Dict(dict) => stack.extend(dict.values().map(|o| (o, depth + 1))),
            Object::Stream(stream) => {
                stack.extend(stream.dict.values().map(|o| (o, depth + 1)));
            }
            _ => {}
        }
    }
    out
}

/// The four values of a `/ByteRange` when they are non-negative, `l1 > 0`, `o1 + l1 < o2` and
/// `o2 + l2 <= file_len` (brief §5 V3); the first value may be anything (the caller checks it).
pub(crate) fn sane_byte_range(byte_range: &[i64], file_len: u64) -> Option<[u64; 4]> {
    let [a, b, c, d] = byte_range else {
        return None;
    };
    let values = [*a, *b, *c, *d].map(|v| u64::try_from(v).ok());
    let [Some(o1), Some(l1), Some(o2), Some(l2)] = values else {
        return None;
    };
    let ok = l1 > 0
        && o1.checked_add(l1).is_some_and(|end| end < o2)
        && o2.checked_add(l2).is_some_and(|end| end <= file_len);
    ok.then_some([o1, l1, o2, l2])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Object {
        folioxide_syntax::parse_object(text.as_bytes(), 0, &folioxide_syntax::ParseCtx::default())
            .unwrap()
            .0
    }

    #[test]
    fn byte_range_sanity() {
        assert_eq!(sane_byte_range(&[0, 10, 20, 5], 25), Some([0, 10, 20, 5]));
        assert_eq!(sane_byte_range(&[0, 10, 20, 6], 25), None, "past the end");
        assert_eq!(
            sane_byte_range(&[0, 0, 20, 5], 25),
            None,
            "empty first range"
        );
        assert_eq!(sane_byte_range(&[0, 20, 20, 5], 25), None, "no gap");
        assert_eq!(sane_byte_range(&[0, -1, 20, 5], 25), None, "negative");
        assert_eq!(sane_byte_range(&[0, 10, 20], 25), None, "three values");
        assert_eq!(
            sane_byte_range(&[0, i64::MAX, i64::MAX, i64::MAX], u64::MAX),
            None
        );
        assert_eq!(sane_byte_range(&[3, 7, 20, 5], 25), Some([3, 7, 20, 5]));
    }

    #[test]
    fn references_are_collected_without_recursion() {
        let mut deep = Object::Ref(ObjectId::new(9, 0));
        for _ in 0..10_000 {
            deep = Object::Array(vec![deep]);
        }
        // Beyond the depth limit nothing is collected, and nothing overflows.
        assert!(references_of(&deep).is_empty());
        let mut dict = Dict::new();
        dict.insert("A", Object::Ref(ObjectId::new(3, 0)));
        dict.insert(
            "B",
            Object::Array(vec![Object::Ref(ObjectId::new(4, 0)), Object::Int(1)]),
        );
        let mut refs = references_of(&Object::Dict(dict));
        refs.sort_unstable();
        assert_eq!(refs, [3, 4]);
    }

    #[test]
    fn new_object_kinds() {
        let store = Store::new_empty((1, 7));
        let kind = |text: &str| classify_new(&store, &parse(text));
        assert_eq!(
            kind("<< /Type /Annot /Subtype /Widget /FT /Sig /T (S) /Rect [0 0 0 0] >>"),
            NewKind::SigField {
                visible: false,
                widget: true
            }
        );
        assert_eq!(
            kind("<< /FT /Sig /T (S) /Rect [0 0 10 10] >>"),
            NewKind::SigField {
                visible: true,
                widget: false
            }
        );
        // Not a signature field for the diff policy: kids, no or a dotted /T, another subtype.
        for other in [
            "<< /FT /Sig /T (S) /Kids [] >>",
            "<< /FT /Sig /Rect [0 0 0 0] >>",
            "<< /FT /Sig /T (a.b) >>",
            "<< /FT /Sig /T 9 0 R >>",
            "<< /Type /Annot /Subtype /Stamp /FT /Sig /T (S) /Rect [0 0 612 792] >>",
            "<< /FT /Tx /T (S) >>",
            "<< /Type /Sig >>",
            "[1 2]",
        ] {
            assert_eq!(kind(other), NewKind::Other, "{other}");
        }
        assert_eq!(
            kind("<< /Type /Sig /Contents <00> >>"),
            NewKind::SigDict { timestamp: false }
        );
        assert_eq!(
            kind("<< /Type /DocTimeStamp /ByteRange [] >>"),
            NewKind::SigDict { timestamp: true }
        );
    }

    #[test]
    fn visibility_reads_the_rect_through_references() {
        let mut store = Store::new_empty((1, 7));
        let big = store.add(parse("[72 680 500 740]")).unwrap();
        let flat = store.add(parse("[0 0 0 792]")).unwrap();
        let text = store.add(parse("(not a rectangle)")).unwrap();
        let visible = |rect: &str| {
            let dict = parse(&format!("<< /FT /Sig /T (S) {rect} >>"));
            is_visible(&store, dict.as_dict().unwrap())
        };
        // As pyHanko: no /Rect and a zero area are invisible.
        assert!(!visible(""));
        assert!(!visible("/Rect null"));
        assert!(!visible("/Rect [0 0 0 0]"));
        assert!(!visible("/Rect [10 10 300 10]"));
        assert!(!visible(&format!("/Rect {} 0 R", flat.num)));
        // An area, directly or through a reference, is visible (QA findings 3, 11b).
        assert!(visible("/Rect [0 0 612 792]"));
        assert!(visible("/Rect [612 792 0 0]"));
        assert!(visible(&format!("/Rect {} 0 R", big.num)));
        // What cannot be read as four numbers counts as visible (conservative).
        assert!(visible("/Rect [0 0 612]"));
        assert!(visible("/Rect [0 0 612 /x]"));
        assert!(visible(&format!("/Rect [0 0 612 {} 0 R]", big.num)));
        assert!(visible(&format!("/Rect {} 0 R", text.num)));
        assert!(visible("/Rect (x)"));
    }

    #[test]
    fn the_work_budget_bounds_the_analysis() {
        use folioxide_testkit::fixtures::{sign_attacks, syntax};
        // Three revisions after the first: an /Info update each.
        let mut pdf = syntax::minimal();
        for _ in 0..3 {
            pdf = sign_attacks::isa_info_only(&pdf).unwrap();
        }
        let doc = Document::open(pdf, &folioxide_syntax::OpenOptions::default()).unwrap();
        let ctx = ModificationContext::default();
        let ample = Revisions::new(&doc).modification(0, &ctx);
        assert_eq!(
            ample.level,
            ModificationLevel::LtaUpdates,
            "{:?}",
            ample.notes
        );
        assert!(
            ample.classes.contains(&ChangeClass::Metadata),
            "{:?}",
            ample.classes
        );
        // Too little budget to open the views: Other, and the notes say why.
        let starved = Revisions::new(&doc)
            .with_work_budget(2)
            .modification(0, &ctx);
        assert_eq!(starved.level, ModificationLevel::Other);
        assert!(
            starved.notes.iter().any(|n| n.contains("work budget")),
            "{:?}",
            starved.notes
        );
        // The outcome of a revision is analysed once and shared.
        let revisions = Revisions::new(&doc);
        let first = revisions.modification(1, &ctx);
        let left = revisions.work_left.get();
        assert_eq!(revisions.modification(1, &ctx), first);
        assert_eq!(
            revisions.work_left.get(),
            left,
            "a cached outcome costs nothing"
        );
    }

    /// Every name token of `data`, or `None` when it has an inline image.
    fn name_tokens(data: &[u8]) -> Option<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for_each_name_token(data, |name| {
            out.push(name.to_vec());
            true
        })
        .then_some(out)
    }

    #[test]
    fn default_appearance_font_names() {
        let names = |da: &str| -> Vec<String> {
            name_tokens(da.as_bytes())
                .unwrap()
                .into_iter()
                .map(|n| String::from_utf8(n).unwrap())
                .collect()
        };
        assert_eq!(names("/Helv 0 Tf 0 g"), ["Helv"]);
        // An escaped name counts decoded and as written (QA round 3).
        assert_eq!(
            names("0 g\n/F1   12\tTf /F#232 9 Tf"),
            ["F1", "F#2", "F#232"]
        );
        // A name ends at a delimiter, not only at white-space (§7.2.3; QA and expert finding:
        // `0 g/F2` was one token, so the guard missed F2).
        assert_eq!(names("0 g/F2 20 Tf"), ["F2"]);
        assert_eq!(names("/F2 20 Tf/F3 9 Tf"), ["F2", "F3"]);
        assert_eq!(names("[/F4]0 d(x)Tj/F5 1 Tf"), ["F4", "F5"]);
        // An operator run together with an operand: pdf.js reads `Tf0 g` as `Tf 0 g`, so the
        // name counts.
        assert_eq!(names("/Helv 12 Tf0 g"), ["Helv"]);
        assert_eq!(names("/Helv 12Tf 0 g"), ["Helv"]);
        // Strings and comments are not names; nothing panics on short or broken strings.
        assert_eq!(names("(/NotAFont) Tj % /Nor 1 Tf\n/Real 1 Tf"), ["Real"]);
        assert!(names("").is_empty());
        assert!(names("Tf").is_empty());
        assert!(names("12 Tf").is_empty());
        assert!(names("Helv 12 Tf 0 g").is_empty());
        assert_eq!(names(") > /A 1 Tf (unterminated"), ["A"]);
        assert_eq!(names("<zz> /B 1 Tf"), ["B"]);
        // An invalid escape stays as written.
        assert_eq!(names("/A#zz 1 Tf"), ["A#zz"]);
        // Content-stream operators name resources too.
        assert_eq!(
            names("q /GS1 gs /CS0 cs 1 scn /Im1 Do Q"),
            ["GS1", "CS0", "Im1"]
        );
        // Inline image data is not made of tokens: a `(` in it would hide what follows.
        assert_eq!(
            name_tokens(b"BI /W 1 /H 1 /BPC 8 /CS /G ID ( EI /F9 1 Tf"),
            None
        );
        assert_eq!(name_tokens(b"/A 1 Tf IDx"), Some(vec![b"A".to_vec()]));
    }

    #[test]
    fn the_signed_names_know_when_they_are_incomplete() {
        let store = Store::new_empty((1, 7));
        let dict = |text: &str| parse(text).as_dict().unwrap().clone();
        let two = dict("<< /DA (/F1 1 Tf/F2 1 Tf) >>");
        let mut names = SignedNames::default();
        names.add_da(&store, &two);
        names.add_da(&store, &dict("<< /T (no DA) >>"));
        assert!(names.complete);
        assert_eq!(names.names.len(), 2);
        assert_eq!(
            names.read, 1,
            "a dictionary without /DA is not a string read"
        );
        // Past the string limit, the collection is incomplete.
        for _ in 0..MAX_DA_STRINGS {
            names.add_da(&store, &two);
        }
        assert!(!names.complete);
        // Past the name limit too.
        let many: String = (0..=MAX_SIGNED_NAMES).map(|i| format!("/N{i} ")).collect();
        let mut names = SignedNames::default();
        names.add_da(&store, &dict(&format!("<< /DA ({many}) >>")));
        assert!(!names.complete);
        assert_eq!(names.names.len(), MAX_SIGNED_NAMES);
        // A /DA with inline image data cannot be read.
        let mut names = SignedNames::default();
        names.add_da(&store, &dict("<< /DA (/F1 1 Tf ID x) >>"));
        assert!(!names.complete);
    }

    /// A new stream object with `dict` (a dictionary's text) and `data`, encoded as `dict`'s
    /// `/Filter` says.
    fn add_stream(store: &mut Store, dict: &str, data: &[u8]) -> ObjectId {
        let dict = parse(dict).as_dict().unwrap().clone();
        store
            .add(Object::Stream(Box::new(Stream::new(
                dict,
                folioxide_syntax::StreamData::Encoded(data.to_vec()),
            ))))
            .unwrap()
    }

    #[test]
    fn the_signed_names_read_every_annotation_and_appearance_stream() {
        let mut store = Store::new_empty((1, 7));
        let decoded = Cell::new(0);
        // An appearance stream with /Resources of its own: its names count too (M4 QA round 1,
        // the F7 residual: a name its own resources lack may be looked up in /DR), and so do
        // those of the form XObjects it draws, nested.
        let nested = add_stream(&mut store, "<< /Subtype /Form >>", b"/Nested 1 Tf");
        let own = add_stream(
            &mut store,
            &format!(
                "<< /Resources << /Font << /F1 9 0 R >> /XObject << /Own {} 0 R >> >> >>",
                nested.num
            ),
            b"/F1 9 Tf /Own Do",
        );
        // One without: every name of its content counts, in a state dictionary too.
        let bare = add_stream(&mut store, "<< >>", b"q /GS7 gs BT /F7 9 Tf (x) Tj ET Q");
        let bare_state = add_stream(&mut store, "<< /Resources null >>", b"/Im3 Do");
        let states = store
            .add(parse(&format!(
                "<< /On {} 0 R /Off {} 0 R >>",
                bare_state.num, own.num
            )))
            .unwrap();
        let annotation = |text: &str| parse(text).as_dict().unwrap().clone();
        let mut names = SignedNames::default();
        names.add_annotation(
            &store,
            &annotation(&format!(
                "<< /Subtype /Widget /DA (/F2 9 Tf) /AP << /N {} 0 R /D {} 0 R /R {} 0 R >> >>",
                own.num, states.num, bare.num
            )),
            &decoded,
        );
        // A FreeText annotation's /DA counts as well.
        names.add_annotation(
            &store,
            &annotation("<< /Subtype /FreeText /DA (/F3 9 Tf 0 g) >>"),
            &decoded,
        );
        let got: Vec<&[u8]> = names.names.iter().map(Vec::as_slice).collect();
        assert_eq!(
            got,
            [
                b"F1".as_slice(),
                b"F2",
                b"F3",
                b"F7",
                b"GS7",
                b"Im3",
                b"Nested",
                b"Own"
            ],
            "{:?}",
            names.names
        );
        assert!(names.complete);
        assert_eq!(
            decoded.get(),
            16 + 12 + 33 + 7,
            "every stream is decoded once"
        );
        // Each appearance object is examined once.
        let before = decoded.get();
        names.add_annotation(
            &store,
            &annotation(&format!("<< /AP << /N {} 0 R >> >>", bare.num)),
            &decoded,
        );
        assert_eq!(decoded.get(), before);

        // A bare stream that cannot be decoded in full, or with inline image data, makes the
        // collection incomplete.
        for (dict, data) in [
            ("<< /Filter /FlateDecode >>", b"not flate".as_slice()),
            ("<< /Filter /DCTDecode >>", b"\xff\xd8"),
            ("<< >>", b"BI /W 1 ID ( EI /F9 1 Tf"),
        ] {
            let stream = add_stream(&mut store, dict, data);
            let mut names = SignedNames::default();
            names.add_annotation(
                &store,
                &annotation(&format!("<< /AP << /N {} 0 R >> >>", stream.num)),
                &decoded,
            );
            assert!(!names.complete, "{dict}");
        }
        // So does a spent decoding budget.
        let spent = Cell::new(MAX_BARE_APPEARANCE_TOTAL);
        let stream = add_stream(&mut store, "<< >>", b"/F8 1 Tf");
        let mut names = SignedNames::default();
        names.add_annotation(
            &store,
            &annotation(&format!("<< /AP << /N {} 0 R >> >>", stream.num)),
            &spent,
        );
        assert!(!names.complete);

        // A page's /Annots: an array (or null) is read; anything else is incomplete.
        let widget = store
            .add(parse("<< /Subtype /Widget /FT /Tx /DA (/F5 9 Tf) >>"))
            .unwrap();
        let mut names = SignedNames::default();
        let annots = parse(&format!("[{} 0 R 99 0 R null 5]", widget.num));
        names.add_page_annotations(&store, Some(&annots), &decoded);
        names.add_page_annotations(&store, Some(&Object::Null), &decoded);
        names.add_page_annotations(&store, None, &decoded);
        assert!(names.complete);
        assert!(names.names.contains(b"F5".as_slice()));
        assert_eq!(names.annotations, 4);
        names.add_page_annotations(&store, Some(&Object::Int(3)), &decoded);
        assert!(!names.complete);

        // A widget inherits the /DA of its field, which may be outside /Fields too; each
        // ancestor is read once, and a chain deeper than the field-depth limit is incomplete.
        let grandparent = store.add(parse("<< /T (G) /DA (/F4 9 Tf) >>")).unwrap();
        let parent = store
            .add(parse(&format!(
                "<< /T (P) /Parent {} 0 R >>",
                grandparent.num
            )))
            .unwrap();
        let kid = store
            .add(parse(&format!(
                "<< /Subtype /Widget /Parent {} 0 R >>",
                parent.num
            )))
            .unwrap();
        let annots = parse(&format!("[{} 0 R {} 0 R]", kid.num, kid.num));
        let mut names = SignedNames::default();
        names.add_page_annotations(&store, Some(&annots), &decoded);
        assert!(names.complete);
        assert!(names.names.contains(b"F4".as_slice()));
        assert_eq!(names.read, 1, "the grandparent's /DA is read once");
        let mut deepest = store.add(parse("<< /DA (/Deep 9 Tf) >>")).unwrap();
        for _ in 0..=field::MAX_FIELD_DEPTH {
            deepest = store
                .add(parse(&format!("<< /Parent {} 0 R >>", deepest.num)))
                .unwrap();
        }
        let annots = parse(&format!("[{} 0 R]", deepest.num));
        let mut names = SignedNames::default();
        names.add_page_annotations(&store, Some(&annots), &decoded);
        assert!(!names.complete);
        assert!(!names.names.contains(b"Deep".as_slice()));
        // Past the annotation limit.
        let mut names = SignedNames {
            annotations: MAX_SIGNED_ANNOTATIONS,
            ..SignedNames::default()
        };
        names.add_page_annotations(&store, Some(&annots), &decoded);
        assert!(!names.complete);
    }

    #[test]
    fn the_signed_names_read_patterns_and_type3_glyphs() {
        // M4 QA round 2, finding 22 (variants R1x-pattern-stream-no-resources and
        // R1x-type3-charproc-no-resources): a name used only inside a tiling pattern or a Type 3
        // glyph procedure of a signed appearance (without resources of its own) is a signed
        // name too.
        let mut store = Store::new_empty((1, 7));
        let decoded = Cell::new(0);
        let pattern = add_stream(
            &mut store,
            "<< /PatternType 1 /PaintType 1 /TilingType 1 /BBox [0 0 10 10] /XStep 10 /YStep 10 >>",
            b"BT /PatFont 9 Tf (x) Tj ET",
        );
        let glyph = add_stream(&mut store, "<< >>", b"0 0 d0 /GlyphImage Do");
        let procs = store
            .add(parse(&format!("<< /a {} 0 R >>", glyph.num)))
            .unwrap();
        let type3 = store
            .add(parse(&format!(
                "<< /Type /Font /Subtype /Type3 /CharProcs {} 0 R \
                 /Resources << /Font << /T3Inner 9 0 R >> >> >>",
                procs.num
            )))
            .unwrap();
        // Shared resource dictionaries are read once however many streams name them.
        let resources = store
            .add(parse(&format!(
                "<< /Pattern << /P1 {} 0 R >> /Font << /T3 {} 0 R \
                 /Inline << /Subtype /Type3 /CharProcs << /b {} 0 R >> >> >> >>",
                pattern.num, type3.num, glyph.num
            )))
            .unwrap();
        let appearance = add_stream(
            &mut store,
            &format!("<< /Subtype /Form /Resources {} 0 R >>", resources.num),
            b"/Pattern cs /P1 scn 0 0 10 10 re f BT /T3 9 Tf (a) Tj ET",
        );
        let second = add_stream(
            &mut store,
            &format!("<< /Subtype /Form /Resources {} 0 R >>", resources.num),
            b"/T3 9 Tf",
        );
        let mut names = SignedNames::default();
        for ap in [appearance, second] {
            names.add_annotation(
                &store,
                parse(&format!("<< /AP << /N {} 0 R >> >>", ap.num))
                    .as_dict()
                    .unwrap(),
                &decoded,
            );
        }
        for name in [
            b"P1".as_slice(),
            b"T3",
            b"PatFont",
            b"GlyphImage",
            b"Pattern",
        ] {
            assert!(
                names.names.contains(name),
                "{}: {:?}",
                String::from_utf8_lossy(name),
                names.names
            );
        }
        assert!(names.complete);
        assert!(names.resources.contains(&(resources.num, Role::Resources)));
        // The glyph is decoded once, though both Type 3 fonts name it.
        let expected = [
            b"/Pattern cs /P1 scn 0 0 10 10 re f BT /T3 9 Tf (a) Tj ET".as_slice(),
            b"/T3 9 Tf",
            b"BT /PatFont 9 Tf (x) Tj ET",
            b"0 0 d0 /GlyphImage Do",
        ]
        .iter()
        .map(|data| data.len())
        .sum::<usize>();
        assert_eq!(decoded.get(), expected, "every stream is decoded once");
    }

    #[test]
    fn the_signed_names_read_graphics_states_and_shared_roles() {
        // M4 QA round 3, findings 6 and 21 (variants R1y-extgstate-smask-group,
        // R1y-extgstate-font-type3, R1y-shared-category-dict-xobject-and-pattern): a name used
        // only by a soft mask's group or a graphics state's Type 3 font is a signed name, and a
        // dictionary shared by two roles is read in each.
        let mut store = Store::new_empty((1, 7));
        let decoded = Cell::new(0);
        let group = add_stream(
            &mut store,
            "<< /Subtype /Form /BBox [0 0 10 10] /Group << /S /Transparency >> >>",
            b"BT /MaskFont 9 Tf (x) Tj ET",
        );
        let glyph = add_stream(&mut store, "<< >>", b"0 0 d0 /StateGlyph Do");
        let type3 = store
            .add(parse(&format!(
                "<< /Type /Font /Subtype /Type3 /CharProcs << /a {} 0 R >> >>",
                glyph.num
            )))
            .unwrap();
        let mask = store
            .add(parse(&format!(
                "<< /Type /Mask /S /Luminosity /G {} 0 R >>",
                group.num
            )))
            .unwrap();
        // One dictionary of entries named both as /XObject and as /Pattern: the tiling pattern
        // under it is read as a pattern too.
        let pattern = add_stream(
            &mut store,
            "<< /PatternType 1 /PaintType 1 /TilingType 1 /BBox [0 0 10 10] /XStep 10 /YStep 10 >>",
            b"BT /SharedFont 9 Tf (y) Tj ET",
        );
        let shared = store
            .add(parse(&format!("<< /S0 {} 0 R >>", pattern.num)))
            .unwrap();
        let appearance = add_stream(
            &mut store,
            &format!(
                "<< /Subtype /Form /Resources << /ExtGState << /GS0 << /SMask {} 0 R >> \
                 /GS1 << /Font [{} 0 R 12] >> /GS2 << /SMask << /S /Alpha /G {} 0 R >> >> >> \
                 /XObject {s} 0 R /Pattern {s} 0 R >> >>",
                mask.num,
                type3.num,
                group.num,
                s = shared.num
            ),
            b"/GS0 gs /GS1 gs /GS2 gs",
        );
        let mut names = SignedNames::default();
        names.add_annotation(
            &store,
            parse(&format!("<< /AP << /N {} 0 R >> >>", appearance.num))
                .as_dict()
                .unwrap(),
            &decoded,
        );
        for name in [b"MaskFont".as_slice(), b"StateGlyph", b"SharedFont", b"GS0"] {
            assert!(
                names.names.contains(name),
                "{}: {:?}",
                String::from_utf8_lossy(name),
                names.names
            );
        }
        assert!(names.complete);
        // The objects read, for the canonical-input checks of a new /DR name (ruling R-12).
        for read in [appearance, group, glyph, type3, mask, shared, pattern] {
            assert!(names.objects.contains(&read.num), "{read}");
        }
    }

    #[test]
    fn the_page_walk_requires_parents_that_mirror_kids() {
        // M4 QA round 3, finding 11, ruling R-13.
        let tree = |pages: &str, page: &str, extra: &[(u32, &str)]| -> (Store, ObjectId) {
            let mut store = Store::new_empty((1, 7));
            let root = store.add(parse(pages)).unwrap();
            assert_eq!(root.num, 1);
            let leaf = store.add(parse(page)).unwrap();
            assert_eq!(leaf.num, 2);
            for (num, text) in extra {
                let id = store.add(parse(text)).unwrap();
                assert_eq!(id.num, *num);
            }
            (store, leaf)
        };
        let catalog = parse("<< /Type /Catalog /Pages 1 0 R >>");
        let catalog = catalog.as_dict();
        let walk =
            |store: &Store, page: ObjectId| PageWalk::read(store, catalog, 64, 1000).0.path(page);
        // A consistent tree: the page, then its parent.
        let (store, page) = tree(
            "<< /Type /Pages /Kids [2 0 R] /Count 1 /Rotate 90 >>",
            "<< /Type /Page /Parent 1 0 R >>",
            &[],
        );
        let (chain, consulted) = walk(&store, page).unwrap();
        assert_eq!(chain, [page, ObjectId::new(1, 0)]);
        assert_eq!(consulted, [2, 1]);
        for (pages, leaf, extra, needle) in [
            (
                "<< /Type /Pages /Kids [2 0 R] /Count 1 >>",
                "<< /Type /Page >>",
                &[][..],
                "/Parent",
            ),
            (
                "<< /Type /Pages /Kids [2 0 R] /Count 1 >>",
                "<< /Type /Page /Parent 3 0 R >>",
                &[(3, "<< /Type /Pages /Kids [2 0 R] /Count 1 >>")][..],
                "/Parent",
            ),
            (
                "<< /Type /Pages /Kids [2 0 R 2 0 R] /Count 2 >>",
                "<< /Type /Page /Parent 1 0 R >>",
                &[],
                "2 times",
            ),
            (
                "<< /Type /Pages /Kids [3 0 R 3 0 R] /Count 2 >>",
                "<< /Type /Page /Parent 3 0 R >>",
                &[(3, "<< /Type /Pages /Parent 1 0 R /Kids [2 0 R] /Count 1 >>")],
                "reached twice",
            ),
            (
                "<< /Type /Pages /Kids [2 0 R] /Count 1 /Parent 1 0 R >>",
                "<< /Type /Page /Parent 1 0 R >>",
                &[],
                "/Parent",
            ),
            (
                "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                "<< /Type /Page /Parent 1 0 R >>",
                &[(3, "<< /Type /Page /Parent 1 0 R >>")],
                "not reached",
            ),
        ] {
            let (store, page) = tree(pages, leaf, extra);
            let err = walk(&store, page).unwrap_err();
            assert!(err.contains(needle), "{pages} {leaf}: {err}");
        }
    }

    #[test]
    fn metadata_stays_below_libxml2_node_limits() {
        // M4 QA round 3, finding 19: a packet of MAX_XMP_BYTES bytes, however it is made up
        // (one comment, text node, attribute value, CDATA section, processing instruction or
        // white-space run), is read; one byte more is not, so no node Folioxide reads reaches
        // libxml2's 10,000,000-byte limits.
        const { assert!(MAX_XMP_BYTES < 10_000_000) };
        let store = Store::new_empty((1, 7));
        let head = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">";
        let tail = "</x:xmpmeta>";
        let shapes: [(&str, &str, u8); 6] = [
            ("<!--", "-->", b'c'),
            ("<t>", "</t>", b't'),
            ("<a v=\"", "\"/>", b'v'),
            ("<![CDATA[", "]]>", b'd'),
            ("<?pi ", "?>", b'p'),
            ("", "", b' '),
        ];
        for (open, close, fill) in shapes {
            for len in [MAX_XMP_BYTES, MAX_XMP_BYTES + 2] {
                let pad = len - head.len() - tail.len() - open.len() - close.len();
                let mut packet = head.as_bytes().to_vec();
                packet.extend_from_slice(open.as_bytes());
                packet.extend(std::iter::repeat_n(fill, pad));
                packet.extend_from_slice(close.as_bytes());
                packet.extend_from_slice(tail.as_bytes());
                assert_eq!(packet.len(), len);
                let mut dict = Dict::new();
                dict.insert("Length", Object::Int(len as i64));
                let stream = Stream::new(dict, folioxide_syntax::StreamData::Encoded(packet));
                let data = metadata::decode(&store, &stream, MAX_XMP_BYTES);
                assert_eq!(
                    data.as_deref().is_some_and(looks_like_xmp),
                    len <= MAX_XMP_BYTES,
                    "{open:?} of {len} bytes"
                );
            }
        }
    }

    #[test]
    fn forbidden_keys_of_a_new_signature_field() {
        for (field, key) in [
            ("<< /FT /Sig /T (S) /A << /S /URI >> >>", Some("A")),
            ("<< /FT /Sig /T (S) /AA << >> >>", Some("AA")),
            ("<< /FT /Sig /T (S) /OC 5 0 R >>", Some("OC")),
            ("<< /FT /Sig /T (S) /Parent 5 0 R >>", Some("Parent")),
            (
                "<< /FT /Sig /T (S) /MK << /BG [1] >> /TU (x) /DA (/Helv 0 Tf) >>",
                None,
            ),
            // QA round 2, finding 23: a whitelist, not a list of four refused keys.
            ("<< /FT /Sig /T (S) /DV 5 0 R >>", Some("DV")),
            ("<< /FT /Sig /T (S) /Popup 5 0 R >>", Some("Popup")),
            ("<< /FT /Sig /T (S) /Tabs /S >>", Some("Tabs")),
            ("<< /FT /Sig /T (S) /AF [] >>", Some("AF")),
            ("<< /FT /Sig /T (S) /Whatever 1 >>", Some("Whatever")),
            (
                "<< /Type /Annot /Subtype /Widget /FT /Sig /T (S) /V 9 0 R /F 132 /Rect [0 0 0 0] \
                 /P 3 0 R /AP << /N 8 0 R >> /MK << /R 90 >> /Lock 7 0 R /SV 6 0 R /Ff 0 \
                 /BS << /W 1 >> /Border [0 0 1] /C [0] /H /N /CA 1 /ca 1 /BM /Normal /NM (n) \
                 /M (D:2026) /Contents (c) /Lang (en) /StructParent 3 /AS /N /TU (t) /TM (m) \
                 /DA (/Helv 0 Tf 0 g) /Q 0 >>",
                None,
            ),
            ("[1 2]", None),
        ] {
            assert_eq!(
                forbidden_sig_field_key(&parse(field)).as_deref(),
                key,
                "{field}"
            );
        }
    }

    #[test]
    fn explained_keeps_the_lowest_level() {
        let mut explained = Explained::default();
        explained.add(7, ModificationLevel::FormFilling, ChangeClass::Signature);
        explained.add(
            7,
            ModificationLevel::LtaUpdates,
            ChangeClass::SignatureField,
        );
        explained.add(7, ModificationLevel::LtaUpdates, ChangeClass::Metadata);
        explained.add(8, ModificationLevel::FormFilling, ChangeClass::FormFill);
        assert_eq!(
            explained.get(7),
            Some((ModificationLevel::LtaUpdates, ChangeClass::SignatureField))
        );
        assert_eq!(
            explained.get(8),
            Some((ModificationLevel::FormFilling, ChangeClass::FormFill))
        );
        assert_eq!(explained.get(9), None);
    }

    #[test]
    fn usages_record_paths_and_page_parents() {
        let watched: BTreeSet<u32> = [5, 6].into_iter().collect();
        let page = parse(
            "<< /Type /Page /Parent 6 0 R /Resources << /Font << /F1 5 0 R >> >> \
             /Annots [1 0 R 6 0 R] >>",
        );
        let record = |field_tree: &BTreeSet<u32>| {
            let mut usages = BTreeMap::new();
            let mut crowded = BTreeSet::new();
            record_usages(
                &page,
                Referrer::Object(3),
                &watched,
                field_tree,
                &mut usages,
                &mut crowded,
            );
            assert!(crowded.is_empty());
            usages
        };
        let font = Usage {
            from: Referrer::Object(3),
            path: vec![
                Step::Key(b"Resources".to_vec()),
                Step::Key(b"Font".to_vec()),
                Step::Key(b"F1".to_vec()),
            ],
            objr: false,
        };
        let annots = Usage {
            from: Referrer::Object(3),
            path: vec![Step::Key(b"Annots".to_vec()), Step::Index(1)],
            objr: false,
        };
        let parent = Usage {
            from: Referrer::Object(3),
            path: vec![Step::Key(b"Parent".to_vec())],
            objr: false,
        };
        // A page's /Parent is a use: the page inherits /Resources from it (expert finding).
        let usages = record(&BTreeSet::new());
        assert_eq!(usages[&5], std::slice::from_ref(&font));
        assert_eq!(usages[&6].len(), 2);
        assert!(usages[&6].contains(&annots) && usages[&6].contains(&parent));
        // The field tree's /Parent link (a kid widget to its field) is not, as in pyHanko.
        let usages = record(&[6].into_iter().collect());
        assert_eq!(usages[&5], [font]);
        assert_eq!(usages[&6], [annots]);

        // Past the cap, an object is crowded.
        let mut usages = BTreeMap::new();
        let mut crowded = BTreeSet::new();
        let many = Object::Array(vec![Object::Ref(ObjectId::new(5, 0)); MAX_USAGES + 1]);
        record_usages(
            &many,
            Referrer::Trailer,
            &watched,
            &BTreeSet::new(),
            &mut usages,
            &mut crowded,
        );
        assert!(crowded.contains(&5));
    }

    #[test]
    fn page_tree_material_is_not_information() {
        let dict = |text: &str| parse(text).as_dict().unwrap().clone();
        for material in [
            "<< /Type /Pages /Count 1 >>",
            "<< /Type /Page >>",
            "<< /Kids [3 0 R] >>",
            "<< /Producer (x) /Resources << >> >>",
            "<< /MediaBox [0 0 612 792] >>",
            "<< /CropBox [0 0 1 1] >>",
            "<< /Rotate 90 >>",
            "<< /FT /Sig >>",
            "<< /V (x) >>",
            "<< /DA (/Helv 0 Tf) >>",
        ] {
            assert!(is_page_or_field_material(&dict(material)), "{material}");
            let info = parse("<< /Producer (x) >>");
            assert_eq!(
                information(&info, &parse(material), "info").0,
                ModificationLevel::Other,
                "{material}"
            );
            assert_eq!(
                information(&parse(material), &info, "info").0,
                ModificationLevel::Other,
                "{material}"
            );
        }
        for plain in [
            "<< /Producer (x) /Title (y) >>",
            "<< /Marked true >>",
            "<< /ADBE << /BaseVersion /1.7 /ExtensionLevel 8 >> >>",
        ] {
            assert!(!is_page_or_field_material(&dict(plain)), "{plain}");
            assert_eq!(
                information(&parse(plain), &parse("<< /Title (z) >>"), "info").0,
                ModificationLevel::LtaUpdates
            );
        }
        assert_eq!(
            information(&parse("<< >>"), &parse("[1]"), "info").0,
            ModificationLevel::Other
        );
    }
}

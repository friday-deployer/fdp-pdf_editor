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
//! - A **new** object must be explained by a rule, as pyHanko's explained references (the lowest
//!   level of the rules that explain it counts): a cross-reference or object stream, the trailer's
//!   new `/Info` dictionary, the catalog's new XMP `/Metadata` stream, `/Extensions` or
//!   `/MarkInfo` dictionary, a new AcroForm or `/Fields` array (`LtaUpdates`) and what a new
//!   `/DR` holds (`FormFilling`); a new signature field registered at the root of the new
//!   `/AcroForm /Fields` (pyHanko's `SigFieldCreationRule`: `/FT /Sig`, a `/T` without `.`, a
//!   widget if anything, without `/A`, `/AA`, `/OC` or `/Parent`, `LtaUpdates` when invisible
//!   and `FormFilling` when its `/Rect`, read through references, has an area), with the new
//!   objects its `/AP`, `/Lock` and `/SV` hold (`FormFilling`); the signature dictionary the `/V`
//!   of such a field or of an existing unsigned signature field names (`FormFilling`; a document
//!   timestamp `LtaUpdates`) and its `/TransformParams`; the new `/AP` of an existing unsigned
//!   signature field that the revision signs, and its `/N /R /D` streams (`FormFilling`); a
//!   page's new `/Annots` array (`LtaUpdates`); and an orphan, a new object neither the trailer
//!   nor a changed object reaches through new objects (`LtaUpdates`, pyHanko's
//!   `ignore_orphaned_objects`). Anything else new, an annotation on a page that is not a
//!   registered signature widget or a new signature field with an action for example, is
//!   `Other`, as is a new object an object of the signed revision already referred to (a
//!   dangling reference that now resolves).
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
//!   appearance stream without `/Resources` of its own names, `FormFilling`; any change to
//!   `/NeedAppearances` or `/DA`, any `/Q` change, changing or removing a `/DR` name and any
//!   other key are `Other`), the `/Fields` array, an unsigned signature field (pyHanko's
//!   `SigFieldModificationRule`: a revision that signs it, its `/V` key absent before and now a
//!   new signature dictionary, may also change `/AP`, `/AS` and `/F`, `FormFilling`; a field that
//!   stays unsigned may change only `/Ff`, `LtaUpdates`), a page or `/Annots` array (only new
//!   signature widgets appended: `LtaUpdates`), the `/Info` dictionary or the XMP metadata stream
//!   (`LtaUpdates`); everything else is `Other` (DECISIONS D10 D-9: stricter than pyHanko for
//!   generic form fields, annotations and `/DSS`). A role is granted only when the object has no
//!   other use in the signed revision (pyHanko clears an overridden reference only once every
//!   path that reaches it is approved): an `/Info` dictionary that is also a page's content
//!   stream, or a `/MarkInfo` dictionary that is also a font, is `Other`. Unlike pyHanko, a
//!   page's `/Parent` counts as a use (a page inherits `/Resources`, `/MediaBox`, `/CropBox` and
//!   `/Rotate` through it), and an `/Info`, `/Extensions` or `/MarkInfo` dictionary with
//!   page-tree or form-field entries is never only information. The `/Info`, `/Extensions` and
//!   `/MarkInfo` objects are never streams (pyHanko's `safe_whitelist`), and a metadata stream
//!   must look like XMP (pyHanko's `MetadataUpdateRule`: well-formed XML without entities whose
//!   root is `x:xmpmeta`, checked on at most 16 MiB of decoded data) in both revisions.
//! - The trailer: a different `/Root` (the Hide-and-Replace root switch) or `/Encrypt` is
//!   `Other`, and `/Info` may only stay or point to a new object.
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

/// The largest metadata stream decoded to check that it is XMP; a larger one is not XMP
/// (QA finding: a Flate bomb as `/Metadata` must not cost a large allocation).
pub(crate) const MAX_XMP_BYTES: usize = 16 * 1024 * 1024;

/// The metadata bytes decoded in total by the analyses of one verification; beyond it a
/// metadata stream that is not decoded yet is not XMP.
const MAX_XMP_TOTAL: usize = 64 * 1024 * 1024;

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

/// The result of [`Revisions::modification`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ModificationOutcome {
    /// The worst modification level.
    pub(crate) level: ModificationLevel,
    /// The objects the later revisions list (free entries included), sorted: the first
    /// [`MAX_CHANGED_OBJECTS`] of them.
    pub(crate) changed: Vec<ObjectId>,
    /// How many objects the later revisions list in all.
    pub(crate) changed_total: usize,
    /// Why the level is what it is, for the report's warnings (at most [`MAX_NOTES`]).
    pub(crate) notes: Vec<String>,
}

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
    /// The modification analyses done, by signed revision (signatures that cover the same
    /// revision share one).
    outcomes: RefCell<BTreeMap<usize, ModificationOutcome>>,
    /// The work left for the modification analyses ([`MAX_MODIFICATION_WORK`]).
    work_left: Cell<u64>,
    /// Whether a metadata stream looks like XMP, by object number and the entry it is read from.
    xmp: RefCell<HashMap<(u32, Option<XrefEntry>), bool>>,
    /// The metadata bytes decoded so far ([`MAX_XMP_TOTAL`]).
    xmp_decoded: Cell<usize>,
    /// The appearance-stream bytes [`SignedNames`] decoded so far
    /// ([`MAX_BARE_APPEARANCE_TOTAL`]).
    appearance_decoded: Cell<usize>,
}

impl<'d> Revisions<'d> {
    /// Reads the revision structure of `doc`.
    pub(crate) fn new(doc: &'d Document) -> Revisions<'d> {
        let store = doc.store();
        let count = store.revisions().len();
        let mut entries = Vec::with_capacity(count);
        let mut first = Vec::with_capacity(count);
        let mut conflicts = Vec::with_capacity(count);
        let mut listed_before = Vec::with_capacity(count.saturating_add(1));
        listed_before.push(0u64);
        for index in 0..count {
            let listed = store.revision_entries(index).ok();
            let mut map: BTreeMap<u32, XrefEntry> = BTreeMap::new();
            let mut conflicting = BTreeSet::new();
            for (num, entry) in listed.iter().flatten() {
                match map.get(num) {
                    Some(seen) if seen != entry => {
                        conflicting.insert(*num);
                    }
                    Some(_) => {}
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
            listed_before,
            views: (0..count).map(|_| OnceCell::new()).collect(),
            refs: OnceCell::new(),
            shareable: !store.structure_repaired() && store.recovered_objects().is_empty(),
            facts: (0..count).map(|_| RefCell::new(BTreeMap::new())).collect(),
            root_fields: (0..count).map(|_| OnceCell::new()).collect(),
            outcomes: RefCell::new(BTreeMap::new()),
            work_left: Cell::new(
                MAX_MODIFICATION_WORK
                    .saturating_add(total_entries.saturating_mul(MODIFICATION_WORK_PER_ENTRY)),
            ),
            xmp: RefCell::new(HashMap::new()),
            xmp_decoded: Cell::new(0),
            appearance_decoded: Cell::new(0),
        }
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

    /// What the revisions after revision `k` changed, compared with revision `k` (analysed once
    /// per revision).
    pub(crate) fn modification(&self, k: usize) -> ModificationOutcome {
        if let Some(known) = self.outcomes.borrow().get(&k) {
            return known.clone();
        }
        let outcome = self.analyse(k);
        self.outcomes.borrow_mut().insert(k, outcome.clone());
        outcome
    }

    /// [`Revisions::modification`] without the cache.
    fn analyse(&self, k: usize) -> ModificationOutcome {
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
            changed_total: changed.len(),
            changed: changed.into_iter().take(MAX_CHANGED_OBJECTS).collect(),
            notes: Vec::new(),
        };
        if k.saturating_add(1) >= count {
            return outcome;
        }
        let mut diff = Diff {
            level: ModificationLevel::LtaUpdates,
            notes: Vec::new(),
        };
        if count > MAX_ANALYSED_REVISIONS || count - k - 1 > MAX_REVISIONS_AFTER_SIGNATURE {
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
                    for r in k + 1..count {
                        if !self.spend_work(k, r) {
                            diff.other(self.budget_spent(k));
                            break;
                        }
                        match self.view(r) {
                            Some(new) => self.compare(&base, old, new, k, r, &mut diff),
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
    /// like an XMP packet ([`looks_like_xmp`]), decoding at most [`MAX_XMP_BYTES`] of it and
    /// each stream once per verification.
    fn is_xmp(&self, store: &Store, rev: usize, id: ObjectId) -> bool {
        let key = (id.num, self.entry_at(id.num, rev));
        if let Some(&known) = self.xmp.borrow().get(&key) {
            return known;
        }
        let verdict = match store.resolve(id).as_deref() {
            Ok(Object::Stream(stream)) => {
                let left = MAX_XMP_TOTAL.saturating_sub(self.xmp_decoded.get());
                match store.stream_data_capped(stream, MAX_XMP_BYTES.min(left)) {
                    Ok(Some(bytes)) => {
                        self.xmp_decoded
                            .set(self.xmp_decoded.get().saturating_add(bytes.data.len()));
                        bytes.is_fully_decoded() && !bytes.truncated && looks_like_xmp(&bytes.data)
                    }
                    // Too large, or not decodable: not an XMP packet.
                    _ => false,
                }
            }
            _ => false,
        };
        self.xmp.borrow_mut().insert(key, verdict);
        verdict
    }

    /// Compares revision `r` with the signed revision `k` (pyHanko's `apply(old, new)`).
    fn compare(
        &self,
        base: &Base,
        old: &Document,
        new: &Document,
        k: usize,
        r: usize,
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
                continue; // a re-listing
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
                            if !same_value(old_store, &old_value, new_store, &new_value) {
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
        let cx = Cx {
            revisions: self,
            old: old_store,
            new: new_store,
            k,
            r,
            new_values: &new_values,
            new_catalog,
        };
        let mut explained = Explained::default();

        // The rules pyHanko applies to every comparison, whatever changed.
        cx.info_rule(&mut explained, diff);
        if let (Some(old_catalog), Some(new_catalog)) = (old_catalog, new_catalog) {
            cx.catalog_reference_rules(old_catalog, new_catalog, &mut explained, diff);
        }

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
                NewKind::SigField { .. } => match forbidden_sig_field_key(&fact.value) {
                    Some(key) => {
                        diff.other(format!(
                            "revision {r} adds the signature field {num} with /{key}, which no \
                             signer writes on a new signature field (an action, optional content \
                             or a parent)"
                        ));
                        NewKind::Other
                    }
                    None => kind,
                },
                kind => kind,
            };
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

        // What the new objects' kinds explain.
        for (&num, kind) in &kinds {
            let Some(value) = new_values.get(&num).map(|fact| &fact.value) else {
                continue;
            };
            match *kind {
                NewKind::XrefStream | NewKind::ObjStm => {
                    explained.add(num, ModificationLevel::LtaUpdates);
                }
                NewKind::SigDict { timestamp } => {
                    explained.add(
                        num,
                        if timestamp {
                            ModificationLevel::LtaUpdates
                        } else {
                            ModificationLevel::FormFilling
                        },
                    );
                    cx.explain_transform_params(value, &mut explained);
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
                    explained.add(
                        num,
                        if visible {
                            ModificationLevel::FormFilling
                        } else {
                            ModificationLevel::LtaUpdates
                        },
                    );
                    // pyHanko clears what the field's /AP, /Lock and /SV hold as form filling;
                    // anything else only the field refers to (an indirect /Rect) stays
                    // unexplained.
                    for key in [b"AP".as_slice(), b"Lock", b"SV"] {
                        if let Some(held) = dict.and_then(|d| d.get(key)) {
                            for dep in cx.new_dependencies(held) {
                                explained.add(dep, ModificationLevel::FormFilling);
                            }
                        }
                    }
                }
                NewKind::Other => {}
            }
        }

        // Changed objects: by their role in the signed revision.
        let rules = Rules {
            cx: &cx,
            kinds: &kinds,
            base,
            reasons: RefCell::new(Vec::new()),
        };
        for change in &changed {
            let level = rules.classify(base, change, diff);
            diff.raise(level);
            rules.explain_changed(base, change, &mut explained);
        }

        // New objects: explained, orphans (pyHanko's ignore_orphaned_objects), or other.
        let reachable = cx.reachable_new(new_trailer, &changed);
        for &num in new_values.keys() {
            let level = if base.dangling.contains(&num) {
                diff.other(format!(
                    "object {num}, added after signing, was already referenced by the signed \
                     revision"
                ));
                ModificationLevel::Other
            } else if !reachable.contains(&num) {
                ModificationLevel::LtaUpdates
            } else if let Some(level) = explained.get(num) {
                level
            } else {
                diff.other(format!(
                    "revision {r} adds object {num}, which no allowed change explains"
                ));
                ModificationLevel::Other
            };
            diff.raise(level);
        }
    }
}

/// An object of the signed revision that a later revision changed: its values then and now.
struct Changed {
    id: ObjectId,
    old: Arc<Object>,
    new: Arc<Object>,
}

/// The new objects a comparison explains, each at the lowest level a rule gives it (pyHanko
/// collects explained references per level and checks the lowest first).
#[derive(Default)]
struct Explained(BTreeMap<u32, ModificationLevel>);

impl Explained {
    fn add(&mut self, num: u32, level: ModificationLevel) {
        let entry = self.0.entry(num).or_insert(level);
        *entry = (*entry).min(level);
    }

    fn get(&self, num: u32) -> Option<ModificationLevel> {
        self.0.get(&num).copied()
    }
}

/// The context of one comparison of the signed revision `k` with a later revision `r`.
struct Cx<'a, 'd> {
    revisions: &'a Revisions<'d>,
    /// The view of revision `k`.
    old: &'a Store,
    /// The view of revision `r`.
    new: &'a Store,
    k: usize,
    r: usize,
    /// The objects new since `k`, as revision `r` shows them.
    new_values: &'a BTreeMap<u32, Rc<Fact>>,
    /// The catalog of revision `r`.
    new_catalog: Option<&'a Dict>,
}

impl Cx<'_, '_> {
    /// Whether `id` is a new object (not in use in the signed revision).
    fn is_new(&self, id: ObjectId) -> bool {
        self.new_values.contains_key(&id.num)
    }

    /// The new objects `value` reaches through new objects (pyHanko's
    /// `collect_dependencies(since_revision=k+1)`).
    fn new_dependencies(&self, value: &Object) -> Vec<u32> {
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        let mut queue: Vec<u32> = references_of(value)
            .into_iter()
            .filter(|n| self.new_values.contains_key(n))
            .collect();
        let mut out = Vec::new();
        while let Some(num) = queue.pop() {
            if !seen.insert(num) {
                continue;
            }
            out.push(num);
            if let Some(held) = self.new_values.get(&num) {
                queue.extend(
                    held.refs
                        .iter()
                        .copied()
                        .filter(|n| self.new_values.contains_key(n) && !seen.contains(n)),
                );
            }
        }
        out
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
            Some(id) if self.is_new(id) => explained.add(id.num, ModificationLevel::LtaUpdates),
            Some(id) => diff.other(format!(
                "revision {r} points the trailer's /Info to the existing object {id}"
            )),
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
                    explained.add(id.num, ModificationLevel::LtaUpdates);
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
                    explained.add(id.num, ModificationLevel::LtaUpdates);
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
            explained.add(id.num, ModificationLevel::LtaUpdates);
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
                explained.add(id.num, ModificationLevel::LtaUpdates);
            }
            if let Some(dr) = acroform.get(b"DR") {
                for dep in self.new_dependencies(dr) {
                    explained.add(dep, ModificationLevel::FormFilling);
                }
            }
        }
    }

    /// The `/TransformParams` dictionaries of a new signature dictionary's direct `/Reference`
    /// entries (pyHanko whitelists them with the signature).
    fn explain_transform_params(&self, sig: &Object, explained: &mut Explained) {
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
                explained.add(id.num, ModificationLevel::FormFilling);
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
    /// The indirect `/Kids` arrays of fields.
    kids_arrays: BTreeSet<u32>,
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
    /// Where the objects with a role that later revisions list are used in revision `k`.
    usages: BTreeMap<u32, Vec<Usage>>,
    /// Those used more than [`MAX_USAGES`] times.
    crowded: BTreeSet<u32>,
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
        let mut kids_arrays = BTreeSet::new();
        let mut signed_names = SignedNames::default();
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
            for node in nodes {
                if node.terminal {
                    // The field, merged with its widget, or its widget kids.
                    signed_names.add_annotation(store, &node.dict, decoded);
                    signed_names.add_kids(store, &node.dict, decoded);
                } else {
                    signed_names.add_da(store, &node.dict);
                }
                if let Some(kids) = node.dict.get_ref(b"Kids") {
                    kids_arrays.insert(kids.num);
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
            .collect();
        watched.retain(|num| changed_later.contains(num));
        let mut usages: BTreeMap<u32, Vec<Usage>> = BTreeMap::new();
        let mut crowded = BTreeSet::new();
        let field_tree: BTreeSet<u32> = fields.keys().copied().collect();
        if !watched.is_empty() {
            // Reachable from the trailer in revision k.
            let mut reachable: BTreeSet<u32> = BTreeSet::new();
            let mut queue: Vec<u32> = trailer_refs;
            while let Some(num) = queue.pop() {
                if num == 0 || !in_use_at_k(num) || !reachable.insert(num) {
                    continue;
                }
                queue.extend(refs_at_k(num).iter().copied());
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

        Base {
            listed,
            containers,
            dangling,
            root,
            acroform: acroform_ref.map(|id| id.num),
            fields_array,
            fields,
            kids_arrays,
            pages,
            annots_arrays,
            info,
            metadata,
            extensions,
            mark_info,
            signed_names_complete: signed_names.complete,
            signed_names: signed_names.names,
            usages,
            crowded,
        }
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
        self.usages
            .get(&num)
            .is_none_or(|uses| uses.iter().all(|usage| self.usage_allowed(num, usage)))
    }

    fn usage_allowed(&self, num: u32, usage: &Usage) -> bool {
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
                    || self.kids_arrays.contains(&o)
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
}

/// The most default appearance strings [`SignedNames`] reads in one signed revision.
const MAX_DA_STRINGS: usize = 4096;

/// The most names [`SignedNames`] keeps for one signed revision.
const MAX_SIGNED_NAMES: usize = 16_384;

/// The most `/Annots` entries of the signed revision's pages [`SignedNames`] visits.
const MAX_SIGNED_ANNOTATIONS: usize = 65_536;

/// The most appearance objects (streams, or dictionaries of appearance states) [`SignedNames`]
/// examines in one signed revision.
const MAX_SIGNED_APPEARANCES: usize = 16_384;

/// The largest appearance stream without `/Resources` of its own that [`SignedNames`] decodes
/// to read its names; a larger one makes the collection incomplete.
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
///   states, §12.5.5) of those annotations and widgets that has no `/Resources` dictionary of
///   its own, since some viewers resolve its names in `/DR`.
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
    /// The appearance objects examined, by object number (each once).
    appearances: HashSet<u32>,
    /// The ancestors of page annotations read, by object number (each once).
    parents: HashSet<u32>,
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
    /// its `/DA` and its appearance streams without `/Resources` of their own. `decoded` counts
    /// the appearance bytes the verification decoded ([`MAX_BARE_APPEARANCE_TOTAL`]).
    fn add_annotation(&mut self, store: &Store, annotation: &Dict, decoded: &Cell<usize>) {
        self.add_da(store, annotation);
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
                if self.appearances.contains(&id.num) {
                    return;
                }
                if self.appearances.len() >= MAX_SIGNED_APPEARANCES {
                    self.complete = false;
                    return;
                }
                self.appearances.insert(id.num);
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
            Object::Stream(stream) => self.add_bare_stream(store, stream, decoded),
            Object::Dict(dict) if states => {
                for state in dict.values() {
                    self.add_appearance(store, state, false, decoded);
                }
            }
            _ => {}
        }
    }

    /// Adds the name tokens of an appearance stream that has no `/Resources` dictionary of its
    /// own, decoding at most [`MAX_BARE_APPEARANCE_BYTES`] of it; one that cannot be decoded in
    /// full makes the collection incomplete.
    fn add_bare_stream(&mut self, store: &Store, stream: &Stream, decoded: &Cell<usize>) {
        let own_resources = stream
            .dict
            .get(b"Resources")
            .and_then(|resources| store.deref(resources).ok())
            .is_some_and(|resources| resources.as_dict().is_some());
        if own_resources {
            return;
        }
        let left = MAX_BARE_APPEARANCE_TOTAL.saturating_sub(decoded.get());
        match store.stream_data_capped(stream, MAX_BARE_APPEARANCE_BYTES.min(left)) {
            Ok(Some(bytes)) if bytes.is_fully_decoded() && !bytes.truncated => {
                decoded.set(decoded.get().saturating_add(bytes.data.len()));
                self.add_names_of(&bytes.data);
            }
            _ => self.complete = false,
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
            if let Object::Ref(id) = &value
                && !self.parents.insert(id.num)
            {
                return; // read already, with its own ancestors
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
    let mut stack: Vec<(&Object, Vec<Step>)> = vec![(value, Vec::new())];
    while let Some((obj, path)) = stack.pop() {
        if path.len() > MAX_REF_DEPTH {
            continue;
        }
        let dict = match obj {
            Object::Ref(id) => {
                if watched.contains(&id.num) {
                    let uses = usages.entry(id.num).or_default();
                    if uses.len() < MAX_USAGES {
                        uses.push(Usage { from, path });
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
                        stack.push((item, next));
                    }
                }
                continue;
            }
            Object::Dict(dict) => dict,
            Object::Stream(stream) => &stream.dict,
            _ => continue,
        };
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
            stack.push((item, next));
        }
    }
}

/// The level and the reasons of one analysis.
struct Diff {
    level: ModificationLevel,
    notes: Vec<String>,
}

impl Diff {
    fn raise(&mut self, level: ModificationLevel) {
        self.level = self.level.max(level);
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

/// The keys a new signature field (merged with its widget) may not carry: an action `/A`
/// (§12.5.6.19), additional actions `/AA` (§12.6.3: on focus, on page open, on activation) and
/// optional content `/OC` (§12.5.2, §8.11: it shows or hides the widget by a state set
/// elsewhere); and `/Parent`, which a field at the root of `/Fields` does not have
/// (§12.7.4.1). No signer writes them; a JavaScript, launch or URI action on a new invisible
/// field would otherwise pass as an LTA update (brief §5 V10 (1), the whitelist; stricter than
/// pyHanko). `/MK` (appearance characteristics, which Acrobat writes for visible signatures)
/// stays allowed.
const SIG_FIELD_FORBIDDEN_KEYS: &[&str] = &["A", "AA", "OC", "Parent"];

/// The first key of [`SIG_FIELD_FORBIDDEN_KEYS`] that the new signature field `value` carries.
fn forbidden_sig_field_key(value: &Object) -> Option<&'static str> {
    let dict = value.as_dict()?;
    SIG_FIELD_FORBIDDEN_KEYS
        .iter()
        .copied()
        .find(|key| dict.contains_key(key.as_bytes()))
}

/// Whether an annotation shows anything (§12.5.2): its `/Rect`, read through references, has an
/// area. No `/Rect` (or `null`) is invisible, as in pyHanko; a `/Rect` that cannot be read as
/// four numbers counts as visible, the conservative choice.
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
    kinds: &'a BTreeMap<u32, NewKind>,
    /// What the analyses know about the signed revision (the names it takes from `/DR`).
    base: &'a Base,
    /// Why the rules applied to the current object refused a change (for the notes).
    reasons: RefCell<Vec<String>>,
}

impl Rules<'_, '_, '_> {
    /// `Other`, with `reason` for the notes.
    fn refuse(&self, reason: impl Into<String>) -> ModificationLevel {
        self.reasons.borrow_mut().push(reason.into());
        ModificationLevel::Other
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
            matches!(self.kinds.get(&id.num), Some(NewKind::SigField { widget, .. }) if *widget || !on_page)
        })
    }

    fn is_new_sig_dict(&self, obj: &Object) -> bool {
        obj.as_ref().is_some_and(|id| {
            matches!(
                self.kinds.get(&id.num),
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
                self.arrays(old, new, false)
            } else {
                self.refuse("the new AcroForm no longer names it as /Fields")
            };
            (level, "the AcroForm /Fields array")
        } else if let Some(&(signature, signed, terminal)) = base.fields.get(&num) {
            if signature && !signed && terminal {
                (
                    self.dicts(old, new, |o, n| self.unsigned_sig_field(o, n)),
                    "an unsigned signature field",
                )
            } else if signature && signed {
                (ModificationLevel::Other, "a signed signature field")
            } else {
                // Any other field (D-9: generic form filling is not classified until M4).
                (ModificationLevel::Other, "a form field")
            }
        } else if base.pages.contains(&num) {
            path_role = false;
            (self.dicts(old, new, |o, n| self.page(o, n)), "a page")
        } else if let Some(owners) = base.annots_arrays.get(&num) {
            let level = if self.annots_still_owned(num, owners) {
                self.arrays(old, new, true)
            } else {
                self.refuse("a page no longer names it as /Annots")
            };
            (level, "a page's /Annots array")
        } else if Some(num) == base.info {
            // pyHanko's safe_whitelist: an updated dictionary, never a stream; and only the
            // dictionary the new trailer names (QA finding: the old /Info changed while the
            // trailer moves to a new one or drops /Info).
            if self.new_trailer_ref(b"Info") == Some(num) {
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
    /// called only for a field that goes from unsigned to signed, `FormFilling`), and a page's
    /// new `/Annots` array (`LtaUpdates`).
    fn explain_changed(&self, base: &Base, change: &Changed, explained: &mut Explained) {
        let num = change.id.num;
        let Some(new) = change.new.as_dict() else {
            return;
        };
        if base.is_unsigned_sig_field(num)
            && change
                .old
                .as_dict()
                .is_some_and(|old| self.signs_field(old, new))
            && let Some(ap) = new.get(b"AP")
        {
            if let Some(id) = ap.as_ref().filter(|id| self.cx.is_new(*id)) {
                explained.add(id.num, ModificationLevel::FormFilling);
            }
            let ap = self.cx.new.deref(ap).ok();
            if let Some(ap) = ap.as_deref().and_then(Object::as_dict) {
                for key in [b"N".as_slice(), b"R", b"D"] {
                    if let Some(held) = ap.get(key) {
                        for dep in self.cx.new_dependencies(held) {
                            explained.add(dep, ModificationLevel::FormFilling);
                        }
                    }
                }
            }
        }
        if base.pages.contains(&num)
            && let Some(id) = new.get_ref(b"Annots").filter(|id| self.cx.is_new(*id))
        {
            explained.add(id.num, ModificationLevel::LtaUpdates);
        }
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
    /// or new signature widgets (`/Annots`, `on_page`).
    fn arrays(&self, old: &Object, new: &Object, on_page: bool) -> ModificationLevel {
        let level = match (old.as_array(), new.as_array()) {
            (Some(o), Some(n)) => self.appended_sig_fields(o, n, on_page),
            _ => ModificationLevel::Other,
        };
        if level == ModificationLevel::Other {
            return self.refuse(if on_page {
                "it gains something other than new signature widgets at its end"
            } else {
                "it gains something other than new root-level signature fields at its end"
            });
        }
        level
    }

    /// `new` is `old` plus references to new registered signature fields (widgets, for a
    /// page's `/Annots`) at the end: `LtaUpdates`.
    fn appended_sig_fields(
        &self,
        old: &[Object],
        new: &[Object],
        on_page: bool,
    ) -> ModificationLevel {
        match new.strip_prefix(old) {
            Some(added) if added.iter().all(|o| self.is_new_sig_field(o, on_page)) => {
                ModificationLevel::LtaUpdates
            }
            _ => ModificationLevel::Other,
        }
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
                b"Version" => ModificationLevel::LtaUpdates,
                b"Extensions" | b"MarkInfo" => self.kept_reference(old.get(key), new.get(key)),
                b"Metadata" => match new.get(key) {
                    None => ModificationLevel::LtaUpdates,
                    Some(Object::Ref(id))
                        if self.cx.revisions.is_xmp(self.cx.new, self.cx.r, *id) =>
                    {
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
                b"DR" => self.default_resources(old.get(key), new.get(key)),
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
    /// appearance stream without `/Resources` of its own; a name that would now resolve), or
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
                 an appearance stream without /Resources of its own)",
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
    fn unsigned_sig_field(&self, old: &Dict, new: &Dict) -> ModificationLevel {
        let signing = self.signs_field(old, new);
        let mut level = ModificationLevel::LtaUpdates;
        for key in Self::changed_keys(old, new) {
            let key_level = match key {
                b"Ff" => ModificationLevel::LtaUpdates,
                b"V" if signing => ModificationLevel::FormFilling,
                b"AP" if signing => self.appearance(old.get(key), new.get(key)),
                b"AS" | b"F" if signing => ModificationLevel::FormFilling,
                _ => ModificationLevel::Other,
            };
            level = level.max(key_level);
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
    /// direct, unchanged or a new object, never another existing object, and a dictionary.
    fn appearance(&self, old: Option<&Object>, new: Option<&Object>) -> ModificationLevel {
        let Some(new) = new else {
            return ModificationLevel::Other;
        };
        if self.kept_reference(old, Some(new)) == ModificationLevel::Other {
            return ModificationLevel::Other;
        }
        match self.cx.new.deref(new) {
            Ok(value) if value.as_dict().is_some() => ModificationLevel::FormFilling,
            _ => ModificationLevel::Other,
        }
    }

    /// A page (§7.7.3.3): only new signature widgets may be appended to `/Annots`.
    fn page(&self, old: &Dict, new: &Dict) -> ModificationLevel {
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
                        (Some(o), Some(n)) if annots_ok => self.appended_sig_fields(&o, &n, true),
                        _ => ModificationLevel::Other,
                    };
                    if annots == ModificationLevel::Other {
                        self.refuse("/Annots gains something other than new signature widgets")
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

/// The deepest element nesting [`looks_like_xmp`] follows.
const MAX_XML_DEPTH: usize = 256;

/// Whether `data` looks like an XMP packet (ISO 16684-1 §7.3): UTF-8 XML whose single root
/// element is `xmpmeta` in the `adobe:ns:meta/` namespace, with balanced tags and no document
/// type or entity declaration.
///
/// pyHanko's `MetadataUpdateRule` parses the stream with lxml, refuses entities and requires
/// the root `{adobe:ns:meta/}xmpmeta`; this is a lighter well-formedness check of the same
/// shape (tags, processing instructions, comments and CDATA sections are matched; attribute
/// syntax and character references are not checked), with a depth limit.
fn looks_like_xmp(data: &[u8]) -> bool {
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let mut rest = text;
    let mut open: Vec<&str> = Vec::new();
    let mut root: Option<bool> = None;
    while let Some((before, markup)) = rest.split_once('<') {
        if open.is_empty() && !before.trim().is_empty() {
            return false; // text outside the root element
        }
        let after = if let Some(pi) = markup.strip_prefix('?') {
            pi.split_once("?>").map(|(_, after)| after)
        } else if let Some(comment) = markup.strip_prefix("!--") {
            comment.split_once("-->").map(|(_, after)| after)
        } else if let Some(cdata) = markup.strip_prefix("![CDATA[") {
            if open.is_empty() {
                return false;
            }
            cdata.split_once("]]>").map(|(_, after)| after)
        } else if markup.starts_with('!') {
            // <!DOCTYPE ...>, <!ENTITY ...>: entities are refused, as pyHanko does.
            return false;
        } else if let Some(end_tag) = markup.strip_prefix('/') {
            let Some((name, after)) = end_tag.split_once('>') else {
                return false;
            };
            if open.pop() != Some(name.trim_end()) {
                return false;
            }
            Some(after)
        } else {
            let Some((tag, after)) = split_start_tag(markup) else {
                return false;
            };
            let (tag, empty) = match tag.strip_suffix('/') {
                Some(tag) => (tag, true),
                None => (tag, false),
            };
            let (name, attributes) = tag
                .split_once(|c: char| c.is_ascii_whitespace())
                .unwrap_or((tag, ""));
            if name.is_empty() {
                return false;
            }
            if open.is_empty() {
                if root.is_some() {
                    return false; // a second root element
                }
                root = Some(is_xmpmeta(name, attributes));
            }
            if !empty {
                if open.len() >= MAX_XML_DEPTH {
                    return false;
                }
                open.push(name);
            }
            Some(after)
        };
        let Some(after) = after else {
            return false; // unterminated markup
        };
        rest = after;
    }
    open.is_empty() && rest.trim().is_empty() && root == Some(true)
}

/// Splits `markup` (after its `<`) at the `>` that ends the start tag, outside quoted
/// attribute values: the tag text and what follows.
fn split_start_tag(markup: &str) -> Option<(&str, &str)> {
    let mut quote: Option<char> = None;
    for (i, c) in markup.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), _) if c == q => quote = None,
            (None, '>') => {
                let (tag, rest) = markup.split_at(i);
                return Some((tag, rest.get(1..).unwrap_or_default()));
            }
            _ => {}
        }
    }
    None
}

/// Whether a start tag is `xmpmeta` in the `adobe:ns:meta/` namespace.
fn is_xmpmeta(name: &str, attributes: &str) -> bool {
    let (prefix, local) = match name.split_once(':') {
        Some((prefix, local)) => (Some(prefix), local),
        None => (None, name),
    };
    if local != "xmpmeta" {
        return false;
    }
    let declaration = match prefix {
        Some(prefix) => format!("xmlns:{prefix}"),
        None => "xmlns".to_owned(),
    };
    let compact: String = attributes
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    ['"', '\'']
        .iter()
        .any(|q| compact.contains(&format!("{declaration}={q}adobe:ns:meta/{q}")))
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
        let ample = Revisions::new(&doc).modification(0);
        assert_eq!(
            ample.level,
            ModificationLevel::LtaUpdates,
            "{:?}",
            ample.notes
        );
        // Too little budget to open the views: Other, and the notes say why.
        let starved = Revisions::new(&doc).with_work_budget(2).modification(0);
        assert_eq!(starved.level, ModificationLevel::Other);
        assert!(
            starved.notes.iter().any(|n| n.contains("work budget")),
            "{:?}",
            starved.notes
        );
        // The outcome of a revision is analysed once and shared.
        let revisions = Revisions::new(&doc);
        let first = revisions.modification(1);
        let left = revisions.work_left.get();
        assert_eq!(revisions.modification(1), first);
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
        assert_eq!(names("0 g\n/F1   12\tTf /F#232 9 Tf"), ["F1", "F#2"]);
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
    fn the_signed_names_read_every_annotation_and_bare_appearance_stream() {
        let mut store = Store::new_empty((1, 7));
        let decoded = Cell::new(0);
        // An appearance stream with /Resources of its own: its names are not read.
        let own = add_stream(
            &mut store,
            "<< /Resources << /Font << /F1 9 0 R >> >> >>",
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
            [b"F2".as_slice(), b"F3", b"F7", b"GS7", b"Im3"],
            "{:?}",
            names.names
        );
        assert!(names.complete);
        assert_eq!(decoded.get(), 33 + 7, "only the bare streams are decoded");
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
            ("[1 2]", None),
        ] {
            assert_eq!(forbidden_sig_field_key(&parse(field)), key, "{field}");
        }
    }

    #[test]
    fn explained_keeps_the_lowest_level() {
        let mut explained = Explained::default();
        explained.add(7, ModificationLevel::FormFilling);
        explained.add(7, ModificationLevel::LtaUpdates);
        explained.add(8, ModificationLevel::FormFilling);
        assert_eq!(explained.get(7), Some(ModificationLevel::LtaUpdates));
        assert_eq!(explained.get(8), Some(ModificationLevel::FormFilling));
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
        };
        let annots = Usage {
            from: Referrer::Object(3),
            path: vec![Step::Key(b"Annots".to_vec()), Step::Index(1)],
        };
        let parent = Usage {
            from: Referrer::Object(3),
            path: vec![Step::Key(b"Parent".to_vec())],
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

    #[test]
    fn xmp_packets_are_recognised() {
        let packet = "\u{feff}<?xpacket begin=\"\u{feff}\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
            <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"a > b\">\n\
            <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n\
            <!-- a comment with <tags> -->\n\
            <rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\
            <dc:format>application/pdf</dc:format><dc:x/><dc:y><![CDATA[<raw>]]></dc:y>\
            </rdf:Description>\n</rdf:RDF>\n</x:xmpmeta>\n                \n\
            <?xpacket end=\"w\"?>";
        assert!(looks_like_xmp(packet.as_bytes()));
        assert!(looks_like_xmp(
            b"<xmpmeta xmlns = 'adobe:ns:meta/'><a/></xmpmeta>"
        ));
        assert!(looks_like_xmp(
            b"<meta:xmpmeta xmlns:meta=\"adobe:ns:meta/\"/>"
        ));
        for bad in [
            &b""[..],
            b"not xml",
            b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">",
            b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><a></b></x:xmpmeta>",
            b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"></x:xmpmeta><second/>",
            b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"></x:xmpmeta> text",
            b"<x:other xmlns:x=\"adobe:ns:meta/\"/>",
            b"<x:xmpmeta xmlns:x=\"http://example.com/\"/>",
            b"<x:xmpmeta xmlns:y=\"adobe:ns:meta/\"/>",
            b"<!DOCTYPE x [<!ENTITY e \"boom\">]><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
            b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><!-- unterminated </x:xmpmeta>",
            b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" a=\"unterminated/>",
            b"\xFF\xFE<\x00x\x00",
        ] {
            assert!(!looks_like_xmp(bad), "{}", String::from_utf8_lossy(bad));
        }
        // Deep nesting stops at the limit instead of growing without bound.
        let deep = format!(
            "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">{}{}</x:xmpmeta>",
            "<a>".repeat(MAX_XML_DEPTH + 1),
            "</a>".repeat(MAX_XML_DEPTH + 1)
        );
        assert!(!looks_like_xmp(deep.as_bytes()));
    }
}

//! Parser differentials in the revisions after a signature (M4 QA round 1, manager ruling R-1;
//! QA round 3, ruling R-12, the canonical-input gate).
//!
//! Folioxide's parser keeps the **last** value of a duplicate dictionary key, as qpdf and poppler
//! do, while pyHanko and pypdf keep the **first** (ISO 32000-2 §7.3.7: "a dictionary shall not
//! contain multiple entries with the same key", and says nothing about what a reader does with
//! one). Likewise readers disagree on which copy of an object an object stream that holds it
//! twice gives, on which entry wins when one cross-reference section lists a number twice, and on
//! what a number such as `++2`, `+-260`, `4294967296` or a 40-digit integer is (Folioxide reads
//! its spelling, PDFium reads 0). A revision after the signed one that writes such bytes shows a
//! different document to different readers, so the classifier cannot know what a viewer shows:
//! the whitelist makes it `Other` (the comparison never depends on a reader's policy). The syntax
//! layer's behaviour is unchanged; these checks re-read the bytes with its public lexer
//! ([`canonical::scan_value`], one linear pass that also finds duplicate keys at any depth):
//!
//! - [`object_ambiguity`]: an uncompressed object, read again from its definition (`N G obj`),
//!   its dictionaries at every depth (stream dictionaries included);
//! - [`container_members`]: an object stream that holds a compressed object: its own dictionary
//!   must be canonical, its header must list `/N` pairs of distinct object numbers (unsigned
//!   integers) at strictly increasing offsets inside the data and nothing else, and each member
//!   must be a canonical value within its region (up to the next member), without an `obj`
//!   header;
//! - [`section_ambiguity`]: a later revision's trailer dictionary and cross-reference stream
//!   dictionary (a hybrid section has both);
//! - [`size_ambiguity`]: the `/Size` of those dictionaries, which must cover every object the
//!   file lists (PDFium drops the objects at or above the newest `/Size`; closing round,
//!   finding 13);
//! - [`layout_ambiguity`]: a later revision's bytes as a whole: every object body in them is one
//!   its cross-reference section lists there, and nothing else is in them but its section,
//!   `startxref`, white-space and comments (M4 QA round 4, finding 3: a reader that rebuilds the
//!   cross-reference data, as PDFium does when a section or trailer is damaged, reads the bodies
//!   a section does not list); its table, if any, is written canonically (manager ruling R-21);
//!   and nowhere in its bytes, stream data, strings and comments included, is there text a
//!   rebuilding reader takes for file structure (ruling R-17 (d): poppler reads `N G obj` at the
//!   start of any line, or of any 255-byte piece of a longer one);
//! - [`tail_ambiguity`]: the end of the file, where readers look for the last `startxref`
//!   (ruling R-17 (a), (b): poppler rebuilds the cross-reference data from the bytes when it is
//!   not in the last 1,024 bytes).
//!
//! The same reading applies to what verification and signing read **in the signed revision**
//! (M4 QA round 2, finding 8; round 3, ruling R-12): [`AmbiguousKeys::ambiguous_keys`] says
//! which entries of a signature dictionary, a signature field, a field lock or a DocMDP
//! declaration object read differently in different readers, so a `/ByteRange` or `/Reference`
//! written twice, or a `/P` spelled `4294967298`, is never read as if it were unambiguous; and
//! [`chain_ambiguity`] says when a trailer of the file's revision chain gives `/Prev` or
//! `/XRefStm` twice with different values, so readers follow different revisions (finding 9).
//!
//! Each check is one pass over the bytes it reads, bounded by the store's limits; the tokens it
//! reads are returned as work, which the classifier charges to its budget.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};

use folioxide_syntax::{
    Dict, Lexer, Limits, Object, ObjectId, ObjectLocation, ParseCtx, Revision, Store, Strictness,
    TokenKind, XrefEntry, XrefKind, parse_indirect_at, parse_indirect_header, parse_object,
};

use super::canonical;

/// What a check found, and the tokens it read (work for the classifier's budget).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Checked<T> {
    /// The verdict.
    pub(crate) verdict: T,
    /// The tokens read.
    pub(crate) work: u64,
}

/// The note for an object (`what`) whose bytes are not canonical (`defect`, from
/// [`canonical::scan_value`]).
fn ambiguity_note(what: &str, defect: &str) -> String {
    format!(
        "{what} reads differently in different readers ({defect}), so what a viewer shows \
         cannot be known (parser differential; manager rulings R-1 and R-12)"
    )
}

/// Why the uncompressed object `id` of `store` (the view of the revision whose entry is in
/// force) reads differently in different readers: its definition, at any depth, is not canonical
/// ([`canonical::scan_value`]: a duplicate key, §7.3.7, or a number, name or string spelling
/// readers read differently). `None` when it is canonical; a definition that cannot be located or
/// re-read is reported too (fail closed).
pub(super) fn object_ambiguity(store: &Store, id: ObjectId) -> Checked<Option<String>> {
    let unreadable = || Checked {
        verdict: Some(format!(
            "object {id}'s definition cannot be re-read to check that every reader reads it the \
             same way"
        )),
        work: 1,
    };
    let Some(ObjectLocation::InFile { start, .. }) = store.object_location(id) else {
        return unreadable();
    };
    let bytes = store.source();
    let Ok(start) = usize::try_from(start) else {
        return unreadable();
    };
    let ctx = ParseCtx::new(*store.limits(), Strictness::Lenient);
    let Ok((_, after)) = parse_indirect_header(bytes, start, &ctx) else {
        return unreadable();
    };
    match canonical::scan_value(bytes, after, store.limits()) {
        Ok(scan) => Checked {
            verdict: scan
                .defect
                .map(|defect| ambiguity_note(&format!("object {id}"), &defect)),
            work: scan.tokens,
        },
        Err(()) => unreadable(),
    }
}

/// Every object some reader may follow from the object `num` of `store`: the references of
/// its raw definition in every value of every key (the first value of a key written twice
/// included, which Folioxide's last-wins parser drops), as `entry` (in force in `store`'s
/// revision) gives it: an uncompressed object, or a member of an object stream. `None` when that
/// cannot be known: the definition cannot be located or re-read, a reference's numbers are not
/// canonical, or the container's header does not name `num` where `entry` points (manager
/// ruling R-12 (2); the role usage index, M4 QA round 3).
pub(super) fn raw_references(store: &Store, num: u32, entry: XrefEntry) -> Option<Vec<u32>> {
    let scan = match entry {
        XrefEntry::InFile { r#gen, .. } => {
            let id = ObjectId::new(num, r#gen);
            let Some(ObjectLocation::InFile { start, .. }) = store.object_location(id) else {
                return None;
            };
            let start = usize::try_from(start).ok()?;
            let bytes = store.source();
            let ctx = ParseCtx::new(*store.limits(), Strictness::Lenient);
            let (_, after) = parse_indirect_header(bytes, start, &ctx).ok()?;
            canonical::scan_value(bytes, after, store.limits()).ok()?
        }
        XrefEntry::InObjStm { stream, index } => {
            let (data, pairs) = container_layout(store, stream).ok()?;
            let at = usize::try_from(index).ok()?;
            let &(listed, start) = pairs.get(at)?;
            if listed != num {
                return None;
            }
            let end = pairs.get(at + 1).map_or(data.len(), |&(_, next)| next);
            let region = data.get(..end)?;
            canonical::scan_value(region, start, store.limits()).ok()?
        }
        _ => return None,
    };
    (!scan.doubtful_reference).then_some(scan.references)
}

/// The object numbers the header of the object stream `container` of `store` lists, in header
/// order, when the container is unambiguous; `Err(reason)` when readers may read it differently
/// (ISO 32000-2 §7.5.7): its own dictionary is not canonical, it is not an object stream that
/// decodes within the store's limits, its `/N` and `/First` are not non-negative integers, its
/// header does not hold exactly `/N` pairs of a positive object number and an offset (unsigned
/// integers, and nothing else), an object number is listed twice, the offsets are not strictly
/// increasing inside the data, or a member is not a canonical value within its region (up to the
/// next member) or has an `N G obj` header.
pub(super) fn container_members(
    store: &Store,
    container: u32,
) -> Checked<std::result::Result<Vec<u32>, String>> {
    let what = format!("object stream {container}");
    let limits = *store.limits();
    let own = object_ambiguity(store, ObjectId::new(container, 0));
    let mut work = own.work;
    if let Some(reason) = own.verdict {
        return Checked {
            verdict: Err(reason),
            work,
        };
    }
    let (data, pairs) = match container_layout(store, container) {
        Ok(layout) => layout,
        Err(reason) => {
            return Checked {
                verdict: Err(reason),
                work,
            };
        }
    };
    work = work.saturating_add(pairs.len() as u64);
    let mut members = Vec::with_capacity(pairs.len());
    for (index, &(num, start)) in pairs.iter().enumerate() {
        let end = pairs.get(index + 1).map_or(data.len(), |&(_, next)| next);
        let region = data.get(..end).unwrap_or_default();
        let ctx = ParseCtx::new(limits, Strictness::Lenient);
        let fail = |reason: String, work: u64| Checked {
            verdict: Err(reason),
            work,
        };
        if parse_indirect_header(region, start, &ctx).is_ok() {
            return fail(
                format!(
                    "{what}'s object {num} has an `obj` header, which readers treat differently"
                ),
                work,
            );
        }
        let Ok(scan) = canonical::scan_value(region, start, &limits) else {
            return fail(
                format!(
                    "{what}'s object {num} is not a value that ends within its region (up to the \
                     next member's offset)"
                ),
                work,
            );
        };
        work = work.saturating_add(scan.tokens);
        if let Some(defect) = scan.defect {
            return fail(
                ambiguity_note(&format!("object {num} in {what} (decoded bytes)"), &defect),
                work,
            );
        }
        // Only white-space and comments may follow the member in its region.
        let mut rest = Lexer::new(region, scan.end);
        if !matches!(rest.next_token(), Ok(None)) {
            return fail(
                format!("{what}'s object {num} is followed by more data before the next member"),
                work,
            );
        }
        members.push(num);
    }
    Checked {
        verdict: Ok(members),
        work,
    }
}

/// An object stream's decoded data and its header's `(object number, start)` pairs.
type Layout = (Vec<u8>, Vec<(u32, usize)>);

/// The decoded data of the object stream `container` of `store` and its header's `(object
/// number, start)` pairs, when the header is unambiguous (see [`container_members`]).
fn container_layout(store: &Store, container: u32) -> std::result::Result<Layout, String> {
    let what = format!("object stream {container}");
    let value = store
        .resolve(ObjectId::new(container, 0))
        .map_err(|_| format!("{what} cannot be read"))?;
    let Object::Stream(stream) = &*value else {
        return Err(format!("{what} is not a stream"));
    };
    let int = |key: &[u8]| -> Option<usize> {
        stream
            .dict
            .get(key)
            .and_then(|v| store.deref(v).ok())
            .and_then(|v| v.as_int())
            .and_then(|v| usize::try_from(v).ok())
    };
    let (Some(n), Some(first)) = (int(b"N"), int(b"First")) else {
        return Err(format!(
            "{what} has no non-negative integer /N and /First (ISO 32000-2 Table 16)"
        ));
    };
    let limits = *store.limits();
    let data = match store.stream_data_capped(stream, limits.max_objstm_decoded) {
        Ok(Some(bytes)) if bytes.is_fully_decoded() && !bytes.truncated => bytes.data,
        _ => return Err(format!("{what} cannot be decoded within the limits")),
    };
    let head = data
        .get(..first)
        .ok_or_else(|| format!("{what}'s /First {first} is past its {} bytes", data.len()))?;
    // The header: exactly N pairs of unsigned integers, then nothing but white-space and
    // comments (ruling R-12: `+7` or `007 4294967296` is no canonical header).
    let mut lexer = Lexer::new(head, 0);
    let mut pairs: Vec<(u32, usize)> = Vec::new();
    let mut numbers: BTreeSet<u32> = BTreeSet::new();
    let header_error =
        || format!("{what}'s header is not /N pairs of an object number and an offset (§7.5.7)");
    let integer = |lexer: &mut Lexer<'_>| -> Option<Option<i64>> {
        let token = match lexer.next_token() {
            Ok(None) => return Some(None),
            Ok(Some(token)) => token,
            Err(_) => return None,
        };
        let raw = head.get(token.start..token.end).unwrap_or_default();
        match token.kind {
            TokenKind::Integer(value)
                if canonical::unsigned_integer_defect(raw, &token.kind).is_none() =>
            {
                Some(Some(value))
            }
            _ => None,
        }
    };
    loop {
        let value = match integer(&mut lexer) {
            Some(Some(value)) => value,
            Some(None) => break,
            None => return Err(header_error()),
        };
        if pairs.len() >= n {
            return Err(header_error());
        }
        let Some(Some(offset)) = integer(&mut lexer) else {
            return Err(header_error());
        };
        let (Ok(num), Ok(offset)) = (u32::try_from(value), usize::try_from(offset)) else {
            return Err(header_error());
        };
        if num == 0 {
            return Err(header_error());
        }
        if !numbers.insert(num) {
            return Err(format!(
                "{what} holds object {num} twice; readers differ on which copy counts (parser \
                 differential)"
            ));
        }
        let start = first.checked_add(offset).ok_or_else(header_error)?;
        if start >= data.len() || pairs.last().is_some_and(|&(_, prev)| prev >= start) {
            return Err(format!(
                "{what}'s offsets are not strictly increasing inside its data (§7.5.7)"
            ));
        }
        pairs.push((num, start));
    }
    if pairs.len() != n {
        return Err(header_error());
    }
    Ok((data, pairs))
}

/// The top-level keys of the dictionary at `pos` of `bytes` whose entry reads differently in
/// different readers ([`canonical::Scan::ambiguous_keys`]: a key written twice, so first-wins
/// and last-wins readers take different values, or a value that is not canonical at any depth);
/// for a value that is not a dictionary, only [`canonical::WHOLE_VALUE`] when it is not
/// canonical anywhere. `Err` when the bytes do not parse, or when a top-level key is itself not
/// canonical (which entry it names cannot be known). One pass over the value.
fn ambiguous_keys_at(
    bytes: &[u8],
    pos: usize,
    limits: &Limits,
) -> std::result::Result<Checked<BTreeSet<Vec<u8>>>, ()> {
    let scan = canonical::scan_value(bytes, pos, limits)?;
    if scan.key_defect {
        return Err(());
    }
    Ok(Checked {
        verdict: scan.ambiguous_keys,
        work: scan.tokens,
    })
}

/// What [`AmbiguousKeys`] found in one object stream: for each member with an ambiguous entry
/// its keys ([`ambiguous_keys_at`]; `None` when it does not parse), or why the container's
/// header cannot be trusted.
type ContainerKeys = std::result::Result<HashMap<u32, Option<BTreeSet<Vec<u8>>>>, String>;

/// Which entries of objects of a store read differently in different readers (M4 QA round 2,
/// finding 8; round 3, ruling R-12): the raw-bytes canonical check, applied to the objects
/// verification and signing read as a verdict input in the signed revision (the signature
/// dictionary, its field, the field's lock, the DocMDP declaration). An object stream is decoded
/// and read once, however many of its members are asked about.
#[derive(Default)]
pub(crate) struct AmbiguousKeys {
    containers: RefCell<HashMap<u32, ContainerKeys>>,
}

impl AmbiguousKeys {
    /// The top-level keys of object `id` of `store` whose entry reads differently in different
    /// readers ([`ambiguous_keys_at`]; [`canonical::WHOLE_VALUE`] for a value that is not a
    /// dictionary), read from its definition (uncompressed, or its region of its object
    /// stream). `Err` when the definition cannot be re-read, or names a key that is itself not
    /// canonical, which callers treat as ambiguous (fail closed). An object without a source
    /// definition has none: a missing or free one, and one added in memory and not saved yet
    /// (Folioxide's writer writes canonical bytes).
    pub(crate) fn ambiguous_keys(
        &self,
        store: &Store,
        id: ObjectId,
    ) -> std::result::Result<BTreeSet<Vec<u8>>, String> {
        let unreadable = || format!("object {id}'s definition cannot be re-read");
        match store.object_location(id) {
            None => Ok(BTreeSet::new()),
            Some(ObjectLocation::InFile { start, .. }) => {
                let bytes = store.source();
                let start = usize::try_from(start).map_err(|_| unreadable())?;
                let ctx = ParseCtx::new(*store.limits(), Strictness::Lenient);
                let (_, after) =
                    parse_indirect_header(bytes, start, &ctx).map_err(|_| unreadable())?;
                ambiguous_keys_at(bytes, after, store.limits())
                    .map(|checked| checked.verdict)
                    .map_err(|()| unreadable())
            }
            Some(ObjectLocation::InObjStm { stream, .. }) => {
                let mut containers = self.containers.borrow_mut();
                let members = containers
                    .entry(stream)
                    .or_insert_with(|| container_keys(store, stream));
                match members {
                    Err(reason) => Err(reason.clone()),
                    Ok(members) => match members.get(&id.num) {
                        None => Ok(BTreeSet::new()),
                        Some(Some(keys)) => Ok(keys.clone()),
                        Some(None) => Err(unreadable()),
                    },
                }
            }
            // ObjectLocation is non-exhaustive: a location this check does not know is
            // ambiguous (fail closed).
            Some(_) => Err(format!("object {id}'s definition cannot be located")),
        }
    }
}

/// The members of the object stream `container` of `store` with an ambiguous entry
/// ([`ContainerKeys`]): one decode and one pass over its data.
fn container_keys(store: &Store, container: u32) -> ContainerKeys {
    let limits = *store.limits();
    let (data, pairs) = container_layout(store, container)?;
    let mut out = HashMap::new();
    for (index, &(num, start)) in pairs.iter().enumerate() {
        let end = pairs.get(index + 1).map_or(data.len(), |&(_, next)| next);
        let region = data.get(..end).unwrap_or_default();
        match ambiguous_keys_at(region, start, &limits) {
            Ok(keys) if keys.verdict.is_empty() => {}
            Ok(keys) => {
                out.insert(num, Some(keys.verdict));
            }
            Err(()) => {
                out.insert(num, None);
            }
        }
    }
    Ok(out)
}

/// Why the trailer or cross-reference stream dictionary of `revision` (of `store`, the whole
/// file's store) reads differently in different readers: it is not canonical (a duplicate key: a
/// trailer `/Root`, `/Info`, `/Prev` or `/Encrypt` written twice picks another document for a
/// first-wins reader, the Hide-and-Replace root switch with a duplicate-key disguise; or a number
/// spelling readers read differently, ruling R-12), or it cannot be re-read where the section
/// says it is. `None` when both are canonical.
pub(super) fn section_ambiguity(
    store: &Store,
    index: usize,
    revision: &Revision,
) -> Checked<Option<String>> {
    let bytes = store.source();
    let limits = *store.limits();
    let header = store.header_offset();
    let absolute = |offset: u64| usize::try_from(offset.checked_add(header)?).ok();
    let what = format!("revision {index}'s");
    let mut work = 0u64;
    let unreadable = |part: &str, work: u64| Checked {
        verdict: Some(format!(
            "{what} {part} cannot be re-read to check that every reader reads it the same way"
        )),
        work,
    };
    // The cross-reference stream: the section's own (stream sections) or its /XRefStm (hybrid).
    let stream_at = match revision.xref_kind {
        XrefKind::Stream => Some(revision.startxref),
        XrefKind::Hybrid => revision.xref_stm,
        _ => None,
    };
    if let Some(at) = stream_at {
        let Some(at) = absolute(at) else {
            return unreadable("cross-reference stream", work);
        };
        let ctx = ParseCtx::new(limits, Strictness::Lenient);
        let Ok((_, after)) = parse_indirect_header(bytes, at, &ctx) else {
            return unreadable("cross-reference stream", work);
        };
        match canonical::scan_value(bytes, after, &limits) {
            Ok(scan) => {
                work = work.saturating_add(scan.tokens);
                if let Some(defect) = scan.defect {
                    return Checked {
                        verdict: Some(ambiguity_note(
                            &format!("{what} cross-reference stream dictionary"),
                            &defect,
                        )),
                        work,
                    };
                }
            }
            Err(()) => return unreadable("cross-reference stream", work),
        }
    }
    // The trailer of a table (classic or hybrid section): after the `trailer` keyword that
    // follows the table, ending where the section ends.
    if matches!(revision.xref_kind, XrefKind::Table | XrefKind::Hybrid) {
        let (Some(start), Ok(end)) = (
            absolute(revision.startxref),
            usize::try_from(revision.section_end),
        ) else {
            return unreadable("trailer", work);
        };
        let mut lexer = Lexer::new(bytes, start);
        let after = loop {
            if lexer.position() >= end {
                return unreadable("trailer", work);
            }
            match lexer.next_token() {
                Ok(Some(token)) => match token.kind {
                    TokenKind::Keyword(b"trailer") => break token.end,
                    TokenKind::Keyword(b"xref" | b"f" | b"n") | TokenKind::Integer(_) => {}
                    _ => return unreadable("trailer", work),
                },
                _ => return unreadable("trailer", work),
            }
        };
        match canonical::scan_value(bytes, after, &limits) {
            Ok(scan) if scan.is_dict && scan.end == end => {
                work = work.saturating_add(scan.tokens);
                if let Some(defect) = scan.defect {
                    return Checked {
                        verdict: Some(ambiguity_note(&format!("{what} trailer"), &defect)),
                        work,
                    };
                }
            }
            _ => return unreadable("trailer", work),
        }
    }
    Checked {
        verdict: None,
        work,
    }
}

/// The `/Size` of a trailer or cross-reference stream dictionary when it is a direct
/// non-negative integer.
fn direct_size(dict: &Dict) -> Option<u64> {
    match dict.get(b"Size") {
        Some(Object::Int(size)) => u64::try_from(*size).ok(),
        _ => None,
    }
}

/// Why the `/Size` of revision `index` of `store` (the whole file's store) lets a reader drop
/// objects the file defines (M4 closing round, finding 13; manager ruling R-26). ISO 32000-2
/// §7.5.5 (Table 15) and §7.5.8.2 (Table 17) make `/Size` one greater than the highest object
/// number defined in the file; PDFium shrinks its object table to the newest trailer's `/Size`
/// and drops every object numbered at or above it, in every revision, while poppler, pyHanko and
/// Folioxide read past it. So a later revision's trailer (and, for a hybrid section, its
/// cross-reference stream dictionary too) must give `/Size` as a direct integer that is greater
/// than every object number its own section lists, and than every number an older section lists
/// (`highest`, free entries included; `None` when a section cannot be read), and not smaller
/// than the previous revision's `/Size` (when that one is a direct integer; a broken older
/// `/Size` is covered by `highest`). `None` when it is. Reads the one or two dictionaries only.
pub(super) fn size_ambiguity(store: &Store, index: usize, highest: Option<u32>) -> Option<String> {
    let revisions = store.revisions();
    let defect = |reason: String| {
        Some(format!(
            "revision {index}'s {reason}: PDFium keeps only the objects numbered below the \
             newest /Size and may show the page without what the others draw, while Folioxide \
             reads them (ISO 32000-2 §7.5.5 Table 15: /Size is one greater than the highest \
             object number in the file)"
        ))
    };
    let Some(revision) = revisions.get(index) else {
        return defect("trailer cannot be read".to_owned());
    };
    let Some(highest) = highest else {
        return defect("cross-reference sections cannot all be read".to_owned());
    };
    let mut sizes = vec![("trailer", direct_size(&revision.trailer))];
    if revision.xref_kind == XrefKind::Hybrid {
        let limits = *store.limits();
        let ctx = ParseCtx::new(limits, Strictness::Lenient);
        let bytes = store.source();
        let stream_dict = revision
            .xref_stm
            .and_then(|at| at.checked_add(store.header_offset()))
            .and_then(|at| usize::try_from(at).ok())
            .and_then(|at| parse_indirect_header(bytes, at, &ctx).ok())
            .and_then(|(_, after)| parse_object(bytes, after, &ctx).ok())
            .and_then(|(value, _)| value.as_dict().and_then(direct_size));
        sizes.push(("cross-reference stream dictionary", stream_dict));
    }
    let previous = index
        .checked_sub(1)
        .and_then(|before| revisions.get(before))
        .and_then(|before| direct_size(&before.trailer));
    for (part, size) in sizes {
        let Some(size) = size else {
            return defect(format!("{part} gives no /Size that is a direct integer"));
        };
        if size <= u64::from(highest) {
            return defect(format!(
                "{part} gives /Size {size}, but the file's sections list object {highest}"
            ));
        }
        if let Some(previous) = previous.filter(|&previous| size < previous) {
            return defect(format!(
                "{part} gives /Size {size}, smaller than the previous revision's {previous}"
            ));
        }
    }
    None
}

/// The bytes of a stream object's data that count as one token of work when
/// [`layout_ambiguity`] reads past them.
const LAYOUT_BYTES_PER_TOKEN: usize = 64;

/// The longest run of white-space accepted between the position a cross-reference entry gives
/// and the `N G obj` header there, and inside such a header, as the syntax layer accepts it
/// (`Store::check_incremental`; real files use none or one byte; manager ruling R-17 (c)).
const MAX_HEADER_SPACE: usize = 32;

/// The most digits of an object number in a canonical object header, and of each number of a
/// canonical table subsection header (manager ruling R-21: `4294967295` has ten).
const MAX_NUMBER_DIGITS: usize = 10;

/// The most digits of a generation number in a canonical object header (`65535`).
const MAX_GENERATION_DIGITS: usize = 5;

/// The length of a cross-reference table entry (ISO 32000-2 §7.5.4: "exactly 20 bytes long,
/// including the end-of-line marker").
const TABLE_ENTRY_LEN: usize = 20;

/// The positions of what an update legitimately writes that a reader rebuilding the
/// cross-reference data takes for file structure ([`layout_ambiguity`], [`rebuild_text`]): the
/// `obj` keywords of the object headers of its bodies (its cross-reference stream's included),
/// the `xref` and `trailer` keywords of its table, and its `startxref`.
#[derive(Default)]
struct Structure {
    headers: HashSet<usize>,
    xref: Option<usize>,
    trailer: Option<usize>,
    startxref: Option<usize>,
}

/// Why the bytes of `revision` (revision `index` of `store`, the whole file's store), from
/// `start` (the end of the revision before it) to `end` (its own end: past its `%%EOF`, or the
/// end of the file for the newest revision), may read differently in a reader that rebuilds the
/// cross-reference data instead of following it (M4 QA round 4, finding 3; round 5, manager
/// rulings R-17 and R-21). A conforming update (ISO 32000-2 §7.5.6) holds its objects, its
/// cross-reference section and `startxref`; the rules, read as a whitelist in one pass:
///
/// - every `N G obj` body in the bytes is at the position its section (`listed`, the section's
///   entries) gives `N G` (after at most [`MAX_HEADER_SPACE`] bytes of white-space), or is its
///   cross-reference stream; its header is written canonically (unsigned numbers without
///   leading zeros, white-space between them); each is read strictly (`parse_indirect_at` in
///   strict mode: its stream data where `/Length` says, `endobj`), and the reading continues
///   after it, so no stream data is read as tokens;
/// - every uncompressed entry of the section points at such a body, or is the entry in force
///   before the revision (`kept`: a re-listing of an older body);
/// - besides the bodies there is only the section (a table from `xref` to the end of its
///   trailer dictionary, written canonically: [`table_layout`]; or the cross-reference stream),
///   then `startxref` and its offset, and white-space and comments (`%%EOF`) anywhere;
/// - nowhere in the bytes, stream data, strings, comments and names included, is there an
///   object header, an `xref` or `startxref` keyword, or a `trailer` keyword before a
///   dictionary, other than those the update writes as its structure ([`rebuild_text`]).
///
/// A body no section lists is invisible to Folioxide and to readers that trust the section, but
/// a reader that rebuilds the data (PDFium, after a 19-byte entry or junk before `startxref`)
/// takes it for the object: QA's update painted the page black there, 477,210 pixels, while
/// Folioxide saw a fill. Text that only looks like a body, inside an appearance stream or a
/// string, did the same in poppler once the file's tail made it rebuild (469,411 pixels).
/// `None` when the bytes follow the rules.
pub(super) fn layout_ambiguity(
    store: &Store,
    index: usize,
    revision: &Revision,
    (start, end): (u64, u64),
    listed: Option<&[(u32, XrefEntry)]>,
    kept: &dyn Fn(u32, XrefEntry) -> bool,
) -> Checked<Option<String>> {
    let mut work = 0u64;
    let defect = |reason: String, work: u64| Checked {
        verdict: Some(format!(
            "revision {index}'s bytes hold {reason}: a reader that rebuilds the cross-reference \
             data from the bytes (PDFium does when a section or trailer is damaged, poppler when \
             it finds no `startxref` near the end of the file) reads another document than one \
             that follows the section (ISO 32000-2 §7.5.6; manager rulings R-17 and R-21)"
        )),
        work,
    };
    let bytes = store.source();
    let limits = *store.limits();
    let header = store.header_offset();
    let position = |offset: u64| usize::try_from(offset).ok();
    let (Some(start), Some(end), Some(listed)) = (position(start), position(end), listed) else {
        return defect("a section that cannot be read".to_owned(), work);
    };
    if start > end || end > bytes.len() {
        return defect("a section outside its own bytes".to_owned(), work);
    }
    let section_at = revision
        .startxref
        .checked_add(header)
        .and_then(position)
        .unwrap_or(usize::MAX);
    let section_end = position(revision.section_end).unwrap_or(usize::MAX);
    let table = matches!(revision.xref_kind, XrefKind::Table | XrefKind::Hybrid);
    let stream_at = match revision.xref_kind {
        XrefKind::Stream => Some(section_at),
        XrefKind::Hybrid => revision
            .xref_stm
            .and_then(|at| at.checked_add(header))
            .and_then(position),
        _ => None,
    };
    // The bodies the section lists inside the bytes, by the position of their `N G obj` (the
    // entry's position, after a little white-space, as readers locate it).
    let mut bodies: HashMap<usize, ObjectId> = HashMap::new();
    for &(num, entry) in listed {
        let XrefEntry::InFile { pos, r#gen } = entry else {
            continue;
        };
        match position(pos).filter(|&at| at >= start && at < end) {
            Some(at) => {
                let run = bytes
                    .get(at..end)
                    .unwrap_or_default()
                    .iter()
                    .take(MAX_HEADER_SPACE + 1)
                    .take_while(|&&b| folioxide_syntax::lexer::is_whitespace(b))
                    .count();
                if run > MAX_HEADER_SPACE {
                    return defect(
                        format!(
                            "a section that lists object {num} at byte {at}, more than \
                             {MAX_HEADER_SPACE} bytes of white-space before its body"
                        ),
                        work,
                    );
                }
                if bodies.insert(at + run, ObjectId::new(num, r#gen)).is_some() {
                    return defect(
                        format!("two objects that its section lists at one position ({at})"),
                        work,
                    );
                }
            }
            None if kept(num, entry) => {}
            None => {
                return defect(
                    format!(
                        "a section that lists object {num} at byte {pos}, outside the revision's \
                         own bytes, where no older section lists it"
                    ),
                    work,
                );
            }
        }
    }
    let ctx = ParseCtx::new(limits, Strictness::Strict);
    let length = |id: ObjectId| store.resolve(id).ok().and_then(|value| value.as_int());
    let mut structure = Structure::default();
    let mut found = 0usize;
    let mut section_seen = false;
    let mut done = false;
    let mut at = start;
    loop {
        let mut lexer = Lexer::new(bytes, at).with_max_string_len(limits.max_string_len);
        let token = match lexer.next_token() {
            Ok(Some(token)) if token.start < end => token,
            Ok(_) => break,
            Err(_) => return defect(format!("bytes at {at} that are no PDF tokens"), work),
        };
        work = work.saturating_add(1);
        if done {
            return defect(
                format!("bytes after its `startxref` (at {})", token.start),
                work,
            );
        }
        match token.kind {
            TokenKind::Integer(_) if !section_seen || !table => {
                let listed_here = bodies.get(&token.start).copied();
                let section_stream = stream_at == Some(token.start);
                if listed_here.is_none() && !section_stream {
                    return defect(
                        format!(
                            "an object body at byte {} that its cross-reference section does not \
                             list there",
                            token.start
                        ),
                        work,
                    );
                }
                let Some(keyword) = canonical_header(bytes, token.start) else {
                    return defect(
                        format!(
                            "an object header at byte {} that is not written canonically (two \
                             unsigned numbers without leading zeros, white-space, `obj`)",
                            token.start
                        ),
                        work,
                    );
                };
                let Ok(object) = parse_indirect_at(bytes, token.start, &ctx, &length) else {
                    return defect(
                        format!(
                            "an object at byte {} that does not read strictly (a stream whose \
                             /Length is not its data's, or no `endobj`)",
                            token.start
                        ),
                        work,
                    );
                };
                if let Some(id) = listed_here {
                    if object.id != id {
                        return defect(
                            format!(
                                "object {} at byte {}, where its section lists {id}",
                                object.id, token.start
                            ),
                            work,
                        );
                    }
                    found += 1;
                }
                if object.end > end {
                    return defect(
                        format!("an object at byte {} that runs past its end", token.start),
                        work,
                    );
                }
                if section_stream && revision.xref_kind == XrefKind::Stream {
                    section_seen = true;
                }
                structure.headers.insert(keyword);
                work = work.saturating_add(
                    (object.end.saturating_sub(token.start) / LAYOUT_BYTES_PER_TOKEN) as u64,
                );
                at = object.end;
            }
            TokenKind::Keyword(b"xref") if table && !section_seen && token.start == section_at => {
                if section_end <= token.start || section_end > end {
                    return defect("a cross-reference table outside its bytes".to_owned(), work);
                }
                match table_layout(bytes, token.start, section_end) {
                    Ok(trailer) => {
                        structure.xref = Some(token.start);
                        structure.trailer = Some(trailer);
                    }
                    Err(reason) => return defect(reason, work),
                }
                work = work.saturating_add(
                    (section_end.saturating_sub(token.start) / LAYOUT_BYTES_PER_TOKEN) as u64,
                );
                section_seen = true;
                at = section_end;
            }
            TokenKind::Keyword(b"startxref") if section_seen => {
                structure.startxref = Some(token.start);
                match lexer.next_token() {
                    Ok(Some(offset)) if matches!(offset.kind, TokenKind::Integer(_)) => {
                        at = offset.end;
                    }
                    _ => {
                        return defect("a `startxref` without an offset".to_owned(), work);
                    }
                }
                done = true;
            }
            _ => {
                return defect(
                    format!(
                        "bytes at {} that are neither an object its section lists, nor its \
                         cross-reference section, nor `startxref`",
                        token.start
                    ),
                    work,
                );
            }
        }
    }
    if !done {
        return defect(
            "no `startxref` after its cross-reference section".to_owned(),
            work,
        );
    }
    if found != bodies.len() {
        return defect(
            "a section that lists an object where its bytes hold none".to_owned(),
            work,
        );
    }
    // Ruling R-17 (d): one more pass over every byte, stream data and strings included, from
    // the start of the line the update begins in (poppler's lines run on from the bytes before).
    // The bytes it reads (linear in their length by construction: closing round, findings 2
    // and 6) are work.
    let line = line_start(bytes, start);
    let (found, steps) = rebuild_text(bytes, line, start, end, &structure);
    let read = steps.saturating_add(start.saturating_sub(line) as u64);
    work = work.saturating_add(read / LAYOUT_BYTES_PER_TOKEN as u64);
    if let Some((found_at, what)) = found {
        return defect(
            format!(
                "{what} at byte {found_at} inside stream data, a string, a comment or a name, \
                 which a reader rebuilding the cross-reference data takes for file structure \
                 (poppler 24.02 matches it at the start of a line, of a 255-byte piece of a \
                 longer one or after an `endobj`, PDFium and pdf.js an object header or \
                 `trailer <<` written as words anywhere, and the newest definition wins)"
            ),
            work,
        );
    }
    Checked {
        verdict: None,
        work,
    }
}

/// The position of the `obj` keyword of the object header at `at` of `bytes`, when the header
/// is written canonically: an object number of at most [`MAX_NUMBER_DIGITS`] digits and a
/// generation number of at most [`MAX_GENERATION_DIGITS`], each without a leading zero (but
/// `0` itself), white-space (no comment, at most [`MAX_HEADER_SPACE`] bytes) after each, then
/// `obj` ended by a delimiter or white-space. Readers that rebuild the cross-reference data, or
/// check a header where an entry points, read other spellings differently (PDFium reads a long
/// word as 0; poppler's scan needs a digit first).
fn canonical_header(bytes: &[u8], at: usize) -> Option<usize> {
    let digits = |from: usize, max: usize| -> Option<usize> {
        let run = bytes
            .get(from..)?
            .iter()
            .take(max + 1)
            .take_while(|b| b.is_ascii_digit())
            .count();
        let padded = run > 1 && bytes.get(from) == Some(&b'0');
        (run >= 1 && run <= max && !padded).then_some(from + run)
    };
    let space = |from: usize| -> Option<usize> {
        let run = bytes
            .get(from..)?
            .iter()
            .take(MAX_HEADER_SPACE + 1)
            .take_while(|&&b| folioxide_syntax::lexer::is_whitespace(b))
            .count();
        (1..=MAX_HEADER_SPACE).contains(&run).then_some(from + run)
    };
    let i = space(digits(at, MAX_NUMBER_DIGITS)?)?;
    let keyword = space(digits(i, MAX_GENERATION_DIGITS)?)?;
    let after = keyword.checked_add(3)?;
    (bytes.get(keyword..after) == Some(b"obj".as_slice())
        && !bytes
            .get(after)
            .is_some_and(|&b| folioxide_syntax::lexer::is_regular(b)))
    .then_some(keyword)
}

/// Why the cross-reference table at `at` of `bytes` (its section ending at `end`) is not written
/// canonically (ISO 32000-2 §7.5.4; manager ruling R-21; M4 QA round 5, findings 11 and 30):
/// `xref` and an end-of-line; then subsections, each a header of two unsigned integers of at most
/// [`MAX_NUMBER_DIGITS`] digits without a leading zero (but `0` itself), separated by spaces and
/// ended by an end-of-line, and its entries of exactly [`TABLE_ENTRY_LEN`] bytes (ten digits, a
/// space, five digits, a space, `n` or `f`, and a two-byte end-of-line: ` \r`, ` \n` or `\r\n`);
/// then, after white-space, the `trailer` keyword. PDFium reads a padded header number as 0 and
/// rebuilds the cross-reference data from the bytes after a 19-byte entry. `Ok` gives the position
/// of the `trailer` keyword. One pass over the table.
fn table_layout(bytes: &[u8], at: usize, end: usize) -> std::result::Result<usize, String> {
    let table = bytes.get(..end).unwrap_or_default();
    let bad = |what: &str, pos: usize| {
        format!("a cross-reference table whose {what} at byte {pos} is not written canonically")
    };
    let spaces = |i: usize| {
        i + table.get(i..).map_or(0, |rest| {
            rest.iter()
                .take_while(|&&b| matches!(b, b' ' | b'\t'))
                .count()
        })
    };
    let eol = |i: usize| match (table.get(i), table.get(i + 1)) {
        (Some(b'\r'), Some(b'\n')) => Some(i + 2),
        (Some(b'\r' | b'\n'), _) => Some(i + 1),
        _ => None,
    };
    let number = |i: usize| -> Option<(u64, usize)> {
        let run = table
            .get(i..)?
            .iter()
            .take(MAX_NUMBER_DIGITS + 1)
            .take_while(|b| b.is_ascii_digit())
            .count();
        let digits = table.get(i..i + run)?;
        if run == 0 || run > MAX_NUMBER_DIGITS || (run > 1 && digits.first() == Some(&b'0')) {
            return None;
        }
        let value = std::str::from_utf8(digits).ok()?.parse().ok()?;
        Some((value, i + run))
    };
    if table.get(at..at + 4) != Some(b"xref".as_slice()) {
        return Err(bad("`xref` keyword", at));
    }
    let mut i = eol(spaces(at + 4)).ok_or_else(|| bad("first line", at))?;
    loop {
        let blank = table.get(i..).map_or(0, |rest| {
            rest.iter()
                .take_while(|&&b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                .count()
        });
        if table
            .get(i + blank..)
            .is_some_and(|rest| rest.starts_with(b"trailer"))
        {
            return Ok(i + blank);
        }
        let header = i;
        let (_, after) = number(i).ok_or_else(|| bad("subsection header", header))?;
        let gap = spaces(after);
        if gap == after {
            return Err(bad("subsection header", header));
        }
        let (count, after) = number(gap).ok_or_else(|| bad("subsection header", header))?;
        i = eol(spaces(after)).ok_or_else(|| bad("subsection header", header))?;
        for _ in 0..count {
            let entry = table
                .get(i..i + TABLE_ENTRY_LEN)
                .ok_or_else(|| bad("entry", i))?;
            let (offset, rest) = entry.split_at(10);
            let (generation, rest) = rest.split_at(6);
            let canonical = offset.iter().all(u8::is_ascii_digit)
                && rest.first() == Some(&b' ')
                && generation.first() == Some(&b' ')
                && generation.iter().skip(1).all(u8::is_ascii_digit)
                && matches!(rest.get(1), Some(b'n' | b'f'))
                && matches!(rest.get(2..), Some(b" \r" | b" \n" | b"\r\n"));
            if !canonical {
                return Err(bad(
                    "entry (20 bytes: `nnnnnnnnnn ggggg n` and an end-of-line)",
                    i,
                ));
            }
            i += TABLE_ENTRY_LEN;
        }
    }
}

/// White-space as a reader rebuilding the cross-reference data skips it: PDF white-space
/// (§7.2.3) and the vertical tab, which C's `isspace` adds (poppler).
fn is_rebuild_space(b: u8) -> bool {
    folioxide_syntax::lexer::is_whitespace(b) || b == 0x0B
}

/// White-space within one of poppler's lines (`Lexer::isSpace`; end-of-lines end the line, and
/// a NUL ends poppler's C string).
fn is_line_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | 0x0C | 0x0B)
}

/// How many bytes poppler's `Stream::getLine` reads into one line at most (a `char buf[256]` and
/// its terminating NUL): a longer line is read, and scanned, as pieces of this length.
const POPPLER_LINE_PIECE: usize = 255;

/// The start of the line that holds `at` of `bytes`, as poppler's `Stream::getLine` splits the
/// bytes: after a line feed, or after a carriage return that no line feed follows (§7.2.3; a
/// CR LF pair ends one line). Linear in the distance.
fn line_start(bytes: &[u8], at: usize) -> usize {
    let mut j = at.min(bytes.len());
    while j > 0 {
        match bytes.get(j - 1) {
            Some(b'\n') => break,
            Some(b'\r') if bytes.get(j) != Some(&b'\n') => break,
            _ => j -= 1,
        }
    }
    j
}

/// Whether `b` ends a word for a regular expression's `\b` (pdf.js `XRef.indexObjects`): it is
/// no ASCII letter, digit or underscore. PDFium's word reader ends a word at fewer bytes
/// (white-space and delimiters only), so a word that ends here for neither is one for no reader.
fn is_word_boundary(b: u8) -> bool {
    !(b.is_ascii_alphanumeric() || b == b'_')
}

/// One [`rebuild_text`] pass over the bytes of an update. Every read of the bytes goes through
/// it and is counted in `steps` (work of the verification's budget), and the reads are linear in
/// the length of the bytes by construction (M4 closing round, findings 2 and 6: every 255-byte
/// piece of a long line of digits read the digit run to its end, so 16 MB of `1` took three
/// minutes):
///
/// - the words pass reads each byte once, and walks back from each `obj` only over the runs of
///   white-space and digits that end at it ([`RebuildScan::header_numbers_before`]); they hold
///   no `obj`, so no two walks read the same byte;
/// - the lines pass reads each line once to find its end, each 255-byte piece once from one
///   `endobj` to the next, and the white-space at the start of each segment up to its first other
///   byte (the next segment starts after an `endobj`, which is past it);
/// - an object-header candidate ([`RebuildScan::header_at`]) reads four runs: the number's
///   digits, white-space, the generation's digits, white-space. The number's run is read once:
///   a later segment that starts inside it is the same candidate (the same runs, the same `obj`
///   position), which came out clean, so it is skipped (`clean_number_end`). A white-space run
///   follows one digit run, and a generation's run follows one number's run, so every run is
///   read at most twice: once after a number, once after a generation;
/// - the white-space after a `trailer` follows no other `trailer`, so it is read at most once
///   per pass.
///
/// So `steps` stays below a small multiple of the length (`EXPECTED_MAX_STEPS_PER_BYTE` in the
/// tests, which feed it 16 MB runs of every byte class it treats specially).
struct RebuildScan<'a> {
    /// The bytes up to the end of the update.
    region: &'a [u8],
    /// What the update writes as its own structure.
    structure: &'a Structure,
    /// The bytes read so far.
    steps: u64,
    /// The end of the number of the last object-header candidate that came out clean.
    clean_number_end: usize,
}

impl RebuildScan<'_> {
    /// The end of the run of bytes from `from` that match `pred`, at `limit` at most.
    fn run_end_before(&mut self, from: usize, limit: usize, pred: fn(u8) -> bool) -> usize {
        let run = self
            .region
            .get(from..limit.min(self.region.len()))
            .map_or(0, |rest| rest.iter().take_while(|&&b| pred(b)).count());
        self.steps = self.steps.saturating_add(run as u64 + 1);
        from + run
    }

    /// The end of the run of bytes from `from` that match `pred`.
    fn run_end(&mut self, from: usize, pred: fn(u8) -> bool) -> usize {
        self.run_end_before(from, self.region.len(), pred)
    }

    /// The start of the run of bytes that end just before `at` and match `pred`.
    fn run_start(&mut self, at: usize, pred: fn(u8) -> bool) -> usize {
        let mut j = at.min(self.region.len());
        while j > 0 && self.region.get(j - 1).is_some_and(|&b| pred(b)) {
            j -= 1;
        }
        self.steps = self.steps.saturating_add((at - j) as u64 + 1);
        j
    }

    /// Whether the first byte after the white-space from `from` (end-of-lines included) opens a
    /// dictionary or a comment: what makes a `trailer` before it a trailer to a rebuilding reader.
    fn dictionary_follows(&mut self, from: usize) -> bool {
        let next = self.run_end(from, is_rebuild_space);
        self.region
            .get(next..)
            .is_some_and(|rest| rest.starts_with(b"<<") || rest.starts_with(b"%"))
    }

    /// Whether the bytes before the `obj` at `at` end in the two numbers of an object header
    /// written as words, as a reader rebuilding the cross-reference data from words matches
    /// them: digits, white-space, digits, optional white-space, the first digit at a word
    /// boundary (PDFium `CPDF_Parser::RebuildCrossRef` reads number words; pdf.js
    /// `XRef.indexObjects` matches `\b\d+\s+\d+\s+obj\b`). The runs walked back end at this `obj`
    /// and belong to no other.
    fn header_numbers_before(&mut self, at: usize) -> bool {
        let generation_end = self.run_start(at, is_rebuild_space);
        let generation = self.run_start(generation_end, |b| b.is_ascii_digit());
        if generation == generation_end {
            return false;
        }
        let number_end = self.run_start(generation, is_rebuild_space);
        let number = self.run_start(number_end, |b| b.is_ascii_digit());
        number_end < generation
            && number < number_end
            && (number == 0
                || self
                    .region
                    .get(number - 1)
                    .is_some_and(|&b| is_word_boundary(b)))
    }

    /// Whether the digit at `p` starts an object header to poppler other than the update's own:
    /// digits, white-space, digits, white-space, then `obj` as a prefix (`5 0 objective` is a
    /// header). The numbers may run on over line breaks and pieces (poppler reads the next line
    /// when a number ends one); Folioxide allows any white-space and any length, the stricter
    /// side. A candidate that starts inside the number of the last clean one reads the same runs
    /// and the same `obj` position, so it is clean too and is not read again.
    fn header_at(&mut self, p: usize) -> bool {
        if p < self.clean_number_end {
            return false;
        }
        let number_end = self.run_end(p, |b| b.is_ascii_digit());
        let generation = self.run_end(number_end, is_rebuild_space);
        let generation_end = self.run_end(generation, |b| b.is_ascii_digit());
        let keyword = self.run_end(generation_end, is_rebuild_space);
        let header = generation > number_end
            && generation_end > generation
            && keyword > generation_end
            && self
                .region
                .get(keyword..)
                .is_some_and(|rest| rest.starts_with(b"obj"))
            && !self.structure.headers.contains(&keyword);
        self.clean_number_end = number_end;
        header
    }

    /// The words pass from `start`: an object header written as words, or `trailer` written as a
    /// word before a dictionary or a comment, anywhere (PDFium, pdf.js).
    fn words(&mut self, start: usize) -> Option<(usize, &'static str)> {
        let region = self.region;
        let mut i = start;
        while let Some(&b) = region.get(i) {
            self.steps = self.steps.saturating_add(1);
            let rest = region.get(i..).unwrap_or_default();
            let after = |len: usize| region.get(i + len).is_none_or(|&b| is_word_boundary(b));
            let before = i == 0 || region.get(i - 1).is_some_and(|&b| is_word_boundary(b));
            match b {
                b'o' if rest.starts_with(b"obj") && after(3) => {
                    if !self.structure.headers.contains(&i) && self.header_numbers_before(i) {
                        return Some((i, "an object header (`N G obj`)"));
                    }
                }
                b't' if rest.starts_with(b"trailer")
                    && before
                    && after(7)
                    && self.structure.trailer != Some(i)
                    && self.dictionary_follows(i + b"trailer".len()) =>
                {
                    return Some((i, "a `trailer` keyword before a dictionary"));
                }
                _ => {}
            }
            i += 1;
        }
        None
    }

    /// What poppler 24.02 `XRef::constructXRef` takes for file structure in a segment of a line
    /// that starts at `seg` (a line start, a 255-byte piece, or the bytes after an `endobj`) and
    /// ends at `piece_end`, other than the update's own structure: after white-space, `trailer`
    /// before a dictionary (or a comment), or an object header ([`RebuildScan::header_at`]).
    /// Where a token of pdf.js's `XRef.indexObjects` starts (`keywords`: a line start or the
    /// bytes after an `endobj`, not a 255-byte piece), also `xref` and `startxref` (manager
    /// ruling R-17 (d)).
    fn segment(
        &mut self,
        seg: usize,
        piece_end: usize,
        keywords: bool,
    ) -> Option<(usize, &'static str)> {
        let region = self.region;
        let p = self.run_end_before(seg, piece_end, is_line_space);
        let text = region.get(p..piece_end).unwrap_or_default();
        if text.starts_with(b"trailer") {
            if self.structure.trailer != Some(p) && self.dictionary_follows(p + b"trailer".len()) {
                return Some((p, "a `trailer` keyword before a dictionary"));
            }
        } else if text.starts_with(b"startxref") {
            if keywords && self.structure.startxref != Some(p) {
                return Some((p, "a `startxref` keyword"));
            }
        } else if text.starts_with(b"xref") {
            if keywords && self.structure.xref != Some(p) {
                return Some((p, "an `xref` keyword"));
            }
        } else if text.first().is_some_and(u8::is_ascii_digit) && self.header_at(p) {
            return Some((p, "an object header (`N G obj`)"));
        }
        None
    }

    /// The lines pass from `line` (the start of the line that `start` is in): where poppler
    /// looks, that is every line, its 255-byte pieces, and what follows an `endobj` in a piece;
    /// segments before `start` are only counted, not checked.
    fn lines(&mut self, line: usize, start: usize) -> Option<(usize, &'static str)> {
        let region = self.region;
        let end = region.len();
        let mut line_at = line.min(end);
        while line_at < end {
            let line_end = self.run_end(line_at, |b| b != b'\n' && b != b'\r');
            let mut piece = line_at;
            loop {
                let piece_end = piece.saturating_add(POPPLER_LINE_PIECE).min(line_end);
                let mut seg = piece;
                // A line start, or the bytes after an `endobj`; not the start of a later piece.
                let mut keywords = piece == line_at;
                loop {
                    if seg >= start
                        && let Some(found) = self.segment(seg, piece_end, keywords)
                    {
                        return Some(found);
                    }
                    let text = region.get(seg..piece_end).unwrap_or_default();
                    let next = text.windows(6).position(|w| w == b"endobj");
                    self.steps = self
                        .steps
                        .saturating_add(next.map_or(text.len(), |k| k + 6) as u64 + 1);
                    match next {
                        Some(k) => {
                            seg += k + 6;
                            keywords = true;
                        }
                        None => break,
                    }
                }
                if piece_end >= line_end {
                    break;
                }
                piece = piece_end;
            }
            // The end-of-line: a CR LF pair is one.
            line_at = match (region.get(line_end), region.get(line_end + 1)) {
                (Some(b'\r'), Some(b'\n')) => line_end + 2,
                _ => line_end + 1,
            };
        }
        None
    }
}

/// Text in `bytes[start..end]` (an update's bytes) that a reader rebuilding the cross-reference
/// data from the bytes takes for file structure, other than the structure the update writes
/// (`structure`; manager ruling R-17 (d)), in stream data, strings, comments and names alike:
///
/// - where poppler 24.02 `XRef::constructXRef` looks ([`RebuildScan::segment`]): at the start of
///   every line (`Stream::getLine`: after a line feed, a carriage return or both), of every
///   255-byte piece of a longer line, and after every `endobj` in a piece, past white-space: an
///   object header or `trailer` before a dictionary; at a line start or after an `endobj` (where
///   pdf.js's tokens start) also `xref` or `startxref` (M4 final fix round 2, finding 3: only
///   there, so a fill value such as `see xref table` is no structure);
/// - anywhere, an object header written as words (`N G obj` with `obj` ended by no letter,
///   digit or underscore: [`RebuildScan::header_numbers_before`]) and `trailer` written as a
///   word before `<<` or a comment: PDFium's `CPDF_Parser::RebuildCrossRef` reads the file as
///   words, and pdf.js's `XRef.indexObjects` ends an object at either inside it.
///
/// `line` is the start of the line `start` is in ([`line_start`]): the pieces of that line are
/// counted from there. Its position and what it is, or `None`, and the bytes read (linear in
/// `end - line` by construction: [`RebuildScan`]).
fn rebuild_text(
    bytes: &[u8],
    line: usize,
    start: usize,
    end: usize,
    structure: &Structure,
) -> (Option<(usize, &'static str)>, u64) {
    let Some(region) = bytes.get(..end) else {
        return (None, 0);
    };
    let mut scan = RebuildScan {
        region,
        structure,
        steps: 0,
        clean_number_end: 0,
    };
    let found = scan.words(start).or_else(|| scan.lines(line, start));
    (found, scan.steps)
}

/// The most bytes that may follow the file's last `%%EOF`: one end-of-line, `\r\n` at most
/// (manager ruling R-17 (b)).
const MAX_TAIL_EOL: usize = 2;

/// How far from the end of the file poppler looks for the last `startxref` (`XRef::getStartXref`
/// reads the last 1,024 bytes; manager ruling R-17 (a)).
const STARTXREF_WINDOW: usize = 1024;

/// The last position of `needle` in `bytes`.
fn rfind(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    bytes
        .windows(needle.len())
        .rposition(|window| window == needle)
}

/// Why the end of the file (`store`'s source) lets a reader rebuild the cross-reference data from
/// the bytes instead of following the file's sections (manager ruling R-17 (a), (b); M4 QA round
/// 5, findings 10, 13 and 16–26: after 25 KB of trailing comments, or 40 KB of white-space, NUL or
/// end-of-lines, poppler 24.02 no longer finds `startxref`, rebuilds, and reads object text from
/// an update's stream data and strings; pyHanko cannot read such a file at all). The file must end
/// with its last `startxref` keyword, at most 1,024 bytes before the end
/// ([`STARTXREF_WINDOW`]), white-space, the offset of the newest revision's section, white-space
/// (spaces, tabs and end-of-lines) and `%%EOF`, then at most [`MAX_TAIL_EOL`] end-of-line bytes.
/// `None` when it does. One backward search.
pub(super) fn tail_ambiguity(store: &Store) -> Option<String> {
    let bytes = store.source();
    let len = bytes.len();
    let defect = |reason: String| {
        Some(format!(
            "the file ends with {reason}: a reader that does not find `startxref` in the last \
             1,024 bytes (poppler) rebuilds the cross-reference data from the bytes, and may read \
             another document than the sections describe (manager ruling R-17)"
        ))
    };
    let Some(eof) = rfind(bytes, b"%%EOF") else {
        return defect("no `%%EOF` marker".to_owned());
    };
    let tail = bytes.get(eof + 5..).unwrap_or_default();
    if tail.len() > MAX_TAIL_EOL || !tail.iter().all(|&b| b == b'\r' || b == b'\n') {
        return defect(format!(
            "{} bytes after its last `%%EOF`, which are not one end-of-line",
            tail.len()
        ));
    }
    let Some(keyword) = rfind(bytes, b"startxref") else {
        return defect("no `startxref`".to_owned());
    };
    if len - keyword > STARTXREF_WINDOW {
        return defect(format!(
            "its last `startxref` {} bytes before its end, more than {STARTXREF_WINDOW}",
            len - keyword
        ));
    }
    let blank = |from: usize, eol: bool| {
        from + bytes.get(from..).map_or(0, |rest| {
            rest.iter()
                .take_while(|&&b| matches!(b, b' ' | b'\t') || (eol && matches!(b, b'\r' | b'\n')))
                .count()
        })
    };
    let digits_at = blank(keyword + b"startxref".len(), true);
    let digits = bytes.get(digits_at..).map_or(0, |rest| {
        rest.iter()
            .take(21)
            .take_while(|b| b.is_ascii_digit())
            .count()
    });
    let value: Option<u64> = bytes
        .get(digits_at..digits_at + digits)
        .and_then(|d| std::str::from_utf8(d).ok())
        .and_then(|d| d.parse().ok());
    if digits_at == keyword + b"startxref".len() || value.is_none() {
        return defect("a last `startxref` without an offset after white-space".to_owned());
    }
    if blank(digits_at + digits, true) != eof {
        return defect(
            "bytes other than white-space between its last `startxref` offset and `%%EOF`"
                .to_owned(),
        );
    }
    let newest = store.revisions().last().map(|r| r.startxref);
    let header = store.header_offset();
    if newest.is_none_or(|at| value != Some(at) && value != at.checked_add(header)) {
        return defect(
            "a last `startxref` that does not point at the newest revision's section".to_owned(),
        );
    }
    None
}

/// The values of the top-level entries `keys` of the dictionary at `pos` of `bytes`, in the
/// order written (a key written twice appears twice). `Err` when the bytes there are not a
/// dictionary that parses.
fn entries_named(
    bytes: &[u8],
    pos: usize,
    limits: Limits,
    keys: &[&[u8]],
) -> std::result::Result<Vec<(Vec<u8>, Object)>, ()> {
    let mut lexer = Lexer::new(bytes, pos);
    let start = lexer.next_token().map_err(|_| ())?.ok_or(())?;
    if start.kind != TokenKind::DictStart {
        return Err(());
    }
    let mut out = Vec::new();
    let mut at = start.end;
    loop {
        let mut lexer = Lexer::new(bytes, at);
        let token = lexer.next_token().map_err(|_| ())?.ok_or(())?;
        let key = match token.kind {
            TokenKind::DictEnd => return Ok(out),
            TokenKind::Name(name) => name.into_owned(),
            _ => return Err(()),
        };
        let ctx = ParseCtx::new(limits, Strictness::Lenient);
        let (value, end) = parse_object(bytes, token.end, &ctx).map_err(|_| ())?;
        if end <= at {
            return Err(());
        }
        if keys.contains(&key.as_slice()) {
            out.push((key, value));
        }
        at = end;
    }
}

/// The chain keys of a trailer or cross-reference stream dictionary (§7.5.5, §7.5.8.2,
/// §7.5.8.4): the revisions a reader follows.
const CHAIN_KEYS: &[&[u8]] = &[b"Prev", b"XRefStm"];

/// Why the revision chain of `store` reads differently in different readers (M4 QA round 2,
/// finding 9): the trailer or cross-reference stream dictionary of one of its revisions gives
/// `/Prev` or `/XRefStm` twice with different values. A first-wins reader (pyHanko, pypdf) then
/// follows other revisions than a last-wins one (Folioxide, qpdf, poppler), and may see a signed
/// revision, with its signatures, that this reading skips. `None` when each is given at most
/// once, or twice with the same value. One pass over each revision's dictionaries. Verification
/// refuses such a file (`Error::Syntax(Xref)`), and so does the signing side (QA round 3,
/// finding 13: a certification the signer's own reading skips must not be signed over).
pub(crate) fn chain_ambiguity(store: &Store) -> Option<String> {
    let bytes = store.source();
    let limits = *store.limits();
    let header = store.header_offset();
    let absolute = |offset: u64| usize::try_from(offset.checked_add(header)?).ok();
    for (index, revision) in store.revisions().iter().enumerate() {
        let mut dicts: Vec<usize> = Vec::new();
        let stream_at = match revision.xref_kind {
            XrefKind::Stream => Some(revision.startxref),
            XrefKind::Hybrid => revision.xref_stm,
            _ => None,
        };
        if let Some(at) = stream_at.and_then(absolute) {
            let ctx = ParseCtx::new(limits, Strictness::Lenient);
            if let Ok((_, after)) = parse_indirect_header(bytes, at, &ctx) {
                dicts.push(after);
            }
        }
        if matches!(revision.xref_kind, XrefKind::Table | XrefKind::Hybrid)
            && let (Some(start), Ok(end)) = (
                absolute(revision.startxref),
                usize::try_from(revision.section_end),
            )
        {
            let mut lexer = Lexer::new(bytes, start);
            while lexer.position() < end {
                match lexer.next_token() {
                    Ok(Some(token)) => match token.kind {
                        TokenKind::Keyword(b"trailer") => {
                            dicts.push(token.end);
                            break;
                        }
                        TokenKind::Keyword(b"xref" | b"f" | b"n") | TokenKind::Integer(_) => {}
                        _ => break,
                    },
                    _ => break,
                }
            }
        }
        for pos in dicts {
            let Ok(entries) = entries_named(bytes, pos, limits, CHAIN_KEYS) else {
                continue; // section_ambiguity reports what cannot be re-read after a signature
            };
            for key in CHAIN_KEYS {
                let mut values = entries.iter().filter(|(k, _)| k.as_slice() == *key);
                if let Some((_, first)) = values.next()
                    && values.any(|(_, value)| value != first)
                {
                    return Some(format!(
                        "revision {index}'s trailer gives /{} twice with different values, so \
                         readers that keep the first value (pyHanko, pypdf) follow other \
                         revisions than those that keep the last (Folioxide, qpdf, poppler), and \
                         may see signatures this reading does not (parser differential, ISO \
                         32000-2 §7.3.7, §7.5.5)",
                        String::from_utf8_lossy(key)
                    ));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use folioxide_syntax::OpenOptions;

    fn open(bytes: &[u8]) -> Store {
        Store::open_bytes(bytes.to_vec(), &OpenOptions::default()).unwrap()
    }

    #[test]
    fn duplicate_keys_are_found_at_any_depth() {
        let limits = Limits::DEFAULT;
        for (text, found) in [
            ("<< /A 1 /B 2 >>", false),
            ("<< /A 1 /A 2 >>", true),
            ("<< /A << /B [<< /C 1 /C 1 >>] >> >>", true),
            ("[<< /A 1 >> << /A 2 >>]", false),
            ("<< /Length 4 /Length 5 >>\nstream\n", true),
        ] {
            let got = canonical::scan_value(text.as_bytes(), 0, &limits).unwrap();
            assert_eq!(got.defect.is_some(), found, "{text}");
        }
        assert!(canonical::scan_value(b"<< /A", 0, &limits).is_err());
        // The top-level keys an ambiguous entry belongs to.
        let keys = ambiguous_keys_at(b"<< /A 1 /B [1 ++2] /A 2 >>", 0, &limits).unwrap();
        assert_eq!(keys.verdict, [b"A".to_vec(), b"B".to_vec()].into());
        assert!(ambiguous_keys_at(b"<< /Byte#00Range 1 >>", 0, &limits).is_err());
    }

    /// A file whose object 4 is the object stream `data` (header `header`, objects after it).
    fn with_container(header: &str, objects: &str, n: usize) -> Vec<u8> {
        let first = header.len();
        let data = format!("{header}{objects}");
        let mut b = folioxide_testkit::PdfBuilder::new();
        b.header("1.7");
        b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>");
        b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        b.obj(
            3,
            0,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] >>",
        );
        b.stream_obj(
            4,
            0,
            format!("<< /Type /ObjStm /N {n} /First {first} >>"),
            data.as_bytes(),
            None,
        );
        b.xref_table(folioxide_testkit::XrefOpts::default());
        let trailer = format!("/Size {} /Root 1 0 R", b.size());
        b.trailer(trailer).startxref(None).eof();
        b.build()
    }

    /// A one-page file (objects 1–3), with an update of `bodies` (object number, value text,
    /// whether its section lists it) and `before_startxref` between its trailer and
    /// `startxref`, then `after`.
    fn updated(bodies: &[(u32, &str, bool)], before_startxref: &str, after: &str) -> Vec<u8> {
        let mut b = folioxide_testkit::PdfBuilder::new();
        b.header("1.7");
        b.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>");
        b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        b.obj(
            3,
            0,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] >>",
        );
        b.xref_table(folioxide_testkit::XrefOpts::default());
        let trailer = format!("/Size {} /Root 1 0 R", b.size());
        b.trailer(trailer).startxref(None).eof();
        let mut out = b.build();
        let prev = folioxide_testkit::fixtures::sign_attacks::last_startxref(&out).unwrap();
        let mut listed = Vec::new();
        for &(num, body, list) in bodies {
            if list {
                listed.push((num, out.len()));
            }
            out.extend(format!("{num} 0 obj\n{body}\nendobj\n").into_bytes());
        }
        let xref = out.len();
        out.extend_from_slice(b"xref\n");
        for (num, at) in listed {
            out.extend(format!("{num} 1\n{at:010} 00000 n \n").into_bytes());
        }
        out.extend(
            format!(
                "trailer\n<< /Size 10 /Root 1 0 R /Prev {prev} >>\n{before_startxref}\
                 startxref\n{xref}\n%%EOF\n{after}"
            )
            .into_bytes(),
        );
        out
    }

    /// [`layout_ambiguity`] of the newest revision of `bytes`.
    fn layout(bytes: &[u8]) -> Option<String> {
        let store = open(bytes);
        let revisions = store.revisions();
        let index = revisions.len() - 1;
        let entries = store.revision_entries(index).ok();
        let range = (revisions[index - 1].eof_end, bytes.len() as u64);
        layout_ambiguity(
            &store,
            index,
            &revisions[index],
            range,
            entries.as_deref(),
            &|_, _| false,
        )
        .verdict
    }

    #[test]
    fn an_update_holds_only_what_its_section_lists() {
        // M4 QA round 4, finding 3.
        let stream = "<< /Length 3 >>\nstream\nabc\nendstream";
        let ok = updated(&[(4, "<< /A 1 >>", true), (5, stream, true)], "", "");
        assert_eq!(layout(&ok), None);
        // Comments and white-space are fine anywhere, trailing ones too.
        let commented = updated(&[(4, "<< /A 1 >>", true)], "% a comment\n", "\n\0 ");
        assert_eq!(layout(&commented), None);
        // Stream data is never read as tokens; ordinary content is fine.
        let content = "<< /Length 22 >>\nstream\n1 0 0 1 72 720 cm (x)\nendstream";
        assert_eq!(layout(&updated(&[(5, content, true)], "", "")), None);
        for (bytes, needle) in [
            (
                updated(
                    &[(4, "<< /A 1 >>", true), (3, "<< /Type /Page >>", false)],
                    "",
                    "",
                ),
                "does not list there",
            ),
            (
                updated(&[(4, "<< /A 1 >>", true)], "junk 1 0 R\n", ""),
                "neither an object",
            ),
            (
                updated(&[(4, "<< /A 1 >>", true)], "", "3 0 obj << >> endobj\n"),
                "after its `startxref`",
            ),
            (
                updated(
                    &[(5, "<< /Length 9 >>\nstream\nabc\nendstream", true)],
                    "",
                    "",
                ),
                "does not read strictly",
            ),
        ] {
            let found = layout(&bytes).unwrap_or_default();
            assert!(found.contains(needle), "{needle}: {found}");
        }
    }

    #[test]
    fn an_update_holds_no_text_a_rebuilding_reader_takes_for_structure() {
        // Manager ruling R-17 (d), M4 QA round 5 (findings 10, 13, 16-26): object text at a line
        // start inside an appearance stream or a string, or anywhere a 255-byte piece of a long
        // line may start, is read by poppler once it rebuilds the cross-reference data.
        let stream =
            |data: &str| format!("<< /Length {} >>\nstream\n{data}\nendstream", data.len());
        for (body, needle) in [
            (
                stream("q\n5 0 obj << /Type /Page >> endobj\nQ"),
                "object header",
            ),
            (stream("q 5\t0\r\nobj Q"), "object header"),
            // The second 255-byte piece of a line starts with the header (poppler's getLine).
            (
                stream(&format!("{}5 0 objective", "x".repeat(255))),
                "object header",
            ),
            // After an `endobj`, poppler scans the rest of the line piece again.
            (stream("(endobj 5 0 objective)"), "object header"),
            // At a line start, poppler matches `obj` as a prefix.
            ("<< /V (Item\n4 7 objective) >>".to_owned(), "object header"),
            ("<< /V (Item\r4 7 objective) >>".to_owned(), "object header"),
            ("<< /V (a\r\n  xref b) >>".to_owned(), "`xref`"),
            ("<< /V (a\nstartxref) >>".to_owned(), "`startxref`"),
            (stream("q endobj xref Q"), "`xref`"),
            (
                stream(&format!("{}trailer <<>>", "x".repeat(255))),
                "`trailer`",
            ),
            // Words anywhere: PDFium and pdf.js.
            (stream("q 1 0 0 1 0 0 cm 12 0 obj Q"), "object header"),
            ("<< /V (see 12 0 obj) >>".to_owned(), "object header"),
            (stream("Q trailer <</Root 9 0 R>>"), "`trailer`"),
            (stream("q\0\0\0 3 0 obj Q"), "object header"),
            (stream("xref\n0 1\n"), "`xref`"),
            (stream("trailer\n<< /Root 9 0 R >>"), "`trailer`"),
            (stream("trailer % hidden\n"), "`trailer`"),
            (stream("startxref\n0"), "`startxref`"),
            (
                "<< /Contents (a\n7 0 obj\n<< >>\nendobj) >>".to_owned(),
                "object header",
            ),
            ("<< /T (x) % 7 0 obj\n>>".to_owned(), "object header"),
        ] {
            let found = layout(&updated(&[(5, &body, true)], "", "")).unwrap_or_default();
            assert!(found.contains(needle), "{body:?}: {found}");
        }
        // Words, numbers and keywords that are no structure stay allowed, and so do encoded
        // spellings (readers match the raw bytes).
        // M4 final fix round 2, finding 3 (variants F1-k-honest-fill-value-*): words inside a
        // line are no structure to poppler, and no word structure to PDFium or pdf.js.
        for body in [
            stream("BT (the trailer park; 12 objects) Tj ET"),
            stream("BT (endobj 0 R) Tj ET 1 0 0 1 0 0 cm"),
            "<< /Contents (5 0 R) /T (Trailer) >>".to_owned(),
            "<< /Contents <78726566> /N /x#72ef >>".to_owned(),
            "<< /V (see xref table) >>".to_owned(),
            "<< /V (startxref) >>".to_owned(),
            "<< /V (Room 12 3 object) >>".to_owned(),
            "<< /V (Item 4 7 objective) >>".to_owned(),
            "<< /V (trailer <b>) >>".to_owned(),
            "<< /V (trailer park) >>".to_owned(),
            "<< /V (999 EUR) >>".to_owned(),
            "<< /V (a\\n4 0 obj\\n) >>".to_owned(),
            "<< /V (a\ntrailer <b>) >>".to_owned(),
            "<< /V (a\nxtrailer << >>) >>".to_owned(),
            stream(&format!("{}5 0 objective", "x".repeat(254))),
            stream(&format!("{}5 0 obj", "x".repeat(300))),
            // pdf.js tokens start at lines, not at poppler's 255-byte pieces.
            stream(&format!("{}xref", "x".repeat(255))),
            stream(&format!("{}startxref", "x".repeat(255))),
        ] {
            assert_eq!(
                layout(&updated(&[(5, &body, true)], "", "")),
                None,
                "{body:?}"
            );
        }
    }

    /// The most bytes [`rebuild_text`] may read per byte of its region (closing round, findings
    /// 2 and 6, manager ruling R-27): a constant, as the scan is linear by construction.
    const EXPECTED_MAX_STEPS_PER_BYTE: u64 = 16;

    /// `unit` repeated to `len` bytes.
    fn run_of(unit: &[u8], len: usize) -> Vec<u8> {
        unit.iter().copied().cycle().take(len).collect()
    }

    /// The scan of `region` as a whole update: whether it finds structure, within the step budget.
    fn scan_within_budget(name: &str, region: &[u8]) -> bool {
        let (found, steps) = rebuild_text(region, 0, 0, region.len(), &Structure::default());
        let budget = EXPECTED_MAX_STEPS_PER_BYTE * region.len() as u64;
        assert!(
            steps <= budget,
            "{name}: {steps} steps for {} bytes (budget {budget})",
            region.len()
        );
        found.is_some()
    }

    #[test]
    fn the_rebuild_scan_is_linear_on_16_mb_runs() {
        // Closing round, findings 2 and 6 (ruling R-27): every 255-byte piece of a long line of
        // digits read the digit run to its end, so 16 MB of `1` in an appearance stream took
        // three minutes. A 16 MB run of each byte class the scan treats specially: digits,
        // white-space, `endobj`, `trailer` and comments.
        const MB16: usize = 16 << 20;
        for (name, unit) in [
            ("digits", b"1".as_slice()),
            ("white-space", b" \t\x0c\x0b\0".as_slice()),
            ("endobj", b"endobj".as_slice()),
            ("trailer", b"trailer ".as_slice()),
            ("comments", b"%".as_slice()),
        ] {
            assert!(!scan_within_budget(name, &run_of(unit, MB16)), "{name}");
        }
    }

    #[test]
    fn the_rebuild_scan_is_linear_on_long_runs_of_every_shape() {
        // Neighbours of the 16 MB runs (closing round, findings 2 and 6), at 1 MB each: a
        // quadratic scan would read about 2,000 times the budget.
        const MB: usize = 1 << 20;
        let half = |unit: &[u8], other: &[u8]| {
            let mut v = run_of(unit, MB / 2);
            v.extend(run_of(other, MB / 2));
            v
        };
        let mut cases: Vec<(&str, Vec<u8>, bool)> = vec![
            ("zeros", run_of(b"0", MB), false),
            ("digit space pairs", run_of(b"1 ", MB), false),
            ("digit lines", run_of(b"1\n", MB), false),
            ("digit CR lines", run_of(b"1\r", MB), false),
            ("spaces", run_of(b" ", MB), false),
            ("line feeds", run_of(b"\n", MB), false),
            ("CR LF pairs", run_of(b"\r\n", MB), false),
            ("endobj spaces", run_of(b"endobj ", MB), false),
            ("endobj lines", run_of(b"endobj\n", MB), false),
            ("endobj digits", run_of(b"endobj1", MB), false),
            ("trailers", run_of(b"trailer", MB), false),
            ("trailer lines", run_of(b"trailer\n", MB), false),
            ("comment lines", run_of(b"% c\n", MB), false),
            ("digits then spaces", half(b"1", b" "), false),
            ("digits then line feeds", half(b"1", b"\n"), false),
            ("spaces then digits", half(b" ", b"1"), false),
            ("endobj then digits", half(b"endobj", b"1"), false),
            ("trailer then spaces", half(b"trailer", b" "), false),
        ];
        // Long numbers: a number, white-space and a generation each spanning many pieces.
        let mut long = run_of(b"1", MB / 4);
        long.extend(run_of(b" ", MB / 4));
        long.extend(run_of(b"1", MB / 4));
        long.extend(run_of(b"\n", MB / 4));
        cases.push(("long number, long generation", long.clone(), false));
        // ... and the same followed by `obj`: an object header, found at the end.
        long.extend(b"obj");
        cases.push(("long header", long, true));
        let mut late = run_of(b"1", MB);
        late.extend(b" 0 obj");
        cases.push(("digits then a header", late, true));
        let mut late = run_of(b" ", MB);
        late.extend(b"trailer <<>>");
        cases.push(("spaces then a trailer", late, true));
        for (name, region, found) in cases {
            assert_eq!(scan_within_budget(name, &region), found, "{name}");
        }
    }

    #[test]
    fn a_candidate_inside_a_clean_number_is_skipped_but_not_a_later_one() {
        // The memo of the linear scan (closing round, findings 2 and 6) skips only the pieces
        // that start inside the number of a candidate that came out clean: a header whose number
        // starts after it is still found, at a piece start and at a line start.
        let mut region = run_of(b"1", 600);
        region.extend(b" ");
        // The fifth piece of the long line starts with `7 0 obj` (poppler's getLine).
        let piece = 4 * POPPLER_LINE_PIECE;
        region.extend(run_of(b"x", piece - region.len()));
        region.extend(b"7 0 objective");
        let (found, _) = rebuild_text(&region, 0, 0, region.len(), &Structure::default());
        assert_eq!(found, Some((piece, "an object header (`N G obj`)")));
        let mut region = run_of(b"1", 600);
        region.extend(b"\n12 0 objection");
        let (found, _) = rebuild_text(&region, 0, 0, region.len(), &Structure::default());
        assert_eq!(found, Some((601, "an object header (`N G obj`)")));
    }

    /// `bytes` with the last `from` replaced by `to`, and the final `startxref` value moved by
    /// the change in length when the change comes before the section it names.
    fn splice_last(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        let at = bytes.windows(from.len()).rposition(|w| w == from).unwrap();
        let mut out = bytes[..at].to_vec();
        out.extend_from_slice(to);
        out.extend_from_slice(&bytes[at + from.len()..]);
        let key = b"startxref\n";
        let sx = out.windows(key.len()).rposition(|w| w == key).unwrap() + key.len();
        let end = sx + out[sx..].iter().position(|&b| b == b'\n').unwrap();
        let value: usize = std::str::from_utf8(&out[sx..end]).unwrap().parse().unwrap();
        if at < value {
            let moved = (value + to.len() - from.len()).to_string();
            out.splice(sx..end, moved.into_bytes());
        }
        out
    }

    /// [`size_ambiguity`] of the newest revision of `bytes`, with the highest number its
    /// sections list.
    fn size(bytes: &[u8]) -> Option<String> {
        let store = open(bytes);
        let newest = store.revisions().len() - 1;
        let highest = (0..=newest)
            .flat_map(|index| store.revision_entries(index).unwrap())
            .map(|(num, _)| num)
            .max();
        size_ambiguity(&store, newest, highest)
    }

    #[test]
    fn a_later_size_covers_every_object_the_file_lists() {
        // Closing round, finding 13 (manager ruling R-26): the base revision lists objects 0-3
        // (/Size 4), the update object 4 (/Size 10).
        let ok = updated(&[(4, "<< /A 1 >>", true)], "", "");
        assert_eq!(size(&ok), None);
        assert_eq!(
            size(&splice_last(&ok, b"/Size 10 ", b"/Size 5 ")),
            None,
            "exactly one more than the highest number"
        );
        for (to, needle) in [
            ("/Size 3 ", "/Size 3, but the file's sections list object 4"),
            ("/Size 4 ", "/Size 4, but the file's sections list object 4"),
            ("/Size 0 ", "/Size 0,"),
            ("/Size 9 0 R ", "no /Size that is a direct integer"),
            ("/Size 5.0 ", "no /Size that is a direct integer"),
            ("/Size -5 ", "no /Size that is a direct integer"),
            ("", "no /Size that is a direct integer"),
        ] {
            let found = size(&splice_last(&ok, b"/Size 10 ", to.as_bytes())).unwrap_or_default();
            assert!(found.contains(needle), "{to:?}: {found}");
            assert!(found.contains("PDFium keeps only"), "{found}");
        }
        // Not smaller than the previous revision's /Size: the base says 8 (the same length, so
        // no offset moves), and the update's 6 covers its object 4 but drops 5 to 7 for PDFium.
        let base = format!("/Size {} /Root 1 0 R", 4);
        let at = ok
            .windows(base.len())
            .position(|w| w == base.as_bytes())
            .unwrap();
        let mut grown = ok.clone();
        grown[at..at + base.len()].copy_from_slice(b"/Size 8 /Root 1 0 R");
        assert_eq!(size(&splice_last(&grown, b"/Size 10 ", b"/Size 8 ")), None);
        let found = size(&splice_last(&grown, b"/Size 10 ", b"/Size 6 ")).unwrap_or_default();
        assert!(
            found.contains("/Size 6, smaller than the previous revision's 8"),
            "{found}"
        );
        // A section that cannot be read gives no highest number: fail closed.
        let store = open(&ok);
        assert!(
            size_ambiguity(&store, 1, None)
                .unwrap_or_default()
                .contains("cannot all be read")
        );
    }

    #[test]
    fn an_update_writes_its_headers_and_table_canonically() {
        // Manager ruling R-21 (M4 QA round 5, findings 11 and 30) and R-17 (c).
        let ok = updated(&[(4, "<< /A 1 >>", true)], "", "");
        assert_eq!(layout(&ok), None);
        for (from, to, needle) in [
            ("\n4 1\n", "\n000004 1\n", "subsection header"),
            ("\n4 1\n", "\n4 01\n", "subsection header"),
            ("\n4 1\n", "\n00000000004 1\n", "subsection header"),
            // Not even a subsection: the section cannot be read as written.
            ("\n4 1\n", "\n41\n", "revision 1's bytes"),
            (" 00000 n \n", " 00000 n\n", "entry"),
            (" 00000 n \n", " 0000 n  \n", "entry"),
            (" 00000 n \n", " 00000 x \n", "revision 1's bytes"),
        ] {
            let found = layout(&splice_last(&ok, from.as_bytes(), to.as_bytes()));
            let found = found.unwrap_or_default();
            assert!(found.contains(needle), "{to:?}: {found}");
        }
        // The same table with CR LF entries and spaces before the end-of-lines is canonical.
        let spaced = splice_last(&ok, b"\n4 1\n", b"\n4 1 \r\n");
        let crlf = splice_last(&spaced, b" 00000 n \n", b" 00000 n\r\n");
        assert_eq!(layout(&crlf), None);
        // A body header spelled with a leading zero, or a comment, is not canonical.
        for header in ["04 0 obj", "4 00 obj", "4 0 % c\nobj"] {
            let respelled = splice_last(&ok, b"4 0 obj", header.as_bytes());
            let found = layout(&respelled).unwrap_or_default();
            assert!(
                found.contains("not written canonically"),
                "{header}: {found}"
            );
        }
        // An entry that points at more than a little white-space before its body.
        let padded = splice_last(
            &ok,
            b"4 0 obj",
            format!("{}4 0 obj", " ".repeat(40)).as_bytes(),
        );
        let found = layout(&padded).unwrap_or_default();
        assert!(found.contains("white-space before its body"), "{found}");
    }

    /// The one-update file of [`updated`], its `%%EOF` preceded by `before_eof` and followed by
    /// `tail` instead of one end-of-line.
    fn with_tail(before_eof: &str, tail: &str) -> Vec<u8> {
        let ok = updated(&[(4, "<< /A 1 >>", true)], "", "");
        let eof = ok.windows(5).rposition(|w| w == b"%%EOF").unwrap();
        let mut out = ok[..eof].to_vec();
        out.extend_from_slice(before_eof.as_bytes());
        out.extend_from_slice(b"%%EOF");
        out.extend_from_slice(tail.as_bytes());
        out
    }

    #[test]
    fn the_file_ends_where_every_reader_finds_its_startxref() {
        // Manager ruling R-17 (a), (b): M4 QA round 5, findings 10, 13, 16-26.
        for tail in ["", "\n", "\r\n", "\r", "\n\n"] {
            assert_eq!(
                tail_ambiguity(&open(&with_tail("", tail))),
                None,
                "{tail:?}"
            );
        }
        let long = format!("\n{}", "\n".repeat(40_000));
        let spaces = " ".repeat(1100);
        for (before, tail, needle) in [
            ("", "\n\n\n", "after its last"),
            ("", "\n ", "after its last"),
            ("", "\n\0", "after its last"),
            ("", "\n% a comment\n", "after its last"),
            ("", long.as_str(), "after its last"),
            (spaces.as_str(), "\n", "more than 1024"),
            ("% comment\n", "\n", "between its last"),
        ] {
            let found = tail_ambiguity(&open(&with_tail(before, tail))).unwrap_or_default();
            assert!(found.contains(needle), "{before:?} {tail:?}: {found}");
        }
        // A last `startxref` that names an older section, or none: the store repairs (R-17
        // (c), which verification reports as `StructureRepaired`), or the tail is refused.
        let ok = with_tail("", "\n");
        let key = b"startxref\n";
        let sx = ok.windows(key.len()).rposition(|w| w == key).unwrap() + key.len();
        let end = sx + ok[sx..].iter().position(|&b| b == b'\n').unwrap();
        for value in ["190", "12", "999999"] {
            let mut wrong = ok.clone();
            wrong.splice(sx..end, value.bytes());
            let store = open(&wrong);
            assert!(
                tail_ambiguity(&store).is_some() || store.structure_repaired(),
                "{value}"
            );
        }
    }

    #[test]
    fn object_stream_headers_are_checked() {
        let ok = open(&with_container("7 0 8 4 ", "<<>><< /A 1 >>", 2));
        let checked = container_members(&ok, 4);
        assert_eq!(checked.verdict, Ok(vec![7, 8]));
        assert!(checked.work > 0);
        for (header, objects, n, needle) in [
            ("7 0 7 4 ", "<<>><< /A 1 >>", 2, "twice"),
            ("7 4 8 0 ", "<<>><< /A 1 >>", 2, "increasing"),
            ("7 0 8 4 ", "<<>><< /A 1 >>", 1, "pairs"),
            ("7 0 8 4 ", "<<>><< /A 1 >>", 3, "pairs"),
            ("7 0 8 99 ", "<<>><< /A 1 >>", 2, "increasing"),
            ("7 0 (x) ", "<<>>", 1, "pairs"),
            ("7 0 8 4 ", "<<>><< /A 1 /A 2 >>", 2, "duplicate key"),
            ("7 0 8 6 ", "<<>> 1<< /A 1 >>", 2, "more data"),
            ("7 0 ", "7 0 obj << >> endobj", 1, "`obj` header"),
            // Ruling R-12: header numbers are unsigned integers, members canonical values.
            ("+7 0 8 4 ", "<<>><< /A 1 >>", 2, "pairs"),
            ("7 0 8 +4 ", "<<>><< /A 1 >>", 2, "pairs"),
            ("7 0 8 4 ", "<<>><< /A ++1 >>", 2, "several signs"),
            ("7 0 8 4 ", "<<>><< /A 4294967296 >>", 2, "outside"),
        ] {
            let store = open(&with_container(header, objects, n));
            let err = container_members(&store, 4).verdict.unwrap_err();
            assert!(err.contains(needle), "{header} {objects}: {err}");
        }
        // Not a container at all.
        assert!(
            container_members(&ok, 3)
                .verdict
                .unwrap_err()
                .contains("not a stream")
        );
    }
}

//! Opening a document and using all of it, for robustness tests and fuzz targets.
//!
//! [`exercise`] opens bytes with [`Store::open`], then resolves every in-use object twice,
//! follows every reference found inside them, reads and decodes every stream, and counts the
//! pages ([`page_count`]). Along the way it checks the guarantees that the store documents (see
//! [`Report::violations`]). It never panics itself, so a panic during [`exercise`] always comes
//! from the code under test.
//!
//! The `no_panic_on_mutated_input` test of `folioxide-syntax` runs it on every mutation of the
//! committed fixtures, and the `fuzz_parse_document` fuzz target on every fuzzer input.
//!
//! ```
//! use folioxide_syntax::OpenOptions;
//! use folioxide_testkit::exercise::exercise;
//! use folioxide_testkit::fixtures::syntax;
//!
//! let report = exercise(&syntax::minimal(), &OpenOptions::default());
//! assert_eq!(report.open_error, None);
//! assert_eq!((report.objects, report.non_null, report.streams), (5, 5, 1));
//! assert_eq!(report.pages, Some(1));
//! assert!(report.violations.is_empty(), "{:?}", report.violations);
//!
//! let report = exercise(b"not a PDF", &OpenOptions::default());
//! assert!(report.open_error.is_some());
//! assert!(report.violations.is_empty());
//! ```

use std::collections::BTreeSet;
use std::sync::Arc;

use folioxide_syntax::{
    ErrorCode, LimitKind, Object, ObjectId, OpenOptions, Store, StreamData, Strictness, keys,
};

/// The most distinct references [`exercise`] follows with [`Store::deref`] per document, so a
/// file with millions of references still finishes quickly.
pub const MAX_REFERENCES: usize = 100_000;

/// The most messages kept in [`Report::violations`]; one is enough to fail a test, and a file
/// with millions of objects must not produce millions of messages.
pub const MAX_VIOLATIONS: usize = 100;

/// The error codes that [`Store::open`] documents for lenient mode.
const LENIENT_OPEN_ERRORS: [ErrorCode; 4] = [
    ErrorCode::Xref,
    ErrorCode::PasswordRequired,
    ErrorCode::Unsupported,
    ErrorCode::LimitExceeded,
];

/// The error codes that [`Store::stream_data`] documents for lenient mode (decoding errors,
/// limits, and the lenient errors of [`Store::deref`]).
const LENIENT_DECODE_ERRORS: [ErrorCode; 3] = [
    ErrorCode::LimitExceeded,
    ErrorCode::Filter,
    ErrorCode::Unsupported,
];

/// What [`exercise`] did, and every documented guarantee it saw broken.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The error code when [`Store::open`] failed; nothing else was done then.
    pub open_error: Option<ErrorCode>,
    /// The in-use objects of the merged cross-reference data ([`Store::object_ids`]).
    pub objects: usize,
    /// How many of [`Report::objects`] resolved to something other than `null`.
    pub non_null: usize,
    /// How many of [`Report::objects`] failed to resolve (strict mode, or limits).
    pub resolve_errors: usize,
    /// How many of the resolved objects are streams.
    pub streams: usize,
    /// How many of those streams failed to decode.
    pub decode_errors: usize,
    /// The total size of the decoded stream data.
    pub decoded_bytes: u64,
    /// [`Store::total_decoded`] after everything was read: every byte the store decoded,
    /// including cross-reference and object streams, each source stream counted once.
    pub total_decoded: u64,
    /// The distinct references followed with [`Store::deref`] (at most [`MAX_REFERENCES`]).
    pub references: usize,
    /// The page count from [`page_count`]; `None` when the catalog has no page tree.
    pub pages: Option<u32>,
    /// The number of diagnostics the store recorded.
    pub diagnostics: usize,
    /// Every broken guarantee (at most [`MAX_VIOLATIONS`]), as a message; empty when the store
    /// kept all of them:
    /// - lenient [`Store::open`] fails only with `Xref`, `PasswordRequired`, `Unsupported` or
    ///   `LimitExceeded`; after a successful open the trailer has a `/Root` that resolves to a
    ///   dictionary;
    /// - [`Store::object_ids`] is strictly increasing (by number, then generation: a
    ///   reconstructed file can define several generations of one number), never contains
    ///   object 0, stays below
    ///   [`folioxide_syntax::Limits::max_objects`], and holds at most
    ///   `min(max_objects, max(4096, file length))` objects (a file cannot claim more objects
    ///   than it has bytes);
    /// - resolving an object twice gives the same cached result (the same [`Arc`], or the same
    ///   error code); lenient [`Store::resolve`] and [`Store::deref`] fail only with
    ///   `LimitExceeded`;
    /// - a resolved stream's raw data is readable, and a [`StreamData::Source`] range is its
    ///   exact slice of the source;
    /// - lenient [`Store::stream_data`] fails only with `LimitExceeded`, `Filter` or
    ///   `Unsupported`, and decoded data never exceeds
    ///   [`folioxide_syntax::Limits::max_decoded_stream`];
    /// - [`Store::total_decoded`] stays within [`folioxide_syntax::Limits::max_total_decoded`],
    ///   and [`Store::diagnostics`] within [`folioxide_syntax::Limits::max_diagnostics`].
    pub violations: Vec<String>,
}

/// Opens `bytes` with `options` and uses everything in the document; see the [module
/// documentation](self).
pub fn exercise(bytes: &[u8], options: &OpenOptions) -> Report {
    match Store::open_bytes(bytes.to_vec(), options) {
        Ok(store) => exercise_store(&store),
        Err(err) => {
            let mut report = Report {
                open_error: Some(err.code()),
                ..Report::default()
            };
            if options.strictness == Strictness::Lenient
                && !LENIENT_OPEN_ERRORS.contains(&err.code())
            {
                report.violations.push(format!(
                    "lenient open failed with undocumented code {:?}: {err}",
                    err.code()
                ));
            }
            report
        }
    }
}

/// Uses everything in an opened `store`; see the [module documentation](self).
pub fn exercise_store(store: &Store) -> Report {
    let mut run = Run {
        store,
        lenient: store.options().strictness == Strictness::Lenient,
        report: Report::default(),
        seen_refs: BTreeSet::new(),
    };
    run.check_root();
    let ids = store.object_ids();
    run.check_ids(&ids);
    run.report.objects = ids.len();
    for (key, value) in store.trailer().iter() {
        let key = String::from_utf8_lossy(key.as_bytes()).into_owned();
        run.follow_references(value, &format!("trailer /{key}"));
    }
    for &id in &ids {
        run.object(id);
    }
    run.report.pages = page_count(store);
    run.check_totals();
    run.report
}

/// The state of one [`exercise_store`] run.
struct Run<'s> {
    store: &'s Store,
    lenient: bool,
    report: Report,
    seen_refs: BTreeSet<ObjectId>,
}

impl Run<'_> {
    fn violation(&mut self, message: String) {
        if self.report.violations.len() < MAX_VIOLATIONS {
            self.report.violations.push(message);
        }
    }

    fn check_root(&mut self) {
        let Some(root) = self.store.root_id() else {
            self.violation("the trailer has no /Root after a successful open".to_owned());
            return;
        };
        match self.store.resolve(root) {
            Ok(catalog) if catalog.as_dict().is_some() => {}
            Ok(other) => self.violation(format!(
                "the catalog {root} is a {}, not a dictionary, after a successful open",
                other.type_name()
            )),
            Err(err) => self.violation(format!(
                "the catalog {root} fails to resolve after a successful open: {err}"
            )),
        }
    }

    fn check_ids(&mut self, ids: &[ObjectId]) {
        let max_objects = self.store.limits().max_objects;
        if ids
            .windows(2)
            .any(|w| matches!(w, [a, b] if (a.num, a.r#gen) >= (b.num, b.r#gen)))
        {
            self.violation("object_ids() is not strictly increasing".to_owned());
        }
        if ids.iter().any(|id| id.num == 0) {
            self.violation("object_ids() contains object 0".to_owned());
        }
        if let Some(id) = ids.iter().find(|id| id.num >= max_objects) {
            self.violation(format!(
                "object_ids() contains {id}, beyond max_objects {max_objects}"
            ));
        }
        // With the default `budget_scale` this is `object_cap(max_objects, len)`.
        let cap = self
            .store
            .limits()
            .budget(LimitKind::ObjectCap, self.store.source().len() as u64);
        if ids.len() as u64 > cap {
            self.violation(format!(
                "object_ids() holds {} objects, over the {cap} a file of {} bytes may keep",
                ids.len(),
                self.store.source().len()
            ));
        }
        if let Some(last) = ids.last()
            && last.num > self.store.max_object_number()
        {
            self.violation(format!(
                "object_ids() contains {last}, beyond max_object_number() {}",
                self.store.max_object_number()
            ));
        }
    }

    /// Resolves `id` twice, then follows its references and decodes it if it is a stream.
    fn object(&mut self, id: ObjectId) {
        let first = self.store.resolve(id);
        let second = self.store.resolve(id);
        let object = match (first, second) {
            (Ok(a), Ok(b)) => {
                if !Arc::ptr_eq(&a, &b) {
                    self.violation(format!("resolving {id} twice gave two different objects"));
                }
                a
            }
            (Err(a), Err(b)) => {
                self.report.resolve_errors += 1;
                if a.code() != b.code() {
                    self.violation(format!(
                        "resolving {id} twice failed with {:?}, then {:?}",
                        a.code(),
                        b.code()
                    ));
                }
                if self.lenient && a.code() != ErrorCode::LimitExceeded {
                    self.violation(format!("lenient resolve({id}) failed: {a}"));
                }
                return;
            }
            (a, b) => {
                self.violation(format!(
                    "resolving {id} twice gave {:?}, then {:?}",
                    a.map(|o| o.type_name()),
                    b.map(|o| o.type_name())
                ));
                return;
            }
        };
        if !object.is_null() {
            self.report.non_null += 1;
        }
        self.follow_references(&object, &id.to_string());
        if let Object::Stream(stream) = &*object {
            self.report.streams += 1;
            self.stream(id, stream);
        }
    }

    fn stream(&mut self, id: ObjectId, stream: &folioxide_syntax::Stream) {
        match self.store.raw_stream_data(stream) {
            Ok(raw) => {
                if let StreamData::Source(range) = &stream.data {
                    let slice = usize::try_from(range.start)
                        .ok()
                        .zip(usize::try_from(range.end).ok())
                        .and_then(|(start, end)| self.store.source().get(start..end));
                    if slice != Some(&*raw) {
                        self.violation(format!(
                            "the raw data of stream {id} is not source[{}..{}]",
                            range.start, range.end
                        ));
                    }
                }
            }
            Err(err) => self.violation(format!("raw_stream_data of stream {id} failed: {err}")),
        }
        let max = self.store.limits().max_decoded_stream;
        match self.store.stream_data(stream) {
            Ok(decoded) => {
                if decoded.data.len() > max {
                    self.violation(format!(
                        "stream {id} decoded to {} bytes, over max_decoded_stream {max}",
                        decoded.data.len()
                    ));
                }
                self.report.decoded_bytes = self
                    .report
                    .decoded_bytes
                    .saturating_add(decoded.data.len() as u64);
            }
            Err(err) => {
                self.report.decode_errors += 1;
                if self.lenient && !LENIENT_DECODE_ERRORS.contains(&err.code()) {
                    self.violation(format!("lenient stream_data of {id} failed: {err}"));
                }
            }
        }
    }

    /// Follows every reference inside `object` with [`Store::deref`] (each distinct reference
    /// once, at most [`MAX_REFERENCES`] per document). `context` names the containing object.
    fn follow_references(&mut self, object: &Object, context: &str) {
        let mut stack: Vec<&Object> = vec![object];
        while let Some(item) = stack.pop() {
            match item {
                Object::Ref(id) => {
                    if self.seen_refs.len() >= MAX_REFERENCES || !self.seen_refs.insert(*id) {
                        continue;
                    }
                    self.report.references += 1;
                    if let Err(err) = self.store.deref(item)
                        && self.lenient
                        && err.code() != ErrorCode::LimitExceeded
                    {
                        self.violation(format!("lenient deref({id}) in {context} failed: {err}"));
                    }
                }
                Object::Array(items) => stack.extend(items.iter()),
                Object::Dict(dict) => stack.extend(dict.values()),
                Object::Stream(stream) => stack.extend(stream.dict.values()),
                _ => {}
            }
        }
    }

    fn check_totals(&mut self) {
        let limits = *self.store.limits();
        if self.store.total_decoded() > limits.max_total_decoded {
            self.violation(format!(
                "total_decoded() {} is over max_total_decoded {}",
                self.store.total_decoded(),
                limits.max_total_decoded
            ));
        }
        let diagnostics = self.store.diagnostics().len();
        if diagnostics > limits.max_diagnostics as usize {
            self.violation(format!(
                "{diagnostics} diagnostics stored, over max_diagnostics {}",
                limits.max_diagnostics
            ));
        }
        self.report.diagnostics = diagnostics;
        self.report.total_decoded = self.store.total_decoded();
    }
}

/// The most in-use objects the store keeps for a file of `len` bytes, as
/// [`folioxide_syntax::Limits::max_objects`] documents it: `min(max_objects, max(4096, len))`
/// (with the default [`folioxide_syntax::Limits::budget_scale`]; see
/// [`folioxide_syntax::Limits::budget`]).
pub fn object_cap(max_objects: u32, len: usize) -> u64 {
    (len as u64).max(4096).min(u64::from(max_objects))
}

/// Counts the pages of the document in `store` by walking its page tree from the catalog's
/// `/Pages` entry (ISO 32000-2 §7.7.3.2): a node with a `/Kids` array is an intermediate node,
/// and a node without one counts as a page when its `/Type` is `/Page`.
///
/// The walk is bounded like the M2 page tree will be: a node is visited at most once (so a
/// cycle cannot loop), nodes deeper than [`folioxide_syntax::Limits::max_page_tree_depth`] are
/// skipped, and nodes that fail to resolve are ignored. `/Count` is not trusted.
///
/// Returns `None` when the catalog has no `/Pages` dictionary.
///
/// ```
/// use folioxide_syntax::{OpenOptions, Store};
/// use folioxide_testkit::{exercise::page_count, fixtures::syntax};
///
/// let store = Store::open_bytes(syntax::many_pages(250), &OpenOptions::default())?;
/// assert_eq!(page_count(&store), Some(250));
/// # Ok::<(), folioxide_syntax::Error>(())
/// ```
pub fn page_count(store: &Store) -> Option<u32> {
    let catalog = store.resolve(store.root_id()?).ok()?;
    let pages = catalog.as_dict()?.get(keys::PAGES)?;
    let root = store.deref(pages).ok()?;
    root.as_dict()?;
    let max_depth = store.limits().max_page_tree_depth;
    let mut visited: BTreeSet<ObjectId> = BTreeSet::new();
    if let Object::Ref(id) = pages {
        visited.insert(*id);
    }
    let mut count: u32 = 0;
    let mut stack: Vec<(Arc<Object>, u16)> = vec![(root.into_arc(), 0)];
    while let Some((node, depth)) = stack.pop() {
        let Some(dict) = node.as_dict() else {
            continue;
        };
        match dict.get_array(keys::KIDS) {
            Some(kids) => {
                if depth >= max_depth {
                    continue;
                }
                // Reversed, so pages are visited in document order (not needed for counting,
                // but it keeps the walk easy to follow in a debugger).
                for kid in kids.iter().rev() {
                    if let Object::Ref(id) = kid
                        && !visited.insert(*id)
                    {
                        continue;
                    }
                    if let Ok(resolved) = store.deref(kid) {
                        stack.push((resolved.into_arc(), depth + 1));
                    }
                }
            }
            None if dict.is_type(keys::PAGE) => count = count.saturating_add(1),
            None => {}
        }
    }
    Some(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::syntax;
    use folioxide_syntax::Limits;

    #[test]
    fn every_fixture_is_exercised_without_violations() {
        for info in syntax::infos() {
            for strictness in [Strictness::Lenient, Strictness::Strict] {
                let options = OpenOptions::default().with_strictness(strictness);
                let report = exercise(&(info.generate)(), &options);
                assert!(
                    report.violations.is_empty(),
                    "{} {strictness:?}: {:?}",
                    info.name,
                    report.violations
                );
                if report.open_error.is_none() {
                    assert_eq!(report.pages, Some(info.pages), "{}", info.name);
                }
            }
        }
    }

    #[test]
    fn report_counts() {
        let report = exercise(&syntax::multi_revision(), &OpenOptions::default());
        assert_eq!(report.open_error, None);
        assert_eq!((report.objects, report.non_null), (7, 7));
        assert_eq!(report.streams, 2);
        assert_eq!(report.pages, Some(2));
        assert_eq!(report.resolve_errors + report.decode_errors, 0);
        assert!(report.references >= 7, "{report:?}");
        assert!(report.decoded_bytes > 0);
        // Two content streams, decoded once each and charged once each.
        assert_eq!(report.total_decoded, report.decoded_bytes);
        assert_eq!(report.diagnostics, 0);

        let strict = OpenOptions::default().with_strictness(Strictness::Strict);
        let report = exercise(&syntax::stream_length_wrong(), &strict);
        assert_eq!(report.resolve_errors, 4);
        assert!(report.violations.is_empty(), "{:?}", report.violations);

        let report = exercise(&syntax::encrypted(), &OpenOptions::default());
        assert_eq!(report.open_error, Some(ErrorCode::PasswordRequired));
        assert_eq!(report.objects, 0);
    }

    #[test]
    fn limits_are_reported_not_violated() {
        let tiny = OpenOptions::default().with_limits(
            Limits::default()
                .with_max_decoded_stream(16)
                .with_max_diagnostics(1),
        );
        let report = exercise(&syntax::stream_length_wrong(), &tiny);
        assert!(report.violations.is_empty(), "{:?}", report.violations);
        assert_eq!(report.diagnostics, 1);
        assert!(report.decode_errors > 0);
    }

    #[test]
    fn object_cap_is_the_documented_one() {
        assert_eq!(object_cap(10_000_000, 100), 4096);
        assert_eq!(object_cap(10_000_000, 1 << 20), 1 << 20);
        assert_eq!(object_cap(1000, 1 << 20), 1000);
        // A file that claims 900,000 objects keeps no more than it has bytes (at least 4096).
        let pdf = crate::fixtures::hostile::huge_index(900_000, 900_000);
        let report = exercise(&pdf, &OpenOptions::default());
        assert!(report.violations.is_empty(), "{:?}", report.violations);
        assert_eq!(report.objects as u64, object_cap(10_000_000, pdf.len()));
    }

    #[test]
    fn page_count_survives_cycles_and_depth() {
        // A /Pages node that lists itself, and a kid that is a page tree node again.
        let mut b = crate::PdfBuilder::new();
        b.header("1.4")
            .obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>")
            .obj(
                2,
                0,
                "<< /Type /Pages /Kids [2 0 R 3 0 R 4 0 R 3 0 R] /Count 3 >>",
            )
            .obj(3, 0, "<< /Type /Page /Parent 2 0 R >>")
            .obj(4, 0, "<< /Type /Pages /Kids [5 0 R] /Count 1 >>")
            .obj(5, 0, "<< /Type /Pages /Kids [4 0 R] /Count 1 >>");
        b.xref_table(crate::XrefOpts::default());
        b.trailer(format!("/Size {} /Root 1 0 R", b.size()))
            .startxref(None)
            .eof();
        let store = Store::open_bytes(b.build(), &OpenOptions::default()).unwrap();
        assert_eq!(page_count(&store), Some(1));
        let shallow =
            OpenOptions::default().with_limits(Limits::default().with_max_page_tree_depth(0));
        let store = Store::open_bytes(syntax::minimal(), &shallow).unwrap();
        assert_eq!(page_count(&store), Some(0));
    }

    #[test]
    fn no_page_tree() {
        let mut b = crate::PdfBuilder::new();
        b.header("1.4").obj(1, 0, "<< /Type /Catalog >>");
        b.xref_table(crate::XrefOpts::default());
        b.trailer(format!("/Size {} /Root 1 0 R", b.size()))
            .startxref(None)
            .eof();
        let store = Store::open_bytes(b.build(), &OpenOptions::default()).unwrap();
        assert_eq!(page_count(&store), None);
        assert!(exercise_store(&store).violations.is_empty());
    }
}

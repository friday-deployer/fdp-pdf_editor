//! Graph equality of two documents, modulo renumbering (M2 brief WP2.4).
//!
//! A full save renumbers objects, drops unreachable ones and re-encodes streams; an incremental
//! save keeps the numbers but writes the edits again. Both must keep what the document *means*:
//! the object graph reachable from the trailer. [`graph_diff`] and [`compare_graphs`] walk the
//! graphs of two [`Store`]s side by side from the trailer's `/Root` and `/Info` and report where
//! they differ, with a path a reader can follow (`trailer /Root → 1 0 R | 1 0 R /Pages → …`).
//!
//! # What counts as equal
//!
//! - **References** pair objects one to one: the first time a reference of `a` meets a reference
//!   of `b` the two objects are paired, and every later meeting must pair them again (a
//!   bijection, so two objects of `a` cannot become one object of `b` or the other way round).
//!   With [`GraphOptions::same_numbers`] the paired identifiers must also be equal (an
//!   incremental save keeps every number). A reference to an object that is not in use
//!   ([`Store::contains`]: free, freed, missing, of another generation) is `null` (§7.3.10). A
//!   reference on one side and a direct value on the other is a difference.
//! - **Dictionaries** have the same keys, where a key whose value is `null` (or a reference to an
//!   object not in use) counts as absent (§7.3.7), and equal values under each key. Order does
//!   not matter.
//! - **Arrays** have the same length and equal elements.
//! - **Streams** have equal dictionaries without the keys that describe the encoding
//!   ([`STREAM_ENCODING_KEYS`]: `/Length`, `/Filter`, `/DecodeParms`, `/DL`), which a writer may
//!   change, and equal data as [`Store::stream_data`] decodes it: the same bytes, the same image
//!   filters left to apply, the same truncation flag (or both fail with the same error code).
//! - **Reals** compare as the serializer writes them
//!   ([`canonical_real`]); every other value
//!   (integers, booleans, names, strings with their literal or hexadecimal form) compares exactly.
//!
//! # Bounds
//!
//! The walk is iterative (any nesting depth is fine), visits each pair of objects once, and stops
//! after [`GraphOptions::max_objects`] pairs or [`GraphOptions::max_values`] values; a comparison
//! cut short reports a [`DiffKind::Incomplete`] difference, so it is never mistaken for
//! equality. Stream data is decoded within the stores' own [`Limits`](folioxide_syntax::Limits).
//!
//! ```
//! use folioxide_syntax::{Object, OpenOptions, SaveOptions, Store};
//! use folioxide_testkit::fixtures::syntax;
//! use folioxide_testkit::graph::{GraphOptions, compare_graphs, graph_diff};
//!
//! let store = Store::open_bytes(syntax::multi_revision(), &OpenOptions::default())?;
//! let saved = Store::open_bytes(store.save(&SaveOptions::default())?, &OpenOptions::default())?;
//! // A full save renumbers, but the graph is the same.
//! assert_eq!(graph_diff(&store, &saved), None);
//! let strict = GraphOptions::default().with_same_numbers(true);
//! assert!(!compare_graphs(&store, &saved, &strict).is_equal());
//!
//! // An edit shows up with the path that leads to it.
//! let mut edited = Store::open_bytes(syntax::multi_revision(), &OpenOptions::default())?;
//! let root = edited.root_id().unwrap();
//! edited.get_mut(root)?.as_dict_mut().unwrap().insert("Lang", Object::literal_string("en"));
//! let diff = graph_diff(&store, &edited).unwrap();
//! assert_eq!(diff.path, "trailer /Root → 1 0 R | 1 0 R");
//! assert!(diff.to_string().contains("only in the right: /Lang"), "{diff}");
//! # Ok::<(), folioxide_syntax::Error>(())
//! ```

use std::collections::{HashMap, VecDeque};
use std::fmt;

use folioxide_syntax::serialize::canonical_real;
use folioxide_syntax::{Dict, Name, Object, ObjectId, Store, keys, serialize_object};

/// The stream dictionary keys that describe how the data is encoded, which a writer may change
/// (§7.3.8.2, Table 5): they are left out when stream dictionaries are compared, and the decoded
/// data is compared instead.
pub const STREAM_ENCODING_KEYS: [&[u8]; 4] =
    [keys::LENGTH, keys::FILTER, keys::DECODE_PARMS, keys::DL];

/// The longest rendering of a value in a difference ([`render`]), in characters; longer ones are
/// cut with `…`.
pub const MAX_RENDERED: usize = 120;

/// Options for [`compare_graphs`].
///
/// `#[non_exhaustive]`: start from [`GraphOptions::default()`] and use the `with_*` setters.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphOptions {
    /// The trailer keys whose values are the roots of both walks. Default `/Root` and `/Info`.
    pub roots: Vec<Name>,
    /// Paired objects must have the same identifier (number and generation), as after an
    /// incremental save. Default false: any one-to-one renumbering is equal.
    pub same_numbers: bool,
    /// Compare decoded stream data (otherwise only stream dictionaries). Default true.
    pub stream_data: bool,
    /// The most pairs of indirect objects compared before the comparison stops as
    /// [`DiffKind::Incomplete`]. Default 1,000,000.
    pub max_objects: usize,
    /// The most values (direct and indirect, nested ones included) compared before the
    /// comparison stops as [`DiffKind::Incomplete`]. Default 50,000,000.
    pub max_values: usize,
    /// The most differences collected; the walk stops at this many. Default 8.
    pub max_differences: usize,
}

impl Default for GraphOptions {
    fn default() -> Self {
        GraphOptions {
            roots: vec![Name::from(keys::ROOT), Name::from(keys::INFO)],
            same_numbers: false,
            stream_data: true,
            max_objects: 1_000_000,
            max_values: 50_000_000,
            max_differences: 8,
        }
    }
}

impl GraphOptions {
    /// Sets [`GraphOptions::roots`].
    #[must_use]
    pub fn with_roots(mut self, roots: &[&[u8]]) -> Self {
        self.roots = roots.iter().map(|&key| Name::from(key)).collect();
        self
    }

    /// Sets [`GraphOptions::same_numbers`].
    #[must_use]
    pub fn with_same_numbers(mut self, same_numbers: bool) -> Self {
        self.same_numbers = same_numbers;
        self
    }

    /// Sets [`GraphOptions::stream_data`].
    #[must_use]
    pub fn with_stream_data(mut self, stream_data: bool) -> Self {
        self.stream_data = stream_data;
        self
    }

    /// Sets [`GraphOptions::max_objects`].
    #[must_use]
    pub fn with_max_objects(mut self, max_objects: usize) -> Self {
        self.max_objects = max_objects;
        self
    }

    /// Sets [`GraphOptions::max_values`].
    #[must_use]
    pub fn with_max_values(mut self, max_values: usize) -> Self {
        self.max_values = max_values;
        self
    }

    /// Sets [`GraphOptions::max_differences`] (at least 1).
    #[must_use]
    pub fn with_max_differences(mut self, max_differences: usize) -> Self {
        self.max_differences = max_differences.max(1);
        self
    }
}

/// What differs at a [`GraphDiff`]'s path. Values are rendered in PDF syntax (shortened).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffKind {
    /// Two values differ: of different types, or equal types with different contents (a
    /// reference on one side and a direct value on the other included).
    Value {
        /// The left value.
        left: String,
        /// The right value.
        right: String,
    },
    /// Two dictionaries have different keys (`null` values count as absent).
    Keys {
        /// Keys only the left dictionary has.
        only_left: Vec<String>,
        /// Keys only the right dictionary has.
        only_right: Vec<String>,
    },
    /// Two arrays have different lengths.
    Length {
        /// The left length.
        left: usize,
        /// The right length.
        right: usize,
    },
    /// Two streams decode to different data.
    StreamData {
        /// The left data, described (length, filters left, truncation, or the error).
        left: String,
        /// The right data, described.
        right: String,
    },
    /// The references pair objects that are already paired with others: the graphs are not
    /// equal modulo renumbering.
    Pairing {
        /// The left object.
        left: ObjectId,
        /// The right object.
        right: ObjectId,
        /// The right object the left one was paired with before, if any.
        left_paired_with: Option<ObjectId>,
        /// The left object the right one was paired with before, if any.
        right_paired_with: Option<ObjectId>,
    },
    /// [`GraphOptions::same_numbers`]: paired objects have different identifiers.
    Number {
        /// The left identifier.
        left: ObjectId,
        /// The right identifier.
        right: ObjectId,
    },
    /// An object failed to resolve on one side or both (strict mode, or a limit), with
    /// different results.
    Unreadable {
        /// The left error, if the left side failed.
        left: Option<String>,
        /// The right error, if the right side failed.
        right: Option<String>,
    },
    /// The comparison stopped at a bound of [`GraphOptions`] before the walk finished: equality
    /// is not established.
    Incomplete {
        /// Which bound.
        reason: String,
    },
}

impl fmt::Display for DiffKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiffKind::Value { left, right } => write!(f, "{left} vs {right}"),
            DiffKind::Keys {
                only_left,
                only_right,
            } => {
                let mut parts = Vec::new();
                if !only_left.is_empty() {
                    parts.push(format!("only in the left: {}", only_left.join(" ")));
                }
                if !only_right.is_empty() {
                    parts.push(format!("only in the right: {}", only_right.join(" ")));
                }
                write!(f, "dictionary keys differ ({})", parts.join("; "))
            }
            DiffKind::Length { left, right } => {
                write!(f, "arrays of {left} and {right} elements")
            }
            DiffKind::StreamData { left, right } => {
                write!(f, "stream data differs: {left} vs {right}")
            }
            DiffKind::Pairing {
                left,
                right,
                left_paired_with,
                right_paired_with,
            } => {
                write!(f, "{left} and {right} do not pair one to one")?;
                if let Some(other) = left_paired_with {
                    write!(f, " ({left} is already paired with {other})")?;
                }
                if let Some(other) = right_paired_with {
                    write!(f, " ({right} is already paired with {other})")?;
                }
                Ok(())
            }
            DiffKind::Number { left, right } => {
                write!(f, "objects {left} and {right} have different numbers")
            }
            DiffKind::Unreadable { left, right } => write!(
                f,
                "unreadable: {} vs {}",
                left.as_deref().unwrap_or("read"),
                right.as_deref().unwrap_or("read")
            ),
            DiffKind::Incomplete { reason } => write!(f, "comparison incomplete: {reason}"),
        }
    }
}

/// One difference between two graphs.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphDiff {
    /// Where: the trailer key, then for every reference followed `→ left | right` (the two
    /// paired identifiers) and the keys (`/Kids`) and indices (`[0]`) inside each object.
    pub path: String,
    /// What differs there.
    pub kind: DiffKind,
    /// The indirect objects that hold the difference (`None` for a trailer value).
    pub objects: Option<(ObjectId, ObjectId)>,
}

impl fmt::Display for GraphDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.kind)
    }
}

/// The result of [`compare_graphs`].
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GraphComparison {
    /// The differences found, in walk order (at most [`GraphOptions::max_differences`]).
    pub differences: Vec<GraphDiff>,
    /// The pairs of indirect objects compared.
    pub objects: usize,
    /// The values compared (nested ones included).
    pub values: usize,
}

impl GraphComparison {
    /// Whether the graphs are equal: no difference, and the walk finished.
    pub fn is_equal(&self) -> bool {
        self.differences.is_empty()
    }

    /// The first difference, if any.
    pub fn first(&self) -> Option<&GraphDiff> {
        self.differences.first()
    }
}

impl fmt::Display for GraphComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.differences.is_empty() {
            return write!(
                f,
                "graphs are equal ({} object pairs, {} values)",
                self.objects, self.values
            );
        }
        write!(
            f,
            "graphs differ ({} difference(s) after {} object pairs):",
            self.differences.len(),
            self.objects
        )?;
        for diff in &self.differences {
            write!(f, "\n- {diff}")?;
        }
        Ok(())
    }
}

/// Compares the graphs of `a` and `b` with the default [`GraphOptions`] (modulo renumbering,
/// from `/Root` and `/Info`) and returns the first difference, or `None` when they are equal.
/// See the [module documentation](self) for what counts as equal.
pub fn graph_diff(a: &Store, b: &Store) -> Option<GraphDiff> {
    let opts = GraphOptions::default().with_max_differences(1);
    compare_graphs(a, b, &opts).differences.into_iter().next()
}

/// Compares the graphs of `a` and `b` reachable from the trailer keys [`GraphOptions::roots`];
/// see the [module documentation](self).
pub fn compare_graphs(a: &Store, b: &Store, opts: &GraphOptions) -> GraphComparison {
    let mut walk = Walk {
        a,
        b,
        opts,
        forward: HashMap::new(),
        backward: HashMap::new(),
        queue: VecDeque::new(),
        origins: Vec::new(),
        result: GraphComparison::default(),
    };
    walk.run();
    walk.result
}

/// Where a pair of objects was first reached: the pair that refers to it (`None`: a trailer
/// key) and the path inside that object.
struct Origin {
    parent: Option<usize>,
    via: String,
    ids: (ObjectId, ObjectId),
}

/// One step of the path inside an object: a dictionary key or an array index.
#[derive(Clone)]
enum Step {
    Key(Name),
    Index(usize),
}

/// The state of one comparison.
struct Walk<'s> {
    a: &'s Store,
    b: &'s Store,
    opts: &'s GraphOptions,
    forward: HashMap<ObjectId, ObjectId>,
    backward: HashMap<ObjectId, ObjectId>,
    /// Paired objects still to compare, as indices into `origins`.
    queue: VecDeque<usize>,
    origins: Vec<Origin>,
    result: GraphComparison,
}

impl Walk<'_> {
    fn run(&mut self) {
        // The trailer values are compared like the values inside an object, without one.
        let (a, b) = (self.a, self.b);
        for key in &self.opts.roots {
            let x = a.trailer().get(key.as_bytes()).unwrap_or(&Object::Null);
            let y = b.trailer().get(key.as_bytes()).unwrap_or(&Object::Null);
            let base = format!("trailer {key}");
            self.values(None, &base, x, y);
            if self.done() {
                return;
            }
        }
        while let Some(index) = self.queue.pop_front() {
            if self.done() {
                return;
            }
            if self.result.objects >= self.opts.max_objects {
                let reason = format!(
                    "more than {} object pairs (GraphOptions::max_objects)",
                    self.opts.max_objects
                );
                self.incomplete(Some(index), reason);
                return;
            }
            self.result.objects += 1;
            self.object(index);
        }
    }

    /// Whether the walk must stop: enough differences, or a bound reached.
    fn done(&self) -> bool {
        self.result.differences.len() >= self.opts.max_differences
            || self
                .result
                .differences
                .last()
                .is_some_and(|d| matches!(d.kind, DiffKind::Incomplete { .. }))
    }

    /// Compares the paired objects `origins[index]`.
    fn object(&mut self, index: usize) {
        let Some(&Origin { ids: (ia, ib), .. }) = self.origins.get(index) else {
            return;
        };
        let (x, y) = match (self.a.resolve(ia), self.b.resolve(ib)) {
            (Ok(x), Ok(y)) => (x, y),
            (Err(ex), Err(ey)) if ex.code() == ey.code() => return,
            (x, y) => {
                let kind = DiffKind::Unreadable {
                    left: x.err().map(|e| e.to_string()),
                    right: y.err().map(|e| e.to_string()),
                };
                self.differ(Some(index), "", kind);
                return;
            }
        };
        let base = String::new();
        self.values(Some(index), &base, &x, &y);
    }

    /// Compares two values held by the object pair `owner` (or the trailer), iteratively.
    fn values(&mut self, owner: Option<usize>, base: &str, x: &Object, y: &Object) {
        // (left, right, index into `steps` of the path to them)
        let mut steps: Vec<(Option<usize>, Step)> = Vec::new();
        let mut stack: Vec<(&Object, &Object, Option<usize>)> = vec![(x, y, None)];
        while let Some((x, y, at)) = stack.pop() {
            if self.done() {
                return;
            }
            if self.result.values >= self.opts.max_values {
                let reason = format!(
                    "more than {} values (GraphOptions::max_values)",
                    self.opts.max_values
                );
                self.incomplete(owner, reason);
                return;
            }
            self.result.values += 1;
            let (x, y) = (live(self.a, x), live(self.b, y));
            let path = || join(base, &render_steps(&steps, at));
            match (x, y) {
                (Object::Ref(ia), Object::Ref(ib)) => {
                    self.pair(owner, path(), *ia, *ib);
                }
                (Object::Dict(dx), Object::Dict(dy)) => {
                    self.dicts(owner, &path(), (dx, dy), &[], at, &mut steps, &mut stack);
                }
                (Object::Stream(sx), Object::Stream(sy)) => {
                    let p = path();
                    self.dicts(
                        owner,
                        &p,
                        (&sx.dict, &sy.dict),
                        &STREAM_ENCODING_KEYS,
                        at,
                        &mut steps,
                        &mut stack,
                    );
                    if self.opts.stream_data {
                        self.stream_data(owner, &p, sx, sy);
                    }
                }
                (Object::Array(ax), Object::Array(ay)) => {
                    if ax.len() != ay.len() {
                        let kind = DiffKind::Length {
                            left: ax.len(),
                            right: ay.len(),
                        };
                        self.differ(owner, &path(), kind);
                        continue;
                    }
                    // Reversed, so elements are compared in order.
                    for (i, (ex, ey)) in ax.iter().zip(ay).enumerate().rev() {
                        steps.push((at, Step::Index(i)));
                        stack.push((ex, ey, Some(steps.len() - 1)));
                    }
                }
                (Object::Real(rx), Object::Real(ry)) => {
                    if canonical_real(*rx) != canonical_real(*ry) {
                        self.differ(owner, &path(), value_kind(x, y));
                    }
                }
                _ => {
                    if x != y {
                        self.differ(owner, &path(), value_kind(x, y));
                    }
                }
            }
        }
    }

    /// Compares the keys of two dictionaries (`skip` aside) and pushes their values.
    #[allow(clippy::too_many_arguments)]
    fn dicts<'o>(
        &mut self,
        owner: Option<usize>,
        path: &str,
        (dx, dy): (&'o Dict, &'o Dict),
        skip: &[&[u8]],
        at: Option<usize>,
        steps: &mut Vec<(Option<usize>, Step)>,
        stack: &mut Vec<(&'o Object, &'o Object, Option<usize>)>,
    ) {
        let (a, b) = (self.a, self.b);
        let kx = present_keys(a, dx, skip);
        let ky = present_keys(b, dy, skip);
        if kx != ky {
            // Both lists are sorted.
            let only = |p: &[&Name], q: &[&Name]| -> Vec<String> {
                p.iter()
                    .filter(|k| q.binary_search(k).is_err())
                    .map(|k| k.to_string())
                    .collect()
            };
            let kind = DiffKind::Keys {
                only_left: only(&kx, &ky),
                only_right: only(&ky, &kx),
            };
            self.differ(owner, path, kind);
        }
        // The common keys are still compared, in the left dictionary's order.
        let mut pairs: Vec<(&'o Name, &'o Object, &'o Object)> = Vec::new();
        for (key, x) in dx.iter() {
            if kx.binary_search(&key).is_err() || ky.binary_search(&key).is_err() {
                continue;
            }
            if let Some(y) = dy.get(key.as_bytes()) {
                pairs.push((key, x, y));
            }
        }
        for (key, x, y) in pairs.into_iter().rev() {
            steps.push((at, Step::Key(key.clone())));
            stack.push((x, y, Some(steps.len() - 1)));
        }
    }

    /// Compares the decoded data of two streams.
    fn stream_data(
        &mut self,
        owner: Option<usize>,
        path: &str,
        sx: &folioxide_syntax::Stream,
        sy: &folioxide_syntax::Stream,
    ) {
        let dx = self.a.stream_data(sx);
        let dy = self.b.stream_data(sy);
        let equal = match (&dx, &dy) {
            (Ok(x), Ok(y)) => x == y,
            (Err(ex), Err(ey)) => ex.code() == ey.code(),
            _ => false,
        };
        if !equal {
            let kind = DiffKind::StreamData {
                left: describe_data(&dx),
                right: describe_data(&dy),
            };
            self.differ(owner, path, kind);
        }
    }

    /// Pairs the referenced objects `ia` and `ib`, queueing them the first time.
    fn pair(&mut self, owner: Option<usize>, via: String, ia: ObjectId, ib: ObjectId) {
        let (fa, fb) = (
            self.forward.get(&ia).copied(),
            self.backward.get(&ib).copied(),
        );
        match (fa, fb) {
            (Some(fa), Some(_)) if fa == ib => return,
            (None, None) => {}
            _ => {
                let kind = DiffKind::Pairing {
                    left: ia,
                    right: ib,
                    left_paired_with: fa,
                    right_paired_with: fb,
                };
                self.differ(owner, &format!("{via} → {ia} | {ib}"), kind);
                return;
            }
        }
        self.forward.insert(ia, ib);
        self.backward.insert(ib, ia);
        self.origins.push(Origin {
            parent: owner,
            via,
            ids: (ia, ib),
        });
        let index = self.origins.len() - 1;
        if self.opts.same_numbers && ia != ib {
            let kind = DiffKind::Number {
                left: ia,
                right: ib,
            };
            self.differ(Some(index), "", kind);
            return;
        }
        self.queue.push_back(index);
    }

    /// Records a difference at `path` inside the object pair `owner`.
    fn differ(&mut self, owner: Option<usize>, path: &str, kind: DiffKind) {
        if self.result.differences.len() >= self.opts.max_differences {
            return;
        }
        let full = join(&self.object_path(owner), path);
        let objects = owner.and_then(|i| self.origins.get(i)).map(|o| o.ids);
        self.result.differences.push(GraphDiff {
            path: full,
            kind,
            objects,
        });
    }

    /// Records that the comparison stopped at a bound (always kept, even past
    /// [`GraphOptions::max_differences`], so a cut-short comparison is never equal).
    fn incomplete(&mut self, owner: Option<usize>, reason: String) {
        if self.result.differences.len() >= self.opts.max_differences {
            self.result.differences.pop();
        }
        let path = self.object_path(owner);
        let objects = owner.and_then(|i| self.origins.get(i)).map(|o| o.ids);
        self.result.differences.push(GraphDiff {
            path,
            kind: DiffKind::Incomplete { reason },
            objects,
        });
    }

    /// The path from the trailer to the object pair `index`: `trailer /Root → 1 0 R | 1 0 R
    /// /Pages → 2 0 R | 3 0 R`.
    fn object_path(&self, index: Option<usize>) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut next = index;
        // Each origin's parent was pushed before it, so this ends.
        let mut guard = self.origins.len();
        while let Some(i) = next {
            let Some(origin) = self.origins.get(i) else {
                break;
            };
            let (ia, ib) = origin.ids;
            parts.push(join(&origin.via, &format!("→ {ia} | {ib}")));
            next = origin.parent.filter(|&p| p < i);
            guard = guard.saturating_sub(1);
            if guard == 0 {
                break;
            }
        }
        parts.reverse();
        parts.join(" ")
    }
}

/// `obj`, or `null` for a reference to an object that is not in use in `store`.
fn live<'o>(store: &Store, obj: &'o Object) -> &'o Object {
    match obj {
        Object::Ref(id) if !store.contains(*id) => &Object::Null,
        other => other,
    }
}

/// The keys of `dict` whose values are present (not `null`, not a reference to an object not in
/// use), `skip` aside, sorted.
fn present_keys<'d>(store: &Store, dict: &'d Dict, skip: &[&[u8]]) -> Vec<&'d Name> {
    let mut present: Vec<&Name> = dict
        .iter()
        .filter(|(key, value)| !skip.contains(&key.as_bytes()) && !live(store, value).is_null())
        .map(|(key, _)| key)
        .collect();
    present.sort();
    present
}

/// The path of steps ending at `at`: `/Kids [0] /MediaBox`.
fn render_steps(steps: &[(Option<usize>, Step)], at: Option<usize>) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut next = at;
    while let Some(i) = next {
        let Some((parent, step)) = steps.get(i) else {
            break;
        };
        parts.push(match step {
            Step::Key(key) => key.to_string(),
            Step::Index(n) => format!("[{n}]"),
        });
        // Parents are pushed before their children.
        next = parent.filter(|&p| p < i);
    }
    parts.reverse();
    parts.join(" ")
}

/// `a` and `b` joined with a space (either may be empty).
fn join(a: &str, b: &str) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, _) => b.to_owned(),
        (_, true) => a.to_owned(),
        _ => format!("{a} {b}"),
    }
}

/// A [`DiffKind::Value`] for two values.
fn value_kind(x: &Object, y: &Object) -> DiffKind {
    DiffKind::Value {
        left: render(x),
        right: render(y),
    }
}

/// A value in PDF syntax, shortened to [`MAX_RENDERED`] characters.
pub fn render(obj: &Object) -> String {
    let mut out = Vec::new();
    match obj {
        Object::Stream(stream) => {
            serialize_object(&Object::Dict(stream.dict.clone()), &mut out);
            out.extend_from_slice(b" stream");
        }
        other => serialize_object(other, &mut out),
    }
    let text = String::from_utf8_lossy(&out);
    let mut shortened: String = text.chars().take(MAX_RENDERED).collect();
    if text.chars().count() > MAX_RENDERED {
        shortened.push('…');
    }
    shortened
}

/// Describes decoded stream data for a [`DiffKind::StreamData`].
fn describe_data(data: &folioxide_syntax::Result<folioxide_syntax::StreamBytes>) -> String {
    match data {
        Ok(bytes) => {
            let mut text = format!("{} bytes", bytes.data.len());
            if !bytes.remaining.is_empty() {
                let filters: Vec<String> =
                    bytes.remaining.iter().map(|f| format!("{f:?}")).collect();
                text.push_str(&format!(" with {} still to apply", filters.join(", ")));
            }
            if bytes.truncated {
                text.push_str(" (truncated)");
            }
            let head: Vec<String> = bytes
                .data
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect();
            text.push_str(&format!(" [{}…]", head.join(" ")));
            text
        }
        Err(err) => format!("error {:?}: {err}", err.code()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{model, syntax};
    use folioxide_syntax::{OpenOptions, SaveOptions, Stream, StreamData};

    /// A document built in memory: a catalog (with `extra` entries) whose `/Pages` has one page,
    /// and an Info dictionary. With `padding`, unreachable objects come first, so the numbers
    /// differ from an unpadded build.
    fn build(padding: usize, extra: &[(&str, Object)]) -> Store {
        let mut store = Store::new_empty((1, 7));
        for _ in 0..padding {
            store.add(Object::Int(0)).unwrap();
        }
        let mut page = Dict::new();
        page.insert(keys::TYPE, Object::name("Page"));
        page.insert(
            keys::MEDIA_BOX,
            Object::Array(vec![0.into(), 0.into(), 612.into(), Object::Real(792.0)]),
        );
        let page = store.add(page.into()).unwrap();
        let mut pages = Dict::new();
        pages.insert(keys::TYPE, Object::name("Pages"));
        pages.insert(keys::KIDS, Object::Array(vec![page.into()]));
        pages.insert(keys::COUNT, 1);
        let pages = store.add(pages.into()).unwrap();
        let mut catalog = Dict::new();
        catalog.insert(keys::TYPE, Object::name("Catalog"));
        catalog.insert(keys::PAGES, pages);
        for (key, value) in extra {
            catalog.insert(*key, value.clone());
        }
        let catalog = store.add(catalog.into()).unwrap();
        store.set_trailer_entry(keys::ROOT, catalog.into()).unwrap();
        let mut info = Dict::new();
        info.insert("Title", Object::literal_string("graph"));
        let info = store.add(info.into()).unwrap();
        store.set_trailer_entry(keys::INFO, info.into()).unwrap();
        store
    }

    fn open(bytes: Vec<u8>) -> Store {
        Store::open_bytes(bytes, &OpenOptions::default()).unwrap()
    }

    #[test]
    fn renumbered_graphs_are_equal_and_same_numbers_is_stricter() {
        let a = build(0, &[]);
        let b = build(3, &[]);
        assert_eq!(graph_diff(&a, &b), None);
        let comparison = compare_graphs(&a, &b, &GraphOptions::default());
        assert!(comparison.is_equal(), "{comparison}");
        // Catalog, pages, page, Info.
        assert_eq!(comparison.objects, 4);
        assert!(comparison.to_string().starts_with("graphs are equal"));

        let strict = GraphOptions::default().with_same_numbers(true);
        let comparison = compare_graphs(&a, &b, &strict);
        let first = comparison.first().unwrap();
        assert!(
            matches!(first.kind, DiffKind::Number { .. }),
            "{comparison}"
        );
        assert_eq!(first.path, "trailer /Root → 3 0 R | 6 0 R");
        assert!(compare_graphs(&a, &build(0, &[]), &strict).is_equal());
    }

    #[test]
    fn differences_have_readable_paths() {
        let a = build(0, &[]);
        let mut b = build(0, &[]);
        let page = ObjectId::new(1, 0);
        b.get_mut(page).unwrap().as_dict_mut().unwrap().insert(
            keys::MEDIA_BOX,
            Object::Array(vec![0.into(), 0.into(), 595.into(), Object::Real(842.0)]),
        );
        let comparison = compare_graphs(&a, &b, &GraphOptions::default());
        assert_eq!(comparison.differences.len(), 2, "{comparison}");
        let first = &comparison.differences[0];
        assert_eq!(
            first.path,
            "trailer /Root → 3 0 R | 3 0 R /Pages → 2 0 R | 2 0 R /Kids [0] → 1 0 R | 1 0 R \
             /MediaBox [2]"
        );
        assert_eq!(
            first.kind,
            DiffKind::Value {
                left: "612".into(),
                right: "595".into()
            }
        );
        assert_eq!(first.objects, Some((page, page)));
        assert_eq!(
            comparison.differences[1].to_string(),
            "trailer /Root → 3 0 R | 3 0 R /Pages → 2 0 R | 2 0 R /Kids [0] → 1 0 R | 1 0 R \
             /MediaBox [3]: 792.0 vs 842.0"
        );
        // graph_diff stops at the first one.
        assert_eq!(graph_diff(&a, &b).as_ref(), Some(first));
        let text = comparison.to_string();
        assert!(text.starts_with("graphs differ (2 difference(s)"), "{text}");

        // Keys, lengths and types.
        let b = build(
            0,
            &[
                ("Lang", Object::literal_string("en")),
                ("Pages", Object::Array(vec![])),
            ],
        );
        let diff = graph_diff(&a, &b).unwrap();
        assert_eq!(
            diff.kind,
            DiffKind::Keys {
                only_left: vec![],
                only_right: vec!["/Lang".into()]
            }
        );
        let comparison = compare_graphs(&a, &b, &GraphOptions::default());
        assert_eq!(
            comparison.differences[1].kind,
            DiffKind::Value {
                left: "2 0 R".into(),
                right: "[]".into()
            }
        );
        let x = build(0, &[("Arr", Object::Array(vec![1.into()]))]);
        let y = build(0, &[("Arr", Object::Array(vec![1.into(), 2.into()]))]);
        assert_eq!(
            graph_diff(&x, &y).unwrap().to_string(),
            "trailer /Root → 3 0 R | 3 0 R /Arr: arrays of 1 and 2 elements"
        );
    }

    #[test]
    fn nulls_and_dangling_references_count_as_absent() {
        let a = build(0, &[]);
        let b = build(
            0,
            &[
                ("Nothing", Object::Null),
                ("Dangling", Object::Ref(ObjectId::new(99, 0))),
            ],
        );
        assert_eq!(graph_diff(&a, &b), None);
        // In an array, a dangling reference is null.
        let x = build(0, &[("Arr", Object::Array(vec![Object::Null]))]);
        let y = build(
            0,
            &[("Arr", Object::Array(vec![ObjectId::new(42, 0).into()]))],
        );
        assert_eq!(graph_diff(&x, &y), None);
        // A reference to an object in use is not null.
        let z = build(
            0,
            &[("Arr", Object::Array(vec![ObjectId::new(1, 0).into()]))],
        );
        assert!(graph_diff(&x, &z).is_some());
        // Reals compare as written; integers and reals do not mix.
        let r1 = build(0, &[("R", Object::Real(1.0 / 3.0))]);
        let r2 = build(0, &[("R", Object::Real(0.3333333333))]);
        assert_eq!(graph_diff(&r1, &r2), None);
        let r3 = build(0, &[("R", Object::Int(1))]);
        let r4 = build(0, &[("R", Object::Real(1.0))]);
        assert!(graph_diff(&r3, &r4).is_some());
        // Literal and hexadecimal strings differ.
        let s1 = build(0, &[("S", Object::literal_string("x"))]);
        let s2 = build(0, &[("S", Object::hex_string("x"))]);
        assert!(graph_diff(&s1, &s2).is_some());
    }

    #[test]
    fn references_must_pair_one_to_one() {
        // Left: two distinct (equal) objects; right: one object referenced twice.
        let mut a = build(0, &[]);
        let one = a.add(Object::Int(7)).unwrap();
        let two = a.add(Object::Int(7)).unwrap();
        let root = a.root_id().unwrap();
        a.get_mut(root)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .insert("Both", Object::Array(vec![one.into(), two.into()]));
        let mut b = build(0, &[]);
        let only = b.add(Object::Int(7)).unwrap();
        let root = b.root_id().unwrap();
        b.get_mut(root)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .insert("Both", Object::Array(vec![only.into(), only.into()]));
        let diff = graph_diff(&a, &b).unwrap();
        assert_eq!(
            diff.kind,
            DiffKind::Pairing {
                left: two,
                right: only,
                left_paired_with: None,
                right_paired_with: Some(one),
            }
        );
        assert!(
            diff.path.ends_with("/Both [1] → 6 0 R | 5 0 R"),
            "{}",
            diff.path
        );
        assert!(graph_diff(&b, &a).is_some());
    }

    #[test]
    fn streams_compare_decoded_data_without_encoding_keys() {
        let with_stream = |data: StreamData, extra: &[(&str, Object)]| {
            let mut store = build(0, &[]);
            let mut dict = Dict::new();
            for (key, value) in extra {
                dict.insert(*key, value.clone());
            }
            let stream = store.add(Stream::new(dict, data).into()).unwrap();
            let root = store.root_id().unwrap();
            store
                .get_mut(root)
                .unwrap()
                .as_dict_mut()
                .unwrap()
                .insert("S", stream);
            store
        };
        let plain = with_stream(StreamData::Decoded(b"hello".to_vec()), &[]);
        let encoded = with_stream(
            StreamData::Encoded(b"68656c6c6f>".to_vec()),
            &[
                ("Filter", Object::name("ASCIIHexDecode")),
                ("Length", Object::Int(11)),
            ],
        );
        assert_eq!(graph_diff(&plain, &encoded), None);
        let other = with_stream(StreamData::Decoded(b"world".to_vec()), &[]);
        let diff = graph_diff(&plain, &other).unwrap();
        assert!(matches!(diff.kind, DiffKind::StreamData { .. }), "{diff}");
        assert!(
            diff.to_string().contains("5 bytes [68 65 6c 6c 6f…]"),
            "{diff}"
        );
        // Without data comparison, only the dictionaries count.
        let opts = GraphOptions::default().with_stream_data(false);
        assert!(compare_graphs(&plain, &other, &opts).is_equal());
        // Other stream keys count.
        let typed = with_stream(
            StreamData::Decoded(b"hello".to_vec()),
            &[("Type", Object::name("XObject"))],
        );
        assert!(graph_diff(&plain, &typed).is_some());
    }

    #[test]
    fn comparisons_are_bounded() {
        let a = build(0, &[]);
        let b = build(2, &[]);
        let opts = GraphOptions::default().with_max_objects(2);
        let comparison = compare_graphs(&a, &b, &opts);
        assert!(!comparison.is_equal());
        assert_eq!(comparison.objects, 2);
        assert!(matches!(
            comparison.first().unwrap().kind,
            DiffKind::Incomplete { .. }
        ));
        let opts = GraphOptions::default().with_max_values(5);
        let comparison = compare_graphs(&a, &b, &opts);
        assert!(
            matches!(
                comparison.differences.last().unwrap().kind,
                DiffKind::Incomplete { .. }
            ),
            "{comparison}"
        );
        assert_eq!(comparison.values, 5);
        // An incomplete comparison is reported even when the difference list is full.
        let x = build(0, &[("A", 1.into()), ("B", 1.into())]);
        let y = build(0, &[("A", 2.into()), ("B", 2.into())]);
        let opts = GraphOptions::default()
            .with_max_differences(1)
            .with_max_objects(1);
        let comparison = compare_graphs(&x, &y, &opts);
        assert_eq!(comparison.differences.len(), 1);
        assert!(!comparison.is_equal());

        // Deep nesting is walked iteratively.
        let mut deep = Object::Int(1);
        for _ in 0..200 {
            deep = Object::Array(vec![deep]);
        }
        let x = build(0, &[("Deep", deep.clone())]);
        let y = build(0, &[("Deep", deep)]);
        assert_eq!(graph_diff(&x, &y), None);
    }

    #[test]
    fn cycles_and_saved_documents() {
        // A page tree with cycles is walked once per object pair.
        let store = open(model::page_tree_cycle());
        let saved = open(store.save(&SaveOptions::default()).unwrap());
        let comparison = compare_graphs(&store, &saved, &GraphOptions::default());
        assert!(comparison.is_equal(), "{comparison}");
        assert_eq!(comparison.objects, store.object_ids().len());
        // Every syntax fixture that opens equals its full save.
        for (name, bytes) in syntax::all() {
            let Ok(store) = Store::open_bytes(bytes, &OpenOptions::default()) else {
                continue;
            };
            let saved = open(store.save(&SaveOptions::default()).unwrap());
            if let Some(diff) = graph_diff(&store, &saved) {
                panic!("{name}: {diff}");
            }
        }
        // Roots can be chosen.
        let a = build(0, &[]);
        let mut b = build(0, &[]);
        b.remove_trailer_entry(keys::INFO).unwrap();
        assert!(graph_diff(&a, &b).is_some());
        let opts = GraphOptions::default().with_roots(&[keys::ROOT]);
        assert!(compare_graphs(&a, &b, &opts).is_equal());
    }

    #[test]
    fn render_shortens_long_values() {
        let long = Object::literal_string(vec![b'a'; 500]);
        let text = render(&long);
        assert_eq!(text.chars().count(), MAX_RENDERED + 1);
        assert!(text.ends_with('…'));
        assert_eq!(render(&Object::Ref(ObjectId::new(3, 1))), "3 1 R");
    }
}

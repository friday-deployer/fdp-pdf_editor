//! Name trees and number trees (ISO 32000-2 §7.9.6, §7.9.7).
//!
//! Both map keys to values through a tree of dictionaries: the root has `/Kids` or the
//! entries, intermediate nodes have `/Kids` and `/Limits` (the smallest and largest key below
//! them), and leaves have `/Limits` and the entries, `/Names [key1 value1 key2 value2 …]` with
//! string keys (sorted by their bytes) or `/Nums […]` with integer keys (sorted numerically).
//! Name trees hold named destinations and embedded files, number trees page labels and the
//! structure parent tree.
//!
//! The walks are iterative and bounded: each indirect node is visited at most once (cycles and
//! shared nodes are skipped), a branch deeper than [`Limits::max_nesting_depth`] or a tree with
//! more nodes than [`Limits::max_objects`] is an
//! [`ErrorCode::LimitExceeded`](folioxide_syntax::ErrorCode::LimitExceeded) error. Malformed
//! parts (a kid that is not a dictionary, a key of the wrong type, an odd number of elements) are
//! skipped. A node with both `/Kids` and entries is read through its `/Kids`, as pdf.js does.
//!
//! [`NameTree::get`] and [`NumberTree::get`] descend only into kids whose `/Limits` admit the
//! key; when that finds nothing, they search the whole tree, because real files have wrong or
//! unsorted `/Limits`. A miss therefore costs a full walk.
//!
//! [`Limits::max_nesting_depth`]: folioxide_syntax::Limits::max_nesting_depth
//! [`Limits::max_objects`]: folioxide_syntax::Limits::max_objects

use std::collections::HashSet;
use std::ops::ControlFlow;
use std::sync::Arc;

use folioxide_syntax::{Error, LimitKind, Object, ObjectId, Result, Store};

/// `/Kids` (§7.9.6, Table 36).
const KIDS: &[u8] = b"Kids";
/// `/Limits` (§7.9.6, Table 36).
const LIMITS: &[u8] = b"Limits";

/// A key type of a tree: strings for name trees, integers for number trees.
trait TreeKey: Sized + PartialOrd {
    /// The key of the entries array: `Names` or `Nums`.
    const ENTRIES: &'static [u8];

    /// Reads a key; `None` when the object is not a valid key.
    fn from_object(obj: &Object) -> Option<Self>;
}

impl TreeKey for Vec<u8> {
    const ENTRIES: &'static [u8] = b"Names";

    fn from_object(obj: &Object) -> Option<Self> {
        obj.as_str_bytes().map(<[u8]>::to_vec)
    }
}

impl TreeKey for i64 {
    const ENTRIES: &'static [u8] = b"Nums";

    fn from_object(obj: &Object) -> Option<Self> {
        match obj {
            Object::Int(i) => Some(*i),
            // §7.9.7 requires integers; integral reals are accepted leniently.
            Object::Real(r) if r.fract() == 0.0 && r.abs() < 9e15 => Some(*r as i64),
            _ => None,
        }
    }
}

/// A node to visit: the node object, and its depth (the root is 1).
struct Pending {
    node: Arc<Object>,
    depth: usize,
}

/// Walks the tree at `root` in key order (kids left to right), calling `visit` for each entry.
///
/// When `key` is given, only kids whose `/Limits` admit it are entered (kids without valid
/// `/Limits` always are); the result says whether a kid was left out that way.
fn walk<K: TreeKey>(
    store: &Store,
    root: &Object,
    key: Option<&K>,
    mut visit: impl FnMut(K, &Object) -> ControlFlow<()>,
) -> Result<bool> {
    let limits = store.limits();
    let max_depth = usize::from(limits.effective_nesting_depth());
    let max_nodes = usize::try_from(limits.max_objects).unwrap_or(usize::MAX);
    let mut visited: HashSet<ObjectId> = HashSet::new();
    let mut nodes = 0usize;
    let mut pruned = false;

    if let Object::Ref(id) = root {
        visited.insert(*id);
    }
    let mut stack = vec![Pending {
        node: store.deref(root)?.into_arc(),
        depth: 1,
    }];
    while let Some(Pending { node, depth }) = stack.pop() {
        nodes += 1;
        if nodes > max_nodes {
            return Err(Error::limit(
                LimitKind::MaxObjects,
                u64::from(limits.max_objects),
                None,
            ));
        }
        let Some(dict) = node.as_dict() else {
            continue;
        };
        if let Some(kids) = dict.get(KIDS) {
            let kids = store.deref(kids)?;
            let Some(kids) = kids.as_array() else {
                continue;
            };
            if depth >= max_depth {
                return Err(Error::limit(
                    LimitKind::MaxNestingDepth,
                    u64::from(limits.effective_nesting_depth()),
                    None,
                ));
            }
            // Pushed in reverse, so the leftmost kid is visited first.
            for kid in kids.iter().rev() {
                if let Object::Ref(id) = kid
                    && !visited.insert(*id)
                {
                    continue;
                }
                let kid = store.deref(kid)?.into_arc();
                if let Some(key) = key
                    && !admits::<K>(store, &kid, key)?
                {
                    pruned = true;
                    continue;
                }
                stack.push(Pending {
                    node: kid,
                    depth: depth + 1,
                });
            }
            continue;
        }
        let Some(entries) = dict.get(K::ENTRIES) else {
            continue;
        };
        let entries = store.deref(entries)?;
        let Some(entries) = entries.as_array() else {
            continue;
        };
        for pair in entries.chunks_exact(2) {
            let [k, v] = pair else {
                continue;
            };
            let Some(k) = K::from_object(&*store.deref(k)?) else {
                continue;
            };
            if visit(k, v).is_break() {
                return Ok(pruned);
            }
        }
    }
    Ok(pruned)
}

/// Whether the `/Limits` of `node` admit `key`: true when it has no valid `/Limits`.
fn admits<K: TreeKey>(store: &Store, node: &Object, key: &K) -> Result<bool> {
    let Some(limits) = node.as_dict().and_then(|d| d.get(LIMITS)) else {
        return Ok(true);
    };
    let limits = store.deref(limits)?;
    let Some([low, high]) = limits.as_array() else {
        return Ok(true);
    };
    let (Some(low), Some(high)) = (
        K::from_object(&*store.deref(low)?),
        K::from_object(&*store.deref(high)?),
    ) else {
        return Ok(true);
    };
    Ok(low <= *key && *key <= high)
}

/// Looks `key` up: first through the `/Limits`, then, when that missed and `/Limits` excluded
/// some kids, through the whole tree.
fn get<K: TreeKey>(store: &Store, root: &Object, key: &K) -> Result<Option<Object>> {
    let mut found = None;
    let pruned = walk(store, root, Some(key), |k, v| find(&mut found, key, k, v))?;
    if found.is_none() && pruned {
        walk(store, root, None, |k, v| find(&mut found, key, k, v))?;
    }
    Ok(found)
}

/// Keeps `value` and stops the walk when `k` is the key looked for.
fn find<K: TreeKey>(found: &mut Option<Object>, key: &K, k: K, value: &Object) -> ControlFlow<()> {
    if k == *key {
        *found = Some(value.clone());
        ControlFlow::Break(())
    } else {
        ControlFlow::Continue(())
    }
}

/// All entries in tree order.
fn entries<K: TreeKey>(store: &Store, root: &Object) -> Result<Vec<(K, Object)>> {
    let mut out = Vec::new();
    walk(store, root, None, |k: K, v: &Object| {
        out.push((k, v.clone()));
        ControlFlow::Continue(())
    })?;
    Ok(out)
}

/// A name tree (§7.9.6): string keys, compared by their bytes.
///
/// Values are returned as written in the tree, which is often an indirect reference: follow it
/// with [`Store::deref`].
///
/// ```
/// use folioxide_model::NameTree;
/// use folioxide_syntax::{parse_object, Object, OpenOptions, ParseCtx, Store};
/// # let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n\
/// # 0000000000 65535 f\r\n0000000009 00000 n\r\ntrailer\n<< /Size 2 /Root 1 0 R >>\n\
/// # startxref\n45\n%%EOF\n";
/// # let store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default())?;
///
/// let (root, _) = parse_object(b"<< /Names [(a) 1 (b) 2] >>", 0, &ParseCtx::default())?;
/// let tree = NameTree::new(&store, &root);
/// assert_eq!(tree.get(b"b")?, Some(Object::Int(2)));
/// assert_eq!(tree.get(b"c")?, None);
/// assert_eq!(tree.entries()?.len(), 2);
/// # Ok::<(), folioxide_syntax::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct NameTree<'a> {
    store: &'a Store,
    root: Object,
}

impl<'a> NameTree<'a> {
    /// The name tree whose root is `root` (a dictionary, or a reference to one).
    pub fn new(store: &'a Store, root: &Object) -> Self {
        NameTree {
            store,
            root: root.clone(),
        }
    }

    /// The value for `key`, or `None` when the tree has no such key. With duplicate keys, the
    /// first in tree order.
    ///
    /// # Errors
    /// [`ErrorCode::LimitExceeded`](folioxide_syntax::ErrorCode::LimitExceeded) for a tree that
    /// is too deep or too large, and the errors of [`Store::deref`].
    pub fn get(&self, key: &[u8]) -> Result<Option<Object>> {
        get(self.store, &self.root, &key.to_vec())
    }

    /// Every entry, in tree order (sorted by key in a well-formed tree).
    ///
    /// # Errors
    /// As [`NameTree::get`].
    pub fn entries(&self) -> Result<Vec<(Vec<u8>, Object)>> {
        entries(self.store, &self.root)
    }
}

/// A number tree (§7.9.7): integer keys.
///
/// Values are returned as written in the tree, which is often an indirect reference: follow it
/// with [`Store::deref`].
#[derive(Clone, Debug)]
pub struct NumberTree<'a> {
    store: &'a Store,
    root: Object,
}

impl<'a> NumberTree<'a> {
    /// The number tree whose root is `root` (a dictionary, or a reference to one).
    pub fn new(store: &'a Store, root: &Object) -> Self {
        NumberTree {
            store,
            root: root.clone(),
        }
    }

    /// The value for `key`, or `None` when the tree has no such key. With duplicate keys, the
    /// first in tree order.
    ///
    /// # Errors
    /// [`ErrorCode::LimitExceeded`](folioxide_syntax::ErrorCode::LimitExceeded) for a tree that
    /// is too deep or too large, and the errors of [`Store::deref`].
    pub fn get(&self, key: i64) -> Result<Option<Object>> {
        get(self.store, &self.root, &key)
    }

    /// Every entry, in tree order (sorted by key in a well-formed tree).
    ///
    /// # Errors
    /// As [`NumberTree::get`].
    pub fn entries(&self) -> Result<Vec<(i64, Object)>> {
        entries(self.store, &self.root)
    }
}

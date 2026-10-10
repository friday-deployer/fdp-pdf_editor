//! The page-tree walk (ISO 32000-2 §7.7.3).
//!
//! The walk is iterative (an explicit stack, never recursion) and reads the tree the way the
//! leaves are reached, not the way `/Count` describes it:
//!
//! - every intermediate (`/Pages`) node is visited at most once (an `ObjectId` set): a node that
//!   appears again, through a cycle or because two nodes list it, is skipped with a diagnostic,
//!   so each `/Kids` array is read once and the walk does at most one step per kid entry of the
//!   file;
//! - a page (a leaf) listed more than once is a page each time it is listed, with a diagnostic:
//!   the same [`PageId`](crate::PageId) at several indices, as poppler, pypdf and qpdf (which
//!   copies the page object) count it; ISO 32000-2 §7.7.3.2 does not define such a tree;
//! - a branch deeper than [`Limits::max_page_tree_depth`] intermediate nodes is a
//!   [`ErrorCode::LimitExceeded`] error (in both modes: the pages below it cannot be numbered),
//!   and so is a tree with more nodes and pages than [`Limits::max_objects`];
//! - a kid that is not an indirect reference to a dictionary, or whose `/Type` is neither
//!   `/Pages` nor `/Page`, is skipped with a diagnostic; a node without `/Type` is a `/Pages`
//!   node when it has `/Kids` and a page otherwise (a missing `/Type` on a leaf is common and
//!   tolerated silently);
//! - a `/Count` that does not match the leaves found under its node, and a kid whose `/Parent`
//!   is not the node that lists it, give diagnostics; the walk itself does not depend on them.
//!
//! Inherited attributes (§7.7.3.4) are looked up along the path the walk took to a page, as
//! poppler does (and qpdf for `/MediaBox` and `/Resources`), so the result agrees with
//! `pdfinfo` even when a `/Parent` is wrong. Readers that follow `/Parent` instead (pdf.js, and
//! qpdf for `/CropBox` and `/Rotate`) can then disagree; the page setters write values that
//! settle it (see [`Document::set_rotation`](crate::Document::set_rotation)).
//!
//! [`Limits::max_page_tree_depth`]: folioxide_syntax::Limits::max_page_tree_depth
//! [`Limits::max_objects`]: folioxide_syntax::Limits::max_objects

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use folioxide_syntax::{
    DiagnosticKind, Dict, Error, ErrorCode, LimitKind, Object, ObjectId, Result, Store, keys,
};

use crate::diag::ModelLog;

/// The result of a page-tree walk: the pages in document order and the intermediate nodes
/// above them.
#[derive(Debug, Default)]
pub(crate) struct PageTree {
    /// The pages, in document order.
    pub(crate) pages: Vec<TreeEntry>,
    /// The intermediate (`/Pages`) nodes that were walked; `nodes[0]` is the root when the
    /// root is a `/Pages` node.
    pub(crate) nodes: Vec<TreeEntry>,
}

/// A page or an intermediate node, and the node it was found in.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TreeEntry {
    /// The object.
    pub(crate) id: ObjectId,
    /// The index of the node that lists it in [`PageTree::nodes`]; `None` for the root.
    pub(crate) parent: Option<usize>,
}

impl PageTree {
    /// Whether `id` is a page or an intermediate node of the tree.
    pub(crate) fn contains(&self, id: ObjectId) -> bool {
        self.pages
            .iter()
            .chain(&self.nodes)
            .any(|entry| entry.id == id)
    }

    /// The intermediate nodes above page `index`, nearest first. Empty when the index is out of
    /// range.
    pub(crate) fn ancestors(&self, index: usize) -> Vec<ObjectId> {
        let mut out = Vec::new();
        let mut next = self.pages.get(index).and_then(|p| p.parent);
        // Parents always come before their kids in `nodes`, so this ends; the bound is a
        // safeguard.
        while let Some(i) = next {
            let Some(node) = self.nodes.get(i) else {
                break;
            };
            out.push(node.id);
            if out.len() > self.nodes.len() {
                break;
            }
            next = node.parent;
        }
        out
    }
}

/// One `/Pages` node on the walk's stack.
struct Frame {
    /// Its index in [`PageTree::nodes`].
    node: usize,
    /// Its `/Kids`.
    kids: Vec<Object>,
    /// The next kid to visit.
    next: usize,
}

/// What a page-tree object is.
enum NodeKind {
    /// An intermediate node (`/Type /Pages`, or no `/Type` but `/Kids`).
    Pages,
    /// A page (`/Type /Page`, or no `/Type` and no `/Kids`).
    Page,
    /// Something else: `/Type` is another name.
    Other,
}

/// Classifies a page-tree dictionary (§7.7.3.2, §7.7.3.3), reporting a missing `/Type` on an
/// intermediate node.
fn classify(dict: &Dict, id: ObjectId, log: &ModelLog) -> NodeKind {
    match dict.get_name(keys::TYPE) {
        Some(t) if *t == keys::PAGES => NodeKind::Pages,
        Some(t) if *t == keys::PAGE => NodeKind::Page,
        Some(_) => NodeKind::Other,
        None if dict.contains_key(keys::KIDS) => {
            log.report(
                DiagnosticKind::PageTree,
                format!("page tree: node {id} has /Kids but no /Type; read as /Pages"),
            );
            NodeKind::Pages
        }
        None => NodeKind::Page,
    }
}

/// Walks the page tree of the document in `store`, reporting what it repairs to `log`.
///
/// # Errors
/// - [`ErrorCode::LimitExceeded`]: the tree is deeper than `max_page_tree_depth`, or has more
///   nodes and pages than `max_objects`.
/// - The errors of [`Store::resolve`] and [`Store::deref`] (in lenient mode only
///   [`ErrorCode::LimitExceeded`]).
pub(crate) fn walk(store: &Store, log: &ModelLog) -> Result<PageTree> {
    let limits = store.limits();
    let max_depth = usize::from(limits.max_page_tree_depth);
    let max_nodes = usize::try_from(limits.max_objects).unwrap_or(usize::MAX);
    let mut tree = PageTree::default();

    let Some(root_id) = store.root_id() else {
        log.report(
            DiagnosticKind::PageTree,
            "page tree: the trailer has no /Root; the document has no pages",
        );
        return Ok(tree);
    };
    let catalog = crate::resolve(store, root_id)?;
    let Some(catalog) = catalog.as_dict() else {
        log.report(
            DiagnosticKind::PageTree,
            "page tree: the catalog is not a dictionary; the document has no pages",
        );
        return Ok(tree);
    };
    // §7.7.2: /Pages is required and shall be an indirect reference.
    let pages_root = match catalog.get(keys::PAGES) {
        Some(Object::Ref(id)) => *id,
        Some(other) => {
            log.report(
                DiagnosticKind::PageTree,
                format!(
                    "page tree: the catalog's /Pages is {}, not an indirect reference; the \
                 document has no pages",
                    crate::type_phrase(other)
                ),
            );
            return Ok(tree);
        }
        None => {
            log.report(
                DiagnosticKind::PageTree,
                "page tree: the catalog has no /Pages; the document has no pages",
            );
            return Ok(tree);
        }
    };

    // The intermediate nodes reached so far: a node is walked once, which bounds the walk and
    // stops cycles. Pages are not in it, since a page listed twice is two pages.
    let mut visited: HashSet<ObjectId> = HashSet::new();
    visited.insert(pages_root);
    // The index of each page's first listing, to report a page listed again.
    let mut first_index: HashMap<ObjectId, usize> = HashMap::new();
    let root = crate::resolve(store, pages_root)?;
    let Some(root_dict) = root.as_dict() else {
        log.report(
            DiagnosticKind::PageTree,
            format!(
                "page tree: the root {pages_root} is {}, not a dictionary; the document has no \
             pages",
                crate::type_phrase(&root)
            ),
        );
        return Ok(tree);
    };
    // Declared /Count per node, checked against the leaves once the walk is done.
    let mut declared: Vec<Option<i64>> = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    match classify(root_dict, pages_root, log) {
        NodeKind::Pages => {
            tree.nodes.push(TreeEntry {
                id: pages_root,
                parent: None,
            });
            declared.push(count_of(store, root_dict)?);
            stack.push(Frame {
                node: 0,
                kids: kids_of(store, root_dict, pages_root, log)?,
                next: 0,
            });
        }
        NodeKind::Page => {
            log.report(
                DiagnosticKind::PageTree,
                format!(
                    "page tree: the root {pages_root} is a page, not a /Pages node; read as a \
                 one-page document"
                ),
            );
            tree.pages.push(TreeEntry {
                id: pages_root,
                parent: None,
            });
        }
        NodeKind::Other => {
            log.report(DiagnosticKind::PageTree, format!(
                "page tree: the root {pages_root} is neither /Pages nor /Page; the document has \
                 no pages"
            ));
        }
    }

    while let Some(frame) = stack.last_mut() {
        let Some(kid) = frame.kids.get(frame.next) else {
            stack.pop();
            continue;
        };
        frame.next += 1;
        let parent = frame.node;
        let parent_id = tree.nodes.get(parent).map_or(pages_root, |n| n.id);

        let Object::Ref(kid_id) = *kid else {
            log.report(
                DiagnosticKind::PageTree,
                format!(
                    "page tree: node {parent_id} lists {} among its /Kids, not an indirect \
                 reference; skipped",
                    crate::type_phrase(kid)
                ),
            );
            continue;
        };
        // A node seen before is not resolved again (it may be the root, or a node on the stack).
        if visited.contains(&kid_id) {
            log.report(
                DiagnosticKind::PageTree,
                format!(
                    "page tree: node {kid_id} appears more than once (a cycle, or a node listed \
                 by two nodes); skipped under node {parent_id}"
                ),
            );
            continue;
        }
        if tree.nodes.len() + tree.pages.len() >= max_nodes {
            return Err(Error::limit(
                LimitKind::MaxObjects,
                u64::from(limits.max_objects),
                None,
            ));
        }
        let object = crate::resolve(store, kid_id)?;
        let Some(dict) = object.as_dict() else {
            log.report(
                DiagnosticKind::PageTree,
                format!(
                    "page tree: kid {kid_id} of node {parent_id} is {}, not a dictionary; skipped",
                    crate::type_phrase(&object)
                ),
            );
            continue;
        };
        if dict.get_ref(keys::PARENT) != Some(parent_id) {
            log.report(
                DiagnosticKind::PageTree,
                format!(
                    "page tree: the /Parent of {kid_id} is not {parent_id}, the node that lists it"
                ),
            );
        }
        match classify(dict, kid_id, log) {
            NodeKind::Page => {
                let index = tree.pages.len();
                match first_index.entry(kid_id) {
                    Entry::Vacant(slot) => {
                        slot.insert(index);
                    }
                    Entry::Occupied(first) => log.report(
                        DiagnosticKind::PageTree,
                        format!(
                            "page tree: page {kid_id} is listed more than once; listed again \
                             under node {parent_id}, it is page {index} as well as page {}",
                            first.get()
                        ),
                    ),
                }
                tree.pages.push(TreeEntry {
                    id: kid_id,
                    parent: Some(parent),
                });
            }
            NodeKind::Pages => {
                visited.insert(kid_id);
                // The root is at depth 1; `stack` holds the nodes above this one.
                if stack.len() >= max_depth {
                    return Err(Error::limit(
                        LimitKind::MaxPageTreeDepth,
                        u64::from(limits.max_page_tree_depth),
                        None,
                    ));
                }
                let node = tree.nodes.len();
                tree.nodes.push(TreeEntry {
                    id: kid_id,
                    parent: Some(parent),
                });
                declared.push(count_of(store, dict)?);
                let kids = kids_of(store, dict, kid_id, log)?;
                stack.push(Frame {
                    node,
                    kids,
                    next: 0,
                });
            }
            NodeKind::Other => {
                let ty = dict
                    .get_name(keys::TYPE)
                    .map(ToString::to_string)
                    .unwrap_or_default();
                log.report(DiagnosticKind::PageTree, format!(
                    "page tree: kid {kid_id} of node {parent_id} has /Type {ty}, neither /Pages \
                     nor /Page; skipped"
                ));
            }
        }
    }

    check_counts(&tree, &declared, log);
    Ok(tree)
}

/// The `/Kids` of a `/Pages` node (§7.7.3.2), following an indirect array.
fn kids_of(store: &Store, dict: &Dict, id: ObjectId, log: &ModelLog) -> Result<Vec<Object>> {
    let Some(kids) = dict.get(keys::KIDS) else {
        log.report(
            DiagnosticKind::PageTree,
            format!("page tree: node {id} has no /Kids"),
        );
        return Ok(Vec::new());
    };
    let kids = store.deref(kids)?;
    match kids.as_array() {
        Some(kids) => Ok(kids.to_vec()),
        None => {
            if !kids.is_null() {
                log.report(
                    DiagnosticKind::PageTree,
                    format!(
                        "page tree: the /Kids of node {id} is {}, not an array",
                        crate::type_phrase(&kids)
                    ),
                );
            } else {
                log.report(
                    DiagnosticKind::PageTree,
                    format!("page tree: node {id} has no /Kids"),
                );
            }
            Ok(Vec::new())
        }
    }
}

/// The `/Count` of a `/Pages` node, following a reference; `None` when it is not an integer.
fn count_of(store: &Store, dict: &Dict) -> Result<Option<i64>> {
    match dict.get(keys::COUNT) {
        Some(count) => Ok(store.deref(count)?.as_int()),
        None => Ok(None),
    }
}

/// Reports every node whose `/Count` differs from the number of pages the walk found under it
/// (§7.7.3.2: `/Count` is the number of leaf nodes that are descendants of the node).
fn check_counts(tree: &PageTree, declared: &[Option<i64>], log: &ModelLog) {
    // Each page counts for the node that lists it; then, since a node is recorded before its
    // descendants (pre-order), adding the nodes' totals to their parents from the last node
    // back gives every node its whole subtree: O(nodes + pages).
    let mut found = vec![0u64; tree.nodes.len()];
    for page in &tree.pages {
        if let Some(count) = page.parent.and_then(|i| found.get_mut(i)) {
            *count += 1;
        }
    }
    for (i, node) in tree.nodes.iter().enumerate().rev() {
        let Some(parent) = node.parent.filter(|&p| p < i) else {
            continue;
        };
        let subtotal = found.get(i).copied().unwrap_or(0);
        if let Some(count) = found.get_mut(parent) {
            *count += subtotal;
        }
    }
    for ((node, declared), found) in tree.nodes.iter().zip(declared).zip(found) {
        let what = if node.parent.is_none() {
            "the page tree root"
        } else {
            "node"
        };
        match declared {
            Some(count) if u64::try_from(*count).ok() == Some(found) => {}
            Some(count) => log.report(
                DiagnosticKind::PageTree,
                format!(
                    "page tree: {what} {} has /Count {count} but {found} pages; the pages found \
                 are used",
                    node.id
                ),
            ),
            None => log.report(
                DiagnosticKind::PageTree,
                format!(
                    "page tree: {what} {} has no integer /Count ({found} pages found)",
                    node.id
                ),
            ),
        }
    }
}

/// The error for a page index past the end.
pub(crate) fn out_of_range(index: usize, count: usize) -> Error {
    Error::new(
        ErrorCode::PageOutOfRange,
        format!("page index {index} is out of range: the document has {count} pages"),
    )
}

//! [`Document`]: a PDF document, built on the syntax layer's [`Store`].
//!
//! This module has the read side; [`edit`] has the write side (new documents, the Info
//! dictionary, page setters, saving).

mod edit;

use std::sync::{Arc, OnceLock};

use folioxide_syntax::{
    Diagnostic, DiagnosticKind, Error, ErrorCode, Object, OpenOptions, Result, SharedBytes, Store,
    keys,
};

use crate::diag::ModelLog;
use crate::info::{self, DocInfo};
use crate::page::{Page, PageId};
use crate::page_tree::{self, PageTree};

/// A PDF document: the object [`Store`] plus the document model on top of it (catalog, page
/// tree, pages, metadata).
///
/// `Document` is `Send + Sync + 'static`: read accessors take `&self` and can run on several
/// threads at once (the store resolves objects lazily and caches them; the page-tree walk runs
/// once and is cached).
///
/// # Editing and saving
/// Edits take `&mut self`: [`Document::set_info`], the page setters
/// ([`Document::set_media_box`], [`Document::set_crop_box`], [`Document::set_rotation`]), and
/// any object edit through [`Document::store_mut`] (which drops the cached walk, since the
/// caller may change the page tree; the setters keep it, see their module). A new document
/// starts from [`Document::new`]. [`Document::save`] writes the whole file again;
/// [`Document::save_incremental`] appends the edits to the original bytes (§7.5.6).
///
/// # Leniency
/// The [`OpenOptions::strictness`] policy applies to the syntax layer: what [`Store::resolve`]
/// repairs or refuses. What the model finds wrong one level up (a wrong page-tree `/Count`, a
/// page tree cycle, a page without a media box, an Info entry of the wrong type) is repaired
/// with a [`Diagnostic`] in both modes, because most model accessors (such as
/// [`Page::media_box`]) have no error channel. Exceeding a [`Limits`] value is an error in both
/// modes.
///
/// ```
/// use folioxide_model::{Document, Rotation};
/// use folioxide_syntax::OpenOptions;
///
/// # fn build(objects: &[&str]) -> Vec<u8> {
/// #     let mut out = b"%PDF-1.7\n".to_vec();
/// #     let mut offsets = Vec::new();
/// #     for (i, body) in objects.iter().enumerate() {
/// #         offsets.push(out.len());
/// #         out.extend(format!("{} 0 obj\n{body}\nendobj\n", i + 1).bytes());
/// #     }
/// #     let xref = out.len();
/// #     out.extend(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).bytes());
/// #     for offset in offsets {
/// #         out.extend(format!("{offset:010} 00000 n \n").bytes());
/// #     }
/// #     let trailer = format!("/Size {} /Root 1 0 R /Info 4 0 R", objects.len() + 1);
/// #     out.extend(format!("trailer\n<< {trailer} >>\nstartxref\n{xref}\n%%EOF\n").bytes());
/// #     out
/// # }
/// // A4 landscape: an A4 media box inherited from the page tree, and a rotated page.
/// let pdf = build(&[
///     "<< /Type /Catalog /Pages 2 0 R >>",
///     "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595 842] >>",
///     "<< /Type /Page /Parent 2 0 R /Rotate 90 >>",
///     "<< /Title (Example) >>",
/// ]);
/// let doc = Document::open(pdf, &OpenOptions::default())?;
/// assert_eq!(doc.version(), (1, 7));
/// assert_eq!(doc.page_count()?, 1);
/// let page = doc.page(0)?;
/// assert_eq!(page.media_box().width(), 595.0);
/// assert_eq!(page.rotation(), Rotation::R90);
/// assert_eq!(page.effective_size(), (842.0, 595.0));
/// assert_eq!(doc.info()?.title.as_deref(), Some("Example"));
/// # Ok::<(), folioxide_syntax::Error>(())
/// ```
///
/// [`Limits`]: folioxide_syntax::Limits
pub struct Document {
    store: Store,
    /// The page-tree walk, done on first use; reset by [`Document::store_mut`] and by edits of
    /// the catalog or a page-tree node.
    page_tree: OnceLock<std::result::Result<Arc<PageTree>, Error>>,
    /// The model's diagnostics (the store keeps its own).
    log: ModelLog,
}

impl std::fmt::Debug for Document {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pages = match self.page_tree.get() {
            Some(Ok(tree)) => Some(tree.pages.len()),
            _ => None,
        };
        f.debug_struct("Document")
            .field("store", &self.store)
            .field("pages", &pages)
            .finish_non_exhaustive()
    }
}

impl Document {
    /// Opens a PDF file held in a vector.
    ///
    /// Opening reads the file's structure only (see [`Store::open`]); pages and metadata are
    /// read when they are first asked for.
    ///
    /// # Errors
    /// The errors of [`Store::open`] (for example [`ErrorCode::Xref`] when no catalog can be
    /// found, [`ErrorCode::PasswordRequired`] for an encrypted file).
    pub fn open(bytes: Vec<u8>, options: &OpenOptions) -> Result<Document> {
        Self::from_store(Store::open_bytes(bytes, options)?)
    }

    /// Opens a PDF file held in shared bytes (a memory map, or a buffer shared with the
    /// caller); see [`Document::open`].
    ///
    /// # Errors
    /// See [`Document::open`].
    pub fn open_shared(source: SharedBytes, options: &OpenOptions) -> Result<Document> {
        Self::from_store(Store::open(source, options)?)
    }

    /// Wraps a store as a document.
    ///
    /// # Errors
    /// - [`ErrorCode::Xref`]: the trailer has no `/Root` (§7.5.5).
    /// - [`ErrorCode::TypeMismatch`]: the catalog `/Root` refers to is not a dictionary
    ///   (§7.7.2).
    /// - The errors of [`Store::deref`].
    pub fn from_store(store: Store) -> Result<Document> {
        let Some(root) = store.root_id() else {
            return Err(Error::new(
                ErrorCode::Xref,
                "the trailer has no /Root: there is no document catalog",
            ));
        };
        let catalog = crate::resolve(&store, root)?;
        if catalog.as_dict().is_none() {
            return Err(Error::type_mismatch("dictionary", catalog.type_name()));
        }
        let log = ModelLog::new(store.limits().max_diagnostics);
        Ok(Document {
            store,
            page_tree: OnceLock::new(),
            log,
        })
    }

    /// The object store.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The object store, mutably, for edits. Drops the cached page-tree walk, since an edit
    /// may change the page tree.
    pub fn store_mut(&mut self) -> &mut Store {
        self.page_tree = OnceLock::new();
        &mut self.store
    }

    /// The object store, giving up the document.
    pub fn into_store(self) -> Store {
        self.store
    }

    /// The diagnostics recorded so far: the store's (opening, resolving, decoding), then the
    /// document model's (page tree, page attributes, metadata), each oldest first and each
    /// bounded by [`Limits::max_diagnostics`](folioxide_syntax::Limits::max_diagnostics).
    ///
    /// Diagnostics accumulate as the document is read. The model's are recorded once each,
    /// however often the accessor that found them runs.
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        let mut out = self.store.diagnostics();
        out.extend(self.log.snapshot());
        out
    }

    /// The number of diagnostics that were not kept because a log was full.
    pub fn dropped_diagnostics(&self) -> u64 {
        self.store
            .dropped_diagnostics()
            .saturating_add(self.log.dropped())
    }

    pub(crate) fn log(&self) -> &ModelLog {
        &self.log
    }

    /// The PDF version: the `%PDF-` header's, or the catalog's `/Version` when that is later
    /// (§7.7.2: an incremental update cannot rewrite the header, so it raises the version
    /// there).
    ///
    /// A `/Version` that is not a name of the form `M.m` is ignored with a diagnostic.
    pub fn version(&self) -> (u8, u8) {
        let header = self.store.version();
        let catalog = match self.catalog() {
            Ok(catalog) => catalog,
            Err(err) => {
                self.log.report(
                    DiagnosticKind::Catalog,
                    format!("version: reading the catalog: {err}"),
                );
                return header;
            }
        };
        let Some(value) = catalog.as_dict().and_then(|d| d.get(keys::VERSION)) else {
            return header;
        };
        let value = match self.store.deref(value) {
            Ok(value) => value,
            Err(err) => {
                self.log.report(
                    DiagnosticKind::Catalog,
                    format!("version: reading the catalog's /Version: {err}"),
                );
                return header;
            }
        };
        match value.as_name().and_then(|n| parse_version(n.as_bytes())) {
            Some(version) => version.max(header),
            None if value.is_null() => header,
            None => {
                self.log.report(
                    DiagnosticKind::Catalog,
                    format!(
                        "version: the catalog's /Version is not a version name ({value:?}); the \
                     header's {}.{} is used",
                        header.0, header.1
                    ),
                );
                header
            }
        }
    }

    /// The document catalog (§7.7.2), the dictionary the trailer's `/Root` refers to.
    ///
    /// # Errors
    /// - [`ErrorCode::Xref`]: the trailer has no `/Root`.
    /// - The errors of [`Store::deref`].
    pub fn catalog(&self) -> Result<Arc<Object>> {
        let root = self.store.root_id().ok_or_else(|| {
            Error::new(
                ErrorCode::Xref,
                "the trailer has no /Root: there is no document catalog",
            )
        })?;
        crate::resolve(&self.store, root)
    }

    /// The page-tree walk, done once and cached.
    fn page_tree(&self) -> Result<Arc<PageTree>> {
        self.page_tree
            .get_or_init(|| page_tree::walk(&self.store, &self.log).map(Arc::new))
            .clone()
    }

    /// The number of pages: the pages the page-tree walk reaches, not the root's `/Count`
    /// (a `/Count` that disagrees gives a diagnostic).
    ///
    /// # Errors
    /// - [`ErrorCode::LimitExceeded`]: the page tree is deeper than
    ///   [`Limits::max_page_tree_depth`](folioxide_syntax::Limits::max_page_tree_depth).
    /// - The errors of [`Store::deref`].
    pub fn page_count(&self) -> Result<usize> {
        Ok(self.page_tree()?.pages.len())
    }

    /// The handles of all pages, in page order.
    ///
    /// A page object that the page tree lists more than once is a page at each place it is
    /// listed (with a diagnostic), as poppler, pypdf and qpdf read it, so its handle appears
    /// more than once; an edit of that page shows at each of its indices.
    ///
    /// # Errors
    /// See [`Document::page_count`].
    pub fn page_ids(&self) -> Result<Vec<PageId>> {
        Ok(self
            .page_tree()?
            .pages
            .iter()
            .map(|p| PageId(p.id))
            .collect())
    }

    /// The 0-based index of the page `id`, or `None` when it is not a page of this document.
    /// For a page the page tree lists more than once, the index of its first listing.
    ///
    /// # Errors
    /// See [`Document::page_count`].
    pub fn page_index(&self, id: PageId) -> Result<Option<usize>> {
        Ok(self.page_tree()?.pages.iter().position(|p| p.id == id.0))
    }

    /// The page at 0-based `index`.
    ///
    /// # Errors
    /// - [`ErrorCode::PageOutOfRange`]: `index` is not less than [`Document::page_count`].
    /// - See [`Document::page_count`].
    pub fn page(&self, index: usize) -> Result<Page<'_>> {
        let tree = self.page_tree()?;
        let Some(entry) = tree.pages.get(index) else {
            return Err(page_tree::out_of_range(index, tree.pages.len()));
        };
        Ok(Page::new(self, index, entry.id, tree.ancestors(index)))
    }

    /// The document information dictionary (§14.3.3), decoded; empty when the document has
    /// none.
    ///
    /// # Errors
    /// The errors of [`Store::deref`].
    pub fn info(&self) -> Result<DocInfo> {
        info::read(&self.store, &self.log)
    }
}

/// Parses a version name such as `1.7` or `2.0` (§7.7.2).
fn parse_version(name: &[u8]) -> Option<(u8, u8)> {
    let text = std::str::from_utf8(name).ok()?;
    let (major, minor) = text.split_once('.')?;
    let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !all_digits(major) || !all_digits(minor) {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_names() {
        assert_eq!(parse_version(b"1.7"), Some((1, 7)));
        assert_eq!(parse_version(b"2.0"), Some((2, 0)));
        assert_eq!(parse_version(b"1"), None);
        assert_eq!(parse_version(b"1."), None);
        assert_eq!(parse_version(b"1.x"), None);
        assert_eq!(parse_version(b"-1.7"), None);
        assert_eq!(parse_version(b"1.700"), None);
    }
}

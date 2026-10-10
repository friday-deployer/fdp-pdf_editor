//! The write side of [`Document`] (M2 brief WP2.3): new documents, the document information
//! dictionary, page boxes and rotation, and saving.
//!
//! Every edit goes through the [`Store`]'s edit layer, so a document can then be saved as a full
//! rewrite ([`Document::save`]) or as an incremental update that leaves the original bytes
//! untouched ([`Document::save_incremental`]). The setters write only what changes: setting a
//! value a page or the Info dictionary already has edits nothing, so an incremental update stays
//! as small as the change.
//!
//! The cached page-tree walk is invalidated precisely: the setters here edit only keys the walk
//! does not read (`/MediaBox`, `/CropBox` and `/Rotate` of a page, Info entries), so the cache
//! survives them, unless an edited object is the catalog or a node of the page tree (an Info
//! dictionary that is also a page-tree node, in a hostile file). [`Document::store_mut`], which
//! cannot know what the caller will change, still drops the cache.

use std::sync::OnceLock;

use folioxide_syntax::{
    DiagnosticKind, Dict, Error, IncrementalOptions, Object, ObjectId, Result, SaveOptions, Store,
    keys,
};

use super::Document;
use crate::diag::ModelLog;
use crate::info::InfoUpdate;
use crate::page::{CROP_BOX, ROTATE, Rect, Rotation, Scope};

/// The header version of a document made by [`Document::new`].
const NEW_DOCUMENT_VERSION: (u8, u8) = (1, 7);

impl Default for Document {
    /// The same as [`Document::new`].
    fn default() -> Self {
        Document::new()
    }
}

impl Document {
    /// A new, empty PDF 1.7 document: a catalog (§7.7.2) and a page tree with no pages
    /// (`<< /Type /Pages /Kids [] /Count 0 >>`, §7.7.3.2), and no Info dictionary.
    ///
    /// The document has no source file, so it can only be saved with [`Document::save`]
    /// (an incremental update needs a file to append to). Saved as it is, it has zero pages,
    /// which ISO 32000 does not forbid (§7.7.3.2: `/Count` is the number of leaves below the
    /// node) but readers treat differently: qpdf (pikepdf 10.16 `check_pdf_syntax`, no
    /// warnings) and pypdf (6.20, strict mode) open it with 0 pages, while poppler's `pdfinfo`
    /// (24.02) refuses it ("Syntax Error: Invalid page count 0", exit code 99), as poppler
    /// refuses every file without a page. Page insertion arrives in M5.
    ///
    /// ```
    /// use folioxide_model::{Document, InfoUpdate};
    /// use folioxide_syntax::{OpenOptions, SaveOptions};
    ///
    /// let mut doc = Document::new();
    /// assert_eq!(doc.page_count()?, 0);
    /// assert_eq!(doc.version(), (1, 7));
    /// doc.set_info(&InfoUpdate::default().with_title(Some("Empty")))?;
    ///
    /// let pdf = doc.save(&SaveOptions::default())?;
    /// assert!(pdf.starts_with(b"%PDF-1.7"));
    /// let reopened = Document::open(pdf, &OpenOptions::default())?;
    /// assert_eq!(reopened.page_count()?, 0);
    /// assert_eq!(reopened.info()?.title.as_deref(), Some("Empty"));
    /// assert!(reopened.diagnostics().is_empty());
    /// # Ok::<(), folioxide_syntax::Error>(())
    /// ```
    pub fn new() -> Document {
        // `Store::add` fails only when the object number reaches `Limits::max_objects`; a new
        // store numbers these two objects 1 and 2, so this never falls back. The fallback (a
        // store without a catalog) only avoids a panic path in library code.
        let store =
            empty_document_store().unwrap_or_else(|_| Store::new_empty(NEW_DOCUMENT_VERSION));
        let log = ModelLog::new(store.limits().max_diagnostics);
        Document {
            store,
            page_tree: OnceLock::new(),
            log,
        }
    }

    /// Whether the document was edited since it was opened (or, for [`Document::new`], whether
    /// it has objects not saved yet): see [`Store::is_modified`].
    pub fn is_modified(&self) -> bool {
        self.store.is_modified()
    }

    // ---- saving -------------------------------------------------------------------------------

    /// Writes the whole document again: a full rewrite with garbage collection, renumbering and
    /// a fresh cross-reference section, as [`folioxide_syntax::writer::save`] describes.
    ///
    /// A full save is also the way to a clean file when opening repaired the structure (which
    /// [`Document::save_incremental`] refuses to append to): its output takes updates.
    ///
    /// ```
    /// use folioxide_model::{Document, InfoUpdate};
    /// use folioxide_syntax::{ErrorCode, IncrementalOptions, OpenOptions, SaveOptions};
    ///
    /// // A file without a cross-reference table: the store finds its objects with a scan.
    /// let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
    /// 2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>\nendobj\n\
    /// 3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";
    /// let mut doc = Document::open(pdf.to_vec(), &OpenOptions::default())?;
    /// doc.set_info(&InfoUpdate::default().with_title(Some("Rewritten")))?;
    /// let refused = doc.save_incremental(&IncrementalOptions::default()).unwrap_err();
    /// assert_eq!(refused.code(), ErrorCode::Unsupported);
    ///
    /// // Object streams make the file smaller; they need PDF 1.5 and a cross-reference stream.
    /// let saved = doc.save(&SaveOptions::default().with_object_streams(true))?;
    /// assert!(saved.starts_with(b"%PDF-1.5"));
    /// let reopened = Document::open(saved, &OpenOptions::default())?;
    /// assert!(!reopened.store().structure_repaired());
    /// assert_eq!(reopened.page_count()?, 1);
    /// assert_eq!(reopened.info()?.title.as_deref(), Some("Rewritten"));
    /// # Ok::<(), folioxide_syntax::Error>(())
    /// ```
    ///
    /// # Errors
    /// The errors of [`folioxide_syntax::writer::save`].
    pub fn save(&self, options: &SaveOptions) -> Result<Vec<u8>> {
        self.store.save(options)
    }

    /// The original file followed by an incremental update with the edits (§7.5.6): the
    /// original bytes stay byte for byte untouched (see
    /// [`folioxide_syntax::writer::save_incremental`]). Without edits, the original bytes.
    ///
    /// ```
    /// use folioxide_model::{Document, InfoUpdate, Rotation};
    /// use folioxide_syntax::{ErrorCode, IncrementalOptions, OpenOptions};
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
    /// #     let trailer = format!("/Size {} /Root 1 0 R", objects.len() + 1);
    /// #     out.extend(format!("trailer\n<< {trailer} >>\nstartxref\n{xref}\n%%EOF\n").bytes());
    /// #     out
    /// # }
    /// // A one-page file with a cross-reference table (built by a hidden helper).
    /// let original = build(&[
    ///     "<< /Type /Catalog /Pages 2 0 R >>",
    ///     "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>",
    ///     "<< /Type /Page /Parent 2 0 R >>",
    /// ]);
    /// let mut doc = Document::open(original.clone(), &OpenOptions::default())?;
    /// doc.set_rotation(0, Rotation::R90)?;
    /// doc.set_info(&InfoUpdate::default().with_title(Some("Updated")))?;
    ///
    /// let pdf = doc.save_incremental(&IncrementalOptions::default())?;
    /// assert!(pdf.starts_with(&original)); // every original byte is kept
    /// let updated = Document::open(pdf, &OpenOptions::default())?;
    /// assert_eq!(updated.store().revisions().len(), 2);
    /// assert_eq!(updated.page(0)?.rotation(), Rotation::R90);
    /// assert_eq!(updated.info()?.title.as_deref(), Some("Updated"));
    ///
    /// // A new document has no file to append to.
    /// let err = Document::new().save_incremental(&IncrementalOptions::default()).unwrap_err();
    /// assert_eq!(err.code(), ErrorCode::InvalidArgument);
    /// # Ok::<(), folioxide_syntax::Error>(())
    /// ```
    ///
    /// # Errors
    /// The errors of [`folioxide_syntax::writer::save_incremental`], among them:
    /// - [`ErrorCode::InvalidArgument`](folioxide_syntax::ErrorCode::InvalidArgument): the
    ///   document has no source file ([`Document::new`]).
    /// - [`ErrorCode::Unsupported`](folioxide_syntax::ErrorCode::Unsupported): opening repaired
    ///   the file's structure ([`Store::structure_repaired`]); save it with [`Document::save`].
    pub fn save_incremental(&self, options: &IncrementalOptions) -> Result<Vec<u8>> {
        self.store.save_incremental(options)
    }

    /// Only the bytes [`Document::save_incremental`] appends to the original file, so that a
    /// caller holding the file (a Tauri app) can append them in place. Empty without edits.
    ///
    /// ```
    /// use folioxide_model::{Document, InfoUpdate};
    /// use folioxide_syntax::{IncrementalOptions, OpenOptions};
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
    /// #     let trailer = format!("/Size {} /Root 1 0 R", objects.len() + 1);
    /// #     out.extend(format!("trailer\n<< {trailer} >>\nstartxref\n{xref}\n%%EOF\n").bytes());
    /// #     out
    /// # }
    /// let original = build(&[
    ///     "<< /Type /Catalog /Pages 2 0 R >>",
    ///     "<< /Type /Pages /Kids [] /Count 0 >>",
    /// ]);
    /// let opts = IncrementalOptions::default();
    /// let unchanged = Document::open(original.clone(), &OpenOptions::default())?;
    /// assert!(unchanged.incremental_suffix(&opts)?.is_empty()); // nothing to append
    ///
    /// let mut doc = Document::open(original.clone(), &OpenOptions::default())?;
    /// doc.set_info(&InfoUpdate::default().with_title(Some("Appended")))?;
    /// let suffix = doc.incremental_suffix(&opts)?;
    /// // Appending the suffix to the file gives what save_incremental returns.
    /// let mut file = original;
    /// file.extend_from_slice(&suffix);
    /// assert_eq!(file, doc.save_incremental(&opts)?);
    /// # Ok::<(), folioxide_syntax::Error>(())
    /// ```
    ///
    /// # Errors
    /// See [`Document::save_incremental`].
    pub fn incremental_suffix(&self, options: &IncrementalOptions) -> Result<Vec<u8>> {
        self.store.incremental_suffix(options)
    }

    // ---- the Info dictionary ------------------------------------------------------------------

    /// Changes the document information dictionary (§14.3.3); see [`InfoUpdate`] for what each
    /// field does. Values are written as text strings
    /// ([`encode_text_string`](crate::text::encode_text_string)), dates as PDF date strings.
    ///
    /// - When the trailer's `/Info` refers to a dictionary, that object is changed in place
    ///   (an incremental update rewrites it with the same number).
    /// - Otherwise a new dictionary object is added and linked from the trailer's `/Info`: when
    ///   there was none, when `/Info` is a direct dictionary (§14.3.3 asks for an indirect
    ///   reference; its entries are kept), or when it is not a dictionary (it is replaced, with
    ///   a [`DiagnosticKind::Metadata`] diagnostic).
    /// - An update that changes nothing edits nothing (removing an entry the dictionary does not
    ///   have does not create one).
    ///
    /// `/ModDate` is not set automatically: the core has no clock, so the caller passes the
    /// modification time ([`InfoUpdate::mod_date`]).
    ///
    /// ```
    /// use folioxide_model::{Document, InfoUpdate, PdfDate};
    ///
    /// let mut doc = Document::new();
    /// let date = PdfDate::new(2026, 10, 10, 9, 30, 0).and_then(|d| d.with_offset(Some(120)));
    /// doc.set_info(
    ///     &InfoUpdate::default()
    ///         .with_title(Some("Отчёт")) // not in PDFDocEncoding: written as UTF-16BE
    ///         .with_mod_date(date),
    /// )?;
    /// let info = doc.info()?;
    /// assert_eq!(info.title.as_deref(), Some("Отчёт"));
    /// assert_eq!(info.mod_date, date);
    /// # Ok::<(), folioxide_syntax::Error>(())
    /// ```
    ///
    /// # Errors
    /// - [`ErrorCode::InvalidArgument`](folioxide_syntax::ErrorCode::InvalidArgument): a custom
    ///   key is a standard key, or a custom key that is set is empty, longer than 127 bytes or
    ///   holds a NUL character (see [`InfoUpdate::custom`]).
    /// - The errors of [`Store::resolve`] and [`Store::deref`] reading the current dictionary,
    ///   and [`ErrorCode::LimitExceeded`](folioxide_syntax::ErrorCode::LimitExceeded) from
    ///   [`Store::add`].
    pub fn set_info(&mut self, update: &InfoUpdate) -> Result<()> {
        update.validate()?;
        if update.is_empty() {
            return Ok(());
        }
        let current = self.store.trailer().get(keys::INFO).cloned();
        if let Some(Object::Ref(id)) = current {
            let object = self.store.resolve(id)?;
            if let Some(dict) = object.as_dict() {
                let mut dict = dict.clone();
                if update.apply(&mut dict) {
                    self.store.set(id, Object::Dict(dict))?;
                    self.invalidate_if_tree_object(id);
                }
                return Ok(());
            }
        }
        // No dictionary object to change in place: build a new one.
        let mut dict = match &current {
            None => Dict::new(),
            Some(value) => {
                let value = self.store.deref(value)?;
                match &*value {
                    Object::Dict(dict) => dict.clone(),
                    Object::Null => Dict::new(),
                    other => {
                        self.log.report(
                            DiagnosticKind::Metadata,
                            format!(
                                "info: the trailer's /Info is {}, not a dictionary; replaced by \
                                 a new Info dictionary",
                                crate::type_phrase(other)
                            ),
                        );
                        Dict::new()
                    }
                }
            }
        };
        if !update.apply(&mut dict) {
            return Ok(());
        }
        let id = self.store.add(Object::Dict(dict))?;
        self.store.set_trailer_entry(keys::INFO, Object::Ref(id))
    }

    // ---- page boxes and rotation --------------------------------------------------------------

    /// Sets the media box of the page at 0-based `index` (§7.7.3.3, §14.11.2).
    ///
    /// The box is written on the page object itself, never on the `/Pages` node the page may
    /// inherit it from, which would change the sibling pages too (§7.7.3.4): an inherited value
    /// is overridden on the page. When the page's crop box (its own or an inherited one)
    /// reaches outside the new media box, the crop box clipped to it is written on the page as
    /// well, so that every reader shows the same crop box (readers clip an oversized crop box
    /// differently). Setting the media box the page already has (as its own `/MediaBox`) edits
    /// nothing.
    ///
    /// The coordinates are rounded as they are written (at most 10 fractional digits, see
    /// [`folioxide_syntax::serialize::format_real`]), so [`Page::media_box`](crate::Page::media_box)
    /// returns what a reader of the saved file gets back: `0.1 + 0.2` becomes `0.3`.
    ///
    /// When a `/Parent` in the file disagrees with the page-tree node that lists the page,
    /// readers that inherit along `/Parent` (pdf.js, qpdf) may see another inherited crop box
    /// than the one read here (along the page tree, as poppler does); when that one reaches
    /// outside the new media box, the crop box read here is written on the page as well, so
    /// that every reader shows it.
    ///
    /// ```
    /// use folioxide_model::{Document, Rect};
    /// use folioxide_syntax::OpenOptions;
    ///
    /// # let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
    /// # 2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 595 842] >>\n\
    /// # endobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n\
    /// # 4 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";
    /// // Two A4 pages that inherit their media box from the page tree root.
    /// let mut doc = Document::open(pdf.to_vec(), &OpenOptions::default())?;
    /// let letter = Rect::new(0.0, 0.0, 612.0, 792.0);
    /// doc.set_media_box(0, letter)?;
    /// assert_eq!(doc.page(0)?.media_box(), letter);
    /// // The second page still inherits A4.
    /// assert_eq!(doc.page(1)?.media_box(), Rect::new(0.0, 0.0, 595.0, 842.0));
    /// # Ok::<(), folioxide_syntax::Error>(())
    /// ```
    ///
    /// # Errors
    /// - [`ErrorCode::InvalidArgument`](folioxide_syntax::ErrorCode::InvalidArgument): a
    ///   coordinate is not finite or is larger in magnitude than about `3.403e38`, or the box
    ///   has no area once its coordinates are rounded for writing (`[0 0 1e-12 1e-12]`).
    /// - [`ErrorCode::PageOutOfRange`](folioxide_syntax::ErrorCode::PageOutOfRange) and the
    ///   other errors of [`Document::page`]; the errors of [`Store::get_mut`].
    pub fn set_media_box(&mut self, index: usize, media_box: Rect) -> Result<()> {
        let media_box = checked_rect(media_box, "media box")?;
        let page = self.page(index)?;
        let id = page.id().object_id();
        if page.lookup_box(keys::MEDIA_BOX, Scope::Own) == Some(media_box) {
            return Ok(());
        }
        // The crop box as written, own or inherited, before it is clipped to the media box:
        // along the page tree (what we and poppler read), and along `/Parent` (pdf.js, qpdf).
        let own_crop = page.lookup_box(CROP_BOX, Scope::Own);
        let tree_inherited = page.lookup_box(CROP_BOX, Scope::Inherited);
        let parents_inherited = page.lookup_box(CROP_BOX, Scope::Parents);
        let crop = own_crop.or(tree_inherited);
        let parents_crop = own_crop.or(parents_inherited);
        let inherits_crop = tree_inherited.is_some() || parents_inherited.is_some();
        let outside = |crop: Option<Rect>| crop.is_some_and(|crop| !media_box.contains(&crop));
        let mut changes = vec![(keys::MEDIA_BOX, Some(media_box.to_object()))];
        if outside(crop) || (parents_crop != crop && outside(parents_crop)) {
            let clipped = crop
                .and_then(|crop| crop.intersect(&media_box))
                .and_then(|clipped| clipped.checked());
            let change = match clipped {
                Some(clipped) => Some(clipped.to_object()),
                // No crop box, or no overlap: the crop box is the media box (§14.11.2 default).
                None => default_crop_box(inherits_crop, &media_box),
            };
            changes.push((CROP_BOX, change));
        }
        self.edit_page(id, &changes)
    }

    /// Sets (`Some`) or removes (`None`) the crop box of the page at 0-based `index`
    /// (§7.7.3.3, §14.11.2).
    ///
    /// - `Some(rect)`: the box clipped to the page's media box is written on the page object
    ///   itself (an inherited crop box is overridden on the page, never changed on the `/Pages`
    ///   node, §7.7.3.4).
    /// - `None`: the page's crop box becomes its media box, the default. Its own `/CropBox` is
    ///   removed; when it would then inherit one from a `/Pages` node, the media box is written
    ///   as its `/CropBox` instead.
    ///
    /// When the page has no valid media box anywhere (readers assume US Letter, see
    /// [`Page::media_box`](crate::Page::media_box)), that US Letter media box is written on the
    /// page too, since §7.7.3.3 requires one and the crop box is clipped to it. Setting the crop
    /// box the page already has edits nothing. The coordinates are rounded as they are written
    /// (see [`Document::set_media_box`]).
    ///
    /// When a `/Parent` in the file disagrees with the page-tree node that lists the page,
    /// readers that inherit along `/Parent` (pdf.js; qpdf for the crop box) may inherit other
    /// values than those read here (along the page tree, as poppler does). A crop box inherited
    /// along either
    /// path counts: `None` then writes the media box as the page's `/CropBox`. When the page
    /// inherits its media box and the two paths give different ones, the media box read here
    /// is written on the page as well, so that every reader clips the crop box alike.
    ///
    /// ```
    /// use folioxide_model::{Document, Rect};
    /// use folioxide_syntax::OpenOptions;
    ///
    /// # let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
    /// # 2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 595 842] \
    /// # /CropBox [20 20 575 822] >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n\
    /// # 4 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";
    /// // Two A4 pages that inherit the crop box [20 20 575 822] from the page tree root.
    /// let mut doc = Document::open(pdf.to_vec(), &OpenOptions::default())?;
    /// let inherited = Rect::new(20.0, 20.0, 575.0, 822.0);
    ///
    /// // The new crop box is clipped to the media box and written on the first page only.
    /// doc.set_crop_box(0, Some(Rect::new(-50.0, 100.0, 400.0, 900.0)))?;
    /// assert_eq!(doc.page(0)?.crop_box(), Rect::new(0.0, 100.0, 400.0, 842.0));
    /// assert_eq!(doc.page(1)?.crop_box(), inherited);
    ///
    /// // Removing it gives the default, the media box, although the root has a crop box.
    /// doc.set_crop_box(0, None)?;
    /// assert_eq!(doc.page(0)?.crop_box(), doc.page(0)?.media_box());
    /// assert_eq!(doc.page(1)?.crop_box(), inherited);
    /// # Ok::<(), folioxide_syntax::Error>(())
    /// ```
    ///
    /// # Errors
    /// - [`ErrorCode::InvalidArgument`](folioxide_syntax::ErrorCode::InvalidArgument): a
    ///   coordinate is not finite or is too large, the box has no area once rounded for
    ///   writing, or it does not overlap the media box.
    /// - See [`Document::set_media_box`].
    pub fn set_crop_box(&mut self, index: usize, crop_box: Option<Rect>) -> Result<()> {
        let crop_box = crop_box
            .map(|rect| checked_rect(rect, "crop box"))
            .transpose()?;
        let page = self.page(index)?;
        let id = page.id().object_id();
        let own_media = page.lookup_box(keys::MEDIA_BOX, Scope::Own);
        let found_media = own_media.or_else(|| page.lookup_box(keys::MEDIA_BOX, Scope::Inherited));
        let media = page.media_box();
        let inherits_crop = page.lookup_box(CROP_BOX, Scope::Inherited).is_some()
            || page.lookup_box(CROP_BOX, Scope::Parents).is_some();
        let mut changes = Vec::new();
        if own_media.is_none()
            && (found_media.is_none()
                || page.lookup_box(keys::MEDIA_BOX, Scope::Parents) != found_media)
        {
            changes.push((keys::MEDIA_BOX, Some(media.to_object())));
        }
        let crop = match crop_box {
            Some(rect) => {
                // Clipped, then rounded again: the clipped box takes coordinates from the media
                // box, which the file may give with more digits than are written.
                let clipped = rect
                    .intersect(&media)
                    .and_then(|clipped| clipped.checked())
                    .ok_or_else(|| {
                        Error::invalid_argument(format!(
                            "the crop box {rect:?} does not overlap the media box {media:?} of \
                             page {index}"
                        ))
                    })?;
                Some(clipped.to_object())
            }
            None => default_crop_box(inherits_crop, &media),
        };
        changes.push((CROP_BOX, crop));
        self.edit_page(id, &changes)
    }

    /// Sets the rotation of the page at 0-based `index` (§7.7.3.3, `/Rotate`).
    ///
    /// The value is written on the page object itself, overriding an inherited `/Rotate` on the
    /// page (§7.7.3.4) without changing the `/Pages` node it comes from. Nothing is edited when
    /// the page's own `/Rotate` already has this value, or when the rotation is
    /// [`Rotation::R0`] and neither the page nor an ancestor has a `/Rotate`. The ancestors are
    /// both the page-tree nodes above the page (what poppler and this crate inherit from) and
    /// the nodes its `/Parent` chain reaches (what pdf.js and qpdf inherit from): they differ
    /// when a `/Parent` in the file is wrong, and then `/Rotate 0` is written whenever either
    /// has a `/Rotate`, so that every reader shows the page upright.
    ///
    /// ```
    /// use folioxide_model::{Document, Rotation};
    /// use folioxide_syntax::{ErrorCode, OpenOptions};
    ///
    /// # let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
    /// # 2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 595 842] \
    /// # /Rotate 90 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n\
    /// # 4 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";
    /// // Two pages that inherit /Rotate 90 from the page tree root.
    /// let mut doc = Document::open(pdf.to_vec(), &OpenOptions::default())?;
    /// doc.set_rotation(0, Rotation::R0)?; // written on the first page, overriding the root
    /// assert_eq!(doc.page(0)?.rotation(), Rotation::R0);
    /// assert_eq!(doc.page(1)?.rotation(), Rotation::R90);
    ///
    /// // Any multiple of 90 degrees converts, negative ones included.
    /// doc.set_rotation(1, Rotation::try_from(-90)?)?;
    /// assert_eq!(doc.page(1)?.rotation(), Rotation::R270);
    /// assert_eq!(doc.page(1)?.effective_size(), (842.0, 595.0));
    ///
    /// let err = doc.set_rotation(2, Rotation::R0).unwrap_err();
    /// assert_eq!(err.code(), ErrorCode::PageOutOfRange);
    /// # Ok::<(), folioxide_syntax::Error>(())
    /// ```
    ///
    /// # Errors
    /// [`ErrorCode::PageOutOfRange`](folioxide_syntax::ErrorCode::PageOutOfRange) and the
    /// other errors of [`Document::page`]; the errors of [`Store::get_mut`].
    pub fn set_rotation(&mut self, index: usize, rotation: Rotation) -> Result<()> {
        let page = self.page(index)?;
        let id = page.id().object_id();
        let own = page.own_entry(ROTATE);
        let value = Object::Int(i64::from(rotation.degrees()));
        if own.as_ref() == Some(&value) {
            return Ok(());
        }
        if own.is_none() && rotation == Rotation::R0 {
            let inherits = page.rotation_in(Scope::Inherited).is_some()
                || page.rotation_in(Scope::Parents).is_some();
            if !inherits {
                // 0 is the default (§7.7.3.3): every reader already shows the page upright.
                return Ok(());
            }
        }
        self.edit_page(id, &[(ROTATE, Some(value))])
    }

    /// Applies `changes` (`Some` sets the key, `None` removes it) to the page object `id`,
    /// skipping those that change nothing, so that an unchanged page is not rewritten.
    ///
    /// The page-tree walk reads none of the keys the setters change (`/MediaBox`, `/CropBox`,
    /// `/Rotate`), so the cached walk stays valid.
    fn edit_page(&mut self, id: ObjectId, changes: &[(&[u8], Option<Object>)]) -> Result<()> {
        let current = crate::resolve(&self.store, id)?;
        let Some(dict) = current.as_dict() else {
            return Err(Error::type_mismatch("dictionary", current.type_name()));
        };
        let needed: Vec<&(&[u8], Option<Object>)> = changes
            .iter()
            .filter(|(key, value)| dict.get(key) != value.as_ref())
            .collect();
        if needed.is_empty() {
            return Ok(());
        }
        let object = self.store.get_mut(id)?;
        let type_name = object.type_name();
        let Some(dict) = object.as_dict_mut() else {
            return Err(Error::type_mismatch("dictionary", type_name));
        };
        for (key, value) in needed {
            match value {
                Some(value) => {
                    dict.insert(*key, value.clone());
                }
                None => {
                    dict.remove(key);
                }
            }
        }
        Ok(())
    }

    /// Drops the cached page-tree walk when `id` is an object the walk reads: the catalog, the
    /// root of the page tree, or a page or node it found (or when the walk failed). Other edits
    /// cannot change the walk.
    fn invalidate_if_tree_object(&mut self, id: ObjectId) {
        let pages_root = self
            .catalog()
            .ok()
            .and_then(|catalog| catalog.as_dict().and_then(|d| d.get_ref(keys::PAGES)));
        let affected = self.store.root_id() == Some(id)
            || pages_root == Some(id)
            || match self.page_tree.get() {
                Some(Ok(tree)) => tree.contains(id),
                Some(Err(_)) => true,
                None => false,
            };
        if affected {
            self.page_tree = OnceLock::new();
        }
    }
}

/// The store of a new, empty document: a page tree with no pages and a catalog.
fn empty_document_store() -> Result<Store> {
    let mut store = Store::new_empty(NEW_DOCUMENT_VERSION);
    let mut pages = Dict::new();
    pages.insert(keys::TYPE, Object::name(keys::PAGES));
    pages.insert(keys::KIDS, Object::Array(Vec::new()));
    pages.insert(keys::COUNT, 0);
    let pages = store.add(pages.into())?;
    let mut catalog = Dict::new();
    catalog.insert(keys::TYPE, Object::name(keys::CATALOG));
    catalog.insert(keys::PAGES, pages);
    let catalog = store.add(catalog.into())?;
    store.set_trailer_entry(keys::ROOT, catalog.into())?;
    Ok(store)
}

/// `rect` normalized and rounded as it is written, or an
/// [`ErrorCode::InvalidArgument`](folioxide_syntax::ErrorCode) error naming `what` when it
/// cannot be written (see [`Rect::checked`]).
fn checked_rect(rect: Rect, what: &str) -> Result<Rect> {
    rect.checked().ok_or_else(|| {
        Error::invalid_argument(format!(
            "the {what} {rect:?} cannot be written: its coordinates must be finite numbers of \
             magnitude at most 3.403e38, and it must have an area once they are written with at \
             most 10 fractional digits"
        ))
    })
}

/// The `/CropBox` change that makes a page's crop box its media box (§14.11.2 default): remove
/// the page's own entry (`None`), or, when the page would then inherit a crop box
/// (`inherits_crop`, along the page tree or along `/Parent`), write the media box as its crop
/// box.
fn default_crop_box(inherits_crop: bool, media: &Rect) -> Option<Object> {
    inherits_crop.then(|| media.to_object())
}

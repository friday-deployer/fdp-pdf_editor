//! The `PdfDocument` class (ARCHITECTURE §A.7, "Class shape" and "Threading").
//!
//! A `PdfDocument` holds a [`folioxide::Document`] behind an `Arc<Mutex<..>>`:
//!
//! - **Synchronous methods** run on the JavaScript thread. They never wait for the lock: while an
//!   asynchronous method has the document (from the call until its work is done), they throw
//!   [`E_BUSY`](crate::error::E_BUSY) at once, so the event loop is never blocked.
//! - **Asynchronous methods** (`openAsync`, `saveAsync`, `saveIncrementalAsync`) return a
//!   promise of a napi-rs [`AsyncTask`]: the work runs on the libuv thread pool, which takes the
//!   lock inside [`Task::compute`]. Two of them on one document run one after the other.
//!
//! "Has the document" is counted from the call, not from when the pool thread takes the lock,
//! so that a synchronous call right after `saveAsync()` throws `E_BUSY` deterministically
//! instead of racing the pool (an edit made then would or would not be in the saved bytes).
//!
//! Input bytes are copied once, into the `Vec<u8>` the document keeps (the JavaScript buffer
//! may change or be collected while the document lives); output bytes become a `Buffer`
//! without a copy.
//!
//! **Native memory.** The JavaScript object is tiny, but the document behind it holds the file
//! and everything read from it (often several times the file's size). V8 is told about that
//! memory ([`Env::adjust_external_memory`]), so that it collects dropped documents in time: the
//! amount is the core's estimate ([`folioxide::Document::store`],
//! `Store::memory_estimate`), reported when the document is opened or created and brought up to
//! date after every method (reading pages and saving grow it), and given back when the object
//! is finalized or `close()`d. `close()` also frees the document at once (or as soon as the
//! asynchronous operations running on it end); every method then throws
//! [`E_CLOSED`](crate::error::E_CLOSED).

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};

use folioxide::Document;
use napi::bindgen_prelude::{AsyncTask, Buffer, Either, Null, ObjectFinalize, Uint8Array};
use napi::{Env, Task};
use napi_derive::napi;

use crate::dto::{
    self, Diagnostic, DocInfo, IncrementalSaveOptions, InfoUpdate, OpenOptions, PageBox, PageInfo,
    Rect, SaveOptions,
};
use crate::error::{self, BindingError, busy, closed, from_core, invalid_argument};

/// What a `PdfDocument` and its asynchronous tasks share.
struct Shared {
    /// The document; `None` once it was closed (or its JavaScript object finalized) and no
    /// asynchronous operation needs it any more. Locked by synchronous methods with `try_lock`
    /// and by asynchronous tasks on the thread pool.
    doc: Mutex<Option<Document>>,
    /// The asynchronous operations started and not finished yet ([`Pending`]).
    pending: AtomicUsize,
    /// Set by `close()` and by finalization: methods throw `E_CLOSED`, and the document is
    /// dropped as soon as no asynchronous operation uses it.
    closed: AtomicBool,
    /// The bytes reported to V8 as external memory for this document (JavaScript thread only).
    reported: AtomicI64,
}

impl Shared {
    fn new(doc: Document) -> Arc<Shared> {
        Arc::new(Shared {
            doc: Mutex::new(Some(doc)),
            pending: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            reported: AtomicI64::new(0),
        })
    }

    /// The document, for a task on the thread pool: waits for the lock (another task may hold
    /// it). A poisoned lock is taken over: the core never panics on its data, and a panic in
    /// one operation leaves the document as consistent as any `&mut` method that returned an
    /// error.
    fn lock(&self) -> MutexGuard<'_, Option<Document>> {
        self.doc.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Tells V8 that this document now holds about `estimate` bytes (the change since the last
    /// report). Nothing once the document is closed. JavaScript thread only.
    fn report(&self, env: &Env, estimate: u64) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let estimate = i64::try_from(estimate).unwrap_or(i64::MAX);
        let old = self.reported.load(Ordering::SeqCst);
        // Both are non-negative, so the difference cannot overflow.
        if estimate != old && env.adjust_external_memory(estimate - old).is_ok() {
            self.reported.store(estimate, Ordering::SeqCst);
        }
    }

    /// Brings the report up to date after an asynchronous operation, if the document is free
    /// (a task running on it reports when it resolves). JavaScript thread only.
    fn report_if_free(&self, env: &Env) {
        let estimate = match self.doc.try_lock() {
            Ok(guard) => guard.as_ref().map(memory_estimate),
            Err(TryLockError::Poisoned(poisoned)) => {
                poisoned.into_inner().as_ref().map(memory_estimate)
            }
            Err(TryLockError::WouldBlock) => None,
        };
        if let Some(estimate) = estimate {
            self.report(env, estimate);
        }
    }

    /// Closes the document: methods throw `E_CLOSED` from now on, V8 gets the reported memory
    /// back, and the document is dropped now, or by the last asynchronous operation using it
    /// (see [`Pending`]). Closing twice does nothing. JavaScript thread only.
    fn close(&self, env: &Env) {
        if let Some(reported) = self.shut()
            && reported != 0
        {
            // A failure leaves V8's count high, which only makes it collect sooner.
            let _ = env.adjust_external_memory(-reported);
        }
    }

    /// [`Shared::close`] without V8: marks the document closed and drops it unless an
    /// asynchronous operation uses it. Returns the bytes reported to V8, to give back, or
    /// `None` when it was closed already.
    fn shut(&self) -> Option<i64> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return None;
        }
        let reported = self.reported.swap(0, Ordering::SeqCst);
        // `closed` is set before `pending` is read, and `Pending` decrements `pending` before it
        // reads `closed`: whichever comes second drops the document (both may; that is fine).
        if self.pending.load(Ordering::SeqCst) == 0 {
            self.release();
        }
        Some(reported)
    }

    /// Drops the document (outside the lock).
    fn release(&self) {
        let doc = self.lock().take();
        drop(doc);
    }
}

/// The core's estimate of the memory a document holds (its store, which dominates).
fn memory_estimate(doc: &Document) -> u64 {
    doc.store().memory_estimate()
}

/// One asynchronous operation in progress on a document: counted in [`Shared::pending`] from
/// its creation (on the JavaScript thread) until it is dropped, which [`SaveTask::compute`] does
/// right after its work, or the task's own drop when the work never ran. The last one to end
/// after the document was closed drops it.
struct Pending(Arc<Shared>);

impl Pending {
    fn new(shared: &Arc<Shared>) -> Pending {
        shared.pending.fetch_add(1, Ordering::SeqCst);
        Pending(Arc::clone(shared))
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if self.0.pending.fetch_sub(1, Ordering::SeqCst) == 1
            && self.0.closed.load(Ordering::SeqCst)
        {
            self.0.release();
        }
    }
}

/// A PDF document opened from bytes or created empty.
///
/// Page indices are 0-based. Every error is thrown (or rejected) with `err.code` set to an
/// `E_*` code; see the package's `index.d.ts` for the full list.
#[napi(custom_finalize)]
pub struct PdfDocument {
    shared: Arc<Shared>,
}

/// The JavaScript object was garbage-collected (or its environment is shutting down): V8 gets
/// the reported memory back, and the document is dropped (now, or when the asynchronous
/// operations still running on it end).
impl ObjectFinalize for PdfDocument {
    fn finalize(self, env: Env) -> napi::Result<()> {
        self.shared.close(&env);
        Ok(())
    }
}

impl PdfDocument {
    fn new(doc: Document) -> PdfDocument {
        PdfDocument {
            shared: Shared::new(doc),
        }
    }

    /// A new `PdfDocument` for `doc`, whose memory is reported to V8.
    fn reported(env: &Env, doc: Document) -> PdfDocument {
        let estimate = memory_estimate(&doc);
        let document = PdfDocument::new(doc);
        document.shared.report(env, estimate);
        document
    }

    /// The document for a synchronous method: `E_CLOSED` once it was closed, `E_BUSY` while an
    /// asynchronous operation has it, never a wait.
    fn try_lock(&self) -> Result<MutexGuard<'_, Option<Document>>, BindingError> {
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err(closed());
        }
        if self.shared.pending.load(Ordering::SeqCst) > 0 {
            return Err(busy());
        }
        match self.shared.doc.try_lock() {
            Ok(guard) => Ok(guard),
            Err(TryLockError::Poisoned(poisoned)) => Ok(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => Err(busy()),
        }
    }

    /// Runs a read-only core operation on the document, then reports its memory (reading
    /// caches what it read).
    fn read<T>(
        &self,
        env: &Env,
        op: impl FnOnce(&Document) -> folioxide::Result<T>,
    ) -> Result<T, BindingError> {
        let guard = self.try_lock()?;
        let doc = guard.as_ref().ok_or_else(closed)?;
        let result = op(doc).map_err(|err| from_core(&err));
        self.shared.report(env, memory_estimate(doc));
        result
    }

    /// Runs an editing core operation on the document, then reports its memory.
    fn edit<T>(
        &self,
        env: &Env,
        op: impl FnOnce(&mut Document) -> folioxide::Result<T>,
    ) -> Result<T, BindingError> {
        let mut guard = self.try_lock()?;
        let doc = guard.as_mut().ok_or_else(closed)?;
        let result = op(doc).map_err(|err| from_core(&err));
        self.shared.report(env, memory_estimate(doc));
        result
    }

    /// A task that saves the document on the thread pool: `E_CLOSED` once it was closed.
    fn save_task(&self, job: SaveJob) -> Result<AsyncTask<SaveTask>, BindingError> {
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err(closed());
        }
        Ok(AsyncTask::new(SaveTask {
            pending: Some(Pending::new(&self.shared)),
            shared: Arc::clone(&self.shared),
            job,
        }))
    }
}

#[napi]
impl PdfDocument {
    /// Opens a PDF file from its bytes, which are copied once. Opening reads the file's
    /// structure only; pages and metadata are read when first asked for.
    ///
    /// Damaged files are repaired (each repair is recorded in `diagnostics()`) unless
    /// `options.strict` is true.
    ///
    /// Throws `E_XREF` or `E_SYNTAX` for data that is not a readable PDF file,
    /// `E_PASSWORD_REQUIRED` for an encrypted file (encryption arrives in a later release),
    /// `E_UNSUPPORTED` for an unsupported security handler, `E_LIMIT_EXCEEDED` when a resource
    /// limit is hit.
    #[napi(factory)]
    pub fn open(
        env: Env,
        data: Uint8Array,
        options: Option<OpenOptions>,
    ) -> Result<PdfDocument, BindingError> {
        let options = options.unwrap_or_default().into_core();
        Document::open(data.to_vec(), &options)
            .map(|doc| PdfDocument::reported(&env, doc))
            .map_err(|err| from_core(&err))
    }

    /// Like `open`, on the libuv thread pool: the bytes are copied before it returns, so the
    /// caller may reuse the buffer at once.
    // The return type is spelled out: napi-rs types an `AsyncTask` whose `Task` impl comes later
    // in the file as `Promise<unknown>`.
    #[napi(ts_return_type = "Promise<PdfDocument>")]
    pub fn open_async(data: Uint8Array, options: Option<OpenOptions>) -> AsyncTask<OpenTask> {
        AsyncTask::new(OpenTask {
            data: data.to_vec(),
            options: options.unwrap_or_default().into_core(),
        })
    }

    /// A new, empty PDF 1.7 document: a catalog and a page tree with no pages. It has no
    /// original file, so it can be saved with `save` only (an incremental update needs a file
    /// to append to).
    #[napi(factory)]
    pub fn create(env: Env) -> PdfDocument {
        PdfDocument::reported(&env, Document::new())
    }

    /// Frees the document's native memory now, instead of when the object is garbage-collected
    /// (which may be much later: the object itself is small). Afterwards every method throws
    /// `E_CLOSED`. An asynchronous operation already started finishes first (its promise
    /// resolves as usual), and the memory is freed when it ends. Closing twice does nothing.
    #[napi]
    pub fn close(&self, env: Env) {
        self.shared.close(&env);
    }

    /// Whether `close()` was called.
    #[napi(getter)]
    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }

    /// An estimate of the native memory the document holds, in bytes (the file, what was read
    /// from it, and the changes), as last reported to V8: it grows as pages are read and when
    /// the document is saved, and is 0 once the document is closed. Never `E_BUSY`.
    #[napi(getter)]
    pub fn native_memory(&self) -> f64 {
        // Exact up to 2^53 bytes.
        self.shared.reported.load(Ordering::SeqCst) as f64
    }

    /// The number of pages (the pages the page tree really has, not its `/Count`).
    #[napi(getter)]
    pub fn page_count(&self, env: Env) -> Result<u32, BindingError> {
        let count = self.read(&env, |doc| doc.page_count())?;
        u32::try_from(count).map_err(|_| {
            error::with_code(
                folioxide::ErrorCode::LimitExceeded,
                "the document has more pages than a JavaScript index can address",
            )
        })
    }

    /// The PDF version, such as `"1.7"`: the header's, or the catalog's `/Version` when that
    /// is later.
    #[napi(getter)]
    pub fn version(&self, env: Env) -> Result<String, BindingError> {
        self.read(&env, |doc| Ok(dto::version_string(doc.version())))
    }

    /// Whether the document has changes not saved yet (always true for a new document).
    #[napi(getter)]
    pub fn is_modified(&self, env: Env) -> Result<bool, BindingError> {
        self.read(&env, |doc| Ok(doc.is_modified()))
    }

    /// The repairs and leniency decisions recorded so far, oldest first: opening, then
    /// whatever reading pages and metadata found.
    #[napi]
    pub fn diagnostics(&self, env: Env) -> Result<Vec<Diagnostic>, BindingError> {
        self.read(&env, |doc| {
            Ok(doc
                .diagnostics()
                .into_iter()
                .map(Diagnostic::from)
                .collect())
        })
    }

    /// The size, boxes and rotation of the page at `index` (0-based).
    ///
    /// Throws `E_PAGE_OUT_OF_RANGE` when there is no such page, `E_INVALID_ARGUMENT` when
    /// `index` is not an integer.
    #[napi]
    pub fn get_page(&self, env: Env, index: f64) -> Result<PageInfo, BindingError> {
        let index = dto::page_index(index)?;
        self.read(&env, |doc| Ok(PageInfo::from(doc.page(index)?.info())))
    }

    /// The document information dictionary (title, author, dates, …), decoded. Entries the
    /// document does not have are left out.
    #[napi]
    pub fn get_info(&self, env: Env) -> Result<DocInfo, BindingError> {
        self.read(&env, |doc| doc.info().map(DocInfo::from))
    }

    /// Changes the document information dictionary: in `update`, a field that is absent keeps
    /// the entry, `null` removes it and a value sets it. Nothing is set automatically (not
    /// even `/ModDate`).
    ///
    /// Throws `E_INVALID_ARGUMENT` for a date that is not a PDF date string, a `trapped` value
    /// other than `'true'`, `'false'` and `'unknown'`, or an invalid custom key.
    #[napi]
    pub fn set_info(&self, env: Env, update: InfoUpdate) -> Result<(), BindingError> {
        let update = update.into_core()?;
        self.edit(&env, |doc| doc.set_info(&update))
    }

    /// Sets the rotation of the page at `index` to `degrees` clockwise: a multiple of 90,
    /// negative ones included (`-90` is the same as 270). The value is written on the page
    /// itself, so the other pages keep theirs.
    #[napi]
    pub fn set_page_rotation(
        &self,
        env: Env,
        index: f64,
        degrees: f64,
    ) -> Result<(), BindingError> {
        let index = dto::page_index(index)?;
        let rotation = dto::rotation(degrees)?;
        self.edit(&env, |doc| doc.set_rotation(index, rotation))
    }

    /// Sets the media box or the crop box of the page at `index`, written on the page itself.
    /// A crop box is clipped to the media box; `null` removes the crop box (it becomes the
    /// media box). A media box cannot be removed.
    ///
    /// Throws `E_INVALID_ARGUMENT` for an unknown box, a box with no area or a coordinate that
    /// is not finite, a crop box outside the media box, or `null` for the media box.
    #[napi]
    pub fn set_page_box(
        &self,
        env: Env,
        index: f64,
        #[napi(ts_arg_type = "PageBox")] kind: String,
        rect: Either<Rect, Null>,
    ) -> Result<(), BindingError> {
        let index = dto::page_index(index)?;
        let rect = match rect {
            Either::A(rect) => Some(folioxide::Rect::from(rect)),
            Either::B(Null) => None,
        };
        match (PageBox::parse(&kind)?, rect) {
            (PageBox::Media, Some(rect)) => self.edit(&env, |doc| doc.set_media_box(index, rect)),
            (PageBox::Media, None) => Err(invalid_argument(
                "a page must have a media box: setPageBox(i, 'media', null) is not allowed",
            )),
            (PageBox::Crop, rect) => self.edit(&env, |doc| doc.set_crop_box(index, rect)),
        }
    }

    /// Writes the whole document again (a full rewrite) and returns the new file.
    ///
    /// Throws `E_INVALID_ARGUMENT` for invalid options, or the error of the writer.
    #[napi]
    pub fn save(&self, env: Env, options: Option<SaveOptions>) -> Result<Buffer, BindingError> {
        let options = options.unwrap_or_default().into_core()?;
        self.read(&env, |doc| doc.save(&options)).map(Buffer::from)
    }

    /// Like `save`, on the libuv thread pool.
    #[napi(ts_return_type = "Promise<Buffer>")]
    pub fn save_async(
        &self,
        options: Option<SaveOptions>,
    ) -> Result<AsyncTask<SaveTask>, BindingError> {
        let options = options.unwrap_or_default().into_core()?;
        self.save_task(SaveJob::Full(options))
    }

    /// Returns the original file with the changes appended as an incremental update (ISO
    /// 32000-2 §7.5.6): the original bytes are kept byte for byte. Without changes, the
    /// original file. With `options.suffixOnly`, only the appended bytes.
    ///
    /// Throws `E_INVALID_ARGUMENT` for a document made with `create()` (there is no original
    /// file), and `E_UNSUPPORTED` when opening repaired the file's structure (other readers
    /// could see an update to it differently): save such a file with `save`.
    #[napi]
    pub fn save_incremental(
        &self,
        env: Env,
        options: Option<IncrementalSaveOptions>,
    ) -> Result<Buffer, BindingError> {
        let (options, suffix_only) = options.unwrap_or_default().into_core();
        self.read(&env, |doc| save_incremental(doc, &options, suffix_only))
            .map(Buffer::from)
    }

    /// Like `saveIncremental`, on the libuv thread pool.
    #[napi(ts_return_type = "Promise<Buffer>")]
    pub fn save_incremental_async(
        &self,
        options: Option<IncrementalSaveOptions>,
    ) -> Result<AsyncTask<SaveTask>, BindingError> {
        let (options, suffix_only) = options.unwrap_or_default().into_core();
        self.save_task(SaveJob::Incremental {
            options,
            suffix_only,
        })
    }
}

/// The incremental save or only its suffix.
fn save_incremental(
    doc: &Document,
    options: &folioxide::IncrementalOptions,
    suffix_only: bool,
) -> folioxide::Result<Vec<u8>> {
    if suffix_only {
        doc.incremental_suffix(options)
    } else {
        doc.save_incremental(options)
    }
}

/// Opens a document on the libuv thread pool (`PdfDocument.openAsync`).
pub struct OpenTask {
    data: Vec<u8>,
    options: folioxide::OpenOptions,
}

#[napi]
impl Task for OpenTask {
    type Output = folioxide::Result<Document>;
    type JsValue = PdfDocument;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        Ok(Document::open(
            std::mem::take(&mut self.data),
            &self.options,
        ))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        output
            .map(|doc| PdfDocument::reported(&env, doc))
            .map_err(|err| error::into_rejection(env, from_core(&err)))
    }
}

/// What a [`SaveTask`] writes.
enum SaveJob {
    Full(folioxide::SaveOptions),
    Incremental {
        options: folioxide::IncrementalOptions,
        suffix_only: bool,
    },
}

/// Why a [`SaveTask`] did not save.
#[derive(Debug)]
pub enum SaveError {
    /// The core's error.
    Core(folioxide::Error),
    /// The document was dropped before the task ran (it cannot be: a closed document is kept
    /// until the tasks started on it end; kept for robustness).
    Closed,
}

/// Saves a document on the libuv thread pool (`saveAsync`, `saveIncrementalAsync`).
pub struct SaveTask {
    shared: Arc<Shared>,
    job: SaveJob,
    /// Marks the document busy until the work is done (dropped at the end of `compute`).
    pending: Option<Pending>,
}

#[napi]
impl Task for SaveTask {
    type Output = Result<Vec<u8>, SaveError>;
    type JsValue = Buffer;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let result = {
            let guard = self.shared.lock();
            match (guard.as_ref(), &self.job) {
                (None, _) => Err(SaveError::Closed),
                (Some(doc), SaveJob::Full(options)) => doc.save(options).map_err(SaveError::Core),
                (
                    Some(doc),
                    SaveJob::Incremental {
                        options,
                        suffix_only,
                    },
                ) => save_incremental(doc, options, *suffix_only).map_err(SaveError::Core),
            }
        };
        // The lock is released: synchronous methods may run again (and, if the document was
        // closed meanwhile, the last task drops it here).
        self.pending = None;
        Ok(result)
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        // Saving read the whole document: report what it holds now.
        self.shared.report_if_free(&env);
        output.map(Buffer::from).map_err(|err| {
            let err = match err {
                SaveError::Core(err) => from_core(&err),
                SaveError::Closed => closed(),
            };
            error::into_rejection(env, err)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_handles_are_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Shared>();
        fn assert_send<T: Send>() {}
        assert_send::<SaveTask>();
        assert_send::<OpenTask>();
    }

    #[test]
    fn synchronous_access_is_refused_while_an_operation_is_pending() {
        let doc = PdfDocument::new(Document::new());
        assert!(doc.try_lock().is_ok());
        let pending = Pending::new(&doc.shared);
        assert_eq!(
            doc.try_lock().err().map(|e| e.status),
            Some(error::E_BUSY.to_owned())
        );
        drop(pending);
        assert!(doc.try_lock().is_ok());
        // A lock held elsewhere (a task on the pool) is E_BUSY too, never a wait.
        let held = doc.shared.lock();
        assert_eq!(
            doc.try_lock().err().map(|e| e.status),
            Some(error::E_BUSY.to_owned())
        );
        drop(held);
    }

    #[test]
    fn save_task_releases_the_document_after_its_work() {
        let doc = PdfDocument::new(Document::new());
        let mut task = SaveTask {
            pending: Some(Pending::new(&doc.shared)),
            shared: Arc::clone(&doc.shared),
            job: SaveJob::Full(folioxide::SaveOptions::default()),
        };
        assert!(doc.try_lock().is_err());
        let bytes = task.compute().expect("compute").expect("save");
        assert!(bytes.starts_with(b"%PDF-1.7"));
        assert!(doc.try_lock().is_ok());

        // A task dropped before its work ran releases the document too.
        let task = SaveTask {
            pending: Some(Pending::new(&doc.shared)),
            shared: Arc::clone(&doc.shared),
            job: SaveJob::Incremental {
                options: folioxide::IncrementalOptions::default(),
                suffix_only: false,
            },
        };
        assert!(doc.try_lock().is_err());
        drop(task);
        assert!(doc.try_lock().is_ok());
    }

    #[test]
    fn incremental_save_of_a_new_document_is_an_invalid_argument() {
        let mut task = SaveTask {
            pending: None,
            shared: Shared::new(Document::new()),
            job: SaveJob::Incremental {
                options: folioxide::IncrementalOptions::default(),
                suffix_only: true,
            },
        };
        let err = task.compute().expect("compute").expect_err("no source");
        let SaveError::Core(err) = err else {
            panic!("{err:?}");
        };
        assert_eq!(from_core(&err).status, "E_INVALID_ARGUMENT");
    }

    #[test]
    fn a_closed_document_is_dropped_and_refused() {
        let doc = PdfDocument::new(Document::new());
        doc.shared.reported.store(1234, Ordering::SeqCst);
        assert_eq!(doc.shared.shut(), Some(1234));
        assert!(doc.shared.lock().is_none(), "dropped at once");
        assert_eq!(doc.shared.reported.load(Ordering::SeqCst), 0);
        // Closing again does nothing (no second give-back).
        assert_eq!(doc.shared.shut(), None);
        assert_eq!(
            doc.try_lock().err().map(|e| e.status),
            Some(error::E_CLOSED.to_owned())
        );
        assert_eq!(
            doc.save_task(SaveJob::Full(folioxide::SaveOptions::default()))
                .err()
                .map(|e| e.status),
            Some(error::E_CLOSED.to_owned())
        );
        // A task whose document is gone (it cannot happen: see the next test) rejects.
        let mut task = SaveTask {
            pending: None,
            shared: Arc::clone(&doc.shared),
            job: SaveJob::Full(folioxide::SaveOptions::default()),
        };
        assert!(matches!(
            task.compute().expect("compute"),
            Err(SaveError::Closed)
        ));
    }

    #[test]
    fn closing_waits_for_the_operations_running() {
        let doc = PdfDocument::new(Document::new());
        let mut first = SaveTask {
            pending: Some(Pending::new(&doc.shared)),
            shared: Arc::clone(&doc.shared),
            job: SaveJob::Full(folioxide::SaveOptions::default()),
        };
        let mut second = SaveTask {
            pending: Some(Pending::new(&doc.shared)),
            shared: Arc::clone(&doc.shared),
            job: SaveJob::Incremental {
                options: folioxide::IncrementalOptions::default(),
                suffix_only: false,
            },
        };
        assert_eq!(doc.shared.shut(), Some(0));
        // Methods are refused at once; the tasks already started still see the document.
        assert_eq!(
            doc.try_lock().err().map(|e| e.status),
            Some(error::E_CLOSED.to_owned())
        );
        assert!(doc.shared.lock().is_some());
        let saved = first.compute().expect("compute").expect("save");
        assert!(saved.starts_with(b"%PDF-1.7"));
        assert!(
            doc.shared.lock().is_some(),
            "the second task still needs it"
        );
        // The last task to end drops the document (here with the core's error: a new document
        // cannot be saved incrementally).
        assert!(matches!(
            second.compute().expect("compute"),
            Err(SaveError::Core(_))
        ));
        assert!(doc.shared.lock().is_none());
    }

    #[test]
    fn a_task_dropped_unrun_after_closing_drops_the_document() {
        let doc = PdfDocument::new(Document::new());
        let task = SaveTask {
            pending: Some(Pending::new(&doc.shared)),
            shared: Arc::clone(&doc.shared),
            job: SaveJob::Full(folioxide::SaveOptions::default()),
        };
        assert_eq!(doc.shared.shut(), Some(0));
        assert!(doc.shared.lock().is_some());
        drop(task);
        assert!(doc.shared.lock().is_none());
    }

    #[test]
    fn open_task_reports_core_errors() {
        let mut task = OpenTask {
            data: b"not a PDF".to_vec(),
            options: folioxide::OpenOptions::default(),
        };
        let err = task.compute().expect("compute").expect_err("not a PDF");
        assert_eq!(from_core(&err).status, "E_XREF");
    }
}

//! The document model's own diagnostics.
//!
//! The store records the repairs of the syntax layer; the model records what it finds wrong
//! one level up (a wrong page-tree `/Count`, a page without a `/MediaBox`, an Info entry of the
//! wrong type), under the model's own kinds: [`DiagnosticKind::PageTree`],
//! [`DiagnosticKind::PageAttribute`], [`DiagnosticKind::Metadata`] and
//! [`DiagnosticKind::Catalog`]. Model accessors may run many times (every `Page::media_box` call looks the box
//! up again), so the log keeps each distinct diagnostic once, and like the store's log it keeps
//! at most [`Limits::max_diagnostics`](folioxide_syntax::Limits::max_diagnostics) of them.

use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard, PoisonError};

use folioxide_syntax::{Diagnostic, DiagnosticKind};

/// A bounded, de-duplicating, thread-safe diagnostic log.
#[derive(Debug)]
pub(crate) struct ModelLog {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    entries: Vec<Diagnostic>,
    seen: HashSet<Diagnostic>,
    capacity: usize,
    dropped: u64,
}

impl ModelLog {
    /// An empty log that keeps at most `capacity` diagnostics.
    pub(crate) fn new(capacity: u32) -> Self {
        ModelLog {
            inner: Mutex::new(Inner {
                capacity: usize::try_from(capacity).unwrap_or(usize::MAX),
                ..Inner::default()
            }),
        }
    }

    // Every update is a single push or increment, so a poisoned lock is simply recovered.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records a diagnostic of kind `kind` (one of the model's kinds:
    /// [`DiagnosticKind::PageTree`], [`DiagnosticKind::PageAttribute`],
    /// [`DiagnosticKind::Metadata`], [`DiagnosticKind::Catalog`]), unless the same one was
    /// recorded before.
    pub(crate) fn report(&self, kind: DiagnosticKind, message: impl Into<String>) {
        let diagnostic = Diagnostic::new(kind, None, message);
        let mut inner = self.lock();
        if inner.seen.contains(&diagnostic) {
            return;
        }
        if inner.entries.len() < inner.capacity {
            inner.seen.insert(diagnostic.clone());
            inner.entries.push(diagnostic);
        } else {
            inner.dropped = inner.dropped.saturating_add(1);
        }
    }

    /// A copy of the recorded diagnostics, oldest first.
    pub(crate) fn snapshot(&self) -> Vec<Diagnostic> {
        self.lock().entries.clone()
    }

    /// The number of reports not kept because the log was full.
    pub(crate) fn dropped(&self) -> u64 {
        self.lock().dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deduplicates_and_is_bounded() {
        let log = ModelLog::new(2);
        log.report(DiagnosticKind::PageTree, "a");
        log.report(DiagnosticKind::PageTree, "a");
        log.report(DiagnosticKind::Metadata, "b");
        log.report(DiagnosticKind::Metadata, "c");
        let entries = log.snapshot();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message, "a");
        assert_eq!(entries[1].message, "b");
        assert_eq!(entries[0].kind, DiagnosticKind::PageTree);
        assert_eq!(entries[1].kind, DiagnosticKind::Metadata);
        assert_eq!(log.dropped(), 1);
        // The same message under another kind is another diagnostic.
        let log = ModelLog::new(4);
        log.report(DiagnosticKind::PageTree, "a");
        log.report(DiagnosticKind::Catalog, "a");
        assert_eq!(log.snapshot().len(), 2);
    }
}

//! # folioxide-model: layer L3, the document model
//!
//! The `Document` that applications work with, built on the syntax layer:
//!
//! - the catalog (ISO 32000-2 §7.7.2) and the page tree with inherited attributes (§7.7.3)
//! - page boxes, rotation and resources; name trees and number trees (§7.9.6, §7.9.7)
//! - text strings and dates (§7.9.2, §7.9.4)
//! - page operations (insert, delete, move, rotate) and cross-document import and merge
//! - document metadata (Info dictionary and XMP), outlines, page labels and attachments
//! - optimization and garbage collection
//!
//! With the `encryption` feature it opens and saves encrypted documents through
//! `folioxide-security`. Dependency direction: `folioxide-syntax ← folioxide-model`.
//!
//! **Status:** scaffolding only (M0). The first document model lands in M2.

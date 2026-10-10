//! # folioxide-redact: layer L5, true redaction
//!
//! Removes content for real rather than covering it: text in page content and shared Form XObjects,
//! partially covered images, annotation and form values, and related metadata. A redacted
//! document is always written as a full rewrite without incremental history. Also hosts editing of
//! existing text.
//!
//! Dependency direction: `folioxide-content + folioxide-interactive ← folioxide-redact`.
//!
//! **Status:** scaffolding only (M0). Redaction lands in M10.

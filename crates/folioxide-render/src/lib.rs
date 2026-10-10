//! # folioxide-render: layer L5, rendering
//!
//! Will rasterize pages to RGBA and PNG through the `hayro` renderer, which receives bytes that
//! Folioxide has serialized (and decrypted where necessary). `hayro` is not a dependency yet.
//!
//! Dependency direction: `folioxide-model ← folioxide-render`.
//!
//! **Status:** scaffolding only (M0). Rendering is on the backlog (M11+).

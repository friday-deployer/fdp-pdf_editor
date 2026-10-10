//! # folioxide-content: layer L4, page content
//!
//! Everything that reads or writes what is drawn on a page:
//!
//! - content-stream tokenizer and builder, including inline images (ISO 32000-2 §7.8, §8)
//! - a graphics-state tracker and the standard-14 font metrics (§9)
//! - TrueType/OpenType font embedding and subsetting, ToUnicode maps (feature `fonts`)
//! - JPEG passthrough and PNG images with soft masks (feature `images`; §8.9, §11.6.5.3)
//! - text layout and text extraction
//!
//! Dependency direction: `folioxide-model ← folioxide-content`.
//!
//! **Status:** scaffolding only (M0). Content creation lands in M7.

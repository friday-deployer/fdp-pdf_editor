//! # folioxide-syntax: layer L1, the PDF syntax layer
//!
//! The lowest layer of Folioxide. It owns the PDF object model and everything needed to turn bytes
//! into objects and objects back into bytes, without any knowledge of pages, fonts or signatures:
//!
//! - the object model (`Object`, `ObjectId`, `Dict`, `Stream`, ...) with `f64` reals (ISO 32000-2 §7.3)
//! - the lexer (§7.2) and a lenient object parser with depth limits (§7.3)
//! - cross-reference tables, streams and hybrids, the `/Prev` chain and repair (§7.5)
//! - object streams (§7.5.7) and stream filters (§7.4)
//! - the lazy, `Send + Sync` object store and the full and incremental writers
//! - `Limits` for hostile input, and `ErrorCode`, the error vocabulary shared by every crate
//!
//! Every other Folioxide crate depends on this one; it depends on no other Folioxide crate.
//! See `docs/ARCHITECTURE.md` §A.3 for the data model.
//!
//! **Status:** scaffolding only (M0). The read path lands in M1, the writers in M2.

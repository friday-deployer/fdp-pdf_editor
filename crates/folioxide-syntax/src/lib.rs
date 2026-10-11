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
//! **Status:** M2 in progress. Available: the object model, errors, limits and diagnostics, the
//! lexer, the object parser, the primitive serializer, the stream filters, the lazy [`Store`]
//! with cross-reference parsing, object streams and repair, its edit layer ([`Store::set`],
//! [`Store::add`], [`Store::free`], ...), and the [`writer`]s: a full rewrite ([`save`]) and
//! incremental updates ([`save_incremental`]).
//!
//! ```
//! use folioxide_syntax::{parse_object, serialize_object, ParseCtx};
//!
//! let (obj, _) = parse_object(b"<< /Type /Page /Rotate 90 /Scale 0.5 >>", 0, &ParseCtx::default())?;
//! let dict = obj.as_dict().unwrap();
//! assert!(dict.is_type(b"Page"));
//! assert_eq!(dict.get_int(b"Rotate"), Some(90));
//!
//! let mut out = Vec::new();
//! serialize_object(&obj, &mut out);
//! assert_eq!(out, b"<</Type /Page /Rotate 90 /Scale 0.5>>");
//! # Ok::<(), folioxide_syntax::Error>(())
//! ```

pub mod diag;
pub mod error;
pub mod filters;
pub mod lexer;
pub mod limits;
pub mod object;
pub mod parser;
pub mod serialize;
pub mod store;
pub mod writer;

mod objstm;
mod repair;
mod xref;

pub use diag::{Diagnostic, DiagnosticKind, DiagnosticLog, DiagnosticSink, Strictness};
pub use error::{Error, ErrorCode, Result};
pub use lexer::{Lexer, Token, TokenKind};
pub use limits::{LimitKind, Limits};
pub use object::{Dict, Name, Object, ObjectId, PdfString, Stream, StreamData, keys};
pub use parser::{
    IndirectObject, ParseCtx, parse_indirect_at, parse_indirect_header, parse_object,
};
pub use serialize::{serialize_indirect, serialize_object};
// M1 WP1.3: the store, cross-reference data and the filter-error glue.
pub use error::filter_error_code;
pub use parser::KeywordIndex;
pub use store::{
    OffsetBase, OpenOptions, Resolved, Revision, SharedBytes, Store, StreamBytes, XrefEntry,
    XrefKind, shared_bytes,
};
// M2 WP2.1: the writers.
pub use writer::{
    IncrementalOptions, IncrementalUpdate, SaveOptions, StreamCompression, XrefStyle,
    incremental_suffix, incremental_update, save, save_incremental,
};
// M3 WP3.1A: overlay-aware incremental update and object locations (signatures).
pub use store::ObjectLocation;
pub use writer::{IncrementalLayout, incremental_suffix_with_overlay};

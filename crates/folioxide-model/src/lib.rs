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
//! Errors are the syntax layer's [`Error`](folioxide_syntax::Error) with its
//! [`ErrorCode`](folioxide_syntax::ErrorCode) (`PageOutOfRange`, `NotFound`, `InvalidArgument`,
//! …): the model adds no error type of its own.
//!
//! **Status:** M2 in progress. Available: [`Document`] (open or create, catalog, version,
//! diagnostics, the page-tree walk, saving in full or incrementally), [`Page`] (boxes, rotation,
//! effective size, resources, inheritance; [`PageInfo`]) and the page setters, the Info
//! dictionary ([`DocInfo`], [`InfoUpdate`]), text strings ([`text`]), dates ([`PdfDate`]), and
//! name and number trees ([`NameTree`], [`NumberTree`]).
//!
//! With the `serde` feature the DTOs ([`DocInfo`], [`InfoUpdate`], [`PageInfo`], [`Rect`],
//! [`Rotation`], [`PdfDate`], [`Trapped`]) implement `Serialize` and `Deserialize` with
//! `camelCase` names (ARCHITECTURE §A.8): the JSON shape the Node binding uses too.
//!
//! ```
//! use folioxide_model::{PdfDate, text};
//!
//! let russian = text::decode_text_string(b"\xFE\xFF\x04\x1F\x04\x40\x04\x38");
//! assert_eq!(russian, "\u{41F}\u{440}\u{438}");
//! assert_eq!(PdfDate::parse(b"D:2024").unwrap().year, 2024);
//! ```

mod date;
mod diag;
mod document;
mod info;
mod page;
mod page_tree;
#[cfg(feature = "serde")]
mod serde_util;
pub mod text;
mod tree;

pub use date::PdfDate;
pub use document::Document;
pub use info::{DocInfo, InfoUpdate, Trapped};
pub use page::{Page, PageId, PageInfo, Rect, Rotation};
pub use tree::{NameTree, NumberTree};

use std::sync::Arc;

use folioxide_syntax::{Object, ObjectId, Result, Store};

/// The object `id` refers to, following reference chains ([`Store::deref`]): `null` when it is
/// missing or free.
pub(crate) fn resolve(store: &Store, id: ObjectId) -> Result<Arc<Object>> {
    Ok(store.deref(&Object::Ref(id))?.into_arc())
}

/// The type of `obj` with an article, for diagnostics: `an integer`, `a dictionary`, `null`.
pub(crate) fn type_phrase(obj: &Object) -> String {
    match obj {
        Object::Null => "null".to_owned(),
        Object::Int(_) | Object::Array(_) => format!("an {}", obj.type_name()),
        _ => format!("a {}", obj.type_name()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_types_are_send_sync_static() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Document>();
        assert_send_sync::<PageId>();
        assert_send_sync::<Rect>();
        assert_send_sync::<Rotation>();
        assert_send_sync::<DocInfo>();
        assert_send_sync::<PdfDate>();
        assert_send_sync::<Trapped>();
        assert_send_sync::<InfoUpdate>();
        assert_send_sync::<PageInfo>();
        fn assert_borrowed_send_sync<T: Send + Sync>() {}
        assert_borrowed_send_sync::<Page<'_>>();
        assert_borrowed_send_sync::<NameTree<'_>>();
        assert_borrowed_send_sync::<NumberTree<'_>>();
    }
}

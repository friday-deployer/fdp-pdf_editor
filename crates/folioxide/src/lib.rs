//! # folioxide: a pure-Rust PDF editing engine
//!
//! This is the facade crate and the only crate with a semver promise. Applications (the Node
//! addon, and later a Tauri app) depend on it alone. It re-exports the public API of the layered
//! `folioxide-*` crates, owns the unified `Error`, the serde DTOs and the `std::fs` helpers, and
//! selects functionality through feature flags:
//!
//! | Feature | Default | Enables |
//! |---|---|---|
//! | `encryption` | yes | open and save encrypted documents (`folioxide-security`) |
//! | `signatures` | yes | digital signatures (`folioxide-sign`, RustCrypto) |
//! | `pkcs12-legacy` | yes | RC2-40 and 3DES PKCS#12 files |
//! | `fonts` | yes | TrueType/OpenType embedding and subsetting |
//! | `images` | yes | PNG decoding (JPEG passthrough is always on) |
//! | `interactive` | yes | annotations and forms (`folioxide-interactive`) |
//! | `jpeg-decode` | no | JPEG pixel decoding |
//! | `shaping` | no | complex-script shaping and bidi |
//! | `redact` | no | true redaction (`folioxide-redact`) |
//! | `render` | no | page rendering (`folioxide-render`) |
//! | `serde` | no | `Serialize`/`Deserialize` on all DTOs |
//! | `std-fs` | no | path helpers, `SystemClock`, optional mmap |
//!
//! No feature adds threads or network I/O.
//!
//! **Status:** pre-alpha; see `docs/ROADMAP.md`. M2 adds the document model: open or create
//! a [`Document`], walk its pages ([`Page`]: boxes, rotation, resources; [`PageInfo`]), read and
//! change its Info dictionary ([`DocInfo`], [`InfoUpdate`]), set page boxes and rotation, and
//! save it as a full rewrite ([`SaveOptions`]) or as an incremental update that keeps the
//! original bytes ([`IncrementalOptions`]). Errors are the syntax layer's [`Error`] with a
//! stable [`ErrorCode`] (a unified error enum arrives with the second error type, in M3).
//!
//! Bytes in, bytes out: the core reads no files and has no clock, so the caller reads and writes
//! the files and passes dates in (ARCHITECTURE §A.8).
//!
//! ```
//! use folioxide::{
//!     Document, ErrorCode, IncrementalOptions, InfoUpdate, OpenOptions, PdfDate, Rect, Rotation,
//!     SaveOptions,
//! };
//!
//! # fn build(objects: &[&str]) -> Vec<u8> {
//! #     let mut out = b"%PDF-1.7\n".to_vec();
//! #     let mut offsets = Vec::new();
//! #     for (i, body) in objects.iter().enumerate() {
//! #         offsets.push(out.len());
//! #         out.extend(format!("{} 0 obj\n{body}\nendobj\n", i + 1).bytes());
//! #     }
//! #     let xref = out.len();
//! #     out.extend(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).bytes());
//! #     for offset in offsets {
//! #         out.extend(format!("{offset:010} 00000 n \n").bytes());
//! #     }
//! #     let trailer = format!("/Size {} /Root 1 0 R", objects.len() + 1);
//! #     out.extend(format!("trailer\n<< {trailer} >>\nstartxref\n{xref}\n%%EOF\n").bytes());
//! #     out
//! # }
//! // An A4 page whose media box comes from the page tree (a hidden helper builds the file).
//! let original: Vec<u8> = build(&[
//!     "<< /Type /Catalog /Pages 2 0 R >>",
//!     "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595 842] >>",
//!     "<< /Type /Page /Parent 2 0 R >>",
//! ]);
//! let mut doc = Document::open(original.clone(), &OpenOptions::default())?;
//! let page = doc.page(0)?.info();
//! assert_eq!((page.width, page.height), (595.0, 842.0));
//!
//! // Turn the page, crop it, and record the title and the modification time.
//! doc.set_rotation(0, Rotation::R90)?;
//! doc.set_crop_box(0, Some(Rect::new(20.0, 20.0, 575.0, 822.0)))?;
//! doc.set_info(
//!     &InfoUpdate::default()
//!         .with_title(Some("Quarterly report"))
//!         .with_mod_date(PdfDate::new(2026, 10, 10, 9, 30, 0)),
//! )?;
//!
//! // Save as an incremental update, which keeps every original byte (as signed files need),
//! // or rewrite the whole file.
//! let updated = doc.save_incremental(&IncrementalOptions::default())?;
//! assert!(updated.starts_with(&original));
//! let rewritten = doc.save(&SaveOptions::default())?;
//! for pdf in [updated, rewritten] {
//!     let doc = Document::open(pdf, &OpenOptions::default())?;
//!     let page = doc.page(0)?.info();
//!     assert_eq!(page.rotation, Rotation::R90);
//!     assert_eq!((page.width, page.height), (802.0, 555.0)); // the crop box, turned
//!     assert_eq!(doc.info()?.title.as_deref(), Some("Quarterly report"));
//! }
//!
//! // A new document starts with an empty page tree.
//! assert_eq!(Document::new().page_count()?, 0);
//!
//! // Errors carry a stable code (`err.code === "E_XREF"` in Node).
//! let err = Document::open(b"not a PDF".to_vec(), &OpenOptions::default()).unwrap_err();
//! assert_eq!(err.code(), ErrorCode::Xref);
//! # Ok::<(), folioxide::Error>(())
//! ```

/// The version of the `folioxide` crate, for example `"0.1.0"`.
///
/// The Node package exposes the same value as `version()`, which lets callers check that the
/// JavaScript wrapper and the native addon come from the same release.
///
/// ```
/// assert_eq!(folioxide::VERSION.split('.').count(), 3);
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// The document model (M2 WP2.2 read side, WP2.3 write side and DTOs).
pub use folioxide_model::{
    DocInfo, Document, InfoUpdate, NameTree, NumberTree, Page, PageId, PageInfo, PdfDate, Rect,
    Rotation, Trapped, text,
};
// The syntax layer: errors, options, diagnostics and the object model that `Document` exposes.
pub use folioxide_syntax::{
    Diagnostic, DiagnosticKind, Dict, Error, ErrorCode, Limits, Name, Object, ObjectId,
    OpenOptions, PdfString, Result, SharedBytes, Store, Strictness, shared_bytes,
};
// The writers' options (M2 WP2.1), for `Document::save` and `Document::save_incremental`.
pub use folioxide_syntax::{IncrementalOptions, SaveOptions, StreamCompression, XrefStyle};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_semver_core() {
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "VERSION {VERSION:?} is not MAJOR.MINOR.PATCH"
        );
        for part in parts {
            assert!(
                !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()),
                "VERSION {VERSION:?} has a non-numeric component"
            );
        }
    }

    #[test]
    fn model_is_reexported() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<Document>();
        assert_send_sync_static::<Error>();
        assert_eq!(Rotation::from_degrees(-90), Some(Rotation::R270));
        assert_eq!(text::encode_text_string("\u{20AC}"), b"\xA0");
        assert_eq!(PdfDate::parse(b"D:2024").map(|d| d.year), Some(2024));
        let err = Document::open(Vec::new(), &OpenOptions::default()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Xref);
    }

    #[test]
    fn write_side_is_reexported() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<InfoUpdate>();
        assert_send_sync_static::<PageInfo>();
        assert_send_sync_static::<SaveOptions>();
        assert_send_sync_static::<IncrementalOptions>();

        let mut doc = Document::new();
        assert!(doc.is_modified());
        doc.set_info(&InfoUpdate::default().with_title(Some("\u{1F600}")))
            .unwrap();
        let options = SaveOptions::default()
            .with_xref(XrefStyle::Stream)
            .with_compress(StreamCompression::CompressNew);
        let pdf = doc.save(&options).unwrap();
        let reopened = Document::open(pdf, &OpenOptions::default()).unwrap();
        assert_eq!(reopened.page_count().unwrap(), 0);
        assert_eq!(reopened.info().unwrap().title.as_deref(), Some("\u{1F600}"));
        assert!(!reopened.is_modified());
        // A new document has no file to append to.
        let err = doc
            .save_incremental(&IncrementalOptions::default())
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// With the `serde` feature the DTOs serialize with `camelCase` names (the same JSON shape
    /// the Node binding uses, ARCHITECTURE §A.7).
    #[cfg(feature = "serde")]
    #[test]
    fn serde_feature_reaches_the_model() {
        fn assert_serde<T: serde::Serialize + serde::de::DeserializeOwned>() {}
        assert_serde::<DocInfo>();
        assert_serde::<InfoUpdate>();
        assert_serde::<PageInfo>();
        assert_serde::<Rect>();
        assert_serde::<Rotation>();
        assert_serde::<PdfDate>();
        assert_serde::<Trapped>();
        assert_serde::<Diagnostic>();
        assert_serde::<SaveOptions>();
    }
}

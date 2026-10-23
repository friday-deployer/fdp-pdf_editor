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
//! **Status:** M4 adds the minimal content-creation kit that visible signature appearances need:
//!
//! - [`builder::ContentBuilder`]: content-stream operators (graphics state, paths, colour, text,
//!   XObject placement), with operands written by the M1 serializer's number rules;
//! - [`standard14`]: metrics of Helvetica and Helvetica-Bold, derived from Adobe's Core 14 AFM
//!   files (see the crate's `NOTICE` file and [`standard14::ADOBE_AFM_NOTICE`]);
//! - [`encoding`]: WinAnsiEncoding (Annex D.2), with `?` for characters it cannot encode;
//! - [`image::jpeg`]: a bounded JPEG header parser and the `/DCTDecode` passthrough image
//!   XObject.
//!
//! Errors are the syntax layer's [`Error`](folioxide_syntax::Error): `InvalidArgument` for bad
//! caller input, `Unsupported` for valid inputs outside what this version handles, and
//! [`Error::Other`](folioxide_syntax::Error::Other) with [`ErrorCode::Image`] or
//! [`ErrorCode::Font`] for malformed images and fonts. Embedded fonts, text extraction and the
//! rest of the list above land in M7.
//!
//! ```
//! use folioxide_content::builder::ContentBuilder;
//! use folioxide_content::encoding::win_ansi_encode;
//! use folioxide_content::standard14::Standard14Font;
//!
//! let text = win_ansi_encode("Signed by Zoë");
//! assert_eq!(text.bytes, b"Signed by Zo\xEB");
//! let width = Standard14Font::Helvetica.text_width(&text.bytes, 12.0);
//! assert!((width - 77.376).abs() < 1e-9);
//!
//! let mut content = ContentBuilder::new();
//! content
//!     .begin_text()
//!     .font(b"F1", 12.0)
//!     .move_text(10.0, 20.5)
//!     .show(&text.bytes)
//!     .end_text();
//! assert_eq!(content.finish()?, b"BT\n/F1 12 Tf\n10 20.5 Td\n(Signed by Zo\xEB) Tj\nET\n");
//! # Ok::<(), folioxide_syntax::Error>(())
//! ```
//!
//! [`ErrorCode::Image`]: folioxide_syntax::ErrorCode::Image
//! [`ErrorCode::Font`]: folioxide_syntax::ErrorCode::Font

pub mod builder;
pub mod encoding;
pub mod image;
pub mod standard14;

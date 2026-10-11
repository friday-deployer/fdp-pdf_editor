//! The plain objects that cross the JavaScript boundary (ARCHITECTURE §A.7, "DTOs").
//!
//! Each one mirrors a core DTO as a `#[napi(object)]` struct, so the generated TypeScript types
//! are precise, with conversions from and to the core type. Field names are `camelCase` and
//! values have the representation of the core's `serde` feature, so Node and a Tauri app see
//! the same JSON (§A.8):
//!
//! - [`PageInfo`]: `{ index, width, height, mediaBox, cropBox, rotation }`, the rotation in
//!   degrees and the boxes as [`Rect`] `{ llx, lly, urx, ury }`;
//! - [`DocInfo`]: absent entries are left out, dates are PDF date strings
//!   (`"D:20261010093000Z"`), `trapped` is `'true'`, `'false'` or `'unknown'`, `custom` is an
//!   object;
//! - [`InfoUpdate`]: a field that is absent (`undefined`) keeps the entry, `null` removes it,
//!   a value sets it;
//! - [`Diagnostic`]: `{ offset, kind, message }`, `offset` `null` when the diagnostic is not
//!   tied to a byte position.
//!
//! The options objects ([`OpenOptions`], [`SaveOptions`], [`IncrementalSaveOptions`]) are
//! input only; [`SaveOptions`] takes `minVersion` as a version string (`"1.7"`, as the
//! document's `version` getter returns it) and `id` as two byte arrays, where the core's serde
//! form has a pair of numbers and two arrays of numbers.
//!
//! The string enums ([`Trapped`], [`PageBox`], [`XrefStyle`], [`StreamCompression`]) are
//! `#[napi(string_enum)]`, emitted as string-literal unions (`"constEnum": false` in
//! `package.json`). Input strings are parsed here rather than by napi-rs, so a wrong value is
//! an `E_INVALID_ARGUMENT` error that lists the accepted ones.

use std::collections::{BTreeMap, HashMap};

use napi::bindgen_prelude::{Either, Null, Uint8Array};
use napi_derive::napi;

use crate::error::{BindingError, JsResult, from_core, invalid_argument, page_out_of_range};

// ---- rectangles and pages --------------------------------------------------------------------

/// A rectangle in default user space (ISO 32000-2 §7.9.5), in PDF points: the core `Rect`.
///
/// Rectangles the binding returns are normalized (`llx <= urx`, `lly <= ury`); rectangles it
/// takes may have their corners in any order.
#[napi(object)]
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize), serde(rename_all = "camelCase"))]
pub struct Rect {
    /// The x coordinate of the lower-left corner.
    pub llx: f64,
    /// The y coordinate of the lower-left corner.
    pub lly: f64,
    /// The x coordinate of the upper-right corner.
    pub urx: f64,
    /// The y coordinate of the upper-right corner.
    pub ury: f64,
}

impl From<folioxide::Rect> for Rect {
    fn from(rect: folioxide::Rect) -> Rect {
        Rect {
            llx: rect.llx,
            lly: rect.lly,
            urx: rect.urx,
            ury: rect.ury,
        }
    }
}

impl From<Rect> for folioxide::Rect {
    /// The core rectangle, normalized ([`folioxide::Rect::new`]).
    fn from(rect: Rect) -> folioxide::Rect {
        folioxide::Rect::new(rect.llx, rect.lly, rect.urx, rect.ury)
    }
}

/// What a page looks like: its size as displayed, its boxes and its rotation (the core
/// `PageInfo`).
#[napi(object)]
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize), serde(rename_all = "camelCase"))]
pub struct PageInfo {
    /// The page's 0-based index.
    pub index: u32,
    /// The width as displayed, in points: the crop box's width, or its height when the page is
    /// rotated by 90 or 270 degrees.
    pub width: f64,
    /// The height as displayed, in points (see `width`).
    pub height: f64,
    /// The media box (§7.7.3.3; inherited from the page tree when the page has none; US Letter
    /// when no valid one exists).
    pub media_box: Rect,
    /// The crop box (§14.11.2), clipped to the media box; the media box when the page has none.
    pub crop_box: Rect,
    /// The rotation, clockwise in degrees: 0, 90, 180 or 270.
    pub rotation: u32,
}

impl From<folioxide::PageInfo> for PageInfo {
    fn from(info: folioxide::PageInfo) -> PageInfo {
        PageInfo {
            // A page index is below the number of objects in the file, which fits in a u32.
            index: u32::try_from(info.index).unwrap_or(u32::MAX),
            width: info.width,
            height: info.height,
            media_box: info.media_box.into(),
            crop_box: info.crop_box.into(),
            rotation: u32::from(info.rotation.degrees()),
        }
    }
}

/// The page box `setPageBox` changes.
#[napi(string_enum = "camelCase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageBox {
    /// The media box (`/MediaBox`, §7.7.3.3): the boundaries of the physical medium.
    Media,
    /// The crop box (`/CropBox`, §14.11.2): the region the page is displayed or printed in.
    Crop,
}

impl PageBox {
    /// Parses `'media'` or `'crop'`.
    ///
    /// # Errors
    /// `E_INVALID_ARGUMENT` for any other string.
    pub fn parse(text: &str) -> JsResult<PageBox> {
        match text {
            "media" => Ok(PageBox::Media),
            "crop" => Ok(PageBox::Crop),
            other => Err(invalid_argument(format!(
                "the page box must be 'media' or 'crop', not {:?}",
                short(other)
            ))),
        }
    }
}

// ---- the document information dictionary ----------------------------------------------------

/// The `/Trapped` entry of the document information dictionary (§14.3.3).
#[napi(string_enum = "camelCase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize), serde(rename_all = "camelCase"))]
pub enum Trapped {
    /// `/True`: the document is fully trapped.
    True,
    /// `/False`: the document has not been trapped.
    False,
    /// `/Unknown`: unknown, or partly trapped.
    Unknown,
}

impl Trapped {
    /// Parses `'true'`, `'false'` or `'unknown'`.
    ///
    /// # Errors
    /// `E_INVALID_ARGUMENT` for any other string.
    pub fn parse(text: &str) -> JsResult<Trapped> {
        match text {
            "true" => Ok(Trapped::True),
            "false" => Ok(Trapped::False),
            "unknown" => Ok(Trapped::Unknown),
            other => Err(invalid_argument(format!(
                "trapped must be 'true', 'false' or 'unknown', not {:?}",
                short(other)
            ))),
        }
    }
}

impl From<folioxide::Trapped> for Trapped {
    fn from(trapped: folioxide::Trapped) -> Trapped {
        match trapped {
            folioxide::Trapped::True => Trapped::True,
            folioxide::Trapped::False => Trapped::False,
            folioxide::Trapped::Unknown => Trapped::Unknown,
        }
    }
}

impl From<Trapped> for folioxide::Trapped {
    fn from(trapped: Trapped) -> folioxide::Trapped {
        match trapped {
            Trapped::True => folioxide::Trapped::True,
            Trapped::False => folioxide::Trapped::False,
            Trapped::Unknown => folioxide::Trapped::Unknown,
        }
    }
}

/// The document information dictionary (§14.3.3), decoded (the core `DocInfo`).
///
/// Entries the dictionary does not have (or has with the wrong type) are left out. Text is
/// decoded from PDFDocEncoding or UTF-16; dates are PDF date strings in the full form
/// `D:YYYYMMDDHHmmSSOHH'mm'` (`fromPdfDate` in the JavaScript facade turns one into a `Date`).
#[napi(object)]
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize), serde(rename_all = "camelCase"))]
pub struct DocInfo {
    /// `/Title`: the document's title.
    #[cfg_attr(test, serde(skip_serializing_if = "Option::is_none"))]
    pub title: Option<String>,
    /// `/Author`: the name of the person who created the document.
    #[cfg_attr(test, serde(skip_serializing_if = "Option::is_none"))]
    pub author: Option<String>,
    /// `/Subject`: the subject of the document.
    #[cfg_attr(test, serde(skip_serializing_if = "Option::is_none"))]
    pub subject: Option<String>,
    /// `/Keywords`: keywords associated with the document.
    #[cfg_attr(test, serde(skip_serializing_if = "Option::is_none"))]
    pub keywords: Option<String>,
    /// `/Creator`: the application that created the original document.
    #[cfg_attr(test, serde(skip_serializing_if = "Option::is_none"))]
    pub creator: Option<String>,
    /// `/Producer`: the application that converted it to PDF.
    #[cfg_attr(test, serde(skip_serializing_if = "Option::is_none"))]
    pub producer: Option<String>,
    /// `/CreationDate`, as a PDF date string.
    #[cfg_attr(test, serde(skip_serializing_if = "Option::is_none"))]
    pub creation_date: Option<String>,
    /// `/ModDate`, as a PDF date string.
    #[cfg_attr(test, serde(skip_serializing_if = "Option::is_none"))]
    pub mod_date: Option<String>,
    /// `/Trapped`.
    #[cfg_attr(test, serde(skip_serializing_if = "Option::is_none"))]
    pub trapped: Option<Trapped>,
    /// Every other entry whose value is a text string, by key (the name without its `/`).
    pub custom: BTreeMap<String, String>,
}

impl From<folioxide::DocInfo> for DocInfo {
    fn from(info: folioxide::DocInfo) -> DocInfo {
        DocInfo {
            title: info.title,
            author: info.author,
            subject: info.subject,
            keywords: info.keywords,
            creator: info.creator,
            producer: info.producer,
            creation_date: info.creation_date.map(|d| d.to_pdf_string()),
            mod_date: info.mod_date.map(|d| d.to_pdf_string()),
            trapped: info.trapped.map(Trapped::from),
            custom: info.custom,
        }
    }
}

/// Changes to the document information dictionary (§14.3.3), for `setInfo` (the core
/// `InfoUpdate`).
///
/// Every field is one change: absent (or `undefined`) keeps the entry, `null` removes it, a value
/// sets it. Text is written as a PDF text string (PDFDocEncoding when every character has a
/// code there, otherwise UTF-16BE), so any Unicode text round-trips. Dates are PDF date strings
/// (the JavaScript facade also takes `Date` objects). `/ModDate` is never set automatically.
#[napi(object)]
#[derive(Default)]
pub struct InfoUpdate {
    /// `/Title`.
    pub title: Option<Either<String, Null>>,
    /// `/Author`.
    pub author: Option<Either<String, Null>>,
    /// `/Subject`.
    pub subject: Option<Either<String, Null>>,
    /// `/Keywords`.
    pub keywords: Option<Either<String, Null>>,
    /// `/Creator`.
    pub creator: Option<Either<String, Null>>,
    /// `/Producer`.
    pub producer: Option<Either<String, Null>>,
    /// `/CreationDate`, as a PDF date string (§7.9.4; partial forms such as `"D:2026"` are
    /// accepted).
    pub creation_date: Option<Either<String, Null>>,
    /// `/ModDate`, as a PDF date string.
    pub mod_date: Option<Either<String, Null>>,
    /// `/Trapped`.
    #[napi(ts_type = "Trapped | null")]
    pub trapped: Option<Either<String, Null>>,
    /// Other entries, by key (the name without its `/`): `null` removes the entry, a string sets
    /// it. A key must not be one of the standard keys above (`Title`, `CreationDate`, …). A key
    /// that is set must not be empty, be longer than 127 bytes in UTF-8 (the PDF name length
    /// limit) or contain a NUL character; any other key can be removed.
    pub custom: Option<HashMap<String, Either<String, Null>>>,
}

impl InfoUpdate {
    /// The core update.
    ///
    /// # Errors
    /// `E_INVALID_ARGUMENT` when a date is not a PDF date or `trapped` is not one of its three
    /// values. (Custom keys are checked by `Document::set_info`.)
    pub fn into_core(self) -> JsResult<folioxide::InfoUpdate> {
        let mut update = folioxide::InfoUpdate::default();
        update.title = self.title.map(text);
        update.author = self.author.map(text);
        update.subject = self.subject.map(text);
        update.keywords = self.keywords.map(text);
        update.creator = self.creator.map(text);
        update.producer = self.producer.map(text);
        update.creation_date = self
            .creation_date
            .map(|value| date(value, "creationDate"))
            .transpose()?;
        update.mod_date = self
            .mod_date
            .map(|value| date(value, "modDate"))
            .transpose()?;
        update.trapped = match self.trapped {
            None => None,
            Some(Either::B(Null)) => Some(None),
            Some(Either::A(value)) => Some(Some(Trapped::parse(&value)?.into())),
        };
        for (key, value) in self.custom.unwrap_or_default() {
            update.custom.insert(key, text(value));
        }
        Ok(update)
    }
}

/// `null` as `None`, a string as `Some`.
fn text(value: Either<String, Null>) -> Option<String> {
    match value {
        Either::A(text) => Some(text),
        Either::B(Null) => None,
    }
}

/// `null` as `None`, a PDF date string as `Some(date)`.
fn date(value: Either<String, Null>, field: &str) -> JsResult<Option<folioxide::PdfDate>> {
    match value {
        Either::B(Null) => Ok(None),
        Either::A(text) => folioxide::PdfDate::parse(text.as_bytes())
            .map(Some)
            .ok_or_else(|| {
                invalid_argument(format!(
                    "{field} must be a PDF date string such as \"D:20261010093000Z\" (ISO \
                     32000-2 §7.9.4) or a Date, not {:?}",
                    short(&text)
                ))
            }),
    }
}

// ---- diagnostics -----------------------------------------------------------------------------

/// A record of one repair or leniency decision made while reading the document (the core
/// `Diagnostic`).
#[napi(object, use_nullable = true)]
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize), serde(rename_all = "camelCase"))]
pub struct Diagnostic {
    /// The byte offset of the problem in the buffer being parsed (the file, or a decoded object
    /// stream), or `null` when it is not tied to a position.
    pub offset: Option<f64>,
    /// The category, a stable `camelCase` identifier such as `"streamLength"` or
    /// `"xrefReconstructed"`.
    pub kind: String,
    /// A human-readable description.
    pub message: String,
}

impl From<folioxide::Diagnostic> for Diagnostic {
    fn from(diagnostic: folioxide::Diagnostic) -> Diagnostic {
        Diagnostic {
            // Byte offsets are below 2^53, where an f64 is exact.
            offset: diagnostic.offset.map(|offset| offset as f64),
            kind: diagnostic.kind.as_str().to_owned(),
            message: diagnostic.message,
        }
    }
}

// ---- options ---------------------------------------------------------------------------------

/// Options for `PdfDocument.open` and `PdfDocument.openAsync`.
#[napi(object)]
#[derive(Clone, Debug, Default)]
pub struct OpenOptions {
    /// Refuse damaged files instead of repairing them (default `false`: repair what can be
    /// repaired and record a diagnostic for each repair).
    pub strict: Option<bool>,
}

impl OpenOptions {
    /// The core options.
    pub fn into_core(self) -> folioxide::OpenOptions {
        let strictness = if self.strict.unwrap_or(false) {
            folioxide::Strictness::Strict
        } else {
            folioxide::Strictness::Lenient
        };
        folioxide::OpenOptions::default().with_strictness(strictness)
    }
}

/// The kind of cross-reference section a full save writes (§7.5.4, §7.5.8).
#[napi(string_enum = "camelCase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XrefStyle {
    /// A cross-reference stream when object streams are on or the source's newest section is a
    /// stream, otherwise a table (the default).
    Auto,
    /// A classic `xref` table (cannot be combined with object streams).
    Table,
    /// A cross-reference stream (the header becomes at least `%PDF-1.5`).
    Stream,
}

impl XrefStyle {
    /// Parses `'auto'`, `'table'` or `'stream'`.
    ///
    /// # Errors
    /// `E_INVALID_ARGUMENT` for any other string.
    pub fn parse(text: &str) -> JsResult<folioxide::XrefStyle> {
        match text {
            "auto" => Ok(folioxide::XrefStyle::Auto),
            "table" => Ok(folioxide::XrefStyle::Table),
            "stream" => Ok(folioxide::XrefStyle::Stream),
            other => Err(invalid_argument(format!(
                "xref must be 'auto', 'table' or 'stream', not {:?}",
                short(other)
            ))),
        }
    }
}

/// How a full save writes stream data.
#[napi(string_enum = "camelCase")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamCompression {
    /// Every stream as it is; new data unfiltered.
    Keep,
    /// New data Flate-encoded; existing streams copied as encoded (the default).
    CompressNew,
    /// Like `compressNew`, and existing streams that can be decoded completely are encoded
    /// again with Flate.
    Recompress,
}

impl StreamCompression {
    /// Parses `'keep'`, `'compressNew'` or `'recompress'`.
    ///
    /// # Errors
    /// `E_INVALID_ARGUMENT` for any other string.
    pub fn parse(text: &str) -> JsResult<folioxide::StreamCompression> {
        match text {
            "keep" => Ok(folioxide::StreamCompression::Keep),
            "compressNew" => Ok(folioxide::StreamCompression::CompressNew),
            "recompress" => Ok(folioxide::StreamCompression::Recompress),
            other => Err(invalid_argument(format!(
                "compress must be 'keep', 'compressNew' or 'recompress', not {:?}",
                short(other)
            ))),
        }
    }
}

/// Options for a full save (`save`, `saveAsync`): the core `SaveOptions`. Every field is
/// optional; the defaults give a compact, garbage-collected, renumbered file.
#[napi(object)]
#[derive(Default)]
pub struct SaveOptions {
    /// The kind of cross-reference section (default `'auto'`).
    #[napi(ts_type = "XrefStyle")]
    pub xref: Option<String>,
    /// Pack objects into object streams (§7.5.7; needs a cross-reference stream). Default
    /// `false`.
    pub object_streams: Option<bool>,
    /// How stream data is written (default `'compressNew'`).
    #[napi(ts_type = "StreamCompression")]
    pub compress: Option<String>,
    /// Write only the objects reachable from the trailer (default `true`).
    pub gc: Option<bool>,
    /// Number the objects densely from 1 (default `true`).
    pub renumber: Option<bool>,
    /// Ask for byte-identical output for identical input and edits (the writer is
    /// deterministic either way; default `false`).
    pub deterministic: Option<bool>,
    /// The file identifier to write (`/ID`, §14.4): two byte strings. Default: the source's
    /// first element and a new second one, or one generated from the content.
    #[napi(ts_type = "[Uint8Array, Uint8Array]")]
    pub id: Option<Vec<Uint8Array>>,
    /// The lowest PDF version for the header: `"1.0"` to `"1.7"` or `"2.0"`.
    pub min_version: Option<String>,
    /// The Flate compression level, an integer from 0 (store) to 9 (best). Default 6.
    pub flate_level: Option<f64>,
}

impl SaveOptions {
    /// The core options, checked as the core's save checks them
    /// ([`folioxide::SaveOptions::validate`]), so that `saveAsync` refuses them before it
    /// starts.
    ///
    /// # Errors
    /// `E_INVALID_ARGUMENT` when a value is not one the option takes (a `minVersion` that is
    /// not a PDF version, `xref: 'table'` with `objectStreams`, …).
    pub fn into_core(self) -> JsResult<folioxide::SaveOptions> {
        let mut options = folioxide::SaveOptions::default();
        if let Some(xref) = self.xref {
            options = options.with_xref(XrefStyle::parse(&xref)?);
        }
        if let Some(object_streams) = self.object_streams {
            options = options.with_object_streams(object_streams);
        }
        if let Some(compress) = self.compress {
            options = options.with_compress(StreamCompression::parse(&compress)?);
        }
        if let Some(gc) = self.gc {
            options = options.with_gc(gc);
        }
        if let Some(renumber) = self.renumber {
            options = options.with_renumber(renumber);
        }
        if let Some(deterministic) = self.deterministic {
            options = options.with_deterministic(deterministic);
        }
        if let Some(id) = self.id {
            let [first, second] = <[Uint8Array; 2]>::try_from(id).map_err(|id| {
                invalid_argument(format!(
                    "id must be two byte arrays, not {} of them",
                    id.len()
                ))
            })?;
            options = options.with_id(Some([first.to_vec(), second.to_vec()]));
        }
        if let Some(version) = self.min_version {
            options = options.with_min_version(Some(parse_version(&version)?));
        }
        if let Some(level) = self.flate_level {
            options = options.with_flate_level(integer_in(level, 0, 9, "flateLevel")? as u8);
        }
        options.validate().map_err(|err| from_core(&err.into()))?;
        Ok(options)
    }
}

/// Options for an incremental save (`saveIncremental`, `saveIncrementalAsync`).
#[napi(object)]
#[derive(Default)]
pub struct IncrementalSaveOptions {
    /// Return only the bytes appended to the original file (an update to append to the file in
    /// place) instead of the whole new file. Default `false`.
    pub suffix_only: Option<bool>,
    /// Ask for byte-identical output for identical input and edits (default `false`).
    pub deterministic: Option<bool>,
    /// The second element of the new `/ID` (§14.4). Default: a digest of the update. The first
    /// element is always kept.
    pub id1: Option<Uint8Array>,
}

impl IncrementalSaveOptions {
    /// The core options and whether only the suffix is wanted.
    pub fn into_core(self) -> (folioxide::IncrementalOptions, bool) {
        let mut options = folioxide::IncrementalOptions::default();
        if let Some(deterministic) = self.deterministic {
            options = options.with_deterministic(deterministic);
        }
        if let Some(id1) = self.id1 {
            options = options.with_id1(Some(id1.to_vec()));
        }
        (options, self.suffix_only.unwrap_or(false))
    }
}

// ---- numbers and versions --------------------------------------------------------------------

/// The PDF version as JavaScript sees it: `"M.m"`, for example `"1.7"`.
pub fn version_string((major, minor): (u8, u8)) -> String {
    format!("{major}.{minor}")
}

/// Parses a version string `"M.m"` (each part an integer from 0 to 255).
///
/// # Errors
/// `E_INVALID_ARGUMENT` for anything else.
pub fn parse_version(text: &str) -> JsResult<(u8, u8)> {
    let parse = |part: &str| {
        (!part.is_empty() && part.len() <= 3 && part.bytes().all(|b| b.is_ascii_digit()))
            .then(|| part.parse::<u8>().ok())
            .flatten()
    };
    text.split_once('.')
        .and_then(|(major, minor)| Some((parse(major)?, parse(minor)?)))
        .ok_or_else(|| {
            invalid_argument(format!(
                "a PDF version must look like \"1.7\", not {:?}",
                short(text)
            ))
        })
}

/// `value` as an integer from `min` to `max`.
///
/// # Errors
/// `E_INVALID_ARGUMENT` when it is not an integer in that range.
pub fn integer_in(value: f64, min: i64, max: i64, name: &str) -> JsResult<i64> {
    let in_range =
        value.is_finite() && value.fract() == 0.0 && value >= min as f64 && value <= max as f64;
    if in_range {
        Ok(value as i64)
    } else {
        Err(invalid_argument(format!(
            "{name} must be an integer from {min} to {max}, not {value}"
        )))
    }
}

/// A 0-based page index from a JavaScript number.
///
/// # Errors
/// `E_INVALID_ARGUMENT` when it is not an integer; `E_PAGE_OUT_OF_RANGE` when it is negative
/// (or too large to be an index).
pub fn page_index(value: f64) -> JsResult<usize> {
    if !value.is_finite() || value.fract() != 0.0 {
        return Err(invalid_argument(format!(
            "a page index must be an integer, not {value}"
        )));
    }
    // 2^32 and above cannot be a page index (a document has fewer objects than that).
    if !(0.0..4_294_967_296.0).contains(&value) {
        return Err(out_of_range(value));
    }
    Ok(value as usize)
}

fn out_of_range(value: f64) -> BindingError {
    page_out_of_range(format!("page index {value} is out of range"))
}

/// A page rotation from a JavaScript number of degrees: any multiple of 90, negative ones
/// included (`-90` is 270).
///
/// # Errors
/// `E_INVALID_ARGUMENT` for anything else.
pub fn rotation(degrees: f64) -> JsResult<folioxide::Rotation> {
    let rotation = (degrees.is_finite() && degrees.fract() == 0.0 && degrees.abs() <= 1e15)
        .then(|| folioxide::Rotation::from_degrees(degrees as i64))
        .flatten();
    rotation.ok_or_else(|| {
        invalid_argument(format!(
            "a page rotation must be a multiple of 90 degrees, not {degrees}"
        ))
    })
}

/// At most the first 40 characters of `text`, for quoting caller input in messages.
fn short(text: &str) -> String {
    text.chars().take(40).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// JSON of a binding DTO equals the core DTO's serde JSON: Node and Tauri see one shape
    /// (ARCHITECTURE §A.7, §A.8). The test derives mirror napi-rs's conversion: `camelCase`
    /// names, `None` left out (`null` for `use_nullable` structs). Numbers compare as
    /// JavaScript numbers (`1234` and `1234.0` are one value there).
    fn assert_same_json<B: serde::Serialize, C: serde::Serialize>(binding: &B, core: &C) {
        let binding = js_numbers(serde_json::to_value(binding).expect("binding DTO serializes"));
        let core = js_numbers(serde_json::to_value(core).expect("core DTO serializes"));
        assert_eq!(binding, core);
    }

    /// `value` with every number as an `f64`, as JavaScript holds it.
    fn js_numbers(value: serde_json::Value) -> serde_json::Value {
        use serde_json::Value;
        match value {
            Value::Number(n) => n
                .as_f64()
                .and_then(serde_json::Number::from_f64)
                .map_or(Value::Null, Value::Number),
            Value::Array(items) => Value::Array(items.into_iter().map(js_numbers).collect()),
            Value::Object(map) => {
                Value::Object(map.into_iter().map(|(k, v)| (k, js_numbers(v))).collect())
            }
            other => other,
        }
    }

    fn sample_document() -> folioxide::Document {
        let mut doc = folioxide::Document::new();
        let date = folioxide::PdfDate::new(2026, 10, 10, 9, 30, 0)
            .and_then(|d| d.with_offset(Some(120)))
            .expect("valid date");
        doc.set_info(
            &folioxide::InfoUpdate::default()
                .with_title(Some("Отчёт 報告 \u{1F600}"))
                .with_author(Some("Folioxide"))
                .with_creation_date(Some(date))
                .with_trapped(Some(folioxide::Trapped::Unknown))
                .with_custom("Department", Some("Finance")),
        )
        .expect("set_info");
        doc
    }

    #[test]
    fn doc_info_json_matches_the_core() {
        let doc = sample_document();
        let core = doc.info().expect("info");
        let binding = DocInfo::from(core.clone());
        assert_same_json(&binding, &core);
        assert_eq!(
            binding.creation_date.as_deref(),
            Some("D:20261010093000+02'00'")
        );
        assert_eq!(binding.trapped, Some(Trapped::Unknown));
        // Absent entries are left out, `custom` is always there.
        let empty = folioxide::DocInfo::default();
        assert_same_json(&DocInfo::from(empty.clone()), &empty);
        let json = serde_json::to_value(DocInfo::from(empty)).expect("serializes");
        assert_eq!(json, serde_json::json!({ "custom": {} }));
    }

    #[test]
    fn page_info_json_matches_the_core() {
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
            2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595 842] >>\nendobj\n\
            3 0 obj\n<< /Type /Page /Parent 2 0 R /Rotate -90 /CropBox [10 10 500.5 800] >>\n\
            endobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";
        let doc = folioxide::Document::open(pdf.to_vec(), &folioxide::OpenOptions::default())
            .expect("opens");
        let core = doc.page(0).expect("page 0").info();
        let binding = PageInfo::from(core);
        assert_same_json(&binding, &core);
        assert_eq!(binding.rotation, 270);
        assert_eq!((binding.width, binding.height), (790.0, 490.5));
        assert_eq!(
            serde_json::to_value(binding).expect("serializes"),
            serde_json::json!({
                "index": 0, "width": 790.0, "height": 490.5,
                "mediaBox": { "llx": 0.0, "lly": 0.0, "urx": 595.0, "ury": 842.0 },
                "cropBox": { "llx": 10.0, "lly": 10.0, "urx": 500.5, "ury": 800.0 },
                "rotation": 270,
            })
        );
    }

    #[test]
    fn diagnostic_json_matches_the_core() {
        let with_offset = folioxide::Diagnostic::new(
            folioxide::DiagnosticKind::StreamLength,
            Some(1234),
            "the /Length is wrong",
        );
        assert_same_json(&Diagnostic::from(with_offset.clone()), &with_offset);
        let without = folioxide::Diagnostic::new(folioxide::DiagnosticKind::PageTree, None, "x");
        assert_same_json(&Diagnostic::from(without.clone()), &without);
        let json = serde_json::to_value(Diagnostic::from(without)).expect("serializes");
        assert_eq!(json["offset"], serde_json::Value::Null);
        assert_eq!(json["kind"], "pageTree");
    }

    #[test]
    fn info_update_three_states() {
        let mut custom = HashMap::new();
        custom.insert("Department".to_owned(), Either::A("Finance".to_owned()));
        custom.insert("Old".to_owned(), Either::B(Null));
        let update = InfoUpdate {
            title: Some(Either::A("Заголовок".to_owned())),
            author: Some(Either::B(Null)),
            creation_date: Some(Either::A("D:2026".to_owned())),
            mod_date: Some(Either::B(Null)),
            trapped: Some(Either::A("false".to_owned())),
            custom: Some(custom),
            ..InfoUpdate::default()
        }
        .into_core()
        .expect("valid update");
        assert_eq!(update.title, Some(Some("Заголовок".to_owned())));
        assert_eq!(update.author, Some(None));
        assert_eq!(update.subject, None);
        assert_eq!(
            update.creation_date,
            Some(folioxide::PdfDate::parse(b"D:2026"))
        );
        assert_eq!(update.mod_date, Some(None));
        assert_eq!(update.trapped, Some(Some(folioxide::Trapped::False)));
        assert_eq!(
            update.custom.get("Department"),
            Some(&Some("Finance".to_owned()))
        );
        assert_eq!(update.custom.get("Old"), Some(&None));
        assert!(InfoUpdate::default().into_core().expect("empty").is_empty());
    }

    #[test]
    fn info_update_rejects_bad_values() {
        let bad_date = InfoUpdate {
            mod_date: Some(Either::A("yesterday".to_owned())),
            ..InfoUpdate::default()
        };
        let err = bad_date.into_core().expect_err("rejected");
        assert_eq!(err.status, "E_INVALID_ARGUMENT");
        assert!(err.reason.contains("modDate"), "{}", err.reason);
        let bad_trapped = InfoUpdate {
            trapped: Some(Either::A("maybe".to_owned())),
            ..InfoUpdate::default()
        };
        let err = bad_trapped.into_core().expect_err("rejected");
        assert_eq!(err.status, "E_INVALID_ARGUMENT");
    }

    #[test]
    fn save_options_convert() {
        let options = SaveOptions {
            xref: Some("stream".to_owned()),
            object_streams: Some(true),
            compress: Some("recompress".to_owned()),
            gc: Some(false),
            renumber: Some(false),
            deterministic: Some(true),
            min_version: Some("1.7".to_owned()),
            flate_level: Some(9.0),
            ..SaveOptions::default()
        }
        .into_core()
        .expect("valid options");
        let expected = folioxide::SaveOptions::default()
            .with_xref(folioxide::XrefStyle::Stream)
            .with_object_streams(true)
            .with_compress(folioxide::StreamCompression::Recompress)
            .with_gc(false)
            .with_renumber(false)
            .with_deterministic(true)
            .with_min_version(Some((1, 7)))
            .with_flate_level(9);
        assert_eq!(options, expected);
        assert_eq!(
            SaveOptions::default().into_core().expect("defaults"),
            folioxide::SaveOptions::default()
        );
        for bad in [
            SaveOptions {
                xref: Some("Table".to_owned()),
                ..SaveOptions::default()
            },
            SaveOptions {
                compress: Some("gzip".to_owned()),
                ..SaveOptions::default()
            },
            SaveOptions {
                min_version: Some("1.x".to_owned()),
                ..SaveOptions::default()
            },
            // Well formed, but not PDF versions (the header would say `%PDF-255.255`).
            SaveOptions {
                min_version: Some("255.255".to_owned()),
                ..SaveOptions::default()
            },
            SaveOptions {
                min_version: Some("9.9".to_owned()),
                ..SaveOptions::default()
            },
            SaveOptions {
                min_version: Some("1.8".to_owned()),
                ..SaveOptions::default()
            },
            SaveOptions {
                min_version: Some("2.1".to_owned()),
                ..SaveOptions::default()
            },
            SaveOptions {
                min_version: Some("0.9".to_owned()),
                ..SaveOptions::default()
            },
            SaveOptions {
                xref: Some("table".to_owned()),
                object_streams: Some(true),
                ..SaveOptions::default()
            },
            SaveOptions {
                flate_level: Some(10.0),
                ..SaveOptions::default()
            },
            SaveOptions {
                flate_level: Some(1.5),
                ..SaveOptions::default()
            },
        ] {
            let err = bad.into_core().expect_err("rejected");
            assert_eq!(err.status, "E_INVALID_ARGUMENT", "{}", err.reason);
        }
    }

    #[test]
    fn page_indices_and_rotations() {
        assert_eq!(page_index(0.0).ok(), Some(0));
        assert_eq!(page_index(41.0).ok(), Some(41));
        assert_eq!(
            page_index(-1.0).err().map(|e| e.status),
            Some("E_PAGE_OUT_OF_RANGE".to_owned())
        );
        assert_eq!(
            page_index(1e20).err().map(|e| e.status),
            Some("E_PAGE_OUT_OF_RANGE".to_owned())
        );
        for bad in [0.5, f64::NAN, f64::INFINITY] {
            assert_eq!(
                page_index(bad).err().map(|e| e.status),
                Some("E_INVALID_ARGUMENT".to_owned())
            );
        }
        assert_eq!(rotation(90.0).ok(), Some(folioxide::Rotation::R90));
        assert_eq!(rotation(-90.0).ok(), Some(folioxide::Rotation::R270));
        assert_eq!(rotation(720.0).ok(), Some(folioxide::Rotation::R0));
        for bad in [45.0, 90.5, f64::NAN, 1e300] {
            assert_eq!(
                rotation(bad).err().map(|e| e.status),
                Some("E_INVALID_ARGUMENT".to_owned())
            );
        }
    }

    #[test]
    fn versions_and_enums_parse() {
        assert_eq!(version_string((1, 7)), "1.7");
        assert_eq!(version_string((2, 0)), "2.0");
        assert_eq!(parse_version("2.0").ok(), Some((2, 0)));
        for bad in ["1", "1.", ".7", "1.7.0", "a.b", "256.0", "-1.7", "1.0000"] {
            assert!(parse_version(bad).is_err(), "{bad}");
        }
        assert_eq!(PageBox::parse("media").ok(), Some(PageBox::Media));
        assert_eq!(PageBox::parse("crop").ok(), Some(PageBox::Crop));
        assert!(PageBox::parse("bleed").is_err());
        assert_eq!(Trapped::parse("unknown").ok(), Some(Trapped::Unknown));
        assert!(Trapped::parse("True").is_err());
        for trapped in [Trapped::True, Trapped::False, Trapped::Unknown] {
            assert_eq!(Trapped::from(folioxide::Trapped::from(trapped)), trapped);
        }
    }
}

//! Visible signature appearances (ISO 32000-2 §12.7.5.5 signature fields, §12.5.6.19 widgets,
//! §12.5.5 appearance streams, §8.10 form XObjects; M4 brief §3.2 and §4.7):
//! [`SignatureAppearance`], what
//! [`SignatureOptions::appearance`](crate::prepare::SignatureOptions::appearance) asks for, and
//! the appearance stream [`prepare`](crate::prepare::prepare) builds from it.
//!
//! **The widget.** The appearance's [`rect`](SignatureAppearance::rect) is in the **default
//! user space** of the page (§8.3.2.3, DECISIONS D13 D-18), the coordinates the page's
//! `/MediaBox` uses, whatever its `/Rotate`. It becomes the widget's `/Rect`, normalized and
//! rounded as the serializer writes it; it must be finite, have an area, intersect the page's
//! crop box and stay within ±10^5 (its coordinates, width and height: the verifier holds a later
//! signer's widget and appearance to that bound, since PDFium maps larger ones in single
//! precision and paints them elsewhere; M4 QA round 4, finding 13; manager ruling R-21). An
//! existing empty signature field keeps its `/Rect`, within the same bound.
//!
//! **The appearance stream** (`/AP /N`) is a form XObject `<< /Type /XObject /Subtype /Form
//! /BBox [0 0 W H] [/Matrix M] /Resources << /Font << /F1 … >> [/XObject << /Im1 … >>] >> >>`,
//! Flate-encoded, with resources of its own (never the AcroForm `/DR`). `(W, H)` is the size the
//! reader sees: the rect's width and height, swapped on a page turned by 90 or 270 degrees, and
//! `/Matrix` turns the drawing against the page's clockwise `/Rotate` (§7.7.3.3) so that the
//! text stands upright on screen, while §12.5.5's transformed bounding box is exactly the rect:
//!
//! | `/Rotate` | `/Matrix` |
//! |---|---|
//! | 0 | none (identity) |
//! | 90 | `[0 1 -1 0 H 0]` |
//! | 180 | `[-1 0 0 -1 W H]` |
//! | 270 | `[0 -1 1 0 0 W]` |
//!
//! **The layout** (M4 brief §4.7), in the form's space `[0 0 W H]`:
//!
//! - a border of [`border_width`](SignatureAppearance::border_width) `bw` (black, stroked inside
//!   the box) when it is positive; everything else is inset by `bw`, then padded by
//!   `p = min(2, W/20, H/20)`;
//! - an image ([`image`](SignatureAppearance::image), JPEG passed through unchanged): on the
//!   [left](ImagePosition::Left), a column `iw = min((H'−2p)·img_w/img_h, (W'−2p)/2)` wide
//!   (`W'`, `H'` the inset box), the image keeping its aspect ratio, vertically centred, the
//!   text to its right; or in the [background](ImagePosition::Background), fitted and centred
//!   behind the text;
//! - the text lines in black, WinAnsi-encoded, from the top: the font size is
//!   [`font_size`](SignatureAppearance::font_size), or `min(12, (H'−2p)/(1.2·n))` for `n` lines,
//!   reduced until the widest line fits, never below 4 points. A line that is still too wide is
//!   cut and ends with `…`, lines below the box are left out, and characters outside WinAnsi
//!   are shown as `?`; each of these gives a warning.
//!
//! The [default text](AppearanceText::Default) is `Digitally signed by <name>` (the signature's
//! [`name`](crate::prepare::SignatureOptions::name), else the signer certificate's common name,
//! else its subject), `Date: <YYYY-MM-DD HH:MM:SS ±HH:MM>` (the claimed
//! [`signing_time`](crate::prepare::SignatureOptions::signing_time), never a timestamp's time),
//! then `Reason: …` and `Location: …` when given.
//!
//! [`Standard14Font`] is this crate's own copy of
//! [`folioxide_content::standard14::Standard14Font`]'s M4 variants, so that it can carry the
//! `serde` names (the content crate has no serde, M4 brief §1: "the crate adds no
//! dependencies"); [`From`] converts it.

use std::fmt;

use folioxide_content::builder::ContentBuilder;
use folioxide_content::encoding::win_ansi_encode;
use folioxide_content::image::jpeg;
use folioxide_content::standard14;
use folioxide_model::{PdfDate, Rect, Rotation};
use folioxide_syntax::serialize::{MAX_REAL, canonical_real};
use folioxide_syntax::{Dict, Object, ObjectId, Stream, StreamData};

use crate::error::{Error, Result};
use crate::field::NewNumbers;
use crate::prepare::SignatureOptions;

/// The largest font size the fitted text uses, in points (M4 brief §4.7).
pub const MAX_FITTED_FONT_SIZE: f64 = 12.0;

/// The smallest font size the fitted text uses, in points; below it, lines are cut instead
/// (M4 brief §4.7).
pub const MIN_FONT_SIZE: f64 = 4.0;

/// The distance between baselines, as a multiple of the font size.
pub const LINE_SPACING: f64 = 1.2;

/// The largest padding inside the border, in points: the padding is `min(2, W/20, H/20)`.
pub const MAX_PADDING: f64 = 2.0;

/// The most text lines an appearance may have.
pub const MAX_LINES: usize = 64;

/// The most characters a text line may have.
pub const MAX_LINE_CHARS: usize = 4096;

/// The largest explicit font size, in points.
pub const MAX_FONT_SIZE: f64 = 1000.0;

/// WinAnsiEncoding `ellipsis` (Annex D.2), which ends a line that was cut.
const ELLIPSIS: u8 = 0x85;

/// The font resource name of the appearance stream.
const FONT_RESOURCE: &[u8] = b"F1";

/// The image resource name of the appearance stream.
const IMAGE_RESOURCE: &[u8] = b"Im1";

/// The font of a visible signature's text (M4 brief §3.2, §4.7; DECISIONS D13 D-16): one of the
/// standard 14 fonts that [`folioxide_content::standard14`] has metrics for, written with
/// WinAnsiEncoding, its `/Widths` and a `/FontDescriptor` (PDF 2.0 deprecates the standard 14
/// fonts' exemption from both, ISO 32000-2 §9.6.2.2), but not embedded: the viewer supplies the
/// font program, so the appearance is not PDF/A conformant (font embedding is M7).
///
/// With the `serde` feature it is `"Helvetica"` or `"Helvetica-Bold"`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Standard14Font {
    /// Helvetica (the default).
    #[default]
    #[cfg_attr(feature = "serde", serde(rename = "Helvetica"))]
    Helvetica,
    /// Helvetica-Bold.
    #[cfg_attr(feature = "serde", serde(rename = "Helvetica-Bold"))]
    HelveticaBold,
}

impl Standard14Font {
    /// The PostScript name, the font dictionary's `/BaseFont`: `"Helvetica"` or
    /// `"Helvetica-Bold"`.
    ///
    /// ```
    /// use folioxide_sign::appearance::Standard14Font;
    ///
    /// assert_eq!(Standard14Font::HelveticaBold.base_font(), "Helvetica-Bold");
    /// ```
    pub fn base_font(self) -> &'static str {
        standard14::Standard14Font::from(self).base_font()
    }
}

impl From<Standard14Font> for standard14::Standard14Font {
    fn from(font: Standard14Font) -> Self {
        match font {
            Standard14Font::Helvetica => standard14::Standard14Font::Helvetica,
            Standard14Font::HelveticaBold => standard14::Standard14Font::HelveticaBold,
        }
    }
}

/// The text of a visible signature (M4 brief §4.7 "Text lines").
///
/// With the `serde` feature it is `"default"` or `{"lines": ["…", …]}`.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum AppearanceText {
    /// `Digitally signed by <name>`, `Date: <signing time>`, and `Reason: …` and `Location: …`
    /// when given.
    #[default]
    Default,
    /// These lines, in order.
    Lines(Vec<String>),
}

/// Where a visible signature's image goes (M4 brief §4.7 "Layout").
///
/// With the `serde` feature it is `"left"` or `"background"`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum ImagePosition {
    /// A column on the left, the text to its right (the default).
    #[default]
    Left,
    /// Fitted and centred behind the text.
    Background,
}

/// The appearance of a visible signature (M4 brief §3.2, §4.7): where its widget goes, and
/// what its appearance stream shows.
///
/// The text uses a [`Standard14Font`] that is not embedded: a visible signature added to a
/// PDF/A document makes it non-conformant (PDF/A requires embedded fonts; embedding is M7).
///
/// Two appearances are equal when every field is, numbers compared by their bits (so equality is
/// an equivalence relation, which makes [`SignatureOptions`] `Eq`). `Debug` prints the image's length, not its bytes.
///
/// With the `serde` feature its fields are `camelCase`; all but `rect` are optional.
///
/// ```
/// use folioxide_model::Rect;
/// use folioxide_sign::appearance::{AppearanceText, SignatureAppearance};
///
/// let appearance = SignatureAppearance::new(Rect::new(300.0, 100.0, 500.0, 160.0))
///     .with_text(AppearanceText::Lines(vec!["Approved".into()]))
///     .with_border_width(1.0);
/// assert_eq!(appearance.rect.map(|r| r.width()), Some(200.0));
/// assert_eq!(SignatureAppearance::for_existing_field().rect, None);
/// ```
#[non_exhaustive]
#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SignatureAppearance {
    /// The widget rectangle in the default user space of
    /// [`FieldSpec::page`](crate::field::FieldSpec)'s page; `None`: the existing field's widget
    /// `/Rect`, which is never changed.
    #[cfg_attr(feature = "serde", serde(default))]
    pub rect: Option<Rect>,
    /// The text lines.
    #[cfg_attr(feature = "serde", serde(default))]
    pub text: AppearanceText,
    /// The font of the text.
    #[cfg_attr(feature = "serde", serde(default))]
    pub font: Standard14Font,
    /// The font size in points; `None`: the largest size from 4 to 12 points that fits.
    #[cfg_attr(feature = "serde", serde(default))]
    pub font_size: Option<f64>,
    /// A JPEG image, embedded unchanged (DCT passthrough, DECISIONS D13 D-17).
    #[cfg_attr(feature = "serde", serde(default))]
    pub image: Option<Vec<u8>>,
    /// Where the image goes.
    #[cfg_attr(feature = "serde", serde(default))]
    pub image_position: ImagePosition,
    /// The border width in points; 0: no border.
    #[cfg_attr(feature = "serde", serde(default))]
    pub border_width: f64,
}

impl SignatureAppearance {
    /// An appearance for a new widget at `rect` (default user space), with the default text,
    /// Helvetica, a fitted size, no image and no border.
    pub fn new(rect: Rect) -> Self {
        SignatureAppearance {
            rect: Some(rect),
            ..Self::for_existing_field()
        }
    }

    /// An appearance for an existing signature field's widget, at its `/Rect`.
    pub fn for_existing_field() -> Self {
        SignatureAppearance {
            rect: None,
            text: AppearanceText::Default,
            font: Standard14Font::Helvetica,
            font_size: None,
            image: None,
            image_position: ImagePosition::Left,
            border_width: 0.0,
        }
    }

    /// Sets [`SignatureAppearance::rect`].
    #[must_use]
    pub fn with_rect(mut self, rect: Option<Rect>) -> Self {
        self.rect = rect;
        self
    }

    /// Sets [`SignatureAppearance::text`].
    #[must_use]
    pub fn with_text(mut self, text: AppearanceText) -> Self {
        self.text = text;
        self
    }

    /// Sets [`SignatureAppearance::font`].
    #[must_use]
    pub fn with_font(mut self, font: Standard14Font) -> Self {
        self.font = font;
        self
    }

    /// Sets [`SignatureAppearance::font_size`].
    #[must_use]
    pub fn with_font_size(mut self, font_size: Option<f64>) -> Self {
        self.font_size = font_size;
        self
    }

    /// Sets [`SignatureAppearance::image`].
    #[must_use]
    pub fn with_image(mut self, image: Option<Vec<u8>>) -> Self {
        self.image = image;
        self
    }

    /// Sets [`SignatureAppearance::image_position`].
    #[must_use]
    pub fn with_image_position(mut self, image_position: ImagePosition) -> Self {
        self.image_position = image_position;
        self
    }

    /// Sets [`SignatureAppearance::border_width`].
    #[must_use]
    pub fn with_border_width(mut self, border_width: f64) -> Self {
        self.border_width = border_width;
        self
    }
}

/// The bits of a rectangle's coordinates, for [`PartialEq`].
fn rect_bits(rect: Option<Rect>) -> Option<[u64; 4]> {
    rect.map(|r| [r.llx, r.lly, r.urx, r.ury].map(f64::to_bits))
}

impl PartialEq for SignatureAppearance {
    /// Field by field, numbers by their bits.
    fn eq(&self, other: &Self) -> bool {
        rect_bits(self.rect) == rect_bits(other.rect)
            && self.text == other.text
            && self.font == other.font
            && self.font_size.map(f64::to_bits) == other.font_size.map(f64::to_bits)
            && self.image == other.image
            && self.image_position == other.image_position
            && self.border_width.to_bits() == other.border_width.to_bits()
    }
}

impl Eq for SignatureAppearance {}

impl fmt::Debug for SignatureAppearance {
    /// Prints the image's length, not its bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureAppearance")
            .field("rect", &self.rect)
            .field("text", &self.text)
            .field("font", &self.font)
            .field("font_size", &self.font_size)
            .field("image_len", &self.image.as_ref().map(Vec::len))
            .field("image_position", &self.image_position)
            .field("border_width", &self.border_width)
            .finish()
    }
}

// =================================================================================================
// Building the appearance (M4 brief §4.7)
// =================================================================================================

/// The appearance stream of a visible signature and the objects it uses, as overlay objects
/// with new numbers (see the [module documentation](self)).
#[derive(Debug)]
pub(crate) struct BuiltAppearance {
    /// The form XObject: the widget's `/AP /N`.
    pub(crate) normal: ObjectId,
    /// The form XObject, its font dictionary and its image XObject (if any), in that order.
    pub(crate) objects: Vec<(ObjectId, Object)>,
    /// Replaced characters, shortened lines, lines left out, an image left out.
    pub(crate) warnings: Vec<String>,
}

/// The text lines of `appearance` for a signature with `options`: its own
/// [`Lines`](AppearanceText::Lines), or the [default text](AppearanceText::Default) with
/// `signer` (the signer certificate's common name, else its subject) as the name when the
/// options have none; without either, the default text has no `Digitally signed by` line.
pub(crate) fn text_lines(
    appearance: &SignatureAppearance,
    options: &SignatureOptions,
    signer: Option<&str>,
) -> Vec<String> {
    match &appearance.text {
        AppearanceText::Lines(lines) => lines.clone(),
        AppearanceText::Default => {
            let mut lines = Vec::with_capacity(4);
            if let Some(name) = options.name.as_deref().or(signer) {
                lines.push(format!("Digitally signed by {name}"));
            }
            lines.push(format!("Date: {}", display_date(&options.signing_time)));
            if let Some(reason) = &options.reason {
                lines.push(format!("Reason: {reason}"));
            }
            if let Some(location) = &options.location {
                lines.push(format!("Location: {location}"));
            }
            lines
        }
    }
}

/// `YYYY-MM-DD HH:MM:SS ±HH:MM` (no offset when the date has none, §7.9.4).
fn display_date(date: &PdfDate) -> String {
    let mut text = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        date.year, date.month, date.day, date.hour, date.minute, date.second
    );
    if let Some(offset) = date.offset_minutes {
        let sign = if offset < 0 { '-' } else { '+' };
        let minutes = offset.unsigned_abs();
        text.push_str(&format!(" {sign}{:02}:{:02}", minutes / 60, minutes % 60));
    }
    text
}

/// `rect` as a new widget's `/Rect` (M4 brief §4.7 "Validation"): normalized, each coordinate
/// rounded as the serializer writes it.
///
/// # Errors
/// [`Error::InvalidArgument`] when a coordinate is not finite, when a coordinate, the width or
/// the height is beyond ±10^5 ([`geometry::MAX_GEOMETRY_MAGNITUDE`]: the verifier makes a later
/// signer's widget or appearance that large `Other`, since PDFium places it elsewhere; M4 QA
/// round 4, finding 13; manager ruling R-21), when the rounded rectangle has no area, or when it
/// does not intersect
/// `crop_box`.
///
/// [`geometry::MAX_GEOMETRY_MAGNITUDE`]: crate::revisions::geometry::MAX_GEOMETRY_MAGNITUDE
pub(crate) fn checked_rect(rect: Rect, crop_box: Rect) -> Result<Rect> {
    let coords = [rect.llx, rect.lly, rect.urx, rect.ury];
    if !coords.iter().all(|v| v.is_finite() && v.abs() <= MAX_REAL) {
        return Err(Error::InvalidArgument(
            "the appearance rect must have four finite coordinates".to_owned(),
        ));
    }
    let [x1, y1, x2, y2] = coords.map(canonical_real);
    let rect = Rect::new(x1, y1, x2, y2);
    rect_within_magnitude(&rect)?;
    if !(rect.width() > 0.0 && rect.height() > 0.0) {
        return Err(Error::InvalidArgument(format!(
            "the appearance rect [{x1} {y1} {x2} {y2}] has no area"
        )));
    }
    if rect.intersect(&crop_box).is_none() {
        return Err(Error::InvalidArgument(format!(
            "the appearance rect [{} {} {} {}] lies outside the page's crop box [{} {} {} {}] \
             (the rect is in the page's default user space, ISO 32000-2 §8.3.2.3)",
            rect.llx,
            rect.lly,
            rect.urx,
            rect.ury,
            crop_box.llx,
            crop_box.lly,
            crop_box.urx,
            crop_box.ury
        )));
    }
    Ok(rect)
}

/// [`Error::InvalidArgument`] unless every coordinate of `rect`, its width and its height are
/// within ±10^5 (`geometry::MAX_GEOMETRY_MAGNITUDE`): its appearance's `/BBox`, its `/Matrix`
/// and the `/BBox` mapped through it are then within the bound the verifier holds new
/// appearances to (M4 QA round 4, finding 13; manager ruling R-21). That mapped box has the
/// rect's size and lies within ±10^5 of the origin, so the verifier's precision bound holds too
/// (`geometry::MAX_APPEARANCE_AMPLIFICATION`, 2^20: the coordinate times the scale onto the
/// rect, which is 1 here; M4 final fix round 2, findings 2 and 4).
pub(crate) fn rect_within_magnitude(rect: &Rect) -> Result<()> {
    let max = crate::revisions::geometry::MAX_GEOMETRY_MAGNITUDE;
    let values = [
        rect.llx,
        rect.lly,
        rect.urx,
        rect.ury,
        rect.width(),
        rect.height(),
    ];
    if values.iter().all(|v| v.is_finite() && v.abs() <= max) {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "the appearance rect [{} {} {} {}] has a coordinate, width or height beyond \
             ±{max:e}; viewers that map appearances in single precision (PDFium) would place it \
             elsewhere",
            rect.llx, rect.lly, rect.urx, rect.ury
        )))
    }
}

/// `(W, H)`: the size the reader sees of a widget `rect` on a page turned by `rotation`, each
/// rounded as the serializer writes it.
fn visual_size(rect: Rect, rotation: Rotation) -> (f64, f64) {
    let (w, h) = (canonical_real(rect.width()), canonical_real(rect.height()));
    if matches!(rotation, Rotation::R90 | Rotation::R270) {
        (h, w)
    } else {
        (w, h)
    }
}

/// The `/Matrix` of the appearance of visual size `(w, h)` on a page turned by `rotation`
/// (M4 brief §4.7; `None` for an upright page): §12.5.5's transformed `/BBox` is then
/// `[0 0 w h]` or `[0 0 h w]`, the rect's size, and the drawing turns against the page.
fn rotation_matrix(rotation: Rotation, w: f64, h: f64) -> Option<[f64; 6]> {
    match rotation {
        Rotation::R90 => Some([0.0, 1.0, -1.0, 0.0, h, 0.0]),
        Rotation::R180 => Some([-1.0, 0.0, 0.0, -1.0, w, h]),
        Rotation::R270 => Some([0.0, -1.0, 1.0, 0.0, 0.0, w]),
        _ => None,
    }
}

/// An integral value as an integer object, anything else as a real.
fn number(v: f64) -> Object {
    if v.fract() == 0.0 && v.abs() <= f64::from(i32::MAX) {
        Object::Int(v as i64)
    } else {
        Object::Real(v)
    }
}

/// Where everything goes in the form's space `[0 0 width height]`.
#[derive(Clone, Debug, PartialEq)]
struct Layout {
    width: f64,
    height: f64,
    /// The font size in points.
    font_size: f64,
    /// The start of the first line.
    text_x: f64,
    /// The first baseline.
    first_baseline: f64,
    /// The lines drawn, WinAnsi-encoded (shortened ones end with `…`).
    lines: Vec<Vec<u8>>,
    /// The image's `[x, y, w, h]`, when it is drawn.
    image: Option<[f64; 4]>,
    warnings: Vec<String>,
}

/// A tolerance for comparing lengths in points.
const EPSILON: f64 = 1e-9;

/// The warning that `shortened` of the `total` lines of the appearance text were shortened to
/// fit at `font_size`, its verbs agreeing with the count (M4 QA round 5, finding 3).
fn shortened_warning(shortened: usize, total: usize, font_size: f64) -> String {
    match (shortened, total) {
        (_, 1) => format!(
            "the line of the appearance text is too wide for the rect at {font_size} pt and was \
             shortened (it ends with …)"
        ),
        (1, _) => format!(
            "1 of the {total} lines of the appearance text is too wide for the rect at \
             {font_size} pt and was shortened (it ends with …)"
        ),
        _ => format!(
            "{shortened} of the {total} lines of the appearance text are too wide for the rect \
             at {font_size} pt and were shortened (they end with …)"
        ),
    }
}

/// The warning that only `drawn` of the `total` lines of the appearance text fit at
/// `font_size`, its verbs agreeing with the counts.
fn dropped_warning(drawn: usize, total: usize, font_size: f64) -> String {
    let left_out = if total - drawn == 1 {
        "the other is left out"
    } else {
        "the others are left out"
    };
    match drawn {
        0 => format!(
            "none of the {total} lines of the appearance text fit in the rect at {font_size} pt; \
             they are left out"
        ),
        1 => format!(
            "only 1 of the {total} lines of the appearance text fits in the rect at {font_size} \
             pt; {left_out}"
        ),
        _ => format!(
            "only {drawn} of the {total} lines of the appearance text fit in the rect at \
             {font_size} pt; {left_out}"
        ),
    }
}

/// The layout of `appearance` in a form of size `(width, height)` with the text `lines` and an
/// image of `image` pixels (M4 brief §4.7 "Layout").
fn layout(
    appearance: &SignatureAppearance,
    width: f64,
    height: f64,
    lines: &[String],
    image: Option<(u16, u16)>,
) -> Layout {
    let font = standard14::Standard14Font::from(appearance.font);
    let bw = appearance.border_width;
    let p = MAX_PADDING.min(width / 20.0).min(height / 20.0);
    let (inner_w, inner_h) = (width - 2.0 * bw, height - 2.0 * bw);
    let mut warnings = Vec::new();

    // The image, and where the text starts.
    let mut text_x = bw + p;
    let mut drawn = None;
    if let Some((pixels_w, pixels_h)) = image {
        let (img_w, img_h) = (f64::from(pixels_w), f64::from(pixels_h));
        let placed = match appearance.image_position {
            ImagePosition::Background => {
                let scale = ((inner_w - 2.0 * p) / img_w).min((inner_h - 2.0 * p) / img_h);
                let (w, h) = (img_w * scale, img_h * scale);
                [bw + (inner_w - w) / 2.0, bw + (inner_h - h) / 2.0, w, h]
            }
            _ => {
                let w = ((inner_h - 2.0 * p) * img_w / img_h).min((inner_w - 2.0 * p) / 2.0);
                let h = w * img_h / img_w;
                [bw + p, bw + (inner_h - h) / 2.0, w, h]
            }
        };
        if placed[2] > EPSILON && placed[3] > EPSILON {
            if appearance.image_position != ImagePosition::Background {
                text_x = bw + p + placed[2] + p;
            }
            drawn = Some(placed);
        } else {
            warnings
                .push("the appearance rect is too small for the image; it is left out".to_owned());
        }
    }

    // The text: WinAnsi, then the font size.
    let encoded: Vec<_> = lines.iter().map(|line| win_ansi_encode(line)).collect();
    let replaced: usize = encoded.iter().map(|text| text.replaced).sum();
    match replaced {
        0 => {}
        1 => warnings.push(
            "1 character cannot be shown with the standard 14 fonts (embedded fonts: M7)"
                .to_owned(),
        ),
        n => warnings.push(format!(
            "{n} characters cannot be shown with the standard 14 fonts (embedded fonts: M7)"
        )),
    }
    let text_w = (width - bw - p - text_x).max(0.0);
    let widest = |size: f64| {
        encoded
            .iter()
            .map(|text| font.text_width(&text.bytes, size))
            .fold(0.0, f64::max)
    };
    let font_size = match appearance.font_size {
        Some(size) => size,
        None => {
            let count = encoded.len().max(1) as f64;
            let mut size = ((inner_h - 2.0 * p) / (count * LINE_SPACING)).min(MAX_FITTED_FONT_SIZE);
            let wide = widest(size);
            if wide > text_w && wide > 0.0 {
                size *= text_w / wide;
            }
            // Hundredths of a point, rounded down: the text still fits.
            size = (size * 100.0).floor() / 100.0;
            if size.is_nan() || size < MIN_FONT_SIZE {
                MIN_FONT_SIZE
            } else {
                size
            }
        }
    };

    // Lines that are still too wide are cut; lines below the box are left out.
    let em = font_size / 1000.0;
    let ellipsis = f64::from(font.win_ansi_width(ELLIPSIS)) * em;
    let mut shortened = 0usize;
    let mut drawn_lines = Vec::with_capacity(encoded.len());
    let first_baseline = height - bw - p - font_size * f64::from(font.ascent()) / 1000.0;
    let bottom = bw + p;
    for (index, text) in encoded.iter().enumerate() {
        let baseline = first_baseline - index as f64 * LINE_SPACING * font_size;
        if index > 0 && baseline + font_size * f64::from(font.descent()) / 1000.0 < bottom - EPSILON
        {
            break;
        }
        if font.text_width(&text.bytes, font_size) <= text_w + EPSILON {
            drawn_lines.push(text.bytes.clone());
            continue;
        }
        shortened += 1;
        let mut used = ellipsis;
        let mut cut = Vec::with_capacity(text.bytes.len());
        for &code in &text.bytes {
            let advance = f64::from(font.win_ansi_width(code)) * em;
            if used + advance > text_w + EPSILON {
                break;
            }
            used += advance;
            cut.push(code);
        }
        cut.push(ELLIPSIS);
        drawn_lines.push(cut);
    }
    if shortened > 0 {
        warnings.push(shortened_warning(shortened, encoded.len(), font_size));
    }
    if drawn_lines.len() < encoded.len() {
        warnings.push(dropped_warning(drawn_lines.len(), encoded.len(), font_size));
    }
    Layout {
        width,
        height,
        font_size,
        text_x,
        first_baseline,
        lines: drawn_lines,
        image: drawn,
        warnings,
    }
}

/// The content stream of `layout` (M4 brief §4.7 "Operators"): `q [border] [image] BT /F1 s Tf
/// 0 g x y0 Td (l1) Tj 0 -1.2s Td (l2) Tj … ET Q`.
fn content(layout: &Layout, border_width: f64) -> Result<Vec<u8>> {
    let mut content = ContentBuilder::new();
    content.save();
    if border_width > 0.0 {
        let bw = border_width;
        content
            .line_width(bw)
            .stroke_gray(0.0)
            .rect(bw / 2.0, bw / 2.0, layout.width - bw, layout.height - bw)
            .stroke();
    }
    if let Some([x, y, w, h]) = layout.image {
        content
            .save()
            .concat([w, 0.0, 0.0, h, x, y])
            .draw_xobject(IMAGE_RESOURCE)
            .restore();
    }
    if !layout.lines.is_empty() {
        content
            .begin_text()
            .font(FONT_RESOURCE, layout.font_size)
            .fill_gray(0.0)
            .move_text(layout.text_x, layout.first_baseline);
        for (index, line) in layout.lines.iter().enumerate() {
            if index > 0 {
                content.move_text(0.0, -LINE_SPACING * layout.font_size);
            }
            content.show(line);
        }
        content.end_text();
    }
    content.restore();
    Ok(content.finish()?)
}

/// Checks the caller's values of `appearance` for a form of size `(width, height)` with
/// `lines`.
fn check(
    appearance: &SignatureAppearance,
    width: f64,
    height: f64,
    lines: &[String],
) -> Result<()> {
    let invalid = |message: String| Err(Error::InvalidArgument(message));
    if let Some(size) = appearance.font_size
        && !(size.is_finite() && size > 0.0 && size <= MAX_FONT_SIZE)
    {
        return invalid(format!(
            "the appearance font size must be above 0 and at most {MAX_FONT_SIZE} points, not \
             {size}"
        ));
    }
    let bw = appearance.border_width;
    if !(bw.is_finite() && bw >= 0.0) {
        return invalid(format!(
            "the appearance border width must be 0 or more, not {bw}"
        ));
    }
    if 2.0 * bw >= width.min(height) {
        return invalid(format!(
            "the appearance border width {bw} leaves no room inside the {width} x {height} rect"
        ));
    }
    if lines.len() > MAX_LINES {
        return invalid(format!(
            "the appearance text has {} lines; at most {MAX_LINES} are allowed",
            lines.len()
        ));
    }
    if let Some(line) = lines
        .iter()
        .find(|line| line.chars().count() > MAX_LINE_CHARS)
    {
        return invalid(format!(
            "an appearance text line has {} characters; at most {MAX_LINE_CHARS} are allowed",
            line.chars().count()
        ));
    }
    Ok(())
}

/// The appearance XObject of `appearance` and its resources as overlay objects (new numbers
/// from `numbers`), for a widget of `rect` (default user space, as
/// [`checked_rect`] returns it) on a page turned by `rotation`, showing `lines` (M4 brief §3.2,
/// §4.7); warnings for replaced characters and cut or left-out lines.
///
/// # Errors
/// - [`Error::InvalidArgument`]: a font size that is not finite or outside `(0, 1000]`, a border
///   width that is negative, not finite or leaves no room, more than [`MAX_LINES`] lines or a
///   line of more than [`MAX_LINE_CHARS`] characters, a rect without area.
/// - The image errors of [`jpeg::image_xobject`]: `Image` for data that is not a JPEG,
///   `Unsupported` for one this version cannot pass through (CMYK, 12-bit, arithmetic or
///   lossless coding, DNL heights).
/// - [`ErrorCode::LimitExceeded`](folioxide_syntax::ErrorCode::LimitExceeded) when no object
///   number is left.
pub(crate) fn build(
    appearance: &SignatureAppearance,
    rect: Rect,
    rotation: Rotation,
    lines: &[String],
    numbers: &mut NewNumbers,
) -> Result<BuiltAppearance> {
    let (width, height) = visual_size(rect, rotation);
    if !(width > 0.0 && height > 0.0) {
        return Err(Error::InvalidArgument(
            "the signature widget has no area, so it cannot show an appearance".to_owned(),
        ));
    }
    check(appearance, width, height, lines)?;
    let image = match &appearance.image {
        Some(data) => Some(jpeg::image_xobject(data.clone())?),
        None => None,
    };
    let layout = layout(
        appearance,
        width,
        height,
        lines,
        image.as_ref().map(|(_, info)| (info.width, info.height)),
    );
    let data = content(&layout, appearance.border_width)?;

    let form = numbers.take()?;
    let font = numbers.take()?;
    let descriptor = numbers.take()?;
    let image = match image {
        Some((stream, _)) if layout.image.is_some() => Some((numbers.take()?, stream)),
        _ => None,
    };
    let mut fonts = Dict::with_capacity(1);
    fonts.insert(FONT_RESOURCE, font);
    let mut resources = Dict::with_capacity(2);
    resources.insert("Font", fonts);
    if let Some((id, _)) = &image {
        let mut xobjects = Dict::with_capacity(1);
        xobjects.insert(IMAGE_RESOURCE, *id);
        resources.insert("XObject", xobjects);
    }
    let mut dict = Dict::with_capacity(6);
    dict.insert("Type", Object::name("XObject"));
    dict.insert("Subtype", Object::name("Form"));
    dict.insert(
        "BBox",
        Object::Array(vec![
            number(0.0),
            number(0.0),
            number(width),
            number(height),
        ]),
    );
    if let Some(matrix) = rotation_matrix(rotation, width, height) {
        dict.insert("Matrix", Object::Array(matrix.map(number).to_vec()));
    }
    dict.insert("Resources", resources);
    // §8.10: a form XObject; the writer Flate-encodes the decoded data.
    let stream = Stream::new(dict, StreamData::Decoded(data));
    // §9.6.2.2 Table 109: PDF 2.0 deprecates the standard 14 fonts' exemption, so the font
    // dictionary carries /Widths and an indirect /FontDescriptor (no font program: the viewer
    // supplies the font).
    let standard = standard14::Standard14Font::from(appearance.font);
    let mut font_dict = standard.font_dict();
    font_dict.insert("FontDescriptor", descriptor);

    let mut objects = vec![
        (form, Object::Stream(Box::new(stream))),
        (font, Object::Dict(font_dict)),
        (descriptor, Object::Dict(standard.font_descriptor())),
    ];
    if let Some((id, stream)) = image {
        objects.push((id, Object::Stream(Box::new(stream))));
    }
    Ok(BuiltAppearance {
        normal: form,
        objects,
        warnings: layout.warnings,
    })
}

/// The `/AP` dictionary of a widget whose normal appearance is `normal`: `<< /N normal >>`.
pub(crate) fn ap_dict(normal: ObjectId) -> Dict {
    let mut ap = Dict::with_capacity(1);
    ap.insert("N", normal);
    ap
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builders_equality_and_debug() {
        let rect = Rect::new(300.0, 100.0, 500.0, 160.0);
        let appearance = SignatureAppearance::new(rect)
            .with_text(AppearanceText::Lines(vec!["A".into()]))
            .with_font(Standard14Font::HelveticaBold)
            .with_font_size(Some(9.0))
            .with_image(Some(vec![0xFF, 0xD8, 0xFF]))
            .with_image_position(ImagePosition::Background)
            .with_border_width(1.5);
        assert_eq!(appearance, appearance.clone());
        assert_ne!(appearance, appearance.clone().with_border_width(2.0));
        assert_ne!(appearance, appearance.clone().with_rect(None));
        let nan = appearance.clone().with_font_size(Some(f64::NAN));
        assert_eq!(nan, nan.clone(), "equality is reflexive, NaN included");
        let debug = format!("{appearance:?}");
        assert!(debug.contains("image_len: Some(3)"), "{debug}");

        let existing = SignatureAppearance::for_existing_field();
        assert_eq!(existing.rect, None);
        assert_eq!(existing.text, AppearanceText::Default);
        assert_eq!(existing.font, Standard14Font::Helvetica);
        assert_eq!(existing.image_position, ImagePosition::Left);
        assert_eq!(
            existing.with_rect(Some(rect)),
            SignatureAppearance::new(rect)
        );
    }

    fn lines(texts: &[&str]) -> Vec<String> {
        texts.iter().map(|t| (*t).to_owned()).collect()
    }

    fn time() -> PdfDate {
        PdfDate::parse(b"D:20261010120000+02'00'").unwrap()
    }

    #[test]
    fn default_text_lines() {
        let appearance = SignatureAppearance::for_existing_field();
        let options = SignatureOptions::new(time())
            .with_reason(Some("Approved".into()))
            .with_location(Some("Berlin".into()));
        assert_eq!(
            text_lines(&appearance, &options, Some("Folioxide Test Signer")),
            [
                "Digitally signed by Folioxide Test Signer",
                "Date: 2026-10-10 12:00:00 +02:00",
                "Reason: Approved",
                "Location: Berlin"
            ]
        );
        // The options' /Name wins over the certificate; without either the line is left out.
        let named = options.clone().with_name(Some("Alice".into()));
        assert_eq!(
            text_lines(&appearance, &named, Some("CN"))[0],
            "Digitally signed by Alice"
        );
        let plain = SignatureOptions::new(PdfDate::parse(b"D:20261010120000").unwrap());
        assert_eq!(
            text_lines(&appearance, &plain, None),
            ["Date: 2026-10-10 12:00:00"]
        );
        let west = SignatureOptions::new(PdfDate::parse(b"D:20261010120000-05'30'").unwrap());
        assert_eq!(
            text_lines(&appearance, &west, None),
            ["Date: 2026-10-10 12:00:00 -05:30"]
        );
        let custom = appearance.with_text(AppearanceText::Lines(lines(&["A", "B"])));
        assert_eq!(text_lines(&custom, &options, Some("CN")), ["A", "B"]);
    }

    #[test]
    fn rects_are_checked_and_rounded() {
        let crop = Rect::new(0.0, 0.0, 612.0, 792.0);
        let r = checked_rect(Rect::new(500.1, 160.0, 300.0, 100.0), crop).unwrap();
        assert_eq!([r.llx, r.lly, r.urx, r.ury], [300.0, 100.0, 500.1, 160.0]);
        // Up to 10^5 (the coordinates, the width and the height) is allowed (ruling R-21).
        assert!(checked_rect(Rect::new(0.0, 0.0, 1e5, 100.0), crop).is_ok());
        for bad in [
            Rect::new(0.0, 0.0, 0.0, 10.0),
            Rect::new(0.0, 0.0, 1e-12, 1e-12),
            {
                let mut nan = Rect::new(0.0, 0.0, 1.0, 1.0);
                nan.llx = f64::NAN;
                nan
            },
            Rect::new(0.0, 0.0, f64::INFINITY, 1.0),
            Rect::new(700.0, 0.0, 800.0, 50.0),
            Rect::new(-100.0, -100.0, 0.0, 0.0),
            // M4 QA round 4, finding 13 (api_probe3 `rect-1e15-huge`), and manager ruling R-21:
            // beyond ±10^5.
            Rect::new(-1e15, -1e15, 1e15, 1e15),
            Rect::new(60.0, -1e9, 260.0, 260.0),
            Rect::new(-6e4, 0.0, 6e4, 100.0),
            Rect::new(0.0, 0.0, 100_001.0, 100.0),
        ] {
            let err = checked_rect(bad, crop).unwrap_err();
            assert_eq!(
                err.code(),
                folioxide_syntax::ErrorCode::InvalidArgument,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn rotation_matrices_map_the_bbox_onto_the_rect() {
        let rect = Rect::new(300.0, 100.0, 500.0, 160.0);
        for rotation in [Rotation::R0, Rotation::R90, Rotation::R180, Rotation::R270] {
            let (w, h) = visual_size(rect, rotation);
            let m = rotation_matrix(rotation, w, h).unwrap_or([1.0, 0.0, 0.0, 1.0, 0.0, 0.0]);
            let corners = [(0.0, 0.0), (w, 0.0), (0.0, h), (w, h)]
                .map(|(x, y)| (m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]));
            let min_x = corners.iter().map(|c| c.0).fold(f64::MAX, f64::min);
            let max_x = corners.iter().map(|c| c.0).fold(f64::MIN, f64::max);
            let min_y = corners.iter().map(|c| c.1).fold(f64::MAX, f64::min);
            let max_y = corners.iter().map(|c| c.1).fold(f64::MIN, f64::max);
            // §12.5.5 step b then only translates: the transformed BBox has the rect's size.
            assert_eq!((min_x, min_y), (0.0, 0.0), "{rotation:?}");
            assert_eq!((max_x, max_y), (200.0, 60.0), "{rotation:?}");
        }
        assert_eq!(visual_size(rect, Rotation::R90), (60.0, 200.0));
        assert_eq!(rotation_matrix(Rotation::R0, 200.0, 60.0), None);
        assert_eq!(
            rotation_matrix(Rotation::R90, 60.0, 200.0),
            Some([0.0, 1.0, -1.0, 0.0, 200.0, 0.0])
        );
        assert_eq!(
            rotation_matrix(Rotation::R180, 200.0, 60.0),
            Some([-1.0, 0.0, 0.0, -1.0, 200.0, 60.0])
        );
        assert_eq!(
            rotation_matrix(Rotation::R270, 60.0, 200.0),
            Some([0.0, -1.0, 1.0, 0.0, 0.0, 60.0])
        );
    }

    #[test]
    fn layout_fits_the_text() {
        let appearance = SignatureAppearance::new(Rect::new(0.0, 0.0, 200.0, 60.0));
        let two = lines(&["Digitally signed by A", "Date: 2026-10-10"]);
        let l = layout(&appearance, 200.0, 60.0, &two, None);
        // p = 2; min(12, 56 / 2.4) = 12, and the widest line fits.
        assert_eq!(l.font_size, 12.0);
        assert_eq!(l.text_x, 2.0);
        assert!((l.first_baseline - (60.0 - 2.0 - 12.0 * 0.718)).abs() < 1e-9);
        assert_eq!(l.lines.len(), 2);
        assert!(l.warnings.is_empty(), "{:?}", l.warnings);
        let text = String::from_utf8(content(&l, 0.0).unwrap()).unwrap();
        assert_eq!(
            text,
            "q\nBT\n/F1 12 Tf\n0 g\n2 49.384 Td\n(Digitally signed by A) Tj\n0 -14.4 Td\n\
             (Date: 2026-10-10) Tj\nET\nQ\n"
        );

        // Many lines in a low box: the height decides.
        let four = lines(&["a", "b", "c", "d"]);
        let l = layout(&appearance, 200.0, 40.0, &four, None);
        assert_eq!(l.font_size, 7.5); // (40 - 4) / 4.8
        assert_eq!(l.lines.len(), 4);

        // A wide line: the size shrinks proportionally until it fits.
        let wide = lines(&["W".repeat(20).as_str()]);
        let l = layout(&appearance, 200.0, 60.0, &wide, None);
        let width = standard14::Standard14Font::Helvetica.text_width(&l.lines[0], l.font_size);
        assert!(
            l.font_size < 12.0 && width <= 196.0 + 1e-9,
            "{}",
            l.font_size
        );
        assert!(l.warnings.is_empty());

        // With a border, everything is inset.
        let bordered = appearance.clone().with_border_width(1.5);
        let l = layout(&bordered, 200.0, 60.0, &two, None);
        assert_eq!(l.text_x, 3.5);
        let text = String::from_utf8(content(&l, 1.5).unwrap()).unwrap();
        assert!(
            text.starts_with("q\n1.5 w\n0 G\n0.75 0.75 198.5 58.5 re\nS\nBT\n"),
            "{text}"
        );
    }

    #[test]
    fn layout_shortens_and_drops_what_does_not_fit() {
        let appearance = SignatureAppearance::new(Rect::new(0.0, 0.0, 60.0, 12.0));
        let long = lines(&[
            "Digitally signed by a very long name indeed",
            "second",
            "third",
        ]);
        let l = layout(&appearance, 60.0, 12.0, &long, None);
        assert_eq!(l.font_size, MIN_FONT_SIZE);
        assert_eq!(l.lines[0].last(), Some(&ELLIPSIS));
        let text_w = 60.0 - 2.0 * 0.6;
        let width = standard14::Standard14Font::Helvetica.text_width(&l.lines[0], 4.0);
        assert!(width <= text_w + 1e-9, "{width}");
        assert!(l.lines.len() < 3, "{}", l.lines.len());
        assert!(
            l.warnings.iter().any(|w| w.contains("shortened")),
            "{:?}",
            l.warnings
        );
        assert!(
            l.warnings.iter().any(|w| w.contains("left out")),
            "{:?}",
            l.warnings
        );

        // M4 QA round 5, finding 3: the verbs agree with the counts.
        assert_eq!(
            shortened_warning(1, 7, 4.0),
            "1 of the 7 lines of the appearance text is too wide for the rect at 4 pt and was \
             shortened (it ends with …)"
        );
        assert!(
            shortened_warning(2, 7, 4.0).starts_with("2 of the 7 lines of the appearance text are")
        );
        assert!(shortened_warning(1, 1, 4.0).starts_with("the line of the appearance text is"));
        assert!(
            dropped_warning(1, 7, 4.0)
                .contains("only 1 of the 7 lines of the appearance text fits")
        );
        assert!(dropped_warning(1, 2, 4.0).ends_with("the other is left out"));
        assert!(dropped_warning(3, 7, 4.0).ends_with("the others are left out"));
        assert!(dropped_warning(0, 2, 4.0).starts_with("none of the 2 lines"));

        // Characters outside WinAnsi become '?', with one warning for all lines.
        let foreign = lines(&["Signed by Łukasz", "Дата"]);
        let l = layout(&appearance.with_rect(None), 200.0, 60.0, &foreign, None);
        assert_eq!(l.lines[0], b"Signed by ?ukasz");
        assert_eq!(l.lines[1], b"????");
        assert_eq!(
            l.warnings,
            ["5 characters cannot be shown with the standard 14 fonts (embedded fonts: M7)"]
        );
    }

    #[test]
    fn layout_places_the_image() {
        let left = SignatureAppearance::new(Rect::new(0.0, 0.0, 200.0, 60.0));
        let text = lines(&["Signed"]);
        // An 85 x 110 image in a 200 x 60 box: the column is (60 - 4) * 85 / 110 wide.
        let l = layout(&left, 200.0, 60.0, &text, Some((85, 110)));
        let [x, y, w, h] = l.image.unwrap();
        assert!((w / h - 85.0 / 110.0).abs() < 1e-12, "aspect kept");
        assert!((h - 56.0).abs() < 1e-9 && (x - 2.0).abs() < 1e-12);
        assert!((y - 2.0).abs() < 1e-9, "vertically centred");
        assert!((l.text_x - (2.0 + w + 2.0)).abs() < 1e-12);
        // A wide image takes at most half the box.
        let l = layout(&left, 200.0, 60.0, &text, Some((1000, 10)));
        let [_, y, w, h] = l.image.unwrap();
        assert!((w - 98.0).abs() < 1e-9 && (y - (60.0 - h) / 2.0).abs() < 1e-12);
        // In the background: fitted, centred, and the text starts at the padding.
        let back = left.with_image_position(ImagePosition::Background);
        let l = layout(&back, 200.0, 60.0, &text, Some((85, 110)));
        let [x, y, w, h] = l.image.unwrap();
        assert!((h - 56.0).abs() < 1e-9 && (x - (200.0 - w) / 2.0).abs() < 1e-12);
        assert!((y - 2.0).abs() < 1e-9);
        assert_eq!(l.text_x, 2.0);
        let text = String::from_utf8(content(&l, 0.0).unwrap()).unwrap();
        assert!(text.contains("cm\n/Im1 Do\nQ\nBT\n"), "{text}");
    }

    #[test]
    fn build_writes_the_form_and_its_resources() {
        let store = folioxide_syntax::Store::open_bytes(
            folioxide_testkit::fixtures::syntax::minimal(),
            &folioxide_syntax::OpenOptions::default(),
        )
        .unwrap();
        let mut numbers = NewNumbers::new(&store);
        let rect = Rect::new(300.0, 100.0, 500.0, 160.0);
        let appearance = SignatureAppearance::new(rect).with_font(Standard14Font::HelveticaBold);
        let built = build(
            &appearance,
            rect,
            Rotation::R90,
            &lines(&["Signed"]),
            &mut numbers,
        )
        .unwrap();
        // The form, the font and its font descriptor (§9.6.2.2: indirect).
        assert_eq!(built.objects.len(), 3);
        let (form_id, form) = &built.objects[0];
        assert_eq!(*form_id, built.normal);
        let form = form.as_stream().unwrap();
        assert!(form.dict.is_type(b"XObject"));
        assert_eq!(form.dict.get_name(b"Subtype").unwrap(), "Form");
        assert_eq!(
            form.dict.get(b"BBox").unwrap(),
            &Rect::new(0.0, 0.0, 60.0, 200.0).to_object()
        );
        assert_eq!(
            form.dict.get(b"Matrix").unwrap(),
            &Object::Array(vec![
                0.into(),
                1.into(),
                (-1).into(),
                0.into(),
                200.into(),
                0.into()
            ])
        );
        let (font_id, font) = &built.objects[1];
        let resources = form.dict.get_dict(b"Resources").unwrap();
        assert_eq!(
            resources.get_dict(b"Font").unwrap().get_ref(b"F1"),
            Some(*font_id)
        );
        assert_eq!(
            font.as_dict().unwrap().get_name(b"BaseFont").unwrap(),
            "Helvetica-Bold"
        );
        let (descriptor_id, descriptor) = &built.objects[2];
        assert_eq!(
            font.as_dict().unwrap().get_ref(b"FontDescriptor"),
            Some(*descriptor_id)
        );
        let descriptor = descriptor.as_dict().unwrap();
        assert!(descriptor.is_type(b"FontDescriptor"));
        assert_eq!(descriptor.get_name(b"FontName").unwrap(), "Helvetica-Bold");
        assert_eq!(descriptor.get_int(b"StemV"), Some(140));
        assert!(!resources.contains_key(b"XObject"));

        // Bad values are refused.
        for bad in [
            appearance.clone().with_font_size(Some(0.0)),
            appearance.clone().with_font_size(Some(f64::NAN)),
            appearance.clone().with_font_size(Some(1001.0)),
            appearance.clone().with_border_width(-1.0),
            appearance.clone().with_border_width(30.0),
            appearance.clone().with_border_width(f64::INFINITY),
        ] {
            let err = build(&bad, rect, Rotation::R0, &[], &mut numbers).unwrap_err();
            assert_eq!(
                err.code(),
                folioxide_syntax::ErrorCode::InvalidArgument,
                "{bad:?}"
            );
        }
        let many: Vec<String> = (0..=MAX_LINES).map(|i| i.to_string()).collect();
        assert!(build(&appearance, rect, Rotation::R0, &many, &mut numbers).is_err());
        let huge = vec!["x".repeat(MAX_LINE_CHARS + 1)];
        assert!(build(&appearance, rect, Rotation::R0, &huge, &mut numbers).is_err());
        // Not a JPEG: an image error, not a panic.
        let bogus = appearance.with_image(Some(b"GIF89a".to_vec()));
        let err = build(&bogus, rect, Rotation::R0, &[], &mut numbers).unwrap_err();
        assert_eq!(err.code(), folioxide_syntax::ErrorCode::Image);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_shapes() {
        let appearance = SignatureAppearance::new(Rect::new(0.0, 0.0, 200.0, 50.0))
            .with_text(AppearanceText::Lines(vec!["x".into()]))
            .with_font(Standard14Font::HelveticaBold);
        let json = serde_json::to_value(&appearance).unwrap();
        assert_eq!(json["rect"]["urx"], 200.0);
        assert_eq!(json["text"], serde_json::json!({"lines": ["x"]}));
        assert_eq!(json["font"], "Helvetica-Bold");
        assert_eq!(json["imagePosition"], "left");
        assert_eq!(json["borderWidth"], 0.0);
        let back: SignatureAppearance = serde_json::from_value(json).unwrap();
        assert_eq!(back, appearance);
        let minimal: SignatureAppearance = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(minimal, SignatureAppearance::for_existing_field());
        assert_eq!(
            serde_json::to_value(AppearanceText::Default).unwrap(),
            "default"
        );
    }
}

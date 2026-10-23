//! A content-stream builder (ISO 32000-2 §7.8.2, §8, §9.4).
//!
//! [`ContentBuilder`] appends one operator per line, operands first, in the order the methods
//! are called. It does not check that operators nest correctly (`q`/`Q`, `BT`/`ET`) or appear
//! where §8.2 allows them: callers build small, fixed sequences such as a signature appearance.
//!
//! **Operands** are written with the M1 serializer's rules ([`format_real`]): no exponent, at
//! most 10 fractional digits, trailing zeros trimmed. Content-stream operands are numbers, which
//! may be integers or reals (§7.3.3, §8.2), so an integral value is written without the `.0` the
//! object serializer keeps (`1 0 0 1 0 0 cm`, not `1.0 0.0 0.0 1.0 0.0 0.0 cm`) when it fits the
//! 32-bit integer range readers must accept (Annex C). A value that is not finite or lies beyond
//! the real range readers must accept ([`MAX_REAL`], about `3.403e38`) is not written: the
//! builder records an [`InvalidArgument`](folioxide_syntax::ErrorCode::InvalidArgument) error
//! and [`ContentBuilder::finish`] returns the first one.
//!
//! **Names** (`/F1` in `Tf`, `/Im1` in `Do`) are written with the serializer's escaping
//! (§7.3.5) and **strings** (`Tj`) as literal strings escaping `(`, `)`, `\`, CR and LF
//! (§7.3.4.2); every other byte, including those above 0x7F, is written as is.
//!
//! ```
//! use folioxide_content::builder::ContentBuilder;
//!
//! let mut content = ContentBuilder::new();
//! content
//!     .save()
//!     .line_width(1.0)
//!     .stroke_gray(0.0)
//!     .rect(0.5, 0.5, 199.0, 59.0)
//!     .stroke()
//!     .restore();
//! assert_eq!(content.finish()?, b"q\n1 w\n0 G\n0.5 0.5 199 59 re\nS\nQ\n");
//! # Ok::<(), folioxide_syntax::Error>(())
//! ```
//!
//! [`format_real`]: folioxide_syntax::serialize::format_real
//! [`MAX_REAL`]: folioxide_syntax::serialize::MAX_REAL

use folioxide_syntax::serialize::{MAX_REAL, format_real, write_literal_string, write_name};
use folioxide_syntax::{Error, Result};

/// The largest magnitude written as an integer: the 32-bit integer limit of ISO 32000 Annex C
/// (Table C.1). Larger integral values are written as reals.
const MAX_INTEGER: f64 = 2_147_483_647.0;

/// Builds the bytes of a content stream, one operator per line.
///
/// Every operator method appends to the stream and returns `&mut Self`, so calls chain;
/// [`ContentBuilder::finish`] returns the bytes, or the first invalid operand. See the
/// [module documentation](self) for the output format.
#[derive(Clone, Debug, Default)]
pub struct ContentBuilder {
    out: Vec<u8>,
    error: Option<Error>,
}

impl ContentBuilder {
    /// An empty content stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether nothing has been written yet.
    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    // ---- graphics state (§8.4.4) -------------------------------------------------------------

    /// `q`: saves the graphics state.
    pub fn save(&mut self) -> &mut Self {
        self.op(&[], b"q")
    }

    /// `Q`: restores the graphics state saved by the matching `q`.
    pub fn restore(&mut self) -> &mut Self {
        self.op(&[], b"Q")
    }

    /// `a b c d e f cm`: concatenates `m` to the current transformation matrix (§8.3.4).
    pub fn concat(&mut self, m: [f64; 6]) -> &mut Self {
        self.op(&m, b"cm")
    }

    /// `w w`: sets the line width in user-space units.
    pub fn line_width(&mut self, w: f64) -> &mut Self {
        self.op(&[w], b"w")
    }

    // ---- paths (§8.5) ------------------------------------------------------------------------

    /// `x y m`: begins a new subpath at (x, y).
    pub fn move_to(&mut self, x: f64, y: f64) -> &mut Self {
        self.op(&[x, y], b"m")
    }

    /// `x y l`: appends a straight line to (x, y).
    pub fn line_to(&mut self, x: f64, y: f64) -> &mut Self {
        self.op(&[x, y], b"l")
    }

    /// `h`: closes the current subpath.
    pub fn close_path(&mut self) -> &mut Self {
        self.op(&[], b"h")
    }

    /// `x y w h re`: appends a rectangle with its lower-left corner at (x, y).
    pub fn rect(&mut self, x: f64, y: f64, w: f64, h: f64) -> &mut Self {
        self.op(&[x, y, w, h], b"re")
    }

    /// `f`: fills the path with the nonzero winding number rule.
    pub fn fill(&mut self) -> &mut Self {
        self.op(&[], b"f")
    }

    /// `S`: strokes the path.
    pub fn stroke(&mut self) -> &mut Self {
        self.op(&[], b"S")
    }

    /// `W n`: intersects the clipping path with the current path (nonzero rule) and ends the
    /// path without painting it (§8.5.4).
    pub fn clip(&mut self) -> &mut Self {
        self.op(&[], b"W").op(&[], b"n")
    }

    /// `n`: ends the path without filling or stroking it.
    pub fn end_path(&mut self) -> &mut Self {
        self.op(&[], b"n")
    }

    // ---- colour (§8.6.8) ---------------------------------------------------------------------

    /// `g g`: sets the fill colour to a DeviceGray level (0 = black, 1 = white).
    pub fn fill_gray(&mut self, g: f64) -> &mut Self {
        self.op(&[g], b"g")
    }

    /// `g G`: sets the stroke colour to a DeviceGray level (0 = black, 1 = white).
    pub fn stroke_gray(&mut self, g: f64) -> &mut Self {
        self.op(&[g], b"G")
    }

    /// `r g b rg`: sets the fill colour to a DeviceRGB colour (components 0 to 1).
    pub fn fill_rgb(&mut self, r: f64, g: f64, b: f64) -> &mut Self {
        self.op(&[r, g, b], b"rg")
    }

    /// `r g b RG`: sets the stroke colour to a DeviceRGB colour (components 0 to 1).
    pub fn stroke_rgb(&mut self, r: f64, g: f64, b: f64) -> &mut Self {
        self.op(&[r, g, b], b"RG")
    }

    // ---- text (§9.4) -------------------------------------------------------------------------

    /// `BT`: begins a text object.
    pub fn begin_text(&mut self) -> &mut Self {
        self.op(&[], b"BT")
    }

    /// `ET`: ends a text object.
    pub fn end_text(&mut self) -> &mut Self {
        self.op(&[], b"ET")
    }

    /// `/Name size Tf`: selects the font named `resource` in the `/Font` resources, at `size`
    /// (§9.3.1). An empty name is an invalid argument.
    pub fn font(&mut self, resource: &[u8], size: f64) -> &mut Self {
        if self.error.is_none() && resource.is_empty() {
            self.error = Some(Error::invalid_argument("empty font resource name for Tf"));
        }
        if self.error.is_some() || !self.check(&[size], b"Tf") {
            return self;
        }
        write_name(resource, &mut self.out);
        self.out.push(b' ');
        self.number(size);
        self.out.extend_from_slice(b" Tf\n");
        self
    }

    /// `tx ty Td`: moves to the start of the next line, offset by (tx, ty) from the start of
    /// the current line (§9.4.2).
    pub fn move_text(&mut self, tx: f64, ty: f64) -> &mut Self {
        self.op(&[tx, ty], b"Td")
    }

    /// `a b c d e f Tm`: sets the text matrix and the text line matrix (§9.4.2).
    pub fn text_matrix(&mut self, m: [f64; 6]) -> &mut Self {
        self.op(&m, b"Tm")
    }

    /// `(…) Tj`: shows `encoded`, a string already in the current font's encoding (for the
    /// standard-14 fonts of this crate, WinAnsiEncoding: see
    /// [`win_ansi_encode`](crate::encoding::win_ansi_encode)). It is written as an escaped
    /// literal string (§7.3.4.2).
    pub fn show(&mut self, encoded: &[u8]) -> &mut Self {
        if self.error.is_some() {
            return self;
        }
        write_literal_string(encoded, &mut self.out);
        self.out.extend_from_slice(b" Tj\n");
        self
    }

    // ---- XObjects (§8.8) ---------------------------------------------------------------------

    /// `/Name Do`: paints the XObject named `resource` in the `/XObject` resources. An image
    /// fills the unit square of the current transformation matrix (§8.9.4), so callers scale it
    /// with [`concat`](Self::concat) inside [`save`](Self::save)/[`restore`](Self::restore). An
    /// empty name is an invalid argument.
    pub fn draw_xobject(&mut self, resource: &[u8]) -> &mut Self {
        if self.error.is_none() && resource.is_empty() {
            self.error = Some(Error::invalid_argument(
                "empty XObject resource name for Do",
            ));
        }
        if self.error.is_some() {
            return self;
        }
        write_name(resource, &mut self.out);
        self.out.extend_from_slice(b" Do\n");
        self
    }

    // ---- output ------------------------------------------------------------------------------

    /// The content-stream bytes.
    ///
    /// # Errors
    /// [`ErrorCode::InvalidArgument`](folioxide_syntax::ErrorCode::InvalidArgument) for the
    /// first operand that was not finite or beyond [`MAX_REAL`] in magnitude, or the first
    /// empty resource name; nothing after it was written.
    pub fn finish(self) -> Result<Vec<u8>> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.out),
        }
    }

    /// Writes `operands operator\n`, unless an earlier operand was invalid or one of these is.
    fn op(&mut self, operands: &[f64], operator: &[u8]) -> &mut Self {
        if self.error.is_some() || !self.check(operands, operator) {
            return self;
        }
        for &value in operands {
            self.number(value);
            self.out.push(b' ');
        }
        self.out.extend_from_slice(operator);
        self.out.push(b'\n');
        self
    }

    /// Records an error for the first operand that cannot be written; whether all can.
    fn check(&mut self, operands: &[f64], operator: &[u8]) -> bool {
        let bad = operands
            .iter()
            .enumerate()
            .find(|(_, v)| !v.is_finite() || v.abs() > MAX_REAL);
        match bad {
            None => true,
            Some((index, value)) => {
                self.error = Some(Error::invalid_argument(format!(
                    "operand {} of the content operator `{}` is not a number PDF can hold: {value}",
                    index + 1,
                    String::from_utf8_lossy(operator),
                )));
                false
            }
        }
    }

    /// Appends a finite operand: an integer when the value is integral and fits 32 bits, else
    /// the serializer's real form.
    fn number(&mut self, value: f64) {
        let text = format_real(value);
        match text.strip_suffix(".0") {
            Some(integer) if value.abs() <= MAX_INTEGER => {
                self.out.extend_from_slice(integer.as_bytes());
            }
            _ => self.out.extend_from_slice(text.as_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use folioxide_syntax::ErrorCode;

    fn finish(build: impl FnOnce(&mut ContentBuilder)) -> Vec<u8> {
        let mut b = ContentBuilder::new();
        build(&mut b);
        b.finish().unwrap()
    }

    #[test]
    fn numbers_follow_the_serializer_without_integral_dot_zero() {
        let cases: &[(f64, &str)] = &[
            (0.0, "0"),
            (-0.0, "0"),
            (1.0, "1"),
            (-12.0, "-12"),
            (0.5, "0.5"),
            (1.0 / 3.0, "0.3333333333"),
            (0.1 + 0.2, "0.3"),
            (1e-11, "0"),
            (2_147_483_647.0, "2147483647"),
            (2_147_483_648.0, "2147483648.0"),
            (-2_147_483_648.0, "-2147483648.0"),
            (1e21, "1000000000000000000000.0"),
            (MAX_REAL, "340282346638528860000000000000000000000.0"),
        ];
        for &(value, expected) in cases {
            let out = finish(|b| {
                b.line_width(value);
            });
            assert_eq!(out, format!("{expected} w\n").as_bytes(), "{value:?}");
        }
    }

    #[test]
    fn first_error_wins_and_stops_output() {
        let mut b = ContentBuilder::new();
        b.save()
            .concat([1.0, 0.0, 0.0, f64::NAN, 0.0, 0.0])
            .line_width(f64::INFINITY)
            .restore();
        let err = b.finish().unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(
            err.to_string()
                .contains("operand 4 of the content operator `cm`"),
            "{err}"
        );
    }

    #[test]
    fn empty_resource_names_are_rejected() {
        let mut b = ContentBuilder::new();
        b.font(b"", 12.0);
        assert_eq!(b.finish().unwrap_err().code(), ErrorCode::InvalidArgument);
        let mut b = ContentBuilder::new();
        b.draw_xobject(b"");
        assert_eq!(b.finish().unwrap_err().code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn names_and_strings_are_escaped() {
        let out = finish(|b| {
            b.font(b"F 1#", 9.0)
                .show(b"a(b)c\\d\re\nf\xE9")
                .draw_xobject(b"Im/1");
        });
        assert_eq!(
            out,
            b"/F#201#23 9 Tf\n(a\\(b\\)c\\\\d\\re\\nf\xE9) Tj\n/Im#2F1 Do\n"
        );
    }

    #[test]
    fn is_empty_tracks_output() {
        let mut b = ContentBuilder::new();
        assert!(b.is_empty());
        b.save();
        assert!(!b.is_empty());
    }
}

//! Metrics of the standard 14 fonts (ISO 32000-2 §9.6.2.2), for text written with them in
//! WinAnsiEncoding (Annex D.2).
//!
//! M4 carries Helvetica and Helvetica-Bold, the fonts of signature appearances (decision D-16);
//! the other twelve arrive with M7. The metrics are derived (widths extracted) from Adobe's Core
//! 14 AFM files as shipped with Apache PDFBox 3.0.3, by `tools/fonts/afm2rs.py`, which records
//! each input's SHA-256 in the generated table. The AFM files' terms
//! ([`ADOBE_AFM_NOTICE`]) travel with the crate in its `NOTICE` file.
//!
//! **Widths are mapped by glyph name**, through WinAnsiEncoding, never by the AFM's own codes,
//! which are StandardEncoding: `quotesingle` is code 169 in the AFM but WinAnsi 0x27, and
//! `Euro` has no AFM code but is WinAnsi 0x80. The unused codes above 0x20 carry the width of
//! `bullet`, the glyph Annex D.2 note 6 says they show.
//!
//! [`Standard14Font::font_dict`] writes `/Widths` explicitly, and
//! [`Standard14Font::font_descriptor`] the font descriptor the font dictionary refers to: PDF 2.0
//! deprecates the special treatment of the standard 14 fonts (§9.6.2.2, Table 109), so a reader
//! may not have built-in metrics. The font program is not embedded (M7 embeds fonts).
//!
//! ```
//! use folioxide_content::standard14::Standard14Font;
//!
//! let font = Standard14Font::Helvetica;
//! assert_eq!(font.base_font(), "Helvetica");
//! assert_eq!(font.win_ansi_width(b'A'), 667);
//! assert_eq!(font.text_width(b"AW", 10.0), 16.11);
//! assert_eq!(font.ascent(), 718);
//! ```

use folioxide_syntax::{Dict, Object};

#[rustfmt::skip]
mod afm_tables;

pub use afm_tables::ADOBE_AFM_NOTICE;

/// The metrics of one AFM file, as `tools/fonts/afm2rs.py` extracts them.
pub(crate) struct AfmMetrics {
    /// `FontName`.
    font_name: &'static str,
    /// The AFM's `Notice` line (its copyright notice).
    notice: &'static str,
    /// `FontBBox`, in glyph space (1/1000 em).
    font_bbox: [i16; 4],
    /// `Ascender`.
    ascender: i16,
    /// `Descender`.
    descender: i16,
    /// `CapHeight`.
    cap_height: i16,
    /// `XHeight`.
    x_height: i16,
    /// `StdVW`.
    std_vw: i16,
    /// The width of each WinAnsiEncoding code 32..=255, by glyph name.
    win_ansi_widths: [u16; 224],
    /// Every `CharMetrics` entry: glyph name, StandardEncoding code (-1 for none), `WX`.
    glyphs: &'static [(&'static str, i16, u16)],
}

/// One of the standard 14 fonts (ISO 32000-2 §9.6.2.2).
///
/// Only Helvetica and Helvetica-Bold exist in M4; the enum is `#[non_exhaustive]` so the other
/// twelve can join (M7).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum Standard14Font {
    /// Helvetica (the default).
    #[default]
    Helvetica,
    /// Helvetica-Bold.
    HelveticaBold,
}

impl Standard14Font {
    /// Every font this version has metrics for.
    pub const ALL: &'static [Standard14Font] =
        &[Standard14Font::Helvetica, Standard14Font::HelveticaBold];

    /// The font with PostScript name `base_font` (`/BaseFont`), if this version has it.
    ///
    /// ```
    /// use folioxide_content::standard14::Standard14Font;
    ///
    /// assert_eq!(Standard14Font::from_base_font("Helvetica-Bold"), Some(Standard14Font::HelveticaBold));
    /// assert_eq!(Standard14Font::from_base_font("Arial"), None);
    /// ```
    pub fn from_base_font(base_font: &str) -> Option<Standard14Font> {
        Self::ALL
            .iter()
            .copied()
            .find(|font| font.base_font() == base_font)
    }

    fn metrics(self) -> &'static AfmMetrics {
        match self {
            Standard14Font::Helvetica => &afm_tables::HELVETICA,
            Standard14Font::HelveticaBold => &afm_tables::HELVETICA_BOLD,
        }
    }

    /// The PostScript name, the value of `/BaseFont`: `"Helvetica"`, `"Helvetica-Bold"`.
    pub fn base_font(self) -> &'static str {
        self.metrics().font_name
    }

    /// The advance width of WinAnsiEncoding code `code`, in 1/1000 em (glyph space): 0 for the
    /// codes below 0x20, which have no glyph; the `bullet` width for the other unused codes
    /// (Annex D.2 note 6).
    pub fn win_ansi_width(self, code: u8) -> u16 {
        let Some(index) = code.checked_sub(32) else {
            return 0;
        };
        self.metrics()
            .win_ansi_widths
            .get(usize::from(index))
            .copied()
            .unwrap_or(0)
    }

    /// The advance width of `win_ansi` (WinAnsiEncoding bytes) at font size `size`, in text
    /// space units: the sum of [`win_ansi_width`](Self::win_ansi_width) times `size / 1000`, with
    /// no kerning, character or word spacing (the defaults of §9.3).
    pub fn text_width(self, win_ansi: &[u8], size: f64) -> f64 {
        let units: u64 = win_ansi
            .iter()
            .map(|&code| u64::from(self.win_ansi_width(code)))
            .sum();
        // Exact up to 2^53 / 1000 units: far beyond any text this builds.
        units as f64 * size / 1000.0
    }

    /// The advance width of the glyph named `glyph` (Adobe Glyph List name), in 1/1000 em, or
    /// `None` when the font has no such glyph. Every glyph of the AFM is covered, including
    /// those WinAnsiEncoding cannot reach.
    pub fn glyph_width(self, glyph: &str) -> Option<u16> {
        self.metrics()
            .glyphs
            .iter()
            .find(|(name, _, _)| *name == glyph)
            .map(|&(_, _, width)| width)
    }

    /// `Ascender`, in 1/1000 em (Helvetica: 718).
    pub fn ascent(self) -> i16 {
        self.metrics().ascender
    }

    /// `Descender`, in 1/1000 em, negative below the baseline (Helvetica: -207).
    pub fn descent(self) -> i16 {
        self.metrics().descender
    }

    /// `CapHeight`, in 1/1000 em (Helvetica: 718).
    pub fn cap_height(self) -> i16 {
        self.metrics().cap_height
    }

    /// `XHeight`, in 1/1000 em (Helvetica: 523).
    pub fn x_height(self) -> i16 {
        self.metrics().x_height
    }

    /// `StdVW`, the dominant vertical stem width, in 1/1000 em (the font descriptor's `/StemV`).
    pub fn stem_v(self) -> i16 {
        self.metrics().std_vw
    }

    /// `FontBBox` `[llx lly urx ury]`, in 1/1000 em (Helvetica: `[-166 -225 1000 931]`).
    pub fn bbox(self) -> [i16; 4] {
        self.metrics().font_bbox
    }

    /// The AFM file's copyright notice (its `Notice` line), which the AFM terms require to be
    /// retained.
    pub fn copyright_notice(self) -> &'static str {
        self.metrics().notice
    }

    /// The font dictionary for text in WinAnsiEncoding (§9.6.2):
    ///
    /// `<< /Type /Font /Subtype /Type1 /BaseFont /… /Encoding /WinAnsiEncoding /FirstChar 32
    /// /LastChar 255 /Widths […] >>`, with the 224 widths of
    /// [`win_ansi_width`](Self::win_ansi_width). The caller adds `/FontDescriptor`, an indirect
    /// reference to [`font_descriptor`](Self::font_descriptor) (§9.6.2.2 Table 109: it shall be
    /// indirect).
    ///
    /// ```
    /// use folioxide_content::standard14::Standard14Font;
    ///
    /// let dict = Standard14Font::HelveticaBold.font_dict();
    /// assert_eq!(dict.get_name(b"BaseFont").unwrap(), "Helvetica-Bold");
    /// assert_eq!(dict.get_array(b"Widths").unwrap().len(), 224);
    /// ```
    pub fn font_dict(self) -> Dict {
        let widths = (32..=255u8)
            .map(|code| Object::Int(i64::from(self.win_ansi_width(code))))
            .collect::<Vec<_>>();
        let mut dict = Dict::with_capacity(8);
        dict.insert("Type", Object::name("Font"));
        dict.insert("Subtype", Object::name("Type1"));
        dict.insert("BaseFont", Object::name(self.base_font()));
        dict.insert("Encoding", Object::name("WinAnsiEncoding"));
        dict.insert("FirstChar", 32);
        dict.insert("LastChar", 255);
        dict.insert("Widths", widths);
        dict
    }

    /// The font descriptor of the font (§9.8, Table 120), from the AFM metrics, without a font
    /// program (the viewer supplies the standard 14 font):
    ///
    /// `<< /Type /FontDescriptor /FontName /… /Flags 32 /FontBBox […] /ItalicAngle 0 /Ascent …
    /// /Descent … /CapHeight … /XHeight … /StemV … >>`. `/Flags 32` is Nonsymbolic (§9.8.2
    /// Table 121, bit 6): the font uses the standard Latin character set, which WinAnsiEncoding
    /// addresses; Helvetica is neither serif, fixed-pitch nor italic.
    ///
    /// ```
    /// use folioxide_content::standard14::Standard14Font;
    ///
    /// let descriptor = Standard14Font::Helvetica.font_descriptor();
    /// assert_eq!(descriptor.get_name(b"FontName").unwrap(), "Helvetica");
    /// assert_eq!(descriptor.get_int(b"StemV"), Some(88));
    /// assert_eq!(descriptor.get_array(b"FontBBox").unwrap().len(), 4);
    /// ```
    pub fn font_descriptor(self) -> Dict {
        let metrics = self.metrics();
        let bbox = metrics
            .font_bbox
            .iter()
            .map(|&v| Object::Int(i64::from(v)))
            .collect::<Vec<_>>();
        let mut dict = Dict::with_capacity(10);
        dict.insert("Type", Object::name("FontDescriptor"));
        dict.insert("FontName", Object::name(self.base_font()));
        dict.insert("Flags", 32);
        dict.insert("FontBBox", bbox);
        dict.insert("ItalicAngle", 0);
        dict.insert("Ascent", i64::from(metrics.ascender));
        dict.insert("Descent", i64::from(metrics.descender));
        dict.insert("CapHeight", i64::from(metrics.cap_height));
        dict.insert("XHeight", i64::from(metrics.x_height));
        dict.insert("StemV", i64::from(metrics.std_vw));
        dict
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::win_ansi_glyph_name;

    /// The generator's WinAnsi transcription (Python) equals this crate's (Rust), code by code.
    #[test]
    fn generated_width_glyphs_match_the_encoding_table() {
        for (index, &generated) in afm_tables::WIDTH_GLYPHS.iter().enumerate() {
            let code = u8::try_from(index + 32).unwrap();
            let ours = win_ansi_glyph_name(code).unwrap_or("bullet");
            assert_eq!(generated, ours, "{code:#04X}");
        }
    }

    /// Each per-code width is the AFM width of the code's glyph.
    #[test]
    fn win_ansi_widths_come_from_the_glyph_table() {
        for &font in Standard14Font::ALL {
            let metrics = font.metrics();
            for (index, &name) in afm_tables::WIDTH_GLYPHS.iter().enumerate() {
                let width = metrics.glyphs.iter().find(|g| g.0 == name).unwrap().2;
                assert_eq!(metrics.win_ansi_widths[index], width, "{font:?} {name}");
            }
            assert_eq!(metrics.glyphs.len(), 315, "{font:?}");
        }
    }

    #[test]
    fn copyright_notices_are_adobes() {
        for &font in Standard14Font::ALL {
            assert!(
                font.copyright_notice()
                    .starts_with("Copyright (c) 1985, 1987, 1989, 1990, 1997 Adobe Systems"),
                "{font:?}"
            );
        }
    }
}

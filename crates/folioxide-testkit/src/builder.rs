//! A byte-level PDF builder for tests: well-formed files and deliberately broken ones.
//!
//! [`PdfBuilder`] writes exactly the bytes it is told to, in order, and records where every
//! indirect object, stream and cross-reference section landed. Cross-reference tables and
//! streams are generated from those records, so a well-formed file needs no offset arithmetic,
//! while every knob that real-world files get wrong is exposed: the end-of-line bytes of table
//! entries, a wrong first subsection number, skewed offsets, a wrong `startxref`, a wrong or
//! indirect `/Length`, zero-width `/W` fields, `/Prev` values patched in after the fact, and junk
//! before the header.
//!
//! # Offsets
//!
//! Every offset the builder reports or writes is **relative to the `%PDF-` header**, which is
//! how files with junk before the header are found in the wild (the junk was prepended to an
//! otherwise valid file; ISO 32000-2 §7.5.2 and ARCHITECTURE §A.10 trap #3). Bytes passed to
//! [`PdfBuilder::junk_prefix`] are placed before everything else when the file is built, so
//! the position of something in [`PdfBuilder::build`]'s output is its offset plus
//! [`PdfBuilder::header_offset`]. Without junk the two are the same.
//!
//! # Example
//!
//! ```
//! use folioxide_testkit::builder::{PdfBuilder, XrefOpts};
//!
//! let mut b = PdfBuilder::new();
//! b.header("1.7")
//!     .obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>")
//!     .obj(2, 0, "<< /Type /Pages /Kids [] /Count 0 >>")
//!     .xref_table(XrefOpts::default());
//! let trailer = format!("/Size {} /Root 1 0 R", b.size());
//! b.trailer(trailer).startxref(None).eof();
//! let pdf = b.build();
//! assert!(pdf.starts_with(b"%PDF-1.7\n"));
//! assert!(pdf.ends_with(b"startxref\n116\n%%EOF\n"));
//! ```

use std::collections::BTreeMap;
use std::ops::Range;

use folioxide_syntax::filters::encode_flate;
use folioxide_syntax::{Object, ObjectId, serialize_object};

/// The zlib compression level the builder uses for every Flate stream. Fixed, so generated
/// files are byte-for-byte reproducible.
pub const FLATE_LEVEL: u8 = 6;

/// The end-of-line bytes after each cross-reference table entry (ISO 32000-2 §7.5.4).
///
/// A conforming entry is exactly 20 bytes: 18 bytes of data plus a two-byte EOL, which is
/// `SP CR`, `SP LF` or `CR LF`. Real files also contain 19-byte entries with a single `LF` or
/// `CR`, which [`XrefEol::Lf`] and [`XrefEol::Cr`] reproduce.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum XrefEol {
    /// `SP LF` (conforming; the default).
    #[default]
    SpaceLf,
    /// `SP CR` (conforming).
    SpaceCr,
    /// `CR LF` (conforming).
    CrLf,
    /// A single `LF`: 19-byte entries (not conforming).
    Lf,
    /// A single `CR`: 19-byte entries (not conforming).
    Cr,
}

impl XrefEol {
    /// Every variant, conforming ones first.
    pub const ALL: [XrefEol; 5] = [
        XrefEol::SpaceLf,
        XrefEol::SpaceCr,
        XrefEol::CrLf,
        XrefEol::Lf,
        XrefEol::Cr,
    ];

    /// The bytes written after each 18-byte entry.
    pub const fn entry_end(self) -> &'static [u8] {
        match self {
            XrefEol::SpaceLf => b" \n",
            XrefEol::SpaceCr => b" \r",
            XrefEol::CrLf => b"\r\n",
            XrefEol::Lf => b"\n",
            XrefEol::Cr => b"\r",
        }
    }

    /// The line end used after `xref` and after each subsection header: the variant's EOL
    /// without the leading space.
    pub const fn line_end(self) -> &'static [u8] {
        match self {
            XrefEol::SpaceLf | XrefEol::Lf => b"\n",
            XrefEol::SpaceCr | XrefEol::Cr => b"\r",
            XrefEol::CrLf => b"\r\n",
        }
    }

    /// Whether entries are the 20 bytes that §7.5.4 requires.
    pub const fn is_conforming(self) -> bool {
        matches!(self, XrefEol::SpaceLf | XrefEol::SpaceCr | XrefEol::CrLf)
    }
}

/// One cross-reference entry (ISO 32000-2 §7.5.4 and §7.5.8.3, Table 18).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XrefEntry {
    /// A free object (`f`, type 0): the next free object number and the generation to use
    /// when the number is reused.
    Free {
        /// The next object number in the free list (0 ends it).
        next: u32,
        /// The generation for the next use of this object number.
        generation: u16,
    },
    /// An object in use at a byte offset (`n`, type 1). The offset is relative to the header,
    /// like every builder offset.
    InUse {
        /// Byte offset of `N G obj`, relative to the header.
        offset: u64,
        /// Generation number.
        generation: u16,
    },
    /// An object stored in an object stream (type 2; cross-reference streams only). A table
    /// leaves it out, as a hybrid file's table must (§7.5.8.4).
    Compressed {
        /// Object number of the object stream.
        stream: u32,
        /// Index of the object within the object stream.
        index: u32,
    },
}

/// How [`PdfBuilder::stream_obj`] writes `/Length`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LengthSpec {
    /// `/Length n` with the given value, right or wrong.
    Direct(i64),
    /// `/Length N G R`. The caller writes object `N G` holding the length, a wrong length, a
    /// reference cycle, or nothing at all.
    Indirect(ObjectId),
    /// Any value text, written verbatim after `/Length ` (for example `5.5` or `(five)`).
    Raw(Vec<u8>),
    /// No `/Length` entry.
    Omit,
}

/// Options for [`PdfBuilder::xref_table`].
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XrefOpts {
    /// The EOL after each entry; also selects the line end of the `xref` and subsection lines.
    pub eol_variant: XrefEol,
    /// Writes this number in the first subsection header instead of the real first object
    /// number, without changing the entries. `Some(1)` reproduces the common bug of a section
    /// that lists object 0's entry first but claims to start at object 1.
    pub first_subsection_start: Option<u32>,
    /// Added to every in-use offset that is written (clamped at 0).
    pub offset_skew: i64,
    /// Entries added to, or replacing, the recorded ones.
    pub extra_entries: Vec<(u32, XrefEntry)>,
    /// Object numbers left out of the section.
    pub omit: Vec<u32>,
}

impl XrefOpts {
    /// The defaults: `SP LF` entries, correct subsection numbers and offsets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`XrefOpts::eol_variant`].
    #[must_use]
    pub fn with_eol_variant(mut self, eol: XrefEol) -> Self {
        self.eol_variant = eol;
        self
    }

    /// Sets [`XrefOpts::first_subsection_start`].
    #[must_use]
    pub fn with_first_subsection_start(mut self, start: u32) -> Self {
        self.first_subsection_start = Some(start);
        self
    }

    /// Sets [`XrefOpts::offset_skew`].
    #[must_use]
    pub fn with_offset_skew(mut self, skew: i64) -> Self {
        self.offset_skew = skew;
        self
    }

    /// Adds an entry to [`XrefOpts::extra_entries`].
    #[must_use]
    pub fn with_entry(mut self, num: u32, entry: XrefEntry) -> Self {
        self.extra_entries.push((num, entry));
        self
    }

    /// Adds an object number to [`XrefOpts::omit`].
    #[must_use]
    pub fn with_omitted(mut self, num: u32) -> Self {
        self.omit.push(num);
        self
    }
}

/// Options for [`PdfBuilder::xref_stream`].
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XrefStreamOpts {
    /// Extra entries for the stream dictionary, which doubles as the trailer (§7.5.8.2), for
    /// example `/Root 1 0 R /ID [...] /Prev 123`. `/Type`, `/Size`, `/W`, `/Index`, `/Filter`,
    /// `/DecodeParms` and `/Length` are written by the builder.
    pub trailer: Vec<u8>,
    /// The `/W` field widths in bytes. `None` picks the smallest widths that hold every value.
    /// A zero width leaves the field out, so the reader must use its default (§7.5.8.2): with
    /// `W[0] = 0` every entry is type 1, so entries of other types are left out of the section.
    pub widths: Option<[u8; 3]>,
    /// Compress the entries with Flate (default `true`).
    pub compress: bool,
    /// Apply the PNG Up predictor (`/Predictor 12`) before compressing, as many writers do.
    /// Ignored without compression.
    pub predictor: bool,
    /// Write the stream that a hybrid file's trailer names in `/XRefStm` (§7.5.8.4): it lists
    /// only the compressed objects recorded since the last section (plus itself), does not end
    /// the section, and is not what `startxref` points to. The [`PdfBuilder::xref_table`] that
    /// follows lists everything else and leaves the compressed objects out: qpdf and poppler
    /// treat an object that the table lists as free as deleted and never look it up in the
    /// `/XRefStm` stream.
    pub hybrid: bool,
    /// Added to every in-use offset that is written (clamped at 0).
    pub offset_skew: i64,
    /// Entries added to, or replacing, the recorded ones.
    pub extra_entries: Vec<(u32, XrefEntry)>,
    /// Object numbers left out of the section.
    pub omit: Vec<u32>,
}

impl Default for XrefStreamOpts {
    fn default() -> Self {
        XrefStreamOpts {
            trailer: Vec::new(),
            widths: None,
            compress: true,
            predictor: false,
            hybrid: false,
            offset_skew: 0,
            extra_entries: Vec::new(),
            omit: Vec::new(),
        }
    }
}

impl XrefStreamOpts {
    /// The defaults: Flate without predictor, automatic widths.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`XrefStreamOpts::trailer`].
    #[must_use]
    pub fn with_trailer(mut self, entries: impl AsRef<[u8]>) -> Self {
        self.trailer = entries.as_ref().to_vec();
        self
    }

    /// Sets [`XrefStreamOpts::widths`].
    #[must_use]
    pub fn with_widths(mut self, widths: [u8; 3]) -> Self {
        self.widths = Some(widths);
        self
    }

    /// Sets [`XrefStreamOpts::compress`].
    #[must_use]
    pub fn with_compression(mut self, compress: bool) -> Self {
        self.compress = compress;
        self
    }

    /// Sets [`XrefStreamOpts::predictor`].
    #[must_use]
    pub fn with_predictor(mut self, predictor: bool) -> Self {
        self.predictor = predictor;
        self
    }

    /// Sets [`XrefStreamOpts::hybrid`].
    #[must_use]
    pub fn with_hybrid(mut self, hybrid: bool) -> Self {
        self.hybrid = hybrid;
        self
    }

    /// Sets [`XrefStreamOpts::offset_skew`].
    #[must_use]
    pub fn with_offset_skew(mut self, skew: i64) -> Self {
        self.offset_skew = skew;
        self
    }

    /// Adds an entry to [`XrefStreamOpts::extra_entries`].
    #[must_use]
    pub fn with_entry(mut self, num: u32, entry: XrefEntry) -> Self {
        self.extra_entries.push((num, entry));
        self
    }

    /// Adds an object number to [`XrefStreamOpts::omit`].
    #[must_use]
    pub fn with_omitted(mut self, num: u32) -> Self {
        self.omit.push(num);
        self
    }
}

/// Options for [`PdfBuilder::objstm`].
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjStmOpts {
    /// `/Extends`: the object stream this one extends (§7.5.7).
    pub extends: Option<ObjectId>,
    /// Compress the stream with Flate (default `true`).
    pub compress: bool,
    /// Writes this `/N` instead of the real object count.
    pub n_override: Option<i64>,
    /// Writes this `/First` instead of the real offset of the first object.
    pub first_override: Option<i64>,
    /// Extra entries for the stream dictionary.
    pub extra_dict: Vec<u8>,
}

impl Default for ObjStmOpts {
    fn default() -> Self {
        ObjStmOpts {
            extends: None,
            compress: true,
            n_override: None,
            first_override: None,
            extra_dict: Vec::new(),
        }
    }
}

impl ObjStmOpts {
    /// The defaults: Flate, correct `/N` and `/First`, no `/Extends`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`ObjStmOpts::extends`].
    #[must_use]
    pub fn with_extends(mut self, stream: ObjectId) -> Self {
        self.extends = Some(stream);
        self
    }

    /// Sets [`ObjStmOpts::compress`].
    #[must_use]
    pub fn with_compression(mut self, compress: bool) -> Self {
        self.compress = compress;
        self
    }

    /// Sets [`ObjStmOpts::n_override`].
    #[must_use]
    pub fn with_n(mut self, n: i64) -> Self {
        self.n_override = Some(n);
        self
    }

    /// Sets [`ObjStmOpts::first_override`].
    #[must_use]
    pub fn with_first(mut self, first: i64) -> Self {
        self.first_override = Some(first);
        self
    }

    /// Sets [`ObjStmOpts::extra_dict`].
    #[must_use]
    pub fn with_extra_dict(mut self, entries: impl AsRef<[u8]>) -> Self {
        self.extra_dict = entries.as_ref().to_vec();
        self
    }
}

/// Where the builder wrote an indirect object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRecord {
    /// The object's identifier.
    pub id: ObjectId,
    /// Offset of `N G obj`, relative to the header.
    pub offset: u64,
    /// Offset just past `endobj` and its EOL.
    pub end: u64,
    /// For a stream, the byte range of its data (relative to the header).
    pub stream_data: Option<Range<u64>>,
}

/// Where the builder put an object inside an object stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressedRecord {
    /// The object's number (its generation is always 0, §7.5.7).
    pub num: u32,
    /// Object number of the object stream.
    pub stream: u32,
    /// Index within the object stream.
    pub index: u32,
}

/// A fixed-width number written now and filled in later with [`PdfBuilder::fill`], for values
/// that are only known after more of the file is written (such as a `/Prev` that points
/// forward to build a loop).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placeholder {
    at: usize,
}

impl Placeholder {
    /// The number of digits a placeholder holds. Values are zero-padded to this width, which
    /// is still a valid PDF integer (§7.3.3).
    pub const WIDTH: usize = 10;
}

/// A byte-level PDF writer that records true offsets. See the [module docs](self).
///
/// Methods append to the file and return `&mut Self` for chaining. Nothing is validated:
/// whatever is asked for is written, which is the point.
#[derive(Clone, Debug, Default)]
pub struct PdfBuilder {
    /// Bytes placed before the header when the file is built.
    junk: Vec<u8>,
    /// The file from the header on; offsets are positions in this buffer.
    body: Vec<u8>,
    /// Every indirect object written, in order.
    objects: Vec<ObjectRecord>,
    /// Every object written into an object stream, in order.
    compressed: Vec<CompressedRecord>,
    /// Entries recorded since the last cross-reference section.
    pending: BTreeMap<u32, XrefEntry>,
    /// Offsets of the cross-reference sections written (`xref` keyword or stream object).
    sections: Vec<u64>,
    /// The highest object number recorded so far.
    max_num: Option<u32>,
}

impl PdfBuilder {
    /// An empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Writes the header `%PDF-<version>` and the binary-marker comment line (§7.5.2).
    pub fn header(&mut self, version: &str) -> &mut Self {
        self.body.extend_from_slice(b"%PDF-");
        self.body.extend_from_slice(version.as_bytes());
        // §7.5.2: a comment with at least four bytes >= 128 marks the file as binary.
        self.body.extend_from_slice(b"\n%\xE2\xE3\xCF\xD3\n");
        self
    }

    /// Adds bytes that go before everything else, the header included, when the file is
    /// built. Offsets stay relative to the header (see the [module docs](self)).
    pub fn junk_prefix(&mut self, junk: impl AsRef<[u8]>) -> &mut Self {
        self.junk.extend_from_slice(junk.as_ref());
        self
    }

    /// Appends bytes verbatim.
    pub fn raw(&mut self, bytes: impl AsRef<[u8]>) -> &mut Self {
        self.body.extend_from_slice(bytes.as_ref());
        self
    }

    /// Writes `num gen obj`, the body text verbatim, and `endobj`, and records the object.
    ///
    /// ```
    /// use folioxide_testkit::builder::PdfBuilder;
    ///
    /// let mut b = PdfBuilder::new();
    /// b.obj(3, 0, "[1 2 3]");
    /// assert_eq!(b.build(), b"3 0 obj\n[1 2 3]\nendobj\n");
    /// assert_eq!(b.offset_of(3, 0), Some(0));
    /// ```
    pub fn obj(&mut self, num: u32, generation: u16, body: impl AsRef<[u8]>) -> &mut Self {
        let offset = self.position();
        self.object_header(num, generation);
        self.body.extend_from_slice(body.as_ref());
        self.body.extend_from_slice(b"\nendobj\n");
        self.record(num, generation, offset, None);
        self
    }

    /// Like [`PdfBuilder::obj`], with the body written by the `folioxide-syntax` serializer.
    pub fn object(&mut self, num: u32, generation: u16, object: &Object) -> &mut Self {
        let mut text = Vec::new();
        serialize_object(object, &mut text);
        self.obj(num, generation, text)
    }

    /// Writes a stream object: `num gen obj`, the dictionary with `/Length`, `stream`, the data
    /// verbatim, `endstream` and `endobj` (§7.3.8).
    ///
    /// `dict` holds the dictionary entries, with or without the surrounding `<<` `>>`; it must
    /// not contain `/Length`. `length` chooses how `/Length` is written: `None` writes the true
    /// data length, anything else see [`LengthSpec`]. The data is preceded by `stream` + LF and
    /// followed by LF + `endstream`, so a correct `/Length` is `data.len()`.
    ///
    /// ```
    /// use folioxide_testkit::builder::{LengthSpec, PdfBuilder};
    ///
    /// let mut b = PdfBuilder::new();
    /// b.stream_obj(4, 0, "", b"BT ET", None);
    /// b.stream_obj(5, 0, "<< /Type /XObject >>", b"xyz", Some(LengthSpec::Direct(99)));
    /// let pdf = b.build();
    /// assert!(pdf.starts_with(b"4 0 obj\n<</Length 5>>\nstream\nBT ET\nendstream\nendobj\n"));
    /// assert!(pdf.ends_with(b"<</Type /XObject /Length 99>>\nstream\nxyz\nendstream\nendobj\n"));
    /// assert_eq!(b.stream_data_range(4, 0), Some(29..34));
    /// ```
    pub fn stream_obj(
        &mut self,
        num: u32,
        generation: u16,
        dict: impl AsRef<[u8]>,
        data: &[u8],
        length: Option<LengthSpec>,
    ) -> &mut Self {
        let offset = self.position();
        self.object_header(num, generation);
        let inner = dict_inner(dict.as_ref());
        self.body.extend_from_slice(b"<<");
        self.body.extend_from_slice(inner);
        let length_text = match length {
            None => Some(data.len().to_string().into_bytes()),
            Some(LengthSpec::Direct(n)) => Some(n.to_string().into_bytes()),
            Some(LengthSpec::Indirect(id)) => {
                Some(format!("{} {} R", id.num, id.r#gen).into_bytes())
            }
            Some(LengthSpec::Raw(text)) => Some(text),
            Some(LengthSpec::Omit) => None,
        };
        if let Some(text) = length_text {
            if !inner.is_empty() {
                self.body.push(b' ');
            }
            self.body.extend_from_slice(b"/Length ");
            self.body.extend_from_slice(&text);
        }
        // §7.3.8.1: `stream` is followed by an EOL; the EOL before `endstream` is not data.
        self.body.extend_from_slice(b">>\nstream\n");
        let data_start = self.position();
        self.body.extend_from_slice(data);
        let data_end = self.position();
        self.body.extend_from_slice(b"\nendstream\nendobj\n");
        self.record(num, generation, offset, Some(data_start..data_end));
        self
    }

    /// Writes a stream whose data is `plain` compressed with Flate ([`FLATE_LEVEL`]), with
    /// `/Filter /FlateDecode` added after the given entries and a correct `/Length`.
    pub fn flate_stream_obj(
        &mut self,
        num: u32,
        generation: u16,
        dict: impl AsRef<[u8]>,
        plain: &[u8],
    ) -> &mut Self {
        let encoded = encode_flate(plain, FLATE_LEVEL);
        let dict = with_entries(dict_inner(dict.as_ref()), b"/Filter /FlateDecode");
        self.stream_obj(num, generation, dict, &encoded, None)
    }

    /// Writes an object stream (§7.5.7) holding `objects` (number and body text) and records
    /// each of them as compressed, so a following [`PdfBuilder::xref_stream`] lists them as
    /// type 2 entries.
    ///
    /// The stream data is the header of `num offset` pairs, an LF, and the bodies separated by
    /// LF; `/First` is the length of the header including its LF.
    pub fn objstm<B: AsRef<[u8]>>(
        &mut self,
        num: u32,
        objects: &[(u32, B)],
        opts: ObjStmOpts,
    ) -> &mut Self {
        let mut header = Vec::new();
        let mut bodies = Vec::new();
        for (i, (obj_num, body)) in objects.iter().enumerate() {
            if i > 0 {
                header.push(b' ');
                bodies.push(b'\n');
            }
            header.extend_from_slice(format!("{obj_num} {}", bodies.len()).as_bytes());
            bodies.extend_from_slice(body.as_ref());
        }
        header.push(b'\n');
        let n = opts.n_override.unwrap_or(objects.len() as i64);
        let first = opts.first_override.unwrap_or(header.len() as i64);
        let mut dict = format!("/Type /ObjStm /N {n} /First {first}").into_bytes();
        if let Some(extends) = opts.extends {
            dict.extend_from_slice(
                format!(" /Extends {} {} R", extends.num, extends.r#gen).as_bytes(),
            );
        }
        let dict = with_entries(&dict, dict_inner(&opts.extra_dict));
        let mut data = header;
        data.extend_from_slice(&bodies);
        if opts.compress {
            self.flate_stream_obj(num, 0, dict, &data);
        } else {
            self.stream_obj(num, 0, dict, &data, None);
        }
        for (index, (obj_num, _)) in (0u32..).zip(objects) {
            self.note_num(*obj_num);
            self.pending
                .insert(*obj_num, XrefEntry::Compressed { stream: num, index });
            self.compressed.push(CompressedRecord {
                num: *obj_num,
                stream: num,
                index,
            });
        }
        self
    }

    /// Records a free entry for `num` (with `next_generation` for its next use) in the next
    /// cross-reference section, as an incremental update that deletes an object does.
    pub fn free(&mut self, num: u32, next_generation: u16) -> &mut Self {
        self.note_num(num);
        self.pending.insert(
            num,
            XrefEntry::Free {
                next: 0,
                generation: next_generation,
            },
        );
        self
    }

    /// Writes a cross-reference table section (§7.5.4) listing every entry recorded since the
    /// previous section, adjusted by `opts`.
    ///
    /// The first section of a file is complete: one subsection from object 0 (the head of the
    /// free list, generation 65535) to the highest number, with unused numbers free and the free
    /// list linked. Later sections (incremental updates, §7.5.6) list only what changed, in one
    /// subsection per run of consecutive numbers.
    ///
    /// Compressed objects are left out, so the subsections skip their numbers: that is how a
    /// hybrid file's table must treat them (see [`XrefStreamOpts::hybrid`]).
    pub fn xref_table(&mut self, opts: XrefOpts) -> &mut Self {
        let full = self.sections.is_empty();
        let mut entries =
            self.finish_entries(self.pending.clone(), full, &opts.extra_entries, &opts.omit);
        entries.retain(|_, entry| !matches!(entry, XrefEntry::Compressed { .. }));
        let offset = self.position();
        self.sections.push(offset);
        self.pending.clear();

        let line_end = opts.eol_variant.line_end();
        self.body.extend_from_slice(b"xref");
        self.body.extend_from_slice(line_end);
        for (i, (start, run)) in subsections(&entries).into_iter().enumerate() {
            let written_start = if i == 0 {
                opts.first_subsection_start.unwrap_or(start)
            } else {
                start
            };
            self.body
                .extend_from_slice(format!("{written_start} {}", run.len()).as_bytes());
            self.body.extend_from_slice(line_end);
            for entry in run {
                let (field, generation, kind) = match entry {
                    XrefEntry::InUse { offset, generation } => {
                        (skewed(offset, opts.offset_skew), generation, 'n')
                    }
                    XrefEntry::Free { next, generation } => (u64::from(next), generation, 'f'),
                    XrefEntry::Compressed { .. } => (0, 0, 'f'),
                };
                let field = field.min(9_999_999_999);
                self.body
                    .extend_from_slice(format!("{field:010} {generation:05} {kind}").as_bytes());
                self.body.extend_from_slice(opts.eol_variant.entry_end());
            }
        }
        self
    }

    /// Writes a cross-reference stream object `num 0 obj` (§7.5.8) listing every entry
    /// recorded since the previous section plus the stream itself, adjusted by `opts`.
    ///
    /// The first section of a file is complete, as for [`PdfBuilder::xref_table`], and its
    /// `/Index` is left out (the default `[0 Size]`); later sections have an `/Index` pair per
    /// run of consecutive numbers. `/Size` is one more than the highest object number recorded.
    pub fn xref_stream(&mut self, num: u32, opts: XrefStreamOpts) -> &mut Self {
        let offset = self.position();
        self.note_num(num);
        let full = self.sections.is_empty() && !opts.hybrid;
        let mut entries: BTreeMap<u32, XrefEntry> = self
            .pending
            .iter()
            .filter(|(_, entry)| !opts.hybrid || matches!(entry, XrefEntry::Compressed { .. }))
            .map(|(n, entry)| (*n, *entry))
            .collect();
        entries.insert(
            num,
            XrefEntry::InUse {
                offset,
                generation: 0,
            },
        );
        let mut entries = self.finish_entries(entries, full, &opts.extra_entries, &opts.omit);

        // Field values per entry: (type, field 2, field 3), §7.5.8.3 Table 18.
        let fields = |entry: &XrefEntry| -> [u64; 3] {
            match *entry {
                XrefEntry::Free { next, generation } => [0, u64::from(next), u64::from(generation)],
                XrefEntry::InUse { offset, generation } => {
                    [1, skewed(offset, opts.offset_skew), u64::from(generation)]
                }
                XrefEntry::Compressed { stream, index } => [2, u64::from(stream), u64::from(index)],
            }
        };
        let widths = opts.widths.unwrap_or_else(|| {
            let max = |i: usize| {
                entries
                    .values()
                    .map(|e| fields(e).get(i).copied().unwrap_or(0))
                    .max()
                    .unwrap_or(0)
            };
            [1, bytes_needed(max(1)), bytes_needed(max(2))]
        });
        if widths[0] == 0 {
            // Without a type field every entry reads as type 1 (§7.5.8.2).
            entries.retain(|_, entry| matches!(entry, XrefEntry::InUse { .. }));
        }
        let runs = subsections(&entries);
        let mut rows = Vec::new();
        for (_, run) in &runs {
            for entry in run {
                for (value, width) in fields(entry).into_iter().zip(widths) {
                    push_be(&mut rows, value, width);
                }
            }
        }

        let size = self.size();
        let mut dict = format!(
            "/Type /XRef /Size {size} /W [{} {} {}]",
            widths[0], widths[1], widths[2]
        );
        let default_index = runs.len() == 1
            && runs
                .first()
                .is_some_and(|(start, run)| *start == 0 && run.len() as u64 == u64::from(size));
        if !(full && default_index) {
            dict.push_str(" /Index [");
            for (i, (start, run)) in runs.iter().enumerate() {
                if i > 0 {
                    dict.push(' ');
                }
                dict.push_str(&format!("{start} {}", run.len()));
            }
            dict.push(']');
        }
        let columns: usize = widths.iter().map(|&w| usize::from(w)).sum();
        let data = if opts.compress {
            dict.push_str(" /Filter /FlateDecode");
            let rows = if opts.predictor {
                dict.push_str(&format!(
                    " /DecodeParms <</Predictor 12 /Columns {columns}>>"
                ));
                png_up(&rows, columns)
            } else {
                rows
            };
            encode_flate(&rows, FLATE_LEVEL)
        } else {
            rows
        };
        let dict = with_entries(dict.as_bytes(), dict_inner(&opts.trailer));
        self.stream_obj(num, 0, dict, &data, None);
        if !opts.hybrid {
            self.sections.push(offset);
            self.pending.clear();
        }
        self
    }

    /// Writes `trailer` and the trailer dictionary (§7.5.5). `dict` holds the entries, with or
    /// without the surrounding `<<` `>>`; nothing is added (write `/Size`, `/Root`, `/Prev`, ...
    /// yourself; [`PdfBuilder::size`] and [`PdfBuilder::last_xref_offset`] help).
    pub fn trailer(&mut self, dict: impl AsRef<[u8]>) -> &mut Self {
        self.body.extend_from_slice(b"trailer\n<<");
        self.body.extend_from_slice(dict_inner(dict.as_ref()));
        self.body.extend_from_slice(b">>\n");
        self
    }

    /// Writes `startxref` and an offset: `offset_override`, or else the offset of the last
    /// cross-reference section written (0 if there is none).
    pub fn startxref(&mut self, offset_override: Option<u64>) -> &mut Self {
        let value = offset_override
            .or_else(|| self.last_xref_offset())
            .unwrap_or(0);
        self.body
            .extend_from_slice(format!("startxref\n{value}\n").as_bytes());
        self
    }

    /// Writes the end-of-file marker `%%EOF` and an LF (§7.5.5).
    pub fn eof(&mut self) -> &mut Self {
        self.body.extend_from_slice(b"%%EOF\n");
        self
    }

    /// Writes a [`Placeholder::WIDTH`]-digit number (`0000000000`) to be set later with
    /// [`PdfBuilder::fill`].
    pub fn placeholder(&mut self) -> Placeholder {
        let at = self.body.len();
        self.body.extend_from_slice(&[b'0'; Placeholder::WIDTH]);
        Placeholder { at }
    }

    /// Sets a placeholder to `value`, zero-padded. Values too large for the width are written
    /// as `9999999999`.
    pub fn fill(&mut self, placeholder: Placeholder, value: u64) -> &mut Self {
        let text = format!("{:010}", value.min(9_999_999_999));
        if let Some(slot) = self
            .body
            .get_mut(placeholder.at..placeholder.at + Placeholder::WIDTH)
        {
            slot.copy_from_slice(text.as_bytes());
        }
        self
    }

    /// The finished file: the junk prefix, then everything else.
    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.junk.len() + self.body.len());
        out.extend_from_slice(&self.junk);
        out.extend_from_slice(&self.body);
        out
    }

    /// Like [`PdfBuilder::build`], consuming the builder.
    pub fn into_bytes(self) -> Vec<u8> {
        if self.junk.is_empty() {
            self.body
        } else {
            self.build()
        }
    }

    /// The offset where the next byte will be written (relative to the header).
    pub fn position(&self) -> u64 {
        self.body.len() as u64
    }

    /// The length of the junk prefix: where the header starts in the built file.
    pub fn header_offset(&self) -> u64 {
        self.junk.len() as u64
    }

    /// `/Size` for a trailer written now: one more than the highest object number recorded
    /// (objects, compressed objects and free entries), or 1 if there is none.
    pub fn size(&self) -> u32 {
        self.max_num.map_or(1, |max| max.saturating_add(1))
    }

    /// The offset of the most recent cross-reference section (the `xref` keyword or the
    /// stream's `N G obj`), as written in `startxref` and `/Prev`. Hybrid streams
    /// ([`XrefStreamOpts::hybrid`]) are not sections; use [`PdfBuilder::offset_of`] for
    /// `/XRefStm`.
    pub fn last_xref_offset(&self) -> Option<u64> {
        self.sections.last().copied()
    }

    /// The offsets of every cross-reference section written, oldest first.
    pub fn xref_offsets(&self) -> &[u64] {
        &self.sections
    }

    /// The offset of the most recent `num generation obj` written.
    pub fn offset_of(&self, num: u32, generation: u16) -> Option<u64> {
        self.find(num, generation).map(|record| record.offset)
    }

    /// The data range of the most recent stream object `num generation` written.
    pub fn stream_data_range(&self, num: u32, generation: u16) -> Option<Range<u64>> {
        self.find(num, generation)
            .and_then(|record| record.stream_data.clone())
    }

    /// Every indirect object written, in order (an object number appears once per revision
    /// that writes it).
    pub fn objects(&self) -> &[ObjectRecord] {
        &self.objects
    }

    /// Every object written into an object stream, in order.
    pub fn compressed_objects(&self) -> &[CompressedRecord] {
        &self.compressed
    }

    fn find(&self, num: u32, generation: u16) -> Option<&ObjectRecord> {
        self.objects
            .iter()
            .rev()
            .find(|record| record.id == ObjectId::new(num, generation))
    }

    fn object_header(&mut self, num: u32, generation: u16) {
        self.body
            .extend_from_slice(format!("{num} {generation} obj\n").as_bytes());
    }

    fn record(&mut self, num: u32, generation: u16, offset: u64, data: Option<Range<u64>>) {
        self.note_num(num);
        self.objects.push(ObjectRecord {
            id: ObjectId::new(num, generation),
            offset,
            end: self.position(),
            stream_data: data,
        });
        self.pending
            .insert(num, XrefEntry::InUse { offset, generation });
    }

    fn note_num(&mut self, num: u32) {
        self.max_num = Some(self.max_num.map_or(num, |max| max.max(num)));
    }

    /// Applies extra and omitted entries and, for a complete section, fills the gaps from 0 to
    /// the highest number with free entries and links the free list (§7.5.4).
    fn finish_entries(
        &self,
        mut entries: BTreeMap<u32, XrefEntry>,
        full: bool,
        extra: &[(u32, XrefEntry)],
        omit: &[u32],
    ) -> BTreeMap<u32, XrefEntry> {
        for (num, entry) in extra {
            entries.insert(*num, *entry);
        }
        if full {
            let top = entries
                .keys()
                .next_back()
                .copied()
                .map_or(self.size(), |max| self.size().max(max.saturating_add(1)));
            entries.entry(0).or_insert(XrefEntry::Free {
                next: 0,
                generation: 65535,
            });
            for num in 1..top {
                entries.entry(num).or_insert(XrefEntry::Free {
                    next: 0,
                    generation: 0,
                });
            }
            // Link the free list: 0 -> first free -> ... -> last free -> 0.
            let free: Vec<u32> = entries
                .iter()
                .filter(|(_, entry)| matches!(entry, XrefEntry::Free { .. }))
                .map(|(num, _)| *num)
                .collect();
            for (i, num) in free.iter().enumerate() {
                let next = free.get(i + 1).copied().unwrap_or(0);
                if let Some(XrefEntry::Free { next: slot, .. }) = entries.get_mut(num) {
                    *slot = next;
                }
            }
        }
        for num in omit {
            entries.remove(num);
        }
        entries
    }
}

/// The entries of `dict` text without surrounding white-space and `<<` `>>`.
fn dict_inner(dict: &[u8]) -> &[u8] {
    let trimmed = dict.trim_ascii();
    trimmed
        .strip_prefix(b"<<")
        .and_then(|rest| rest.strip_suffix(b">>"))
        .map_or(trimmed, <[u8]>::trim_ascii)
}

/// `a` and `b` joined by a space (either may be empty).
fn with_entries(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = a.to_vec();
    if !a.is_empty() && !b.is_empty() {
        out.push(b' ');
    }
    out.extend_from_slice(b);
    out
}

/// Runs of consecutive object numbers: `(first number, entries)`.
fn subsections(entries: &BTreeMap<u32, XrefEntry>) -> Vec<(u32, Vec<XrefEntry>)> {
    let mut runs: Vec<(u32, Vec<XrefEntry>)> = Vec::new();
    let mut expected = None;
    for (&num, &entry) in entries {
        match runs.last_mut() {
            Some((_, run)) if expected == Some(num) => run.push(entry),
            _ => runs.push((num, vec![entry])),
        }
        expected = num.checked_add(1);
    }
    runs
}

fn skewed(offset: u64, skew: i64) -> u64 {
    offset.saturating_add_signed(skew)
}

/// The number of bytes needed to hold `value` big-endian (at least 1).
fn bytes_needed(value: u64) -> u8 {
    let bits = u64::BITS - value.leading_zeros();
    u8::try_from(bits.div_ceil(8).max(1)).unwrap_or(8)
}

/// Appends the low `width` bytes of `value`, big-endian (§7.5.8.2: high-order byte first).
fn push_be(out: &mut Vec<u8>, value: u64, width: u8) {
    for i in (0..u32::from(width)).rev() {
        let byte = value.checked_shr(8 * i).unwrap_or(0) & 0xFF;
        out.push(byte as u8);
    }
}

/// Encodes rows of `columns` bytes with the PNG Up predictor (tag 2 per row; §7.4.4.4).
fn png_up(data: &[u8], columns: usize) -> Vec<u8> {
    let columns = columns.max(1);
    let mut out = Vec::with_capacity(data.len() + data.len() / columns + 1);
    let mut previous = vec![0u8; columns];
    for row in data.chunks(columns) {
        out.push(2);
        for (byte, above) in row.iter().zip(previous.iter_mut()) {
            out.push(byte.wrapping_sub(*above));
            *above = *byte;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use folioxide_syntax::filters::{Filter, FilterParams, decode};
    use folioxide_syntax::{ParseCtx, parse_indirect_at};

    fn text(b: &PdfBuilder) -> String {
        String::from_utf8_lossy(&b.build()).into_owned()
    }

    #[test]
    fn header_has_binary_marker() {
        let mut b = PdfBuilder::new();
        b.header("2.0");
        assert_eq!(b.build(), b"%PDF-2.0\n%\xE2\xE3\xCF\xD3\n");
        assert_eq!(b.position(), 15);
    }

    #[test]
    fn first_table_is_complete_with_linked_free_list() {
        let mut b = PdfBuilder::new();
        b.obj(1, 0, "1").obj(3, 0, "3").obj(5, 2, "5");
        b.xref_table(XrefOpts::default());
        let out = text(&b);
        let xref = &out[out.find("xref").unwrap()..];
        assert_eq!(
            xref,
            "xref\n0 6\n\
             0000000002 65535 f \n\
             0000000000 00000 n \n\
             0000000004 00000 f \n\
             0000000017 00000 n \n\
             0000000000 00000 f \n\
             0000000034 00002 n \n"
        );
        assert_eq!(b.size(), 6);
        assert_eq!(b.last_xref_offset(), Some(51));
    }

    #[test]
    fn table_entries_are_20_bytes_for_conforming_eols() {
        for eol in XrefEol::ALL {
            let mut b = PdfBuilder::new();
            b.obj(1, 0, "null");
            b.xref_table(XrefOpts::new().with_eol_variant(eol));
            let out = b.build();
            let header_len = 4 + eol.line_end().len() + 3 + eol.line_end().len();
            let table = &out[b.last_xref_offset().unwrap() as usize..];
            let entries = &table[header_len..];
            let entry_len = if eol.is_conforming() { 20 } else { 19 };
            assert_eq!(entries.len(), 2 * entry_len, "{eol:?}");
            assert!(entries.ends_with(eol.entry_end()));
        }
    }

    #[test]
    fn update_sections_have_one_subsection_per_run() {
        let mut b = PdfBuilder::new();
        b.obj(1, 0, "1").obj(2, 0, "2");
        b.xref_table(XrefOpts::default());
        b.obj(2, 0, "2b").free(4, 1).obj(5, 0, "5");
        let start = b.position() as usize;
        b.xref_table(XrefOpts::default());
        let out = b.build();
        let section = String::from_utf8_lossy(&out[start..]);
        let lines: Vec<&str> = section.lines().collect();
        assert_eq!(lines[0], "xref");
        assert_eq!(lines[1], "2 1");
        assert!(lines[2].ends_with(" 00000 n "));
        assert_eq!(lines[3], "4 2");
        assert_eq!(lines[4], "0000000000 00001 f ");
        assert!(lines[5].ends_with(" 00000 n "));
        assert_eq!(b.xref_offsets().len(), 2);
    }

    #[test]
    fn first_subsection_start_and_skew() {
        let mut b = PdfBuilder::new();
        b.obj(1, 0, "1");
        b.xref_table(
            XrefOpts::new()
                .with_first_subsection_start(1)
                .with_offset_skew(7),
        );
        let out = text(&b);
        assert!(out.ends_with("xref\n1 2\n0000000000 65535 f \n0000000007 00000 n \n"));
    }

    #[test]
    fn stream_length_variants() {
        let mut b = PdfBuilder::new();
        b.stream_obj(1, 0, "<< /A 1 >>", b"abc", Some(LengthSpec::Omit));
        b.stream_obj(
            2,
            0,
            "",
            b"abc",
            Some(LengthSpec::Indirect(ObjectId::new(9, 0))),
        );
        b.stream_obj(3, 0, "/B 2", b"abc", Some(LengthSpec::Raw(b"(x)".to_vec())));
        let out = text(&b);
        assert!(out.contains("1 0 obj\n<</A 1>>\nstream\nabc\n"));
        assert!(out.contains("2 0 obj\n<</Length 9 0 R>>\nstream\n"));
        assert!(out.contains("3 0 obj\n<</B 2 /Length (x)>>\nstream\n"));
        let range = b.stream_data_range(1, 0).unwrap();
        assert_eq!(&b.build()[range.start as usize..range.end as usize], b"abc");
    }

    #[test]
    fn junk_prefix_does_not_shift_offsets() {
        let mut b = PdfBuilder::new();
        b.junk_prefix(b"JUNK").header("1.4").obj(1, 0, "null");
        assert_eq!(b.header_offset(), 4);
        assert_eq!(b.offset_of(1, 0), Some(15));
        let out = b.build();
        assert_eq!(&out[4 + 15..4 + 22], b"1 0 obj");
        b.xref_table(XrefOpts::default()).startxref(None);
        assert!(text(&b).ends_with(&format!("startxref\n{}\n", b.last_xref_offset().unwrap())));
    }

    #[test]
    fn startxref_override_and_placeholder() {
        let mut b = PdfBuilder::new();
        let ph = b.placeholder();
        b.raw(b" ").startxref(Some(42)).eof();
        b.fill(ph, 1234);
        assert_eq!(text(&b), "0000001234 startxref\n42\n%%EOF\n");
        b.fill(ph, u64::MAX);
        assert!(text(&b).starts_with("9999999999 "));
    }

    #[test]
    fn xref_stream_round_trips_through_the_filters() {
        let mut b = PdfBuilder::new();
        b.header("1.5").obj(1, 0, "<< >>").obj(2, 0, "<< >>");
        b.xref_stream(
            3,
            XrefStreamOpts::new()
                .with_predictor(true)
                .with_trailer("/Root 1 0 R"),
        );
        let out = b.build();
        let at = b.last_xref_offset().unwrap();
        let parsed = parse_indirect_at(&out, at as usize, &ParseCtx::default(), &|_| None).unwrap();
        let stream = parsed.object.as_stream().unwrap();
        let dict = &stream.dict;
        assert!(dict.is_type(b"XRef"));
        assert_eq!(dict.get_int(b"Size"), Some(4));
        assert!(dict.get(b"Index").is_none());
        assert_eq!(dict.get_ref(b"Root"), Some(ObjectId::new(1, 0)));
        let w: Vec<i64> = dict
            .get_array(b"W")
            .unwrap()
            .iter()
            .map(|o| o.as_int().unwrap())
            .collect();
        assert_eq!(w, [1, 1, 2]);
        let range = parsed.stream_data_range.unwrap();
        let raw = &out[range.start as usize..range.end as usize];
        let params = FilterParams::new().with_predictor(12).with_columns(4);
        let rows = decode(Filter::Flate, raw, &params, &Default::default()).unwrap();
        let o1 = b.offset_of(1, 0).unwrap() as u8;
        let o2 = b.offset_of(2, 0).unwrap() as u8;
        assert_eq!(
            rows.data,
            [
                0, 0, 0xFF, 0xFF, 1, o1, 0, 0, 1, o2, 0, 0, 1, at as u8, 0, 0
            ]
        );
    }

    #[test]
    fn xref_stream_zero_width_type_field_drops_other_types() {
        let mut b = PdfBuilder::new();
        b.obj(1, 0, "1").obj(3, 0, "3");
        b.xref_stream(
            4,
            XrefStreamOpts::new()
                .with_widths([0, 2, 0])
                .with_compression(false),
        );
        let out = text(&b);
        assert!(out.contains("/Type /XRef /Size 5 /W [0 2 0] /Index [1 1 3 2] /Length 6>>"));
    }

    #[test]
    fn objstm_records_compressed_entries() {
        let mut b = PdfBuilder::new();
        b.objstm(
            7,
            &[(1, "<< /A 1 >>"), (2, "[2]")],
            ObjStmOpts::new()
                .with_compression(false)
                .with_extends(ObjectId::new(6, 0)),
        );
        let out = text(&b);
        assert!(out.contains(
            "<</Type /ObjStm /N 2 /First 9 /Extends 6 0 R /Length 23>>\nstream\n1 0 2 11\n<< /A 1 >>\n[2]\n"
        ));
        assert_eq!(
            b.compressed_objects(),
            [
                CompressedRecord {
                    num: 1,
                    stream: 7,
                    index: 0
                },
                CompressedRecord {
                    num: 2,
                    stream: 7,
                    index: 1
                }
            ]
        );
        b.xref_stream(8, XrefStreamOpts::new().with_compression(false));
        assert!(text(&b).contains("/Type /XRef /Size 9 /W [1 1 2]"));
    }

    #[test]
    fn hybrid_stream_lists_only_compressed_objects() {
        let mut b = PdfBuilder::new();
        b.obj(3, 0, "3");
        b.objstm(4, &[(1, "1"), (2, "2")], ObjStmOpts::new());
        b.xref_stream(
            5,
            XrefStreamOpts::new()
                .with_hybrid(true)
                .with_compression(false),
        );
        assert!(b.last_xref_offset().is_none());
        assert!(text(&b).contains("/Index [1 2 5 1]"));
        b.xref_table(XrefOpts::default());
        let out = text(&b);
        let table = &out[out.rfind("xref\n").unwrap()..];
        assert!(table.starts_with("xref\n0 1\n0000000000 65535 f \n3 3\n"));
    }

    #[test]
    fn typed_objects_and_into_bytes() {
        let mut b = PdfBuilder::new();
        let mut dict = folioxide_syntax::Dict::new();
        dict.insert("Count", 2);
        dict.insert("Kids", vec![Object::Ref(ObjectId::new(3, 0))]);
        b.junk_prefix(b"J").object(2, 1, &Object::Dict(dict));
        assert_eq!(b.offset_of(2, 1), Some(0));
        assert_eq!(b.offset_of(2, 0), None);
        let built = b.build();
        assert_eq!(b.into_bytes(), built);
        assert_eq!(built, b"J2 1 obj\n<</Count 2 /Kids [3 0 R]>>\nendobj\n");
    }

    #[test]
    fn helpers() {
        assert_eq!(dict_inner(b" << /A 1 >> "), b"/A 1");
        assert_eq!(dict_inner(b"/A 1"), b"/A 1");
        assert_eq!(dict_inner(b"<<>>"), b"");
        assert_eq!(bytes_needed(0), 1);
        assert_eq!(bytes_needed(255), 1);
        assert_eq!(bytes_needed(256), 2);
        assert_eq!(bytes_needed(u64::MAX), 8);
        let mut out = Vec::new();
        push_be(&mut out, 0x0102_0304, 3);
        push_be(&mut out, 7, 0);
        push_be(&mut out, 1, 10);
        assert_eq!(out, [2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(png_up(&[1, 2, 3, 5], 2), [2, 1, 2, 2, 2, 3]);
    }
}

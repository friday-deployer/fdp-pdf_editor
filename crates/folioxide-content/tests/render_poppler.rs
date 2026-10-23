//! End to end: a one-page PDF built with `Document::new`, a `ContentBuilder` stream, both
//! standard-14 fonts in WinAnsiEncoding and two passthrough JPEGs (M4 brief §3.2, §4.7), read
//! back by Folioxide and by poppler 24.02 (brief §0 "What a viewer shows"):
//!
//! - Folioxide reopens it: the content stream, the font dictionaries and the JPEG bytes come
//!   back unchanged;
//! - `pdffonts` lists Helvetica and Helvetica-Bold as unembedded Type 1 fonts in WinAnsi;
//! - `pdftotext` reads every line, including all 217 printable WinAnsi codes, as
//!   [`win_ansi_decode`] says;
//! - `pdftotext -bbox` puts each word where our widths put it (poppler uses `/Widths`);
//! - `pdftoppm` draws the text dark, and the RGB image (component IDs `R`, `G`, `B`,
//!   `/ColorTransform 0`) in its four colours, upright, where the `cm` put it.
//!
//! The poppler checks are skipped, with a note on stderr, when the tools are not installed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use folioxide_content::builder::ContentBuilder;
use folioxide_content::encoding::{win_ansi_decode, win_ansi_encode};
use folioxide_content::image::jpeg;
use folioxide_content::standard14::Standard14Font;
use folioxide_model::Document;
use folioxide_syntax::{Dict, Object, ObjectId, OpenOptions, SaveOptions, Stream, StreamData};

const PAGE_W: f64 = 300.0;
const PAGE_H: f64 = 200.0;

/// Where the RGB test image (48 x 32, quadrants black, red / white, blue) is drawn.
const IMAGE_RGB: [f64; 4] = [200.0, 120.0, 96.0, 64.0]; // x, y, w, h
/// Where the gray image (minimal.pdf at 10 dpi, 85 x 110) is drawn.
const IMAGE_GRAY: [f64; 4] = [210.0, 10.0, 51.0, 66.0];

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/images")
            .join(name),
    )
    .unwrap()
}

/// One shown line: font, size, start, WinAnsi bytes.
struct Line {
    font: Standard14Font,
    size: f64,
    x: f64,
    y: f64,
    bytes: Vec<u8>,
}

impl Line {
    fn resource(&self) -> &'static [u8] {
        match self.font {
            Standard14Font::HelveticaBold => b"F2",
            _ => b"F1",
        }
    }
}

/// The lines of the sample page.
fn lines() -> Vec<Line> {
    let mut lines = vec![
        Line {
            font: Standard14Font::Helvetica,
            size: 14.0,
            x: 10.0,
            y: 176.0,
            bytes: win_ansi_encode("Folioxide content test").bytes,
        },
        Line {
            font: Standard14Font::HelveticaBold,
            size: 12.0,
            x: 10.0,
            y: 158.0,
            bytes: win_ansi_encode("Signed by Zoë Müller – “OK”").bytes,
        },
    ];
    // Every printable WinAnsi code except the spaces (0x20, 0xA0), five lines at 6 pt.
    let codes: Vec<u8> = (0x21..=0xFFu8)
        .filter(|&c| c != 0xA0 && win_ansi_decode(c).is_some())
        .collect();
    assert_eq!(codes.len(), 216);
    for (i, chunk) in codes.chunks(44).enumerate() {
        lines.push(Line {
            font: Standard14Font::Helvetica,
            size: 6.0,
            x: 10.0,
            y: 130.0 - 12.0 * i as f64,
            bytes: chunk.to_vec(),
        });
    }
    lines
}

/// The sample's content stream.
fn content(lines: &[Line]) -> Vec<u8> {
    let mut b = ContentBuilder::new();
    let [x, y, w, h] = IMAGE_RGB;
    b.save()
        .concat([w, 0.0, 0.0, h, x, y])
        .draw_xobject(b"Im1")
        .restore();
    let [x, y, w, h] = IMAGE_GRAY;
    b.save()
        .concat([w, 0.0, 0.0, h, x, y])
        .draw_xobject(b"Im2")
        .restore();
    // A frame around the gray image, so its area is visibly drawn whatever the image holds.
    b.save()
        .line_width(1.0)
        .stroke_rgb(0.0, 0.0, 0.0)
        .rect(x - 2.0, y - 2.0, w + 4.0, h + 4.0)
        .stroke()
        .restore();
    for line in lines {
        b.begin_text()
            .font(line.resource(), line.size)
            .fill_gray(0.0)
            .move_text(line.x, line.y)
            .show(&line.bytes)
            .end_text();
    }
    b.finish().unwrap()
}

/// A one-page document holding `content`, the two fonts and the two images.
fn sample(content: Vec<u8>) -> Vec<u8> {
    let mut doc = Document::new();
    let pages_id = doc
        .catalog()
        .unwrap()
        .as_dict()
        .unwrap()
        .get_ref(b"Pages")
        .unwrap();
    let store = doc.store_mut();
    let (rgb, _) = jpeg::image_xobject(fixture("rgb-ids.jpg")).unwrap();
    let (gray, _) = jpeg::image_xobject(fixture("gray-baseline.jpg")).unwrap();
    let im1 = store.add(rgb.into()).unwrap();
    let im2 = store.add(gray.into()).unwrap();
    let contents = store
        .add(Stream::new(Dict::new(), StreamData::Decoded(content)).into())
        .unwrap();
    // Indirect font dictionaries, as appearance streams carry them (brief §4.7).
    let f1 = store
        .add(Standard14Font::Helvetica.font_dict().into())
        .unwrap();
    let f2 = store
        .add(Standard14Font::HelveticaBold.font_dict().into())
        .unwrap();
    let mut fonts = Dict::new();
    fonts.insert("F1", f1);
    fonts.insert("F2", f2);
    let mut xobjects = Dict::new();
    xobjects.insert("Im1", im1);
    xobjects.insert("Im2", im2);
    let mut resources = Dict::new();
    resources.insert("Font", fonts);
    resources.insert("XObject", xobjects);
    let mut page = Dict::new();
    page.insert("Type", Object::name("Page"));
    page.insert("Parent", pages_id);
    page.insert(
        "MediaBox",
        vec![0.into(), 0.into(), PAGE_W.into(), PAGE_H.into()],
    );
    page.insert("Resources", resources);
    page.insert("Contents", contents);
    let page_id = store.add(page.into()).unwrap();
    let pages = store.get_mut(pages_id).unwrap().as_dict_mut().unwrap();
    pages.insert("Kids", vec![Object::Ref(page_id)]);
    pages.insert("Count", 1);
    doc.save(&SaveOptions::default().with_deterministic(true))
        .unwrap()
}

fn resolve_dict(doc: &Document, obj: &Object) -> Dict {
    doc.store()
        .deref(obj)
        .unwrap()
        .into_owned()
        .as_dict()
        .unwrap()
        .clone()
}

fn stream_of(doc: &Document, id: ObjectId) -> Stream {
    doc.store()
        .resolve(id)
        .unwrap()
        .as_stream()
        .unwrap()
        .clone()
}

/// Folioxide reads back what was built.
#[test]
fn content_round_trips_through_document_save() {
    let lines = lines();
    let content = content(&lines);
    let pdf = sample(content.clone());
    let doc = Document::open(pdf, &OpenOptions::default()).unwrap();
    assert!(doc.diagnostics().is_empty(), "{:?}", doc.diagnostics());
    assert_eq!(doc.page_count().unwrap(), 1);
    let page = doc.page(0).unwrap();
    let page_dict = page.object().unwrap().as_dict().unwrap().clone();
    let contents = stream_of(&doc, page_dict.get_ref(b"Contents").unwrap());
    // The writer Flate-encodes the decoded stream (M2 rule); it decodes to the built bytes.
    assert_eq!(contents.dict.get_name(b"Filter").unwrap(), "FlateDecode");
    let decoded = doc.store().stream_data(&contents).unwrap();
    assert!(decoded.is_fully_decoded() && !decoded.truncated);
    assert_eq!(decoded.data, content);

    let resources = page.resources().unwrap().unwrap();
    let fonts = resolve_dict(&doc, resources.get(b"Font").unwrap());
    assert_eq!(
        resolve_dict(&doc, fonts.get(b"F1").unwrap()),
        Standard14Font::Helvetica.font_dict()
    );
    assert_eq!(
        resolve_dict(&doc, fonts.get(b"F2").unwrap()),
        Standard14Font::HelveticaBold.font_dict()
    );
    let xobjects = resolve_dict(&doc, resources.get(b"XObject").unwrap());
    for (name, file) in [(&b"Im1"[..], "rgb-ids.jpg"), (b"Im2", "gray-baseline.jpg")] {
        let image = stream_of(&doc, xobjects.get_ref(name).unwrap());
        let (expected, _) = jpeg::image_xobject(fixture(file)).unwrap();
        assert_eq!(image.dict, expected.dict, "{file}");
        // Passthrough: the file bytes, still DCT-encoded.
        assert_eq!(
            &*doc.store().raw_stream_data(&image).unwrap(),
            &fixture(file)[..],
            "{file}"
        );
    }
}

// ---- poppler ---------------------------------------------------------------------------------

/// Runs a poppler tool on `pdf` and returns its standard output (`pdftotext` is told to
/// write there with `-`; `pdffonts` and `pdftoppm` without an output root do anyway); `None`
/// when the tool is not installed.
fn run(tool: &str, args: &[&str], pdf: &Path) -> Option<Vec<u8>> {
    let mut command = Command::new(tool);
    command.args(args).arg(pdf);
    if tool == "pdftotext" {
        command.arg("-");
    }
    let output = match command.output() {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("render_poppler: {tool} is not installed; poppler checks skipped");
            return None;
        }
        Err(e) => panic!("{tool}: {e}"),
    };
    assert!(
        output.status.success(),
        "{tool} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{tool} {args:?} warned: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output.stdout)
}

/// A sample file, removed when dropped.
struct Sample(PathBuf);

impl std::ops::Deref for Sample {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Sample {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Writes the sample to a file named after `name` and this process, so that test runs sharing a
/// target directory never race on one file (M4 QA round 5, finding 1: poppler read a file another
/// run was rewriting, "Document stream is empty").
fn write_sample(name: &str) -> (Sample, Vec<Line>) {
    let lines = lines();
    let pdf = sample(content(&lines));
    let unique = format!("{}-{name}", std::process::id());
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(unique);
    std::fs::write(&path, pdf).unwrap();
    (Sample(path), lines)
}

/// What poppler extracts for a WinAnsi line: the decoded characters, except that the glyph
/// `hyphen` at 0xAD reads back as U+002D (poppler maps glyph names, Annex D.2 note 5).
fn expected_text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            0xAD => '-',
            _ => win_ansi_decode(b).unwrap(),
        })
        .collect()
}

#[test]
fn pdffonts_lists_unembedded_winansi_type1() {
    let (path, _) = write_sample("pdffonts.pdf");
    let Some(out) = run("pdffonts", &[], &path).map(|o| String::from_utf8(o).unwrap()) else {
        return;
    };
    // name type encoding emb sub uni object ID
    let rows: Vec<Vec<&str>> = out
        .lines()
        .skip(2)
        .map(|l| l.split_whitespace().collect())
        .collect();
    assert_eq!(rows.len(), 2, "{out}");
    for (row, name) in rows.iter().zip(["Helvetica", "Helvetica-Bold"]) {
        // Not embedded, not subset, no ToUnicode map: the standard-14 font by name.
        assert_eq!(
            &row[..7],
            [name, "Type", "1", "WinAnsi", "no", "no", "no"],
            "{out}"
        );
    }
}

#[test]
fn pdftotext_reads_every_line() {
    let (path, lines) = write_sample("pdftotext.pdf");
    let Some(out) = run("pdftotext", &["-raw", "-enc", "UTF-8"], &path) else {
        return;
    };
    let text = String::from_utf8(out).unwrap();
    let got: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let expected: Vec<String> = lines.iter().map(|l| expected_text(&l.bytes)).collect();
    assert_eq!(got, expected, "\n{text}");
}

/// Parses poppler's `-bbox` XHTML: (word, xMin, yMin, xMax, yMax).
fn bbox_words(xhtml: &str) -> Vec<(String, [f64; 4])> {
    let mut words = Vec::new();
    for chunk in xhtml.split("<word ").skip(1) {
        let attr = |name: &str| -> f64 {
            let start = chunk.find(&format!("{name}=\"")).unwrap() + name.len() + 2;
            let end = start + chunk[start..].find('"').unwrap();
            chunk[start..end].parse().unwrap()
        };
        let word_start = chunk.find('>').unwrap() + 1;
        let word_end = chunk.find("</word>").unwrap();
        let word = chunk[word_start..word_end]
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'");
        words.push((
            word,
            [attr("xMin"), attr("yMin"), attr("xMax"), attr("yMax")],
        ));
    }
    words
}

/// poppler places every word of the first two lines where the AFM widths put it.
#[test]
fn pdftotext_bbox_matches_afm_widths() {
    let (path, lines) = write_sample("pdftotext-bbox.pdf");
    let Some(out) = run("pdftotext", &["-bbox", "-enc", "UTF-8"], &path) else {
        return;
    };
    let words = bbox_words(&String::from_utf8(out).unwrap());
    let mut checked = 0;
    for line in &lines[..2] {
        // Each word's start and end, from our widths.
        let mut x = line.x;
        for word in line.bytes.split(|&b| b == b' ') {
            let start = x;
            let end = start + line.font.text_width(word, line.size);
            x = end + line.font.text_width(b" ", line.size);
            let text = expected_text(word);
            let (_, [x_min, _, x_max, y_max]) = words
                .iter()
                .find(|(w, b)| *w == text && (b[0] - start).abs() < 1.0)
                .unwrap_or_else(|| panic!("{text} at {start}: {words:?}"));
            assert!(
                (x_min - start).abs() < 0.01,
                "{text}: xMin {x_min}, ours {start}"
            );
            assert!(
                (x_max - end).abs() < 0.01,
                "{text}: xMax {x_max}, ours {end}"
            );
            // The baseline is at y (page space, so PAGE_H - y from the top) and the box
            // reaches up to the ascent.
            assert!(*y_max > PAGE_H - line.y, "{text}: yMax {y_max}");
            checked += 1;
        }
    }
    assert_eq!(checked, 3 + 6);
}

/// A binary PPM (P6), as `pdftoppm` writes it.
struct Raster {
    width: usize,
    height: usize,
    rgb: Vec<u8>,
}

impl Raster {
    fn parse(data: &[u8]) -> Raster {
        let mut fields = Vec::new();
        let mut pos = 0;
        while fields.len() < 4 {
            while data[pos].is_ascii_whitespace() {
                pos += 1;
            }
            let start = pos;
            while !data[pos].is_ascii_whitespace() {
                pos += 1;
            }
            fields.push(std::str::from_utf8(&data[start..pos]).unwrap().to_owned());
        }
        assert_eq!(fields[0], "P6");
        assert_eq!(fields[3], "255");
        let (width, height) = (fields[1].parse().unwrap(), fields[2].parse().unwrap());
        let rgb = data[pos + 1..].to_vec();
        assert_eq!(rgb.len(), width * height * 3);
        Raster { width, height, rgb }
    }

    /// The pixel at page-space point (x, y), at 72 dpi.
    fn at(&self, x: f64, y: f64) -> [u8; 3] {
        let col = x.floor() as usize;
        let row = (PAGE_H - y).floor() as usize;
        let i = (row * self.width + col) * 3;
        [self.rgb[i], self.rgb[i + 1], self.rgb[i + 2]]
    }

    /// How many pixels of the page-space rectangle are dark (every channel < 128).
    fn dark_in(&self, x: f64, y: f64, w: f64, h: f64) -> usize {
        let mut dark = 0;
        let (x0, x1) = (x.floor() as usize, (x + w).ceil() as usize);
        let (r0, r1) = (
            (PAGE_H - y - h).floor() as usize,
            (PAGE_H - y).ceil() as usize,
        );
        for row in r0..r1.min(self.height) {
            for col in x0..x1.min(self.width) {
                let i = (row * self.width + col) * 3;
                if self.rgb[i..i + 3].iter().all(|&c| c < 128) {
                    dark += 1;
                }
            }
        }
        dark
    }
}

fn near(pixel: [u8; 3], expected: [u8; 3]) -> bool {
    pixel
        .iter()
        .zip(expected)
        .all(|(&p, e)| (i16::from(p) - i16::from(e)).abs() <= 48)
}

#[test]
fn pdftoppm_draws_text_and_images() {
    let (path, lines) = write_sample("pdftoppm.pdf");
    let Some(out) = run("pdftoppm", &["-r", "72"], &path) else {
        return;
    };
    let raster = Raster::parse(&out);
    assert_eq!((raster.width, raster.height), (300, 200));

    // The RGB image, upright: black and red on top, white and blue below.
    let [x, y, w, h] = IMAGE_RGB;
    let quadrant = |fx: f64, fy: f64| raster.at(x + fx * w, y + fy * h);
    let checks = [
        (quadrant(0.25, 0.75), [0, 0, 0], "top left: black"),
        (quadrant(0.75, 0.75), [255, 0, 0], "top right: red"),
        (quadrant(0.25, 0.25), [255, 255, 255], "bottom left: white"),
        (quadrant(0.75, 0.25), [0, 0, 255], "bottom right: blue"),
    ];
    for (pixel, expected, what) in checks {
        assert!(near(pixel, expected), "{what}: {pixel:?}");
    }
    // Nothing is drawn right of the image or above it.
    assert_eq!(raster.at(x + w + 2.0, y + h / 2.0), [255, 255, 255]);
    assert_eq!(raster.at(x + w / 2.0, y + h + 2.0), [255, 255, 255]);

    // The gray image's frame, and the text of every line, are dark.
    let [x, y, w, _] = IMAGE_GRAY;
    assert!(raster.dark_in(x - 3.0, y - 3.0, w + 6.0, 2.0) > 40);
    for line in &lines {
        let width = line.font.text_width(&line.bytes, line.size);
        let dark = raster.dark_in(line.x, line.y, width, line.size * 0.718);
        assert!(
            dark > (width * line.size / 20.0) as usize,
            "line at {}: {dark}",
            line.y
        );
        // Nothing right of where our widths end the line.
        assert_eq!(
            raster.dark_in(line.x + width + 2.0, line.y, 20.0, line.size * 0.7),
            0
        );
    }
}

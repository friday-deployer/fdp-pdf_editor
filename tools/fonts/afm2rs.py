#!/usr/bin/env python3
"""Generate the standard-14 font metric tables of `folioxide-content` from Adobe's Core 14 AFM files.

Output: `crates/folioxide-content/src/standard14/afm_tables.rs` (committed; nothing is fetched at
build time). M4 brief §4.7, decision D-16.

Inputs: `Helvetica.afm`, `Helvetica-Bold.afm` and the accompanying `MustRead.html` (the Adobe
Core 14 AFM notice) as shipped with Apache PDFBox 3.0.3, in
`pdfbox/src/main/resources/org/apache/pdfbox/resources/afm/`. Each input's SHA-256 is pinned
below and recorded in the generated file's header; the AFM files themselves are not committed.

The widths are mapped **by glyph name** through WinAnsiEncoding (ISO 32000-2 Annex D.2), never by
the AFM `C` code, which is StandardEncoding: `quotesingle` is `C 169` in the AFM but WinAnsi
0x27, and `Euro` is `C -1` but WinAnsi 0x80. Codes WinAnsiEncoding leaves unused above 0x20
(0x7F, 0x81, 0x8D, 0x8F, 0x90, 0x9D) carry the width of `bullet`: Annex D.2, note 6, says
"In WinAnsiEncoding, all unused codes greater than 40 [octal] map to the bullet character",
and poppler and pdf.js draw a bullet there.

Usage (from the repository root):

    python3 -I tools/fonts/afm2rs.py                   # download the pinned inputs, write the file
    python3 -I tools/fonts/afm2rs.py --afm-dir DIR     # read the inputs from DIR instead
    python3 -I tools/fonts/afm2rs.py --check [...]     # compare with the committed file; exit 1 on a difference

Exit codes: 0 success, 1 the committed file differs (`--check`), 2 an input is missing, cannot be
downloaded, or does not match its pinned SHA-256.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import re
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT = REPO_ROOT / "crates" / "folioxide-content" / "src" / "standard14" / "afm_tables.rs"

PDFBOX_TAG = "3.0.3"
AFM_DIR_IN_PDFBOX = "pdfbox/src/main/resources/org/apache/pdfbox/resources/afm"
BASE_URL = f"https://raw.githubusercontent.com/apache/pdfbox/{PDFBOX_TAG}/{AFM_DIR_IN_PDFBOX}/"

# SHA-256 of each input as served by GitHub for the tag (checked 2026-10-11).
INPUTS = {
    "Helvetica.afm": "5654761eab868ccb3080122accf13b4fb79edf37af09e1c57a881c35c334ee03",
    "Helvetica-Bold.afm": "59ac93091bc7e76eb6baf60210526a4df88fe107dd5e13eb0ae70c9fc6d91fb9",
    "MustRead.html": "b226bfc00e1b8b8a80c7b3cfbbc322d13b4b0401f94cdeafdd93b2210ad802eb",
}

# (Rust constant, AFM file, expected FontName)
FONTS = [
    ("HELVETICA", "Helvetica.afm", "Helvetica"),
    ("HELVETICA_BOLD", "Helvetica-Bold.afm", "Helvetica-Bold"),
]

# The Adobe Core 14 AFM notice, verbatim. The generator checks it against MustRead.html.
ADOBE_AFM_NOTICE = (
    "This file and the 14 PostScript(R) AFM files it accompanies may be used, copied, and "
    "distributed for any purpose and without charge, with or without modification, provided "
    "that all copyright notices are retained; that the AFM files are not distributed without "
    "this file; that all modifications to this file or any of the AFM files are prominently "
    "noted in the modified file(s); and that this paragraph is not modified. Adobe Systems has "
    "no responsibility or obligation to support the use of the AFM files."
)

# WinAnsiEncoding (ISO 32000-2 Annex D.2): code -> glyph name. Unlisted codes are unused.
_ASCII_NAMES = (
    "space exclam quotedbl numbersign dollar percent ampersand quotesingle parenleft parenright "
    "asterisk plus comma hyphen period slash zero one two three four five six seven eight nine "
    "colon semicolon less equal greater question at A B C D E F G H I J K L M N O P Q R S T U V "
    "W X Y Z bracketleft backslash bracketright asciicircum underscore grave a b c d e f g h i j "
    "k l m n o p q r s t u v w x y z braceleft bar braceright asciitilde"
).split()
_HIGH_NAMES = {
    0x80: "Euro", 0x82: "quotesinglbase", 0x83: "florin", 0x84: "quotedblbase",
    0x85: "ellipsis", 0x86: "dagger", 0x87: "daggerdbl", 0x88: "circumflex",
    0x89: "perthousand", 0x8A: "Scaron", 0x8B: "guilsinglleft", 0x8C: "OE", 0x8E: "Zcaron",
    0x91: "quoteleft", 0x92: "quoteright", 0x93: "quotedblleft", 0x94: "quotedblright",
    0x95: "bullet", 0x96: "endash", 0x97: "emdash", 0x98: "tilde", 0x99: "trademark",
    0x9A: "scaron", 0x9B: "guilsinglright", 0x9C: "oe", 0x9E: "zcaron", 0x9F: "Ydieresis",
}
_LATIN1_NAMES = (
    # 0xA0: Annex D.2 note 4, the space character is also encoded as 240 (octal).
    # 0xAD: Annex D.2 note 5, the hyphen character is also encoded as 255 (octal).
    "space exclamdown cent sterling currency yen brokenbar section dieresis copyright "
    "ordfeminine guillemotleft logicalnot hyphen registered macron degree plusminus twosuperior "
    "threesuperior acute mu paragraph periodcentered cedilla onesuperior ordmasculine "
    "guillemotright onequarter onehalf threequarters questiondown Agrave Aacute Acircumflex "
    "Atilde Adieresis Aring AE Ccedilla Egrave Eacute Ecircumflex Edieresis Igrave Iacute "
    "Icircumflex Idieresis Eth Ntilde Ograve Oacute Ocircumflex Otilde Odieresis multiply "
    "Oslash Ugrave Uacute Ucircumflex Udieresis Yacute Thorn germandbls agrave aacute "
    "acircumflex atilde adieresis aring ae ccedilla egrave eacute ecircumflex edieresis igrave "
    "iacute icircumflex idieresis eth ntilde ograve oacute ocircumflex otilde odieresis divide "
    "oslash ugrave uacute ucircumflex udieresis yacute thorn ydieresis"
).split()


def win_ansi_names() -> dict[int, str]:
    names: dict[int, str] = {}
    assert len(_ASCII_NAMES) == 0x7F - 0x20, len(_ASCII_NAMES)
    for i, name in enumerate(_ASCII_NAMES):
        names[0x20 + i] = name
    names.update(_HIGH_NAMES)
    assert len(_LATIN1_NAMES) == 0x100 - 0xA0, len(_LATIN1_NAMES)
    for i, name in enumerate(_LATIN1_NAMES):
        names[0xA0 + i] = name
    # Independent check of the transcription: every named code is a Windows-1252 code, and the
    # five codes cp1252 leaves undefined are exactly the unused ones above 0x7F.
    for code in range(0x20, 0x100):
        try:
            bytes([code]).decode("cp1252")
            defined = True
        except UnicodeDecodeError:
            defined = False
        if code == 0x7F:
            assert code not in names
        else:
            assert defined == (code in names), hex(code)
    return names


UNUSED_GLYPH = "bullet"  # Annex D.2 note 6


def width_glyph_names() -> list[str]:
    """The glyph whose width each `/Widths` entry (codes 32..=255) carries."""
    names = win_ansi_names()
    return [names.get(code, UNUSED_GLYPH) for code in range(32, 256)]


# ---- AFM parsing ---------------------------------------------------------------------------


class Afm:
    def __init__(self, text: str) -> None:
        self.header: dict[str, str] = {}
        self.glyphs: list[tuple[str, int, int]] = []  # (name, StandardEncoding code, WX)
        in_metrics = False
        expected = None
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("StartCharMetrics"):
                in_metrics = True
                expected = int(line.split()[1])
                continue
            if line.startswith("EndCharMetrics"):
                in_metrics = False
                continue
            if in_metrics:
                self.glyphs.append(parse_char_metric(line))
                continue
            if line.startswith(("StartKernData", "StartComposites")):
                break
            key, _, value = line.partition(" ")
            if key != "Comment":
                self.header[key] = value.strip()
        if expected is None or expected != len(self.glyphs):
            raise ValueError(f"StartCharMetrics {expected}, found {len(self.glyphs)} glyphs")
        names = [g[0] for g in self.glyphs]
        if len(set(names)) != len(names):
            raise ValueError("duplicate glyph names")
        self.widths = {name: wx for name, _, wx in self.glyphs}

    def int(self, key: str) -> int:
        return int(self.header[key])

    def bbox(self) -> list[int]:
        values = [int(v) for v in self.header["FontBBox"].split()]
        if len(values) != 4:
            raise ValueError("FontBBox")
        return values


def parse_char_metric(line: str) -> tuple[str, int, int]:
    fields = {}
    for part in line.split(";"):
        part = part.strip()
        if not part:
            continue
        key, _, value = part.partition(" ")
        fields.setdefault(key, value.strip())
    return fields["N"], int(fields["C"]), int(fields["WX"])


def notice_from_must_read(html_text: str) -> str:
    """The notice paragraph of MustRead.html, tags and the trailing white filler text removed."""
    match = re.search(r"(This file and the 14 PostScript.*?use of the AFM files\.)", html_text, re.S)
    if not match:
        raise ValueError("MustRead.html does not contain the AFM notice")
    return " ".join(html.unescape(match.group(1)).split())


# ---- inputs ----------------------------------------------------------------------------------


def load_inputs(afm_dir: Path | None) -> dict[str, bytes]:
    data: dict[str, bytes] = {}
    for name, sha in INPUTS.items():
        if afm_dir is not None:
            path = afm_dir / name
            if not path.is_file():
                fail(f"missing input {path}")
            content = path.read_bytes()
        else:
            url = BASE_URL + name
            try:
                with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 (fixed https URL)
                    content = response.read()
            except OSError as exc:
                fail(f"cannot download {url}: {exc}")
        actual = hashlib.sha256(content).hexdigest()
        if actual != sha:
            fail(f"{name}: SHA-256 {actual}, expected {sha} (PDFBox {PDFBOX_TAG})")
        data[name] = content
    return data


def fail(message: str) -> None:
    print(f"afm2rs: {message}", file=sys.stderr)
    sys.exit(2)


# ---- generation ------------------------------------------------------------------------------

# The values M4 brief §4.7 verified by hand in Helvetica.afm.
VERIFIED_HELVETICA = {
    "space": 278, "A": 667, "W": 944, "quotesingle": 191, "bullet": 350, "ellipsis": 1000,
    "Euro": 556,
}


def rust_str(value: str) -> str:
    out = ['"']
    for ch in value:
        if ch in '"\\':
            out.append("\\" + ch)
        elif 0x20 <= ord(ch) < 0x7F:
            out.append(ch)
        else:
            raise ValueError(f"non-ASCII character in {value!r}")
    out.append('"')
    return "".join(out)


def wrap_list(items: list[str], indent: str, width: int = 100) -> list[str]:
    lines: list[str] = []
    current = indent
    for item in items:
        piece = item + ","
        candidate = piece if current == indent else " " + piece
        if len(current) + len(candidate) > width and current != indent:
            lines.append(current)
            current = indent + piece
        else:
            current += candidate
    if current != indent:
        lines.append(current)
    return lines


def generate(inputs: dict[str, bytes]) -> str:
    notice = notice_from_must_read(inputs["MustRead.html"].decode("iso-8859-1"))
    if notice != ADOBE_AFM_NOTICE:
        fail("the notice in MustRead.html differs from ADOBE_AFM_NOTICE:\n" + notice)
    glyph_for_width = width_glyph_names()

    fonts = []
    for const, file_name, font_name in FONTS:
        afm = Afm(inputs[file_name].decode("ascii"))
        if afm.header.get("FontName") != font_name:
            raise ValueError(f"{file_name}: FontName {afm.header.get('FontName')}")
        missing = sorted({n for n in glyph_for_width if n not in afm.widths})
        if missing:
            raise ValueError(f"{file_name}: no metrics for {missing}")
        fonts.append((const, file_name, afm))

    helvetica = fonts[0][2]
    for name, width in VERIFIED_HELVETICA.items():
        assert helvetica.widths[name] == width, (name, helvetica.widths[name])
    assert helvetica.bbox() == [-166, -225, 1000, 931]
    assert (helvetica.int("Ascender"), helvetica.int("Descender"), helvetica.int("CapHeight")) == (
        718, -207, 718)

    out: list[str] = []
    w = out.append
    w("// @generated by tools/fonts/afm2rs.py; do not edit by hand. Regenerate with")
    w("// `python3 -I tools/fonts/afm2rs.py` and check with `--check`.")
    w("//")
    w("// Font metrics derived (widths extracted) from the Adobe AFM files for the PDF Core 14 fonts,")
    w(f"// as shipped with Apache PDFBox {PDFBOX_TAG} ({AFM_DIR_IN_PDFBOX}/):")
    for name, sha in INPUTS.items():
        w(f"//   {name:<20} SHA-256 {sha}")
    w("//")
    w("// Modification notice (required by the Adobe notice below): this file is not an AFM file.")
    w("// It holds values extracted from the AFM files listed above: FontName, FontBBox, Ascender,")
    w("// Descender, CapHeight, XHeight, StdVW, the Notice line, and the name and WX of every")
    w("// CharMetrics entry; the per-code WinAnsiEncoding widths are computed from those by glyph")
    w("// name. Kerning, ligature and glyph bounding-box data are omitted. The AFM files themselves")
    w("// are not distributed with Folioxide.")
    w("//")
    w("// Copyright notices of the AFM files (retained as the notice requires):")
    for _, file_name, afm in fonts:
        w(f"//   {file_name}: {afm.header['Notice']}")
    w("//")
    w("// The Adobe Core 14 AFM notice (MustRead.html), verbatim:")
    w("//")
    w(f"// {ADOBE_AFM_NOTICE}")
    w("")
    w("use super::AfmMetrics;")
    w("")
    w("/// The Adobe Core 14 AFM notice, verbatim, as it accompanies the AFM files the standard-14")
    w("/// metrics are derived from (the `MustRead.html` shipped with them; PDFBox 3.0.3).")
    w("///")
    w("/// Its terms require that it travels with the metrics: it is also in the repository's root")
    w("/// `NOTICE` file and in `crates/folioxide-content/NOTICE`, which is packaged with the crate.")
    w(f"pub const ADOBE_AFM_NOTICE: &str = {rust_str(ADOBE_AFM_NOTICE)};")
    w("")
    w("/// The glyph whose width each `/Widths` entry carries, for codes 32..=255 (WinAnsiEncoding,")
    w(f"/// ISO 32000-2 Annex D.2; unused codes carry `{UNUSED_GLYPH}`, Annex D.2 note 6). The unit")
    w("/// tests compare it with the crate's own WinAnsiEncoding table.")
    w("#[cfg(test)]")
    w("pub(super) const WIDTH_GLYPHS: [&str; 224] = [")
    out.extend(wrap_list([rust_str(n) for n in glyph_for_width], "    "))
    w("];")
    for const, file_name, afm in fonts:
        widths = [str(afm.widths[n]) for n in glyph_for_width]
        bbox = ", ".join(str(v) for v in afm.bbox())
        w("")
        w(f"/// Metrics of `{afm.header['FontName']}`, from `{file_name}`.")
        w(f"pub(super) static {const}: AfmMetrics = AfmMetrics {{")
        w(f"    font_name: {rust_str(afm.header['FontName'])},")
        w(f"    notice: {rust_str(afm.header['Notice'])},")
        w(f"    font_bbox: [{bbox}],")
        w(f"    ascender: {afm.int('Ascender')},")
        w(f"    descender: {afm.int('Descender')},")
        w(f"    cap_height: {afm.int('CapHeight')},")
        w(f"    x_height: {afm.int('XHeight')},")
        w(f"    std_vw: {afm.int('StdVW')},")
        w("    win_ansi_widths: [")
        out.extend(wrap_list(widths, "        "))
        w("    ],")
        w("    glyphs: &[")
        out.extend(wrap_list(
            [f"({rust_str(name)}, {code}, {wx})" for name, code, wx in afm.glyphs], "        "))
        w("    ],")
        w("};")
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--afm-dir", type=Path, help="read the inputs from this directory")
    parser.add_argument("--check", action="store_true",
                        help="compare with the committed file instead of writing it")
    args = parser.parse_args()
    text = generate(load_inputs(args.afm_dir))
    if args.check:
        committed = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if committed != text:
            print(f"afm2rs: {OUTPUT.relative_to(REPO_ROOT)} is out of date", file=sys.stderr)
            return 1
        print(f"afm2rs: {OUTPUT.relative_to(REPO_ROOT)} matches the PDFBox {PDFBOX_TAG} AFM files")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(text, encoding="utf-8")
    print(f"afm2rs: wrote {OUTPUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Hand-written PDF bytes for the oracle self-tests.

The self-tests must not depend on Folioxide's own Rust code, so this module writes tiny but
valid PDFs byte by byte: a classic xref table, one Helvetica text line per page and an Info
dictionary (ISO 32000-2 §7.5). Offsets are computed, never guessed.
"""

from __future__ import annotations

import hashlib
import re


def _pdf_string(text: str) -> bytes:
    """Literal string with the three characters that need escaping escaped (§7.3.4.2)."""
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return b"(" + escaped.encode("latin-1") + b")"


def build_pdf(
    *,
    version: str = "1.7",
    page_texts: tuple[str, ...] = ("Hello Folioxide",),
    info: dict[str, str] | None = None,
    catalog_version: str | None = None,
) -> bytes:
    """Return the bytes of a minimal PDF with one text line per page.

    ``info`` maps Info dictionary keys (without the slash) to text values. ``catalog_version``
    adds ``/Version`` to the catalog, which overrides an older header version (§7.7.2).
    """
    if info is None:
        info = {
            "Title": "Folioxide oracle self-test",
            "Author": "Folioxide contributors",
            "Producer": "pdfgen.py (hand-written bytes)",
            "CreationDate": "D:20261010120000Z",
        }
    page_count = len(page_texts)
    # Object numbers: 1 catalog, 2 page tree, 3 font, 4 info, then (page, content) pairs.
    first_page = 5
    page_ids = [first_page + 2 * i for i in range(page_count)]

    objects: dict[int, bytes] = {}
    catalog = b"<< /Type /Catalog /Pages 2 0 R"
    if catalog_version is not None:
        catalog += b" /Version /" + catalog_version.encode("ascii")
    objects[1] = catalog + b" >>"
    kids = b" ".join(b"%d 0 R" % pid for pid in page_ids)
    objects[2] = b"<< /Type /Pages /Kids [" + kids + b"] /Count %d >>" % page_count
    objects[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
    objects[4] = (
        b"<< "
        + b" ".join(b"/" + k.encode("ascii") + b" " + _pdf_string(v) for k, v in info.items())
        + b" >>"
    )
    for pid, text in zip(page_ids, page_texts, strict=True):
        content = b"BT /F1 24 Tf 72 720 Td " + _pdf_string(text) + b" Tj ET\n"
        objects[pid] = (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]"
            b" /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>" % (pid + 1)
        )
        objects[pid + 1] = b"<< /Length %d >>\nstream\n" % len(content) + content + b"endstream"

    out = bytearray(b"%PDF-" + version.encode("ascii") + b"\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + objects[num] + b"\nendobj\n"

    size = max(objects) + 1
    xref_offset = len(out)
    out += b"xref\n0 %d\n" % size
    out += b"0000000000 65535 f \n"
    for num in range(1, size):
        out += b"%010d 00000 n \n" % offsets[num]
    file_id = hashlib.md5(bytes(out)).hexdigest().upper().encode("ascii")
    out += (
        b"trailer\n<< /Size %d /Root 1 0 R /Info 4 0 R /ID [<" % size
        + file_id
        + b"> <"
        + file_id
        + b">] >>\nstartxref\n%d\n%%%%EOF\n" % xref_offset
    )
    return bytes(out)


def shift_body(pdf: bytes, junk: bytes = b"% junk inserted after the header\n") -> bytes:
    """Insert bytes after the header so every xref offset points at the wrong place."""
    header_end = pdf.index(b"\n", pdf.index(b"\n") + 1) + 1
    return pdf[:header_end] + junk + pdf[header_end:]


def truncate(pdf: bytes, keep: float = 0.6) -> bytes:
    """Drop the tail of the file, including the xref table and trailer."""
    return pdf[: int(len(pdf) * keep)]


def flip_byte(data: bytes, offset: int) -> bytes:
    """Return ``data`` with the byte at ``offset`` XOR-ed with 0x01."""
    mutable = bytearray(data)
    mutable[offset] ^= 0x01
    return bytes(mutable)


def append_update(pdf: bytes, objects: dict[int, bytes]) -> bytes:
    """Append an incremental update (§7.5.6) that (re)defines ``objects`` (number -> dict bytes).

    The new section is a classic xref table whose trailer carries ``/Root`` and ``/Size`` over
    from the last trailer and points ``/Prev`` at the previous xref. Like pyHanko, it starts with
    the object 0 free-list head (§7.5.4), which pypdf's strict mode expects. That covers what
    pdfgen and pyHanko write; it is not meant for files whose last section is an xref stream.
    """
    trailer = pdf[pdf.rindex(b"trailer") :]
    root = re.search(rb"/Root\s+(\d+\s+\d+\s+R)", trailer)
    size = re.search(rb"/Size\s+(\d+)", trailer)
    startxrefs = re.findall(rb"startxref\s+(\d+)", pdf)
    if root is None or size is None or not startxrefs:
        raise ValueError("append_update needs a classic trailer with /Root and /Size, and a startxref")
    out = bytearray(pdf if pdf.endswith(b"\n") else pdf + b"\n")
    offsets: dict[int, int] = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + objects[num] + b"\nendobj\n"
    xref_offset = len(out)
    out += b"xref\n0 1\n0000000000 65535 f \n"
    for num in sorted(objects):
        out += b"%d 1\n%010d 00000 n \n" % (num, offsets[num])
    new_size = max(int(size.group(1)), max(objects) + 1)
    out += (
        b"trailer\n<< /Size %d /Root " % new_size
        + root.group(1)
        + b" /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (int(startxrefs[-1]), xref_offset)
    )
    return bytes(out)

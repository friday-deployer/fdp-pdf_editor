#!/usr/bin/env python3
"""Structural oracle checks for one PDF (docs/ARCHITECTURE.md §A.9, "Structural validity").

Three independent parsers must accept the file:

* ``structure.pdfinfo``: poppler's ``pdfinfo`` exits 0 and prints no ``Syntax Error``
* ``structure.pikepdf``: pikepdf (qpdf) opens it and ``Pdf.check_pdf_syntax()`` reports no
  problems, including warnings such as "file is damaged" or "reconstructing xref"
* ``structure.pypdf``: ``pypdf.PdfReader(strict=True)`` reads every page, decodes its content
  streams and logs no warnings

Value checks compare an expectation against every parser that exposes the value:

* ``pages``: page count from pdfinfo, pikepdf and pypdf
* ``version``: the effective PDF version, ``max(header, catalog /Version)`` (ISO 32000-2 §7.7.2),
  from pdfinfo, pikepdf and pypdf
* ``info``: Info dictionary entries from pdfinfo (standard keys only), pikepdf and pypdf.
  Values are text; dates are compared raw (``D:20261010120000Z``); ``null`` means "absent".
* ``objectCount``: the number of in-use objects, from pikepdf (see :func:`check_object_count`
  for exactly what is compared)
* ``boxes``: every page's media box, crop box, rotation and displayed size, from
  ``pdfinfo -box -f 1 -l N`` (see :func:`check_boxes`, which also lists poppler's quirks)

CLI::

    check_pdf.py FILE [--pages N] [--version 1.7] [--info Title=Text]... [--object-count N]
                 [--boxes JSON] [--json]
"""

from __future__ import annotations

import argparse
import functools
import json
import math
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if str(Path(__file__).resolve().parent) not in sys.path:
    # `python -I` does not put the script directory on sys.path.
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from oracle_common import (  # noqa: E402
    CheckResult,
    ExpectError,
    OracleEnvError,
    captured_logs,
    cli,
    compare,
    exit_code,
    failed,
    first_line,
    import_module,
    passed,
    print_results,
    run_tool,
    text,
)

#: Info keys that ``pdfinfo`` prints (ISO 32000-2 §14.3.3, Table 349).
STANDARD_INFO_KEYS = (
    "Title",
    "Author",
    "Subject",
    "Keywords",
    "Creator",
    "Producer",
    "CreationDate",
    "ModDate",
)

_VERSION_RE = re.compile(r"^(\d)\.(\d)$")


@dataclass(frozen=True)
class PdfInfo:
    """Parsed output of ``pdfinfo -enc UTF-8 -rawdates``."""

    returncode: int
    fields: dict[str, str]
    stderr: str

    @property
    def errors(self) -> list[str]:
        return [line for line in self.stderr.splitlines() if "error" in line.lower()]


@functools.lru_cache(maxsize=64)
def _pdfinfo_cached(path: str, mtime_ns: int, size: int) -> PdfInfo:
    proc = run_tool(["pdfinfo", "-enc", "UTF-8", "-rawdates", path])
    fields: dict[str, str] = {}
    for line in text(proc.stdout).splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return PdfInfo(proc.returncode, fields, text(proc.stderr))


def pdfinfo(path: Path) -> PdfInfo:
    """Run ``pdfinfo`` once per file version (cached on path, mtime and size)."""
    st = path.stat()
    return _pdfinfo_cached(str(path), st.st_mtime_ns, st.st_size)


def parse_version(value: str) -> tuple[int, int] | None:
    m = _VERSION_RE.match(value.strip().lstrip("/"))
    return (int(m.group(1)), int(m.group(2))) if m else None


def effective_version(header: str, catalog: str | None) -> str:
    """``max(header, catalog /Version)``: an incremental update can only raise the version."""
    best = header.strip()
    if catalog:
        cat = catalog.strip().lstrip("/")
        h, c = parse_version(best), parse_version(cat)
        if c is not None and (h is None or c > h):
            best = cat
    return best


# --------------------------------------------------------------------------------------------
# Structure
# --------------------------------------------------------------------------------------------


def check_structure_pdfinfo(path: Path) -> CheckResult:
    info = pdfinfo(path)
    if info.returncode != 0:
        return failed("structure.pdfinfo", f"pdfinfo exit {info.returncode}: {first_line(info.stderr)}")
    if info.errors:
        return failed("structure.pdfinfo", f"pdfinfo reported: {info.errors[0]}")
    return passed("structure.pdfinfo")


def check_structure_pikepdf(path: Path) -> CheckResult:
    pikepdf = import_module("pikepdf")
    with captured_logs("pikepdf"):
        try:
            with pikepdf.open(path) as pdf:
                problems = list(pdf.check_pdf_syntax())
        except pikepdf.PasswordError:
            return failed("structure.pikepdf", "file is encrypted and needs a password")
        except Exception as exc:  # noqa: BLE001 - any parser failure is a FAIL, not a crash
            return failed("structure.pikepdf", f"{type(exc).__name__}: {exc}")
    if problems:
        shown = "; ".join(p.replace(str(path), "<file>") for p in problems[:3])
        more = f" (+{len(problems) - 3} more)" if len(problems) > 3 else ""
        return failed("structure.pikepdf", f"check_pdf_syntax: {shown}{more}")
    return passed("structure.pikepdf")


def check_structure_pypdf(path: Path) -> CheckResult:
    pypdf = import_module("pypdf")
    with captured_logs("pypdf") as logs:
        try:
            reader = pypdf.PdfReader(path, strict=True)
            if reader.is_encrypted:
                return failed("structure.pypdf", "file is encrypted and needs a password")
            for page in reader.pages:
                _ = page.mediabox
                contents = page.get_contents()
                if contents is not None:
                    contents.get_data()
        except Exception as exc:  # noqa: BLE001
            return failed("structure.pypdf", f"{type(exc).__name__}: {exc}")
    if logs:
        return failed("structure.pypdf", "; ".join(logs[:3]))
    return passed("structure.pypdf", f"{len(reader.pages)} pages read")


def structure_checks(path: Path) -> list[CheckResult]:
    """The baseline checks that every oracle case runs."""
    return [
        check_structure_pdfinfo(path),
        check_structure_pikepdf(path),
        check_structure_pypdf(path),
    ]


# --------------------------------------------------------------------------------------------
# Values
# --------------------------------------------------------------------------------------------


def _guard(name: str, fn: Any) -> CheckResult:
    """Run ``fn() -> CheckResult``; a parser exception becomes a FAIL for that check."""
    try:
        return fn()
    except (ExpectError, OracleEnvError):
        raise
    except Exception as exc:  # noqa: BLE001
        return failed(name, f"{type(exc).__name__}: {exc}")


def check_pages(path: Path, expected: Any) -> list[CheckResult]:
    if isinstance(expected, bool) or not isinstance(expected, int) or expected < 0:
        raise ExpectError(f"'pages' must be a non-negative integer, got {expected!r}")
    pikepdf = import_module("pikepdf")
    pypdf = import_module("pypdf")

    def via_pdfinfo() -> CheckResult:
        raw = pdfinfo(path).fields.get("Pages")
        return compare("pages.pdfinfo", expected, int(raw) if raw and raw.isdigit() else raw)

    def via_pikepdf() -> CheckResult:
        with captured_logs("pikepdf"), pikepdf.open(path) as pdf:
            return compare("pages.pikepdf", expected, len(pdf.pages))

    def via_pypdf() -> CheckResult:
        with captured_logs("pypdf"):
            return compare("pages.pypdf", expected, len(pypdf.PdfReader(path).pages))

    return [
        _guard("pages.pdfinfo", via_pdfinfo),
        _guard("pages.pikepdf", via_pikepdf),
        _guard("pages.pypdf", via_pypdf),
    ]


def check_version(path: Path, expected: Any) -> list[CheckResult]:
    if not isinstance(expected, str) or parse_version(expected) is None:
        raise ExpectError(f"'version' must be a string like \"1.7\", got {expected!r}")
    pikepdf = import_module("pikepdf")
    pypdf = import_module("pypdf")

    def via_pdfinfo() -> CheckResult:
        return compare("version.pdfinfo", expected, pdfinfo(path).fields.get("PDF version"))

    def via_pikepdf() -> CheckResult:
        with captured_logs("pikepdf"), pikepdf.open(path) as pdf:
            catalog = pdf.Root.get("/Version")
            actual = effective_version(str(pdf.pdf_version), str(catalog) if catalog is not None else None)
            return compare("version.pikepdf", expected, actual)

    def via_pypdf() -> CheckResult:
        with captured_logs("pypdf"):
            reader = pypdf.PdfReader(path)
            header = reader.pdf_header.removeprefix("%PDF-")
            catalog = reader.trailer["/Root"].get_object().get("/Version")
            actual = effective_version(header, str(catalog) if catalog is not None else None)
            return compare("version.pypdf", expected, actual)

    return [
        _guard("version.pdfinfo", via_pdfinfo),
        _guard("version.pikepdf", via_pikepdf),
        _guard("version.pypdf", via_pypdf),
    ]


def check_info(path: Path, expected: Any) -> list[CheckResult]:
    if not isinstance(expected, dict) or not expected:
        raise ExpectError("'info' must be a non-empty object of key -> string or null")
    wanted: dict[str, str | None] = {}
    for key, value in expected.items():
        if not isinstance(key, str) or not key.lstrip("/"):
            raise ExpectError(f"'info' key must be a name such as \"Title\", got {key!r}")
        if value is not None and not isinstance(value, str):
            raise ExpectError(f"'info.{key}' must be a string or null, got {value!r}")
        wanted[key.lstrip("/")] = value
    pikepdf = import_module("pikepdf")
    pypdf = import_module("pypdf")

    results: list[CheckResult] = []
    info = pdfinfo(path)
    for key, value in wanted.items():
        if key in STANDARD_INFO_KEYS:
            results.append(compare(f"info.{key}.pdfinfo", value, info.fields.get(key)))

    def via_pikepdf() -> list[CheckResult]:
        with captured_logs("pikepdf"), pikepdf.open(path) as pdf:
            docinfo = pdf.docinfo
            return [
                compare(
                    f"info.{key}.pikepdf",
                    value,
                    str(docinfo[f"/{key}"]) if f"/{key}" in docinfo else None,
                )
                for key, value in wanted.items()
            ]

    def via_pypdf() -> list[CheckResult]:
        with captured_logs("pypdf"):
            metadata = pypdf.PdfReader(path).metadata or {}
            out = []
            for key, value in wanted.items():
                raw = metadata.get(f"/{key}")
                out.append(compare(f"info.{key}.pypdf", value, None if raw is None else str(raw)))
            return out

    for name, fn in (("info.pikepdf", via_pikepdf), ("info.pypdf", via_pypdf)):
        try:
            results.extend(fn())
        except Exception as exc:  # noqa: BLE001
            results.append(failed(name, f"{type(exc).__name__}: {exc}"))
    return results


def pikepdf_object_count(pdf: Any) -> tuple[int, int]:
    """``(len(pdf.objects), number of those that are null)`` for an open ``pikepdf.Pdf``.

    pikepdf turns a null object into Python ``None`` (and other scalars into Python values), so
    a null entry is one that ``is None``.
    """
    objects = list(pdf.objects)
    return len(objects), sum(1 for obj in objects if obj is None)


def check_object_count(path: Path, expected: Any) -> list[CheckResult]:
    """Compare Folioxide's in-use object count with pikepdf's (M1 brief WP1.5).

    **What Folioxide writes** (``objectCount`` in expect.json): the number of in-use objects in
    the merged cross-reference data of every revision (``Store::object_ids()``: the newest entry
    for each object number wins, free entries and object 0 are excluded) that resolve to
    something other than ``null``. Objects inside object streams count one by one, and the
    object stream containers and cross-reference streams count too when the cross-reference
    data lists them, as writers do.

    **What pikepdf gives**: ``len(pdf.objects)``, which is qpdf's ``getAllObjects()``: every
    object qpdf has in its cache after resolving the whole cross-reference table, with objects
    inside object streams, object stream containers and listed cross-reference streams counted
    individually, like ours.

    **Adjustment**: entries that are null are subtracted. qpdf also lists an object number that
    an older revision had in use and a newer one freed; it resolves to null (seen with qpdf
    12.4 for ``fixtures/syntax/multi-revision.pdf``, whose third revision frees the ``/Info``
    object 6). An in-use object whose value is literally ``null`` is excluded on both sides.

    The comparison is only meaningful for files that qpdf reads without repair; the ``syntax``
    suite marks the others ``oracleSkip``.
    """
    if isinstance(expected, bool) or not isinstance(expected, int) or expected < 0:
        raise ExpectError(f"'objectCount' must be a non-negative integer, got {expected!r}")
    pikepdf = import_module("pikepdf")

    def via_pikepdf() -> CheckResult:
        with captured_logs("pikepdf"), pikepdf.open(path) as pdf:
            total, nulls = pikepdf_object_count(pdf)
        actual = total - nulls
        detail = f"len(pdf.objects) {total} - {nulls} null = {actual}"
        if actual != expected:
            detail = f"expected {expected!r}, got {actual!r} ({detail})"
        return CheckResult("objectCount.pikepdf", actual == expected, detail)

    return [_guard("objectCount.pikepdf", via_pikepdf)]


# --------------------------------------------------------------------------------------------
# Page boxes and rotation (M2 brief, acceptance criterion 5)
# --------------------------------------------------------------------------------------------

#: The keys of one ``boxes`` entry: Folioxide's ``PageInfo`` JSON shape (``camelCase``,
#: docs/ARCHITECTURE.md §A.8). ``index`` only says which page the entry describes.
BOX_ENTRY_KEYS = frozenset({"index", "width", "height", "mediaBox", "cropBox", "rotation"})

#: Expect field -> the box name ``pdfinfo -box`` prints (ISO 32000-2 §14.11.2).
_BOX_NAMES = {"mediaBox": "MediaBox", "cropBox": "CropBox"}

#: ``pdfinfo -box`` prints box coordinates with ``%9.2f`` and sizes with ``%g`` (six
#: significant digits), so values are compared to within that rounding.
_ABS_TOL = 0.006
_REL_TOL = 1e-5

_PAGE_PREFIX = r"^Page\s+(?P<page>\d+)\s+"
_SIZE_LINE = re.compile(_PAGE_PREFIX + r"size:\s+(?P<w>\S+)\s+x\s+(?P<h>\S+)\s+pts")
_ROT_LINE = re.compile(_PAGE_PREFIX + r"rot:\s+(?P<rot>-?\d+)\s*$")
_BOX_LINE = re.compile(_PAGE_PREFIX + r"(?P<box>MediaBox|CropBox|BleedBox|TrimBox|ArtBox):"
                       r"\s+(?P<x1>\S+)\s+(?P<y1>\S+)\s+(?P<x2>\S+)\s+(?P<y2>\S+)\s*$")

Rect = tuple[float, float, float, float]


@dataclass
class PageBoxes:
    """What ``pdfinfo -box`` prints for one page: the size line, the rotation and the boxes."""

    size: tuple[float, float] | None = None
    rotation: int | None = None
    boxes: dict[str, Rect] = field(default_factory=dict)


@dataclass(frozen=True)
class PdfInfoBoxes:
    """Parsed output of ``pdfinfo -box -f 1 -l N``: the page count and pages 1..N (1-based)."""

    returncode: int
    pages: int | None
    by_page: dict[int, PageBoxes]
    stderr: str


def parse_pdfinfo_boxes(stdout: str) -> tuple[int | None, dict[int, PageBoxes]]:
    """Parse the ``Pages:`` line and the per-page ``size``, ``rot`` and box lines.

    A value that cannot be read (a number printed as ``nan``, say) is left out, so the check for
    that value fails with "printed no value" instead of crashing.
    """
    pages: int | None = None
    by_page: dict[int, PageBoxes] = {}
    for line in stdout.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() == "Pages" and value.strip().isdigit():
            pages = int(value.strip())
            continue
        try:
            if m := _SIZE_LINE.match(line):
                by_page.setdefault(int(m["page"]), PageBoxes()).size = (float(m["w"]), float(m["h"]))
            elif m := _ROT_LINE.match(line):
                by_page.setdefault(int(m["page"]), PageBoxes()).rotation = int(m["rot"])
            elif m := _BOX_LINE.match(line):
                rect = (float(m["x1"]), float(m["y1"]), float(m["x2"]), float(m["y2"]))
                if all(math.isfinite(v) for v in rect):
                    by_page.setdefault(int(m["page"]), PageBoxes()).boxes[m["box"]] = rect
        except ValueError:
            continue
    return pages, by_page


@functools.lru_cache(maxsize=64)
def _pdfinfo_boxes_cached(path: str, mtime_ns: int, size: int, last: int) -> PdfInfoBoxes:
    proc = run_tool(["pdfinfo", "-box", "-f", "1", "-l", str(last), path])
    pages, by_page = parse_pdfinfo_boxes(text(proc.stdout))
    return PdfInfoBoxes(proc.returncode, pages, by_page, text(proc.stderr))


def pdfinfo_boxes(path: Path, last: int) -> PdfInfoBoxes:
    """Run ``pdfinfo -box -f 1 -l last`` once per file version and page range (cached)."""
    st = path.stat()
    return _pdfinfo_boxes_cached(str(path), st.st_mtime_ns, st.st_size, max(1, last))


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def expect_rect(value: Any, where: str) -> Rect:
    """A rectangle from expect.json, normalized as ISO 32000-2 §7.9.5 asks readers to: either
    ``{"llx", "lly", "urx", "ury"}`` (Folioxide's ``Rect`` JSON) or ``[llx, lly, urx, ury]``."""
    if isinstance(value, dict) and set(value) == {"llx", "lly", "urx", "ury"}:
        coords = [value["llx"], value["lly"], value["urx"], value["ury"]]
    elif isinstance(value, list) and len(value) == 4:
        coords = list(value)
    else:
        raise ExpectError(f"'{where}' must be {{llx, lly, urx, ury}} or [llx, lly, urx, ury], "
                          f"got {value!r}")
    if not all(_is_number(c) for c in coords):
        raise ExpectError(f"'{where}' must hold four finite numbers, got {value!r}")
    x1, y1, x2, y2 = (float(c) for c in coords)
    return (min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2))


def _fmt(values: tuple[float, ...]) -> str:
    return "[" + " ".join(f"{v:g}" for v in values) + "]"


def _compare_values(name: str, expected: tuple[float, ...], actual: tuple[float, ...] | None) -> CheckResult:
    """PASS when every value is equal to within pdfinfo's printing precision."""
    if actual is None:
        return failed(name, f"expected {_fmt(expected)}, but pdfinfo printed no value")
    close = all(math.isclose(e, a, rel_tol=_REL_TOL, abs_tol=_ABS_TOL)
                for e, a in zip(expected, actual, strict=True))
    if close:
        return passed(name, _fmt(actual))
    return failed(name, f"expected {_fmt(expected)}, got {_fmt(actual)}")


def _validate_boxes(expected: Any) -> list[dict[str, Any]]:
    """The entries of a ``boxes`` expectation, validated (raises :class:`ExpectError`)."""
    if not isinstance(expected, list) or not expected:
        raise ExpectError("'boxes' must be a non-empty list with one entry per page, in page order")
    for i, entry in enumerate(expected):
        where = f"boxes[{i}]"
        if not isinstance(entry, dict):
            raise ExpectError(f"'{where}' must be an object (Folioxide's PageInfo), got {entry!r}")
        unknown = sorted(set(entry) - BOX_ENTRY_KEYS)
        if unknown:
            raise ExpectError(f"'{where}' has unknown key(s) {unknown}; known: {sorted(BOX_ENTRY_KEYS)}")
        if not set(entry) - {"index"}:
            raise ExpectError(f"'{where}' checks nothing: give mediaBox, cropBox, rotation or "
                              "width and height")
        index = entry.get("index", i)
        if isinstance(index, bool) or not isinstance(index, int) or index != i:
            raise ExpectError(f"'{where}.index' must be {i} (entries are in page order), got {index!r}")
        if ("width" in entry) != ("height" in entry):
            raise ExpectError(f"'{where}' must give both 'width' and 'height', or neither")
        for key in ("width", "height"):
            if key in entry and not _is_number(entry[key]):
                raise ExpectError(f"'{where}.{key}' must be a finite number, got {entry[key]!r}")
        rotation = entry.get("rotation", 0)
        if isinstance(rotation, bool) or not isinstance(rotation, int):
            raise ExpectError(f"'{where}.rotation' must be an integer number of degrees, got {rotation!r}")
        for key in _BOX_NAMES:
            if key in entry:
                expect_rect(entry[key], f"{where}.{key}")
    return expected


def check_boxes(path: Path, expected: Any) -> list[CheckResult]:
    """Compare every page's boxes and rotation with ``pdfinfo -box -f 1 -l N`` (M2 brief AC5).

    ``expected`` is a list with one entry per page, in page order, in the JSON shape of
    Folioxide's ``PageInfo``: ``{"index", "width", "height", "mediaBox", "cropBox",
    "rotation"}``, rectangles as ``{"llx", "lly", "urx", "ury"}`` or ``[llx, lly, urx, ury]``.
    Every key is optional and checked when present (``index`` must then be the entry's
    position). There is one check per value, so a ``knownFailures`` entry waives exactly one
    value of one page:

    * ``boxes.count.pdfinfo``: the number of entries equals pdfinfo's ``Pages`` (the root's
      ``/Count``; poppler does not count the leaves)
    * ``boxes[i].mediaBox.pdfinfo`` and ``boxes[i].cropBox.pdfinfo``: the box, to within
      pdfinfo's two decimals (``i`` is the 0-based page index, as in ``PageInfo``)
    * ``boxes[i].rotation.pdfinfo``: the rotation in degrees, exactly
    * ``boxes[i].size.pdfinfo``: ``[width, height]``, the size as displayed. pdfinfo prints the
      crop box's width and height *unrotated*, so they are swapped when pdfinfo's own rotation
      is 90 or 270 before comparing.

    A pdfinfo failure is the single failed check ``boxes.pdfinfo``.

    **poppler quirks** (poppler 24.02, ``PageAttrs`` in ``Page.cc``), which a case lists under
    ``knownFailures`` with the reason when its file has them:

    * ``/Rotate`` is read only when it is an integer, and is not checked for being a multiple of
      90 (ISO 32000-2 §7.7.3.3 requires one): ``/Rotate 45`` prints ``45``, where Folioxide and
      pdf.js use 0; and an integral real such as ``/Rotate 90.0`` is ignored, so the page
      inherits its parent's value, where Folioxide reads 90. Both normalize other multiples of
      90 (``-90``, ``450``) into 0–270 alike.
    * A crop box wider (or taller) than the media box is replaced, in that direction, by the
      media box's extent and then clamped to it, instead of being intersected with the media box
      (§14.11.2); a crop box that does not overlap the media box is clamped into a box without
      area, where Folioxide ignores it (the crop box is then the media box). Folioxide's box
      setters always write a crop box inside the media box, which every reader reads alike.
    """
    entries = _validate_boxes(expected)
    info = pdfinfo_boxes(path, len(entries))
    if info.returncode != 0:
        return [failed("boxes.pdfinfo", f"pdfinfo -box exit {info.returncode}: {first_line(info.stderr)}")]
    results = [compare("boxes.count.pdfinfo", len(entries), info.pages)]
    for i, entry in enumerate(entries):
        page = info.by_page.get(i + 1, PageBoxes())
        for key, box in _BOX_NAMES.items():
            if key in entry:
                want = expect_rect(entry[key], f"boxes[{i}].{key}")
                results.append(_compare_values(f"boxes[{i}].{key}.pdfinfo", want, page.boxes.get(box)))
        if "rotation" in entry:
            results.append(compare(f"boxes[{i}].rotation.pdfinfo", entry["rotation"], page.rotation))
        if "width" in entry:
            shown = page.size
            if shown is not None and page.rotation is not None and page.rotation % 180 == 90:
                shown = (shown[1], shown[0])
            want_size = (float(entry["width"]), float(entry["height"]))
            results.append(_compare_values(f"boxes[{i}].size.pdfinfo", want_size, shown))
    return results


# --------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------


def _parse_info(pairs: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep:
            raise ExpectError(f"--info expects KEY=VALUE, got {pair!r}")
        out[key] = value
    return out


@cli
def main(argv: list[str] | None = None) -> int:
    """Run the structural checks plus any requested value checks on one PDF."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("pdf", type=Path)
    parser.add_argument("--pages", type=int)
    parser.add_argument("--version")
    parser.add_argument("--info", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--object-count", type=int, metavar="N")
    parser.add_argument("--boxes", metavar="JSON",
                        help="the 'boxes' expectation as JSON: one PageInfo object per page")
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    args = parser.parse_args(argv)
    if not args.pdf.is_file():
        raise ExpectError(f"no such file: {args.pdf}")
    boxes = None
    if args.boxes is not None:
        try:
            boxes = json.loads(args.boxes)
        except json.JSONDecodeError as exc:
            raise ExpectError(f"--boxes is not valid JSON: {exc}") from exc

    results = structure_checks(args.pdf)
    if args.pages is not None:
        results += check_pages(args.pdf, args.pages)
    if args.version is not None:
        results += check_version(args.pdf, args.version)
    if args.info:
        results += check_info(args.pdf, _parse_info(args.info))
    if args.object_count is not None:
        results += check_object_count(args.pdf, args.object_count)
    if boxes is not None:
        results += check_boxes(args.pdf, boxes)

    if args.json:
        print(json.dumps([r.to_json() for r in results], indent=2))
    else:
        print_results(results)
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())

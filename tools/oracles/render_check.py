#!/usr/bin/env python3
"""Render probes: what a viewer shows inside and outside a rectangle (M4 brief §6.3, D-22).

``renderProbes`` is a list of probes ``{"page": 0, "rect": [x0, y0, x1, y1], "minDark": 50,
"maxDarkOutside": 10}``:

* ``page``: the 0-based page index (as ``boxes[].index``);
* ``rect``: a rectangle in the page's **default user space** (ISO 32000-2 §8.3.2.3), for
  example a widget's ``/Rect``;
* ``minDark``: at least this many dark pixels (gray value below 128) inside the rectangle;
* ``maxDarkOutside`` (optional): at most this many dark pixels on the rest of the page.

The page is rendered by poppler (``pdftoppm -r 72 -gray -cropbox -f p -l p -singlefile``: the
crop box, what a viewer shows), so one pixel is one point. The rectangle is mapped onto the raster through the page's crop box and its
``/Rotate`` (§7.7.3.3: the page is turned **clockwise** on display), both read with pypdf
(inherited values included). A pixel counts as inside when its centre lies inside the mapped
rectangle.

Each probe gives the rows ``renderProbes[i].inside`` and, with ``maxDarkOutside``,
``renderProbes[i].outside``.

CLI::

    render_check.py FILE --page 0 --rect X0 Y0 X1 Y1 [--min-dark N] [--max-dark-outside N]
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

if str(Path(__file__).resolve().parent) not in sys.path:
    # `python -I` does not put the script directory on sys.path.
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from oracle_common import (  # noqa: E402
    CheckResult,
    ExpectError,
    OracleEnvError,
    cli,
    exit_code,
    failed,
    first_line,
    import_module,
    print_results,
    run_tool,
    text,
)

#: The gray value below which a pixel is dark.
DARK_BELOW = 128

#: The keys a probe may have.
PROBE_KEYS = frozenset({"page", "rect", "minDark", "maxDarkOutside"})


def _validate(probes: Any) -> list[dict[str, Any]]:
    if not isinstance(probes, list) or not probes:
        raise ExpectError("'renderProbes' must be a non-empty list of probes")
    out = []
    for i, probe in enumerate(probes):
        if not isinstance(probe, dict):
            raise ExpectError(f"renderProbes[{i}] must be an object")
        unknown = sorted(set(probe) - PROBE_KEYS)
        if unknown:
            raise ExpectError(f"renderProbes[{i}]: unknown key(s) {unknown}; allowed: {sorted(PROBE_KEYS)}")
        page = probe.get("page")
        if isinstance(page, bool) or not isinstance(page, int) or page < 0:
            raise ExpectError(f"renderProbes[{i}].page must be a 0-based page index")
        rect = probe.get("rect")
        if (not isinstance(rect, list) or len(rect) != 4
                or not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in rect)):
            raise ExpectError(f"renderProbes[{i}].rect must be four numbers [x0, y0, x1, y1]")
        for key in ("minDark", "maxDarkOutside"):
            value = probe.get(key, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ExpectError(f"renderProbes[{i}].{key} must be a non-negative integer")
        if "minDark" not in probe:
            raise ExpectError(f"renderProbes[{i}] needs minDark")
        out.append(probe)
    return out


def parse_pgm(data: bytes) -> tuple[int, int, bytes]:
    """``(width, height, pixels)`` of a binary 8-bit PGM (``P5``), one byte per pixel."""
    tokens: list[bytes] = []
    pos = 0
    while len(tokens) < 4:
        while pos < len(data) and data[pos:pos + 1].isspace():
            pos += 1
        if data[pos:pos + 1] == b"#":
            while pos < len(data) and data[pos:pos + 1] not in (b"\n", b"\r"):
                pos += 1
            continue
        start = pos
        while pos < len(data) and not data[pos:pos + 1].isspace():
            pos += 1
        if start == pos:
            raise ValueError("truncated PGM header")
        tokens.append(data[start:pos])
    if tokens[0] != b"P5":
        raise ValueError(f"not a binary PGM: {tokens[0]!r}")
    width, height, maxval = (int(t) for t in tokens[1:])
    if maxval > 255:
        raise ValueError("16-bit PGM is not supported")
    pixels = data[pos + 1: pos + 1 + width * height]
    if len(pixels) != width * height:
        raise ValueError("truncated PGM data")
    return width, height, pixels


def map_rect(rect: list[float], crop: list[float], rotate: int) -> tuple[float, float, float, float]:
    """The raster box ``(u0, v0, u1, v1)`` (pixels from the top-left corner) of a rectangle in
    default user space, on a page with crop box ``crop`` turned clockwise by ``rotate``."""
    cx0, cy0, cx1, cy1 = min(crop[0], crop[2]), min(crop[1], crop[3]), max(crop[0], crop[2]), max(crop[1], crop[3])

    def point(x: float, y: float) -> tuple[float, float]:
        if rotate == 90:
            return y - cy0, x - cx0
        if rotate == 180:
            return cx1 - x, y - cy0
        if rotate == 270:
            return cy1 - y, cx1 - x
        return x - cx0, cy1 - y

    (u0, v0), (u1, v1) = point(rect[0], rect[1]), point(rect[2], rect[3])
    return min(u0, u1), min(v0, v1), max(u0, u1), max(v0, v1)


def render(pdf: Path, page: int) -> tuple[int, int, bytes]:
    """The page's crop box rendered by ``pdftoppm -r 72 -gray`` (0-based ``page``)."""
    with tempfile.TemporaryDirectory(prefix="folioxide-render-") as tmp:
        prefix = Path(tmp) / "page"
        proc = run_tool(["pdftoppm", "-r", "72", "-gray", "-cropbox", "-f", str(page + 1), "-l",
                         str(page + 1), "-singlefile", pdf, prefix])
        image = prefix.with_suffix(".pgm")
        if proc.returncode != 0 or not image.is_file():
            raise RuntimeError(f"pdftoppm exit {proc.returncode}: {first_line(text(proc.stderr))}")
        return parse_pgm(image.read_bytes())


def count_dark(width: int, height: int, pixels: bytes, box: tuple[float, float, float, float]) -> tuple[int, int]:
    """Dark pixels ``(inside, outside)`` of ``box``; a pixel is inside when its centre is."""
    u0, v0, u1, v1 = box
    inside = outside = 0
    for v in range(height):
        row = pixels[v * width:(v + 1) * width]
        cv = v + 0.5
        in_rows = v0 <= cv <= v1
        for u, value in enumerate(row):
            if value >= DARK_BELOW:
                continue
            if in_rows and u0 <= u + 0.5 <= u1:
                inside += 1
            else:
                outside += 1
    return inside, outside


def check_render_probes(pdf: Path, probes: Any) -> list[CheckResult]:
    """The rows of a ``renderProbes`` expectation."""
    probes = _validate(probes)
    pypdf = import_module("pypdf")
    try:
        reader = pypdf.PdfReader(str(pdf))
        pages = list(reader.pages)
    except Exception as exc:  # noqa: BLE001 - an unreadable file is a failure
        return [failed("renderProbes", f"pypdf cannot read the pages: {type(exc).__name__}: {exc}")]
    results: list[CheckResult] = []
    for i, probe in enumerate(probes):
        prefix = f"renderProbes[{i}]"
        index = probe["page"]
        if index >= len(pages):
            results.append(failed(f"{prefix}.inside", f"page {index} out of range ({len(pages)} pages)"))
            continue
        page = pages[index]
        crop = [float(v) for v in page.cropbox]
        rotate = int(page.rotation or 0) % 360
        try:
            width, height, pixels = render(pdf, index)
        except (RuntimeError, ValueError) as exc:
            results.append(failed(f"{prefix}.inside", str(exc)))
            continue
        box = map_rect([float(v) for v in probe["rect"]], crop, rotate)
        inside, outside = count_dark(width, height, pixels, box)
        shown = "(" + ", ".join(f"{v:g}" for v in box) + ")"
        results.append(CheckResult(f"{prefix}.inside", inside >= probe["minDark"],
                                   f"{inside} dark pixels in {shown} of the {width}x{height} raster "
                                   f"(rotate {rotate}); at least {probe['minDark']}"))
        if "maxDarkOutside" in probe:
            results.append(CheckResult(f"{prefix}.outside", outside <= probe["maxDarkOutside"],
                                       f"{outside} dark pixels outside; at most {probe['maxDarkOutside']}"))
    return results


@cli
def main(argv: list[str] | None = None) -> int:
    """Probe one rectangle of one page."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("pdf", type=Path)
    parser.add_argument("--page", type=int, default=0, help="0-based page index")
    parser.add_argument("--rect", type=float, nargs=4, required=True, metavar=("X0", "Y0", "X1", "Y1"))
    parser.add_argument("--min-dark", type=int, default=1)
    parser.add_argument("--max-dark-outside", type=int)
    args = parser.parse_args(argv)
    if not args.pdf.is_file():
        raise ExpectError(f"no such file: {args.pdf}")
    probe: dict[str, Any] = {"page": args.page, "rect": args.rect, "minDark": args.min_dark}
    if args.max_dark_outside is not None:
        probe["maxDarkOutside"] = args.max_dark_outside
    try:
        results = check_render_probes(args.pdf, [probe])
    except OracleEnvError:
        raise
    print_results(results)
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())

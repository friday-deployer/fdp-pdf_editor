#!/usr/bin/env python3
"""Regenerate the JPEG fixtures of `fixtures/images/` (M4 brief §4.7, §6.3; decision D-17).

Small, generated images for `folioxide_content::image::jpeg` and the visible-signature tests:

- `gray-baseline.jpg`: `fixtures/syntax/minimal.pdf` rendered by `pdftoppm -gray -r 10 -singlefile`
  (poppler; 85 x 110 PGM) and written by Pillow as a one-component baseline (SOF0) JFIF.
  `pdftoppm -jpeg -gray` itself writes three components, so the JPEG step is Pillow's.
- `rgb-baseline.jpg`, `rgb-progressive.jpg`: a 48 x 32 four-colour test pattern (black, red,
  white and blue quadrants) written by Pillow as baseline (SOF0) and progressive (SOF2) JFIF,
  YCbCr with component IDs 1, 2, 3.
- `rgb-adobe.jpg`: the same pattern with `keep_rgb=True`: no colour transform, component IDs
  'R', 'G', 'B', and an Adobe APP14 marker with transform 0 (what libjpeg writes for RGB).
- `rgb-ids.jpg`: `rgb-adobe.jpg` with the APP14 segment removed: only the component IDs say RGB,
  which is the case `/DecodeParms << /ColorTransform 0 >>` is written for.
- `cmyk.jpg`: the pattern as CMYK (four components, Adobe APP14): the `Unsupported` case.

Usage, from the repository root: `python3 -I fixtures/images/generate.py` (needs Pillow and
poppler's `pdftoppm`). The output depends on the libjpeg-turbo and poppler versions, so it is
not byte-reproducible across machines; the tests only rely on the headers described above.
"""

from __future__ import annotations

import io
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent

# Quadrant colours, top-left, top-right, bottom-left, bottom-right.
QUADRANTS = [(0, 0, 0), (255, 0, 0), (255, 255, 255), (0, 0, 255)]
WIDTH, HEIGHT = 48, 32


def pattern() -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT))
    half_w, half_h = WIDTH // 2, HEIGHT // 2
    boxes = [(0, 0), (half_w, 0), (0, half_h), (half_w, half_h)]
    for (x, y), colour in zip(boxes, QUADRANTS):
        image.paste(colour, (x, y, x + half_w, y + half_h))
    return image


def save(image: Image.Image, **options) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, "JPEG", quality=90, **options)
    return buffer.getvalue()


def strip_app14(data: bytes) -> bytes:
    """`data` without its APP14 segments (the marker walk stops at SOS)."""
    out = bytearray(data[:2])
    pos = 2
    while pos + 4 <= len(data):
        marker = data[pos + 1]
        length = int.from_bytes(data[pos + 2:pos + 4], "big")
        if marker == 0xDA:
            break
        if marker != 0xEE:
            out += data[pos:pos + 2 + length]
        pos += 2 + length
    out += data[pos:]
    return bytes(out)


def gray_baseline() -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "gray"
        subprocess.run(
            ["pdftoppm", "-gray", "-r", "10", "-singlefile",
             str(FIXTURES / "syntax" / "minimal.pdf"), str(root)],
            check=True,
        )
        with Image.open(root.with_suffix(".pgm")) as rendered:
            gray = rendered.convert("L")
        return save(gray)


def main() -> int:
    image = pattern()
    rgb_adobe = save(image, keep_rgb=True)
    outputs = {
        "gray-baseline.jpg": gray_baseline(),
        "rgb-baseline.jpg": save(image),
        "rgb-progressive.jpg": save(image, progressive=True),
        "rgb-adobe.jpg": rgb_adobe,
        "rgb-ids.jpg": strip_app14(rgb_adobe),
        "cmyk.jpg": save(image.convert("CMYK")),
    }
    for name, data in outputs.items():
        (HERE / name).write_bytes(data)
        print(f"wrote fixtures/images/{name} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

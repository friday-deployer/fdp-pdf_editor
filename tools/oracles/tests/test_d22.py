"""Self-tests of the M4 runner extensions (brief D-22): ``renderProbes`` and the signature keys
``timestamp: "invalid"`` and ``timestampTrusted``.

The render probes are checked on hand-written pages (pdfgen) with one black rectangle, on every
``/Rotate`` and with an offset crop box; the timestamp keys on pyHanko-signed B-T files, one
with a token substituted from another signature (pyHanko: not intact; OpenSSL: imprint
mismatch) and one timestamped with a TSA certificate without an extended key usage (pyHanko:
valid, not trusted).
"""

from __future__ import annotations

import unittest

import _support  # noqa: F401  (first: puts tools/oracles on sys.path for the imports below)
import extract_cms
import render_check
import run_suite
import validate_sig
from _support import PKI, pdfgen, sign, temp_dir, write_case
from oracle_common import ExpectError

ROOT = [PKI / "root.pem"]

#: A 200 x 100 page with a black rectangle at x 20..60, y 30..50 (800 square points).
RECT = [20, 30, 60, 50]
CONTENT = b"0 g 20 30 40 20 re f\n"


def _page(entries: str) -> bytes:
    return pdfgen.build_pdf(page_entries=(entries,), page_contents=(CONTENT,))


def _names(results):
    return {r.name: r.ok for r in results}


class RenderProbeTests(unittest.TestCase):
    def test_every_rotation_maps_the_rectangle(self):
        for rotate in (0, 90, 180, 270):
            with self.subTest(rotate=rotate), temp_dir() as tmp:
                path = tmp / "page.pdf"
                path.write_bytes(_page(f"/MediaBox [0 0 200 100] /Rotate {rotate}"))
                good = render_check.check_render_probes(
                    path, [{"page": 0, "rect": RECT, "minDark": 700, "maxDarkOutside": 100}])
                self.assertTrue(all(r.ok for r in good), good)
                # The same area elsewhere on the page is empty.
                empty = render_check.check_render_probes(
                    path, [{"page": 0, "rect": [120, 30, 160, 50], "minDark": 1}])
                self.assertEqual(_names(empty), {"renderProbes[0].inside": False})

    def test_the_crop_box_offsets_the_raster(self):
        with temp_dir() as tmp:
            path = tmp / "crop.pdf"
            # The crop box starts at (10, 20): the rectangle stays at its user-space place.
            path.write_bytes(_page("/MediaBox [0 0 300 200] /CropBox [10 20 210 120] /Rotate 90"))
            results = render_check.check_render_probes(
                path, [{"page": 0, "rect": RECT, "minDark": 700, "maxDarkOutside": 100}])
            self.assertTrue(all(r.ok for r in results), results)

    def test_map_rect_and_pgm(self):
        crop = [0, 0, 200, 100]
        self.assertEqual(render_check.map_rect(RECT, crop, 0), (20, 50, 60, 70))
        self.assertEqual(render_check.map_rect(RECT, crop, 90), (30, 20, 50, 60))
        self.assertEqual(render_check.map_rect(RECT, crop, 180), (140, 30, 180, 50))
        self.assertEqual(render_check.map_rect(RECT, crop, 270), (50, 140, 70, 180))
        width, height, pixels = render_check.parse_pgm(b"P5\n# comment\n3 2\n255\n" + bytes([0, 255, 0, 255, 0, 255]))
        self.assertEqual((width, height), (3, 2))
        self.assertEqual(render_check.count_dark(width, height, pixels, (0, 0, 1, 1)), (1, 2))
        with self.assertRaises(ValueError):
            render_check.parse_pgm(b"P6\n1 1\n255\n\x00\x00\x00")

    def test_probe_validation(self):
        for bad in ([], [{"page": 0, "rect": RECT}], [{"page": -1, "rect": RECT, "minDark": 1}],
                    [{"page": 0, "rect": [1, 2, 3], "minDark": 1}],
                    [{"page": 0, "rect": RECT, "minDark": 1, "colour": "red"}]):
            with self.subTest(bad=bad), self.assertRaises(ExpectError):
                render_check._validate(bad)

    def test_run_suite_key(self):
        with temp_dir() as tmp:
            write_case(tmp, "probe", _page("/MediaBox [0 0 200 100]"),
                       {"renderProbes": [{"page": 0, "rect": RECT, "minDark": 700, "maxDarkOutside": 100}]})
            self.assertEqual(run_suite.main([str(tmp)]), 0)
            write_case(tmp, "probe", _page("/MediaBox [0 0 200 100]"),
                       {"renderProbes": [{"page": 0, "rect": [100, 0, 200, 100], "minDark": 1}]})
            self.assertEqual(run_suite.main([str(tmp)]), 1)


def _substituted_token() -> bytes:
    """A pyHanko B-T file whose signature timestamp token is another signature's, written into
    its ``/Contents`` in place."""
    from asn1crypto import cms

    a = sign(pdfgen.build_pdf(page_texts=("first",)), "signer-p256", timestamp=True)
    b = sign(pdfgen.build_pdf(page_texts=("second",)), "signer-p256", timestamp=True)
    with temp_dir() as tmp:
        (tmp / "a.pdf").write_bytes(a)
        (tmp / "b.pdf").write_bytes(b)
        [blob_a] = extract_cms.extract(tmp / "a.pdf")
        [blob_b] = extract_cms.extract(tmp / "b.pdf")
    ci_a = cms.ContentInfo.load(blob_a.cms_der)
    ci_b = cms.ContentInfo.load(blob_b.cms_der)
    ci_a["content"]["signer_infos"][0]["unsigned_attrs"] = ci_b["content"]["signer_infos"][0]["unsigned_attrs"]
    digits = ci_a.dump(force=True).hex().upper().encode("ascii")
    start, end = blob_a.byte_range[1] + 1, blob_a.byte_range[2] - 1
    if len(digits) > end - start:
        raise AssertionError("the substituted CMS does not fit")
    return a[:start] + digits + b"0" * (end - start - len(digits)) + a[end:]


class TimestampKeyTests(unittest.TestCase):
    def test_invalid_token(self):
        with temp_dir() as tmp:
            path = tmp / "substituted.pdf"
            path.write_bytes(_substituted_token())
            results = validate_sig.check_signatures(path, [{"timestamp": "invalid"}], ROOT)
            names = _names(results)
            self.assertTrue(names["signatures[0].timestamp.pyhanko"], results)
            self.assertTrue(names["signatures[0].timestamp.openssl"], results)
            # A sound token is not "invalid", and an invalid one is not `true`.
            good = tmp / "good.pdf"
            good.write_bytes(sign(pdfgen.build_pdf(), "signer-p256", timestamp=True))
            names = _names(validate_sig.check_signatures(good, [{"timestamp": "invalid"}], ROOT))
            self.assertFalse(names["signatures[0].timestamp.pyhanko"])
            self.assertFalse(names["signatures[0].timestamp.openssl"])
            names = _names(validate_sig.check_signatures(path, [{"timestamp": True}], ROOT))
            self.assertFalse(names["signatures[0].timestamp.pyhanko"])
            self.assertFalse(names["signatures[0].timestamp.openssl"])

    def test_timestamp_trusted(self):
        with temp_dir() as tmp:
            good = tmp / "good.pdf"
            good.write_bytes(sign(pdfgen.build_pdf(), "signer-p256", timestamp=True))
            results = validate_sig.check_signatures(good, [{"timestamp": True, "timestampTrusted": True}], ROOT)
            self.assertFalse([r for r in results if not r.ok], results)
            # A TSA certificate without an EKU: pyHanko's token is valid but not trusted.
            no_eku = tmp / "no-eku.pdf"
            no_eku.write_bytes(sign(pdfgen.build_pdf(), "signer-p256", timestamp=True, tsa="tsa-no-eku"))
            names = _names(validate_sig.check_signatures(no_eku, [{"timestampTrusted": False}], ROOT))
            self.assertTrue(names["signatures[0].timestampTrusted.pyhanko"])
            names = _names(validate_sig.check_signatures(no_eku, [{"timestampTrusted": True}], ROOT))
            self.assertFalse(names["signatures[0].timestampTrusted.pyhanko"])
            # It needs trust roots, and the values are checked.
            with self.assertRaises(ExpectError):
                validate_sig.check_signatures(good, [{"timestampTrusted": True}], [])
            with self.assertRaises(ExpectError):
                validate_sig.check_signatures(good, [{"timestamp": "maybe"}], ROOT)


if __name__ == "__main__":
    unittest.main()

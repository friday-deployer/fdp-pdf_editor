"""Self-tests for the ``boxes`` expect key (M2 brief, acceptance criterion 5): every page's media
box, crop box, rotation and displayed size against ``pdfinfo -box -f 1 -l N``."""

from __future__ import annotations

import contextlib
import io
import json
import unittest

import _support  # noqa: F401  (first: puts tools/oracles on sys.path for the imports below)
import check_pdf
import run_suite
from _support import pdfgen, temp_dir, write_case
from oracle_common import ExpectError

#: Pages that inherit from the page tree root (`/MediaBox` A4, `/Rotate 180`) or override it.
AGREEING_PAGES = (
    "",  # everything inherited
    "/MediaBox [612 792 0 0] /CropBox [10 10 300 400.5] /Rotate -90",  # corners reversed
)
#: What Folioxide's PageInfo says for AGREEING_PAGES (rotation normalized, size as displayed).
AGREEING_INFO = [
    {"index": 0, "width": 595.0, "height": 842.0,
     "mediaBox": {"llx": 0.0, "lly": 0.0, "urx": 595.0, "ury": 842.0},
     "cropBox": {"llx": 0.0, "lly": 0.0, "urx": 595.0, "ury": 842.0}, "rotation": 180},
    {"index": 1, "width": 390.5, "height": 290.0,
     "mediaBox": {"llx": 0.0, "lly": 0.0, "urx": 612.0, "ury": 792.0},
     "cropBox": [10, 10, 300, 400.5], "rotation": 270},
]
#: Pages where poppler 24.02 and Folioxide read the same file differently (see
#: check_pdf.check_boxes), with Folioxide's PageInfo for each.
QUIRK_PAGES = (
    "/Rotate 45",  # poppler: 45 (not a multiple of 90); Folioxide: 0
    "/Rotate 90.0",  # poppler: ignores the real, inherits 180; Folioxide: 90
    "/CropBox [100 0 700 400]",  # wider than the media box: poppler [0 0 595 400]; Folioxide clips
)
QUIRK_INFO = [
    {"width": 595, "height": 842, "cropBox": [0, 0, 595, 842], "rotation": 0},
    {"width": 842, "height": 595, "cropBox": [0, 0, 595, 842], "rotation": 90},
    {"width": 495, "height": 400, "mediaBox": [0, 0, 595, 842], "cropBox": [100, 0, 595, 400],
     "rotation": 180},
]
#: The checks the quirks fail, and nothing else.
QUIRK_FAILURES = {
    "boxes[0].rotation.pdfinfo",
    "boxes[1].rotation.pdfinfo",
    "boxes[1].size.pdfinfo",
    "boxes[2].cropBox.pdfinfo",
    "boxes[2].size.pdfinfo",
}


def build(pages: tuple[str, ...]) -> bytes:
    return pdfgen.build_pdf(page_texts=tuple(f"Page {i + 1}" for i in range(len(pages))),
                            page_entries=pages, tree_entries="/MediaBox [0 0 595 842] /Rotate 180")


def failing(results) -> set[str]:
    return {r.name for r in results if not r.ok}


class BoxesTests(unittest.TestCase):
    def setUp(self):
        self._tmp = temp_dir()
        self.dir = self._tmp.__enter__()

    def tearDown(self):
        self._tmp.__exit__(None, None, None)

    def write(self, name: str, data: bytes):
        path = self.dir / name
        path.write_bytes(data)
        return path

    def test_page_info_agrees_with_pdfinfo(self):
        path = self.write("agree.pdf", build(AGREEING_PAGES))
        self.assertTrue(all(r.ok for r in check_pdf.structure_checks(path)))
        results = check_pdf.check_boxes(path, AGREEING_INFO)
        self.assertEqual(failing(results), set(), results)
        self.assertEqual([r.name for r in results], [
            "boxes.count.pdfinfo",
            "boxes[0].mediaBox.pdfinfo", "boxes[0].cropBox.pdfinfo", "boxes[0].rotation.pdfinfo",
            "boxes[0].size.pdfinfo",
            "boxes[1].mediaBox.pdfinfo", "boxes[1].cropBox.pdfinfo", "boxes[1].rotation.pdfinfo",
            "boxes[1].size.pdfinfo",
        ])
        # Only the keys an entry gives are checked.
        partial = check_pdf.check_boxes(path, [{"rotation": 180}, {"cropBox": [300, 400.5, 10, 10]}])
        self.assertEqual([r.name for r in partial], ["boxes.count.pdfinfo", "boxes[0].rotation.pdfinfo",
                                                     "boxes[1].cropBox.pdfinfo"])
        self.assertEqual(failing(partial), set())

    def test_each_wrong_value_fails_its_own_check(self):
        path = self.write("agree.pdf", build(AGREEING_PAGES))
        for page, key, value in (
            (0, "rotation", 0),
            (1, "rotation", 90),  # 90 and 270 swap the size alike: only the rotation fails
            (1, "mediaBox", [0, 0, 612, 791.9]),  # off by more than pdfinfo's rounding
            (0, "cropBox", {"llx": 1, "lly": 0, "urx": 595, "ury": 842}),
        ):
            with self.subTest(page=page, key=key):
                expected = json.loads(json.dumps(AGREEING_INFO))
                expected[page][key] = value
                results = check_pdf.check_boxes(path, expected)
                self.assertEqual(failing(results), {f"boxes[{page}].{key}.pdfinfo"}, results)
        wrong_size = json.loads(json.dumps(AGREEING_INFO))
        wrong_size[1]["width"], wrong_size[1]["height"] = 290.0, 390.5  # not swapped
        results = check_pdf.check_boxes(path, wrong_size)
        self.assertEqual(failing(results), {"boxes[1].size.pdfinfo"})
        [size] = [r for r in results if not r.ok]
        self.assertEqual(size.detail, "expected [290 390.5], got [390.5 290]")

    def test_values_within_pdfinfos_rounding_pass(self):
        path = self.write("agree.pdf", build(AGREEING_PAGES))
        close = [{"cropBox": [0.004, -0.004, 595.005, 842]}, {"cropBox": [10, 10, 300.0049, 400.5]}]
        self.assertEqual(failing(check_pdf.check_boxes(path, close)), set())
        off = [{"cropBox": [0.01, 0, 595, 842]}, {"cropBox": [10, 10, 300, 400.5]}]
        self.assertEqual(failing(check_pdf.check_boxes(path, off)), {"boxes[0].cropBox.pdfinfo"})

    def test_poppler_quirks_fail_exactly_the_documented_checks(self):
        path = self.write("quirks.pdf", build(QUIRK_PAGES))
        self.assertTrue(all(r.ok for r in check_pdf.structure_checks(path)))
        results = check_pdf.check_boxes(path, QUIRK_INFO)
        self.assertEqual(failing(results), QUIRK_FAILURES, results)
        details = {r.name: r.detail for r in results}
        self.assertEqual(details["boxes[0].rotation.pdfinfo"], "expected 0, got 45")
        self.assertEqual(details["boxes[1].rotation.pdfinfo"], "expected 90, got 180")
        self.assertEqual(details["boxes[2].cropBox.pdfinfo"], "expected [100 0 595 400], got [0 0 595 400]")

    def test_page_count_mismatches(self):
        path = self.write("agree.pdf", build(AGREEING_PAGES))
        fewer = check_pdf.check_boxes(path, AGREEING_INFO[:1])
        self.assertEqual(failing(fewer), {"boxes.count.pdfinfo"})
        more = check_pdf.check_boxes(path, [*AGREEING_INFO, {"rotation": 0, "width": 1, "height": 1}])
        self.assertEqual(failing(more), {"boxes.count.pdfinfo", "boxes[2].rotation.pdfinfo",
                                         "boxes[2].size.pdfinfo"})
        self.assertIn("pdfinfo printed no value", {r.name: r.detail for r in more}["boxes[2].size.pdfinfo"])

    def test_unreadable_file_is_one_failure(self):
        path = self.write("broken.pdf", b"%PDF-1.7\nnot a pdf\n")
        [result] = check_pdf.check_boxes(path, [{"rotation": 0}])
        self.assertEqual(result.name, "boxes.pdfinfo")
        self.assertFalse(result.ok)
        self.assertIn("pdfinfo -box exit", result.detail)

    def test_invalid_expectations_raise(self):
        path = self.write("agree.pdf", build(AGREEING_PAGES))
        for bad in (
            [], {}, None, [1], [{}], [{"index": 0}], [{"rotate": 90}],
            [{"index": 1, "rotation": 0}], [{"index": True, "rotation": 0}], [{"index": 0.0, "rotation": 0}],
            [{"width": 1}], [{"width": "1", "height": 2}], [{"width": float("nan"), "height": 2}],
            [{"rotation": 90.0}], [{"rotation": True}],
            [{"mediaBox": [0, 0, 1]}], [{"mediaBox": {"llx": 0, "lly": 0, "urx": 1}}],
            [{"cropBox": [0, 0, 1, "2"]}], [{"cropBox": [0, 0, 1, float("inf")]}],
        ):
            with self.subTest(boxes=bad), self.assertRaises(ExpectError):
                check_pdf.check_boxes(path, bad)


class ParserTests(unittest.TestCase):
    def test_parse_pdfinfo_boxes(self):
        stdout = "\n".join([
            "Title:           Size: 3 x 4 pts",
            "Pages:           2",
            "Page    1 size:  575.5 x 790 pts",
            "Page    1 rot:   90",
            "Page    1 MediaBox:      0.00     0.00   595.00   842.00",
            "Page    1 CropBox:      10.00    10.00   585.50   800.00",
            "Page    2 size:  612 x 792 pts (letter)",
            "Page    2 rot:   45",
            "Page    2 MediaBox:       nan     0.00   612.00   792.00",
            "Page    2 TrimBox:     -12.25     0.00   612.00   792.00",
        ])
        pages, by_page = check_pdf.parse_pdfinfo_boxes(stdout)
        self.assertEqual(pages, 2)
        self.assertEqual(by_page[1].size, (575.5, 790.0))
        self.assertEqual(by_page[1].rotation, 90)
        self.assertEqual(by_page[1].boxes, {"MediaBox": (0.0, 0.0, 595.0, 842.0),
                                            "CropBox": (10.0, 10.0, 585.5, 800.0)})
        self.assertEqual(by_page[2].rotation, 45)
        self.assertEqual(by_page[2].boxes, {"TrimBox": (-12.25, 0.0, 612.0, 792.0)})  # nan left out

    def test_expect_rect_forms(self):
        self.assertEqual(check_pdf.expect_rect([612, 792, 0, 0], "r"), (0.0, 0.0, 612.0, 792.0))
        self.assertEqual(check_pdf.expect_rect({"llx": 1, "lly": 2.5, "urx": 3, "ury": 4}, "r"),
                         (1.0, 2.5, 3.0, 4.0))


class SuiteTests(unittest.TestCase):
    """The ``boxes`` key through run_suite.py, with the quirks waived by ``knownFailures``."""

    def run_suite(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = run_suite.main([str(a) for a in argv])
        return code, out.getvalue()

    def test_known_quirks_pass_as_xfail(self):
        reason = "poppler reads this page differently (check_pdf.check_boxes)"
        with temp_dir() as tmp:
            write_case(tmp / "agree", "agree", build(AGREEING_PAGES), {"pages": 2, "boxes": AGREEING_INFO})
            code, out = self.run_suite(tmp / "agree")
            self.assertEqual(code, 0, out)
            self.assertIn("PASS    agree.pdf  boxes[1].size.pdfinfo", out)

            write_case(tmp / "plain", "quirks", build(QUIRK_PAGES), {"boxes": QUIRK_INFO})
            code, out = self.run_suite(tmp / "plain")
            self.assertEqual(code, 1, out)
            self.assertIn("FAIL    quirks.pdf  boxes[0].rotation.pdfinfo  expected 0, got 45", out)

            known = {name: reason for name in sorted(QUIRK_FAILURES)}
            write_case(tmp / "waived", "quirks", build(QUIRK_PAGES),
                       {"boxes": QUIRK_INFO, "knownFailures": known})
            code, out = self.run_suite(tmp / "waived")
            self.assertEqual(code, 0, out)
            self.assertIn("XFAIL   quirks.pdf  boxes[1].rotation.pdfinfo", out)
            self.assertIn(f"; {len(QUIRK_FAILURES)} known failure(s)", out)

    def test_invalid_boxes_is_an_error(self):
        with temp_dir() as tmp:
            write_case(tmp, "bad", build(AGREEING_PAGES), {"boxes": [{"rotate": 0}]})
            code, out = self.run_suite(tmp)
        self.assertEqual(code, 2, out)
        self.assertIn("ERROR   bad.pdf", out)
        self.assertIn("unknown key(s) ['rotate']", out)


class CliTests(unittest.TestCase):
    def test_boxes_option(self):
        def run(*argv):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                return check_pdf.main(list(argv)), out.getvalue() + err.getvalue()

        with temp_dir() as tmp:
            path = tmp / "agree.pdf"
            path.write_bytes(build(AGREEING_PAGES))
            code, out = run(str(path), "--boxes", json.dumps(AGREEING_INFO))
            self.assertEqual(code, 0, out)
            self.assertIn("PASS  boxes[1].cropBox.pdfinfo", out)
            self.assertEqual(run(str(path), "--boxes", json.dumps(QUIRK_INFO[:2]))[0], 1)
            code, out = run(str(path), "--boxes", "[{not json")
            self.assertEqual(code, 2)
            self.assertIn("--boxes is not valid JSON", out)


if __name__ == "__main__":
    unittest.main()

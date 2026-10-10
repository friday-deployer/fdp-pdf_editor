"""Text oracle self-tests (pdftotext)."""

from __future__ import annotations

import contextlib
import io
import unittest

import _support  # noqa: F401  (first: puts tools/oracles on sys.path for the imports below)
import text_check
from _support import pdfgen, temp_dir
from oracle_common import ExpectError


class TextCheckTests(unittest.TestCase):
    def setUp(self):
        self._tmp = temp_dir()
        self.dir = self._tmp.__enter__()
        self.path = self.dir / "text.pdf"
        self.path.write_bytes(pdfgen.build_pdf(page_texts=("Hello Folioxide", "Second page text")))

    def tearDown(self):
        self._tmp.__exit__(None, None, None)

    def test_contains_and_absent(self):
        results = text_check.check_text(self.path, contains=["Hello Folioxide", "Second page"],
                                        absent=["Goodbye", "Third page"])
        self.assertEqual(len(results), 4)
        self.assertTrue(all(r.ok for r in results), results)

    def test_failures_are_reported(self):
        results = text_check.check_text(self.path, contains=["Goodbye"], absent=["Hello"])
        self.assertEqual([r.ok for r in results], [False, False])
        self.assertEqual(results[0].detail, "not found by pdftotext")
        self.assertEqual(results[1].detail, "found by pdftotext")

    def test_whitespace_is_normalised(self):
        # Two pages come out on separate lines; normalisation lets a needle span the break.
        self.assertTrue(text_check.check_text(self.path, contains=["Folioxide \n\n Second"])[0].ok)

    def test_invalid_expectations_raise(self):
        for bad in ("Hello", [1], ["  "]):
            with self.subTest(bad=bad), self.assertRaises(ExpectError):
                text_check.check_text(self.path, contains=bad)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(text_check.main([str(self.path), "--contains", "Hello"]), 0)
            self.assertEqual(text_check.main([str(self.path), "--absent", "Hello"]), 1)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(text_check.main([str(self.path)]), 2)


if __name__ == "__main__":
    unittest.main()

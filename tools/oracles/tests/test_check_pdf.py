"""Structural oracle self-tests: a hand-written PDF passes, corrupted copies fail."""

from __future__ import annotations

import contextlib
import io
import unittest

import _support  # noqa: F401  (first: puts tools/oracles on sys.path for the imports below)
import check_pdf
from _support import pdfgen, temp_dir
from oracle_common import ExpectError

INFO = {
    "Title": "Folioxide oracle self-test",
    "Author": "Folioxide contributors",
    "Producer": "pdfgen.py (hand-written bytes)",
    "CreationDate": "D:20261010120000Z",
}


def _all_ok(results):
    return all(r.ok for r in results)


class StructureTests(unittest.TestCase):
    def test_hand_written_pdf_passes_every_structural_check(self):
        with temp_dir() as tmp:
            path = tmp / "good.pdf"
            path.write_bytes(pdfgen.build_pdf())
            results = check_pdf.structure_checks(path)
        self.assertEqual([r.name for r in results],
                         ["structure.pdfinfo", "structure.pikepdf", "structure.pypdf"])
        self.assertTrue(_all_ok(results), results)

    def test_corrupted_copies_fail_every_structural_check(self):
        good = pdfgen.build_pdf()
        corruptions = {
            "xref offsets shifted": pdfgen.shift_body(good),
            "truncated before xref": pdfgen.truncate(good),
        }
        for label, data in corruptions.items():
            with self.subTest(label), temp_dir() as tmp:
                path = tmp / "bad.pdf"
                path.write_bytes(data)
                results = check_pdf.structure_checks(path)
                failing = [r.name for r in results if not r.ok]
                self.assertEqual(failing, ["structure.pdfinfo", "structure.pikepdf", "structure.pypdf"],
                                 results)

    def test_multi_page_document(self):
        with temp_dir() as tmp:
            path = tmp / "three.pdf"
            path.write_bytes(pdfgen.build_pdf(page_texts=("one", "two", "three")))
            self.assertTrue(_all_ok(check_pdf.structure_checks(path)))
            self.assertTrue(_all_ok(check_pdf.check_pages(path, 3)))
            wrong = check_pdf.check_pages(path, 1)
        self.assertEqual([r.ok for r in wrong], [False, False, False])


class ValueTests(unittest.TestCase):
    def setUp(self):
        self._tmp = temp_dir()
        self.dir = self._tmp.__enter__()
        self.path = self.dir / "doc.pdf"
        self.path.write_bytes(pdfgen.build_pdf(info=INFO))

    def tearDown(self):
        self._tmp.__exit__(None, None, None)

    def test_pages_version_and_info_match_all_parsers(self):
        results = (
            check_pdf.check_pages(self.path, 1)
            + check_pdf.check_version(self.path, "1.7")
            + check_pdf.check_info(self.path, {**INFO, "Subject": None, "Keywords": None})
        )
        self.assertTrue(_all_ok(results), [r for r in results if not r.ok])
        oracles = {r.name.rsplit(".", 1)[-1] for r in results}
        self.assertEqual(oracles, {"pdfinfo", "pikepdf", "pypdf"})

    def test_mismatches_fail_in_every_parser(self):
        self.assertEqual([r.ok for r in check_pdf.check_version(self.path, "2.0")], [False] * 3)
        info = check_pdf.check_info(self.path, {"Title": "Something else"})
        self.assertEqual([r.ok for r in info], [False] * 3)
        absent = check_pdf.check_info(self.path, {"Author": None})
        self.assertEqual([r.ok for r in absent], [False] * 3)

    def test_custom_info_key_is_checked_without_pdfinfo(self):
        path = self.dir / "custom.pdf"
        path.write_bytes(pdfgen.build_pdf(info={"Title": "T", "FolioxideCase": "custom value"}))
        results = check_pdf.check_info(path, {"FolioxideCase": "custom value"})
        self.assertEqual([r.name for r in results],
                         ["info.FolioxideCase.pikepdf", "info.FolioxideCase.pypdf"])
        self.assertTrue(_all_ok(results))

    def test_catalog_version_overrides_older_header(self):
        path = self.dir / "bumped.pdf"
        path.write_bytes(pdfgen.build_pdf(version="1.4", catalog_version="1.7"))
        self.assertTrue(_all_ok(check_pdf.check_version(path, "1.7")))
        self.assertEqual([r.ok for r in check_pdf.check_version(path, "1.4")], [False] * 3)

    def test_invalid_expectations_raise(self):
        for bad in ("1", -1, True, None):
            with self.subTest(pages=bad), self.assertRaises(ExpectError):
                check_pdf.check_pages(self.path, bad)
        for bad in ("17", 1.7, "1.7.1"):
            with self.subTest(version=bad), self.assertRaises(ExpectError):
                check_pdf.check_version(self.path, bad)
        for bad in ({}, {"Title": 3}, ["Title"]):
            with self.subTest(info=bad), self.assertRaises(ExpectError):
                check_pdf.check_info(self.path, bad)

    def test_effective_version(self):
        self.assertEqual(check_pdf.effective_version("1.4", "/1.7"), "1.7")
        self.assertEqual(check_pdf.effective_version("1.7", "/1.4"), "1.7")
        self.assertEqual(check_pdf.effective_version("2.0", None), "2.0")


class ObjectCountTests(unittest.TestCase):
    """``objectCount``: pikepdf's ``len(pdf.objects)`` minus its null entries."""

    def setUp(self):
        self._tmp = temp_dir()
        self.dir = self._tmp.__enter__()

    def tearDown(self):
        self._tmp.__exit__(None, None, None)

    def write(self, name, data):
        path = self.dir / name
        path.write_bytes(data)
        return path

    def test_counts_every_object(self):
        # Catalog, page tree, font, Info, and a page plus its content stream per page.
        path = self.write("three.pdf", pdfgen.build_pdf(page_texts=("one", "two", "three")))
        [result] = check_pdf.check_object_count(path, 10)
        self.assertTrue(result.ok, result)
        self.assertEqual(result.name, "objectCount.pikepdf")
        self.assertEqual(result.detail, "len(pdf.objects) 10 - 0 null = 10")
        [wrong] = check_pdf.check_object_count(path, 9)
        self.assertFalse(wrong.ok)
        self.assertIn("expected 9, got 10", wrong.detail)

    def test_objects_freed_by_a_later_revision_are_not_counted(self):
        # qpdf still lists the freed Info dictionary 4, as a null object.
        path = self.write("freed.pdf", pdfgen.append_free(pdfgen.build_pdf(), (4,)))
        import pikepdf

        with pikepdf.open(path) as pdf:
            self.assertEqual(check_pdf.pikepdf_object_count(pdf), (6, 1))
        [result] = check_pdf.check_object_count(path, 5)
        self.assertTrue(result.ok, result)
        self.assertEqual(result.detail, "len(pdf.objects) 6 - 1 null = 5")
        self.assertTrue(all(r.ok for r in check_pdf.structure_checks(path)))

    def test_redefined_objects_count_once(self):
        updated = pdfgen.append_update(pdfgen.build_pdf(), {4: b"<< /Title (Updated) >>",
                                                            7: b"<< /Extra true >>"})
        path = self.write("updated.pdf", updated)
        self.assertTrue(check_pdf.check_object_count(path, 7)[0].ok)

    def test_unreadable_file_fails_and_bad_expectations_raise(self):
        path = self.write("broken.pdf", b"%PDF-1.7\nnot a pdf\n")
        [result] = check_pdf.check_object_count(path, 1)
        self.assertFalse(result.ok)
        for bad in ("5", -1, True, None, 5.0):
            with self.subTest(objectCount=bad), self.assertRaises(ExpectError):
                check_pdf.check_object_count(path, bad)


class CliTests(unittest.TestCase):
    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = check_pdf.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_exit_codes(self):
        with temp_dir() as tmp:
            good = tmp / "good.pdf"
            good.write_bytes(pdfgen.build_pdf())
            bad = tmp / "bad.pdf"
            bad.write_bytes(pdfgen.shift_body(pdfgen.build_pdf()))
            code, out, _ = self.run_main(str(good), "--pages", "1", "--version", "1.7",
                                         "--info", "Title=Folioxide oracle self-test",
                                         "--object-count", "6")
            self.assertEqual(code, 0, out)
            self.assertIn("PASS  structure.pikepdf", out)
            self.assertIn("PASS  objectCount.pikepdf", out)
            self.assertEqual(self.run_main(str(good), "--object-count", "5")[0], 1)
            self.assertEqual(self.run_main(str(good), "--pages", "2")[0], 1)
            self.assertEqual(self.run_main(str(bad))[0], 1)
            self.assertEqual(self.run_main(str(tmp / "missing.pdf"))[0], 2)


if __name__ == "__main__":
    unittest.main()

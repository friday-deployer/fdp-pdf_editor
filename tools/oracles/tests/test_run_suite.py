"""Contract tests for run_suite.py (docs/milestones/M0.md, "Oracle runner CLI")."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import sys
import unittest
from unittest import mock

import _support  # noqa: F401  (first: puts tools/oracles on sys.path for the imports below)
import run_suite
from _support import (
    ORACLES_DIR,
    REPO_ROOT,
    nonzero_padding,
    pdfgen,
    shadowed_contents,
    sign,
    temp_dir,
    write_case,
)

NOT_IMPLEMENTED = ("encrypted", "xmpContains", "fields", "annots", "fontsEmbedded", "images")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = run_suite.main([str(a) for a in argv])
    return code, out.getvalue(), err.getvalue()


class RegistryTests(unittest.TestCase):
    def test_every_spec_key_is_either_wired_or_pending(self):
        wired = {"pages", "version", "info", "signatures", "textContains", "textAbsent", "prefixOf",
                 "revisions", "objectCount", "boxes", "renderProbes"}
        self.assertEqual(set(run_suite.REGISTRY), wired)
        self.assertEqual(set(run_suite.SPEC_KEYS) - wired, set(NOT_IMPLEMENTED))

    def test_register_rejects_keys_outside_the_spec(self):
        with self.assertRaises(ValueError):
            run_suite.register("colour")


class ContractTests(unittest.TestCase):
    def test_passing_suite_exits_0_and_prints_a_table(self):
        base = pdfgen.build_pdf(page_texts=("Hello Folioxide", "Page two"))
        with temp_dir() as tmp:
            suite = tmp / "oracle"
            write_case(suite / "structure", "two-pages", base, {
                "pages": 2, "version": "1.7",
                "info": {"Title": "Folioxide oracle self-test", "ModDate": None},
                "textContains": ["Hello Folioxide", "Page two"], "textAbsent": ["Page three"],
                "revisions": 1,
            })
            (suite / "sign").mkdir(parents=True)
            (suite / "sign" / "input.pdf").write_bytes(base)  # no expect.json: not a case
            write_case(suite / "sign", "signed", sign(base), {
                "trustRoots": ["fixtures/pki/root.pem"],
                "prefixOf": "input.pdf",
                "revisions": 2,
                "signatures": [{"field": "Signature1", "intact": True, "valid": True, "trusted": True,
                                "coverage": "entireFile", "modification": "none", "pades": "B-B"}],
            })
            code, out, err = run(suite)
            self.assertEqual(code, 0, out + err)
            self.assertIn("RESULT  CASE", out)
            self.assertIn("PASS    sign/signed.pdf", out)
            self.assertIn("structure/two-pages.pdf", out)
            self.assertNotIn("FAIL", out.replace("0 failed", ""))
            self.assertIn("oracle: 2 case(s)", out)

            report = tmp / "report.json"
            code, out, _ = run("--failures-only", "--json-report", report, suite)
            self.assertEqual(code, 0)
            self.assertNotIn("PASS ", out)
            data = json.loads(report.read_text())
            self.assertEqual([c["status"] for c in data], ["PASS", "PASS"])

    def test_failed_check_exits_1(self):
        with temp_dir() as tmp:
            write_case(tmp, "wrong", pdfgen.build_pdf(), {"pages": 3})
            code, out, _ = run(tmp)
        self.assertEqual(code, 1)
        self.assertIn("FAIL    wrong.pdf", out)
        self.assertIn("expected 3, got 1", out)

    def test_structural_failure_without_any_key_exits_1(self):
        with temp_dir() as tmp:
            write_case(tmp, "broken", pdfgen.shift_body(pdfgen.build_pdf()), {})
            code, out, _ = run(tmp)
        self.assertEqual(code, 1)
        self.assertIn("structure.pikepdf", out)

    def test_prefix_and_revision_failures(self):
        base = pdfgen.build_pdf()
        other = pdfgen.build_pdf(page_texts=("Different",))
        with temp_dir() as tmp:
            (tmp / "other.pdf").write_bytes(other)
            write_case(tmp, "signed", sign(base), {"prefixOf": "other.pdf", "revisions": 1})
            code, out, _ = run(tmp)
        self.assertEqual(code, 1)
        self.assertIn("FAIL    signed.pdf  prefixOf", out)
        self.assertIn("revisions.startxref", out)
        self.assertIn("expected 1, got 2", out)

    def test_no_cases_exits_0(self):
        with temp_dir() as tmp:
            (tmp / "lonely.pdf").write_bytes(pdfgen.build_pdf())
            code, out, _ = run(tmp)
        self.assertEqual(code, 0)
        self.assertIn("no oracle cases", out)

    def test_unknown_key_exits_2(self):
        with temp_dir() as tmp:
            write_case(tmp, "typo", pdfgen.build_pdf(), {"pagez": 1})
            code, out, _ = run(tmp)
        self.assertEqual(code, 2)
        self.assertIn("unknown expect key(s) ['pagez']", out)

    def test_not_implemented_keys_exit_2_never_pass_silently(self):
        for key in NOT_IMPLEMENTED:
            with self.subTest(key), temp_dir() as tmp:
                write_case(tmp, "pending", pdfgen.build_pdf(), {"pages": 1, key: []})
                code, out, _ = run(tmp)
                self.assertEqual(code, 2)
                self.assertIn(f"check not implemented yet for expect key(s) ['{key}']", out)

    def test_usage_and_environment_errors_exit_2(self):
        with temp_dir() as tmp:
            self.assertEqual(run(tmp / "missing")[0], 2)
            write_case(tmp / "a", "bad-json", pdfgen.build_pdf(), "{not json")
            self.assertEqual(run(tmp / "a")[0], 2)
            (tmp / "b").mkdir()
            (tmp / "b" / "orphan.expect.json").write_text("{}")
            code, out, _ = run(tmp / "b")
            self.assertEqual(code, 2)
            self.assertIn("has no sibling orphan.pdf", out)
            write_case(tmp / "c", "bad-type", pdfgen.build_pdf(), {"pages": "one"})
            self.assertEqual(run(tmp / "c")[0], 2)
            write_case(tmp / "d", "no-roots", sign(pdfgen.build_pdf()), {"signatures": [{"trusted": True}]})
            code, out, _ = run(tmp / "d")
            self.assertEqual(code, 2)
            self.assertIn("'trusted' needs trust roots", out)
            # ...which --trust-root supplies.
            self.assertEqual(run("--trust-root", REPO_ROOT / "fixtures/pki/root.pem", tmp / "d")[0], 0)
        self.assertEqual(run()[0], 2)

    def test_missing_tool_exits_2(self):
        real_which = shutil.which

        def without_poppler(name, *args, **kwargs):
            return None if name.startswith("pdf") else real_which(name, *args, **kwargs)

        with temp_dir() as tmp:
            write_case(tmp, "case", pdfgen.build_pdf(), {"pages": 1, "textContains": ["Hello"]})
            with mock.patch("oracle_common.shutil.which", side_effect=without_poppler):
                code, out, _ = run(tmp)
        self.assertEqual(code, 2)
        self.assertIn("required tool 'pdfinfo' not found on PATH", out)

    def test_failure_outranks_error(self):
        """A genuine failure exits 1 even when another case could not be evaluated."""
        with temp_dir() as tmp:
            write_case(tmp, "fails", pdfgen.build_pdf(), {"pages": 9})
            write_case(tmp, "errors", pdfgen.build_pdf(), {"images": []})
            (tmp / "orphan.expect.json").write_text("{}")
            code, out, _ = run(tmp)
        self.assertEqual(code, 1)
        self.assertIn("1 failed, 2 error(s)", out)
        self.assertIn("ERROR   errors.pdf", out)
        self.assertIn("ERROR   orphan.pdf", out)
        self.assertIn("FAIL    fails.pdf", out)

    def test_error_without_failure_exits_2(self):
        with temp_dir() as tmp:
            write_case(tmp, "passes", pdfgen.build_pdf(), {"pages": 1})
            write_case(tmp, "errors", pdfgen.build_pdf(), {"images": []})
            code, out, _ = run(tmp)
        self.assertEqual(code, 2)
        self.assertIn("0 failed, 1 error(s)", out)

    def test_minimal_signature_entry_still_checks_structure_and_crypto(self):
        """``{"field": ...}`` alone must not let a broken signature through the suite."""
        signed = sign(pdfgen.build_pdf())
        tampered = pdfgen.flip_byte(signed, signed.index(b"Hello Folioxide"))
        minimal = {"signatures": [{"field": "Signature1"}]}
        with temp_dir() as tmp:
            write_case(tmp / "good", "signed", signed, minimal)
            self.assertEqual(run(tmp / "good")[0], 0)
            for name, data, row in (("tampered", tampered, "signatures[0].openssl"),
                                    ("padding", nonzero_padding(signed), "signatures[0].padding"),
                                    ("shadow", shadowed_contents(signed), "signatures[0].gap")):
                with self.subTest(name):
                    write_case(tmp / name, "signed", data, minimal)
                    report = tmp / f"{name}.json"
                    code, out, _ = run("--json-report", report, tmp / name)
                    self.assertEqual(code, 1, out)
                    self.assertIn(f"FAIL    signed.pdf  {row}", out)
                    [case] = json.loads(report.read_text())
                    failing = {c["name"] for c in case["checks"] if not c["ok"]}
                    if name == "tampered":
                        self.assertEqual(failing, {"signatures[0].intact.pyhanko", "signatures[0].pdfsig",
                                                   "signatures[0].openssl"})
                    else:  # every other oracle, structural ones included, accepts these files
                        self.assertEqual(failing, {row})

    def test_several_directories(self):
        with temp_dir() as tmp:
            write_case(tmp / "one", "a", pdfgen.build_pdf(), {"pages": 1})
            write_case(tmp / "two", "b", pdfgen.build_pdf(), {"pages": 1})
            code, out, _ = run(tmp / "one", tmp / "two")
        self.assertEqual(code, 0)
        self.assertIn("one/a.pdf", out)
        self.assertIn("two/b.pdf", out)


class SkipAndKnownFailureTests(unittest.TestCase):
    """The meta keys ``oracleSkip`` and ``knownFailures`` (M1 brief WP1.5, oracle suite ``syntax``)."""

    def test_skipped_case_runs_no_check_and_exits_0(self):
        broken = pdfgen.shift_body(pdfgen.build_pdf())  # every structural check would fail
        with temp_dir() as tmp:
            write_case(tmp, "repaired", broken, {"oracleSkip": "the oracles must repair this file"})
            write_case(tmp, "good", pdfgen.build_pdf(), {"pages": 1, "objectCount": 6})
            report = tmp / "report.json"
            code, out, _ = run("--json-report", report, tmp)
            self.assertEqual(code, 0, out)
            self.assertIn("SKIP    repaired.pdf", out)
            self.assertIn("the oracles must repair this file", out)
            self.assertIn("PASS    good.pdf      objectCount.pikepdf", out)
            self.assertIn("1 passed, 0 failed, 0 error(s), 1 skipped", out)
            data = {c["case"]: c for c in json.loads(report.read_text())}
            self.assertEqual(data["repaired.pdf"]["status"], "SKIP")
            self.assertEqual(data["repaired.pdf"]["checks"], [])
            self.assertEqual(data["repaired.pdf"]["skipped"], "the oracles must repair this file")
            self.assertEqual(data["good.pdf"]["status"], "PASS")
            # --failures-only hides skipped cases too.
            code, out, _ = run("--failures-only", tmp)
            self.assertEqual(code, 0)
            self.assertNotIn("SKIP    ", out)

    def test_skipped_case_keys_are_still_validated(self):
        for expect in ({"oracleSkip": ""}, {"oracleSkip": 1}, {"oracleSkip": "why", "pagez": 1},
                       {"oracleSkip": "why", "knownFailures": {"structure.pypdf": "why"}}):
            with self.subTest(expect=expect), temp_dir() as tmp:
                write_case(tmp, "case", pdfgen.build_pdf(), expect)
                code, out, _ = run(tmp)
                self.assertEqual(code, 2, out)
                self.assertIn("ERROR   case.pdf", out)

    def test_object_count_mismatch_fails(self):
        with temp_dir() as tmp:
            write_case(tmp, "count", pdfgen.build_pdf(), {"objectCount": 7})
            code, out, _ = run(tmp)
        self.assertEqual(code, 1)
        self.assertIn("FAIL    count.pdf  objectCount.pikepdf", out)
        self.assertIn("expected 7, got 6", out)

    def test_known_failure_passes_as_xfail(self):
        # pypdf's strict mode warns about an update section whose first subsection is not 0.
        # The update re-lists object 4 at its old offset, without the object 0 entry.
        base = pdfgen.build_pdf()
        startxref = int(base[base.rindex(b"startxref") + 9:].split()[0])
        update = (b"xref\n4 1\n%010d 00000 n \ntrailer\n<< /Size 7 /Root 1 0 R /Prev %d >>\n"
                  % (base.index(b"4 0 obj"), startxref))
        data = base + update + b"startxref\n%d\n%%%%EOF\n" % len(base)
        reason = "pypdf strict warns about update sections that do not start at 0"
        with temp_dir() as tmp:
            write_case(tmp / "plain", "update", data, {"pages": 1})
            code, out, _ = run(tmp / "plain")
            self.assertEqual(code, 1, out)
            self.assertIn("FAIL    update.pdf  structure.pypdf", out)

            write_case(tmp / "waived", "update", data,
                       {"pages": 1, "knownFailures": {"structure.pypdf": reason}})
            report = tmp / "report.json"
            code, out, _ = run("--json-report", report, tmp / "waived")
            self.assertEqual(code, 0, out)
            self.assertIn("XFAIL   update.pdf  structure.pypdf", out)
            self.assertIn(f"known failure: {reason} [", out)
            self.assertIn("; 1 known failure(s)", out)
            [case] = json.loads(report.read_text())
            waived = {c["name"]: c["knownFailure"] for c in case["checks"]}
            self.assertTrue(waived["structure.pypdf"])
            self.assertFalse(waived["structure.pikepdf"])

    def test_stale_known_failure_fails(self):
        with temp_dir() as tmp:
            write_case(tmp, "clean", pdfgen.build_pdf(),
                       {"knownFailures": {"structure.pypdf": "no longer true"}})
            code, out, _ = run(tmp)
        self.assertEqual(code, 1)
        self.assertIn("FAIL    clean.pdf  structure.pypdf", out)
        self.assertIn("remove the entry", out)

    def test_known_failure_of_a_check_that_does_not_run_is_an_error(self):
        for known in ({"pages.pikepdf": "not requested"}, {"structure.pypdf": ""}, ["structure.pypdf"]):
            with self.subTest(known=known), temp_dir() as tmp:
                write_case(tmp, "case", pdfgen.build_pdf(), {"knownFailures": known})
                code, out, _ = run(tmp)
                self.assertEqual(code, 2, out)
                self.assertIn("knownFailures", out)


class IsolatedCliTests(unittest.TestCase):
    """The contract invocation: ``python -I tools/oracles/run_suite.py <dir>`` from any cwd."""

    def test_python_isolated_mode(self):
        with temp_dir() as tmp:
            write_case(tmp, "ok", pdfgen.build_pdf(), {"pages": 1})
            proc = subprocess.run([sys.executable, "-I", str(ORACLES_DIR / "run_suite.py"), str(tmp)],
                                  capture_output=True, text=True, cwd=tmp, check=False)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("PASS    ok.pdf", proc.stdout)
            empty = tmp / "empty"
            empty.mkdir()
            proc = subprocess.run([sys.executable, "-I", str(ORACLES_DIR / "run_suite.py"), str(empty)],
                                  capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0)
            self.assertIn("no oracle cases", proc.stdout)

    def test_every_oracle_module_has_a_cli(self):
        for module in ("check_pdf", "validate_sig", "extract_cms", "pades_profile", "text_check",
                       "run_suite"):
            with self.subTest(module):
                proc = subprocess.run([sys.executable, "-I", str(ORACLES_DIR / f"{module}.py"), "--help"],
                                      capture_output=True, text=True, check=False)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn("usage:", proc.stdout)


if __name__ == "__main__":
    unittest.main()

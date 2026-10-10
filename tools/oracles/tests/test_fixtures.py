"""Fixture hygiene (fixtures/README.md): every committed file is documented and under 200 KB."""

from __future__ import annotations

import fnmatch
import re
import unittest

from _support import REPO_ROOT

FIXTURES = REPO_ROOT / "fixtures"
MAX_BYTES = 200 * 1024


def documented_patterns() -> list[str]:
    """The backticked paths/globs in the first column of the provenance table."""
    patterns: list[str] = []
    for line in (FIXTURES / "README.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("| `"):
            first_cell = line.split("|")[1]
            patterns.extend(re.findall(r"`([^`]+)`", first_cell))
    return patterns


def fixture_files() -> list[str]:
    return sorted(
        p.relative_to(FIXTURES).as_posix()
        for p in FIXTURES.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    )


class FixtureTests(unittest.TestCase):
    def test_every_fixture_has_a_provenance_row(self):
        patterns = documented_patterns()
        self.assertTrue(patterns)
        for rel in fixture_files():
            with self.subTest(rel):
                self.assertTrue(any(fnmatch.fnmatchcase(rel, pat) for pat in patterns),
                                f"fixtures/{rel} has no row in fixtures/README.md")

    def test_every_fixture_is_small(self):
        for rel in fixture_files():
            with self.subTest(rel):
                self.assertLess((FIXTURES / rel).stat().st_size, MAX_BYTES)

    def test_license_policy_is_stated(self):
        text = (FIXTURES / "README.md").read_text(encoding="utf-8")
        self.assertIn("licensed **`MIT`**", text)
        self.assertIn("External corpora are never committed", text)
        self.assertIn("test data only", text)

    def test_pki_readme_marks_keys_as_test_only(self):
        self.assertIn("test-only", (FIXTURES / "pki" / "README.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

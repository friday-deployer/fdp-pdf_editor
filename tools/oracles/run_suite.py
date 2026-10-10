#!/usr/bin/env python3
"""Oracle suite runner: the contract between Folioxide's tests and the external oracles.

Usage::

    python -I tools/oracles/run_suite.py [--trust-root PEM]... [--failures-only]
                                         [--json-report FILE] DIR [DIR ...]

Rust tests built with the ``folioxide-testkit/emit`` feature write ``<name>.pdf`` plus
``<name>.expect.json`` under ``target/oracle/<suite>/`` (docs/ARCHITECTURE.md §A.9). This runner
searches every DIR recursively, takes every ``*.pdf`` that has a sibling ``<name>.expect.json``,
runs the baseline structural checks plus one check per expect key, and prints a PASS/FAIL table.

Exit codes:

* ``0``: every check passed, or no cases were found (prints "no oracle cases")
* ``1``: at least one check failed, even when other cases ended in ERROR (a genuine failure is
  never reported as an environment problem; the ERROR rows are still printed)
* ``2``: no check failed, but there was a usage or environment error: a missing DIR, tool or
  Python module, an invalid expect.json, an expect.json without its PDF, an unknown expect key,
  or a key whose check is not implemented yet

Expect keys (§A.9). Implemented:

* ``pages`` (int), ``version`` ("1.7"), ``info`` ({"Title": "...", "ModDate": null}): see
  ``check_pdf.py``
* ``signatures`` ([{field, intact, valid, trusted, coverage, modification, docmdp, docmdpOk,
  pades, timestamp}]): see ``validate_sig.py``. ``intact`` and ``valid`` default to true, and
  every signature also gets the structural, pdfsig and OpenSSL checks
* ``textContains`` / ``textAbsent`` (lists of strings): see ``text_check.py``
* ``prefixOf`` (path): the PDF starts with every byte of that file (incremental-save integrity)
* ``revisions`` (int): number of ``startxref`` keywords in the file, and pyHanko's revision count

Not implemented yet (exit 2 until their milestone adds them): ``encrypted``, ``xmpContains``,
``fields``, ``annots``, ``fontsEmbedded``, ``images``.

Meta key: ``trustRoots`` (list of paths) adds trust anchors for ``signatures``, on top of any
``--trust-root``. Relative paths in expect.json (``prefixOf``, ``trustRoots``) are resolved
against the expect.json's directory first, then against the repository root.

Every case also runs the structural checks of ``check_pdf.py`` (pdfinfo, pikepdf, pypdf).
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if str(Path(__file__).resolve().parent) not in sys.path:
    # `python -I` does not put the script directory on sys.path.
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_pdf  # noqa: E402
import text_check  # noqa: E402
import validate_sig  # noqa: E402
from oracle_common import (  # noqa: E402
    EXIT_ENV,
    EXIT_FAIL,
    EXIT_OK,
    CheckResult,
    ExpectError,
    OracleEnvError,
    captured_logs,
    compare,
    failed,
    import_module,
    passed,
    resolve_path,
)

EXPECT_SUFFIX = ".expect.json"

#: Every expect key named in docs/ARCHITECTURE.md §A.9, in the order checks run.
SPEC_KEYS = (
    "pages",
    "version",
    "encrypted",
    "info",
    "xmpContains",
    "signatures",
    "fields",
    "annots",
    "textContains",
    "textAbsent",
    "fontsEmbedded",
    "images",
    "prefixOf",
    "revisions",
)
#: Keys that configure the run instead of naming a check.
META_KEYS = frozenset({"trustRoots"})


@dataclass
class Case:
    """One ``<name>.pdf`` + ``<name>.expect.json`` pair."""

    label: str
    pdf: Path
    expect_path: Path
    expect: dict[str, Any] = field(default_factory=dict)
    trust_roots: list[Path] = field(default_factory=list)


CheckFn = Callable[[Case, Any], list[CheckResult]]

#: The pluggable check registry: expect key -> check function.
REGISTRY: dict[str, CheckFn] = {}


def register(key: str) -> Callable[[CheckFn], CheckFn]:
    """Register ``fn`` as the check for an expect key (later milestones add keys here)."""
    if key not in SPEC_KEYS:
        raise ValueError(f"{key!r} is not an expect key from docs/ARCHITECTURE.md §A.9")

    def decorator(fn: CheckFn) -> CheckFn:
        REGISTRY[key] = fn
        return fn

    return decorator


@register("pages")
def _check_pages(case: Case, value: Any) -> list[CheckResult]:
    return check_pdf.check_pages(case.pdf, value)


@register("version")
def _check_version(case: Case, value: Any) -> list[CheckResult]:
    return check_pdf.check_version(case.pdf, value)


@register("info")
def _check_info(case: Case, value: Any) -> list[CheckResult]:
    return check_pdf.check_info(case.pdf, value)


@register("signatures")
def _check_signatures(case: Case, value: Any) -> list[CheckResult]:
    return validate_sig.check_signatures(case.pdf, value, case.trust_roots)


@register("textContains")
def _check_text_contains(case: Case, value: Any) -> list[CheckResult]:
    return text_check.check_text(case.pdf, contains=value)


@register("textAbsent")
def _check_text_absent(case: Case, value: Any) -> list[CheckResult]:
    return text_check.check_text(case.pdf, absent=value)


@register("prefixOf")
def _check_prefix_of(case: Case, value: Any) -> list[CheckResult]:
    if not isinstance(value, str) or not value:
        raise ExpectError(f"'prefixOf' must be a path string, got {value!r}")
    original = resolve_path(value, case.expect_path.parent).read_bytes()
    data = case.pdf.read_bytes()
    if data.startswith(original):
        return [passed("prefixOf", f"first {len(original)} of {len(data)} bytes are the original")]
    limit = min(len(original), len(data))
    first_diff = next((i for i in range(limit) if original[i] != data[i]), limit)
    return [failed("prefixOf", f"differs from {value} at byte {first_diff} "
                               f"(original {len(original)} bytes, file {len(data)} bytes)")]


_STARTXREF = re.compile(rb"(?<![A-Za-z])startxref\s")


@register("revisions")
def _check_revisions(case: Case, value: Any) -> list[CheckResult]:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ExpectError(f"'revisions' must be a positive integer, got {value!r}")
    data = case.pdf.read_bytes()
    results = [compare("revisions.startxref", value, len(_STARTXREF.findall(data)))]
    reader_mod = import_module("pyhanko.pdf_utils.reader")
    try:
        with captured_logs("pyhanko"):
            reader = reader_mod.PdfFileReader(io.BytesIO(data), strict=False)
            results.append(compare("revisions.pyhanko", value, reader.xrefs.total_revisions))
    except Exception as exc:  # noqa: BLE001
        results.append(failed("revisions.pyhanko", f"{type(exc).__name__}: {exc}"))
    return results


# --------------------------------------------------------------------------------------------
# Discovery and execution
# --------------------------------------------------------------------------------------------


@dataclass
class CaseOutcome:
    case_label: str
    results: list[CheckResult] = field(default_factory=list)
    error: str | None = None  # usage/environment problem: the case could not be evaluated

    @property
    def status(self) -> str:
        if self.error is not None:
            return "ERROR"
        return "PASS" if all(r.ok for r in self.results) else "FAIL"


def discover(dirs: list[Path]) -> tuple[list[Case], list[CaseOutcome]]:
    """Find cases; expect files without a PDF become ERROR outcomes."""
    cases: list[Case] = []
    orphans: list[CaseOutcome] = []
    seen: set[Path] = set()
    for root in dirs:
        for expect_path in sorted(root.rglob(f"*{EXPECT_SUFFIX}")):
            resolved = expect_path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            stem = expect_path.name[: -len(EXPECT_SUFFIX)]
            pdf = expect_path.with_name(f"{stem}.pdf")
            label = (expect_path.parent / f"{stem}.pdf").relative_to(root).as_posix()
            if len(dirs) > 1:
                label = f"{root.name}/{label}"
            if not pdf.is_file():
                orphans.append(CaseOutcome(label, error=f"{expect_path.name} has no sibling {pdf.name}"))
                continue
            cases.append(Case(label=label, pdf=pdf, expect_path=expect_path))
    return cases, orphans


def load_expect(case: Case, default_roots: list[Path]) -> None:
    """Parse and validate the expect.json of ``case`` (raises ExpectError)."""
    try:
        expect = json.loads(case.expect_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExpectError(f"cannot read {case.expect_path.name}: {exc}") from exc
    if not isinstance(expect, dict):
        raise ExpectError(f"{case.expect_path.name} must contain a JSON object")
    unknown = sorted(k for k in expect if k not in SPEC_KEYS and k not in META_KEYS)
    if unknown:
        raise ExpectError(f"unknown expect key(s) {unknown}; known: {list(SPEC_KEYS) + sorted(META_KEYS)}")
    pending = [k for k in SPEC_KEYS if k in expect and k not in REGISTRY]
    if pending:
        raise ExpectError(f"check not implemented yet for expect key(s) {pending}")
    roots = expect.get("trustRoots", [])
    if not isinstance(roots, list) or not all(isinstance(r, str) for r in roots):
        raise ExpectError("'trustRoots' must be a list of paths")
    case.expect = expect
    case.trust_roots = list(default_roots) + [resolve_path(r, case.expect_path.parent) for r in roots]


def run_case(case: Case, default_roots: list[Path]) -> CaseOutcome:
    outcome = CaseOutcome(case.label)
    try:
        load_expect(case, default_roots)
        outcome.results.extend(check_pdf.structure_checks(case.pdf))
        for key in SPEC_KEYS:
            if key in case.expect:
                outcome.results.extend(REGISTRY[key](case, case.expect[key]))
    except (ExpectError, OracleEnvError) as exc:
        outcome.error = str(exc)
    return outcome


def print_table(outcomes: list[CaseOutcome], failures_only: bool) -> None:
    rows: list[tuple[str, str, str, str]] = []
    for o in outcomes:
        if o.error is not None:
            rows.append(("ERROR", o.case_label, "-", o.error))
            continue
        for r in o.results:
            if failures_only and r.ok:
                continue
            rows.append(("PASS" if r.ok else "FAIL", o.case_label, r.name, r.detail))
    if not rows:
        return
    w_case = max(len("CASE"), *(len(r[1]) for r in rows))
    w_check = max(len("CHECK"), *(len(r[2]) for r in rows))
    print(f"{'RESULT':<6}  {'CASE':<{w_case}}  {'CHECK':<{w_check}}  DETAIL")
    for status, case, check, detail in rows:
        print(f"{status:<6}  {case:<{w_case}}  {check:<{w_check}}  {detail}".rstrip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_suite.py",
        description="Run the Folioxide oracle checks for every <name>.pdf + <name>.expect.json.",
    )
    parser.add_argument("dirs", nargs="+", type=Path, metavar="DIR")
    parser.add_argument("--trust-root", type=Path, action="append", default=[],
                        help="trust anchor (PEM) for every case's signature checks; repeatable")
    parser.add_argument("--failures-only", action="store_true", help="print only FAIL and ERROR rows")
    parser.add_argument("--json-report", type=Path, help="also write the results as JSON")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse exits 2 on usage errors already; keep its code
        return int(exc.code) if isinstance(exc.code, int) else EXIT_ENV

    for d in args.dirs:
        if not d.is_dir():
            print(f"error: not a directory: {d}", file=sys.stderr)
            return EXIT_ENV
    for root in args.trust_root:
        if not root.is_file():
            print(f"error: no such trust root: {root}", file=sys.stderr)
            return EXIT_ENV

    cases, outcomes = discover(args.dirs)
    if not cases and not outcomes:
        print(f"no oracle cases in {', '.join(d.as_posix() for d in args.dirs)}")
        return EXIT_OK
    outcomes.extend(run_case(case, args.trust_root) for case in cases)
    outcomes.sort(key=lambda o: o.case_label)

    print_table(outcomes, args.failures_only)
    counts = {s: sum(1 for o in outcomes if o.status == s) for s in ("PASS", "FAIL", "ERROR")}
    checks = sum(len(o.results) for o in outcomes)
    print(f"\noracle: {len(outcomes)} case(s), {checks} check(s): "
          f"{counts['PASS']} passed, {counts['FAIL']} failed, {counts['ERROR']} error(s)")

    if args.json_report is not None:
        report = [
            {"case": o.case_label, "status": o.status, "error": o.error,
             "checks": [r.to_json() for r in o.results]}
            for o in outcomes
        ]
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if counts["FAIL"]:
        return EXIT_FAIL
    return EXIT_ENV if counts["ERROR"] else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

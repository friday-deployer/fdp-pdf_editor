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

CLI::

    check_pdf.py FILE [--pages N] [--version 1.7] [--info Title=Text]... [--json]
"""

from __future__ import annotations

import argparse
import functools
import json
import re
import sys
from dataclasses import dataclass
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
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    args = parser.parse_args(argv)
    if not args.pdf.is_file():
        raise ExpectError(f"no such file: {args.pdf}")

    results = structure_checks(args.pdf)
    if args.pages is not None:
        results += check_pages(args.pdf, args.pages)
    if args.version is not None:
        results += check_version(args.pdf, args.version)
    if args.info:
        results += check_info(args.pdf, _parse_info(args.info))

    if args.json:
        print(json.dumps([r.to_json() for r in results], indent=2))
    else:
        print_results(results)
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())

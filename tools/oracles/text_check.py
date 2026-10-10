#!/usr/bin/env python3
"""Text oracle: ``pdftotext`` output contains, or lacks, given strings.

Both the extracted text and the needles are whitespace-normalised (every run of whitespace
becomes one space) before comparing, because ``pdftotext`` may break a phrase across lines.
A needle that is empty after normalisation is an expectation error.

CLI::

    text_check.py FILE [--contains TEXT]... [--absent TEXT]... [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

if str(Path(__file__).resolve().parent) not in sys.path:
    # `python -I` does not put the script directory on sys.path.
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from oracle_common import (  # noqa: E402
    CheckResult,
    ExpectError,
    cli,
    exit_code,
    failed,
    first_line,
    passed,
    print_results,
    run_tool,
    text,
)

_WS = re.compile(r"\s+")


def normalize(s: str) -> str:
    return _WS.sub(" ", s).strip()


def extract_text(path: Path) -> str:
    """Return the whole document text as decoded by ``pdftotext -enc UTF-8``."""
    proc = run_tool(["pdftotext", "-enc", "UTF-8", path, "-"])
    if proc.returncode != 0:
        raise RuntimeError(f"pdftotext exit {proc.returncode}: {first_line(proc.stderr)}")
    return text(proc.stdout)


def _needles(key: str, value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ExpectError(f"'{key}' must be a list of strings, got {value!r}")
    out = [normalize(v) for v in value]
    if any(not v for v in out):
        raise ExpectError(f"'{key}' contains an empty or whitespace-only string")
    return out


def check_text(
    path: Path, contains: Any = None, absent: Any = None
) -> list[CheckResult]:
    """Checks ``textContains`` / ``textAbsent``; either may be ``None`` (not requested)."""
    want = _needles("textContains", contains) if contains is not None else []
    avoid = _needles("textAbsent", absent) if absent is not None else []
    try:
        haystack = normalize(extract_text(path))
    except RuntimeError as exc:
        return [failed("text.pdftotext", str(exc))]
    results = []
    for needle in want:
        name = f"textContains[{needle!r}]"
        results.append(passed(name) if needle in haystack else failed(name, "not found by pdftotext"))
    for needle in avoid:
        name = f"textAbsent[{needle!r}]"
        results.append(passed(name) if needle not in haystack else failed(name, "found by pdftotext"))
    return results


@cli
def main(argv: list[str] | None = None) -> int:
    """Check that the extracted text of a PDF contains or lacks the given strings."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("pdf", type=Path)
    parser.add_argument("--contains", action="append", default=[])
    parser.add_argument("--absent", action="append", default=[])
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    args = parser.parse_args(argv)
    if not args.pdf.is_file():
        raise ExpectError(f"no such file: {args.pdf}")
    if not args.contains and not args.absent:
        raise ExpectError("give at least one --contains or --absent")
    results = check_text(args.pdf, args.contains or None, args.absent or None)
    if args.json:
        print(json.dumps([r.to_json() for r in results], indent=2))
    else:
        print_results(results)
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())

"""Shared plumbing for the Folioxide oracle scripts in ``tools/oracles``.

The oracles are dev-only cross-validation tools (docs/ARCHITECTURE.md §A.9). They run external
programs (poppler, OpenSSL) and Python libraries (pyHanko, pypdf, pikepdf) against PDFs that
Folioxide wrote, and report PASS/FAIL per check.

Exit codes shared by every CLI in this directory:

* ``0`` every check passed
* ``1`` at least one check failed
* ``2`` usage or environment error: a missing tool or module, a bad argument, or an expectation
  that cannot be evaluated (unknown or not-yet-implemented expect key)
"""

from __future__ import annotations

import contextlib
import dataclasses
import importlib
import logging
import shutil
import subprocess
import sys
import warnings
from collections.abc import Callable, Iterable, Iterator, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

#: Repository root (``tools/oracles/oracle_common.py`` -> ``<repo>``).
REPO_ROOT = Path(__file__).resolve().parents[2]

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_ENV = 2

#: Upper bound for any external tool run; a hung oracle must not hang CI.
TOOL_TIMEOUT_SECONDS = 300

SETUP_HINT = "run: bash tools/setup-venv.sh"


class OracleEnvError(Exception):
    """The environment cannot run a check: a tool or module is missing (exit code 2)."""


class ExpectError(Exception):
    """An expectation or argument is invalid or not implemented yet (exit code 2)."""


@dataclasses.dataclass(frozen=True)
class CheckResult:
    """Outcome of one named check."""

    name: str
    ok: bool
    detail: str = ""

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail}


def passed(name: str, detail: str = "") -> CheckResult:
    return CheckResult(name, True, detail)


def failed(name: str, detail: str) -> CheckResult:
    return CheckResult(name, False, detail)


def compare(name: str, expected: Any, actual: Any) -> CheckResult:
    """PASS when ``expected == actual``; the detail always shows both values."""
    detail = f"expected {expected!r}, got {actual!r}"
    return CheckResult(name, expected == actual, detail if expected != actual else repr(actual))


def require_tool(name: str) -> str:
    """Return the absolute path of an external tool or raise :class:`OracleEnvError`."""
    path = shutil.which(name)
    if path is None:
        hint = {
            "openssl": "install OpenSSL 3.x",
        }.get(name, "install poppler-utils (apt-get install poppler-utils)")
        raise OracleEnvError(f"required tool '{name}' not found on PATH; {hint}")
    return path


def run_tool(
    args: Sequence[str | Path], *, input_bytes: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    """Run an external tool without a shell and capture stdout and stderr as bytes."""
    exe = require_tool(str(args[0]))
    argv = [exe, *(str(a) for a in args[1:])]
    try:
        return subprocess.run(
            argv,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise OracleEnvError(f"{args[0]} timed out after {TOOL_TIMEOUT_SECONDS}s") from exc


def text(data: bytes) -> str:
    """Decode tool output; never fails on bad bytes."""
    return data.decode("utf-8", errors="replace")


def first_line(data: bytes | str, limit: int = 200) -> str:
    s = text(data) if isinstance(data, bytes) else data
    line = s.strip().splitlines()[0] if s.strip() else ""
    return line if len(line) <= limit else line[: limit - 3] + "..."


def import_module(name: str) -> ModuleType:
    """Import an oracle dependency or raise :class:`OracleEnvError` with the setup hint."""
    try:
        return importlib.import_module(name)
    except ImportError as exc:
        raise OracleEnvError(
            f"Python module '{name}' is not available ({exc}); {SETUP_HINT} "
            "and use .venv/bin/python"
        ) from exc


@contextlib.contextmanager
def captured_logs(*logger_names: str) -> Iterator[list[str]]:
    """Collect WARNING+ records of the named loggers (and Python warnings) instead of printing."""
    records: list[str] = []

    class _Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(f"{record.levelname}: {record.getMessage()}")

    handler = _Collector(level=logging.WARNING)
    saved = []
    for name in logger_names:
        logger = logging.getLogger(name)
        saved.append((logger, logger.propagate))
        logger.addHandler(handler)
        logger.propagate = False
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            yield records
        records.extend(f"warning: {w.message}" for w in caught)
    finally:
        for logger, propagate in saved:
            logger.removeHandler(handler)
            logger.propagate = propagate


def resolve_path(value: str, base_dir: Path) -> Path:
    """Resolve a path from an expectation file.

    Absolute paths are used as is. A relative path is tried against ``base_dir`` (the directory
    of the expect.json) first and then against the repository root, so both ``input.pdf`` next
    to the case and ``fixtures/pki/root.pem`` work.
    """
    candidate = Path(value)
    if candidate.is_absolute():
        if not candidate.exists():
            raise ExpectError(f"path does not exist: {value}")
        return candidate
    for base in (base_dir, REPO_ROOT):
        resolved = base / candidate
        if resolved.exists():
            return resolved
    raise ExpectError(f"path '{value}' exists neither next to the case ({base_dir}) nor in {REPO_ROOT}")


def exit_code(results: Iterable[CheckResult]) -> int:
    return EXIT_OK if all(r.ok for r in results) else EXIT_FAIL


def print_results(results: Iterable[CheckResult], stream: Any = None) -> None:
    out = stream if stream is not None else sys.stdout
    rows = list(results)
    width = max((len(r.name) for r in rows), default=10)
    for r in rows:
        status = "PASS" if r.ok else "FAIL"
        detail = f"  {r.detail}" if r.detail else ""
        print(f"{status}  {r.name.ljust(width)}{detail}".rstrip(), file=out)


def cli(main: Callable[[list[str] | None], int]) -> Callable[[list[str] | None], int]:
    """Wrap a CLI ``main`` so environment and expectation errors exit with code 2."""

    def wrapper(argv: list[str] | None = None) -> int:
        try:
            return main(argv)
        except (OracleEnvError, ExpectError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ENV

    wrapper.__doc__ = main.__doc__
    wrapper.__name__ = main.__name__
    return wrapper

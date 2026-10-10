#!/usr/bin/env python3
"""Generate or check the qpdf-written fixtures in fixtures/qpdf/ (fixtures/README.md).

Usage, from anywhere, with the oracle venv (bash tools/setup-venv.sh):

    .venv/bin/python -I tools/fixtures/qpdf.py            write fixtures/qpdf/*.pdf
    .venv/bin/python -I tools/fixtures/qpdf.py --check    compare with the committed files

`cargo xtask fixtures [--check]` runs it too when the venv exists (ARCHITECTURE §A.9, "Fixtures
policy": tools/fixtures/*.py make the fixtures that need pikepdf).

These files have layouts that real writers produce and our own byte-level builder does not:
qpdf's linearization (ISO 32000-2 Annex F) with a first-page cross-reference section near the
start of the file and the main section at the end. Every file is a three-page document built
here with pikepdf and saved by libqpdf with `linearize=True` and a deterministic /ID, once with
cross-reference tables and once with object streams and cross-reference streams.

qpdf's output is deterministic for a given qpdf version, so --check regenerates the files in
memory and compares them byte for byte, and also asks qpdf to check each committed file's
linearization. Both modes need the pikepdf and libqpdf versions the committed files were made
with (PIKEPDF and LIBQPDF below, the pins of tools/requirements-dev.txt); with other versions
the script exits 2 without writing or comparing. When the pins change, update the constants and
regenerate the files in the same change.

Exit codes: 0 success, 1 a committed file differs or is not linearized, 2 a usage or
environment error (pikepdf missing, other versions).
"""

from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = REPO_ROOT / "fixtures" / "qpdf"

#: The versions the committed files were written with (tools/requirements-dev.txt).
PIKEPDF = "10.16.0"
LIBQPDF = "12.4.2"

#: The pages of every document: the text each content stream shows.
PAGES = 3


def document(name: str):
    """A new three-page document: a shared Helvetica font, one content stream per page, /Info."""
    import pikepdf
    from pikepdf import Array, Dictionary, Name, String

    pdf = pikepdf.new()
    font = pdf.make_indirect(
        Dictionary(Type=Name.Font, Subtype=Name.Type1, BaseFont=Name.Helvetica)
    )
    for page in range(1, PAGES + 1):
        content = pdf.make_stream(f"BT /F1 24 Tf 72 720 Td ({name}, page {page}) Tj ET".encode())
        pdf.pages.append(
            pikepdf.Page(
                Dictionary(
                    Type=Name.Page,
                    MediaBox=Array([0, 0, 612, 792]),
                    Resources=Dictionary(Font=Dictionary(F1=font)),
                    Contents=content,
                )
            )
        )
    pdf.docinfo = pdf.make_indirect(Dictionary(Title=String(f"Folioxide fixture {name}")))
    return pdf


def cases():
    """The fixture name and the pikepdf save options for each committed file."""
    import pikepdf

    return {
        # Cross-reference tables: the first-page section is followed by `startxref 0 %%EOF`.
        "linearized": {"object_stream_mode": pikepdf.ObjectStreamMode.disable},
        # Object streams and cross-reference streams (PDF 1.5).
        "linearized-objstm": {"object_stream_mode": pikepdf.ObjectStreamMode.generate},
    }


def generate(name: str, options: dict) -> bytes:
    out = io.BytesIO()
    document(name).save(out, linearize=True, deterministic_id=True, **options)
    return out.getvalue()


def linearization_ok(data: bytes) -> list[str]:
    """Problems qpdf finds with the linearization of `data` (none for a good file)."""
    import pikepdf

    with pikepdf.open(io.BytesIO(data)) as pdf:
        if not pdf.is_linearized:
            return ["not linearized"]
        report = io.StringIO()
        if not pdf.check_linearization(stream=report):
            return [report.getvalue().strip() or "check_linearization() failed"]
        if len(pdf.pages) != PAGES:
            return [f"{len(pdf.pages)} pages, expected {PAGES}"]
    return []


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="compare, do not write")
    args = parser.parse_args(argv)
    try:
        import pikepdf
    except ImportError:
        print("qpdf fixtures: pikepdf is not installed; run bash tools/setup-venv.sh",
              file=sys.stderr)
        return 2
    have = (pikepdf.__version__, pikepdf.__libqpdf_version__)
    if have != (PIKEPDF, LIBQPDF):
        print(f"qpdf fixtures: need pikepdf {PIKEPDF} with libqpdf {LIBQPDF} (the committed "
              f"files were written with them), found pikepdf {have[0]} with libqpdf {have[1]}",
              file=sys.stderr)
        return 2

    failures = []
    written = 0
    names = cases()
    for name, options in names.items():
        path = OUT_DIR / f"{name}.pdf"
        data = generate(name, options)
        if args.check:
            try:
                committed = path.read_bytes()
            except OSError as err:
                failures.append(f"{path.relative_to(REPO_ROOT)}: {err}")
                continue
            if committed != data:
                failures.append(f"{path.relative_to(REPO_ROOT)} differs from the generated bytes")
            failures.extend(f"{path.relative_to(REPO_ROOT)}: {problem}"
                            for problem in linearization_ok(committed))
        else:
            problems = linearization_ok(data)
            if problems:
                failures.extend(f"{name}: {problem}" for problem in problems)
                continue
            OUT_DIR.mkdir(parents=True, exist_ok=True)
            if not path.is_file() or path.read_bytes() != data:
                path.write_bytes(data)
                written += 1
                print(f"qpdf fixtures: wrote {path.relative_to(REPO_ROOT)} ({len(data)} bytes)")
    stale = sorted(p.name for p in OUT_DIR.glob("*.pdf") if p.stem not in names)
    failures.extend(f"fixtures/qpdf/{file} is not produced by this script" for file in stale)
    for failure in failures:
        print(f"qpdf fixtures: FAIL {failure}")
    if failures:
        return 1
    if args.check:
        print(f"qpdf fixtures: {len(names)} files in fixtures/qpdf match pikepdf {PIKEPDF} "
              f"(libqpdf {LIBQPDF})")
    else:
        print(f"qpdf fixtures: fixtures/qpdf: {written} written, {len(names) - written} unchanged "
              f"(pikepdf {PIKEPDF}, libqpdf {LIBQPDF})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""Shared helpers for the oracle self-tests.

Run the suite with::

    .venv/bin/python -I -m unittest discover -s tools/oracles/tests

The self-tests prove that the oracles work before Folioxide has its own writer or signer: the
PDFs come from hand-written bytes (``pdfgen.py``) and the signatures from pyHanko with the
committed test PKI (``fixtures/pki``). Everything they write goes to temporary directories.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

TESTS_DIR = Path(__file__).resolve().parent
ORACLES_DIR = TESTS_DIR.parent
REPO_ROOT = ORACLES_DIR.parents[1]
PKI = REPO_ROOT / "fixtures" / "pki"
PASSWORD = b"folioxide"

for path in (ORACLES_DIR, TESTS_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import pdfgen  # noqa: E402

#: How each fixture signer is loaded, so every key format in fixtures/pki gets exercised.
SIGNER_SOURCES = {
    "signer-rsa2048": "encrypted-pem",  # signer-rsa2048.key.enc.pem + password
    "signer-rsa3072": "pem",
    "signer-p256": "p12",  # signer-p256-modern.p12
    "signer-p384": "pem",
    "expired": "pem",
}


def load_signer(name: str) -> Any:
    """A pyHanko SimpleSigner for one of the fixture identities."""
    from pyhanko.sign import signers

    source = SIGNER_SOURCES[name]
    if source == "p12":
        return signers.SimpleSigner.load_pkcs12(str(PKI / f"{name}-modern.p12"), passphrase=PASSWORD)
    key = PKI / (f"{name}.key.enc.pem" if source == "encrypted-pem" else f"{name}.key.pem")
    signer = signers.SimpleSigner.load(
        str(key),
        str(PKI / f"{name}.pem"),
        ca_chain_files=(str(PKI / "intermediate.pem"),),
        key_passphrase=PASSWORD if source == "encrypted-pem" else None,
    )
    if signer is None:
        raise RuntimeError(f"pyHanko could not load signer {name}")
    return signer


def dummy_tsa(identity: str = "tsa") -> Any:
    """An in-process RFC 3161 TSA backed by ``fixtures/pki/<identity>.pem`` (no network)."""
    from pyhanko.keys import load_cert_from_pemder, load_private_key_from_pemder
    from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper

    return DummyTimeStamper(
        tsa_cert=load_cert_from_pemder(str(PKI / f"{identity}.pem")),
        tsa_key=load_private_key_from_pemder(str(PKI / f"{identity}.key.pem"), passphrase=None),
    )


def sign(
    data: bytes,
    signer: str = "signer-rsa2048",
    *,
    field: str = "Signature1",
    pades: bool = True,
    timestamp: bool = False,
) -> bytes:
    """Append a signature revision to ``data`` with pyHanko."""
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields, signers

    meta = signers.PdfSignatureMetadata(
        field_name=field,
        subfilter=fields.SigSeedSubFilter.PADES if pades else fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
    )
    writer = IncrementalPdfFileWriter(io.BytesIO(data))
    out = signers.sign_pdf(writer, meta, signer=load_signer(signer),
                           timestamper=dummy_tsa() if timestamp else None)
    return out.getvalue()


def doc_timestamp(data: bytes, field: str = "DocTimeStamp1", tsa: str = "tsa") -> bytes:
    """Append an ETSI.RFC3161 document timestamp revision with pyHanko (TSA identity ``tsa``)."""
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers

    stamper = signers.PdfTimeStamper(timestamper=dummy_tsa(tsa), field_name=field)
    out = io.BytesIO()
    stamper.timestamp_pdf(IncrementalPdfFileWriter(io.BytesIO(data)), md_algorithm="sha256", output=out)
    return out.getvalue()


@contextlib.contextmanager
def temp_dir() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="folioxide-oracle-test-") as tmp:
        yield Path(tmp)


def write_case(directory: Path, name: str, pdf: bytes, expect: dict[str, Any] | str) -> Path:
    """Write ``<name>.pdf`` and ``<name>.expect.json`` (a str is written verbatim)."""
    directory.mkdir(parents=True, exist_ok=True)
    pdf_path = directory / f"{name}.pdf"
    pdf_path.write_bytes(pdf)
    body = expect if isinstance(expect, str) else json.dumps(expect, indent=2)
    (directory / f"{name}.expect.json").write_text(body, encoding="utf-8")
    return pdf_path


def offset_in_first_range(pdf: bytes, needle: bytes = b"Hello Folioxide") -> int:
    """Offset of a harmless byte (inside page text) that every signature covers."""
    return pdf.index(needle)


# --------------------------------------------------------------------------------------------
# Crafted structural defects in a pyHanko-signed file (one signature, field Signature1)
# --------------------------------------------------------------------------------------------


def _gap(data: bytes) -> tuple[int, int]:
    """(start, end) of the last signature's ByteRange gap, ``<`` and ``>`` included."""
    o1, l1, o2, _ = map(int, re.findall(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", data)[-1])
    return o1 + l1, o2


def nonzero_padding(data: bytes) -> bytes:
    """Turn the last zero hex digit of /Contents into ``1``: outside the signed bytes, so only
    the padding rule is broken (the gap still equals /Contents, the CMS still verifies)."""
    _, end = _gap(data)
    if data[end - 2 : end] != b"0>":
        raise AssertionError("expected zero padding at the end of /Contents")
    return data[: end - 2] + b"1" + data[end - 1 :]


def byte_range_from_one(data: bytes) -> bytes:
    """Rewrite ``/ByteRange [0 l1 ...`` as ``[1 l1-1 ...`` (same gap, same file length)."""
    match = list(re.finditer(rb"/ByteRange\s*\[\s*0\s+(\d+)", data))[-1]
    new = b"/ByteRange [1 %d" % (int(match.group(1)) - 1)
    if len(new) > len(match.group(0)):
        raise AssertionError("cannot keep the file length")
    return data[: match.start()] + new.ljust(len(match.group(0))) + data[match.end() :]


def shadowed_contents(data: bytes) -> bytes:
    """Append an update that redefines the signature dictionary with a /Contents one zero byte
    shorter: same CMS, same ByteRange, but the gap is no longer the dictionary's /Contents (the
    "shadow" trick of docs/ARCHITECTURE.md §A.10 #14)."""
    import pypdf

    field = pypdf.PdfReader(io.BytesIO(data)).trailer["/Root"]["/AcroForm"]["/Fields"][0].get_object()
    num = field.raw_get("/V").idnum
    start = list(re.finditer(rb"(?<!\d)%d 0 obj" % num, data))[-1].start()
    body = data[data.index(b"<<", start) : data.index(b"endobj", start)].rstrip()
    gap_start, gap_end = _gap(data)
    contents = data[gap_start:gap_end]
    if contents not in body or not contents.endswith(b"00>"):
        raise AssertionError("the signature dictionary does not hold the gap's /Contents")
    return pdfgen.append_update(data, {num: body.replace(contents, contents[:-3] + b">")})


__all__ = [
    "ORACLES_DIR",
    "PKI",
    "REPO_ROOT",
    "byte_range_from_one",
    "doc_timestamp",
    "nonzero_padding",
    "offset_in_first_range",
    "pdfgen",
    "shadowed_contents",
    "sign",
    "temp_dir",
    "write_case",
]

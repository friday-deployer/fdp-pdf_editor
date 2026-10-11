#!/usr/bin/env python3
"""Extract each signature's CMS blob and signed bytes so OpenSSL can verify them independently.

For every signature dictionary reachable from ``/AcroForm /Fields`` (ISO 32000-2 §12.7.4,
§12.8.1) this reads ``/ByteRange [o1 l1 o2 l2]`` and slices the file itself:

* the signed bytes are ``file[o1:o1+l1] + file[o2:o2+l2]``
* the CMS is the hex string in the gap ``file[o1+l1:o2]``, which must be exactly ``<...>``.
  It is hex-decoded and cut to the length of its outer DER (or BER) element; whatever follows
  must be zero padding.

``SignatureBlob.structure_checks`` turns the structural findings into PASS/FAIL rows, which
both this CLI and the suite (``validate_sig.py``) enforce for every signature:

* ``byteRange``: the first range starts at offset 0 (§12.8.1: a signature covers its whole
  revision except the ``/Contents`` value)
* ``gap``: the gap is the ``/Contents`` value of the parsed signature dictionary, so a ByteRange
  that points at a different hex string (a "signature wrapping" or shadow trick) is reported
* ``padding``: only zero bytes follow the CMS element inside ``/Contents``

``openssl_verify`` then runs, depending on ``/SubFilter``::

    openssl cms -verify -binary -inform DER -in sig.der -content signed.bin \\
        -CAfile root.pem -purpose any -out /dev/null           # CMS signatures
    openssl ts -verify -data signed.bin -in sig.der -token_in -CAfile root.pem   # ETSI.RFC3161

Without a CA file it checks only the digest and the signature value: ``cms -verify -noverify``,
or, for a document timestamp, ``ts -verify -partial_chain`` anchored at the certificates the
token itself embeds (``ts -verify`` has no ``-noverify``).

CLI::

    extract_cms.py FILE [--out-dir DIR] [--verify [--ca-file root.pem] [--certfile chain.pem]]
    # exit 0 when every signature passes the structural checks (and --verify)

With ``--out-dir`` it writes, per signature ``N`` (1-based): ``sigN.der`` (CMS), ``sigN.signed.bin``
(signed bytes), ``sigN.sigvalue.bin`` (the SignerInfo signature octets, the data an RFC 3161
signature timestamp covers) and, if present, ``sigN.tst.der`` (the signature timestamp token).
"""

from __future__ import annotations

import argparse
import json
import os
import string
import sys
import tempfile
from dataclasses import dataclass, field
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
    exit_code,
    failed,
    first_line,
    import_module,
    passed,
    print_results,
    run_tool,
    text,
)

#: Nesting limit when walking the field tree and BER structures (hostile input guard).
MAX_DEPTH = 64

_HEX = frozenset(string.hexdigits.encode())
#: Hex digits plus the PDF white-space characters (ISO 32000-2 §7.2.3, Table 1).
_HEX_OR_WS = _HEX | frozenset(b" \t\r\n\f\x00")


class ExtractionError(Exception):
    """The file's signature structure is malformed (a check FAIL, not an environment error)."""


@dataclass
class SignatureBlob:
    """One signature dictionary with the bytes it covers."""

    index: int
    field_name: str | None
    sig_type: str | None
    sub_filter: str | None
    byte_range: tuple[int, int, int, int]
    cms_der: bytes
    signed_bytes: bytes
    #: Only zero bytes follow the CMS element inside ``/Contents``.
    trailing_padding_ok: bool
    #: The ByteRange gap is byte-for-byte the signature dictionary's ``/Contents``.
    contents_match_dict: bool
    #: What is wrong with the ByteRange itself (empty when it starts at offset 0).
    problems: list[str] = field(default_factory=list)
    #: The keys of the signature dictionary, e.g. ``{"/Type", "/M", "/Contents", ...}`` (for the
    #: PAdES checks of ``/M`` and ``/Cert``).
    dict_keys: frozenset[str] = frozenset()

    @property
    def is_doc_timestamp(self) -> bool:
        return self.sub_filter == "/ETSI.RFC3161" or self.sig_type == "/DocTimeStamp"

    def structure_checks(self, prefix: str | None = None) -> list[CheckResult]:
        """``byteRange``, ``gap`` and ``padding`` rows: what every signature must meet."""
        p = prefix or f"signatures[{self.index}]"
        return [
            failed(f"{p}.byteRange", "; ".join(self.problems))
            if self.problems
            else passed(f"{p}.byteRange", f"{list(self.byte_range)} starts at 0"),
            passed(f"{p}.gap", "matches /Contents")
            if self.contents_match_dict
            else failed(f"{p}.gap", "the ByteRange gap differs from the signature dictionary's /Contents"),
            passed(f"{p}.padding", "only zero bytes after the CMS")
            if self.trailing_padding_ok
            else failed(f"{p}.padding", "non-zero bytes after the CMS element"),
        ]

    def summary(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "field": self.field_name,
            "type": self.sig_type,
            "subFilter": self.sub_filter,
            "byteRange": list(self.byte_range),
            "cmsLength": len(self.cms_der),
            "signedLength": len(self.signed_bytes),
            "trailingPaddingOk": self.trailing_padding_ok,
            "contentsMatchDict": self.contents_match_dict,
            "problems": self.problems,
        }


# --------------------------------------------------------------------------------------------
# BER/DER length of the outer element
# --------------------------------------------------------------------------------------------


def _read_header(data: bytes, pos: int) -> tuple[int, int | None, bool]:
    """Return (content offset, content length or None for indefinite, constructed)."""
    if pos >= len(data):
        raise ExtractionError("truncated BER: missing tag")
    tag = data[pos]
    pos += 1
    if tag & 0x1F == 0x1F:  # high tag number form
        while True:
            if pos >= len(data):
                raise ExtractionError("truncated BER: tag")
            pos += 1
            if not data[pos - 1] & 0x80:
                break
    if pos >= len(data):
        raise ExtractionError("truncated BER: missing length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return pos, first, bool(tag & 0x20)
    if first == 0x80:
        if not tag & 0x20:
            raise ExtractionError("indefinite length on a primitive BER element")
        return pos, None, True
    n = first & 0x7F
    if n > 8 or pos + n > len(data):
        raise ExtractionError("bad BER length")
    return pos + n, int.from_bytes(data[pos : pos + n], "big"), bool(tag & 0x20)


def ber_element_length(data: bytes, pos: int = 0, depth: int = 0) -> int:
    """Total length of the BER/DER element at ``pos`` (supports indefinite lengths)."""
    if depth > MAX_DEPTH:
        raise ExtractionError("BER nesting too deep")
    content, length, _constructed = _read_header(data, pos)
    if length is not None:
        end = content + length
        if end > len(data):
            raise ExtractionError("BER element runs past the end of /Contents")
        return end - pos
    cur = content
    while True:  # indefinite: children until the end-of-contents octets 00 00
        if data[cur : cur + 2] == b"\x00\x00":
            return cur + 2 - pos
        cur += ber_element_length(data, cur, depth + 1)


# --------------------------------------------------------------------------------------------
# Locating signature dictionaries
# --------------------------------------------------------------------------------------------


def _signature_fields(reader: Any) -> list[tuple[str | None, Any]]:
    """(qualified field name, signature dictionary) for each signed /FT /Sig field."""
    generic = import_module("pypdf.generic")
    root = reader.trailer["/Root"].get_object()
    acroform = root.get("/AcroForm")
    if acroform is None:
        return []
    fields = acroform.get_object().get("/Fields")
    if fields is None:
        return []
    found: list[tuple[str | None, Any]] = []
    seen: set[tuple[int, int]] = set()

    def walk(items: Any, parent_name: str | None, inherited_ft: Any, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise ExtractionError("field tree nesting too deep")
        for item in items.get_object():
            if isinstance(item, generic.IndirectObject):
                key = (item.idnum, item.generation)
                if key in seen:
                    continue  # cycle or shared kid
                seen.add(key)
            node = item.get_object()
            if not isinstance(node, generic.DictionaryObject):
                continue
            partial = node.get("/T")
            name = parent_name
            if partial is not None:
                name = f"{parent_name}.{partial}" if parent_name else str(partial)
            ft = node.get("/FT", inherited_ft)  # /FT is inheritable (§12.7.4.1)
            value = node.get("/V")
            if ft == "/Sig" and value is not None:
                sig = value.get_object()
                if isinstance(sig, generic.DictionaryObject):
                    found.append((name, sig))
            kids = node.get("/Kids")
            if kids is not None:
                walk(kids, name, ft, depth + 1)

    walk(fields, None, None, 0)
    return found


def _string_bytes(obj: Any) -> bytes:
    """Raw bytes of a pypdf string object (pypdf may decode binary strings as text)."""
    if obj is None:
        return b""
    value = obj.get_object()
    if isinstance(value, bytes):
        return bytes(value)
    original = getattr(value, "original_bytes", None)
    if isinstance(original, bytes):
        return original
    return str(value).encode("latin-1", errors="replace")


def _int_byte_range(raw: Any) -> tuple[int, int, int, int]:
    values = list(raw.get_object()) if raw is not None else []
    if len(values) != 4 or not all(isinstance(v, int) and not isinstance(v, bool) for v in values):
        raise ExtractionError(f"/ByteRange must be 4 integers, got {values!r}")
    o1, l1, o2, l2 = (int(v) for v in values)
    return o1, l1, o2, l2


@dataclass(frozen=True)
class ExtractionFailure:
    """A signature field whose CMS and signed bytes could not be sliced out of the file."""

    field_name: str | None
    reason: str


def extract(path: Path) -> list[SignatureBlob]:
    """Find every signature and slice its CMS and signed bytes from the raw file.

    Raises :class:`ExtractionError` when the file cannot be read or any signature cannot be
    extracted; :func:`extract_all` reports the latter per field instead.
    """
    blobs, failures = extract_all(path)
    if failures:
        raise ExtractionError(failures[0].reason)
    return blobs


def extract_all(path: Path) -> tuple[list[SignatureBlob], list[ExtractionFailure]]:
    """Like :func:`extract`, but a signature that cannot be extracted (a ByteRange that is not 4
    integers or does not fit the file, a gap that is not a ``<hex>`` string) is returned as an
    :class:`ExtractionFailure` while the other signatures are still extracted.

    Raises :class:`ExtractionError` only when the signature fields cannot be read at all.
    """
    pypdf = import_module("pypdf")
    data = path.read_bytes()
    with captured_logs("pypdf"):
        try:
            reader = pypdf.PdfReader(path, strict=False)
            fields = _signature_fields(reader)
        except (ExtractionError, OracleEnvError):
            raise
        except Exception as exc:  # noqa: BLE001 - a file pypdf cannot read is a FAIL
            raise ExtractionError(f"cannot read the signature fields: {type(exc).__name__}: {exc}") from exc

        blobs: list[SignatureBlob] = []
        failures: list[ExtractionFailure] = []
        for name, sig in fields:
            try:
                blobs.append(_extract_one(data, name, sig))
            except OracleEnvError:
                raise
            except ExtractionError as exc:
                failures.append(ExtractionFailure(name, str(exc)))
            except Exception as exc:  # noqa: BLE001 - malformed objects are a FAIL, not a crash
                failures.append(ExtractionFailure(name, f"field {name!r}: {type(exc).__name__}: {exc}"))
    # Order of application: the signature covering the shortest prefix came first.
    blobs.sort(key=lambda b: b.byte_range[2] + b.byte_range[3])
    for i, blob in enumerate(blobs):
        blob.index = i
    return blobs, failures


def _extract_one(data: bytes, name: str | None, sig: Any) -> SignatureBlob:
    o1, l1, o2, l2 = _int_byte_range(sig.get("/ByteRange"))
    problems: list[str] = []
    if o1 != 0:
        problems.append(f"ByteRange starts at {o1}, not 0")
    gap_start, gap_end = o1 + l1, o2
    if min(o1, l1, o2, l2) < 0 or not gap_start < gap_end or o2 + l2 > len(data):
        raise ExtractionError(
            f"field {name!r}: ByteRange {[o1, l1, o2, l2]} is inconsistent with the file size {len(data)}"
        )
    gap = data[gap_start:gap_end]
    if len(gap) < 2 or gap[:1] != b"<" or gap[-1:] != b">":
        raise ExtractionError(f"field {name!r}: the ByteRange gap is not a <hex> string")
    hex_body = gap[1:-1]
    if not set(hex_body) <= _HEX_OR_WS:
        raise ExtractionError(f"field {name!r}: the ByteRange gap contains non-hex bytes")
    digits = bytes(b for b in hex_body if b in _HEX)
    if len(digits) % 2:
        digits += b"0"  # §7.3.4.3: an odd final digit is followed by an implied 0
    raw = bytes.fromhex(digits.decode("ascii"))
    length = ber_element_length(raw)
    cms_der, padding = raw[:length], raw[length:]
    contents_bytes = _string_bytes(sig.get("/Contents"))
    return SignatureBlob(
        index=0,
        field_name=name,
        sig_type=str(sig.get("/Type")) if sig.get("/Type") is not None else None,
        sub_filter=str(sig.get("/SubFilter")) if sig.get("/SubFilter") is not None else None,
        byte_range=(o1, l1, o2, l2),
        cms_der=cms_der,
        signed_bytes=data[o1 : o1 + l1] + data[o2 : o2 + l2],
        trailing_padding_ok=not padding.strip(b"\x00"),
        contents_match_dict=contents_bytes == raw,
        problems=problems,
        dict_keys=frozenset(str(key) for key in sig.keys()),
    )


# --------------------------------------------------------------------------------------------
# CMS details (asn1crypto)
# --------------------------------------------------------------------------------------------


def signer_info(cms_der: bytes) -> Any:
    """The single SignerInfo of a SignedData ContentInfo."""
    cms = import_module("asn1crypto.cms")
    content_info = cms.ContentInfo.load(cms_der)
    if content_info["content_type"].native != "signed_data":
        raise ExtractionError(f"CMS content type is {content_info['content_type'].native}, not signed_data")
    infos = content_info["content"]["signer_infos"]
    if len(infos) != 1:
        raise ExtractionError(f"expected exactly one SignerInfo, found {len(infos)}")
    return infos[0]


def signature_value(cms_der: bytes) -> bytes:
    """``SignerInfo.signature`` octets: what a signature timestamp's message imprint hashes."""
    return bytes(signer_info(cms_der)["signature"].native)


def embedded_certificates_pem(cms_der: bytes) -> bytes:
    """PEM of every certificate in a SignedData's ``certificates`` set (empty when none)."""
    cms = import_module("asn1crypto.cms")
    pem = import_module("asn1crypto.pem")
    certs = cms.ContentInfo.load(cms_der)["content"]["certificates"]
    return b"".join(
        pem.armor("CERTIFICATE", choice.chosen.dump()) for choice in (certs or []) if choice.name == "certificate"
    )


def timestamp_token(cms_der: bytes) -> bytes | None:
    """DER of the id-aa-signatureTimeStampToken unsigned attribute (RFC 3161 Appendix A)."""
    unsigned = signer_info(cms_der)["unsigned_attrs"]
    if not unsigned:
        return None
    for attr in unsigned:
        if attr["type"].native == "signature_time_stamp_token":
            return attr["values"][0].dump()
    return None


# --------------------------------------------------------------------------------------------
# OpenSSL verification
# --------------------------------------------------------------------------------------------


def _openssl_reason(proc: Any) -> str:
    """First meaningful line of a failed openssl run (``ts`` prints a config banner first)."""
    lines = [line for line in (text(proc.stderr) + "\n" + text(proc.stdout)).splitlines()
             if line.strip() and not line.startswith("Using configuration from")]
    return f"openssl exit {proc.returncode}: {first_line(lines[0]) if lines else 'no output'}"


def _ts_anchors(token_der: bytes, ca_file: Path | None, tmp: Path) -> tuple[list[str | Path], str]:
    """Trust-anchor arguments for ``openssl ts -verify`` and a label for the mode used.

    ``ts -verify`` has no ``-noverify``. Without ``ca_file`` the token's own certificates become
    the anchors with ``-partial_chain``, so OpenSSL still checks the message imprint, the TSA's
    signature, the ESS signing-certificate binding and the critical timeStamping EKU, but not
    the chain. Raises ExtractionError when the token embeds no usable certificate.
    """
    if ca_file is not None:
        return ["-CAfile", ca_file], "-CAfile"
    try:
        embedded = embedded_certificates_pem(token_der)
    except (ValueError, KeyError, TypeError) as exc:
        raise ExtractionError(f"cannot read the timestamp token's certificates: {exc}") from exc
    if not embedded:
        raise ExtractionError("the timestamp token embeds no certificate; a CA file is needed")
    anchors = tmp / "token-certs.pem"
    anchors.write_bytes(embedded)
    return ["-CAfile", anchors, "-partial_chain"], "-partial_chain (token certificates)"


def openssl_verify(
    blob: SignatureBlob,
    ca_file: Path | None,
    certfile: Path | None = None,
    name: str | None = None,
) -> CheckResult:
    """Verify one signature with OpenSSL: ``cms -verify`` or, for ``ETSI.RFC3161``, ``ts -verify``.

    With ``ca_file`` the signer chain must validate against it. Without it only the digest and
    the signature value are checked: ``cms -verify -noverify`` for a CMS signature, and
    ``ts -verify -partial_chain`` anchored at the token's own certificates for a document
    timestamp (``ts -verify`` has no ``-noverify``; the TSA EKU and the message imprint are still
    checked).
    """
    label = name or f"signatures[{blob.index}].openssl"
    with tempfile.TemporaryDirectory(prefix="folioxide-cms-") as tmp:
        sig_path = Path(tmp) / "sig.der"
        data_path = Path(tmp) / "signed.bin"
        sig_path.write_bytes(blob.cms_der)
        data_path.write_bytes(blob.signed_bytes)
        if blob.is_doc_timestamp:
            try:
                anchors, mode = _ts_anchors(blob.cms_der, ca_file, Path(tmp))
            except ExtractionError as exc:
                return failed(label, str(exc))
            args: list[str | Path] = ["openssl", "ts", "-verify", "-data", data_path, "-in", sig_path,
                                      "-token_in", *anchors]
            if certfile is not None:
                args += ["-untrusted", certfile]
        else:
            mode = "-CAfile" if ca_file is not None else "-noverify"
            args = ["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", sig_path,
                    "-content", data_path, "-purpose", "any", "-out", os.devnull]
            args += ["-CAfile", ca_file] if ca_file is not None else ["-noverify"]
            if certfile is not None:
                args += ["-certfile", certfile]
        proc = run_tool(args)
    output = text(proc.stdout) + text(proc.stderr)
    ok = proc.returncode == 0 and ("Verification successful" in output or "Verification: OK" in output)
    if ok:
        return passed(label, f"{mode}: verified")
    return failed(label, f"{mode}: {_openssl_reason(proc)}")


def openssl_ts_verify_signature_timestamp(
    blob: SignatureBlob, ca_file: Path | None, name: str | None = None
) -> CheckResult:
    """``openssl ts -verify -data sigvalue.bin -in token.der -token_in`` for a B-T signature.

    Without ``ca_file`` the chain is not checked (see ``_ts_anchors``).
    """
    label = name or f"signatures[{blob.index}].timestamp.openssl"
    try:
        token = timestamp_token(blob.cms_der)
    except (ExtractionError, ValueError, KeyError, TypeError) as exc:
        return failed(label, f"cannot read the CMS: {exc}")
    if token is None:
        return failed(label, "no signature timestamp token")
    with tempfile.TemporaryDirectory(prefix="folioxide-tst-") as tmp:
        try:
            anchors, mode = _ts_anchors(token, ca_file, Path(tmp))
        except ExtractionError as exc:
            return failed(label, str(exc))
        data_path = Path(tmp) / "sigvalue.bin"
        token_path = Path(tmp) / "token.der"
        data_path.write_bytes(signature_value(blob.cms_der))
        token_path.write_bytes(token)
        proc = run_tool(["openssl", "ts", "-verify", "-data", data_path, "-in", token_path,
                         "-token_in", *anchors])
    if proc.returncode == 0 and "Verification: OK" in text(proc.stdout) + text(proc.stderr):
        return passed(label, f"{mode}: Verification: OK")
    return failed(label, f"{mode}: {_openssl_reason(proc)}")


# --------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------


def write_blobs(blobs: list[SignatureBlob], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for blob in blobs:
        stem = out_dir / f"sig{blob.index + 1}"
        files = {
            Path(f"{stem}.der"): blob.cms_der,
            Path(f"{stem}.signed.bin"): blob.signed_bytes,
        }
        if not blob.is_doc_timestamp:
            files[Path(f"{stem}.sigvalue.bin")] = signature_value(blob.cms_der)
            token = timestamp_token(blob.cms_der)
            if token is not None:
                files[Path(f"{stem}.tst.der")] = token
        for path, content in files.items():
            path.write_bytes(content)
            written.append(path)
    return written


@cli
def main(argv: list[str] | None = None) -> int:
    """Extract (and optionally verify with OpenSSL) every signature's CMS and signed bytes."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("pdf", type=Path)
    parser.add_argument("--out-dir", type=Path, help="write sigN.der / sigN.signed.bin / ... here")
    parser.add_argument("--verify", action="store_true",
                        help="run openssl cms|ts -verify (without --ca-file: digest and signature value only)")
    parser.add_argument("--ca-file", type=Path, help="trust anchor(s) for --verify (PEM)")
    parser.add_argument("--certfile", type=Path, help="extra untrusted certificates (PEM)")
    parser.add_argument("--json", action="store_true", help="print a JSON summary")
    args = parser.parse_args(argv)
    if not args.pdf.is_file():
        raise ExpectError(f"no such file: {args.pdf}")

    try:
        blobs = extract(args.pdf)
    except ExtractionError as exc:
        print(f"FAIL  {exc}")
        return 1
    if args.out_dir is not None:
        for path in write_blobs(blobs, args.out_dir):
            print(f"wrote {path}", file=sys.stderr)

    results: list[CheckResult] = []
    for blob in blobs:
        results.extend(blob.structure_checks())
        if args.verify:
            results.append(openssl_verify(blob, args.ca_file, args.certfile))
            if not blob.is_doc_timestamp and timestamp_token(blob.cms_der) is not None:
                results.append(openssl_ts_verify_signature_timestamp(blob, args.ca_file))

    if args.json:
        print(json.dumps({"signatures": [b.summary() for b in blobs],
                          "results": [r.to_json() for r in results]}, indent=2))
    else:
        for blob in blobs:
            print(f"#{blob.index + 1} field={blob.field_name!r} subFilter={blob.sub_filter} "
                  f"byteRange={list(blob.byte_range)} cms={len(blob.cms_der)} bytes"
                  + (f" problems={blob.problems}" if blob.problems else ""))
        print_results(results)
        if not blobs:
            print("no signatures found")
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())

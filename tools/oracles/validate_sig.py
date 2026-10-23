#!/usr/bin/env python3
"""Signature oracle: pyHanko validation, cross-checked with ``pdfsig`` and OpenSSL.

pyHanko (``validate_pdf_signature`` / ``validate_pdf_timestamp``) reports per signature:
``intact`` (digest matches), ``valid`` (cryptographic signature verifies), ``trusted`` (a path to
one of the trust roots validates; needs trust roots), ``coverage`` (entireFile, entireRevision,
contiguousBlockFromStart, unclear), ``modification`` (none, ltaUpdates, formFilling, annotations,
other; ``null`` when pyHanko cannot tell), ``docmdp`` (the certification level P, 1-3, or
``null``), ``docmdpOk``, ``timestamp`` (a signature timestamp token is present and valid) and
``timestampTrusted`` (pyHanko's ``timestamp_validity.trusted``; needs trust roots).

``timestamp`` takes three values (M4 brief D-22): ``true`` (pyHanko's token is intact and valid,
and ``openssl ts -verify`` of the token over the signature value succeeds), ``false`` (no token)
and ``"invalid"`` (a token is present, pyHanko's token is not intact and valid, **and** ``openssl
ts -verify`` fails).

An expectation entry describes a good signature unless it says otherwise: ``intact`` and
``valid`` default to ``true``. A tamper case sets ``"intact": false`` (pyHanko still reports
``valid: true`` for a document changed after signing, because the signature over the signed
attributes still verifies). The other keys are checked only when given.

Every entry, even ``{"field": "Signature1"}``, also runs these independent checks:

* structure (``extract_cms.py``): the ByteRange starts at offset 0, its gap is the dictionary's
  own ``/Contents`` (no signature wrapping) and only zero padding follows the CMS. These must
  pass whatever else the entry expects
* ``pdfsig -nocert`` (poppler/NSS), for signatures (poppler cannot validate RFC 3161 document
  timestamps): it must say "Signature is Valid." exactly when ``intact`` and ``valid`` are both
  expected
* OpenSSL (``extract_cms.py``): ``openssl cms -verify`` (``openssl ts -verify`` for a document
  timestamp) over the extracted CMS and byte ranges must succeed exactly when ``intact`` and
  ``valid`` are both expected. With ``trusted: true`` it also validates the chain against the
  trust roots (``-CAfile``); otherwise it checks only the digest and the signature value.
  ``timestamp: true`` adds ``openssl ts -verify`` of the signature timestamp token, against the
  trust roots when there are any

Expectation entries are matched to signatures by ``field`` when given, otherwise by position
(signatures are ordered by the end of their byte range, i.e. in signing order). The number of
entries must equal the number of signatures.

**A file pyHanko cannot read** (it raises while reading the cross-reference data) gives one
``signatures.pyhanko`` FAIL row instead of the per-signature pyHanko rows, and the independent
checks above (structure, ``pdfsig``, OpenSSL, ``pades``) still run for every entry, matched by
``field``. A case whose file is deliberately unreadable for pyHanko (an attack that a lenient
reader repairs) lists ``signatures.pyhanko`` in ``knownFailures`` and still has its ``intact`` /
``valid`` expectation checked by pdfsig and OpenSSL.

**Negative cases** (M3 brief D-3): ``{"field": "Signature1", "rejected": true}`` expects every
oracle to reject that signature, and takes no other key. It passes when

* pyHanko raises (reading the file, listing its signatures or validating this one), does not
  list the field, or reports ``intact`` or ``valid`` false for it (``rejected.pyhanko``);
* ``pdfsig -nocert`` does not print "Signature is Valid." for it (it fails, does not list the
  field, or prints another verdict; ``rejected.pdfsig``); and
* the OpenSSL route fails: the CMS and the signed bytes cannot be extracted from the signature
  dictionary (no usable ``/ByteRange``, a gap that is not a ``<hex>`` string or not the
  dictionary's own ``/Contents``, a ByteRange that does not start at 0), or
  ``openssl cms -verify -noverify`` (``ts -verify`` for a document timestamp) fails
  (``rejected.openssl``).

The structure rows (``byteRange``, ``gap``, ``padding``) are not reported for a rejected entry:
a failing one counts as an extraction failure. When an expectation list has a rejected entry,
every entry must name its ``field`` (unless there is only one), and the counts only require
that the oracles list no more signatures than there are entries (a broken signature may not be
listed at all).

CLI::

    validate_sig.py FILE [--trust-root PEM]... [--json]
    # exit 0 when every signature is intact and valid (and trusted, when roots are given)
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

if str(Path(__file__).resolve().parent) not in sys.path:
    # `python -I` does not put the script directory on sys.path.
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from extract_cms import (  # noqa: E402
    ExtractionError,
    ExtractionFailure,
    SignatureBlob,
    extract_all,
    openssl_ts_verify_signature_timestamp,
    openssl_verify,
    timestamp_token,
)
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
from pades_profile import check_pades, profile  # noqa: E402

#: Keys allowed inside one ``signatures[]`` expectation entry.
SIGNATURE_KEYS = frozenset(
    {"field", "intact", "valid", "trusted", "coverage", "modification", "docmdp", "docmdpOk",
     "pades", "timestamp", "timestampTrusted", "rejected"}
)

#: The keys a ``"rejected": true`` entry may have besides ``rejected`` (M3 brief D-3).
REJECTED_KEYS = frozenset({"field", "rejected"})

#: What an entry expects when it does not say: an intact, cryptographically valid signature.
DEFAULTS = {"intact": True, "valid": True}

_LOGGERS = ("pyhanko", "pyhanko_certvalidator", "pypdf")

#: Accepted spellings that differ from pyHanko's enum names (after normalisation).
_ALIASES = {"wholefile": "entirefile", "revision": "entirerevision"}


def _norm(value: str) -> str:
    key = value.replace("_", "").replace("-", "").replace(" ", "").lower()
    return _ALIASES.get(key, key)


def _camel(enum_name: str) -> str:
    head, *rest = enum_name.lower().split("_")
    return head + "".join(part.capitalize() for part in rest)


@dataclass
class SigStatus:
    """pyHanko's verdict on one signature, flattened to JSON-friendly values."""

    index: int
    field: str | None
    kind: str  # "signature" or "timestamp"
    sub_filter: str | None
    intact: bool
    valid: bool
    trusted: bool
    coverage: str | None
    modification: str | None
    docmdp: int | None
    docmdp_ok: bool | None
    timestamp: bool
    timestamp_valid: bool | None
    md_algorithm: str | None
    signer: str | None
    byte_range: list[int]
    #: pyHanko raised while validating this signature (``intact`` and ``valid`` are then false).
    error: str | None = None
    #: pyHanko's ``timestamp_validity.trusted`` for the signature timestamp, if there is one.
    timestamp_trusted: bool | None = None

    def to_json(self) -> dict[str, Any]:
        d = asdict(self)
        return {
            "index": d["index"], "field": d["field"], "kind": d["kind"], "subFilter": d["sub_filter"],
            "intact": d["intact"], "valid": d["valid"], "trusted": d["trusted"],
            "coverage": d["coverage"], "modification": d["modification"], "docmdp": d["docmdp"],
            "docmdpOk": d["docmdp_ok"], "timestamp": d["timestamp"],
            "timestampValid": d["timestamp_valid"], "timestampTrusted": d["timestamp_trusted"],
            "mdAlgorithm": d["md_algorithm"],
            "signer": d["signer"], "byteRange": d["byte_range"], "error": d["error"],
        }


def load_trust_roots(paths: list[Path]) -> list[Any]:
    keys = import_module("pyhanko.keys")
    roots: list[Any] = []
    for path in paths:
        try:
            roots.extend(keys.load_certs_from_pemder([str(path)]))
        except Exception as exc:  # noqa: BLE001
            raise ExpectError(f"cannot load trust root {path}: {exc}") from exc
    return roots


def validate(path: Path, trust_roots: list[Path]) -> list[SigStatus]:
    """Validate every signature and document timestamp with pyHanko."""
    reader_mod = import_module("pyhanko.pdf_utils.reader")
    validation = import_module("pyhanko.sign.validation")
    certvalidator = import_module("pyhanko_certvalidator")
    roots = load_trust_roots(trust_roots)

    def context() -> Any:
        # Never fetch anything: tests are offline. The test PKI has no CRLs or OCSP.
        return certvalidator.ValidationContext(trust_roots=roots, allow_fetching=False)

    statuses: list[SigStatus] = []
    with captured_logs(*_LOGGERS):
        reader = reader_mod.PdfFileReader(io.BytesIO(path.read_bytes()), strict=False)
        embedded, broken = _embedded_signatures(reader)
        embedded.sort(key=lambda s: s.byte_range[2] + s.byte_range[3])
        for i, sig in enumerate(embedded):
            is_ts = sig.sig_object_type == "/DocTimeStamp"
            try:
                if is_ts:
                    status = validation.validate_pdf_timestamp(sig, validation_context=context())
                else:
                    status = validation.validate_pdf_signature(sig, signer_validation_context=context())
            except (ExpectError, OracleEnvError):
                raise
            except Exception as exc:  # noqa: BLE001 - pyHanko rejected this signature
                statuses.append(_failed_status(i, sig, is_ts, f"{type(exc).__name__}: {exc}"))
                continue
            tst = getattr(status, "timestamp_validity", None)
            level = sig.docmdp_level
            modification = status.modification_level
            statuses.append(
                SigStatus(
                    index=i,
                    field=sig.field_name,
                    kind="timestamp" if is_ts else "signature",
                    sub_filter=str(sig.sig_object.get("/SubFilter")),
                    intact=bool(status.intact),
                    valid=bool(status.valid),
                    trusted=bool(status.trusted),
                    coverage=_camel(status.coverage.name) if status.coverage is not None else None,
                    modification=_camel(modification.name) if modification is not None else None,
                    docmdp=int(level.value) if level is not None else None,
                    docmdp_ok=status.docmdp_ok,
                    timestamp=tst is not None,
                    timestamp_valid=(bool(tst.intact and tst.valid) if tst is not None else None),
                    timestamp_trusted=(bool(tst.trusted) if tst is not None else None),
                    md_algorithm=status.md_algorithm,
                    signer=status.signing_cert.subject.human_friendly if status.signing_cert else None,
                    byte_range=list(sig.byte_range),
                )
            )
        # Signatures pyHanko could not even read come last, in field order.
        statuses.extend(_broken_status(field, error) for field, error in broken)
    for index, status in enumerate(statuses):
        status.index = index
    return statuses


def _embedded_signatures(reader: Any) -> tuple[list[Any], list[tuple[str | None, str]]]:
    """pyHanko's ``reader.embedded_signatures``, one signature at a time.

    ``collect_embedded_signatures`` (pdf_embedded.py) builds every ``EmbeddedPdfSignature`` at
    once, so one unreadable signature (a missing ``/Contents``, garbage CMS) makes the whole file
    unreadable. This does the same per field: the readable signatures are returned, and every
    field pyHanko raises on is returned as ``(field name, error)``. Signatures with a SubFilter
    pyHanko does not know are skipped, as pyHanko skips them.
    """
    fields_mod = import_module("pyhanko.sign.fields")
    embedded_mod = import_module("pyhanko.sign.validation.pdf_embedded")
    known = {str(sub.value) for sub in fields_mod.SigSeedSubFilter}
    embedded: list[Any] = []
    broken: list[tuple[str | None, str]] = []
    for fq_name, sig_obj, sig_field in fields_mod.enumerate_sig_fields(reader, filled_status=True):
        try:
            if str(sig_obj.get_object().get("/SubFilter", None)) not in known:
                continue
            sig = embedded_mod.EmbeddedPdfSignature(reader, sig_field, fq_name)
            _ = sig.signed_revision  # what pyHanko sorts by: the parse that may still fail
            embedded.append(sig)
        except (ExpectError, OracleEnvError):
            raise
        except Exception as exc:  # noqa: BLE001 - pyHanko rejected this signature
            broken.append((fq_name, f"{type(exc).__name__}: {exc}"))
    return embedded, broken


def _broken_status(field: str | None, error: str) -> SigStatus:
    """The status of a signature pyHanko could not read."""
    return SigStatus(index=-1, field=field, kind="signature", sub_filter=None, intact=False, valid=False,
                     trusted=False, coverage=None, modification=None, docmdp=None, docmdp_ok=None,
                     timestamp=False, timestamp_valid=None, md_algorithm=None, signer=None, byte_range=[],
                     error=error)


def _failed_status(index: int, sig: Any, is_ts: bool, error: str) -> SigStatus:
    """The status of a signature whose validation raised."""

    def attempt(read: Any, default: Any) -> Any:
        try:
            return read()
        except Exception:  # noqa: BLE001 - a broken signature dictionary
            return default

    return SigStatus(
        index=index,
        field=attempt(lambda: sig.field_name, None),
        kind="timestamp" if is_ts else "signature",
        sub_filter=attempt(lambda: str(sig.sig_object.get("/SubFilter")), None),
        intact=False,
        valid=False,
        trusted=False,
        coverage=None,
        modification=None,
        docmdp=None,
        docmdp_ok=None,
        timestamp=False,
        timestamp_valid=None,
        md_algorithm=None,
        signer=None,
        byte_range=attempt(lambda: list(sig.byte_range), []),
        error=error,
    )


@dataclass(frozen=True)
class PdfsigEntry:
    field: str | None
    validation: str
    total_document_signed: bool

    @property
    def is_valid(self) -> bool:
        return self.validation.startswith("Signature is Valid")


def pdfsig(path: Path) -> list[PdfsigEntry]:
    """Parse ``pdfsig -nocert`` output (one block per signature field, in file order)."""
    proc = run_tool(["pdfsig", "-nocert", path])
    out = text(proc.stdout)
    if proc.returncode != 0 and "does not contain any signatures" not in out + text(proc.stderr):
        raise RuntimeError(f"pdfsig exit {proc.returncode}: {first_line(proc.stderr)}")
    entries: list[PdfsigEntry] = []
    current: dict[str, Any] | None = None
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("Signature #"):
            if current is not None:
                entries.append(PdfsigEntry(**current))
            current = {"field": None, "validation": "", "total_document_signed": False}
        elif current is not None and stripped.startswith("- "):
            item = stripped[2:]
            key, sep, value = item.partition(":")
            if sep and key == "Signature Field Name":
                current["field"] = value.strip()
            elif sep and key == "Signature Validation":
                current["validation"] = value.strip()
            elif item == "Total document signed":
                current["total_document_signed"] = True
    if current is not None:
        entries.append(PdfsigEntry(**current))
    return entries


def _bundle(paths: list[Path], tmp: Path) -> Path | None:
    if not paths:
        return None
    bundle = tmp / "trust-roots.pem"
    bundle.write_bytes(b"\n".join(p.read_bytes() for p in paths))
    return bundle


def _validate_entry(entry: Any, i: int) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise ExpectError(f"signatures[{i}] must be an object, got {entry!r}")
    unknown = sorted(set(entry) - SIGNATURE_KEYS)
    if unknown:
        raise ExpectError(f"signatures[{i}]: unknown key(s) {unknown}; allowed: {sorted(SIGNATURE_KEYS)}")
    if "rejected" in entry and not isinstance(entry["rejected"], bool):
        raise ExpectError(f"signatures[{i}].rejected must be true or false")
    if entry.get("rejected") and set(entry) - REJECTED_KEYS:
        raise ExpectError(f"signatures[{i}]: a rejected entry takes only {sorted(REJECTED_KEYS)}, "
                          f"not {sorted(set(entry) - REJECTED_KEYS)}")
    for key in ("intact", "valid", "trusted", "timestampTrusted"):
        if key in entry and not isinstance(entry[key], bool):
            raise ExpectError(f"signatures[{i}].{key} must be true or false")
    if "timestamp" in entry and not (isinstance(entry["timestamp"], bool) or entry["timestamp"] == "invalid"):
        raise ExpectError(f"signatures[{i}].timestamp must be true, false or \"invalid\"")
    if "docmdpOk" in entry and entry["docmdpOk"] is not None and not isinstance(entry["docmdpOk"], bool):
        raise ExpectError(f"signatures[{i}].docmdpOk must be true, false or null")
    if "docmdp" in entry and entry["docmdp"] not in (None, 1, 2, 3):
        raise ExpectError(f"signatures[{i}].docmdp must be 1, 2, 3 or null")
    for key in ("field", "coverage"):
        if key in entry and not isinstance(entry[key], str):
            raise ExpectError(f"signatures[{i}].{key} must be a string")
    if "modification" in entry and entry["modification"] is not None and not isinstance(entry["modification"], str):
        raise ExpectError(f"signatures[{i}].modification must be a string or null")
    return entry


def check_signatures(path: Path, expected: Any, trust_roots: list[Path]) -> list[CheckResult]:
    """Evaluate a ``signatures`` expectation list against all oracles."""
    if not isinstance(expected, list):
        raise ExpectError("'signatures' must be a list of objects")
    entries = [_validate_entry(e, i) for i, e in enumerate(expected)]
    if any("trusted" in e or "timestampTrusted" in e for e in entries) and not trust_roots:
        raise ExpectError("'trusted' needs trust roots (so does 'timestampTrusted'): pass --trust-root or "
                          "set \"trustRoots\" in expect.json")
    rejected = [bool(e.get("rejected")) for e in entries]
    if any(rejected) and len(entries) > 1 and not all("field" in e for e in entries):
        raise ExpectError("with a 'rejected' entry, every signatures[] entry must name its 'field'")
    all_rejected = bool(entries) and all(rejected)

    # A file pyHanko cannot read is a FAIL (the row ``signatures.pyhanko``), unless every entry
    # expects a rejection. The independent oracles (structure, pdfsig, OpenSSL) still run on
    # every entry that is not a rejection, so a case that lists ``signatures.pyhanko`` in
    # ``knownFailures`` (pyHanko cannot read a deliberately broken file) still has its
    # ``intact``/``valid`` expectation checked by pdfsig and OpenSSL.
    pyhanko_error: str | None = None
    unreadable: CheckResult | None = None
    try:
        statuses = validate(path, trust_roots)
    except (ExpectError, OracleEnvError):
        raise
    except Exception as exc:  # noqa: BLE001
        statuses, pyhanko_error = [], f"pyHanko cannot read the file: {type(exc).__name__}: {exc}"
        if not all_rejected:
            unreadable = failed("signatures.pyhanko", f"{type(exc).__name__}: {exc}")
    head = [unreadable] if unreadable is not None else []
    extract_error: str | None = None
    try:
        blobs, failures = extract_all(path)
    except ExtractionError as exc:
        if not all_rejected:
            return head + [failed("signatures.extract", str(exc))]
        blobs, failures, extract_error = [], [], str(exc)

    found = len(blobs) + len(failures)
    if any(rejected):
        # A broken signature may not be listed at all; none may be listed beyond the entries.
        results = head + [
            CheckResult("signatures.count.pyhanko", len(statuses) <= len(entries),
                        f"{len(statuses)} listed, at most {len(entries)} expected"),
            CheckResult("signatures.count.fields", found <= len(entries),
                        f"{found} listed, at most {len(entries)} expected"),
        ]
    elif unreadable is not None:
        results = head + [compare("signatures.count.fields", len(entries), found)]
    else:
        results = [
            compare("signatures.count.pyhanko", len(entries), len(statuses)),
            compare("signatures.count.fields", len(entries), found),
        ]
        if len(statuses) != len(entries):
            return results

    by_field = {s.field: s for s in statuses}
    blob_by_field = {b.field_name: b for b in blobs}
    failure_by_field = {f.field_name: f for f in failures}
    try:
        pdfsig_entries: list[PdfsigEntry] | None = pdfsig(path)
        pdfsig_error = ""
    except RuntimeError as exc:
        pdfsig_entries, pdfsig_error = None, str(exc)
    pdfsig_by_field = {e.field: e for e in (pdfsig_entries or [])}

    with tempfile.TemporaryDirectory(prefix="folioxide-roots-") as tmp:
        ca_bundle = _bundle(trust_roots, Path(tmp))
        for i, entry in enumerate(entries):
            prefix = f"signatures[{i}]"
            if entry.get("rejected"):
                if "field" in entry:
                    name = entry["field"]
                else:  # the only entry: whatever the oracles list first
                    name = (statuses[0].field if statuses else blobs[0].field_name if blobs
                            else failures[0].field_name if failures else None)
                results.extend(_check_rejected(
                    prefix, name, by_field.get(name), pyhanko_error, blob_by_field.get(name),
                    failure_by_field.get(name), extract_error,
                    pdfsig_by_field if pdfsig_entries is not None else None, pdfsig_error))
                continue
            if unreadable is not None:
                # No pyHanko status: the independent oracles only, by field (or by position).
                if "field" in entry:
                    name = entry["field"]
                else:
                    name = blobs[i].field_name if i < len(blobs) else None
                blob = blob_by_field.get(name)
                failure = failure_by_field.get(name)
                kind = "timestamp" if blob is not None and blob.is_doc_timestamp else "signature"
                results.extend(_check_independent(
                    prefix, entry, name, kind, blob, ca_bundle,
                    pdfsig_by_field if pdfsig_entries is not None else None, pdfsig_error,
                    failure.reason if failure is not None else None))
                continue
            if "field" in entry:
                status = by_field.get(entry["field"])
                if status is None:
                    results.append(failed(f"signatures[{i}].field",
                                          f"no signature field {entry['field']!r}; have {sorted(map(str, by_field))}"))
                    continue
            else:
                status = statuses[i]
            blob = blob_by_field.get(status.field)
            failure = failure_by_field.get(status.field)
            results.extend(_check_one(prefix, entry, status, blob, ca_bundle,
                                      pdfsig_by_field if pdfsig_entries is not None else None, pdfsig_error,
                                      failure.reason if failure is not None else None))
    return results


def _check_rejected(
    prefix: str,
    name: str | None,
    status: SigStatus | None,
    pyhanko_error: str | None,
    blob: SignatureBlob | None,
    failure: ExtractionFailure | None,
    extract_error: str | None,
    pdfsig_by_field: dict[str | None, PdfsigEntry] | None,
    pdfsig_error: str,
) -> list[CheckResult]:
    """The rows of a ``"rejected": true`` entry: each oracle must reject the signature (D-3)."""
    results: list[CheckResult] = []

    # pyHanko: raises, does not list the field, or reports intact/valid false.
    if pyhanko_error is not None:
        results.append(passed(f"{prefix}.rejected.pyhanko", pyhanko_error))
    elif status is None:
        results.append(passed(f"{prefix}.rejected.pyhanko", f"pyHanko lists no signature field {name!r}"))
    elif status.error is not None:
        results.append(passed(f"{prefix}.rejected.pyhanko", f"pyHanko raises: {status.error}"))
    else:
        ok = not (status.intact and status.valid)
        results.append(CheckResult(f"{prefix}.rejected.pyhanko", ok,
                                   f"intact={status.intact} valid={status.valid}"
                                   + ("" if ok else "; expected a rejection")))

    # pdfsig: never "Signature is Valid." for this field.
    if pdfsig_by_field is None:
        results.append(passed(f"{prefix}.rejected.pdfsig", f"pdfsig fails: {pdfsig_error}"))
    else:
        entry = pdfsig_by_field.get(name)
        if entry is None:
            results.append(passed(f"{prefix}.rejected.pdfsig", f"pdfsig lists no field {name!r}"))
        else:
            results.append(CheckResult(f"{prefix}.rejected.pdfsig", not entry.is_valid,
                                       f"pdfsig: {entry.validation or 'no validation line'}"
                                       + ("; expected a rejection" if entry.is_valid else "")))

    # OpenSSL: extraction fails (structurally unusable signature) or the verification fails.
    label = f"{prefix}.rejected.openssl"
    if extract_error is not None:
        results.append(passed(label, f"extraction fails: {extract_error}"))
    elif failure is not None:
        results.append(passed(label, f"extraction fails: {failure.reason}"))
    elif blob is None:
        results.append(passed(label, f"extract_cms finds no signature dictionary for field {name!r}"))
    else:
        broken = [r for r in blob.structure_checks(prefix) if not r.ok and not r.name.endswith(".padding")]
        if broken:
            results.append(passed(label, "extraction fails: " + "; ".join(r.detail for r in broken)))
        else:
            run = openssl_verify(blob, None, name=label)
            results.append(CheckResult(label, not run.ok,
                                       run.detail if not run.ok else f"{run.detail}; expected a rejection"))
    return results


def _check_independent(
    prefix: str,
    entry: dict[str, Any],
    field: str | None,
    kind: str,
    blob: SignatureBlob | None,
    ca_bundle: Path | None,
    pdfsig_by_field: dict[str | None, PdfsigEntry] | None,
    pdfsig_error: str,
    extract_failure: str | None = None,
) -> list[CheckResult]:
    """The rows that do not depend on pyHanko: structure, pdfsig, OpenSSL and the PAdES profile.

    ``kind`` is ``"signature"`` or ``"timestamp"`` (poppler cannot validate RFC 3161 document
    timestamps, so they get no pdfsig row).
    """
    want = {key: entry.get(key, default) for key, default in DEFAULTS.items()}
    results: list[CheckResult] = []

    # Structure: no expectation can waive these (ByteRange from 0, gap == /Contents, zero padding).
    if blob is None:
        results.append(failed(f"{prefix}.extract", extract_failure or
                              f"extract_cms found no signature dictionary for field {field!r}"))
    else:
        results.extend(blob.structure_checks(prefix))

    # Cryptographic outcome that the independent oracles must agree on.
    expect_ok = want["intact"] and want["valid"]
    if kind == "signature":
        if pdfsig_by_field is None:
            results.append(failed(f"{prefix}.pdfsig", pdfsig_error))
        else:
            ps = pdfsig_by_field.get(field)
            if ps is None:
                results.append(failed(f"{prefix}.pdfsig", f"pdfsig lists no field {field!r}"))
            else:
                results.append(CheckResult(f"{prefix}.pdfsig", ps.is_valid == expect_ok,
                                           f"pdfsig: {ps.validation or 'no validation line'}"))
    if blob is not None:
        # The chain is checked against the trust roots only when trust is part of the expectation;
        # otherwise OpenSSL checks the digest and the signature value alone.
        use_ca = ca_bundle if entry.get("trusted") is True else None
        run = openssl_verify(blob, use_ca, name=f"{prefix}.openssl")
        results.append(CheckResult(run.name, run.ok == expect_ok,
                                   run.detail if run.ok == expect_ok
                                   else f"expected {'success' if expect_ok else 'failure'}; {run.detail}"))

    if "pades" in entry:
        if blob is None:
            results.append(failed(f"{prefix}.pades", "signature not found by extract_cms"))
        else:
            results.append(check_pades(f"{prefix}.pades", profile(blob), entry["pades"]))
    return results


def _check_one(
    prefix: str,
    entry: dict[str, Any],
    status: SigStatus,
    blob: SignatureBlob | None,
    ca_bundle: Path | None,
    pdfsig_by_field: dict[str | None, PdfsigEntry] | None,
    pdfsig_error: str,
    extract_failure: str | None = None,
) -> list[CheckResult]:
    want = {key: entry.get(key, default) for key, default in DEFAULTS.items()}
    if status.error is not None:
        results = [failed(f"{prefix}.pyhanko", f"pyHanko raises: {status.error}")]
    else:
        results = [compare(f"{prefix}.intact.pyhanko", want["intact"], status.intact),
                   compare(f"{prefix}.valid.pyhanko", want["valid"], status.valid)]
    for key, actual in (("trusted", status.trusted), ("docmdp", status.docmdp), ("docmdpOk", status.docmdp_ok)):
        if key in entry:
            results.append(compare(f"{prefix}.{key}.pyhanko", entry[key], actual))
    for key, actual in (("coverage", status.coverage), ("modification", status.modification)):
        if key in entry:
            want_value = entry[key]
            ok = (_norm(want_value) == _norm(actual) if want_value is not None and actual is not None
                  else want_value == actual)
            results.append(CheckResult(f"{prefix}.{key}.pyhanko", ok,
                                       repr(actual) if ok else f"expected {want_value!r}, got {actual!r}"))

    results.extend(_check_independent(prefix, entry, status.field, status.kind, blob, ca_bundle,
                                      pdfsig_by_field, pdfsig_error, extract_failure))

    if "timestamp" in entry:
        if entry["timestamp"] == "invalid":
            # D-22: a token is present, pyHanko's token is not intact and valid, and OpenSSL fails.
            ok = status.timestamp and status.timestamp_valid is False
            results.append(CheckResult(f"{prefix}.timestamp.pyhanko", ok,
                                       f"token present={status.timestamp}, valid={status.timestamp_valid}"
                                       + ("" if ok else "; expected an invalid token")))
            if blob is None:
                results.append(failed(f"{prefix}.timestamp.openssl", "signature not found by extract_cms"))
            else:
                run = openssl_ts_verify_signature_timestamp(blob, ca_bundle, f"{prefix}.timestamp.openssl")
                results.append(CheckResult(run.name, not run.ok,
                                           run.detail if not run.ok else f"{run.detail}; expected a failure"))
        elif entry["timestamp"]:
            ok = status.timestamp and bool(status.timestamp_valid)
            results.append(CheckResult(f"{prefix}.timestamp.pyhanko", ok,
                                       f"token present={status.timestamp}, valid={status.timestamp_valid}"))
            if blob is not None:  # without trust roots: imprint and TSA signature, no chain
                results.append(openssl_ts_verify_signature_timestamp(blob, ca_bundle,
                                                                     f"{prefix}.timestamp.openssl"))
        else:
            try:
                token = timestamp_token(blob.cms_der) if blob is not None and not blob.is_doc_timestamp else None
            except (ExtractionError, ValueError, KeyError, TypeError) as exc:  # malformed CMS: a FAIL
                results.append(failed(f"{prefix}.timestamp.pyhanko", f"cannot read the CMS: {exc}"))
            else:
                results.append(CheckResult(f"{prefix}.timestamp.pyhanko", not status.timestamp and token is None,
                                           f"token present={status.timestamp or token is not None}"))
    if "timestampTrusted" in entry:
        results.append(compare(f"{prefix}.timestampTrusted.pyhanko", entry["timestampTrusted"],
                               status.timestamp_trusted))
    return results


@cli
def main(argv: list[str] | None = None) -> int:
    """Validate every signature of a PDF and print pyHanko's and pdfsig's verdicts."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("pdf", type=Path)
    parser.add_argument("--trust-root", type=Path, action="append", default=[],
                        help="PEM/DER trust anchor (repeatable)")
    parser.add_argument("--json", action="store_true", help="print the statuses as JSON")
    args = parser.parse_args(argv)
    if not args.pdf.is_file():
        raise ExpectError(f"no such file: {args.pdf}")
    for root in args.trust_root:
        if not root.is_file():
            raise ExpectError(f"no such trust root: {root}")

    try:
        statuses = validate(args.pdf, args.trust_root)
    except (ExpectError, OracleEnvError):
        raise
    except Exception as exc:  # noqa: BLE001 - a file pyHanko cannot read is a FAIL
        print(f"FAIL  pyHanko could not read the file: {type(exc).__name__}: {exc}")
        return 1
    try:
        ps_by_field = {e.field: e for e in pdfsig(args.pdf)}
    except RuntimeError as exc:
        print(f"FAIL  {exc}")
        return 1

    results: list[CheckResult] = []
    for s in statuses:
        prefix = f"signatures[{s.index}]"
        ok = s.intact and s.valid and (s.trusted or not args.trust_root)
        results.append(CheckResult(f"{prefix}.pyhanko", ok,
                                   f"field={s.field!r} intact={s.intact} valid={s.valid} trusted={s.trusted} "
                                   f"coverage={s.coverage} modification={s.modification}"
                                   + (f" error={s.error}" if s.error else "")))
        if s.kind == "signature":
            ps = ps_by_field.get(s.field)
            results.append(CheckResult(f"{prefix}.pdfsig", ps is not None and ps.is_valid,
                                       f"pdfsig: {ps.validation if ps else 'field not listed'}"))
    if args.json:
        print(json.dumps([s.to_json() for s in statuses], indent=2))
    else:
        print_results(results)
        if not statuses:
            print("no signatures found")
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())

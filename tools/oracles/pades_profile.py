#!/usr/bin/env python3
"""PAdES baseline profile oracle (ETSI EN 319 142-1 §6.3; docs/ARCHITECTURE.md §A.6.3).

For each signature this parses the CMS with asn1crypto and reports:

* ``subFilter``: must be ``/ETSI.CAdES.detached``
* ``contentType``: the content-type signed attribute is present and equals id-data
* ``messageDigest``: the message-digest signed attribute is present
* ``signingCertificateV2``: the signing-certificate-v2 attribute (RFC 5035) is present, its first
  ESSCertIDv2 hashes the signer certificate, and a SHA-256 hashAlgorithm is omitted as DER
  requires for a DEFAULT value
* ``noSigningTime``: the signing-time attribute is absent (the claimed time lives in ``/M``)
* ``detached``: ``encapContentInfo`` has no eContent
* ``timestamp``: an id-aa-signatureTimeStampToken unsigned attribute is present (B-T)

``level`` is ``B-T`` when every B-B requirement holds and a timestamp token is present, ``B-B``
when every B-B requirement holds, and ``null`` otherwise. Document timestamps
(``/ETSI.RFC3161``) are reported with level ``null`` and skipped by the B-B checks.

CLI::

    pades_profile.py FILE [--json]     # exit 0 when every signature meets B-B
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

if str(Path(__file__).resolve().parent) not in sys.path:
    # `python -I` does not put the script directory on sys.path.
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from extract_cms import ExtractionError, SignatureBlob, extract  # noqa: E402
from oracle_common import (  # noqa: E402
    CheckResult,
    ExpectError,
    OracleEnvError,
    cli,
    compare,
    exit_code,
    failed,
    import_module,
    passed,
    print_results,
)

OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"
OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"
OID_SIGNATURE_TIMESTAMP = "1.2.840.113549.1.9.16.2.14"
OID_DATA = "1.2.840.113549.1.7.1"


@dataclass
class PadesReport:
    """PAdES-relevant facts about one signature."""

    index: int
    field: str | None
    sub_filter: str | None
    content_type: bool = False
    message_digest: bool = False
    signing_certificate_v2: bool = False
    no_signing_time: bool = False
    detached: bool = False
    timestamp: bool = False
    level: str | None = None
    problems: list[str] = field(default_factory=list)

    @property
    def is_baseline_b(self) -> bool:
        return self.level in ("B-B", "B-T")

    def to_json(self) -> dict[str, Any]:
        d = asdict(self)
        return {
            "index": d["index"],
            "field": d["field"],
            "subFilter": d["sub_filter"],
            "contentType": d["content_type"],
            "messageDigest": d["message_digest"],
            "signingCertificateV2": d["signing_certificate_v2"],
            "noSigningTime": d["no_signing_time"],
            "detached": d["detached"],
            "timestamp": d["timestamp"],
            "level": d["level"],
            "problems": d["problems"],
        }


def _asn1_types() -> Any:
    """asn1crypto 1.5 has no RFC 5035 types, so define the ones we need."""
    core = import_module("asn1crypto.core")
    algos = import_module("asn1crypto.algos")
    x509 = import_module("asn1crypto.x509")

    class IssuerSerial(core.Sequence):
        _fields = [("issuer", x509.GeneralNames), ("serial_number", core.Integer)]

    class ESSCertIDv2(core.Sequence):
        _fields = [
            ("hash_algorithm", algos.DigestAlgorithm, {"default": {"algorithm": "sha256"}}),
            ("cert_hash", core.OctetString),
            ("issuer_serial", IssuerSerial, {"optional": True}),
        ]

    class ESSCertIDv2s(core.SequenceOf):
        _child_spec = ESSCertIDv2

    class SigningCertificateV2(core.Sequence):
        _fields = [("certs", ESSCertIDv2s), ("policies", core.Any, {"optional": True})]

    return SigningCertificateV2


def _signer_certificate(signed_data: Any, sid: Any) -> Any | None:
    """The certificate in SignedData.certificates that ``sid`` names."""
    if sid.name == "issuer_and_serial_number":
        want_issuer = sid.chosen["issuer"]
        want_serial = sid.chosen["serial_number"].native
        for choice in signed_data["certificates"] or []:
            if choice.name != "certificate":
                continue
            cert = choice.chosen
            if cert.serial_number == want_serial and cert.issuer == want_issuer:
                return cert
    elif sid.name == "subject_key_identifier":
        want = sid.chosen.native
        for choice in signed_data["certificates"] or []:
            if choice.name == "certificate" and choice.chosen.key_identifier == want:
                return choice.chosen
    return None


def profile(blob: SignatureBlob) -> PadesReport:
    """Evaluate one signature against the PAdES baseline B-B/B-T requirements."""
    cms = import_module("asn1crypto.cms")
    report = PadesReport(index=blob.index, field=blob.field_name, sub_filter=blob.sub_filter)
    if blob.is_doc_timestamp:
        report.problems.append("document timestamp: not a PAdES signature")
        return report
    if blob.sub_filter != "/ETSI.CAdES.detached":
        report.problems.append(f"SubFilter is {blob.sub_filter}, not /ETSI.CAdES.detached")

    try:
        content_info = cms.ContentInfo.load(blob.cms_der)
        signed_data = content_info["content"]
        infos = signed_data["signer_infos"]
        if len(infos) != 1:
            report.problems.append(f"{len(infos)} SignerInfos (PAdES requires exactly one)")
            return report
        info = infos[0]
        eci = signed_data["encap_content_info"]
        report.detached = eci["content"].native is None
        if not report.detached:
            report.problems.append("encapContentInfo carries eContent (not detached)")
        if eci["content_type"].dotted != OID_DATA:
            report.problems.append(f"eContentType is {eci['content_type'].dotted}, not id-data")

        attrs = {a["type"].dotted: a for a in (info["signed_attrs"] or [])}
        ct = attrs.get(OID_CONTENT_TYPE)
        report.content_type = ct is not None and ct["values"][0].dump() == cms.ContentType("data").dump()
        if not report.content_type:
            report.problems.append("content-type attribute missing or not id-data")
        report.message_digest = OID_MESSAGE_DIGEST in attrs
        if not report.message_digest:
            report.problems.append("message-digest attribute missing")
        report.no_signing_time = OID_SIGNING_TIME not in attrs
        if not report.no_signing_time:
            report.problems.append("signing-time attribute present (PAdES puts the time in /M)")

        scv2 = attrs.get(OID_SIGNING_CERTIFICATE_V2)
        if scv2 is None:
            report.problems.append("signing-certificate-v2 attribute missing")
        else:
            report.signing_certificate_v2 = _check_signing_certificate_v2(
                scv2["values"][0].dump(), signed_data, info, report.problems
            )
        if OID_SIGNING_CERTIFICATE in attrs:
            report.problems.append("signing-certificate (v1, SHA-1) present; PAdES uses v2")

        unsigned = {a["type"].dotted for a in (info["unsigned_attrs"] or [])}
        report.timestamp = OID_SIGNATURE_TIMESTAMP in unsigned
    except OracleEnvError:
        raise
    except Exception as exc:  # noqa: BLE001 - malformed CMS is a FAIL, not a crash
        report.problems.append(f"cannot parse CMS: {type(exc).__name__}: {exc}")
        return report

    baseline = (
        blob.sub_filter == "/ETSI.CAdES.detached"
        and report.content_type
        and report.message_digest
        and report.signing_certificate_v2
        and report.no_signing_time
        and report.detached
        and not report.problems
    )
    if baseline:
        report.level = "B-T" if report.timestamp else "B-B"
    return report


def _check_signing_certificate_v2(der: bytes, signed_data: Any, info: Any, problems: list[str]) -> bool:
    signing_certificate_v2 = _asn1_types()
    try:
        value = signing_certificate_v2.load(der)
        first = value["certs"][0]
    except Exception as exc:  # noqa: BLE001
        problems.append(f"signing-certificate-v2 does not parse: {exc}")
        return False
    # DER omits DEFAULT values: an explicit sha256 AlgorithmIdentifier is a DER violation.
    first_der = first.dump()
    body_offset = 2 if first_der[1] < 0x80 else 2 + (first_der[1] & 0x7F)
    hash_alg = first["hash_algorithm"]["algorithm"].native
    explicit_alg = body_offset < len(first_der) and first_der[body_offset] == 0x30  # SEQUENCE
    if explicit_alg and hash_alg == "sha256":
        problems.append("ESSCertIDv2 encodes the DEFAULT sha256 hashAlgorithm explicitly (not DER)")
    cert = _signer_certificate(signed_data, info["sid"])
    if cert is None:
        problems.append("signer certificate not found in SignedData.certificates")
        return False
    try:
        digest = hashlib.new(hash_alg, cert.dump()).digest()
    except ValueError:
        problems.append(f"unsupported ESSCertIDv2 hash algorithm {hash_alg}")
        return False
    if digest != first["cert_hash"].native:
        problems.append("ESSCertIDv2 certHash does not match the signer certificate")
        return False
    return True


def profiles(path: Path) -> list[PadesReport]:
    return [profile(blob) for blob in extract(path)]


def check_pades(name: str, report: PadesReport, expected: Any) -> CheckResult:
    """Expectation: ``true`` (meets B-B), ``false`` (does not), or a level ``"B-B"`` / ``"B-T"``."""
    if isinstance(expected, bool):
        detail = f"level {report.level}" + (f"; {'; '.join(report.problems)}" if report.problems else "")
        return CheckResult(name, report.is_baseline_b == expected, detail)
    if expected in ("B-B", "B-T"):
        result = compare(name, expected, report.level)
        if not result.ok and report.problems:
            return failed(name, f"{result.detail}; {'; '.join(report.problems)}")
        return result
    raise ExpectError(f"'pades' must be true, false, \"B-B\" or \"B-T\", got {expected!r}")


@cli
def main(argv: list[str] | None = None) -> int:
    """Report the PAdES baseline profile of every signature; exit 0 when all meet B-B."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("pdf", type=Path)
    parser.add_argument("--json", action="store_true", help="print the reports as JSON")
    args = parser.parse_args(argv)
    if not args.pdf.is_file():
        raise ExpectError(f"no such file: {args.pdf}")
    try:
        reports = profiles(args.pdf)
    except ExtractionError as exc:
        print(f"FAIL  {exc}")
        return 1
    results = [
        passed(f"signatures[{r.index}].pades", r.level or "")
        if r.is_baseline_b
        else failed(f"signatures[{r.index}].pades", "; ".join(r.problems) or "not B-B")
        for r in reports
    ]
    if args.json:
        print(json.dumps([r.to_json() for r in reports], indent=2))
    else:
        print_results(results)
        if not reports:
            print("no signatures found")
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())

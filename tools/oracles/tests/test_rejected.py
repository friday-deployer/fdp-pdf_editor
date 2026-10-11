"""Self-tests of the ``rejected`` signature expectation (M3 brief D-3) and of the PAdES profile
checks added in M3 (``/M``, ``/Cert``, the signer certificate in ``SignedData.certificates``,
ESS ``issuerSerial``).

The negative files are pyHanko-signed documents with one defect each, made the way the attack
corpus of ``folioxide_testkit::fixtures::sign_attacks`` makes them: same-length, in-place edits
(a renamed key, a shortened ByteRange, garbage CMS bytes), so the cross-reference data stays
valid and each case tests the signature defence alone.
"""

from __future__ import annotations

import dataclasses
import re
import unittest

import _support  # noqa: F401  (first: puts tools/oracles on sys.path for the imports below)
import extract_cms
import pades_profile
import validate_sig
from _support import PKI, offset_in_first_range, pdfgen, sign, temp_dir, write_case
from oracle_common import ExpectError

ROOT = [PKI / "root.pem"]
REJECTED = {"field": "Signature1", "rejected": True}
REJECTED_ROWS = {"signatures[0].rejected.pyhanko", "signatures[0].rejected.pdfsig",
                 "signatures[0].rejected.openssl"}


class _Docs:
    """PDFs signed once per test run."""

    _cache: dict[str, bytes] = {}

    @classmethod
    def get(cls, key: str) -> bytes:
        if key not in cls._cache:
            if key == "one":
                cls._cache[key] = sign(pdfgen.build_pdf(), "signer-p256")
            elif key == "two":
                cls._cache[key] = sign(cls.get("one"), "signer-p384", field="Signature2")
            else:
                raise KeyError(key)
        return cls._cache[key]


def _gap(data: bytes) -> tuple[int, int]:
    """(start, end) of the last signature's gap, ``<`` and ``>`` included."""
    o1, l1, o2, _ = map(int, re.findall(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", data)[-1])
    return o1 + l1, o2


def contents_renamed(data: bytes) -> bytes:
    """``/Contents`` of the last signature dictionary renamed ``/Kontents`` (same length)."""
    start, _ = _gap(data)
    key = data.rindex(b"/Contents", 0, start)
    return data[:key] + b"/Kontents" + data[key + len(b"/Contents"):]


def byte_range_two_values(data: bytes) -> bytes:
    """The last ``/ByteRange [0 a b c]`` rewritten as ``[0 a]`` padded with spaces."""
    match = list(re.finditer(rb"/ByteRange\s*\[\s*0\s+(\d+)\s+\d+\s+\d+\s*\]", data))[-1]
    new = b"/ByteRange [0 %s]" % match.group(1)
    return data[: match.start()] + new.ljust(len(match.group(0))) + data[match.end():]


def cms_garbage(data: bytes) -> bytes:
    """The first 64 hex digits of the last CMS replaced by ``A5…`` (not a DER ContentInfo)."""
    start, _ = _gap(data)
    return data[: start + 1] + b"A5" * 32 + data[start + 65:]


def _failing(results) -> set[str]:
    return {r.name for r in results if not r.ok}


def _check(data: bytes, expected: list) -> list:
    with temp_dir() as tmp:
        path = tmp / "doc.pdf"
        path.write_bytes(data)
        return validate_sig.check_signatures(path, expected, ROOT)


class RejectedTests(unittest.TestCase):
    def test_a_good_signature_is_not_rejected(self):
        results = _check(_Docs.get("one"), [REJECTED])
        self.assertEqual(_failing(results), REJECTED_ROWS)
        # No structure rows for a rejected entry.
        self.assertFalse({r.name for r in results} & {"signatures[0].gap", "signatures[0].byteRange"})

    def test_a_tampered_signature_is_rejected(self):
        signed = _Docs.get("one")
        tampered = pdfgen.flip_byte(signed, offset_in_first_range(signed))
        results = _check(tampered, [REJECTED])
        self.assertFalse(_failing(results), [r for r in results if not r.ok])
        rows = {r.name: r.detail for r in results}
        self.assertIn("intact=False", rows["signatures[0].rejected.pyhanko"])
        self.assertIn("Digest Mismatch", rows["signatures[0].rejected.pdfsig"])
        self.assertIn("-noverify", rows["signatures[0].rejected.openssl"])

    def test_usf_defects_are_rejected_by_every_oracle(self):
        signed = _Docs.get("one")
        for name, mutate in (("contents renamed", contents_renamed),
                             ("byte range with two values", byte_range_two_values),
                             ("garbage CMS", cms_garbage)):
            with self.subTest(name):
                broken = mutate(signed)
                self.assertEqual(len(broken), len(signed))
                results = _check(broken, [REJECTED])
                self.assertFalse(_failing(results), [r for r in results if not r.ok])
                # The same file fails an entry that expects a good signature.
                self.assertTrue(_failing(_check(broken, [{"field": "Signature1"}])))

    def test_a_single_rejected_entry_may_omit_the_field(self):
        broken = cms_garbage(_Docs.get("one"))
        results = _check(broken, [{"rejected": True}])
        self.assertFalse(_failing(results), [r for r in results if not r.ok])

    def test_one_of_two_signatures_rejected(self):
        two = _Docs.get("two")
        broken = cms_garbage(two)  # Signature2's CMS; Signature1's bytes are untouched
        expected = [
            {"field": "Signature1", "intact": True, "valid": True, "trusted": True,
             "coverage": "entireRevision", "modification": "formFilling"},
            {"field": "Signature2", "rejected": True},
        ]
        results = _check(broken, expected)
        self.assertFalse(_failing(results), [r for r in results if not r.ok])
        names = {r.name for r in results}
        self.assertIn("signatures[1].rejected.openssl", names)
        self.assertIn("signatures[0].gap", names)
        # Rejecting the good one fails.
        swapped = [{"field": "Signature1", "rejected": True}, {"field": "Signature2", "rejected": True}]
        self.assertEqual(_failing(_check(broken, swapped)), {
            "signatures[0].rejected.pyhanko", "signatures[0].rejected.pdfsig", "signatures[0].rejected.openssl"})

    def test_a_broken_signature_does_not_hide_the_good_one(self):
        # pyHanko's own listing raises for the whole file when one /Contents key is gone;
        # validate_sig reads the signatures one at a time.
        broken = contents_renamed(_Docs.get("two"))
        good = {"field": "Signature1", "intact": True, "valid": True, "trusted": True,
                "coverage": "entireRevision"}
        results = _check(broken, [good, {"field": "Signature2", "rejected": True}])
        self.assertFalse(_failing(results), [r for r in results if not r.ok])
        rows = {r.name: r.detail for r in results}
        self.assertIn("pyHanko raises", rows["signatures[1].rejected.pyhanko"])
        # Expecting a good second signature fails at pyHanko, pdfsig and the extraction.
        failing = _failing(_check(broken, [good, {"field": "Signature2"}]))
        self.assertIn("signatures[1].pyhanko", failing)
        self.assertIn("signatures[1].pdfsig", failing)

    def test_independent_oracles_run_when_pyhanko_cannot_read_the_file(self):
        # An update whose startxref points past the end of the file (the attack corpus's
        # isa_bad_startxref_update): pyHanko cannot read the file, while the signed bytes are
        # untouched, so pdfsig and OpenSSL validate the signature.
        signed = _Docs.get("one")
        broken = signed + b"4 0 obj\n<< /Shadow true >>\nendobj\nstartxref\n999999999\n%%EOF\n"
        good = {"field": "Signature1", "intact": True, "valid": True, "coverage": "entireRevision"}
        results = _check(broken, [good])
        rows = {r.name: r for r in results}
        # The pyHanko verdict is one FAIL row (a case may waive it in knownFailures) ...
        self.assertEqual(_failing(results), {"signatures.pyhanko"})
        self.assertNotIn("signatures.count.pyhanko", rows)
        self.assertNotIn("signatures[0].intact.pyhanko", rows)
        # ... and the independent oracles still check the expectation.
        for name in ("signatures.count.fields", "signatures[0].byteRange", "signatures[0].gap",
                     "signatures[0].padding", "signatures[0].pdfsig", "signatures[0].openssl"):
            self.assertTrue(rows[name].ok, f"{name}: {rows[name].detail}")
        # Expecting a broken signature there fails at pdfsig and OpenSSL.
        failing = _failing(_check(broken, [dict(good, intact=False)]))
        self.assertEqual(failing, {"signatures.pyhanko", "signatures[0].pdfsig", "signatures[0].openssl"})
        # A rejection is still all or nothing: pdfsig and OpenSSL accept the signature.
        failing = _failing(_check(broken, [REJECTED]))
        self.assertEqual(failing, {"signatures[0].rejected.pdfsig", "signatures[0].rejected.openssl"})

    def test_rejected_entries_are_validated(self):
        signed = _Docs.get("one")
        for entry in ({"rejected": "yes"}, {"field": "Signature1", "rejected": True, "intact": False},
                      {"rejected": True, "coverage": "entireFile"}):
            with self.subTest(entry=entry), self.assertRaises(ExpectError):
                _check(signed, [entry])
        with self.assertRaises(ExpectError):
            _check(_Docs.get("two"), [{"field": "Signature1"}, {"rejected": True}])
        # "rejected": false is an ordinary entry.
        self.assertFalse(_failing(_check(signed, [{"field": "Signature1", "rejected": False}])))

    def test_the_runner_accepts_rejected_cases(self):
        import run_suite

        broken = cms_garbage(_Docs.get("one"))
        with temp_dir() as tmp:
            write_case(tmp / "sign-attacks", "usf-cms-garbage", broken,
                       {"pages": 1, "signatures": [{"field": "Signature1", "rejected": True}]})
            write_case(tmp / "sign-attacks", "good-is-not-rejected", _Docs.get("one"),
                       {"signatures": [{"field": "Signature1", "rejected": True}]})
            outcomes = {o.case_label: o for o in (run_suite.run_case(c, []) for c in run_suite.discover([tmp])[0])}
        self.assertEqual(outcomes["sign-attacks/usf-cms-garbage.pdf"].status, "PASS")
        self.assertEqual(outcomes["sign-attacks/good-is-not-rejected.pdf"].status, "FAIL")


class PadesBaselineAdditionsTests(unittest.TestCase):
    def _blob(self) -> extract_cms.SignatureBlob:
        with temp_dir() as tmp:
            path = tmp / "doc.pdf"
            path.write_bytes(_Docs.get("one"))
            [blob] = extract_cms.extract(path)
        return blob

    def test_pyhanko_signature_meets_every_addition(self):
        blob = self._blob()
        self.assertIn("/M", blob.dict_keys)
        report = pades_profile.profile(blob)
        self.assertEqual(report.level, "B-B", report.problems)
        self.assertTrue(report.m_present and report.no_cert_entry and report.signer_certificate_included)
        self.assertEqual(report.to_json()["mPresent"], True)

    def test_m_missing_and_cert_present_are_not_baseline(self):
        blob = self._blob()
        for keys, problem in ((blob.dict_keys - {"/M"}, "no /M"), (blob.dict_keys | {"/Cert"}, "has /Cert")):
            with self.subTest(problem):
                report = pades_profile.profile(dataclasses.replace(blob, dict_keys=keys))
                self.assertIsNone(report.level)
                self.assertIn(problem, "; ".join(report.problems))

    def test_signer_certificate_must_be_included(self):
        from asn1crypto import cms

        blob = self._blob()
        content_info = cms.ContentInfo.load(blob.cms_der)
        signed_data = content_info["content"]
        signer_serial = signed_data["signer_infos"][0]["sid"].chosen["serial_number"].native
        others = [c for c in signed_data["certificates"] if c.chosen.serial_number != signer_serial]
        for certs, problem in ((others, "signer certificate not found"), ([], "certificates is empty")):
            with self.subTest(problem):
                signed_data["certificates"] = cms.CertificateSet(certs)
                report = pades_profile.profile(dataclasses.replace(blob, cms_der=content_info.dump(force=True)))
                self.assertIsNone(report.level)
                self.assertFalse(report.signer_certificate_included)
                self.assertIn(problem, "; ".join(report.problems))

    def test_ess_issuer_serial_must_match(self):
        from asn1crypto import cms

        blob = self._blob()
        signed_data = cms.ContentInfo.load(blob.cms_der)["content"]
        signer_serial = signed_data["signer_infos"][0]["sid"].chosen["serial_number"]
        serial_tlv = signer_serial.dump()
        ess_oid = bytes.fromhex("060B2A864886F70D010910022F")  # id-aa-signingCertificateV2
        start = blob.cms_der.index(ess_oid)
        at = blob.cms_der.index(serial_tlv, start)  # issuerSerial.serialNumber (pyHanko writes it)
        last = at + len(serial_tlv) - 1
        changed = blob.cms_der[:last] + bytes([blob.cms_der[last] ^ 1]) + blob.cms_der[last + 1:]
        report = pades_profile.profile(dataclasses.replace(blob, cms_der=changed))
        self.assertIsNone(report.level)
        self.assertIn("issuerSerial", "; ".join(report.problems))


if __name__ == "__main__":
    unittest.main()

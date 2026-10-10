"""Signature oracle self-tests: pyHanko signs with fixtures/pki, every oracle must agree.

This is the M0 proof that validate_sig.py, extract_cms.py + ``openssl cms -verify``, ``pdfsig``
and pades_profile.py accept good signatures and reject a one-byte tamper, before Folioxide's
own signer exists (M3).
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import subprocess
import unittest

import _support  # noqa: F401  (first: puts tools/oracles on sys.path for the imports below)
import extract_cms
import pades_profile
import validate_sig
from _support import (
    PKI,
    byte_range_from_one,
    nonzero_padding,
    offset_in_first_range,
    pdfgen,
    shadowed_contents,
    sign,
    temp_dir,
)
from oracle_common import ExpectError

ROOT = [PKI / "root.pem"]

GOOD = {"intact": True, "valid": True, "trusted": True, "coverage": "entireFile",
        "modification": "none", "docmdp": None, "docmdpOk": True, "pades": "B-B", "timestamp": False}


class _Docs:
    """PDFs signed once per test run (signing with RSA-3072 is the slow part)."""

    _cache: dict[str, bytes] = {}

    @classmethod
    def get(cls, key: str) -> bytes:
        if key not in cls._cache:
            base = pdfgen.build_pdf()
            if key == "base":
                cls._cache[key] = base
            elif key.startswith("pades:"):
                cls._cache[key] = sign(base, key.split(":", 1)[1])
            elif key == "pkcs7":
                cls._cache[key] = sign(base, "signer-rsa2048", pades=False)
            elif key == "two":
                first = sign(base, "signer-rsa2048", field="Signature1")
                cls._cache[key] = sign(first, "signer-p256", field="Signature2")
            elif key == "bt":
                cls._cache[key] = sign(base, "signer-p256", timestamp=True)
            elif key == "doc-ts":
                from _support import doc_timestamp

                cls._cache[key] = doc_timestamp(cls.get("bt"))
            else:
                raise KeyError(key)
        return cls._cache[key]


def _failures(results):
    return [r for r in results if not r.ok]


def _failing_names(results):
    return {r.name for r in results if not r.ok}


class SignAndValidateTests(unittest.TestCase):
    """pyHanko signs; pyHanko, pdfsig, OpenSSL and the PAdES profile all accept."""

    def test_every_fixture_signer_validates_in_every_oracle(self):
        for signer in ("signer-rsa2048", "signer-rsa3072", "signer-p256", "signer-p384"):
            with self.subTest(signer), temp_dir() as tmp:
                path = tmp / "signed.pdf"
                path.write_bytes(_Docs.get(f"pades:{signer}"))
                results = validate_sig.check_signatures(path, [dict(GOOD, field="Signature1")], ROOT)
                self.assertFalse(_failures(results), _failures(results))
                names = {r.name for r in results}
                for oracle in ("signatures[0].pdfsig", "signatures[0].openssl", "signatures[0].pades",
                               "signatures[0].intact.pyhanko", "signatures[0].trusted.pyhanko"):
                    self.assertIn(oracle, names)

    def test_validate_reports_pyhanko_status(self):
        with temp_dir() as tmp:
            path = tmp / "signed.pdf"
            path.write_bytes(_Docs.get("pades:signer-p256"))
            [status] = validate_sig.validate(path, ROOT)
            untrusted = validate_sig.validate(path, [])[0]
        self.assertEqual((status.field, status.kind, status.sub_filter),
                         ("Signature1", "signature", "/ETSI.CAdES.detached"))
        self.assertTrue(status.intact and status.valid and status.trusted)
        self.assertEqual((status.coverage, status.modification), ("entireFile", "none"))
        self.assertTrue(untrusted.valid)
        self.assertFalse(untrusted.trusted)

    def test_pdfsig_parser(self):
        with temp_dir() as tmp:
            path = tmp / "two.pdf"
            path.write_bytes(_Docs.get("two"))
            entries = validate_sig.pdfsig(path)
        self.assertEqual([e.field for e in entries], ["Signature1", "Signature2"])
        self.assertTrue(all(e.is_valid for e in entries))
        self.assertEqual([e.total_document_signed for e in entries], [False, True])

    def test_two_signatures_coverage_and_modification(self):
        with temp_dir() as tmp:
            path = tmp / "two.pdf"
            path.write_bytes(_Docs.get("two"))
            expected = [
                {"field": "Signature1", "intact": True, "valid": True, "trusted": True,
                 "coverage": "entireRevision", "modification": "formFilling", "pades": "B-B"},
                {"field": "Signature2", "intact": True, "valid": True, "trusted": True,
                 "coverage": "entireFile", "modification": "none", "pades": "B-B"},
            ]
            results = validate_sig.check_signatures(path, expected, ROOT)
            self.assertFalse(_failures(results), _failures(results))
            # Matching by position gives the same answer as matching by field.
            by_position = [{k: v for k, v in e.items() if k != "field"} for e in expected]
            self.assertFalse(_failures(validate_sig.check_signatures(path, by_position, ROOT)))

    def test_signature_timestamp_b_t(self):
        with temp_dir() as tmp:
            path = tmp / "bt.pdf"
            path.write_bytes(_Docs.get("bt"))
            results = validate_sig.check_signatures(
                path, [{"intact": True, "valid": True, "trusted": True, "timestamp": True, "pades": "B-T"}], ROOT)
            self.assertFalse(_failures(results), _failures(results))
            self.assertIn("signatures[0].timestamp.openssl", {r.name for r in results})
            # Expecting no timestamp must fail.
            wrong = validate_sig.check_signatures(path, [{"timestamp": False}], ROOT)
            self.assertTrue(_failures(wrong))
            # Without trust roots OpenSSL still checks the token (imprint and TSA signature).
            no_roots = validate_sig.check_signatures(path, [{"timestamp": True}], [])
            self.assertFalse(_failures(no_roots), _failures(no_roots))
            [ts] = [r for r in no_roots if r.name == "signatures[0].timestamp.openssl"]
            self.assertIn("-partial_chain", ts.detail)

    def test_document_timestamp_is_validated_with_openssl_ts(self):
        with temp_dir() as tmp:
            path = tmp / "doc-ts.pdf"
            path.write_bytes(_Docs.get("doc-ts"))
            results = validate_sig.check_signatures(path, [
                {"field": "Signature1", "intact": True, "valid": True, "trusted": True,
                 "coverage": "entireRevision", "modification": "ltaUpdates", "timestamp": True},
                {"field": "DocTimeStamp1", "intact": True, "valid": True, "trusted": True,
                 "coverage": "entireFile", "pades": False},
            ], ROOT)
            self.assertFalse(_failures(results), _failures(results))
            ts_check = [r for r in results if r.name == "signatures[1].openssl"]
            self.assertEqual(len(ts_check), 1)
            self.assertIn("verified", ts_check[0].detail)
            blobs = extract_cms.extract(path)
            self.assertTrue(blobs[1].is_doc_timestamp)

    def test_document_timestamp_without_trust_roots_still_gets_openssl(self):
        with temp_dir() as tmp:
            path = tmp / "doc-ts.pdf"
            path.write_bytes(_Docs.get("doc-ts"))
            results = validate_sig.check_signatures(path, [{"field": "Signature1"}, {"field": "DocTimeStamp1"}], [])
            self.assertFalse(_failures(results), _failures(results))
            [ts] = [r for r in results if r.name == "signatures[1].openssl"]
            self.assertIn("-partial_chain (token certificates): verified", ts.detail)
            # A changed byte breaks both; with "intact": false that is the expected outcome.
            tampered = tmp / "doc-ts-tampered.pdf"
            tampered.write_bytes(pdfgen.flip_byte(path.read_bytes(), offset_in_first_range(path.read_bytes())))
            expect_tamper = validate_sig.check_signatures(tampered, [{"intact": False}, {"intact": False}], [])
            self.assertFalse(_failures(expect_tamper), _failures(expect_tamper))
            self.assertEqual(_failing_names(validate_sig.check_signatures(tampered, [{}, {}], [])), {
                "signatures[0].intact.pyhanko", "signatures[0].pdfsig", "signatures[0].openssl",
                "signatures[1].intact.pyhanko", "signatures[1].openssl",
            })

    def test_document_timestamp_without_roots_still_needs_a_timestamping_eku(self):
        """-partial_chain skips only the chain: a token from a non-TSA certificate still fails."""
        from _support import doc_timestamp

        with temp_dir() as tmp:
            path = tmp / "wrong-tsa.pdf"
            path.write_bytes(doc_timestamp(_Docs.get("base"), tsa="wrong-ku"))
            [blob] = extract_cms.extract(path)
            result = extract_cms.openssl_verify(blob, None)
        self.assertFalse(result.ok)
        self.assertIn("unsuitable certificate purpose", result.detail)

    def test_expired_signer_is_valid_but_not_trusted(self):
        with temp_dir() as tmp:
            path = tmp / "expired.pdf"
            path.write_bytes(sign(_Docs.get("base"), "expired"))
            results = validate_sig.check_signatures(
                path, [{"intact": True, "valid": True, "trusted": False}], ROOT)
        self.assertFalse(_failures(results), _failures(results))

    def test_trusted_needs_trust_roots(self):
        with temp_dir() as tmp:
            path = tmp / "signed.pdf"
            path.write_bytes(_Docs.get("pades:signer-rsa2048"))
            with self.assertRaises(ExpectError):
                validate_sig.check_signatures(path, [{"trusted": True}], [])
            with self.assertRaises(ExpectError):
                validate_sig.check_signatures(path, [{"intact": True, "colour": "red"}], ROOT)
            count = validate_sig.check_signatures(path, [], ROOT)
            self.assertEqual([r.ok for r in count], [False, False])


class EveryEntryIsCheckedTests(unittest.TestCase):
    """An entry that pins nothing still means "a good signature" and runs every oracle."""

    ALWAYS = ("intact.pyhanko", "valid.pyhanko", "byteRange", "gap", "padding", "pdfsig", "openssl")

    def _check(self, data: bytes, entry: dict) -> list:
        with temp_dir() as tmp:
            path = tmp / "doc.pdf"
            path.write_bytes(data)
            return validate_sig.check_signatures(path, [entry], ROOT)

    def test_minimal_entries_run_every_oracle(self):
        good = _Docs.get("pades:signer-rsa2048")
        for entry in ({"field": "Signature1"}, {"coverage": "entireFile"}, {}):
            with self.subTest(entry=entry):
                results = self._check(good, entry)
                self.assertFalse(_failures(results), _failures(results))
                names = {r.name for r in results}
                for row in self.ALWAYS:
                    self.assertIn(f"signatures[0].{row}", names)
                [openssl] = [r for r in results if r.name == "signatures[0].openssl"]
                self.assertIn("-noverify: verified", openssl.detail)

    def test_minimal_entry_rejects_a_tampered_signature(self):
        signed = _Docs.get("pades:signer-rsa2048")
        tampered = pdfgen.flip_byte(signed, offset_in_first_range(signed))
        self.assertEqual(_failing_names(self._check(tampered, {"field": "Signature1"})),
                         {"signatures[0].intact.pyhanko", "signatures[0].pdfsig", "signatures[0].openssl"})

    def test_nonzero_padding_fails_although_every_signature_oracle_accepts(self):
        results = self._check(nonzero_padding(_Docs.get("pades:signer-rsa2048")), {"field": "Signature1"})
        self.assertEqual(_failing_names(results), {"signatures[0].padding"})

    def test_shadowed_contents_fails_the_gap_check(self):
        results = self._check(shadowed_contents(_Docs.get("pades:signer-rsa2048")), {"field": "Signature1"})
        self.assertEqual(_failing_names(results), {"signatures[0].gap"})

    def test_byte_range_not_starting_at_zero_fails(self):
        results = self._check(byte_range_from_one(_Docs.get("pades:signer-rsa2048")), {"intact": False})
        self.assertEqual(_failing_names(results), {"signatures[0].byteRange"})
        [row] = [r for r in results if r.name == "signatures[0].byteRange"]
        self.assertIn("ByteRange starts at 1, not 0", row.detail)

    def test_malformed_cms_is_a_failure_not_a_crash(self):
        with temp_dir() as tmp:
            path = tmp / "signed.pdf"
            path.write_bytes(_Docs.get("pades:signer-rsa2048"))
            [status] = validate_sig.validate(path, ROOT)
            [blob] = extract_cms.extract(path)
        garbage = dataclasses.replace(blob, cms_der=b"\x30\x03\x02\x01\x05")
        results = validate_sig._check_one("s", {"timestamp": False, "pades": "B-B"}, status, garbage, None, None,
                                          "pdfsig not run")
        failing = _failing_names(results)
        self.assertLessEqual({"s.openssl", "s.pades", "s.timestamp.pyhanko"}, failing)

    def test_no_expectation_waives_the_structure_checks(self):
        data = nonzero_padding(_Docs.get("pades:signer-rsa2048"))
        for entry in ({"intact": False}, {"valid": False}, {"intact": True, "valid": True, "trusted": True}):
            with self.subTest(entry=entry):
                self.assertIn("signatures[0].padding", _failing_names(self._check(data, entry)))


class TamperTests(unittest.TestCase):
    """Flipping one byte inside the signed range must make every oracle report it."""

    def setUp(self):
        signed = _Docs.get("pades:signer-rsa2048")
        offset = offset_in_first_range(signed)
        blob_range = None
        with temp_dir() as tmp:
            path = tmp / "signed.pdf"
            path.write_bytes(signed)
            blob_range = extract_cms.extract(path)[0].byte_range
        self.assertLess(offset, blob_range[1], "the flipped byte must be inside the first signed range")
        self.tampered = pdfgen.flip_byte(signed, offset)

    def test_tampered_signature_is_not_intact(self):
        with temp_dir() as tmp:
            path = tmp / "tampered.pdf"
            path.write_bytes(self.tampered)
            [status] = validate_sig.validate(path, ROOT)
            self.assertFalse(status.intact)
            [entry] = validate_sig.pdfsig(path)
            self.assertFalse(entry.is_valid)
            self.assertIn("Digest Mismatch", entry.validation)
            blob = extract_cms.extract(path)[0]
            self.assertFalse(extract_cms.openssl_verify(blob, PKI / "root.pem").ok)
            self.assertFalse(extract_cms.openssl_verify(blob, None).ok)
            # Expecting the tamper passes in every oracle; expecting validity fails in every oracle.
            expect_tamper = validate_sig.check_signatures(path, [{"intact": False}], ROOT)
            self.assertFalse(_failures(expect_tamper), _failures(expect_tamper))
            expect_good = validate_sig.check_signatures(path, [{"intact": True, "valid": True}], ROOT)
            failing = {r.name for r in _failures(expect_good)}
            self.assertEqual(failing, {"signatures[0].intact.pyhanko", "signatures[0].pdfsig",
                                       "signatures[0].openssl"})

    def test_validate_sig_cli_exit_codes(self):
        with temp_dir() as tmp:
            good = tmp / "good.pdf"
            good.write_bytes(_Docs.get("pades:signer-rsa2048"))
            bad = tmp / "bad.pdf"
            bad.write_bytes(self.tampered)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(validate_sig.main([str(good), "--trust-root", str(PKI / "root.pem")]), 0)
                self.assertEqual(validate_sig.main([str(bad), "--trust-root", str(PKI / "root.pem")]), 1)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(validate_sig.main([str(tmp / "missing.pdf")]), 2)


class ExtractCmsTests(unittest.TestCase):
    def test_extracted_files_verify_with_the_documented_openssl_command(self):
        with temp_dir() as tmp:
            path = tmp / "bt.pdf"
            path.write_bytes(_Docs.get("bt"))
            out_dir = tmp / "out"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = extract_cms.main([str(path), "--out-dir", str(out_dir), "--verify",
                                         "--ca-file", str(PKI / "root.pem")])
            self.assertEqual(code, 0)
            self.assertEqual(sorted(p.name for p in out_dir.iterdir()),
                             ["sig1.der", "sig1.signed.bin", "sig1.sigvalue.bin", "sig1.tst.der"])
            cms = subprocess.run(
                ["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", out_dir / "sig1.der",
                 "-content", out_dir / "sig1.signed.bin", "-CAfile", PKI / "root.pem", "-purpose", "any",
                 "-out", tmp / "content.out"],
                capture_output=True, check=False)
            self.assertEqual(cms.returncode, 0, cms.stderr)
            self.assertIn(b"Verification successful", cms.stderr)
            self.assertEqual((tmp / "content.out").read_bytes(), (out_dir / "sig1.signed.bin").read_bytes())
            ts = subprocess.run(
                ["openssl", "ts", "-verify", "-data", out_dir / "sig1.sigvalue.bin", "-in",
                 out_dir / "sig1.tst.der", "-token_in", "-CAfile", PKI / "tsa-root.pem"],
                capture_output=True, check=False)
            self.assertEqual(ts.returncode, 0, ts.stderr)
            self.assertIn(b"Verification: OK", ts.stdout)

    def test_signed_bytes_and_gap_follow_the_byte_range(self):
        data = _Docs.get("pades:signer-p384")
        with temp_dir() as tmp:
            path = tmp / "signed.pdf"
            path.write_bytes(data)
            [blob] = extract_cms.extract(path)
        o1, l1, o2, l2 = blob.byte_range
        self.assertEqual(o1, 0)
        self.assertEqual(o2 + l2, len(data))
        self.assertEqual(blob.signed_bytes, data[:l1] + data[o2:])
        self.assertEqual(data[l1:l1 + 1], b"<")
        self.assertEqual(data[o2 - 1:o2], b">")
        self.assertTrue(blob.contents_match_dict)
        self.assertTrue(blob.trailing_padding_ok)
        self.assertEqual(blob.cms_der[:1], b"\x30")

    def test_structure_checks_flag_each_problem(self):
        with temp_dir() as tmp:
            path = tmp / "signed.pdf"
            path.write_bytes(_Docs.get("pades:signer-p256"))
            [blob] = extract_cms.extract(path)
        self.assertEqual([(r.name, r.ok) for r in blob.structure_checks()],
                         [("signatures[0].byteRange", True), ("signatures[0].gap", True),
                          ("signatures[0].padding", True)])
        for change, row in (({"problems": ["ByteRange starts at 7, not 0"]}, "p.byteRange"),
                            ({"contents_match_dict": False}, "p.gap"),
                            ({"trailing_padding_ok": False}, "p.padding")):
            with self.subTest(row):
                broken = dataclasses.replace(blob, **change)
                self.assertEqual(_failing_names(broken.structure_checks("p")), {row})

    def test_cli_enforces_the_structure_checks(self):
        signed = _Docs.get("pades:signer-rsa2048")
        with temp_dir() as tmp:
            for name, data, want in (("good", signed, 0), ("padding", nonzero_padding(signed), 1),
                                     ("shadow", shadowed_contents(signed), 1),
                                     ("byte-range", byte_range_from_one(signed), 1)):
                with self.subTest(name):
                    path = tmp / f"{name}.pdf"
                    path.write_bytes(data)
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out):
                        self.assertEqual(extract_cms.main([str(path)]), want, out.getvalue())

    def test_cli_verifies_a_document_timestamp_without_a_ca_file(self):
        with temp_dir() as tmp:
            path = tmp / "doc-ts.pdf"
            path.write_bytes(_Docs.get("doc-ts"))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(extract_cms.main([str(path), "--verify"]), 0, out.getvalue())
        self.assertIn("PASS  signatures[1].openssl", out.getvalue())
        self.assertIn("-partial_chain", out.getvalue())

    def test_unsigned_pdf_has_no_signatures(self):
        with temp_dir() as tmp:
            path = tmp / "plain.pdf"
            path.write_bytes(_Docs.get("base"))
            self.assertEqual(extract_cms.extract(path), [])

    def test_ber_element_length(self):
        self.assertEqual(extract_cms.ber_element_length(b"\x30\x03\x02\x01\x05" + b"\x00" * 8), 5)
        long_form = b"\x04\x81\x80" + b"\xaa" * 0x80
        self.assertEqual(extract_cms.ber_element_length(long_form + b"\x00"), len(long_form))
        indefinite = b"\x30\x80" + b"\x02\x01\x05" + b"\x30\x80\x00\x00" + b"\x00\x00"
        self.assertEqual(extract_cms.ber_element_length(indefinite + b"\x00" * 4), len(indefinite))
        for bad in (b"", b"\x30", b"\x30\x05\x00", b"\x04\x80\x00\x00", b"\x30\x89" + b"\x00" * 9):
            with self.subTest(bad=bad), self.assertRaises(extract_cms.ExtractionError):
                extract_cms.ber_element_length(bad)


class PadesProfileTests(unittest.TestCase):
    def _profiles(self, key):
        with temp_dir() as tmp:
            path = tmp / "doc.pdf"
            path.write_bytes(_Docs.get(key))
            return pades_profile.profiles(path)

    def test_pyhanko_pades_signature_is_baseline_b(self):
        [report] = self._profiles("pades:signer-rsa2048")
        self.assertEqual(report.level, "B-B")
        self.assertEqual(report.problems, [])
        self.assertTrue(report.content_type and report.message_digest and report.signing_certificate_v2)
        self.assertTrue(report.no_signing_time and report.detached)
        self.assertFalse(report.timestamp)

    def test_timestamped_signature_is_baseline_t(self):
        [report] = self._profiles("bt")
        self.assertEqual(report.level, "B-T")

    def test_pkcs7_detached_signature_is_not_pades(self):
        [report] = self._profiles("pkcs7")
        self.assertIsNone(report.level)
        self.assertFalse(report.no_signing_time)
        joined = "; ".join(report.problems)
        self.assertIn("SubFilter is /adbe.pkcs7.detached", joined)
        self.assertIn("signing-time attribute present", joined)

    def test_check_pades_expectations(self):
        [report] = self._profiles("pades:signer-p256")
        self.assertTrue(pades_profile.check_pades("p", report, True).ok)
        self.assertFalse(pades_profile.check_pades("p", report, False).ok)
        self.assertTrue(pades_profile.check_pades("p", report, "B-B").ok)
        self.assertFalse(pades_profile.check_pades("p", report, "B-T").ok)
        with self.assertRaises(ExpectError):
            pades_profile.check_pades("p", report, "B-LTA")


if __name__ == "__main__":
    unittest.main()

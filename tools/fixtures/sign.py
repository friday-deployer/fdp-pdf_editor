#!/usr/bin/env python3
"""Generate or check the signature fixtures in fixtures/sign/ (fixtures/README.md).

Usage, from anywhere, with the oracle venv (bash tools/setup-venv.sh) and OpenSSL 3.x:

    .venv/bin/python -I tools/fixtures/sign.py                 write fixtures/sign/*
    .venv/bin/python -I tools/fixtures/sign.py --only chain    write one group (cms, chain, pdf, tsa)
    .venv/bin/python -I tools/fixtures/sign.py --only pdf --pdf NAME
                                                               write only these PDFs (repeatable)
    .venv/bin/python -I tools/fixtures/sign.py --check         verify the committed files

Four groups of foreign inputs for folioxide-sign's tests (M3 brief §6.2, WP3.1B and WP3.2B; M4
brief WP4.1B):

* cms: detached CMS SignedData made by OpenSSL and by pyHanko over `data.bin`, with every
  feature the parser and the verifier must handle (BER indefinite lengths, RSA-PSS, SHA-1, no
  signed attributes, a serial number over 20 bytes, signing-time and CAdES attributes), golden
  RSA PKCS#1 v1.5 signatures, and key files for the negative key-loading cases;
* chain: certificates for the trust-path tests (`chain_*.rs`), issued by the test PKI's CAs
  with `openssl ca` (unknown critical extension, path-length violation, CA without
  keyCertSign, end-entity issuer, SHA-1 and RSA-PSS certificate signatures, single key usages,
  self-signed signer, impostor root);
* pdf: PDFs signed by pyHanko (RSA and ECDSA, one and two signatures, adbe.pkcs7.detached,
  certifications with P=1 and P=2, a document timestamp, an empty signature field; M4: a PAdES
  B-T signature, a P=1 certification followed by a document timestamp, a P=2 certification
  followed by an approval in a new visible field) and PDFs whose CMS `openssl cms -sign` made,
  for verification interop;
* tsa (M4 brief §6.2 "Interoperability"): the RFC 3161 request Folioxide makes for the
  deterministic RSA-2048 signature of `minimal.pdf` (written by the Rust test
  `bt_external_openssl_token_embedded` with FOLIOXIDE_TSA_REQUEST_OUT set; nonce
  0x0102030405060708), answered by `openssl ts -reply` with tools/tsa/openssl-tsa.cnf
  (`openssl-reply.{tsq,tsr}`) and by pyHanko's DummyTimeStamper (`pyhanko-dummy.{tsq,tsr}`: ESS
  v1, a fractional genTime). It needs `cargo`. The request goes stale whenever the signed bytes
  of `minimal.pdf` change (brief R-15): the Rust test then fails and names this command.

Every key here is a published **test-only** key.

Signing times, serial numbers and ECDSA nonces change on every run, so regenerating never
reproduces the committed bytes; --check therefore verifies properties instead of comparing:
each CMS verifies with `openssl cms -verify` and, when detached, with pyHanko's
`async_validate_detached_cms` (intact and valid), the golden signatures verify with `openssl
dgst -verify` and are deterministic, the key files have the documented types, each chain
certificate has its name, fixed validity window, issuer signature and the verdict
pyhanko-certvalidator gives it, and each PDF extends its input and passes the oracle suite's
signature checks (tools/oracles/validate_sig.py: pyHanko, pdfsig, OpenSSL, structure, PAdES)
with the expectations in PDF_EXPECTED. Regenerate everything in one change when fixtures/pki is
regenerated (everything here is made with its keys).

Exit codes: 0 success, 1 a check failed, 2 a usage or environment error (OpenSSL or pyHanko
missing).
"""

from __future__ import annotations

import argparse
import asyncio
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PKI = REPO_ROOT / "fixtures" / "pki"
OUT_DIR = REPO_ROOT / "fixtures" / "sign"
PASSWORD = "folioxide"

#: The signed content of every CMS vector.
DATA = b"Folioxide CMS test vector: the bytes a detached signature covers.\n"

#: CMS made by `openssl cms -sign` over DATA: name -> (signer, extra arguments).
OPENSSL_CMS = {
    # contentType, signingTime, messageDigest (no ESS attribute without -cades).
    "openssl-rsa2048-sha256.p7s": ("signer-rsa2048", ["-md", "sha256"]),
    # -cades adds signingCertificateV2 (ESSCertIDv2 with issuerSerial).
    "openssl-p256-cades.p7s": ("signer-p256", ["-md", "sha256", "-cades"]),
    "openssl-p384-sha384.p7s": ("signer-p384", ["-md", "sha384"]),
    # RSASSA-PSS (brief R-11, `verify_rsa_pss_openssl_fixture`).
    "openssl-rsa2048-pss.p7s": (
        "signer-rsa2048",
        ["-md", "sha256", "-keyopt", "rsa_padding_mode:pss"],
    ),
    # SHA-1 (brief R-12, `verify_sha1_legacy_weak`).
    "openssl-rsa2048-sha1.p7s": ("signer-rsa2048", ["-md", "sha1"]),
    # -stream with DER output writes BER indefinite lengths and embeds DATA as a constructed
    # OCTET STRING: an attached signature (`cms_parse_ber_indefinite`, EContentPresent).
    "openssl-p256-ber-attached.p7s": ("signer-p256", ["-md", "sha256", "-stream"]),
    # No signed attributes: the signature covers DATA itself (adbe.pkcs7.detached allows it).
    "openssl-rsa2048-noattr.p7s": ("signer-rsa2048", ["-md", "sha256", "-noattr"]),
}

#: CMS made by pyHanko's SimpleSigner.async_sign(use_pades=True): name -> (signer, digest, pss).
PYHANKO_CMS = {
    "pyhanko-rsa2048.p7s": ("signer-rsa2048", "sha256", False),
    "pyhanko-p256.p7s": ("signer-p256", "sha256", False),
    "pyhanko-p384-sha384.p7s": ("signer-p384", "sha384", False),
    "pyhanko-rsa3072-pss.p7s": ("signer-rsa3072", "sha256", True),
}

#: Raw RSASSA-PKCS1-v1_5 signatures of DATA (`openssl dgst -sign`): name -> (key, digest).
GOLDEN = {
    "golden-rsa2048-sha256.sig": ("signer-rsa2048", "sha256"),
    "golden-rsa3072-sha512.sig": ("signer-rsa3072", "sha512"),
}

#: Vectors whose content is embedded (eContent present); every other CMS is detached.
ATTACHED = {"openssl-p256-ber-attached.p7s"}

#: A detached BER vector: this DER vector with its outer structures re-encoded with indefinite
#: lengths, as streaming signers write them; the signed attributes and the certificates keep
#: their DER bytes, so the signature stays valid.
BER_SOURCE = "openssl-p256-cades.p7s"
BER_OUTPUT = "ber-indefinite-p256.p7s"

#: A self-signed P-256 certificate with a 24-byte serial number (RFC 5280 allows 20).
LONG_SERIAL = "0x0102030405060708090A0B0C0D0E0F101112131415161718"

#: Certificates for the trust-path tests (`chain_*.rs`), written to chain/ by `openssl ca` with
#: the committed CA keys of fixtures/pki and the same fixed validity window as the PKI.
#: name -> (issuer: a pki/ name, a chain/ name or "self", key spec, CN, extension section, md,
#: extra `openssl ca` arguments). Issuers come before the certificates they issue.
CHAIN_DIR = "chain"
CHAIN_NOT_BEFORE = "20250101000000Z"
CHAIN_NOT_AFTER = "20751231235959Z"
CHAIN = {
    # A signer with an unknown critical extension (RFC 5280 §4.2: must be rejected).
    "unknown-critical": ("pki:intermediate", "ec:P-256", "Folioxide Test Signer (unknown critical extension)",
                         "ext_unknown_critical", "sha384", []),
    # A CA under the intermediate, whose pathlen:0 forbids it; and a signer it issued.
    "sub-ca": ("pki:intermediate", "ec:P-256", "Folioxide Test Sub-CA (path length violation)",
               "ext_ca", "sha384", []),
    "sub-ca-signer": ("sub-ca", "ec:P-256", "Folioxide Test Signer (under the sub-CA)",
                      "ext_signer", "sha256", []),
    # A CA (issued by the root) whose key usage lacks keyCertSign; and a signer it issued.
    "no-certsign-ca": ("pki:root", "ec:P-256", "Folioxide Test CA without keyCertSign",
                       "ext_ca_no_certsign", "sha256", []),
    "no-certsign-signer": ("no-certsign-ca", "ec:P-256", "Folioxide Test Signer (CA lacks keyCertSign)",
                           "ext_signer", "sha256", []),
    # A signer issued by an end-entity certificate (pki/signer-p256 is CA:FALSE).
    "issued-by-ee": ("pki:signer-p256", "ec:P-256", "Folioxide Test Signer (issued by an end entity)",
                     "ext_signer", "sha256", []),
    # A signer whose certificate is signed with ecdsa-with-SHA1 (weak).
    "sha1-signer": ("pki:intermediate", "ec:P-256", "Folioxide Test Signer (SHA-1 certificate signature)",
                    "ext_signer", "sha1", []),
    # A CA signed by the root with RSASSA-PSS, and a signer it issued (PSS certificate signatures).
    "pss-ca": ("pki:root", "ec:P-256", "Folioxide Test CA (RSASSA-PSS signature)", "ext_ca", "sha256",
               ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32"]),
    "pss-ca-signer": ("pss-ca", "ec:P-256", "Folioxide Test Signer (under the PSS CA)", "ext_signer",
                      "sha256", []),
    # Signers with only one of the two signing key usages (D-10: Folioxide accepts either;
    # pyHanko requires nonRepudiation).
    "ku-digital-signature": ("pki:intermediate", "ec:P-256", "Folioxide Test Signer (digitalSignature only)",
                             "ext_signer_ds", "sha384", []),
    "ku-non-repudiation": ("pki:intermediate", "ec:P-256", "Folioxide Test Signer (nonRepudiation only)",
                           "ext_signer_nr", "sha384", []),
    # RSA keys below 2048 bits (pyhanko-certvalidator's DisallowWeakAlgorithmsPolicy threshold):
    # a CA with an RSA-1024 key and a signer under it, and an RSA-1024 signer.
    "rsa1024-ca": ("pki:root", "rsa:1024", "Folioxide Test CA (RSA-1024 key)", "ext_ca", "sha256", []),
    "rsa1024-ca-signer": ("rsa1024-ca", "ec:P-256", "Folioxide Test Signer (under the RSA-1024 CA)",
                          "ext_signer", "sha256", []),
    "rsa1024-signer": ("pki:intermediate", "rsa:1024", "Folioxide Test Signer (RSA-1024 key)", "ext_signer",
                       "sha384", []),
    # A self-signed signer, and a self-signed root with the test root's name but another key.
    "self-signed": ("self", "ec:P-256", "Folioxide Test Self-Signed Signer", "ext_signer", "sha256", []),
    "impostor-root": ("self", "ec:P-256", "Folioxide Test Root CA", "ext_ca", "sha256", []),
}

#: pyhanko-certvalidator's verdict on each chain certificate (trust root fixtures/pki/root.pem,
#: the PKI intermediate and the chain CAs as other certificates, key usage nonRepudiation),
#: and a fragment of its error. The Rust tests assert the same outcome for build_trust.
CHAIN_EXPECTED = {
    "unknown-critical": (False, "unsupported critical extension"),
    "sub-ca-signer": (False, "maximum path length"),
    "no-certsign-signer": (False, "not allowed to sign certificates"),
    "issued-by-ee": (False, "is not a CA"),
    "sha1-signer": (False, "sha1"),
    "pss-ca-signer": (True, ""),
    "self-signed": (False, ""),
    # The deliberate difference D-10: Folioxide trusts this signer.
    "ku-digital-signature": (False, "non repudiation"),
    "ku-non-repudiation": (True, ""),
    "rsa1024-ca-signer": (False, "disallowed signature mechanism"),
    # Path validation does not check the signer's own key; pyHanko's CMS validation does
    # (generic_cms._enforce_algorithm_usage), so a signature by it is never trusted. Folioxide's
    # build_trust checks it on the path.
    "rsa1024-signer": (True, ""),
}

#: The openssl ca extension sections of the chain certificates.
CHAIN_EXTENSIONS = """
[ ext_signer ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ ext_signer_ds ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ ext_signer_nr ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, nonRepudiation
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ ext_unknown_critical ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
# RFC 5612 documentation enterprise number: an extension no validator knows.
1.3.6.1.4.1.32473.1    = critical, ASN1:UTF8String:folioxide

[ ext_ca ]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ ext_ca_no_certsign ]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, digitalSignature, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
"""

DN_PREFIX = "/O=Folioxide Test PKI/OU=TEST ONLY - DO NOT TRUST"


def run(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, check=True, capture_output=True, **kwargs)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr
        raise RuntimeError(f"{' '.join(map(str, args))} failed:\n{stderr}") from exc


def openssl(*args: str, **kwargs) -> subprocess.CompletedProcess:
    return run(["openssl", *args], **kwargs)


def write_keys(out: Path, work: Path) -> None:
    """The key files of the negative key-loading cases and the long-serial certificate."""
    # Unsupported or too-small keys (rsa_below_2048_rejected; unsupported curves and types).
    openssl("genpkey", "-quiet", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024",
            "-out", str(out / "rsa1024.key.pem"))
    openssl("genpkey", "-quiet", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-521",
            "-pkeyopt", "ec_param_enc:named_curve", "-out", str(out / "p521.key.pem"))
    openssl("genpkey", "-quiet", "-algorithm", "ED25519", "-out", str(out / "ed25519.key.pem"))
    # Legacy OpenSSL encryption (Proc-Type: 4,ENCRYPTED) and PBES1, both Unsupported.
    openssl("rsa", "-in", str(PKI / "signer-rsa2048.key.pem"), "-traditional", "-aes128",
            "-passout", f"pass:{PASSWORD}", "-out", str(out / "signer-rsa2048.key.legacy-enc.pem"))
    openssl("pkcs8", "-topk8", "-v1", "PBE-SHA1-3DES", "-in", str(PKI / "signer-p256.key.pem"),
            "-passout", f"pass:{PASSWORD}", "-out", str(out / "signer-p256.key.pbes1.pem"))
    # A PKCS#12 without a MAC: a wrong password shows only as a decryption failure.
    openssl("pkcs12", "-export", "-nomac", "-inkey", str(PKI / "signer-p256.key.pem"),
            "-in", str(PKI / "signer-p256.pem"), "-certfile", str(PKI / "intermediate.pem"),
            "-passout", f"pass:{PASSWORD}", "-name", "Folioxide Test Signer P-256",
            "-out", str(out / "signer-p256-nomac.p12"))
    # The long-serial certificate and its key.
    openssl("genpkey", "-quiet", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-pkeyopt", "ec_param_enc:named_curve", "-out", str(out / "long-serial.key.pem"))
    config = work / "req.cnf"
    config.write_text("[req]\ndistinguished_name = dn\n[dn]\n", encoding="ascii")
    openssl("req", "-new", "-x509", "-config", str(config), "-key", str(out / "long-serial.key.pem"),
            "-subj", "/O=Folioxide Test PKI/OU=TEST ONLY - DO NOT TRUST/CN=Folioxide Long Serial",
            "-set_serial", LONG_SERIAL, "-days", "36500", "-sha256",
            "-addext", "keyUsage=critical,digitalSignature,nonRepudiation",
            "-out", str(out / "long-serial.pem"))


def write_chain(out: Path, work: Path) -> None:
    """The trust-path certificates (CHAIN), issued with `openssl ca` as tools/gen-pki.sh does
    (OpenSSL 3.0 has no `x509 -not_before`). Only the certificates are kept; the new keys are
    thrown away."""
    ca = work / "ca"
    (ca / "newcerts").mkdir(parents=True)
    (ca / "index.txt").write_text("", encoding="ascii")
    config = ca / "ca.cnf"
    config.write_text(f"""[ ca ]
default_ca = fx_ca

[ fx_ca ]
database        = {ca}/index.txt
new_certs_dir   = {ca}/newcerts
serial          = {ca}/serial
default_md      = sha256
policy          = fx_policy
unique_subject  = no
copy_extensions = none
email_in_dn     = no

[ fx_policy ]
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied

[ req ]
distinguished_name = req_dn

[ req_dn ]
{CHAIN_EXTENSIONS}""", encoding="ascii")
    chain_out = out / CHAIN_DIR
    chain_out.mkdir()
    keys: dict[str, Path] = {}
    certs: dict[str, Path] = {}
    for name, (issuer, spec, cn, ext, md, extra) in CHAIN.items():
        key = work / f"{name}.key.pem"
        kind, param = spec.split(":")
        if kind == "ec":
            openssl("genpkey", "-quiet", "-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{param}",
                    "-pkeyopt", "ec_param_enc:named_curve", "-out", str(key))
        else:
            openssl("genpkey", "-quiet", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{param}",
                    "-out", str(key))
        csr = work / f"{name}.csr"
        openssl("req", "-new", "-config", str(config), "-key", str(key), "-subj", f"{DN_PREFIX}/CN={cn}",
                "-out", str(csr))
        cert = chain_out / f"{name}.pem"
        if issuer == "self":
            signing = ["-selfsign", "-keyfile", str(key)]
        elif issuer.startswith("pki:"):
            base = issuer.split(":", 1)[1]
            signing = ["-cert", str(PKI / f"{base}.pem"), "-keyfile", str(PKI / f"{base}.key.pem")]
        else:
            signing = ["-cert", str(certs[issuer]), "-keyfile", str(keys[issuer])]
        openssl("ca", "-batch", "-notext", "-rand_serial", "-config", str(config), *signing, "-md", md,
                "-extensions", ext, "-startdate", CHAIN_NOT_BEFORE, "-enddate", CHAIN_NOT_AFTER,
                *extra, "-in", str(csr), "-out", str(cert))
        keys[name] = key
        certs[name] = cert


#: Signed PDFs for verification interop (pdf/): name -> (base, how, details). The base is
#: fixtures/syntax/minimal.pdf ("minimal") or an earlier entry; each file starts with every byte
#: of its base. "pyhanko" signs with SimpleSigner (PAdES unless the subfilter says otherwise),
#: "certify" certifies with DocMDP P, "timestamp" adds an ETSI.RFC3161 document timestamp with
#: an in-process TSA (pki/tsa), "empty-field" adds an unsigned signature field, and "openssl"
#: embeds a CMS that `openssl cms -sign` made over the byte ranges pyHanko prepared.
PDF_DIR = "pdf"
PDFS = {
    "pyhanko-rsa2048.pdf": ("minimal", "pyhanko", {"signer": "signer-rsa2048", "field": "Signature1"}),
    "pyhanko-p256.pdf": ("minimal", "pyhanko", {"signer": "signer-p256", "field": "Signature1"}),
    "pyhanko-two-signatures.pdf": ("pyhanko-rsa2048.pdf", "pyhanko",
                                   {"signer": "signer-p384", "field": "Signature2", "md": "sha384"}),
    "pyhanko-pkcs7-rsa3072.pdf": ("minimal", "pyhanko",
                                  {"signer": "signer-rsa3072", "field": "Signature1", "pkcs7": True}),
    "pyhanko-certified-p1.pdf": ("minimal", "certify", {"signer": "signer-p256", "field": "Signature1", "p": 1}),
    "pyhanko-certified-p2.pdf": ("minimal", "certify",
                                 {"signer": "signer-rsa2048", "field": "Signature1", "p": 2}),
    "pyhanko-doc-timestamp.pdf": ("pyhanko-p256.pdf", "timestamp", {"field": "DocTimeStamp1"}),
    "pyhanko-empty-field.pdf": ("minimal", "empty-field", {"field": "Approval"}),
    # M4: PAdES B-T with the in-process TSA (ESS v1, fractional genTime).
    "pyhanko-bt-rsa2048.pdf": ("minimal", "pyhanko",
                               {"signer": "signer-rsa2048", "field": "Signature1", "timestamp": True}),
    # M4 (fixtures for the `certify` suite, brief §6.3): P=1 then a document timestamp
    # (ltaUpdates, docmdpOk true), and P=2 then an approval in a new visible field (other,
    # docmdpOk false: pyHanko's valid_when_certifying=False).
    "pyhanko-certified-p1-dts.pdf": ("pyhanko-certified-p1.pdf", "timestamp", {"field": "DocTimeStamp1"}),
    "pyhanko-certified-p2-visible-approval.pdf": ("pyhanko-certified-p2.pdf", "pyhanko",
                                                  {"signer": "signer-p256", "field": "Signature2",
                                                   "box": (300, 100, 500, 160)}),
    "openssl-rsa2048.pdf": ("minimal", "openssl",
                            {"signer": "signer-rsa2048", "field": "Signature1", "md": "sha256", "cades": False}),
    "openssl-p256-cades.pdf": ("minimal", "openssl",
                               {"signer": "signer-p256", "field": "Signature1", "md": "sha256", "cades": True}),
    "openssl-rsa2048-sha1.pdf": ("minimal", "openssl",
                                 {"signer": "signer-rsa2048", "field": "Signature1", "md": "sha1", "cades": False}),
}

#: What every oracle must say about each PDF: the `signatures` expectation of the oracle suite
#: (tools/oracles/validate_sig.py; trust root pki/root.pem), checked by --check.
_GOOD = {"intact": True, "valid": True, "trusted": True, "timestamp": False}
PDF_EXPECTED = {
    "pyhanko-rsa2048.pdf": [dict(_GOOD, field="Signature1", coverage="entireFile", modification="none",
                                 pades="B-B", docmdp=None)],
    "pyhanko-p256.pdf": [dict(_GOOD, field="Signature1", coverage="entireFile", modification="none",
                              pades="B-B")],
    "pyhanko-two-signatures.pdf": [
        dict(_GOOD, field="Signature1", coverage="entireRevision", modification="formFilling", pades="B-B"),
        dict(_GOOD, field="Signature2", coverage="entireFile", modification="none", pades="B-B"),
    ],
    "pyhanko-pkcs7-rsa3072.pdf": [dict(_GOOD, field="Signature1", coverage="entireFile", modification="none",
                                       pades=False)],
    "pyhanko-certified-p1.pdf": [dict(_GOOD, field="Signature1", coverage="entireFile", modification="none",
                                      pades="B-B", docmdp=1, docmdpOk=True)],
    "pyhanko-certified-p2.pdf": [dict(_GOOD, field="Signature1", coverage="entireFile", modification="none",
                                      pades="B-B", docmdp=2, docmdpOk=True)],
    "pyhanko-doc-timestamp.pdf": [
        dict(_GOOD, field="Signature1", coverage="entireRevision", modification="ltaUpdates", pades="B-B"),
        {"field": "DocTimeStamp1", "intact": True, "valid": True, "trusted": True,
         "coverage": "entireFile", "pades": False},
    ],
    "pyhanko-empty-field.pdf": [],
    "pyhanko-bt-rsa2048.pdf": [dict(_GOOD, field="Signature1", coverage="entireFile", modification="none",
                                    pades="B-T", timestamp=True)],
    "pyhanko-certified-p1-dts.pdf": [
        dict(_GOOD, field="Signature1", coverage="entireRevision", modification="ltaUpdates", pades="B-B",
             docmdp=1, docmdpOk=True),
        {"field": "DocTimeStamp1", "intact": True, "valid": True, "trusted": True,
         "coverage": "entireFile", "pades": False},
    ],
    "pyhanko-certified-p2-visible-approval.pdf": [
        dict(_GOOD, field="Signature1", coverage="entireRevision", modification="other", pades="B-B",
             docmdp=2, docmdpOk=False),
        dict(_GOOD, field="Signature2", coverage="entireFile", modification="none", pades="B-B"),
    ],
    "openssl-rsa2048.pdf": [dict(_GOOD, field="Signature1", coverage="entireFile", modification="none",
                                 pades=False)],
    "openssl-p256-cades.pdf": [dict(_GOOD, field="Signature1", coverage="entireFile", modification="none",
                                    pades=False)],
    # SHA-1 is a weak hash for pyHanko: intact and valid, never trusted.
    "openssl-rsa2048-sha1.pdf": [dict(_GOOD, field="Signature1", trusted=False, coverage="entireFile",
                                      modification="none", pades=False)],
}

#: The base document of every PDF fixture (committed, deterministic: `cargo xtask fixtures`).
MINIMAL = REPO_ROOT / "fixtures" / "syntax" / "minimal.pdf"

#: The TSA fixtures (fixtures/sign/tsa): the request Folioxide writes, answered by two TSAs.
TSA_DIR = "tsa"
TSA_NONCE = 0x0102030405060708


def _pyhanko_signer(name: str):
    from pyhanko.sign import signers

    if name == "signer-p256":  # the PKCS#12 route, as the Node tests use it
        signer = signers.SimpleSigner.load_pkcs12(str(PKI / "signer-p256-modern.p12"),
                                                  passphrase=PASSWORD.encode())
    else:
        signer = signers.SimpleSigner.load(str(PKI / f"{name}.key.pem"), str(PKI / f"{name}.pem"),
                                           ca_chain_files=(str(PKI / "intermediate.pem"),))
    if signer is None:
        raise RuntimeError(f"pyHanko could not load {name}")
    return signer


def _dummy_tsa():
    from pyhanko.keys import load_cert_from_pemder, load_private_key_from_pemder
    from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper

    return DummyTimeStamper(tsa_cert=load_cert_from_pemder(str(PKI / "tsa.pem")),
                            tsa_key=load_private_key_from_pemder(str(PKI / "tsa.key.pem"), passphrase=None))


def _sign_pdf(data: bytes, how: str, details: dict, work: Path) -> bytes:
    import io

    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields, signers

    writer = IncrementalPdfFileWriter(io.BytesIO(data))
    field = details["field"]
    if how == "empty-field":
        fields.append_signature_field(writer, fields.SigFieldSpec(sig_field_name=field))
        out = io.BytesIO()
        writer.write(out)
        return out.getvalue()
    if how == "timestamp":
        out = io.BytesIO()
        signers.PdfTimeStamper(timestamper=_dummy_tsa(), field_name=field).timestamp_pdf(
            writer, md_algorithm="sha256", output=out)
        return out.getvalue()
    subfilter = (fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED if details.get("pkcs7") or how == "openssl"
                 and not details.get("cades") else fields.SigSeedSubFilter.PADES)
    meta = signers.PdfSignatureMetadata(field_name=field, subfilter=subfilter,
                                        md_algorithm=details.get("md", "sha256"))
    if how == "certify":
        meta = signers.PdfSignatureMetadata(field_name=field, subfilter=subfilter, certify=True,
                                            docmdp_permissions=fields.MDPPerm(details["p"]))
    if how in ("pyhanko", "certify"):
        timestamper = _dummy_tsa() if details.get("timestamp") else None
        new_field = None
        if "box" in details:
            new_field = fields.SigFieldSpec(sig_field_name=field, box=details["box"])
        return signers.sign_pdf(writer, meta, signer=_pyhanko_signer(details["signer"]),
                                timestamper=timestamper, new_field_spec=new_field).getvalue()
    if how == "openssl":
        return asyncio.run(_openssl_signed_pdf(writer, meta, details, work))
    raise ValueError(how)


async def _openssl_signed_pdf(writer, meta, details: dict, work: Path) -> bytes:
    """pyHanko prepares the placeholder and the byte ranges; `openssl cms -sign` signs them;
    pyHanko embeds that CMS unchanged."""
    from pyhanko.keys import load_cert_from_pemder
    from pyhanko.sign import signers
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    signer = details["signer"]
    cert = load_cert_from_pemder(str(PKI / f"{signer}.pem"))
    registry = SimpleCertificateStore.from_certs([load_cert_from_pemder(str(PKI / "intermediate.pem"))])
    placeholder = signers.ExternalSigner(signing_cert=cert, cert_registry=registry, signature_value=bytes(512))
    pdf_signer = signers.PdfSigner(meta, signer=placeholder)
    prepared, _tbs, output = await pdf_signer.async_digest_doc_for_signing(writer, bytes_reserved=16384)
    buffer = output.getvalue()
    signed = buffer[: prepared.reserved_region_start] + buffer[prepared.reserved_region_end:]
    content = work / "openssl-signed.bin"
    content.write_bytes(signed)
    cms_path = work / "openssl.p7s"
    args = ["cms", "-sign", "-binary", "-outform", "DER", "-nosmimecap", "-md", details["md"],
            "-in", str(content), "-signer", str(PKI / f"{signer}.pem"),
            "-inkey", str(PKI / f"{signer}.key.pem"), "-certfile", str(PKI / "intermediate.pem"),
            "-out", str(cms_path)]
    if details["cades"]:
        args.append("-cades")
    openssl(*args)
    prepared.fill_with_cms(output, cms_path.read_bytes())
    return output.getvalue()


def write_pdfs(out: Path, work: Path, only: tuple[str, ...] = ()) -> None:
    """The signed PDFs (PDFS), in order: later entries may build on earlier ones. With `only`,
    just those PDFs are written, on top of the committed bases."""
    import logging

    logging.disable(logging.WARNING)
    pdf_out = out / PDF_DIR
    pdf_out.mkdir()
    unknown = sorted(set(only) - set(PDFS))
    if unknown:
        raise ValueError(f"unknown PDF fixture(s) {unknown}")
    for name, (base, how, details) in PDFS.items():
        if only and name not in only:
            continue
        if base == "minimal":
            data = MINIMAL.read_bytes()
        elif (pdf_out / base).is_file():
            data = (pdf_out / base).read_bytes()
        else:
            data = (OUT_DIR / PDF_DIR / base).read_bytes()
        (pdf_out / name).write_bytes(_sign_pdf(data, how, details, work))


def write_tsa(out: Path, work: Path) -> None:
    """The TSA fixtures: Folioxide's request (from the Rust test), answered by `openssl ts
    -reply` and by pyHanko's DummyTimeStamper."""
    import os

    tsa_out = out / TSA_DIR
    tsa_out.mkdir()
    request = work / "request.tsq"
    env = dict(os.environ, FOLIOXIDE_TSA_REQUEST_OUT=str(request))
    run(["cargo", "test", "-p", "folioxide-sign", "--test", "bt_sign", "--",
         "--exact", "bt_external_openssl_token_embedded"], cwd=REPO_ROOT, env=env)
    if not request.is_file():
        raise RuntimeError("the Rust test did not write the request")
    serial_dir = work / "openssl-tsa"
    serial_dir.mkdir()
    (serial_dir / "tsaserial").write_text("01\n", encoding="ascii")
    env = dict(os.environ, FOLIOXIDE_TSA_DIR=str(serial_dir))
    run(["openssl", "ts", "-reply", "-config", "tools/tsa/openssl-tsa.cnf", "-queryfile", str(request),
         "-out", str(tsa_out / "openssl-reply.tsr")], cwd=REPO_ROOT, env=env)
    shutil.copyfile(request, tsa_out / "openssl-reply.tsq")
    shutil.copyfile(request, tsa_out / "pyhanko-dummy.tsq")
    from asn1crypto import tsp

    req = tsp.TimeStampReq.load(request.read_bytes())
    resp = asyncio.run(_dummy_tsa().async_request_tsa_response(req))
    (tsa_out / "pyhanko-dummy.tsr").write_bytes(resp.dump())


def check_tsa(expect) -> None:
    """The TSA fixtures: Folioxide's request shape, and each reply verifies with `openssl ts
    -verify -queryfile` against the TSA root."""
    from asn1crypto import tsp

    for stem in ("openssl-reply", "pyhanko-dummy"):
        tsq = OUT_DIR / TSA_DIR / f"{stem}.tsq"
        tsr = OUT_DIR / TSA_DIR / f"{stem}.tsr"
        if not (tsq.is_file() and tsr.is_file()):
            expect(False, f"{TSA_DIR}/{stem}.tsq or .tsr is missing")
            continue
        req = tsp.TimeStampReq.load(tsq.read_bytes())
        expect(req["nonce"].native == TSA_NONCE and req["cert_req"].native is True
               and req["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha256",
               f"{stem}.tsq is not Folioxide's SHA-256 request with nonce {TSA_NONCE:#x}")
        result = subprocess.run(
            ["openssl", "ts", "-verify", "-queryfile", str(tsq), "-in", str(tsr),
             "-CAfile", str(PKI / "tsa-root.pem")],
            capture_output=True, text=True, check=False)
        expect("Verification: OK" in result.stdout + result.stderr,
               f"openssl ts -verify {stem}: {(result.stdout + result.stderr).strip()}")
        resp = tsp.TimeStampResp.load(tsr.read_bytes())
        expect(resp["status"]["status"].native == "granted", f"{stem}.tsr is not granted")
    dummy = tsp.TimeStampResp.load((OUT_DIR / TSA_DIR / "pyhanko-dummy.tsr").read_bytes())
    signed = dummy["time_stamp_token"]["content"]
    attrs = {a["type"].native for a in signed["signer_infos"][0]["signed_attrs"]}
    expect("signing_certificate" in attrs and "signing_certificate_v2" not in attrs,
           "pyhanko-dummy.tsr does not carry ESS signing-certificate v1 only")
    gen_time = signed["encap_content_info"]["content"].parsed["gen_time"]
    expect(b"." in gen_time.contents, "pyhanko-dummy.tsr genTime has no fraction")


def check_pdfs(expect) -> None:
    """Every PDF: its base is a byte prefix, and every oracle of the suite (pyHanko, pdfsig,
    OpenSSL, the structural and PAdES checks) says what PDF_EXPECTED says."""
    import logging

    logging.disable(logging.WARNING)
    oracles = REPO_ROOT / "tools" / "oracles"
    if str(oracles) not in sys.path:
        sys.path.insert(0, str(oracles))
    import validate_sig  # noqa: PLC0415 - the oracle module, found through sys.path

    for name, (base, how, _details) in PDFS.items():
        path = OUT_DIR / PDF_DIR / name
        if not path.is_file():
            expect(False, f"{PDF_DIR}/{name} is missing")
            continue
        data = path.read_bytes()
        base_data = MINIMAL.read_bytes() if base == "minimal" else (OUT_DIR / PDF_DIR / base).read_bytes()
        expect(data.startswith(base_data) and len(data) > len(base_data),
               f"{name} does not extend {base} (incremental update)")
        results = validate_sig.check_signatures(path, PDF_EXPECTED[name], [PKI / "root.pem"])
        failing = [f"{r.name}: {r.detail}" for r in results if not r.ok]
        expect(not failing, f"{name}: {failing}")
        if how == "empty-field":
            import pypdf

            reader = pypdf.PdfReader(path)
            fields = [f.get_object() for f in reader.trailer["/Root"]["/AcroForm"]["/Fields"]]
            expect([(f.get("/T"), f.get("/FT"), "/V" in f) for f in fields] == [("Approval", "/Sig", False)],
                   f"{name}: expected one empty signature field Approval")
    # The SWA mutators need a signature dictionary whose /Contents precedes its /ByteRange: the
    # /ByteRange key lies after the gap, in the second signed range.
    import re

    rsa = OUT_DIR / PDF_DIR / "pyhanko-rsa2048.pdf"
    data = rsa.read_bytes() if rsa.is_file() else b""
    match = re.search(rb"/ByteRange\s*\[\s*0\s+(\d+)\s+(\d+)", data)
    expect(match is not None and match.start() >= int(match.group(2)),
           "pyhanko-rsa2048.pdf: /Contents does not precede /ByteRange")


def tlv(data: bytes, pos: int) -> tuple[int, int, int, int]:
    """(tag, content start, content end, element end) of the DER element at pos."""
    tag = data[pos]
    first = data[pos + 1]
    if first < 0x80:
        return tag, pos + 2, pos + 2 + first, pos + 2 + first
    count = first & 0x7F
    length = int.from_bytes(data[pos + 2 : pos + 2 + count], "big")
    start = pos + 2 + count
    return tag, start, start + length, start + length


def children(data: bytes, start: int, end: int) -> list[tuple[int, int, int, int, int]]:
    out = []
    pos = start
    while pos < end:
        tag, cstart, cend, eend = tlv(data, pos)
        out.append((pos, tag, cstart, cend, eend))
        pos = eend
    return out


def indefinite(data: bytes, pos: int, descend) -> bytes:
    """Re-encodes the constructed element at pos with an indefinite length (X.690 §8.1.3.6);
    `descend(path_index, tag)` says which children get the same treatment."""
    tag, cstart, cend, _ = tlv(data, pos)
    body = b""
    for index, (cpos, ctag, _, _, ceend) in enumerate(children(data, cstart, cend)):
        sub = descend(index, ctag)
        body += indefinite(data, cpos, sub) if sub is not None else data[cpos:ceend]
    return bytes([tag, 0x80]) + body + b"\x00\x00"


def ber_from_der(der: bytes) -> bytes:
    """ContentInfo, [0], SignedData, encapContentInfo, signerInfos and the SignerInfo become
    indefinite; digestAlgorithms, certificates and signedAttrs keep their DER encoding."""
    never = lambda index, tag: None  # noqa: E731
    signer_info = never
    signer_infos = lambda index, tag: signer_info  # noqa: E731

    def signed_data(index, tag):
        if tag == 0x30 and index == 2:  # encapContentInfo
            return never
        if tag == 0x31 and index > 2:  # signerInfos
            return signer_infos
        return None

    explicit = lambda index, tag: signed_data  # noqa: E731
    content_info = lambda index, tag: explicit if tag == 0xA0 else None  # noqa: E731
    return indefinite(der, 0, content_info)


def write_openssl_cms(out: Path) -> None:
    data = out / "data.bin"
    for name, (signer, extra) in OPENSSL_CMS.items():
        openssl("cms", "-sign", "-binary", "-outform", "DER", "-nosmimecap", "-in", str(data),
                "-signer", str(PKI / f"{signer}.pem"), "-inkey", str(PKI / f"{signer}.key.pem"),
                "-certfile", str(PKI / "intermediate.pem"), *extra, "-out", str(out / name))
    openssl("cms", "-sign", "-binary", "-outform", "DER", "-nosmimecap", "-md", "sha256",
            "-in", str(data), "-signer", str(out / "long-serial.pem"),
            "-inkey", str(out / "long-serial.key.pem"), "-out", str(out / "openssl-long-serial.p7s"))
    for name, (key, digest) in GOLDEN.items():
        openssl("dgst", f"-{digest}", "-sign", str(PKI / f"{key}.key.pem"), "-out", str(out / name),
                str(data))
    (out / BER_OUTPUT).write_bytes(ber_from_der((out / BER_SOURCE).read_bytes()))


async def write_pyhanko_cms(out: Path) -> None:
    from pyhanko.sign.signers.pdf_cms import SimpleSigner

    for name, (signer_name, digest, pss) in PYHANKO_CMS.items():
        signer = SimpleSigner.load(
            str(PKI / f"{signer_name}.key.pem"),
            str(PKI / f"{signer_name}.pem"),
            ca_chain_files=(str(PKI / "intermediate.pem"),),
            prefer_pss=pss,
        )
        if signer is None:
            raise RuntimeError(f"pyHanko could not load {signer_name}")
        import hashlib

        content_info = await signer.async_sign(
            hashlib.new(digest, DATA).digest(), digest, use_pades=True
        )
        (out / name).write_bytes(content_info.dump())


#: The groups of files `generate` can write; `--only` picks some of them.
GROUPS = ("cms", "chain", "pdf", "tsa")


def generate(groups: tuple[str, ...] = GROUPS, pdfs: tuple[str, ...] = ()) -> int:
    """Writes the files of `groups` (the CMS vectors and key files, the chain certificates, the
    signed PDFs), then checks everything."""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        out = work / "out"
        out.mkdir()
        if "cms" in groups:
            (out / "data.bin").write_bytes(DATA)
            write_keys(out, work)
            write_openssl_cms(out)
            asyncio.run(write_pyhanko_cms(out))
        if "chain" in groups:
            write_chain(out, work)
        if "pdf" in groups:
            write_pdfs(out, work, pdfs)
        if "tsa" in groups:
            write_tsa(out, work)
        written = 0
        for f in sorted(out.rglob("*")):
            if f.is_file():
                target = OUT_DIR / f.relative_to(out)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(f, target)
                written += 1
        print(f"sign.py: wrote {written} files to {OUT_DIR}")
    return check()


async def pyhanko_status(path: Path):
    import logging

    # pyHanko logs the SHA-1 policy failure of the legacy vector with a traceback; the status
    # (intact, valid, untrusted) is what is checked.
    logging.disable(logging.CRITICAL)
    from asn1crypto import cms, pem, x509
    from pyhanko.sign.validation.generic_cms import async_validate_detached_cms
    from pyhanko_certvalidator import ValidationContext

    roots = []
    for root_file in (PKI / "root.pem", OUT_DIR / "long-serial.pem"):
        _, _, der = pem.unarmor(root_file.read_bytes())
        roots.append(x509.Certificate.load(der))
    signed_data = cms.ContentInfo.load(path.read_bytes())["content"]
    context = ValidationContext(trust_roots=roots, allow_fetching=False)
    return await async_validate_detached_cms(
        DATA, signed_data, signer_validation_context=context
    )


#: The validation time of the chain checks (and of the Rust chain tests).
CHAIN_MOMENT = "2026-10-10T12:00:00+00:00"


def _load_cert(path: Path):
    from asn1crypto import pem, x509

    data = path.read_bytes()
    if pem.detect(data):
        _, _, data = pem.unarmor(data)
    return x509.Certificate.load(data)


def _chain_issuer(name: str, issuer: str):
    if issuer == "self":
        return _load_cert(OUT_DIR / CHAIN_DIR / f"{name}.pem")
    if issuer.startswith("pki:"):
        return _load_cert(PKI / f"{issuer.split(':', 1)[1]}.pem")
    return _load_cert(OUT_DIR / CHAIN_DIR / f"{issuer}.pem")


async def _certvalidator_verdict(cert, roots, others) -> tuple[bool, str]:
    """pyhanko-certvalidator's verdict for a signer certificate at CHAIN_MOMENT."""
    from datetime import datetime

    from pyhanko_certvalidator import CertificateValidator, ValidationContext

    context = ValidationContext(trust_roots=roots, other_certs=others, allow_fetching=False,
                                moment=datetime.fromisoformat(CHAIN_MOMENT))
    validator = CertificateValidator(cert, validation_context=context)
    try:
        await validator.async_validate_usage({"non_repudiation"})
    except Exception as exc:  # noqa: BLE001 - every validation error is a verdict
        return False, f"{type(exc).__name__}: {exc}"
    return True, ""


def check_chain(expect) -> None:
    """The chain certificates: names, fixed validity, issuer signatures, the extensions that make
    each case, and pyhanko-certvalidator's verdict (CHAIN_EXPECTED)."""
    from datetime import datetime, timezone

    from pyhanko_certvalidator.sig_validate import DefaultSignatureValidator

    validator = DefaultSignatureValidator()
    not_before = datetime(2025, 1, 1, tzinfo=timezone.utc)
    not_after = datetime(2075, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    certs = {}
    for name, (issuer, _spec, cn, ext, md, extra) in CHAIN.items():
        path = OUT_DIR / CHAIN_DIR / f"{name}.pem"
        if not path.is_file():
            expect(False, f"{CHAIN_DIR}/{name}.pem is missing")
            continue
        cert = _load_cert(path)
        certs[name] = cert
        expect(cert.subject.native.get("common_name") == cn, f"{name}: CN is not {cn!r}")
        validity = cert["tbs_certificate"]["validity"]
        expect(validity["not_before"].native == not_before and validity["not_after"].native == not_after,
               f"{name}: validity is not 2025-01-01 .. 2075-12-31")
        issuer_cert = _chain_issuer(name, issuer)
        expect(cert.issuer == issuer_cert.subject, f"{name}: issuer name is not {issuer}'s subject")
        try:
            validator.validate_signature(
                signature=cert["signature_value"].native,
                signed_data=cert["tbs_certificate"].dump(),
                public_key_info=issuer_cert.public_key,
                signature_algorithm=cert["signature_algorithm"],
            )
            signed = True
        except Exception:  # noqa: BLE001
            signed = False
        expect(signed, f"{name}: the signature does not verify with {issuer}'s key")
        algorithm = cert["signature_algorithm"].signature_algo
        hash_algo = cert["signature_algorithm"].hash_algo
        expect(hash_algo == md, f"{name}: signed with {hash_algo}, not {md}")
        if extra:
            expect(algorithm == "rsassa_pss", f"{name}: signed with {algorithm}, not RSASSA-PSS")
        expect(cert.ca == (ext in ("ext_ca", "ext_ca_no_certsign")), f"{name}: unexpected CA flag")
        if ext == "ext_unknown_critical":
            expect("1.3.6.1.4.1.32473.1" in cert.critical_extensions,
                   f"{name}: no critical 1.3.6.1.4.1.32473.1 extension")
        if ext == "ext_ca_no_certsign":
            expect("key_cert_sign" not in cert.key_usage_value.native, f"{name}: has keyCertSign")

    if len(certs) != len(CHAIN):
        return
    root = _load_cert(PKI / "root.pem")
    intermediate = _load_cert(PKI / "intermediate.pem")
    others = [intermediate, _load_cert(PKI / "signer-p256.pem")]
    others += [certs[n] for n, entry in CHAIN.items() if entry[3].startswith("ext_ca")]
    for name, (trusted, fragment) in CHAIN_EXPECTED.items():
        ok, error = asyncio.run(_certvalidator_verdict(certs[name], [root], others))
        expect(ok == trusted and fragment in error,
               f"pyhanko-certvalidator on {name}: trusted={ok} ({error}); expected trusted={trusted}"
               + (f" with {fragment!r}" if fragment else ""))
    # The self-signed signer is trusted when it is its own anchor; a root with the real root's
    # name but another key anchors nothing.
    ok, error = asyncio.run(_certvalidator_verdict(certs["self-signed"], [certs["self-signed"]], []))
    expect(ok, f"pyhanko-certvalidator on self-signed as its own root: {error}")
    # An intermediate as the trust anchor: its own pathLenConstraint is not applied to the path
    # below it (RFC 5280 §6.1.1 (d): an anchor is a name and a key).
    ok, error = asyncio.run(_certvalidator_verdict(certs["sub-ca-signer"], [intermediate], [certs["sub-ca"]]))
    expect(ok, f"pyhanko-certvalidator on sub-ca-signer under the intermediate as anchor: {error}")
    signer = _load_cert(PKI / "signer-p256.pem")
    ok, error = asyncio.run(_certvalidator_verdict(signer, [certs["impostor-root"]], [intermediate]))
    expect(not ok, "pyhanko-certvalidator trusts signer-p256 under impostor-root")
    ok, error = asyncio.run(_certvalidator_verdict(signer, [root], [intermediate]))
    expect(ok, f"pyhanko-certvalidator on signer-p256: {error}")


def check() -> int:
    failures: list[str] = []
    passed = 0

    def expect(ok: bool, what: str) -> None:
        nonlocal passed
        if ok:
            passed += 1
        else:
            failures.append(what)

    data = OUT_DIR / "data.bin"
    expect(data.read_bytes() == DATA, "data.bin differs from DATA")
    cms_files = [*OPENSSL_CMS, "openssl-long-serial.p7s", BER_OUTPUT, *PYHANKO_CMS]
    for name in cms_files:
        path = OUT_DIR / name
        ca = OUT_DIR / "long-serial.pem" if name == "openssl-long-serial.p7s" else PKI / "root.pem"
        content = [] if name in ATTACHED else ["-content", str(data)]
        result = subprocess.run(
            ["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", str(path),
             *content, "-CAfile", str(ca), "-purpose", "any", "-out", "/dev/null"],
            capture_output=True, text=True, check=False)
        expect("Verification successful" in result.stderr, f"openssl cms -verify {name}: "
               f"{result.stderr.strip()}")
        if name in ATTACHED:
            # pyHanko's validator is for detached signatures only; OpenSSL checked it above.
            continue
        status = asyncio.run(pyhanko_status(path))
        expect(status.intact and status.valid, f"pyHanko {name}: intact={status.intact} "
               f"valid={status.valid}")
    for name in ("openssl-p256-ber-attached.p7s", BER_OUTPUT):
        ber = (OUT_DIR / name).read_bytes()
        expect(ber[:2] == b"\x30\x80", f"{name} does not start with an indefinite length")
    expect(ber_from_der((OUT_DIR / BER_SOURCE).read_bytes()) == (OUT_DIR / BER_OUTPUT).read_bytes(),
           f"{BER_OUTPUT} is not the indefinite-length form of {BER_SOURCE}")
    for name, (key, digest) in GOLDEN.items():
        result = subprocess.run(
            ["openssl", "dgst", f"-{digest}", "-prverify", str(PKI / f"{key}.key.pem"),
             "-signature", str(OUT_DIR / name), str(data)],
            capture_output=True, text=True, check=False)
        expect("Verified OK" in result.stdout, f"{name} does not verify: {result.stdout}")
        again = openssl("dgst", f"-{digest}", "-sign", str(PKI / f"{key}.key.pem"), str(data)).stdout
        expect(again == (OUT_DIR / name).read_bytes(), f"{name} is not the deterministic signature")
    headers = {
        "rsa1024.key.pem": "PRIVATE KEY",
        "p521.key.pem": "PRIVATE KEY",
        "ed25519.key.pem": "PRIVATE KEY",
        "long-serial.key.pem": "PRIVATE KEY",
        "signer-rsa2048.key.legacy-enc.pem": "RSA PRIVATE KEY",
        "signer-p256.key.pbes1.pem": "ENCRYPTED PRIVATE KEY",
    }
    for name, label in headers.items():
        first = (OUT_DIR / name).read_text(encoding="ascii").splitlines()[0]
        expect(first == f"-----BEGIN {label}-----", f"{name} is not PEM '{label}'")
    legacy = (OUT_DIR / "signer-rsa2048.key.legacy-enc.pem").read_text(encoding="ascii")
    expect("Proc-Type: 4,ENCRYPTED" in legacy, "the legacy key has no Proc-Type header")
    serial = openssl("x509", "-in", str(OUT_DIR / "long-serial.pem"), "-noout", "-serial").stdout
    expect(serial.decode().strip().endswith(LONG_SERIAL[2:].upper()), f"long-serial.pem: {serial!r}")
    info = subprocess.run(
        ["openssl", "pkcs12", "-info", "-noout", "-passin", f"pass:{PASSWORD}",
         "-in", str(OUT_DIR / "signer-p256-nomac.p12")],
        capture_output=True, text=True, check=False)
    expect("MAC:" not in info.stderr + info.stdout, "signer-p256-nomac.p12 has a MAC")

    check_chain(expect)
    check_pdfs(expect)
    check_tsa(expect)

    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if failures:
        print(f"sign.py --check: {len(failures)} failed, {passed} passed", file=sys.stderr)
        return 1
    print(f"sign.py --check: all {passed} checks passed ({OUT_DIR})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="verify the committed files")
    parser.add_argument("--only", action="append", choices=GROUPS,
                        help="regenerate only this group (repeatable); the others stay as committed")
    parser.add_argument("--pdf", action="append", default=[], metavar="NAME",
                        help="with the pdf group, regenerate only this PDF (repeatable)")
    args = parser.parse_args()
    if shutil.which("openssl") is None:
        print("sign.py: openssl not found", file=sys.stderr)
        return 2
    try:
        import pyhanko  # noqa: F401
    except ImportError:
        print("sign.py: pyHanko is missing; run bash tools/setup-venv.sh", file=sys.stderr)
        return 2
    return check() if args.check else generate(tuple(args.only or GROUPS), tuple(args.pdf))


if __name__ == "__main__":
    sys.exit(main())

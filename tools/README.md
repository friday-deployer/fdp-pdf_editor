# Developer tools

Dev-only helpers. Nothing here is linked into Folioxide: the oracles are external processes
(docs/DECISIONS.md D6), and their GPL/MPL licenses never reach the crates.

| Path | Purpose |
|---|---|
| `setup-venv.sh` | creates `<repo>/.venv` with the pinned oracle packages (`requirements-dev.txt`); idempotent |
| `requirements-dev.txt` | exact pins: pyHanko, pypdf, pikepdf, pyhanko-certvalidator, asn1crypto, PyYAML |
| `gen-pki.sh` | generates the test PKI in `fixtures/pki/`; `--check` validates the committed files |
| `fixtures/qpdf.py` | writes the qpdf-linearized fixtures in `fixtures/qpdf/` (oracle venv); `--check` regenerates and compares them |
| `fixtures/sign.py` | writes the CMS vectors, key files, trust-path certificates, signed PDFs and TSA replies in `fixtures/sign/` (oracle venv, OpenSSL, cargo for `tsa`; `--only cms|chain|pdf|tsa` for one group, `--pdf NAME` for one PDF); `--check` verifies them with OpenSSL, pyHanko, pyhanko-certvalidator and the signature oracles |
| `tsa/openssl-tsa.cnf` | `openssl ts -reply` configuration for the fixture TSA |
| `oracles/` | cross-validation scripts and their self-tests |

Requirements: Python 3.11+ (CI uses 3.13), OpenSSL 3.x with the legacy provider, poppler-utils
(`pdfinfo`, `pdfsig`, `pdftotext`).

```
bash tools/setup-venv.sh                                         # once
.venv/bin/python -I -m unittest discover -s tools/oracles/tests  # oracle self-tests
bash tools/gen-pki.sh --check                                    # validate fixtures/pki
.venv/bin/python -I tools/fixtures/qpdf.py --check               # validate fixtures/qpdf
.venv/bin/python -I tools/fixtures/sign.py --check               # validate fixtures/sign (CMS, chain, signed PDFs)
cargo xtask oracle [--suite <name>]                              # Rust-emitted cases
```

## Oracles

Each module has a CLI (`--help`) and is importable. All exit `0` on success, `1` when a check
fails and `2` on a usage or environment error (missing tool or module, bad expectation).
`run_suite.py` exits `1` whenever any check failed, even if another case ended in ERROR; it
exits `2` only when nothing failed but something could not be evaluated.

| Module | Checks |
|---|---|
| `oracles/run_suite.py` | the runner: `python -I tools/oracles/run_suite.py DIR...` |
| `oracles/check_pdf.py` | structure (pdfinfo exit 0 and no syntax errors; pikepdf `check_pdf_syntax()`; pypdf `strict=True` reads every page), page count, effective version, Info entries, in-use object count (pikepdf), page boxes and rotation (`pdfinfo -box`) |
| `oracles/validate_sig.py` | pyHanko `intact`/`valid`/`trusted`/coverage/modification/DocMDP/timestamp, cross-checked for every signature with the structural checks, `pdfsig -nocert` and `openssl cms -verify` / `openssl ts -verify` |
| `oracles/extract_cms.py` | slices `/Contents` DER and the signed byte ranges out of the file for `openssl cms -verify` / `openssl ts -verify`; structural checks: ByteRange starts at 0, gap is the dictionary's own `/Contents`, only zero padding after the CMS |
| `oracles/pades_profile.py` | PAdES baseline: SubFilter, content-type, message-digest, signing-certificate-v2 present, signing-time absent, B-B/B-T level |
| `oracles/text_check.py` | `pdftotext` contains / lacks strings |
| `oracles/render_check.py` | `renderProbes`: dark pixels inside and outside a default-user-space rectangle of `pdftoppm -r 72 -gray -cropbox`, mapped through the crop box and `/Rotate` (M4 brief D-22) |

### `expect.json` reference

Tests built with `folioxide-testkit/emit` write `target/oracle/<suite>/<name>.pdf` next to
`<name>.expect.json`. Every case that is not skipped runs the structural checks; each key adds
checks:

```jsonc
{
  "pages": 2,                                   // pdfinfo, pikepdf and pypdf page counts
  "version": "1.7",                             // max(header, catalog /Version)
  "info": {"Title": "Report", "ModDate": null}, // null = absent; dates raw ("D:2026...Z")
  "textContains": ["Hello"],                    // pdftotext, whitespace-normalised
  "textAbsent": ["secret"],
  "prefixOf": "input.pdf",                      // incremental save kept every original byte
  "revisions": 2,                               // startxref count and pyHanko's revision count
  "objectCount": 7,                             // in-use objects: pikepdf len(pdf.objects) minus its nulls
  "boxes": [{"mediaBox": [0, 0, 595, 842], "cropBox": [0, 0, 595, 842], "rotation": 90,
             "width": 842, "height": 595}], // per page (PageInfo JSON): pdfinfo -box -f 1 -l N
  "renderProbes": [{"page": 0, "rect": [300, 100, 500, 160], "minDark": 50, "maxDarkOutside": 900}],
                                                // dark (< 128) pixels of pdftoppm -r 72 -gray -cropbox in / outside a
                                                // default-user-space rect (through the crop box and /Rotate); page 0-based
  "knownFailures": {"structure.pypdf": "why"},  // still run; a failure is XFAIL, a pass is FAIL (stale)
  "oracleSkip": "why",                          // SKIP: no check runs (files the oracles would repair)
  "trustRoots": ["fixtures/pki/root.pem"],      // trust anchors for "trusted"
  "signatures": [{
    "field": "Signature1",                      // match by name (else by position)
    "intact": true, "valid": true,              // default true; a tamper case sets "intact": false
    "trusted": true,                            // chain to trustRoots (also makes OpenSSL use -CAfile)
    "coverage": "entireFile",                   // entireFile | entireRevision | contiguousBlockFromStart | unclear
    "modification": "none",                     // none | ltaUpdates | formFilling | annotations | other | null
    "docmdp": null, "docmdpOk": true,           // certification level P (1-3) or null
    "pades": "B-B",                             // true | false | "B-B" | "B-T"
    "timestamp": false,                         // true: token present, pyHanko intact+valid, openssl ts -verify OK;
                                                // false: no token; "invalid": present, pyHanko not intact+valid,
                                                // and openssl ts -verify fails (M4 D-22)
    "timestampTrusted": true                    // pyHanko timestamp_validity.trusted (needs trustRoots)
  }, {
    "field": "Signature2", "rejected": true     // negative case (D-3): every oracle must reject it
  }]
}
```

Every `signatures` entry, even `{"field": "Signature1"}`, runs the structural checks
(`byteRange`, `gap`, `padding`, which no expectation can waive), `pdfsig` (signatures only;
poppler cannot validate document timestamps) and OpenSSL. The cross-checks must succeed exactly
when `intact` and `valid` are both expected. OpenSSL validates the chain only for
`"trusted": true`; otherwise it checks the digest and the signature value (`cms -verify
-noverify`, or `ts -verify -partial_chain` anchored at the token's own certificates).

`"rejected": true` (M3 brief D-3, for the USF attack cases) takes no key but `field` and expects
every oracle to reject the signature: pyHanko raises or reports `intact`/`valid` false
(`rejected.pyhanko`), `pdfsig` does not print "Signature is Valid." (`rejected.pdfsig`), and the
OpenSSL route fails, either at the extraction (no usable `/ByteRange`, a gap that is not the
dictionary's own `/Contents` `<hex>` string) or at `openssl cms -verify` (`rejected.openssl`).
The structure rows are not reported for it. pyHanko reads the signatures one at a time, so a
broken signature does not hide the others. With a rejected entry every entry must name its
`field` (unless there is only one), and the counts only require that no more signatures are
listed than there are entries.

`objectCount` counts the in-use objects of the merged cross-reference data that resolve to a
non-null object; `check_pdf.check_object_count` documents exactly how pikepdf's count is
adjusted. `boxes` has one entry per page in Folioxide's `PageInfo` JSON shape and one check per
page and value (`boxes[0].rotation.pdfinfo`); `check_pdf.check_boxes` documents the poppler quirks
(raw `/Rotate 45`, an ignored `/Rotate 90.0`, oversized crop boxes) that cases waive with
`knownFailures`. `oracleSkip` and `knownFailures` cannot be combined, and `knownFailures` may only name
checks the case runs. The `syntax` suite (M1) uses all three.

Relative paths resolve against the expect.json's directory first, then the repository root.
The keys `encrypted`, `xmpContains`, `fields`, `annots`, `fontsEmbedded` and `images` are reserved
for later milestones: until their check is registered in `run_suite.py` (`@register("key")`),
using one exits `2` with "check not implemented yet". Any other key is an error too.

## Test TSA

```
export FOLIOXIDE_TSA_DIR="$(mktemp -d)"     # writable: openssl keeps its serial file here
openssl ts -query -data doc.bin -sha256 -cert -out req.tsq
openssl ts -reply -config tools/tsa/openssl-tsa.cnf -queryfile req.tsq -out resp.tsr
openssl ts -verify -data doc.bin -in resp.tsr -CAfile fixtures/pki/tsa-root.pem   # Verification: OK
```

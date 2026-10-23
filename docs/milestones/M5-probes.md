<!-- Evidence for docs/milestones/M5.md §0, from the M5 stage-0 reference probes (read-only QA, 2026-10-23). Re-run with the probe harness (archived by the manager). Rulings R-1 to R-6 in DECISIONS D15 apply it. -->

# M5 stage-0 reference probes: evidence report

**Script:** `/tmp/m5-probes/run_probes.sh`. It re-runs every probe in about a minute and prints the results. Verbatim output per probe is in `/tmp/m5-probes/results/<probe>.out` (all of it in `/tmp/m5-probes/results_all.out`). Crafted PDFs are in `/tmp/m5-probes/out/`. Helpers sit next to the script: `common.py`, `mkenc.py`, `legacy.py`, `pdfjs_open.mjs`, and `p1.py`…`p17.py`. The last run exited 0 with no tracebacks. The repository was not touched.


**Versions probed:** pikepdf 10.16.0 (libqpdf 12.4.2), pypdf 6.20.0, pyHanko 0.37.0, cryptography 50.0.2, poppler 24.02.0, OpenSSL 3.0.13, node 22.22.

**Deviations from the brief's setup (the brief's "read-only" rule was kept):**
1. **No qpdf CLI.** I could not fetch it (GitHub access was refused). `qpdf --pages` is EMULATED with pikepdf: `pages.append()` per foreign page, then libqpdf's `AcroForm.fix_copied_annotations`. The CLI's exact glue code is therefore unverified (P-11, P-15).
2. **`tools/fixtures/encrypt.py` does not exist yet.** It is planned for WP5.1A. P-4 and the other crafted-file probes use my own `mkenc.py` and `legacy.py`. These take keys from a pikepdf-encrypted file, or derive Algorithms 2/3/5 themselves (checked against qpdf: O, U and key match).
3. **pdf.js is not in the repo.** I installed `pdfjs-dist@6.4.299` from npm into `/tmp/m5-probes/pdfjs` and ran it from node. The brief says "master", so treat pdf.js results as that version. I also read its `build/pdf.worker.mjs` for source facts.
4. **pikepdf cannot write incremental updates.** For P-8 I emulated them by appending a raw revision, and also tried a full pikepdf re-save.
5. **pikepdf `Pdf.open(hex_password=True)` means "the password is the hex encryption KEY"** and opens anything. I did not use it.

---

## Summary table

| Probe | Result vs brief §0 |
|---|---|
| P-1 methods × readers, `Encrypted:` format | CONFIRMS (flag semantics and R2 mapping need correction) |
| P-2 wrong / owner-only / empty-user / order | CONTRADICTS 2 cells (poppler "flags yes", pdf.js order); pypdf wording needs nuance |
| P-3 EncryptMetadata false | CONFIRMS qpdf; CONTRADICTS the poppler assumption; new facts on pdf.js, pypdf, pyHanko |
| P-4 EFF ≠ StmF, Identity cases | CONFIRMS E6 ("qpdf informational"); CONTRADICTS row 91 qpdf and pdf.js cells |
| P-5 per-stream `/Crypt` | New fact: qpdf REQUIRES `/Type /CryptFilterDecodeParms` |
| P-6 `Ⅸ`/`IX` | CONFIRMS (poppler FAILS; pdf.js OPENS); CONTRADICTS E11 and E12 |
| P-7 pyHanko on AES-256 | CONFIRMS |
| P-8 pyHanko MAC | CONFIRMS D-6 |
| P-9 page-tree helpers | CONFIRMS (with nuance) |
| P-10 pdfunite | Filled in |
| P-11 `qpdf --pages` field name | `name+1` (emulated) |
| Extras | See below |

---

## P-1. Each method × (pdfinfo, pdftotext, pypdf), with the `Encrypted:` format

**Commands** (script `p1.py`; `-upw u -opw o` used on pikepdf files made with `pikepdf.Encryption(user="u", owner="o", R=…)`; RC4 needs `aes=False, metadata=False`):
- `pdfinfo [-upw u | -opw o] F`
- `pdftotext [-upw u | -opw o] F -`
- `pypdf.PdfReader(F).decrypt(pw)` with `"u"`, `"o"`, `""`, `"bad"`

**Output:**
- `Encrypted:       yes (print:yes copy:yes change:yes addNotes:yes algorithm:RC4)` for R2 and R3.
- `algorithm:AES` for R4, and `algorithm:AES-256` for both R5 and R6.
- No password gives `Command Line Error: Incorrect password` (rc 1) for every method.
- `-upw u` and `-opw o` both open, and text is extracted.
- pypdf returns `USER_PASSWORD` (1) for `"u"` and `OWNER_PASSWORD` (2) for `"o"`.
- pypdf returns `NOT_DECRYPTED` (0) for `""` and `"bad"`.
- pikepdf and pdf.js open all five.
- pikepdf `R=5` emits `UserWarning: Encryption R=5 is deprecated`. It writes `/ExtensionLevel 3`; R6 writes `8`.

**CONFIRMS** "R5 poppler reads" and "pdfinfo prints print/copy/change/addNotes".

**Other facts for §4 of the brief:**
- **Headers written by qpdf:** RC4-40 → `%PDF-1.3`, RC4-128 → 1.4, AES-128 → 1.6, R5/R6 → 1.7.
- **R6 extensions:** R6 gets `/Extensions << /ADBE << /BaseVersion /1.7 /ExtensionLevel 8 >> >>`. This CONFIRMS §4.5's "qpdf's layout, probe P-1".
- **P bits (pdfinfo flags):** print = P bit 3, copy = bit 5, change = bit 4, addNotes = bit 6. Nothing is printed for bits 9–12.
- **`/P` values:** all permissions granted gives `-4` for R2, R3, R4 and R6. This CONFIRMS "all give -4".
- **"None give -3904" holds only for R3.**
  - R2 none-granted: `-64`. Bits 9–12 are written as 1, which CONFIRMS "For R2, bits 9–12 are written as 1".
  - R4 and R6 none-granted: `-3392`. Bit 10 stays 1 for **R4 as well as R6**; the brief says R6 only.
  - R3 none-granted: `-3904`.
- **R2 reading (§4.4, "bits 9–12 reported as granted when bits 4/6 grant them") is incomplete.** pikepdf's actual mapping for R2 is:
  - fillForms ← bit 6
  - accessibility ← bit 5
  - assemble ← bit 4
  - printHighRes ← bit 3
- **qpdf's `/Encrypt` dictionary:**
  - **V4 carries empty `/OE <> /UE <>`.** An R4 reader must not reject or "short-string" these; §1.2 lists OE/UE/Perms as "—" for V4.
  - **No `/Type /CryptFilter` in `/CF`.** Real example: `<< /CF << /StdCF << /AuthEvent /DocOpen /CFM /AESV2 /Length 16 >> >> /Filter /Standard /Length 128 /O <..> /OE <> /P -1028 /R 4 /StmF /StdCF /StrF /StdCF /U <..> /UE <> /V 4 >>`.

---

## P-2. Wrong password, owner-only, empty-user, order (poppler and pikepdf, plus pypdf and pdf.js)

**Commands (R3 and R6 files, user `u`, owner `o`, all permissions denied):**
- `pdfinfo -upw bad F`, `-opw bad`, `pdftotext -upw bad F -`, `pdfinfo F`
- `pdfinfo -upw u|-opw o|-opw o -upw u|-opw u|-upw o|-opw bad -upw u|-opw o -upw bad F`
- `Pdf.open(F, password=…)`, `PdfReader(F, password=…)`, `PdfReader(F).decrypt(…)`

**Wrong password:**
- **poppler:** `Command Line Error: Incorrect password` (rc 1). CONFIRMS "Incorrect password".
- **pikepdf:** `pikepdf._core.PasswordError: <path>: invalid password`. CONFIRMS.
- **pdf.js:** `PasswordException: Incorrect Password (code 2)`. Passing none gives `No password given (code 1)`.
- **pypdf:** `decrypt('bad')` returns `NOT_DECRYPTED` and does **not** raise. `PdfReader(F, password='bad')` raises `WrongPasswordError: Wrong password`. `PdfReader(F).pages[0]` raises `FileNotDecryptedError: File has not been decrypted`.
- **Brief claim:** "password given and wrong: `WrongPasswordError`; none given: … `FileNotDecryptedError`". This is true only through the constructor. Suggested wording: "constructor `password=` raises `WrongPasswordError`; `decrypt()` returns `NOT_DECRYPTED`".

**Empty user password:** opens with no password in poppler (rc 0), pikepdf, pdf.js and pypdf (auto-decrypted at construction). CONFIRMS row 89.

**Owner-only (user `u`, owner `o`):**
- **CONTRADICTS (row 88, poppler cell): "`-opw` opens, every flag yes".** `-opw o` opens, but on a permission-restricted file pdfinfo still prints `print:no copy:no change:no addNotes:no`.
  - Poppler's pdfinfo reports the raw P bits regardless of owner status.
  - Suggested correction: "`-opw` opens; the flags always show the P bits, never 'owner'".
  - pdf.js behaves the same: `getPermissions()` is built from P with no owner distinction.
- **Poppler option plumbing:**
  - `-opw o`, `-opw o -upw u`, `-opw bad -upw u` and `-opw o -upw bad` all open.
  - `-upw o` and `-opw u` fail with "Incorrect password". Poppler never tries `-upw` as an owner password.
- **`pdftotext` does not enforce copy permission in 24.02:** `-upw u` extracts text from a no-permission file.

**Try order, qpdf side:**
- **pikepdf has no "owner matched" flag** (the brief cites `owner_password_matched` [src]). `p.encryption` exposes only `user_password`:
  - R3 opened with the owner password: `b'u'`, the recovered user password.
  - R6 opened with the owner password: `b''`.
- **pypdf, same password for user and owner:** `OWNER_PASSWORD` (owner first). CONFIRMS.
- **pypdf, empty user and empty owner:** `decrypt('')` returns `OWNER_PASSWORD`. This supports "access = owner if the owner password is also empty".

**CONTRADICTS (row 87, pdf.js cell): "owner then user [probe]".** Source, `build/pdf.worker.mjs` lines 57775–57777: for R5/R6 `checkUserPassword` is tried first and `checkOwnerPassword` only if the password is non-empty. For R≤4 `#prepareKeyData(password as user)` runs first, then the user password is derived from the owner. So pdf.js tries user first. The order is not externally observable.

**Row 86, pdf.js cell:** passing a wrong password gives code 2 `INCORRECT_PASSWORD`; passing none gives code 1 `NEED_PASSWORD`.

**E10 (writing user non-empty, owner empty):**
- pikepdf does NOT refuse. The qpdf "refuses unless `--allow-insecure`" claim is CLI-level and not testable here.
- R6: `Encryption(user="u", owner="")` writes an empty owner password. `''` then opens in pikepdf and pypdf (`OWNER_PASSWORD`).
- R3: qpdf generates a random owner password, so `''` fails everywhere.

---

## P-3. EncryptMetadata false, both writers

**Commands** (`p3.py`, `p3b.py`):
- **pikepdf:** `Encryption(R=4 aes|rc4, R=6, metadata=False)`.
- **pyHanko:** `copy_into_new_writer` then `w.encrypt("o","u", encrypt_metadata=False, pdf_mac=False)`.
- **pypdf:** `PdfWriter.encrypt` (it has no EncryptMetadata option, so no pypdf-written variant).
- **Read side:** raw-byte scan of the catalog `/Metadata`, `pdfinfo -meta -upw u`, pypdf `xmp_metadata`, pdf.js `getMetadata()`.

**qpdf writer (R4 AES, R4 RC4, R6):**
- **Raw XMP is plain:** `<< /Subtype /XML /Type /Metadata /Length 596 >>` followed by `<?xpacket begin=…`. There is no `/Filter`.
- **No `/Crypt` filter:** the raw file contains neither `/Crypt` nor `/Identity`. Answer: pikepdf does NOT add a `/Crypt` Identity filter. The dictionary has `/EncryptMetadata false`.
- **Info `/Title`** stays encrypted and readable.
- **Page-level `/Metadata` stream** in the same file is still ciphertext. CONFIRMS "only the catalog's `/Metadata` is exempt" for qpdf.
- **R3 (`R<4`):** qpdf encrypts the XMP, because the flag cannot be expressed.
- **R3 with a hand-added `/EncryptMetadata false`:** qpdf ignores the flag and decrypts. This CONFIRMS Folioxide's "ignored for R2/R3".

**Reader results on the qpdf-written file:**

| Reader | Result |
|---|---|
| pypdf | XMP read correctly through `xmp_metadata`; a generic `get_data()` on the catalog `/Metadata` returns decrypted garbage (the brief's "only through xmp_metadata" holds). |
| pdf.js | Reads the XMP (`xmp="MetaTitle"`) for V4/V5. |
| poppler 24.02 | CONTRADICTS the brief's assumption: `pdfinfo -meta` prints decrypted garbage (for example `stdout=95 bytes, printable=41, looks-like-XMP=False` on the R4 file). Poppler ignores EncryptMetadata false. |

- **pdf.js, catalog-only:** source line 40352, `xref.fetch(streamRef, !encryptMetadata)` in the catalog getter, supports the "catalog metadata only" cell. Page-level metadata is not exposed by pdf.js, so that part was not probed.
- **pdf.js, V<4:** pdf.js computes `encryptMetadata = (algorithm 4||5) && EncryptMetadata!==false`, so for V1/V2 it never decrypts the XMP. Result: `xmp=null` on an R3 file even when valid.
- **pypdf, R3 with `/EncryptMetadata false` hand-added:** pypdf honours it for R3 too and fails to parse the XMP (`no element found`). qpdf ignores it.

**pyHanko writer:** CONTRADICTS what one would expect.
- With `encrypt_metadata=False` it writes `/EncryptMetadata false` but still ENCRYPTS the catalog XMP (raw ciphertext).
- pikepdf reads garbage, pypdf raises `XML in XmpInformation was invalid`, pdf.js gives `xmp=null`. Only poppler happens to decode it.
- So pyHanko-written EncryptMetadata-false files are non-conformant. Do not use them as a reference for the exemption.

---

## P-4. EFF ≠ StmF, and Identity with StrF `/StdCF`

**Commands** (`p4.py`): hand-built V4/R4 AES-128 files via `mkenc.py`. Embedded file stream `/Type /EmbeddedFile`. Read via `pikepdf p.attachments`, `pypdf r.attachments`, `pdfdetach -saveall`, `pdf.js getAttachmentContent`.

**CONFIRMS E6 ("qpdf: EFF informational only").** Results by reader:

| Case | qpdf | pypdf | poppler | pdf.js |
|---|---|---|---|---|
| EFF=/Identity, StmF=/StdCF, attachment stored plain | decrypts it with StmF (garbage) | same | same (empty) | reads plain (follows EFF) |
| Same, attachment stored AES | decrypts correctly | decrypts correctly | decrypts correctly | NOT decrypted (garbage) |
| StmF=/Identity, EFF=/StdCF, attachment AES | ciphertext (EFF ignored) | ciphertext | ciphertext | decrypts correctly |

So pdf.js is the only reference that follows §7.6.6. Source: `CipherTransform.createStream` uses `embeddedFilterName` for `EmbeddedFile` streams. Folioxide's EFF rule therefore matches pdf.js and the spec, and differs from qpdf, pypdf and poppler.

**StmF=/Identity with StrF=/StdCF** (streams plain, strings AES):
- **qpdf and pypdf:** correct.
- **poppler:** prints `Unimplemented Feature: Unsupported version/revision (4/4) of Standard security handler` and decrypts nothing. The plain content is readable, but the AES strings come out as garbage (Title garbled). The reverse case (StmF=/StdCF, StrF=/Identity) gives garbage content with a plain Title.
- **pdf.js:** correct.

**Identity without `/CF`** (V4, StmF=StrF=/Identity, no `/CF` key). This CONTRADICTS the pdf.js [test] "Identity even without /CF" as observed with 6.4.299:
- **pdf.js:** fails with `InvalidPDFException: Invalid Root reference`, because `this.cf.get` runs on an undefined `cf`.
- **pypdf:** crashes with `KeyError: '/CF'`.
- **qpdf and poppler:** fine (poppler with the same warning).

**CONTRADICTS (row 91, qpdf cell): "`/Identity` gives no decryption".** With `/CF << /Identity << /CFM /AESV2 … >> /StdCF … >>` and StmF=StrF=/Identity:
- **qpdf (pikepdf) and pdf.js** apply the `/CF` entry: content comes out garbage, Title is `''`.
- **pypdf and poppler** keep the built-in Identity (plain content, Title correct).
- Folioxide's §1.2 rule (ignore a `/CF` key named Identity) = pypdf/poppler. Suggested row 91 correction: "qpdf and pdf.js: a `/CF` entry named Identity overrides the built-in".

---

## P-5. Per-stream `/Crypt` filter, with and without `/Type /CryptFilterDecodeParms`

**Does qpdf need the `/Type`?** YES. Commands in `p5.py`: V4 AES-128 file, content stream stored as indicated, `/Filter /Crypt` plus varying `/DecodeParms`.

| Case | qpdf | pypdf | poppler | pdf.js |
|---|---|---|---|---|
| `/Type /CryptFilterDecodeParms /Name /Identity`, plain | reads plain | silent garbage | reads | reads |
| `<< /Name /Identity >>` (no `/Type`), plain | decrypts anyway (garbage) | garbage | reads | reads |
| `/Filter /Crypt`, no `/DecodeParms`, plain | decrypts anyway (garbage) | garbage | reads | reads (default Identity) |
| `[/Crypt /FlateDecode]` with Type | plain | n/a | plain | plain |
| `[/FlateDecode /Crypt]` (E5) | honours it anywhere | n/a | `Syntax Error (0): Can't revert non decrypt streams` | honours |
| `/Name /StdCF`, AES data | decrypts | `NotImplementedError: /Crypt filter with /Name or /Type not supported yet` | undecrypted garbage (treats every Crypt as identity) | decrypts |
| `/Name /NoSuchFilter`, plain data | decrypts with the default (garbage) | n/a | plain | plain (unknown name → NullCipher) |

- **CONFIRMS** "pypdf: per-stream `/Crypt` not handled" and E5 ("qpdf honours it anywhere").
- **Suggested addition to §0.3:** qpdf ignores a `/Crypt` filter whose `/DecodeParms` lacks `/Type /CryptFilterDecodeParms`. Spec Table 14 makes `/Type` optional and defaults `/Name` to Identity. Folioxide §1.4 follows the spec (as poppler and pdf.js do), so this is a difference from qpdf.

---

## P-6. R6 password `Ⅸ` written as `IX`

**Commands** (`p6.py`, `p6g.py`): `Pdf.open`, `PdfReader.decrypt`, `pdftotext -upw`, pdf.js. Table of "file written with X, opened with Y":

| Written / opened | pikepdf | pypdf | poppler | pdf.js |
|---|---|---|---|---|
| `IX` / `IX` | OPEN | OPEN | OPEN | OPEN |
| `IX` / `Ⅸ` | FAIL (PasswordError) | OPEN | FAIL | OPEN |
| `IX` / `I<U+00AD>X` | FAIL | OPEN | FAIL | OPEN |
| `a` / `ª` (U+00AA) | FAIL | OPEN | FAIL | OPEN |
| `Ⅸ` (qpdf writes raw UTF-8) / `Ⅸ` | OPEN | FAIL (NOT_DECRYPTED) | OPEN | OPEN |
| `Ⅸ` / `IX` | FAIL | FAIL | FAIL | FAIL |

- **CONFIRMS** the P-6 expectations (pikepdf fails, pypdf opens), and adds poppler: it FAILS because it does no SASLprep.
- **Row 98 additions:**
  - **qpdf (pikepdf):** no SASLprep on read or write.
  - **pdf.js:** SASLprep then raw fallback. CONFIRMS its [test] cell.
  - **pypdf:** SASLprep only. It falls back to raw UTF-8 only when SASLprep itself fails (log: `SASLprep normalization failed, using plain UTF-8: SASLprep: ASCII control character U+0007`). It cannot open a qpdf-written `Ⅸ` file. Folioxide's "SASLprep, then raw" candidate rule is a superset of both.
- **CONTRADICTS E12** ("pypdf writes raw UTF-8"): pypdf SASLpreps on write. A pypdf-written `Ⅸ` file opens with `IX`, not with `Ⅸ`. Raw UTF-8 is written only when SASLprep fails.
- **127-byte truncation (R6):** all fail on password lengths 128 and up when written by pikepdf.
  - Reading truncates to 127 in qpdf, pypdf and pdf.js.
  - **qpdf does not truncate when writing**, so a >127-byte password gives a file that no reader (including qpdf) can open. A file written with 127 bytes opens with 128 or 129 bytes in qpdf, pypdf and pdf.js.
  - pypdf truncates on both write and read.
  - Poppler could not be probed for this (every poppler open failed even at length 126, so it is probably an argv-length limit).
- **R4 (row 99):**
  - **CONTRADICTS E11** ("qpdf/pikepdf write UTF-8"). pikepdf encodes the R3/R4 password as PDFDocEncoding: `é` becomes `0xE9`. It raises `ValueError: Encryption level is R3/R4 and password is not encodable as PDFDocEncoding` for `Ⅸ`. This is exactly Folioxide's E11 behaviour.
  - Opening: pikepdf with the str `"é"` (UTF-8 `c3a9`) FAILS, with bytes `b"\xe9"` OPENS; qpdf reads bytes as given. pypdf (Latin-1 then UTF-8) OPENS. Poppler opens with raw `0xE9` and fails with `c3a9`. pdf.js (Latin-1 only for R≤4) OPENS.

---

## P-7. pyHanko validating a signature on a pikepdf AES-256 file

**Commands** (`p7.py`):
- pikepdf `Encryption(R=6|4|3)`.
- pyHanko: `r=PdfFileReader(f); r.decrypt("u"); IncrementalPdfFileWriter(f, prev=r); signers.sign_pdf(...)` (PAdES, `fixtures/pki/signer-p256`).
- `validate_pdf_signature` after `decrypt("u")`.
- `pdfsig -nocert -upw u F`
- `openssl cms -verify -binary -inform DER -in sig.der -content signed.bin -CAfile fixtures/pki/root.pem -purpose any`

**CONFIRMS** (R6, R4 and RC4-128 alike):
- **pyHanko:** `intact=True valid=True trusted=True coverage=ENTIRE_FILE modification=NONE bottom_line=True`.
- **pdfsig:** `Signature Type: ETSI.CAdES.detached … Total document signed … Signature Validation: Signature is Valid.`
  - With `-upw u` it validates.
  - Without a password: `Command Line Error: Incorrect password`.
  - With `-opw o` alone it also validates.
- **OpenSSL:** `CMS Verification successful`, using ByteRange slices taken from the raw file. `/Contents` is unencrypted hex starting `3082…` in the encrypted file.
- **qpdf** returns the signature `/Contents` unchanged (raw); **pypdf** decrypts it (different bytes, "no exemption").

**Tooling gap:** `tools/oracles/extract_cms.py FILE --verify` fails on these files with `cannot read the signature fields: FileNotDecryptedError`. §WP5 mentions `validate_sig.py --password`, but `extract_cms.py` also needs a password option.

---

## P-8. pyHanko `encrypt(pdf_mac=True)` then a non-MAC-aware update

**Commands** (`p8.py`, `p16.py`):
- `w.encrypt("o","u", pdf_mac=True)`.
- pikepdf full re-save of the MAC file (`Pdf.open(mac, password="o"); save(encryption=True)`).
- A raw incremental revision appended to the MAC file (new `/Info` object AES-encrypted with the file key, classic xref, `/Prev`), once with a stale `/AuthCode` kept and once without it.
- `PdfFileReader(f).decrypt("u")`.

**CONFIRMS D-6.**
- **The MAC file as written:** `%PDF-2.0`, `/P -4100` (bit 13 CLEAR), `/KDFSalt` in `/Encrypt`, trailer `/AuthCode`, `/Extensions /ISO_ … /ExtensionLevel 32004`. pyHanko reopens it: `USER; mac_status=SUCCESSFUL`.
- **pyHanko's own incremental update:** reopens fine (it recomputes the MAC).
- **Raw incremental update, MAC-unaware:**
  - Stale `/AuthCode` kept: `decrypt -> FAILED; mac_status=FAILED reason='Failed to locate AuthCode dictionary'`.
  - `/AuthCode` omitted: `FAILED … 'PDF MAC token must have /ByteRange covering the entire file'`.
- **pikepdf full re-save:** drops `/KDFSalt`, keeps the stale trailer `/AuthCode` and P bit 13 clear. pyHanko result: `FAILED` (same reason as the omitted-AuthCode case).
- **The same raw update on a `pdf_mac=False` file:** pyHanko opens it (`NOT_APPLICABLE`).
- **qpdf, pypdf, poppler and pdf.js all open the broken-MAC files without complaint.** This CONFIRMS "ignored" in row 105.
- **P-16 (each trigger alone, on an ordinary R6 file):** `/KDFSalt` alone fails authentication, trailer `/AuthCode` alone fails, and **P bit 13 clear alone fails** (with `/Perms` rebuilt to match). The no-trigger control passes. This CONFIRMS the three triggers in §0.1's pyHanko notes.
- **Wording:** the P-8 brief says "pikepdf incremental save". pikepdf has none, so this is an emulation.

---

## P-9. `pdf.pages.insert` on a three-level tree with inherited attributes

**Commands** (`p9.py`, `p9b.py`): a 3-level tree built with pikepdf (A has `/MediaBox /Resources /Rotate 90`; B has `/CropBox`; C below B; one leaf overrides `/MediaBox` and `/Rotate`). Then: open+save, read-only access, `pages.insert`, `del pages[0]`, `pages.append(foreign)`, `pages.reverse()`.

**CONFIRMS** "page helpers flatten the tree into the root and push `/Resources /MediaBox /CropBox /Rotate` down", with nuance:
- **Push-down happens at open** by default (`inherit_page_attributes=True`). The attributes land on every leaf and are removed from intermediate nodes, but the tree stays nested if no structural call is made. Read-only access (`len(pages)`, `pages[0]`) does not flatten.
- **Flattening** happens on the first structural operation (insert, delete, append, reverse): `/Kids` of the root are all pages, `/Count` is correct, and intermediate nodes are gone. It also pushes down with `inherit_page_attributes=False`.
- **A page's own value wins**, and the closest ancestor wins (B's `/Rotate 270` beat A's 90). Verified with `pdfinfo -box` (sizes 490×690 with a CropBox, 300×400 rot 180, and so on).
- **Non-inheritable keys on intermediate `/Pages` nodes are dropped** (`/Foo`, `/Group` vanished from the file). The root keeps only `/Count /Kids /Type`.
- **Same page listed twice** (hand-written raw file; `p9b.py`): qpdf logs `kid 2 (from 0) appears more than once in the pages tree; creating a new page object as a copy` at the first page-tree access. The copy is shallow: `/Contents` is the same object (`(7,0)`) on both pages. CONFIRMS row 157 ("flattening copies it"). pypdf instead lists the same object twice (`[5, 6, 5]`).

---

## P-10. `pdfunite` on two files with outlines and forms

**Commands** (`p10.py`): two 2-page documents A and B. Each has an outline with a child, an AcroForm with text widgets `name` and `onlyA`/`onlyB`, a Link with explicit `/Dest` to page 2, a named-destination GoTo link, `/Dests`, StructTreeRoot/MarkInfo/Lang, PageLabels, and Info Title/Author. Then `pdfunite A B U` and `pdfunite B A U2`.

**Result:**
- **Survives:**
  - Pages (4).
  - AcroForm: `/DA`, `/DR` and both `/Fields` lists concatenated. `name` appears twice with no renaming and values `A-name-value`, `B-name-value`.
  - Widgets and Link annotations.
- **Lost:** Info (no Title or Author), Outlines, StructTreeRoot/MarkInfo/Lang (`Tagged: no`), `/Dests`, PageLabels.
- **Dangling after the merge:**
  - Explicit-`/Dest` links and widget `/P` point at the old source pages, which are not in the new page tree.
  - Named GoTo links remain but `/Dests` is gone.
  - Pages keep a stale `/StructParents`.
- **Order:** `pdfunite B A` is symmetric (nothing is taken from the first file).

This fills the pdfunite cells of rows 158, 159, 160, 161 and 162 (all [probe]). Outlines are dropped entirely, so "outlines to missing pages" is moot.

---

## P-11. `qpdf --pages a b`, field `name` in both: what does the output call the second?

**Emulated** (see deviation 1): `a.pages.append(b_page)` followed by `a.acroform.fix_copied_annotations(new_page, old_page, b.acroform)`.
- **`name+1`**, with the widget `/T` renamed to match and `/V` kept (`B-name-value`).
- **Next collisions:** A+B+B gives `name+1`, then `name+2` (and `onlyB`, `onlyB+1`).
- **Hierarchical:** a parent `name` with kids `first`/`last` becomes `name+1.first`, `name+1.last`.
- **`/DR` font collision** (`/Helv` in A and a different `/Helv` in B): the B font becomes `/Helv_1` (suffix `_1`), and B's widgets' `/DA` is rewritten to `/Helv_1 12 Tf 0 g`.
- **Without the helper**, plain `pages.extend()` leaves B's widgets on the pages but out of `/Fields`.
- **Not `name#2` and `name_2`:** those are Folioxide's own choice (A.3).
- **Row 158 vs 161:**
  - The row 158 qpdf cell says form fields come "from the primary input only". Row 161 and this probe show foreign form fields ARE copied. Suggested: remove "form fields" from row 158's qpdf list.
  - Outlines, struct tree and Info come from the primary only in the emulation (by construction, since the emulation starts from A).
  - A foreign page's stale `/StructParents` is retained.
- **Links to a page not carried over** (`p15.py`): in the emulated subset copy, a link `/Dest [page2 /Fit]` becomes `[null /Fit]`. This is the A.3 "→ Null" behaviour, whereas Folioxide drops the link. Deleting a page in place leaves the link and the outline items pointing at the orphaned page object (the "qpdf leaves it broken" in P4). `pdfseparate -f 1 -l 1` also leaves orphan targets and drops the outline.

---

## Other [probe] rows of §0.1 and §0.4 (beyond P-1…P-11)

| Row | Result |
|---|---|
| **R5 / empty user, poppler** | Reads (P-1, P-2). |
| **Unknown crypt filter, row 92** | See the list below the table. |
| **Strings in object streams / xref streams, rows 94-95** | CONFIRMS for qpdf, pypdf, poppler and pdf.js. `p13.py`: R4 and R6 with `ObjectStreamMode.generate`. All four read the Info Title correctly. The qpdf-decrypted ObjStm container contains the Title as a plain literal `(StringInObjStm)`. The `/Type /XRef` dictionary is plain text in the raw file. |
| **Signature `/Contents`, row 96** | CONFIRMS "kept raw only for `/Type /Sig` + `/ByteRange`" in qpdf (P-17). A `/Type /DocTimeStamp` + `/ByteRange` dictionary, a `/ByteRange` + `/Contents` dictionary with no `/Type`, and `/Type /Sig` without `/ByteRange` are all decrypted by qpdf (garbage). This CONFIRMS the premise of E7. pypdf decrypts everything. |
| **Missing or malformed `/ID`, row 97** | `p12.py`. qpdf logs `invalid /ID in trailer dictionary` for a missing `/ID`, a one-element `/ID` and a non-array `/ID`, but not for `[<> <>]`. R6 (no ID dependence) opens in all four readers with all of these, except pypdf raising `TypeError: 'NumberObject' object is not subscriptable` for `/ID 5`. R4 encrypted with an empty ID[0] opens in all four with no `/ID` or `[<> <>]` in the trailer. A mismatched ID gives a plain wrong-password error. |
| **`/Perms` mismatch (R6), row 100** | Corrupted `/Perms`, `/P` changed, and `/Perms` empty. qpdf warns `/Perms field in encryption dictionary doesn't match expected value` and opens. pypdf logs `ignore '/Perms' verify failed` and opens. Poppler and pdf.js stay silent and open. Perms of 8 bytes: pypdf crashes at open with `ValueError: The length of the provided data is not a multiple of the block length`; qpdf only warns. |
| **Short `/O /U /OE /UE /Perms`, row 101** | R6 `/U` 40 or 47 bytes: qpdf opens with garbage text/Title, no throw; pypdf silently garbage; poppler prints `Syntax Error: Invalid encryption key length …` but rc 0 and decrypts nothing; pdf.js silent garbage. `/UE` 31 bytes: pypdf `ValueError`; `/UE` empty: pypdf `WrongPasswordError`. R4: qpdf `PdfError: incorrect length for /O and/or /U in encryption dictionary` only when LONGER than 32 (33). Shorter `/U` (31, 16) opens; `/O` 31 gives a wrong password. Refusing as `E_SYNTAX` is stricter than all of these. |
| **Bad `/Length`, row 102** (V2/R3 file really using a 128-bit key) | qpdf opens it with `/Length` absent, 100, 127, 136, 256, 32, 0, -8, `128.0` and `(128)`, which CONFIRMS "guesses 128". pypdf: `ValueError: Invalid key size (96) for RC4`, `TypeError` for the real and string values, `WrongPasswordError` when absent. pdf.js: `UnknownErrorException: invalid key length` for non-multiples of 8 or under 40; `Incorrect Password` for 0, 136, 256 and absent. Poppler: `Incorrect password` for most. A genuine 64-bit key with `/Length 64` opens in qpdf, poppler and pdf.js, and fails in pypdf with `ValueError: Invalid key size (104) for RC4`. |
| **AES ciphertext oddities, row 103** (`p13.py`, embedded-file stream with crafted bytes) | CONFIRMS qpdf: ≤16 bytes gives empty output; IV+1 byte gives 16 garbage bytes (the zero-filled tail); invalid padding (pad byte 0x00, 0x11, a 0x10 with one matching byte, and a 0x04 with mismatched earlier bytes) strips nothing; no error. Other readers differ: poppler and pdf.js drop a ragged tail; pypdf and poppler strip blindly or return empty on bad padding; pdf.js strips nothing on invalid padding like qpdf. |
| **Permission bits, row 104** | CONFIRMS "`pdfinfo` prints `print/copy/change/addNotes`", with the semantics noted above. |
| **ISO/TS 32004, row 105** | All of qpdf, pypdf, poppler and pdf.js ignore the MAC (P-8). |
| **§0.4 pdfunite cells** | See P-10. |

**Unknown crypt filter (row 92):**
- **qpdf** (for CFM `/Foo`, `/None`, or StmF/StrF naming a filter not in `/CF`):
  - Logs `unknown encryption filter for streams (check /StmF from /Encrypt dictionary); streams may be decrypted improperly` (and a "strings" variant) and decrypts with AES. This CONFIRMS "warning, then assumes AES".
  - **CFM `/None` is treated as unknown by qpdf**, so plain data comes out garbage. This is not what §1.2 does (it accepts `/None`).
  - **qpdf also decrypts CFM `/AESV3` in V4 and `/AESV2` in V5.**
- **pypdf:** `NotImplementedError: StmF Method /Foo NOT supported!` (and for `/None`); `KeyError: '/Nope'` for an unknown name. An unknown EFF name makes pypdf raise `KeyError` at open.
- **pdf.js:**
  - Unknown CFM: the whole file fails (`Invalid Root reference`).
  - A name that is not in `/CF`: NullCipher, so that part is silently not decrypted. An unknown EFF name leaves only embedded files undecrypted.
  - CFM `/None` is plain. This matches the spec and §1.2.
  - V5 + `/AESV2` is decrypted with AES-256, which matches E8's [test].
- **poppler:** `Unimplemented Feature: Unsupported version/revision (4/4) of Standard security handler`, and nothing is decrypted. V5 + `/AESV2` gives "Incorrect password" in poppler and `ValueError: Invalid key size (0) for AES` in pypdf.
- **V5 with StmF/StrF absent** (default Identity, plain data): qpdf, pypdf and pdf.js read it; poppler decrypts anyway (garbage).

---

## Suggested §0 corrections (for the manager's R-n rulings)

1. **Row 87, pdf.js:** user first, then owner (source lines 57775–57777).
2. **Row 88, poppler:** the flags are the raw P bits, not "every flag yes". Poppler never tries `-upw` as an owner password.
3. **Row 86, pypdf:** the cell is accurate only for the constructor. `decrypt()` returns `NOT_DECRYPTED`.
4. **Row 86, qpdf/pikepdf:** drop `owner_password_matched`; pikepdf exposes only `EncryptionInfo.user_password`.
5. **Row 91:**
   - qpdf and pdf.js let a `/CF` entry named `Identity` override the built-in.
   - pdf.js (6.4.299) and pypdf fail on V4 with no `/CF`.
   - qpdf requires `/Type /CryptFilterDecodeParms` for a per-stream `/Crypt` (add as a new E-row; poppler/pdf.js follow the spec).
6. **Row 93:**
   - Poppler ignores EncryptMetadata false.
   - pdf.js never decrypts R≤3 XMP.
   - pypdf honours the flag for R3.
   - pyHanko `encrypt_metadata=False` still encrypts the XMP.
7. **Rows 98 and 99, E11, E12:**
   - pikepdf writes PDFDocEncoding for R≤4 (same as E11, so remove "qpdf/pikepdf write UTF-8").
   - pypdf SASLpreps on write (E12 is wrong in the normal case).
   - Poppler does no SASLprep.
   - qpdf does not truncate to 127 bytes on write.
8. **Row 101:** qpdf does not throw on short R6 `/U`; it throws only for R≤4 values longer than 32.
9. **§4.4:** the R2 reading is bit 9 ← 6, bit 10 ← 5, bit 11 ← 4, bit 12 ← 3. Bit 10 is forced to 1 for R4 and R6, not only R6. "None give -3904" is R3-only (R2: -64; R4/R6: -3392).
10. **§4.5 and §1.2:** qpdf V4 files carry `/OE <> /UE <>`, and its `/CF` has no `/Type /CryptFilter`. A V4 reader must tolerate the empty strings.
11. **Row 158, qpdf cell:** drop "form fields" from the primary-only list.
12. **P-8 text:** pikepdf has no incremental save; stage-0 used a raw revision and a full re-save.
13. **P-4 text:** `tools/fixtures/encrypt.py --identity-streams` does not exist yet.

## Could not probe

- The real qpdf CLI: E10's `--allow-insecure` refusal, and the CLI's exact glue for `--pages` (all of P-11/P-15 is a libqpdf-level emulation).
- pdf.js master and its tests (only the npm 6.4.299 build was run).
- pdf.js page-level `/Metadata` under EncryptMetadata false (not exposed by the API).
- pdf.js try order (not observable; read from source).
- pypdf `strict=True` AES behaviour (row 103 pypdf cell).
- Poppler with passwords longer than ~32 bytes.

**Script:** `/tmp/m5-probes/run_probes.sh`

# Folioxide roadmap

Milestones are delivered in order. Each one passes the QA gate described in `.claude/team.md` and is
committed as `M<n>: <title>`. Progress is tracked in the table below. The detailed scope, the work packages
and the acceptance criteria for each milestone follow it.

| Milestone | Title | Status |
|---|---|---|
| M0 | Project scaffolding | ✅ done |
| M1 | Syntax layer, read path | ✅ done |
| M2 | Writers, document model v1, Node open/save | ⏳ in progress |
| M3 | Signatures I: PAdES B-B, external signing, verification | pending |
| M4 | Signatures II: B-T timestamps, certification, visible signatures | pending |
| M5 | Encryption ∥ page operations | pending |
| M6 | Document structure ∥ optimization | pending |
| M7 | Content creation (text, fonts, images, shapes, watermarks) | pending |
| M8 | Annotations ∥ form filling | pending |
| M9 | Form creation and flattening ∥ text extraction | pending |
| M10 | True redaction, editing existing text | pending |
| M11+ | Rendering, LTV, PDF/A, linearization, WASM (backlog) | backlog |

User priorities, in order: **PDF signing**, then **page & document ops**, **annotations & forms**, and **content editing**.
Rendering and extraction come later.

**Conventions**
- "Dev A" and "Dev B" are the two senior developers. **∥** marks packages that run in parallel; they touch different crates or modules, so they do not conflict.
- Every milestone also has the standing gates: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check`, and the Node tests when bindings change.
- "Oracle" means `cargo xtask oracle --suite <s>` exits 0.
- Week figures are rough estimates of senior-developer weeks.

## M0: Project scaffolding (about 1 week)
**Goal:** an empty but complete pipeline. **Out of scope:** any PDF code.

- **WP0.1 (Dev A) ∥ Rust workspace**
  - root `Cargo.toml` with `[workspace.dependencies]` and `[workspace.lints]` (`unsafe_code = "forbid"` in the core crates; clippy `unwrap_used`/`expect_used`/`panic`/`indexing_slicing` = warn in non-test code)
  - empty crates per A.2 with `lib.rs` docs
  - `rust-toolchain.toml` (1.97.0), `rustfmt.toml`, `deny.toml` (allow: MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0, MIT-0, CC0-1.0; copyleft denied; crates.io source only; RUSTSEC-2023-0071 ignored with reason)
  - `xtask` with `fixtures` (no-op) and `oracle` subcommands
  - `CLAUDE.md` with gate commands and conventions
  - **dependency spike:** add `rsa =0.10.0-rc.19`, `cms =0.3.0-pre.1`, `p12-keystore 0.4.0`, `x509-cert 0.3.0`, `der 0.8.2` to `folioxide-sign` and confirm a single resolution
- **WP0.2 (Dev B) ∥ Node, Python and CI**
  - `bindings/node` with napi v3, exporting `version(): string` (returns `folioxide::VERSION`)
  - `package.json` (name `folioxide`, napi config per A.7), `pnpm build` / `pnpm test` scripts
  - `test/version.test.mjs`, `test/types.test-d.ts`
  - `tools/setup-venv.sh` + `requirements-dev.txt` (pyhanko==0.37.0, pypdf==6.20.0, pikepdf==10.16.0)
  - `tools/oracles/run_suite.py` skeleton (reads `*.expect.json` and dispatches checks)
  - `tools/gen-pki.sh`, with output committed to `fixtures/pki/`
  - `fuzz/` skeleton
  - `.github/workflows/ci.yml` with jobs `fmt`, `clippy`, `test` (ubuntu, macos, windows), `deny`, `node` (Node 22), `oracle` (ubuntu: apt poppler-utils, venv); `fuzz-nightly.yml`; `release-npm.yml` (matrix build, `napi prepublish`) as a draft

**Acceptance**
1. All standing gates pass. `cargo deny check licenses bans sources advisories` passes (if `cargo-deny` is installed; it is required in CI).
2. `cargo tree -i cms --workspace` shows exactly one `cms` version. `cargo tree -p folioxide -e normal | grep -E "napi|tauri"` prints nothing.
3. In `bindings/node`, `pnpm install && pnpm build && pnpm test` passes, with `version()` equal to the workspace version. `binding.d.ts` contains `export declare function version(): string`. `npx tsc --noEmit -p test` passes.
4. `bash tools/setup-venv.sh && .venv/bin/python -c "import pyhanko, pypdf, pikepdf"` exits 0.
5. `bash tools/gen-pki.sh --check` reproduces the files and `openssl verify -CAfile fixtures/pki/root.pem -untrusted fixtures/pki/intermediate.pem fixtures/pki/signer-rsa2048.pem` prints OK. The three `.p12` flavors open with `openssl pkcs12 -info -noout [-legacy]`.
6. `cargo xtask fixtures` and `cargo xtask oracle` exit 0 (empty suites). `fixtures/README.md` states the license policy.
7. `ci.yml` defines the jobs listed above. `napi create-npm-dirs` output names are recorded in `docs/ARCHITECTURE.md`.

## M1: Syntax layer, read path (about 4 weeks; depends on M0)
**Goal:** open any reasonable PDF lazily and robustly, and serialize objects. **Out of scope:** encryption (encrypted files return `PasswordRequired`/`Unsupported`), document-level writing.

- **WP1.1 (Dev A) ∥** `folioxide-syntax::{object, lexer, parser, serialize, limits, error}`: the `Object` model (A.3), lexer, object parser with depth limits, primitive serializer (real formatting, name escaping), `ErrorCode`.
- **WP1.2 (Dev B) ∥** `folioxide-syntax::filters`: Flate (lenient partial), predictors 2 and 10–15, LZW (EarlyChange), ASCIIHex, ASCII85, RunLength; encoders for Flate, ASCIIHex and ASCII85; passthrough markers for DCT, JPX, JBIG2 and CCITT; bomb limits. Also fuzz targets `fuzz_filters` and `fuzz_lexer`.
- **WP1.3 (Dev A, after 1.1) ∥** `folioxide-syntax::{xref, objstm, store, repair}`: xref tables, streams and hybrids, `/Prev` chain with loop detection, `Revision` list, header offset, lazy `Store` with `OnceLock`, object-stream decoding and caching, reconstruction scan.
- **WP1.4 (Dev B, after 1.2) ∥** `folioxide-testkit` byte-level builder (broken-file generators), committed `fixtures/syntax/*`, proptest round trips, the `no_panic_on_mutated_input` harness, `fuzz_parse_document`.

**Acceptance**
1. `cargo test -p folioxide-syntax` includes and passes:
   `lexer_spec_examples`, `real_formatting_no_exponent`, `name_escape_roundtrip`, `depth_limit_errors_not_overflow` (100k nested `[`), `flate_truncated_partial`, `flate_bomb_limited`, `png_predictor_all_types`, `lzw_early_change`, `ascii85_z_and_eod`, `xref_table_eol_variants`, `xref_subsection_starts_at_1_repaired`, `startxref_off_by_n_repaired`, `prev_loop_detected`, `junk_before_header`, `xref_stream_w0_default`, `hybrid_xrefstm`, `objstm_extends_chain`, `stream_length_wrong_recovers`, `length_indirect_cycle`, `missing_xref_full_reconstruct`.
2. `open_is_lazy`: opening a 2,000-page generated file and calling `resolve(root)` parses fewer than 50 objects (counter exposed under `cfg(test)`).
3. `proptest` `object_serialize_parse_roundtrip` runs ≥ 10k cases. `no_panic_on_mutated_input` runs ≥ 20k mutations over all fixtures with no panic.
4. `cargo +nightly fuzz build` succeeds for all M1 targets (CI). Nightly runs 10 minutes per target with no crash.
5. For each `fixtures/syntax/*.pdf`, testkit counts reachable objects; this matches pikepdf's count for the same file (via `cargo xtask oracle --suite syntax`, using `len(pdf.objects)` on files without free-list oddities).

## M2: Writers, document model v1 and Node open/save (about 3–4 weeks; depends on M1)
**Goal:** full and incremental saves, a page tree with inheritance, the Info dictionary, Node `open`/`save`. **Out of scope:** page mutation (M5), encryption (M5).

- **WP2.1 (Dev A) ∥** `folioxide-syntax::writer`:
  - full save (classic xref or xref stream, object-stream packing with exclusions, GC from the trailer, renumbering, deterministic mode)
  - incremental save and `incremental_suffix` (A.3 rules)
  - `Store` edit API (`set`, `get_mut`, `add`, `free`)
- **WP2.2 (Dev B) ∥** `folioxide-model`:
  - `Document` facade (`open`, `new`, `save*`, `diagnostics`), catalog, page tree traversal with inherited attributes and cycle limits
  - `Page` view (boxes, rotation, resources), get and set of `/MediaBox`, `/CropBox`, `/Rotate`
  - Info dictionary get and set, text-string codec, `PdfDate`, name tree and number tree readers
  - `folioxide` facade unified `Error`
- **WP2.3 (Dev B, after 2.2):** Node `PdfDocument.open/openAsync/create/save/saveAsync/saveIncremental/pageCount/getPage/getInfo/setInfo`, error codes, the `E_BUSY` rule, DTOs.

**Acceptance**
1. `incremental_prefix_preserved_all_fixtures`: for every fixture, set `/Title`, save incrementally, then check `out[..orig.len()] == orig`, that reopening shows the new title, and that `revisions().len()` increased by 1.
2. `incremental_matches_previous_xref_kind`: a table after a table, a stream after a stream or hybrid.
3. `full_save_roundtrip_deep_equal`: open, save (classic), reopen, and the resolved graph equals the original modulo renumbering. The same holds with `object_streams=true`.
4. `gc_removes_unreachable` and `deterministic_save_is_byte_stable` (two saves give identical bytes).
5. Oracle suite `writer`: every output passes `pdfinfo`, pikepdf `check()` (no errors), and pypdf strict. Page counts and `/Title` (via `pdfinfo`) match `expect.json`. `cmp -n` passes for the incremental outputs.
6. `inherited_attributes`: a page with no MediaBox inherits one from its grandparent; `pdfinfo -box` agrees.
7. Node: `test/open-save.test.mjs` passes (pageCount, setInfo/save/reopen, saveIncremental prefix check in JS). An invalid input throws an error with `code === "E_SYNTAX"`. `saveAsync` resolves to a Buffer. Calling `save()` during a `saveAsync` throws `E_BUSY` or completes without deadlock.

## M3: Signatures I, PAdES B-B (about 4 weeks; depends on M2)
**Goal:** invisible signing with local keys and the external two-phase flow, sequential signatures, and verification (integrity, certificate info, modified-after-signing). **Out of scope:** timestamps, DocMDP, visible appearance (M4), encrypted documents (M5).

- **WP3.1 (Dev B) ∥** `folioxide-sign::{keys, cms, x509info, algorithms}`:
  - PKCS#12 (p12-keystore) and PEM loading (PKCS#8 plain and encrypted, PKCS#1, SEC1, certificate chain)
  - `LocalSigner`: RSA PKCS#1 v1.5 with SHA-256/384/512; ECDSA P-256/SHA-256 and P-384/SHA-384; P1363→DER conversion
  - SignedData assembly with the PAdES attributes (A.6.3)
  - CMS parsing and signature verification (RSA v1.5 and PSS, ECDSA)
  - `CertificateInfo`
  - This is PDF-agnostic and unit-tested against openssl.
- **WP3.2 (Dev A) ∥** `folioxide-sign::{field, placeholder, prepare, verify_pdf, revisions}`:
  - signature field creation (invisible, existing empty field, auto-name `Signature{n}`)
  - AcroForm creation and update, SigFlags
  - placeholder writer and ByteRange patching, digest
  - `prepare`/`finish`/`embed_cms`, `sign`
  - sequential signatures
  - signature discovery, ByteRange sanity, revision coverage, changed-object list (basic `ModificationLevel` without the DocMDP policy)
  - Uses a stub CMS until WP3.1 lands.
- **WP3.3 (Dev A + B, last week):** Node `LocalSigner`, `prepareSignature`, `PreparedSignature`, `verifySignatures`, facade `signPdf` (no TSA yet), and integration.

**Acceptance**
1. `cargo test -p folioxide-sign` passes:
   `cms_signed_attrs_retagged_0x31`, `ess_cert_id_v2_omits_default_sha256`, `no_signing_time_attr`, `pkcs12_modern_aes`, `pkcs12_legacy_3des`, `pkcs12_legacy_rc2_40`, `pkcs12_wrong_password_code`, `pem_pkcs8_encrypted`, `pem_sec1_ec`, `ecdsa_p1363_accepted`, `sign_invisible_rsa2048`, `sign_invisible_p256`, `sign_invisible_p384_sha384`, `external_two_phase_matches_local`, `prepared_signature_serde_roundtrip`, `sequential_two_signatures`, `verify_detects_byte_flip_in_range`, `verify_detects_appended_revision`, `verify_rejects_byterange_gap_mismatch`, `placeholder_overflow_retries`.
2. Oracle suite `sign-bb`, for every output:
   - `validate_sig.py`: `intact=True`, `valid=True`, `trusted=True` with `fixtures/pki/root.pem`
   - the last signature's `coverage == ENTIRE_FILE`
   - in a 2-signature document, signature 1 has `coverage == ENTIRE_REVISION` and `modification_level ≤ FORM_FILLING`
   - `pdfsig -nocert` shows "Signature is Valid." for each signature
   - `extract_cms.py` + `openssl cms -verify … -purpose any` prints "Verification successful"
   - `pades_profile.py`: SubFilter `/ETSI.CAdES.detached`, content-type, message-digest and signing-certificate-v2 present, signing-time absent
   - `cmp -n` prefix preserved against the unsigned input
3. Tamper oracle: flipping one byte inside the signed range makes pyHanko report `intact=False` **and** our `verify` report `intact=false`.
4. Node `test/sign.test.mjs`:
   - signs with the `.p12` and with PEM
   - external flow with a JS signer built on `node:crypto.sign` (RSA and ECDSA with `dsaEncoding: 'ieee-p1363'`)
   - `verifySignatures()` returns `intact`, `signatureValid` and signer subject
   - wrong password gives `E_WRONG_PASSWORD`

## M4: Signatures II, B-T, certification and visible signatures (about 4 weeks; depends on M3)
**Goal:** a timestamp provider, DocMDP certification and modification policy, visible appearances. **Out of scope:** LTV/DSS (M11).

- **WP4.1 (Dev B) ∥** `folioxide-sign::tsp`:
  - own RFC 3161 DER types, `timestamp_request`, response validation (A.6.4), unsigned-attribute embedding, timestamp verification
  - `Timestamper` trait
  - placeholder sizing with `tsa_reserve`
  - testkit `MockTsa` (signs TSTInfo with the fixture TSA key)
  - Node `signPdf({ timestamp })` callback through the two-phase flow
- **WP4.2 (Dev A) ∥** `folioxide-sign::{docmdp, modification}`:
  - certification (P = 1, 2, 3), first-signature rule, refusing to sign when P = 1
  - modification classifier (A.6.7 step 8), `docmdp_ok`
- **WP4.3 (Dev A, after 4.2):** minimal `folioxide-content::{builder, standard14}`:
  - content operator builder
  - standard-14 AFM width tables (Adobe Core14 AFM, permissive redistribution notice; include it in `fixtures/README`/NOTICE)
  - WinAnsi encoding
  - JPEG passthrough XObject (SOF/APP14 parser)
  - signature appearance layout: text lines (name, date, reason), optional image, `/AP /N` with correct BBox
  - visible signature fields at page and rect

**Acceptance**
1. Tests: `tst_request_der_golden`, `tst_nonce_mismatch_rejected`, `tst_imprint_mismatch_rejected`, `sign_bt_mock_tsa`, `certify_p1_then_sign_rejected`, `certify_twice_rejected`, `certify_p2_then_approval_ok`, `p3_annotation_after_certify_classified_annotations`, `visible_signature_has_ap_and_rect`.
2. Oracle suite `sign-bt`:
   - pyHanko reports a valid timestamp (`timestamp_validity.intact/valid`, trusted with the TSA root)
   - `openssl ts -verify -data sigvalue.bin -in token.der -token_in -CAfile fixtures/pki/tsa-root.pem` prints "Verification: OK"
   - also with a token produced by **`openssl ts -reply`** (`tools/tsa/openssl-tsa.cnf`) fed through the external path, proving interoperability
3. Oracle suite `certify`: pyHanko `docmdp_ok=True` for P = 2 with a later form-fill revision, and `docmdp_ok=False` for P = 1 followed by an incremental Info change.
4. Visible signature: `pdftoppm -r 72 -f 1 -l 1` probe finds non-white pixels inside the widget rect; pyHanko still `intact`/`valid`; `pdftotext` contains the signer name.
5. Node: `test/sign-bt.test.mjs` (TSA callback receives a DER TimeStampReq and returns the mock response), `test/certify.test.mjs`.

## M5: Encryption ∥ page operations (about 4 weeks; depends on M2; signing integration needs M3)
**Goal:** read and write every standard security handler, and the core page operations.

- **WP5.1 (Dev A) ∥** `folioxide-security`:
  - Algorithms 1, 1.A, 2–7, 2.A, 2.B, 8–10; R5 read
  - permissions DTO; crypt filters; `EncryptMetadata`
  - `Decryptor` wired into the reader and both writers
  - encrypt on full save, change and remove passwords
  - incremental save of encrypted documents; signing and verifying encrypted documents
  - Node `open({password})`, `save({encryption})`
- **WP5.2 (Dev B) ∥** `folioxide-model::{pageops, import}`:
  - insert blank page, delete, move, reorder, rotate, set boxes; materialize inherited attributes
  - `ImportSession` (dedup), `import_pages`, `merge`, `split(ranges)`, `extract`
  - dest and outline pruning, AcroForm merging with renames, struct stripping
  - balanced page tree on full save
  - Node API

**Acceptance**
1. Tests: `decrypt_rc4_40`, `decrypt_rc4_128`, `decrypt_aes128`, `decrypt_aes256_r6`, `decrypt_r5_readonly`, `r6_unicode_password_saslprep`, `wrong_password_code`, `owner_password_opens_with_full_perms`, `encrypt_roundtrip_each_method`, `encrypt_metadata_false_xmp_plain`, `encrypted_objstm_strings`, `incremental_on_encrypted_keeps_id0`, `sign_encrypted_doc`.
2. Oracle suite `encrypt`:
   - for each of RC4-40, RC4-128, AES-128 and AES-256: pikepdf opens with user and owner passwords and reports the expected `R`, `bits`, `stream_method`
   - `pdfinfo -upw u` shows "Encrypted: yes" with the expected permission flags
   - pypdf `decrypt()` returns the right password type
   - inputs generated with pikepdf for all four methods decrypt in our code, and page text matches `pdftotext` on the unencrypted source
3. Oracle `sign-encrypted`: pyHanko validates a signature added to an AES-256 document (reader opened with the password).
4. Page-ops tests: `delete_pages_prunes_outline_dests`, `rotate_normalizes`, `reorder_permutation`, `extract_materializes_inherited`, `import_dedups_shared_font` (importing 10 pages sharing one font adds the font once), `merge_acroform_name_collision`, `split_ranges`.
5. Oracle suite `pageops`: `pdfinfo` page counts and `-box`/rotation per `expect.json`; pypdf strict; merge output page count = sum (cross-checked with `pdfunite` output count).
6. Node: `test/encrypt.test.mjs`, `test/pages.test.mjs`.

## M6: Document structure ∥ optimization (about 3 weeks; depends on M5)
- **WP6.1 (Dev B) ∥** `folioxide-model::{metadata, xmp, outlines, labels, attachments, names}`:
  - Info and XMP read, write and sync (quick-xml)
  - outlines CRUD (tree with `/First /Last /Next /Prev /Count`, destinations by page)
  - page labels CRUD (number tree, styles D/R/r/A/a, prefixes, start)
  - attachments (EmbeddedFiles name tree with `/Params` size and dates, `/AF`; list, add, extract, remove)
  - named destinations
  - Node API
- **WP6.2 (Dev A) ∥** `folioxide-model::optimize`:
  - object and xref streams, Flate recompression (level option, decompress-only option)
  - identical-object/stream dedup, unused resource pruning (requires a resource-name scan of content; use the M7 tokenizer if available, otherwise a conservative name scan)
  - GC, `OptimizeReport` DTO
  - Node `optimize()`

**Acceptance**
1. Tests: `xmp_info_sync`, `xmp_packet_wrapper_valid`, `outline_crud_counts`, `page_labels_roman_prefix`, `attachment_roundtrip_bytes_equal`, `optimize_dedups_identical_images`, `optimize_never_breaks_signed_on_incremental` (optimize on a signed document requires full rewrite and returns a warning).
2. Oracles: `pdfinfo` Title/Author/Subject/Keywords/Creator/Producer match; `pdfinfo -meta` contains `dc:title` with the same value; pypdf `.outline` titles and destination page indices; `.page_labels` list equals expected; `pdfdetach -list` names, and `pdfdetach -save 1` bytes equal the source; pikepdf opens optimized files and `check()` is clean.
3. Size: optimizing the fixture `fixtures/syntax/uncompressed-50p.pdf` reduces it by ≥ 40%, and `pdftotext` output is identical before and after.

## M7: Content creation (about 5 weeks; depends on M4's content builder and M5)
- **WP7.1 (Dev A) ∥** `folioxide-content::{tokenizer, ops, gstate, resources, shapes, overlays}`:
  - full content-stream tokenizer and operator model (inline images), builder, graphics-state tracker
  - unique resource naming; wrap existing content with `q…Q`
  - vector shapes (rect, ellipse, line, polygon, path, stroke/fill, color spaces, opacity via ExtGState)
  - watermarks and stamps (Form XObject, rotation, opacity, behind or in front)
  - headers and footers with page-number tokens and page labels
  - Node API
- **WP7.2 (Dev B) ∥** `folioxide-content::{fonts, text}`:
  - skrifa font loading; subsetting (subsetter) and GID remap
  - Type0/CIDFontType2/FontFile2 and CFF `FontFile3 /OpenType`; `/W` widths; ToUnicode CMap writer; subset tag
  - standard-14 text (WinAnsi)
  - simple layout (measure, wrap, align, line height); optional `shaping` feature
  - `add_text` API
- **WP7.3 (Dev B, after 7.2; or Dev A):** `folioxide-content::images`:
  - JPEG passthrough (gray, RGB, CMYK with Adobe Decode)
  - PNG: 1–16 bit, palette, tRNS, alpha → SMask, interlace
  - `add_image(page, rect, fit)`

**Acceptance**
1. Tests: `tokenizer_inline_image_ei_in_data`, `wrap_unbalanced_q`, `subset_glyphs_only_used`, `tounicode_ligature`, `cid_widths_scaled`, `png_rgba_to_smask`, `png_palette_trns`, `jpeg_cmyk_adobe_decode`, `watermark_on_rotated_page`.
2. Oracle suite `content`:
   - `pdffonts` shows emb=yes, sub=yes, uni=yes for embedded TrueType and OTF (CFF) fonts
   - `pdftotext` contains the inserted strings, including non-Latin ones (Cyrillic and CJK sample with a fixture font under OFL; OFL fonts are fine as **test data only**, noted in the fixtures README)
   - `pdfimages -list` shows `smask` rows for PNG-with-alpha and the right bpc and colors
   - `pdftoppm` probes confirm watermark pixels and header/footer positions on 0°, 90° and 270° rotated pages
3. Node: `test/content.test.mjs` (`addText` with a font buffer, `addImage` with PNG and JPEG, watermark).

## M8: Annotations ∥ form filling (about 4 weeks; depends on M7)
- **WP8.1 (Dev A) ∥** `folioxide-interactive::annots`:
  - model and CRUD for Text, FreeText, Highlight, Underline, StrikeOut, Squiggly, Square, Circle, Line (LE endings), Polygon, PolyLine, Ink, Link (URI and GoTo), Stamp (standard names and custom image)
  - appearance generators for each
  - `/F` Print default, `/NM`, `/M`, `/Popup`
  - Node API with DTOs
- **WP8.2 (Dev B) ∥** `folioxide-interactive::forms`:
  - field tree read (inheritance, fully qualified names, merged widgets)
  - fill text, checkbox, radio, combo and list fields
  - variable-text appearance generation (DA parsing, auto-size, multiline wrap, comb, Q alignment, `/MaxLen`, font fallback to an embedded font for characters outside the DA font)
  - NeedAppearances handling, XFA policy
  - Node `getFields()` / `fillFields()`

**Acceptance**
1. Tests: `annot_crud_each_type`, `highlight_quadpoints_order`, `annot_ap_bbox_matrix_maps_to_rect`, `form_field_inheritance`, `checkbox_on_state_from_ap`, `radio_opt_export_values`, `combo_opt_pairs`, `text_autosize_zero_tf`, `comb_field`, `xfa_removed_on_fill`.
2. Oracle suite `annots`: pypdf lists each `/Subtype` with `/AP`; `pdftoppm` probes find non-white pixels inside each rect; a Highlight probe shows the underlying text is still readable (multiply blend: pixel is not pure annotation color).
3. Oracle suite `forms`: pypdf `get_fields()` values equal the expected values; with `NeedAppearances` absent, `pdftoppm` shows field values; `pdftotext` contains the text-field values.
4. Filling a signed form incrementally keeps pyHanko `intact=True` and `modification_level=FORM_FILLING` (the A.6.7 classifier agrees).
5. Node: `test/annots.test.mjs`, `test/forms.test.mjs`.

## M9: Form creation and flattening ∥ text extraction (about 4 weeks; depends on M8)
- **WP9.1 (Dev B) ∥** `folioxide-interactive::{create, flatten}`:
  - create text, checkbox, radio group, combo, list, push button and signature fields with widgets and `/DR` fonts
  - flatten forms and/or annotations (A.10 #20)
  - Node API
- **WP9.2 (Dev A) ∥** `folioxide-content::extract`:
  - font decoding (simple encodings and Differences with AGL glyph names, TrueType cmap rules, CID with Identity and predefined CMaps — check whether `hayro-cmap` 0.1.0 ships the CMap data and its license — and ToUnicode)
  - glyph boxes from widths and FontBBox/ascent/descent
  - run and line assembly (`TextSpan { text, quads, font, size, page }`)
  - search returning quads
  - Node `extractText()`, `search()`

**Acceptance**
1. Tests: `create_each_field_type_roundtrip`, `flatten_skips_hidden`, `flatten_signed_doc_warns`, `extract_differences_encoding`, `extract_identity_h_tounicode`, `extract_rotated_page_quads`, `search_returns_quads`.
2. Oracles: created fields are listed by pypdf with the right `/FT`/`/Ff`; flattened output has no widget annotations (pypdf) while `pdftotext` still contains the values; extracted text equals `pdftotext -raw` on the fixtures, ignoring whitespace normalization, for ≥ 95% of characters across the `fixtures/fonts` set.

## M10: True redaction and editing existing text (about 5 weeks; depends on M9)
- **WP10.1 (Dev A) ∥** `folioxide-redact::apply`:
  - redaction regions from rects or from `/Redact` annotations (mark, then apply)
  - glyph-level text removal with TJ position compensation; render-mode-3 text
  - Form XObjects copy-on-write; Type3
  - path removal for fully covered paths (clip partially covered)
  - image pixel redaction (decode via `zune-jpeg`/`png`/hayro, black-out, re-encode Flate)
  - scrub annotations, field values in region, `/ActualText` and `/Alt`; optional metadata and outline scrub
  - overlay fill color; **forced full rewrite with GC**
  - Node `redact()`
- **WP10.2 (Dev B) ∥** `folioxide-redact::edit_text`:
  - locate a run (M9 extraction)
  - replace in place when the font can encode every new character (reverse cmap/ToUnicode → codes, width check)
  - otherwise redact the old glyphs and add new text with a matching or substitute embedded font at the same baseline
  - `replace_text(page, quad|search, new)`
  - Node API

**Acceptance**
1. Tests: `redact_text_in_shared_form_xobject_only_on_target_page`, `redact_tj_keeps_following_positions`, `redact_invisible_ocr_text`, `redact_image_pixels`, `redact_forces_full_rewrite`, `redact_annotation_apply`, `edit_text_same_font`, `edit_text_fallback_font`.
2. Oracle suite `redact`:
   - `pdftotext` lacks every redacted string, and text outside the regions is unchanged (diff limited to the redacted words)
   - a pikepdf scan of every decoded stream and string finds none of the redacted strings (Latin-1, UTF-16BE and hex)
   - exactly one `%%EOF`
   - `pdftoppm` probe shows the fill color in each region
   - `pdfimages` re-extracted images have black pixels in the region
3. Oracle suite `edit`: `pdftotext` shows the new text and not the old; `pdffonts` still valid.

## M11 and later (unordered backlog)
- **Rendering:** `folioxide-render` on hayro 0.8 → RGBA and PNG, `render(page, dpi)`; oracle comparison with `pdftoppm` (PSNR threshold); image extraction.
- **LTV:** `/DSS` with `/Certs /OCSPs /CRLs /VRI` (ISO 32000-2 §12.8.4.3), PAdES B-LT and B-LTA with `/DocTimeStamp` (`ETSI.RFC3161`); caller-supplied OCSP/CRL bytes (no network); own OCSP DER types. Oracles: pyHanko LTV validation, optionally EU DSS (Java).
- Then: FieldMDP and lock dictionaries, the public-key security handler, PDF/A-2b output (veraPDF oracle), linearization (qpdf `--check-linearization` via pikepdf as oracle), tagged-PDF preservation on merge, and WASM enablement (`getrandom/wasm_js`, no `std-fs`).

### Dependency summary
`M0 → M1 → M2 → M3 → M4`. M5 needs M2, and also M3 for signing encrypted documents. Then `M5 → M6`, `M4+M5 → M7 → M8 → M9 → M10`.
- The first signed PDF ships at the **end of M3**, about 12 weeks in with two developers.
- PAdES B-T, certification and visible signatures follow at **M4**, about 16 weeks in.


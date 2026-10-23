# Decision log

Newest entries go at the bottom. Each entry records what was decided, why, and who decided it.

## D1: Product scope and priorities (user, 2026-10-10)
- **Product:** a fully featured PDF editor core in **pure Rust**. Node.js is the first consumer, through a napi-rs native addon. Tauri comes later and links the core crate directly.
- **Priority order:** PDF signing, then page & document ops, then annotations & forms, then content editing. Rendering and text extraction come later.
- **Working mode:** fully autonomous. Every milestone passes a QA gate and gets its own commit.

## D2: Name "Folioxide" (manager, 2026-10-10)
- The name is *folio* (a leaf of a book) plus *oxide* (Rust).
- `folioxide`, `folioxide-core`, `folioxide-node` and the `@folioxide` npm scope were all free on crates.io and npm on 2026-10-10.
- A web search found no product or brand using the name. "Papyra" was rejected because it is too close to "Papyrio", an existing PDF tool.

## D3: Own syntax layer instead of lopdf (expert + manager, 2026-10-10)
- **Problems with `lopdf`:**
  - It loads every object eagerly.
  - It stores reals as `f32`, which loses precision.
  - It decrypts in place.
  - It handles incremental updates through a separate, manually synchronised type.
  - It has no model for limiting hostile input.
- Signatures need byte-exact incremental appends and lazy loading.
- See ARCHITECTURE §A.1.

## D4: Multi-crate workspace behind a `folioxide` facade (expert + manager, 2026-10-10)
- **Why:** faster compiles, clean feature gating, two developers can work in separate crates, and Tauri depends on one crate only.
- See ARCHITECTURE §A.2.

## D5: Open decisions from the design review, resolved by the manager (2026-10-10)
1. **MSRV:** *superseded by D7.2, which sets 1.89.* Originally the core declared `rust-version = "1.85"` (edition 2024). Development is pinned to 1.97.0 through `rust-toolchain.toml`. The `render` feature will need 1.92 or later.
2. **Permissions:** the core *reports* owner permissions (`/P`) and does not enforce them by default. An `enforce_permissions` open option enables enforcement. This matches common library practice; enforcement is the application's job.
3. **npm platform packages:** we use the napi-rs default naming, `@folioxide/binding-<platform>`, for example `@folioxide/binding-linux-x64-gnu`. The main package is `folioxide`.
4. **RSA timing side channel (RUSTSEC-2023-0071):**
   - Accepted and documented. There is still no patched `rsa` release.
   - The advisory is ignored in `deny.toml` with a stated reason.
   - The docs recommend ECDSA keys or the external KMS/HSM signing flow for server-side deployments.
   - Re-check on every `rsa` release.
5. **Tagged-PDF structure on merge or import:** stripped in v1 (`/StructParents` removed, StructTreeRoot not merged) and documented. Preserving it is on the backlog.

## D6: License (manager, 2026-10-10; *revised by D8*)
- Originally `MIT OR Apache-2.0`. **Superseded by D8: the project is MIT-licensed.**
- Dependencies must use permissive licenses, enforced by `cargo deny`.
- GPL, AGPL, LGPL and MPL tools such as poppler, qpdf/pikepdf and veraPDF may be used only as **external test oracles** and are never linked.

## D7: Decisions from M0 (manager, 2026-10-10)
1. **Resolver:** the workspace uses `resolver = "3"`, which picks the newest versions compatible with the workspace `rust-version`.
2. **MSRV raised to 1.89 for every crate** (this revises D5.1).
   - At 1.85 the resolver held back `time` 0.3.45, which is affected by RUSTSEC-2026-0009, and `aes` 0.9.2. napi 3.x already needs 1.88, and RustCrypto patch releases keep raising their MSRV.
   - A brand-new library gains nothing from supporting compilers this old. Node users get prebuilt binaries, and Tauri apps use current Rust.
   - Result: `time` 0.3.55 and `aes` 0.9.3, and the RUSTSEC-2026-0009 ignore is removed. CI's `msrv` job checks the core crates with `cargo +1.89`.
3. **napi features:** `napi = { default-features = false, features = ["napi8", "dyn-symbols"] }`. `dyn-symbols` looks up `napi_*` symbols at load time, so binaries that link napi code (including Rust unit tests of the binding) link without a Node host. This is also the configuration napi-rs ships by default.
4. **`unsafe_code` in `bindings/node` is `deny`, not `forbid`.** The `#[napi]` macros wrap their FFI glue in `#[allow(unsafe_code)]`, which `forbid` rejects. Hand-written `unsafe` is still an error. Core crates keep `forbid`.
5. **Oracle directory convention.**
   - Each case is `target/oracle/<suite>/<name>.pdf` with a sibling `<name>.expect.json`. Suite names match `[A-Za-z0-9_-]+`.
   - `cargo xtask oracle` empties `target/oracle`, then runs `cargo test --workspace --features folioxide-testkit/emit` with `FOLIOXIDE_ORACLE_DIR` set. Tests get their directory from `folioxide_testkit::oracle_dir(suite)` and write only when `EMIT_ENABLED` is set.
   - It then runs `.venv/bin/python -I tools/oracles/run_suite.py target/oracle[/<suite>]`.
6. **Runner semantics.**
   - **Exit codes:** FAIL outranks ERROR. Exit 1 if any check failed, otherwise 2 if any case errored, otherwise 0.
   - **`signatures[]` entries:** `intact` and `valid` default to true. The structural checks always run: ByteRange starts at 0, the gap equals `/Contents`, and the padding is zero. So do the pdfsig and OpenSSL cross-checks.
   - **Structural checks:** every case runs them (pdfinfo, pikepdf/qpdf, pypdf strict), even when its expect.json is `{}`.
   - **Paths:** relative paths in expect.json resolve against the expect file's own directory first, then the repo root.
7. **Generated `bindings/node/binding.js` and `binding.d.ts` are committed**, following the napi-rs convention, so changes to the JS API show up in review. CI fails if they are stale after `pnpm build`.
8. **Test PKI.**
   - Root: RSA-3072. Intermediate: P-384, so chain checks exercise both RSA and ECDSA.
   - Signers: RSA-2048, RSA-3072, P-256 and P-384. The TSA certificate has a critical `timeStamping` EKU.
   - Validity runs from 2025-01-01 to 2075-12-31. `expired.pem` was valid only during 2025.
   - The `.p12` password and the encrypted-key password are both `folioxide`. These keys are for tests only.

## D8: Project license is MIT (user, 2026-10-10)
- Folioxide is licensed under **MIT** alone. The license text is in `LICENSE` at the repository root, and a copy
  is in `bindings/node/LICENSE` for the npm package.
- Every crate and npm package declares `license = "MIT"`.
- The dependency policy is unchanged: permissive licenses only, enforced by `cargo deny`. Apache-2.0, BSD, ISC
  and Zlib dependencies are compatible with an MIT project.

## D9: Decisions from M1, the syntax layer (manager, 2026-10-10)
1. **Filters:**
   - `miniz_oxide` alone handles Flate in both directions: lenient partial inflate, and deflate. `flate2` is not used.
   - LZW is our own decoder of about 100 lines, so we control `EarlyChange`, leniency and limits. `weezl` is not used.
   - Filters are always lenient and report a `truncated` flag. The store turns that flag into a diagnostic (Lenient) or an error (Strict).
   - The `Crypt` filter is the identity in the filter layer, because the security handler owns crypt filters.
   - `DecodeLimits::max_chain_len` (default 16) bounds `/Filter` arrays.
2. **Strictness:** `Strict` turns every repair that `Lenient` would make into an error. `LimitExceeded` is a policy outcome and is never downgraded to null, even in lenient mode.
3. **References:** a reference whose generation does not match the xref resolves to null with a `WrongGeneration` diagnostic in both modes (§7.3.10).
4. **Reconstructed files:** `XrefKind::Reconstructed` marks files rebuilt by a full scan. **Writers must do a full save** for them; incremental saves are refused.
5. **Hybrid files (ISO 32000-2 §7.5.8.4):** within one section the table wins, free entries included; then that section's `/XRefStm`; then `/Prev`. This matches qpdf, poppler and pdf.js. Our writers leave compressed objects out of the table, as Acrobat does, and never list them as free.
6. **Object streams:** a container must itself be an uncompressed object. Members that share one offset are read once: the first reads the value, the others are null with a diagnostic.
7. **Hostile input stays linear:** opening, resolving every object and decoding every stream are linear in the file size on hostile input. This rests on parse bounds (next object or xref position), xref byte and entry budgets, a memo for shared indirect values, decode budgets charged once per source stream, and bounded reconstruction. Any later change to the store must keep this guarantee, and the tests in `store/tests.rs` enforce it.
8. **Recovering damaged files is qpdf-compatible.**
   - **Reference reader:** whenever a file's structure is damaged (bad final `startxref`, an update that no `startxref` reaches, missing xref), the store resolves objects the way **qpdf** does. qpdf is the reference reader for recovery.
   - **Signalling:** recovery always sets `Store::structure_repaired()` and emits a diagnostic: `XrefReconstructed`, `UnreferencedUpdate` and so on. M3 signature verification treats a repaired structure as "content outside the signed revisions is possible".
   - **What counts as an object definition during recovery:** a header at a line start, not inside a comment, not inside another parsed object, and keyed by (number, generation). Decoy text never shadows a valid chain.
   - **Never trusted:** header text inside an object that parses successfully never changes what a valid chain resolves to. This covers strings in arrays and dictionaries, strings that do not start a line, and stream data. qpdf (and pdf.js) take such line-start headers in damaged files; we keep the valid chain by design.
   - **How decoys are recognised:** one coverage pass, linear by construction, walks the line-start headers in file order.
     - A parse that **succeeds** covers its bytes; header text inside it is ignored.
     - A parse that **fails** covers only what it read. Headers inside that failed stretch are taken as definitions, as qpdf takes them.
     - During this pass, hex strings end at their first invalid byte, as in qpdf. Value reads stay lenient.
     - There is no budget and no cutoff.
   - **Accepted differences from qpdf:**
     - (a) a number deleted in a later revision after its last on-disk definition stays deleted, where qpdf, pdf.js and poppler would show it again if referenced;
     - (b) the decoy cases above;
     - (c) a container closed at an object keyword reads as truncated, where qpdf gives null;
     - (c2) an object that holds a header taken from a failed stretch reads only up to that header, where qpdf reads it whole;
     - (c3) qpdf's 10-byte first-token cut is not copied;
     - (d) an object whose `endobj` is the last token in the file, which qpdf nulls ("EOF after endobj");
     - (e) a table entry whose generation disagrees with its header is accepted and marked recovered.
9. **Errors and names:**
   - `Error` is a `#[non_exhaustive]` thiserror enum; callers match on `code()`.
   - `ErrorCode` serializes as SCREAMING_SNAKE_CASE, and the JS code is `E_` plus that name.
   - `DiagnosticKind` and `Strictness` serialize as camelCase.
10. **Fixtures:** they are generated deterministically by `folioxide-testkit`, with offsets relative to the `%PDF-` header. `cargo xtask fixtures --check` is part of `cargo xtask ci`.
11. **Oracle `objectCount`:** our count is the in-use ids from the merged xref that resolve to non-null objects. pikepdf's count is `len(pdf.objects)` minus nulls, because qpdf lists objects that an older revision used and a newer revision freed.

## D10: M3 signature design decisions (expert proposal, accepted by the manager, 2026-10-10)
All 19 open decisions in `docs/milestones/M3.md` §8 (D-1 … D-19) are accepted as recommended. The most important:
1. **Reference validator:** pyHanko 0.37.0, with openssl cms and poppler pdfsig as secondary oracles. Our modification level is **never more lenient than pyHanko**. The cases where we are deliberately stricter are listed in M3 §0 and in the test table `DELIBERATE_DIFFERENCES` (D-9).
2. **Vocabulary:** `Coverage` and `ModificationLevel` use pyHanko's names (D-4). ARCHITECTURE §A.6.7 is updated after M3.
3. **Refusals:** signing is refused for files with junk before the header (D-2), for `structure_repaired()` files (D9.4/D9.8; a full save comes first), and for certified documents with P=1 (D-14). `/Lock` and required `/SV` are `Unsupported` (D-13).
4. **Signing details:**
   - RSA blinding uses a default-on `sys-rng` feature (getrandom `SysRng`), with an override `LocalSigner::with_rng` (D-1).
   - `/Contents` sizing is exact rather than a heuristic, with a minimum of 8192 bytes (D-7).
   - RSA keys: ≥ 2048 bits to sign, ≥ 1024 bits to verify (D-12).
5. **Verification details:**
   - The signer key usage must contain digitalSignature **or** nonRepudiation (D-10; pyHanko requires nonRepudiation).
   - Trust path building is part of M3 (D-16).
   - `verify` with pending edits gives `InvalidArgument` (D-8).
6. **The oracle runner gains `rejected: true`** for negative signature cases (D-3; it changes D7.6). The runner then passes only when every oracle rejects the signature.
7. **Form state:** `/NeedAppearances` is left untouched, with a warning (D-5). `/SigFlags 3` is set only when no signed field exists yet (D-6).
8. **`PreparedSignature`** has an own versioned binary format, plus serde behind the `serde` feature (D-17).
9. **Field naming:** auto-named fields never take over an existing empty signature field (D-18).
10. **`/Contents` padding:** non-zero bytes after the CMS give a warning only (D-19).

## D11: Decisions from M2, writers and document model (manager, 2026-10-10)
1. **Edits:**
   - Edits are layered on the lazy store and keyed by `ObjectId`. `Edit` is crate-private and holds `Arc<Object>`. Every public read sees edits first.
   - The store's own loads (indirect `/Length`, object-stream containers) read the source only, so editing them never changes how the source is parsed.
   - `add` returns `Result<ObjectId>` (`LimitExceeded` at `max_objects`). Trailer edits are limited to `/Root`, `/Info` and `/ID`.
2. **Full save:**
   - GC starts from every carried trailer entry. References to objects that are not in use are written as `null`. Stream `/Length` is always written directly and never followed.
   - With renumbering, numbers are dense from 1. Object streams hold at most 100 objects. The source's own xref and object-stream containers and the linearization dictionary are dropped.
   - `/ID` comes from the options, otherwise the first trailer element plus an MD5 of the body. MD5 is a private RFC 1321 implementation tested against the RFC vectors; there is no RNG in the core.
3. **Incremental save:** never touches the source; follows the previous xref kind; tables are zero-indexed; never uses object streams.
   - Edited `Decoded` streams are Flate-encoded, but source data is never recompressed.
   - `/Prev` is written in the file's offset base.
   - Saves are refused for reconstructed or `structure_repaired()` stores, so `OffsetBase::Absolute` files are full-save-only.
   - `incremental_update()` returns the absolute span of every written object and the xref position (used by M3).
   - The new file length is `source.len() + suffix.len()`. After reopening, the new revision's `eof_end` equals it.
4. **Strictness in the model:** strictness governs the syntax layer only. Document-model repairs (wrong `/Count`, invalid kids, bad boxes or `/Rotate`, wrong Info types) are diagnostics in both modes. Exceeding a limit is an error in both modes. Model diagnostics have their own `DiagnosticKind`s.
5. **Inheritance:** inherited page attributes follow the path the page-tree walk took, as poppler and qpdf do. A `/Parent` that disagrees gets a diagnostic. Setters write the inherited value onto the leaf before changing it.
6. **PDFDocEncoding matches qpdf exactly:**
   - Undefined C0 codes 0x00–0x17 pass through.
   - 0x7F, 0x9F and 0xAD decode to U+FFFD.
   - Encoding writes only defined codes, and anything else goes to UTF-16BE with a BOM.
7. **`PageInfo` size:** `width`/`height` are the effective size (crop box after rotation). `mediaBox`, `cropBox` and `rotation` are exposed separately.
8. **`Document::new()`** produces a valid zero-page PDF that qpdf and pypdf accept. poppler `pdfinfo` rejects zero-page files ("Invalid page count 0"), so that oracle row is a `knownFailure`.
9. **DTOs:** `Rect`, `PdfDate`, `DocInfo` and the other DTOs are `#[non_exhaustive]` (§A.8 #4) and are built through constructors outside their crates.
10. **Object numbering:** `Store::next_object_number()` (and so `add`) numbers above every number that any xref section lists, any edit uses, or any source object or trailer **refers to**, as qpdf's fixDanglingReferences does. New objects therefore never collide with dangling references, and never reuse freed numbers.
11. **Where incremental updates are refused:** they are also refused (`Unsupported`, "full save required") when an in-use object is not at the offset its xref entry gives, because poppler would rebuild such a file and lose the update. `Store::check_incremental()` tells callers ahead of time.
12. **Page setters:**
    - They write on the page object itself, never on a `/Pages` ancestor.
    - `set_media_box` re-clips a crop box that reaches outside the new media box.
    - `set_crop_box(None)` means "crop box = media box".
    - Invalid rectangles give `InvalidArgument`.
13. **Serde and JSON shapes, shared by Node and Tauri:**
    - `Rotation` is a number of degrees. `PdfDate` is a PDF date string. `Trapped` is `"true" | "false" | "unknown"`.
    - `InfoUpdate` has three states per field: absent keeps, `null` removes, a value sets. `custom` is a map of `string | null`.
    - `DocInfo` leaves absent entries out.
    - All names are camelCase.
14. **Text strings written by `set_info`:** literal when the text fits PDFDocEncoding, otherwise hex UTF-16BE with a BOM. A value whose bytes already match is no change.
15. **Node native memory:**
    - Documents report `Store::memory_estimate()` to V8, and `close()` or `[Symbol.dispose]` (`using`) frees a document at once. After that every method throws `E_CLOSED`.
    - **Bounded memory in long-running loops requires `close()` or `using`.** GC alone is not enough (README "Memory", ARCHITECTURE §A.7).
16. **Edit and save rules:**
    - Object-stream containers cannot be edited or freed while they hold members in use that no edit has replaced (§7.5.7).
    - `SaveOptions::validate()` accepts only real PDF versions (1.0–1.7, 2.0).
    - Signature dictionaries are recognised by `/Type /Sig`, `/ByteRange`, or `/Contents` plus `/Filter` or `/SubFilter`, and are never packed into object streams.
17. **Known limitation:** a name holding a NUL byte (non-conformant input such as `/A#00B`) is copied as `#00`, which qpdf rejects. Garbage in, garbage out; a later sanitising option may rewrite such names.
18. **Build profile:** `[profile.dev] debug = "line-tables-only"` keeps per-worktree build directories small.

## D12: Decisions from M3, signatures I (manager, 2026-10-11)
1. **The modification classifier is whitelist-based** (V10 in the M3 brief, ARCHITECTURE §A.6.7).
   - A later revision gets a level below `Other` **only** for the exact changes legitimate later signers make. Every other change to an object reachable from the signed revision is `Other`.
   - The result is never more lenient than pyHanko. Each stricter result has a `sign-attacks` case and a `DELIBERATE_DIFFERENCES` row.
   - This principle replaced rule-by-rule emulation of pyHanko after three QA rounds kept finding new shadow Hide/Replace variants.
2. **AcroForm whitelist, final after five hardening rounds.** Only three AcroForm changes stay below `Other`:
   - (a) `/Fields` gaining new root-level signature fields, with their widget, signature dictionary and the page `/Annots` append;
   - (b) the `/SigFlags` change that signing requires;
   - (c) `/DR` gaining **new** resource names that no signed `/DA` selects. The check covers the field tree, **every widget on every page** and the AcroForm `/DA`, and is tokenized with the PDF lexer. An incomplete walk counts as `Other`.

   Everything else is `Other`:
   - any change to `/NeedAppearances`, including removal, since removing it reveals stale stored appearances;
   - adding, changing or removing `/DA` (exceptions for "safe" additions leaked twice);
   - `/Q`, `/DR /Encoding`, and removing or replacing `/DR` names.

   **Consequences:**
   - Documents whose later signer deleted `/NeedAppearances`, as pyHanko's signer does, or added an AcroForm `/DA` show the earlier signatures as `Other` (stricter than pyHanko, recorded).
   - **Residual risk:** a new `/DR` name used only by a signed appearance stream that has no `/Resources` of its own.
3. **Role objects:** an old `/Info`, `/Metadata`, `/Extensions` or `/MarkInfo` object, and the AcroForm, `/Fields` and `/Annots` arrays, keep their relaxed rule only while the new revision still points to them.
4. **New signature fields:**
   - A new field carrying `/A`, `/AA`, `/OC` or `/Parent` is `Other`. `/MK` is allowed.
   - Catalog `/Version`, `/Extensions`, `/MarkInfo` and an XMP `/Metadata` stream count as `LtaUpdates`, as in pyHanko.
5. **Trust:** `trusted` requires `intact && signature_valid`, and is `None` without trust anchors.
   - Trust problems (`WeakAlgorithm` for SHA-1, MD5 or RSA < 2048 in the path) appear in `problems`, so `is_valid()` is false for them.
   - Path building is bounded and covers RFC 5280 basics. There is no revocation and no network.
6. **CMS:**
   - The certificates `[0]` SET is DER-sorted (brief §4.3), and the signer is found through IssuerAndSerialNumber.
   - `verify_detached` requires eContentType id-data, which is stricter than pyHanko.
   - PKCS#12 files in indefinite-length BER (some Windows and Java exports) are not supported yet.
7. **Node API:**
   - `verifySignatures` is async only.
   - The verify option is named `extraCertificates`.
   - `ExternalSigner.sign(tbs, digest, digestAlgorithm)` may return an `ArrayBuffer` (WebCrypto).
   - `signPdf` retries placeholder overflow once, using `details.needed`, only when the caller set `contentsReserve`.
   - The first `finish`/`embedCms` call consumes a `PreparedSignature`; keep `serialize()` bytes to retry.
   - `LocalSigner` supports `close()`/`using`.
   - Report objects use the core serde JSON shape, except that certificate `der` is a Buffer.
8. **Hardening limits:** the number of signature reports and the revisions analysed are bounded, as are the field-tree name lengths. The verify cost is linear in file size times a bounded signature count.
9. **`/SigFlags`:** every `/SigFlags` change after a signature is `Other`, matching pyHanko's strict comparison. Folioxide sets it only while no field is signed, so sequential signing never trips it.
10. **Remaining residuals, documented:** names used inside a nested form XObject of a signed appearance stream are not read, and neither are names a viewer looks up in `/DR` after missing them in a stream's own `/Resources`. **M4 QA must include an independent adversarial pass on the classifier**, because the M3 round-5 expert pass was cut short.


## D13: M4 design decisions (expert proposal, accepted by the manager, 2026-10-11)
All 24 open decisions in `docs/milestones/M4.md` §8 (D-1 … D-24) are accepted as recommended. The most important:
1. **D-1, the single exception to D10.1** ("never more lenient than pyHanko"):
   - On documents certified with P = 3, adding plain markup annotations, from an add-only whitelist with no actions, JavaScript or appearance tricks (M4 §5.2), is reported as `Annotations` where pyHanko reports `Other`.
   - Rationale: P = 3 explicitly permits annotations (ISO 32000-2 §12.8.2.2). Reporting them as `Other` would make every reviewed P = 3 document look tampered with.
   - The default acceptance threshold (`formFilling`) still rejects `Annotations`, so callers must opt in or rely on `docmdp_ok`.
   - The rows in M4 §0.2 record it, and the M4 adversarial pass (D12.10) must cover it.
2. **D-2, P = 1 is stricter than pyHanko:** `/Info` and XMP changes give `docmdp_ok = false`, where pyHanko gives true. ROADMAP M4 acceptance #3 is reworded accordingly.
3. **D-3:** no new **visible** signature field on certified documents (`DocMdpForbids`). Existing empty fields and invisible approval signatures are still allowed.
4. **Timestamps:**
   - The TSA certificate is checked with OpenSSL's timestamp-signing purpose; a failure makes the token invalid (D-4).
   - Several tokens are accepted, and the earliest sound and trusted one is selected (D-5).
   - Timestamp problems are reported in `TimestampInfo` and do not affect the signature's `is_valid()` (D-6).
   - The signer is validated at a trusted `genTime` when no validation time is given (D-7).
   - `tsa_reserve` defaults to 8192, with one retry (D-8). `grantedWithMods` is accepted (D-9).
   - A nonce is mandatory and compared as an INTEGER (D-10). Requests use SHA-2 (D-11).
   - BER tokens are embedded verbatim, with a warning (D-12).
5. **D-13:** `docmdp_ok` is always computed, and `is_acceptable` requires `docmdp_ok != Some(false)`. This changes the semantics of an M3 API before 1.0.
6. **Form-fill whitelist:** deliberate stricter differences per D-14. XFA, and the evaluated signature's own FieldMDP, make generic form filling `Other` until M11 (D-23).
7. **Visible signatures:**
   - Fonts are Helvetica and Helvetica-Bold, with WinAnsi encoding and `?` replacement. AFM metrics come from the PDFBox resources, with the Adobe notice in `NOTICE` (D-16).
   - JPEGs: SOF0/1/2, 8-bit, gray or RGB only; CMYK comes in M7 (D-17).
   - The rectangle is in default user space, with rotation compensation (D-18).
8. **Test infrastructure:**
   - MockTsa lives in the testkit (D-21).
   - New oracle runner keys: `renderProbes`, `timestamp: "invalid"` and `timestampTrusted` (D-22).
   - B-T through a later document timestamp is deferred to M11 (D-20).

## D14: Decisions from M4, signatures II (manager, 2026-10-23)
The M4 QA gate ran five review rounds, two final fix rounds, a closing round and their verification passes. The rulings were issued as R-1 … R-28. The binding outcomes:

1. **Verification is a whitelist over unambiguous input.**
   - The classifier grants a level below `Other` only when every object its decision reads is lexically canonical. Those objects are:
     - every object written after the signed revision;
     - the signed copies of the objects those writes relist or compare against;
     - the page-tree objects it consults;
     - the signature's own dictionary, field, `/Lock` and `/Reference` chain.
   - Canonical means (R-1, R-12):
     - no duplicate keys;
     - integers `[+-]?[0-9]+` in 32-bit range;
     - reals in plain decimal form within ISO 32000-2 Annex C limits;
     - no `#00` in names;
     - object streams and xref sections that list each object once, with canonical headers and 20-byte entries.
   - The parser itself is unchanged (last value wins). A defect in the signature's own objects is the `SigDictAmbiguous` problem.
2. **Updates must be rebuild-proof (R-17, R-18, R-21, R-26).** Otherwise the update is `Other`. The conditions:
   - the final `startxref` lies in the last 1024 bytes;
   - at most two EOL bytes follow the final `%%EOF`;
   - the store needed no repair, and every new object sits at its xref offset;
   - no text of the update (stream data, strings, names and comments included) is structure to a reader that rebuilds the cross-reference data. The final shape of the R-17 (d) scan:
     - where poppler's `constructXRef` looks (a line start, the start of each 255-byte piece of a longer line, and the bytes after an `endobj`, past white space): no object header, and no `trailer` before a dictionary;
     - at a line start or after an `endobj`: no `xref` or `startxref`;
     - anywhere: no object header `N G obj` and no `trailer <<` written as words (PDFium's `RebuildCrossRef`, pdf.js's `indexObjects`);
     - one scan, linear by construction (closing round findings 2 and 6, R-27: 16 MB runs of digits, white space, `endobj`, `trailer` and `%` each verify within a step budget);
     - it fails closed on some honest values: `x endobj xref`, `see 12 0 obj`, `trailer <<` inside a fill value, or a line inside a string that begins with `xref`, are `Other` where pyHanko says `formFilling`. `see xref table` inside a line stays a fill.
   - every member of a new object stream is listed by that revision's xref, at its index;
   - **`/Size` (R-26, closing round finding 13):** every later trailer, and a hybrid section's cross-reference stream dictionary, gives `/Size` as a direct integer above every object number the file lists and not below the previous revision's `/Size`. So a hybrid `/XRefStm` stream without a direct `/Size` is `Other` (ISO 32000-2 Table 17 requires it). An over-declared `/Size` (above the highest number + 1) drops nothing and passes.
     - The rule rests on the expert's recollection that PDFium shrinks its object table to the newest `/Size` (`ShrinkObjectMap`). That is unverified (brief §9; PDFium is not installed), so the rule is a whitelist, not a reproduced render difference. A pypdfium2 probe is on the backlog.
     - Folioxide's signer numbers a signature's new objects from the previous `/Size` when that is above `next_object_number()`, as pyHanko's writer does. So its co-signature after an over-declared `/Size` keeps the earlier signatures' level (final fix round 2 verification, expert finding 1: it had made them `Other`). The plain incremental writer (`Document::save_incremental`, Node `saveIncremental`) carries the previous `/Size` the same way: it writes max(highest + 1, the previous direct `/Size` within `Limits::max_objects`). That change in `folioxide-syntax` is the one waiver of brief §6.1, ruling R-30 (a).
3. **Page consistency (R-13).**
   - Page-dependent rules need a page that the `/Kids` walk reaches exactly once and whose `/Parent` chain mirrors that walk.
   - Rotation is inherited along that walk.
4. **Geometry (R-2, R-3, R-14, R-21).**
   - New markup annotations need an `/AP /N` form XObject with a `/BBox`, and all their geometry must lie inside `/Rect`.
   - New annotation and signature widgets may set only `/F` bits 1, 4, 64, 128 and 512.
   - Text annotations on rotated pages are `Other`.
   - Form fills of widgets with NoZoom, NoRotate or reserved `/F` bits are `Other`.
   - Geometry numbers are bounded at 1e5, and so are BBox corners mapped through `/Matrix`.
   - The largest coordinate of a new appearance's `/BBox` mapped through its `/Matrix`, times its scale onto the `/Rect`, is at most 2^20 (final fix round 2, findings 2 and 4). Single-precision readers (PDFium) then place it as Folioxide does, to within 1/16 unit.
     - The bound over-refuses some placements PDFium gets right: a 1-unit `/BBox` translated by 10^4 to 5·10^4 is `Other` in ours, `formFilling` in pyHanko, with 0 px outside in PDFium (closing round nit 4). A finer model (|mapped left| × scale) is on the backlog.
   - A new signature widget's `/Rect` must be four numbers.
   - `SIG_FIELD_KEYS` is a whitelist that includes `/Lock`, `/SV` and `/StructParent`.
5. **DocMDP.**
   - A field `/Lock /P` (ISO 32000-2 §12.7.5.5) sets the signature's DocMDP level; with a DocMDP reference too, the stricter value wins (R-4).
   - An unreadable DocMDP declaration means P = 1 for both verification and signing (R-6).
   - A missing `/P` in TransformParams means 2 (Table 257). This is the one DELIBERATE_DIFFERENCES row that is not stricter.
   - `P_effective` = min(own P, P in force).
   - `docmdp_ok` is `None` for DocTimeStamp entries (R-5). Their modification is still judged under the permissions in force, for markup annotations (R-20; P = 1 is item 13). This amends D13.5.
6. **pyHanko parity rows.**
   - A field whose signed `/AP` dictionary has more than one usage context makes every later change `Other`, as pyHanko does (R-19). This covers:
     - every field node of the signed revision, terminal or not (pyHanko's `_list_fields` yields every named node; closing round finding 10);
     - unnamed nodes and `/Fields` roots too, which is stricter than pyHanko;
     - an unsigned signature field, for the revision that signs it (pyHanko's `SigFieldModificationRule`; final fix round 2, finding 1). The signer warns when it signs such a field.
   - The approval-plus-P = 3 markup row is accepted as part of D-1 (R-7).
   - Document-timestamp bookkeeping (the `/Info` ModDate and Producer, XMP `xmp:ModifyDate` and `pdf:Producer`, `/Version`, ESIC) is exempt only in the revision that adds the timestamp, and only for that object's last write in the window (R-8).
   - The XMP comparison is a strict subset that libxml2 accepts: masked values, the XML declaration, namespace URIs, and Flate-only metadata filters. Anything else is `Metadata`.
7. **Timestamps and certificate paths (R-11, R-14, R-22, R-26).**
   - Tokens are read as a whitelist that OpenSSL can decode.
   - ESS later identifiers must name certificates on the validated path.
   - The `TsaNameMismatch` problem code covers RFC 3161 §2.4.2.
   - AKI consistency is checked on every path edge.
   - An RSASSA-PSS SPKI may verify PSS signatures only.
   - TSA certificates with duplicate or undecodable known extensions are invalid.
   - **OpenSSL's critical-extension rule (R-26, closing round findings 8 and 11).** A critical extension that OpenSSL 3.0's `X509_supported_extension` does not list (subjectKeyIdentifier, authorityKeyIdentifier, authorityInfoAccess, freshestCRL, qcStatements, private extensions) has two effects:
     - it makes a TSA certificate unsuitable: the token is invalid, and the signer refuses it;
     - it makes any signer or TSA path untrusted.
     - This is stricter than pyHanko and equal to OpenSSL; RFC 5280 says SKI, AKI and AIA must be non-critical. Only keyUsage, subjectAltName, basicConstraints, cRLDistributionPoints, certificatePolicies, extKeyUsage and ocspNoCheck may be critical. A critical extension that OpenSSL handles but Folioxide does not process (nsCertType, name or policy constraints, RFC 3779, proxyCertInfo) stays a trust problem, stricter than both.
   - **PSS hash parameters (R-26, closing round finding 7).** The hash and MGF1-hash AlgorithmIdentifiers inside `RSASSA-PSS-params` must have absent or NULL parameters (RFC 4055 §2.1).
     - On an anchor's or intermediate's key this equals pyHanko (untrusted) and is stricter than OpenSSL, which ignores them.
     - In a token's own signature algorithm, or on the TSA certificate's key, it makes the token invalid. That is stricter than pyHanko and than `openssl ts -verify`, which both ignore them there.
   - **Certificate signature algorithm parameters (R-30 (b)).** On every certificate-signature check (path edges and the ESS links behind a TSA's signing-certificate list), the parameters of both `tbsCertificate.signature` and the outer `signatureAlgorithm` must be:
     - absent or NULL for RSA PKCS#1 v1.5 (RFC 4055 §5). That equals pyHanko and is stricter than OpenSSL;
     - absent for ECDSA (RFC 5758 §3.2). That is stricter than both pyHanko and OpenSSL, and recorded as deliberate-difference rows.
     - Otherwise the edge is untrusted. A consequence: a TSA certificate with bad RSA parameters plus an ESS list with later identifiers makes the token not valid (`TimestampEssMismatch`), where pyHanko and OpenSSL call it valid. That case is stricter and has no dedicated test.
   - **Limitation: trust anchors are trusted as given** (RFC 5280 §6.1.1 (d), pyHanko parity). Their validity, CA flag, key usage and extensions are not evaluated. So an anchor with a critical extension OpenSSL would refuse is trusted where `openssl ts -verify` fails (OpenSSL's `check_chain_extensions` also checks the anchor). This is on the backlog.
   - **Limitation:** `signPdf` embeds, without a warning, a token whose TSA path can never become trusted (a well-formed RFC 3779 block or `proxyCertInfo`: untrusted at verification, stricter than pyHanko). An optional signing-time warning is on the backlog (closing round nit 9).
   - RSASSA-PSS-signed tokens and subjectKeyIdentifier signer identifiers are **accepted**. This is a recorded exception to M4 §5.5 (iii): only OpenSSL 3.0's PKCS7-based `ts -verify` refuses them, while pyHanko and `openssl cms -verify` accept them.
   - The request nonce is ≥ 1.
   - Unsigned attributes beyond `MAX_ATTRIBUTES` are skipped with a warning.
8. **The verify API.**
   - A duplicate `/Prev` or `/XRefStm` with different values makes `verify` fail with `E_XREF`.
   - ECDSA values in SignerInfos, tokens and certificates must be minimal DER; only `finish` normalizes signer output.
9. **Node.**
   - After `timestampRequest`, `finish` without a response is refused until `discardTimestampRequest()` is called.
   - `signPdf` passes its own request explicitly.
   - `accuracyMicros` is `null` above 2^53.
10. **Signing side.**
    - A new visible field on a certified document is refused (D-3).
    - An existing empty field whose widget is Hidden or NoView is refused for visible signing.
    - A split widget (`/Kids`) is refused, which is backed by pyHanko reporting OTHER for that case (D-18 probe).
    - The appearance font carries a `/FontDescriptor`. It is not embedded until M7, so PDF/A conformance is not met.
    - A signature's new objects are numbered from the larger of `next_object_number()` and the previous trailer's `/Size` (item 2).
    - **Limitation (R-24):** only a JPEG's header is parsed. A JPEG whose scan data cannot hold the size its SOF declares (an empty scan, say) is embedded unchanged, and viewers then draw nothing or an error box inside the appearance. Decoding or sizing the scan belongs to M7's image work.
11. **Residuals, stated in M4 brief §0.3 and ARCHITECTURE §A.6.7.** These are levels below `Other` whose change a viewer can still show:
    - **The premise.** Every residual assumes that all readers read the bytes the same way. That is checked only for the lexical differentials of V10 (the canonical-input gate, R-12; page-tree consistency, R-13; rebuild-proof updates, item 2), not for every way two readers can differ.
    - **`FormFilling`:** a filled field shows any text the filler chooses inside the widget's `/Rect`, and an opaque fill can cover signed page content beneath it. pyHanko and Acrobat allow both. The visible signature appearances of later signers likewise draw what they like inside their `/Rect`.
    - **`Annotations` (D-1):** an opaque markup annotation inside its `/Rect` can cover signed content. That is what P = 3 grants.
    - Text annotations' implicit NoZoom affects zoomed-out viewers.
    - **Shared `/Annots` arrays** (QA round 5 finding 9): a later signature widget added to an indirect `/Annots` array that several pages share shows on each of those pages, inside its `/Rect` as each page maps it. A shared array that gains a markup annotation is `Other`, so D-1 does not reach this.
    - JavaScript calculate, format and validate actions (`/AA`, `/CO`) of signed fields run in JS-capable viewers on filled values.
    - Signature timestamps can be removed or replaced (until LTA in M11).
    - **Retired TSA keys** (QA round 1 finding F8): without a validation time, the TSA path and the signer are validated at the token's own `genTime`. That time is the TSA's claim, so a TSA key that outlived its certificate can sign a token that makes itself and the signer trusted. Both carry a warning. A caller (and the Node binding, which passes "now" by default) breaks the circle with a validation time.
    - **Document timestamps under P = 1:** the decision is item 13.
    - pdf.js's rebuild (which runs only when its cross-reference data cannot be read) ends an object body at a word `xref` inside a line. It is not probed; item 2 leaves pdf.js nothing to rebuild for.
    - Viewers that are not installed (PDFium, Acrobat, MuPDF, pdf.js) were not probed.
12. **Process (M4 lesson).** The independent adversarial pass found new mechanism classes in every round.
    - It is closed by an explicit criterion (R-25, R-28): saved variants are re-run and fixes are verified. Exploration is limited to 25 %, and to none in the closing pass.
    - New classes go to the **verification-hardening backlog in ROADMAP** unless they are reproduced Blockers. The backlog section lists the items M4 deferred: a pypdfium2 probe of the `/Size` rule, the trust-anchor extension check, the nit 9 signing warning, an Acrobat `/F 28` sample, the stricter variant of item 13's timestamp decision, a finer single-precision bound, pdf.js's rebuild, and the probes of viewers that are not installed.
    - Rulings are issued between rounds as numbered, binding text (`R-n`) that every agent reads.
13. **Decisions the brief and ARCHITECTURE leave to D14.** Dev A proposed both in final fix round 2, and the manager confirms them as written.
    - **Sticky notes with `/F 28`** (Print | NoZoom | NoRotate; brief §0.2): they stay `Other` on every page in M4 (A3, R-2).
      - Reasons: no Acrobat-made sample was checked, and NoZoom draws a note at a fixed size, which spills out of its `/Rect` when zoomed out.
      - Cost: this removes part of D-1's benefit, because Acrobat is believed to write `/F 28` for sticky notes.
      - Relaxing it, for a Text annotation with an `/AP` on an upright page, needs an Acrobat sample and a render probe at several zoom levels. It is on the backlog.
    - **Document timestamps under P = 1** (brief §0.3, ARCHITECTURE §A.6.7): M4 keeps pyHanko parity.
      - A timestamp's window is judged under the P in force only for markup annotations. So after a P = 1 certification, a timestamp followed by a form fill, an `/Info` or XMP change or an approval signature reports `formFilling` or `ltaUpdates` with `docmdp_ok` `None`, and `is_acceptable(FormFilling)` accepts that report.
      - The violation shows in the certification's own report (`docmdp_ok` false). The docs tell callers to check every report.
      - Criterion (i) holds. Making such a timestamp entry `Other` would be stricter and safe; it is on the backlog, at the latest for LTA in M11.
14. **Dependencies.** `ctutils` is bumped from 0.4.2 to 0.4.4 in `Cargo.lock` for RUSTSEC-2026-0385, a RustCrypto transitive dependency. This was needed for `cargo deny`, and adds no new dependency.

## D15: M5 design decisions (expert proposal, accepted by the manager, 2026-10-23)
All 22 open decisions in `docs/milestones/M5.md` §9 (D-1 … D-22) are accepted as recommended, together with the deliberate differences E1–E15 (encryption) and P1–P6 (page operations) of brief §0. The most important:
1. **One exemption predicate (D-1).**
   - A single function in `folioxide_syntax::crypt`, shared by the reader and both writers, decides which strings and streams are not encrypted.
   - The signature `/Contents` uses the D11.16 signature-dictionary predicate, which is wider than qpdf's (E7).
2. **No padding oracle (D-2).**
   - Padding validity is never observable: no error code, diagnostic or timing difference beyond the unavoidable.
   - Only key-independent ciphertext defects produce diagnostics.
   - XMP changes in encrypted files are `Other` (E15, stricter than pyHanko).
3. **Page operations on signed or certified files are refused (D-3).**
   - The errors are `E_SIGNED_DOCUMENT`, a new `ErrorCode::SignedDocument`, and `E_DOC_MDP_FORBIDS`.
   - Opting in with `allow_invalidating_signatures` overrides the refusal.
   - The rule also applies to the M2 page setters. This is a behaviour change before 1.0.
4. **No ambient randomness (D-4).**
   - New R6 encryption takes a caller seed, and IVs are synthetic (HMAC-derived, brief §1.8).
   - The save functions take no RNG; Node passes a seed from `crypto.randomBytes`.
5. **Revisions.**
   - R5 is read, and an existing R5 dictionary is kept on saves; Folioxide never creates one (D-5).
   - ISO/TS 32004 MACs are detected. Incremental saves and signing are refused for them, and a full save drops the MAC (D-6).
6. **Passwords (D-7, D-8).**
   - At most two candidates are tried, and password bytes are used verbatim.
   - The owner password defaults to the user password.
   - Restricted permissions with an empty owner password, or one equal to the user password, are refused because they cannot be enforced.
7. **Permissions (D-9).** Permissions are reported by default (D5.2). `OpenOptions::enforce_permissions` enforces the brief §5.5 table.
8. **The page tree (D-10).**
   - It is flattened on the first structural operation (qpdf parity).
   - A full save rebuilds a balanced tree with fanout 32, through the writer's overlay.
   - Incremental saves keep the tree flat.
9. **Defaults for page operations (D-11, D-12, D-13, D-19, D-20, D-21).**
   - A blank page takes the neighbouring media box, else US Letter.
   - Links to pages that were deleted or not imported are dropped (pypdf parity).
   - Signed signature fields are dropped on import.
   - AcroForm merges rename fields `name#k` and `/DR` fonts `Name_k`, with `/DA` rewritten, and remove the target's `/XFA`.
   - Named destinations become explicit on import.
   - `ImportSession` identity is a `Weak<DocIdentity>` plus an edit epoch, with no global counter.
10. **Crates and encodings (D-14 … D-18).**
    - RC4 comes from `rc4` 0.2.0, with a fallback to our own implementation.
    - The PDFDocEncoding table moves to `folioxide-syntax::text::pdfdoc`.
    - Ciphertext strings are written as hex.
    - New R6 files are PDF 1.7 with `/Extensions /ADBE` level 8, or 2.0 on request.
    - Writing RC4 needs `allow_weak_crypto` (qpdf parity).
11. **Errors (D-22).**
    - `ErrorCode::SignedDocument` is new; there is no `E_PAGE_RANGE` or `E_ENCRYPTED`.
    - `DiagnosticKind::{Encryption, Ciphertext}` are new.
12. **QA (brief §7).**
    - Two general lenses and two adversarial lenses: H (hostile encrypted input) and G (page-operation graph integrity).
    - Variant minimums and pass criteria (i)–(vii) are fixed up front.
    - Closure rule: at most 3 review rounds plus a closing round. Every round re-runs all saved variants, new-class exploration is capped at 25 %, and the closing round is verify-only.


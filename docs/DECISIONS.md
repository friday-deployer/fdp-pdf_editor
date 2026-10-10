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

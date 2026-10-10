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

## D6: License (manager, 2026-10-10)
- The project license is `MIT OR Apache-2.0`, the Rust ecosystem convention.
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

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
1. **MSRV:** the core declares `rust-version = "1.85"` (edition 2024). Development is pinned to 1.97.0 through `rust-toolchain.toml`. The `render` feature will need 1.92 or later.
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

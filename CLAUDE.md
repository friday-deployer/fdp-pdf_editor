# Folioxide: a pure-Rust PDF editor core

Folioxide is a fully featured PDF editing engine written in pure Rust.
- **Consumers:** Node.js first, through the napi-rs addon in `bindings/node` (npm package `folioxide`). A Tauri desktop app later links the `folioxide` crate directly.
- **Priorities:** PDF signing, then page & document ops, then annotations & forms, then content editing.

Read these before working:
- `docs/ARCHITECTURE.md`: the design. It is the source of truth for crate layout, data model, signature design and spec traps.
- `docs/ROADMAP.md`: milestones, work packages, acceptance criteria and progress.
- `docs/DECISIONS.md`: the decision log.
- `.claude/team.md`: team roles and the milestone/QA workflow. Agent role cards are in `.claude/agents/`.

## Repository layout
```
crates/folioxide-syntax       L1  objects, lexer, parser, xref, object streams, filters, lazy store, writers, limits, ErrorCode
crates/folioxide-security     L2  standard security handler (RC4/AES-128/AES-256), permissions
crates/folioxide-model        L3  Document, catalog, page tree, page ops, import/merge, metadata, outlines, labels, attachments, optimize
crates/folioxide-content      L4  content streams, fonts (embed/subset), images, text layout, text extraction
crates/folioxide-interactive  L5  annotations + appearances, AcroForm fill/create/flatten
crates/folioxide-sign         L5  keys (PKCS#12/PEM), CMS/PAdES, timestamps, sign/prepare/finish/verify, DocMDP
crates/folioxide-redact       L5  true redaction, existing-text editing (M10)
crates/folioxide-render       L5  hayro adapter (later)
crates/folioxide              facade: re-exports, feature flags, unified Error, serde DTOs, std-fs helpers
crates/folioxide-testkit      (publish = false) byte-level PDF builder, fixture generators, test PKI, mock TSA
bindings/node                 crate folioxide-node (cdylib, napi v3) + npm package `folioxide`
fixtures/                     small committed fixtures; README.md records provenance and license per file
tools/                        oracle venv setup, PKI generation, Python cross-validation scripts
xtask/                        cargo xtask fixtures | oracle [--suite X] | ci
fuzz/                         cargo-fuzz targets (outside the workspace)
docs/                         architecture, roadmap, decisions, API docs
```
Dependency direction is strict: `syntax ← security`, `syntax ← model`, `model ← content ← interactive`,
`model + content ← sign`, `content + interactive ← redact`, everything ← `folioxide` ← `bindings/node`.
Never add an upward or sideways dependency without updating ARCHITECTURE.md.

## Gate commands (Definition of Done)
Run from the repo root. All must pass before a work package counts as done.
```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check                                  # licenses, bans, sources, advisories
(cd bindings/node && pnpm install && pnpm build && pnpm test)   # when bindings changed
cargo xtask oracle [--suite <name>]               # cross-validation against poppler/pypdf/pikepdf/pyHanko/openssl
```
Oracle setup (once): `bash tools/setup-venv.sh` creates `.venv/` with pinned pypdf, pikepdf and pyHanko.
These are dev-only external processes and are never linked.

## Engineering rules
- **Pure Rust, permissive licenses only.** Allowed: MIT, Apache-2.0, BSD-2/3, ISC, Zlib, Unicode-3.0, MIT-0, CC0. No GPL, AGPL, LGPL or MPL crates and no C/C++ PDF libraries. Add every dependency to `[workspace.dependencies]` with an exact or caret pin and `default-features = false` where sensible.
- **Never panic on untrusted input.** In library code: no `unwrap`/`expect`/unchecked indexing or slicing on parsed data, `checked_*` arithmetic for sizes and offsets, and depth, size and count limits from `Limits`. Return `Result` with the crate error type, which exposes `code() -> ErrorCode`.
- **Lazy and faithful.** Source bytes are never re-serialized on incremental save. Reals are `f64`. Decryption happens on copies, never in place.
- **No ambient state in the core.** No clock, RNG or network I/O inside core crates: signing time, RNG and the timestamp provider are passed in. No global mutable state. `std::fs` only behind the `std-fs` feature.
- **Tauri readiness.** Core crates never depend on napi, Node or Tauri. `Document` and DTOs are `Send + Sync + 'static`. DTOs derive serde behind the `serde` feature with `camelCase` names.
- **RustCrypto types stay out of public APIs.** Public signatures take and return DER bytes and our own enums, because several crypto crates are pre-releases.
- **Spec references.** Cite ISO 32000-2 sections (e.g. `// §7.5.8.3`) in comments wherever behaviour is non-obvious.
- **Tests.** Every feature gets unit tests plus round-trip/integration tests. Tests are deterministic and never touch the network. Generated fixtures beat committed binaries; any committed fixture must be under 200 KB and documented in `fixtures/README.md`.
- **Docs.** Every public item has rustdoc. Every user-visible Node API gets JSDoc and a test in `bindings/node/test/`.
- **Style.** Edition 2024, rustfmt defaults plus `rustfmt.toml`, clippy clean with `-D warnings`. `unsafe` is forbidden in core crates.

## Node binding conventions
- **Class:** `PdfDocument`, with 0-based page indices at the boundary.
- **Sync and async:** heavy operations have `…Async` variants (napi `AsyncTask`). Sync methods `try_lock` and throw `E_BUSY` rather than block.
- **Errors:** JS errors carry `err.code = "E_<ERROR_CODE>"`, for example `E_WRONG_PASSWORD`. Messages never contain key material or passwords.
- **Tests:** Node's built-in runner (`node --test`) on `.mjs` files, plus TypeScript type tests run with `tsc --noEmit`.

## Git and team workflow
- **Branch:** `claude/eager-euler-ag4bjo`. One commit per QA-approved milestone, titled `M<n>: <title>`.
- **Only the manager (main session) commits and pushes.** Developers in a worktree commit on their worktree branch. Developers in the main tree leave changes uncommitted.
- **QA and the expert are read-only.** Findings use the severity scale in `.claude/team.md`. Nothing is committed while a Blocker or Major finding is open.
- **Progress:** update the milestone table in `docs/ROADMAP.md` when a milestone lands.

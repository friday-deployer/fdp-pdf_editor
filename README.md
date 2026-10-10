# Folioxide

Folioxide is a PDF editing engine written in pure Rust. It is built for Node.js first, through the
`folioxide` npm package (a napi-rs addon), and will later be linked directly by a Tauri desktop app.
The engine covers PDF signing, page and document operations, annotations and forms, and content editing.
It has no C or C++ PDF dependencies and is licensed under permissive terms only.

> **Status: pre-alpha.** M0 (project scaffolding) is done: the workspace, Node binding, test oracles,
> test PKI and CI are in place. M1 (the PDF syntax layer) is in progress. The library cannot open, edit or
> sign documents yet.

## Roadmap

Work is delivered in ordered milestones, each gated by QA. The priorities, in order, are:

1. **PDF signing** (PAdES, timestamps, verification)
2. **Page and document operations**
3. **Annotations and forms**
4. **Content editing**

Rendering and text extraction come later. The full milestone plan, work packages and acceptance criteria
are in [`docs/ROADMAP.md`](docs/ROADMAP.md). The design is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
and decisions are logged in [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Development quick start

Run these from the repository root. The gate commands are the Definition of Done for every work package.

Prerequisites: the Rust toolchain pinned in `rust-toolchain.toml` (1.97.0), `cargo-deny`, Node.js 22 with
pnpm, and Python 3 for the oracle tooling.

```sh
# Rust gates
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check                                  # licenses, bans, sources, advisories

# Node binding (when bindings/node changed)
(cd bindings/node && pnpm install && pnpm build && pnpm test)

# Oracles: cross-validation against poppler, pypdf, pikepdf, pyHanko and openssl
bash tools/setup-venv.sh                          # once: creates .venv/ with pinned Python tools
cargo xtask oracle [--suite <name>]
```

The oracle tools are dev-only external processes. They are never linked into the library.

## Repository layout

| Path | Contents |
|---|---|
| `crates/` | Rust crates, from the syntax layer up to the `folioxide` facade |
| `bindings/node/` | The napi-rs addon and the `folioxide` npm package |
| `fixtures/` | Small committed test fixtures, with provenance and license in `fixtures/README.md` |
| `tools/` | Oracle venv setup, test PKI generation and Python cross-validation scripts |
| `xtask/` | Project tasks: `cargo xtask fixtures`, `cargo xtask oracle`, `cargo xtask ci` |
| `fuzz/` | cargo-fuzz targets, outside the main workspace |
| `docs/` | Architecture, roadmap, decisions and milestone briefs |

`CLAUDE.md` holds the engineering rules and conventions for contributors.

## License

Folioxide is dual-licensed under either of

- the [MIT license](LICENSE-MIT), or
- the [Apache License, Version 2.0](LICENSE-APACHE),

at your option.

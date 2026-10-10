# Folioxide architecture

Folioxide is a pure-Rust PDF editing core. Node.js is its first consumer, through the napi-rs addon in
`bindings/node`. A Tauri desktop app will later link the `folioxide` crate directly.

- **Status:** the design was agreed at project start (2026-10-10) by the manager and the PDF expert.
- **Decision log:** [`docs/DECISIONS.md`](DECISIONS.md).
- **Milestone plan:** [`docs/ROADMAP.md`](ROADMAP.md).

Treat this document as the source of truth. A change to the architecture means an update here plus an entry in `DECISIONS.md`.

**The main decisions in brief:**
1. **We build our own syntax layer** (object model, lexer, parser, xref, writer). We do not use `lopdf` or `pdf-writer` in the core.
2. **The core is several `folioxide-*` crates behind a `folioxide` facade crate.** The Node addon lives in `bindings/node`.
3. **Crypto comes from the RustCrypto 2026 generation:** `der` 0.8, `x509-cert` 0.3, `sha2` 0.11, `p256`/`p384` 0.14, `ecdsa` 0.17 and `rsa` 0.10.0-rc.19. On top of those we use `cms` 0.3.0-pre.1 (for its types only) and `p12-keystore` 0.4.0 for PKCS#12.
4. **We write three pieces ourselves** because no suitable crate exists: CMS SignedData assembly, the RFC 3161 timestamp types, and the PAdES attributes.

## A.0 Glossary and spec references
- "ISO 32000-1" is PDF 1.7 and "ISO 32000-2" is PDF 2.0. Section numbers below follow ISO 32000-2 unless marked otherwise. Interactive-form subsection numbers differ between editions, so check against your copy.
- **PAdES** is ETSI EN 319 142-1. **CAdES** is ETSI EN 319 122-1. Relevant RFCs:
  - RFC 5652: CMS
  - RFC 5035: ESS signing-certificate-v2
  - RFC 3161 and RFC 5816: TSP
  - RFC 7292: PKCS#12
  - RFC 8018: PKCS#5

## A.1 Build vs buy: our own syntax layer, not `lopdf`

### Candidates (checked on crates.io API, 2026-10-10)

| Crate | Latest | License | Activity | What it is |
|---|---|---|---|---|
| `lopdf` | 0.45.0 (2026-09-08) | MIT | Very active (commits up to 2026-10-09); 84 open issues | Read/modify/write object model |
| `pdf-writer` | 0.15.0 (2026-05-27) | MIT OR Apache-2.0 | Active (typst) | Write-only, streaming, typed PDF writer |
| `hayro-syntax` | 0.8.0 (2026-10-04) | Apache-2.0 OR MIT | Very active | **Read-only** parser with xref repair. README: "main missing feature is support for password-protected documents" |
| `pdf` (pdf-rs) | 0.10.0 (2026-03-02) | MIT | Moderate | Typed reader with some writing support |

### Why not `lopdf`
I read `src/object.rs`, `src/document.rs` and `src/incremental_document.rs` on `main`.

1. **Eager object model.** `Document.objects: BTreeMap<ObjectId, Object>` loads every object at open time. Our large-file and lazy-loading requirements cannot be met without forking.
2. **`Object::Real(f32)`.** A full rewrite silently loses precision in coordinates and matrices. For example, 1234567.8 comes back as 1234567.75, and f32 only carries 7 significant digits. That is not acceptable for an editor whose output must be byte-faithful.
3. **Decrypt-in-place on load.** The README says "PDFs encrypted with empty passwords are automatically decrypted on load", so once loaded you can no longer map objects back to the original ciphertext. Incremental updates to encrypted files need the reverse mapping, and so does signing an encrypted file.
4. **Incremental updates are a separate type.** `IncrementalDocument { bytes_documents, prev_documents, new_document }` makes the caller copy objects into `new_document` by hand (`opt_clone_object_to_new_document`). There is no automatic dirty tracking, and the docs warn that a mismatch between bytes and the previous document "might result in broken PDFs". Signatures need one model that can do both full and incremental saves, with tight control over the bytes and offsets.
5. **No resource-limit model** for hostile input. The October 2026 commits are still fixing panics, for example "don't panic on huge predictor DecodeParms" (#589). The default features also pull in `rayon` threads.
6. **Coverage.** It covers at most the bottom 25–30% of what we need. Everything from the document model upward (forms, annotations, signatures, fonts, redaction) is ours either way.

### Why not `pdf-writer` in the core
- It is a write-once, ordered `Chunk` builder with no in-memory editing and no parsing.
- Our writer has to serialize arbitrary parsed objects, preserve object IDs and generations for incremental updates, and patch byte offsets for `/ByteRange`. A writer for our own `Object` type is about 600–900 lines.
- `pdf-writer` is fine as a **dev-dependency** for generating fixtures in tests.

### Why not `hayro-syntax`
It is read-only, has no encryption support, and its object types are built for rendering rather than editing.

### Decision
Build `folioxide-syntax`: our own `Object` model, lexer, lenient parser, xref (table, stream, hybrid), object streams, filters, a lazy object store, and full and incremental writers. Our own estimate is about 7–9k lines of Rust for M1 and M2 together.

What we reuse instead:
- `hayro` 0.8.0 for **rendering**, later. We hand it bytes we have serialized, decrypted if necessary.
- `hayro-ccitt` 0.4.0, and later `hayro-jbig2` / `hayro-jpeg2000`, as decoders.

`lopdf` may appear only as a dev-dependency (a second parser to cross-check against). That is optional, not required.

## A.2 Workspace and crate layout

Recommendation: **several crates behind one facade.** Reasons:
- Compile times: RustCrypto, the font stack and hayro only get rebuilt when their own crate changes.
- Feature gating is cleaner.
- Two developers can work in separate crates, which mostly avoids merge conflicts.
- Tauri depends on just the facade.

The cost is that some cross-crate items have to be `pub`. Hide them with `#[doc(hidden)] pub mod __private` or a `pub(crate)`-style convention, and keep the semver promise on the facade crate only.

```
fdp-pdf_editor/
├─ Cargo.toml                  # [workspace] members, [workspace.package] (edition 2024, license "MIT OR Apache-2.0"),
│                              # [workspace.dependencies] (all versions pinned here), [workspace.lints]
├─ rust-toolchain.toml         # channel = "1.97.0", components = ["rustfmt","clippy"]
├─ rustfmt.toml  clippy.toml  deny.toml  .cargo/config.toml (alias xtask = "run -p xtask --")
├─ CLAUDE.md                   # team conventions + gate commands (created in M0)
├─ crates/
│  ├─ folioxide-syntax/        # L1: objects, lexer, parser, xref, objstm, filters, store, writer, limits, Decryptor trait
│  ├─ folioxide-security/      # L2: standard security handler (RC4-40/128, AES-128, AES-256 R5 read / R6), perms
│  ├─ folioxide-model/         # L3: Document facade, catalog, page tree + inheritance, resources, name/number trees,
│  │                           #     text strings & dates, page ops, import, metadata (Info+XMP), outlines,
│  │                           #     page labels, attachments, optimize/GC
│  ├─ folioxide-content/       # L4: content-stream parse/build, graphics state, standard-14 metrics, font embedding
│  │                           #     + subsetting, images (JPEG/PNG), text layout, text extraction
│  ├─ folioxide-interactive/   # L5: annotations CRUD + appearance generators, AcroForm read/fill/create, flatten
│  ├─ folioxide-sign/          # L5: keys (PKCS#12/PEM), Signer trait, CMS/PAdES build+parse, TSP, sig fields,
│  │                           #     sign / prepare / finish / verify, DocMDP, modification analysis
│  ├─ folioxide-redact/        # L5 (M10): true redaction, existing-text editing
│  ├─ folioxide-render/        # L5 (later): hayro adapter → RGBA/PNG
│  ├─ folioxide/               # facade: re-exports, feature flags, unified Error/ErrorCode, serde DTOs, fs helpers
│  └─ folioxide-testkit/       # publish = false: byte-level PDF builder for broken files, fixture generators,
│                              # test-PKI loader, mock RFC 3161 TSA, oracle-output emitter
├─ bindings/
│  └─ node/                    # crate `folioxide-node` (cdylib, napi) + npm package `folioxide`
│     ├─ Cargo.toml  build.rs  src/{lib,document,pages,sign,forms,annots,errors,dto}.rs
│     ├─ package.json  index.js  index.d.ts   # hand-written facade (async helpers: sign(), TSA callback)
│     ├─ binding.js  binding.d.ts             # generated by `napi build`
│     ├─ npm/<platform>/package.json          # generated by `napi create-npm-dirs`
│     └─ test/*.test.mjs  test/types.test-d.ts
├─ fuzz/                       # cargo-fuzz crate, NOT a workspace member (excluded)
├─ fixtures/                   # small committed fixtures, README.md with provenance + license per file
│  ├─ pki/                     # test CA, RSA-2048/3072, P-256, P-384 signers, TSA cert; .p12 modern + legacy
│  ├─ syntax/  encrypt/  forms/  fonts/  images/
├─ tools/
│  ├─ setup-venv.sh  requirements-dev.txt     # pinned pyhanko/pypdf/pikepdf
│  ├─ gen-pki.sh  tsa/openssl-tsa.cnf
│  └─ oracles/{run_suite.py, check_pdf.py, validate_sig.py, extract_cms.py, pades_profile.py, text_check.py}
├─ xtask/                      # `cargo xtask fixtures | oracle [--suite X] | ci`
└─ .github/workflows/{ci.yml, release-npm.yml, fuzz-nightly.yml}
```

### Dependency direction (strict, enforced with `cargo tree` in CI)
```
syntax ← security
syntax ← model (→ security behind feature "encryption")
model ← content ← interactive
model + content ← sign            (content only for visible appearances)
content + interactive ← redact
model ← render (hayro)
all ← folioxide (facade) ← bindings/node ; future Tauri app → folioxide
```

### Facade feature flags (`crates/folioxide`)

| Feature | Default | Enables |
|---|---|---|
| `encryption` | yes | `folioxide-security` (open/save encrypted documents) |
| `signatures` | yes | `folioxide-sign` (pulls in RustCrypto) |
| `pkcs12-legacy` | yes | `p12-keystore/pbes1` (RC2-40 and 3DES PKCS#12 bags). Off gives modern PBES2/AES only |
| `fonts` | yes | TrueType/OpenType embedding and subsetting (`skrifa`, `subsetter`). Without it, only the standard-14 fonts |
| `images` | yes | PNG decoding (`png`). JPEG passthrough is always available |
| `jpeg-decode` | no | `zune-jpeg`, needed for pixel-level image redaction and for rendering |
| `shaping` | no | `harfrust` (complex scripts), plus bidi |
| `interactive` | yes | annotations and forms |
| `redact` | no until M10 | `folioxide-redact` |
| `render` | no | `folioxide-render` (hayro) |
| `serde` | no | `Serialize`/`Deserialize` on all DTOs (Tauri turns this on; Node does not need it) |
| `std-fs` | no | `Document::open_path`, `save_to_path`, `SystemClock`, optional mmap via `memmap2` 0.9.11 |

**No feature adds threads or network I/O.** A future `parallel` feature (`rayon`) could only speed up `optimize` and must never be required.

## A.3 Core data model (`folioxide-syntax`)

```rust
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ObjectId { pub num: u32, pub gen: u16 }      // ISO 32000-2 §7.3.10; num 0 is always free; gen ≤ 65535

#[derive(Clone, Debug, PartialEq)]
pub enum Object {
    Null, Bool(bool), Int(i64),
    Real(f64),                     // NEVER f32. Writer: no exponent (§7.3.3), ≤ 10 fractional digits, trim zeros, "-0"→"0"
    String(PdfString),
    Name(Name),
    Array(Vec<Object>),
    Dict(Dict),
    Stream(Box<Stream>),           // only valid as the top-level value of an indirect object
    Ref(ObjectId),
}
pub struct PdfString { pub bytes: Vec<u8>, pub hex: bool }   // keep literal vs hex form (sig /Contents must stay hex)
pub struct Name(Box<[u8]>);                                  // decoded bytes (#xx resolved); PartialEq<&[u8]>, consts for common keys
pub struct Dict(IndexMap<Name, Object>);                     // preserves order (deterministic output, readable diffs)
pub struct Stream { pub dict: Dict, pub data: StreamData }
pub enum StreamData {
    Source(Range<u64>),            // still-encoded bytes inside the source buffer (zero-copy; resolved through the doc)
    Encoded(Vec<u8>),              // encoded per dict /Filter, owned
    Decoded(Vec<u8>),              // plain; the writer encodes per SaveOptions (Flate by default), fixes /Length, /Filter, /DecodeParms
}
```

### The document store (lazy, `Send + Sync`, no mandatory threads)

```rust
pub type SharedBytes = Arc<dyn AsRef<[u8]> + Send + Sync>; // Vec<u8>, Arc<[u8]>, or Mmap (std-fs)

pub struct Store {
    source: Option<SharedBytes>,
    header_offset: u64,                    // junk before "%PDF-" shifts every offset (see risk register)
    revisions: Vec<Revision>,              // oldest → newest
    index: Vec<Slot>,                      // dense by object number (bounded by Limits::max_objects)
    edits: BTreeMap<u32, Edit>,            // the dirty set: what an incremental save writes
    next_num: u32,
    decryptor: Option<Arc<dyn Decryptor>>, // implemented by folioxide-security
    objstm_cache: HashMap<u32, OnceLock<Result<Arc<ObjStm>, ErrorCode>>>,
    limits: Limits,
    diagnostics: Mutex<Vec<Diagnostic>>,   // repairs and leniency warnings (std Mutex works without threads and on wasm)
}
pub struct Slot { loc: Location, gen: u16, parsed: OnceLock<Result<Arc<Object>, ErrorCode>> }
pub enum Location { Free { next_gen: u16 }, InFile { offset: u64 }, InObjStm { stream: u32, index: u32 }, Missing }
pub enum Edit { Set(Object), Free }
pub struct Revision {
    pub startxref: u64,
    pub eof_end: u64,            // offset after "%%EOF" + EOL; signatures cover [0, eof_end) of some revision
    pub xref_kind: XrefKind,     // Table | Stream | Hybrid
    pub trailer: Dict,
}
pub trait Decryptor: Send + Sync {
    fn decrypt_string(&self, id: ObjectId, data: &mut Vec<u8>) -> Result<()>;
    fn decrypt_stream(&self, id: ObjectId, dict: &Dict, data: Vec<u8>) -> Result<Vec<u8>>;
    fn encrypt_string(&self, id: ObjectId, data: &[u8]) -> Result<Vec<u8>>;
    fn encrypt_stream(&self, id: ObjectId, dict: &Dict, data: &[u8]) -> Result<Vec<u8>>;
    fn is_exempt(&self, id: ObjectId) -> bool; // /Encrypt dict, xref streams, sig /Contents, unencrypted metadata
}
```

### Rules
- **Read path:** `edits` first, then `Slot.parsed` (parsed once via `OnceLock` from the source), and an error becomes `Object::Null` plus a `Diagnostic`. The API is `resolve(&self, id) -> Result<Arc<Object>>` with `&self`, so concurrent readers are safe.
- **Write path:** `set(&mut self, id, obj)`, `get_mut(&mut self, id) -> &mut Object` (copy-on-write into `edits`), `add(&mut self, obj) -> ObjectId`, `free(&mut self, id)`.
- **Decryption happens at parse time, on a copy.** The source bytes stay ciphertext. This is what makes incremental saves of encrypted files possible.
- **Full save** (`save(&SaveOptions)`):
  1. Walk the graph from the trailer (`/Root`, `/Info`, `/Encrypt`) and garbage-collect unreachable objects.
  2. Optionally renumber densely.
  3. Optionally pack eligible objects into object streams and write an xref stream (header ≥ 1.5).
  4. Re-encrypt if the target is encrypted.
  5. Deterministic mode (`SaveOptions::deterministic`) uses a fixed `/ID` and fixed ordering, for golden tests.
- **Incremental save** (`save_incremental()`, plus `incremental_suffix() -> Vec<u8>` so Tauri can append to a file in place):
  - Output is `source` **byte for byte**, then an EOL if the source does not end with one, then only the `edits` objects (same IDs; freed objects get a gen+1 free entry), then a new xref section and trailer.
  - Trailer: `/Prev` = last `startxref`, `/Size` = max number + 1, `/Root`, `/Info`, `/Encrypt` carried over, `/ID [orig0 new1]`.
  - Use **the same xref kind as the last revision**: a table after a table, a stream after a stream or hybrid (§7.5.6, §7.5.8.4).
  - The source bytes are never re-serialized.
- **Cross-document import:** `ImportSession { src_doc_uid, map: HashMap<ObjectId, ObjectId> }`.
  - Deep copy with renumbering. Reusing one session across calls deduplicates shared fonts and images.
  - Skip page `/Parent`, annotation `/P` (rewired), `/StructParents` (stripped in v1) and `/B` article beads.
  - A `/Dest` that points to a page not being imported becomes `Null`.
  - Imported AcroForm fields are merged into the target's `/AcroForm /Fields`, renamed `name#2` on collision.
  - Optional dedup by content hash (SHA-256 of the canonical serialization) runs in `optimize`.
- **`Limits`** (configurable through `OpenOptions`, with safe defaults):

```rust
pub struct Limits {
    pub max_objects: u32,              // 10_000_000
    pub max_nesting_depth: u16,        // 256 for arrays/dicts (parser AND recursive walkers)
    pub max_decoded_stream: usize,     // 512 MiB per stream (Flate/LZW bombs)
    pub max_total_decoded: u64,        // 4 GiB per document session
    pub max_xref_sections: u32,        // 4096 (/Prev chain; loop detection by offset set)
    pub max_page_tree_depth: u16,      // 64, cycle detection by ObjectId set
    pub max_string_len: usize,         // 128 MiB
    pub max_image_pixels: u64,         // 1 << 28, checked with checked_mul on W*H*BPC*comps
    pub max_ref_chain: u16,            // 32 for Ref→Ref→… (e.g. indirect /Length)
}
```

## A.4 Layering and public API style

| Layer | Crate | Responsibility |
|---|---|---|
| L1 Syntax | `folioxide-syntax` | Lexer (§7.2), object parser (§7.3), xref, trailer, object streams (§7.5), filters (§7.4: Flate with predictors, LZW, ASCIIHex, ASCII85, RunLength; DCT, JPX, JBIG2 and CCITT pass through), writer, store, limits, repair (full scan for `N G obj`) |
| L2 Security | `folioxide-security` | §7.6: Algorithms 1, 1.A, 2–7 (R2–R4), 2.A, 2.B, 8–10 (R6), and R5 read-only. Crypt filters (`/Identity`, `/StdCF`, `/V2`, `/AESV2`, `/AESV3`), `EncryptMetadata`, permissions (`/P`), change and remove password |
| L3 Model | `folioxide-model` | Catalog (§7.7.2), page tree and inheritance (§7.7.3.4), boxes, rotation, resources, name trees and number trees (§7.9.6–7), text strings (PDFDocEncoding, UTF-16BE BOM, UTF-8 BOM in 2.0, §7.9.2.2), dates (§7.9.4), outlines (§12.3.3), page labels (§12.4.2), embedded files (§7.11.4), XMP (§14.3.2), page ops, import, optimize |
| L4 Content | `folioxide-content` | Content-stream tokenizer and builder (§7.8, §8, §9), including inline images; graphics-state tracker; standard-14 metrics; TrueType and OpenType embedding (Type0/CIDFontType2/FontFile2, CFF via FontFile3 `/OpenType`); ToUnicode writer; JPEG and PNG images with SMask (§8.9, §11.6.5.3); text layout; text extraction |
| L5 Features | `interactive`, `sign`, `redact`, `render` | Annotations (§12.5), AcroForm (§12.7), signatures (§12.8), redaction, rendering |

### API conventions
- **Handles:**
  - `Document` owns everything.
  - `PageId(ObjectId)` is a stable handle; 0-based indices are used at the bindings boundary.
  - `Page<'a>` is a borrowed read view; mutation goes through `doc.page_mut(idx)`.
  - `FieldId`, `AnnotId` and `SignatureId` all wrap `ObjectId`.
- **Options:** `#[non_exhaustive] struct XxxOptions` with `Default`, constructors and `with_*` setters, for example `SaveOptions::default().with_object_streams(true)`. Required inputs go in constructor arguments, e.g. `SignRequest::new(signer, signing_time)`.
- **No clock or RNG ambient state in the core.** Signing time is passed in. The RNG is `&mut dyn CryptoRng` (`rand_core` 0.10), with a default `OsRng`-style helper via `getrandom` 0.4.3. `std::time::SystemTime::now()` panics on wasm32-unknown-unknown, so the clock helper lives behind `std-fs`.
- **Errors:** each crate has an `Error` that is `#[non_exhaustive]` and uses `thiserror`. All of them expose `fn code(&self) -> ErrorCode`, where `ErrorCode` is defined once, in `folioxide-syntax`:

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(rename_all = "SCREAMING_SNAKE_CASE"))]
pub enum ErrorCode {
    Syntax, Xref, MissingObject, TypeMismatch, LimitExceeded, Filter, Unsupported,
    PasswordRequired, WrongPassword, PermissionDenied,
    InvalidArgument, PageOutOfRange, NotFound,
    Font, Image, Crypto, KeyLoad, Certificate,
    SignaturePlaceholderTooSmall, SignatureInvalid, DocMdpForbids, TimestampInvalid,
    Io,
}
// facade: pub enum folioxide::Error { Syntax(syntax::Error), Security(..), Model(..), Sign(..), ... } with From impls
```

  In JS, `ErrorCode::WrongPassword` becomes `err.code === "E_WRONG_PASSWORD"`. Error messages never include key material or passwords.
- **Leniency is a policy, not a scattered behavior.** Use `OpenOptions { strictness: Lenient | Strict, password: Option<Vec<u8>>, limits }`. Lenient is the default and records `Diagnostic`s, available through `doc.diagnostics()`.

## A.5 Dependency table

All rows were verified on the crates.io API on 2026-10-10 unless marked. Versions must be compatible with the workspace MSRV, 1.89 (DECISIONS D7.2). Pin everything in `[workspace.dependencies]` and set `default-features = false` where possible.

| Purpose | Crate | Version | License | Notes |
|---|---|---|---|---|
| Ordered dict | `indexmap` | 2.14.2 | Apache-2.0 OR MIT | |
| Errors | `thiserror` | 2.0.21 | MIT OR Apache-2.0 | |
| DTO serialization | `serde` | 1.0.229 | MIT OR Apache-2.0 | optional (`serde` feature) |
| Deflate | `flate2` | 1.1.10 | MIT OR Apache-2.0 | default `rust_backend`, i.e. `miniz_oxide` |
| Deflate (lenient / partial decode) | `miniz_oxide` | 0.9.1 | MIT OR Zlib OR Apache-2.0 | used directly for "decode as much as possible" on truncated streams |
| LZW | `weezl` | 0.2.1 | MIT OR Apache-2.0 | `/EarlyChange` handling is ours |
| CCITT decode | `hayro-ccitt` | 0.4.0 | Apache-2.0 OR MIT | only needed for redaction and rendering |
| MD5 (R2–R4 keys) | `md-5` | 0.11.0 | MIT OR Apache-2.0 | |
| SHA-1 | `sha1` | 0.11.0 | MIT OR Apache-2.0 | legacy verification only |
| SHA-2 | `sha2` | 0.11.0 | MIT OR Apache-2.0 | |
| AES | `aes` | 0.9.3 | MIT OR Apache-2.0 | |
| CBC mode | `cbc` | 0.2.1 | MIT OR Apache-2.0 | |
| RC4 | `rc4` | 0.2.0 | MIT OR Apache-2.0 | |
| RSA | `rsa` | **=0.10.0-rc.19** | MIT OR Apache-2.0 | stable 0.9.10 is on the old `digest` 0.10 / `der` 0.7 stack; **RUSTSEC-2023-0071 is unpatched in both** (see gaps) |
| ECDSA | `ecdsa` | 0.17.0 | Apache-2.0 OR MIT | |
| P-256 / P-384 | `p256`, `p384` | 0.14.0 | Apache-2.0 OR MIT | `p521` not verified; add it later if needed |
| Signature traits | `signature` | 3.0.0 | Apache-2.0 OR MIT | |
| ASN.1 DER | `der` | 0.8.2 | Apache-2.0 OR MIT | features `derive`, `oid`, `alloc`, `pem`. 0.8.0 was yanked |
| X.509 | `x509-cert` | 0.3.0 | Apache-2.0 OR MIT | `builder` only in testkit |
| Key formats | `pkcs8` 0.11.0, `sec1` 0.8.1, `spki` 0.8 (transitive), `pkcs1` 0.8.0-rc.5 (via `rsa`) | — | Apache-2.0 OR MIT | |
| CMS types | `cms` | **=0.3.0-pre.1** | Apache-2.0 OR MIT | types only, no `builder` feature. The exact pin is forced by `pkcs12 0.2.0-pre.0` (see gaps) |
| PKCS#12 | `p12-keystore` | 0.4.0 (2026-10-09) | MIT/Apache-2.0 | `pbes1` feature gives RC2 and 3DES. "MD5-based encryption schemes are not supported." Depends on `pkcs12 0.2.0-pre.0`, `cms ^0.3.0-pre.1` and `x509-parser 0.18.1` (MIT OR Apache-2.0) |
| RNG | `rand_core` 0.10.1, `getrandom` 0.4.3 | — | MIT OR Apache-2.0 | `getrandom` needs `wasm_js` on wasm (later) |
| Secret wiping | `zeroize` | 1.8.x | Apache-2.0 OR MIT | |
| Font parsing | `skrifa` | 0.48.0 | MIT OR Apache-2.0 | preferred over `ttf-parser` 0.25.1, which has not been released since 2024-11 |
| Font subsetting | `subsetter` | 0.2.6 | MIT OR Apache-2.0 | TrueType and CFF outlines. "Variable fonts are not supported yet." Output is usable only for PDF |
| Shaping (optional) | `harfrust` | 0.14.0 | MIT | the `shaping` feature |
| PNG | `png` | 0.18.1 | MIT OR Apache-2.0 | |
| JPEG decode (optional) | `zune-jpeg` | 0.5.15 | MIT OR Apache-2.0 OR Zlib | passthrough needs only our own SOF/APP14 header parser |
| XMP | `quick-xml` | 0.42.0 | MIT | |
| Rendering (later) | `hayro` | 0.8.0 | Apache-2.0 OR MIT | depends on `image` 0.25, `vello_cpu` 0.3, `kurbo`, `pic-scale` 0.7.12 (BSD-3-Clause OR Apache-2.0). MSRV 1.92 |
| mmap (`std-fs`) | `memmap2` | 0.9.11 | MIT OR Apache-2.0 | optional |
| Node-API | `napi` 3.14.2, `napi-derive` 3.6.12, `napi-build` 2.6.0 | — | MIT | |
| napi CLI (npm) | `@napi-rs/cli` | 3.10.8 | MIT | engines: Node `^20.17 \|\| ^22.13 \|\| >=23.5`. Check that local Node 22 is ≥ 22.13 |
| Property tests | `proptest` | 1.11.0 | MIT OR Apache-2.0 | |
| Fuzzing | `libfuzzer-sys` | 0.4.13 | (MIT OR Apache-2.0) AND NCSA | the `fuzz/` crate is outside the workspace and outside `deny` |
| Dev oracles (pip) | `pyhanko` 0.37.0 (MIT), `pypdf` 6.20.0 (BSD-3-Clause), `pikepdf` 10.16.0 (**MPL-2.0**) | — | — | **external, dev-only processes, never linked.** pikepdf's MPL license is fine for that use |

**Excluded or rejected:**
- `cryptographic-message-syntax` 0.28.0: **MPL-2.0**, rejected.
- `x509-tsp` 0.1.0 (2023): built on the old `der` 0.7 / `cms` 0.2 stack, incompatible.
- `x509-ocsp` 0.2.1 (2024-01): old stack too, which affects LTV later.
- `ring`, `aws-lc-rs`, `openssl`: contain C or assembly, so they violate the pure-Rust rule.
- `lopdf`: see A.1.

### Gaps and how to handle them
1. **CMS builder maturity.** `cms` 0.3 is pre-release (pre.2, 2026-01-25), and its `SignerInfoBuilder` needs a local `Signer + Keypair`. That rules out HSM/KMS two-phase signing.
   → Use the `cms` **types** only and write our own SignedData/SignerInfo assembly in `folioxide-sign::cms` (about 400 lines).
   → If the `cms` pin ever conflicts, replace it with our own `der`-derived structs. The subset we need (ContentInfo, SignedData, SignerInfo, Attribute, CertificateChoices::Certificate) is about 250 lines.
2. **The `cms` version pin.** `pkcs12 0.2.0-pre.0` requires `cms = "=0.3.0-pre.1"`, and Cargo allows only one version per semver-compatible range, so the whole graph must use pre.1.
   → M0 spike: confirm `cargo tree -i cms` shows exactly one version.
3. **RFC 3161 types.** No crate is compatible with our stack.
   → Write our own `der` derive structs: `TimeStampReq`, `MessageImprint`, `TimeStampResp`, `PKIStatusInfo`, `TSTInfo`, `Accuracy` (about 200 lines).
4. **RSA side channel.** RUSTSEC-2023-0071 (Marvin): "No patch is yet available… Still affected as of 2026-09-12: rsa 0.9.10 and rsa 0.10.0-rc.18". The advisory considers local use acceptable but not use where attackers can measure timing over a network.
   → Document it. Recommend ECDSA keys or the external KMS/HSM flow for server-side Node deployments.
   → Add `deny.toml` `[advisories] ignore = [{ id = "RUSTSEC-2023-0071", reason = "..." }]`.
   → Re-check every release.
5. **RSA is still a release candidate** (rc.19, 2026-10-06). Pin it exactly and keep RustCrypto types **out of our public API**: public signatures take and return DER `&[u8]`/`Vec<u8>` and our own enums. An RC bump then never breaks our semver.
6. **PKCS#12.** `p12-keystore` covers PBES2 (AES/PBKDF2), plus RC2-40 and 3DES when `pbes1` is on. MD5-based PBES1 is not supported (very rare).
   → Fallback if it stalls: our own decoder on `pkcs12` types + `pkcs5` + `des` + `rc2` (about 600 lines).
7. **OCSP and CRL types for LTV** are not available on the new stack. That is an M11 problem: own `der` structs for OCSPResponse/BasicOCSPResponse, or wait for `x509-ocsp` 0.3.
8. **No JBIG2 or JPX encoders** exist in pure Rust. We pass these through, and when they must be modified (redaction) we decode with hayro and re-encode as Flate.
9. **No pure-Rust PDF/A validator.** Use veraPDF (Java, external process, dual GPL/MPL) as an optional oracle only.

## A.6 Signature design

### A.6.1 Incremental update layout for one signature

```
<original bytes [0, L) untouched>                      # previous revision(s) incl. "%%EOF"
[\n]                                                   # only if byte L-1 is not CR/LF
N 0 obj                                                # signature dictionary — uncompressed, never in an ObjStm
<</Type/Sig/Filter/Adobe.PPKLite/SubFilter/ETSI.CAdES.detached
/ByteRange [0 0000000000 0000000000 0000000000]        # placeholder, see below
/Contents <000000…0000>                                # 2*R hex digits, R = reserved DER bytes
/M (D:20261010120000Z)                                 # PAdES: claimed signing time lives HERE, not in CMS
/Name (..)/Reason (..)/Location (..)/ContactInfo (..)  # optional
[/Reference [<</Type/SigRef/TransformMethod/DocMDP     # only for certification signatures
             /TransformParams<</Type/TransformParams/P 2/V/1.2>>>>]]
>>
endobj
F 0 obj  <</Type/Annot/Subtype/Widget/FT/Sig/T(Signature1)/V N 0 R/F 132/Rect[0 0 0 0]/P <page> 0 R
          [/AP<</N <appearance> 0 R>>] >> endobj       # merged field+widget; F 132 = Print|Locked; visible → real Rect + AP
<page> 0 obj  (page dict rewritten with /Annots [... F 0 R]) endobj   # or the /Annots array object if indirect
<acroform or catalog> (AcroForm /Fields [... F 0 R] /SigFlags 3)       # 3 = SignaturesExist|AppendOnly (§12.7.3? Table "SigFlags")
[<catalog> (/Perms <</DocMDP N 0 R>>) ]                # certification only
xref … trailer <</Size …/Prev <prev startxref>/Root …/ID[<orig0><new1>] [/Encrypt …]>>   (or xref stream)
startxref
<offset>
%%EOF\n
```

Any edits the user has pending (`doc.edits`) are written in **the same revision**, before the signature, which is how Acrobat behaves.

### A.6.2 `/ByteRange` and `/Contents` mechanics (ISO 32000-2 §12.8.1)
1. Serialize the whole update into a `Vec<u8>`.
   - `/ByteRange` is written as `[0 ` followed by three 10-digit placeholders and `]`. Ten digits cover files up to 9.3 GB.
   - Record the absolute offsets of the ByteRange placeholder and of the `/Contents` `<`.
2. `a` = offset of `<`; `b` = offset just after `>`; `c` = `total_len − b`.
   - Overwrite the placeholder with `[0 a b c` padded with **spaces** before `]`. Never use leading zeros, and never change the length.
   - The ByteRange itself sits inside the signed range, so patch it **before** hashing.
3. `document_digest = H(buf[0..a] || buf[b..b+c])`. That excludes exactly the hex string including its delimiters.
4. Build the CMS (A.6.3) and hex-encode it into `/Contents`, uppercase or lowercase. Pad the rest with `0`. Verifiers read the DER length and ignore the padding.
5. **Reservation size (R bytes):**
   ```
   R = Σ len(DER cert_i)                                   (signer + chain, root optional)
     + sig_len (RSA: modulus bytes; ECDSA: 2·⌈n/8⌉ + 9)
     + 600                                                 (SignedData/SignerInfo/attrs incl. signing-cert-v2 ≈ 150)
     + tsa_reserve (B-T only; default 8192, configurable)
     → × 1.15, round up to 1024
   ```
   - The default with no TSA is at least 8 KiB. `SignRequest::contents_reserve` overrides it.
   - **On overflow** the result is `ErrorCode::SignaturePlaceholderTooSmall { needed }`.
   - The local-key `sign()` retries **once** automatically with `needed + 2048`. The digest changes, so this is a full redo.
   - The external flow cannot redo the signature without the caller, so it returns the error, and the caller should over-reserve. The Node wrapper retries by calling the user's signer again.

### A.6.3 CMS content (RFC 5652, PAdES baseline B-B: ETSI EN 319 142-1 §6.3)
- `ContentInfo { contentType: id-signedData, content: SignedData }`
- `SignedData`:
  - `version` 1
  - `digestAlgorithms { sha256 }` (sha384 for P-384 by default)
  - `encapContentInfo { eContentType id-data (1.2.840.113549.1.7.1), eContent ABSENT }` (detached)
  - `certificates [0]`: signer cert first, then intermediates
  - no CRLs
  - exactly one `SignerInfo`
- `SignerInfo`:
  - `version` 1, `sid = issuerAndSerialNumber`
  - `digestAlgorithm`
  - **`signedAttrs`** (DER `SET OF`, sorted; `der::SetOfVec` handles the sorting):
    - `content-type` (1.2.840.113549.1.9.3) = id-data. **Required.**
    - `message-digest` (1.2.840.113549.1.9.4) = `document_digest`. **Required.**
    - `signing-certificate-v2` (1.2.840.113549.1.9.16.2.47, RFC 5035) = `SEQUENCE { SEQUENCE { ESSCertIDv2 { hashAlgorithm (OMITTED when sha256 because DER omits DEFAULT values), certHash = H(signer cert DER), issuerSerial { GeneralNames{directoryName issuer}, serial } } } }`. **Required by PAdES.**
    - **No `signing-time`.** PAdES baseline says the CMS signing-time attribute shall not be present; the claimed time goes in `/M`. Verify this against EN 319 142-1 §6.3 Table 1 when the docs are written.
    - Optional later: `signature-policy-identifier`, `commitment-type-indication`, `content-time-stamp`.
  - `signatureAlgorithm`: `sha256WithRSAEncryption` (1.2.840.113549.1.1.11), `rsassa-pss` (optional), `ecdsa-with-SHA256`/`SHA384` (1.2.840.10045.4.3.2 / .3)
  - **`signature` = Sign(DER(signedAttrs encoded with the universal SET tag 0x31))**, not with the `[0] IMPLICIT` tag `0xA0` used inside SignerInfo (RFC 5652 §5.4). This is the classic bug.
  - ECDSA values must be the DER `ECDSA-Sig-Value`. Many KMSes and WebCrypto return raw `r‖s` (IEEE P1363), so we accept both and convert by length.
  - `unsignedAttrs [1]`: `id-aa-signatureTimeStampToken` (1.2.840.113549.1.9.16.2.14) = the TimeStampToken `ContentInfo` DER (B-T).

### A.6.4 Pluggable timestamp (B-T); no network I/O in the core
- `TimeStampReq { version 1, messageImprint { hashAlg, H(SignerInfo.signature OCTET STRING contents) }, nonce: random u64, certReq: TRUE }`
- Core trait (synchronous): `trait Timestamper { fn timestamp(&self, request_der: &[u8]) -> Result<Vec<u8> /* TimeStampResp DER */>; }`. Async hosts (Node) use the two-phase API instead (A.7).
- When validating the response, check:
  - `status ∈ {granted(0), grantedWithMods(1)}`
  - the token is SignedData with eContentType `id-ct-TSTInfo` (1.2.840.113549.1.9.16.1.4)
  - `TSTInfo.messageImprint` matches and `nonce` matches
  - the TSA's CMS signature verifies
  - the TSA certificate has EKU `id-kp-timeStamping`, marked critical
- Embed the token, not the whole response.

### A.6.5 External / deferred signing (two-phase)

```rust
pub struct PrepareRequest { pub field: FieldSpec, pub signer_chain_der: Vec<Vec<u8>>, pub sig_alg: SignatureAlgorithm,
                            pub digest: DigestAlgorithm, pub signing_time: PdfDate, pub contents_reserve: Option<usize>,
                            pub certification: Option<DocMdpPermissions>, pub appearance: Option<SignatureAppearance>, .. }
pub fn prepare(doc: &Document, req: &PrepareRequest) -> Result<PreparedSignature>;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]   // can be persisted between Tauri commands / processes
pub struct PreparedSignature {
    pub pdf: Vec<u8>,                 // full bytes with patched ByteRange and zeroed /Contents
    pub contents_range: (u64, u64),   // [a, b)
    pub signed_attrs_der: Vec<u8>,    // the exact bytes the caller signs (with 0x31 tag)
    pub digest_alg: DigestAlgorithm, pub sig_alg: SignatureAlgorithm, pub chain_der: Vec<Vec<u8>>,
}
impl PreparedSignature {
    pub fn to_be_signed(&self) -> &[u8];                  // for "sign message" KMS APIs
    pub fn to_be_signed_digest(&self) -> Vec<u8>;         // H(to_be_signed) for "sign digest" HSM/KMS APIs
    pub fn timestamp_request(&self, signature: &[u8], nonce: u64) -> Result<Vec<u8>>; // for B-T
    pub fn finish(self, signature: &[u8], timestamp_response: Option<&[u8]>) -> Result<Vec<u8>>;
    pub fn embed_cms(self, cms_der: &[u8]) -> Result<Vec<u8>>; // caller produced the whole CMS (remote signing services)
}
pub trait Signer: Send + Sync {                 // local keys implement it; Tauri can add OS keychain / PKCS#11 later
    fn chain_der(&self) -> &[Vec<u8>];
    fn algorithm(&self) -> SignatureAlgorithm;
    fn sign(&self, to_be_signed: &[u8]) -> Result<Vec<u8>>;
}
pub fn sign(doc: &Document, req: &SignRequest<'_>) -> Result<Vec<u8>>;   // = prepare + signer.sign + timestamper + finish
pub fn load_pkcs12(der: &[u8], password: &str) -> Result<LocalSigner>;
pub fn load_pem(key_pem: &str, certs_pem: &str, key_password: Option<&str>) -> Result<LocalSigner>; // PKCS#8 (enc/plain), PKCS#1, SEC1
```

### A.6.6 DocMDP and certification (ISO 32000-2 §12.8.2.2)
- A certification signature **must be the first signature** in the document. Refuse with `DocMdpForbids` if one already exists.
- Write `/Reference [<</Type/SigRef/TransformMethod/DocMDP/TransformParams<</Type/TransformParams/P n/V/1.2>>>>]` in the signature dictionary and `/Perms <</DocMDP sigdict>>` in the catalog.
  - `P = 1`: no changes allowed.
  - `P = 2`: form filling, signing and page templates (the default).
  - `P = 3`: P = 2 plus annotation create, delete and modify.
- When signing a document that is already certified: refuse if P = 1. If P = 2 or 3, only an approval signature is allowed.
- FieldMDP (`/Lock`, `/TransformMethod /FieldMDP`) is out of scope until M11.

### A.6.7 Verification algorithm (`verify(bytes, &VerifyOptions) -> Vec<SignatureReport>`)
1. Open leniently.
   - Enumerate signature fields from `/AcroForm /Fields`, recursing through `/Kids` with `/FT /Sig` and `/V`.
   - Also scan for orphaned `/Type /Sig` dictionaries and report them as `orphan`.
   - Also report `/DocTimeStamp` dictionaries.
2. **ByteRange sanity:**
   - exactly 4 non-negative integers, `[0, a, b, c]`, with `0 < a < b ≤ b + c ≤ file_len`
   - `bytes[a] == b'<'`, `bytes[b-1] == b'>'`, everything in between is hex or whitespace
   - the gap corresponds to *this* dictionary's `/Contents`, checked by locating the token via the parsed object's offset
   - `b + c` equals the `eof_end` of some revision (a trailing EOL is tolerated)
   - Anything else gives `ByteRangeInvalid`. This stops "signature wrapping" tricks.
3. Parse the CMS. Choose the routine by `/SubFilter`:
   - `ETSI.CAdES.detached`, `adbe.pkcs7.detached`: detached CMS over the byte ranges
   - `adbe.pkcs7.sha1`: eContent = SHA-1 of the data (verify only)
   - `ETSI.RFC3161`: document timestamp
   - `adbe.x509.rsa_sha1`: verify-only, optional
4. Recompute the digest over the ranges and compare it with `message-digest`. Then verify `signature` over DER(signedAttrs re-tagged 0x31) with the signer certificate's SPKI: RSA PKCS#1 v1.5, RSA-PSS, ECDSA P-256 or P-384.
5. Check that `signing-certificate-v2` (or v1) matches the signer certificate hash. PAdES profile flags: SubFilter, `signing-time` absent, signing-cert-v2 present.
6. **Timestamp:** verify the token as in A.6.4 against the signature value. Report `genTime` and TSA certificate info.
7. **Certificates:**
   - DTO `{subject, issuer, serialHex, notBefore, notAfter, sha256, keyAlgorithm, keyUsage, extKeyUsage}` for the signer, chain and TSA
   - optional trust check against caller-supplied anchors: path building, chain signatures, validity at the time (TSA `genTime` if present, otherwise `/M`, flagged "claimed")
   - **no revocation and no network**
8. **Modified after signing:**
   - `coverage = WholeFile` if `b + c == file_len`, otherwise `Revision(k)`.
   - For each later revision, compute changed object IDs from the xref sections after the signed revision, then classify with a whitelist modelled on pyHanko's DiffPolicy:
     - new signature fields and their widgets, `/AcroForm` `/Fields` and `/SigFlags`, page `/Annots` additions of signature widgets → `Signing`
     - `/DSS` and its streams, `/DocTimeStamp` → `LtvOnly`
     - field `/V`, `/AS` and `/AP` changes → `FormFilling`
     - annotation CRUD → `Annotations`
     - anything else → `Other`
   - `docmdpOk = level ≤ allowed(P)`. The report includes the list of changed objects.

```rust
pub struct SignatureReport { pub field_name: String, pub sub_filter: String, pub intact: bool, pub signature_valid: bool,
  pub byte_range_ok: bool, pub coverage: Coverage, pub modification: ModificationLevel, pub docmdp: Option<u8>, pub docmdp_ok: Option<bool>,
  pub signer: CertificateInfo, pub chain: Vec<CertificateInfo>, pub trusted: Option<bool>, pub claimed_time: Option<PdfDate>,
  pub timestamp: Option<TimestampInfo>, pub pades_level: Option<PadesLevel>, pub warnings: Vec<String> }
```

### A.6.8 Encrypted documents
- The signature `/Contents` string is **never encrypted** (§7.6.2). Every other new string and stream in the update is encrypted with the existing file key and the object's own ID.
- `/ID[0]` must not change: the R2–R4 key derivation uses it.
- The xref stream is never encrypted.

## A.7 Node binding design (napi-rs v3)

- **Crate `folioxide-node`** (`crate-type = ["cdylib"]`): `napi = { version = "3.14", default-features = false, features = ["napi8", "dyn-symbols"] }` (`dyn-symbols` resolves Node-API symbols at load time; see DECISIONS D7.3) and `napi-derive = "3.6"`. Its `build.rs` calls `napi_build::setup()`. It is the **only** crate that depends on napi.
- **npm package `folioxide`:**
  - `index.js` / `index.d.ts`: hand-written ESM+CJS facade with JSDoc
  - `binding.js` / `binding.d.ts`: generated by `napi build --platform --release --js binding.js --dts binding.d.ts`
  - Platform packages through `optionalDependencies`. Set `"napi": { "binaryName": "folioxide", "packageName": "@folioxide/binding", "targets": [...] }`. Per the napi config source, platform suffixes are appended to `packageName`, so the packages are named `@folioxide/binding-linux-x64-gnu` and so on. A bare `@folioxide/linux-x64-gnu` does not seem to be directly supported. **Verified in M0** with `napi create-npm-dirs` (`@napi-rs/cli` 3.10.8), whose output is committed as `bindings/node/npm/<dir>/package.json`. Each package ships one binary named `folioxide.<dir>.node`:
    - `x86_64-unknown-linux-gnu`: `@folioxide/binding-linux-x64-gnu` (dir `linux-x64-gnu`)
    - `aarch64-unknown-linux-gnu`: `@folioxide/binding-linux-arm64-gnu` (dir `linux-arm64-gnu`)
    - `x86_64-unknown-linux-musl`: `@folioxide/binding-linux-x64-musl` (dir `linux-x64-musl`)
    - `aarch64-unknown-linux-musl`: `@folioxide/binding-linux-arm64-musl` (dir `linux-arm64-musl`)
    - `x86_64-apple-darwin`: `@folioxide/binding-darwin-x64` (dir `darwin-x64`)
    - `aarch64-apple-darwin`: `@folioxide/binding-darwin-arm64` (dir `darwin-arm64`)
    - `x86_64-pc-windows-msvc`: `@folioxide/binding-win32-x64-msvc` (dir `win32-x64-msvc`)
    - `aarch64-pc-windows-msvc`: `@folioxide/binding-win32-arm64-msvc` (dir `win32-arm64-msvc`)

    Both `folioxide` (crates.io and npm) were unregistered on 2026-10-10; reserve them and the `@folioxide` npm scope now.
  - Targets: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`.

### Class shape (TypeScript surface)

```ts
export class PdfDocument {
  static open(data: Uint8Array, opts?: OpenOptions): PdfDocument;           // sync; copies once into Rust
  static openAsync(data: Uint8Array, opts?: OpenOptions): Promise<PdfDocument>;
  static create(opts?: { version?: string }): PdfDocument;
  get pageCount(): number;
  get isEncrypted(): boolean;
  diagnostics(): Diagnostic[];
  save(opts?: SaveOptions): Buffer;               saveAsync(opts?: SaveOptions): Promise<Buffer>;
  saveIncremental(opts?: { suffixOnly?: boolean }): Buffer;  saveIncrementalAsync(...): Promise<Buffer>;
  // pages (M5) — 0-based indices
  getPage(i: number): PageInfo; insertBlankPage(at: number, size?: Size): void; deletePages(idx: number[]): void;
  movePage(from: number, to: number): void; rotatePage(i: number, deg: 0|90|180|270): void;
  importPages(src: PdfDocument, indices: number[], at?: number): void;
  // signatures (M3/M4)
  prepareSignature(opts: PrepareSignatureOptions): PreparedSignature;
  verifySignatures(opts?: VerifyOptions): Promise<SignatureReport[]>;
  // info/metadata, outlines, forms, annots … added per milestone
}
export class PreparedSignature {
  readonly toBeSigned: Buffer; readonly toBeSignedDigest: Buffer; readonly digestAlgorithm: 'sha256'|'sha384'|'sha512';
  timestampRequest(signature: Uint8Array): Buffer;
  finish(signature: Uint8Array, timestampResponse?: Uint8Array): Buffer;
  embedCms(cms: Uint8Array): Buffer;
  serialize(): Buffer; static deserialize(b: Uint8Array): PreparedSignature;
}
export class LocalSigner { static fromPkcs12(p12: Uint8Array, password: string): LocalSigner;
  static fromPem(keyPem: string, certsPem: string, keyPassword?: string): LocalSigner;
  get certificateChain(): Buffer[]; sign(tbs: Uint8Array): Buffer; signAsync(tbs: Uint8Array): Promise<Buffer>; }
// Hand-written facade (index.js), composes async callbacks in JS — no ThreadsafeFunction needed:
export function signPdf(doc: PdfDocument, opts: {
  signer: LocalSigner | { certificateChain: Uint8Array[]; algorithm: SigAlg; sign(tbs: Buffer, digest: Buffer): Promise<Uint8Array> };
  timestamp?: (request: Buffer) => Promise<Uint8Array>;   // caller POSTs to TSA (application/timestamp-query)
  field?: FieldSpec; reason?: string; location?: string; signingTime?: Date; certify?: 1|2|3; appearance?: AppearanceSpec;
}): Promise<Buffer>;
```

### Design rules
- **Buffers:**
  - Input is taken as `&[u8]` / `Uint8Array` and copied once into an `Arc<[u8]>`. This is unavoidable because the document outlives the call and async tasks need `Send` data.
  - Output is `Buffer::from(Vec<u8>)`, which hands ownership over without a copy.
  - Note: Electron's V8 sandbox disallows external buffers. Verify napi-rs's fallback if Electron is ever a target.
- **Threading:**
  - `#[napi] struct PdfDocument { inner: Arc<Mutex<folioxide::Document>> }`.
  - Heavy operations (open, save, sign, verify, optimize, flatten, render) get an `…Async` variant that returns `AsyncTask<T>`. `Task::compute` runs on the libuv pool, clones the `Arc` and locks.
  - Sync methods use `try_lock()` and throw `E_BUSY` rather than blocking the event loop while an async task holds the document.
  - Core `Document: Send + Sync`, asserted at compile time in a test.
- **Errors:** `napi::Error::new(format!("E_{code}"), msg)` sets the JS `err.code`. The facade wraps errors into a `FolioxideError extends Error` with `.code` and optional `.details`, for example `{needed}` on placeholder overflow. All codes are exported as a TS string-literal union.
- **DTOs:**
  - Mirror the core DTOs as `#[napi(object)]` structs with `From` conversions, so the generated TS types are precise.
  - Field names are camelCase, identical to the core's `serde(rename_all = "camelCase")`. Node and Tauri therefore see the same JSON shape.
  - Enums use `#[napi(string_enum)]`.
- **Type tests:** `tsc --noEmit -p test/tsconfig.json` on `test/types.test-d.ts`.
- **Runtime tests:** Node 22's built-in runner, `node --test test/`, with `.mjs` files so no TypeScript toolchain is needed at runtime.

## A.8 Tauri readiness (what the core does now)
1. No napi, Node or Tauri types in any `crates/*` crate. CI checks `cargo tree -p folioxide -e normal | grep -E 'napi|tauri'` is empty.
2. `Document`, `PreparedSignature` and all DTOs are `Send + Sync + 'static`. No `Rc`/`RefCell` in the core; laziness uses `OnceLock`.
3. No global mutable state. Standard-14 metrics are `static` tables only.
4. Every DTO derives `Serialize`/`Deserialize` behind the `serde` feature, uses camelCase, and is versioned through `#[non_exhaustive]`. `ErrorCode` serializes the same way, and `ErrorDto { code, message, details }` is the Tauri command error.
5. Bytes in, bytes out. Path helpers live only behind `std-fs`. `incremental_suffix()` lets Tauri append to the open file without rewriting it.
6. No clock, RNG or network inside the core (A.4). A sync `Signer` trait means Tauri can wrap the OS keychain or PKCS#11 later.
7. Long operations take an optional `&dyn Fn(Progress) -> ControlFlow<()>` for progress and cancellation (Tauri can emit events). It is ignored by default.
8. Later, Tauri TS types come from `specta` or `ts-rs` on the same DTOs. Nothing is needed now beyond keeping DTOs plain (no lifetimes, no RustCrypto types).

## A.9 Testing strategy

### Layers
1. **Unit tests** in each module: lexer tokens (§7.2), every filter, every encryption algorithm against spec test vectors and pikepdf-generated files, ASN.1 encoders with golden DER.
2. **Integration tests** (`crates/*/tests/*.rs`): round trips such as open → modify → save → reopen → deep-equal.
3. **Property tests** (`proptest`):
   - arbitrary `Object` trees serialize and parse back to equality
   - random byte mutations of valid fixtures never panic (`no_panic_on_mutated_input`, a stable-toolchain stand-in for fuzzing)
   - incremental save always keeps the prefix
4. **Fuzzing** (`fuzz/`, cargo-fuzz on nightly in CI): targets `fuzz_lexer`, `fuzz_parse_document` (open plus resolve all objects plus page count), `fuzz_filters`, `fuzz_content_stream`, `fuzz_cms_parse`, `fuzz_xmp`. Seed corpus is `fixtures/` plus testkit output. Corpora and crash artifacts are not committed. **Verify that nightly is installable in CI**, since only stable 1.97 is installed locally.
5. **Golden tests:** deterministic save mode, so tests can compare bytes for writer output (plus `insta`, if adopted; its version is not verified).
6. **Node tests:** `node --test` covering the API surface, error codes, async variants, and the TSA/KMS callbacks with a JS mock.

### Fixtures policy
- **Generate everything we can.**
  - `folioxide-testkit` builds PDFs at byte level, including deliberately broken ones: wrong xref offsets, `/Prev` loops, junk before the header, wrong `/Length`, truncated Flate, hybrid files.
  - `tools/fixtures/*.py` uses pikepdf/pypdf to make encrypted files (R2, R3, R4 with RC4 or AES, R6), object-stream and linearized files, and forms.
  - All of this is reproducible with `cargo xtask fixtures`.
- **Commit small generated files** (each < 200 KB) so `cargo test` needs no Python. `fixtures/README.md` lists each file's generator and license ("generated by this project, MIT OR Apache-2.0").
- **External corpora** (pdf.js, PDFBox, hayro-tests) contain files under mixed or unclear licenses. They are **not committed**. An opt-in smoke test runs over `FOLIOXIDE_CORPUS=/path` with "no panic plus open rate" metrics.
- **Test PKI:**
  - `tools/gen-pki.sh` (openssl) makes: a root CA, an intermediate, RSA-2048, RSA-3072, P-256 and P-384 signers (keyUsage digitalSignature+nonRepudiation), a TSA certificate (EKU timeStamping, critical), an expired certificate, and a wrong-key-usage certificate.
  - PKCS#12 in three flavors:
    - modern: `openssl pkcs12 -export` with OpenSSL 3 defaults (AES-256-CBC/PBKDF2, SHA-256 MAC)
    - 3DES: `-keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1`
    - RC2-40: `-legacy`. The legacy provider is present at `/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so`.
  - Committed under `fixtures/pki/`. Keys are test-only and marked as such.

### Oracle mechanism
- Tests under the feature `folioxide-testkit/emit` write `target/oracle/<suite>/<name>.pdf` plus `<name>.expect.json`.
- `cargo xtask oracle [--suite X]` runs those tests, then `.venv/bin/python -I tools/oracles/run_suite.py target/oracle/<suite>`. That prints a PASS/FAIL table and exits non-zero on failure.
- `expect.json` keys: `pages`, `version`, `encrypted{R,V,method,user,owner}`, `info{}`, `xmpContains[]`, `signatures[{field,intact,valid,coverage,modification,docmdp,pades,timestamp}]`, `fields{}`, `annots[]`, `textContains[]`, `textAbsent[]`, `fontsEmbedded[]`, `images[]`, `prefixOf`, `revisions`.

### Oracle matrix (all available locally)
Found in `/usr/bin`: `pdfinfo`, `pdfsig`, `pdftotext`, `pdffonts`, `pdfimages`, `pdftoppm`, `pdfdetach`, `pdfattach`, `pdfseparate`, `pdfunite`, `openssl` (3.x with the legacy provider), and `python3.13`. Java is available too.

| Feature | Oracles and checks |
|---|---|
| Structural validity | `pdfinfo` exit 0, Pages, PDF version; pikepdf `Pdf.open` + `pdf.check()` (qpdf engine as an external process) returns no errors; pypdf `PdfReader(strict=True)` reads every page |
| Boxes and rotation | `pdfinfo -box -f 1 -l N` (MediaBox, CropBox, Rot) |
| Incremental integrity | `cmp -n $(stat -c%s orig) orig out`; pikepdf/pypdf open; count of `startxref` occurrences = revisions |
| Object/xref streams, compression | pikepdf (objects inside ObjStm, xref stream present), file-size deltas |
| Encryption | pikepdf `Pdf.open(p, password=…)`: `pdf.encryption.R/.bits/.stream_method`; `pdfinfo -upw/-opw` (Encrypted line with permission flags); pypdf `decrypt()` returns OWNER/USER |
| Signatures | pyHanko `validate_pdf_signature` (`intact`, `valid`, `trusted` with fixture roots, `coverage`, `modification_level`, `docmdp_ok`, timestamp validity) in `validate_sig.py`. `pdfsig -nocert` must show "Signature is Valid" per signature. `extract_cms.py` + `openssl cms -verify -binary -inform DER -in sig.der -content signed.bin -CAfile fixtures/pki/root.pem -purpose any`. `pades_profile.py` (asn1crypto): SubFilter, content-type/message-digest/signing-cert-v2 present, signing-time absent. `openssl ts -verify -data sigvalue.bin -in token.der -token_in -CAfile tsa-root.pem` |
| Metadata | `pdfinfo` (Title, Author…), `pdfinfo -meta` (XMP packet), pikepdf `open_metadata()` |
| Outlines, labels, attachments | pypdf `.outline`, `.page_labels`; `pdfdetach -list`; pikepdf `.attachments` |
| Fonts | `pdffonts`: emb=yes, sub=yes, uni=yes, type CID TrueType; `pdftotext` round-trips the inserted text |
| Images | `pdfimages -list`: type image + smask, dims, bpc, color; `pdftoppm` pixel probes |
| Annotations | pypdf `/Annots` subtypes and `/AP` present; `pdftoppm -r 72` pixel probe inside `/Rect` (non-white) |
| Forms | pypdf `get_fields()` values; `pdftoppm` probe shows values rendered while NeedAppearances is false |
| Flatten | pypdf: no `/Annots` widgets and no `/AcroForm` fields; `pdftotext` still contains the values |
| Redaction | `pdftotext` lacks the redacted strings; pikepdf scan of **all** decoded streams and strings for the bytes (Latin-1, UTF-16BE, hex); `pdftoppm` probe shows a black box; exactly 1 `%%EOF` (no history) |
| Rendering (later) | hayro output vs `pdftoppm` at the same DPI; per-page PSNR threshold |
| Optional, Java | Apache PDFBox app (Apache-2.0) as a 3rd parser; EU DSS (LGPL) or veraPDF (GPL/MPL) as external validators for B-LT/LTA and PDF/A. External processes only |

## A.10 Spec traps and risk register

| # | Area | Trap | Ref | Mitigation / test |
|---|---|---|---|---|
| 1 | Lexer | `stream` keyword must be followed by CRLF or LF, never a lone CR; `/Length` may be indirect, wrong or missing | §7.3.8.1 | Resolve the indirect Length with ref-chain limit; validate that `endstream` follows; otherwise scan for `endstream`. Tests `stream_length_wrong_recovers`, `length_indirect_cycle` |
| 2 | Lexer | Numbers like `.5`, `5.`, `-.5`, `--5` (accept as -5), `+17`; no exponents; names with `#xx`; literal strings with balanced parens, `\ddd` octal, line continuations; hex strings with whitespace and odd digit count (pad 0) | §7.3.3–7.3.5 | Table-driven lexer tests from the spec examples |
| 3 | Xref | Entries are 20 bytes with EOL variants (`␠\r`, `␠\n`, `\r\n`); subsection starting at 1 instead of 0; offsets off by N; `startxref` wrong; `/Prev` loops; junk before `%PDF-` | §7.5.4, Annex H | Offset sanity check (does `N G obj` exist there?) → local search ±64 bytes → full reconstruction scan. Offset base = header position. Loop detection. Tests per case |
| 4 | Xref streams | `/W` with zero-width fields (type defaults to 1); `/Index` pairs; hybrid `/XRefStm` precedence; xref streams are never encrypted | §7.5.8 | Tests `xref_stream_w0_default`, `hybrid_xrefstm` |
| 5 | Object streams | `/N`, `/First`, offsets must be validated; `/Extends` chains (loops); objects inside are gen 0; streams cannot be inside; **strings inside an encrypted ObjStm are not decrypted again** | §7.5.7, §7.6.2 | Decrypt the container only. Test `encrypted_objstm_strings` |
| 6 | Filters | PNG predictors 10–15 (per-row tag), TIFF predictor 2, `Colors`/`BitsPerComponent`/`Columns` overflow, LZW `EarlyChange`, ASCII85 `z` and optional `<~`, truncated Flate; decompression bombs | §7.4 | `checked_mul`, `max_decoded_stream`, partial-decode diagnostic |
| 7 | Encryption | R6 Algorithm 2.B: K = SHA-256(pw‖salt‖[U]); loop K1 = (pw‖K‖U)×64; E = AES-128-CBC(key K[0..16], iv K[16..32], K1, no padding); mod-3 of the first 16 bytes of E as a big-endian integer (sum of bytes mod 3 is equivalent) chooses SHA-256/384/512; stop when round ≥ 64 and last byte of E ≤ round − 32. Passwords: SASLprep then UTF-8, truncated to 127 bytes. Validate `/Perms` ('adb' at bytes 9–11) | ISO 32000-2 §7.6.4.3.3–4 | Vectors from pikepdf-generated files; tests `r6_user`, `r6_owner`, `r6_unicode_password`, `r5_read_only` |
| 8 | Encryption | R2–R4: 32-byte padding string, `/P` as a **signed** 32-bit int; R3+ 50 MD5 iterations; object key = MD5(key‖num(3 bytes LE)‖gen(2 bytes LE)[‖"sAlT" for AES]) truncated to min(n+5, 16); AES strings and streams are 16-byte IV ‖ CBC/PKCS#7 | §7.6.2 Alg. 1, 1.A; §7.6.4.3 | Tests for each `/V`/`/R` combination |
| 9 | Encryption | Exempt from encryption: `/Encrypt` dict, xref streams, **signature `/Contents`**, metadata when `EncryptMetadata false`, streams with an `/Identity` crypt filter. The `/ID` array is never encrypted | §7.6.2, §7.6.6 | `Decryptor::is_exempt`. Test `sign_encrypted_doc_pyhanko_valid` |
| 10 | Page tree | Inheritable `/Resources`, `/MediaBox`, `/CropBox`, `/Rotate`; `/Count` wrong; cycles; `/Rotate` not a multiple of 90; missing MediaBox (default to Letter + diagnostic) | §7.7.3.3–4 | Materialize inherited attributes on import, split and extract. Tests `inherited_resources_materialized_on_extract`, `page_tree_cycle` |
| 11 | Page ops | Dangling `/Dest` and outline entries after deletion; `/Annots /P`; AcroForm field name collisions on merge; StructTreeRoot (tagged PDF) not mergeable in v1 | §12.3.2, §14.7 | Prune dests to Null. Rename `name#2`. Strip structure on import and document it |
| 12 | Incremental | Original lacks a final EOL; previous revision used an xref stream; hybrid; `/ID[0]` must stay; linearized files (appending is fine but linearization becomes invalid, which is OK) | §7.5.6 | Same xref kind as before. Tests `incremental_prefix_preserved_all_fixtures` |
| 13 | Signatures | Placeholder overflow (TSA tokens and long chains); ByteRange width changes the file; signing over `[0x31]`-retagged attrs; ESSCertIDv2 DEFAULT omission; ECDSA raw vs DER; sig dict in an ObjStm or a compressed stream; Contents encrypted; certification not first; signing a `P=1` doc | §12.8.1, RFC 5652 §5.4, RFC 5035 | A.6. Tests `placeholder_overflow_retries`, `ecdsa_p1363_accepted`, `certify_twice_rejected` |
| 14 | Verification | ByteRange gap not matching the actual `/Contents` (wrapping attack); multiple sig dicts sharing ranges; trailing garbage after `%%EOF` (incremental "shadow" attacks) | — | A.6.7 steps 2 and 8 |
| 15 | Fonts / encoding | Simple fonts: `/Encoding` base + `/Differences`, symbolic flag, TrueType cmap (3,0) vs (3,1); Type0 with non-Identity CMaps; missing ToUnicode; subset fonts lacking glyphs for new text; Type3 fonts | §9.6–9.10 | Editing existing text only when every new char maps to an existing glyph in the same font; otherwise overlay with a new embedded font. Report `Unsupported` clearly |
| 16 | Fonts / embedding | `/W` widths in glyph space ÷ unitsPerEm × 1000; CIDToGIDMap Identity requires CID == new GID after subsetting; subset tag `ABCDEF+` (6 uppercase letters); ToUnicode for ligatures (one GID → many chars); CFF in FontFile3 `/OpenType` needs PDF 1.6+ | §9.7, §9.9 | Tests checked with `pdffonts` and a `pdftotext` round trip |
| 17 | Text strings | PDFDocEncoding vs UTF-16BE BOM vs UTF-8 BOM (2.0 only); dates `D:YYYYMMDDHHmmSSOHH'mm` (trailing `'` optional) | §7.9.2, §7.9.4 | Codec tests; write UTF-16BE when any char is not in PDFDocEncoding |
| 18 | Annotations | Appearance placement: BBox transformed by Matrix, then fit to Rect (§12.5.5 algorithm); QuadPoints order in practice is TL, TR, BL, BR (Acrobat), not what the spec text implies; `/F` Print flag (4), otherwise nothing prints; Highlight needs `/BM /Multiply`; `/Popup` pairs; `/NM` uniqueness | §12.5.5–6 | Render probes with `pdftoppm` |
| 19 | Forms | Inheritable `/FT /Ff /V /DV /DA /Q` through `/Parent`; merged field/widget dicts; checkbox `/V` must equal an `/AS` name in `/AP /N` (e.g. `/Yes`, not always); radio `/Opt` and `NoToggleToOff`; combo `/Opt` `[export display]` pairs; `/DA` auto-size `0 Tf`; comb fields need `/MaxLen`; `/NeedAppearances true` (deprecated in 2.0); **XFA**: when `/AcroForm /XFA` exists, fill the AcroForm, then remove `/XFA` (configurable), and refuse dynamic XFA | §12.7 | Tests per field type plus pypdf values and render probe |
| 20 | Flatten | Hidden/NoView annotations must be skipped; a signed doc's flatten invalidates signatures (warn); shared appearance XObjects | §12.5.3 | Full rewrite only |
| 21 | Redaction | Text inside **Form XObjects** shared across pages (copy-on-write per use); text in Type3 glyph procs; `TJ` glyph removal must keep following glyph positions (insert compensating kerning numbers); text render mode 3 (invisible OCR layer) must be redacted too; images partially covered → decode, black out pixels, re-encode (JPX/JBIG2 → Flate); also scrub annotations, form values, `/ActualText` and `/Alt` in the structure tree, outlines/bookmark titles (optional), metadata (optional), thumbnails `/Thumb`; **always a full rewrite with GC (no incremental history)** | §8–9, §14.7 | Oracle "redaction" row. Test `redaction_removes_text_in_shared_xobject` |
| 22 | Content streams | Inline images (`BI … ID <binary> EI`); `EI` can appear inside the data, so use a whitespace and next-operator heuristic plus `/L` (2.0 `/Length`); unbalanced `q/Q` in existing content, so wrap the original content in `q … Q` before appending | §8.9.7, §8.4.2 | Content tokenizer tests |
| 23 | Images | JPEG CMYK from Adobe (APP14 transform=0 or 2 → `/Decode [1 0 1 0 1 0 1 0]`); progressive JPEG fine for passthrough; PNG 16-bit, palette+tRNS → SMask, interlaced, so decode before re-encoding; gamma ignored | §8.9.5, §11.6.5.3 | `pdfimages -list` checks |
| 24 | Metadata | Info vs XMP sync (2.0 deprecates Info except dates); XMP packet wrapper; Metadata stream unfiltered (PDF/A friendliness); `EncryptMetadata` | §14.3 | `pdfinfo -meta` |
| 25 | Writer | Reals without exponents; name escaping (`#` + delimiters + bytes outside 0x21–0x7E); binary marker comment line; header ≥ 1.5 when using xref or object streams; incremental cannot rewrite the header, so bump the catalog `/Version` | §7.2.3, §7.5.2, §7.7.2 | Golden writer tests |
| 26 | Supply chain | RustCrypto pre-releases (`rsa` rc, `cms` pre); RUSTSEC-2023-0071 | — | Exact pins, no RustCrypto types in the public API, `cargo deny` |
| 27 | Rendering | hayro is "experimental", performance "not a focus", no knockout groups or non-embedded CID fonts | hayro README | Keep it behind the `render` feature; compare against `pdftoppm` |


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
├─ Cargo.toml                  # [workspace] members, [workspace.package] (edition 2024, license "MIT"),
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
pub struct Dict(Box<IndexMap<Name, Object>>);                // preserves order (deterministic output, readable diffs);
                                                             // boxed so that an Object is 32 bytes (arrays of numbers)
pub struct Stream { pub dict: Dict, pub data: StreamData }
pub enum StreamData {
    Source(Range<u64>),            // still-encoded bytes inside the source buffer (zero-copy; resolved through the doc)
    Encoded(Vec<u8>),              // encoded per dict /Filter, owned
    Decoded(Vec<u8>),              // plain; the writer encodes per SaveOptions (Flate by default), fixes /Length, /Filter, /DecodeParms
}
```

### The document store (lazy, `Send + Sync`, no mandatory threads)

The M1 shape (`folioxide_syntax::store`, re-exported at the crate root), with the M2 edit layer. Fields marked M5 arrive with decryption.

```rust
pub type SharedBytes = Arc<dyn AsRef<[u8]> + Send + Sync>; // Vec<u8>, Box<[u8]>, &'static [u8], or Mmap (std-fs); shared_bytes(b)

pub struct Store {
    source: SharedBytes,
    options: OpenOptions,                  // #[non_exhaustive] { strictness, limits }; password arrives in M5
    header_offset: u64,                    // junk before "%PDF-": every offset in the file is relative to the header (Annex H)
    version: (u8, u8),                     // from the header; (1, 4) when missing or malformed
    revisions: Vec<Revision>,              // oldest → newest
    trailer: Dict,                         // the newest trailer, repaired (/Root, /Encrypt from older trailers or a scan)
    slots: Vec<Slot>,                      // the merged xref's IN-USE objects, SORTED by object number (binary search, O(1)
                                           // fast path when numbering is dense); never sized from /Size; free entries take no
                                           // slot (a free or unlisted number reads as null); at most object_cap (see Rules)
    others: Vec<Slot>,                     // further generations of numbers in `slots`, sorted by (number, generation): a
                                           // reconstruction keeps every generation it finds (`5 0 obj` and `5 1 obj` are
                                           // different objects, §7.3.10, as in qpdf); a reference resolves to the one with its
                                           // own generation. Empty for a file read through its xref data
    max_object_number: u32,                // largest number any section lists, free entries included
    offset_base: OffsetBase,               // HeaderRelative | Absolute: which position the file's offsets count from (Annex H)
    structure_repaired: AtomicBool,        // set when opening repaired the xref structure (see structure_repaired())
    by_position: Vec<u32>,                 // indices (`slots`, then `others`) of the in-file slots sorted by position: an
                                           // object's parse region ends at the next object or xref section (`region_end`)
    by_container: Vec<u32>,                // indices of the compressed slots sorted by (object stream, index): the objects
                                           // one container settles when it is decoded again (see Rules)
    section_starts: Vec<usize>,            // absolute positions of the xref sections read (tables, streams, /XRefStm)
    objstm_cache: Mutex<ObjStmCache>,      // decoded containers: number → Arc<OnceLock<Result<Arc<ObjStm>, Error>>>,
                                           // LRU within Limits::max_objstm_cache bytes (see Rules); the lock is held
                                           // only to fetch or account a cell, never while decoding. Nested loads put
                                           // their private (quiet) decodes here too; a blocking load replaces such an
                                           // entry with its own decode, which reports diagnostics (never two copies)
    peeked_objects: Mutex<HashMap<ObjectId, Option<Arc<Object>>>>,     // peek memo for nested loads (see Rules)
    settled: Mutex<HashMap<u32, Result<Arc<Object>, Box<Error>>>>,  // compressed objects a settling pass loaded with their
                                           // container, taken by their slot's first load (see Rules: settling never waits)
    objstm_parsed: AtomicU64,              // memory of the objects parsed from object streams (ParseBudget estimate),
                                           // at most LimitKind::ObjStmParsed
    scan: OnceLock<ScanIndex>,             // one linear scan of the file, built at most once and only when needed
                                           // (reconstruction, a wrong offset or /Length); also the parser's KeywordIndex
    definitions: OnceLock<Definitions>,    // the object definitions among the scan's headers, by (number, generation):
                                           // line-start headers outside every object that parses (see Rules), derived once
    diagnostics: DiagnosticLog,            // bounded by Limits::max_diagnostics (std Mutex: works without threads and on wasm)
    total_decoded: AtomicU64,              // enforces Limits::max_total_decoded: each SOURCE stream counts once (see Rules)
    charged: Mutex<HashMap<(u64, u64), u64>>, // bytes charged per source stream (by data range): re-decodes are free,
                                           // object-stream containers included (see Rules)
    reconstruct_budget: AtomicU64,         // decoded bytes a reconstruction may still spend on object-stream headers
    parsed_objects: AtomicUsize,           // #[doc(hidden)] parsed_object_count(), for the laziness test
    // M2, the edit layer (store/edit.rs; see Rules, "Write path"):
    edits: BTreeMap<ObjectId, Edit>,       // replaced, added and freed objects: the dirty set an incremental save writes
    next_num: u32,                         // the number add() gives next: never a number reused (see next_object_number)
    referenced_floor: OnceLock<u32>,       // 1 + the largest number a SOURCE object or trailer refers to (below max_objects),
                                           // found by one walk on the first add()/next_object_number(): a dangling
                                           // reference keeps meaning null
    trailer_edited: bool,                  // set_trailer_entry / remove_trailer_entry changed `trailer`
    has_source: bool,                      // false for Store::new_empty
    // M5: decryptor: Option<Arc<dyn Decryptor>> (implemented by folioxide-security)
}
struct Slot {                              // 48 bytes; one per in-use object
    num: u32,
    gen: u16,                              // 0 for compressed objects
    recovered: AtomicBool,                 // its location did not come from the xref as written (recovered_objects())
    loc: Location,
    parsed: OnceLock<Result<Arc<Object>, Box<Error>>>, // the full Error (code, offset, message), boxed to keep the slot
                                           // small. Lenient: an unreadable object is stored as Ok(null) and reported once;
                                           // strict: the error is stored. LimitExceeded is an Err in both modes.
}
enum Location {                            // in-use only: a free number has no slot, like an unlisted one (both null)
    InFile { pos: u64 },                   // ABSOLUTE position in `source` (header offset already added)
    InObjStm { stream: u32, index: u32 },  // entry `index` of object stream `stream`; generation 0
}
struct ObjStm {                            // a decoded, validated object stream (§7.5.7); data + 20 B per member
    num: u32,
    data: Vec<u8>,                         // the decoded container (≤ max_objstm_decoded, so 32-bit offsets)
    members: Vec<Entry>,                   // one per header pair read, in header order (the xref index addresses it);
                                           // at most object_cap pairs are read (the rest ignored: `capped`)
    by_number: Vec<(u32, u32)>,            // (object number, index), sorted: lookups when the index is wrong
    extends: Option<ObjectId>,             // /Extends, followed with loop detection and Limits::max_ref_chain
    capped: bool,
}
struct Entry { num: u32, start: u32, end: u32 }      // 12 bytes; num 0 = invalid pair. end = the next member's offset
                                                     // (start, for a second number at an offset already taken):
                                                     // each member is parsed in its region

#[non_exhaustive] pub struct Revision { // one LOGICAL section, in /Prev order (oldest first), not a byte range in file
                                 // order: a linearized file's newest section is the first-page xref near the start
    pub startxref: u64,          // offset of this revision's xref section RELATIVE TO THE HEADER (what a startxref or a
                                 // later /Prev holds when offset_base is HeaderRelative; add header_offset for Absolute);
                                 // the repaired value when the file's own offset was wrong
    pub eof_end: u64,            // ABSOLUTE position after "%%EOF" + EOL; signatures cover [0, eof_end) of some revision.
                                 // Found from the `startxref` whose value points at this section (the first one after
                                 // it), so a linearized first-page section ends with the file, not at its dummy
                                 // "startxref 0 %%EOF". Without one: the first %%EOF within 2 KB of the section; without
                                 // %%EOF: the end of the startxref line, else of the section (of the file for the newest).
                                 // NOT monotonic across revisions; an incremental save appends after source.len(),
                                 // never after an eof_end
    pub section_end: u64,        // ABSOLUTE end of the section itself (trailer dict, or xref stream object)
    pub xref_stm: Option<u64>,   // hybrid only: offset (header-relative, like startxref) of the /XRefStm stream read
    pub xref_kind: XrefKind,     // #[non_exhaustive] Table | Stream | Hybrid | Reconstructed (no trustworthy revision
                                 // structure: write with a full save, not an incremental one)
    pub trailer: Dict,           // as written; for an xref stream, the stream dictionary
}
#[non_exhaustive] pub enum OffsetBase { HeaderRelative, Absolute } // which position offsets count from: how the newest
                                 // section was found
                                 // (at offset + header_offset, or at the offset itself), else where the catalog's entry is
#[non_exhaustive] pub enum XrefEntry {          // one entry as a section writes it (Store::revision_entries)
    Free { gen: u16 },           // also an entry for the null object: an unknown xref-stream type (§7.5.8.3) or an
                                 // in-use entry with an out-of-range generation/offset; it HIDES older entries, as any
                                 // entry does (skipping it would let an older object show through: a reader differential)
    InFile { pos: u64, gen: u16 }, // ABSOLUTE position
    InObjStm { stream: u32, index: u32 },
}

#[derive(Clone, Debug, PartialEq)]
pub enum Resolved<'a> {          // what deref() returns; Deref<Target = Object>, into_arc(), into_owned()
    Direct(&'a Object),          // the input was not a reference: no clone, no Arc
    Indirect(Arc<Object>),       // the shared object at the end of the reference chain (null if missing or free)
}

pub trait KeywordIndex {         // parser hook (ParseCtx::with_keyword_index): stream recovery asks it for the next
    fn next_endstream(&self, from: usize) -> Option<usize>; // `endstream` / `endobj` instead of searching the buffer
    fn next_endobj(&self, from: usize) -> Option<usize>;    // again for every broken stream (O(log n) per object). The
}                                // store's ScanIndex implements it; positions are verified, so a wrong index can only
                                 // make recovery slower, never produce a range outside the buffer

pub trait Decryptor: Send + Sync {                           // M5
    fn decrypt_string(&self, id: ObjectId, data: &mut Vec<u8>) -> Result<()>;
    fn decrypt_stream(&self, id: ObjectId, dict: &Dict, data: Vec<u8>) -> Result<Vec<u8>>;
    fn encrypt_string(&self, id: ObjectId, data: &[u8]) -> Result<Vec<u8>>;
    fn encrypt_stream(&self, id: ObjectId, dict: &Dict, data: &[u8]) -> Result<Vec<u8>>;
    fn is_exempt(&self, id: ObjectId) -> bool; // /Encrypt dict, xref streams, sig /Contents, unencrypted metadata
}
pub(crate) enum Edit { Set(Arc<Object>), Free }              // M2, crate-private: the public surface is the
                                                             // Store methods; Set is shared so resolve() hands out
                                                             // snapshots, and get_mut clones it only when one is held
```

Public read API (M1): `Store::open(SharedBytes, &OpenOptions)`, `open_bytes(Vec<u8>, &OpenOptions)`, `resolve(&self, ObjectId) -> Result<Arc<Object>>`, `deref(&self, &'a Object) -> Result<Resolved<'a>>`, `stream_data(&self, &Stream) -> Result<StreamBytes { data, remaining, truncated }>`, `raw_stream_data(&self, &Stream) -> Result<Cow<[u8]>>`, `trailer()`, `root_id()`, `revisions()`, `revision_entries(k) -> Result<Vec<(u32, XrefEntry)>>` (re-reads one revision's section lazily: its entries as written, then its /XRefStm's, free ones included), `header_offset()`, `offset_base()`, `version()`, `object_ids()`, `max_object_number()`, `structure_repaired()`, `recovered_objects() -> Vec<ObjectId>`, `diagnostics()`, `dropped_diagnostics()`, `total_decoded()`, `source()`, `shared_source()`, `options()`, `limits()`. `Store: Send + Sync` is asserted in a test.

Public edit and write API (M2): `Store::new_empty(version)` (no source, no revisions), `has_source()`, `set(id, obj) -> Result<()>`, `get_mut(id) -> Result<&mut Object>` (copy-on-write), `add(obj) -> Result<ObjectId>` (`LimitExceeded` at `Limits::max_objects`), `free(id) -> Result<()>`, `set_trailer_entry(key, value) -> Result<()>` and `remove_trailer_entry(key) -> Result<Option<Object>>`, `is_modified()`, `edited_ids()` (sorted), `contains(id)` (in use, edits included), `generation_of(num)` (the current xref generation; a freed number's next generation), `next_object_number()`, `object_stream_members(id)` (what a source object stream still holds), `memory_estimate()` (the heap bytes the store holds, `O(1)`, for hosts that report native memory to a GC; §A.7), `check_incremental() -> Result<()>`, and the writers `save(&SaveOptions)`, `save_incremental(&IncrementalOptions)`, `incremental_suffix(..)` and `incremental_update(..) -> IncrementalUpdate` (also free functions in `folioxide_syntax::writer`). `object_ids()` is edit-aware: freed objects leave it, added ones join it; `max_object_number()` stays the source's.

### Rules
- **Opening reads structure only:** the header, the xref chain (`startxref` → `/Prev` → …, with `/XRefStm` for hybrids; loops and `Limits::max_xref_sections` cut the chain), the trailer, and the catalog (parsed once to check it is a dictionary; it stays cached). Encryption is checked before the catalog is parsed. Nothing else is parsed until it is resolved, and the file is scanned only when the xref data is unusable (full reconstruction) or turns out wrong. **Recovery matches qpdf 12** (pikepdf 10.16 is the oracle) wherever the structure is damaged: qpdf, pdf.js and poppler reconstruct a file whose last `startxref` does not lead to a section at its offset, and the last definition of each object by position wins. The store keeps more of the file's own structure, but only when it shows what that reconstruction shows (`Store::differs_from_reconstruction`): (a) when the last `startxref` leads to no section, the earlier `startxref` values are tried newest first (at most 8, lenient only), so a valid multi-revision file with a bogus tail keeps its revisions; (b) when the newest section is found near its offset or at its offset counted from byte 0 (concatenated files, where the second file's `startxref` leads near the first file's table), its chain is checked the same way. Such a chain is used only when nothing but junk follows its revisions (no object header or `trailer` at the start of a line: an appended update whose own `startxref` is the damaged one, or a second file, is `UnreferencedUpdate` and makes the file reconstructed) and before that tail every object definition is where the chain resolves it (`Store::shadowed_definition`: an orphan `N G obj` after the definition the table lists for `N G`, an uncompressed `N 0 obj` after the object stream an entry names, a definition after the section that frees the number, or a number no section lists, all make the file reconstructed; `structure_repaired()`). Such a chain also gets the other generations the reconstruction would show (`5 1 obj` besides the table's `5 0 obj`, added to `others` and `recovered_objects()`), so `5 1 R` resolves as in qpdf while `5 0 R` keeps the revision's object.
- **What counts as an object definition** (`repair::definitions`, used by reconstruction, the shadow check, the scan fallback of `locate` and the update detection): an `N G obj` header **at the start of a line** (after optional white-space), the way qpdf and poppler rebuild a file, so header-like text in the middle of a line, and so inside a `%` comment, never counts; and **not inside an object that parses**. One **coverage pass** goes over the line-start candidates in file order and parses each one it reaches with the real parser (lenient, quiet; an indirect `/Length` is read from the last candidate for that object, parsed only up to the next header after it). A parse that **succeeds** (the parser knows where the object ends: a wrong `/Length` delimited by `endstream` or a missing `endobj` are fine) covers `[pos, end)`, and the candidates inside it (a header inside the object's string, dictionary or stream data) are text, skipped. A parse that **fails**, or only guesses where the object ends (a container closed by an object keyword, a stream without `endstream`, `stream` after a value that is not a dictionary), covers what it read, `[pos, where the lexer stopped)`, and the candidates inside it are **definitions taken unparsed**, as qpdf takes every line-start header: nothing tells whether the damaged object encloses them (when a header `N G obj` closed the containers, the stretch ends before that header, whose object is parsed in turn). The pass then resumes at the first candidate after the stretch. **Linear by construction, no budget:** the stretches never overlap, and a parse reads past its stretch at most one lookahead token (and the white-space and comments before it), or the header `N G obj` that closed its containers (`parser::parse_indirect_extent` reports how far a parse read, lookahead included; only an integer value has a lookahead, the one for `N G R`, which lexes a token only when its first byte can start a number, so it never reads a string past the object's end, and after such a number one more only when it starts with `R`). A token is read ahead only by the parse whose value it follows: the next parse starts at the first candidate after the stretch, not before that token, and reads again at most the number or header it starts with. So together the parses read the file about once (`Definitions::bytes_read`; tests `the_coverage_parses_read_the_file_about_once`, `resolving_damaged_objects_is_linear`, `an_extent_reads_past_the_value_only_its_lookahead`). A literal string that never closes stops after 4 KiB (`lexer::ParenIndex`: one pass sums the unescaped parentheses per 4 KiB block, with 64-way summaries above, which answers whether a string closes in about 4 KiB of work), so it takes the headers in those 4 KiB, not every header to the end of the file; past them, objects that parse still cover their text. (Reading such a string to the end of the file is linear too; stopping early matched qpdf as well or better on every probe: the objects after it read whole, and a header in a top-level string, which qpdf's token cut skips, stays text.) A hexadecimal string ends, and its parse fails, at its first byte that is neither a hexadecimal digit nor white-space, where qpdf's token ends (`ParseCtx::with_hex_ending_at_invalid_byte`, coverage parses only; value reads stay lenient, trap #14). Definitions are keyed by number **and generation**: another generation of `N` is another object (§7.3.10) and shadows nothing; the newest definition of each number is the entry the merged view shows, the others are kept (`others`). A definition inside stream data (by the scan's lexical state) still loses to a clean one. Every definition of the pass counts alike, for reconstruction and for the chain decision (`shadowed_definition`, `newer_data_after`). Text inside an object that parses is never a definition, so it never changes what a valid chain resolves to; where qpdf differs, see trap #14 (deliberate differences).
- **An update that no `startxref` leads to** (object headers, `xref` or `trailer`, each at the start of a line, after the end of the newest revision: a save cut short before its `startxref`, content appended outside any revision, a second file appended to the first) is a `DiagnosticKind::UnreferencedUpdate` repair (`structure_repaired()`; an error in strict mode, whose message only says what was found), found by a linear look at the bytes after the last `eof_end`, without the full scan. What the store shows then matches qpdf 12, which looks for the last `startxref` only in the last 1054 bytes: when it is there, qpdf reads the chain and ignores the update (as poppler and pypdf do whatever the distance); when it is not, qpdf scans the file and still reads the chain when the last `startxref` comes after the last object header ("startxref was more than 1024 bytes before end of file"), so the store reconstructs only when the last `startxref` is more than 1054 bytes from the end **and** an object header (line start) follows it. (qpdf also requires the chain's `/Root` to have a `/Pages` dictionary before it keeps the chain; the store does not check that.) Junk after `%%EOF` (comments, binary data, another `%%EOF`, header-like text in a comment or in the middle of a line) is not an update and is not reported.
- **Opening is linear in the file size, whatever the xref data claims** (`xref.rs` `XrefBudget`): all sections and every attempt together may parse at most `max(1 MiB, 4 × len)` source bytes (overlapping sections, unterminated trailers) and read at most `max(2^20, 4 × len)` entries (a `/Prev` chain of highly compressed xref streams); xref-stream rows are merged as they are decoded (no per-section copy), with an output cap from the rows left. At most `object_cap = min(max_objects, max(4096, len))` in-use objects are kept (the lowest numbers): a file cannot claim more objects than it has bytes. Exceeding a budget cuts the chain (lenient: a diagnostic, then the scan fills in; strict: `LimitExceeded`). Derived budgets are reported under their own `LimitKind` (`XrefEntries`, `XrefBytes`, `ObjectCap`, `ReconstructDecoded`, `ObjStmParsed`; `MaxObjects` when that field is the smaller bound), whose message says to raise `Limits::budget_scale`, which multiplies all of them (`Limits::budget(kind, len)` computes each). A reconstruction reads object streams for their member lists only, uncached, within `max(16 MiB, 16 × len)` decoded bytes, and parses trailer candidates only up to the next object header or `trailer` keyword.
- **Object streams are bounded three ways** (their decoded data can be ~1000× the file): one container decodes to at most `Limits::max_objstm_decoded` (64 MiB; real ones are a few hundred KB) and lists at most `object_cap` members (20 B of tables each); the decoded containers kept take at most `Limits::max_objstm_cache` (64 MiB, LRU; the container in use is always kept), and a container decoded again after it was dropped *settles* its objects: the same pass loads every object the xref puts in it that is not loaded yet (`Store::settle_container`; a blocking load puts them in the `settled` memo, which each slot's first load takes, and a nested load fills the peek memo with the members found in the container itself), so however the cache thrashes, the loads of a container's own objects decode it at most twice for blocking loads and twice for nested ones (plus once when a blocking load replaces a nested load's quiet decode). Each container's source data therefore counts once against `max_total_decoded`, like any stream, and a long-lived store with scattered access never runs out of budget; only a dropped container decoded again to follow another one's `/Extends` (the xref names the wrong object stream: a damaged file) is charged again; and the objects parsed from object streams take at most `LimitKind::ObjStmParsed = max(64 MiB, 128 × len)` bytes over the life of the store (an estimate the parser charges as it builds: 32 B per value, string and name bytes, dictionary overheads), so `[0 0 0 …]` decoded from kilobytes cannot become gigabytes of objects. Real files measure 25–55 bytes per file byte even when they hold nothing but object streams.
- **Xref precedence:** the newest section that lists an object number wins. Within a hybrid section the **table wins over its `/XRefStm` stream, free entries included**; the stream supplies only numbers the table does not list, before the `/Prev` section is consulted (§7.5.8.4: "if an entry is not found in any given standard cross-reference section, the search shall proceed to a cross-reference stream specified by the XRefStm entry before looking in the previous cross-reference section"). A hidden object's free entry in an *older* section is therefore overridden by the newer section's stream. Same as qpdf, poppler and pdf.js; see `merge_section` in `xref.rs`.
- **Offsets:** every position stored in the store, in `StreamData::Source` ranges, and in diagnostics and errors is absolute in `source` (except objects inside object streams, which have no file position); only `Revision::startxref` and `Revision::xref_stm` are header-relative. An in-file offset is validated (`N G obj` must be there), then tried as absolute (writers that counted the junk before the header), then searched within ±64 bytes, then (lenient) looked up in the scan. `offset_base()` records which convention the file uses; M2 writes `/Prev` and new offsets in that base.
- **Repair state is exposed, not hidden:** `structure_repaired()` is true when opening repaired the xref structure (a section found away from its offset, a damaged section, a `/Prev`/`/XRefStm` that leads nowhere or loops, a cut chain, an earlier `startxref` used, objects merged from the scan, a rebuilt trailer or replaced `/Root`, an update that no `startxref` leads to). `recovered_objects()` lists objects whose location did not come from the xref as written (scan, ±64-byte search, absolute-offset fallback, another object-stream member), and objects whose own bytes needed a repair that decides what they hold (a header generation that differs from the entry's, a `/Length` that does not end at `endstream`, a missing `endstream` or `endobj`, a `stream` keyword without CRLF/LF); objects join it as they are resolved. M3 uses both (A.6.7). An xref-stream entry of an unknown type is conforming (§7.5.8.3): it reads as null and hides older entries, with an `XrefUnknownEntryType` note in both modes, and is not a repair.
- **Read path:** `edits` first (M2), then `Slot.parsed` (parsed once via `OnceLock` from the source). Lenient: an unreadable object becomes `Object::Null` plus a `Diagnostic`; strict: the error. `resolve(&self, id)` takes `&self`, so concurrent readers are safe; a free or missing object, or a generation that does not match the entry (plus a diagnostic), is `null`; so is an object freed by `free`. Reference chains are followed only by `deref`, bounded by `Limits::max_ref_chain` with loop detection. Every public read sees the edits (`resolve`, `deref`, and through them `stream_data`'s `/Filter` and `/DecodeParms` references); **the store's own loads read the source only** (`resolve_source`: indirect `/Length` values, object stream containers, the settling and peek paths), so an edit never changes how the source is parsed. An `Arc` handed out before an edit stays a snapshot.
- **Settling never waits on a slot.** A settling pass runs inside the `OnceLock` initialisation of the slot whose load decoded the container again, so it must not wait on another slot's `OnceLock`: two threads settling the same container would each wait for a slot the other is filling (QA round 3 deadlock). It parses the other members itself into the `settled` memo and skips filled slots; a thread that loads one of them meanwhile parses it too (a second parse, never a wait). The waits-for order is acyclic: a compressed object's load waits only on container cells; a container's decode waits only on the slot of its (uncompressed) stream object; an uncompressed object's load waits on nothing but the scan and definitions `OnceLock`s, whose initialisation waits on nothing. Test `settling_never_waits_on_another_slot` (8 threads, 6 × 60 members, a cache that keeps no container, 40 rounds).
- **Nested loads never wait.** Loading one object can need another (an indirect `/Length`, a container, a `/Filter` or `/DecodeParms` reference). Those nested loads never block on a slot's or container's `OnceLock` (another thread may be filling it, or this very call path): they use a filled cell, else the **peek memo** (objects), else load a private copy. A call-path chain detects cycles (`5 0 obj << /Length 5 0 R >>`) and bounds nesting by `max_ref_chain` (at most 16 levels, to protect the stack). A private result that did not depend on the call path (no load below it was refused for a cycle or depth) goes into the peek memo, or for a container into the object-stream cache as a quiet entry, so a `/Length` or container that many streams share is loaded once, not once per stream.
- **Linear-time resolution on hostile files:** each uncompressed object is parsed only within its **region**, which ends at the next object (the next in-file entry by position whose position really holds its own `N G obj` header, also tried after the skew that relocated this object) or xref section; when the next entries cannot be checked, the scan's next header decides. Overlapping objects (headers inside another object's string, comment or stream data) therefore cost each byte a bounded number of times, for resolving and for decoding. (Region bounds use every header-like text, line start or not; only definitions are filtered as described above. A definition taken unparsed inside what a damaged object's parse read bounds regions like any other, so an object that holds such a header reads only up to it.) Test `resolving_damaged_objects_is_linear` counts the region bytes of resolving every object of damaged runs (no `endobj`, one at the end, one per object) at two sizes. Object-stream members are bounded by the next member's offset the same way, and members of different numbers never share one region (all but the first at a shared offset read as unreadable).
- **Uncompressed-container rule:** an object stream must itself be an uncompressed (in-file) object (it is a stream, §7.5.7). A container named by a compressed entry is rejected, which also guarantees that decoding one container never waits on another.
- **Decryption happens at parse time, on a copy** (M5). The source bytes stay ciphertext. This is what makes incremental saves of encrypted files possible. Until M5, a trailer with `/Encrypt` makes `open` fail with `PasswordRequired` (`/Standard`) or `Unsupported` (any other handler).
- **Write path (M2, `store/edit.rs`):** edits take `&mut self` (no locks; the read guarantees above are unchanged) and live beside the lazy store, which never changes what it read.
  - `set(id, obj)` replaces an object in use (a source object with its generation, or one `add` returned); object 0, a free, freed or never-used number, or another generation is `InvalidArgument`. `get_mut(id)` clones the resolved object into `edits` on first use (copy-on-write). `free(id)` makes it read as `null`; the incremental writer writes a free entry with generation + 1 (65535 stays 65535, §7.5.4). An object stream of the source cannot be set, changed or freed while it holds objects in use that no edit replaced or freed (`object_stream_members(id)`; `InvalidArgument`): the store keeps reading them from the source's container, so the edit would change nothing in memory while an incremental update would leave them unreadable (a freed container that held the catalog). Cross-reference streams stay editable: readers find them by position, not by number.
  - `add(obj) -> Result<ObjectId>` numbers new objects from `next_object_number()`, generation 0, and fails with `LimitExceeded` at `Limits::max_objects`. **Numbers are never reused**: `next_object_number()` is above every number any section lists (in use or free: a reused freed number reads as clobbering to a revision comparer such as pyHanko), above every number an object or a trailer **of the source refers to** (below `max_objects`; a reference to a number no section lists means `null`, §7.3.10, and a new object under it would silently become, say, a page tree kid; qpdf's `fixDanglingReferences` guards the same way; one walk over the source on the first call, remembered), and above every number added before. Everything from it up is unused, so an incremental update (and M3's overlay objects) can number new objects from it.
  - Trailer edits: `set_trailer_entry` accepts `/Root` and `/Info` (indirect references) and `/ID` (two strings); `remove_trailer_entry` accepts `/Info` and `/ID`. The keys the writers compute (`/Size`, `/Prev`, `/XRefStm`, `/W`, `/Index`, `/Filter`, `/DecodeParms`, `/Length`, `/Type`, `/DL`, `/F`, `/FFilter`, `/FDecodeParms`) are refused, and `/Encrypt` waits for M5. `trailer()` shows the edited trailer; `Revision::trailer` keeps each section's as written.
  - Edited streams carry `StreamData::Decoded` (the writer encodes it and fixes `/Length`, `/Filter`, `/DecodeParms`, `/DL`) or `StreamData::Encoded` (written as is with the dictionary's `/Filter`); a stream nested in an array or dictionary is refused by the writers (§7.3.8).
- **Full save** (`writer::save(&Store, &SaveOptions)`, `writer/full.rs`):
  1. Walk the graph breadth first from the trailer's entries (`/Root`, `/Info`, any other carried key) and garbage-collect unreachable objects (`gc`, default true; without it every object in use is written except the source's xref streams, object streams and linearization dictionary). A stream's `/Length` is not followed; a reference to an object not in use is written as `null`.
  2. Renumber densely from 1 in walk order, generation 0 (`renumber`, default true; without it numbers and generations are kept, freed numbers get free entries with their next generation).
  3. Header `%PDF-x.y` + a binary comment line: the highest of the source's header version, `min_version`, and 1.5 when an xref stream is written, always a PDF version (1.0 to 1.7, 2.0): `min_version` outside that set is `InvalidArgument` (`SaveOptions::validate`), and a source header that names none (`%PDF-1.9`, `%PDF-9.9`) is written as the next one up, or 2.0. Junk before the source's header is dropped.
  4. Source streams are copied as raw encoded bytes (zero decode) unless `StreamCompression::Recompress`, which re-encodes only streams this layer decodes completely (no image codec, not truncated, no `/F`); `Decoded` data is Flate-encoded (`CompressNew`, default) or written plain (`Keep`).
  5. Object streams (`object_streams`, default false) hold at most 100 objects each; streams, objects of generation ≠ 0 and signature dictionaries are never packed: `/Type /Sig` or `/DocTimeStamp`, or, since `/Type` is optional in a signature dictionary (§12.8.1 Table 255), a dictionary with `/ByteRange`, or with `/Contents` and `/Filter` or `/SubFilter`. They need an xref stream (`XrefStyle::Auto`: a stream with object streams or when the source's newest section is a stream or hybrid, else a table).
  6. Tables have one subsection from 0 with 20-byte entries and the free list linked from object 0 (pypdf strict mode refuses tables that are not zero-indexed); an xref stream lists itself.
  7. `/ID` from `SaveOptions::id`, else the trailer's first element with the second recomputed, else generated: the MD5 of the bytes written before the xref section (no RNG in the core; unique as far as the content is). Output is deterministic (`deterministic` states the requirement for golden tests).
  8. Re-encrypt if the target is encrypted (M5; until then a trailer with `/Encrypt` is `Unsupported`).
- **Incremental save** (`save_incremental()`, `incremental_suffix() -> Vec<u8>` so Tauri can append to a file in place, and `incremental_update() -> IncrementalUpdate`, `writer/incremental.rs`):
  - **Refusals** (`Store::check_incremental()` reports them without building anything): no source (`InvalidArgument`); the newest revision is `XrefKind::Reconstructed`, `structure_repaired()` is true, or an in-use object is not at the position its entry gives (`Unsupported`, "full save required": the store finds it nearby, but qpdf and poppler reconstruct the whole file and need not see the update as the store does; the writer oracle suite caught poppler losing a new `/Info` that way). A full save is the way out, and its output takes updates. With nothing edited, the source comes back unchanged (not an error).
  - Output is `source` **byte for byte** (bytes before `%PDF-` included), then an EOL if the source does not end with CR or LF, then only the `edits` objects in id order (same IDs; never in an object stream, never compressing the source: signatures need byte-exact control; `Decoded` data is Flate-encoded), then a new xref section and trailer.
  - Use **the same xref kind as the last revision**: a table after a table (first subsection `0 1` or `0 N`, object 0 the head of the free list), a stream after a stream or hybrid (it takes `next_object_number()`, or one more than the highest number the section lists if that is higher, as M3's overlay objects may be, and lists itself) (§7.5.6, §7.5.8.4). Freed objects get a gen+1 free entry, linked from object 0; a number added then freed gets none.
  - Trailer: `/Prev` = the last revision's `startxref` and offsets in `Store::offset_base()` (header-relative; see trap #12), `/Size` = the highest number + 1, or the last revision's own `/Size` when that is larger (a direct non-negative integer within `Limits::max_objects`; an update never shrinks the `/Size`, which PDFium trusts and the M4 verifier checks; manager ruling R-30 (a)), every other entry of the (edited) trailer but the computed keys, `/ID [orig0 new1]` (`IncrementalOptions::id1`, else the MD5 of the update).
  - **Positions for M3:** `IncrementalUpdate { bytes, start, objects, xref_pos, xref_kind }`. `start` = `source.len()`; the new file is `start + bytes.len()` bytes and, reopened, has one more revision whose `eof_end` is that length (the previous `eof_end` equals `source.len()` only when nothing follows its `%%EOF`: the update is appended after the whole source, never after an `eof_end`); `objects` gives the ABSOLUTE span of every object written, from `N G obj` to after `endobj\n`; `xref_pos` the absolute position of the section.
  - The source bytes are never re-serialized. The store is not changed: reopen the output to keep editing (tests `incremental_updates_chain_on_every_fixture`).
- **Cross-document import:** `ImportSession { src_doc_uid, map: HashMap<ObjectId, ObjectId> }`.
  - Deep copy with renumbering. Reusing one session across calls deduplicates shared fonts and images.
  - Skip page `/Parent`, annotation `/P` (rewired), `/StructParents` (stripped in v1) and `/B` article beads.
  - A `/Dest` that points to a page not being imported becomes `Null`.
  - Imported AcroForm fields are merged into the target's `/AcroForm /Fields`, renamed `name#2` on collision.
  - Optional dedup by content hash (SHA-256 of the canonical serialization) runs in `optimize`.
- **`Limits`** (`#[non_exhaustive]`, configurable through `OpenOptions`, with safe defaults and `with_*` setters):

```rust
pub struct Limits {
    pub max_objects: u32,              // 10_000_000; effective cap per file min(max_objects, max(4096, len)) in-use objects
                                       // (~50 B each); the xref reader reads at most max(2^20, 4 × len) entries
    pub max_nesting_depth: u16,        // 256 for arrays/dicts (parser AND recursive walkers); clamped to
                                       // Limits::MAX_NESTING_DEPTH = 512, because Object's derived Clone/Drop/PartialEq/Debug
                                       // recurse (~200 KiB of stack at 512 in release builds, ~600 KiB in debug)
    pub max_decoded_stream: usize,     // 512 MiB per stream (Flate/LZW bombs)
    pub max_total_decoded: u64,        // 4 GiB per document: each SOURCE stream counts once (its largest decode; a decode
                                       // stopped by a limit counts what it was allowed), so re-decoding is free for a
                                       // long-lived store while many bombs still stop here; caller-owned data
                                       // (StreamData::Encoded/Decoded) is bounded per stream only
    pub max_xref_sections: u32,        // 4096 (/Prev chain; loop detection by offset set); also reported when the sections
                                       // together need more than max(1 MiB, 4 × len) bytes of parsing
    pub max_page_tree_depth: u16,      // 64, cycle detection by ObjectId set
    pub max_string_len: usize,         // 128 MiB
    pub max_image_pixels: u64,         // 1 << 28, checked with checked_mul on W*H*BPC*comps
    pub max_ref_chain: u16,            // 32 for Ref→Ref→… (e.g. indirect /Length) and /Extends chains
    pub max_diagnostics: u32,          // 10_000 stored per document; the rest are only counted
    pub max_objstm_decoded: usize,     // 64 MiB per object stream (and ≤ max_decoded_stream); a larger one is refused
    pub max_objstm_cache: usize,       // 64 MiB of decoded object streams kept (LRU); a re-decode settles the container
    pub budget_scale: u32,             // 1; multiplies every budget derived from the file length (Limits::budget):
                                       // xref entries/bytes, object_cap, reconstruction decode, objects parsed from
                                       // object streams. Derived budgets have their own LimitKind
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
  - `Page<'a>` is a borrowed read view (it holds `&Document` and is `Send + Sync`, so pages can be read from several threads at once).
  - **Page mutation goes through `Document` methods that take the 0-based page index**, not through a mutable page view (there is no `doc.page_mut(idx)`): `set_media_box(index, Rect)`, `set_crop_box(index, Option<Rect>)` and `set_rotation(index, Rotation)` (M2); the page operations of M5 (insert, delete, move, rotate) follow the same pattern. A mutable view would borrow the whole document for as long as it lives and adds nothing the index does not give. The setters:
    - write the value on the page object itself, **materializing** an inherited value there instead of changing the `/Pages` node it came from, which would change the sibling pages too (§7.7.3.4). A value counts as inherited when it comes from the page-tree nodes above the page (what poppler and the model read, and qpdf for `/MediaBox` and `/Resources`) or from the nodes its `/Parent` chain reaches (what pdf.js reads, and qpdf for `/CropBox` and `/Rotate`; the two differ only when a `/Parent` is wrong), so that after the edit every reader shows the value set;
    - keep the boxes consistent: a crop box is written clipped to the media box, and a new media box under a crop box that sticks out also writes the clipped crop box, because readers clip an oversized crop box differently (poppler, see the oracle suite `model`); `set_crop_box(i, None)` makes the crop box the media box, writing it when the page would otherwise inherit one;
    - edit nothing when the value does not change, so an incremental update stays as small as the change, and keep the cached page-tree walk (they never touch `/Kids`, `/Parent` or `/Count`);
    - round a box's coordinates as the serializer writes them (at most 10 fractional digits) before using it, so the document in memory says what its saved file says, and return `PageOutOfRange` for an index past the last page and `InvalidArgument` for a box that is not finite or has no area once rounded.
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

  In JS, `ErrorCode::WrongPassword` becomes `err.code === "E_WRONG_PASSWORD"`. Error messages never include key material or passwords. As of M2, `folioxide-model` adds no error type of its own: it returns `folioxide_syntax::Error` (codes `PageOutOfRange`, `NotFound`, `InvalidArgument`, …), and the facade re-exports that type as `folioxide::Error` until a second error type exists (M3).
- **Leniency is a policy, not a scattered behavior.** Use `OpenOptions { strictness: Lenient | Strict, password: Option<Vec<u8>>, limits }`. Lenient is the default and records `Diagnostic`s, available through `doc.diagnostics()` (the store's, then the model's, each recorded once however often the accessor that found it runs).
  - **Strictness applies to the syntax layer only:** what the `Store` repairs or refuses while it reads the file (the cross-reference structure, unreadable objects, stream data).
  - **Model repairs are diagnostics in both modes.** What the model finds wrong one level up is repaired the same way in lenient and strict mode, with a `Diagnostic` of kind `PageTree`, `PageAttribute`, `Metadata` or `Catalog`: a wrong `/Count` (the leaf walk counts), a page-tree cycle or a kid that is neither `/Page` nor `/Pages` (skipped), a missing or invalid `/MediaBox` (US Letter), a `/Rotate` that is not a multiple of 90 (0), a crop box outside the media box (ignored), an Info entry of the wrong type (left out), a catalog `/Version` that is not a version name (the header's). The reason: most model accessors return plain values with no error channel (`Page::media_box() -> Rect`, `Page::rotation() -> Rotation`), and a file whose syntax is sound but whose page attributes are odd should read the same in both modes.
  - **Exceeding a `Limits` value is an error in both modes** (`LimitExceeded`; for the model, a page tree deeper than `max_page_tree_depth`, a name or number tree deeper than `max_nesting_depth`, and a page, name or number tree with more nodes than `max_objects`).

## A.5 Dependency table

All rows were verified on the crates.io API on 2026-10-10 unless marked. Versions must be compatible with the workspace MSRV, 1.89 (DECISIONS D7.2). Pin everything in `[workspace.dependencies]` and set `default-features = false` where possible.

| Purpose | Crate | Version | License | Notes |
|---|---|---|---|---|
| Ordered dict | `indexmap` | 2.14.2 | Apache-2.0 OR MIT | |
| Errors | `thiserror` | 2.0.21 | MIT OR Apache-2.0 | |
| DTO serialization | `serde` | 1.0.229 | MIT OR Apache-2.0 | optional (`serde` feature) |
| Deflate | ~~`flate2`~~ (not used, D9.1) | — | — | `miniz_oxide` alone does inflate and deflate |
| Deflate (lenient / partial decode) | `miniz_oxide` | 0.9.1 | MIT OR Zlib OR Apache-2.0 | used directly for "decode as much as possible" on truncated streams |
| LZW | ~~`weezl`~~ (not used, D9.1) | — | — | own decoder in `filters::lzw` (`/EarlyChange`, leniency, limits) |
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
The M4 brief §4.1–§4.5 holds the byte layouts; this is their summary.
- **Request** (`PreparedSignature::timestamp_request(signature, &TimestampParams)`): `TimeStampReq { version 1, messageImprint { SHA-2 with NULL parameters, as openssl ts -query writes it (D-11; the signature's digest unless the params say otherwise, never SHA-1), H(contents octets of the normalized signature value) }, reqPolicy (optional), nonce (the params' u64 from 1 to 2^64 − 1, since brief §4.1 makes it a positive INTEGER and 0 is refused, R-24; else a non-zero draw of the OS RNG with feature sys-rng), certReq TRUE }`. The value is verified and normalized first (an ECDSA value given as IEEE P1363 is timestamped as the DER value that is embedded).
- **Core trait** (synchronous; there is no network in the core): `trait Timestamper { fn timestamp(&self, request_der: &[u8]) -> Result<Vec<u8> /* TimeStampResp DER */>; }`, also implemented by any `Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync`. Async hosts (Node) use the two-phase flow instead (A.6.5, A.7).
- **Response validation** (`tsp::validate_response`, called by `finish_with_timestamp`): ordered checks, the first failure is `TimestampInvalid` with the check named:
  1. `status ∈ {granted(0), grantedWithMods(1)}` (D-9), else `TSA refused: status <n>, "<statusString>", failInfo <names>`;
  2. a token is present;
  3. the token passes the verifier's whitelist (V7b step 1, `tsp/shape.rs`): SignedData version 3 with one SignerInfo, eContentType `id-ct-TSTInfo` (1.2.840.113549.1.9.16.1.4) and eContent, the digest set, the SignerInfo version its `sid` implies, certificate entries that decode, algorithm parameters, every primitive a valid X.690 encoding, signed attributes in DER and ESS attributes that decode whole (M4 QA round 3 findings 2, 3 and 5), and every name as OpenSSL's `X509_NAME` decodes it, its strings ones OpenSSL converts to UTF-8 (no BMPString surrogate, no UniversalString beyond Unicode; QA round 4 findings 1 and 4);
  4. the TSTInfo: version 1, `extensions` that decode (QA round 3 finding 4) and a `tsa` GeneralName that decodes as OpenSSL's `GENERAL_NAME` template reads it (QA round 4 findings 2 and 4); the request's `messageImprint` (the same OID, NULL and absent parameters equivalent, the same hash); a nonce exactly when the request had one, equal as an INTEGER value; the request's `reqPolicy` when it had one; a `genTime` Folioxide's own parser reads;
  5. the TSA's CMS signature verifies with the certificate the token carries (certReq was true, RFC 3161 §2.4.1), and not with SHA-1; a TSA key whose SubjectPublicKeyInfo is `id-RSASSA-PSS` verifies RSASSA-PSS only, with its parameters when it states them (A.6.7 step 4; manager ruling R-22 (b));
  6. ESS: `signing-certificate` (v1) or `signing-certificate-v2` present, and every one present a single value whose first identifier names the TSA certificate and whose later identifiers name certificates of the token that issued it or one of its issuers, each link checked by name, by the authority key identifier (R-22 (a)) and by a verified signature (M4 QA round 2 finding 3); the TSTInfo `tsa` name, when present, is the TSA certificate's subject or a subjectAltName entry (RFC 3161 §2.4.2; the subjectAltName decoded as the `tsa` name is, one that does not decode naming nothing). Names compare as RFC 5280 §7.1 and OpenSSL's `X509_NAME_cmp` do (string type, ASCII case and white space folded);
  7. `check_tsa_certificate` (D-4, OpenSSL `check_purpose_timestamp_sign`): no extension type twice and every extension of a type Folioxide, asn1crypto or OpenSSL decodes decoding (R-22 (c), final fix round 2 finding 1: OpenSSL's `ossl_x509v3_cache_extensions` marks such a certificate invalid), and no critical extension OpenSSL does not handle (closing round, findings 8 and 11; A.6.7 step 6.6); EKU present, critical and exactly `id-kp-timeStamping`; key usage absent or within {digitalSignature, nonRepudiation}. Trust is no signing-side check: a token whose TSA certificate carries an extension Folioxide does not process on a path (a well-formed `proxyCertInfo` or RFC 3779 block) is embedded, and verifies as valid but untrusted, which `openssl ts -verify` refuses for that chain reason only (closing round, finding 9: no change);
  8. `genTime` within the TSA certificate's validity;
  9. the request handed to `finish_with_timestamp` parses, has `certReq` true and its imprint is the digest of the normalized signature value.
  
  So Folioxide never embeds a token its own verifier calls malformed or invalid without trust anchors (with anchors the verifier also wants the later ESS identifiers on the validated path, V7b step 9, which the signing side cannot check).
- **Embedding** (§4.3): the token, not the whole response, as exactly one unsigned attribute `id-aa-signatureTimeStampToken` with exactly one value; the signed attributes and the signature value are untouched. A BER token is embedded verbatim with a warning (D-12).
- **Sizing** (§4.4): `SignatureOptions::tsa_reserve` budgets the token in `/Contents` (default 0; `sign` with a timestamper and the Node binding use `DEFAULT_TSA_RESERVE` = 8192, enough for a chain of about three certificates). A token that does not fit gives `PlaceholderTooSmall { needed, reserved }` before anything is written.

### A.6.5 External / deferred signing (two-phase)

```rust
pub struct SignatureOptions { pub field: FieldSpec, pub signing_time: PdfDate, pub digest: Option<DigestAlgorithm>,
    pub sub_filter: SubFilter, pub name / reason / location / contact_info: Option<String>, pub contents_reserve: Option<usize>,
    pub certification: Option<DocMdpPermissions>, pub appearance: Option<SignatureAppearance>, pub tsa_reserve: Option<usize>, .. }
pub struct PrepareRequest { pub chain_der: Vec<Vec<u8>>, pub algorithm: SignatureAlgorithm, pub options: SignatureOptions }
pub fn prepare(doc: &Document, req: &PrepareRequest) -> Result<PreparedSignature>;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]   // to_bytes/from_bytes (FXPS v1): persisted between Tauri commands / processes
pub struct PreparedSignature { /* the PDF with its patched /ByteRange and zeroed /Contents, the signed attributes, digest, algorithm, chain */ }
impl PreparedSignature {
    pub fn to_be_signed(&self) -> &[u8];                      // DER signedAttrs (0x31 tag), for "sign message" KMS APIs
    pub fn to_be_signed_digest(&self) -> Vec<u8>;             // H(to_be_signed), for "sign digest" HSM/KMS APIs
    pub fn to_be_signed_digest_info(&self) -> Vec<u8>;        // DER DigestInfo, for raw RSA signing (PKCS#11 CKM_RSA_PKCS)
    pub fn finish(self, signature: &[u8]) -> Result<Vec<u8>>; // PAdES B-B; try_finish gives the prepared signature back on error
    pub fn timestamp_request(&self, signature: &[u8], params: &TimestampParams) -> Result<Vec<u8>>; // DER TimeStampReq (A.6.4)
    pub fn finish_with_timestamp(self, signature: &[u8], request_der: &[u8], response_der: &[u8]) -> Result<Vec<u8>>; // B-T
    pub fn embed_cms(self, cms_der: &[u8]) -> Result<Vec<u8>>; // the caller produced the whole CMS (remote signing services)
}
pub trait Signer: Send + Sync {                 // local keys implement it; Tauri can add OS keychain / PKCS#11 later
    fn certificate_chain(&self) -> &[Vec<u8>];
    fn algorithm(&self) -> SignatureAlgorithm;
    fn key_kind(&self) -> KeyKind;
    fn sign(&self, digest: DigestAlgorithm, to_be_signed: &[u8]) -> Result<Vec<u8>>;
}
pub fn sign(doc: &Document, req: &SignRequest<'_>) -> Result<Vec<u8>>;   // = prepare + signer.sign + (timestamper) + finish
// SignRequest::new(&signer, time).with_options(options).with_timestamper(&timestamper, TimestampParams::new())
// LocalSigner::from_pkcs12(der, password), ::from_pem(key_pem, certs_pem, key_password), ::from_pkcs8_der(key, chain)
```

The B-T flow for async hosts (M4 brief §4.5): `prepare` → the signer signs `to_be_signed` → `timestamp_request(value, params)` → the host sends it to the TSA → `finish_with_timestamp(value, request, response)`. `PreparedSignature` stays stateless: `finish_with_timestamp` normalizes the value again (deterministically) and checks that the request's imprint is its digest. Every check runs before the file is touched, and the `try_*` variants give the prepared signature back with the error, so a caller can retry with another value or response. **The Node slot** (A.7) remembers the last request `timestampRequest` returned; once it is remembered, `finish` (and `finishAsync`) without a `timestampResponse` throws `E_INVALID_ARGUMENT`, so a forgotten response never gives a file without a timestamp, until `discardTimestampRequest()` forgets it and `finish` makes a B-B file after all. `serialize` does not keep the request: after `deserialize`, pass it to `finish`.

### A.6.6 DocMDP and certification (ISO 32000-2 §12.8.2.2)
The M4 brief §4.6 holds the details; `docmdp.rs` implements both sides.
- **Certifying** (`SignatureOptions::certification`): the signature dictionary gets `/Reference [<</Type /SigRef /TransformMethod /DocMDP /TransformParams <</Type /TransformParams /P n /V /1.2>>>>]` (all direct, as pyHanko writes it; `/V /1.2` is a name), inserted before `/ByteRange` so `/Contents` stays last, and the catalog `/Perms <</DocMDP sig>>` (an existing `/Perms` is edited, an existing `/UR3` kept with a warning).
  - `P = 1`: no changes allowed.
  - `P = 2`: form filling, signing and page templates (the default).
  - `P = 3`: P = 2 plus annotation create, delete and modify.
- **Refusals** (`DocMdpForbids`, the message naming the rule):
  - (a) certifying when any signature field is signed already (document timestamps included: "it shall be the first signed field", §12.8.2.2.1) or the catalog already has `/Perms /DocMDP`;
  - (b) an approval on a certified document: refused under `P = 1`; under `P = 2` or `3` allowed for a new **invisible** field or an **existing empty** field (visible or not), while a **new visible** field is refused (D-3: pyHanko marks the certification `OTHER` then);
  - (c) certification together with an appearance is allowed: it is the certifier's own field.
- **Which `P` is in force** when signing on top (`docmdp::certification`): the catalog's `/Perms /DocMDP` signature, every signed field whose signature dictionary has a DocMDP reference, and (PDF 2.0, §12.7.5.5 Table 236; manager ruling R-4) every signed field whose **lock dictionary** has `/P`, which takes part in the signature's DocMDP level as in pyHanko's `docmdp_level`; the smallest `P` counts. So a field lock `/P 1` refuses every later signature and `/P 2` or `3` allows only invisible or existing-field approvals, as rule (b). A declaration that cannot be read (`/Reference` not an array, an entry without `/TransformMethod`, `/P` not an integer from 1 to 3, two DocMDP references, a malformed `/Lock`, a key written twice) counts as **`P = 1`**, never as the default 2 (R-6), so Folioxide refuses to sign on top of it; a missing `/P` in `/TransformParams` is 2 (Table 257). The signing side never writes such a declaration.
- **The revision chain:** a trailer or cross-reference stream dictionary of the chain that writes `/Prev` or `/XRefStm` twice with different values is refused with `Error::Syntax(Xref)` (`E_XREF` in Node) by `docmdp::certification`, so by `prepare` and `sign` (M4 QA round 3 finding 13): first-wins and last-wins readers follow different revisions, and Folioxide's last-wins reading could miss a certification a first-wins reader sees. Verification fails the same way (A.6.7 step 10). A signed declaration that is not written canonically (a key twice, `/P 4294967298`, the R-12 gate of A.6.7 step 10) counts as unreadable, so `P = 1`.
- **Verification** (V11, A.6.7 step 11) reads the same declarations: `docmdp`, `P_effective` and `docmdp_ok`.
- **FieldMDP field locking** itself (which fields a lock's `/Action` and `/Fields`, or a `/TransformMethod /FieldMDP` reference, protect) is not evaluated until M11: the signing side never writes a lock, and verification reads only the lock's `/P` (R-4) and, conservatively, treats every generic form fill under the evaluated signature's own FieldMDP as `Other` (D-23).

### A.6.7 Verification algorithm (`verify(bytes, &VerifyOptions) -> Vec<SignatureReport>`)

The binding steps are V0–V12 of the M3 brief §5 with the M4 additions of the M4 brief §5 (V7b, V7c,
V8–V11, §5.1–§5.3); this section is their summary, and the briefs hold the details and the
deliberate-difference tables (M3 §0.1, M4 §0.1–§0.3). The reference validator is pyHanko (0.37);
Folioxide is **never more lenient** than it, with one recorded exception (D-1 below), and every
stricter result is a corpus case with a `DELIBERATE_DIFFERENCES` row (`sign-attacks`, `certify`,
`sign-bt`). For timestamp tokens OpenSSL `ts -verify` is a second reference: a token it refuses for
a reason other than trust is never `valid`, with two recorded exceptions that RFC 5652 allows and
OpenSSL 3.0's PKCS #7 layer cannot read (an RSASSA-PSS token signature, a SignerInfo identified by
its subjectKeyIdentifier), which Folioxide and pyHanko accept (manager ruling R-11, brief §5.5
(iii)). Since QA round 3 this covers the parts OpenSSL decodes that no check of Folioxide uses (the
TSTInfo `extensions`, the ESS `policies` and issuer names) and the signed attributes, which OpenSSL
re-encodes as DER before it verifies them, and since QA round 4 every name of the token (OpenSSL
converts the strings of every name it decodes to UTF-8) and the TSTInfo `tsa` GeneralName.
Folioxide is stricter than OpenSSL in a few recorded places (signed attributes out of DER order,
which OpenSSL keeps as read and BouncyCastle sorts; empty TSTInfo `extensions`; a BMPString
surrogate outside a name; a certificate of the token whose name holds a UniversalString, which
x509-cert cannot decode, so such a TSA loses B-T; a TSA or signer path through a CA with name or
policy constraints, never trusted, step 9). Since QA round 5 (manager ruling R-22) the certificate
rules OpenSSL and pyhanko-certvalidator apply below the trust decision hold too: the authority key
identifier on every path edge (step 9), the `id-RSASSA-PSS` key restriction (step 4) and a TSA
certificate's extension list (step 6.6).

1. Open leniently.
   - Enumerate signature fields from `/AcroForm /Fields`, recursing through `/Kids` with `/FT /Sig` and `/V`.
   - Also scan for orphaned `/Type /Sig` dictionaries and report them as `orphan`.
   - Document timestamps (`/Type /DocTimeStamp` or `/SubFilter /ETSI.RFC3161`) are reports of
     kind `DocTimeStamp`, verified by V7c (M3's `PendingTimestampVerification` is retired, D-19).
2. **ByteRange sanity:**
   - exactly 4 non-negative integers, `[0, a, b, c]`, with `0 < a < b ≤ b + c ≤ file_len`
   - `bytes[a] == b'<'`, `bytes[b-1] == b'>'`, everything in between is hex or whitespace
   - the gap corresponds to *this* dictionary's `/Contents`, checked by locating the token via the parsed object's offset
   - `b + c` equals the `eof_end` of some revision (a trailing EOL is tolerated)
   - Anything else gives `ByteRangeInvalid`. This stops "signature wrapping" tricks.
3. Parse the CMS. Choose the routine by `/SubFilter`:
   - `ETSI.CAdES.detached`, `adbe.pkcs7.detached`: detached CMS over the byte ranges
   - `adbe.pkcs7.sha1`: eContent = SHA-1 of the data (verify only)
   - `ETSI.RFC3161`: document timestamp (V7c)
   - `adbe.x509.rsa_sha1`: verify-only, optional
4. Recompute the digest over the ranges and compare it with `message-digest`. Then verify `signature` over DER(signedAttrs re-tagged 0x31) with the signer certificate's SPKI: RSA PKCS#1 v1.5, RSA-PSS, ECDSA P-256 or P-384. An embedded ECDSA value must be a minimal DER `ECDSA-Sig-Value`, as OpenSSL and pyHanko verify it (P1363 input is normalized by `finish` only; M4 QA finding F1). An RSA key whose SPKI algorithm is `id-RSASSA-PSS` verifies RSASSA-PSS signatures only (RFC 4055 §1.2), and when the SPKI states `RSASSA-PSS-params` only signatures with exactly those parameters, the hash, MGF1 on it and the salt length (§3.1, as pyHanko compares them; OpenSSL takes the salt length as a minimum, so equal is the stricter reading): a PKCS #1 v1.5 value with such a key is `SignatureInvalid`, as for pyHanko (an assertion) and OpenSSL (`illegal or unsupported padding mode`), for document signatures, timestamp tokens and certificate signatures on a path alike (`keys::public::RsaKeyUse`; manager ruling R-22 (b), M4 QA round 5 finding 36). `RSASSA-PSS-params`, in a SignerInfo, a certificate signature or an SPKI, are read in their definition's order, `[0]` to `[3]`, each field at most once with exactly one element and minimal INTEGERs (`cms::verify::pss_parameters`; M4 final fix round 2, finding 2): a reader that let a repeated field overwrite the earlier one took SHA-256 or a 20-byte salt where pyHanko reads the first (`PSSParameterMismatch`, or "Unknown element" for an out-of-order field) and OpenSSL cannot decode the key (sign-bt rows `tst-tsa-spki-pss-params-dup-salt`, `tst-pss-params-dup-{salt,hash}`). Their two hash AlgorithmIdentifiers, the hash and MGF1's, have absent or NULL parameters only (RFC 4055 §2.1; closing round, finding 7): an anchor or intermediate whose `id-RSASSA-PSS` key carried an INTEGER there had verified its certificates where pyHanko, comparing the parameters structurally, does not trust them; such a key is now unusable (sign-bt rows `tst-tsa-{anchor,inter}-pss-hash-params-int`, equal to pyHanko; OpenSSL ignores the hash parameters and verifies the path, so this is stricter than OpenSSL, for trust only). The signing side never signs with such a certificate: `certificate_key_kind`, so `prepare`, refuses it (`Unsupported`), since Folioxide signs RSA with PKCS #1 v1.5.
5. Check that `signing-certificate-v2` (or v1 without v2) matches the signer certificate hash (pyHanko's rule: the first identifier, and its issuerSerial when present). PAdES profile flags: SubFilter, `signing-time` absent, signing-cert-v2 present.
6. **Signature timestamps (V7b; `tsp::verify_token`, `verify_pdf/timestamp.rs`).** Every value of every `id-aa-signatureTimeStampToken` unsigned attribute of `ETSI.CAdES.detached` and `adbe.pkcs7.detached` signatures, at most `MAX_TIMESTAMP_TOKENS` (8, more get a warning), over the signature value's OCTET STRING contents. Unsigned attributes are not signed, so more than `MAX_ATTRIBUTES` (64) of them are not an error: the ones after the limit are not read, with a warning (finding F10). Per token:
   1. **Shape, as a whitelist** (findings F5, F6): a SignedData of version 3 with one SignerInfo, eContentType `id-ct-TSTInfo` and eContent; `digestAlgorithms` listing only digests Folioxide implements (absent or NULL parameters) and the SignerInfo's (OpenSSL `PKCS7_dataInit`); every certificate entry an X.509 certificate that decodes, its names holding only the value types OpenSSL's `X509_NAME_ENTRY` takes; every CRL one that decodes, its issuer a name that does; the SignerInfo version its `sid` implies (RFC 5652 §5.3); digest and PKCS #1 / ECDSA signature algorithms without parameters other than NULL; and every primitive of the token and of its TSTInfo a valid X.690 encoding of its universal type (no empty or padded INTEGER, no invalid OBJECT IDENTIFIER or UTF-8, no BMPString code unit in D800–DFFF, lone or paired, no UniversalString value that is a surrogate or above 10FFFF, …; `cms::tlv::check_primitives` and `string_converts`, one pass; QA round 4 finding 1: OpenSSL converts every value of every name it decodes to UTF-8, `x509_name_canon`, so such a string anywhere in a certificate, a CRL issuer, an ESS issuer or the `tsa` name makes `ts -verify` refuse the token; the rule holds for every such string of the token, which is stricter outside names). The SignerInfo's signed attributes are present (RFC 5652 §5.3) and DER (QA round 3 finding 2: minimal definite lengths, the attributes and each attribute's values in `SET OF` order, BOOLEANs `FF`/`00`, clear unused bits; RFC 5652 §5.4 signs the DER encoding, OpenSSL re-encodes each attribute and BouncyCastle the whole set before verifying, so a TSA that signed another encoding made a token they refuse, while a verifier that hashes the bytes as found accepts it). Every value of an ESS signing-certificate attribute decodes as OpenSSL's `ESS_SIGNING_CERT(_V2)` templates read it (QA round 3 finding 3): `policies` as `SEQUENCE OF PolicyInformation` (RFC 5280 §4.2.1.4, the CPS and user-notice qualifiers typed), each `IssuerSerial` one directoryName whose name values `X509_NAME_ENTRY` takes. Else `TimestampMalformed`.
   2. A TSTInfo of version 1 whose `genTime` Folioxide's own parser reads (`YYYYMMDDhhmmss[.f{1,9}]Z`; never `der::GeneralizedTime`, R-3); a `tsa` field is exactly one GeneralName that decodes as OpenSSL's `GENERAL_NAME` template reads it (`x509info::names::general_name`; QA round 4 finding 2: each of the nine choices with its tag, form and content, an otherName's `[0] EXPLICIT` value, an ediPartyName's DirectoryStrings, a directoryName's one `Name`; a universal tag, a context tag above `[8]` or the wrong form is malformed); `extensions` a non-empty list of `Extension { OID, BOOLEAN DEFAULT FALSE, OCTET STRING }` (RFC 5280 §4.1; QA round 3 finding 4: OpenSSL decodes them, though nothing acts on one). Else `TimestampMalformed`.
   3. `intact`: the imprint is `H_alg(signature value)` and its hash algorithm has absent or NULL parameters (finding F4; OpenSSL `ts_check_imprints`), else `TimestampImprintMismatch`; SHA-1 adds `WeakAlgorithm` (never trusted), an algorithm Folioxide lacks gives `UnsupportedAlgorithm`.
   4. The TSA's CMS signature (`cms::verify_encapsulated`), else `TimestampSignatureInvalid`.
   5. The ESS binding as OpenSSL `ossl_ess_check_signing_certs` checks it (finding F3): every signing-certificate attribute present (v2 **and** v1) has one value, its first identifier names the TSA certificate and every later one a certificate, among the token's, the caller's extra certificates and the trust anchors, that issued it or one of its issuers, **each link checked by name, by the authority key identifier (as on a path, step 9) and by a verified signature** (`x509info::chain::linked_issuers`, bounded by `MAX_SIGNATURE_CHECKS`; M4 QA round 2 finding 3: a decoy that only carries an issuer's name never counts); else `TimestampEssMismatch` (pyHanko reads only the first identifier of v2, or of v1 without v2). The TSTInfo `tsa` name, when present, must be the TSA certificate's subject or one of its subjectAltName entries (RFC 3161 §2.4.2, OpenSSL `ts_check_signer_name`; finding F2), else `TsaNameMismatch`; the subjectAltName is decoded as the `tsa` name is (one that does not decode names nothing, as OpenSSL's `X509_get_ext_d2i` fails there), and a choice other than a directoryName compares byte for byte. Names (here, in the CMS `sid` and in path building) compare as RFC 5280 §7.1 and OpenSSL's `X509_NAME_cmp`: string types converted to UTF-8, white space trimmed and collapsed, ASCII case folded, RDN sets unordered, nothing else folded, and a value holding a character beyond the Basic Multilingual Plane compared exactly, string type included, since asn1crypto (so pyHanko) does not fold a UTF-8 and a UCS-4 spelling of it (`x509info::cert::canonical_name`; finding 4, QA round 5 finding 34).
   6. The TSA certificate (`check_tsa_certificate`): first its extension list, no extension type twice, every extension of a type Folioxide decodes (step 9's list) decoding as its definition says, critical or not, and no `proxyCertInfo` in a certificate that is a CA or carries an alternative name (manager ruling R-22 (c), M4 QA round 5 finding 37, final fix round 2 finding 1: OpenSSL's `ossl_x509v3_cache_extensions` marks such a certificate invalid, so `ts -verify` refuses the token whatever the anchors; pyHanko accepts it unless asn1crypto parses the type, so stricter: sign-bt rows `tst-tsa-cert-duplicate-{ski,bc}`, `tst-tsa-cert-{nscerttype,ipaddrblocks,asid,proxycertinfo}-junk`, and, where pyHanko only distrusts the token, `tst-tsa-cert-{pkup,subjdirattrs,tlsfeature}-junk`); then no critical extension that OpenSSL 3.0's `X509_supported_extension` does not list (`x509info::extensions::unhandled_critical`; closing round, findings 8 and 11, manager ruling R-26): OpenSSL sets `EXFLAG_CRITICAL` and refuses every chain with the certificate ("unhandled critical extension"), so a critical subjectKeyIdentifier, authorityKeyIdentifier (RFC 5280 §4.2.1.1, §4.2.1.2: MUST be non-critical), authorityInfoAccess, subjectInfoAccess, freshestCRL, qcStatements, issuerAltName, privateKeyUsagePeriod, subjectDirectoryAttributes, TLS feature or private extension made a token Folioxide signed and trusted that `ts -verify` refuses (pyHanko trusts the first three: stricter than pyHanko, sign-bt rows `tst-tsa-cert-critical-{ski,aki,aia,freshestcrl,qcstatements}`, controls `tst-tsa-cert-critical-{crldp,ocspnocheck}`); then its purpose, OpenSSL's `check_purpose_timestamp_sign` (D-4): EKU exactly `id-kp-timeStamping` and critical, KU absent or within {digitalSignature, nonRepudiation}; else `TsaCertificateUnsuitable` (pyHanko ignores criticality and extra purposes). On a document signer's path the same extension defects are a trust problem only (step 9).
   7. `genTime` within the TSA certificate's validity, else `TsaCertificateNotValidAtGenTime`.
   8. `valid` = 4 ∧ 5 ∧ 6 ∧ 7.
   9. `trusted`: `build_trust_for(TimeStamping, …)` against `timestamp_trust_anchors_der` (default: the signature's anchors) at the validation time, else at the token's own `genTime` with a warning (finding F8), and only for an intact and valid token without a weak algorithm; `None` without anchors. Once a path above the TSA certificate is trusted, every later ESS identifier must name a certificate of that path, anchor included, which is the chain OpenSSL searches: otherwise `TimestampEssMismatch` and the token is not `valid` (a re-issued copy of the root, same name and key, passes step 5 but is not the anchor).
   10. Selection (D-5): `report.timestamp` is the earliest `genTime` among intact, valid and not untrusted tokens, else the first; `report.timestamps` lists all. Token problems stay in `TimestampInfo::problems` (D-6): a broken timestamp token never makes the signature invalid. The unsigned attribute that holds it is CMS syntax, though: one that is not a well-formed `Attribute` (its values not a `SET`, or none) makes the CMS malformed, as for pyHanko, which cannot read such a file either (QA round 4 finding 6). A selected `genTime` before `/M` gives a warning. A token value that cannot be read at all (a truncated or huge declared length, nesting beyond the depth limit) is not listed, and the report warns that an unsigned attribute could not be read, so a damaged timestamp is not mistaken for none (QA round 3 finding 1).

   `validate_response` (the signing side, M4 brief §4.2) applies the same shape, ESS, name and certificate rules, so Folioxide never embeds a token its own verifier refuses without trust anchors (the step-9 path rule needs anchors the signing side does not have).
7. **Document timestamps (V7c).** The token in `/Contents`, steps 1–9 over the signed byte ranges: `intact` from step 3, `signature_valid` from step 8 (and `/SubFilter /ETSI.RFC3161`, else `UnsupportedSubFilter`), `signer` the TSA certificate, `claimed_time = genTime`, `pades_level = None`; for a document timestamp the token *is* the signature, so its problems are the report's.
8. **PAdES level (V8).** `B-B` for `ETSI.CAdES.detached` with a DER SignedData (a TSA's token inside is opaque, D-12), the B-B signed attributes, one detached SignerInfo whose certificate the CMS carries, `/M` present and no `/Cert`; `B-T` when the selected signature timestamp is also intact and valid. When only the DER condition fails, the report says so in a warning (QA round 3 finding 1). `B-T` does not say the TSA is trusted: a caller relying on the time also requires `timestamp.trusted == Some(true)`. B-T through a later document timestamp is M11 (D-20).
9. **Certificates and trust (V9):**
   - DTO `{subject, issuer, serialHex, notBefore, notAfter, sha256, keyAlgorithm, keyUsage, extKeyUsage}` for the signer, chain and TSA
   - trust against caller-supplied anchors: path building, chain signatures, validity at `VerifyOptions::validation_time`; without one at the `genTime` of a selected signature timestamp that is trusted (D-7), else at `/M`, each with a warning in the report. **Residual (finding F8):** `genTime` is the TSA's own claim, so with no validation time a TSA key that outlived its certificate can sign a token that claims a time inside that certificate's validity, and both the token and the signer it vouches for are then trusted; only a validation time (the Node binding passes "now" unless told otherwise) breaks the circle.
   - path validation (`x509info::chain`, `x509info::extensions`): every certificate's names hold only valid encodings and strings OpenSSL converts to UTF-8 (no BMPString surrogate; QA round 4 finding 1); a critical extension may only be one that path validation processes or that needs no processing **and** that OpenSSL handles as critical (`KNOWN_CRITICAL_EXTENSIONS`: keyUsage, subjectAltName, basicConstraints, cRLDistributionPoints, certificatePolicies, extKeyUsage, ocspNoCheck): any other critical extension, unknown, one OpenSSL refuses as critical (step 6.6: a critical key identifier, information access, freshestCRL, qcStatements, …; closing round, findings 8 and 11) or one Folioxide does not process (nsCertType, the constraints below, RFC 3779, proxyCertInfo) makes the path untrusted; every extension of a type Folioxide, asn1crypto (pyHanko) or OpenSSL decodes (key identifiers, key usage, alternative names, basic constraints, name and policy constraints, policy mappings, CRL distribution points and freshest CRL, certificate policies, extended key usage, information access, qcStatements, OCSP no-check; and since final fix round 2, finding 1, subject directory attributes, the private key usage period and the TLS feature, which asn1crypto parses, and the Netscape certificate type, the RFC 3779 IP address and AS identifier blocks and the proxy certificate information, which OpenSSL decodes) must decode as its definition says, critical or not, as pyhanko-certvalidator and OpenSSL (`EXFLAG_INVALID`) require (a value with a stray byte after it does not decode, which both let pass for some types: stricter, closing round finding 9, no change); an extension type outside that union is decoded by neither reference; a certificate anywhere on the path, the signer and the TSA included, with an RFC 3779 block (an empty or inherit-only one too) or a `proxyCertInfo` is never trusted, since Folioxide implements neither RFC 3779 resource nor RFC 3820 proxy path processing and OpenSSL refuses such chains on their own (`X509_V_ERR_UNNESTED_RESOURCE`, `X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED`; stricter than pyHanko, which does not know them: sign-bt rows `tst-tsa-cert-proxycertinfo-valid`, `tst-tsa-cert-ipaddrblocks-inherit`); an issuer with `nameConstraints`, `policyMappings` or `policyConstraints`, critical or not, or a signer with `policyConstraints`, makes the path untrusted, since Folioxide does not process them (M4 QA round 4 findings 5 and 9: a non-critical `nameConstraints` excluding the signer's name made paths trusted that pyHanko and OpenSSL reject). A path that satisfies such a constraint is untrusted too, stricter than both (sign-bt row `tst-tsa-ca-name-constraints-satisfied`); a non-critical `inhibitAnyPolicy` cannot fail a path without policy constraints and is allowed; no extension type may occur twice. Document signers and TSAs share it.
   - **path edges** (manager ruling R-22 (a), M4 QA round 5 finding 32): a candidate issuer, anchor or pool certificate, must also be the one the certificate's `authorityKeyIdentifier` describes (`x509info::extensions::KeyIds::mismatch`, checked before the signature): a `keyIdentifier` equal to every `subjectKeyIdentifier` the issuer carries (one that does not decode equals none); an `authorityCertSerialNumber` equal to the issuer's serial number; an `authorityCertIssuer` only together with a serial number, and with a first entry that is a `directoryName` byte-identical to the issuer's own issuer name. That is the union of OpenSSL's `X509_check_akid` and pyhanko-certvalidator's issuer filter (`find_potential_issuers`, `is_potential_issuer_of`), so an edge either refuses is no edge: before, a certificate whose AKI named another CA was chained and trusted where both refuse the path. A wrong serial number given alone is refused as OpenSSL does, which pyHanko ignores (stricter: sign-bt row `tst-tsa-akid-serial-only-wrong`); an AKI that does not decode constrains no edge, since that certificate is refused anyway (above). Signature, signature-timestamp and document-timestamp paths share the rule, and so do the ESS links of step 6.5. Every edge's certificate signature, the ESS links included, must also carry the parameters its algorithm defines in both the outer `signatureAlgorithm` and `tbsCertificate.signature`, absent or NULL for RSASSA-PKCS1-v1_5 (RFC 4055 §5) and absent for ECDSA (RFC 5758 §3.2), or the edge is untrusted (manager ruling R-30 (b), `x509info::chain::parameters_defect`: pyHanko's verdict for the RSA algorithms, whose NULL asn1crypto forces, sign-bt rows `tst-tsa-cert-sigalg-params-*`; stricter than pyHanko and OpenSSL for ECDSA, rows `doc-signer-sigalg-ecdsa-params-*`). The trust anchor contributes its name, key and key identifiers only: its own validity, basic constraints, key usage and extensions are not evaluated (user-supplied anchors are trusted as given, as pyHanko's default trust-anchor qualifiers do; OpenSSL refuses an anchor that is not a CA, for example).
   - **no revocation and no network**; a weak algorithm is never trusted
10. **Modified after signing (V10; `revisions.rs`):**
   - `coverage = WholeFile` if `b + c == file_len`, otherwise `Revision(k)`.
   - For each later revision, compute changed object IDs from the xref sections after the signed revision (`Store::revision_entries(k)`). For a hybrid section the changed set is the UNION of the table's entries and its `/XRefStm` stream's, whatever a particular reader would take from either (otherwise a change can hide in the half another reader prefers: a shadow attack), and it includes every free entry and every entry that reads as null. Then classify with a **whitelist** modelled on pyHanko's DiffPolicy, in pyHanko's vocabulary (`ModificationLevel`: `None < LtaUpdates < FormFilling < Annotations < Other`). **Principle:** a later revision gets a level below `Other` only for the exact changes legitimate later signers, form fillers and (under `P = 3`) commenters make; every other change to an object reachable from the signed revision is `Other`. `Revisions::modification(k, &ModificationContext { certifying, permissions, field_mdp, timestamp })` evaluates each signature's own window `k..r` (R-7) and caches per (revision, context); `permissions` is the signature's `P_effective` (step 11) for a signature that sets permissions and for a document timestamp (manager ruling R-20, below). The whitelist (M3 brief §5 V10 and M4 brief §5.1–§5.3 have the details):
     - a re-listed or unchanged object, a new cross-reference or object stream, an orphan (a new object nothing reaches), the trailer's `/Info` (changed in place or a new dictionary), the catalog's XMP `/Metadata` (a new or changed packet must be well-formed XML with namespaces whose root is `x:xmpmeta`, with no XML declaration but a valid one at its very start and namespace names that are URI references outside the reserved bindings, read in one bounded pass, `revisions/xmp.rs`; below 10,000,000 bytes, with names of at most 50,000 bytes, libxml2's limits as lxml applies them for pyHanko; decoded only through what pyHanko decodes alike, `revisions/metadata.rs`: no `/Filter`, or a chain of `/FlateDecode` with a complete zlib stream and matching Adler-32 and no `/Predictor` other than 1, `/ASCIIHexDecode` and `/ASCII85Decode` with their end markers and never after a Flate, `/Crypt /Identity`, an exact `/Length`, no `/F` or `/FFilter`; anything else is not XMP, so `Other`), `/Extensions`, `/MarkInfo` and `/Version` → `LtaUpdates`
     - a new **invisible** signature field registered at the root of `/AcroForm /Fields` (`/FT /Sig`, no `/Kids`, a `/T` without `.`, no `/A`, `/AA`, `/OC` or `/Parent`; `/MK` allowed), appended to `/Fields` and to its page's `/Annots`; an unsigned signature field's `/Ff` → `LtaUpdates`
     - a new signature dictionary that a new or an unsigned field's new `/V` names, with the appearance (`/AP`, `/AS`, `/F`) the signed field gets; a new **visible** signature field → `FormFilling`. **New signature widgets** (any signature, R-3): `/F` may set only Invisible, Print, ReadOnly, Locked and LockedContents (signers write 4 or 132; Hidden, NoZoom, NoRotate, NoView and ToggleNoView draw elsewhere or not on screen), its `/Rect` is four numbers written canonically (R-12, below) and within ±10^5 (single-precision readers such as PDFium place larger ones elsewhere; QA round 4 finding 13; manager ruling R-21: ISO 32000-2 Annex C limits user space to 14,400 units), on a page every reader places the same way (R-13, below), a new signature field has only whitelisted keys (`SIG_FIELD_KEYS`), and the appearance is a new form XObject with a direct `/BBox` and an invertible `/Matrix`, their numbers within ±10^5 too, and so are the four `/BBox` corners mapped through the `/Matrix` (R-21, QA round 5 findings 28 and 31: PDFium drew a one-unit `/BBox` translated by 10^7 thousands of pixels outside the widget), and the largest coordinate of that mapped box times the scale onto the `/Rect` is at most 2^20 (final fix round 2, findings 2 and 4: PDFium maps it in single precision, and a `/BBox [0 0 0.01 0.01]` translated by 99,999 was drawn 2,806 pixels outside the widget; `geometry::MAX_APPEARANCE_AMPLIFICATION`; the bound also refuses some boxes PDFium still places within the widget, such as a `/BBox [0 0 1 1]` translated by 10,000 to 99,999, the stricter side: closing round, finding 4); else `Other`. Folioxide's own signer refuses a larger appearance rectangle (`InvalidArgument`). **C1:** when the evaluated signature sets DocMDP permissions (a certification, or a field lock `/P`, R-4), a new *visible* signature field is `Other` (pyHanko `valid_when_certifying=False`); signing an existing empty field stays `FormFilling`
     - **form filling** of non-signature fields (§5.1, F0–F8; level `FormFilling`, class `FormFill`): only `/V` (direct, of the field's type), on a merged button widget `/AS` (a signed state the value selects) and on a merged text or choice widget `/AP` together with `/V` (new form XObject streams with a direct `/BBox`, its and the `/Matrix`'s numbers and the `/BBox` corners mapped through the `/Matrix` within ±10^5 (R-21) and mapped onto the widget's `/Rect` precisely in single precision (at most 2^20 as above), or the signed stream rewritten in place when nothing else uses it, in every reader: the usage index also follows the raw references of objects that are not canonical); never for a pushbutton, a ReadOnly field, an `/XFA` form or under the evaluated signature's own FieldMDP (D-23); the field must stay in the tree and its widget in its page's `/Annots`, and a structure-tree `/OBJR` reference is an allowed context (D-24). Everything else of a field or widget (`/F`, `/DA`, `/Q`, `/Ff`, `/Rect`, `/MK`, `/DV`, `/TU`, `/Kids`, …) → `Other` (several stricter than pyHanko, D-14)
     - **the AcroForm, exactly** (manager decision, M3 QA round 5): (a) `/Fields` gaining new root-level signature fields (with their widget, signature dictionary and the page's `/Annots` append, above) → `LtaUpdates`; (b) `/SigFlags` only as signing requires, which no signing after a signature does (D-6; pyHanko compares it strictly), so any `/SigFlags` change → `Other`; (c) `/DR` gaining NEW resource names (in `/Font /XObject /ColorSpace /ExtGState /Pattern /Shading /ProcSet`) that the signed revision does not name → `FormFilling`. The signed revision names every name token (PDF tokenizer) of every `/DA` string of the AcroForm, of its field tree's fields and widgets and of every annotation on every page and its `/Parent` chain (orphan widgets outside `/Fields` included), of every appearance stream of those that has no `/Resources` of its own, and (M4 QA round 1, F7) every name that any signed appearance stream, of any widget or annotation in any state, uses, decoded or as written, read with every content stream it draws, nested: form XObjects, tiling patterns and Type 3 glyph procedures with their font's resources (QA round 2 finding 22), the soft-mask transparency groups (`/ExtGState /SMask /G`, §11.6.5.2) and Type 3 fonts (`/ExtGState /Font`) of the graphics states it sets (QA round 3 findings 6 and 21), a form XObject or Type 3 font recognized by a `/Subtype` written through a reference too, and, for such a stream without `/Resources` of its own or whose `/Resources` lack one of the categories `/ExtGState /ColorSpace /Pattern /Shading /XObject /Font /Properties` (PDFium looks a name its category lacks up in the page's resources; QA round 5 finding 29), what the resources of every page and page-tree node draw, inherited along both the `/Kids` walk from the catalog's `/Pages` (poppler) and each page's `/Parent` chain (PDFium; §7.8.3, §7.7.3.4; QA round 4 finding 12); each object is read once per role; when these cannot all be read within the limits, or an object they are read from is not canonical (R-12), any new `/DR` name → `Other`. So a viewer that looks up in `/DR` a name a signed stream draws and its own and the page's resources lack (poppler 24.02 and PDFium do not; pdf.js and MuPDF were not probed) finds nothing new; names only page content uses are not read, since viewers resolve those in the page's resources, never in `/DR`. Everything else in the AcroForm → `Other`
     - **markup annotations** (§5.2, decision D-1; level `Annotations`, class `Annotation`): a *new* object appended at the end of an existing page's `/Annots` with a markup `/Subtype` (Text, FreeText, Line, Square, Circle, Polygon, PolyLine, the text markups, Caret, Ink, Stamp) or a Popup of one added with it, only the allowed keys per subtype (A2), an `/AP /N` new form XObject with a `/BBox` (R-2), its geometry (`/QuadPoints`, `/InkList`, `/L`, `/Vertices`, `/Path`, `/CL`, with `/RD`, `/BE` and the border width; direct arrays of direct numbers, charged to the work budget) inside its `/Rect` (`revisions/geometry.rs`), `/F` limited as for signature widgets, its `/Rect`, `/BBox` and `/Matrix` numbers canonical and within ±10^5, the `/BBox` mapped through the `/Matrix` too (R-21), and a Text annotation only on a page whose effective `/Rotate` is 0 (§12.5.6.4: Text is drawn as if NoZoom and NoRotate were set), inherited along a page tree every reader walks the same way (R-13, below); existing annotations unchanged and in order (A6, A7). **This is the one level more lenient than pyHanko**, which never emits `ANNOTATIONS` (it declares P = 3 unsupported); it is recorded as the exception to D10.1, and `docmdp_ok` accepts it only under `P = 3`
     - `/DSS` (until M11) → `Other` (D-9)
     - **parser differentials** (manager ruling R-1): a revision with a duplicate dictionary key at any depth (stream dictionaries, objects in object streams, its trailer or cross-reference stream dictionary), an object stream holding a number twice or with a header and offset table that do not describe its data exactly, or a cross-reference section listing a number twice → `Other`: readers keep the first or the last value, so no classifier can know what a viewer shows. The syntax layer still parses last-wins; `revisions/differential.rs` reads the raw bytes with the public lexer and parser. The evaluated signature's own dictionary and field (with its `/Lock` and `/Reference` chain) are re-read the same way (M4 QA round 2): a duplicate key there, or since R-12 any defect of the canonical-input gate below (`/P 4294967298`, `/P ++2`), gives `SigDictAmbiguous`, an ambiguous `/ByteRange` or `/Contents` makes the signature not intact, and an ambiguous `/Reference` or `/Lock` is `DocMdpInvalid` (P = 1). A trailer or cross-reference stream dictionary that gives `/Prev` or `/XRefStm` twice with different values makes `verify` fail with `Error::Syntax(Xref)`, and the signing side refuses such a chain the same way (A.6.6).
     - **The canonical-input gate** (manager ruling R-12; `revisions/canonical.rs`), which replaced chasing one parser or lexer differential after another: a level below `Other` is granted only when every object the decision reads passes a strict lexical check of its raw bytes, namely (1) every object revisions `k+1..=r` write (objects in object streams and their container's header numbers, the trailers and the cross-reference stream dictionaries included); (2) the signed copy (revision ≤ `k`) of every object a later revision changes, re-lists or compares against, the signed objects the form rules read (the field, its ancestors, its widgets, their `/AP` and `/AP /N`), the signed `/DR` and every object the F7 guard reads, and the objects of `k` the role usage index walks, following the raw references of every object that is not canonical too, so a carrier only first-wins readers reach, several hops away, is found (QA round 4 finding 1); (3) the page-tree nodes a page rule consults. **Canonical** means: no dictionary writes a key twice, at any depth; an integer is `[+-]?[0-9]+` within ±2,147,483,647 and at most 11 characters (zero padding included; PDFium reads a word of 256 characters or more as 0); a real is `[+-]?([0-9]+\.[0-9]*|\.[0-9]+)` of at most 40 characters and magnitude at most 3.403 × 10^38 (Annex C); a name has no `#00` and no `#` without two hexadecimal digits, a hexadecimal string only hexadecimal digits and white space (no token the lexer repairs); a reference `N G R` has unsigned integers within the same length; an object stream lists each number once with increasing offsets inside its data; a cross-reference section lists each number once; a value that does not re-read fails closed. Any failure makes the revision `Other`, with a note naming the object and the defect. One linear token pass per object, cached, charged to the modification work budget (one unit per 8 tokens). Folioxide's lexer and poppler read `++6`, `4294967296` or a 21-digit integer as numbers, PDFium reads them as 0, pyHanko cannot read two signs: a re-listed signed object respelled so looked unchanged while viewers showed a hidden widget, and a new `/Rect` ending in `4294967296` was painted elsewhere by PDFium.
     - **The update layout** (QA round 4 finding 3; `differential::layout_ambiguity`): each revision `k+1..=r`, from the end of the revision before it to its own end, holds only the object bodies its cross-reference section lists, at exactly their positions (stream data read by `/Length`, `endobj`), its section and `startxref` with its offset, with white space and comments between; every uncompressed entry points at such a body or is the entry in force before it. Otherwise `Other`: a reader that rebuilds the cross-reference data (PDFium, when an entry is 19 bytes or junk precedes `startxref`) takes an unlisted body for the object, where Folioxide, poppler and pyHanko follow the section.
     - **Rebuild-proof updates** (manager rulings R-17 and R-21; QA round 5 findings 10, 11, 13, 16–26 and 30). poppler rebuilds the cross-reference data when it finds no `startxref` in the last 1,024 bytes (`XRef::getStartXref`), PDFium after a malformed entry, and both then take any text that looks like an object header for an object (poppler drew object text from an annotation's appearance stream data over the whole page, 469,411 pixels, after 25 KB of trailing comments or 40 KB of white space, NUL or end-of-lines). So a revision `k+1..=r` is below `Other` only when (a) the file's final `startxref` lies within its last 1,024 bytes and (b) at most two end-of-line bytes follow the final `%%EOF` (`differential::tail_ambiguity`; no comment, white space run or NUL; otherwise every signature's modification is `Other`, the newest one's too); (c) the store needed no reconstruction or repair and every in-use object the revision writes sits at the offset its entry gives (`Store::check_incremental`); (d) no text of the update, stream data, strings, names and comments included, is structure to a rebuilding reader other than the structure it writes (one linear scan, `differential::rebuild_text`): where poppler's `XRef::constructXRef` looks (the start of a line, of a 255-byte piece of a longer line, or the bytes after an `endobj`, past white-space) no object header or `trailer` before a dictionary, and at a line start or after an `endobj` (where pdf.js's tokens start) no `xref` or `startxref`; anywhere, no object header `N G obj` or `trailer <<` written as words (PDFium's `RebuildCrossRef` reads words, pdf.js's `indexObjects` ends an object at either); and its object headers are written canonically. A fill value such as `see xref table` or `Room 12 3 object` inside a line is therefore no structure (final fix round 2, finding 3); and (e) a table it writes is canonical (§7.5.4): subsection headers of unsigned integers of at most ten digits without a leading zero (PDFium reads a padded word as 0) and entries of exactly 20 bytes (a 19-byte entry makes PDFium rebuild); and (f) its trailer's (and a hybrid section's stream dictionary's) `/Size` is a direct integer above every object number the file lists and not below the previous revision's (manager ruling R-26, closing round finding 13: PDFium keeps only the objects below the newest `/Size`; `differential::size_ambiguity`). The scan of (d) is linear by construction (closing round, findings 2 and 6). pyHanko cannot read the padded files at all ("EOF marker not found"), so those rows are stricter by construction.
     - **New object streams** (manager ruling R-18, QA round 5 finding 27; `Revisions::object_stream_check`): every member of an object stream a revision `k+1..=r` writes is the target of a compressed entry of that same revision's section, in that stream at its header index, and the revision writes no other copy of it; each member is then classified like any object of the revision. An unreferenced member, an index mismatch or a second copy → `Other` (a classic table cannot list compressed objects, so such a revision adds no non-empty object stream): PDFium's rebuild took an unlisted member, a page re-pointed to a black content stream, for the object under a P = 1 certification that pyHanko and Folioxide had called `ltaUpdates`.
     - **Shared field appearances** (manager ruling R-19, QA round 5 finding 7; parity with pyHanko's `GenericFieldModificationRule._allow_appearance_update`): when a non-signature field node of the signed revision, terminal or not (closing round, finding 10: pyHanko's `_list_fields` yields every named node, non-terminal parents included), has an indirect `/AP` dictionary whose raw-reference usage count is not exactly 1 (hidden first-wins carriers count, R-12 (2)), every later revision whose level would be above `None` is `Other`, whatever it changes (pyHanko refuses it even for an `/Info`-only update). The same count applies to the indirect `/AP` dictionary of a terminal **unsigned signature field** of the signed revision, but only when a later revision signs that field (gives it a `/V`): pyHanko's `SigFieldModificationRule` runs `_allow_appearance_update` for a field that becomes signed (final fix round 2, finding 1: two empty signature fields sharing one `/AP` dictionary, the second signed later, make the first signature `other`, under a certification `docmdp_ok` false). Folioxide's signer warns when it signs such a field.
     - **Page-tree consistency** (manager ruling R-13): a rule that depends on the page (a page's `/Annots` gaining a signature widget or an annotation, the effective `/Rotate` a Text annotation needs) holds only when the page is reached exactly once by the iterative `/Kids` walk from the catalog's `/Pages` (each node once, typed `/Pages`, `/Page` or untyped; a `/Page` with `/Kids`, or an untyped node with `/Kids` and `/Contents` or `/Annots`, fails), the root has no `/Parent` and every other node's `/Parent` is the node that lists it, and the `/Rotate` inherited along that walk (§7.7.3.4) is a direct integer on every node of the path. Otherwise `Other`: poppler inherits along `/Kids`, PDFium along `/Parent`.
     - anything else → `Other`: for example any change to `/NeedAppearances` (removing it too, also in a later signer's signing revision, which makes the earlier signatures `Other` where pyHanko reports `FormFilling`), any change to the AcroForm `/DA` (adding one too), changing `/Q`, changing or removing a `/DR` name or adding another `/DR` entry (`/Encoding`), a new signature field with an action, optional content or a `/Parent`, or any change to a role object (`/Info`, `/Metadata`, `/Extensions`, `/MarkInfo`, the AcroForm, `/Fields`, a page's `/Annots`) that the new revision's trailer, catalog, AcroForm or page no longer points to, or that the signed revision also uses elsewhere
   - **Change classes.** Every explained object also gets a `ChangeClass` (`Relisting`, `Orphan`, `XrefStream`, `Metadata`, `SignatureField`, `Signature`, `DocTimeStamp`, `DefaultResources`, `FormFill`, `Annotation`); the outcome is the level and the set of classes, which `docmdp_ok` reads for `P = 1`.
   - **Document timestamp bookkeeping** (class `DocTimeStamp`, not `Metadata`): the `/Info` `/ModDate` and `/Producer`, the catalog's `/Version` and ESIC developer extension, and the XMP `xmp:ModifyDate` and `pdf:Producer` values that pyHanko's timestamper rewrites, masked in the same linear XMP pass. They are exempt only when the revision that adds the document timestamp (the first that lists its dictionary) wrote the object and no later revision of the window rewrote it (manager ruling R-8); the same edit in a revision without a timestamp is `Metadata`.
   - **A document timestamp's own window** (manager ruling R-20, QA round 5 finding 14) is judged with the permissions in force at it, `P_effective` of step 11, exactly as a signature that sets permissions; a timestamp has no `docmdp_ok` of its own (R-5). In the classifier the permissions gate the markup-annotation rule only (`ModificationContext::permissions`, read by the annotation gate alone): a markup annotation after a document timestamp is `Annotations` only when `P = 3` is in force, and `Other` after a `P = 1` or `P = 2` certification or without one, as pyHanko says (`certify_p{1,2}_doc_timestamp_then_markup`). The other `P = 1` restrictions (ISO 32000-2 §12.8.2.2 Table 257: no changes) do not lower a timestamp's level: under a `P = 1` certification, a document timestamp that a form fill, an `/Info` change or an approval signature follows reports `FormFilling` or `LtaUpdates` with `docmdp_ok` `None`, the level pyHanko reports too (its `DocumentTimestampStatus` has no `docmdp_ok`), and `is_acceptable(FormFilling)` accepts that report. The violation shows in the certification's own `docmdp_ok` (`false`) only, so a caller checks every report (residual below; M4 final fix round 2, finding 3).
   - The report includes the list of changed objects.
   - **Repairs are modifications we cannot attribute:** if `Store::structure_repaired()` is true, or `Store::recovered_objects()` (taken after resolving every object the verifier reads) is not empty, or the newest trailer's `/Root` is not listed in any section after the signed revision while it differs from the signed revision's `/Root`, then `modification = Other` plus a warning naming the repair. Scan-based recovery can show objects that sit after the last `%%EOF` or in no xref section; an xref-based diff would never see them.
   - Revisions are logical sections in `/Prev` order and `eof_end` need not be monotonic (linearized files); step 2 matches `b + c` against the `eof_end` of *any* revision.
11. **DocMDP (V11; `docmdp.rs`).**
   - `docmdp`: the signature's own `/Reference` DocMDP transform (`/P` absent means 2, ISO 32000-2 Table 257), and its field's `/Lock /P` (PDF 2.0, §12.7.5.5 Table 236; R-4), the stricter of the two when both are present, as pyHanko's `docmdp_level`; M3's fallback stays (a `/Perms /DocMDP` naming the dictionary without a reference reads as 2). A declaration that cannot be read (`/Reference` not an array, an entry without `/TransformMethod`, `/P` not 1–3 or not an integer, two DocMDP references, a malformed `/Lock`) is `DocMdpInvalid`, `docmdp` is `None` and **`P = 1`** is in force for the signature and those after it, never 2 (R-6). A DocMDP signature that is not the earliest-ending signed field gets `CertificationNotFirst`. The signing side (`docmdp::certification`) reads the same way and refuses to sign on top of an unreadable declaration.
   - `P_effective` (C2): for a signature that sets its own `P` (a certification or a field lock `/P`, the stricter of the two; 1 for `DocMdpInvalid`), the stricter of that and the `P` already in force, the smallest `P` of the restricting signatures that end at or before it, `min(own P, P in force)` (ISO 32000-2 §12.7.5.5 Table 236: a lock's `/P` "shall specify permissions less than or equal to the permissions already in effect", a greater number is ignored, so a lock `/P 3` never widens a `P = 2` certification; corpus `lock_p3_after_p2_certification_then_markup`, `lock_p3_after_p1_certification_then_markup`); for any other signature, and for a document timestamp, that smallest `P`; else 2. The modification analysis of a signature that sets permissions, and of a document timestamp (R-20), runs with this value, so the annotation rule reads the `P` in force (M4 QA round 4 expert finding 34, round 5 findings 15 and 49).
   - `docmdp_ok` (C3), over the signature's own window: `P = 1` → the classes are within {`Relisting`, `Orphan`, `XrefStream`, `DocTimeStamp`} (D-2: stricter than pyHanko, which also accepts `/Info` and XMP changes); `P = 2` → `modification ≤ FormFilling`; `P = 3` → `modification ≤ Annotations` (D-1); `Other` is never ok. pyHanko computes `not (mod == OTHER or mod.value > P)` (its `ModificationLevel` values against `MDPPerm`); ours equals it wherever pyHanko's vocabulary is reached and is stricter elsewhere. An approval in a `P = 3` document gets `P_effective = 3`, so a later markup annotation is ok for it too (R-7, a recorded D-1 consequence). A **document timestamp** sets no permissions: its `docmdp_ok` is `None`, as pyHanko's `DocumentTimestampStatus` (R-5), and its `modification` is judged with `P_effective` (R-20, step 10), which decides only the markup-annotation rule: the `P` in force keeps a markup annotation after a timestamp at `Other` unless it is 3, but a form fill, metadata change or approval signature after a timestamp under a `P = 1` certification stays `FormFilling` or `LtaUpdates` for the timestamp's report, which `is_acceptable` accepts; only the certification's report refuses it (`docmdp_ok` `false`). Callers check every report (residual below).
12. **`is_acceptable(max)` (V12, D-13):** `is_valid() ∧ modification ≤ max ∧ docmdp_ok ≠ Some(false)`.

**Residuals** (levels below `Other` whose change a viewer can still show; M4 brief §0.3 is the source). Each assumes the bytes read the same in every reader. That is checked for the lexical differentials of step 10 (the canonical-input gate, R-12; the update layout and, since QA round 5, the rebuild-proof checks, R-17, R-18 and R-21, so a reader that rebuilds the cross-reference data finds the same objects; the page tree, R-13; duplicate keys and object-stream defects, R-1; repairs), not for every way two readers can differ:
- `FormFilling`: a filled field shows any text its filler chooses **inside its widget's `/Rect`** (which never moves; the appearance is clipped to its `/BBox`; a field whose signed widget sets NoZoom or NoRotate is not filled at this level), and an opaque one covers the signed page content beneath it, as pyHanko and Acrobat allow. A later signer's visible appearance likewise draws what it likes inside its `/Rect`.
- **JavaScript calculation, format and validation** (QA round 5 finding 8, manager ruling R-23): a signed field's `/AA` `/C`, `/F`, `/V` and `/K` actions, and the AcroForm `/CO` calculation order, run in a JavaScript-capable viewer (Acrobat; not probed) on the filled value, so filling one field can change what another field displays, or how the filled value displays, beyond what F1–F4 compare. pyHanko allows it too; poppler and PDFium run no JavaScript and draw the stored appearances. No precondition is added: this is a residual only.
- **Shared `/Annots` arrays** (QA round 5 finding 9): a later signature widget appended to an indirect `/Annots` array that several pages share shows on each of them, inside its `/Rect` as each page maps it, although its `/P` names one page. A markup annotation added to such an array is `Other` (M4 brief §5.2), so D-1 does not reach this.
- `Annotations` (D-1): a whitelisted markup annotation renders inside its `/Rect` at 100 % zoom in every viewer probed, given canonical numbers within ±10^5 (R-21; R-12: PDFium reads a `/Rect` coordinate of `4294967296` as 0 and paints elsewhere, so such a `/Rect` is `Other`) and a page tree every reader walks the same way (R-13), but there an opaque one can cover signed content: that is what `P = 3` grants. Text is the exception the whitelist narrows: it is allowed only on upright pages, and a viewer that implements its implicit NoZoom draws it unscaled from the `/Rect`'s upper-left corner when zoomed out (M4 brief §0.3).
- **Document timestamps under `P = 1`** (M4 final fix round 2, finding 3): a timestamp's report is judged with the `P` in force for markup annotations only, so a form fill, an `/Info` or XMP change or an approval signature after a document timestamp in a `P = 1` certified document leaves the timestamp's report at `FormFilling` or `LtaUpdates` with `docmdp_ok` `None` (pyHanko's level too), and `is_acceptable(FormFilling)` accepts that report although ISO 32000-2 §12.8.2.2 forbids the change. The certification's own report says `docmdp_ok = false`; a caller that gates on the newest report alone misses it. Making such a timestamp entry `Other` would be stricter than pyHanko and safe; it is left for the M4 decision record (D14).
- Timestamps: unsigned attributes are not signed and `/Contents` is outside the ByteRange, so **anyone can remove or replace the signature timestamp of the last signature in place** (as in pyHanko; LTA covers it in M11). A replacement needs a trusted TSA token over the same signature value, which can only post-date the original; removing it downgrades B-T to B-B; the report says what is there now. `genTime` means something only when `timestamp.trusted == Some(true)`, judged at a validation time the caller gives (the retired-key residual of step 9 otherwise).

```rust
pub struct SignatureReport { pub kind: SignatureKind /* Signature | DocTimeStamp */, pub field_name: Option<String>,
  pub sub_filter: Option<String>, pub intact: bool, pub signature_valid: bool, pub byte_range_ok: bool, pub coverage: Coverage,
  pub modification: ModificationLevel, pub changed_objects: Vec<ObjectId>, pub docmdp: Option<u8>, pub docmdp_ok: Option<bool>,
  pub signer: Option<CertificateInfo>, pub chain: Vec<CertificateInfo>, pub trusted: Option<bool>, pub claimed_time: Option<String>,
  pub timestamp: Option<TimestampInfo> /* the selected token (V7b step 10) */, pub timestamps: Vec<TimestampInfo>,
  pub pades_level: Option<PadesLevel> /* B-B | B-T */, pub problems: Vec<Problem>, pub warnings: Vec<String>, .. }
pub struct TimestampInfo { pub gen_time: String, pub tsa: Option<CertificateInfo>, pub tsa_name: Option<String>, pub policy: Option<String>,
  pub serial_hex: Option<String>, pub accuracy_micros: Option<u64>, pub ordering: bool, pub imprint_algorithm: Option<String>,
  pub signature_algorithm: Option<String>, pub intact: bool, pub valid: bool, pub trusted: Option<bool>,
  pub problems: Vec<Problem>, pub warnings: Vec<String> }
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
  // M2 (implemented; `bindings/node/index.d.ts` documents every member)
  static open(data: Uint8Array, opts?: OpenOptions): PdfDocument;           // sync; copies once into Rust
  static openAsync(data: Uint8Array, opts?: OpenOptions): Promise<PdfDocument>;  // OpenOptions { strict? }
  static create(): PdfDocument;                    // empty PDF 1.7 (Document::new); no version option yet
  get pageCount(): number;  get version(): string /* "1.7" */;  get isModified(): boolean;
  diagnostics(): Diagnostic[];                     // { offset: number | null, kind: DiagnosticKind, message }
  getPage(i: number): PageInfo;                    // { index, width, height, mediaBox, cropBox, rotation }
  getInfo(): DocInfo;  setInfo(update: InfoUpdate): void;   // undefined keeps, null removes; dates: string | Date
  setPageRotation(i: number, deg: number): void;   setPageBox(i: number, box: 'media'|'crop', rect: Rect | null): void;
  save(opts?: SaveOptions): Buffer;               saveAsync(opts?: SaveOptions): Promise<Buffer>;
  saveIncremental(opts?: { suffixOnly?: boolean; deterministic?: boolean; id1?: Uint8Array }): Buffer;
  saveIncrementalAsync(opts?: IncrementalSaveOptions): Promise<Buffer>;
  close(): void;  [Symbol.dispose](): void;        // frees the native memory now; then E_CLOSED
  get isClosed(): boolean;  get nativeMemory(): number;   // bytes reported to V8 (0 once closed)
  get isEncrypted(): boolean;                      // M5, with encryption
  // pages (M5) — 0-based indices
  getPage(i: number): PageInfo; insertBlankPage(at: number, size?: Size): void; deletePages(idx: number[]): void;
  movePage(from: number, to: number): void; rotatePage(i: number, deg: 0|90|180|270): void;
  importPages(src: PdfDocument, indices: number[], at?: number): void;
  // signatures (M3 and M4, implemented; `index.d.ts` documents every member)
  prepareSignature(o: PrepareSignatureOptions): PreparedSignature;            // E_BUSY rule as for every sync method
  prepareSignatureAsync(o: PrepareSignatureOptions): Promise<PreparedSignature>;
  verifySignatures(o?: VerifyOptions): Promise<SignatureReport[]>;            // async only; validationTime default now
  // info/metadata, outlines, forms, annots … added per milestone
}
// PrepareSignatureOptions { certificateChain: Uint8Array[] (DER or PEM text); algorithm: SigAlg; digest?: DigestAlg;
//   signingTime?: Date | string (default now); field?: { name?, page?, mode?: FieldMode }; subFilter?: SubFilter;
//   name?, reason?, location?, contactInfo?: string; contentsReserve?: number;
//   certify?: DocMdpLevel (1 | 2 | 3); appearance?: SignatureAppearanceOptions; tsaReserve?: number }   // M4
// SignatureAppearanceOptions { rect?: [llx, lly, urx, ury] | Rect; lines?: string[]; font?: 'Helvetica' | 'Helvetica-Bold';
//   fontSize?: number; image?: Uint8Array (JPEG); imagePosition?: 'left' | 'background'; borderWidth?: number }
// VerifyOptions { trustAnchors?: Uint8Array[]; extraCertificates?: Uint8Array[]; validationTime?: Date | string | null;
//   timestampTrustAnchors?: Uint8Array[] /* M4; default trustAnchors */ }
// SignatureReport (M4) += timestamp: TimestampInfo | null; timestamps: TimestampInfo[]; padesLevel 'B-B' | 'B-T';
//   docmdp; docmdpOk (always computed, D13 D-13). TimestampInfo { genTime, tsa, tsaName, policy, serialHex,
//   accuracyMicros, ordering, imprintAlgorithm, signatureAlgorithm, intact, valid, trusted, problems, warnings }
export class PreparedSignature {                // #[napi] class; Arc<Mutex<Slot>> holds Option<core::PreparedSignature>
  readonly toBeSigned: Buffer; readonly toBeSignedDigest: Buffer; readonly toBeSignedDigestInfo: Buffer;
  readonly digestAlgorithm: DigestAlg; readonly algorithm: SigAlg; readonly subFilter: SubFilter;
  readonly contentsCapacity: number; readonly byteRange: number[]; readonly warnings: string[]; readonly isFinished: boolean;
  timestampRequest(signature: Uint8Array, o?: TimestampRequestOptions): Buffer;   // M4; remembered in the slot
  discardTimestampRequest(): void;                // M4 QA round 1: finish without a remembered request's response
  finish(signature: Uint8Array, timestampResponse?: Uint8Array, timestampRequest?: Uint8Array): Buffer;
  finishAsync(signature: Uint8Array, timestampResponse?: Uint8Array, timestampRequest?: Uint8Array): Promise<Buffer>;
  embedCms(cms: Uint8Array): Buffer; embedCmsAsync(cms: Uint8Array): Promise<Buffer>;
  serialize(): Buffer; static deserialize(b: Uint8Array): PreparedSignature;   // the core's versioned `FXPS` form
}
// TimestampRequestOptions { digest?: DigestAlg; policy?: string /* dotted OID */; nonce?: bigint /* default random */ }
export class LocalSigner { static fromPkcs12(p12: Uint8Array, password: string | Uint8Array): LocalSigner;
  static fromPem(keyPem: string | Uint8Array, certsPem: string | Uint8Array, keyPassword?: string | Uint8Array): LocalSigner;
  readonly certificateChain: Buffer[]; readonly algorithm: SigAlg; readonly defaultDigest: DigestAlg;
  sign(tbs: Uint8Array, digest?: DigestAlg): Buffer; signAsync(tbs: Uint8Array, digest?: DigestAlg): Promise<Buffer>;
  close(): void; [Symbol.dispose](): void; readonly isClosed: boolean; }   // close wipes the key; then E_CLOSED
export interface ExternalSigner { certificateChain: Uint8Array[]; algorithm: SigAlg; digest?: DigestAlg;
  sign(toBeSigned: Buffer, toBeSignedDigest: Buffer, digestAlgorithm: DigestAlg):
    Promise<Uint8Array | ArrayBuffer> | Uint8Array | ArrayBuffer; }      // ECDSA: DER or IEEE P1363
// Hand-written facade (index.js), composes async callbacks in JS — no ThreadsafeFunction needed:
export type TimestampCallback = (request: Buffer) => Promise<Uint8Array | ArrayBuffer> | Uint8Array | ArrayBuffer;
export function signPdf(doc: PdfDocument, opts: Omit<PrepareSignatureOptions, 'certificateChain'|'algorithm'> &
  { signer: LocalSigner | ExternalSigner; timestamp?: TimestampCallback /* M4: the caller POSTs to its TSA */;
    timestampOptions?: TimestampRequestOptions }): Promise<Buffer>;
```

### Design rules
- **Buffers:**
  - Input is taken as `Uint8Array` (a `Buffer` is one) and copied once, into the `Vec<u8>` that `Document::open` wraps in its `SharedBytes` (no second copy). This is unavoidable because the document outlives the call and async tasks need `Send` data; `openAsync` copies before it returns, so the caller may reuse the buffer at once.
  - Output is `Buffer::from(Vec<u8>)`, which hands ownership over without a copy.
  - Note: Electron's V8 sandbox disallows external buffers. Verify napi-rs's fallback if Electron is ever a target.
- **Threading:**
  - `#[napi(custom_finalize)] struct PdfDocument { shared: Arc<Shared> }` with `Shared { doc: Mutex<Option<folioxide::Document>>, pending: AtomicUsize, closed: AtomicBool, reported: AtomicI64 }` (see "Native memory").
  - Heavy operations (open, save, sign, verify, optimize, flatten, render) get an `…Async` variant that returns `AsyncTask<T>`. `Task::compute` runs on the libuv pool on a clone of the `Arc` and locks there (waiting is fine on the pool: two async operations on one document run one after the other).
  - Sync methods (getters included) never wait: they throw `E_BUSY` while an async operation has the document, then `try_lock()`. "Has the document" counts from the `…Async` call (a `Pending` guard increments `pending` on the JS thread and is dropped right after `compute` has done its work, or with the task if it never ran), not from when the pool takes the lock, so a sync call right after `saveAsync()` is refused deterministically instead of racing the pool (an edit made then would or would not be in the saved bytes). A poisoned lock is taken over (the core never panics on its data).
  - Core `Document: Send + Sync`, asserted at compile time in a test.
- **Native memory:**
  - The JS object is tiny while the document holds the file and everything read from it (a 20 MB file with 300k objects holds about 85 MB). Unreported, V8 never collects such objects in time and RSS grows without bound (M2 QA). So the binding reports the core's estimate, `Store::memory_estimate()` (source bytes, xref index, the objects cached so far, the object-stream cache, a repaired file's scan, the edits; `O(1)`, kept up to date as objects are parsed and edits made), with `Env::adjust_external_memory`: on `open`, `openAsync` (in `resolve`) and `create`, and again after every sync method and when an async save resolves (reading pages and saving grow it). `nativeMemory` returns the amount reported.
  - `#[napi(custom_finalize)]`: the finalizer gives the amount back and closes the document. Node runs native finalizers from the event loop only, so a loop that never yields keeps every document until it does: `close()` (and `[Symbol.dispose]` in the facade, for `using`) gives the memory back and drops the `Document` at once, or, when async tasks are pending, when the last one ends (`Shared { doc: Mutex<Option<Document>>, closed, reported, .. }`; the last `Pending` to drop after `closed` drops the document). Afterwards every method throws `E_CLOSED` (binding-only, like `E_BUSY`); an async save already started resolves normally.
  - **Contract (M2 QA):** bounded memory in long-running loops **requires** `close()` or `using`. Relying on GC alone can let RSS grow for hundreds of iterations even when the loop yields, because finalizers run late and glibc returns memory late. Future bulk APIs (merge, split, batch signing) should default to close-friendly patterns.
- **Errors:**
  - `napi::Error::new(format!("E_{code}"), msg)` sets the JS `err.code`. `#[napi]` functions return `Result<T, BindingError>` (`napi::Error<String>`), spelled out: the macro recognizes a fallible function by the name `Result`, not through an alias. Messages are the core error's `Display`, cut to 1 KiB.
  - `napi::Task` errors carry a `napi::Status`, which cannot hold an `E_*` code. A task's `Output` is therefore the core `Result`, and `resolve` (on the JS thread) builds the JS error object with its code and rejects with a reference to it (`napi::Error::from(Unknown)`): the promise rejects with that very object.
  - The facade (`index.js`, a JS class wrapping the native object in a private field) turns every error into a `FolioxideError extends Error` with `.code`, the native error as `.cause` and optional `.details`, for example `{needed}` on placeholder overflow. napi-rs's own argument-conversion errors (status `InvalidArg`, `NumberExpected`, …) become `E_INVALID_ARGUMENT` with `details.status`; the facade checks argument types first, so they are rare. All codes, plus `E_BUSY` and `E_CLOSED`, are exported as the TS string-literal union `ErrorCode`; a Rust unit test checks `index.d.ts` lists every `ErrorCode::ALL` (and every `DiagnosticKind::ALL` in the `DiagnosticKind` union).
- **DTOs:**
  - Mirror the core DTOs as `#[napi(object)]` structs with `From` conversions, so the generated TS types are precise.
  - Field names are camelCase, identical to the core's `serde(rename_all = "camelCase")`, and values have the core's serde representation (dates as PDF date strings, rotation in degrees, absent `DocInfo` entries left out; `Diagnostic` is `use_nullable`, so `offset` is `null` as in serde). Node and Tauri therefore see the same JSON shape. Unit tests derive `Serialize` on the binding DTOs under `cfg(test)`, mirroring napi-rs's conversion, and compare their JSON with the core's.
  - `InfoUpdate` fields are `Option<Either<T, Null>>`: absent or `undefined` keeps, `null` removes, a value sets. The facade converts `Date` values to PDF date strings (UTC) first; `toPdfDate` and `fromPdfDate` (native `pdfDateToIso`) convert in both directions.
  - Enums use `#[napi(string_enum)]`, emitted as type-only string-literal unions (`"constEnum": false` in `package.json`; a TS `const enum` would not accept the literal `'media'`). Input strings are parsed by the binding, so a wrong value is `E_INVALID_ARGUMENT` listing the accepted ones (`#[napi(ts_type)]` / `ts_arg_type` keep the precise type).
  - Option objects are input only: `SaveOptions` takes `minVersion` as a version string (`"1.7"`, like the `version` getter) and `id` as two byte arrays, where the core's serde form has a pair of numbers and arrays of numbers.
- **Signing (M3):**
  - `signPdf` (hand-written in `index.js`) is `await doc.prepareSignatureAsync(…)` (the core's `prepare` on the libuv pool), then `await signer.sign(toBeSigned, toBeSignedDigest, digestAlgorithm)` on the JavaScript side (a `LocalSigner` uses `signAsync`), then `prepared.finishAsync(signature)`. The signer is awaited in JavaScript, so no ThreadsafeFunction is needed. When `prepareSignatureAsync` throws `E_SIGNATURE_PLACEHOLDER_TOO_SMALL` because of an explicit `contentsReserve`, it prepares once more with `details.needed`. An external signer's own error becomes `E_CRYPTO` with the error as `cause` (its message is not repeated: it could quote what the signer was given); a returned `ArrayBuffer` (WebCrypto) is accepted.
  - `PreparedSignature` is a `#[napi(custom_finalize)]` class holding a `Slot { prepared: Option<core::PreparedSignature>, in_flight, finished, reported }` behind `Arc<Mutex<…>>` (locked on the JavaScript thread only) and copies of the small fields. Finishing goes through the core's `try_finish` / `try_embed_cms`, which return the prepared signature with the error (`FinishError`): a refused value or CMS goes back into the slot, so the caller can try again; the first finish that **succeeds** takes the value, and later finishing calls and `serialize` throw `E_INVALID_ARGUMENT`; the getters keep working. `finishAsync` / `embedCmsAsync` move the value into the task at the call (`in_flight`: the other finishing methods and `serialize` throw `E_BUSY`), and the task's `resolve` puts a refused value back. The prepared file (a full copy of the output) is reported to V8 as external memory until a finish succeeds or the object is finalized.
  - `LocalSigner` holds `Option<Arc<core::LocalSigner>>`; `close()` (and `[Symbol.dispose]`) drops it, which wipes the key (RustCrypto key types zeroize on drop), or, while a `signAsync` task holds a reference, when that task ends; afterwards methods throw `E_CLOSED`. Passwords and PEM keys are taken as `string | Uint8Array`: the binding's `String` copy is `Zeroizing`, bytes are read in place so the caller can wipe them; JavaScript strings cannot be wiped (documented next to the RSA advisory).
  - `prepareSignatureAsync` and `verifySignatures` are document tasks like `saveAsync` (a `Pending` guard from the call: `E_BUSY` for sync methods, `E_CLOSED` once closed). `verifySignatures` is asynchronous only; the facade passes `validationTime: new Date()` unless the caller gives one (`null`: the core's default, the signer's claimed time, with a warning), so trust agrees with pyHanko's "now".
  - Certificates (`certificateChain`, `trustAnchors`, `extraCertificates`) are DER, or PEM text (one or more `CERTIFICATE` blocks in one `Uint8Array`, recognised by `-----BEGIN`); `LocalSigner.fromPem` takes strings or bytes.
  - Dates (`signingTime`, `validationTime`) are `Date` (formatted in UTC by `toPdfDate`) or strings parsed by `PdfDate::parse` (PDF dates, and the ISO 8601 form).
- **Signing II (M4: B-T, certification, visible; M4 brief §3.5):**
  - **B-T without a ThreadsafeFunction.** The TSA is asynchronous in Node, so the binding exposes the core's two-phase flow and the facade awaits the TSA in JavaScript, as it awaits the signer. `signPdf` with `timestamp` is: `prepareSignatureAsync` with `tsaReserve ?? 8192`; `await signer.sign(…)`; `prepared.timestampRequest(sig, timestampOptions)` (the core's `timestamp_request`, which verifies and normalizes the value first: the imprint covers the DER value that is embedded); `await timestamp(request)`; `prepared.finishAsync(sig, response, request)` (the core's `try_finish_with_timestamp`, so a refused response goes back into the slot like a refused value). A callback that throws becomes `E_TIMESTAMP_INVALID` with the error as `cause` (its message is not repeated); an `ArrayBuffer` is accepted. On `E_SIGNATURE_PLACEHOLDER_TOO_SMALL` from that finish, the facade redoes every step **once** with `contentsReserve: details.needed + 1024` (`DEFAULT_TSA_RESERVE` and `TSA_RETRY_MARGIN` in `index.js` equal the core's constants, a Rust test checks it): the signer and the callback may each be called twice (documented).
  - **The slot remembers the request.** `timestampRequest` stores the DER request in the `PreparedSignature`'s `Slot` (it reads the core value, so it is `E_BUSY` while a `finishAsync` runs and `E_INVALID_ARGUMENT` once finished); `finish(sig, response)` uses it, `finish(sig, response, request)` an explicit one. While a request is remembered, `finish(sig)` without a response is `E_INVALID_ARGUMENT` (M4 QA round 1 finding 1: a forgotten response must not silently give a B-B file); `discardTimestampRequest()` forgets the request to finish without a timestamp on purpose. The core `PreparedSignature` stays stateless and the FXPS form unchanged, so a deserialized object remembers no request (`E_INVALID_ARGUMENT` until one is passed). A successful finish forgets it. `signPdf` hands the `timestamp` callback a copy of the request (finding 2), so a callback that wipes or reuses its buffer cannot change the request the response is checked against.
  - **Options.** `certify` (an integer 1–3, else `E_INVALID_ARGUMENT`) is `SignatureOptions::certification`; the certification rules are the core's (`E_DOC_MDP_FORBIDS`, the message naming the rule). `appearance` is `SignatureAppearanceOptions`: the facade turns a `[llx, lly, urx, ury]` tuple into a `Rect` and checks types; the binding refuses non-finite numbers, a non-positive font size, a negative border width and unknown font or image-position names (`E_INVALID_ARGUMENT`); the core checks the rectangle against the page and the JPEG (`E_INVALID_ARGUMENT`, `E_IMAGE`, `E_UNSUPPORTED`). The nonce is a `bigint` (`napi::BigInt`, lossless 1 to 2^64 − 1, a positive INTEGER as brief §4.1 says, so 0 is `E_INVALID_ARGUMENT`, R-24; the facade also takes a positive safe integer).
  - **Report.** `TimestampInfo` is a `#[napi(object, use_nullable = true)]` mirror of the core DTO (`accuracyMicros` a number, `null` above `Number.MAX_SAFE_INTEGER` rather than a rounded value, R-24); `SignatureReport` gains `timestamp` and `timestamps`, and `padesLevel` `'B-T'`. `SignatureProblem.code` is typed by a type-only `#[napi(string_enum)] ProblemCode` listing the core's codes, so `binding.d.ts` and `index.d.ts` agree exactly (`Equal<binding.SignatureReport, SignatureReport>`, `Equal<binding.TimestampInfo, TimestampInfo>`; a Rust test checks the generated union lists exactly `ProblemCode::ALL`). The Rust JSON test now compares the whole report, timestamps included, with the core's serde form.
  - **`isSignatureAcceptable`** mirrors the core's `is_acceptable` (D13 D-13): it also requires `docmdpOk !== false`, which is now computed for every signature (with `P = 2` when none set permissions; `null` for a document timestamp, R-5), so a change that is `'other'` is refused at every `maxModification`.
  - `E_SIGNATURE_PLACEHOLDER_TOO_SMALL` gets `details = { needed, reserved }`, parsed by the facade from the core's fixed `Display` text.
  - The report DTOs (`SignatureReport`, `CertificateInfo`, `KeyDescription`, `ObjectRef` `{num, gen}`, `SignatureProblem` `{code, message}`) are `#[napi(object, use_nullable = true)]` mirrors: `null` where the core's serde writes `null`, enum values from the core's `as_str()` (`'entireFile'`, `'formFilling'`, `'B-B'`, `'digestMismatch'`, …; type-only `#[napi(string_enum)]` unions name them in `binding.d.ts`), and the certificate `der` as a `Buffer` (an array of numbers in serde). A Rust test compares their JSON with the core's, and one checks `index.d.ts` lists every `ProblemCode::ALL` and report enum value.
- **Type tests:** `tsc --noEmit -p test` on `test/types.test-d.ts`, with `@types/node` (for `Buffer`). They also check the generated `binding.d.ts` agrees with the hand-written `index.d.ts` (`Equal<binding.PageInfo, PageInfo>`, `Equal<binding.CertificateInfo, CertificateInfo>` and so on).
- **Runtime tests:** Node 22's built-in runner, `node --test "test/**/*.test.mjs"`, with `.mjs` files so no TypeScript toolchain is needed at runtime: `open-save.test.mjs` and `errors.test.mjs` run on the committed `fixtures/syntax/*.pdf` (helpers in `test/helpers.mjs`); `sign.test.mjs` signs with the `fixtures/pki` keys (PKCS#12 modern and legacy, PEM, external signers on `node:crypto` and WebCrypto) and checks every signed output with the signature oracles (`tools/oracles/validate_sig.py` for pyHanko and pdfsig, `extract_cms.py --verify` for OpenSSL) when `.venv` exists, skipping them otherwise. M4 adds `sign-bt.test.mjs` (the TSA is `test/helpers/mock-tsa.mjs`, a pure JavaScript mock with its own DER writer and `node:crypto` RSA over `tsa.key.pem`, independent of the Rust code; `openssl ts -reply -config tools/tsa/openssl-tsa.cnf` is an extra TSA when OpenSSL is installed), `certify.test.mjs` and `visible.test.mjs`; their outputs are checked by pyHanko (timestamp validity with the test root as TSA anchor, DocMDP level and verdict) and by `openssl ts -verify` of each token over its signature value (`test/helpers/oracle.mjs`).

## A.8 Tauri readiness (what the core does now)
1. No napi, Node or Tauri types in any `crates/*` crate. CI checks `cargo tree -p folioxide -e normal | grep -E 'napi|tauri'` is empty.
2. `Document`, `PreparedSignature` and all DTOs are `Send + Sync + 'static`. No `Rc`/`RefCell` in the core; laziness uses `OnceLock`.
3. No global mutable state. Standard-14 metrics are `static` tables only.
4. Every DTO derives `Serialize`/`Deserialize` behind the `serde` feature (`folioxide-syntax` and `folioxide-model` each have one; the facade's `serde` feature turns them on), uses camelCase field names, and is versioned through `#[non_exhaustive]` (every DTO struct; the closed enums `Rotation` and `Trapped`, whose values the standard fixes, are not). `ErrorCode` serializes as its SCREAMING_SNAKE_CASE name (`"PAGE_OUT_OF_RANGE"`), and `ErrorDto { code, message, details }` will be the Tauri command error (not written yet). The M2 shapes, which the Node binding's objects mirror (tests `crates/folioxide-model/tests/serde_dto.rs`):
   - `Rotation` is its number of degrees, `0`, `90`, `180` or `270`. Deserializing accepts any multiple of 90 and normalizes it (`-90` is `270`, `450` is `90`); anything else is an error.
   - `Rect` is `{ "llx", "lly", "urx", "ury" }`; deserializing normalizes the corners like `Rect::new`.
   - `PdfDate` is its PDF date string (`PdfDate::to_pdf_string`), for example `"D:20240229133005+05'30'"` or `"D:20261010120000Z"`, not an RFC 3339 string or a number; deserializing parses it as leniently as a date in a file (`PdfDate::parse`: partial dates, no `D:`, a missing apostrophe).
   - `Trapped` is lower case: `"true"`, `"false"` or `"unknown"` (the PDF names are `/True`, `/False`, `/Unknown`).
   - `DocInfo` is `{ "title", "author", "subject", "keywords", "creator", "producer", "creationDate", "modDate", "trapped", "custom" }`: an absent entry is left out (not `null`), and `custom` maps other keys to their text.
   - `InfoUpdate` has **three states** per field (`Option<Option<T>>`): the field absent keeps the entry, `null` removes it, a value sets it. `custom` maps a key to a string (set) or `null` (remove), and is left out when empty. An empty object `{}` changes nothing.
   - `PageInfo` is `{ "index", "width", "height", "mediaBox", "cropBox", "rotation" }`: `width` and `height` are the size as displayed (the crop box, swapped for 90 and 270 degrees), the boxes are `Rect`s, `rotation` is degrees. The oracle suite `model` compares this JSON with `pdfinfo -box` page by page (expect key `boxes`).
   - `Diagnostic` is `{ "offset", "kind", "message" }`.
5. Bytes in, bytes out. Path helpers live only behind `std-fs`. `Document::incremental_suffix()` (and `Store::incremental_suffix()`) lets Tauri append to the open file without rewriting it.
6. No clock, RNG or network inside the core (A.4). A sync `Signer` trait means Tauri can wrap the OS keychain or PKCS#11 later.
7. Long operations take an optional `&dyn Fn(Progress) -> ControlFlow<()>` for progress and cancellation (Tauri can emit events). It is ignored by default.
8. Later, Tauri TS types come from `specta` or `ts-rs` on the same DTOs. Nothing is needed now beyond keeping DTOs plain (no lifetimes, no RustCrypto types).

## A.9 Testing strategy

### Layers
1. **Unit tests** in each module: lexer tokens (§7.2), every filter, every encryption algorithm against spec test vectors and pikepdf-generated files, ASN.1 encoders with golden DER.
2. **Integration tests** (`crates/*/tests/*.rs`): round trips such as open → modify → save → reopen → deep-equal.
3. **Property tests** (`proptest`):
   - arbitrary `Object` trees serialize and parse back to equality
   - random byte mutations of valid fixtures never panic (`no_panic_on_mutated_input`, a stable-toolchain stand-in for fuzzing), with a per-mutation time budget and a peak-memory ceiling
   - resource exhaustion at the **default** limits: `folioxide_testkit::fixtures::hostile` builds files that amplify work or memory (`/Prev` chains of compressed xref streams, overlapping sections, outsized `/Index`, object-stream bombs on the reconstruction path and in the cache, object-stream headers with millions of members, a huge array in an object stream, unterminated trailers), and `tests/hostile_default_limits.rs` bounds the work deterministically (rows, sections, objects kept, `Store::total_decoded`), in time (`budget::within`) and in peak RSS (each test runs in a process of its own, under a ceiling of its own). Small instances of every shape are committed in `fixtures/hostile/` as fuzz seeds
   - incremental save always keeps the prefix
4. **Fuzzing** (`fuzz/`, cargo-fuzz on nightly in CI): targets `fuzz_lexer`, `fuzz_parse_document` (open plus resolve all objects plus page count; reduced decoding limits) and `fuzz_parse_document_default_limits` (the same with `Limits::default()`; both with a per-input work budget and a hang watchdog), `fuzz_filters`, `fuzz_content_stream`, `fuzz_cms_parse`, `fuzz_xmp`. Seed corpus is `fixtures/` plus testkit output. Corpora and crash artifacts are not committed. **Verify that nightly is installable in CI**, since only stable 1.97 is installed locally.
5. **Golden tests:** deterministic save mode, so tests can compare bytes for writer output (plus `insta`, if adopted; its version is not verified).
6. **Node tests:** `node --test` covering the API surface, error codes, async variants, and the TSA/KMS callbacks with a JS mock.

### Fixtures policy
- **Generate everything we can.**
  - `folioxide-testkit` builds PDFs at byte level, including deliberately broken ones: wrong xref offsets, `/Prev` loops, junk before the header, wrong `/Length`, truncated Flate, hybrid files.
  - `tools/fixtures/*.py` uses pikepdf/pypdf to make encrypted files (R2, R3, R4 with RC4 or AES, R6), object-stream and linearized files, and forms.
  - All of this is reproducible with `cargo xtask fixtures`.
- **Commit small generated files** (each < 200 KB) so `cargo test` needs no Python. `fixtures/README.md` lists each file's generator and license ("generated by this project, MIT").
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
| 10 | Page tree | Inheritable `/Resources`, `/MediaBox`, `/CropBox`, `/Rotate`; `/Count` wrong; cycles (each `/Pages` node is walked once); a page listed twice (a page at each listing, as poppler, pypdf and qpdf count it); `/Parent` not the listing node (inherit along the walk, as poppler does; pdf.js, and qpdf for `/CropBox` and `/Rotate`, follow `/Parent`, so the setters consult both); `/Rotate` not a multiple of 90; missing MediaBox (default to Letter + diagnostic) | §7.7.3.3–4 | Materialize inherited attributes on import, split and extract. Tests `inherited_resources_materialized_on_extract`, `page_tree_cycle` |
| 11 | Page ops | Dangling `/Dest` and outline entries after deletion; `/Annots /P`; AcroForm field name collisions on merge; StructTreeRoot (tagged PDF) not mergeable in v1 | §12.3.2, §14.7 | Prune dests to Null. Rename `name#2`. Strip structure on import and document it |
| 12 | Incremental | Original lacks a final EOL; previous revision used an xref stream; hybrid; `/ID[0]` must stay; linearized files (appending is fine but linearization becomes invalid, which is OK); junk before the header (offsets may count from the header or from byte 0); a repaired structure; objects away from their xref offsets; a new object taking the number of a dangling reference | §7.5.6, §7.3.10, Annex H | Same xref kind as before. Append after `source.len()`, never after an `eof_end`. Write `/Prev` and new offsets in `Store::offset_base()` (header-relative + `header_offset` for `Absolute`). Refuse an incremental save of a store whose `structure_repaired()` is true (full save first). **`OffsetBase::Absolute` files are full-save-only in practice:** the store finds their newest section only at its offset counted from byte 0, which is a structure repair (`structure_repaired()`; other readers count from the header and reconstruct), so `check_incremental` refuses them; the writer's conversion for `Absolute` stays general (test `offsets_follow_the_files_offset_base`). Refuse too when an in-use object is not at its entry's offset (`check_incremental`; qpdf and poppler reconstruct such a file: poppler lost the update's `/Info` in the writer oracle suite). New objects are numbered above every listed number and every number a source object refers to (`next_object_number`), so a dangling reference keeps meaning `null`. Tests `incremental_prefix_preserved_all_fixtures`, `incremental_updates_chain_on_every_fixture`, `next_object_number_is_above_every_listed_number`, `add_never_takes_the_number_of_a_dangling_reference` |
| 13 | Signatures | Placeholder overflow (TSA tokens and long chains); ByteRange width changes the file; signing over `[0x31]`-retagged attrs; ESSCertIDv2 DEFAULT omission; ECDSA raw vs DER; sig dict in an ObjStm or a compressed stream; Contents encrypted; certification not first; signing a `P=1` doc; junk before the header (`/ByteRange` is file-absolute, §12.8.1, while xref offsets count from the header) | §12.8.1, RFC 5652 §5.4, RFC 5035 | A.6. `sign()` refuses an incremental signature when `header_offset > 0` or `structure_repaired()` (proposed: a full save first, which drops the junk). Tests `placeholder_overflow_retries`, `ecdsa_p1363_accepted`, `certify_twice_rejected` |
| 14 | Verification | ByteRange gap not matching the actual `/Contents` (wrapping attack); multiple sig dicts sharing ranges; trailing garbage after `%%EOF` (incremental "shadow" attacks); hybrid table vs `/XRefStm` differentials; xref-stream entries of unknown type (null, §7.5.8.3); objects found only by scan-based recovery; content hidden behind a short or wrong `/Length` (or a missing `endstream`/`endobj`) in a later revision (Mladenov et al. shadow attacks); an appended update whose own `startxref` is damaged; with a damaged last `startxref`, object definitions that no xref section lists or that come after the definition (or deletion) the earlier chain takes, which reconstructing readers (qpdf, pdf.js, poppler) show; an update with no `startxref` at all (a save cut short, or content appended after the signed revision) | — | A.6.7 steps 2 and 8: changed set = table ∪ `/XRefStm` incl. free/null entries (`Store::revision_entries`); `structure_repaired()` / `recovered_objects()` (location repairs and object-level `/Length`/`endstream`/`endobj`/generation repairs) → `Other` + warning. An earlier `startxref` is used only when its chain shows what a reconstruction shows (`Store::shadowed_definition`), otherwise the file is reconstructed (last definition wins). Data after the last revision is `UnreferencedUpdate` (a repair); reconstructed as qpdf does when the last `startxref` is more than 1054 bytes before the end. Header-like text that is no definition (comments, mid-line, inside an object that parses) never makes a valid chain reconstructed, and another generation never shadows. **Deliberate differences** (measured with qpdf 12.4.2 / pikepdf 10.16): a header at the start of a line inside an object that parses (in a string inside an array or a dictionary, in a string that does not start a line or whose first line is longer than 10 bytes, or in stream data) is text here, so with a damaged last `startxref` a valid chain keeps its object and the object holding the text reads whole, and a reconstruction does not take it either; qpdf, whose rebuild takes every line-start header except one swallowed by a top-level string token at the start of a line (its 10-byte token cut), and pdf.js (by its source) take those headers in damaged files and show the text's object (tests `header_text_never_shadows_a_valid_chain`, `damaged_objects_never_let_header_text_after_them_shadow_a_valid_chain`, `an_object_after_damaged_objects_reads_whole`). They agree for comments, mid-line text, a string token at the start of a line, other generations, and a header at the top level after damaged objects (`a_definition_after_damaged_objects_still_shadows_a_valid_chain`). Headers inside what a damaged object's parse read (the first 4 KiB of a string that never closes, a hexadecimal string up to its first invalid byte, an array up to the nesting limit) are definitions taken unparsed, as qpdf takes them, and count like any other: they can make a valid chain reconstructed, and they bound the region of the object before them (`headers_inside_a_damaged_object_count_as_qpdf_counts_them`). Two differences remain there: an object that holds such a header reads only up to it (null when that cuts it), where qpdf, which does not bound an object by the next header, reads it whole; and qpdf's 10-byte first-token cut is not copied (a top-level string token at the start of a line swallows the headers on its following lines in qpdf's line scan): a header inside such a string, in a stretch that a damaged object read, is a definition here and not in qpdf (probes `Q_unterminated_*`, `R4_unterm40_str_*`: 5 reads "evil" here, "good" in qpdf). Parser leniency: a container interrupted by an object keyword is closed there (`<< /A (x) 5 0 obj … /B 1 >>` reads as `<< /A (x) >>`, `[ 1 2 5 0 obj (evil) endobj ]` as `[1 2 5 0]`), while qpdf skips the stray tokens and keeps reading the dictionary (`/B` too) or reads the array as null; a value read skips an invalid character in a hexadecimal string with a diagnostic (§7.3.4.3 allows only hexadecimal digits and white-space; `<41 42 zz 43>` reads as `(ABC)`), while qpdf ends the token there as bad: the object `<41 42 zz 43>` reads as null, `<< /A <41 42 zz 43> /B 1 >>` as `<< /B 1 >>` and `[ <41zz42> 1 2 ]` as an array of 5 (here `(ABC)`, `<< /A (ABC) /B 1 >>`, `[(AB) 1 2]`; probes `V5I_hexinvalid`, `L7_hex_invalid`). The coverage parses of `repair::definitions` end a hexadecimal string at its first invalid byte, as qpdf does, while value reads stay lenient: read leniently there, one stray character ran the string on to the next `>` anywhere in the file, the parse succeeded, and every top-level header in between was text, which hid an orphan redefinition after the damaged object (probe `P13_hexswallow`: `7 0 obj <41 zz`, then 6 and an orphan `5 0 obj`; with a damaged last `startxref` or no cross-reference data, 5 now reads "orphan" and 6 "six", as in qpdf; test `a_hex_string_with_an_invalid_byte_hides_no_definition_after_it`). **Accepted differential:** a number deleted in a later revision *after* its last on-disk definition keeps the chain and stays deleted (null), while qpdf, pdf.js and poppler reconstruct a file with a damaged last `startxref` and show the old definition again if something still references it (the store follows the revisions; the manager records the decision in DECISIONS.md). Tests `an_appended_update_with_a_bad_startxref_is_not_hidden`, `an_earlier_chain_that_hides_a_definition_is_not_used`, `header_text_never_shadows_a_valid_chain`, `a_definition_after_damaged_objects_still_shadows_a_valid_chain`, `headers_inside_a_damaged_object_count_as_qpdf_counts_them`, `a_reconstruction_keys_objects_by_number_and_generation`, `an_update_that_no_startxref_leads_to_is_reported`, `concatenated_files_read_as_qpdf_reads_them` |
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


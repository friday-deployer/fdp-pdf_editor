# folioxide

Folioxide is a PDF editing engine written in pure Rust, packaged for Node.js as a native
[napi-rs](https://napi.rs) addon. It is built for PDF signing (PAdES), page and document operations,
annotations and forms, and content editing. It has no C or C++ PDF dependencies.

> **Status: pre-alpha.** This release opens, inspects and saves PDF documents: page sizes, boxes and
> rotation, the document information dictionary, full saves and incremental updates that keep the
> original bytes. Signing, encryption and page operations come in later releases. The API will
> change without notice until 1.0.

## Install

```sh
npm install folioxide
```

Node.js 20 or later is required. npm installs the prebuilt native addon for your platform from one
of the optional `@folioxide/binding-<platform>` packages, so no Rust toolchain is needed:

| Platform | Package |
|---|---|
| Linux x64 (glibc) | `@folioxide/binding-linux-x64-gnu` |
| Linux arm64 (glibc) | `@folioxide/binding-linux-arm64-gnu` |
| Linux x64 (musl) | `@folioxide/binding-linux-x64-musl` |
| Linux arm64 (musl) | `@folioxide/binding-linux-arm64-musl` |
| macOS x64 | `@folioxide/binding-darwin-x64` |
| macOS arm64 | `@folioxide/binding-darwin-arm64` |
| Windows x64 | `@folioxide/binding-win32-x64-msvc` |
| Windows arm64 | `@folioxide/binding-win32-arm64-msvc` |

## Usage

The package ships CommonJS and ES module entry points with TypeScript declarations (`index.d.ts`
documents every type; TypeScript users need `@types/node` for `Buffer`).

```js
import { readFile, writeFile } from 'node:fs/promises'
import { PdfDocument } from 'folioxide'

const doc = await PdfDocument.openAsync(await readFile('in.pdf'))
console.log(doc.pageCount, doc.version) // 3 "1.7"
console.log(doc.getPage(0))
// { index: 0, width: 612, height: 792,
//   mediaBox: { llx: 0, lly: 0, urx: 612, ury: 792 }, cropBox: { ... }, rotation: 0 }
console.log(doc.getInfo()) // { title: 'Annual report', creationDate: 'D:20260101120000Z', custom: {} }

doc.setInfo({ title: 'Отчёт 2026', author: null, modDate: new Date() })
doc.setPageRotation(0, 90)

// Append the changes to the original bytes (they stay untouched: signatures remain valid) ...
await writeFile('updated.pdf', await doc.saveIncrementalAsync())
// ... or write the whole file again.
await writeFile('rewritten.pdf', await doc.saveAsync({ objectStreams: true }))
```

```js
const { PdfDocument, FolioxideError } = require('folioxide')
```

### `PdfDocument`

| Member | What it does |
|---|---|
| `PdfDocument.open(data, { strict? })` | Opens a PDF from a `Buffer` or `Uint8Array` (copied once). Damaged files are repaired unless `strict` is true. |
| `PdfDocument.openAsync(data, { strict? })` | The same on the libuv thread pool; returns a promise. |
| `PdfDocument.create()` | A new, empty PDF 1.7 document (no pages yet). |
| `pageCount`, `version`, `isModified` | The number of pages, the PDF version (`"1.7"`), whether there are unsaved changes. |
| `diagnostics()` | What opening and reading repaired: `{ offset, kind, message }[]`. |
| `getPage(i)` | `{ index, width, height, mediaBox, cropBox, rotation }` of page `i` (0-based). Width and height are as displayed (rotation applied); boxes are `{ llx, lly, urx, ury }` in points. |
| `getInfo()` / `setInfo(update)` | The document information dictionary. In `update`, an absent field keeps the entry, `null` removes it, a value sets it. Any Unicode text round-trips. Dates are PDF date strings (`"D:20261010093000+02'00'"`); `setInfo` also takes `Date` objects. `custom` holds other entries. |
| `setPageRotation(i, degrees)` | Rotates a page (a multiple of 90; `-90` is 270). |
| `setPageBox(i, 'media' \| 'crop', rect \| null)` | Sets a page's media box or crop box; `null` removes the crop box. |
| `save(options?)`, `saveAsync(options?)` | A full rewrite. Options: `xref` (`'auto'`, `'table'`, `'stream'`), `objectStreams`, `compress` (`'keep'`, `'compressNew'`, `'recompress'`), `gc`, `renumber`, `deterministic`, `id`, `minVersion` (`"1.0"` to `"1.7"`, or `"2.0"`), `flateLevel` (0–9). |
| `saveIncremental(options?)`, `saveIncrementalAsync(options?)` | The original bytes followed by an incremental update with the changes (ISO 32000-2 §7.5.6). `suffixOnly: true` returns only the appended bytes. |
| `close()`, `[Symbol.dispose]()` | Frees the document's native memory now. Afterwards every method throws `E_CLOSED`. |
| `isClosed`, `nativeMemory` | Whether `close()` was called; an estimate of the native memory the document holds, in bytes (0 once closed). |

Synchronous methods never block the event loop: while `saveAsync` or `saveIncrementalAsync` is
using a document, they throw an error with code `E_BUSY`. Await the promise first.

### Memory

A document keeps the file and whatever was read from it in native memory, often several times
the file's size (a full save reads everything). That memory is reported to V8, which helps the garbage collector, but
**garbage collection alone does not keep memory bounded in long-running loops**. Node frees native
objects only from the event loop, and only after a later GC cycle, so resident memory can keep
growing for hundreds of iterations, even in a loop that awaits every round. **Always close
documents you are done with**, by calling `close()` or with `using` (Node 24 and later). Memory
then stays flat:

```js
for (const file of files) {
  using doc = PdfDocument.open(await readFile(file))
  await writeFile(file, doc.save())
} // each document is freed here
```

An asynchronous save that is running when `close()` is called finishes normally; the memory is
freed when it ends.

### Errors

Every error is a `FolioxideError` (a subclass of `Error`) with a stable `code`:

```js
try {
  PdfDocument.open(bytes)
} catch (err) {
  if (err instanceof FolioxideError && err.code === 'E_PASSWORD_REQUIRED') {
    // encrypted files open in a later release
  }
}
```

Common codes: `E_SYNTAX` and `E_XREF` (not a readable PDF), `E_PAGE_OUT_OF_RANGE`,
`E_INVALID_ARGUMENT`, `E_UNSUPPORTED` (for example an incremental save of a file whose structure
had to be repaired: use `save()` instead), `E_PASSWORD_REQUIRED`, `E_LIMIT_EXCEEDED`, `E_BUSY` and
`E_CLOSED` (the document was closed).
The `ErrorCode` type in `index.d.ts` lists them all.

### Dates

`toPdfDate(date)` formats a `Date` as a PDF date string in UTC (`"D:20261010073000Z"`);
`fromPdfDate(text)` parses one (leniently, as real files write them) into a `Date`, or `null`.

### `version(): string`

Returns the version of the native Folioxide library. It always equals the version of the npm
package, so it shows that the JavaScript wrapper and the native addon come from the same release.

## Roadmap

Signing comes first, then page and document operations, then annotations and forms, then content
editing. The milestone plan is in `docs/ROADMAP.md` in the
[source repository](https://github.com/friday-deployer/fdp-pdf_editor).

## License

Licensed under the MIT license ([LICENSE](LICENSE)).

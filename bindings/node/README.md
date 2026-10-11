# folioxide

Folioxide is a PDF editing engine written in pure Rust, packaged for Node.js as a native
[napi-rs](https://napi.rs) addon. It is built for PDF signing (PAdES), page and document operations,
annotations and forms, and content editing. It has no C or C++ PDF dependencies.

> **Status: pre-alpha.** This release opens, inspects and saves PDF documents (page sizes, boxes and
> rotation, the document information dictionary, full saves and incremental updates that keep the
> original bytes), signs them with invisible PAdES B-B signatures (local PKCS#12 and PEM keys, or
> any external signer: a KMS, an HSM, WebCrypto, `node:crypto`), and verifies signatures.
> Timestamps, certification, visible signatures, encryption and page operations come in later
> releases. The API will change without notice until 1.0.

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
| `prepareSignature(options)`, `prepareSignatureAsync(options)` | The first phase of signing: a `PreparedSignature` (see Signing). Options: `certificateChain`, `algorithm`, `digest` (`'sha256'`, `'sha384'`, `'sha512'`), `signingTime` (`Date` or PDF date), `field` (`{ name?, page?, mode? }`), `subFilter`, `name`, `reason`, `location`, `contactInfo`, `contentsReserve`. |
| `verifySignatures(options?)` | A promise of one `SignatureReport` per signature (see Verifying). |
| `close()`, `[Symbol.dispose]()` | Frees the document's native memory now. Afterwards every method throws `E_CLOSED`. |
| `isClosed`, `nativeMemory` | Whether `close()` was called; an estimate of the native memory the document holds, in bytes (0 once closed). |

Synchronous methods never block the event loop: while `saveAsync`, `saveIncrementalAsync`,
`prepareSignatureAsync` or `verifySignatures` is using a document, they throw an error with code
`E_BUSY`. Await the promise first.

### Signing

`signPdf` adds an invisible PAdES baseline B-B signature (`/SubFilter /ETSI.CAdES.detached`) in its
own incremental update and returns the signed file. The original bytes are kept as they are, so a
second signature keeps the first one valid. The document itself is not changed: open the returned
bytes to keep working with them.

```js
import { readFile, writeFile } from 'node:fs/promises'
import { LocalSigner, PdfDocument, signPdf } from 'folioxide'

const doc = await PdfDocument.openAsync(await readFile('contract.pdf'))
const signer = LocalSigner.fromPkcs12(await readFile('signer.p12'), process.env.P12_PASSWORD)
const signed = await signPdf(doc, {
  signer,
  reason: 'Approved',
  location: 'Berlin',
  // signingTime defaults to now; field defaults to a new field "Signature1" on page 0
})
await writeFile('contract-signed.pdf', signed)
```

`LocalSigner.fromPem(keyPem, certsPem, password?)` loads PKCS#8 (plain or encrypted), PKCS#1 and SEC1
keys with their certificate chain. Keys are RSA (2048 to 8192 bits), P-256 or P-384.

**External signers.** Any object with `certificateChain` (DER or PEM certificates, the signer's
first), `algorithm` (`'rsa-pkcs1v15'` or `'ecdsa'`) and a `sign(toBeSigned, toBeSignedDigest,
digestAlgorithm)` function can sign. It may return a promise, so a cloud KMS or an HSM fits
directly. ECDSA values may be DER or IEEE P1363 (`r || s`, what WebCrypto returns):

```js
import { createPrivateKey, sign } from 'node:crypto'

const key = createPrivateKey(await readFile('signer.key.pem'))
const signed = await signPdf(doc, {
  signer: {
    certificateChain: [await readFile('signer.pem'), await readFile('intermediate.pem')],
    algorithm: 'ecdsa',
    sign: (toBeSigned, toBeSignedDigest, digestAlgorithm) =>
      sign(digestAlgorithm, toBeSigned, { key, dsaEncoding: 'ieee-p1363' }),
  },
})
```

A signer that takes a precomputed digest (most KMS "sign digest" APIs) signs `toBeSignedDigest`
instead; raw RSA (PKCS#11 `CKM_RSA_PKCS`) signs `prepared.toBeSignedDigestInfo`. RSA signing in the
local key path uses the blinded `rsa` crate path, which has an unpatched timing advisory
(RUSTSEC-2023-0071): on servers where an attacker can time many signatures, prefer ECDSA keys or an
external signer.

**Key hygiene.** A `LocalSigner` keeps its key in native memory that is wiped when it is dropped:
call `signer.close()` (or declare it with `using`) when you are done, rather than waiting for the
garbage collector; afterwards its methods throw `E_CLOSED`. The addon wipes its own copies of the
password and the PEM key once the key is loaded, but JavaScript strings are immutable and cannot be
wiped. To keep secrets out of the heap as strings, pass them as bytes and wipe those:

```js
const password = await readFile('signer.pass') // a Buffer, not a string
using signer = LocalSigner.fromPkcs12(await readFile('signer.p12'), password)
password.fill(0)
const signed = await signPdf(doc, { signer }) // the key is wiped at the end of the block
```

`fromPem(keyPem, certsPem, keyPassword)` takes the key and its password as bytes too. While a
PKCS#12 file is loaded, the `p12-keystore` crate holds an unwiped copy of the key; it is dropped
before `fromPkcs12` returns. Key files with key-derivation parameters that would make loading a
denial of service (more than 10 000 000 PBKDF2 iterations, scrypt above 256 MiB of memory or
1 GiB of work) are refused with `E_KEY_LOAD`.

**Two phases.** `signPdf` is `prepareSignature`, the signer, then `finish`. Do them yourself when the
signature comes later or from elsewhere; a prepared signature can be stored in between:

```js
import { PreparedSignature } from 'folioxide'

const prepared = await doc.prepareSignatureAsync({ certificateChain, algorithm: 'ecdsa' })
const stored = prepared.serialize() // a Buffer: the prepared file and the bytes to sign
// ... later, possibly in another process ...
const restored = PreparedSignature.deserialize(stored)
const signature = await kms.sign(restored.toBeSignedDigest)
const signed = await restored.finishAsync(signature) // or embedCms(cms) with a whole CMS
```

`finish` verifies the value with the signer certificate before it embeds it (`E_SIGNATURE_INVALID`
otherwise). A refused value or CMS leaves the prepared signature as it was, so you can ask the signer
again and call `finish` once more; the first `finish`, `finishAsync`, `embedCms` or `embedCmsAsync`
that succeeds takes it, and later calls throw `E_INVALID_ARGUMENT`. While `finishAsync` or
`embedCmsAsync` runs, the other three and `serialize` throw `E_BUSY`.

### Verifying

```js
import { isSignatureAcceptable } from 'folioxide'

const reports = await PdfDocument.open(signed).verifySignatures({
  trustAnchors: [await readFile('root.pem')], // DER or PEM; without anchors `trusted` is null
  // extraCertificates: [...], validationTime: new Date() (the default; null: the signing time)
})
for (const r of reports) {
  console.log(r.fieldName, r.intact, r.signatureValid, r.trusted, r.coverage, r.modification)
  console.log(r.signer.subject, r.claimedTime, r.reason, r.problems)
}
// Accept the document only if every signature is sound, nothing but later signatures was
// appended after it, and the signer is trusted.
const accepted =
  reports.length > 0 && reports.every((r) => isSignatureAcceptable(r, 'formFilling') && r.trusted === true)
```

**Gate on `modification`, not only on `intact` and `signatureValid`.** A signature covers the
revision it signed: when a later incremental update replaces page content, fonts or the catalog
(an incremental saving or shadow attack), the signature stays intact and valid, and only
`modification: 'other'` reports the change. `isSignatureAcceptable(report, maxModification)` checks
both; its default `'formFilling'` accepts later signatures.

**`'formFilling'` includes visible signature appearances added after signing**, and those can
cover signed content: a new visible signature field with an appearance (signed or still empty), or
the appearance a later signature gives the field it signs. pyHanko and Acrobat accept this at the
same level; it is inherent to sequential signing in PDF. No level accepts later signatures while
refusing visible ones (a later signature, visible or not, is `'formFilling'`), so when no further
signer is expected, `'ltaUpdates'` is the strict choice. A signature field that stays unsigned may
change only its field flags: an appearance, appearance state or annotation flags added to it
without a signature is `'other'`.

The AcroForm is checked against an exact whitelist. After signing, a later revision may only (a)
add new top-level signature fields to `/Fields` (with their widgets, signature dictionaries and the
pages' `/Annots` entries), (b) change `/SigFlags` as signing requires, which no signing after a
signature does, so any `/SigFlags` change is `'other'` (as in pyHanko), and (c) add new `/DR`
resource names that the signed revision does not name. Everything else in the AcroForm is
`'other'`: any change to `/NeedAppearances` (setting it makes viewers rebuild the signed fields'
appearances from their values, and removing it makes them show stored appearances that may differ
from what the signer saw; that includes a later signer that removes it while signing, as
pyHanko's signer does, where pyHanko reports `'formFilling'` for the earlier signatures), any
change to `/DA` (adding one too: an added `/DA` restyles every field a viewer rebuilds), any
change to `/Q`, and changing or removing a `/DR` resource name. The signed revision names every
name in a default appearance string (`/DA`) of the AcroForm, its fields and widgets and every
annotation on every page (with the `/DA` it inherits from its field), and every name in an appearance stream of those that has no
`/Resources` of its own; when these cannot all be read within the verifier's limits, no new `/DR`
name is allowed. The residual risk of `'formFilling'` here: names that a form XObject nested in an
appearance stream uses, and names a viewer looks up in `/DR` after failing to find them in an
appearance stream's own resources, are not read.

There is one report per signature, in signing order. `intact` (the signed bytes are unchanged),
`signatureValid`, `trusted` (a certification path to an anchor at the validation time; no revocation
checks), `coverage` (`'entireFile'`, `'entireRevision'`, `'contiguousBlockFromStart'`, `'unclear'`)
and `modification` (what later revisions changed: `'none'`, `'ltaUpdates'`, `'formFilling'`,
`'annotations'`, `'other'`) use the vocabulary of the pyHanko validator and are never more lenient
than it: they agree with pyHanko except in the deliberate differences listed in the M3 brief
(`docs/milestones/M3.md` §0), where Folioxide is stricter (for example `'other'` where pyHanko
reports `'ltaUpdates'`). After two signatures, the first reports `'entireRevision'` and
`'formFilling'`, the second `'entireFile'` and `'none'`. `byteRangeOk` and `problems` (`{ code, message }`, for example `digestMismatch` or
`gapNotContents`) report the defences against the known PDF signature attacks (signature wrapping,
incremental saving and shadow attacks). A report has the JSON shape of the Rust core's DTOs.

Hostile files cannot make verification grow with their size: a signature dictionary that several
fields share is reported for at most 8 of them (a warning counts the others), at most 1,024 reports
are returned (every report then says how many were left out; only 256 signatures are verified in
full, so a cut list always holds reports that are not valid), and `changedObjects` names at most
1,024 objects (a warning gives the full count).

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
`E_INVALID_ARGUMENT`, `E_UNSUPPORTED` (for example an incremental save or a signature on a file
whose structure had to be repaired: use `save()` first), `E_PASSWORD_REQUIRED`, `E_LIMIT_EXCEEDED`,
`E_BUSY` and `E_CLOSED` (the document was closed). Signing adds `E_WRONG_PASSWORD`,
`E_PASSWORD_REQUIRED` and `E_KEY_LOAD` (loading keys), `E_CERTIFICATE`, `E_CRYPTO` (also when an
external signer throws; its error is the `cause`), `E_SIGNATURE_INVALID` (the signer's value does
not verify), `E_DOC_MDP_FORBIDS` (a certified document that allows no changes) and
`E_SIGNATURE_PLACEHOLDER_TOO_SMALL`, whose `err.details` is `{ needed, reserved }` (`signPdf`
retries once with `needed` when you set a too-small `contentsReserve`). Messages never contain
passwords or key material. The `ErrorCode` type in `index.d.ts` lists them all.

### Dates

`toPdfDate(date)` formats a `Date` as a PDF date string in UTC (`"D:20261010073000Z"`);
`fromPdfDate(text)` parses one (leniently, as real files write them) into a `Date`, or `null`.

### `version(): string`

Returns the version of the native Folioxide library. It always equals the version of the npm
package, so it shows that the JavaScript wrapper and the native addon come from the same release.

## Roadmap

Signatures with timestamps (PAdES B-T), certification and visible signatures come next, then page
and document operations, then annotations and forms, then content
editing. The milestone plan is in `docs/ROADMAP.md` in the
[source repository](https://github.com/friday-deployer/fdp-pdf_editor).

## License

Licensed under the MIT license ([LICENSE](LICENSE)).

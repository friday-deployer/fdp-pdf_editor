# folioxide

Folioxide is a PDF editing engine written in pure Rust, packaged for Node.js as a native
[napi-rs](https://napi.rs) addon. It is built for PDF signing (PAdES), page and document operations,
annotations and forms, and content editing. It has no C or C++ PDF dependencies.

> **Status: pre-alpha.** This release opens, inspects and saves PDF documents (page sizes, boxes and
> rotation, the document information dictionary, full saves and incremental updates that keep the
> original bytes), signs them with PAdES B-B and B-T signatures (local PKCS#12 and PEM keys, or
> any external signer: a KMS, an HSM, WebCrypto, `node:crypto`; RFC 3161 timestamps from any TSA
> you call), certification signatures (DocMDP) and visible signatures, and verifies signatures,
> their timestamps and document timestamps. Encryption and page operations come in later
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

`signPdf` adds a PAdES baseline B-B signature (`/SubFilter /ETSI.CAdES.detached`), invisible unless
you give it an `appearance`, in its own incremental update and returns the signed file. The original bytes are kept as they are, so a
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
`embedCmsAsync` runs, the other three, `timestampRequest` and `serialize` throw `E_BUSY`.

**Timestamps (PAdES B-T).** Give `signPdf` a `timestamp` callback: it receives the DER RFC 3161
`TimeStampReq` (over the signature value, asking for the TSA certificate, with a random nonce) and
returns the TSA's DER `TimeStampResp`. Folioxide does no network I/O itself, so you choose the TSA,
the transport and its authentication:

```js
const signed = await signPdf(doc, {
  signer,
  timestamp: async (request) => {
    const response = await fetch('https://tsa.example.com/', {
      method: 'POST',
      headers: { 'content-type': 'application/timestamp-query' },
      body: request,
    })
    if (!response.ok) throw new Error(`TSA: HTTP ${response.status}`)
    return response.arrayBuffer()
  },
  // timestampOptions: { digest: 'sha384', policy: '1.2.3.4.1', nonce: 42n },
})
```

The response is validated before the token is embedded: the status (`granted` or
`grantedWithMods`), the imprint and nonce of the request, the TSA's signature, every
signing-certificate attribute and the token's `tsa` name, the TSA certificate's timestamping purpose
(extended key usage timeStamping only, marked critical, as RFC 3161 requires and OpenSSL checks)
and its extensions (none twice, every known one decoding, no critical one that OpenSSL does not
handle), and the shape of the whole token (what it carries must be what RFC 3161 and RFC 5652
allow, in an encoding OpenSSL can decode, its names included: every string one OpenSSL converts to
UTF-8, the `tsa` field one of the GeneralName choices it decodes): Folioxide never embeds a token
its own verifier would call invalid. Trust is not checked when signing: a token whose TSA path the
verifier will not trust (one through a certificate with proxy certificate information or an RFC
3779 block, for example, which `openssl ts -verify` refuses for that chain reason) is embedded,
and verifies as valid but untrusted. A
refusal, a callback that throws (its error is the `cause`) or a response that fails a check rejects
with `E_TIMESTAMP_INVALID`. The callback gets its own copy of the request, so reusing or wiping its
buffer is safe. The placeholder budgets `tsaReserve` bytes for the token (default 8192,
enough for a TSA chain of about three certificates). **If the token is larger, `signPdf` signs and
timestamps once more with room for it, so the signer and the callback may each be called twice.**

In two phases, `prepared.timestampRequest(signature, options?)` returns the request (and remembers
it), and `prepared.finish(signature, timestampResponse)` embeds the token. A refused response leaves
the prepared signature as it was. Once a request is remembered, `finish(signature)` without a
response throws `E_INVALID_ARGUMENT`, so a forgotten response never gives a file without a
timestamp; to finish without one after all (the TSA is down, say), call
`prepared.discardTimestampRequest()` first. `serialize` does not keep the request: after
`deserialize`, pass it as `finish(signature, response, request)`.

```js
const prepared = await doc.prepareSignatureAsync({ certificateChain, algorithm: 'ecdsa', tsaReserve: 8192 })
const signature = await kms.sign(prepared.toBeSignedDigest)
const response = await postToTsa(prepared.timestampRequest(signature))
const signed = await prepared.finishAsync(signature, response)
```

**Certification.** `certify: 1 | 2 | 3` makes the signature a certification signature (DocMDP,
ISO 32000-2 §12.8.2.2): the author signs first and states which later changes keep the
certification valid: `1` none at all, `2` filling in forms and signing, `3` that plus annotations.
It must be the document's first signature. Later signing respects it: on a `P = 1` document every
signature is refused, and on a `P = 2` or `3` document a new *visible* signature field is refused (it
would break the certification; sign an existing empty field instead), all with `E_DOC_MDP_FORBIDS`.

```js
const certified = await signPdf(doc, { signer, certify: 2, reason: 'Issued' })
```

**Visible signatures.** `appearance` draws the signature in a widget on the field's page (`field.page`,
default 0): a box with text lines and an optional JPEG image, upright on rotated pages.

```js
const signed = await signPdf(doc, {
  signer,
  field: { page: 0 },
  appearance: {
    rect: [360, 40, 560, 100], // [llx, lly, urx, ury] in the page's default user space, or a Rect
    image: await readFile('logo.jpg'), // baseline or progressive JPEG, gray or RGB
    // lines: ['Approved by Jane Doe'], font: 'Helvetica-Bold', fontSize: 9,
    // imagePosition: 'left' | 'background', borderWidth: 1
  },
})
```

`rect` is in PDF points in the page's **default (unrotated) user space**, the space of its
`/MediaBox`: on a page with `/Rotate` 90 or 270 its width appears on screen as height (and its height
as width), so give such a page a tall rectangle for a wide box. The appearance itself is turned to
stay upright. The default text is `Digitally signed by <name>` (the `name` option, else the
certificate's common name), the date, and the reason and location when given; characters outside
Windows-1252 show as `?`. The text uses Helvetica, which is **not embedded** (font embedding comes
in M7): a visible signature added to a PDF/A document makes it non-conformant, and PDF 2.0
deprecates the exemption of the standard 14 fonts, so sign PDF/A documents invisibly until then.
Omit `rect` to sign an existing empty field in its own widget (one whose flags hide it or would draw
it outside its rectangle is refused with `E_INVALID_ARGUMENT`: sign it without an appearance). A
rectangle without an area or outside the page is `E_INVALID_ARGUMENT`; an image that is not a JPEG
is `E_IMAGE`, a CMYK JPEG `E_UNSUPPORTED`.

### Verifying

```js
import { isSignatureAcceptable } from 'folioxide'

const reports = await PdfDocument.open(signed).verifySignatures({
  trustAnchors: [await readFile('root.pem')], // DER or PEM; without anchors `trusted` is null
  // extraCertificates: [...], validationTime: new Date() (the default; null: see below),
  // timestampTrustAnchors: [...] (the TSAs' roots; default trustAnchors)
})
for (const r of reports) {
  console.log(r.fieldName, r.intact, r.signatureValid, r.trusted, r.coverage, r.modification)
  console.log(r.signer.subject, r.claimedTime, r.reason, r.problems)
  console.log(r.padesLevel, r.timestamp?.genTime, r.timestamp?.trusted, r.docmdp, r.docmdpOk)
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
cover signed content inside their rectangle: a new visible signature field with an appearance
(signed or still empty), or the appearance a later signature gives the field it signs. pyHanko and
Acrobat accept this at the same level; it is inherent to sequential signing in PDF. Such a widget may
only print and lock (its flags may not make it hidden, unrotated, unzoomed or print-only, which
would draw it elsewhere or not on screen), and its appearance must be a new form XObject with a
bounding box, so it is drawn inside its rectangle. No level accepts later signatures while
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
`/Resources` of its own, and every name a signed appearance stream (of any widget or annotation,
in any state) uses, with every content stream it draws (form XObjects, whatever way their
`/Subtype` is written, tiling patterns, Type 3 glyphs and the soft-mask groups of its graphics
states, nested, and what the resources of every page draw, inherited along the `/Kids` walk and
each page's `/Parent` chain, when such a stream has no `/Resources` of its own or resources that
lack a category); when these cannot all be read within the verifier's limits, no new `/DR` name is allowed. So a viewer that looks up in `/DR` a name a signed appearance stream
draws and that neither the stream's own resources nor the page's hold cannot pick up a new
resource; names that only page content uses are not read, since viewers resolve those in the
page's resources, never in `/DR`.

There is one report per signature, in signing order. `intact` (the signed bytes are unchanged),
`signatureValid`, `trusted` (a certification path to an anchor at the validation time; no revocation
checks; never through a certificate authority with name constraints, policy constraints or policy
mappings, critical or not, which Folioxide does not process, nor through any certificate with an
RFC 3779 IP address or AS identifier block or with proxy certificate information, which Folioxide
does not process either (OpenSSL refuses such chains, except for an inherit-only RFC 3779 block;
pyHanko trusts them), nor through a certificate whose known extensions do not decode (a stray byte
after a value included, which OpenSSL and pyHanko let pass) or that has an extension twice, nor
through one with a critical extension that OpenSSL does not handle (a critical subject or authority
key identifier, which RFC 5280 says must be non-critical, authority information access, freshest
CRL, QC statements or a private extension: OpenSSL refuses such chains, pyHanko trusts some of
them), nor along an edge that the certificate's authority key identifier does not describe: a key
identifier, issuer name or serial number that names another certificate than its issuer, as OpenSSL
and pyHanko refuse it; the anchors themselves
are trusted as given, their own validity, CA flag, key usage and extensions not evaluated, as in
pyHanko, where OpenSSL refuses an anchor that is not a CA), `coverage` (`'entireFile'`, `'entireRevision'`, `'contiguousBlockFromStart'`, `'unclear'`)
and `modification` (what later revisions changed: `'none'`, `'ltaUpdates'`, `'formFilling'`,
`'annotations'`, `'other'`) use the vocabulary of the pyHanko validator and are never more lenient
than it: they agree with pyHanko except in the deliberate differences listed in the M3 brief
(`docs/milestones/M3.md` §0), where Folioxide is stricter (for example `'other'` where pyHanko
reports `'ltaUpdates'`). After two signatures, the first reports `'entireRevision'` and
`'formFilling'`, the second `'entireFile'` and `'none'`. `byteRangeOk` and `problems` (`{ code, message }`, for example `digestMismatch` or
`gapNotContents`) report the defences against the known PDF signature attacks (signature wrapping,
incremental saving and shadow attacks). A report has the JSON shape of the Rust core's DTOs.

**Timestamps and certification in the report.** `timestamp` is the signature's timestamp token
(`genTime`, the TSA certificate `tsa`, `policy`, `serialHex`, `accuracyMicros`, `imprintAlgorithm`,
`intact`, `valid`, `trusted`, and its own `problems`), and `timestamps` lists every token;
`padesLevel` is `'B-T'` when the token is intact and valid. A broken timestamp token never makes
the signature itself invalid, as long as the unsigned attribute holding it is a well-formed
attribute (a type and a `SET` of values); an attribute that is not makes the whole CMS malformed
(`cmsMalformed`, the signature not intact), as for pyHanko, which cannot read such a file either.
A token is read as a whitelist, as OpenSSL reads it: its structure (the optional fields OpenSSL
decodes included: the TSTInfo `extensions`, the ESS `policies` and the value types of the ESS
issuer names), every name it carries (each string one OpenSSL converts to UTF-8, so no BMPString
with a UTF-16 surrogate and no UniversalString beyond Unicode; the TSTInfo `tsa` field one of the
GeneralName choices OpenSSL decodes, and the TSA certificate's subject alternative names it is
matched against decoded the same way), the encoding of its signed attributes (DER, the encoding the
TSA must sign: a TSA that signed another encoding of them made a token OpenSSL and BouncyCastle
refuse), the message imprint, the TSA name it states (compared as OpenSSL compares names) and its
ESS signing-certificate attributes must all match, every ESS identifier included: the first names
the TSA certificate and the later ones certificates that really issued it, checked by signature
and, with trust anchors, on the validated path, so a certificate that only carries an issuer's
name does not count. The TSA certificate itself must have no extension twice, every extension
Folioxide knows decoding (OpenSSL marks such a certificate invalid) and no critical extension that
OpenSSL does not handle (a critical key identifier, for example: OpenSSL refuses the chain with
"unhandled critical extension"), and a TSA key whose certificate restricts it to RSASSA-PSS
(`id-RSASSA-PSS`) verifies no PKCS #1 v1.5 token, and, when the certificate states RSASSA-PSS
parameters, only tokens with exactly those. RSASSA-PSS parameters whose hash algorithms carry
parameters other than absent or NULL (RFC 4055) make the key unusable, on the TSA, its issuers and
the trust anchor alike, as pyHanko does not trust them either. A token `openssl ts
-verify` refuses for one of these reasons is not `valid` here either (pyHanko accepts most of
these). The same key rule holds for document signers: a signature by a key restricted to RSASSA-PSS
must be an RSASSA-PSS signature, so such a certificate cannot sign with Folioxide, which signs RSA
with PKCS #1 v1.5 (`prepareSignature` and `signPdf` throw `E_UNSUPPORTED`). Two constructs that RFC 5652 allows are the known
exceptions: OpenSSL 3.0 cannot read a token signed with RSASSA-PSS or one whose signer is
identified by its subjectKeyIdentifier, which Folioxide and pyHanko accept. Folioxide is stricter
than OpenSSL in a few places (signed attributes out of DER order, empty TSTInfo `extensions`, a
BMPString surrogate outside a name, a certificate in the token whose name holds a UniversalString,
which Folioxide's certificate decoder cannot read, so such a TSA gets no `'B-T'`; RFC 5280 keeps
UniversalString for backward compatibility only; certificate times OpenSSL also reads, such as a
UTCTime without seconds or a GeneralizedTime with a fraction; an `rsaEncryption` key without its
NULL parameters or an RSA key whose integers are not DER; and its limits: at most 256
subjectAltName entries, so a longer list names nothing for the TSTInfo `tsa` name, at most 64
certificates in a token and as many ESS identifiers, at most 16 strings in the status text
(`PKIFreeText`) of a TSA's response), so a token OpenSSL accepts is not always `valid` here, a TSA path through a
certificate authority with name constraints is never `trusted`, even one OpenSSL and pyHanko
accept, and neither is one whose certificate's authority key identifier gives only a wrong serial
number, which OpenSSL refuses and pyHanko ignores. Names compare as OpenSSL compares them (string
type, ASCII case and white space folded), except that a value with a character outside the Basic
Multilingual Plane is compared exactly, string type included, as pyHanko compares it. A token that cannot be read at all (a
truncated value, say) is not listed, but the report's `warnings` say that an unsigned attribute
could not be read, and why `padesLevel` is `null` when the CMS around it is no longer DER.
**`genTime`
means something only when `timestamp.trusted` is `true`**, and a signature timestamp is not covered
by the signature: anyone can remove it (B-T becomes B-B) or replace it with a later valid one.
`trusted` is judged at `validationTime` (now, by default); with `validationTime: null` a TSA is
validated at its token's own `genTime` and a signer at the trusted `genTime` of its timestamp, which
the report's warnings say: that time is the TSA's claim, so a TSA key that outlived its certificate
could backdate a token. A document timestamp (`kind: 'docTimeStamp'`) is verified the same way, with
its token in `timestamp`.

`docmdp` is the `P` a signature sets: a certification signature's, or the `P` of its field's lock
dictionary (PDF 2.0), the stricter of the two when both are there; a DocMDP declaration that cannot
be read gives the problem `docMdpInvalid` and `P = 1` in force. `docmdpOk` says whether the later
revisions respect the permissions in force for each signature (the strictest of its own `P` and
those of the signatures before it, else 2: a field lock cannot grant more than a certification
already in force, ISO 32000-2 §12.7.5.5), and `isSignatureAcceptable` requires it not to be `false`: after `P = 1` even
an `/Info` change is refused (pyHanko accepts that one), and `'annotations'` passes only under
`P = 3`. A document timestamp sets no permissions: its `docmdpOk` is `null` (as in pyHanko). Its
`modification` uses the permissions in force for markup annotations only (one after it is `'other'`
unless `P = 3` is in force): in a `P = 1` certified document, a form fill, an `/Info` change or an
approval signature after a document timestamp leaves the timestamp's report at `'formFilling'` or
`'ltaUpdates'`, which `isSignatureAcceptable` accepts, as pyHanko's level does; the
certification's own report has `docmdpOk: false` then. **Check every report**, not only the
newest.
`'formFilling'` also covers filling in form fields (a value, a check box state, a text field's new
appearance, by a whitelist), and `'annotations'` new markup annotations (comments, highlights,
shapes; the one level more lenient than pyHanko, which reports `'other'`).

**What these levels still let a later revision show.** A filled form field can show any text its
filler chooses inside the field's rectangle, and an opaque one covers the signed page content
beneath it; the rectangle itself never moves. A markup annotation accepted at `'annotations'` must
draw inside its rectangle (its appearance is required and its geometry checked), but there it can
cover signed content too: that is what `P = 3` grants. That holds at 100 % zoom: a sticky note
(Text annotation) is drawn at a fixed size, so below 100 % zoom a viewer that honours NoZoom can
draw it past its rectangle (its own appearance, at its rectangle's size). Annotations a viewer
draws unzoomed or unrotated are `'other'`: sticky notes on a rotated page, and annotations flagged
NoZoom or NoRotate (such as the `/F 28` sticky notes Acrobat is believed to write). Form fields whose widget is
flagged so are not filled at `'formFilling'` either. A new field or signature appearance must also
be drawn at about its widget's size: a tiny bounding box moved far away and scaled up onto the
widget (which PDFium places in single precision, so it can land beside the widget) is `'other'`,
even in the cases PDFium still places correctly, such as a one-unit box moved by 10,000 units;
what signers and form fillers write is the widget's own size. Gate on `'ltaUpdates'` (or check the
reports' `changedObjects`) when no such change is expected.

Hostile files cannot make verification grow with their size: a signature dictionary that several
fields share is reported for at most 8 of them (a warning counts the others), at most 1,024 reports
are returned (every report then says how many were left out; only 256 signatures are verified in
full, so a cut list always holds reports that are not valid), and `changedObjects` names at most
1,024 objects (a warning gives the full count).

A file whose revisions other readers would follow differently is refused rather than reported:
when a trailer or cross-reference stream gives `/Prev` (or `/XRefStm`) twice with different
values, `verifySignatures` rejects with `E_XREF`, since a reader keeping the other value may see
signatures this one does not. A signature dictionary or field (with its `/Lock` and DocMDP
`/Reference`) that other readers could read differently gets the problem `sigDictAmbiguous`: a key
written twice, or any value not written canonically (a number with two signs or an exponent, an
integer beyond ±2,147,483,647 or longer than 11 characters, a real longer than 40 characters or
beyond ±3.403 × 10^38, a name with `#00`, a token the lexer has to repair; manager ruling R-12).
The signature is then not intact when the key is `/ByteRange` or `/Contents`, and an
ambiguous DocMDP declaration or lock gives `docMdpInvalid` with `P = 1` in force. The same
canonical-input rule holds for every object a later revision writes or a modification level reads:
otherwise the level is `'other'`.

A level below `'other'` also needs a file that a reader which rebuilds the cross-reference data
(poppler does when it cannot find `startxref`, PDFium after a malformed entry) reads the same way,
so these files report `'other'` for the signatures concerned, although nothing visible may have
changed:

- **The file's tail.** The file must end with its last `startxref` at most 1,024 bytes before the
  end, then the offset, `%%EOF` and at most two end-of-line bytes. More than two bytes, or any byte
  that is not CR or LF, after the final `%%EOF` (comments, spaces, NUL), or a final `startxref`
  farther from the end, makes **every** signature `'other'`, the newest one too, even a single
  signature with nothing appended: a mail gateway or upload filter that adds `\r\n` to a file
  ending `%%EOF\n` turns a signed file into `'other'`. A file ending `%%EOF`, `%%EOF\n` or
  `%%EOF\r\n` is fine. Keep signed files byte-exact.
- **Text that looks like structure.** The scan for it fails closed: text inside a later
  revision's strings, streams (page content and appearance streams included), names or comments
  that a rebuilding reader takes for structure makes the earlier signatures `'other'`. That is:
  - an object header (`12 0 obj`) written as separate words anywhere, and `trailer` followed by
    `<<` or a `%` comment anywhere;
  - an object header or `trailer <<` at the start of a line, at the start of each 255-byte piece
    of a longer line, or right after an `endobj`, past white space;
  - `xref` or `startxref` at the start of a line, past white space, or right after an `endobj` in
    a line.

  So a value that contains `xref`, `startxref` or `Room 12 3 object` inside a line stays a fill,
  and so does a line inside a string that begins with other words, such as `see xref table`. A
  line inside a string that begins with `xref` or `startxref`, and values such as `x endobj xref`,
  `see 12 0 obj` or `trailer <<`, make the earlier signatures `'other'`, although nothing visible
  changes and pyHanko calls them fills.
- **New object streams in a classic-table update.** A classic cross-reference table cannot list
  compressed objects, so an update that writes one adds no non-empty object stream; one that does,
  or an object stream whose members its own section does not list at their index, is `'other'`.
- **`/Size`.** A later revision's trailer (or cross-reference stream dictionary) `/Size` must be a
  direct integer above every object number the file lists and not below the previous revision's:
  PDFium keeps only the objects below the newest `/Size`. Folioxide's own updates
  (`saveIncremental()` and signing) never write a `/Size` below the previous one, even after a
  revision that over-declares it.
- **Shared field appearances.** When a non-signature field of the signed revision, a field node
  with kids included, has an indirect appearance dictionary (`/AP`) that is named more than once
  (another field or widget, or a hidden copy of the object, uses the same dictionary), every later
  revision that would be above `'none'` is `'other'`, whatever it changes, as pyHanko decides; for
  an unsigned signature field that shares its `/AP` dictionary, the revision that signs that field
  is.

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
not verify), `E_DOC_MDP_FORBIDS` (the certification rules refuse the signature; the message names
the rule), `E_TIMESTAMP_INVALID` (the TSA refused, its response failed a check, or the `timestamp`
callback threw; its error is the `cause`), `E_IMAGE` (a visible signature's image is not a JPEG)
and `E_SIGNATURE_PLACEHOLDER_TOO_SMALL`, whose `err.details` is `{ needed, reserved }` (`signPdf`
retries once with `needed` when you set a too-small `contentsReserve`, and signs and timestamps once
more when a timestamp token does not fit). Messages never contain
passwords or key material. The `ErrorCode` type in `index.d.ts` lists them all.

### Dates

`toPdfDate(date)` formats a `Date` as a PDF date string in UTC (`"D:20261010073000Z"`);
`fromPdfDate(text)` parses one (leniently, as real files write them) into a `Date`, or `null`.

### `version(): string`

Returns the version of the native Folioxide library. It always equals the version of the npm
package, so it shows that the JavaScript wrapper and the native addon come from the same release.

## Roadmap

Encryption and page and document operations come next, then annotations and forms, then content
editing; long-term validation (PAdES B-LT and B-LTA) later. The milestone plan is in `docs/ROADMAP.md` in the
[source repository](https://github.com/friday-deployer/fdp-pdf_editor).

## License

Licensed under the MIT license ([LICENSE](LICENSE)).

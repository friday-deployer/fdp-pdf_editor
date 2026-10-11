/**
 * Folioxide: a pure-Rust PDF editing engine for Node.js.
 *
 * Type declarations for the hand-written facade (`index.js` for CommonJS, `index.mjs` for ESM).
 *
 * The plain objects the API returns ({@link PageInfo}, {@link DocInfo}, {@link Diagnostic},
 * {@link SignatureReport}) have the JSON shape of the Rust core's serde DTOs (`camelCase` names,
 * absent entries left out or `null` as the core writes them), so a Tauri app built on the same core
 * sees the same JSON. (A certificate's `der` is a `Buffer` here, an array of numbers in serde.)
 *
 * @packageDocumentation
 */

/// <reference types="node" />

// ---- errors ------------------------------------------------------------------------------------

/**
 * Every `code` a {@link FolioxideError} can have: the Rust core's `ErrorCode` with an `E_` prefix,
 * plus `E_BUSY` and `E_CLOSED`.
 *
 * - `E_SYNTAX`: malformed PDF syntax (ISO 32000-2 §7.2–7.3).
 * - `E_XREF`: a broken or unusable cross-reference table, stream or trailer (§7.5); also data
 *   that is not a PDF file at all.
 * - `E_MISSING_OBJECT`, `E_TYPE_MISMATCH`: a required object is missing or has the wrong type.
 * - `E_LIMIT_EXCEEDED`: a resource limit was hit (a decompression bomb, an absurd object count).
 * - `E_FILTER`: a stream filter failed to decode its data (§7.4).
 * - `E_UNSUPPORTED`: a feature this version does not support, such as an incremental save of a
 *   file whose structure had to be repaired (save it in full instead).
 * - `E_PASSWORD_REQUIRED`, `E_WRONG_PASSWORD`, `E_PERMISSION_DENIED`: encryption (opening
 *   encrypted files arrives in a later release).
 * - `E_INVALID_ARGUMENT`: an argument has the wrong type or value.
 * - `E_PAGE_OUT_OF_RANGE`: no page has this index.
 * - `E_NOT_FOUND`: a named item was not found.
 * - `E_WRONG_PASSWORD`, `E_PASSWORD_REQUIRED` also for PKCS#12 files and encrypted PEM keys
 *   ({@link LocalSigner}).
 * - `E_KEY_LOAD`: a private key could not be loaded or does not belong to its certificate.
 * - `E_CERTIFICATE`: a certificate does not parse.
 * - `E_CRYPTO`: a cryptographic operation failed, or an external signer's `sign()` threw (the
 *   signer's error is the `cause`).
 * - `E_SIGNATURE_PLACEHOLDER_TOO_SMALL`: the CMS does not fit the `/Contents` placeholder;
 *   `details` is `{ needed, reserved }` (bytes of DER).
 * - `E_SIGNATURE_INVALID`: a signature value or CMS does not verify with the signer
 *   certificate over the prepared bytes (another key, another digest).
 * - `E_DOC_MDP_FORBIDS`: the document is certified with permissions that forbid signing.
 * - `E_FONT`, `E_IMAGE`, `E_TIMESTAMP_INVALID`: fonts, images and timestamps (later releases).
 * - `E_IO`: an I/O operation failed.
 * - `E_BUSY`: a synchronous method was called while an asynchronous one (`saveAsync`,
 *   `saveIncrementalAsync`, `prepareSignatureAsync`, `verifySignatures`) is using the document,
 *   or a {@link PreparedSignature} was used while its `finishAsync` or `embedCmsAsync` runs;
 *   await its promise first.
 * - `E_CLOSED`: a method was called on a document after {@link PdfDocument.close}, or on a
 *   signer after {@link LocalSigner.close}.
 */
export type ErrorCode =
  | 'E_SYNTAX'
  | 'E_XREF'
  | 'E_MISSING_OBJECT'
  | 'E_TYPE_MISMATCH'
  | 'E_LIMIT_EXCEEDED'
  | 'E_FILTER'
  | 'E_UNSUPPORTED'
  | 'E_PASSWORD_REQUIRED'
  | 'E_WRONG_PASSWORD'
  | 'E_PERMISSION_DENIED'
  | 'E_INVALID_ARGUMENT'
  | 'E_PAGE_OUT_OF_RANGE'
  | 'E_NOT_FOUND'
  | 'E_FONT'
  | 'E_IMAGE'
  | 'E_CRYPTO'
  | 'E_KEY_LOAD'
  | 'E_CERTIFICATE'
  | 'E_SIGNATURE_PLACEHOLDER_TOO_SMALL'
  | 'E_SIGNATURE_INVALID'
  | 'E_DOC_MDP_FORBIDS'
  | 'E_TIMESTAMP_INVALID'
  | 'E_IO'
  | 'E_BUSY'
  | 'E_CLOSED'

/**
 * The error every function and method of this package throws, and every promise rejects with.
 *
 * ```js
 * try {
 *   PdfDocument.open(bytes)
 * } catch (err) {
 *   if (err instanceof FolioxideError && err.code === 'E_XREF') { ... }
 * }
 * ```
 *
 * Messages are for people and may change; `code` is stable. Messages never contain passwords or
 * key material.
 */
export declare class FolioxideError extends Error {
  /**
   * @param code The `E_*` code.
   * @param message A human-readable description.
   * @param options The error that caused this one (`cause`), and structured `details`.
   */
  constructor(
    code: ErrorCode,
    message: string,
    options?: { cause?: unknown; details?: Record<string, unknown> },
  )
  /** Always `'FolioxideError'`. */
  name: 'FolioxideError'
  /** The stable, machine-readable error code. */
  readonly code: ErrorCode
  /**
   * Structured details, when there are any: `{ needed, reserved }` (numbers, bytes of DER) for
   * `E_SIGNATURE_PLACEHOLDER_TOO_SMALL`; the napi status for an argument that the native addon
   * could not convert (`{ status: 'NumberExpected' }`).
   */
  readonly details?: Record<string, unknown>
}

// ---- plain objects -----------------------------------------------------------------------------

/**
 * A rectangle in default user space (ISO 32000-2 §7.9.5), in PDF points (1/72 inch).
 *
 * Rectangles the API returns are normalized (`llx <= urx`, `lly <= ury`); rectangles it takes
 * may have their corners in any order.
 */
export interface Rect {
  /** The x coordinate of the lower-left corner. */
  llx: number
  /** The y coordinate of the lower-left corner. */
  lly: number
  /** The x coordinate of the upper-right corner. */
  urx: number
  /** The y coordinate of the upper-right corner. */
  ury: number
}

/** What a page looks like: its size as displayed, its boxes and its rotation. */
export interface PageInfo {
  /** The page's 0-based index. */
  index: number
  /**
   * The width as displayed, in points: the crop box's width, or its height when the page is
   * rotated by 90 or 270 degrees.
   */
  width: number
  /** The height as displayed, in points (see `width`). */
  height: number
  /**
   * The media box (§7.7.3.3), inherited from the page tree when the page has none; US Letter
   * (`[0 0 612 792]`) when no valid one exists, with a diagnostic.
   */
  mediaBox: Rect
  /** The crop box (§14.11.2), clipped to the media box; the media box when the page has none. */
  cropBox: Rect
  /** The rotation, clockwise in degrees: 0, 90, 180 or 270. */
  rotation: number
}

/** A page box {@link PdfDocument.setPageBox} can change. */
export type PageBox = 'media' | 'crop'

/** The `/Trapped` entry of the document information dictionary (§14.3.3). */
export type Trapped = 'true' | 'false' | 'unknown'

/**
 * The document information dictionary (§14.3.3), decoded.
 *
 * Entries the dictionary does not have (or has with the wrong type) are left out. Text is
 * decoded from PDFDocEncoding or UTF-16. Dates are PDF date strings in the full form
 * `D:YYYYMMDDHHmmSSOHH'mm'`, for example `"D:20261010093000+02'00'"`; {@link fromPdfDate} turns
 * one into a `Date`.
 */
export interface DocInfo {
  /** `/Title`: the document's title. */
  title?: string
  /** `/Author`: the name of the person who created the document. */
  author?: string
  /** `/Subject`: the subject of the document. */
  subject?: string
  /** `/Keywords`: keywords associated with the document. */
  keywords?: string
  /** `/Creator`: the application that created the original document. */
  creator?: string
  /** `/Producer`: the application that converted it to PDF. */
  producer?: string
  /** `/CreationDate`, as a PDF date string. */
  creationDate?: string
  /** `/ModDate`, as a PDF date string. */
  modDate?: string
  /** `/Trapped`. */
  trapped?: Trapped
  /** Every other entry whose value is a text string, by key (the name without its `/`). */
  custom: Record<string, string>
}

/** A date for {@link InfoUpdate}: a `Date` (written in UTC) or a PDF date string. */
export type PdfDateInput = Date | string

/**
 * Changes to the document information dictionary (§14.3.3), for {@link PdfDocument.setInfo}.
 *
 * Every field is one change: absent (or `undefined`) keeps the entry, `null` removes it, a value
 * sets it. Text is written as a PDF text string (PDFDocEncoding when every character has a code
 * there, otherwise UTF-16BE), so any Unicode text round-trips.
 */
export interface InfoUpdate {
  /** `/Title`. */
  title?: string | null
  /** `/Author`. */
  author?: string | null
  /** `/Subject`. */
  subject?: string | null
  /** `/Keywords`. */
  keywords?: string | null
  /** `/Creator`. */
  creator?: string | null
  /** `/Producer`. */
  producer?: string | null
  /**
   * `/CreationDate`: a `Date` or a PDF date string (§7.9.4; partial forms such as `"D:2026"`
   * are accepted).
   */
  creationDate?: PdfDateInput | null
  /**
   * `/ModDate`: a `Date` or a PDF date string. It is never set automatically: pass
   * `new Date()` to record the modification time.
   */
  modDate?: PdfDateInput | null
  /** `/Trapped`. */
  trapped?: Trapped | null
  /**
   * Other entries, by key (the name without its `/`): `null` removes the entry, a string sets
   * it, keys not listed are kept. A key must not be one of the standard keys above (`Title`,
   * `CreationDate`, …). A key that is set must not be empty, be longer than 127 bytes in UTF-8
   * (the PDF name length limit) or contain a NUL character; any other key can be removed.
   */
  custom?: Record<string, string | null>
}

/**
 * The category of a {@link Diagnostic}, a stable `camelCase` identifier: what was repaired or
 * decided while reading (`streamLength`: a stream's `/Length` was wrong; `xrefReconstructed`:
 * the cross-reference data was unusable and the file was scanned; `pageTree`, `pageAttribute`,
 * `metadata`, `catalog`: the document model read around damage).
 */
export type DiagnosticKind =
  | 'malformedNumber'
  | 'invalidHexDigit'
  | 'invalidNameEscape'
  | 'duplicateKey'
  | 'invalidDictKey'
  | 'missingDictValue'
  | 'unknownKeyword'
  | 'unclosedContainer'
  | 'invalidReference'
  | 'streamKeywordEol'
  | 'streamLength'
  | 'missingEndstream'
  | 'missingEndobj'
  | 'emptyObject'
  | 'streamWithoutDict'
  | 'headerOffset'
  | 'missingHeader'
  | 'malformedHeader'
  | 'xrefOffsetRepaired'
  | 'xrefSubsectionShifted'
  | 'xrefMalformed'
  | 'xrefReconstructed'
  | 'xrefLoop'
  | 'trailerRebuilt'
  | 'wrongGeneration'
  | 'objectUnreadable'
  | 'objectStream'
  | 'unresolvedReference'
  | 'filterTruncated'
  | 'cryptFilterIgnored'
  | 'xrefUnknownEntryType'
  | 'unreferencedUpdate'
  | 'pageTree'
  | 'pageAttribute'
  | 'metadata'
  | 'catalog'
  | 'other'

/** A record of one repair or leniency decision made while reading the document. */
export interface Diagnostic {
  /**
   * The byte offset of the problem in the buffer being parsed (the file, or a decoded object
   * stream), or `null` when it is not tied to a position.
   */
  offset: number | null
  /** The category. */
  kind: DiagnosticKind
  /** A human-readable description. */
  message: string
}

// ---- options -----------------------------------------------------------------------------------

/** Options for {@link PdfDocument.open} and {@link PdfDocument.openAsync}. */
export interface OpenOptions {
  /**
   * Refuse damaged files (`E_SYNTAX`, `E_XREF`, …) instead of repairing them. Default `false`:
   * repair what can be repaired and record a {@link Diagnostic} for each repair.
   */
  strict?: boolean
}

/**
 * The kind of cross-reference section a full save writes (§7.5.4, §7.5.8): `'auto'` (a stream
 * when object streams are on or the source's newest section is a stream, otherwise a table),
 * `'table'` or `'stream'` (the header becomes at least `%PDF-1.5`).
 */
export type XrefStyle = 'auto' | 'table' | 'stream'

/**
 * How a full save writes stream data: `'keep'` (every stream as it is, new data unfiltered),
 * `'compressNew'` (new data Flate-encoded, existing streams copied as encoded) or `'recompress'`
 * (like `'compressNew'`, and existing streams that can be decoded completely are encoded again
 * with Flate).
 */
export type StreamCompression = 'keep' | 'compressNew' | 'recompress'

/**
 * Options for a full save ({@link PdfDocument.save}, {@link PdfDocument.saveAsync}). Every field
 * is optional; the defaults give a compact, garbage-collected, renumbered file.
 */
export interface SaveOptions {
  /** The kind of cross-reference section. Default `'auto'`. */
  xref?: XrefStyle
  /** Pack objects into object streams (§7.5.7; needs a cross-reference stream). Default `false`. */
  objectStreams?: boolean
  /** How stream data is written. Default `'compressNew'`. */
  compress?: StreamCompression
  /** Write only the objects reachable from the trailer. Default `true`. */
  gc?: boolean
  /** Number the objects densely from 1. Default `true`. */
  renumber?: boolean
  /**
   * Ask for byte-identical output for identical input and edits. The writer is deterministic
   * either way; default `false`.
   */
  deterministic?: boolean
  /**
   * The file identifier to write (`/ID`, §14.4): two byte strings. Default: the source's first
   * element and a new second one, or an identifier generated from the content.
   */
  id?: [Uint8Array, Uint8Array]
  /**
   * The lowest PDF version for the header: `"1.0"` to `"1.7"` or `"2.0"` (any other value throws
   * `E_INVALID_ARGUMENT`). The header names the highest of the document's version, this, and
   * `"1.5"` when a cross-reference stream is written.
   */
  minVersion?: string
  /** The Flate compression level, an integer from 0 (store) to 9 (best). Default 6. */
  flateLevel?: number
}

/** Options for {@link PdfDocument.saveIncremental} and {@link PdfDocument.saveIncrementalAsync}. */
export interface IncrementalSaveOptions {
  /**
   * Return only the bytes to append to the original file (to update a file in place) instead of
   * the whole new file. Default `false`.
   */
  suffixOnly?: boolean
  /** Ask for byte-identical output for identical input and edits. Default `false`. */
  deterministic?: boolean
  /**
   * The second element of the new `/ID` (§14.4). Default: a digest of the update. The first
   * element is always kept.
   */
  id1?: Uint8Array
}

// ---- the document ------------------------------------------------------------------------------

/**
 * A PDF document, opened from bytes ({@link PdfDocument.open}, {@link PdfDocument.openAsync}) or
 * created empty ({@link PdfDocument.create}).
 *
 * ```js
 * import { readFile, writeFile } from 'node:fs/promises'
 * import { PdfDocument } from 'folioxide'
 *
 * const doc = await PdfDocument.openAsync(await readFile('in.pdf'))
 * console.log(doc.pageCount, doc.getPage(0).width, doc.getInfo().title)
 * doc.setInfo({ title: 'Отчёт 2026', modDate: new Date() })
 * await writeFile('out.pdf', await doc.saveIncrementalAsync())
 * ```
 *
 * Page indices are 0-based. Every error is a {@link FolioxideError} with an `E_*` code.
 *
 * **Threading.** The heavy operations have `…Async` variants that run on the libuv thread pool.
 * Synchronous methods and getters never block the event loop: while an asynchronous method is
 * using the document (from the call until its work is done), they throw `E_BUSY`. Two
 * asynchronous methods on one document run one after the other.
 *
 * **Memory.** A document keeps the file and what was read from it in native memory, often
 * several times the file's size. That memory is reported to V8, so a document that is no longer
 * referenced is garbage-collected in time. Node frees native objects from the event loop only,
 * so a loop that never awaits keeps every document until it ends; {@link PdfDocument.close} (or
 * `using`, which calls `[Symbol.dispose]`) frees it at once:
 *
 * ```js
 * for (const file of files) {
 *   using doc = PdfDocument.open(await readFile(file))
 *   await writeFile(file, doc.save())
 * } // each document is freed here
 * ```
 */
export declare class PdfDocument implements Disposable {
  /** Use {@link PdfDocument.open}, {@link PdfDocument.openAsync} or {@link PdfDocument.create}. */
  private constructor()

  /**
   * Opens a PDF file from its bytes. The bytes are copied once, so the buffer may be reused
   * afterwards. Opening reads the file's structure only; pages and metadata are read when first
   * asked for.
   *
   * Damaged files are repaired (each repair is listed by {@link PdfDocument.diagnostics}) unless
   * `options.strict` is true.
   *
   * @param data The file: a `Buffer` or another `Uint8Array`.
   * @throws {FolioxideError} `E_XREF` or `E_SYNTAX` when the data is not a readable PDF file,
   *   `E_PASSWORD_REQUIRED` for an encrypted file (not supported yet), `E_UNSUPPORTED` for an
   *   unsupported security handler, `E_LIMIT_EXCEEDED` when a resource limit is hit,
   *   `E_INVALID_ARGUMENT` when `data` is not a `Uint8Array`.
   */
  static open(data: Uint8Array, options?: OpenOptions): PdfDocument

  /**
   * Like {@link PdfDocument.open}, on the libuv thread pool. The bytes are copied before the
   * promise is returned.
   */
  static openAsync(data: Uint8Array, options?: OpenOptions): Promise<PdfDocument>

  /**
   * A new, empty PDF 1.7 document: a catalog and a page tree with no pages. It has no original
   * file, so it can be saved with {@link PdfDocument.save} only.
   */
  static create(): PdfDocument

  /**
   * Frees the document's native memory now, instead of when the object is garbage-collected.
   * Afterwards every method and getter but {@link PdfDocument.isClosed} throws `E_CLOSED`. An
   * asynchronous operation already started finishes first (its promise resolves as usual) and
   * the memory is freed when it ends. Calling it again does nothing.
   */
  close(): void

  /** The same as {@link PdfDocument.close}, for `using` declarations. */
  [Symbol.dispose](): void

  /** Whether {@link PdfDocument.close} was called. */
  get isClosed(): boolean

  /**
   * An estimate of the native memory the document holds, in bytes: the file, what was read from
   * it and the changes. This is what V8 is told about, so that garbage collection accounts for
   * it. It grows as pages are read and when the document is saved (which reads everything), and
   * is 0 once the document is closed. Never throws.
   */
  get nativeMemory(): number

  /** The number of pages: the pages the page tree really has, not its `/Count`. */
  get pageCount(): number

  /** The PDF version, such as `"1.7"`: the header's, or the catalog's `/Version` when later. */
  get version(): string

  /** Whether the document has changes not saved yet (always true for a new document). */
  get isModified(): boolean

  /**
   * The repairs and leniency decisions recorded so far, oldest first: opening, then whatever
   * reading pages and metadata found.
   */
  diagnostics(): Diagnostic[]

  /**
   * The size, boxes and rotation of a page.
   *
   * @param index The 0-based page index.
   * @throws {FolioxideError} `E_PAGE_OUT_OF_RANGE` when there is no such page,
   *   `E_INVALID_ARGUMENT` when `index` is not an integer.
   */
  getPage(index: number): PageInfo

  /** The document information dictionary, decoded; entries it does not have are left out. */
  getInfo(): DocInfo

  /**
   * Changes the document information dictionary. In `update`, a field that is absent keeps the
   * entry, `null` removes it and a value sets it. Nothing is set automatically, not even
   * `/ModDate`.
   *
   * @throws {FolioxideError} `E_INVALID_ARGUMENT` for a date that is not a PDF date, a
   *   `trapped` value that is not a {@link Trapped}, or an invalid custom key.
   */
  setInfo(update: InfoUpdate): void

  /**
   * Sets the rotation of a page, written on the page itself (the other pages keep theirs).
   *
   * @param index The 0-based page index.
   * @param degrees Clockwise: a multiple of 90, negative ones included (`-90` is 270).
   * @throws {FolioxideError} `E_INVALID_ARGUMENT` when `degrees` is not a multiple of 90,
   *   `E_PAGE_OUT_OF_RANGE` when there is no such page.
   */
  setPageRotation(index: number, degrees: number): void

  /**
   * Sets the media box or the crop box of a page, written on the page itself. A crop box is
   * clipped to the media box; `null` removes the crop box (it becomes the media box).
   *
   * @param index The 0-based page index.
   * @param box Which box.
   * @param rect The box in points, or `null` to remove the crop box.
   * @throws {FolioxideError} `E_INVALID_ARGUMENT` for a box with no area, a coordinate that is
   *   not finite, a crop box outside the media box, or `null` for the media box;
   *   `E_PAGE_OUT_OF_RANGE` when there is no such page.
   */
  setPageBox(index: number, box: PageBox, rect: Rect | null): void

  /**
   * Writes the whole document again (garbage-collected, renumbered, with a fresh
   * cross-reference section) and returns the new file.
   *
   * @throws {FolioxideError} `E_INVALID_ARGUMENT` for invalid options, or the error of the
   *   writer.
   */
  save(options?: SaveOptions): Buffer

  /** Like {@link PdfDocument.save}, on the libuv thread pool. */
  saveAsync(options?: SaveOptions): Promise<Buffer>

  /**
   * Returns the original file followed by an incremental update with the changes (ISO 32000-2
   * §7.5.6): the original bytes are kept byte for byte, which keeps existing signatures valid.
   * Without changes, the original file. With `options.suffixOnly`, only the appended bytes.
   *
   * @throws {FolioxideError} `E_INVALID_ARGUMENT` for a document made with
   *   {@link PdfDocument.create} (there is no original file); `E_UNSUPPORTED` when opening had
   *   to repair the file's structure (other readers could see an update to it differently): save
   *   such a file with {@link PdfDocument.save}.
   */
  saveIncremental(options?: IncrementalSaveOptions): Buffer

  /** Like {@link PdfDocument.saveIncremental}, on the libuv thread pool. */
  saveIncrementalAsync(options?: IncrementalSaveOptions): Promise<Buffer>

  /**
   * The first phase of signing: builds the incremental update that adds an invisible PAdES
   * signature (the document's unsaved changes, the signature field and the signature dictionary
   * with its placeholders), digests the signed byte ranges and builds the bytes to sign. The
   * document is not changed.
   *
   * Sign {@link PreparedSignature.toBeSigned} (or its digest) with the key of the first
   * certificate, then call {@link PreparedSignature.finish}. {@link signPdf} does all of it.
   *
   * @throws {FolioxideError} `E_INVALID_ARGUMENT` for invalid options (an empty chain, an
   *   algorithm that does not match the certificate, a signing time that is not a date, a field
   *   name with a `.`, …); `E_SIGNATURE_PLACEHOLDER_TOO_SMALL` (with `details.needed`) for a
   *   `contentsReserve` below what the signature needs; `E_UNSUPPORTED` when opening repaired
   *   the file's structure or the file has bytes before its header (save it in full first);
   *   `E_DOC_MDP_FORBIDS` for a certified document that allows no changes;
   *   `E_PAGE_OUT_OF_RANGE`, `E_NOT_FOUND` (an existing field asked for), `E_CERTIFICATE`;
   *   `E_BUSY`, `E_CLOSED`.
   */
  prepareSignature(options: PrepareSignatureOptions): PreparedSignature

  /** Like {@link PdfDocument.prepareSignature}, on the libuv thread pool. */
  prepareSignatureAsync(options: PrepareSignatureOptions): Promise<PreparedSignature>

  /**
   * Verifies every signature of the document on the libuv thread pool: one
   * {@link SignatureReport} per signature dictionary, in signing order (dictionaries no field
   * refers to last). An unsigned document gives `[]`.
   *
   * Hostile files cannot make the list grow with their size: a signature dictionary that several
   * fields share is reported for at most 8 of them (a warning counts the others), at most 1,024
   * reports are returned (each then says how many were left out; the list stays fail-closed,
   * since only 256 signatures are verified in full and the others are reported not valid), and a
   * report names at most 1,024 `changedObjects`.
   *
   * ```js
   * const [report] = await PdfDocument.open(signed).verifySignatures({ trustAnchors: [rootPem] })
   * report.intact && report.signatureValid && report.trusted // true
   * ```
   *
   * @throws {FolioxideError} `E_INVALID_ARGUMENT` when the document has unsaved changes (verify
   *   the saved file) or an option is invalid; `E_CLOSED`.
   */
  verifySignatures(options?: VerifyOptions): Promise<SignatureReport[]>
}

// ---- signatures --------------------------------------------------------------------------------

/**
 * A signature algorithm: RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) or ECDSA on P-256 or P-384 (the curve
 * comes from the certificate).
 */
export type SigAlg = 'rsa-pkcs1v15' | 'ecdsa'

/** A digest algorithm for signing. SHA-1 is never used to sign. */
export type DigestAlg = 'sha256' | 'sha384' | 'sha512'

/**
 * The `/SubFilter` of a signature dictionary (ISO 32000-2 §12.8.3.1). Folioxide writes the same
 * CMS (PAdES baseline B-B signed attributes) for both; `'ETSI.CAdES.detached'` is PAdES.
 */
export type SubFilter = 'ETSI.CAdES.detached' | 'adbe.pkcs7.detached'

/**
 * Whether a signature uses an existing signature field, creates one, or either:
 *
 * - `'createOrUse'` (the default): sign the named field when it exists and is an unsigned
 *   signature field, otherwise create it; without a name, always create a new field;
 * - `'existingOnly'`: sign the named existing field (`E_NOT_FOUND` when there is none);
 * - `'createOnly'`: always create a new field (`E_INVALID_ARGUMENT` when the name is taken).
 */
export type FieldMode = 'createOrUse' | 'existingOnly' | 'createOnly'

/** Which signature field to sign or create. New fields are invisible (a zero-size widget). */
export interface SignatureFieldSpec {
  /**
   * The field name: an existing field's fully qualified name, or a new field's partial name
   * (without `.`). Default: a new field `Signature1`, `Signature2`, … (the first free name).
   */
  name?: string
  /** The 0-based index of the page that holds a new field's widget. Default 0. */
  page?: number
  /** Whether an existing field may be used and a new one created. Default `'createOrUse'`. */
  mode?: FieldMode
}

/** Options for {@link PdfDocument.prepareSignature} and {@link PdfDocument.prepareSignatureAsync}. */
export interface PrepareSignatureOptions {
  /**
   * The certificates: the signer's first, then the intermediates (the root is optional). Each
   * entry is a DER certificate, or PEM text with one or more `CERTIFICATE` blocks. They are
   * embedded in the signature byte for byte.
   */
  certificateChain: Uint8Array[]
  /** The signature algorithm of the signer's key. */
  algorithm: SigAlg
  /** The digest algorithm. Default: SHA-256 for RSA and P-256 keys, SHA-384 for P-384 keys. */
  digest?: DigestAlg
  /**
   * The claimed signing time, written as `/M`: a `Date` (written in UTC) or a PDF date string.
   * Default: now.
   */
  signingTime?: PdfDateInput
  /** Which signature field to sign or create. Default: a new field on the first page. */
  field?: SignatureFieldSpec
  /** The `/SubFilter`. Default `'ETSI.CAdES.detached'`. */
  subFilter?: SubFilter
  /** `/Name`: the signer's name. Any Unicode text. */
  name?: string
  /** `/Reason`: why the document is signed. */
  reason?: string
  /** `/Location`: where it is signed. */
  location?: string
  /** `/ContactInfo`: how to reach the signer. */
  contactInfo?: string
  /**
   * The bytes of DER the `/Contents` placeholder holds. Default: the exact size of the CMS plus
   * a margin, at least 8192. A value below what the CMS needs throws
   * `E_SIGNATURE_PLACEHOLDER_TOO_SMALL` with `details.needed` ({@link signPdf} then prepares
   * once more with that size).
   */
  contentsReserve?: number
}

/**
 * A prepared signature: the file with the placeholders, and the bytes to sign. Made by
 * {@link PdfDocument.prepareSignature} or {@link PreparedSignature.deserialize}.
 *
 * ```js
 * const prepared = doc.prepareSignature({ certificateChain, algorithm: 'ecdsa' })
 * const signature = await kms.sign(prepared.toBeSignedDigest) // or sign prepared.toBeSigned
 * const signed = prepared.finish(signature)
 * ```
 *
 * The first of {@link PreparedSignature.finish}, `finishAsync`, `embedCms` and `embedCmsAsync`
 * **that succeeds** takes the prepared file; a later call throws `E_INVALID_ARGUMENT`, and the
 * getters keep working. A refused value or CMS leaves the prepared signature as it was, so an
 * external signer that returned a wrong value can be asked again without preparing again. While
 * `finishAsync` or `embedCmsAsync` runs, the other finishing methods and `serialize` throw
 * `E_BUSY`.
 */
export declare class PreparedSignature {
  /** Use {@link PdfDocument.prepareSignature} or {@link PreparedSignature.deserialize}. */
  private constructor()

  /**
   * Reads what {@link PreparedSignature.serialize} wrote, checking every invariant again (the
   * file, the byte range and the signed attributes must be unchanged).
   *
   * @throws {FolioxideError} `E_INVALID_ARGUMENT` for bytes that are not a serialized prepared
   *   signature of this version, or that were changed; `E_CERTIFICATE`, `E_UNSUPPORTED`.
   */
  static deserialize(data: Uint8Array): PreparedSignature

  /**
   * The bytes to sign: the DER signed attributes (RFC 5652 §5.4), for "sign message" APIs that
   * hash themselves (`crypto.sign(digestAlgorithm, toBeSigned, key)`, WebCrypto, KMS `RAW`).
   */
  readonly toBeSigned: Buffer
  /** The digest of `toBeSigned` with `digestAlgorithm`, for "sign digest" HSM and KMS APIs. */
  readonly toBeSignedDigest: Buffer
  /**
   * The DER `DigestInfo` of `toBeSignedDigest` (RFC 8017 §9.2), for raw RSA signing (PKCS#11
   * `CKM_RSA_PKCS`).
   */
  readonly toBeSignedDigestInfo: Buffer
  /** The digest algorithm the signature uses. */
  readonly digestAlgorithm: DigestAlg
  /** The signature algorithm of the signer's key. */
  readonly algorithm: SigAlg
  /** The `/SubFilter` of the signature dictionary. */
  readonly subFilter: SubFilter
  /** The bytes of DER the `/Contents` placeholder holds. */
  readonly contentsCapacity: number
  /**
   * `[0, a, b, c]`: the signed byte ranges `[0, a)` and `[b, b + c)` of the finished file;
   * `[a, b)` is the `/Contents` hexadecimal string.
   */
  readonly byteRange: number[]
  /** Observations from preparing, for example an AcroForm `/NeedAppearances true` kept. */
  readonly warnings: string[]
  /** Whether `finish`, `finishAsync`, `embedCms` or `embedCmsAsync` succeeded. */
  readonly isFinished: boolean

  /**
   * Finishes the file with the signature value over {@link PreparedSignature.toBeSigned}, made
   * with the key of the first certificate: returns the signed PDF. The value is verified before
   * it is embedded; a refused value leaves the prepared signature as it was.
   *
   * @param signature RSA: the modulus length; ECDSA: DER or IEEE P1363 (`r || s`, as WebCrypto
   *   and `dsaEncoding: 'ieee-p1363'` return it).
   * @throws {FolioxideError} `E_SIGNATURE_INVALID` when the value does not verify (another key,
   *   another digest, other bytes); `E_INVALID_ARGUMENT` when a finish succeeded already;
   *   `E_BUSY` while `finishAsync` or `embedCmsAsync` runs.
   */
  finish(signature: Uint8Array): Buffer

  /**
   * Like {@link PreparedSignature.finish}, on the libuv thread pool. Until it settles, the other
   * finishing methods and `serialize` throw `E_BUSY`.
   */
  finishAsync(signature: Uint8Array): Promise<Buffer>

  /**
   * Finishes the file with a whole CMS (`ContentInfo` with `SignedData`, DER) that a signing
   * service made over the prepared byte ranges: returns the signed PDF. The CMS must sign exactly
   * these bytes, with one signer whose signature verifies; for `'ETSI.CAdES.detached'` it must
   * meet PAdES baseline B-B.
   *
   * A refused CMS leaves the prepared signature as it was.
   *
   * @throws {FolioxideError} `E_SIGNATURE_INVALID` when it signs other bytes or does not verify;
   *   `E_INVALID_ARGUMENT` when it is not such a CMS or a finish succeeded already;
   *   `E_SIGNATURE_PLACEHOLDER_TOO_SMALL` when it is larger than `contentsCapacity`; `E_BUSY`
   *   while `finishAsync` or `embedCmsAsync` runs.
   */
  embedCms(cms: Uint8Array): Buffer

  /**
   * Like {@link PreparedSignature.embedCms}, on the libuv thread pool. Until it settles, the
   * other finishing methods and `serialize` throw `E_BUSY`.
   */
  embedCmsAsync(cms: Uint8Array): Promise<Buffer>

  /**
   * The prepared signature in a versioned binary form (it holds the whole prepared file), to
   * finish it later or in another process with {@link PreparedSignature.deserialize}.
   *
   * @throws {FolioxideError} `E_INVALID_ARGUMENT` when a finish succeeded already; `E_BUSY` while
   *   `finishAsync` or `embedCmsAsync` runs.
   */
  serialize(): Buffer
}

/**
 * A private key held in memory with its certificate chain, loaded from PKCS#12 or PEM. Pass it
 * to {@link signPdf} as the `signer`.
 *
 * ```js
 * const signer = LocalSigner.fromPkcs12(await readFile('signer.p12'), password)
 * const signed = await signPdf(doc, { signer, reason: 'Approved' })
 * ```
 *
 * RSA signatures use the blinded path of the `rsa` crate, which has an unpatched timing
 * advisory (RUSTSEC-2023-0071): on servers where an attacker can time many signatures, prefer
 * ECDSA keys or an {@link ExternalSigner} (KMS, HSM).
 *
 * **Key hygiene.** The key is held in native memory that is wiped by {@link LocalSigner.close}
 * (or a `using` declaration), or when the object is garbage-collected if that comes first. The
 * addon wipes its own copies of the password and the PEM key once the key is loaded, but
 * JavaScript strings are immutable and cannot be wiped: to keep a secret out of the heap as a
 * string, pass it as a `Uint8Array` of UTF-8 and `fill(0)` it after loading. While a PKCS#12
 * file is loaded, the `p12-keystore` crate holds an unwiped copy of the key; it is dropped
 * before `fromPkcs12` returns.
 *
 * ```js
 * const password = await readFile('signer.pass') // a Buffer, not a string
 * using signer = LocalSigner.fromPkcs12(await readFile('signer.p12'), password)
 * password.fill(0)
 * const signed = await signPdf(doc, { signer })
 * // the key is wiped at the end of the block
 * ```
 */
export declare class LocalSigner {
  /** Use {@link LocalSigner.fromPkcs12} or {@link LocalSigner.fromPem}. */
  private constructor()

  /**
   * Loads the key and its certificate chain from a PKCS#12 (`.p12`, `.pfx`) file. The MAC is
   * checked before anything is decrypted; modern (AES) and legacy (3DES, RC2-40) files load.
   *
   * @param password A string, or its UTF-8 bytes (which the caller can wipe afterwards).
   * @throws {FolioxideError} `E_WRONG_PASSWORD` for a wrong password; `E_UNSUPPORTED` for an
   *   unsupported encryption scheme; `E_KEY_LOAD` for anything else (no key, a corrupt file, a
   *   key that does not match its certificate, an RSA key below 2048 bits, excessive
   *   key-derivation parameters); `E_INVALID_ARGUMENT` for password bytes that are not UTF-8.
   *   Messages never contain the password.
   */
  static fromPkcs12(data: Uint8Array, password: string | Uint8Array): LocalSigner

  /**
   * Loads the key from PEM (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `RSA PRIVATE KEY` or
   * `EC PRIVATE KEY`) and the certificates from one or more `CERTIFICATE` blocks (a string, or
   * the bytes of a PEM file). The certificate that matches the key is put first.
   *
   * @param keyPem The key as text, or as the bytes of a PEM file (read in place, never copied
   *   into a string, so the caller can wipe them afterwards).
   * @param keyPassword The password of an encrypted key, as a string or its UTF-8 bytes.
   * @throws {FolioxideError} `E_PASSWORD_REQUIRED` for an encrypted key without a password;
   *   `E_WRONG_PASSWORD` when it does not decrypt; `E_CERTIFICATE` when the certificates do not
   *   parse; `E_UNSUPPORTED` for legacy OpenSSL encryption (`Proc-Type: 4,ENCRYPTED`) or an
   *   unsupported key type; `E_KEY_LOAD` for anything else (no certificate matches the key,
   *   excessive key-derivation parameters); `E_INVALID_ARGUMENT` for bytes that are not UTF-8.
   */
  static fromPem(
    keyPem: string | Uint8Array,
    certsPem: string | Uint8Array,
    keyPassword?: string | Uint8Array,
  ): LocalSigner

  /**
   * Wipes the key from memory now, instead of when the object is garbage-collected. Afterwards
   * every method and getter but {@link LocalSigner.isClosed} throws `E_CLOSED`. A `signAsync`
   * already started finishes first, and the key is wiped when it ends. Calling it again does
   * nothing.
   */
  close(): void

  /** The same as {@link LocalSigner.close}, for `using` declarations. */
  [Symbol.dispose](): void

  /** Whether {@link LocalSigner.close} was called. */
  get isClosed(): boolean

  /** The DER certificates: the signer's first, then the intermediates (and the root, if given). */
  readonly certificateChain: Buffer[]
  /** The signature algorithm of the key. */
  readonly algorithm: SigAlg
  /** The digest used when none is given: SHA-256 for RSA and P-256 keys, SHA-384 for P-384. */
  readonly defaultDigest: DigestAlg

  /**
   * Signs `data`, hashing it with `digest` (default {@link LocalSigner.defaultDigest}): RSA
   * PKCS#1 v1.5 (the modulus length), or ECDSA (DER, deterministic per RFC 6979).
   *
   * @throws {FolioxideError} `E_INVALID_ARGUMENT` for an unknown digest; `E_CRYPTO`; `E_CLOSED`
   *   after {@link LocalSigner.close}.
   */
  sign(data: Uint8Array, digest?: DigestAlg): Buffer

  /** Like {@link LocalSigner.sign}, on the libuv thread pool. */
  signAsync(data: Uint8Array, digest?: DigestAlg): Promise<Buffer>
}

/**
 * A signer outside Folioxide (a cloud KMS, an HSM, WebCrypto, `node:crypto`), for
 * {@link signPdf}.
 *
 * ```js
 * import { sign } from 'node:crypto'
 *
 * const signer = {
 *   certificateChain: [signerCertDer, intermediateDer],
 *   algorithm: 'ecdsa',
 *   sign: (toBeSigned) => sign('sha256', toBeSigned, { key: privateKey, dsaEncoding: 'ieee-p1363' }),
 * }
 * ```
 */
export interface ExternalSigner {
  /**
   * The certificates: the signer's first, then the intermediates. Each entry is a DER
   * certificate, or PEM text with one or more certificates.
   */
  certificateChain: Uint8Array[]
  /** The signature algorithm of the key. */
  algorithm: SigAlg
  /**
   * The digest to sign with (when the options of {@link signPdf} name none). Default: SHA-256
   * for RSA and P-256 keys, SHA-384 for P-384 keys.
   */
  digest?: DigestAlg
  /**
   * Signs: return the signature value over `toBeSigned` hashed with `digestAlgorithm` (or,
   * equivalently, over the precomputed `toBeSignedDigest`). RSA: PKCS#1 v1.5, the modulus
   * length. ECDSA: DER or IEEE P1363 (`r || s`). It may return a promise. An error it throws
   * rejects {@link signPdf} with `E_CRYPTO` and the error as the `cause`.
   */
  sign(
    toBeSigned: Buffer,
    toBeSignedDigest: Buffer,
    digestAlgorithm: DigestAlg,
  ): Promise<Uint8Array | ArrayBuffer> | Uint8Array | ArrayBuffer
}

/** Options for {@link signPdf}: the signer, and the signature options. */
export type SignPdfOptions = Omit<PrepareSignatureOptions, 'certificateChain' | 'algorithm'> & {
  /** A {@link LocalSigner}, or any {@link ExternalSigner}. */
  signer: LocalSigner | ExternalSigner
}

/** Options for {@link PdfDocument.verifySignatures}. */
export interface VerifyOptions {
  /**
   * Trusted root certificates (DER, or PEM text). Without any, `trusted` is `null` in every
   * report.
   */
  trustAnchors?: Uint8Array[]
  /**
   * More certificates (DER, or PEM text) for finding signers and building certification paths,
   * besides those the signatures carry.
   */
  extraCertificates?: Uint8Array[]
  /**
   * The time at which certificates must be valid: a `Date` or a PDF date string. Default: now.
   * `null`: each signer's claimed signing time `/M` (with a warning in the report).
   */
  validationTime?: PdfDateInput | null
}

/** What a signature dictionary is: a signature, or a document timestamp (listed, not verified). */
export type SignatureKind = 'signature' | 'docTimeStamp'

/**
 * How much of the file a signature's byte ranges cover (pyHanko's `SignatureCoverageLevel`):
 * the whole file but the signature itself (`'entireFile'`), one complete revision followed by
 * later ones (`'entireRevision'`; see `modification`), a block from the start that does not end
 * at a revision (`'contiguousBlockFromStart'`), or anything else (`'unclear'`).
 */
export type Coverage = 'entireFile' | 'entireRevision' | 'contiguousBlockFromStart' | 'unclear'

/**
 * What the revisions appended after a signature changed, in pyHanko's vocabulary (its
 * `ModificationLevel`), from harmless to anything: nothing (`'none'`); updates that keep the
 * content, such as `/Info`, metadata or new invisible signature fields (`'ltaUpdates'`); signing
 * and filling signature fields (`'formFilling'`, what a later signature is, including the visible
 * appearance a later signature or a new visible signature field may add, which can cover signed
 * content); annotation changes (`'annotations'`); anything else, or a change that cannot be
 * attributed (`'other'`). Never more lenient than pyHanko: where Folioxide is stricter, the M3
 * brief's deliberate-differences table lists the case.
 */
export type ModificationLevel = 'none' | 'ltaUpdates' | 'formFilling' | 'annotations' | 'other'

/** The PAdES baseline level a signature meets (ETSI EN 319 142-1 §6). */
export type PadesLevel = 'B-B'

/**
 * Why a signature is not valid. The dictionary and byte range: `sigValueNotIndirect`,
 * `sigDictNotDictionary`, `byteRangeMissing`, `byteRangeIndirect`, `byteRangeMalformed`,
 * `byteRangeNotFromZero`, `byteRangeOutOfBounds`, `contentsMissing`, `contentsNotHex`,
 * `gapNotContents` (signature wrapping), `sigDictCompressed`, `sigDictOutsideSignedRange`,
 * `sigDictRedefinedLater`, `signedRevisionNotInChain`. The CMS: `cmsMalformed`, `notSignedData`,
 * `signerInfoCount`, `eContentPresent`, `contentTypeMismatch`, `messageDigestMissing`,
 * `digestMismatch`, `signerCertNotFound`, `signingCertificateMismatch`,
 * `algorithmProtectionMismatch`. Algorithms: `digestSignatureAlgorithmMismatch`,
 * `unsupportedAlgorithm`, `unsupportedSubFilter`, `signatureInvalid`, `weakAlgorithm`. The file:
 * `structureRepaired`, `orphan`, `pendingTimestampVerification`.
 */
export type ProblemCode =
  | 'sigValueNotIndirect'
  | 'sigDictNotDictionary'
  | 'byteRangeMissing'
  | 'byteRangeIndirect'
  | 'byteRangeMalformed'
  | 'byteRangeNotFromZero'
  | 'byteRangeOutOfBounds'
  | 'contentsMissing'
  | 'contentsNotHex'
  | 'gapNotContents'
  | 'sigDictCompressed'
  | 'sigDictOutsideSignedRange'
  | 'sigDictRedefinedLater'
  | 'signedRevisionNotInChain'
  | 'cmsMalformed'
  | 'notSignedData'
  | 'signerInfoCount'
  | 'eContentPresent'
  | 'contentTypeMismatch'
  | 'messageDigestMissing'
  | 'digestMismatch'
  | 'signerCertNotFound'
  | 'signingCertificateMismatch'
  | 'algorithmProtectionMismatch'
  | 'digestSignatureAlgorithmMismatch'
  | 'unsupportedAlgorithm'
  | 'unsupportedSubFilter'
  | 'signatureInvalid'
  | 'weakAlgorithm'
  | 'structureRepaired'
  | 'orphan'
  | 'pendingTimestampVerification'

/** One reason a signature is not valid. */
export interface SignatureProblem {
  /** The category. */
  code: ProblemCode
  /** What exactly was wrong, in English. */
  message: string
}

/** An indirect object's identifier (ISO 32000-2 §7.3.10). */
export interface ObjectRef {
  /** The object number. */
  num: number
  /** The generation number. */
  gen: number
}

/** A certificate's public key. */
export interface KeyDescription {
  /** `"rsa"` or `"ec"`; for other keys, the dotted OID of the key algorithm. */
  algorithm: string
  /** The key size in bits (the RSA modulus or the curve's field size); 0 when unknown. */
  bits: number
  /** For EC keys, the curve: `"P-256"`, `"P-384"`, or a dotted OID; `null` for RSA. */
  curve: string | null
}

/** Information about an X.509 certificate (RFC 5280). */
export interface CertificateInfo {
  /**
   * The subject as RFC 4514 text, most specific first, for example
   * `"CN=Folioxide Test Signer RSA-2048,OU=TEST ONLY - DO NOT TRUST,O=Folioxide Test PKI"`.
   */
  subject: string
  /** The issuer, in the same form. */
  issuer: string
  /** The subject's common name (`CN`). */
  commonName: string | null
  /** The serial number, uppercase hexadecimal. */
  serialHex: string
  /** The start of the validity period, RFC 3339 UTC (`"2025-01-01T00:00:00Z"`). */
  notBefore: string
  /** The end of the validity period, RFC 3339 UTC. */
  notAfter: string
  /** The SHA-256 fingerprint of the DER, lowercase hexadecimal. */
  sha256Hex: string
  /** The public key. */
  key: KeyDescription
  /** The key usages by their RFC 5280 names (`"digitalSignature"`, `"nonRepudiation"`, …). */
  keyUsage: string[]
  /** The extended key usages, as dotted OIDs. */
  extKeyUsage: string[]
  /** Whether the certificate is a CA certificate (basicConstraints `cA`). */
  isCa: boolean
  /** The certificate's DER. */
  der: Buffer
}

/**
 * The verification result of one signature dictionary.
 *
 * The signature itself is sound when `byteRangeOk && intact && signatureValid && fieldName !==
 * null && problems.length === 0` and `coverage` is `'entireFile'` or `'entireRevision'`.
 * **That alone does not mean the document is what was signed**: a signature over an earlier
 * revision stays sound when a later incremental update replaces page content, fonts or the
 * catalog, which only `modification` (`'other'`) reports. To accept a document, use
 * {@link isSignatureAcceptable} (which also bounds `modification`) and check `trusted`. `intact`,
 * `signatureValid`, `trusted`, `coverage` and `modification` use the pyHanko validator's
 * vocabulary and are never more lenient than it: they agree with pyHanko except in the deliberate
 * differences the M3 brief lists, where Folioxide is stricter.
 */
export interface SignatureReport {
  /**
   * The fully qualified name of the signature field; `null` for a signature dictionary no field
   * refers to (problem `orphan`).
   */
  fieldName: string | null
  /** A signature or a document timestamp. */
  kind: SignatureKind
  /** The signature dictionary's object. */
  sigObject: ObjectRef
  /** The `/SubFilter`, for example `"ETSI.CAdES.detached"`. */
  subFilter: string | null
  /** The `/ByteRange` as written; `null` when it is missing or not an array of integers. */
  byteRange: number[] | null
  /**
   * The byte range is sound: four integers from 0, inside the file, whose gap is exactly this
   * dictionary's `/Contents`, in an uncompressed dictionary inside the signed bytes, not
   * redefined later (the defences against signature wrapping).
   */
  byteRangeOk: boolean
  /** The digest of the signed bytes equals the digest the signature signs: nothing changed. */
  intact: boolean
  /** The CMS signature verifies with the signer certificate. */
  signatureValid: boolean
  /** How much of the file the byte ranges cover. */
  coverage: Coverage
  /** The index (oldest first) of the revision the signature covers. */
  signedRevision: number | null
  /** What later revisions changed. */
  modification: ModificationLevel
  /**
   * The objects later revisions list, sorted: at most 1,024 of them (the first by object number),
   * with a warning giving the full count when there are more.
   */
  changedObjects: ObjectRef[]
  /** The digest algorithm, for example `"sha256"`. */
  digestAlgorithm: string | null
  /** The signature algorithm, for example `"sha256WithRSAEncryption"`. */
  signatureAlgorithm: string | null
  /** The signer certificate. */
  signer: CertificateInfo | null
  /** Every certificate of the signature, in file order. */
  chain: CertificateInfo[]
  /**
   * Whether a certification path from the signer to one of `trustAnchors` validates at the
   * validation time (no revocation checking, no network); `null` without anchors.
   */
  trusted: boolean | null
  /** The claimed signing time `/M`, RFC 3339. */
  claimedTime: string | null
  /** `/Name`. */
  name: string | null
  /** `/Reason`. */
  reason: string | null
  /** `/Location`. */
  location: string | null
  /** `/ContactInfo`. */
  contactInfo: string | null
  /** The PAdES baseline level the signature meets. */
  padesLevel: PadesLevel | null
  /** For a certification signature, its DocMDP permissions `P` (1–3). */
  docmdp: number | null
  /** Whether later revisions respect the DocMDP permissions; `null` (not checked yet). */
  docmdpOk: boolean | null
  /** Why the signature is not valid; empty when nothing is wrong. */
  problems: SignatureProblem[]
  /** Observations that do not make the signature invalid. */
  warnings: string[]
}

// ---- functions ---------------------------------------------------------------------------------

/**
 * Signs a document with an invisible PAdES B-B signature in its own incremental update and
 * returns the signed PDF (the original bytes are kept as they are, so earlier signatures stay
 * valid). The document is not changed: open the returned bytes to keep working.
 *
 * It prepares the signature on the libuv thread pool ({@link PdfDocument.prepareSignatureAsync}),
 * awaits the signer, and finishes the file ({@link PreparedSignature.finishAsync}). When an
 * explicit `contentsReserve` is too small, it prepares once more with the size needed, before the
 * signer is called.
 *
 * ```js
 * const signer = LocalSigner.fromPkcs12(await readFile('signer.p12'), password)
 * const signed = await signPdf(doc, { signer, reason: 'Approved', location: 'Berlin' })
 * ```
 *
 * @throws {FolioxideError} the errors of {@link PdfDocument.prepareSignature};
 *   `E_SIGNATURE_INVALID` when the signer's value does not verify with its certificate;
 *   `E_CRYPTO` when an external signer throws (its error is the `cause`); `E_INVALID_ARGUMENT`
 *   when `doc` is not a {@link PdfDocument}, the signer is neither a {@link LocalSigner} nor an
 *   {@link ExternalSigner}, or it returns something that is not bytes.
 */
export declare function signPdf(doc: PdfDocument, options: SignPdfOptions): Promise<Buffer>

/**
 * The fail-safe verdict for accepting a signed document from a report of
 * {@link PdfDocument.verifySignatures}: the signature itself is sound (`byteRangeOk`, `intact`,
 * `signatureValid`, a field name, no problems, coverage `'entireFile'` or `'entireRevision'`)
 * **and** what was appended after the signed revision is at most `maxModification`.
 *
 * The signature checks alone do not detect content changed after signing (an incremental saving
 * or shadow attack): only `modification` does. The default `'formFilling'` accepts later
 * signatures (sequential signing); `'ltaUpdates'` accepts only metadata and invisible signature
 * fields, `'none'` nothing. Trust is separate: also require `report.trusted === true`.
 *
 * **`'formFilling'` includes visible signature appearances added after signing**, which can cover
 * signed content: a new visible signature field with an appearance (signed or still empty), or
 * the appearance a later signature gives the field it signs. pyHanko and Acrobat allow this at the
 * same level; it is inherent to sequential signing in PDF. No level accepts later signatures while
 * refusing visible ones (a later signature, visible or not, is `'formFilling'`), so when no further
 * signer is expected, `'ltaUpdates'` is the strict choice. A signature field that stays unsigned
 * may change only its field flags: an appearance added to it is `'other'`.
 *
 * The AcroForm is checked against an exact whitelist: after signing, a later revision may only
 * add new top-level signature fields to `/Fields`, change `/SigFlags` as signing requires (which
 * no signing after a signature does, so any change is `'other'`, as in pyHanko), and add new
 * `/DR` resource names that the signed revision does not name. Everything else is `'other'`: any
 * change to `/NeedAppearances` (removing it too, also when a later signer removes it while
 * signing, as pyHanko's signer does; pyHanko then reports `'formFilling'`), any change to `/DA`
 * (adding one too), any change to `/Q`, and changing or removing a `/DR` resource name. The
 * signed revision names every name in a `/DA` of the AcroForm, its fields and widgets and every
 * annotation on every page (with the `/DA` it inherits), and every name in an appearance stream of those without `/Resources`
 * of its own; when these cannot all be read within the limits, no new `/DR` name is allowed.
 * Residual risk: names that a form XObject nested in an appearance stream uses, and names a viewer
 * looks up in `/DR` after failing to find them in an appearance stream's own resources, are not
 * read.
 *
 * ```js
 * const reports = await doc.verifySignatures({ trustAnchors: [root] })
 * const ok = reports.length > 0 && reports.every((r) => isSignatureAcceptable(r) && r.trusted === true)
 * ```
 *
 * @throws {FolioxideError} `E_INVALID_ARGUMENT` for an unknown `maxModification` or a report that
 *   is not an object.
 */
export declare function isSignatureAcceptable(
  report: SignatureReport,
  maxModification?: ModificationLevel,
): boolean

/**
 * Formats a `Date` as a PDF date string (ISO 32000-2 §7.9.4) in UTC, such as
 * `"D:20261010073000Z"`. Milliseconds are dropped (PDF dates have whole seconds).
 *
 * @throws {FolioxideError} `E_INVALID_ARGUMENT` for an invalid `Date` or a year outside 0–9999.
 */
export declare function toPdfDate(date: Date): string

/**
 * Parses a PDF date string (ISO 32000-2 §7.9.4), as {@link PdfDocument.getInfo} returns it, into
 * a `Date`; `null` when the text is not a date. Parsing is lenient: partial dates such as
 * `"D:2026"`, a missing `D:` and the offset forms real files use are accepted. A date without a
 * UT offset is read as local time.
 */
export declare function fromPdfDate(text: string): Date | null

/**
 * Returns the version of the native Folioxide library, for example `"0.1.0"`.
 *
 * It always equals the version of the `folioxide` npm package, so it can be used to check that the
 * JavaScript wrapper and the native addon come from the same release.
 *
 * @returns The semantic version `MAJOR.MINOR.PATCH`.
 */
export declare function version(): string

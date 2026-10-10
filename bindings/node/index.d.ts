/**
 * Folioxide: a pure-Rust PDF editing engine for Node.js.
 *
 * Type declarations for the hand-written facade (`index.js` for CommonJS, `index.mjs` for ESM).
 *
 * The plain objects the API returns ({@link PageInfo}, {@link DocInfo}, {@link Diagnostic}) have
 * the JSON shape of the Rust core's serde DTOs (`camelCase` names, absent entries left out), so a
 * Tauri app built on the same core sees the same JSON.
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
 * - `E_FONT`, `E_IMAGE`, `E_CRYPTO`, `E_KEY_LOAD`, `E_CERTIFICATE`,
 *   `E_SIGNATURE_PLACEHOLDER_TOO_SMALL`, `E_SIGNATURE_INVALID`, `E_DOC_MDP_FORBIDS`,
 *   `E_TIMESTAMP_INVALID`: fonts, images and signatures (later releases).
 * - `E_IO`: an I/O operation failed.
 * - `E_BUSY`: a synchronous method was called while an asynchronous one (`saveAsync`,
 *   `saveIncrementalAsync`) is using the document; await its promise first.
 * - `E_CLOSED`: a method was called on a document after {@link PdfDocument.close}.
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
   * Structured details, when there are any. An argument that the native addon could not
   * convert has the napi status here (`{ status: 'NumberExpected' }`).
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
}

// ---- functions ---------------------------------------------------------------------------------

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

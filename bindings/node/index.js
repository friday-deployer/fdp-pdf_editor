'use strict'

/**
 * Folioxide: a pure-Rust PDF editing engine for Node.js.
 *
 * This hand-written facade is the package's public API (CommonJS entry point; `index.mjs` is the
 * ESM entry point and re-exports the same values). It wraps the loader that `napi build`
 * generates (`binding.js`), which picks the native addon for the current platform from the
 * `@folioxide/binding-<platform>` packages. The facade
 *
 * - turns every error into a {@link FolioxideError} whose `code` is an `E_*` code,
 * - checks argument types before they reach the native addon,
 * - accepts `Date` objects for the dates of {@link PdfDocument#setInfo}, and offers
 *   {@link toPdfDate} and {@link fromPdfDate} to convert between `Date` and PDF date strings.
 *
 * The plain objects it returns (`PageInfo`, `DocInfo`, `Diagnostic`) have the JSON shape of the
 * Rust core's serde DTOs, so a Tauri app built on the same core sees the same JSON.
 *
 * @module folioxide
 */

const { types } = require('node:util')

const binding = require('./binding.js')

/** Error codes have this form: `E_` and an upper-case identifier. */
const ERROR_CODE = /^E_[A-Z0-9_]+$/

/**
 * The error every function and method of this package throws (or rejects with).
 *
 * `code` is a stable, machine-readable `E_*` code (see the `ErrorCode` type in `index.d.ts`):
 * the Rust core's `ErrorCode` with an `E_` prefix (`E_SYNTAX`, `E_PAGE_OUT_OF_RANGE`, …),
 * `E_BUSY` when a synchronous method is called while an asynchronous one is using the
 * document, or `E_CLOSED` after {@link PdfDocument#close}. Messages never contain passwords or
 * key material.
 */
class FolioxideError extends Error {
  /**
   * @param {string} code The `E_*` code.
   * @param {string} message A human-readable description.
   * @param {{ cause?: unknown, details?: Record<string, unknown> }} [options] The error that
   *   caused this one, and structured details.
   */
  constructor(code, message, options) {
    super(message, options && 'cause' in options ? { cause: options.cause } : undefined)
    /** @type {string} */
    this.name = 'FolioxideError'
    /** @type {string} */
    this.code = code
    if (options && options.details !== undefined) {
      /** @type {Record<string, unknown> | undefined} */
      this.details = options.details
    }
  }
}

/**
 * An `E_INVALID_ARGUMENT` error.
 *
 * @param {string} message
 * @returns {FolioxideError}
 */
function invalidArgument(message) {
  return new FolioxideError('E_INVALID_ARGUMENT', message)
}

/**
 * Turns an error thrown by the native addon into a {@link FolioxideError}.
 *
 * The addon sets `code` to an `E_*` code itself. Errors napi-rs raises while converting
 * arguments carry a napi status instead (`InvalidArg`, `NumberExpected`, …): they become
 * `E_INVALID_ARGUMENT`, with the status in `details.status`.
 *
 * @param {unknown} err
 * @returns {FolioxideError}
 */
function toFolioxideError(err) {
  if (err instanceof FolioxideError) {
    return err
  }
  const message = err instanceof Error ? err.message : String(err)
  const code = err !== null && typeof err === 'object' ? /** @type {any} */ (err).code : undefined
  if (typeof code === 'string' && ERROR_CODE.test(code)) {
    return new FolioxideError(code, message, { cause: err })
  }
  return new FolioxideError('E_INVALID_ARGUMENT', message, {
    cause: err,
    details: typeof code === 'string' ? { status: code } : undefined,
  })
}

/**
 * Calls the native addon and converts what it throws.
 *
 * @template T
 * @param {() => T} fn
 * @returns {T}
 */
function callNative(fn) {
  try {
    return fn()
  } catch (err) {
    throw toFolioxideError(err)
  }
}

/**
 * Awaits a native promise and converts what it rejects with.
 *
 * @template T
 * @param {() => Promise<T>} fn
 * @returns {Promise<T>}
 */
async function callNativeAsync(fn) {
  try {
    return await fn()
  } catch (err) {
    throw toFolioxideError(err)
  }
}

/**
 * @param {unknown} value
 * @param {string} name
 */
function checkBytes(value, name) {
  if (!types.isUint8Array(value)) {
    throw invalidArgument(`${name} must be a Uint8Array or a Buffer`)
  }
}

/**
 * @param {unknown} value
 * @param {string} name
 */
function checkObject(value, name) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidArgument(`${name} must be an object`)
  }
}

/**
 * @param {unknown} value
 * @param {string} name
 */
function checkOptionalObject(value, name) {
  if (value !== undefined && value !== null) {
    checkObject(value, `${name}, when given,`)
  }
}

/**
 * @param {unknown} value
 * @param {string} name
 */
function checkNumber(value, name) {
  if (typeof value !== 'number') {
    throw invalidArgument(`${name} must be a number`)
  }
}

/** Passed by the static factories so that `new PdfDocument()` cannot be called directly. */
const CONSTRUCT = Symbol('PdfDocument.construct')

/**
 * A PDF document, opened from bytes ({@link PdfDocument.open}, {@link PdfDocument.openAsync})
 * or created empty ({@link PdfDocument.create}).
 *
 * Page indices are 0-based. Synchronous methods never block: while an asynchronous method
 * (`saveAsync`, `saveIncrementalAsync`) is using the document, they throw `E_BUSY`; await the
 * promise first.
 *
 * The native memory a document holds is reported to V8, so unreferenced documents are
 * collected in time; {@link PdfDocument#close} (or `using`, through `Symbol.dispose`) frees it
 * at once.
 */
class PdfDocument {
  /** The native `PdfDocument` (`binding.js`). */
  #native

  /**
   * Use {@link PdfDocument.open}, {@link PdfDocument.openAsync} or {@link PdfDocument.create}.
   *
   * @param {symbol} token
   * @param {import('./binding.js').PdfDocument} native
   */
  constructor(token, native) {
    if (token !== CONSTRUCT) {
      throw invalidArgument(
        'PdfDocument cannot be constructed directly: use PdfDocument.open(), PdfDocument.openAsync() or PdfDocument.create()',
      )
    }
    this.#native = native
  }

  /**
   * Opens a PDF file from its bytes, which are copied once (the buffer may be reused
   * afterwards). Opening reads the file's structure only.
   *
   * @param {Uint8Array} data The file.
   * @param {import('./index').OpenOptions} [options] `strict: true` refuses damaged files
   *   instead of repairing them.
   * @returns {PdfDocument}
   */
  static open(data, options) {
    checkBytes(data, 'data')
    checkOptionalObject(options, 'options')
    return new PdfDocument(
      CONSTRUCT,
      callNative(() => binding.PdfDocument.open(data, options)),
    )
  }

  /**
   * Like {@link PdfDocument.open}, on the libuv thread pool.
   *
   * @param {Uint8Array} data The file.
   * @param {import('./index').OpenOptions} [options]
   * @returns {Promise<PdfDocument>}
   */
  static async openAsync(data, options) {
    checkBytes(data, 'data')
    checkOptionalObject(options, 'options')
    const native = await callNativeAsync(() => binding.PdfDocument.openAsync(data, options))
    return new PdfDocument(CONSTRUCT, native)
  }

  /**
   * A new, empty PDF 1.7 document with no pages. It can be saved with {@link PdfDocument#save}
   * only.
   *
   * @returns {PdfDocument}
   */
  static create() {
    return new PdfDocument(
      CONSTRUCT,
      callNative(() => binding.PdfDocument.create()),
    )
  }

  /**
   * Frees the document's native memory now instead of when the object is garbage-collected.
   * Afterwards every method throws `E_CLOSED`; an asynchronous operation already started
   * finishes first. Calling it again does nothing.
   */
  close() {
    callNative(() => this.#native.close())
  }

  /** @returns {boolean} Whether {@link PdfDocument#close} was called. */
  get isClosed() {
    return callNative(() => this.#native.isClosed)
  }

  /**
   * @returns {number} An estimate of the native memory the document holds, in bytes, as
   *   reported to V8; 0 once it is closed.
   */
  get nativeMemory() {
    return callNative(() => this.#native.nativeMemory)
  }

  /** @returns {number} The number of pages. */
  get pageCount() {
    return callNative(() => this.#native.pageCount)
  }

  /** @returns {string} The PDF version, such as `"1.7"`. */
  get version() {
    return callNative(() => this.#native.version)
  }

  /** @returns {boolean} Whether the document has changes not saved yet. */
  get isModified() {
    return callNative(() => this.#native.isModified)
  }

  /**
   * The repairs and leniency decisions recorded so far.
   *
   * @returns {import('./index').Diagnostic[]}
   */
  diagnostics() {
    return /** @type {any} */ (callNative(() => this.#native.diagnostics()))
  }

  /**
   * The size, boxes and rotation of a page.
   *
   * @param {number} index The 0-based page index.
   * @returns {import('./index').PageInfo}
   */
  getPage(index) {
    checkNumber(index, 'index')
    return callNative(() => this.#native.getPage(index))
  }

  /**
   * The document information dictionary, decoded.
   *
   * @returns {import('./index').DocInfo}
   */
  getInfo() {
    return callNative(() => this.#native.getInfo())
  }

  /**
   * Changes the document information dictionary: a field that is absent (or `undefined`)
   * keeps the entry, `null` removes it, a value sets it. Dates may be `Date` objects or PDF
   * date strings.
   *
   * @param {import('./index').InfoUpdate} update
   */
  setInfo(update) {
    checkObject(update, 'update')
    /** @type {Record<string, unknown>} */
    const native = { ...update }
    for (const key of ['creationDate', 'modDate']) {
      const value = native[key]
      if (types.isDate(value)) {
        native[key] = toPdfDate(value)
      }
    }
    if (native.custom !== undefined) {
      checkObject(native.custom, 'update.custom')
    }
    callNative(() => this.#native.setInfo(/** @type {any} */ (native)))
  }

  /**
   * Sets the rotation of a page.
   *
   * @param {number} index The 0-based page index.
   * @param {number} degrees Clockwise; a multiple of 90 (negative ones too).
   */
  setPageRotation(index, degrees) {
    checkNumber(index, 'index')
    checkNumber(degrees, 'degrees')
    callNative(() => this.#native.setPageRotation(index, degrees))
  }

  /**
   * Sets the media box or the crop box of a page; `null` removes the crop box.
   *
   * @param {number} index The 0-based page index.
   * @param {'media' | 'crop'} box Which box.
   * @param {import('./index').Rect | null} rect The box in points, or `null`.
   */
  setPageBox(index, box, rect) {
    checkNumber(index, 'index')
    if (box !== 'media' && box !== 'crop') {
      throw invalidArgument(`box must be 'media' or 'crop', not ${JSON.stringify(String(box))}`)
    }
    if (rect !== null) {
      checkObject(rect, 'rect')
    }
    callNative(() => this.#native.setPageBox(index, box, rect))
  }

  /**
   * Writes the whole document again and returns the new file.
   *
   * @param {import('./index').SaveOptions} [options]
   * @returns {Buffer}
   */
  save(options) {
    checkOptionalObject(options, 'options')
    return callNative(() => this.#native.save(options))
  }

  /**
   * Like {@link PdfDocument#save}, on the libuv thread pool.
   *
   * @param {import('./index').SaveOptions} [options]
   * @returns {Promise<Buffer>}
   */
  async saveAsync(options) {
    checkOptionalObject(options, 'options')
    return callNativeAsync(() => this.#native.saveAsync(options))
  }

  /**
   * The original file with the changes appended as an incremental update.
   *
   * @param {import('./index').IncrementalSaveOptions} [options]
   * @returns {Buffer}
   */
  saveIncremental(options) {
    checkOptionalObject(options, 'options')
    return callNative(() => this.#native.saveIncremental(options))
  }

  /**
   * Like {@link PdfDocument#saveIncremental}, on the libuv thread pool.
   *
   * @param {import('./index').IncrementalSaveOptions} [options]
   * @returns {Promise<Buffer>}
   */
  async saveIncrementalAsync(options) {
    checkOptionalObject(options, 'options')
    return callNativeAsync(() => this.#native.saveIncrementalAsync(options))
  }
}

// `using doc = PdfDocument.open(...)` closes the document at the end of the block. Node 20
// before 20.4 has no `Symbol.dispose`; there the method is simply absent.
if (typeof Symbol.dispose === 'symbol') {
  Object.defineProperty(PdfDocument.prototype, Symbol.dispose, {
    value: function dispose() {
      this.close()
    },
    writable: true,
    configurable: true,
  })
}

/**
 * Formats a `Date` as a PDF date string (ISO 32000-2 §7.9.4) in UTC, such as
 * `"D:20261010073000Z"`. Milliseconds are dropped (PDF dates have whole seconds).
 *
 * @param {Date} date A valid date in the years 0 to 9999.
 * @returns {string}
 */
function toPdfDate(date) {
  if (!types.isDate(date) || Number.isNaN(date.getTime())) {
    throw invalidArgument('toPdfDate expects a valid Date')
  }
  const year = date.getUTCFullYear()
  if (year < 0 || year > 9999) {
    throw invalidArgument(`a PDF date has a year from 0 to 9999, not ${year}`)
  }
  /**
   * @param {number} n
   * @param {number} [width]
   */
  const pad = (n, width = 2) => String(n).padStart(width, '0')
  return (
    `D:${pad(year, 4)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
    `${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`
  )
}

/**
 * Parses a PDF date string (ISO 32000-2 §7.9.4) as `getInfo()` returns it, leniently (partial
 * dates such as `"D:2026"`, the offset forms real files use), into a `Date`; `null` when the
 * text is not a date. A date without a UT offset is read as local time.
 *
 * @param {string} text
 * @returns {Date | null}
 */
function fromPdfDate(text) {
  if (typeof text !== 'string') {
    throw invalidArgument('fromPdfDate expects a string')
  }
  const iso = binding.pdfDateToIso(text)
  if (iso === null) {
    return null
  }
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? null : date
}

/**
 * Returns the version of the native Folioxide library, for example `"0.1.0"`.
 *
 * It always equals the version of the `folioxide` npm package, so it can be used to check that the
 * JavaScript wrapper and the native addon come from the same release.
 *
 * @returns {string} The semantic version `MAJOR.MINOR.PATCH`.
 */
function version() {
  return binding.version()
}

module.exports = { FolioxideError, PdfDocument, fromPdfDate, toPdfDate, version }

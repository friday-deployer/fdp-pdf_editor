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
 * - accepts `Date` objects for the dates of {@link PdfDocument#setInfo}, the signing time and
 *   the validation time, and offers {@link toPdfDate} and {@link fromPdfDate} to convert between
 *   `Date` and PDF date strings,
 * - composes the two phases of signing with a signer that may be asynchronous (a KMS, an HSM,
 *   WebCrypto, `node:crypto`) in {@link signPdf}: the native addon prepares and finishes on the
 *   libuv thread pool, and the signer is awaited in JavaScript in between, and so is the timestamp
 *   authority of a PAdES B-T signature (the `timestamp` callback).
 *
 * The plain objects it returns (`PageInfo`, `DocInfo`, `Diagnostic`, `SignatureReport`) have the
 * JSON shape of the Rust core's serde DTOs, so a Tauri app built on the same core sees the same
 * JSON (a certificate's `der` is a `Buffer` here).
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
 * document (or a prepared signature), or `E_CLOSED` after {@link PdfDocument#close} or
 * {@link LocalSigner#close}. Messages never contain passwords or key material.
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
 * The fixed text of the core's placeholder-overflow error (M3 brief §3.2), which carries the
 * sizes `details` exposes.
 */
const PLACEHOLDER_TOO_SMALL = /signature placeholder too small: needed (\d+) bytes, reserved (\d+)/

/**
 * Structured details for an error code, parsed from the native message: `{ needed, reserved }`
 * for `E_SIGNATURE_PLACEHOLDER_TOO_SMALL`.
 *
 * @param {string} code
 * @param {string} message
 * @returns {Record<string, unknown> | undefined}
 */
function detailsOf(code, message) {
  if (code === 'E_SIGNATURE_PLACEHOLDER_TOO_SMALL') {
    const match = PLACEHOLDER_TOO_SMALL.exec(message)
    if (match) {
      return { needed: Number(match[1]), reserved: Number(match[2]) }
    }
  }
  return undefined
}

/**
 * Turns an error thrown by the native addon into a {@link FolioxideError}.
 *
 * The addon sets `code` to an `E_*` code itself. Errors napi-rs raises while converting
 * arguments carry a napi status instead (`InvalidArg`, `NumberExpected`, …): they become
 * `E_INVALID_ARGUMENT`, with the status in `details.status`. An
 * `E_SIGNATURE_PLACEHOLDER_TOO_SMALL` error gets `details.needed` and `details.reserved`.
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
    return new FolioxideError(code, message, { cause: err, details: detailsOf(code, message) })
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

/**
 * @param {unknown} value
 * @param {string} name
 */
function checkString(value, name) {
  if (typeof value !== 'string') {
    throw invalidArgument(`${name} must be a string`)
  }
}

/**
 * Bytes given as a `Uint8Array` (a `Buffer` is one) or an `ArrayBuffer`, as a `Uint8Array`.
 *
 * @param {unknown} value
 * @param {string} name
 * @returns {Uint8Array}
 */
function bytesOf(value, name) {
  if (types.isUint8Array(value)) {
    return value
  }
  if (types.isArrayBuffer(value)) {
    return new Uint8Array(value)
  }
  throw invalidArgument(`${name} must be a Uint8Array, a Buffer or an ArrayBuffer`)
}

/**
 * Optional bytes: `undefined` for `undefined` and `null`.
 *
 * @param {unknown} value
 * @param {string} name
 * @returns {Uint8Array | undefined}
 */
function optionalBytes(value, name) {
  return value === undefined || value === null ? undefined : bytesOf(value, name)
}

/**
 * @param {unknown} value
 * @param {string} name
 */
function checkBytesArray(value, name) {
  if (!Array.isArray(value)) {
    throw invalidArgument(`${name} must be an array of Uint8Array or Buffer`)
  }
  value.forEach((item, i) => checkBytes(item, `${name}[${i}]`))
}

/**
 * A secret (a password, a PEM private key) given as a string or as UTF-8 bytes. Bytes are passed
 * to the native addon as they are, so the caller can wipe them after loading.
 *
 * @param {unknown} value
 * @param {string} name
 */
function checkSecret(value, name) {
  if (typeof value !== 'string' && !types.isUint8Array(value)) {
    throw invalidArgument(`${name} must be a string, or a Uint8Array or Buffer of UTF-8`)
  }
}

/**
 * PEM text given as a string, or as bytes (a `Buffer` read from a file), as a string.
 *
 * @param {unknown} value
 * @param {string} name
 * @returns {string}
 */
function pemText(value, name) {
  if (typeof value === 'string') {
    return value
  }
  if (types.isUint8Array(value)) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('utf8')
  }
  throw invalidArgument(`${name} must be PEM text: a string, or a Uint8Array or Buffer`)
}

/**
 * A date option as a PDF date string: a `Date` is formatted in UTC, a string is passed on (the
 * native addon parses it leniently).
 *
 * @param {unknown} value
 * @param {string} name
 * @returns {string}
 */
function pdfDateOption(value, name) {
  if (types.isDate(value)) {
    if (Number.isNaN(value.getTime())) {
      throw invalidArgument(`${name} is an invalid Date`)
    }
    return toPdfDate(value)
  }
  if (typeof value === 'string') {
    return value
  }
  throw invalidArgument(`${name} must be a Date or a PDF date string`)
}

/**
 * Passed by the static factories so that `new PdfDocument()`, `new LocalSigner()` and
 * `new PreparedSignature()` cannot be called directly.
 */
const CONSTRUCT = Symbol('folioxide.construct')

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

  /**
   * The first phase of signing: builds the incremental update that adds a PAdES signature
   * (invisible, or visible with `appearance`; a certification with `certify`), digests the signed
   * byte ranges and builds the bytes to sign. The document is not changed. Sign
   * {@link PreparedSignature#toBeSigned} with the key of the first certificate, then call
   * {@link PreparedSignature#finish} (after {@link PreparedSignature#timestampRequest} for B-T);
   * {@link signPdf} does all of it.
   *
   * @param {import('./index').PrepareSignatureOptions} options `signingTime` defaults to now.
   * @returns {PreparedSignature}
   */
  prepareSignature(options) {
    const native = nativePrepareOptions(options)
    return new PreparedSignature(
      CONSTRUCT,
      callNative(() => this.#native.prepareSignature(native)),
    )
  }

  /**
   * Like {@link PdfDocument#prepareSignature}, on the libuv thread pool.
   *
   * @param {import('./index').PrepareSignatureOptions} options
   * @returns {Promise<PreparedSignature>}
   */
  async prepareSignatureAsync(options) {
    const native = nativePrepareOptions(options)
    const prepared = await callNativeAsync(() => this.#native.prepareSignatureAsync(native))
    return new PreparedSignature(CONSTRUCT, prepared)
  }

  /**
   * Verifies every signature of the document on the libuv thread pool: one report per
   * signature dictionary, in signing order.
   *
   * @param {import('./index').VerifyOptions} [options] `validationTime` defaults to now; `null`
   *   validates at a trusted signature timestamp's time, else at each signer's claimed signing
   *   time. `timestampTrustAnchors` default to `trustAnchors`.
   * @returns {Promise<import('./index').SignatureReport[]>}
   */
  async verifySignatures(options) {
    checkOptionalObject(options, 'options')
    const { trustAnchors, extraCertificates, validationTime, timestampTrustAnchors } = options ?? {}
    if (trustAnchors !== undefined) {
      checkBytesArray(trustAnchors, 'options.trustAnchors')
    }
    if (extraCertificates !== undefined) {
      checkBytesArray(extraCertificates, 'options.extraCertificates')
    }
    if (timestampTrustAnchors !== undefined) {
      checkBytesArray(timestampTrustAnchors, 'options.timestampTrustAnchors')
    }
    const native = {
      trustAnchors,
      extraCertificates,
      timestampTrustAnchors,
      validationTime:
        validationTime === null
          ? undefined
          : pdfDateOption(validationTime ?? new Date(), 'options.validationTime'),
    }
    const reports = await callNativeAsync(() => this.#native.verifySignatures(native))
    return /** @type {any} */ (reports)
  }
}

/**
 * The native options of `prepareSignature`: the types checked, the signing time as a PDF date
 * string (default now).
 *
 * @param {unknown} options
 * @returns {import('./binding.js').PrepareSignatureOptions}
 */
function nativePrepareOptions(options) {
  checkObject(options, 'options')
  const { signingTime, certify, appearance, tsaReserve, ...rest } = /** @type {Record<string, any>} */ (
    options
  )
  checkBytesArray(rest.certificateChain, 'options.certificateChain')
  checkString(rest.algorithm, 'options.algorithm')
  checkOptionalObject(rest.field, 'options.field')
  if (rest.contentsReserve !== undefined && rest.contentsReserve !== null) {
    checkNumber(rest.contentsReserve, 'options.contentsReserve')
  }
  /** @type {Record<string, any>} */
  const native = {
    ...rest,
    signingTime: pdfDateOption(signingTime ?? new Date(), 'options.signingTime'),
  }
  if (certify !== undefined && certify !== null) {
    checkNumber(certify, 'options.certify')
    native.certify = certify
  }
  if (tsaReserve !== undefined && tsaReserve !== null) {
    checkNumber(tsaReserve, 'options.tsaReserve')
    native.tsaReserve = tsaReserve
  }
  if (appearance !== undefined && appearance !== null) {
    native.appearance = nativeAppearance(appearance)
  }
  return /** @type {any} */ (native)
}

/**
 * A rectangle given as `[llx, lly, urx, ury]` or as a `Rect`, as a `Rect`. The native addon
 * checks the numbers are finite, the core that the rectangle has an area and meets the page.
 *
 * @param {unknown} value
 * @param {string} name
 * @returns {import('./index').Rect}
 */
function nativeRect(value, name) {
  if (Array.isArray(value)) {
    if (value.length !== 4 || !value.every((v) => typeof v === 'number')) {
      throw invalidArgument(`${name} must be [llx, lly, urx, ury] (four numbers) or a Rect`)
    }
    const [llx, lly, urx, ury] = value
    return { llx, lly, urx, ury }
  }
  if (value === null || typeof value !== 'object') {
    throw invalidArgument(`${name} must be [llx, lly, urx, ury] (four numbers) or a Rect`)
  }
  const rect = /** @type {Record<string, unknown>} */ (value)
  for (const key of ['llx', 'lly', 'urx', 'ury']) {
    checkNumber(rect[key], `${name}.${key}`)
  }
  return /** @type {any} */ ({ llx: rect.llx, lly: rect.lly, urx: rect.urx, ury: rect.ury })
}

/**
 * The native form of `options.appearance`: the types checked, the rectangle as a `Rect`.
 *
 * @param {unknown} value
 * @returns {import('./binding.js').SignatureAppearanceOptions}
 */
function nativeAppearance(value) {
  checkObject(value, 'options.appearance')
  const { rect, lines, font, fontSize, image, imagePosition, borderWidth } = /** @type {Record<string, any>} */ (
    value
  )
  /** @type {Record<string, any>} */
  const native = {}
  if (rect !== undefined && rect !== null) {
    native.rect = nativeRect(rect, 'options.appearance.rect')
  }
  if (lines !== undefined && lines !== null) {
    if (!Array.isArray(lines) || !lines.every((line) => typeof line === 'string')) {
      throw invalidArgument('options.appearance.lines must be an array of strings')
    }
    native.lines = lines
  }
  if (font !== undefined && font !== null) {
    checkString(font, 'options.appearance.font')
    native.font = font
  }
  if (fontSize !== undefined && fontSize !== null) {
    checkNumber(fontSize, 'options.appearance.fontSize')
    native.fontSize = fontSize
  }
  if (image !== undefined && image !== null) {
    checkBytes(image, 'options.appearance.image')
    native.image = image
  }
  if (imagePosition !== undefined && imagePosition !== null) {
    checkString(imagePosition, 'options.appearance.imagePosition')
    native.imagePosition = imagePosition
  }
  if (borderWidth !== undefined && borderWidth !== null) {
    checkNumber(borderWidth, 'options.appearance.borderWidth')
    native.borderWidth = borderWidth
  }
  return /** @type {any} */ (native)
}

/**
 * The native form of timestamp request options: the types checked, a numeric nonce as a bigint.
 *
 * @param {unknown} options
 * @param {string} name
 * @returns {import('./binding.js').TimestampRequestOptions | undefined}
 */
function nativeTimestampOptions(options, name) {
  checkOptionalObject(options, name)
  if (options === undefined || options === null) {
    return undefined
  }
  const { digest, policy, nonce } = /** @type {Record<string, any>} */ (options)
  /** @type {Record<string, any>} */
  const native = {}
  if (digest !== undefined && digest !== null) {
    checkString(digest, `${name}.digest`)
    native.digest = digest
  }
  if (policy !== undefined && policy !== null) {
    checkString(policy, `${name}.policy`)
    native.policy = policy
  }
  if (nonce !== undefined && nonce !== null) {
    if (typeof nonce === 'bigint') {
      native.nonce = nonce
    } else if (typeof nonce === 'number' && Number.isSafeInteger(nonce) && nonce >= 1) {
      native.nonce = BigInt(nonce)
    } else {
      throw invalidArgument(`${name}.nonce must be a bigint from 1 to 2^64 - 1`)
    }
  }
  return /** @type {any} */ (native)
}

/**
 * A prepared signature: the file with the placeholders, and the bytes to sign. Made by
 * {@link PdfDocument#prepareSignature} or {@link PreparedSignature.deserialize}.
 *
 * The first of {@link PreparedSignature#finish}, `finishAsync`, `embedCms` and `embedCmsAsync`
 * **that succeeds** takes the prepared file; a later call throws `E_INVALID_ARGUMENT`. A refused
 * value or CMS (`E_SIGNATURE_INVALID`, for example) leaves it as it was, so the caller can try
 * again with a corrected one. While `finishAsync` or `embedCmsAsync` runs, the other finishing
 * methods and `serialize` throw `E_BUSY`.
 */
class PreparedSignature {
  /** The native `PreparedSignature` (`binding.js`). */
  #native

  /**
   * Use {@link PdfDocument#prepareSignature} or {@link PreparedSignature.deserialize}.
   *
   * @param {symbol} token
   * @param {import('./binding.js').PreparedSignature} native
   */
  constructor(token, native) {
    if (token !== CONSTRUCT) {
      throw invalidArgument(
        'PreparedSignature cannot be constructed directly: use PdfDocument.prepareSignature() or PreparedSignature.deserialize()',
      )
    }
    this.#native = native
  }

  /**
   * Reads what {@link PreparedSignature#serialize} wrote, checking every invariant again.
   *
   * @param {Uint8Array} data
   * @returns {PreparedSignature}
   */
  static deserialize(data) {
    checkBytes(data, 'data')
    return new PreparedSignature(
      CONSTRUCT,
      callNative(() => binding.PreparedSignature.deserialize(data)),
    )
  }

  /** @returns {Buffer} The bytes to sign: the DER signed attributes. */
  get toBeSigned() {
    return callNative(() => this.#native.toBeSigned)
  }

  /** @returns {Buffer} The digest of `toBeSigned`, for "sign digest" APIs. */
  get toBeSignedDigest() {
    return callNative(() => this.#native.toBeSignedDigest)
  }

  /** @returns {Buffer} The DER `DigestInfo` of `toBeSignedDigest`, for raw RSA signing. */
  get toBeSignedDigestInfo() {
    return callNative(() => this.#native.toBeSignedDigestInfo)
  }

  /** @returns {import('./index').DigestAlg} The digest algorithm of the signature. */
  get digestAlgorithm() {
    return callNative(() => this.#native.digestAlgorithm)
  }

  /** @returns {import('./index').SigAlg} The signature algorithm of the signer's key. */
  get algorithm() {
    return callNative(() => this.#native.algorithm)
  }

  /** @returns {import('./index').SubFilter} The `/SubFilter` of the signature dictionary. */
  get subFilter() {
    return callNative(() => this.#native.subFilter)
  }

  /** @returns {number} The bytes of DER the `/Contents` placeholder holds. */
  get contentsCapacity() {
    return callNative(() => this.#native.contentsCapacity)
  }

  /** @returns {number[]} `[0, a, b, c]`: the signed byte ranges of the finished file. */
  get byteRange() {
    return callNative(() => this.#native.byteRange)
  }

  /** @returns {string[]} Observations from preparing. */
  get warnings() {
    return callNative(() => this.#native.warnings)
  }

  /** @returns {boolean} Whether `finish` or `embedCms` (or their async forms) succeeded. */
  get isFinished() {
    return callNative(() => this.#native.isFinished)
  }

  /**
   * The DER `TimeStampReq` (RFC 3161) for a signature timestamp over `signature`, the value
   * {@link PreparedSignature#finish} will embed: send it to a TSA, then call
   * `finish(signature, timestampResponse)`. The value is verified first; the request is
   * remembered for `finish` (not by `serialize`). Once it is remembered, `finish` without a
   * response throws `E_INVALID_ARGUMENT`: call {@link PreparedSignature#discardTimestampRequest}
   * to finish without a signature timestamp after all.
   *
   * @param {Uint8Array} signature The signature value over `toBeSigned`.
   * @param {import('./index').TimestampRequestOptions} [options] `nonce` is a bigint from 1 to
   *   2^64 - 1 (a positive safe integer is accepted too); default random.
   * @returns {Buffer}
   */
  timestampRequest(signature, options) {
    checkBytes(signature, 'signature')
    const native = nativeTimestampOptions(options, 'options')
    return callNative(() => this.#native.timestampRequest(signature, native))
  }

  /**
   * Forgets the request {@link PreparedSignature#timestampRequest} remembered, so that
   * `finish(signature)` without a response finishes the file without a signature timestamp
   * (PAdES B-B), for example when the TSA could not be reached. Without a remembered request it
   * does nothing.
   */
  discardTimestampRequest() {
    callNative(() => this.#native.discardTimestampRequest())
  }

  /**
   * Finishes the file with the signature value over `toBeSigned`: returns the signed PDF. With
   * `timestampResponse`, the TSA's response to the request of
   * {@link PreparedSignature#timestampRequest} (or to `timestampRequest`), the token is validated
   * and embedded as the signature timestamp (PAdES B-T). A refused value or response leaves the
   * prepared signature as it was.
   *
   * After `timestampRequest`, a `finish` without `timestampResponse` (omitted or `null`) throws
   * `E_INVALID_ARGUMENT`, so that a forgotten response never gives a file without a timestamp;
   * {@link PreparedSignature#discardTimestampRequest} first finishes without one.
   *
   * @param {Uint8Array} signature RSA: the modulus length; ECDSA: DER or IEEE P1363.
   * @param {Uint8Array} [timestampResponse] The TSA's DER `TimeStampResp` (an `ArrayBuffer` is
   *   accepted too).
   * @param {Uint8Array} [timestampRequest] The DER `TimeStampReq` it answers; default the one
   *   `timestampRequest` returned last.
   * @returns {Buffer}
   */
  finish(signature, timestampResponse, timestampRequest) {
    checkBytes(signature, 'signature')
    const response = optionalBytes(timestampResponse, 'timestampResponse')
    const request = optionalBytes(timestampRequest, 'timestampRequest')
    return callNative(() => this.#native.finish(signature, response, request))
  }

  /**
   * Like {@link PreparedSignature#finish}, on the libuv thread pool (the same rule about a
   * remembered timestamp request without a response).
   *
   * @param {Uint8Array} signature
   * @param {Uint8Array} [timestampResponse]
   * @param {Uint8Array} [timestampRequest]
   * @returns {Promise<Buffer>}
   */
  async finishAsync(signature, timestampResponse, timestampRequest) {
    checkBytes(signature, 'signature')
    const response = optionalBytes(timestampResponse, 'timestampResponse')
    const request = optionalBytes(timestampRequest, 'timestampRequest')
    return callNativeAsync(() => this.#native.finishAsync(signature, response, request))
  }

  /**
   * Finishes the file with a whole CMS that signs the prepared byte ranges. A refused CMS leaves
   * the prepared signature as it was.
   *
   * @param {Uint8Array} cms A DER `ContentInfo` (`SignedData`).
   * @returns {Buffer}
   */
  embedCms(cms) {
    checkBytes(cms, 'cms')
    return callNative(() => this.#native.embedCms(cms))
  }

  /**
   * Like {@link PreparedSignature#embedCms}, on the libuv thread pool.
   *
   * @param {Uint8Array} cms
   * @returns {Promise<Buffer>}
   */
  async embedCmsAsync(cms) {
    checkBytes(cms, 'cms')
    return callNativeAsync(() => this.#native.embedCmsAsync(cms))
  }

  /**
   * The prepared signature in the core's versioned binary form, for
   * {@link PreparedSignature.deserialize}.
   *
   * @returns {Buffer}
   */
  serialize() {
    return callNative(() => this.#native.serialize())
  }
}

/**
 * A private key held in memory with its certificate chain, loaded from PKCS#12
 * ({@link LocalSigner.fromPkcs12}) or PEM ({@link LocalSigner.fromPem}).
 *
 * The key is wiped from memory by {@link LocalSigner#close} (or `using`, through
 * `Symbol.dispose`), or when the object is garbage-collected if that comes first. The native
 * addon wipes its own copies of the password and the PEM key once the key is loaded; JavaScript
 * strings cannot be wiped, so pass secrets as a `Uint8Array` and `fill(0)` it after loading to
 * keep them out of the heap.
 */
class LocalSigner {
  /** The native `LocalSigner` (`binding.js`). */
  #native

  /**
   * Use {@link LocalSigner.fromPkcs12} or {@link LocalSigner.fromPem}.
   *
   * @param {symbol} token
   * @param {import('./binding.js').LocalSigner} native
   */
  constructor(token, native) {
    if (token !== CONSTRUCT) {
      throw invalidArgument(
        'LocalSigner cannot be constructed directly: use LocalSigner.fromPkcs12() or LocalSigner.fromPem()',
      )
    }
    this.#native = native
  }

  /**
   * Loads a key and its certificate chain from a PKCS#12 (`.p12`, `.pfx`) file.
   *
   * @param {Uint8Array} data The file.
   * @param {string | Uint8Array} password Its password, as a string or as UTF-8 bytes.
   * @returns {LocalSigner}
   */
  static fromPkcs12(data, password) {
    checkBytes(data, 'data')
    checkSecret(password, 'password')
    return new LocalSigner(
      CONSTRUCT,
      callNative(() => binding.LocalSigner.fromPkcs12(data, password)),
    )
  }

  /**
   * Loads a key from PEM and its certificates from one or more PEM `CERTIFICATE` blocks.
   *
   * @param {string | Uint8Array} keyPem The private key (bytes are read in place, not copied
   *   into a string).
   * @param {string | Uint8Array} certsPem The certificates, in any order.
   * @param {string | Uint8Array} [keyPassword] The password of an encrypted key.
   * @returns {LocalSigner}
   */
  static fromPem(keyPem, certsPem, keyPassword) {
    if (typeof keyPem !== 'string' && !types.isUint8Array(keyPem)) {
      throw invalidArgument('keyPem must be PEM text: a string, or a Uint8Array or Buffer')
    }
    const certs = pemText(certsPem, 'certsPem')
    if (keyPassword !== undefined && keyPassword !== null) {
      checkSecret(keyPassword, 'keyPassword')
    }
    return new LocalSigner(
      CONSTRUCT,
      callNative(() => binding.LocalSigner.fromPem(keyPem, certs, keyPassword ?? undefined)),
    )
  }

  /**
   * Wipes the key from memory now, instead of when the object is garbage-collected. Every
   * method then throws `E_CLOSED`; a `signAsync` already running finishes first. Calling it
   * again does nothing.
   */
  close() {
    callNative(() => this.#native.close())
  }

  /** @returns {boolean} Whether {@link LocalSigner#close} was called. */
  get isClosed() {
    return callNative(() => this.#native.isClosed)
  }

  /** @returns {Buffer[]} The DER certificates, the signer's first. */
  get certificateChain() {
    return callNative(() => this.#native.certificateChain)
  }

  /** @returns {import('./index').SigAlg} The signature algorithm of the key. */
  get algorithm() {
    return callNative(() => this.#native.algorithm)
  }

  /** @returns {import('./index').DigestAlg} The digest used when none is given. */
  get defaultDigest() {
    return callNative(() => this.#native.defaultDigest)
  }

  /**
   * Signs `data`, hashing it with `digest` (default {@link LocalSigner#defaultDigest}).
   *
   * @param {Uint8Array} data
   * @param {import('./index').DigestAlg} [digest]
   * @returns {Buffer}
   */
  sign(data, digest) {
    checkBytes(data, 'data')
    return callNative(() => this.#native.sign(data, digest))
  }

  /**
   * Like {@link LocalSigner#sign}, on the libuv thread pool.
   *
   * @param {Uint8Array} data
   * @param {import('./index').DigestAlg} [digest]
   * @returns {Promise<Buffer>}
   */
  async signAsync(data, digest) {
    checkBytes(data, 'data')
    return callNativeAsync(() => this.#native.signAsync(data, digest))
  }
}

/**
 * The signature value an external signer returned, as a `Uint8Array`.
 *
 * @param {unknown} value
 * @returns {Uint8Array}
 */
function signatureValue(value) {
  if (types.isUint8Array(value)) {
    return value
  }
  if (types.isArrayBuffer(value)) {
    return new Uint8Array(value)
  }
  throw invalidArgument(
    'options.signer.sign() must return (or resolve to) a Uint8Array, a Buffer or an ArrayBuffer',
  )
}

/**
 * The timestamp token budget `signPdf` prepares with when a `timestamp` callback is given and
 * `tsaReserve` is not: the core's `DEFAULT_TSA_RESERVE` (M4 brief D-8).
 */
const DEFAULT_TSA_RESERVE = 8192

/**
 * The margin added to the size a too-large token needed, when `signPdf` signs once more: the
 * core's `TSA_RETRY_MARGIN` (M4 brief §3.1, D-8). A second token can differ by a few bytes.
 */
const TSA_RETRY_MARGIN = 1024

/**
 * The response a `timestamp` callback returned, as a `Uint8Array`. A throw becomes
 * `E_TIMESTAMP_INVALID` with the error as the cause. The callback gets a copy of the request:
 * what it does with its buffer (a `fill(0)`, a pool that reuses it) cannot change the request
 * `finish` checks the response against.
 *
 * @param {(request: Buffer) => unknown} timestamp
 * @param {Buffer} request
 * @returns {Promise<Uint8Array>}
 */
async function askTsa(timestamp, request) {
  let response
  try {
    response = await timestamp(Buffer.from(request))
  } catch (err) {
    throw new FolioxideError('E_TIMESTAMP_INVALID', 'options.timestamp() failed (see the cause)', { cause: err })
  }
  if (types.isUint8Array(response)) {
    return response
  }
  if (types.isArrayBuffer(response)) {
    return new Uint8Array(response)
  }
  throw invalidArgument(
    'options.timestamp() must return (or resolve to) the DER TimeStampResp: a Uint8Array, a Buffer or an ArrayBuffer',
  )
}

/**
 * Whether `err` is the error of a finish whose CMS (with its timestamp token) did not fit the
 * placeholder.
 *
 * @param {unknown} err
 * @returns {err is FolioxideError}
 */
function isOverflow(err) {
  return (
    err instanceof FolioxideError &&
    err.code === 'E_SIGNATURE_PLACEHOLDER_TOO_SMALL' &&
    typeof err.details?.needed === 'number'
  )
}

/**
 * Signs a document: prepares the signature on the libuv thread pool, awaits the signer, and
 * finishes the file. Returns the signed PDF (the original bytes followed by one incremental
 * update); the document is not changed.
 *
 * When an explicit `contentsReserve` is too small for the signature, it prepares once more with
 * the size needed, before the signer is called.
 *
 * With a `timestamp` callback (PAdES B-T) it prepares with `tsaReserve` (default 8192), awaits
 * the signer, makes the timestamp request for the signature value, awaits the callback with it,
 * and finishes with the response. When the token does not fit the placeholder, it does all of
 * that **once more** with a placeholder of the size needed (plus 1024 bytes): the signer and the
 * callback may each be called twice.
 *
 * @param {PdfDocument} doc
 * @param {import('./index').SignPdfOptions} options
 * @returns {Promise<Buffer>}
 */
async function signPdf(doc, options) {
  if (!(doc instanceof PdfDocument)) {
    throw invalidArgument('doc must be a PdfDocument')
  }
  checkObject(options, 'options')
  const { signer, timestamp, timestampOptions, ...rest } = /** @type {Record<string, any>} */ (options)
  if (timestamp !== undefined && timestamp !== null && typeof timestamp !== 'function') {
    throw invalidArgument('options.timestamp must be a function that sends a DER TimeStampReq to a TSA')
  }
  if (timestampOptions !== undefined && timestampOptions !== null) {
    if (typeof timestamp !== 'function') {
      throw invalidArgument('options.timestampOptions needs options.timestamp')
    }
    nativeTimestampOptions(timestampOptions, 'options.timestampOptions')
  }
  /** @type {Record<string, any>} */
  let prepareOptions
  /** @type {(prepared: PreparedSignature) => Promise<Uint8Array>} */
  let signWith
  if (signer instanceof LocalSigner) {
    prepareOptions = { ...rest, certificateChain: signer.certificateChain, algorithm: signer.algorithm }
    signWith = (prepared) => signer.signAsync(prepared.toBeSigned, prepared.digestAlgorithm)
  } else {
    if (signer === null || typeof signer !== 'object' || typeof signer.sign !== 'function') {
      throw invalidArgument(
        'options.signer must be a LocalSigner or an object with certificateChain, algorithm and sign(toBeSigned, toBeSignedDigest)',
      )
    }
    checkBytesArray(signer.certificateChain, 'options.signer.certificateChain')
    checkString(signer.algorithm, 'options.signer.algorithm')
    prepareOptions = {
      ...rest,
      certificateChain: signer.certificateChain,
      algorithm: signer.algorithm,
      digest: rest.digest ?? signer.digest,
    }
    signWith = async (prepared) => {
      let value
      try {
        value = await signer.sign(prepared.toBeSigned, prepared.toBeSignedDigest, prepared.digestAlgorithm)
      } catch (err) {
        if (err instanceof FolioxideError) {
          throw err
        }
        // The signer's own error is the cause; its message is not repeated here, since it
        // could quote what the signer was given.
        throw new FolioxideError('E_CRYPTO', 'options.signer.sign() failed (see the cause)', { cause: err })
      }
      return signatureValue(value)
    }
  }
  if (typeof timestamp === 'function') {
    prepareOptions.tsaReserve = rest.tsaReserve ?? DEFAULT_TSA_RESERVE
  }

  /**
   * Prepares; an explicit reserve below what the CMS needs is retried once with exactly that size
   * (M3 brief §3.3), before anything is signed.
   *
   * @param {Record<string, any>} opts
   * @param {boolean} explicitReserve Whether `opts.contentsReserve` was given.
   */
  const prepare = async (opts, explicitReserve) => {
    try {
      return await doc.prepareSignatureAsync(/** @type {any} */ (opts))
    } catch (err) {
      if (!explicitReserve || !isOverflow(err)) {
        throw err
      }
      return doc.prepareSignatureAsync(/** @type {any} */ ({ ...opts, contentsReserve: err.details?.needed }))
    }
  }

  /**
   * Prepares, signs, timestamps and finishes. A finish whose CMS with its token does not fit is
   * returned as `{ overflow }` rather than thrown.
   *
   * @param {Record<string, any>} opts
   * @param {boolean} explicitReserve
   * @returns {Promise<{ pdf: Buffer } | { overflow: FolioxideError }>}
   */
  const attempt = async (opts, explicitReserve) => {
    const prepared = await prepare(opts, explicitReserve)
    const signature = await signWith(prepared)
    if (typeof timestamp !== 'function') {
      return { pdf: await prepared.finishAsync(signature) }
    }
    const request = prepared.timestampRequest(signature, timestampOptions)
    const response = await askTsa(timestamp, request)
    try {
      return { pdf: await prepared.finishAsync(signature, response, request) }
    } catch (err) {
      if (isOverflow(err)) {
        return { overflow: err }
      }
      throw err
    }
  }

  const explicit = rest.contentsReserve !== undefined && rest.contentsReserve !== null
  let outcome = await attempt(prepareOptions, explicit)
  if ('overflow' in outcome) {
    // The token is larger than its budget: everything once more, with room for it (M4 brief
    // §3.5, D-8). The signer and the TSA are called again.
    const needed = /** @type {number} */ (outcome.overflow.details?.needed)
    outcome = await attempt({ ...prepareOptions, contentsReserve: needed + TSA_RETRY_MARGIN }, true)
    if ('overflow' in outcome) {
      throw outcome.overflow
    }
  }
  return outcome.pdf
}

// `using doc = PdfDocument.open(...)` closes the document at the end of the block, and
// `using signer = LocalSigner.fromPem(...)` wipes the key. Node 20 before 20.4 has no
// `Symbol.dispose`; there the method is simply absent.
if (typeof Symbol.dispose === 'symbol') {
  for (const cls of [PdfDocument, LocalSigner]) {
    Object.defineProperty(cls.prototype, Symbol.dispose, {
      value: function dispose() {
        this.close()
      },
      writable: true,
      configurable: true,
    })
  }
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

/** The modification levels of a {@link SignatureReport}, from the least to the most change. */
const MODIFICATION_LEVELS = ['none', 'ltaUpdates', 'formFilling', 'annotations', 'other']

/**
 * The fail-safe verdict for accepting a signed document from a report of
 * {@link PdfDocument#verifySignatures}: the signature itself is sound (`byteRangeOk`, `intact`,
 * `signatureValid`, a field name, no problems, coverage `'entireFile'` or `'entireRevision'`),
 * what was appended after the signed revision is at most `maxModification`, **and** the DocMDP
 * permissions in force are respected (`docmdpOk` is not `false`: a certification with `P = 1`
 * refuses even an `/Info` change, and `'annotations'` passes only under `P = 3`).
 *
 * The signature checks alone do not detect content changed after signing: a signature over an
 * earlier revision stays intact when a later incremental update replaces page content, fonts or
 * the catalog; only `modification` (`'other'`) says so. The default `'formFilling'` accepts later
 * signatures (sequential signing); `'ltaUpdates'` accepts only metadata and invisible signature
 * fields, `'none'` nothing. Trust is separate: also require `report.trusted === true`.
 *
 * **`'formFilling'` includes visible signature fields added after signing**, whose appearance can
 * cover signed content: a new visible signature field with an appearance (signed or still empty),
 * or the appearance a later signature gives the field it signs. pyHanko and Acrobat accept this at
 * the same level; it is inherent to sequential signing in PDF. No level accepts later signatures
 * while refusing visible ones (a later signature, visible or not, is `'formFilling'`), so when no
 * further signer is expected, `'ltaUpdates'` is the strict choice. A signature field that stays
 * unsigned may change only its field flags: an appearance added to it is `'other'`.
 *
 * @param {object} report A `SignatureReport`.
 * @param {string} [maxModification='formFilling'] The most change to accept.
 * @returns {boolean}
 */
function isSignatureAcceptable(report, maxModification = 'formFilling') {
  const max = MODIFICATION_LEVELS.indexOf(maxModification)
  if (max < 0) {
    throw invalidArgument(`maxModification must be one of ${MODIFICATION_LEVELS.join(', ')}`)
  }
  if (report === null || typeof report !== 'object') {
    throw invalidArgument('isSignatureAcceptable expects a SignatureReport')
  }
  const level = MODIFICATION_LEVELS.indexOf(report.modification)
  return (
    report.docmdpOk !== false &&
    report.byteRangeOk === true &&
    report.intact === true &&
    report.signatureValid === true &&
    typeof report.fieldName === 'string' &&
    Array.isArray(report.problems) &&
    report.problems.length === 0 &&
    (report.coverage === 'entireFile' || report.coverage === 'entireRevision') &&
    level >= 0 &&
    level <= max
  )
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

module.exports = {
  FolioxideError,
  LocalSigner,
  PdfDocument,
  PreparedSignature,
  fromPdfDate,
  isSignatureAcceptable,
  signPdf,
  toPdfDate,
  version,
}

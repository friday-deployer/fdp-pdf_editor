/**
 * ESM entry point of `folioxide`. It re-exports the CommonJS facade (`index.js`), so both module
 * systems share one instance of the native addon (and `instanceof` works across them). See
 * `index.d.ts` for the documented API.
 *
 * @module folioxide
 */

import facade from './index.js'

/** A PDF document: open, inspect, edit and save. */
export const PdfDocument = facade.PdfDocument

/** The error every function and method of the package throws; `code` is an `E_*` code. */
export const FolioxideError = facade.FolioxideError

/** A private key with its certificate chain, from PKCS#12 or PEM. */
export const LocalSigner = facade.LocalSigner

/** A prepared signature: the bytes to sign, then `finish` with the signature value. */
export const PreparedSignature = facade.PreparedSignature

/**
 * Signs a document with a local or an external (possibly asynchronous) signer and returns the
 * signed PDF.
 *
 * @type {typeof facade.signPdf}
 */
export const signPdf = facade.signPdf

/**
 * Formats a `Date` as a PDF date string in UTC, such as `"D:20261010073000Z"`.
 *
 * @type {(date: Date) => string}
 */
export const toPdfDate = facade.toPdfDate

/**
 * Parses a PDF date string into a `Date`, or `null` when it is not a date.
 *
 * @type {(text: string) => Date | null}
 */
export const fromPdfDate = facade.fromPdfDate

/**
 * The fail-safe verdict for accepting a signed document: the signature is sound and what was
 * appended after it is at most `maxModification` (default `'formFilling'`, which includes later
 * signatures and visible signature fields added after signing; `'ltaUpdates'` is the strict choice
 * when no further signer is expected).
 *
 * @type {typeof facade.isSignatureAcceptable}
 */
export const isSignatureAcceptable = facade.isSignatureAcceptable

/**
 * Returns the version of the native Folioxide library, for example `"0.1.0"`.
 *
 * @returns {string} The semantic version `MAJOR.MINOR.PATCH`.
 */
export const version = facade.version

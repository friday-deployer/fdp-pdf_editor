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
 * Returns the version of the native Folioxide library, for example `"0.1.0"`.
 *
 * @returns {string} The semantic version `MAJOR.MINOR.PATCH`.
 */
export const version = facade.version

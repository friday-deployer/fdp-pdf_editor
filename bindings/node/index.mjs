/**
 * ESM entry point of `folioxide`. It re-exports the CommonJS facade (`index.js`), so both module
 * systems share one instance of the native addon. See `index.d.ts` for the documented API.
 *
 * @module folioxide
 */

import facade from './index.js'

/**
 * Returns the version of the native Folioxide library, for example `"0.1.0"`.
 *
 * @returns {string} The semantic version `MAJOR.MINOR.PATCH`.
 */
export const version = facade.version

'use strict'

/**
 * Folioxide: a pure-Rust PDF editing engine for Node.js.
 *
 * This hand-written facade is the package's public API (CommonJS entry point; `index.mjs` is the
 * ESM entry point and re-exports the same functions). It wraps the loader that `napi build`
 * generates (`binding.js`), which picks the native addon for the current platform from the
 * `@folioxide/binding-<platform>` packages.
 *
 * @module folioxide
 */

const binding = require('./binding.js')

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

module.exports = { version }

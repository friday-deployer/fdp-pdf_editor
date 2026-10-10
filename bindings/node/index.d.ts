/**
 * Folioxide: a pure-Rust PDF editing engine for Node.js.
 *
 * Type declarations for the hand-written facade (`index.js` for CommonJS, `index.mjs` for ESM).
 *
 * @packageDocumentation
 */

/**
 * Returns the version of the native Folioxide library, for example `"0.1.0"`.
 *
 * It always equals the version of the `folioxide` npm package, so it can be used to check that the
 * JavaScript wrapper and the native addon come from the same release.
 *
 * @returns The semantic version `MAJOR.MINOR.PATCH`.
 */
export declare function version(): string

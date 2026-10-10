//! # folioxide-node: Node.js binding for Folioxide
//!
//! A napi-rs (Node-API) addon that exposes the `folioxide` facade crate to JavaScript. It is the
//! only crate in the workspace that depends on napi. The npm package `folioxide` wraps the
//! generated loader (`binding.js`) in a hand-written facade (`index.js`, `index.mjs`,
//! `index.d.ts`); see `docs/ARCHITECTURE.md` §A.7.

use napi_derive::napi;

/// Returns the version of the native Folioxide library, for example `"0.1.0"`.
///
/// It equals the version of the `folioxide` npm package.
#[napi]
pub fn version() -> String {
    folioxide::VERSION.to_owned()
}

# folioxide

Folioxide is a PDF editing engine written in pure Rust, packaged for Node.js as a native
[napi-rs](https://napi.rs) addon. It is built for PDF signing (PAdES), page and document operations,
annotations and forms, and content editing. It has no C or C++ PDF dependencies.

> **Status: pre-alpha.** This release contains the project scaffolding only. The package loads the
> native addon and reports its version, but it cannot open, edit or sign PDF documents yet. The API
> will change without notice until 1.0.

## Install

```sh
npm install folioxide
```

Node.js 20 or later is required. npm installs the prebuilt native addon for your platform from one
of the optional `@folioxide/binding-<platform>` packages, so no Rust toolchain is needed:

| Platform | Package |
|---|---|
| Linux x64 (glibc) | `@folioxide/binding-linux-x64-gnu` |
| Linux arm64 (glibc) | `@folioxide/binding-linux-arm64-gnu` |
| Linux x64 (musl) | `@folioxide/binding-linux-x64-musl` |
| Linux arm64 (musl) | `@folioxide/binding-linux-arm64-musl` |
| macOS x64 | `@folioxide/binding-darwin-x64` |
| macOS arm64 | `@folioxide/binding-darwin-arm64` |
| Windows x64 | `@folioxide/binding-win32-x64-msvc` |
| Windows arm64 | `@folioxide/binding-win32-arm64-msvc` |

## Usage

The package ships CommonJS and ES module entry points with TypeScript declarations.

```js
import { version } from 'folioxide'

console.log(version()) // "0.1.0"
```

```js
const { version } = require('folioxide')
```

### `version(): string`

Returns the version of the native Folioxide library. It always equals the version of the npm
package, so it shows that the JavaScript wrapper and the native addon come from the same release.

## Roadmap

Signing comes first, then page and document operations, then annotations and forms, then content
editing. The milestone plan is in `docs/ROADMAP.md` in the
[source repository](https://github.com/friday-deployer/fdp-pdf_editor).

## License

Licensed under the MIT license ([LICENSE](LICENSE)).

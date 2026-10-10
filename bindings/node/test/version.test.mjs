import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { test } from 'node:test'

// Import through the package's own "exports" map, exactly as a user would.
import { version } from 'folioxide'

const require = createRequire(import.meta.url)

const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))

/** Reads `version` from the `[workspace.package]` table of the root Cargo.toml. */
function cargoWorkspaceVersion() {
  const manifest = readFileSync(new URL('../../../Cargo.toml', import.meta.url), 'utf8')
  const table = manifest.split(/^\[workspace\.package\]\s*$/m)[1]
  assert.ok(table, 'root Cargo.toml has a [workspace.package] table')
  const body = table.split(/^\[/m)[0]
  const match = body.match(/^version\s*=\s*"([^"]+)"/m)
  assert.ok(match, '[workspace.package] declares a version')
  return match[1]
}

test('version() returns a MAJOR.MINOR.PATCH string', () => {
  assert.equal(typeof version(), 'string')
  assert.match(version(), /^\d+\.\d+\.\d+$/)
})

test('version() equals the package.json version', () => {
  assert.equal(version(), packageJson.version)
})

test('version() equals the Cargo workspace version', () => {
  assert.equal(version(), cargoWorkspaceVersion())
})

test('the facade forwards to the native binding', () => {
  const binding = require('../binding.js')
  assert.equal(version(), binding.version())
})

test('CommonJS and ESM entry points export the same function', () => {
  const cjs = require('folioxide')
  assert.equal(typeof cjs.version, 'function')
  assert.equal(cjs.version, version)
})

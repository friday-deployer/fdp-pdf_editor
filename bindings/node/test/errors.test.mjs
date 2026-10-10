// Errors at the JavaScript boundary: every error is a FolioxideError whose `code` is an E_* code
// (M2 WP2.5, ARCHITECTURE §A.7 "Errors").

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { test } from 'node:test'

import { FolioxideError, PdfDocument, fromPdfDate, toPdfDate } from 'folioxide'

import {
  ENCRYPTED,
  REPAIRED,
  assertCode,
  assertRejectsCode,
  assertThrowsCode,
  largeDocument,
  syntaxFixture,
} from './helpers.mjs'

const require = createRequire(import.meta.url)

/** A one-page document for the argument checks. */
const minimal = () => PdfDocument.open(syntaxFixture('minimal.pdf'))

test('invalid input throws E_SYNTAX or E_XREF', async () => {
  const inputs = [
    Buffer.alloc(0),
    Buffer.from('not a PDF file at all'),
    Buffer.from('%PDF-1.7\n'),
    // The catalog is a string, not a dictionary.
    Buffer.from('%PDF-1.7\n1 0 obj\n(abc\nendobj\ntrailer\n<< /Root 1 0 R >>\n'),
    syntaxFixture('minimal.pdf').subarray(0, 40),
  ]
  for (const bytes of inputs) {
    for (const options of [undefined, { strict: true }]) {
      assertThrowsCode(() => PdfDocument.open(bytes, options), ['E_SYNTAX', 'E_XREF'])
      await assertRejectsCode(PdfDocument.openAsync(bytes, options), ['E_SYNTAX', 'E_XREF'])
    }
  }
  // Strict mode refuses a file without a %PDF- header as a syntax error.
  assertThrowsCode(() => PdfDocument.open(Buffer.from('not a PDF'), { strict: true }), 'E_SYNTAX')
})

test('the native error is kept as the cause', () => {
  try {
    PdfDocument.open(Buffer.from('nope'))
    assert.fail('open should throw')
  } catch (err) {
    assertCode(err, 'E_XREF')
    assert.ok(err.cause instanceof Error)
    assert.equal(err.cause.code, 'E_XREF')
    assert.equal(err.message, err.cause.message)
  }
})

test('the native binding itself sets err.code', async () => {
  const binding = require('../binding.js')
  assert.throws(
    () => binding.PdfDocument.open(Buffer.from('nope')),
    (err) => err instanceof Error && err.code === 'E_XREF',
  )
  await assert.rejects(binding.PdfDocument.openAsync(Buffer.from('nope')), (err) => err instanceof Error && err.code === 'E_XREF')
  const doc = binding.PdfDocument.create()
  await assert.rejects(doc.saveIncrementalAsync(), (err) => err instanceof Error && err.code === 'E_INVALID_ARGUMENT')
})

test('an out-of-range page index throws E_PAGE_OUT_OF_RANGE', () => {
  const doc = minimal()
  for (const index of [1, 2, 1e9, 2 ** 40, -1]) {
    assertThrowsCode(() => doc.getPage(index), 'E_PAGE_OUT_OF_RANGE')
    assertThrowsCode(() => doc.setPageRotation(index, 90), 'E_PAGE_OUT_OF_RANGE')
    assertThrowsCode(() => doc.setPageBox(index, 'crop', null), 'E_PAGE_OUT_OF_RANGE')
  }
  assertThrowsCode(() => PdfDocument.create().getPage(0), 'E_PAGE_OUT_OF_RANGE')
  for (const index of [0.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assertThrowsCode(() => doc.getPage(index), 'E_INVALID_ARGUMENT')
  }
})

test('an incremental save of a repaired file throws E_UNSUPPORTED', async () => {
  for (const name of REPAIRED) {
    const doc = PdfDocument.open(syntaxFixture(name))
    // Refused even without changes: the structure cannot take an update.
    assertThrowsCode(() => doc.saveIncremental(), 'E_UNSUPPORTED')
    doc.setInfo({ title: 'repaired' })
    assertThrowsCode(() => doc.saveIncremental(), 'E_UNSUPPORTED')
    assertThrowsCode(() => doc.saveIncremental({ suffixOnly: true }), 'E_UNSUPPORTED')
    await assertRejectsCode(doc.saveIncrementalAsync(), 'E_UNSUPPORTED')
    // A full save is the way out, and its output takes updates.
    const full = PdfDocument.open(doc.save())
    assert.equal(full.getInfo().title, 'repaired')
    full.setInfo({ subject: 'after a full save' })
    assert.equal(PdfDocument.open(full.saveIncremental()).getInfo().subject, 'after a full save')
  }
})

test('encrypted fixtures throw E_PASSWORD_REQUIRED (or E_UNSUPPORTED)', async () => {
  assert.equal(ENCRYPTED['encrypted.pdf'], 'E_PASSWORD_REQUIRED')
  for (const [name, code] of Object.entries(ENCRYPTED)) {
    assertThrowsCode(() => PdfDocument.open(syntaxFixture(name)), code)
    await assertRejectsCode(PdfDocument.openAsync(syntaxFixture(name)), code)
  }
})

test('an incremental save of a created document throws E_INVALID_ARGUMENT', async () => {
  const doc = PdfDocument.create()
  assertThrowsCode(() => doc.saveIncremental(), 'E_INVALID_ARGUMENT')
  await assertRejectsCode(doc.saveIncrementalAsync(), 'E_INVALID_ARGUMENT')
})

test('invalid setInfo values throw E_INVALID_ARGUMENT', () => {
  const doc = minimal()
  const bad = [
    { creationDate: 'yesterday' },
    { modDate: 'D:20261301' },
    { modDate: new Date(Number.NaN) },
    { modDate: new Date('+010000-01-01T00:00:00Z') },
    { trapped: 'maybe' },
    { trapped: true },
    { title: 42 },
    { custom: { Title: 'standard keys have their own fields' } },
    { custom: { '': 'empty key' } },
    { custom: { 'a\u0000b': 'NUL in a key' } },
    { custom: { ['x'.repeat(128)]: 'a name of more than 127 bytes' } },
    { custom: { ['é'.repeat(64)]: '128 bytes in UTF-8' } },
    { custom: { Key: 7 } },
    { custom: 'not an object' },
  ]
  for (const update of bad) {
    assertThrowsCode(() => doc.setInfo(update), 'E_INVALID_ARGUMENT')
  }
  for (const update of [null, undefined, 'title', [1]]) {
    assertThrowsCode(() => doc.setInfo(update), 'E_INVALID_ARGUMENT')
  }
  // Nothing was changed by the refused updates.
  assert.equal(doc.isModified, false)
  assert.deepEqual(doc.getInfo(), { custom: {} })
})

test('invalid page edits throw E_INVALID_ARGUMENT', () => {
  const doc = minimal()
  for (const degrees of [45, 91, 0.5, Number.NaN, 1e300]) {
    assertThrowsCode(() => doc.setPageRotation(0, degrees), 'E_INVALID_ARGUMENT')
  }
  assertThrowsCode(() => doc.setPageRotation(0, '90'), 'E_INVALID_ARGUMENT')
  const box = { llx: 0, lly: 0, urx: 100, ury: 100 }
  assertThrowsCode(() => doc.setPageBox(0, 'bleed', box), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.setPageBox(0, 'media', null), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.setPageBox(0, 'media', { llx: 0, lly: 0, urx: 0, ury: 100 }), 'E_INVALID_ARGUMENT')
  // A box that would be written as [0 0 0.0 0.0] (reals have at most 10 fractional digits).
  assertThrowsCode(() => doc.setPageBox(0, 'media', { llx: 0, lly: 0, urx: 1e-12, ury: 1e-12 }), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.setPageBox(0, 'media', { ...box, urx: Number.POSITIVE_INFINITY }), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.setPageBox(0, 'crop', { llx: 700, lly: 900, urx: 800, ury: 1000 }), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.setPageBox(0, 'crop', { llx: 0, lly: 0, urx: 100 }), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.setPageBox(0, 'crop', { llx: 'a', lly: 0, urx: 100, ury: 100 }), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.setPageBox(0, 'crop'), 'E_INVALID_ARGUMENT')
  assert.equal(doc.isModified, false)
})

test('arguments of the wrong type throw E_INVALID_ARGUMENT', async () => {
  for (const data of ['%PDF-1.7', 42, null, undefined, new ArrayBuffer(8), [37, 80], new Uint16Array(4)]) {
    assertThrowsCode(() => PdfDocument.open(data), 'E_INVALID_ARGUMENT')
    await assertRejectsCode(PdfDocument.openAsync(data), 'E_INVALID_ARGUMENT')
  }
  const bytes = syntaxFixture('minimal.pdf')
  assertThrowsCode(() => PdfDocument.open(bytes, 'strict'), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => PdfDocument.open(bytes, { strict: 'yes' }), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => new PdfDocument(), 'E_INVALID_ARGUMENT')

  const doc = minimal()
  assertThrowsCode(() => doc.getPage('0'), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.getPage(), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.save('stream'), 'E_INVALID_ARGUMENT')
  for (const options of [
    { xref: 'Table' },
    { compress: 'gzip' },
    { flateLevel: 10 },
    { flateLevel: 1.5 },
    { minVersion: '1' },
    { minVersion: 1.7 },
    // Well formed but not PDF versions: the header would say `%PDF-255.255`.
    { minVersion: '255.255' },
    { minVersion: '9.9' },
    { minVersion: '1.8' },
    { minVersion: '2.1' },
    { xref: 'table', objectStreams: true },
    { id: [Buffer.from('only one')] },
    { objectStreams: 'yes' },
  ]) {
    assertThrowsCode(() => doc.save(options), 'E_INVALID_ARGUMENT')
    await assertRejectsCode(doc.saveAsync(options), 'E_INVALID_ARGUMENT')
  }
  assertThrowsCode(() => doc.saveIncremental({ id1: 'abc' }), 'E_INVALID_ARGUMENT')
  await assertRejectsCode(doc.saveIncrementalAsync([]), 'E_INVALID_ARGUMENT')

  assertThrowsCode(() => toPdfDate('2026-10-10'), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => fromPdfDate(new Date()), 'E_INVALID_ARGUMENT')
})

test('napi conversion errors keep their napi status in details', () => {
  const doc = minimal()
  try {
    doc.save({ objectStreams: 'yes' })
    assert.fail('save should throw')
  } catch (err) {
    assertCode(err, 'E_INVALID_ARGUMENT')
    assert.equal(typeof err.details?.status, 'string')
    assert.notEqual(err.details.status, '')
  }
})

test('sync methods throw E_BUSY while an async save has the document', async () => {
  // A large stream, recompressed at the highest level: the save takes long enough to call every
  // synchronous method while it runs. The document is busy from the saveAsync() call on.
  const doc = PdfDocument.open(largeDocument(8 * 1024 * 1024))
  const pending = doc.saveAsync({ compress: 'recompress', flateLevel: 9 })
  const calls = [
    () => doc.pageCount,
    () => doc.version,
    () => doc.isModified,
    () => doc.diagnostics(),
    () => doc.getPage(0),
    () => doc.getInfo(),
    () => doc.setInfo({ title: 'not now' }),
    () => doc.setPageRotation(0, 90),
    () => doc.setPageBox(0, 'crop', null),
    () => doc.save(),
    () => doc.saveIncremental(),
  ]
  for (const call of calls) {
    assertThrowsCode(call, 'E_BUSY')
  }
  const saved = await pending
  assert.ok(Buffer.isBuffer(saved))
  // The refused edits were not made, and the document works again.
  assert.equal(doc.isModified, false)
  assert.equal(doc.pageCount, 1)
  const reopened = PdfDocument.open(saved)
  assert.equal(reopened.pageCount, 1)
  assert.equal(reopened.getInfo().title, undefined)
})

test('E_BUSY is a FolioxideError with a message that says what to do', async () => {
  const doc = PdfDocument.open(largeDocument(4 * 1024 * 1024))
  const pending = doc.saveIncrementalAsync()
  let busy
  try {
    doc.getInfo()
  } catch (err) {
    busy = err
  }
  await pending
  if (busy !== undefined) {
    assertCode(busy, 'E_BUSY')
    assert.match(busy.message, /await/)
  }
})

test('every code a FolioxideError can have is declared in index.d.ts', () => {
  const dts = readFileSync(new URL('../index.d.ts', import.meta.url), 'utf8')
  const union = dts.split('export type ErrorCode =')[1]?.split('\n\n')[0] ?? ''
  for (const code of [
    'E_SYNTAX',
    'E_XREF',
    'E_PAGE_OUT_OF_RANGE',
    'E_INVALID_ARGUMENT',
    'E_UNSUPPORTED',
    'E_PASSWORD_REQUIRED',
    'E_LIMIT_EXCEEDED',
    'E_BUSY',
    'E_CLOSED',
  ]) {
    assert.ok(union.includes(`'${code}'`), code)
  }
})

test('FolioxideError can be constructed and caught by code', () => {
  const cause = new Error('inner')
  const err = new FolioxideError('E_NOT_FOUND', 'no such field', { cause, details: { name: 'x' } })
  assert.ok(err instanceof Error)
  assert.equal(err.name, 'FolioxideError')
  assert.equal(err.code, 'E_NOT_FOUND')
  assert.equal(err.message, 'no such field')
  assert.equal(err.cause, cause)
  assert.deepEqual(err.details, { name: 'x' })
  assert.equal(new FolioxideError('E_IO', 'x').details, undefined)
  assert.match(String(err.stack), /FolioxideError: no such field/)
})

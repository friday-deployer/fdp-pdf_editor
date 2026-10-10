// Native memory (ARCHITECTURE §A.7 "Native memory"): what a document holds is reported to V8, so
// documents nothing refers to are collected in time, and close() (or Symbol.dispose) frees it at
// once. Without the report, a loop that opened, saved and dropped documents grew without bound
// (M2 QA: about 85 MB per 20 MB document).

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { PdfDocument } from 'folioxide'

import { assertRejectsCode, assertThrowsCode, largeDocument, syntaxFixture } from './helpers.mjs'

/**
 * `count` small dictionaries and a catalog, without a cross-reference table (the file is read
 * by a scan, as in the QA reproducer): opened, it holds several times its size. With
 * `reachable`, the catalog refers to every dictionary, so a full save reads them all.
 */
function manyObjects(count, { reachable = false } = {}) {
  const parts = ['%PDF-1.4\n']
  for (let i = 1; i <= count; i++) {
    parts.push(`${i} 0 obj\n<< /A ${i} /S (some string content ${i}) >>\nendobj\n`)
  }
  const all = reachable ? `/All [${Array.from({ length: count }, (_, i) => `${i + 1} 0 R`).join(' ')}]` : ''
  parts.push(`${count + 1} 0 obj\n<< /Type /Catalog ${all} >>\nendobj\ntrailer\n<< /Root ${count + 1} 0 R >>\n`)
  return Buffer.from(parts.join(''), 'latin1')
}

test('nativeMemory follows what the document holds', async () => {
  const bytes = manyObjects(5000, { reachable: true })
  const doc = PdfDocument.open(bytes)
  const opened = doc.nativeMemory
  assert.ok(opened >= bytes.length, `${opened} < ${bytes.length}`)
  doc.pageCount
  // A full save reads every object.
  doc.save()
  const saved = doc.nativeMemory
  assert.ok(saved > opened + 5000 * 32, `${opened} -> ${saved}`)
  // Edits count too.
  doc.setInfo({ title: 'x'.repeat(100_000) })
  assert.ok(doc.nativeMemory >= saved + 100_000, `${saved} -> ${doc.nativeMemory}`)

  const opener = await PdfDocument.openAsync(bytes)
  assert.ok(opener.nativeMemory >= bytes.length)
  assert.ok(PdfDocument.create().nativeMemory > 0)
  // An asynchronous save reports what it read when it resolves.
  const before = opener.nativeMemory
  await opener.saveAsync()
  assert.ok(opener.nativeMemory > before, `${before} -> ${opener.nativeMemory}`)
})

test('close() frees the document; then every method throws E_CLOSED', async () => {
  const doc = PdfDocument.open(syntaxFixture('minimal.pdf'))
  assert.equal(doc.isClosed, false)
  assert.ok(doc.nativeMemory > 0)
  doc.close()
  assert.equal(doc.isClosed, true)
  assert.equal(doc.nativeMemory, 0)
  for (const call of [
    () => doc.pageCount,
    () => doc.version,
    () => doc.isModified,
    () => doc.diagnostics(),
    () => doc.getPage(0),
    () => doc.getInfo(),
    () => doc.setInfo({ title: 'too late' }),
    () => doc.setPageRotation(0, 90),
    () => doc.setPageBox(0, 'crop', null),
    () => doc.save(),
    () => doc.saveIncremental(),
  ]) {
    assertThrowsCode(call, 'E_CLOSED')
  }
  await assertRejectsCode(doc.saveAsync(), 'E_CLOSED')
  await assertRejectsCode(doc.saveIncrementalAsync(), 'E_CLOSED')
  // Closing again does nothing.
  doc.close()
  assert.equal(doc.isClosed, true)
  try {
    doc.getInfo()
  } catch (err) {
    assert.match(err.message, /close\(\)/)
  }
})

test('Symbol.dispose closes the document (for `using`)', { skip: typeof Symbol.dispose !== 'symbol' }, () => {
  const doc = PdfDocument.create()
  assert.equal(typeof doc[Symbol.dispose], 'function')
  doc[Symbol.dispose]()
  assert.equal(doc.isClosed, true)
  assertThrowsCode(() => doc.pageCount, 'E_CLOSED')
})

test('closing during an asynchronous save lets the save finish', async () => {
  for (const save of [(doc) => doc.saveAsync({ compress: 'recompress' }), (doc) => doc.saveIncrementalAsync()]) {
    const doc = PdfDocument.open(largeDocument(2 * 1024 * 1024))
    doc.setInfo({ title: 'closing' })
    const pending = save(doc)
    doc.close()
    assert.equal(doc.isClosed, true)
    assertThrowsCode(() => doc.pageCount, 'E_CLOSED')
    const bytes = await pending
    assert.ok(Buffer.isBuffer(bytes))
    const reopened = PdfDocument.open(bytes)
    assert.equal(reopened.getInfo().title, 'closing')
    assert.equal(reopened.pageCount, 1)
    assert.equal(doc.nativeMemory, 0)
  }
})

/**
 * Opens, reads and saves `rounds` documents of `bytes` one after the other, keeping none, and
 * returns how much the resident set grew at its peak, in multiples of `rounds * bytes.length`.
 */
async function residentGrowth(bytes, rounds, { close = false, yieldToLoop = false } = {}) {
  const base = process.memoryUsage().rss
  let peak = base
  for (let i = 0; i < rounds; i++) {
    const doc = PdfDocument.open(bytes)
    doc.pageCount
    doc.save()
    assert.ok(doc.nativeMemory > bytes.length, `${doc.nativeMemory}`)
    if (close) {
      doc.close()
    }
    peak = Math.max(peak, process.memoryUsage().rss)
    if (yieldToLoop) {
      // Node runs the finalizers of native objects from the event loop.
      await new Promise(setImmediate)
    }
  }
  return (peak - base) / (rounds * bytes.length)
}

// Each document below holds about four times its 1.9 MB file. A loop that keeps every one grows
// by about 4 file sizes per round; one that frees them stays flat (about 1.4 per round over 40
// rounds when V8 collects as it goes, which falls as the rounds grow).

test('documents nothing refers to are collected while the event loop runs', async () => {
  // Without the report to V8 the JavaScript objects look tiny, so V8 never collects them and
  // every document stays in memory.
  const growth = await residentGrowth(manyObjects(30_000), 60, { yieldToLoop: true })
  assert.ok(growth < 2.5, `the resident set grew by ${growth.toFixed(2)} file sizes per document`)
})

test('close() frees memory in a loop that never yields to the event loop', async () => {
  // Node only finalizes native objects from the event loop, so such a loop must close.
  const growth = await residentGrowth(manyObjects(30_000), 40, { close: true })
  assert.ok(growth < 1, `the resident set grew by ${growth.toFixed(2)} file sizes per document`)
})

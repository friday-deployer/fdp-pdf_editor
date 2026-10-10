// PdfDocument: opening, inspecting, editing and saving (M2 WP2.5, acceptance criterion 6).

import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { test } from 'node:test'

import * as esm from 'folioxide'
import { PdfDocument, fromPdfDate, toPdfDate } from 'folioxide'

import {
  ENCRYPTED,
  PAGE_COUNTS,
  REPAIRED,
  assertCode,
  buildPdf,
  declaredDiagnosticKinds,
  startsWithBytes,
  syntaxFixture,
  syntaxFixtureNames,
} from './helpers.mjs'

/** A PageInfo has exactly the core's serde shape. */
function assertPageInfo(page, index) {
  assert.deepEqual(Object.keys(page).sort(), ['cropBox', 'height', 'index', 'mediaBox', 'rotation', 'width'])
  assert.equal(page.index, index)
  for (const box of [page.mediaBox, page.cropBox]) {
    assert.deepEqual(Object.keys(box).sort(), ['llx', 'lly', 'urx', 'ury'])
    assert.ok(box.llx < box.urx && box.lly < box.ury, JSON.stringify(box))
  }
  assert.ok([0, 90, 180, 270].includes(page.rotation))
  const sideways = page.rotation % 180 === 90
  const crop = page.cropBox
  assert.equal(page.width, sideways ? crop.ury - crop.lly : crop.urx - crop.llx)
  assert.equal(page.height, sideways ? crop.urx - crop.llx : crop.ury - crop.lly)
}

/** Every diagnostic has the core's serde shape and a declared kind. */
function assertDiagnostics(diagnostics) {
  const kinds = declaredDiagnosticKinds()
  assert.ok(Array.isArray(diagnostics))
  for (const diagnostic of diagnostics) {
    assert.deepEqual(Object.keys(diagnostic).sort(), ['kind', 'message', 'offset'])
    assert.ok(diagnostic.offset === null || Number.isSafeInteger(diagnostic.offset))
    assert.ok(kinds.has(diagnostic.kind), diagnostic.kind)
    assert.equal(typeof diagnostic.message, 'string')
  }
}

test('every committed syntax fixture opens, or fails with its E_ code', async () => {
  const names = syntaxFixtureNames()
  assert.ok(names.length >= 20, `only ${names.length} fixtures`)
  for (const name of names) {
    const bytes = syntaxFixture(name)
    if (name in ENCRYPTED) {
      assert.throws(() => PdfDocument.open(bytes), (err) => assertCode(err, ENCRYPTED[name]))
      continue
    }
    for (const doc of [PdfDocument.open(bytes), await PdfDocument.openAsync(bytes)]) {
      assert.equal(doc.pageCount, PAGE_COUNTS[name] ?? 1, name)
      assert.match(doc.version, /^\d\.\d$/)
      assert.equal(doc.isModified, false)
      for (let i = 0; i < doc.pageCount; i++) {
        assertPageInfo(doc.getPage(i), i)
      }
      assert.deepEqual(doc.getInfo().custom !== undefined, true)
      assertDiagnostics(doc.diagnostics())
    }
  }
})

test('repaired files report what was repaired', () => {
  for (const name of REPAIRED) {
    const diagnostics = PdfDocument.open(syntaxFixture(name)).diagnostics()
    assert.ok(diagnostics.length > 0, name)
    assertDiagnostics(diagnostics)
  }
})

test('getPage and getInfo return the core JSON shapes', () => {
  const doc = PdfDocument.open(syntaxFixture('minimal.pdf'))
  assert.equal(doc.version, '1.4')
  assert.deepEqual(doc.getPage(0), {
    index: 0,
    width: 612,
    height: 792,
    mediaBox: { llx: 0, lly: 0, urx: 612, ury: 792 },
    cropBox: { llx: 0, lly: 0, urx: 612, ury: 792 },
    rotation: 0,
  })
  // Absent entries are left out (not `undefined` properties), custom is always there.
  assert.deepEqual(doc.getInfo(), { custom: {} })
  assert.deepEqual(Object.keys(doc.getInfo()), ['custom'])
})

test('open/save round trip', () => {
  const original = syntaxFixture('multi-revision.pdf')
  const doc = PdfDocument.open(original)
  const saved = doc.save()
  assert.ok(Buffer.isBuffer(saved))
  assert.ok(startsWithBytes(saved, Buffer.from('%PDF-')))
  assert.ok(saved.subarray(-8).toString('latin1').includes('%%EOF'))

  const reopened = PdfDocument.open(saved)
  assert.equal(reopened.pageCount, doc.pageCount)
  for (let i = 0; i < doc.pageCount; i++) {
    assert.deepEqual(reopened.getPage(i), doc.getPage(i))
  }
  assert.deepEqual(reopened.getInfo(), doc.getInfo())
  assert.deepEqual(reopened.diagnostics(), [])
  assert.equal(reopened.isModified, false)
})

test('save options: cross-reference streams, object streams, recompression, version', () => {
  const doc = PdfDocument.open(syntaxFixture('minimal.pdf'))
  const options = {
    xref: 'stream',
    objectStreams: true,
    compress: 'recompress',
    gc: true,
    renumber: true,
    deterministic: true,
    minVersion: '1.7',
    flateLevel: 9,
  }
  const first = doc.save(options)
  assert.ok(startsWithBytes(first, Buffer.from('%PDF-1.7')))
  assert.ok(first.includes(Buffer.from('/ObjStm')))
  assert.ok(first.includes(Buffer.from('/XRef')))
  // Deterministic: the same document and options give the same bytes.
  assert.equal(Buffer.compare(first, doc.save(options)), 0)
  const reopened = PdfDocument.open(first)
  assert.equal(reopened.version, '1.7')
  assert.deepEqual(reopened.getPage(0), doc.getPage(0))

  const table = doc.save({ xref: 'table', compress: 'keep', id: [Buffer.from('first'), Buffer.from('second')] })
  assert.ok(table.includes(Buffer.from('\nxref\n')))
  // The /ID strings are written in hexadecimal.
  const hex = (text) => Buffer.from(text).toString('hex').toUpperCase()
  assert.ok(table.includes(Buffer.from(`/ID [<${hex('first')}> <${hex('second')}>]`)))
  assert.equal(PdfDocument.open(table).pageCount, 1)

  // The highest PDF version is accepted; anything above it throws (see errors.test.mjs).
  const v2 = doc.save({ minVersion: '2.0' })
  assert.ok(startsWithBytes(v2, Buffer.from('%PDF-2.0\n')))
  assert.equal(PdfDocument.open(v2).version, '2.0')
})

test('setInfo/getInfo round trip with non-Latin text (UTF-16)', () => {
  const original = syntaxFixture('minimal.pdf')
  const doc = PdfDocument.open(original)
  const created = new Date(Date.UTC(2026, 9, 10, 7, 30, 15))
  const update = {
    title: 'Отчёт 2026: 年度報告 📄✅',
    author: 'Ζωή Παπαδοπούλου',
    subject: 'Prix: 42 € (PDFDocEncoding)',
    keywords: 'pdf, 署名, подпись',
    creator: 'folioxide test',
    producer: 'Folioxide',
    creationDate: created,
    modDate: "D:20261010093000+02'00'",
    trapped: 'false',
    custom: { Department: 'Финансы', Reviewer: '김민준' },
  }
  doc.setInfo(update)
  assert.equal(doc.isModified, true)
  const expected = {
    ...update,
    creationDate: 'D:20261010073015Z',
    modDate: "D:20261010093000+02'00'",
  }
  assert.deepEqual(doc.getInfo(), expected)
  assert.equal(fromPdfDate(doc.getInfo().creationDate).getTime(), created.getTime())
  assert.equal(toPdfDate(created), 'D:20261010073015Z')

  // Through a full save and reopen.
  const full = PdfDocument.open(doc.save())
  assert.deepEqual(full.getInfo(), expected)

  // Through an incremental save and reopen: the text strings are UTF-16BE with a byte order mark
  // (the update is never compressed, so the strings are visible in its bytes).
  const incremental = doc.saveIncremental()
  const suffix = incremental.subarray(original.length)
  const bom = suffix.includes(Buffer.from([0xfe, 0xff])) || /<FEFF/i.test(suffix.toString('latin1'))
  assert.ok(bom, 'the update holds UTF-16BE text strings')
  const reopened = PdfDocument.open(incremental)
  assert.deepEqual(reopened.getInfo(), expected)

  // undefined keeps an entry, null removes it.
  reopened.setInfo({ title: undefined, author: null, trapped: null, custom: { Reviewer: null } })
  const after = reopened.getInfo()
  assert.equal(after.title, update.title)
  assert.equal('author' in after, false)
  assert.equal('trapped' in after, false)
  assert.deepEqual(after.custom, { Department: 'Финансы' })
  assert.deepEqual(PdfDocument.open(reopened.saveIncremental()).getInfo(), after)
})

test('saveIncremental keeps the original bytes (prefix check in JS)', () => {
  let checked = 0
  for (const name of syntaxFixtureNames()) {
    if (name in ENCRYPTED || REPAIRED.includes(name)) {
      continue
    }
    const original = syntaxFixture(name)
    const doc = PdfDocument.open(original)
    // Without changes the original file comes back unchanged.
    assert.equal(Buffer.compare(doc.saveIncremental(), original), 0, name)
    assert.equal(doc.saveIncremental({ suffixOnly: true }).length, 0, name)

    doc.setInfo({ title: `incremental ${name}` })
    doc.setPageRotation(0, 90)
    const out = doc.saveIncremental()
    assert.ok(out.length > original.length, name)
    assert.equal(Buffer.compare(out.subarray(0, original.length), original), 0, `${name}: prefix changed`)
    // The suffix alone is what was appended.
    const suffix = doc.saveIncremental({ suffixOnly: true })
    assert.equal(Buffer.compare(Buffer.concat([original, suffix]), out), 0, name)

    const reopened = PdfDocument.open(out)
    assert.equal(reopened.getInfo().title, `incremental ${name}`)
    assert.equal(reopened.getPage(0).rotation, 90)
    assert.equal(reopened.pageCount, doc.pageCount)
    checked++
  }
  assert.ok(checked >= 15, `only ${checked} fixtures checked`)
})

test('the bytes before %PDF- survive an incremental save', () => {
  const original = syntaxFixture('junk-before-header.pdf')
  assert.ok(!startsWithBytes(original, Buffer.from('%PDF-')))
  const doc = PdfDocument.open(original)
  doc.setInfo({ title: 'after the junk' })
  const out = doc.saveIncremental()
  assert.ok(startsWithBytes(out, original))
  assert.equal(PdfDocument.open(out).getInfo().title, 'after the junk')
})

test('saveAsync and saveIncrementalAsync resolve to Buffers', async () => {
  const original = syntaxFixture('xref-stream.pdf')
  const doc = await PdfDocument.openAsync(original)
  doc.setInfo({ title: 'async' })
  const full = await doc.saveAsync({ deterministic: true })
  assert.ok(Buffer.isBuffer(full))
  assert.equal(Buffer.compare(full, doc.save({ deterministic: true })), 0)
  assert.equal(PdfDocument.open(full).getInfo().title, 'async')

  const incremental = await doc.saveIncrementalAsync()
  assert.ok(Buffer.isBuffer(incremental))
  assert.ok(startsWithBytes(incremental, original))
  assert.equal(Buffer.compare(incremental, doc.saveIncremental()), 0)
  const suffix = await doc.saveIncrementalAsync({ suffixOnly: true })
  assert.equal(Buffer.compare(Buffer.concat([original, suffix]), incremental), 0)
})

test('a sync call during saveAsync throws E_BUSY or completes, without deadlock', async () => {
  const doc = PdfDocument.open(syntaxFixture('multi-revision.pdf'))
  doc.setInfo({ title: 'busy' })
  const pending = doc.saveAsync()
  let pageCount
  try {
    pageCount = doc.pageCount
  } catch (err) {
    assertCode(err, 'E_BUSY')
  }
  if (pageCount !== undefined) {
    assert.equal(pageCount, 2)
  }
  const saved = await pending
  assert.ok(Buffer.isBuffer(saved))
  // Once the promise settled, synchronous methods work again.
  assert.equal(doc.pageCount, 2)
  assert.equal(PdfDocument.open(saved).getInfo().title, 'busy')
})

test('concurrent asynchronous saves of one document all complete', async () => {
  const original = syntaxFixture('objstm.pdf')
  const doc = PdfDocument.open(original)
  doc.setInfo({ subject: 'concurrent' })
  const results = await Promise.all([
    doc.saveAsync({ deterministic: true }),
    doc.saveIncrementalAsync(),
    doc.saveAsync({ deterministic: true }),
    doc.saveIncrementalAsync({ suffixOnly: true }),
  ])
  assert.equal(Buffer.compare(results[0], results[2]), 0)
  assert.ok(startsWithBytes(results[1], original))
  assert.equal(Buffer.compare(Buffer.concat([original, results[3]]), results[1]), 0)
  for (const bytes of results.slice(0, 3)) {
    assert.equal(PdfDocument.open(bytes).getInfo().subject, 'concurrent')
  }
})

test('create() -> save -> reopen', () => {
  const doc = PdfDocument.create()
  assert.equal(doc.pageCount, 0)
  assert.equal(doc.version, '1.7')
  assert.equal(doc.isModified, true)
  assert.deepEqual(doc.getInfo(), { custom: {} })
  doc.setInfo({ title: 'Новый документ', creationDate: new Date(Date.UTC(2026, 0, 2, 3, 4, 5)) })
  const saved = doc.save()
  assert.ok(startsWithBytes(saved, Buffer.from('%PDF-1.7')))

  const reopened = PdfDocument.open(saved)
  assert.equal(reopened.pageCount, 0)
  assert.equal(reopened.version, '1.7')
  assert.equal(reopened.isModified, false)
  assert.deepEqual(reopened.getInfo(), {
    title: 'Новый документ',
    creationDate: 'D:20260102030405Z',
    custom: {},
  })
  assert.deepEqual(reopened.diagnostics(), [])
})

test('page rotation and boxes, through an incremental save', () => {
  // Two pages that inherit an A4 media box and a rotation from the page tree root.
  const original = buildPdf([
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 595 842] /Rotate 180 >>',
    '<< /Type /Page /Parent 2 0 R >>',
    '<< /Type /Page /Parent 2 0 R >>',
  ])
  const doc = PdfDocument.open(original)
  assert.equal(doc.getPage(0).rotation, 180)

  doc.setPageRotation(0, -90)
  assert.equal(doc.getPage(0).rotation, 270)
  assert.equal(doc.getPage(0).width, 842)
  assert.equal(doc.getPage(0).height, 595)
  // The sibling keeps the inherited values.
  assert.equal(doc.getPage(1).rotation, 180)

  doc.setPageBox(0, 'crop', { llx: 550, lly: 800, urx: 50, ury: 40 })
  assert.deepEqual(doc.getPage(0).cropBox, { llx: 50, lly: 40, urx: 550, ury: 800 })
  doc.setPageBox(1, 'media', { llx: 0, lly: 0, urx: 612, ury: 792 })
  assert.deepEqual(doc.getPage(1).mediaBox, { llx: 0, lly: 0, urx: 612, ury: 792 })
  assert.deepEqual(doc.getPage(0).mediaBox, { llx: 0, lly: 0, urx: 595, ury: 842 })

  const reopened = PdfDocument.open(doc.saveIncremental())
  assert.deepEqual(reopened.getPage(0), doc.getPage(0))
  assert.deepEqual(reopened.getPage(1), doc.getPage(1))

  // null removes the crop box: it is the media box again.
  reopened.setPageBox(0, 'crop', null)
  assert.deepEqual(reopened.getPage(0).cropBox, reopened.getPage(0).mediaBox)
})

test('the input buffer is copied: reusing it does not change the document', async () => {
  const bytes = Buffer.from(syntaxFixture('minimal.pdf'))
  const doc = PdfDocument.open(bytes)
  const pending = PdfDocument.openAsync(bytes)
  bytes.fill(0)
  assert.equal(doc.pageCount, 1)
  assert.equal((await pending).pageCount, 1)
  assert.ok(startsWithBytes(doc.saveIncremental(), Buffer.from('%PDF-1.4')))
  // A plain Uint8Array (not a Buffer) works too.
  const plain = new Uint8Array(syntaxFixture('minimal.pdf'))
  assert.equal(PdfDocument.open(plain).pageCount, 1)
})

test('strict mode refuses repaired files that lenient mode opens', () => {
  for (const name of REPAIRED) {
    const bytes = syntaxFixture(name)
    assert.equal(PdfDocument.open(bytes).pageCount, 1, name)
    assert.throws(() => PdfDocument.open(bytes, { strict: true }), (err) => assertCode(err, ['E_XREF', 'E_SYNTAX']))
  }
  assert.equal(PdfDocument.open(syntaxFixture('minimal.pdf'), { strict: true }).pageCount, 1)
})

test('toPdfDate and fromPdfDate', () => {
  assert.equal(toPdfDate(new Date(Date.UTC(2026, 9, 10, 7, 30, 5, 999))), 'D:20261010073005Z')
  assert.equal(toPdfDate(new Date('0005-01-01T00:00:00Z')), 'D:00050101000000Z')
  assert.equal(fromPdfDate("D:20240229133005+05'30'").toISOString(), '2024-02-29T08:00:05.000Z')
  assert.equal(fromPdfDate('D:20261010073005Z').toISOString(), '2026-10-10T07:30:05.000Z')
  // Without an offset the time is local.
  assert.equal(fromPdfDate('D:2026').getTime(), new Date(2026, 0, 1).getTime())
  assert.equal(fromPdfDate('yesterday'), null)
  assert.equal(fromPdfDate(''), null)
})

test('CommonJS and ESM entry points export the same values', () => {
  const cjs = createRequire(import.meta.url)('folioxide')
  assert.deepEqual(Object.keys(cjs).sort(), Object.keys(esm).sort())
  for (const name of Object.keys(cjs)) {
    assert.equal(esm[name], cjs[name], name)
  }
  // One class for both, so documents and errors pass instanceof checks across module systems.
  assert.ok(PdfDocument.create() instanceof cjs.PdfDocument)
})

// Visible signatures from Node (M4 WP4.3B; brief §3.5, §4.7 and §6.4): the `appearance` option
// (a widget rectangle, text lines, a JPEG image), its argument checks, and the core's refusals
// (E_INVALID_ARGUMENT for a bad rectangle, E_IMAGE for an image that is not a JPEG, E_UNSUPPORTED
// for a CMYK JPEG). pyHanko checks the signed files when the oracle venv is set up.
//
// The appearance itself is built by the core (WP4.3A); the argument checks of the binding and the
// facade are tested here as well.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { LocalSigner, PdfDocument, isSignatureAcceptable, signPdf } from 'folioxide'

import { assertRejectsCode, assertThrowsCode, buildPdf, syntaxFixture } from './helpers.mjs'
import { MockTsa, REPO } from './helpers/mock-tsa.mjs'
import { ORACLE_UNAVAILABLE, pyhanko } from './helpers/oracle.mjs'

const PKI = new URL('fixtures/pki/', REPO)
const pki = (name) => readFileSync(new URL(name, PKI))
const pkiText = (name) => readFileSync(new URL(name, PKI), 'utf8')
const image = (name) => readFileSync(new URL(`fixtures/images/${name}`, REPO))

const ROOT = pki('root.pem')
const INPUT = syntaxFixture('minimal.pdf')
const SIGNING_TIME = new Date('2026-10-10T12:00:00Z')
const RECT = [100, 100, 300, 160]

const p256 = () =>
  LocalSigner.fromPem(pkiText('signer-p256.key.pem'), pkiText('signer-p256.pem') + pkiText('intermediate.pem'))

/** Verifies a signed file against the test root. */
async function verify(bytes) {
  const doc = PdfDocument.open(bytes)
  try {
    return await doc.verifySignatures({ trustAnchors: [ROOT] })
  } finally {
    doc.close()
  }
}

/** The `/Rect` values of the widgets the incremental update after `original` writes. */
function widgetRects(signed, original) {
  const update = signed.subarray(original.length).toString('latin1')
  const number = String.raw`(-?\d+(?:\.\d+)?)`
  const re = new RegExp(String.raw`/Rect\s*\[\s*${number}\s+${number}\s+${number}\s+${number}\s*\]`, 'g')
  return [...update.matchAll(re)].map((match) => match.slice(1, 5).map(Number))
}

/** pyHanko must find every signature intact, valid and trusted. */
function oracle(t, bytes, count = 1) {
  if (ORACLE_UNAVAILABLE) {
    t.diagnostic(`oracle skipped: ${ORACLE_UNAVAILABLE}`)
    return
  }
  const statuses = pyhanko(bytes)
  assert.equal(statuses.length, count, 'pyHanko lists every signature')
  statuses.forEach((status, i) => {
    assert.equal(status.intact, true, `pyHanko signatures[${i}].intact`)
    assert.equal(status.valid, true, `pyHanko signatures[${i}].valid`)
    assert.equal(status.trusted, true, `pyHanko signatures[${i}].trusted`)
  })
}

// ---- always: the argument checks of the facade and the binding ---------------------------------

test('invalid appearance rectangles and options give E_INVALID_ARGUMENT', async () => {
  const signer = p256()
  const bad = [
    { rect: [Number.NaN, 100, 300, 160] },
    { rect: [100, 100, Number.POSITIVE_INFINITY, 160] },
    { rect: [100, 100, 300] },
    { rect: [100, 100, 300, 160, 5] },
    { rect: ['100', 100, 300, 160] },
    { rect: 'rect' },
    { rect: { llx: 100, lly: 100, urx: 300 } },
    { rect: { llx: 100, lly: 100, urx: 300, ury: Number.NaN } },
    { rect: RECT, lines: 'Approved' },
    { rect: RECT, lines: ['Approved', 7] },
    { rect: RECT, font: 'Times-Roman' },
    { rect: RECT, font: 12 },
    { rect: RECT, fontSize: 0 },
    { rect: RECT, fontSize: -3 },
    { rect: RECT, fontSize: '9' },
    { rect: RECT, imagePosition: 'right' },
    { rect: RECT, borderWidth: -1 },
    { rect: RECT, image: 'logo.jpg' },
    'visible',
  ]
  for (const appearance of bad) {
    await assertRejectsCode(
      signPdf(PdfDocument.open(INPUT), { signer, appearance }),
      'E_INVALID_ARGUMENT',
    )
    const doc = PdfDocument.open(INPUT)
    assertThrowsCode(
      () =>
        doc.prepareSignature({ certificateChain: signer.certificateChain, algorithm: signer.algorithm, appearance }),
      'E_INVALID_ARGUMENT',
    )
    doc.close()
  }
})

// ---- with the core's appearances ---------------------------------------------------------------

test('appearance with a rect and an image: the widget has the rect, and the result verifies', async (t) => {
  const signed = await signPdf(PdfDocument.open(INPUT), {
    signer: p256(),
    signingTime: SIGNING_TIME,
    reason: 'Approved',
    appearance: { rect: RECT, image: image('gray-baseline.jpg'), borderWidth: 1 },
  })
  assert.deepEqual(widgetRects(signed, INPUT), [RECT])
  const [report] = await verify(signed)
  assert.equal(report.intact && report.signatureValid && report.byteRangeOk, true)
  assert.equal(report.trusted, true)
  assert.deepEqual(report.problems, [])
  assert.equal(report.modification, 'none')
  assert.equal(isSignatureAcceptable(report), true)
  oracle(t, signed)

  // The rectangle as a Rect with its corners in any order, text lines, the bold font, the image
  // in the background: the same normalized widget rectangle.
  const again = await signPdf(PdfDocument.open(INPUT), {
    signer: p256(),
    appearance: {
      rect: { llx: 300, lly: 160, urx: 100, ury: 100 },
      lines: ['Approved', 'Folioxide Test Signer'],
      font: 'Helvetica-Bold',
      fontSize: 10,
      image: image('rgb-baseline.jpg'),
      imagePosition: 'background',
    },
  })
  assert.deepEqual(widgetRects(again, INPUT), [RECT])
  const [second] = await verify(again)
  assert.equal(second.intact && second.signatureValid && second.trusted, true)
  oracle(t, again)
})

test('rectangles without an area or outside the page give E_INVALID_ARGUMENT', async () => {
  for (const rect of [
    [100, 100, 100, 160],
    [100, 100, 300, 100],
    [10000, 10000, 10200, 10060],
  ]) {
    await assertRejectsCode(
      signPdf(PdfDocument.open(INPUT), { signer: p256(), appearance: { rect } }),
      'E_INVALID_ARGUMENT',
    )
  }
})

test('an image that is not a JPEG gives E_IMAGE; a CMYK JPEG gives E_UNSUPPORTED', async () => {
  for (const bytes of [Buffer.from('\x89PNG\r\n\x1a\n not a JPEG', 'latin1'), Buffer.from('not an image')]) {
    await assertRejectsCode(
      signPdf(PdfDocument.open(INPUT), { signer: p256(), appearance: { rect: RECT, image: bytes } }),
      'E_IMAGE',
    )
  }
  await assertRejectsCode(
    signPdf(PdfDocument.open(INPUT), { signer: p256(), appearance: { rect: RECT, image: image('cmyk.jpg') } }),
    'E_UNSUPPORTED',
  )
})

/** A one-page document with an empty visible signature field `Visible` at `[300 100 500 160]`. */
function withEmptyVisibleField() {
  return buildPdf([
    '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] >> >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>',
    '<< /FT /Sig /T (Visible) /Type /Annot /Subtype /Widget /Rect [300 100 500 160] /F 132 /P 3 0 R >>',
  ])
}

test('an existing empty visible field is signed in its own widget rectangle', async (t) => {
  const original = withEmptyVisibleField()
  const signed = await signPdf(PdfDocument.open(original), {
    signer: p256(),
    field: { name: 'Visible', mode: 'existingOnly' },
    appearance: { lines: ['Approved'] },
  })
  const [report] = await verify(signed)
  assert.equal(report.fieldName, 'Visible')
  assert.equal(report.intact && report.signatureValid && report.trusted, true)
  // The widget keeps its rectangle: a rect that differs is refused.
  await assertRejectsCode(
    signPdf(PdfDocument.open(original), {
      signer: p256(),
      field: { name: 'Visible', mode: 'existingOnly' },
      appearance: { rect: RECT },
    }),
    'E_INVALID_ARGUMENT',
  )
  oracle(t, signed)
})

test('visible, certified (P = 2) and timestamped (B-T) in one signature', async (t) => {
  const tsa = new MockTsa({ genTime: '20261010120030Z' })
  const signed = await signPdf(PdfDocument.open(INPUT), {
    signer: p256(),
    signingTime: SIGNING_TIME,
    certify: 2,
    appearance: { rect: RECT },
    timestamp: tsa.callback,
  })
  assert.deepEqual(widgetRects(signed, INPUT), [RECT])
  const [report] = await verify(signed)
  assert.equal(report.docmdp, 2)
  assert.equal(report.docmdpOk, true)
  assert.equal(report.padesLevel, 'B-T')
  assert.equal(report.timestamp.trusted, true)
  oracle(t, signed)
})

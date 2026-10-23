// Certification signatures from Node (M4 WP4.3B; brief §3.5, §4.6 and §6.4): the `certify` option
// (DocMDP P = 1, 2, 3), the refusals that keep a certified document valid (E_DOC_MDP_FORBIDS), an
// approval signature on a P = 2 document, and the report's `docmdp` and `docmdpOk`. pyHanko checks
// the DocMDP level and verdict when the oracle venv is set up (`bash tools/setup-venv.sh`).

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { LocalSigner, PdfDocument, isSignatureAcceptable, signPdf } from 'folioxide'

import { assertRejectsCode, syntaxFixture } from './helpers.mjs'
import { MockTsa, REPO } from './helpers/mock-tsa.mjs'
import { ORACLE_UNAVAILABLE, pyhanko } from './helpers/oracle.mjs'

const PKI = new URL('fixtures/pki/', REPO)
const pki = (name) => readFileSync(new URL(name, PKI))
const pkiText = (name) => readFileSync(new URL(name, PKI), 'utf8')

const ROOT = pki('root.pem')
const INPUT = syntaxFixture('minimal.pdf')
const SIGNING_TIME = new Date('2026-10-10T12:00:00Z')

const p256 = () =>
  LocalSigner.fromPem(pkiText('signer-p256.key.pem'), pkiText('signer-p256.pem') + pkiText('intermediate.pem'))
const rsa = () => LocalSigner.fromPkcs12(pki('signer-rsa2048-modern.p12'), 'folioxide')

/** Verifies a signed file against the test root. */
async function verify(bytes) {
  const doc = PdfDocument.open(bytes)
  try {
    return await doc.verifySignatures({ trustAnchors: [ROOT] })
  } finally {
    doc.close()
  }
}

/** Certifies `minimal.pdf` with `P`. */
const certify = (p, options = {}) =>
  signPdf(PdfDocument.open(INPUT), { signer: p256(), signingTime: SIGNING_TIME, certify: p, ...options })

/**
 * pyHanko's verdict on each signature must have `expected`'s `docmdp`, `docmdpOk` and
 * `modification` (pyHanko's values, which agree with ours in these cases).
 */
function oracle(t, bytes, expected) {
  if (ORACLE_UNAVAILABLE) {
    t.diagnostic(`oracle skipped: ${ORACLE_UNAVAILABLE}`)
    return
  }
  const statuses = pyhanko(bytes)
  assert.equal(statuses.length, expected.length, 'pyHanko lists every signature')
  statuses.forEach((status, i) => {
    assert.equal(status.intact, true, `pyHanko signatures[${i}].intact`)
    assert.equal(status.valid, true, `pyHanko signatures[${i}].valid`)
    assert.equal(status.trusted, true, `pyHanko signatures[${i}].trusted`)
    for (const [key, value] of Object.entries(expected[i])) {
      assert.equal(status[key], value, `pyHanko signatures[${i}].${key}`)
    }
  })
}

test('certify: 1, 2 and 3 give docmdp 1, 2 and 3', async (t) => {
  for (const p of [1, 2, 3]) {
    const signed = await certify(p)
    const [report] = await verify(signed)
    assert.equal(report.docmdp, p, `P = ${p}`)
    assert.equal(report.docmdpOk, true)
    assert.equal(report.modification, 'none')
    assert.equal(report.intact && report.signatureValid && report.trusted, true)
    assert.deepEqual(report.problems, [])
    assert.equal(isSignatureAcceptable(report, 'none'), true)
    // The certification is written as ISO 32000-2 §12.8.2.2 asks: a DocMDP /Reference with
    // /P in the signature dictionary, and /Perms /DocMDP in the catalog.
    const update = signed.subarray(INPUT.length).toString('latin1')
    assert.match(update, new RegExp(`/TransformMethod\\s*/DocMDP`))
    assert.match(update, new RegExp(`/P\\s+${p}\\b`))
    assert.match(update, /\/Perms\s*<<\s*\/DocMDP\s+\d+\s+0\s+R/)
    oracle(t, signed, [{ docmdp: p, docmdpOk: true, modification: 'none' }])
  }
})

test('P = 1, then any signature is refused with E_DOC_MDP_FORBIDS', async () => {
  const certified = await certify(1)
  for (const options of [{}, { field: { name: 'Approval' } }, { certify: 2 }]) {
    await assert.rejects(signPdf(PdfDocument.open(certified), { signer: rsa(), ...options }), (err) => {
      assert.equal(err.code, 'E_DOC_MDP_FORBIDS')
      assert.match(err.message, /DocMDP/)
      return true
    })
  }
})

test('certifying twice, or after an approval signature, is refused with E_DOC_MDP_FORBIDS', async () => {
  const certified = await certify(2)
  await assertRejectsCode(
    signPdf(PdfDocument.open(certified), { signer: rsa(), certify: 2 }),
    'E_DOC_MDP_FORBIDS',
  )
  const approved = await signPdf(PdfDocument.open(INPUT), { signer: rsa() })
  await assertRejectsCode(
    signPdf(PdfDocument.open(approved), { signer: p256(), certify: 3 }),
    'E_DOC_MDP_FORBIDS',
  )
})

test('P = 2, then a visible approval signature in a new field is refused with E_DOC_MDP_FORBIDS', async () => {
  const certified = await certify(2)
  await assert.rejects(
    signPdf(PdfDocument.open(certified), {
      signer: rsa(),
      field: { name: 'Approval' },
      appearance: { rect: [100, 100, 300, 160] },
    }),
    (err) => {
      assert.equal(err.code, 'E_DOC_MDP_FORBIDS')
      assert.match(err.message, /visible/)
      return true
    },
  )
})

test('P = 2, then an invisible approval: the certification is form filling and docmdpOk', async (t) => {
  const certified = await certify(2)
  const approved = await signPdf(PdfDocument.open(certified), { signer: rsa(), signingTime: SIGNING_TIME })
  const [certification, approval] = await verify(approved)
  assert.equal(certification.docmdp, 2)
  assert.equal(certification.docmdpOk, true)
  assert.equal(certification.modification, 'formFilling')
  assert.equal(isSignatureAcceptable(certification), true)
  assert.equal(isSignatureAcceptable(certification, 'ltaUpdates'), false)
  assert.equal(approval.docmdp, null)
  assert.equal(approval.docmdpOk, true)
  assert.equal(approval.modification, 'none')
  oracle(t, approved, [
    { docmdp: 2, docmdpOk: true, modification: 'formFilling' },
    { docmdp: null, modification: 'none' },
  ])
})

test('P = 3 allows an approval too; P = 1 then an /Info change is not docmdpOk (stricter than pyHanko)', async () => {
  const certified = await certify(3)
  const approved = await signPdf(PdfDocument.open(certified), { signer: rsa() })
  const [p3] = await verify(approved)
  assert.equal(p3.docmdp, 3)
  assert.equal(p3.docmdpOk, true)
  assert.equal(p3.modification, 'formFilling')

  // P = 1 permits no change at all (ISO 32000-2 §12.8.2.2; M4 brief §0.1 `certify_p1_info_changed`):
  // an /Info change is 'ltaUpdates', which pyHanko accepts under P = 1, and which Folioxide does not.
  const strict = await certify(1)
  const doc = PdfDocument.open(strict)
  doc.setInfo({ title: 'Changed after certification' })
  const changed = doc.saveIncremental()
  doc.close()
  const [p1] = await verify(changed)
  assert.equal(p1.docmdp, 1)
  assert.equal(p1.modification, 'ltaUpdates')
  assert.equal(p1.docmdpOk, false)
  assert.equal(isSignatureAcceptable(p1, 'ltaUpdates'), false)
  assert.equal(isSignatureAcceptable(p1, 'other'), false)
})

test('a certification with a signature timestamp (B-T)', async (t) => {
  const tsa = new MockTsa({ genTime: '20261010120030Z' })
  const signed = await certify(2, { timestamp: tsa.callback })
  const [report] = await verify(signed)
  assert.equal(report.docmdp, 2)
  assert.equal(report.docmdpOk, true)
  assert.equal(report.padesLevel, 'B-T')
  assert.equal(report.timestamp.trusted, true)
  oracle(t, signed, [{ docmdp: 2, docmdpOk: true, timestamp: true, timestampValid: true }])
})

test('certify values are checked', async () => {
  for (const certifyValue of [0, 4, 1.5, '2', true, Number.NaN]) {
    await assertRejectsCode(
      signPdf(PdfDocument.open(INPUT), { signer: p256(), certify: certifyValue }),
      'E_INVALID_ARGUMENT',
    )
  }
  const doc = PdfDocument.open(INPUT)
  const signer = p256()
  assert.throws(
    () => doc.prepareSignature({ certificateChain: signer.certificateChain, algorithm: signer.algorithm, certify: 9 }),
    (err) => err.code === 'E_INVALID_ARGUMENT' && /certify/.test(err.message),
  )
  // A synchronous prepare with certify works, and the document is not changed.
  const prepared = doc.prepareSignature({
    certificateChain: signer.certificateChain,
    algorithm: signer.algorithm,
    certify: 1,
  })
  assert.equal(doc.isModified, false)
  const signed = prepared.finish(signer.sign(prepared.toBeSigned))
  doc.close()
  assert.equal((await verify(signed))[0].docmdp, 1)
})

test('a document timestamp has no docmdpOk; the certification before it keeps its verdict', async () => {
  // Manager ruling R-5: pyHanko reports no docmdp_ok for a document timestamp, and `null` never
  // refuses it in isSignatureAcceptable.
  const bytes = readFileSync(new URL('fixtures/sign/pdf/pyhanko-certified-p1-dts.pdf', REPO))
  const reports = await verify(bytes)
  const timestamp = reports.find((r) => r.kind === 'docTimeStamp')
  const certification = reports.find((r) => r.kind === 'signature')
  assert.ok(timestamp && certification)
  assert.equal(timestamp.docmdp, null)
  assert.equal(timestamp.docmdpOk, null)
  assert.equal(isSignatureAcceptable(timestamp, 'none'), true)
  assert.equal(certification.docmdp, 1)
  assert.equal(certification.docmdpOk, true)
})

// Signing and verification from Node (M3 WP3.3B; brief §3.3 and §6.4): LocalSigner from PKCS#12
// and PEM, the two-phase flow with external signers built on node:crypto and WebCrypto, signPdf,
// PreparedSignature, verifySignatures and the error codes. Every signed output is also checked by
// the signature oracles when the oracle venv is set up (`bash tools/setup-venv.sh`): pyHanko and
// pdfsig through tools/oracles/validate_sig.py, OpenSSL (`cms -verify` against the test root,
// plus the ByteRange/gap/padding structure checks) through tools/oracles/extract_cms.py.

import assert from 'node:assert/strict'
import { execFile, spawnSync } from 'node:child_process'
import {
  X509Certificate,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  webcrypto,
} from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import {
  FolioxideError,
  LocalSigner,
  PdfDocument,
  PreparedSignature,
  isSignatureAcceptable,
  signPdf,
} from 'folioxide'

import {
  REPAIRED,
  assertCode,
  assertRejectsCode,
  assertThrowsCode,
  startsWithBytes,
  syntaxFixture,
} from './helpers.mjs'

const execFileAsync = promisify(execFile)

const REPO = new URL('../../../', import.meta.url)
const PKI = new URL('fixtures/pki/', REPO)
const PASSWORD = 'folioxide'
const RSA_SUBJECT = 'CN=Folioxide Test Signer RSA-2048,OU=TEST ONLY - DO NOT TRUST,O=Folioxide Test PKI'

/** A file of the committed test PKI (`fixtures/pki`), as bytes. */
const pki = (name) => readFileSync(new URL(name, PKI))
/** A file of the committed test PKI, as text. */
const pkiText = (name) => readFileSync(new URL(name, PKI), 'utf8')
/** The DER of a PEM certificate of the test PKI. */
const der = (name) => Buffer.from(new X509Certificate(pki(name)).raw)

const ROOT = pki('root.pem')
const INPUT = syntaxFixture('minimal.pdf')
const SIGNING_TIME = new Date('2026-10-10T12:00:00Z')

const rsaP12 = (file = 'signer-rsa2048-modern.p12') => LocalSigner.fromPkcs12(pki(file), PASSWORD)
const p256Pem = () =>
  LocalSigner.fromPem(pkiText('signer-p256.key.pem'), pkiText('signer-p256.pem') + pkiText('intermediate.pem'))

/** Verifies a signed file against the test root (at the current time, the facade's default). */
async function verify(bytes, options = {}) {
  const doc = PdfDocument.open(bytes)
  try {
    return await doc.verifySignatures({ trustAnchors: [ROOT], ...options })
  } finally {
    doc.close()
  }
}

/** Asserts a report describes a good, trusted PAdES B-B signature. */
function assertGood(report) {
  assert.equal(report.intact, true, 'intact')
  assert.equal(report.signatureValid, true, 'signatureValid')
  assert.equal(report.byteRangeOk, true, 'byteRangeOk')
  assert.equal(report.trusted, true, 'trusted')
  assert.deepEqual(report.problems, [])
  assert.equal(report.kind, 'signature')
  assert.ok(report.fieldName)
}

// ---- the oracle ---------------------------------------------------------------------------------

const PYTHON = fileURLToPath(new URL('.venv/bin/python', REPO))
const VALIDATE_SIG = fileURLToPath(new URL('tools/oracles/validate_sig.py', REPO))
const EXTRACT_CMS = fileURLToPath(new URL('tools/oracles/extract_cms.py', REPO))
const ROOT_PATH = fileURLToPath(new URL('root.pem', PKI))

/** Why the oracle cannot run here, or `null` when it can. */
function oracleUnavailable() {
  if (!existsSync(PYTHON)) {
    return 'no oracle venv (.venv/bin/python; run `bash tools/setup-venv.sh`)'
  }
  if (spawnSync('pdfsig', ['-v']).error) {
    return 'pdfsig (poppler-utils) is not installed'
  }
  return null
}
const ORACLE_UNAVAILABLE = oracleUnavailable()

/** Runs an oracle script; fails the test with its output when it exits with an error. */
async function runOracle(script, args) {
  try {
    const { stdout } = await execFileAsync(PYTHON, ['-I', script, ...args], {
      cwd: fileURLToPath(REPO),
      maxBuffer: 16 << 20,
    })
    return stdout
  } catch (err) {
    assert.fail(`${script} rejected the file: ${err.message}\n${err.stdout ?? ''}${err.stderr ?? ''}`)
  }
}

/**
 * Checks a signed file with the signature oracles: pyHanko must find every signature intact,
 * valid and trusted (with the test root), with our coverage and modification; pdfsig must call
 * it valid; OpenSSL must verify the CMS over the signed bytes up to the test root, and the
 * ByteRange, gap and padding must be sound. Does nothing (but say so) when the oracles are not
 * set up.
 */
async function oracle(t, bytes, reports) {
  if (ORACLE_UNAVAILABLE) {
    t.diagnostic(`oracle skipped: ${ORACLE_UNAVAILABLE}`)
    return
  }
  const dir = mkdtempSync(join(tmpdir(), 'folioxide-sign-'))
  const file = join(dir, 'signed.pdf')
  writeFileSync(file, bytes)
  let stdout
  try {
    ;[stdout] = await Promise.all([
      runOracle(VALIDATE_SIG, [file, '--trust-root', ROOT_PATH, '--json']),
      runOracle(EXTRACT_CMS, [file, '--verify', '--ca-file', ROOT_PATH]),
    ])
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
  const statuses = JSON.parse(stdout)
  assert.equal(statuses.length, reports.length, 'pyHanko lists every signature')
  statuses.forEach((status, i) => {
    assert.equal(status.field, reports[i].fieldName)
    assert.equal(status.intact, reports[i].intact)
    assert.equal(status.valid, reports[i].signatureValid)
    assert.equal(status.trusted, reports[i].trusted)
    assert.equal(status.coverage, reports[i].coverage, `signatures[${i}].coverage`)
    assert.equal(status.modification, reports[i].modification, `signatures[${i}].modification`)
  })
}

test('the signature oracles are available (pyHanko, pdfsig, OpenSSL)', { skip: ORACLE_UNAVAILABLE ?? false }, () => {
  assert.equal(ORACLE_UNAVAILABLE, null)
})

// ---- 1, 13: PKCS#12 ------------------------------------------------------------------------------

test('signPdf with a PKCS#12 key: one trusted, whole-file signature', async (t) => {
  const signer = rsaP12()
  assert.equal(signer.algorithm, 'rsa-pkcs1v15')
  assert.equal(signer.defaultDigest, 'sha256')
  assert.equal(signer.certificateChain.length, 3, 'signer, intermediate and root')
  assert.ok(signer.certificateChain.every((cert) => Buffer.isBuffer(cert)))

  const doc = PdfDocument.open(INPUT)
  const out = await signPdf(doc, { signer, signingTime: SIGNING_TIME })
  // 13: an incremental update; the document itself is unchanged.
  assert.ok(out.subarray(0, INPUT.length).equals(INPUT), 'the original bytes are a prefix')
  assert.equal(doc.isModified, false)

  const reports = await verify(out)
  assert.equal(reports.length, 1)
  const [report] = reports
  assertGood(report)
  assert.equal(report.coverage, 'entireFile')
  assert.equal(report.modification, 'none')
  assert.equal(report.signer.subject, RSA_SUBJECT)
  assert.equal(report.fieldName, 'Signature1')
  assert.equal(report.subFilter, 'ETSI.CAdES.detached')
  assert.equal(report.padesLevel, 'B-B')
  assert.equal(report.digestAlgorithm, 'sha256')
  assert.equal(report.signatureAlgorithm, 'sha256WithRSAEncryption')
  assert.equal(report.claimedTime, '2026-10-10T12:00:00Z')
  assert.equal(report.signer.key.algorithm, 'rsa')
  assert.equal(report.signer.key.bits, 2048)
  assert.equal(report.signer.key.curve, null)
  assert.ok(report.signer.der.equals(signer.certificateChain[0]))
  assert.deepEqual(
    report.chain.map((cert) => cert.commonName),
    ['Folioxide Test Signer RSA-2048', 'Folioxide Test Intermediate CA', 'Folioxide Test Root CA'],
  )
  assert.deepEqual(report.byteRange.slice(0, 1), [0])
  assert.equal(report.byteRange[2] + report.byteRange[3], out.length)
  assert.deepEqual(report.sigObject, { num: report.sigObject.num, gen: 0 })
  assert.deepEqual(report.changedObjects, [])
  assert.equal(report.docmdp, null)
  // M4 (D-13): docmdpOk is computed for every signature, with P = 2 when none is certified.
  assert.equal(report.docmdpOk, true)
  assert.equal(report.timestamp, null)
  assert.deepEqual(report.timestamps, [])
  assert.equal(report.padesLevel, 'B-B')
  // The report is plain JSON data (the shape of the core's serde DTOs).
  const json = JSON.parse(JSON.stringify(report))
  assert.equal(json.coverage, 'entireFile')
  await oracle(t, out, reports)
})

test('signPdf with legacy PKCS#12 files (3DES and RC2-40)', async (t) => {
  for (const file of ['signer-rsa2048-3des.p12', 'signer-rsa2048-rc2-40.p12']) {
    const out = await signPdf(PdfDocument.open(INPUT), { signer: rsaP12(file) })
    const reports = await verify(out)
    assert.equal(reports.length, 1, file)
    assertGood(reports[0])
    assert.equal(reports[0].signer.subject, RSA_SUBJECT)
    await oracle(t, out, reports)
  }
})

// ---- 2: PEM -------------------------------------------------------------------------------------

test('signPdf with PEM keys: P-256 with its chain, and an encrypted P-384 key', async (t) => {
  const p256 = p256Pem()
  assert.equal(p256.algorithm, 'ecdsa')
  assert.equal(p256.defaultDigest, 'sha256')
  const out = await signPdf(PdfDocument.open(INPUT), { signer: p256 })
  let reports = await verify(out)
  assertGood(reports[0])
  assert.equal(reports[0].signer.key.curve, 'P-256')
  assert.equal(reports[0].signatureAlgorithm, 'ecdsa-with-SHA256')
  await oracle(t, out, reports)

  // The key as bytes read from a file, the chain in any order (the matching certificate goes
  // first), the key encrypted.
  const p384 = LocalSigner.fromPem(
    pki('signer-p384.key.enc.pem'),
    pkiText('intermediate.pem') + pkiText('signer-p384.pem'),
    PASSWORD,
  )
  assert.equal(p384.defaultDigest, 'sha384')
  assert.ok(p384.certificateChain[0].equals(der('signer-p384.pem')))
  const out384 = await signPdf(PdfDocument.open(INPUT), { signer: p384 })
  reports = await verify(out384)
  assertGood(reports[0])
  assert.equal(reports[0].signer.key.curve, 'P-384')
  assert.equal(reports[0].digestAlgorithm, 'sha384')
  await oracle(t, out384, reports)

  // PKCS#1 and SEC1 keys load too.
  assert.equal(
    LocalSigner.fromPem(pkiText('signer-rsa3072.key.pkcs1.pem'), pkiText('signer-rsa3072.pem')).algorithm,
    'rsa-pkcs1v15',
  )
  assert.equal(
    LocalSigner.fromPem(pkiText('signer-p384.key.sec1.pem'), pkiText('signer-p384.pem')).defaultDigest,
    'sha384',
  )
})

// ---- 3: key-loading errors ----------------------------------------------------------------------

test('key-loading errors have stable codes and never quote the password', () => {
  const wrong = 'not-the-password-7f3a'
  const messages = []
  const expectCode = (fn, code) =>
    assert.throws(fn, (err) => {
      assertCode(err, code)
      messages.push(err.message)
      return true
    })
  expectCode(() => LocalSigner.fromPkcs12(pki('signer-rsa2048-modern.p12'), wrong), 'E_WRONG_PASSWORD')
  expectCode(() => LocalSigner.fromPkcs12(pki('signer-rsa2048-3des.p12'), wrong), 'E_WRONG_PASSWORD')
  expectCode(
    () => LocalSigner.fromPem(pkiText('signer-p384.key.enc.pem'), pkiText('signer-p384.pem')),
    'E_PASSWORD_REQUIRED',
  )
  expectCode(
    () => LocalSigner.fromPem(pkiText('signer-p384.key.enc.pem'), pkiText('signer-p384.pem'), wrong),
    'E_WRONG_PASSWORD',
  )
  expectCode(() => LocalSigner.fromPkcs12(Buffer.from('garbage, not a PKCS#12 file'), wrong), 'E_KEY_LOAD')
  expectCode(() => LocalSigner.fromPem('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n', pkiText('signer-p256.pem')), 'E_KEY_LOAD')
  // A key whose certificate is not in the PEM.
  expectCode(() => LocalSigner.fromPem(pkiText('signer-p256.key.pem'), pkiText('signer-p384.pem')), 'E_KEY_LOAD')
  expectCode(() => LocalSigner.fromPem(pkiText('signer-p256.key.pem'), 'no certificates here'), 'E_CERTIFICATE')
  for (const message of messages) {
    assert.ok(!message.includes(wrong), `the message quotes the password: ${message}`)
    assert.ok(!message.includes(PASSWORD), `the message quotes a password: ${message}`)
  }
  // Argument types are checked before anything reaches the native addon.
  assertThrowsCode(() => LocalSigner.fromPkcs12('signer.p12', PASSWORD), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => LocalSigner.fromPkcs12(pki('signer-rsa2048-modern.p12')), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => LocalSigner.fromPem(42, 'x'), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => new LocalSigner(), 'E_INVALID_ARGUMENT')
})

test('LocalSigner signs bytes directly (RSA PKCS#1 v1.5, ECDSA DER)', async () => {
  const data = Buffer.from('bytes to sign')
  const rsa = rsaP12()
  const rsaSignature = rsa.sign(data)
  assert.equal(rsaSignature.length, 256)
  assert.ok(cryptoVerify('sha256', data, createPublicKey(pki('signer-rsa2048.pem')), rsaSignature))
  // PKCS#1 v1.5 is deterministic: the async form gives the same bytes.
  assert.ok((await rsa.signAsync(data)).equals(rsaSignature))

  const p256 = p256Pem()
  const ecdsa = p256.sign(data, 'sha384')
  assert.equal(ecdsa[0], 0x30, 'a DER ECDSA-Sig-Value')
  assert.ok(cryptoVerify('sha384', data, createPublicKey(pki('signer-p256.pem')), ecdsa))
  assertThrowsCode(() => p256.sign(data, 'sha1'), 'E_INVALID_ARGUMENT')
  await assertRejectsCode(p256.signAsync(data, 'md5'), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => p256.sign('text'), 'E_INVALID_ARGUMENT')
})

test('LocalSigner takes secrets as bytes, and close() or using wipes the key', async () => {
  // The password and the PEM key as bytes, which the caller wipes after loading.
  const password = Buffer.from(PASSWORD)
  const fromP12 = LocalSigner.fromPkcs12(pki('signer-p256-modern.p12'), password)
  password.fill(0)
  const keyPem = pki('signer-p384.key.enc.pem')
  const keyPassword = new TextEncoder().encode(PASSWORD)
  const fromPem = LocalSigner.fromPem(keyPem, pki('signer-p384.pem'), keyPassword)
  keyPem.fill(0)
  keyPassword.fill(0)
  assert.equal(fromPem.defaultDigest, 'sha384')
  assert.equal(fromP12.algorithm, 'ecdsa')
  expectNoSecret(() => LocalSigner.fromPkcs12(pki('signer-p256-modern.p12'), Buffer.from('wrong-secret')), 'E_WRONG_PASSWORD')
  expectNoSecret(() => LocalSigner.fromPkcs12(pki('signer-p256-modern.p12'), Buffer.from([0xff, 0xfe])), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => LocalSigner.fromPkcs12(pki('signer-p256-modern.p12'), 42), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => LocalSigner.fromPem(pkiText('signer-p384.key.enc.pem'), pkiText('signer-p384.pem'), 42), 'E_INVALID_ARGUMENT')

  // close(): every method and getter but isClosed throws E_CLOSED; a second close does nothing.
  const data = Buffer.from('bytes to sign')
  const running = fromP12.signAsync(data)
  assert.equal(fromP12.isClosed, false)
  fromP12.close()
  fromP12.close()
  assert.equal(fromP12.isClosed, true)
  // A signAsync started before close() still signs.
  assert.ok(cryptoVerify('sha256', data, createPublicKey(pki('signer-p256.pem')), await running))
  assertThrowsCode(() => fromP12.sign(data), 'E_CLOSED')
  await assertRejectsCode(fromP12.signAsync(data), 'E_CLOSED')
  assertThrowsCode(() => fromP12.certificateChain, 'E_CLOSED')
  assertThrowsCode(() => fromP12.algorithm, 'E_CLOSED')
  assertThrowsCode(() => fromP12.defaultDigest, 'E_CLOSED')
  await assertRejectsCode(signPdf(PdfDocument.open(INPUT), { signer: fromP12 }), 'E_CLOSED')

  // Symbol.dispose, which `using` calls (Node 20.4 and later).
  if (typeof Symbol.dispose === 'symbol') {
    fromPem[Symbol.dispose]()
    assert.equal(fromPem.isClosed, true)
    assertThrowsCode(() => fromPem.sign(data), 'E_CLOSED')
  }
})

/** Asserts `fn` throws `code` with a message that quotes no secret. */
function expectNoSecret(fn, code) {
  try {
    fn()
  } catch (err) {
    assertCode(err, code)
    assert.ok(!err.message.includes('wrong-secret'), err.message)
    return
  }
  assert.fail(`expected ${code}`)
}

// ---- 4-6: external signers ----------------------------------------------------------------------

/** An external signer over node:crypto with a PEM key of the test PKI. */
function nodeSigner(keyFile, certFiles, algorithm, { dsaEncoding, digest } = {}) {
  const key = createPrivateKey(pki(keyFile))
  return {
    // DER certificates (PEM text would do too).
    certificateChain: certFiles.map(der),
    algorithm,
    digest,
    sign(toBeSigned, toBeSignedDigest, digestAlgorithm) {
      assert.ok(Buffer.isBuffer(toBeSigned) && Buffer.isBuffer(toBeSignedDigest))
      return cryptoSign(digestAlgorithm, toBeSigned, dsaEncoding ? { key, dsaEncoding } : key)
    },
  }
}

test('external RSA signer on node:crypto', async (t) => {
  const signer = nodeSigner('signer-rsa2048.key.pem', ['signer-rsa2048.pem', 'intermediate.pem'], 'rsa-pkcs1v15')
  const out = await signPdf(PdfDocument.open(INPUT), { signer })
  const reports = await verify(out)
  assertGood(reports[0])
  assert.equal(reports[0].signer.subject, RSA_SUBJECT)
  await oracle(t, out, reports)

  // The external value equals the local one: PKCS#1 v1.5 is deterministic.
  const local = await signPdf(PdfDocument.open(INPUT), {
    signer: LocalSigner.fromPem(pkiText('signer-rsa2048.key.pem'), pkiText('signer-rsa2048.pem') + pkiText('intermediate.pem')),
    signingTime: SIGNING_TIME,
  })
  const external = await signPdf(PdfDocument.open(INPUT), { signer, signingTime: SIGNING_TIME })
  assert.ok(local.equals(external), 'byte-identical')
})

test('external ECDSA P-256 signer: IEEE P1363 and DER values', async (t) => {
  for (const dsaEncoding of ['ieee-p1363', 'der']) {
    const signer = nodeSigner('signer-p256.key.pem', ['signer-p256.pem', 'intermediate.pem'], 'ecdsa', { dsaEncoding })
    const out = await signPdf(PdfDocument.open(INPUT), { signer, reason: dsaEncoding })
    const reports = await verify(out)
    assertGood(reports[0])
    assert.equal(reports[0].reason, dsaEncoding)
    assert.equal(reports[0].signer.key.curve, 'P-256')
    await oracle(t, out, reports)
  }
})

test('external ECDSA P-384 signer with SHA-384', async (t) => {
  const signer = nodeSigner('signer-p384.key.pem', ['signer-p384.pem', 'intermediate.pem'], 'ecdsa', {
    dsaEncoding: 'ieee-p1363',
    digest: 'sha384',
  })
  const out = await signPdf(PdfDocument.open(INPUT), { signer })
  const reports = await verify(out)
  assertGood(reports[0])
  assert.equal(reports[0].digestAlgorithm, 'sha384')
  assert.equal(reports[0].signatureAlgorithm, 'ecdsa-with-SHA384')
  await oracle(t, out, reports)
  // The options' digest wins over the signer's.
  const sha512 = await signPdf(PdfDocument.open(INPUT), { signer, digest: 'sha512' })
  assert.equal((await verify(sha512))[0].digestAlgorithm, 'sha512')
})

test('external WebCrypto signer returning an ArrayBuffer', async (t) => {
  const pkcs8 = createPrivateKey(pki('signer-p256.key.pem')).export({ type: 'pkcs8', format: 'der' })
  const key = await webcrypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
  const signer = {
    // PEM text works as well as DER.
    certificateChain: [pki('signer-p256.pem'), pki('intermediate.pem')],
    algorithm: 'ecdsa',
    sign: (toBeSigned) => webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, toBeSigned),
  }
  const out = await signPdf(PdfDocument.open(INPUT), { signer })
  const reports = await verify(out)
  assertGood(reports[0])
  await oracle(t, out, reports)
})

// ---- 7: asynchronous signers, concurrency -------------------------------------------------------

test('an asynchronous signer, and two signPdf calls at once on two documents', async (t) => {
  const inner = nodeSigner('signer-p256.key.pem', ['signer-p256.pem', 'intermediate.pem'], 'ecdsa', {
    dsaEncoding: 'ieee-p1363',
  })
  let calls = 0
  const signer = {
    ...inner,
    sign: (tbs, digest, alg) =>
      new Promise((resolve) => {
        calls += 1
        setTimeout(() => resolve(inner.sign(tbs, digest, alg)), 20)
      }),
  }
  const other = syntaxFixture('xref-stream.pdf')
  const [first, second] = await Promise.all([
    signPdf(PdfDocument.open(INPUT), { signer, reason: 'first' }),
    signPdf(PdfDocument.open(other), { signer, reason: 'second' }),
  ])
  assert.equal(calls, 2)
  assert.ok(startsWithBytes(first, INPUT))
  assert.ok(startsWithBytes(second, other))
  for (const [out, reason] of [[first, 'first'], [second, 'second']]) {
    const reports = await verify(out)
    assertGood(reports[0])
    assert.equal(reports[0].reason, reason)
    await oracle(t, out, reports)
  }
})

// ---- 8: a signer with the wrong key ------------------------------------------------------------

test('a signature by another key is refused with E_SIGNATURE_INVALID', async () => {
  // The chain is the RSA-2048 signer's, the key another RSA-2048 key.
  const signer = nodeSigner('wrong-ku.key.pem', ['signer-rsa2048.pem', 'intermediate.pem'], 'rsa-pkcs1v15')
  await assertRejectsCode(signPdf(PdfDocument.open(INPUT), { signer }), 'E_SIGNATURE_INVALID')
  // A value of the wrong length, and garbage for ECDSA.
  const prepared = PdfDocument.open(INPUT).prepareSignature({
    certificateChain: [der('signer-p256.pem')],
    algorithm: 'ecdsa',
  })
  assertThrowsCode(() => prepared.finish(Buffer.alloc(63, 1)), 'E_SIGNATURE_INVALID')
})

test('a refused value leaves the prepared signature, so the signer can be asked again', async () => {
  const signer = p256Pem()
  const options = { certificateChain: signer.certificateChain, algorithm: signer.algorithm, signingTime: SIGNING_TIME }
  const prepared = PdfDocument.open(INPUT).prepareSignature(options)
  const stored = prepared.serialize()
  const wrongKey = createPrivateKey(pki('signer-p384.key.pem'))
  const byOtherKey = cryptoSign('sha256', prepared.toBeSigned, wrongKey)
  const overOtherBytes = signer.sign(Buffer.from('other bytes'))

  // Synchronous and asynchronous refusals, of values and of CMSes: nothing is taken.
  assertThrowsCode(() => prepared.finish(byOtherKey), 'E_SIGNATURE_INVALID')
  await assertRejectsCode(prepared.finishAsync(overOtherBytes), 'E_SIGNATURE_INVALID')
  assertThrowsCode(() => prepared.embedCms(Buffer.from('not a CMS')), 'E_INVALID_ARGUMENT')
  await assertRejectsCode(prepared.embedCmsAsync(Buffer.from('not a CMS')), 'E_INVALID_ARGUMENT')
  assert.equal(prepared.isFinished, false)
  assert.ok(prepared.serialize().equals(stored), 'unchanged')

  // While finishAsync runs, the other finishing methods and serialize are busy.
  const value = signer.sign(prepared.toBeSigned, prepared.digestAlgorithm)
  const running = prepared.finishAsync(value)
  assertThrowsCode(() => prepared.finish(value), 'E_BUSY')
  assertThrowsCode(() => prepared.embedCms(Buffer.alloc(8)), 'E_BUSY')
  assertThrowsCode(() => prepared.serialize(), 'E_BUSY')
  await assertRejectsCode(prepared.finishAsync(value), 'E_BUSY')
  await assertRejectsCode(prepared.embedCmsAsync(Buffer.alloc(8)), 'E_BUSY')
  assert.equal(prepared.isFinished, false)
  const signed = await running
  assert.equal(prepared.isFinished, true)
  assertGood((await verify(signed))[0])
  // The same file as finishing at once.
  assert.ok(PreparedSignature.deserialize(stored).finish(value).equals(signed))
  // Once finished, it is taken.
  assertThrowsCode(() => prepared.finish(value), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => prepared.serialize(), 'E_INVALID_ARGUMENT')
})

// ---- 9: the two phases, serialization ------------------------------------------------------------

test('prepareSignature, serialize, deserialize and finish give the same file as finishing directly', async () => {
  const signer = p256Pem()
  const doc = PdfDocument.open(INPUT)
  const options = { certificateChain: signer.certificateChain, algorithm: signer.algorithm, signingTime: SIGNING_TIME }
  const prepared = doc.prepareSignature(options)
  assert.equal(prepared.digestAlgorithm, 'sha256')
  assert.equal(prepared.algorithm, 'ecdsa')
  assert.equal(prepared.subFilter, 'ETSI.CAdES.detached')
  assert.ok(prepared.contentsCapacity >= 8192)
  assert.equal(prepared.toBeSigned[0], 0x31, 'the signed attributes, SET tag')
  assert.equal(prepared.toBeSignedDigest.length, 32)
  assert.equal(prepared.toBeSignedDigestInfo.length, 51)
  assert.ok(prepared.toBeSignedDigestInfo.subarray(19).equals(prepared.toBeSignedDigest))
  assert.deepEqual(prepared.warnings, [])
  assert.equal(prepared.isFinished, false)
  const [zero, a, b, c] = prepared.byteRange
  assert.equal(zero, 0)
  assert.equal(b - a, 2 * prepared.contentsCapacity + 2)

  const serialized = prepared.serialize()
  assert.equal(serialized.subarray(0, 4).toString('latin1'), 'FXPS')
  const restored = PreparedSignature.deserialize(serialized)
  assert.ok(restored.toBeSigned.equals(prepared.toBeSigned))
  assert.deepEqual(restored.byteRange, prepared.byteRange)

  const signature = signer.sign(prepared.toBeSigned, prepared.digestAlgorithm)
  const direct = prepared.finish(signature)
  const fromSerialized = await restored.finishAsync(signature)
  assert.ok(direct.equals(fromSerialized), 'byte-identical')
  assert.equal(direct.length, a + (b - a) + c)
  assertGood((await verify(direct))[0])

  // Finishing takes the prepared file: a second call is refused, the getters keep working.
  assert.equal(prepared.isFinished, true)
  assertThrowsCode(() => prepared.finish(signature), 'E_INVALID_ARGUMENT')
  await assertRejectsCode(prepared.finishAsync(signature), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => prepared.embedCms(Buffer.alloc(8)), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => prepared.serialize(), 'E_INVALID_ARGUMENT')
  assert.equal(prepared.digestAlgorithm, 'sha256')

  // Changed bytes are refused.
  const tampered = Buffer.from(serialized)
  tampered[tampered.length - 40] ^= 0x01
  assertThrowsCode(() => PreparedSignature.deserialize(tampered), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => PreparedSignature.deserialize(Buffer.from('FXPS')), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => PreparedSignature.deserialize('FXPS'), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => new PreparedSignature(), 'E_INVALID_ARGUMENT')
})

/** The DER CMS in the `/Contents` of a signed file, given the prepared byte range. */
function cmsOf(signed, [, a, b]) {
  const bytes = Buffer.from(signed.toString('latin1', a + 1, b - 1), 'hex')
  assert.equal(bytes[0], 0x30)
  let length = bytes[1]
  let header = 2
  if (length & 0x80) {
    const count = length & 0x7f
    length = 0
    for (let i = 0; i < count; i++) {
      length = length * 256 + bytes[2 + i]
    }
    header += count
  }
  return bytes.subarray(0, header + length)
}

test('embedCms finishes with a whole CMS made elsewhere', async () => {
  const signer = rsaP12()
  const doc = PdfDocument.open(INPUT)
  const options = { certificateChain: signer.certificateChain, algorithm: signer.algorithm, signingTime: SIGNING_TIME }
  // Preparing is deterministic: two preparations of one document are the same.
  const first = doc.prepareSignature(options)
  const second = await doc.prepareSignatureAsync(options)
  assert.ok(first.toBeSigned.equals(second.toBeSigned))
  const signed = first.finish(signer.sign(first.toBeSigned))
  const cms = cmsOf(signed, first.byteRange)
  const embedded = second.embedCms(cms)
  assert.ok(embedded.equals(signed), 'the same file as finish')

  // A CMS over other bytes (another signing time), and garbage.
  const other = doc.prepareSignature({ ...options, signingTime: new Date('2026-10-11T12:00:00Z') })
  assertThrowsCode(() => other.embedCms(cms), 'E_SIGNATURE_INVALID')
  const third = doc.prepareSignature(options)
  await assertRejectsCode(third.embedCmsAsync(Buffer.from('not a CMS')), 'E_INVALID_ARGUMENT')
})

// ---- 10: the placeholder ------------------------------------------------------------------------

test('a too-small contentsReserve throws E_SIGNATURE_PLACEHOLDER_TOO_SMALL with details; signPdf retries', async (t) => {
  const signer = rsaP12()
  const doc = PdfDocument.open(INPUT)
  const options = { certificateChain: signer.certificateChain, algorithm: signer.algorithm, contentsReserve: 100 }
  let caught
  assert.throws(
    () => doc.prepareSignature(options),
    (err) => {
      caught = err
      return assertCode(err, 'E_SIGNATURE_PLACEHOLDER_TOO_SMALL')
    },
  )
  assert.ok(caught instanceof FolioxideError)
  assert.equal(typeof caught.details.needed, 'number')
  assert.ok(caught.details.needed > 100, `needed ${caught.details.needed}`)
  assert.equal(caught.details.reserved, 100)
  await assert.rejects(doc.prepareSignatureAsync(options), (err) => {
    assertCode(err, 'E_SIGNATURE_PLACEHOLDER_TOO_SMALL')
    return err.details.needed === caught.details.needed
  })
  // The exact size fits.
  const exact = doc.prepareSignature({ ...options, contentsReserve: caught.details.needed })
  assert.equal(exact.contentsCapacity, caught.details.needed)

  // signPdf prepares once more with the size needed.
  const out = await signPdf(doc, { signer, contentsReserve: 100 })
  const reports = await verify(out)
  assertGood(reports[0])
  await oracle(t, out, reports)
  assertThrowsCode(() => doc.prepareSignature({ ...options, contentsReserve: 0 }), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.prepareSignature({ ...options, contentsReserve: 5e6 }), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.prepareSignature({ ...options, contentsReserve: '100' }), 'E_INVALID_ARGUMENT')
})

// ---- 11: sequential signatures ------------------------------------------------------------------

test('sequential signatures: the first covers its revision, the second added form filling', async (t) => {
  const first = await signPdf(PdfDocument.open(INPUT), { signer: rsaP12(), reason: 'first' })
  const second = await signPdf(PdfDocument.open(first), { signer: p256Pem(), reason: 'second' })
  assert.ok(startsWithBytes(second, first))
  const reports = await verify(second)
  assert.equal(reports.length, 2)
  reports.forEach(assertGood)
  assert.deepEqual(
    reports.map((r) => [r.fieldName, r.reason]),
    [
      ['Signature1', 'first'],
      ['Signature2', 'second'],
    ],
  )
  assert.equal(reports[0].coverage, 'entireRevision')
  assert.equal(reports[0].modification, 'formFilling')
  assert.ok(reports[0].changedObjects.length > 0)
  assert.equal(reports[0].signedRevision + 1, reports[1].signedRevision)
  assert.equal(reports[1].coverage, 'entireFile')
  assert.equal(reports[1].modification, 'none')
  await oracle(t, second, reports)
})

// ---- 12: tampering ------------------------------------------------------------------------------

test('a byte changed inside the signed range makes the signature not intact', async () => {
  const out = await signPdf(PdfDocument.open(INPUT), { signer: p256Pem() })
  const tampered = Buffer.from(out)
  // The page content `(minimal)`, in the first signed range.
  const at = tampered.indexOf('(minimal)', 0, 'latin1') + 1
  assert.ok(at > 0)
  tampered[at] = 'M'.charCodeAt(0)
  const [report] = await verify(tampered)
  assert.equal(report.intact, false)
  assert.ok(report.problems.some((problem) => problem.code === 'digestMismatch'), JSON.stringify(report.problems))
  assert.equal(report.byteRangeOk, true)
})

test('isSignatureAcceptable gates on what was appended after signing, not only on the signature', async () => {
  const signed = await signPdf(PdfDocument.open(INPUT), { signer: p256Pem() })
  const [whole] = await verify(signed)
  assert.equal(isSignatureAcceptable(whole), true)
  assert.equal(isSignatureAcceptable(whole, 'none'), true)

  // A later incremental update changes the page: the signature over its revision stays intact and
  // valid, and only `modification` says that the document changed.
  const doc = PdfDocument.open(signed)
  doc.setPageRotation(0, 90)
  const changed = doc.saveIncremental()
  doc.close()
  const [report] = await verify(changed)
  assert.equal(report.intact && report.signatureValid && report.byteRangeOk, true)
  assert.equal(report.coverage, 'entireRevision')
  assert.equal(report.modification, 'other')
  assert.equal(isSignatureAcceptable(report), false)
  assert.equal(isSignatureAcceptable(report, 'annotations'), false)
  // M4 (D-13): a change that is 'other' breaks the DocMDP permissions in force (P = 2 without a
  // certification), so not even 'other' accepts it; the modification bound alone would.
  assert.equal(report.docmdpOk, false)
  assert.equal(isSignatureAcceptable(report, 'other'), false)
  assert.equal(isSignatureAcceptable({ ...report, docmdpOk: null }, 'other'), true)

  // A second signature is form filling for the first: accepted by default, not with 'ltaUpdates'.
  const twice = await signPdf(PdfDocument.open(signed), { signer: rsaP12() })
  const [first] = await verify(twice)
  assert.equal(first.modification, 'formFilling')
  assert.equal(isSignatureAcceptable(first), true)
  assert.equal(isSignatureAcceptable(first, 'ltaUpdates'), false)

  // A report that is not sound is never acceptable; bad arguments are refused.
  assert.equal(isSignatureAcceptable({ ...whole, intact: false }, 'other'), false)
  assert.equal(isSignatureAcceptable({ ...whole, problems: [{ code: 'orphan', message: '' }] }), false)
  assertThrowsCode(() => isSignatureAcceptable(whole, 'everything'), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => isSignatureAcceptable(null), 'E_INVALID_ARGUMENT')
})

/**
 * `signed` (one signature by Folioxide on `minimal.pdf`) with an incremental update that adds a
 * visible, still unsigned signature field at the root of `/Fields` and on page 1, whose appearance
 * paints over the whole page (QA finding: a new visible signature widget added after signing).
 */
function withVisibleSignatureField(signed) {
  const text = signed.toString('latin1')
  const last = (re) => [...text.matchAll(re)].at(-1)
  const root = Number(last(/\/Root (\d+) 0 R/g)[1])
  const acroform = Number(last(/\/AcroForm (\d+) 0 R/g)[1])
  const fields = new RegExp(`\\n${acroform} 0 obj\\n<</Fields \\[([^\\]]*)\\]`).exec(text)[1]
  const [, page, pageDict, annots] = last(/\n(\d+) 0 obj\n(<<\/Type \/Page [^\n]*\/Annots \[([^\]]*)\]>>)\nendobj\n/g)
  const size = Number(last(/\/Size (\d+)/g)[1])
  const prev = Number(last(/startxref\s+(\d+)/g)[1])
  const [appearance, widget] = [size, size + 1]
  const offsets = new Map()
  const parts = []
  let offset = signed.length
  const add = (num, body) => {
    const object = `${num} 0 obj\n${body}\nendobj\n`
    offsets.set(Number(num), offset)
    parts.push(object)
    offset += object.length
  }
  const paint = '1 1 1 rg 0 0 612 792 re f'
  add(page, pageDict.replace(`/Annots [${annots}]`, `/Annots [${annots} ${widget} 0 R]`))
  add(acroform, `<</Fields [${fields} ${widget} 0 R] /SigFlags 3>>`)
  add(
    appearance,
    `<</Type /XObject /Subtype /Form /BBox [0 0 612 792] /Length ${paint.length}>>\nstream\n${paint}\nendstream`,
  )
  add(widget, `<</Type /Annot /Subtype /Widget /FT /Sig /T (Overlay) /F 4 /P ${page} 0 R /Rect [0 0 612 792] /AP <</N ${appearance} 0 R>>>>`)
  const entry = (num) => `${String(offsets.get(Number(num))).padStart(10, '0')} 00000 n \n`
  const xref = `xref\n${page} 1\n${entry(page)}${acroform} 1\n${entry(acroform)}${appearance} 2\n${entry(appearance)}${entry(widget)}`
  const trailer = `trailer\n<</Size ${widget + 1} /Root ${root} 0 R /Prev ${prev}>>\nstartxref\n${offset}\n%%EOF\n`
  return Buffer.concat([signed, Buffer.from(parts.join('') + xref + trailer, 'latin1')])
}

test("isSignatureAcceptable: 'formFilling' includes a visible signature field added after signing", async (t) => {
  // What the docs of isSignatureAcceptable say: such a field's appearance can cover signed
  // content, pyHanko classifies it as form filling too, and 'ltaUpdates' is the strict choice.
  const signed = await signPdf(PdfDocument.open(INPUT), { signer: p256Pem() })
  const overlaid = withVisibleSignatureField(signed)
  assert.ok(overlaid.subarray(0, signed.length).equals(signed))
  const reports = await verify(overlaid)
  // The new field has no value, so it has no report of its own.
  assert.equal(reports.length, 1, JSON.stringify(reports))
  const [report] = reports
  assert.equal(report.intact && report.signatureValid && report.byteRangeOk && report.trusted, true)
  assert.equal(report.coverage, 'entireRevision')
  assert.equal(report.modification, 'formFilling', JSON.stringify(report.warnings))
  assert.equal(isSignatureAcceptable(report), true)
  assert.equal(isSignatureAcceptable(report, 'ltaUpdates'), false)
  await oracle(t, overlaid, reports)
})

/**
 * `signed` (one signature by Folioxide on `minimal.pdf`) with an empty incremental update whose
 * trailer gives `/Prev` twice: the signed revision's section first, then the unsigned base's (M4
 * QA round 2, finding 9).
 */
function withTwoPrevs(signed) {
  const text = signed.toString('latin1')
  const sections = [...text.matchAll(/startxref\s+(\d+)/g)].map((m) => Number(m[1]))
  assert.equal(sections.length, 2, 'the signed file has two revisions')
  const [base, real] = sections
  const root = [...text.matchAll(/\/Root (\d+) 0 R/g)].at(-1)[1]
  const size = [...text.matchAll(/\/Size (\d+)/g)].at(-1)[1]
  const update =
    `xref\n0 1\n0000000000 65535 f \ntrailer\n<</Size ${size} /Root ${root} 0 R /Prev ${real} /Prev ${base}>>\n` +
    `startxref\n${signed.length}\n%%EOF\n`
  return Buffer.concat([signed, Buffer.from(update, 'latin1')])
}

test('verifySignatures rejects a trailer that gives /Prev twice with E_XREF', async () => {
  // First-wins readers (pyHanko, pypdf) follow the signed revision and list the signature; a
  // last-wins reader follows the unsigned base and would list none. An empty list would let a
  // "no signatures" policy branch through, so verification fails instead.
  const signed = await signPdf(PdfDocument.open(INPUT), { signer: p256Pem() })
  const doc = PdfDocument.open(withTwoPrevs(signed))
  try {
    await assertRejectsCode(doc.verifySignatures({ trustAnchors: [ROOT] }), 'E_XREF')
  } finally {
    doc.close()
  }
})

/**
 * `signed` (one signature, `Signature1`, by Folioxide) with an incremental update that adds a root
 * field `P` whose `kids` kid fields all have the signature's dictionary as `/V` (QA K100k: one
 * signature dictionary shared by a hundred thousand fields).
 */
function kidsSharingTheSignature(signed, kids) {
  const text = signed.toString('latin1')
  const last = (re) => Number([...text.matchAll(re)].at(-1)[1])
  const root = last(/\/Root (\d+) 0 R/g)
  const acroform = last(/\/AcroForm (\d+) 0 R/g)
  const sig = last(/\/T \(Signature1\) \/V (\d+) 0 R/g)
  const fields = new RegExp(`\\n${acroform} 0 obj\\n<</Fields \\[([^\\]]*)\\]`).exec(text)[1]
  const size = last(/\/Size (\d+)/g)
  const prev = last(/startxref\s+(\d+)/g)
  const parent = size
  const offsets = new Map()
  const parts = []
  let offset = signed.length
  const add = (num, body) => {
    const object = `${num} 0 obj\n${body}\nendobj\n`
    offsets.set(num, offset)
    parts.push(object)
    offset += object.length
  }
  const kidRefs = Array.from({ length: kids }, (_, k) => `${parent + 1 + k} 0 R`)
  add(parent, `<</FT /Sig /T (P) /Kids [${kidRefs.join(' ')}]>>`)
  for (let k = 0; k < kids; k++) add(parent + 1 + k, `<</T (k${k}) /Parent ${parent} 0 R /V ${sig} 0 R>>`)
  add(acroform, `<</Fields [${fields} ${parent} 0 R] /SigFlags 3>>`)
  const entry = (num) => `${String(offsets.get(num)).padStart(10, '0')} 00000 n \n`
  const xrefAt = offset
  let xref = `xref\n${acroform} 1\n${entry(acroform)}${parent} ${kids + 1}\n`
  for (let num = parent; num <= parent + kids; num++) xref += entry(num)
  const trailer = `trailer\n<</Size ${parent + kids + 1} /Root ${root} 0 R /Prev ${prev}>>\nstartxref\n${xrefAt}\n%%EOF\n`
  return Buffer.concat([signed, Buffer.from(parts.join('') + xref + trailer, 'latin1')])
}

test('verifySignatures stays bounded when 50,000 fields share one signature dictionary', async () => {
  // QA finding (K100k): each field used to get its own report (about 43 KB of JS heap each, with
  // a copy of every changed object). The dictionary is now reported for its first 8 fields only,
  // and each report names at most 1,024 changed objects.
  const signed = await signPdf(PdfDocument.open(INPUT), { signer: p256Pem() })
  const kids = 50_000
  const pdf = kidsSharingTheSignature(signed, kids)
  const rssBefore = process.memoryUsage().rss
  const started = Date.now()
  const reports = await verify(pdf)
  const elapsed = Date.now() - started
  const grown = process.memoryUsage().rss - rssBefore

  assert.equal(reports.length, 8)
  assert.equal(reports[0].fieldName, 'Signature1')
  assert.equal(reports[0].intact && reports[0].signatureValid, true)
  assert.equal(reports[0].modification, 'other')
  for (const report of reports) {
    assert.deepEqual(report.sigObject, reports[0].sigObject)
    assert.ok(
      report.warnings.some((w) => w.includes(`is the value of ${kids + 1} fields; it is reported for the first 8`)),
      JSON.stringify(report.warnings),
    )
    assert.equal(report.changedObjects.length, 1024)
  }
  assert.ok(elapsed < 30_000, `verifySignatures took ${elapsed} ms`)
  assert.ok(grown < 512 * 1024 * 1024, `RSS grew by ${Math.round(grown / 1e6)} MB`)
})

// ---- 14: the busy rule --------------------------------------------------------------------------

test('a synchronous call during verifySignatures throws E_BUSY or completes, without deadlock', async () => {
  const signer = p256Pem()
  const signed = await signPdf(PdfDocument.open(INPUT), { signer })
  const doc = PdfDocument.open(signed)
  const options = { certificateChain: signer.certificateChain, algorithm: signer.algorithm }
  const verifying = doc.verifySignatures({ trustAnchors: [ROOT] })
  try {
    const prepared = doc.prepareSignature(options)
    assert.ok(prepared instanceof PreparedSignature)
  } catch (err) {
    assertCode(err, 'E_BUSY')
  }
  const preparing = doc.prepareSignatureAsync(options)
  assertThrowsCode(() => doc.pageCount, 'E_BUSY')
  const [reports, prepared] = await Promise.all([verifying, preparing])
  assertGood(reports[0])
  // Free again: a second signature on the signed file.
  const out = prepared.finish(signer.sign(prepared.toBeSigned))
  assert.equal((await verify(out)).length, 2)
  assert.equal(doc.pageCount, 1)
})

// ---- 15: report fields ----------------------------------------------------------------------------

test('the signature dictionary text entries round-trip, Unicode included', async (t) => {
  const reason = 'Genehmigt – 承認 ✓ \u{1F58A}'
  const out = await signPdf(PdfDocument.open(INPUT), {
    signer: p256Pem(),
    reason,
    name: 'Zoë Ångström',
    location: 'Zürich',
    contactInfo: 'zoe@example.com',
    signingTime: '2026-10-10T14:30:00+02:00',
    field: { name: 'Approval', page: 0 },
  })
  const reports = await verify(out)
  const [report] = reports
  assertGood(report)
  assert.equal(report.reason, reason)
  assert.equal(report.name, 'Zoë Ångström')
  assert.equal(report.location, 'Zürich')
  assert.equal(report.contactInfo, 'zoe@example.com')
  assert.equal(report.fieldName, 'Approval')
  assert.equal(report.claimedTime, '2026-10-10T14:30:00+02:00')
  await oracle(t, out, reports)
})

// ---- other options --------------------------------------------------------------------------------

test('adbe.pkcs7.detached signatures are valid but not PAdES', async (t) => {
  const out = await signPdf(PdfDocument.open(INPUT), { signer: rsaP12(), subFilter: 'adbe.pkcs7.detached' })
  const reports = await verify(out)
  assertGood(reports[0])
  assert.equal(reports[0].subFilter, 'adbe.pkcs7.detached')
  assert.equal(reports[0].padesLevel, null)
  await oracle(t, out, reports)
})

test('signature fields: an existing empty field is signed by name; field modes are enforced', async () => {
  const signer = p256Pem()
  const signed = await signPdf(PdfDocument.open(INPUT), { signer, field: { name: 'Approval' } })
  const doc = PdfDocument.open(signed)
  const options = { certificateChain: signer.certificateChain, algorithm: signer.algorithm }
  // The field is signed already.
  assertThrowsCode(() => doc.prepareSignature({ ...options, field: { name: 'Approval' } }), 'E_INVALID_ARGUMENT')
  assertThrowsCode(
    () => doc.prepareSignature({ ...options, field: { name: 'Missing', mode: 'existingOnly' } }),
    'E_NOT_FOUND',
  )
  assertThrowsCode(() => doc.prepareSignature({ ...options, field: { name: 'a.b' } }), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.prepareSignature({ ...options, field: { page: 3 } }), 'E_PAGE_OUT_OF_RANGE')
  assertThrowsCode(() => doc.prepareSignature({ ...options, field: { mode: 'sometimes' } }), 'E_INVALID_ARGUMENT')
  const second = await signPdf(doc, { signer, field: { name: 'Review', mode: 'createOnly' } })
  assert.deepEqual(
    (await verify(second)).map((r) => r.fieldName),
    ['Approval', 'Review'],
  )
})

test('verifySignatures options: anchors as DER or PEM, extra certificates, the validation time', async () => {
  // The chain without the intermediate: trust needs it as an extra certificate.
  const signer = {
    certificateChain: [der('signer-p256.pem')],
    algorithm: 'ecdsa',
    sign: (tbs) => p256Pem().sign(tbs),
  }
  const out = await signPdf(PdfDocument.open(INPUT), { signer })
  const doc = PdfDocument.open(out)
  const [untrusted] = await doc.verifySignatures()
  assert.equal(untrusted.trusted, null, 'no anchors')
  assert.equal(untrusted.intact && untrusted.signatureValid, true)
  assert.equal((await doc.verifySignatures({ trustAnchors: [der('root.pem')] }))[0].trusted, false)
  const [trusted] = await doc.verifySignatures({
    trustAnchors: [der('root.pem')],
    extraCertificates: [pki('intermediate.pem')],
  })
  assert.equal(trusted.trusted, true)
  // After every certificate expired, and at the signer's claimed time (with a warning).
  const options = { trustAnchors: [ROOT], extraCertificates: [pki('intermediate.pem')] }
  assert.equal((await doc.verifySignatures({ ...options, validationTime: new Date('2080-01-01T00:00:00Z') }))[0].trusted, false)
  assert.equal((await doc.verifySignatures({ ...options, validationTime: 'D:20800101000000Z' }))[0].trusted, false)
  const [claimed] = await doc.verifySignatures({ ...options, validationTime: null })
  assert.equal(claimed.trusted, true)
  assert.ok(claimed.warnings.length > 0, 'a warning names the claimed time')

  // Option checks.
  await assertRejectsCode(doc.verifySignatures({ trustAnchors: ROOT }), 'E_INVALID_ARGUMENT')
  await assertRejectsCode(doc.verifySignatures({ validationTime: 'yesterday' }), 'E_INVALID_ARGUMENT')
  await assertRejectsCode(doc.verifySignatures({ validationTime: new Date(Number.NaN) }), 'E_INVALID_ARGUMENT')
  await assertRejectsCode(doc.verifySignatures(42), 'E_INVALID_ARGUMENT')
  // An unsigned document has no reports; one with unsaved changes is refused.
  assert.deepEqual(await PdfDocument.open(INPUT).verifySignatures(), [])
  doc.setInfo({ title: 'changed' })
  await assertRejectsCode(doc.verifySignatures(), 'E_INVALID_ARGUMENT')
})

// ---- argument and state errors ------------------------------------------------------------------

test('signPdf checks its arguments and wraps signer failures in E_CRYPTO', async () => {
  const doc = PdfDocument.open(INPUT)
  const chain = [der('signer-p256.pem')]
  await assertRejectsCode(signPdf(INPUT, { signer: p256Pem() }), 'E_INVALID_ARGUMENT')
  await assertRejectsCode(signPdf(doc), 'E_INVALID_ARGUMENT')
  await assertRejectsCode(signPdf(doc, { signer: {} }), 'E_INVALID_ARGUMENT')
  await assertRejectsCode(
    signPdf(doc, { signer: { certificateChain: 'x', algorithm: 'ecdsa', sign: () => Buffer.alloc(64) } }),
    'E_INVALID_ARGUMENT',
  )
  await assertRejectsCode(
    signPdf(doc, { signer: { certificateChain: chain, algorithm: 'dsa', sign: () => Buffer.alloc(64) } }),
    'E_INVALID_ARGUMENT',
  )
  // An algorithm that does not match the certificate's key.
  await assertRejectsCode(
    signPdf(doc, { signer: { certificateChain: chain, algorithm: 'rsa-pkcs1v15', sign: () => Buffer.alloc(256) } }),
    'E_INVALID_ARGUMENT',
  )
  await assertRejectsCode(
    signPdf(doc, { signer: { certificateChain: chain, algorithm: 'ecdsa', sign: () => 'not bytes' } }),
    'E_INVALID_ARGUMENT',
  )
  const failure = new Error('KMS unavailable')
  await assert.rejects(
    signPdf(doc, {
      signer: {
        certificateChain: chain,
        algorithm: 'ecdsa',
        sign: async () => {
          throw failure
        },
      },
    }),
    (err) => {
      assertCode(err, 'E_CRYPTO')
      assert.equal(err.cause, failure)
      return true
    },
  )
  await assertRejectsCode(signPdf(doc, { signer: p256Pem(), signingTime: 'not a date' }), 'E_INVALID_ARGUMENT')
  await assertRejectsCode(signPdf(doc, { signer: p256Pem(), digest: 'sha1' }), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.prepareSignature({ certificateChain: [], algorithm: 'ecdsa' }), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.prepareSignature({ algorithm: 'ecdsa' }), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.prepareSignature(), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => doc.prepareSignature({ certificateChain: [Buffer.from('not a certificate')], algorithm: 'ecdsa' }), 'E_CERTIFICATE')
})

test('documents that cannot be signed, and closed documents', async () => {
  const signer = p256Pem()
  const options = { certificateChain: signer.certificateChain, algorithm: signer.algorithm }
  // A repaired structure and bytes before the header: save a full copy first.
  for (const name of [REPAIRED[0], 'junk-before-header.pdf']) {
    const doc = PdfDocument.open(syntaxFixture(name))
    assertThrowsCode(() => doc.prepareSignature(options), 'E_UNSUPPORTED')
    await assertRejectsCode(signPdf(doc, { signer }), 'E_UNSUPPORTED')
    const full = PdfDocument.open(doc.save())
    assertGood((await verify(await signPdf(full, { signer })))[0])
  }
  // A new document has no pages (and no file to append to).
  assertThrowsCode(() => PdfDocument.create().prepareSignature(options), ['E_INVALID_ARGUMENT', 'E_PAGE_OUT_OF_RANGE'])

  const doc = PdfDocument.open(INPUT)
  doc.close()
  assertThrowsCode(() => doc.prepareSignature(options), 'E_CLOSED')
  await assertRejectsCode(doc.prepareSignatureAsync(options), 'E_CLOSED')
  await assertRejectsCode(doc.verifySignatures(), 'E_CLOSED')
  await assertRejectsCode(signPdf(doc, { signer }), 'E_CLOSED')
})

test('pending changes go into the signed revision', async (t) => {
  const doc = PdfDocument.open(INPUT)
  doc.setInfo({ title: 'Signed with a title' })
  const out = await signPdf(doc, { signer: p256Pem() })
  assert.equal(doc.isModified, true, 'the document keeps its changes')
  const signed = PdfDocument.open(out)
  assert.equal(signed.getInfo().title, 'Signed with a title')
  const reports = await signed.verifySignatures({ trustAnchors: [ROOT] })
  assertGood(reports[0])
  assert.equal(reports[0].coverage, 'entireFile')
  await oracle(t, out, reports)
})

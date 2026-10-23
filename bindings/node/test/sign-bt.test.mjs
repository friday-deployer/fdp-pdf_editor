// PAdES B-T from Node (M4 WP4.3B; brief §3.5 and §6.4): signPdf with a `timestamp` callback, the
// two-phase PreparedSignature.timestampRequest / finish(signature, response) flow, the token
// overflow retry, refused responses, and the report's timestamp fields. The TSA is the pure
// JavaScript mock of `helpers/mock-tsa.mjs` (and `openssl ts -reply` when OpenSSL is installed).
// Every signed output is checked by pyHanko (timestamp validity with the test root as the TSA
// anchor) and by `openssl ts -verify` of the token over the signature value, when the oracle venv
// is set up (`bash tools/setup-venv.sh`).

import assert from 'node:assert/strict'
import { createHash, createPrivateKey, sign as cryptoSign } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { FolioxideError, LocalSigner, PdfDocument, PreparedSignature, isSignatureAcceptable, signPdf } from 'folioxide'

import { assertCode, assertRejectsCode, assertThrowsCode, syntaxFixture } from './helpers.mjs'
import { MockTsa, OPENSSL_UNAVAILABLE, REPO, children, opensslTsa, parseRequest, pkiDer, readTlv } from './helpers/mock-tsa.mjs'
import { ORACLE_UNAVAILABLE, opensslTimestamps, pyhanko } from './helpers/oracle.mjs'

const PKI = new URL('fixtures/pki/', REPO)
const pki = (name) => readFileSync(new URL(name, PKI))
const pkiText = (name) => readFileSync(new URL(name, PKI), 'utf8')

const ROOT = pki('root.pem')
const INPUT = syntaxFixture('minimal.pdf')
const SIGNING_TIME = new Date('2026-10-10T12:00:00Z')
/** The mock's `genTime`: 30 seconds after the claimed signing time. */
const GEN_TIME = '20261010120030Z'

const p256 = () =>
  LocalSigner.fromPem(pkiText('signer-p256.key.pem'), pkiText('signer-p256.pem') + pkiText('intermediate.pem'))
const rsa = () => LocalSigner.fromPkcs12(pki('signer-rsa2048-modern.p12'), 'folioxide')

/** An external signer around a LocalSigner that records every value it returns. */
function recording(local) {
  const values = []
  return {
    values,
    signer: {
      certificateChain: local.certificateChain,
      algorithm: local.algorithm,
      sign: (toBeSigned, _digest, digestAlgorithm) => {
        const value = local.sign(toBeSigned, digestAlgorithm)
        values.push(value)
        return value
      },
    },
  }
}

/** The DER length octets of `n`. */
function derLength(n) {
  if (n < 0x80) {
    return Buffer.from([n])
  }
  const bytes = []
  for (let v = n; v > 0; v >>= 8) {
    bytes.unshift(v & 0xff)
  }
  return Buffer.from([0x80 | bytes.length, ...bytes])
}

/** The subject `Name` (the whole TLV) of a DER certificate. */
function certificateSubject(der) {
  const certificate = readTlv(der)
  const tbs = readTlv(certificate.content)
  const fields = children(tbs.content)
  const skip = fields[0].tag === 0xa0 ? 1 : 0
  return Buffer.from(fields[skip + 4].whole)
}

/** Verifies a signed file against the test root (at the current time, the facade's default). */
async function verify(bytes, options = {}) {
  const doc = PdfDocument.open(bytes)
  try {
    return await doc.verifySignatures({ trustAnchors: [ROOT], ...options })
  } finally {
    doc.close()
  }
}

/** Asserts a report describes a good, trusted PAdES B-T signature by the mock TSA. */
function assertBT(report, { genTime = '2026-10-10T12:00:30Z' } = {}) {
  assert.equal(report.intact, true, 'intact')
  assert.equal(report.signatureValid, true, 'signatureValid')
  assert.equal(report.trusted, true, 'trusted')
  assert.deepEqual(report.problems, [])
  assert.equal(report.padesLevel, 'B-T')
  const timestamp = report.timestamp
  assert.ok(timestamp, 'a signature timestamp')
  assert.equal(timestamp.intact, true, 'timestamp.intact')
  assert.equal(timestamp.valid, true, 'timestamp.valid')
  assert.equal(timestamp.trusted, true, 'timestamp.trusted')
  assert.deepEqual(timestamp.problems, [])
  if (genTime !== null) {
    assert.equal(timestamp.genTime, genTime)
  }
  assert.equal(timestamp.tsa.commonName, 'Folioxide Test TSA')
  assert.ok(timestamp.tsa.der.equals(pkiDer('tsa.pem')))
  assert.equal(timestamp.signatureAlgorithm, 'sha256WithRSAEncryption')
  assert.deepEqual(report.timestamps, [timestamp])
  assert.equal(isSignatureAcceptable(report), true)
}

/**
 * Checks a B-T file with the oracles: pyHanko must find every signature intact, valid and
 * trusted with a valid and trusted signature timestamp, and `openssl ts -verify` must accept every
 * token over its signature value.
 */
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
    assert.equal(status.timestamp, true, `pyHanko signatures[${i}] has a signature timestamp`)
    assert.equal(status.timestampValid, true, `pyHanko signatures[${i}].timestamp intact and valid`)
    assert.equal(status.timestampTrusted, true, `pyHanko signatures[${i}].timestampTrusted`)
  })
  const tokens = opensslTimestamps(bytes)
  assert.equal(tokens.length, count, 'OpenSSL finds every token')
  for (const token of tokens) {
    assert.ok(token.ok, `openssl ts -verify of signature ${token.index}: ${token.output}`)
  }
}

test('the timestamp oracles are available (pyHanko, OpenSSL)', { skip: ORACLE_UNAVAILABLE ?? false }, () => {
  assert.equal(ORACLE_UNAVAILABLE, null)
})

// ---- 1: the callback gets the request over the signature value ----------------------------------

test('signPdf with a timestamp callback: the request is over the signature value; the result is B-T', async (t) => {
  const tsa = new MockTsa({ genTime: GEN_TIME })
  const { signer, values } = recording(p256())
  const requests = []
  const signed = await signPdf(PdfDocument.open(INPUT), {
    signer,
    signingTime: SIGNING_TIME,
    timestamp: (request) => {
      assert.ok(Buffer.isBuffer(request), 'the request is a Buffer')
      requests.push(request)
      return tsa.respond(request)
    },
  })
  assert.equal(values.length, 1)
  assert.equal(requests.length, 1)
  const request = parseRequest(requests[0])
  assert.equal(request.version, 1)
  assert.equal(request.digest, 'sha256')
  assert.ok(request.hash.equals(createHash('sha256').update(values[0]).digest()), 'imprint = sha256(signature value)')
  assert.equal(request.certReq, true)
  assert.ok(request.nonce && request.nonce.length >= 1 && request.nonce.length <= 9, 'a 64-bit nonce')
  assert.equal(request.policy, null)

  const [report] = await verify(signed)
  assertBT(report)
  assert.equal(report.timestamp.imprintAlgorithm, 'sha256')
  assert.equal(report.timestamp.policy, '1.2.3.4.1')
  assert.equal(report.timestamp.serialHex, '01')
  assert.equal(report.timestamp.accuracyMicros, 1_000_000)
  assert.equal(report.timestamp.ordering, false)
  assert.equal(report.modification, 'none')
  // The report is plain JSON data.
  assert.equal(JSON.parse(JSON.stringify(report)).timestamp.genTime, '2026-10-10T12:00:30Z')
  oracle(t, signed)
})

// ---- 2: an asynchronous callback ----------------------------------------------------------------

test('an asynchronous timestamp callback (setTimeout), returning an ArrayBuffer, with an RSA key', async (t) => {
  const tsa = new MockTsa({ genTime: GEN_TIME })
  const signer = rsa()
  const signed = await signPdf(PdfDocument.open(INPUT), {
    signer,
    signingTime: SIGNING_TIME,
    timestamp: (request) =>
      new Promise((resolve) =>
        setTimeout(() => {
          const response = tsa.respond(request)
          resolve(response.buffer.slice(response.byteOffset, response.byteOffset + response.byteLength))
        }, 20),
      ),
  })
  const [report] = await verify(signed)
  assertBT(report)
  assert.equal(report.signer.key.algorithm, 'rsa')
  oracle(t, signed)
  signer.close()
})

// ---- 3: a callback that throws ------------------------------------------------------------------

test('a timestamp callback that throws or rejects gives E_TIMESTAMP_INVALID with the cause', async () => {
  const cause = new Error('TSA unreachable: ECONNREFUSED (secret-token-123)')
  for (const timestamp of [
    () => {
      throw cause
    },
    async () => {
      throw cause
    },
  ]) {
    await assert.rejects(signPdf(PdfDocument.open(INPUT), { signer: p256(), timestamp }), (err) => {
      assertCode(err, 'E_TIMESTAMP_INVALID')
      assert.equal(err.cause, cause)
      assert.equal(err.message, 'options.timestamp() failed (see the cause)')
      assert.ok(!err.message.includes('secret-token-123'))
      return true
    })
  }
  // A callback that returns something that is not bytes is a programming error.
  await assertRejectsCode(
    signPdf(PdfDocument.open(INPUT), { signer: p256(), timestamp: () => 'not bytes' }),
    'E_INVALID_ARGUMENT',
  )
  // Garbage bytes are an invalid response.
  await assertRejectsCode(
    signPdf(PdfDocument.open(INPUT), { signer: p256(), timestamp: () => Buffer.from('garbage') }),
    'E_TIMESTAMP_INVALID',
  )
})

// ---- 4, 5: responses the signer refuses --------------------------------------------------------

test('a response with a wrong nonce gives E_TIMESTAMP_INVALID', async () => {
  const tsa = new MockTsa({ genTime: GEN_TIME, nonce: Buffer.from([1, 2, 3]) })
  await assert.rejects(signPdf(PdfDocument.open(INPUT), { signer: p256(), timestamp: tsa.callback }), (err) => {
    assertCode(err, 'E_TIMESTAMP_INVALID')
    assert.match(err.message, /nonce/i)
    return true
  })
  // A token without the nonce is refused too, and so is one over other bytes.
  for (const options of [{ nonce: 'omit' }, { imprint: Buffer.alloc(32, 7) }, { ess: 'missing' }]) {
    const other = new MockTsa({ genTime: GEN_TIME, ...options })
    await assertRejectsCode(
      signPdf(PdfDocument.open(INPUT), { signer: p256(), timestamp: other.callback }),
      'E_TIMESTAMP_INVALID',
    )
  }
})

test('a TSTInfo tsa field OpenSSL cannot decode gives E_TIMESTAMP_INVALID (M4 QA round 4 finding 4)', async () => {
  // ts-sign-r5-tsa-gn-unknown-ctx9 and ts-sign-r5-tsa-gn-universal-null: the signing side reads
  // the token with the verifier's whitelist, so it never embeds a token `openssl ts -verify`
  // refuses for its tsa GeneralName (no matching choice type).
  for (const tsaName of [Buffer.from([0x89, 0x03, 0x74, 0x73, 0x61]), Buffer.from([0x05, 0x00])]) {
    const tsa = new MockTsa({ genTime: GEN_TIME, tsa: tsaName })
    await assert.rejects(signPdf(PdfDocument.open(INPUT), { signer: p256(), timestamp: tsa.callback }), (err) => {
      assertCode(err, 'E_TIMESTAMP_INVALID')
      assert.match(err.message, /tsa is a GeneralName that does not decode/)
      return true
    })
  }
  // The control: the TSA certificate's own subject as a directoryName.
  const subject = certificateSubject(pkiDer('tsa.pem'))
  const named = new MockTsa({ genTime: GEN_TIME, tsa: Buffer.concat([Buffer.from([0xa4]), derLength(subject.length), subject]) })
  const signed = await signPdf(PdfDocument.open(INPUT), { signer: p256(), signingTime: SIGNING_TIME, timestamp: named.callback })
  const report = (await verify(signed))[0]
  assert.equal(report.padesLevel, 'B-T')
  assert.equal(report.timestamp.valid, true)
  assert.match(report.timestamp.tsaName, /Folioxide Test TSA/)
})

test('a rejection status gives E_TIMESTAMP_INVALID with the status text in the message', async () => {
  const tsa = new MockTsa({ status: 2, statusString: 'request refused: policy not accepted', failInfo: 1 << 15 })
  await assert.rejects(signPdf(PdfDocument.open(INPUT), { signer: p256(), timestamp: tsa.callback }), (err) => {
    assertCode(err, 'E_TIMESTAMP_INVALID')
    assert.match(err.message, /status 2/)
    assert.match(err.message, /request refused: policy not accepted/)
    assert.match(err.message, /unacceptedPolicy/)
    return true
  })
  // grantedWithMods (1) is accepted (M4 brief D-9).
  const mods = new MockTsa({ status: 1, genTime: GEN_TIME })
  const signed = await signPdf(PdfDocument.open(INPUT), {
    signer: p256(),
    signingTime: SIGNING_TIME,
    timestamp: mods.callback,
  })
  assertBT((await verify(signed))[0])
})

// ---- 6: the two-phase flow ----------------------------------------------------------------------

test('two phases: timestampRequest then finish; serialize, deserialize and finish(sig, resp, req) give the same file', async (t) => {
  const tsa = new MockTsa({ genTime: GEN_TIME })
  const signer = p256()
  const doc = PdfDocument.open(INPUT)
  const prepared = doc.prepareSignature({
    certificateChain: signer.certificateChain,
    algorithm: signer.algorithm,
    signingTime: SIGNING_TIME,
    tsaReserve: 8192,
  })
  doc.close()
  const value = signer.sign(prepared.toBeSigned)
  const request = prepared.timestampRequest(value, { nonce: 42n })
  assert.ok(Buffer.isBuffer(request))
  const parsed = parseRequest(request)
  assert.equal(parsed.nonceValue, 42n)
  assert.ok(parsed.hash.equals(createHash('sha256').update(value).digest()))
  // The same options give the same request (the nonce fixed).
  assert.ok(prepared.timestampRequest(value, { nonce: 42 }).equals(request), 'a safe integer nonce works too')
  const serialized = prepared.serialize()
  const response = tsa.respond(request)

  const first = prepared.finish(value, response)
  assert.equal(prepared.isFinished, true)
  assertThrowsCode(() => prepared.timestampRequest(value), 'E_INVALID_ARGUMENT')

  const restored = PreparedSignature.deserialize(serialized)
  // A deserialized prepared signature remembers no request: the response alone is refused.
  assertThrowsCode(() => restored.finish(value, response), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => restored.finish(value, undefined, request), 'E_INVALID_ARGUMENT')
  const second = await restored.finishAsync(value, response, request)
  assert.ok(first.equals(second), 'byte-identical')

  const [report] = await verify(first)
  assertBT(report)
  oracle(t, first)
})

test('after timestampRequest, finish without a response is refused until discardTimestampRequest', async () => {
  // QA round 1 finding 1: a forgotten response gave a B-B file without a word.
  const signer = p256()
  const doc = PdfDocument.open(INPUT)
  const prepared = doc.prepareSignature({
    certificateChain: signer.certificateChain,
    algorithm: signer.algorithm,
    signingTime: SIGNING_TIME,
    tsaReserve: 8192,
  })
  doc.close()
  const value = signer.sign(prepared.toBeSigned)
  prepared.timestampRequest(value)
  assert.throws(
    () => prepared.finish(value),
    (err) => assertCode(err, 'E_INVALID_ARGUMENT') && /discardTimestampRequest/.test(err.message),
  )
  assertThrowsCode(() => prepared.finish(value, null), 'E_INVALID_ARGUMENT')
  await assertRejectsCode(prepared.finishAsync(value), 'E_INVALID_ARGUMENT')
  assert.equal(prepared.isFinished, false)

  // Discarding (twice is fine) finishes without a signature timestamp, on purpose.
  prepared.discardTimestampRequest()
  prepared.discardTimestampRequest()
  const signed = await prepared.finishAsync(value)
  const [report] = await verify(signed)
  assert.equal(report.signatureValid, true)
  assert.equal(report.padesLevel, 'B-B')
  assert.equal(report.timestamp, null)
  // Once finished, discarding is still harmless.
  prepared.discardTimestampRequest()
})

test('the timestamp callback gets its own copy of the request', async (t) => {
  // QA round 1 finding 2: a callback that wipes or reuses its buffer must not change the
  // request the response is checked against.
  const tsa = new MockTsa({ genTime: GEN_TIME })
  const seen = []
  const signed = await signPdf(PdfDocument.open(INPUT), {
    signer: p256(),
    signingTime: SIGNING_TIME,
    timestamp: (request) => {
      const response = tsa.respond(request)
      seen.push(Buffer.from(request))
      request.fill(0)
      return response
    },
  })
  assert.equal(seen.length, 1)
  const [report] = await verify(signed)
  assertBT(report)
  oracle(t, signed)
})

// ---- 7: a token larger than its budget ----------------------------------------------------------

test('a token larger than tsaReserve: signPdf signs and timestamps once more, and the result verifies', async (t) => {
  const tsa = new MockTsa({ genTime: GEN_TIME })
  const signer = p256()
  // The exact size of the CMS with a 1-byte token: a placeholder that fits no real token.
  const doc = PdfDocument.open(INPUT)
  let needed
  try {
    doc.prepareSignature({
      certificateChain: signer.certificateChain,
      algorithm: signer.algorithm,
      contentsReserve: 1,
      tsaReserve: 1,
    })
    assert.fail('a 1-byte placeholder is too small')
  } catch (err) {
    assertCode(err, 'E_SIGNATURE_PLACEHOLDER_TOO_SMALL')
    needed = err.details.needed
  }
  doc.close()

  let signs = 0
  let timestamps = 0
  const signed = await signPdf(PdfDocument.open(INPUT), {
    signer: {
      certificateChain: signer.certificateChain,
      algorithm: signer.algorithm,
      sign: (toBeSigned) => {
        signs++
        return signer.sign(toBeSigned)
      },
    },
    signingTime: SIGNING_TIME,
    contentsReserve: needed,
    tsaReserve: 1,
    timestamp: (request) => {
      timestamps++
      return tsa.respond(request)
    },
  })
  assert.equal(signs, 2, 'the signer is called twice')
  assert.equal(timestamps, 2, 'the TSA is called twice')
  const [report] = await verify(signed)
  assertBT(report)
  oracle(t, signed)

  // Finishing directly reports the size needed.
  const doc2 = PdfDocument.open(INPUT)
  const prepared = doc2.prepareSignature({
    certificateChain: signer.certificateChain,
    algorithm: signer.algorithm,
    contentsReserve: needed,
    tsaReserve: 1,
  })
  doc2.close()
  const value = signer.sign(prepared.toBeSigned)
  const response = tsa.respond(prepared.timestampRequest(value))
  try {
    prepared.finish(value, response)
    assert.fail('the token does not fit')
  } catch (err) {
    assertCode(err, 'E_SIGNATURE_PLACEHOLDER_TOO_SMALL')
    assert.ok(err.details.needed > needed, `${err.details.needed} > ${needed}`)
    assert.equal(err.details.reserved, prepared.contentsCapacity)
  }
  assert.equal(prepared.isFinished, false)
})

// ---- 8: a response to another request -----------------------------------------------------------

test('a response to another request is refused, and the prepared signature can still be finished', async (t) => {
  const tsa = new MockTsa({ genTime: GEN_TIME })
  const signer = p256()
  const prepare = (name) => {
    const doc = PdfDocument.open(INPUT)
    try {
      return doc.prepareSignature({
        certificateChain: signer.certificateChain,
        algorithm: signer.algorithm,
        signingTime: SIGNING_TIME,
        field: { name },
        tsaReserve: 8192,
      })
    } finally {
      doc.close()
    }
  }
  const prepared = prepare('Mine')
  const other = prepare('Other')
  const value = signer.sign(prepared.toBeSigned)
  const otherValue = signer.sign(other.toBeSigned)
  const request = prepared.timestampRequest(value)
  const wrong = tsa.respond(other.timestampRequest(otherValue))

  assertThrowsCode(() => prepared.finish(value, wrong), 'E_TIMESTAMP_INVALID')
  await assertRejectsCode(prepared.finishAsync(value, wrong), 'E_TIMESTAMP_INVALID')
  // A request made for another signature value is refused even with its own response.
  assertThrowsCode(
    () => prepared.finish(value, wrong, other.timestampRequest(otherValue)),
    'E_TIMESTAMP_INVALID',
  )
  assert.equal(prepared.isFinished, false)

  // While finishAsync runs, the prepared signature is busy; afterwards it is finished.
  const pending = prepared.finishAsync(value, tsa.respond(request))
  assertThrowsCode(() => prepared.timestampRequest(value), 'E_BUSY')
  assertThrowsCode(() => prepared.finish(value), 'E_BUSY')
  const signed = await pending
  assert.equal(prepared.isFinished, true)
  const [report] = await verify(signed)
  assertBT(report)
  assert.equal(report.fieldName, 'Mine')
  oracle(t, signed)
})

// ---- interoperability: OpenSSL as the TSA -------------------------------------------------------

test('OpenSSL `ts -reply` as the TSA', { skip: OPENSSL_UNAVAILABLE ?? false }, async (t) => {
  const signed = await signPdf(PdfDocument.open(INPUT), {
    signer: rsa(),
    signingTime: SIGNING_TIME,
    timestamp: opensslTsa,
  })
  const [report] = await verify(signed)
  assertBT(report, { genTime: null })
  assert.equal(report.timestamp.policy, '1.2.3.4.1')
  assert.equal(report.timestamp.tsaName, 'CN=Folioxide Test TSA,OU=TEST ONLY - DO NOT TRUST,O=Folioxide Test PKI')
  oracle(t, signed)
})

// ---- options ------------------------------------------------------------------------------------

test('timestampOptions: the imprint digest, the policy and the nonce', async (t) => {
  const tsa = new MockTsa({ genTime: GEN_TIME, policy: '1.2.3.4.5' })
  const signed = await signPdf(PdfDocument.open(INPUT), {
    signer: p256(),
    signingTime: SIGNING_TIME,
    timestamp: tsa.callback,
    timestampOptions: { digest: 'sha384', policy: '1.2.3.4.5', nonce: 0xffff_ffff_ffff_ffffn },
  })
  const request = parseRequest(tsa.requests[0])
  assert.equal(request.digest, 'sha384')
  assert.equal(request.policy, '1.2.3.4.5')
  assert.equal(request.nonceValue, 0xffff_ffff_ffff_ffffn)
  const [report] = await verify(signed)
  assertBT(report)
  assert.equal(report.timestamp.imprintAlgorithm, 'sha384')
  assert.equal(report.timestamp.policy, '1.2.3.4.5')
  oracle(t, signed)

  // A TSA answering with another policy than the one asked for is refused.
  const other = new MockTsa({ genTime: GEN_TIME })
  await assertRejectsCode(
    signPdf(PdfDocument.open(INPUT), {
      signer: p256(),
      timestamp: other.callback,
      timestampOptions: { policy: '1.2.3.4.5' },
    }),
    'E_TIMESTAMP_INVALID',
  )
})

test('timestamp arguments are checked', async () => {
  const tsa = new MockTsa()
  const signer = p256()
  const cases = [
    { timestamp: 'https://tsa.example.com/' },
    { timestampOptions: { nonce: 1n } },
    { timestamp: tsa.callback, timestampOptions: { nonce: -1n } },
    { timestamp: tsa.callback, timestampOptions: { nonce: 2n ** 64n } },
    { timestamp: tsa.callback, timestampOptions: { nonce: 1.5 } },
    // M4 QA round 5 finding 4 (ruling R-24): the nonce is a positive INTEGER (brief §4.1).
    { timestamp: tsa.callback, timestampOptions: { nonce: 0n } },
    { timestamp: tsa.callback, timestampOptions: { nonce: 0 } },
    { timestamp: tsa.callback, timestampOptions: { digest: 'sha1' } },
    { timestamp: tsa.callback, timestampOptions: { policy: 'not an OID' } },
    { timestamp: tsa.callback, timestampOptions: 'sha256' },
    { timestamp: tsa.callback, tsaReserve: -1 },
    { timestamp: tsa.callback, tsaReserve: '8192' },
  ]
  for (const options of cases) {
    await assertRejectsCode(signPdf(PdfDocument.open(INPUT), { signer, ...options }), 'E_INVALID_ARGUMENT')
  }
  const doc = PdfDocument.open(INPUT)
  const prepared = doc.prepareSignature({ certificateChain: signer.certificateChain, algorithm: signer.algorithm })
  doc.close()
  const value = signer.sign(prepared.toBeSigned)
  assertThrowsCode(() => prepared.timestampRequest('signature'), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => prepared.timestampRequest(value, { nonce: 'x' }), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => prepared.timestampRequest(value, { nonce: 0n }), 'E_INVALID_ARGUMENT')
  assertThrowsCode(() => prepared.timestampRequest(value, { nonce: 0 }), 'E_INVALID_ARGUMENT')
  assert.equal(parseRequest(prepared.timestampRequest(value, { nonce: 1 })).nonceValue, 1n)
  assertThrowsCode(() => prepared.timestampRequest(Buffer.from('not a signature')), 'E_SIGNATURE_INVALID')
  assertThrowsCode(() => prepared.finish(value, 'response'), 'E_INVALID_ARGUMENT')
  assert.ok(prepared.timestampRequest(value) instanceof Buffer)
  // Two requests without a nonce get different random nonces.
  const a = parseRequest(prepared.timestampRequest(value)).nonceValue
  const b = parseRequest(prepared.timestampRequest(value)).nonceValue
  assert.notEqual(a, b)
})

// ---- verification options and report fields ------------------------------------------------------

test('verifySignatures: timestampTrustAnchors, and B-B without a timestamp', async () => {
  const tsa = new MockTsa({ genTime: GEN_TIME })
  const signed = await signPdf(PdfDocument.open(INPUT), {
    signer: p256(),
    signingTime: SIGNING_TIME,
    timestamp: tsa.callback,
  })
  // The TSA is issued by the root: with only the intermediate as its anchor it is not trusted,
  // which leaves the signature sound and B-T (the token is intact and valid).
  const [report] = await verify(signed, { timestampTrustAnchors: [pki('intermediate.pem')] })
  assert.equal(report.trusted, true)
  assert.equal(report.timestamp.intact, true)
  assert.equal(report.timestamp.valid, true)
  assert.equal(report.timestamp.trusted, false)
  assert.equal(report.padesLevel, 'B-T')
  // Without any anchors nothing is trusted, but the timestamp is still checked.
  const [untrusted] = await verify(signed, { trustAnchors: [] })
  assert.equal(untrusted.trusted, null)
  assert.equal(untrusted.timestamp.trusted, null)
  assert.equal(untrusted.timestamp.valid, true)
  await assertRejectsCode(
    PdfDocument.open(signed).verifySignatures({ timestampTrustAnchors: 'root.pem' }),
    'E_INVALID_ARGUMENT',
  )

  // Without a timestamp callback the signature is B-B, with no timestamp.
  const plain = await signPdf(PdfDocument.open(INPUT), { signer: p256() })
  const [bb] = await verify(plain)
  assert.equal(bb.padesLevel, 'B-B')
  assert.equal(bb.timestamp, null)
  assert.deepEqual(bb.timestamps, [])
})

test('two B-T signatures: the first is form filling for the second', async (t) => {
  const tsa = new MockTsa({ genTime: GEN_TIME })
  const once = await signPdf(PdfDocument.open(INPUT), {
    signer: p256(),
    signingTime: SIGNING_TIME,
    timestamp: tsa.callback,
  })
  const twice = await signPdf(PdfDocument.open(once), {
    signer: rsa(),
    signingTime: SIGNING_TIME,
    timestamp: tsa.callback,
  })
  const reports = await verify(twice)
  assert.equal(reports.length, 2)
  reports.forEach((report) => assertBT(report))
  assert.equal(reports[0].modification, 'formFilling')
  assert.equal(reports[1].modification, 'none')
  assert.equal(reports[0].timestamp.serialHex, '01')
  assert.equal(reports[1].timestamp.serialHex, '02')
  oracle(t, twice, 2)
})

test('E_TIMESTAMP_INVALID is a FolioxideError', () => {
  const err = new FolioxideError('E_TIMESTAMP_INVALID', 'x')
  assert.ok(err instanceof Error)
  assert.equal(err.code, 'E_TIMESTAMP_INVALID')
})

// ---- keys for the external-signer check: node:crypto signs the same value as LocalSigner ----------

test('an external node:crypto ECDSA signer returning IEEE P1363: the request is over the DER value', async (t) => {
  const tsa = new MockTsa({ genTime: GEN_TIME })
  const key = createPrivateKey(pki('signer-p256.key.pem'))
  const p1363 = []
  const signed = await signPdf(PdfDocument.open(INPUT), {
    signer: {
      certificateChain: [pki('signer-p256.pem'), pki('intermediate.pem')],
      algorithm: 'ecdsa',
      sign: (toBeSigned) => {
        const value = cryptoSign('sha256', toBeSigned, { key, dsaEncoding: 'ieee-p1363' })
        p1363.push(value)
        return value
      },
    },
    signingTime: SIGNING_TIME,
    timestamp: tsa.callback,
  })
  // The imprint is not over the P1363 value but over the DER value that is embedded (R-6).
  const request = parseRequest(tsa.requests[0])
  assert.ok(!request.hash.equals(createHash('sha256').update(p1363[0]).digest()))
  const [report] = await verify(signed)
  assertBT(report)
  oracle(t, signed)
})

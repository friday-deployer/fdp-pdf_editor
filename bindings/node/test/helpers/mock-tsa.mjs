// A mock RFC 3161 timestamp authority for the Node tests (M4 brief §6.4), in plain JavaScript: its
// own small DER writer and reader, and RSA PKCS#1 v1.5 with SHA-256 by node:crypto with the test
// TSA key (`fixtures/pki/tsa.key.pem`, certificate `tsa.pem`). It is independent of the Rust code,
// so it cross-checks the native request writer and response validation. Not a test file itself
// (the runner picks up `*.test.mjs` only).
//
// The tokens have the shape of `openssl ts -reply` tokens: SignedData version 3, digestAlgorithm
// sha256 with NULL parameters, the TSTInfo as eContent, the TSA certificate and the root, and one
// SignerInfo with the signed attributes content-type, message-digest and ESS
// signing-certificate-v2 (RFC 5816), signed with sha256WithRSAEncryption. Options bend the
// response for negative tests: another status, nonce or imprint, a v1 or missing ESS attribute,
// padding certificates to make the token larger.
//
// `opensslTsa(request)` answers with `openssl ts -reply -config tools/tsa/openssl-tsa.cnf` instead,
// when OpenSSL is installed (`OPENSSL_UNAVAILABLE` says why not).

import { spawnSync } from 'node:child_process'
import { X509Certificate, createHash, createPrivateKey, sign } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

/** The repository root. */
export const REPO = new URL('../../../../', import.meta.url)
const PKI = new URL('fixtures/pki/', REPO)

/** The DER of the first certificate of a PEM file of the test PKI. */
export function pkiDer(name) {
  return Buffer.from(new X509Certificate(readFileSync(new URL(name, PKI))).raw)
}

// ---- DER, written by hand (X.690) ----------------------------------------------------------------

/** `tag || length || content`, definite length, one-octet tag. */
export function tlv(tag, ...contents) {
  const content = Buffer.concat(contents.map((c) => Buffer.from(c)))
  const length = content.length
  if (length < 0x80) {
    return Buffer.concat([Buffer.from([tag, length]), content])
  }
  const octets = []
  for (let n = length; n > 0; n = Math.floor(n / 256)) {
    octets.unshift(n & 0xff)
  }
  return Buffer.concat([Buffer.from([tag, 0x80 | octets.length, ...octets]), content])
}

const sequence = (...contents) => tlv(0x30, ...contents)
const octetString = (bytes) => tlv(0x04, bytes)
const NULL = Buffer.from([0x05, 0x00])

/** The content octets of the minimal DER INTEGER for a non-negative `value`. */
function integerContent(value) {
  let v = BigInt(value)
  const octets = []
  do {
    octets.unshift(Number(v & 0xffn))
    v >>= 8n
  } while (v > 0n)
  if (octets[0] & 0x80) {
    octets.unshift(0)
  }
  return Buffer.from(octets)
}

const integer = (value) => tlv(0x02, integerContent(value))

/** The content octets of a dotted OID (X.690 §8.19). */
function oidContent(dotted) {
  const arcs = dotted.split('.').map(BigInt)
  const out = []
  const push = (value) => {
    const group = [Number(value & 0x7fn)]
    for (let v = value >> 7n; v > 0n; v >>= 7n) {
      group.unshift(Number(0x80n | (v & 0x7fn)))
    }
    out.push(...group)
  }
  push(arcs[0] * 40n + arcs[1])
  arcs.slice(2).forEach(push)
  return Buffer.from(out)
}

const oid = (dotted) => tlv(0x06, oidContent(dotted))

/** The dotted form of OID content octets. */
function decodeOid(content) {
  const arcs = []
  let value = 0n
  for (const byte of content) {
    value = (value << 7n) | BigInt(byte & 0x7f)
    if ((byte & 0x80) === 0) {
      arcs.push(value)
      value = 0n
    }
  }
  const first = arcs[0] < 80n ? arcs[0] / 40n : 2n
  return [first, arcs[0] - first * 40n, ...arcs.slice(1)].join('.')
}

/** The order of two encodings in a DER `SET OF` (X.690 §11.6). */
function derOrder(a, b) {
  const length = Math.max(a.length, b.length)
  for (let i = 0; i < length; i++) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0)
    if (diff !== 0) {
      return diff
    }
  }
  return 0
}

/** A DER `SET OF` the encodings: sorted. */
const setOf = (encodings) => tlv(0x31, ...[...encodings].sort(derOrder))

/** `Attribute ::= SEQUENCE { attrType OID, attrValues SET { value } }`. */
const attribute = (dotted, value) => sequence(oid(dotted), tlv(0x31, value))

// ---- DER, read by hand ---------------------------------------------------------------------------

/** The DER element at `offset`: `{ tag, content, whole, end }`. */
export function readTlv(bytes, offset = 0) {
  const tag = bytes[offset]
  const first = bytes[offset + 1]
  if (tag === undefined || first === undefined) {
    throw new Error('truncated DER')
  }
  let length = first
  let header = 2
  if (first >= 0x80) {
    const count = first & 0x7f
    if (count === 0 || count > 4) {
      throw new Error('unsupported DER length')
    }
    length = 0
    for (let i = 0; i < count; i++) {
      length = length * 256 + bytes[offset + 2 + i]
    }
    header = 2 + count
  }
  const end = offset + header + length
  if (end > bytes.length) {
    throw new Error('truncated DER')
  }
  return { tag, content: bytes.subarray(offset + header, end), whole: bytes.subarray(offset, end), end }
}

/** The elements of a constructed element's content. */
export function children(content) {
  const out = []
  for (let offset = 0; offset < content.length; ) {
    const element = readTlv(content, offset)
    out.push(element)
    offset = element.end
  }
  return out
}

const OIDS = {
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
}

/**
 * What a DER `TimeStampReq` asks for: `{ version, algorithm (the whole AlgorithmIdentifier),
 * digest ('sha256', …), hash, policy, nonce (the INTEGER content octets) , nonceValue (a bigint),
 * certReq }`.
 */
export function parseRequest(der) {
  const request = readTlv(Buffer.from(der))
  if (request.tag !== 0x30 || request.end !== der.length) {
    throw new Error('a TimeStampReq is one SEQUENCE')
  }
  const [version, imprint, ...rest] = children(request.content)
  const [algorithm, hash] = children(imprint.content)
  const [algorithmOid] = children(algorithm.content)
  const policy = rest.find((field) => field.tag === 0x06)
  const nonce = rest.find((field) => field.tag === 0x02)
  const certReq = rest.find((field) => field.tag === 0x01)
  return {
    version: version.content[0],
    algorithm: Buffer.from(algorithm.whole),
    digest: OIDS[decodeOid(algorithmOid.content)] ?? decodeOid(algorithmOid.content),
    hash: Buffer.from(hash.content),
    policy: policy ? decodeOid(policy.content) : null,
    nonce: nonce ? Buffer.from(nonce.content) : null,
    nonceValue: nonce ? BigInt(`0x${Buffer.from(nonce.content).toString('hex') || '0'}`) : null,
    certReq: certReq ? certReq.content[0] !== 0 : false,
  }
}

/** The issuer, serial number and subject TLVs of a DER certificate. */
function certificateParts(der) {
  const [tbs] = children(readTlv(der).content)
  let fields = children(tbs.content)
  if (fields[0].tag === 0xa0) {
    fields = fields.slice(1)
  }
  const [serial, , issuer, , subject] = fields
  return { serial: serial.whole, issuer: issuer.whole, subject: subject.whole }
}

/** `YYYYMMDDhhmmssZ` for a `Date`. */
export function generalizedTime(date) {
  return `${date.toISOString().slice(0, 19).replace(/[-:T]/g, '')}Z`
}

// ---- the mock ------------------------------------------------------------------------------------

const ID_SIGNED_DATA = '1.2.840.113549.1.7.2'
const ID_CT_TST_INFO = '1.2.840.113549.1.9.16.1.4'
const ID_CONTENT_TYPE = '1.2.840.113549.1.9.3'
const ID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
const ID_SIGNING_CERTIFICATE = '1.2.840.113549.1.9.16.2.12'
const ID_SIGNING_CERTIFICATE_V2 = '1.2.840.113549.1.9.16.2.47'
const ID_SHA256 = '2.16.840.1.101.3.4.2.1'
const SHA256_WITH_RSA = '1.2.840.113549.1.1.11'

/**
 * A deterministic mock TSA. `respond(request)` answers a DER `TimeStampReq` with a DER
 * `TimeStampResp`; `requests` lists the requests it answered.
 *
 * Options (all optional):
 * - `genTime`: the `genTime` text (default: now, `YYYYMMDDhhmmssZ`)
 * - `serial`: the first serial number (default 1; each response takes the next)
 * - `policy`: the TSA policy OID (default `1.2.3.4.1`)
 * - `status`, `statusString`, `failInfo`: the PKIStatusInfo (default granted); a token is
 *   written for status 0 and 1 only
 * - `nonce`: `'echo'` (default), `'omit'`, or the INTEGER content octets to write instead
 * - `imprint`: `'echo'` (default) or the hash to write instead
 * - `ess`: `'v2'` (default), `'v1'` or `'missing'`
 * - `extraCertificates`: DER certificates after the TSA's (default: the root); repeat some to
 *   make the token larger
 * - `tsa`: a DER GeneralName written as the TSTInfo `tsa` field (`[0] EXPLICIT`; default none)
 */
export class MockTsa {
  constructor(options = {}) {
    this.options = {
      policy: '1.2.3.4.1',
      status: 0,
      nonce: 'echo',
      imprint: 'echo',
      ess: 'v2',
      extraCertificates: [pkiDer('root.pem')],
      ...options,
    }
    this.serial = BigInt(this.options.serial ?? 1)
    this.key = createPrivateKey(readFileSync(new URL('tsa.key.pem', PKI)))
    this.certificate = pkiDer('tsa.pem')
    /** The requests answered so far, as Buffers. */
    this.requests = []
  }

  /** A `timestamp` callback for `signPdf` that answers with this TSA. */
  get callback() {
    return (request) => this.respond(request)
  }

  /** The DER `TimeStampResp` for the DER `TimeStampReq` `requestDer`. */
  respond(requestDer) {
    this.requests.push(Buffer.from(requestDer))
    const o = this.options
    const status = this.statusInfo()
    if (o.status > 1) {
      return sequence(status)
    }
    return sequence(status, this.token(parseRequest(requestDer)))
  }

  /** `PKIStatusInfo ::= SEQUENCE { status, statusString OPTIONAL, failInfo OPTIONAL }`. */
  statusInfo() {
    const { status, statusString, failInfo } = this.options
    const parts = [integer(status)]
    if (statusString !== undefined) {
      parts.push(sequence(tlv(0x0c, Buffer.from(statusString, 'utf8'))))
    }
    if (failInfo !== undefined) {
      // Bit i is the i-th bit from the top of the first octet (X.690 §8.6.2); DER drops trailing
      // zero octets of a named bit list and counts the unused bits (X.690 §11.2.2).
      const octets = [0, 0, 0, 0]
      for (let bit = 0; bit < 32; bit++) {
        if (failInfo & (1 << bit)) {
          octets[bit >> 3] |= 0x80 >> (bit & 7)
        }
      }
      while (octets.length > 0 && octets.at(-1) === 0) {
        octets.pop()
      }
      let unused = 0
      if (octets.length > 0) {
        for (let last = octets.at(-1); (last & 1) === 0; last >>= 1) {
          unused++
        }
      }
      parts.push(tlv(0x03, Buffer.from([unused, ...octets])))
    }
    return sequence(...parts)
  }

  /** The `TimeStampToken` (ContentInfo) for a parsed request. */
  token(request) {
    const o = this.options
    const cert = certificateParts(this.certificate)
    const hash = o.imprint === 'echo' ? request.hash : Buffer.from(o.imprint)
    const fields = [
      integer(1),
      oid(o.policy),
      sequence(request.algorithm, octetString(hash)),
      integer(this.serial++),
      tlv(0x18, Buffer.from(o.genTime ?? generalizedTime(new Date()), 'latin1')),
      sequence(integer(1)), // accuracy: 1 second
    ]
    const nonce = o.nonce === 'echo' ? request.nonce : o.nonce === 'omit' ? null : Buffer.from(o.nonce)
    if (nonce) {
      fields.push(tlv(0x02, nonce))
    }
    if (o.tsa) {
      fields.push(tlv(0xa0, Buffer.from(o.tsa)))
    }
    const tstInfo = sequence(...fields)

    // ESSCertID(v2) ::= SEQUENCE { certHash, issuerSerial SEQUENCE { GeneralNames { [4] issuer },
    // serial } }; SigningCertificate(V2) ::= SEQUENCE { certs SEQUENCE OF ESSCertID(v2) }. The v2
    // hashAlgorithm is the DEFAULT sha256, so it is omitted.
    const issuerSerial = sequence(sequence(tlv(0xa4, cert.issuer)), cert.serial)
    const certId = (algorithm) =>
      sequence(sequence(sequence(octetString(createHash(algorithm).update(this.certificate).digest()), issuerSerial)))
    const attrs = [
      attribute(ID_CONTENT_TYPE, oid(ID_CT_TST_INFO)),
      attribute(ID_MESSAGE_DIGEST, octetString(createHash('sha256').update(tstInfo).digest())),
    ]
    if (o.ess === 'v2') {
      attrs.push(attribute(ID_SIGNING_CERTIFICATE_V2, certId('sha256')))
    } else if (o.ess === 'v1') {
      attrs.push(attribute(ID_SIGNING_CERTIFICATE, certId('sha1')))
    }
    const signedAttrs = setOf(attrs)
    const signature = sign('sha256', signedAttrs, this.key)
    const implicitAttrs = Buffer.from(signedAttrs)
    implicitAttrs[0] = 0xa0

    const sha256 = sequence(oid(ID_SHA256), NULL)
    const signerInfo = sequence(
      integer(1),
      sequence(cert.issuer, cert.serial),
      sha256,
      implicitAttrs,
      sequence(oid(SHA256_WITH_RSA), NULL),
      octetString(signature),
    )
    const certificates = tlv(0xa0, ...[this.certificate, ...o.extraCertificates].sort(derOrder))
    const signedData = sequence(
      integer(3),
      tlv(0x31, sha256),
      sequence(oid(ID_CT_TST_INFO), tlv(0xa0, octetString(tstInfo))),
      certificates,
      tlv(0x31, signerInfo),
    )
    return sequence(oid(ID_SIGNED_DATA), tlv(0xa0, signedData))
  }
}

// ---- OpenSSL as the TSA --------------------------------------------------------------------------

/** Why `opensslTsa` cannot run here, or `null` when it can. */
export const OPENSSL_UNAVAILABLE = spawnSync('openssl', ['version']).error
  ? 'OpenSSL is not installed'
  : null

/**
 * The DER `TimeStampResp` of `openssl ts -reply -config tools/tsa/openssl-tsa.cnf` (the test TSA,
 * signing-certificate-v2, the root as extra certificate) to the DER `TimeStampReq` `request`.
 */
export function opensslTsa(request) {
  const dir = mkdtempSync(join(tmpdir(), 'folioxide-tsa-'))
  try {
    const query = join(dir, 'request.tsq')
    const reply = join(dir, 'response.tsr')
    writeFileSync(query, request)
    const result = spawnSync(
      'openssl',
      ['ts', '-reply', '-config', 'tools/tsa/openssl-tsa.cnf', '-queryfile', query, '-out', reply],
      { cwd: fileURLToPath(REPO), env: { ...process.env, FOLIOXIDE_TSA_DIR: dir }, encoding: 'utf8' },
    )
    if (result.status !== 0) {
      throw new Error(`openssl ts -reply failed: ${result.stderr}`)
    }
    return readFileSync(reply)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

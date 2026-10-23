// The signature oracles for the M4 Node tests (M4 brief §6.4): pyHanko through
// `tools/oracles/validate_sig.py` (signature and timestamp validity, DocMDP), and OpenSSL
// `ts -verify` of each signature timestamp token over its signature value (the files
// `tools/oracles/extract_cms.py --out-dir` writes). They run when the oracle venv is set up
// (`bash tools/setup-venv.sh`) and are skipped otherwise. Not a test file itself.

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { REPO } from './mock-tsa.mjs'

const PYTHON = fileURLToPath(new URL('.venv/bin/python', REPO))
const VALIDATE_SIG = fileURLToPath(new URL('tools/oracles/validate_sig.py', REPO))
const EXTRACT_CMS = fileURLToPath(new URL('tools/oracles/extract_cms.py', REPO))
const ROOT_PATH = fileURLToPath(new URL('fixtures/pki/root.pem', REPO))
const TSA_ROOT_PATH = fileURLToPath(new URL('fixtures/pki/tsa-root.pem', REPO))

/** Why the oracles cannot run here, or `null` when they can. */
export const ORACLE_UNAVAILABLE = (() => {
  if (!existsSync(PYTHON)) {
    return 'no oracle venv (.venv/bin/python; run `bash tools/setup-venv.sh`)'
  }
  if (spawnSync('openssl', ['version']).error) {
    return 'OpenSSL is not installed'
  }
  return null
})()

/** Runs `fn(path)` with `bytes` written to a temporary file. */
function withFile(bytes, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'folioxide-oracle-'))
  try {
    const file = join(dir, 'signed.pdf')
    writeFileSync(file, bytes)
    return fn(file, dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

/**
 * pyHanko's verdict on every signature of `bytes`, validated with the test root as the trust
 * anchor (for the signers and the TSA): `validate_sig.py --json` entries (`intact`, `valid`,
 * `trusted`, `modification`, `docmdp`, `docmdpOk`, `timestamp`, `timestampValid`,
 * `timestampTrusted`, …), in signing order.
 */
export function pyhanko(bytes) {
  return withFile(bytes, (file) => {
    const result = spawnSync(PYTHON, ['-I', VALIDATE_SIG, file, '--trust-root', ROOT_PATH, '--json'], {
      cwd: fileURLToPath(REPO),
      encoding: 'utf8',
      maxBuffer: 16 << 20,
    })
    // It exits 1 when a signature is not intact, valid and trusted; the JSON is printed anyway.
    const start = result.stdout.indexOf('[')
    assert.ok(start >= 0, `validate_sig.py printed no JSON: ${result.stdout}${result.stderr}`)
    return JSON.parse(result.stdout.slice(start))
  })
}

/**
 * `openssl ts -verify -data sigN.sigvalue.bin -in sigN.tst.der -token_in -CAfile tsa-root.pem`
 * for every signature of `bytes` that has a signature timestamp: `[{ index, ok, output }]`, with
 * `index` the 1-based signature number.
 */
export function opensslTimestamps(bytes) {
  return withFile(bytes, (file, dir) => {
    const out = join(dir, 'cms')
    const extract = spawnSync(PYTHON, ['-I', EXTRACT_CMS, file, '--out-dir', out], {
      cwd: fileURLToPath(REPO),
      encoding: 'utf8',
    })
    assert.equal(extract.status, 0, `extract_cms.py failed: ${extract.stdout}${extract.stderr}`)
    return readdirSync(out)
      .filter((name) => name.endsWith('.tst.der'))
      .sort()
      .map((name) => {
        const index = Number(name.slice(3, -'.tst.der'.length))
        const verify = spawnSync(
          'openssl',
          [
            'ts',
            '-verify',
            '-data',
            join(out, `sig${index}.sigvalue.bin`),
            '-in',
            join(out, name),
            '-token_in',
            '-CAfile',
            TSA_ROOT_PATH,
          ],
          { encoding: 'utf8' },
        )
        const output = `${verify.stdout}${verify.stderr}`
        return { index, ok: verify.status === 0 && output.includes('Verification: OK'), output }
      })
  })
}

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readdirSync, readFileSync } from 'node:fs'
import { test } from 'node:test'

const packageDir = new URL('../', import.meta.url)
const repoRoot = new URL('../../../', import.meta.url)

const readJson = (url) => JSON.parse(readFileSync(url, 'utf8'))
const packageJson = readJson(new URL('package.json', packageDir))

// What `npm publish` puts in the `folioxide` tarball. Anything else (the `.node` binaries, which ship
// in the platform packages, and the Rust sources, tests and lockfile) must stay out.
const EXPECTED_TARBALL = [
  'LICENSE-APACHE',
  'LICENSE-MIT',
  'README.md',
  'binding.d.ts',
  'binding.js',
  'index.d.ts',
  'index.js',
  'index.mjs',
  'package.json',
]

/** Lists the files `npm pack` would publish, without writing a tarball or running scripts. */
function npmPackFileList() {
  const isWindows = process.platform === 'win32'
  const stdout = execFileSync(
    isWindows ? 'npm.cmd' : 'npm',
    ['pack', '--dry-run', '--json', '--ignore-scripts', '--offline'],
    {
      cwd: packageDir,
      encoding: 'utf8',
      env: { ...process.env, npm_config_update_notifier: 'false' },
      shell: isWindows,
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  )
  const [result] = JSON.parse(stdout)
  return result.files.map((file) => file.path).sort()
}

test('the npm tarball holds the facade, the generated loader, the README and both licenses', () => {
  assert.deepEqual(npmPackFileList(), EXPECTED_TARBALL)
})

test('the packaged license texts are identical to the repository licenses', () => {
  for (const name of ['LICENSE-MIT', 'LICENSE-APACHE']) {
    const packaged = readFileSync(new URL(name, packageDir), 'utf8')
    const original = readFileSync(new URL(name, repoRoot), 'utf8')
    assert.equal(packaged, original, `bindings/node/${name} must be a copy of the root ${name}`)
  }
})

test('the main package is published with public access', () => {
  // `napi create-npm-dirs` copies `publishConfig.access` from here into every platform package.
  assert.equal(packageJson.publishConfig?.access, 'public')
})

test('the platform packages match the napi config and the main package', () => {
  const { binaryName, packageName, targets } = packageJson.napi
  const dirs = readdirSync(new URL('npm/', packageDir), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
  assert.equal(dirs.length, targets.length, 'one npm/<platform> directory per napi target')

  for (const dir of dirs) {
    const platform = readJson(new URL(`npm/${dir}/package.json`, packageDir))
    assert.equal(platform.name, `${packageName}-${dir}`)
    assert.equal(platform.version, packageJson.version, `${platform.name} version`)
    assert.equal(platform.license, packageJson.license, `${platform.name} license`)
    assert.deepEqual(platform.engines, packageJson.engines, `${platform.name} engines`)
    assert.deepEqual(platform.repository, packageJson.repository, `${platform.name} repository`)
    assert.deepEqual(platform.files, [`${binaryName}.${dir}.node`], `${platform.name} files`)
    // Scoped packages are private by default; without this the first publish fails.
    assert.equal(platform.publishConfig?.access, 'public', `${platform.name} publishConfig.access`)
  }
})

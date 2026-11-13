import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { Miniflare } from 'miniflare'
import { configArguments, validateConfig } from '../scripts/preflight.mjs'
import { makeEnv } from './fixtures.js'
import './docs-examples.test.mjs'
import './tooling-cases.mjs'

const folder = mkdtempSync(join(tmpdir(), 'approov-preflight-'))
const main = resolve('src/index.js')
const configPath = join(folder, 'wrangler.json')
const config = { name: 'approov-preflight-test', main, compatibility_date: '2025-12-15', compatibility_flags: ['nodejs_compat'], vars: { APPROOV_MODE: 'annotate', API_DOMAIN: 'origin.example.com' } }
writeFileSync(configPath, JSON.stringify(config))
after(() => rmSync(folder, { recursive: true, force: true }))

test('selected environment and overrides use Wrangler configuration semantics', () => {
  const file = join(folder, 'environments.jsonc')
  writeFileSync(file, JSON.stringify({
    ...config,
    env: {
      valid: { vars: { ...config.vars, APPROOV_MODE: 'block', APPROOV_TOKEN_ACTION: 'continue', APPROOV_MESSAGE_SIGNING_ACTION: 'block' } },
      invalid: { vars: { ...config.vars, APPROOV_TOKEN_ACTION: 'block' } }
    }
  }))
  assert.equal(validateConfig(['--config', file, '--env', 'valid']).approovMode, 'block')
  assert.throws(() => validateConfig(['--config', file, '--env', 'invalid']), /must not be set in annotate mode/)
  assert.equal(validateConfig(['--config', file, '--env', 'invalid', '--var', 'APPROOV_MODE:block', '--var', 'APPROOV_MESSAGE_SIGNING_ACTION:continue']).approovMode, 'block')
  assert.throws(() => validateConfig(['--config', file, '--env', 'valid', '--var', 'APPROOV_TOKEN_ACTION:log']), /APPROOV_TOKEN_ACTION/)
})

test('policy validation runs without the optional backend export', () => {
  assert.equal(validateConfig(['--config', configPath]).isValid, true)
  assert.throws(() => validateConfig(['--config', configPath, '--var', 'APPROOV_MESSAGE_SIGNING_ACTION:block']), /annotate mode/)
})

test('preflight accepts explicit signing requirements and rejects unsupported values', () => {
  for (const policy of ['install', 'account', 'either', 'both']) {
    assert.equal(validateConfig(['--config', configPath, '--var', `APPROOV_MESSAGE_SIGNING_REQUIRED:${policy}`]).approovMessageSigningRequired, policy)
  }
  assert.throws(() => validateConfig(['--config', configPath, '--var', 'APPROOV_MESSAGE_SIGNING_REQUIRED:none']), /APPROOV_MESSAGE_SIGNING_REQUIRED/)
})

test('invalid deployment and preview arguments stop before invoking Wrangler', () => {
  for (const command of [['deploy', '--dry-run'], ['versions', 'upload']]) {
    const child = spawnSync(process.execPath, ['scripts/wrangler.mjs', ...command, '--config', configPath, '--var', 'APPROOV_TOKEN_ACTION:block'], { encoding: 'utf8' })
    assert.equal(child.status, 1)
    assert.match(child.stderr, /must not be set in annotate mode/)
    assert.doesNotMatch(child.stdout, /Total Upload|Version ID|Uploaded/)
  }
})

test('preflight rejects a plugin setting whatever plugins are selected for this build', () => {
  for (const selection of ['', 'arc']) {
    const env = { ...process.env, PLUGINS: selection }
    const valid = spawnSync(process.execPath, ['scripts/validate-config.js', '--config', configPath], { encoding: 'utf8', env })
    assert.equal(valid.status, 0, valid.stderr)
    const unknown = spawnSync(process.execPath, ['scripts/validate-config.js', '--config', configPath,
      '--var', 'APPROOV_UNKNOWN_PLUGIN_SETTING:false'], { encoding: 'utf8', env })
    assert.equal(unknown.status, 1, unknown.stderr)
    assert.match(unknown.stderr, /unknown configuration field env\.APPROOV_UNKNOWN_PLUGIN_SETTING/)
  }
})

test('development loads local secrets; deployment does not load development overrides', () => {
  writeFileSync(join(folder, '.dev.vars'), `APPROOV_BACKEND_CONFIG='${makeEnv().APPROOV_BACKEND_CONFIG}'\nAPPROOV_MODE=block\n`)
  const local = join(folder, 'local.json')
  writeFileSync(local, JSON.stringify({ ...config, secrets: { required: ['APPROOV_BACKEND_CONFIG'] } }))
  assert.throws(() => validateConfig(['--config', local], { development: true }), /APPROOV_TOKEN_ACTION/)
  assert.equal(validateConfig(['--config', local]).approovMode, 'annotate')
  rmSync(join(folder, '.dev.vars'))
})

test('local backend exports and supplied secret files are validated without exposing contents', () => {
  const exportFile = join(folder, 'approov-config.json')
  writeFileSync(exportFile, 'PRIVATE-SECRET')
  assert.throws(() => validateConfig(['--config', configPath]), error => {
    assert.match(error.message, /APPROOV_BACKEND_CONFIG/)
    assert.doesNotMatch(error.message, /PRIVATE-SECRET/)
    return true
  })
  rmSync(exportFile)
  const secretFile = join(folder, 'secrets.json')
  writeFileSync(secretFile, JSON.stringify({ APPROOV_BACKEND_CONFIG: makeEnv().APPROOV_BACKEND_CONFIG }))
  assert.equal(validateConfig(['--config', configPath, '--secrets-file', secretFile]).isValid, true)
  const dotEnv = join(folder, 'secrets.env')
  writeFileSync(dotEnv, `APPROOV_BACKEND_CONFIG='${makeEnv().APPROOV_BACKEND_CONFIG}'\n`)
  assert.equal(validateConfig(['--config', configPath, '--secrets-file', dotEnv]).isValid, true)
})

test('explicit env files resolve from the command directory, including --cwd and named environments', () => {
  const commandDir = join(folder, 'env-paths')
  const nested = join(commandDir, 'nested')
  mkdirSync(nested, { recursive: true })
  const secrets = { required: ['APPROOV_BACKEND_CONFIG'] }
  const file = join(nested, 'wrangler.json')
  writeFileSync(file, JSON.stringify({
    ...config,
    secrets,
    env: { staging: { vars: { ...config.vars, APPROOV_TOKEN_AUDIENCE: 'staging' }, secrets } }
  }))
  writeFileSync(join(commandDir, 'secrets.env'), `APPROOV_BACKEND_CONFIG='${makeEnv().APPROOV_BACKEND_CONFIG}'\nAPI_DOMAIN=command.example.com\n`)
  // A different file beside the configuration must not shadow the CLI path.
  writeFileSync(join(nested, 'secrets.env'), 'APPROOV_BACKEND_CONFIG=wrong-file\nAPI_DOMAIN=wrong.example.com\n')
  const cwd = process.cwd()
  const relative = validateConfig(['--cwd', commandDir, '--config', 'nested/wrangler.json', '--env', 'staging', '--env-file', 'secrets.env'], { development: true })
  const absolute = validateConfig(['--config', file, '--env', 'staging', '--env-file', join(commandDir, 'secrets.env')], { development: true })
  for (const context of [relative, absolute]) {
    assert.equal(context.apiHost, 'command.example.com')
    assert.equal(context.approovTokenAudience, 'staging')
  }
  assert.equal(process.cwd(), cwd)

  writeFileSync(join(commandDir, 'second.env'), 'API_DOMAIN=second.example.com\n')
  writeFileSync(join(commandDir, 'third.env'), 'API_DOMAIN=third.example.com\n')
  const multiple = validateConfig(['--cwd', commandDir, '--config', 'nested/wrangler.json', '--env-file', 'secrets.env', '--env-file=second.env', 'third.env'], { development: true })
  assert.equal(multiple.apiHost, 'third.example.com')
  assert.equal(process.cwd(), cwd)
})

test('argument parsing preserves colons, aliases, repeated overrides, and inline flags', () => {
  const args = configArguments(['--config=one.toml', '-e', 'staging', '--var', 'A:https://example.com', 'B:true', '--var=C:continue'])
  assert.deepEqual(args.vars, { A: 'https://example.com', B: 'true', C: 'continue' })
  assert.equal(args.config, 'one.toml')
  assert.equal(args.env, 'staging')
  assert.deepEqual(configArguments(['dev', '--env-file', 'first.env', 'second.env', '--env-file=third.env']).envFiles, ['first.env', 'second.env', 'third.env'])
  assert.throws(() => configArguments(['--var', 'bad']), /NAME:value/)
})

test('the actual Worker entrypoint refuses invalid bindings during initialization', async () => {
  const output = join(folder, 'bundle')
  const require = createRequire(import.meta.url)
  const cli = join(resolve(require.resolve('wrangler/package.json'), '..'), 'bin/wrangler.js')
  const built = spawnSync(process.execPath, [cli,
    'deploy', '--dry-run', '--config', configPath, '--outdir', output], { encoding: 'utf8' })
  assert.equal(built.status, 0, built.stderr)
  const script = readFileSync(join(output, 'index.js'), 'utf8')
  for (const [bindings, valid] of [
    [makeEnv(), true],
    [makeEnv({ APPROOV_TOKEN_ACTION: 'continue' }), false],
    [makeEnv({ APPROOV_MODE: 'BLOCK' }), false],
    [makeEnv({ APPROOV_BACKEND_CONFIG: 'not-json' }), false],
    [{ ...makeEnv(), APPROOV_MODE: 'block' }, false]
  ]) {
    const worker = new Miniflare({
      modules: true,
      script,
      compatibilityDate: '2025-12-15',
      compatibilityFlags: ['nodejs_compat'],
      bindings
    })
    try {
      if (valid) await worker.ready
      else await assert.rejects(worker.ready)
    } finally {
      try { await worker.dispose() } catch { /* expected after refused startup */ }
    }
  }
})

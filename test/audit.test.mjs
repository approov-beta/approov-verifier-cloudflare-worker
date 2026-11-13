import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { assessAudit, exception, runAudit } from '../scripts/audit.mjs'

const require = createRequire(import.meta.url)
const fixture = JSON.parse(readFileSync(new URL('./fixtures/audit-minimatch.json', import.meta.url), 'utf8'))
const now = new Date('2026-11-04T12:00:00Z')
const source = readFileSync(require.resolve('minimatch'))
const evidence = () => ({
  lockfile: JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8')),
  source,
  installedVersion: require('minimatch/package.json').version,
  now
})
const assess = (report = structuredClone(fixture), local = evidence()) => assessAudit({ report, ...local })
const clean = () => ({
  auditReportVersion: 2,
  vulnerabilities: {},
  metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } }
})
const recount = report => {
  const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 }
  for (const entry of Object.values(report.vulnerabilities)) { counts[entry.severity]++; counts.total++ }
  report.metadata.vulnerabilities = counts
  return report
}

test('the captured full npm report permits only the verified development-only false positive', () => {
  const result = assess()
  assert.equal(result.ok, true)
  assert.equal(result.excepted.length, 15)
  assert.deepEqual(result.blocked, [])
})

test('a clean full audit needs neither an exception nor the old package installed', () => {
  assert.deepEqual(assess(clean(), { now: new Date('2030-01-01') }), { ok: true, excepted: [], blocked: [] })
})

test('the upstream amplification reproducer has no optimization pass in pinned minimatch3', () => {
  const { Minimatch } = require('minimatch')
  assert.equal(typeof Minimatch.prototype.firstPhasePreProcess, 'undefined')
  assert.equal(typeof Minimatch.prototype.secondPhasePreProcess, 'undefined')
  assert.equal(source.includes('optimizationLevel'), false)
  const matcher = new Minimatch(Array(30).fill('**/../a/b').join('/'), { optimizationLevel: 2, braceExpandMax: 64 })
  assert.equal(matcher.set.length, 1)
})

const localChanges = [
  ['different package version', e => { e.lockfile.packages['node_modules/minimatch'].version = '3.1.6' }],
  ['runtime dependency', e => { delete e.lockfile.packages['node_modules/minimatch'].dev }],
  ['different integrity', e => { e.lockfile.packages['node_modules/minimatch'].integrity += 'changed' }],
  ['different registry', e => { e.lockfile.packages['node_modules/minimatch'].resolved = 'https://other.invalid/minimatch.tgz' }],
  ['different installed version', e => { e.installedVersion = '10.2.6' }],
  ['changed installed source', e => { e.source = Buffer.concat([source, Buffer.from('\nchanged')]) }],
  ['missing installed source', e => { delete e.source }],
  ['missing lock package', e => { delete e.lockfile.packages['node_modules/minimatch'] }],
  ['missing lockfile', e => { delete e.lockfile }],
  ['expired exception', e => { e.now = new Date(exception.expires) }],
  ['invalid clock', e => { e.now = new Date(NaN) }]
]
for (const [name, mutate] of localChanges) {
  test(`fails closed for ${name}`, () => {
    const local = evidence()
    mutate(local)
    const result = assess(structuredClone(fixture), local)
    assert.equal(result.ok, false)
    assert.equal(result.excepted.length, 0)
    assert.equal(result.blocked.length, 15)
  })
}

const advisoryChanges = [
  ['new advisory URL', a => { a.url = 'https://github.com/advisories/GHSA-new-issue' }],
  ['different advisory identifier', a => { a.source++ }],
  ['new affected range', a => { a.range = '<12.0.0' }],
  ['different package name', a => { a.name = 'another-package' }],
  ['different dependency', a => { a.dependency = 'another-package' }],
  ['escalated severity', a => { a.severity = 'high' }],
  ['changed title', a => { a.title += ' UPDATED' }],
  ['changed CVSS data', a => { a.cvss.score = 5 }],
  ['new advisory metadata', a => { a.description = 'New evidence requires a review' }]
]
for (const [name, mutate] of advisoryChanges) {
  test(`does not except ${name}`, () => {
    const report = structuredClone(fixture)
    mutate(report.vulnerabilities.minimatch.via[0])
    const result = assess(report)
    assert.equal(result.ok, false)
    assert.equal(result.excepted.length, 0)
  })
}

test('a second advisory on minimatch blocks it and every affected ancestor', () => {
  const report = structuredClone(fixture)
  report.vulnerabilities.minimatch.via.push({ ...report.vulnerabilities.minimatch.via[0], source: 99999, url: 'https://github.com/advisories/GHSA-new-issue' })
  const result = assess(report)
  assert.equal(result.ok, false)
  assert.equal(result.excepted.length, 0)
  assert.equal(result.blocked.length, 15)
})

test('an unrelated low-severity finding still blocks the gate', () => {
  const report = structuredClone(fixture)
  report.vulnerabilities.unrelated = {
    name: 'unrelated',
    severity: 'low',
    nodes: ['node_modules/unrelated'],
    via: [{ source: 99999, name: 'unrelated', dependency: 'unrelated', url: 'https://github.com/advisories/GHSA-new-issue', severity: 'low', range: '*' }]
  }
  const result = assess(recount(report))
  assert.equal(result.ok, false)
  assert.equal(result.excepted.length, 15)
  assert.deepEqual(result.blocked, ['unrelated'])
})

test('a new advisory on a lint plugin is not hidden behind its excepted dependency', () => {
  const report = structuredClone(fixture)
  report.vulnerabilities['eslint-plugin-import'].via.push({ source: 99999, name: 'eslint-plugin-import', url: 'https://github.com/advisories/GHSA-new-issue' })
  const result = assess(report)
  assert.equal(result.ok, false)
  assert.ok(result.blocked.includes('eslint-plugin-import'))
  assert.ok(result.blocked.includes('eslint-config-standard'))
})

test('a runtime location in a meta-vulnerability cannot inherit the development exception', () => {
  const local = evidence()
  delete local.lockfile.packages['node_modules/eslint'].dev
  assert.ok(assess(structuredClone(fixture), local).blocked.includes('eslint'))
})

test('a second minimatch installation is outside the reviewed exception', () => {
  const report = structuredClone(fixture)
  report.vulnerabilities.minimatch.nodes.push('node_modules/other/node_modules/minimatch')
  assert.equal(assess(report).excepted.length, 0)
})

test('a new direct dependency is outside the reviewed exception', () => {
  const report = structuredClone(fixture)
  report.vulnerabilities.minimatch.isDirect = true
  assert.equal(assess(report).excepted.length, 0)
})

test('changed computed finding ranges require a new review', () => {
  const report = structuredClone(fixture)
  report.vulnerabilities.minimatch.range = '<12'
  assert.equal(assess(report).ok, false)
})

test('advisory JSON key order does not change its canonical fingerprint', () => {
  const report = structuredClone(fixture)
  const advisory = report.vulnerabilities.minimatch.via[0]
  advisory.cvss = Object.fromEntries(Object.entries(advisory.cvss).reverse())
  report.vulnerabilities.minimatch.via[0] = Object.fromEntries(Object.entries(advisory).reverse())
  assert.equal(assess(report).ok, true)
})

test('a cycle without a concrete advisory cannot be interpreted as an exception', () => {
  const report = structuredClone(fixture)
  report.vulnerabilities.minimatch.via = ['eslint']
  assert.equal(assess(report).ok, false)
})

const badReports = [
  ['unsupported schema', r => { r.auditReportVersion = 3 }],
  ['service error', r => { r.error = { code: 'ENOTFOUND', detail: 'PRIVATE-DATA' } }],
  ['missing vulnerabilities', r => { delete r.vulnerabilities }],
  ['incorrect total', r => { r.metadata.vulnerabilities.total = 0 }],
  ['incorrect severity counts', r => { r.metadata.vulnerabilities.high++ }],
  ['unknown severity', r => { r.vulnerabilities.minimatch.severity = 'unknown' }],
  ['empty via list', r => { r.vulnerabilities.minimatch.via = [] }],
  ['missing locations', r => { delete r.vulnerabilities.minimatch.nodes }],
  ['invalid location', r => { r.vulnerabilities.minimatch.nodes = [null] }],
  ['mismatched name', r => { r.vulnerabilities.minimatch.name = 'changed' }],
  ['missing advisory dependency', r => { r.vulnerabilities.minimatch.via = ['not-in-report'] }],
  ['invalid advisory', r => { r.vulnerabilities.minimatch.via = [null] }]
]
for (const [name, mutate] of badReports) {
  test(`rejects a malformed report: ${name}`, () => {
    const report = structuredClone(fixture)
    mutate(report)
    assert.throws(() => assess(report))
  })
}

const invoke = (child, production = { status: 0, stdout: JSON.stringify(clean()) }) => {
  const messages = []
  const log = { log: value => messages.push(value), error: value => messages.push(value) }
  const status = runAudit({ run: (_, args) => args.includes('--omit=dev') ? production : child, evidence, log, npmCli: '/fixture/npm-cli.js', now })
  return { status, output: messages.join('\n') }
}

test('the CLI runner permits the reviewed case and names its expiry without claiming a clean raw audit', () => {
  const result = invoke({ status: 1, stdout: JSON.stringify(fixture) })
  assert.equal(result.status, 0)
  assert.match(result.output, /reported 15/)
  assert.ok(result.output.includes(exception.advisory))
  assert.ok(result.output.includes(exception.expires))
  assert.match(result.output, /production-only audit: 0/)
})

test('the CLI runner reports a changed advisory as blocking, without running a production audit', () => {
  const report = structuredClone(fixture)
  report.vulnerabilities.minimatch.via[0].url = 'https://github.com/advisories/GHSA-new-issue'
  const result = invoke({ status: 1, stdout: JSON.stringify(report) })
  assert.equal(result.status, 1)
  assert.match(result.output, /exception not applied/)
  assert.match(result.output, /Unreviewed findings \(15\)/)
  assert.ok(!result.output.includes('production-only audit'))
})

test('the actual CLI verifies installed evidence and propagates the gate result through child processes', () => {
  const folder = mkdtempSync(join(tmpdir(), 'approov-audit-cli-'))
  try {
    const fakeNpm = join(folder, 'npm-cli.mjs')
    writeFileSync(fakeNpm, `
      import { readFileSync } from 'node:fs'
      const production = process.argv.includes('--omit=dev')
      const report = production ? ${JSON.stringify(clean())} : JSON.parse(readFileSync(${JSON.stringify(fileURLToPath(new URL('./fixtures/audit-minimatch.json', import.meta.url)))}, 'utf8'))
      console.log(JSON.stringify(report))
      process.exitCode = production ? 0 : 1
    `)
    const child = spawnSync(process.execPath, ['scripts/audit.mjs'], {
      encoding: 'utf8', timeout: 10000, env: { ...process.env, npm_execpath: fakeNpm }
    })
    assert.equal(child.status, 0, child.stderr)
    assert.match(child.stdout, /reported 15/)
    assert.match(child.stdout, /production-only audit: 0/)
    assert.match(child.stdout, /gate: PASS/)
  } finally {
    rmSync(folder, { recursive: true, force: true })
  }
})

test('no exception applies to a finding reproduced in the production-only audit', () => {
  const child = { status: 1, stdout: JSON.stringify(fixture) }
  const result = invoke(child, child)
  assert.equal(result.status, 1)
  assert.match(result.output, /production-only audit: 15/)
  assert.match(result.output, /gate: FAIL/)
})

test('an unavailable production-only audit cannot turn a development exception into a pass', () => {
  const result = invoke({ status: 1, stdout: JSON.stringify(fixture) }, { status: 1, stdout: 'PRIVATE-DATA' })
  assert.equal(result.status, 1)
  assert.match(result.output, /failed closed/)
  assert.ok(!result.output.includes('PRIVATE-DATA'))
})

test('the CLI runner accepts a genuinely clean audit without loading stale exception evidence', () => {
  assert.equal(runAudit({ run: () => ({ status: 0, stdout: JSON.stringify(clean()) }), npmCli: '/fixture/npm-cli.js', evidence: () => { throw new Error('must not be called') }, log: { log () {}, error () {} } }), 0)
})

test('the CLI runner invokes the full npm audit without severity filters, omissions, or a shell', () => {
  const status = runAudit({
    npmCli: '/fixture/npm-cli.js',
    run: (command, args, options) => {
      assert.equal(command, process.execPath)
      assert.deepEqual(args, ['/fixture/npm-cli.js', 'audit', '--json'])
      assert.notEqual(options.shell, true)
      assert.equal(options.timeout, 60000)
      assert.equal(options.maxBuffer, 4 * 1024 * 1024)
      return { status: 0, stdout: JSON.stringify(clean()) }
    },
    log: { log () {}, error () {} }
  })
  assert.equal(status, 0)
})

test('the CLI runner fails closed when local verification evidence cannot be read', () => {
  assert.equal(runAudit({
    npmCli: '/fixture/npm-cli.js',
    run: () => ({ status: 1, stdout: JSON.stringify(fixture) }),
    evidence: () => { throw new Error('PRIVATE-DATA') },
    log: { log () {}, error: value => assert.ok(!value.includes('PRIVATE-DATA')) }
  }), 1)
})

test('the CLI runner requires an explicit npm executable and never falls back to a shell', () => {
  assert.equal(runAudit({ npmCli: null, run: () => { throw new Error('must not run') }, log: { log () {}, error () {} } }), 1)
})

for (const [name, child] of [
  ['non-JSON response', { status: 1, stdout: 'PRIVATE-DATA' }],
  ['non-audit exit', { status: 2, stdout: JSON.stringify(fixture) }],
  ['signal termination', { status: null, stdout: JSON.stringify(fixture) }],
  ['timeout', { status: null, error: new Error('PRIVATE-DATA') }],
  ['exit status inconsistent with findings', { status: 0, stdout: JSON.stringify(fixture) }],
  ['failed exit with no findings', { status: 1, stdout: JSON.stringify(clean()) }]
]) {
  test(`the CLI runner fails closed for ${name}`, () => {
    const result = invoke(child)
    assert.equal(result.status, 1)
    assert.match(result.output, /failed closed/)
    assert.ok(!result.output.includes('PRIVATE-DATA'))
  })
}

test('the existing linter still rejects correctness, import, and Standard Style regressions', async () => {
  const { ESLint } = require('eslint')
  const eslint = new ESLint()
  const cases = [
    ['console.log(notDefined)\n', 'no-undef'],
    ['const unused = 1\n', 'no-unused-vars'],
    ["console.log('style');\n", 'semi'],
    ["import { readFileSync } from 'node:fs'\nimport { writeFileSync } from 'node:fs'\nconsole.log(readFileSync, writeFileSync)\n", 'import/no-duplicates']
  ]
  for (const [code, rule] of cases) {
    const [result] = await eslint.lintText(code, { filePath: 'src/lint-policy-probe.js' })
    assert.ok(result.messages.some(message => message.ruleId === rule), `${rule} must remain enforced`)
  }
  const [valid] = await eslint.lintText("const value = Buffer.from('safe')\nconsole.log(value)\n", { filePath: 'src/lint-policy-probe.js' })
  assert.equal(valid.errorCount, 0)
})

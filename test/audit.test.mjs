import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { assessAudit, runAudit } from '../scripts/audit.mjs'

const require = createRequire(import.meta.url)
const clean = () => ({
  auditReportVersion: 2,
  vulnerabilities: {},
  metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } }
})
const advisory = (name, severity) => ({
  source: 1, name, dependency: name, title: 'synthetic advisory', url: 'https://github.com/advisories/GHSA-test', severity, range: '<9.9.9'
})
// One development-only root finding and the package that inherits it.
const findings = (severity = 'moderate') => ({
  auditReportVersion: 2,
  vulnerabilities: {
    'dev-tool': { name: 'dev-tool', severity, isDirect: false, via: [advisory('dev-tool', severity)], effects: ['dev-parent'], range: '<9.9.9', nodes: ['node_modules/dev-tool'], fixAvailable: false },
    'dev-parent': { name: 'dev-parent', severity, isDirect: true, via: ['dev-tool'], effects: [], range: '*', nodes: ['node_modules/dev-parent'], fixAvailable: false }
  },
  metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, [severity]: 2, total: 2 } }
})

test('a clean full audit passes', () => {
  assert.deepEqual(assessAudit({ report: clean() }), { ok: true, blocked: [] })
})

for (const severity of ['info', 'low', 'moderate', 'high', 'critical']) {
  test(`a ${severity} finding blocks the gate, including development-only packages`, () => {
    assert.deepEqual(assessAudit({ report: findings(severity) }), { ok: false, blocked: ['dev-tool', 'dev-parent'] })
  })
}

const badReports = [
  ['unsupported schema', r => { r.auditReportVersion = 3 }],
  ['service error', r => { r.error = { code: 'ENOTFOUND', detail: 'PRIVATE-DATA' } }],
  ['missing vulnerabilities', r => { delete r.vulnerabilities }],
  ['incorrect total', r => { r.metadata.vulnerabilities.total = 0 }],
  ['incorrect severity counts', r => { r.metadata.vulnerabilities.high++ }],
  ['unknown severity', r => { r.vulnerabilities['dev-tool'].severity = 'unknown' }],
  ['empty via list', r => { r.vulnerabilities['dev-tool'].via = [] }],
  ['missing locations', r => { delete r.vulnerabilities['dev-tool'].nodes }],
  ['invalid location', r => { r.vulnerabilities['dev-tool'].nodes = [null] }],
  ['mismatched name', r => { r.vulnerabilities['dev-tool'].name = 'changed' }]
]
for (const [name, mutate] of badReports) {
  test(`rejects a malformed report: ${name}`, () => {
    const report = findings()
    mutate(report)
    assert.throws(() => assessAudit({ report }))
  })
}

const invoke = (child) => {
  const messages = []
  const log = { log: value => messages.push(value), error: value => messages.push(value) }
  const status = runAudit({ run: () => child, log, npmCli: '/fixture/npm-cli.js' })
  return { status, output: messages.join('\n') }
}

test('the CLI runner passes a clean audit', () => {
  const result = invoke({ status: 0, stdout: JSON.stringify(clean()) })
  assert.equal(result.status, 0)
  assert.match(result.output, /reported 0/)
  assert.match(result.output, /gate: PASS/)
})

test('the CLI runner names every finding and fails', () => {
  const result = invoke({ status: 1, stdout: JSON.stringify(findings()) })
  assert.equal(result.status, 1)
  assert.match(result.output, /Findings \(2\): dev-tool, dev-parent/)
  assert.match(result.output, /gate: FAIL/)
})

test('the actual CLI propagates the gate result through child processes', () => {
  const folder = mkdtempSync(join(tmpdir(), 'approov-audit-cli-'))
  try {
    for (const [report, status, verdict] of [[clean(), 0, /gate: PASS/], [findings(), 1, /gate: FAIL/]]) {
      const fakeNpm = join(folder, `npm-cli-${status}.mjs`)
      writeFileSync(fakeNpm, `console.log(${JSON.stringify(JSON.stringify(report))})\nprocess.exitCode = ${status}\n`)
      const child = spawnSync(process.execPath, ['scripts/audit.mjs'], {
        encoding: 'utf8', timeout: 10000, env: { ...process.env, npm_execpath: fakeNpm }
      })
      assert.equal(child.status, status, child.stderr)
      assert.match(child.stdout, verdict)
    }
  } finally {
    rmSync(folder, { recursive: true, force: true })
  }
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

test('the CLI runner requires an explicit npm executable and never falls back to a shell', () => {
  assert.equal(runAudit({ npmCli: null, run: () => { throw new Error('must not run') }, log: { log () {}, error () {} } }), 1)
})

for (const [name, child] of [
  ['non-JSON response', { status: 1, stdout: 'PRIVATE-DATA' }],
  ['non-audit exit', { status: 2, stdout: JSON.stringify(findings()) }],
  ['signal termination', { status: null, stdout: JSON.stringify(findings()) }],
  ['timeout', { status: null, error: new Error('PRIVATE-DATA') }],
  ['exit status inconsistent with findings', { status: 0, stdout: JSON.stringify(findings()) }],
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

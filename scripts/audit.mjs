import { spawnSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'

// The gate has no severity threshold and no exceptions. See
// docs/dependency-audit.md before adding either.
const root = new URL('../', import.meta.url)
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const severities = ['info', 'low', 'moderate', 'high', 'critical']

/** Reject incomplete reports rather than interpreting missing data as clean. */
const validateReport = report => {
  if (!record(report) || report.error || report.auditReportVersion !== 2 ||
    !record(report.vulnerabilities) || !record(report.metadata?.vulnerabilities)) throw new Error('Unsupported audit report')
  const counts = Object.fromEntries(severities.map(name => [name, 0]))
  for (const [name, entry] of Object.entries(report.vulnerabilities)) {
    if (!record(entry) || entry.name !== name || !severities.includes(entry.severity) ||
      !Array.isArray(entry.via) || !entry.via.length ||
      !Array.isArray(entry.nodes) || !entry.nodes.length ||
      entry.nodes.some(node => typeof node !== 'string')) throw new Error('Incomplete vulnerability entry')
    counts[entry.severity]++
  }
  const totals = report.metadata.vulnerabilities
  if (severities.some(name => totals[name] !== counts[name]) ||
    totals.total !== Object.keys(report.vulnerabilities).length) throw new Error('Inconsistent audit totals')
}

/** Assess the full npm report. Every reported package entry fails the gate. */
export const assessAudit = ({ report }) => {
  validateReport(report)
  const blocked = Object.keys(report.vulnerabilities)
  return { ok: blocked.length === 0, blocked }
}

/** Run npm itself without a shell. Network/tool/schema failures always fail CI. */
export const runAudit = ({ run = spawnSync, log = console, npmCli = process.env.npm_execpath } = {}) => {
  try {
    if (typeof npmCli !== 'string' || !npmCli) throw new Error('Use npm run audit')
    const child = run(process.execPath, [npmCli, 'audit', '--json'], {
      cwd: fileURLToPath(root), encoding: 'utf8', timeout: 60000, maxBuffer: 4 * 1024 * 1024
    })
    if (child.error || ![0, 1].includes(child.status)) throw new Error('Audit process failed')
    const report = JSON.parse(child.stdout)
    const result = assessAudit({ report })
    if (child.status !== (result.ok ? 0 : 1)) throw new Error('Audit status does not match report')
    log.log(`npm audit reported ${result.blocked.length} vulnerable package entries.`)
    if (result.blocked.length) log.error(`Findings (${result.blocked.length}): ${result.blocked.join(', ')}`)
    log.log(`Dependency audit gate: ${result.ok ? 'PASS' : 'FAIL'}. No severity classes are excluded.`)
    return result.ok ? 0 : 1
  } catch {
    log.error('Dependency audit failed closed: npm returned an error or an unsupported/incomplete report.')
    return 1
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = runAudit()
}

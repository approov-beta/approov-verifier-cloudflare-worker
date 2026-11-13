import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'

// This is an applicability exception, not a severity threshold. See the source
// evidence and removal criteria in docs/dependency-audit.md before changing it.
export const exception = Object.freeze({
  advisory: 'https://github.com/advisories/GHSA-g3hv-75wg-m249',
  source: 1244012,
  version: '3.1.5',
  expires: '2026-12-04T00:00:00Z',
  integrity: 'sha512-VgjWUsnnT6n+NUk6eZq77zeFdpW2LWDzP6zFGrCbHXiYNul5Dzqk2HHQ5uFH2DNW5Xbp8+jVzaeNt94ssEEl4w==',
  sourceSha256: '746849f267c4868a53729225bd85c7dccd387712136fb305fcc0a3eadd4a3d9d',
  advisorySha256: '40ce900bafdd753e977fddf1e00309fdca02f9ce067d9d54a686a11221771d4b'
})

const root = new URL('../', import.meta.url)
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const severities = ['info', 'low', 'moderate', 'high', 'critical']
const minimatchPath = 'node_modules/minimatch'
const sha256 = value => createHash('sha256').update(value).digest('hex')
const canonicalJson = value => JSON.stringify(value, (_, item) => record(item)
  ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0))
  : item)

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

/** Follow npm's meta-vulnerabilities, including peer cycles, to their advisories. */
const causes = (entries, name, seen = new Set()) => {
  if (!Object.hasOwn(entries, name)) throw new Error('Missing advisory dependency')
  if (seen.has(name)) return []
  seen.add(name)
  return entries[name].via.flatMap(via => {
    if (typeof via === 'string') return causes(entries, via, seen)
    if (!record(via)) throw new Error('Invalid advisory')
    return [{ owner: name, advisory: via }]
  })
}

/** Every reported location must be development-only in the installed lockfile. */
const developmentOnly = (entry, lockfile) => entry.nodes.every(node =>
  Object.hasOwn(lockfile.packages, node) && lockfile.packages[node].dev === true)

/** Assess the full npm report. Any unreviewed finding remains a gate failure. */
export const assessAudit = ({ report, lockfile, source, installedVersion, now = new Date() }) => {
  validateReport(report)
  const entries = report.vulnerabilities
  const excepted = []
  const blocked = []
  const locked = lockfile?.packages?.[minimatchPath]
  const vulnerable = entries.minimatch
  const verifiedLegacyPackage = record(lockfile?.packages) && record(locked) &&
    locked.version === exception.version && locked.dev === true &&
    locked.integrity === exception.integrity &&
    locked.resolved === 'https://registry.npmjs.org/minimatch/-/minimatch-3.1.5.tgz' &&
    installedVersion === exception.version && Buffer.isBuffer(source) &&
    sha256(source) === exception.sourceSha256 &&
    record(vulnerable) && vulnerable.isDirect === false && vulnerable.severity === 'moderate' &&
    vulnerable.range === '<11.0.1' &&
    vulnerable.nodes.length === 1 && vulnerable.nodes[0] === minimatchPath &&
    Number.isFinite(now.getTime()) && now < new Date(exception.expires)

  const allowed = ({ owner, advisory }) => verifiedLegacyPackage && owner === 'minimatch' &&
    advisory.name === 'minimatch' && advisory.dependency === 'minimatch' &&
    advisory.source === exception.source && advisory.url === exception.advisory &&
    advisory.severity === 'moderate' && advisory.range === '<11.0.1' &&
    sha256(canonicalJson(advisory)) === exception.advisorySha256

  for (const [name, entry] of Object.entries(entries)) {
    const advisories = causes(entries, name)
    if (verifiedLegacyPackage && entry.severity === 'moderate' && developmentOnly(entry, lockfile) &&
      advisories.length && advisories.every(allowed)) excepted.push(name)
    else blocked.push(name)
  }
  return { ok: blocked.length === 0, excepted, blocked }
}

const localEvidence = () => ({
  lockfile: JSON.parse(readFileSync(new URL('package-lock.json', root), 'utf8')),
  source: readFileSync(new URL(`${minimatchPath}/minimatch.js`, root)),
  installedVersion: JSON.parse(readFileSync(new URL(`${minimatchPath}/package.json`, root), 'utf8')).version
})

/** Run npm itself without a shell. Network/tool/schema failures always fail CI. */
export const runAudit = ({ run = spawnSync, evidence = localEvidence, log = console, npmCli = process.env.npm_execpath, now = new Date() } = {}) => {
  try {
    if (typeof npmCli !== 'string' || !npmCli) throw new Error('Use npm run audit')
    const execute = args => {
      const child = run(process.execPath, [npmCli, 'audit', '--json', ...args], {
        cwd: fileURLToPath(root), encoding: 'utf8', timeout: 60000, maxBuffer: 4 * 1024 * 1024
      })
      if (child.error || ![0, 1].includes(child.status)) throw new Error('Audit process failed')
      const report = JSON.parse(child.stdout)
      validateReport(report)
      if (child.status !== (report.metadata.vulnerabilities.total ? 1 : 0)) throw new Error('Audit status does not match report')
      return report
    }
    const report = execute([])
    const count = report.metadata.vulnerabilities.total
    const result = assessAudit({ report, ...(count ? evidence() : {}), now })
    log.log(`npm audit reported ${count} vulnerable package entries.`)
    if (result.excepted.length) {
      log.log(`Reviewed false positive: ${exception.advisory}; minimatch ${exception.version}, development-only; expires ${exception.expires}.`)
      log.log(`Excepted entries (${result.excepted.length}): ${result.excepted.join(', ')}`)
    } else if (Object.hasOwn(report.vulnerabilities, 'minimatch')) {
      log.error(`Minimatch exception not applied: verify advisory, package evidence, development-only scope, and expiry ${exception.expires}. See docs/dependency-audit.md.`)
    }
    if (result.blocked.length) log.error(`Unreviewed findings (${result.blocked.length}): ${result.blocked.join(', ')}`)
    let ok = result.ok
    if (ok && result.excepted.length) {
      const production = execute(['--omit=dev'])
      const count = production.metadata.vulnerabilities.total
      log.log(`Additional production-only audit: ${count} vulnerable package entries. No production exceptions are allowed.`)
      if (count) ok = false
    }
    log.log(`Dependency audit gate: ${ok ? 'PASS' : 'FAIL'}. No severity classes are excluded.`)
    return ok ? 0 : 1
  } catch {
    log.error('Dependency audit failed closed: npm returned an error or an unsupported/incomplete report, or local package evidence could not be verified.')
    return 1
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = runAudit()
}

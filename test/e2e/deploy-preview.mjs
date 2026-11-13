/**
 * Deploy a Worker preview version for one matrix profile and return its URL.
 *
 * Uses `wrangler versions upload`, which uploads a new version (with its own
 * preview URL) without touching production. Requires CLOUDFLARE_API_TOKEN and
 * CLOUDFLARE_ACCOUNT_ID in the environment, and preview URLs enabled on the
 * account's workers.dev subdomain.
 *
 * The plugin set is controlled by regenerating the registry with the profile's
 * PLUGINS value *before* upload, so the bundle contains exactly that subset
 * regardless of whether `versions upload` re-runs the [build] hook.
 */
import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { passToken } from './request-builder.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(here, '..', '..')
const configPath = join(here, 'wrangler.e2e.toml')
const generator = join(repoRoot, 'scripts', 'generate-plugins.mjs')
const wrapper = join(repoRoot, 'scripts', 'wrangler.mjs')
// A separate alias isolates this run even from other machines or canceled jobs.
const runId = randomBytes(6).toString('hex')
const PREVIEW_ALIAS = `approov-e2e-${runId}`
let previewHostname = null
let workerExistenceChecked = false

const baseBackendConfig = (() => {
  const toml = readFileSync(configPath, 'utf8')
  const match = toml.match(/^APPROOV_BACKEND_CONFIG = '(.*)'$/m)
  if (!match) throw new Error('could not read APPROOV_BACKEND_CONFIG from the E2E Wrangler config')
  return JSON.parse(match[1])
})()

const run = (file, args, env = {}) => {
  const childEnv = { ...process.env, ...env }
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) delete childEnv[key]
  }
  return execFileSync(file, args, { cwd: repoRoot, env: childEnv, encoding: 'utf8' })
}

/** Regenerate the plugin registry, optionally filtered by a PLUGINS value. */
export const regeneratePlugins = (plugins) => {
  run('node', [generator], { PLUGINS: plugins })
}

/** Restore the registry to all discovered plugins (post-run hygiene). */
export const regenerateAllPlugins = () => regeneratePlugins(undefined)

/** Bootstrap the named test Worker on accounts where it has never been deployed. */
const ensureWorkerExists = () => {
  if (workerExistenceChecked) return

  try {
    run('npx', ['wrangler', 'deployments', 'list', '--config', configPath])
  } catch {
    regenerateAllPlugins()
    run('node', [wrapper, 'deploy', '--config', configPath], { PLUGINS: undefined })
  }
  workerExistenceChecked = true
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/**
 * Deploy a preview for a profile and return its base URL.
 *
 * @param {{name: String, plugins?: String, vars?: Object}} profile
 * @returns {Promise<String>} Preview base URL.
 */
export const deployPreview = async (profile) => {
  ensureWorkerExists()
  regeneratePlugins(profile.plugins)
  const upstreamMarker = `${runId}.${profile.name}.e2e.invalid`

  const upload = (backendConfig = null) => {
    const args = [
      wrapper,
      'versions',
      'upload',
      '--config',
      configPath,
      '--preview-alias',
      PREVIEW_ALIAS,
      '--var',
      `API_DOMAIN:${upstreamMarker}`
    ]
    for (const [key, value] of Object.entries(profile.vars || {})) {
      args.push('--var', `${key}:${value}`)
    }
    if (backendConfig) {
      args.push('--var', `APPROOV_BACKEND_CONFIG:${JSON.stringify(backendConfig)}`)
    }

    const env = { PLUGINS: profile.plugins }
    const out = run('node', args, env)
    const match = out.match(/Version Preview Alias URL:\s*(https:\/\/\S+)/)
    if (!match) {
      throw new Error(`could not parse preview alias URL from wrangler output:\n${out}`)
    }
    return match[1]
  }

  // This run's preview alias gives all of its profiles the same hostname.
  // Bootstrap it once, then bind that exact incoming hostname into `apis` for
  // all real scenario uploads. The bootstrap version is never exercised.
  if (!previewHostname) {
    previewHostname = new URL(upload()).hostname
  }
  const backendConfig = structuredClone(baseBackendConfig)
  backendConfig.apis[previewHostname] = {
    kid: '__default__',
    isPassKeyPresent: true,
    isFailKeyPresent: true
  }
  const url = upload(backendConfig)

  // A preview alias can briefly serve the preceding version while Cloudflare
  // rolls out the new one. Require several consecutive responses carrying this
  // run and profile's unique upstream marker before starting its scenarios.
  let consecutiveMatches = 0
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`${url}?readiness=${i}`, {
        method: 'GET',
        headers: { 'Approov-Token': passToken() }
      })
      const body = res.status === 200 ? await res.json() : null
      const servedUpstream = body && body.url ? new URL(body.url).hostname : null
      const expectedUpstream = profile.vars?.API_PASSTHROUGH === 'true' ? new URL(url).hostname : upstreamMarker
      if (servedUpstream === expectedUpstream) {
        consecutiveMatches++
        if (consecutiveMatches >= 10) return url
      } else {
        consecutiveMatches = 0
      }
    } catch {
      consecutiveMatches = 0
    }
    await sleep(1000)
  }
  throw new Error(`preview alias did not stabilize on profile "${profile.name}"`)
}

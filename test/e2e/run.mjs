/**
 * L2 e2e runner.
 *
 * Two modes:
 *
 *  - CI / preview (default): for each profile, deploy a Worker preview version
 *    (plugin set + config), then run its request scenarios against the preview
 *    URL. Requires Cloudflare credentials (see deploy-preview.mjs).
 *
 *  - Local single-profile: set E2E_BASE_URL to an already-running worker (e.g.
 *    `wrangler dev`) and E2E_PROFILE to the profile whose config that server was
 *    started with. Skips deployment — useful for verifying the loop locally.
 *
 *      E2E_BASE_URL=http://localhost:8799 E2E_PROFILE=binding node test/e2e/run.mjs
 *
 * Assertions live in profiles.mjs; this file is just orchestration + reporting.
 */
import { profiles } from './profiles.mjs'
import { decodeApproovResult } from './request-builder.mjs'
import { deployPreview, regenerateAllPlugins } from './deploy-preview.mjs'
import { acquireRegistryLock } from './registry-lock.mjs'
import { fileURLToPath } from 'node:url'

const BASE_URL = process.env.E2E_BASE_URL || null
const ONLY = process.env.E2E_PROFILE || null

const runScenario = async (baseUrl, scenario) => {
  const request = typeof scenario.request === 'function'
    ? await scenario.request(baseUrl)
    : scenario.request
  const url = baseUrl.replace(/\/$/, '') + request.path
  const res = await fetch(url, {
    method: request.method || 'GET',
    headers: request.headers || {},
    body: request.body
  })

  const text = await res.text()
  let body = null
  try {
    body = JSON.parse(text)
  } catch {
    // non-JSON (e.g. a rejection response body)
  }
  const result = body && body.headers ? decodeApproovResult(body) : null

  scenario.expect({ status: res.status, result, body, text, baseUrl })
}

const main = async () => {
  const selected = profiles.filter((p) => !ONLY || p.name === ONLY)
  if (selected.length === 0) {
    throw new Error(`no profile matched E2E_PROFILE="${ONLY}"`)
  }

  let total = 0
  let failures = 0

  const release = BASE_URL ? null : acquireRegistryLock(fileURLToPath(new URL('../../', import.meta.url)))
  try {
    for (const profile of selected) {
      const baseUrl = BASE_URL || (await deployPreview(profile))
      console.log(`\n▶ profile "${profile.name}" → ${baseUrl}`)

      for (const scenario of profile.scenarios) {
        total++
        try {
          await runScenario(baseUrl, scenario)
          console.log(`  ✓ ${scenario.name}`)
        } catch (err) {
          failures++
          console.error(`  ✗ ${scenario.name}\n      ${err.message.split('\n').join('\n      ')}`)
        }
      }
    }
  } finally {
    // Restore the registry to all plugins only when we mutated it (deploy mode).
    try {
      if (!BASE_URL) regenerateAllPlugins()
    } finally {
      release?.()
    }
  }

  console.log(`\n${total - failures}/${total} scenario(s) passed`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})

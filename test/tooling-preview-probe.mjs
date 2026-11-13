// Isolate builtin mocks from the Node test runner and all real Wrangler calls.
import childProcess from 'node:child_process'
import { syncBuiltinESMExports } from 'node:module'
import assert from 'node:assert/strict'

const versions = new Map()
const uploads = []
const requests = new Map()
childProcess.execFileSync = (file, args) => {
  if (!args.includes('upload')) return ''
  const alias = args[args.indexOf('--preview-alias') + 1]
  const hostname = `${alias}-approov-gateway-e2e.example.workers.dev`
  const vars = Object.fromEntries(args.flatMap((value, i) => {
    if (value !== '--var') return []
    const colon = args[i + 1].indexOf(':')
    return [[args[i + 1].slice(0, colon), args[i + 1].slice(colon + 1)]]
  }))
  versions.set(hostname, vars.API_PASSTHROUGH === 'true' ? hostname : vars.API_DOMAIN)
  uploads.push({ alias, hostname, vars })
  return `Version Preview Alias URL: https://${hostname}\n`
}
syncBuiltinESMExports()
globalThis.fetch = async url => {
  const hostname = new URL(url).hostname
  const count = (requests.get(hostname) || 0) + 1
  requests.set(hostname, count)
  // A stale rollout response must not satisfy readiness.
  const marker = count === 1 ? 'old-run.e2e.invalid' : versions.get(hostname)
  return { status: 200, json: async () => ({ url: `https://${marker}/` }) }
}
globalThis.setTimeout = callback => setImmediate(callback)

const helper = new URL('./e2e/deploy-preview.mjs', import.meta.url)
const [first, second, passthrough] = await Promise.all(['first', 'second', 'passthrough'].map(run => import(`${helper}?run=${run}`)))
const urls = await Promise.all([
  first.deployPreview({ name: 'annotate', vars: {} }),
  second.deployPreview({ name: 'annotate', vars: {} }),
  passthrough.deployPreview({ name: 'passthrough', vars: { API_PASSTHROUGH: 'true', API_DOMAIN: '' } })
])
assert.equal(new Set(urls).size, 3, 'independent runs need different preview URLs even for the same profile')
for (const upload of uploads) {
  assert.match(upload.alias, /^approov-e2e-[a-f0-9]{12}$/)
  assert.ok(upload.alias.length <= 28)
  if (upload.vars.APPROOV_BACKEND_CONFIG) {
    assert.ok(JSON.parse(upload.vars.APPROOV_BACKEND_CONFIG).apis[upload.hostname], 'the exact alias hostname needs an API policy')
  }
  if (upload.vars.API_PASSTHROUGH !== 'true') {
    assert.equal(upload.vars.API_DOMAIN, `${upload.alias.slice('approov-e2e-'.length)}.annotate.e2e.invalid`)
  }
}
for (const count of requests.values()) assert.equal(count, 11, 'readiness must reject a stale run before ten consecutive matches')
console.log(JSON.stringify({ urls, uploads: uploads.length, readinessRequests: [...requests.values()] }))

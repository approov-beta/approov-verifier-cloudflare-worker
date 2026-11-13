import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import jwt from 'jsonwebtoken'
import {
  EXPIRED_EXP, FAIL_PRIVATE_KEY, FUTURE_EXP, PASS_PRIVATE_KEY,
  makeEnv, signEs256, sha256Base64
} from './fixtures.js'
import arcPlugin from '../plugins/arc/index.js'

vi.mock('../src/plugins.generated.js', () => ({ plugins: [] }))
const { plugins, runPlugins, PLUGIN_EVALUATION_TIMEOUT_MS } = await import('../src/plugin-host.js')
const { createAnalytics } = await import('../src/analytics.js')
const { handleRequest } = await import('../src/worker/handle-request.js')

let logSpy
let logSpies
let writeDataPoint
const request = (token) => new Request('https://worker.local/api', {
  headers: token === undefined ? {} : { 'Approov-Token': token }
})
const event = () => logSpy.mock.calls.map(([entry]) => entry).findLast(entry => entry?.event === 'approov.request')
const enabledEnv = (overrides = {}) => makeEnv({
  APPROOV_ANALYTICS_ENABLED: 'true',
  APPROOV_LOGGING_ENABLED: 'true',
  APPROOV_ANALYTICS: { writeDataPoint },
  ...overrides
})
const passing = () => signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP })
// A second annotation plugin, so plugin sets are exercised beyond ARC alone.
// Its summary keeps the status and leaves the detail out.
const samplePlugin = {
  id: 'sample',
  resultKey: 'sampleResult',
  evaluate: () => ({ status: 'DISABLED', detail: 'PRIVATE-DETAIL' }),
  summarize: result => ({ status: result.status })
}

beforeEach(() => {
  plugins.splice(0)
  logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
  logSpies = [logSpy, ...['info', 'warn', 'error'].map(channel => vi.spyOn(console, channel).mockImplementation(() => {}))]
  writeDataPoint = vi.fn()
  vi.stubGlobal('fetch', vi.fn(async () => new Response('upstream', { status: 201 })))
})
afterEach(() => {
  plugins.splice(0)
  vi.useRealTimers()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('core request analytics', () => {
  it.each([
    [undefined, 'MISSING', 'NOT_CHECKED', 'UNAVAILABLE'],
    ['', 'EMPTY', 'NOT_CHECKED', 'UNAVAILABLE'],
    ['   ', 'EMPTY', 'NOT_CHECKED', 'UNAVAILABLE'],
    ['not-a-token', 'PRESENT', 'MALFORMED', 'UNAVAILABLE'],
    ['ey.not-json.signature', 'PRESENT', 'UNPARSABLE', 'UNAVAILABLE'],
    [() => signEs256(PASS_PRIVATE_KEY, { exp: EXPIRED_EXP }), 'PRESENT', 'EXPIRED', 'UNAVAILABLE'],
    [() => signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP }).slice(0, -10) + 'aaaaaaaaaa', 'PRESENT', 'INVALID_SIG', 'UNAVAILABLE'],
    [passing, 'PRESENT', 'VERIFIED', 'PASS'],
    [() => signEs256(FAIL_PRIVATE_KEY, { exp: FUTURE_EXP }), 'PRESENT', 'VERIFIED', 'FAIL']
  ])('distinguishes %s', async (token, presence, verification, attestation) => {
    await handleRequest(request(typeof token === 'function' ? token() : token), enabledEnv())
    expect(event()).toMatchObject({
      token: { presence, verification },
      attestation,
      validation: attestation === 'PASS' ? 'PASS' : 'FAIL',
      mode: 'annotate',
      action: 'forward',
      responseStatus: 201,
      upstreamStatus: 201,
      plugins: {}
    })
    expect(writeDataPoint).toHaveBeenCalledTimes(1)
    expect(logSpy.mock.calls.filter(([entry]) => entry?.event === 'approov.request')).toHaveLength(1)
  })

  it('writes the exact fixed Analytics Engine schema', async () => {
    const response = await handleRequest(request(passing()), enabledEnv())
    expect(response.status).toBe(201)
    expect(writeDataPoint).toHaveBeenCalledWith({
      blobs: ['3', 'annotate', 'forward', 'PRESENT', 'VERIFIED', 'PASS', 'DISABLED', 'none', 'NOT_REQUIRED', 'PASS', 'missing'],
      doubles: [201, 201, expect.any(Number)],
      indexes: ['VERIFIED:PASS:PASS']
    })
    expect(event().durationMs).toBeGreaterThanOrEqual(0)
    expect(writeDataPoint.mock.calls[0][0].doubles[2]).toBe(event().durationMs)
  })

  it.each([
    [{ APPROOV_TOKEN_BINDING_ENABLED: 'true' }, 'MISSING_HEADER', 'none', 'NOT_REQUIRED'],
    [{ }, 'DISABLED', 'install', 'INVALID_INSTALL_KEY_CLAIM'],
    [{ APPROOV_TOKEN_BINDING_ENABLED: 'true' }, 'MISSING_HEADER', 'install', 'INVALID_INSTALL_KEY_CLAIM']
  ])('includes secondary verification failures (%j)', async (overrides, binding, mode, status) => {
    const token = mode === 'install' ? signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, ipk: 'not-a-key' }) : passing()
    await handleRequest(request(token), enabledEnv(overrides))
    expect(event()).toMatchObject({
      token: { verification: 'VERIFIED' },
      attestation: 'PASS',
      binding,
      messageSignature: { mode, status },
      validation: 'FAIL'
    })
  })

  it('records configured rejection and suppresses the duplicate legacy outcome log', async () => {
    const response = await handleRequest(request(), enabledEnv({ APPROOV_MODE: 'block', APPROOV_BLOCK_RESPONSE_STATUS: 418 }))
    expect(response.status).toBe(418)
    expect(fetch).not.toHaveBeenCalled()
    expect(event()).toMatchObject({ action: 'block', responseStatus: 418, upstreamStatus: null })
    expect(writeDataPoint.mock.calls[0][0].doubles.slice(0, 2)).toEqual([418, -1])
    expect(logSpy.mock.calls.some(([entry]) => typeof entry === 'string' && entry.startsWith('[Approov]'))).toBe(false)
  })

  it('records passing reject mode and echo mode without contacting upstream', async () => {
    await handleRequest(request(passing()), enabledEnv({ APPROOV_MODE: 'block', APPROOV_ECHO_MODE: 'true' }))
    expect(event()).toMatchObject({ validation: 'PASS', mode: 'block', action: 'echo', responseStatus: 200, upstreamStatus: null })
    expect(fetch).not.toHaveBeenCalled()
  })

  it.each([
    [{ APPROOV_BACKEND_CONFIG: 'broken' }, 500, 'NOT_CHECKED', 'UNAVAILABLE'],
    [{ API_PASSTHROUGH: 'true', API_DOMAIN: '' }, 508, 'MISSING', 'annotate']
  ])('emits on configuration and loop-detection exits (%j)', async (overrides, status, presence, mode) => {
    const req = new Request('https://worker.local/api', { headers: { 'Approov-Gateway-Hop': '1' } })
    const response = await handleRequest(req, enabledEnv(overrides))
    expect(response.status).toBe(status)
    expect(event()).toMatchObject({ token: { presence, verification: 'NOT_CHECKED' }, mode, action: 'error', validation: 'NOT_EVALUATED' })
    expect(writeDataPoint).toHaveBeenCalledTimes(1)
    expect(fetch).not.toHaveBeenCalled()
  })

  it('emits when incoming API policy cannot be resolved', async () => {
    const response = await handleRequest(new Request('https://unknown.example/api'), enabledEnv())
    expect(response.status).toBe(500)
    expect(event()).toMatchObject({ validation: 'NOT_EVALUATED', action: 'error', responseStatus: 500 })
    expect(writeDataPoint).toHaveBeenCalledTimes(1)
  })

  it('reports an unreachable upstream as a 502 with established validation and no retry', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    fetch.mockRejectedValue(new Error('upstream unavailable'))
    const response = await handleRequest(request(passing()), enabledEnv())
    expect(response.status).toBe(502)
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(event()).toMatchObject({ validation: 'PASS', action: 'error', responseStatus: 502, upstreamStatus: null })
    expect(writeDataPoint.mock.calls[0][0].doubles.slice(0, 2)).toEqual([502, -1])
  })

  it('preserves completed verification while forwarding an ERROR annotation', async () => {
    plugins.push({ id: 'bigint', evaluate: () => 1n })
    const response = await handleRequest(request(passing()), enabledEnv())
    expect(response.status).toBe(201)
    expect(event()).toMatchObject({ token: { verification: 'VERIFIED' }, attestation: 'PASS', validation: 'ERROR', action: 'forward' })
  })

  it('retains authenticity when binding evaluation throws after token verification', async () => {
    const req = request(passing())
    const originalGet = req.headers.get.bind(req.headers)
    vi.spyOn(req.headers, 'get').mockImplementation(name => {
      if (name === 'Authorization') throw new Error('PRIVATE-BINDING-ERROR')
      return originalGet(name)
    })
    await handleRequest(req, enabledEnv({ APPROOV_TOKEN_BINDING_ENABLED: 'true', APPROOV_MODE: 'block' }))
    expect(event()).toMatchObject({ token: { verification: 'VERIFIED' }, attestation: 'PASS', validation: 'ERROR', action: 'block' })
  })

  it.each([{}, { APPROOV_ANALYTICS_ENABLED: 'false' }, { APPROOV_ANALYTICS_ENABLED: 'invalid' }])('is opt-in (%j)', async (overrides) => {
    await handleRequest(request(passing()), makeEnv({ APPROOV_ANALYTICS: { writeDataPoint }, ...overrides }))
    expect(writeDataPoint).not.toHaveBeenCalled()
    expect(event()).toBeUndefined()
  })

  it('allows Analytics Engine without structured logs without duplicate outcome logs', async () => {
    await handleRequest(request(), enabledEnv({ APPROOV_LOGGING_ENABLED: 'false', APPROOV_MODE: 'block' }))
    expect(event()).toBeUndefined()
    expect(writeDataPoint).toHaveBeenCalledTimes(1)
    expect(logSpy.mock.calls.some(([entry]) => typeof entry === 'string' && entry.startsWith('[Approov]'))).toBe(false)
  })

  it('allows structured logs without an Analytics Engine binding', async () => {
    await handleRequest(request(passing()), enabledEnv({ APPROOV_ANALYTICS: undefined }))
    expect(event().validation).toBe('PASS')
    expect(writeDataPoint).not.toHaveBeenCalled()
  })

  it.each(['log', 'engine', 'both'])('isolates failing destinations (%s)', async (failure) => {
    if (failure !== 'engine') logSpy.mockImplementation(() => { throw new Error('log sink failure') })
    if (failure !== 'log') writeDataPoint.mockImplementation(() => { throw new Error('engine failure') })
    const response = await handleRequest(request(passing()), enabledEnv())
    expect(response.status).toBe(201)
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(writeDataPoint).toHaveBeenCalledTimes(1)
    expect(fetch.mock.calls[0][0].headers.get('Approov-Result')).not.toBeNull()
  })

  it('isolates failing diagnostic logs when debug is enabled or analytics logs are disabled', async () => {
    for (const spy of logSpies) spy.mockImplementation(() => { throw new Error('console failure') })
    plugins.push({ id: 'throws', evaluate: () => { throw new Error('plugin failed') }, summarize: () => ({ status: 'DONE' }) })
    const response = await handleRequest(request(passing()), enabledEnv({ APPROOV_DEBUG: 'true', APPROOV_LOGGING_ENABLED: 'false', APPROOV_MODE: 'block' }))
    expect(response.status).toBe(201)
    expect(writeDataPoint.mock.calls[0][0].blobs[9]).toBe('PASS')
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('isolates collector initialization failures from security evaluation', async () => {
    plugins.push({ id: 'invalid-summary-hook', evaluate: () => 'annotation', get summarize () { throw new Error('summary registration failure') } })
    expect((await handleRequest(request(passing()), enabledEnv())).status).toBe(201)
    expect(fetch.mock.calls[0][0].headers.get('Approov-Result')).not.toBeNull()
  })

  it('isolates finalization failures from the returned response', async () => {
    vi.spyOn(performance, 'now').mockReturnValueOnce(0).mockImplementation(() => { throw new Error('collector failure') })
    expect((await handleRequest(request(passing()), enabledEnv())).status).toBe(201)
  })

  it('does not read request or response bodies for analytics', async () => {
    const req = request(passing())
    const response = new Response('streaming payload')
    fetch.mockResolvedValue(response)
    const readRequest = vi.spyOn(req, 'text')
    const readResponse = vi.spyOn(response, 'text')
    expect(await handleRequest(req, enabledEnv())).toBe(response)
    expect(readRequest).not.toHaveBeenCalled()
    expect(readResponse).not.toHaveBeenCalled()
    expect(response.bodyUsed).toBe(false)
  })

  it('keeps concurrent request summaries separate', async () => {
    await Promise.all([handleRequest(request(passing()), enabledEnv()), handleRequest(request(), enabledEnv())])
    const summaries = logSpy.mock.calls.map(([entry]) => entry).filter(entry => entry?.event === 'approov.request')
    expect(summaries.map(entry => entry.token.presence).sort()).toEqual(['MISSING', 'PRESENT'])
    expect(writeDataPoint).toHaveBeenCalledTimes(2)
  })
})

describe('safe, optional plugin summaries', () => {
  it.each([
    [PASS_PRIVATE_KEY, 'AAAAAUKWPP', 'PASS', 'pass'],
    [FAIL_PRIVATE_KEY, 'AAAAAVJXIO', 'FAIL', 'fail']
  ])('records decoded ARC only in logs for signed fixture %#', async (key, arc, attestation, marker) => {
    plugins.push(arcPlugin)
    await handleRequest(request(signEs256(key, { exp: FUTURE_EXP, arc })), enabledEnv())
    expect(event()).toMatchObject({ token: { verification: 'VERIFIED' }, attestation, plugins: { arc: { status: 'DECODED' } } })
    expect(event().plugins.arc.properties[0]).toBe(marker)
    expect(event().plugins.arc.properties).toContain('debug')
    expect(JSON.stringify(event())).not.toContain(arc)
    expect(writeDataPoint.mock.calls[0][0].blobs).toHaveLength(11)
    expect(JSON.stringify(writeDataPoint.mock.calls)).not.toContain('properties')
  })

  it.each([[], [arcPlugin], [samplePlugin], [arcPlugin, samplePlugin]])('supports installed plugin set %#', async (...installed) => {
    // Vitest spreads each row, so reconstruct the selected plugin set.
    plugins.push(...installed)
    await handleRequest(request(passing()), enabledEnv())
    expect(Object.keys(event().plugins)).toEqual(installed.map(plugin => plugin.id))
    if (installed.includes(arcPlugin)) expect(event().plugins.arc).toEqual({ status: 'UNAVAILABLE', properties: null })
    if (installed.includes(samplePlugin)) expect(event().plugins.sample).toEqual({ status: 'DISABLED' })
    const point = writeDataPoint.mock.calls[0][0]
    expect(point.blobs).toHaveLength(11)
    const annotation = JSON.parse(Buffer.from(fetch.mock.calls[0][0].headers.get('Approov-Result'), 'base64').toString())
    expect(annotation).not.toHaveProperty('plugins')
    expect(annotation).not.toHaveProperty('version')
  })

  it('accepts a setting only when an installed plugin declares it', async () => {
    const env = () => enabledEnv({ APPROOV_SAMPLE_ENABLED: 'true' })
    expect((await handleRequest(request(passing()), env())).status).toBe(500)
    plugins.push({ ...samplePlugin, configSchema: { APPROOV_SAMPLE_ENABLED: { type: 'boolean' } } })
    expect((await handleRequest(request(passing()), env())).status).toBe(201)
  })

  it('records summarizable plugins as NOT_CHECKED when token evaluation exits early', async () => {
    plugins.push(arcPlugin, samplePlugin)
    await handleRequest(request(), enabledEnv())
    expect(event().plugins).toEqual({ arc: { status: 'NOT_CHECKED' }, sample: { status: 'NOT_CHECKED' } })
  })

  it('only passes the plugin result to summarize and does not change its annotation', async () => {
    const result = Object.freeze({ status: 'DONE', secret: 'private-value', metrics: { count: 1 } })
    const summarize = vi.fn(value => ({ status: value.status, metrics: value.metrics }))
    plugins.push({ id: 'custom', resultKey: 'customAnnotation', evaluate: () => result, summarize })
    await handleRequest(request(passing()), enabledEnv())
    expect(summarize).toHaveBeenCalledWith(result)
    expect(summarize.mock.calls[0]).toHaveLength(1)
    expect(event().plugins.custom).toEqual({ status: 'DONE', metrics: { count: 1 } })
    expect(event().plugins.custom.metrics).not.toBe(result.metrics)
    const annotation = JSON.parse(Buffer.from(fetch.mock.calls[0][0].headers.get('Approov-Result'), 'base64').toString())
    expect(annotation.customAnnotation).toEqual(result)
  })

  it('summarizes undefined results and isolates summary and evaluation failures', async () => {
    const mustNotSummarize = vi.fn()
    plugins.push(
      { id: 'legacy', evaluate: () => 'legacy' },
      { id: 'skipped', summarize: () => ({ status: 'DONE' }) },
      { id: 'undefined', evaluate: () => undefined, summarize: () => ({ status: 'UNAVAILABLE' }) },
      { id: 'throws', evaluate: () => { throw new Error('PRIVATE-ERROR') }, summarize: mustNotSummarize },
      { id: 'summary-throws', evaluate: () => 'annotation', summarize: () => { throw new Error('PRIVATE-SUMMARY') } }
    )
    await handleRequest(request(passing()), enabledEnv())
    expect(event().validation).toBe('PASS')
    expect(event().plugins).toEqual({
      skipped: { status: 'NOT_CHECKED' },
      undefined: { status: 'UNAVAILABLE' },
      throws: { status: 'ERROR' },
      'summary-throws': { status: 'SUMMARY_ERROR' }
    })
    expect(mustNotSummarize).not.toHaveBeenCalled()
    expect(JSON.stringify(logSpy.mock.calls)).not.toContain('PRIVATE')
  })

  it('records timeout once and ignores late plugin settlement', async () => {
    vi.useFakeTimers()
    let settle
    const summarize = vi.fn()
    plugins.push({ id: 'slow', evaluate: () => new Promise(resolve => { settle = resolve }), summarize })
    const pending = handleRequest(request(passing()), enabledEnv())
    await vi.advanceTimersByTimeAsync(PLUGIN_EVALUATION_TIMEOUT_MS)
    expect((await pending).status).toBe(201)
    expect(event().plugins.slow).toEqual({ status: 'TIMEOUT' })
    settle({ secret: 'late-secret' })
    await vi.advanceTimersByTimeAsync(0)
    expect(summarize).not.toHaveBeenCalled()
    expect(writeDataPoint).toHaveBeenCalledTimes(1)
  })

  it('isolates an observer that throws and still runs subsequent plugins', async () => {
    plugins.push({ id: 'one', evaluate: () => 1 }, { id: 'two', evaluate: () => 2 })
    const out = {}
    await runPlugins({}, {}, out, () => { throw new Error('observer failed') })
    expect(out).toEqual({ one: 1, two: 2 })
  })

  it('preserves the leading ARC outcome', () => {
    const properties = Object.freeze(['fail', 'rooted'])
    expect(arcPlugin.summarize(properties)).toEqual({ status: 'DECODED', properties })
  })
})

describe('summary bounds and safe core fallbacks', () => {
  const collect = (value) => {
    const plugin = { id: 'bounded', summarize: () => value }
    plugins.push(plugin)
    const analytics = createAnalytics(enabledEnv())
    analytics.observePlugin(plugin, {}, null)
    analytics.emit()
    return event().plugins.bounded
  }

  it('accepts bounded plain JSON and null-prototype objects', () => {
    const value = Object.assign(Object.create(null), { status: 'DONE', flags: [null, true, false, 0, 1.5, 'label'], nested: { count: 1 } })
    expect(collect(value)).toEqual(value)
  })

  it.each([
    null, false, 1, 'scalar', [], undefined, { field: undefined }, { field: 1n }, { field: NaN },
    { field: Infinity }, { field: () => 'secret' }, new Date(), { field: Symbol('private') },
    { labels: Array(65).fill('label') }, { long: 'é'.repeat(2049) },
    { a: 'a'.repeat(2500), b: 'b'.repeat(2500) },
    { a: { b: { c: { d: { e: 'too deep' } } } } },
    JSON.parse('{"__proto__":{"secret":"private"}}'),
    { constructor: 'private' }, { prototype: 'private' }, { toJSON: () => 'private' }
  ])('rejects unsupported or oversized summary %#', (value) => {
    expect(collect(value)).toEqual({ status: 'SUMMARY_ERROR' })
  })

  it('rejects symbols, accessors and cycles without invoking getters', () => {
    const getter = vi.fn(() => 'private')
    const value = Object.defineProperty({}, 'field', { get: getter, enumerable: true })
    expect(collect(value)).toEqual({ status: 'SUMMARY_ERROR' })
    expect(getter).not.toHaveBeenCalled()
    expect(collect({ [Symbol('hidden')]: 'private' })).toEqual({ status: 'SUMMARY_ERROR' })
    const cycle = {}; cycle.self = cycle
    expect(collect(cycle)).toEqual({ status: 'SUMMARY_ERROR' })
  })

  it('rejects asynchronous summaries and absorbs their rejection', async () => {
    expect(collect(Promise.reject(new Error('private asynchronous failure')))).toEqual({ status: 'SUMMARY_ERROR' })
    await Promise.resolve()
  })

  it('bounds the combined plugin payload', () => {
    plugins.push(...Array.from({ length: 8 }, (_, i) => ({ id: `plugin-${i}`, summarize: () => ({ text: 'x'.repeat(4000) }) })))
    const analytics = createAnalytics(enabledEnv())
    for (const plugin of plugins) analytics.observePlugin(plugin, null, null)
    analytics.emit()
    expect(Buffer.byteLength(JSON.stringify(event().plugins))).toBeLessThanOrEqual(16384)
    expect(event().plugins['plugin-7']).toEqual({ status: 'SUMMARY_ERROR' })
  })

  it('bounds NOT_CHECKED entries and omits a replacement that cannot fit', () => {
    // Exactly fill the combined budget with two initial entries.
    plugins.push({ id: 'a'.repeat(8000), summarize: () => ({ text: 'x'.repeat(4000) }) },
      { id: 'b'.repeat(8327), summarize: () => ({ text: 'x'.repeat(4000) }) },
      { id: 'omitted', summarize: () => ({ status: 'DONE' }) })
    const analytics = createAnalytics(enabledEnv())
    for (const plugin of plugins) analytics.observePlugin(plugin, null, null)
    analytics.emit()
    expect(Buffer.byteLength(JSON.stringify(event().plugins))).toBeLessThanOrEqual(16384)
    expect(event().plugins).not.toHaveProperty('omitted')
  })

  it.each([
    [{ tokenResult: 'PASS' }, 'NOT_CHECKED', 'UNAVAILABLE'],
    [{ tokenResult: 'FAIL' }, 'NOT_CHECKED', 'UNAVAILABLE'],
    [{ tokenResult: 'ERROR', tokenVerification: { status: 'PASS' } }, 'VERIFIED', 'PASS'],
    [{ tokenResult: 'EXPIRED' }, 'EXPIRED', 'UNAVAILABLE'],
    [{ tokenResult: 'EMPTY_HEADER' }, 'NOT_CHECKED', 'UNAVAILABLE'],
    [{ tokenResult: 'NOT_CHECKED' }, 'NOT_CHECKED', 'UNAVAILABLE'],
    [{ tokenResult: 'INVALID_ALG' }, 'INVALID_ALG', 'UNAVAILABLE'],
    [{ tokenResult: 'INVALID_AUD' }, 'INVALID_AUD', 'UNAVAILABLE'],
    [{ tokenResult: 'private-unknown-status', bindingResult: 'private', messageSigningResult: 'private' }, 'NOT_CHECKED', 'UNAVAILABLE']
  ])('maps core result %# without exposing unknown values', (result, verification, attestation) => {
    const analytics = createAnalytics(enabledEnv())
    analytics.configure({ isValid: true, approovTokenHeaderName: 'Approov-Token' }, request('present'))
    analytics.evaluated(result, 'failure', false)
    analytics.emit()
    expect(event()).toMatchObject({ token: { verification }, attestation })
    expect(JSON.stringify(event())).not.toContain('private')
  })

  it('records an evaluation exception with no result', () => {
    const analytics = createAnalytics(enabledEnv())
    analytics.evaluated(null, 'evaluation error', true)
    analytics.emit()
    expect(event().validation).toBe('ERROR')
  })

  it('distinguishes message-signature evaluation errors from failed checks', () => {
    const analytics = createAnalytics(enabledEnv())
    analytics.evaluated({ tokenResult: 'PASS', tokenVerification: { status: 'PASS' }, messageSigningResult: 'ERROR' }, 'messageSigningResult: ERROR', false)
    analytics.emit()
    expect(event()).toMatchObject({ token: { verification: 'VERIFIED' }, attestation: 'PASS', messageSignature: { status: 'ERROR' }, validation: 'ERROR' })
  })
})

describe('log privacy', () => {
  it.each(['true', 'false'])('excludes sensitive fixture values with analytics %s and debug enabled', async (analyticsEnabled) => {
    plugins.push(arcPlugin, samplePlugin, { id: 'throws', evaluate: () => { throw new Error('PRIVATE-EXCEPTION') }, summarize: () => ({ status: 'DONE' }) })
    const credential = 'PRIVATE-CREDENTIAL'
    const token = signEs256(PASS_PRIVATE_KEY, {
      exp: FUTURE_EXP,
      arc: 'PRIVATE-ENCODED-ARC',
      did: 'PRIVATE-DEVICE',
      customClaim: 'PRIVATE-CLAIM',
      pay: sha256Base64(credential),
      mskid: 'PRIVATE-MSKID'
    })
    fetch.mockResolvedValue(new Response('PRIVATE-BODY', { statusText: 'PRIVATE-STATUS-TEXT' }))
    await handleRequest(new Request('https://worker.local/PRIVATE-PATH?secret=PRIVATE-QUERY', {
      headers: { 'X-Custom-Token': token, 'X-Custom-Binding': credential, 'Approov-TraceID': 'PRIVATE-TRACE-ID', Authorization: credential, Cookie: 'PRIVATE-COOKIE' }
    }), enabledEnv({
      APPROOV_ANALYTICS_ENABLED: analyticsEnabled,
      APPROOV_DEBUG: 'true',
      APPROOV_TOKEN_HEADER_NAME: 'X-Custom-Token',
      APPROOV_TOKEN_BINDING_HEADER_NAME: 'X-Custom-Binding',
      APPROOV_TOKEN_BINDING_ENABLED: 'true',
      APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET: 'PRIVATE-ACCOUNT-SECRET'
    }))
    const logs = JSON.stringify(logSpies.flatMap(spy => spy.mock.calls))
    expect(logs).not.toContain('PRIVATE-')
    expect(logs).not.toContain(token)
    expect(logs).not.toContain(sha256Base64(credential))
  })

  it('does not log request-controlled JWT decode or audience error messages', async () => {
    vi.spyOn(jwt, 'decode').mockImplementationOnce(() => { throw new Error('PRIVATE-DECODE') })
    await handleRequest(request('raw-private-token'), enabledEnv({ APPROOV_DEBUG: 'true' }))
    await handleRequest(request(passing()), enabledEnv({ APPROOV_TOKEN_AUDIENCE: 'PRIVATE-AUDIENCE', APPROOV_DEBUG: 'true' }))
    const logs = JSON.stringify(logSpies.flatMap(spy => spy.mock.calls))
    expect(logs).not.toContain('PRIVATE-')
  })
})

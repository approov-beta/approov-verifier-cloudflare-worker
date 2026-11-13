import { afterEach, describe, expect, it, vi } from 'vitest'
import { handleRequest } from '../src/worker/handle-request.js'
import { EXPIRED_EXP, FAIL_PRIVATE_KEY, FUTURE_EXP, PASS_PRIVATE_KEY, makeEnv, signEs256 } from './fixtures.js'

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

describe('backend enforcement before shared cache responses', () => {
  it.each([
    ['missing', null],
    ['expired', () => signEs256(PASS_PRIVATE_KEY, { exp: EXPIRED_EXP })],
    ['fail', () => signEs256(FAIL_PRIVATE_KEY, { exp: FUTURE_EXP })]
  ])('bypasses an existing protected cache entry for a %s token', async (_name, token) => {
    const origin = vi.fn(request => {
      const result = JSON.parse(Buffer.from(request.headers.get('Approov-Result'), 'base64').toString())
      const allowed = result.tokenResult === 'PASS' &&
        ['VALID', 'DISABLED'].includes(result.bindingResult) &&
        ['VALID', 'NOT_REQUIRED'].includes(result.messageSigningResult)
      return new Response(allowed ? 'fresh protected asset' : 'Forbidden', {
        status: allowed ? 200 : 403,
        headers: { 'Cache-Control': 'public, max-age=600' }
      })
    })
    // Model an entry left by an earlier valid request. The runtime cache mode
    // must bypass both this existing entry and storage of the new response.
    const cache = new Map([['https://upstream.example.com/protected.png', 'previous protected asset']])
    const outbound = vi.fn(request => {
      if (request.cache !== 'no-store' && cache.has(request.url)) {
        return new Response(cache.get(request.url), { headers: { 'CF-Cache-Status': 'HIT' } })
      }
      return origin(request)
    })
    vi.stubGlobal('fetch', outbound)
    const env = makeEnv()
    const passing = signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP })
    const goodResponse = await handleRequest(new Request('https://worker.local/protected.png', {
      headers: { 'Approov-Token': passing }
    }), env)
    expect(goodResponse.status).toBe(200)
    expect(await goodResponse.text()).toBe('fresh protected asset')

    const headers = token === null ? {} : { 'Approov-Token': token() }
    const denied = await handleRequest(new Request('https://worker.local/protected.png', { headers }), env)
    expect(denied.status).toBe(403)
    expect(await denied.text()).toBe('Forbidden')
    expect(origin).toHaveBeenCalledTimes(2)
    expect(outbound.mock.calls.every(([request]) => request.cache === 'no-store')).toBe(true)
  })

  it('keeps block-mode rejection ahead of any cache or origin call', async () => {
    const outbound = vi.fn()
    vi.stubGlobal('fetch', outbound)
    const response = await handleRequest(new Request('https://worker.local/protected.png'), makeEnv({ APPROOV_MODE: 'block' }))
    expect(response.status).toBe(403)
    expect(outbound).not.toHaveBeenCalled()
  })
})

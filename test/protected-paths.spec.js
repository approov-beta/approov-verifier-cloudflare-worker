/**
 * APPROOV_PROTECTED_PATHS scoping.
 *
 * Unset, every request is checked. Set, only matching paths are checked and
 * every other path is forwarded unchecked and unannotated, with any
 * client-supplied Approov-Result still stripped.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { makeEnv } from './fixtures.js'

vi.mock('../src/approov/evaluate.js', () => ({
  evaluateApproovToken: vi.fn()
}))

const { evaluateApproovToken } = await import('../src/approov/evaluate.js')
const { handleRequest } = await import('../src/worker/handle-request.js')
const { establishContext } = await import('../src/config/context.js')
const { isProtectedPath } = await import('../src/config/protected-paths.js')

const failingResult = {
  tokenResult: 'FAIL',
  bindingResult: 'DISABLED',
  messageSigningResult: 'NOT_REQUIRED'
}

const contextFor = (patterns) => establishContext(makeEnv({ APPROOV_PROTECTED_PATHS: patterns }))

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  vi.clearAllMocks()
})

describe('protected path patterns', () => {
  it('protects every path when the setting is unset or blank', () => {
    expect(isProtectedPath(establishContext(makeEnv()), '/anything/at/all')).toBe(true)
    expect(isProtectedPath(contextFor('  '), '/anything/at/all')).toBe(true)
  })

  it('covers every market with one "*" per segment', () => {
    const ctx = contextFor('/shop/*/*/checkout, /customer/v*/carts')
    expect(ctx.isValid).toBe(true)
    for (const path of [
      '/shop/de/v6/checkout',
      '/shop/it/v6/checkout',
      '/shop/gb/v7/checkout/payment',
      '/SHOP/fr/v6/checkout',
      '//shop/se/v6//checkout',
      '/shop/%64e/v6/checkout',
      '/customer/v6/carts',
      '/customer/v10/carts/items'
    ]) {
      expect(isProtectedPath(ctx, path), path).toBe(true)
    }
  })

  it('never lets "*" cross a "/", match an empty segment, or extend the last segment', () => {
    const ctx = contextFor('/shop/*/*/checkout, /customer/v*/carts')
    for (const path of [
      '/shop/de/checkout',
      '/shop/de/v6/extra/checkout',
      '/shop/de/v6/checkouts',
      '/shop/de/v6/check',
      '/customer/carts',
      '/customer/x/v6/carts',
      '/other/de/v6/checkout'
    ]) {
      expect(isProtectedPath(ctx, path), path).toBe(false)
    }
  })

  it('treats every character other than "*" literally', () => {
    const ctx = contextFor('/api.v1/*/pay(now)')
    expect(isProtectedPath(ctx, '/api.v1/de/pay(now)')).toBe(true)
    expect(isProtectedPath(ctx, '/apixv1/de/pay(now)')).toBe(false)
    expect(isProtectedPath(ctx, '/api.v1/de/paynow')).toBe(false)
  })

  it('rejects an entry without a leading "/" instead of leaving it silently unprotected', () => {
    const ctx = contextFor('/shop/*/*/checkout, shop/*/*/cart')
    expect(ctx.isValid).toBe(false)
    expect(ctx.errors).toContain('env.APPROOV_PROTECTED_PATHS entries must start with "/"')
  })

  it('covers a path and everything below it with a bare prefix, and only what is below it with "/*"', () => {
    const prefix = contextFor('/api')
    expect(isProtectedPath(prefix, '/api')).toBe(true)
    expect(isProtectedPath(prefix, '/api/')).toBe(true)
    expect(isProtectedPath(prefix, '/api/users/1')).toBe(true)
    expect(isProtectedPath(prefix, '/apiary')).toBe(false)

    const below = contextFor('/api/*')
    expect(isProtectedPath(below, '/api/users')).toBe(true)
    expect(isProtectedPath(below, '/api/users/1')).toBe(true)
    expect(isProtectedPath(below, '/api')).toBe(false)
  })

  it('checks alternate spellings that origins commonly route to the protected path', () => {
    const ctx = contextFor('/shop/*/*/checkout')
    for (const path of [
      '/shop/de/v6/checkout;jsessionid=1',
      '/shop;a=b/de/v6/checkout',
      '/shop/de/v6/checkout%3Bx=1',
      '/shop/de/v6/checkout.json',
      '/shop/de/v6/checkout%20',
      '/shop/de/v6/checkout%00',
      '/shop%5Cde%5Cv6%5Ccheckout'
    ]) {
      expect(isProtectedPath(ctx, path), path).toBe(true)
    }
    expect(isProtectedPath(ctx, '/shop/de/v6/checkout-old')).toBe(false)
  })

  it.each(['/api/', '/', '/shop/*/'])('rejects the trailing-slash entry %s, which would protect nothing below it', (entry) => {
    const ctx = contextFor(`/shop/*/*/checkout, ${entry}`)
    expect(ctx.isValid).toBe(false)
    expect(ctx.errors.some((error) => error.startsWith('env.APPROOV_PROTECTED_PATHS entries must not end with "/"'))).toBe(true)
  })
})

describe('handleRequest with APPROOV_PROTECTED_PATHS', () => {
  it('checks and blocks a matching path in block mode', async () => {
    const fetchMock = vi.fn(async () => new Response('ok', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    evaluateApproovToken.mockResolvedValue(failingResult)

    const response = await handleRequest(
      new Request('http://worker.local/shop/de/v6/checkout', { method: 'POST' }),
      makeEnv({ APPROOV_MODE: 'block', APPROOV_PROTECTED_PATHS: '/shop/*/*/checkout' })
    )

    expect(response.status).toBe(403)
    expect(evaluateApproovToken).toHaveBeenCalledTimes(1)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('forwards a non-matching path unchecked in block mode', async () => {
    const fetchMock = vi.fn(async () => new Response('ok', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    evaluateApproovToken.mockResolvedValue(failingResult)

    const response = await handleRequest(
      new Request('http://worker.local/shop/de/v6/products'),
      makeEnv({ APPROOV_MODE: 'block', APPROOV_PROTECTED_PATHS: '/shop/*/*/checkout' })
    )

    expect(response.status).toBe(200)
    expect(evaluateApproovToken).not.toHaveBeenCalled()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('forwards a non-matching path unannotated and strips a forged Approov-Result in annotate mode', async () => {
    const fetchMock = vi.fn(async () => new Response('ok', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    await handleRequest(
      new Request('http://worker.local/shop/de/v6/products', {
        headers: { 'Approov-Result': 'forged-by-client' }
      }),
      makeEnv({ APPROOV_PROTECTED_PATHS: '/shop/*/*/checkout' })
    )

    expect(evaluateApproovToken).not.toHaveBeenCalled()
    const forwarded = fetchMock.mock.calls[0][0]
    expect(forwarded.headers.get('Approov-Result')).toBeNull()
  })

  it('records the unchecked forward as its own analytics action', async () => {
    const fetchMock = vi.fn(async () => new Response('ok', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    const writeDataPoint = vi.fn()

    await handleRequest(
      new Request('http://worker.local/shop/de/v6/products'),
      makeEnv({
        APPROOV_PROTECTED_PATHS: '/shop/*/*/checkout',
        APPROOV_ANALYTICS_ENABLED: 'true',
        APPROOV_ANALYTICS: { writeDataPoint }
      })
    )

    const blobs = writeDataPoint.mock.calls[0][0].blobs
    expect(blobs[2]).toBe('unprotected')
    expect(blobs[9]).toBe('NOT_EVALUATED')
  })
})

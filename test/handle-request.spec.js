/**
 * Fail-closed behaviour of the request handler.
 *
 * The token evaluation step is mocked to throw so we can exercise the top-level
 * catch in handleRequest: an unexpected error must never be treated as a passing
 * validation. Blocking actions reject it; annotation mode forwards it with a
 * minimal ERROR result.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { makeEnv } from './fixtures.js'

vi.mock('../src/approov/evaluate.js', () => ({
  evaluateApproovToken: vi.fn()
}))

const { evaluateApproovToken } = await import('../src/approov/evaluate.js')
const { handleRequest } = await import('../src/worker/handle-request.js')

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  vi.clearAllMocks()
})

describe('handleRequest fail-closed behaviour', () => {
  it('returns 500 and logs which hostname has no usable Approov policy', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    const response = await handleRequest(new Request('http://unregistered.example/x'), makeEnv())

    expect(response.status).toBe(500)
    expect(fetchMock).not.toHaveBeenCalled()
    expect(errors).toHaveBeenCalledWith('approov: unable to resolve incoming API policy', {
      reason: 'incoming API domain "unregistered.example" is not present in APPROOV_BACKEND_CONFIG.apis'
    })
  })

  it('uses the configured block response when evaluation throws in block mode', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(console, 'log').mockImplementation(() => {})
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    evaluateApproovToken.mockRejectedValue(new Error('evaluation blew up'))

    const response = await handleRequest(
      new Request('http://worker.local/x'),
      makeEnv({ APPROOV_MODE: 'block', APPROOV_BLOCK_RESPONSE_STATUS: '418' })
    )

    expect(response.status).toBe(418)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('forwards an ERROR annotation when evaluation throws in annotate mode', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const fetchMock = vi.fn(async () => new Response('ok', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    // A non-Error throw also confirms the error-message normalization path.
    evaluateApproovToken.mockRejectedValue('a non-error throw value')

    const response = await handleRequest(new Request('http://worker.local/x'), makeEnv())

    expect(response.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const forwarded = fetchMock.mock.calls[0][0]
    expect(JSON.parse(Buffer.from(forwarded.headers.get('Approov-Result'), 'base64').toString()).tokenResult).toBe('ERROR')
  })

  it('forwards a minimal ERROR annotation when result serialization fails', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const fetchMock = vi.fn(async () => new Response('ok', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    // An unserializable plugin field must not prevent the ERROR fallback.
    evaluateApproovToken.mockResolvedValue({
      tokenResult: 'FAIL',
      bindingResult: 'NOT_CHECKED',
      messageSigningResult: 'NOT_CHECKED',
      unserializable: 1n
    })

    const response = await handleRequest(new Request('http://worker.local/x'), makeEnv())

    expect(response.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const forwarded = fetchMock.mock.calls[0][0]
    expect(JSON.parse(Buffer.from(forwarded.headers.get('Approov-Result'), 'base64').toString()).tokenResult).toBe('ERROR')
  })
})

describe('handleRequest Approov-Result spoofing protection', () => {
  const passingResult = {
    tokenResult: 'PASS',
    bindingResult: 'DISABLED',
    messageSigningResult: 'NOT_REQUIRED'
  }

  it('strips a client-supplied Approov-Result header when annotation is disabled', async () => {
    const fetchMock = vi.fn(async () => new Response('ok', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    evaluateApproovToken.mockResolvedValue(passingResult)

    await handleRequest(
      new Request('http://worker.local/x', {
        headers: { 'Approov-Result': 'forged-by-client' }
      }),
      makeEnv({ APPROOV_MODE: 'block' })
    )

    const forwarded = fetchMock.mock.calls[0][0]
    expect(forwarded.headers.get('Approov-Result')).toBeNull()
  })

  it('strips a client-supplied Approov-Result header when a failed request is forwarded unannotated', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const fetchMock = vi.fn(async () => new Response('ok', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    evaluateApproovToken.mockRejectedValue(new Error('evaluation blew up'))

    await handleRequest(
      new Request('http://worker.local/x', {
        headers: { 'Approov-Result': 'forged-by-client' }
      }),
      makeEnv({ APPROOV_MODE: 'block', APPROOV_TOKEN_ACTION: 'continue', APPROOV_MESSAGE_SIGNING_ACTION: 'continue' })
    )

    const forwarded = fetchMock.mock.calls[0][0]
    expect(forwarded.headers.get('Approov-Result')).toBeNull()
  })

  it('replaces (never merges with) a client-supplied Approov-Result header when annotating', async () => {
    const fetchMock = vi.fn(async () => new Response('ok', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    evaluateApproovToken.mockResolvedValue(passingResult)

    await handleRequest(
      new Request('http://worker.local/x', {
        headers: { 'Approov-Result': 'forged-by-client' }
      }),
      makeEnv()
    )

    const forwarded = fetchMock.mock.calls[0][0]
    const header = forwarded.headers.get('Approov-Result')
    expect(header).not.toContain('forged-by-client')
    const decoded = JSON.parse(Buffer.from(header, 'base64').toString('utf8'))
    expect(decoded.tokenResult).toBe('PASS')
  })
})

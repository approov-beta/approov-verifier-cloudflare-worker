import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { handleRequest } from '../src/worker/handle-request.js'
import { parseClientStatus } from '../src/approov/client-status.js'
import { FUTURE_EXP, PASS_PRIVATE_KEY, makeEnv, signEs256 } from './fixtures.js'

let logSpy
const events = () => logSpy.mock.calls.map(([entry]) => entry).filter(entry => entry?.event === 'approov.request')

beforeEach(() => {
  logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.stubGlobal('fetch', vi.fn(async () => new Response('upstream')))
})
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('client token-fetch status', () => {
  it.each(['no_network', 'poor_network', 'untrusted_network', 'rejected', 'success'])('records %s without accepting a missing token', async status => {
    const response = await handleRequest(new Request('https://worker.local/api', {
      headers: { 'Approov-Status': status }
    }), makeEnv({ APPROOV_MODE: 'block', APPROOV_LOGGING_ENABLED: 'true' }))

    expect(response.status).toBe(403)
    expect(fetch).not.toHaveBeenCalled()
    expect(events()).toHaveLength(1)
    expect(events()[0]).toMatchObject({
      clientStatus: status,
      token: { presence: 'MISSING', verification: 'NOT_CHECKED' },
      attestation: 'UNAVAILABLE',
      action: 'block'
    })
  })

  it('reports the status in the annotation while preserving empty-token rejection', async () => {
    const response = await handleRequest(new Request('https://worker.local/api', {
      headers: { 'Approov-Status': 'no_approov_service', 'Approov-Token': '' }
    }), makeEnv({ APPROOV_ECHO_MODE: 'true' }))
    const echo = await response.json()
    const result = JSON.parse(Buffer.from(echo.headers['approov-result'], 'base64').toString())
    expect(result).toMatchObject({ tokenResult: 'EMPTY_HEADER', clientStatus: 'no_approov_service' })

    const rejected = await handleRequest(new Request('https://worker.local/api', {
      headers: { 'Approov-Status': 'success', 'Approov-Token': '' }
    }), makeEnv({ APPROOV_MODE: 'block' }))
    expect(rejected.status).toBe(403)
    expect(fetch).not.toHaveBeenCalled()
  })

  it('uses the configured status header, with case-insensitive header names', async () => {
    await handleRequest(new Request('https://worker.local/api', {
      headers: { 'x-client-status': 'no_network', 'Approov-Status': 'success' }
    }), makeEnv({ APPROOV_MODE: 'block', APPROOV_LOGGING_ENABLED: 'true', APPROOV_STATUS_HEADER_NAME: 'X-Client-Status' }))
    expect(events()[0]).toMatchObject({ clientStatus: 'no_network', action: 'block' })
  })

  it.each([['', 'invalid'], ['SUCCESS', 'invalid'], ['no_network, success', 'invalid'],
    ['PRIVATE-HEADER', 'invalid'], ['x'.repeat(10000), 'invalid'], [null, null]])('filters an untrusted status %#', async (value, expected) => {
    const headers = value === null ? {} : { 'Approov-Status': value }
    await handleRequest(new Request('https://worker.local/api', { headers }), makeEnv({ APPROOV_MODE: 'block', APPROOV_LOGGING_ENABLED: 'true' }))
    expect(events()[0].clientStatus).toBe(expected)
    expect(JSON.stringify(logSpy.mock.calls)).not.toContain('PRIVATE-HEADER')
  })

  it('does not let a reported failure override a verified token', async () => {
    await handleRequest(new Request('https://worker.local/api', {
      headers: { 'Approov-Status': 'no_network', 'Approov-Token': signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP }) }
    }), makeEnv({ APPROOV_MODE: 'block', APPROOV_LOGGING_ENABLED: 'true' }))
    expect(events()[0]).toMatchObject({ clientStatus: 'no_network', attestation: 'PASS', action: 'forward' })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it.each(['success\r\nPRIVATE-HEADER', 'no_network\tPRIVATE-HEADER', 'réjected', 'future_status'])('does not report unknown or control-character data %#', value => {
    expect(parseClientStatus(value)).toBe('invalid')
  })

  it('reports the diagnostic in Analytics Engine without requiring console logging', async () => {
    const writeDataPoint = vi.fn()
    await handleRequest(new Request('https://worker.local/api', { headers: { 'Approov-Status': 'no_network' } }),
      makeEnv({ APPROOV_MODE: 'block', APPROOV_ANALYTICS_ENABLED: 'true', APPROOV_ANALYTICS: { writeDataPoint } }))
    expect(events()).toEqual([])
    expect(writeDataPoint.mock.calls[0][0].blobs).toEqual([
      '3', 'block', 'block', 'MISSING', 'NOT_CHECKED', 'UNAVAILABLE', 'DISABLED', 'unknown', 'NOT_CHECKED', 'FAIL', 'no_network'
    ])
  })
})

import { afterEach, describe, expect, it, vi } from 'vitest'
import { establishContext } from '../src/config/context.js'
import { FUTURE_EXP, PASS_PRIVATE_KEY, makeEnv, signEs256 } from './fixtures.js'

vi.mock('../src/approov/message-signing.js', async importOriginal => {
  const actual = await importOriginal()
  return {
    ...actual,
    getMessageSigningMode: vi.fn(actual.getMessageSigningMode),
    validateMessageSignatures: vi.fn(actual.validateMessageSignatures)
  }
})
const { getMessageSigningMode, validateMessageSignatures } = await import('../src/approov/message-signing.js')
const { evaluateApproovToken } = await import('../src/approov/evaluate.js')
afterEach(() => vi.restoreAllMocks())

describe('message signing errors preserve completed token verification', () => {
  it.each(['selection', 'verification', 'returned-error'])('isolates %s errors', async stage => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
    if (stage === 'selection') getMessageSigningMode.mockImplementationOnce(() => { throw new Error('PRIVATE-SELECTION') })
    if (stage === 'verification') validateMessageSignatures.mockRejectedValueOnce(new Error('PRIVATE-VERIFICATION'))
    if (stage === 'returned-error') validateMessageSignatures.mockResolvedValueOnce({ status: 'ERROR' })
    const result = await evaluateApproovToken(establishContext(makeEnv()), new Request('https://worker.local/api', {
      headers: { 'Approov-Token': signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP }) }
    }))
    expect(result.tokenResult).toBe('PASS')
    expect(result.tokenVerification.status).toBe('PASS')
    expect(result.messageSigningResult).toBe('ERROR')
    expect(JSON.stringify(result)).not.toContain('PRIVATE')
    expect(errors).toHaveBeenCalledWith(
      'approov: message signing verification error',
      stage === 'returned-error' ? { status: 'ERROR' } : { status: 'ERROR', error: 'Error' }
    )
  })
})

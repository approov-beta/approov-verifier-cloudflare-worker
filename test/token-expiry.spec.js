/**
 * A verified token must carry an expiry.
 *
 * jsonwebtoken checks `exp` only when the claim is present, so the verifier
 * itself rejects a correctly signed token that could otherwise never expire.
 */
import { describe, expect, it } from 'vitest'
import { establishContext } from '../src/config/context.js'
import { evaluateApproovToken } from '../src/approov/evaluate.js'
import { FAIL_PRIVATE_KEY, FUTURE_EXP, PASS_PRIVATE_KEY, makeEnv, signEs256 } from './fixtures.js'

const evaluate = (token) => evaluateApproovToken(
  establishContext(makeEnv()),
  new Request('https://worker.local/api', { headers: { 'Approov-Token': token } })
)

describe('token expiry requirement', () => {
  it.each([
    ['pass', PASS_PRIVATE_KEY],
    ['fail', FAIL_PRIVATE_KEY]
  ])('reports MALFORMED for a %s-key token without an exp claim', async (_name, key) => {
    const result = await evaluate(signEs256(key))
    expect(result.tokenResult).toBe('MALFORMED')
    expect(result.tokenVerification.decoded).toBeNull()
    expect(result.messageSigningResult).toBe('NOT_CHECKED')
  })

  it('still accepts a token with a future exp claim', async () => {
    expect((await evaluate(signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP }))).tokenResult).toBe('PASS')
  })
})

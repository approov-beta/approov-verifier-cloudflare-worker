import crypto from 'node:crypto'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { establishContext } from '../src/config/context.js'
import { evaluateApproovToken } from '../src/approov/evaluate.js'
import { validateMessageSignatures } from '../src/approov/message-signing.js'
import { handleRequest } from '../src/worker/handle-request.js'
import { createSigner, httpbis } from '../src/vendor/http-message-signatures.js'
import {
  ACCOUNT_DEVICE_ID,
  ACCOUNT_SIGNING_KEY_ID,
  ACCOUNT_SIGNING_SECRET_BASE64URL,
  ACCOUNT_SIGNING_SECRET_RAW,
  EXPIRED_EXP,
  FAIL_PRIVATE_KEY,
  FUTURE_EXP,
  PASS_PRIVATE_KEY,
  signEs256,
  makeEnv
} from './fixtures.js'

const url = 'https://worker.local/account?amount=1'
const otherDevice = Buffer.from('another-deviceID').toString('base64')
const fallbackDevice = '+++UnknownDeviceID+++w=='
const accountSecret = Buffer.from(ACCOUNT_SIGNING_SECRET_RAW, 'utf8')
// Independent Python hashlib/hmac vector for bytes 00..0f and this fixture secret.
const expectedDeviceKey = Buffer.from('4d8a2daffff25b86312c125a6dedac7fbfe7799289e1baae389be4bfd7b82ae4f762d21ed5af09f43cb23ac1f524561b25addc904fb94a8cb8bde8d9db27c474', 'hex')
const installation = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const ipk = installation.publicKey.export({ type: 'spki', format: 'pem' }).toString()
const env = makeEnv({
  APPROOV_MODE: 'block',
  APPROOV_TOKEN_ACTION: 'block',
  APPROOV_MESSAGE_SIGNING_ACTION: 'block',
  APPROOV_ECHO_MODE: true,
  APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET: ACCOUNT_SIGNING_SECRET_BASE64URL,
  APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID: ACCOUNT_SIGNING_KEY_ID
})
const ctx = establishContext(env)
const claims = (overrides = {}) => ({ exp: FUTURE_EXP, did: ACCOUNT_DEVICE_ID, mskid: ACCOUNT_SIGNING_KEY_ID, ...overrides })
const deriveFixtureKey = (did) => crypto.createHmac('sha512', accountSecret).update(Buffer.from(did, 'base64')).digest()

const signedRequest = async ({ token = signEs256(PASS_PRIVATE_KEY, claims()), key = expectedDeviceKey, names = ['account'] } = {}) => {
  const headers = { 'Approov-Token': token }
  for (const name of names) {
    const signed = await httpbis.signMessage({
      name,
      key: createSigner(name === 'account' ? key : installation.privateKey.export({ type: 'pkcs8', format: 'pem' }),
        name === 'account' ? 'hmac-sha256' : 'ecdsa-p256-sha256'),
      fields: ['@method', '@target-uri', 'approov-token']
    }, { url, method: 'GET', headers: { 'Approov-Token': token } })
    for (const header of ['Signature', 'Signature-Input']) {
      headers[header] = headers[header] ? `${headers[header]}, ${signed.headers[header]}` : signed.headers[header]
    }
  }
  return new Request(url, { headers })
}
const sha512Calls = (spy) => spy.mock.calls.filter(([algorithm]) => algorithm === 'sha512')
afterEach(() => { vi.restoreAllMocks() })

describe('device-specific account message signing', () => {
  it.each(['account', 'both'])('verifies a device-derived signature in %s mode', async mode => {
    const token = signEs256(PASS_PRIVATE_KEY, claims(mode === 'both' ? { ipk } : {}))
    const request = await signedRequest({ token, names: mode === 'both' ? ['install', 'account'] : ['account'] })
    const result = await evaluateApproovToken(ctx, request)
    expect(result).toMatchObject({ tokenResult: 'PASS', messageSigningMode: mode === 'both' ? 'either' : mode, messageSigningResult: 'VALID' })
    expect(result.messageSigningVerification.signatures.account.status).toBe('VALID')
    expect((await handleRequest(request, env)).status).toBe(200)
  })

  it.each(['account', 'both'])('rejects raw account-secret signatures without fallback in %s mode', async mode => {
    const token = signEs256(PASS_PRIVATE_KEY, claims(mode === 'both' ? { ipk } : {}))
    const request = await signedRequest({ token, key: accountSecret, names: mode === 'both' ? ['install', 'account'] : ['account'] })
    const result = await evaluateApproovToken(ctx, request)
    expect(result.tokenResult).toBe('PASS')
    expect(result.messageSigningVerification.signatures.account.status).toBe('INVALID')
    if (mode === 'both') expect(result.messageSigningVerification.signatures.install.status).toBe('VALID')
    expect((await handleRequest(request, env)).status).toBe(403)
  })

  it('accepts reordered install/account dictionary members', async () => {
    const token = signEs256(PASS_PRIVATE_KEY, claims({ ipk }))
    const request = await signedRequest({ token, names: ['account', 'install'] })
    expect((await handleRequest(request, env)).status).toBe(200)
  })

  it.each([ACCOUNT_DEVICE_ID, fallbackDevice])('derives the exact authenticated device bytes (%s)', async did => {
    const token = signEs256(PASS_PRIVATE_KEY, claims({ did }))
    const request = await signedRequest({ token, key: deriveFixtureKey(did) })
    expect((await handleRequest(request, env)).status).toBe(200)
  })

  it.each([otherDevice, fallbackDevice])('rejects a signature made with another device key (%s)', async did => {
    const request = await signedRequest({ key: deriveFixtureKey(did) })
    expect((await evaluateApproovToken(ctx, request)).messageSigningResult).toBe('INVALID')
    expect((await handleRequest(request, env)).status).toBe(403)
  })

  it('rejects a valid token for a different did even when the signature covers that token', async () => {
    const token = signEs256(PASS_PRIVATE_KEY, claims({ did: otherDevice }))
    const request = await signedRequest({ token })
    expect((await evaluateApproovToken(ctx, request)).messageSigningResult).toBe('INVALID')
  })

  it.each([
    ['missing', undefined], ['null', null], ['number', 42], ['boolean', true], ['object', {}], ['array', []],
    ['empty', ''], ['spaces', ' '], ['unpadded', ACCOUNT_DEVICE_ID.slice(0, -2)],
    ['short padding', ACCOUNT_DEVICE_ID.slice(0, -1)], ['excess padding', ACCOUNT_DEVICE_ID + '='],
    ['base64url', '___UnknownDeviceID___w=='], ['nonzero padding bits', ACCOUNT_DEVICE_ID.replace('Dw==', 'Dx==')],
    ['leading whitespace', ' ' + ACCOUNT_DEVICE_ID], ['trailing whitespace', ACCOUNT_DEVICE_ID + ' '],
    ['trailing newline', ACCOUNT_DEVICE_ID + '\n'], ['embedded newline', ACCOUNT_DEVICE_ID.slice(0, 8) + '\n' + ACCOUNT_DEVICE_ID.slice(8)],
    ['invalid alphabet', '!' + ACCOUNT_DEVICE_ID.slice(1)],
    ['15 bytes', Buffer.alloc(15).toString('base64')], ['17 bytes', Buffer.alloc(17).toString('base64')],
    ['oversized', 'A'.repeat(10000)]
  ])('rejects %s did without deriving a key', async (_label, did) => {
    const request = await signedRequest({ token: signEs256(PASS_PRIVATE_KEY, claims({ did })) })
    const hmac = vi.spyOn(crypto, 'createHmac')
    const result = await evaluateApproovToken(ctx, request)
    expect(result.tokenResult).toBe('PASS')
    expect(result.messageSigningResult).toBe('INVALID_DEVICE_ID_CLAIM')
    expect(sha512Calls(hmac)).toHaveLength(0)
    expect((await handleRequest(request, env)).status).toBe(403)
  })

  it('reports an invalid did while still verifying the required installation signature', async () => {
    const token = signEs256(PASS_PRIVATE_KEY, claims({ ipk, did: null }))
    const result = await evaluateApproovToken(ctx, await signedRequest({ token, names: ['install', 'account'] }))
    expect(result.messageSigningResult).toBe('INVALID')
    expect(result.messageSigningVerification.signatures.install.status).toBe('VALID')
    expect(result.messageSigningVerification.signatures.account.status).toBe('INVALID_DEVICE_ID_CLAIM')
  })

  it('does not require did for an installation-only token', async () => {
    const token = signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, ipk })
    const request = await signedRequest({ token, names: ['install'] })
    const hmac = vi.spyOn(crypto, 'createHmac')
    expect((await handleRequest(request, env)).status).toBe(200)
    expect(sha512Calls(hmac)).toHaveLength(0)
  })

  it.each(['missing', 'empty', 'whitespace', 'malformed', 'forged did', 'expired'])('never derives from an unauthenticated %s token', async scenario => {
    const valid = signEs256(PASS_PRIVATE_KEY, claims())
    let token = valid
    if (scenario === 'expired') token = signEs256(PASS_PRIVATE_KEY, claims({ exp: EXPIRED_EXP }))
    if (scenario === 'malformed') token = 'malformed'
    if (scenario === 'forged did') {
      const parts = valid.split('.')
      parts[1] = Buffer.from(JSON.stringify(claims({ did: otherDevice }))).toString('base64url')
      token = parts.join('.')
    }
    const request = await signedRequest({ token })
    if (scenario === 'missing') request.headers.delete('Approov-Token')
    if (scenario === 'empty') request.headers.set('Approov-Token', '')
    if (scenario === 'whitespace') request.headers.set('Approov-Token', ' ')
    const hmac = vi.spyOn(crypto, 'createHmac')
    const result = await evaluateApproovToken(ctx, request)
    expect(result.messageSigningResult).toBe('NOT_CHECKED')
    expect(result.messageSigningVerification).toBeNull()
    expect(sha512Calls(hmac)).toHaveLength(0)
    expect((await handleRequest(request, env)).status).toBe(403)
  })

  it('keeps token-failure enforcement for authenticated FAIL-key tokens', async () => {
    const request = await signedRequest({ token: signEs256(FAIL_PRIVATE_KEY, claims()) })
    const result = await evaluateApproovToken(ctx, request)
    expect(result).toMatchObject({ tokenResult: 'FAIL', messageSigningResult: 'VALID' })
    expect((await handleRequest(request, env)).status).toBe(403)
  })

  it.each(['signature', 'target'])('rejects a tampered %s', async field => {
    const request = await signedRequest()
    if (field === 'signature') request.headers.set('Signature', 'account=:AAAA:')
    const changed = field === 'target' ? new Request(url.replace('amount=1', 'amount=2'), request) : request
    expect((await evaluateApproovToken(ctx, changed)).messageSigningResult).toBe('INVALID')
    expect((await handleRequest(changed, env)).status).toBe(403)
  })

  it('does not expose a derivation error or hide the installation result', async () => {
    const token = signEs256(PASS_PRIVATE_KEY, claims({ ipk }))
    const request = await signedRequest({ token, names: ['install', 'account'] })
    const createHmac = crypto.createHmac
    vi.spyOn(crypto, 'createHmac').mockImplementation((...args) => {
      if (args[0] === 'sha512') throw new Error('PRIVATE-DERIVATION-ERROR')
      return createHmac(...args)
    })
    const result = await validateMessageSignatures(ctx, request, claims({ ipk }))
    expect(result.status).toBe('ERROR')
    expect(result.signatures.account.status).toBe('ERROR')
    expect(result.signatures.install.status).toBe('VALID')
    expect(JSON.stringify(result)).not.toContain('PRIVATE-DERIVATION-ERROR')
  })
})

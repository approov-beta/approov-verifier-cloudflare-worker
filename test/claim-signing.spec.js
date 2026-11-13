import { afterEach, describe, expect, it, vi } from 'vitest'
import crypto from 'node:crypto'
import { createSigner, createVerifier, httpbis } from '../src/vendor/http-message-signatures.js'
import { validateMessageSignatures } from '../src/approov/message-signing.js'
import { establishContext } from '../src/config/context.js'
import { handleRequest } from '../src/worker/handle-request.js'
import { ACCOUNT_DEVICE_ID, FAIL_PRIVATE_KEY, PASS_PRIVATE_KEY, FUTURE_EXP, makeEnv, signEs256, sha256Base64 } from './fixtures.js'

vi.mock('../src/vendor/http-message-signatures.js', async importOriginal => {
  const actual = await importOriginal()
  return { ...actual, createVerifier: vi.fn(actual.createVerifier) }
})

const url = 'https://worker.local/api?amount=1'
const install = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const ipk = install.publicKey.export({ type: 'spki', format: 'pem' }).toString()
const account = Buffer.from('dual-signature-account-secret')
const accountSigningKey = crypto.createHmac('sha512', account).update(Buffer.from(ACCOUNT_DEVICE_ID, 'base64')).digest()
const settings = {
  APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET: account.toString('base64'),
  APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID: 'account-key'
}
const context = establishContext(makeEnv(settings))

const signedHeaders = async (names, token = 'test-token', body) => {
  const headers = { 'Approov-Token': token }
  const fields = ['@method', '@target-uri', 'approov-token']
  if (body !== undefined) {
    headers['Content-Digest'] = `sha-256=:${sha256Base64(body)}:`
    fields.push('content-digest')
  }
  for (const name of names) {
    const signed = await httpbis.signMessage({
      key: createSigner(name === 'install' ? install.privateKey.export({ type: 'pkcs8', format: 'pem' }) : accountSigningKey,
        name === 'install' ? 'ecdsa-p256-sha256' : 'hmac-sha256'),
      name,
      fields
    }, { url, method: body === undefined ? 'GET' : 'POST', headers: { 'Approov-Token': token, ...headers } })
    // Each signature is generated independently over the same request.
    for (const header of ['Signature', 'Signature-Input']) {
      const entry = signed.headers[header].split(', ').find(entry => entry.startsWith(`${name}=`))
      headers[header] = headers[header] ? `${headers[header]}, ${entry}` : entry
    }
  }
  return headers
}
const verify = (payload, headers, ctx = context, body) => validateMessageSignatures(ctx,
  new Request(url, { headers, ...(body === undefined ? {} : { method: 'POST', body }) }), payload)
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('trusted claims supply message-signature keys', () => {
  it.each([
    [{}, [], 'none'], [{ ipk }, ['install'], 'install'],
    [{ did: ACCOUNT_DEVICE_ID, mskid: 'account-key' }, ['account'], 'account'],
    [{ ipk, did: ACCOUNT_DEVICE_ID, mskid: 'account-key' }, ['install', 'account'], 'either']
  ])('verifies the required entries (%j)', async (claims, names, mode) => {
    const result = await verify(claims, await signedHeaders(names))
    expect(result).toMatchObject({ ok: true, mode, status: names.length ? 'VALID' : 'NOT_REQUIRED' })
    for (const name of ['install', 'account']) {
      expect(result.signatures[name]).toEqual(names.includes(name) ? { ok: true, status: 'VALID', error: null } : null)
    }
  })

  it('rejects malformed signature headers even when neither claim exists', async () => {
    const result = await verify({}, { Signature: '@@@', 'Signature-Input': '@@@' }, context, 'unsigned body')
    expect(result.status).toBe('MALFORMED_HEADERS')
  })

  it.each(['install', 'account'])('requires %s when both are explicitly required', async missing => {
    const result = await verify({ ipk, did: ACCOUNT_DEVICE_ID, mskid: 'account-key' }, await signedHeaders([missing === 'install' ? 'account' : 'install']), { ...context, approovMessageSigningRequired: 'both' })
    expect(result.status).toBe('INVALID')
    expect(result.signatures[missing].status).toBe('MISSING_SIGNATURE_ENTRY')
    expect(result.signatures[missing === 'install' ? 'account' : 'install'].status).toBe('VALID')
  })

  it.each(['install', 'account'])('reports an invalid %s without hiding the other result', async bad => {
    const headers = await signedHeaders(['install', 'account'])
    headers.Signature = headers.Signature.replace(new RegExp(`${bad}=:[^:]+:`), `${bad}=:YWJj:`)
    const result = await verify({ ipk, did: ACCOUNT_DEVICE_ID, mskid: 'account-key' }, headers)
    expect(result.status).toBe('INVALID')
    expect(result.signatures[bad].status).toBe('INVALID')
    expect(result.signatures[bad === 'install' ? 'account' : 'install'].status).toBe('VALID')
  })

  it('rejects a present account signature without an account key claim', async () => {
    const headers = await signedHeaders(['install', 'account'])
    headers.Signature = headers.Signature.replace(/account=:[^:]+:/, 'account=:YWJj:')
    const result = await verify({ ipk }, headers)
    expect(result.status).toBe('INVALID')
    expect(result.signatures.account.status).toBe('INVALID_ACCOUNT_KEY_ID_CLAIM')
  })

  it.each([null, '', ' ', 42, {}, []])('does not treat invalid claims as absent (%j)', async value => {
    expect((await verify({ ipk: value }, {})).status).toBe('INVALID_INSTALL_KEY_CLAIM')
    expect((await verify({ did: ACCOUNT_DEVICE_ID, mskid: value }, {})).status).toBe('INVALID_ACCOUNT_KEY_ID_CLAIM')
  })

  it('reports a bad install claim and still verifies the account entry', async () => {
    const result = await verify({ ipk: null, did: ACCOUNT_DEVICE_ID, mskid: 'account-key' }, await signedHeaders(['account']), { ...context, approovMessageSigningRequired: 'both' })
    expect(result.status).toBe('INVALID')
    expect(result.signatures.install.status).toBe('INVALID_INSTALL_KEY_CLAIM')
    expect(result.signatures.account.status).toBe('VALID')
  })

  it.each([
    ['install', 'creation'], ['account', 'creation'],
    ['install', 'operation'], ['account', 'operation']
  ])('isolates internal %s verifier %s errors and completes the other signature', async (name, stage) => {
    const headers = await signedHeaders(['install', 'account'])
    const actualFactory = createVerifier.getMockImplementation()
    if (name === 'account') createVerifier.mockImplementationOnce(actualFactory)
    createVerifier.mockImplementationOnce(() => {
      if (stage === 'creation') throw new Error('PRIVATE-CRYPTO-ERROR')
      return async () => { throw new Error('PRIVATE-CRYPTO-ERROR') }
    })
    const result = await verify({ ipk, did: ACCOUNT_DEVICE_ID, mskid: 'account-key' }, headers)
    expect(result.status).toBe('ERROR')
    expect(result.signatures[name].status).toBe('ERROR')
    expect(result.signatures[name === 'install' ? 'account' : 'install'].status).toBe('VALID')
    expect(JSON.stringify(result)).not.toContain('PRIVATE-CRYPTO-ERROR')
  })

  it.each([
    ['rsa', { modulusLength: 1024 }],
    ['ec', { namedCurve: 'secp384r1' }]
  ])('rejects an install key with the wrong algorithm or curve (%s)', async (type, options) => {
    const key = crypto.generateKeyPairSync(type, options).publicKey.export({ type: 'spki', format: 'pem' }).toString()
    expect((await verify({ ipk: key }, {})).status).toBe('INVALID_INSTALL_KEY_CLAIM')
  })

  it('checks the body digest only once for both signatures', async () => {
    const headers = await signedHeaders(['install', 'account'], 'test-token', 'original')
    const request = new Request(url, { method: 'POST', body: 'original', headers })
    const clone = vi.spyOn(request, 'clone')
    expect((await validateMessageSignatures(context, request, { ipk, did: ACCOUNT_DEVICE_ID, mskid: 'account-key' })).status).toBe('VALID')
    expect(clone).toHaveBeenCalledTimes(1)
    const changed = await verify({ ipk, did: ACCOUNT_DEVICE_ID, mskid: 'account-key' }, headers, context, 'changed')
    expect(changed.status).toBe('INVALID')
    expect(changed.signatures.install.status).toBe('INVALID_CONTENT_DIGEST')
    expect(changed.signatures.account.status).toBe('INVALID_CONTENT_DIGEST')
  })

  it('reports a malformed client digest as a verification failure for both signatures', async () => {
    const headers = await signedHeaders(['install', 'account'], 'test-token', 'original')
    headers['Content-Digest'] = '@@@'
    const result = await verify({ ipk, did: ACCOUNT_DEVICE_ID, mskid: 'account-key' }, headers, context, 'original')
    expect(result.status).toBe('INVALID')
    expect(result.signatures.install.status).toBe('INVALID_CONTENT_DIGEST')
    expect(result.signatures.account.status).toBe('INVALID_CONTENT_DIGEST')
  })

  it.each([
    [{ ipk }, ['install']], [{ did: ACCOUNT_DEVICE_ID, mskid: 'account-key' }, ['account']],
    [{ ipk, did: ACCOUNT_DEVICE_ID, mskid: 'account-key' }, ['install', 'account']]
  ])('reports an internal body-reading error for every required signature (%j)', async (claims, names) => {
    const headers = await signedHeaders(names, 'test-token', 'original')
    const request = new Request(url, { method: 'POST', body: 'original', headers })
    const clone = vi.spyOn(request, 'clone').mockImplementation(() => { throw new Error('PRIVATE-BODY-ERROR') })
    const result = await validateMessageSignatures(context, request, claims)
    expect(clone).toHaveBeenCalledTimes(1)
    expect(result.status).toBe('ERROR')
    for (const name of names) expect(result.signatures[name].status).toBe('ERROR')
    expect(JSON.stringify(result)).not.toContain('PRIVATE-BODY-ERROR')
  })

  it.each([{ ipk }, { did: ACCOUNT_DEVICE_ID, mskid: 'account-key' }, { ipk, did: ACCOUNT_DEVICE_ID, mskid: 'account-key' }])('captures unexpected errors per required entry (%j)', async claims => {
    const request = new Request(url)
    vi.spyOn(request.headers, 'get').mockImplementation(() => { throw new Error('PRIVATE-ERROR') })
    const result = await validateMessageSignatures(context, request, claims)
    expect(result.status).toBe('ERROR')
    expect(JSON.stringify(result)).not.toContain('PRIVATE-ERROR')
    expect(Object.values(result.signatures).filter(Boolean).every(entry => entry.status === 'ERROR')).toBe(true)
  })
})

describe('independent block actions', () => {
  const actions = ['block', 'continue']
  const combinations = actions.flatMap(token => actions.flatMap(binding => actions.map(signing => [token, binding, signing])))
  for (const failedLayer of ['token', 'binding', 'messageSigning']) {
    it.each(combinations)(`${failedLayer} failure with actions %s / %s / %s`, async (tokenAction, bindingAction, signingAction) => {
      const log = vi.spyOn(console, 'log').mockImplementation(() => {})
      const origin = vi.fn(async () => new Response('origin', { status: 201 }))
      vi.stubGlobal('fetch', origin)
      const claims = { exp: FUTURE_EXP, ipk, did: ACCOUNT_DEVICE_ID, mskid: 'account-key', pay: sha256Base64('correct') }
      const token = signEs256(failedLayer === 'token' ? FAIL_PRIVATE_KEY : PASS_PRIVATE_KEY, claims)
      const headers = await signedHeaders(['install', 'account'], token)
      headers.Authorization = failedLayer === 'binding' ? 'incorrect' : 'correct'
      headers['Approov-Result'] = 'client-forgery'
      if (failedLayer === 'messageSigning') headers.Signature = headers.Signature.replace(/account=:[^:]+:/, 'account=:YWJj:')
      const response = await handleRequest(new Request(url, { headers }), makeEnv({
        ...settings,
        APPROOV_MODE: 'block',
        APPROOV_TOKEN_BINDING_ENABLED: true,
        APPROOV_TOKEN_ACTION: tokenAction,
        APPROOV_TOKEN_BINDING_ACTION: bindingAction,
        APPROOV_MESSAGE_SIGNING_ACTION: signingAction,
        APPROOV_LOGGING_ENABLED: true
      }))
      const blocks = ({ token: tokenAction, binding: bindingAction, messageSigning: signingAction })[failedLayer] === 'block'
      expect(response.status).toBe(blocks ? 403 : 201)
      expect(origin).toHaveBeenCalledTimes(blocks ? 0 : 1)
      if (!blocks) expect(origin.mock.calls[0][0].headers.has('Approov-Result')).toBe(false)
      const summary = log.mock.calls.map(([entry]) => entry).find(entry => entry?.event === 'approov.request')
      expect(summary.validation).toBe('FAIL')
      expect(summary.action).toBe(blocks ? 'block' : 'forward')
      expect(summary.messageSignature.signatures.install).toBe('VALID')
      expect(summary.messageSignature.signatures.account).toBe(failedLayer === 'messageSigning' ? 'INVALID' : 'VALID')
      expect(JSON.stringify(summary)).not.toContain(token)
      expect(JSON.stringify(summary)).not.toContain(ipk)
    })
  }

  it('does not trust claims from an invalid token when token failures continue', async () => {
    const origin = vi.fn()
    vi.stubGlobal('fetch', origin)
    const response = await handleRequest(new Request(url, { headers: { 'Approov-Token': 'invalid' } }), makeEnv({
      APPROOV_MODE: 'block', APPROOV_TOKEN_ACTION: 'continue', APPROOV_MESSAGE_SIGNING_ACTION: 'block'
    }))
    expect(response.status).toBe(403)
    expect(origin).not.toHaveBeenCalled()
  })
})

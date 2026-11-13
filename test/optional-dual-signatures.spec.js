import crypto from 'node:crypto'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { establishContext } from '../src/config/context.js'
import { validateWorkerConfig } from '../src/config/schema.mjs'
import { evaluateApproovToken } from '../src/approov/evaluate.js'
import { handleRequest } from '../src/worker/handle-request.js'
import { ACCOUNT_DEVICE_ID, FAIL_PRIVATE_KEY, FUTURE_EXP, PASS_PRIVATE_KEY, makeEnv, signEs256 } from './fixtures.js'

// Independent wire fixtures: use Node crypto and explicit RFC 9421 bases, not
// the vendored signer that the Worker uses for verification. All keys are local
// test keys. The component list and 15-second lifetime follow issue #47.
const installation = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const installPrivateKey = installation.privateKey.export({ type: 'pkcs8', format: 'pem' })
const ipk = installation.publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
const secret = Buffer.from('issue-47-synthetic-account-secret')
const deviceKey = crypto.createHmac('sha512', secret).update(Buffer.from(ACCOUNT_DEVICE_ID, 'base64')).digest()
const dualClaims = { exp: FUTURE_EXP, ipk, mskid: 'issue-47-key', did: ACCOUNT_DEVICE_ID }
const settings = { APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET: secret.toString('base64'), APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID: 'issue-47-key' }
const context = (policy, extra = {}) => establishContext(makeEnv({ ...settings, APPROOV_MESSAGE_SIGNING_REQUIRED: policy, ...extra }))
const url = 'https://worker.local/v1/shapes?colour=red&id=7'

const wireRequest = ({ names = ['install'], claims = dualClaims, method = 'POST', repeated = false, tamper = null, tokenKey = PASS_PRIVATE_KEY, headerName = 'Approov-Token' } = {}) => {
  const token = signEs256(tokenKey, claims)
  const body = method === 'POST' ? '{"a":1}' : undefined
  const headers = new Headers({ [headerName]: token, 'Approov-TraceID': 'synthetic-trace', Authorization: 'Bearer synthetic-test-value' })
  const fields = ['@method', '@target-uri', headerName.toLowerCase(), 'approov-traceid', 'authorization']
  if (body !== undefined) {
    headers.set('Content-Type', 'application/json; charset=utf-8')
    headers.set('Content-Length', String(Buffer.byteLength(body)))
    headers.set('Content-Digest', `sha-256=:${crypto.createHash('sha256').update(body).digest('base64')}:`)
    fields.push('content-length', 'content-type', 'content-digest')
  }
  const created = Math.floor(Date.now() / 1000)
  const signatureEntries = []
  const inputEntries = []
  for (const name of names) {
    const alg = name === 'install' ? 'ecdsa-p256-sha256' : 'hmac-sha256'
    const parameters = `(${fields.map(field => `"${field}"`).join(' ')});created=${created};expires=${created + 15};alg="${alg}"`
    const components = fields.map(field => `"${field}": ${field === '@method' ? method : field === '@target-uri' ? url : headers.get(field)}`)
    const base = [...components, `"@signature-params": ${parameters}`].join('\n')
    const signature = name === 'install'
      ? crypto.sign('sha256', Buffer.from(base), { key: installPrivateKey, dsaEncoding: 'ieee-p1363' })
      : crypto.createHmac('sha256', deviceKey).update(base).digest()
    expect(signature.length).toBe(name === 'install' ? 64 : 32)
    signatureEntries.push(`${name}=:${(name === tamper ? Buffer.alloc(signature.length) : signature).toString('base64')}:`)
    inputEntries.push(`${name}=${parameters}`)
  }
  for (const [header, entries] of [['Signature', signatureEntries], ['Signature-Input', inputEntries]]) {
    if (repeated) entries.forEach(entry => headers.append(header, entry))
    else if (entries.length) headers.set(header, entries.join(', '))
  }
  return new Request(url, { method, headers, body })
}

const evaluate = (policy, options, extra) => evaluateApproovToken(context(policy, extra), wireRequest(options))
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('optional dual message signatures (#47)', () => {
  it.each(['GET', 'POST'])('accepts install-only, account-only and dual wire fixtures with both claims (%s)', async method => {
    for (const names of [['install'], ['account'], ['install', 'account'], ['account', 'install']]) {
      for (const policy of [undefined, 'either']) {
        const result = await evaluate(policy, { names, method })
        expect(result).toMatchObject({ tokenResult: 'PASS', messageSigningMode: 'either', messageSigningResult: 'VALID' })
        for (const name of ['install', 'account']) {
          expect(result.messageSigningVerification.signatures[name]?.status ?? null).toBe(names.includes(name) ? 'VALID' : null)
        }
      }
    }
  })

  it.each(['install', 'account', 'either', 'both'])('accepts both dictionary members on repeated HTTP header lines (%s)', async policy => {
    const result = await evaluate(policy, { names: ['install', 'account'], repeated: true })
    expect(result.messageSigningResult).toBe('VALID')
    expect(result.messageSigningMode).toBe(policy)
    expect(result.messageSigningVerification.signatures.install.status).toBe('VALID')
    expect(result.messageSigningVerification.signatures.account.status).toBe('VALID')
  })

  it.each(['install', 'account'])('requires the configured %s member even when the other is valid', async required => {
    const other = required === 'install' ? 'account' : 'install'
    for (const policy of [required, 'both']) {
      const result = await evaluate(policy, { names: [other] })
      expect(result.messageSigningResult).toBe('INVALID')
      expect(result.messageSigningVerification.signatures[required].status).toBe('MISSING_SIGNATURE_ENTRY')
      expect(result.messageSigningVerification.signatures[other].status).toBe('VALID')
    }
  })

  it.each(['install', 'account'])('permits the configured %s member alone despite both claims', async required => {
    expect((await evaluate(required, { names: [required] })).messageSigningResult).toBe('VALID')
  })

  it.each([undefined, 'install', 'account', 'either', 'both'])('never lets a valid member hide a present invalid member (%s)', async policy => {
    for (const tamper of ['install', 'account']) {
      const result = await evaluate(policy, { names: ['install', 'account'], tamper })
      expect(result.messageSigningResult).toBe('INVALID')
      expect(result.messageSigningVerification.signatures[tamper].status).toBe('INVALID')
      expect(result.messageSigningVerification.signatures[tamper === 'install' ? 'account' : 'install'].status).toBe('VALID')
    }
  })

  it.each(['Signature', 'Signature-Input'])('treats a recognized member in only %s as present and invalid', async header => {
    const request = wireRequest({ names: ['install', 'account'] })
    request.headers.set(header, request.headers.get(header).split(', ').filter(entry => entry.startsWith('install=')).join(', '))
    const result = await evaluateApproovToken(context('install'), request)
    expect(result.messageSigningResult).toBe('INVALID')
    expect(result.messageSigningVerification.signatures.install.status).toBe('VALID')
    expect(result.messageSigningVerification.signatures.account.status).toBe('MISSING_SIGNATURE_ENTRY')
  })

  it('does not require an unused account secret or device ID for install-only signing', async () => {
    const result = await evaluate(undefined, { claims: { exp: FUTURE_EXP, ipk, mskid: 'issue-47-key' } }, {
      APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET: undefined
    })
    expect(result.messageSigningResult).toBe('VALID')
    expect(result.messageSigningVerification.signatures.account).toBeNull()
  })

  it('fails a present account member when its secret is missing', async () => {
    const result = await evaluate('install', { names: ['install', 'account'] }, { APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET: undefined })
    expect(result.messageSigningResult).toBe('INVALID')
    expect(result.messageSigningVerification.signatures.install.status).toBe('VALID')
    expect(result.messageSigningVerification.signatures.account.status).toBe('ACCOUNT_SECRET_NOT_CONFIGURED')
  })

  it.each(['install', 'account'])('fails a present %s member without its trusted key claim', async missing => {
    const claims = { ...dualClaims }
    delete claims[missing === 'install' ? 'ipk' : 'mskid']
    const result = await evaluate(undefined, { names: ['install', 'account'], claims })
    expect(result.messageSigningResult).toBe('INVALID')
    expect(result.messageSigningVerification.signatures[missing].status).toBe(missing === 'install' ? 'INVALID_INSTALL_KEY_CLAIM' : 'INVALID_ACCOUNT_KEY_ID_CLAIM')
  })

  it.each(['install', 'account', 'either', 'both'])('cannot satisfy an explicit %s requirement by omitting both claims', async policy => {
    const result = await evaluate(policy, { names: [], claims: { exp: FUTURE_EXP } })
    expect(result.messageSigningResult).not.toBe('NOT_REQUIRED')
    expect(result.messageSigningVerification.ok).toBe(false)
  })

  it.each([undefined, 'either'])('requires at least one signature when both claims exist (%s)', async policy => {
    expect((await evaluate(policy, { names: [] })).messageSigningVerification.ok).toBe(false)
    const request = wireRequest({ names: [] })
    request.headers.set('Signature', 'unrelated=:YWJj:')
    request.headers.set('Signature-Input', 'unrelated=("@method");alg="hmac-sha256"')
    expect((await evaluateApproovToken(context(policy), request)).messageSigningVerification.ok).toBe(false)
  })

  it('retains token-only compatibility when no requirement is configured', async () => {
    expect((await evaluate(undefined, { names: [], claims: { exp: FUTURE_EXP } })).messageSigningResult).toBe('NOT_REQUIRED')
    expect((await evaluate(undefined, { names: ['install'], claims: { exp: FUTURE_EXP } })).messageSigningVerification.ok).toBe(false)
  })

  it('ignores well-formed unknown members without letting them satisfy an explicit requirement', async () => {
    const request = wireRequest({ names: [], claims: { exp: FUTURE_EXP } })
    request.headers.set('Signature', 'unrelated=:YWJj:')
    request.headers.set('Signature-Input', 'unrelated=("@method")')
    expect((await evaluateApproovToken(context(), request)).messageSigningResult).toBe('NOT_REQUIRED')
    expect((await evaluateApproovToken(context('either'), request)).messageSigningVerification.ok).toBe(false)
  })

  it('does not validate an unused installation key for an account-only request', async () => {
    const result = await evaluate('account', { names: ['account'], claims: { ...dualClaims, ipk: 'unused-invalid-key' } })
    expect(result.messageSigningResult).toBe('VALID')
    expect(result.messageSigningVerification.signatures.install).toBeNull()
  })

  it('uses the configured token header in each independent signature base', async () => {
    expect((await evaluate('either', { names: ['install', 'account'], headerName: 'X-Approov' }, { APPROOV_TOKEN_HEADER_NAME: 'X-Approov' })).messageSigningResult).toBe('VALID')
  })

  it('rejects a modified body even when only the install member is present', async () => {
    const signed = wireRequest()
    const request = new Request(signed, { body: '{"a":2}' })
    const result = await evaluateApproovToken(context('either'), request)
    expect(result.messageSigningResult).toBe('INVALID_CONTENT_DIGEST')
  })

  it('never authenticates an unknown token or converts a FAIL token to PASS', async () => {
    const untrusted = wireRequest()
    untrusted.headers.set('Approov-Token', 'untrusted')
    expect((await evaluateApproovToken(context('either'), untrusted)).messageSigningResult).toBe('NOT_CHECKED')
    expect(await evaluate('either', { tokenKey: FAIL_PRIVATE_KEY })).toMatchObject({ tokenResult: 'FAIL', messageSigningResult: 'VALID' })
  })

  it.each(['annotate', 'block'])('keeps invalid present signatures subject to the existing %s enforcement', async mode => {
    const origin = vi.fn(async () => new Response('origin', { status: 201 }))
    vi.stubGlobal('fetch', origin)
    const env = makeEnv({ ...settings, APPROOV_MODE: mode, APPROOV_MESSAGE_SIGNING_REQUIRED: 'either' })
    const valid = await handleRequest(wireRequest(), env)
    expect(valid.status).toBe(201)
    const invalid = await handleRequest(wireRequest({ names: ['install', 'account'], tamper: 'account' }), env)
    expect(invalid.status).toBe(mode === 'block' ? 403 : 201)
    expect(origin).toHaveBeenCalledTimes(mode === 'block' ? 1 : 2)
    if (mode === 'annotate') {
      expect(JSON.parse(Buffer.from(origin.mock.calls[1][0].headers.get('Approov-Result'), 'base64').toString('utf8'))).toMatchObject({ tokenResult: 'PASS', messageSigningResult: 'INVALID' })
    }
  })

  it('enforces requirement changes on the same environment object', async () => {
    const origin = vi.fn(async () => new Response('origin'))
    vi.stubGlobal('fetch', origin)
    const env = makeEnv({ ...settings, APPROOV_MODE: 'block', APPROOV_MESSAGE_SIGNING_REQUIRED: 'either' })
    expect((await handleRequest(wireRequest(), env)).status).toBe(200)
    env.APPROOV_MESSAGE_SIGNING_REQUIRED = 'both'
    expect((await handleRequest(wireRequest(), env)).status).toBe(403)
    expect((await handleRequest(wireRequest({ names: [], claims: { exp: FUTURE_EXP } }), env)).status).toBe(403)
    expect(origin).toHaveBeenCalledTimes(1)
  })

  it('logs the selected requirement and both signature results without key material', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    const writeDataPoint = vi.fn()
    vi.stubGlobal('fetch', vi.fn(async () => new Response('origin')))
    const env = makeEnv({ ...settings, APPROOV_MODE: 'block', APPROOV_MESSAGE_SIGNING_REQUIRED: 'either', APPROOV_LOGGING_ENABLED: true, APPROOV_ANALYTICS_ENABLED: true, APPROOV_ANALYTICS: { writeDataPoint } })
    expect((await handleRequest(wireRequest({ names: ['install', 'account'], tamper: 'account' }), env)).status).toBe(403)
    const summary = log.mock.calls.map(([value]) => value).find(value => value?.event === 'approov.request')
    expect(summary.messageSignature).toMatchObject({ mode: 'either', status: 'INVALID', signatures: { install: 'VALID', account: 'INVALID' } })
    expect(writeDataPoint.mock.calls[0][0].blobs[7]).toBe('either')
    expect(JSON.stringify(summary)).not.toContain(ipk)
    expect(JSON.stringify(summary)).not.toContain(secret.toString('base64'))
  })
})

describe('message-signing requirement configuration', () => {
  it.each(['install', 'account', 'either', 'both'])('accepts %s in annotation and block mode', policy => {
    for (const mode of ['annotate', 'block']) {
      const env = makeEnv({ APPROOV_MODE: mode, APPROOV_MESSAGE_SIGNING_REQUIRED: policy })
      expect(validateWorkerConfig(env)).toEqual([])
      expect(establishContext(env).approovMessageSigningRequired).toBe(policy)
    }
  })

  it.each(['none', 'INSTALL', ' either ', '', null, false])('rejects an unsupported requirement (%j)', policy => {
    expect(validateWorkerConfig(makeEnv({ APPROOV_MESSAGE_SIGNING_REQUIRED: policy })).join('\n')).toContain('APPROOV_MESSAGE_SIGNING_REQUIRED')
  })
})

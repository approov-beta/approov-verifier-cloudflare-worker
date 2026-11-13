import crypto from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { establishContext } from '../src/config/context.js'
import { evaluateApproovToken } from '../src/approov/evaluate.js'
import { ACCOUNT_DEVICE_ID, FUTURE_EXP, PASS_PRIVATE_KEY, makeEnv, signEs256 } from './fixtures.js'

// Wire conformance with the Approov 3.7 service layers, using the request
// shapes pinned by approov-service-okhttp release/3.7.0 (ApproovDefaultMessageSigning
// and its TargetUriWireUrl370Test). The signature bases are built here by hand
// with Node crypto, exactly as the client serializes them, and never with the
// vendored signer the Worker verifies with. All keys are local test keys.
//
// What a 3.7 client sends:
// - one Signature and one Signature-Input dictionary, members `install`
//   (ecdsa-p256-sha256, raw 64 byte r||s) and/or `account` (hmac-sha256),
//   `install` first, both over the same covered components
// - parameters in the order created, expires, alg (alg is set last, per member)
// - @method, @target-uri (the URL exactly as sent), the token header, then
//   approov-traceid, authorization, content-length and content-type when
//   present, then content-digest (sha-256) when the body can be digested,
//   which includes an empty body but not a one-shot or chunked body
const installation = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const installPrivateKey = installation.privateKey.export({ type: 'pkcs8', format: 'pem' })
const ipk = installation.publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
const secret = Buffer.from('sdk-3.7-synthetic-account-secret')
const deviceKey = crypto.createHmac('sha512', secret).update(Buffer.from(ACCOUNT_DEVICE_ID, 'base64')).digest()
const claims = { exp: FUTURE_EXP, ipk, mskid: 'sdk-3.7-key', did: ACCOUNT_DEVICE_ID }
const ctx = establishContext(makeEnv({
  APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET: secret.toString('base64'),
  APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID: 'sdk-3.7-key'
}))
const origin = 'https://worker.local'
const sha256Digest = body => `sha-256=:${crypto.createHash('sha256').update(body).digest('base64')}:`

// Serializes a covered component the way the client's StringItem does.
const identifier = ([name, params = '']) => `"${name}"${params}`

/**
 * Builds a request as a 3.7 client signs it.
 *
 * @param {Object} options
 * @param {String} options.target Path and query exactly as sent on the wire.
 * @param {String} [options.method]
 * @param {String|ReadableStream|null} [options.body] Request body, if any.
 * @param {Boolean} [options.digest] Whether the client could digest the body.
 * @param {Object} [options.headers] Further headers the app sends.
 * @param {Array} [options.extra] Further covered components as [name, params, value].
 * @param {Function} [options.fields] Maps the default component list to a custom one.
 */
const clientRequest = ({ target, method = 'GET', body = null, digest = body !== null, headers: appHeaders = {}, extra = [], fields = list => list, names = ['install', 'account'] }) => {
  const url = origin + target
  const headers = new Headers({ 'Approov-Token': signEs256(PASS_PRIVATE_KEY, claims), 'Approov-TraceID': 'synthetic-trace', ...appHeaders })
  const covered = [['@method'], ['@target-uri'], ['approov-token'], ['approov-traceid']]
  for (const optional of ['authorization', 'content-length', 'content-type']) {
    if (headers.has(optional)) covered.push([optional])
  }
  if (digest) {
    headers.set('Content-Digest', sha256Digest(typeof body === 'string' ? body : ''))
    covered.push(['content-digest'])
  }
  const components = fields([...covered, ...extra.map(([name, params]) => [name, params])])
  const values = new Map(extra.map(([name, params, value]) => [identifier([name, params]), value]))
  const created = Math.floor(Date.now() / 1000)
  const signatures = []
  const inputs = []
  for (const name of names) {
    const alg = name === 'install' ? 'ecdsa-p256-sha256' : 'hmac-sha256'
    const parameters = `(${components.map(identifier).join(' ')});created=${created};expires=${created + 15};alg="${alg}"`
    const lines = components.map(component => {
      const id = identifier(component)
      const value = values.has(id)
        ? values.get(id)
        : component[0] === '@method' ? method : component[0] === '@target-uri' ? url : headers.get(component[0])
      return `${id}: ${value}`
    })
    const base = [...lines, `"@signature-params": ${parameters}`].join('\n')
    const signature = name === 'install'
      ? crypto.sign('sha256', Buffer.from(base), { key: installPrivateKey, dsaEncoding: 'ieee-p1363' })
      : crypto.createHmac('sha256', deviceKey).update(base).digest()
    signatures.push(`${name}=:${signature.toString('base64')}:`)
    inputs.push(`${name}=${parameters}`)
  }
  headers.set('Signature', signatures.join(', '))
  headers.set('Signature-Input', inputs.join(', '))
  const init = { method, headers }
  if (body !== null) Object.assign(init, { body, duplex: 'half' })
  const request = new Request(url, init)
  // The Worker must see the URL as the client sent it, or @target-uri differs.
  expect(request.url).toBe(url)
  return request
}

const verify = async options => {
  const result = await evaluateApproovToken(ctx, clientRequest(options))
  expect(result.tokenResult).toBe('PASS')
  return result
}
const expectBothValid = async options => {
  const result = await verify(options)
  expect(result.messageSigningVerification.error).toBeNull()
  expect(result.messageSigningResult).toBe('VALID')
  expect(result.messageSigningVerification.signatures.install.status).toBe('VALID')
  expect(result.messageSigningVerification.signatures.account.status).toBe('VALID')
}

describe('Approov 3.7 service layer wire conformance', () => {
  it.each([
    ['a raw | in the query', '/maps/api/staticmap?path=color:red|weight:5&markers=size:mid|label:A'],
    ['characters java.net.URI rejects', '/s?f={%22a%22:1}&c=^`&p=x|y'],
    ['no query', '/v1/shapes'],
    ['an empty query', '/v1/shapes?'],
    ['a repeated query parameter', '/p?key=v1&other=1&key=v2']
  ])('verifies a default GET whose @target-uri has %s', async (_, target) => {
    await expectBothValid({ target, headers: { Authorization: 'Bearer app-credential' } })
  })

  it('verifies a POST with encoded spaces, a literal percent and non-ASCII characters', async () => {
    const body = '{"a":1}'
    await expectBothValid({
      target: '/caf%C3%A9/x?q=a%20b&pct=100%25&name=caf%C3%A9&pipe=x|y',
      method: 'POST',
      body,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': String(Buffer.byteLength(body)) }
    })
  })

  it.each([['install'], ['account']])('verifies a request signed with the %s signature only', async name => {
    const result = await verify({ target: '/v1/shapes?colour=red&id=7', names: [name] })
    expect(result.messageSigningResult).toBe('VALID')
    expect(result.messageSigningVerification.signatures[name].status).toBe('VALID')
  })

  it('verifies an empty body, which a 3.7 client sends with a Content-Digest', async () => {
    const request = clientRequest({ target: '/empty', method: 'POST', body: '', headers: { 'Content-Length': '0' } })
    expect(request.headers.get('Content-Digest')).toBe('sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:')
    expect((await evaluateApproovToken(ctx, request)).messageSigningResult).toBe('VALID')
  })

  it('rejects a chunked body, which a 3.7 client signs without a Content-Digest', async () => {
    // The client cannot digest a one-shot body or one of unknown length, so
    // by default it signs the request without covering the body. The Worker
    // does not accept a body the signature does not protect.
    const body = new ReadableStream({
      start (controller) {
        controller.enqueue(new TextEncoder().encode('chunked'))
        controller.close()
      }
    })
    const result = await verify({ target: '/body', method: 'POST', body, digest: false, headers: { 'Content-Type': 'text/plain' } })
    expect(result.messageSigningResult).toBe('INVALID')
    expect(result.messageSigningVerification.signatures.install.status).toBe('MISSING_CONTENT_DIGEST')
    expect(result.messageSigningVerification.signatures.account.status).toBe('MISSING_CONTENT_DIGEST')
  })

  it('verifies the token on Authorization, covered once', async () => {
    // setTokenHeader("Authorization", "") puts the token on a header that is
    // also an optional header of the default factory; RFC 9421 section 2
    // allows a component only once, so the client covers it once.
    const authorizationCtx = establishContext(makeEnv({
      APPROOV_TOKEN_HEADER_NAME: 'Authorization',
      APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET: secret.toString('base64'),
      APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID: 'sdk-3.7-key'
    }))
    const request = clientRequest({
      target: '/p',
      headers: { Authorization: signEs256(PASS_PRIVATE_KEY, claims) },
      fields: list => list.filter(([name]) => name !== 'approov-token')
    })
    request.headers.delete('Approov-Token')
    const result = await evaluateApproovToken(authorizationCtx, request)
    expect(result).toMatchObject({ tokenResult: 'PASS', messageSigningResult: 'VALID' })
  })

  // RFC 9421 section 2.2.8: the value is the decoded parameter value encoded
  // again with the application/x-www-form-urlencoded percent-encode set, which
  // leaves only ASCII letters, digits and *-._ unencoded, with a space as %20.
  // The name parameter of the component is encoded the same way.
  it.each([
    ['a plain value', '/p?id=7', 'id', '7'],
    ['an empty value', '/p?flag=', 'flag', ''],
    ['a name without a value', '/p?flag', 'flag', ''],
    ['a space sent as +', '/p?q=a+b', 'q', 'a%20b'],
    ['a space sent as %20', '/p?q=a%20b', 'q', 'a%20b'],
    ['characters encodeURIComponent leaves alone', '/p?q=!%27()~*-._', 'q', '%21%27%28%29%7E*-._'],
    ['a raw |', '/p?pipe=x|y', 'pipe', 'x%7Cy'],
    ['non-ASCII characters', '/p?name=caf%C3%A9', 'name', 'caf%C3%A9'],
    ['a literal percent', '/p?pct=100%25', 'pct', '100%25'],
    ['an encoded name', '/p?var+name=1', 'var+name', '1'],
    ['a percent-encoded name', '/p?var%20name=1', 'var%20name', '1']
  ])('verifies a covered @query-param with %s', async (_, target, name, value) => {
    await expectBothValid({ target, extra: [['@query-param', `;name="${name}"`, value]] })
  })

  it('rejects a covered @query-param that occurs more than once', async () => {
    // RFC 9421 section 2.2.8: a parameter that occurs more than once must not
    // be covered by name. The client does not sign such a request.
    const result = await verify({ target: '/p?key=v1&key=v2', extra: [['@query-param', ';name="key"', 'v1']] })
    expect(result.messageSigningResult).toBe('INVALID')
  })
})

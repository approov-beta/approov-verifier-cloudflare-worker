/**
 * The L2 matrix: two orthogonal axes.
 *
 *  - `plugins`  — build-time plugin set (PLUGINS env on the deploy). `undefined`
 *                 means "all discovered"; '' means none; 'arc' a subset.
 *  - `vars`     — runtime config overrides applied via `--var` at deploy.
 *
 * Each profile lists request `scenarios`. A scenario's `expect(ctx)` receives
 * `{ status, result, body, text, baseUrl }` where `result` is the decoded
 * Approov-Result (or null, e.g. when a request was rejected before echo), `body`
 * is the parsed echo payload, and `baseUrl` is the deployed origin under test.
 * Assertions throw on failure.
 */
import assert from 'node:assert/strict'
import * as B from './request-builder.mjs'

const PATH = '/v3/shapes/'

// Tokens (keys are constant, so build once).
// Codes 0→pass, 1→debug; 31/63/95 are "skip" codes (no property) used only to
// reach the 10-char minimum ARC length. Decodes to exactly ['pass', 'debug'].
const arcClaim = B.buildArc([0, 1, 31, 63, 95])
const eligibleToken = B.passToken({ mskid: B.ACCOUNT_KEY_ID, arc: arcClaim }) // PASS + account-signing + arc
const arcToken = B.passToken({ arc: arcClaim })
const failTok = B.failToken()
const expiredTok = B.expiredToken()
const invalidSigTok = B.invalidSignatureToken()
const invalidAlgTok = B.invalidAlgorithmToken()
const defaultSecretTok = B.defaultSecretToken()
const bindingValue = 'Bearer e2e-binding-value'
const boundToken = B.passToken({ pay: B.bindingHash(bindingValue) })
const installToken = B.passToken({ ipk: B.INSTALL_PUBLIC_KEY_CLAIM })
const bothToken = B.passToken({ ipk: B.INSTALL_PUBLIC_KEY_CLAIM, mskid: B.ACCOUNT_KEY_ID })
const badInstallToken = B.passToken({ ipk: 'not-a-public-key' })

const dummySignature = (name, algorithm) => ({
  Signature: `${name}=:YWJj:`,
  'Signature-Input': `${name}=("@method" "@target-uri" "approov-token");alg="${algorithm}";created=1704067200;expires=4070908800`
})
const findHeader = (headers, name) => Object.entries(headers || {})
  .find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1]

const tokenHeader = (token) => ({ 'Approov-Token': token })

export const profiles = [
  // ── Forwarding axis ────────────────────────────────────────────────────────
  // Echo mode reports the *rewritten* upstream URL, so pass-through is
  // observable without a second origin: the host must be the deployed preview
  // hostname rather than the `e2e.invalid` placeholder in wrangler.e2e.toml.
  {
    name: 'passthrough',
    vars: { API_PASSTHROUGH: 'true', API_DOMAIN: '' },
    scenarios: [
      {
        name: 'forwards to the inbound hostname instead of API_DOMAIN',
        request: { path: PATH, headers: tokenHeader(eligibleToken) },
        expect: ({ status, result, body, baseUrl }) => {
          assert.equal(status, 200)
          assert.equal(result.tokenResult, 'PASS')
          assert.equal(
            new URL(body.url).host,
            new URL(baseUrl).host,
            'passthrough must forward to the inbound host, not API_DOMAIN'
          )
        }
      },
      {
        name: 'stamps the hop marker on the forwarded request',
        request: { path: PATH, headers: tokenHeader(eligibleToken) },
        expect: ({ status, body }) => {
          assert.equal(status, 200)
          assert.equal(findHeader(body.headers, 'Approov-Gateway-Hop'), '1')
        }
      },
      {
        name: 'rejects a re-entered request with 508',
        request: {
          path: PATH,
          headers: { ...tokenHeader(eligibleToken), 'Approov-Gateway-Hop': '1' }
        },
        expect: ({ status }) => {
          assert.equal(status, 508, 'a request already carrying the hop marker must fail closed')
        }
      }
    ]
  },

  // ── Protected-path axis ────────────────────────────────────────────────────
  // In annotate mode a checked path echoes an Approov-Result and an unchecked
  // path does not, so the edge's own handling of each spelling is observable.
  {
    name: 'protected-paths',
    vars: { APPROOV_PROTECTED_PATHS: '/api,/shop/*/checkout' },
    scenarios: [
      ...[
        '/api/users',
        '/API/users',
        '/api.json',
        '/%61pi/users/%ff',
        '/%2561pi/users',
        '/public%2f..%2fapi/users',
        '/public%5c..%5capi/users',
        '/public/..;/api/users',
        '/shop/de/checkout',
        '/shop/d%2fe/checkout',
        '/shop/d%5ce/checkout',
        '/shop/d%252fe/checkout',
        '/shop%2fd%252fe/checkout'
      ].map((path) => ({
        name: `checks ${path}`,
        request: { path, headers: tokenHeader(arcToken) },
        expect: ({ status, result }) => {
          assert.equal(status, 200)
          assert.equal(result?.tokenResult, 'PASS', 'a protected path must carry the Worker result')
        }
      })),
      ...['/open', '/apiary', '/shop/d/e/checkout', '/shop%2fcheckout'].map((path) => ({
        name: `forwards ${path} unchecked, without a forged or Worker result`,
        request: { path, headers: { ...tokenHeader(failTok), 'Approov-Result': 'forged-by-client' } },
        expect: ({ status, body }) => {
          assert.equal(status, 200)
          assert.equal(findHeader(body.headers, 'approov-result'), undefined)
        }
      }))
    ]
  },

  // ── Plugin-presence axis (exercises the drop-in discovery/wiring flow) ──────
  {
    name: 'plugins-none',
    plugins: '',
    vars: {},
    scenarios: [
      {
        name: 'no plugin results even with arc claim',
        request: { path: PATH, headers: tokenHeader(eligibleToken) },
        expect: ({ status, result }) => {
          assert.equal(status, 200)
          assert.equal(result.tokenResult, 'PASS')
          assert.equal('arcProperties' in result, false, 'arcProperties must be absent without the arc plugin')
        }
      }
    ]
  },
  {
    name: 'plugins-arc-only',
    plugins: 'arc',
    vars: {},
    scenarios: [
      {
        name: 'arc decodes',
        request: { path: PATH, headers: tokenHeader(eligibleToken) },
        expect: ({ status, result }) => {
          assert.equal(status, 200)
          assert.equal(result.tokenResult, 'PASS')
          assert.deepEqual(result.arcProperties, ['pass', 'debug'])
        }
      }
    ]
  },
  // ── Config axis (all plugins present: PLUGINS unset) ────────────────────────
  {
    name: 'annotate',
    plugins: undefined,
    vars: {}, // defaults: backend-enforced annotation mode; echo is configured in Wrangler
    scenarios: [
      {
        name: 'PASS token annotated, forwarded',
        request: { path: PATH, headers: tokenHeader(arcToken) },
        expect: ({ status, result }) => {
          assert.equal(status, 200)
          assert.equal(result.tokenResult, 'PASS')
          assert.deepEqual(result.arcProperties, ['pass', 'debug'])
        }
      },
      {
        name: 'FAIL token annotated, NOT rejected',
        request: { path: PATH, headers: tokenHeader(failTok) },
        expect: ({ status, result }) => {
          assert.equal(status, 200)
          assert.equal(result.tokenResult, 'FAIL')
        }
      },
      {
        name: 'expired token → EXPIRED, not rejected',
        request: { path: PATH, headers: tokenHeader(expiredTok) },
        expect: ({ status, result }) => {
          assert.equal(status, 200)
          assert.equal(result.tokenResult, 'EXPIRED')
        }
      },
      {
        name: 'missing token header → MISSING_HEADER',
        request: { path: PATH, headers: {} },
        expect: ({ status, result }) => {
          assert.equal(status, 200)
          assert.equal(result.tokenResult, 'MISSING_HEADER')
        }
      },
      {
        // Cloudflare delivers the empty header to the Worker. An ingress that
        // drops it instead gives MISSING_HEADER. Neither is a passing token.
        name: 'empty token header → EMPTY_HEADER, or MISSING_HEADER when ingress drops it',
        request: { path: PATH, headers: { 'Approov-Token': '' } },
        expect: ({ status, result }) => {
          assert.equal(status, 200)
          assert.ok(['EMPTY_HEADER', 'MISSING_HEADER'].includes(result.tokenResult), result.tokenResult)
        }
      },
      {
        name: 'unknown signer → INVALID_SIG',
        request: { path: PATH, headers: tokenHeader(invalidSigTok) },
        expect: ({ result }) => assert.equal(result.tokenResult, 'INVALID_SIG')
      },
      {
        name: 'unsupported JWT algorithm → INVALID_ALG',
        request: { path: PATH, headers: tokenHeader(invalidAlgTok) },
        expect: ({ result }) => assert.equal(result.tokenResult, 'INVALID_ALG')
      },
      {
        name: 'malformed token → MALFORMED',
        request: { path: PATH, headers: tokenHeader('abc') },
        expect: ({ result }) => assert.equal(result.tokenResult, 'MALFORMED')
      },
      {
        name: 'unparsable JWT → UNPARSABLE',
        request: { path: PATH, headers: tokenHeader('eyJhbGciOiJFUzI1NiJ9..') },
        expect: ({ result }) => assert.equal(result.tokenResult, 'UNPARSABLE')
      },
      {
        name: 'default HS256 token rejected when compatibility is off',
        request: { path: PATH, headers: tokenHeader(defaultSecretTok) },
        expect: ({ result }) => assert.equal(result.tokenResult, 'INVALID_SIG')
      },
      {
        name: 'echo redacts credentials and replaces forged Approov-Result',
        request: {
          path: '/v3/shapes/?probe=redaction',
          method: 'POST',
          body: 'e2e-body',
          headers: {
            ...tokenHeader(arcToken),
            Authorization: 'Bearer must-not-echo',
            Cookie: 'session=must-not-echo',
            'Approov-Result': 'forged-by-client',
            'X-E2E-Keep': 'visible'
          }
        },
        expect: ({ status, result, body }) => {
          assert.equal(status, 200)
          assert.equal(result.tokenResult, 'PASS')
          assert.equal(body.method, 'POST')
          assert.equal(body.bodyText, 'e2e-body')
          assert.equal(new URL(body.url).pathname, '/v3/shapes/')
          assert.equal(new URL(body.url).search, '?probe=redaction')
          assert.equal(findHeader(body.headers, 'authorization'), '[redacted]')
          assert.equal(findHeader(body.headers, 'approov-token'), '[redacted]')
          assert.equal(findHeader(body.headers, 'cookie'), '[redacted]')
          assert.equal(findHeader(body.headers, 'x-e2e-keep'), 'visible')
          assert.notEqual(findHeader(body.headers, 'approov-result'), 'forged-by-client')
        }
      }
    ]
  },
  {
    name: 'block',
    plugins: undefined,
    vars: { APPROOV_MODE: 'block', APPROOV_TOKEN_ACTION: 'block', APPROOV_MESSAGE_SIGNING_ACTION: 'block' },
    scenarios: [
      {
        name: 'PASS → 200 (forwarded/echoed)',
        request: { path: PATH, headers: tokenHeader(arcToken) },
        expect: ({ status, result, body }) => {
          assert.equal(status, 200)
          assert.equal(result, null)
          assert.equal(findHeader(body.headers, 'approov-result'), undefined)
        }
      },
      {
        name: 'FAIL → 403 (rejected, no echo body)',
        request: { path: PATH, headers: tokenHeader(failTok) },
        expect: ({ status, result }) => {
          assert.equal(status, 403)
          assert.equal(result, null)
        }
      },
      {
        name: 'missing token → 403',
        request: { path: PATH, headers: {} },
        expect: ({ status }) => assert.equal(status, 403)
      }
    ]
  },
  {
    name: 'custom-rejection',
    plugins: undefined,
    vars: {
      APPROOV_MODE: 'block',
      APPROOV_TOKEN_ACTION: 'block',
      APPROOV_MESSAGE_SIGNING_ACTION: 'block',
      APPROOV_BLOCK_RESPONSE_STATUS: '418',
      APPROOV_BLOCK_RESPONSE_BODY: 'E2E rejected'
    },
    scenarios: [
      {
        name: 'configured rejection status and body are exact',
        request: { path: PATH, headers: tokenHeader(failTok) },
        expect: ({ status, result, text }) => {
          assert.equal(status, 418)
          assert.equal(result, null)
          assert.equal(text, 'E2E rejected')
        }
      }
    ]
  },
  {
    name: 'continue',
    plugins: undefined,
    vars: { APPROOV_MODE: 'block', APPROOV_TOKEN_ACTION: 'continue', APPROOV_MESSAGE_SIGNING_ACTION: 'continue' },
    scenarios: [
      {
        name: 'PASS is forwarded without a result header',
        request: { path: PATH, headers: tokenHeader(arcToken) },
        expect: ({ status, result, body }) => {
          assert.equal(status, 200)
          assert.equal(result, null)
          assert.equal(findHeader(body.headers, 'approov-result'), undefined)
        }
      },
      {
        name: 'failed request is forwarded without forged or worker result',
        request: {
          path: PATH,
          headers: { ...tokenHeader(failTok), 'Approov-Result': 'forged-by-client' }
        },
        expect: ({ status, result, body }) => {
          assert.equal(status, 200)
          assert.equal(result, null)
          assert.equal(findHeader(body.headers, 'approov-result'), undefined)
        }
      }
    ]
  },
  {
    name: 'mixed-actions',
    plugins: undefined,
    vars: { APPROOV_MODE: 'block', APPROOV_TOKEN_ACTION: 'block', APPROOV_MESSAGE_SIGNING_ACTION: 'continue' },
    scenarios: [
      {
        name: 'passing request is forwarded without forged or worker result',
        request: {
          path: PATH,
          headers: { ...tokenHeader(arcToken), 'Approov-Result': 'forged-by-client' }
        },
        expect: ({ status, result, body }) => {
          assert.equal(status, 200)
          assert.equal(result, null)
          assert.equal(findHeader(body.headers, 'approov-result'), undefined)
        }
      },
      {
        name: 'missing required signature continues without a result header',
        request: { path: PATH, headers: tokenHeader(installToken) },
        expect: ({ status, result, body }) => {
          assert.equal(status, 200)
          assert.equal(result, null)
          assert.equal(findHeader(body.headers, 'approov-result'), undefined)
        }
      },
      {
        name: 'token failure is blocked',
        request: { path: PATH, headers: tokenHeader(failTok) },
        expect: ({ status }) => assert.equal(status, 403)
      }
    ]
  },
  {
    name: 'audience',
    plugins: undefined,
    vars: { APPROOV_TOKEN_AUDIENCE: 'e2e-audience' },
    scenarios: [
      {
        name: 'matching audience → PASS',
        request: { path: PATH, headers: tokenHeader(B.passToken({ aud: 'e2e-audience' })) },
        expect: ({ result }) => assert.equal(result.tokenResult, 'PASS')
      },
      {
        name: 'wrong audience → INVALID_AUD',
        request: { path: PATH, headers: tokenHeader(B.passToken({ aud: 'wrong-audience' })) },
        expect: ({ result }) => assert.equal(result.tokenResult, 'INVALID_AUD')
      }
    ]
  },
  {
    name: 'default-secret-compat',
    plugins: undefined,
    vars: { APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET: 'true' },
    scenarios: [
      {
        name: 'default HS256 token accepted only in compatibility profile',
        request: { path: PATH, headers: tokenHeader(defaultSecretTok) },
        expect: ({ result }) => {
          assert.equal(result.tokenResult, 'PASS')
          assert.equal(result.tokenVerification.verification.source, 'defaultPassJWKS')
        }
      },
      {
        name: 'keyset token also accepted during migration overlap',
        request: { path: PATH, headers: tokenHeader(arcToken) },
        expect: ({ result }) => assert.equal(result.tokenResult, 'PASS')
      }
    ]
  },
  {
    name: 'binding',
    plugins: undefined,
    vars: { APPROOV_TOKEN_BINDING_ENABLED: 'true' },
    scenarios: [
      {
        name: 'matching binding → VALID',
        request: { path: PATH, headers: { ...tokenHeader(boundToken), Authorization: bindingValue } },
        expect: ({ status, result }) => {
          assert.equal(status, 200)
          assert.equal(result.bindingResult, 'VALID')
        }
      },
      {
        name: 'mismatched binding → INVALID',
        request: { path: PATH, headers: { ...tokenHeader(boundToken), Authorization: 'Bearer wrong' } },
        expect: ({ result }) => assert.equal(result.bindingResult, 'INVALID')
      },
      {
        name: 'pass token without binding claim → MISSING_CLAIM',
        request: { path: PATH, headers: { ...tokenHeader(arcToken), Authorization: bindingValue } },
        expect: ({ result }) => assert.equal(result.bindingResult, 'MISSING_CLAIM')
      },
      {
        name: 'missing binding header → MISSING_HEADER',
        request: { path: PATH, headers: tokenHeader(boundToken) },
        expect: ({ result }) => assert.equal(result.bindingResult, 'MISSING_HEADER')
      },
      {
        name: 'empty Authorization is normalized away by Cloudflare → MISSING_HEADER',
        request: { path: PATH, headers: { ...tokenHeader(boundToken), Authorization: '' } },
        expect: ({ result }) => assert.equal(result.bindingResult, 'MISSING_HEADER')
      }
    ]
  },
  {
    name: 'account-signing',
    plugins: undefined,
    vars: {
      APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID: B.ACCOUNT_KEY_ID
    },
    scenarios: [
      {
        name: 'mskid token without signature headers → MISSING_HEADERS',
        request: { path: PATH, headers: tokenHeader(eligibleToken) },
        expect: ({ status, result }) => {
          assert.equal(status, 200)
          assert.equal(result.messageSigningResult, 'MISSING_HEADERS')
        }
      },
      {
        name: 'valid account signature → VALID',
        request: (baseUrl) => B.signedAccountRequest(baseUrl, { path: PATH, token: eligibleToken }),
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'VALID')
      },
      {
        name: 'valid signature covers the full query string',
        request: (baseUrl) => B.signedAccountRequest(baseUrl, { path: `${PATH}?amount=1&tag=a&tag=b`, token: eligibleToken }),
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'VALID')
      },
      {
        name: 'changed query string invalidates the signature',
        request: async (baseUrl) => ({
          ...await B.signedAccountRequest(baseUrl, { path: `${PATH}?amount=1`, token: eligibleToken }),
          path: `${PATH}?amount=999`
        }),
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'INVALID')
      },
      {
        name: 'valid signed body preserves payload',
        request: (baseUrl) => B.signedAccountRequest(baseUrl, {
          path: PATH,
          token: eligibleToken,
          method: 'POST',
          body: 'signed-e2e-body'
        }),
        expect: ({ result, body }) => {
          assert.equal(result.messageSigningResult, 'VALID')
          assert.equal(body.bodyText, 'signed-e2e-body')
        }
      },
      {
        name: 'malformed signature headers → MALFORMED_HEADERS',
        request: {
          path: PATH,
          headers: { ...tokenHeader(eligibleToken), Signature: 'account=@@@', 'Signature-Input': 'account=@@@' }
        },
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'MALFORMED_HEADERS')
      },
      {
        name: 'present account member without a key claim → INVALID_ACCOUNT_KEY_ID_CLAIM',
        request: {
          path: PATH,
          headers: { ...tokenHeader(arcToken), ...dummySignature('account', 'hmac-sha256') }
        },
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'INVALID_ACCOUNT_KEY_ID_CLAIM')
      },
      {
        name: 'wrong account key claim → ACCOUNT_KEY_ID_MISMATCH',
        request: {
          path: PATH,
          headers: {
            ...tokenHeader(B.passToken({ mskid: 'wrong-key-id' })),
            ...dummySignature('account', 'hmac-sha256')
          }
        },
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'ACCOUNT_KEY_ID_MISMATCH')
      },
      {
        // Every present member is verified, so the install entry fails on its
        // own missing key claim next to the missing account entry.
        name: 'install entry cannot replace required account signature',
        request: {
          path: PATH,
          headers: { ...tokenHeader(eligibleToken), ...dummySignature('install', 'ecdsa-p256-sha256') }
        },
        expect: ({ result }) => {
          assert.equal(result.messageSigningResult, 'INVALID')
          assert.equal(result.messageSigningVerification.signatures.account.status, 'MISSING_SIGNATURE_ENTRY')
          assert.equal(result.messageSigningVerification.signatures.install.status, 'INVALID_INSTALL_KEY_CLAIM')
        }
      },
      {
        name: 'missing account entry → MISSING_SIGNATURE_ENTRY',
        request: {
          path: PATH,
          headers: { ...tokenHeader(eligibleToken), ...dummySignature('other', 'hmac-sha256') }
        },
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'MISSING_SIGNATURE_ENTRY')
      },
      {
        name: 'bad account signature → INVALID',
        request: {
          path: PATH,
          headers: { ...tokenHeader(eligibleToken), ...dummySignature('account', 'hmac-sha256') }
        },
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'INVALID')
      },
      {
        name: 'body without Content-Digest → MISSING_CONTENT_DIGEST',
        request: {
          path: PATH,
          method: 'POST',
          body: 'unsigned-body',
          headers: { ...tokenHeader(eligibleToken), ...dummySignature('account', 'hmac-sha256') }
        },
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'MISSING_CONTENT_DIGEST')
      },
      {
        name: 'wrong Content-Digest → INVALID_CONTENT_DIGEST',
        request: {
          path: PATH,
          method: 'POST',
          body: 'actual-body',
          headers: {
            ...tokenHeader(eligibleToken),
            'Content-Digest': 'sha-256=:YWJj:',
            ...dummySignature('account', 'hmac-sha256')
          }
        },
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'INVALID_CONTENT_DIGEST')
      }
    ]
  },
  {
    name: 'install-signing',
    plugins: undefined,
    vars: {},
    scenarios: [
      {
        name: 'valid install signature → VALID',
        request: (baseUrl) => B.signedInstallRequest(baseUrl, { path: PATH, token: installToken }),
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'VALID')
      },
      {
        name: 'valid signature covers the full query string',
        request: (baseUrl) => B.signedInstallRequest(baseUrl, { path: `${PATH}?amount=1&tag=a&tag=b`, token: installToken }),
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'VALID')
      },
      {
        name: 'changed query string invalidates the signature',
        request: async (baseUrl) => ({
          ...await B.signedInstallRequest(baseUrl, { path: `${PATH}?amount=1`, token: installToken }),
          path: `${PATH}?amount=999`
        }),
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'INVALID')
      },
      {
        name: 'no signing claims and no signature headers → NOT_REQUIRED',
        request: { path: PATH, headers: tokenHeader(arcToken) },
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'NOT_REQUIRED')
      },
      {
        name: 'present install member without a key claim → INVALID_INSTALL_KEY_CLAIM',
        request: {
          path: PATH,
          headers: { ...tokenHeader(arcToken), ...dummySignature('install', 'ecdsa-p256-sha256') }
        },
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'INVALID_INSTALL_KEY_CLAIM')
      },
      {
        name: 'malformed install key claim → INVALID_INSTALL_KEY_CLAIM',
        request: {
          path: PATH,
          headers: { ...tokenHeader(badInstallToken), ...dummySignature('install', 'ecdsa-p256-sha256') }
        },
        expect: ({ result }) => assert.equal(result.messageSigningResult, 'INVALID_INSTALL_KEY_CLAIM')
      },
      {
        name: 'account entry cannot replace required install signature',
        request: {
          path: PATH,
          headers: { ...tokenHeader(installToken), ...dummySignature('account', 'hmac-sha256') }
        },
        expect: ({ result }) => {
          assert.equal(result.messageSigningResult, 'INVALID')
          assert.equal(result.messageSigningVerification.signatures.install.status, 'MISSING_SIGNATURE_ENTRY')
          assert.equal(result.messageSigningVerification.signatures.account.status, 'INVALID_ACCOUNT_KEY_ID_CLAIM')
        }
      }
    ]
  },
  {
    name: 'both-signatures',
    vars: {},
    scenarios: [
      {
        name: 'both claims verify both signatures and preserve the signed body',
        request: (baseUrl) => B.signedBothRequest(baseUrl, { path: PATH, token: bothToken, method: 'POST', body: 'dual-signature-body' }),
        expect: ({ result, body }) => {
          assert.equal(result.messageSigningMode, 'either')
          assert.equal(result.messageSigningResult, 'VALID')
          assert.equal(result.messageSigningVerification.signatures.install.status, 'VALID')
          assert.equal(result.messageSigningVerification.signatures.account.status, 'VALID')
          assert.equal(body.bodyText, 'dual-signature-body')
        }
      },
      ...['install', 'account'].map((name) => ({
        name: `a bad ${name} signature does not hide the other result`,
        request: async (baseUrl) => {
          const request = await B.signedBothRequest(baseUrl, { path: PATH, token: bothToken })
          request.headers.Signature = request.headers.Signature.replace(new RegExp(`${name}=:[^:]+:`), `${name}=:YWJj:`)
          return request
        },
        expect: ({ result }) => {
          assert.equal(result.messageSigningResult, 'INVALID')
          assert.equal(result.messageSigningVerification.signatures[name].status, 'INVALID')
          assert.equal(result.messageSigningVerification.signatures[name === 'install' ? 'account' : 'install'].status, 'VALID')
        }
      })),
      {
        name: 'both claims accept an installation signature alone',
        request: (baseUrl) => B.signedInstallRequest(baseUrl, { path: PATH, token: bothToken }),
        expect: ({ result }) => {
          assert.equal(result.messageSigningMode, 'either')
          assert.equal(result.messageSigningResult, 'VALID')
          assert.equal(result.messageSigningVerification.signatures.install.status, 'VALID')
          assert.equal(result.messageSigningVerification.signatures.account, null)
        }
      },
      {
        name: 'both claims accept an account signature alone',
        request: (baseUrl) => B.signedAccountRequest(baseUrl, { path: PATH, token: bothToken }),
        expect: ({ result }) => {
          assert.equal(result.messageSigningResult, 'VALID')
          assert.equal(result.messageSigningVerification.signatures.install, null)
          assert.equal(result.messageSigningVerification.signatures.account.status, 'VALID')
        }
      }
    ]
  }
]

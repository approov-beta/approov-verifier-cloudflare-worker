import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import crypto from 'node:crypto'
import jwt from 'jsonwebtoken'
import worker from '../src'
import { createSigner, httpbis } from '../src/vendor/http-message-signatures.js'
import { classifyJwtError, validateToken } from '../src/approov/token.js'
import { validateMessageSignatures } from '../src/approov/message-signing.js'
import { evaluateApproovToken } from '../src/approov/evaluate.js'
import { establishContext, resolveApiPolicy } from '../src/config/context.js'
import { errorMessage, errorName } from '../src/utils/errors.js'
import { logError, logInfo, logWarn } from '../src/utils/logging.js'
import { rewriteApiRequest } from '../src/http/proxy.js'
import { decodeBase64OrBase64Url, sha256Base64 as sha256Base64Util, timingSafeStringEqual } from '../src/utils/crypto.js'
import { hasText, parseBoolean, trimOrNull } from '../src/utils/text.js'
import {
  ACCOUNT_DEVICE_ID,
  ACCOUNT_SIGNING_DEVICE_KEY,
  ACCOUNT_SIGNING_KEY_ID,
  ACCOUNT_SIGNING_SECRET_BASE64URL,
  ACCOUNT_SIGNING_SECRET_RAW,
  DEFAULT_TOKEN_KEY_ID,
  DEFAULT_TOKEN_SECRET_RAW,
  EXPIRED_EXP,
  FAIL_PRIVATE_KEY,
  FAIL_PUBLIC_KEY,
  FUTURE_EXP,
  PASS_PRIVATE_KEY,
  PASS_PUBLIC_KEY,
  defaultPassJwk,
  failJwk,
  makeEnv,
  makeBackendConfig,
  passJwk,
  sha256Base64,
  signEs256
} from './fixtures.js'

const DEFAULT_URL = 'http://worker.local/get?hello=world'
const SIGNATURE_FIELDS = ['@method', '@target-uri', 'approov-token']

const { privateKey: UNKNOWN_PRIVATE_KEY } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'prime256v1'
})

const { privateKey: INSTALL_PRIVATE_KEY, publicKey: INSTALL_PUBLIC_KEY } =
  crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })

const TOKEN_FIXTURES = Object.freeze({
  PASS: signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, did: 'pass-token' }),
  FAIL: signEs256(FAIL_PRIVATE_KEY, { exp: FUTURE_EXP, did: 'fail-token' }),
  INVALID_SIG: signEs256(UNKNOWN_PRIVATE_KEY, { exp: FUTURE_EXP, did: 'unknown-signer' }),
  EXPIRED: signEs256(PASS_PRIVATE_KEY, { exp: EXPIRED_EXP, did: 'expired-token' }),
  INVALID_ALG: jwt.sign({ exp: FUTURE_EXP }, 'test-hs384-secret', {
    algorithm: 'HS384',
    noTimestamp: true
  }),
  MALFORMED: 'abc',
  UNPARSABLE: 'eyJhbGciOiJFUzI1NiJ9..',
  PASS_WITH_INSTALL_KEY: signEs256(PASS_PRIVATE_KEY, {
    exp: FUTURE_EXP,
    ipk: INSTALL_PUBLIC_KEY.export({ format: 'der', type: 'spki' }).toString('base64')
  }),
  PASS_WITH_BAD_INSTALL_KEY: signEs256(PASS_PRIVATE_KEY, {
    exp: FUTURE_EXP,
    did: 'pass-bad-install-key',
    ipk: 'not-a-valid-public-key'
  }),
  PASS_WITH_ACCOUNT_KEY: signEs256(PASS_PRIVATE_KEY, {
    exp: FUTURE_EXP,
    did: ACCOUNT_DEVICE_ID,
    mskid: ACCOUNT_SIGNING_KEY_ID
  }),
  PASS_WITH_WRONG_ACCOUNT_KEY: signEs256(PASS_PRIVATE_KEY, {
    exp: FUTURE_EXP,
    did: ACCOUNT_DEVICE_ID,
    mskid: 'different-account-key'
  }),
  PASS_NO_ACCOUNT_KEY: signEs256(PASS_PRIVATE_KEY, {
    exp: FUTURE_EXP,
    did: 'pass-no-account-key'
  })
})

const installFixture = await httpbis.signMessage({
  key: createSigner(INSTALL_PRIVATE_KEY.export({ type: 'pkcs8', format: 'pem' }), 'ecdsa-p256-sha256'),
  name: 'install',
  fields: SIGNATURE_FIELDS
}, {
  method: 'GET',
  url: DEFAULT_URL,
  headers: { 'Approov-Token': TOKEN_FIXTURES.PASS_WITH_INSTALL_KEY }
})
const INSTALL_SIGNATURE_HEADER = installFixture.headers.Signature
const INSTALL_SIGNATURE_INPUT_HEADER = installFixture.headers['Signature-Input']

const BINDING_VALUE = 'Bearer binding-value'
const VALID_BINDING_HASH = sha256Base64(BINDING_VALUE)

const BINDING_TOKEN_FIXTURES = Object.freeze({
  PASS_WITH_CLAIM: signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, pay: VALID_BINDING_HASH }),
  PASS_NO_CLAIM: signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP }),
  FAIL: TOKEN_FIXTURES.FAIL,
  INVALID_SIG: TOKEN_FIXTURES.INVALID_SIG
})

let fetchMock

beforeEach(() => {
  fetchMock = vi.fn(async (request) => {
    return new Response(
      JSON.stringify({
        url: request.url,
        method: request.method,
        headers: Object.fromEntries(request.headers.entries()),
        bodyText: await request.text()
      }),
      {
        status: 200,
        headers: {
          'content-type': 'application/json'
        }
      }
    )
  })

  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

const runWorker = async ({
  headers = {},
  envOverrides = {},
  url = DEFAULT_URL,
  method = 'GET',
  body = undefined
} = {}) => {
  const request = new Request(url, {
    headers,
    method,
    body
  })

  const ctx = createExecutionContext()
  const response = await worker.fetch(request, makeEnv(envOverrides), ctx)
  await waitOnExecutionContext(ctx)

  return response
}

const getHeaderValue = (headers, name) => {
  const entry = Object.entries(headers).find(([k]) => k.toLowerCase() === name.toLowerCase())
  return entry ? entry[1] : undefined
}

const parseApproovResultFromResponse = async (response) => {
  const body = await response.json()
  const encodedResult = getHeaderValue(body.headers, 'Approov-Result')

  expect(encodedResult).toBeDefined()
  return JSON.parse(Buffer.from(encodedResult, 'base64').toString('utf8'))
}

const signHeadersForRequest = async ({
  url,
  method = 'GET',
  headers,
  signatureName,
  key,
  algorithm,
  fields = SIGNATURE_FIELDS,
  paramValues = undefined
}) => {
  const signer = createSigner(key, algorithm)
  const config = {
    key: signer,
    name: signatureName,
    fields
  }
  if (paramValues) {
    config.paramValues = paramValues
  }
  const signed = await httpbis.signMessage(
    config,
    {
      method,
      url,
      headers
    }
  )

  return {
    signature: signed.headers.Signature || signed.headers.signature,
    signatureInput: signed.headers['Signature-Input'] || signed.headers['signature-input']
  }
}

const tamperSignatureHeader = (header, signatureName) => {
  const prefix = `${signatureName}=:`
  const suffix = ':'
  if (!header || !header.startsWith(prefix) || !header.endsWith(suffix)) {
    return header
  }

  const sigB64 = header.slice(prefix.length, -suffix.length)
  const bytes = Buffer.from(sigB64, 'base64')
  bytes[0] = bytes[0] ^ 0xff
  const tamperedB64 = bytes.toString('base64')
  return `${prefix}${tamperedB64}${suffix}`
}

describe('Token outcome matrix (APPROOV_TOKEN_BINDING_ENABLED=false)', () => {
  const cases = [
    {
      name: 'MISSING_HEADER when Approov token header is absent',
      headers: {},
      expectedToken: 'MISSING_HEADER',
      expectedBinding: 'DISABLED',
      expectedMessageSigning: 'NOT_CHECKED'
    },
    {
      name: 'EMPTY_HEADER when Approov token header is blank',
      headers: { 'Approov-Token': '   ' },
      expectedToken: 'EMPTY_HEADER',
      expectedBinding: 'DISABLED',
      expectedMessageSigning: 'NOT_CHECKED'
    },
    {
      name: 'PASS for token signed with pass key',
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS },
      expectedToken: 'PASS',
      expectedBinding: 'DISABLED',
      expectedMessageSigning: 'NOT_REQUIRED'
    },
    {
      name: 'FAIL for token signed with fail key',
      headers: { 'Approov-Token': TOKEN_FIXTURES.FAIL },
      expectedToken: 'FAIL',
      expectedBinding: 'DISABLED',
      expectedMessageSigning: 'NOT_REQUIRED'
    },
    {
      name: 'INVALID_SIG for token signed by unknown key',
      headers: { 'Approov-Token': TOKEN_FIXTURES.INVALID_SIG },
      expectedToken: 'INVALID_SIG',
      expectedBinding: 'DISABLED',
      expectedMessageSigning: 'NOT_CHECKED'
    },
    {
      name: 'INVALID_ALG for unsupported algorithm',
      headers: { 'Approov-Token': TOKEN_FIXTURES.INVALID_ALG },
      expectedToken: 'INVALID_ALG',
      expectedBinding: 'DISABLED',
      expectedMessageSigning: 'NOT_CHECKED'
    },
    {
      name: 'MALFORMED for malformed token structure',
      headers: { 'Approov-Token': TOKEN_FIXTURES.MALFORMED },
      expectedToken: 'MALFORMED',
      expectedBinding: 'DISABLED',
      expectedMessageSigning: 'NOT_CHECKED'
    },
    {
      name: 'UNPARSABLE for syntactically invalid token',
      headers: { 'Approov-Token': TOKEN_FIXTURES.UNPARSABLE },
      expectedToken: 'UNPARSABLE',
      expectedBinding: 'DISABLED',
      expectedMessageSigning: 'NOT_CHECKED'
    },
    {
      name: 'EXPIRED for expired token',
      headers: { 'Approov-Token': TOKEN_FIXTURES.EXPIRED },
      expectedToken: 'EXPIRED',
      expectedBinding: 'DISABLED',
      expectedMessageSigning: 'NOT_CHECKED'
    }
  ]

  it.each(cases)('$name', async ({ headers, expectedToken, expectedBinding, expectedMessageSigning }) => {
    const response = await runWorker({ headers })

    expect(response.status).toBe(200)
    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe(expectedToken)
    expect(result.bindingResult).toBe(expectedBinding)
    expect(result.messageSigningResult).toBe(expectedMessageSigning)
    expect(result.messageSigningMode).toBe(result.messageSigningResult === 'NOT_REQUIRED' ? 'none' : 'unknown')
  })
})

describe('Binding outcome matrix (APPROOV_TOKEN_BINDING_ENABLED=true)', () => {
  const tokenBindingEnv = { APPROOV_TOKEN_BINDING_ENABLED: 'true' }

  const cases = [
    {
      name: 'NOT_CHECKED when token header is missing',
      headers: { Authorization: BINDING_VALUE },
      expectedToken: 'MISSING_HEADER',
      expectedBinding: 'NOT_CHECKED',
      expectedMessageSigning: 'NOT_CHECKED'
    },
    {
      name: 'MISSING_HEADER when binding header is absent',
      headers: { 'Approov-Token': BINDING_TOKEN_FIXTURES.PASS_WITH_CLAIM },
      expectedToken: 'PASS',
      expectedBinding: 'MISSING_HEADER',
      expectedMessageSigning: 'NOT_REQUIRED'
    },
    {
      name: 'EMPTY_HEADER when binding header is blank',
      headers: {
        'Approov-Token': BINDING_TOKEN_FIXTURES.PASS_WITH_CLAIM,
        Authorization: '   '
      },
      expectedToken: 'PASS',
      expectedBinding: 'EMPTY_HEADER',
      expectedMessageSigning: 'NOT_REQUIRED'
    },
    {
      name: 'MISSING_CLAIM when pass token lacks binding claim',
      headers: {
        'Approov-Token': BINDING_TOKEN_FIXTURES.PASS_NO_CLAIM,
        Authorization: BINDING_VALUE
      },
      expectedToken: 'PASS',
      expectedBinding: 'MISSING_CLAIM',
      expectedMessageSigning: 'NOT_REQUIRED'
    },
    {
      name: 'INVALID when binding hash does not match claim',
      headers: {
        'Approov-Token': BINDING_TOKEN_FIXTURES.PASS_WITH_CLAIM,
        Authorization: 'Bearer mismatched-value'
      },
      expectedToken: 'PASS',
      expectedBinding: 'INVALID',
      expectedMessageSigning: 'NOT_REQUIRED'
    },
    {
      name: 'VALID when binding hash matches claim',
      headers: {
        'Approov-Token': BINDING_TOKEN_FIXTURES.PASS_WITH_CLAIM,
        Authorization: BINDING_VALUE
      },
      expectedToken: 'PASS',
      expectedBinding: 'VALID',
      expectedMessageSigning: 'NOT_REQUIRED'
    },
    {
      name: 'MISSING_CLAIM for authentic fail token',
      headers: {
        'Approov-Token': BINDING_TOKEN_FIXTURES.FAIL,
        Authorization: BINDING_VALUE
      },
      expectedToken: 'FAIL',
      expectedBinding: 'MISSING_CLAIM',
      expectedMessageSigning: 'NOT_REQUIRED'
    },
    {
      name: 'NOT_CHECKED for invalid signature token',
      headers: {
        'Approov-Token': BINDING_TOKEN_FIXTURES.INVALID_SIG,
        Authorization: BINDING_VALUE
      },
      expectedToken: 'INVALID_SIG',
      expectedBinding: 'NOT_CHECKED',
      expectedMessageSigning: 'NOT_CHECKED'
    }
  ]

  it.each(cases)('$name', async ({
    headers,
    expectedToken,
    expectedBinding,
    expectedMessageSigning
  }) => {
    const response = await runWorker({
      headers,
      envOverrides: tokenBindingEnv
    })

    expect(response.status).toBe(200)
    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe(expectedToken)
    expect(result.bindingResult).toBe(expectedBinding)
    expect(result.messageSigningResult).toBe(expectedMessageSigning)
  })
})

describe('Token binding enforcement in reject mode (audit 1.2)', () => {
  const rejectBindingEnv = { APPROOV_TOKEN_BINDING_ENABLED: 'true', APPROOV_MODE: 'block', APPROOV_LOGGING_ENABLED: 'true' }

  it('forwards when binding is VALID', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': BINDING_TOKEN_FIXTURES.PASS_WITH_CLAIM,
        Authorization: BINDING_VALUE
      },
      envOverrides: rejectBindingEnv
    })
    expect(response.status).toBe(200)
    expect(fetchMock).toHaveBeenCalled()
  })

  const blockedCases = [
    {
      name: 'rejects when binding header is missing (no silent bypass)',
      headers: { 'Approov-Token': BINDING_TOKEN_FIXTURES.PASS_WITH_CLAIM }
    },
    {
      name: 'rejects when binding header is empty',
      headers: { 'Approov-Token': BINDING_TOKEN_FIXTURES.PASS_WITH_CLAIM, Authorization: '   ' }
    },
    {
      name: 'rejects when the token lacks the binding claim',
      headers: { 'Approov-Token': BINDING_TOKEN_FIXTURES.PASS_NO_CLAIM, Authorization: BINDING_VALUE }
    },
    {
      name: 'rejects when the binding hash does not match',
      headers: { 'Approov-Token': BINDING_TOKEN_FIXTURES.PASS_WITH_CLAIM, Authorization: 'Bearer mismatched-value' }
    }
  ]

  it.each(blockedCases)('$name', async ({ headers }) => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const response = await runWorker({ headers, envOverrides: rejectBindingEnv })
    expect(response.status).toBe(403)
    expect(fetchMock).not.toHaveBeenCalled()
    const blockedLogged = logSpy.mock.calls.some(([message]) =>
      message?.event === 'approov.request' && message.binding !== 'VALID'
    )
    expect(blockedLogged).toBe(true)
  })
})

describe('Echo mode header redaction (audit 4.3)', () => {
  it('redacts credential headers in the echoed response', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': TOKEN_FIXTURES.PASS,
        Authorization: 'Bearer super-secret',
        Cookie: 'session=abc123',
        'X-Custom': 'keep-me'
      },
      envOverrides: { APPROOV_ECHO_MODE: 'true' }
    })

    expect(response.status).toBe(200)
    expect(fetchMock).not.toHaveBeenCalled()

    const body = await response.json()
    expect(getHeaderValue(body.headers, 'authorization')).toBe('[redacted]')
    expect(getHeaderValue(body.headers, 'approov-token')).toBe('[redacted]')
    expect(getHeaderValue(body.headers, 'cookie')).toBe('[redacted]')
    // Non-sensitive headers pass through unchanged.
    expect(getHeaderValue(body.headers, 'x-custom')).toBe('keep-me')
  })
})

describe('Message signing matrix (install mode)', () => {
  const installModeEnv = {}

  it('accepts a valid install signature', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': TOKEN_FIXTURES.PASS_WITH_INSTALL_KEY,
        Signature: INSTALL_SIGNATURE_HEADER,
        'Signature-Input': INSTALL_SIGNATURE_INPUT_HEADER
      },
      envOverrides: installModeEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('PASS')
    expect(result.messageSigningMode).toBe('install')
    expect(result.messageSigningResult).toBe('VALID')
  })

  it('parses a PEM-encoded ipk claim (then verifies the signature against it)', async () => {
    // `ipk` may arrive as PEM text rather than base64 DER. Supply a valid EC
    // P-256 public key in PEM form so the PEM parsing branch runs; the static
    // signature was computed for a different token, so verification then fails —
    // which is exactly the point: the key parsed (no INVALID_INSTALL_KEY_CLAIM)
    // and we reached signature verification.
    const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const ipkPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()
    const token = signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, did: 'pem-install', ipk: ipkPem })

    const response = await runWorker({
      headers: {
        'Approov-Token': token,
        Signature: INSTALL_SIGNATURE_HEADER,
        'Signature-Input': INSTALL_SIGNATURE_INPUT_HEADER
      },
      envOverrides: installModeEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('PASS')
    expect(result.messageSigningResult).toBe('INVALID')
  })

  it('returns MISSING_HEADERS when signature headers are absent', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': TOKEN_FIXTURES.PASS_WITH_INSTALL_KEY
      },
      envOverrides: installModeEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.messageSigningResult).toBe('MISSING_HEADERS')
  })

  it('returns INVALID for tampered install signature bytes', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': TOKEN_FIXTURES.PASS_WITH_INSTALL_KEY,
        Signature: tamperSignatureHeader(INSTALL_SIGNATURE_HEADER, 'install'),
        'Signature-Input': INSTALL_SIGNATURE_INPUT_HEADER
      },
      envOverrides: installModeEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.messageSigningResult).toBe('INVALID')
  })

  it('returns NOT_REQUIRED when signing claims are absent', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': TOKEN_FIXTURES.PASS
      },
      envOverrides: installModeEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.messageSigningResult).toBe('NOT_REQUIRED')

    // A present recognized member must have a trusted key claim.
    const responseWithHeaders = await runWorker({
      headers: {
        'Approov-Token': TOKEN_FIXTURES.PASS,
        Signature: INSTALL_SIGNATURE_HEADER,
        'Signature-Input': INSTALL_SIGNATURE_INPUT_HEADER
      },
      envOverrides: installModeEnv
    })

    const reached = await parseApproovResultFromResponse(responseWithHeaders)
    expect(reached.messageSigningResult).toBe('INVALID_INSTALL_KEY_CLAIM')
  })

  it('returns INVALID_INSTALL_KEY_CLAIM when ipk claim is malformed', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': TOKEN_FIXTURES.PASS_WITH_BAD_INSTALL_KEY,
        Signature: INSTALL_SIGNATURE_HEADER,
        'Signature-Input': INSTALL_SIGNATURE_INPUT_HEADER
      },
      envOverrides: installModeEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.messageSigningResult).toBe('INVALID_INSTALL_KEY_CLAIM')
  })

  it('requires the install entry when only an account entry is supplied', async () => {
    const headers = {
      'Approov-Token': TOKEN_FIXTURES.PASS_WITH_INSTALL_KEY
    }

    const signed = await signHeadersForRequest({
      url: DEFAULT_URL,
      headers,
      signatureName: 'account',
      key: ACCOUNT_SIGNING_DEVICE_KEY,
      algorithm: 'hmac-sha256'
    })

    const response = await runWorker({
      headers: {
        ...headers,
        Signature: signed.signature,
        'Signature-Input': signed.signatureInput
      },
      envOverrides: installModeEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.messageSigningResult).toBe('INVALID')
    expect(result.messageSigningVerification.signatures.install.status).toBe('MISSING_SIGNATURE_ENTRY')
    expect(result.messageSigningVerification.signatures.account.status).toBe('INVALID_ACCOUNT_KEY_ID_CLAIM')
  })
})

describe('Message signing matrix (account mode)', () => {
  const accountModeEnv = {
    APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET: ACCOUNT_SIGNING_SECRET_BASE64URL,
    APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID: ACCOUNT_SIGNING_KEY_ID
  }

  it('accepts a valid account signature', async () => {
    const headers = {
      'Approov-Token': TOKEN_FIXTURES.PASS_WITH_ACCOUNT_KEY
    }

    const signed = await signHeadersForRequest({
      url: DEFAULT_URL,
      headers,
      signatureName: 'account',
      key: ACCOUNT_SIGNING_DEVICE_KEY,
      algorithm: 'hmac-sha256'
    })

    const response = await runWorker({
      headers: {
        ...headers,
        Signature: signed.signature,
        'Signature-Input': signed.signatureInput
      },
      envOverrides: accountModeEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('PASS')
    expect(result.messageSigningMode).toBe('account')
    expect(result.messageSigningResult).toBe('VALID')
  })

  it('validates Content-Digest without consuming the forwarded body', async () => {
    const body = 'signed request body'
    const contentDigest = `sha-256=:${crypto
      .createHash('sha256')
      .update(body, 'utf8')
      .digest('base64')}:`
    const headers = {
      'Approov-Token': TOKEN_FIXTURES.PASS_WITH_ACCOUNT_KEY,
      'Content-Digest': contentDigest
    }

    const signed = await signHeadersForRequest({
      url: DEFAULT_URL,
      method: 'POST',
      headers,
      signatureName: 'account',
      key: ACCOUNT_SIGNING_DEVICE_KEY,
      algorithm: 'hmac-sha256',
      fields: [...SIGNATURE_FIELDS, 'content-digest']
    })

    const response = await runWorker({
      headers: {
        ...headers,
        Signature: signed.signature,
        'Signature-Input': signed.signatureInput
      },
      method: 'POST',
      body,
      envOverrides: accountModeEnv
    })

    const responseBody = await response.json()
    const result = JSON.parse(
      Buffer
        .from(getHeaderValue(responseBody.headers, 'Approov-Result'), 'base64')
        .toString('utf8')
    )

    expect(responseBody.bodyText).toBe(body)
    expect(result.messageSigningResult).toBe('VALID')
  })

  it('rejects Content-Digest bodies over the configured byte limit', async () => {
    const body = 'too large'
    const contentDigest = `sha-256=:${crypto
      .createHash('sha256')
      .update(body, 'utf8')
      .digest('base64')}:`
    const headers = {
      'Approov-Token': TOKEN_FIXTURES.PASS_WITH_ACCOUNT_KEY,
      'Content-Digest': contentDigest
    }

    const signed = await signHeadersForRequest({
      url: DEFAULT_URL,
      method: 'POST',
      headers,
      signatureName: 'account',
      key: ACCOUNT_SIGNING_DEVICE_KEY,
      algorithm: 'hmac-sha256'
    })

    const cancel = vi.spyOn(ReadableStreamDefaultReader.prototype, 'cancel')
    const response = await runWorker({
      headers: {
        ...headers,
        Signature: signed.signature,
        'Signature-Input': signed.signatureInput
      },
      method: 'POST',
      body,
      envOverrides: {
        ...accountModeEnv,
        APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES: '3'
      }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.messageSigningResult).toBe('INVALID_CONTENT_DIGEST')
    expect(result.messageSigningVerification.error).toContain('3 byte limit')
    // The over-limit body branch is released instead of buffering the upload.
    expect(cancel).toHaveBeenCalledTimes(1)
  })

  it('returns INVALID_ACCOUNT_KEY_ID_CLAIM for a present account member when mskid is absent', async () => {
    const headers = {
      'Approov-Token': TOKEN_FIXTURES.PASS_NO_ACCOUNT_KEY
    }

    const signed = await signHeadersForRequest({
      url: DEFAULT_URL,
      headers,
      signatureName: 'account',
      key: ACCOUNT_SIGNING_DEVICE_KEY,
      algorithm: 'hmac-sha256'
    })

    const response = await runWorker({
      headers: {
        ...headers,
        Signature: signed.signature,
        'Signature-Input': signed.signatureInput
      },
      envOverrides: accountModeEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.messageSigningResult).toBe('INVALID_ACCOUNT_KEY_ID_CLAIM')
  })

  it('returns ACCOUNT_KEY_ID_MISMATCH when mskid does not match configured key id', async () => {
    const headers = {
      'Approov-Token': TOKEN_FIXTURES.PASS_WITH_WRONG_ACCOUNT_KEY
    }

    const signed = await signHeadersForRequest({
      url: DEFAULT_URL,
      headers,
      signatureName: 'account',
      key: ACCOUNT_SIGNING_DEVICE_KEY,
      algorithm: 'hmac-sha256'
    })

    const response = await runWorker({
      headers: {
        ...headers,
        Signature: signed.signature,
        'Signature-Input': signed.signatureInput
      },
      envOverrides: accountModeEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.messageSigningResult).toBe('ACCOUNT_KEY_ID_MISMATCH')
  })

  it('requires the account entry when only an install entry is supplied', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': TOKEN_FIXTURES.PASS_WITH_ACCOUNT_KEY,
        Signature: INSTALL_SIGNATURE_HEADER,
        'Signature-Input': INSTALL_SIGNATURE_INPUT_HEADER
      },
      envOverrides: accountModeEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.messageSigningResult).toBe('INVALID')
    expect(result.messageSigningVerification.signatures.account.status).toBe('MISSING_SIGNATURE_ENTRY')
    expect(result.messageSigningVerification.signatures.install.status).toBe('INVALID_INSTALL_KEY_CLAIM')
  })

  it('returns INVALID for tampered account signatures', async () => {
    const headers = {
      'Approov-Token': TOKEN_FIXTURES.PASS_WITH_ACCOUNT_KEY
    }

    const signed = await signHeadersForRequest({
      url: DEFAULT_URL,
      headers,
      signatureName: 'account',
      key: ACCOUNT_SIGNING_DEVICE_KEY,
      algorithm: 'hmac-sha256'
    })

    const response = await runWorker({
      headers: {
        ...headers,
        Signature: tamperSignatureHeader(signed.signature, 'account'),
        'Signature-Input': signed.signatureInput
      },
      envOverrides: accountModeEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.messageSigningResult).toBe('INVALID')
  })
})

describe('Message signing — advanced cryptographic scenarios', () => {
  const accountModeEnv = {
    APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET: ACCOUNT_SIGNING_SECRET_BASE64URL,
    APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID: ACCOUNT_SIGNING_KEY_ID
  }
  const ACCOUNT_KEY = ACCOUNT_SIGNING_DEVICE_KEY

  const digestFor = (algo, nodeAlgo, body) =>
    `${algo}=:${crypto.createHash(nodeAlgo).update(body, 'utf8').digest('base64')}:`

  const runSignedAccountRequest = async ({ body, contentDigest, method = 'POST', paramValues, envOverrides = {} }) => {
    const headers = {
      'Approov-Token': TOKEN_FIXTURES.PASS_WITH_ACCOUNT_KEY,
      ...(contentDigest ? { 'Content-Digest': contentDigest } : {})
    }
    const signed = await signHeadersForRequest({
      url: DEFAULT_URL,
      method,
      headers,
      signatureName: 'account',
      key: ACCOUNT_KEY,
      algorithm: 'hmac-sha256',
      fields: contentDigest
        ? [...SIGNATURE_FIELDS, 'content-digest']
        : SIGNATURE_FIELDS,
      paramValues
    })
    return runWorker({
      headers: { ...headers, Signature: signed.signature, 'Signature-Input': signed.signatureInput },
      method,
      body,
      envOverrides: { ...accountModeEnv, ...envOverrides }
    })
  }

  it('accepts a valid sha-512 Content-Digest end-to-end and preserves the body', async () => {
    const body = 'payload hashed with sha-512'
    const response = await runSignedAccountRequest({
      body,
      contentDigest: digestFor('sha-512', 'sha512', body)
    })

    const responseBody = await response.json()
    const result = JSON.parse(
      Buffer.from(getHeaderValue(responseBody.headers, 'Approov-Result'), 'base64').toString('utf8')
    )
    expect(result.messageSigningResult).toBe('VALID')
    expect(responseBody.bodyText).toBe(body)
  })

  it('accepts a Content-Digest carrying both sha-256 and sha-512', async () => {
    const body = 'multi-digest body'
    const both = `${digestFor('sha-256', 'sha256', body)}, ${digestFor('sha-512', 'sha512', body)}`
    const response = await runSignedAccountRequest({ body, contentDigest: both })

    const result = await parseApproovResultFromResponse(response)
    expect(result.messageSigningResult).toBe('VALID')
  })

  it('rejects a signature whose expiry is in the past', async () => {
    const nowSec = Math.floor(Date.now() / 1000)
    const response = await runSignedAccountRequest({
      body: undefined,
      method: 'GET',
      paramValues: {
        created: new Date((nowSec - 7200) * 1000),
        expires: new Date((nowSec - 3600) * 1000) // an hour ago, well past tolerance
      }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.messageSigningResult).toBe('INVALID')
    expect(result.messageSigningVerification.error).toMatch(/expired/i)
  })

  it('rejects a signature created too far in the future', async () => {
    const nowSec = Math.floor(Date.now() / 1000)
    const response = await runSignedAccountRequest({
      body: undefined,
      method: 'GET',
      paramValues: {
        created: new Date((nowSec + 7200) * 1000), // two hours ahead, beyond tolerance
        expires: new Date((nowSec + 10800) * 1000)
      }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.messageSigningResult).toBe('INVALID')
  })

  it('honours a widened tolerance for a slightly-future signature', async () => {
    const nowSec = Math.floor(Date.now() / 1000)
    const response = await runSignedAccountRequest({
      body: undefined,
      method: 'GET',
      paramValues: {
        created: new Date((nowSec + 120) * 1000), // 2 min ahead
        expires: new Date((nowSec + 3600) * 1000)
      },
      envOverrides: { APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS: '600' } // 10 min skew allowed
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.messageSigningResult).toBe('VALID')
  })

  it('rejects when the signed Content-Digest does not match the forwarded body', async () => {
    const signedBody = 'the body that was signed'
    const response = await runSignedAccountRequest({
      body: 'a different body entirely',
      contentDigest: digestFor('sha-256', 'sha256', signedBody)
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.messageSigningResult).toBe('INVALID_CONTENT_DIGEST')
  })
})

describe('Request handling and configuration validation', () => {
  it('rewrites the upstream request URL and includes Approov-Result header', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': TOKEN_FIXTURES.PASS
      },
      envOverrides: {
        API_DOMAIN: 'api.example.com',
        API_PORT: '8443'
      },
      url: 'http://worker.local/test/path?foo=bar'
    })

    const body = await response.json()

    expect(body.url).toBe('https://api.example.com:8443/test/path?foo=bar')
    expect(body.method).toBe('GET')
    expect(getHeaderValue(body.headers, 'Approov-Result')).toBeDefined()
  })

  it('logs safe evaluation outcomes when APPROOV_DEBUG is enabled', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

    const response = await runWorker({
      headers: {
        'Approov-Token': TOKEN_FIXTURES.PASS
      },
      envOverrides: {
        APPROOV_DEBUG: 'true'
      }
    })

    expect(response.status).toBe(200)

    const hasDecodedApproovResultLog = logSpy.mock.calls.some(([message]) => {
      return typeof message === 'string' && message.includes('approov: Approov evaluation complete')
    })
    const hasMessageSigningDebugLog = logSpy.mock.calls.some(([message]) => {
      return typeof message === 'string' && message.includes('approov: message signing verification complete')
    })

    expect(hasDecodedApproovResultLog).toBe(true)
    expect(hasMessageSigningDebugLog).toBe(true)
  })

  it('loads pass and fail keys from APPROOV_BACKEND_CONFIG', async () => {
    const normalizePem = (pem) => {
      const raw = pem.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\s)/g, '')
      return [
        '-----BEGIN PUBLIC KEY-----',
        raw.match(/.{1,64}/g).join('\n'),
        '-----END PUBLIC KEY-----'
      ].join('\n')
    }

    const passKeyObj = crypto.createPublicKey({ key: normalizePem(PASS_PUBLIC_KEY), format: 'pem' })
    const failKeyObj = crypto.createPublicKey({ key: normalizePem(FAIL_PUBLIC_KEY), format: 'pem' })

    const passJwk = passKeyObj.export({ format: 'jwk' })
    const failJwk = failKeyObj.export({ format: 'jwk' })
    Object.assign(passJwk, { alg: 'ES256', use: 'sig' })
    Object.assign(failJwk, { alg: 'ES256', use: 'sig' })

    const backendConfig = makeBackendConfig({
      passJWKS: { keys: [passJwk] },
      failJWKS: { keys: [failJwk] }
    })

    const passResponse = await runWorker({
      headers: {
        'Approov-Token': TOKEN_FIXTURES.PASS
      },
      envOverrides: {
        APPROOV_BACKEND_CONFIG: backendConfig
      }
    })

    expect(passResponse.status).toBe(200)
    const passResult = await parseApproovResultFromResponse(passResponse)
    expect(passResult.tokenResult).toBe('PASS')

    const failResponse = await runWorker({
      headers: {
        'Approov-Token': TOKEN_FIXTURES.FAIL
      },
      envOverrides: {
        APPROOV_BACKEND_CONFIG: backendConfig
      }
    })

    expect(failResponse.status).toBe(200)
    const failResult = await parseApproovResultFromResponse(failResponse)
    expect(failResult.tokenResult).toBe('FAIL')
  })

  it('selects the correct verification key based on kid from a multi-key JWKS keyset', async () => {
    const normalizePem = (pem) => {
      const raw = pem.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\s)/g, '')
      return [
        '-----BEGIN PUBLIC KEY-----',
        raw.match(/.{1,64}/g).join('\n'),
        '-----END PUBLIC KEY-----'
      ].join('\n')
    }

    const passKeyObj = crypto.createPublicKey({ key: normalizePem(PASS_PUBLIC_KEY), format: 'pem' })
    const passJwk1 = passKeyObj.export({ format: 'jwk' })
    Object.assign(passJwk1, { kid: 'correct-key-id', alg: 'ES256', use: 'sig' })

    const { publicKey: dummyKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const passJwk2 = dummyKey.export({ format: 'jwk' })
    Object.assign(passJwk2, { kid: 'dummy-key-id', alg: 'ES256', use: 'sig' })

    const token = jwt.sign(
      { aud: '', ip: '1.2.3.4', exp: FUTURE_EXP },
      PASS_PRIVATE_KEY,
      { algorithm: 'ES256', header: { kid: 'correct-key-id' }, noTimestamp: true }
    )

    const response = await runWorker({
      headers: {
        'Approov-Token': token
      },
      envOverrides: {
        APPROOV_BACKEND_CONFIG: makeBackendConfig({
          passJWKS: { keys: [passJwk2, passJwk1] },
          failJWKS: { keys: [{ ...failJwk, kid: 'correct-key-id' }] },
          apis: {
            'worker.local': { kid: 'correct-key-id', isPassKeyPresent: true, isFailKeyPresent: true }
          }
        })
      }
    })

    expect(response.status).toBe(200)
    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('PASS')
  })

  it('fails verification when token kid does not match any key in JWKS', async () => {
    const normalizePem = (pem) => {
      const raw = pem.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\s)/g, '')
      return [
        '-----BEGIN PUBLIC KEY-----',
        raw.match(/.{1,64}/g).join('\n'),
        '-----END PUBLIC KEY-----'
      ].join('\n')
    }

    const passKeyObj = crypto.createPublicKey({ key: normalizePem(PASS_PUBLIC_KEY), format: 'pem' })
    const passJwk1 = passKeyObj.export({ format: 'jwk' })
    Object.assign(passJwk1, { kid: 'correct-key-id', alg: 'ES256', use: 'sig' })

    const token = jwt.sign(
      { aud: '', ip: '1.2.3.4', exp: FUTURE_EXP },
      PASS_PRIVATE_KEY,
      { algorithm: 'ES256', header: { kid: 'unknown-key-id' }, noTimestamp: true }
    )

    const response = await runWorker({
      headers: {
        'Approov-Token': token
      },
      envOverrides: {
        APPROOV_BACKEND_CONFIG: makeBackendConfig({
          passJWKS: { keys: [passJwk1] },
          failJWKS: { keys: [{ ...failJwk, kid: 'correct-key-id' }] },
          apis: {
            'worker.local': { kid: 'correct-key-id', isPassKeyPresent: true, isFailKeyPresent: true }
          }
        })
      }
    })

    expect(response.status).toBe(200)
    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).not.toBe('PASS')
  })

  it('supports loading configuration from APPROOV_BACKEND_CONFIG environment variable', async () => {
    const normalizePem = (pem) => {
      const raw = pem.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\s)/g, '')
      return [
        '-----BEGIN PUBLIC KEY-----',
        raw.match(/.{1,64}/g).join('\n'),
        '-----END PUBLIC KEY-----'
      ].join('\n')
    }

    const passKeyObj = crypto.createPublicKey({ key: normalizePem(PASS_PUBLIC_KEY), format: 'pem' })
    const passJwk = passKeyObj.export({ format: 'jwk' })
    Object.assign(passJwk, { kid: 'ecc1', alg: 'ES256', use: 'sig' })

    const failKeyObj = crypto.createPublicKey({ key: normalizePem(FAIL_PUBLIC_KEY), format: 'pem' })
    const failJwk = failKeyObj.export({ format: 'jwk' })
    Object.assign(failJwk, { kid: 'ecc1', alg: 'ES256', use: 'sig' })

    const backendConfig = {
      currentArcEncodingSecret: 'unit-test-arc-secret',
      defaultPassJWKS: { keys: [defaultPassJwk] },
      passJWKS: { keys: [passJwk] },
      failJWKS: { keys: [failJwk] },
      arcFlagMappings: { 1: 'custom-debug' },
      apis: {
        'worker.local': { kid: 'ecc1', isPassKeyPresent: true, isFailKeyPresent: true }
      }
    }

    const token = jwt.sign(
      { aud: '', ip: '1.2.3.4', exp: FUTURE_EXP },
      PASS_PRIVATE_KEY,
      { algorithm: 'ES256', header: { kid: 'ecc1' }, noTimestamp: true }
    )

    const response = await runWorker({
      headers: {
        'Approov-Token': token
      },
      envOverrides: {
        APPROOV_BACKEND_CONFIG: JSON.stringify(backendConfig)
      }
    })

    expect(response.status).toBe(200)
    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('PASS')
  })

  it('passes a token when configured audience matches', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': signEs256(PASS_PRIVATE_KEY, {
          exp: FUTURE_EXP,
          aud: 'api.example.com'
        })
      },
      envOverrides: {
        APPROOV_TOKEN_AUDIENCE: 'api.example.com'
      }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('PASS')
  })

  it('rejects a token when configured audience does not match', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': signEs256(PASS_PRIVATE_KEY, {
          exp: FUTURE_EXP,
          aud: 'other.example.com'
        })
      },
      envOverrides: {
        APPROOV_TOKEN_AUDIENCE: 'api.example.com'
      }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('INVALID_AUD')
  })

  // Two API domains assigned the same keyset key: without an audience check a
  // token issued for one of them also verifies on the other.
  const sharedKeyApi = { kid: '__default__', isPassKeyPresent: true, isFailKeyPresent: true }
  const audienceFromHostEnv = {
    APPROOV_TOKEN_AUDIENCE_FROM_HOST: 'true',
    APPROOV_BACKEND_CONFIG: makeBackendConfig({
      apis: { 'api-one.example.com': sharedKeyApi, 'api-two.example.com': sharedKeyApi }
    })
  }

  it('passes a token whose audience matches the request host', async () => {
    const response = await runWorker({
      url: 'https://api-one.example.com/get',
      headers: {
        'Approov-Token': signEs256(PASS_PRIVATE_KEY, {
          exp: FUTURE_EXP,
          aud: 'api-one.example.com'
        })
      },
      envOverrides: audienceFromHostEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('PASS')
  })

  it('matches the audience against the lowercased request host', async () => {
    const response = await runWorker({
      url: 'https://API-One.Example.com/get',
      headers: {
        'Approov-Token': signEs256(PASS_PRIVATE_KEY, {
          exp: FUTURE_EXP,
          aud: 'api-one.example.com'
        })
      },
      envOverrides: audienceFromHostEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('PASS')
  })

  it('accepts a token on another domain sharing the key when no audience check is configured', async () => {
    const response = await runWorker({
      url: 'https://api-two.example.com/get',
      headers: {
        'Approov-Token': signEs256(PASS_PRIVATE_KEY, {
          exp: FUTURE_EXP,
          aud: 'api-one.example.com'
        })
      },
      envOverrides: { APPROOV_BACKEND_CONFIG: audienceFromHostEnv.APPROOV_BACKEND_CONFIG }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('PASS')
  })

  it('rejects a token issued for another domain served by the same keys', async () => {
    const response = await runWorker({
      url: 'https://api-two.example.com/get',
      headers: {
        'Approov-Token': signEs256(PASS_PRIVATE_KEY, {
          exp: FUTURE_EXP,
          aud: 'api-one.example.com'
        })
      },
      envOverrides: { ...audienceFromHostEnv, APPROOV_MODE: 'block' }
    })

    expect(response.status).toBe(403)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('rejects a default account secret token issued for another domain', async () => {
    const defaultSecretApi = { kid: '', isPassKeyPresent: true, isFailKeyPresent: false }
    const response = await runWorker({
      url: 'https://api-two.example.com/get',
      headers: {
        'Approov-Token': jwt.sign(
          { aud: 'api-one.example.com', exp: FUTURE_EXP },
          DEFAULT_TOKEN_SECRET_RAW,
          { algorithm: 'HS256', noTimestamp: true }
        )
      },
      envOverrides: {
        APPROOV_TOKEN_AUDIENCE_FROM_HOST: 'true',
        APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET: 'true',
        APPROOV_BACKEND_CONFIG: makeBackendConfig({
          apis: { 'api-one.example.com': defaultSecretApi, 'api-two.example.com': defaultSecretApi }
        })
      }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('INVALID_AUD')
  })

  it.each([
    ['empty', ''],
    ['wildcard', '*'],
    ['upstream domain', 'upstream.example.com']
  ])('rejects a %s audience when the audience comes from the host', async (_, aud) => {
    const response = await runWorker({
      url: 'https://api-one.example.com/get',
      headers: {
        'Approov-Token': signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, aud })
      },
      envOverrides: audienceFromHostEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('INVALID_AUD')
  })

  it('rejects a token without an aud claim when the audience comes from the host', async () => {
    const token = jwt.sign(
      { ip: '1.2.3.4', exp: FUTURE_EXP },
      PASS_PRIVATE_KEY,
      { algorithm: 'ES256', header: { kid: '__default__' }, noTimestamp: true }
    )
    const response = await runWorker({
      url: 'https://api-one.example.com/get',
      headers: { 'Approov-Token': token },
      envOverrides: audienceFromHostEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('INVALID_AUD')
  })

  it('still reports FAIL for a failing token whose audience matches the request host', async () => {
    const response = await runWorker({
      url: 'https://api-one.example.com/get',
      headers: {
        'Approov-Token': signEs256(FAIL_PRIVATE_KEY, {
          exp: FUTURE_EXP,
          aud: 'api-one.example.com'
        })
      },
      envOverrides: audienceFromHostEnv
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('FAIL')
  })

  it('returns 500 when both a fixed audience and the host audience are configured', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const response = await runWorker({
      envOverrides: {
        APPROOV_TOKEN_AUDIENCE: 'api.example.com',
        APPROOV_TOKEN_AUDIENCE_FROM_HOST: 'true'
      }
    })

    expect(response.status).toBe(500)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('returns 500 and skips upstream call when required env is missing', async () => {
    const response = await runWorker({
      envOverrides: {
        API_DOMAIN: ''
      }
    })

    expect(response.status).toBe(500)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('returns 500 when account signature mode is enabled without an account secret', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': TOKEN_FIXTURES.PASS_WITH_ACCOUNT_KEY
      },
      envOverrides: {

        APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET: ''
      }
    })

    expect(response.status).toBe(500)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('accepts a raw (non-base64) account secret via auto-detection', async () => {
    const rawSecretEnv = {

      APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET: '***a-raw-secret-not-base64***'
    }

    const response = await runWorker({
      headers: {
        'Approov-Token': TOKEN_FIXTURES.PASS_WITH_ACCOUNT_KEY
      },
      envOverrides: rawSecretEnv
    })

    // A raw secret is valid configuration, so the worker starts up (no 500) and
    // proceeds to evaluate the request rather than failing config validation.
    expect(response.status).not.toBe(500)
  })

  describe('worker modes and log options', () => {
    it.each([204, 205, 304])('returns bodyless rejection status %s without throwing', async (status) => {
      const response = await runWorker({
        headers: { 'Approov-Token': TOKEN_FIXTURES.FAIL },
        envOverrides: {
          APPROOV_MODE: 'block',
          APPROOV_BLOCK_RESPONSE_STATUS: String(status),
          APPROOV_BLOCK_RESPONSE_BODY: 'must not be sent'
        }
      })

      expect(response.status).toBe(status)
      expect(await response.text()).toBe('')
      expect(fetchMock).not.toHaveBeenCalled()
    })

    it('blocks failed requests with the configured block response', async () => {
      const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
      const response = await runWorker({
        headers: {
          'Approov-Token': TOKEN_FIXTURES.FAIL
        },
        envOverrides: {
          APPROOV_MODE: 'block',
          APPROOV_BLOCK_RESPONSE_STATUS: '401',
          APPROOV_BLOCK_RESPONSE_BODY: 'Unauthorized',
          APPROOV_LOGGING_ENABLED: 'true'
        }
      })

      expect(response.status).toBe(401)
      expect(await response.text()).toBe('Unauthorized')
      expect(fetchMock).not.toHaveBeenCalled()

      // Should log the validation failure
      const loggedFailure = logSpy.mock.calls.some(([message]) => {
        return message?.event === 'approov.request' && message.action === 'block'
      })
      expect(loggedFailure).toBe(true)
    })

    it('forwards passing requests without Approov-Result in block mode', async () => {
      const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
      const response = await runWorker({
        headers: {
          'Approov-Token': TOKEN_FIXTURES.PASS
        },
        envOverrides: {
          APPROOV_MODE: 'block',
          APPROOV_LOGGING_ENABLED: 'true'
        }
      })

      expect(response.status).toBe(200)
      expect(fetchMock).toHaveBeenCalled()

      const body = await response.json()
      expect(getHeaderValue(body.headers, 'Approov-Result')).toBeUndefined()

      // Should log the validation pass
      const loggedPass = logSpy.mock.calls.some(([message]) => {
        return message?.event === 'approov.request' && message.validation === 'PASS'
      })
      expect(loggedPass).toBe(true)
    })

    it('forwards passing requests without Approov-Result in block mode', async () => {
      const response = await runWorker({
        headers: {
          'Approov-Token': TOKEN_FIXTURES.PASS
        },
        envOverrides: {
          APPROOV_MODE: 'block',
          APPROOV_TOKEN_ACTION: 'continue'
        }
      })

      expect(response.status).toBe(200)
      expect(fetchMock).toHaveBeenCalled()

      const body = await response.json()
      expect(getHeaderValue(body.headers, 'Approov-Result')).toBeUndefined()
    })

    it('annotates failures when structured logging is disabled', async () => {
      const response = await runWorker({
        headers: {
          'Approov-Token': TOKEN_FIXTURES.FAIL
        },
        envOverrides: {
          APPROOV_MODE: 'annotate',
          APPROOV_LOGGING_ENABLED: 'false'
        }
      })

      expect(response.status).toBe(200)
      expect(fetchMock).toHaveBeenCalled()

      const body = await response.json()
      expect(getHeaderValue(body.headers, 'Approov-Result')).toBeDefined()
    })

    it('annotates failures when structured logging is enabled', async () => {
      const response = await runWorker({
        headers: {
          'Approov-Token': TOKEN_FIXTURES.FAIL
        },
        envOverrides: {
          APPROOV_MODE: 'annotate',
          APPROOV_LOGGING_ENABLED: 'true'
        }
      })

      expect(response.status).toBe(200)
      expect(fetchMock).toHaveBeenCalled()

      const body = await response.json()
      expect(getHeaderValue(body.headers, 'Approov-Result')).toBeDefined()
    })
  })
})

describe('Configuration validation failures (return 500)', () => {
  const invalidConfigs = [
    { name: 'removed reject-on-fail variable', env: { APPROOV_REJECT_ON_FAIL: 'treu' } },
    { name: 'malformed token-binding boolean', env: { APPROOV_TOKEN_BINDING_ENABLED: 'treu' } },
    { name: 'removed annotation variable', env: { APPROOV_ANNOTATE_RESULT: 'maybe' } },
    { name: 'removed failure annotation variable', env: { APPROOV_ANNOTATE_ON_FAIL: 'maybe' } },
    { name: 'malformed debug boolean', env: { APPROOV_DEBUG: 'maybe' } },
    { name: 'malformed echo-mode boolean', env: { APPROOV_ECHO_MODE: 'maybe' } },
    { name: 'malformed default-secret boolean', env: { APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET: 'maybe' } },
    { name: 'removed message signing mode variable', env: { APPROOV_MESSAGE_SIGNING_MODE: 'bogus' } },
    { name: 'negative message signing tolerance', env: { APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS: '-5' } },
    { name: 'non-numeric message signing tolerance', env: { APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS: 'abc' } },
    { name: 'non-digit max body bytes', env: { APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES: 'abc' } },
    { name: 'unsafe-integer max body bytes', env: { APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES: '99999999999999999999' } },
    { name: 'missing pass JWKS', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ passJWKS: null }) } },
    { name: 'missing fail JWKS', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ failJWKS: null }) } },
    { name: 'missing default signing JWK', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ defaultPassJWKS: { keys: [] } }) } },
    { name: 'missing API assignments', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ apis: null }) } },
    { name: 'non-numeric API_PORT', env: { API_PORT: 'abc' } },
    { name: 'trailing-garbage API_PORT', env: { API_PORT: '443abc' } },
    { name: 'out-of-range API_PORT', env: { API_PORT: '70000' } },
    { name: 'zero API_PORT', env: { API_PORT: '0' } },
    { name: 'API_DOMAIN with a scheme', env: { API_DOMAIN: 'https://api.example.com' } },
    { name: 'API_DOMAIN with a path', env: { API_DOMAIN: 'api.example.com/v1' } },
    { name: 'API_DOMAIN with credentials', env: { API_DOMAIN: 'user@api.example.com' } },
    { name: 'API_DOMAIN with an embedded port', env: { API_DOMAIN: 'api.example.com:8443' } },
    { name: 'unparsable API_DOMAIN', env: { API_DOMAIN: 'exa mple' } },
    { name: 'malformed passthrough boolean', env: { API_PASSTHROUGH: 'maybe' } },
    { name: 'passthrough with API_DOMAIN also set', env: { API_PASSTHROUGH: 'true' } },
    { name: 'neither passthrough nor API_DOMAIN', env: { API_PASSTHROUGH: 'false', API_DOMAIN: '' } },
    { name: 'trailing-garbage message signing tolerance', env: { APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS: '12abc' } },
    { name: 'unsafe-integer message signing tolerance', env: { APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS: '99999999999999999999' } },
    { name: 'trailing-garbage fail response status', env: { APPROOV_BLOCK_RESPONSE_STATUS: '403abc' } },
    { name: 'informational fail response status 100', env: { APPROOV_BLOCK_RESPONSE_STATUS: '100' } },
    { name: 'informational fail response status 199', env: { APPROOV_BLOCK_RESPONSE_STATUS: '199' } },
    { name: 'out-of-range fail response status', env: { APPROOV_BLOCK_RESPONSE_STATUS: '999' } },
    { name: 'non-numeric fail response status', env: { APPROOV_BLOCK_RESPONSE_STATUS: 'abc' } },
    { name: 'malformed backend config JSON', env: { APPROOV_BACKEND_CONFIG: '{not json' } },
    { name: 'pass JWKS with empty keys array', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ passJWKS: { keys: [] } }) } },
    { name: 'pass JWKS with only symmetric keys', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ passJWKS: { keys: [{ kty: 'oct', k: 'AAAA', kid: 's' }] } }) } },
    { name: 'fail JWKS with empty keys array', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ failJWKS: { keys: [] } }) } },
    { name: 'non-object signing JWK', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ passJWKS: { keys: [null] } }) } },
    { name: 'signing JWK without use or kid', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ passJWKS: { keys: [{ kty: 'EC', alg: 'ES256' }] } }) } },
    { name: 'unsupported signing algorithm without kid', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ passJWKS: { keys: [{ kty: 'oct', use: 'sig', alg: 'HS384', k: 'AAAA' }] } }) } },
    { name: 'algorithm and key type mismatch without kid', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ passJWKS: { keys: [{ kty: 'RSA', use: 'sig', alg: 'ES256' }] } }) } },
    { name: 'ES256 curve mismatch without kid', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ passJWKS: { keys: [{ kty: 'EC', use: 'sig', alg: 'ES256', crv: 'P-384' }] } }) } },
    { name: 'HS256 key without material', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ defaultPassJWKS: { keys: [{ kty: 'oct', use: 'sig', alg: 'HS256' }] } }) } },
    { name: 'invalid API hostname', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ apis: { 'https://worker.local': {} } }) } },
    { name: 'case-insensitive duplicate API hostname', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ apis: { 'worker.local': {}, 'WORKER.LOCAL': {} } }) } },
    { name: 'non-object API configuration', env: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ apis: { 'worker.local': null } }) } }
  ]

  it.each(invalidConfigs)('returns 500 for $name', async ({ env }) => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const response = await runWorker({
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS },
      envOverrides: env
    })

    expect(response.status).toBe(500)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('requires APPROOV_BACKEND_CONFIG', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const response = await runWorker({
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS },
      envOverrides: { APPROOV_BACKEND_CONFIG: '' }
    })

    expect(response.status).toBe(500)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('Configuration variations (accepted)', () => {
  it('serves requests with ARC decoding disabled when the ARC encoding secret is missing', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const response = await runWorker({
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS },
      envOverrides: { APPROOV_BACKEND_CONFIG: makeBackendConfig({ currentArcEncodingSecret: null }) }
    })

    expect(response.status).toBe(200)
    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('PASS')
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('ARC encoding secrets')
    )
  })

  it('uses a custom Approov token header name', async () => {
    const response = await runWorker({
      headers: { 'X-Approov': TOKEN_FIXTURES.PASS },
      envOverrides: { APPROOV_TOKEN_HEADER_NAME: 'X-Approov' }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('PASS')
  })

  it('loads a differently keyed HS256 verifier alongside an ES256 verifier', async () => {
    const response = await runWorker({
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS },
      envOverrides: {
        APPROOV_BACKEND_CONFIG: makeBackendConfig({
          passJWKS: {
            keys: [{ kty: 'oct', k: 'QUFBQQ', kid: 'sym', alg: 'HS256', use: 'sig' }, passJwk]
          }
        })
      }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('PASS')
  })

  it('ignores encryption-only JWKs in each exported keyset', async () => {
    const encryptionKeys = [
      { kty: 'oct', use: 'enc', alg: 'A256GCMKW', kid: 'enc-by-use', k: 'AAAA' },
      { kty: 'oct', use: 'other', alg: 'A256GCMKW', kid: 'enc-by-alg', k: 'AAAA' }
    ]
    const response = await runWorker({
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS },
      envOverrides: {
        APPROOV_BACKEND_CONFIG: makeBackendConfig({
          passJWKS: { keys: [...encryptionKeys, passJwk] },
          failJWKS: { keys: [...encryptionKeys, failJwk] }
        })
      }
    })

    expect((await parseApproovResultFromResponse(response)).tokenResult).toBe('PASS')
  })

  it('honours a custom binding claim name', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, cnf: VALID_BINDING_HASH }),
        Authorization: BINDING_VALUE
      },
      envOverrides: { APPROOV_TOKEN_BINDING_ENABLED: 'true', APPROOV_TOKEN_BINDING_CLAIM_NAME: 'cnf' }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.bindingResult).toBe('VALID')
  })

  it('honours a custom binding header name', async () => {
    const bindingValue = 'Bearer custom-header-binding'
    const response = await runWorker({
      headers: {
        'Approov-Token': signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, pay: sha256Base64Util(bindingValue) }),
        'X-Bind': bindingValue
      },
      envOverrides: { APPROOV_TOKEN_BINDING_ENABLED: 'true', APPROOV_TOKEN_BINDING_HEADER_NAME: 'X-Bind' }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.bindingResult).toBe('VALID')
  })
})

describe('Default-secret migration support', () => {
  const defaultApiConfig = () => makeBackendConfig({
    apis: {
      'worker.local': { kid: '', isPassKeyPresent: true, isFailKeyPresent: false }
    }
  })

  const signDefault = (payload = {}, kid = undefined, secret = DEFAULT_TOKEN_SECRET_RAW) => jwt.sign(
    { aud: '', ip: '1.2.3.4', exp: FUTURE_EXP, ...payload },
    secret,
    {
      algorithm: 'HS256',
      noTimestamp: true,
      ...(kid === undefined ? {} : { header: { kid } })
    }
  )

  it.each([
    { name: 'without a kid', kid: undefined },
    { name: 'with the exported default kid', kid: DEFAULT_TOKEN_KEY_ID }
  ])('accepts an authentic HS256 default token $name when enabled', async ({ kid }) => {
    const response = await runWorker({
      headers: { 'Approov-Token': signDefault({ did: 'default-pass' }, kid) },
      envOverrides: {
        APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET: 'true',
        APPROOV_BACKEND_CONFIG: defaultApiConfig()
      }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('PASS')
    expect(result.tokenVerification.verification).toEqual({
      apiDomain: 'worker.local',
      source: 'defaultPassJWKS',
      algorithm: 'HS256',
      keyId: DEFAULT_TOKEN_KEY_ID
    })
  })

  it('emits a deployment-wide startup warning whenever compatibility is enabled', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const ctx = establishContext(makeEnv({
      APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET: 'true',
      APPROOV_BACKEND_CONFIG: defaultApiConfig()
    }))

    expect(ctx.isValid).toBe(true)
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('entire Worker deployment')
    )
  })

  it('returns a configuration error for a default-secret API when compatibility is disabled', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const response = await runWorker({
      headers: { 'Approov-Token': signDefault() },
      envOverrides: { APPROOV_BACKEND_CONFIG: defaultApiConfig() }
    })

    expect(response.status).toBe(500)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('never trusts or ARC-decodes a forged default-secret token', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': signDefault({ arc: 'attacker-controlled' }, undefined, 'wrong-default-secret')
      },
      envOverrides: {
        APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET: 'true',
        APPROOV_BACKEND_CONFIG: defaultApiConfig()
      }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('INVALID_SIG')
    expect(result.tokenVerification.decoded).toBeNull()
    expect(result.tokenVerification.verification).toBeNull()
    expect(result.arcProperties).toBeNull()
  })

  it('rejects a default token carrying an unknown kid', async () => {
    const response = await runWorker({
      headers: { 'Approov-Token': signDefault({}, 'unknown-default-kid') },
      envOverrides: {
        APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET: 'true',
        APPROOV_BACKEND_CONFIG: defaultApiConfig()
      }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('INVALID_SIG')
    expect(result.tokenVerification.verification).toBeNull()
  })

  it('accepts old default and new pass/fail keyset tokens concurrently', async () => {
    const migrationConfig = makeBackendConfig({
      passJWKS: { keys: [{ ...passJwk, kid: 'new-key' }] },
      failJWKS: { keys: [{ ...failJwk, kid: 'new-key' }] },
      apis: {
        'worker.local': { kid: '', isPassKeyPresent: true, isFailKeyPresent: false }
      }
    })
    const envOverrides = {
      APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET: 'true',
      APPROOV_BACKEND_CONFIG: migrationConfig
    }
    const tokens = [
      [signDefault(), 'PASS', 'defaultPassJWKS'],
      [jwt.sign({ exp: FUTURE_EXP }, PASS_PRIVATE_KEY, { algorithm: 'ES256', header: { kid: 'new-key' }, noTimestamp: true }), 'PASS', 'passJWKS'],
      [jwt.sign({ exp: FUTURE_EXP }, FAIL_PRIVATE_KEY, { algorithm: 'ES256', header: { kid: 'new-key' }, noTimestamp: true }), 'FAIL', 'failJWKS']
    ]

    for (const [token, expectedStatus, expectedSource] of tokens) {
      const response = await runWorker({ headers: { 'Approov-Token': token }, envOverrides })
      const result = await parseApproovResultFromResponse(response)
      expect(result.tokenResult).toBe(expectedStatus)
      expect(result.tokenVerification.verification.source).toBe(expectedSource)
    }
  })

  it('requires migration keyset kids to exist in both exported keysets', async () => {
    const token = jwt.sign(
      { exp: FUTURE_EXP },
      PASS_PRIVATE_KEY,
      { algorithm: 'ES256', header: { kid: 'future-key' }, noTimestamp: true }
    )
    const response = await runWorker({
      headers: { 'Approov-Token': token },
      envOverrides: {
        APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET: 'true',
        APPROOV_BACKEND_CONFIG: makeBackendConfig({
          passJWKS: { keys: [{ ...passJwk, kid: 'future-key' }] },
          apis: {
            'worker.local': { kid: '', isPassKeyPresent: true, isFailKeyPresent: false }
          }
        })
      }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('INVALID_SIG')
    expect(result.tokenVerification.verification).toBeNull()
  })

  it('immediately rejects cached default tokens after the flag is disabled while keyset traffic continues', async () => {
    const assignedConfig = makeBackendConfig({
      passJWKS: { keys: [{ ...passJwk, kid: 'new-key' }] },
      failJWKS: { keys: [{ ...failJwk, kid: 'new-key' }] },
      apis: {
        'worker.local': { kid: 'new-key', isPassKeyPresent: true, isFailKeyPresent: true }
      }
    })
    const oldResponse = await runWorker({
      headers: { 'Approov-Token': signDefault() },
      envOverrides: { APPROOV_BACKEND_CONFIG: assignedConfig }
    })
    const newResponse = await runWorker({
      headers: {
        'Approov-Token': jwt.sign(
          { exp: FUTURE_EXP },
          PASS_PRIVATE_KEY,
          { algorithm: 'ES256', header: { kid: 'new-key' }, noTimestamp: true }
        )
      },
      envOverrides: { APPROOV_BACKEND_CONFIG: assignedConfig }
    })

    expect((await parseApproovResultFromResponse(oldResponse)).tokenResult).toBe('INVALID_SIG')
    expect((await parseApproovResultFromResponse(newResponse)).tokenResult).toBe('PASS')
  })

  it('supports an RS256 keyset and records the verified path', async () => {
    const passPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    const failPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    const toJwk = (key) => ({
      ...key.export({ format: 'jwk' }),
      kid: 'rsa-key',
      alg: 'RS256',
      use: 'sig'
    })
    const backendConfig = makeBackendConfig({
      passJWKS: { keys: [toJwk(passPair.publicKey)] },
      failJWKS: { keys: [toJwk(failPair.publicKey)] },
      apis: {
        'worker.local': { kid: 'rsa-key', isPassKeyPresent: true, isFailKeyPresent: true }
      }
    })
    const token = jwt.sign(
      { exp: FUTURE_EXP },
      passPair.privateKey,
      { algorithm: 'RS256', header: { kid: 'rsa-key' }, noTimestamp: true }
    )
    const response = await runWorker({
      headers: { 'Approov-Token': token },
      envOverrides: { APPROOV_BACKEND_CONFIG: backendConfig }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('PASS')
    expect(result.tokenVerification.verification).toMatchObject({
      source: 'passJWKS',
      algorithm: 'RS256',
      keyId: 'rsa-key'
    })
  })

  it.each([
    {
      name: 'an unknown incoming hostname',
      url: 'https://unknown.example/get',
      config: makeBackendConfig()
    },
    {
      name: 'a token-disabled API',
      url: DEFAULT_URL,
      config: makeBackendConfig({
        apis: {
          'worker.local': { kid: '', isPassKeyPresent: false, isFailKeyPresent: false }
        }
      })
    }
  ])('returns a configuration error for $name', async ({ url, config }) => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const response = await runWorker({
      url,
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS },
      envOverrides: { APPROOV_BACKEND_CONFIG: config }
    })

    expect(response.status).toBe(500)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('rejects algorithm confusion without attempting a mismatched key type', async () => {
    const token = jwt.sign(
      { exp: FUTURE_EXP },
      'attacker-controlled-secret',
      { algorithm: 'HS256', header: { kid: '__default__' }, noTimestamp: true }
    )
    const response = await runWorker({ headers: { 'Approov-Token': token } })
    const result = await parseApproovResultFromResponse(response)

    expect(result.tokenResult).toBe('INVALID_ALG')
    expect(result.tokenVerification.verification).toBeNull()
  })

  it('classifies an expired fail-key token after pass verification fails', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': signEs256(FAIL_PRIVATE_KEY, { exp: EXPIRED_EXP })
      }
    })
    const result = await parseApproovResultFromResponse(response)

    expect(result.tokenResult).toBe('EXPIRED')
    expect(result.tokenVerification.verification).toBeNull()
  })

  it('handles direct policy resolution and no-candidate verification defensively', async () => {
    expect(() => resolveApiPolicy(null, '')).toThrow('(empty)')

    const ctx = establishContext(makeEnv())
    const tokenWithoutKid = jwt.sign(
      { exp: FUTURE_EXP },
      PASS_PRIVATE_KEY,
      { algorithm: 'ES256', noTimestamp: true }
    )
    const result = await validateToken(
      {
        ...ctx,
        approovAcceptDefaultAccountSecret: true,
        approovTokenDefaultPassKeys: new Map(),
        approovTokenPassKeys: new Map(),
        approovTokenFailKeys: new Map()
      },
      tokenWithoutKid,
      { domain: 'worker.local', kid: '' }
    )

    expect(result.status).toBe('INVALID_SIG')

    const disabledCompatibilityResult = await validateToken(
      {
        ...ctx,
        approovAcceptDefaultAccountSecret: false,
        approovTokenPassKeys: new Map(),
        approovTokenFailKeys: new Map()
      },
      tokenWithoutKid,
      { domain: 'worker.local', kid: '' }
    )
    expect(disabledCompatibilityResult.status).toBe('INVALID_SIG')
  })
})

describe('Enforcement on message-signing failure (reject mode)', () => {
  it('rejects a PASS token when the required signature headers are missing', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const response = await runWorker({
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS_WITH_INSTALL_KEY },
      envOverrides: { APPROOV_MODE: 'block', APPROOV_LOGGING_ENABLED: 'true' }
    })

    expect(response.status).toBe(403)
    expect(fetchMock).not.toHaveBeenCalled()
    const blockedLogged = logSpy.mock.calls.some(([message]) =>
      message?.event === 'approov.request' && message.messageSignature.status === 'MISSING_HEADERS'
    )
    expect(blockedLogged).toBe(true)
  })
})

describe('Token verification edge cases', () => {
  it('rejects a keyset token that omits its API-assigned kid', async () => {
    const tokenWithoutKid = jwt.sign(
      { aud: '', ip: '1.2.3.4', exp: FUTURE_EXP },
      PASS_PRIVATE_KEY,
      { algorithm: 'ES256', noTimestamp: true }
    )
    const response = await runWorker({
      headers: { 'Approov-Token': tokenWithoutKid },
      envOverrides: {
        APPROOV_BACKEND_CONFIG: makeBackendConfig({
          passJWKS: { keys: [{ ...passJwk, kid: 'k1' }] },
          failJWKS: { keys: [{ ...failJwk, kid: 'k1' }] },
          apis: {
            'worker.local': { kid: 'k1', isPassKeyPresent: true, isFailKeyPresent: true }
          }
        })
      }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('INVALID_SIG')
    expect(result.tokenVerification.verification).toBeNull()
  })

  it('treats a non-string binding claim as MISSING_CLAIM', async () => {
    const response = await runWorker({
      headers: {
        'Approov-Token': signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, pay: 12345 }),
        Authorization: BINDING_VALUE
      },
      envOverrides: { APPROOV_TOKEN_BINDING_ENABLED: 'true' }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.bindingResult).toBe('MISSING_CLAIM')
  })

  it('returns ERROR when called without context or token', async () => {
    expect((await validateToken(null, 'token')).status).toBe('ERROR')
    expect((await validateToken({}, null)).status).toBe('ERROR')
    expect((await validateToken({}, '')).status).toBe('ERROR')
  })

  it('returns MALFORMED when decoding the token header throws', async () => {
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {})
    vi.spyOn(jwt, 'decode').mockImplementation(() => {
      throw new Error('decode exploded')
    })

    const ctx = { approovTokenPassKeys: new Map(), approovTokenFailKeys: new Map() }
    const result = await validateToken(ctx, 'any-token', { domain: 'worker.local', kid: 'k1' })

    expect(result.status).toBe('MALFORMED')
    const logged = infoSpy.mock.calls.some(([message]) =>
      typeof message === 'string' && message.includes('failed to decode token header')
    )
    expect(logged).toBe(true)
  })

  it('treats a token header with no alg as alg=null without throwing', async () => {
    // jsonwebtoken always stamps an `alg`, so craft a header that omits it to
    // exercise the `alg || null` fallback during header decoding.
    const header = Buffer.from(JSON.stringify({ typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ exp: FUTURE_EXP })).toString('base64url')
    const noAlgToken = `${header}.${payload}.`

    const ctx = establishContext(makeEnv())
    const result = await validateToken(ctx, noAlgToken, ctx.approovApiPolicies.get('worker.local'))

    // With no signature/alg the token cannot pass, but resolution must be clean.
    expect(result.status).not.toBe('PASS')
  })

  it('rejects configuration when an API key ID has no matching fail key', async () => {
    const token = jwt.sign(
      { aud: '', ip: '1.2.3.4', exp: FUTURE_EXP },
      FAIL_PRIVATE_KEY,
      { algorithm: 'ES256', header: { kid: 'k1' }, noTimestamp: true }
    )

    const response = await runWorker({
      headers: { 'Approov-Token': token },
      envOverrides: {
        APPROOV_BACKEND_CONFIG: makeBackendConfig({
          passJWKS: { keys: [{ ...passJwk, kid: 'k1' }] },
          failJWKS: { keys: [{ ...failJwk, kid: '__default__' }] },
          apis: {
            'worker.local': { kid: 'k1', isPassKeyPresent: true, isFailKeyPresent: true }
          }
        })
      }
    })

    expect(response.status).toBe(500)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('classifyJwtError', () => {
  const cases = [
    { name: 'expiry', err: { name: 'TokenExpiredError', message: 'jwt expired' }, kind: 'EXPIRED' },
    { name: 'malformed', err: { name: 'JsonWebTokenError', message: 'jwt malformed' }, kind: 'MALFORMED' },
    { name: 'missing signature', err: { name: 'JsonWebTokenError', message: 'jwt signature is required' }, kind: 'MALFORMED' },
    { name: 'non-numeric exp', err: { name: 'JsonWebTokenError', message: 'invalid exp value' }, kind: 'MALFORMED' },
    { name: 'non-numeric nbf', err: { name: 'JsonWebTokenError', message: 'invalid nbf value' }, kind: 'MALFORMED' },
    { name: 'invalid algorithm', err: { name: 'JsonWebTokenError', message: 'invalid algorithm' }, kind: 'INVALID_ALG' },
    { name: 'audience', err: { name: 'JsonWebTokenError', message: 'jwt audience invalid' }, kind: 'INVALID_AUD' },
    { name: 'signature', err: { name: 'JsonWebTokenError', message: 'invalid signature' }, kind: 'INVALID_SIG' },
    { name: 'unparsable', err: { name: 'JsonWebTokenError', message: 'invalid token' }, kind: 'UNPARSABLE' },
    { name: 'unrelated JsonWebTokenError', err: { name: 'JsonWebTokenError', message: 'something else' }, kind: 'ERROR' },
    { name: 'unknown error type', err: { name: 'WeirdError', message: 'boom' }, kind: 'ERROR' },
    { name: 'null error', err: null, kind: 'ERROR' }
  ]

  it.each(cases)('classifies $name as $kind', ({ err, kind }) => {
    expect(classifyJwtError(err).kind).toBe(kind)
  })
})

describe('Message signing internals (verifyContentDigest and entry selection)', () => {
  const ACCOUNT_SECRET_BUF = Buffer.from(ACCOUNT_SIGNING_SECRET_RAW, 'utf8')

  const msAccountCtx = (overrides = {}) => ({
    approovMessageSigningMode: 'account',
    approovMessageSigningTolerance: 60,
    approovMessageSigningMaxBodyBytes: 1048576,
    approovAccountMessageSigningSecret: ACCOUNT_SECRET_BUF,
    approovAccountMessageSigningKeyId: null,
    ...overrides
  })

  const VALID_INPUT = 'account=("@method");alg="hmac-sha256";created=1;expires=2'

  const requestWith = (headers, body) => new Request(DEFAULT_URL, {
    method: body === undefined ? 'GET' : 'POST',
    headers,
    body
  })

  it('rejects a present account member when its trusted key claim is absent', async () => {
    const result = await validateMessageSignatures(
      {},
      requestWith({ signature: 'account=:YWJj:', 'signature-input': VALID_INPUT }),
      {}
    )
    expect(result.status).toBe('INVALID_ACCOUNT_KEY_ID_CLAIM')
    expect(result.mode).toBe('none')
  })

  it('returns ACCOUNT_SECRET_NOT_CONFIGURED when account mode lacks a secret', async () => {
    // Config validation normally blocks this at startup, so the branch is only
    // reachable by invoking the validator directly with a secret-less context.
    const result = await validateMessageSignatures(
      msAccountCtx({ approovAccountMessageSigningSecret: null }),
      requestWith({ signature: 'account=:YWJj:', 'signature-input': VALID_INPUT }),
      { did: ACCOUNT_DEVICE_ID, mskid: 'account-key-id-1' }
    )
    expect(result.status).toBe('ACCOUNT_SECRET_NOT_CONFIGURED')
  })

  it('returns MALFORMED_HEADERS for unparsable signature headers', async () => {
    const result = await validateMessageSignatures(
      msAccountCtx(),
      requestWith({ signature: 'account=@@@', 'signature-input': VALID_INPUT }),
      { did: ACCOUNT_DEVICE_ID, mskid: 'account-key-id-1' }
    )
    expect(result.status).toBe('MALFORMED_HEADERS')
  })

  it('returns MISSING_SIGNATURE_ENTRY when the named entry is absent', async () => {
    const result = await validateMessageSignatures(
      msAccountCtx(),
      requestWith({
        signature: 'other=:YWJj:',
        'signature-input': 'other=("@method");alg="hmac-sha256";created=1;expires=2'
      }),
      { did: ACCOUNT_DEVICE_ID, mskid: 'account-key-id-1' }
    )
    expect(result.status).toBe('MISSING_SIGNATURE_ENTRY')
  })

  it('rejects a mismatched Content-Digest', async () => {
    const result = await validateMessageSignatures(
      msAccountCtx(),
      requestWith({
        signature: 'account=:YWJj:',
        'signature-input': VALID_INPUT,
        'content-digest': 'sha-256=:AAAA:'
      }, 'hello'),
      { did: ACCOUNT_DEVICE_ID, mskid: 'account-key-id-1' }
    )
    expect(result.status).toBe('INVALID_CONTENT_DIGEST')
    expect(result.error).toContain('Content digest verification failed')
  })

  it('rejects an unsupported Content-Digest algorithm', async () => {
    const result = await validateMessageSignatures(
      msAccountCtx(),
      requestWith({
        signature: 'account=:YWJj:',
        'signature-input': VALID_INPUT,
        'content-digest': 'md5=:AAAA:'
      }, 'hello'),
      { did: ACCOUNT_DEVICE_ID, mskid: 'account-key-id-1' }
    )
    expect(result.status).toBe('INVALID_CONTENT_DIGEST')
    expect(result.error).toContain('Unsupported content digest algorithm')
  })

  it('rejects a string-form Content-Digest value before comparing bytes', async () => {
    const result = await validateMessageSignatures(
      msAccountCtx(),
      requestWith({
        signature: 'account=:YWJj:',
        'signature-input': VALID_INPUT,
        'content-digest': 'sha-256="abc"'
      }, 'hello'),
      { did: ACCOUNT_DEVICE_ID, mskid: 'account-key-id-1' }
    )
    expect(result.status).toBe('INVALID_CONTENT_DIGEST')
    expect(result.error).toContain('Unsupported Content-Digest value')
  })

  it('validates Content-Digest against an empty body on a bodyless request', async () => {
    // sha-256 of the empty string; a GET carries no body, so the hasher sees no
    // bytes and the digest of "nothing" must match.
    const emptyDigest = crypto.createHash('sha256').update('', 'utf8').digest('base64')
    const result = await validateMessageSignatures(
      msAccountCtx(),
      requestWith({
        signature: 'account=:YWJj:',
        'signature-input': VALID_INPUT,
        'content-digest': `sha-256=:${emptyDigest}:`
      }),
      { did: ACCOUNT_DEVICE_ID, mskid: 'account-key-id-1' }
    )
    // Digest of the absent body matches, so we proceed past the content-digest
    // check and fail during signature verification (the input covers only
    // "@method", missing the required signed fields).
    expect(result.status).toBe('INVALID')
    expect(result.error).toContain('Missing required signed fields')
  })

  it('returns MISSING_CONTENT_DIGEST for a body without a Content-Digest header', async () => {
    const result = await validateMessageSignatures(
      msAccountCtx(),
      requestWith({
        signature: 'account=:YWJj:',
        'signature-input': VALID_INPUT
      }, 'hello'),
      { did: ACCOUNT_DEVICE_ID, mskid: 'account-key-id-1' }
    )
    expect(result.status).toBe('MISSING_CONTENT_DIGEST')
  })

  it('rejects a signature that does not cover the required components', async () => {
    // The entry parses and the timestamps are fine, but "@path", "@authority"
    // and the token header are not signed — the verifier must refuse it before
    // even checking the signature bytes.
    const result = await validateMessageSignatures(
      msAccountCtx(),
      requestWith({
        signature: 'account=:YWJj:',
        'signature-input': VALID_INPUT
      }),
      { did: ACCOUNT_DEVICE_ID, mskid: 'account-key-id-1' }
    )
    expect(result.status).toBe('INVALID')
    expect(result.error).toContain('Missing required signed fields')
  })

  it('rejects a Content-Digest value that is neither bytes nor a string', async () => {
    // `sha-256=123` parses to an Integer item — an unsupported digest value.
    const result = await validateMessageSignatures(
      msAccountCtx(),
      requestWith({
        signature: 'account=:YWJj:',
        'signature-input': VALID_INPUT,
        'content-digest': 'sha-256=123'
      }, 'hello'),
      { did: ACCOUNT_DEVICE_ID, mskid: 'account-key-id-1' }
    )
    expect(result.status).toBe('INVALID_CONTENT_DIGEST')
    expect(result.error).toContain('Unsupported Content-Digest value')
  })

  it('accepts a matching sha-512 Content-Digest (digest passes, signature then fails)', async () => {
    const body = 'hello'
    const digest = crypto.createHash('sha512').update(body, 'utf8').digest('base64')
    const result = await validateMessageSignatures(
      msAccountCtx(),
      requestWith({
        signature: 'account=:YWJj:',
        'signature-input': VALID_INPUT,
        'content-digest': `sha-512=:${digest}:`
      }, body),
      { did: ACCOUNT_DEVICE_ID, mskid: 'account-key-id-1' }
    )
    // The sha-512 digest validates, so the failure comes from signature
    // verification (missing required signed fields), not the content digest.
    expect(result.status).toBe('INVALID')
    expect(result.error).not.toContain('Content digest')
  })
})

describe('rewriteApiRequest', () => {
  it('preserves the root path while rewriting scheme/host/port', () => {
    const out = rewriteApiRequest({ apiHost: 'api.example.com', apiPort: 8443 }, new Request('http://worker.local/'))
    const url = new URL(out.url)
    expect(url.pathname).toBe('/')
    expect(url.host).toBe('api.example.com:8443')
    expect(url.protocol).toBe('https:')
  })

  it('preserves a non-root path and query', () => {
    const out = rewriteApiRequest({ apiHost: 'api.example.com', apiPort: 443 }, new Request('http://worker.local/a/b?x=1'))
    const url = new URL(out.url)
    expect(url.pathname).toBe('/a/b')
    expect(url.search).toBe('?x=1')
  })

  it('preserves the inbound host and port in passthrough mode', () => {
    const out = rewriteApiRequest(
      { apiPassthrough: true, apiHost: '', apiPort: 443 },
      new Request('http://api.example.com:8443/v1/things?x=1')
    )
    const url = new URL(out.url)
    expect(url.host).toBe('api.example.com:8443')
    expect(url.protocol).toBe('https:')
    expect(url.pathname).toBe('/v1/things')
    expect(url.search).toBe('?x=1')
  })

  it('ignores apiHost and apiPort entirely in passthrough mode', () => {
    const out = rewriteApiRequest(
      { apiPassthrough: true, apiHost: 'should-not-be-used.example.com', apiPort: 9999 },
      new Request('https://api.example.com/v1')
    )
    expect(new URL(out.url).host).toBe('api.example.com')
  })

  it('does not follow upstream redirects', () => {
    const out = rewriteApiRequest(
      { apiHost: 'api.example.com', apiPort: 443 },
      new Request('https://worker.local/r')
    )
    expect(out.redirect).toBe('manual')
  })
})

describe('crypto utils', () => {
  it('sha256Base64 matches a reference digest', () => {
    const expected = crypto.createHash('sha256').update('hello', 'utf8').digest('base64')
    expect(sha256Base64Util('hello')).toBe(expected)
  })

  it('timingSafeStringEqual compares values correctly', () => {
    expect(timingSafeStringEqual('abc', 'abc')).toBe(true)
    expect(timingSafeStringEqual('abc', 'abd')).toBe(false)
    expect(timingSafeStringEqual('abc', 'abcd')).toBe(false)
  })

  const decodeCases = [
    { name: 'empty value', input: '', error: 'value is empty' },
    { name: 'invalid characters', input: '!!!', error: 'not valid base64' },
    { name: 'invalid padding', input: 'YWJj=', error: 'not valid base64' },
    { name: 'invalid length', input: 'YWJjZ', error: 'invalid base64/base64url length' },
    { name: 'non-canonical round-trip', input: 'YR', error: 'failed base64/base64url validation' }
  ]

  it.each(decodeCases)('decodeBase64OrBase64Url throws for $name', ({ input, error }) => {
    expect(() => decodeBase64OrBase64Url(input)).toThrow(error)
  })

  it('decodeBase64OrBase64Url decodes valid base64 and base64url', () => {
    expect(decodeBase64OrBase64Url('YWJj').toString('utf8')).toBe('abc')
    expect(decodeBase64OrBase64Url('YT9_').length).toBe(3)
  })
})

describe('text utils', () => {
  it('hasText distinguishes non-empty strings', () => {
    expect(hasText('x')).toBe(true)
    expect(hasText('  ')).toBe(false)
    expect(hasText('')).toBe(false)
    expect(hasText(null)).toBe(false)
    expect(hasText(5)).toBe(false)
  })

  it('trimOrNull trims or returns null', () => {
    expect(trimOrNull('  x  ')).toBe('x')
    expect(trimOrNull('   ')).toBe(null)
    expect(trimOrNull(undefined)).toBe(null)
  })

  const truthy = [true, 'true']
  const falsy = [false, 'false']

  it.each(truthy)('parseBoolean treats %s as true', (value) => {
    expect(parseBoolean(value, false)).toBe(true)
  })

  it.each(falsy)('parseBoolean treats %s as false', (value) => {
    expect(parseBoolean(value, true)).toBe(false)
  })

  it('parseBoolean falls back for unknown or missing values', () => {
    expect(parseBoolean('maybe', true)).toBe(true)
    expect(parseBoolean('maybe', false)).toBe(false)
    expect(parseBoolean(null, true)).toBe(true)
    expect(parseBoolean(undefined, false)).toBe(false)
  })

  it('parseBoolean defaults its fallback to false when omitted', () => {
    expect(parseBoolean('maybe')).toBe(false)
    expect(parseBoolean('on')).toBe(false)
  })
})

describe('logging helpers', () => {
  it('emit handles both the details-present and details-absent forms', () => {
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {})
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    // Without a details argument (default-parameter path).
    logInfo('info-no-details')
    logWarn('warn-no-details')
    logError('error-no-details')
    // With a details payload.
    logInfo('info-with-details', { a: 1 })
    logError('error-with-details', { b: 2 })

    expect(infoSpy).toHaveBeenCalledWith('approov: info-no-details')
    expect(infoSpy).toHaveBeenCalledWith('approov: info-with-details', { a: 1 })
    expect(warnSpy).toHaveBeenCalledWith('approov: warn-no-details')
    expect(errorSpy).toHaveBeenCalledWith('approov: error-no-details')
    expect(errorSpy).toHaveBeenCalledWith('approov: error-with-details', { b: 2 })
  })
})

describe('evaluateApproovToken branches', () => {
  const evalRequest = (headers = {}) => new Request(DEFAULT_URL, { headers })

  it('uses trusted claims from an authentic FAIL token', async () => {
    // An authentic FAIL token without signing claims requires no signature.
    const response = await runWorker({
      headers: { 'Approov-Token': TOKEN_FIXTURES.FAIL },
      envOverrides: { }
    })

    const result = await parseApproovResultFromResponse(response)
    expect(result.tokenResult).toBe('FAIL')
    expect(result.messageSigningMode).toBe('none')
    expect(result.messageSigningResult).toBe('NOT_REQUIRED')
  })

  it('returns ERROR and logs when evaluation throws unexpectedly', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    // A context whose pass-key map is undefined makes validateToken throw after
    // a successful header decode, exercising the top-level catch in evaluate.
    const brokenCtx = {
      approovTokenHeaderName: 'Approov-Token',
      approovTokenBinding: false,
      approovMessageSigningMode: 'disabled',
      approovAcceptDefaultAccountSecret: false,
      approovTokenPassKeys: undefined,
      approovTokenFailKeys: new Map(),
      approovDebug: false
    }

    const out = await evaluateApproovToken(
      brokenCtx,
      evalRequest({ 'Approov-Token': TOKEN_FIXTURES.PASS }),
      { domain: 'worker.local', kid: '__default__', isPassKeyPresent: true, isFailKeyPresent: true }
    )

    expect(out.tokenResult).toBe('ERROR')
    const logged = errorSpy.mock.calls.some(([message]) =>
      typeof message === 'string' && message.includes('token verification error')
    )
    expect(logged).toBe(true)
  })
})

describe('establishContext accepted variations', () => {
  it('accepts a valid non-negative message-signing tolerance', () => {
    const ctx = establishContext(makeEnv({ APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS: '30' }))
    expect(ctx.isValid).toBe(true)
    expect(ctx.approovMessageSigningTolerance).toBe(30)
  })

  it('accepts a valid message-signing max body byte limit', () => {
    const ctx = establishContext(makeEnv({ APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES: '2048' }))
    expect(ctx.isValid).toBe(true)
    expect(ctx.approovMessageSigningMaxBodyBytes).toBe(2048)
  })

  it('applies defaults for header names, claim name and API port when unset', () => {
    // A minimal env (none of the optional header/port settings present) must
    // resolve to the documented defaults.
    const ctx = establishContext({
      APPROOV_MODE: 'annotate',
      APPROOV_BACKEND_CONFIG: makeBackendConfig({ currentArcEncodingSecret: 'secret' }),
      API_DOMAIN: 'api.example.com'
    })

    expect(ctx.isValid).toBe(true)
    expect(ctx.approovTokenHeaderName).toBe('Approov-Token')
    expect(ctx.approovBindingHeaderName).toBe('Authorization')
    expect(ctx.approovBindingClaimName).toBe('pay')
    expect(ctx.apiPort).toBe(443)
  })

  it('memoizes the context per env object', () => {
    const env = makeEnv()
    const first = establishContext(env)
    const second = establishContext(env)
    expect(second).toBe(first)

    // A distinct env object (even with identical values) is parsed afresh.
    const other = establishContext(makeEnv())
    expect(other).not.toBe(first)
  })

  it('rejects duplicate key IDs in a JWKS', () => {
    const ctx = establishContext(makeEnv({
      APPROOV_BACKEND_CONFIG: makeBackendConfig({ passJWKS: { keys: [passJwk, passJwk] } })
    }))

    expect(ctx.isValid).toBe(false)
    expect(ctx.errors).toEqual(expect.arrayContaining([
      expect.stringContaining('duplicate key ID')
    ]))
  })
})

describe('API_PASSTHROUGH configuration', () => {
  it('accepts passthrough when API_DOMAIN and API_PORT are both absent', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const response = await runWorker({
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS },
      envOverrides: { API_PASSTHROUGH: 'true', API_DOMAIN: undefined, API_PORT: undefined }
    })

    expect(response.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(warn.mock.calls.flat().join(' ')).not.toContain('API_PORT')
  })

  it('does not warn when API_PORT is blank under passthrough', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const response = await runWorker({
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS },
      envOverrides: { API_PASSTHROUGH: 'true', API_DOMAIN: undefined, API_PORT: '' }
    })

    expect(response.status).toBe(200)
    expect(warn.mock.calls.flat().join(' ')).not.toContain('API_PORT')
  })

  it('treats a whitespace-only API_DOMAIN as unset under passthrough', async () => {
    const response = await runWorker({
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS },
      envOverrides: { API_PASSTHROUGH: 'true', API_DOMAIN: '   ' }
    })

    expect(response.status).toBe(200)
  })

  it('warns but does not fail when API_PORT is set alongside passthrough', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const response = await runWorker({
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS },
      envOverrides: { API_PASSTHROUGH: 'true', API_DOMAIN: undefined, API_PORT: '8443' }
    })

    expect(response.status).toBe(200)
    expect(warn.mock.calls.flat().join(' ')).toContain('API_PORT')
  })
})

describe('Worker re-entry detection', () => {
  it('returns 508 when a passthrough request already carries the hop marker', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})

    const response = await runWorker({
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS, 'Approov-Gateway-Hop': '1' },
      envOverrides: { API_PASSTHROUGH: 'true', API_DOMAIN: undefined }
    })

    expect(response.status).toBe(508)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('returns 508 in fixed mode when API_DOMAIN is the hostname the marked request arrived on', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})

    const response = await runWorker({
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS, 'Approov-Gateway-Hop': '1' },
      envOverrides: { API_DOMAIN: 'Worker.Local' }
    })

    expect(response.status).toBe(508)
    expect(fetchMock).not.toHaveBeenCalled()
    expect(error.mock.calls.flat().map((entry) => JSON.stringify(entry)).join(' ')).toContain('API_DOMAIN')
  })

  it('forwards an unmarked fixed-mode request whose hostname equals API_DOMAIN', async () => {
    const response = await runWorker({
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS },
      envOverrides: { API_DOMAIN: 'worker.local' }
    })

    expect(response.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('ignores a client-supplied hop marker in fixed mode', async () => {
    const response = await runWorker({
      headers: { 'Approov-Token': TOKEN_FIXTURES.PASS, 'Approov-Gateway-Hop': '1' },
      envOverrides: { API_PASSTHROUGH: 'false' }
    })

    expect(response.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('stamps the hop marker on every forwarded request', () => {
    const out = rewriteApiRequest(
      { apiHost: 'api.example.com', apiPort: 443 },
      new Request('https://worker.local/x')
    )
    expect(out.headers.get('Approov-Gateway-Hop')).toBe('1')
  })

  it('replaces a client-supplied hop marker rather than appending to it', () => {
    const out = rewriteApiRequest(
      { apiHost: 'api.example.com', apiPort: 443 },
      new Request('https://worker.local/x', { headers: { 'Approov-Gateway-Hop': 'forged, values' } })
    )
    expect(out.headers.get('Approov-Gateway-Hop')).toBe('1')
  })
})

describe('errorName', () => {
  it('names the error class and never the message', () => {
    expect(errorName(new TypeError('PRIVATE'))).toBe('TypeError')
    expect(errorName('PRIVATE')).toBe('string')
    expect(errorName(null)).toBe('object')
  })
})

describe('errorMessage', () => {
  it('returns .message for error-like values and stringifies everything else', () => {
    expect(errorMessage(new Error('boom'))).toBe('boom')
    expect(errorMessage({ message: 'has-message' })).toBe('has-message')
    expect(errorMessage('plain string')).toBe('plain string')
    expect(errorMessage(null)).toBe('null')
    expect(errorMessage(undefined)).toBe('undefined')
    expect(errorMessage(42)).toBe('42')
  })
})

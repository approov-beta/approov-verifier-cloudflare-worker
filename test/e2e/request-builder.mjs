/**
 * Synthetic request/token builders for the L2 e2e matrix.
 *
 * Reuses the SAME test key material as the unit suite (test/fixtures.js) so the
 * tokens minted here validate against the e2e Worker deployment, which is
 * configured with the matching test JWKS/secrets (test/e2e/wrangler.e2e.toml).
 */
import crypto from 'node:crypto'
import jwt from 'jsonwebtoken'
import { createSigner, httpbis } from '../../src/vendor/http-message-signatures.js'
import {
  ACCOUNT_DEVICE_ID,
  ACCOUNT_SIGNING_KEY_ID,
  ACCOUNT_SIGNING_SECRET_RAW,
  DEFAULT_TOKEN_KEY_ID,
  DEFAULT_TOKEN_SECRET_RAW,
  EXPIRED_EXP,
  FAIL_PRIVATE_KEY,
  FUTURE_EXP,
  PASS_PRIVATE_KEY,
  sha256Base64,
  signEs256
} from '../fixtures.js'

// Must match currentArcEncodingSecret in APPROOV_BACKEND_CONFIG in wrangler.e2e.toml.
export const ARC_SECRET = 'unit-test-arc-secret'
const ACCOUNT_SECRET = Buffer.from(ACCOUNT_SIGNING_SECRET_RAW, 'utf8')
const S_BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const SIGNATURE_FIELDS = ['@method', '@target-uri', 'approov-token']

const { privateKey: UNKNOWN_PRIVATE_KEY } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'prime256v1'
})
const {
  privateKey: INSTALL_PRIVATE_KEY,
  publicKey: INSTALL_PUBLIC_KEY
} = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })

export const ACCOUNT_KEY_ID = ACCOUNT_SIGNING_KEY_ID
export const INSTALL_PUBLIC_KEY_CLAIM = INSTALL_PUBLIC_KEY
  .export({ format: 'der', type: 'spki' })
  .toString('base64')

/** Mint a PASS token (signed by the pass key). */
export const passToken = (claims = {}) => signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, did: ACCOUNT_DEVICE_ID, ...claims })
/** Mint a FAIL token (signed by the fail key). */
export const failToken = (claims = {}) => signEs256(FAIL_PRIVATE_KEY, { exp: FUTURE_EXP, did: ACCOUNT_DEVICE_ID, ...claims })
/** Mint an expired (otherwise-valid) pass token. */
export const expiredToken = (claims = {}) => signEs256(PASS_PRIVATE_KEY, { exp: EXPIRED_EXP, ...claims })
/** Mint a token signed by an unknown ES256 key. */
export const invalidSignatureToken = (claims = {}) => signEs256(UNKNOWN_PRIVATE_KEY, { exp: FUTURE_EXP, did: ACCOUNT_DEVICE_ID, ...claims })
/** Mint a token carrying an algorithm the worker does not permit. */
export const invalidAlgorithmToken = () => jwt.sign(
  { exp: FUTURE_EXP },
  'e2e-hs384-secret',
  { algorithm: 'HS384', noTimestamp: true }
)
/** Mint a valid token using the exported default HS256 account secret. */
export const defaultSecretToken = (claims = {}) => jwt.sign(
  { aud: '', exp: FUTURE_EXP, ...claims },
  DEFAULT_TOKEN_SECRET_RAW,
  { algorithm: 'HS256', header: { kid: DEFAULT_TOKEN_KEY_ID }, noTimestamp: true }
)

/** SHA-256/base64 of a binding header value (matches the `pay` claim format). */
export const bindingHash = (value) => sha256Base64(value)

const signedRequest = async ({
  baseUrl,
  path,
  token,
  signatureName,
  key,
  algorithm,
  method = 'GET',
  body = undefined
}) => {
  const headers = { 'Approov-Token': token }
  const fields = [...SIGNATURE_FIELDS]
  if (body !== undefined) {
    headers['Content-Digest'] = `sha-256=:${crypto.createHash('sha256').update(body, 'utf8').digest('base64')}:`
    fields.push('content-digest')
  }

  const signer = createSigner(key, algorithm)
  const signed = await httpbis.signMessage(
    { key: signer, name: signatureName, fields },
    {
      method,
      url: baseUrl.replace(/\/$/, '') + path,
      headers
    }
  )

  return {
    path,
    method,
    body,
    headers: {
      ...headers,
      Signature: signed.headers.Signature || signed.headers.signature,
      'Signature-Input': signed.headers['Signature-Input'] || signed.headers['signature-input']
    }
  }
}

/** Build a request with a valid account-level RFC 9421 message signature. */
export const signedAccountRequest = (baseUrl, { path, token, method, body } = {}) => signedRequest({
  baseUrl,
  path,
  token,
  method,
  body,
  signatureName: 'account',
  key: crypto.createHmac('sha512', ACCOUNT_SECRET).update(Buffer.from(jwt.decode(token).did, 'base64')).digest(),
  algorithm: 'hmac-sha256'
})

/** Build a request with a valid install-level RFC 9421 message signature. */
export const signedInstallRequest = (baseUrl, { path, token, method, body } = {}) => signedRequest({
  baseUrl,
  path,
  token,
  method,
  body,
  signatureName: 'install',
  key: INSTALL_PRIVATE_KEY,
  algorithm: 'ecdsa-p256-sha256'
})

/** Build both independent signatures over the same request components. */
export const signedBothRequest = async (baseUrl, options) => {
  const account = await signedAccountRequest(baseUrl, options)
  const install = await signedInstallRequest(baseUrl, options)
  return {
    ...account,
    headers: {
      ...account.headers,
      Signature: `${install.headers.Signature}, ${account.headers.Signature}`,
      'Signature-Input': `${install.headers['Signature-Input']}, ${account.headers['Signature-Input']}`
    }
  }
}

/**
 * Encode a list of ARC codes into an ARC claim string for ARC_SECRET.
 *
 * @param {Number[]} values Monotonic non-decreasing ARC codes.
 * @param {String} [prefix] 5-char ARC prefix.
 * @returns {String} Encoded ARC string.
 */
export const buildArc = (values, prefix = 'AAAAA') => {
  const hmac = crypto.createHmac('sha256', ARC_SECRET).update(prefix, 'utf8').digest()
  let arc = prefix
  let baseIndex = 0
  for (let i = 0; i < values.length; i++) {
    const decodedByte = values[i] - baseIndex
    arc += S_BASE32[decodedByte ^ (hmac[i] & 31)]
    if ((values[i] & 31) === 31) baseIndex += 32
  }
  return arc
}

/**
 * Decode the base64 Approov-Result from an echo-mode response body.
 *
 * @param {Object} echoBody Parsed echo JSON `{ headers, ... }`.
 * @returns {Object|null} Decoded Approov-Result, or null when absent.
 */
export const decodeApproovResult = (echoBody) => {
  const headers = echoBody && echoBody.headers ? echoBody.headers : {}
  const entry = Object.entries(headers).find(([k]) => k.toLowerCase() === 'approov-result')
  if (!entry) return null
  return JSON.parse(Buffer.from(entry[1], 'base64').toString('utf8'))
}

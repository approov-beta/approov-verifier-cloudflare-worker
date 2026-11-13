/**
 * Shared test fixtures and helpers.
 *
 * Single source of truth for key material, token signing, and base environment
 * config used by both the core test suite (`test/unit.spec.js`) and the
 * co-located plugin tests (`plugins/<name>/*.spec.js`).
 */
import crypto from 'node:crypto'
import jwt from 'jsonwebtoken'

export const PASS_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----`

export const FAIL_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrykD7X6nOhvjzL2c
9F9SNq0diTTc69gRNsljmW4Q5z6hRANCAAQ6hqRSh7kYBXGlmrgz/FxdzIsElWYq
w8ssLxD4IdrB4PFTKmfJ6s/SqSzvuLthQE+0ZruWWblN9C2BcrIuxOQD
-----END PRIVATE KEY-----`

export const PASS_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==-----END PUBLIC KEY-----'
export const FAIL_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOoakUoe5GAVxpZq4M/xcXcyLBJVmKsPLLC8Q+CHaweDxUypnyerP0qks77i7YUBPtGa7llm5TfQtgXKyLsTkAw==-----END PUBLIC KEY-----'

export const FUTURE_EXP = 2000000000
export const EXPIRED_EXP = 1

export const ACCOUNT_SIGNING_SECRET_RAW = 'unit-test-account-secret'
export const ACCOUNT_SIGNING_SECRET_BASE64URL = Buffer
  .from(ACCOUNT_SIGNING_SECRET_RAW, 'utf8')
  .toString('base64url')
export const ACCOUNT_SIGNING_KEY_ID = 'account-key-id-1'
export const ACCOUNT_DEVICE_ID = 'AAECAwQFBgcICQoLDA0ODw=='
export const ACCOUNT_SIGNING_DEVICE_KEY = crypto.createHmac('sha512', Buffer.from(ACCOUNT_SIGNING_SECRET_RAW, 'utf8'))
  .update(Buffer.from(ACCOUNT_DEVICE_ID, 'base64'))
  .digest()
export const DEFAULT_TOKEN_SECRET_RAW = 'unit-test-default-token-secret'
export const DEFAULT_TOKEN_KEY_ID = '_HS256'

/**
 * Re-wrap a single-line PEM public key into a multi-line PEM.
 *
 * @param {String} pem Compact PEM string.
 * @returns {String} Normalized multi-line PEM.
 */
export const normalizePem = (pem) => {
  const raw = pem.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\s)/g, '')
  return [
    '-----BEGIN PUBLIC KEY-----',
    raw.match(/.{1,64}/g).join('\n'),
    '-----END PUBLIC KEY-----'
  ].join('\n')
}

/**
 * Build a JWK (with a chosen `kid`) from a PEM public key.
 *
 * @param {String} publicKeyPem PEM public key (compact or multi-line).
 * @param {String} kid Key id to stamp on the JWK.
 * @returns {Object} JWK object.
 */
export const buildJwk = (publicKeyPem, kid) => {
  const keyObj = crypto.createPublicKey({ key: normalizePem(publicKeyPem), format: 'pem' })
  const jwk = keyObj.export({ format: 'jwk' })
  jwk.kid = kid
  jwk.alg = 'ES256'
  jwk.use = 'sig'
  return jwk
}

export const passJwk = buildJwk(PASS_PUBLIC_KEY, '__default__')
export const failJwk = buildJwk(FAIL_PUBLIC_KEY, '__default__')

export const defaultPassJwk = Object.freeze({
  kty: 'oct',
  use: 'sig',
  alg: 'HS256',
  kid: DEFAULT_TOKEN_KEY_ID,
  k: Buffer.from(DEFAULT_TOKEN_SECRET_RAW, 'utf8').toString('base64url')
})

export const BACKEND_CONFIG = Object.freeze({
  currentArcEncodingSecret: 'unit-test-arc-secret',
  defaultPassJWKS: { keys: [defaultPassJwk] },
  passJWKS: { keys: [passJwk] },
  failJWKS: { keys: [failJwk] },
  arcFlagMappings: { 1: 'debug', 2: 'scan-fail' },
  apis: {
    'worker.local': {
      kid: '__default__',
      isPassKeyPresent: true,
      isFailKeyPresent: true,
      comment: 'unit-test keyset API'
    }
  }
})

export const makeBackendConfig = (overrides = {}) => JSON.stringify({
  ...BACKEND_CONFIG,
  ...overrides
})

export const BASE_ENV = Object.freeze({
  APPROOV_MODE: 'annotate',
  APPROOV_TOKEN_HEADER_NAME: 'Approov-Token',
  APPROOV_TOKEN_BINDING_HEADER_NAME: 'Authorization',
  APPROOV_TOKEN_BINDING_CLAIM_NAME: 'pay',
  APPROOV_BACKEND_CONFIG: makeBackendConfig(),
  API_DOMAIN: 'upstream.example.com',
  API_PORT: '443'
})

/**
 * Merge overrides onto the base environment.
 *
 * @param {Object} [overrides] Env overrides.
 * @returns {Object} Combined env object.
 */
export const makeEnv = (overrides = {}) => {
  const env = { ...BASE_ENV, ...overrides }
  // Test builders produce valid block profiles unless a test overrides actions.
  if (env.APPROOV_MODE === 'block') {
    if (!Object.hasOwn(overrides, 'APPROOV_TOKEN_ACTION')) env.APPROOV_TOKEN_ACTION = 'block'
    if (!Object.hasOwn(overrides, 'APPROOV_MESSAGE_SIGNING_ACTION')) env.APPROOV_MESSAGE_SIGNING_ACTION = 'block'
    if ([true, 'true'].includes(env.APPROOV_TOKEN_BINDING_ENABLED) && !Object.hasOwn(overrides, 'APPROOV_TOKEN_BINDING_ACTION')) {
      env.APPROOV_TOKEN_BINDING_ACTION = 'block'
    }
  }
  for (const name of Object.keys(env)) if (env[name] === undefined) delete env[name]
  return env
}

/**
 * Compute a SHA-256/base64 digest (test mirror of the worker helper).
 *
 * @param {*} data Input data.
 * @returns {String} Base64 digest.
 */
export const sha256Base64 = (data) => crypto
  .createHash('sha256')
  .update(data, 'utf8')
  .digest('base64')

/**
 * Sign an ES256 Approov-style token with sensible defaults.
 *
 * @param {String} privateKey PEM private key.
 * @param {Object} [payload] Additional claims.
 * @returns {String} Signed JWT.
 */
export const signEs256 = (privateKey, payload = {}) => jwt.sign(
  { aud: '', ip: '1.2.3.4', ...payload },
  privateKey,
  { algorithm: 'ES256', header: { kid: '__default__' }, noTimestamp: true }
)

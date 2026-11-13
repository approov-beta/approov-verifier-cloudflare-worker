export const APPROOV_PERMITTED_ALGORITHMS = Object.freeze([
  'HS256', 'ES256', 'RS256'
])

export const APPROOV_BINDING_OUTCOMES = Object.freeze({
  DISABLED: 'DISABLED',
  ERROR: 'ERROR',
  EMPTY_HEADER: 'EMPTY_HEADER',
  INVALID: 'INVALID',
  MISSING_CLAIM: 'MISSING_CLAIM',
  MISSING_HEADER: 'MISSING_HEADER',
  NOT_CHECKED: 'NOT_CHECKED',
  VALID: 'VALID'
})

export const APPROOV_TOKEN_OUTCOMES = Object.freeze({
  EMPTY_HEADER: 'EMPTY_HEADER',
  ERROR: 'ERROR',
  EXPIRED: 'EXPIRED',
  FAIL: 'FAIL',
  INVALID_AUD: 'INVALID_AUD',
  INVALID_ALG: 'INVALID_ALG',
  INVALID_SIG: 'INVALID_SIG',
  MALFORMED: 'MALFORMED',
  MISSING_HEADER: 'MISSING_HEADER',
  NOT_CHECKED: 'NOT_CHECKED',
  PASS: 'PASS',
  UNPARSABLE: 'UNPARSABLE'
})

export const APPROOV_MESSAGE_SIGNING_MODES = Object.freeze({
  ACCOUNT: 'account',
  BOTH: 'both',
  EITHER: 'either',
  NONE: 'none',
  INSTALL: 'install',
  UNKNOWN: 'unknown'
})

export const APPROOV_MESSAGE_SIGNING_OUTCOMES = Object.freeze({
  ACCOUNT_KEY_ID_MISMATCH: 'ACCOUNT_KEY_ID_MISMATCH',
  ACCOUNT_SECRET_NOT_CONFIGURED: 'ACCOUNT_SECRET_NOT_CONFIGURED',
  NOT_REQUIRED: 'NOT_REQUIRED',
  ERROR: 'ERROR',
  INVALID: 'INVALID',
  INVALID_CONTENT_DIGEST: 'INVALID_CONTENT_DIGEST',
  INVALID_INSTALL_KEY_CLAIM: 'INVALID_INSTALL_KEY_CLAIM',
  INVALID_ACCOUNT_KEY_ID_CLAIM: 'INVALID_ACCOUNT_KEY_ID_CLAIM',
  INVALID_DEVICE_ID_CLAIM: 'INVALID_DEVICE_ID_CLAIM',
  MALFORMED_HEADERS: 'MALFORMED_HEADERS',
  MISSING_CONTENT_DIGEST: 'MISSING_CONTENT_DIGEST',
  MISSING_HEADERS: 'MISSING_HEADERS',
  MISSING_SIGNATURE_ENTRY: 'MISSING_SIGNATURE_ENTRY',
  NOT_CHECKED: 'NOT_CHECKED',
  VALID: 'VALID'
})

export const APPROOV_MESSAGE_SIGNING_ALGORITHMS = Object.freeze({
  ACCOUNT: 'hmac-sha256',
  INSTALL: 'ecdsa-p256-sha256'
})

export const APPROOV_MESSAGE_SIGNING_REQUIRED_PARAMS = Object.freeze([
  'alg',
  'created',
  'expires'
])

// Method is always required. The configured token header and body digest are
// appended by the verifier. URL coverage may use @target-uri or all four
// separate components; @path and @authority alone omit scheme and query.
export const APPROOV_MESSAGE_SIGNING_REQUIRED_FIELDS = Object.freeze(['@method'])
export const APPROOV_MESSAGE_SIGNING_URL_FIELDS = Object.freeze([
  '@scheme', '@authority', '@path', '@query'
])

export const APPROOV_RESULT_HEADER_NAME = 'Approov-Result'

// Stamped on every forwarded request so a subrequest that re-enters this Worker
// (wrong topology for pass-through, or the global_fetch_strictly_public
// compatibility flag enabled) fails with a clear diagnostic instead of an
// opaque Cloudflare subrequest-depth error.
export const APPROOV_GATEWAY_HOP_HEADER_NAME = 'Approov-Gateway-Hop'

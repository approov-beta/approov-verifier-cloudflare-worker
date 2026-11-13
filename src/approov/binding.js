import { APPROOV_BINDING_OUTCOMES } from '../constants.js'
import { sha256Base64, timingSafeStringEqual } from '../utils/crypto.js'

/**
 * Validate Approov token binding.
 *
 * The worker hashes the configured binding header value (default `Authorization`)
 * with SHA-256/base64 and compares it to the binding claim in the token payload
 * (default `pay`).
 *
 * @param {*} ctx Worker context containing binding header/claim names.
 * @param {*} request Incoming request.
 * @param {*} payload Decoded Approov token payload.
 * @returns {Promise<{ok: Boolean, status: String, claimName: String|null, expected: String|null, actual: String|null}>}
 *   Structured binding verification result.
 */
export const validateBinding = async (ctx, request, payload) => {
  const result = {
    ok: false,
    status: null,
    claimName: null,
    expected: null,
    actual: null
  }

  const binding = request.headers.get(ctx.approovBindingHeaderName)
  if (binding === null) {
    result.status = APPROOV_BINDING_OUTCOMES.MISSING_HEADER
    return result
  }
  if (binding.trim() === '') {
    result.status = APPROOV_BINDING_OUTCOMES.EMPTY_HEADER
    return result
  }

  const claimName = ctx.approovBindingClaimName
  result.claimName = claimName
  const claimValue = payload[claimName]
  if (!claimValue || typeof claimValue !== 'string') {
    result.status = APPROOV_BINDING_OUTCOMES.MISSING_CLAIM
    return result
  }

  const hash = sha256Base64(binding)
  result.expected = claimValue
  result.actual = hash

  if (timingSafeStringEqual(claimValue, hash)) {
    result.ok = true
    result.status = APPROOV_BINDING_OUTCOMES.VALID
    return result
  }

  result.status = APPROOV_BINDING_OUTCOMES.INVALID
  return result
}

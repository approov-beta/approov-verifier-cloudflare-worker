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
 * @returns {{status: String}} Binding verification outcome.
 */
export const validateBinding = (ctx, request, payload) => {
  const binding = request.headers.get(ctx.approovBindingHeaderName)
  if (binding === null) return { status: APPROOV_BINDING_OUTCOMES.MISSING_HEADER }
  if (binding.trim() === '') return { status: APPROOV_BINDING_OUTCOMES.EMPTY_HEADER }

  const claimValue = payload[ctx.approovBindingClaimName]
  if (!claimValue || typeof claimValue !== 'string') return { status: APPROOV_BINDING_OUTCOMES.MISSING_CLAIM }

  return {
    status: timingSafeStringEqual(claimValue, sha256Base64(binding))
      ? APPROOV_BINDING_OUTCOMES.VALID
      : APPROOV_BINDING_OUTCOMES.INVALID
  }
}

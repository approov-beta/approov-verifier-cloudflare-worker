import jwt from 'jsonwebtoken'
import { APPROOV_TOKEN_OUTCOMES, APPROOV_PERMITTED_ALGORITHMS } from '../constants.js'
import { logInfo, logWarn } from '../utils/logging.js'

/**
 * Normalize jsonwebtoken verification exceptions to stable worker outcomes.
 *
 * This isolates dependency-specific error names/messages from the rest of the
 * worker so callers can branch on fixed status values.
 *
 * @param {Error} err Verification error thrown by `jsonwebtoken`.
 * @returns {{kind: String, name: String, message: String}} Classified error details.
 */
export const classifyJwtError = (err) => {
  const name = err && err.name ? String(err.name) : 'UnknownError'
  const message = err && err.message ? String(err.message) : ''

  if (name === 'TokenExpiredError') {
    return { kind: APPROOV_TOKEN_OUTCOMES.EXPIRED, name, message }
  }

  if (name === 'JsonWebTokenError') {
    if (message.toLowerCase().includes('jwt malformed') ||
      message.toLowerCase().includes('jwt signature is required')) {
      return { kind: APPROOV_TOKEN_OUTCOMES.MALFORMED, name, message }
    }
    if (message.toLowerCase().includes('invalid algorithm')) {
      return { kind: APPROOV_TOKEN_OUTCOMES.INVALID_ALG, name, message }
    }
    if (message.toLowerCase().includes('jwt audience invalid')) {
      return { kind: APPROOV_TOKEN_OUTCOMES.INVALID_AUD, name, message }
    }
    if (message.toLowerCase().includes('invalid signature')) {
      return { kind: APPROOV_TOKEN_OUTCOMES.INVALID_SIG, name, message }
    }
    if (message.toLowerCase().includes('invalid token')) {
      return { kind: APPROOV_TOKEN_OUTCOMES.UNPARSABLE, name, message }
    }
  }

  return { kind: APPROOV_TOKEN_OUTCOMES.ERROR, name, message }
}

/**
 * Resolve the audience the token must carry for this request.
 *
 * With `APPROOV_TOKEN_AUDIENCE_FROM_HOST` enabled the audience is the incoming
 * API domain, which is the hostname the client called. Approov sets `aud` to
 * the domain the token was issued for (when the account audience policy is
 * on), so a token issued for one domain is rejected on every other domain,
 * even when they share a keyset key or the default account secret.
 * Otherwise the fixed `APPROOV_TOKEN_AUDIENCE` applies, if any.
 *
 * @param {*} ctx Worker context.
 * @param {*} apiPolicy Resolved policy for the incoming API domain.
 * @returns {String|null} Required audience, or null when no audience check applies.
 */
export const resolveTokenAudience = (ctx, apiPolicy) => ctx.approovTokenAudienceFromHost
  ? apiPolicy.domain
  : ctx.approovTokenAudience || null

/**
 * Validate an Approov token against pass/fail public keys and allowed algorithms.
 *
 * Resolution order:
 * 1. Verify with pass key.
 * 2. If not pass and not a fatal parse/expiry error, verify with fail key.
 *
 * The returned `status` distinguishes security outcomes (`PASS`, `FAIL`,
 * `INVALID_SIG`, etc.) without throwing.
 *
 * @param {*} ctx Worker context containing key material and algorithm config.
 * @param {String} token Raw Approov token from request header.
 * @param {*} apiPolicy Resolved policy for the incoming API domain.
 * @returns {Promise<{ok: Boolean, status: String, decoded: *}>} Verification result.
 */
export const validateToken = async (ctx, token, apiPolicy) => {
  const result = {
    ok: false,
    status: APPROOV_TOKEN_OUTCOMES.ERROR,
    decoded: null,
    verification: null
  }

  if (!ctx || !token || !apiPolicy) {
    result.status = APPROOV_TOKEN_OUTCOMES.ERROR
    return result
  }

  let kid = null
  let alg = null
  let decodedComplete = null
  try {
    decodedComplete = jwt.decode(token, { complete: true })
    if (decodedComplete && decodedComplete.header) {
      kid = decodedComplete.header.kid || null
      alg = decodedComplete.header.alg || null
    }
  } catch (err) {
    logInfo('failed to decode token header', { status: 'MALFORMED' })
    result.status = APPROOV_TOKEN_OUTCOMES.MALFORMED
    return result
  }

  if (!decodedComplete) {
    if (typeof token === 'string' && token.startsWith('ey') && token.includes('.')) {
      result.status = APPROOV_TOKEN_OUTCOMES.UNPARSABLE
    } else {
      result.status = APPROOV_TOKEN_OUTCOMES.MALFORMED
    }
    return result
  }

  if (!alg || !APPROOV_PERMITTED_ALGORITHMS.includes(alg)) {
    result.status = APPROOV_TOKEN_OUTCOMES.INVALID_ALG
    return result
  }

  const passCandidates = []
  const failCandidates = []
  let kidMatchedDifferentAlgorithm = false

  const addCandidate = (collection, verifier) => {
    if (!verifier) return
    if (verifier.alg !== alg) {
      kidMatchedDifferentAlgorithm = true
      return
    }
    collection.push(verifier)
  }

  if (ctx.approovAcceptDefaultAccountSecret) {
    // The account default is specifically the HS256 secret. Never treat other
    // entries in defaultPassJWKS as compatibility candidates.
    if (alg === 'HS256') {
      if (kid) {
        addCandidate(passCandidates, ctx.approovTokenDefaultPassKeys.get(kid))
      } else {
        for (const verifier of ctx.approovTokenDefaultPassKeys.values()) {
          addCandidate(passCandidates, verifier)
        }
      }
    }

    // Migration keyset candidates are deliberately broader than the API's
    // current assignment, but only an explicit token KID exported in both the
    // pass and fail sets is eligible. This allows safe predeployment while
    // preserving fail-token semantics.
    if (kid && ctx.approovTokenPassKeys.has(kid) && ctx.approovTokenFailKeys.has(kid)) {
      addCandidate(passCandidates, ctx.approovTokenPassKeys.get(kid))
      addCandidate(failCandidates, ctx.approovTokenFailKeys.get(kid))
    }
  } else if (apiPolicy.kid) {
    // `__default__` is the internal identifier used when an exported JWK has
    // no KID. Named keysets always require the token to carry the exact KID.
    if ((kid && kid !== apiPolicy.kid) || (!kid && apiPolicy.kid !== '__default__')) {
      result.status = APPROOV_TOKEN_OUTCOMES.INVALID_SIG
      return result
    }
    addCandidate(passCandidates, ctx.approovTokenPassKeys.get(apiPolicy.kid))
    addCandidate(failCandidates, ctx.approovTokenFailKeys.get(apiPolicy.kid))
  }

  if (passCandidates.length === 0 && failCandidates.length === 0) {
    if (!kid) {
      logWarn('token header is missing key id (kid) and no verification candidate is available')
    } else {
      logWarn('no permitted verification candidate is available for token key ID')
    }
    result.status = kidMatchedDifferentAlgorithm
      ? APPROOV_TOKEN_OUTCOMES.INVALID_ALG
      : APPROOV_TOKEN_OUTCOMES.INVALID_SIG
    return result
  }

  const fatalErrors = new Set([
    APPROOV_TOKEN_OUTCOMES.EXPIRED,
    APPROOV_TOKEN_OUTCOMES.INVALID_AUD,
    APPROOV_TOKEN_OUTCOMES.MALFORMED,
    APPROOV_TOKEN_OUTCOMES.UNPARSABLE
  ])

  const audience = resolveTokenAudience(ctx, apiPolicy)

  const verifyWithCandidate = (verifier) => {
    const options = { algorithms: [verifier.alg] }
    if (audience) options.audience = audience
    return jwt.verify(token, verifier.key, options)
  }

  const setVerifiedResult = (verifier, payload, status) => {
    result.ok = status === APPROOV_TOKEN_OUTCOMES.PASS
    result.status = status
    result.decoded = payload
    result.verification = Object.freeze({
      apiDomain: apiPolicy.domain,
      source: verifier.source,
      algorithm: verifier.alg,
      keyId: verifier.kid
    })
    return result
  }

  for (const verifier of passCandidates) {
    try {
      return setVerifiedResult(
        verifier,
        verifyWithCandidate(verifier),
        APPROOV_TOKEN_OUTCOMES.PASS
      )
    } catch (err) {
      const classification = classifyJwtError(err)
      if (!fatalErrors.has(classification.kind)) continue
      logInfo('token verification failed', {
        status: classification.kind
      })
      result.status = classification.kind
      return result
    }
  }

  for (const verifier of failCandidates) {
    try {
      return setVerifiedResult(
        verifier,
        verifyWithCandidate(verifier),
        APPROOV_TOKEN_OUTCOMES.FAIL
      )
    } catch (err) {
      const classification = classifyJwtError(err)
      if (!fatalErrors.has(classification.kind)) continue
      logInfo('token verification failed', {
        status: classification.kind
      })
      result.status = classification.kind
      return result
    }
  }

  result.status = APPROOV_TOKEN_OUTCOMES.INVALID_SIG
  return result
}

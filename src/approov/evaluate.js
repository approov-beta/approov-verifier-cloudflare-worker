import {
  APPROOV_BINDING_OUTCOMES,
  APPROOV_MESSAGE_SIGNING_MODES,
  APPROOV_MESSAGE_SIGNING_OUTCOMES,
  APPROOV_TOKEN_OUTCOMES
} from '../constants.js'
import { logDebug, logError } from '../utils/logging.js'
import { runPlugins } from '../plugin-host.js'
import { resolveApiPolicy } from '../config/context.js'
import { validateBinding } from './binding.js'
import { getMessageSigningMode, validateMessageSignatures } from './message-signing.js'
import { validateToken } from './token.js'
import { parseClientStatus } from './client-status.js'

/**
 * Evaluate the full Approov security envelope for one request.
 *
 * Workflow:
 * 1. Extract and validate Approov token.
 * 2. Optionally decode ARC properties.
 * 3. Optionally run token binding checks.
 * 4. Optionally run message-signing checks.
 *
 * All outcomes are captured in a structured result object suitable for
 * forwarding in the `Approov-Result` header.
 *
 * @param {*} ctx Worker context.
 * @param {*} request Incoming request.
 * @param {*} [resolvedApiPolicy] Pre-resolved incoming API policy.
 * @param {Function|null} [observer] Optional request-local plugin analytics callback.
 * @returns {Promise<*>} Structured Approov evaluation result.
 */
export const evaluateApproovToken = async (ctx, request, resolvedApiPolicy = null, observer = null) => {
  const out = {
    clientStatus: parseClientStatus(request.headers.get(ctx.approovStatusHeaderName)),
    tokenResult: null,
    bindingResult: ctx.approovTokenBinding ? APPROOV_BINDING_OUTCOMES.NOT_CHECKED : APPROOV_BINDING_OUTCOMES.DISABLED,
    messageSigningMode: APPROOV_MESSAGE_SIGNING_MODES.UNKNOWN,
    messageSigningResult: APPROOV_MESSAGE_SIGNING_OUTCOMES.NOT_CHECKED,
    messageSigningVerification: null,
    tokenVerification: null
  }

  logDebug(ctx, 'starting request evaluation', {
    method: request.method,
    tokenHeaderName: ctx.approovTokenHeaderName,
    tokenHeaderPresent: request.headers.has(ctx.approovTokenHeaderName),
    bindingStrategy: ctx.approovTokenBinding ? 'token-binding' : 'token',
    messageSigningMode: APPROOV_MESSAGE_SIGNING_MODES.UNKNOWN
  })

  const approovToken = request.headers.get(ctx.approovTokenHeaderName)
  if (approovToken === null) {
    out.tokenResult = APPROOV_TOKEN_OUTCOMES.MISSING_HEADER
    logDebug(ctx, 'token header missing', {
      tokenHeaderName: ctx.approovTokenHeaderName
    })
    return out
  }

  if (approovToken.trim() === '') {
    out.tokenResult = APPROOV_TOKEN_OUTCOMES.EMPTY_HEADER
    logDebug(ctx, 'token header empty', {
      tokenHeaderName: ctx.approovTokenHeaderName
    })
    return out
  }

  try {
    const apiPolicy = resolvedApiPolicy || resolveApiPolicy(ctx, new URL(request.url).hostname)
    const tokenVerification = await validateToken(ctx, approovToken, apiPolicy)
    out.tokenVerification = tokenVerification
    out.tokenResult = tokenVerification.status
    logDebug(ctx, 'token verification complete', {
      tokenResult: out.tokenResult,
      ok: tokenVerification.ok
    })

    const trusted = tokenVerification.status === APPROOV_TOKEN_OUTCOMES.PASS ||
      tokenVerification.status === APPROOV_TOKEN_OUTCOMES.FAIL
    if (trusted) {
      if (ctx.approovTokenBinding) {
        try {
          const bindingVerification = await validateBinding(ctx, request, tokenVerification.decoded)
          out.bindingResult = bindingVerification.status
        } catch {
          out.bindingResult = APPROOV_BINDING_OUTCOMES.ERROR
          logError('token binding verification error', { status: 'ERROR' })
        }
      }
      try {
        out.messageSigningMode = getMessageSigningMode(tokenVerification.decoded, ctx)
        const signing = await validateMessageSignatures(ctx, request, tokenVerification.decoded)
        out.messageSigningVerification = signing
        out.messageSigningResult = signing.status
        if (signing.status === 'ERROR') logError('message signing verification error', { status: 'ERROR' })
      } catch {
        out.messageSigningResult = APPROOV_MESSAGE_SIGNING_OUTCOMES.ERROR
        logError('message signing verification error', { status: 'ERROR' })
      }
    }

    logDebug(ctx, 'binding verification complete', { status: out.bindingResult })
    logDebug(ctx, 'message signing verification complete', { status: out.messageSigningResult })

    // Drop-in plugins (e.g. ARC) annotate the result. They are isolated and
    // never affect pass/fail enforcement.
    await runPlugins(ctx, { request, approovToken, tokenVerification }, out, observer)
    return out
  } catch (err) {
    out.tokenResult = APPROOV_TOKEN_OUTCOMES.ERROR
    logError('token verification error', { status: 'ERROR' })
    return out
  }
}

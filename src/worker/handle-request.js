import { APPROOV_GATEWAY_HOP_HEADER_NAME, APPROOV_RESULT_HEADER_NAME } from '../constants.js'
import { evaluateApproovToken } from '../approov/evaluate.js'
import { establishContext, resolveApiPolicy } from '../config/context.js'
import { isProtectedPath } from '../config/protected-paths.js'
import { rewriteApiRequest } from '../http/proxy.js'
import { createAnalytics } from '../analytics.js'
import { assessProtection, shouldBlock } from '../approov/policy.js'
import { logDebug, logError } from '../utils/logging.js'
import { errorMessage } from '../utils/errors.js'

// Header names that must never be reflected verbatim in echo-mode output.
const ALWAYS_REDACTED_ECHO_HEADERS = Object.freeze(['authorization', 'cookie', 'set-cookie'])

/**
 * Build the header map for an echo-mode response, redacting credential headers
 * so the testing endpoint does not reflect tokens/secrets back to the caller.
 *
 * @param {Headers} headers Outgoing request headers.
 * @param {*} ctx Worker context (for configured token/binding header names).
 * @returns {Object} Plain header map with sensitive values replaced.
 */
const buildEchoHeaders = (headers, ctx) => {
  const sensitive = new Set(ALWAYS_REDACTED_ECHO_HEADERS)
  sensitive.add(ctx.approovTokenHeaderName.toLowerCase())
  /* istanbul ignore else -- defensive: approovBindingHeaderName always resolves
     to a non-empty value (defaults to 'Authorization'), so the else never runs. */
  if (ctx.approovBindingHeaderName) {
    sensitive.add(ctx.approovBindingHeaderName.toLowerCase())
  }

  const out = {}
  for (const [name, value] of headers.entries()) {
    out[name] = sensitive.has(name.toLowerCase()) ? '[redacted]' : value
  }
  return out
}

const ERROR_RESULT = Object.freeze({
  clientStatus: null,
  tokenResult: 'ERROR',
  bindingResult: 'NOT_CHECKED',
  messageSigningMode: 'unknown',
  messageSigningResult: 'NOT_CHECKED',
  messageSigningVerification: null,
  tokenVerification: null
})
// A literal fallback remains usable if a plugin's JSON serialization fails.
const ERROR_RESULT_BASE64 = Buffer.from(JSON.stringify(ERROR_RESULT)).toString('base64')

/** Evaluate, enforce the selected actions, and optionally annotate the origin request. */
export const handleRequest = async (request, env) => {
  let analytics = null
  try { analytics = createAnalytics(env) } catch { /* best effort */ }
  try {
    return await handleRequestWithAnalytics(request, env, analytics)
  } finally {
    try { analytics?.emit() } catch { /* never replace the response or exception */ }
  }
}

const handleRequestWithAnalytics = async (request, env, analytics) => {
  const respond = (response, action, upstreamStatus = null) => {
    analytics?.respond(response, action, upstreamStatus)
    return response
  }
  const ctx = establishContext(env)
  analytics?.configure(ctx, request)
  if (!ctx.isValid) {
    logError('unable to establish context', {
      errorCount: ctx.errors.length
    })

    return respond(new Response('Internal Server Error', { status: 500 }), 'error')
  }

  // A request that already carries the hop marker and would be forwarded to
  // the hostname it arrived on came back to this Worker instead of reaching
  // the origin. That is every marked request in pass-through mode, and in
  // fixed mode one whose hostname equals API_DOMAIN. Fail closed with a
  // distinct status: continuing would recurse until Cloudflare's subrequest
  // limit and report an unrelated error. A marker on any other fixed-mode
  // request is client-supplied and is ignored.
  const url = new URL(request.url)
  if (request.headers.has(APPROOV_GATEWAY_HOP_HEADER_NAME) &&
    (ctx.apiPassthrough || url.hostname === ctx.apiHost.toLowerCase())) {
    logError('worker re-entered its own route', {
      message: ctx.apiPassthrough
        ? 'API_PASSTHROUGH requires the Worker Route topology with the global_fetch_strictly_public compatibility flag disabled'
        : 'API_DOMAIN is the hostname this Worker serves; point it at the origin or use the Worker Route topology'
    })
    return respond(new Response('Loop Detected', { status: 508 }), 'error')
  }

  let apiPolicy
  try {
    apiPolicy = resolveApiPolicy(ctx, url.hostname)
  } catch (err) {
    // The reason names only the incoming hostname and the unmet requirement,
    // never key material, and is what an operator needs to fix the 500.
    logError('unable to resolve incoming API policy', { reason: errorMessage(err) })
    return respond(new Response('Internal Server Error', { status: 500 }), 'error')
  }

  // A path outside APPROOV_PROTECTED_PATHS is forwarded unchecked and
  // unannotated. Without that setting every path is protected.
  const protectedPath = isProtectedPath(ctx, url.pathname)
  let approovResultBase64 = null

  if (protectedPath) {
    let approovResult = null
    let evaluationError = false

    try {
      approovResult = await evaluateApproovToken(ctx, request, apiPolicy, analytics?.observePlugin)
      logDebug(ctx, 'Approov evaluation complete', {
        tokenResult: approovResult.tokenResult,
        bindingResult: approovResult.bindingResult,
        messageSigningResult: approovResult.messageSigningResult
      })

      if (ctx.approovMode === 'annotate') {
        approovResultBase64 = Buffer.from(JSON.stringify(approovResult)).toString('base64')
      }
    } catch (err) {
      evaluationError = true
      logError('unrecoverable error caught')
      approovResult = approovResult || ERROR_RESULT
      approovResultBase64 = ERROR_RESULT_BASE64
    }
    const failures = assessProtection(approovResult)
    analytics?.evaluated(approovResult, Object.values(failures).some(Boolean), evaluationError)

    if (shouldBlock(ctx, failures)) {
      const statusCode = ctx.approovBlockResponseStatus
      const body = [204, 205, 304].includes(statusCode) ? null : ctx.approovBlockResponseBody
      return respond(new Response(body, { status: statusCode }), 'block')
    }
  } else {
    logDebug(ctx, 'path is outside APPROOV_PROTECTED_PATHS: forwarding unchecked')
  }

  const apiRequest = rewriteApiRequest(ctx, request)
  // The Approov-Result header is trust-bearing: a client-supplied value must
  // never reach the upstream, so it is stripped unconditionally before the
  // worker optionally attaches its own.
  apiRequest.headers.delete(APPROOV_RESULT_HEADER_NAME)
  logDebug(ctx, 'rewrote upstream request', {
    method: apiRequest.method
  })

  if (ctx.approovMode === 'annotate' && approovResultBase64) {
    apiRequest.headers.set(APPROOV_RESULT_HEADER_NAME, approovResultBase64)
  }

  if (ctx.approovEchoMode) {
    logDebug(ctx, 'echo mode enabled: replying with received message')
    const bodyText = await apiRequest.text()
    return respond(new Response(
      JSON.stringify({
        url: apiRequest.url,
        method: apiRequest.method,
        headers: buildEchoHeaders(apiRequest.headers, ctx),
        bodyText
      }),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json'
        }
      }
    ), 'echo')
  }

  let response
  try {
    response = await fetch(apiRequest)
  } catch {
    // An unreachable upstream is a gateway failure, not a Worker exception:
    // answer with a plain 502 and a Worker log line instead of an edge error
    // page. The exception text is not logged because it can carry the URL.
    logError('upstream request failed', { status: 502 })
    return respond(new Response('Bad Gateway', { status: 502 }), 'error')
  }
  logDebug(ctx, 'upstream response received', {
    status: response.status
  })

  return respond(response, protectedPath ? 'forward' : 'unprotected', response.status)
}

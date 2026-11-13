import { APPROOV_GATEWAY_HOP_HEADER_NAME } from '../constants.js'

/**
 * Rewrite an incoming worker request to target the upstream API.
 *
 * The function preserves method/path/query/headers/body. In the default fixed
 * mode it rewrites scheme/host/port from runtime context. In pass-through mode
 * (`ctx.apiPassthrough`) it keeps the inbound host and port so the same-zone
 * subrequest reaches the origin behind that hostname's own DNS record, letting
 * one deployment serve several Worker Routes. The scheme is forced to https in
 * both modes.
 *
 * @param {*} ctx Worker context containing `apiPassthrough`, `apiHost` and `apiPort`.
 * @param {*} request Incoming client request.
 * @returns {Request} New request addressed to the upstream API.
 */
export const rewriteApiRequest = (ctx, request) => {
  const url = new URL(request.url)

  url.protocol = 'https:'
  if (!ctx.apiPassthrough) {
    url.host = ctx.apiHost
    url.port = String(ctx.apiPort)
  }

  const headers = new Headers(request.headers)

  // Set (never append): a client-supplied value must not survive into the
  // forwarded request, or re-entry detection could be spoofed or confused.
  headers.set(APPROOV_GATEWAY_HOP_HEADER_NAME, '1')

  // GET and HEAD requests cannot contain a request body or body-length headers.
  // Standard Fetch API throws a TypeError if a body is present on GET/HEAD,
  // and some upstream servers reject them (returning a 501 Not Implemented or
  // 411 Length Required) when headers like 'content-length' are present.
  // This is particularly relevant for some client libraries (like Flutter's dio/dio2
  // service layers) that may send GET requests with an empty body indicator and
  // a 'content-length' header, which we strip here to avoid upstream errors.
  const hasBody = request.method !== 'GET' && request.method !== 'HEAD'
  if (!hasBody) {
    headers.delete('content-length')
    headers.delete('transfer-encoding')
  }

  return new Request(url.toString(), {
    method: request.method,
    headers,
    body: hasBody ? request.body : null,
    // Annotation mode relies on backend enforcement for this exact request.
    // A shared cache must not answer before that middleware sees the result.
    // Cloudflare-hosted upstreams also need the documented cache-bypass rules.
    cache: ctx.approovMode === 'annotate' ? 'no-store' : undefined,
    // A transparent proxy must hand 3xx responses to the client unchanged
    // rather than following them at the edge. In pass-through mode a followed
    // same-host redirect would also re-enter the Worker Route.
    redirect: 'manual'
  })
}

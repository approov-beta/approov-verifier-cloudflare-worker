# Backend Enforcement and Trusted Ingress

`APPROOV_MODE="annotate"` validates each request, removes any client-supplied
`Approov-Result` header, and attaches its own base64-encoded result before forwarding the
request. The backend is the enforcement point in this mode.

This guide applies to annotation mode. Block mode strips `Approov-Result`; the Worker applies its explicit layer actions instead.

## Required backend decision

Run Approov enforcement in centralized middleware before routing to business logic or performing
expensive work. Apply it to every operation that requires a valid mobile app instance; define
public, health-check, webhook, browser preflight, and non-mobile exceptions explicitly instead of
making a missing result pass globally.

The middleware must reject the request when the `Approov-Result` header is missing, duplicated,
too large, not valid base64, not valid UTF-8 JSON, or does not have the expected shape. Treat a
comma-joined value as ambiguous rather than attempting to select one result. Parse JSON into a
plain data object, read only known own-properties, and validate result fields against the documented
string enums before making a decision.

After safe decoding, allow the Approov part of the decision only when all core checks passed:

```text
tokenResult == "PASS"
and bindingResult in {"VALID", "DISABLED"}
and messageSigningResult in {"VALID", "NOT_REQUIRED"}
```

`NOT_CHECKED` is not a passing result for an enabled binding or message-signing policy. The
backend must apply its normal authentication and authorization checks independently; an Approov
pass proves the calling app instance, not the user's identity or permissions. When Cloudflare API
Shield validates a user JWT, it supplies an independent edge control. It does not turn
`Approov-Result` into user authorization and does not remove the backend's need to enforce the
application's authorization policy.

The final protected-operation decision is therefore:

```text
normal authentication and authorization passed
and tokenResult == "PASS"
and bindingResult in {"VALID", "DISABLED"}
and messageSigningResult in {"VALID", "NOT_REQUIRED"}
```

For example, middleware can implement the Approov portion as follows:

```javascript
function isPassingApproovResult(result) {
  return result !== null &&
    typeof result === 'object' &&
    !Array.isArray(result) &&
    result.tokenResult === 'PASS' &&
    (result.bindingResult === 'VALID' || result.bindingResult === 'DISABLED') &&
    (result.messageSigningResult === 'VALID' || result.messageSigningResult === 'NOT_REQUIRED')
}
```

This predicate assumes the transport header has already passed the strict base64, JSON, size,
duplication, and shape checks above. Keep those parsing checks separate and fail closed on every
exception.

Do not authorize a request merely because the header exists. Do not accept a result supplied
directly by a client.

## Core results versus annotations

The core fields above are the Worker's enforcement contract. Diagnostic detail such as
`tokenVerification` must not override a non-passing core result.

Plugin results are annotation-only at the Worker:

- `arcProperties` decodes device and attestation properties when available.

Their absence or failure does not alter `tokenResult`, binding, or message-signing results. A
backend may add an application-specific risk policy based on these annotations, but it should do
so as an explicit additional deny rule. An ARC annotation must never convert a failing
core result into an allow.

## Trusted ingress is mandatory

`Approov-Result` is trusted because the Worker removes a client value and replaces it after
verification. It is not independently signed for transport to an arbitrary public origin.
The backend must therefore be reachable only through a path that guarantees the Worker ran.

The complete routing and authentication policy must prove that this exact gateway Worker ran:

- Put this Worker on a Cloudflare Worker Route in front of the existing proxied API hostname.
  Cover every protected path and close every alternate route to that origin.
- For a separately public origin, require gateway-specific authentication on every protected request.
  For example, the origin can require a credential or client certificate held only by this gateway.
  Credential injection or client-certificate dispatch requires a source extension in this version.
  The extension must overwrite client-supplied credentials, and the origin must reject missing or invalid credentials.

Network and connection controls supplement this policy. Authenticated Origin Pulls (AOP) authenticates a Cloudflare-to-origin connection, not execution of this Worker.
Global AOP uses a certificate shared across Cloudflare accounts. Even an account-specific certificate does not prove that this Worker ran.
A direct request to an allowed proxied origin hostname can still pass AOP.
A publicly reachable Cloudflare Tunnel hostname also needs the same gateway enforcement or gateway-specific authentication.
See [Cloudflare's AOP certificate scopes](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/#configuration-levels).

A private Worker through a [service binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/http/)
is an extension option, not a configuration-only topology supported by this version.
The handler currently calls global `fetch()`. A source extension must dispatch through `env.BINDING_NAME.fetch(request)` before a private Worker can serve as the upstream.

For an existing API origin, configure the Worker Route to fail closed rather than bypassing the
Worker when the account's Worker request allowance is exhausted. Restrict the origin firewall,
load balancer, and DNS aliases consistently; protecting only the primary public hostname is not
enough if an origin IP or alternate hostname remains reachable.

Do not expose both the Worker gateway and an unrestricted origin hostname for the same API.
An attacker could call the origin directly and supply a fabricated `Approov-Result` value.

In staging, send a fabricated passing result through each alternate hostname and direct origin address.
Require rejection even when the connection passes AOP or tunnel authentication.

## Cache bypass is mandatory before enforcement

Every protected request must reach backend middleware before a cache can reuse a response.
This requirement covers Cloudflare caches, other CDNs, reverse proxies, and application caches ahead of that middleware.
A cache hit before enforcement can return an earlier passing response for a missing, expired, or fail token.

Annotation-mode outbound requests use `cache: 'no-store'`. Cloudflare documents automatic cache bypass for this option only for origins not hosted by Cloudflare.
The option also sends no-cache request headers. It does not guarantee bypass of another Cloudflare zone's cache or an independently configured upstream cache.
See [Cloudflare fetch cache behavior](https://developers.cloudflare.com/workers/runtime-apis/fetch/#parameters).

Configure explicit cache bypass for protected paths in each applicable zone and upstream cache.
Alternatively, use an effective origin policy such as `Cache-Control: private, no-store`, or mandatory revalidation that always executes backend middleware.
Make sure that Cache Rules do not override that policy and serve protected responses without enforcement.
See [Origin Cache Control](https://developers.cloudflare.com/cache/concepts/cache-control/).

Before production, do this staging test for every deployed topology, including same-zone routes and external Cloudflare-hosted origins:

1. Request a cacheable protected asset, such as `/protected.png`, with a passing token.
2. Repeat the identical URL with missing, expired, and fail tokens.
3. Require each request to reach backend middleware and return its rejection.
4. Inspect origin request counts as well as response cache status. A client response alone does not prove that middleware ran.

The Worker does not configure account Cache Rules, origin policy, or other upstream caches.

## Failure behavior

Return a stable `401` or `403` for validation failures and avoid including decoded token claims
in the response. Log only the result category and request correlation data needed for operations;
do not log raw Approov tokens, authorization values, or the full result payload in production.

Keep health checks and other intentionally public endpoints on a route that does not require an
Approov result, or give them a separate narrowly scoped authentication mechanism. Never make a
missing result pass solely to accommodate monitoring.

Log the normalized outcome fields, protected operation, Cloudflare request identifier, and an
application correlation identifier. Do not log raw `Approov-Token`, `Authorization`, message
signatures, secrets, or the complete decoded result. Apply rate limits to repeated failures so
annotation mode does not turn the backend into an unlimited token-analysis endpoint.

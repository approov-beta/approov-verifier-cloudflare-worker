# Cloudflare API Shield Deployment Checklist

Use this checklist to deploy API Shield and the Approov Worker on an existing Cloudflare-proxied
API hostname. Importing `APPROOV_BACKEND_CONFIG` supplies verification material, but it does not
create the Worker Route, configure API Shield, implement backend enforcement, or close alternate
paths to the origin.

## 1. Define the protected surface

Inventory the host, method, and path of every API operation. Classify each operation as:

- Mobile-only and Approov-required.
- Shared by mobile and another trusted client with a separate policy.
- Intentionally public, such as a narrowly scoped health endpoint.
- A browser CORS preflight (`OPTIONS`), login/bootstrap operation, or third-party webhook that
  needs an explicit exception.

Use the same inventory for API Shield selectors, Worker Route patterns, and backend middleware.
Do not use a broad backend exception to solve a single client or endpoint compatibility problem.

## 2. Configure API Shield for incoming-request controls

1. Add the protected operations to API Shield Endpoint Management. Schema and JWT rules apply
   only to endpoints known to Endpoint Management.
2. Import the API's OpenAPI 3.0 schema and begin schema validation in logging mode. Resolve valid
   client mismatches before moving the rule to blocking.
3. Create a JWT validation configuration for the user or service credential, normally read from
   `Authorization`, using the identity provider's public JWKS.
4. Create a token validation rule that requires the credential on the intended operations and
   blocks invalid, expired, not-yet-valid, or unexpectedly missing JWTs.
5. Exclude only operations that genuinely cannot carry that credential, such as a token-issuing
   endpoint or browser preflight. Keep API Shield and backend exclusions synchronized.
6. Configure mTLS, rate limiting, sequence controls, or GraphQL limits where the API design needs
   them.

Do not point API Shield JWT validation at `Approov-Token`. API Shield should validate the normal
identity credential; this Worker supplies the domain policy, pass/fail key distinction, binding,
message signing, and ARC behavior required for Approov.

See Cloudflare's documentation for
[Endpoint Management](https://developers.cloudflare.com/api-shield/management-and-monitoring/),
[JWT validation](https://developers.cloudflare.com/api-shield/security/jwt-validation/), and
[schema validation](https://developers.cloudflare.com/api-shield/security/schema-validation/).

## 3. Register the public hostname with Approov

Register the exact hostname used by the mobile app and assign its intended Approov keyset KID
before exporting backend configuration:

```shell
approov api -add api.example.com -keySetKID "example-es256"
approov secret -getBackendConfig approov-config.json
```

Check that `approov-config.json` contains `api.example.com` under `apis`, that its KID exists in
both `passJWKS` and `failJWKS`, and that token checking is enabled for the domain. Register each
distinct production hostname; do not rely on wildcard mode as the production policy.

The exported file contains secret verification material. Keep it out of source control, logs,
CI artifacts, shell history, and support attachments.

## 4. Configure and deploy the Worker

For an existing API origin, use a Worker Route rather than making the Worker a Custom Domain:

```toml
workers_dev = false

[[routes]]
pattern = "api.example.com/*"
zone_name = "example.com"

[vars]
API_DOMAIN = "api.example.com"
API_PORT = "443"

APPROOV_MODE = "annotate"
```

Upload the backend configuration as an encrypted Worker secret:

```shell
npx wrangler secret put APPROOV_BACKEND_CONFIG < approov-config.json
npm run deploy -- --tag "$(git describe --tags --always --dirty)"
```

The deployment tag identifies the source revision in Cloudflare's **Worker → Deployments** page.
For PowerShell and ZIP downloads, use the [tagged deployment examples](../README.md#tag-a-deployment).

Keep `APPROOV_BACKEND_CONFIG` in `[secrets].required`. The deployment command always validates policy.
If the export exists beside the selected Wrangler file, preflight validates it too:

```shell
node scripts/validate-config.js
npm run deploy -- --dry-run
```

Do not enable echo mode in production. Configure the Worker Route to **fail closed** so an
exhausted Worker allowance does not bypass verification. Follow
[Deployment in Front of an Existing API Origin](existing-domain.md) for the routing details.

## 5. Enable optional Approov checks consistently

Token binding requires both sides to use the exact same source value:

```toml
APPROOV_TOKEN_BINDING_ENABLED = "true"
APPROOV_TOKEN_BINDING_HEADER_NAME = "Authorization"
```

The app must bind the identical authorization string, including its prefix and encoding. A
frequently changing binding value can cause additional Approov token fetches.

Message signing must use the same mode, covered components, path representation, and body digest
in the mobile integration and Worker. Account mode also requires
`APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET`; add it to `[secrets].required` when enabling it. Keep the default request body limit and clock tolerance only if they match the API's
largest signed request and operational clock-skew requirements.

ARC plugin results are annotations. Configure any backend risk policy for them
explicitly; enabling the plugin alone does not block a request.

## 6. Install backend enforcement

Before declaring an operation protected, install centralized middleware that:

1. Rejects missing, duplicate, oversized, malformed, or structurally invalid `Approov-Result`.
2. Requires `tokenResult == "PASS"`.
3. Requires binding `VALID` or `DISABLED`, and message signing `VALID` or `NOT_REQUIRED`.
4. Applies normal user authentication and authorization independently.
5. Runs before the protected business handler and any expensive downstream processing.
6. Uses an explicit operation allowlist for endpoints that do not require Approov.

Use [Backend Enforcement and Trusted Ingress](backend-enforcement.md) as the enforcement contract.

## 7. Close origin bypasses

The Worker removes a client-supplied result and adds its own, but the header is not independently
signed for delivery through an arbitrary public path. Restrict every origin IP, load balancer,
alternate hostname, staging hostname, and direct cloud-provider URL.

Require the routing and authentication policy to prove that this exact gateway Worker ran.
AOP, firewall rules, or a publicly reachable tunnel alone do not prove that execution.
For a separately public origin, require gateway-specific authentication on every protected request.
Credential injection, client-certificate dispatch, and private Worker service-binding forwarding require source extensions in this version.
See [the supported ingress paths and extension requirements](backend-enforcement.md#trusted-ingress-is-mandatory).

In staging, send a fabricated passing result directly through every alternate hostname and origin address.
Require rejection even when AOP or tunnel authentication succeeds.

Bypass every cache before backend enforcement. Annotation requests use `cache: 'no-store'`, but another Cloudflare zone can still apply its own cache policy.
Configure explicit cache bypass or effective origin private/no-store or mandatory-revalidation policy for protected paths.
Make sure that Cache Rules cannot override that policy.
Run [the cache staging test](backend-enforcement.md#cache-bypass-is-mandatory-before-enforcement) for every deployed topology before production.

## 8. Configure operations and rollout

- Keep `APPROOV_DEBUG = "false"` in production except during a bounded diagnostic window.
- Log normalized outcome categories and request correlation identifiers, never raw tokens,
  authorization values, signing material, or the full decoded result.
- Alert on missing results, malformed results, increases in `FAIL`/`INVALID_SIG`, Worker startup
  errors, and direct-origin attempts.
- Exercise the complete verification matrix in staging, then protect production operations in
  controlled batches. API Shield features have no traffic effect while their action remains
  `log`; explicitly move the intended API Shield rules to `block`.
- If you switch to Worker block mode, configure every enabled layer action first. Block mode
  removes `Approov-Result`, so replace middleware that requires this annotation. Keep API Shield
  and application authorization checks.

Complete the [API Shield and Approov Verification Matrix](api-shield-verification.md) before
go-live and after changes to keys, routes, identity providers, schemas, binding, or signing policy.

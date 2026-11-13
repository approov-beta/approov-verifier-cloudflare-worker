# Deployment in Front of an Existing API Origin

This guide places the Approov Worker on an existing API hostname already proxied by a
Cloudflare zone, such as `api.example.com`. The existing application server remains the
origin; the Worker Route becomes the public validation and annotation layer in front of it.

This is topology C in [Deployment Topologies](deployment-topologies.md), which compares it with
the `workers.dev` and Custom Domain alternatives and explains how many Workers you need when
protecting several API hostnames.

## Use a Worker Route, not a Custom Domain

Cloudflare uses the two terms for different topologies:

- A **Worker Route** runs a Worker in front of an existing proxied DNS origin.
- A **Custom Domain** makes the Worker itself the origin and creates Worker-owned DNS.

This topology requires a Worker Route. Do not set `custom_domain = true`: that would describe
a different deployment, cannot use the `/*` path pattern shown below, and can conflict with
the existing origin DNS record.

## Request flow

1. A request for `api.example.com` matches the Worker Route.
2. The Worker validates the Approov token and creates the authoritative `Approov-Result`.
3. In the default annotation mode, it forwards the rewritten request to the same hostname.
4. Cloudflare sends that subrequest to the application server defined by the zone's DNS
   configuration.
5. The backend decodes `Approov-Result` and rejects non-passing requests as described in
   [Backend Enforcement and Trusted Ingress](backend-enforcement.md).

This behavior depends on same-zone subrequests being routed to the origin. Do not enable the
`global_fetch_strictly_public` compatibility flag for this topology; it can send the subrequest
back through Cloudflare's public routing path and cause the Worker to invoke itself again.

## Prerequisites

- The hostname has an active proxied (orange-clouded) DNS record in the Cloudflare zone.
- The DNS record points to the intended application origin.
- The hostname is registered in Approov and appears in `APPROOV_BACKEND_CONFIG.apis` with the
  intended keyset KID.
- Direct access to the origin IP or alternate origin hostname is blocked or independently
  authenticated.

## Wrangler configuration

Bind the Worker to a route associated with the existing zone:

```toml
workers_dev = false

[[routes]]
pattern = "api.example.com/*"
zone_name = "example.com"
```

Then target the same API hostname and normal HTTPS port:

```toml
[vars]
API_DOMAIN = "api.example.com"
API_PORT = "443"

# Default: forward the authoritative result for backend enforcement.
APPROOV_MODE = "annotate"
```

To block failures at the edge, set `APPROOV_MODE = "block"` and configure every enabled layer action.
Block mode removes `Approov-Result`. Replace backend middleware that requires this annotation before switching modes.
Keep application authentication and authorization checks.

### Several hostnames in one deployment

To protect more than one API hostname with a single Worker, add a `[[routes]]` entry per hostname
and enable pass-through forwarding instead of naming a fixed upstream:

```toml
[[routes]]
pattern = "api.example.com/*"
zone_name = "example.com"

[[routes]]
pattern = "testapi.example.com/*"
zone_name = "example.com"

[vars]
API_PASSTHROUGH = "true"
```

Each request is verified against its own hostname's keyset from `APPROOV_BACKEND_CONFIG.apis` and
forwarded to that hostname's own DNS origin. `API_DOMAIN` must be removed — setting both is a
startup error. Note that `[vars]` are deployment-wide, so every hostname shares the same
enforcement, binding, and message-signing settings; a hostname needing different Approov policy
still needs its own deployment, as does a fixed `APPROOV_TOKEN_AUDIENCE`. To check audiences
across several hostnames in one deployment, set `APPROOV_TOKEN_AUDIENCE_FROM_HOST = "true"`.

## Validation

After deployment, test through the public API hostname:

- A valid token reaches the backend with a decoded passing result.
- Missing, malformed, fail, and expired tokens reach the backend with non-passing results and
  are rejected there.
- A client-supplied `Approov-Result` value is replaced by the Worker.
- Direct requests to the origin IP or alternate origin hostname fail before application logic.
- Fabricated passing results through alternate hostnames fail even when AOP or tunnel authentication succeeds.
- The [cache staging test](backend-enforcement.md#cache-bypass-is-mandatory-before-enforcement) proves that every protected request reaches backend enforcement.
- Requests with query strings and representative body sizes reach the origin once, without a
  Worker recursion error.

See Cloudflare's current documentation for
[Worker Routes](https://developers.cloudflare.com/workers/configuration/routing/routes/),
[Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/),
and the [`global_fetch_strictly_public` compatibility flag](https://developers.cloudflare.com/workers/configuration/compatibility-flags/#global-fetch-strictly-public).

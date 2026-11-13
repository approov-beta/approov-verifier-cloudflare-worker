# Live Cloudflare validation: 2 October 2026

All **193 curl scenarios passed** across 37 configuration profiles.
Cloudflare rejected all **15 invalid uploads**. No Worker code changes were needed.

## Deployment

- Source: `786430389fdcab40caa33f9cb1e81832452d7aac` on `feature/behaviourAndConfigChanges`.
- Review: [PR #36](https://github.com/approov/approov-verifier-cloudflare-worker/pull/36), above PR #35.
- Staging: [approov-v2-config-smoke-20261002](https://approov-v2-config-smoke-20261002.approovinternal.workers.dev).
- Final version: `a0752a29-5247-40e8-b56a-3e4567ae0195`.
- Final settings: `annotate`, request logging enabled, Analytics Engine disabled, token binding disabled.

The deployment uses synthetic test keys and a separate Cloudflare test origin.
Customer Workers and production routes were not changed.
Forwarded requests reached the test origin; rejected requests received the configured blocking response.

## Curl results

| Test group | Passed | Coverage |
| --- | ---: | --- |
| Existing request matrix | 62 | Token outcomes, binding, signatures, plugins, forwarding, and header handling |
| Additional signature cases | 42 | Trusted `FAIL` tokens, malformed claims, extra signatures, tampering, body limits, audience, and custom headers |
| Enforcement combinations | 64 | All eight combinations of three `block` / `continue` actions |
| Missing account secret | 6 | Annotation, blocking, and continuation with account or both signatures required |
| Logging destinations | 9 | Logs and Analytics Engine independently enabled or disabled; operational error with logging disabled |
| Restored deployment | 10 | Token outcomes, spoofed result, install/account/both signatures, body tampering, and body preservation |
| **Total** | **193** | Rollout probes and instrumentation retries are excluded |

Annotation mode added `Approov-Result` when absent and replaced client-supplied values.
Every protection outcome was forwarded with the Worker's result.
Block mode removed the header. Each configured action controlled its own layer.
All actions set to `continue` still ran verification.

Trusted claims selected none, install, account, or both signatures.
Authentic `FAIL` tokens received dependent checks.
Untrusted tokens left those checks unavailable.
Both required signatures were checked independently; either failure produced an overall failure.

## Invalid configuration uploads

Raw Wrangler uploads bypassed local preflight to test Cloudflare initialization directly.
Cloudflare returned [validation error 10021](https://developers.cloudflare.com/workers/observability/errors/#validation-errors-10021) for each invalid upload.
The active deployment remained unchanged during these tests.

Rejected configurations included missing mode/actions, actions in annotation mode, empty prohibited fields,
disabled binding with an action, uppercase values, obsolete `log`, malformed booleans,
negative limits, legacy/unknown variables, unavailable plugin fields, conflicting forwarding settings,
and malformed backend secret contents.

## Logs and Analytics Engine

Live log events confirmed the expected behavior for 83 curl scenarios.
Logging enabled produced one structured summary per request; logging disabled produced none.
Operational errors still produced an error log.
Summaries included actions, layer results, individual signatures, decision, response status, and duration.

The privacy check covered 101 captured invocations and 94 request summaries.
Console messages contained no sensitive fixture values or full URLs.
Cloudflare's live-tail request metadata was excluded from this console-message check.

Analytics Engine Studio SQL returned six weighted requests and zero unexpected records.
It confirmed schema version `2`, the existing column order, and aggregate signing results.
The dataset is `approov_worker_v2_smoke_20261002`.

## Scope and repeat checks

The staging origin is another Worker, so this fixture enables
[`global_fetch_strictly_public`](https://developers.cloudflare.com/workers/runtime-apis/fetch/).
Private-origin deployments through Worker Routes require their documented routing configuration.
Pass-through hostname selection and the loop guard were tested in echo mode.
Actual private-origin routing and real Approov SDK/device requests remain untested.

[Version aliases](https://developers.cloudflare.com/workers/versions-and-deployments/version-urls/)
were used for isolated HTTP tests. Active deployments were used for live log checks.
The temporary missing-secret Worker was removed. Staging and its test origin remain available.

Run these requests against staging. Both return HTTP `200`; the origin receives a Worker-generated
result with `tokenResult: MISSING_HEADER`:

```sh
curl -i https://approov-v2-config-smoke-20261002.approovinternal.workers.dev/live/manual
curl -i -H 'Approov-Result: forged-by-client' \
  https://approov-v2-config-smoke-20261002.approovinternal.workers.dev/live/manual
```

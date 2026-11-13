# Approov Worker analytics

Version 3 · 29 October 2026

Add one safe summary for each request. Reuse the results the worker already produces. Record token verification, attestation, message signing, and available plugin results. Include token binding and the worker’s action so operators can understand why a request was forwarded or rejected.

The implementation consists of a small analytics module, a final emission step in the request handler, and one optional summary function per plugin. The summary is independent of enforcement and annotation.

**What the summary contains.** Existing verification and plugin status values are reused wherever possible. Structured records include `event: "approov.request"`.

| Field | Values or structure | Meaning |
|---|---|---|
| `version` | `3` | Version of the log format |
| `clientStatus` | Known lowercase SDK status name, `invalid`, or null | Client diagnostic, independent of token verification |
| `token.presence` | `MISSING`, `EMPTY`, `PRESENT`, `NOT_CHECKED` | Whether the configured token header was present |
| `token.verification` | `VERIFIED`, `NOT_CHECKED`, `EXPIRED`, `INVALID_SIG`, `INVALID_ALG`, `INVALID_AUD`, `MALFORMED`, `UNPARSABLE`, `ERROR` | Result of token verification |
| `attestation` | `PASS`, `FAIL`, `UNAVAILABLE` | Outcome established by the verified pass or fail key |
| `binding` | Existing binding status | Includes `VALID`, `INVALID`, `DISABLED`, and `NOT_CHECKED` |
| `messageSignature` | `{ mode, status, signatures: { install, account } }` | Selected signing requirement, overall result, and individual status strings or null |
| `plugins` | Object keyed by plugin ID | Safe summaries from installed plugins |
| `validation` | `PASS`, `FAIL`, `ERROR`, `NOT_EVALUATED` | Combined core result, including binding and message signing |
| `mode` | `annotate`, `block`, or `UNAVAILABLE` | Configured enforcement behavior |
| `actions` | Object or null | Block-mode actions for token, binding, and message signing; null in annotation mode |
| `action` | `forward`, `unprotected`, `block`, `echo`, `error` | What the handler did; `unprotected` is a forward of a path outside `APPROOV_PROTECTED_PATHS` |
| `responseStatus` | HTTP status or null | Status of the response returned by the handler |
| `upstreamStatus` | HTTP status or null | Status received from the upstream, if contacted successfully |
| `durationMs` | Number | Elapsed time until response availability, not body completion |

A signed FAIL token is authentic but represents failed attestation. An invalid signature means this deployment could not establish authenticity with its accepted keys. It does not prove that Approov never issued the token.

| Situation | Presence | Verification | Attestation |
|---|---|---|---|
| No token header | `MISSING` | `NOT_CHECKED` | `UNAVAILABLE` |
| Empty token header | `EMPTY` | `NOT_CHECKED` | `UNAVAILABLE` |
| Signature cannot be verified | `PRESENT` | `INVALID_SIG` | `UNAVAILABLE` |
| Token expired | `PRESENT` | `EXPIRED` | `UNAVAILABLE` |
| Accepted pass-key token | `PRESENT` | `VERIFIED` | `PASS` |
| Accepted fail-key token | `PRESENT` | `VERIFIED` | `FAIL` |
| Configuration prevents inspection | `NOT_CHECKED` | `NOT_CHECKED` | `UNAVAILABLE` |

The collector uses the completed token verifier result for authenticity. A later evaluation error must remain visible in `validation` without erasing that evidence. Attestation remains available even if ARC decoding is unavailable.

**Plugins supply their own safe summary.** Add an optional synchronous `summarize(result)` function to the plugin export. It receives only that plugin’s existing result and returns a small object for logging. It must not modify the result or perform I/O.

For example, a plugin can return only its status:

```js
summarize (result) {
  return {
    status: result.status
  }
}
```

The host calls this function only for a completed plugin evaluation. A thrown evaluation produces `{ "status": "ERROR" }` without exception text. An evaluation deadline produces `{ "status": "TIMEOUT" }`. An installed plugin with a summary function that was not reached gets `NOT_CHECKED`. The host catches summary-function errors independently and records `SUMMARY_ERROR`. Plugins without this function continue working and add no telemetry fields. With no plugins, `plugins` is empty.

The collector accepts plain objects, finite scalar values, and arrays with at most 64 entries. The maximum nesting depth is four. Each plugin summary has a 4 KiB UTF-8 JSON limit. Combined plugin summaries have a 16 KiB limit. Unsupported or oversized summaries produce `SUMMARY_ERROR`; entries are omitted if even that status cannot fit. Getters, symbols, functions, class instances, cycles, and asynchronous summaries are unsupported. The collector copies accepted data. Plugins remain trusted code and must exclude sensitive values themselves.

| Plugin | Summary | Excluded |
|---|---|---|
| ARC | Decode status and decoded property labels | Encoded ARC and secrets |
| Future plugin | Small summary chosen by its author | Complete result dumps |

ARC is a standard diagnostic when installed. Its summary reports `DECODED` with the existing property array, or `UNAVAILABLE` when the result is null. The array retains its existing leading `pass` or `fail` marker. The current null result does not identify the precise decode failure, so detailed decode reasons are deferred.

ARC properties provide attestation context. They are not necessarily the exact policy rejection reasons, and they can appear on PASS tokens too. [Approov ARC documentation](https://docs.approov.io/app-integration/frontend/attestation/)

A shortened example is:

```json
{
  "version": 3,
  "clientStatus": "success",
  "token": { "presence": "PRESENT", "verification": "VERIFIED" },
  "attestation": "FAIL",
  "binding": "DISABLED",
  "messageSignature": { "mode": "account", "status": "MISSING_HEADERS", "signatures": { "install": null, "account": "MISSING_HEADERS" } },
  "validation": "FAIL",
  "mode": "block",
  "action": "block",
  "responseStatus": 403,
  "upstreamStatus": null,
  "plugins": {
    "arc": {
      "status": "DECODED",
      "properties": ["fail", "rooted"]
    }
  }
}
```

**Where the summary goes.** Structured Workers Logs provide the first useful interface, including decoded ARC and other plugin results. An optional Analytics Engine binding writes one fixed record per request for core outcome charts. Both destinations use the same safe summary. Plugin details remain in structured logs initially. A separate plugin metrics dataset, generic fact rows, and custom exporters are deferred.

Analytics is opt-in. Logging and Analytics Engine have separate enable switches, both defaulting to false. Analytics Engine also needs its dataset binding. There is no application sampling setting initially. Analytics Engine queries account for Cloudflare sampling through `_sample_interval`. Customer-configured Workers Logs sampling is independent. [Analytics Engine sampling](https://developers.cloudflare.com/analytics/analytics-engine/sampling/)

The handler emits once from a finalizer covering early returns and exceptions. Analytics failures cannot change enforcement, trigger another upstream request, or replace the response. No request or response body is read for analytics. No external HTTP export runs on the request path.

**Safe logging applies to existing logs too.** Do not log tokens, encoded ARC, credentials, binding hashes, complete claims, bodies, or full request URLs. Replace existing debug dumps of those values with safe status summaries. Debug mode must follow the same rule. Platform-generated logs have separate metadata controls.

The implementation tests establish four things:

- Missing, invalid, expired, pass-key, and fail-key tokens produce distinct summaries.
- Plugin summaries work with any set of installed plugins, or none.
- Sensitive fixture values never appear in logs, including debug output.
- Disabled analytics, missing bindings, and throwing emitters preserve existing request behavior.

Detailed ARC error reporting and aggregate charts for arbitrary plugin fields are deferred.

## Enable analytics

Set these variables in the existing `[vars]` table in `wrangler.toml`:

```toml
[vars]
APPROOV_ANALYTICS_ENABLED = "true"
APPROOV_LOGGING_ENABLED = "true"
```

Add this top-level binding outside the `[vars]` table:

```toml
[[analytics_engine_datasets]]
binding = "APPROOV_ANALYTICS"
dataset = "approov_worker_v2"
```

Enable Analytics Engine for the account in the Cloudflare dashboard before the first deployment. A disabled account rejects the upload with code `10089`.

Cloudflare creates the dataset on its first write. The Worker uses the native binding, without an HTTP exporter or API credentials. `writeDataPoint()` returns immediately. The runtime handles background delivery without `await` or `waitUntil`. [Analytics Engine setup](https://developers.cloudflare.com/analytics/analytics-engine/get-started/)

Both switches default to false. Accept native booleans or exact lowercase `"true"`/`"false"` strings.
Invalid settings are configuration errors.

Use `APPROOV_LOGGING_ENABLED="true"` without enabling analytics for structured logs alone.
Use `APPROOV_ANALYTICS_ENABLED="true"` and `APPROOV_LOGGING_ENABLED="false"` for Analytics Engine alone.
No legacy outcome line is emitted. Errors and warnings remain enabled.
Missing or failing destinations cannot change enforcement, responses, or forwarding.

To retain structured logs, add the optional Workers Logs configuration:

```toml
[observability.logs]
enabled = true
invocation_logs = false
head_sampling_rate = 1.0
```

Cloudflare invocation logs can contain full URLs. Their controls are separate from Worker-authored summaries. Customer log sampling is independent of Analytics Engine sampling. [Workers Logs configuration](https://developers.cloudflare.com/workers/observability/logs/workers-logs/)

Named Wrangler environments need their own dataset bindings and analytics variables. Use distinct dataset names for deployments whose outcomes must remain separate.

## Analytics Engine columns

One request produces at most one native data point. Plugin details, individual signatures, and configured actions remain in structured logs.
Version 3 appends the client token-fetch status in `blob11`. The first ten columns keep their positions.
The signing-mode vocabulary includes `either`. Consumers with a fixed mode allowlist must accept it:
when the requirement is unset, a token with two key claims reports `either`; an explicit `both` reports `both`.

| Column | Field | Values |
|---|---|---|
| `blob1` | Version | `"3"` |
| `blob2` | Enforcement mode | `annotate`, `block`, `UNAVAILABLE` |
| `blob3` | Handler action | `forward`, `unprotected`, `block`, `echo`, `error` |
| `blob4` | Token presence | `MISSING`, `EMPTY`, `PRESENT`, `NOT_CHECKED` |
| `blob5` | Token verification | `VERIFIED`, `NOT_CHECKED`, or existing verification failure status |
| `blob6` | Attestation | `PASS`, `FAIL`, `UNAVAILABLE` |
| `blob7` | Binding | Existing binding status |
| `blob8` | Message-signature mode | `none`, `install`, `account`, `either`, `both`, `unknown` |
| `blob9` | Message-signature status | Existing message-signature status |
| `blob10` | Combined validation | `PASS`, `FAIL`, `ERROR`, `NOT_EVALUATED` |
| `blob11` | Client token-fetch status | Known lowercase SDK status name, `invalid`, or `missing` |
| `double1` | Returned HTTP status | Integer, or `-1` when unavailable |
| `double2` | Upstream HTTP status | Integer, or `-1` when unavailable |
| `double3` | Duration | Milliseconds until response availability or handler exception |
| `index1` | Sampling bucket | `verification:attestation:validation`, for example `VERIFIED:FAIL:FAIL` |

The column order is fixed. Incompatible changes require a new dataset version. The runtime supplies `timestamp` automatically.
The record uses eleven blobs, three doubles, and one short index. [Analytics Engine limits](https://developers.cloudflare.com/analytics/analytics-engine/limits/)

`clientStatus` comes from the client and does not establish trust. It never changes verification or enforcement.
Unknown, repeated, empty, and oversized values produce `invalid`. Raw status-header values never enter this dataset or the structured logs.
Missing headers produce `null` in structured logs and `missing` in `blob11`.

Version 3 records this diagnostic even when Analytics Engine is enabled and structured logs are disabled.
Version 2 records do not contain this field. The dataset binding and existing sampling index do not change.

Before rollout, update consumers that accept only version 2. A filter of `blob1 = '2'` excludes all new records.
For historical core metrics, use `blob1 IN ('2', '3')`. For client-status metrics, use `blob1 = '3'`.
Structured-log consumers must also accept version 3 and the additional `clientStatus` field.

The outcome index gives lower-volume failures their own sampling group. It contains no customer, device, or request identifiers. Analytics Engine samples at write and query time. It cannot guarantee retrieval of an individual request or an exact sequence of events. [Sampling behavior](https://developers.cloudflare.com/analytics/analytics-engine/sampling/)

## SQL examples

Run these queries through the [Analytics Engine SQL API](https://developers.cloudflare.com/analytics/analytics-engine/sql-api/). Use `SUM(_sample_interval)` for counts. Use weighted totals for averages and percentages.

These examples select version 3 records. Queries for both versions can use the historical filter described earlier.

Token outcomes for the last hour:

```sql
SELECT blob4 AS presence, blob5 AS verification, blob6 AS attestation,
       SUM(_sample_interval) AS requests
FROM approov_worker_v2
WHERE blob1 = '3' AND timestamp >= NOW() - INTERVAL '1' HOUR
GROUP BY presence, verification, attestation
ORDER BY requests DESC
```

Percentage of requests rejected by the Worker:

```sql
SELECT 100.0 * SUM(IF(blob3 = 'block', _sample_interval, 0))
       / SUM(_sample_interval) AS rejection_percent
FROM approov_worker_v2
WHERE blob1 = '3' AND timestamp >= NOW() - INTERVAL '1' HOUR
```

Message-signature failures, excluding requests that require no signatures or could not be checked:

```sql
SELECT blob8 AS mode, blob9 AS signature_status,
       SUM(_sample_interval) AS requests
FROM approov_worker_v2
WHERE blob1 = '3' AND timestamp >= NOW() - INTERVAL '1' HOUR
  AND blob9 NOT IN ('VALID', 'NOT_REQUIRED', 'NOT_CHECKED')
GROUP BY mode, signature_status
ORDER BY requests DESC
```

Average time to response availability, grouped by handler action:

```sql
SELECT blob3 AS action,
       SUM(double3 * _sample_interval) / SUM(_sample_interval) AS average_ms
FROM approov_worker_v2
WHERE blob1 = '3' AND timestamp >= NOW() - INTERVAL '1' HOUR
GROUP BY action
```

## Deployment smoke check

Use a staging deployment whose backend configuration includes its incoming hostname.

1. Enable analytics and add the dataset binding. Deploy through the normal staging process.
2. Send one request without a token, one with an empty token, and one with `Approov-Token: invalid`.
3. If suitable signed fixtures are available, also send accepted pass-key and fail-key tokens.
4. Run the token-outcome query through the SQL API after ingestion. Use an API token with `Account Analytics Read` permission.
5. Verify distinct `MISSING`, `EMPTY`, and `MALFORMED` outcomes. Signed fixtures must show `VERIFIED` with the appropriate attestation.
6. Verify that response and annotation behavior matches the selected enforcement mode.
7. In Workers Logs, verify the `approov.request` record and safe plugin summaries. Tokens and encoded ARC must be absent.

Sampling and ingestion delay prevent exact per-request delivery assertions. Local tests verify exact adapter calls and column ordering without a live dataset.

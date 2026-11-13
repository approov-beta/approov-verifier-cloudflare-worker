# Migrate from v1.1 to v2

This guide compares the [v1.1 review-fixes branch](https://github.com/CriticalBlue/internal-approov-cloudflare-worker/tree/feature/review-fixes), reviewed at `a0c4c266`, with v2.

## Configuration comparison

| V1.1 | V2 |
|---|---|
| Annotation only | Required `APPROOV_MODE`: `annotate` or `block` |
| `APPROOV_TOKEN_PASS_PEM`, `APPROOV_TOKEN_FAIL_PEM`, `APPROOV_ARC_ENCODING_SECRET_BASE64` | One `APPROOV_BACKEND_CONFIG` secret |
| `APPROOV_TOKEN_SIGNING_ALGORITHM` | Remove it. Each exported JWK declares its algorithm. |
| `APPROOV_VERIFICATION_STRATEGY="token"` | `APPROOV_TOKEN_BINDING_ENABLED="false"` |
| `APPROOV_VERIFICATION_STRATEGY="token-binding"` | `APPROOV_TOKEN_BINDING_ENABLED="true"` |
| `APPROOV_BINDING_HEADER_NAME` | `APPROOV_TOKEN_BINDING_HEADER_NAME`; default `Authorization` |
| `APPROOV_BINDING_CLAIM_NAME` | `APPROOV_TOKEN_BINDING_CLAIM_NAME`; default `pay` |
| `APPROOV_ANALYTICS_LOG` | `APPROOV_LOGGING_ENABLED`; default `false` |
| Configurable analytics layout, binding name, sampling, index, and field lists | Remove those variables. V2 uses a fixed schema and `APPROOV_ANALYTICS` binding. |
| `API_DOMAIN` | Keep it, or use `API_PASSTHROUGH="true"` with `API_DOMAIN` absent. See [topologies](deployment-topologies.md). |
| `ALLOWED_PATH_PREFIXES`, `ALLOWED_PATH_SUFFIXES` | `APPROOV_PROTECTED_PATHS`: path prefixes where `*` stands for one segment, so `/shop/*/*/checkout` covers every market. Unset, every request reaching v2 receives checks. |
| `UNMATCHED_PATH_ACTION` | No equivalent. With `APPROOV_PROTECTED_PATHS` set, other paths are forwarded unchecked and unannotated; there is no unmatched-path 404. |

Unknown `APPROOV_` variables and old v2 switches are errors. Do not copy the complete old variable table into v2.

## 1. Prepare the backend config

Record the current Worker, routes, bindings, and rollback version. Test v2 on a separate Worker before moving production routes.

Export the complete configuration with Approov CLI 3.6.0 or later:

```shell
approov secret -getBackendConfig approov-config.json
npx wrangler secret put APPROOV_BACKEND_CONFIG < approov-config.json
```

Use the v2 Worker's name when uploading. The export must include the incoming public hostname in `apis` and its matching pass/fail keys.
Keep the complete export. For local tests, put its JSON on one line in `.dev.vars`.
Do not commit secrets or the export.

Remove old variables and secret bindings from the v2 target. Keep the v1.1 Worker intact for rollback.
Narrower Worker routes do not reproduce the old unmatched-path HTTP 404 behavior.

## 2. Start in annotation mode

In `[vars]`, set:

```toml
APPROOV_MODE = "annotate"
APPROOV_TOKEN_BINDING_ENABLED = "false"
APPROOV_LOGGING_ENABLED = "true"
APPROOV_ECHO_MODE = "false"
```

Enable binding if the old strategy used it. Do not set layer actions or block-response variables in annotation mode.

V2 forwards every protection result in `Approov-Result`, including failures and `ERROR` annotations.
Update backend middleware to allow only token `PASS`, binding `VALID`/`DISABLED`, and signing `VALID`/`NOT_REQUIRED`.
Reject missing or malformed results. See [backend enforcement](backend-enforcement.md).

Invalid configuration refuses startup. Later invalid binding changes return HTTP 500 without contacting the origin.

## 3. Configure message-signature requirements

Set `APPROOV_MESSAGE_SIGNING_REQUIRED` to `install`, `account`, `either`, or `both`.
An explicit requirement applies even to trusted tokens without signing claims.
Choose `either` for SDK integrations that can send one or both signatures. Choose `both` to require both protections.

When unset, the Worker retains compatibility with token-only deployments:

| Trusted claims | Required signatures |
|---|---|
| Neither | None: `NOT_REQUIRED` |
| `ipk` | `install` |
| `mskid` | `account` |
| Both | At least one recognized signature must pass |

Every present `install` or `account` member must pass, regardless of the configured requirement.
A member present in only one signature dictionary fails. Unknown members cannot satisfy the requirement.
Claims provide keys; malformed claims fail when needed by a required or present member.
Untrusted tokens produce `NOT_CHECKED`.
Results include `signatures.install` and `signatures.account` inside `messageSigningVerification`.
The reported mode is `either` for the two-claim compatibility case. Log and dashboard consumers must accept this additional value.
Deployments that relied on both claims requiring both signatures must now set `APPROOV_MESSAGE_SIGNING_REQUIRED = "both"`.

For account signing, retain the separate `APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET` until the backend export bug is fixed.
Add it to `[secrets].required` when used. The expected account key ID remains optional.

## 4. Switch to block mode when ready

```toml
APPROOV_MODE = "block"
APPROOV_TOKEN_ACTION = "block"
APPROOV_MESSAGE_SIGNING_ACTION = "block"
# Required only when binding is enabled:
# APPROOV_TOKEN_BINDING_ACTION = "block"
```

Each action is `block` or `continue`. Both run checks. `continue` forwards failures; `block` rejects them.
Block mode never forwards `Approov-Result`. Remove result-header enforcement from this backend path; retain trusted ingress and normal authorization.

Logging is independent of these actions. Analytics Engine uses `APPROOV_ANALYTICS_ENABLED`; use a new v2 dataset and [updated queries](worker-analytics-proposal.md).

## 5. Verify before cutover

```shell
npm run validate:config
npm test
npm run test:preflight
npm run deploy -- --dry-run
```

Test passing, failing, missing, and expired tokens; binding failures; and each signature combination.
Check header replacement in annotation mode and header absence in block mode.
Move the production routes only after staging tests pass. Restore the original route target and recorded configuration if rollback is needed.

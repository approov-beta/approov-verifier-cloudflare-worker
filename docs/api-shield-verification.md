# API Shield and Approov Verification Matrix

Run this matrix against a staging environment that matches the production Worker Route, API
Shield rules, origin restrictions, and backend middleware. Repeat the relevant sections after
changes to routes, keys, identity providers, schemas, binding, message signing, or endpoint scope.

The expected enforcement layer matters as much as the HTTP status:

- **API Shield** blocks violations of its incoming-request policy.
- **Backend Approov middleware** blocks non-passing `Approov-Result` in annotation mode.
- **Trusted ingress** blocks attempts to bypass the Worker.

Do not assert that the Worker ran when API Shield blocks a request. The integration does not rely
on undocumented ordering between Cloudflare product phases; assert that the protected business
handler was not reached and use the responsible layer's logs to identify the decision.

## Test preparation

Prepare non-production fixtures for:

- A valid user JWT and missing, expired, not-yet-valid, malformed, and incorrectly signed variants.
- A valid Approov pass token, an Approov fail token, an expired token, an unknown-signer token,
  and a malformed token for the exact staging hostname.
- Bound and unbound Approov tokens if token binding is enabled.
- Correctly signed and deliberately modified requests for every enabled message-signing mode.
- Representative valid and schema-invalid request bodies.
- Every origin IP, alternate hostname, load-balancer address, and cloud-provider URL that could
  otherwise reach the backend.

Use Approov CLI example tokens only in test environments. Do not store tokens, authorization
values, account secrets, private keys, or complete decoded results in test output or CI artifacts.

For each scenario, record the response status, responsible enforcement layer, API Shield event,
normalized Approov outcome, whether the business handler ran, and a correlation identifier.

## Combined authorization matrix

These cases prove that user authorization and app integrity form an AND decision:

| User credential | Approov token | Expected result | Responsible layer |
|---|---|---|---|
| Valid and authorized | Valid pass | Request reaches the protected handler | Backend after both controls pass |
| Valid but unauthorized | Valid pass | Rejected; handler not reached | Backend authorization |
| Missing or invalid | Valid pass | Rejected; handler not reached | API Shield JWT rule |
| Valid and authorized | Missing | `MISSING_HEADER`; rejected | Backend Approov middleware |
| Valid and authorized | Approov fail | `FAIL`; rejected | Backend Approov middleware |
| Valid and authorized | Expired Approov token | `EXPIRED`; rejected | Backend Approov middleware |
| Valid and authorized | Unknown signer | `INVALID_SIG`; rejected | Backend Approov middleware |
| Valid and authorized | Malformed Approov token | `MALFORMED` or `UNPARSABLE`; rejected | Backend Approov middleware |
| Missing or invalid | Missing or invalid | Rejected; handler not reached | At least API Shield; do not assume Worker execution |

Also send a request with a forged passing `Approov-Result` and no Approov token. Through the
public API hostname, the Worker must replace it with its own non-passing result and the backend
must reject it.

## API Shield controls

| Scenario | Expected result |
|---|---|
| Valid JWT on a covered operation | JWT rule passes; other controls continue |
| Missing JWT where presence is required | API Shield blocks and records a token-validation violation |
| Expired, not-yet-valid, malformed, or bad-signature JWT | API Shield blocks |
| Valid JWT on an operation the user cannot access | Backend authorization still blocks |
| Body or parameters violate the imported schema | Schema rule logs or blocks according to rollout state |
| Valid browser `OPTIONS` request on an explicitly exempted operation | Preflight follows the documented exception policy |
| JWT or schema violation on an operation absent from Endpoint Management | Test must fail the release gate; add or intentionally exempt the operation |

Verify the JWT rule reads the intended user credential source. It must not consume
`Approov-Token`, and API Shield must not be configured to trust `Approov-Result`.

## Result-header parser and endpoint scope

Exercise backend middleware directly through the trusted test path, without weakening production
ingress controls:

| Scenario | Expected result |
|---|---|
| Missing `Approov-Result` on a protected operation | Reject |
| Repeated or comma-joined result values | Reject as ambiguous |
| Oversized header | Reject before base64 or JSON parsing |
| Invalid base64, invalid UTF-8, or invalid JSON | Reject |
| JSON array, scalar, `null`, or missing core field | Reject |
| Unknown core enum or wrong field type | Reject |
| `tokenResult=PASS`, binding `NOT_CHECKED` while binding is enabled | Reject |
| `tokenResult=PASS`, message signing `NOT_CHECKED` while signing is enabled | Reject |
| Passing core fields with unexpected diagnostic/plugin data | Ignore unknown data or apply an explicit deny-only policy |
| Intentionally public or webhook operation | Follow its explicit separate policy |
| Newly added operation with no classification | Fail the release gate until classified |

Confirm middleware executes before business logic and expensive downstream calls. Responses must
not reveal decoded claims, validation keys, expected hashes, signature material, or internal
failure detail.

## Token binding

When `APPROOV_TOKEN_BINDING_ENABLED = "true"`, run:

| Scenario | Expected `bindingResult` and action |
|---|---|
| Token bound to the exact `Authorization` string | `VALID`; continue |
| Token bound to another valid user's credential | `INVALID`; backend rejects |
| Header prefix, whitespace, case, or encoding differs from the bound value | `INVALID`; backend rejects |
| Binding header missing or empty | `MISSING_HEADER` or `EMPTY_HEADER`; backend rejects |
| Approov token has no binding claim | `MISSING_CLAIM`; backend rejects |
| User credential refreshes while an older bound Approov token is reused | `INVALID`; app obtains a newly bound token and retries safely |

This catches the common integration error where API Shield accepts the user JWT but the app and
Worker hash different byte strings for binding.

## Message signing

Set `APPROOV_MESSAGE_SIGNING_REQUIRED` to `install`, `account`, `either`, or `both`.
When unset, `ipk` requires install, `mskid` requires account, both permit either signature, and neither requires none.
Every present recognized member must pass, including optional members. Claims supply keys after token authentication.
For each required or present signature, begin with a correctly signed request and change one component at a time:

- Remove `Signature`, `Signature-Input`, or a required `Content-Digest`.
- Change the method, path, a covered header, or the body after signing.
- Change the Approov token without recreating the message signature.
- Send a stale, future, or expired signature outside the configured tolerance.
- Use the wrong installation key, account key ID, or signature type for the trusted claims.
- With `both`, remove or corrupt each signature independently; both cases must fail.
- With `either`, check installation-only, account-only, and dual signing. Each must pass.
- With each requirement, keep one valid member and corrupt the other; the request must fail and both results must be recorded.
- Exercise the maximum accepted body size and one byte above it.
- Exercise trailing slashes, percent-encoded path segments, query strings, empty bodies, and the
  largest legitimate signed upload.

Only an unmodified, correctly signed request should produce `messageSigningResult=VALID`.
If neither claim nor signature is present, an unset requirement produces `NOT_REQUIRED`; an explicit requirement must fail.
Backend middleware accepts `VALID`
or `NOT_REQUIRED` and rejects other signing outcomes. Confirm that proxies and
frameworks do not normalize a signed component differently before the Worker verifies it.

## ARC annotations

The ARC plugin does not participate in the core Worker pass/fail decision. Verify that:

- A supported ARC claim decodes to the expected `arcProperties` without changing `tokenResult`.
- Missing or malformed ARC data remains an annotation failure and cannot turn a failed token into
  a pass.
- Any backend ARC risk rule is explicit and deny-only; it never overrides a core failure.

## Routing, secrets, and rotation

| Scenario | Expected result |
|---|---|
| Request to public API hostname | Worker runs once and upstream receives one request |
| Direct request to origin IP or alternate hostname | Rejected by trusted ingress before application logic |
| Forged passing result sent directly to an origin address | Rejected by trusted ingress |
| Hostname absent from `APPROOV_BACKEND_CONFIG.apis` | Configuration/policy failure; never silently pass |
| Required backend-config secret absent | Deployment or startup fails; no unverified forwarding |
| Invalid or incomplete pass/fail key pair | Build-time validation or startup fails |
| Worker allowance exhausted | Fail-closed route returns an error rather than bypassing the Worker |
| API-assigned keyset KID in use | Newly issued token passes |
| Old and new keyset KIDs exported in both pass/fail JWKS with the migration switch enabled | Tokens for both KIDs pass during the bounded overlap |
| Non-assigned keyset KID with the migration switch disabled | Token is rejected |
| Current, pending, and previous ARC secrets exported during ARC rotation | ARC from expected overlap generations decodes |
| Retired key or ARC secret removed after its overlap window | Token is rejected or ARC annotation no longer decodes, as applicable |

Check for redirect loops and repeated Worker invocation. The existing-domain topology must not use
a compatibility option that sends the same-zone upstream subrequest back through the public Worker
Route.

## Observability and release gates

Confirm that logs and alerts distinguish API Shield JWT/schema failures, Worker configuration
errors, core Approov outcomes, backend parser failures, and origin-bypass attempts. Inspect sampled
events to prove that raw tokens, credentials, result payloads, and secrets are absent.

Do not approve go-live until all of the following are true:

- Every protected operation is registered and covered by the intended API Shield rules.
- Every Approov-required operation rejects all non-passing and malformed result cases.
- User authorization and Approov verification both pass before business logic runs.
- Direct-origin and alternate-hostname tests fail before application logic.
- CORS, login/bootstrap, health, webhook, and non-mobile exceptions are explicit and minimal.
- Binding and message-signing negative cases pass when those features are enabled.
- Worker routes fail closed and execute only once per request.
- Key rotation and rollback procedures have been exercised with non-production keys.
- Alerts and dashboards identify the responsible enforcement layer without exposing secrets.

The repository's deployed L2 suite in [`test/e2e/`](../test/e2e/) verifies Worker runtime and
header behavior with synthetic material. It does not configure a customer's API Shield account,
origin network controls, or backend middleware, so this staging matrix remains required.

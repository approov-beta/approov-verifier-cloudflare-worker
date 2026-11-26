# Approov Cloudflare Worker

![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-22%2B-339933?logo=node.js&logoColor=white)
![Tests](https://img.shields.io/badge/tests-vitest-6E9F18?logo=vitest&logoColor=white)
![Message Signing](https://img.shields.io/badge/Message%20Signing-RFC%209421-1f6feb)

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/approov-beta/approov-verifier-cloudflare-worker)

> [!NOTE]
> Copyright © 2026 Approov Limited. Released under the [MIT License](LICENSE).
> Customer-specific confidential logic is not part of this repository: Approov delivers it
> separately as [drop-in plugins](#plugins).

A reverse-proxy [Cloudflare Worker](https://developers.cloudflare.com/workers/) that
verifies [Approov](https://approov.io) attestation tokens at the edge, annotates each
request in annotation mode, or applies explicit protection actions in block mode.

---

## Table of Contents

- [Quickstart](#quickstart)
  - [Stage 1: First verified request](#stage-1-first-verified-request)
  - [Stage 2: Move to your API hostname](#stage-2-move-to-your-api-hostname)
  - [Stage 3: Add protection](#stage-3-add-protection)
  - [Stage 4: Enforce](#stage-4-enforce)
  - [Test locally](#test-locally)
  - [Tag a deployment](#tag-a-deployment)
- [How It Works](#how-it-works)
- [What the Worker Verifies](#what-the-worker-verifies)
- [Request Flow](#request-flow)
- [Configuration Reference](#configuration-reference)
  - [Secrets (key material)](#secrets-key-material)
  - [Environment variables (`[vars]`)](#environment-variables-vars)
- [Operation Modes](#operation-modes)
- [The `Approov-Result` Header](#the-approov-result-header)
- [Feature Guides](#feature-guides)
  - [Token audience checks](#token-audience-checks)
  - [Migrating from the default account secret](#migrating-from-the-default-account-secret)
  - [Rotating a keyset key](#rotating-a-keyset-key)
  - [Rotating ARC encoding secrets](#rotating-arc-encoding-secrets)
  - [Token binding checks](#token-binding-checks)
  - [Message signing checks](#message-signing-checks)
  - [Customizing the rejection response](#customizing-the-rejection-response)
- [Plugins](#plugins)
- [Custom Deployment Scenarios](#custom-deployment-scenarios)
- [Debugging](#debugging)
- [Troubleshooting](#troubleshooting)
- [Codebase Structure](#codebase-structure)
- [Testing](#testing)
- [Outcome Reference](#outcome-reference)
- [Useful Links](#useful-links)

---

## Quickstart

Get one verified request through the Worker. This takes about 15 minutes.

The quickstart uses the simplest setup: a `workers.dev` hostname, token check only, annotate
mode. Every other setup starts from here and changes one thing at a time. The guide has
four stages, and steps are numbered by stage, so step 2.1 is the first step of stage 2:

- [Stage 1: First verified request](#stage-1-first-verified-request). The same for everyone, 8 steps.
- [Stage 2: Move to your API hostname](#stage-2-move-to-your-api-hostname). Pick one of three setups, 3 steps.
- [Stage 3: Add protection](#stage-3-add-protection). One layer at a time, 2 steps per layer.
- [Stage 4: Enforce](#stage-4-enforce). At the backend or at the edge, 2 steps.

Do not skip stage 1. It proves your Approov account and keys work before Cloudflare routing
is involved.

You need:

- Node.js 22 or later.
- The [Approov CLI](https://ext.approov.io/docs/latest/approov-installation/) 3.6.0 or later
  ([approovcli.zip](https://approov.io/downloads/approovcli.zip)), with an admin role.
- A Cloudflare account with a Worker entitlement.
- `curl` and [`jq`](https://jqlang.org/).

The commands assume a POSIX shell. On Windows, follow the
[Windows quickstart (PowerShell)](docs/windows-quickstart.md).

### Stage 1: First verified request

#### Step 1.1: Save your hostname in a variable

The Worker picks its Approov settings from the hostname each request arrives on. On
`workers.dev` that hostname is `approov-gateway.<your-subdomain>.workers.dev`:

- `approov-gateway` is the `name` in [`wrangler.toml`](wrangler.toml).
- Your subdomain is shown at the bottom of **Workers & Pages** in the Cloudflare dashboard.

Several commands below need this hostname, and a typo in any of them breaks the setup. So
type it once and save it in a shell variable named `API_HOST`. Replace `<your-subdomain>`
first:

```shell
export API_HOST="approov-gateway.<your-subdomain>.workers.dev"
```

From now on, wherever a command contains `"$API_HOST"`, your shell puts the hostname there.
You can copy those commands as they are.

Good to know:

- **It is only a shortcut for this guide.** The Worker, Wrangler and Approov never read it.
  It is not the same as `API_DOMAIN` in `wrangler.toml`, which is where the Worker sends
  requests.
- **It exists only in the terminal where you set it.** In a new terminal window or tab, run
  the `export` line again.
- **Check it whenever a command behaves oddly:**

  ```shell
  echo "$API_HOST"
  ```

  This must print your hostname. If it prints an empty line, the `approov` commands fail with
  misleading errors such as `type is only valid with genExample`, or print nothing.

#### Step 1.2: Install and log in

```shell
npm install
npx wrangler login
```

A browser window opens. Allow Wrangler to use your Cloudflare account.

#### Step 1.3: Create a keyset key

```shell
approov keyset -add ES256 -kid example-es256
```

Skip this if `approov keyset -list` already shows a key you want to use. Use its key ID in
step 1.4. See [Managing Key Sets](https://docs.approov.io/operations/managing-key-sets/).

#### Step 1.4: Register the hostname with that key

```shell
approov api -add "$API_HOST" -keySetKID example-es256
```

**Do not leave out `-keySetKID`.** A hostname without a keyset key uses your account's default
secret. The Worker refuses that and returns `500` for every request.

#### Step 1.5: Export the config and check it

```shell
approov secret -getBackendConfig approov-config.json
jq '.apis | map_values(.kid // "NO KEYSET KEY")' approov-config.json
```

This lists every hostname in the export with its key ID. Yours must be there with the key
from step 1.3:

```json
{
  "approov-gateway.example.workers.dev": "example-es256"
}
```

| You see | Fix |
|---|---|
| Your hostname is not listed | It is not registered. Check `echo "$API_HOST"`, then repeat step 1.4. |
| `"NO KEYSET KEY"` beside your hostname | It has no keyset key. Repeat step 1.4 with `-keySetKID`. |

Repeat this step after every keyset or API change. The Worker only knows what you upload.
The file holds key material. The repository ignores it so it cannot be committed by accident.

<details>
<summary>What the whole export looks like</summary>

```json
{
  "currentArcEncodingSecret": "ObfuscatedCurrentSecret",
  "pendingArcEncodingSecret": "ObfuscatedPendingSecret",
  "previousArcEncodingSecrets": [
    {
      "secret": "ObfuscatedPreviousSecret",
      "timestamp": "2026-04-08T12:19:30+01:00"
    }
  ],
  "defaultPassJWKS": {
    "keys": [
      { "alg": "A256GCMKW", "k": "ObfuscatedSymmetricKey",  "kid": "_A256GCMKW", "kty": "oct", "use": "enc" },
      { "alg": "HS256",     "k": "ObfuscatedSymmetricKey2", "kid": "_HS256",     "kty": "oct", "use": "sig" }
    ]
  },
  "passJWKS": {
    "keys": [
      { "alg": "ES256", "crv": "P-256", "kid": "example-es256", "kty": "EC", "use": "sig", "x": "ObfuscatedPassKeyX", "y": "ObfuscatedPassKeyY" }
    ]
  },
  "failJWKS": {
    "keys": [
      { "alg": "ES256", "crv": "P-256", "kid": "example-es256", "kty": "EC", "use": "sig", "x": "ObfuscatedFailKeyX", "y": "ObfuscatedFailKeyY" }
    ]
  },
  "arcFlagMappings": { "1": "debug", "2": "scan-fail" },
  "apis": {
    "approov-gateway.example.workers.dev": {
      "kid": "example-es256",
      "isPassKeyPresent": true,
      "isFailKeyPresent": true,
      "comment": "API uses a key ID present in both the pass and fail key sets"
    }
  }
}
```

The key ID of each hostname must be present in both `passJWKS` and `failJWKS`.

</details>

#### Step 1.6: Upload the config and deploy

```shell
npx wrangler secret put APPROOV_BACKEND_CONFIG < approov-config.json
npm run validate:config
npm run deploy
```

If Wrangler asks to create the Worker, say yes. The whole export goes into one encrypted
secret, and Wrangler refuses to deploy without it.

Both `npm` commands read `approov-config.json` and stop if your hostname has no keyset key in
it. Keep the file beside `wrangler.toml` and export it again before each deploy.

`wrangler.toml` needs no changes yet. It forwards to `postman-echo.com`, which sends back the
headers it received, so you can see what the Worker added.

#### Step 1.7: Test with example tokens

```shell
approov token -genExample "$API_HOST"
approov token -genExample "$API_HOST" -type invalid
```

Save both:

```shell
export VALID_APPROOV_TOKEN='<the valid token>'
export INVALID_APPROOV_TOKEN='<the invalid token>'
```

Call the Worker:

```shell
curl -sS "https://$API_HOST/get" --compressed -H "Approov-Token: $VALID_APPROOV_TOKEN" \
  | jq -r '.headers."approov-result"' | base64 -d \
  | jq '{tokenResult, bindingResult, messageSigningResult, key: .tokenVerification.verification.keyId}'
```

```json
{
  "tokenResult": "PASS",
  "bindingResult": "DISABLED",
  "messageSigningResult": "NOT_REQUIRED",
  "key": "example-es256"
}
```

| Token | `tokenResult` |
|---|---|
| `$VALID_APPROOV_TOKEN` | `PASS`, with `key` showing your key ID |
| `$INVALID_APPROOV_TOKEN` | `FAIL` |
| No `Approov-Token` header | `MISSING_HEADER` |

Example tokens expire after 2 hours. Generate new ones after any keyset change. Never generate
long-lived valid tokens for a production account.

The result shows up here only because Postman Echo sends request headers back. The Worker adds
`Approov-Result` to the request it forwards, not to the response. `/get` is a Postman Echo
path. The root path `/` is not.

#### Step 1.8: Test from your app

Point a test build of your app at `https://$API_HOST` and watch the results:

```shell
npx wrangler tail --format pretty
```

For more detail, set `APPROOV_DEBUG = "true"` and `APPROOV_LOGGING_ENABLED = "true"` in
`wrangler.toml` and deploy again.

#### If it fails

Run `npx wrangler tail --format pretty` in a second terminal and repeat the request. The
response body never says why. The log does. Then find the symptom in
[Troubleshooting](#troubleshooting).

### Stage 2: Move to your API hostname

`workers.dev` is for testing only. For real traffic, pick the row that matches your API:

| Your API today | Setup | `API_HOST` | `API_DOMAIN` |
|---|---|---|---|
| Hostname already proxied by Cloudflare (orange cloud) | Worker Route | The existing API hostname | The same hostname |
| Origin outside Cloudflare, or you want a new public hostname | Custom Domain | The new hostname | The origin's hostname |
| Several Cloudflare hostnames, each with its own origin | Worker Route with pass-through | Each hostname | Remove it |

#### Step 2.1: Register the new hostname

Run the `export` line from step 1.1 again with the new hostname. Then repeat steps 1.4 and 1.5
to register it and check the export. For several hostnames, repeat step 1.4 for each one.

#### Step 2.2: Route traffic to the Worker

Add the block for your setup to `wrangler.toml`. Then repeat step 1.6 to upload the config
and deploy.

**Worker Route**

```toml
workers_dev = false

[[routes]]
pattern = "api.example.com/*"
zone_name = "example.com"

[vars]
API_DOMAIN = "api.example.com"
```

**Custom Domain**

```toml
workers_dev = false

[[routes]]
pattern = "api.example.com"
custom_domain = true

[vars]
API_DOMAIN = "origin.example.net"
```

**Worker Route with pass-through**

```toml
workers_dev = false

[[routes]]
pattern = "api.example.com/*"
zone_name = "example.com"

[[routes]]
pattern = "testapi.example.com/*"
zone_name = "example.com"

[vars]
API_PASSTHROUGH = "true"
# Remove API_DOMAIN.
```

> [!WARNING]
> A Worker Route takes all traffic for that hostname as soon as you deploy. If the uploaded
> config has no `kid` for the hostname, every request returns `500`. `npm run deploy` stops
> when the local `approov-config.json` shows that, so always upload the same file you
> validated. Try a staging hostname first, and never turn on `APPROOV_ECHO_MODE` on a live
> hostname.

Details and diagrams: [deployment topologies](docs/deployment-topologies.md) and
[existing API domain](docs/existing-domain.md).

#### Step 2.3: Test on the new hostname

Repeat step 1.7 with a real path on your API instead of `/get`. Your API does not send the
result back, so read it in your backend logs, or set `APPROOV_LOGGING_ENABLED = "true"` and
watch `npx wrangler tail`.

### Stage 3: Add protection

In annotate mode nothing is rejected, so each layer is safe to try on live traffic. Do both
steps for one layer, then start again for the next.

#### Step 3.1: Turn on one layer

Pick a row. Run the Approov part first, then change the Worker part.

| Layer | In Approov | In the Worker | Passing result |
|---|---|---|---|
| Token check | Done in stage 1 | Done in stage 1 | `tokenResult: PASS` |
| [Audience](#token-audience-checks) | `approov policy -setAudience on` first | `APPROOV_TOKEN_AUDIENCE_FROM_HOST = "true"` | `tokenResult: PASS` |
| [Token binding](#token-binding-checks) | The app sets the binding value in the SDK | `APPROOV_TOKEN_BINDING_ENABLED = "true"` | `bindingResult: VALID` |
| [Installation message signing](#message-signing-checks) | `approov policy -setInstallPubKey on`, and the app signs requests | Nothing. The Worker checks it when the token asks for it. | `messageSigningResult: VALID` |
| [Account message signing](#message-signing-checks) | `approov secret -messageSigningKey get-base64url` | `npx wrangler secret put APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET`, and add the name to `[secrets].required` | `messageSigningResult: VALID` |

#### Step 3.2: Deploy and test

```shell
npm run deploy
```

Send a request and look for the passing result from the table. Each linked guide has the
full rules and test commands. Test message signing from the app.

### Stage 4: Enforce

Until now the Worker only reports.

#### Step 4.1: Choose where to reject

Pick where failing requests are rejected:

| Option | Setting | Who rejects |
|---|---|---|
| Backend (default) | `APPROOV_MODE = "annotate"` | Your backend reads `Approov-Result` and rejects anything that is not passing. |
| Edge | `APPROOV_MODE = "block"` plus an action per layer | The Worker returns `403`. Your backend gets no `Approov-Result`. |

See [Operation Modes](#operation-modes) for the settings.

#### Step 4.2: Close every path around the Worker

Before going live, close every path to your origin that skips the Worker, and bypass caches
for protected paths. In annotate mode the backend can trust `Approov-Result` only if the
Worker is the only way in. Follow
[Backend Enforcement and Trusted Ingress](docs/backend-enforcement.md).

### Test locally

Optional. Worker secrets are not available in local development, so write the config to
`.dev.vars` first:

```shell
printf "APPROOV_BACKEND_CONFIG='%s'\n" "$(jq -c . approov-config.json)" > .dev.vars
npm start
```

`.dev.vars` needs the whole JSON on one line, which is what `jq -c` produces. Add optional
settings from [`.dev.vars.example`](.dev.vars.example) below that line. The file is
git-ignored. Never commit it.

The Worker listens on port 8787. It picks its settings from the hostname, so call your
registered hostname and resolve it to localhost. A request to `localhost` returns `500`.

```shell
curl -sS --resolve "$API_HOST:8787:127.0.0.1" "http://$API_HOST:8787/get" --compressed \
  -H "Approov-Token: $VALID_APPROOV_TOKEN" \
  | jq -r '.headers."approov-result"' | base64 -d | jq
```

### Tag a deployment

Attach a source version to each deployment. From a Git checkout:

```shell
npm run deploy -- --tag "$(git describe --tags --always --dirty)"
```

Git returns a release tag, a tag plus later commits, or a commit ID. Modified tracked files
add `-dirty`.

In PowerShell:

```powershell
$workerVersion = git describe --tags --always --dirty
npm run deploy -- --tag $workerVersion
```

From a ZIP download, use the release version you downloaded:

```shell
npm run deploy -- --tag v2.0.0
```

Cloudflare shows the tag under **Workers & Pages → your Worker → Deployments**. See
[Cloudflare versions and deployments](https://developers.cloudflare.com/workers/versions-and-deployments/)
and the [Wrangler deployment options](https://developers.cloudflare.com/workers/wrangler/commands/workers/).

---

## How It Works

The worker sits in front of your API as a reverse proxy. For every request it:

1. Reads the Approov token from a configurable header (default `Approov-Token`).
2. Verifies the token signature against your **pass** and **fail** key sets.
3. Optionally decodes the `arc` claim, checks token binding, and verifies RFC 9421 message signatures.
4. In `annotate` mode, forwards every request with `Approov-Result`.
5. In `block` mode, applies each layer's action and never forwards `Approov-Result`.

Set `APPROOV_MODE` explicitly. See [Operation Modes](#operation-modes).

---

## What the Worker Verifies

The data stream of an Approov attestation is carried inside the token. Broadly there are
three questions to answer:

| Question | How it is answered |
|---|---|
| **Was the token issued by Approov?** | A passing attestation is signed by the Approov **Pass** secret; a failing attestation by the **Fail** secret; anything else is tampering. |
| **Did attestation pass or fail?** | Determined by which key set verifies the signature (`PASS` vs `FAIL`). |
| **Which device property flags are present?** | Encoded in the `arc` (Attestation Response Code) claim, decoded with the ARC encoding secret. |

> [!WARNING]
> ARC flags include their own pass/fail signal, but the **token signature must still be
> verified**. Otherwise an attacker could embed a passing ARC into a JWT re-signed with
> their own key material.

**Token binding** ties a token to a specific client session or piece of request data
(such as the `Authorization` header). **Message signing** cryptographically proves that
request headers and/or the body were not tampered with in transit. Token binding is optional. Deployment requirements select message signing; trusted claims supply its keys — see the [feature guides](#feature-guides).

---

## Request Flow

```mermaid
flowchart TD
    A[Client request] --> B{Configuration valid?}
    B -->|No| X[Refuse startup, or return 500]
    B -->|Yes| P{Incoming hostname registered in apis?}
    P -->|No| X2[Return 500]
    P -->|Yes| S{Path protected?}
    S -->|"No: outside APPROOV_PROTECTED_PATHS"| U[Remove Approov-Result]
    S -->|"Yes: every path by default"| C[Verify Approov token]
    C --> D[Check enabled binding and required or present signatures]
    D --> E{APPROOV_MODE}
    E -->|annotate| F[Replace Approov-Result with authoritative result]
    E -->|block| G{Any blocking layer failed?}
    G -->|Yes| H[Return configured block response]
    G -->|No| I[Remove Approov-Result]
    F --> O[Forward to origin]
    I --> O
    U --> O
    O -->|Origin unreachable| Y[Return 502]
    O -->|Origin responds| R[Return origin response]
    X --> L[Emit optional request summary]
    X2 --> L
    H --> L
    Y --> L
    R --> L
```

Two diagnostic paths are left out of the diagram. With `APPROOV_ECHO_MODE` the Worker replies
with the rewritten request instead of forwarding it. A forwarded request that comes back to the
Worker is answered with `508 Loop Detected`.

The message-signing requirement comes from `APPROOV_MESSAGE_SIGNING_REQUIRED`, or from the
token's claims when that setting is unset:

```mermaid
flowchart TD
    A[Completed token verification] --> B{Signature, expiry and audience valid?}
    B -->|No| N[Signing NOT_CHECKED]
    B -->|PASS or authentic FAIL| Q{APPROOV_MESSAGE_SIGNING_REQUIRED set?}
    Q -->|Yes| R1["Requirement: the configured install, account, either or both"]
    Q -->|No| C{Signing claims in the token}
    C -->|Neither| R2["Requirement: none"]
    C -->|ipk only| R3["Requirement: install"]
    C -->|mskid only| R4["Requirement: account"]
    C -->|Both| R5["Requirement: either"]
    R1 --> S{Requirement is none and no install or account member was sent?}
    R2 --> S
    R3 --> S
    R4 --> S
    R5 --> S
    S -->|Yes| D[Signing NOT_REQUIRED]
    S -->|No| H[Check body digest once, then verify every required or present member independently]
    H --> I{Member results}
    I -->|All valid| V[VALID]
    I -->|Any verification failure| X[Failure outcome]
    I -->|Internal error| E[ERROR]
    N --> J[Record result and apply mode and actions]
    D --> J
    V --> J
    X --> J
    E --> J
```

With `either`, at least one of the two members must be sent, and every member that is sent
must verify. See [message signing checks](#message-signing-checks) for the full rules.

---

## Configuration Reference

### Secrets (key material)

Set with `wrangler secret put APPROOV_BACKEND_CONFIG` (or, locally, in `.dev.vars`). The worker
loads all Approov JWKS and ARC configuration from this single encrypted value.

| Secret | Required | Description |
|---|---|---|
| `APPROOV_BACKEND_CONFIG` | Required | Complete CLI-exported config. Supplies default/pass/fail JWKS, per-domain API assignments, current/pending/previous ARC secrets, and ARC mappings in one encrypted value. |
| `APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET` | When checking account signatures | Account message-signing secret (raw, base64, or base64url — auto-detected). Account signatures use a device key derived from these secret bytes. |

> **Why a single secret?** Sensitive material is encrypted at rest by Cloudflare, never
> committed to source control or stored in plaintext in `wrangler.toml`, and you avoid
> escaping JSON key sets inside TOML.

### Environment variables (`[vars]`)

Defined in [`wrangler.toml`](wrangler.toml). **Changes take effect on the next `npm run deploy`, or when `npm start` restarts locally.**

<details>
<summary><strong>Upstream</strong></summary>

| Variable | Default | Description |
|---|---|---|
| `API_DOMAIN` | _(required unless `API_PASSTHROUGH`)_ | Upstream target domain. Must not be set when `API_PASSTHROUGH = "true"`. |
| `API_PORT` | `443` | Upstream port. Ignored under `API_PASSTHROUGH`. |
| `API_PASSTHROUGH` | `false` | Forward to the hostname the request arrived on, so one deployment can protect several API hostnames. **Worker Route topology only** — see [deployment topologies](docs/deployment-topologies.md). |

</details>

<details>
<summary><strong>Mode and actions</strong></summary>

| Variable | Default | Rule |
|---|---|---|
| `APPROOV_MODE` | Required | `annotate` or `block`; no implicit default. |
| `APPROOV_TOKEN_ACTION` | Required in block mode | `block` or `continue`. |
| `APPROOV_MESSAGE_SIGNING_ACTION` | Required in block mode | `block` or `continue`. |
| `APPROOV_TOKEN_BINDING_ACTION` | Required when binding is enabled in block mode | `block` or `continue`; prohibited otherwise. |
| `APPROOV_BLOCK_RESPONSE_STATUS` | `403` | Block mode only; integer from 200 to 599. |
| `APPROOV_BLOCK_RESPONSE_BODY` | `Forbidden` | Block mode only; string. |
| `APPROOV_PROTECTED_PATHS` | unset (every path) | Comma-separated path prefixes to check; `*` stands for one path segment, so `/shop/*/*/checkout` covers every market. An entry matches its path and everything below it: `/api` covers `/api` and `/api/users`, and `/api/*` covers only what is below `/api`. Matching ignores case, percent-encoding, duplicate slashes and `;` path parameters, and also covers a suffix such as `/checkout.json`. Other paths are forwarded unchecked and unannotated. Each entry must start with `/` and must not end with `/`. |

Annotation mode prohibits all action and block-response variables, including empty values.
Both actions run checks. `continue` forwards a failed result; `block` rejects it.

</details>

<details>
<summary><strong>Token verification</strong></summary>

| Variable | Default | Description |
|---|---|---|
| `APPROOV_TOKEN_HEADER_NAME` | `"Approov-Token"` | Header carrying the Approov token. |
| `APPROOV_STATUS_HEADER_NAME` | `"Approov-Status"` | Header carrying the client token-fetch status. Match the service layer configuration. |
| `APPROOV_TOKEN_AUDIENCE` | _(unset)_ | If set, the token's `aud` claim must match. |
| `APPROOV_TOKEN_AUDIENCE_FROM_HOST` | `"false"` | If `"true"`, the token's `aud` claim must match the hostname of the incoming request. Cannot be combined with `APPROOV_TOKEN_AUDIENCE`. |
| `APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET` | `false` | Deployment-wide migration switch. `true` accepts valid default HS256 tokens and exported pass/fail keyset pairs; return it to `false` after cached default tokens expire. |

`APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET = "false"` is the normal, secure mode:

- Only the exact keyset KID assigned to the incoming API domain is accepted.
- Default HS256 account-secret tokens are rejected.
- Requests for a domain still configured with the default account secret return a
  configuration error.

`APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET = "true"` is temporary migration mode:

- Valid default HS256 tokens are accepted with either no KID or the exported `_HS256` KID.
- Any exact keyset KID present in both exported `passJWKS` and `failJWKS` is also accepted.
- Old cached tokens and new keyset tokens can therefore overlap safely.
- A startup warning is emitted because compatibility applies to the entire Worker deployment.

The migration flow is: set the switch to `true`, move the APIs to keysets, wait for old cached
tokens to expire, and then set it back to `false`.

</details>

The worker accepts signing JWKs declared as `HS256`/`oct`, `ES256`/`EC P-256`,
or `RS256`/`RSA`. Encryption-only keys such as `A256GCMKW` are ignored; JWE is
not supported. Every verification attempt is pinned to the selected JWK's
declared algorithm and key type.

<details>
<summary><strong>Token binding</strong></summary>

| Variable | Default | Description |
|---|---|---|
| `APPROOV_TOKEN_BINDING_ENABLED` | `false` | Enable token-binding verification. |
| `APPROOV_TOKEN_BINDING_HEADER_NAME` | `"Authorization"` | Header whose value is bound to the token. |
| `APPROOV_TOKEN_BINDING_CLAIM_NAME` | `"pay"` | Token claim holding the bound (hashed) value. |

</details>

<details>
<summary><strong>Message signing</strong></summary>

| Variable | Default | Description |
|---|---|---|
| `APPROOV_MESSAGE_SIGNING_REQUIRED` | _(unset)_ | Require `install`, `account`, `either`, or `both` for every trusted token. Unset preserves token-only compatibility; see [message signing checks](#message-signing-checks). |
| `APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS` | `60` | Allowed clock skew for `created`/`expires`. |
| `APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES` | `1048576` | Max body bytes consumed while checking `Content-Digest`. |
| `APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID` | _(unset)_ | If set, must match `mskid` whenever an account signature is checked. Does not itself require an account signature. |

</details>

<details>
<summary><strong>Diagnostics</strong></summary>

| Variable | Default | Description |
|---|---|---|
| `APPROOV_DEBUG` | `false` | Emit detailed `approov:` debug logs. |
| `APPROOV_ECHO_MODE` | `false` | Reply with the (rewritten) request as JSON instead of forwarding upstream. Credential headers are redacted. **Testing only.** |
| `APPROOV_ANALYTICS_ENABLED` | `false` | Write core outcomes to the optional `APPROOV_ANALYTICS` dataset binding. |
| `APPROOV_LOGGING_ENABLED` | `false` | Log every request result, including individual signatures and safe plugin summaries. Independent of Analytics Engine. |

</details>

---

## Operation Modes

| Mode | Protection failures | Origin request |
|---|---|---|
| `annotate` | Always forward | Replace any client `Approov-Result` with the Worker's result. |
| `block` | Apply each layer's `block` or `continue` action | Never forward `Approov-Result`. |

The example configuration explicitly selects annotation mode. To enforce at the edge, replace its mode and add actions:

```toml
APPROOV_MODE = "block"
APPROOV_TOKEN_ACTION = "block"
APPROOV_MESSAGE_SIGNING_ACTION = "block"
APPROOV_TOKEN_BINDING_ENABLED = "true"
APPROOV_TOKEN_BINDING_ACTION = "block"
```

Any failed blocking layer rejects the request. `ERROR` and unavailable required checks also fail.
Disabled binding and signing `NOT_REQUIRED` are acceptable. All actions can be `continue`.

In annotation mode, the backend must require `tokenResult=PASS`, binding `VALID` or `DISABLED`,
and signing `VALID` or `NOT_REQUIRED`. Reject missing, malformed, or non-passing annotations.
See [backend enforcement](docs/backend-enforcement.md). Update older middleware that accepts signing `DISABLED`.
Block mode requires a backend ingress that trusts the Worker; result-header middleware applies to annotation mode only.

`APPROOV_LOGGING_ENABLED="true"` emits one structured summary per request in either mode.
`APPROOV_DEBUG` controls additional diagnostics. Errors and warnings remain enabled.
See [Worker analytics](docs/worker-analytics.md).

### Configuration validation

Use exact lowercase mode/action values and booleans `true`, `false`, `"true"`, or `"false"`.
Unknown `APPROOV_` names, removed variables, malformed values, and conflicting combinations are errors.
Plugin variables are accepted only when their plugin is installed and declares them.

`npm run validate:config` checks configuration even without a local backend export.
With an export, it also checks every hostname the deployment serves: each `[[routes]]` hostname
without a wildcard, and any registered `<name>.<subdomain>.workers.dev` hostname of this Worker.
A hostname that is missing from `apis`, has tokens disabled, or has no keyset key while
`APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET` is `false` stops validation and deployment.
The check reads the local export only. It cannot see the secret already uploaded to Cloudflare.
`npm run deploy -- --env staging` and `npm run versions:upload -- --config other.toml`
validate the selected configuration and command-line overrides before invoking Wrangler.
`npm start` also validates the local bindings and secrets that Wrangler loads.

The Worker validates actual bindings during initialization and refuses invalid uploads.
It uses Cloudflare's [global binding access](https://developers.cloudflare.com/workers/runtime-apis/bindings/#importing-env-as-a-global).
Cloudflare checks [top-level execution during uploads](https://developers.cloudflare.com/workers/observability/errors/#validation-errors-10021).
A request-time guard also rejects invalid binding changes with HTTP 500 before contacting the origin.
Local preflight cannot read existing encrypted Cloudflare secret values; initialization validates their contents.

---

## The `Approov-Result` Header

For each request the worker computes a verification result and (when annotating) attaches it
as the `Approov-Result` header on the **upstream** request. The value is **base64-encoded
JSON** with these fields:

| Field | Type | Description |
|---|---|---|
| `tokenResult` | string | Token outcome — see [Outcome Reference](#outcome-reference). |
| `clientStatus` | string \| null | Client token-fetch status, filtered to known lowercase SDK status names. Missing headers produce `null`. Other values produce `invalid`. |
| `bindingResult` | string | Binding outcome — see [Outcome Reference](#outcome-reference). |
| `messageSigningMode` | string | `none` \| `install` \| `account` \| `either` \| `both` \| `unknown`. Explicit requirement or compatibility requirement from trusted claims. |
| `messageSigningResult` | string | Message-signing outcome — see [Outcome Reference](#outcome-reference). |
| `messageSigningVerification` | object \| null | Detail object (`ok`, `status`, `mode`, `signatureName`, `error`, `signatures`). `signatures.install` and `.account` contain individual results or `null`, or `null` when not run. |
| `tokenVerification` | object \| null | `{ ok, status, decoded, verification }`; `verification` is populated only after signature verification and identifies the API domain, key source, algorithm, and KID. |
| `arcProperties` | string[] \| null | Decoded ARC properties (`pass`/`fail` first), or `null` when no `arc` claim was present. |

`clientStatus` is a client diagnostic. It never changes token verification or enforcement.
A request with `clientStatus: success` and no valid token still fails token verification.
Unknown, repeated, empty, and oversized status values produce `invalid`. The Worker does not log their raw values.
Structured request logs also contain `clientStatus`. Analytics Engine schema version 3 adds this value in `blob11`.
Before rollout, update version-specific log and analytics consumers. See the [analytics migration notes](docs/worker-analytics.md#analytics-engine-columns).

Decode the result like this:

```shell
curl ... | jq -r '.headers."approov-result"' | base64 -d | jq
```

```jsonc
{
  "tokenResult": "PASS",
  "bindingResult": "DISABLED",
  "messageSigningMode": "none",
  "messageSigningResult": "NOT_REQUIRED",
  "messageSigningVerification": { "ok": true, "status": "NOT_REQUIRED", "mode": "none", "signatureName": null, "error": null, "signatures": { "install": null, "account": null } },
  "tokenVerification": {
    "ok": true,
    "status": "PASS",
    "decoded": { "exp": 1766072633, "ip": "1.2.3.4", "did": "ExampleApproovTokenDID==" },
    "verification": {
      "apiDomain": "approov-gateway.example.workers.dev",
      "source": "passJWKS",
      "algorithm": "ES256",
      "keyId": "example-es256"
    }
  },
  "arcProperties": ["pass"]
}
```

> [!NOTE]
> The header is added to the request sent to `API_DOMAIN`; it is **not** automatically added
> to the client response. In this quickstart you see it because Postman Echo reflects request
> headers back in its JSON body.

---

## Feature Guides

Use the workflow that matches the material being changed:

| Situation | Compatibility switch | What overlaps |
|---|---|---|
| Keyset API, no rotation | `false` | Only the KID assigned to the incoming API domain is accepted. |
| Keyset-to-keyset rotation | Temporarily `true` | Old and new KIDs that each exist in both `passJWKS` and `failJWKS`. |
| Default HS256 to keyset migration | Temporarily `true` | Cached default HS256 tokens and the new keyset KID. |
| ARC secret rotation | No change required | Current, pending, and previous ARC encoding secrets. |

> [!IMPORTANT]
> The compatibility switch is deployment-wide. During a keyset rotation it also enables valid
> default account-secret HS256 tokens, even if the API being rotated already uses a keyset.
> Keep the overlap short, verify token audiences where possible, and return the switch to
> `false` after cached old tokens expire. Use separate Worker deployments if different APIs
> require independent rotation windows.

### Token audience checks

With `APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET = "false"` the worker accepts only the keyset key
assigned to the incoming API domain. That does not separate domains that are assigned the same
keyset key, and while default-secret compatibility is enabled the account-wide HS256 secret and
every exported pass/fail keyset pair are accepted on every domain. In those cases a token issued
for one domain also verifies on the others. Audience checks close that gap.

Enable audience inclusion on your Approov account so every token carries an `aud` claim set to
the domain it was issued for (wildcard tokens carry `*`):

```shell
approov policy -setAudience on
```

Then choose one of:

- `APPROOV_TOKEN_AUDIENCE_FROM_HOST = "true"` (recommended): the `aud` claim must equal the
  hostname of the incoming request. This works for a worker serving one or several hostnames,
  including pass-through forwarding.
- `APPROOV_TOKEN_AUDIENCE = "<domain>"`: the `aud` claim must equal this fixed value. Use it only
  when the worker serves a single hostname.

The audience is the domain your app calls, which is the worker's own hostname, not
`API_DOMAIN`. Tokens with a missing, empty or `*` audience are rejected. A mismatch yields
`tokenResult: INVALID_AUD`.

Enable the account policy first and deploy the worker setting once tokens with `aud` are being
issued; until then every token would be rejected with `INVALID_AUD`.

Audience checking is strongly recommended while default-secret compatibility is enabled.
The default secret is account-wide, so an HS256 token without a checked audience cannot be
cryptographically restricted to one API domain.

### Migrating from the default account secret

Customers already using a per-API keyset should leave
`APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET = "false"`. The worker then accepts only the exact
KID assigned to the incoming hostname in the exported `apis` map.

For a controlled migration:

1. Create the new keyset key without changing the API assignment.
2. Export and deploy the complete transitional backend configuration containing the default
   key and the new keyset pass/fail pair.
3. Set `APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET = "true"`. This affects the entire Worker
   deployment and produces a startup warning.
4. Confirm existing HS256 traffic reports `verification.source: "defaultPassJWKS"`.
5. Switch staging and then production API assignments to the new keyset.
6. Monitor until traffic reports only `passJWKS` or `failJWKS` for the new KID.
7. Wait at least the configured Approov token lifetime plus a safety margin, then deploy a
   fresh final CLI export.
8. Set `APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET = "false"`. This explicit change completes
   migration and immediately rejects any remaining cached default tokens.

While compatibility is enabled, a token with an exact KID found in both exported keyset
pass/fail sets can be verified before the `apis` assignment changes. Default-secret
verification is pass-only: a bad HS256 signature is `INVALID_SIG`, never a trusted failure
token, and its ARC is not decoded. Rotate the account secret only for an independent security
reason; rotation is not required to complete this migration.

### Rotating a keyset key

Keyset rotation uses a new KID. The old and new pass/fail keys coexist in the exported JWKS
while cached tokens signed with the old key drain. This is different from ARC rotation: there
are no `pendingPassJWKS` or `pendingFailJWKS` fields.

For a rotation without an availability gap:

1. Add the new keyset key with a new KID, but do not change the API assignment yet.
2. Run `approov secret -getBackendConfig approov-config.json`. Confirm that both the old and
   new KIDs occur exactly once in `passJWKS` and exactly once in `failJWKS`.
3. Upload this transitional configuration to the Worker.
4. Temporarily set `APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET = "true"`. In this mode the Worker
   can verify the new KID before the exported `apis` assignment changes. Remember that this
   also enables the default account HS256 secret for the whole deployment.
5. Generate valid and invalid example tokens for staging. Confirm both are verified and that
   `tokenVerification.verification.keyId` reports the new KID; the source should be
   `passJWKS` for valid tokens and `failJWKS` for genuine failure tokens.
6. Change the staging API and then the production API to the new keyset KID. Preserve every
   other API option when updating the Approov API configuration.
7. Monitor `tokenVerification.verification.keyId` until the old KID is no longer observed.
8. Wait at least the configured token lifetime plus a safety margin before removing the old
   key from the Approov keyset.
9. Export and deploy the final backend configuration, which should no longer contain the old
   KID.
10. Set `APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET = "false"`. Confirm new-KID PASS and FAIL
    traffic continues and old-KID tokens now produce `INVALID_SIG`.

Do not reuse a KID with different key material. The overlap depends on the JWT header selecting
one unambiguous exported pass/fail pair. Audience verification is strongly recommended while
multiple API keysets are accepted by the deployment.

### Rotating ARC encoding secrets

The latest CLI backend export contains the active ARC secret in
`currentArcEncodingSecret`, an optional staged secret in `pendingArcEncodingSecret`, and
archived secrets in `previousArcEncodingSecrets`. Deploy the freshly exported configuration
before promoting a pending secret.

For every trusted PASS or FAIL token ARC, the worker tries the exported secrets in this order:

1. Current secret.
2. Pending secret, when present.
3. Previous secrets, in exported order.

This allows ARC decoding to continue before, during, and after promotion, including for cached
tokens encoded before the rotation. Duplicate secret values are tried only once. Re-export the
configuration with the latest Approov CLI before deploying a rotation so all active and archived
secrets are included.

ARC structure alone does not prove which rotation secret was used: a wrong secret can occasionally
produce a structurally valid but incorrect set of flags. The worker therefore checks every candidate
against the JWT's signed PASS/FAIL outcome. It uses the decoded properties only when the remaining
candidates agree on one interpretation; conflicting plausible interpretations leave `arcProperties`
as `null` and emit an ambiguity error rather than returning potentially incorrect security flags.
See [ARC secret rotation ambiguity](docs/arc-secret-rotation-ambiguity.md) for the decoder-level
reproduction, impact analysis, and guidance for reviewing other backend implementations.

### Token binding checks

Token binding ties a token to a value carried in a request header. It is **off** by default
(`APPROOV_TOKEN_BINDING_ENABLED = "false"`). To enable it, set `APPROOV_TOKEN_BINDING_ENABLED = "true"` and
deploy again.

A token is **bound** when the SHA-256/base64 hash of the binding header value (default
`Authorization`) matches the binding claim in the token payload (default `pay`). Change the
header with `APPROOV_TOKEN_BINDING_HEADER_NAME` and the claim with `APPROOV_TOKEN_BINDING_CLAIM_NAME`.

Generate a token that embeds a data hash:

```shell
approov token -genExample "$API_HOST" -setDataHashInToken 'Bearer 0123456789abcdef'
```

Send the **same** value in the binding header. As in the [local test](#test-locally), `--resolve` sends
the request to localhost while preserving the registered gateway hostname that selects its
Approov policy:

```shell
curl --resolve "$API_HOST:8787:127.0.0.1" \
  "http://$API_HOST:8787/get" -s --compressed \
  -H "Approov-Token: $VALID_APPROOV_TOKEN_WITH_HASH" \
  -H "Authorization: Bearer 0123456789abcdef" \
  | jq -r '.headers."approov-result"' | base64 -d | jq
```

```jsonc
{ "tokenResult": "PASS", "bindingResult": "VALID", /* ... */ }
```

A mismatching value yields `bindingResult: INVALID` even though the token itself is valid:

```shell
curl --resolve "$API_HOST:8787:127.0.0.1" \
  "http://$API_HOST:8787/get" -s --compressed \
  -H "Approov-Token: $VALID_APPROOV_TOKEN_WITH_HASH" \
  -H "Authorization: a random string" \
  | jq -r '.headers."approov-result"' | base64 -d | jq
```

```jsonc
{ "tokenResult": "PASS", "bindingResult": "INVALID", /* ... */ }
```

See [Approov Token Binding](https://ext.approov.io/docs/latest/approov-usage-documentation/#token-binding)
for full details.

### Message signing checks

The worker verifies [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) HTTP message
signatures using a vendored copy of `http-message-signatures` (under
[`vendor/http-message-signatures`](vendor/http-message-signatures)). When a `Content-Digest`
header is present it is validated too (RFC 9530, `sha-256`/`sha-512`).
The [vendor build guide](vendor/README.md) documents source inputs, licenses, and
the reproducible build checked by CI.

A signature must cover `@method`, the configured Approov token header, and the full
inbound URL. URL coverage can use `@target-uri` (used by current Approov service
signers), or all four of `@scheme`, `@authority`, `@path`, and `@query`.
The query component is required even when the original URL has no query, so a
query cannot be added later without invalidating the signature.

**Compatibility change:** custom signers that cover only `@path` and `@authority`
must switch to one of the complete URL forms above. There is no fallback to
partial URL coverage. See the [Approov React Native signer](https://github.com/approov/approov-service-react-native)
and [Unity signer](https://github.com/approov/approov-service-unity) for client examples.

Requests with a body must carry a `Content-Digest` header
(`MISSING_CONTENT_DIGEST` otherwise). When present, that header must itself be
signed. The worker checks its digest against the body before accepting the
signature. This policy applies to both installation and account signing.

Approov 3.7 service layers add a `Content-Digest` to every body they can read again,
including an empty one. They cannot digest a one-shot body or a body of unknown length
(sent chunked), and by default sign such a request without covering its body. The worker
reports `MISSING_CONTENT_DIGEST` for it. Send those bodies with a known length, or
handle the outcome with `APPROOV_MESSAGE_SIGNING_ACTION`.

A signature may also cover individual query parameters with `@query-param`. As RFC 9421
section 2.2.8 requires, the worker encodes the value with the
`application/x-www-form-urlencoded` percent-encode set (a space is `%20`) and rejects a
parameter that occurs more than once. This is in addition to the full URL coverage above.

Set `APPROOV_MESSAGE_SIGNING_REQUIRED` to choose the required signatures after token signature, expiry, and audience validation:

| Setting | Required signatures |
|---|---|
| `install` | An `install` member, using the trusted `ipk` key |
| `account` | An `account` member, using the trusted `mskid`, `did`, and configured account secret |
| `either` | At least one recognized member |
| `both` | Both named members |

Every recognized member present in either `Signature` or `Signature-Input` must pass, including optional members.
A valid install signature cannot hide an invalid account signature, or the reverse.
Missing key claims, missing secrets, unmatched members, and invalid signatures fail verification.
Unknown member names cannot satisfy a requirement. Well-formed unknown members are ignored.

For example, this setting accepts installation-only and dual-signed requests even when the token contains both key claims:

```toml
APPROOV_MESSAGE_SIGNING_REQUIRED = "either"
```

Use `both` when the deployment requires both protections. With `either`, removing one complete member leaves the other eligible to pass.
The claims supply verification keys; they do not prove that the app produced both signatures.
An unused claim does not require its key material: an installation-only request does not need the account secret or `did`.

When the setting is **unset**, compatibility with token-only deployments is retained:

| Claims | Required signatures |
|---|---|
| Neither | None: `NOT_REQUIRED` |
| `ipk` | `install`, using ECDSA P-256 |
| `mskid` | `account`, using a device-derived HMAC-SHA256 key |
| Both | At least one recognized member; every present member must pass |

An authentic `FAIL` token also receives these checks. Its attestation result stays `FAIL`.
Untrusted tokens produce `NOT_CHECKED`; a blocking signing action rejects this outcome.
An explicit requirement also rejects tokens with no signing claims. Leaving the setting unset permits those tokens without signatures.
Empty or malformed claims fail when their signature is required or present. Malformed signature headers fail even for tokens without signing claims.
Each signature must cover the required components itself. Both entries share one body-digest check.
The reported signing `mode` is the selected requirement (`either` for the two-claim compatibility case); per-member results show which signatures were checked.

For account signatures, the Worker derives the same device key as the attester:

```text
device_key = HMAC-SHA512(account_secret_bytes, base64decode(verified_token.did))
message_signature = HMAC-SHA256(device_key, signature_base)
```

The verified `did` claim must contain canonical, padded standard base64 for exactly 16 bytes.
Missing or malformed values produce `INVALID_DEVICE_ID_CLAIM` for the account signature.
Unpadded values, base64url, whitespace, and nonzero padding bits fail verification.
The Worker derives no key from an untrusted token. Installation-only tokens do not require `did`.
The fixed fallback DeviceID uses the same derivation, so every device that reports it shares one key.

**Account-signing compatibility:** the Worker accepts device-derived signatures only. It does not try the raw account secret as a verification key.
The Approov service version, not the SDK version, determines which key format an app receives.
A request signed with the raw account secret is rejected. If account signatures fail for every device after you enable this check,
contact [Approov support](https://approov.io/info/contact) to confirm that your account issues device-derived keys.

Optional tuning values:

```toml
APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS = "60"
APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES = "1048576"
```

For account signatures, retrieve (or rotate) your account secret with the Approov CLI — the
output also includes the key id (`mskid`):

```shell
approov secret -messageSigningKey get-base64url
# or rotate:
approov secret -messageSigningKey change
```

Store that account secret in `APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET`. Do not replace it with a
device key: the Worker derives that key for each authenticated request. Optionally also set a
fixed key id that the token's `mskid` must match:

```shell
npx wrangler secret put APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET
# optional, in [vars]:
# APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID = "<expected-mskid>"
```

Also add `APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET` to `[secrets].required` in
`wrangler.toml`. This makes Wrangler load it from `.dev.vars` locally and verify that it exists
before deployments that declare it as required. A missing secret on an account-signed request fails verification.

Keep this separate secret until the Approov backend export includes the message-signing key.

### Customizing the rejection response

In block mode, set `APPROOV_BLOCK_RESPONSE_STATUS` and `APPROOV_BLOCK_RESPONSE_BODY`.
Defaults are HTTP 403 and `Forbidden`. Bodyless statuses 204, 205, and 304 omit the configured body.
These fields are prohibited in annotation mode.

---

## Plugins

Optional capabilities are **drop-in plugins** under `plugins/<name>/` rather than part of the
core worker. The ARC plugin ships in this repository; Approov delivers customer-specific
confidential plugins separately, and you add one by copying its folder into `plugins/`. A plugin is discovered
automatically at build time, declares and parses its own configuration, and produces informational results.
These results enter annotations or structured logs according to the Worker mode and logging settings.
Plugins do not affect enforcement. When removing a plugin, also remove its configuration fields.

One plugin ships today, documented in its own folder:

| Plugin | Purpose | Docs |
|--------|---------|------|
| `arc` | Decode the `arc` claim into device-property labels (`arcProperties`). | [`plugins/arc/README.md`](plugins/arc/README.md) |

See the [plugin architecture guide](docs/plugins.md) for how discovery, the
plugin contract, and testing work.

---

## Custom Deployment Scenarios

Depending on your architecture, follow one of the dedicated guides:

- **[Deployment topologies](docs/deployment-topologies.md)** — start here: the three supported
  Cloudflare topologies with diagrams, which configuration layer is per-hostname versus
  per-deployment, and how many Workers you need for several API hostnames.
- **[Backend enforcement and trusted ingress](docs/backend-enforcement.md)** — implement the
  default annotation-mode decision and prevent direct-origin bypass.
- **[Deployment on an existing custom API domain](docs/existing-domain.md)** — intercept
  requests directly on an API domain already managed in Cloudflare and route them natively to
  your origin.
- **[Cloudflare API Shield deployment checklist](docs/api-shield-deployment.md)** — configure
  Endpoint Management, user JWT validation, the Worker Route, backend enforcement, and trusted
  origin ingress in the required order.
- **[API Shield with backend-enforced Approov verification](docs/parallel-jwt-validation.md)** —
  understand the responsibility split and stream structured logs to an external system.
- **[API Shield and Approov verification matrix](docs/api-shield-verification.md)** — prove the
  combined identity, app-integrity, backend, routing, and origin-bypass controls before go-live.

---

## Debugging

Set `APPROOV_DEBUG = "true"` to emit detailed logs covering:

1. Request evaluation start (token header presence, binding strategy, message-signing mode).
2. Token verification outcomes.
3. Binding verification status.
4. Message-signing status.
5. Safe core evaluation statuses and annotation metadata.

Debug logs exclude tokens, encoded ARC, decoded claims, binding hashes, bodies,
full URLs, and raw exception text. Decoded ARC properties and other safe plugin
details are available through opt-in [Worker analytics](docs/worker-analytics.md).

Stream them with:

```shell
npx wrangler tail --format pretty
```

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `500`, and the log reason says `uses the default account secret` | The hostname is registered without a keyset key. Do [steps 1.3 to 1.6](#step-13-create-a-keyset-key) of the quickstart. |
| `500`, and the log reason says `is not present in APPROOV_BACKEND_CONFIG.apis` | The hostname is not in the uploaded configuration. Check the hostname, then do [steps 1.4 to 1.6](#step-14-register-the-hostname-with-that-key). Locally, call the registered hostname with `curl --resolve` rather than `localhost`. |
| `500`, and the log reason says `has Approov tokens disabled` | The export has `isPassKeyPresent: false` for this hostname, so Approov issues no tokens for it. Register it with a keyset key: [steps 1.4 to 1.6](#step-14-register-the-hostname-with-that-key). |
| `npm start` or `npm run deploy` stops with `Invalid Approov configuration` | Preflight lists each invalid or unknown variable by name. Fix the listed entries in `wrangler.toml` or `.dev.vars`. If it names a hostname instead, that hostname is not registered or has no keyset key in `approov-config.json`: do [steps 1.4 to 1.6](#step-14-register-the-hostname-with-that-key). |
| Cloudflare rejects an upload with validation error `10021` | A deployed binding, usually the `APPROOV_BACKEND_CONFIG` secret, is missing or invalid. Upload the secret again from a fresh export. |
| Every token reports `INVALID_SIG` | The uploaded configuration does not hold the key that signed the token. Do [steps 1.5 and 1.6](#step-15-export-the-config-and-check-it) again after any keyset or API change, then generate new example tokens. |
| `502 Bad Gateway` with the body `Bad Gateway` | The Worker could not reach the upstream and logged `approov: upstream request failed`. Check `API_DOMAIN`, `API_PORT` and that the origin accepts HTTPS. |
| `508 Loop Detected` | The forwarded request came back to the Worker. `API_PASSTHROUGH` is enabled outside the Worker Route topology, `API_DOMAIN` names the Worker's own Custom Domain or `workers.dev` hostname, or `global_fetch_strictly_public` is on. A client that sends the `Approov-Gateway-Hop` header itself gets it too. See [deployment topologies](docs/deployment-topologies.md). |

Read the Worker's log lines with `npx wrangler tail --format pretty`.

---

## Codebase Structure

The worker is split into focused modules so each concern is easy to review and maintain.

**Entrypoint & orchestration**

| File | Responsibility |
|---|---|
| [`src/index.js`](src/index.js) | Cloudflare `fetch` entrypoint; validates the bindings when the Worker starts. |
| [`src/worker/handle-request.js`](src/worker/handle-request.js) | Top-level request lifecycle and enforcement/annotation decisions. |

**Configuration & shared primitives**

| File | Responsibility |
|---|---|
| [`src/config/schema.mjs`](src/config/schema.mjs) | Variable schema and policy rules shared by the Worker and the Wrangler preflight. |
| [`src/config/context.js`](src/config/context.js) | Environment parsing, key loading, per-hostname policy, and the immutable runtime context. |
| [`src/config/protected-paths.js`](src/config/protected-paths.js) | `APPROOV_PROTECTED_PATHS` parsing and path matching. |
| [`src/constants.js`](src/constants.js) | Outcome enums and configuration constants. |
| [`src/utils/text.js`](src/utils/text.js) | Text/boolean parsing helpers. |
| [`src/utils/crypto.js`](src/utils/crypto.js) | Hashing and strict base64/base64url decoding. |
| [`src/utils/logging.js`](src/utils/logging.js) | Centralized logging helpers. |
| [`src/utils/errors.js`](src/utils/errors.js) | Error-message normalization. |

**Approov verification**

| File | Responsibility |
|---|---|
| [`src/approov/evaluate.js`](src/approov/evaluate.js) | Composed per-request evaluation flow. |
| [`src/approov/token.js`](src/approov/token.js) | Token verification and JWT error classification. |
| [`src/approov/binding.js`](src/approov/binding.js) | Token binding verification. |
| [`src/approov/message-signing.js`](src/approov/message-signing.js) | Installation/account message-signature verification. |
| [`src/approov/account-key.js`](src/approov/account-key.js) | Device key derivation for account signatures. |
| [`src/approov/client-status.js`](src/approov/client-status.js) | Filtering of the client-supplied status header. |
| [`src/approov/policy.js`](src/approov/policy.js) | Maps verification results to layer failures and the block decision. |
| [`src/vendor/http-message-signatures.js`](src/vendor/http-message-signatures.js) | Entry to the vendored RFC 9421 bundle ([build guide](vendor/README.md)). |

**Plugins & analytics**

| File | Responsibility |
|---|---|
| [`src/plugin-host.js`](src/plugin-host.js) | Drop-in plugin registry loader and lifecycle runner. |
| [`src/plugin-kit.js`](src/plugin-kit.js) | The stable API surface plugins may import. |
| `src/plugins.generated.js` | Build-time plugin registry written by `scripts/generate-plugins.mjs`. |
| [`plugins/arc/`](plugins/arc/) | ARC decoding plugin. |
| [`src/analytics.js`](src/analytics.js) | Optional per-request summary for Workers Logs and Analytics Engine. |

**HTTP proxy**

| File | Responsibility |
|---|---|
| [`src/http/proxy.js`](src/http/proxy.js) | Rewrites the incoming request to target the upstream API. |

**Tooling**

| File | Responsibility |
|---|---|
| [`scripts/wrangler.mjs`](scripts/wrangler.mjs), [`scripts/preflight.mjs`](scripts/preflight.mjs) | Validate the selected configuration, then run Wrangler (`npm start`, `npm run deploy`). |
| [`scripts/validate-config.js`](scripts/validate-config.js) | `npm run validate:config`. |
| [`scripts/audit.mjs`](scripts/audit.mjs) | Dependency audit gate. |
| [`scripts/build-message-signatures.mjs`](scripts/build-message-signatures.mjs) | Rebuilds or checks the vendored message-signature bundle. |

---

## Testing

```shell
npm test                # Workers runtime tests; fails below 100% coverage
npm run test:preflight  # configuration preflight, startup, and documentation-example tests
npm run test:audit      # dependency audit policy and lint policy tests
npm run lint            # eslint
npm run audit           # dependency audit gate
npm run check:vendor    # vendored bundle matches its sources
```

`npm test` runs every `test/*.spec.js` suite and each plugin's `plugins/<name>/*.spec.js` in the
Workers runtime. CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs all of the
commands above plus a `wrangler deploy --dry-run` build on every push and on pull requests to `main`.
The audit gate includes all severities and development dependencies and has no exceptions; see
[the audit policy](docs/dependency-audit.md).

The deployed end-to-end matrix is separate and manual; see [`test/e2e/README.md`](test/e2e/README.md).

The suites cover these message-signing scenarios:

<details>
<summary><strong>Message-signing coverage</strong></summary>

| Mode | Scenarios covered |
|---|---|
| `install` | Valid, missing, tampered, or malformed required signatures and keys; present account members must also pass. |
| `account` | Device-derived signatures; raw-secret rejection; missing, malformed, or different device IDs; invalid `mskid`, missing secret, or key-ID mismatch. |
| `either` / `both` | Optional and required dual signatures; independent results, either entry failing, required coverage, and one shared digest check. |
| `none` / `unknown` | No trusted claims versus untrusted token; blocking unavailable checks. |

</details>

---

## Outcome Reference

The canonical outcome enums live in [`src/constants.js`](src/constants.js). The first two tables
show which outcome each common scenario produces; the lists after them give every possible value.

<details>
<summary><strong>Token scenarios (token binding disabled)</strong></summary>

| Scenario | `tokenResult` | `bindingResult` |
|---|---|---|
| No `Approov-Token` header | `MISSING_HEADER` | `DISABLED` |
| Empty `Approov-Token` header | `EMPTY_HEADER` | `DISABLED` |
| Valid pass token | `PASS` | `DISABLED` |
| Valid fail token | `FAIL` | `DISABLED` |
| Unknown signer | `INVALID_SIG` | `DISABLED` |
| Audience mismatch | `INVALID_AUD` | `DISABLED` |
| Unsupported JWT algorithm | `INVALID_ALG` | `DISABLED` |
| Malformed JWT, or a signed token without a numeric `exp` claim | `MALFORMED` | `DISABLED` |
| Unparsable JWT | `UNPARSABLE` | `DISABLED` |
| Expired token | `EXPIRED` | `DISABLED` |

</details>

<details>
<summary><strong>Binding scenarios (token binding enabled)</strong></summary>

| Scenario | `tokenResult` | `bindingResult` |
|---|---|---|
| Missing token header | `MISSING_HEADER` | `NOT_CHECKED` |
| PASS token + missing binding header | `PASS` | `MISSING_HEADER` |
| PASS token + empty binding header | `PASS` | `EMPTY_HEADER` |
| PASS token + missing binding claim | `PASS` | `MISSING_CLAIM` |
| PASS token + hash mismatch | `PASS` | `INVALID` |
| PASS token + hash match | `PASS` | `VALID` |
| Authentic FAIL token | `FAIL` | Binding checked using trusted claims |
| INVALID_SIG token | `INVALID_SIG` | `NOT_CHECKED` |

</details>

<details>
<summary><strong>All token outcomes</strong></summary>

`PASS`, `FAIL`, `EXPIRED`, `INVALID_AUD`, `INVALID_ALG`, `INVALID_SIG`, `MALFORMED`,
`UNPARSABLE`, `MISSING_HEADER`, `EMPTY_HEADER`, `NOT_CHECKED`, `ERROR`.

</details>

<details>
<summary><strong>All binding outcomes</strong></summary>

`VALID`, `INVALID`, `DISABLED`, `MISSING_HEADER`, `EMPTY_HEADER`, `MISSING_CLAIM`,
`NOT_CHECKED`, `ERROR`.

</details>

<details>
<summary><strong>All message-signing outcomes</strong></summary>

`VALID`, `INVALID`, `NOT_REQUIRED`, `NOT_CHECKED`, `MISSING_HEADERS`, `MALFORMED_HEADERS`,
`MISSING_SIGNATURE_ENTRY`, `INVALID_CONTENT_DIGEST`, `MISSING_CONTENT_DIGEST`,
`INVALID_INSTALL_KEY_CLAIM`, `INVALID_ACCOUNT_KEY_ID_CLAIM`, `INVALID_DEVICE_ID_CLAIM`, `ACCOUNT_KEY_ID_MISMATCH`,
`ACCOUNT_SECRET_NOT_CONFIGURED`, `ERROR`.

`INVALID_DEVICE_ID_CLAIM` means the required account-signing `did` claim is missing or malformed.
The claim must contain canonical, padded standard base64 for exactly 16 bytes.

</details>

---

## Useful Links

**Cloudflare — development**

- [Getting started](https://developers.cloudflare.com/workers/)
- [Observability and debugging](https://developers.cloudflare.com/workers/observability/)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)

**Cloudflare — logs**

- [Tail logs with the Wrangler CLI](https://developers.cloudflare.com/workers/observability/logs/real-time-logs/)
- [Workers Logpush](https://developers.cloudflare.com/workers/observability/logs/logpush/)

**Approov**

- [Approov installation](https://ext.approov.io/docs/latest/approov-installation/)
- [Managing key sets](https://ext.approov.io/docs/latest/approov-usage-documentation/#managing-key-sets)
- [Token binding](https://ext.approov.io/docs/latest/approov-usage-documentation/#token-binding)

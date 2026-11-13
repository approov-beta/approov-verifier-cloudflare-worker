# Windows Quickstart (PowerShell)

The [main quickstart](../README.md#quickstart-wrangler) assumes a POSIX shell. This guide walks
the same deployment on Windows and calls out the places where the commands genuinely differ —
input redirection, `curl`, file encoding, and the missing `jq`/`base64` utilities.

Use **PowerShell 7+** (`pwsh`) where possible. Windows PowerShell 5.1 works, but its default
UTF-16 output encoding is a real hazard for the secret file — see [Upload the backend
config](#5-upload-the-backend-config).

## Prerequisites

- **Node.js 22 or later**, as required by Wrangler 4:

  ```powershell
  node -v
  ```

- The [Approov CLI](https://ext.approov.io/docs/latest/approov-installation/) **3.6.0 or
  later** ([approovcli.zip](https://approov.io/downloads/approovcli.zip)). Unzip it and add
  `approov.exe` to your `PATH`, then confirm:

  ```powershell
  approov -version
  ```

- An Approov account configured with an ECDSA or RSA key set — see
  [Managing Key Sets](https://ext.approov.io/docs/latest/approov-usage-documentation/#managing-key-sets).
- A Cloudflare account with a Worker entitlement, and Wrangler already authenticated.

Two placeholders are used throughout, matching the main README:

- `$(WORKER_NAME)` — the `name` field in [`wrangler.toml`](../wrangler.toml), default
  `approov-gateway`.
- `$(WORKER_DOMAIN)` — your `*.workers.dev` subdomain, shown at the bottom of the
  **Workers & Pages** dashboard.

## 1. Install dependencies

```powershell
npm install
```

## 2. Confirm the Wrangler login

```powershell
npx wrangler whoami
```

This prints the authenticated account. If it reports that you are not logged in, run
`npx wrangler login` and authorize Wrangler in the browser window that opens.

## 3. Register the gateway domain with Approov

The Worker resolves its verification policy from the **incoming hostname**, so the public
hostname must be registered with Approov before the backend config is exported:

```powershell
approov api -add $(WORKER_NAME).$(WORKER_DOMAIN) -keySetKID "example-es256"
```

Register the custom hostname instead if the Worker will be served from one. Changing the
Worker name or public hostname later requires repeating this step and re-exporting the
configuration.

## 4. Export the backend configuration

Run this beside your selected Wrangler configuration, so that preflight validation can find the exported file:

```powershell
approov secret -getBackendConfig approov-config.json
```

Confirm the registered hostname is present and carries a key ID:

```powershell
(Get-Content -Raw approov-config.json | ConvertFrom-Json).apis
```

Each API entry must have a `kid` that exists in both `passJWKS` and `failJWKS`. An entry
without a `kid` falls back to the account-wide HS256 secret and is rejected unless
`APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET` is enabled.

## 5. Upload the backend config

> [!IMPORTANT]
> **PowerShell has no `<` input redirection.** The README's
> `npx wrangler secret put APPROOV_BACKEND_CONFIG < approov-config.json` fails with a parser
> error. Pipe the file instead:

```powershell
Get-Content -Raw approov-config.json | npx wrangler secret put APPROOV_BACKEND_CONFIG
```

From `cmd.exe`, the redirection form in the README works unchanged:

```bat
npx wrangler secret put APPROOV_BACKEND_CONFIG < approov-config.json
```

Verify the binding exists:

```powershell
npx wrangler secret list
```

> [!WARNING]
> Never regenerate this file with `>` under Windows PowerShell 5.1 — the redirection operator
> writes **UTF-16LE**, and the Worker's `JSON.parse` of `APPROOV_BACKEND_CONFIG` will fail at
> startup. If you must write the file from a script, use `Set-Content -Encoding utf8`.

## 6. Configure the upstream API

`API_DOMAIN` lives in the `[vars]` block of [`wrangler.toml`](../wrangler.toml). It ships as
`postman-echo.com`, which reflects request headers back in its JSON response, so the first
end-to-end test can show exactly what the Worker forwarded.

## 7. Generate example tokens

```powershell
$env:VALID_APPROOV_TOKEN   = (approov token -genExample $(WORKER_NAME).$(WORKER_DOMAIN))
$env:INVALID_APPROOV_TOKEN = (approov token -genExample $(WORKER_NAME).$(WORKER_DOMAIN) -type invalid)
```

Example tokens expire after **2 hours**. If the CLI prints surrounding text, assign only the
JWT itself. These variables live for the current PowerShell session only.

## 8. Prepare local secrets

Cloudflare secrets are not available to `wrangler dev`, so they come from `.dev.vars`:

```powershell
Copy-Item .dev.vars.example .dev.vars
```

`APPROOV_BACKEND_CONFIG` must be the entire JSON document on a **single line**. Rather than
hand-editing, generate the line directly from the exported file:

```powershell
"APPROOV_BACKEND_CONFIG='" + (Get-Content -Raw approov-config.json | ConvertFrom-Json | ConvertTo-Json -Compress -Depth 20) + "'" | Set-Content -Encoding utf8 .dev.vars
```

Add any optional settings from [`.dev.vars.example`](../.dev.vars.example) below that line.
`.dev.vars` is git-ignored — never commit it.

## 9. Run and test locally

```powershell
npm start -- --port 8787
```

> [!IMPORTANT]
> In PowerShell, `curl` is an **alias for `Invoke-WebRequest`**, which does not understand
> `--resolve` or `-H`. Always call `curl.exe` explicitly. Windows 10 1803 and later ship it.

The Worker selects its keys from the `Host` header, so the request must carry the registered
hostname while resolving to localhost. Windows has no `jq` or `base64`, so decode the
`Approov-Result` header with PowerShell built-ins:

```powershell
$h = "$(WORKER_NAME).$(WORKER_DOMAIN)"
$r = curl.exe -s --resolve "${h}:8787:127.0.0.1" "http://${h}:8787/get" --compressed -H "Approov-Token: $env:VALID_APPROOV_TOKEN" | ConvertFrom-Json
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($r.headers.'approov-result')) | ConvertFrom-Json | ConvertTo-Json
```

```jsonc
{
  "tokenResult": "PASS",
  "bindingResult": "DISABLED",
  "messageSigningMode": "none",
  "messageSigningResult": "NOT_REQUIRED"
  // ...
}
```

Repeat with `$env:INVALID_APPROOV_TOKEN` and expect `tokenResult: FAIL`. In the default
annotation mode the request is still forwarded — the backend enforces the policy.

> [!TIP]
> `approov-result` appears in this output only because Postman Echo reflects request headers.
> The Worker attaches the header to the **upstream request**, not to the client response.

## 10. Deploy

```powershell
npm run deploy --
```

Re-run the check against the live hostname — no `--resolve`, and `https`:

```powershell
$h = "$(WORKER_NAME).$(WORKER_DOMAIN)"
$r = curl.exe -s "https://${h}/get" --compressed -H "Approov-Token: $env:VALID_APPROOV_TOKEN" | ConvertFrom-Json
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($r.headers.'approov-result')) | ConvertFrom-Json | ConvertTo-Json
```

Stream live logs:

```powershell
npx wrangler tail --format pretty
```

## Command translation reference

| POSIX form in the README | Windows equivalent |
| --- | --- |
| `wrangler secret put X < file` | `Get-Content -Raw file \| npx wrangler secret put X` (PowerShell); `<` works in `cmd.exe` |
| `cp .dev.vars.example .dev.vars` | `Copy-Item .dev.vars.example .dev.vars` |
| `curl ... --resolve ...` | `curl.exe ... --resolve ...` — the bare `curl` alias is `Invoke-WebRequest` |
| `... \| jq -r '.headers."approov-result"'` | `... \| ConvertFrom-Json` then `$r.headers.'approov-result'` |
| `base64 -d \| jq` | `[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($v))` |
| `export VAR=value` | `$env:VAR = "value"` |
| `cmd > file` | `... \| Set-Content -Encoding utf8 file` (avoids UTF-16 under PowerShell 5.1) |

## Troubleshooting

- **`npm install` or `wrangler` fails on startup** — check `node -v` is 22 or later.
- **`The '<' operator is reserved for future use`** — you used redirection in PowerShell; use
  the pipe form in [step 5](#5-upload-the-backend-config).
- **`Invoke-WebRequest: A parameter cannot be found that matches parameter name 'resolve'`** —
  you invoked `curl` rather than `curl.exe`.
- **Worker returns 500** — the incoming hostname is not present in
  `APPROOV_BACKEND_CONFIG.apis`, or its entry has no `kid`. Run `npx wrangler tail` (or read
  the `npm start` output): the `approov: unable to resolve incoming API policy` line carries a
  `reason` that names the hostname and what is missing.
- **`invalid env.APPROOV_BACKEND_CONFIG`** — the secret was uploaded with the wrong encoding.
  Re-export with the Approov CLI and re-upload using the pipe form.

## Before going live

`postman-echo.com` and annotation mode are for the smoke test only. In annotation mode the
backend trusts `Approov-Result` solely because ingress controls guarantee this Worker set it.
Read [Backend Enforcement and Trusted Ingress](backend-enforcement.md) before pointing the
Worker at a production origin, and see
[Deployment in Front of an Existing API Origin](existing-domain.md) for custom hostnames.

# L2 end-to-end matrix

These tests run the **real worker, deployed**, and drive it with synthetic
requests — verifying behaviour that the in-process unit suite (L1) can't:
the Cloudflare runtime, the `[build]` plugin-generation step, env-var parsing on
deploy, routing, real status codes, and header handling.

This suite does not configure a customer's API Shield rules, backend enforcement middleware, or
origin network policy. Use the
[API Shield and Approov Verification Matrix](../../docs/api-shield-verification.md) to validate
those production integration boundaries in a representative staging environment.

They are the middle layer of a test pyramid:

| Layer | What | Where |
|-------|------|-------|
| **L1** | All logic + edge cases, synthetic tokens, in-process | `test/*.spec.js`, `plugins/**/*.spec.js` |
| **L2** | Deployed worker + synthetic HTTP matrix (this folder) | `test/e2e/` |
| **L3** | Real device + Approov SDK | Not part of this repository |

## How it works

- The worker is deployed with **test key material** (`wrangler.e2e.toml`,
  mirroring `test/fixtures.js`) so synthetic tokens validate against it.
- **Echo mode is on**, so the worker reflects the evaluated request (including
  the base64 `Approov-Result` header) instead of proxying upstream — a
  self-contained assertion surface. No mock upstream needed.
- The runner mints synthetic tokens (`request-builder.mjs`), fires
  HTTP at the deployment, decodes `Approov-Result`, and asserts.

## Two axes

`profiles.mjs` defines the matrix:

- **Plugin presence** (build-time, via the `PLUGINS` allowlist on the deploy):
  `none`, `arc` only, all. This exercises the drop-in
  discovery/wiring flow itself.
- **Runtime config** (via `--var` at deploy): annotate, block, continue, mixed actions,
  protected paths, token binding, and install, account, either and both signature requirements.
  Block mode checks that forwarded requests contain no `Approov-Result` header. The protected-paths
  profile checks that alternate spellings of a protected path are still verified at the edge.

## Running it

### Against Cloudflare preview deployments (CI)

Deploys a preview version per profile, tests it, tears down the registry.
Requires credentials:

```bash
export CLOUDFLARE_API_TOKEN=...      # Workers Scripts:Edit
export CLOUDFLARE_ACCOUNT_ID=...
npm run test:e2e
```

The account needs `workers.dev` preview URLs enabled. This is what
`.github/workflows/e2e.yml` runs through manual dispatch. All refs share one workflow concurrency
group, and an active run finishes before another run starts.
The deploy helper uses a unique Cloudflare preview alias for each run, discovers its hostname once,
and injects that exact hostname into the test backend config. Readiness checks include the run and
profile identity. Other runs cannot move this alias to a different source revision.

Local deployment runs also hold `.wrangler/e2e-registry.lock` while they use the generated plugin
registry. A second run in the same checkout stops before changing that registry. Normal exit and
supported termination signals release the lock. After a forced termination, inspect the PID in a
remaining lock file and remove the file only after that process stops. Runs in different checkouts
use separate registries and separate preview aliases.

### Locally against `wrangler dev` (no Cloudflare account)

Start the worker for one profile's config, then point the runner at it with
`E2E_BASE_URL` + `E2E_PROFILE` (which skips deployment):

```bash
# e.g. the binding profile (all plugins, token binding on)
npm start -- --config test/e2e/wrangler.e2e.toml \
  --var APPROOV_TOKEN_BINDING_ENABLED:true --port 8799 &

E2E_BASE_URL=http://127.0.0.1:8799 E2E_PROFILE=binding npm run test:e2e
```

For plugin-presence profiles, set `PLUGINS` when starting the dev server so the
build bundles the right subset, e.g. `PLUGINS=arc npm start -- …` then
`E2E_PROFILE=plugins-arc-only`.

## Files

| File | Purpose |
|------|---------|
| `wrangler.e2e.toml` | Test deployment config (test keys, echo mode). |
| `profiles.mjs` | The matrix: plugin sets × config × scenarios + assertions. |
| `request-builder.mjs` | Mint synthetic tokens / ARC claims (reuses L1 keys). |
| `deploy-preview.mjs` | Validated preview upload per profile → preview URL. |
| `run.mjs` | Orchestration + reporting (CI and local modes). |

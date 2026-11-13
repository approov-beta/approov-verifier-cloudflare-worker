# Plugin architecture

This worker supports **drop-in plugins**: self-contained feature modules under
`plugins/<name>/` that are wired in automatically at build time. Optional
capabilities stay out of the core, and Approov can deliver customer-specific
confidential plugins separately: copying such a folder into `plugins/` adds it
without editing the core worker. The plugins in this repository are covered by
its MIT licence.

This document describes the **mechanism**. Each plugin documents itself in its
own folder — see the [shipped plugins](#shipped-plugins) below.

---

## Why build-time discovery

Cloudflare Workers have **no runtime filesystem** and cannot dynamically import
arbitrary paths at request time — the worker ships as a single bundle. So plugin
discovery happens at **build time**:

```
plugins/<name>/index.js   ──scan──▶  scripts/generate-plugins.mjs
                                         │ writes
                                         ▼
                              src/plugins.generated.js   (static import registry)
                                         │ imported by
                                         ▼
              src/plugin-host.js  ◀── core (context.js, evaluate.js)
```

`scripts/generate-plugins.mjs` is wired into:

- **`wrangler.toml` `[build]`** — runs on `wrangler dev` and `wrangler deploy`.
- **npm `pretest`** — runs before `npm test`.

So adding or removing a `plugins/<name>/` folder is picked up on the next
build/test with no manual edits. An empty `plugins/` directory yields an empty
registry and **zero bundle cost**.

> Trust note: a dropped-in plugin runs with full worker privileges. Plugins
> should be delivered through a trusted channel (ideally checksummed/signed).

## The plugin contract

Each plugin is a folder with an `index.js` whose default export is:

```js
export default {
  id: 'my-plugin',           // unique, stable id
  resultKey: 'myResult',     // key under which evaluate() output lands in Approov-Result
                             //   (defaults to id)

  // Declare every APPROOV_ configuration field before using it.
  configSchema: {
    APPROOV_MY_PLUGIN_ENABLED: { type: 'boolean' }
  },

  // Parse + validate env config at startup. Push human-readable strings onto
  // `errors` to fail the worker's config validation. `shared` carries
  // pre-parsed primitives the core already computed (e.g. `shared.backendConfig`)
  // so plugins need not re-parse APPROOV_BACKEND_CONFIG.
  configure (env, errors, shared) { return { /* config fragment */ } },

  // Run during request evaluation. Return value is stored in the result payload.
  async evaluate ({ ctx, config, request, approovToken, tokenVerification, signal }) { /* ... */ },

  // Optional: synchronous analytics summary of this plugin's result only.
  summarize (result) { return { status: result.status } }
}
```

The host (`src/plugin-host.js`) provides:

- `configurePlugins(env, errors, shared)` — called by `establishContext`; merges
  each plugin's config under `ctx.pluginConfig[id]` and lets plugins contribute
  startup errors that gate `ctx.isValid`. `shared` currently carries the parsed
  `backendConfig`.
- `runPlugins(ctx, args, out)` — called by `evaluateApproovToken` after token
  verification; runs each plugin's `evaluate` and writes the result to
  `out[resultKey]`. A plugin that throws is isolated (records `ERROR`) and never
  affects the core pass/fail outcome.

Plugins depend only on `src/plugin-kit.js` (a stable host API surface: base64
decode, text/boolean parsing, logging helpers) plus Node built-ins — never on
core internals directly.

The shared validator checks `configSchema` during preflight, initialization, and requests.
Supported field types are `boolean`, `header`, `text` (non-empty string), `string`,
`integer` (with `min` and `max`), and `enum` (with a `values` array).
Use exact lowercase enum values. Booleans accept native values or `"true"`/`"false"`.
Plugin fields must start with `APPROOV_` and must not replace core or legacy fields.
If a plugin is absent from the build, its configuration fields are unknown and cause an error.
Remove those fields when you exclude the plugin.

`configure` receives `shared.deferSecrets=true` during deployment preflight.
In this case, defer missing-secret checks until initialization. Still validate any supplied secret.
Report field names in errors. Do not include configuration values or secret contents.

Plugins are informational. In annotation mode, their results enter `Approov-Result`.
In block mode, their results are available in structured logs when logging is enabled.
They do not contribute to the Worker's enforcement decision.

## Evaluation deadline

Each plugin evaluation has a 1000 ms asynchronous deadline. On timeout, the host
records `{ "status": "TIMEOUT", "error": "Plugin evaluation exceeded 1000 ms" }`
under that plugin's result key and continues to the next plugin.
It preserves the core verification result. A late result cannot replace the
timeout annotation, and a late rejection is handled.

The host passes an optional `AbortSignal` as `signal`. Plugins that perform
asynchronous I/O can pass it to `fetch` or check `signal.aborted` to stop work.
Existing plugins can ignore the additional argument. The host clears its timer
on success, rejection, and timeout.

This deadline bounds asynchronous waiting. It cannot interrupt a synchronous
loop, cancel work that ignores the signal, or undo plugin side effects.
Cloudflare timers do not advance during CPU execution. Plugins execute with
full Worker privileges and must remain trusted, bounded code.
The `configure` hook must be synchronous and bounded too.

The limit applies to each plugin, so several slow plugins can add several
seconds. Avoid network calls and other slow work in annotation plugins.
See [Cloudflare's timer model](https://developers.cloudflare.com/workers/runtime-apis/performance/).

## Safe analytics summaries

The optional `summarize(result)` hook receives only the result from its own
completed evaluation. It must not mutate that result or perform I/O. Return a
plain object with safe fields. Do not return tokens, encoded ARC, identifiers,
credentials, claims, bodies, or exception text.

The host isolates hook errors and rejects unsupported or oversized summaries.
Legacy plugins work without this hook. Plugin summaries enter structured logs;
they do not change `Approov-Result` or the core Analytics Engine columns.
See [Worker analytics](worker-analytics-proposal.md) for limits and configuration.

## Tests

Plugin tests live next to the plugin as `plugins/<name>/*.spec.js`. Vitest
discovers them via its default filename glob (`**/*.{test,spec}.?(c|m)[jt]s?(x)`),
so they run as part of `npm test` with no config change. Shared test scaffolding
(keys, token signing, base env) lives in [`test/fixtures.js`](../test/fixtures.js)
and is imported by both the core suite and the plugin suites. Because spec files
are not imported by `index.js`, they never enter the worker bundle.

## Adding a new plugin

1. Create `plugins/<name>/index.js` exporting the contract above.
2. Add a `plugins/<name>/README.md` documenting the plugin's config and result.
3. Co-locate tests as `plugins/<name>/*.spec.js`.
4. Run `npm run generate:plugins` (or just `npm test` / `wrangler dev`).

No core edits are required.

## Shipped plugins

Each plugin's behaviour, configuration, and result shape are documented in its
own folder:

| Plugin | Docs |
|--------|------|
| ARC decoding | [`plugins/arc/README.md`](../plugins/arc/README.md) |

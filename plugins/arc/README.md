# ARC plugin

Decodes the obfuscated Approov **ARC** (Attestation Response Code) token claim
into a list of semantic property labels and surfaces them as `arcProperties` in
the `Approov-Result` payload.

## Files

| File | Purpose |
|------|---------|
| [`index.js`](index.js) | Plugin entry: config parsing + per-request evaluation. |
| [`decode.js`](decode.js) | `arcDecode(arc, secret, customMappings)` — the decoder. |
| [`arc-flag-mappings.json`](arc-flag-mappings.json) | Default code → label map. |
| [`arc.spec.js`](arc.spec.js) | Unit + integration tests. |

## What it does

For any **decoded** token (PASS *or* FAIL) that carries an `arc` claim, the
plugin HMAC-derives a keystream from the ARC secret, decodes each base32 symbol,
resolves codes to labels, and prepends `pass`/`fail`:

```json
"arcProperties": ["pass", "debug", "rooted"]
```

A decode failure (malformed/invalid ARC) leaves `arcProperties` as `null` — it is
logged but **never** affects the token outcome.

## Configuration

The ARC encoding secrets and optional flag mappings come from the parsed
`APPROOV_BACKEND_CONFIG` blob passed to the plugin via `shared.backendConfig`:

| Backend config field | Required | Meaning |
|----------------------|----------|---------|
| `currentArcEncodingSecret` | Recommended | Active secret used for newly issued tokens. |
| `pendingArcEncodingSecret` | Optional | Staged secret accepted before it is promoted. |
| `previousArcEncodingSecrets` | Optional | Archived `{secret, timestamp}` entries used for tokens from earlier rotations. |
| `arcFlagMappings` | Optional | JSON map of `code → label`, e.g. `{"1":"debug","2":"scan-fail"}`. Overrides the built-in map. |

Candidates are tried in current, pending, then previous order, with duplicate values removed.
A structurally valid decode is not treated as proof that a candidate secret matched. Each decode
must agree with the JWT's signed PASS/FAIL result, and all remaining successful candidates must
produce the same properties. Conflicting plausible decodes leave `arcProperties` as `null` and are
logged as ambiguous.
A missing encoding secret disables ARC decoding with a startup **warning**
(`arcProperties` stays `null`); the plugin is annotation-only, so it never
blocks the worker from serving requests. Removing the `plugins/arc/` folder
disables ARC decoding entirely.

## Result shape

`arcProperties` is produced on the main evaluation path (an array, or `null` on
decode failure / when no `arc` claim is present). On the no-token
(`MISSING_HEADER`/`EMPTY_HEADER`) and token-error paths it is omitted.

## Testing

```bash
npm test                 # runs all suites, including this plugin's
npx vitest run plugins/arc
```

See the [plugin architecture doc](../../docs/plugins.md) for how plugins are
discovered and wired into the worker.

# Vendored message-signature library

The Worker imports `src/vendor/http-message-signatures.bundle.js` through the
small ESM wrapper beside it. The bundle contains the committed JavaScript in
`vendor/http-message-signatures/lib/` and the `structured-headers` parser.
It does not load the installed parser package at runtime.

## Rebuild and check

From the repository root:

```sh
npm ci
npm run build:vendor
npm run check:vendor
npm test
npx wrangler deploy --dry-run
```

Commit the source changes and regenerated bundle together.
Do not edit the generated bundle by hand.

`npm run check:vendor` builds in memory and compares the exact output bytes with
the committed file. It fails on drift without modifying the bundle. CI runs
this check before the Worker dry-run build.

## Build inputs

- `scripts/http-message-signatures-entry.mjs` defines the public exports and
  CommonJS/ESM interoperability adapter.
- `scripts/vendor-node-shims/` maps CommonJS `crypto` and `constants` imports to
  their Workers-compatible `node:` ESM exports. This avoids dynamic `require`.
- `scripts/build-message-signatures.mjs` fixes the build root, entry, target,
  output format, and dependency aliases. It works from any current directory.
- `package.json` pins `esbuild` at 0.28.1 and `structured-headers` at 1.0.1 as
  development dependencies. `package-lock.json` records the exact dependency tree.
- `vendor/http-message-signatures/lib/` contains the maintained vendored sources,
  including the existing expiry handling and `@query-param` encoding fixes. Rebuilding
  preserves those fixes.

The output contains repository-relative source comments. It contains no temporary
entry paths, build timestamps, or machine-specific absolute paths.
The build does not download a fresh upstream copy or overwrite local vendor fixes.

## Licenses

- `http-message-signatures`: [ISC license](http-message-signatures/LICENSE.md).
- Embedded `structured-headers` 1.0.1: [MIT license](structured-headers/LICENSE).

Keep these notices with distributions of the generated bundle.

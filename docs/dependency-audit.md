# Dependency audit gate

Run `npm run audit` for the same dependency gate as CI. It runs the full `npm audit --json`, including development dependencies. There is no severity threshold. Unknown findings and audit-service errors fail the gate.

`npm audit` remains available as the unfiltered diagnostic. It currently exits 1 with 15 moderate package entries. Those entries trace to one advisory, not 15 separate advisories. The gate prints the raw count, the exact exception, its expiry, and every package entry it applies to. It must not describe this report as zero vulnerabilities.

Run `npm run test:audit` to check the gate's failure boundaries and the existing linter's correctness, import, and style rules. CI runs these tests before the audit gate. Worker coverage thresholds are unchanged.

## Temporary minimatch applicability exception

Reviewed on **4 November 2026**. Expires on **4 December 2026 at 00:00 UTC**. If the finding remains after that time, CI fails and requires a new review. Do not extend the date without checking current upstream evidence.

The exception applies only to [GHSA-g3hv-75wg-m249 / CVE-2026-118764](https://github.com/advisories/GHSA-g3hv-75wg-m249), npm advisory identifier `1244012`, on the existing `minimatch@3.1.5` development installation.

The published sources disagree about the affected range:

- The [maintainer advisory](https://github.com/isaacs/minimatch/security/advisories/GHSA-g3hv-75wg-m249) identifies `10.2.6`.
- The aggregate GitHub/npm advisory marks all versions below `11.0.1`.
- The description requires `optimizationLevel >= 2`, `firstPhasePreProcess`, and `secondPhasePreProcess`. None exists in the installed 3.1.5 implementation.
- The [upstream fix and regression test](https://github.com/isaacs/minimatch/commit/77a0f5c4b80bdc641c3c930a1d9edf5ad2db57f8) limit pattern growth in those preprocessing passes. Running its 30-part `**/../a/b` pattern on 3.1.5 creates one pattern, without those passes. The committed policy test repeats this check.

This evidence supports a false positive for this specific legacy package and advisory. It does not establish that minimatch has no other possible vulnerabilities. Any other advisory remains blocking.

The exception in `scripts/audit.mjs` verifies all of these conditions:

- The root finding is exactly minimatch, advisory identifier and URL, moderate severity, and affected range `<11.0.1`.
- A canonical fingerprint pins the complete npm-reported advisory object. Changes to its title, score, affected range, or other metadata require review.
- There is exactly one reported minimatch installation: `node_modules/minimatch`. It is a transitive development dependency, version 3.1.5, in both the installed package and lockfile.
- The lockfile's registry URL and SHA-512 integrity match the reviewed official npm artifact.
- The installed `minimatch.js` has SHA-256 `746849f267c4868a53729225bd85c7dccd387712136fb305fcc0a3eadd4a3d9d`. The source digest was independently checked against the official tarball and its SHA-512 integrity.
- The exception has not expired.

An inherited npm meta-vulnerability is excepted only when **every** reachable advisory meets these conditions and every reported location is development-only in the lockfile. Peer-dependency cycles are handled without treating an empty cycle as clean. A second advisory, another installation, changed source, minimatch upgrade, runtime location, missing dependency, or malformed report fails the gate.

Before an exception can produce a passing gate, a second, fresh `npm audit --json --omit=dev` must report zero findings. No production exception is allowed. An unavailable or malformed production audit also fails the gate. This check supplements the full audit; it does not replace it.

## Why retain this lint toolchain temporarily

`eslint-config-standard@17.1.0` requires ESLint 8 and plugins that use minimatch's older API. npm's forced repair suggests downgrading ESLint to 4.0.0. That is not an acceptable compatibility or security fix.

A disposable migration probe tested ESLint 10.14.0, neostandard 0.14.1, eslint-plugin-import-x 4.17.1, and minimatch 11.0.4. Its audit was clean, but the lint plugin failed to load because minimatch 11 no longer exports `makeRe`. The probe was not applied to this repository. Removing import checks to make that migration pass would weaken the existing gate.

The current manifest and lockfile dependency graph remain unchanged. Lint rules and file exclusions remain unchanged. ESLint 8's end-of-support status remains maintenance work; this exception does not authorize ignoring future findings in it.

## Removal and follow-up

Recheck the upstream advisory classification before the expiry date. No upstream issue, advisory edit, or other contact was made as part of this change.

Remove this exception when either:

1. Corrected advisory metadata no longer flags the reviewed legacy package; or
2. A supported, compatibility-tested lint migration removes the affected dependency path.

For a migration, preserve the current correctness, Node, promise, import, and Standard Style checks. Test matching and ignore behavior as well as normal lint output. Run a fresh `npm ci`, raw full and production audits, policy tests, full Worker and startup tests, lint, vendor reproducibility, and a Wrangler dry-run. Do not use a blanket major-version override to satisfy audit metadata.

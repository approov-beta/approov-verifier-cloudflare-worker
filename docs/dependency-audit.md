# Dependency audit gate

Run `npm run audit` for the same dependency gate as CI. It runs the full `npm audit --json`,
including development dependencies.

- There is no severity threshold: a finding of any severity fails the gate.
- There are no exceptions: every reported package entry is listed and blocks.
- An unavailable audit service, a malformed report, or an exit status that does not match the
  report also fails the gate.

`npm audit` remains available as the unfiltered diagnostic.

Run `npm run test:audit` to check the gate's failure boundaries and the linter's correctness,
import, and style rules. CI runs these tests before the audit gate.

## Handling a finding

1. Prefer an upgrade that removes the affected version. Run a fresh `npm ci`, the audit gate,
   the policy tests, the Worker and startup tests, lint, the vendor reproducibility check, and a
   Wrangler dry-run.
2. Do not use a blanket major-version override to satisfy audit metadata, and do not lower the
   gate to a severity threshold.
3. If a finding is a verified false positive with no available upgrade, record the evidence in
   this file and add a narrowly scoped, expiring exception to `scripts/audit.mjs` together with
   tests for its boundaries. Remove it as soon as the advisory or the dependency path changes.

## Lint toolchain

`eslint-config-standard@17.1.0` requires ESLint 8, which is past its end of support. Migrating
to a supported ESLint release is outstanding maintenance work. A migration must preserve the
current correctness, Node, promise, import, and Standard Style checks, and must test matching
and ignore behaviour as well as normal lint output.

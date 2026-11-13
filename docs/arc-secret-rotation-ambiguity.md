# ARC secret rotation can produce ambiguous structural decodes

## Summary

An ARC value does not authenticate which ARC encoding secret produced it. During secret rotation,
the same ARC claim can therefore pass the decoder's structural checks under more than one configured
secret while producing different security properties.

This becomes a correctness and potentially a security issue when a backend tries the current,
pending, and previous secrets in order and accepts the first decode that does not throw. A
structurally valid result is not proof that the candidate secret is correct.

The issue is not specific to Cloudflare Workers or JWT verification. It can affect any backend that:

1. uses the same ARC decoding scheme;
2. accepts multiple ARC secrets during a rotation window; and
3. treats the first structurally successful decode as authoritative.

This note demonstrates the ambiguity with this Worker's decoder and explains the selection rule
the ARC plugin applies. It says nothing about which candidate-selection strategy any other backend
integration uses.

## Root cause

The ARC decoder derives a keystream from the five-character ARC prefix and a candidate secret, then
decodes the remaining base32 symbols. It rejects malformed values when, for example, the value is
too short or long, contains an invalid character, or produces a non-monotonic code sequence.

Those checks validate structure, not secret authenticity. A wrong secret produces a different
keystream, but the resulting codes can still happen to satisfy all structural constraints. When
several secrets are configured, `decode succeeded` is therefore insufficient as a secret-selection
rule.

The JWT signature remains valid throughout this scenario. The problem is not that an attacker can
edit an ARC claim without invalidating the token. The problem is that a legitimate signed token from
one side of a rotation window can be assigned the wrong ARC interpretation by the receiving backend.

## Exact reproduction

The following synthetic values reproduce the ambiguity with the decoder in
[`plugins/arc/decode.js`](../plugins/arc/decode.js):

- Current ARC secret: `current-arc-secret`
- Pending ARC secret: `pending-arc-secret`
- ARC claim: `AAAAH2BOY3`
- JWT signing result: `PASS`

Import the decoder and decode the same claim with both configured secrets:

```js
import { expect, it } from 'vitest'
import { arcDecode } from './decode.js'

it('reproduces an ARC rotation collision', () => {
  const arc = 'AAAAH2BOY3'

  const currentResult = arcDecode(arc, 'current-arc-secret')
  const pendingResult = arcDecode(arc, 'pending-arc-secret')

  // Both calls return normally: both interpretations pass every structural check.
  expect(currentResult).toEqual([
    'fail',
    'bad-hmac',
    'device-changed',
    'jailbroken',
    'rooted'
  ])
  expect(pendingResult).toEqual([
    'pass',
    'playintegrity-completed',
    'playintegrity-fail-app-cert-hash',
    'scan-fail'
  ])

  expect(currentResult).not.toEqual(pendingResult)
})
```

Run the focused test with:

```sh
npx vitest run plugins/arc/arc.spec.js
```

To see the effect on a backend that accepts the first structurally successful decode, put
`AAAAH2BOY3` in an ES256 token signed by the configured pass key, then configure the two ARC
secrets in this order:

```json
{
  "currentArcEncodingSecret": "current-arc-secret",
  "pendingArcEncodingSecret": "pending-arc-secret",
  "previousArcEncodingSecrets": []
}
```

Token verification returns `PASS`, but a first-match decoder stops after the structurally
successful current-secret decode and returns:

```json
{
  "tokenResult": "PASS",
  "arcProperties": [
    "fail",
    "bad-hmac",
    "device-changed",
    "jailbroken",
    "rooted"
  ]
}
```

The pending secret is the secret that produced the ARC. Its correct interpretation starts with
`pass` and contains `scan-fail` and the two Play Integrity properties shown above.

## Signed PASS/FAIL is useful but not sufficient by itself

The JWT's pass or fail verification key provides an independent signed security outcome. It can
reject the contradictory current-secret interpretation in the first reproduction. However, two
wrong/different interpretations can also agree on that first flag while disagreeing on the
remaining properties.

For example, the same synthetic secrets both structurally decode `AAAA64HAIH` as `pass`, but return
different properties:

```text
current: pass, cloned, debug, debug, frida
pending: pass, playintegrity-completed, playintegrity-fail-app-cert-hash, scan-fail
```

Consequently, checking only that the ARC result agrees with the signed token's PASS/FAIL outcome
does not fully resolve secret ambiguity.

## Impact

The impact depends on how a deployment consumes ARC properties:

- In this Worker, ARC is an annotation and cannot change core JWT, binding, or message-signing
  enforcement. The core token result is unaffected, and the selection rule below keeps a wrong
  interpretation out of `arcProperties`.
- A downstream API that uses ARC properties for an explicit deny rule could incorrectly allow or
  deny a legitimate request if it trusts a misdecoded annotation.
- Logging, alerting, risk scoring, and incident analysis can attribute incorrect device or app
  security conditions.
- Backends using only one ARC secret are not exposed to candidate ambiguity.

This is primarily a secret-attribution flaw in rotation handling, rather than a failure of JWT
signature verification.

## Safe selection rule

When the ARC format does not provide a trusted secret identifier or authentication tag, a backend
should use a conservative selection rule:

1. Decode the ARC with every eligible current, pending, and previous secret.
2. Discard structural failures.
3. Discard interpretations whose first `pass`/`fail` property contradicts the independently signed
   JWT outcome.
4. Group all remaining candidates by their complete decoded property list.
5. Accept the result only when exactly one distinct interpretation remains. Multiple secrets may be
   accepted when they produce the same complete interpretation.
6. If no interpretation remains, or multiple different interpretations remain, return no ARC
   annotation and log the condition without exposing secrets.

The Worker follows this rule. Because ARC is annotation-only here, returning
`arcProperties: null` on unresolved ambiguity is safer than emitting confidently incorrect flags.

If another backend requires ARC properties for mandatory enforcement and cannot tolerate an
ambiguous result, the stronger architectural solution is deterministic secret selection using
trusted rotation metadata, a secret identifier bound into the signed token, or an authenticated ARC
format. Trying secrets until one produces plausible plaintext cannot provide that guarantee.

## Applicability to other backends

The underlying ambiguity follows from the ARC decoding format and is therefore backend-agnostic.
The observable bug exists only when the caller uses an unsafe multi-secret selection policy.

Other backend implementations should be reviewed for logic equivalent to:

```js
for (const secret of rotationSecrets) {
  try {
    return arcDecode(arc, secret)
  } catch {
    // try the next secret
  }
}
```

An implementation is not affected by this specific issue if it uses one secret, selects the correct
secret from trusted authenticated metadata, or detects and rejects conflicting candidate decodes.

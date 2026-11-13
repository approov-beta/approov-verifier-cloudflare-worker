import { describe, expect, it, vi } from 'vitest'
import crypto from 'node:crypto'
import {
  FAIL_PRIVATE_KEY,
  FUTURE_EXP,
  PASS_PRIVATE_KEY,
  makeEnv,
  makeBackendConfig,
  signEs256
} from '../../test/fixtures.js'
import { establishContext } from '../../src/config/context.js'
import { evaluateApproovToken } from '../../src/approov/evaluate.js'
import arcPlugin from './index.js'
import { arcDecode } from './decode.js'

const S_BASE32_ENCODING = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

// Encode a list of target codes into an ARC string for a given secret/prefix.
const buildArc = (secret, prefix, values) => {
  const hmac = crypto.createHmac('sha256', secret).update(prefix, 'utf8').digest()
  let arc = prefix
  let baseIndex = 0
  for (let i = 0; i < values.length; i++) {
    const decodedByte = values[i] - baseIndex
    arc += S_BASE32_ENCODING[decodedByte ^ (hmac[i] & 31)]
    if ((values[i] & 31) === 31) baseIndex += 32
  }
  return arc
}

describe('ARC plugin', () => {
  const ARC_SECRET = '4yQ48/SnKkvnQi9ec4qcmA=='

  describe('decode', () => {
    it('falls back to static mappings when no customMappings are provided', () => {
      const arc = buildArc(ARC_SECRET, 'AAAAA', [0, 1, 31, 32, 63, 64])
      const decoded = arcDecode(arc, ARC_SECRET)
      expect(decoded).toContain('pass')
      expect(decoded).toContain('debug') // 1 resolves to 'debug' in the static mappings
    })

    it('uses customMappings when provided', () => {
      const arc = buildArc(ARC_SECRET, 'AAAAA', [0, 1, 31, 32, 63, 64])
      const customMappings = { 1: 'custom-flag' }
      const decoded = arcDecode(arc, ARC_SECRET, customMappings)
      expect(decoded).toContain('pass')
      expect(decoded).toContain('custom-flag')
      expect(decoded).not.toContain('debug')
    })

    it('prepends "fail" when no pass (code 0) symbol is present', () => {
      // No value of 0 anywhere → isPass stays false → first property is 'fail'.
      const arc = buildArc(ARC_SECRET, 'AAAAA', [1, 2, 3, 4, 5])
      const decoded = arcDecode(arc, ARC_SECRET)
      expect(decoded[0]).toBe('fail')
      expect(decoded).not.toContain('pass')
    })
  })

  describe('input validation', () => {
    it('throws when no ARC is provided', () => {
      expect(() => arcDecode('', ARC_SECRET)).toThrow('no ARC provided')
    })

    it('throws when the ARC is too short', () => {
      expect(() => arcDecode('AAAAA', ARC_SECRET)).toThrow('ARC is too short')
    })

    it('throws when the ARC is too long', () => {
      // Max is prefix (5) + one keystream byte per symbol (32) = 37: beyond
      // that the HMAC keystream would be exhausted and symbols would silently
      // "decode" with a zero keystream.
      expect(() => arcDecode('A'.repeat(38), ARC_SECRET)).toThrow('ARC is too long')
    })

    it('accepts an ARC at the exact keystream limit', () => {
      // 37 chars consumes the full 32-byte keystream: length must be accepted
      // (any failure would then be about content, not length).
      const codes = Array.from({ length: 32 }, (_, i) => i)
      const arc = buildArc(ARC_SECRET, 'AAAAA', codes)
      expect(arc).toHaveLength(37)
      expect(() => arcDecode(arc, ARC_SECRET)).not.toThrow()
    })

    it('throws on an out-of-alphabet character', () => {
      expect(() => arcDecode('AAAAA11111', ARC_SECRET)).toThrow('invalid ARC character')
    })

    it('throws when decoded values are not monotonically non-decreasing', () => {
      const arc = buildArc(ARC_SECRET, 'AAAAA', [5, 4, 3, 2, 1])
      expect(() => arcDecode(arc, ARC_SECRET)).toThrow('invalid ARC')
    })
  })

  describe('configure', () => {
    it('warns and disables (never fails startup) when the ARC encoding secret is missing', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
      const errors = []
      const config = arcPlugin.configure({}, errors, {})
      expect(errors).toEqual([])
      expect(config.secrets).toEqual([])
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('ARC encoding secrets')
      )
      warnSpy.mockRestore()
    })

    it('defaults shared to an empty object when omitted', () => {
      // Called with only (env, errors) — the `shared = {}` default parameter path.
      const errors = []
      const config = arcPlugin.configure({}, errors)
      expect(errors).toEqual([])
      expect(config.secrets).toEqual([])
      expect(config.flagMappings).toBeNull()
    })

    it('loads current, pending, and previous ARC secrets in safe rotation order', () => {
      const errors = []
      const config = arcPlugin.configure({}, errors, {
        backendConfig: {
          currentArcEncodingSecret: 'current-secret',
          pendingArcEncodingSecret: 'pending-secret',
          previousArcEncodingSecrets: [
            { secret: 'previous-secret', timestamp: '2026-04-08T12:19:30+01:00' },
            { secret: 'previous-without-timestamp' },
            { secret: 'current-secret', timestamp: '2026-03-01T00:00:00Z' }
          ]
        }
      })

      expect(errors).toEqual([])
      expect(config.secrets).toEqual([
        { secret: 'current-secret', source: 'currentArcEncodingSecret', timestamp: null },
        { secret: 'pending-secret', source: 'pendingArcEncodingSecret', timestamp: null },
        {
          secret: 'previous-secret',
          source: 'previousArcEncodingSecrets[0]',
          timestamp: '2026-04-08T12:19:30+01:00'
        },
        {
          secret: 'previous-without-timestamp',
          source: 'previousArcEncodingSecrets[1]',
          timestamp: null
        }
      ])
    })

    it.each([
      {
        name: 'non-string current secret',
        backendConfig: { currentArcEncodingSecret: 123 },
        error: 'currentArcEncodingSecret'
      },
      {
        name: 'non-array previous secrets',
        backendConfig: { previousArcEncodingSecrets: {} },
        error: 'expected an array'
      },
      {
        name: 'non-object previous entry',
        backendConfig: { previousArcEncodingSecrets: [null] },
        error: 'expected an object'
      },
      {
        name: 'non-string previous timestamp',
        backendConfig: { previousArcEncodingSecrets: [{ secret: 'old', timestamp: 123 }] },
        error: 'timestamp'
      },
      {
        name: 'non-string previous secret',
        backendConfig: { previousArcEncodingSecrets: [{ secret: 123 }] },
        error: 'expected a non-empty string'
      },
      {
        name: 'missing previous secret',
        backendConfig: { previousArcEncodingSecrets: [{}] },
        error: 'expected a non-empty string'
      }
    ])('records a startup error for $name', ({ backendConfig, error }) => {
      const errors = []
      arcPlugin.configure({}, errors, { backendConfig })
      expect(errors.join(' ')).toContain(error)
    })

    it('records a startup error when flag mappings cannot be coerced', () => {
      const errors = []
      // A null-prototype object has no toString/valueOf, so `String(value)`
      // throws — exercising the defensive catch around flag-mapping normalization.
      arcPlugin.configure(
        {},
        errors,
        { backendConfig: { arcFlagMappings: { 1: Object.create(null) } } }
      )
      expect(errors.join(' ')).toContain('invalid ARC flag mappings')
    })
  })

  describe('integration via evaluateApproovToken', () => {
    it('parses custom flag mappings from backend config at runtime', async () => {
      const arcVal = buildArc(ARC_SECRET, 'AAAAA', [0, 2, 31, 32, 63, 64])
      const token = signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, arc: arcVal })

      const ctx = establishContext(makeEnv({
        APPROOV_BACKEND_CONFIG: makeBackendConfig({
          currentArcEncodingSecret: ARC_SECRET,
          arcFlagMappings: { 2: 'custom-scan-fail' }
        })
      }))
      expect(ctx.isValid).toBe(true)

      const request = new Request('https://worker.local/v3/shapes/', {
        headers: { 'Approov-Token': token }
      })
      const out = await evaluateApproovToken(ctx, request)

      expect(out.tokenResult).toBe('PASS')
      expect(out.arcProperties).toContain('pass')
      expect(out.arcProperties).toContain('custom-scan-fail')
      expect(out.arcProperties).not.toContain('scan-fail')
    })

    it('leaves arcProperties null when the arc claim is malformed', async () => {
      const token = signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, arc: 'too-short' })
      const ctx = establishContext(makeEnv({
        APPROOV_BACKEND_CONFIG: makeBackendConfig({ currentArcEncodingSecret: ARC_SECRET })
      }))

      const request = new Request('https://worker.local/v3/shapes/', {
        headers: { 'Approov-Token': token }
      })
      const out = await evaluateApproovToken(ctx, request)

      expect(out.tokenResult).toBe('PASS')
      expect(out.arcProperties).toBeNull()
    })

    it.each([
      {
        name: 'pending',
        secret: 'pending-arc-secret',
        config: {
          currentArcEncodingSecret: 'current-arc-secret',
          pendingArcEncodingSecret: 'pending-arc-secret'
        }
      },
      {
        name: 'previous',
        secret: 'previous-arc-secret',
        config: {
          currentArcEncodingSecret: 'current-arc-secret',
          previousArcEncodingSecrets: [
            { secret: 'previous-arc-secret', timestamp: '2026-04-08T12:19:30+01:00' }
          ]
        }
      }
    ])('decodes an ARC generated with the $name rotation secret', async ({ secret, config }) => {
      const arcVal = buildArc(secret, 'AAAAA', [0, 2, 31, 32, 63, 64])
      const token = signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, arc: arcVal })
      const ctx = establishContext(makeEnv({
        APPROOV_BACKEND_CONFIG: makeBackendConfig(config)
      }))
      const request = new Request('https://worker.local/v3/shapes/', {
        headers: { 'Approov-Token': token }
      })

      const out = await evaluateApproovToken(ctx, request)
      expect(out.tokenResult).toBe('PASS')
      expect(out.arcProperties).toContain('pass')
      expect(out.arcProperties).toContain('scan-fail')
    })

    it('rejects a structurally valid current-secret decode that contradicts the signed token outcome', async () => {
      // This pending-secret ARC also passes every structural check under the
      // current secret, but the two interpretations have opposite security
      // flags. The signed PASS token disambiguates them.
      const arcVal = 'AAAAH2BOY3'
      const currentDecoded = arcDecode(arcVal, 'current-arc-secret')
      const pendingDecoded = arcDecode(arcVal, 'pending-arc-secret')

      expect(currentDecoded[0]).toBe('fail')
      expect(pendingDecoded[0]).toBe('pass')
      expect(currentDecoded).not.toEqual(pendingDecoded)

      const token = signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, arc: arcVal })
      const ctx = establishContext(makeEnv({
        APPROOV_BACKEND_CONFIG: makeBackendConfig({
          currentArcEncodingSecret: 'current-arc-secret',
          pendingArcEncodingSecret: 'pending-arc-secret',
          arcFlagMappings: null
        })
      }))
      const request = new Request('https://worker.local/v3/shapes/', {
        headers: { 'Approov-Token': token }
      })

      const out = await evaluateApproovToken(ctx, request)
      expect(out.tokenResult).toBe('PASS')
      expect(out.arcProperties).toEqual(pendingDecoded)
    })

    it('returns no ARC annotation when rotation secrets yield conflicting plausible decodes', async () => {
      // Both interpretations agree with the signed PASS outcome but disagree
      // on the remaining flags, so the claim cannot be safely attributed to a
      // single rotation secret.
      const arcVal = 'AAAA64HAIH'
      const currentDecoded = arcDecode(arcVal, 'current-arc-secret')
      const pendingDecoded = arcDecode(arcVal, 'pending-arc-secret')

      expect(currentDecoded[0]).toBe('pass')
      expect(pendingDecoded[0]).toBe('pass')
      expect(currentDecoded).not.toEqual(pendingDecoded)

      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      const token = signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, arc: arcVal })
      const ctx = establishContext(makeEnv({
        APPROOV_BACKEND_CONFIG: makeBackendConfig({
          currentArcEncodingSecret: 'current-arc-secret',
          pendingArcEncodingSecret: 'pending-arc-secret',
          arcFlagMappings: null
        })
      }))
      const request = new Request('https://worker.local/v3/shapes/', {
        headers: { 'Approov-Token': token }
      })

      const out = await evaluateApproovToken(ctx, request)
      expect(out.tokenResult).toBe('PASS')
      expect(out.arcProperties).toBeNull()
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining('ambiguous across rotation secrets'),
        expect.objectContaining({ distinctResults: 2 })
      )
      errorSpy.mockRestore()
    })

    it('accepts multiple rotation secrets only when they produce the same ARC interpretation', async () => {
      const arcVal = 'AACFA5W6AP'
      const collapsedMappings = {
        2: 'same-flag',
        3: 'same-flag',
        10: 'same-flag',
        21: 'same-flag',
        32: 'same-flag',
        33: 'same-flag'
      }
      const currentDecoded = arcDecode(arcVal, 'current-arc-secret', collapsedMappings)
      const pendingDecoded = arcDecode(arcVal, 'pending-arc-secret', collapsedMappings)
      expect(currentDecoded).toEqual(pendingDecoded)

      const token = signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, arc: arcVal })
      const ctx = establishContext(makeEnv({
        APPROOV_BACKEND_CONFIG: makeBackendConfig({
          currentArcEncodingSecret: 'current-arc-secret',
          pendingArcEncodingSecret: 'pending-arc-secret',
          arcFlagMappings: collapsedMappings
        })
      }))
      const request = new Request('https://worker.local/v3/shapes/', {
        headers: { 'Approov-Token': token }
      })

      const out = await evaluateApproovToken(ctx, request)
      expect(out.tokenResult).toBe('PASS')
      expect(out.arcProperties).toEqual(currentDecoded)
    })

    it('returns no ARC annotation when every structural decode contradicts a signed FAIL token', async () => {
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      const token = signEs256(FAIL_PRIVATE_KEY, { exp: FUTURE_EXP, arc: 'AAAA64HAIH' })
      const ctx = establishContext(makeEnv({
        APPROOV_BACKEND_CONFIG: makeBackendConfig({
          currentArcEncodingSecret: 'current-arc-secret',
          pendingArcEncodingSecret: 'pending-arc-secret',
          arcFlagMappings: null
        })
      }))
      const request = new Request('https://worker.local/v3/shapes/', {
        headers: { 'Approov-Token': token }
      })

      const out = await evaluateApproovToken(ctx, request)
      expect(out.tokenResult).toBe('FAIL')
      expect(out.arcProperties).toBeNull()
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining('ARC decoding error'),
        expect.objectContaining({
          status: 'UNAVAILABLE',
          rejectedForSecurityFlag: 2
        })
      )
      errorSpy.mockRestore()
    })
  })
})

/**
 * Approov ARC decoding plugin.
 *
 * Drop-in plugin that decodes the obfuscated `arc` token claim into semantic
 * property labels and surfaces them as `arcProperties` in the Approov-Result
 * payload. Runs for any decoded token (PASS or FAIL) that carries an `arc`
 * claim; a decode failure leaves `arcProperties` as null (logged, never fatal).
 *
 * Config comes from the parsed `APPROOV_BACKEND_CONFIG` blob passed in via
 * `shared.backendConfig`. A missing ARC
 * encoding secret disables ARC decoding with a startup warning — plugins are
 * annotation-only, so it never blocks the worker from serving requests.
 *
 * Self-contained: depends only on the host plugin-kit plus its own decoder.
 *
 * @module plugins/arc
 */
import { logDebug, logError, logWarn } from '../../src/plugin-kit.js'
import { arcDecode } from './decode.js'

/**
 * Resolve every ARC encoding secret exported for a rotation window.
 *
 * @param {Object|null} backendConfig Parsed APPROOV_BACKEND_CONFIG, if any.
 * @param {String[]} errors Mutable startup error list.
 * @returns {ReadonlyArray<*>} Ordered current, pending, then previous candidates.
 */
const resolveEncodingSecrets = (backendConfig, errors) => {
  const candidates = []
  const seen = new Set()

  const addSecret = (value, source, timestamp = null) => {
    if (value === undefined || value === null || value === '') return
    if (typeof value !== 'string') {
      errors.push(`invalid ${source}: ARC encoding secret must be a string`)
      return
    }
    if (seen.has(value)) return
    seen.add(value)
    candidates.push(Object.freeze({ secret: value, source, timestamp }))
  }

  addSecret(backendConfig?.currentArcEncodingSecret, 'currentArcEncodingSecret')
  addSecret(backendConfig?.pendingArcEncodingSecret, 'pendingArcEncodingSecret')

  const previous = backendConfig?.previousArcEncodingSecrets
  if (previous !== undefined && previous !== null) {
    if (!Array.isArray(previous)) {
      errors.push('invalid previousArcEncodingSecrets: expected an array')
    } else {
      for (const [index, entry] of previous.entries()) {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
          errors.push(`invalid previousArcEncodingSecrets[${index}]: expected an object`)
          continue
        }
        if (entry.timestamp !== undefined && typeof entry.timestamp !== 'string') {
          errors.push(`invalid previousArcEncodingSecrets[${index}].timestamp: expected a string`)
          continue
        }
        if (typeof entry.secret !== 'string' || entry.secret.length === 0) {
          errors.push(`invalid previousArcEncodingSecrets[${index}].secret: expected a non-empty string`)
          continue
        }
        addSecret(
          entry.secret,
          `previousArcEncodingSecrets[${index}]`,
          entry.timestamp || null
        )
      }
    }
  }

  return Object.freeze(candidates)
}

/**
 * Parse ARC flag mappings from backend config.
 *
 * @param {Object|null} backendConfig Parsed APPROOV_BACKEND_CONFIG, if any.
 * @param {String[]} errors Mutable startup error list.
 * @returns {Object|null} Frozen `{ [code]: label }` map or null.
 */
const parseFlagMappings = (backendConfig, errors) => {
  const parsed = backendConfig?.arcFlagMappings
  if (!parsed) return null

  try {
    return Object.freeze(Object.fromEntries(
      Object.entries(parsed).map(([key, value]) => [parseInt(key, 10), String(value)])
    ))
  } catch (err) {
    errors.push(`invalid ARC flag mappings: ${err.message}`)
    return null
  }
}

export default {
  id: 'arc',
  resultKey: 'arcProperties',

  summarize (result) {
    return { status: result === null ? 'UNAVAILABLE' : 'DECODED', properties: result }
  },

  configure (_env, errors, shared = {}) {
    const backendConfig = shared.backendConfig ?? null

    const secrets = resolveEncodingSecrets(backendConfig, errors)
    if (secrets.length === 0 && !shared.deferSecrets) {
      // Annotation-only plugin: degrade to disabled rather than failing the
      // whole worker's startup over a missing decode secret.
      logWarn('no ARC encoding secrets are available in APPROOV_BACKEND_CONFIG; ARC decoding is disabled')
    }

    const flagMappings = parseFlagMappings(backendConfig, errors)

    return { secrets, flagMappings }
  },

  async evaluate ({ ctx, config, tokenVerification }) {
    const arcRaw = tokenVerification && tokenVerification.decoded && tokenVerification.decoded.arc
    if (!arcRaw || !config || !config.secrets || config.secrets.length === 0) {
      return null
    }

    // A decoded payload is only retained after verification with the pass or
    // fail key, so its stable status is the signed ARC security flag.
    const expectedSecurityFlag = tokenVerification.status.toLowerCase()

    let rejectedForSecurityFlag = 0
    const variants = new Map()

    for (const candidate of config.secrets) {
      try {
        const arcProperties = arcDecode(arcRaw, candidate.secret, config.flagMappings)

        // ARC has no authentication tag, so a wrong rotation secret can still
        // produce a structurally valid decode. The JWT signature independently
        // establishes PASS/FAIL; reject any ARC interpretation that contradicts
        // that signed outcome before considering the candidate a match.
        if (arcProperties[0] !== expectedSecurityFlag) {
          rejectedForSecurityFlag++
          continue
        }

        const key = JSON.stringify(arcProperties)
        const variant = variants.get(key)
        if (variant) {
          variant.candidates.push(candidate)
        } else {
          variants.set(key, { arcProperties, candidates: [candidate] })
        }
      } catch { /* try the remaining rotation secrets */ }
    }

    if (variants.size === 1) {
      const selected = variants.values().next().value
      logDebug(ctx, 'arc decoded', {
        status: 'DECODED',
        propertyCount: selected.arcProperties.length
      })
      return selected.arcProperties
    }

    if (variants.size > 1) {
      logError('ARC decoding is ambiguous across rotation secrets', {
        candidatesTried: config.secrets.length,
        matchingCandidates: Array.from(variants.values())
          .reduce((total, variant) => total + variant.candidates.length, 0),
        distinctResults: variants.size,
        rejectedForSecurityFlag
      })
      return null
    }

    logError('ARC decoding error', {
      status: 'UNAVAILABLE',
      candidatesTried: config.secrets.length,
      rejectedForSecurityFlag
    })
    return null
  }
}

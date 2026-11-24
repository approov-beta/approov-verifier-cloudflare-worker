import crypto from 'node:crypto'
import { APPROOV_PERMITTED_ALGORITHMS } from '../constants.js'
import { configurePlugins, plugins } from '../plugin-host.js'
import { decodeBase64OrBase64Url } from '../utils/crypto.js'
import { logDebug, logWarn } from '../utils/logging.js'
import { parseBoolean, trimOrNull } from '../utils/text.js'
import { validateWorkerConfig } from './schema.mjs'
import { parseProtectedPaths } from './protected-paths.js'

/**
 * Check that a configured upstream domain is a bare hostname.
 *
 * The upstream rewrite assigns the value to `url.host`, and the WHATWG URL
 * host setter silently ignores values containing a scheme, path, port or
 * credentials — which would leave requests pointed at the worker itself. This
 * probe round-trips the value through a URL to reject such inputs up front.
 *
 * @param {String} value Candidate hostname.
 * @returns {Boolean} True when the value is exactly a hostname.
 */
const isBareHost = (value) => {
  try {
    const probe = new URL(`https://${value}`)
    return probe.hostname === value.toLowerCase() &&
      probe.pathname === '/' &&
      probe.search === '' &&
      probe.hash === '' &&
      probe.username === '' &&
      probe.password === '' &&
      probe.port === ''
  } catch {
    return false
  }
}

/**
 * Parse allowed timestamp skew for message-signing verification.
 *
 * @param {*} env Worker environment bindings.
 * @param {String[]} errors Mutable configuration error list.
 * @returns {Number} Non-negative tolerance value in seconds.
 */
const parseMessageSigningTolerance = (env, errors) => {
  const toleranceRaw = typeof env.APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS === 'number'
    ? String(env.APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS)
    : trimOrNull(env.APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS)
  if (!toleranceRaw) return 60

  if (!/^\d+$/.test(toleranceRaw) || !Number.isSafeInteger(Number.parseInt(toleranceRaw, 10))) {
    errors.push('env.APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS must be a non-negative integer')
    return 60
  }
  return Number.parseInt(toleranceRaw, 10)
}

/**
 * Parse the maximum request body size to consume while validating Content-Digest.
 *
 * @param {*} env Worker environment bindings.
 * @param {String[]} errors Mutable configuration error list.
 * @returns {Number} Non-negative maximum in bytes.
 */
const parseMessageSigningMaxBodyBytes = (env, errors) => {
  const maxBodyBytesRaw = typeof env.APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES === 'number'
    ? String(env.APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES)
    : trimOrNull(env.APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES)
  if (!maxBodyBytesRaw) return 1048576

  if (!/^\d+$/.test(maxBodyBytesRaw)) {
    errors.push('env.APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES must be a non-negative integer')
    return 1048576
  }

  const parsed = Number.parseInt(maxBodyBytesRaw, 10)
  if (!Number.isSafeInteger(parsed)) {
    errors.push('env.APPROOV_MESSAGE_SIGNING_MAX_BODY_BYTES must be a safe integer')
    return 1048576
  }

  return parsed
}

/**
 * Load the account message-signing secret from `APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET`.
 *
 * The encoding is auto-detected: a value that is valid base64/base64url is
 * decoded to its underlying bytes; otherwise the value is used verbatim as a
 * raw UTF-8 secret. (A raw secret that happens to also be valid base64 will be
 * treated as base64 — base64-encode such secrets to remove the ambiguity.)
 *
 * @param {*} env Worker environment bindings.
 * @returns {Buffer|null} Secret bytes or null if unset.
 */
const loadAccountMessageSigningSecret = (env) => {
  const value = trimOrNull(env.APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET)
  if (!value) return null

  try {
    return decodeBase64OrBase64Url(value)
  } catch {
    return Buffer.from(value, 'utf8')
  }
}

const ALGORITHM_KEY_TYPES = Object.freeze({
  HS256: 'oct',
  RS256: 'RSA',
  ES256: 'EC'
})

const ALGORITHM_EC_CURVES = Object.freeze({
  ES256: 'P-256'
})

/**
 * Parse signing keys from a CLI-exported JWKS into typed verifier records.
 * Encryption-only entries are ignored; malformed signing entries fail startup.
 *
 * @param {*} jwks JWKS object.
 * @param {String} source Configuration field name.
 * @returns {Map<String, *>} Map of key ID to verifier record.
 */
const parseVerifiersFromJwks = (jwks, source) => {
  if (!jwks || !Array.isArray(jwks.keys)) {
    throw new Error(`${source} must contain a keys array`)
  }

  const verifiers = new Map()
  for (const jwk of jwks.keys) {
    if (!jwk || typeof jwk !== 'object') {
      throw new Error(`${source} contains a non-object JWK`)
    }

    if (jwk.use === 'enc' || jwk.alg === 'A256GCMKW') continue
    if (jwk.use !== 'sig') {
      throw new Error(`${source} JWK "${jwk.kid || '__default__'}" must declare use "sig"`)
    }
    if (!APPROOV_PERMITTED_ALGORITHMS.includes(jwk.alg)) {
      throw new Error(`${source} JWK "${jwk.kid || '__default__'}" uses unsupported signing algorithm "${String(jwk.alg)}"`)
    }

    const expectedKeyType = ALGORITHM_KEY_TYPES[jwk.alg]
    if (jwk.kty !== expectedKeyType) {
      throw new Error(`${source} JWK "${jwk.kid || '__default__'}" algorithm ${jwk.alg} requires kty ${expectedKeyType}`)
    }
    if (expectedKeyType === 'EC' && jwk.crv !== ALGORITHM_EC_CURVES[jwk.alg]) {
      throw new Error(`${source} JWK "${jwk.kid || '__default__'}" algorithm ${jwk.alg} requires curve ${ALGORITHM_EC_CURVES[jwk.alg]}`)
    }

    const kid = typeof jwk.kid === 'string' && jwk.kid.trim() ? jwk.kid : '__default__'
    if (verifiers.has(kid)) {
      throw new Error(`${source} contains duplicate key ID "${kid}"`)
    }

    let key
    if (expectedKeyType === 'oct') {
      if (typeof jwk.k !== 'string' || !jwk.k.trim()) {
        throw new Error(`${source} JWK "${kid}" is missing symmetric key material`)
      }
      key = crypto.createSecretKey(decodeBase64OrBase64Url(jwk.k))
    } else {
      key = crypto.createPublicKey({ key: jwk, format: 'jwk' })
    }

    verifiers.set(kid, Object.freeze({
      kid,
      alg: jwk.alg,
      kty: jwk.kty,
      source,
      key
    }))
  }
  return verifiers
}

/**
 * Resolve the verification policy for an incoming public API hostname.
 *
 * @param {*} ctx Runtime context.
 * @param {String} apiDomain Incoming request hostname.
 * @returns {*} Frozen API policy.
 * @throws {Error} When the domain is unknown, disabled, or requires disabled compatibility.
 */
export const resolveApiPolicy = (ctx, apiDomain) => {
  const normalized = String(apiDomain || '').trim().toLowerCase()
  const policy = ctx && ctx.approovApiPolicies
    ? ctx.approovApiPolicies.get(normalized)
    : null

  if (!policy) {
    throw new Error(`incoming API domain "${normalized || '(empty)'}" is not present in APPROOV_BACKEND_CONFIG.apis`)
  }
  if (!policy.isPassKeyPresent) {
    throw new Error(`incoming API domain "${normalized}" has Approov tokens disabled`)
  }
  if (!policy.kid && !ctx.approovAcceptDefaultAccountSecret) {
    throw new Error(`incoming API domain "${normalized}" uses the default account secret; set APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET=true to accept it`)
  }
  return policy
}

// Workers reuse the same env bindings object for every request in an isolate,
// and establishContext is pure with respect to env, so the parsed context
// (including the JWKS -> KeyObject conversion) is cached on env identity to
// avoid re-parsing key material per request.
const contextCache = new WeakMap()

/**
 * Establish immutable runtime context from worker environment bindings.
 *
 * This function:
 * - validates configuration and accumulates startup errors
 * - parses Approov keys/secrets and verification settings
 * - applies defaults for headers, claims and API target
 * - returns a frozen context consumed by request handling logic
 *
 * The result is memoized per `env` object until a binding value changes.
 *
 * @param {*} env Cloudflare Worker environment bindings.
 * @returns {*} Immutable context with configuration, parsed key material, and validity metadata.
 */
export const establishContext = (env, { preflight = false } = {}) => {
  const cached = contextCache.get(env)
  const bindings = Object.entries(env)
  if (cached && !preflight && cached.bindings.length === bindings.length &&
    cached.bindings.every(([name, value], i) => name === bindings[i][0] && value === bindings[i][1])) {
    return cached.ctx
  }

  const errors = validateWorkerConfig(env, plugins.filter(p => p && p.configSchema).map(p => p.configSchema))
  const approovDebug = parseBoolean(env.APPROOV_DEBUG, false, errors, 'APPROOV_DEBUG')

  const backendConfigRaw = trimOrNull(env.APPROOV_BACKEND_CONFIG)
  let backendConfig = null
  if (backendConfigRaw) {
    try {
      backendConfig = JSON.parse(backendConfigRaw)
    } catch (err) {
      errors.push('invalid env.APPROOV_BACKEND_CONFIG: expected valid JSON')
    }
  } else if (!preflight) {
    errors.push('missing env.APPROOV_BACKEND_CONFIG')
  }

  let approovTokenDefaultPassKeys = new Map()
  let approovTokenPassKeys = new Map()
  let approovTokenFailKeys = new Map()

  if (backendConfigRaw || !preflight) {
    for (const [field, assign] of [
      ['defaultPassJWKS', (keys) => { approovTokenDefaultPassKeys = keys }],
      ['passJWKS', (keys) => { approovTokenPassKeys = keys }],
      ['failJWKS', (keys) => { approovTokenFailKeys = keys }]
    ]) {
      try {
        assign(parseVerifiersFromJwks(backendConfig?.[field], field))
      } catch (err) {
        errors.push(`invalid ${field} in env.APPROOV_BACKEND_CONFIG: ${err.message.includes('duplicate key ID') ? 'duplicate key ID' : 'invalid signing key set'}`)
      }
    }
    if (![...approovTokenDefaultPassKeys.values()].some((verifier) => verifier.alg === 'HS256')) {
      errors.push('env.APPROOV_BACKEND_CONFIG.defaultPassJWKS must contain an HS256 signing key')
    }
  }

  const approovApiPolicies = new Map()
  if (backendConfigRaw || !preflight) {
    const apis = backendConfig?.apis
    if (!apis || typeof apis !== 'object' || Array.isArray(apis) || Object.keys(apis).length === 0) {
      errors.push('env.APPROOV_BACKEND_CONFIG.apis must be a non-empty object')
    } else {
      for (const [domain, apiConfig] of Object.entries(apis)) {
        const normalizedDomain = String(domain).trim().toLowerCase()
        if (!isBareHost(normalizedDomain)) {
          errors.push('invalid API domain in env.APPROOV_BACKEND_CONFIG.apis')
          continue
        }
        if (approovApiPolicies.has(normalizedDomain)) {
          errors.push('duplicate API domain in env.APPROOV_BACKEND_CONFIG.apis')
          continue
        }
        if (!apiConfig || typeof apiConfig !== 'object' || Array.isArray(apiConfig)) {
          errors.push('invalid API configuration in env.APPROOV_BACKEND_CONFIG.apis')
          continue
        }

        const kid = typeof apiConfig.kid === 'string' ? apiConfig.kid.trim() : ''
        const isPassKeyPresent = apiConfig.isPassKeyPresent === true
        const isFailKeyPresent = apiConfig.isFailKeyPresent === true
        if (kid && isPassKeyPresent) {
          if (!approovTokenPassKeys.has(kid)) {
            errors.push('env.APPROOV_BACKEND_CONFIG.apis references a key missing from passJWKS')
          }
          if (!isFailKeyPresent || !approovTokenFailKeys.has(kid)) {
            errors.push('env.APPROOV_BACKEND_CONFIG.apis references a key without a matching failJWKS key')
          }
        }

        approovApiPolicies.set(normalizedDomain, Object.freeze({
          domain: normalizedDomain,
          kid,
          isPassKeyPresent,
          isFailKeyPresent
        }))
      }
    }
  }

  const approovAcceptDefaultAccountSecret = parseBoolean(
    env.APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET,
    false,
    errors,
    'APPROOV_ACCEPT_DEFAULT_ACCOUNT_SECRET'
  )
  if (approovAcceptDefaultAccountSecret) {
    logWarn('default account secret token verification is enabled for this entire Worker deployment')
  }

  const approovTokenHeaderName = trimOrNull(env.APPROOV_TOKEN_HEADER_NAME) || 'Approov-Token'
  const approovStatusHeaderName = trimOrNull(env.APPROOV_STATUS_HEADER_NAME) || 'Approov-Status'
  const approovTokenAudience = trimOrNull(env.APPROOV_TOKEN_AUDIENCE)
  const approovTokenAudienceFromHost = parseBoolean(
    env.APPROOV_TOKEN_AUDIENCE_FROM_HOST,
    false,
    errors,
    'APPROOV_TOKEN_AUDIENCE_FROM_HOST'
  )

  // a fixed audience and a per-request audience contradict each other, so
  // refuse to start rather than silently preferring one of them
  if (approovTokenAudienceFromHost && approovTokenAudience) {
    errors.push('env.APPROOV_TOKEN_AUDIENCE and env.APPROOV_TOKEN_AUDIENCE_FROM_HOST cannot both be set')
  }
  const approovBindingHeaderName = trimOrNull(env.APPROOV_TOKEN_BINDING_HEADER_NAME) || 'Authorization'
  const approovBindingClaimName = trimOrNull(env.APPROOV_TOKEN_BINDING_CLAIM_NAME) || 'pay'

  const approovTokenBinding = parseBoolean(env.APPROOV_TOKEN_BINDING_ENABLED, false, errors, 'APPROOV_TOKEN_BINDING_ENABLED')

  const approovMessageSigningTolerance = parseMessageSigningTolerance(env, errors)
  const approovMessageSigningRequired = env.APPROOV_MESSAGE_SIGNING_REQUIRED ?? null
  const approovMessageSigningMaxBodyBytes = parseMessageSigningMaxBodyBytes(env, errors)
  const approovAccountMessageSigningSecret = loadAccountMessageSigningSecret(env)
  const approovAccountMessageSigningKeyId = trimOrNull(env.APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID)
  const hasAccountMessageSigningSecret =
    Buffer.isBuffer(approovAccountMessageSigningSecret) &&
    approovAccountMessageSigningSecret.length > 0

  // Pass-through forwarding keeps the inbound hostname so one deployment can
  // serve several Worker Routes, each reaching its own origin via the zone's
  // DNS record. It is only valid in the Worker Route topology: on a Custom
  // Domain or workers.dev hostname the Worker is the origin for the incoming
  // hostname, so preserving it would make the Worker fetch itself.
  const apiPassthrough = parseBoolean(env.API_PASSTHROUGH, false, errors, 'API_PASSTHROUGH')

  const configuredApiHost = env.API_DOMAIN ? String(env.API_DOMAIN).trim() : ''
  let apiHost = ''
  if (apiPassthrough) {
    // Requiring API_DOMAIN to be absent keeps the operator's intent explicit:
    // a leftover value must never be silently ignored.
    if (configuredApiHost) {
      errors.push('env.API_DOMAIN must not be set when env.API_PASSTHROUGH is true; remove one of them to make the forwarding target explicit')
    }
    if (env.API_PORT !== undefined && String(env.API_PORT).trim() !== '') {
      logWarn('env.API_PORT is ignored when env.API_PASSTHROUGH is true; the inbound port is preserved')
    }
  } else if (!configuredApiHost) {
    errors.push('missing env.API_DOMAIN')
  } else if (!isBareHost(configuredApiHost)) {
    // A scheme, path, or userinfo would be silently discarded by the URL host
    // setter during the upstream rewrite (sending traffic back to the worker's
    // own hostname), so reject the value outright.
    errors.push('env.API_DOMAIN must be a bare hostname such as "api.example.com" (no scheme, path, or credentials)')
  } else {
    apiHost = configuredApiHost
  }

  const apiPortRaw = env.API_PORT !== undefined && String(env.API_PORT).trim() !== ''
    ? String(env.API_PORT).trim()
    : '443'
  const apiPort = Number.parseInt(apiPortRaw, 10)
  if (!/^\d+$/.test(apiPortRaw) || apiPort < 1 || apiPort > 65535) {
    errors.push('env.API_PORT must be an integer between 1 and 65535')
  }

  const approovMode = env.APPROOV_MODE
  const approovActions = Object.freeze({
    token: env.APPROOV_TOKEN_ACTION ?? null,
    binding: env.APPROOV_TOKEN_BINDING_ACTION ?? null,
    messageSigning: env.APPROOV_MESSAGE_SIGNING_ACTION ?? null
  })
  if (approovMode === 'block' && !Object.values(approovActions).includes('block')) {
    logWarn('env.APPROOV_MODE is "block" but no action is "block": failing requests are forwarded and never annotated')
  }
  const approovBlockResponseStatus = env.APPROOV_BLOCK_RESPONSE_STATUS === undefined
    ? 403
    : Number(env.APPROOV_BLOCK_RESPONSE_STATUS)
  const approovBlockResponseBody = env.APPROOV_BLOCK_RESPONSE_BODY ?? 'Forbidden'
  const approovLoggingEnabled = parseBoolean(env.APPROOV_LOGGING_ENABLED)
  const approovAnalyticsEnabled = parseBoolean(env.APPROOV_ANALYTICS_ENABLED)

  const approovEchoMode = parseBoolean(env.APPROOV_ECHO_MODE, false, errors, 'APPROOV_ECHO_MODE')
  const approovProtectedPaths = parseProtectedPaths(env, errors)

  // Drop-in plugins contribute their own config + startup validation. Run last
  // so plugin errors join the same startup error list that gates `isValid`.
  // `backendConfig` is shared so plugins (e.g. ARC) can read it without
  // re-parsing APPROOV_BACKEND_CONFIG.
  const pluginConfig = configurePlugins(env, errors, { backendConfig, deferSecrets: preflight })

  const ctx = Object.freeze({
    approovTokenDefaultPassKeys,
    approovTokenPassKeys,
    approovTokenFailKeys,
    approovApiPolicies,
    approovAcceptDefaultAccountSecret,
    approovTokenAudience,
    approovTokenAudienceFromHost,
    approovTokenHeaderName,
    approovStatusHeaderName,
    approovBindingHeaderName,
    approovBindingClaimName,
    approovTokenBinding,
    approovDebug,
    approovMessageSigningTolerance,
    approovMessageSigningRequired,
    approovMessageSigningMaxBodyBytes,
    approovAccountMessageSigningSecret,
    approovAccountMessageSigningKeyId,
    apiHost,
    apiPassthrough,
    apiPort,
    approovMode,
    approovActions,
    approovBlockResponseStatus,
    approovBlockResponseBody,
    approovLoggingEnabled,
    approovAnalyticsEnabled,
    approovEchoMode,
    approovProtectedPaths,
    pluginConfig,
    isValid: errors.length === 0,
    errors: Object.freeze([...new Set(errors)])
  })

  if (ctx.isValid) {
    logDebug(ctx, 'debug logging enabled', {
      tokenHeaderName: approovTokenHeaderName,
      bindingHeaderName: approovBindingHeaderName,
      bindingClaimName: approovBindingClaimName,
      tokenAudienceFromHost: approovTokenAudienceFromHost,
      tokenBindingEnabled: approovTokenBinding,
      acceptDefaultAccountSecret: approovAcceptDefaultAccountSecret,
      messageSigningToleranceSeconds: approovMessageSigningTolerance,
      messageSigningRequired: approovMessageSigningRequired,
      messageSigningMaxBodyBytes: approovMessageSigningMaxBodyBytes,
      hasAccountMessageSigningSecret,
      hasAccountMessageSigningKeyId: Boolean(approovAccountMessageSigningKeyId),
      apiPassthrough,
      apiPort,
      approovMode,
      approovActions,
      approovBlockResponseStatus,
      approovEchoMode,
      protectedPathCount: approovProtectedPaths ? approovProtectedPaths.length : null
    })
  }

  if (!preflight) contextCache.set(env, { bindings, ctx })
  return ctx
}

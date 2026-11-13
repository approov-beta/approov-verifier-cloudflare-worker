import {
  APPROOV_BINDING_OUTCOMES,
  APPROOV_MESSAGE_SIGNING_MODES,
  APPROOV_MESSAGE_SIGNING_OUTCOMES,
  APPROOV_TOKEN_OUTCOMES
} from './constants.js'
import { isRunnablePlugin, plugins } from './plugin-host.js'
import { parseBoolean } from './config/schema.mjs'
import { parseClientStatus } from './approov/client-status.js'

const MAX_PLUGIN_BYTES = 4096
const MAX_PLUGINS_BYTES = 16384
const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype'])
const VERIFICATION_STATUSES = new Set(Object.values(APPROOV_TOKEN_OUTCOMES))

const statusFrom = (values, value, fallback) => Object.values(values).includes(value) ? value : fallback

// Copy data, never getters, class instances, or toJSON hooks. Limits apply to
// the copy before it reaches either destination. Plugins remain trusted code.
const copyJson = (value, depth = 0) => {
  if (value instanceof Promise) {
    value.catch(() => {})
    throw new Error('asynchronous summary')
  }
  if (depth > 4) throw new Error('summary depth exceeded')
  if (value === null || typeof value === 'boolean') return value
  if (typeof value === 'string' && Buffer.byteLength(value) <= MAX_PLUGIN_BYTES) return value
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value !== 'object') throw new Error('unsupported summary value')

  const array = Array.isArray(value)
  const prototype = Object.getPrototypeOf(value)
  if (!array && prototype !== Object.prototype && prototype !== null) throw new Error('summary must be plain JSON')
  if (array && value.length > 64) throw new Error('summary array exceeded')
  if (Object.getOwnPropertySymbols(value).length) throw new Error('symbol property')
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const copy = array ? [] : {}
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (array && key === 'length') continue
    if (UNSAFE_KEYS.has(key) || !Object.hasOwn(descriptor, 'value')) throw new Error('unsafe summary property')
    copy[key] = copyJson(descriptor.value, depth + 1)
    if (Buffer.byteLength(JSON.stringify(copy)) > MAX_PLUGIN_BYTES) throw new Error('summary size exceeded')
  }
  return copy
}

/**
 * Create optional, request-local analytics independently of security config.
 * Configuration and output errors cannot change request enforcement.
 * @param {Object} env Worker bindings.
 * @returns {Object|null} Collector, or null when disabled.
 */
export const createAnalytics = (env) => {
  const logsEnabled = parseBoolean(env.APPROOV_LOGGING_ENABLED)
  const analyticsEnabled = parseBoolean(env.APPROOV_ANALYTICS_ENABLED)
  if (!logsEnabled && !analyticsEnabled) return null
  const started = performance.now()
  const summary = {
    version: 3,
    clientStatus: null,
    token: { presence: 'NOT_CHECKED', verification: 'NOT_CHECKED' },
    attestation: 'UNAVAILABLE',
    binding: 'NOT_CHECKED',
    messageSignature: { mode: 'unknown', status: 'NOT_CHECKED', signatures: { install: null, account: null } },
    plugins: {},
    validation: 'NOT_EVALUATED',
    mode: 'UNAVAILABLE',
    action: 'error',
    actions: null,
    responseStatus: null,
    upstreamStatus: null,
    durationMs: 0
  }
  for (const plugin of plugins) {
    if (isRunnablePlugin(plugin) && typeof plugin.summarize === 'function') {
      const candidate = { ...summary.plugins, [plugin.id]: { status: 'NOT_CHECKED' } }
      if (Buffer.byteLength(JSON.stringify(candidate)) <= MAX_PLUGINS_BYTES) summary.plugins = candidate
    }
  }

  return {
    logsEnabled,
    configure (ctx, request) {
      if (!ctx.isValid) return
      summary.mode = ctx.approovMode
      summary.clientStatus = parseClientStatus(request.headers.get(ctx.approovStatusHeaderName))
      summary.actions = ctx.approovMode === 'block' ? { ...ctx.approovActions } : null
      const token = request.headers.get(ctx.approovTokenHeaderName)
      summary.token.presence = token === null ? 'MISSING' : token.trim() === '' ? 'EMPTY' : 'PRESENT'
    },
    observePlugin (plugin, result, failure) {
      if (!Object.hasOwn(summary.plugins, plugin.id)) return
      let safe
      try {
        safe = failure ? { status: failure } : copyJson(plugin.summarize(result))
        if (safe === null || Array.isArray(safe) || typeof safe !== 'object') throw new Error('summary must be an object')
      } catch {
        safe = { status: 'SUMMARY_ERROR' }
      }
      const candidate = { ...summary.plugins, [plugin.id]: safe }
      if (Buffer.byteLength(JSON.stringify(candidate)) > MAX_PLUGINS_BYTES) {
        candidate[plugin.id] = { status: 'SUMMARY_ERROR' }
        if (Buffer.byteLength(JSON.stringify(candidate)) > MAX_PLUGINS_BYTES) delete candidate[plugin.id]
      }
      summary.plugins = candidate
    },
    evaluated (result, failed, error) {
      if (result) {
        const verified = result.tokenVerification?.status
        const status = verified ?? result.tokenResult
        if (status === 'PASS' || status === 'FAIL') {
          // Only the completed verifier establishes authenticity, not the
          // outer tokenResult, which can become ERROR at a later stage.
          if (verified) {
            summary.token.verification = 'VERIFIED'
            summary.attestation = verified
          }
        } else if (VERIFICATION_STATUSES.has(status) && !['MISSING_HEADER', 'EMPTY_HEADER', 'NOT_CHECKED'].includes(status)) {
          summary.token.verification = status
        }
        summary.binding = statusFrom(APPROOV_BINDING_OUTCOMES, result.bindingResult, 'NOT_CHECKED')
        summary.messageSignature.mode = statusFrom(APPROOV_MESSAGE_SIGNING_MODES, result.messageSigningMode, 'unknown')
        for (const name of ['install', 'account']) {
          const entry = result.messageSigningVerification?.signatures?.[name]
          summary.messageSignature.signatures[name] = entry
            ? statusFrom(APPROOV_MESSAGE_SIGNING_OUTCOMES, entry.status, 'ERROR')
            : null
        }
        summary.messageSignature.status = statusFrom(APPROOV_MESSAGE_SIGNING_OUTCOMES, result.messageSigningResult, 'NOT_CHECKED')
      }
      summary.validation = error || result?.tokenResult === 'ERROR' || result?.bindingResult === 'ERROR' || result?.messageSigningResult === 'ERROR'
        ? 'ERROR'
        : failed ? 'FAIL' : 'PASS'
    },
    respond (response, action, upstreamStatus) {
      summary.action = action
      summary.responseStatus = response.status
      summary.upstreamStatus = upstreamStatus
    },
    emit () {
      summary.durationMs = Math.max(0, performance.now() - started)
      if (logsEnabled) {
        try { console.log({ event: 'approov.request', ...summary }) } catch { /* best effort */ }
      }
      try {
        // writeDataPoint returns void; the Workers runtime handles delivery.
        if (analyticsEnabled) {
          env.APPROOV_ANALYTICS?.writeDataPoint({
            blobs: [
              '3', summary.mode, summary.action, summary.token.presence,
              summary.token.verification, summary.attestation, summary.binding,
              summary.messageSignature.mode, summary.messageSignature.status, summary.validation,
              summary.clientStatus ?? 'missing'
            ],
            doubles: [summary.responseStatus ?? -1, summary.upstreamStatus ?? -1, summary.durationMs],
            indexes: [[summary.token.verification, summary.attestation, summary.validation].join(':')]
          })
        }
      } catch { /* best effort, independent of structured logs */ }
    }
  }
}

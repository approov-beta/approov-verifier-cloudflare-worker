/**
 * Generic plugin host.
 *
 * Loads the build-time-generated registry and invokes each plugin's lifecycle
 * hooks without the core needing to know anything about individual plugins.
 * Adding or removing a plugin therefore requires no edits to the core worker.
 *
 * Plugin contract (default export of `plugins/<name>/index.js`):
 *   {
 *     id: String,                 // unique, stable identifier
 *     resultKey?: String,         // key under which evaluate() output is stored
 *                                 //   in the Approov-Result payload (defaults to id)
 *     configSchema?: Object,      // APPROOV_ field definitions for the shared validator
 *     configure?(env, errors, shared) -> Object|null,
 *                                 // parse + validate env config at startup;
 *                                 //   push human-readable strings onto `errors`.
 *                                 //   `shared` carries pre-parsed primitives the
 *                                 //   core already computed (e.g. backendConfig)
 *                                 //   so plugins need not re-parse them.
 *     evaluate?({ ctx, config, request, approovToken, tokenVerification, signal }) -> any
 *                                 // run during request evaluation; return value
 *                                 //   is stored in the result payload
 *     summarize?(result) -> Object // synchronous, safe JSON summary; no I/O
 *   }
 *
 * @module plugin-host
 */
import { plugins } from './plugins.generated.js'
import { errorMessage } from './utils/errors.js'
import { logError } from './utils/logging.js'

// Annotation plugins must not hold up forwarding indefinitely. This bounds
// asynchronous waiting, not synchronous CPU work in the shared Worker isolate.
export const PLUGIN_EVALUATION_TIMEOUT_MS = 1000

const RESERVED_RESULT_KEYS = new Set([
  'clientStatus',
  'tokenResult',
  'bindingResult',
  'messageSigningMode',
  'messageSigningResult',
  'messageSigningVerification',
  'tokenVerification'
])

const UNSAFE_PROPERTY_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

const pluginResultKey = (plugin) =>
  plugin && plugin.resultKey === undefined ? plugin.id : plugin && plugin.resultKey

const isValidPluginKey = (value) =>
  typeof value === 'string' && value.trim() !== '' && value === value.trim()

const isSafePluginKey = (value) =>
  isValidPluginKey(value) && !UNSAFE_PROPERTY_KEYS.has(value)

const validatePluginRegistry = (errors) => {
  const ids = new Set()
  const resultKeys = new Set()
  const invalidPlugins = new Set()

  for (const plugin of plugins) {
    if (!plugin || typeof plugin !== 'object') {
      errors.push('invalid plugin: expected an object export')
      invalidPlugins.add(plugin)
      continue
    }

    const id = plugin.id
    const key = pluginResultKey(plugin)
    if (!isValidPluginKey(id)) {
      errors.push('invalid plugin id: expected a non-empty string without surrounding whitespace')
      invalidPlugins.add(plugin)
    } else if (UNSAFE_PROPERTY_KEYS.has(id)) {
      errors.push(`unsafe plugin id "${id}"`)
      invalidPlugins.add(plugin)
    } else if (ids.has(id)) {
      errors.push(`duplicate plugin id "${id}"`)
    }

    if (!isValidPluginKey(key)) {
      errors.push(`invalid plugin result key for "${String(id)}": expected a non-empty string without surrounding whitespace`)
      invalidPlugins.add(plugin)
    } else if (UNSAFE_PROPERTY_KEYS.has(key)) {
      errors.push(`unsafe plugin result key "${key}"`)
      invalidPlugins.add(plugin)
    } else if (resultKeys.has(key)) {
      errors.push(`duplicate plugin result key "${key}"`)
    } else if (RESERVED_RESULT_KEYS.has(key)) {
      errors.push(`plugin "${id}" uses reserved result key "${key}"`)
      invalidPlugins.add(plugin)
    }

    if (isSafePluginKey(id)) ids.add(id)
    if (isSafePluginKey(key)) resultKeys.add(key)
  }

  return invalidPlugins
}

export const isRunnablePlugin = (plugin) => {
  if (!plugin || typeof plugin !== 'object') return false
  const key = pluginResultKey(plugin)
  return isSafePluginKey(plugin.id) &&
    isSafePluginKey(key) &&
    !RESERVED_RESULT_KEYS.has(key)
}

/**
 * Run every plugin's `configure` hook, collecting per-plugin config fragments.
 *
 * @param {*} env Worker environment bindings.
 * @param {String[]} errors Mutable startup error list (shared with core config).
 * @param {Object} [shared] Pre-parsed primitives shared with plugins (e.g. `backendConfig`).
 * @returns {Object} Map of plugin id -> config fragment (or null).
 */
export const configurePlugins = (env, errors, shared = {}) => {
  const pluginConfig = Object.create(null)
  const invalidPlugins = validatePluginRegistry(errors)
  for (const plugin of plugins) {
    if (invalidPlugins.has(plugin)) continue
    if (typeof plugin.configure !== 'function') {
      pluginConfig[plugin.id] = null
      continue
    }
    try {
      pluginConfig[plugin.id] = plugin.configure(env, errors, shared) ?? null
    } catch (err) {
      errors.push(`plugin "${plugin.id}" configure failed`)
      pluginConfig[plugin.id] = null
    }
  }
  return pluginConfig
}

/**
 * Run every plugin's `evaluate` hook, writing each result into `out`.
 *
 * A plugin that throws is isolated: its slot records an `ERROR` status and the
 * remaining plugins still run. A pending evaluation times out after 1000 ms,
 * records TIMEOUT, and receives an abort signal. Its late result is ignored.
 * Timers cannot preempt synchronous code; plugins remain trusted code.
 * Plugins are annotation-only — their results ride
 * along in the Approov-Result payload and never affect pass/fail enforcement.
 *
 * @param {*} ctx Worker context (carries `ctx.pluginConfig`).
 * @param {*} args Shared evaluation inputs `{ request, approovToken, tokenVerification }`.
 * @param {Object} out Mutable structured result object to annotate.
 * @param {Function|null} [observer] Isolated analytics callback (plugin, result, failure).
 * @returns {Promise<void>}
 */
export const runPlugins = async (ctx, args, out, observer = null) => {
  for (const plugin of plugins) {
    if (!isRunnablePlugin(plugin)) {
      logError('invalid or unsafe plugin skipped at runtime')
      continue
    }
    if (typeof plugin.evaluate !== 'function') continue

    const key = pluginResultKey(plugin)
    const config = ctx.pluginConfig ? ctx.pluginConfig[plugin.id] : null
    const controller = new AbortController()
    const timeoutError = new Error(`Plugin evaluation exceeded ${PLUGIN_EVALUATION_TIMEOUT_MS} ms`)
    let timer
    const timeout = new Promise((_resolve, reject) => {
      timer = setTimeout(() => {
        // Settle the race before notifying cooperative plugins, which may reject
        // with their own error from the abort handler.
        reject(timeoutError)
        controller.abort(timeoutError)
      }, PLUGIN_EVALUATION_TIMEOUT_MS)
    })
    let result
    let failure = null
    try {
      result = await Promise.race([
        plugin.evaluate({ ...args, ctx, config, signal: controller.signal }),
        timeout
      ])
      if (result !== undefined) {
        out[key] = result
      }
    } catch (err) {
      const message = errorMessage(err)
      failure = err === timeoutError ? 'TIMEOUT' : 'ERROR'
      logError(`plugin "${plugin.id}" evaluate failed`, { status: failure })
      out[key] = { status: failure, error: message }
    } finally {
      clearTimeout(timer)
    }
    // Observation has its own boundary: a telemetry failure must never replace
    // the plugin annotation, change enforcement, or stop subsequent plugins.
    try { observer?.(plugin, result, failure) } catch { /* best effort */ }
  }
}

export { plugins }

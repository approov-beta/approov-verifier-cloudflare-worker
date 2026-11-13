/**
 * Centralized logging for the worker.
 *
 * Two prefixes are used deliberately:
 * - `approov:` for internal diagnostics (debug/info/warn/error)
 * - `[Approov]` for operational request-outcome summaries
 *
 * Routing every log through these helpers keeps channels (console.log/info/
 * warn/error) and prefixes consistent across the codebase.
 */

const DIAGNOSTIC_PREFIX = 'approov:'
const OUTCOME_PREFIX = '[Approov]'

const emit = (channel, prefix, message, details) => {
  try {
    if (details === undefined) {
      channel(`${prefix} ${message}`)
      return
    }
    channel(`${prefix} ${message}`, details)
  } catch { /* diagnostic output must not change security or response behavior */ }
}

/**
 * Emit a debug log only when Approov debug mode is enabled in context.
 *
 * Keeps production output quiet while preserving rich diagnostics for local
 * troubleshooting and integration testing.
 *
 * @param {*} ctx Runtime context containing `approovDebug`.
 * @param {String} message Log message fragment.
 * @param {*} [details] Optional structured payload.
 * @returns {void}
 */
export const logDebug = (ctx, message, details = undefined) => {
  if (!ctx || !ctx.approovDebug) return
  emit(console.log, DIAGNOSTIC_PREFIX, message, details)
}

/**
 * Emit an informational diagnostic (always on).
 *
 * @param {String} message Log message fragment.
 * @param {*} [details] Optional structured payload.
 * @returns {void}
 */
export const logInfo = (message, details = undefined) => emit(console.info, DIAGNOSTIC_PREFIX, message, details)

/**
 * Emit a warning diagnostic (always on).
 *
 * @param {String} message Log message fragment.
 * @param {*} [details] Optional structured payload.
 * @returns {void}
 */
export const logWarn = (message, details = undefined) => emit(console.warn, DIAGNOSTIC_PREFIX, message, details)

/**
 * Emit an error diagnostic (always on).
 *
 * @param {String} message Log message fragment.
 * @param {*} [details] Optional structured payload.
 * @returns {void}
 */
export const logError = (message, details = undefined) => emit(console.error, DIAGNOSTIC_PREFIX, message, details)

/**
 * Emit an operational request-outcome summary (always on, `[Approov]` prefix).
 *
 * @param {String} message Outcome message.
 * @param {*} [details] Optional verified-path metadata.
 * @returns {void}
 */
export const logOutcome = (message, details = undefined) =>
  emit(console.log, OUTCOME_PREFIX, message, details)

/**
 * Stable host API surface for drop-in plugins.
 *
 * Plugins under `plugins/<name>/` must depend ONLY on this module (plus Node
 * built-ins such as `node:crypto`) and never reach into `src/` internals
 * directly. This keeps each plugin self-contained and insulated from internal
 * refactors: as long as the exports here stay stable, a plugin keeps working.
 *
 * @module plugin-kit
 */
export { decodeBase64OrBase64Url, timingSafeStringEqual } from './utils/crypto.js'
export { deriveAccountDeviceKey } from './approov/account-key.js'
export { hasText, parseBoolean, trimOrNull } from './utils/text.js'
export { errorMessage } from './utils/errors.js'
export { logDebug, logError, logInfo, logWarn } from './utils/logging.js'

/**
 * Error normalization helpers.
 *
 * Thrown values are not guaranteed to be `Error` instances (a `throw` can carry
 * any value), so callers that want to log or surface a message route through
 * here instead of duplicating the same defensive ternary everywhere.
 */

/**
 * Extract a printable message from an arbitrary caught value.
 *
 * @param {*} err A caught/thrown value (Error, string, null, ...).
 * @returns {String} The error's `message` when present, else a stringified form.
 */
export const errorMessage = (err) => (err && err.message ? String(err.message) : String(err))

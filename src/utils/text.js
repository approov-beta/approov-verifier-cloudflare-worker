/**
 * Return whether a value is a non-empty string once surrounding whitespace is removed.
 *
 * @param {*} value Any runtime value.
 * @returns {Boolean} True when value is a string containing non-whitespace text.
 */
export const hasText = (value) => {
  return typeof value === 'string' && value.trim().length > 0
}

/**
 * Convert string-like configuration values into a normalized trimmed string.
 *
 * Empty strings are treated as missing values to keep env parsing consistent.
 *
 * @param {*} value Any runtime value.
 * @returns {String|null} Trimmed text or null when value is absent/blank.
 */
export const trimOrNull = (value) => {
  return hasText(value) ? value.trim() : null
}

// Exact booleans are shared with deployment validation.
export { parseBoolean } from '../config/schema.mjs'

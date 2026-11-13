import crypto from 'node:crypto'

/**
 * Compute a SHA-256 hash and encode the digest as base64.
 *
 * Used for token binding claim verification where Approov expects base64-encoded
 * SHA-256 output.
 *
 * @param {*} data Input data to hash.
 * @returns {String} Base64-encoded SHA-256 digest.
 */
export const sha256Base64 = (data) => {
  const hash = crypto.createHash('sha256')
  hash.update(data, 'utf8')
  return hash.digest('base64')
}

/**
 * Compare two strings in constant time to avoid leaking match information
 * through timing. Returns false immediately when lengths differ.
 *
 * @param {String} a First value.
 * @param {String} b Second value.
 * @returns {Boolean} True when the byte sequences are equal.
 */
export const timingSafeStringEqual = (a, b) => {
  const bufA = Buffer.from(String(a), 'utf8')
  const bufB = Buffer.from(String(b), 'utf8')
  if (bufA.length !== bufB.length) {
    return false
  }
  return crypto.timingSafeEqual(bufA, bufB)
}

/**
 * Decode a strict base64 or base64url string.
 *
 * Validation intentionally rejects malformed inputs (invalid characters, invalid
 * padding, invalid length, or values that do not round-trip) so configuration
 * errors fail fast during startup.
 *
 * @param {String} value Encoded string value.
 * @returns {Buffer} Decoded bytes.
 * @throws {Error} When the input is malformed or decodes to empty bytes.
 */
export const decodeBase64OrBase64Url = (value) => {
  const trimmed = String(value).trim()
  if (!trimmed) {
    throw new Error('value is empty')
  }

  const hasInvalidPadding = trimmed.includes('=') && (trimmed.length % 4) !== 0
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(trimmed) || hasInvalidPadding) {
    throw new Error('value is not valid base64/base64url')
  }

  const normalized = trimmed.replace(/-/g, '+').replace(/_/g, '/')
  if ((normalized.length % 4) === 1) {
    throw new Error('value has invalid base64/base64url length')
  }

  const padded = normalized.padEnd(
    normalized.length + ((4 - (normalized.length % 4)) % 4),
    '='
  )
  const decoded = Buffer.from(padded, 'base64')
  /* istanbul ignore next -- defensive: the alphabet/length checks above already
     guarantee at least one decoded byte, so this branch is unreachable in
     practice; kept as a belt-and-braces guard. */
  if (decoded.length === 0) {
    throw new Error('value decodes to empty bytes')
  }

  const normalizedNoPadding = normalized.replace(/=+$/g, '')
  const roundTripped = decoded.toString('base64').replace(/=+$/g, '')
  if (roundTripped !== normalizedNoPadding) {
    throw new Error('value failed base64/base64url validation')
  }

  return decoded
}

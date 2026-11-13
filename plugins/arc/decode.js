/**
 * Approov ARC (Attestation Response Code) decoding.
 *
 * Decodes the obfuscated `arc` token claim into a list of semantic property
 * labels (e.g. `pass`/`fail`, `rooted`, `emulator`, ...). Self-contained within
 * the plugin: ships its own default code map.
 *
 * @module plugins/arc/decode
 */
import crypto from 'node:crypto'
import arcMeaningsJson from './arc-flag-mappings.json'

const APPROOV_ARC_CODE_MAP = Object.freeze(Object.fromEntries(
  Object.entries(arcMeaningsJson).map(([key, value]) => [parseInt(key, 10), value])
))

/**
 * Compute the ARC decode keystream prefix using the account ARC secret.
 *
 * @param {String} prefix First five ARC characters.
 * @param {String} secret Shared ARC encoding secret.
 * @returns {Buffer} HMAC output bytes used during ARC decode.
 */
const arcHmacPrefix = (prefix, secret) => {
  return crypto
    .createHmac('sha256', secret)
    .update(prefix, 'utf8')
    .digest()
}

/**
 * Decode an Approov ARC string into a list of normalized properties.
 *
 * The decoder reproduces Approov's ARC mapping:
 * - validates ARC size and alphabet
 * - uses HMAC-derived keystream to decode each symbol
 * - resolves each decoded code to a semantic property label when known
 * - prepends `pass` or `fail` as the first property
 *
 * @param {String} arc Encoded ARC claim value.
 * @param {String} secret ARC shared secret.
 * @param {Object|null} [customMappings] Optional override of the default code map.
 * @returns {String[]} Sorted ARC properties with pass/fail in position 0.
 * @throws {Error} When ARC input is malformed.
 */
export const arcDecode = (arc, secret, customMappings = null) => {
  const S_BASE32_ENCODING = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const ARCPrefixLen = 5
  const ARC_MIN_LENGTH = 10
  // The keystream is a single HMAC-SHA256 output (32 bytes), one byte per
  // encoded symbol after the prefix. Anything longer would index past the
  // digest and silently "decode" with a zero keystream, so it is rejected.
  const ARC_MAX_LENGTH = ARCPrefixLen + 32
  const ARC_MAP_CODE_PASS = 0
  const BASE32_MASK = 31
  const BASE32_RANGE = 32

  if (!arc || arc.length === 0) {
    throw new Error('approov: no ARC provided')
  }
  if (arc.length < ARC_MIN_LENGTH) {
    throw new Error('approov: ARC is too short')
  }
  if (arc.length > ARC_MAX_LENGTH) {
    throw new Error('approov: ARC is too long')
  }

  const arcPrefix = arc.slice(0, ARCPrefixLen)
  const hmacResult = arcHmacPrefix(arcPrefix, secret)

  let isPass = false
  let lastValue = 0
  let baseIndex = 0

  const properties = []

  for (let i = ARCPrefixLen; i < arc.length; i++) {
    const char = arc[i]
    const charIndex = S_BASE32_ENCODING.indexOf(char)
    if (charIndex < 0) {
      throw new Error('approov: invalid ARC character')
    }

    const decodedByte = charIndex ^ (hmacResult[i - ARCPrefixLen] & BASE32_MASK)
    const decodedValue = baseIndex + decodedByte

    if (decodedValue < lastValue) {
      throw new Error('approov: invalid ARC')
    }
    lastValue = decodedValue

    if (decodedValue === ARC_MAP_CODE_PASS) {
      isPass = true
    } else if ((decodedValue & BASE32_MASK) === BASE32_MASK) {
      baseIndex += BASE32_RANGE
    } else {
      const mappings = customMappings || APPROOV_ARC_CODE_MAP
      const prop = mappings[decodedValue]
      properties.push(prop || String(decodedValue))
    }
  }

  properties.sort()
  properties.unshift(isPass ? 'pass' : 'fail')

  return properties
}

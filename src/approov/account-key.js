import crypto from 'node:crypto'

/**
 * Derive an account device key from a cryptographically authenticated DeviceID.
 * Callers must authenticate the token and supply the configured account secret.
 * Invalid DeviceIDs return null. Cryptographic errors propagate to the caller.
 *
 * @param {Buffer} secret Account message-signing secret bytes.
 * @param {*} did Authenticated token claim: canonical base64 for 16 bytes.
 * @returns {Buffer|null} Device key, or null for an invalid DeviceID claim.
 */
export const deriveAccountDeviceKey = (secret, did) => {
  if (typeof did !== 'string' || !/^[A-Za-z0-9+/]{22}==$/.test(did)) return null
  const deviceID = Buffer.from(did, 'base64')
  // Reject nonzero padding bits, whitespace and alternate encodings.
  if (deviceID.toString('base64') !== did) return null
  return crypto.createHmac('sha512', secret).update(deviceID).digest()
}

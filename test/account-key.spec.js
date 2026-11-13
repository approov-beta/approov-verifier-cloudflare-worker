import crypto from 'node:crypto'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { deriveAccountDeviceKey } from '../src/plugin-kit.js'
import { ACCOUNT_DEVICE_ID, ACCOUNT_SIGNING_SECRET_RAW } from './fixtures.js'

const secret = Buffer.from(ACCOUNT_SIGNING_SECRET_RAW, 'utf8')
// Independent Python hmac/hashlib vector, also used by account-signature tests.
const expected = '4d8a2daffff25b86312c125a6dedac7fbfe7799289e1baae389be4bfd7b82ae4f762d21ed5af09f43cb23ac1f524561b25addc904fb94a8cb8bde8d9db27c474'
afterEach(() => { vi.restoreAllMocks() })

describe('shared authenticated account device key', () => {
  it('matches an independently calculated key for canonical DeviceID bytes', () => {
    expect(deriveAccountDeviceKey(secret, ACCOUNT_DEVICE_ID).toString('hex')).toBe(expected)
  })

  it('separates device keys and accepts the canonical fallback DeviceID', () => {
    const ordinary = deriveAccountDeviceKey(secret, ACCOUNT_DEVICE_ID)
    const other = deriveAccountDeviceKey(secret, Buffer.from('another-deviceID').toString('base64'))
    const fallback = deriveAccountDeviceKey(secret, '+++UnknownDeviceID+++w==')
    expect(other.equals(ordinary)).toBe(false)
    expect(fallback.length).toBe(64)
    expect(fallback.equals(ordinary)).toBe(false)
  })

  it.each([undefined, null, 42, '', ACCOUNT_DEVICE_ID.slice(0, -2), ACCOUNT_DEVICE_ID + '\n', '___UnknownDeviceID___w==', ACCOUNT_DEVICE_ID.replace('Dw==', 'Dx==')])('rejects an invalid DeviceID (%j) before HMAC derivation', did => {
    const hmac = vi.spyOn(crypto, 'createHmac')
    expect(deriveAccountDeviceKey(secret, did)).toBeNull()
    expect(hmac).not.toHaveBeenCalled()
  })

  it('propagates a crypto failure for the caller to classify', () => {
    vi.spyOn(crypto, 'createHmac').mockImplementation(() => { throw new Error('crypto unavailable') })
    expect(() => deriveAccountDeviceKey(secret, ACCOUNT_DEVICE_ID)).toThrow('crypto unavailable')
  })
})

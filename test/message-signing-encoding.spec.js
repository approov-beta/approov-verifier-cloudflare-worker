import crypto from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { validateMessageSignatures } from '../src/approov/message-signing.js'
import { ACCOUNT_DEVICE_ID, ACCOUNT_SIGNING_KEY_ID, ACCOUNT_SIGNING_SECRET_RAW, FUTURE_EXP, PASS_PRIVATE_KEY, signEs256 } from './fixtures.js'

const url = 'https://worker.local/encoding?amount=1'
const accountSecret = Buffer.from(ACCOUNT_SIGNING_SECRET_RAW, 'utf8')
// Independent Python hmac/hashlib vector for the fixture DeviceID and secret.
const deviceKey = Buffer.from('4d8a2daffff25b86312c125a6dedac7fbfe7799289e1baae389be4bfd7b82ae4f762d21ed5af09f43cb23ac1f524561b25addc904fb94a8cb8bde8d9db27c474', 'hex')
const installation = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const now = Math.floor(Date.now() / 1000)
const context = {
  approovTokenHeaderName: 'Approov-Token',
  approovMessageSigningTolerance: 60,
  approovMessageSigningMaxBodyBytes: 1048576,
  approovAccountMessageSigningSecret: accountSecret,
  approovAccountMessageSigningKeyId: ACCOUNT_SIGNING_KEY_ID
}
const modes = [
  { name: 'account', algorithm: 'hmac-sha256', claims: { did: ACCOUNT_DEVICE_ID, mskid: ACCOUNT_SIGNING_KEY_ID }, sign: base => crypto.createHmac('sha256', deviceKey).update(base).digest() },
  { name: 'install', algorithm: 'ecdsa-p256-sha256', claims: { ipk: installation.publicKey.export({ type: 'spki', format: 'pem' }).toString() }, sign: base => crypto.sign('sha256', Buffer.from(base), { key: installation.privateKey.export({ type: 'pkcs8', format: 'pem' }), dsaEncoding: 'ieee-p1363' }) }
]

for (const mode of modes) {
  describe(`message-signature encoding (${mode.name})`, () => {
    const token = signEs256(PASS_PRIVATE_KEY, { exp: FUTURE_EXP, ...mode.claims })
    // Construct the RFC signature base directly, independent of the vendor signer.
    const request = ({ created = String(now), expires = String(now + 300), signedCreated = created, signedExpires = expires, digest, body } = {}) => {
      const method = body === undefined ? 'GET' : 'POST'
      const fields = ['@method', '@target-uri', 'approov-token', ...(digest === undefined ? [] : ['content-digest'])]
      const input = `(${fields.map(name => `"${name}"`).join(' ')});alg="${mode.algorithm}";created=${created};expires=${expires}`
      const signedInput = `(${fields.map(name => `"${name}"`).join(' ')});alg="${mode.algorithm}";created=${signedCreated};expires=${signedExpires}`
      const lines = [`"@method": ${method}`, `"@target-uri": ${url}`, `"approov-token": ${token}`]
      if (digest !== undefined) lines.push(`"content-digest": ${digest}`)
      lines.push(`"@signature-params": ${signedInput}`)
      const signature = mode.sign(lines.join('\n')).toString('base64')
      return new Request(url, {
        method,
        body,
        headers: { 'Approov-Token': token, Signature: `${mode.name}=:${signature}:`, 'Signature-Input': `${mode.name}=${input}`, ...(digest === undefined ? {} : { 'Content-Digest': digest }) }
      })
    }
    const verify = args => validateMessageSignatures(context, request(args), mode.claims)

    it('accepts integer creation and expiration timestamps', async () => {
      expect((await verify()).status).toBe('VALID')
    })

    const badTimes = [
      ['quoted integer', `"${now}"`],
      ['String', '"never"'],
      ['Token', 'never'],
      ['Byte Sequence', ':bmV2ZXI=:'],
      ['Boolean', '?1'],
      ['Decimal', `${now}.5`]
    ]
    for (const parameter of ['created', 'expires']) {
      it.each(badTimes)(`rejects a ${parameter} timestamp encoded as %s`, async (_type, value) => {
        const result = await verify({ [parameter]: value })
        expect(result.status).toBe('INVALID')
        expect(result.error).toContain(`Signature timestamp "${parameter}" must be an Integer`)
      })
    }

    it('rejects a quoted expired timestamp instead of concatenating the tolerance', async () => {
      expect((await verify({ created: String(now - 300), expires: `"${now - 120}"` })).status).toBe('INVALID')
      expect((await verify({ created: String(now - 300), expires: String(now - 120) })).status).toBe('INVALID')
    })

    it.each(['created', 'expires'])('characterizes integral Decimal normalization for %s', async parameter => {
      // Parser 1.0.1 represents N.0 as number N and serializes it as an Integer.
      // The independent MAC signs that canonical form, not the transmitted .0.
      const value = parameter === 'created' ? now : now + 300
      const signedParameter = parameter === 'created' ? 'signedCreated' : 'signedExpires'
      expect((await verify({ [parameter]: `${value}.0`, [signedParameter]: String(value) })).status).toBe('VALID')
    })

    it('preserves expiration and future-creation checks after integral Decimal normalization', async () => {
      const expired = await verify({ created: String(now - 300), expires: `${now - 120}.0`, signedExpires: String(now - 120) })
      expect(expired.status).toBe('INVALID')
      expect(expired.error).toContain('Signature has expired')
      const future = await verify({ created: `${now + 120}.0`, signedCreated: String(now + 120) })
      expect(future.status).toBe('INVALID')
      expect(future.error).toContain('Signature is too old')
    })

    for (const algorithm of ['sha-256', 'sha-512']) {
      const body = 'digest representation regression'
      const digestBytes = crypto.createHash(algorithm.replace('-', '')).update(body).digest()
      const padded = digestBytes.toString('base64')
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
      const lastIndex = padded.replace(/=+$/, '').length - 1
      const nonzeroPadBits = padded.slice(0, lastIndex) + alphabet[alphabet.indexOf(padded[lastIndex]) + 1] + padded.slice(lastIndex + 1)
      it.each([
        ['padded', padded],
        ['unpadded', padded.replace(/=+$/, '')],
        ['nonzero pad bits', nonzeroPadBits]
      ])(`accepts equivalent ${algorithm} digest bytes in %s base64`, async (_form, encoded) => {
        expect(Buffer.from(encoded, 'base64').equals(digestBytes)).toBe(true)
        const result = await verify({ body, digest: `${algorithm}=:${encoded}:` })
        expect(result.status).toBe('VALID')
      })

      it(`rejects a String ${algorithm} digest even when its bytes match`, async () => {
        const result = await verify({ body, digest: `${algorithm}="${padded}"` })
        expect(result.status).toBe('INVALID_CONTENT_DIGEST')
        expect(result.error).toContain('Unsupported Content-Digest value')
      })

      it(`rejects changed ${algorithm} digest bytes`, async () => {
        const changed = Buffer.from(digestBytes)
        changed[0] ^= 1
        const result = await verify({ body, digest: `${algorithm}=:${changed.toString('base64')}:` })
        expect(result.status).toBe('INVALID_CONTENT_DIGEST')
      })
    }

    it.each([':A:', ':AA=A:', ':A===:', ':====:', ':AAAA=:'])('rejects malformed digest base64 %s', async encoded => {
      const result = await verify({ body: 'body', digest: `sha-256=${encoded}` })
      expect(result.status).toBe('INVALID_CONTENT_DIGEST')
      expect(result.error).toContain('Unsupported Content-Digest value')
    })

    it.each(['?0', 'foo', '::'])('rejects an unsupported or empty digest value %s', async encoded => {
      expect((await verify({ body: 'body', digest: `sha-256=${encoded}` })).status).toBe('INVALID_CONTENT_DIGEST')
    })
  })
}

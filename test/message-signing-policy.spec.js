import { describe, expect, it } from 'vitest'
import crypto from 'node:crypto'
import { ACCOUNT_DEVICE_ID } from './fixtures.js'
import { validateMessageSignatures } from '../src/approov/message-signing.js'
import { createSigner, httpbis } from '../src/vendor/http-message-signatures.js'

const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const accountKey = Buffer.from('message-signing-policy-test-key')
const accountSigningKey = crypto.createHmac('sha512', accountKey).update(Buffer.from(ACCOUNT_DEVICE_ID, 'base64')).digest()
const url = 'https://api.example.com/pay?amount=1&tag=a&tag=b&value=%2F'
const tokenHeader = 'x-custom-approov-token'
const targetFields = ['@method', '@target-uri', tokenHeader]
const separateFields = ['@method', '@scheme', '@authority', '@path', '@query', tokenHeader]
const payload = { ipk: publicKey.export({ type: 'spki', format: 'pem' }).toString(), did: ACCOUNT_DEVICE_ID, mskid: 'test-key' }
const digest = (body) => `sha-256=:${crypto.createHash('sha256').update(body).digest('base64')}:`

for (const mode of ['install', 'account']) {
  describe(`Message signature coverage (${mode})`, () => {
    const ctx = {
      approovMessageSigningMode: mode,
      approovTokenHeaderName: tokenHeader,
      approovMessageSigningTolerance: 60,
      approovMessageSigningMaxBodyBytes: 1048576,
      approovAccountMessageSigningSecret: accountKey,
      approovAccountMessageSigningKeyId: 'test-key'
    }
    const sign = async ({ fields = targetFields, signedUrl = url, body } = {}) => {
      const headers = { [tokenHeader]: 'test-token' }
      if (body !== undefined) headers['content-digest'] = digest(body)
      const message = await httpbis.signMessage({
        key: createSigner(mode === 'install' ? privateKey.export({ type: 'pkcs8', format: 'pem' }) : accountSigningKey,
          mode === 'install' ? 'ecdsa-p256-sha256' : 'hmac-sha256'),
        name: mode,
        fields
      }, { url: signedUrl, method: body === undefined ? 'GET' : 'POST', headers })
      return message.headers
    }
    const verify = (headers, target = url, init = {}) =>
      validateMessageSignatures(ctx, new Request(target, { headers, ...init }), mode === 'install' ? { ipk: payload.ipk } : { did: ACCOUNT_DEVICE_ID, mskid: payload.mskid })

    for (const [form, fields] of [['target URI', targetFields], ['separate URL components', separateFields]]) {
      describe(form, () => {
        it('accepts complete coverage with the configured token header', async () => {
          expect((await verify(await sign({ fields }))).status).toBe('VALID')
        })

        it.each([
          ['query value', url.replace('amount=1', 'amount=999')],
          ['removed query', 'https://api.example.com/pay'],
          ['duplicate query value', url.replace('tag=b', 'tag=c')],
          ['query encoding', url.replace('%2F', '/')],
          ['query order', url.replace('tag=a&tag=b', 'tag=b&tag=a')],
          ['path', url.replace('/pay?', '/refund?')],
          ['authority', url.replace('api.example.com', 'other.example.com')],
          ['scheme', url.replace('https:', 'http:')]
        ])('rejects a changed %s', async (_name, changedUrl) => {
          expect((await verify(await sign({ fields }), changedUrl)).status).toBe('INVALID')
        })

        it('rejects a query added to an originally queryless URL', async () => {
          const signedUrl = 'https://api.example.com/pay'
          const headers = await sign({ fields, signedUrl })
          expect((await verify(headers, signedUrl)).status).toBe('VALID')
          expect((await verify(headers, `${signedUrl}?amount=999`)).status).toBe('INVALID')
        })

        it('rejects a changed method or token', async () => {
          const headers = await sign({ fields })
          expect((await verify(headers, url, { method: 'DELETE' })).status).toBe('INVALID')
          expect((await verify({ ...headers, [tokenHeader]: 'another-token' })).status).toBe('INVALID')
        })

        it('binds the body digest to the signature', async () => {
          const headers = await sign({ fields: [...fields, 'content-digest'], body: 'original' })
          expect((await verify(headers, url, { method: 'POST', body: 'original' })).status).toBe('VALID')
          expect((await verify(headers, url, { method: 'POST', body: 'changed' })).status).toBe('INVALID_CONTENT_DIGEST')
          const changed = { ...headers, 'content-digest': digest('changed') }
          expect((await verify(changed, url, { method: 'POST', body: 'changed' })).status).toBe('INVALID')
        })
      })
    }

    it.each(separateFields)('rejects complete-component signatures missing %s', async (missing) => {
      const headers = await sign({ fields: separateFields.filter(field => field !== missing) })
      const result = await verify(headers)
      expect(result.status).toBe('INVALID')
      expect(result.error).toContain('Missing required signed fields')
    })

    it('rejects the old path-and-host-only signature policy', async () => {
      const headers = await sign({ fields: ['@method', '@path', '@authority', tokenHeader] })
      expect((await verify(headers)).status).toBe('INVALID')
    })

    it('does not borrow URL coverage from another signature entry', async () => {
      const headers = await sign({ fields: ['@method', tokenHeader] })
      const extra = await sign()
      headers['Signature-Input'] += ', other=' + extra['Signature-Input'].slice(mode.length + 1)
      headers.Signature += ', other=' + extra.Signature.slice(mode.length + 1)
      expect((await verify(headers)).status).toBe('INVALID')
    })

    it('rejects a digest that is present but unsigned', async () => {
      const headers = await sign({ body: 'original' })
      expect((await verify(headers, url, { method: 'POST', body: 'original' })).status).toBe('INVALID')
    })

    it('rejects malformed signature input instead of throwing', async () => {
      const headers = await sign()
      headers['Signature-Input'] = `${mode}=42`
      expect((await verify(headers)).status).toBe('INVALID')
    })

    it('does not accept a parameterized target URI as complete URL coverage', async () => {
      const headers = await sign({ fields: ['@method', '"@target-uri";foo', tokenHeader] })
      expect((await verify(headers)).status).toBe('INVALID')
    })
  })
}
